from typing import Annotated, Any, Dict, List, Sequence, TypedDict, Optional
import json
import re

from langchain_core.messages import BaseMessage, SystemMessage, HumanMessage, AIMessage, ToolMessage
from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode

from .safety import SafetyLayer, SafetyVerdict
from .tools.registry import ToolRegistry

class TaskState(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]
    goal: str
    plan: dict
    findings: dict
    iteration: int
    is_completed: bool
    requires_approval: bool
    final_report: str
    is_verified: bool
    # UX transparency state keys — intercepted by engine.py for UI events
    thinking: str          # current node's reasoning (→ evt_thinking)
    hypothesis: str        # current working hypothesis (→ evt_hypothesis)
    resolution_plan: list  # structured repair steps (→ evt_resolution_plan)
    
    # Infinite loop protection
    no_progress_cycles: int
    last_progress_hash: str


# ---------------------------------------------------------------------------
# Deterministic tool set — observer marks these complete without LLM
# ---------------------------------------------------------------------------
DETERMINISTIC_TOOLS = {
    "system_info", "network_info",
}


class AutonomousController:
    def __init__(self, llm, tools, system_prompt: str = ""):
        self.llm = llm
        self.tools = tools
        self.tool_node = ToolNode(tools)
        self.system_prompt = system_prompt
        self.tool_map = {t.name: t for t in tools}
        self.safety = SafetyLayer()
        self.registry = ToolRegistry()

    def build_graph(self):
        workflow = StateGraph(TaskState)

        workflow.add_node("planner",        self.planner_node)
        workflow.add_node("executor",       self.executor_node)
        workflow.add_node("tools",          self.safe_tool_node)
        workflow.add_node("observer",       self.observer_node)
        workflow.add_node("goal_checker",   self.goal_checker_node)
        workflow.add_node("final_response", self.final_response_node)

        workflow.set_entry_point("planner")
        workflow.add_edge("planner", "executor")

        def should_continue_executor(state: TaskState):
            if state.get("is_completed", False) or state.get("requires_approval", False):
                return END
            last = (state.get("messages") or [None])[-1]
            if getattr(last, "tool_calls", None):
                return "tools"
            return END

        workflow.add_conditional_edges("executor", should_continue_executor,
                                       {"tools": "tools", END: END})
        workflow.add_edge("tools", "observer")
        workflow.add_edge("observer", "goal_checker")

        def should_continue_goal_checker(state: TaskState):
            if state.get("iteration", 0) > 20:
                return END
            if state.get("plan", {}).get("completed", False):
                return "final_response"
            return "executor"

        workflow.add_conditional_edges("goal_checker", should_continue_goal_checker,
                                       {"final_response": "final_response",
                                        "executor": "executor", END: END})
        workflow.add_edge("final_response", END)
        return workflow.compile()

    # -----------------------------------------------------------------------
    # Robust JSON parser with LLM auto-repair
    # -----------------------------------------------------------------------
    def _robust_json_parse(self, sys_msg, tags, max_retries=2, fallback_response=None):
        from langchain_core.messages import HumanMessage
        messages = [sys_msg]
        for attempt in range(max_retries):
            try:
                response = self.llm.with_config({"tags": tags}).invoke(messages)
                raw = response.content
                if "```" in raw:
                    raw = re.sub(r"```(?:json)?\s*", "", raw).strip("` \n")
                
                start_idx = raw.find('{')
                start_array = raw.find('[')
                if start_idx == -1 or (start_array != -1 and start_array < start_idx):
                    start_idx = start_array
                if start_idx != -1:
                    raw = raw[start_idx:]
                json_str = re.search(r'(\{.*\}|\[.*\])', raw, re.DOTALL).group(0)
                return json.loads(json_str)
            except Exception as e:
                if attempt == max_retries - 1:
                    if fallback_response is not None:
                        return fallback_response
                    return {}
                # Append the failed response and a repair prompt
                if 'response' in locals():
                    messages.append(response)
                messages.append(HumanMessage(content=f"Your previous output failed to parse as valid JSON. Error: {str(e)}\n\nPlease repair the JSON and output STRICTLY valid JSON ONLY. Do not include markdown fences or any other text."))

    # -----------------------------------------------------------------------
    # Safe tool wrapper
    # -----------------------------------------------------------------------
    def safe_tool_node(self, state: TaskState):
        last = (state.get("messages") or [None])[-1]
        if getattr(last, "tool_calls", None):
            tc = last.tool_calls[0]
            meta = self.registry.get_metadata(tc["name"])
            if meta:
                check = self.safety.check(meta, tc["args"])
                if check.verdict == SafetyVerdict.BLOCKED:
                    return {"messages": [ToolMessage(
                        content=f"Error: BLOCKED by safety layer - {check.reason}",
                        name=tc["name"], tool_call_id=tc["id"])]}
                elif check.verdict == SafetyVerdict.APPROVAL_REQUIRED:
                    return {"requires_approval": True, "messages": [ToolMessage(
                        content=f"Paused: APPROVAL REQUIRED for {tc['name']} - {check.reason}.",
                        name=tc["name"], tool_call_id=tc["id"])]}
        return self.tool_node.invoke(state)

    # -----------------------------------------------------------------------
    # Planner Node — generates task plan + initial hypothesis
    # -----------------------------------------------------------------------
    def planner_node(self, state: TaskState):
        goal = state["goal"]
        existing_plan = state.get("plan", {})
        existing_tasks = existing_plan.get("tasks", [])
        
        has_pending = any(t.get("status") in ["pending", "running"] for t in existing_tasks)

        if existing_plan and existing_tasks and has_pending:
            return {"plan": existing_plan,
                    "thinking": f"Resuming existing plan for: {goal}"}

        prompt = f"""You are an autonomous SRE execution agent.

Goal: {goal}

Your job:
1. Classify the user's intent. Intent Types: Explain / Identify, Read Information, Modify, Create, Delete, Investigate Incident, Debug Problem, Research.
2. Think about what investigation steps are needed based on the intent.
3. Write a concise hypothesis about what might be wrong (or what is needed).
4. Create a strict numbered task plan as a JSON array of strings.

CRITICAL RULES:
- For Explain/Identify requests (e.g., "what is this file", "what does this mean", "identify this", "explain this folder"):
  - DO NOT create investigative or recovery workflows.
  - Never assume corruption, recovery, restoration, debugging, security incidents, or hidden problems unless explicitly stated or directly supported by evidence.
  - Minimal Task Plan: 1. Inspect object, 2. Gather metadata, 3. Explain findings.
- For simple queries ("time now", "hostname", "uptime") → exactly ONE task.
- For complex issues ("why nginx stopped?") → sequential investigation steps.
- Tasks must be actions the agent performs, not instructions to the user.

Output STRICTLY this JSON structure:
{{
  "intent": "The classified intent type",
  "thinking": "Your internal reasoning about the goal based on the intent",
  "hypothesis": "Your initial working hypothesis (if applicable)",
  "tasks": ["Task 1 description", "Task 2 description"]
}}
"""
        thinking_out = f"Analyzing goal: {goal}"
        tasks = []
        new_tasks = []
        fallback_json = {
            "intent": "Research",
            "thinking": f"Fallback: Generating default task for {goal}",
            "hypothesis": "",
            "tasks": [f"Investigate: {goal}"]
        }
        
        data = self._robust_json_parse(
            HumanMessage(content=prompt), 
            ["planner_llm"], 
            fallback_response=fallback_json
        )
        
        thinking_out  = data.get("thinking", thinking_out)
        hypothesis_out = data.get("hypothesis", "")
        intent_out     = data.get("intent", "Research")
        task_titles    = data.get("tasks", [])
        
        start_id = max((t.get("id", 0) for t in existing_tasks), default=0)
        
        if not task_titles:
            task_titles = [f"Investigate: {goal}"]
            
        for i, title in enumerate(task_titles):
            new_tasks.append({
                "id": start_id + i + 1,
                "description": title,
                "status": "pending",
                "attempts": 0,
                "max_attempts": 3,
                "tool": None,
                "tool_args": {},
                "result": None,
                "evidence": [],
                "completed": False,
            })

        existing_tasks.extend(new_tasks)
        existing_plan["tasks"]         = existing_tasks
        existing_plan["intent"]        = intent_out
        existing_plan["completed"]     = False
        existing_plan["dynamic_count"] = 0

        return {
            "plan":       existing_plan,
            "iteration":  state.get("iteration", 0),
            "thinking":   thinking_out,
            "hypothesis": hypothesis_out,
        }

    # -----------------------------------------------------------------------
    # Executor Node — selects next pending task, picks ONE tool
    # -----------------------------------------------------------------------
    def executor_node(self, state: TaskState):
        plan         = state.get("plan", {})
        tasks        = plan.get("tasks", [])
        findings     = state.get("findings", {})
        hypothesis   = state.get("hypothesis", "")

        current_task = next((t for t in tasks if t["status"] == "pending"), None)
        if not current_task:
            return {"plan": plan, "iteration": state.get("iteration", 0) + 1,
                    "thinking": "No pending tasks remaining."}

        current_task["attempts"] = current_task.get("attempts", 0) + 1
        if current_task["attempts"] > current_task.get("max_attempts", 3):
            current_task["status"]    = "failed"
            current_task["completed"] = False
            current_task["result"]    = "Max execution attempts reached."
            return {"plan": plan, "iteration": state.get("iteration", 0) + 1,
                    "thinking": f"Task '{current_task['description']}' exceeded max attempts and was marked failed."}

        current_task["status"] = "running"

        sys_msg = SystemMessage(content=f"""{self.system_prompt}

=== CURRENT INVESTIGATION ===
Goal: {state['goal']}
Current Task (#{current_task['id']}): {current_task['description']}
Attempt: {current_task['attempts']} / {current_task.get('max_attempts', 3)}
Working Hypothesis: {hypothesis}

Findings so far:
{json.dumps(findings.get('findings', []), indent=2)}

Available tools: {', '.join(self.tool_map.keys())}

=== INSTRUCTION ===
Select exactly ONE tool to execute this task.
Respond ONLY with valid JSON — no explanation, no markdown fences:
{{
  "thinking": "Why this tool was chosen for this specific task",
  "next_action": "tool_name",
  "tool_args": {{"arg": "value"}},
  "reason": "Short public reason for the user"
}}
""")
        fallback_json = {
            "thinking": "Fallback: Execution failed to parse JSON, attempting safe system check",
            "next_action": "system_info",
            "tool_args": {"aspect": "all"},
            "reason": "Agent encountered an internal parsing error, running a safe diagnostic."
        }
        
        data = self._robust_json_parse(
            sys_msg, 
            ["executor_llm"], 
            fallback_response=fallback_json
        )

        tool_name = data.get("next_action")
        tool_args = data.get("tool_args", {})
        thinking  = data.get("thinking", f"Executing {tool_name} for task: {current_task['description']}")

        if tool_name in self.tool_map:
            current_task["tool_args"] = tool_args
            tool_call = {"name": tool_name, "args": tool_args, "id": f"call_{current_task['id']}"}
            ai_msg = AIMessage(content=data.get("reason", thinking), tool_calls=[tool_call])
            return {"messages": [ai_msg], "plan": plan, "thinking": thinking}
        else:
            current_task["status"] = "pending"
            current_task["result"] = f"Invalid tool selected: {tool_name}"
            return {"plan": plan,
                    "thinking": f"Executor picked unknown tool '{tool_name}', retrying."}

    # -----------------------------------------------------------------------
    # Observer Node — validates tool output, extracts findings
    # -----------------------------------------------------------------------
    def observer_node(self, state: TaskState):
        messages     = state["messages"]
        plan         = state.get("plan", {})
        tasks        = plan.get("tasks", [])
        findings_data = state.get("findings", {})
        if "findings" not in findings_data:
            findings_data["findings"] = []

        last_msg     = messages[-1]
        current_task = next((t for t in tasks if t["status"] == "running"), None)

        if not (current_task and isinstance(last_msg, ToolMessage)):
            return {"plan": plan, "findings": findings_data,
                    "thinking": "Observer: no running task or no tool output to analyze."}

        tool_output  = last_msg.content
        tool_name    = last_msg.name
        current_task["tool"]   = tool_name
        current_task["result"] = tool_output[:500]

        # Deterministic fast-path
        is_error = "Error" in tool_output or "error" in tool_output.lower()
        if tool_name in DETERMINISTIC_TOOLS and not is_error and tool_output.strip():
            current_task["status"]    = "completed"
            current_task["completed"] = True
            current_task["evidence"]  = [tool_output[:500]]
            finding_text = f"[{tool_name}] Task '{current_task['description']}' succeeded."
            findings_data["findings"].append(finding_text)
            return {
                "plan":     plan,
                "findings": findings_data,
                "thinking": f"Observer: '{tool_name}' produced valid output. Task marked completed deterministically.",
            }

        prompt = f"""You are an SRE observer analyzing tool output.

Tool: {tool_name}
Task: {current_task['description']}
Goal: {state['goal']}

Tool Output (truncated to 2000 chars):
{tool_output[:2000]}

Analyze and respond ONLY with valid JSON.
CRITICAL CONSTITUTION RULES:
1. Tool Success is NOT Goal Success. Tool Success alone must never complete a task.
2. A task is only completed when the user objective has been verified.
3. You must always answer: Did the tool run? Did it produce expected output? Did the output satisfy the goal? What evidence proves it?

{{
  "answers": {{
    "did_tool_run": true or false,
    "expected_output": true or false,
    "satisfied_goal": true or false,
    "evidence_extracted": true or false
  }},
  "task_completed": true or false,
  "new_findings": ["specific finding 1", "specific finding 2"],
  "evidence": ["quoted evidence from tool output"],
  "hypothesis_update": "Updated working hypothesis based on this evidence"
}}
"""
        fallback_json = {
            "answers": {"did_tool_run": True, "expected_output": False, "satisfied_goal": False, "evidence_extracted": False},
            "task_completed": False,
            "new_findings": ["Observer encountered a parsing error."],
            "evidence": [],
            "hypothesis_update": "System error during observation, need to re-evaluate."
        }

        try:
            data = self._robust_json_parse(HumanMessage(content=prompt), ["observer_llm"], fallback_response=fallback_json)

            # Enforce constitution: completion requires all answers to be True
            answers = data.get("answers", {})
            is_comp = data.get("task_completed", False)
            if is_comp and not (answers.get("did_tool_run") and answers.get("expected_output") and answers.get("satisfied_goal") and answers.get("evidence_extracted")):
                is_comp = False
                data["hypothesis_update"] = "Verification missing. " + data.get("hypothesis_update", "")

            current_task["status"]    = "completed" if is_comp else "failed"
            current_task["completed"] = is_comp
            current_task["evidence"]  = data.get("evidence", [])
            findings_data["findings"].extend(data.get("new_findings", []))
            new_hyp = data.get("hypothesis_update", "")

            return {
                "plan":       plan,
                "findings":   findings_data,
                "thinking":   f"Observer analyzed '{tool_name}': task {'completed' if is_comp else 'verification required'}.",
                "hypothesis": new_hyp if new_hyp else state.get("hypothesis", ""),
            }
        except Exception:
            current_task["status"]    = "completed"
            current_task["completed"] = True
            return {"plan": plan, "findings": findings_data,
                    "thinking": "Observer: LLM analysis failed, task marked completed as fallback."}

    # -----------------------------------------------------------------------
    # Goal Checker Node — determines if user goal is met; injects verification
    # -----------------------------------------------------------------------
    def goal_checker_node(self, state: TaskState):
        plan          = state.get("plan", {})
        tasks         = plan.get("tasks", [])
        findings_data = state.get("findings", {})
        
        import hashlib
        completed_count = sum(1 for t in tasks if t.get("completed"))
        evidence_count = sum(len(t.get("evidence", [])) for t in tasks)
        findings_count = len(findings_data.get("findings", []))
        
        state_str = f"{len(tasks)}_{completed_count}_{evidence_count}_{findings_count}"
        current_hash = hashlib.md5(state_str.encode()).hexdigest()
        
        last_hash = state.get("last_progress_hash", "")
        no_prog_cycles = state.get("no_progress_cycles", 0)
        
        if current_hash == last_hash:
            no_prog_cycles += 1
        else:
            no_prog_cycles = 0
            
        if no_prog_cycles >= 2:
            plan["completed"] = True
            findings_data["findings"].append("Investigation terminated due to lack of progress.")
            return {
                "plan": plan, 
                "findings": findings_data,
                "thinking": "Goal checker: No progress detected for 2 consecutive cycles. Terminating.",
                "no_progress_cycles": no_prog_cycles,
                "last_progress_hash": current_hash
            }

        has_pending = any(t["status"] in ["pending", "running"] for t in tasks)
        if has_pending:
            return {
                "iteration": state.get("iteration", 0) + 1,
                "thinking": "Goal checker: pending tasks remain, continuing execution.",
                "no_progress_cycles": no_prog_cycles,
                "last_progress_hash": current_hash
            }

        # Fast-path: single deterministic task completed
        if len(tasks) == 1 and tasks[0].get("completed", False):
            if tasks[0].get("tool") in DETERMINISTIC_TOOLS:
                plan["completed"] = True
                return {
                    "plan": plan,
                    "thinking": "Goal checker: single deterministic task completed — proceeding to final response.",
                    "no_progress_cycles": no_prog_cycles,
                    "last_progress_hash": current_hash
                }

        # LLM goal evaluation - Verification Gate
        prompt = f"""You are the Verification Gate for an SRE investigation.

Goal: {state['goal']}

Findings:
{json.dumps(findings_data.get('findings', []), indent=2)}

Tasks Evidence:
{json.dumps([{"task": t["description"], "evidence": t.get("evidence", [])} for t in tasks], indent=2)}

CRITICAL CONSTITUTION RULES:
1. Completion requires goal_verified = true.
2. You must independently validate the original goal against the produced evidence and completed tasks.
3. If evidence does not conclusively prove the goal is achieved, you MUST NOT mark it solved.
4. Execution without verification is never considered complete.

Analyze the evidence. Has the user's original goal been completely and verifiably solved?
Respond ONLY with valid JSON:
{{
  "goal_verified": true or false,
  "reason": "explanation of verification result",
  "resolution_steps": ["step 1", "step 2"]
}}
"""
        resolution_steps = []
        fallback_json = {
            "goal_verified": False,
            "reason": "Parsing failed during verification. Assuming unverified.",
            "resolution_steps": []
        }
        
        try:
            data = self._robust_json_parse(HumanMessage(content=prompt), ["goal_llm"], fallback_response=fallback_json)
            is_goal_met      = data.get("goal_verified", False)
            resolution_steps = data.get("resolution_steps", [])
        except Exception:
            is_goal_met = False

        if is_goal_met:
            intent = plan.get("intent", "")
            is_readonly = any(k in intent.lower() for k in ["explain", "identify", "read", "research"])
            
            # Inject verification task for SRE multi-task investigations
            if len(tasks) > 1 and not is_readonly:
                has_verified = any(
                    "verify" in t["description"].lower() or
                    "verification" in t["description"].lower()
                    for t in tasks
                )
                if not has_verified and plan.get("dynamic_count", 0) < 2:
                    new_id = len(tasks) + 1
                    tasks.append({
                        "id": new_id,
                        "description": "Run final SRE verification (service status, config validity, endpoints)",
                        "status": "pending", "attempts": 0, "max_attempts": 3,
                        "tool": None, "tool_args": {}, "result": None,
                        "evidence": [], "completed": False,
                    })
                    plan["dynamic_count"] = plan.get("dynamic_count", 0) + 1
                    return {
                        "plan": plan,
                        "iteration": state.get("iteration", 0) + 1,
                        "resolution_plan": resolution_steps,
                        "thinking": "Goal checker: solution verified — injecting final SRE verification task.",
                        "no_progress_cycles": no_prog_cycles,
                        "last_progress_hash": current_hash
                    }
            plan["completed"] = True
            return {
                "plan": plan,
                "resolution_plan": resolution_steps,
                "thinking": "Goal checker: goal fully achieved — proceeding to final response.",
                "no_progress_cycles": no_prog_cycles,
                "last_progress_hash": current_hash
            }
        else:
            dyn_count = plan.get("dynamic_count", 0)
            if dyn_count >= 2:
                plan["completed"] = True
                return {
                    "plan": plan,
                    "thinking": "Goal checker: dynamic task limit reached — finalizing with available evidence.",
                    "no_progress_cycles": no_prog_cycles,
                    "last_progress_hash": current_hash
                }
            new_id = len(tasks) + 1
            tasks.append({
                "id": new_id,
                "description": "Investigate deeper — gather more evidence to resolve the goal",
                "status": "pending", "attempts": 0, "max_attempts": 3,
                "tool": None, "tool_args": {}, "result": None,
                "evidence": [], "completed": False,
            })
            plan["dynamic_count"] = dyn_count + 1
            return {
                "plan": plan,
                "iteration": state.get("iteration", 0) + 1,
                "resolution_plan": resolution_steps,
                "thinking": f"Goal checker: goal not yet met ({data.get('reason', '')}) — adding deeper investigation task.",
                "no_progress_cycles": no_prog_cycles,
                "last_progress_hash": current_hash
            }

    # -----------------------------------------------------------------------
    # Final Response Node — generates human-readable answer from evidence
    # -----------------------------------------------------------------------
    def final_response_node(self, state: TaskState):
        plan          = state.get("plan", {})
        tasks         = plan.get("tasks", [])
        findings_data = state.get("findings", {})

        # Build evidence summary from all completed tasks
        evidence_lines = []
        for t in tasks:
            if t.get("evidence"):
                evidence_lines.append(f"Task: {t['description']}\n" +
                                      "\n".join(f"  - {e}" for e in t["evidence"]))

        is_simple = (len(tasks) == 1 and plan.get("dynamic_count", 0) == 0)

        if is_simple:
            prompt = f"""You are a result interpreter for an SRE agent. You are NOT a tool-output relay.

User Request: {state['goal']}

Tool Evidence:
{chr(10).join(evidence_lines) or "No direct evidence captured."}

Rules:
- Answer the user's question directly and concisely in 1-2 sentences.
- NEVER dump raw logs, directory listings, JSON, or command output.
- CRITICAL CONSTITUTION RULE: Never generate a completion message solely because tools executed successfully. Completion without evidence is forbidden. Your answer must be based entirely on the gathered evidence.

Output ONLY valid JSON:
{{
  "artifact_name": "response.md",
  "report_content": "Your concise 1-2 sentence human-readable answer."
}}"""
        else:
            prompt = f"""You are a result interpreter for an SRE agent. You are NOT a tool-output relay.

User Request: {state['goal']}

Investigation Findings:
{json.dumps(findings_data.get('findings', []), indent=2)}

Evidence from Tasks:
{chr(10).join(evidence_lines) or "No direct evidence captured."}

Tasks Executed:
{json.dumps([{"task": t["description"], "status": t["status"], "result": t.get("result", "")[:200]} for t in tasks], indent=2)}

Rules:
- Synthesize findings into a clear SRE investigation report.
- Use EXACTLY these sections in the report_content: ## Summary, ## Root Cause, ## Evidence, ## Actions Taken, ## Verification, ## Remaining Issues.
- CRITICAL CONSTITUTION RULE: The final response must be generated ONLY from findings, evidence, and verification results. Completion without evidence is forbidden.

Output ONLY valid JSON:
{{
  "artifact_name": "investigation_report.md",
  "report_content": "The full markdown report."
}}"""

        fallback_json = {
            "artifact_name": "investigation_report.md",
            "report_content": "Investigation concluded. Note: The final report generation failed to parse gracefully, but the raw evidence is available in the timeline."
        }

        try:
            data = self._robust_json_parse(HumanMessage(content=prompt), ["agent_llm"], fallback_response=fallback_json)
            final_report = data.get("report_content", "Investigation completed.")
            artifact_name = data.get("artifact_name", "report.md")
        except Exception:
            final_report = "Investigation completed (fallback response)."
            artifact_name = "report.md"

        return {
            "messages":    [AIMessage(content=final_report)],
            "is_completed": True,
            "is_verified":  True,
            "final_report": final_report,
            "artifact_name": artifact_name,
            "plan":         plan,
            "thinking":     "Final response generated from verified evidence.",
        }
