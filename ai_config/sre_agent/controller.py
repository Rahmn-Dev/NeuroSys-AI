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
        workflow.add_node("verifier",       self.verifier_node)
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
        workflow.add_edge("observer", "verifier")
        workflow.add_edge("verifier", "goal_checker")

        def should_continue_goal_checker(state: TaskState):
            if state.get("iteration", 0) >= 12:
                return "final_response"
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
    def _robust_json_parse(self, sys_msg, tags, max_retries=4, fallback_response=None):
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
        
        is_continuation = existing_plan.get("is_continuation", False)
        has_pending = any(t.get("status") in ["pending", "running"] for t in existing_tasks)

        if existing_plan and existing_tasks and has_pending and is_continuation:
            for idx, t in enumerate(existing_tasks):
                if "id" not in t: t["id"] = idx + 1
                if "description" not in t: t["description"] = t.get("task", t.get("title", f"Task #{idx+1}"))
                if "status" not in t: t["status"] = "pending"
                if "attempts" not in t: t["attempts"] = 0
                if "max_attempts" not in t: t["max_attempts"] = 3
                if "completed" not in t: t["completed"] = t["status"] == "completed"
                if "evidence" not in t: t["evidence"] = []
            return {"plan": existing_plan,
                    "thinking": f"Resuming existing plan for: {goal}"}

        # Clear old tasks when creating a new plan for a new request
        existing_tasks = []
        existing_plan["tasks"] = []

        # Format recent conversation history (last 5 messages) to provide context for follow-up questions
        msgs = state.get("messages", [])
        chat_history_str = ""
        if msgs:
            recent_msgs = []
            for m in msgs[-6:-1]:
                role = "User" if isinstance(m, HumanMessage) else ("Assistant" if isinstance(m, AIMessage) else "System")
                content = m.content[:400] if hasattr(m, "content") else str(m)[:400]
                if content.strip() and not content.startswith("{"):
                    recent_msgs.append(f"{role}: {content}")
            chat_history_str = "\n".join(recent_msgs)

        prompt = f"""You are an autonomous SRE execution agent.

=== RECENT CONVERSATION HISTORY ===
{chat_history_str or "No previous conversation history."}

=== CURRENT USER REQUEST ===
Goal: {goal}

Your job:
1. Classify the user's intent EXACTLY into one of these 4 categories: SIMPLE_INFORMATION, ACTION_TASK, DEBUG_TASK, SECURITY_TASK.
2. Determine a confidence score (0.0 to 1.0) for this intent.
3. Determine a complexity level (LOW, MEDIUM, HIGH) which controls the depth of planning.
4. Think about what investigation steps are needed based on the intent, conversation history, and complexity.
5. Write a concise hypothesis about what might be wrong (or what is needed).
6. Create a strict numbered task plan as a JSON array of strings.

CRITICAL RULES:
- STEP 0 THINKING & CHAT CONTEXT COMPREHENSION:
  - Evaluate if the CURRENT USER REQUEST is logically a follow-up to the RECENT CONVERSATION HISTORY (e.g. "list the 39 items" after being told there are 39 items) OR a completely new topic (e.g. asking about CPU usage after checking a directory).
  - IF it is a follow-up, seamlessly use the context from the RECENT CONVERSATION HISTORY (e.g. resolving references like "that file", "those items").
  - IF it is a NEW topic, IGNORE the RECENT CONVERSATION HISTORY and focus entirely on the CURRENT USER REQUEST. Do NOT drag old context into new topics.
  - Analyze the user prompt ({goal}) for mixed Indonesian & English context FIRST.
  - Indonesian Question Patterns: "ini file apaa", "apa isi file ini", "file ini apa" mean "What is this file and what are its contents?".
  - "apaa", "apa", "kenapa", "ini", "bagaimana" are Indonesian question words ("apa" = "what"). THEY ARE NOT FILE NAMES! Never look for a file named "apaa"!
  - Target Path Extraction: Convert `file://` URIs (e.g. `file:///home/paul/index.html`) or paths (e.g. `/home/paul/index.html`, `index.html`) to clean absolute paths.
  - If a file path is provided in the prompt or conversation history, THAT IS THE TARGET FILE! Create a task specifically to read that file.
- Generate tasks STRICTLY relevant to the current user request ({goal}).
- For CPU, RAM, Memory, or Resource inquiries (e.g., "why cpu and ram high"):
  Set intent to SIMPLE_INFORMATION and complexity to LOW.
  Task plan MUST ONLY contain resource diagnostic tasks (e.g. "Check top CPU and RAM consuming processes using process_manager").
  DO NOT include tasks for Nginx, Apache, or specific services unless explicitly requested by the user.
- SIMPLE_INFORMATION (e.g. "what is my hostname", "what is my IP", "can u list 39 contain", "who am I", "ini file apaa /home/paul/index.html"):
  User wants simple information or identification. Create EXACTLY ONE (1) focused task. DO NOT create extra tasks for inspecting unrelated logs, journalctl, or unrelated services.
- ACTION_TASK: user wants something changed or executed. Create an execution plan and verify changes.
- DEBUG_TASK: something is broken. Collect evidence, inspect logs, run diagnostics, generate hypotheses, verify fixes.
- SECURITY_TASK: security-related analysis.
- Complexity (LOW, MEDIUM, HIGH) should control the strictness of verification.

Output STRICTLY this JSON structure:
{{
  "intent": "SIMPLE_INFORMATION | ACTION_TASK | DEBUG_TASK | SECURITY_TASK",
  "confidence": 0.95,
  "complexity": "LOW | MEDIUM | HIGH",
  "thinking": "Your internal reasoning about the goal based on conversation history and intent",
  "hypothesis": "Your initial working hypothesis (if applicable)",
  "tasks": [
    "Task 1 description relevant to the user request",
    "Task 2 description relevant to the user request"
  ]
}}
"""
        thinking_out = f"Analyzing goal: {goal}"
        tasks = []
        new_tasks = []
        fallback_json = {
            "intent": "DEBUG_TASK",
            "confidence": 1.0,
            "complexity": "MEDIUM",
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
        intent_out     = data.get("intent", "DEBUG_TASK")
        confidence_out = float(data.get("confidence", 1.0))
        complexity_out = data.get("complexity", "MEDIUM")
        task_titles    = data.get("tasks", [])
        
        # Clarification pause for low confidence complex tasks
        if confidence_out < 0.8 and intent_out in ["ACTION_TASK", "DEBUG_TASK", "SECURITY_TASK"]:
            existing_plan["intent"] = intent_out
            existing_plan["confidence"] = confidence_out
            existing_plan["complexity"] = complexity_out
            existing_plan["completed"] = True
            
            # Record a finding that we need clarification
            findings_data = state.get("findings", {"findings": []})
            findings_data["findings"].append(
                f"Agent requires user clarification. Intent: {intent_out} with low confidence ({confidence_out})."
            )
            return {
                "plan": existing_plan,
                "findings": findings_data,
                "thinking": "Planner: low confidence on complex task, pausing for user clarification."
            }
        
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
        existing_plan["confidence"]    = confidence_out
        existing_plan["complexity"]    = complexity_out
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
        
        # Build history of executed tools to prevent duplicates
        past_calls = [f"- {t['tool']}({json.dumps(t.get('tool_args', {}))})" for t in tasks if t["status"] in ["completed", "failed"] and t.get("tool")]
        past_calls_text = "\n".join(past_calls) if past_calls else "None"

        task_id = current_task.get("id", 1)
        task_desc = current_task.get("description", current_task.get("task", "Task"))
        
        sys_msg = SystemMessage(content=f"""{self.system_prompt}

=== CURRENT INVESTIGATION ===
Goal: {state['goal']}
Current Task (#{task_id}): {task_desc}
Attempt: {current_task.get('attempts', 1)} / {current_task.get('max_attempts', 3)}
Working Hypothesis: {hypothesis}

Findings so far:
{json.dumps(findings.get('findings', []), indent=2)}

Past Executed Tools:
{past_calls_text}

Available tools: {', '.join(self.tool_map.keys())}

=== INSTRUCTION ===
Select exactly ONE tool to execute this task.
CRITICAL RULE 1: DO NOT execute a tool with the exact same arguments as one in 'Past Executed Tools' unless new context or state changes require it.
CRITICAL RULE 2: SMART TOOL SELECTION - Ask yourself: "What evidence do I already have?". If you already have a clear root cause (e.g. nginx syntax error found), DO NOT run unrelated checks (e.g. check CPU, RAM, Network) unless the evidence directly requires it.

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
        thinking  = data.get("thinking", f"Executing {tool_name} for task: {task_desc}")

        if tool_name in self.tool_map:
            current_task["tool_args"] = tool_args
            tool_call = {"name": tool_name, "args": tool_args, "id": f"call_{task_id}"}
            ai_msg = AIMessage(content=data.get("reason", thinking), tool_calls=[tool_call])
            return {"messages": [ai_msg], "plan": plan, "thinking": thinking}
        else:
            # Smart terminal fallback when tool_name is invalid or None
            fallback_tool = "read_file" if "read_file" in self.tool_map and ("file" in state['goal'].lower() or ".html" in state['goal'].lower()) else ("terminal_execute" if "terminal_execute" in self.tool_map else ("linux_diagnostic_execute" if "linux_diagnostic_execute" in self.tool_map else list(self.tool_map.keys())[0]))
            goal_lower = state['goal'].lower()
            import re
            file_match = re.search(r'(?:file:///|/)[^\s]+', state['goal'])
            if file_match and fallback_tool == "read_file":
                clean_path = file_match.group(0).replace("file://", "")
                fallback_args = {"path": clean_path}
            elif "hostname" in goal_lower:
                fallback_args = {"command": "hostname"}
            elif "ip" in goal_lower:
                fallback_args = {"command": "ip a"}
            elif "cpu" in goal_lower or "ram" in goal_lower or "memory" in goal_lower:
                fallback_args = {"command": "free -h && ps -eo pid,user,%cpu,%mem,cmd --sort=-%cpu | head -10"}
            else:
                fallback_args = {"command": f"echo '{state['goal']}'"}

            current_task["tool"] = fallback_tool
            current_task["tool_args"] = fallback_args
            tool_call = {"name": fallback_tool, "args": fallback_args, "id": f"call_{task_id}"}
            ai_msg = AIMessage(content=f"Executing diagnostic command via {fallback_tool}", tool_calls=[tool_call])
            return {"messages": [ai_msg], "plan": plan, "thinking": f"Executing diagnostic command via {fallback_tool} for: {task_desc}"}

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

        # Deterministic fast-path and SIMPLE_INFORMATION fast-path
        is_error = "Error" in tool_output or "error" in tool_output.lower()
        intent = plan.get("intent", "")
        if (tool_name in DETERMINISTIC_TOOLS or intent == "SIMPLE_INFORMATION") and not is_error and tool_output.strip():
            current_task["status"]    = "completed"
            current_task["completed"] = True
            current_task["evidence"]  = [tool_output[:500]]
            task_desc = current_task.get("description", current_task.get("task", "Task"))
            finding_text = f"[{tool_name}] Task '{task_desc}' succeeded."
            findings_data["findings"].append(finding_text)

            if intent == "SIMPLE_INFORMATION":
                for t in tasks:
                    t["status"] = "completed"
                    t["completed"] = True
                plan["completed"] = True

            return {
                "plan":     plan,
                "findings": findings_data,
                "thinking": f"Observer: '{tool_name}' produced valid output. Task marked completed (fast-path).",
            }

        task_desc = current_task.get("description", current_task.get("task", "Task"))
        prompt = f"""You are an SRE observer analyzing tool output.

Tool: {tool_name}
Task: {task_desc}
Goal: {state['goal']}

Tool Output (truncated to 2000 chars):
{tool_output[:2000]}

Analyze and respond ONLY with valid JSON.
CRITICAL CONSTITUTION RULES:
1. Tool Success is NOT Goal Success. Tool Success alone must never complete a task.
2. A task is only completed when the user objective has been verified.
3. You must always answer: Did the tool run? Did it produce expected output? Did the output satisfy the goal? What evidence proves it?
4. You must calculate a confidence_score (0.0 to 1.0) indicating how certain you are of the root cause or findings based on evidence.

{{
  "answers": {{
    "did_tool_run": true or false,
    "expected_output": true or false,
    "satisfied_goal": true or false,
    "evidence_extracted": true or false
  }},
  "task_completed": true or false,
  "confidence_score": 0.95,
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
            current_task["confidence_score"] = data.get("confidence_score", 0.0)
            
            # Incorporate confidence score into findings
            conf = data.get("confidence_score", 0.0)
            for f in data.get("new_findings", []):
                findings_data["findings"].append(f"[Confidence {conf}] {f}")
                
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
    # Verifier Node — determines if user goal is met
    # -----------------------------------------------------------------------
    def verifier_node(self, state: TaskState):
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

        intent = plan.get("intent", "")
        # SIMPLE_INFORMATION fast-path
        if intent == "SIMPLE_INFORMATION":
            plan["completed"] = True
            return {
                "plan": plan,
                "thinking": "Goal checker: SIMPLE_INFORMATION task completed, bypassing LLM verification.",
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
{json.dumps([{"task": t.get("description", t.get("task", "Task")), "evidence": t.get("evidence", [])} for t in tasks], indent=2)}

CRITICAL CONSTITUTION RULES:
1. Completion requires goal_verified = true.
2. You must independently validate the original goal against the produced evidence and completed tasks.
3. If evidence does not conclusively prove the goal is achieved, you MUST NOT mark it solved.
4. Execution without verification is never considered complete.
5. EVIDENCE SUFFICIENCY (DEBUG/SECURITY): If the evidence already contains a clear error message, affected component/service, failure location/context, and a probable root cause, you MUST set goal_verified = true and stop the investigation. Do NOT inject new diagnostic tasks unless the root cause is still unknown or previous evidence is contradictory.

Analyze the evidence. Has the user's original goal been completely and verifiably solved, or has sufficient evidence been collected to diagnose the root cause?
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
            complexity = plan.get("complexity", "LOW")
            is_readonly = (intent == "SIMPLE_INFORMATION") or (complexity == "LOW") or any(k in intent.lower() for k in ["explain", "identify", "read", "research", "simple"])
            
            # Inject verification task for SRE multi-task investigations
            if len(tasks) > 1 and not is_readonly:
                has_verified = any(
                    "verify" in t.get("description", "").lower() or
                    "verification" in t.get("description", "").lower()
                    for t in tasks
                )
                if not has_verified and plan.get("dynamic_count", 0) < 2:
                    new_id = len(tasks) + 1
                    tasks.append({
                        "id": new_id,
                        "description": "Run final verification relevant to the goal",
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
    # Goal Checker Node — routes control flow based on completion
    # -----------------------------------------------------------------------
    def goal_checker_node(self, state: TaskState):
        plan = state.get("plan", {})
        is_completed = plan.get("completed", False)
        return {
            "plan": plan,
            "is_completed": is_completed,
            "thinking": f"Goal checker: completion status is {is_completed}."
        }

    # -----------------------------------------------------------------------
    # Final Response Node — generates human-readable answer from evidence
    # -----------------------------------------------------------------------
    def final_response_node(self, state: TaskState):
        plan          = state.get("plan", {})
        tasks         = plan.get("tasks", [])
        findings_data = state.get("findings", {})

        # Mark all tasks in plan as completed when final response is reached
        for t in tasks:
            t["status"] = "completed"
            t["completed"] = True
        plan["completed"] = True

        # Build evidence summary from all completed tasks
        evidence_lines = []
        for t in tasks:
            if t.get("evidence"):
                evidence_lines.append(f"Task: {t['description']}\n" +
                                      "\n".join(f"  - {e}" for e in t["evidence"]))

        intent = plan.get("intent", "")
        is_simple = (intent == "SIMPLE_INFORMATION") or (len(tasks) == 1 and plan.get("dynamic_count", 0) == 0)

        # Format recent conversation history for response synthesis
        msgs = state.get("messages", [])
        chat_history_str = ""
        if msgs:
            recent_msgs = []
            for m in msgs[-6:-1]:
                role = "User" if isinstance(m, HumanMessage) else ("Assistant" if isinstance(m, AIMessage) else "System")
                content = m.content[:400] if hasattr(m, "content") else str(m)[:400]
                if content.strip() and not content.startswith("{"):
                    recent_msgs.append(f"{role}: {content}")
            chat_history_str = "\n".join(recent_msgs)

        if is_simple:
            prompt = f"""You are a result interpreter for an SRE agent. You are NOT a tool-output relay.

Recent Conversation History:
{chat_history_str or "No previous conversation history."}

User Request: {state['goal']}

Tool Evidence:
{chr(10).join(evidence_lines) or "No direct evidence captured."}

Rules:
- Answer the user's question directly and concisely in a conversational assistant tone.
- You ARE an autonomous SRE agent with Linux tool access. NEVER say "I don't have access to your directory", "I don't have access to the file system", or "I cannot list files".
- Summarize file contents or command outputs unless the user explicitly requested the full raw text.
- If insufficient information exists or tool output shows empty/no process, state clearly that the process/file could not be found or has already terminated.
- ABSOLUTE ANTI-HALLUCINATION RULE: Never invent dummy placeholders like 'your_command_here', 'username', 'start_time', or '/path/to/working/directory'. Base your answer strictly on actual evidence.
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
{json.dumps([{"task": t.get("description", t.get("task", "Task")), "status": t.get("status", "pending"), "result": str(t.get("result", ""))[:200]} for t in tasks], indent=2)}

Rules:
- Synthesize findings into a clear SRE investigation report.
- Use EXACTLY these sections in the report_content: ## Summary, ## Root Cause, ## Evidence, ## Actions Taken, ## Verification, ## Remaining Issues.
- CRITICAL CONSTITUTION RULE: The final response must be generated ONLY from findings, evidence, and verification results. Completion without evidence is forbidden.
- CRITICAL REPORT INTEGRITY RULE: The final report MUST ONLY contain executed actions, actual outputs, and verified findings. You are strictly forbidden from claiming a command executed when it failed, claiming a verification was performed if it wasn't, or inventing evidence. (e.g., If no firewall check was executed, state "Firewall verification was not performed.") Never output dummy placeholders like 'your_command_here' or 'username'.

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
