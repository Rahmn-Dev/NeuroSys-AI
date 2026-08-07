"""
NeuroSys-AI Autonomous Controller — Hybrid Parallel Agent Architecture.

Flow:
  User Request
  → Fast-Path Router (trivial queries bypass LLM entirely)
  → Strategic Planner (single LLM call → DAG of tasks with tools pre-selected)
  → Parallel Executor (concurrent asyncio execution of independent tasks)
  → Evidence Observer (single LLM call → aggregate analysis)
  → Goal Checker (route to final response or focused follow-up)
  → Final Response (single LLM call → synthesized answer)

Key design principles:
  - Think Once, Execute Many, Synthesize Once
  - Independent tasks run concurrently (asyncio)
  - Safety checks per-tool before execution
  - Evidence sufficiency stops investigation early when root cause found
  - Zero LLM calls for trivial queries (hostname, uptime, pwd, etc.)
"""

from typing import Annotated, Any, Dict, List, Sequence, TypedDict, Optional
import asyncio
import json
import re
import time

from langchain_core.messages import BaseMessage, SystemMessage, HumanMessage, AIMessage, ToolMessage
from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode

from .safety import SafetyLayer, SafetyVerdict
from .tools.registry import ToolRegistry
from .parallel import ParallelExecutor, TaskResult
from .worker import WorkerScheduler, WorkerState


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

class TaskState(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]
    goal: str
    terminal_cwd: str
    active_workspace: str
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
    # Parallel execution tracking
    execution_history: list  # list of (tool, args_hash) executed — duplicate prevention
    parallel_results: list   # list of TaskResult dicts from parallel executor





# ---------------------------------------------------------------------------
# Controller
# ---------------------------------------------------------------------------

class AutonomousController:
    def __init__(self, llm, tools, system_prompt: str = ""):
        self.llm = llm
        self.tools = tools
        self.tool_node = ToolNode(tools)
        self.system_prompt = system_prompt
        self.tool_map = {t.name: t for t in tools}
        self.safety = SafetyLayer()
        self.registry = ToolRegistry()
        self.parallel_executor = ParallelExecutor(safety=self.safety)
        self.worker_scheduler = WorkerScheduler(llm=llm, tool_map=self.tool_map, safety=self.safety)

    def build_graph(self):
        workflow = StateGraph(TaskState)

        workflow.add_node("fast_path_router",  self.fast_path_router_node)
        workflow.add_node("direct_executor",   self.direct_executor_node)
        workflow.add_node("planner",           self.planner_node)
        workflow.add_node("worker_scheduler",  self.worker_scheduler_node)   # replaces parallel_executor
        workflow.add_node("aggregator",        self.aggregator_node)          # replaces evidence_observer
        workflow.add_node("goal_checker",      self.goal_checker_node)
        workflow.add_node("final_response",    self.final_response_node)

        workflow.set_entry_point("fast_path_router")

        def route_after_fast_path(state: TaskState):
            if state.get("plan", {}).get("fast_path"):
                return "direct_executor"
            return "planner"

        workflow.add_conditional_edges("fast_path_router", route_after_fast_path,
                                       {"direct_executor": "direct_executor",
                                        "planner": "planner"})

        workflow.add_edge("direct_executor", "final_response")
        workflow.add_edge("planner",         "worker_scheduler")
        workflow.add_edge("worker_scheduler", "aggregator")
        workflow.add_edge("aggregator",      "goal_checker")

        def route_after_goal_checker(state: TaskState):
            if state.get("iteration", 0) >= 8:
                return "final_response"
            if state.get("plan", {}).get("completed", False):
                return "final_response"
            if state.get("requires_approval", False):
                return "final_response"
            return "planner"

        workflow.add_conditional_edges("goal_checker", route_after_goal_checker,
                                       {"final_response": "final_response",
                                        "planner": "planner"})

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
                if 'response' in locals():
                    messages.append(response)
                messages.append(HumanMessage(content=f"Your previous output failed to parse as valid JSON. Error: {str(e)}\n\nPlease repair the JSON and output STRICTLY valid JSON ONLY. Do not include markdown fences or any other text."))

    # -----------------------------------------------------------------------
    # NODE: Fast-Path Router — zero LLM calls for trivial queries
    # -----------------------------------------------------------------------
    def fast_path_router_node(self, state: TaskState):
        goal = state["goal"].strip()
        intent = "SIMPLE_INFORMATION"

        # 1. Tool Discovery & Semantic Ranking
        from .tools.registry import ToolRegistry
        registry = ToolRegistry()
        
        # Call the semantic ranker
        ranked_tools = registry.rank_capabilities(goal, intent)
        
        # Filter down to tools that are actually loaded in this run context (self.tool_map)
        available_ranked = [t for t in ranked_tools if t["name"] in self.tool_map]
        
        # Take top 5 candidates
        candidates = available_ranked[:5]
        
        # If no candidates, fallback
        if not candidates:
            return {
                "plan": state.get("plan", {}),
                "thinking": "Micro Tool Selector: No tools available for capability ranking.",
            }
            
        # 2. Fast bypass if only 1 highly relevant tool exists?
        if len(available_ranked) == 1:
            best = available_ranked[0]
            if not getattr(best["tool"], "args_schema", None):
                # Ensure safety gate is passed even on bypass
                if best["meta"].safe_fast_path:
                    return {
                        "plan": {
                            "fast_path": True,
                            "intent": "SIMPLE_INFORMATION",
                            "tasks": [{
                                "id": "FP",
                                "description": f"Fast-path: {best['name']}",
                                "tool": best["name"],
                                "tool_args": {},
                                "status": "pending",
                                "depends_on": [],
                                "group": "system",
                            }],
                            "completed": False,
                        },
                        "thinking": f"Micro Tool Selector: Only 1 tool discovered ({best['name']}), bypassing LLM.",
                    }
        
        # 3. Micro Tool Selector LLM call
        tools_prompt_lines = []
        for c in candidates:
            meta = c["meta"]
            args_str = ""
            try:
                schema = c["tool"].args_schema.model_json_schema() if getattr(c["tool"], "args_schema", None) else {}
                props = schema.get("properties", {})
                if props:
                    args_str = "{" + ", ".join(f'"{k}": "{v.get("type","any")}"' for k, v in props.items()) + "}"
            except Exception:
                pass
            
            tools_prompt_lines.append(
                f"- {c['name']}:\n"
                f"  Capabilities: {', '.join(meta.capabilities) if meta.capabilities else 'None'}\n"
                f"  Supported Intents: {', '.join(meta.supported_intents) if meta.supported_intents else 'None'}\n"
                f"  Capability Score: {c['capability_match_score']:.2f}\n"
                f"  Final Rank Score: {c['final_score']:.2f}\n"
                f"  Args schema: {args_str}"
            )
            
        tools_prompt = "\n".join(tools_prompt_lines)
        
        prompt = f"""You are the Micro Tool Selector. Your ONLY job is to select exactly one tool for a simple informational query.

User Query: {goal}

Candidate Tools (Ranked by semantic capability score):
{tools_prompt}

Rules:
1. Tool capabilities represent the actual abilities of a tool. Match user intent against capabilities before deciding.
2. Choose the single most relevant tool to instantly answer the query.
3. If the query requires complex investigation, planning, or multiple tools, you MUST return null for the tool.
4. Dedicated tools should be strongly preferred over generic tools for simple lookups.
5. Provide a confidence score (0.0 to 1.0). If you are guessing, confidence should be low (<0.8).

Output EXACTLY valid JSON matching this format:
{{
  "tool": "tool_name_or_null",
  "args": {{"arg1": "value"}},
  "confidence": 0.95
}}"""

        fallback = {"tool": None, "args": {}, "confidence": 0.0}
        
        from langchain_core.messages import HumanMessage
        try:
            data = self._robust_json_parse(HumanMessage(content=prompt), ["agent_llm"], fallback_response=fallback)
        except Exception:
            data = fallback
            
        tool_choice = data.get("tool")
        confidence = data.get("confidence", 0.0)
        
        # 4. Safety gate rules
        if tool_choice and tool_choice in self.tool_map:
            meta = registry.get_metadata(tool_choice)
            is_safe = meta.safe_fast_path if meta else False
            
            # Phase A.5: Fallback if confidence < 0.7
            if confidence >= 0.7 and is_safe and intent == "SIMPLE_INFORMATION":
                return {
                    "plan": {
                        "fast_path": True,
                        "intent": "SIMPLE_INFORMATION",
                        "tasks": [{
                            "id": "FP",
                            "description": f"Fast-path: {tool_choice}",
                            "tool": tool_choice,
                            "tool_args": data.get("args", {}),
                            "status": "pending",
                            "depends_on": [],
                            "group": "system",
                        }],
                        "completed": False,
                    },
                    "thinking": f"Micro Tool Selector: Selected '{tool_choice}' with confidence {confidence:.2f}.",
                }
            
            # Log why it failed the gate
            if confidence < 0.7:
                reason = f"confidence {confidence:.2f} < 0.7"
            elif not is_safe:
                reason = "safe_fast_path=False"
            else:
                reason = "intent not SIMPLE_INFORMATION"
                
            return {
                "plan": state.get("plan", {}),
                "thinking": f"Micro Tool Selector: Deferred to Planner ({reason}).",
            }
            
        return {
            "plan": state.get("plan", {}),
            "thinking": f"Micro Tool Selector: Deferred to Planner (tool={tool_choice}).",
        }

        # Not a fast-path query → route to planner
        return {
            "plan": state.get("plan", {}),
            "thinking": "Complex query — routing to strategic planner.",
        }

    # -----------------------------------------------------------------------
    # NODE: Direct Executor — runs fast-path tool directly, no LLM
    # -----------------------------------------------------------------------
    def direct_executor_node(self, state: TaskState):
        plan = state.get("plan", {})
        tasks = plan.get("tasks", [])
        if not tasks:
            return {"plan": plan, "thinking": "Direct executor: no tasks to execute."}

        task = tasks[0]
        tool_name = task.get("tool", "")
        tool_args = task.get("tool_args", {})
        tool_obj = self.tool_map.get(tool_name)

        if not tool_obj:
            task["status"] = "failed"
            task["result"] = f"Tool '{tool_name}' not found."
            return {"plan": plan, "thinking": f"Direct executor: tool '{tool_name}' not found."}

        try:
            output = tool_obj.invoke(tool_args)
            output_str = str(output) if output else ""
        except Exception as e:
            output_str = f"Error: {str(e)}"

        task["status"] = "completed"
        task["completed"] = True
        task["result"] = output_str[:2000]
        task["evidence"] = [output_str[:2000]]
        plan["completed"] = True

        findings = state.get("findings", {"findings": []})
        findings["findings"].append(f"[{tool_name}] {output_str[:500]}")

        return {
            "plan": plan,
            "findings": findings,
            "thinking": f"Direct executor: '{tool_name}' completed (fast-path).",
        }

    # -----------------------------------------------------------------------
    # NODE: Strategic Planner — OBJECTIVES ONLY (no tool/tool_args)
    # -----------------------------------------------------------------------
    def planner_node(self, state: TaskState):
        goal = state["goal"]
        existing_plan = state.get("plan", {})
        iteration = state.get("iteration", 0)
        is_followup = iteration > 0
        is_continuation = existing_plan.get("is_continuation", False)



        # Extract file:// URIs and resolve to absolute paths
        # so both the planner and workers get concrete paths, not guesses
        import re as _re
        _file_uri_re = _re.compile(r'file:///([^\s]+)')
        _file_matches = _file_uri_re.findall(goal)
        extracted_files_note = ""
        if _file_matches:
            resolved = [f'/{p}' for p in _file_matches]
            # Clean up goal: replace URIs with resolved paths
            for fpath in _file_matches:
                goal = goal.replace(f'file:///{fpath}', f'/{fpath}')
            extracted_files_note = f"\nEXTRACTED FILE PATHS (use these exact paths in worker goals): {', '.join(resolved)}\n"


        # Format recent conversation history
        msgs = state.get("messages", [])
        chat_history_str = ""
        if msgs and (is_continuation or is_followup):
            recent_msgs = []
            for m in msgs[-6:-1]:
                role = "User" if isinstance(m, HumanMessage) else ("Assistant" if isinstance(m, AIMessage) else "System")
                content = m.content[:400] if hasattr(m, "content") else str(m)[:400]
                if content.strip() and not content.startswith("{"):
                    recent_msgs.append(f"{role}: {content}")
            chat_history_str = "\n".join(recent_msgs)

        followup_note = ""
        if is_followup:
            prev_workers = existing_plan.get("workers", [])
            # Fix 3: Include verification state and domain coverage in prior summary.
            # Fix 5 merge-back ensures prev_workers now contains real execution state.
            if prev_workers:
                prior_summary = "\n".join(
                    f"  Worker {w.get('id','?')}: {w.get('goal','')} — "
                    f"confidence={w.get('confidence_score', 0):.2f}, "
                    f"root_cause={w.get('root_cause','none')}, "
                    f"verified={w.get('has_verified_evidence', False)}, "
                    f"domains_covered={w.get('investigation_coverage', [])}"
                    for w in prev_workers
                )
                # Fix 3: Satisfied domains hard prohibition
                satisfied_domains = existing_plan.get("satisfied_domains", [])
                satisfied_note = ""
                if satisfied_domains:
                    satisfied_note = f"""
=== PERMANENTLY SATISFIED DOMAINS ===
The following investigation domains have verified root-cause evidence and are CLOSED.
Do NOT generate any worker targeting these domains: {', '.join(satisfied_domains)}
"""
                followup_note = f"""
=== FOLLOW-UP: PREVIOUS WORKERS COMPLETED ===
Prior results:
{prior_summary}
{satisfied_note}
Generate ONLY workers for remaining UNRESOLVED aspects.
Do NOT repeat goals that were already investigated.
Do NOT create workers for satisfied domains listed above.
"""

        terminal_cwd_note = (
            f"\n(Note: User's terminal is currently at {state.get('terminal_cwd')} "
            f"— do not assume the issue is located here unless explicitly stated)"
        ) if state.get('terminal_cwd') else ""
        
        prompt = f"""You are a strategic SRE planner. You assign investigation objectives to autonomous workers.

=== RECENT CONVERSATION HISTORY ===
{chat_history_str or "No previous conversation history."}

=== CURRENT USER REQUEST ===
Goal: {goal}{terminal_cwd_note}
{extracted_files_note}{followup_note}
Current Iteration: {iteration}

Your job:
1. Classify intent: SIMPLE_INFORMATION, ACTION_TASK, DEBUG_TASK, SECURITY_TASK.
2. Determine complexity: LOW, MEDIUM, HIGH.
3. Classify incident type: service failure, resource issue, network issue, application error, etc.
4. Define targeted worker objectives — one per narrow diagnostic domain.

CRITICAL RULES:
- Each worker gets a GOAL (what to investigate AND remediate), NOT a list of commands.
- Give each worker an ACTIONABLE objective (e.g. "Validate and fix configuration files" instead of just "Validate").
- Workers will autonomously decide which tools and commands to run.
- Independent workers (depends_on: []) run in parallel. Use this for non-interfering checks.
- ADAPTIVE WORKER SCALING:
  - If Current Iteration is 0 (Phase 1): Start with ONLY minimal high-probability diagnostic workers (e.g. service status, config validation, application logs). Do NOT generate workers for broad resource checks (CPU/memory/disk) yet.
  - If Current Iteration > 0 (Phase 2+): Analyze evidence gaps from prior results and dynamically expand the investigation (e.g. resource checks, network checks) ONLY if Phase 1 failed to identify the root cause.
- For service failures, dynamically identify the exact service (e.g. Service A, Runtime B) and generate narrow, application-specific workers.
- Do NOT generate broad "Analyze entire system" workers. Give each worker one clear objective.
- SIMPLE_INFORMATION: 1 worker max.
- Do NOT generate 'tool' or 'tool_args' — workers decide their own execution strategy.
- DO NOT create workers for unrelated services unless explicitly requested.
- You MUST define `expected_diagnostic_domains` dynamically based on the exact issue type (e.g. database failure -> ["database_status", "connection_logs"]; memory issue -> ["memory_usage", "process_analysis"]).
- If EXTRACTED FILE PATHS are provided above, you MUST include the exact absolute path in the worker goal.

Context rules:
- Indonesian question words ("apa", "kenapa", "ini", "apaa") are NOT file names.
- Extract file paths from `file://` URIs or absolute paths.

Output STRICTLY this JSON:
{{
  "intent": "SIMPLE_INFORMATION | ACTION_TASK | DEBUG_TASK | SECURITY_TASK",
  "complexity": "LOW | MEDIUM | HIGH",
  "thinking": "Incident classification and strategic reasoning",
  "hypothesis": "Initial hypothesis about what's wrong",
  "workers": [
    {{
      "id": "A",
      "goal": "Check systemd service status for target application and restart/fix if failed",
      "expected_diagnostic_domains": ["service_status"],
      "depends_on": [],
      "priority": "high"
    }},
    {{
      "id": "B",
      "goal": "Validate configuration files for target application and fix any syntax errors",
      "expected_diagnostic_domains": ["configuration"],
      "depends_on": [],
      "priority": "high"
    }},
    {{
      "id": "C",
      "goal": "Check system resources (CPU, memory, disk)",
      "expected_diagnostic_domains": ["resource_usage"],
      "depends_on": ["A", "B"],
      "priority": "low"
    }}
  ]
}}
"""
        fallback_json = {
            "intent": "DEBUG_TASK",
            "complexity": "MEDIUM",
            "thinking": f"Fallback: Generating default worker for {goal}",
            "hypothesis": "",
            "workers": [{"id": "A", "goal": goal, "expected_diagnostic_domains": [], "depends_on": [], "priority": "high"}]
        }

        data = self._robust_json_parse(
            HumanMessage(content=prompt),
            ["planner_llm"],
            fallback_response=fallback_json
        )

        intent_out     = data.get("intent", "DEBUG_TASK")
        complexity_out = data.get("complexity", "MEDIUM")
        thinking_out   = data.get("thinking", f"Analyzing: {goal}")
        hypothesis_out = data.get("hypothesis", "")
        raw_workers    = data.get("workers", [])

        # Normalize worker specs
        worker_specs = []
        for i, w in enumerate(raw_workers):
            worker_specs.append({
                "id": w.get("id", chr(65 + i)),
                "goal": w.get("goal", goal),
                "expected_diagnostic_domains": w.get("expected_diagnostic_domains", []),
                "depends_on": w.get("depends_on", []),
                "priority": w.get("priority", "medium"),
                "status": "pending",
                "terminal_cwd": state.get("terminal_cwd", ""),
                "active_workspace": state.get("active_workspace", "")
            })

        if not worker_specs:
            worker_specs = [{
                "id": "A", "goal": goal, "expected_diagnostic_domains": [], "depends_on": [], "priority": "high", "status": "pending",
                "terminal_cwd": state.get("terminal_cwd", ""),
                "active_workspace": state.get("active_workspace", "")
            }]

        plan = {
            "intent": intent_out,
            "complexity": complexity_out,
            "workers": worker_specs,
            # Keep backward-compat 'tasks' field (used by DB sync in engine.py)
            "tasks": [{
                "id": w["id"],
                "description": w["goal"],
                "status": "pending",
                "completed": False,
                "depends_on": w.get("depends_on", []),
            } for w in worker_specs],
            "completed": False,
            "dynamic_count": existing_plan.get("dynamic_count", 0) + (1 if is_followup else 0),
            "investigation_id": existing_plan.get("investigation_id", ""),
            "title": existing_plan.get("title", goal[:40]),
            "created_at": existing_plan.get("created_at", ""),
        }

        return {
            "plan": plan,
            "iteration": iteration,
            "thinking": thinking_out,
            "hypothesis": hypothesis_out,
        }

    # -----------------------------------------------------------------------
    # NODE: Worker Scheduler — launches InvestigationWorkers concurrently
    # -----------------------------------------------------------------------
    def worker_scheduler_node(self, state: TaskState):
        plan = state.get("plan", {})
        worker_specs = plan.get("workers", [])
        findings = state.get("findings", {})
        if "findings" not in findings:
            findings["findings"] = []

        # Fix 3 (defence-in-depth): Also filter out workers whose diagnostic domains
        # are already satisfied, even if planner somehow generated them.
        satisfied_domains = set(plan.get("satisfied_domains", []))
        pending_specs = [
            w for w in worker_specs
            if w.get("status") == "pending"
            and not any(
                domain in satisfied_domains
                for domain in w.get("expected_diagnostic_domains", [])
            )
        ]
        if not pending_specs:
            return {
                "plan": plan,
                "findings": findings,
                "thinking": "Worker scheduler: no pending workers (all completed or domains satisfied).",
            }

        # Run all workers concurrently via WorkerScheduler
        worker_states: List[WorkerState] = self.worker_scheduler.run_workers_sync(pending_specs)

        # Merge worker results back into plan
        total_duration = 0.0
        requires_approval = False
        worker_results = []
        
        def collect_workers(ws):
            worker_result = {
                "id": ws.id,
                "goal": ws.goal,
                "status": ws.status,
                "confidence_score": ws.confidence.score,
                "confidence_summary": ws.confidence.summary(),
                "hypothesis": ws.hypothesis,
                "root_cause": ws.root_cause,
                "recommendations": ws.recommendations,
                "iterations": ws.iteration,
                "findings_count": len(ws.findings),
                "children_count": len(ws.children),
                "findings": ws.findings,
                "is_child": getattr(ws, "is_child", False),
                "parent_id": getattr(ws, "parent_id", None),
                # Evidence quality: True only if any finding is verified root cause
                "has_verified_evidence": ws.confidence.has_verified_evidence,
                "evidence_chain": getattr(ws, "evidence_chain", []),
                "evidence_chain_confidence": getattr(ws, "evidence_chain_confidence", 0.0),
                "investigation_coverage": getattr(ws, "investigation_coverage", []),
                "max_evidence_relevance": max([e.relevance_score for e in ws.confidence.evidence] + [0.0]),
                "children": [{
                    "id": c.id, "goal": c.goal,
                    "confidence_score": c.confidence.score,
                    "root_cause": c.root_cause,
                    "findings": c.findings,
                } for c in ws.children],
            }
            worker_results.append(worker_result)

            # Update tasks list for DB sync compatibility
            for t in plan.get("tasks", []):
                if t["id"] == ws.id:
                    t["status"] = ws.status
                    t["completed"] = ws.completed
                    t["result"] = ws.root_cause or ws.hypothesis
                    t["evidence"] = [f.get("output", "")[:300] for f in ws.findings[:3]]

            # Add findings to global findings
            for f in ws.findings:
                findings["findings"].append(
                    f"[Worker {ws.id}][{f.get('signal','?')}] "
                    f"{f.get('tool','?')}({json.dumps(f.get('args',{}))[:60]}): "
                    f"{str(f.get('output',''))[:200]}"
                )
                
            for child in getattr(ws, "children", []):
                collect_workers(child)

        for ws in worker_states:
            total_duration += ws.total_duration
            if ws.requires_approval:
                requires_approval = True
            collect_workers(ws)

        # Fix 5: Merge execution results back into plan["workers"] specs.
        # This is the structural fix: without this merge, plan["workers"] keeps
        # "status": "pending" indefinitely, so the scheduler re-runs workers on
        # every subsequent iteration even after they completed with verified evidence.
        # This fix is independent of satisfied_domains — it works even if domain
        # propagation fails for any reason.
        result_map = {wr["id"]: wr for wr in worker_results}
        for spec in plan.get("workers", []):
            result = result_map.get(spec["id"])
            if result:
                spec["status"] = result.get("status", "completed")
                spec["root_cause"] = result.get("root_cause", "")
                spec["has_verified_evidence"] = result.get("has_verified_evidence", False)
                spec["confidence_score"] = result.get("confidence_score", 0.0)
                spec["investigation_coverage"] = result.get("investigation_coverage", [])

        plan["worker_results"] = worker_results

        # Serialize parallel_results for engine.py event handling
        parallel_results = [{
            "task_id": wr["id"],
            "tool_name": f"worker_{wr['id']}",
            "output": wr["root_cause"] or wr["hypothesis"] or f"{wr['findings_count']} findings",
            "exit_code": 0,
            "duration": total_duration / max(len(worker_results), 1),
            "safety_verdict": "approved",
            "error": "",
        } for wr in worker_results]

        return {
            "plan": plan,
            "findings": findings,
            "parallel_results": parallel_results,
            "requires_approval": requires_approval,
            "thinking": (
                f"Worker scheduler: {len(worker_states)} workers completed in {total_duration:.1f}s. "
                f"Highest confidence: {max((w.confidence.score for w in worker_states), default=0):.2f}"
            ),
        }

    # -----------------------------------------------------------------------
    # NODE: Aggregator — synthesizes all worker findings (replaces evidence_observer)
    # -----------------------------------------------------------------------
    def aggregator_node(self, state: TaskState):
        plan = state.get("plan", {})
        findings_data = state.get("findings", {})
        if "findings" not in findings_data:
            findings_data["findings"] = []

        intent = plan.get("intent", "")
        worker_results = plan.get("worker_results", [])

        # SIMPLE_INFORMATION fast-path: skip LLM aggregation
        if intent == "SIMPLE_INFORMATION" and worker_results:
            plan["completed"] = True
            return {
                "plan": plan,
                "findings": findings_data,
                "thinking": "Aggregator: SIMPLE_INFORMATION — worker completed, skipping LLM synthesis.",
            }

        # Compute global confidence from all workers
        worker_scores = [w.get("confidence_score", 0) for w in worker_results]
        global_confidence = max(worker_scores) if worker_scores else 0.0
        plan["global_confidence"] = global_confidence

        # Fix 2: Two-path acceptance for verified root causes.
        # Path A: Full LLM-validated evidence chain (existing strict gate).
        # Path B: Deterministic rule-engine verified direct_error — accepted without LLM chain.
        # Acceptance is based on evidence STATE (finding fields), never on root_cause string content.
        def _is_deterministic_verified(w: dict) -> bool:
            """True if any finding records a rule-engine verified direct_error."""
            return any(
                f.get("evidence_type") == "direct_error" and f.get("verified") is True
                for f in w.get("findings", [])
            )

        all_root_causes = [w["root_cause"] for w in worker_results if w.get("root_cause")]
        verified_root_causes = [
            w["root_cause"] for w in worker_results
            if w.get("root_cause") and (
                # Path A: LLM-validated evidence chain
                (
                    w.get("has_verified_evidence", False)
                    and len(w.get("evidence_chain", [])) >= 2
                    and w.get("evidence_chain_confidence", 0.0) >= 0.8
                    and w.get("max_evidence_relevance", 0.0) >= 0.8
                    and len(w.get("investigation_coverage", [])) >= 2
                )
                # Path B: Deterministic rule-engine direct error (verified=True, evidence_type=direct_error)
                or _is_deterministic_verified(w)
            )
        ]
        all_recommendations = []
        for w in worker_results:
            all_recommendations.extend(w.get("recommendations", []))

        contradictions = []
        for w in worker_results:
            cs = w.get("confidence_summary", {})
            if cs.get("contradiction_count", 0) > 0:
                contradictions.append(f"Worker {w['id']} has {cs['contradiction_count']} contradictions")

        # Completion gate: verified root cause found → mark complete and set satisfied_domains.
        from .worker import WORKER_CONFIDENCE_THRESHOLD
        if verified_root_causes:
            # Collect all investigation domains covered by verified workers for Fix 3 (planner prohibition)
            all_satisfied = []
            for w in worker_results:
                if _is_deterministic_verified(w) or w.get("has_verified_evidence"):
                    all_satisfied.extend(w.get("investigation_coverage", []))
            plan["satisfied_domains"] = list(set(all_satisfied))
            plan["completed"] = True
            findings_data["findings"].append(f"[Aggregator] Verified root cause: {'; '.join(verified_root_causes[:3])}")
            return {
                "plan": plan,
                "findings": findings_data,
                "thinking": f"Aggregator: verified root cause accepted (causes={verified_root_causes}).",
                "resolution_plan": list(dict.fromkeys(all_recommendations))[:10],
            }
        
        # Workers claimed a root cause but without verified evidence, or no root cause found yet
        # Continue to LLM synthesis to give the aggregator LLM a chance to assess whether evidence is sufficient.

        # Not confident enough — one LLM call to synthesize and decide
        evidence_summary = []
        for w in worker_results:
            top_findings = w.get("findings", [])[:4]
            finding_lines = [f"    [{f.get('signal','?')}] {f.get('tool','?')}: {str(f.get('output',''))[:300]}" for f in top_findings]
            evidence_summary.append(
                f"Worker {w['id']} (goal: {w['goal']}, confidence: {w['confidence_score']:.2f}):\n" +
                "\n".join(finding_lines)
            )

        prompt = f"""You are the global aggregator for a parallel SRE investigation.

Goal: {state['goal']}
Global confidence so far: {global_confidence:.2f}
Worker contradictions: {contradictions or 'None'}

=== WORKER EVIDENCE SUMMARY ===
{chr(10).join(evidence_summary)}

Analyze all worker evidence together:
1. Is the root cause identified across all workers?
2. Are there contradictions between worker findings?
3. Is overall confidence sufficient (>= {WORKER_CONFIDENCE_THRESHOLD})?

EVIDENCE PRIORITY HIERARCHY (Higher priority MUST ALWAYS override lower priority):
Priority 1: Direct deterministic failure evidence (e.g. config syntax errors, crash logs)
Priority 2: Application/service specific logs
Priority 3: Service manager failure state
Priority 4: Generic system symptoms (e.g. disk permission denied, high memory)

CRITICAL RULE: Priority 4 generic environmental evidence MUST NEVER override Priority 1/2/3 direct causal root causes.

Respond ONLY with valid JSON:
{{
  "sufficient": true or false,
  "confidence": 0.0-1.0,
  "root_cause": "unified root cause or null",
  "summary": "brief synthesis",
  "recommendations": ["step 1", "step 2"]
}}
"""
        fallback = {"sufficient": True, "confidence": global_confidence,
                    "root_cause": None, "summary": "Aggregation complete.",
                    "recommendations": all_recommendations[:5]}

        data = self._robust_json_parse(
            HumanMessage(content=prompt),
            ["aggregator_llm"],
            fallback_response=fallback
        )

        # The aggregator should only mark completed if it actually identified a valid root cause
        # or confirmed that the system is completely healthy and no root cause exists.
        has_root_cause = bool(data.get("root_cause"))
        if (data.get("sufficient") or data.get("confidence", 0) >= WORKER_CONFIDENCE_THRESHOLD) and has_root_cause:
            plan["completed"] = True

        if data.get("root_cause"):
            findings_data["findings"].append(f"[Aggregator] {data['root_cause']}")

        return {
            "plan": plan,
            "findings": findings_data,
            "thinking": f"Aggregator (LLM): sufficient={data.get('sufficient')}, confidence={data.get('confidence', 0):.2f}. {data.get('summary', '')}",
            "resolution_plan": data.get("recommendations", []),
        }
        plan = state.get("plan", {})
        tasks = plan.get("tasks", [])
        findings_data = state.get("findings", {})
        if "findings" not in findings_data:
            findings_data["findings"] = []

        intent = plan.get("intent", "")

        # SIMPLE_INFORMATION fast-path: skip LLM analysis
        completed_tasks = [t for t in tasks if t.get("completed")]
        if intent == "SIMPLE_INFORMATION" and completed_tasks:
            plan["completed"] = True
            return {
                "plan": plan,
                "findings": findings_data,
                "thinking": "Evidence observer: SIMPLE_INFORMATION — all tasks completed, skipping LLM analysis.",
            }

        # Build combined evidence block for LLM analysis
        evidence_block = []
        for t in tasks:
            status_str = t.get("status", "pending")
            result_str = t.get("result", "No output")
            evidence_block.append(f"Task [{t['id']}] '{t['description']}' ({status_str}):\n{result_str[:800]}")

        combined_evidence = "\n\n".join(evidence_block)

        prompt = f"""You are the Evidence Observer for an SRE investigation. Analyze ALL task results together.

Goal: {state['goal']}

=== COMBINED EVIDENCE FROM ALL TASKS ===
{combined_evidence}

Analyze the evidence and determine:
1. Is the root cause identified? (specific error message, file, line number)
2. Is the affected component/service identified?
3. Is there sufficient evidence to answer the user's question?
4. What is the confidence level?

EVIDENCE SUFFICIENCY RULES:
- If a clear error message with file path and context is found → sufficient (set sufficient=true)
- If a service status clearly shows the problem → sufficient
- If all diagnostic checks passed with no errors → sufficient (report "all healthy")
- Only mark insufficient if evidence is genuinely contradictory or incomplete

Respond ONLY with valid JSON:
{{
  "sufficient": true or false,
  "confidence": 0.95,
  "root_cause": "The identified root cause or null",
  "affected_component": "The affected service/file or null",
  "summary": "Brief summary of what the evidence shows",
  "hypothesis_update": "Updated hypothesis based on all evidence",
  "resolution_steps": ["step 1 to fix", "step 2"]
}}
"""
        fallback_json = {
            "sufficient": True,
            "confidence": 0.7,
            "root_cause": None,
            "affected_component": None,
            "summary": "Evidence analysis completed.",
            "hypothesis_update": "",
            "resolution_steps": []
        }

        data = self._robust_json_parse(
            HumanMessage(content=prompt),
            ["observer_llm"],
            fallback_response=fallback_json
        )

        is_sufficient = data.get("sufficient", False)
        confidence = data.get("confidence", 0.5)
        hypothesis_update = data.get("hypothesis_update", "")
        resolution_steps = data.get("resolution_steps", [])
        summary = data.get("summary", "")

        if summary:
            findings_data["findings"].append(f"[Observer] {summary}")

        if is_sufficient or confidence >= 0.85:
            plan["completed"] = True

        return {
            "plan": plan,
            "findings": findings_data,
            "thinking": f"Evidence observer: {'sufficient' if is_sufficient else 'insufficient'} (confidence={confidence}). {summary}",
            "hypothesis": hypothesis_update if hypothesis_update else state.get("hypothesis", ""),
            "resolution_plan": resolution_steps,
        }

    # -----------------------------------------------------------------------
    # NODE: Goal Checker — routes to final_response or back to planner
    # -----------------------------------------------------------------------
    def goal_checker_node(self, state: TaskState):
        plan = state.get("plan", {})
        is_completed = plan.get("completed", False)
        iteration = state.get("iteration", 0)
        dynamic_count = plan.get("dynamic_count", 0)

        # Force completion if too many follow-up rounds
        if dynamic_count >= 3:
            plan["completed"] = True
            is_completed = True

        return {
            "plan": plan,
            "is_completed": is_completed,
            "iteration": iteration + 1,
            "thinking": f"Goal checker: completed={is_completed}, iteration={iteration + 1}, dynamic_count={dynamic_count}.",
        }

    # -----------------------------------------------------------------------
    # NODE: Final Response — generates human-readable answer from evidence
    # -----------------------------------------------------------------------
    def final_response_node(self, state: TaskState):
        plan = state.get("plan", {})
        tasks = plan.get("tasks", [])
        findings_data = state.get("findings", {})

        # Mark all tasks as completed
        for t in tasks:
            t["status"] = "completed"
            t["completed"] = True
        plan["completed"] = True

        # Build evidence summary
        evidence_lines = []
        for t in tasks:
            if t.get("evidence"):
                evidence_lines.append(f"Task: {t['description']}\n" +
                                      "\n".join(f"  - {e}" for e in t["evidence"]))

        intent = plan.get("intent", "")
        is_simple = (intent == "SIMPLE_INFORMATION") or (len(tasks) <= 2 and plan.get("dynamic_count", 0) == 0)

        # Format recent conversation history
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

        # ---------- DETERMINISTIC BYPASS FOR SIMPLE FACTUAL QUERIES ----------
        # When intent is SIMPLE_INFORMATION and we have actual tool output,
        # skip LLM synthesis entirely — just return the raw output directly.
        # This eliminates the hallucination risk for "what time now", "hostname", etc.
        if is_simple:
            # Collect raw tool outputs from tasks
            raw_outputs = []
            for t in tasks:
                raw = t.get("result") or (t.get("evidence") or [None])[0]
                if raw and str(raw).strip() and "error" not in str(raw).lower()[:50]:
                    raw_outputs.append(str(raw).strip())

            # Also scan findings for tool outputs
            findings_texts = findings_data.get("findings", [])
            for f in findings_texts:
                if f and not f.startswith("[Observer]") and len(f) > 5:
                    raw_outputs.append(f)

            if raw_outputs:
                # Extract the most useful output (first non-empty one)
                primary_output = raw_outputs[0]

                # Try to parse JSON tool output (terminal_execute returns JSON)
                try:
                    parsed = json.loads(primary_output)
                    stdout = parsed.get("stdout", "").strip()
                    if stdout:
                        primary_output = stdout
                except Exception:
                    pass

                # Generate a natural language wrapper around the raw output
                # Use LLM only if the output is not self-evident (e.g. complex JSON)
                goal_lower_check = state['goal'].lower()
                # For date/time queries, just return the value directly
                time_keywords = ["time", "date", "hostname", "whoami", "uptime", "uname", "ip"]
                if any(kw in goal_lower_check for kw in time_keywords):
                    final_report = primary_output
                    return {
                        "messages":    [AIMessage(content=final_report)],
                        "is_completed": True,
                        "is_verified":  True,
                        "final_report": final_report,
                        "artifact_name": "response.md",
                        "plan":         plan,
                        "thinking":     "Final response: deterministic bypass — raw tool output returned.",
                    }

            # Fallback to LLM for simple queries where raw output alone isn't enough
            prompt = f"""You are a result interpreter for an SRE agent.

Recent Conversation History:
{chat_history_str or "No previous conversation history."}

User Request: {state['goal']}

Raw Tool Output (use THIS to answer — do NOT ignore it):
{chr(10).join(raw_outputs) if raw_outputs else "No output captured."}

Tool Evidence:
{chr(10).join(evidence_lines) or "No direct evidence captured."}

CRITICAL RULES:
- You HAVE already executed a real Linux command and received the output above.
- NEVER say "I don't have access", "I cannot execute", or "I'm sorry".
- NEVER refuse. NEVER hallucinate. Answer ONLY from the raw tool output above.
- If raw output is empty, say "The command returned no output".
- Give a short, direct, conversational answer.

Output ONLY valid JSON:
{{
  "artifact_name": "response.md",
  "report_content": "Your direct factual answer based on the tool output."
}}"""
        else:
            prompt = f"""You are a result interpreter for an SRE agent. You are NOT a tool-output relay.

Recent Conversation History:
{chat_history_str or "No previous conversation history."}

User Request: {state['goal']}

Investigation Findings:
{json.dumps(findings_data.get('findings', []), indent=2)}

Evidence from Tasks:
{chr(10).join(evidence_lines) or "No direct evidence captured."}

Tasks Executed:
{json.dumps([{"task": t.get("description", "Task"), "status": t.get("status", "pending"), "tool": t.get("tool", ""), "result": str(t.get("result", ""))[:200]} for t in tasks], indent=2)}

Rules:
- Synthesize findings into a clear SRE investigation report.
- Use EXACTLY these sections in the report_content: ## Summary, ## Root Cause, ## Evidence, ## Actions Taken, ## Verification, ## Remaining Issues.
- You ARE an autonomous SRE agent with Linux tool access. NEVER say "I don't have access".
- CRITICAL CONSTITUTION RULE: The final response must be generated ONLY from findings, evidence, and verification results.
- FINAL REPORT COMPLETION GUARD: You MUST ONLY state claims that are backed by the provided execution evidence. FORBIDDEN: Do not claim files were fixed, configurations changed, or services restarted unless there is explicit execution evidence (e.g. `systemctl restart nginx`) proving it happened.
- CRITICAL REPORT INTEGRITY RULE: The final report MUST ONLY contain executed actions, actual outputs, and verified findings. Never output dummy placeholders like 'your_command_here' or 'username'.

Output ONLY valid JSON:
{{
  "artifact_name": "investigation_report.md",
  "report_content": "The full markdown report."
}}"""

        fallback_json = {
            "artifact_name": "report.md",
            "report_content": "Investigation concluded. Note: The final report generation failed to parse gracefully, but the raw evidence is available in the timeline."
        }

        try:
            data = self._robust_json_parse(HumanMessage(content=prompt), ["agent_llm"], fallback_response=fallback_json)
            final_report = data.get("report_content", "Investigation completed.")
            artifact_name = data.get("artifact_name", "report.md")
        except Exception:
            final_report = "Investigation completed (fallback response)."
            artifact_name = "report.md"

        global_confidence = plan.get("global_confidence", 1.0)
        is_verified = global_confidence >= 0.5
        
        if not is_verified:
            final_report = f"> [!WARNING]\n> **Best Effort Result** (Confidence {global_confidence:.2f} < 0.5)\n> The system could not definitively verify this conclusion.\n\n" + final_report

        return {
            "messages":    [AIMessage(content=final_report)],
            "is_completed": True,
            "is_verified":  is_verified,
            "final_report": final_report,
            "artifact_name": artifact_name,
            "plan":         plan,
            "thinking":     "Final response generated from verified evidence." if is_verified else "Final response: Best Effort Result.",
        }
