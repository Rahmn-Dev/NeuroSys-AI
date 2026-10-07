import asyncio
import json
import os
import time
import uuid
import traceback
from typing import AsyncGenerator, Dict
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage, ToolMessage
from langchain_core.tools import tool
from .events import *
from .security_boundary import POLICY, INJECTION, audit, untrusted_observation
from .tools.registry import ToolRegistry

# How many times the exact same tool call may be suppressed before the engine
# forces the agent to conclude. 1 = first duplicate only nudges, 2 = second
# duplicate forces finish_task, 3 = still repeating ends the run. Looping is
# allowed; burning the whole budget on one command is not.
DUPLICATE_TOLERANCE = 3


def _call_signature(tool_name: str, tool_args: dict) -> str:
    """Stable signature for duplicate detection.

    Whitespace-only and trailing-separator differences must count as the same
    call, otherwise a model can 'vary' a command cosmetically and loop forever.
    """
    normalized = {}
    for key, value in (tool_args or {}).items():
        if isinstance(value, str):
            value = " ".join(value.split())
            while value.endswith((";", "|", "&&")):
                value = value[:-1].rstrip()
        normalized[key] = value
    return f"{tool_name}:{json.dumps(normalized, sort_keys=True, default=str)}"

@tool
def finish_task(summary: str) -> str:
    """Use this tool ONLY when the main goal is 100% achieved and verified. Call this to finish your task."""
    return "Task Finished"

def parse_narrated_tool_calls(text: str) -> list:
    """Extract tool calls narrated as JSON text instead of native calls.

    Handles shapes like {"name": "read_file", "args"|"parameters"|"arguments": {...}}
    and array-wrapped variants ([{...}] and [[{...}]]). Returns a list of
    {"name":..., "args": {...}}. Pure function (unit-testable). Never raises.
    """
    found = []
    if not text or "{" not in text:
        return found
    try:
        decoder = json.JSONDecoder()
        idx, n = 0, len(text)
        while idx < n:
            ch = text[idx]
            if ch in "{[":
                try:
                    obj, end = decoder.raw_decode(text[idx:])
                    found.append(obj)
                    idx += end
                    continue
                except Exception:
                    pass
            idx += 1
    except Exception:
        return []
    calls = []

    def _flatten(obj):
        if isinstance(obj, list):
            for sub in obj:
                yield from _flatten(sub)
        else:
            yield obj

    for obj in found:
        for item in _flatten(obj):
            if not isinstance(item, dict) or not isinstance(item.get("name"), str):
                continue
            args = item.get("parameters", item.get("args", item.get("arguments", {})))
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except Exception:
                    continue
            if isinstance(args, dict):
                calls.append({"name": item["name"], "args": args})
    return calls


def _looks_like_raw_tool_call(final_msg: str) -> bool:
    """Heuristic: message smells like a tool call written as raw JSON text."""
    _known_tools = ("get_current_directory", "read_file", "write_file", "edit_file",
                    "terminal_execute", "spawn_subagent", "finish_task")
    return (
        "{" in (final_msg or "")
        and any(t in final_msg for t in _known_tools)
        and ('"command"' in final_msg or '"path"' in final_msg or '"name"' in final_msg
             or '"parameters"' in final_msg or '"tool"' in final_msg)
    )


def _invoke_with_approval_context(tool, tool_args):
    """Run a sync tool with the authorization context and approval lifecycle bound.

    Sync tool bodies execute in a worker thread. Context variables are not
    inherited there, so without this the approval guard inside the tool finds no
    lifecycle and an action that legitimately needs operator approval surfaces
    as a bare denial instead of the Allow/Deny prompt.
    """
    from .approvals import current_context, bind_context, _CTX
    from .approval_lifecycle import active_lifecycle, resolve_lifecycle
    snapshot = dict(current_context() or {})
    lifecycle = resolve_lifecycle()
    token_ctx = bind_context(
        snapshot.get("session_id", ""),
        snapshot.get("user_id", "anonymous"),
        mode=snapshot.get("mode", "controlled"),
        scope=snapshot.get("scope", []),
        goal=snapshot.get("goal", ""),
    )
    token_lifecycle = active_lifecycle.set(lifecycle)
    try:
        return tool.invoke(tool_args)
    finally:
        try:
            active_lifecycle.reset(token_lifecycle)
        except Exception:
            pass
        try:
            _CTX.reset(token_ctx)
        except Exception:
            pass


class ReactEngine:
    def __init__(self, llm, tools: list, system_prompt: str, session_id: str, mode: str = "autonomous_multi", goal: str = "", tool_choice: str = "any"):
        self.llm = llm
        self.mode = mode
        # The operator's goal selects the evidence checklist and drives the
        # objective rotation between budget slices.
        self.goal = goal
        # How tools are offered. "any" forces a call every turn; some thinking
        # models (DeepSeek thinking mode via OpenAI-compatible gateways) reject
        # forced calls with a 400, so those rows use "auto" instead.
        self.tool_choice = tool_choice or "any"

        if self.mode == "autonomous_single":
            # Single Agent owns the request; delegation is available only for
            # bounded independent work and does not replace direct execution.
            self.tools = list(tools)
        elif self.mode == "guided":
            # Guided means the operator runs the commands, so the agent keeps
            # read-only tools only - and no delegation either, because a
            # subagent could execute what guided deliberately withholds.
            self.tools = [t for t in tools
                          if t.name not in {"write_file", "edit_file", "terminal_execute",
                                            "spawn_subagent"}]
        else:
            # Multi-agent Mode: Orchestrator MUST delegate all execution to subagents via spawn_subagent
            direct_execution_tools = [
                "write_file", "edit_file", "multi_replace_file_content",
                "replace_file_content", "terminal_execute", "safe_execute"
            ]
            self.tools = [t for t in tools if t.name not in direct_execution_tools]

        self.tools.append(finish_task)
        self.system_prompt = system_prompt
        self.session_id = session_id
        self.completed = False
        self.outcome = "idle"
        self.completion_summary = ""
        self.evidence_count = 0

        self.tool_map = {t.name: t for t in self.tools}
        if hasattr(self.llm, "bind_tools"):
            try:
                self.llm_with_tools = self.llm.bind_tools(self.tools, tool_choice=self.tool_choice)
            except Exception:
                self.llm_with_tools = self.llm.bind_tools(self.tools)
        else:
            self.llm_with_tools = self.llm

    # Tools that change a file on disk. Their artifacts must show what actually
    # changed in the file, not that a tool happened to run.
    FILE_MUTATING_TOOLS = {"write_file", "edit_file", "multi_replace_file_content",
                           "replace_file_content", "create_file", "append_file"}

    def _file_target(self, tool_name: str, params: dict):
        """The (path, action) a mutating tool is about to touch, if any."""
        if tool_name not in self.FILE_MUTATING_TOOLS:
            return None, None
        path = ""
        for key in ("path", "file_path", "filepath", "target_file"):
            value = params.get(key)
            if isinstance(value, str) and value.strip():
                path = value.strip()
                break
        if not path:
            return None, None
        import os
        action = "edit" if tool_name == "edit_file" else "create"
        try:
            if not os.path.exists(path):
                action = "create"
        except Exception:
            pass
        return path, action

    def _read_file_state(self, path: str):
        """Content of a file before the tool runs, or None when it is new."""
        import os
        try:
            if not path or not os.path.exists(path):
                return None
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                return handle.read()
        except Exception:
            return None

    async def _record_file_change(self, tool_name: str, params: dict, result: str,
                                  before: str, case_id: str = ""):
        """Store the real before/after of a file the agent just changed."""
        try:
            import os
            from sre_agent.artifacts import ArtifactManager
            path, action = self._file_target(tool_name, params)
            if not path:
                return
            after = self._read_file_state(path)
            if after is None:
                return
            if before is not None and before == after:
                # Nothing actually changed on disk (e.g. a denied write).
                return
            if before is None:
                action = "create"
            mgr = ArtifactManager(workspace_path=os.getcwd(),
                                  session_id=self.session_id or "default",
                                  case_id=case_id or "")
            await mgr.create_artifact(path, after, action_type=action,
                                      old_content=before or "")
        except Exception:
            pass

    # --- execution audit -----------------------------------------------------
    # What the agent actually ran has to survive the UI: the run card can be
    # scrolled away and history is paged, so every call is written to the audit
    # table and summarised once per run as an execution artifact.
    async def _audit_tool_call(self, tool_name: str, params: dict, result: str,
                               started_at: float, status: str = "success", case_id: str = ""):
        """Record one tool call. Awaited so the write cannot be lost, and
        wrapped so bookkeeping can never fail a run."""
        try:
            import time as _time
            from asgiref.sync import sync_to_async
            from chatbot.models import ToolExecutionLog
            from .events import sanitize_tool_args_for_audit, redact_text

            duration = round(max(0.0, _time.time() - started_at), 3)
            # sanitize returns a dict; it has to be serialised before it can be
            # stored or sliced, and slicing it used to raise and silently skip
            # the whole audit record.
            safe_args = sanitize_tool_args_for_audit(params)
            args_json = __import__("json").dumps(safe_args, default=str)[:4000]
            safe_out = redact_text(str(result or ""), 2000)

            await sync_to_async(ToolExecutionLog.objects.create)(
                conversation_id=self.session_id,
                tool_name=str(tool_name)[:100],
                input_parameters=args_json,
                output_result=str(safe_out or "")[:4000],
                status=status[:50],
                execution_time=duration,
            )
            return {
                "tool": tool_name, "status": status, "duration": duration,
                "case_id": case_id or "", "args": safe_args,
            }
        except Exception:
            return None

    async def _save_agent_artifact(self, tool_name: str, params: dict, result: str):
        """Kept for callers that still record a tool-level note."""
        return None

    async def _record_run_execution(self, case_id: str, started_at: float):
        """One execution record per run: which tools ran, how long, what failed."""
        try:
            import time as _time
            import os as _os
            from sre_agent.artifacts import ArtifactManager
            entries = list(getattr(self, "_execution_log", []) or [])
            total = round(max(0.0, _time.time() - started_at), 1)
            tools = {}
            for entry in entries:
                slot = tools.setdefault(entry["tool"], {"n": 0, "failed": 0, "seconds": 0.0})
                slot["n"] += 1
                slot["seconds"] += entry.get("duration", 0.0)
                if entry.get("status") != "success":
                    slot["failed"] += 1
            outcome = str(getattr(self, "outcome", "unknown") or "unknown")
            if outcome in {"blocked", "security_blocked"}:
                outcome = "failed"
            lines = [f"# Agent execution\n",
                     f"**Case**: {case_id or 'session'}\n",
                     f"**Outcome**: {outcome}\n",
                     f"**Tool calls**: {len(entries)} in {total}s\n",
                     f"**Tools**: {', '.join(sorted(tools))}\n",
                     "\n## Calls\n"]
            if not entries:
                lines.append("_No tool calls were recorded before the run stopped._\n")
            for entry in entries:
                cmd = ""
                args = entry.get("args") or {}
                if isinstance(args, dict):
                    cmd = str(args.get("command") or args.get("path") or args.get("file_path") or "")[:160]
                lines.append(f"- `{entry['tool']}` {cmd} - {entry['status']} ({entry['duration']}s)\n")
            mgr = ArtifactManager(workspace_path=_os.getcwd(),
                                  session_id=self.session_id or "default",
                                  case_id=case_id or "")
            await mgr.upsert_artifact(
                f".neurosys/sessions/{self.session_id}/investigations/{case_id or 'session'}/agent_execution.md",
                "".join(lines), action_type="agent_execution", case_id=case_id or "")
            return entries
        except Exception:
            return None

    async def _sync_single_plan_tasks(self, plan: dict):
        """Persist the single-agent phase checklist so reloads show it too."""
        try:
            from asgiref.sync import sync_to_async
            from chatbot.models import Investigation, InvestigationTask
            inv_id = plan.get("investigation_id") or ""
            if not inv_id:
                return

            @sync_to_async
            def _db():
                if not Investigation.objects.filter(id=inv_id).exists():
                    return
                InvestigationTask.objects.filter(investigation_id=inv_id).delete()
                for idx, t in enumerate(plan.get("tasks", [])):
                    InvestigationTask.objects.create(
                        investigation_id=inv_id,
                        title=str(t.get("description", ""))[:255],
                        status=t.get("status", "pending"),
                        task_order=idx)
            await _db()
        except Exception:
            pass

    async def astream(self, initial_state: dict) -> AsyncGenerator[str, None]:
        import time as _start
        self._run_started_at = _start.time()
        self._execution_log = []
        self.completed = False
        self.outcome = "running"
        self.completion_summary = ""
        self.evidence_count = 0
        goal = initial_state.get("goal", "")
        lifecycle = initial_state.get("_lifecycle")
        if INJECTION.search(str(goal)) or any(
            INJECTION.search(str(getattr(m, "content", "")))
            for m in initial_state.get("messages", []) if isinstance(m, HumanMessage)
        ):
            audit("direct_injection", verdict="blocked")
            audit("security_blocked", verdict="direct_injection")
            self.outcome = "security_blocked"
            yield evt_security_blocked("Request blocked: instruction override detected.")
            if lifecycle:
                await lifecycle.atransition("security", "blocked", "direct_injection", {})
            return
        terminal_cwd = initial_state.get("terminal_cwd", "")
        messages = initial_state.get("messages", [])

        if self.mode == "autonomous_single":
            react_system_prompt = f"""You are the Single Agent running directly on the server and own the complete task.
Complete the user's request using the focused core tools provided to you. Prefer direct tool use. You may use `spawn_subagent` only for a bounded, independent subtask that materially benefits from delegation; you remain responsible for checking and integrating its result.

Current Working Directory: {terminal_cwd}

CRITICAL RULES:
1. You have direct access to `get_current_directory`, `read_file`, `write_file`, `edit_file`, `terminal_execute`, and `spawn_subagent`.
2. READ-ONLY FIRST: always begin with dedicated read-only tools (`get_current_directory`, `read_file`) or an approved read-only `terminal_execute` pipeline. NEVER open with an approval-gated call — it ends the run before you have evidence.
3. If `terminal_execute` can solve the task directly, use it.
3. Diagnose within the user request. Mutations require independently verified authorization; stop and report when denied.
4. NEVER provide code blocks or commands for the user to run. YOU MUST RUN IT YOURSELF.
5. DO NOT output raw JSON blocks to call tools. You MUST use the native API tool calling capability.
6. Prefer one precise read-only pipeline (`source | grep/sed | tail`) when it can collect the required evidence. Do not repeat broad discovery after decisive evidence exists.
7. Call `finish_task` immediately after the goal is answered and verified; never keep planning merely to use the iteration budget.

- Keep private reasoning out of responses. Report only observations and verified conclusions.

You are running in an autonomous background loop. The ONLY way to complete the task is by calling the `finish_task` tool.

CRITICAL DIRECTIVE - ACTION OVER NARRATION:
You MUST invoke a tool on EVERY SINGLE TURN. Do NOT explain what you are going to do. Do NOT apologize. JUST CALL THE TOOL.
If you need to think, use `<think>...</think>` tags, and IMMEDIATELY follow it with a tool call. If you do not invoke a tool, the system will fail.
Do NOT stop calling tools until you are ready to call `finish_task`.
"""
        else:
            react_system_prompt = f"""You are the Orchestrator Agent (base2) of a Hierarchical Multi-Agent System running on the server.
Your absolute goal is to complete the user's request comprehensively by orchestrating specialized sub-agents.
You DO NOT execute terminal commands or edit files directly. You MUST delegate all actions using the 'spawn_subagent' tool.

Current Working Directory: {terminal_cwd}

CRITICAL RULES FOR ORCHESTRATION:
1. You MUST delegate ALL tasks using the 'spawn_subagent' tool by setting `agent_type` to:
   - 'basher': For running terminal commands, checking systemctl, running tests, or inspecting ports. (e.g. {{"command": "systemctl status nginx"}})
   - 'file-picker': Translates natural language to `find` or `locate` commands to explore directories. (e.g. {{"query": "find all python files in src"}})
   - 'code-searcher': Translates natural language to `grep` or `ripgrep` to search file contents. (e.g. {{"query": "where is user authentication handled?"}})
   - 'thinker': Solves complex logic or refactoring problems. Pass the codebase context and the problem. It returns a detailed <PLAN>. (e.g. {{"context": "...", "problem": "..."}})
   - 'editor': Makes physical code changes based on your instructions. Pass the target files and exact instructions. (e.g. {{"files": ["/path/to/file"], "instructions": "..."}})
   - 'code-reviewer': Reviews code changes or diffs and returns feedback. (e.g. {{"diff": "..."}})

2. **Sequence agents properly:**
   - [Explore]: Spawn 'file-picker' or 'code-searcher' to gather context.
   - [Terminal/System]: Spawn 'basher' to check system state, ports, or logs.
   - [Read]: Read specific files using 'read_file'.
   - [Think]: For complex tasks, spawn a 'thinker' agent to generate a plan.
   - [Implement]: Spawn the 'editor' agent to implement code changes.
   - [Validate]: Spawn a 'basher' to run tests or verify fixes.

3. Diagnose within the user request. Do not delegate denied actions or expand a diagnosis into unauthorized changes.
4. NEVER provide code blocks or commands for the user to run. YOU MUST DELEGATE IT TO SUBAGENTS.
5. DO NOT output raw JSON blocks to call tools. You MUST use the native API tool calling capability.

- Keep private reasoning out of responses. Report only observations and verified conclusions.

You are running in an autonomous background loop. The ONLY way to complete the task is by calling the `finish_task` tool.

CRITICAL DIRECTIVE - ACTION OVER NARRATION:
You MUST invoke a tool on EVERY SINGLE TURN. Do NOT explain what you are going to do. Do NOT apologize. JUST CALL THE TOOL.
If you need to think, use `<think>...</think>` tags, and IMMEDIATELY follow it with a tool call. If you do not invoke a tool, the system will fail.
Do NOT stop calling tools until you are ready to call `finish_task`.
"""

        history = [m for m in messages if not isinstance(m, SystemMessage)]
        history.insert(0, SystemMessage(content=self.system_prompt + "\n" + react_system_prompt + "\n" + POLICY))

        yield evt_planning("Starting Autonomous ReAct Mode...")

        # Single-agent todo list: phase checklist with real statuses, shown
        # in the same Task Plan UI as guided mode and persisted for reloads.
        single_plan = None
        if self.mode == "autonomous_single":
            # A 'continue' against an existing investigation must not start a
            # fresh checklist: carry the statuses forward so the operator sees
            # where the previous run stopped and the agent picks up from the
            # next open task. The message history already carries the prior
            # tool calls, so the model itself also resumes mid-thought.
            prior_tasks = (initial_state.get("plan") or {}).get("tasks") or []
            carried_id = str((initial_state.get("plan") or {}).get("investigation_id") or "")
            if prior_tasks:
                single_plan = {
                    "investigation_id": carried_id,
                    "title": str(goal or "")[:40],
                    "tasks": [
                        {
                            "id": str(t.get("id", idx + 1)),
                            "description": str(t.get("description") or t.get("title") or ""),
                            "status": str(t.get("status") or "pending"),
                            "completed": bool(t.get("completed"))
                                or str(t.get("status", "")).lower() in ("completed", "done"),
                        }
                        for idx, t in enumerate(prior_tasks)
                    ],
                    "completed": all(
                        bool(t.get("completed")) or str(t.get("status", "")).lower() in ("completed", "done")
                        for t in prior_tasks
                    ),
                }
                # Whatever step was in flight last run resumes as running.
                if not single_plan["completed"]:
                    for t in single_plan["tasks"]:
                        if t["status"] in ("running", "in_progress", "pending"):
                            t["status"] = "running" if not t["completed"] else "completed"
                            break
            else:
                single_plan = {
                    "investigation_id": carried_id,
                    "title": str(goal or "")[:40],
                    "tasks": [
                        {"id": "S1", "description": "Gather evidence with read-only tools",
                         "status": "running", "completed": False},
                        {"id": "S2", "description": "Execute actions and verify results",
                         "status": "pending", "completed": False},
                        {"id": "S3", "description": "Finish and report",
                         "status": "pending", "completed": False},
                    ],
                    "completed": False,
                }
            yield evt_task_plan(single_plan)
            await self._sync_single_plan_tasks(single_plan)

        # Single-agent investigations can need many steps (collect evidence,
        # read configs, apply a fix, verify it). A small hard cap makes every
        # non-trivial task die with "Max iterations reached" - so the budget is
        # generous by default and env-overridable. The real safety guards are
        # the duplicate-command suppression and the approval policy, not a tiny
        # step counter.
        if self.mode == "autonomous_single":
            try:
                max_iterations = int(os.environ.get("SRE_SINGLE_MAX_ITERATIONS", "40"))
            except ValueError:
                max_iterations = 40
        else:
            try:
                max_iterations = int(os.environ.get("SRE_MULTI_MAX_ITERATIONS", "20"))
            except ValueError:
                max_iterations = 20
        # The per-slice budget above is NOT the end of the investigation: it only
        # decides when to rotate to a new objective. A case may use far more
        # steps than one slice, which is what a thorough SRE investigation of a
        # brute force or a flood actually needs.
        try:
            total_step_cap = int(os.environ.get("SRE_CASE_MAX_STEPS", "200"))
        except ValueError:
            total_step_cap = 200
        goal_text = str(getattr(self, "goal", "") or "")
        from .coverage import coverage_from_commands, next_objective, render_coverage_report
        covered_checks: set = set()
        executed_commands: list = []
        iteration = 0
        # signature -> how many times that exact call has been suppressed
        seen_tool_calls: Dict[str, int] = {}
        # signatures whose tool actually ran. Duplicate suppression only applies
        # to real repeats: a call that was deflected or blocked by policy must be
        # re-evaluated so the security path still terminates the run.
        executed_signatures = set()
        no_tool_streak = 0
        must_conclude = False

        slice_left = max_iterations
        objective_attempts = 0
        while iteration < total_step_cap:
            if slice_left <= 0:
                # Slice exhausted: rotate to the next missing check rather than
                # giving up. Never repeat what the earlier slice proved.
                objective_attempts += 1
                objective = next_objective(goal_text, covered_checks, objective_attempts)
                if objective is None:
                    yield evt_status(
                        "All checks for this domain are covered; wrapping up with the evidence gathered."
                    )
                    break
                item_id, instruction = objective
                slice_left = max_iterations
                history.append(HumanMessage(content=(
                    "BUDGET SLICE COMPLETE. Rotate to a different check - do not repeat previous "
                    f"commands. {instruction}. Then continue towards the original goal."
                )))
                yield evt_status(
                    f"Slice complete after {iteration} step(s) - coverage {len(covered_checks)} check(s). {instruction}"
                )
            iteration += 1
            slice_left -= 1
            if iteration == 1:
                yield evt_thinking("Selecting the shortest verified action...")

            try:
                from .provider_runtime import invoke_with_retry
                if executed_commands:
                    covered_checks = coverage_from_commands(executed_commands, goal_text)
                response = await invoke_with_retry(lambda: self.llm_with_tools.ainvoke(history))
                history.append(response)

                content_val = response.content
                final_msg = ""
                if isinstance(content_val, str):
                    final_msg = content_val
                elif isinstance(content_val, list):
                    final_msg = "".join(part.get("text", "") for part in content_val if isinstance(part, dict) and part.get("type") == "text")

                if final_msg:
                    import re
                    think_blocks = re.findall(r'<think>(.*?)</think>', final_msg, re.DOTALL)
                    for block in think_blocks:
                        yield evt_thinking(f"Internal Thought:\n{block.strip()}")

                    ui_text = re.sub(r'<think>.*?</think>', '', final_msg, flags=re.DOTALL).strip()
                    if ui_text:
                        yield evt_message_chunk(ui_text + "\n\n")

                if not response.tool_calls:
                    # Narrated-call fallback: some models/proxies write the
                    # tool call as JSON text instead of native tool calling.
                    # Parse it and EXECUTE it through the normal guarded path
                    # instead of merely reminding (reminders alone loop forever).
                    _narrated = [c for c in parse_narrated_tool_calls(final_msg)
                                 if c["name"] in self.tool_map]
                    if _narrated:
                        names = ", ".join(c["name"] for c in _narrated)
                        yield evt_thinking(f"Executing narrated tool call(s): {names}...")
                        history.append(HumanMessage(content=(
                            "SYSTEM NOTE: your tool call was written as JSON text, "
                            "so I executed it directly this time. Prefer the native "
                            "API tool calling feature on the next turn.")))
                        response = AIMessage(
                            content="",
                            tool_calls=[{
                                "name": c["name"],
                                "args": c["args"],
                                "id": f"narrated-{uuid.uuid4().hex[:8]}",
                                "type": "tool_call",
                            } for c in _narrated],
                        )
                        history.append(response)
                    else:
                        # Programmatic enforcement: don't let it suggest commands
                        lower_msg = final_msg.lower()
                        if "sudo " in lower_msg or "systemctl" in lower_msg or "```bash" in lower_msg or "run the following" in lower_msg:
                            yield evt_thinking("System intercepted a suggestion. Forcing agent to execute it...")
                            history.append(HumanMessage(content="SYSTEM INSTRUCTION: You just suggested commands for the user to run. This is strictly forbidden (Rule 13). You MUST run these commands YOURSELF using your tools (terminal_execute or spawn_subagent). Do it now."))
                            no_tool_streak += 1
                        elif _looks_like_raw_tool_call(final_msg):
                            yield evt_thinking("System intercepted a raw JSON tool call. Reminding agent...")
                            history.append(HumanMessage(content="SYSTEM INSTRUCTION: You just outputted a raw JSON string to call a tool. This is forbidden. You MUST use the native API tool calling feature instead of writing JSON in your message. If the goal is already answered with verified tool output, call 'finish_task' now. Try again."))
                            no_tool_streak += 1
                        else:
                            yield evt_thinking("Agent stopped without calling finish_task. Forcing loop continuation...")
                            history.append(HumanMessage(content="SYSTEM INSTRUCTION: You did not call any tools. You are running in a background loop. You MUST call tools to continue working, or call 'finish_task' if the goal is completely achieved. Do NOT wait for user input."))
                            no_tool_streak += 1
                        if no_tool_streak >= 3:
                            self.outcome = "failed"
                            yield evt_error("Model tidak memakai tool calling setelah 3x diingatkan (narrated JSON tidak valid / bukan tool dikenal). Run dihentikan agar tidak membakar token.")
                            return
                        continue

                should_exit_loop = False
                no_tool_streak = 0
                for tc in response.tool_calls:
                    tool_name = tc["name"]
                    tool_args = tc["args"]
                    tool_call_id = tc["id"]
                    if tool_name != "finish_task":
                        executed_commands.append(f"{tool_name} {str(tool_args)[:300]}")

                    call_signature = _call_signature(tool_name, tool_args)
                    repeat_count = seen_tool_calls.get(call_signature, 0) if call_signature in executed_signatures else 0
                    if tool_name != "finish_task" and repeat_count:
                        # A duplicate call is suppressed, NOT fatal. The run keeps
                        # going so the model can pick a different approach; only a
                        # persistent repeat loop ends the run.
                        seen_tool_calls[call_signature] = repeat_count + 1
                        if repeat_count + 1 < DUPLICATE_TOLERANCE:
                            yield evt_thinking(
                                f"Duplicate {tool_name} suppressed (attempt {repeat_count + 1}); "
                                "asking for a different approach."
                            )
                            history.append(ToolMessage(
                                content=(
                                    "SUPPRESSED - this exact call already ran and returned the same "
                                    "result. Repeating it changes nothing. Either vary the command "
                                    "(different flags, different path, different tool) or call "
                                    "'finish_task' and report what you verified so far."
                                ),
                                name=tool_name,
                                tool_call_id=tool_call_id,
                            ))
                            continue

                        if not must_conclude:
                            must_conclude = True
                            yield evt_thinking(
                                "Same action repeated again; no new evidence is possible from it. "
                                "Forcing a conclusion."
                            )
                            history.append(HumanMessage(content=(
                                "SYSTEM INSTRUCTION: You have repeated the same action too many times and "
                                "it yields no new evidence. STOP calling tools. Call 'finish_task' now with "
                                "an honest summary of what you verified and what remains unverified."
                            )))
                            continue

                        self.outcome = "paused"
                        yield evt_error(
                            "Agent kept repeating the identical action "
                            f"({tool_name}) and was asked to conclude three times. Run paused instead of "
                            "looping further. Continue with a different approach, e.g. another tool, "
                            "another path, or a manual decision."
                        )
                        return

                    seen_tool_calls[call_signature] = 1
                    must_conclude = False

                    if tool_name == "finish_task":
                        summary = tool_args.get("summary", "Goal Achieved.")
                        if self.evidence_count < 1:
                            history.append(ToolMessage(
                                content="Completion rejected: collect at least one successful tool observation first.",
                                name=tool_name,
                                tool_call_id=tool_call_id,
                            ))
                            yield evt_thinking("Completion requested before verification; continuing investigation.")
                            continue
                        self.completed = True
                        self.outcome = "completed"
                        self.completion_summary = str(summary)
                        await self._record_run_execution(
                            (single_plan or {}).get("investigation_id", ""),
                            getattr(self, "_run_started_at", 0.0) or __import__('time').time())
                        from .events import FINAL_ANSWER_MARKER
                        yield evt_message_chunk(f"\n\n{FINAL_ANSWER_MARKER}✅ **Task Completed**: {summary}")
                        history.append(ToolMessage(content="Task completed successfully.", name=tool_name, tool_call_id=tool_call_id))
                        if single_plan is not None:
                            for t in single_plan["tasks"]:
                                t["status"] = "completed"
                                t["completed"] = True
                            single_plan["completed"] = True
                            yield evt_task_plan(single_plan)
                            yield evt_task_updated({"task": "Finish and report", "new_status": "completed"})
                            await self._sync_single_plan_tasks(single_plan)
                        should_exit_loop = True
                        break

                    # Read-only-first enforcement: never burn the run on an
                    # approval-gated terminal/delegation call before any
                    # evidence exists. Nudge once toward dedicated read-only
                    # tools; calls that are already auto-approved pass through.
                    if (not getattr(self, "_readonly_nudged", False)
                            and self.evidence_count == 0
                            and tool_name in ("terminal_execute", "spawn_subagent")):
                        from .security_boundary import evaluate as _policy_evaluate
                        _meta = ToolRegistry().get_metadata(tool_name)
                        if _meta is not None:
                            _verdict, _ = _policy_evaluate(_meta, dict(tool_args))
                            if _verdict != "approved":
                                self._readonly_nudged = True
                                yield evt_thinking("First action needs approval; gathering read-only evidence first...")
                                history.append(ToolMessage(
                                    content=("That call requires operator approval and you have no "
                                             "evidence yet. First collect read-only evidence with dedicated "
                                             "tools (`get_current_directory`, `read_file`) or an approved "
                                             "read-only `terminal_execute` pipeline, then proceed. If the goal "
                                             "is already answered with verified output, call `finish_task`."),
                                    name=tool_name,
                                    tool_call_id=tool_call_id,
                                ))
                                continue

                    # Show what will actually run; evt_tool_start summarises and
                    # masks secrets itself.
                    yield evt_tool_start(tool_name, tool_args)

                    if tool_name in self.tool_map:
                        tool = self.tool_map[tool_name]
                        try:
                            if ToolRegistry().get_metadata(tool_name) is None:
                                raise PermissionError("Unregistered tool")
                            executed_signatures.add(call_signature)
                            # Capture the file's content BEFORE the write, so the
                            # recorded artifact can show a real before/after.
                            _file_path, _file_action = self._file_target(tool_name, tool_args)
                            _file_before = self._read_file_state(_file_path) if _file_path else None
                            import time as _time
                            _call_started = _time.time()
                            self._execution_log = getattr(self, "_execution_log", [])
                            # A sync tool body runs in a worker thread, and
                            # neither the authorization context nor the approval
                            # lifecycle follows a call into a thread. They are
                            # re-bound there, otherwise a guarded sync tool
                            # (terminal_execute, writes) could never raise the
                            # approval prompt and the operator only saw
                            # "action denied". asyncio.to_thread is used
                            # precisely because it does propagate context.
                            if getattr(tool, "coroutine", None) is not None:
                                tool_result = await tool.ainvoke(tool_args)
                            else:
                                tool_result = await asyncio.to_thread(
                                    _invoke_with_approval_context, tool, tool_args
                                )
                            output_str = str(tool_result)[:4000]
                            # Retrieved content is evidence, never executable instruction.
                            # Stop this run after quarantine so the model cannot loop over
                            # the same hostile file or attempt a different tool path.
                            if output_str.startswith("[Untrusted observation quarantined:"):
                                audit("security_blocked", tool_name, "indirect_injection")
                                self.outcome = "security_blocked"
                                yield evt_security_blocked(
                                    "Untrusted tool content blocked by security policy."
                                )
                                return
                            if output_str.strip() and not output_str.lower().startswith(("error", "blocked", "failed")):
                                first_evidence = self.evidence_count == 0
                                self.evidence_count += 1
                                if first_evidence and single_plan is not None:
                                    single_plan["tasks"][0]["status"] = "completed"
                                    single_plan["tasks"][0]["completed"] = True
                                    single_plan["tasks"][1]["status"] = "running"
                                    yield evt_task_plan(single_plan)
                                    yield evt_task_updated({"task": "Gather evidence with read-only tools",
                                                            "new_status": "completed"})
                                    await self._sync_single_plan_tasks(single_plan)
                        except PermissionError as denied_exc:
                            # Say what actually happened. A hard block can never
                            # be approved, so promising an authorization the
                            # operator cannot give is what made this read like a
                            # bug in the approval popup.
                            reason = str(denied_exc)
                            audit("agent_stopped", tool_name, "authorization_required")
                            self.outcome = "blocked"
                            # The rejected call is still part of the execution
                            # record, even though no tool result was produced.
                            try:
                                from .events import sanitize_tool_args_for_audit
                                self._execution_log.append({
                                    "tool": tool_name,
                                    "status": "blocked",
                                    "duration": round(max(0.0, _time.time() - _call_started), 3),
                                    "args": sanitize_tool_args_for_audit(tool_args),
                                })
                            except Exception:
                                pass
                            if reason.startswith("blocked:"):
                                detail = reason.split(":", 1)[1].strip()
                                yield evt_error(
                                    f"Blocked by security policy and not approvable: {detail}."
                                )
                            elif reason.startswith("approval_required:"):
                                yield evt_error(
                                    "This action needs your approval, but the approval "
                                    "prompt could not be opened for this run. Sign in again "
                                    "and retry."
                                )
                            else:
                                yield evt_error(f"Action denied by security policy: {reason}")
                            return
                        except Exception as e:
                            output_str = f"Error executing {tool_name}: {str(e)}"

                        _call_case = (single_plan or {}).get("investigation_id", "")
                        _entry = await self._audit_tool_call(
                            tool_name, tool_args, output_str, _call_started,
                            status="error" if str(output_str or "").lower().startswith(("error", "blocked", "failed")) else "success",
                            case_id=_call_case)
                        if _entry:
                            self._execution_log.append(_entry)
                        if _file_path and not str(output_str or "").lower().startswith(("error", "blocked", "failed")):
                            await self._record_file_change(
                                tool_name, tool_args, output_str, _file_before,
                                case_id=_call_case,
                            )

                        yield evt_tool_end(tool_name, output_str)

                        history.append(ToolMessage(
                            content=untrusted_observation(output_str),
                            name=tool_name,
                            tool_call_id=tool_call_id
                        ))
                    else:
                        history.append(ToolMessage(content=f"Error: Tool {tool_name} not found.", name=tool_name, tool_call_id=tool_call_id))

                if should_exit_loop:
                    break

            except Exception as e:
                error_trace = traceback.format_exc()
                self.outcome = "failed"
                from .canonical_lifecycle import normalize_provider_error
                error_info = normalize_provider_error(e)
                active_model = getattr(self.llm_with_tools, "active_label", "selected model")
                detail = getattr(self, "_selected_model_hint", "") or ""
                yield evt_error(
                    f"Single Agent failed on {active_model} ({error_info['category']}). "
                    "The case stays active; Auto Models will skip unavailable models."
                    + (f" {detail}" if detail else "")
                )
                break

        if not self.completed and iteration >= max_iterations:
            # Never end on "reply continue": synthesise an answer from whatever
            # evidence the run already gathered, and say what is still unverified.
            summary = ""
            evidence_lines = []
            try:
                steps = [str(m.content) for m in history if getattr(m, "type", "") == "tool"]
                evidence_lines = steps[-12:]
            except Exception:
                evidence_lines = []
            coverage_note = render_coverage_report(goal_text, covered_checks)
            synth_prompt = (
                "The investigation reached its total step cap without calling finish_task. "
                "Write the operator's answer NOW from the evidence below. State the "
                "conclusion, the evidence that supports it, anything still unverified, "
                "and the single most useful next step. Do not call any tool, do not plan, "
                "and do not ask to continue.\n\n"
                + (coverage_note + "\n\n" if coverage_note else "")
                + "Recent tool results:\n"
                + ("\n".join(evidence_lines) or "(none captured)")
            )
            try:
                from .provider_runtime import invoke_with_retry
                final = await invoke_with_retry(
                    lambda: self.llm.ainvoke(history + [HumanMessage(content=synth_prompt)])
                )
                summary = (getattr(final, "content", "") or "")
                if not isinstance(summary, str):
                    summary = str(summary)
            except Exception:
                summary = ""

            if summary.strip():
                self.outcome = "completed"
                self.completed = True
                self.completion_summary = summary.strip()
                yield evt_status(f"Step budget reached ({max_iterations}); answering from the evidence gathered.")
                from .events import FINAL_ANSWER_MARKER
                yield evt_message_chunk(FINAL_ANSWER_MARKER + summary.strip())
                if lifecycle:
                    await lifecycle.atransition("finalization", "completed", "budget_synthesis", {"iterations": iteration})
                return

            self.outcome = "paused"
            yield evt_status(
                f"Step budget reached ({max_iterations}). The case is still active - "
                "reply 'continue' to keep going, or tell me to focus on one specific step."
            )
            paused_note = "Investigation paused before concluding. Evidence collected so far is saved in the timeline; resume to continue."
            if coverage_note:
                paused_note += "\n\n" + coverage_note
            yield evt_message_chunk(paused_note)
            if lifecycle:
                await lifecycle.atransition("finalization", "failed", "iteration_budget_exhausted", {"iterations": iteration})
