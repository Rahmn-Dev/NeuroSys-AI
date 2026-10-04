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


class ReactEngine:
    def __init__(self, llm, tools: list, system_prompt: str, session_id: str, mode: str = "autonomous_multi"):
        self.llm = llm
        self.mode = mode

        if self.mode == "autonomous_single":
            # Single Agent owns the request; delegation is available only for
            # bounded independent work and does not replace direct execution.
            self.tools = list(tools)
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
                self.llm_with_tools = self.llm.bind_tools(self.tools, tool_choice="any")
            except Exception:
                self.llm_with_tools = self.llm.bind_tools(self.tools)
        else:
            self.llm_with_tools = self.llm

    async def _save_agent_artifact(self, tool_name: str, params: dict, result: str):
        try:
            import os, time, json
            from sre_agent.artifacts import ArtifactManager
            session_id = self.session_id or "default"
            mgr = ArtifactManager(workspace_path=os.getcwd(), session_id=session_id)
            timestamp = int(time.time())
            file_path = f".neurosys/sessions/{session_id}/artifacts/agent_{tool_name}_{timestamp}.md"
            from .events import sanitize_tool_args_for_audit, redact_text
            safe_args = sanitize_tool_args_for_audit(params)
            safe_result = redact_text(result, 3000)
            content = f"# Agent Tool Execution Record ({tool_name.upper()})\n\n**Tool Name**: {tool_name}\n**Timestamp**: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n## Input Parameters\n```json\n{json.dumps(safe_args, indent=2, default=str)[:2000]}\n```\n\n## Output / Result\n```\n{safe_result}\n```\n"
            await mgr.create_artifact(file_path, content, action_type="agent_execution")
        except Exception as e:
            print(f"[AgentArtifact] Warning: Failed to record artifact: {e}")

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
        iteration = 0
        # signature -> how many times that exact call has been suppressed
        seen_tool_calls: Dict[str, int] = {}
        # signatures whose tool actually ran. Duplicate suppression only applies
        # to real repeats: a call that was deflected or blocked by policy must be
        # re-evaluated so the security path still terminates the run.
        executed_signatures = set()
        no_tool_streak = 0
        must_conclude = False

        while iteration < max_iterations:
            iteration += 1
            if iteration == 1:
                yield evt_thinking("Selecting the shortest verified action...")

            try:
                from .provider_runtime import invoke_with_retry
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
                        yield evt_message_chunk(f"\n\n✅ **Task Completed**: {summary}")
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
                            if hasattr(tool, "ainvoke"):
                                tool_result = await tool.ainvoke(tool_args)
                            else:
                                tool_result = tool.invoke(tool_args)
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
                        except PermissionError:
                            audit("agent_stopped", tool_name, "authorization_required")
                            self.outcome = "blocked"
                            yield evt_error("Action denied by security policy; operator authorization is required.")
                            return
                        except Exception as e:
                            output_str = f"Error executing {tool_name}: {str(e)}"

                        if tool_name not in ["finish_task", "spawn_subagent"]:
                            await self._save_agent_artifact(tool_name, tool_args, output_str)

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
            self.outcome = "paused"
            yield evt_status(
                f"Step budget reached ({max_iterations}). The case is still active - "
                "reply 'continue' to keep going, or tell me to focus on one specific step."
            )
            yield evt_message_chunk(
                "Investigation paused before concluding to avoid runaway looping. "
                "All evidence collected so far is saved in the timeline; resume to continue."
            )
            if lifecycle:
                await lifecycle.atransition("finalization", "failed", "iteration_budget_exhausted", {"iterations": iteration})
