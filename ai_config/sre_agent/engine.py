"""
SRE Agent Engine — the core agentic execution loop.

Flow:
  User Request
  → Explore Workspace
  → Understand Goal
  → Discover Relevant Tools
  → Create Execution Plan (via LLM)
  → Execute Tools (with safety checks)
  → Observe & Analyze Results
  → Update Memory
  → Continue Until Goal Completed

Uses Mistral as the LLM provider via LangGraph's create_react_agent.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from typing import Any, AsyncGenerator, Dict, List, Optional

from django.conf import settings
from asgiref.sync import sync_to_async
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from .discovery import ToolDiscoveryAgent
from .events import (
    AgentEvent, evt_status, evt_exploring, evt_discovering, evt_planning,
    evt_thinking, evt_tool_start, evt_tool_end, evt_message_chunk,
    evt_completed, evt_error, evt_session_id, evt_session_title, evt_observing,
    evt_safety_blocked, evt_safety_warn, evt_analyzing,
    evt_creating_artifact, evt_restoring_artifact, evt_security_scan
)
from .memory import LongTermMemory, ShortTermMemory, WorkspaceMemory
from .safety import SafetyLayer, SafetyVerdict
from .tools.registry import RiskLevel, ToolRegistry
from .workspace import WorkspaceAnalyzer


# ---------------------------------------------------------------------------
# Ensure all tools are registered on first import
# ---------------------------------------------------------------------------

def _ensure_tools_registered():
    """Register all tool modules if not already done."""
    registry = ToolRegistry()
    if registry.count() > 0:
        return  # already registered

    from .tools.filesystem import register_filesystem_tools
    from .tools.linux import register_linux_tools
    from .tools.docker import register_docker_tools
    from .tools.network import register_network_tools
    from .tools.shell import register_shell_tools
    from .tools.monitoring import register_monitoring_tools
    from .tools.security import register_security_tools

    register_filesystem_tools()
    register_linux_tools()
    register_docker_tools()
    register_network_tools()
    register_shell_tools()
    register_monitoring_tools()
    register_security_tools()


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """You are NeuroSysAI — an advanced AI SRE (Site Reliability Engineer) agent.

## Your Capabilities
You are a multi-step reasoning agent that can diagnose, troubleshoot, and resolve
infrastructure issues on Linux servers. You have access to a dynamically-selected
set of tools based on the current task.

## Your Approach
1. UNDERSTAND the user's goal before taking action
2. EXPLORE the system to gather context
3. PLAN your approach — think step by step
4. EXECUTE tools one at a time, observing results
5. ANALYZE results before deciding the next step
6. NEVER guess — always verify with tools
7. SUMMARIZE your findings clearly when done

## Environment Context
{workspace_context}

## Current System User
{system_user}

## Working Directory
{working_dir}

## Available Tools
You have {tool_count} tools loaded for this task:
{tool_descriptions}

## Past Incidents (if relevant)
{past_incidents}

## Rules
- Be precise and technical in your analysis
- Always show relevant command outputs to support your conclusions
- If a tool fails, try an alternative approach
- For destructive operations, explain what you will do BEFORE doing it
- Format your responses clearly with sections and bullet points
- If you are unsure, say so — do not fabricate information
"""


# ---------------------------------------------------------------------------
# SRE Agent Engine
# ---------------------------------------------------------------------------

class SREAgentEngine:
    """
    The core agent execution engine.

    Usage:
        engine = SREAgentEngine(session_id="...")
        async for event in engine.run("Why is my website returning 502?"):
            send_to_websocket(event.to_dict())
    """

    MAX_ITERATIONS = 15

    def __init__(self, session_id: str = ""):
        self.session_id = session_id or str(uuid.uuid4())
        self.short_memory = ShortTermMemory()
        self.safety = SafetyLayer()
        self.discovery = ToolDiscoveryAgent()
        self._tools_used: List[str] = []

        _ensure_tools_registered()

    def _get_llm(self):
        """Get the Mistral LLM instance."""
        from langchain_mistralai import ChatMistralAI
        api_key = getattr(settings, "MISTRAL_API_KEY", os.environ.get("MISTRAL_API_KEY", ""))
        return ChatMistralAI(
            model="mistral-large-latest",
            mistral_api_key=api_key,
            temperature=0.1,
            max_tokens=4096,
        )

    async def _run_internal(self, user_message: str, terminal_cwd: Optional[str] = None) -> AsyncGenerator[AgentEvent, None]:
        """
        Internal loop — runs the full agent loop and yields events.
        """
        start_time = time.time()

        # --- Phase 1: Session setup ---
        db_session_id = await self._get_or_create_session()
        self.session_id = str(db_session_id)
        yield evt_session_id(str(db_session_id))

        from chatbot.models import ChatSession
        session_obj = await sync_to_async(ChatSession.objects.get)(id=db_session_id)
        if session_obj.title == "New Chat":
            new_title = user_message[:40] + "..." if len(user_message) > 40 else user_message
            session_obj.title = new_title
            await sync_to_async(session_obj.save)(update_fields=['title'])
            yield evt_session_title(new_title)

        await self._save_message(db_session_id, "user", user_message)
        self.short_memory.add("user_input", user_message)

        # --- Phase 2: Smart Intent Classification ---
        llm = self._get_llm()
        
        intent_prompt = f"""Categorize the user's intent based on their message. 
Categories:
- conversation: greeting, thanks, casual_conversation, identity_question.
- simple_action: time lookup, uptime, current directory, hostname, basic system information (e.g., cek ram).
- investigation: debugging, troubleshooting, analysis, modification, multi-step diagnosis.

Rules:
- Identity questions ("siapa saya", "siapa kamu", "what are you", "who am I") are ALWAYS 'conversation'. DO NOT interpret natural language identity questions as infrastructure tasks.
- 'simple_action' requires real-time tools for one-off lookup (e.g. "what time now", "jam berapa sekarang").
- 'investigation' requires complex tool usage.
User message: {user_message}
Output strictly the category name."""
        resp_intent = await llm.ainvoke([HumanMessage(content=intent_prompt)])
        intent = resp_intent.content.strip().lower()
        
        if intent == "conversation" or any(ci in intent for ci in ["greeting", "thanks", "casual", "identity", "capability"]):
            # Bypass all heavy tooling and respond directly
            history = await self._fetch_history(db_session_id)
            messages = [SystemMessage(content="You are NeuroSys AI SRE. Respond kindly and briefly.")]
            for msg in history[-20:-1]:
                if msg.sender.lower() == "user":
                    messages.append(HumanMessage(content=msg.message))
                else:
                    messages.append(AIMessage(content=msg.message))
            messages.append(HumanMessage(content=user_message))
            
            conv_resp = await llm.ainvoke(messages)
            yield evt_message_chunk(conv_resp.content)
            
            duration = time.time() - start_time
            yield evt_completed(f"Task completed in {duration:.1f}s", duration=duration)
            return

        # --- Phase 3: Explore workspace ---
        yield evt_exploring("Scanning workspace and system environment...")
        workspace_ctx = await sync_to_async(self._analyze_workspace)(terminal_cwd=terminal_cwd)
        workspace_text = workspace_ctx.to_prompt_context() if workspace_ctx else "No workspace context available"

        # Save workspace info
        if workspace_ctx:
            await WorkspaceMemory.save(workspace_ctx.path, workspace_ctx.to_dict())
            self.short_memory.add("observation", f"Workspace: {workspace_ctx.framework} / {workspace_ctx.language}")

        # --- Phase 3: Discover tools ---
        yield evt_discovering("Analyzing intent and discovering relevant tools...")
        ws_dict = workspace_ctx.to_dict() if workspace_ctx else {}
        discovery_result = self.discovery.discover(user_message, workspace_context=ws_dict)

        yield evt_discovering(
            f"Intent: {discovery_result.intent_description}. Loaded {len(discovery_result.tools)} tools.",
            tools=discovery_result.tool_names,
        )
        self.short_memory.add("observation",
            f"Intent: {discovery_result.intent}. Tools: {', '.join(discovery_result.tool_names)}")

        # --- Phase 4: Recall past incidents ---
        past_incidents_text = ""
        try:
            past = await LongTermMemory.recall_similar(user_message, limit=3)
            if past:
                lines = []
                for inc in past:
                    lines.append(f"- [{inc['category']}] {inc['problem'][:100]} → {inc['solution'][:100]}")
                past_incidents_text = "\n".join(lines)
        except Exception:
            past_incidents_text = "(no past incidents)"

        # --- Phase 5: Build system prompt ---
        tool_desc_lines = []
        for t in discovery_result.tools:
            tool_desc_lines.append(f"- {t.name}: {t.description}")
        tool_descriptions = "\n".join(tool_desc_lines)

        import subprocess
        try:
            whoami = subprocess.run("whoami", shell=True, capture_output=True, text=True, timeout=5).stdout.strip()
            pwd = subprocess.run("pwd", shell=True, capture_output=True, text=True, timeout=5).stdout.strip()
        except Exception:
            whoami, pwd = "unknown", "/home"

        system_prompt = _SYSTEM_PROMPT.format(
            workspace_context=workspace_text,
            system_user=whoami,
            working_dir=pwd,
            tool_count=len(discovery_result.tools),
            tool_descriptions=tool_descriptions,
            past_incidents=past_incidents_text or "(none)",
        )
        
        if terminal_cwd:
            system_prompt += f"\n\n[IDE CONTEXT]\nThe user is currently working in the terminal at directory: {terminal_cwd}\nAssume relative paths or unspecified paths refer to this directory."

        # --- Phase 6: Build message history ---
        history = await self._fetch_history(db_session_id)
        messages = [SystemMessage(content=system_prompt)]
        for msg in history[-20:-1]:
            if msg.sender.lower() == "user":
                messages.append(HumanMessage(content=msg.message))
            else:
                messages.append(AIMessage(content=msg.message))
        messages.append(HumanMessage(content=user_message))

        # --- Phase 8: Run LangGraph agent loop ---
        yield evt_planning("Creating execution plan and starting reasoning loop...")

        try:
            from .controller import AutonomousController
            from .artifacts import ArtifactManager
            from chatbot.models import Investigation, InvestigationTask, InvestigationFinding
            import json

            controller = AutonomousController(llm, discovery_result.tools, system_prompt)
            agent = controller.build_graph()

            final_message = ""
            plan_data = {}
            findings_data = {}
            artifact_mgr = None
            if workspace_ctx:
                artifact_mgr = ArtifactManager(workspace_ctx.path)
                
            task_plan_path = f".neurosys/sessions/{self.session_id}/task_plan.json"
            findings_path = f".neurosys/sessions/{self.session_id}/findings.json"

            latest_inv = None
            if intent == "investigation":
                latest_inv = await sync_to_async(
                    lambda: Investigation.objects.filter(session_id=self.session_id).order_by('-created_at').first()
                )()
            if latest_inv:
                tasks = await sync_to_async(lambda: list(latest_inv.tasks.all()))()
                findings = await sync_to_async(lambda: list(latest_inv.findings.all()))()
                plan_data = {
                    "investigation_id": latest_inv.id,
                    "title": latest_inv.title,
                    "tasks": [{"task": t.title, "status": t.status} for t in tasks]
                }
                findings_data = {
                    "investigation_id": latest_inv.id,
                    "findings": [f.content for f in findings]
                }
            
            initial_state = {
                "messages": messages,
                "goal": user_message,
                "plan": plan_data if isinstance(plan_data, dict) else {},
                "findings": findings_data if isinstance(findings_data, dict) else {},
                "iteration": 0,
                "is_completed": False
            }
            
            # Continuation classification
            is_continuation = False
            if history and initial_state["plan"] and initial_state["plan"].get("tasks") and intent == "investigation":
                prev_goal = initial_state["plan"].get("title", "")
                is_continuation_prompt = f"Previous investigation goal: '{prev_goal}'. New request: '{user_message}'. Is the user continuing the investigation or starting a completely new one? Reply 'CONTINUE' or 'NEW'."
                resp = await llm.ainvoke([HumanMessage(content=is_continuation_prompt)])
                if "CONTINUE" in resp.content.upper():
                    is_continuation = True
                    
            if not is_continuation and intent == "investigation":
                from .events import evt_investigation_started
                inv_id = "inv_" + str(uuid.uuid4())[:8]
                now_str = time.strftime("%Y-%m-%dT%H:%M:%SZ")
                plan_data = {"investigation_id": inv_id, "title": user_message[:40], "created_at": now_str, "tasks": []}
                findings_data = {"investigation_id": inv_id, "title": user_message[:40], "created_at": now_str, "findings": []}
                initial_state["plan"] = plan_data
                initial_state["findings"] = findings_data
                
                # Persist to DB
                await sync_to_async(Investigation.objects.create)(
                    id=inv_id,
                    session_id=self.session_id,
                    title=user_message[:40]
                )
                
                yield evt_investigation_started(inv_id, user_message[:40])

            async for event in agent.astream_events(initial_state, version="v2"):
                kind = event["event"]
                name = event.get("name", "")
                tags = event.get("tags", [])
                
                with open("/home/paul/project-ai/NeuroSys-AI/ai_config/logs_test.txt", "a") as f:
                    f.write(f"kind={kind}, name={name}, tags={tags}\n")
                
                # Intercept StateGraph Node outputs
                if kind == "on_chain_end":
                    if name == "planner":
                        state_output = event["data"].get("output", {})
                        if isinstance(state_output, dict) and "plan" in state_output:
                            from .events import evt_task_plan
                            new_plan = state_output["plan"]
                            plan_data = new_plan
                            yield evt_task_plan(new_plan)
                            if artifact_mgr:
                                await artifact_mgr.upsert_artifact(task_plan_path, json.dumps(new_plan, indent=2), action_type="active_state")
                            
                            inv_id = new_plan.get("investigation_id")
                            if inv_id:
                                await sync_to_async(lambda: InvestigationTask.objects.filter(investigation_id=inv_id).delete())()
                                for idx, t in enumerate(new_plan.get("tasks", [])):
                                    await sync_to_async(InvestigationTask.objects.create)(
                                        investigation_id=inv_id,
                                        title=t["task"],
                                        status=t["status"],
                                        task_order=idx
                                    )
                    elif name == "reflector":
                        state_output = event["data"].get("output", {})
                        if isinstance(state_output, dict):
                            if "findings" in state_output:
                                from .events import evt_findings
                                new_findings = state_output["findings"]
                                findings_data = new_findings
                                yield evt_findings(new_findings)
                                
                                # Sync Findings to DB
                                inv_id = new_findings.get("investigation_id")
                                if inv_id:
                                    new_f_list = new_findings.get("findings", [])
                                    await sync_to_async(lambda: InvestigationFinding.objects.filter(investigation_id=inv_id).delete())()
                                    for f in new_f_list:
                                        await sync_to_async(InvestigationFinding.objects.create)(
                                            investigation_id=inv_id,
                                            content=f
                                        )
                            if "plan" in state_output:
                                from .events import evt_task_plan, evt_task_updated
                                new_plan = state_output["plan"]
                                new_tasks = new_plan.get("tasks", [])
                                old_tasks = plan_data.get("tasks", []) if isinstance(plan_data, dict) else []
                                
                                for idx, p in enumerate(new_tasks):
                                    old_p = old_tasks[idx] if idx < len(old_tasks) else {}
                                    if old_p and old_p.get("status") != p.get("status"):
                                        yield evt_task_updated({
                                            "task_id": idx,
                                            "task": p.get("task"),
                                            "old_status": old_p.get("status"),
                                            "new_status": p.get("status")
                                        })
                                plan_data = new_plan
                                yield evt_task_plan(new_plan)
                                
                                # Sync Tasks to DB
                                inv_id = new_plan.get("investigation_id")
                                if inv_id:
                                    await sync_to_async(lambda: InvestigationTask.objects.filter(investigation_id=inv_id).delete())()
                                    for idx, t in enumerate(new_tasks):
                                        await sync_to_async(InvestigationTask.objects.create)(
                                            investigation_id=inv_id,
                                            title=t["task"],
                                            status=t["status"],
                                            task_order=idx
                                        )

                elif kind == "on_chat_model_stream":
                    if "agent_llm" in tags:
                        chunk = event["data"].get("chunk")
                        if chunk:
                            content = getattr(chunk, "content", "")
                            if isinstance(content, str) and content:
                                final_message += content
                                yield evt_message_chunk(final_message)
                            elif isinstance(content, list):
                                try:
                                    text_part = "".join(c.get("text", "") if isinstance(c, dict) else str(c) for c in content)
                                    if text_part:
                                        final_message += text_part
                                        yield evt_message_chunk(final_message)
                                except:
                                    pass

                elif kind == "on_chat_model_end":
                    if "agent_llm" in tags:
                        msg = event["data"].get("output")
                        if msg:
                            tool_calls = getattr(msg, "tool_calls", [])
                            if tool_calls:
                                if final_message.strip():
                                    yield evt_thinking(final_message)
                                final_message = ""

                elif kind == "on_tool_start":
                    tool_name = name
                    args = event["data"].get("input", {})

                    # Safety check
                    meta = ToolRegistry().get_metadata(tool_name)
                    if meta:
                        check = self.safety.check(meta, args)

                        if check.verdict == SafetyVerdict.BLOCKED:
                            yield evt_safety_blocked(tool_name, check.reason)
                            self.short_memory.add("observation", f"BLOCKED: {tool_name} - {check.reason}")
                            continue

                        if check.verdict == SafetyVerdict.WARN:
                            yield evt_safety_warn(tool_name, check.reason)

                    # Emit tool start event
                    cmd_str = str(args.get("command", "")) or str(args.get("path", "")) or str(args)[:100]
                    yield evt_tool_start(tool_name, args)
                    self.short_memory.add("tool_call", f"{tool_name}({cmd_str})")
                    self._tools_used.append(tool_name)

                elif kind == "on_tool_end":
                    result = str(event["data"].get("output", "No output"))
                    yield evt_tool_end(name, result)
                    self.short_memory.add("observation", f"{name} result: {result[:300]}")

        except Exception as e:
            yield evt_error(f"Agent engine error: {str(e)}")
            final_message = ""

        finally:
            # --- Phase 8: Save results and update memory ---
            if final_message:
                await self._save_message(db_session_id, "ai", final_message)
    
                # Store in long-term memory if it looks like a resolved incident
                if any(kw in user_message.lower() for kw in ["error", "failed", "down", "issue", "problem", "fix", "why"]):
                    try:
                        await LongTermMemory.store_incident(
                            problem=user_message,
                            solution=final_message[:500],
                            tools_used=self._tools_used,
                            category=discovery_result.intent,
                            session_id=self.session_id,
                        )
                    except Exception:
                        pass  # non-critical
    
            duration = time.time() - start_time
            yield evt_completed(f"Task completed in {duration:.1f}s", duration=duration)

    # -----------------------------------------------------------------------
    # Logging & Wrapper
    # -----------------------------------------------------------------------
    
    @sync_to_async
    def _log_event(self, event: AgentEvent):
        from chatbot.models import AgentEventLog, ChatSession
        try:
            session = ChatSession.objects.filter(id=self.session_id).first()
            if session:
                AgentEventLog.objects.create(
                    conversation=session,
                    event_type=event.type.value,
                    message=event.content,
                    metadata=event.metadata
                )
        except Exception:
            pass
            
    @sync_to_async
    def _log_tool_execution(self, tool_name, args, result, status, duration):
        from chatbot.models import ToolExecutionLog, ChatSession
        try:
            session = ChatSession.objects.filter(id=self.session_id).first()
            if session:
                ToolExecutionLog.objects.create(
                    conversation=session,
                    tool_name=tool_name,
                    input_parameters=str(args),
                    output_result=str(result),
                    status=status,
                    execution_time=duration
                )
        except Exception:
            pass

    async def run(self, user_message: str, terminal_cwd: Optional[str] = None) -> AsyncGenerator[AgentEvent, None]:
        """Main entry point — wraps internal loop to persist events and tool logs."""
        tool_start_times = {}
        tool_args = {}
        events_history = []
        
        async for event in self._run_internal(user_message, terminal_cwd):
            events_history.append(event.to_dict())
            await self._log_event(event)
            
            if event.type.value == "tool_start":
                tool_name = event.metadata.get("tool", "")
                tool_start_times[tool_name] = time.time()
                tool_args[tool_name] = event.metadata.get("command", "")
                
            elif event.type.value == "tool_end":
                tool_name = event.metadata.get("tool", "")
                duration = time.time() - tool_start_times.get(tool_name, time.time())
                await self._log_tool_execution(
                    tool_name=tool_name,
                    args=tool_args.get(tool_name, ""),
                    result=event.metadata.get("result", ""),
                    status="success",
                    duration=duration
                )
                
            elif event.type.value == "safety_blocked":
                # Assuming the tool is somehow identifiable or we just log blocked status
                await self._log_tool_execution(
                    tool_name="unknown (blocked)",
                    args="",
                    result=event.content,
                    status="blocked",
                    duration=0.0
                )
                
            yield event
            
        if events_history:
            await self._update_last_message_metadata({"events": events_history})

    # -----------------------------------------------------------------------
    # Database helpers
    # -----------------------------------------------------------------------

    async def _get_or_create_session(self):
        from chatbot.models import ChatSession

        @sync_to_async
        def _db():
            sid = str(self.session_id)
            if sid in ("null", ""):
                return ChatSession.objects.create().id
            try:
                session, _ = ChatSession.objects.get_or_create(id=uuid.UUID(sid))
                return session.id
            except (ValueError, Exception):
                return ChatSession.objects.create().id

        return await _db()

    async def _save_message(self, session_id, sender: str, message: str):
        from chatbot.models import ChatMessage

        @sync_to_async
        def _db():
            ChatMessage.objects.create(session_id=session_id, sender=sender, message=message)

        await _db()
        
    async def _update_last_message_metadata(self, metadata: dict):
        from chatbot.models import ChatMessage
        @sync_to_async
        def _db():
            msg = ChatMessage.objects.filter(session_id=self.session_id, sender="ai").order_by("-created_at").first()
            if msg:
                msg.metadata = metadata
                msg.save(update_fields=['metadata'])
        await _db()

    async def _fetch_history(self, session_id):
        from chatbot.models import ChatMessage

        @sync_to_async
        def _db():
            return list(ChatMessage.objects.filter(session_id=session_id).order_by("created_at"))

        return await _db()

    # -----------------------------------------------------------------------
    # Workspace analysis (synchronous)
    # -----------------------------------------------------------------------

    def _analyze_workspace(self, terminal_cwd=None):
        try:
            base_path = terminal_cwd if terminal_cwd else settings.BASE_DIR
            analyzer = WorkspaceAnalyzer(str(base_path))
            return analyzer.analyze()
        except Exception as e:
            print(f"Workspace Analysis failed: {e}")
            return None
