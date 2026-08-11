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

from .context import current_model_name
from .discovery import ToolDiscoveryAgent
from .events import (
    AgentEvent, evt_status, evt_exploring, evt_discovering, evt_planning,
    evt_thinking, evt_tool_start, evt_tool_end, evt_message_chunk,
    evt_completed, evt_error, evt_session_id, evt_session_title, evt_observing,
    evt_safety_blocked, evt_safety_warn, evt_analyzing,
    evt_creating_artifact, evt_restoring_artifact, evt_security_scan,
    evt_hypothesis, evt_resolution_plan,
    evt_parallel_start, evt_parallel_progress, evt_parallel_complete,
    evt_approval_required, AgentEventType
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
    from .tools.docker import register_docker_tools
    from .tools.network import register_network_tools
    from .tools.shell import register_shell_tools
    from .tools.monitoring import register_monitoring_tools
    from .tools.security import register_security_tools
    from .tools.terminal import register_terminal_tools

    register_filesystem_tools()
    register_docker_tools()
    register_network_tools()
    register_shell_tools()
    register_monitoring_tools()
    register_security_tools()
    register_terminal_tools()


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """You are an autonomous SRE execution agent.
Your responsibility is to investigate and resolve infrastructure problems.

Do not only explain what should be done.

When tools are available:
- execute actions
- verify results
- collect evidence
- update investigation state

Never stop after creating a plan.
A plan is not progress.
Execution and verification are progress.

## Current Environment

System:
{system_context}

Current Terminal Directory:
{terminal_cwd}

Active Workspace:
{active_workspace}

Project Workspace:
{project_workspace}

Selected File:
{selected_file}

## Available Tools
You have {tool_count} tools loaded for this task:
{tool_descriptions}

## Past Incidents (if relevant)
{past_incidents}

## Rules
- CRITICAL: The underlying tools execute in a different background directory. You MUST NEVER use relative paths (like '.' or './') in your tool arguments.
- CRITICAL: Always construct FULL ABSOLUTE PATHS by prepending the 'Current Terminal Directory' to your paths before calling any file or directory tools (e.g. read_file, list_directory).
- Terminal directory has highest priority for all path resolution.
- Selected file has highest priority for "this file" references.
- Never assume the user is working inside the project workspace.
- Be precise and technical in your analysis.
- Always show relevant command outputs to support your conclusions.
- If a tool fails, NEVER give up. Try an alternative approach (e.g., if edit_file fails, use sed or echo via terminal).
- ALWAYS read a file's content first before attempting to edit it so you have the exact text.
- If a service fails, keep investigating logs, fixing config files, and restarting until it is successfully running.
- ALWAYS verify the result of your actions (e.g., if you restart a service, check its status to ensure it actually started).
- For destructive operations, explain what you will do BEFORE doing it.
- Format your responses clearly with sections and bullet points.
- CRITICAL: If you need root privileges, simply use `sudo <command>`. The sudo password is automatically injected by the system. NEVER attempt to pipe a password yourself (e.g., do NOT use `echo 'password' | sudo -S`).
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

    def __init__(self, session_id: str = "", model_name: str = "mistral-large-latest", rsa_private_key=None, encrypted_sudo_pwd: str = ""):
        self.session_id = session_id or str(uuid.uuid4())
        self.model_name = model_name
        self.rsa_private_key = rsa_private_key
        self.encrypted_sudo_pwd = encrypted_sudo_pwd
        self.short_memory = ShortTermMemory()
        self.safety = SafetyLayer()
        self.discovery = ToolDiscoveryAgent()
        self._tools_used: List[str] = []

        _ensure_tools_registered()

    def _get_llm(self):
        """Get the selected LLM instance dynamically."""
        provider = None
        target_model = self.model_name
        custom_base_url = None

        try:
            from chatbot.models import AIModel
            db_model = AIModel.objects.filter(model_id=self.model_name).first()
            if not db_model:
                db_model = AIModel.objects.filter(name=self.model_name).first()
            if db_model:
                provider = (db_model.provider or "").lower().strip()
                target_model = db_model.model_id
                custom_base_url = db_model.base_url
        except Exception:
            pass

        # 1. Ollama Native Client
        if provider == 'ollama' or (target_model in ["mistral:latest", "qwen2.5-coder:latest"] and not custom_base_url):
            from langchain_ollama import ChatOllama
            ollama_url = custom_base_url or getattr(settings, "OLLAMA_URL", os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434"))
            return ChatOllama(
                model=target_model,
                base_url=ollama_url,
                temperature=0.1,
                num_ctx=8192
            )

        # 2. Explicit Mistral AI Official API
        elif provider == 'mistral' and not custom_base_url:
            from langchain_mistralai import ChatMistralAI
            api_key = getattr(settings, "MISTRAL_API_KEY", os.environ.get("MISTRAL_API_KEY", ""))
            return ChatMistralAI(
                model=target_model,
                mistral_api_key=api_key,
                temperature=0.1,
                max_tokens=2048,
            )

        # 3. Default / 9Router / Custom Base URL / OpenAI-compatible API (Includes OPENCODE, GROQ, NVIDIA, DeepSeek, GPT-OSS)
        else:
            from langchain_openai import ChatOpenAI
            
            if self.model_name.startswith("9router:"):
                real_model = self.model_name.split(":", 1)[1]
            elif target_model and target_model != "9router":
                real_model = target_model
            else:
                real_model = "OPENCODE"
                
            base_url = custom_base_url if (custom_base_url and custom_base_url.strip()) else "http://localhost:20128/v1"
            api_key = getattr(settings, "ROUTER_API_KEY", os.environ.get("ROUTER_API_KEY", os.environ.get("OPENAI_API_KEY", "9router")))
            
            return ChatOpenAI(
                model=real_model,
                base_url=base_url,
                api_key=api_key if api_key else "9router",
                temperature=0.1,
                max_tokens=4096,
            )




    async def _run_internal(self, user_message: str, terminal_cwd: Optional[str] = None, active_workspace: Optional[str] = None, selected_file: Optional[str] = None, selected_file_name: Optional[str] = None, mode: str = "guided") -> AsyncGenerator[AgentEvent, None]:
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
- Questions about files (e.g., "jelaskan file ini", "explain this file", "fix this file", "analyze this") MUST be classified as 'investigation', NEVER 'conversation'.
User message: {user_message}
Output strictly the category name."""
        resp_intent = await llm.ainvoke([HumanMessage(content=intent_prompt)])
        intent = resp_intent.content.strip().lower()
        
        if intent == "conversation" or any(ci in intent for ci in ["greeting", "thanks", "casual", "identity", "capability"]):
            # Bypass all heavy tooling and respond directly
            history = await self._fetch_history(db_session_id)
            conv_sys_prompt = "You are NeuroSys AI SRE. Respond kindly and briefly."
            
            # Inject IDE Context even for simple conversations
            if active_workspace or terminal_cwd or selected_file:
                conv_sys_prompt += f"\n\n## Current Environment\n\n"
                conv_sys_prompt += f"Current Terminal Directory:\n{terminal_cwd or 'Not provided'}\n\n"
                conv_sys_prompt += f"Active Workspace:\n{active_workspace or terminal_cwd or 'Not provided'}\n\n"
                conv_sys_prompt += f"Selected File:\n{selected_file if selected_file else 'None'}\n"

            messages = [SystemMessage(content=conv_sys_prompt)]
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
        workspace_ctx = await sync_to_async(self._analyze_workspace)(terminal_cwd=active_workspace or terminal_cwd)
        workspace_text = workspace_ctx.to_prompt_context() if workspace_ctx else "No workspace context available"

        # Save workspace info
        if workspace_ctx:
            await WorkspaceMemory.save(workspace_ctx.path, workspace_ctx.to_dict())
            self.short_memory.add("observation", f"Workspace: {workspace_ctx.framework} / {workspace_ctx.language}")

        # --- Phase 3: Discover tools ---
        yield evt_discovering("Analyzing intent and discovering relevant tools...")
        ws_dict = workspace_ctx.to_dict() if workspace_ctx else {}
        max_discovery_tools = 30 if mode == "autonomous" else 12
        discovery_result = self.discovery.discover(user_message, workspace_context=ws_dict, max_tools=max_discovery_tools)

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
        except Exception:
            whoami = "unknown"
            
        system_context_str = f"User: {whoami}\nOS/Env Info:\n{workspace_text}"
        project_workspace_str = settings.BASE_DIR
        terminal_cwd_str = terminal_cwd or "Not provided"
        
        import socket
        # Populate SessionContext
        from .context import current_session_context, SessionContext
        current_session_context.set(SessionContext(
            cwd=terminal_cwd or "",
            user=whoami,
            hostname=socket.gethostname(),
            environment="local",
            rsa_private_key=self.rsa_private_key,
            encrypted_sudo_pwd=self.encrypted_sudo_pwd,
            session_id=self.session_id,
            workspace_path=workspace_ctx.path if workspace_ctx else os.getcwd()
        ))
        
        if terminal_cwd:
            os.environ["SRE_TERMINAL_CWD"] = terminal_cwd
        active_workspace_str = active_workspace or terminal_cwd or "Not provided"
        selected_file_str = f"{selected_file}\n(Name: {selected_file_name})" if selected_file else "None"

        system_prompt = _SYSTEM_PROMPT.format(
            system_context=system_context_str,
            terminal_cwd=terminal_cwd_str,
            active_workspace=active_workspace_str,
            project_workspace=project_workspace_str,
            selected_file=selected_file_str,
            tool_count=len(discovery_result.tools),
            tool_descriptions=tool_descriptions,
            past_incidents=past_incidents_text or "(none)",
        )

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
            ws_path = workspace_ctx.path if workspace_ctx else os.getcwd()
            artifact_mgr = ArtifactManager(ws_path, session_id=self.session_id)
                
            task_plan_path = None
            findings_path = None
            history_path = None

            latest_inv = None
            latest_inv = await sync_to_async(
                lambda: Investigation.objects.filter(session_id=self.session_id).order_by('-created_at').first()
            )()
            if latest_inv:
                tasks = await sync_to_async(lambda: list(latest_inv.tasks.all()))()
                findings = await sync_to_async(lambda: list(latest_inv.findings.all()))()
                plan_data = {
                    "investigation_id": latest_inv.id,
                    "title": latest_inv.title,
                    "tasks": [{
                        "id": idx + 1,
                        "description": t.title,
                        "status": t.status,
                        "attempts": 0,
                        "max_attempts": 3,
                        "tool": None,
                        "tool_args": {},
                        "result": None,
                        "evidence": [],
                        "completed": t.status == "completed"
                    } for idx, t in enumerate(tasks)]
                }
                findings_data = {
                    "investigation_id": latest_inv.id,
                    "findings": [f.content for f in findings]
                }
            
            initial_state = {
                "messages": messages,
                "goal": user_message,
                "terminal_cwd": terminal_cwd or "",
                "active_workspace": active_workspace or "",
                "plan": plan_data if isinstance(plan_data, dict) else {},
                "findings": findings_data if isinstance(findings_data, dict) else {},
                "iteration": 0,
                "is_completed": False
            }
            
            # Continuation classification (Hybrid: Keyword + Strict LLM Fallback)
            is_continuation = False
            if history and initial_state["plan"] and initial_state["plan"].get("tasks"):
                explicit_continuation_phrases = ["continue", "lanjutkan", "lanjut cek", "still failing", "same issue", "tadi"]
                user_msg_lower = user_message.lower()
                if any(phrase in user_msg_lower for phrase in explicit_continuation_phrases):
                    is_continuation = True
                else:
                    # Strict LLM Fallback
                    prev_goal = initial_state["plan"].get("title", "")
                    # Findings contain the root cause and domains from previous investigation
                    prev_findings = "\n".join(initial_state["findings"].get("findings", [])[-4:])
                    
                    is_continuation_prompt = f"""You are a continuation classifier for an SRE investigation agent.

Previous investigation goal: '{prev_goal}'
Previous investigation findings/root causes:
{prev_findings}

New user request: '{user_message}'

Is the new user request a direct continuation of the EXACT SAME investigation?
RULES:
1. STRICT INVESTIGATION BOUNDARIES: A new investigation_id MUST be created (answer 'NEW') when:
   - A new user request starts
   - The incident target changes (e.g. from nginx to postgres)
   - The incident class changes (e.g. from service failure to server slow)
2. If the user is asking about a different service, system issue, or diagnostic domain, answer 'NEW'.
3. Generic words like "service", "error", "failed", or "system" in the new request are NOT enough to classify as a continuation.
4. Only classify as 'CONTINUE' if the new request explicitly refers to the exact same failure or service from the previous findings.

Reply STRICTLY 'CONTINUE' or 'NEW'."""
                    
                    resp = await llm.ainvoke([HumanMessage(content=is_continuation_prompt)])
                    if "CONTINUE" in resp.content.upper():
                        is_continuation = True
                    
            if not is_continuation:
                from .events import evt_investigation_started
                inv_id = "inv_" + str(uuid.uuid4())[:8]
                now_str = time.strftime("%Y-%m-%dT%H:%M:%SZ")
                # Fix 8: Aggregation State Isolation. Strict reset of all states.
                plan_data = {
                    "investigation_id": inv_id, 
                    "title": user_message[:40], 
                    "created_at": now_str, 
                    "tasks": [], 
                    "is_continuation": False,
                    "completed": False,
                    "satisfied_domains": []
                }
                findings_data = {
                    "investigation_id": inv_id, 
                    "title": user_message[:40], 
                    "created_at": now_str, 
                    "findings": []
                }
                initial_state["plan"] = plan_data
                initial_state["findings"] = findings_data
                
                # Persist to DB
                await sync_to_async(Investigation.objects.create)(
                    id=inv_id,
                    session_id=self.session_id,
                    title=user_message[:40]
                )
                
                yield evt_investigation_started(inv_id, user_message[:40])
            else:
                inv_id = initial_state["plan"].get("investigation_id", "inv_" + str(uuid.uuid4())[:8])
                initial_state["plan"]["is_continuation"] = True

            # Fix 8: Artifact Segmentation. Scope artifacts by investigation_id.
            task_plan_path = f".neurosys/sessions/{self.session_id}/investigations/{inv_id}/task_plan.json"
            findings_path = f".neurosys/sessions/{self.session_id}/investigations/{inv_id}/findings.json"
            history_path = f".neurosys/sessions/{self.session_id}/investigations/{inv_id}/execution_history.json"

            if mode in ["autonomous_single", "autonomous_multi"]:
                from .react_engine import ReactEngine
                current_model_name.set(self.model_name)
                react_engine = ReactEngine(llm, discovery_result.tools, system_prompt, self.session_id, mode=mode)
                async for event in react_engine.astream(initial_state):
                    if event.type == AgentEventType.MESSAGE_CHUNK:
                        final_message += event.content
                    elif event.type == AgentEventType.TOOL_START:
                        tool_name = event.metadata.get("tool_name", "unknown")
                        self._tools_used.append(tool_name)
                        args = event.metadata.get("args", {})
                        if tool_name in ["write_file", "edit_file"] and artifact_mgr:
                            path = args.get("path") or args.get("file_path") or args.get("target_file") or args.get("file")
                            if path:
                                try:
                                    ws_base = workspace_ctx.path if workspace_ctx else os.getcwd()
                                    abs_path = os.path.join(ws_base, path) if not os.path.isabs(path) else path
                                    is_backup = any(b in path.lower() for b in [".bak", ".backup", ".orig", ".old", "copy"])
                                    action_type = "backup" if is_backup else ("edit" if tool_name == "edit_file" else "create")
                                    if tool_name == "write_file":
                                        new_content = args.get("content", "")
                                    else:
                                        old_c = ""
                                        if os.path.exists(abs_path):
                                            with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
                                                old_c = f.read()
                                        new_content = old_c.replace(args.get("old_text", ""), args.get("new_text", ""), 1)
                                    from .events import evt_creating_artifact
                                    yield evt_creating_artifact(f"Creating artifact for {os.path.basename(path)}")
                                    await artifact_mgr.create_artifact(path, new_content, action_type=action_type)
                                except Exception:
                                    pass
                    yield event
            else:
                async for event in agent.astream_events(initial_state, version="v2", config={"recursion_limit": 100}):
                    kind = event["event"]
                    name = event.get("name", "")
                    tags = event.get("tags", [])
                
                    with open("/home/paul/project-ai/NeuroSys-AI/ai_config/logs_test.txt", "a") as f:
                        f.write(f"kind={kind}, name={name}, tags={tags}\n")
                
                    # Intercept StateGraph Node outputs
                    if kind == "on_chain_end":
                        if name in ["fast_path_router", "direct_executor", "planner", "worker_scheduler", "aggregator", "goal_checker", "final_response"]:
                            state_output = event["data"].get("output", {})
                            if isinstance(state_output, dict):
                            
                                # Dump execution history if plan/tasks are present
                                if artifact_mgr and "plan" in state_output and isinstance(state_output["plan"], dict):
                                    await artifact_mgr.upsert_artifact(history_path, json.dumps(state_output["plan"].get("tasks", []), indent=2), action_type="history")

                                # Handle Requires Approval
                                if state_output.get("requires_approval"):
                                    final_message = "I need your permission to execute a high-risk command. Please reply with 'approve' to continue, or 'deny' to cancel."
                                    yield evt_error("Safety Block: Approval Required")
                                
                                # UX Transparency: Thinking
                                if state_output.get("thinking"):
                                    yield evt_thinking(state_output["thinking"])

                                # UX Transparency: Hypothesis
                                if state_output.get("hypothesis"):
                                    yield evt_hypothesis(state_output["hypothesis"])

                                # UX Transparency: Resolution Plan
                                if state_output.get("resolution_plan"):
                                    yield evt_resolution_plan(state_output["resolution_plan"])

                                # Worker scheduler completion events
                                if name == "worker_scheduler" and "parallel_results" in state_output:
                                    p_results = state_output["parallel_results"]
                                    total = len(p_results)
                                    task_summaries = [r.get("task_id", "") for r in p_results]
                                    yield evt_parallel_start(total, task_summaries)
                                    total_duration = sum(r.get("duration", 0) for r in p_results)
                                    yield evt_parallel_complete(total, total_duration)

                                # Handle Final Report — always emit, never guard on final_message
                                if name == "final_response" and state_output.get("final_report"):
                                    final_message = state_output["final_report"]
                                    yield evt_message_chunk(final_message)
                                
                                    if artifact_mgr:
                                        artifact_name = state_output.get("artifact_name", "report.md")
                                        # Ensure artifact_name doesn't contain directory traversal
                                        safe_name = os.path.basename(artifact_name)
                                        artifact_path = f".neurosys/sessions/{self.session_id}/artifacts/{safe_name}"
                                        await artifact_mgr.upsert_artifact(artifact_path, final_message, action_type="report")

                                    # Mark Investigation and tasks as completed in DB
                                    inv_id = plan_data.get("investigation_id") if isinstance(plan_data, dict) else None
                                    if inv_id:
                                        await sync_to_async(lambda: Investigation.objects.filter(id=inv_id).update(status="completed"))()
                                        await sync_to_async(lambda: InvestigationTask.objects.filter(investigation_id=inv_id).update(status="completed"))()


                                # Sync Findings
                                if "findings" in state_output:
                                    from .events import evt_findings
                                    new_findings = state_output["findings"]
                                    findings_data = new_findings
                                    yield evt_findings(new_findings)
                                
                                    # Resolve inv_id first
                                    inv_id = plan_data.get("investigation_id") if isinstance(plan_data, dict) else None
                                    if not inv_id and isinstance(new_findings, dict):
                                        inv_id = new_findings.get("investigation_id")
                                
                                    if artifact_mgr:
                                        if inv_id:
                                            findings_path = f".neurosys/sessions/{self.session_id}/investigations/{inv_id}/findings.json"
                                        else:
                                            findings_path = f".neurosys/sessions/{self.session_id}/artifacts/findings.json"
                                        await artifact_mgr.upsert_artifact(findings_path, json.dumps(new_findings, indent=2), action_type="finding")
                                
                                    # Sync Findings to DB
                                    if inv_id:
                                        new_f_list = new_findings.get("findings", []) if isinstance(new_findings, dict) else new_findings
                                        await sync_to_async(lambda: InvestigationFinding.objects.filter(investigation_id=inv_id).delete())()
                                        for f in new_f_list:
                                            await sync_to_async(InvestigationFinding.objects.create)(
                                                investigation_id=inv_id,
                                                content=f
                                            )

                                # Sync Plan
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
                                                "task": p.get("description", p.get("title", p.get("task", ""))),
                                                "old_status": old_p.get("status"),
                                                "new_status": p.get("status")
                                            })
                                    plan_data = new_plan
                                    yield evt_task_plan(new_plan)
                                
                                    if artifact_mgr:
                                        await artifact_mgr.upsert_artifact(task_plan_path, json.dumps(new_plan, indent=2), action_type="plan")
                                
                                    # Sync Tasks to DB
                                    inv_id = new_plan.get("investigation_id")
                                    if inv_id:
                                        await sync_to_async(
                                            lambda: Investigation.objects.get_or_create(
                                                id=inv_id,
                                                defaults={"session_id": self.session_id, "title": user_message[:40]}
                                            )
                                        )()
                                        await sync_to_async(lambda: InvestigationTask.objects.filter(investigation_id=inv_id).delete())()
                                        for idx, t in enumerate(new_tasks):
                                            await sync_to_async(InvestigationTask.objects.create)(
                                                investigation_id=inv_id,
                                                title=t.get("description", t.get("title", t.get("task", ""))),
                                                status=t.get("status", "pending"),
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
                                else:
                                    # If streaming populated final_message incrementally, good.
                                    # If not (invoke path), emit from the complete output now.
                                    full_content = getattr(msg, "content", "")
                                    if full_content and not final_message.strip():
                                        final_message = full_content
                                        yield evt_message_chunk(final_message)

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

                            if check.verdict == SafetyVerdict.APPROVAL_REQUIRED:
                                cmd_str = str(args.get("command", "")) or str(args.get("path", "")) or str(args)[:100]
                                yield evt_approval_required(tool_name, cmd_str, check.reason)

                            if check.verdict == SafetyVerdict.WARN:
                                yield evt_safety_warn(tool_name, check.reason)

                        # Emit tool start event
                        cmd_str = str(args.get("command", "")) or str(args.get("path", "")) or str(args)[:100]
                        yield evt_tool_start(tool_name, args)
                        self.short_memory.add("tool_call", f"{tool_name}({cmd_str})")
                        self._tools_used.append(tool_name)
                    
                        # Intercept file modifications to create artifacts
                        if tool_name in ["write_file", "edit_file"] and artifact_mgr:
                            path = args.get("path") or args.get("file_path") or args.get("target_file") or args.get("file")
                            if path:
                                try:
                                    ws_base = workspace_ctx.path if workspace_ctx else os.getcwd()
                                    abs_path = os.path.join(ws_base, path) if not os.path.isabs(path) else path
                                
                                    is_backup = any(b in path.lower() for b in [".bak", ".backup", ".orig", ".old", "copy"])
                                    action_type = "backup" if is_backup else ("edit" if tool_name == "edit_file" else "create")

                                    if tool_name == "write_file":
                                        new_content = args.get("content", "")
                                    else:
                                        old_c = ""
                                        if os.path.exists(abs_path):
                                            with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
                                                old_c = f.read()
                                        new_content = old_c.replace(args.get("old_text", ""), args.get("new_text", ""), 1)
                                
                                    from .events import evt_creating_artifact
                                    yield evt_creating_artifact(f"Creating artifact for {os.path.basename(path)}")
                                    await artifact_mgr.create_artifact(path, new_content, action_type=action_type)
                                except Exception as e:
                                    pass

                    elif kind == "on_tool_end":
                        result = str(event["data"].get("output", "No output"))
                        yield evt_tool_end(name, result)
                        self.short_memory.add("observation", f"{name} result: {result[:300]}")

                    elif kind == "on_custom_event":
                        if event.get("name") == "worker_activity":
                            from .events import evt_worker_activity
                            yield evt_worker_activity(event["data"].get("workers", []))

        except Exception as e:
            import traceback
            tb = traceback.format_exc()
            yield evt_error(f"Agent engine error: {str(e)}\nTraceback:\n{tb}")
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

    async def run(self, user_message: str, terminal_cwd: Optional[str] = None, active_workspace: Optional[str] = None, selected_file: Optional[str] = None, selected_file_name: Optional[str] = None, mode: str = "guided") -> AsyncGenerator[AgentEvent, None]:
        """Main entry point — wraps internal loop to persist events and tool logs."""
        tool_start_times = {}
        tool_args = {}
        events_history = []
        
        async for event in self._run_internal(user_message, terminal_cwd, active_workspace, selected_file, selected_file_name, mode):
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
