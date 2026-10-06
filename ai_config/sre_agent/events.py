"""
Agent Event Types — structured events streamed to the frontend.

Every step of the agent loop emits an event so the UI can show
real-time progress with proper categorisation and styling.
"""

from __future__ import annotations

import enum
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional



import re

_SECRET_PATTERNS = [
    (re.compile(r"(?i)(api[_-]?key|password|secret|token|bearer)\s*[:=]\s*\S+"), r"\1=***"),
    (re.compile(r"sk-[A-Za-z0-9_-]{10,}"), "sk-***"),
    (re.compile(r"-----BEGIN[^-]*PRIVATE KEY-----.*?-----END[^-]*PRIVATE KEY-----", re.S), "[REDACTED PRIVATE KEY]"),
]


def redact_text(text, max_len: int = 4000) -> str:
    """Strip obvious secret material and cap length. For UI/audit display."""
    if not text:
        return "" if text is None else text
    out = str(text)
    for pattern, repl in _SECRET_PATTERNS:
        out = pattern.sub(repl, out)
    if len(out) > max_len:
        out = out[:max_len] + "\n... [truncated]"
    return out


def summarize_tool_args(args) -> str:
    """One-line, secret-safe description of what the tool call does."""
    if isinstance(args, str):
        return redact_text(args, 120)
    if not isinstance(args, dict):
        return str(args)[:120]
    for key in ("command", "path", "file_path", "target_file", "url", "pattern"):
        if key in args and args[key]:
            return redact_text(str(args[key]), 120)
    if "agent_type" in args:
        return str(args["agent_type"])
    return redact_text(json.dumps(args, default=str), 120)


def sanitize_tool_args_for_audit(args) -> dict:
    """Copy of the call args suitable for the execution audit record."""
    safe = {}
    for key, value in (args or {}).items():
        text = value if isinstance(value, str) else json.dumps(value, default=str)
        if any(marker in key.lower() for marker in ("password", "secret", "api_key", "apikey", "token", "auth")):
            safe[key] = "***"
        else:
            safe[key] = redact_text(text, 300)
    return safe


class AgentEventType(str, enum.Enum):
    """All possible event types the agent can emit."""
    STATUS = "status"
    EXPLORING = "exploring"
    DISCOVERING_TOOLS = "discovering_tools"
    PLANNING = "planning"
    TASK_PLAN = "task_plan"
    TASK_UPDATED = "task_updated"
    FINDINGS = "findings"
    THINKING = "thinking"
    EXECUTING = "executing"
    OBSERVING = "observing"
    ANALYZING = "analyzing"
    EDITING = "editing"
    CREATING_ARTIFACT = "creating_artifact"
    RESTORING_ARTIFACT = "restoring_artifact"
    SECURITY_SCAN = "security_scan"
    APPROVAL_REQUIRED = "approval_required"
    SECURITY_BLOCKED = "security_blocked"
    SAFETY_BLOCKED = "safety_blocked"
    SAFETY_WARN = "safety_warn"
    MESSAGE_CHUNK = "message_chunk"
    TOOL_START = "tool_start"
    TOOL_END = "tool_end"
    MEMORY_UPDATE = "memory_update"
    COMPLETED = "completed"
    ERROR = "error"
    SESSION_ID = "session_id"
    SESSION_TITLE = "session_title"
    INVESTIGATION_STARTED = "investigation_started"
    HYPOTHESIS = "hypothesis"
    RESOLUTION_PLAN = "resolution_plan"
    PARALLEL_START = "parallel_start"
    PARALLEL_PROGRESS = "parallel_progress"
    PARALLEL_COMPLETE = "parallel_complete"
    WORKER_ACTIVITY = "worker_activity"
    LIFECYCLE = "lifecycle"
    PROVIDER_FALLBACK = "provider_fallback"
    VERIFYING = "verifying"
    RESUMING = "resuming"
    DIRECT_CHAT = "direct_chat"
    MESSAGE_SAVED = "message_saved"


def public_text(value):
    text = str(value)
    text = re.sub(r"<think>.*?(?:</think>|$)", "", text, flags=re.I | re.S)
    text = re.sub(r"(?i)(authorization\s*:\s*bearer\s+)[^\s]+", r"\1[REDACTED]", text)
    text = re.sub(r"(?i)((?:api[_-]?key|password|secret|access[_-]?token)\s*[:=]\s*)[^\s,;]+", r"\1[REDACTED]", text)
    return re.sub(r"\bsk-[A-Za-z0-9_-]{16,}\b", "[REDACTED]", text)


def public_value(value):
    if isinstance(value, str):
        return public_text(value)
    if isinstance(value, dict):
        return {k: "[REDACTED]" if re.search(r"password|secret|api.?key|access.?token", str(k), re.I) else public_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [public_value(v) for v in value]
    return value


@dataclass
class AgentEvent:
    """A single event emitted by the agent engine."""
    type: AgentEventType
    content: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize for JSON WebSocket transmission."""
        d = {
            "type": self.type.value,
            "content": public_text(self.content),
            "timestamp": self.timestamp,
        }
        if self.metadata:
            d.update(public_value(self.metadata))
        if self.type.value in {"thinking", "analyzing", "observing"}:
            d["content"] = {"thinking": "Evaluating collected evidence", "analyzing": "Analyzing collected evidence", "observing": "Observation recorded"}[self.type.value]
        # Tool events stream the operator-visible command and a bounded,
        # redacted copy of the result. Raw *args* are never sent (they can
        # contain passwords or keys), and every string passes through
        # public_text/public_value which mask API keys, tokens and secrets.
        if self.type.value in {"tool_start", "tool_end", "executing"}:
            d.pop("args", None)
            if isinstance(d.get("command"), str):
                d["command"] = public_text(d["command"])
            if isinstance(d.get("result"), str):
                d["result"] = public_text(d["result"])[:1000]
        return d

    def to_history_dict(self) -> Dict[str, Any]:
        """Serialize for durable chat history.

        Same shape as to_dict (history replay code paths keep working), but
        content keeps the real bounded text instead of the live-UI
        placeholders, so a reloaded session shows what actually happened.
        Secrets stay redacted via public_text; message deltas are dropped
        by the caller (the final AI message is stored separately).
        """
        d = self.to_dict()
        raw = public_text(self.content or "").strip()
        if raw:
            d["content"] = raw[:2000]
        findings = d.get("findings")
        if isinstance(findings, list):
            d["findings"] = [str(f)[:1000] for f in findings[:100]]
        return d


# ---------------------------------------------------------------------------
# Convenience constructors
# ---------------------------------------------------------------------------

def evt_message_saved(sender: str, msg_id: str) -> AgentEvent:
    """Typed acknowledgement that a chat message was persisted."""
    return AgentEvent(type=AgentEventType.MESSAGE_SAVED,
                      metadata={"sender": sender, "msg_id": str(msg_id)})

def evt_direct_chat(msg: str = "Direct answer, no tools needed") -> AgentEvent:
    """Marker: this turn was answered directly, with no agent tooling."""
    return AgentEvent(type=AgentEventType.DIRECT_CHAT, content=msg)


def evt_status(msg: str) -> AgentEvent:
    return AgentEvent(type=AgentEventType.STATUS, content=msg)

def evt_lifecycle(status: str, *, run_id: str = "", task_id: str = "", provider: str = "", model: str = "", reason: str = "") -> AgentEvent:
    return AgentEvent(type=AgentEventType.LIFECYCLE, content=status, metadata={
        "status": status, "run_id": run_id, "task_id": task_id,
        "provider": provider, "model": model, "reason": reason,
    })

def evt_verifying(message: str = "Verifying postconditions") -> AgentEvent:
    return AgentEvent(type=AgentEventType.VERIFYING, content=message)

def evt_exploring(msg: str) -> AgentEvent:
    return AgentEvent(type=AgentEventType.EXPLORING, content=msg)

def evt_discovering(msg: str, tools: list = None) -> AgentEvent:
    return AgentEvent(type=AgentEventType.DISCOVERING_TOOLS, content=msg,
                      metadata={"tools": tools or []})

def evt_planning(msg: str) -> AgentEvent:
    return AgentEvent(type=AgentEventType.PLANNING, content=msg)

def evt_task_plan(plan_items: list) -> AgentEvent:
    # plan_items is a list of dicts: [{"task": "Scan workspace", "status": "pending"}, ...]
    return AgentEvent(type=AgentEventType.TASK_PLAN, content="Updating task plan", metadata={"plan": plan_items})

def evt_task_updated(task: dict) -> AgentEvent:
    return AgentEvent(type=AgentEventType.TASK_UPDATED, content=f"Task updated: {task.get('task', '')}", metadata={"task": task})

def evt_findings(findings: list) -> AgentEvent:
    # findings is a list of strings
    return AgentEvent(type=AgentEventType.FINDINGS, content="Updating findings", metadata={"findings": findings})

def evt_thinking(msg: str) -> AgentEvent:
    return AgentEvent(type=AgentEventType.THINKING, content="Evaluating collected evidence")

def evt_executing(tool_name: str, args: str = "") -> AgentEvent:
    return AgentEvent(type=AgentEventType.EXECUTING, content=f"Running {tool_name}",
                      metadata={"tool": tool_name, "args": "[arguments redacted]"})

def evt_tool_start(tool_name: str, args: dict = None) -> AgentEvent:
    detail = summarize_tool_args(args)
    return AgentEvent(type=AgentEventType.TOOL_START, content=f"Running {tool_name}",
                      metadata={"tool": tool_name, "command": detail})

def evt_tool_end(tool_name: str, result: str = "") -> AgentEvent:
    return AgentEvent(type=AgentEventType.TOOL_END, content=result[:500],
                      metadata={"tool": tool_name, "result": result})

def evt_observing(msg: str) -> AgentEvent:
    return AgentEvent(type=AgentEventType.OBSERVING, content=msg)

def evt_analyzing(msg: str) -> AgentEvent:
    return AgentEvent(type=AgentEventType.ANALYZING, content=msg)

# Marks where the reasoning narration ends and the answer begins. It travels in
# the stored message text, so a live turn and the same turn replayed from
# history split at exactly the same place instead of guessing.
FINAL_ANSWER_MARKER = "<!--sre-final-->"


def evt_message_chunk(accumulated: str) -> AgentEvent:
    return AgentEvent(type=AgentEventType.MESSAGE_CHUNK, content=accumulated)

def evt_creating_artifact(msg: str) -> AgentEvent:
    return AgentEvent(type=AgentEventType.CREATING_ARTIFACT, content=msg)

def evt_restoring_artifact(msg: str) -> AgentEvent:
    return AgentEvent(type=AgentEventType.RESTORING_ARTIFACT, content=msg)

def evt_security_scan(msg: str) -> AgentEvent:
    return AgentEvent(type=AgentEventType.SECURITY_SCAN, content=msg)

def evt_approval_required(tool: str, args: str, reason: str, approval_id=None) -> AgentEvent:
    return AgentEvent(type=AgentEventType.APPROVAL_REQUIRED, content=reason,
                      metadata={"tool": tool, "args": args, "approval_id": approval_id})

def evt_security_blocked(reason: str, request_id=None) -> AgentEvent:
    return AgentEvent(type=AgentEventType.SECURITY_BLOCKED, content=reason,
                      metadata={"request_id": request_id} if request_id else {})

def evt_safety_blocked(tool: str, reason: str) -> AgentEvent:
    return AgentEvent(type=AgentEventType.SAFETY_BLOCKED, content=reason,
                      metadata={"tool": tool})

def evt_safety_warn(tool: str, reason: str) -> AgentEvent:
    return AgentEvent(type=AgentEventType.SAFETY_WARN, content=reason,
                      metadata={"tool": tool})

def evt_session_title(title: str) -> AgentEvent:
    return AgentEvent(type=AgentEventType.SESSION_TITLE, content=title)

def evt_investigation_started(investigation_id: str, title: str) -> AgentEvent:
    return AgentEvent(type=AgentEventType.INVESTIGATION_STARTED, content=title, metadata={"investigation_id": investigation_id})

def evt_completed(summary: str, duration: float = 0) -> AgentEvent:
    return AgentEvent(type=AgentEventType.COMPLETED, content=summary,
                      metadata={"duration": duration})

def evt_error(msg: str) -> AgentEvent:
    return AgentEvent(type=AgentEventType.ERROR, content=msg)

def evt_session_id(sid: str) -> AgentEvent:
    return AgentEvent(type=AgentEventType.SESSION_ID, content=sid)

def evt_hypothesis(msg: str) -> AgentEvent:
    return AgentEvent(type=AgentEventType.HYPOTHESIS, content=msg)

def evt_resolution_plan(steps: list) -> AgentEvent:
    return AgentEvent(type=AgentEventType.RESOLUTION_PLAN, content="Resolution plan ready", metadata={"steps": steps})

def evt_parallel_start(total_tasks: int, task_summaries: list = None) -> AgentEvent:
    return AgentEvent(type=AgentEventType.PARALLEL_START,
                      content=f"Executing {total_tasks} tasks in parallel...",
                      metadata={"total": total_tasks, "tasks": task_summaries or []})

def evt_parallel_progress(completed: int, total: int, task_id: str = "", task_desc: str = "") -> AgentEvent:
    return AgentEvent(type=AgentEventType.PARALLEL_PROGRESS,
                      content=f"{completed}/{total} tasks completed",
                      metadata={"completed": completed, "total": total, "task_id": task_id, "task_desc": task_desc})

def evt_parallel_complete(total: int, duration: float = 0) -> AgentEvent:
    return AgentEvent(type=AgentEventType.PARALLEL_COMPLETE,
                      content=f"All {total} tasks completed in {duration:.1f}s",
                      metadata={"total": total, "duration": duration})

def evt_worker_activity(workers: list) -> AgentEvent:
    return AgentEvent(type=AgentEventType.WORKER_ACTIVITY,
                      content="Worker activity updated",
                      metadata={"workers": workers})
