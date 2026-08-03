"""
Agent Memory System — three layers of context.

1. ShortTermMemory  — in-memory, per-session task steps
2. WorkspaceMemory  — persistent project info (via Django ORM)
3. LongTermMemory   — persistent incident history (via Django ORM)
"""

from __future__ import annotations

import json
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from asgiref.sync import sync_to_async


# ---------------------------------------------------------------------------
# Short Term Memory — in-memory, per task
# ---------------------------------------------------------------------------

@dataclass
class MemoryEntry:
    """A single step/observation in the agent's working memory."""
    step_type: str          # "plan", "tool_call", "observation", "analysis", "user_input"
    content: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class ShortTermMemory:
    """
    FIFO memory for the active task.  Keeps the last N steps.
    Used to build the agent's "scratchpad" for multi-step reasoning.
    """

    def __init__(self, max_entries: int = 25):
        self._entries: deque[MemoryEntry] = deque(maxlen=max_entries)

    def add(self, step_type: str, content: str, **metadata) -> None:
        self._entries.append(MemoryEntry(
            step_type=step_type,
            content=content,
            metadata=metadata,
        ))

    def get_all(self) -> List[MemoryEntry]:
        return list(self._entries)

    def get_last(self, n: int = 5) -> List[MemoryEntry]:
        return list(self._entries)[-n:]

    def to_prompt_text(self) -> str:
        """Format memory as text for injection into LLM prompt."""
        if not self._entries:
            return "(no previous steps)"
        lines = []
        for i, entry in enumerate(self._entries, 1):
            prefix = {
                "plan": "📋 Plan",
                "tool_call": "🔧 Tool",
                "observation": "👁️ Observed",
                "analysis": "🧠 Analysis",
                "user_input": "👤 User",
            }.get(entry.step_type, f"📝 {entry.step_type}")
            lines.append(f"Step {i} [{prefix}]: {entry.content[:500]}")
        return "\n".join(lines)

    def clear(self) -> None:
        self._entries.clear()

    def __len__(self) -> int:
        return len(self._entries)


# ---------------------------------------------------------------------------
# Workspace Memory — persistent via Django ORM
# ---------------------------------------------------------------------------

class WorkspaceMemory:
    """
    Persists workspace analysis results (framework, structure, etc.)
    via the WorkspaceInfo Django model.
    """

    @staticmethod
    @sync_to_async
    def save(workspace_path: str, context_dict: Dict[str, Any]) -> None:
        from chatbot.models import WorkspaceInfo
        WorkspaceInfo.objects.update_or_create(
            workspace_path=workspace_path,
            defaults={
                "framework": context_dict.get("framework", "unknown"),
                "language": context_dict.get("language", "unknown"),
                "database": context_dict.get("database", "unknown"),
                "web_server": context_dict.get("web_server", "unknown"),
                "dependencies_json": json.dumps(context_dict.get("dependencies", [])),
                "deployment_json": json.dumps(context_dict.get("deployment_methods", [])),
                "has_docker": context_dict.get("has_docker", False),
                "has_nginx": context_dict.get("has_nginx", False),
                "context_json": json.dumps(context_dict),
            }
        )

    @staticmethod
    @sync_to_async
    def load(workspace_path: str) -> Optional[Dict[str, Any]]:
        from chatbot.models import WorkspaceInfo
        try:
            info = WorkspaceInfo.objects.get(workspace_path=workspace_path)
            return json.loads(info.context_json) if info.context_json else None
        except WorkspaceInfo.DoesNotExist:
            return None


# ---------------------------------------------------------------------------
# Long Term Memory — persistent incident history
# ---------------------------------------------------------------------------

class LongTermMemory:
    """
    Stores past incidents and solutions.
    Enables the agent to learn from previous troubleshooting sessions.
    """

    @staticmethod
    @sync_to_async
    def store_incident(
        problem: str,
        solution: str,
        tools_used: List[str],
        category: str = "general",
        session_id: str = "",
    ) -> None:
        from chatbot.models import AgentIncident
        AgentIncident.objects.create(
            problem=problem,
            solution=solution,
            tools_used_json=json.dumps(tools_used),
            category=category,
            session_id=session_id,
        )

    @staticmethod
    @sync_to_async
    def recall_similar(query: str, limit: int = 5) -> List[Dict[str, Any]]:
        """
        Search for similar past incidents using keyword matching.
        Returns a list of dicts with problem, solution, tools_used.
        """
        from chatbot.models import AgentIncident
        from django.db.models import Q

        words = [w for w in query.lower().split() if len(w) > 2]
        if not words:
            # Fall back to most recent
            incidents = AgentIncident.objects.order_by("-created_at")[:limit]
        else:
            q = Q()
            for word in words[:5]:  # cap to avoid huge queries
                q |= Q(problem__icontains=word) | Q(solution__icontains=word)
            incidents = AgentIncident.objects.filter(q).order_by("-created_at")[:limit]

        return [
            {
                "problem": inc.problem,
                "solution": inc.solution,
                "tools_used": json.loads(inc.tools_used_json) if inc.tools_used_json else [],
                "category": inc.category,
                "timestamp": inc.created_at.isoformat() if inc.created_at else "",
            }
            for inc in incidents
        ]

    @staticmethod
    @sync_to_async
    def get_recent(limit: int = 10) -> List[Dict[str, Any]]:
        from chatbot.models import AgentIncident
        incidents = AgentIncident.objects.order_by("-created_at")[:limit]
        return [
            {
                "problem": inc.problem,
                "solution": inc.solution,
                "category": inc.category,
                "timestamp": inc.created_at.isoformat() if inc.created_at else "",
            }
            for inc in incidents
        ]

# ---------------------------------------------------------------------------
# Conversation Memory — persistent chat history and metadata
# ---------------------------------------------------------------------------

class ConversationMemory:
    """Stores and retrieves conversation messages and agent states."""
    
    @staticmethod
    @sync_to_async
    def add_message(session_id: str, role: str, content: str, metadata: dict = None) -> None:
        from chatbot.models import ChatSession, ChatMessage
        if not metadata:
            metadata = {}
        try:
            session = ChatSession.objects.get(id=session_id)
            ChatMessage.objects.create(
                session=session,
                role=role,
                sender='user' if role == 'user' else 'ai',
                message=content,
                metadata=metadata
            )
        except ChatSession.DoesNotExist:
            pass

    @staticmethod
    @sync_to_async
    def get_messages(session_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        from chatbot.models import ChatSession, ChatMessage
        try:
            session = ChatSession.objects.get(id=session_id)
            messages = session.messages.order_by('created_at')[:limit]
            return [
                {
                    "role": msg.role,
                    "content": msg.message,
                    "metadata": msg.metadata,
                    "timestamp": msg.created_at.isoformat()
                }
                for msg in messages
            ]
        except ChatSession.DoesNotExist:
            return []
