"""
Tool Discovery Agent — intelligently selects the right tools for each task.

Instead of loading ALL tools into the LLM context, this agent:
1. Analyzes the user's intent
2. Maps intent → relevant tool categories + keywords
3. Queries the ToolRegistry to find matching tools
4. Returns a lean, focused toolset (max ~10 tools)
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from langchain_core.tools import BaseTool

from .tools.registry import ToolRegistry, ToolMetadata, RiskLevel


# ---------------------------------------------------------------------------
# Intent categories & their tool mappings
# ---------------------------------------------------------------------------

# Static mapping — fast, no LLM call needed for common intents
_INTENT_MAP: Dict[str, Dict] = {
    "troubleshooting_web": {
        "categories": ["network", "docker", "linux", "filesystem"],
        "keywords": ["nginx", "docker", "logs", "error", "502", "503", "504", "web", "http"],
        "description": "Diagnosing web server / reverse proxy issues",
    },
    "troubleshooting_service": {
        "categories": ["linux", "filesystem"],
        "keywords": ["service", "systemctl", "failed", "restart", "status", "journal", "log"],
        "description": "Diagnosing systemd service failures",
    },
    "troubleshooting_network": {
        "categories": ["network"],
        "keywords": ["port", "ping", "dns", "firewall", "connectivity", "timeout", "connection"],
        "description": "Diagnosing network connectivity issues",
    },
    "system_monitoring": {
        "categories": ["linux"],
        "keywords": ["cpu", "memory", "disk", "uptime", "process", "load", "status"],
        "description": "Checking system health and resource usage",
    },
    "docker_management": {
        "categories": ["docker"],
        "keywords": ["container", "docker", "compose", "image", "volume"],
        "description": "Managing Docker containers and services",
    },
    "file_operations": {
        "categories": ["filesystem"],
        "keywords": ["file", "read", "write", "edit", "search", "directory", "config"],
        "description": "Reading, writing, searching files",
    },
    "security_audit": {
        "categories": ["linux", "network", "filesystem"],
        "keywords": ["auth", "firewall", "user", "login", "permission", "security", "ssh"],
        "description": "Security auditing and hardening",
    },
    "deployment": {
        "categories": ["docker", "linux", "filesystem", "network"],
        "keywords": ["deploy", "compose", "nginx", "service", "config", "restart"],
        "description": "Deploying or updating services",
    },
    "log_analysis": {
        "categories": ["linux", "docker", "filesystem"],
        "keywords": ["log", "error", "tail", "journal", "syslog", "auth", "grep"],
        "description": "Analyzing log files for errors or patterns",
    },
    "general": {
        "categories": ["linux", "filesystem", "shell"],
        "keywords": [],
        "description": "General system administration",
    },
}

# Keyword → intent mapping for fast classification
_KEYWORD_INTENT: List[Tuple[List[str], str]] = [
    (["502", "503", "504", "nginx", "web server", "website", "reverse proxy", "upstream"], "troubleshooting_web"),
    (["service", "systemctl", "daemon", "failed service", "unit"], "troubleshooting_service"),
    (["ping", "dns", "port", "firewall", "connection refused", "timeout", "unreachable"], "troubleshooting_network"),
    (["cpu", "memory", "ram", "disk", "load average", "uptime", "status", "health"], "system_monitoring"),
    (["docker", "container", "compose", "image"], "docker_management"),
    (["file", "read", "write", "edit", "config", "directory", "folder"], "file_operations"),
    (["security", "auth", "login", "ssh", "firewall", "permission", "audit", "intrusion"], "security_audit"),
    (["deploy", "deployment", "release", "update service"], "deployment"),
    (["log", "error log", "syslog", "journal", "tail", "grep log"], "log_analysis"),
]


# ---------------------------------------------------------------------------
# Discovery result
# ---------------------------------------------------------------------------

@dataclass
class DiscoveryResult:
    """What the discovery agent returns to the execution engine."""
    intent: str
    intent_description: str
    tools: List[BaseTool]
    tool_names: List[str]
    categories_used: List[str]


# ---------------------------------------------------------------------------
# Tool Discovery Agent
# ---------------------------------------------------------------------------

class ToolDiscoveryAgent:
    """
    Lightweight agent that maps user intent → relevant tools.

    Uses keyword-based classification (no LLM call) for speed.
    Falls back to broad search if no intent is matched.
    """

    def __init__(self):
        self.registry = ToolRegistry()

    def classify_intent(self, user_message: str) -> str:
        """
        Classify the user's message into an intent category.
        Uses keyword matching — fast and deterministic.
        """
        msg_lower = user_message.lower()

        # Score each intent by keyword hits
        scores: Dict[str, int] = {}
        for keywords, intent in _KEYWORD_INTENT:
            score = sum(1 for kw in keywords if kw in msg_lower)
            if score > 0:
                scores[intent] = scores.get(intent, 0) + score

        if scores:
            return max(scores, key=scores.get)

        return "general"

    def discover(
        self,
        user_message: str,
        workspace_context: Optional[Dict] = None,
        max_tools: int = 12,
    ) -> DiscoveryResult:
        """
        Main entry point: analyze user message → discover relevant tools.

        1. Classify intent from the message
        2. Determine tool categories and keywords
        3. Query the ToolRegistry
        4. Enrich based on workspace context (e.g., if Django project → filesystem tools)
        5. Deduplicate and cap at max_tools
        """
        intent = self.classify_intent(user_message)
        intent_config = _INTENT_MAP.get(intent, _INTENT_MAP["general"])

        categories = list(intent_config["categories"])
        keywords = list(intent_config["keywords"])

        # Enrich from workspace context
        if workspace_context:
            if workspace_context.get("has_docker"):
                if "docker" not in categories:
                    categories.append("docker")
            if workspace_context.get("has_nginx"):
                keywords.extend(["nginx", "web"])
            if workspace_context.get("framework") == "django":
                keywords.extend(["manage.py", "django", "gunicorn", "daphne"])

        # Query registry
        results = self.registry.discover(
            categories=categories,
            keywords=keywords if keywords else None,
        )

        # If too few results from keyword search, broaden to full categories
        if len(results) < 3:
            results = []
            for cat in categories:
                results.extend(self.registry.get_by_category(cat))

        # Deduplicate by tool name
        seen = set()
        unique_results = []
        for tool, meta in results:
            if meta.name not in seen:
                seen.add(meta.name)
                unique_results.append((tool, meta))

        # Always include safe_execute as a fallback
        safe_exec = self.registry.get_tool("safe_execute")
        if safe_exec and "safe_execute" not in seen:
            meta = self.registry.get_metadata("safe_execute")
            unique_results.append((safe_exec, meta))

        # Cap at max_tools
        unique_results = unique_results[:max_tools]

        return DiscoveryResult(
            intent=intent,
            intent_description=intent_config["description"],
            tools=[t for t, _ in unique_results],
            tool_names=[m.name for _, m in unique_results],
            categories_used=categories,
        )

    def get_tools_summary(self) -> str:
        """Return a human-readable summary of all registered tools, grouped by category."""
        categories = self.registry.get_categories()
        lines = []
        for cat in categories:
            tools = self.registry.get_by_category(cat)
            lines.append(f"\n📦 {cat.upper()} ({len(tools)} tools)")
            for _, meta in tools:
                risk_icon = {RiskLevel.LOW: "🟢", RiskLevel.MEDIUM: "🟡", RiskLevel.HIGH: "🔴"}[meta.risk_level]
                lines.append(f"  {risk_icon} {meta.name}: {meta.description}")
        return "\n".join(lines)
