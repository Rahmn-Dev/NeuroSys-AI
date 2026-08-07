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
        "keywords": ["web", "http", "proxy", "server", "site", "url", "logs", "error"],
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
        "keywords": ["runtime", "container", "image", "volume", "pod", "sandbox"],
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
        "keywords": ["deploy", "release", "service", "config", "restart", "app"],
        "description": "Deploying or updating services",
    },
    "log_analysis": {
        "keywords": ["log", "error", "tail", "journal", "syslog", "auth", "grep", "trace"],
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
    (["web server", "reverse proxy", "upstream", "site", "http", "https"], "troubleshooting_web"),
    (["service", "systemctl", "daemon", "failed service", "unit"], "troubleshooting_service"),
    (["ping", "dns", "port", "firewall", "connection refused", "timeout", "unreachable"], "troubleshooting_network"),
    (["cpu", "memory", "ram", "disk", "load average", "uptime", "status", "health"], "system_monitoring"),
    (["container", "runtime", "image", "pod", "sandbox"], "docker_management"),
    (["file", "read", "write", "edit", "config", "directory", "folder"], "file_operations"),
    (["security", "auth", "login", "ssh", "firewall", "permission", "audit", "intrusion"], "security_audit"),
    (["deploy", "deployment", "release", "update service"], "deployment"),
    (["log", "error log", "syslog", "journal", "tail", "grep log"], "log_analysis"),
    (["browser", "search", "google", "documentation", "lookup", "url", "webpage", "website"], "browser_tools"),
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
        # Ensure all tool modules are registered in the global ToolRegistry.
        # We do this inline (not via engine import) to avoid circular imports.
        registry = ToolRegistry()
        if registry.count() == 0:
            from .tools.filesystem import register_filesystem_tools
            from .tools.linux import register_linux_tools
            from .tools.terminal import register_terminal_tools
            from .tools.shell import register_shell_tools
            register_filesystem_tools()
            register_linux_tools()
            register_terminal_tools()
            register_shell_tools()
        self.registry = registry

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
        import logging
        logger = logging.getLogger(__name__)

        intent = self.classify_intent(user_message)
        intent_config = _INTENT_MAP.get(intent, _INTENT_MAP["general"])

        categories = list(intent_config.get("categories", []))
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

        # -----------------------------------------------------------------------
        # STEP 1: Semantic Capability Ranking (runs FIRST, across ALL tools)
        # This ensures high-capability tools like terminal_execute are discovered
        # regardless of their category.
        # -----------------------------------------------------------------------
        semantic_ranked = self.registry.rank_capabilities(user_message, "SIMPLE_INFORMATION")
        
        logger.debug("=== Capability Injection Results ===")
        for r in semantic_ranked[:5]:
            logger.debug(
                f"  {r['name']}: cap_score={r['capability_match_score']:.2f}, "
                f"final_score={r['final_score']:.2f}, "
                f"matched={r['matched_capabilities']}"
            )

        # Collect top capability-matched tools (score > 0) to inject at the front
        capability_results = []
        injected_names = []
        for ranked_tool in semantic_ranked:
            if ranked_tool["capability_match_score"] > 0:
                capability_results.append((ranked_tool["tool"], ranked_tool["meta"]))
                injected_names.append(ranked_tool["name"])
        
        logger.debug(f"=== Injected capability candidates: {injected_names} ===")

        # -----------------------------------------------------------------------
        # STEP 2: Category/keyword query as supplementary tools
        # -----------------------------------------------------------------------
        category_results = self.registry.discover(
            categories=categories,
            keywords=keywords if keywords else None,
        )

        # If too few category results, broaden to full categories
        if len(category_results) < 3:
            category_results = []
            for cat in categories:
                category_results.extend(self.registry.get_by_category(cat))

        # -----------------------------------------------------------------------
        # STEP 3: Merge — capability tools FIRST, then category tools
        # This guarantees capability-matched tools survive the max_tools cap
        # -----------------------------------------------------------------------
        results = capability_results + category_results

        # Deduplicate by tool name
        seen = set()
        unique_results = []
        for tool, meta in results:
            if meta.name not in seen:
                seen.add(meta.name)
                unique_results.append((tool, meta))

        # Always include fundamental tools as fallbacks
        for fallback_tool in ["safe_execute", "read_file", "get_current_directory"]:
            tool = self.registry.get_tool(fallback_tool)
            if tool and fallback_tool not in seen:
                meta = self.registry.get_metadata(fallback_tool)
                unique_results.append((tool, meta))
                seen.add(fallback_tool)

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
