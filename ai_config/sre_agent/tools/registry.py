"""
Dynamic Tool Registry for NeuroSysAI SRE Agent.

Tools are registered with rich metadata (category, risk level, examples)
so that the Discovery Agent can selectively load only the tools relevant
to the current task — keeping the LLM context window lean and focused.
"""

from __future__ import annotations

import enum
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence

from langchain_core.tools import BaseTool


# ---------------------------------------------------------------------------
# Risk levels
# ---------------------------------------------------------------------------

class RiskLevel(enum.IntEnum):
    """Tri-level risk classification for tool execution."""
    LOW = 1      # read-only / observational
    MEDIUM = 2   # modifies config, restarts services
    HIGH = 3     # destructive / arbitrary shell


# ---------------------------------------------------------------------------
# Tool metadata
# ---------------------------------------------------------------------------

@dataclass
class ToolMetadata:
    """Rich descriptor attached to every registered tool."""
    name: str
    description: str
    category: str                       # e.g. "filesystem", "linux", "docker"
    risk_level: RiskLevel = RiskLevel.LOW
    required_permission: str = ""       # e.g. "sudo", "docker"
    input_schema: Dict[str, Any] = field(default_factory=dict)
    examples: List[str] = field(default_factory=list)
    keywords: List[str] = field(default_factory=list)  # extra search terms
    priority: int = 50                  # Ranking priority for Fast Tool Intelligence
    capabilities: List[str] = field(default_factory=list)
    supported_intents: List[str] = field(default_factory=list)
    safe_fast_path: bool = False


# ---------------------------------------------------------------------------
# Registry entry (tool + metadata bundled together)
# ---------------------------------------------------------------------------

@dataclass
class _RegistryEntry:
    tool: BaseTool
    meta: ToolMetadata


# ---------------------------------------------------------------------------
# Singleton Tool Registry
# ---------------------------------------------------------------------------

class ToolRegistry:
    """
    Thread-safe, singleton registry that holds every tool the agent
    *could* use.  The Discovery Agent queries this registry — the
    execution engine never loads all tools at once.
    """

    _instance: Optional["ToolRegistry"] = None
    _lock = threading.Lock()

    def __new__(cls) -> "ToolRegistry":
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._entries: Dict[str, _RegistryEntry] = {}
                cls._instance._initialized = False
            return cls._instance

    # -- registration -------------------------------------------------------

    def register(self, tool: BaseTool, meta: ToolMetadata) -> None:
        """Register a tool with its metadata."""
        import logging
        if not getattr(meta, "name", None):
            logging.error("Tool registration failed: Missing 'name' in metadata.")
            meta.name = getattr(tool, "name", "unknown_tool")
            
        if not getattr(meta, "description", None):
            logging.warning(f"Tool '{meta.name}' missing 'description' in metadata. Adding fallback.")
            meta.description = f"Tool: {meta.name}"

        # Ensure the underlying BaseTool also has a description to prevent downstream crashes
        if not getattr(tool, "description", None):
            try:
                tool.description = meta.description
            except Exception as e:
                logging.warning(f"Failed to set description on BaseTool '{meta.name}': {e}")
                
        self._entries[meta.name] = _RegistryEntry(tool=tool, meta=meta)

    def bulk_register(self, pairs: Sequence[tuple[BaseTool, ToolMetadata]]) -> None:
        for tool, meta in pairs:
            self.register(tool, meta)

    # -- discovery queries ---------------------------------------------------

    def list_all(self) -> List[ToolMetadata]:
        """Return metadata for every registered tool."""
        return [e.meta for e in self._entries.values()]

    def get_tool(self, name: str) -> Optional[BaseTool]:
        entry = self._entries.get(name)
        return entry.tool if entry else None

    def get_metadata(self, name: str) -> Optional[ToolMetadata]:
        entry = self._entries.get(name)
        return entry.meta if entry else None

    def get_by_category(self, category: str) -> List[tuple[BaseTool, ToolMetadata]]:
        """Return all tools in a given category."""
        return [
            (e.tool, e.meta) for e in self._entries.values()
            if e.meta.category == category
        ]

    def get_by_risk(self, max_risk: RiskLevel) -> List[tuple[BaseTool, ToolMetadata]]:
        """Return tools at or below the given risk level."""
        return [
            (e.tool, e.meta) for e in self._entries.values()
            if e.meta.risk_level <= max_risk
        ]

    def get_categories(self) -> List[str]:
        """Return a deduplicated list of all categories."""
        return sorted({e.meta.category for e in self._entries.values()})

    def rank_capabilities(self, goal: str, intent: str) -> List[dict]:
        """Rank all registered tools based on capability and intent matching score."""
        import re
        goal_lower = goal.lower()
        
        # Tokenize goal for simple matching
        tokens = set(re.findall(r'\w+', goal_lower))
        
        ranked_results = []
        for name, entry in self._entries.items():
            meta = entry.meta
            
            # Intent match (1.0 if match, 0.0 otherwise)
            intent_match_score = 1.0 if intent in meta.supported_intents else 0.0
            
            # Capability match score
            best_cap_score = 0.0
            matched_caps = []
            
            for cap in meta.capabilities:
                cap_lower = cap.lower()
                # Substring match gives a base score
                if cap_lower in goal_lower:
                    best_cap_score = max(best_cap_score, 0.8)
                    matched_caps.append(cap)
                # Token overlap gives a partial score
                cap_tokens = set(re.findall(r'\w+', cap_lower))
                if cap_tokens:
                    overlap = len(tokens.intersection(cap_tokens)) / len(cap_tokens)
                    if overlap > 0:
                        best_cap_score = max(best_cap_score, overlap * 0.9)
                        if overlap >= 0.4 and cap not in matched_caps:
                            matched_caps.append(cap)
            
            # Calculate final score according to requested formula:
            # final_score = (capability_match_score * 0.6) + (intent_match_score * 0.25) + (priority_score * 0.15)
            # We assume priority_score is scaled 0.0 to 1.0 (priority / 100)
            priority_score = min(meta.priority / 100.0, 1.0)
            
            final_score = (best_cap_score * 0.6) + (intent_match_score * 0.25) + (priority_score * 0.15)
            
            ranked_results.append({
                "name": name,
                "tool": entry.tool,
                "meta": meta,
                "capability_match_score": best_cap_score,
                "intent_match_score": intent_match_score,
                "priority_score": priority_score,
                "final_score": final_score,
                "matched_capabilities": matched_caps
            })
            
        # Sort descending by final_score
        ranked_results.sort(key=lambda x: x["final_score"], reverse=True)
        return ranked_results

    def discover(
        self,
        categories: Optional[List[str]] = None,
        keywords: Optional[List[str]] = None,
        max_risk: RiskLevel = RiskLevel.HIGH,
    ) -> List[tuple[BaseTool, ToolMetadata]]:
        """
        Primary discovery interface.  Filters by categories, keyword match
        (against name + description + keywords), and maximum risk.
        """
        results: List[tuple[BaseTool, ToolMetadata]] = []

        for entry in self._entries.values():
            meta = entry.meta

            # risk filter
            if meta.risk_level > max_risk:
                continue

            # category filter
            if categories and meta.category not in categories:
                continue

            # keyword filter (any keyword matches name, description, or meta.keywords)
            if keywords:
                searchable = (
                    meta.name.lower()
                    + " " + meta.description.lower()
                    + " " + " ".join(meta.keywords).lower()
                    + " " + meta.category.lower()
                )
                if not any(kw.lower() in searchable for kw in keywords):
                    continue

            results.append((entry.tool, entry.meta))

        return results

    def search(self, query: str) -> List[tuple[BaseTool, ToolMetadata]]:
        """Simple text-based search across all tool metadata."""
        return self.discover(keywords=query.lower().split())

    # -- helpers -------------------------------------------------------------

    def count(self) -> int:
        return len(self._entries)

    def reset(self) -> None:
        """Clear all entries — useful for testing."""
        self._entries.clear()
        self._initialized = False

    def __repr__(self) -> str:
        return f"<ToolRegistry tools={self.count()}>"
