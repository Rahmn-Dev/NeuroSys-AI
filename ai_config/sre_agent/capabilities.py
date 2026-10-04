"""Deterministic Goal -> Capability -> Tool selection contract."""
from dataclasses import dataclass
from typing import Any, Iterable


@dataclass(frozen=True)
class CapabilityDecision:
    goal: str
    capability: str
    tool: str | None
    reason: str
    candidates: tuple[str, ...]
    risk: int = 0


def select_tool(goal: str, capability: str, candidates: Iterable[tuple[Any, Any]], *,
                allow_risk: int = 1, required_permission: str = "") -> CapabilityDecision:
    """Select metadata-first; an LLM string cannot directly name a callable."""
    ranked = []
    for tool, meta in candidates:
        risk = int(getattr(meta, "risk_level", 0) or 0)
        permission = getattr(meta, "required_permission", "") or ""
        if risk > allow_risk or (required_permission and permission != required_permission):
            continue
        name = getattr(meta, "name", getattr(tool, "name", ""))
        ranked.append((risk, name, tool))
    ranked.sort(key=lambda row: (row[0], row[1]))
    names = tuple(row[1] for row in ranked)
    if not ranked:
        return CapabilityDecision(goal, capability, None, "no candidate satisfies risk/permission policy", names)
    risk, name, _ = ranked[0]
    return CapabilityDecision(goal, capability, name, "metadata-first candidate selected", names, risk)
