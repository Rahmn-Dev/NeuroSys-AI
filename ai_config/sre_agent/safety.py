"""
Safety Layer — risk analysis and command validation before tool execution.

- Checks tool risk level against thresholds
- Uses a conservative execution allowlist
- Generates approval requests for HIGH-risk actions
- Denies mutations without independently verified action authorization
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict

from .tools.registry import RiskLevel, ToolMetadata


# ---------------------------------------------------------------------------
# Safety result
# ---------------------------------------------------------------------------

class SafetyVerdict(str, Enum):
    APPROVED = "approved"           # safe to proceed
    WARN = "warn"                   # proceed but log a warning
    APPROVAL_REQUIRED = "approval_required"  # needs user confirmation
    BLOCKED = "blocked"             # absolutely refused


@dataclass
class SafetyCheckResult:
    verdict: SafetyVerdict
    risk_level: RiskLevel
    reason: str
    tool_name: str
    args_summary: str


class SafetyLayer:
    """
    Pre-flight safety checks before any tool execution.
    """

    def check(self, tool_meta: ToolMetadata, args: Dict[str, Any]) -> SafetyCheckResult:
        """
        Analyze the tool + arguments and return a SafetyCheckResult.

        In Full Access mode with auto-approve enabled, approval-required
        actions are returned as APPROVED (the execution guard re-evaluates
        and audits the same decision). Hard blocks are never softened here.
        """
        from .security_boundary import evaluate
        verdict, reason = evaluate(tool_meta, args)
        if verdict == "approval_required":
            try:
                from .approvals import full_access_auto_approves
                if full_access_auto_approves():
                    return SafetyCheckResult(
                        SafetyVerdict.APPROVED,
                        RiskLevel.LOW,
                        "Full-access auto-approved; audited at execution",
                        tool_meta.name, "[arguments omitted]",
                    )
            except Exception:
                pass
        return SafetyCheckResult(
            SafetyVerdict(verdict),
            RiskLevel.LOW if verdict == "approved" else RiskLevel.HIGH,
            reason, tool_meta.name, "[arguments omitted]",
        )

    def validate_command(self, command: str) -> SafetyCheckResult:
        return self.check(ToolMetadata(
            name="terminal_execute", description="Shell", category="system",
            risk_level=RiskLevel.HIGH,
        ), {"command": command})

    @staticmethod
    def risk_icon(level: RiskLevel) -> str:
        return {
            RiskLevel.LOW: "🟢",
            RiskLevel.MEDIUM: "🟡",
            RiskLevel.HIGH: "🔴",
        }.get(level, "⚪")
