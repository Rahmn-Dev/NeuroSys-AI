"""
Safety Layer — risk analysis and command validation before tool execution.

- Checks tool risk level against thresholds
- Validates shell commands against a blacklist
- Generates approval requests for HIGH-risk actions
- Auto-approves LOW-risk, warns on MEDIUM, blocks HIGH (unless approved)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional

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


# ---------------------------------------------------------------------------
# Blocked command patterns
# ---------------------------------------------------------------------------

_BLOCKED_PATTERNS: List[str] = [
    r"rm\s+-rf\s+/\b",
    r"rm\s+-rf\s+/\*",
    r"rm\s+-rf\s+~",
    r"mkfs\b",
    r"dd\s+if=/dev/(zero|random|urandom)\s+of=/dev/",
    r"chmod\s+(000|777)\s+/\b",
    r"chmod\s+-R\s+(000|777)\s+/\b",
    r":\(\)\s*\{\s*:\|\:\&\s*\}\s*;",    # fork bomb
    r">\s*/dev/sd[a-z]",
    r"mv\s+/\s",
    r"\bshutdown\b",
    r"\breboot\b",
    r"\binit\s+[06]\b",
    r"\bhalt\b",
    r"\bpoweroff\b",
    r"wget\s+.*\|\s*sh",
    r"curl\s+.*\|\s*sh",
    r"curl\s+.*\|\s*bash",
    r"python\s+-c\s+.*import\s+os.*system",
]

_BLOCKED_RE = [re.compile(pat, re.IGNORECASE) for pat in _BLOCKED_PATTERNS]

# Commands that bump risk level to MEDIUM even from a LOW tool
_SENSITIVE_COMMANDS = [
    "sudo ", "systemctl status", "systemctl stop", "systemctl start",
    "pip install", "npm install",
    "docker stop",
]

# Commands that strictly require user approval (HIGH risk)
_HIGH_RISK_COMMANDS = [
    "apt install", "apt remove", "apt-get install", "apt-get remove",
    "systemctl restart", "docker restart", "docker rm", "rm -", "rm ",
    "mv ", "cp "
]


# ---------------------------------------------------------------------------
# Safety Layer
# ---------------------------------------------------------------------------

class SafetyLayer:
    """
    Pre-flight safety checks before any tool execution.
    """

    def check(self, tool_meta: ToolMetadata, args: Dict[str, Any]) -> SafetyCheckResult:
        """
        Analyze the tool + arguments and return a SafetyCheckResult.
        """
        tool_name = tool_meta.name
        risk = tool_meta.risk_level
        args_str = str(args)

        # 0. Terminal & Diagnostic Tool Safety Model (Dynamic Denylist)
        if tool_name in ["linux_diagnostic_execute", "terminal_execute", "terminal_session", "start_background_process", "execute_command"]:
            cmd = args.get("command", "").strip()
            if cmd:
                # 0.1 Check strictly blocked dangerous commands
                for regex in _BLOCKED_RE:
                    if regex.search(cmd):
                        return SafetyCheckResult(
                            verdict=SafetyVerdict.BLOCKED,
                            risk_level=RiskLevel.HIGH,
                            reason=f"Dangerous command refused: {regex.pattern}",
                            tool_name=tool_name,
                            args_summary=cmd[:200],
                        )

                # 0.2 Check destructive/high risk/sudo commands requiring approval
                high_risk = ["sudo ", "sudo", "rm ", "rmdir ", "kill ", "killall ", "reboot", "shutdown", "mkfs", "dd ", ">", ">>"]
                if any(h in cmd for h in high_risk):
                    return SafetyCheckResult(
                        verdict=SafetyVerdict.APPROVAL_REQUIRED,
                        risk_level=RiskLevel.HIGH,
                        reason="Elevated privileges (sudo) or destructive command requires explicit approval.",
                        tool_name=tool_name,
                        args_summary=cmd[:200],
                    )
                
                # 0.3 Check service modification commands requiring approval
                medium_risk = ["systemctl restart", "systemctl stop", "systemctl reload", "docker restart", "docker stop", "service "]
                if any(m in cmd for m in medium_risk):
                    return SafetyCheckResult(
                        verdict=SafetyVerdict.APPROVAL_REQUIRED,
                        risk_level=RiskLevel.MEDIUM,
                        reason="Service state modification requires approval.",
                        tool_name=tool_name,
                        args_summary=cmd[:200],
                    )

        # 1. Check blocked patterns in arguments
        for regex in _BLOCKED_RE:
            if regex.search(args_str):
                return SafetyCheckResult(
                    verdict=SafetyVerdict.BLOCKED,
                    risk_level=RiskLevel.HIGH,
                    reason=f"Command matches a dangerous pattern: {regex.pattern}",
                    tool_name=tool_name,
                    args_summary=args_str[:200],
                )

        # 2. Check if args contain sensitive or high risk commands (escalate risk)
        effective_risk = risk
        for high_risk in _HIGH_RISK_COMMANDS:
            if high_risk.lower() in args_str.lower():
                effective_risk = RiskLevel.HIGH
                break
                
        if effective_risk != RiskLevel.HIGH:
            for sensitive in _SENSITIVE_COMMANDS:
                if sensitive.lower() in args_str.lower():
                    effective_risk = max(effective_risk, RiskLevel.MEDIUM)
                    break
        
        # 2.5 Also treat write_file/edit_file (config overwrites) as HIGH risk if they modify system files
        if tool_name in ["write_file", "edit_file"]:
            path_arg = args.get("path", "")
            if path_arg.startswith("/etc/") or path_arg.startswith("/var/") or path_arg.startswith("/usr/"):
                effective_risk = RiskLevel.HIGH

        # 3. Determine verdict based on effective risk
        if effective_risk == RiskLevel.LOW:
            return SafetyCheckResult(
                verdict=SafetyVerdict.APPROVED,
                risk_level=effective_risk,
                reason="Low-risk read-only operation",
                tool_name=tool_name,
                args_summary=args_str[:200],
            )
        elif effective_risk == RiskLevel.MEDIUM:
            return SafetyCheckResult(
                verdict=SafetyVerdict.WARN,
                risk_level=effective_risk,
                reason="Medium-risk operation — proceeding with caution",
                tool_name=tool_name,
                args_summary=args_str[:200],
            )
        else:  # HIGH
            return SafetyCheckResult(
                verdict=SafetyVerdict.APPROVAL_REQUIRED,
                risk_level=effective_risk,
                reason="High-risk operation — requires user approval",
                tool_name=tool_name,
                args_summary=args_str[:200],
            )

    def validate_command(self, command: str) -> SafetyCheckResult:
        """
        Standalone validation for arbitrary shell commands.
        Used by execute_command and similar tools.
        """
        for regex in _BLOCKED_RE:
            if regex.search(command):
                return SafetyCheckResult(
                    verdict=SafetyVerdict.BLOCKED,
                    risk_level=RiskLevel.HIGH,
                    reason=f"Command blocked: matches dangerous pattern",
                    tool_name="shell",
                    args_summary=command[:200],
                )

        # Check sensitivity
        is_sensitive = any(s in command.lower() for s in _SENSITIVE_COMMANDS)
        if is_sensitive:
            return SafetyCheckResult(
                verdict=SafetyVerdict.WARN,
                risk_level=RiskLevel.MEDIUM,
                reason="Command involves a sensitive operation",
                tool_name="shell",
                args_summary=command[:200],
            )

        return SafetyCheckResult(
            verdict=SafetyVerdict.APPROVED,
            risk_level=RiskLevel.LOW,
            reason="Command appears safe",
            tool_name="shell",
            args_summary=command[:200],
        )

    @staticmethod
    def risk_icon(level: RiskLevel) -> str:
        return {
            RiskLevel.LOW: "🟢",
            RiskLevel.MEDIUM: "🟡",
            RiskLevel.HIGH: "🔴",
        }.get(level, "⚪")
