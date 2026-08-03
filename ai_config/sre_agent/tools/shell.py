"""
General shell execution tools — for commands that don't fit
a specific category.  HIGH risk — used as last resort.

All tools registered in the global ToolRegistry on import.
"""

import subprocess

from langchain_core.tools import tool

from .registry import ToolRegistry, ToolMetadata, RiskLevel


# ---------------------------------------------------------------------------
# Dangerous-command blacklist
# ---------------------------------------------------------------------------

_BLOCKED_PATTERNS = [
    "rm -rf /",
    "rm -rf /*",
    "mkfs",
    "dd if=/dev/zero",
    "dd if=/dev/random",
    "chmod 000 /",
    "chmod -R 000",
    ":(){ :|:& };:",       # fork bomb
    "> /dev/sda",
    "mv / ",
    "wget | sh",
    "curl | sh",
    "shutdown",
    "reboot",
    "init 0",
    "init 6",
    "halt",
    "poweroff",
]


def _is_blocked(command: str) -> bool:
    """Check if a command matches any blocked pattern."""
    cmd_lower = command.lower().strip()
    return any(pat in cmd_lower for pat in _BLOCKED_PATTERNS)


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

@tool
def execute_command(command: str) -> str:
    """Execute an arbitrary shell command and return stdout + stderr.
    This is a HIGH-RISK tool — use only when no specialized tool is available.
    Dangerous commands (rm -rf /, mkfs, shutdown, etc.) are blocked."""
    if _is_blocked(command):
        return f"BLOCKED: Command '{command}' matches a dangerous pattern and was refused."

    try:
        r = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=60
        )
        out = (r.stdout + "\n" + r.stderr).strip()
        if len(out) > 4000:
            out = out[:4000] + "\n... (output truncated)"
        return f"$ {command}\n(exit code: {r.returncode})\n{out}"
    except subprocess.TimeoutExpired:
        return f"Error: Command timed out after 60 seconds."
    except Exception as e:
        return f"Error: {e}"


@tool
def safe_execute(command: str) -> str:
    """Execute a shell command from a limited safe set.
    Allowed prefixes: cat, head, tail, wc, sort, uniq, awk, sed (read mode),
    grep, find, which, whoami, id, env, echo, date, stat, file, du, df, free,
    uptime, hostname, ip, ss, dig, nslookup, curl -s, ping, traceroute.
    Commands outside this list are rejected."""
    safe_prefixes = [
        "cat ", "head ", "tail ", "wc ", "sort ", "uniq ", "awk ", "sed ",
        "grep ", "find ", "which ", "whoami", "id ", "id", "env", "echo ",
        "date", "stat ", "file ", "du ", "df", "free", "uptime", "hostname",
        "ip ", "ss ", "dig ", "nslookup ", "curl -s", "ping ", "traceroute ",
        "ls ", "ls", "pwd", "uname",
    ]
    cmd_stripped = command.strip()
    if not any(cmd_stripped.startswith(p) for p in safe_prefixes):
        return f"REJECTED: Command '{command}' is not in the safe command list."

    try:
        r = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=30
        )
        out = (r.stdout + "\n" + r.stderr).strip()
        if len(out) > 3000:
            out = out[:3000] + "\n... (output truncated)"
        return out or "(no output)"
    except subprocess.TimeoutExpired:
        return f"Error: Command timed out after 30 seconds."
    except Exception as e:
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def register_shell_tools() -> None:
    """Register shell tools in the global ToolRegistry."""
    registry = ToolRegistry()
    registry.bulk_register([
        (execute_command, ToolMetadata(
            name="execute_command",
            description="Execute an arbitrary shell command (HIGH RISK — use as last resort)",
            category="shell",
            risk_level=RiskLevel.HIGH,
            input_schema={"command": "string — the shell command to execute"},
            examples=["execute_command('netstat -tlnp')", "execute_command('cat /proc/cpuinfo')"],
            keywords=["shell", "bash", "command", "execute", "run", "terminal"],
        )),
        (safe_execute, ToolMetadata(
            name="safe_execute",
            description="Execute a shell command from a restricted safe set (read-only operations)",
            category="shell",
            risk_level=RiskLevel.MEDIUM,
            input_schema={"command": "string — must start with an allowed prefix"},
            examples=["safe_execute('df -h')", "safe_execute('grep error /var/log/syslog')"],
            keywords=["shell", "safe", "read", "query", "inspect"],
        )),
    ])
