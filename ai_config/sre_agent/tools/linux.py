"""
Linux system administration tools — system info, services, processes,
packages, logs, users.

All tools registered in the global ToolRegistry on import.
"""

import subprocess
from typing import Optional

from langchain_core.tools import tool

from .registry import ToolRegistry, ToolMetadata, RiskLevel


def _run(cmd: str, timeout: int = 30) -> str:
    """Helper — run a shell command and return combined output."""
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        out = (r.stdout + "\n" + r.stderr).strip()
        if len(out) > 3000:
            out = out[:3000] + "\n... (output truncated)"
        return out or "(no output)"
    except subprocess.TimeoutExpired:
        return f"Error: Command timed out after {timeout}s"
    except Exception as e:
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

@tool
def system_info(aspect: str = "all") -> str:
    """Gather Linux system information.
    `aspect` can be: all, cpu, memory, disk, os, uptime, hostname.
    Returns a comprehensive system status report."""
    sections = []

    if aspect in ("all", "os", "hostname"):
        sections.append("=== OS & Host ===\n" + _run("uname -a && hostname"))

    if aspect in ("all", "uptime"):
        sections.append("=== Uptime ===\n" + _run("uptime"))

    if aspect in ("all", "cpu"):
        sections.append("=== CPU ===\n" + _run("lscpu | head -20 && echo '---' && mpstat 2>/dev/null || cat /proc/loadavg"))

    if aspect in ("all", "memory"):
        sections.append("=== Memory ===\n" + _run("free -h"))

    if aspect in ("all", "disk"):
        sections.append("=== Disk ===\n" + _run("df -h --total"))

    return "\n\n".join(sections) if sections else "Unknown aspect. Use: all, cpu, memory, disk, os, uptime, hostname."


@tool
def service_manager(action: str, service_name: str = "") -> str:
    """Manage systemd services.
    `action`: status, start, stop, restart, list, failed.
    `service_name`: required for status/start/stop/restart."""
    if action == "list":
        return _run("systemctl list-units --type=service --state=running --no-pager --no-legend | head -40")
    elif action == "failed":
        return _run("systemctl list-units --failed --no-pager --no-legend")
    elif action in ("status", "start", "stop", "restart"):
        if not service_name:
            return f"Error: service_name is required for action '{action}'"
        return _run(f"systemctl {action} {service_name} 2>&1")
    else:
        return "Unknown action. Use: status, start, stop, restart, list, failed."


@tool
def process_manager(action: str, target: str = "") -> str:
    """Manage Linux processes.
    `action`: list, top, search, kill.
    `target`: process name/PID for search/kill."""
    if action == "list":
        return _run("ps aux --sort=-%mem | head -25")
    elif action == "top":
        return _run("top -b -n 1 | head -30")
    elif action == "search":
        if not target:
            return "Error: target (process name) is required for search."
        return _run(f"pgrep -af '{target}'")
    elif action == "kill":
        if not target:
            return "Error: target (PID) is required for kill."
        return _run(f"kill {target}")
    else:
        return "Unknown action. Use: list, top, search, kill."


@tool
def package_manager(action: str, package: str = "") -> str:
    """Manage system packages (apt/dpkg).
    `action`: list_installed, search, info, update, install.
    `package`: package name for search/info/install."""
    if action == "list_installed":
        return _run("dpkg --list | tail -30")
    elif action == "search":
        if not package:
            return "Error: package name required."
        return _run(f"apt-cache search '{package}' | head -20")
    elif action == "info":
        if not package:
            return "Error: package name required."
        return _run(f"apt-cache show '{package}' 2>/dev/null | head -30")
    elif action == "update":
        return _run("apt update 2>&1 | tail -5", timeout=120)
    elif action == "install":
        if not package:
            return "Error: package name required."
        return _run(f"apt install -y '{package}' 2>&1", timeout=120)
    else:
        return "Unknown action. Use: list_installed, search, info, update, install."


@tool
def log_reader(source: str, lines: int = 50, filter_pattern: str = "") -> str:
    """Read system logs.
    `source`: syslog, auth, kern, nginx, docker, journal, or a file path.
    `lines`: number of tail lines (default 50).
    `filter_pattern`: optional grep filter."""
    log_map = {
        "syslog": "/var/log/syslog",
        "auth": "/var/log/auth.log",
        "kern": "/var/log/kern.log",
        "nginx": "/var/log/nginx/error.log",
        "nginx_access": "/var/log/nginx/access.log",
    }

    if source == "journal":
        cmd = f"journalctl --no-pager -n {lines}"
    elif source == "docker":
        cmd = f"journalctl -u docker --no-pager -n {lines}"
    elif source in log_map:
        cmd = f"tail -n {lines} {log_map[source]}"
    else:
        # treat as file path
        cmd = f"tail -n {lines} {source}"

    if filter_pattern:
        cmd += f" | grep -i '{filter_pattern}'"

    return _run(cmd, timeout=15)


@tool
def memory_info() -> str:
    """Get system memory and RAM usage."""
    return _run("free -h && echo '---' && ps -eo pid,user,%cpu,%mem,cmd --sort=-%mem | head -10")

@tool
def whoami() -> str:
    """Get the current logged in user."""
    from ..context import current_session_context
    try:
        ctx = current_session_context.get()
        if ctx and ctx.user:
            return ctx.user
    except LookupError:
        pass
    return _run("whoami")

@tool
def hostname() -> str:
    """Get the system hostname."""
    from ..context import current_session_context
    try:
        ctx = current_session_context.get()
        if ctx and ctx.hostname:
            return ctx.hostname
    except LookupError:
        pass
    return _run("hostname")

@tool
def uptime() -> str:
    """Get system uptime."""
    return _run("uptime")

@tool
def user_manager(action: str = "who") -> str:
    """Get information about system users.
    `action`: who (currently logged in), last (recent logins), list (all users)."""
    if action == "who":
        return _run("who -a 2>/dev/null || w")
    elif action == "last":
        return _run("last -n 15")
    elif action == "list":
        return _run("awk -F: '$3 >= 1000 {print $1, $3, $6, $7}' /etc/passwd")
    else:
        return "Unknown action. Use: who, last, list."


@tool
def linux_diagnostic_execute(command: str) -> str:
    """Execute a safe Linux diagnostic command via subprocess.
    Allowed commands are restricted by the safety layer (e.g., systemctl status, journalctl, cat, grep, ps, etc)."""
    return _run(command, timeout=20)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def register_linux_tools() -> None:
    """Register all Linux tools in the global ToolRegistry."""
    registry = ToolRegistry()
    registry.bulk_register([
        (memory_info, ToolMetadata(
            name="memory_info",
            description="Get system memory and RAM usage",
            category="linux",
            risk_level=RiskLevel.LOW,
            input_schema={},
            examples=["memory_info()"],
            keywords=["memory", "ram", "free"],
            priority=100,
            capabilities=["resource_monitoring", "memory_analysis"],
            supported_intents=["SIMPLE_INFORMATION"],
            safe_fast_path=True,
        )),
        (whoami, ToolMetadata(
            name="whoami",
            description="Get the current logged in user",
            category="linux",
            risk_level=RiskLevel.LOW,
            input_schema={},
            examples=["whoami()"],
            keywords=["user", "whoami", "current user"],
            priority=100,
            capabilities=["system_analysis", "user_analysis"],
            supported_intents=["SIMPLE_INFORMATION"],
            safe_fast_path=True,
        )),
        (hostname, ToolMetadata(
            name="hostname",
            description="Get the system hostname",
            category="linux",
            risk_level=RiskLevel.LOW,
            input_schema={},
            examples=["hostname()"],
            keywords=["hostname", "host"],
            priority=100,
            capabilities=["system_analysis", "network_analysis"],
            supported_intents=["SIMPLE_INFORMATION"],
            safe_fast_path=True,
        )),
        (uptime, ToolMetadata(
            name="uptime",
            description="Get system uptime",
            category="linux",
            risk_level=RiskLevel.LOW,
            input_schema={},
            examples=["uptime()"],
            keywords=["uptime", "how long"],
            priority=100,
            capabilities=["resource_monitoring", "system_analysis"],
            supported_intents=["SIMPLE_INFORMATION"],
            safe_fast_path=True,
        )),
        (system_info, ToolMetadata(
            name="system_info",
            description="Gather system information (CPU, memory, disk, OS, uptime)",
            category="linux",
            risk_level=RiskLevel.LOW,
            input_schema={"aspect": "all|cpu|memory|disk|os|uptime|hostname"},
            examples=["system_info('memory')", "system_info('all')"],
            keywords=["system", "cpu", "memory", "ram", "disk", "uptime", "os", "uname", "hostname", "status"],
            priority=40,
            capabilities=["resource_monitoring", "system_analysis", "hardware_analysis"],
            supported_intents=["SIMPLE_INFORMATION"],
            safe_fast_path=True,
        )),
        (service_manager, ToolMetadata(
            name="service_manager",
            description="Manage systemd services — status, start, stop, restart, list running, list failed",
            category="linux",
            risk_level=RiskLevel.MEDIUM,
            required_permission="sudo (for start/stop/restart)",
            input_schema={"action": "status|start|stop|restart|list|failed", "service_name": "string (optional)"},
            examples=["service_manager('list')", "service_manager('status', 'nginx')"],
            keywords=["service", "systemctl", "daemon", "nginx", "docker", "start", "stop", "restart", "failed"],
            priority=80,
            capabilities=["service_inspection", "service_management"],
        )),
        (process_manager, ToolMetadata(
            name="process_manager",
            description="List, search, or kill Linux processes",
            category="linux",
            risk_level=RiskLevel.LOW,
            input_schema={"action": "list|top|search|kill", "target": "string (PID or name)"},
            examples=["process_manager('list')", "process_manager('search', 'python')"],
            keywords=["process", "ps", "top", "kill", "pid", "cpu", "memory"],
            priority=60,
            capabilities=["process_analysis", "process_management"],
        )),
        (package_manager, ToolMetadata(
            name="package_manager",
            description="Manage apt/dpkg packages — list, search, info, update, install",
            category="linux",
            risk_level=RiskLevel.MEDIUM,
            required_permission="sudo (for update/install)",
            input_schema={"action": "list_installed|search|info|update|install", "package": "string"},
            examples=["package_manager('search', 'nginx')"],
            keywords=["package", "apt", "dpkg", "install", "update", "dependency"],
            priority=60,
            capabilities=["package_management", "software_analysis"],
        )),
        (log_reader, ToolMetadata(
            name="log_reader",
            description="Read system logs (syslog, auth, kern, nginx, docker, journalctl, or arbitrary log file)",
            category="linux",
            risk_level=RiskLevel.LOW,
            input_schema={"source": "syslog|auth|kern|nginx|docker|journal|<filepath>", "lines": "int", "filter_pattern": "string"},
            examples=["log_reader('nginx', 100, 'error')", "log_reader('journal', 50, 'failed')"],
            keywords=["log", "syslog", "journalctl", "error", "tail", "nginx", "auth", "kern"],
            priority=50,
            capabilities=["log_analysis"],
        )),
        (user_manager, ToolMetadata(
            name="user_manager",
            description="Get information about system users — who is logged in, recent logins, list all users",
            category="linux",
            risk_level=RiskLevel.LOW,
            input_schema={"action": "who|last|list"},
            examples=["user_manager('who')", "user_manager('last')"],
            keywords=["user", "login", "who", "last", "session"],
            priority=50,
            capabilities=["user_analysis", "security_analysis"],
        )),
        (linux_diagnostic_execute, ToolMetadata(
            name="linux_diagnostic_execute",
            description="Execute safe Linux diagnostic commands (e.g. systemctl status, journalctl, cat, grep, ps)",
            category="linux",
            risk_level=RiskLevel.MEDIUM,
            input_schema={"command": "string"},
            examples=["linux_diagnostic_execute('systemctl status nginx')", "linux_diagnostic_execute('nginx -t')"],
            keywords=["linux", "diagnostic", "command", "shell", "execute", "systemctl", "journalctl", "cat", "grep", "ps"],
            priority=10,
            capabilities=["command_execution", "service_inspection", "configuration_validation", "log_analysis", "process_analysis"],
            supported_intents=["SIMPLE_INFORMATION", "DIAGNOSIS"],
            safe_fast_path=False, # Arbitrary commands shouldn't fast-path blindly unless it's a dedicated tool
        )),
    ])
