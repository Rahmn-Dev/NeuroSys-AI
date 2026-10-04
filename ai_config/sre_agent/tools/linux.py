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


def _run_argv(command, timeout: int = 30) -> str:
    """Run validated dynamic arguments without a shell."""
    try:
        result = subprocess.run(command, shell=False, capture_output=True, text=True, timeout=timeout)
        output = (result.stdout + "\n" + result.stderr).strip()
        return (output[:3000] + ("\n... (output truncated)" if len(output) > 3000 else "")) or "(no output)"
    except subprocess.TimeoutExpired:
        return f"Error: Command timed out after {timeout}s"
    except Exception:
        return "Error: command execution failed"


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
    elif action in ("status", "is-active", "show", "start", "stop", "restart"):
        if not service_name:
            return f"Error: service_name is required for action '{action}'"
        result = _run_argv(["systemctl", action, service_name])
        if action in {"start", "stop", "restart"}:
            state = _run_argv(["systemctl", "is-active", service_name]).strip()
            expected = "inactive" if action == "stop" else "active"
            if state != expected:
                return f"Error: service postcondition not verified (expected {expected}, observed {state})"
            return f"Service action verified: {service_name} is {state}"
        return result
    else:
        return "Unknown action. Use: status, start, stop, restart, list, failed."


@tool
def service_config_check(service_name: str) -> str:
    """Validate configuration syntax for an allowlisted service without mutation."""
    commands = {
        "nginx": ["nginx", "-t"],
        "apache2": ["apache2ctl", "configtest"],
        "httpd": ["apachectl", "configtest"],
    }
    command = commands.get(str(service_name).lower())
    if not command:
        return "Error: configuration validation is not supported for this service"
    return _run_argv(command, timeout=30)


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
        return _run_argv(["pgrep", "-af", target])
    elif action == "kill":
        if not target:
            return "Error: target (PID) is required for kill."
        return _run_argv(["kill", target])
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
        return _run_argv(["apt-cache", "search", package])
    elif action == "info":
        if not package:
            return "Error: package name required."
        return _run_argv(["apt-cache", "show", package])
    elif action == "update":
        return _run("apt update 2>&1 | tail -5", timeout=120)
    elif action == "install":
        if not package:
            return "Error: package name required."
        return _run_argv(["apt", "install", "-y", package], timeout=120)
    else:
        return "Unknown action. Use: list_installed, search, info, update, install."


@tool
def log_reader(source: str, lines: int = 50, filter_pattern: str = "") -> str:
    """Read system logs.
    `source`: syslog, auth, kern, journal, or a file path.
    `lines`: number of tail lines (default 50).
    `filter_pattern`: optional grep filter."""
    log_map = {
        "syslog": "/var/log/syslog",
        "auth": "/var/log/auth.log",
        "kern": "/var/log/kern.log",
    }

    try:
        lines = max(1, min(int(lines), 500))
        if source == "journal":
            command = ["journalctl", "--no-pager", "-n", str(lines)]
        elif source in log_map or source.startswith("/"):
            command = ["tail", "-n", str(lines), "--", log_map.get(source, source)]
        else:
            command = ["journalctl", "--no-pager", "-n", str(lines), "-u", source]
        result = subprocess.run(command, capture_output=True, text=True, timeout=15)
        if result.returncode:
            return "Error: log collection failed"
        output = result.stdout
        if filter_pattern:
            output = "\n".join(line for line in output.splitlines() if filter_pattern.lower() in line.lower())
        return output[:12000] or "(no matching log entries)"
    except (ValueError, OSError, subprocess.TimeoutExpired):
        return "Error: log collection failed"



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
            capabilities=["environment_discovery"],
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
            capabilities=["environment_discovery"],
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
            capabilities=["environment_discovery", "network_operation"],
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
            capabilities=["environment_discovery"],
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
            capabilities=["environment_discovery"],
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
            capabilities=["service_management", "environment_discovery"],
        )),
        (service_config_check, ToolMetadata(
            name="service_config_check",
            description="Read-only syntax validation for allowlisted service configuration (nginx/apache)",
            category="linux",
            risk_level=RiskLevel.LOW,
            input_schema={"service_name": "nginx|apache2|httpd"},
            examples=["service_config_check('nginx')"],
            keywords=["nginx", "apache", "config", "configuration", "syntax", "validate", "test"],
            priority=90,
            capabilities=["service_config_validation", "environment_discovery"],
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
            capabilities=["process_management", "environment_discovery"],
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
            capabilities=["package_management", "environment_discovery"],
        )),
        (log_reader, ToolMetadata(
            name="log_reader",
            description="Read bounded system logs under /var/log or journalctl; use this instead of read_file for service logs",
            category="filesystem_operation",
            risk_level=RiskLevel.LOW,
            input_schema={"source": "syslog|auth|kern|journal|<filepath>", "lines": "int", "filter_pattern": "string"},
            examples=["log_reader('/var/log/application.log', 100, 'error')", "log_reader('journal', 50, 'failed')"],
            keywords=["log", "syslog", "journalctl", "error", "tail", "auth", "kern"],
            priority=50,
            capabilities=["filesystem_operation", "environment_discovery"],
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
            capabilities=["environment_discovery"],
        )),
    ])
