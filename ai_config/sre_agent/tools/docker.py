"""
Docker management tools — containers, images, compose, logs.

All tools registered in the global ToolRegistry on import.
"""

import subprocess

from langchain_core.tools import tool

from .registry import ToolRegistry, ToolMetadata, RiskLevel


def _run(cmd: str, timeout: int = 30) -> str:
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
def container_list(show_all: bool = False) -> str:
    """List Docker containers. Set show_all=True to include stopped containers."""
    flag = "-a" if show_all else ""
    return _run(f'docker ps {flag} --format "table {{{{.ID}}}}\\t{{{{.Names}}}}\\t{{{{.Status}}}}\\t{{{{.Ports}}}}"')


@tool
def container_inspect(container: str) -> str:
    """Inspect a Docker container — detailed JSON configuration, network, mounts, etc.
    `container` can be a name or ID."""
    output = _run(f"docker inspect {container} 2>&1")
    if len(output) > 3000:
        # Provide a summary instead
        summary = _run(
            f'docker inspect --format '
            f'"Name: {{{{.Name}}}}\\nState: {{{{.State.Status}}}}\\n'
            f'Image: {{{{.Config.Image}}}}\\nPorts: {{{{.NetworkSettings.Ports}}}}\\n'
            f'RestartCount: {{{{.RestartCount}}}}\\nStartedAt: {{{{.State.StartedAt}}}}" '
            f'{container}'
        )
        return summary
    return output


@tool
def container_logs(container: str, lines: int = 100, since: str = "") -> str:
    """Get logs from a Docker container.
    `container`: name or ID.
    `lines`: number of tail lines.
    `since`: time filter (e.g. '1h', '30m', '2024-01-01')."""
    cmd = f"docker logs --tail {lines}"
    if since:
        cmd += f" --since {since}"
    cmd += f" {container} 2>&1"
    return _run(cmd)


@tool
def container_restart(container: str) -> str:
    """Restart a Docker container by name or ID."""
    return _run(f"docker restart {container} 2>&1")


@tool
def container_exec(container: str, command: str) -> str:
    """Execute a command inside a running Docker container.
    Use with caution — this runs arbitrary commands in the container."""
    return _run(f"docker exec {container} {command} 2>&1", timeout=30)


@tool
def docker_compose_status(compose_dir: str = ".") -> str:
    """Show status of Docker Compose services in the given directory."""
    return _run(f"cd {compose_dir} && docker compose ps 2>&1 || docker-compose ps 2>&1")


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def register_docker_tools() -> None:
    """Register all Docker tools in the global ToolRegistry."""
    registry = ToolRegistry()
    registry.bulk_register([
        (container_list, ToolMetadata(
            name="container_list",
            description="List Docker containers (running or all)",
            category="docker",
            risk_level=RiskLevel.LOW,
            input_schema={"show_all": "bool (default: false)"},
            examples=["container_list()", "container_list(True)"],
            keywords=["docker", "container", "ps", "list", "running", "stopped"],
        )),
        (container_inspect, ToolMetadata(
            name="container_inspect",
            description="Inspect a Docker container's full configuration",
            category="docker",
            risk_level=RiskLevel.LOW,
            input_schema={"container": "string — container name or ID"},
            examples=["container_inspect('nginx')"],
            keywords=["docker", "inspect", "config", "network", "ports", "mounts"],
        )),
        (container_logs, ToolMetadata(
            name="container_logs",
            description="Retrieve logs from a Docker container",
            category="docker",
            risk_level=RiskLevel.LOW,
            input_schema={"container": "string", "lines": "int (default 100)", "since": "string (optional)"},
            examples=["container_logs('web-app', 200, '1h')"],
            keywords=["docker", "logs", "container", "error", "output", "debug"],
        )),
        (container_restart, ToolMetadata(
            name="container_restart",
            description="Restart a Docker container",
            category="docker",
            risk_level=RiskLevel.MEDIUM,
            required_permission="docker",
            input_schema={"container": "string — container name or ID"},
            examples=["container_restart('nginx')"],
            keywords=["docker", "restart", "container", "reload"],
        )),
        (container_exec, ToolMetadata(
            name="container_exec",
            description="Execute a command inside a running Docker container",
            category="docker",
            risk_level=RiskLevel.HIGH,
            required_permission="docker",
            input_schema={"container": "string", "command": "string"},
            examples=["container_exec('web', 'cat /etc/nginx/nginx.conf')"],
            keywords=["docker", "exec", "command", "shell", "inside"],
        )),
        (docker_compose_status, ToolMetadata(
            name="docker_compose_status",
            description="Show status of Docker Compose services",
            category="docker",
            risk_level=RiskLevel.LOW,
            input_schema={"compose_dir": "string — path to compose directory"},
            examples=["docker_compose_status('/opt/myapp')"],
            keywords=["docker", "compose", "services", "status", "stack"],
        )),
    ])
