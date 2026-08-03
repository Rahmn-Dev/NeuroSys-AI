import psutil
import subprocess
from langchain_core.tools import tool
from .registry import ToolRegistry, RiskLevel

@tool
def get_cpu_usage() -> str:
    """Returns the current CPU usage percentage and core info."""
    percent = psutil.cpu_percent(interval=1)
    cores = psutil.cpu_count(logical=True)
    return f"CPU Usage: {percent}% across {cores} cores."

@tool
def get_memory_usage() -> str:
    """Returns the current memory (RAM) usage details."""
    mem = psutil.virtual_memory()
    total = round(mem.total / (1024**3), 2)
    used = round(mem.used / (1024**3), 2)
    return f"Memory Usage: {mem.percent}% ({used} GB / {total} GB)"

@tool
def get_disk_usage(path: str = "/") -> str:
    """Returns the disk usage for a specific path."""
    try:
        usage = psutil.disk_usage(path)
        total = round(usage.total / (1024**3), 2)
        used = round(usage.used / (1024**3), 2)
        return f"Disk Usage for {path}: {usage.percent}% ({used} GB / {total} GB)"
    except Exception as e:
        return f"Error reading disk usage: {e}"

@tool
def process_list(sort_by: str = "memory", top: int = 10) -> str:
    """Lists the top processes sorted by 'memory' or 'cpu'."""
    try:
        if sort_by not in ["memory", "cpu"]:
            sort_by = "memory"
        
        procs = []
        for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            procs.append(p.info)
            
        procs = sorted(procs, key=lambda x: x[f'{sort_by}_percent'] or 0, reverse=True)
        
        res = [f"Top {top} processes by {sort_by}:"]
        for p in procs[:top]:
            res.append(f"PID: {p['pid']} | Name: {p['name']} | CPU: {p.get('cpu_percent', 0)}% | MEM: {round(p.get('memory_percent', 0), 1)}%")
            
        return "\n".join(res)
    except Exception as e:
        return f"Error listing processes: {e}"

@tool
def service_health_check(service_name: str) -> str:
    """Checks the health and status of a systemd service."""
    try:
        result = subprocess.run(
            ["systemctl", "status", service_name, "--no-pager"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            return f"Service {service_name} is HEALTHY/RUNNING.\n{result.stdout[:500]}"
        else:
            return f"Service {service_name} status check failed or is stopped.\n{result.stdout[:500]}\n{result.stderr[:500]}"
    except Exception as e:
        return f"Error checking service: {e}"

def register_monitoring_tools():
    from .registry import ToolMetadata
    registry = ToolRegistry()
    registry.register(get_cpu_usage, ToolMetadata(name="get_cpu_usage", description="Returns CPU usage", category="monitoring", risk_level=RiskLevel.LOW))
    registry.register(get_memory_usage, ToolMetadata(name="get_memory_usage", description="Returns memory usage", category="monitoring", risk_level=RiskLevel.LOW))
    registry.register(get_disk_usage, ToolMetadata(name="get_disk_usage", description="Returns disk usage", category="monitoring", risk_level=RiskLevel.LOW))
    registry.register(process_list, ToolMetadata(name="process_list", description="Lists top processes", category="monitoring", risk_level=RiskLevel.LOW))
    registry.register(service_health_check, ToolMetadata(name="service_health_check", description="Checks service health", category="monitoring", risk_level=RiskLevel.LOW))
