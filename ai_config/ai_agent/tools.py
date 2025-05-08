from langchain.tools import tool
import subprocess
import os
import json
import psutil

@tool
def run_shell(command: str) -> str:
    """Run a shell command and return output."""
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
        return output
    except subprocess.CalledProcessError as e:
        return f"Error: {e.output}"

@tool
def list_directory(path: str = ".") -> str:
    """List files in a directory."""
    try:
        return "\n".join(os.listdir(path))
    except Exception as e:
        return f"Error: {str(e)}"

@tool
def read_file(file_path: str) -> str:
    """Read the content of a file."""
    try:
        with open(file_path, "r") as f:
            return f.read()
    except Exception as e:
        return f"Error: {str(e)}"

@tool
def write_file(command: str) -> str:
    """
    Write to a file. Input should be in the format: /path/to/file.txt|||file content
    """
    try:
        path, content = command.split("|||", 1)
        with open(path.strip(), "w") as f:
            f.write(content)
        return f"Wrote to {path.strip()}"
    except Exception as e:
        return f"Error: {str(e)}"
    


# @tool
# def get_system_status(_: str = "") -> str:
#     """Return basic system status (CPU, memory, disk)."""
#     status = {
#         "cpu_usage": psutil.cpu_percent(interval=1),
#         "memory_usage": psutil.virtual_memory().percent,
#         "disk_usage": psutil.disk_usage('/').percent,
#         "uptime": psutil.boot_time()
#     }
#     return json.dumps(status, indent=2)

@tool
def restart_service(service_name: str) -> str:
    """Restart a Linux service (requires sudo permissions)."""
    try:
        output = subprocess.check_output(
            f"sudo systemctl restart {service_name}",
            shell=True, stderr=subprocess.STDOUT, text=True
        )
        return f"Service {service_name} restarted successfully.\n{output}"
    except subprocess.CalledProcessError as e:
        return f"Failed to restart {service_name}:\n{e.output}"

@tool
def tail_log(command: str) -> str:
    """Tail a log file. Format input: /path/to/log|||number_of_lines"""
    try:
        path, lines = command.split("|||", 1)
        output = subprocess.check_output(f"tail -n {lines.strip()} {path.strip()}", shell=True, text=True)
        return output
    except subprocess.CalledProcessError as e:
        return f"Error: {e.output}"