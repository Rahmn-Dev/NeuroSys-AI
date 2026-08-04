import os
import subprocess
import time
from typing import Dict

from langchain_core.tools import tool
from .registry import ToolRegistry, ToolMetadata, RiskLevel

# ---------------------------------------------------------------------------
# Global State for Persistent Sessions and Background Processes
# ---------------------------------------------------------------------------
_TERMINAL_SESSIONS: Dict[str, dict] = {}
_BACKGROUND_PROCESSES: Dict[str, subprocess.Popen] = {}


@tool
def terminal_execute(command: str, timeout: int = 30) -> str:
    """Execute a Linux command safely, capturing stdout, stderr, and exit code.
    Use this for general system capabilities when specific diagnostic tools are unavailable."""
    import json
    try:
        start_time = time.time()
        p = subprocess.Popen(
            command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        stdout, stderr = p.communicate(timeout=timeout)
        duration = time.time() - start_time
        
        if len(stdout) > 4000: stdout = stdout[:4000] + "\n... (truncated)"
        if len(stderr) > 4000: stderr = stderr[:4000] + "\n... (truncated)"
        
        return json.dumps({
            "command": command,
            "stdout": stdout.strip(),
            "stderr": stderr.strip(),
            "exit_code": p.returncode,
            "duration": f"{duration:.2f}s",
            "pid": p.pid
        }, indent=2)
    except subprocess.TimeoutExpired:
        p.kill()
        return json.dumps({"error": f"Command timed out after {timeout}s", "command": command})
    except Exception as e:
        return json.dumps({"error": str(e), "command": command})


@tool
def terminal_session(action: str, session_id: str, command: str = "") -> str:
    """Manage a persistent interactive shell session.
    `action` can be 'create', 'execute', or 'close'."""
    import json
    
    if action == "create":
        if session_id in _TERMINAL_SESSIONS:
            return json.dumps({"error": f"Session {session_id} already exists."})
        _TERMINAL_SESSIONS[session_id] = {"cwd": os.getcwd(), "env": os.environ.copy()}
        return json.dumps({"status": "created", "session_id": session_id, "cwd": _TERMINAL_SESSIONS[session_id]["cwd"]})
        
    elif action == "execute":
        if session_id not in _TERMINAL_SESSIONS:
            return json.dumps({"error": f"Session {session_id} not found. Create it first."})
        
        session = _TERMINAL_SESSIONS[session_id]
        
        # Handle 'cd' specially to update the stateful CWD
        cmd_stripped = command.strip()
        if cmd_stripped.startswith("cd "):
            target_dir = cmd_stripped[3:].strip()
            if target_dir.startswith("~"):
                target_dir = os.path.expanduser(target_dir)
            new_cwd = os.path.normpath(os.path.join(session["cwd"], target_dir))
            if os.path.isdir(new_cwd):
                session["cwd"] = new_cwd
                return json.dumps({"command": command, "cwd": session["cwd"], "stdout": "", "exit_code": 0})
            else:
                return json.dumps({"command": command, "stderr": f"cd: {target_dir}: No such file or directory", "exit_code": 1})
        
        try:
            start_time = time.time()
            p = subprocess.Popen(
                command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                cwd=session["cwd"], env=session["env"]
            )
            stdout, stderr = p.communicate(timeout=30)
            duration = time.time() - start_time
            
            if len(stdout) > 4000: stdout = stdout[:4000] + "\n... (truncated)"
            if len(stderr) > 4000: stderr = stderr[:4000] + "\n... (truncated)"
            
            return json.dumps({
                "command": command,
                "stdout": stdout.strip(),
                "stderr": stderr.strip(),
                "exit_code": p.returncode,
                "cwd": session["cwd"],
                "duration": f"{duration:.2f}s"
            }, indent=2)
        except subprocess.TimeoutExpired:
            p.kill()
            return json.dumps({"error": "Command timed out after 30s", "command": command})
        except Exception as e:
            return json.dumps({"error": str(e), "command": command})
            
    elif action == "close":
        if session_id in _TERMINAL_SESSIONS:
            del _TERMINAL_SESSIONS[session_id]
            return json.dumps({"status": "closed", "session_id": session_id})
        return json.dumps({"error": f"Session {session_id} not found."})
        
    return json.dumps({"error": f"Unknown action '{action}'"})


@tool
def start_background_process(command: str, process_id: str) -> str:
    """Start a long-running command in the background (e.g. Django server)."""
    import json
    if process_id in _BACKGROUND_PROCESSES:
        return json.dumps({"error": f"Process ID {process_id} already in use."})
        
    try:
        log_file = f"/tmp/bg_{process_id}.log"
        f = open(log_file, "w")
        p = subprocess.Popen(
            command, shell=True, stdout=f, stderr=subprocess.STDOUT, text=True, start_new_session=True
        )
        _BACKGROUND_PROCESSES[process_id] = p
        return json.dumps({"status": "running", "pid": p.pid, "process_id": process_id, "log_file": log_file})
    except Exception as e:
        return json.dumps({"error": str(e), "command": command})


@tool
def process_status(process_id: str) -> str:
    """Check the status of a background process."""
    import json
    if process_id not in _BACKGROUND_PROCESSES:
        return json.dumps({"error": f"Process {process_id} not found."})
    
    p = _BACKGROUND_PROCESSES[process_id]
    ret = p.poll()
    if ret is None:
        return json.dumps({"process_id": process_id, "pid": p.pid, "status": "running"})
    else:
        return json.dumps({"process_id": process_id, "pid": p.pid, "status": "exited", "exit_code": ret})


@tool
def process_logs(process_id: str, lines: int = 50) -> str:
    """Read the latest logs from a background process."""
    import json
    log_file = f"/tmp/bg_{process_id}.log"
    if not os.path.exists(log_file):
        return json.dumps({"error": f"Log file for {process_id} not found."})
    
    try:
        out = subprocess.check_output(f"tail -n {lines} {log_file}", shell=True, text=True)
        return json.dumps({"process_id": process_id, "logs": out.strip()})
    except Exception as e:
        return json.dumps({"error": str(e)})


@tool
def process_stop(process_id: str) -> str:
    """Stop a background process."""
    import json
    if process_id not in _BACKGROUND_PROCESSES:
        return json.dumps({"error": f"Process {process_id} not found."})
        
    p = _BACKGROUND_PROCESSES[process_id]
    try:
        p.terminate()
        p.wait(timeout=5)
    except subprocess.TimeoutExpired:
        p.kill()
        
    del _BACKGROUND_PROCESSES[process_id]
    return json.dumps({"status": "stopped", "process_id": process_id})


def register_terminal_tools() -> None:
    registry = ToolRegistry()
    registry.bulk_register([
        (terminal_execute, ToolMetadata(
            name="terminal_execute",
            description="Execute Linux commands safely, capturing stdout, stderr, exit code. Supports timeouts.",
            category="terminal",
            risk_level=RiskLevel.MEDIUM,
            input_schema={"command": "string", "timeout": "int"},
        )),
        (terminal_session, ToolMetadata(
            name="terminal_session",
            description="Manage interactive shell session with persistent state (cwd, env).",
            category="terminal",
            risk_level=RiskLevel.MEDIUM,
            input_schema={"action": "create|execute|close", "session_id": "string", "command": "string (optional)"},
        )),
        (start_background_process, ToolMetadata(
            name="start_background_process",
            description="Start long-running commands in background (e.g. servers).",
            category="terminal",
            risk_level=RiskLevel.MEDIUM,
            input_schema={"command": "string", "process_id": "string"},
        )),
        (process_status, ToolMetadata(
            name="process_status",
            description="Check status of background process.",
            category="terminal",
            risk_level=RiskLevel.LOW,
            input_schema={"process_id": "string"},
        )),
        (process_logs, ToolMetadata(
            name="process_logs",
            description="Read logs of background process.",
            category="terminal",
            risk_level=RiskLevel.LOW,
            input_schema={"process_id": "string", "lines": "int (optional)"},
        )),
        (process_stop, ToolMetadata(
            name="process_stop",
            description="Stop background process.",
            category="terminal",
            risk_level=RiskLevel.MEDIUM,
            input_schema={"process_id": "string"},
        )),
    ])
