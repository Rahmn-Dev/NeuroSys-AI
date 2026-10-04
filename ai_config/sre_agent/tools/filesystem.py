"""
Filesystem tools — read, write, edit, search, list, stat.

All tools are registered in the global ToolRegistry on import.
"""

import os
import re
import subprocess
from typing import Optional

from langchain_core.tools import tool

from .registry import ToolRegistry, ToolMetadata, RiskLevel


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

def _write_file_direct(abs_path: str, content: str) -> None:
    """Write as the service user (requires write permission)."""
    with open(abs_path, "w", encoding="utf-8") as f:
        f.write(content)


def _write_file_via_sudo(abs_path: str, content: str) -> bool:
    """Write protected paths by routing through the operator's sudo secret.

    The temp file is written as the service user, then `sudo cp` moves it
    into place as root. The sudo password comes from the session's encrypted
    secret (same one terminal_execute uses), so no password ever appears in
    the command or the tool log.
    """
    try:
        from ..context import current_session_context
        from ..crypto import decrypt_rsa_oaep
        import tempfile

        ctx = current_session_context.get()
        if ctx is not None and not getattr(ctx, "encrypted_sudo_pwd", ""):
            # No secret yet: surface the lock modal and wait for the operator.
            from ..context import wait_for_sudo_secret
            entered = wait_for_sudo_secret(getattr(ctx, "session_id", ""), timeout=90)
            if entered:
                try:
                    ctx.encrypted_sudo_pwd = entered
                except Exception:
                    pass
        if not (ctx and getattr(ctx, "encrypted_sudo_pwd", "") and getattr(ctx, "rsa_private_key", None)):
            return False
        pwd = decrypt_rsa_oaep(ctx.rsa_private_key, ctx.encrypted_sudo_pwd)

        fd, tmp_path = tempfile.mkstemp()
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(content)
            os.chmod(tmp_path, 0o644)
            proc = subprocess.run(
                ["sudo", "-S", "-p", "", "cp", tmp_path, abs_path],
                input=(pwd + "\n").encode(),
                capture_output=True,
                timeout=30,
            )
            return proc.returncode == 0
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
    except Exception:
        return False


@tool
def get_current_directory() -> str:
    """Get the current working directory of the user's terminal session.
    Always prefer this dedicated tool when asked for the current directory."""
    from ..context import current_session_context
    try:
        ctx = current_session_context.get()
        if ctx and ctx.cwd:
            return ctx.cwd
    except LookupError:
        pass
    return os.getcwd()

@tool
def read_file(path: str) -> str:
    """Read a bounded regular text file anywhere on the system.
    Credential/device paths remain blocked by the execution boundary."""
    try:
        abs_path = os.path.abspath(path)
        if not os.path.isabs(path):
            abs_path = os.path.abspath(path)
        if not os.path.isfile(abs_path):
            return f"Error: '{abs_path}' is not a file or does not exist."
        size = os.path.getsize(abs_path)
        if size > 1_000_000:  # 1 MB safety cap
            return f"Error: File is too large ({size} bytes). Use search_files or read a slice."
        with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        line_count = content.count("\n")
        return f"[{abs_path}] ({line_count} lines, {size} bytes)\n{content}"
    except Exception as e:
        return f"Error reading file: {e}"


@tool
def write_file(path: str, content: str) -> str:
    """Write content to a file, creating parent directories if needed.
    Returns a success or error message."""
    try:
        abs_path = os.path.abspath(path)
        try:
            os.makedirs(os.path.dirname(abs_path), exist_ok=True)
        except PermissionError:
            pass
        try:
            _write_file_direct(abs_path, content)
        except PermissionError:
            if not _write_file_via_sudo(abs_path, content):
                return (
                    f"Error writing file: permission denied and sudo fallback is "
                    f"unavailable. Run the write via terminal_execute with 'sudo tee'/'sudo cp', "
                    f"or set the sudo password via the lock button."
                )
        from ..verification import verify_file_readback, require_verification
        require_verification(verify_file_readback(abs_path, expected_content=content))
        return f"Successfully wrote and verified {len(content.encode('utf-8'))} bytes to {abs_path}"
    except Exception as e:
        return f"Error writing file: {e}"


@tool
def edit_file(path: str, old_text: str, new_text: str) -> str:
    """Replace the first occurrence of `old_text` with `new_text` in a file.
    Useful for targeted configuration changes without rewriting the whole file."""
    try:
        abs_path = os.path.abspath(path)
        with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        if old_text not in content:
            return f"Error: Could not find the target text in {abs_path}"
        new_content = content.replace(old_text, new_text, 1)
        try:
            _write_file_direct(abs_path, new_content)
        except PermissionError:
            if not _write_file_via_sudo(abs_path, new_content):
                return (
                    f"Error editing file: permission denied and sudo fallback is "
                    f"unavailable. Run the change via terminal_execute with 'sudo tee', "
                    f"or set the sudo password via the lock button."
                )
        from ..verification import verify_file_readback, require_verification
        require_verification(verify_file_readback(abs_path, expected_content=new_content))
        return f"Successfully edited and verified {abs_path}"
    except Exception as e:
        return f"Error editing file: {e}"


@tool
def search_files(pattern: str, path: str = ".", file_glob: str = "") -> str:
    """Search for a text pattern in files using grep.
    `pattern` is a regex pattern, `path` is the directory to search,
    `file_glob` optionally filters files (e.g. '*.py', '*.conf').
    Returns matching lines with filenames and line numbers."""
    try:
        cmd = ["grep", "-rnI", "--color=never"]
        cmd += ["--exclude=.env", "--exclude=*.pem", "--exclude=*.key",
                "--exclude-dir=.ssh", "--exclude-dir=.aws", "--exclude-dir=.gnupg"]
        if file_glob:
            cmd += ["--include", file_glob]
        cmd += [pattern, os.path.abspath(path)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        output = result.stdout.strip()
        if not output:
            return f"No matches found for pattern '{pattern}' in {path}"
        lines = output.split("\n")
        if len(lines) > 50:
            return "\n".join(lines[:50]) + f"\n... ({len(lines)} total matches, showing first 50)"
        return output
    except subprocess.TimeoutExpired:
        return "Error: Search timed out after 30 seconds."
    except Exception as e:
        return f"Error searching files: {e}"


@tool
def list_directory(path: str = ".") -> str:
    """List the contents of a directory with file types and sizes.
    Returns a formatted listing similar to 'ls -lah'."""
    try:
        abs_path = os.path.abspath(path)
        if not os.path.isdir(abs_path):
            return f"Error: '{abs_path}' is not a directory."

        entries = []
        for name in sorted(os.listdir(abs_path)):
            full = os.path.join(abs_path, name)
            try:
                stat = os.stat(full)
                if os.path.isdir(full):
                    entries.append(f"  📁 {name}/")
                else:
                    size_kb = stat.st_size / 1024
                    if size_kb > 1024:
                        size_str = f"{size_kb / 1024:.1f} MB"
                    else:
                        size_str = f"{size_kb:.1f} KB"
                    entries.append(f"  📄 {name}  ({size_str})")
            except OSError:
                entries.append(f"  ❓ {name}  (access denied)")

        header = f"Directory: {abs_path}  ({len(entries)} items)"
        return header + "\n" + "\n".join(entries)
    except Exception as e:
        return f"Error listing directory: {e}"


@tool
def file_info(path: str) -> str:
    """Get detailed information about a file or directory —
    size, permissions, owner, modification time."""
    try:
        abs_path = os.path.abspath(path)
        if not os.path.exists(abs_path):
            return f"Error: '{abs_path}' does not exist."
        result = subprocess.run(
            ["stat", abs_path], capture_output=True, text=True, timeout=10
        )
        return result.stdout.strip() or result.stderr.strip()
    except Exception as e:
        return f"Error getting file info: {e}"


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def register_filesystem_tools() -> None:
    """Register all filesystem tools in the global ToolRegistry."""
    registry = ToolRegistry()
    registry.bulk_register([
        (get_current_directory, ToolMetadata(
            name="get_current_directory",
            description="Get the current working directory of the user's terminal session",
            category="filesystem",
            risk_level=RiskLevel.LOW,
            input_schema={},
            examples=["get_current_directory()"],
            keywords=["pwd", "cwd", "directory", "current", "where"],
            priority=100,
            capabilities=["environment_discovery", "filesystem_operation"],
            supported_intents=["SIMPLE_INFORMATION"],
            safe_fast_path=True,
        )),
        (read_file, ToolMetadata(
            name="read_file",
            description="Read a bounded regular text file from the project or operating system; secret/device paths are denied",
            category="filesystem",
            risk_level=RiskLevel.LOW,
            input_schema={"path": "string — absolute or relative file path"},
            examples=["read_file('/etc/nginx/nginx.conf')", "read_file('/var/log/nginx/error.log')", "read_file('src/settings.py')"],
            capabilities=["workspace_operation", "filesystem_operation", "system_inspection"],
        )),
        (write_file, ToolMetadata(
            name="write_file",
            description="Write content to a file, creating directories if needed",
            category="filesystem",
            risk_level=RiskLevel.MEDIUM,
            input_schema={"path": "string", "content": "string"},
            examples=["write_file('/tmp/test.txt', 'hello world')"],
            capabilities=["workspace_operation", "filesystem_operation"],
        )),
        (edit_file, ToolMetadata(
            name="edit_file",
            description="Replace text in a file (targeted edit without full rewrite)",
            category="filesystem",
            risk_level=RiskLevel.MEDIUM,
            input_schema={"path": "string", "old_text": "string", "new_text": "string"},
            examples=["edit_file('/etc/nginx/nginx.conf', 'worker_connections 768', 'worker_connections 1024')"],
            capabilities=["workspace_operation", "filesystem_operation"],
        )),
    ])
