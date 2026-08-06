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
    """Read the full content of a file and return it as text.
    Use this when you need to inspect configuration files, source code,
    or log snippets.  For very large files (>500 lines) consider using
    search_files instead."""
    try:
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
        os.makedirs(os.path.dirname(abs_path), exist_ok=True)
        with open(abs_path, "w", encoding="utf-8") as f:
            f.write(content)
        return f"Successfully wrote {len(content)} bytes to {abs_path}"
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
        with open(abs_path, "w", encoding="utf-8") as f:
            f.write(new_content)
        return f"Successfully edited {abs_path}"
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
            capabilities=["current directory", "working directory", "pwd", "where am i", "current location"],
            supported_intents=["SIMPLE_INFORMATION"],
            safe_fast_path=True,
        )),
        (read_file, ToolMetadata(
            name="read_file",
            description="Read the full content of a file",
            category="filesystem",
            risk_level=RiskLevel.LOW,
            input_schema={"path": "string — absolute or relative file path"},
            examples=["read_file('/etc/nginx/nginx.conf')", "read_file('docker-compose.yml')"],
            keywords=["read", "cat", "view", "content", "config", "log", "file"],
        )),
        (write_file, ToolMetadata(
            name="write_file",
            description="Write content to a file, creating directories if needed",
            category="filesystem",
            risk_level=RiskLevel.MEDIUM,
            input_schema={"path": "string", "content": "string"},
            examples=["write_file('/tmp/test.txt', 'hello world')"],
            keywords=["write", "create", "save", "file", "output"],
        )),
        (edit_file, ToolMetadata(
            name="edit_file",
            description="Replace text in a file (targeted edit without full rewrite)",
            category="filesystem",
            risk_level=RiskLevel.MEDIUM,
            input_schema={"path": "string", "old_text": "string", "new_text": "string"},
            examples=["edit_file('/etc/nginx/nginx.conf', 'worker_connections 768', 'worker_connections 1024')"],
            keywords=["edit", "modify", "replace", "change", "update", "config"],
        )),
        (search_files, ToolMetadata(
            name="search_files",
            description="Search for a text pattern in files using grep (regex supported)",
            category="filesystem",
            risk_level=RiskLevel.LOW,
            input_schema={"pattern": "string (regex)", "path": "string", "file_glob": "string (optional)"},
            examples=["search_files('ERROR', '/var/log/', '*.log')", "search_files('listen 80', '/etc/nginx/')"],
            keywords=["search", "grep", "find", "pattern", "text", "log"],
            priority=20,
        )),
        (list_directory, ToolMetadata(
            name="list_directory",
            description="List contents of a directory with types and sizes",
            category="filesystem",
            risk_level=RiskLevel.LOW,
            input_schema={"path": "string — directory path (default: '.')"},
            examples=["list_directory('/etc/nginx/')", "list_directory('.')"],
            keywords=["list", "ls", "directory", "folder", "files", "tree"],
            priority=40,
        )),
        (file_info, ToolMetadata(
            name="file_info",
            description="Get detailed metadata about a file (size, permissions, owner, timestamps)",
            category="filesystem",
            risk_level=RiskLevel.LOW,
            input_schema={"path": "string"},
            examples=["file_info('/var/log/syslog')"],
            keywords=["stat", "info", "metadata", "permissions", "owner", "size"],
        )),
    ])
