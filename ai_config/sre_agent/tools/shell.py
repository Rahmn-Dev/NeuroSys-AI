"""
General shell execution tools — for commands that don't fit
a specific category.  HIGH risk — used as last resort.

All tools registered in the global ToolRegistry on import.
"""

from .registry import ToolRegistry

# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def register_shell_tools() -> None:
    """Register shell tools in the global ToolRegistry."""
    # The redundant tools (execute_command, safe_execute) have been removed.
    # We now strictly rely on terminal_execute from terminal.py to avoid clutter.
    pass
