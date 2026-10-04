"""
Shared Session Context for NeuroSys-AI SRE Agent.
Provides thread-safe and async-safe global context for tools and execution layers.
"""

from dataclasses import dataclass
from contextvars import ContextVar

@dataclass
class SessionContext:
    cwd: str = ""
    user: str = ""
    hostname: str = ""
    environment: str = ""
    encrypted_sudo_pwd: str = ""
    rsa_private_key: any = None
    session_id: str = ""
    workspace_path: str = ""

# The context variable storing the active session's context.
# Tools should read from this instead of using os.environ or os.getcwd() directly.
current_session_context: ContextVar[SessionContext] = ContextVar("session_context", default=SessionContext())
current_model_name: ContextVar[str] = ContextVar("current_model_name", default="mistral:latest")


import asyncio as _asyncio
import threading as _threading


_SUDO_PROMPTER_LOOP = None
_SUDO_PROMPTER_SEND = None
_SUDO_WAIT = _threading.Event()
_SUDO_SECRET = ""


def register_sudo_prompter(loop, sender):
    """Install the WS callback used to ask the UI for the sudo secret."""
    global _SUDO_PROMPTER_LOOP, _SUDO_PROMPTER_SEND
    _SUDO_PROMPTER_LOOP = loop
    _SUDO_PROMPTER_SEND = sender


async def _ask_operator_for_sudo(session_id: str):
    """Default UI prompt: open the lock modal and tell the agent it is waiting."""
    return {"type": "sudo_password_required",
            "content": "This action needs a sudo password. Set it with the lock button; the agent will resume automatically once validated."}


def notify_sudo_secret_ready(encrypted_pwd: str):
    global _SUDO_SECRET
    _SUDO_SECRET = encrypted_pwd or ""
    _SUDO_WAIT.set()


def fail_sudo_secret():
    global _SUDO_SECRET
    _SUDO_SECRET = ""
    _SUDO_WAIT.set()


from typing import Optional as _Opt

def wait_for_sudo_secret(session_id: str, timeout: int = 90) -> _Opt[str]:
    """Block the calling (sync) tool thread until the operator provides a sudo
    secret through the lock modal, or the timeout elapses."""
    global _SUDO_SECRET
    if _SUDO_PROMPTER_SEND is not None and _SUDO_PROMPTER_LOOP is not None:
        try:
            _SUDO_PROMPTER_LOOP.call_soon_threadsafe(
                _asyncio.ensure_future, _SUDO_PROMPTER_SEND(session_id))
        except Exception:
            pass
    # A secret that already arrived (and was not consumed yet) wins: do not
    # clear the latch and sleep again.
    if _SUDO_SECRET:
        return _SUDO_SECRET
    _SUDO_SECRET = ""
    _SUDO_WAIT.clear()
    if _SUDO_WAIT.wait(timeout):
        return _SUDO_SECRET or None
    return None
