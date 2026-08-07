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

# The context variable storing the active session's context.
# Tools should read from this instead of using os.environ or os.getcwd() directly.
current_session_context: ContextVar[SessionContext] = ContextVar("session_context", default=SessionContext())
current_model_name: ContextVar[str] = ContextVar("current_model_name", default="mistral:latest")
