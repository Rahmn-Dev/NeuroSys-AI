"""Turn routing: everyday conversation vs. operational work.

The decision is made by the model itself, because it is the only thing that
understands intent. A single small call returns a strict verdict; anything
uncertain falls through to the full agent pipeline, so a wrong guess costs
one direct answer, never a skipped investigation.

Deterministic rules remain only where correctness is not negotiable:
one-off lookups that must read real system state, and a hard refusal to
route a secrets/destructive request into a no-tool answer.
"""
import re

from .canonical_lifecycle import classify_case

# Kinds that genuinely need a tool even when phrased casually.
_LOOKUP_KINDS = {"time_lookup", "date_lookup", "host_lookup", "file_lookup"}

# Safety override, not a routing heuristic: these must never be answered from
# conversation memory without the guarded pipeline and its approval checks.
_NEVER_DIRECT = re.compile(
    r"\b(password|passwd|secret|token|api[\s_-]?key|private[\s_-]?key|credential|"
    r"sudoers|\.env\b|id_rsa|shadow\b|htpasswd|"
    r"drop\s+(table|database)|truncate\s+table|rm\s+-[rf]{2}|mkfs|dd\s+if=|"
    r"shutdown|reboot|kill\s+-9\s+1|chmod\s+777\s+/|>\s*/dev/sd)\b",
    re.I,
)

ROUTER_SYSTEM_PROMPT = (
    "You are the request router for NeuroSysAI, an SRE assistant. Decide how the "
    "operator's message must be handled. Reply with one line of JSON only, no "
    "markdown.\n\n"
    '{"route": "direct", "reason": "<= 15 words"}   when the message is ordinary '
    "conversation that needs no access to the system, for example: greetings, "
    "thanks, feelings, jokes, small talk, general knowledge, questions about the "
    "assistant itself, or a question about something already said in this "
    "conversation. A direct answer is written from the conversation alone.\n"
    '{"route": "agent", "reason": "<= 15 words"}   whenever answering requires '
    "inspecting or changing the machine: services, processes, logs, files, "
    "directories, code, configuration, git, containers, metrics, network, "
    "security, package or database state. Also route to the agent when the "
    "operator asks to continue, retry, verify or resume previous work, when "
    "they ask where something is or what the current time, host, directory or "
    "user is, or when you are unsure.\n\n"
    "When a message mixes both (small talk plus a real task), choose agent. "
    "Never choose direct for anything that reads or mutates state."
)


def is_lookup_turn(message: str) -> bool:
    """Deterministic one-step lookups must read real state, not be answered."""
    try:
        return classify_case(message or "").get("kind") in _LOOKUP_KINDS
    except Exception:
        return False


def is_secret_or_destructive(message: str) -> bool:
    """Hard override: never answer these from conversation memory."""
    return bool(_NEVER_DIRECT.search(message or ""))


def parse_route(raw: str) -> tuple[str, str]:
    """Read the router's verdict. Anything unexpected means 'agent'."""
    text = str(raw or "").strip()
    if not text:
        return "agent", "empty router response"
    match = re.search(r"\{.*\}", text, re.S)
    if match:
        try:
            import json
            payload = json.loads(match.group(0))
            route = str(payload.get("route", "")).strip().lower()
            reason = str(payload.get("reason", "")).strip()[:120]
            if route in ("direct", "agent"):
                return route, reason
        except Exception:
            pass
    lowered = text.lower()
    if "direct" in lowered:
        return "direct", "router keyword"
    return "agent", "unparsable router response"


async def route_turn(llm, message: str) -> tuple[str, str]:
    """Ask the model itself. Returns (route, reason)."""
    from langchain_core.messages import HumanMessage, SystemMessage

    messages = [
        SystemMessage(content=ROUTER_SYSTEM_PROMPT),
        HumanMessage(content=str(message or "")[:4000]),
    ]
    try:
        response = await llm.ainvoke(messages)
        return parse_route(getattr(response, "content", response))
    except Exception as exc:  # a router failure must never block the operator
        return "agent", f"router unavailable: {exc}"[:120]


DIRECT_CHAT_SYSTEM_PROMPT = (
    "You are NeuroSysAI, an SRE assistant. This turn needs no tooling: it is "
    "everyday conversation or a question about what you already reported. "
    "Answer directly from the conversation, without calling any tool, without "
    "inspecting the system, and without describing a plan. Keep the warm, "
    "human tone of a teammate. Never invent findings that are not in the "
    "conversation. Answer only the latest message: if the operator switched "
    "topic, follow the new topic and never resume earlier work unless they "
    "ask for it. If the operator actually needs something checked or changed, "
    "say what you would need and let them send the real request."
)


def direct_chat_prompt(terminal_cwd: str = "", active_workspace: str = "", selected_file: str = "") -> str:
    prompt = DIRECT_CHAT_SYSTEM_PROMPT
    if terminal_cwd or active_workspace or selected_file:
        prompt += "\n\n## Current Environment\n"
        prompt += f"Terminal Directory: {terminal_cwd or 'not provided'}\n"
        prompt += f"Active Workspace: {active_workspace or terminal_cwd or 'not provided'}\n"
        prompt += f"Selected File: {selected_file or 'none'}\n"
    return prompt