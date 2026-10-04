"""Direct conversation routing.

Everyday conversation ("hi", "thanks", "who are you") should not pay for a
tool-calling investigation: no tools, no workspace discovery, no planning,
no case in the Session Graph. This module decides, with zero provider calls,
whether a turn is plain conversation or operational work.

The rule is deliberately conservative: anything that smells like system or
code work always goes to the full agent, and only short, obviously social
messages take the direct path.
"""
import re

# System/ops vocabulary: never answered directly.
_OPS_WORDS = re.compile(
    r"\b("
    r"log|logs|logging|error|errors|exception|traceback|stack ?trace|panic|fatal|"
    r"service|services|systemd|systemctl|unit|daemon|process|processes|pid|port|ports|"
    r"docker|container|containers|compose|kubernetes|k8s|pod|pods|namespace|"
    r"nginx|apache|caddy|postgres|postgresql|mysql|mariadb|redis|memcached|mongo|"
    r"journalctl|journal|tail|head|grep|awk|sed|curl|wget|ss|netstat|lsof|ip a|ifconfig|"
    r"cpu|ram|memory|disk|storage|swap|load average|uptime|throughput|latency|"
    r"server|host|hostname|node|cluster|replica|shard|queue|broker|"
    r"firewall|ufw|iptables|network|dns|ip address|subnet|port\s?scan|"
    r"deploy|deployment|release|rollback|restart|reload|backup|restore|"
    r"config|configuration|configmap|secret|env|environment|variable|settings|"
    r"file|files|folder|directory|path|repo|repository|branch|commit|merge|diff|git|"
    r"database|db|schema|migration|query|index|table|transaction|lock|deadlock|"
    r"api|endpoint|websocket|socket|thread|race|permission|sudo|root|user|group|"
    r"install|package|dependency|module|package|version|release|upgrade|patch|"
    r"monitoring|monitor|alert|alerts|alerting|incident|outage|downtime|postmortem|"
    r"test|tests|pytest|unittest|coverage|trace|metric|metrics|logline|"
    r"cert|certificate|tls|ssl|key|token|auth|authentication|authorization|sso|"
    r"disk usage|storage|ceph|nfs|raid|mount|volume|kernel|module|driver|hardware"
    r")\b",
    re.I,
)

# Short openers and pleasantries.
_GREETING = re.compile(
    r"^\s*(hi|hey|hello|hola|yo|sup|hiya|heya|good\s?(morning|afternoon|evening|day|night)|"
    r"guten\s?tag|bonjour|salut|ciao|ola|hei|hallo|halo|helo|hi\b|pagi|siang|sore|malam|"
    r"selamat\s?(pagi|siang|sore|malam|datang)|assalamualaikum|salam|permisi|maaf|mohon|"
    r"bye|goodbye|see\s?ya|farewell|sampai\s?jumpa|dah|dadah|ok|okay|okey|oke|siap|"
    r"sip|yes|yep|yup|no|nope|sure|thanks|thank\s?you|thx|ty|makasih|terima\s?kasih|"
    r"tengkyu|nuhun|good\s?job|nice|cool|awesome|great|perfect|wow|ohh|oh|ah|hmm|"
    r"haha|hahaha|lol|wkwk|wkwkw|hehe|lmao|test|testing|tes|ping|pong|"
    r"apa\s+kabar|gimana\s+kabar|how\s+are\s+you|help|bantuan|butuh\s+bantuan|"
    r"help\s+me|sure|cool)\b(\s+[\w'-]+){0,2}[\s\W]*$",
    re.I,
)

# Identity / capability questions about the assistant itself.
_IDENTITY = re.compile(
    r"^\s*(siapa\s+(kamu|anda|lo|lu)|kamu\s+(siapa|apa|bot|manusia|man)|"
    r"who\s+are\s+you|what\s+are\s+you|who\s+r\s+you|what\s+can\s+you\s+do|"
    r"what\s+do\s+you\s+do|who\s+made\s+you|are\s+you\s+(an?\s+)?(ai|robot|bot|human)|"
    r"are\s+you\s+real|joke|tell\s+me\s+a\s+joke|lontar|pls|"
    r"siapa\s+(saya|aku|lo|lu|anda)|who\s+am\s+i|what\s+am\s+i)\??(\s+[\w'-]+){0,2}[\s\W]*$",
    re.I,
)

_MAX_LEN = 200


def is_direct_conversation(message: str) -> bool:
    """True when the turn is everyday conversation needing no tools at all."""
    text = (message or "").strip()
    if not text or len(text) > _MAX_LEN:
        return False
    if _OPS_WORDS.search(text):
        # "test the service" or "install docker" are work, not small talk.
        return False
    if _IDENTITY.match(text):
        return True
    return bool(_GREETING.match(text))


DIRECT_CHAT_SYSTEM_PROMPT = (
    "You are NeuroSysAI, an SRE assistant. This turn is everyday conversation, "
    "so answer directly and briefly without calling any tool, without inspecting "
    "the system, and without describing a plan. Keep the warm, human tone of a "
    "teammate. If the operator actually needs something checked or changed, say "
    "what you would need and let them send the real request."
)


def direct_chat_prompt(terminal_cwd: str = "", active_workspace: str = "", selected_file: str = "") -> str:
    prompt = DIRECT_CHAT_SYSTEM_PROMPT
    if terminal_cwd or active_workspace or selected_file:
        prompt += "\n\n## Current Environment\n"
        prompt += f"Terminal Directory: {terminal_cwd or 'not provided'}\n"
        prompt += f"Active Workspace: {active_workspace or terminal_cwd or 'not provided'}\n"
        prompt += f"Selected File: {selected_file or 'none'}\n"
    return prompt