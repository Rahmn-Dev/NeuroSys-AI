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
    r"code|kode|script|program|aplikasi|app|endpoint|request|response|payload|"
    r"test|tests|pytest|unittest|coverage|trace|metric|metrics|logline|"
    r"cert|certificate|tls|ssl|key|token|auth|authentication|authorization|sso|"
    r"disk usage|storage|ceph|nfs|raid|mount|volume|kernel|module|driver|hardware|"
    r"web|website|frontend|backend|lambat|respons|respond|hang|macet|nyala|down|up|"
    r"nyawa|hidup|start|startup|boot|init|systemctl|unit|scheduler|cron|job|queue|"
    r"load|avg|spike|leak|memory|oom|killed|timeout|timed out|refused|denied|forbidden|"
    r"verify|validasi|cek|periksa|test|scan|audit|health|status|ringan|berat|penuh|penUH"
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

# A question about what was already said/found. The answer lives in the
# conversation, so it must not trigger tools.
_REFERENCE = re.compile(
    r"\b("
    r"itu|ini|yang\s+(tadi|kamu|anda|lu|lo|you)\s*(tulis|katakan|cari|found|said|wrote)|"
    r"jawaban(nya)?|hasil(nya)?|temuan|ringkasan|laporan(nya)?|case|kasus(nya)?|investigasi|"
    r"that|those|this|what\s+you\s+(said|wrote|found|mean)|what\s+did\s+you\s+(say|find|mean|do)|"
    r"your\s+(answer|conclusion|finding)|"
    r"the\s+(case|result|findings?|report)|previous|earlier|before"
    r")\b",
    re.I,
)

# A question can carry its question word anywhere ("itu apa ya?"), so this is
# matched against the whole message instead of only its first word.
_QUESTION = re.compile(
    r"\?|\b(why|what|how|when|which|who|"
    r"apa|mengapa|kenapa|maksud|bagai(iman)?|gimana|jelaskan|ceritakan|ringkas|"
    r"ulangi|ulang|lagi|explain|summari[sz]e|repeat|mean)\b",
    re.I,
)

# Words that really mean "carry on with the investigation", not "answer me".
_RESUME = re.compile(
    r"\b(lanjut(?:kan|in)?|lanjutkan|lanjutin|teruskan|sambung|resume|continue|go\s+on|"
    r"carry\s+on|keep\s+going|run\s+it|jalankan|eksekusi|fix|perbaiki|cek|check)\b",
    re.I,
)

# "Explain / summarize / why ...?" — asking to restate or interpret what was
# already reported. A bare question word is not enough: "what time is it?"
# still needs a lookup.
_META_VERB = re.compile(
    r"\b(jelaskan|ceritakan|ringkas|ulangi|ulang|lagi|"
    r"explain|summari[sz]e|repeat|mean|maksud|kenapa|mengapa|why)\b",
    re.I,
)

# One-off lookups that need a real tool even though they mention nothing
# operational: "jam berapa sekarang", "where am i", "hostname".
# Shell / package commands are work by definition.
_COMMANDS = re.compile(
    r"\b(apt|apt-get|aptitude|yum|dnf|apk|pacman|zypper|pip|pip3|npm|pnpm|yarn|bun|"
    r"docker|docker-compose|podman|kubectl|helm|terraform|ansible|systemctl|service|journalctl|"
    r"tail|head|grep|rg|sed|awk|cut|sort|uniq|curl|wget|chmod|chown|chgrp|mkdir|rmdir|rm|kill|"
    r"pkill|killall|htop|iotop|netstat|lsof|uname|ls|nano|vim|emacs|tar|zip|unzip|gzip|"
    r"crontab|systemd-run|nohup|screen|tmux|export|source)\b",
    re.I,
)

_NEEDS_TOOL = re.compile(
    r"\b(jam\s+(berapa|sekarang|apa)|tanggal|hari\s+ini|waktu\s+(sekarang|apa)|"
    r"tanggal\s+(sekarang|apa)|uptime|berjalan\s+berapa|aktif\s+berapa|"
    r"pwd|current\s+directory|where\s+am\s+i|where\s+is\s+my|hostname|nama\s+host|"
    r"whoami|user\s+(apa|saya|sekarang)|siapa\s+(user|pengguna|saya)|"
    r"direktori(\s+(apa|saya|sekarang|aktif))?|folder(\s+(mana|aktif))?|"
    r"file\s+(mana|di\s+mana|berada)|lokasi\s+file|di\s+mana\s+file|"
    r"ukuran|size\s+(file|folder)|how\s+(many|much)|what\s+time|what\'s\s+the\s+time|"
    r"tanggal\s+hari|day\s+is\s+it|list\s+(files|directory)|ls\b|stat\b|df\b|"
    r"brankas|lemari|vault|keystore|password|passwd|api[-_ ]?key|secret|rahasia|"
    r"(where|di\s+mana|mana)\b[^?]{0,24}\b(file|folder|directory|path|lokasi|user|"
    r"password|brankas|lemari|token|key|service|port)\b)\b",
    re.I,
)

_MAX_LEN = 200
_MAX_HISTORY_LEN = 400


def is_case_question(message: str) -> bool:
    """True when the turn only asks about the previous case/answer.

    "itu apa ya?", "jelaskan lagi", "why did you say that?" are answerable
    from the conversation itself, so they must not spin up the agent.
    "lanjut" and any command-style verb stay with the investigation.
    """
    text = (message or "").strip()
    if not text or len(text) > _MAX_HISTORY_LEN:
        return False
    if _OPS_WORDS.search(text) or _RESUME.search(text):
        return False
    # Either it points back at the previous case/answer and reads as a
    # question, or it explicitly asks to explain/restate what was reported.
    if _REFERENCE.search(text) and _QUESTION.search(text):
        return True
    return bool(_META_VERB.search(text))


def is_direct_conversation(message: str) -> bool:
    """True when the turn needs no tools at all.

    Covers everyday small talk and questions about what the assistant already
    said or found.
    """
    text = (message or "").strip()
    if not text:
        return False
    if is_case_question(text):
        return True
    if len(text) > _MAX_LEN:
        return False
    # "test the service" or "install docker" are work, not small talk.
    if _OPS_WORDS.search(text) or _NEEDS_TOOL.search(text):
        return False
    if _COMMANDS.search(text):
        return False
    if _IDENTITY.match(text):
        return True
    if _GREETING.match(text):
        return True
    # Nothing operational in it: everyday talk. Operational work in this
    # domain always names a service, a file, a command or a symptom, so the
    # absence of that vocabulary is a safe signal.
    return True


DIRECT_CHAT_SYSTEM_PROMPT = (
    "You are NeuroSysAI, an SRE assistant. This turn needs no tooling: it is "
    "everyday conversation or a question about what you already reported. "
    "Answer directly from the conversation, without calling any tool, without "
    "re-inspecting the system, and without describing a plan. Keep the warm, "
    "human tone of a teammate. Never invent findings that are not in the "
    "conversation. If the operator actually needs something checked or "
    "changed, say what you would need and let them send the real request."
)


def direct_chat_prompt(terminal_cwd: str = "", active_workspace: str = "", selected_file: str = "") -> str:
    prompt = DIRECT_CHAT_SYSTEM_PROMPT
    if terminal_cwd or active_workspace or selected_file:
        prompt += "\n\n## Current Environment\n"
        prompt += f"Terminal Directory: {terminal_cwd or 'not provided'}\n"
        prompt += f"Active Workspace: {active_workspace or terminal_cwd or 'not provided'}\n"
        prompt += f"Selected File: {selected_file or 'none'}\n"
    return prompt