"""Thread memory: topic state, rolling digest, session entities.

Three cheap structures that make a session feel continuous instead of fresh
every turn:

1. Topic state: explicit "we are talking about X", updated deterministically
   from entity/keyword overlap. No LLM call, no re-guessing.
2. Rolling digest: old turns compressed to a few lines by a cheap model call,
   run in the background every N turns. The prompt then carries
   [digest] + [last 4 turns] instead of 12 raw messages.
3. Session entities: everything named in this session (services, files, codes),
   so "nginx 502" from 30 turns ago still resolves.

All persistence lives in SessionMemory (one row per chat session).
"""
from __future__ import annotations

DIGEST_EVERY_TURNS = 8
DIGEST_MAX_LINES = 5
RECENT_TURNS_KEPT = 4

DIGEST_SYSTEM_PROMPT = (
    "Summarize a chat excerpt for thread memory. Output at most {lines} short "
    "lines, no preamble. Cover: (1) subjects discussed, (2) decisions or "
    "conclusions reached, (3) concrete facts worth remembering (service names, "
    "file paths, error codes, numbers), (4) anything explicitly left open. "
    "Drop greetings, filler and repeated pleasantries. Write in the same "
    "language the excerpt uses."
)


def merge_entities(current: list, new_items: list, limit: int = 40) -> list:
    """Union that keeps first-seen order and a hard cap."""
    seen = set(str(x) for x in (current or []))
    merged = list(current or [])
    for item in new_items or []:
        key = str(item)
        if key and key not in seen:
            seen.add(key)
            merged.append(item)
    return merged[:limit]


# Deliberately conservative: single-letter and short suffixes ("-i", "-an",
# "-in") mangle roots ("pakai" -> "paka", "bukan" -> "buk"), so only the
# unambiguous clitics are stripped.
_SUFFIXES = ("nya", "kan", "kah", "lah", "tah", "pun", "ku", "mu")
_PREFIXES = ("ber", "ter", "mem", "men", "meny", "meng", "menge", "pem", "pen", "peny",
             "peng", "penge", "per", "pel", "di", "ke", "se")


def stem_word(word: str) -> str:
    """Tiny Indonesian stemmer for topic matching only.

    "madunya" and "madu" are the same thread; the stored keywords keep their
    original form, only the comparison is stemmed.
    """
    w = (word or "").lower()
    for suffix in _SUFFIXES:
        if len(w) > len(suffix) + 2 and w.endswith(suffix):
            w = w[: -len(suffix)]
            break
    for prefix in _PREFIXES:
        if len(w) > len(prefix) + 2 and w.startswith(prefix):
            w = w[len(prefix):]
            break
    return w


# First words that continue a thread instead of starting one: anaphoric words,
# question continuers, acknowledgements and bare resume words.
_KEEP_LEADS = {
    "itu", "ini", "tadi", "tersebut", "yang", "gimana", "bagaimana", "kenapa",
    "mengapa", "apa", "jelaskan", "ceritakan", "ulangi", "ulang", "lagi",
    "terus", "lalu", "trus", "lanjut", "lanjutkan", "teruskan", "continue",
    "resume", "oke", "ok", "okay", "siap", "sip", "mengerti", "paham",
    "noted", "thanks", "makasih", "wkwk", "haha", "hehe", "oh", "iya", "ya",
}

# Function words that never count as a new subject on their own.
_STOP_NOUNS = {
    "bisa", "engga", "tidak", "buat", "cara", "pilih", "tau", "tahu",
    "tolong", "coba", "kasih", "lihat", "cek", "gimana", "bagaimana",
    "kenapa", "mengapa", "yang", "dan", "itu", "ini", "saya", "kamu",
    "dia", "kita", "kami", "apa", "sudah", "belum", "jangan", "bukan",
}


def first_word(text: str) -> str:
    import re as _re
    words = _re.findall(r"[A-Za-z']+", str(text or "").lower())
    return words[0] if words else ""


def looks_like_continuation(text: str) -> bool:
    """An elliptical follow-up needs its antecedent, so it stays in-thread."""
    lead = first_word(text)
    if lead in _KEEP_LEADS:
        return True
    # Passive-verb fragment ("dipakai ...", "dibahas ...") refers to something.
    return len(lead) > 4 and lead.startswith(("di", "ter"))


def new_subject_words(text: str, topic_keywords: list) -> list:
    """Content words with no link to the current topic: a real subject change."""
    import re as _re
    topic_stems = {stem_word(w) for w in (topic_keywords or [])}
    found = []
    for word in _re.findall(r"[A-Za-z']{5,}", str(text or "").lower()):
        stemmed = stem_word(word)
        if stemmed in _STOP_NOUNS or stemmed in topic_stems:
            continue
        if word.startswith(("di", "ter", "ber", "men", "mem", "pen", "pem")):
            continue  # verb forms refer back, they do not name a subject
        found.append(word)
    return found


def topic_label_for(text: str, entities: list, keywords: list) -> str:
    """A short human label for the current topic."""
    text = (text or "").strip()
    if entities:
        return f"{entities[0]}: {text[:60]}"
    words = [w for w in (keywords or []) if len(w) > 3][:4]
    if words:
        return " ".join(words) + (f": {text[:40]}" if len(text) > 40 else "")
    return text[:70] or "general chat"


def update_topic(state: dict, message: str, min_score: float = 0.30) -> dict:
    """Fold one turn into the topic. Returns the new state dict.

    Same subject (entity/keyword overlap) keeps and enriches the topic;
    anything else records a switch and starts a new one. Pure python,
    no provider call.
    """
    from .memory_graph import extract_features, similarity, _Turn

    state = dict(state or {})
    features = extract_features(message or "")
    current_entities = list(state.get("entities") or [])
    current_keywords = list(state.get("keywords") or [])

    if not current_entities and not current_keywords:
        return {
            "label": topic_label_for(message, features["entities"], features["keywords"]),
            "entities": features["entities"][:12],
            "keywords": features["keywords"][:16],
            "history": list(state.get("history") or []),
        }

    probe = _Turn(message or "")
    probe.entities = features["entities"]
    probe.keywords = [stem_word(w) for w in features["keywords"]]
    ref = _Turn(" ".join(current_entities + current_keywords))
    ref.entities, ref.keywords = current_entities, [stem_word(w) for w in current_keywords]
    score, shared = similarity(features, ref)
    # Stemmed overlap keeps inflected turns ("madunya" vs "madu") in one thread.
    stemmed_overlap = set(probe.keywords) & set(ref.keywords) - {"yang", "dan", "itu", "ini"}
    if stemmed_overlap and not shared:
        shared = sorted(stemmed_overlap)

    if score >= min_score or shared:
        keep = True
    elif looks_like_continuation(message):
        keep = True
    elif new_subject_words(message, current_keywords):
        keep = False
    else:
        # Short fragment with nothing new: it only makes sense in-thread.
        keep = True
    if keep:
        history = list(state.get("history") or [])
        return {
            "label": state.get("label") or topic_label_for(message, features["entities"], features["keywords"]),
            "entities": merge_entities(current_entities, features["entities"], 16),
            "keywords": merge_entities(current_keywords, features["keywords"], 24),
            "history": history,
        }

    history = list(state.get("history") or [])
    if state.get("label"):
        history.append(state.get("label"))
    return {
        "label": topic_label_for(message, features["entities"], features["keywords"]),
        "entities": features["entities"][:12],
        "keywords": features["keywords"][:16],
        "history": history[-6:],
    }


def digest_prompt(turns: list[str]) -> str:
    """Build the summarisation prompt for a slice of turns."""
    body = "\n".join(f"- {t[:600]}" for t in turns if (t or "").strip())
    return DIGEST_SYSTEM_PROMPT.format(lines=DIGEST_MAX_LINES) + "\n\n" + body


def build_thread_context(memory) -> str:
    """Render the SessionMemory row as prompt context. Empty when nothing known."""
    if memory is None:
        return ""
    parts = []
    label = (getattr(memory, "topic_label", "") or "").strip()
    if label:
        parts.append(f"Current thread: {label}")
    entities = list(getattr(memory, "session_entities", "") or [])[:20]
    if entities:
        parts.append("Session entities: " + ", ".join(str(e) for e in entities))
    digest = (getattr(memory, "digest", "") or "").strip()
    if digest:
        parts.append("Earlier in this session:\n" + digest)
    past = list(getattr(memory, "topic_history", "") or [])[-3:]
    if past:
        parts.append("Previous threads: " + " | ".join(str(p)[:80] for p in past))
    if not parts:
        return ""
    return "## Thread memory (this session)\n" + "\n".join(parts)


async def get_session_memory(session_id):
    """Fetch the SessionMemory row, creating it on first use."""
    from asgiref.sync import sync_to_async
    from chatbot.models import SessionMemory

    @sync_to_async
    def _db():
        row, _ = SessionMemory.objects.get_or_create(session_id=session_id)
        return row

    return await _db()


async def record_turn(session_id, message: str):
    """Fold one user turn into topic state and session entities."""
    from asgiref.sync import sync_to_async
    from .memory_graph import extract_features
    from chatbot.models import SessionMemory

    memory = await get_session_memory(session_id)
    features = extract_features(message or "")

    @sync_to_async
    def _db():
        row = SessionMemory.objects.filter(session_id=session_id).first()
        if row is None:
            return None
        state = {
            "label": row.topic_label,
            "entities": row.topic_entities,
            "keywords": row.topic_keywords,
            "history": row.topic_history,
        }
        updated = update_topic(state, message or "")
        row.topic_label = updated["label"]
        row.topic_entities = updated["entities"]
        row.topic_keywords = updated["keywords"]
        row.topic_history = updated["history"]
        row.session_entities = merge_entities(row.session_entities, features["entities"], 40)
        row.save(update_fields=[
            "topic_label", "topic_entities", "topic_keywords",
            "topic_history", "session_entities",
        ])
        return row

    return await _db()


async def maybe_refresh_digest(session_id, llm=None):
    """Compress turns older than the digest window. Best-effort, never fatal.

    Runs after a response is delivered; a failure only means the next turn
    retries, because digest_upto advances solely on success.
    """
    from asgiref.sync import sync_to_async
    from chatbot.models import ChatMessage, SessionMemory

    @sync_to_async
    def _pending():
        row = SessionMemory.objects.filter(session_id=session_id).first()
        if row is None:
            return None, []
        total = ChatMessage.objects.filter(session_id=session_id).count()
        if total - (row.digest_upto or 0) < DIGEST_EVERY_TURNS + RECENT_TURNS_KEPT:
            return None, []
        # Summarise everything except the recent window, which stays verbatim.
        cutoff = total - RECENT_TURNS_KEPT
        msgs = list(
            ChatMessage.objects.filter(session_id=session_id)
            .order_by("created_at")[row.digest_upto:cutoff]
        )
        return row, msgs

    row, msgs = await _pending()
    if row is None or not msgs:
        return None
    if llm is None:
        return None

    from langchain_core.messages import HumanMessage, SystemMessage

    turns = [
        f"{'assistant' if (m.sender or '').lower() == 'ai' else 'user'}: {(m.message or '')[:600]}"
        for m in msgs
    ]
    try:
        response = await llm.ainvoke([
            SystemMessage(content=digest_prompt([]).split("\n\n")[0]),
            HumanMessage(content="\n".join(turns)),
        ])
        summary = str(getattr(response, "content", "") or "").strip()
        if not summary:
            return None
    except Exception:
        return None

    @sync_to_async
    def _save():
        fresh = SessionMemory.objects.filter(session_id=session_id).first()
        if fresh is None:
            return None
        previous = (fresh.digest or "").strip()
        combined = (previous + "\n" + summary).strip() if previous else summary
        # Keep the digest bounded: newest lines win.
        lines = [line for line in combined.splitlines() if line.strip()]
        fresh.digest = "\n".join(lines[-(DIGEST_MAX_LINES * 2):])
        fresh.digest_upto = fresh.digest_upto + len(msgs)
        fresh.save(update_fields=["digest", "digest_upto"])
        return fresh

    return await _save()
