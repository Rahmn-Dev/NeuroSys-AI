"""Compact semantic case memory with deterministic, provider-neutral retrieval."""
from __future__ import annotations

import re
from typing import Iterable

from .canonical_lifecycle import classify_case

_ENTITY = re.compile(
    r"(?:/[A-Za-z0-9_.@+\-/]+)|(?:\b(?:nginx|apache2?|httpd|postgres(?:ql)?|mysql|mariadb|redis|docker|ssh(?:d)?|systemd|suricata|gunicorn|daphne)\b)|(?:\bport\s*[:=]?\s*\d{1,5}\b)|(?::\d{3,5}\b)|(?:\b(?:400|401|403|404|408|429|500|501|502|503|504)\b)",
    re.I,
)
_WORDS = re.compile(r"[a-zA-Z0-9_.@-]{3,}")
_STOP = {
    "yang", "dan", "atau", "dari", "untuk", "dengan", "pada", "ini", "itu", "saya", "aku",
    "coba", "tolong", "cek", "apakah", "kenapa", "sekarang", "masih", "the", "and", "for",
    "with", "this", "that", "what", "please", "error", "failed", "service", "system",
}


def extract_features(text: str) -> dict:
    raw = str(text or "")
    entities = set()
    for match in _ENTITY.finditer(raw):
        entity = match.group(0).lower().strip()
        number = re.search(r"\d{2,5}", entity)
        if entity.startswith("port") or entity.startswith(":"):
            entity = f"port:{number.group(0)}"
        elif number:
            entity = f"http:{number.group(0)}"
        entities.add(entity)
    entities = sorted(entities)[:24]
    keywords = []
    for word in _WORDS.findall(raw.lower()):
        if word not in _STOP and word not in keywords:
            keywords.append(word)
    case = classify_case(raw)
    return {"entities": entities, "keywords": keywords[:32], "kind": case["kind"], "signature": case["signature"]}


def similarity(features: dict, case) -> tuple[float, list[str]]:
    entities = set(features.get("entities") or [])
    old_entities = set(getattr(case, "entities", None) or extract_features(case.title)["entities"])
    keywords = set(features.get("keywords") or [])
    old_keywords = set(getattr(case, "keywords", None) or extract_features(case.title)["keywords"])
    shared_entities = sorted(entities & old_entities)
    entity_score = len(shared_entities) / max(1, len(entities | old_entities))
    keyword_score = len(keywords & old_keywords) / max(1, len(keywords | old_keywords))
    kind_score = 1.0 if features.get("kind") == getattr(case, "case_kind", "") and features.get("kind") != "general" else 0.0
    score = min(1.0, entity_score * 0.65 + keyword_score * 0.20 + kind_score * 0.15)
    return round(score, 4), shared_entities


def best_case_candidate(message: str, cases: Iterable) -> tuple[object | None, float]:
    features = extract_features(message)
    ranked = sorted(((case, similarity(features, case)[0]) for case in cases), key=lambda item: item[1], reverse=True)
    if not ranked:
        return None, 0.0
    case, score = ranked[0]
    # Exact entity overlap plus matching domain can reopen an older case.
    _, shared = similarity(features, case)
    if shared and score >= 0.52:
        return case, score
    return None, score


def refresh_relations(case_id: str) -> None:
    from chatbot.models import Investigation, InvestigationRelation
    current = Investigation.objects.get(pk=case_id)
    candidates = Investigation.objects.filter(session=current.session).exclude(pk=current.pk)
    features = {"entities": current.entities, "keywords": current.keywords, "kind": current.case_kind}
    ranked = []
    for candidate in candidates:
        score, shared = similarity(features, candidate)
        if score >= 0.18:
            ranked.append((candidate, score, shared))
    ranked.sort(key=lambda row: row[1], reverse=True)
    keep = set()
    for candidate, score, shared in ranked[:5]:
        # Only real overlap creates a link. Two unrelated investigations that
        # happen to share a diagnostic domain must not become each other's
        # context, or a new topic inherits the previous one's evidence.
        if not shared and score < 0.45:
            continue
        keep.add(candidate.pk)
        relation_type = "same_entity" if shared else "semantically_related"
        InvestigationRelation.objects.update_or_create(
            source=current, target=candidate,
            defaults={"relation_type": relation_type, "confidence": score,
                      "shared_entities": shared, "reason": ("Shared: " + ", ".join(shared))[:255] if shared else "Related diagnostic domain"},
        )
    InvestigationRelation.objects.filter(source=current).exclude(target_id__in=keep).delete()


def update_case_memory(case_id: str, goal: str, answer: str) -> None:
    from chatbot.models import Investigation
    case = Investigation.objects.filter(pk=case_id).first()
    if not case:
        return
    combined = f"{case.title}\n{goal}\n{answer}"
    features = extract_features(combined)
    findings = list(case.findings.order_by('-created_at').values_list('content', flat=True)[:4])
    digest = []
    for value in findings + ([answer] if answer else []):
        clean = " ".join(str(value).split())[:500]
        if clean and clean not in digest:
            digest.append(clean)
    case.entities = features["entities"]
    case.keywords = features["keywords"]
    case.case_kind = features["kind"] if case.case_kind == "general" else case.case_kind
    case.context_summary = " ".join(str(answer or case.context_summary).split())[:1400]
    case.evidence_digest = digest[:5]
    case.save(update_fields=['entities', 'keywords', 'case_kind', 'context_summary', 'evidence_digest', 'updated_at'])
    refresh_relations(case.pk)


class _Turn:
    """Adapter so a plain chat turn can be scored like a case."""

    def __init__(self, text: str, sender: str = "user"):
        self.sender = sender
        self.message = text
        features = extract_features(text)
        self.entities = features["entities"]
        self.keywords = features["keywords"]
        self.case_kind = features["kind"]
        self.title = text


def relevant_prior_turns(message: str, history, max_chars: int = 4000,
                         always_last: int = 2, min_score: float = 0.30,
                         per_turn_chars: int = 900):
    """Pick the prior turns worth spending context on.

    Always keeps the last exchange so a running thread is never lost, then
    adds older turns only while they share real signal with the current
    message (entity or keyword overlap). Unrelated earlier work - a finished
    nginx case while the operator asks about something else - is dropped
    instead of steering the answer.
    """
    turns = list(history or [])
    if not turns:
        return []
    keep = turns[-always_last:] if always_last > 0 else []
    seen_ids = {id(t) for t in keep}
    probe = extract_features(message or "")
    scored = []
    for turn in turns[:-always_last] if always_last > 0 else turns:
        text = getattr(turn, "message", "") or ""
        if not text.strip() or id(turn) in seen_ids:
            continue
        score, shared = similarity(probe, _Turn(text))
        if score >= min_score or shared:
            scored.append((score, turns.index(turn), turn))
    scored.sort(key=lambda row: row[0], reverse=True)
    chosen = keep + [row[2] for row in scored]
    chosen.sort(key=lambda t: turns.index(t))

    budget = max_chars
    trimmed = []
    for turn in reversed(chosen):  # newest first while trimming
        text = (getattr(turn, "message", "") or "").strip()
        if not text:
            continue
        text = text[:per_turn_chars]
        if len(text) > budget:
            text = text[:max(0, budget)]
        if not text:
            break
        budget -= len(text)
        # Return trimmed copies so the caller cannot accidentally re-inject the
        # full message and blow the budget.
        trimmed.append(_Turn(text, getattr(turn, "sender", "user")))
    trimmed.reverse()
    return trimmed


def retrieval_context(case_id: str, max_cases: int = 3, max_chars: int = 4800) -> dict:
    from chatbot.models import Investigation, InvestigationRelation
    active = Investigation.objects.filter(pk=case_id).first()
    if not active:
        return {"active_case": None, "related_cases": []}
    outgoing = list(InvestigationRelation.objects.filter(source=active).select_related('target'))
    incoming = list(InvestigationRelation.objects.filter(target=active).select_related('source'))
    related = []
    seen = set()
    ordered = sorted(outgoing + incoming, key=lambda item: item.confidence, reverse=True)
    for relation in ordered:
        if relation.confidence < 0.35 and not relation.shared_entities:
            # Weak correlation is not context; drop it instead of nudging the
            # agent back towards an unrelated earlier case.
            continue
        other = relation.target if relation.source_id == active.pk else relation.source
        if other.pk in seen:
            continue
        seen.add(other.pk)
        related.append((relation, other))
        if len(related) >= max_cases:
            break
    payload = {
        "active_case": {"id": active.id, "title": active.title, "kind": active.case_kind,
                        "entities": active.entities[:16], "summary": active.context_summary[:1400],
                        "evidence": active.evidence_digest[:4]},
        "related_cases": [{"id": other.id, "title": other.title,
                           "relation": rel.relation_type, "confidence": round(rel.confidence, 3),
                           "shared_entities": rel.shared_entities[:12],
                           "summary": other.context_summary[:900],
                           "evidence": other.evidence_digest[:2]} for rel, other in related],
        "instruction_authority": "none",
    }
    import json
    while len(json.dumps(payload, ensure_ascii=True)) > max_chars and payload["related_cases"]:
        payload["related_cases"].pop()
    return payload
