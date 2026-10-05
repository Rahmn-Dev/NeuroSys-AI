"""Thread memory: topic state, rolling digest window, session entities."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "ai_config"))

from sre_agent.thread_memory import (  # noqa: E402
    build_thread_context,
    digest_prompt,
    merge_entities,
    topic_label_for,
    update_topic,
)


def test_first_turn_starts_the_topic():
    state = update_topic({}, "cek error nginx 502 di /etc/nginx")
    assert "nginx" in state["entities"] or "502" in str(state["entities"] + [state["label"]])
    assert state["history"] == []


def test_same_subject_keeps_and_enriches_the_topic():
    state = update_topic({}, "cek error nginx 502")
    same = update_topic(state, "nginx-nya timeout juga di upstream")
    assert same["label"] == state["label"]
    assert same["history"] == []


def test_new_subject_records_a_switch_and_starts_fresh():
    state = update_topic({}, "cek error nginx 502")
    switched = update_topic(state, "sepatu roda")
    assert switched["label"] != state["label"]
    assert state["label"] in switched["history"]
    assert not any("nginx" in str(e) for e in switched["entities"])


def test_honey_thread_survives_while_it_is_named():
    state = update_topic({}, "berarti madunya awet ya")
    state = update_topic(state, "dipakai buat luka bisa engga")
    assert "madu" in " ".join(state["entities"] + [state["label"]]).lower()
    back = update_topic(state, "tadi soal madu untuk luka bagaimana")
    assert "madu" in " ".join(back["entities"] + [back["label"]]).lower()


def test_merge_entities_keeps_order_and_cap():
    assert merge_entities(["a", "b"], ["b", "c", "d"], limit=4) == ["a", "b", "c", "d"]
    assert len(merge_entities([], [f"e{i}" for i in range(100)], limit=40)) == 40


def test_digest_prompt_is_bounded():
    prompt = digest_prompt(["hello " * 500, "short"])
    assert len(prompt) < 2000
    assert "short" in prompt


def test_thread_context_renders_nothing_when_empty():
    class _Empty:
        topic_label = ""
        session_entities = []
        digest = ""
        topic_history = []

    assert build_thread_context(None) == ""
    assert build_thread_context(_Empty()) == ""


def test_thread_context_renders_topic_entities_and_digest():
    class _Full:
        topic_label = "nginx 502"
        session_entities = ["nginx", "http:502", "/etc/nginx"]
        digest = "Kemarin: madu, lalu nginx 502."
        topic_history = ["madu hutan"]

    ctx = build_thread_context(_Full())
    assert "Current thread: nginx 502" in ctx
    assert "nginx" in ctx
    assert "Kemarin: madu" in ctx
    assert "madu hutan" in ctx


def test_topic_label_prefers_entities():
    assert topic_label_for("cek error nginx 502", ["nginx"], ["error"]) == "nginx: cek error nginx 502"


# --- topic continuity rules --------------------------------------------------

import pytest  # noqa: E402

from sre_agent.thread_memory import (  # noqa: E402
    looks_like_continuation,
    new_subject_words,
    stem_word,
)


def _thread(*messages):
    state = {}
    for message in messages:
        state = update_topic(state, message)
    return state


@pytest.mark.parametrize("message", [
    "dipakai buat luka bisa engga",
    "dibahas kemarin kan",
    "itu kenapa ya",
    "jelaskan lagi dong",
    "lanjut",
    "oke",
])
def test_elliptical_follow_ups_stay_in_thread(message):
    assert looks_like_continuation(message) is True
    thread = _thread("berarti madunya awet ya", message)
    assert thread["history"] == [] or "madu" in " ".join(
        thread["entities"] + [thread["label"]] + thread["history"]
    ).lower() or message in ("lanjut", "oke")


@pytest.mark.parametrize("message", [
    "sepatu roda",
    "kasih tau cara pilih sepatu roda",
    "beli laptop baru",
])
def test_new_subjects_start_a_fresh_thread(message):
    thread = _thread("cek error nginx 502", message)
    assert "nginx" in thread["history"][0]
    assert "nginx" not in " ".join(thread["entities"] + [thread["label"]]).lower()


def test_stemmer_maps_inflections_to_the_same_root():
    assert stem_word("madunya") == stem_word("madu") == "madu"
    assert stem_word("dipakai") == stem_word("pakai") == "pakai"
    assert stem_word("dimana") == "mana"
    # ...without mangling short roots.
    assert stem_word("bukan") == "bukan"
    assert stem_word("jangan") == "jangan"


def test_new_subject_words_ignores_verbs_and_function_words():
    assert new_subject_words("dipakai buat luka bisa engga", ["madu"]) == []
    assert "sepatu" in new_subject_words("kasih tau cara pilih sepatu roda", ["nginx"])


# --- recap intent + activity record ------------------------------------------

import pytest  # noqa: E402

from sre_agent.thread_memory import build_activity_context, is_recap_request  # noqa: E402


@pytest.mark.parametrize("message", [
    "aku mau tanya jadi yg sudah kamu kerjakan dari tadi apa saja dongg pengen tahu",
    "coba ingatan kamu apa ajaa yang sudah saya lakukan sebelum sebelumnyaa",
    "apa saja yang sudah dibahas",
    "what have you done so far in this chat",
    "ringkas pekerjaan tadi",
])
def test_recap_questions_are_recognised(message):
    assert is_recap_request(message) is True


@pytest.mark.parametrize("message", [
    "cek disk sekarang",
    "halo",
    "bandingkan config nginx lama dan baru",
    "tolong cek error nginx sekarang juga",
    "jam berapa sekarang",
    "sepatu roda",
])
def test_ordinary_turns_are_not_recaps(message):
    assert is_recap_request(message) is False


@pytest.fixture
def activity_tables():
    from django.db import connection
    from chatbot.models import ChatSession, Investigation, ToolExecutionLog, WorkspaceInfo
    with connection.schema_editor() as editor:
        for model in (WorkspaceInfo, ChatSession, Investigation, ToolExecutionLog):
            try:
                editor.create_model(model)
            except Exception:
                pass
    yield


def test_activity_context_lists_cases_and_tool_usage(activity_tables):
    import asyncio
    import uuid as _uuid

    from chatbot.models import ChatSession, Investigation, ToolExecutionLog

    session = ChatSession.objects.create()
    Investigation.objects.create(
        id="inv_" + _uuid.uuid4().hex[:8], session_id=session.id,
        title="cek nginx apakah hidup", status="completed",
    )
    Investigation.objects.create(
        id="inv_" + _uuid.uuid4().hex[:8], session_id=session.id,
        title="disk root tersisa 17 gb", status="completed",
    )
    ToolExecutionLog.objects.create(
        conversation=session, tool_name="terminal_execute", status="success")
    ToolExecutionLog.objects.create(
        conversation=session, tool_name="terminal_execute", status="success")
    ToolExecutionLog.objects.create(
        conversation=session, tool_name="read_file", status="success")

    from sre_agent.thread_memory import _activity_rows, render_activity
    cases, logs = _activity_rows(str(session.id))
    text = render_activity(cases, logs)
    assert "cek nginx apakah hidup" in text
    assert "disk root tersisa" in text
    assert "completed" in text
    assert "terminal_execute x2" in text
    assert "read_file x1" in text


def test_activity_context_is_empty_for_a_fresh_chat(activity_tables):
    import asyncio

    from chatbot.models import ChatSession

    session = ChatSession.objects.create()
    assert asyncio.run(build_activity_context(str(session.id))) == ""
