"""Turn routing: the model decides, deterministic rules only where required."""

import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "ai_config"))

from sre_agent.direct_chat import (  # noqa: E402
    direct_chat_prompt,
    is_lookup_turn,
    is_secret_or_destructive,
    parse_route,
    route_turn,
)


def test_router_verdict_is_read_from_json():
    assert parse_route('{"route": "direct", "reason": "greeting"}')[:2] == ("direct", "greeting")
    assert parse_route('{"route":"agent","reason":"needs log read"}')[0] == "agent"


def test_router_verdict_carries_the_thread_fields():
    route, reason, topic, switched = parse_route(
        '{"route": "direct", "reason": "follow-up", "topic": "madu untuk luka", "topic_switched": false}'
    )
    assert (route, topic, switched) == ("direct", "madu untuk luka", False)
    route, _, topic, switched = parse_route(
        '{"route": "agent", "reason": "new task", "topic": "cek disk", "topic_switched": true}'
    )
    assert (route, topic, switched) == ("agent", "cek disk", True)


@pytest.mark.parametrize("raw", ["", "   ", "garbage", "direct", '{"route":"weird"}', "{}"])
def test_unusable_router_output_falls_back_to_the_agent(raw):
    route, reason, topic, switched = parse_route(raw)
    assert route == "agent"
    assert reason
    assert topic == "" and switched is False


@pytest.mark.parametrize("message", [
    "jam berapa sekarang",
    "what time is it",
    "where am i",
    "hostname apa",
])
def test_one_off_lookups_are_never_answered_from_memory(message):
    assert is_lookup_turn(message) is True


# Phrasings the deterministic guard cannot classify ("file mana ya") are left
# to the model router on purpose: the router prompt tells it that questions
# about files, location and current state belong to the agent.
@pytest.mark.parametrize("message", [
    "halo paul",
    "terima kasih",
    "bisakah kamu menghibur saya",
    "fix error di nginx",
    "neu di jerman sekarang musim apa",
])
def test_ordinary_turns_are_left_for_the_model_to_route(message):
    assert is_lookup_turn(message) is False


@pytest.mark.parametrize("message", [
    "print the root password",
    "tampilkan api key di .env",
    "drop table users",
    "shutdown the server now",
])
def test_secrets_and_destructive_requests_never_take_the_direct_path(message):
    assert is_secret_or_destructive(message) is True


@pytest.mark.parametrize("message", ["halo", "terima kasih", "fix error di nginx"])
def test_normal_turns_are_not_secret_requests(message):
    assert is_secret_or_destructive(message) is False


def test_router_uses_the_model_verdict():
    class _Chunk:
        content = '{"route": "direct", "reason": "small talk", "topic": "sapa", "topic_switched": false}'

    class _LLM:
        def __init__(self):
            self.calls = 0
            self.seen = []

        async def ainvoke(self, messages):
            self.calls += 1
            self.seen = [getattr(m, "content", "") for m in messages]
            return _Chunk()

    llm = _LLM()
    route, reason, topic, switched = asyncio.run(route_turn(llm, "halo", thread=""))
    assert (route, reason, topic, switched) == ("direct", "small talk", "sapa", False)
    assert llm.calls == 1


def test_router_sends_the_current_thread_for_comparison():
    class _Chunk:
        content = '{"route": "agent", "reason": "new", "topic": "disk", "topic_switched": true}'

    class _LLM:
        async def ainvoke(self, messages):
            self.human = [m for m in messages if m.__class__.__name__ == "HumanMessage"][0]
            return _Chunk()

    llm = _LLM()
    route, _, topic, switched = asyncio.run(route_turn(llm, "cek disk", thread="nginx 502"))
    assert (route, topic, switched) == ("agent", "disk", True)
    assert "CURRENT THREAD: nginx 502" in llm.human.content


def test_router_failure_routes_to_the_agent():
    class _LLM:
        async def ainvoke(self, messages):
            raise RuntimeError("provider down")

    route, reason, _, _ = asyncio.run(route_turn(_LLM(), "halo"))
    assert route == "agent"
    assert "unavailable" in reason


def test_prompt_carries_environment_only_when_present():
    bare = direct_chat_prompt()
    assert "Terminal Directory" not in bare
    with_env = direct_chat_prompt("/srv/app", "/srv/app", "/srv/app/main.py")
    assert "/srv/app/main.py" in with_env

# --- selective conversation memory -----------------------------------------

from sre_agent.memory_graph import relevant_prior_turns  # noqa: E402


class _Turn:
    def __init__(self, sender, message):
        self.sender = sender
        self.message = message


def _ops_history():
    return [
        _Turn("user", "tolong cek error nginx 502 di /etc/nginx"),
        _Turn("ai", "Upstream timeout, saya perbaiki config nginx"),
        _Turn("user", "sekarang lanjut ke backend python"),
        _Turn("ai", "Backend python sudah di-restart"),
        _Turn("user", "sepatu roda"),
    ]


def test_unrelated_topic_does_not_inherit_the_previous_case():
    kept = relevant_prior_turns("sepatu roda", _ops_history())
    texts = [t.message for t in kept]
    assert not any("nginx" in t for t in texts)
    assert not any("Upstream" in t for t in texts)


def test_related_topic_keeps_the_relevant_case_turns():
    kept = relevant_prior_turns("nginx 502 lagi muncul", _ops_history())
    texts = " ".join(t.message for t in kept)
    assert "nginx" in texts


def test_running_thread_is_kept_when_it_is_named():
    """Naming the subject keeps the thread, even mid-conversation."""
    honey = [
        _Turn("user", "berarti madunya awet ya"),
        _Turn("ai", "Madu bertahan bertahun-tahun jika disimpan kering"),
        _Turn("user", "dipakai buat luka"),
        _Turn("ai", "Madu punya sifat antibakteri untuk luka ringan"),
        _Turn("user", "sekarang balik ke topicserius"),
    ]
    kept = relevant_prior_turns("tadi soal madu untuk luka bagaimana", honey)
    texts = " ".join(t.message for t in kept)
    assert "Madu" in texts


def test_topic_switch_drops_the_old_thread():
    honey = [
        _Turn("user", "berarti madunya awet ya"),
        _Turn("ai", "Madu bertahan bertahun-tahun jika disimpan kering"),
        _Turn("user", "dipakai buat luka"),
        _Turn("ai", "Madu punya sifat antibakteri untuk luka ringan"),
        _Turn("user", "sepatu roda"),
    ]
    # Only the last exchange is always kept (so a thread is never lost); older
    # turns from the previous subject must not come along.
    kept = relevant_prior_turns("sepatu roda", honey)
    texts = " ".join(t.message for t in kept)
    assert "Madu bertahan bertahun-tahun" not in texts
    assert "dipakai buat luka" not in texts


def test_memory_window_is_budgeted():
    long_history = [_Turn("user", "x" * 5000) for _ in range(10)]
    long_history.append(_Turn("user", "halo"))
    kept = relevant_prior_turns("halo", long_history, max_chars=1000)
    assert sum(len(t.message) for t in kept) <= 1000


# --- SRE domain clamp ------------------------------------------------------

from sre_agent.direct_chat import SRE_DOMAIN_CLAMP, DIRECT_CHAT_SYSTEM_PROMPT  # noqa: E402


def test_domain_clamp_is_part_of_the_direct_chat_prompt():
    prompt = direct_chat_prompt()
    assert SRE_DOMAIN_CLAMP in prompt
    assert "SRE assistant" in prompt


def test_domain_clamp_redirects_without_cutting_the_helpfulness():
    assert "off-topic" in SRE_DOMAIN_CLAMP
    assert "answer properly and in real detail" in SRE_DOMAIN_CLAMP
    assert "do not refuse simply because the subject is off-topic" in SRE_DOMAIN_CLAMP
    assert "medical" in SRE_DOMAIN_CLAMP
    # It must not turn the assistant curt.
    assert "one or two sentences" not in SRE_DOMAIN_CLAMP
    assert "single short sentence" not in SRE_DOMAIN_CLAMP


def test_direct_chat_prompt_still_forbids_tools_and_invention():
    assert "without calling any tool" in DIRECT_CHAT_SYSTEM_PROMPT
    assert "Never invent findings" in DIRECT_CHAT_SYSTEM_PROMPT


# --- resume scoping ---------------------------------------------------------

from sre_agent.canonical_lifecycle import is_generic_continuation  # noqa: E402


@pytest.mark.parametrize("message", ["continue", "lanjut", "lanjutkan", "resume"])
def test_bare_continuation_words_are_recognised(message):
    assert is_generic_continuation(message) is True


def test_resume_ttl_setting_has_a_default():
    from django.conf import settings
    assert getattr(settings, "SRE_RESUME_TTL_MINUTES", 180) == 180


# --- regression: locally imported helpers must be imported where they are used -

import inspect  # noqa: E402

from sre_agent.engine import SREAgentEngine  # noqa: E402
from sre_agent.events import AgentEventType, evt_completed, evt_message_saved  # noqa: E402


def test_run_direct_chat_imports_every_helper_it_calls():
    """A function-local import does not leak: a missing one is a NameError at
    runtime, which surfaced as an opaque provider_error."""
    source = inspect.getsource(SREAgentEngine._run_direct_chat)
    for helper in ("direct_chat_prompt", "relevant_prior_turns"):
        assert f"import {helper}" in source, f"{helper} is used but never imported"
    assert source.index("yield evt_direct_chat") < source.index("yield evt_thinking") < source.index("llm.astream")
    assert "evt_planning(" not in source
    assert "evt_discovering(" not in source
    assert "evt_task_plan(" not in source


def test_conversation_branch_imports_its_domain_clamp():
    source = inspect.getsource(SREAgentEngine._run_internal)
    assert "import SRE_DOMAIN_CLAMP" in source
    # the router call lives in a tuple import, so match the module import
    assert "from .direct_chat import" in source
    assert "route_turn(" in source
    assert "len(simple) <= 20" not in source


def test_router_prompt_keeps_short_operational_requests_on_the_agent_path():
    from sre_agent.direct_chat import ROUTER_SYSTEM_PROMPT

    assert "'cek nginx dong'" in ROUTER_SYSTEM_PROMPT
    assert "short length do not change this rule" in ROUTER_SYSTEM_PROMPT
    assert "pseudo tool calls" in direct_chat_prompt()


def test_saved_message_notifications_follow_the_typed_agent_event_contract():
    event = evt_message_saved("user", "message-123")
    assert event.type is AgentEventType.MESSAGE_SAVED
    assert event.to_dict()["type"] == "message_saved"
    assert event.to_dict()["sender"] == "user"
    assert event.to_dict()["msg_id"] == "message-123"

    source = inspect.getsource(SREAgentEngine)
    assert 'yield {"type": "message_saved"' not in source


def test_verified_graph_report_survives_noncritical_finalization_exception():
    source = inspect.getsource(SREAgentEngine._run_internal)
    verified_branch = source.index("if run_completed and final_message:")
    failure_branch = source.index("else:", verified_branch)
    verified_handling = source[verified_branch:failure_branch]
    assert "terminal_failure = True" not in verified_handling
    assert 'final_message = ""' not in verified_handling
    assert "yield evt_error" not in verified_handling


@pytest.mark.asyncio
async def test_runner_wrapper_accepts_the_saved_message_event_before_completion():
    engine = SREAgentEngine(session_id="99999999-0000-4000-8000-000000000001")

    async def fake_internal(*args, **kwargs):
        yield evt_message_saved("user", "message-123")
        yield evt_completed("Hello!")

    engine._run_internal = fake_internal
    async def noop(*args, **kwargs):
        return None
    engine._update_last_message_metadata = noop
    engine._log_event = noop
    engine._persist_run_history = noop
    events = [event async for event in engine.run("hello")]

    assert [event.type.value for event in events] == ["message_saved", "completed"]


# --- evidence coverage checklists -------------------------------------------

from sre_agent.coverage import (  # noqa: E402
    checklist_for,
    coverage_from_commands,
    domain_for,
    next_objective,
    render_coverage_report,
)


def test_domains_are_detected_from_the_goal():
    assert domain_for("check network apakah ada anomali engga") == "network_anomaly"
    assert domain_for("cek ada brute force ssh tidak") == "bruteforce"
    assert domain_for("kena ddos?") == "flood_ddos"
    assert domain_for("nginx service-nya down") == "service_health"
    assert domain_for("disk penuh") == "resource_issue"
    assert domain_for("halo") is None


def test_real_network_session_counts_as_covered():
    commands = [
        "terminal_execute ss -tuln | head -20",
        "terminal_execute netstat -an | grep ESTABLISHED | wc -l",
        "terminal_execute cat /proc/net/snmp | grep -E 'Ip|Tcp|Udp'",
        "terminal_execute ip -s link show wlp0s20f3",
        "terminal_execute ip route show",
        "terminal_execute ping -c 4 8.8.8.8",
        "terminal_execute sudo iptables -L -n -v",
        "terminal_execute sudo tcpdump -i any -n -c 50",
    ]
    covered = coverage_from_commands(commands, "check network apakah ada anomali engga")
    # ss -tuln must satisfy the listening-sockets hint even though it says -tulpn
    assert "listeners" in covered
    assert {"counters", "interface", "route", "firewall", "capture"} <= covered
    # and there is still something left to verify, so a slice must rotate
    objective = next_objective("check network apakah ada anomali engga", covered)
    assert objective is not None
    assert "Next objective" in objective[1]


def test_coverage_report_names_what_is_missing():
    report = render_coverage_report("cek ada brute force ssh tidak", {"auth_failures"})
    assert "Coverage" in report
    assert "auth_failures" in report
    assert "Not verified" in report


def test_unknown_domain_has_no_checklist():
    assert checklist_for("halo") == {}
    assert next_objective("halo", set()) is None
    assert render_coverage_report("halo", set()) == ""


# --- the six-tool architecture ----------------------------------------------

from sre_agent.engine import _ensure_tools_registered  # noqa: E402
from sre_agent.tools import ToolRegistry  # noqa: E402


def test_registry_only_exposes_the_six_powerful_tools():
    _ensure_tools_registered()
    names = {m.name for m in ToolRegistry().list_all()}
    assert names == {
        "get_current_directory", "read_file", "write_file", "edit_file",
        "terminal_execute", "spawn_subagent",
    }


def test_spawn_subagent_is_registered_so_multi_agent_can_delegate():
    _ensure_tools_registered()
    registry = ToolRegistry()
    assert registry.get_tool("spawn_subagent") is not None
    assert registry.get_metadata("spawn_subagent") is not None


def test_orchestrator_mode_can_delegate_but_cannot_execute_directly():
    from sre_agent.discovery import ToolDiscoveryAgent
    from sre_agent.react_engine import ReactEngine

    class _LLM:
        def bind_tools(self, tools, **kwargs):
            return self

    tools = ToolDiscoveryAgent().discover_single_agent_tools("cek dua service sekaligus").tools
    multi = [t.name for t in ReactEngine(_LLM(), tools, "sys", "sid", mode="autonomous_multi").tools]
    assert "spawn_subagent" in multi
    assert not {"terminal_execute", "write_file", "edit_file"} & set(multi)

    guided = [t.name for t in ReactEngine(_LLM(), tools, "sys", "sid", mode="guided").tools]
    # Guided withholds execution from the model, including via delegation.
    assert not {"terminal_execute", "write_file", "edit_file", "spawn_subagent"} & set(guided)


# --- planner JSON extraction for weaker models ------------------------------

from sre_agent.controller import AutonomousController  # noqa: E402


def test_extracts_json_from_prose_around_it():
    raw = (
        'Here is the plan you asked for:\n'
        '{"workers": [{"id": "A", "goal": "check nginx"}]}\n'
        'Let me know if you want more checks.'
    )
    assert AutonomousController._extract_first_json(raw) == '{"workers": [{"id": "A", "goal": "check nginx"}]}'


def test_ignores_a_second_object_after_the_first():
    raw = '{"a": 1} some trailing note {"b": 2}'
    assert AutonomousController._extract_first_json(raw) == '{"a": 1}'


def test_ignores_braces_inside_strings():
    raw = 'note {"workers": [{"goal": "check {nginx} ports"}]} end'
    assert AutonomousController._extract_first_json(raw) == '{"workers": [{"goal": "check {nginx} ports"}]}'


def test_returns_none_when_no_json_present():
    assert AutonomousController._extract_first_json('no json here at all') is None


# --- per-model tool_choice (thinking models reject forced calls) ------------

from sre_agent.react_engine import ReactEngine  # noqa: E402


class _BindRecorder:
    def __init__(self):
        self.calls = []

    def bind_tools(self, tools, **kwargs):
        self.calls.append(kwargs.get("tool_choice"))
        return self


def test_react_engine_uses_the_configured_tool_choice():
    rec = _BindRecorder()
    ReactEngine(rec, [], "sys", "sid", mode="autonomous_single", tool_choice="auto")
    assert rec.calls == ["auto"]


def test_react_engine_defaults_to_forcing_a_tool_call():
    rec = _BindRecorder()
    ReactEngine(rec, [], "sys", "sid", mode="autonomous_single")
    assert rec.calls == ["any"]


# --- lookup gate must not swallow real work ----------------------------------

import pytest  # noqa: E402

from sre_agent.direct_chat import is_lookup_turn  # noqa: E402


@pytest.mark.parametrize("message", [
    "jam berapa sekarang",
    "hostname",
    "whoami",
    "where am i",
    "uptime",
    "baca file /etc/hostname",
])
def test_pure_single_fact_questions_stay_deterministic(message):
    assert is_lookup_turn(message) is True


@pytest.mark.parametrize("message", [
    "bandingkan isi file /etc/hostname dengan baris 127.0.0.1 di /etc/hosts, simpulkan satu kalimat",
    "baca file /etc/hostname lalu jawab apa isinya dalam satu kalimat",
    "cek apakah file /etc/hostname bisa dibaca, jawab singkat saja",
    "bandingkan config nginx lama dan baru, apa bedanya",
    "cek disk dan memory, jawab singkat",
    "jelaskan isi /etc/hosts",
])
def test_comparative_or_analytical_turns_reach_tools(message):
    assert is_lookup_turn(message) is False


# --- retry drops failed terminals, keeps everything else ---------------------

import asyncio  # noqa: E402 (already imported above, kept for clarity)


@pytest.fixture
def chat_tables():
    from django.db import connection
    from chatbot.models import ChatMessage, ChatSession, WorkspaceInfo
    with connection.schema_editor() as editor:
        for model in (WorkspaceInfo, ChatSession, ChatMessage):
            try:
                editor.create_model(model)
            except Exception:
                pass
    yield


def test_retry_removes_failed_terminals_but_keeps_answers(chat_tables):
    import uuid as _uuid

    from chatbot.models import ChatMessage, ChatSession
    from sre_agent.engine import SREAgentEngine

    session = ChatSession.objects.create()
    case_id = "inv_" + _uuid.uuid4().hex[:8]
    failed = ChatMessage.objects.create(
        session_id=session.id, sender="ai",
        message="Agent execution failed; no successful completion was recorded.",
        metadata={"case_id": case_id, "events": [{"type": "error", "content": "boom"}]},
    )
    answered = ChatMessage.objects.create(
        session_id=session.id, sender="ai",
        message="Nginx is alive and running.",
        metadata={"case_id": case_id, "events": [{"type": "completed", "content": "done"}]},
    )
    asked = ChatMessage.objects.create(
        session_id=session.id, sender="user",
        message="coba ingatan kamu",
        metadata={"case_id": case_id},
    )

    # Call the synchronous core directly: the async wrapper only adds
    # thread-hopping, which in-memory SQLite test databases do not survive.
    from sre_agent.engine import SREAgentEngine
    removed = SREAgentEngine._drop_failed_terminals_sync(str(session.id), case_id)
    assert removed == 1
    remaining = set(
        ChatMessage.objects.filter(session_id=session.id).values_list("id", flat=True)
    )
    assert failed.id not in remaining
    assert answered.id in remaining
    assert asked.id in remaining


# --- explicit resume selection ------------------------------------------------

from types import SimpleNamespace  # noqa: E402
import datetime as _dt  # noqa: E402

from sre_agent.engine import select_resumable_case  # noqa: E402


def _case(cid, status, minutes_ago):
    return SimpleNamespace(
        id=cid, pk=cid, status=status,
        updated_at=_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(minutes=minutes_ago),
    )


def test_bare_continue_gets_the_fresh_latest_case_only():
    fresh = _case("inv_new", "active", 10)
    old = _case("inv_old", "active", 500)
    resumable, expired, refusal = select_resumable_case([fresh, old], "", True)
    assert resumable.id == "inv_new"
    assert expired == [] and refusal == ""


def test_bare_continue_expires_a_stale_latest_case():
    stale = _case("inv_old", "active", 500)
    resumable, expired, refusal = select_resumable_case([stale], "", True)
    assert resumable is None
    assert expired == ["inv_old"] and refusal == ""


def test_explicit_retry_names_its_case_regardless_of_age():
    stale = _case("inv_old", "active", 500)
    resumable, _, refusal = select_resumable_case([stale], "inv_old", True)
    assert resumable.id == "inv_old" and refusal == ""


def test_explicit_retry_of_a_foreign_case_is_refused_not_rerouted():
    mine = _case("inv_mine", "active", 5)
    resumable, _, refusal = select_resumable_case([mine], "inv_theirs", True)
    assert resumable is None
    assert "another chat" in refusal


def test_explicit_retry_of_a_completed_case_is_refused():
    done = _case("inv_done", "completed", 5)
    resumable, _, refusal = select_resumable_case([done], "inv_done", True)
    assert resumable is None
    assert "already completed" in refusal


def test_case_id_without_a_retry_word_is_ignored():
    fresh = _case("inv_new", "active", 5)
    resumable, _, refusal = select_resumable_case([fresh], "inv_new", False)
    assert resumable.id == "inv_new" and refusal == ""
