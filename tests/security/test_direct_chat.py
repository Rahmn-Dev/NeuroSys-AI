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
    assert parse_route('{"route": "direct", "reason": "greeting"}') == ("direct", "greeting")
    assert parse_route('{"route":"agent","reason":"needs log read"}')[0] == "agent"


def test_router_verdict_from_plain_keyword():
    assert parse_route("direct")[0] == "direct"


@pytest.mark.parametrize("raw", ["", "   ", "garbage", '{"route":"weird"}', "{}"])
def test_unusable_router_output_falls_back_to_the_agent(raw):
    route, reason = parse_route(raw)
    assert route == "agent"
    assert reason


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
        content = '{"route": "direct", "reason": "small talk"}'

    class _LLM:
        def __init__(self):
            self.calls = 0

        async def ainvoke(self, messages):
            self.calls += 1
            return _Chunk()

    llm = _LLM()
    route, reason = asyncio.run(route_turn(llm, "halo"))
    assert (route, reason) == ("direct", "small talk")
    assert llm.calls == 1


def test_router_failure_routes_to_the_agent():
    class _LLM:
        async def ainvoke(self, messages):
            raise RuntimeError("provider down")

    route, reason = asyncio.run(route_turn(_LLM(), "halo"))
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
