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