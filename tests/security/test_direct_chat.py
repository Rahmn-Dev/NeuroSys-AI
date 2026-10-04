"""Everyday conversation must not trigger tools, discovery or a case."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "ai_config"))

from sre_agent.direct_chat import is_direct_conversation, direct_chat_prompt  # noqa: E402


@pytest.mark.parametrize("message", [
    "hi",
    "hello",
    "halo paul",
    "selamat pagi",
    "terima kasih",
    "thanks bro",
    "oke",
    "wkwk",
    "apa kabar",
    "how are you",
    "siapa kamu?",
    "who are you",
    "what can you do",
    "siapa saya",
    "tell me a joke",
    "help",
])
def test_small_talk_takes_the_direct_path(message):
    assert is_direct_conversation(message) is True


@pytest.mark.parametrize("message", [
    "cek error di nginx",
    "restart docker",
    "tail -f /var/log/syslog",
    "buatkan file hello.py",
    "test service now",
    "continue",
    "what time is it",
    "where am i",
    "fix the crash in journalctl",
])
def test_operational_work_never_takes_the_direct_path(message):
    assert is_direct_conversation(message) is False


def test_long_messages_are_always_agent_work():
    assert is_direct_conversation("hi " * 200) is False


def test_empty_message_is_not_direct():
    assert is_direct_conversation("") is False
    assert is_direct_conversation("   ") is False


def test_greeting_with_ops_word_is_still_agent_work():
    assert is_direct_conversation("ok cek ram dong") is False


def test_prompt_carries_environment_only_when_present():
    bare = direct_chat_prompt()
    assert "Terminal Directory" not in bare
    with_env = direct_chat_prompt("/srv/app", "/srv/app", "/srv/app/main.py")
    assert "/srv/app/main.py" in with_env

@pytest.mark.parametrize("message", [
    "itu apa ya",
    "jelaskan lagi",
    "kenapa begitu?",
    "what did you find?",
    "why did you say that?",
    "summarize the case",
    "case tadi gimana?",
    "the result earlier?",
    "explain that again",
])
def test_questions_about_the_previous_case_stay_direct(message):
    """Asking about what was already reported needs no tools either."""
    assert is_direct_conversation(message) is True


@pytest.mark.parametrize("message", [
    "lanjut",
    "lanjutkan investigasinya",
    "fix error di nginx",
    "jelaskan kode ini",
    "apa arti error ini",
    "kenapa server down?",
    "cek ram",
])
def test_case_question_rules_do_not_swallow_real_work(message):
    assert is_direct_conversation(message) is False


@pytest.mark.parametrize("message", [
    "kiwww",
    "aaaa.....",
    "bisakah kamu menghibur saya",
    "tau gak neu di jerman sekarang musim apa",
    "is it free?",
    "give me a joke",
])
def test_operationally_empty_turns_are_small_talk(message):
    """No service, file, command or symptom is named, so no tool is needed."""
    assert is_direct_conversation(message) is True


@pytest.mark.parametrize("message", [
    "apt update",
    "docker ps",
    "tail -f app.log",
    "jam berapa sekarang",
    "brankas mana ya",
    "password apa ya",
    "user siapa yang login",
    "cek memory server sekarang",
])
def test_commands_lookups_and_secrets_still_reach_the_agent(message):
    assert is_direct_conversation(message) is False
