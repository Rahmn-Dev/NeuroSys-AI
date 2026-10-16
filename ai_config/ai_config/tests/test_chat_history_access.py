"""Access control for the chat history REST surface.

The sidebar and the replay pager read sessions and messages over
`/api/v1/chat-sessions/`. The only page that renders them is chat3, which is
itself @login_required, so nothing in the working app needs anonymous access.
This file pins that contract: anonymous is refused, an authenticated operator is
served, and the sidebar search keeps working after the gate is applied.
"""
import pytest
from django.contrib.auth.models import User
from django.test import Client
from django.urls import reverse

from chatbot.models import ChatMessage, ChatSession

pytestmark = pytest.mark.django_db


SESSIONS_URL = "/api/v1/chat-sessions/"


def _seed():
    session = ChatSession.objects.create(title="suricata alert triage")
    ChatMessage.objects.create(session=session, role="user",
                               message="tolong jelaskan alert suricata ini")
    other = ChatSession.objects.create(title="unrelated deploy chat")
    ChatMessage.objects.create(session=other, role="user",
                               message="jalankan uptime saja")
    return session, other


def _client():
    return Client()


def _operator_client():
    """A logged-in operator that also clears EnforceActiveSessionMiddleware.

    That middleware bounces any authenticated user whose Profile is not flagged
    active to the 2FA page, so a bare create_user() gets a 302 instead of data.
    """
    user = User.objects.create_user("operator", password="x")
    user.profile.is_active_session = True
    user.profile.save()
    client = _client()
    client.force_login(user)
    return client


def test_anonymous_cannot_list_chat_sessions():
    _seed()
    response = _client().get(SESSIONS_URL)
    assert response.status_code in (401, 403), (
        "chat history is readable without a session; anyone who can reach the "
        f"port gets it (got {response.status_code})"
    )


def test_anonymous_cannot_read_chat_messages():
    session, _ = _seed()
    response = _client().get(f"{SESSIONS_URL}{session.id}/messages/")
    assert response.status_code in (401, 403), (
        f"messages of {session.id} readable anonymously (got {response.status_code})"
    )


def test_authenticated_operator_still_gets_the_sidebar():
    _seed()
    client = _operator_client()
    response = client.get(SESSIONS_URL)
    assert response.status_code == 200
    assert len(response.json()["results"]) == 2


def test_sidebar_search_matches_title_and_message_text():
    session, other = _seed()
    client = _operator_client()

    by_title = client.get(SESSIONS_URL, {"search": "triage"}).json()["results"]
    assert [s["id"] for s in by_title] == [str(session.id)]

    # The operator searches for a word that only appears inside the
    # conversation, never in the generated title.
    by_message = client.get(SESSIONS_URL, {"search": "uptime"}).json()["results"]
    assert [s["id"] for s in by_message] == [str(other.id)]


def test_search_does_not_duplicate_a_session_on_repeated_hits():
    session, _ = _seed()
    # Three messages contain the term; the session must still come back once.
    for _ in range(2):
        ChatMessage.objects.create(session=session, role="user",
                                   message="mention of suricata again")
    client = _operator_client()
    results = client.get(SESSIONS_URL, {"search": "suricata"}).json()["results"]
    assert [s["id"] for s in results] == [str(session.id)]


def test_empty_search_returns_everything():
    _seed()
    client = _operator_client()
    for term in ("", "   "):
        assert len(client.get(SESSIONS_URL, {"search": term}).json()["results"]) == 2


def test_search_ignores_sql_wildcards_as_literals():
    _seed()
    client = _operator_client()
    # A bare % must not turn into "match everything" through LIKE.
    assert client.get(SESSIONS_URL, {"search": "%"}).json()["results"] == []