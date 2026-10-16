"""The REST surface behind the Explorer, Artifacts and Models tabs.

These six endpoints were all @api_view(['GET']) with no permission class, so
DRF's default AllowAny applied and the Cloudflare tunnel made them readable from
the public internet. Two of them handed out real secrets:

  /api/v1/workspace/file/?path=.env  -> 200, every API key in the file
  /api/v1/workspace/tree/?path=/etc  -> 200, a map of the filesystem that tells
                                        an attacker which path to ask for next

Each test pins both directions. A guard that also locked the operator out of
their own tabs would be worse than the hole, so the authenticated half is
asserted as loudly as the anonymous half.
"""
import pytest
from django.contrib.auth.models import User
from django.test import Client

from chatbot.models import (AgentArtifact, AIModel, ChatMessage, ChatSession,
                             WorkspaceInfo)

pytestmark = pytest.mark.django_db

PROJECT_ROOT = "/api/v1/"

# (url, method) for the guarded endpoints.
GUARDED = [
    ("/api/v1/system_status/", "get"),
    ("/api/v1/chat/", "post"),
    ("/api/v1/workspace/tree/", "get"),
    ("/api/v1/workspace/file/", "get"),
    ("/api/v1/workspace/artifacts/", "get"),
]


def _operator_client():
    """A login that also clears EnforceActiveSessionMiddleware's 2FA bounce."""
    user = User.objects.create_user("operator", password="x")
    user.profile.is_active_session = True
    user.profile.save()
    client = Client()
    client.force_login(user)
    return client


def _seed():
    session = ChatSession.objects.create(title="triage suricata")
    ChatMessage.objects.create(session=session, role="user", message="alert suricata")
    workspace = WorkspaceInfo.objects.create(workspace_path="/tmp/probe")
    AgentArtifact.objects.create(workspace=workspace, session_id=str(session.id),
                                 file_path="/tmp/a.md", action_type="file_write")
    return session


# --- anonymous is refused --------------------------------------------------

@pytest.mark.parametrize("url,method", GUARDED)
def test_anonymous_is_refused(url, method):
    _seed()
    response = getattr(Client(), method)(url)
    assert response.status_code in (401, 403), (
        f"{url} answered {response.status_code} with no session"
    )


def test_anonymous_cannot_read_the_env_file():
    response = Client().get("/api/v1/workspace/file/", {"path": ".env"})
    assert response.status_code in (401, 403), (
        f".env was served to an anonymous caller ({response.status_code})"
    )


def test_anonymous_cannot_map_the_filesystem():
    response = Client().get("/api/v1/workspace/tree/", {"path": "/etc"})
    assert response.status_code in (401, 403)


def test_anonymous_cannot_list_artifacts():
    _seed()
    response = Client().get("/api/v1/workspace/artifacts/", {"session_id": "x"})
    assert response.status_code in (401, 403)


def test_anonymous_is_bounced_from_the_model_list():
    response = Client().get("/api/v1/ai-models/")
    # Plain Django view guarded with @login_required, so it redirects to the
    # login page instead of answering 403 like the DRF ones.
    assert response.status_code in (302, 401, 403)


# --- the operator keeps every feature --------------------------------------

def test_operator_gets_system_status():
    response = _operator_client().get("/api/v1/system_status/")
    assert response.status_code == 200
    assert "cpu_usage" in response.json()


def test_operator_can_browse_the_explorer():
    response = _operator_client().get("/api/v1/workspace/tree/", {"path": "/tmp"})
    assert response.status_code == 200


def test_operator_can_list_artifacts():
    session = _seed()
    response = _operator_client().get(
        "/api/v1/workspace/artifacts/", {"session_id": str(session.id)}
    )
    assert response.status_code == 200
    assert len(response.json()) == 1


def test_operator_reaches_the_model_list():
    # Seed a row so seed_default_ai_models() short-circuits. It only touches
    # DEFAULT_AI_MODELS when the table is empty, and that name is undefined in
    # this module - a pre-existing bug that a populated database hides.
    AIModel.objects.create(name="Probe", model_id="probe-model")
    response = _operator_client().get("/api/v1/ai-models/")
    assert response.status_code == 200
    assert response.json()["status"] == "success"


def test_operator_can_still_post_to_the_legacy_chat_endpoint():
    # The only caller is generator/textGenerator.html, whose view is commented
    # out in urls.py, so nothing in the live app depends on it. Guarded anyway
    # because it reaches execute_step().
    response = _operator_client().post("/api/v1/chat/",
                                      {"prompt": "", "additional_input": None},
                                      content_type="application/json")
    # Authenticated and reaching the view: an empty prompt is its own 400.
    assert response.status_code == 400