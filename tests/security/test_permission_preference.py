import pytest
from django.contrib.auth.models import User
from django.db import connection
from rest_framework.test import APIRequestFactory, force_authenticate

from chatbot.api import agent_permission
from chatbot.models import AgentPermissionAudit, Profile


@pytest.fixture
def permission_tables():
    models = (User, Profile, AgentPermissionAudit)
    with connection.schema_editor() as editor:
        for model in models:
            editor.create_model(model)
    try:
        yield
    finally:
        with connection.schema_editor() as editor:
            for model in reversed(models):
                editor.delete_model(model)


def test_permission_defaults_closed_and_change_is_audited(permission_tables):
    user = User.objects.create_user(username="operator")
    factory = APIRequestFactory()

    get_request = factory.get("/api/v1/agent-permission/")
    force_authenticate(get_request, user=user)
    assert agent_permission(get_request).data == {"mode": "need_approval"}

    put_request = factory.put(
        "/api/v1/agent-permission/", {"mode": "full_access"}, format="json"
    )
    force_authenticate(put_request, user=user)
    assert agent_permission(put_request).data == {"mode": "full_access"}
    audit = AgentPermissionAudit.objects.get(user=user)
    assert (audit.previous_mode, audit.new_mode, audit.source) == (
        "need_approval", "full_access", "ui"
    )


def test_permission_rejects_unknown_mode_without_audit(permission_tables):
    user = User.objects.create_user(username="operator")
    request = APIRequestFactory().put(
        "/api/v1/agent-permission/", {"mode": "unrestricted"}, format="json"
    )
    force_authenticate(request, user=user)
    response = agent_permission(request)
    assert response.status_code == 400
    assert Profile.objects.get(user=user).agent_permission_mode == "need_approval"
    assert not AgentPermissionAudit.objects.exists()
