import pytest
from django.contrib.auth.models import User
from django.db import connection

from chatbot import mutations
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

    assert mutations.get_permission_mode(user) == {"mode": "need_approval"}
    assert mutations.set_permission_mode(user, "full_access") == {"mode": "full_access"}
    audit = AgentPermissionAudit.objects.get(user=user)
    assert (audit.previous_mode, audit.new_mode, audit.source) == (
        "need_approval", "full_access", "ui"
    )


def test_permission_rejects_unknown_mode_without_audit(permission_tables):
    user = User.objects.create_user(username="operator")
    with pytest.raises(mutations.MutationError):
        mutations.set_permission_mode(user, "unrestricted")
    assert Profile.objects.get(user=user).agent_permission_mode == "need_approval"
    assert not AgentPermissionAudit.objects.exists()


def test_mutations_require_sign_in(permission_tables):
    from django.contrib.auth.models import AnonymousUser

    anon = AnonymousUser()
    with pytest.raises(mutations.MutationError):
        mutations.set_permission_mode(anon, "full_access")
    with pytest.raises(mutations.MutationError):
        mutations.delete_chat_session(anon, "00000000-0000-0000-0000-000000000000")
