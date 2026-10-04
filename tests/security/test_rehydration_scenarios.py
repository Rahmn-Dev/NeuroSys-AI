from datetime import timedelta
from types import SimpleNamespace
import pytest
from django.db import connection
from django.test import RequestFactory
from django.utils import timezone
from chatbot.models import WorkspaceInfo, ChatSession, ChatMessage, AgentRun, AgentTask, AgentTransition, AgentApproval
from chatbot.views import agent_run_snapshot

MODELS = (WorkspaceInfo, ChatSession, ChatMessage, AgentRun, AgentTask, AgentTransition, AgentApproval)


@pytest.fixture
def snapshot_fixture():
    with connection.schema_editor() as editor:
        for model in MODELS:
            try: editor.create_model(model)
            except Exception: pass
    session = ChatSession.objects.create(title='rehydration scenarios')
    run = AgentRun.objects.create(session=session, user_id='7', goal='safe resume', status='running',
                                  model='fixture', idempotency_key='scenario-run')
    ChatMessage.objects.create(session=session, role='user', sender='user', message='same transcript')
    def snapshot():
        request = RequestFactory().get('/api/v1/agent-runs/snapshot/', {'session_id': str(session.id)})
        request.user = SimpleNamespace(pk=7, is_active=True, is_authenticated=True)
        return agent_run_snapshot(request).data
    yield session, run, snapshot
    for model in reversed(MODELS):
        try: editor.delete_model(model)
        except Exception: pass


def test_refresh_during_awaiting_approval_reuses_token(snapshot_fixture):
    session, run, snapshot = snapshot_fixture
    approval = AgentApproval.objects.create(session_id=str(session.id), user_id='7', tool_name='fixture',
        arguments_hash='a'*64, arguments_preview={'keys': ['path'], 'target': '[redacted action arguments]'},
        expires_at=timezone.now()+timedelta(seconds=30), request_id='approval-refresh')
    run.status = 'awaiting_approval'; run.save(update_fields=['status'])
    first, second = snapshot(), snapshot()
    assert first['run']['id'] == second['run']['id'] == run.id
    assert first['run']['pending_approval']['request_id'] == second['run']['pending_approval']['request_id'] == approval.request_id
    assert AgentApproval.objects.count() == 1


def test_reconnect_running_keeps_checkpoint_and_run(snapshot_fixture):
    _, run, snapshot = snapshot_fixture
    run.checkpoint_version = 4; run.current_node = 'execution'; run.save(update_fields=['checkpoint_version', 'current_node'])
    first, second = snapshot(), snapshot()
    assert first['run']['id'] == second['run']['id']
    assert first['run']['checkpoint_version'] == second['run']['checkpoint_version'] == 4


def test_reload_after_done_rehydrates_final_state(snapshot_fixture):
    _, run, snapshot = snapshot_fixture
    run.status = 'completed'; run.summary = 'done'; run.save(update_fields=['status', 'summary'])
    first, second = snapshot(), snapshot()
    assert first['run']['status'] == second['run']['status'] == 'completed'
    assert first['messages'][0]['id'] == second['messages'][0]['id']


def test_expiry_while_disconnected_finalizes_denied_timeout(snapshot_fixture):
    session, run, snapshot = snapshot_fixture
    AgentApproval.objects.create(session_id=str(session.id), user_id='7', tool_name='fixture',
        arguments_hash='b'*64, arguments_preview={}, expires_at=timezone.now()-timedelta(seconds=1), request_id='approval-expired')
    run.status = 'awaiting_approval'; run.save(update_fields=['status'])
    payload = snapshot()
    assert payload['run']['status'] == 'blocked'
    assert AgentApproval.objects.get(request_id='approval-expired').status == 'denied_timeout'


def test_duplicate_reconnect_has_no_new_run_or_transcript_duplicates(snapshot_fixture):
    _, run, snapshot = snapshot_fixture
    before = AgentRun.objects.count()
    first, second = snapshot(), snapshot()
    assert AgentRun.objects.count() == before == 1
    ids = [m['id'] for m in first['messages'] + second['messages']]
    assert len(set(ids[:len(first['messages'])])) == len(first['messages'])
    assert first['messages'] == second['messages']


def test_resume_does_not_duplicate_side_effect_transition(snapshot_fixture):
    _, run, snapshot = snapshot_fixture
    AgentTransition.objects.create(run=run, sequence=1, node='execution', from_status='running',
                                   to_status='running', event_type='tool_once', payload={'idempotency_key': 'same'})
    before = AgentTransition.objects.count()
    snapshot(); snapshot()
    assert AgentTransition.objects.count() == before
    assert AgentRun.objects.get(pk=run.pk).idempotency_key == 'scenario-run'


def test_reconnect_bootstrap_observes_new_checkpoint_without_new_run(snapshot_fixture):
    _, run, snapshot = snapshot_fixture
    first = snapshot()
    run.status = 'verifying'; run.checkpoint_version = 2; run.current_node = 'verification'
    run.save(update_fields=['status', 'checkpoint_version', 'current_node'])
    second = snapshot()
    assert second['run']['id'] == first['run']['id']
    assert second['run']['checkpoint_version'] > first['run']['checkpoint_version']
    assert second['run']['status'] == 'verifying'
    assert AgentRun.objects.count() == 1
