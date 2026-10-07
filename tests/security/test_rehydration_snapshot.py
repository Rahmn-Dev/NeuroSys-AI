from types import SimpleNamespace
from django.db import connection
from django.test import RequestFactory
from chatbot.models import WorkspaceInfo, ChatSession, ChatMessage, AgentRun, AgentTask, AgentTransition, AgentApproval
from chatbot.views import agent_run_snapshot


def test_snapshot_is_owned_and_contains_checkpoint_task_and_transcript():
    models = (WorkspaceInfo, ChatSession, ChatMessage, AgentRun, AgentTask, AgentTransition, AgentApproval)
    with connection.schema_editor() as editor:
        for model in models:
            try:
                editor.create_model(model)
            except Exception:
                pass
    try:
        session = ChatSession.objects.create(title='rehydration')
        ChatMessage.objects.create(session=session, role='user', sender='user', message='resume me')
        run = AgentRun.objects.create(session=session, user_id='7', goal='resume me', status='awaiting_approval',
                                      model='fixture', idempotency_key='rehydration-test')
        AgentTask.objects.create(run=run, task_key='t1', title='pending task', status='awaiting_approval')
        AgentTransition.objects.create(run=run, sequence=1, node='approval', from_status='running',
                                       to_status='awaiting_approval', event_type='approval_required', payload={'tool': 'fixture'})
        request = RequestFactory().get('/api/v1/agent-runs/snapshot/', {'session_id': str(session.id)})
        request.user = SimpleNamespace(pk=7, is_active=True, is_authenticated=True)
        response = agent_run_snapshot(request)
        assert response.status_code == 200
        payload = response.data
        assert payload['run']['status'] == 'awaiting_approval'
        assert payload['run']['created_at']
        assert payload['run']['tasks'][0]['status'] == 'awaiting_approval'
        assert payload['run']['events'][0]['event_type'] == 'approval_required'
        assert payload['messages'][0]['content'] == 'resume me'
    finally:
        for model in reversed(models):
            try:
                editor.delete_model(model)
            except Exception:
                pass
