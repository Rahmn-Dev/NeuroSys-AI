import pytest
from django.db import connection
from django.utils import timezone
from chatbot.models import AgentApproval
from sre_agent.approvals import request_approval, approve, deny, consume_for, execution_context
from sre_agent.tools.registry import ToolMetadata, RiskLevel


@pytest.fixture
def approval_table():
    with connection.schema_editor() as editor:
        try: editor.create_model(AgentApproval)
        except Exception: pass
    yield
    try: editor.delete_model(AgentApproval)
    except Exception: pass


def test_snapshot_reconnect_deny_uses_same_approval_and_no_renewal(approval_table):
    obj = request_approval(session_id='run-smoke', user_id='7', tool_name='edit_file',
                           args={'path': 'fixture.txt'}, correlation_id='run-smoke')
    assert deny(obj.pk, session_id='run-smoke', user_id='7').status == 'denied'
    assert AgentApproval.objects.count() == 1
    assert AgentApproval.objects.get(pk=obj.pk).request_id == obj.request_id


def test_allow_once_exact_scope_and_single_use(approval_table):
    args = {'path': 'fixture.txt', 'new_text': 'safe'}
    obj = request_approval(session_id='run-smoke', user_id='7', tool_name='edit_file',
                           args=args, correlation_id='run-smoke')
    approved = approve(obj.pk, session_id='run-smoke', user_id='7')
    meta = ToolMetadata(name='edit_file', description='fixture', category='filesystem', risk_level=RiskLevel.MEDIUM,
                        required_permission='edit')
    with execution_context('run-smoke', '7', scope=[], approval_id=approved.pk):
        first = consume_for(meta, args)
        assert first
        with pytest.raises(PermissionError):
            consume_for(meta, args)
    assert AgentApproval.objects.count() == 1
    assert AgentApproval.objects.get(pk=obj.pk).request_id == obj.request_id
