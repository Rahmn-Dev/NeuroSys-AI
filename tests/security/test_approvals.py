import json
from datetime import timedelta
from types import SimpleNamespace

import pytest
from django.db import connection
from django.utils import timezone
from langchain_core.tools import StructuredTool

from chatbot.models import AgentApproval
from sre_agent.approvals import (approve, args_hash, consume_for,
                                 deny, derive_goal_scope, execution_context,
                                 request_approval)
from sre_agent.tools.registry import ToolMetadata, ToolRegistry, RiskLevel


@pytest.fixture(autouse=True)
def approval_table():
    with connection.schema_editor() as editor:
        editor.create_model(AgentApproval)
    try:
        yield
    finally:
        with connection.schema_editor() as editor:
            editor.delete_model(AgentApproval)


def mutation_meta():
    return ToolMetadata("service_manager", "test mutation", "test", RiskLevel.MEDIUM)


def test_unauthorized_mutation_blocked():
    with execution_context("s1", "u1", mode="controlled"):
        with pytest.raises(PermissionError, match="approval_required"):
            consume_for(mutation_meta(), {"action": "restart", "service_name": "demo"})


def test_allow_once_is_exact_and_single_use():
    args = {"action": "restart", "service_name": "demo"}
    obj = request_approval(session_id="s1", user_id="u1", tool_name="service_manager", args=args)
    approve(obj.pk, session_id="s1", user_id="u1")
    with execution_context("s1", "u1", mode="controlled", approval_id=obj.pk):
        consume_for(mutation_meta(), args)
        with pytest.raises(PermissionError):
            consume_for(mutation_meta(), args)
    assert AgentApproval.objects.get(pk=obj.pk).status == "consumed"


def test_approval_a_does_not_authorize_b():
    a = {"action": "restart", "service_name": "demo"}
    b = {"action": "stop", "service_name": "demo"}
    obj = request_approval(session_id="s1", user_id="u1", tool_name="service_manager", args=a)
    approve(obj.pk, session_id="s1", user_id="u1")
    with execution_context("s1", "u1", approval_id=obj.pk):
        with pytest.raises(PermissionError):
            consume_for(mutation_meta(), b)


def test_expired_approval_rejected():
    args = {"action": "restart", "service_name": "demo"}
    obj = request_approval(session_id="s1", user_id="u1", tool_name="service_manager", args=args)
    approve(obj.pk, session_id="s1", user_id="u1")
    AgentApproval.objects.filter(pk=obj.pk).update(expires_at=timezone.now() - timedelta(seconds=1))
    with execution_context("s1", "u1", approval_id=obj.pk):
        with pytest.raises(PermissionError):
            consume_for(mutation_meta(), args)
    assert AgentApproval.objects.get(pk=obj.pk).status == "expired"


def test_session_and_user_mismatch_rejected():
    args = {"action": "restart", "service_name": "demo"}
    obj = request_approval(session_id="s1", user_id="u1", tool_name="service_manager", args=args)
    with pytest.raises(PermissionError):
        approve(obj.pk, session_id="s2", user_id="u1")
    approve(obj.pk, session_id="s1", user_id="u1")
    with execution_context("s2", "u1", approval_id=obj.pk):
        with pytest.raises(PermissionError):
            consume_for(mutation_meta(), args)


def test_full_access_auto_approves_non_blocked_actions_without_scope():
    # Full Access = pre-authorized: approval-required actions proceed with an
    # audit record instead of waiting for a human click. Disable via
    # AGENT_FULL_ACCESS_AUTO_APPROVE=False to restore strict scope.
    args = {"action": "restart", "service_name": "demo"}
    with execution_context("s1", "u1", mode="full", scope=[]):
        assert consume_for(mutation_meta(), args)


def test_controlled_mode_still_requires_approval():
    args = {"action": "restart", "service_name": "demo"}
    with execution_context("s1", "u1", mode="controlled", scope=[]):
        with pytest.raises(PermissionError, match="approval_required"):
            consume_for(mutation_meta(), args)


def test_full_access_scope_is_derived_from_explicit_goal_and_exact_action():
    args = {"action": "restart", "service_name": "nginx"}
    scope = derive_goal_scope("Please restart nginx")
    assert scope == [{"tool": "service_manager", "args_hash": args_hash(args)}]
    with execution_context("s1", "u1", mode="full", scope=scope):
        assert consume_for(mutation_meta(), args)
        # Auto-approve is on by default, so an out-of-scope non-blocked
        # action still proceeds (audited) instead of raising.


@pytest.mark.parametrize("goal", [
    "inspect nginx", "run sudo id", "execute rm -rf /", "restart nginx; then restart ssh",
])
def test_goal_scope_never_authorizes_shell_or_ambiguous_extra_actions(goal):
    scope = derive_goal_scope(goal)
    assert all(item["tool"] not in {"terminal_execute", "execute_command", "safe_execute"} for item in scope)


def test_full_access_hard_block_remains_active():
    meta = ToolMetadata("terminal_execute", "shell", "system", RiskLevel.HIGH)
    with execution_context("s1", "u1", mode="full", scope=[{"tool": "terminal_execute", "args_hash": args_hash({"command": "rm -rf /"})}]):
        with pytest.raises(PermissionError, match="blocked"):
            consume_for(meta, {"command": "rm -rf /"})

def test_full_access_secret_exfiltration_hard_block():
    meta = ToolMetadata("terminal_execute", "shell", "system", RiskLevel.HIGH)
    with execution_context("s1", "u1", mode="full", scope=[{"tool": "terminal_execute", "args_hash": args_hash({"command": "cat /etc/shadow"})}]):
        with pytest.raises(PermissionError, match="blocked"):
            consume_for(meta, {"command": "cat /etc/shadow"})


def test_preview_and_audit_never_store_payload():
    args = {"command": "sudo id PASSWORD=canary-secret"}
    obj = request_approval(session_id="s1", user_id="u1", tool_name="terminal_execute", args=args)
    raw = json.dumps(obj.arguments_preview)
    assert "canary-secret" not in raw

def test_lifecycle_audit_events_are_emitted_without_payload(caplog):
    args = {"action": "restart", "service_name": "demo"}
    obj = request_approval(session_id="s1", user_id="u1", tool_name="service_manager", args=args)
    approve(obj.pk, session_id="s1", user_id="u1")
    with execution_context("s1", "u1", approval_id=obj.pk):
        consume_for(mutation_meta(), args)
    names = [r.message for r in caplog.records if r.name == "neurosys.security"]
    assert any('approval_requested' in n for n in names)
    assert any('approval_approved' in n for n in names)
    assert any('approval_consumed' in n for n in names)
    assert "restart" in "".join(names) or "service_manager" in "".join(names)
    assert "demo" not in "".join(names)

@pytest.mark.parametrize('decision, expected', [(True, 'approved'), (False, 'denied'), (None, 'denied_timeout')])
def test_server_owned_wait_and_exact_resume(decision, expected, caplog):
    import asyncio
    from asgiref.sync import async_to_sync
    from django.test import override_settings
    from sre_agent.approval_lifecycle import ApprovalLifecycle, ApprovalStopped, active_lifecycle
    from sre_agent.security_boundary import protect_tool
    events, effects = [], []
    def action(service_name: str, action: str):
        effects.append(service_name)
        return 'ok'
    tool = StructuredTool.from_function(action, name='service_manager', description='test')
    protect_tool(tool, mutation_meta())
    async def scenario():
        async def send(event):
            events.append(event)
        lifecycle = ApprovalLifecycle(send)
        token = active_lifecycle.set(lifecycle)
        try:
            with execution_context('s1', 'u1'):
                task = asyncio.create_task(tool.ainvoke({'service_name':'demo', 'action':'restart'}))
                for _ in range(200):
                    if lifecycle.pending: break
                    await asyncio.sleep(.001)
                assert lifecycle.pending and not task.done() and not effects
                obj, _ = lifecycle.pending
                assert events[0]['status'] == 'awaiting_approval'
                assert not any(e['type'] == 'completed' for e in events)
                assert not lifecycle.decide({'approval_id':obj.pk,'session_id':'wrong','approved':True}, 'u1')
                if decision is not None:
                    assert lifecycle.decide({'approval_id':obj.pk,'session_id':'s1','approved':decision}, 'u1')
                    assert not lifecycle.decide({'approval_id':obj.pk,'session_id':'s1','approved':decision}, 'u1')
                if decision:
                    assert await task == 'ok'
                else:
                    with pytest.raises(asyncio.CancelledError): await task
        finally:
            active_lifecycle.reset(token)
    with override_settings(AGENT_APPROVAL_TIMEOUT_SECONDS=.08 if decision is None else 30):
        async_to_sync(scenario)()
    assert effects == (['demo'] if decision else [])
    assert events[-1]['status'] == expected
    names = '\n'.join(r.message for r in caplog.records)
    assert ('approval_consumed' if decision else 'approval_auto_denied' if decision is None else 'approval_denied') in names


def test_default_timeout_and_no_early_or_terminal_expiry():
    from sre_agent.approvals import expire
    before = timezone.now()
    obj = request_approval(session_id='s', user_id='u', tool_name='service_manager', args={'action': 'restart', 'service_name': 'nginx'})
    assert 29.9 <= (obj.expires_at-before).total_seconds() <= 30.1
    with pytest.raises(PermissionError): expire(obj.pk, session_id='s', user_id='u')
    approve(obj.pk, session_id='s', user_id='u')
    with pytest.raises(PermissionError): deny(obj.pk, session_id='s', user_id='u')
    assert AgentApproval.objects.get(pk=obj.pk).status == 'approved'

@pytest.mark.parametrize('user,tool', [('other','service_manager'), ('u','other_tool')])
def test_consume_wrong_user_or_tool(user, tool):
    obj=request_approval(session_id='s',user_id='u',tool_name='service_manager',args={'action': 'restart', 'service_name': 'nginx'})
    approve(obj.pk,session_id='s',user_id='u')
    meta=ToolMetadata(tool,'test','test',RiskLevel.HIGH)
    with execution_context('s',user,approval_id=obj.pk), pytest.raises(PermissionError):
        consume_for(meta,{})


def test_full_access_workspace_write_scope_is_prefix_confined(monkeypatch):
    # With auto-approve disabled, the derived workspace scope is the only
    # thing standing between the agent and the filesystem: exact-prefix
    # writes pass, everything else needs a human.
    import django.conf
    monkeypatch.setattr(django.conf.settings, "AGENT_FULL_ACCESS_AUTO_APPROVE", False, raising=False)
    scope = derive_goal_scope("tulis laporan ke /tmp/ws/REPORT.md", workspace="/tmp/ws")
    assert {"tool": "write_file", "path_prefix": "/tmp/ws"} in scope
    assert {"tool": "edit_file", "path_prefix": "/tmp/ws"} in scope
    meta = ToolMetadata("write_file", "test write", "test", RiskLevel.MEDIUM)
    with execution_context("s1", "u1", mode="full", scope=scope):
        assert consume_for(meta, {"path": "/tmp/ws/REPORT.md", "content": "x"})
        with pytest.raises(PermissionError):
            consume_for(meta, {"path": "/etc/cron.d/evil", "content": "x"})
        with pytest.raises(PermissionError):
            consume_for(meta, {"path": "REPORT.md", "content": "x"})
        with pytest.raises(PermissionError):
            consume_for(meta, {"path": "/tmp/ws/.env", "content": "x"})


def test_write_scope_requires_explicit_write_intent_and_workspace():
    assert derive_goal_scope("cek service nginx", workspace="/tmp/ws") == []
    assert derive_goal_scope("tulis laporan ringkas") == []


def test_full_access_still_blocks_credential_writes():
    meta = ToolMetadata("write_file", "test write", "test", RiskLevel.MEDIUM)
    with execution_context("s1", "u1", mode="full", scope=[]):
        with pytest.raises(PermissionError, match="blocked"):
            consume_for(meta, {"path": "/root/.ssh/authorized_keys", "content": "x"})
        with pytest.raises(PermissionError, match="blocked"):
            consume_for(meta, {"path": "/tmp/ws/../evil.txt", "content": "x"})
        with pytest.raises(PermissionError, match="blocked"):
            consume_for(meta, {"content": "x"})


def test_full_access_auto_approve_can_be_disabled(monkeypatch):
    import django.conf
    monkeypatch.setattr(django.conf.settings, "AGENT_FULL_ACCESS_AUTO_APPROVE", False, raising=False)
    args = {"action": "restart", "service_name": "demo"}
    with execution_context("s1", "u1", mode="full", scope=[]):
        with pytest.raises(PermissionError, match="approval_required"):
            consume_for(mutation_meta(), args)
