"""Behavioral regressions for run identity, terminal authority and health coverage."""
import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock
import pytest
from django.db import connection
from chatbot.models import WorkspaceInfo, ChatSession, AgentRun, AgentTransition, AgentTask, AgentResourceLock
from sre_agent.canonical_lifecycle import DurableAgentLifecycle, TERMINAL_STATUSES, ContextManager, TrustedObservation, RunAlreadyActive
from sre_agent.security_boundary import evaluate
from sre_agent.health_evidence import collect_health_evidence, requests_system_health


@pytest.fixture
def run_tables():
    models = (WorkspaceInfo, ChatSession, AgentRun, AgentTransition, AgentTask, AgentResourceLock)
    with connection.schema_editor() as editor:
        for model in models:
            editor.create_model(model)
    yield
    with connection.schema_editor() as editor:
        for model in reversed(models):
            editor.delete_model(model)


@pytest.mark.parametrize('status', sorted(TERMINAL_STATUSES) + ['finalized_failed'])
def test_terminal_is_immutable_and_never_resumed(status, run_tables):
    session = ChatSession.objects.create(title='repeat')
    run = DurableAgentLifecycle(session_id=session.pk, goal='nginx')
    first = run.open().pk
    run.transition('finalization', status, status)
    checkpoint = run.run.checkpoint_version
    run.transition('context', 'running', 'run_started')
    assert run.run.status == status
    assert run.run.checkpoint_version == checkpoint
    assert run.resume() is None
    fresh = DurableAgentLifecycle(session_id=session.pk, goal='nginx')
    assert fresh.open().pk != first


def test_duplicate_active_run_rejected(run_tables):
    session = ChatSession.objects.create(title='active')
    DurableAgentLifecycle(session_id=session.pk, goal='nginx').open()
    with pytest.raises(RunAlreadyActive):
        DurableAgentLifecycle(session_id=session.pk, goal='logs').open()


@pytest.mark.parametrize('action', ['list', 'failed', 'status', 'is-active', 'show'])
def test_read_service_never_needs_approval(action):
    meta = SimpleNamespace(name='service_manager', risk_level=3, required_permission='sudo')
    assert evaluate(meta, {'action': action, 'service_name': 'nginx'})[0] == 'approved'


@pytest.mark.parametrize('action', ['start', 'stop', 'restart'])
def test_service_mutation_requires_approval(action):
    meta = SimpleNamespace(name='service_manager', risk_level=3, required_permission='sudo')
    assert evaluate(meta, {'action': action, 'service_name': 'nginx'})[0] == 'approval_required'


def test_service_config_check_is_bounded_read_only():
    meta = SimpleNamespace(name='service_config_check', risk_level=0, required_permission='')
    assert evaluate(meta, {'service_name': 'nginx'})[0] == 'approved'
    assert evaluate(meta, {'service_name': 'custom;id'})[0] == 'blocked'


def test_targeted_system_files_are_readable_but_credentials_remain_blocked():
    meta = SimpleNamespace(name='read_file', risk_level=0, required_permission='')
    assert evaluate(meta, {'path': '/etc/nginx/nginx.conf'})[0] == 'approved'
    assert evaluate(meta, {'path': '/var/log/nginx/error.log'})[0] == 'approved'
    assert evaluate(meta, {'path': '/etc/shadow'})[0] == 'blocked'
    assert evaluate(meta, {'path': '/proc/1/environ'})[0] == 'blocked'


def test_unbounded_root_search_needs_scope_but_targeted_search_is_read_only():
    meta = SimpleNamespace(name='search_files', risk_level=0, required_permission='')
    assert evaluate(meta, {'path': '/', 'pattern': 'nginx'})[0] == 'approval_required'
    assert evaluate(meta, {'path': '/etc/nginx', 'pattern': 'server_name'})[0] == 'approved'


def test_service_discovery_uses_the_shell_not_deleted_wrappers():
    from sre_agent.discovery import ToolDiscoveryAgent
    result = ToolDiscoveryAgent().discover('cek nginx error log dan validasi config')
    # log_reader / service_config_check were thin journalctl+systemctl wrappers.
    assert 'terminal_execute' in result.tool_names
    assert not {'log_reader', 'service_config_check'} & set(result.tool_names)


@pytest.mark.parametrize('service', ['nginx;id', '--root=/tmp', '$(id)', 'nginx\nreboot'])
def test_service_arguments_cannot_inject_shell(service):
    meta = SimpleNamespace(name='service_manager', risk_level=0, required_permission='')
    assert evaluate(meta, {'action': 'status', 'service_name': service})[0] == 'blocked'


def test_health_collects_full_coverage_as_internal_probes():
    # Health coverage is server-side probing, not model-facing tools, so it
    # costs no prompt tokens and cannot be mis-selected. The registry argument
    # is accepted for call-site compatibility and ignored.
    evidence = asyncio.run(collect_health_evidence(object()))
    assert {e['aspect'] for e in evidence} >= {'cpu', 'memory', 'disk', 'uptime_load',
                                               'failed_units', 'service_states', 'service:nginx'}
    assert all(e['source'] and e['collected_at'] for e in evidence)
    assert all(e['status'] in {'collected', 'collection_failed'} for e in evidence)


def test_disk_only_does_not_expand_to_system_health():
    assert not requests_system_health('check disk usage')
    assert requests_system_health('check the system health')


def test_context_budget_dedup_and_stale_filter():
    observation = TrustedObservation('log', 'bounded data', 'nginx', 'fresh')
    context = ContextManager(max_chars=2500).build(policy='policy', goal='goal', evidence=[observation, observation, TrustedObservation('log','old','nginx','stale')], recent_turns=[{'role':'user','content':'x'*10000}]*20)
    assert len(json.dumps(context)) <= 2500
    assert all(e['freshness'] != 'stale' for e in context.get('evidence', []))


def test_engine_terminal_persists_before_yield_and_deduplicates(monkeypatch):
    from sre_agent.engine import SREAgentEngine
    from sre_agent.events import evt_completed
    engine = SREAgentEngine(session_id='fixture')
    lifecycle = SimpleNamespace(run=SimpleNamespace(pk='run', checkpoint_version=0), atransition=AsyncMock())
    engine._lifecycle = lifecycle
    async def internal(*args, **kwargs):
        yield evt_completed('done')
        yield evt_completed('duplicate')
    monkeypatch.setattr(engine, '_run_internal', internal)
    monkeypatch.setattr(engine, '_log_event', AsyncMock())
    monkeypatch.setattr(engine, '_update_last_message_metadata', AsyncMock())
    async def execute():
        events = []
        async for event in engine.run('fixture'):
            assert lifecycle.atransition.await_count == 1
            events.append(event.to_dict())
        return events
    events = asyncio.run(execute())
    assert len(events) == 1
    assert events[0]['run_id'] == 'run'
    assert events[0]['event_id'] == 'run:terminal'


def test_abandoned_run_watchdog_is_terminal_not_reexecution(run_tables):
    from datetime import timedelta
    from django.utils import timezone
    from sre_agent.canonical_lifecycle import expire_abandoned_runs
    session = ChatSession.objects.create(title='abandoned')
    lifecycle = DurableAgentLifecycle(session_id=session.pk, goal='nginx', user_id='7')
    run = lifecycle.open()
    # Abandoned means "stopped moving", so both stamps go back: the run records
    # a transition for every real step, and a run that is merely old is still
    # alive. See the regression test below for exactly that case.
    stale = timezone.now() - timedelta(seconds=340)
    AgentRun.objects.filter(pk=run.pk).update(created_at=stale, updated_at=stale)
    assert expire_abandoned_runs(session.pk, '7') == 1
    run.refresh_from_db()
    assert run.status == 'failed'
    assert run.transitions.count() == 1
    assert expire_abandoned_runs(session.pk, '7') == 0


def test_running_run_is_not_failed_just_for_being_old(run_tables):
    """A long investigation that keeps progressing must survive the watchdog.

    The operator reported a still-running nginx investigation being marked
    failed after they returned to the chat: the watchdog judged it by age, so
    every investigation longer than the budget was reported as broken.
    """
    from datetime import timedelta
    from django.utils import timezone
    from sre_agent.canonical_lifecycle import expire_abandoned_runs
    session = ChatSession.objects.create(title='long but progressing')
    lifecycle = DurableAgentLifecycle(session_id=session.pk, goal='nginx', user_id='7')
    run = lifecycle.open()
    # Older than the budget, but it recorded activity a moment ago.
    AgentRun.objects.filter(pk=run.pk).update(
        created_at=timezone.now() - timedelta(seconds=900),
        updated_at=timezone.now() - timedelta(seconds=5),
    )
    assert expire_abandoned_runs(session.pk, '7') == 0
    run.refresh_from_db()
    assert run.status not in ('failed', 'expired')


def test_cancellation_propagates_and_persists(monkeypatch):
    from sre_agent.engine import SREAgentEngine
    engine = SREAgentEngine(session_id='fixture')
    lifecycle = SimpleNamespace(atransition=AsyncMock())
    engine._lifecycle = lifecycle
    async def internal(*args, **kwargs):
        raise asyncio.CancelledError()
        yield
    monkeypatch.setattr(engine, '_run_internal', internal)
    async def execute():
        with pytest.raises(asyncio.CancelledError):
            async for _ in engine.run('fixture'):
                pytest.fail('cancelled run emitted completion')
    asyncio.run(execute())
    lifecycle.atransition.assert_awaited_once_with('finalization', 'cancelled', 'cancelled', {})


def test_error_cannot_be_followed_by_success(monkeypatch):
    from sre_agent.engine import SREAgentEngine
    from sre_agent.events import evt_error, evt_completed
    engine = SREAgentEngine(session_id='fixture')
    async def internal(*args, **kwargs):
        yield evt_error('failure')
        yield evt_completed('incorrect success')
    monkeypatch.setattr(engine, '_run_internal', internal)
    monkeypatch.setattr(engine, '_log_event', AsyncMock())
    monkeypatch.setattr(engine, '_update_last_message_metadata', AsyncMock())
    async def execute():
        return [event.type.value async for event in engine.run('fixture')]
    assert asyncio.run(execute()) == ['error']


def test_single_agent_only_completes_through_finish_task(monkeypatch):
    from langchain_core.messages import AIMessage
    from langchain_core.tools import tool
    from sre_agent.react_engine import ReactEngine
    from sre_agent.tools.registry import ToolRegistry

    @tool
    def inspect_fixture() -> str:
        """Collect deterministic fixture evidence."""
        return "fixture is verified"

    class FakeModel:
        calls = 0

        def bind_tools(self, *args, **kwargs):
            return self

        async def ainvoke(self, history):
            self.calls += 1
            if self.calls == 1:
                return AIMessage(content="", tool_calls=[{
                    "name": "inspect_fixture", "args": {},
                    "id": "inspect-1", "type": "tool_call",
                }])
            return AIMessage(content="", tool_calls=[{
                "name": "finish_task", "args": {"summary": "verified"},
                "id": "finish-1", "type": "tool_call",
            }])

    monkeypatch.setattr(ToolRegistry, "get_metadata", lambda self, name: object())
    engine = ReactEngine(FakeModel(), [inspect_fixture], "system", "session", mode="autonomous_single")

    async def execute():
        return [event.type.value async for event in engine.astream({"goal": "check", "messages": []})]

    events = asyncio.run(execute())
    assert engine.completed is True
    assert engine.outcome == "completed"
    assert engine.evidence_count == 1
    assert "error" not in events


def test_single_agent_provider_failure_remains_incomplete(monkeypatch):
    from sre_agent.react_engine import ReactEngine
    from sre_agent import provider_runtime

    class FakeModel:
        def bind_tools(self, *args, **kwargs):
            return self

    async def fail(call):
        raise RuntimeError("rate limit")

    monkeypatch.setattr(provider_runtime, "invoke_with_retry", fail)
    engine = ReactEngine(FakeModel(), [], "system", "session", mode="autonomous_single")

    async def execute():
        return [event.type.value async for event in engine.astream({"goal": "check", "messages": []})]

    events = asyncio.run(execute())
    assert engine.completed is False
    assert engine.outcome == "failed"
    assert "error" in events


def test_guided_partial_report_does_not_complete_or_relabel_tasks():
    from sre_agent.controller import AutonomousController

    controller = AutonomousController.__new__(AutonomousController)
    controller._robust_json_parse = lambda *args, **kwargs: {
        "artifact_name": "report.md", "report_content": "Partial evidence only."
    }
    task = {"id": "inspect", "description": "Inspect service", "status": "pending", "evidence": []}
    result = controller.final_response_node({
        "goal": "check service", "plan": {"completed": False, "tasks": [task], "global_confidence": 0.9},
        "findings": {"findings": []}, "messages": [],
    })
    assert result["is_completed"] is False
    assert result["is_verified"] is False
    assert task["status"] == "pending"


def test_durable_tasks_require_evidence_before_done(run_tables):
    session = ChatSession.objects.create(title='guided')
    lifecycle = DurableAgentLifecycle(session_id=session.pk, goal='nginx')
    lifecycle.open()
    lifecycle.record_plan({'tasks': [{'id': 'inspect', 'description': 'Inspect nginx', 'status': 'completed'}]})
    assert lifecycle.run.tasks.get(task_key='inspect').status == 'verifying'
    lifecycle.record_plan({'tasks': [{'id': 'inspect', 'description': 'Inspect nginx', 'status': 'completed', 'evidence': [{'source': 'service_manager', 'state': 'active'}]}]})
    assert lifecycle.run.tasks.get(task_key='inspect').status == 'done'


@pytest.mark.parametrize('message', ['401 unauthorized', '402 insufficient balance'])
def test_controller_does_not_convert_provider_failure_to_success(message):
    from sre_agent.controller import AutonomousController
    from unittest.mock import Mock
    controller = AutonomousController.__new__(AutonomousController)
    controller.llm = Mock()
    caller = controller.llm.with_config.return_value.invoke
    caller.side_effect = RuntimeError(message)
    with pytest.raises(RuntimeError):
        controller._robust_json_parse('fixture', [], fallback_response={'success': True})
    assert caller.call_count == 1


def test_canonical_mutation_claims_and_releases_durable_lease(run_tables):
    from sre_agent.mutation_scope import active_run, mutation_scope
    session = ChatSession.objects.create(title='mutate')
    run = DurableAgentLifecycle(session_id=session.pk, goal='restart nginx').open()
    token = active_run.set(run)
    meta = SimpleNamespace(name='service_manager', risk_level=3, required_permission='sudo')
    try:
        with mutation_scope(meta, {'action': 'restart', 'service_name': 'nginx'}):
            assert AgentResourceLock.objects.get(run=run).resource_key == 'canonical:mutations'
        assert not AgentResourceLock.objects.exists()
        with mutation_scope(meta, {'action': 'status', 'service_name': 'nginx'}):
            assert not AgentResourceLock.objects.exists()
    finally:
        active_run.reset(token)


def test_same_run_workers_cannot_steal_live_lease(run_tables):
    from sre_agent.resource_locks import ResourceLockManager, ResourceConflict
    session = ChatSession.objects.create(title='workers')
    run = DurableAgentLifecycle(session_id=session.pk, goal='restart nginx').open()
    manager = ResourceLockManager()
    lease = manager.claim_db(run=run, task_key='one', resource='nginx')
    with pytest.raises(ResourceConflict):
        manager.claim_db(run=run, task_key='two', resource='nginx')
    manager.release_db(lease.lease_token)


def test_canonical_mutation_releases_lease_on_error(run_tables):
    from sre_agent.mutation_scope import active_run, mutation_scope
    session = ChatSession.objects.create(title='failure')
    run = DurableAgentLifecycle(session_id=session.pk, goal='restart nginx').open()
    token = active_run.set(run)
    try:
        with pytest.raises(RuntimeError), mutation_scope(SimpleNamespace(name='service_manager', risk_level=3, required_permission=''), {'action': 'restart', 'service_name': 'nginx'}):
            raise RuntimeError('fixture')
        assert not AgentResourceLock.objects.exists()
    finally:
        active_run.reset(token)


def test_public_events_exclude_reasoning_secrets_and_sensitive_tool_args():
    from sre_agent.events import AgentEvent, AgentEventType
    event = AgentEvent(AgentEventType.MESSAGE_CHUNK, '<think>private reasoning</think>Result api_key=secret123 Authorization: Bearer token123')
    payload = event.to_dict()
    assert 'private reasoning' not in payload['content']
    assert 'secret123' not in payload['content']
    assert 'token123' not in payload['content']
    # Raw args never leave the event; secret *values* in the result are
    # masked by public_value/public_text (that is what can be checked with
    # real markers), while ordinary output text is streamed to the UI.
    event = AgentEvent(
        AgentEventType.TOOL_END,
        'Result: ok\nunexpected api_key=secret123\nAuthorization: Bearer token123',
        {'args': {'password': 'unsafe'}, 'result': 'ok api_key=secret123', 'tool': 'fixture'},
    )
    payload = event.to_dict()
    dumped = json.dumps(payload)
    assert 'unsafe' not in dumped          # raw args were dropped
    assert 'secret123' not in dumped       # secret value masked
    assert 'token123' not in dumped        # bearer token masked
    assert payload['result'].startswith('ok') or payload['content'].startswith('ok')


def test_multi_duplicate_tasks_share_real_evidence(monkeypatch):
    from sre_agent.parallel import ParallelExecutor, TaskResult
    executor = ParallelExecutor()
    calls = []
    async def execute(task, *args):
        calls.append(task['id'])
        await asyncio.sleep(0)
        return TaskResult(task['id'], 'fixture', {}, 'verified evidence', 0, 0.01, 'approved')
    monkeypatch.setattr(executor, '_execute_single', execute)
    results = asyncio.run(executor.execute_dag([{'id':'one','tool':'fixture'}, {'id':'two','tool':'fixture'}], {}))
    assert calls == ['one']
    assert [r.output for r in results] == ['verified evidence', 'verified evidence']
    assert [r.task_id for r in results] == ['one', 'two']


def test_multi_failed_dependency_prevents_side_effect(monkeypatch):
    from sre_agent.parallel import ParallelExecutor, TaskResult
    executor = ParallelExecutor()
    calls = []
    async def execute(task, *args):
        calls.append(task['id'])
        return TaskResult(task['id'], 'fixture', {}, 'failed', 1, 0, 'error')
    monkeypatch.setattr(executor, '_execute_single', execute)
    results = asyncio.run(executor.execute_dag([{'id':'one','tool':'inspect'}, {'id':'two','tool':'mutate','depends_on':['one']}], {}))
    assert calls == ['one']
    assert results[1].safety_verdict == 'blocked'


def test_cancellation_request_is_owner_scoped_and_terminal_safe(run_tables):
    from sre_agent.canonical_lifecycle import request_run_cancellation
    session = ChatSession.objects.create(title='cancel')
    lifecycle = DurableAgentLifecycle(session_id=session.pk, user_id='7', goal='inspect')
    lifecycle.open()
    assert not request_run_cancellation(session.pk, '8')
    assert request_run_cancellation(session.pk, '7')
    lifecycle.run.refresh_from_db()
    assert lifecycle.run.state['cancellation_requested'] is True
    lifecycle.transition('finalization', 'cancelled', 'cancelled')
    assert not request_run_cancellation(session.pk, '7')


@pytest.mark.parametrize('previous,current,changed', [
    ('nginx investigation', 'related logs', False),
    ('nginx investigation', 'what is the root cause?', False),
    ('nginx investigation', 'continue with PostgreSQL', True),
    ('postgres investigation', 'PostgreSQL logs', False),
])
def test_context_target_continuity(previous, current, changed):
    from sre_agent.canonical_lifecycle import investigation_target_changed
    assert investigation_target_changed(previous, current) is changed


def test_real_file_tool_writes_and_verifies(tmp_path):
    from sre_agent.tools.filesystem import write_file
    target = tmp_path / 'safe.txt'
    callable_ = write_file.func
    while hasattr(callable_, '__wrapped__'):
        callable_ = callable_.__wrapped__
    result = callable_(str(target), 'verified fixture')
    assert 'verified' in result
    assert target.read_text() == 'verified fixture'


@pytest.mark.parametrize('source', ['journal', 'nginx', 'postgresql', '/var/log/nginx/error.log'])
def test_readonly_logs_do_not_require_mutation_approval(source):
    meta = SimpleNamespace(name='log_reader', risk_level=3, required_permission='sudo')
    assert evaluate(meta, {'source': source})[0] == 'approved'


@pytest.mark.parametrize('source', ['/etc/shadow', 'nginx;id', '$(id)', '--help'])
def test_log_sources_are_scoped(source):
    meta = SimpleNamespace(name='log_reader', risk_level=0, required_permission='')
    assert evaluate(meta, {'source': source})[0] == 'blocked'


def test_presence_payload_lists_active_and_latest(run_tables):
    from chatbot.views import build_presence_payload
    session = ChatSession.objects.create(title='presence')
    live = AgentRun.objects.create(session=session, user_id='7', goal='live',
                                   status='running', idempotency_key='t-live')
    old = AgentRun.objects.create(session=session, user_id='7', goal='old',
                                  status='completed', idempotency_key='t-old')
    other = AgentRun.objects.create(
        session=ChatSession.objects.create(title='other'),
        user_id='7', goal='theirs', status='failed', idempotency_key='t-other')
    from django.utils import timezone
    AgentRun.objects.filter(pk=live.pk).update(updated_at=timezone.now())
    payload = build_presence_payload('7')
    assert {r['status'] for r in payload['runs']} == {'running'}
    by_session = {r['session_id']: r['status'] for r in payload['latest']}
    assert by_session[str(session.pk)] == 'running'
    assert by_session[str(other.session_id)] == 'failed'
    assert all('goal' in r and 'updated_at' in r for r in payload['runs'])


def test_presence_group_name_is_safe():
    from sre_agent.canonical_lifecycle import presence_group
    assert presence_group('7') == 'presence-u-7'
    assert presence_group('a/b.c@d') == 'presence-u-a_b_c_d'
    assert presence_group('') == 'presence-u-anonymous'
