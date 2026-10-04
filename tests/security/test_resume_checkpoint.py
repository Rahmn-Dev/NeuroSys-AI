from django.db import connection
from chatbot.models import WorkspaceInfo, ChatSession, AgentRun, AgentTransition, AgentTask
from sre_agent.canonical_lifecycle import DurableAgentLifecycle


def test_checkpoint_resume_returns_same_run():
    with connection.schema_editor() as editor:
        for model in (WorkspaceInfo, ChatSession, AgentRun, AgentTransition, AgentTask):
            try:
                editor.create_model(model)
            except Exception:
                pass
    try:
        session = ChatSession.objects.create(title="resume")
        lifecycle = DurableAgentLifecycle(session_id=str(session.id), goal="resume task", idempotency_key="resume-key")
        lifecycle.open()
        lifecycle.add_task("t1", "write and verify")
        try:
            lifecycle.complete_task("t1", {"verified": False, "evidence": {}})
            assert False, "unverified mutation was accepted"
        except ValueError:
            pass
        lifecycle.complete_task("t1", {"verified": True, "verifier": "fixture", "evidence": {"readback": True}})
        lifecycle.transition("planning", "running", "checkpoint", {"todo": "inspect"})
        resumed = DurableAgentLifecycle(session_id=str(session.id), goal="resume task", idempotency_key="resume-key")
        assert resumed.resume().id == lifecycle.run.id
        assert resumed.run.checkpoint_version == 2
        assert resumed.run.current_node == "planning"
    finally:
        for model in (AgentTask, AgentTransition, AgentRun, ChatSession, WorkspaceInfo):
            try:
                editor.delete_model(model)
            except Exception:
                pass
