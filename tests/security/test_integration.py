"""Integration with real LangChain tools and Django ORM; external side effects mocked."""
import asyncio
import json
from types import SimpleNamespace
from unittest.mock import Mock
import django
from django.conf import settings
if not settings.configured:
    settings.configure(
        SECRET_KEY="test-only-not-a-deployment-secret",
        INSTALLED_APPS=["django.contrib.auth", "django.contrib.contenttypes", "chatbot"],
        DATABASES={"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}},
        USE_TZ=True,
    )
    django.setup()
import pytest
from django.db import connection
from django.core.management import get_commands
from chatbot.models import SuricataLog
from ai_config.security_service import SecurityService
from management.commands.start_security_monitor import Command
from sre_agent.tools.registry import ToolRegistry

@pytest.mark.parametrize("method", ["block_ip_iptables", "unblock_ip_iptables"])
def test_attack_firewall_ip_injection_never_launches(method, monkeypatch):
    run = Mock()
    monkeypatch.setattr("ai_config.security_service.subprocess.run", run)
    assert getattr(SecurityService, method)("192.0.2.1; touch /tmp/owned") is False
    run.assert_not_called()

@pytest.mark.parametrize("method", ["block_ip_iptables", "unblock_ip_iptables"])
def test_benign_firewall_argv(method, monkeypatch):
    run = Mock(return_value=SimpleNamespace(returncode=0))
    monkeypatch.setattr("ai_config.security_service.subprocess.run", run)
    assert getattr(SecurityService, method)("192.0.2.1") is True
    args, kwargs = run.call_args
    assert isinstance(args[0], list) and "192.0.2.1" in args[0]
    assert not kwargs.get("shell", False) and kwargs["timeout"] == 10

def test_attack_alert_does_not_authorize_auto_block(monkeypatch):
    block = Mock()
    monkeypatch.setattr(SecurityService, "block_ip_iptables", block)
    assert SecurityService.auto_block_suspicious_ip(SimpleNamespace(source_ip="192.0.2.1")) is False
    block.assert_not_called()

def test_eve_command_discovery_and_database():
    assert get_commands()["start_security_monitor"] == "chatbot"
    with connection.schema_editor() as editor:
        editor.create_model(SuricataLog)
    try:
        command = Command()
        command.process_suricata_log(json.dumps({
            "event_type": "alert", "timestamp": "2026-09-25T00:00:00Z",
            "src_ip": "192.0.2.1", "dest_ip": "192.0.2.2", "proto": "TCP",
            "alert": {"signature": "test fixture only", "severity": 1},
        }))
        command.process_suricata_log('{"event_type":"alert", "alert":[]}')
        assert SuricataLog.objects.count() == 1
        entry = SuricataLog.objects.get()
        assert entry.severity == "High" and entry.priority == 1
    finally:
        with connection.schema_editor() as editor:
            editor.delete_model(SuricataLog)

def test_attack_real_terminal_tool_blocks_before_popen(monkeypatch):
    from sre_agent.tools.terminal import register_terminal_tools, terminal_execute
    ToolRegistry().reset()
    register_terminal_tools()
    popen = Mock()
    monkeypatch.setattr("sre_agent.tools.terminal.subprocess.Popen", popen)
    with pytest.raises(PermissionError):
        terminal_execute.invoke({"command": "sudo id"})
    popen.assert_not_called()
    ToolRegistry().reset()

def test_attack_real_write_tool_does_not_create_file(tmp_path):
    from sre_agent.tools.filesystem import register_filesystem_tools, write_file
    ToolRegistry().reset()
    register_filesystem_tools()
    target = tmp_path / "must-not-exist"
    with pytest.raises(PermissionError):
        write_file.invoke({"path": str(target), "content": "attacker payload"})
    assert not target.exists()
    ToolRegistry().reset()
