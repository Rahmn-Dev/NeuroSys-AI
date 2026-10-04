from sre_agent.discovery import ToolDiscoveryAgent

def test_indonesian_server_health_baseline_is_broad_read_only():
    result = ToolDiscoveryAgent().discover(
        'cek kondisi server saya, termasuk resource utama dan service yang bermasalah'
    )
    assert result.intent == 'system_health'
    assert {'system_info', 'service_manager'}.issubset(set(result.tool_names))
    assert 'terminal_execute' in result.tool_names
    assert not {'write_file', 'edit_file', 'spawn_subagent', 'safe_execute'} & set(result.tool_names)
    service = next(tool for tool in result.tools if tool.name == 'service_manager')
    import inspect
    source = inspect.getsource(getattr(service.func, '__wrapped__', service.func))
    assert 'systemctl list-units --failed' in source


def test_guided_mode_routes_to_single_agent_core_toolkit():
    # Engine routes BOTH guided and autonomous_single through
    # discover_single_agent_tools (engine.py); the old terminal-only guided
    # profile was dead code and has been removed.
    discovery = ToolDiscoveryAgent()
    assert not hasattr(discovery, 'discover_guided_tools')
    result = discovery.discover_single_agent_tools('check nginx is down or active')

    assert result.intent == 'single_agent_core'
    assert set(result.tool_names) == {
        'get_current_directory', 'read_file', 'write_file', 'edit_file',
        'spawn_subagent', 'terminal_execute',
    }


def test_single_agent_gets_the_requested_core_tools_without_keyword_routing():
    result = ToolDiscoveryAgent().discover_single_agent_tools('check nginx is down or active')

    assert result.intent == 'single_agent_core'
    assert set(result.tool_names) == {
        'get_current_directory', 'read_file', 'write_file', 'edit_file',
        'spawn_subagent', 'terminal_execute',
    }


def test_planner_assigns_unique_team_roles():
    import json
    from types import SimpleNamespace
    from sre_agent.controller import AutonomousController

    payload = {
        "intent": "DEBUG_TASK", "complexity": "MEDIUM",
        "thinking": "t", "hypothesis": "h",
        "workers": [
            {"id": "A", "role": "Log Hound", "goal": "check app logs",
             "expected_diagnostic_domains": ["logs"], "depends_on": [], "priority": "high"},
            {"id": "B", "role": "Log Hound", "goal": "check other logs",
             "expected_diagnostic_domains": ["logs2"], "depends_on": [], "priority": "high"},
        ],
    }

    class FakeLLM:
        def with_config(self, *a, **k):
            return self

        def invoke(self, messages):
            return SimpleNamespace(content=json.dumps(payload))

    controller = AutonomousController(FakeLLM(), [], "sys")
    out = controller.planner_node({
        "goal": "nginx down", "messages": [], "plan": {},
        "iteration": 0, "terminal_cwd": "", "active_workspace": "",
    })
    workers = out["plan"]["workers"]
    assert workers[0]["role"] == "Log Hound"
    assert workers[1]["role"] != "Log Hound"
    assert workers[1]["role"].startswith("Worker ")
    assert all("role" in t for t in out["plan"]["tasks"])
