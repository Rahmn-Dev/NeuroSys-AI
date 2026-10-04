from langchain_core.messages import HumanMessage, SystemMessage

from sre_agent.anthropic_caching import build_caching_anthropic, mark_system_blocks


def _sys(text):
    return SystemMessage(content=text)


def test_mark_system_blocks_marks_big_prefix_only():
    small = _sys("hi")
    big = _sys("x" * 9000)
    user = HumanMessage(content="hello")
    out = mark_system_blocks([small, big, user, "raw-string", None])
    assert out[0] is small
    assert out[2] is user
    assert out[3] == "raw-string"
    marked = out[1].content
    assert isinstance(marked, list) and marked[0]["cache_control"] == {"type": "ephemeral"}
    assert marked[0]["text"] == "x" * 9000


def test_mark_system_blocks_extends_existing_list_content():
    msg = SystemMessage(content=[{"type": "text", "text": "y" * 9000}])
    out = mark_system_blocks([msg])
    assert out[0].content[0]["cache_control"] == {"type": "ephemeral"}


def test_caching_wrapper_exposes_usage_summary():
    client = build_caching_anthropic(model="claude-haiku-4-5-20251001", api_key="dummy")
    assert client.get_usage_summary() == {
        "calls": 0, "input_tokens": 0, "output_tokens": 0,
        "cache_read": 0, "cache_write": 0,
    }
    bound = client.bind_tools([])
    assert bound.get_usage_summary()["calls"] == 0


def test_parse_narrated_tool_calls_shapes():
    from sre_agent.react_engine import parse_narrated_tool_calls
    # Exact shape from the nginx incident (array-wrapped, "parameters")
    raw = '[[{"name": "terminal_execute", "parameters": {"command": "nginx -t", "timeout": 30}}]]'
    calls = parse_narrated_tool_calls(raw)
    assert calls == [{"name": "terminal_execute", "args": {"command": "nginx -t", "timeout": 30}}]
    # Plain dict with args + surrounding prose
    raw2 = 'I will check.\n{"name": "read_file", "args": {"path": "/etc/nginx/nginx.conf"}}\nDone.'
    assert parse_narrated_tool_calls(raw2) == [
        {"name": "read_file", "args": {"path": "/etc/nginx/nginx.conf"}}]
    # No name -> ignored; garbage -> empty, never raises
    assert parse_narrated_tool_calls('{"command": "ls"}') == []
    assert parse_narrated_tool_calls('no json here') == []
    assert parse_narrated_tool_calls('{{{') == []
