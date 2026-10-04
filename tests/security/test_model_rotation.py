import pytest
from types import SimpleNamespace

from sre_agent.provider_runtime import RoundRobinChatModel, is_model_failover_error
from sre_agent.engine import SREAgentEngine


class FakeModel:
    def __init__(self, result=None, error=None, chunks=None):
        self.result, self.error, self.chunks = result, error, chunks or []
        self.calls = 0

    def invoke(self, value, *args, **kwargs):
        self.calls += 1
        if self.error:
            raise self.error
        return self.result

    async def ainvoke(self, value, *args, **kwargs):
        return self.invoke(value, *args, **kwargs)

    async def astream(self, value, *args, **kwargs):
        self.calls += 1
        for chunk in self.chunks:
            yield chunk
        if self.error:
            raise self.error

    def bind_tools(self, tools, **kwargs):
        return self

    def with_config(self, config):
        return self


@pytest.mark.asyncio
async def test_quota_failure_rotates_to_next_compatible_model():
    first = FakeModel(error=RuntimeError("402 insufficient balance"))
    second = FakeModel(result="ok")
    switches = []
    pool = RoundRobinChatModel([("model-a", first), ("model-b", second)], on_switch=switches.append)
    assert await pool.ainvoke("bounded prompt") == "ok"
    assert pool.active_label == "model-b"
    assert switches == [{"from": "model-a", "to": "model-b", "reason": "quota"}]


@pytest.mark.asyncio
async def test_application_error_does_not_rotate_models():
    first = FakeModel(error=ValueError("invalid task state"))
    second = FakeModel(result="must not run")
    pool = RoundRobinChatModel([("model-a", first), ("model-b", second)])
    with pytest.raises(ValueError):
        await pool.ainvoke("prompt")
    assert second.calls == 0


@pytest.mark.asyncio
async def test_stream_is_never_spliced_after_content_was_emitted():
    first = FakeModel(error=RuntimeError("provider unavailable"), chunks=["partial"])
    second = FakeModel(chunks=["replacement"])
    pool = RoundRobinChatModel([("model-a", first), ("model-b", second)])
    received = []
    with pytest.raises(RuntimeError):
        async for chunk in pool.astream("prompt"):
            received.append(chunk)
    assert received == ["partial"]
    assert second.calls == 0


def test_auth_and_tool_errors_are_not_failover_conditions():
    assert not is_model_failover_error(RuntimeError("401 unauthorized api key"))
    assert not is_model_failover_error(RuntimeError("tool execution failed"))
    assert is_model_failover_error(RuntimeError("429 rate limit"))
    assert is_model_failover_error(RuntimeError("selected model does not support tools"))


def test_router_wrapped_model_free_tier_restriction_rotates():
    error = RuntimeError(
        'HTTP 400: [403] {"type":"FreeTierError","message":'
        '"OpenCode free tier can only be used from within OpenCode"}'
    )
    assert is_model_failover_error(error)


@pytest.mark.asyncio
async def test_wrapped_model_restriction_continues_to_next_alias():
    restricted = FakeModel(error=RuntimeError("400 [403] FreeTierError: only be used from within OpenCode"))
    healthy = FakeModel(result="ok")
    switches = []
    pool = RoundRobinChatModel([("OpenCode", restricted), ("Groq", healthy)], on_switch=switches.append)
    assert await pool.ainvoke("prompt") == "ok"
    assert switches == [{"from": "OpenCode", "to": "Groq", "reason": "model_restricted"}]


def test_router_alias_labels_share_transport_without_crossing_to_ollama():
    opencode = SimpleNamespace(provider="OpenCode", base_url=None, api_key=None)
    nvidia_alias = SimpleNamespace(provider="NVIDIA", base_url=None, api_key=None)
    ollama = SimpleNamespace(provider="ollama", base_url=None, api_key=None)
    assert SREAgentEngine._model_transport_key(opencode) == SREAgentEngine._model_transport_key(nvidia_alias)
    assert SREAgentEngine._model_transport_key(opencode) != SREAgentEngine._model_transport_key(ollama)
