import asyncio
import pytest

from sre_agent.provider_runtime import RoundRobinChatModel, invoke_sync_with_retry, invoke_with_retry


@pytest.mark.asyncio
async def test_provider_retry_is_bounded_and_transient_only():
    attempts = []
    async def call():
        attempts.append(1)
        if len(attempts) < 3:
            raise RuntimeError("HTTP 429 rate limit")
        return "ok"
    assert await invoke_with_retry(call, max_attempts=3, base_delay=0) == "ok"
    assert len(attempts) == 3


@pytest.mark.asyncio
async def test_quota_error_is_not_retried():
    attempts = []
    async def call():
        attempts.append(1)
        raise RuntimeError("HTTP 402 insufficient balance")
    with pytest.raises(RuntimeError):
        await invoke_with_retry(call, max_attempts=3, base_delay=0)
    assert len(attempts) == 1


@pytest.mark.asyncio
async def test_round_robin_fails_over_on_malformed_model_response():
    class FakeModel:
        def __init__(self, result=None, error=None):
            self.result = result
            self.error = error
            self.calls = 0

        async def ainvoke(self, _input, *args, **kwargs):
            self.calls += 1
            if self.error:
                raise self.error
            return self.result

    broken = FakeModel(error=RuntimeError("Malformed tool-call JSON"))
    healthy = FakeModel(result="ok")
    switches = []
    pool = RoundRobinChatModel(
        [("broken", broken), ("healthy", healthy)],
        start_index=0,
        on_switch=switches.append,
    )

    assert await pool.ainvoke("request") == "ok"
    assert broken.calls == 1
    assert healthy.calls == 1
    assert switches == [{"from": "broken", "to": "healthy", "reason": "malformed"}]


@pytest.mark.asyncio
async def test_round_robin_tries_cross_provider_candidates_in_order():
    class FakeModel:
        def __init__(self, error=None, result=None):
            self.error = error
            self.result = result
            self.calls = 0

        async def ainvoke(self, _input, *args, **kwargs):
            self.calls += 1
            if self.error:
                raise self.error
            return self.result

    cerebras = FakeModel(error=RuntimeError("HTTP 429 rate limit"))
    gemini = FakeModel(error=RuntimeError("Malformed tool-call JSON"))
    groq = FakeModel(result="answer")
    pool = RoundRobinChatModel([
        ("Cerebras Provider", cerebras),
        ("Gemini Provider", gemini),
        ("Groq Provider", groq),
    ])

    assert await pool.ainvoke("request") == "answer"
    assert [cerebras.calls, gemini.calls, groq.calls] == [1, 1, 1]


@pytest.mark.asyncio
async def test_exhausted_model_pool_is_not_retried_as_a_whole():
    class BrokenModel:
        def __init__(self):
            self.calls = 0

        async def ainvoke(self, _input, *args, **kwargs):
            self.calls += 1
            raise RuntimeError("Malformed provider JSON")

    models = [BrokenModel(), BrokenModel(), BrokenModel()]
    pool = RoundRobinChatModel([(f"provider-{index}", model) for index, model in enumerate(models)])

    with pytest.raises(RuntimeError, match="All 3 configured model"):
        await invoke_with_retry(lambda: pool.ainvoke("request"), max_attempts=3, base_delay=0)
    assert [model.calls for model in models] == [1, 1, 1]


def test_sync_guided_retry_does_not_repeat_exhausted_model_pool():
    class BrokenModel:
        def __init__(self):
            self.calls = 0

        def invoke(self, _input, *args, **kwargs):
            self.calls += 1
            raise RuntimeError("Malformed provider JSON")

    models = [BrokenModel(), BrokenModel()]
    pool = RoundRobinChatModel([(f"guided-provider-{index}", model) for index, model in enumerate(models)])

    with pytest.raises(RuntimeError, match="All 2 configured model"):
        invoke_sync_with_retry(lambda: pool.invoke("request"), max_attempts=3, base_delay=0)
    assert [model.calls for model in models] == [1, 1]
