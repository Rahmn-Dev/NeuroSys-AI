import pytest
from sre_agent.provider_runtime import ProviderPolicy, invoke_provider_chain


@pytest.mark.asyncio
async def test_provider_chain_falls_back_after_429():
    seen = []
    async def groq():
        seen.append("groq"); raise RuntimeError("429 rate limit")
    async def local():
        seen.append("local"); return {"ok": True}
    provider, result = await invoke_provider_chain({"groq": groq, "local": local}, ProviderPolicy(("groq", "local"), max_attempts=1))
    assert (provider, result, seen) == ("local", {"ok": True}, ["groq", "local"])


@pytest.mark.asyncio
async def test_provider_chain_does_not_fallback_on_402():
    async def groq(): raise RuntimeError("402 insufficient balance")
    async def local(): return "must not run"
    with pytest.raises(RuntimeError):
        await invoke_provider_chain({"groq": groq, "local": local}, ProviderPolicy(("groq", "local"), max_attempts=1))
