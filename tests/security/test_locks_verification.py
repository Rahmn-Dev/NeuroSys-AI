import asyncio
import json
import pytest

from sre_agent.resource_locks import ResourceConflict, ResourceLockManager
from sre_agent.verification import verify_file_readback, verify_config_fixture, require_verification


@pytest.mark.asyncio
async def test_same_resource_is_serialized_and_duplicate_is_skipped():
    manager = ResourceLockManager(max_concurrency=2)
    active = 0
    peak = 0
    async def worker():
        nonlocal active, peak
        async with manager.acquire("file:/tmp/test"):
            active += 1; peak = max(peak, active)
            await asyncio.sleep(0)
            active -= 1
    await asyncio.gather(worker(), worker())
    assert peak == 1
    key = manager.idempotency_key("file:/tmp/test", "write", {"x": 1})
    assert manager.mark_once(key) is True
    assert manager.mark_once(key) is False


def test_verification_requires_postcondition(tmp_path):
    target = tmp_path / "config.json"
    target.write_text(json.dumps({"enabled": True}))
    result = verify_file_readback(str(target), expected_content=json.dumps({"enabled": True}))
    assert require_verification(result)["verifier"] == "file_readback"
    assert verify_config_fixture(str(target)).verified
    assert not verify_config_fixture(str(target), parser=lambda _: (_ for _ in ()).throw(ValueError("bad"))).verified
