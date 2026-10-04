"""One-command deterministic lifecycle backtest manifest runner.

Usage: PYTHONPATH=ai_config pipenv run python tests/security/run_backtest.py
"""
import asyncio
import json
import tempfile
import time
from pathlib import Path

from sre_agent.canonical_lifecycle import ContextManager, normalize_provider_error
from sre_agent.provider_runtime import ProviderPolicy, invoke_provider_chain
from sre_agent.resource_locks import ResourceLockManager
from sre_agent.verification import verify_file_readback


async def main():
    results = []
    def record(scenario, goal, mode, provider, expected, fn):
        start = time.perf_counter()
        try:
            fn()
            status, reason = "PASS", "deterministic fixture completed"
        except AssertionError as exc:
            status, reason = "FAIL", str(exc)
        except Exception as exc:
            status, reason = "ERROR", type(exc).__name__
        results.append({"scenario_id": scenario, "goal": goal, "mode": mode,
                        "provider": provider, "expected": expected,
                        "transitions": ["running", "verifying", "done" if status == "PASS" else "failed"],
                        "tools": [], "security": [], "evidence": [],
                        "final_status": status, "latency_ms": round((time.perf_counter()-start)*1000, 3),
                        "attempts": 1, "fallback": False, "result": status, "reason": reason})
    record("CTX-001", "bounded trusted context", "guided", "mock", "PASS",
           lambda: ContextManager(max_chars=500).build(policy="stop", goal="inspect"))
    record("SEC-001", "normalize provider 402", "guided", "mock-402", "PASS",
           lambda: (_ for _ in ()).throw(AssertionError()) if normalize_provider_error(RuntimeError("402 insufficient balance"))["retryable"] else None)
    async def fallback_case():
        async def first(): raise RuntimeError("429 rate limit")
        async def second(): return "ok"
        assert (await invoke_provider_chain({"first": first, "second": second}, ProviderPolicy(("first", "second"), max_attempts=1)))[0] == "second"
    start = time.perf_counter()
    try:
        await fallback_case(); status, reason = "PASS", "429 fallback preserved contract"
    except AssertionError as exc:
        status, reason = "FAIL", str(exc)
    except Exception as exc:
        status, reason = "ERROR", type(exc).__name__
    results.append({"scenario_id": "PROV-001", "goal": "provider 429 fallback", "mode": "guided", "provider": "mock-429",
                    "expected": "PASS", "transitions": ["running", "provider_fallback", "done"], "tools": [], "security": [], "evidence": [],
                    "final_status": status, "latency_ms": round((time.perf_counter()-start)*1000, 3), "attempts": 2,
                    "fallback": True, "result": status, "reason": reason})
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "fixture.txt"; path.write_text("verified")
        record("VERIFY-001", "file mutation readback", "guided", "local", "PASS",
               lambda: (_ for _ in ()).throw(AssertionError()) if not verify_file_readback(str(path), expected_content="verified").verified else None)
    lock = ResourceLockManager()
    record("LOCK-001", "duplicate mutation idempotency", "multi-agent", "local", "PASS",
           lambda: (_ for _ in ()).throw(AssertionError()) if not (lock.mark_once("same") and not lock.mark_once("same")) else None)
    print(json.dumps({"generated_at": time.time(), "totals": {
        "PASS": sum(r["result"] == "PASS" for r in results), "FAIL": sum(r["result"] == "FAIL" for r in results), "ERROR": sum(r["result"] == "ERROR" for r in results), "SKIP": sum(r["result"] == "SKIP" for r in results)},
        "scenarios": results}, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
