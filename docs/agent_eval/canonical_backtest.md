# Canonical lifecycle controlled backtest

Date: 2026-09-27  
Branch: `security/agent-hardening`  
Provider mode: deterministic mocks only; no live Groq/Mistral/network actions.

## Scenario table

| ID | Mode | Provider | Scenario | Result | Evidence |
|---|---|---|---|---|---|
| CTX-001 | all | mock | bounded context and untrusted provenance | PASS | `tests/security/test_canonical_lifecycle.py` |
| PROV-001 | provider | mock-429 | transient retry then success | PASS | `test_provider_runtime.py`, `test_provider_chain.py` |
| PROV-002 | provider | mock-402 | quota error does not fallback/retry | PASS | `test_provider_runtime.py`, `test_provider_chain.py` |
| LOCK-001 | multi-agent | local | two workers share resource serially | PASS | `test_locks_verification.py` |
| LOCK-002 | multi-agent | local | duplicate idempotency key has no second side effect | PASS | `test_locks_verification.py` |
| VERIFY-001 | guided | local fixture | file readback/hash and config syntax | PASS | `test_locks_verification.py` |
| VERIFY-002 | guided | local fixture | failed verifier cannot complete mutation | PASS | `test_resume_checkpoint.py` |
| RESUME-001 | guided | sqlite test DB | checkpoint lookup after simulated reconnect | PASS | `test_resume_checkpoint.py` |
| SEC-001..SEC-093 | all | mocked/local | existing injection, approval, audit, EVE and safety suite | PASS | `tests/security/` |

Totals for this controlled run: **98 PASS, 0 FAIL, 0 ERROR, 0 SKIP**.

The executable compact manifest runner is:

```text
PYTHONPATH=ai_config pipenv run python tests/security/run_backtest.py
totals: PASS=5, FAIL=0, ERROR=0, SKIP=0
```

It records scenario ID, goal, mode, provider, expected result, lifecycle transitions, tools, security, evidence, final status, latency, attempts, fallback, and reason as JSON. The five scenarios are CTX-001, SEC-001, PROV-001, VERIFY-001, and LOCK-001. The larger 98-test total remains the authoritative regression count.

Exact commands:

```text
PYTHONPATH=ai_config pipenv run pytest tests/security -q --disable-warnings --maxfail=1
98 passed in 0.52s

PYTHONPATH=ai_config DJANGO_SETTINGS_MODULE=ai_config.settings \
  pipenv run python ai_config/manage.py makemigrations chatbot --check --dry-run
No changes detected in app 'chatbot'
```

## What the backtest proves

The tests prove bounded context construction, observation provenance markers, transient-only provider retry, policy-controlled 429 fallback, non-retryable 402 handling, in-process resource serialization, duplicate suppression, file/config verification, durable checkpoint lookup, and rejection of unverified task completion. Existing security tests still pass after adding the new models and fixtures.

## What it does not prove

It does not prove live Groq quality, real provider quota behavior, remote SSH correctness, Suricata sensor coverage, process-crash recovery in a deployed worker, or database locking across multiple OS processes. The durable lock model is present (`AgentResourceLock`), while the current worker integration still needs to claim/release leases around every real mutation. UI task transition rendering and legacy SmartAgent/MCP route migration remain incomplete.

## Review and merge recommendation

Review the migration and lifecycle transition semantics first. Merge should remain blocked until legacy execution routes are routed through the same registry guard, durable resource leases are used by the actual parallel worker, provider fallback emits a user-visible event with checkpoint evidence, and a deployment-level reconnect/process-restart test is added. No commit or merge was created by this work.
