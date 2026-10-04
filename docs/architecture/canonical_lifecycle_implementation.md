# Canonical lifecycle implementation

This implementation keeps the existing security boundary and adds a shared durable lifecycle for guided and ReAct adapters. It does not claim that every legacy path has been fully migrated; legacy integrations still need route-level end-to-end coverage before production use.

## Production files and schema

* `ai_config/chatbot/models.py`: `AgentRun`, `AgentTask`, and append-only `AgentTransition`. These store provider-neutral run state, task dependencies/status, budgets, evidence/artifact references, idempotency keys, and checkpoint sequence.
* `ai_config/chatbot/migrations/0022_agentrun_agenttask_agenttransition.py`: schema migration and Groq provider choice.
* `ai_config/sre_agent/canonical_lifecycle.py`: bounded `ContextManager`, provenance-tagged `TrustedObservation`, transactional lifecycle transitions, resume lookup, and normalized provider errors.
* `ai_config/sre_agent/provider_runtime.py`: transient-only bounded retry with cancellation support.
* `ai_config/sre_agent/capabilities.py`: deterministic metadata-first capability selection contract.
* `ai_config/sre_agent/engine.py`: guided path opens and checkpoints the canonical lifecycle; security/approval/error/finalization events become durable transitions.
* `ai_config/sre_agent/react_engine.py`: autonomous adapter opens the same lifecycle when Django persistence is available.
* `ai_config/sre_agent/resource_locks.py` and `parallel.py`: mutation resource serialization, duplicate idempotency, and durable lease claim/release API.
* `ai_config/sre_agent/verification.py`: file readback/hash and config syntax postcondition contracts.
* `ai_config/ai_config/consumers.py`: legacy Chat and smart-workflow routes now adapt to the guarded SRE engine; direct MCP requests are explicitly disabled and marked deprecated.

## Before and after

Before, each loop owned its own in-memory messages and task dictionaries. After, the durable run is opened at session setup, records provider/context/planning/finalization transitions, and stores bounded state references. Tool authorization remains at the guarded callable in `security_boundary.py`; model text is not an approval credential.

## Context contract

`ContextManager.build()` emits policy, goal, bounded summary/recent turns, TODO records, provenance-tagged memories/evidence, artifact references, environment, approval metadata, and remaining budgets. Evidence includes `instruction_authority: none`; only policy and the current goal are control instructions. Raw full chat history is not required by this contract.

## Provider and fallback behavior

Unknown or inactive `AIModel` selections now fail closed in `SREAgentEngine._get_llm` instead of silently selecting the first active model. `ChatGroq` remains server-side and requires a configured key. `normalize_provider_error()` categorizes auth, quota/402, rate-limit/429, transient timeout/5xx, context overflow, malformed, and generic failures. `invoke_with_retry()` retries only transient, rate-limit, and malformed failures with bounded exponential backoff. A full provider fallback policy still needs wiring to the UI-visible `provider_fallback` event and a live provider test.

## Verification and multi-agent limits

The existing guarded callable, approval, and evidence paths remain authoritative. The new task graph supplies durable statuses and dependencies, but resource leases and mutation serialization are not yet wired into `ParallelExecutor`; that is a remaining production hardening item. ReAct remains an adapter and must not be treated as proof that all legacy SmartAgent/MCP routes share this lifecycle.

## Reproducible checks

```text
PYTHONPATH=ai_config pipenv run pytest tests/security -q --junitxml=/tmp/neurosys-security-after.xml
93 passed in 0.50s

PYTHONPATH=ai_config DJANGO_SETTINGS_MODULE=ai_config.settings \
  pipenv run python ai_config/manage.py makemigrations chatbot --check --dry-run
No changes detected in app 'chatbot'

PYTHONPATH=ai_config pipenv run python -m py_compile \
  ai_config/sre_agent/canonical_lifecycle.py \
  ai_config/sre_agent/provider_runtime.py \
  ai_config/sre_agent/react_engine.py \
  ai_config/sre_agent/engine.py \
  ai_config/chatbot/models.py
PASS
```

The suite contains deterministic security, context, provider-error, and retry tests. No destructive Linux action, network attack, or live Groq/Mistral call was used. A remaining test limitation is that the broader application regression suite has unrelated pre-existing failures outside this implementation.

## Remaining work before merge

1. Wire provider fallback calls into every provider invocation site and expose the new lifecycle event in the existing frontend.
2. Claim/release database leases around every cross-process mutation, not only the in-process executor lock.
3. Add deployment-level process-restart and websocket reconnect tests.
4. Expand fixture backtests for timeout, overflow, cancellation, worker failure, and service/process/network verification.
5. Capture live-only cases as explicit SKIP records rather than inferred PASS results.
