# NeuroSysAI reliability hardening review

Date: 2026-09-27. Checkout: `/home/paul/project-ai/NeuroSys-AI`. Branch: `security/agent-hardening`.

Substantial reliability fixes are implemented and deterministic checks pass. The entire requested product acceptance scope is **not yet proven complete**. This is suitable for code review, not a production-readiness or merge recommendation. No commit, push, merge, branch switch, attribution, or co-author was added. The existing dirty checkout and unrelated files were preserved.

## Root causes and implemented corrections

1. **Prompt text was execution identity.** The canonical engine hashed session/model/mode/prompt into a reusable idempotency key. Repeating a completed prompt could reopen the old run. New execution requests now get a fresh UUID key; conversation history remains separate.
2. **The Single adapter created another run.** It now receives the canonical engine lifecycle instead of opening its own durable run.
3. **Terminal transitions were mutable.** Transactional transition handling now refuses to change a terminal run or append duplicate terminal transitions. Resume lookup excludes terminal runs. New-run claims serialize on the conversation row and reject an already active run.
4. **Completion raced cleanup and appeared twice.** Single emitted an inner completion and a second completion in a `finally` block. Completion now follows result persistence, is recorded before transmission, and is suppressed after an error or earlier completion. Cancellation no longer executes a completion yield from `finally`. Replay metadata updates the exact assistant message, not whichever message is newest.
5. **Tool-level risk hid safe actions.** Validated service `list`, `failed`, `status`, `is-active`, and `show` are read-only. Start/stop/restart require authorization. Safe process/package reads and scoped logs follow action-aware policy. Log reads now use subprocess argument arrays rather than shell interpolation.
6. **Health coverage depended on model tool choices.** Broad system-health requests collect CPU, memory, disk, uptime/load, failed units, service inventory, and configured key service states before reasoning. Each check has a source, collection timestamp, result, or explicit collection failure. Single now retains the common system/context prompt containing that evidence. Disk-only requests do not invoke this whole-system collector.
7. **Socket reconnect did not subscribe a replacement connection.** Agent subscriptions now join an owner-scoped Channels group and return current lifecycle/terminal state. Durable approval decisions can be made from a replacement socket and observed by the original pending execution without a new approval token or action.
8. **Recovery and polling could remain unbounded.** Engine execution is bounded to 300 seconds. An abandoned active run older than 330 seconds becomes failed with a review-required reason, rather than rerunning possibly completed side effects. Fallback snapshot polling stops after 12 attempts or an open socket. Agent and Suricata heartbeat handling detects inactive connections.
9. **Host-specific sockets and retry policy were stale.** Agent/Suricata/dashboard/service-control sockets use current-origin ws/wss. Suricata delay includes jitter and is capped at 30 seconds after jitter; normal/permanent/protocol/auth closes stop retries. Sensor failures do not reload the chat page.
10. **Provider failures could look like successful empty plans.** Provider lookup requires an active supported selection and fails closed. Controller provider errors no longer enter JSON-repair fallback as successful empty plans. Real controller, classifier, and Single call sites use bounded same-provider retries; common hosted clients have explicit timeout/retry settings. OpenAI selection no longer silently targets the local router default.
11. **Multi dependency/duplicate handling lost correctness.** Duplicate tasks in the same DAG share the real result/evidence without another tool call. A failed prerequisite blocks dependent execution. Cancellation is propagated instead of treated as a result object. Unregistered tools are blocked.
12. **Lock helpers were not on the canonical mutation path.** Registered tools executed within a canonical run now acquire a durable global mutation lease; same-run workers cannot steal each other's live lease. File writes/edits perform read-back verification and service mutations check resulting service state.
13. **Progress/audit could expose private content.** Public serialization suppresses private reasoning blocks, replaces reasoning-progress text with fixed state narration, removes raw tool arguments/results, and redacts common credential forms. Engine event audit storage keeps structured identifiers/status rather than raw model/tool messages. Raw exception tracebacks are no longer streamed to the UI.

## Architecture and lifecycle

`SREAgentEngine` owns the run for Guided, Single, and Multi orchestration. A conversation can retain recent turns without retaining execution identity. Active statuses include planning/executing/verifying as well as running/paused/approval states. Completed, failed, cancelled, denied, denied_timeout, blocked, security_blocked, error, finalized, and `finalized_*` states are terminal.

Guided plan events mirror tasks, dependencies, attempts, selected tools, and evidence into `AgentTask`. A reported completed task without evidence becomes `verifying`, rather than done. The frontend does not mark every task done merely because a completion event arrives.

Cancellation requests are owner-scoped and persisted. An executing engine checks cancellation while running; a disconnected socket is not needed to submit the durable request. This does not guarantee termination of an already-running remote command or synchronous subprocess; see limitations below.

The watchdog intentionally fails abandoned executions rather than pretending to resume them. Reconnecting to a live execution subscribes to the same run. This is not automatic process-crash graph continuation.

## Event and progress contract

Canonical engine events carry `type`, public `content`, timestamp, `run_id`, stable `event_id`, and `checkpoint_version`. Completion uses `<run_id>:terminal` so live delivery and terminal replay deduplicate. Subscription state uses a run/checkpoint identity. Approval events use run/approval/action identity.

The frontend deduplicates identified events, messages during history replay, and completion by run. Checkpoint comparisons include run identity, so checkpoint 1 of a new run is not suppressed by a higher checkpoint from an older run. Canonical lifecycle, resuming, provider fallback, and verification events have replay handling. Terminal lifecycle notices update controls rather than rendering a second completion card.

Only wall-clock duration currently has a defined complete runtime measurement. No fabricated active-execution-time value was added. If a separate active duration is introduced, it must be another field on the same completion card.

Raw tool data stays available to guarded execution/model reasoning but is omitted from public tool progress and structured audit. Redaction is defense in depth, not proof against every possible secret format or model disclosure.

## Context and evidence policy

The provider-neutral envelope bounds serialized size, recent turns, evidence, artifacts, task references, and environment. It deduplicates evidence and removes explicitly stale observations. Recent database history reads are limited to the newest nine turns; the model receives bounded recent context rather than audit/progress logs.

Explicit target changes (for example nginx to PostgreSQL) override continuation language. Related logs/root-cause requests retain conversational context. Historical context is not a license to reuse a run identifier or replay side effects.

Health services default to nginx, PostgreSQL, and SSH and can be configured with `AGENT_HEALTH_SERVICES`. Collection is local to the execution environment. Missing/inaccessible collectors/services must be reported as unknown or failed collection. This does not demonstrate SSH coverage of a remote machine.

## Tool and approval policy

Read-only operations bypass mutation approval only after argument validation. Service names cannot inject shell syntax. Log paths are confined to `/var/log` after resolution; service-unit log sources are validated, line counts bounded, and filters applied without a shell. Existing destructive-action/injection guards remain in force.

Mutation approval remains identity-, session-, tool-, and argument-bound and single-use. Denial/timeout transitions are durable. Snapshot expiry uses the transactional approval helper, preventing a stale snapshot from blindly overwriting an already decided approval.

Canonical mutations use a database-backed serialization lease; read-only calls do not acquire it. File-write/edit and service start/stop/restart postconditions are implemented. Not every generic mutator has a dedicated postcondition verifier; this remains an acceptance gap.

## Files changed during this pass

Application/lifecycle:

- `ai_config/ai_config/consumers.py`
- `ai_config/chatbot/views.py`
- `ai_config/sre_agent/canonical_lifecycle.py`
- `ai_config/sre_agent/engine.py`
- `ai_config/sre_agent/controller.py`
- `ai_config/sre_agent/react_engine.py`
- `ai_config/sre_agent/parallel.py`
- `ai_config/sre_agent/events.py`
- `ai_config/sre_agent/security_boundary.py`
- `ai_config/sre_agent/approval_lifecycle.py`
- `ai_config/sre_agent/provider_runtime.py`
- `ai_config/sre_agent/resource_locks.py`
- `ai_config/sre_agent/health_evidence.py` (new)
- `ai_config/sre_agent/mutation_scope.py` (new)
- `ai_config/sre_agent/tools/filesystem.py`
- `ai_config/sre_agent/tools/linux.py`

UI:

- `ai_config/templates/chat3.html`
- `ai_config/templates/layout/layout1.html`
- `ai_config/templates/network_security.html`
- `ai_config/templates/dashboard.html`
- `ai_config/templates/service_control.html`

Tests/evidence:

- `tests/security/test_reliability_hardening.py` (new)
- `tests/security/frontend_syntax.cjs` (new)
- `tests/security/run_acceptance_matrix.py` (new)
- `tests/security/test_approvals.py` (valid mutation fixtures)
- `tests/security/test_realtime_socket_policy.py` (expanded permanent-close policy)
- `tests/security/run_backtest.py` (distinct assertion failure vs execution error)
- `docs/agent_eval/reliability_*` (this report, matrix, JUnit, backtest)

Several listed lifecycle/security files were already untracked at entry. This inventory does not imply this pass authored all their existing content. Existing migrations 0020–0023 and unrelated dirty files were preserved; no new model migration was required.

## Executed verification

| Check | PASS | FAIL | ERROR | SKIP |
|---|---:|---:|---:|---:|
| Security/reliability/provider/resume/rehydration/Multi pytest suite | 170 | 0 | 0 | 0 |
| UI handler assertions (deterministic DOM stubs) | 7 | 0 | 0 | 0 |
| Inline JavaScript syntax parses | 7 | 0 | 0 | 0 |
| Compact controlled backtest | 5 | 0 | 0 | 0 |
| Manual/live acceptance scenarios a–o | 0 | 0 | 0 | 15 |

The initial suite had 117 passing tests. There are 53 new parameterized regression cases in this pass. Matrix rows overlap underlying tests and are not additional independent tests. All 15 component-contract rows pass, which is explicitly different from full product E2E acceptance.

Commands:

```text
PYTHONPATH=ai_config pipenv run pytest tests/security -q --disable-warnings --junitxml=docs/agent_eval/reliability_results.xml
python3 tests/security/run_acceptance_matrix.py
PYTHONPATH=ai_config pipenv run python tests/security/run_backtest.py
node tests/security/frontend_syntax.cjs
node tests/security/ui_lifecycle.cjs
PYTHONPATH=ai_config DJANGO_SETTINGS_MODULE=ai_config.settings pipenv run python ai_config/manage.py check
PYTHONPATH=ai_config DJANGO_SETTINGS_MODULE=ai_config.settings pipenv run python ai_config/manage.py makemigrations --check --dry-run
```

Django: no issues. Migration consistency: no changes detected. JavaScript syntax checking removes Django placeholders before parsing; it is not a browser render test.

The literal `git diff --check` reports CRLF trailing-whitespace diagnostics in pre-existing changed lines. `git -c core.whitespace=cr-at-eol diff --check` passes. Existing unrelated content and line endings were not broadly rewritten to hide those diagnostics.

No live provider, SSH, Suricata sensor, browser acceptance session, or production proxy test was run. See `reliability_matrix.md` and JSON for a–o mappings and exact supporting test names.

## Deployment/keepalive notes

Use the configured shared Redis Channels layer across ASGI workers; an in-memory layer cannot deliver subscriptions across processes. Proxy WebSocket upgrade headers must be forwarded and idle timeouts should exceed the 15-second application ping / 45-second inactivity window (at least 60 seconds, preferably 90). Configure ASGI WebSocket ping/timeout consistently. A normal application disconnect must not reload/reset the chat or restart tools. Watchdog recovery records failure for review; it does not grant permission to retry a mutation.

## Remaining gaps and review recommendation

- Full interactive scenarios a–o remain unexecuted. Live multi-worker subscription, approval races, proxy loss, process restart, and remote cancellation require deployment-level tests.
- Generic terminal/package/container/network mutations still need dedicated postcondition contracts. File and service verification should not be generalized into a claim that every mutator is verified.
- Durable mutation leases serialize live work, but do not provide target-side exactly-once semantics after a crash. The DAG duplicate-result cache is process-local. Reclaiming a lease after an uncertain remote side effect requires inspection, not automatic replay.
- There is no automatic restoration of a lost graph execution after a worker/process crash. Existing live runs re-subscribe; abandoned runs fail under the watchdog.
- Provider-chain fallback is a tested explicit helper; this pass integrates bounded same-provider retries and fail-closed selection, not a deployed automatic multi-provider routing policy. Provider SDK/network cancellation behavior remains unverified.
- Task evidence mirroring does not independently validate every model-generated evidence item. Stronger source-linked task completion and generic mutation verification remain necessary.
- Legacy execution endpoints outside the canonical SRE path still need an exhaustive route-by-route parity/security review. This pass does not claim all legacy agents were migrated.
- Event/checkpoint dedupe is implemented, but exhaustive browser replay/stream interleaving and legacy events without stable identifiers need a real browser test.
- Secret filtering covers common forms and private-reasoning tags, not every credential encoding or possible model output.

**Recommendation:** review the concrete lifecycle, approval, transport, and verification changes with the recorded test evidence. Keep release/merge approval gated on the remaining implementation and live acceptance work. Do not describe this as production ready or as Codex/Claude parity.
