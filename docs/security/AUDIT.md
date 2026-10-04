# NeuroSysAI security audit and bounded hardening

Branch: `security/agent-hardening`. Changes reuse SafetyLayer, ToolRegistry, the existing
ReAct loop, SuricataLog model, monitor command and WebSocket consumer. No production
service was restarted, no live exploit was sent, and no firewall rules were changed.
Existing unrelated working-tree changes were preserved.

## Approval modes

Ask/Controlled creates an `AgentApproval` row server-side for a risky action. The row
binds session and user, stores the tool name and SHA-256 of canonical exact arguments,
keeps only a redacted argument-key preview, and expires after five minutes. Allow Once
locks and consumes exactly that row; changed tool/arguments, another session/user,
second use, or expiry is rejected. Audit events cover requested, approved, denied,
consumed, and expired. The API endpoints are `/api/v1/approvals/`,
`<id>/allow-once/`, and `<id>/deny/`; the SRE websocket emits the approval ID and
the chat UI displays Deny and Allow Once. Allow Once changes server state only; the
client must resend the original request with that approval ID, and the execution
boundary rechecks the exact hash.

Full Access still requires an explicit server-side list of `{tool, args_hash}` entries
in the execution context. It bypasses per-action approval only for those exact entries.
Destructive shell patterns, arbitrary session/background shells, secret paths, invalid
arguments, and other hard blocks run before scope matching. Client text and a
client-provided scope are not authorization credentials.

## Architecture and findings

`engine.py` discovers registered tools and routes requests through guided/controller,
worker/parallel, or autonomous ReAct execution. Workers can use PythonToolExecutor.
Tools use LangChain StructuredTool callables; several eventually execute subprocesses.

| Boundary | Finding from source audit | Patch |
|---|---|---|
| SafetyLayer | Terminal HIGH metadata downgraded to LOW; sudo only warned; blacklist bypassable | Exact fixed diagnostic allowlist; arbitrary execution and mutations require authorization |
| ReAct / PythonToolExecutor / controller fast path | Direct invoke could bypass checks | Registry wraps actual sync/async callables before invocation; executor and ReAct reject unregistered tools |
| Guided engine streaming | A `continue` in on_tool_start only affects event processing, not underlying execution | Callable guard remains authoritative regardless of stream/UI behavior |
| Delegation / LOW metadata | Delegated editor and shell-interpolating helpers can expand authority | Only fixed basher diagnostics allowed automatically; dangerous LOW helpers also require authorization |
| Prompt input / tool evidence | ReAct demanded automatic fixes; tool content could contain instructions | Common engine and ReAct direct override screening, policy prompt, registered tool observation quarantine; stop ReAct on denial |
| Audit | ReAct artifact included raw tool args/results | JSON security decisions/results with timestamp, tool, random call ID, verdict; ReAct artifact omits payloads |
| EVE monitor | Placeholder `your_app.models`, wrong Django command location, no rotation handling | Installed-app command wrapper, shared bounded schema validation, partial line and rotation handling |
| WebSocket | fast.log ingestion duplicated DB writes per viewer; reversed severity; anonymous access | EVE display for authenticated staff; persistence assigned to one independent monitor |
| Firewall | IP interpolated into shell; alerts could trigger blocking | Canonical IP validation, argv subprocess, noninteractive sudo, timeout; auto-block disabled by default |

## Deliberate execution restriction

Medium/HIGH tools, arbitrary commands, writes, recursive searches and unsafe
delegation require a matching server-side Allow Once row or a trusted Full Access
scope. Model arguments, user prose, sudo credentials and UI text are never approval
credentials. This preserves controlled remediation while keeping unscoped autonomous
mutations denied.

The code change is a guard around existing execution, not an OS sandbox. Run the
service as an unprivileged account with minimal filesystem access; Python process
compromise, direct legacy HTTP/SSH execution routes outside registered SRE tools,
and administrator actions are outside the protection established by this patch.

Prompt matching is heuristic, including English/Indonesian examples. It can have false
positives and miss paraphrases, encoded or multilingual instructions. The authoritative
protection against the tested harmful actions is the execution boundary, independent
of whether the prompt matcher detects them. File path restrictions resolve symlinks
and constrain reads to process cwd, but do not constitute complete secret discovery
or eliminate filesystem races. Existing chat/history/artifact subsystems other than
the changed ReAct execution record have not received a comprehensive redaction audit.

## Security logging

`neurosys.security` emits JSON to stderr through Django LOGGING: decisions, outcomes,
injection quarantine, EVE rejects/ingestion and auto-block suppression. Tool decision
and outcome share a random call ID. No prompts, command arguments, file contents,
credentials or exception messages enter these new records. Service-manager/external
log collection is needed for retention/access control; these records are not a
cryptographically tamper-proof audit ledger. The existing service process must not
have permissions to modify its external retained audit trail.

## Suricata operations

Run exactly one ingestion worker in the configured application environment:

```sh
cd ai_config
python manage.py start_security_monitor --suricata-log /var/log/suricata/eve.json
```

The command is now discoverable through installed `chatbot`. It starts at EOF by
default. `--replay` explicitly ingests existing records and may create duplicates.
WebSocket clients display EVE and no longer persist records themselves, so the
independent worker is required for persistence. `SURICATA_EVE_PATH` configures the
viewer; pass the same path to the worker. Staff authorization uses Django's existing
`is_staff` field. Severity 1/2/3 is normalized High/Medium/Low; non-alert events ignored.
Invalid schema/IP/port/timestamp and records above 64 KiB are rejected with audit events.

There is no durable cursor or event deduplication migration. Restart can miss events;
replay can duplicate them. Inode rotation is detected, but unread tail bytes in a
replaced inode can be lost. Copytruncate is detected when size is below current
position; truncate-and-regrow between polls can escape detection. Use a durable log
shipper/checkpoint design if lossless ingestion is required. Oversize rejection is a
chosen operational limit; deployments enabling large EVE payload fields must assess it.

Auto-block is off by default even for high-priority alerts. Enabling it is an operator
configuration decision and should require a reviewed whitelist and rule policy.
An alert alone is evidence, not proof that an IP should be blocked.

Live evidence is separated from deterministic results: [live prompt records](live_prompt_injection.json),
[prompt evaluation](live_prompt_injection.md), and [Suricata/Nmap status](live_suricata_nmap.md).
The completed live result is limited to 10/10 direct pre-model blocks. Indirect live
evaluation has no reported rate because the remote provider returned insufficient
balance and the local Ollama engine probe did not complete. Suricata/Nmap validation
was not run because an authorized lab target was not identifiable.

## Framework mapping (pinned OWASP 2025 edition)

These are scenario mappings, not claims of certification or full technique coverage.

| Tested behavior / evidence | OWASP LLM 2025 | MITRE ATT&CK interpretation |
|---|---|---|
| Direct role override / indirect malicious tool evidence | LLM01 Prompt Injection | No forced ATT&CK equivalence for prompt injection itself |
| Unauthorized shell and interpreter commands rejected | LLM06 Excessive Agency | T1059.004 Unix Shell for shell execution attempts |
| sudo/pkexec/setuid-related action attempts rejected | LLM06 Excessive Agency | T1548.003 applies to sudo scenarios; other escalation methods need their own technique mapping |
| Secret paths and symlink access denied; payload-free audit | LLM02 Sensitive Information Disclosure (partial mitigation) | No claim of complete credential access coverage |
| IP shell injection and malformed EVE rejected | LLM05 Improper Output Handling when untrusted model/tool output reaches execution; also ordinary input validation | Shell injection attempts can map to T1059.004; malformed logs alone do not imply an ATT&CK technique |
| Network scan alerts, if later produced in a live lab | Context-dependent | T1046 Network Service Discovery is a proposed live scenario, **not tested detection here** |

Sources checked for the mapping and EVE field structure:

- [OWASP LLM01:2025](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
- [OWASP LLM06:2025](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/)
- [OWASP Top 10, 2025 PDF](https://owasp.org/www-project-top-10-for-large-language-model-applications/assets/PDF/OWASP-Top-10-for-LLMs-v2025.pdf)
- [MITRE T1059.004](https://attack.mitre.org/techniques/T1059/004/)
- [MITRE T1548.003](https://attack.mitre.org/techniques/T1548/003/)
- [MITRE T1046](https://attack.mitre.org/techniques/T1046/)
- [Suricata EVE format](https://docs.suricata.io/en/latest/output/eve/eve-json-format.html)

## Reproduce and interpret results

Use Python 3.12 with the repository's relevant pinned dependencies:
`langchain-core==0.3.60`, `Django==5.1.6`, `channels==4.2.0`, `pytest==8.3.5`,
plus `jsonfield==3.1.0` and `psutil==7.0.0` for ORM/tool imports.

```sh
python tests/security/run.py
```

The runner records every case in `results.xml` and derives `summary.json` and
`RESULTS.md` from the executed cases. Tests use real LangChain wrappers and a real
Django in-memory SQLite table, with mocked LLM responses and subprocess entry points.
No remote model, production DB, live Suricata service or firewall is used.
Resistance rates cover only their specified deterministic fixture corpus. Benign and
regression checks have a separate pass rate. There is no measured pre-patch baseline,
no statistically representative red-team corpus, and no live detection/false-positive
rate. Full application startup and deployment remain unverified.
