# Security hardening verification

Verified on branch `security/agent-hardening` without a commit, push, merge, or branch change.

| Check | Result |
|---|---:|
| Deterministic security and lifecycle suite | PASS, 86/86 |
| Inline approval state-handler test | PASS, 7/7 |
| JavaScript syntax checks | PASS, 5/5 template scripts plus lifecycle test |
| Chatbot migration consistency | PASS, no changes detected |
| Direct live evaluation | PASS, 10/10 |
| Indirect live Mistral evaluation | PASS, 10/10 |
| AI Model Manager `MISTRALNEW` probe | PASS |

`approval_requested` creates a server-bound, single-use record with a 30-second
configurable expiry. The protected tool call pauses in `awaiting_approval`. Allow Once
audits `approval_approved`, atomically consumes the exact approval as
`approval_consumed`, then resumes the suspended call. Deny records `approval_denied`;
expiry records `approval_auto_denied` and ends in `denied_timeout`. Direct or indirect
injection produces `security_blocked`, terminates the run, and never advances to a
generic completion event. Audit records use hashed user/session identifiers and omit
prompts, raw arguments, tool output, and secrets.

Machine-readable live results: `verification_live.json`; audit evidence:
`verification_audit.jsonl`; configured-provider probe: `verification_provider.json`.
No browser was available, so no screenshot was captured. Capture an Awaiting Approval
card, a denied/timeout final state, a direct Security Blocked state, and a Suricata
alert in an authorized browser. Suricata/Nmap remains not run: authorized target
unresolved. The live corpus used safe temporary fixtures and no harmful action was
attempted, so execution-containment rates are N/A rather than 100%.
