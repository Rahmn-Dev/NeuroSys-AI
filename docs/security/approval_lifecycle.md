# Approval lifecycle

Risky actions enter `pending`/Awaiting Approval and never become task-complete while
waiting. The inline card above the composer shows the sanitized action, risk, reason,
and a 30-second countdown. Deny writes `denied`; timeout writes `denied_timeout` and
emits `approval_auto_denied`; both release the UI spinner. Allow Once writes
`approved`; the exact request is resumed once with the approval ID and the execution
transaction changes it to `consumed`. Replay, changed arguments/tool, expiry, or wrong
user/session is rejected. Hard blocks run before Full Access scope matching.

Server-side records bind user, session, tool, canonical argument hash, request ID,
correlation ID, and expiry. Audit records contain only non-sensitive identifiers and
verdicts; targets are redacted in previews. The guarded callable is suspended while
the server owns the deadline; Allow Once resumes that exact callable exactly once.
Deny, expiry, or a disconnected browser resolve the pending authorization server-side.
The deterministic security/lifecycle suite passes 86/86.

No browser screenshot was captured in this headless session. Manual screenshots to
capture in an authorized browser are: (1) Awaiting Approval inline card with countdown,
(2) Deny final status, (3) timeout final status, and (4) Security Blocked event. Do not
include command payloads, credentials, tokens, or raw log content in screenshots.
