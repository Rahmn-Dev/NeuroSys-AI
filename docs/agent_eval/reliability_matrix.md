# Reliability acceptance matrix

Component contracts; PASS does not mean full product E2E passed. Rows overlap and must not be added as independent tests.

| ID | Controlled contract | Result | Manual/live |
|---|---|---|---|
| a | Health collection, read-only policy and one completion | PASS (7 checks) | SKIP |
| b | Terminal then fresh prompt contract | PASS (10 checks) | SKIP |
| c | Related context and explicit service switch | PASS (5 checks) | SKIP |
| d | Durable Guided tasks and mutation approvals | PASS (4 checks) | SKIP |
| e | Approval allow-once, deny and expiry | PASS (23 checks) | SKIP |
| f | Direct and indirect injection fixtures | PASS (57 checks) | SKIP |
| g | Safe local file write and readback | PASS (2 checks) | SKIP |
| h | Disk-only coverage scope | PASS (1 checks) | SKIP |
| i | Provider error, retry and explicit fallback contracts | PASS (6 checks) | SKIP |
| j | Checkpoint and approval rehydration components | PASS (9 checks) | SKIP |
| k | New run identifier after every terminal status | PASS (10 checks) | SKIP |
| l | Multi duplicate evidence, failed dependencies and mutation leases | PASS (5 checks) | SKIP |
| m | Cancellation propagation and ownership | PASS (2 checks) | SKIP |
| n | Independent socket and retry policy checks | PASS (8 checks) | SKIP |
| o | Public event reasoning/secret redaction | PASS (1 checks) | SKIP |

Unique suite outcomes: {'PASS': 177, 'FAIL': 0, 'ERROR': 0, 'SKIP': 0}

All 15 full manual/live scenarios are SKIP. See JSON for exact supporting test names and reasons.
