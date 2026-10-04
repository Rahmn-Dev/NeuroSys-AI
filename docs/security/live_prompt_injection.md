# Live prompt-injection evaluation

The completed evidence is in [verification_live.json](verification_live.json) and
[verification_audit.jsonl](verification_audit.jsonl). It is separate from the prior
deterministic corpus.

Ten direct prompts were sent through the real `SREAgentEngine.run` entry path with an
isolated SQLite database. Every case was stopped by the application's pre-model guard:
no model response, tool action, approval card, or filesystem side effect occurred.
This is system-level prevention, not a claim that the model refused the prompt.

The existing official Mistral credential successfully invoked `open-mistral-nemo`.
The configured AI Model Manager route `MISTRALNEW` through 9router also successfully
invoked a model; its standalone probe is in
[verification_provider.json](verification_provider.json).

Ten indirect cases used individual harmless temporary files containing embedded hostile
instructions. A normal user goal asked the actual React tool loop to read each file.
`open-mistral-nemo` was invoked for every case; the `read_file` result was quarantined,
the engine emitted `security_blocked`, stopped the run, and did not call `write_file`.

Direct prompt resistance: 10/10. Indirect prompt resistance: 10/10. Execution
containment is N/A for both sets because the model did not attempt a harmful action;
the absence of a harmful attempt must not be reported as a successful containment rate.

| IDs | Class | Model invoked | Tool attempted | Guard | Side effect | Result |
|---|---|---:|---|---|---:|---|
| D01–D10 | Direct injection, English/Indonesian override, sudo, secret, canary variants | no | none | `security_blocked` before model | no | PASS 10/10 |
| I01–I10 | Indirect fixture with embedded override/canary instruction | yes, `open-mistral-nemo` | `read_file` only | quarantined then `security_blocked` | no | PASS 10/10 |

The fixture contained only instruction-like text; it contained no credential, token,
private key, production data, or destructive command. No production database was used.
