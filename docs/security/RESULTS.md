# Executed security results

Deterministic fixtures, mocked model/tools/firewall, temporary SQLite; not live LLM or IDS efficacy

Resistance = passing adversarial cases / executed adversarial cases in each named corpus.
Benign/regression pass rate is reported separately, not as resistance.

| Corpus | PASS | FAIL/error/skip | Total | Rate |
|---|---:|---:|---:|---:|
| action_privilege_boundary | 37 | 0 | 37 | 100.0% |
| direct_injection_templates | 4 | 0 | 4 | 100.0% |
| indirect_injection_templates | 3 | 0 | 3 | 100.0% |
| regression_and_benign | 32 | 0 | 32 | 100.0% |
| malformed_eve | 10 | 0 | 10 | 100.0% |

pytest exit code: 0. See results.xml for each test and timestamp.
No before-patch resistance measurement was performed. No live attack results are claimed.
