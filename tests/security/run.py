"""Run the bounded security corpus and derive metrics solely from JUnit results."""
import json
import os
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

root = Path(__file__).resolve().parents[2]
out = root / "docs/security"
out.mkdir(parents=True, exist_ok=True)
env = dict(os.environ, PYTHONPATH=str(root / "ai_config"))
result = subprocess.run([sys.executable, "-m", "pytest", "tests/security", "-q",
                         f"--junitxml={out / 'results.xml'}"], cwd=root, env=env)
tree = ET.parse(out / "results.xml")
cases = list(tree.iter("testcase"))
def passed(case):
    return not any(case.find(tag) is not None for tag in ("failure", "error", "skipped"))
def category(name):
    if not name.startswith("test_attack_"):
        return "regression_and_benign"
    if "eve_" in name:
        return "malformed_eve"
    if "direct_react" in name:
        return "direct_injection_templates"
    if "indirect_" in name:
        return "indirect_injection_templates"
    return "action_privilege_boundary"
metrics = {}
for case in cases:
    group = metrics.setdefault(category(case.get("name", "")), {"passed": 0, "total": 0})
    group["total"] += 1
    group["passed"] += int(passed(case))
for name, group in metrics.items():
    group["rate_percent"] = round(100 * group["passed"] / group["total"], 2)
summary = {"scope": "Deterministic fixtures, mocked model/tools/firewall, temporary SQLite; not live LLM or IDS efficacy",
           "tests": len(cases), "passed": sum(passed(c) for c in cases),
           "pytest_exit_code": result.returncode, "groups": metrics}
(out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
lines = ["# Executed security results", "", summary["scope"], "",
         "Resistance = passing adversarial cases / executed adversarial cases in each named corpus.",
         "Benign/regression pass rate is reported separately, not as resistance.", "",
         "| Corpus | PASS | FAIL/error/skip | Total | Rate |", "|---|---:|---:|---:|---:|"]
for name, group in metrics.items():
    lines.append(f"| {name} | {group['passed']} | {group['total']-group['passed']} | {group['total']} | {group['rate_percent']}% |")
lines += ["", f"pytest exit code: {result.returncode}. See results.xml for each test and timestamp.",
          "No before-patch resistance measurement was performed. No live attack results are claimed."]
(out / "RESULTS.md").write_text("\n".join(lines) + "\n")
sys.exit(result.returncode)
