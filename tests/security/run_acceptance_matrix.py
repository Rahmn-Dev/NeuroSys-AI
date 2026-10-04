"""Derive acceptance-component outcomes from executed JUnit, never inferred success.

Run pytest --junitxml=docs/agent_eval/reliability_results.xml first.
Live/manual acceptance is explicitly separate from deterministic contract checks.
"""
import json
from pathlib import Path
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / 'docs/agent_eval'
SCENARIOS = [
 ('a', 'Health collection, read-only policy and one completion', ['test_health_collects', 'test_read_service', 'test_engine_terminal']),
 ('b', 'Terminal then fresh prompt contract', ['test_terminal_is_immutable']),
 ('c', 'Related context and explicit service switch', ['test_context_target_continuity', 'test_context_budget']),
 ('d', 'Durable Guided tasks and mutation approvals', ['test_durable_tasks', 'test_service_mutation']),
 ('e', 'Approval allow-once, deny and expiry', ['test_approvals.', 'test_approval_reconnect_smoke.']),
 ('f', 'Direct and indirect injection fixtures', ['test_adversarial.']),
 ('g', 'Safe local file write and readback', ['test_real_file_tool', 'test_verification_requires']),
 ('h', 'Disk-only coverage scope', ['test_disk_only']),
 ('i', 'Provider error, retry and explicit fallback contracts', ['test_provider_runtime.', 'test_provider_chain.', 'test_controller_does_not']),
 ('j', 'Checkpoint and approval rehydration components', ['test_resume_checkpoint.', 'test_rehydration_scenarios.', 'test_rehydration_snapshot.']),
 ('k', 'New run identifier after every terminal status', ['test_terminal_is_immutable']),
 ('l', 'Multi duplicate evidence, failed dependencies and mutation leases', ['test_multi_', 'test_canonical_mutation', 'test_same_run_workers']),
 ('m', 'Cancellation propagation and ownership', ['test_cancellation_']),
 ('n', 'Independent socket and retry policy checks', ['test_realtime_socket_policy.']),
 ('o', 'Public event reasoning/secret redaction', ['test_public_events_exclude']),
]

def outcome(case):
    for tag, status in [('error','ERROR'), ('failure','FAIL'), ('skipped','SKIP')]:
        if case.find(tag) is not None:
            return status
    return 'PASS'


def main():
    cases = list(ET.parse(OUTPUT / 'reliability_results.xml').iter('testcase'))
    rows = []
    for ident, scope, selectors in SCENARIOS:
        selected = [c for c in cases if any(s in c.get('classname','') + '.' + c.get('name','') for s in selectors)]
        outcomes = [outcome(c) for c in selected]
        status = next((s for s in ['ERROR','FAIL','SKIP'] if s in outcomes), 'PASS') if selected else 'ERROR'
        rows.append({'id': ident, 'controlled_scope': scope, 'controlled_result': status,
                     'test_cases': [c.get('classname','') + '.' + c.get('name','') for c in selected],
                     'manual_live_result': 'SKIP',
                     'manual_reason': 'No live browser/provider/SSH/sensor acceptance session was executed.'})
    totals = {s: sum(outcome(c) == s for c in cases) for s in ['PASS','FAIL','ERROR','SKIP']}
    report = {'scope': 'Component contracts; PASS does not mean full product E2E passed. Rows overlap and must not be added as independent tests.',
              'suite_totals': totals, 'matrix_totals': {s: sum(r['controlled_result'] == s for r in rows) for s in totals},
              'manual_live_totals': {'PASS': 0, 'FAIL': 0, 'ERROR': 0, 'SKIP': len(rows)}, 'scenarios': rows}
    (OUTPUT / 'reliability_matrix.json').write_text(json.dumps(report, indent=2) + '\n')
    lines = ['# Reliability acceptance matrix', '', report['scope'], '', '| ID | Controlled contract | Result | Manual/live |', '|---|---|---|---|']
    lines += [f"| {r['id']} | {r['controlled_scope']} | {r['controlled_result']} ({len(r['test_cases'])} checks) | SKIP |" for r in rows]
    lines += ['', f'Unique suite outcomes: {totals}', '', 'All 15 full manual/live scenarios are SKIP. See JSON for exact supporting test names and reasons.']
    (OUTPUT / 'reliability_matrix.md').write_text('\n'.join(lines) + '\n')
    print(json.dumps({k: report[k] for k in ['suite_totals','matrix_totals','manual_live_totals']}))
    return int(any(r['controlled_result'] in {'FAIL','ERROR'} for r in rows))

if __name__ == '__main__':
    raise SystemExit(main())
