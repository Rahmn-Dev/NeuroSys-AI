"""
NeuroSys-AI — True Hybrid Parallel Worker Engine.

Each InvestigationWorker is an autonomous investigator that independently:
  1. Thinks (LLM) → selects next tool + args
  2. Executes the tool
  3. Observes with Rule Engine (deterministic) → LLM fallback only on uncertainty
  4. Updates ConfidenceEngine from rules + LLM + child workers
  5. Optionally spawns a child worker for sub-investigations
  6. Terminates when confidence threshold reached or iteration limit hit

WorkerScheduler runs all workers concurrently with multi-level cancellation:
  - Worker-level: self-terminates when confidence >= WORKER_THRESHOLD
  - Aggregator-level: cancels remaining workers when global confidence >= GLOBAL_THRESHOLD
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set


# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

WORKER_CONFIDENCE_THRESHOLD = 0.82   # worker self-terminates above this
GLOBAL_CONFIDENCE_THRESHOLD = 0.92   # aggregator cancels siblings above this
MAX_WORKER_ITERATIONS       = 8      # hard cap per worker
MAX_CHILD_ITERATIONS        = 4      # children get fewer iterations
MAX_WORKER_DEPTH            = 2      # max depth for child worker spawning
CHILD_TIMEOUT_SEC           = 30     # child hard timeout
TOOL_TIMEOUT_SEC            = 25     # per-tool execution timeout


# ─────────────────────────────────────────────────────────────────────────────
# Evidence & Contradiction
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Evidence:
    source: str       # "rule" | "llm" | "child_worker"
    signal: str       # "CRITICAL" | "FAILURE" | "SUCCESS" | "WARNING" | "INFO"
    finding: str      # e.g. "config_error", "service_failed"
    detail: str       # raw snippet that triggered the evidence
    weight: float     # 0.0–1.0 contribution to confidence
    tool_name: str = ""
    timestamp: float  = field(default_factory=time.time)
    # Evidence quality metadata
    evidence_type: str = "observation"  # "observation" | "direct_error" | "service_status" | "correlated"
    verified: bool = False              # True only for confirmed root-cause rule matches
    relevance_score: float = 0.0        # 0.0-1.0: how directly this relates to the failure


@dataclass
class Contradiction:
    finding_a: str
    finding_b: str
    detail: str
    penalty: float = 0.15


# ─────────────────────────────────────────────────────────────────────────────
# Confidence Engine
# ─────────────────────────────────────────────────────────────────────────────

# Signal → base weight mapping
_SIGNAL_WEIGHT = {
    "CRITICAL": 0.80,
    "FAILURE":  0.60,
    "SUCCESS":  0.50,
    "WARNING":  0.20,
    "INFO":     0.10,
}

# Pairs of findings that contradict each other
_CONTRADICTION_PAIRS = [
    ("service_running", "service_failed"),
    ("config_valid",    "config_error"),
    ("port_open",       "connection_refused"),
    ("disk_ok",         "disk_full"),
]


@dataclass
class ConfidenceEngine:
    score: float = 0.0
    evidence: List[Evidence] = field(default_factory=list)
    contradictions: List[Contradiction] = field(default_factory=list)

    # ── update methods ──────────────────────────────────────────────────────

    def update_from_rules(self, signal: str, finding: str, detail: str,
                          tool_name: str = "", is_root_cause: bool = False) -> None:
        """Apply a deterministic rule observation to confidence."""
        base_weight = _SIGNAL_WEIGHT.get(signal, 0.10)
        # Diminishing returns: each additional same-signal evidence contributes less
        same_signal_count = sum(1 for e in self.evidence if e.signal == signal)
        weight = base_weight * (0.7 ** same_signal_count)

        # Classify evidence type based on signal and root_cause flag
        if is_root_cause and signal in ("CRITICAL", "FAILURE"):
            ev_type = "direct_error"
            verified = True
            relevance = 0.95
        elif signal == "SUCCESS":
            ev_type = "service_status"
            verified = False
            relevance = 0.8
        elif signal in ("CRITICAL", "FAILURE"):
            ev_type = "observation"
            verified = False
            relevance = 0.6
        else:
            ev_type = "observation"
            verified = False
            relevance = 0.3

        ev = Evidence(source="rule", signal=signal, finding=finding,
                      detail=detail[:300], weight=weight, tool_name=tool_name,
                      evidence_type=ev_type, verified=verified, relevance_score=relevance)
        self.evidence.append(ev)
        self._check_contradictions(finding)
        self._recalculate()

    def update_from_llm(self, llm_score: float, reasoning: str) -> None:
        """Blend LLM observation confidence with current rule-based score."""
        ev = Evidence(source="llm", signal="INFO", finding="llm_observation",
                      detail=reasoning[:300], weight=0.0)  # weight=0, only blending
        self.evidence.append(ev)
        # Blend: 40% LLM, 60% existing rule-based score
        self.score = min(1.0, 0.60 * self.score + 0.40 * llm_score)

    def update_from_child(self, child_state: "WorkerState") -> None:
        """Inherit evidence from a completed child worker."""
        if not child_state.completed:
            return
        child_weight = child_state.confidence.score * 0.7  # child contributes up to 70%
        ev = Evidence(
            source="child_worker",
            signal="INFO",
            finding=f"child_{child_state.id}_result",
            detail=child_state.root_cause[:300] if child_state.root_cause else
                   f"Child {child_state.id} findings: {len(child_state.findings)} items",
            weight=child_weight,
        )
        self.evidence.append(ev)
        # Propagate child evidence objects
        for ce in child_state.confidence.evidence:
            propagated = Evidence(
                source="child_worker", signal=ce.signal, finding=ce.finding,
                detail=ce.detail, weight=ce.weight * 0.6,
                tool_name=ce.tool_name,
            )
            self.evidence.append(propagated)
        self._recalculate()

    # ── internal ────────────────────────────────────────────────────────────

    def _recalculate(self) -> None:
        """Recompute score from all evidence minus contradiction penalties."""
        raw = sum(e.weight for e in self.evidence if e.source != "llm")
        penalty = sum(c.penalty for c in self.contradictions)
        self.score = min(1.0, max(0.0, raw - penalty))

    def _check_contradictions(self, new_finding: str) -> None:
        """Detect contradictions between new finding and existing evidence."""
        existing_findings = {e.finding for e in self.evidence}
        for a, b in _CONTRADICTION_PAIRS:
            if new_finding == b and a in existing_findings:
                self.contradictions.append(Contradiction(
                    finding_a=a, finding_b=b,
                    detail=f"Contradicting signals: {a} vs {b}"
                ))
            elif new_finding == a and b in existing_findings:
                self.contradictions.append(Contradiction(
                    finding_a=b, finding_b=a,
                    detail=f"Contradicting signals: {b} vs {a}"
                ))

    @property
    def is_sufficient(self) -> bool:
        """True when evidence is strong enough to conclude."""
        # Must have at least one FAILURE/CRITICAL/SUCCESS rule-based finding
        has_strong_signal = any(
            e.signal in ("CRITICAL", "FAILURE", "SUCCESS")
            for e in self.evidence if e.source != "llm"
        )
        if not has_strong_signal or self.score < WORKER_CONFIDENCE_THRESHOLD:
            return False
        # CRITICAL GATE: require at least one verified root-cause evidence.
        # Without this, a worker with only observations (high memory) would
        # self-terminate claiming a root cause it never confirmed.
        has_verified_cause = any(e.verified for e in self.evidence)
        if not has_verified_cause:
            return False
        return True

    @property
    def has_verified_evidence(self) -> bool:
        """True if any evidence item is confirmed as a verified root cause."""
        return any(e.verified for e in self.evidence)

    def summary(self) -> dict:
        return {
            "score": round(self.score, 3),
            "evidence_count": len(self.evidence),
            "contradiction_count": len(self.contradictions),
            "is_sufficient": self.is_sufficient,
            "has_verified_evidence": self.has_verified_evidence,
            "top_findings": [e.finding for e in self.evidence
                             if e.signal in ("CRITICAL", "FAILURE") and e.source == "rule"][:5],
        }


# ─────────────────────────────────────────────────────────────────────────────
# Rule Observation Engine
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class RuleMatch:
    signal: str
    finding: str
    matched_text: str
    uncertain: bool = False   # True → trigger LLM fallback
    root_cause: bool = False


class RuleObserver:
    """
    Deterministic observation rules applied to raw tool output.
    Returns a RuleMatch or uncertain=True (which triggers LLM fallback).
    """

    # (regex_pattern, signal, finding_key, root_cause)
    RULES: List[tuple] = [
        # Service/process state
        (r"Active:\s+failed",                          "FAILURE",  "service_failed", False),
        (r"Active:\s+active\s+\(running\)",            "SUCCESS",  "service_running", False),
        (r"Active:\s+inactive",                        "WARNING",  "service_inactive", False),
        (r"Active:\s+activating",                      "WARNING",  "service_activating", False),
        (r"failed to start",                           "FAILURE",  "service_start_failed", False),
        (r"start request repeated too quickly",        "FAILURE",  "service_restart_loop", False),
        # Config
        (r"syntax error|invalid directive|unknown directive|nginx: \[emerg\]",
                                                       "FAILURE",  "config_error", True),
        (r"syntax is ok|test is successful|configuration file.*syntax is ok",
                                                       "SUCCESS",  "config_valid", False),
        # Filesystem
        (r"No such file or directory",                 "FAILURE",  "file_not_found", False),
        (r"No space left on device",                   "CRITICAL", "disk_full", True),
        (r"Permission denied",                         "FAILURE",  "permission_denied", False),
        (r"Read-only file system",                     "CRITICAL", "readonly_fs", False),
        # Network
        (r"Connection refused",                        "FAILURE",  "connection_refused", False),
        (r"Connection timed out|Network is unreachable","FAILURE", "network_unreachable", False),
        (r"0 received.*100% packet loss",              "FAILURE",  "network_unreachable", False),
        (r"LISTEN",                                    "SUCCESS",  "port_listening", False),
        (r"Address already in use",                    "FAILURE",  "port_conflict", False),
        # Memory/CPU
        (r"Out of memory|OOM killer|oom-kill",         "CRITICAL", "oom_kill", False),
        (r"Killed process",                            "CRITICAL", "process_killed", False),
        # Docker
        (r"Exited \([^0]",                             "FAILURE",  "container_exited", False),
        (r"Up \d+ (second|minute|hour|day)",           "SUCCESS",  "container_running", False),
        (r"cannot connect to docker daemon",           "FAILURE",  "docker_daemon_down", False),
        # Disk
        (r"\b(9[5-9]|100)%",                          "CRITICAL", "disk_near_full", False),
        (r"\b([0-7][0-9])%",                           "INFO",     "disk_ok", False),
        # Generic errors
        (r"command not found",                         "WARNING",  "command_not_found", False),
        (r"Segmentation fault",                        "CRITICAL", "segfault", False),
        (r"core dumped",                               "CRITICAL", "core_dump", False),
        (r'"exit_code":\s*[1-9]',                      "WARNING",  "non_zero_exit", False),
        (r'"exit_code":\s*0',                          "INFO",     "zero_exit", False),
    ]

    _compiled = [(re.compile(pat, re.IGNORECASE | re.MULTILINE), sig, key, rc)
                 for pat, sig, key, rc in RULES]

    def observe(self, tool_output: str, tool_name: str = "") -> RuleMatch:
        """
        Apply rules to tool output. Return best match or uncertain=True.
        Priority order: CRITICAL > FAILURE > SUCCESS > WARNING > INFO.
        """
        if not tool_output or not tool_output.strip():
            return RuleMatch(signal="WARNING", finding="empty_output",
                             matched_text="", uncertain=True)

        # Try to extract stdout from JSON tool responses
        text = tool_output
        try:
            parsed = json.loads(tool_output)
            text = (parsed.get("stdout", "") + " " +
                    parsed.get("stderr", "") + " " +
                    str(parsed.get("exit_code", ""))).strip()
            if not text.strip():
                text = tool_output
        except Exception:
            pass

        priority_order = ["CRITICAL", "FAILURE", "SUCCESS", "WARNING", "INFO"]
        matches_by_signal: Dict[str, RuleMatch] = {}

        for regex, signal, finding, root_cause in self._compiled:
            m = regex.search(text)
            if m:
                matched_text = m.group(0)[:200]
                if signal not in matches_by_signal:
                    matches_by_signal[signal] = RuleMatch(
                        signal=signal, finding=finding,
                        matched_text=matched_text, uncertain=False,
                        root_cause=root_cause
                    )

        for sig in priority_order:
            if sig in matches_by_signal:
                return matches_by_signal[sig]

        # No rule matched → uncertain, LLM fallback needed
        return RuleMatch(signal="INFO", finding="no_match",
                         matched_text="", uncertain=True)


# ─────────────────────────────────────────────────────────────────────────────
# Worker State
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class WorkerState:
    id: str
    goal: str
    hypothesis: str                           = ""
    findings: List[dict]                      = field(default_factory=list)
    tool_history: List[str]                   = field(default_factory=list)
    confidence: ConfidenceEngine              = field(default_factory=ConfidenceEngine)
    iteration: int                            = 0
    status: str                               = "pending"   # pending|running|completed|failed|blocked|cancelled
    completed: bool                           = False
    root_cause: str                           = ""
    recommendations: List[str]               = field(default_factory=list)
    children: List["WorkerState"]             = field(default_factory=list)
    is_child: bool                            = False
    parent_id: Optional[str]                  = None
    total_duration: float                     = 0.0
    requires_approval: bool                   = False
    terminal_cwd: str                         = ""
    active_workspace: str                     = ""
    evidence_chain: List[str]                 = field(default_factory=list)
    evidence_chain_confidence: float          = 0.0
    expected_diagnostic_domains: List[str]    = field(default_factory=list)
    investigation_coverage: List[str]         = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# Investigation Worker
# ─────────────────────────────────────────────────────────────────────────────

class InvestigationWorker:
    """
    Autonomous SRE investigator.

    Owns its own Think → Execute → Rule-Observe → (LLM-Observe fallback) loop.
    Can spawn child workers for sub-investigations.
    Self-terminates when confidence threshold reached.
    """

    def __init__(
        self,
        worker_id: str,
        goal: str,
        llm,
        tool_map: Dict[str, Any],
        safety,
        max_iterations: int = MAX_WORKER_ITERATIONS,
        is_child: bool = False,
        parent_id: Optional[str] = None,
        parent_context: Optional[List[dict]] = None,
        expected_diagnostic_domains: Optional[List[str]] = None,
    ):
        self.state = WorkerState(
            id=worker_id,
            goal=goal,
            is_child=is_child,
            parent_id=parent_id,
            expected_diagnostic_domains=expected_diagnostic_domains or [],
        )
        self.llm = llm
        self.tool_map = tool_map
        self.safety = safety
        self.max_iterations = max_iterations
        self.rule_observer = RuleObserver()
        self._execution_hashes: Set[str] = set()
        self._parent_context = parent_context or []
        self._child_depth = 1 if is_child else 0
        self._active_children: List[asyncio.Task] = []

    # ── public entry point ───────────────────────────────────────────────────

    async def run(self, cancel_event: Optional[asyncio.Event] = None, on_progress: Optional[Callable] = None) -> WorkerState:
        """Run the full investigation loop. Returns final WorkerState."""
        self.state.status = "running"
        if on_progress:
            on_progress(self.state, "Starting")
        start_time = time.time()

        try:
            while (self.state.iteration < self.max_iterations
                   and not self.state.completed):

                # Check external cancellation (from aggregator)
                if cancel_event and cancel_event.is_set():
                    self.state.status = "cancelled"
                    break

                # 1. Think — decide next action
                if on_progress:
                    on_progress(self.state, "Thinking")
                action = await self._think()
                if not action:
                    break  # LLM gave up

                # Handle spawn_child request
                if action.get("spawn_child"):
                    # Start the child worker as an asyncio Task for concurrent execution
                    child_task = asyncio.create_task(
                        self._spawn_child_worker(
                            goal=action["child_goal"],
                            cancel_event=cancel_event,
                        )
                    )
                    
                    def _on_child_done(t):
                        try:
                            child_state = t.result()
                            if child_state:
                                self.state.confidence.update_from_child(child_state)
                                self.state.children.append(child_state)
                        except Exception:
                            pass

                    child_task.add_done_callback(_on_child_done)
                    self._active_children.append(child_task)
                    self.state.iteration += 1
                    continue

                tool_name = action.get("tool", "")
                tool_args = action.get("args", {})
                hypothesis_update = action.get("hypothesis_update", "")
                if hypothesis_update:
                    self.state.hypothesis = hypothesis_update

                # 2. Duplicate check
                exec_hash = self._hash(tool_name, tool_args)
                if exec_hash in self._execution_hashes:
                    self.state.findings.append({
                        "tool": tool_name, "args": tool_args,
                        "output": "BLOCKED: Duplicate tool execution. You must select a NEW tool or set 'done': true.",
                        "signal": "WARNING", "iteration": self.state.iteration,
                    })
                    self.state.tool_history.append(f"{tool_name}({json.dumps(tool_args)[:100]}) - BLOCKED: DUPLICATE")
                    self.state.iteration += 1
                    continue
                self._execution_hashes.add(exec_hash)
                self.state.last_tool = tool_name
                self.state.tool_history.append(f"{tool_name}({json.dumps(tool_args)[:100]})")

                # 3. Safety check
                approved, block_reason = self._safety_check(tool_name, tool_args)
                if not approved:
                    self.state.findings.append({
                        "tool": tool_name, "args": tool_args,
                        "output": f"BLOCKED: {block_reason}",
                        "signal": "BLOCKED", "iteration": self.state.iteration,
                    })
                    if "approval_required" in block_reason.lower():
                        self.state.requires_approval = True
                        self.state.status = "blocked"
                        break
                    self.state.iteration += 1
                    continue

                # 4. Execute tool
                if on_progress:
                    on_progress(self.state, f"Executing: {tool_name}")
                output = await self._execute_tool(tool_name, tool_args)
                if on_progress:
                    on_progress(self.state, f"Finished: {tool_name}")

                # 5. Rule observation (deterministic)
                rule_match = self.rule_observer.observe(output, tool_name)
                is_rule_root_cause = getattr(rule_match, "root_cause", False)

                finding_record = {
                    "tool": tool_name,
                    "args": tool_args,
                    "output": output[:1500],
                    "signal": rule_match.signal,
                    "finding": rule_match.finding,
                    "iteration": self.state.iteration,
                    "timestamp": time.time(),
                    # Evidence quality metadata
                    "evidence_type": "direct_error" if is_rule_root_cause else "observation",
                    "verified": is_rule_root_cause and rule_match.signal in ("CRITICAL", "FAILURE"),
                }
                self.state.findings.append(finding_record)

                if not rule_match.uncertain:
                    # Rule was decisive — update confidence from rules
                    self.state.confidence.update_from_rules(
                        rule_match.signal, rule_match.finding,
                        rule_match.matched_text, tool_name=tool_name,
                        is_root_cause=is_rule_root_cause,
                    )

                    # If this rule flags a definite root cause, complete immediately
                    if is_rule_root_cause:
                        # Fix 1: Auto-populate evidence state from actual observations.
                        # The rule broke the loop before the LLM could populate these fields,
                        # so we build them deterministically from real tool history.
                        executed_tools = [f"Executed: {t}" for t in self.state.tool_history[-5:]]
                        self.state.evidence_chain = executed_tools + [
                            f"Direct evidence [{rule_match.finding}]: {rule_match.matched_text[:200]}"
                        ]
                        self.state.evidence_chain_confidence = 1.0  # deterministic rule = certain
                        # Coverage is derived from signals that actually produced findings
                        self.state.investigation_coverage = list({
                            f.get("finding", "")
                            for f in self.state.findings
                            if f.get("signal") in ("FAILURE", "CRITICAL", "SUCCESS") and f.get("finding")
                        })
                        # Structured root_cause — no ambiguous "Found via rule:" prefix
                        self.state.root_cause = f"{rule_match.finding}: {rule_match.matched_text[:200]}"
                        self.state.completed = True
                        self.state.status = "completed"
                        break
                else:
                    # Uncertain — call LLM observe as fallback
                    llm_obs = await self._llm_observe(output, rule_match)
                    if llm_obs:
                        self.state.confidence.update_from_llm(
                            llm_obs.get("confidence", 0.3),
                            llm_obs.get("reasoning", ""),
                        )
                        finding_record["llm_observation"] = llm_obs.get("observation", "")
                        finding_record["evidence_type"] = llm_obs.get("evidence_type", "observation")
                        finding_record["verified"] = llm_obs.get("verified", False)
                        finding_record["relevance_score"] = llm_obs.get("relevance_score", 0.0)
                        
                        # Only accept an LLM root cause if it claims correlated/direct evidence
                        llm_ev_type = llm_obs.get("evidence_type", "observation")
                        if llm_obs.get("root_cause") and llm_ev_type in ("direct_error", "correlated"):
                            self.state.root_cause = llm_obs["root_cause"]
                            
                        # Update the latest evidence with LLM metadata
                        if self.state.confidence.evidence:
                            self.state.confidence.evidence[-1].verified = llm_obs.get("verified", False)
                            self.state.confidence.evidence[-1].evidence_type = llm_ev_type
                            self.state.confidence.evidence[-1].relevance_score = llm_obs.get("relevance_score", 0.0)
                        if llm_obs.get("recommendations"):
                            self.state.recommendations = llm_obs["recommendations"]

                self.state.iteration += 1

                # 6. Worker-level early termination
                if self.state.confidence.is_sufficient:
                    self.state.completed = True
                    self.state.status = "completed"
                    break

            # Iteration limit reached
            if not self.state.completed:
                self.state.status = "completed"  # report what we have
                self.state.completed = True

            # Await any pending children before returning
            if self._active_children:
                pending = [t for t in self._active_children if not t.done()]
                if pending:
                    await asyncio.gather(*pending, return_exceptions=True)

        except asyncio.CancelledError:
            self.state.status = "cancelled"
            if on_progress:
                on_progress(self.state, "Cancelled")
        except Exception as e:
            self.state.status = "failed"
            self.state.findings.append({
                "tool": "_worker_error", "args": {},
                "output": str(e), "signal": "WARNING",
                "finding": "worker_exception", "iteration": self.state.iteration,
            })
            if on_progress:
                on_progress(self.state, "Failed")

        self.state.total_duration = time.time() - start_time
        if self.state.status == "completed" and on_progress:
            on_progress(self.state, "Completed")
            
        return self.state

    # ── Think ────────────────────────────────────────────────────────────────

    async def _think(self) -> Optional[dict]:
        """LLM decides the next action: which tool, what args, updated hypothesis."""
        prior_findings_str = self._format_prior_findings()
        available_tools = self._describe_tools()

        is_child_note = f"\n[CHILD WORKER] Parent ID: {self.state.parent_id}\n" if self.state.is_child else ""
        parent_ctx_str = ""
        if self._parent_context:
            parent_ctx_str = f"\nParent context:\n" + "\n".join(
                f"  - {f.get('finding','')}: {str(f.get('output',''))[:200]}"
                for f in self._parent_context[:3]
            )

        expected_domains_str = ", ".join(self.state.expected_diagnostic_domains) if self.state.expected_diagnostic_domains else "None specified (determine appropriate domains yourself)"
        prompt = f"""You are an autonomous SRE investigation worker.{is_child_note}

INVESTIGATION GOAL: {self.state.goal}
EXPECTED DIAGNOSTIC DOMAINS: {expected_domains_str}
CURRENT HYPOTHESIS: {self.state.hypothesis or "Not yet established"}
CONFIDENCE: {self.state.confidence.score:.2f} (threshold: {WORKER_CONFIDENCE_THRESHOLD})
ITERATION: {self.state.iteration + 1} of {self.max_iterations}
TERMINAL WORKING DIRECTORY: {self.state.terminal_cwd or "Unknown"}
{parent_ctx_str}

PRIOR FINDINGS (most recent first):
{prior_findings_str}

ALREADY EXECUTED (do NOT repeat):
{chr(10).join(self.state.tool_history[-8:]) or "None yet"}

AVAILABLE TOOLS:
{available_tools}

RULES:
- Select the SINGLE MOST VALUABLE next action to advance the investigation.
- If investigating a service failure (e.g. nginx), STRICTLY PRIORITIZE direct service diagnostics (service status, config tests, logs) over basic reconnaissance like whoami or get_current_directory.
- EVIDENCE PRIORITY HIERARCHY (Higher overrides lower):
  1. Verified deterministic evidence (e.g. config syntax failure, explicit crash)
  2. Application/service specific failure logs
  3. Service state failures (systemd/service status)
  4. Generic environmental symptoms (e.g. permission denied, disk warnings, generic resource usage)
- Generic environmental symptoms MUST NOT override a direct service failure root cause.
- Read the AVAILABLE TOOLS carefully. Workers MUST ONLY select actions explicitly exposed by tool schemas. Never invent tool actions, parameters, or capabilities.
- For service config tests (e.g. nginx config validation), DO NOT invent actions for `service_manager`. You MUST use `linux_diagnostic_execute` to run the specific test command (e.g., `nginx -t`, `apache2ctl configtest`).
- Do NOT repeat a tool+args combination already in the ALREADY EXECUTED list. If you do, it will be BLOCKED.
- If a diagnostic domain has already been satisfied and verified, move to the next logical domain.
- RETRIEVAL PRIORITY: For SIMPLE_INFORMATION or data retrieval tasks, prioritize direct retrieval tools over investigative tools.
- If the goal contains a concrete file path AND `read_file` is available, you MUST use `read_file` immediately before attempting exploratory tools like `get_current_directory` or `search_files`.
- When a dedicated tool exists for a goal (e.g. get_current_directory, whoami), ALWAYS prefer it before attempting exploratory file system scans or indirect inference.
- If a sub-investigation is needed (e.g., network latency, DB connection), you may spawn a child worker.
- You may spawn a child worker while current depth < MAX_WORKER_DEPTH.
- CRITICAL: You MUST execute at least one tool before you can set "done": true. If no tools have been executed yet, you MUST choose Option A.
- Only set "done": true when you have actual tool output as evidence.
- To set "done": true, you MUST construct a logical `evidence_chain` grounded in actual observations (symptom -> mechanism -> failure root). Do NOT invent causal links. Each chain element must reference an observation, command output, or verified signal.
- The `evidence_chain_confidence` must be >= 0.8 for the root cause to be accepted.
- Do not conclude an investigation only because a suspicious metric exists. First verify that the metric explains the failure of the requested component.
- Example Bad Reasoning: "nginx down, memory high -> memory caused nginx failure"
- Example Good Reasoning: "nginx failed -> nginx worker disappeared -> journal shows OOM kill event -> kernel killed nginx because memory exhausted -> root cause: memory exhaustion"

Respond ONLY with valid JSON, one of:

Option A - Execute a tool:
{{
  "reasoning": "why this tool next",
  "tool": "tool_name",
  "args": {{"arg1": "value1"}},
  "hypothesis_update": "updated hypothesis",
  "done": false
}}

Option B - Spawn child worker (only if not already a child):
{{
  "reasoning": "why a sub-investigation is needed",
  "spawn_child": true,
  "child_goal": "Specific goal for the child worker",
  "hypothesis_update": "updated hypothesis",
  "done": false
}}

Option C - Done (sufficient evidence found):
{{
  "reasoning": "why investigation is complete",
  "done": true,
  "investigation_coverage": ["service_status", "service_logs"],
  "root_cause": "The identified root cause",
  "evidence_chain": ["symptom finding", "mechanism link", "failure root"],
  "evidence_chain_confidence": 0.95,
  "evidence_relevance_score": 0.9,
  "recommendations": ["step 1", "step 2"]
}}
"""
        try:
            response = await asyncio.get_running_loop().run_in_executor(
                None,
                lambda: self.llm.with_config({"tags": [f"worker_{self.state.id}_think"]}).invoke(
                    [HumanMessage(content=prompt)]
                )
            )
            raw = response.content
            if "```" in raw:
                raw = re.sub(r"```(?:json)?\s*", "", raw).strip("` \n")
            m = re.search(r'\{.*\}', raw, re.DOTALL)
            if not m:
                return None
            data = json.loads(m.group(0))

            if data.get("done"):
                # Safety guard 1: never allow done=true with zero findings
                if not self.state.findings:
                    data["done"] = False
                    return data  # force a tool execution on this iteration
                # Safety guard 2: block done=true if only observation-level findings exist.
                # A worker must have at least one direct_error/correlated/service_status
                # finding before concluding. Observations alone (e.g. high memory) are
                # insufficient — the worker must continue to verify the causal link.
                has_direct_evidence = any(
                    f.get("evidence_type") in ("direct_error", "correlated", "service_status")
                    for f in self.state.findings
                )
                if not has_direct_evidence:
                    data["done"] = False
                    data["hypothesis_update"] = (
                        data.get("hypothesis_update", "") or
                        f"Need direct evidence to confirm root cause: {data.get('root_cause', 'unknown')}"
                    )
                    return data  # continue investigating
                
                # Safety guard 3: enforce evidence chain
                chain = data.get("evidence_chain", [])
                chain_conf = data.get("evidence_chain_confidence", 0.0)
                if len(chain) < 2 or chain_conf < 0.8:
                    data["done"] = False
                    data["hypothesis_update"] = (
                        data.get("hypothesis_update", "") or
                        "Need to establish a grounded evidence chain (symptom -> mechanism -> failure) with confidence >= 0.8 before concluding."
                    )
                    return data  # continue investigating

                # Safety guard 4: enforce investigation coverage and relevance
                coverage = data.get("investigation_coverage", [])
                relevance = data.get("evidence_relevance_score", 0.0)
                expected_domains = self.state.expected_diagnostic_domains
                missing_domains = [d for d in expected_domains if d not in coverage]
                
                if missing_domains:
                    data["done"] = False
                    data["hypothesis_update"] = (
                        data.get("hypothesis_update", "") or
                        f"Need to investigate missing domains: {', '.join(missing_domains)} before concluding."
                    )
                    return data
                    
                if relevance < 0.8:
                    data["done"] = False
                    data["hypothesis_update"] = (
                        data.get("hypothesis_update", "") or
                        "Need evidence with relevance >= 0.8 that directly explains the failure."
                    )
                    return data

                self.state.root_cause = data.get("root_cause", "")
                self.state.evidence_chain = chain
                self.state.evidence_chain_confidence = chain_conf
                self.state.investigation_coverage = coverage
                
                # Mark latest evidence with the LLM's relevance score
                if self.state.confidence.evidence:
                    self.state.confidence.evidence[-1].relevance_score = relevance
                    
                self.state.recommendations = data.get("recommendations", [])
                self.state.completed = True
                self.state.status = "completed"
                return None

            return data

        except Exception:
            return None

    # ── LLM Observe fallback ─────────────────────────────────────────────────

    async def _llm_observe(self, tool_output: str, rule_match: RuleMatch) -> Optional[dict]:
        """LLM observation — only called when rule engine returns uncertain=True."""
        prior_signals = ", ".join(
            f"{f.get('signal','?')}/{f.get('evidence_type','?')}"
            for f in self.state.findings[-4:]
        )
        prompt = f"""You are an SRE evidence analyst. Analyze this tool output.

INVESTIGATION GOAL: {self.state.goal}
CURRENT HYPOTHESIS: {self.state.hypothesis}
PRIOR SIGNALS (recent): {prior_signals or 'None yet'}

TOOL OUTPUT:
{tool_output[:2000]}

Rules matched (uncertain): {rule_match.finding}

Evidence Classification Rules:
- "observation": Something you noticed (e.g. memory is high, CPU is busy). NOT a root cause by itself.
- "service_status": Direct status of a specific service (e.g. nginx is stopped, active=failed).
- "direct_error": A specific error message directly from the affected component's logs (e.g. nginx OOM kill, config syntax error).
- "correlated": You found two pieces of evidence that together form a causal chain (e.g. memory high + OOM kill timestamp matches nginx crash time).

Relevance Score (0.0 - 1.0):
- 0.0-0.3: Unrelated observation
- 0.4-0.7: Supporting signal (e.g. high memory but no direct link yet)
- 0.8-1.0: Directly explains the failure (e.g. OOM killer logs, config error)

CRITICAL RULES:
- An observation (e.g. high memory) is NOT a root cause unless you have direct evidence linking it to the failed component.
- Only set root_cause and verified=true if evidence_type is "direct_error" or "correlated".
- confidence 0.0-1.0. Be conservative; 0.9+ only if root cause is definitively identified with direct evidence.
- Never hallucinate. Base ONLY on the actual output above.
- If output is empty or uninformative, set confidence to 0.1.

Respond with ONLY valid JSON:
{{
  "observation": "What this output shows in 1-2 sentences",
  "evidence_type": "observation | service_status | direct_error | correlated",
  "relevance_score": 0.0,
  "verified": false,
  "confidence": 0.0,
  "reasoning": "why this confidence level",
  "root_cause": "identified root cause or null — only set if evidence_type is direct_error or correlated",
  "recommendations": ["step 1", "step 2"]
}}
"""
        try:
            response = await asyncio.get_running_loop().run_in_executor(
                None,
                lambda: self.llm.with_config({"tags": [f"worker_{self.state.id}_observe"]}).invoke(
                    [HumanMessage(content=prompt)]
                )
            )
            raw = response.content
            if "```" in raw:
                raw = re.sub(r"```(?:json)?\s*", "", raw).strip("` \n")
            m = re.search(r'\{.*\}', raw, re.DOTALL)
            if m:
                return json.loads(m.group(0))
        except Exception:
            pass
        return None

    # ── Tool execution ───────────────────────────────────────────────────────

    async def _execute_tool(self, tool_name: str, tool_args: dict) -> str:
        """Execute a tool safely with timeout."""
        tool_obj = self.tool_map.get(tool_name)
        if not tool_obj:
            return json.dumps({"error": f"Tool '{tool_name}' not found", "exit_code": 1})
        try:
            result = await asyncio.wait_for(
                asyncio.get_running_loop().run_in_executor(
                    None, lambda: tool_obj.invoke(tool_args)
                ),
                timeout=TOOL_TIMEOUT_SEC
            )
            return str(result)[:4000] if result else ""
        except asyncio.TimeoutError:
            return json.dumps({"error": f"Tool '{tool_name}' timed out after {TOOL_TIMEOUT_SEC}s", "exit_code": 1})
        except Exception as e:
            return json.dumps({"error": str(e), "exit_code": 1})

    # ── Child worker spawning ────────────────────────────────────────────────

    async def _spawn_child_worker(
        self,
        goal: str,
        cancel_event: Optional[asyncio.Event] = None,
    ) -> Optional[WorkerState]:
        """Spawn a child worker for sub-investigation. Depth limit based on MAX_WORKER_DEPTH."""
        if self._child_depth >= MAX_WORKER_DEPTH:
            return None  # reached max depth

        child = InvestigationWorker(
            worker_id=f"{self.state.id}_c{len(self.state.children)}",
            goal=goal,
            llm=self.llm,
            tool_map=self.tool_map,
            safety=self.safety,
            max_iterations=MAX_CHILD_ITERATIONS,
            is_child=True,
            parent_id=self.state.id,
            parent_context=self.state.findings[-3:],
        )
        child._child_depth = self._child_depth + 1

        try:
            child_state = await asyncio.wait_for(
                child.run(cancel_event=cancel_event),
                timeout=CHILD_TIMEOUT_SEC
            )
            return child_state
        except asyncio.TimeoutError:
            child.state.status = "failed"
            child.state.findings.append({
                "tool": "_timeout", "args": {}, "output": "Child timed out",
                "signal": "WARNING", "finding": "child_timeout",
                "iteration": child.state.iteration, "timestamp": time.time()
            })
            return child.state
        except Exception:
            return None

    # ── Safety check ─────────────────────────────────────────────────────────

    def _safety_check(self, tool_name: str, tool_args: dict) -> tuple[bool, str]:
        """Returns (approved: bool, reason: str)."""
        from .safety import SafetyVerdict
        meta = None
        try:
            from .tools.registry import ToolRegistry
            meta = ToolRegistry().get_metadata(tool_name)
        except Exception:
            pass

        if meta:
            result = self.safety.check(meta, tool_args)
            if result.verdict == SafetyVerdict.BLOCKED:
                return False, f"BLOCKED: {result.reason}"
            if result.verdict == SafetyVerdict.APPROVAL_REQUIRED:
                return False, f"approval_required: {result.reason}"
        return True, ""

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _format_prior_findings(self) -> str:
        if not self.state.findings:
            return "None yet."
        recent = self.state.findings[-5:]  # last 5 findings for context
        lines = []
        for f in reversed(recent):
            out = str(f.get("output", ""))[:400]
            lines.append(
                f"  [{f.get('signal','?')}] {f.get('tool','?')} → {f.get('finding','?')}: {out}"
            )
        return "\n".join(lines)

    def _describe_tools(self) -> str:
        lines = []
        for name, tool_obj in list(self.tool_map.items())[:15]:
            desc = getattr(tool_obj, "description", "")[:120]
            # Extract argument names from tool schema if available
            args_str = ""
            try:
                schema = tool_obj.args_schema.model_json_schema() if hasattr(tool_obj, "args_schema") and tool_obj.args_schema else {}
                props = schema.get("properties", {})
                if props:
                    args_str = " | args: " + ", ".join(
                        f"{k}({v.get('type','any')})" for k, v in props.items()
                    )
            except Exception:
                pass
            lines.append(f"  {name}{args_str}: {desc}")
        return "\n".join(lines)

    @staticmethod
    def _hash(tool_name: str, tool_args: dict) -> str:
        key = json.dumps({"t": tool_name, "a": tool_args}, sort_keys=True)
        return hashlib.md5(key.encode()).hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# Worker Scheduler
# ─────────────────────────────────────────────────────────────────────────────

class WorkerScheduler:
    """
    Launches multiple InvestigationWorkers concurrently.

    Multi-level early termination:
    - Worker-level: worker self-terminates when confidence >= WORKER_THRESHOLD
    - Aggregator-level: cancel_event fired when global confidence >= GLOBAL_THRESHOLD
    """

    MAX_CONCURRENT_WORKERS = 5

    def __init__(self, llm, tool_map: Dict[str, Any], safety,
                 global_threshold: float = GLOBAL_CONFIDENCE_THRESHOLD):
        self.llm = llm
        self.tool_map = tool_map
        self.safety = safety
        self.global_threshold = global_threshold

    async def run_workers(
        self,
        worker_specs: List[dict],
        on_worker_start: Optional[Callable] = None,
        on_worker_complete: Optional[Callable] = None,
    ) -> List[WorkerState]:
        """
        Execute workers concurrently. Returns all WorkerState results.

        worker_specs: list of {"id": "A", "goal": "...", "depends_on": []}
        """
        if not worker_specs:
            return []

        semaphore = asyncio.Semaphore(self.MAX_CONCURRENT_WORKERS)
        cancel_event = asyncio.Event()
        results: List[Optional[WorkerState]] = [None] * len(worker_specs)
        active_workers_state = {}

        def _on_worker_progress(ws: WorkerState, current_action: str = ""):
            # Maintain active worker list without overwriting the object itself
            active_workers_state[ws.id] = {
                "id": ws.id,
                "goal": ws.goal,
                "current_action": current_action,
                "last_tool": getattr(ws, "last_tool", None),
                "findings_count": len(ws.findings),
                "evidence_count": len(ws.confidence.evidence)
            }
            try:
                from langchain_core.callbacks.manager import dispatch_custom_event
                dispatch_custom_event("worker_activity", {"workers": list(active_workers_state.values())})
            except Exception:
                pass

        async def run_single(idx: int, spec: dict) -> None:
            async with semaphore:
                if cancel_event.is_set():
                    results[idx] = WorkerState(
                        id=spec["id"], goal=spec.get("goal", ""),
                        status="cancelled", completed=True
                    )
                    return

                goal = spec.get("goal", "Investigate")
                # Extract file:// URIs from goal and resolve to absolute paths
                # so workers receive concrete paths, not placeholders
                import re as _re
                file_uri_pattern = _re.compile(r'file:///([^\s]+)')
                file_uri_matches = file_uri_pattern.findall(goal)
                if file_uri_matches:
                    # Replace file:// URIs with absolute paths inline
                    for fpath in file_uri_matches:
                        goal = goal.replace(f'file:///{fpath}', f'/{fpath}')
                    # Also append a clear instruction so planner worker goal includes it
                    resolved_paths = [f'/{p}' for p in file_uri_matches]
                    goal = goal + f" [FILE PATH: {', '.join(resolved_paths)}]"

                worker = InvestigationWorker(
                    worker_id=spec["id"],
                    goal=goal,
                    llm=self.llm,
                    tool_map=self.tool_map,
                    safety=self.safety,
                    max_iterations=spec.get("max_iterations", MAX_WORKER_ITERATIONS),
                )

                if on_worker_start:
                    await _maybe_await(on_worker_start, spec["id"], spec.get("goal", ""))

                state = await worker.run(cancel_event=cancel_event, on_progress=_on_worker_progress)
                results[idx] = state

                if on_worker_complete:
                    await _maybe_await(on_worker_complete, spec["id"], state)

                # Fix 4: Cancel remaining workers when any worker finds verified root-cause evidence.
                # Previously score-gated at 0.90, but a FAILURE rule scores only 0.60,
                # so parallel workers kept running unrelated diagnostics.
                if state.confidence.has_verified_evidence or state.confidence.score >= self.global_threshold:
                    cancel_event.set()

        await asyncio.gather(*[run_single(i, spec) for i, spec in enumerate(worker_specs)],
                              return_exceptions=True)

        return [r for r in results if r is not None]

    def run_workers_sync(self, worker_specs: List[dict]) -> List[WorkerState]:
        """Synchronous entry point — bridges asyncio from sync LangGraph node."""
        import concurrent.futures
        try:
            try:
                loop = asyncio.get_running_loop()
                is_running = loop.is_running()
            except RuntimeError:
                is_running = False
            if is_running:
                # Inside async context (ASGI/Django channels)
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    future = pool.submit(asyncio.run, self.run_workers(worker_specs))
                    return future.result(timeout=300)
            else:
                return asyncio.run(self.run_workers(worker_specs))
        except Exception as e:
            # Absolute fallback: single-threaded sequential
            states = []
            for spec in worker_specs:
                state = WorkerState(id=spec["id"], goal=spec.get("goal", ""),
                                    status="failed")
                state.findings.append({"tool": "_error", "args": {},
                                        "output": str(e), "signal": "WARNING",
                                        "finding": "scheduler_error",
                                        "iteration": 0, "timestamp": time.time()})
                states.append(state)
            return states


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

async def _maybe_await(fn: Callable, *args) -> Any:
    result = fn(*args)
    if asyncio.iscoroutine(result):
        return await result
    return result


# Deferred import to avoid circular deps at module level
def _get_human_message():
    from langchain_core.messages import HumanMessage
    return HumanMessage

# Patch HumanMessage into the module-level Think/Observe methods
# (imported at the top of the file body where used)
try:
    from langchain_core.messages import HumanMessage
except ImportError:
    HumanMessage = None  # type: ignore
