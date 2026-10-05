"""Bounded read-only coverage for whole-system health questions.

These are server-side probes, not agent tools: the model never sees a schema
for them, so health coverage costs no prompt tokens and cannot be mis-selected.
Each probe is a fixed read-only pipeline with its own timeout.
"""
import asyncio
import re
from datetime import datetime, timezone


def requests_system_health(goal):
    return bool(re.search(r'\b(system|server|host)\b.{0,35}\b(health|healthy|status|check)\b|\b(health|healthy)\b.{0,35}\b(system|server|host)\b', goal, re.I))


# (aspect, shell pipeline, needs_sudo_hint)
_PROBES = [
    ("cpu", "top -bn1 | head -5"),
    ("memory", "free -h"),
    ("disk", "df -h /"),
    ("inodes", "df -i /"),
    ("uptime_load", "uptime"),
    ("failed_units", "systemctl --failed --no-pager 2>&1 | head -20"),
    ("service_states", "systemctl list-units --type=service --state=running --no-pager 2>&1 | head -25"),
]

_FAILURE = re.compile(r"error|failed to|not been booted|not found|permission denied|refused", re.I)


async def _probe(command: str, timeout: float = 10.0) -> str:
    proc = await asyncio.create_subprocess_shell(
        command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return "probe timed out"
    return (out or b"").decode("utf-8", "replace").strip()


async def collect_health_evidence(registry=None):
    """Collect the standard health picture. `registry` is accepted and ignored
    so existing call sites keep working."""
    from django.conf import settings

    checks = list(_PROBES)
    for service in getattr(settings, "AGENT_HEALTH_SERVICES", ("nginx", "postgresql", "ssh"))[:10]:
        checks.append((f"service:{service}", f"systemctl is-active {service} 2>&1"))

    evidence = []
    for aspect, command in checks:
        source = command.split()[0]
        try:
            content = await _probe(command)
            failed = (not content) or bool(_FAILURE.search(content)) and aspect != "failed_units"
            if aspect == "failed_units":
                # A non-empty list of failed units is the finding, not a failure
                # of collection.
                failed = "no failed units" in content.lower()
            evidence.append(dict(
                aspect=aspect,
                source=source,
                status="collection_failed" if failed else "collected",
                content=content[:1800],
                collected_at=datetime.now(timezone.utc).isoformat(),
            ))
        except Exception as exc:
            evidence.append(dict(aspect=aspect, source=source, status="collection_failed",
                                 content=type(exc).__name__,
                                 collected_at=datetime.now(timezone.utc).isoformat()))
    return evidence
