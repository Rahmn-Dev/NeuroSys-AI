"""Bounded read-only coverage for whole-system health questions."""
import asyncio
import re
from datetime import datetime, timezone


def requests_system_health(goal):
    return bool(re.search(r'\b(system|server|host)\b.{0,35}\b(health|healthy|status|check)\b|\b(health|healthy)\b.{0,35}\b(system|server|host)\b', goal, re.I))


async def collect_health_evidence(registry):
    checks = [
        ('cpu', 'get_cpu_usage', {}),
        ('memory', 'get_memory_usage', {}),
        ('disk', 'get_disk_usage', {'path': '/'}),
        ('uptime_load', 'system_info', {'aspect': 'uptime'}),
        ('failed_units', 'service_manager', {'action': 'failed'}),
        ('service_states', 'service_manager', {'action': 'list'}),
    ]
    from django.conf import settings
    for service in getattr(settings, "AGENT_HEALTH_SERVICES", ("nginx", "postgresql", "ssh"))[:10]:
        checks.append(("service:" + service, "service_manager", {"action": "is-active", "service_name": service}))
    evidence = []
    for aspect, name, args in checks:
        tool = registry.get_tool(name)
        try:
            if tool is None:
                raise LookupError('collector unavailable')
            result = str(await asyncio.wait_for(tool.ainvoke(args), timeout=10))
            failed = bool(re.search(r'error|failed to|not been booted|not found|permission denied', result, re.I))
            evidence.append(dict(aspect=aspect, source=name, status='collection_failed' if failed else 'collected',
                                 content=result[:1800], collected_at=datetime.now(timezone.utc).isoformat()))
        except Exception as exc:
            evidence.append(dict(aspect=aspect, source=name, status='collection_failed',
                                 content=type(exc).__name__, collected_at=datetime.now(timezone.utc).isoformat()))
    return evidence
