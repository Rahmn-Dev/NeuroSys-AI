"""Evidence coverage checklists.

An SRE answer is only as good as the checks behind it. A network anomaly
question cannot be closed after one `ss -tuln`: brute force, flood traffic and
exposure are different investigations. Each domain lists the checks that must
be covered, so the loop can rotate to the next missing objective instead of
repeating what it already proved, and so the final answer states what is still
unverified.
"""
from __future__ import annotations

import re

# id -> (label, command hint)
CHECKLISTS: dict[str, dict[str, tuple[str, str]]] = {
    "network_anomaly": {
        "listeners": ("listening sockets and exposed ports", "ss -tulpn"),
        "established": ("established connections and peers", "ss -tan state established"),
        "states": ("socket state distribution (TIME_WAIT / CLOSE_WAIT / SYN_RECV)", "ss -tan | awk '{print $1}' | sort | uniq -c"),
        "counters": ("TCP/IP counters: retransmits, resets, errors, discards", "cat /proc/net/snmp"),
        "interface": ("per-interface traffic, drops and errors", "ip -s link"),
        "route": ("routing table and gateway", "ip route show"),
        "gateway_latency": ("baseline latency to the internet", "ping -c 4 1.1.1.1"),
        "gateway_ports": ("services exposed on the gateway", "sudo nmap -sV -p 22,80,443,8080 <gw>"),
        "neighbours": ("ARP / neighbour table anomalies", "ip neigh"),
        "firewall": ("firewall rules and counters", "sudo iptables -L -n -v"),
        "dns": ("resolver configuration", "cat /etc/resolv.conf"),
        "capture": ("short packet capture sample", "sudo tcpdump -i any -n -c 50"),
    },
    "bruteforce": {
        "auth_failures": ("failed authentication attempts", "sudo journalctl -u ssh --since '-1 hour' | grep -ci 'failed password'"),
        "source_concentration": ("source IPs behind the failures", "sudo journalctl -u ssh --since '-1 hour' | grep -i 'failed password' | awk '{print $NF}' | sort | uniq -c | sort -rn | head"),
        "success_after_fail": ("successful logins following failures", "sudo journalctl -u ssh --since '-1 hour' | grep -i 'accepted' | tail -30"),
        "valid_users": ("accounts targeted", "sudo journalctl -u ssh --since '-1 hour' | grep -i 'failed password' | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn"),
        "sshd_config": ("sshd hardening settings", "sudo sshd -T | grep -Ei 'maxauthtries|permitroot|passwordauth|allowusers'"),
        "fail2ban": ("ban list and fail2ban state", "sudo fail2ban-client status sshd"),
        "auth_log": ("auth log summary", "sudo journalctl _COMM=sshd --since '-1 hour' --no-pager | tail -50"),
        "firewall": ("firewall rules blocking the source", "sudo iptables -L -n -v"),
        "rate": ("attempt rate over time", "sudo journalctl -u ssh --since '-1 hour' | grep -i 'failed password' | awk '{print $1, $2, substr($3,1,2)}' | uniq -c"),
    },
    "flood_ddos": {
        "syn_state": ("SYN_RECV / SYN_SENT volume", "ss -tan | grep -c SYN_RECV"),
        "retransmits": ("retransmission volume", "cat /proc/net/snmp | grep '^Tcp:'"),
        "conntrack": ("connection tracking table usage", "sudo conntrack -C 2>/dev/null || cat /proc/sys/net/netfilter/nf_conntrack_count"),
        "bandwidth": ("interface throughput and drops", "ip -s link"),
        "packet_rate": ("packet sample rate", "sudo tcpdump -i any -n -c 200 -q | tail -5"),
        "udp_sources": ("UDP source concentration", "sudo ss -uan | awk '{print $5}' | sort | uniq -c | sort -rn | head"),
        "established_flood": ("established connection concentration", "ss -tan state established | awk '{print $4}' | cut -d: -f1 | sort | uniq -c | sort -rn | head"),
        "backlog": ("accept queue pressure", "ss -ltn; cat /proc/sys/net/core/somaxconn; cat /proc/sys/net/ipv4/tcp_max_syn_backlog"),
        "firewall": ("rate limiting or blocking rules", "sudo iptables -L -n -v"),
        "uptime_load": ("load average and CPU saturation", "uptime; top -bn1 | head -5"),
    },
    "service_health": {
        "unit_state": ("unit state", "systemctl status <unit>"),
        "failed_units": ("all failed units", "systemctl --failed --no-pager"),
        "recent_logs": ("recent unit logs", "sudo journalctl -u <unit> -n 100 --no-pager"),
        "listening": ("is it listening and on which port", "ss -tulpn | grep <port>"),
        "local_health": ("local health endpoint", "curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:<port>/"),
        "process": ("process health and restarts", "ps aux | grep <proc>"),
        "restart_policy": ("restart policy and count", "systemctl show <unit> | grep -E 'Restart|NRestarts'"),
        "resources": ("memory and cpu of the process", "ps -o pid,%cpu,%mem,rss,cmd -p <pid>"),
        "dependencies": ("dependencies it needs", "ss -tanp | grep <pid>"),
        "disk": ("disk space for its data path", "df -h"),
    },
    "resource_issue": {
        "top_cpu": ("top cpu consumers", "ps aux --sort=-%cpu | head -10"),
        "top_mem": ("top memory consumers", "ps aux --sort=-%mem | head -10"),
        "load": ("load average", "uptime"),
        "disk_usage": ("filesystem usage", "df -h"),
        "inodes": ("inode usage", "df -i"),
        "big_dirs": ("largest directories", "sudo du -xh --max-depth=2 / | sort -rh | head -20"),
        "memory_pressure": ("swap and memory pressure", "free -h; cat /proc/pressure/memory"),
        "kernel": ("kernel and hardware errors", "sudo dmesg -T | grep -Ei 'error|oom|thermal' | tail -30"),
        "process_count": ("process and thread count", "ps -eLf | wc -l"),
        "cgroup_limits": ("cgroup limits", "systemctl show <unit> | grep -E 'MemoryMax|CPUQuota|TasksMax'"),
    },
}

_DOMAIN_PATTERNS = (
    ("bruteforce", r"brute ?force|bruteforce|ssh attack|failed password|login attack|password attack|auth attack|penetrasi|serangan brute"),
    ("flood_ddos", r"\bddos\b|denial of service|flood|syn flood|udp flood|icmp flood|paket floods?|serangan ddos|lodi|anomali (jaringan|network)|network anomaly|traffic spike|lalu lintas (network|traffic) (meningkat|tiba)"),
    ("network_anomaly", r"network|jaringan|anomali|anomaly|koneksi|connection|packet|traffic|lalu lintas|port|tcp|udp|arp|dns|socket|interface|router"),
    ("service_health", r"service|servis|lgi|service manager|systemctl|unit|\.service|health check|healthcheck|status layanan|aplikasi|application"),
    ("resource_issue", r"disk|cpu|ram|memory|storage|space|penuh|full|slow|lambat|hang|loading|resource|memory leak|swap|load"),
)


def domain_for(goal: str) -> str | None:
    text = str(goal or "").lower()
    for name, pattern in _DOMAIN_PATTERNS:
        if re.search(pattern, text, re.I):
            return name
    return None


def checklist_for(goal: str) -> dict[str, tuple[str, str]]:
    return dict(CHECKLISTS.get(domain_for(goal) or "", {}))


_GENERIC = {"the", "and", "for", "with", "from", "this", "that", "count", "usage", "state",
            "list", "table", "rules", "settings", "summary", "sample", "anomalies", "volume",
            "pressure", "every", "over", "time", "are", "was", "per", "raw", "top", "all"}


def _tokens(hint: str) -> set:
    """Distinctive tokens of a check: command names, flags, paths, counters."""
    out = set()
    for raw in re.findall(r"[A-Za-z0-9_./|%:@-]+", str(hint or "")):
        token = raw.strip("|'\"")
        if len(token) < 3:
            continue
        low = token.lower()
        if low in _GENERIC:
            continue
        out.add(low)
    return out


def coverage_from_commands(commands: list, goal: str) -> set:
    """Which checklist items the executed commands already cover.

    Matching is token based rather than literal, so `ss -tuln` still counts as
    the listening-sockets check whose hint says `ss -tulpn`.
    """
    checks = checklist_for(goal)
    if not checks:
        return set()
    blob = "\n".join(str(c or "") for c in commands).lower()
    covered = set()
    for item_id, (label, hint) in checks.items():
        tokens = _tokens(hint) | _tokens(label)
        if not tokens:
            continue
        def _matched(token: str) -> bool:
            if token in blob:
                return True
            # `ss -tuln` must satisfy a `ss -tulpn` hint, so a long flag only
            # needs its distinctive head to be present.
            return len(token) >= 4 and token[:4] in blob

        hits = sum(1 for token in tokens if _matched(token))
        # A single strong token (a command name or a specific counter) is enough;
        # otherwise ask for most of them.
        strong = {t for t in tokens if t.startswith(("-", "/", "nf_", "tcp_")) or len(t) >= 6}
        if hits >= 2 or (strong and hits >= 1):
            covered.add(item_id)
    return covered


def next_objective(goal: str, covered: set[str], attempts: int = 0) -> tuple[str, str] | None:
    """The next uncovered check, described as a single objective line."""
    checks = checklist_for(goal)
    if not checks:
        return None
    missing = [(i, v) for i, v in checks.items() if i not in covered]
    if not missing:
        return None
    # Rotate past the ones already attempted so a slice never spins on one gap.
    if attempts:
        missing = missing[attempts % len(missing):] + missing[:attempts % len(missing)]
    item_id, (label, hint) = missing[0]
    return item_id, f"Next objective: verify {label}. Suggested command: {hint}"


def render_coverage_report(goal: str, covered: set[str]) -> str:
    checks = checklist_for(goal)
    if not checks:
        return ""
    done = [f"{label} [{item_id}]" for item_id, (label, _) in checks.items() if item_id in covered]
    missing = [f"{label} [{item_id}]" for item_id, (label, _) in checks.items() if item_id not in covered]
    lines = [f"Coverage for this investigation ({len(done)}/{len(checks)} checks):"]
    if done:
        lines.append("Covered: " + "; ".join(done))
    if missing:
        lines.append("Not verified: " + "; ".join(missing))
    return "\n".join(lines)
