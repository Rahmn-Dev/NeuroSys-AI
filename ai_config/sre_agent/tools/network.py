"""
Network diagnostic tools — ports, connectivity, DNS, firewall, nginx.

All tools registered in the global ToolRegistry on import.
"""

import subprocess

from langchain_core.tools import tool

from .registry import ToolRegistry, ToolMetadata, RiskLevel


def _run(cmd: str, timeout: int = 15) -> str:
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        out = (r.stdout + "\n" + r.stderr).strip()
        if len(out) > 3000:
            out = out[:3000] + "\n... (output truncated)"
        return out or "(no output)"
    except subprocess.TimeoutExpired:
        return f"Error: Command timed out after {timeout}s"
    except Exception as e:
        return f"Error: {e}"


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------

@tool
def port_checker(port: int = 0, protocol: str = "tcp") -> str:
    """Check which ports are listening on this system.
    If `port` is specified, check only that port. Otherwise list all listening ports.
    `protocol` can be 'tcp', 'udp', or 'all'."""
    if port:
        return _run(f"ss -{'t' if protocol == 'tcp' else 'u' if protocol == 'udp' else 'tu'}lpn sport = :{port}")
    else:
        return _run("ss -tulpn | head -40")


@tool
def connectivity_test(target: str, method: str = "ping") -> str:
    """Test network connectivity to a target host.
    `method`: ping, curl, traceroute.
    `target`: hostname or IP address."""
    if method == "ping":
        return _run(f"ping -c 3 -W 2 {target}", timeout=10)
    elif method == "curl":
        return _run(f"curl -sS -o /dev/null -w 'HTTP %{{http_code}} | Time: %{{time_total}}s | Size: %{{size_download}} bytes' {target}", timeout=10)
    elif method == "traceroute":
        return _run(f"traceroute -m 15 {target}", timeout=30)
    else:
        return "Unknown method. Use: ping, curl, traceroute."


@tool
def dns_lookup(domain: str, record_type: str = "A") -> str:
    """Perform DNS lookup for a domain.
    `record_type`: A, AAAA, MX, NS, TXT, CNAME, SOA."""
    return _run(f"dig +short {domain} {record_type} 2>/dev/null || nslookup {domain}")


@tool
def firewall_status(action: str = "status") -> str:
    """Check firewall status and rules.
    `action`: status, rules, ports."""
    if action == "status":
        return _run("ufw status verbose 2>/dev/null || iptables -L -n --line-numbers 2>/dev/null | head -40")
    elif action == "rules":
        return _run("ufw status numbered 2>/dev/null || iptables -L -n -v --line-numbers 2>/dev/null | head -50")
    elif action == "ports":
        return _run("ufw status 2>/dev/null | grep -E 'ALLOW|DENY' || iptables -L INPUT -n --line-numbers 2>/dev/null | head -30")
    else:
        return "Unknown action. Use: status, rules, ports."


@tool
def nginx_status(action: str = "status") -> str:
    """Check Nginx web server status and configuration.
    `action`: status, config_test, sites, connections."""
    if action == "status":
        return _run("systemctl status nginx --no-pager 2>&1 | head -20")
    elif action == "config_test":
        return _run("nginx -t 2>&1")
    elif action == "sites":
        return _run("ls -la /etc/nginx/sites-enabled/ 2>/dev/null && echo '---' && ls -la /etc/nginx/conf.d/ 2>/dev/null")
    elif action == "connections":
        return _run("ss -tlpn | grep -E ':80|:443|nginx'")
    else:
        return "Unknown action. Use: status, config_test, sites, connections."


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def register_network_tools() -> None:
    """Register all network tools in the global ToolRegistry."""
    registry = ToolRegistry()
    registry.bulk_register([
        (port_checker, ToolMetadata(
            name="port_checker",
            description="Check listening ports on this system, or check if a specific port is open",
            category="network",
            risk_level=RiskLevel.LOW,
            input_schema={"port": "int (optional — 0 means list all)", "protocol": "tcp|udp|all"},
            examples=["port_checker(80)", "port_checker()"],
            keywords=["port", "listen", "socket", "ss", "netstat", "open", "bind"],
        )),
        (connectivity_test, ToolMetadata(
            name="connectivity_test",
            description="Test network connectivity using ping, curl, or traceroute",
            category="network",
            risk_level=RiskLevel.LOW,
            input_schema={"target": "string (host/URL)", "method": "ping|curl|traceroute"},
            examples=["connectivity_test('google.com', 'ping')", "connectivity_test('https://example.com', 'curl')"],
            keywords=["ping", "curl", "connectivity", "network", "traceroute", "reach", "down", "timeout"],
        )),
        (dns_lookup, ToolMetadata(
            name="dns_lookup",
            description="Perform DNS lookup — resolve domain names to IPs, check MX/NS/TXT records",
            category="network",
            risk_level=RiskLevel.LOW,
            input_schema={"domain": "string", "record_type": "A|AAAA|MX|NS|TXT|CNAME|SOA"},
            examples=["dns_lookup('example.com', 'A')", "dns_lookup('example.com', 'MX')"],
            keywords=["dns", "resolve", "domain", "dig", "nslookup", "record"],
        )),
        (firewall_status, ToolMetadata(
            name="firewall_status",
            description="Check firewall (ufw/iptables) status and rules",
            category="network",
            risk_level=RiskLevel.LOW,
            input_schema={"action": "status|rules|ports"},
            examples=["firewall_status('status')"],
            keywords=["firewall", "ufw", "iptables", "rules", "block", "allow", "security"],
        )),
        (nginx_status, ToolMetadata(
            name="nginx_status",
            description="Check Nginx status, test config, list sites, check connections",
            category="network",
            risk_level=RiskLevel.LOW,
            input_schema={"action": "status|config_test|sites|connections"},
            examples=["nginx_status('config_test')", "nginx_status('status')"],
            keywords=["nginx", "web", "server", "proxy", "reverse", "config", "site", "502", "503", "504"],
        )),
    ])
