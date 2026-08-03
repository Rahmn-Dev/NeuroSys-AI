import subprocess
from langchain_core.tools import tool
from .registry import ToolRegistry, RiskLevel

@tool
def list_open_ports() -> str:
    """Lists all open TCP/UDP ports on the server."""
    try:
        result = subprocess.run(
            ["ss", "-tuln"],
            capture_output=True, text=True, timeout=5
        )
        return f"Open Ports:\n{result.stdout}"
    except Exception as e:
        return f"Error listing open ports: {e}"

@tool
def firewall_status() -> str:
    """Checks the status of the UFW firewall."""
    try:
        result = subprocess.run(
            ["ufw", "status"],
            capture_output=True, text=True, timeout=5
        )
        return f"Firewall Status:\n{result.stdout}"
    except Exception as e:
        return f"Error checking firewall: {e}"

@tool
def ssh_security_check() -> str:
    """Checks common SSH security configurations."""
    try:
        with open("/etc/ssh/sshd_config", "r") as f:
            content = f.read()
            
        findings = []
        if "PermitRootLogin yes" in content:
            findings.append("Finding: Root Login Enabled | Severity: HIGH | Recommendation: Disable PermitRootLogin | Remediation: Set PermitRootLogin to no")
        if "PasswordAuthentication yes" in content:
            findings.append("Finding: Password Auth Enabled | Severity: MEDIUM | Recommendation: Use SSH Keys | Remediation: Set PasswordAuthentication to no")
            
        if not findings:
            return "SSH Configuration appears secure (Root login disabled, Password auth not explicitly enabled in standard form)."
            
        return "SSH Security Findings:\n" + "\n".join(findings)
    except Exception as e:
        return f"Error checking SSH config: {e}"

def register_security_tools():
    from .registry import ToolMetadata
    registry = ToolRegistry()
    registry.register(list_open_ports, ToolMetadata(name="list_open_ports", description="Lists open ports", category="security", risk_level=RiskLevel.LOW))
    registry.register(firewall_status, ToolMetadata(name="firewall_status", description="Checks firewall status", category="security", risk_level=RiskLevel.LOW))
    registry.register(ssh_security_check, ToolMetadata(name="ssh_security_check", description="Checks SSH security", category="security", risk_level=RiskLevel.LOW))
