"""Suspicious PowerShell detection — encoded commands, download cradles."""
from detections.rules.base import BaseRule

SUSPICIOUS_PATTERNS = [
    "-encodedcommand", "-enc ", "-nop ", "-noprofile",
    "downloadstring", "downloadfile", "iex(", "invoke-expression",
    "hidden", "-exec bypass", "webclient", "net.webclient",
    "system.net.sockets.tcpclient", "mimikatz", "invoke-mimikatz",
    "invoke-bloodhound", "sharphound", "powersploit", "empire",
    "cobalt", "meterpreter",
]


class SuspiciousPowerShellRule(BaseRule):
    name = "suspicious_powershell"

    async def evaluate(self, log: dict, windows: dict) -> dict | None:
        if log.get("process", "").lower() not in ("powershell.exe", "pwsh.exe"):
            if "powershell" not in log.get("message", "").lower():
                if log.get("event_type") != "suspicious_powershell":
                    return None

        raw = (log.get("raw_log", "") + log.get("message", "") + log.get("powershell_payload", "")).lower()
        matched = [p for p in SUSPICIOUS_PATTERNS if p in raw]

        if not matched:
            return None

        return {
            "title": f"Suspicious PowerShell Activity on {log.get('hostname', 'unknown')}",
            "description": (
                f"Suspicious PowerShell patterns detected: [{', '.join(matched[:3])}] "
                f"by {log.get('username', 'unknown')} on {log.get('hostname', 'unknown')}"
            ),
            "severity": "critical",
            "rule_name": self.name,
            "mitre_techniques": ["T1059.001", "T1027", "T1140"],
            "tags": ["powershell", "execution", "defense_evasion"],
        }
