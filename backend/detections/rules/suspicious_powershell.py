"""Suspicious PowerShell detection - encoded commands, download cradles."""
from backend.models.events import OCSFBaseEvent
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

    async def evaluate(self, log: OCSFBaseEvent, windows: dict) -> dict | None:
        if getattr(log, 'process', None).lower() not in ("powershell.exe", "pwsh.exe"):
            if "powershell" not in (log.message or "").lower():
                if (log.class_name.lower() if log.class_name else "") != "suspicious_powershell":
                    return None

        raw = (getattr(log, 'raw_log', None) + (log.message or "") + getattr(log, 'powershell_payload', None)).lower()
        matched = [p for p in SUSPICIOUS_PATTERNS if p in raw]

        if not matched:
            return None

        return {
            "title": f"Suspicious PowerShell Activity on {getattr(log, 'hostname', None)}",
            "description": (
                f"Suspicious PowerShell patterns detected: [{', '.join(matched[:3])}] "
                f"by {getattr(log, 'username', None)} on {getattr(log, 'hostname', None)}"
            ),
            "severity": "critical",
            "rule_name": self.name,
            "mitre_techniques": ["T1059.001", "T1027", "T1140"],
            "tags": ["powershell", "execution", "defense_evasion"],
        }
