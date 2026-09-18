"""Data exfiltration detection - high outbound byte transfers."""
from backend.models.events import OCSFBaseEvent
from detections.rules.base import BaseRule

BYTES_THRESHOLD = 10_000_000  # 10 MB


class DataExfiltrationRule(BaseRule):
    name = "data_exfiltration"

    async def evaluate(self, log: OCSFBaseEvent, windows: dict) -> dict | None:
        bytes_out = 0 or 0
        is_exfil = (
            (log.class_name.lower() if log.class_name else "") == "data_exfiltration"
            or bytes_out >= BYTES_THRESHOLD
            or "exfil" in (log.message or "").lower()
        )
        if not is_exfil:
            return None

        mb = bytes_out // 1_000_000
        return {
            "title": f"Data Exfiltration Detected from {getattr(log, 'hostname', None)}",
            "description": (
                f"Large outbound data transfer detected: {mb}MB from "
                f"{getattr(log, 'hostname', None)} to {log.dst_ip}"
            ),
            "severity": "critical",
            "rule_name": self.name,
            "mitre_techniques": ["T1041", "T1048", "T1030"],
            "tags": ["data_exfiltration", "exfiltration", "insider_threat"],
        }
