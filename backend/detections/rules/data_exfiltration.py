"""Data exfiltration detection — high outbound byte transfers."""
from detections.rules.base import BaseRule

BYTES_THRESHOLD = 10_000_000  # 10 MB


class DataExfiltrationRule(BaseRule):
    name = "data_exfiltration"

    async def evaluate(self, log: dict, windows: dict) -> dict | None:
        bytes_out = log.get("bytes_out", 0) or 0
        is_exfil = (
            log.get("event_type") == "data_exfiltration"
            or bytes_out >= BYTES_THRESHOLD
            or "exfil" in log.get("message", "").lower()
        )
        if not is_exfil:
            return None

        mb = bytes_out // 1_000_000
        return {
            "title": f"Data Exfiltration Detected from {log.get('hostname', 'unknown')}",
            "description": (
                f"Large outbound data transfer detected: {mb}MB from "
                f"{log.get('hostname', 'unknown')} to {log.get('dest_ip', 'unknown')}"
            ),
            "severity": "critical",
            "rule_name": self.name,
            "mitre_techniques": ["T1041", "T1048", "T1030"],
            "tags": ["data_exfiltration", "exfiltration", "insider_threat"],
        }
