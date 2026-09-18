"""Impossible travel detection - same user logging in from two distant locations."""
import time
from backend.models.events import OCSFBaseEvent
from detections.rules.base import BaseRule


class ImpossibleTravelRule(BaseRule):
    name = "impossible_travel"

    async def evaluate(self, log: OCSFBaseEvent, windows: dict) -> dict | None:
        if (log.class_name.lower() if log.class_name else "") == "impossible_travel":
            return {
                "title": f"Impossible Travel Detected for {getattr(log, 'username', None)}",
                "description": getattr(log, 'message', None),
                "severity": "high",
                "rule_name": self.name,
                "mitre_techniques": ["T1078", "T1534"],
                "tags": ["impossible_travel", "account_compromise", "anomaly"],
            }
        return None
