"""Impossible travel detection — same user logging in from two distant locations."""
import time
from detections.rules.base import BaseRule


class ImpossibleTravelRule(BaseRule):
    name = "impossible_travel"

    async def evaluate(self, log: dict, windows: dict) -> dict | None:
        if log.get("event_type") == "impossible_travel":
            return {
                "title": f"Impossible Travel Detected for {log.get('username', 'unknown')}",
                "description": log.get("message", "Impossible travel login detected"),
                "severity": "high",
                "rule_name": self.name,
                "mitre_techniques": ["T1078", "T1534"],
                "tags": ["impossible_travel", "account_compromise", "anomaly"],
            }
        return None
