"""Brute force login detection — SSH and Windows logon failures."""
import time
from detections.rules.base import BaseRule

WINDOW_SECONDS = 120
THRESHOLD = 10


class BruteForceRule(BaseRule):
    name = "brute_force"

    async def evaluate(self, log: dict, windows: dict) -> dict | None:
        event_type = log.get("event_type", "")
        is_failed = (
            event_type in ("failed_logon_attempt", "ssh_failed_login")
            or log.get("event_id") == 4625
            or "Failed password" in log.get("message", "")
        )
        if not is_failed:
            return None

        src_ip = log.get("source_ip", "unknown")
        key = f"brute_force:{src_ip}"
        now = time.time()

        bucket = windows.setdefault(key, [])
        bucket.append(now)
        # Purge old timestamps
        windows[key] = [t for t in bucket if now - t < WINDOW_SECONDS]

        count = len(windows[key])
        if count >= THRESHOLD:
            windows[key] = []  # Reset after firing
            return {
                "title": f"Brute Force Attack Detected from {src_ip}",
                "description": (
                    f"{count} failed login attempts from {src_ip} within "
                    f"{WINDOW_SECONDS}s on host {log.get('hostname', 'unknown')}"
                ),
                "severity": "high",
                "rule_name": self.name,
                "mitre_techniques": ["T1110.001", "T1078"],
                "tags": ["brute_force", "authentication", "lateral_movement"],
            }
        return None
