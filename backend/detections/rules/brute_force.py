"""Brute force login detection - SSH and Windows logon failures."""
import time
from backend.models.events import OCSFBaseEvent
from detections.rules.base import BaseRule

WINDOW_SECONDS = 120
THRESHOLD = 10


class BruteForceRule(BaseRule):
    name = "brute_force"

    async def evaluate(self, log: OCSFBaseEvent, windows: dict) -> dict | None:
        event_type = (log.class_name.lower() if log.class_name else "")
        is_failed = (
            event_type in ("failed_logon_attempt", "ssh_failed_login")
            or str(log.event_id) == 4625
            or "Failed password" in (log.message or "")
        )
        if not is_failed:
            return None

        src_ip = (str(log.src_ip) if log.src_ip else "unknown")
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
                    f"{WINDOW_SECONDS}s on host {getattr(log, 'hostname', None)}"
                ),
                "severity": "high",
                "rule_name": self.name,
                "mitre_techniques": ["T1110.001", "T1078"],
                "tags": ["brute_force", "authentication", "lateral_movement"],
            }
        return None
