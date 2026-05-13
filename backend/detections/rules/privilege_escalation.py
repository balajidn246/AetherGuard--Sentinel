"""Privilege escalation detection — EventID 4728, 4672, 4720."""
from detections.rules.base import BaseRule

PRIV_EVENT_IDS = {4728, 4672, 4720, 4732, 4756}
PRIV_KEYWORDS = [
    "domain admins", "enterprise admins", "schema admins",
    "privilege escalation", "added to", "special privileges"
]


class PrivilegeEscalationRule(BaseRule):
    name = "privilege_escalation"

    async def evaluate(self, log: dict, windows: dict) -> dict | None:
        event_id = log.get("event_id")
        msg_lower = log.get("message", "").lower()

        triggered = (
            event_id in PRIV_EVENT_IDS
            or log.get("event_type") == "privilege_escalation"
            or any(k in msg_lower for k in PRIV_KEYWORDS)
        )
        if not triggered:
            return None

        return {
            "title": f"Privilege Escalation on {log.get('hostname', 'unknown')}",
            "description": (
                f"User {log.get('username', 'unknown')} performed a privilege escalation "
                f"action (EventID {event_id}) on {log.get('hostname', 'unknown')}"
            ),
            "severity": "critical",
            "rule_name": self.name,
            "mitre_techniques": ["T1078.002", "T1098", "T1134"],
            "tags": ["privilege_escalation", "persistence", "credential_access"],
        }
