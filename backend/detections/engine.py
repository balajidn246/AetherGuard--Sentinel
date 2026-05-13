"""
Detection Engine — evaluates every ingested log against all detection rules.
Matches trigger Alert creation and WebSocket broadcast.
"""
import logging
import uuid
from datetime import datetime, timezone
from typing import List

logger = logging.getLogger(__name__)


class DetectionEngine:
    def __init__(self, ws_manager):
        self.ws_manager = ws_manager
        self._rules = self._load_rules()
        # Rolling window buffers for stateful rules {key: [timestamps]}
        self._event_windows: dict = {}
        logger.info(f"🔍 Detection Engine loaded {len(self._rules)} rules")

    def _load_rules(self) -> list:
        from detections.rules.brute_force import BruteForceRule
        from detections.rules.port_scan import PortScanRule
        from detections.rules.privilege_escalation import PrivilegeEscalationRule
        from detections.rules.suspicious_powershell import SuspiciousPowerShellRule
        from detections.rules.impossible_travel import ImpossibleTravelRule
        from detections.rules.data_exfiltration import DataExfiltrationRule
        from detections.rules.malware_indicators import MalwareIndicatorsRule
        from detections.rules.beaconing import BeaconingRule
        return [
            BruteForceRule(),
            PortScanRule(),
            PrivilegeEscalationRule(),
            SuspiciousPowerShellRule(),
            ImpossibleTravelRule(),
            DataExfiltrationRule(),
            MalwareIndicatorsRule(),
            BeaconingRule(),
        ]

    async def evaluate(self, log: dict):
        """Run all rules against a single log event."""
        for rule in self._rules:
            try:
                match = await rule.evaluate(log, self._event_windows)
                if match:
                    await self._create_alert(log, match)
            except Exception as exc:
                logger.error(f"Rule {rule.name} error: {exc}")

    async def _create_alert(self, log: dict, match: dict):
        from db.database import db_insert
        alert = {
            "_id": str(uuid.uuid4()),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "title": match["title"],
            "description": match["description"],
            "severity": match["severity"],
            "rule_name": match["rule_name"],
            "source_ip": log.get("source_ip", ""),
            "hostname": log.get("hostname", ""),
            "username": log.get("username", ""),
            "log_id": log.get("_id", ""),
            "mitre_techniques": match.get("mitre_techniques", []),
            "tags": match.get("tags", []),
            "acknowledged": False,
            "acknowledged_by": None,
            "incident_id": None,
            "raw_log_snippet": log.get("raw_log", "")[:200],
        }
        await db_insert("alerts", alert)
        await self.ws_manager.send_alert(alert)
        logger.info(f"🚨 ALERT [{alert['severity'].upper()}] {alert['title']}")
