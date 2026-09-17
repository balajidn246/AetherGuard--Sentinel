"""
Detection Engine - evaluates every ingested log against all detection rules.
Matches trigger Alert creation and WebSocket broadcast.
"""
import logging
import uuid
from datetime import datetime, timezone
from typing import List

import os
from backend.detections.yaml_engine import YamlDetectionEngine

try:
    from backend.core.metrics import SIGNALS_CREATED
    _metrics_enabled = True
except Exception:
    _metrics_enabled = False

logger = logging.getLogger(__name__)


class DetectionEngine:
    def __init__(self, ws_manager):
        self.ws_manager = ws_manager
        self._rules = self._load_rules()
        # Rolling window buffers for stateful rules {key: [timestamps]}
        self._event_windows: dict = {}
        
        # Load YAML Rules
        rules_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'rules', 'custom')
        self.yaml_engine = YamlDetectionEngine(rules_path)
        
        logger.info(f"[DETECTION] Loaded {len(self._rules)} python rules and {len(self.yaml_engine.rules)} yaml rules")

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
        # 1. Hardcoded Python Rules
        for rule in self._rules:
            try:
                match = await rule.evaluate(log, self._event_windows)
                if match:
                    await self._create_alert(log, match)
            except Exception as exc:
                logger.error(f"Rule {rule.name} error: {exc}")

        # 2. Dynamic YAML Rules
        try:
            yaml_matches = self.yaml_engine.evaluate_event(log)
            for ym in yaml_matches:
                match = {
                    "title": ym["rule_name"],
                    "description": f"Triggered YAML rule: {ym['rule_id']}",
                    "severity": ym["severity"],
                    "rule_name": ym["rule_name"],
                    "mitre_techniques": ym["mitre"],
                    "tags": ["yaml-engine"]
                }
                await self._create_alert(log, match)
        except Exception as exc:
            logger.error(f"YAML Engine evaluation error: {exc}")

    async def _create_alert(self, log: dict, match: dict):
        from backend.db.postgres import AsyncSessionLocal
        from backend.models.signal import SecuritySignal
        
        signal_id = str(uuid.uuid4())
        
        # 1. Save to Real Database (PostgreSQL)
        try:
            async with AsyncSessionLocal() as session:
                new_signal = SecuritySignal(
                    id=signal_id,
                    tenant_id=log.get("tenant_id", "default"),
                    title=match["title"],
                    description=match["description"],
                    severity=match["severity"],
                    status="new",
                    rule_name=match.get("rule_name", "unknown"),
                    source_ip=log.get("source_ip") or log.get("src_ip", ""),
                    hostname=log.get("hostname") or log.get("host_name", ""),
                    username=log.get("username") or log.get("user_name", ""),
                    tags=match.get("tags", []),
                    evidence_refs=[log.get("id", log.get("_id", "unknown"))],
                    mitre_tactics=match.get("mitre_techniques", []),
                    source_alert_id=match.get("rule_name", "unknown")
                )
                session.add(new_signal)
                await session.commit()
                logger.info(f"[POSTGRES] Persisted Security Signal {signal_id}")
                if _metrics_enabled:
                    SIGNALS_CREATED.labels(
                        tenant_id=log.get("tenant_id", "default"),
                        severity=match["severity"],
                        rule=match.get("rule_name", "unknown")
                    ).inc()
        except Exception as e:
            logger.error(f"Failed to persist signal to Postgres: {e}")

        # 2. Real-Time UI WebSocket Broadcast (Point 35)
        alert_payload = {
            "_id": signal_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "title": match["title"],
            "description": match["description"],
            "severity": match["severity"],
            "rule_name": match["rule_name"],
            "source_ip": log.get("source_ip") or log.get("src_ip", ""),
            "hostname": log.get("hostname") or log.get("host_name", ""),
            "username": log.get("username") or log.get("user_name", ""),
            "log_id": log.get("id", ""),
            "mitre_techniques": match.get("mitre_techniques", []),
            "tags": match.get("tags", []),
            "acknowledged": False,
        }
        # Broadcast alert to specific tenant via WebSocket
        tenant_id = log.get("tenant_id", "default")
        await self.ws_manager.send_alert(alert_payload, tenant_id)
        logger.info(f"[ALERT] [{alert_payload['severity'].upper()}] {alert_payload['title']}")

        # 3. Autonomous AI Triage for High/Critical Signals
        if match.get("severity", "").lower() in ["critical", "high"]:
            import asyncio
            from backend.services.ai_gateway import ai_gateway
            sig_dict = {
                "id": signal_id,
                "title": match["title"],
                "description": match["description"],
                "severity": match["severity"],
                "rule_name": match.get("rule_name", "unknown"),
                "source_ip": log.get("source_ip") or log.get("src_ip", ""),
                "mitre_techniques": match.get("mitre_techniques", [])
            }
            asyncio.create_task(
                ai_gateway.investigate_signal(
                    signal_dict=sig_dict,
                    evidence_events=[log],
                    actor_id="autonomous_agent",
                    actor_username="AetherGuard-AI",
                    tenant_id=log.get("tenant_id", "default"),
                    ws_manager=self.ws_manager
                )
            )

