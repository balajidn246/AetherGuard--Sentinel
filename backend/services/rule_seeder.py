"""
Seed Default Detection Rules into PostgreSQL so they are managed and visible via API/UI.
"""
import logging
from sqlalchemy import select
from backend.db.postgres import AsyncSessionLocal
from backend.models.detection_rule import DetectionRuleModel

logger = logging.getLogger(__name__)

DEFAULT_RULES = [
    {
        "rule_id": "rule-auth-bruteforce-01",
        "name": "Authentication Brute Force",
        "description": "Detects repeated failed authentication attempts from a single source within a sliding window.",
        "severity": "high",
        "rule_type": "python",
        "mitre_techniques": ["T1110.001", "T1110"],
        "author": "AetherGuard Security Team",
        "false_positive_notes": "Legitimate users mistyping passwords, automated credential verification scripts."
    },
    {
        "rule_id": "rule-network-portscan-01",
        "name": "Network Port Scanning Activity",
        "description": "Detects systematic scanning across multiple destination ports from a single IP address.",
        "severity": "medium",
        "rule_type": "python",
        "mitre_techniques": ["T1046"],
        "author": "AetherGuard Security Team",
        "false_positive_notes": "Internal network inventory scanners, vulnerability assessment tools."
    },
    {
        "rule_id": "rule-privilege-escalation-01",
        "name": "Privilege Escalation via Group Membership",
        "description": "Detects addition of user accounts to privileged groups (Domain Admins, Administrators, wheel, sudo).",
        "severity": "critical",
        "rule_type": "python",
        "mitre_techniques": ["T1078.002", "T1098"],
        "author": "AetherGuard Security Team",
        "false_positive_notes": "Authorized IT administrators creating or promoting service accounts."
    },
    {
        "rule_id": "rule-suspicious-powershell-01",
        "name": "Suspicious Encoded PowerShell Execution",
        "description": "Detects execution of PowerShell with bypass flags, encoded commands, or direct web download cradles.",
        "severity": "critical",
        "rule_type": "python",
        "mitre_techniques": ["T1059.001", "T1027"],
        "author": "AetherGuard Security Team",
        "false_positive_notes": "Legitimate administrative deployment scripts or RMM agents."
    },
    {
        "rule_id": "rule-impossible-travel-01",
        "name": "Impossible Geographic Travel",
        "description": "Detects authentication from geographically distant locations within a physically impossible time window.",
        "severity": "high",
        "rule_type": "python",
        "mitre_techniques": ["T1078"],
        "author": "AetherGuard Security Team",
        "false_positive_notes": "Analyst using corporate VPN toggling locations."
    },
    {
        "rule_id": "rule-data-exfiltration-01",
        "name": "Unusual High-Volume Outbound Data Exfiltration",
        "description": "Detects anomalous outbound data transfers exceeding normal baseline thresholds.",
        "severity": "critical",
        "rule_type": "python",
        "mitre_techniques": ["T1048", "T1041"],
        "author": "AetherGuard Security Team",
        "false_positive_notes": "Scheduled database cloud backups, large video/asset uploads."
    },
    {
        "rule_id": "rule-malware-indicators-01",
        "name": "Malware Artifact or Known Threat Signature",
        "description": "Detects execution of known malicious process names, tooling, or matched IOC hashes.",
        "severity": "critical",
        "rule_type": "python",
        "mitre_techniques": ["T1059", "T1055", "T1036"],
        "author": "AetherGuard Security Team",
        "false_positive_notes": "Security testing tools in isolated lab environments."
    },
    {
        "rule_id": "rule-c2-beaconing-01",
        "name": "Periodic Command-and-Control (C2) Beaconing",
        "description": "Detects repetitive network connections to external endpoints with regular interval jitter.",
        "severity": "high",
        "rule_type": "python",
        "mitre_techniques": ["T1071.001", "T1573"],
        "author": "AetherGuard Security Team",
        "false_positive_notes": "NTP, software update checkers, legitimate telemetry heartbeats."
    },
    {
        "rule_id": "rule-sigma-mimikatz-01",
        "name": "Sigma: Mimikatz LSASS Memory Access",
        "description": "Sigma detection for unauthorized processes accessing or dumping LSASS process memory.",
        "severity": "critical",
        "rule_type": "sigma",
        "mitre_techniques": ["T1003.001"],
        "author": "Sigma Community / AetherGuard",
        "false_positive_notes": "Endpoint security agents, antivirus memory scanners."
    },
    {
        "rule_id": "rule-sigma-pass-the-hash-01",
        "name": "Sigma: Pass-the-Hash Lateral Movement",
        "description": "Sigma detection for explicit credential authentication using NTLM hash injection.",
        "severity": "critical",
        "rule_type": "sigma",
        "mitre_techniques": ["T1550.002", "T1021.002"],
        "author": "Sigma Community / AetherGuard",
        "false_positive_notes": "Legacy domain migration services."
    }
]

async def seed_default_rules():
    """Seeds default detection rules into PostgreSQL if not already present."""
    try:
        async with AsyncSessionLocal() as session:
            for r in DEFAULT_RULES:
                stmt = select(DetectionRuleModel).where(DetectionRuleModel.rule_id == r["rule_id"])
                existing = (await session.execute(stmt)).scalar_one_or_none()
                if not existing:
                    new_rule = DetectionRuleModel(
                        tenant_id="default",
                        rule_id=r["rule_id"],
                        name=r["name"],
                        description=r["description"],
                        severity=r["severity"],
                        rule_type=r["rule_type"],
                        enabled=True,
                        mitre_techniques=r["mitre_techniques"],
                        author=r["author"],
                        false_positive_notes=r["false_positive_notes"],
                        content={"seeded": True}
                    )
                    session.add(new_rule)
            await session.commit()
            logger.info(f"[RULES] Seeded {len(DEFAULT_RULES)} default detection rules")
    except Exception as exc:
        logger.error(f"[RULES] Error seeding default rules: {exc}")
