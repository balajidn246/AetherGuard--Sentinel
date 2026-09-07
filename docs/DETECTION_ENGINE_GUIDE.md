# AetherGuard--Sentinel — Detection Engine Guide

The AetherGuard Detection Engine is a hybrid rule evaluation pipeline combining **stateful Python correlation rules** and **declarative YAML (Sigma-compatible) rules**.

---

## Architecture Overview

```
[ Ingested Log Event ]
         │
         ├──► [ Python Stateful Rules ] ──► (Sliding Window Buffer)
         │                                       │
         └──► [ YAML / Sigma Engine ]   ─────────┤
                                                 ▼
                                        [ Rule Match Found ]
                                                 │
                                                 ├──► [ SecuritySignal in PostgreSQL ]
                                                 ├──► [ Real-time WebSocket Alert ]
                                                 └──► [ High/Critical -> Autonomous AI Triage ]
```

---

## 1. Python Detection Rules

Python rules are used for stateful, temporal, or threshold-based correlation across events.

### Rule Structure
All Python rules subclass `BaseRule` and implement the asynchronous `evaluate` method:

```python
from detections.rules.base import BaseRule
import time

class ExampleRule(BaseRule):
    name = "example_rule_name"

    async def evaluate(self, log: dict, windows: dict) -> dict | None:
        """
        log: normalized log event dict
        windows: mutable dictionary of sliding window state
        """
        if log.get("event_type") != "sensitive_action":
            return None

        src_ip = log.get("source_ip", "unknown")
        key = f"example:{src_ip}"
        now = time.time()

        # Update sliding window buffer
        bucket = windows.setdefault(key, [])
        bucket.append(now)
        windows[key] = [t for t in bucket if now - t < 60]  # 60 second window

        if len(windows[key]) >= 5:
            windows[key] = []  # reset window after firing
            return {
                "title": f"Sensitive Action Threshold Exceeded ({src_ip})",
                "description": f"5 actions detected in 60s from {src_ip}",
                "severity": "high",
                "rule_name": self.name,
                "mitre_techniques": ["T1078"],
                "tags": ["example", "threshold"],
            }
        return None
```

---

## 2. Built-in Detection Rules

| Rule ID | Rule Name | Severity | MITRE ATT&CK | Description |
| :--- | :--- | :--- | :--- | :--- |
| `rule-auth-bruteforce-01` | Brute Force Detection | High | T1110.001 | Detects 10+ failed logins within 120 seconds |
| `rule-network-portscan-01` | Port Scan Activity | Medium | T1046 | Detects scanning of 20+ denied ports within 60 seconds |
| `rule-privilege-escalation-01` | Privilege Escalation | Critical | T1078.003 | Detects unauthorized administrative group modifications |
| `rule-process-powershell-01` | Suspicious PowerShell | High | T1059.001 | Flags obfuscated, bypass, or encoded command flags |
| `rule-auth-impossible-travel-01`| Impossible Travel | High | T1078 | Flags simultaneous logins across unrealistic geographic distances |
| `rule-network-exfiltration-01` | Data Exfiltration | Critical | T1048 | Detects large anomalous outbound data transfers (>100MB) |
| `rule-malware-indicators-01` | Malware Execution | Critical | T1204.002 | Matches against known ransomware strings and malicious hashes |
| `rule-c2-beaconing-01` | C2 Beaconing Activity | High | T1071.001 | Detects periodic outbound network heartbeats |
| `rule-sigma-mimikatz-01` | Mimikatz LSASS Access | Critical | T1003.001 | Flags LSASS dumping commands and privilege debug tokens |
| `rule-sigma-pass-the-hash-01` | Pass-the-Hash Movement | High | T1550.002 | Detects NTLM authentication over SMB from unusual hosts |

---

## 3. Testing Rules

Rules can be tested without impacting production traffic:

1. **Via UI**: Navigate to `/rules`, select any rule, enter a test JSON payload in the **Rule Test Sandbox**, and click **Execute Test**.
2. **Via Automated Test Suite**:
```powershell
$env:PYTHONPATH = "."
python backend/tests/test_phase6_unit.py
```
