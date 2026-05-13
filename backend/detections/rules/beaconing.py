"""Beaconing detection — periodic outbound connections to same external IP."""
import time
from detections.rules.base import BaseRule

BEACON_WINDOW = 300   # 5 minutes
BEACON_COUNT = 8      # min hits to declare beaconing


class BeaconingRule(BaseRule):
    name = "beaconing"

    async def evaluate(self, log: dict, windows: dict) -> dict | None:
        if log.get("log_source") not in ("firewall", "netflow", "ids_ips"):
            return None
        if log.get("action") not in ("ALLOW", None):
            return None

        dest_ip = log.get("dest_ip") or log.get("source_ip", "")
        if not dest_ip:
            return None

        # Only track outbound to external IPs
        if dest_ip.startswith("192.168.") or dest_ip.startswith("10."):
            return None

        src_host = log.get("hostname", "unknown")
        key = f"beacon:{src_host}:{dest_ip}"
        now = time.time()
        ts_bucket = windows.setdefault(key, [])
        ts_bucket.append(now)
        windows[key] = [t for t in ts_bucket if now - t < BEACON_WINDOW]

        count = len(windows[key])
        if count >= BEACON_COUNT:
            windows[key] = []
            return {
                "title": f"C2 Beaconing Detected: {src_host} → {dest_ip}",
                "description": (
                    f"{src_host} made {count} periodic connections to {dest_ip} "
                    f"within {BEACON_WINDOW}s — possible C2 beacon"
                ),
                "severity": "high",
                "rule_name": self.name,
                "mitre_techniques": ["T1071.001", "T1102", "T1008"],
                "tags": ["c2", "beaconing", "command_control", "persistence"],
            }
        return None
