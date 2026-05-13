"""Port scan detection — rapid SYN/DENY events from single source IP."""
import time
from detections.rules.base import BaseRule

WINDOW_SECONDS = 60
PORT_THRESHOLD = 20


class PortScanRule(BaseRule):
    name = "port_scan"

    async def evaluate(self, log: dict, windows: dict) -> dict | None:
        if log.get("log_source") != "firewall":
            return None
        if log.get("action") not in ("DENY", "DROP"):
            return None

        src_ip = log.get("source_ip", "unknown")
        dst_port = log.get("dest_port")
        if not dst_port:
            return None

        key = f"port_scan:{src_ip}"
        now = time.time()
        bucket = windows.setdefault(key, set())

        # Store (timestamp, port) pairs — use list for time-windowing
        timed_key = f"port_scan_ts:{src_ip}"
        ts_bucket = windows.setdefault(timed_key, [])
        ts_bucket.append((now, dst_port))
        windows[timed_key] = [(t, p) for t, p in ts_bucket if now - t < WINDOW_SECONDS]

        unique_ports = len({p for _, p in windows[timed_key]})
        if unique_ports >= PORT_THRESHOLD:
            windows[timed_key] = []
            return {
                "title": f"Port Scan Detected from {src_ip}",
                "description": (
                    f"Source {src_ip} scanned {unique_ports} unique ports "
                    f"on {log.get('dest_ip', 'unknown')} within {WINDOW_SECONDS}s"
                ),
                "severity": "medium",
                "rule_name": self.name,
                "mitre_techniques": ["T1046"],
                "tags": ["port_scan", "reconnaissance", "network"],
            }
        return None
