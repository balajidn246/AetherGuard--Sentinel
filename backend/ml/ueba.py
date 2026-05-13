"""
UEBA — User Entity Behavior Analytics.
Tracks per-user event counters and detects deviations from baseline.
"""
import logging
from collections import defaultdict
from datetime import datetime

logger = logging.getLogger(__name__)


class UEBAEngine:
    def __init__(self):
        # {username: {hour_bucket: event_count}}
        self._user_hourly: dict = defaultdict(lambda: defaultdict(int))
        # {username: baseline_avg}
        self._baselines: dict = {}
        # {username: [risk_scores]}
        self._user_risk: dict = defaultdict(list)
        logger.info("✅ UEBA Engine initialised")

    def _hour_key(self) -> str:
        return datetime.utcnow().strftime("%Y-%m-%dT%H")

    def record_event(self, log: dict):
        username = log.get("username", "unknown")
        if not username:
            return
        bucket = self._hour_key()
        self._user_hourly[username][bucket] += 1
        risk = log.get("risk_score", 20)
        self._user_risk[username].append(risk)
        # Keep last 1000 events per user
        self._user_risk[username] = self._user_risk[username][-1000:]

    def get_user_profile(self, username: str) -> dict:
        hourly = self._user_hourly.get(username, {})
        counts = list(hourly.values())
        avg_hourly = sum(counts) / len(counts) if counts else 0
        risk_scores = self._user_risk.get(username, [])
        avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 20

        return {
            "username": username,
            "avg_hourly_events": round(avg_hourly, 2),
            "current_hour_events": hourly.get(self._hour_key(), 0),
            "avg_risk_score": round(avg_risk, 2),
            "peak_risk": max(risk_scores) if risk_scores else 0,
            "total_events": sum(counts),
            "anomaly_flag": avg_risk > 60 or hourly.get(self._hour_key(), 0) > avg_hourly * 3,
        }

    def get_all_profiles(self) -> list:
        return [self.get_user_profile(u) for u in self._user_hourly]

    def get_top_risky_users(self, n: int = 10) -> list:
        profiles = self.get_all_profiles()
        return sorted(profiles, key=lambda x: x["avg_risk_score"], reverse=True)[:n]
