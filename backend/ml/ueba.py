"""
UEBA - User Entity Behavior Analytics.
Tracks per-user event counters, detects statistical deviations from baseline,
and persists historical snapshots to PostgreSQL.
"""
import asyncio
import logging
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from sqlalchemy import select, text
from backend.db.postgres import AsyncSessionLocal
from backend.models.ueba_snapshot import UEBASnapshot

logger = logging.getLogger(__name__)


class UEBAEngine:
    def __init__(self):
        # {username: {hour_bucket: event_count}}
        self._user_hourly: dict = defaultdict(lambda: defaultdict(int))
        # {username: baseline_avg}
        self._baselines: dict = {}
        # {username: [risk_scores]}
        self._user_risk: dict = defaultdict(list)
        logger.info("[UEBA] Engine initialised")

    def _hour_key(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H")

    async def load_baselines_from_db(self):
        """Pre-load past 7 days of UEBA snapshots from PostgreSQL on startup."""
        try:
            seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)
            async with AsyncSessionLocal() as session:
                stmt = select(UEBASnapshot).where(UEBASnapshot.created_at >= seven_days_ago)
                rows = (await session.execute(stmt)).scalars().all()
                for r in rows:
                    self._user_hourly[r.username][r.hour_bucket] = r.event_count
                    self._user_risk[r.username].append(r.avg_risk_score)
                logger.info(f"[UEBA] Loaded {len(rows)} historical snapshots from PostgreSQL")
        except Exception as exc:
            logger.warning(f"[UEBA] Could not load snapshots from database: {exc}")

    def record_event(self, log: dict, tenant_id: str = "default"):
        username = log.get("username") or log.get("user_name", "unknown")
        if not username or username == "unknown":
            return
        bucket = self._hour_key()
        self._user_hourly[username][bucket] += 1
        risk = log.get("risk_score", 20)
        self._user_risk[username].append(risk)
        # Keep last 1000 events per user in memory
        self._user_risk[username] = self._user_risk[username][-1000:]

        # Asynchronously schedule snapshot persistence
        asyncio.create_task(self._persist_snapshot_bg(username, bucket, tenant_id))

    async def _persist_snapshot_bg(self, username: str, bucket: str, tenant_id: str):
        """Persist or update snapshot in PostgreSQL."""
        try:
            profile = self.get_user_profile(username)
            async with AsyncSessionLocal() as session:
                stmt = select(UEBASnapshot).where(
                    UEBASnapshot.tenant_id == tenant_id,
                    UEBASnapshot.username == username,
                    UEBASnapshot.hour_bucket == bucket
                )
                existing = (await session.execute(stmt)).scalar_one_or_none()
                if existing:
                    existing.event_count = profile["current_hour_events"]
                    existing.avg_risk_score = profile["avg_risk_score"]
                    existing.peak_risk_score = profile["peak_risk"]
                    existing.anomaly_flag = profile["anomaly_flag"]
                else:
                    new_snap = UEBASnapshot(
                        tenant_id=tenant_id,
                        username=username,
                        hour_bucket=bucket,
                        event_count=profile["current_hour_events"],
                        avg_risk_score=profile["avg_risk_score"],
                        peak_risk_score=profile["peak_risk"],
                        anomaly_flag=profile["anomaly_flag"]
                    )
                    session.add(new_snap)
                await session.commit()
        except Exception as exc:
            logger.debug(f"[UEBA] Background snapshot error: {exc}")

    def get_user_profile(self, username: str) -> dict:
        hourly = self._user_hourly.get(username, {})
        counts = list(hourly.values())
        avg_hourly = sum(counts) / len(counts) if counts else 0
        risk_scores = self._user_risk.get(username, [])
        avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 20
        peak_risk = max(risk_scores) if risk_scores else 20
        current_count = hourly.get(self._hour_key(), 0)

        anomaly_flag = (avg_risk > 60) or (current_count > avg_hourly * 3 and current_count > 10)

        return {
            "username": username,
            "avg_hourly_events": round(avg_hourly, 2),
            "current_hour_events": current_count,
            "avg_risk_score": round(avg_risk, 2),
            "peak_risk": peak_risk,
            "total_events": sum(counts),
            "anomaly_flag": anomaly_flag,
        }

    def get_all_profiles(self) -> list:
        return [self.get_user_profile(u) for u in self._user_hourly]

    def get_top_risky_users(self, n: int = 10) -> list:
        profiles = self.get_all_profiles()
        return sorted(profiles, key=lambda x: x["avg_risk_score"], reverse=True)[:n]
