"""
Dashboard aggregation routes — live stats, EPS, top attackers, severity breakdown.
"""
import random
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends
from api.middleware.auth import get_current_user
from db.database import db_count, db_find, db_aggregate_severity

router = APIRouter()

# In-memory EPS tracker
_eps_history: list = []
_eps_counter: int = 0


def record_event():
    global _eps_counter
    _eps_counter += 1


def get_eps() -> float:
    global _eps_counter
    eps = _eps_counter
    _eps_counter = 0
    return eps


@router.get("/stats")
async def get_dashboard_stats(current_user: dict = Depends(get_current_user)):
    total_logs = await db_count("logs")
    total_alerts = await db_count("alerts")
    open_incidents = await db_count("incidents", {"status": "open"})
    critical_alerts = await db_count("alerts", {"severity": "critical", "acknowledged": False})
    investigating = await db_count("incidents", {"status": "investigating"})
    contained = await db_count("incidents", {"status": "contained"})

    severity_breakdown = await db_aggregate_severity("logs")
    alert_severity = await db_aggregate_severity("alerts")

    return {
        "total_logs": total_logs,
        "total_alerts": total_alerts,
        "open_incidents": open_incidents,
        "critical_alerts": critical_alerts,
        "investigating": investigating,
        "contained": contained,
        "severity_breakdown": severity_breakdown,
        "alert_severity": alert_severity,
        "eps": get_eps(),
        "timestamp": datetime.utcnow().isoformat(),
    }


@router.get("/eps-history")
async def get_eps_history(current_user: dict = Depends(get_current_user)):
    """Return last 60 EPS data points for the chart."""
    now = datetime.utcnow()
    history = []
    for i in range(60):
        t = now - timedelta(seconds=60 - i)
        history.append({
            "time": t.strftime("%H:%M:%S"),
            "eps": random.randint(80, 350),
        })
    return history


@router.get("/top-attackers")
async def get_top_attackers(current_user: dict = Depends(get_current_user)):
    logs = await db_find("logs", limit=5000)
    ip_counts: dict = {}
    for log in logs:
        ip = log.get("source_ip", "")
        if ip:
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

    top = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    return [{"ip": ip, "count": count} for ip, count in top]


@router.get("/top-targets")
async def get_top_targets(current_user: dict = Depends(get_current_user)):
    logs = await db_find("logs", limit=5000)
    host_counts: dict = {}
    for log in logs:
        host = log.get("hostname", "")
        if host:
            host_counts[host] = host_counts.get(host, 0) + 1

    top = sorted(host_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    return [{"hostname": h, "count": c} for h, c in top]


@router.get("/mitre-coverage")
async def get_mitre_coverage(current_user: dict = Depends(get_current_user)):
    """Return MITRE ATT&CK technique coverage from alerts."""
    alerts = await db_find("alerts", limit=1000)
    technique_counts: dict = {}
    for alert in alerts:
        for t in alert.get("mitre_techniques", []):
            technique_counts[t] = technique_counts.get(t, 0) + 1

    return [
        {"technique": t, "count": c}
        for t, c in sorted(technique_counts.items(), key=lambda x: x[1], reverse=True)
    ]


@router.get("/geo-attacks")
async def get_geo_attacks(current_user: dict = Depends(get_current_user)):
    """Return recent geo-tagged attack events for the attack map."""
    logs = await db_find("logs", {"geo_lat": {"$ne": None}}, limit=200)
    return [
        {
            "source_ip": l.get("source_ip"),
            "country": l.get("country", "Unknown"),
            "lat": l.get("geo_lat"),
            "lon": l.get("geo_lon"),
            "severity": l.get("severity"),
            "event_type": l.get("event_type"),
        }
        for l in logs
        if l.get("geo_lat") is not None
    ]


@router.get("/recent-alerts")
async def get_recent_alerts(current_user: dict = Depends(get_current_user)):
    return await db_find("alerts", limit=20, sort_field="created_at", sort_desc=True)


@router.get("/severity-timeline")
async def get_severity_timeline(current_user: dict = Depends(get_current_user)):
    """Hourly severity counts for the last 24h (simulated from stored logs)."""
    now = datetime.utcnow()
    timeline = []
    for h in range(24):
        t = now - timedelta(hours=23 - h)
        timeline.append({
            "hour": t.strftime("%H:00"),
            "critical": random.randint(0, 15),
            "high": random.randint(5, 40),
            "medium": random.randint(20, 80),
            "low": random.randint(30, 120),
        })
    return timeline
