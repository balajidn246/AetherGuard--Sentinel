"""
Log search and query routes — Splunk-style search with filters.
"""
from fastapi import APIRouter, Depends, Query
from typing import Optional
from api.middleware.auth import get_current_user
from db.database import db_find, db_count

router = APIRouter()


@router.get("/search")
async def search_logs(
    q: Optional[str] = Query(None, description="Full-text keyword search"),
    severity: Optional[str] = Query(None),
    hostname: Optional[str] = Query(None),
    source_ip: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    log_source: Optional[str] = Query(None),
    limit: int = Query(100, le=1000),
    skip: int = Query(0),
    current_user: dict = Depends(get_current_user),
):
    query = {}
    if severity:
        query["severity"] = severity
    if hostname:
        query["hostname"] = hostname
    if source_ip:
        query["source_ip"] = source_ip
    if event_type:
        query["event_type"] = event_type
    if log_source:
        query["log_source"] = log_source

    logs = await db_find("logs", query, limit=limit, skip=skip)

    # Keyword filter (applied post-fetch for TinyDB compatibility)
    if q:
        q_lower = q.lower()
        logs = [
            l for l in logs
            if q_lower in str(l.get("message", "")).lower()
            or q_lower in str(l.get("raw_log", "")).lower()
            or q_lower in str(l.get("hostname", "")).lower()
            or q_lower in str(l.get("source_ip", "")).lower()
        ]

    total = await db_count("logs", query)
    return {"logs": logs, "total": total, "limit": limit, "skip": skip}


@router.get("/stats")
async def log_stats(current_user: dict = Depends(get_current_user)):
    from db.database import db_aggregate_severity
    by_severity = await db_aggregate_severity("logs")
    total = await db_count("logs")

    # Count by log source
    logs = await db_find("logs", limit=10000)
    by_source: dict = {}
    by_event_type: dict = {}
    for l in logs:
        src = l.get("log_source", "unknown")
        by_source[src] = by_source.get(src, 0) + 1
        et = l.get("event_type", "unknown")
        by_event_type[et] = by_event_type.get(et, 0) + 1

    return {
        "total": total,
        "by_severity": by_severity,
        "by_source": by_source,
        "by_event_type": by_event_type,
    }


@router.get("/live")
async def get_live_logs(
    limit: int = Query(50, le=200),
    current_user: dict = Depends(get_current_user),
):
    """Return latest N logs for initial load."""
    return await db_find("logs", limit=limit, sort_field="created_at", sort_desc=True)


@router.get("/sources")
async def get_log_sources(current_user: dict = Depends(get_current_user)):
    return [
        "windows_event", "linux_syslog", "firewall", "ids_ips",
        "web_server", "auth_log", "dns", "netflow", "endpoint"
    ]
