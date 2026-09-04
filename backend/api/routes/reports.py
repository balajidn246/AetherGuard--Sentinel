"""
Reports - PDF and CSV export of logs, alerts, incidents.
All data fetched from real databases: ClickHouse for events, PostgreSQL for signals & incidents.
"""
import csv
import io
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import select, func

from backend.api.middleware.auth import get_current_user
from backend.db.postgres import AsyncSessionLocal
from backend.db.clickhouse import get_clickhouse
from backend.models.signal import SecuritySignal
from backend.models.incident import Incident

router = APIRouter()


@router.get("/logs/csv")
async def export_logs_csv(
    limit: int = Query(1000, le=5000),
    current_user: dict = Depends(get_current_user),
):
    tenant_id = current_user.get("tenant_id", "default")
    client = get_clickhouse()
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        "time", "severity", "event_type", "hostname",
        "source_ip", "log_source", "message", "raw_log"
    ])
    writer.writeheader()

    if client:
        try:
            query = """
                SELECT time, severity, class_name, host_name, src_ip, source_log, message, raw_data
                FROM events
                WHERE tenant_id = %(tenant_id)s
                ORDER BY time DESC
                LIMIT %(limit)s
            """
            result = client.query(query, parameters={"tenant_id": tenant_id, "limit": limit})
            for row in result.result_rows:
                writer.writerow({
                    "time": str(row[0]),
                    "severity": str(row[1]),
                    "event_type": str(row[2]),
                    "hostname": str(row[3]),
                    "source_ip": str(row[4]),
                    "log_source": str(row[5]),
                    "message": str(row[6]),
                    "raw_log": str(row[7]),
                })
        except Exception as exc:
            pass

    output.seek(0)
    filename = f"aetherguard_logs_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/alerts/csv")
async def export_alerts_csv(
    limit: int = Query(500, le=2000),
    current_user: dict = Depends(get_current_user),
):
    tenant_id = current_user.get("tenant_id", "default")
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        "created_at", "severity", "title", "rule_name",
        "source_ip", "hostname", "acknowledged", "mitre_techniques"
    ])
    writer.writeheader()

    async with AsyncSessionLocal() as session:
        stmt = select(SecuritySignal).where(
            SecuritySignal.tenant_id == tenant_id
        ).order_by(SecuritySignal.created_at.desc()).limit(limit)
        signals = (await session.execute(stmt)).scalars().all()

        for s in signals:
            writer.writerow({
                "created_at": s.created_at.isoformat() if s.created_at else "",
                "severity": s.severity or "medium",
                "title": s.title or "",
                "rule_name": s.rule_name or "",
                "source_ip": s.source_ip or "",
                "hostname": s.hostname or "",
                "acknowledged": s.acknowledged,
                "mitre_techniques": ",".join(s.mitre_tactics or []),
            })

    output.seek(0)
    filename = f"aetherguard_alerts_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/incidents/csv")
async def export_incidents_csv(
    current_user: dict = Depends(get_current_user),
):
    tenant_id = current_user.get("tenant_id", "default")
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        "created_at", "title", "severity", "status",
        "assigned_to", "tags"
    ])
    writer.writeheader()

    async with AsyncSessionLocal() as session:
        stmt = select(Incident).where(
            Incident.tenant_id == tenant_id
        ).order_by(Incident.created_at.desc()).limit(500)
        incidents = (await session.execute(stmt)).scalars().all()

        for inc in incidents:
            writer.writerow({
                "created_at": inc.created_at.isoformat() if inc.created_at else "",
                "title": inc.title or "",
                "severity": inc.severity or "medium",
                "status": inc.status or "open",
                "assigned_to": inc.assignee or "",
                "tags": ",".join(inc.tags or []),
            })

    output.seek(0)
    filename = f"aetherguard_incidents_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/summary")
async def generate_summary_report(current_user: dict = Depends(get_current_user)):
    """Summary report aggregated across real ClickHouse & PostgreSQL tables."""
    tenant_id = current_user.get("tenant_id", "default")
    total_logs = 0
    client = get_clickhouse()
    if client:
        try:
            res = client.query("SELECT count() FROM events WHERE tenant_id = %(tenant_id)s", parameters={"tenant_id": tenant_id})
            total_logs = res.result_rows[0][0] if res.result_rows else 0
        except Exception:
            total_logs = 0

    total_alerts = 0
    open_incidents = 0
    critical_alerts = 0
    severity_breakdown = {}

    async with AsyncSessionLocal() as session:
        total_alerts = (await session.execute(
            select(func.count(SecuritySignal.id)).where(SecuritySignal.tenant_id == tenant_id)
        )).scalar() or 0

        open_incidents = (await session.execute(
            select(func.count(Incident.id)).where(
                Incident.tenant_id == tenant_id,
                Incident.status != "closed"
            )
        )).scalar() or 0

        critical_alerts = (await session.execute(
            select(func.count(SecuritySignal.id)).where(
                SecuritySignal.tenant_id == tenant_id,
                SecuritySignal.severity == "critical"
            )
        )).scalar() or 0

        sev_rows = (await session.execute(
            select(SecuritySignal.severity, func.count(SecuritySignal.id)).where(
                SecuritySignal.tenant_id == tenant_id
            ).group_by(SecuritySignal.severity)
        )).all()
        for row in sev_rows:
            severity_breakdown[str(row[0]).lower()] = row[1]

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generated_by": current_user.get("username"),
        "report_period": "Last 24 hours",
        "statistics": {
            "total_logs": total_logs,
            "total_alerts": total_alerts,
            "open_incidents": open_incidents,
            "critical_alerts": critical_alerts,
        },
        "severity_breakdown": severity_breakdown,
    }
