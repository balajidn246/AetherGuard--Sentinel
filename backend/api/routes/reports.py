"""
Reports — PDF and CSV export of logs, alerts, incidents.
"""
import csv
import io
from datetime import datetime
from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from api.middleware.auth import get_current_user
from db.database import db_find

router = APIRouter()


@router.get("/logs/csv")
async def export_logs_csv(
    limit: int = Query(1000, le=5000),
    current_user: dict = Depends(get_current_user),
):
    logs = await db_find("logs", limit=limit, sort_field="created_at", sort_desc=True)
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        "created_at", "severity", "event_type", "hostname",
        "source_ip", "log_source", "message", "raw_log"
    ])
    writer.writeheader()
    for log in logs:
        writer.writerow({
            "created_at": log.get("created_at", ""),
            "severity": log.get("severity", ""),
            "event_type": log.get("event_type", ""),
            "hostname": log.get("hostname", ""),
            "source_ip": log.get("source_ip", ""),
            "log_source": log.get("log_source", ""),
            "message": log.get("message", ""),
            "raw_log": log.get("raw_log", ""),
        })

    output.seek(0)
    filename = f"aetherguard_logs_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
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
    alerts = await db_find("alerts", limit=limit, sort_field="created_at", sort_desc=True)
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        "created_at", "severity", "title", "rule_name",
        "source_ip", "hostname", "acknowledged", "mitre_techniques"
    ])
    writer.writeheader()
    for a in alerts:
        writer.writerow({
            "created_at": a.get("created_at", ""),
            "severity": a.get("severity", ""),
            "title": a.get("title", ""),
            "rule_name": a.get("rule_name", ""),
            "source_ip": a.get("source_ip", ""),
            "hostname": a.get("hostname", ""),
            "acknowledged": a.get("acknowledged", False),
            "mitre_techniques": ",".join(a.get("mitre_techniques", [])),
        })
    output.seek(0)
    filename = f"aetherguard_alerts_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/incidents/csv")
async def export_incidents_csv(
    current_user: dict = Depends(get_current_user),
):
    incidents = await db_find("incidents", limit=500)
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        "created_at", "title", "severity", "status",
        "assigned_to", "source_ip", "hostname", "mitre_techniques"
    ])
    writer.writeheader()
    for inc in incidents:
        writer.writerow({
            "created_at": inc.get("created_at", ""),
            "title": inc.get("title", ""),
            "severity": inc.get("severity", ""),
            "status": inc.get("status", ""),
            "assigned_to": inc.get("assigned_to", ""),
            "source_ip": inc.get("source_ip", ""),
            "hostname": inc.get("hostname", ""),
            "mitre_techniques": ",".join(inc.get("mitre_techniques", [])),
        })
    output.seek(0)
    filename = f"aetherguard_incidents_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/summary")
async def generate_summary_report(current_user: dict = Depends(get_current_user)):
    """JSON summary report."""
    from db.database import db_count, db_aggregate_severity
    return {
        "generated_at": datetime.utcnow().isoformat(),
        "generated_by": current_user.get("username"),
        "report_period": "Last 24 hours",
        "statistics": {
            "total_logs": await db_count("logs"),
            "total_alerts": await db_count("alerts"),
            "open_incidents": await db_count("incidents", {"status": "open"}),
            "critical_alerts": await db_count("alerts", {"severity": "critical"}),
        },
        "severity_breakdown": await db_aggregate_severity("alerts"),
    }
