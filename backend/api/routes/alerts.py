"""
Alert management routes.
"""
from fastapi import APIRouter, Depends, Query, HTTPException
from typing import Optional
from pydantic import BaseModel
from api.middleware.auth import get_current_user, require_analyst
from db.database import db_find, db_find_one, db_update_one, db_count, db_insert

router = APIRouter()


class AlertAckRequest(BaseModel):
    notes: str = ""


@router.get("/")
async def list_alerts(
    severity: Optional[str] = Query(None),
    acknowledged: Optional[bool] = Query(None),
    rule_name: Optional[str] = Query(None),
    limit: int = Query(50, le=500),
    skip: int = Query(0),
    current_user: dict = Depends(get_current_user),
):
    query = {}
    if severity:
        query["severity"] = severity
    if acknowledged is not None:
        query["acknowledged"] = acknowledged
    if rule_name:
        query["rule_name"] = rule_name

    alerts = await db_find("alerts", query, limit=limit, skip=skip)
    total = await db_count("alerts", query)
    return {"alerts": alerts, "total": total}


@router.get("/{alert_id}")
async def get_alert(alert_id: str, current_user: dict = Depends(get_current_user)):
    alert = await db_find_one("alerts", {"_id": alert_id})
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.post("/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: str,
    body: AlertAckRequest,
    current_user: dict = Depends(require_analyst),
):
    alert = await db_find_one("alerts", {"_id": alert_id})
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    await db_update_one(
        "alerts",
        {"_id": alert_id},
        {
            "acknowledged": True,
            "acknowledged_by": current_user.get("username"),
            "ack_notes": body.notes,
        },
    )
    return {"message": "Alert acknowledged"}


@router.post("/{alert_id}/escalate")
async def escalate_to_incident(
    alert_id: str,
    current_user: dict = Depends(require_analyst),
):
    from datetime import datetime
    alert = await db_find_one("alerts", {"_id": alert_id})
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    incident = {
        "title": f"[Escalated] {alert.get('title', 'Security Alert')}",
        "description": alert.get("description", ""),
        "severity": alert.get("severity", "high"),
        "status": "open",
        "alert_ids": [alert_id],
        "assigned_to": current_user.get("username"),
        "created_by": current_user.get("username"),
        "mitre_techniques": alert.get("mitre_techniques", []),
        "source_ip": alert.get("source_ip", ""),
        "hostname": alert.get("hostname", ""),
        "timeline": [
            {
                "ts": datetime.utcnow().isoformat(),
                "action": "incident_created",
                "actor": current_user.get("username"),
                "note": f"Escalated from alert {alert_id}",
            }
        ],
        "notes": [],
        "tags": alert.get("tags", []),
    }
    incident_id = await db_insert("incidents", incident)
    await db_update_one("alerts", {"_id": alert_id}, {"incident_id": incident_id})
    return {"message": "Escalated to incident", "incident_id": incident_id}


@router.get("/stats/summary")
async def alert_summary(current_user: dict = Depends(get_current_user)):
    from db.database import db_aggregate_severity
    by_severity = await db_aggregate_severity("alerts")
    unacked = await db_count("alerts", {"acknowledged": False})
    critical = await db_count("alerts", {"severity": "critical"})
    return {"by_severity": by_severity, "unacknowledged": unacked, "critical": critical}
