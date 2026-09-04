"""
Alert & Security Signal management routes - REAL queries to PostgreSQL security_signals table.
"""
from fastapi import APIRouter, Depends, Query, HTTPException
from typing import Optional
from pydantic import BaseModel
from sqlalchemy import select, func, update
from api.middleware.auth import get_current_user, require_analyst
from backend.db.postgres import AsyncSessionLocal
from backend.models.signal import SecuritySignal
from backend.models.incident import Incident

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
    tenant_id = current_user.get("tenant_id", "default")
    alerts_list = []
    total = 0

    async with AsyncSessionLocal() as session:
        query = select(SecuritySignal).where(SecuritySignal.tenant_id == tenant_id)
        count_query = select(func.count(SecuritySignal.id)).where(SecuritySignal.tenant_id == tenant_id)

        if severity:
            query = query.where(SecuritySignal.severity == severity.lower())
            count_query = count_query.where(SecuritySignal.severity == severity.lower())
        if acknowledged is not None:
            query = query.where(SecuritySignal.acknowledged == acknowledged)
            count_query = count_query.where(SecuritySignal.acknowledged == acknowledged)
        if rule_name:
            query = query.where(SecuritySignal.rule_name == rule_name)
            count_query = count_query.where(SecuritySignal.rule_name == rule_name)

        query = query.order_by(SecuritySignal.created_at.desc()).offset(skip).limit(limit)

        total = (await session.execute(count_query)).scalar() or 0
        rows = (await session.execute(query)).scalars().all()

        for s in rows:
            alerts_list.append({
                "_id": s.id,
                "created_at": s.created_at.isoformat() if s.created_at else "",
                "title": s.title,
                "description": s.description,
                "severity": s.severity,
                "rule_name": s.rule_name,
                "source_ip": s.source_ip,
                "hostname": s.hostname,
                "username": s.username,
                "acknowledged": s.acknowledged,
                "acknowledged_by": s.acknowledged_by,
                "ack_notes": s.ack_notes,
                "incident_id": s.incident_id,
                "mitre_techniques": s.mitre_tactics or [],
                "tags": s.tags or [],
                "ai_verdict": s.ai_verdict,
                "ai_confidence": s.ai_confidence,
                "ai_analysis": s.ai_analysis,
                "evidence_refs": s.evidence_refs or []
            })

    return {"alerts": alerts_list, "total": total}

@router.get("/{alert_id}")
async def get_alert(alert_id: str, current_user: dict = Depends(get_current_user)):
    tenant_id = current_user.get("tenant_id", "default")
    async with AsyncSessionLocal() as session:
        stmt = select(SecuritySignal).where(
            SecuritySignal.id == alert_id,
            SecuritySignal.tenant_id == tenant_id
        )
        s = (await session.execute(stmt)).scalar_one_or_none()
        if not s:
            raise HTTPException(status_code=404, detail="Alert not found")

        return {
            "_id": s.id,
            "created_at": s.created_at.isoformat() if s.created_at else "",
            "title": s.title,
            "description": s.description,
            "severity": s.severity,
            "rule_name": s.rule_name,
            "source_ip": s.source_ip,
            "hostname": s.hostname,
            "username": s.username,
            "acknowledged": s.acknowledged,
            "acknowledged_by": s.acknowledged_by,
            "ack_notes": s.ack_notes,
            "incident_id": s.incident_id,
            "mitre_techniques": s.mitre_tactics or [],
            "tags": s.tags or [],
            "ai_verdict": s.ai_verdict,
            "ai_confidence": s.ai_confidence,
            "ai_analysis": s.ai_analysis,
            "evidence_refs": s.evidence_refs or []
        }

@router.post("/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: str,
    body: AlertAckRequest,
    current_user: dict = Depends(require_analyst),
):
    tenant_id = current_user.get("tenant_id", "default")
    username = current_user.get("username", "analyst")
    async with AsyncSessionLocal() as session:
        stmt = update(SecuritySignal).where(
            SecuritySignal.id == alert_id,
            SecuritySignal.tenant_id == tenant_id
        ).values(
            acknowledged=True,
            acknowledged_by=username,
            ack_notes=body.notes
        )
        res = await session.execute(stmt)
        if res.rowcount == 0:
            raise HTTPException(status_code=404, detail="Alert not found")
        await session.commit()

    return {"message": "Alert acknowledged", "acknowledged_by": username}

@router.post("/{alert_id}/escalate")
async def escalate_to_incident(
    alert_id: str,
    current_user: dict = Depends(require_analyst),
):
    tenant_id = current_user.get("tenant_id", "default")
    username = current_user.get("username", "analyst")
    async with AsyncSessionLocal() as session:
        stmt = select(SecuritySignal).where(
            SecuritySignal.id == alert_id,
            SecuritySignal.tenant_id == tenant_id
        )
        s = (await session.execute(stmt)).scalar_one_or_none()
        if not s:
            raise HTTPException(status_code=404, detail="Alert not found")

        # Create real Incident
        inc = Incident(
            tenant_id=tenant_id,
            title=f"[Escalated] {s.title}",
            description=s.description or f"Escalated from security signal {s.id}",
            severity=s.severity,
            status="open",
            assignee=username,
            source_signal_ids=[s.id],
            tags=s.tags or [],
            notes=[{"author": username, "content": f"Escalated from alert {s.id}", "ts": s.created_at.isoformat() if s.created_at else ""}]
        )
        session.add(inc)
        await session.flush()

        s.incident_id = inc.id
        await session.commit()
        return {"message": "Escalated to incident", "incident_id": inc.id}

@router.get("/stats/summary")
async def alert_summary(current_user: dict = Depends(get_current_user)):
    tenant_id = current_user.get("tenant_id", "default")
    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    unacked = 0
    critical = 0

    async with AsyncSessionLocal() as session:
        sev_stmt = select(SecuritySignal.severity, func.count(SecuritySignal.id)).where(
            SecuritySignal.tenant_id == tenant_id
        ).group_by(SecuritySignal.severity)
        for row in (await session.execute(sev_stmt)).all():
            by_severity[str(row[0]).lower()] = row[1]

        unacked_stmt = select(func.count(SecuritySignal.id)).where(
            SecuritySignal.tenant_id == tenant_id,
            SecuritySignal.acknowledged == False
        )
        unacked = (await session.execute(unacked_stmt)).scalar() or 0

        crit_stmt = select(func.count(SecuritySignal.id)).where(
            SecuritySignal.tenant_id == tenant_id,
            SecuritySignal.severity == "critical"
        )
        critical = (await session.execute(crit_stmt)).scalar() or 0

    return {"by_severity": by_severity, "unacknowledged": unacked, "critical": critical}
