"""
Incident management routes - REAL queries to PostgreSQL incidents table.
"""
from datetime import datetime, timezone
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, func, update
from api.middleware.auth import get_current_user, require_analyst
from backend.db.postgres import AsyncSessionLocal
from backend.models.incident import Incident

router = APIRouter()

class IncidentCreate(BaseModel):
    title: str
    description: str
    severity: str = "medium"
    assigned_to: Optional[str] = None
    tags: List[str] = []
    source_ip: Optional[str] = None
    hostname: Optional[str] = None
    mitre_techniques: List[str] = []

class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    tags: Optional[List[str]] = None

class IncidentNote(BaseModel):
    content: str

VALID_STATUSES = ["open", "investigating", "contained", "resolved", "closed"]
VALID_TRANSITIONS = {
    "open": ["investigating", "closed"],
    "investigating": ["contained", "resolved", "open"],
    "contained": ["resolved", "investigating"],
    "resolved": ["closed", "investigating"],
    "closed": [],
}

@router.get("/")
async def list_incidents(
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    assigned_to: Optional[str] = Query(None),
    limit: int = Query(50, le=200),
    skip: int = Query(0),
    current_user: dict = Depends(get_current_user),
):
    tenant_id = current_user.get("tenant_id", "default")
    incidents_list = []
    total = 0

    async with AsyncSessionLocal() as session:
        query = select(Incident).where(Incident.tenant_id == tenant_id)
        count_query = select(func.count(Incident.id)).where(Incident.tenant_id == tenant_id)

        if status:
            query = query.where(Incident.status == status.lower())
            count_query = count_query.where(Incident.status == status.lower())
        if severity:
            query = query.where(Incident.severity == severity.lower())
            count_query = count_query.where(Incident.severity == severity.lower())
        if assigned_to:
            query = query.where(Incident.assignee == assigned_to)
            count_query = count_query.where(Incident.assignee == assigned_to)

        query = query.order_by(Incident.created_at.desc()).offset(skip).limit(limit)

        total = (await session.execute(count_query)).scalar() or 0
        rows = (await session.execute(query)).scalars().all()

        for inc in rows:
            incidents_list.append({
                "_id": inc.id,
                "id": inc.id,
                "title": inc.title,
                "description": inc.description,
                "severity": inc.severity,
                "status": inc.status,
                "assigned_to": inc.assignee,
                "source_signal_ids": inc.source_signal_ids or [],
                "tags": inc.tags or [],
                "notes": inc.notes or [],
                "created_at": inc.created_at.isoformat() if inc.created_at else "",
                "updated_at": inc.updated_at.isoformat() if inc.updated_at else ""
            })

    return {"incidents": incidents_list, "total": total}

@router.get("/stats")
async def incident_stats(current_user: dict = Depends(get_current_user)):
    tenant_id = current_user.get("tenant_id", "default")
    counts = {s: 0 for s in VALID_STATUSES}
    total = 0

    async with AsyncSessionLocal() as session:
        stmt = select(Incident.status, func.count(Incident.id)).where(
            Incident.tenant_id == tenant_id
        ).group_by(Incident.status)
        for row in (await session.execute(stmt)).all():
            st = str(row[0]).lower()
            if st in counts:
                counts[st] = row[1]

        total_stmt = select(func.count(Incident.id)).where(Incident.tenant_id == tenant_id)
        total = (await session.execute(total_stmt)).scalar() or 0

    return {"by_status": counts, "total": total}

@router.get("/{incident_id}")
async def get_incident(incident_id: str, current_user: dict = Depends(get_current_user)):
    tenant_id = current_user.get("tenant_id", "default")
    async with AsyncSessionLocal() as session:
        stmt = select(Incident).where(
            Incident.id == incident_id,
            Incident.tenant_id == tenant_id
        )
        inc = (await session.execute(stmt)).scalar_one_or_none()
        if not inc:
            raise HTTPException(status_code=404, detail="Incident not found")

        return {
            "_id": inc.id,
            "id": inc.id,
            "title": inc.title,
            "description": inc.description,
            "severity": inc.severity,
            "status": inc.status,
            "assigned_to": inc.assignee,
            "source_signal_ids": inc.source_signal_ids or [],
            "tags": inc.tags or [],
            "notes": inc.notes or [],
            "created_at": inc.created_at.isoformat() if inc.created_at else "",
            "updated_at": inc.updated_at.isoformat() if inc.updated_at else ""
        }

@router.post("/")
async def create_incident(body: IncidentCreate, current_user: dict = Depends(require_analyst)):
    tenant_id = current_user.get("tenant_id", "default")
    username = current_user.get("username", "analyst")

    async with AsyncSessionLocal() as session:
        inc = Incident(
            tenant_id=tenant_id,
            title=body.title,
            description=body.description,
            severity=body.severity,
            status="open",
            assignee=body.assigned_to or username,
            tags=body.tags or [],
            notes=[{
                "author": username,
                "content": "Incident created manually",
                "ts": datetime.now(timezone.utc).isoformat()
            }]
        )
        session.add(inc)
        await session.commit()
        return {"message": "Incident created", "incident_id": inc.id}

@router.put("/{incident_id}")
async def update_incident(
    incident_id: str,
    body: IncidentUpdate,
    current_user: dict = Depends(require_analyst),
):
    tenant_id = current_user.get("tenant_id", "default")
    async with AsyncSessionLocal() as session:
        stmt = select(Incident).where(
            Incident.id == incident_id,
            Incident.tenant_id == tenant_id
        )
        inc = (await session.execute(stmt)).scalar_one_or_none()
        if not inc:
            raise HTTPException(status_code=404, detail="Incident not found")

        if body.title is not None:
            inc.title = body.title
        if body.description is not None:
            inc.description = body.description
        if body.severity is not None:
            inc.severity = body.severity
        if body.assigned_to is not None:
            inc.assignee = body.assigned_to
        if body.tags is not None:
            inc.tags = body.tags
        if body.status is not None:
            if body.status not in VALID_TRANSITIONS.get(inc.status, []):
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid transition: {inc.status} -> {body.status}",
                )
            inc.status = body.status

        await session.commit()
        return {"message": "Incident updated"}

@router.post("/{incident_id}/transition")
async def transition_status(
    incident_id: str,
    new_status: str,
    current_user: dict = Depends(require_analyst),
):
    tenant_id = current_user.get("tenant_id", "default")
    username = current_user.get("username", "analyst")

    async with AsyncSessionLocal() as session:
        stmt = select(Incident).where(
            Incident.id == incident_id,
            Incident.tenant_id == tenant_id
        )
        inc = (await session.execute(stmt)).scalar_one_or_none()
        if not inc:
            raise HTTPException(status_code=404, detail="Incident not found")

        if new_status not in VALID_TRANSITIONS.get(inc.status, []):
            raise HTTPException(
                status_code=400,
                detail=f"Cannot transition from {inc.status} to {new_status}",
            )

        notes = list(inc.notes or [])
        notes.append({
            "author": username,
            "content": f"Status changed: {inc.status} -> {new_status}",
            "ts": datetime.now(timezone.utc).isoformat()
        })
        inc.notes = notes
        inc.status = new_status
        await session.commit()
        return {"message": f"Status updated to {new_status}"}

@router.post("/{incident_id}/notes")
async def add_note(
    incident_id: str,
    body: IncidentNote,
    current_user: dict = Depends(require_analyst),
):
    tenant_id = current_user.get("tenant_id", "default")
    username = current_user.get("username", "analyst")

    async with AsyncSessionLocal() as session:
        stmt = select(Incident).where(
            Incident.id == incident_id,
            Incident.tenant_id == tenant_id
        )
        inc = (await session.execute(stmt)).scalar_one_or_none()
        if not inc:
            raise HTTPException(status_code=404, detail="Incident not found")

        notes = list(inc.notes or [])
        notes.append({
            "content": body.content,
            "author": username,
            "ts": datetime.now(timezone.utc).isoformat()
        })
        inc.notes = notes
        await session.commit()
        return {"message": "Note added"}
