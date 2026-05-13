"""
Incident management routes — full CRUD + workflow transitions.
"""
from datetime import datetime
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from api.middleware.auth import get_current_user, require_analyst
from db.database import db_find, db_find_one, db_insert, db_update_one, db_count

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
    query = {}
    if status:
        query["status"] = status
    if severity:
        query["severity"] = severity
    if assigned_to:
        query["assigned_to"] = assigned_to

    incidents = await db_find("incidents", query, limit=limit, skip=skip)
    total = await db_count("incidents", query)
    return {"incidents": incidents, "total": total}


@router.get("/stats")
async def incident_stats(current_user: dict = Depends(get_current_user)):
    counts = {}
    for s in VALID_STATUSES:
        counts[s] = await db_count("incidents", {"status": s})
    total = await db_count("incidents")
    return {"by_status": counts, "total": total}


@router.get("/{incident_id}")
async def get_incident(incident_id: str, current_user: dict = Depends(get_current_user)):
    incident = await db_find_one("incidents", {"_id": incident_id})
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.post("/")
async def create_incident(body: IncidentCreate, current_user: dict = Depends(require_analyst)):
    incident = {
        "title": body.title,
        "description": body.description,
        "severity": body.severity,
        "status": "open",
        "assigned_to": body.assigned_to or current_user.get("username"),
        "created_by": current_user.get("username"),
        "tags": body.tags,
        "source_ip": body.source_ip or "",
        "hostname": body.hostname or "",
        "mitre_techniques": body.mitre_techniques,
        "alert_ids": [],
        "notes": [],
        "timeline": [
            {
                "ts": datetime.utcnow().isoformat(),
                "action": "incident_created",
                "actor": current_user.get("username"),
                "note": "Incident created manually",
            }
        ],
    }
    incident_id = await db_insert("incidents", incident)
    return {"message": "Incident created", "incident_id": incident_id}


@router.put("/{incident_id}")
async def update_incident(
    incident_id: str,
    body: IncidentUpdate,
    current_user: dict = Depends(require_analyst),
):
    incident = await db_find_one("incidents", {"_id": incident_id})
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    updates = {k: v for k, v in body.dict().items() if v is not None}
    updates["updated_at"] = datetime.utcnow().isoformat()
    updates["updated_by"] = current_user.get("username")

    if "status" in updates:
        current_status = incident.get("status", "open")
        new_status = updates["status"]
        if new_status not in VALID_TRANSITIONS.get(current_status, []):
            raise HTTPException(
                status_code=400,
                detail=f"Invalid transition: {current_status} → {new_status}",
            )

    await db_update_one("incidents", {"_id": incident_id}, updates)
    return {"message": "Incident updated"}


@router.post("/{incident_id}/transition")
async def transition_status(
    incident_id: str,
    new_status: str,
    current_user: dict = Depends(require_analyst),
):
    incident = await db_find_one("incidents", {"_id": incident_id})
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    current_status = incident.get("status", "open")
    if new_status not in VALID_TRANSITIONS.get(current_status, []):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot transition from {current_status} to {new_status}",
        )

    timeline = incident.get("timeline", [])
    timeline.append({
        "ts": datetime.utcnow().isoformat(),
        "action": "status_change",
        "actor": current_user.get("username"),
        "note": f"Status changed: {current_status} → {new_status}",
    })

    await db_update_one(
        "incidents",
        {"_id": incident_id},
        {"status": new_status, "timeline": timeline, "updated_at": datetime.utcnow().isoformat()},
    )
    return {"message": f"Status updated to {new_status}"}


@router.post("/{incident_id}/notes")
async def add_note(
    incident_id: str,
    body: IncidentNote,
    current_user: dict = Depends(require_analyst),
):
    incident = await db_find_one("incidents", {"_id": incident_id})
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    notes = incident.get("notes", [])
    notes.append({
        "content": body.content,
        "author": current_user.get("username"),
        "ts": datetime.utcnow().isoformat(),
    })
    await db_update_one("incidents", {"_id": incident_id}, {"notes": notes})
    return {"message": "Note added"}
