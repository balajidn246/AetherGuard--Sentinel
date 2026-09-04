"""
Case Management routes - Full investigation cases with evidence, timeline, notes, and signal correlation.
"""
from datetime import datetime, timezone
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, func, update

from backend.api.middleware.auth import get_current_user, require_analyst
from backend.db.postgres import AsyncSessionLocal
from backend.models.case import Case
from backend.models.signal import SecuritySignal
from backend.services.audit_service import audit_service

router = APIRouter()

class CaseCreate(BaseModel):
    title: str
    description: str = ""
    priority: str = "medium"
    signal_ids: List[str] = []
    incident_ids: List[str] = []
    tags: List[str] = []

class CaseUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    priority: Optional[str] = None
    owner_id: Optional[str] = None

class CaseNote(BaseModel):
    content: str

VALID_STATUSES = ["open", "investigating", "contained", "resolved", "closed"]

@router.get("/")
async def list_cases(
    status: Optional[str] = Query(None),
    priority: Optional[str] = Query(None),
    owner_id: Optional[str] = Query(None),
    limit: int = Query(50, le=200),
    skip: int = Query(0),
    current_user: dict = Depends(get_current_user),
):
    tenant_id = current_user.get("tenant_id", "default")
    cases_list = []
    total = 0

    async with AsyncSessionLocal() as session:
        query = select(Case).where(Case.tenant_id == tenant_id)
        count_query = select(func.count(Case.id)).where(Case.tenant_id == tenant_id)

        if status:
            query = query.where(Case.status == status.lower())
            count_query = count_query.where(Case.status == status.lower())
        if priority:
            query = query.where(Case.priority == priority.lower())
            count_query = count_query.where(Case.priority == priority.lower())
        if owner_id:
            query = query.where(Case.owner_id == owner_id)
            count_query = count_query.where(Case.owner_id == owner_id)

        query = query.order_by(Case.created_at.desc()).offset(skip).limit(limit)

        total = (await session.execute(count_query)).scalar() or 0
        rows = (await session.execute(query)).scalars().all()

        for c in rows:
            cases_list.append({
                "id": c.id,
                "title": c.title,
                "description": c.description,
                "status": c.status,
                "priority": c.priority,
                "owner_id": c.owner_id,
                "signal_ids": c.signal_ids or [],
                "incident_ids": c.incident_ids or [],
                "evidence_refs": c.evidence_refs or [],
                "timeline": c.timeline or [],
                "notes": c.notes or [],
                "ai_summary": c.ai_summary,
                "created_at": c.created_at.isoformat() if c.created_at else "",
                "updated_at": c.updated_at.isoformat() if c.updated_at else ""
            })

    return {"cases": cases_list, "total": total}

@router.get("/{case_id}")
async def get_case(case_id: str, current_user: dict = Depends(get_current_user)):
    tenant_id = current_user.get("tenant_id", "default")
    async with AsyncSessionLocal() as session:
        stmt = select(Case).where(Case.id == case_id, Case.tenant_id == tenant_id)
        c = (await session.execute(stmt)).scalar_one_or_none()
        if not c:
            raise HTTPException(status_code=404, detail="Case not found")

        return {
            "id": c.id,
            "title": c.title,
            "description": c.description,
            "status": c.status,
            "priority": c.priority,
            "owner_id": c.owner_id,
            "signal_ids": c.signal_ids or [],
            "incident_ids": c.incident_ids or [],
            "evidence_refs": c.evidence_refs or [],
            "timeline": c.timeline or [],
            "notes": c.notes or [],
            "ai_summary": c.ai_summary,
            "created_at": c.created_at.isoformat() if c.created_at else "",
            "updated_at": c.updated_at.isoformat() if c.updated_at else ""
        }

@router.post("/")
async def create_case(body: CaseCreate, current_user: dict = Depends(require_analyst)):
    tenant_id = current_user.get("tenant_id", "default")
    username = current_user.get("username", "analyst")

    evidence = []
    timeline = [{
        "action": "case_created",
        "actor": username,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "details": f"Case created: {body.title}"
    }]

    async with AsyncSessionLocal() as session:
        # Collect evidence references from associated signals if given
        if body.signal_ids:
            stmt = select(SecuritySignal).where(
                SecuritySignal.id.in_(body.signal_ids),
                SecuritySignal.tenant_id == tenant_id
            )
            signals = (await session.execute(stmt)).scalars().all()
            for s in signals:
                evidence.extend(s.evidence_refs or [])

        new_case = Case(
            tenant_id=tenant_id,
            title=body.title,
            description=body.description,
            priority=body.priority,
            status="open",
            owner_id=username,
            signal_ids=body.signal_ids,
            incident_ids=body.incident_ids,
            evidence_refs=list(set(evidence)),
            timeline=timeline,
            notes=[{
                "author": username,
                "content": "Initial case creation",
                "ts": datetime.now(timezone.utc).isoformat()
            }]
        )
        session.add(new_case)
        await session.commit()

        await audit_service.log_action(
            actor_id=current_user.get("sub", ""),
            actor_username=username,
            action="case.create",
            resource="case",
            resource_id=new_case.id,
            details={"title": body.title, "priority": body.priority},
            tenant_id=tenant_id
        )

        return {"message": "Case created", "case_id": new_case.id}

@router.patch("/{case_id}")
async def update_case(case_id: str, body: CaseUpdate, current_user: dict = Depends(require_analyst)):
    tenant_id = current_user.get("tenant_id", "default")
    username = current_user.get("username", "analyst")

    async with AsyncSessionLocal() as session:
        stmt = select(Case).where(Case.id == case_id, Case.tenant_id == tenant_id)
        c = (await session.execute(stmt)).scalar_one_or_none()
        if not c:
            raise HTTPException(status_code=404, detail="Case not found")

        timeline = list(c.timeline or [])
        if body.title is not None:
            c.title = body.title
        if body.description is not None:
            c.description = body.description
        if body.priority is not None:
            c.priority = body.priority
        if body.owner_id is not None:
            c.owner_id = body.owner_id
        if body.status is not None:
            if body.status not in VALID_STATUSES:
                raise HTTPException(status_code=400, detail=f"Invalid status: {body.status}")
            timeline.append({
                "action": "status_change",
                "actor": username,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "details": f"Status updated from {c.status} to {body.status}"
            })
            c.status = body.status

        c.timeline = timeline
        await session.commit()

        await audit_service.log_action(
            actor_id=current_user.get("sub", ""),
            actor_username=username,
            action="case.update",
            resource="case",
            resource_id=case_id,
            details=body.model_dump(exclude_unset=True),
            tenant_id=tenant_id
        )

        return {"message": "Case updated"}

@router.post("/{case_id}/notes")
async def add_case_note(case_id: str, body: CaseNote, current_user: dict = Depends(require_analyst)):
    tenant_id = current_user.get("tenant_id", "default")
    username = current_user.get("username", "analyst")

    async with AsyncSessionLocal() as session:
        stmt = select(Case).where(Case.id == case_id, Case.tenant_id == tenant_id)
        c = (await session.execute(stmt)).scalar_one_or_none()
        if not c:
            raise HTTPException(status_code=404, detail="Case not found")

        notes = list(c.notes or [])
        notes.append({
            "author": username,
            "content": body.content,
            "ts": datetime.now(timezone.utc).isoformat()
        })
        c.notes = notes
        await session.commit()

        return {"message": "Note added"}

@router.post("/{case_id}/signals")
async def attach_signal(case_id: str, signal_id: str = Query(...), current_user: dict = Depends(require_analyst)):
    tenant_id = current_user.get("tenant_id", "default")
    username = current_user.get("username", "analyst")

    async with AsyncSessionLocal() as session:
        stmt = select(Case).where(Case.id == case_id, Case.tenant_id == tenant_id)
        c = (await session.execute(stmt)).scalar_one_or_none()
        if not c:
            raise HTTPException(status_code=404, detail="Case not found")

        sig_stmt = select(SecuritySignal).where(SecuritySignal.id == signal_id, SecuritySignal.tenant_id == tenant_id)
        s = (await session.execute(sig_stmt)).scalar_one_or_none()
        if not s:
            raise HTTPException(status_code=404, detail="SecuritySignal not found")

        signals = list(c.signal_ids or [])
        if signal_id not in signals:
            signals.append(signal_id)
        c.signal_ids = signals

        evidence = list(c.evidence_refs or [])
        for ref in (s.evidence_refs or []):
            if ref not in evidence:
                evidence.append(ref)
        c.evidence_refs = evidence

        timeline = list(c.timeline or [])
        timeline.append({
            "action": "signal_attached",
            "actor": username,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "details": f"Attached security signal: {s.title} ({s.id})"
        })
        c.timeline = timeline

        await session.commit()
        return {"message": "Signal attached to case"}
