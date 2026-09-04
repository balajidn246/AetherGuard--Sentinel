"""
Audit Log routes - Read-only query access to immutable audit trails for compliance & SOC accountability.
"""
from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, func

from backend.api.middleware.auth import get_current_user, require_admin
from backend.db.postgres import AsyncSessionLocal
from backend.models.audit_log import AuditLog

router = APIRouter()

@router.get("/")
async def list_audit_logs(
    actor: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    resource: Optional[str] = Query(None),
    limit: int = Query(50, le=200),
    skip: int = Query(0),
    current_user: dict = Depends(require_admin),
):
    tenant_id = current_user.get("tenant_id", "default")
    logs_list = []
    total = 0

    async with AsyncSessionLocal() as session:
        query = select(AuditLog).where(AuditLog.tenant_id == tenant_id)
        count_query = select(func.count(AuditLog.id)).where(AuditLog.tenant_id == tenant_id)

        if actor:
            query = query.where(AuditLog.actor_username == actor)
            count_query = count_query.where(AuditLog.actor_username == actor)
        if action:
            query = query.where(AuditLog.action == action)
            count_query = count_query.where(AuditLog.action == action)
        if resource:
            query = query.where(AuditLog.resource == resource)
            count_query = count_query.where(AuditLog.resource == resource)

        query = query.order_by(AuditLog.created_at.desc()).offset(skip).limit(limit)

        total = (await session.execute(count_query)).scalar() or 0
        rows = (await session.execute(query)).scalars().all()

        for log in rows:
            logs_list.append({
                "id": log.id,
                "timestamp": log.created_at.isoformat() if log.created_at else "",
                "actor": log.actor_username,
                "action": log.action,
                "resource": log.resource,
                "resource_id": log.resource_id,
                "details": log.details or {},
                "result": log.result,
                "ip_address": log.ip_address,
            })

    return {"audit_logs": logs_list, "total": total}

@router.get("/actions")
async def get_distinct_actions(current_user: dict = Depends(require_admin)):
    tenant_id = current_user.get("tenant_id", "default")
    async with AsyncSessionLocal() as session:
        stmt = select(AuditLog.action).where(AuditLog.tenant_id == tenant_id).distinct()
        actions = (await session.execute(stmt)).scalars().all()
        return {"actions": sorted(list(actions))}
