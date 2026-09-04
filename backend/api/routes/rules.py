"""
Detection Rule Management - View, create, test, and toggle Python, YAML, and Sigma rules.
"""
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, update

from backend.api.middleware.auth import get_current_user, require_admin, require_analyst
from backend.db.postgres import AsyncSessionLocal
from backend.models.detection_rule import DetectionRuleModel
from backend.services.audit_service import audit_service

router = APIRouter()

class RuleCreate(BaseModel):
    rule_id: str
    name: str
    description: str = ""
    severity: str = "medium"
    rule_type: str = "yaml"  # yaml, sigma
    mitre_techniques: List[str] = []
    author: str = "AetherGuard Analyst"
    content: Dict[str, Any] = {}
    false_positive_notes: str = ""

class RuleToggle(BaseModel):
    enabled: bool

class RuleTestRequest(BaseModel):
    event: Dict[str, Any]

@router.get("/")
async def list_rules(
    rule_type: Optional[str] = Query(None),
    enabled: Optional[bool] = Query(None),
    current_user: dict = Depends(get_current_user)
):
    tenant_id = current_user.get("tenant_id", "default")
    rules_list = []

    async with AsyncSessionLocal() as session:
        query = select(DetectionRuleModel).where(DetectionRuleModel.tenant_id == tenant_id)
        if rule_type:
            query = query.where(DetectionRuleModel.rule_type == rule_type)
        if enabled is not None:
            query = query.where(DetectionRuleModel.enabled == enabled)

        query = query.order_by(DetectionRuleModel.created_at.desc())
        rows = (await session.execute(query)).scalars().all()

        for r in rows:
            rules_list.append({
                "id": r.id,
                "rule_id": r.rule_id,
                "name": r.name,
                "description": r.description,
                "severity": r.severity,
                "rule_type": r.rule_type,
                "enabled": r.enabled,
                "mitre_techniques": r.mitre_techniques or [],
                "author": r.author,
                "version": r.version,
                "hit_count": r.hit_count,
                "content": r.content,
                "false_positive_notes": r.false_positive_notes,
                "created_at": r.created_at.isoformat() if r.created_at else "",
            })

    return {"rules": rules_list, "total": len(rules_list)}

@router.get("/{rule_id}")
async def get_rule(rule_id: str, current_user: dict = Depends(get_current_user)):
    tenant_id = current_user.get("tenant_id", "default")
    async with AsyncSessionLocal() as session:
        stmt = select(DetectionRuleModel).where(
            DetectionRuleModel.rule_id == rule_id,
            DetectionRuleModel.tenant_id == tenant_id
        )
        r = (await session.execute(stmt)).scalar_one_or_none()
        if not r:
            raise HTTPException(status_code=404, detail="Rule not found")

        return {
            "id": r.id,
            "rule_id": r.rule_id,
            "name": r.name,
            "description": r.description,
            "severity": r.severity,
            "rule_type": r.rule_type,
            "enabled": r.enabled,
            "mitre_techniques": r.mitre_techniques or [],
            "author": r.author,
            "version": r.version,
            "hit_count": r.hit_count,
            "content": r.content,
            "false_positive_notes": r.false_positive_notes,
        }

@router.post("/")
async def create_rule(body: RuleCreate, current_user: dict = Depends(require_admin)):
    tenant_id = current_user.get("tenant_id", "default")
    username = current_user.get("username", "admin")

    async with AsyncSessionLocal() as session:
        # Check duplicate rule_id
        stmt = select(DetectionRuleModel).where(
            DetectionRuleModel.rule_id == body.rule_id,
            DetectionRuleModel.tenant_id == tenant_id
        )
        existing = (await session.execute(stmt)).scalar_one_or_none()
        if existing:
            raise HTTPException(status_code=400, detail=f"Rule with ID '{body.rule_id}' already exists")

        new_rule = DetectionRuleModel(
            tenant_id=tenant_id,
            rule_id=body.rule_id,
            name=body.name,
            description=body.description,
            severity=body.severity,
            rule_type=body.rule_type,
            enabled=True,
            mitre_techniques=body.mitre_techniques,
            author=body.author or username,
            content=body.content,
            false_positive_notes=body.false_positive_notes,
        )
        session.add(new_rule)
        await session.commit()

        await audit_service.log_action(
            actor_id=current_user.get("sub", ""),
            actor_username=username,
            action="rule.create",
            resource="detection_rule",
            resource_id=new_rule.rule_id,
            details={"name": body.name, "severity": body.severity},
            tenant_id=tenant_id
        )

        return {"message": "Detection rule registered", "rule_id": new_rule.rule_id}

@router.patch("/{rule_id}/enable")
async def toggle_rule(rule_id: str, body: RuleToggle, current_user: dict = Depends(require_admin)):
    tenant_id = current_user.get("tenant_id", "default")
    username = current_user.get("username", "admin")

    async with AsyncSessionLocal() as session:
        stmt = update(DetectionRuleModel).where(
            DetectionRuleModel.rule_id == rule_id,
            DetectionRuleModel.tenant_id == tenant_id
        ).values(enabled=body.enabled)
        res = await session.execute(stmt)
        if res.rowcount == 0:
            raise HTTPException(status_code=404, detail="Rule not found")
        await session.commit()

        await audit_service.log_action(
            actor_id=current_user.get("sub", ""),
            actor_username=username,
            action="rule.toggle",
            resource="detection_rule",
            resource_id=rule_id,
            details={"enabled": body.enabled},
            tenant_id=tenant_id
        )

        return {"message": f"Rule '{rule_id}' enabled set to {body.enabled}"}

@router.post("/{rule_id}/test")
async def test_rule(rule_id: str, body: RuleTestRequest, current_user: dict = Depends(require_analyst)):
    """Test a rule evaluation against a mock or sample event."""
    tenant_id = current_user.get("tenant_id", "default")
    async with AsyncSessionLocal() as session:
        stmt = select(DetectionRuleModel).where(
            DetectionRuleModel.rule_id == rule_id,
            DetectionRuleModel.tenant_id == tenant_id
        )
        r = (await session.execute(stmt)).scalar_one_or_none()
        if not r:
            raise HTTPException(status_code=404, detail="Rule not found")

        # Test against rule conditions in content
        matched = False
        reason = "Rule condition not satisfied"
        content = r.content or {}
        conditions = content.get("conditions", {})

        if conditions:
            all_match = True
            for field, expected in conditions.items():
                actual = body.event.get(field)
                if isinstance(expected, list):
                    if actual not in expected:
                        all_match = False
                        break
                elif actual != expected:
                    all_match = False
                    break
            matched = all_match
            reason = "All conditions matched" if matched else "Condition mismatch"
        else:
            # Fallback simple keyword match in message
            target_kw = content.get("keyword")
            if target_kw and target_kw.lower() in str(body.event.get("message", "")).lower():
                matched = True
                reason = f"Keyword '{target_kw}' matched in message"

        return {
            "rule_id": rule_id,
            "tested_against": body.event,
            "matched": matched,
            "reason": reason,
            "severity_if_triggered": r.severity
        }
