"""
Threat Intelligence routes - REAL queries to PostgreSQL iocs table.
Zero fake reputation scores, zero random numbers.
"""
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, func, delete
from api.middleware.auth import get_current_user, require_analyst
from backend.db.postgres import AsyncSessionLocal
from backend.models.ioc import IOC

router = APIRouter()

class IOCCreate(BaseModel):
    ioc_type: str                  # ip | hash | domain | url
    value: str
    threat_type: str = "unknown"   # malware | phishing | c2 | scanner
    confidence: int = 50           # 0-100
    tags: List[str] = []
    notes: str = ""
    source: str = "manual"

@router.get("/iocs")
async def list_iocs(
    ioc_type: Optional[str] = Query(None),
    limit: int = Query(50, le=500),
    skip: int = Query(0),
    current_user: dict = Depends(get_current_user),
):
    tenant_id = current_user.get("tenant_id", "default")
    iocs_list = []
    total = 0

    async with AsyncSessionLocal() as session:
        query = select(IOC).where(IOC.tenant_id == tenant_id)
        count_query = select(func.count(IOC.id)).where(IOC.tenant_id == tenant_id)

        if ioc_type:
            query = query.where(IOC.ioc_type == ioc_type.lower())
            count_query = count_query.where(IOC.ioc_type == ioc_type.lower())

        query = query.order_by(IOC.created_at.desc()).offset(skip).limit(limit)

        total = (await session.execute(count_query)).scalar() or 0
        rows = (await session.execute(query)).scalars().all()

        for item in rows:
            iocs_list.append({
                "_id": item.id,
                "id": item.id,
                "ioc_type": item.ioc_type,
                "value": item.value,
                "threat_type": item.threat_type,
                "confidence": item.confidence,
                "tags": item.tags or [],
                "notes": item.notes or "",
                "source": item.source,
                "active": item.active,
                "created_by": item.created_by,
                "hit_count": item.hit_count,
                "created_at": item.created_at.isoformat() if item.created_at else ""
            })

    return {"iocs": iocs_list, "total": total}

@router.post("/iocs")
async def create_ioc(body: IOCCreate, current_user: dict = Depends(require_analyst)):
    tenant_id = current_user.get("tenant_id", "default")
    username = current_user.get("username", "analyst")

    async with AsyncSessionLocal() as session:
        ioc = IOC(
            tenant_id=tenant_id,
            ioc_type=body.ioc_type.lower(),
            value=body.value.strip(),
            threat_type=body.threat_type.lower(),
            confidence=max(0, min(100, body.confidence)),
            tags=body.tags or [],
            notes=body.notes or "",
            source=body.source or "manual",
            active=True,
            created_by=username,
            hit_count=0
        )
        session.add(ioc)
        await session.commit()
        return {"message": "IOC created", "ioc_id": ioc.id}

@router.delete("/iocs/{ioc_id}")
async def delete_ioc(ioc_id: str, current_user: dict = Depends(require_analyst)):
    tenant_id = current_user.get("tenant_id", "default")
    async with AsyncSessionLocal() as session:
        stmt = delete(IOC).where(
            IOC.id == ioc_id,
            IOC.tenant_id == tenant_id
        )
        res = await session.execute(stmt)
        if res.rowcount == 0:
            raise HTTPException(status_code=404, detail="IOC not found")
        await session.commit()

    return {"message": "IOC deleted"}

@router.get("/ip-reputation/{ip}")
async def ip_reputation(ip: str, current_user: dict = Depends(get_current_user)):
    """Check IP against real PostgreSQL IOC database. Never fabricates reputation."""
    tenant_id = current_user.get("tenant_id", "default")
    
    async with AsyncSessionLocal() as session:
        stmt = select(IOC).where(
            IOC.tenant_id == tenant_id,
            IOC.ioc_type == "ip",
            IOC.value == ip.strip()
        )
        match = (await session.execute(stmt)).scalar_one_or_none()
        
        if match and match.active:
            # Increment hit count on real match
            match.hit_count = (match.hit_count or 0) + 1
            await session.commit()
            return {
                "ip": ip,
                "risk_score": match.confidence,
                "is_malicious": True,
                "threat_type": match.threat_type,
                "threat_feed_match": False,
                "ioc_match": True,
                "tags": match.tags or ["ioc_match"],
                "notes": match.notes or "",
                "status": "MALICIOUS"
            }

    # If no real threat record exists in database, return genuine UNKNOWN state (Point 17)
    return {
        "ip": ip,
        "risk_score": 0,
        "is_malicious": False,
        "threat_type": "unknown",
        "threat_feed_match": False,
        "ioc_match": False,
        "tags": ["unclassified"],
        "notes": "No matching IOC found in local repository.",
        "status": "UNKNOWN"
    }

@router.get("/hash/{hash_value}")
async def check_hash(hash_value: str, current_user: dict = Depends(get_current_user)):
    """Check file hash against real PostgreSQL IOC database."""
    tenant_id = current_user.get("tenant_id", "default")
    
    async with AsyncSessionLocal() as session:
        stmt = select(IOC).where(
            IOC.tenant_id == tenant_id,
            IOC.ioc_type == "hash",
            IOC.value == hash_value.strip()
        )
        match = (await session.execute(stmt)).scalar_one_or_none()
        if match and match.active:
            return {
                "hash": hash_value,
                "is_malicious": True,
                "threat_type": match.threat_type,
                "risk_score": match.confidence
            }

    return {
        "hash": hash_value,
        "is_malicious": False,
        "threat_type": "unknown",
        "risk_score": 0
    }

@router.get("/feeds")
async def get_threat_feeds(current_user: dict = Depends(get_current_user)):
    """Return status of local threat feeds."""
    tenant_id = current_user.get("tenant_id", "default")
    local_ioc_count = 0
    async with AsyncSessionLocal() as session:
        stmt = select(func.count(IOC.id)).where(IOC.tenant_id == tenant_id)
        local_ioc_count = (await session.execute(stmt)).scalar() or 0

    return [
        {
            "name": "Local Threat Intel Repository",
            "status": "active",
            "source": "PostgreSQL",
            "ioc_count": local_ioc_count,
            "description": "Enterprise-managed indicators of compromise"
        }
    ]

@router.get("/blocklist")
async def get_blocklist(current_user: dict = Depends(get_current_user)):
    """Return real active blocklist IOCs from database."""
    tenant_id = current_user.get("tenant_id", "default")
    blocklist = []

    async with AsyncSessionLocal() as session:
        stmt = select(IOC).where(
            IOC.tenant_id == tenant_id,
            IOC.active == True
        ).limit(500)
        rows = (await session.execute(stmt)).scalars().all()
        for b in rows:
            blocklist.append({
                "id": b.id,
                "ioc_type": b.ioc_type,
                "value": b.value,
                "threat_type": b.threat_type,
                "confidence": b.confidence
            })

    return {"blocklist": blocklist, "total": len(blocklist)}

@router.post("/sync")
async def sync_threat_feeds(current_user: dict = Depends(require_analyst)):
    """Trigger external open-source threat feed ingestion (CISA KEV, etc.)."""
    from backend.services.threat_intel_service import threat_intel_service
    tenant_id = current_user.get("tenant_id", "default")
    synced = await threat_intel_service.sync_cisa_kev(tenant_id)
    return {"message": "Threat intelligence synchronization complete", "new_indicators": synced}

