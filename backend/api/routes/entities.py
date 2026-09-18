"""
Entity Graph API — Canonical entity node and relationship queries.
Provides the backend for the Security Graph / Entity Topology view.

All queries are tenant-scoped. Zero cross-tenant data leakage.
"""
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy import select, func, and_
from typing import Optional
from api.middleware.auth import get_current_user
from backend.db.postgres import AsyncSessionLocal
from backend.db.clickhouse import get_clickhouse
from backend.models.entities import EntityNode, EntityRelationship
from backend.core.logging import get_logger

logger = get_logger(__name__)
router = APIRouter()


# ---------------------------------------------------------------------------
# GET /api/entities/nodes
# ---------------------------------------------------------------------------
@router.get("/nodes")
async def list_entity_nodes(
    entity_type: Optional[str] = Query(None, description="Filter by type: ip, user, host, domain, process, file_hash"),
    risk_level: Optional[str] = Query(None, description="Filter by risk_level: low, medium, high, critical"),
    limit: int = Query(100, le=500),
    offset: int = Query(0, ge=0),
    current_user: dict = Depends(get_current_user)
):
    """List canonical entity nodes for this tenant, with optional filters."""
    tenant_id = current_user.get("tenant_id", "default")

    async with AsyncSessionLocal() as session:
        q = select(EntityNode).where(EntityNode.tenant_id == tenant_id)
        if entity_type:
            q = q.where(EntityNode.entity_type == entity_type)
        if risk_level:
            q = q.where(EntityNode.risk_level == risk_level)
        q = q.order_by(EntityNode.last_seen.desc()).limit(limit).offset(offset)
        rows = (await session.execute(q)).scalars().all()

    return [
        {
            "id": n.id,
            "entity_type": n.entity_type,
            "canonical_value": n.canonical_value,
            "display_value": n.display_value,
            "first_seen": n.first_seen.isoformat() if n.first_seen else None,
            "last_seen": n.last_seen.isoformat() if n.last_seen else None,
            "current_risk_score": n.current_risk_score,
            "risk_level": n.risk_level,
            "status": n.status,
            "attributes": n.attributes or {},
        }
        for n in rows
    ]


# ---------------------------------------------------------------------------
# GET /api/entities/nodes/{node_id}
# ---------------------------------------------------------------------------
@router.get("/nodes/{node_id}")
async def get_entity_node(
    node_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Fetch a single entity node by ID."""
    tenant_id = current_user.get("tenant_id", "default")

    async with AsyncSessionLocal() as session:
        row = (await session.execute(
            select(EntityNode).where(
                and_(EntityNode.id == node_id, EntityNode.tenant_id == tenant_id)
            )
        )).scalar_one_or_none()

    if not row:
        raise HTTPException(status_code=404, detail="Entity not found")

    return {
        "id": row.id,
        "entity_type": row.entity_type,
        "canonical_value": row.canonical_value,
        "display_value": row.display_value,
        "first_seen": row.first_seen.isoformat() if row.first_seen else None,
        "last_seen": row.last_seen.isoformat() if row.last_seen else None,
        "current_risk_score": row.current_risk_score,
        "risk_level": row.risk_level,
        "status": row.status,
        "attributes": row.attributes or {},
    }


# ---------------------------------------------------------------------------
# GET /api/entities/nodes/{node_id}/graph
# Returns the ego-graph: the node + all immediate neighbours + edges
# ---------------------------------------------------------------------------
@router.get("/nodes/{node_id}/graph")
async def get_entity_graph(
    node_id: str,
    depth: int = Query(1, le=2, description="Graph traversal depth (max 2)"),
    current_user: dict = Depends(get_current_user)
):
    """
    Returns the entity ego-graph for a specific node:
    - The focal node
    - All relationships where it is source or target
    - All neighbour nodes

    This is the data source for the Security Graph UI.
    """
    tenant_id = current_user.get("tenant_id", "default")

    async with AsyncSessionLocal() as session:
        # Focal node
        focal = (await session.execute(
            select(EntityNode).where(
                and_(EntityNode.id == node_id, EntityNode.tenant_id == tenant_id)
            )
        )).scalar_one_or_none()

        if not focal:
            raise HTTPException(status_code=404, detail="Entity not found")

        # First-degree relationships (source or target)
        rels = (await session.execute(
            select(EntityRelationship).where(
                and_(
                    EntityRelationship.tenant_id == tenant_id,
                    (EntityRelationship.source_entity_id == node_id) |
                    (EntityRelationship.target_entity_id == node_id)
                )
            )
        )).scalars().all()

        # Collect neighbour IDs
        neighbour_ids = set()
        for r in rels:
            if r.source_entity_id != node_id:
                neighbour_ids.add(r.source_entity_id)
            if r.target_entity_id != node_id:
                neighbour_ids.add(r.target_entity_id)

        # Fetch neighbour nodes
        neighbour_nodes = []
        if neighbour_ids:
            neighbour_nodes = (await session.execute(
                select(EntityNode).where(
                    and_(
                        EntityNode.id.in_(list(neighbour_ids)),
                        EntityNode.tenant_id == tenant_id
                    )
                )
            )).scalars().all()

    def _node_to_dict(n):
        return {
            "id": n.id,
            "entity_type": n.entity_type,
            "canonical_value": n.canonical_value,
            "display_value": n.display_value,
            "risk_level": n.risk_level,
            "current_risk_score": n.current_risk_score,
            "status": n.status,
            "last_seen": n.last_seen.isoformat() if n.last_seen else None,
        }

    nodes = [_node_to_dict(focal)] + [_node_to_dict(n) for n in neighbour_nodes]

    edges = [
        {
            "id": r.id,
            "source": r.source_entity_id,
            "target": r.target_entity_id,
            "relation_type": r.relation_type,
            "observation_count": r.observation_count,
            "confidence": r.confidence,
            "first_seen": r.first_seen.isoformat() if r.first_seen else None,
            "last_seen": r.last_seen.isoformat() if r.last_seen else None,
            "last_event_id": r.last_event_id,
            "source_type": r.source_type,
        }
        for r in rels
    ]

    return {
        "focal_node_id": node_id,
        "nodes": nodes,
        "edges": edges,
    }


# ---------------------------------------------------------------------------
# GET /api/entities/relationships
# ---------------------------------------------------------------------------
@router.get("/relationships")
async def list_relationships(
    relation_type: Optional[str] = Query(None),
    source_entity_id: Optional[str] = Query(None),
    target_entity_id: Optional[str] = Query(None),
    limit: int = Query(100, le=500),
    current_user: dict = Depends(get_current_user)
):
    """List entity relationships for this tenant."""
    tenant_id = current_user.get("tenant_id", "default")

    async with AsyncSessionLocal() as session:
        q = select(EntityRelationship).where(EntityRelationship.tenant_id == tenant_id)
        if relation_type:
            q = q.where(EntityRelationship.relation_type == relation_type)
        if source_entity_id:
            q = q.where(EntityRelationship.source_entity_id == source_entity_id)
        if target_entity_id:
            q = q.where(EntityRelationship.target_entity_id == target_entity_id)
        q = q.order_by(EntityRelationship.last_seen.desc()).limit(limit)
        rows = (await session.execute(q)).scalars().all()

    return [
        {
            "id": r.id,
            "source_entity_id": r.source_entity_id,
            "target_entity_id": r.target_entity_id,
            "relation_type": r.relation_type,
            "observation_count": r.observation_count,
            "confidence": r.confidence,
            "first_seen": r.first_seen.isoformat() if r.first_seen else None,
            "last_seen": r.last_seen.isoformat() if r.last_seen else None,
            "last_event_id": r.last_event_id,
            "source_type": r.source_type,
        }
        for r in rows
    ]


# ---------------------------------------------------------------------------
# GET /api/entities/summary
# Returns per-type counts and highest risk entities for dashboard widgets
# ---------------------------------------------------------------------------
@router.get("/summary")
async def entity_summary(current_user: dict = Depends(get_current_user)):
    """Aggregated entity summary for dashboard widgets."""
    tenant_id = current_user.get("tenant_id", "default")

    async with AsyncSessionLocal() as session:
        # Count per type
        type_counts_q = (
            select(EntityNode.entity_type, func.count(EntityNode.id).label("count"))
            .where(EntityNode.tenant_id == tenant_id)
            .group_by(EntityNode.entity_type)
        )
        type_rows = (await session.execute(type_counts_q)).all()
        type_summary = {row[0]: row[1] for row in type_rows}

        # Top 5 high-risk entities
        risky_q = (
            select(EntityNode)
            .where(
                and_(
                    EntityNode.tenant_id == tenant_id,
                    EntityNode.current_risk_score.isnot(None)
                )
            )
            .order_by(EntityNode.current_risk_score.desc())
            .limit(5)
        )
        risky_rows = (await session.execute(risky_q)).scalars().all()

    return {
        "total_nodes": sum(type_summary.values()),
        "by_type": type_summary,
        "top_risk_entities": [
            {
                "id": n.id,
                "entity_type": n.entity_type,
                "canonical_value": n.canonical_value,
                "current_risk_score": n.current_risk_score,
                "risk_level": n.risk_level,
            }
            for n in risky_rows
        ],
    }


# ---------------------------------------------------------------------------
# GET /api/entities/search
# ---------------------------------------------------------------------------
@router.get("/search")
async def search_entities(
    q: str = Query(..., min_length=2, description="Search term for canonical_value or display_value"),
    limit: int = Query(20, le=100),
    current_user: dict = Depends(get_current_user)
):
    """Full-text search across entity canonical and display values."""
    tenant_id = current_user.get("tenant_id", "default")

    async with AsyncSessionLocal() as session:
        stmt = (
            select(EntityNode)
            .where(
                and_(
                    EntityNode.tenant_id == tenant_id,
                    (EntityNode.canonical_value.ilike(f"%{q}%")) |
                    (EntityNode.display_value.ilike(f"%{q}%"))
                )
            )
            .order_by(EntityNode.last_seen.desc())
            .limit(limit)
        )
        rows = (await session.execute(stmt)).scalars().all()

    return [
        {
            "id": n.id,
            "entity_type": n.entity_type,
            "canonical_value": n.canonical_value,
            "display_value": n.display_value,
            "risk_level": n.risk_level,
            "last_seen": n.last_seen.isoformat() if n.last_seen else None,
        }
        for n in rows
    ]
