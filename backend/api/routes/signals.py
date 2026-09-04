"""
Signals & AI Investigation routes - REAL database queries and real inference.
Zero mock data, real evidence gathering from ClickHouse, real persistence to PostgreSQL.
"""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Request
from sqlalchemy import select, update
from api.middleware.auth import get_current_user
from backend.core.permissions import require, Permission
from backend.core.context import RequestContext
from backend.db.postgres import AsyncSessionLocal
from backend.db.clickhouse import get_clickhouse
from backend.models.signal import SecuritySignal
from backend.services.ai_service import ai_service
from backend.core.logging import get_logger

logger = get_logger(__name__)
router = APIRouter()

async def perform_investigation(signal_id: str, tenant_id: str, app_state=None):
    """Background task: Gathers real ClickHouse evidence, runs AI investigation, updates PostgreSQL."""
    logger.info("Gathering real evidence for AI investigation", signal_id=signal_id)
    
    # 1. Fetch real signal from PostgreSQL
    signal_dict = {}
    evidence_refs = []
    async with AsyncSessionLocal() as session:
        stmt = select(SecuritySignal).where(
            SecuritySignal.id == signal_id,
            SecuritySignal.tenant_id == tenant_id
        )
        s = (await session.execute(stmt)).scalar_one_or_none()
        if not s:
            logger.error("Signal not found for investigation", signal_id=signal_id)
            return

        signal_dict = {
            "id": s.id,
            "title": s.title,
            "description": s.description,
            "severity": s.severity,
            "rule_name": s.rule_name,
            "source_ip": s.source_ip,
            "hostname": s.hostname,
            "username": s.username
        }
        evidence_refs = list(s.evidence_refs or [])

    # 2. Query real ClickHouse events for evidence (Point 12)
    events = []
    ch_client = get_clickhouse()
    if ch_client:
        try:
            # Query by event ID if available or by source IP
            conditions = ["tenant_id = {t:String}"]
            params = {"t": tenant_id}
            
            if signal_dict.get("source_ip"):
                conditions.append("src_ip = {sip:String}")
                params["sip"] = signal_dict["source_ip"]
            elif evidence_refs:
                conditions.append("toString(event_id) IN {ids:Array(String)}")
                params["ids"] = [str(x) for x in evidence_refs if str(x) != "unknown"]

            sql = f"""
            SELECT
                toString(event_id) as id,
                formatDateTime(time, '%Y-%m-%dT%H:%M:%SZ') as timestamp,
                class_name,
                severity,
                message,
                src_ip,
                dst_ip,
                host_name,
                user_name
            FROM events
            WHERE {" AND ".join(conditions)}
            ORDER BY time DESC
            LIMIT 50
            """
            rows = ch_client.query(sql, parameters=params)
            for r in rows.result_rows:
                events.append({
                    "id": r[0],
                    "timestamp": r[1],
                    "class_name": r[2],
                    "severity": r[3],
                    "message": r[4],
                    "src_ip": r[5],
                    "dst_ip": r[6],
                    "host_name": r[7],
                    "user_name": r[8]
                })
        except Exception as e:
            logger.error("Failed to query ClickHouse evidence", error=str(e))

    # 3. Execute AI Investigation through AISecurityGateway (Sanitized, Validated, Audited)
    from backend.services.ai_gateway import ai_gateway
    ws_mgr = getattr(app_state, "ws_manager", None) if app_state else None
    result = await ai_gateway.investigate_signal(
        signal_dict=signal_dict,
        evidence_events=events,
        actor_id="system",
        actor_username="analyst_or_system",
        tenant_id=tenant_id,
        ws_manager=ws_mgr
    )
    logger.info("Completed AI investigation through AISecurityGateway", signal_id=signal_id, verdict=result.verdict)



@router.post("/{signal_id}/investigate")
async def trigger_investigation(
    signal_id: str,
    background_tasks: BackgroundTasks,
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    """
    Triggers an asynchronous local AI investigation on a real security signal.
    """
    tenant_id = current_user.get("tenant_id", "default")
    
    # Validate signal exists in PostgreSQL
    async with AsyncSessionLocal() as session:
        stmt = select(SecuritySignal).where(
            SecuritySignal.id == signal_id,
            SecuritySignal.tenant_id == tenant_id
        )
        s = (await session.execute(stmt)).scalar_one_or_none()
        if not s:
            raise HTTPException(status_code=404, detail="Security signal not found")

    background_tasks.add_task(perform_investigation, signal_id, tenant_id, request.app.state)
    return {
        "status": "accepted",
        "signal_id": signal_id,
        "message": "AI investigation queued to local AI runtime."
    }


@router.get("/ai-health")
async def get_ai_health(current_user: dict = Depends(get_current_user)):
    """Check if the local Ollama instance is available."""
    is_online = await ai_service.check_health()
    return {
        "status": "online" if is_online else "offline",
        "model": ai_service.model,
        "base_url": ai_service.base_url
    }
