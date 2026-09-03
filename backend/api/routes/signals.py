from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from typing import List, Dict, Any
from backend.core.permissions import require, Permission
from backend.core.context import RequestContext
from backend.services.ai_service import ai_service
from backend.core.logging import get_logger

logger = get_logger(__name__)
router = APIRouter()

async def perform_investigation(signal_id: str, signal_context: dict):
    """Background task to run the AI investigation and update the DB."""
    logger.info("Starting AI investigation", signal_id=signal_id)
    result = await ai_service.investigate_signal(signal_context)
    
    # In a full implementation, we update the SecuritySignal in PostgreSQL here
    # e.g. signal.ai_verdict = result.get('verdict')
    
    logger.info(
        "Investigation complete", 
        signal_id=signal_id, 
        verdict=result.get("verdict"),
        confidence=result.get("confidence")
    )

@router.post("/{signal_id}/investigate")
async def trigger_investigation(
    signal_id: str,
    background_tasks: BackgroundTasks,
    context: RequestContext = Depends(require(Permission.AI_INVESTIGATE))
):
    """
    Triggers an asynchronous local AI investigation on a specific signal.
    """
    # Stub: Fetch the signal and its evidence from DB (ClickHouse + Postgres)
    mock_context = {
        "signal_id": signal_id,
        "title": "Suspicious Authentication Activity",
        "evidence_count": 3,
        "events": [
            {"event_type": "login", "message": "Failed login attempt", "src_ip": "103.45.67.89", "time": "2024-03-15T10:00:00Z"},
            {"event_type": "login", "message": "Failed login attempt", "src_ip": "103.45.67.89", "time": "2024-03-15T10:00:05Z"},
            {"event_type": "login", "message": "Successful login", "src_ip": "103.45.67.89", "time": "2024-03-15T10:00:10Z"}
        ]
    }
    
    background_tasks.add_task(perform_investigation, signal_id, mock_context)
    return {"status": "accepted", "message": "AI investigation queued to local Ollama instance."}

@router.get("/ai-health")
async def get_ai_health(context: RequestContext = Depends(require(Permission.AI_INVESTIGATE))):
    """Check if the local Ollama instance is available."""
    is_online = await ai_service.check_health()
    return {"status": "online" if is_online else "offline", "model": ai_service.model}
