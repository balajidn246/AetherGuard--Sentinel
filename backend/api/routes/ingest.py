from fastapi import APIRouter, Depends, BackgroundTasks, Request
from typing import List, Dict, Any
from backend.core.permissions import require, Permission
from backend.models.events import OCSFBaseEvent
from backend.services.ingest_service import IngestService
from backend.core.context import RequestContext

router = APIRouter()

@router.post("/")
async def ingest_events(
    events: List[OCSFBaseEvent],
    background_tasks: BackgroundTasks,
    request: Request,
    context: RequestContext = Depends(require(Permission.EVENTS_WRITE))
):
    """
    Ingest a batch of normalized security events.
    """
    background_tasks.add_task(IngestService.process_events, events, context.tenant_id, request.app.state)
    return {"status": "accepted", "count": len(events)}

@router.post("/raw")
async def ingest_raw(
    request: Request,
    background_tasks: BackgroundTasks,
    context: RequestContext = Depends(require(Permission.EVENTS_WRITE))
):
    """
    Ingest raw unparsed logs. The system will attempt to wrap and normalize them.
    """
    raw_data = await request.json()
    
    if isinstance(raw_data, dict):
        raw_data = [raw_data]
        
    events = []
    for item in raw_data:
        events.append(OCSFBaseEvent(
            message=str(item.get("message", "Raw log ingestion")),
            raw_data=str(item),
            source_log="api_raw"
        ))
        
    background_tasks.add_task(IngestService.process_events, events, context.tenant_id, request.app.state)
    return {"status": "accepted", "count": len(events)}
