import json
import asyncio
import uuid
import time
from typing import List
from backend.core.logging import get_logger
from backend.models.events import OCSFBaseEvent
from backend.db.clickhouse import get_clickhouse
from backend.pipeline.funnel import funnel
try:
    from backend.core.metrics import EVENTS_INGESTED, INGEST_LATENCY
    _metrics_enabled = True
except Exception:
    _metrics_enabled = False

logger = get_logger(__name__)

class IngestService:
    @staticmethod
    async def process_events(events: List[OCSFBaseEvent], tenant_id: str, app_state=None) -> dict:
        # 1. Deduplicate
        events = await funnel.process(events)
        if not events:
            return {"status": "success", "ingested": 0}
            
        processed = []
        for event in events:
            event.tenant_id = tenant_id
            processed.append(event)
            
            # 2. Bridge to Legacy Detection Engine & WebSocket
            if app_state:
                legacy_dict = {
                    "id": str(event.event_id),
                    "timestamp": event.time.isoformat(),
                    "message": event.message or "",
                    "raw_data": event.raw_data or "",
                    "source_ip": str(event.src_ip) if event.src_ip else "",
                    "dest_ip": str(event.dst_ip) if event.dst_ip else "",
                    "source_port": event.src_port or 0,
                    "dest_port": event.dst_port or 0,
                    "event_type": event.class_name.lower() if event.class_name != "Unknown" else "log",
                    "class_name": event.class_name,
                    "category_name": event.category_name,
                    "severity": event.severity.lower(),
                    "username": event.user_name or "",
                    "hostname": event.host_name or "",
                    "process_name": event.process_name or "",
                    "source_log": event.source_log or "",
                    "bytes_out": 0,
                }
                
                if hasattr(app_state, "detection_engine"):
                    # The detection engine evaluates asynchronously
                    asyncio.create_task(app_state.detection_engine.evaluate(legacy_dict))

                if hasattr(app_state, "ueba_engine"):
                    # Track user activity in UEBA baseline
                    app_state.ueba_engine.record_event(legacy_dict, tenant_id)
                    
                if hasattr(app_state, "ws_manager"):
                    # Broadcast to specific tenant
                    asyncio.create_task(app_state.ws_manager.send_log(legacy_dict, tenant_id))

        
        # 3. Attempt to send to ClickHouse
        client = get_clickhouse()
        _start = time.monotonic()
        if client:
            try:
                data = [
                    [
                        e.tenant_id,
                        e.time,
                        uuid.UUID(e.event_id),
                        e.class_uid,
                        e.class_name,
                        e.category_uid,
                        e.category_name,
                        e.severity_id,
                        e.severity,
                        e.original_time or "",
                        e.message or "",
                        e.raw_data or e.model_dump_json(exclude={"raw_data"}),
                        str(e.src_ip) if e.src_ip else "",
                        str(e.dst_ip) if e.dst_ip else "",
                        e.src_port or 0,
                        e.dst_port or 0,
                        e.user_name or "",
                        e.host_name or "",
                        e.process_name or "",
                        e.file_hash or "",
                        e.source_log
                    ] for e in processed
                ]
                
                columns = [
                    "tenant_id", "time", "event_id", 
                    "class_uid", "class_name", "category_uid", "category_name", 
                    "severity_id", "severity", "original_time", "message", "raw_data", 
                    "src_ip", "dst_ip", "src_port", "dst_port", 
                    "user_name", "host_name", "process_name", "file_hash", 
                    "source_log"
                ]
                
                client.insert('events', data, column_names=columns)
                logger.info("Events ingested to ClickHouse", count=len(processed), tenant_id=tenant_id)
                if _metrics_enabled:
                    EVENTS_INGESTED.labels(tenant_id=tenant_id, source="api").inc(len(processed))
                    INGEST_LATENCY.labels(tenant_id=tenant_id).observe(time.monotonic() - _start)
            except Exception as e:
                logger.error("ClickHouse insert failed", error=str(e), count=len(processed))
        else:
            logger.info("ClickHouse offline. Events deduplicated and sent to live UI.", count=len(processed))

        return {"status": "success", "ingested": len(processed)}
