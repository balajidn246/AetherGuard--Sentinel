import json
import asyncio
import uuid
from typing import List
from backend.core.logging import get_logger
from backend.models.events import OCSFBaseEvent
from backend.db.clickhouse import get_clickhouse
from backend.pipeline.funnel import funnel

logger = get_logger(__name__)

class IngestService:
    @staticmethod
    async def process_events(events: List[OCSFBaseEvent], tenant_id: str, app_state=None) -> dict:
        # 1. Deterministic Funnel (Compression)
        events = funnel.process(events)
        if not events:
            return {"status": "success", "ingested": 0}
            
        processed = []
        for event in events:
            event.tenant_id = tenant_id
            processed.append(event)
            
            # 2. Bridge to Legacy Detection Engine & WebSocket
            if app_state:
                legacy_dict = {
                    "id": event.event_id,
                    "timestamp": event.time.isoformat(),
                    "message": event.message,
                    "source_ip": str(event.src_ip) if event.src_ip else "unknown",
                    "dest_ip": str(event.dst_ip) if event.dst_ip else "unknown",
                    "event_type": event.class_name.lower() if event.class_name != "Unknown" else "log",
                    "severity": event.severity.lower(),
                    "bytes_out": 0 # Default for legacy rules
                }
                
                if hasattr(app_state, "detection_engine"):
                    # The legacy engine evaluates asynchronously
                    asyncio.create_task(app_state.detection_engine.evaluate(legacy_dict))
                    
                if hasattr(app_state, "ws_manager"):
                    # Use create_task since send_log is async
                    asyncio.create_task(app_state.ws_manager.send_log(legacy_dict))
        
        # 3. Attempt to send to ClickHouse
        client = get_clickhouse()
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
                        e.raw_data or json.dumps(e.model_dump(exclude={"raw_data"})),
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
            except Exception as e:
                logger.error("ClickHouse insert failed", error=str(e), count=len(processed))
        else:
            logger.info("ClickHouse offline. Events deduplicated and sent to live UI.", count=len(processed))

        return {"status": "success", "ingested": len(processed)}
