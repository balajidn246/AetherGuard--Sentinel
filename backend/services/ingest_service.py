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
            event = event.model_copy(update={"tenant_id": tenant_id})
            processed.append(event)
            
            # 2. Bridge to Legacy Detection Engine & WebSocket
            if app_state:
                
                if hasattr(app_state, "detection_engine"):
                    # DetectionEngine is migrated to OCSFBaseEvent
                    asyncio.create_task(app_state.detection_engine.evaluate(event))

                if hasattr(app_state, "ueba_engine"):
                    # UEBA is migrated to OCSFBaseEvent
                    app_state.ueba_engine.record_event(event, tenant_id)
                    
                if hasattr(app_state, "ws_manager"):
                    # WebSocket broadcast
                    asyncio.create_task(app_state.ws_manager.send_log(event.model_dump(), tenant_id))

            # Entity Extraction
            from backend.pipeline.entity_extractor import EntityExtractor
            from backend.pipeline.entity_queue import entity_queue
            extracted_entities, extracted_rels = EntityExtractor.extract(event)
            asyncio.create_task(entity_queue.push_candidates(extracted_entities, extracted_rels))

        
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
