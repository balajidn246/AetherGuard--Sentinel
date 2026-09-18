import asyncio
import logging
from datetime import datetime
from backend.db.clickhouse import get_clickhouse
from backend.pipeline.entity_extractor import EntityExtractor
from backend.pipeline.entity_queue import entity_queue
from backend.models.events import OCSFBaseEvent

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("reconciler")

async def rebuild_entities_from_clickhouse(tenant_id: str = None, days_back: int = 7):
    """
    Reads historical telemetry from ClickHouse and pushes it back into the Redis
    entity queue to reconstruct the PostgreSQL entity view.
    """
    client = get_clickhouse()
    if not client:
        logger.error("ClickHouse client unavailable.")
        return

    where_clause = f"time >= now() - INTERVAL {days_back} DAY"
    if tenant_id:
        where_clause += f" AND tenant_id = '{tenant_id}'"

    # We read in chunks to avoid blowing up memory
    query = f"""
        SELECT 
            tenant_id, time, event_id, class_uid, class_name, category_uid, category_name,
            severity_id, severity, original_time, message, raw_data, src_ip, dst_ip,
            src_port, dst_port, user_name, host_name, process_name, file_hash, source_log
        FROM events
        WHERE {where_clause}
        ORDER BY time ASC
    """
    
    logger.info(f"Starting entity reconciliation. {where_clause}")
    
    try:
        # In a real massive dataset, we'd paginate using LIMIT/OFFSET or time windows.
        result = client.query(query)
        rows = result.result_rows
        
        logger.info(f"Fetched {len(rows)} events from ClickHouse for reconciliation.")
        
        await entity_queue.connect()
        
        batch_entities = []
        batch_rels = []
        
        for row in rows:
            # Map back to OCSFBaseEvent
            event = OCSFBaseEvent(
                tenant_id=row[0],
                time=row[1],
                event_id=str(row[2]),
                class_uid=row[3],
                class_name=row[4],
                category_uid=row[5],
                category_name=row[6],
                severity_id=row[7],
                severity=row[8],
                original_time=row[9],
                message=row[10],
                raw_data=row[11],
                src_ip=row[12] if row[12] else None,
                dst_ip=row[13] if row[13] else None,
                src_port=row[14],
                dst_port=row[15],
                user_name=row[16] if row[16] else None,
                host_name=row[17] if row[17] else None,
                process_name=row[18] if row[18] else None,
                file_hash=row[19] if row[19] else None,
                source_log=row[20]
            )
            
            entities, rels = EntityExtractor.extract(event)
            batch_entities.extend(entities)
            batch_rels.extend(rels)
            
            # Flush batch
            if len(batch_entities) > 500 or len(batch_rels) > 500:
                await entity_queue.push_candidates(batch_entities, batch_rels)
                batch_entities.clear()
                batch_rels.clear()
                
        # Final flush
        if batch_entities or batch_rels:
            await entity_queue.push_candidates(batch_entities, batch_rels)
            
        logger.info("Entity reconciliation completed. Candidates queued.")
        
    except Exception as e:
        logger.error(f"Reconciliation failed: {e}")

if __name__ == "__main__":
    asyncio.run(rebuild_entities_from_clickhouse())
