from backend.db.clickhouse import get_clickhouse
from backend.core.logging import get_logger

logger = get_logger(__name__)

def init_db():
    client = get_clickhouse()
    if not client:
        logger.warning("ClickHouse client not available. Skipping initialization.")
        return

    # OCSF-aligned normalized event schema
    create_events_table = """
    CREATE TABLE IF NOT EXISTS events (
        tenant_id String,
        time DateTime64(3, 'UTC'),
        event_id UUID,
        
        -- OCSF Base
        class_uid UInt16,
        class_name LowCardinality(String),
        category_uid UInt16,
        category_name LowCardinality(String),
        severity_id UInt8,
        severity LowCardinality(String),
        
        -- Original Event
        original_time String,
        message String,
        raw_data String,
        
        -- Observables / Entities
        src_ip IPv4,
        dst_ip IPv4,
        src_port UInt16,
        dst_port UInt16,
        user_name LowCardinality(String),
        host_name LowCardinality(String),
        process_name LowCardinality(String),
        file_hash String,
        
        -- Metadata
        source_log LowCardinality(String)
    ) ENGINE = MergeTree()
    PARTITION BY toYYYYMM(time)
    ORDER BY (tenant_id, time, category_name)
    """
    
    try:
        client.command(create_events_table)
        logger.info("ClickHouse events table initialized.")
    except Exception as e:
        logger.error("Error creating ClickHouse tables", error=str(e))

if __name__ == "__main__":
    init_db()
