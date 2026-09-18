import asyncio
import logging
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.dialects.postgresql import insert
from backend.db.postgres import AsyncSessionLocal
from backend.pipeline.entity_queue import entity_queue
from backend.models.entities import EntityNode, EntityRelationship

logger = logging.getLogger(__name__)

class EntityBatchWorker:
    def __init__(self):
        self.stream_name = "aetherguard:entity_candidates"
        self.group_name = "entity_persister"
        self.consumer_name = "worker-1"
        self.batch_size = 500
        self.running = False

    async def setup_stream(self):
        await entity_queue.connect()
        try:
            await entity_queue.redis.xgroup_create(self.stream_name, self.group_name, id="0", mkstream=True)
        except Exception as e:
            if "BUSYGROUP Consumer Group name already exists" not in str(e):
                logger.warning(f"Consumer group setup issue: {e}")

    async def run(self):
        self.running = True
        await self.setup_stream()
        logger.info("EntityBatchWorker started")
        
        while self.running:
            try:
                # Block for 2 seconds waiting for messages
                messages = await entity_queue.redis.xreadgroup(
                    groupname=self.group_name,
                    consumername=self.consumer_name,
                    streams={self.stream_name: ">"},
                    count=self.batch_size,
                    block=2000
                )
                
                if messages:
                    for stream, msgs in messages:
                        if msgs:
                            await self.process_batch(msgs)
                            # Ack messages
                            msg_ids = [msg_id for msg_id, _ in msgs]
                            await entity_queue.redis.xack(self.stream_name, self.group_name, *msg_ids)
            except Exception as e:
                logger.error(f"Entity batch worker error: {e}")
                await asyncio.sleep(5) # backoff on error

    async def process_batch(self, msgs):
        nodes_to_upsert = {}
        rels_to_upsert = {}
        
        for msg_id, data in msgs:
            tenant_id = data.get("tenant_id")
            timestamp = datetime.fromisoformat(data.get("timestamp"))
            msg_type = data.get("type")
            
            if msg_type == "entity":
                key = (tenant_id, data["entity_type"], data["canonical_value"])
                if key not in nodes_to_upsert or timestamp > nodes_to_upsert[key]["last_seen"]:
                    nodes_to_upsert[key] = {
                        "tenant_id": tenant_id,
                        "entity_type": data["entity_type"],
                        "canonical_value": data["canonical_value"],
                        "display_value": data["display_value"],
                        "first_seen": timestamp,
                        "last_seen": timestamp
                    }
                    
            elif msg_type == "relationship":
                # We need source and target entity IDs, but we don't have UUIDs yet.
                # However, the unique constraint uses canonical_value conceptually?
                # Ah! The schema requires `source_entity_id` and `target_entity_id`.
                # We need to resolve them!
                key = (tenant_id, data["source_canonical"], data["target_canonical"], data["relation_type"])
                if key not in rels_to_upsert:
                    rels_to_upsert[key] = {
                        "tenant_id": tenant_id,
                        "source_type": data["source_type"],
                        "source_canonical": data["source_canonical"],
                        "target_type": data["target_type"],
                        "target_canonical": data["target_canonical"],
                        "relation_type": data["relation_type"],
                        "first_seen": timestamp,
                        "last_seen": timestamp,
                        "observation_count": 0,
                        "last_event_id": data.get("event_id"),
                        "source_sys": data.get("source_log")
                    }
                rels_to_upsert[key]["observation_count"] += 1
                if timestamp > rels_to_upsert[key]["last_seen"]:
                    rels_to_upsert[key]["last_seen"] = timestamp
                    rels_to_upsert[key]["last_event_id"] = data.get("event_id")

        if not nodes_to_upsert and not rels_to_upsert:
            return

        async with AsyncSessionLocal() as session:
            # 1. Upsert nodes
            if nodes_to_upsert:
                stmt = insert(EntityNode).values(list(nodes_to_upsert.values()))
                stmt = stmt.on_conflict_do_update(
                    constraint="uq_entity_node_identity",
                    set_=dict(
                        last_seen=stmt.excluded.last_seen,
                        display_value=stmt.excluded.display_value
                    )
                ).returning(EntityNode.id, EntityNode.tenant_id, EntityNode.entity_type, EntityNode.canonical_value)
                
                result = await session.execute(stmt)
                
                # Build lookup dict for relationship resolution
                node_lookup = {}
                for row in result:
                    node_lookup[(row.tenant_id, row.entity_type, row.canonical_value)] = row.id

                # 2. Upsert relationships
                if rels_to_upsert:
                    final_rels = []
                    for key, r in rels_to_upsert.items():
                        src_id = node_lookup.get((r["tenant_id"], r["source_type"], r["source_canonical"]))
                        tgt_id = node_lookup.get((r["tenant_id"], r["target_type"], r["target_canonical"]))
                        if src_id and tgt_id:
                            final_rels.append({
                                "tenant_id": r["tenant_id"],
                                "source_entity_id": src_id,
                                "target_entity_id": tgt_id,
                                "relation_type": r["relation_type"],
                                "first_seen": r["first_seen"],
                                "last_seen": r["last_seen"],
                                "observation_count": r["observation_count"],
                                "last_event_id": r["last_event_id"],
                                "source_type": r["source_sys"]
                            })

                    if final_rels:
                        rel_stmt = insert(EntityRelationship).values(final_rels)
                        rel_stmt = rel_stmt.on_conflict_do_update(
                            constraint="uq_entity_rel_identity",
                            set_=dict(
                                last_seen=rel_stmt.excluded.last_seen,
                                observation_count=EntityRelationship.observation_count + rel_stmt.excluded.observation_count,
                                last_event_id=rel_stmt.excluded.last_event_id
                            )
                        )
                        await session.execute(rel_stmt)

            await session.commit()
