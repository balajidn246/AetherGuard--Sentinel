import json
from redis.asyncio import Redis
from backend.core.config import settings
from backend.core.logging import get_logger
from backend.pipeline.entity_extractor import EntityCandidate, RelationshipCandidate

logger = get_logger(__name__)

class EntityQueue:
    def __init__(self):
        self.redis: Redis = None
        self.stream_name = "aetherguard:entity_candidates"
        # Bounded queue size
        self.max_len = 100000

    async def connect(self):
        if not self.redis:
            self.redis = Redis.from_url(settings.REDIS_URL, decode_responses=True)

    async def push_candidates(self, entities: list[EntityCandidate], relationships: list[RelationshipCandidate]):
        if not self.redis:
            await self.connect()
            
        pipeline = self.redis.pipeline()
        count = 0
        
        for e in entities:
            payload = {
                "type": "entity",
                "tenant_id": e.tenant_id,
                "entity_type": e.entity_type,
                "canonical_value": e.canonical_value,
                "display_value": e.display_value,
                "timestamp": e.timestamp.isoformat()
            }
            pipeline.xadd(self.stream_name, payload, maxlen=self.max_len, approximate=True)
            count += 1
            
        for r in relationships:
            payload = {
                "type": "relationship",
                "tenant_id": r.tenant_id,
                "source_type": r.source_candidate.entity_type,
                "source_canonical": r.source_candidate.canonical_value,
                "target_type": r.target_candidate.entity_type,
                "target_canonical": r.target_candidate.canonical_value,
                "relation_type": r.relation_type,
                "timestamp": r.timestamp.isoformat(),
                "event_id": r.event_id,
                "source_log": r.source_log
            }
            pipeline.xadd(self.stream_name, payload, maxlen=self.max_len, approximate=True)
            count += 1
            
        if count > 0:
            try:
                await pipeline.execute()
            except Exception as exc:
                logger.error(f"Failed to push to entity queue: {exc}. Ingestion continuing.")
                # We intentionally swallow the error so ingestion is loss-tolerant

entity_queue = EntityQueue()
