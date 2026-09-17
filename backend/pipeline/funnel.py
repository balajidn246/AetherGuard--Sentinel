import hashlib
import time
from typing import List
from backend.core.logging import get_logger
from backend.models.events import OCSFBaseEvent
from backend.db.redis import get_redis

logger = get_logger(__name__)

class DeterministicFunnel:
    """
    The Deterministic Funnel compresses raw high-volume events into bounded 
    security signals before AI processing, ensuring cost control and context limits.
    """
    def __init__(self):
        self.dedup_window_seconds = 60

    def compute_hash(self, event: OCSFBaseEvent) -> str:
        """Compute a deterministic content hash of the event, ignoring time/id."""
        content = f"{event.tenant_id}|{event.class_name}|{event.src_ip}|{event.dst_ip}|{event.message}"
        return hashlib.sha256(content.encode('utf-8')).hexdigest()

    async def deduplicate(self, events: List[OCSFBaseEvent]) -> List[OCSFBaseEvent]:
        """Drop events that are exact duplicates within the time window."""
        r = await get_redis()
        if not r:
            logger.warning("[FUNNEL] Redis not available, skipping dedup")
            return events

        unique_events = []
        for event in events:
            event_hash = self.compute_hash(event)
            key = f"ag:funnel:dedup:{event_hash}"
            
            # SETNX (Set if not exists)
            is_new = await r.set(key, "1", ex=self.dedup_window_seconds, nx=True)
            if is_new:
                unique_events.append(event)
                
        dropped = len(events) - len(unique_events)
        if dropped > 0:
            logger.info("Funnel deduplicated events", dropped=dropped)
            
        return unique_events
        
    async def process(self, events: List[OCSFBaseEvent]) -> List[OCSFBaseEvent]:
        """Run events through the full deterministic funnel."""
        return await self.deduplicate(events)

funnel = DeterministicFunnel()
