import hashlib
import time
from typing import List
from backend.core.logging import get_logger
from backend.models.events import OCSFBaseEvent

logger = get_logger(__name__)

class DeterministicFunnel:
    """
    The Deterministic Funnel compresses raw high-volume events into bounded 
    security signals before AI processing, ensuring cost control and context limits.
    """
    def __init__(self):
        # In-memory fallback (Redis should be used in production scale)
        self._seen_hashes = {}
        self.dedup_window_seconds = 60

    def compute_hash(self, event: OCSFBaseEvent) -> str:
        """Compute a deterministic content hash of the event, ignoring time/id."""
        content = f"{event.tenant_id}|{event.class_name}|{event.src_ip}|{event.dst_ip}|{event.message}"
        return hashlib.sha256(content.encode('utf-8')).hexdigest()

    def deduplicate(self, events: List[OCSFBaseEvent]) -> List[OCSFBaseEvent]:
        """Drop events that are exact duplicates within the time window."""
        now = time.time()
        unique_events = []
        
        # Clean up old hashes
        expired = [h for h, t in self._seen_hashes.items() if now - t > self.dedup_window_seconds]
        for h in expired:
            del self._seen_hashes[h]

        for event in events:
            event_hash = self.compute_hash(event)
            if event_hash in self._seen_hashes:
                continue
            
            self._seen_hashes[event_hash] = now
            unique_events.append(event)
            
        dropped = len(events) - len(unique_events)
        if dropped > 0:
            logger.info("Funnel deduplicated events", dropped=dropped)
            
        return unique_events
        
    def process(self, events: List[OCSFBaseEvent]) -> List[OCSFBaseEvent]:
        """Run events through the full deterministic funnel."""
        # 1. Deduplicate
        return self.deduplicate(events)

funnel = DeterministicFunnel()
