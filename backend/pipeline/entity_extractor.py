import json
from typing import List, Dict, Any, Optional
from datetime import datetime
from backend.models.events import OCSFBaseEvent
from backend.pipeline.entity_normalizer import EntityNormalizer

class EntityCandidate:
    def __init__(self, tenant_id: str, entity_type: str, raw_value: str, timestamp: datetime, source_log: str):
        self.tenant_id = tenant_id
        self.entity_type = entity_type
        self.raw_value = raw_value
        self.timestamp = timestamp
        self.source_log = source_log
        self.canonical_value: Optional[str] = None
        self.display_value: Optional[str] = None
        self._normalize()
        
    def _normalize(self):
        norm = EntityNormalizer()
        if self.entity_type == "ip":
            self.canonical_value, self.display_value = norm.normalize_ip(self.raw_value)
        elif self.entity_type == "user":
            self.canonical_value, self.display_value = norm.normalize_username(self.raw_value)
        elif self.entity_type == "host":
            self.canonical_value, self.display_value = norm.normalize_hostname(self.raw_value)
        elif self.entity_type == "file_hash":
            self.canonical_value, self.display_value = norm.normalize_hash(self.raw_value)
        elif self.entity_type == "domain":
            self.canonical_value, self.display_value = norm.normalize_domain(self.raw_value)
        elif self.entity_type == "process":
            self.canonical_value, self.display_value = norm.normalize_process(self.raw_value)
            
    def is_valid(self) -> bool:
        return self.canonical_value is not None

class RelationshipCandidate:
    def __init__(self, tenant_id: str, source_type: str, source_raw: str, target_type: str, target_raw: str, relation_type: str, timestamp: datetime, event_id: str, source_log: str):
        self.tenant_id = tenant_id
        self.source_candidate = EntityCandidate(tenant_id, source_type, source_raw, timestamp, source_log)
        self.target_candidate = EntityCandidate(tenant_id, target_type, target_raw, timestamp, source_log)
        self.relation_type = relation_type
        self.timestamp = timestamp
        self.event_id = event_id
        self.source_log = source_log
        
    def is_valid(self) -> bool:
        return self.source_candidate.is_valid() and self.target_candidate.is_valid()

class EntityExtractor:
    @staticmethod
    def extract(event: OCSFBaseEvent) -> tuple[List[EntityCandidate], List[RelationshipCandidate]]:
        entities = []
        relationships = []
        
        tenant = event.tenant_id
        ts = event.time
        src_log = event.source_log
        ev_id = str(event.event_id)
        
        # Extract base entities
        if event.src_ip:
            entities.append(EntityCandidate(tenant, "ip", str(event.src_ip), ts, src_log))
        if event.dst_ip:
            entities.append(EntityCandidate(tenant, "ip", str(event.dst_ip), ts, src_log))
        if event.user_name:
            entities.append(EntityCandidate(tenant, "user", event.user_name, ts, src_log))
        if event.host_name:
            entities.append(EntityCandidate(tenant, "host", event.host_name, ts, src_log))
        if getattr(event, 'file_hash', None):
            entities.append(EntityCandidate(tenant, "file_hash", event.file_hash, ts, src_log))
        if getattr(event, 'process_name', None):
            entities.append(EntityCandidate(tenant, "process", event.process_name, ts, src_log))
        if getattr(event, 'domain', None):
            entities.append(EntityCandidate(tenant, "domain", event.domain, ts, src_log))
            
        # Extract explicit relationship semantics
        # user --logged_in_from--> host
        if event.user_name and event.host_name and event.class_name in ("Authentication", "Logon"):
            relationships.append(RelationshipCandidate(tenant, "user", event.user_name, "host", event.host_name, "logged_in_to", ts, ev_id, src_log))
            
        # user --logged_in_from--> src_ip
        if event.user_name and event.src_ip and event.class_name in ("Authentication", "Logon"):
            relationships.append(RelationshipCandidate(tenant, "user", event.user_name, "ip", str(event.src_ip), "logged_in_from", ts, ev_id, src_log))
            
        # host --connected_to--> dst_ip
        if event.host_name and event.dst_ip and event.class_name in ("Network Activity", "Connection"):
            relationships.append(RelationshipCandidate(tenant, "host", event.host_name, "ip", str(event.dst_ip), "connected_to", ts, ev_id, src_log))
            
        # host --executed--> process
        if event.host_name and getattr(event, 'process_name', None) and event.class_name in ("Process Activity", "Execution"):
            relationships.append(RelationshipCandidate(tenant, "host", event.host_name, "process", event.process_name, "executed", ts, ev_id, src_log))
            
        # domain --resolved_to--> dst_ip
        if getattr(event, 'domain', None) and event.dst_ip and event.class_name in ("DNS Activity", "Resolution"):
            relationships.append(RelationshipCandidate(tenant, "domain", event.domain, "ip", str(event.dst_ip), "resolved_to", ts, ev_id, src_log))

        valid_entities = [e for e in entities if e.is_valid()]
        valid_rels = [r for r in relationships if r.is_valid()]
        
        return valid_entities, valid_rels
