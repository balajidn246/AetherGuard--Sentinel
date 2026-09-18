import uuid
from sqlalchemy import Column, String, Float, DateTime, Integer
from sqlalchemy.dialects.postgresql import JSON
from sqlalchemy.schema import Index, UniqueConstraint

from backend.models.base import Base

class EntityNode(Base):
    __tablename__ = "entity_nodes"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String, nullable=False, index=True)
    entity_type = Column(String, nullable=False, index=True) # e.g. "ip", "user", "host"
    canonical_value = Column(String, nullable=False)
    display_value = Column(String, nullable=False)
    
    first_seen = Column(DateTime(timezone=True), nullable=True)
    last_seen = Column(DateTime(timezone=True), nullable=True, index=True)
    
    current_risk_score = Column(Float, nullable=True, index=True)
    risk_level = Column(String, nullable=True) # "low", "medium", "high", "critical"
    
    status = Column(String, default="active") # "active", "inactive", "disabled", "unknown"
    attributes = Column(JSON, default={})
    
    created_at = Column(DateTime(timezone=True), nullable=True)
    updated_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint('tenant_id', 'entity_type', 'canonical_value', name='uq_entity_node_identity'),
        Index('idx_entity_tenant_type', 'tenant_id', 'entity_type'),
    )


class EntityRelationship(Base):
    __tablename__ = "entity_relationships"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String, nullable=False, index=True)
    
    source_entity_id = Column(String, nullable=False, index=True)
    target_entity_id = Column(String, nullable=False, index=True)
    
    relation_type = Column(String, nullable=False, index=True)
    
    first_seen = Column(DateTime(timezone=True), nullable=True)
    last_seen = Column(DateTime(timezone=True), nullable=True, index=True)
    
    observation_count = Column(Integer, default=1)
    confidence = Column(Integer, default=100)
    
    source_type = Column(String, nullable=True) # E.g. the category_name or source system
    last_event_id = Column(String, nullable=True) # The event UUID from ClickHouse
    
    attributes = Column(JSON, default={})
    
    created_at = Column(DateTime(timezone=True), nullable=True)
    updated_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint('tenant_id', 'source_entity_id', 'target_entity_id', 'relation_type', name='uq_entity_rel_identity'),
    )
