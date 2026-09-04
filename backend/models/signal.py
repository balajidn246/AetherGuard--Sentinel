import uuid
from sqlalchemy import Column, String, JSON, Boolean
from backend.models.base import Base, TimestampMixin

class SecuritySignal(Base, TimestampMixin):
    __tablename__ = "security_signals"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), index=True, nullable=False, default="default")
    title = Column(String(255), nullable=False)
    description = Column(String(2000), default="")
    severity = Column(String(20), default="medium")     # critical, high, medium, low, info
    status = Column(String(20), default="new")          # new, triaged, investigating, resolved, closed
    
    rule_name = Column(String(100), default="custom")
    source_ip = Column(String(45), default="")
    hostname = Column(String(100), default="")
    username = Column(String(100), default="")
    tags = Column(JSON, default=list)
    
    # Acknowledgment & Lifecycle
    acknowledged = Column(Boolean, default=False)
    acknowledged_by = Column(String(100), nullable=True)
    ack_notes = Column(String(1000), nullable=True)
    incident_id = Column(String(36), nullable=True)
    
    # Real AI Investigation Results (Point 11, 13)
    ai_verdict = Column(String(50), nullable=True)
    ai_confidence = Column(String(20), nullable=True)
    ai_analysis = Column(String(5000), nullable=True)
    
    # Real Evidence References (ClickHouse event UUIDs) (Point 12)
    evidence_refs = Column(JSON, default=list)
    mitre_tactics = Column(JSON, default=list)
    source_alert_id = Column(String(36), nullable=True)
