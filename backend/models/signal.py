import uuid
from sqlalchemy import Column, String, JSON
from backend.models.base import Base, TimestampMixin

class SecuritySignal(Base, TimestampMixin):
    __tablename__ = "security_signals"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), index=True, nullable=False, default="default")
    title = Column(String(200), nullable=False)
    description = Column(String(1000))
    severity = Column(String(20), default="medium")
    status = Column(String(20), default="new")  # new, triaged, investigating, resolved
    
    # AI Investigation Results
    ai_verdict = Column(String(50))
    ai_confidence = Column(String(20))
    ai_analysis = Column(String(5000))
    
    # Evidence References (Stored as JSON array of ClickHouse event IDs)
    evidence_refs = Column(JSON, default=list)
    mitre_tactics = Column(JSON, default=list)
    
    # Link to legacy alert if generated from one
    source_alert_id = Column(String(36), nullable=True)
