import uuid
from sqlalchemy import Column, String, JSON
from backend.models.base import Base, TimestampMixin

class Case(Base, TimestampMixin):
    __tablename__ = "cases"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), index=True, nullable=False, default="default")
    title = Column(String(255), nullable=False)
    description = Column(String(2000), default="")
    status = Column(String(30), default="open")          # open, investigating, contained, resolved, closed
    priority = Column(String(20), default="medium")       # critical, high, medium, low
    owner_id = Column(String(100), nullable=True)
    signal_ids = Column(JSON, default=list)
    incident_ids = Column(JSON, default=list)
    evidence_refs = Column(JSON, default=list)
    timeline = Column(JSON, default=list)
    notes = Column(JSON, default=list)
    ai_summary = Column(String(5000), nullable=True)
