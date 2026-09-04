import uuid
from sqlalchemy import Column, String, JSON, Integer
from backend.models.base import Base, TimestampMixin

class Incident(Base, TimestampMixin):
    __tablename__ = "incidents"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), index=True, nullable=False, default="default")
    title = Column(String(255), nullable=False)
    description = Column(String(2000), default="")
    severity = Column(String(20), default="medium")  # critical, high, medium, low
    status = Column(String(20), default="open")      # open, investigating, contained, resolved, closed
    assignee = Column(String(100), nullable=True)
    source_signal_ids = Column(JSON, default=list)
    tags = Column(JSON, default=list)
    notes = Column(JSON, default=list)
