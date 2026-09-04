import uuid
from sqlalchemy import Column, String, JSON
from backend.models.base import Base, TimestampMixin

class AuditLog(Base, TimestampMixin):
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), index=True, nullable=False, default="default")
    actor_id = Column(String(100), nullable=False)
    actor_username = Column(String(100), nullable=False)
    action = Column(String(100), nullable=False)
    resource = Column(String(100), nullable=False)
    resource_id = Column(String(100), nullable=True)
    details = Column(JSON, default=dict)
    result = Column(String(20), default="success")
    ip_address = Column(String(45), default="")
