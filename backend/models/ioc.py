import uuid
from sqlalchemy import Column, String, Integer, Boolean, JSON
from backend.models.base import Base, TimestampMixin

class IOC(Base, TimestampMixin):
    __tablename__ = "iocs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), index=True, nullable=False, default="default")
    ioc_type = Column(String(20), index=True, nullable=False)  # ip, hash, domain, url
    value = Column(String(512), index=True, nullable=False)
    threat_type = Column(String(50), default="unknown")        # malware, phishing, c2, scanner
    confidence = Column(Integer, default=50)                   # 0 - 100
    tags = Column(JSON, default=list)
    notes = Column(String(1000), default="")
    source = Column(String(100), default="manual")
    active = Column(Boolean, default=True)
    created_by = Column(String(100), default="system")
    hit_count = Column(Integer, default=0)
