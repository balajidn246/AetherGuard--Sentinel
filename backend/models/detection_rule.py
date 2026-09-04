import uuid
from sqlalchemy import Column, String, Integer, Boolean, JSON
from backend.models.base import Base, TimestampMixin

class DetectionRuleModel(Base, TimestampMixin):
    __tablename__ = "detection_rules"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), index=True, nullable=False, default="default")
    rule_id = Column(String(100), unique=True, index=True, nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(String(2000), default="")
    severity = Column(String(20), default="medium")
    rule_type = Column(String(20), default="yaml")       # python, yaml, sigma
    enabled = Column(Boolean, default=True, nullable=False)
    content = Column(JSON, default=dict)
    mitre_techniques = Column(JSON, default=list)
    version = Column(String(20), default="1.0.0")
    author = Column(String(100), default="AetherGuard")
    false_positive_notes = Column(String(1000), default="")
    hit_count = Column(Integer, default=0, nullable=False)
