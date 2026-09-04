import uuid
from sqlalchemy import Column, String, Integer, Float, Boolean
from backend.models.base import Base, TimestampMixin

class UEBASnapshot(Base, TimestampMixin):
    __tablename__ = "ueba_snapshots"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id = Column(String(36), index=True, nullable=False, default="default")
    username = Column(String(100), index=True, nullable=False)
    hour_bucket = Column(String(20), index=True, nullable=False)
    event_count = Column(Integer, default=0, nullable=False)
    avg_risk_score = Column(Float, default=20.0, nullable=False)
    peak_risk_score = Column(Float, default=20.0, nullable=False)
    anomaly_flag = Column(Boolean, default=False, nullable=False)
