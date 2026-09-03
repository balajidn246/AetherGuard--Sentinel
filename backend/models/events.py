import uuid
from pydantic import BaseModel, Field, IPvAnyAddress
from typing import Optional, Dict, Any
from datetime import datetime, timezone

def utc_now():
    return datetime.now(timezone.utc)

class OCSFBaseEvent(BaseModel):
    """Base OCSF Event Schema for normalization."""
    time: datetime = Field(default_factory=utc_now)
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    
    # OCSF Base Event attributes
    class_uid: int = Field(default=0, description="Event Class ID")
    class_name: str = Field(default="Unknown", description="Event Class Name")
    category_uid: int = Field(default=0, description="Event Category ID")
    category_name: str = Field(default="Unknown", description="Event Category Name")
    severity_id: int = Field(default=1, description="1=Informational, 2=Low, 3=Medium, 4=High, 5=Critical")
    severity: str = Field(default="Informational")
    
    # Original Data
    original_time: Optional[str] = None
    message: Optional[str] = None
    raw_data: Optional[str] = None
    
    # Observables (Flattened for analytical DB performance)
    src_ip: Optional[IPvAnyAddress] = None
    dst_ip: Optional[IPvAnyAddress] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    user_name: Optional[str] = None
    host_name: Optional[str] = None
    process_name: Optional[str] = None
    file_hash: Optional[str] = None
    
    # Metadata
    source_log: str = Field(default="api", description="Source identifier")
    tenant_id: str = Field(default="default", description="Automatically populated by middleware")

    class Config:
        extra = "allow"
