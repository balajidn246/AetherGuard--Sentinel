from dataclasses import dataclass, field
from typing import Optional, Set, List

@dataclass(frozen=True)
class RequestContext:
    """
    Immutable request context passed through the application.
    Ensures tenant attribution and user identity are always available.
    """
    tenant_id: str
    user_id: str
    username: str
    roles: List[str] = field(default_factory=list)
    permissions: Set[str] = field(default_factory=set)
    region: Optional[str] = None
    request_id: str = ""
    ip_address: str = ""
