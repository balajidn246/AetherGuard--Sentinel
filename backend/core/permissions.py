from enum import Enum
from fastapi import Request, HTTPException, status

class Permission(str, Enum):
    # Events & Logs
    EVENTS_READ = "events:read"
    EVENTS_WRITE = "events:write"
    
    # Alerts & Signals
    ALERTS_READ = "alerts:read"
    ALERTS_WRITE = "alerts:write"
    ALERTS_ACKNOWLEDGE = "alerts:acknowledge"
    ALERTS_ESCALATE = "alerts:escalate"
    
    # Detections
    DETECTIONS_READ = "detections:read"
    DETECTIONS_WRITE = "detections:write"
    
    # Cases & Incidents
    CASES_READ = "cases:read"
    CASES_WRITE = "cases:write"
    
    # Threat Intel
    THREAT_INTEL_READ = "threatintel:read"
    THREAT_INTEL_WRITE = "threatintel:write"
    
    # AI
    AI_INVESTIGATE = "ai:investigate"
    
    # Admin
    ADMIN_USERS = "admin:users"
    ADMIN_TENANTS = "admin:tenants"

# Default role mapping
ROLE_PERMISSIONS = {
    "admin": {
        Permission.EVENTS_READ, Permission.EVENTS_WRITE,
        Permission.ALERTS_READ, Permission.ALERTS_WRITE, Permission.ALERTS_ACKNOWLEDGE, Permission.ALERTS_ESCALATE,
        Permission.DETECTIONS_READ, Permission.DETECTIONS_WRITE,
        Permission.CASES_READ, Permission.CASES_WRITE,
        Permission.THREAT_INTEL_READ, Permission.THREAT_INTEL_WRITE,
        Permission.AI_INVESTIGATE,
        Permission.ADMIN_USERS, Permission.ADMIN_TENANTS
    },
    "analyst": {
        Permission.EVENTS_READ,
        Permission.ALERTS_READ, Permission.ALERTS_ACKNOWLEDGE, Permission.ALERTS_ESCALATE,
        Permission.DETECTIONS_READ,
        Permission.CASES_READ, Permission.CASES_WRITE,
        Permission.THREAT_INTEL_READ, Permission.THREAT_INTEL_WRITE,
        Permission.AI_INVESTIGATE
    },
    "viewer": {
        Permission.EVENTS_READ,
        Permission.ALERTS_READ,
        Permission.DETECTIONS_READ,
        Permission.CASES_READ,
        Permission.THREAT_INTEL_READ
    }
}

def require(*required_permissions: Permission):
    """
    FastAPI dependency to enforce RBAC.
    Validates that the current request context contains the required permissions.
    """
    def dependency(request: Request):
        if not hasattr(request.state, "context"):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
        
        user_permissions = request.state.context.permissions
        
        missing = [p for p in required_permissions if p not in user_permissions]
        if missing:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, 
                detail=f"Missing required permissions: {', '.join(missing)}"
            )
        return request.state.context
        
    return dependency
