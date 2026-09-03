import uuid
import time
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
import structlog
from backend.core.security import decode_token
from backend.core.context import RequestContext
from backend.core.permissions import ROLE_PERMISSIONS

logger = structlog.get_logger(__name__)

class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = str(uuid.uuid4())
        start_time = time.time()
        
        # Default empty context for unauthenticated requests
        tenant_id = "public"
        user_id = "anonymous"
        username = "anonymous"
        roles = []
        permissions = set()
        
        # Attempt to extract JWT token from Authorization header
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
            payload = decode_token(token)
            if payload:
                user_id = payload.get("sub", user_id)
                username = payload.get("username", username)
                tenant_id = payload.get("tenant_id", "default")
                
                # Handle legacy role formats and map to new permissions
                role = payload.get("role")
                if role:
                    roles = [role]
                    permissions = ROLE_PERMISSIONS.get(role, set())
                
                # Also support modern explicit roles/permissions array if present
                if "roles" in payload:
                    roles = payload["roles"]
                if "permissions" in payload:
                    permissions = permissions.union(set(payload["permissions"]))
        
        # Create the typed RequestContext
        context = RequestContext(
            tenant_id=tenant_id,
            user_id=user_id,
            username=username,
            roles=roles,
            permissions=permissions,
            request_id=request_id,
            ip_address=request.client.host if request.client else ""
        )
        
        # Attach to request state for FastAPI dependencies (like `require()`)
        request.state.context = context
        
        # Bind to structured logger context for all subsequent logs in this request
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(
            request_id=request_id,
            tenant_id=tenant_id,
            user_id=user_id,
            path=request.url.path,
            method=request.method
        )
        
        # Process request
        response = await call_next(request)
        
        process_time = time.time() - start_time
        logger.info("Request completed", status_code=response.status_code, duration_s=round(process_time, 4))
        
        response.headers["X-Request-ID"] = request_id
        return response
