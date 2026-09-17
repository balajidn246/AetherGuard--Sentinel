import uuid
import time
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
import structlog
from backend.core.security import decode_token
from backend.core.context import RequestContext
from backend.core.permissions import ROLE_PERMISSIONS, Permission
from backend.core.config import settings

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
        
        # 1. Check API Key Header for ingestion / automated collectors
        api_key = request.headers.get("X-AetherGuard-Key") or request.headers.get("X-API-Key")
        if api_key and api_key == settings.INGEST_API_KEY:
            user_id = "ingest_service"
            username = "ingest_service"
            tenant_id = request.headers.get("X-Tenant-ID", "default")
            roles = ["ingest"]
            permissions = {Permission.EVENTS_WRITE, Permission.EVENTS_READ}
        else:
            # 2. Extract JWT token from Authorization header
            auth_header = request.headers.get("Authorization")
            if auth_header and auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]
                payload = decode_token(token)
                if payload:
                    user_id = payload.get("sub", user_id)
                    username = payload.get("username", username)
                    tenant_id = payload.get("tenant_id", "default")
                    
                    role = payload.get("role")
                    if role:
                        roles = [role]
                        permissions = ROLE_PERMISSIONS.get(role, set()).copy()
                    
                    if "roles" in payload:
                        roles = payload["roles"]
                    if "permissions" in payload:
                        permissions = permissions.union(set(payload["permissions"]))
            elif settings.ENVIRONMENT == "development" and request.url.path.startswith("/api/ingest"):
                # Development mode grace for local testing
                user_id = "dev_ingest"
                username = "dev_ingest"
                tenant_id = request.headers.get("X-Tenant-ID", "default")
                roles = ["ingest"]
                permissions = {Permission.EVENTS_WRITE, Permission.EVENTS_READ}
        
        # Create typed RequestContext
        context = RequestContext(
            tenant_id=tenant_id,
            user_id=user_id,
            username=username,
            roles=roles,
            permissions=permissions,
            request_id=request_id,
            ip_address=request.client.host if request.client else ""
        )
        
        request.state.context = context
        
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(
            request_id=request_id,
            tenant_id=tenant_id,
            user_id=user_id,
            path=request.url.path,
            method=request.method
        )
        
        # --- Rate Limiting ---
        client_ip = request.client.host if request.client else "127.0.0.1"
        from backend.db.redis import get_redis
        r = await get_redis()
        if r:
            rl_key = f"ag:ratelimit:{client_ip}"
            req_count = await r.incr(rl_key)
            if req_count == 1:
                await r.expire(rl_key, 60)
            if req_count > 1000:
                from fastapi.responses import JSONResponse
                return JSONResponse(status_code=429, content={"detail": "Too Many Requests"})
        
        response = await call_next(request)
        
        process_time = time.time() - start_time
        logger.info("Request completed", status_code=response.status_code, duration_s=round(process_time, 4))
        
        response.headers["X-Request-ID"] = request_id
        return response
