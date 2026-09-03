from fastapi import Request
from fastapi.responses import JSONResponse

class AetherGuardError(Exception):
    """Base exception for AetherGuard--Sentinel."""
    def __init__(self, message: str, status_code: int = 500, error_code: str = "INTERNAL_ERROR", details: dict = None):
        self.message = message
        self.status_code = status_code
        self.error_code = error_code
        self.details = details or {}
        super().__init__(self.message)

class AuthenticationError(AetherGuardError):
    def __init__(self, message: str = "Authentication failed", details: dict = None):
        super().__init__(message, 401, "AUTH_001", details)

class AuthorizationError(AetherGuardError):
    def __init__(self, message: str = "Permission denied", details: dict = None):
        super().__init__(message, 403, "AUTH_002", details)

class NotFoundError(AetherGuardError):
    def __init__(self, message: str = "Resource not found", details: dict = None):
        super().__init__(message, 404, "NOT_FOUND", details)

class TenantIsolationError(AetherGuardError):
    def __init__(self, message: str = "Tenant isolation violation", details: dict = None):
        super().__init__(message, 403, "TENANT_ISO_001", details)

async def aetherguard_exception_handler(request: Request, exc: AetherGuardError):
    """FastAPI exception handler for custom errors."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "code": exc.error_code,
                "message": exc.message,
                "details": exc.details
            }
        }
    )
