"""
Audit Service - Structured, immutable auditing for all security actions,
user logins, incident transitions, rule changes, and AI investigations.
"""
import logging
from backend.db.postgres import AsyncSessionLocal
from backend.models.audit_log import AuditLog

logger = logging.getLogger(__name__)

class AuditService:
    @staticmethod
    async def log_action(
        actor_id: str,
        actor_username: str,
        action: str,
        resource: str,
        resource_id: str = None,
        details: dict = None,
        result: str = "success",
        ip_address: str = "",
        tenant_id: str = "default"
    ):
        try:
            async with AsyncSessionLocal() as session:
                entry = AuditLog(
                    tenant_id=tenant_id,
                    actor_id=actor_id or "system",
                    actor_username=actor_username or "system",
                    action=action,
                    resource=resource,
                    resource_id=resource_id,
                    details=details or {},
                    result=result,
                    ip_address=ip_address or ""
                )
                session.add(entry)
                await session.commit()
                logger.debug(f"[AUDIT] {actor_username} performed {action} on {resource}:{resource_id} ({result})")
        except Exception as exc:
            logger.error(f"[AUDIT] Failed to record audit log: {exc}")

audit_service = AuditService()
