"""
Authentication service - REAL PostgreSQL User management with Argon2 / bcrypt and JWT.
"""
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional
import jwt
from sqlalchemy import select, update
from backend.core.config import settings
from backend.core.security import hash_password, verify_password
from backend.db.postgres import AsyncSessionLocal
from backend.models.user import User

logger = logging.getLogger(__name__)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode["exp"] = expire
    to_encode["iat"] = datetime.now(timezone.utc)
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm="HS256")

def decode_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None

async def get_user_by_username(username: str) -> Optional[dict]:
    async with AsyncSessionLocal() as session:
        stmt = select(User).where(User.username == username)
        u = (await session.execute(stmt)).scalar_one_or_none()
        if not u:
            return None
        return {
            "id": u.id,
            "tenant_id": u.tenant_id,
            "username": u.username,
            "email": u.email,
            "hashed_password": u.hashed_password,
            "role": u.role,
            "is_active": u.is_active,
            "full_name": u.full_name,
            "department": u.department,
        }

async def authenticate_user(username: str, password: str) -> Optional[dict]:
    user = await get_user_by_username(username)
    if not user:
        return None
    if not verify_password(password, user["hashed_password"]):
        return None
    if not user.get("is_active", True):
        return None
    return user

async def create_default_users():
    """Seed default admin, analyst, and viewer accounts in PostgreSQL on first start."""
    defaults = [
        {
            "username": "admin",
            "email": "admin@aetherguard.soc",
            "password": "aetherguard2024",
            "role": "admin",
            "full_name": "System Administrator",
            "department": "SOC Management",
        },
        {
            "username": "analyst",
            "email": "analyst@aetherguard.soc",
            "password": "sentinel2024",
            "role": "analyst",
            "full_name": "SOC Analyst",
            "department": "Threat Analysis",
        },
        {
            "username": "viewer",
            "email": "viewer@aetherguard.soc",
            "password": "viewer2024",
            "role": "viewer",
            "full_name": "Read-Only Viewer",
            "department": "Management",
        },
    ]

    async with AsyncSessionLocal() as session:
        for u_data in defaults:
            stmt = select(User).where(User.username == u_data["username"])
            existing = (await session.execute(stmt)).scalar_one_or_none()
            if not existing:
                new_user = User(
                    username=u_data["username"],
                    email=u_data["email"],
                    hashed_password=hash_password(u_data["password"]),
                    role=u_data["role"],
                    full_name=u_data["full_name"],
                    department=u_data["department"],
                    is_active=True
                )
                session.add(new_user)
                logger.info(f"  ? Seeded user: {u_data['username']} [{u_data['role']}]")
        await session.commit()
    logger.info("[OK] PostgreSQL Default users seeded")
