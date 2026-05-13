"""
Authentication service — JWT + bcrypt.
"""
import logging
from datetime import datetime, timedelta
from typing import Optional

from jose import JWTError, jwt
from passlib.context import CryptContext

from config.settings import settings
from db.sqlite_db import (
    get_user_by_username,
    create_user,
    update_last_login,
    get_all_users,
)

logger = logging.getLogger(__name__)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ---------- helpers ----------

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode["exp"] = expire
    to_encode["iat"] = datetime.utcnow()
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

def decode_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except JWTError:
        return None

# ---------- user operations ----------

async def authenticate_user(username: str, password: str) -> Optional[dict]:
    user = await get_user_by_username(username)
    if not user:
        return None
    if not verify_password(password, user["hashed_password"]):
        return None
    if not user.get("is_active", True):
        return None
    await update_last_login(user["id"])
    return user

async def create_default_users():
    """Seed default admin and analyst accounts on first start."""
    users_exist = await get_all_users()
    if users_exist:
        return

    defaults = [
        {
            "username": "admin",
            "email": "admin@aetherguard.soc",
            "hashed_password": hash_password("aetherguard2024"),
            "role": "admin",
            "full_name": "System Administrator",
            "department": "SOC Management",
        },
        {
            "username": "analyst",
            "email": "analyst@aetherguard.soc",
            "hashed_password": hash_password("sentinel2024"),
            "role": "analyst",
            "full_name": "SOC Analyst",
            "department": "Threat Analysis",
        },
        {
            "username": "viewer",
            "email": "viewer@aetherguard.soc",
            "hashed_password": hash_password("viewer2024"),
            "role": "viewer",
            "full_name": "Read-Only Viewer",
            "department": "Management",
        },
    ]

    for u in defaults:
        await create_user(u)
        logger.info(f"  👤 Created user: {u['username']} [{u['role']}]")
    logger.info("✅ Default users seeded")
