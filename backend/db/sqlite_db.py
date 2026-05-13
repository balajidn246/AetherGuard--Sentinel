"""
SQLite/SQLAlchemy user store for authentication.
"""
import uuid
import logging
from datetime import datetime
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy import Column, String, Boolean, DateTime, Text, select

logger = logging.getLogger(__name__)

_engine = None
_AsyncSessionLocal = None


class Base(DeclarativeBase):
    pass


class UserModel(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(20), default="analyst")   # admin | analyst | viewer
    is_active = Column(Boolean, default=True)
    full_name = Column(String(100), default="")
    department = Column(String(100), default="SOC")
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)


class AuditLogModel(Base):
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36))
    username = Column(String(50))
    action = Column(String(100))
    resource = Column(String(200))
    details = Column(Text, default="")
    ip_address = Column(String(50), default="")
    timestamp = Column(DateTime, default=datetime.utcnow)


async def init_sqlite():
    global _engine, _AsyncSessionLocal
    _engine = create_async_engine(
        "sqlite+aiosqlite:///./aetherguard.db",
        echo=False,
        future=True,
    )
    _AsyncSessionLocal = sessionmaker(
        _engine, class_=AsyncSession, expire_on_commit=False
    )
    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("✅ SQLite database initialised (aetherguard.db)")


def get_session() -> AsyncSession:
    return _AsyncSessionLocal()


async def get_user_by_username(username: str) -> dict | None:
    async with get_session() as session:
        result = await session.execute(
            select(UserModel).where(UserModel.username == username)
        )
        user = result.scalar_one_or_none()
        if user:
            return {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "hashed_password": user.hashed_password,
                "role": user.role,
                "is_active": user.is_active,
                "full_name": user.full_name,
                "department": user.department,
                "created_at": user.created_at.isoformat() if user.created_at else None,
                "last_login": user.last_login.isoformat() if user.last_login else None,
            }
        return None


async def get_user_by_id(user_id: str) -> dict | None:
    async with get_session() as session:
        result = await session.execute(
            select(UserModel).where(UserModel.id == user_id)
        )
        user = result.scalar_one_or_none()
        if user:
            return {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "role": user.role,
                "is_active": user.is_active,
                "full_name": user.full_name,
                "department": user.department,
            }
        return None


async def get_all_users() -> list:
    async with get_session() as session:
        result = await session.execute(select(UserModel))
        users = result.scalars().all()
        return [
            {
                "id": u.id,
                "username": u.username,
                "email": u.email,
                "role": u.role,
                "is_active": u.is_active,
                "full_name": u.full_name,
                "department": u.department,
                "created_at": u.created_at.isoformat() if u.created_at else None,
                "last_login": u.last_login.isoformat() if u.last_login else None,
            }
            for u in users
        ]


async def create_user(user_data: dict) -> dict:
    async with get_session() as session:
        user = UserModel(
            id=str(uuid.uuid4()),
            username=user_data["username"],
            email=user_data["email"],
            hashed_password=user_data["hashed_password"],
            role=user_data.get("role", "analyst"),
            full_name=user_data.get("full_name", ""),
            department=user_data.get("department", "SOC"),
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)
        return {"id": user.id, "username": user.username}


async def update_last_login(user_id: str):
    async with get_session() as session:
        result = await session.execute(
            select(UserModel).where(UserModel.id == user_id)
        )
        user = result.scalar_one_or_none()
        if user:
            user.last_login = datetime.utcnow()
            await session.commit()


async def write_audit_log(user_id: str, username: str, action: str, resource: str, details: str = "", ip: str = ""):
    async with get_session() as session:
        log = AuditLogModel(
            id=str(uuid.uuid4()),
            user_id=user_id,
            username=username,
            action=action,
            resource=resource,
            details=details,
            ip_address=ip,
        )
        session.add(log)
        await session.commit()
