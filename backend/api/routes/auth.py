"""
Authentication routes - login, token refresh, logout, me.
All operations backed by real PostgreSQL (no SQLite).
"""
from datetime import timedelta
from fastapi import APIRouter, HTTPException, status, Depends, Request
from pydantic import BaseModel
from sqlalchemy import select, insert
from typing import Optional

from backend.services.auth_service import authenticate_user, create_access_token, get_user_by_username
from backend.core.security import hash_password
from backend.api.middleware.auth import get_current_user
from backend.core.config import settings
from backend.db.postgres import AsyncSessionLocal
from backend.models.user import User

router = APIRouter()


class LoginRequest(BaseModel):
    username: str
    password: str


class CreateUserRequest(BaseModel):
    username: str
    email: str
    password: str
    role: str = "analyst"
    full_name: str = ""
    department: str = "SOC"


@router.post("/login")
async def login(request: Request, body: LoginRequest):
    user = await authenticate_user(body.username, body.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    token_data = {
        "sub": user["id"],
        "username": user["username"],
        "role": user["role"],
        "tenant_id": user.get("tenant_id", "default"),
        "full_name": user.get("full_name", ""),
        "department": user.get("department", "SOC"),
    }
    access_token = create_access_token(
        token_data,
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"],
            "full_name": user.get("full_name", ""),
            "department": user.get("department", "SOC"),
            "email": user.get("email", ""),
        },
    }


@router.get("/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    return current_user


@router.post("/logout")
async def logout(current_user: dict = Depends(get_current_user)):
    return {"message": "Logged out successfully"}


@router.get("/users")
async def list_users(current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    async with AsyncSessionLocal() as session:
        tenant_id = current_user.get("tenant_id", "default")
        result = await session.execute(select(User).where(User.tenant_id == tenant_id))
        users = result.scalars().all()
        return [
            {
                "id": u.id,
                "username": u.username,
                "email": u.email,
                "role": u.role,
                "full_name": u.full_name,
                "department": u.department,
                "is_active": u.is_active,
                "tenant_id": u.tenant_id,
            }
            for u in users
        ]


@router.post("/users")
async def add_user(body: CreateUserRequest, current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")

    # Check if user already exists
    existing = await get_user_by_username(body.username)
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")

    tenant_id = current_user.get("tenant_id", "default")

    async with AsyncSessionLocal() as session:
        new_user = User(
            username=body.username,
            email=body.email,
            hashed_password=hash_password(body.password),
            role=body.role,
            full_name=body.full_name,
            department=body.department,
            is_active=True,
            tenant_id=tenant_id,
        )
        session.add(new_user)
        await session.commit()
        return {"message": "User created", "username": body.username, "role": body.role}
