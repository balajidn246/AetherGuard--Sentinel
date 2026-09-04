"""
User management routes (admin only) - backed by real PostgreSQL.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from backend.api.middleware.auth import get_current_user, require_admin
from backend.db.postgres import AsyncSessionLocal
from backend.models.user import User

router = APIRouter()


@router.get("/")
async def list_users(current_user: dict = Depends(require_admin)):
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User))
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
            }
            for u in users
        ]


@router.get("/me")
async def get_my_profile(current_user: dict = Depends(get_current_user)):
    return current_user


@router.get("/{user_id}")
async def get_user(user_id: str, current_user: dict = Depends(require_admin)):
    async with AsyncSessionLocal() as session:
        user = (await session.execute(
            select(User).where(User.id == user_id)
        )).scalar_one_or_none()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "full_name": user.full_name,
            "department": user.department,
            "is_active": user.is_active,
        }
