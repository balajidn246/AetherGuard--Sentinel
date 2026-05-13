"""
User management routes (admin only).
"""
from fastapi import APIRouter, Depends, HTTPException
from api.middleware.auth import get_current_user, require_admin
from db.sqlite_db import get_all_users, get_user_by_id

router = APIRouter()


@router.get("/")
async def list_users(current_user: dict = Depends(require_admin)):
    return await get_all_users()


@router.get("/me")
async def get_my_profile(current_user: dict = Depends(get_current_user)):
    return current_user


@router.get("/{user_id}")
async def get_user(user_id: str, current_user: dict = Depends(require_admin)):
    user = await get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user
