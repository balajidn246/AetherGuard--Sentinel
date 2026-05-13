"""
Authentication routes — login, token refresh, logout, me.
"""
from datetime import timedelta
from fastapi import APIRouter, HTTPException, status, Depends, Request
from pydantic import BaseModel

from services.auth_service import authenticate_user, create_access_token
from api.middleware.auth import get_current_user
from config.settings import settings
from db.sqlite_db import write_audit_log, get_all_users, create_user
from services.auth_service import hash_password

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
        "full_name": user.get("full_name", ""),
        "department": user.get("department", "SOC"),
    }
    access_token = create_access_token(
        token_data,
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    )

    await write_audit_log(
        user_id=user["id"],
        username=user["username"],
        action="LOGIN",
        resource="/api/auth/login",
        details=f"Successful login",
        ip=request.client.host if request.client else "",
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
    await write_audit_log(
        user_id=current_user.get("sub", ""),
        username=current_user.get("username", ""),
        action="LOGOUT",
        resource="/api/auth/logout",
        details="User logged out",
    )
    return {"message": "Logged out successfully"}


@router.get("/users")
async def list_users(current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    return await get_all_users()


@router.post("/users")
async def add_user(body: CreateUserRequest, current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    result = await create_user({
        "username": body.username,
        "email": body.email,
        "hashed_password": hash_password(body.password),
        "role": body.role,
        "full_name": body.full_name,
        "department": body.department,
    })
    return {"message": "User created", "user": result}
