"""Authentication API contracts."""
from __future__ import annotations

from pydantic import BaseModel, EmailStr, field_validator


class LoginRequest(BaseModel):
    tenant_id: str = "company-a"
    email: str
    password: str


class RegisterRequest(BaseModel):
    tenant_id: str = "company-a"
    email: str
    password: str
    role: str = "analyst"

    @field_validator("role")
    @classmethod
    def role_must_be_valid(cls, v: str) -> str:
        allowed = {"admin", "analyst", "viewer"}
        if v not in allowed:
            raise ValueError(f"role must be one of {sorted(allowed)}")
        return v

    @field_validator("password")
    @classmethod
    def password_min_length(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("password must be at least 8 characters")
        return v


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict[str, str]


class StatusUpdateRequest(BaseModel):
    status: str
