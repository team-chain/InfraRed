"""Authentication API contracts."""
from __future__ import annotations

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    tenant_id: str = "company-a"
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict[str, str]


class StatusUpdateRequest(BaseModel):
    status: str = Field(
        ...,
        pattern="^(open|acknowledged|resolved|false_positive)$",
    )
