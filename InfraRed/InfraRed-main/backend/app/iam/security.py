"""JWT helpers for agents and users."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt

from app.config import get_settings


bearer = HTTPBearer(auto_error=True)


def create_token(
    subject: str,
    *,
    tenant_id: str,
    agent_id: str | None = None,
    role: str = "agent",
    ttl_seconds: int | None = None,
) -> str:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    ttl = ttl_seconds or (
        settings.jwt_agent_ttl_seconds if role == "agent" else settings.jwt_user_ttl_seconds
    )
    payload: dict[str, Any] = {
        "sub": subject,
        "tenant_id": tenant_id,
        "role": role,
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=ttl)).timestamp()),
    }
    if agent_id:
        payload["agent_id"] = agent_id
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_alg)


async def verify_token(
    credentials: HTTPAuthorizationCredentials = Depends(bearer),
) -> dict[str, Any]:
    settings = get_settings()
    try:
        claims = jwt.decode(
            credentials.credentials,
            settings.jwt_secret,
            algorithms=[settings.jwt_alg],
            audience=settings.jwt_audience,
            issuer=settings.jwt_issuer,
        )
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid_or_expired_token",
        ) from exc
    return claims


async def verify_agent_token(claims: dict[str, Any] = Depends(verify_token)) -> dict[str, Any]:
    if claims.get("role") != "agent":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="agent_role_required")
    return claims
