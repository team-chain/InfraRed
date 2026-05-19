"""JWT helpers for agents and users."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt

from app.config import get_settings
from app.iam.rbac import has_permission


_bearer = HTTPBearer(auto_error=False)


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


def _decode_raw(raw: str) -> dict[str, Any]:
    settings = get_settings()
    try:
        return jwt.decode(
            raw,
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


async def verify_token(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> dict[str, Any]:
    """Accept JWT from Authorization: Bearer header OR infrared_token cookie."""
    if credentials:
        return _decode_raw(credentials.credentials)
    cookie = request.cookies.get("infrared_token")
    if cookie:
        return _decode_raw(cookie)
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="not_authenticated",
    )


async def verify_agent_token(
    claims: dict[str, Any] = Depends(verify_token),
) -> dict[str, Any]:
    # v3.0: watchdog role 도 에이전트 계열 토큰으로 허용 (tamper-report 엔드포인트)
    if claims.get("role") not in {"agent", "watchdog"}:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="agent_role_required")
    return claims


async def verify_user_token(
    claims: dict[str, Any] = Depends(verify_token),
) -> dict[str, Any]:
    if claims.get("role") == "agent":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="user_role_required")
    return claims


def require_permission(permission: str):
    async def dependency(claims: dict[str, Any] = Depends(verify_user_token)) -> dict[str, Any]:
        if not has_permission(str(claims.get("role")), permission):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="permission_denied")
        return claims
    return dependency
