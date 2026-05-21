"""Redis-based sliding-window rate limiter.

보안 제품 자체에 brute-force/spam 방어가 없으면 안티패턴.
sensitive endpoint (login, register, forgot/reset password, revoke 등)에
FastAPI Depends 패턴으로 적용.

설계
====
- Sliding window via Redis sorted set (key=bucket, score=timestamp).
- 매 요청마다: 윈도 밖 멤버 제거(ZREMRANGEBYSCORE) → 현재 count(ZCARD) → 초과면 429.
- key 구성: prefix:scope (예: rl:login:ip:1.2.3.4)
- TTL = window + buffer (자동 청소).
- Fail-open: Redis 에러 시 통과 (가용성 우선, log only).

사용 예
=======
```python
@router.post("/auth/login")
async def login(
    payload: LoginRequest,
    _: None = Depends(rate_limit("login", 10, 60, by="email_or_ip")),
):
    ...
```
"""
from __future__ import annotations

import time
from typing import Callable, Literal

from fastapi import HTTPException, Request, status

from app.common.logging import get_logger
from app.redis_kv.client import get_redis

log = get_logger(__name__)

# Identifier 추출 모드
ByMode = Literal["ip", "email_or_ip", "user", "token"]


def _client_ip(request: Request) -> str:
    """X-Forwarded-For 우선, 없으면 client.host. nginx 뒤에서 정확함."""
    fwd = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
    if fwd:
        return fwd
    if request.client:
        return request.client.host
    return "unknown"


async def _extract_identifier(request: Request, by: ByMode) -> str:
    """rate-limit 키 구성 요소."""
    if by == "ip":
        return f"ip:{_client_ip(request)}"

    if by == "email_or_ip":
        # POST body에서 email 추출 시도 (login/forgot에서 사용)
        try:
            # body는 한 번만 읽을 수 있어 cache
            body = await request.body()
            if body:
                import json
                data = json.loads(body)
                email = data.get("email") if isinstance(data, dict) else None
                if email:
                    return f"email:{email.lower().strip()}"
        except Exception:
            pass
        return f"ip:{_client_ip(request)}"

    if by == "user":
        # 인증된 사용자 ID — JWT claims에서 (Depends order에 주의: rate_limit이 verify_token 뒤에)
        # 여기선 단순화: header의 Authorization을 hash해서 사용 (대략적)
        auth = request.headers.get("Authorization", "")
        if auth:
            import hashlib
            return f"user:{hashlib.sha256(auth.encode()).hexdigest()[:16]}"
        return f"ip:{_client_ip(request)}"

    if by == "token":
        # path parameter "token"에서 (reset-password 등)
        token = request.path_params.get("token") if hasattr(request, "path_params") else None
        if token:
            return f"token:{token[:16]}"
        return f"ip:{_client_ip(request)}"

    return f"ip:{_client_ip(request)}"


def rate_limit(
    bucket: str,
    max_requests: int,
    window_seconds: int,
    *,
    by: ByMode = "ip",
) -> Callable:
    """FastAPI Depends 호환 rate-limit 데코레이터 팩토리.

    Args:
        bucket: 키 prefix (예: "login", "register", "forgot_password")
        max_requests: 윈도 안 허용 횟수
        window_seconds: 윈도 길이 (초)
        by: identifier 추출 모드 (ip / email_or_ip / user / token)

    초과 시 429 + Retry-After 헤더.
    """

    async def dependency(request: Request) -> None:
        identifier = await _extract_identifier(request, by)
        key = f"rl:{bucket}:{identifier}"
        now_ms = int(time.time() * 1000)
        window_ms = window_seconds * 1000
        cutoff_ms = now_ms - window_ms

        try:
            redis = get_redis()
            # 1) 윈도 밖 멤버 제거
            await redis.zremrangebyscore(key, 0, cutoff_ms)
            # 2) 현재 count
            count = await redis.zcard(key)
            if count >= max_requests:
                # 가장 오래된 항목의 expire 추정
                oldest = await redis.zrange(key, 0, 0, withscores=True)
                retry_after = window_seconds
                if oldest:
                    retry_after = max(1, int((oldest[0][1] + window_ms - now_ms) / 1000))
                log.warning(
                    "rate_limit_exceeded",
                    bucket=bucket, identifier=identifier,
                    count=count, max=max_requests, window=window_seconds,
                )
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="rate_limit_exceeded",
                    headers={"Retry-After": str(retry_after)},
                )
            # 3) 현재 요청 등록
            await redis.zadd(key, {f"{now_ms}-{count}": now_ms})
            await redis.expire(key, window_seconds + 60)  # 자동 청소
        except HTTPException:
            raise
        except Exception as exc:  # noqa: BLE001
            # Fail-open: Redis 장애 시에도 서비스 계속 동작
            log.warning("rate_limit_redis_failed", bucket=bucket, error=str(exc))

    return dependency


# Pre-configured limiters for common endpoints
limit_login         = rate_limit("login",         max_requests=10, window_seconds=60, by="email_or_ip")
limit_register      = rate_limit("register",      max_requests=5,  window_seconds=3600, by="ip")
limit_forgot_pw     = rate_limit("forgot_pw",     max_requests=3,  window_seconds=3600, by="email_or_ip")
limit_reset_pw      = rate_limit("reset_pw",      max_requests=5,  window_seconds=60, by="token")
limit_verify_email  = rate_limit("verify_email",  max_requests=10, window_seconds=60, by="ip")
limit_revoke_all    = rate_limit("revoke_all",    max_requests=5,  window_seconds=60, by="user")
limit_request_verif = rate_limit("request_verif", max_requests=3,  window_seconds=300, by="user")
limit_invite        = rate_limit("invite",        max_requests=30, window_seconds=3600, by="user")
