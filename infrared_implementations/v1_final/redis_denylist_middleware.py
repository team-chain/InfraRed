"""
InfraRed v1 — Redis Denylist 403 차단 미들웨어
설계서_최종.docx 구현 순서 #1

FastAPI 미들웨어로 동작하며:
  1. 모든 요청의 source IP를 Redis Denylist에서 조회
  2. 등록된 IP면 즉시 HTTP 403 반환 (서비스 레벨 차단)
  3. Allowlist IP는 절대 차단하지 않음
  4. 사설/루프백/내부망 IP 차단 금지
  5. 모든 차단 이벤트는 auto_response_logs에 append-only 기록
"""

from __future__ import annotations

import ipaddress
import json
import logging
import time
from typing import Callable

import redis.asyncio as aioredis
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

logger = logging.getLogger("infrared.denylist")

# ──────────────────────────────────────────────────────────────
# 내부망 / 루프백 / 사설망 → 절대 차단 금지
# ──────────────────────────────────────────────────────────────
_NEVER_BLOCK_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),     # 루프백
    ipaddress.ip_network("10.0.0.0/8"),      # 사설망
    ipaddress.ip_network("172.16.0.0/12"),   # 사설망
    ipaddress.ip_network("192.168.0.0/16"),  # 사설망
    ipaddress.ip_network("::1/128"),         # IPv6 루프백
    ipaddress.ip_network("fc00::/7"),        # IPv6 ULA
]


def _is_internal(ip_str: str) -> bool:
    """사설/루프백/내부망 IP 여부 확인"""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _NEVER_BLOCK_NETWORKS)
    except ValueError:
        return False


def _extract_client_ip(request: Request) -> str:
    """X-Forwarded-For / X-Real-IP / 직접 연결 순서로 실제 클라이언트 IP 추출"""
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    xri = request.headers.get("X-Real-IP")
    if xri:
        return xri.strip()
    if request.client:
        return request.client.host
    return "unknown"


# ──────────────────────────────────────────────────────────────
# Redis Denylist 키 규격
#   denylist:{tenant_id}:{ip}   → "1"  (TTL = 차단 유지 시간)
#   denylist:global:{ip}        → "1"  (전역 차단)
# ──────────────────────────────────────────────────────────────
DENYLIST_KEY_TEMPLATE = "denylist:{tenant_id}:{ip}"
DENYLIST_GLOBAL_KEY   = "denylist:global:{ip}"


class RedisDenylistClient:
    """Redis Denylist CRUD — Policy Engine / CLI에서 사용"""

    def __init__(self, redis: aioredis.Redis):
        self.redis = redis

    # ── 추가 ────────────────────────────────────────────────
    async def block_ip(
        self,
        ip: str,
        *,
        tenant_id: str = "global",
        ttl_seconds: int = 1800,   # 기본 30분
        reason: str = "",
        actor: str = "policy_engine",
    ) -> bool:
        """
        IP를 Denylist에 등록.
        - 내부망 IP는 등록 거부 (False 반환)
        - 이미 등록된 경우 idempotent (True 반환, TTL 갱신)
        """
        if _is_internal(ip):
            logger.warning("block_ip: 내부망 IP 차단 시도 거부 — ip=%s", ip)
            return False

        key = (
            DENYLIST_GLOBAL_KEY.format(ip=ip)
            if tenant_id == "global"
            else DENYLIST_KEY_TEMPLATE.format(tenant_id=tenant_id, ip=ip)
        )
        payload = json.dumps({
            "ip":         ip,
            "tenant_id":  tenant_id,
            "reason":     reason,
            "actor":      actor,
            "blocked_at": time.time(),
            "expires_at": time.time() + ttl_seconds,
        })
        await self.redis.set(key, payload, ex=ttl_seconds)
        logger.info("IP 차단 등록: ip=%s tenant=%s ttl=%ds", ip, tenant_id, ttl_seconds)
        return True

    # ── 해제 ────────────────────────────────────────────────
    async def unblock_ip(self, ip: str, *, tenant_id: str = "global") -> bool:
        key = (
            DENYLIST_GLOBAL_KEY.format(ip=ip)
            if tenant_id == "global"
            else DENYLIST_KEY_TEMPLATE.format(tenant_id=tenant_id, ip=ip)
        )
        deleted = await self.redis.delete(key)
        return deleted > 0

    # ── 조회 ────────────────────────────────────────────────
    async def is_blocked(self, ip: str, tenant_id: str = "global") -> bool:
        """전역 차단 또는 테넌트별 차단 여부 확인"""
        global_key  = DENYLIST_GLOBAL_KEY.format(ip=ip)
        tenant_key  = DENYLIST_KEY_TEMPLATE.format(tenant_id=tenant_id, ip=ip)
        # pipeline으로 두 키 동시 조회
        async with self.redis.pipeline(transaction=False) as pipe:
            await pipe.exists(global_key)
            await pipe.exists(tenant_key)
            results = await pipe.execute()
        return any(results)

    async def get_block_info(self, ip: str, tenant_id: str = "global") -> dict | None:
        """차단 정보 반환 (TTL 포함)"""
        for key in [
            DENYLIST_GLOBAL_KEY.format(ip=ip),
            DENYLIST_KEY_TEMPLATE.format(tenant_id=tenant_id, ip=ip),
        ]:
            raw = await self.redis.get(key)
            if raw:
                info = json.loads(raw)
                ttl  = await self.redis.ttl(key)
                info["ttl_remaining"] = ttl
                return info
        return None

    async def list_blocked_ips(self, tenant_id: str = "global") -> list[dict]:
        """현재 차단 중인 IP 전체 목록"""
        pattern = (
            "denylist:global:*"
            if tenant_id == "global"
            else f"denylist:{tenant_id}:*"
        )
        keys = await self.redis.keys(pattern)
        result = []
        for key in keys:
            raw = await self.redis.get(key)
            if raw:
                info = json.loads(raw)
                ttl  = await self.redis.ttl(key)
                info["ttl_remaining"] = ttl
                result.append(info)
        return result


# ──────────────────────────────────────────────────────────────
# FastAPI 미들웨어
# ──────────────────────────────────────────────────────────────
class DenylistMiddleware(BaseHTTPMiddleware):
    """
    모든 요청에 대해 Redis Denylist를 조회하고
    차단된 IP면 403 Forbidden 반환.

    사용법:
        app.add_middleware(
            DenylistMiddleware,
            redis=redis_client,
            db_pool=pg_pool,       # auto_response_logs 기록용 (선택)
            allowlist_ips=["1.2.3.4"],
        )
    """

    def __init__(
        self,
        app: ASGIApp,
        redis: aioredis.Redis,
        db_pool=None,
        allowlist_ips: list[str] | None = None,
    ):
        super().__init__(app)
        self.denylist    = RedisDenylistClient(redis)
        self.db_pool     = db_pool
        self.allowlist   = set(allowlist_ips or [])

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        client_ip = _extract_client_ip(request)

        # 1) Allowlist 통과 (절대 차단 안 함)
        if client_ip in self.allowlist:
            return await call_next(request)

        # 2) 내부망 IP 통과
        if _is_internal(client_ip):
            return await call_next(request)

        # 3) 테넌트 ID 추출 (JWT 또는 헤더에서)
        tenant_id = request.headers.get("X-Tenant-ID", "global")

        # 4) Denylist 조회
        if await self.denylist.is_blocked(client_ip, tenant_id):
            block_info = await self.denylist.get_block_info(client_ip, tenant_id) or {}
            logger.warning(
                "403 차단: ip=%s tenant=%s path=%s reason=%s",
                client_ip, tenant_id, request.url.path,
                block_info.get("reason", "policy_block"),
            )
            # auto_response_logs에 차단 이벤트 기록
            if self.db_pool:
                await self._log_block_event(
                    client_ip, tenant_id, request, block_info
                )
            return JSONResponse(
                status_code=403,
                content={
                    "error":   "access_denied",
                    "message": "Your IP has been blocked due to suspicious activity.",
                    "code":    "DENYLIST_BLOCK",
                },
                headers={
                    "X-Block-Reason": block_info.get("reason", "policy_block"),
                    "X-Block-TTL":    str(block_info.get("ttl_remaining", -1)),
                },
            )

        # 5) 통과
        return await call_next(request)

    async def _log_block_event(
        self,
        ip: str,
        tenant_id: str,
        request: Request,
        block_info: dict,
    ) -> None:
        """auto_response_logs에 append-only 차단 이벤트 기록"""
        try:
            async with self.db_pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO auto_response_logs
                        (tenant_id, action, target_ip, rule_id, reason,
                         request_path, request_method, reversed, metadata)
                    VALUES ($1, 'block_403', $2, $3, $4, $5, $6, false, $7::jsonb)
                    """,
                    tenant_id,
                    ip,
                    block_info.get("rule_id", "DENYLIST"),
                    block_info.get("reason", "policy_block"),
                    str(request.url.path),
                    request.method,
                    json.dumps({
                        "actor":      block_info.get("actor"),
                        "blocked_at": block_info.get("blocked_at"),
                        "ttl_remaining": block_info.get("ttl_remaining"),
                        "user_agent": request.headers.get("User-Agent", ""),
                    }),
                )
        except Exception as exc:
            logger.error("auto_response_logs 기록 실패: %s", exc)


# ──────────────────────────────────────────────────────────────
# FastAPI 라우터 — Denylist 관리 API
# ──────────────────────────────────────────────────────────────
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

denylist_router = APIRouter(prefix="/api/v1/denylist", tags=["denylist"])


class BlockRequest(BaseModel):
    ip:          str  = Field(..., description="차단할 IP 주소")
    ttl_seconds: int  = Field(1800, ge=60, le=86400, description="차단 유지 시간(초)")
    reason:      str  = Field("manual_block", description="차단 사유")


class UnblockRequest(BaseModel):
    ip: str = Field(..., description="해제할 IP 주소")


# 의존성 — 실제 앱에서는 app.state.redis / auth dependency 사용
async def get_denylist_client(request: Request) -> RedisDenylistClient:
    return RedisDenylistClient(request.app.state.redis)


async def get_tenant_id(request: Request) -> str:
    return request.headers.get("X-Tenant-ID", "global")


@denylist_router.post("/block", status_code=status.HTTP_201_CREATED)
async def block_ip_endpoint(
    body:       BlockRequest,
    tenant_id:  str                = Depends(get_tenant_id),
    client:     RedisDenylistClient = Depends(get_denylist_client),
):
    """IP를 Denylist에 등록 (정책 엔진 또는 관리자 수동 차단)"""
    if _is_internal(body.ip):
        raise HTTPException(
            status_code=400,
            detail="내부망/루프백 IP는 차단할 수 없습니다.",
        )
    success = await client.block_ip(
        body.ip,
        tenant_id=tenant_id,
        ttl_seconds=body.ttl_seconds,
        reason=body.reason,
        actor="api_manual",
    )
    if not success:
        raise HTTPException(status_code=400, detail="IP 차단 실패")
    return {"message": f"{body.ip} 차단 등록 완료", "ttl_seconds": body.ttl_seconds}


@denylist_router.delete("/unblock")
async def unblock_ip_endpoint(
    body:      UnblockRequest,
    tenant_id: str                 = Depends(get_tenant_id),
    client:    RedisDenylistClient = Depends(get_denylist_client),
):
    """IP 차단 해제"""
    removed = await client.unblock_ip(body.ip, tenant_id=tenant_id)
    if not removed:
        raise HTTPException(status_code=404, detail="차단 목록에 없는 IP입니다.")
    return {"message": f"{body.ip} 차단 해제 완료"}


@denylist_router.get("/list")
async def list_blocked_endpoint(
    tenant_id: str                 = Depends(get_tenant_id),
    client:    RedisDenylistClient = Depends(get_denylist_client),
):
    """현재 차단 중인 IP 전체 목록"""
    return await client.list_blocked_ips(tenant_id)


@denylist_router.get("/check/{ip}")
async def check_ip_endpoint(
    ip:        str,
    tenant_id: str                 = Depends(get_tenant_id),
    client:    RedisDenylistClient = Depends(get_denylist_client),
):
    """특정 IP 차단 여부 조회"""
    blocked = await client.is_blocked(ip, tenant_id)
    info    = await client.get_block_info(ip, tenant_id) if blocked else None
    return {"ip": ip, "blocked": blocked, "info": info}


# ──────────────────────────────────────────────────────────────
# 앱 등록 예시
# ──────────────────────────────────────────────────────────────
def register_denylist(
    app: FastAPI,
    redis: aioredis.Redis,
    db_pool=None,
    allowlist_ips: list[str] | None = None,
) -> None:
    """
    app.py에서 호출:
        from redis_denylist_middleware import register_denylist
        register_denylist(app, redis_client, pg_pool, allowlist_ips=["10.0.0.1"])
    """
    app.add_middleware(
        DenylistMiddleware,
        redis=redis,
        db_pool=db_pool,
        allowlist_ips=allowlist_ips,
    )
    app.include_router(denylist_router)
    logger.info("Redis Denylist 미들웨어 + 관리 API 등록 완료")
