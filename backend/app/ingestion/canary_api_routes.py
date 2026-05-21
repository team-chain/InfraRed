"""CANARY-API-001 Canary API Route — v8.0 설계서

역할:
  공격자만 접근할 수 있는 숨겨진 FastAPI 미끼 엔드포인트.
  일반 사용자는 절대 접근하지 않으며, 접근 시 즉시 인시던트를 생성.

설계:
  - 정상 API 문서(OpenAPI)에는 노출되지 않음 (include_in_schema=False)
  - URL 경로는 공격자가 노리는 일반적인 경로를 사용 (admin, debug, backup 등)
  - 요청 IP + User-Agent + 요청 본문을 수집하여 공격자 프로파일링
  - Redis를 통해 Detection Worker에 즉시 경보 전달
  - 접근 로그는 audit_logs에 저장

MITRE ATT&CK:
  T1083 — File and Directory Discovery (관리자 디렉터리 탐색)
  T1190 — Exploit Public-Facing Application
  T1595 — Active Scanning

엔드포인트 목록 (모두 숨김):
  GET  /api/v1/admin/config
  GET  /api/v1/admin/users
  POST /api/v1/admin/reset
  GET  /api/v1/debug/env
  GET  /api/v1/debug/vars
  GET  /api/v1/backup/download
  GET  /api/v1/.env
  GET  /api/v1/config.php
  POST /api/v1/api/user/login (모방 경로)
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Request, status
from fastapi.responses import JSONResponse

from app.config import get_settings
from app.redis_kv.client import get_redis

router = APIRouter(tags=["canary-api"])
log = logging.getLogger("infrared.canary_api")
settings = get_settings()


# ─────────────────────────────────────────────────────────────────────────────
# 공통 핸들러
# ─────────────────────────────────────────────────────────────────────────────

async def _trigger_canary(
    request: Request,
    endpoint_name: str,
    mitre_technique: str = "T1083",
) -> JSONResponse:
    """
    Canary API 접근 감지 — 공통 처리 로직.
    접근 즉시 Redis에 이벤트를 발행하고 그럴듯한 오류 응답을 반환.
    """
    # 요청자 정보 수집
    client_ip = (
        request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or (request.client.host if request.client else "unknown")
    )
    user_agent = request.headers.get("User-Agent", "")
    path = request.url.path
    method = request.method

    # 요청 본문 (최대 1KB)
    body_bytes = b""
    try:
        body_bytes = await request.body()
        body_bytes = body_bytes[:1024]
    except Exception:
        pass

    event_id = f"CANARY-{uuid.uuid4().hex[:12]}"

    log.warning(
        "canary_api_triggered rule=CANARY-API-001 event_id=%s "
        "endpoint=%s method=%s ip=%s ua=%s",
        event_id, endpoint_name, method, client_ip, user_agent[:100],
    )

    # Redis Stream에 이벤트 발행
    event: dict[str, Any] = {
        "event_id": event_id,
        "rule_id": "CANARY-API-001",
        "event_type": "canary_api_access",
        "mitre_technique": mitre_technique,
        "severity": "critical",
        "confidence": "1.0",
        "detected_at": datetime.now(timezone.utc).isoformat(),
        "client_ip": client_ip,
        "user_agent": user_agent[:200],
        "endpoint": endpoint_name,
        "method": method,
        "path": path,
        "body_preview": body_bytes[:256].decode("utf-8", errors="replace"),
        "description": (
            f"Canary API 접근 감지: {method} {path} from {client_ip}. "
            f"이 경로는 공격자 탐지용 미끼 엔드포인트입니다."
        ),
    }

    try:
        redis = get_redis()
        import json
        payload = {k: (v if isinstance(v, str) else json.dumps(v))
                   for k, v in event.items() if v is not None}
        await redis.xadd("infrared:events:canary", payload, maxlen=10_000)
    except Exception:
        log.exception("canary_api_redis_push_failed event_id=%s", event_id)

    # 공격자에게 그럴듯한 오류를 반환 (401 또는 403)
    # 실제 관리자 페이지처럼 보이게 하여 공격자가 계속 시도하도록 유도
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={
            "error": "authentication_required",
            "message": "Authentication credentials were not provided.",
            "code": 401,
        },
        headers={"WWW-Authenticate": "Bearer"},
    )


# ─────────────────────────────────────────────────────────────────────────────
# Canary 미끼 엔드포인트들 (모두 OpenAPI 문서에서 숨김)
# ─────────────────────────────────────────────────────────────────────────────

@router.api_route(
    "/admin/config",
    methods=["GET", "POST"],
    include_in_schema=False,
    status_code=status.HTTP_401_UNAUTHORIZED,
)
async def canary_admin_config(request: Request) -> JSONResponse:
    """[CANARY] 관리자 설정 미끼 — T1083"""
    return await _trigger_canary(request, "admin_config", "T1083")


@router.api_route(
    "/admin/users",
    methods=["GET", "POST"],
    include_in_schema=False,
    status_code=status.HTTP_401_UNAUTHORIZED,
)
async def canary_admin_users(request: Request) -> JSONResponse:
    """[CANARY] 관리자 사용자 목록 미끼 — T1083"""
    return await _trigger_canary(request, "admin_users", "T1083")


@router.api_route(
    "/admin/reset",
    methods=["GET", "POST"],
    include_in_schema=False,
    status_code=status.HTTP_401_UNAUTHORIZED,
)
async def canary_admin_reset(request: Request) -> JSONResponse:
    """[CANARY] 관리자 초기화 미끼 — T1190"""
    return await _trigger_canary(request, "admin_reset", "T1190")


@router.api_route(
    "/debug/env",
    methods=["GET"],
    include_in_schema=False,
    status_code=status.HTTP_401_UNAUTHORIZED,
)
async def canary_debug_env(request: Request) -> JSONResponse:
    """[CANARY] 환경변수 노출 미끼 — T1083"""
    return await _trigger_canary(request, "debug_env", "T1083")


@router.api_route(
    "/debug/vars",
    methods=["GET"],
    include_in_schema=False,
    status_code=status.HTTP_401_UNAUTHORIZED,
)
async def canary_debug_vars(request: Request) -> JSONResponse:
    """[CANARY] 변수 덤프 미끼 — T1083"""
    return await _trigger_canary(request, "debug_vars", "T1083")


@router.api_route(
    "/backup/download",
    methods=["GET", "POST"],
    include_in_schema=False,
    status_code=status.HTTP_401_UNAUTHORIZED,
)
async def canary_backup_download(request: Request) -> JSONResponse:
    """[CANARY] 백업 다운로드 미끼 — T1083"""
    return await _trigger_canary(request, "backup_download", "T1083")


@router.api_route(
    "/.env",
    methods=["GET"],
    include_in_schema=False,
    status_code=status.HTTP_401_UNAUTHORIZED,
)
async def canary_dotenv(request: Request) -> JSONResponse:
    """[CANARY] .env 파일 노출 미끼 — T1552.001"""
    return await _trigger_canary(request, "dotenv_exposure", "T1552.001")


@router.api_route(
    "/config.php",
    methods=["GET"],
    include_in_schema=False,
    status_code=status.HTTP_401_UNAUTHORIZED,
)
async def canary_config_php(request: Request) -> JSONResponse:
    """[CANARY] PHP 설정 파일 미끼 — T1190"""
    return await _trigger_canary(request, "config_php", "T1190")


@router.api_route(
    "/api/user/login",
    methods=["POST"],
    include_in_schema=False,
    status_code=status.HTTP_401_UNAUTHORIZED,
)
async def canary_api_user_login(request: Request) -> JSONResponse:
    """[CANARY] 일반 로그인 API 모방 미끼 — T1595"""
    return await _trigger_canary(request, "api_user_login", "T1595")


@router.api_route(
    "/wp-login.php",
    methods=["GET", "POST"],
    include_in_schema=False,
    status_code=status.HTTP_401_UNAUTHORIZED,
)
async def canary_wp_login(request: Request) -> JSONResponse:
    """[CANARY] WordPress 로그인 미끼 — T1190"""
    return await _trigger_canary(request, "wp_login", "T1190")


@router.api_route(
    "/actuator/env",
    methods=["GET"],
    include_in_schema=False,
    status_code=status.HTTP_401_UNAUTHORIZED,
)
async def canary_spring_actuator(request: Request) -> JSONResponse:
    """[CANARY] Spring Boot Actuator 미끼 — T1083"""
    return await _trigger_canary(request, "spring_actuator_env", "T1083")
