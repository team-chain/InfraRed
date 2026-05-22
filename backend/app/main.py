"""InfraRed FastAPI application."""
# ruff: noqa: I001
# (Import block grouped by router version/role, not strict alphabetical — intentional.)
from __future__ import annotations

import hmac
import os
import secrets as _secrets

from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import CONTENT_TYPE_LATEST, Counter, generate_latest
from pydantic import BaseModel
from sqlalchemy import text as _text
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

# v4.0 엔터프라이즈 인증 라우터 (SSO/MFA)
from app.auth.routes import router as auth_enterprise_router
from app.auth.verification_routes import (
    _send_verification_email,
    router as auth_verification_router,
)
from app.db.connection import get_session as _get_session

# v4.0 Stripe 과금 라우터
from app.billing.routes import router as billing_router
from app.common.logging import configure_logging, get_logger
from app.config import get_settings
from app.db.repositories import (
    authenticate_user,
    get_incident_contract,
    list_detection_rules,
    list_incidents,
    register_user,
    save_llm_result,
    update_incident_status,
)
from app.dispatcher.service import dispatch_incident_alert
from app.iam.audit import write_audit_log
from app.iam.security import create_token, require_permission, verify_user_token
from app.middleware.rate_limit import (
    limit_login,
    limit_register,
    limit_revoke_all,
)
from app.ingestion.agent_mgmt_routes import router as agent_mgmt_router
from app.ingestion.api_routes import router as api_router
from app.ingestion.asset_criticality_routes import router as asset_criticality_router
from app.ingestion.audit_routes import router as audit_router
from app.ingestion.block_approval_routes import router as block_approval_router

# v7.0 Break-Glass·Dead Man's Switch 라우터
from app.ingestion.breakglass_routes import router as breakglass_router
from app.ingestion.campaign_routes import router as campaign_router

# v8.0 Canary API Route (미끼 엔드포인트 — 공격자 탐지용)
from app.ingestion.canary_api_routes import router as canary_api_router
from app.ingestion.canary_pack_routes import router as canary_pack_router

# v6.0 CIS Benchmark 라우터
from app.ingestion.cis_routes import router as cis_router
from app.ingestion.command_routes import router as command_router

# v6.0 운영 품질·보안 KPI 라우터
from app.ingestion.compliance_routes import router as compliance_router
from app.ingestion.container_routes import router as container_router

# v3.0 CTI 수동 조회 라우터
from app.ingestion.cti_routes import router as cti_router
from app.ingestion.deadman_routes import router as deadman_router

# v3.0 Debug / 재생 라우터 (dev/staging 전용)
from app.ingestion.debug_routes import router as debug_router
from app.ingestion.deception_routes import router as deception_router
from app.ingestion.enterprise_routes import router as enterprise_router

# v4.0 Falco/eBPF 연동 라우터
from app.ingestion.falco_routes import router as falco_router

# v8.0 신규 라우터
from app.ingestion.first_exec_routes import router as first_exec_router
from app.ingestion.fluent_routes import router as fluent_router

# v5.0 포렌식·취약점 스캐너 라우터
from app.ingestion.forensic_routes import router as forensic_router

# v7 GDPR 삭제 충돌 해결 라우터
from app.ingestion.gdpr_routes import router as gdpr_router
from app.ingestion.health_routes import router as health_router
from app.ingestion.install_routes import router as install_router
from app.ingestion.ops_metrics_routes import router as ops_metrics_router
from app.ingestion.status_routes import router as status_router
from app.ingestion.honey_key_routes import router as honey_key_router

# Phase 1~5 고도화 라우터
from app.ingestion.incident_routes import router as incident_workflow_router

# v4.0 Integration Hub 테스트 라우터
from app.ingestion.integrations_routes import router as integrations_router
from app.ingestion.jit_ssh_routes import router as jit_ssh_router
from app.ingestion.kpi_routes import router as kpi_router

# v7.0 Zeek/Suricata 네트워크 센서 연동 라우터
from app.ingestion.network_sensor_routes import router as network_sensor_router
from app.ingestion.policy_routes import router as policy_router
from app.ingestion.routes import router as ingestion_router
from app.ingestion.rule_mgmt_routes import router as rule_mgmt_router
from app.ingestion.settings_routes import router as settings_router

# v4.0 SIGMA 룰 관리 라우터
from app.ingestion.sigma_routes import router as sigma_router
from app.ingestion.sse_routes import router as sse_router

# v6.0 SSL 인증서 모니터링 라우터
from app.ingestion.ssl_routes import router as ssl_router
from app.ingestion.suppression_routes import router as suppression_router

# v3.0 신규 라우터
from app.ingestion.tamper_routes import router as tamper_router

# v4.0 UEBA 행동 분석 라우터
from app.ingestion.ueba_routes import router as ueba_router
from app.ingestion.user_routes import router as user_router
from app.ingestion.vuln_routes import router as vuln_router
from app.ingestion.web_routes import router as web_router

# v7.0 mTLS 미들웨어
from app.middleware.mtls import MTLSMiddleware
from app.models.auth import (
    LoginRequest,
    RegisterRequest,
    StatusUpdateRequest,
    TokenResponse,
)
from app.models.llm import LLMResult
from app.redis_kv import keys as redis_keys
from app.redis_kv.client import get_redis
from app.workers.llm.service import analyze_contract_with_cache

configure_logging()
settings = get_settings()
log = get_logger(__name__)

# ── Sentry 초기화 (DSN 없으면 no-op) ────────────────────────────────────
if settings.sentry_dsn:
    try:
        import sentry_sdk
        from sentry_sdk.integrations.asyncio import AsyncioIntegration
        from sentry_sdk.integrations.fastapi import FastApiIntegration
        from sentry_sdk.integrations.starlette import StarletteIntegration

        sentry_sdk.init(
            dsn=settings.sentry_dsn,
            environment=settings.sentry_environment or settings.env,
            traces_sample_rate=settings.sentry_traces_sample_rate,
            profiles_sample_rate=settings.sentry_profiles_sample_rate,
            send_default_pii=False,  # PII 보호 — 보안 제품이라 더욱 중요
            integrations=[
                StarletteIntegration(transaction_style="endpoint"),
                FastApiIntegration(transaction_style="endpoint"),
                AsyncioIntegration(),
            ],
            release=os.getenv("GIT_SHA", "dev"),
        )
        log.info("sentry_initialized", environment=settings.sentry_environment or settings.env)
    except Exception as exc:  # noqa: BLE001
        log.warning("sentry_init_failed", error=str(exc))

_TAGS_METADATA = [
    {"name": "auth",               "description": "로그인 / 가입 / JWT / 토큰 revoke"},
    {"name": "auth-verification",  "description": "이메일 인증 + 비밀번호 재설정"},
    {"name": "users",              "description": "RBAC 멤버십, 초대, 온보딩"},
    {"name": "incidents",          "description": "인시던트 조회 / 상태 변경 / 코멘트 / 링크"},
    {"name": "rules",              "description": "탐지 룰 목록 / 관리 / 임계값 조정"},
    {"name": "containers",         "description": "컨테이너 격리/해제 명령 (owner only)"},
    {"name": "agents",             "description": "에이전트 등록 / heartbeat / 명령 polling"},
    {"name": "alerts",             "description": "Discord/Slack/Email 알림 설정"},
    {"name": "billing",            "description": "Stripe 구독 / 인보이스 / 플랜"},
    {"name": "compliance",         "description": "정기 보고서 / KPI / 감사 로그"},
    {"name": "deception",          "description": "HoneyKey / CanaryPack / 미끼 자산"},
    {"name": "jit-ssh",            "description": "Just-in-time SSH 키 발급/만료"},
]

app = FastAPI(
    title="InfraRed API",
    version="1.0.0",
    summary="Multi-tenant SOC platform — detection + automatic response",
    description=(
        "**InfraRed** is a hosted SOC for Linux/Container infrastructure.\n\n"
        "- Real-time SSH/Web attack detection (28 production rules)\n"
        "- Automatic iptables IP block within ~10s for high-confidence threats\n"
        "- MITRE ATT&CK attack-chain correlation\n"
        "- AI incident summarization (Bedrock Claude with static fallback)\n"
        "- Discord / Slack / Email alerts\n\n"
        "Authentication: Bearer JWT from `/auth/login`. Most endpoints are RBAC-scoped to a tenant."
    ),
    contact={"name": "InfraRed", "url": "https://infrared.kr"},
    license_info={"name": "Source-available, contact for production use"},
    openapi_tags=_TAGS_METADATA,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# v7.0: mTLS 클라이언트 인증서 검증 미들웨어
# 프로덕션에서 MTLS_ENABLED=true + Nginx ssl_verify_client on 설정 필요
app.add_middleware(
    MTLSMiddleware,
    mtls_enabled=settings.mtls_enabled,
    require_agent_cn=settings.mtls_require_agent_cn,
)

REQUEST_COUNT = Counter(
    "infrared_http_requests_total",
    "Total HTTP requests",
    ["method", "path", "status"],
)

_DENYLIST_EXEMPT_PREFIXES = ("/healthz", "/metrics", "/auth/", "/sdk.js", "/status/")


@app.middleware("http")
async def denylist_middleware(request: Request, call_next):
    """Redis Denylist IP 체크 -> 차단된 IP는 즉시 403 반환."""
    path = request.url.path
    if not any(path.startswith(p) for p in _DENYLIST_EXEMPT_PREFIXES):
        client_ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or (
            request.client.host if request.client else None
        )
        if client_ip:
            try:
                redis = get_redis()
                tenant_id = settings.tenant_id
                is_blocked = await redis.sismember(redis_keys.policy_denylist(tenant_id), client_ip)
                if is_blocked:
                    log.info("denylist_blocked", ip=client_ip, path=path)
                    return JSONResponse(
                        status_code=403,
                        content={
                            "detail": "blocked",
                            "message": "이 IP는 보안 정책에 의해 차단되었습니다.",
                            "ip": client_ip,
                        },
                    )
            except Exception as exc:
                log.warning("denylist_check_failed", error=str(exc))

    response = await call_next(request)
    return response


@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    response = await call_next(request)
    REQUEST_COUNT.labels(request.method, request.url.path, str(response.status_code)).inc()
    return response


app.include_router(ingestion_router)
app.include_router(web_router)
app.include_router(policy_router)
app.include_router(fluent_router)
app.include_router(api_router)
app.include_router(command_router, prefix="/ingest")
app.include_router(container_router)
app.include_router(settings_router)
app.include_router(sse_router)
# Phase 1~5 고도화 라우터
app.include_router(incident_workflow_router)
app.include_router(health_router)
app.include_router(install_router)  # 인증 없는 public — install-agent.sh + agent-source.tar.gz
app.include_router(status_router)
app.include_router(ops_metrics_router)
app.include_router(rule_mgmt_router)
app.include_router(suppression_router)
app.include_router(user_router)
app.include_router(agent_mgmt_router)
app.include_router(enterprise_router)
# v3.0 신규 라우터
app.include_router(tamper_router)
app.include_router(block_approval_router)
app.include_router(campaign_router)
app.include_router(asset_criticality_router)
app.include_router(audit_router)
# v3.0 CTI 수동 조회
app.include_router(cti_router)
# v3.0 Debug / replay-events (dev/staging 전용)
app.include_router(debug_router)
# v4.0 Falco/eBPF 연동 라우터
app.include_router(falco_router, prefix="/api/v1")
app.include_router(network_sensor_router, prefix="/api/v1")
app.include_router(canary_api_router, prefix="/api/v1")  # v8.0 Canary API (숨김)
# v4.0 엔터프라이즈 인증 (SSO/MFA)
app.include_router(auth_enterprise_router)
app.include_router(auth_verification_router)
# v4.0 Stripe 과금
app.include_router(billing_router)
# v4.0 UEBA 행동 분석
app.include_router(ueba_router)
# v4.0 Integration Hub 테스트 (Slack/PagerDuty/Jira/Splunk)
app.include_router(integrations_router)
# v4.0 SIGMA 룰 관리
app.include_router(sigma_router)
app.include_router(gdpr_router, prefix="/api/v1")
# v8.0 신규 라우터
app.include_router(first_exec_router)    # EXEC-FIRST-001/002 binary hash API
app.include_router(honey_key_router)     # DECEPTION-003 AWS Honey Key API
app.include_router(jit_ssh_router)       # JIT SSH API
app.include_router(canary_pack_router)   # Canary Pack 배포 관리 API
# v5.0 포렌식·취약점 스캐너 라우터
app.include_router(forensic_router)
app.include_router(vuln_router)
# v6.0 운영 품질·보안 KPI 라우터
app.include_router(compliance_router)
app.include_router(kpi_router)
app.include_router(deception_router)
# v6.0 CIS Benchmark 라우터
app.include_router(cis_router)
# v6.0 SSL 인증서 모니터링 라우터
app.include_router(ssl_router)
# v7.0 Break-Glass·Dead Man's Switch 라우터
app.include_router(breakglass_router)
app.include_router(deadman_router)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok", "env": settings.env}


@app.get("/metrics")
async def metrics(request: Request) -> Response:
    bearer_token = settings.prometheus_bearer_token
    if bearer_token:
        auth_header = request.headers.get("Authorization", "")
        if not hmac.compare_digest(auth_header, f"Bearer {bearer_token}"):
            return Response(status_code=401)
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.post("/auth/login", response_model=TokenResponse)
async def login(
    payload: LoginRequest,
    request: Request,
    _rate: None = Depends(limit_login),
) -> Response:
    user = await authenticate_user(
        tenant_id=payload.tenant_id,
        email=payload.email,
        password=payload.password,
    )
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid_credentials")

    await write_audit_log(
        tenant_id=user["tenant_id"],
        actor=user["email"],
        action="auth.login",
        resource="user",
        ip=request.client.host if request.client else None,
        metadata={"role": user["role"]},
    )
    token = create_token(subject=user["user_id"], tenant_id=user["tenant_id"], role=user["role"])
    response = JSONResponse(content={"access_token": token, "user": user})
    response.set_cookie(
        key="infrared_token", value=token, httponly=True,
        secure=(settings.env == "prod"), samesite="lax",
        max_age=settings.jwt_user_ttl_seconds, path="/",
    )
    return response


@app.post("/auth/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(
    payload: RegisterRequest,
    request: Request,
    _rate: None = Depends(limit_register),
) -> Response:
    user = await register_user(
        tenant_id=payload.tenant_id,
        email=payload.email,
        password=payload.password,
        role=payload.role,
    )
    if user is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="tenant_missing_or_user_exists")

    # 가입 직후 이메일 인증 토큰 자동 발급 + 메일 발송 (best-effort)
    try:
        verification_token = _secrets.token_urlsafe(32)
        async with _get_session() as _session:
            await _session.execute(
                _text(
                    "UPDATE users SET verification_token = :t, verification_sent_at = NOW() "
                    "WHERE user_id = :uid::uuid"
                ),
                {"t": verification_token, "uid": user["user_id"]},
            )
            await _session.commit()
        await _send_verification_email(user["email"], verification_token, user["tenant_id"])
    except Exception as _exc:  # noqa: BLE001
        log.warning("post_register_verification_failed", error=str(_exc))

    await write_audit_log(
        tenant_id=user["tenant_id"],
        actor=user["email"],
        action="auth.register",
        resource="user",
        ip=request.client.host if request.client else None,
        metadata={"role": user["role"]},
    )
    token = create_token(subject=user["user_id"], tenant_id=user["tenant_id"], role=user["role"])
    response = JSONResponse(content={"access_token": token, "user": user}, status_code=status.HTTP_201_CREATED)
    response.set_cookie(
        key="infrared_token", value=token, httponly=True,
        secure=(settings.env == "prod"), samesite="lax",
        max_age=settings.jwt_user_ttl_seconds, path="/",
    )
    return response


@app.post("/auth/logout")
async def logout(claims: dict = Depends(verify_user_token)) -> Response:
    """로그아웃 — 쿠키 삭제 + 현재 토큰의 jti를 revoke (재사용 방지)."""
    import time

    from app.iam.token_revocation import revoke_jti
    jti = claims.get("jti")
    exp = int(claims.get("exp", 0))
    if jti and exp:
        ttl = max(0, exp - int(time.time()))
        if ttl > 0:
            try:
                await revoke_jti(str(jti), ttl)
            except Exception as exc:  # noqa: BLE001
                log.warning("logout_revoke_failed", error=str(exc))
    response = JSONResponse(content={"ok": True})
    response.delete_cookie(key="infrared_token", path="/")
    return response


@app.get("/auth/me")
async def me(claims: dict = Depends(verify_user_token)) -> dict[str, object]:
    return {"subject": claims.get("sub"), "tenant_id": claims.get("tenant_id"), "role": claims.get("role")}


class RevokeTokenRequest(BaseModel):
    """현재 사용자의 모든 토큰 revoke (기본) 또는 다른 사용자(admin/owner만)."""
    target_user_id: str | None = None  # 비우면 본인. 채우면 owner role 필요.


@app.post("/auth/revoke-all")
async def revoke_all_user_tokens(
    payload: RevokeTokenRequest,
    claims: dict = Depends(verify_user_token),
    _rate: None = Depends(limit_revoke_all),
) -> dict[str, object]:
    """사용자의 모든 활성 토큰 무효화 (이후 발급된 토큰은 영향 없음).

    본인은 항상 가능. 타인 토큰은 owner만 가능.
    """
    from app.iam.token_revocation import revoke_user_tokens
    actor_id = str(claims.get("sub", ""))
    target_id = payload.target_user_id or actor_id

    if target_id != actor_id and claims.get("role") != "owner":
        raise HTTPException(status_code=403, detail="owner_required_to_revoke_others")

    revoked_at = await revoke_user_tokens(target_id)
    await write_audit_log(
        tenant_id=str(claims.get("tenant_id", "")),
        actor=actor_id,
        action="auth.revoke_all",
        resource=target_id,
        metadata={"revoked_at": revoked_at},
    )
    return {"revoked_at": revoked_at, "user_id": target_id}


@app.get("/incidents")
async def incidents(
    tenant_id: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    claims: dict = Depends(require_permission("incident:read")),
) -> dict[str, object]:
    requested_tenant = tenant_id or claims["tenant_id"]
    if requested_tenant != claims["tenant_id"]:
        raise HTTPException(status_code=403, detail="tenant_mismatch")
    return {"items": await list_incidents(tenant_id=requested_tenant, limit=limit)}


@app.get("/incidents/{incident_id}")
async def incident_contract(
    incident_id: str,
    claims: dict = Depends(require_permission("incident:read")),
) -> dict[str, object]:
    contract = await get_incident_contract(incident_id)
    if contract is None:
        raise HTTPException(status_code=404, detail="incident_not_found")
    if contract["incident"]["tenant_id"] != claims["tenant_id"]:
        raise HTTPException(status_code=403, detail="tenant_mismatch")
    return contract


@app.post("/incidents/{incident_id}/analyze", response_model=LLMResult)
async def analyze_incident(
    incident_id: str,
    request: Request,
    refresh: bool = Query(default=False),
    claims: dict = Depends(require_permission("incident:write")),
) -> LLMResult:
    contract = await get_incident_contract(incident_id)
    if contract is None:
        raise HTTPException(status_code=404, detail="incident_not_found")
    if contract["incident"]["tenant_id"] != claims["tenant_id"]:
        raise HTTPException(status_code=403, detail="tenant_mismatch")
    result = await analyze_contract_with_cache(contract, refresh=refresh)
    await save_llm_result(result, tenant_id=claims["tenant_id"])
    await write_audit_log(
        tenant_id=claims["tenant_id"], actor=str(claims["sub"]),
        action="incident.analyze", resource=incident_id,
        ip=request.client.host if request.client else None,
        metadata={"cached": result.cached, "model": result.model},
    )
    return result


@app.post("/incidents/{incident_id}/dispatch")
async def dispatch_incident(
    incident_id: str,
    request: Request,
    claims: dict = Depends(require_permission("incident:write")),
) -> dict[str, bool]:
    contract = await get_incident_contract(incident_id)
    if contract is None:
        raise HTTPException(status_code=404, detail="incident_not_found")
    if contract["incident"]["tenant_id"] != claims["tenant_id"]:
        raise HTTPException(status_code=403, detail="tenant_mismatch")
    llm_row = contract.get("llm_result")
    result = LLMResult.model_validate(llm_row) if llm_row else await analyze_contract_with_cache(contract)
    if not llm_row:
        await save_llm_result(result, tenant_id=claims["tenant_id"])
    dispatch_result = await dispatch_incident_alert(
        claims["tenant_id"], result,
        severity=contract["incident"].get("severity", "high"),
    )
    await write_audit_log(
        tenant_id=claims["tenant_id"], actor=str(claims["sub"]),
        action="incident.dispatch", resource=incident_id,
        ip=request.client.host if request.client else None,
        metadata={
            "model": result.model,
            "discord_sent": dispatch_result.discord_sent,
            "email_sent": dispatch_result.email_sent,
            "errors": list(dispatch_result.errors),
        },
    )
    return {
        "dispatched": dispatch_result.dispatched,
        "discord_sent": dispatch_result.discord_sent,
        "email_sent": dispatch_result.email_sent,
    }


@app.patch("/incidents/{incident_id}/status")
async def patch_incident_status(
    incident_id: str,
    payload: StatusUpdateRequest,
    request: Request,
    claims: dict = Depends(require_permission("incident:write")),
) -> dict[str, object]:
    updated = await update_incident_status(
        tenant_id=claims["tenant_id"],
        incident_id=incident_id,
        status=payload.status,
    )
    if updated is None:
        raise HTTPException(status_code=404, detail="incident_not_found")
    await write_audit_log(
        tenant_id=claims["tenant_id"], actor=str(claims["sub"]),
        action="incident.status_update", resource=incident_id,
        ip=request.client.host if request.client else None,
        metadata={"status": payload.status},
    )
    return {"incident": updated}


@app.get("/detection-rules")
async def detection_rules(
    claims: dict = Depends(require_permission("rule:read")),
) -> dict[str, object]:
    rules = await list_detection_rules(claims["tenant_id"])
    return {"rules": rules}
