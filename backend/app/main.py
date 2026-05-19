"""InfraRed FastAPI application."""
from __future__ import annotations

import hmac
import os

from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import CONTENT_TYPE_LATEST, Counter, generate_latest
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response

from app.common.logging import configure_logging, get_logger
from app.config import get_settings
from app.redis_kv import keys as redis_keys
from app.redis_kv.client import get_redis
from app.db.repositories import (
    authenticate_user,
    get_incident_contract,
    list_assets,
    list_audit_logs,
    list_detection_rules,
    list_incidents,
    register_user,
    save_llm_result,
    update_incident_status,
)
from app.autoresponse.engine import rollback_denylist
from app.dispatcher.service import dispatch_incident_alert
from app.iam.audit import write_audit_log
from app.iam.security import create_token, require_permission, verify_user_token
from app.ingestion.routes import router as ingestion_router
from app.ingestion.web_routes import router as web_router
from app.ingestion.fluent_routes import router as fluent_router
from app.ingestion.api_routes import router as api_router
from app.ingestion.command_routes import router as command_router
from app.ingestion.settings_routes import router as settings_router
from app.ingestion.policy_routes import router as policy_router
from app.ingestion.sse_routes import router as sse_router
# Phase 1~5 고도화 라우터
from app.ingestion.incident_routes import router as incident_workflow_router
from app.ingestion.health_routes import router as health_router
from app.ingestion.rule_mgmt_routes import router as rule_mgmt_router
from app.ingestion.suppression_routes import router as suppression_router
from app.ingestion.user_routes import router as user_router
from app.ingestion.agent_mgmt_routes import router as agent_mgmt_router
from app.ingestion.enterprise_routes import router as enterprise_router
# v3.0 신규 라우터
from app.ingestion.tamper_routes import router as tamper_router
from app.ingestion.block_approval_routes import router as block_approval_router
from app.ingestion.campaign_routes import router as campaign_router
from app.ingestion.asset_criticality_routes import router as asset_criticality_router
# v3.0 CTI 수동 조회 라우터
from app.ingestion.cti_routes import router as cti_router
# v3.0 Debug / 재생 라우터 (dev/staging 전용)
from app.ingestion.debug_routes import router as debug_router
# v4.0 Falco/eBPF 연동 라우터
from app.ingestion.falco_routes import router as falco_router
# v7.0 Zeek/Suricata 네트워크 센서 연동 라우터
from app.ingestion.network_sensor_routes import router as network_sensor_router
# v8.0 Canary API Route (미끼 엔드포인트 — 공격자 탐지용)
from app.ingestion.canary_api_routes import router as canary_api_router
# v4.0 엔터프라이즈 인증 라우터 (SSO/MFA)
from app.auth.routes import router as auth_enterprise_router
# v7.0 mTLS 미들웨어
from app.middleware.mtls import MTLSMiddleware
# v4.0 Stripe 과금 라우터
from app.billing.routes import router as billing_router
# v4.0 UEBA 행동 분석 라우터
from app.ingestion.ueba_routes import router as ueba_router
# v4.0 Integration Hub 테스트 라우터
from app.ingestion.integrations_routes import router as integrations_router
# v7 GDPR 삭제 충돌 해결 라우터
from app.ingestion.gdpr_routes import router as gdpr_router
# v4.0 SIGMA 룰 관리 라우터
from app.ingestion.sigma_routes import router as sigma_router
# v5.0 포렌식·취약점 스캐너 라우터
from app.ingestion.forensic_routes import router as forensic_router
from app.ingestion.vuln_routes import router as vuln_router
# v6.0 운영 품질·보안 KPI 라우터
from app.ingestion.compliance_routes import router as compliance_router
from app.ingestion.kpi_routes import router as kpi_router
from app.ingestion.deception_routes import router as deception_router
# v6.0 CIS Benchmark 라우터
from app.ingestion.cis_routes import router as cis_router
# v6.0 SSL 인증서 모니터링 라우터
from app.ingestion.ssl_routes import router as ssl_router
# v7.0 Break-Glass·Dead Man's Switch 라우터
from app.ingestion.breakglass_routes import router as breakglass_router
from app.ingestion.deadman_routes import router as deadman_router
# v8.0 신규 라우터
from app.ingestion.first_exec_routes import router as first_exec_router
from app.ingestion.honey_key_routes import router as honey_key_router
from app.ingestion.jit_ssh_routes import router as jit_ssh_router
from app.ingestion.canary_pack_routes import router as canary_pack_router
from app.models.auth import LoginRequest, RegisterRequest, StatusUpdateRequest, TokenResponse
from app.models.llm import LLMResult
from app.workers.llm.service import analyze_contract_with_cache


configure_logging()
settings = get_settings()
log = get_logger(__name__)

app = FastAPI(title="InfraRed API", version="0.1.0")
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

_DENYLIST_EXEMPT_PREFIXES = ("/healthz", "/metrics", "/auth/", "/sdk.js")


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
app.include_router(settings_router)
app.include_router(sse_router)
# Phase 1~5 고도화 라우터
app.include_router(incident_workflow_router)
app.include_router(health_router)
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
async def login(payload: LoginRequest, request: Request) -> Response:
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
async def register(payload: RegisterRequest, request: Request) -> Response:
    user = await register_user(
        tenant_id=payload.tenant_id,
        email=payload.email,
        password=payload.password,
        role=payload.role,
    )
    if user is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="tenant_missing_or_user_exists")

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
async def logout() -> Response:
    response = JSONResponse(content={"ok": True})
    response.delete_cookie(key="infrared_token", path="/")
    return response


@app.get("/auth/me")
async def me(claims: dict = Depends(verify_user_token)) -> dict[str, object]:
    return {"subject": claims.get("sub"), "tenant_id": claims.get("tenant_id"), "role": claims.get("role")}


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
    return {"items": await list_detection_rules(claims["tenant_id"])}


@app.get("/audit-logs")
async def audit_logs(
    limit: int = Query(default=100, ge=1, le=500),
    claims: dict = Depends(require_permission("audit:read")),
) -> dict[str, object]:
    return {"items": await list_audit_logs(claims["tenant_id"], limit=limit)}


@app.get("/assets")
async def assets(
    claims: dict = Depends(require_permission("incident:read")),
) -> dict[str, object]:
    return {"items": await list_assets(claims["tenant_id"])}


@app.delete("/policy/denylist/{ip}")
async def unblock_ip(
    ip: str,
    request: Request,
    claims: dict = Depends(require_permission("incident:write")),
) -> dict[str, object]:
    """DELETE /policy/denylist/{ip} -- IP 차단 롤백."""
    tenant_id = claims["tenant_id"]
    removed = await rollback_denylist(tenant_id, ip, actor=str(claims.get("sub", "unknown")))
    try:
        from sqlalchemy import text
        from app.db.connection import get_session
        from datetime import datetime, timezone
        async with get_session() as session:
            await session.execute(
                text("""
                    UPDATE auto_response_logs
                    SET reversed = true,
                        reversed_at = :ts,
                        reversed_by = :actor
                    WHERE tenant_id = :tenant_id
                      AND actions_taken::text LIKE :ip_pattern
                      AND reversed = false
                """),
                {
                    "tenant_id": tenant_id,
                    "ts": datetime.now(timezone.utc),
                    "actor": str(claims.get("sub", "unknown")),
                    "ip_pattern": f"%{ip}%",
                },
            )
            await session.commit()
    except Exception as exc:
        log.warning("unblock_ip_log_failed", ip=ip, error=str(exc))
    await write_audit_log(
        tenant_id=tenant_id,
        actor=str(claims.get("sub", "unknown")),
        action="policy.denylist.remove",
        resource=ip,
        ip=request.client.host if request.client else None,
        metadata={"ip_removed": ip, "was_in_denylist": removed},
    )
    return {"ok": True, "ip": ip, "removed": removed}


@app.get("/policy/denylist")
async def list_denylist(
    claims: dict = Depends(require_permission("incident:read")),
) -> dict[str, object]:
    tenant_id = claims["tenant_id"]
    redis = get_redis()
    ips = await redis.smembers(redis_keys.policy_denylist(tenant_id))
    return {"items": [ip.decode() if isinstance(ip, bytes) else ip for ip in ips]}


@app.get("/install-agent.sh", response_class=PlainTextResponse)
async def install_agent_script() -> PlainTextResponse:
    script_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "scripts", "install-agent.sh")
    )
    if not os.path.exists(script_path):
        raise HTTPException(status_code=404, detail="install script not found")
    with open(script_path, "r") as f:
        script_content = f.read()
    return PlainTextResponse(content=script_content, media_type="text/x-shellscript")
