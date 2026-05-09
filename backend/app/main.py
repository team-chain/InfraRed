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

REQUEST_COUNT = Counter(
    "infrared_http_requests_total",
    "Total HTTP requests",
    ["method", "path", "status"],
)


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
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid_credentials",
        )

    await write_audit_log(
        tenant_id=user["tenant_id"],
        actor=user["email"],
        action="auth.login",
        resource="user",
        ip=request.client.host if request.client else None,
        metadata={"role": user["role"]},
    )
    token = create_token(
        subject=user["user_id"],
        tenant_id=user["tenant_id"],
        role=user["role"],
    )

    response = JSONResponse(
        content={"access_token": token, "user": user},
    )
    response.set_cookie(
        key="infrared_token",
        value=token,
        httponly=True,
        secure=(settings.env == "prod"),
        samesite="lax",
        max_age=settings.jwt_user_ttl_seconds,
        path="/",
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
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="tenant_missing_or_user_exists",
        )

    await write_audit_log(
        tenant_id=user["tenant_id"],
        actor=user["email"],
        action="auth.register",
        resource="user",
        ip=request.client.host if request.client else None,
        metadata={"role": user["role"]},
    )
    token = create_token(
        subject=user["user_id"],
        tenant_id=user["tenant_id"],
        role=user["role"],
    )

    response = JSONResponse(
        content={"access_token": token, "user": user},
        status_code=status.HTTP_201_CREATED,
    )
    response.set_cookie(
        key="infrared_token",
        value=token,
        httponly=True,
        secure=(settings.env == "prod"),
        samesite="lax",
        max_age=settings.jwt_user_ttl_seconds,
        path="/",
    )
    return response


@app.post("/auth/logout")
async def logout() -> Response:
    response = JSONResponse(content={"ok": True})
    response.delete_cookie(key="infrared_token", path="/")
    return response


@app.get("/auth/me")
async def me(claims: dict = Depends(verify_user_token)) -> dict[str, object]:
    return {
        "subject": claims.get("sub"),
        "tenant_id": claims.get("tenant_id"),
        "role": claims.get("role"),
    }


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
        tenant_id=claims["tenant_id"],
        actor=str(claims["sub"]),
        action="incident.analyze",
        resource=incident_id,
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
    result = (
        LLMResult.model_validate(llm_row)
        if llm_row
        else await analyze_contract_with_cache(contract)
    )
    if not llm_row:
        await save_llm_result(result, tenant_id=claims["tenant_id"])
    dispatch_result = await dispatch_incident_alert(
        claims["tenant_id"], result,
        severity=contract["incident"].get("severity", "high"),
    )
    await write_audit_log(
        tenant_id=claims["tenant_id"],
        actor=str(claims["sub"]),
        action="incident.dispatch",
        resource=incident_id,
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
        tenant_id=claims["tenant_id"],
        actor=str(claims["sub"]),
        action="incident.status_update",
        resource=incident_id,
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


@app.get("/install-agent.sh", response_class=PlainTextResponse)
async def install_agent_script() -> PlainTextResponse:
    """Serve the agent install script — users can pipe it directly from curl."""
    script_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "scripts", "install-agent.sh")
    )
    if not os.path.exists(script_path):
        raise HTTPException(status_code=404, detail="install script not found")
    with open(script_path, "r") as f:
        script_content = f.read()
    return PlainTextResponse(content=script_content, media_type="text/x-shellscript")
