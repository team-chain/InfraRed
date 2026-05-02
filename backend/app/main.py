"""InfraRed FastAPI application."""
from __future__ import annotations

from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import CONTENT_TYPE_LATEST, Counter, generate_latest
from starlette.requests import Request
from starlette.responses import Response

from app.common.logging import configure_logging, get_logger
from app.config import get_settings
from app.db.repositories import (
    authenticate_user,
    get_incident_contract,
    list_audit_logs,
    list_detection_rules,
    list_incidents,
    save_llm_result,
    update_incident_status,
)
from app.dispatcher.service import dispatch_incident_alert
from app.iam.audit import write_audit_log
from app.iam.security import create_token, require_permission, verify_user_token
from app.ingestion.routes import router as ingestion_router
from app.models.auth import LoginRequest, StatusUpdateRequest, TokenResponse
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


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok", "env": settings.env}


@app.get("/metrics")
async def metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.post("/auth/login", response_model=TokenResponse)
async def login(payload: LoginRequest, request: Request) -> TokenResponse:
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
    return TokenResponse(access_token=token, user=user)


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
    await dispatch_incident_alert(
        claims["tenant_id"], result,
        severity=contract["incident"].get("severity", "high"),
    )
    await write_audit_log(
        tenant_id=claims["tenant_id"],
        actor=str(claims["sub"]),
        action="incident.dispatch",
        resource=incident_id,
        ip=request.client.host if request.client else None,
        metadata={"model": result.model},
    )
    return {"dispatched": True}


@app.patch("/incidents/{incident_id}/status")
async def patch_incident_status(
    incident_id: str,
    payload: StatusUpdateRequest,
    request: Request,
    claims: dict = Depends(require_permission("incident:write")),
) -> dict[str, object]:
    allowed = {"open", "acknowledged", "resolved", "false_positive"}
    if payload.status not in allowed:
        raise HTTPException(status_code=422, detail=f"status must be one of {sorted(allowed)}")
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
