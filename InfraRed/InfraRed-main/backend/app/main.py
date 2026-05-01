"""InfraRed FastAPI application."""
from __future__ import annotations

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import CONTENT_TYPE_LATEST, Counter, generate_latest
from starlette.requests import Request
from starlette.responses import Response

from app.common.logging import configure_logging, get_logger
from app.config import get_settings
from app.db.repositories import get_incident_contract, list_incidents
from app.ingestion.routes import router as ingestion_router


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


@app.get("/incidents")
async def incidents(
    tenant_id: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
) -> dict[str, object]:
    return {"items": await list_incidents(tenant_id=tenant_id or settings.tenant_id, limit=limit)}


@app.get("/incidents/{incident_id}")
async def incident_contract(incident_id: str) -> dict[str, object]:
    contract = await get_incident_contract(incident_id)
    if contract is None:
        raise HTTPException(status_code=404, detail="incident_not_found")
    return contract
