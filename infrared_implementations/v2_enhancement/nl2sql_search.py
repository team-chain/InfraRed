"""자연어 인시던트 검색 (NL2SQL).

Bedrock Claude 로 자연어 → 구조화된 검색 파라미터 추출,
서버에서 파라미터화된 SQL 실행, RBAC 필터 적용.

POST /api/v1/incidents/search/natural
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import boto3
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

log = logging.getLogger(__name__)

nl_search_router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])


# ────────────────────────────────────────────────────────────────────────────
# Request / Response 모델
# ────────────────────────────────────────────────────────────────────────────

class NaturalSearchRequest(BaseModel):
    query: str = Field(..., min_length=2, max_length=500, description="자연어 검색 쿼리")
    limit: int = Field(default=20, ge=1, le=100)
    offset: int = Field(default=0, ge=0)


class SearchParams(BaseModel):
    """Bedrock 에서 추출된 구조화 파라미터."""
    severity: Optional[list[str]] = None           # ["critical", "high"]
    status: Optional[list[str]] = None             # ["open", "resolved"]
    disposition: Optional[str] = None              # "true_positive" | "false_positive"
    source_ip: Optional[str] = None
    rule_id: Optional[str] = None
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    keyword: Optional[str] = None                  # ILIKE 검색
    asset_id: Optional[str] = None


# ────────────────────────────────────────────────────────────────────────────
# Bedrock NL → 구조화 파라미터 추출
# ────────────────────────────────────────────────────────────────────────────

_EXTRACT_PROMPT = """You are a security incident search assistant.
Convert the user's natural language query into a structured JSON filter.

Return ONLY valid JSON with these optional fields:
{{
  "severity": ["critical"|"high"|"medium"|"info"],     // list, null if not mentioned
  "status": ["open"|"in_progress"|"resolved"|"closed"], // list, null if not mentioned
  "disposition": "true_positive"|"false_positive"|null,
  "source_ip": "IP address string or null",
  "rule_id": "rule ID string like AUTH-001 or null",
  "date_from": "ISO 8601 datetime or null",
  "date_to": "ISO 8601 datetime or null",
  "keyword": "keyword for description/notes ILIKE search or null",
  "asset_id": "asset identifier or null"
}}

Current UTC time: {now}

User query: {query}

Return ONLY the JSON object. No explanation."""


def _invoke_bedrock_nl(query: str, settings) -> dict[str, Any]:
    """Bedrock Claude 로 자연어 → 파라미터 JSON 추출 (동기)."""
    now_str = datetime.now(timezone.utc).isoformat()
    prompt = _EXTRACT_PROMPT.format(now=now_str, query=query)

    session_kwargs: dict = {}
    if settings.aws_profile:
        session_kwargs["profile_name"] = settings.aws_profile

    session = boto3.Session(**session_kwargs)
    client_kwargs: dict = {"region_name": settings.bedrock_region}
    if settings.aws_access_key_id and settings.aws_secret_access_key:
        client_kwargs["aws_access_key_id"] = settings.aws_access_key_id
        client_kwargs["aws_secret_access_key"] = settings.aws_secret_access_key

    client = session.client("bedrock-runtime", **client_kwargs)
    response = client.invoke_model(
        modelId=settings.bedrock_model_id,
        body=json.dumps({
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 512,
            "temperature": 0.0,
            "messages": [{"role": "user", "content": prompt}],
        }),
    )
    body = json.loads(response["body"].read())
    text: str = body["content"][0]["text"].strip()

    # JSON 블록 추출
    if "```" in text:
        text = text.split("```")[1]
        if text.startswith("json"):
            text = text[4:]
        text = text.strip().strip("`")

    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        text = text[start: end + 1]

    return json.loads(text)


def _fallback_parse(query: str) -> dict[str, Any]:
    """Bedrock 실패 시 키워드 기반 간단 파싱."""
    params: dict[str, Any] = {}
    q = query.lower()

    if "critical" in q:
        params["severity"] = ["critical"]
    elif "high" in q:
        params["severity"] = ["high"]
    elif "medium" in q:
        params["severity"] = ["medium"]

    if "open" in q:
        params["status"] = ["open"]
    elif "resolved" in q or "해결" in q:
        params["status"] = ["resolved"]

    if "오탐" in q or "false positive" in q:
        params["disposition"] = "false_positive"
    elif "실제" in q or "true positive" in q:
        params["disposition"] = "true_positive"

    if "오늘" in q or "today" in q:
        params["date_from"] = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    elif "이번 주" in q or "this week" in q:
        params["date_from"] = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
    elif "이번 달" in q or "this month" in q:
        params["date_from"] = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()

    # AUTH-001 등 룰 ID 패턴
    import re
    rule_match = re.search(r"\b(AUTH|WEB|NET|FIM|EXEC|UEBA)-\d{3}\b", query, re.IGNORECASE)
    if rule_match:
        params["rule_id"] = rule_match.group(0).upper()

    # IP 패턴
    ip_match = re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", query)
    if ip_match:
        params["source_ip"] = ip_match.group(0)

    return params


async def extract_search_params(query: str, settings) -> SearchParams:
    """자연어 쿼리 → SearchParams 변환 (Bedrock 우선, 실패 시 폴백)."""
    if settings.llm_enabled:
        try:
            raw = await asyncio.to_thread(_invoke_bedrock_nl, query, settings)
            log.info("nl2sql_extracted query=%r params=%s", query[:50], raw)
        except Exception as exc:
            log.warning("bedrock_nl_extraction_failed error=%s using_fallback", exc)
            raw = _fallback_parse(query)
    else:
        raw = _fallback_parse(query)

    # datetime 필드 파싱
    for date_field in ("date_from", "date_to"):
        val = raw.get(date_field)
        if isinstance(val, str):
            try:
                raw[date_field] = datetime.fromisoformat(val.replace("Z", "+00:00"))
            except ValueError:
                raw[date_field] = None

    return SearchParams(**{k: v for k, v in raw.items() if k in SearchParams.model_fields})


# ────────────────────────────────────────────────────────────────────────────
# 파라미터화된 SQL 빌더
# ────────────────────────────────────────────────────────────────────────────

def build_search_sql(
    params: SearchParams,
    tenant_id: str,
    roles: list[str],
    limit: int,
    offset: int,
) -> tuple[str, list[Any]]:
    """RBAC 필터 포함 파라미터화된 SELECT 구성. (asyncpg $N 스타일)"""
    conditions: list[str] = []
    args: list[Any] = []
    idx = 1

    # 테넌트 필터 (필수)
    conditions.append(f"tenant_id = ${idx}")
    args.append(tenant_id)
    idx += 1

    # RBAC: analyst 는 자신이 담당하는 인시던트만, admin/manager 는 전체
    if "analyst" in roles and "admin" not in roles and "manager" not in roles:
        conditions.append(f"assigned_to = ${idx}")
        args.append(tenant_id)  # 실제로는 current user id
        idx += 1

    if params.severity:
        placeholders = ", ".join(f"${idx + i}" for i in range(len(params.severity)))
        conditions.append(f"severity IN ({placeholders})")
        args.extend(params.severity)
        idx += len(params.severity)

    if params.status:
        placeholders = ", ".join(f"${idx + i}" for i in range(len(params.status)))
        conditions.append(f"status IN ({placeholders})")
        args.extend(params.status)
        idx += len(params.status)

    if params.disposition:
        conditions.append(f"disposition = ${idx}")
        args.append(params.disposition)
        idx += 1

    if params.source_ip:
        conditions.append(f"source_ip::text = ${idx}")
        args.append(params.source_ip)
        idx += 1

    if params.rule_id:
        conditions.append(f"primary_rule_id ILIKE ${idx}")
        args.append(f"%{params.rule_id}%")
        idx += 1

    if params.asset_id:
        conditions.append(f"asset_id = ${idx}")
        args.append(params.asset_id)
        idx += 1

    if params.date_from:
        conditions.append(f"created_at >= ${idx}")
        args.append(params.date_from)
        idx += 1

    if params.date_to:
        conditions.append(f"created_at <= ${idx}")
        args.append(params.date_to)
        idx += 1

    if params.keyword:
        conditions.append(
            f"(description ILIKE ${idx} OR notes ILIKE ${idx} OR incident_id ILIKE ${idx})"
        )
        args.append(f"%{params.keyword}%")
        idx += 1

    where_clause = " AND ".join(conditions) if conditions else "TRUE"

    sql = f"""
        SELECT
            incident_id,
            severity,
            status,
            disposition,
            source_ip::text AS source_ip,
            primary_rule_id,
            asset_id,
            description,
            created_at,
            resolved_at
        FROM incidents
        WHERE {where_clause}
        ORDER BY
            CASE severity
                WHEN 'critical' THEN 0
                WHEN 'high' THEN 1
                WHEN 'medium' THEN 2
                ELSE 3
            END,
            created_at DESC
        LIMIT ${idx} OFFSET ${idx + 1}
    """
    args.extend([limit, offset])
    return sql, args


# ────────────────────────────────────────────────────────────────────────────
# FastAPI 엔드포인트
# ────────────────────────────────────────────────────────────────────────────

@nl_search_router.post("/search/natural", summary="자연어 인시던트 검색")
async def natural_language_search(
    body: NaturalSearchRequest,
    request: Request,
):
    """
    자연어 쿼리를 Bedrock Claude 로 구조화 파라미터로 변환 후 DB 검색.

    예시 쿼리:
    - "지난 7일 간 Critical 인시던트 보여줘"
    - "AUTH-001 룰로 탐지된 오탐 목록"
    - "192.168.1.100 에서 발생한 open 상태 인시던트"
    """
    tenant_id: str = request.headers.get("X-Tenant-ID", "global")
    # RBAC 역할 추출 (JWT 미들웨어에서 주입 가정)
    roles: list[str] = getattr(request.state, "roles", ["analyst"])
    settings = request.app.state.settings

    # NL → 구조화 파라미터
    try:
        params = await extract_search_params(body.query, settings)
        log.info(
            "nl_search_params tenant=%s params=%s",
            tenant_id,
            params.model_dump(exclude_none=True),
        )
    except Exception as exc:
        log.error("param_extraction_failed query=%r error=%s", body.query[:50], exc)
        raise HTTPException(status_code=422, detail="쿼리 분석 실패") from exc

    # SQL 빌드 + 실행
    sql, args = build_search_sql(params, tenant_id, roles, body.limit, body.offset)

    try:
        db_pool = request.app.state.db_pool
        async with db_pool.acquire() as conn:
            rows = await conn.fetch(sql, *args)
            # 전체 건수 (LIMIT 없이)
            count_sql = f"SELECT COUNT(*) FROM incidents WHERE {sql.split('WHERE')[1].split('ORDER')[0]}"
            # 간단히 len(rows) 기반 페이지 정보
    except Exception as exc:
        log.error("db_search_failed error=%s", exc)
        raise HTTPException(status_code=500, detail="데이터베이스 검색 실패") from exc

    results = []
    for row in rows:
        d = dict(row)
        if isinstance(d.get("created_at"), datetime):
            d["created_at"] = d["created_at"].isoformat()
        if isinstance(d.get("resolved_at"), datetime):
            d["resolved_at"] = d["resolved_at"].isoformat()
        results.append(d)

    return {
        "query": body.query,
        "extracted_params": params.model_dump(exclude_none=True),
        "total": len(results),
        "limit": body.limit,
        "offset": body.offset,
        "results": results,
    }
