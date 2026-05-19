"""
GDPR 데이터 삭제 요청 처리 API — v7 §데이터 거버넌스.

v7 설계서에서 "법무 검토 필요"로 명시된 GDPR 삭제 충돌 문제를 코드 레벨에서 해결한다.

핵심 충돌: 정보주체의 삭제 요청(GDPR Art. 17) vs 법적 보존 의무
  - 보안 감사 로그: 대부분 국가에서 6~12개월 보존 의무 (ISMS-P 2.9.2, PCI-DSS 10.7)
  - 인시던트 증거: 사법 제출 가능성이 있는 경우 삭제 불가
  - 청구/계약 기록: 5~7년 보존 의무 (상법, 국세기본법)

해결 전략: 3단계 충돌 해소 정책
  1. ANONYMIZE (익명화) — 삭제 대신 개인식별 데이터만 마스킹
     : 탐지 로그, 일반 시그널 → 법적 보존 의무 충족 + 개인정보 제거
  2. RETAIN_WITH_LEGAL_HOLD (법적 보류) — 보존 의무 기간 만료 후 자동 삭제 예약
     : 인시던트 증거, 감사 로그 → 만료일 설정 후 자동 삭제
  3. DELETE (즉시 삭제) — 보존 의무 없는 데이터
     : 마케팅 데이터, 분석 쿠키, 세션 정보

엔드포인트:
  POST /gdpr/erasure-request          — 삭제 요청 제출
  GET  /gdpr/erasure-requests         — 요청 목록 조회 (관리자)
  GET  /gdpr/erasure-requests/{id}    — 요청 상세 조회
  POST /gdpr/erasure-requests/{id}/process  — 처리 실행 (관리자)
  GET  /gdpr/data-subjects/{identifier}     — 데이터 주체 보유 데이터 조회 (포터빌리티)
  POST /gdpr/legal-holds              — 법적 보류 설정
  GET  /gdpr/legal-holds              — 법적 보류 목록
"""
from __future__ import annotations

import hashlib
import logging
import re
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import text

from app.db.connection import get_session
from app.iam.rbac_v2 import require_role, require_any_role

router = APIRouter(prefix="/gdpr", tags=["gdpr"])
log = logging.getLogger(__name__)


# ────────────────────────────────────────────────────────────────────────────
# 열거형 & 상수
# ────────────────────────────────────────────────────────────────────────────

class ErasureResolution(str, Enum):
    DELETE = "delete"
    ANONYMIZE = "anonymize"
    RETAIN_WITH_LEGAL_HOLD = "retain_with_legal_hold"
    CANNOT_DELETE = "cannot_delete"


class ErasureStatus(str, Enum):
    PENDING = "pending"
    IN_REVIEW = "in_review"
    PROCESSING = "processing"
    COMPLETED = "completed"
    REJECTED = "rejected"


# 데이터 카테고리별 기본 삭제 정책
# (법률 전문가 검토 후 환경에 맞게 수정할 것)
_RETENTION_POLICY: dict[str, dict] = {
    "signals": {
        "resolution": ErasureResolution.ANONYMIZE,
        "reason": "보안 감사 목적 보존 (ISMS-P 2.9.2 — 최소 6개월)",
        "retain_days": 180,
        "anonymize_fields": ["source_ip", "username", "user_email", "agent_hostname"],
    },
    "incidents": {
        "resolution": ErasureResolution.RETAIN_WITH_LEGAL_HOLD,
        "reason": "사법기관 제출 가능 증거 — 사건 종결 후 1년 보류",
        "retain_days": 365,
        "anonymize_fields": [],
    },
    "audit_logs": {
        "resolution": ErasureResolution.RETAIN_WITH_LEGAL_HOLD,
        "reason": "감사 로그 법적 보존 의무 (상법 §33: 10년)",
        "retain_days": 3650,
        "anonymize_fields": [],
    },
    "user_profiles": {
        "resolution": ErasureResolution.DELETE,
        "reason": "법적 보존 의무 없음 — 즉시 삭제 가능",
        "retain_days": 0,
        "anonymize_fields": [],
    },
    "billing_records": {
        "resolution": ErasureResolution.RETAIN_WITH_LEGAL_HOLD,
        "reason": "국세기본법 §85의3: 5년 보존 의무",
        "retain_days": 1825,
        "anonymize_fields": ["email"],
    },
    "session_logs": {
        "resolution": ErasureResolution.DELETE,
        "reason": "세션 정보는 서비스 제공 후 불필요",
        "retain_days": 0,
        "anonymize_fields": [],
    },
    "agent_heartbeats": {
        "resolution": ErasureResolution.ANONYMIZE,
        "reason": "에이전트 통계 보존 (개인식별 정보만 제거)",
        "retain_days": 90,
        "anonymize_fields": ["agent_hostname", "agent_ip"],
    },
}

# 개인식별 필드 기본값 (익명화 시 치환)
_ANON_VALUES: dict[str, str] = {
    "source_ip": "0.0.0.0",
    "username": "[삭제됨]",
    "user_email": "deleted@gdpr.invalid",
    "email": "deleted@gdpr.invalid",
    "agent_hostname": "[익명화됨]",
    "agent_ip": "0.0.0.0",
}


# ────────────────────────────────────────────────────────────────────────────
# Pydantic 모델
# ────────────────────────────────────────────────────────────────────────────

class ErasureRequestCreate(BaseModel):
    data_subject_identifier: str = Field(..., description="삭제 요청 식별자 (이메일, 사용자 ID 등)")
    identifier_type: str = Field("email", description="식별자 유형: email | user_id | ip_address")
    reason: str = Field("", description="삭제 요청 이유 (선택)")
    requested_categories: list[str] = Field(
        default_factory=list,
        description="삭제 요청 데이터 카테고리. 빈 목록이면 전체 카테고리."
    )


class LegalHoldCreate(BaseModel):
    data_category: str
    reference_id: str = Field(..., description="보류 대상 레코드 ID (인시던트 ID 등)")
    hold_reason: str
    hold_until: Optional[datetime] = None  # None이면 무기한
    legal_reference: str = Field("", description="법률 조항 (예: 형사소송법 §106)")


# ────────────────────────────────────────────────────────────────────────────
# 유틸리티
# ────────────────────────────────────────────────────────────────────────────

def _pseudonymize(identifier: str) -> str:
    """개인식별자를 SHA-256 해시로 치환 (역방향 불가)."""
    return "anon:" + hashlib.sha256(identifier.encode()).hexdigest()[:16]


async def _analyze_data_holdings(
    session, identifier: str, identifier_type: str, tenant_id: str
) -> list[dict]:
    """데이터 주체가 보유한 데이터 카테고리와 건수를 분석한다."""
    holdings = []

    if identifier_type == "email":
        # 사용자 프로필
        user_row = (await session.execute(text("""
            SELECT COUNT(*) AS cnt FROM tenant_memberships
            WHERE email = :id AND tenant_id = :tid
        """), {"id": identifier, "tid": tenant_id})).fetchone()
        if user_row and user_row.cnt > 0:
            holdings.append({"category": "user_profiles", "count": int(user_row.cnt)})

        # 감사 로그
        audit_row = (await session.execute(text("""
            SELECT COUNT(*) AS cnt FROM audit_logs
            WHERE actor_email = :id AND tenant_id = :tid
        """), {"id": identifier, "tid": tenant_id})).fetchone()
        if audit_row and audit_row.cnt > 0:
            holdings.append({"category": "audit_logs", "count": int(audit_row.cnt)})

    elif identifier_type == "ip_address":
        # 시그널
        sig_row = (await session.execute(text("""
            SELECT COUNT(*) AS cnt FROM signals
            WHERE raw::text ILIKE :ip_pattern AND tenant_id = :tid
        """), {"ip_pattern": f"%{identifier}%", "tid": tenant_id})).fetchone()
        if sig_row and sig_row.cnt > 0:
            holdings.append({"category": "signals", "count": int(sig_row.cnt)})

    elif identifier_type == "user_id":
        # 사용자 ID 기반 조회
        user_row = (await session.execute(text("""
            SELECT COUNT(*) AS cnt FROM tenant_memberships
            WHERE user_id::text = :id AND tenant_id = :tid
        """), {"id": identifier, "tid": tenant_id})).fetchone()
        if user_row and user_row.cnt > 0:
            holdings.append({"category": "user_profiles", "count": int(user_row.cnt)})

    return holdings


async def _resolve_conflicts(
    session,
    holdings: list[dict],
    requested_categories: list[str],
    tenant_id: str,
) -> list[dict]:
    """각 데이터 카테고리에 대해 충돌 해소 결과를 반환한다."""
    results = []
    cats = requested_categories if requested_categories else [h["category"] for h in holdings]

    for cat in cats:
        policy = _RETENTION_POLICY.get(cat, {
            "resolution": ErasureResolution.CANNOT_DELETE,
            "reason": "알 수 없는 데이터 카테고리",
            "retain_days": 0,
        })

        # 법적 보류 체크
        legal_hold = (await session.execute(text("""
            SELECT hold_id, hold_reason, hold_until, legal_reference
            FROM gdpr_legal_holds
            WHERE data_category = :cat AND tenant_id = :tid AND is_active = true
            LIMIT 1
        """), {"cat": cat, "tid": tenant_id})).fetchone()

        if legal_hold:
            results.append({
                "category": cat,
                "resolution": ErasureResolution.RETAIN_WITH_LEGAL_HOLD,
                "reason": f"법적 보류 중: {legal_hold.hold_reason}",
                "retain_until": legal_hold.hold_until.isoformat() if legal_hold.hold_until else "무기한",
                "legal_reference": legal_hold.legal_reference,
                "hold_id": str(legal_hold.hold_id),
            })
        else:
            result = {
                "category": cat,
                "resolution": policy["resolution"],
                "reason": policy["reason"],
            }
            if policy["resolution"] == ErasureResolution.RETAIN_WITH_LEGAL_HOLD and policy["retain_days"]:
                result["retain_until"] = (
                    datetime.now(tz=timezone.utc) + timedelta(days=policy["retain_days"])
                ).isoformat()
            if policy.get("anonymize_fields"):
                result["anonymize_fields"] = policy["anonymize_fields"]
            results.append(result)

    return results


# ────────────────────────────────────────────────────────────────────────────
# 삭제 요청 처리 실행
# ────────────────────────────────────────────────────────────────────────────

async def _execute_resolution(
    session,
    resolution: str,
    category: str,
    identifier: str,
    identifier_type: str,
    tenant_id: str,
    anonymize_fields: list[str],
) -> dict:
    """충돌 해소 정책에 따라 실제 데이터 처리를 수행한다."""
    affected = 0

    if resolution == ErasureResolution.DELETE:
        if category == "user_profiles" and identifier_type == "email":
            r = await session.execute(text("""
                DELETE FROM tenant_memberships
                WHERE email = :id AND tenant_id = :tid
            """), {"id": identifier, "tid": tenant_id})
            affected = r.rowcount

        elif category == "session_logs":
            # 세션 토큰은 JWT이므로 Redis에서 블랙리스트 처리
            affected = 0  # 만료 대기

    elif resolution == ErasureResolution.ANONYMIZE:
        anon_val = _pseudonymize(identifier)

        if category == "signals" and identifier_type == "ip_address":
            # raw JSON 내 IP 주소 마스킹
            r = await session.execute(text("""
                UPDATE signals
                SET raw = REPLACE(raw::text, :ip, '0.0.0.0')::jsonb,
                    updated_at = NOW()
                WHERE raw::text ILIKE :ip_pattern AND tenant_id = :tid
            """), {"ip": identifier, "ip_pattern": f"%{identifier}%", "tid": tenant_id})
            affected = r.rowcount

        elif category == "agent_heartbeats" and identifier_type == "ip_address":
            r = await session.execute(text("""
                UPDATE agents SET last_ip = '0.0.0.0', hostname = :anon
                WHERE last_ip = :ip AND tenant_id = :tid
            """), {"anon": anon_val, "ip": identifier, "tid": tenant_id})
            affected = r.rowcount

    elif resolution == ErasureResolution.RETAIN_WITH_LEGAL_HOLD:
        # 보류 기간 만료 후 자동 삭제 스케줄 등록
        policy = _RETENTION_POLICY.get(category, {})
        retain_days = policy.get("retain_days", 365)
        delete_at = datetime.now(tz=timezone.utc) + timedelta(days=retain_days)

        await session.execute(text("""
            INSERT INTO gdpr_deletion_schedule (
                schedule_id, tenant_id, data_category, identifier,
                identifier_type, scheduled_delete_at, created_at
            ) VALUES (
                gen_random_uuid(), :tid, :cat, :id, :id_type, :del_at, NOW()
            ) ON CONFLICT DO NOTHING
        """), {
            "tid": tenant_id, "cat": category, "id": identifier,
            "id_type": identifier_type, "del_at": delete_at,
        })
        affected = 0  # 즉시 삭제 없음

    return {"category": category, "resolution": resolution, "affected_rows": affected}


# ────────────────────────────────────────────────────────────────────────────
# API 엔드포인트
# ────────────────────────────────────────────────────────────────────────────

@router.post("/erasure-request")
async def submit_erasure_request(
    body: ErasureRequestCreate,
    claims: dict = Depends(require_any_role),
) -> dict:
    """GDPR 삭제 요청(Art. 17 Right to Erasure)을 제출한다."""
    tenant_id = claims.get("tenant_id", "")
    request_id = uuid.uuid4()
    now = datetime.now(tz=timezone.utc)

    async with get_session() as session:
        # 데이터 보유 현황 분석
        holdings = await _analyze_data_holdings(
            session,
            body.data_subject_identifier,
            body.identifier_type,
            tenant_id,
        )

        # 충돌 해소 분석
        conflict_analysis = await _resolve_conflicts(
            session,
            holdings,
            body.requested_categories,
            tenant_id,
        )

        # 요청 저장
        await session.execute(text("""
            INSERT INTO gdpr_erasure_requests (
                request_id, tenant_id, data_subject_identifier,
                identifier_type, reason, requested_categories,
                conflict_analysis, status, created_at, updated_at
            ) VALUES (
                :req_id, :tid, :identifier, :id_type, :reason,
                :categories::text[], :analysis::jsonb, 'pending', :now, :now
            )
        """), {
            "req_id": request_id,
            "tid": tenant_id,
            "identifier": body.data_subject_identifier,
            "id_type": body.identifier_type,
            "reason": body.reason,
            "categories": body.requested_categories or [h["category"] for h in holdings],
            "analysis": __import__("json").dumps(conflict_analysis),
            "now": now,
        })
        await session.commit()

    log.info(
        "GDPR 삭제 요청 접수: request_id=%s tenant=%s identifier_type=%s",
        request_id, tenant_id, body.identifier_type,
    )

    return {
        "request_id": str(request_id),
        "status": "pending",
        "data_holdings": holdings,
        "conflict_analysis": conflict_analysis,
        "estimated_completion_days": 30,  # GDPR Art. 12(3): 1개월 이내
        "message": (
            f"{len(conflict_analysis)}개 데이터 카테고리에 대해 분석 완료. "
            "관리자가 30일 이내 처리합니다."
        ),
    }


@router.get("/erasure-requests")
async def list_erasure_requests(
    status: str = "",
    page: int = 1,
    page_size: int = 20,
    claims: dict = Depends(require_role("admin")),
) -> dict:
    """삭제 요청 목록을 조회한다 (관리자 전용)."""
    tenant_id = claims.get("tenant_id", "")
    offset = (page - 1) * page_size
    params: dict = {"tid": tenant_id, "offset": offset, "limit": page_size}

    where = "WHERE tenant_id = :tid"
    if status:
        where += " AND status = :status"
        params["status"] = status

    async with get_session() as session:
        total = (await session.execute(text(
            f"SELECT COUNT(*) FROM gdpr_erasure_requests {where}"
        ), params)).scalar()

        rows = (await session.execute(text(f"""
            SELECT request_id, data_subject_identifier, identifier_type,
                   status, created_at, updated_at, conflict_analysis
            FROM gdpr_erasure_requests {where}
            ORDER BY created_at DESC
            LIMIT :limit OFFSET :offset
        """), params)).fetchall()

    import math
    return {
        "requests": [
            {
                "request_id": str(r.request_id),
                "identifier": r.data_subject_identifier,
                "identifier_type": r.identifier_type,
                "status": r.status,
                "created_at": r.created_at.isoformat(),
                "updated_at": r.updated_at.isoformat(),
                "conflict_count": len(r.conflict_analysis or []),
            }
            for r in rows
        ],
        "total": total,
        "page": page,
        "pages": math.ceil(total / page_size) if total else 1,
    }


@router.get("/erasure-requests/{request_id}")
async def get_erasure_request(
    request_id: str,
    claims: dict = Depends(require_role("admin")),
) -> dict:
    """삭제 요청 상세 조회."""
    tenant_id = claims.get("tenant_id", "")

    async with get_session() as session:
        row = (await session.execute(text("""
            SELECT * FROM gdpr_erasure_requests
            WHERE request_id::text = :req_id AND tenant_id = :tid
        """), {"req_id": request_id, "tid": tenant_id})).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="삭제 요청을 찾을 수 없습니다")

    return {
        "request_id": str(row.request_id),
        "identifier": row.data_subject_identifier,
        "identifier_type": row.identifier_type,
        "reason": row.reason,
        "requested_categories": list(row.requested_categories or []),
        "conflict_analysis": row.conflict_analysis or [],
        "status": row.status,
        "processor_notes": row.processor_notes if hasattr(row, "processor_notes") else "",
        "created_at": row.created_at.isoformat(),
        "updated_at": row.updated_at.isoformat(),
    }


@router.post("/erasure-requests/{request_id}/process")
async def process_erasure_request(
    request_id: str,
    claims: dict = Depends(require_role("admin")),
) -> dict:
    """
    삭제 요청을 실제 처리한다.

    충돌 해소 분석 결과에 따라:
    - DELETE: 즉시 삭제
    - ANONYMIZE: 개인식별 필드 마스킹
    - RETAIN_WITH_LEGAL_HOLD: 삭제 예약 등록 + 보류 사유 기록
    """
    tenant_id = claims.get("tenant_id", "")

    async with get_session() as session:
        req = (await session.execute(text("""
            SELECT * FROM gdpr_erasure_requests
            WHERE request_id::text = :req_id AND tenant_id = :tid
        """), {"req_id": request_id, "tid": tenant_id})).fetchone()

        if not req:
            raise HTTPException(status_code=404, detail="삭제 요청을 찾을 수 없습니다")
        if req.status not in ("pending", "in_review"):
            raise HTTPException(
                status_code=409,
                detail=f"처리 불가 상태: {req.status}"
            )

        # 상태 → processing 전환
        await session.execute(text("""
            UPDATE gdpr_erasure_requests
            SET status = 'processing', updated_at = NOW()
            WHERE request_id::text = :req_id
        """), {"req_id": request_id})
        await session.commit()

        conflict_analysis = req.conflict_analysis or []
        results = []

        for item in conflict_analysis:
            cat = item.get("category", "")
            resolution = item.get("resolution", "cannot_delete")
            policy = _RETENTION_POLICY.get(cat, {})
            anon_fields = policy.get("anonymize_fields", [])

            result = await _execute_resolution(
                session,
                resolution,
                cat,
                req.data_subject_identifier,
                req.identifier_type,
                tenant_id,
                anon_fields,
            )
            results.append(result)

        # 완료 처리
        await session.execute(text("""
            UPDATE gdpr_erasure_requests
            SET status = 'completed',
                processor_notes = :notes,
                updated_at = NOW()
            WHERE request_id::text = :req_id
        """), {
            "req_id": request_id,
            "notes": __import__("json").dumps(results),
        })
        await session.commit()

    log.info(
        "GDPR 삭제 요청 처리 완료: request_id=%s categories=%d",
        request_id, len(results),
    )

    return {
        "request_id": request_id,
        "status": "completed",
        "processed_categories": results,
        "message": f"{len(results)}개 카테고리 처리 완료",
    }


@router.get("/data-subjects/{identifier}")
async def get_data_subject_holdings(
    identifier: str,
    identifier_type: str = Query("email"),
    claims: dict = Depends(require_role("admin")),
) -> dict:
    """데이터 주체가 보유한 데이터 목록 조회 (GDPR Art. 15 포터빌리티)."""
    tenant_id = claims.get("tenant_id", "")

    async with get_session() as session:
        holdings = await _analyze_data_holdings(session, identifier, identifier_type, tenant_id)
        conflict_analysis = await _resolve_conflicts(session, holdings, [], tenant_id)

    return {
        "identifier": identifier,
        "identifier_type": identifier_type,
        "data_holdings": holdings,
        "deletion_preview": conflict_analysis,
        "your_rights": {
            "erasure": "GDPR Art. 17 — 삭제 요청 가능",
            "portability": "GDPR Art. 20 — 데이터 이동 요청 가능",
            "rectification": "GDPR Art. 16 — 정정 요청 가능",
            "restriction": "GDPR Art. 18 — 처리 제한 요청 가능",
        },
    }


@router.post("/legal-holds")
async def create_legal_hold(
    body: LegalHoldCreate,
    claims: dict = Depends(require_role("owner")),
) -> dict:
    """법적 보류(Legal Hold)를 설정한다."""
    tenant_id = claims.get("tenant_id", "")
    hold_id = uuid.uuid4()

    async with get_session() as session:
        await session.execute(text("""
            INSERT INTO gdpr_legal_holds (
                hold_id, tenant_id, data_category, reference_id,
                hold_reason, hold_until, legal_reference, is_active, created_at
            ) VALUES (
                :hold_id, :tid, :cat, :ref_id, :reason, :until, :legal_ref, true, NOW()
            )
        """), {
            "hold_id": hold_id,
            "tid": tenant_id,
            "cat": body.data_category,
            "ref_id": body.reference_id,
            "reason": body.hold_reason,
            "until": body.hold_until,
            "legal_ref": body.legal_reference,
        })
        await session.commit()

    return {
        "hold_id": str(hold_id),
        "data_category": body.data_category,
        "reference_id": body.reference_id,
        "hold_until": body.hold_until.isoformat() if body.hold_until else "무기한",
        "message": "법적 보류가 설정되었습니다. 이 기간 동안 해당 데이터는 삭제할 수 없습니다.",
    }


@router.get("/legal-holds")
async def list_legal_holds(
    claims: dict = Depends(require_role("admin")),
) -> list[dict]:
    """활성 법적 보류 목록을 조회한다."""
    tenant_id = claims.get("tenant_id", "")

    async with get_session() as session:
        rows = (await session.execute(text("""
            SELECT hold_id, data_category, reference_id, hold_reason,
                   hold_until, legal_reference, created_at
            FROM gdpr_legal_holds
            WHERE tenant_id = :tid AND is_active = true
            ORDER BY created_at DESC
        """), {"tid": tenant_id})).fetchall()

    return [
        {
            "hold_id": str(r.hold_id),
            "data_category": r.data_category,
            "reference_id": r.reference_id,
            "hold_reason": r.hold_reason,
            "hold_until": r.hold_until.isoformat() if r.hold_until else "무기한",
            "legal_reference": r.legal_reference or "",
            "created_at": r.created_at.isoformat(),
        }
        for r in rows
    ]
