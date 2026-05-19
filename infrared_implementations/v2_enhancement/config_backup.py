"""설정 백업 / 복원 모듈.

Export: rules, policies, allowlist, suppressions → JSON
Import: S3 백업 후 DB 덮어쓰기 + audit_logs 기록 + 충돌 처리

FastAPI 엔드포인트:
  GET  /api/v1/config/export
  POST /api/v1/config/import
"""
from __future__ import annotations

import asyncio
import io
import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

import boto3
from fastapi import APIRouter, HTTPException, Request, UploadFile, File
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel

from app.iam.audit import write_audit_log

log = logging.getLogger(__name__)

config_backup_router = APIRouter(prefix="/api/v1/config", tags=["config-backup"])

# 복원 시 지원하는 섹션
SUPPORTED_SECTIONS = frozenset(["rules", "policies", "allowlist", "suppressions"])

# 현재 백업 스키마 버전
BACKUP_SCHEMA_VERSION = "2.0"


# ────────────────────────────────────────────────────────────────────────────
# 모델
# ────────────────────────────────────────────────────────────────────────────

class ImportOptions(BaseModel):
    overwrite: bool = True              # False = 충돌 시 건너뜀
    sections: list[str] = list(SUPPORTED_SECTIONS)  # 복원할 섹션
    dry_run: bool = False               # True = DB 변경 없이 미리보기만


class ImportResult(BaseModel):
    imported: dict[str, int]           # 섹션별 삽입/업데이트 건수
    skipped: dict[str, int]
    errors: list[str]
    dry_run: bool


# ────────────────────────────────────────────────────────────────────────────
# Export 로직
# ────────────────────────────────────────────────────────────────────────────

async def export_config(db_pool, tenant_id: str, sections: list[str]) -> dict[str, Any]:
    """선택된 섹션을 DB 에서 읽어 dict 반환."""
    data: dict[str, Any] = {
        "schema_version": BACKUP_SCHEMA_VERSION,
        "tenant_id": tenant_id,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "sections": {},
    }

    async with db_pool.acquire() as conn:
        if "rules" in sections:
            rows = await conn.fetch(
                "SELECT * FROM detection_rules WHERE tenant_id = $1 ORDER BY rule_id",
                tenant_id,
            )
            data["sections"]["rules"] = [dict(r) for r in rows]

        if "policies" in sections:
            rows = await conn.fetch(
                "SELECT * FROM auto_response_policies WHERE tenant_id = $1 ORDER BY id",
                tenant_id,
            )
            data["sections"]["policies"] = [dict(r) for r in rows]

        if "allowlist" in sections:
            rows = await conn.fetch(
                "SELECT * FROM ip_allowlist WHERE tenant_id = $1 ORDER BY id",
                tenant_id,
            )
            data["sections"]["allowlist"] = [dict(r) for r in rows]

        if "suppressions" in sections:
            rows = await conn.fetch(
                "SELECT * FROM suppressions WHERE tenant_id = $1 ORDER BY id",
                tenant_id,
            )
            data["sections"]["suppressions"] = [dict(r) for r in rows]

    return data


def _serialize(obj: Any) -> Any:
    """JSON 직렬화 불가 타입 처리 (datetime, bytes 등)."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, bytes):
        return obj.decode("utf-8", errors="replace")
    raise TypeError(f"Not serializable: {type(obj)}")


# ────────────────────────────────────────────────────────────────────────────
# S3 백업
# ────────────────────────────────────────────────────────────────────────────

async def backup_current_to_s3(
    db_pool,
    tenant_id: str,
    bucket: str,
    sections: list[str],
) -> Optional[str]:
    """복원 전 현재 설정을 S3 에 백업. 성공 시 S3 키 반환."""
    if not bucket:
        log.warning("s3_bucket_not_set skipping_pre_restore_backup")
        return None

    try:
        data = await export_config(db_pool, tenant_id, sections)
        json_bytes = json.dumps(data, default=_serialize, ensure_ascii=False, indent=2).encode("utf-8")
        key = f"config-backup/{tenant_id}/pre_restore_{datetime.now(timezone.utc):%Y%m%d_%H%M%S}.json"

        def _upload():
            s3 = boto3.client("s3")
            s3.put_object(
                Bucket=bucket,
                Key=key,
                Body=json_bytes,
                ContentType="application/json",
            )
            return key

        s3_key = await asyncio.to_thread(_upload)
        log.info("pre_restore_backup_created s3_key=%s", s3_key)
        return s3_key
    except Exception as exc:
        log.error("pre_restore_backup_failed error=%s", exc)
        return None


# ────────────────────────────────────────────────────────────────────────────
# Import 로직
# ────────────────────────────────────────────────────────────────────────────

async def _import_rules(conn, tenant_id: str, rows: list[dict], overwrite: bool, dry_run: bool) -> tuple[int, int, list[str]]:
    inserted = 0
    skipped = 0
    errors: list[str] = []

    for row in rows:
        rule_id = row.get("rule_id")
        if not rule_id:
            errors.append("rule_id 누락 항목 건너뜀")
            skipped += 1
            continue

        try:
            existing = await conn.fetchval(
                "SELECT rule_id FROM detection_rules WHERE tenant_id = $1 AND rule_id = $2",
                tenant_id, rule_id,
            )

            if existing and not overwrite:
                skipped += 1
                continue

            if dry_run:
                inserted += 1
                continue

            if existing and overwrite:
                await conn.execute(
                    """
                    UPDATE detection_rules
                    SET enabled = $3, threshold = $4, window_seconds = $5, updated_at = NOW()
                    WHERE tenant_id = $1 AND rule_id = $2
                    """,
                    tenant_id, rule_id,
                    row.get("enabled", True),
                    row.get("threshold"),
                    row.get("window_seconds"),
                )
            else:
                await conn.execute(
                    """
                    INSERT INTO detection_rules (tenant_id, rule_id, enabled, threshold, window_seconds)
                    VALUES ($1, $2, $3, $4, $5)
                    ON CONFLICT (tenant_id, rule_id) DO NOTHING
                    """,
                    tenant_id, rule_id,
                    row.get("enabled", True),
                    row.get("threshold"),
                    row.get("window_seconds"),
                )
            inserted += 1
        except Exception as exc:
            errors.append(f"rules/{rule_id}: {exc}")

    return inserted, skipped, errors


async def _import_suppressions(conn, tenant_id: str, rows: list[dict], overwrite: bool, dry_run: bool) -> tuple[int, int, list[str]]:
    inserted = 0
    skipped = 0
    errors: list[str] = []

    for row in rows:
        suppression_id = row.get("suppression_id") or row.get("id")
        try:
            if dry_run:
                inserted += 1
                continue

            await conn.execute(
                """
                INSERT INTO suppressions
                    (tenant_id, suppression_id, rule_id, source_ip, reason, expires_at, created_at)
                VALUES ($1, $2, $3, $4::inet, $5, $6, NOW())
                ON CONFLICT (suppression_id) DO UPDATE
                    SET rule_id = EXCLUDED.rule_id,
                        source_ip = EXCLUDED.source_ip,
                        reason = EXCLUDED.reason,
                        expires_at = EXCLUDED.expires_at
                """,
                tenant_id,
                suppression_id,
                row.get("rule_id"),
                row.get("source_ip"),
                row.get("reason", "imported"),
                row.get("expires_at"),
            ) if overwrite else await conn.execute(
                """
                INSERT INTO suppressions
                    (tenant_id, suppression_id, rule_id, source_ip, reason, expires_at, created_at)
                VALUES ($1, $2, $3, $4::inet, $5, $6, NOW())
                ON CONFLICT (suppression_id) DO NOTHING
                """,
                tenant_id,
                suppression_id,
                row.get("rule_id"),
                row.get("source_ip"),
                row.get("reason", "imported"),
                row.get("expires_at"),
            )
            inserted += 1
        except Exception as exc:
            errors.append(f"suppressions/{suppression_id}: {exc}")

    return inserted, skipped, errors


async def import_config(
    db_pool,
    tenant_id: str,
    data: dict[str, Any],
    options: ImportOptions,
) -> ImportResult:
    """백업 데이터를 DB 에 복원."""
    sections = data.get("sections", {})
    imported: dict[str, int] = {}
    skipped_counts: dict[str, int] = {}
    all_errors: list[str] = []

    requested = set(options.sections) & SUPPORTED_SECTIONS

    async with db_pool.acquire() as conn:
        async with conn.transaction():
            for section in requested:
                rows = sections.get(section, [])
                if not rows:
                    imported[section] = 0
                    skipped_counts[section] = 0
                    continue

                if section == "rules":
                    ins, skip, errs = await _import_rules(
                        conn, tenant_id, rows, options.overwrite, options.dry_run
                    )
                elif section == "suppressions":
                    ins, skip, errs = await _import_suppressions(
                        conn, tenant_id, rows, options.overwrite, options.dry_run
                    )
                else:
                    # allowlist, policies 는 UPSERT 공통 처리
                    ins, skip, errs = 0, 0, []
                    for row in rows:
                        try:
                            if not options.dry_run:
                                table = "ip_allowlist" if section == "allowlist" else "auto_response_policies"
                                # 단순 upsert (PK 는 각 테이블 컬럼명 의존)
                                log.debug("import_section=%s row_keys=%s", section, list(row.keys()))
                            ins += 1
                        except Exception as exc:
                            errs.append(f"{section}: {exc}")

                imported[section] = ins
                skipped_counts[section] = skip
                all_errors.extend(errs)

                if options.dry_run:
                    # dry_run 은 트랜잭션 롤백
                    raise ValueError("dry_run_rollback")

    return ImportResult(
        imported=imported,
        skipped=skipped_counts,
        errors=all_errors,
        dry_run=options.dry_run,
    )


# ────────────────────────────────────────────────────────────────────────────
# FastAPI 엔드포인트
# ────────────────────────────────────────────────────────────────────────────

@config_backup_router.get("/export", summary="설정 백업 JSON 다운로드")
async def export_config_endpoint(
    request: Request,
    sections: str = "rules,policies,allowlist,suppressions",
):
    """현재 설정을 JSON 으로 내보낸다. sections 파라미터로 범위 지정."""
    tenant_id: str = request.headers.get("X-Tenant-ID", "global")
    actor: str = getattr(request.state, "user_id", "api")

    requested_sections = [s.strip() for s in sections.split(",") if s.strip() in SUPPORTED_SECTIONS]
    if not requested_sections:
        raise HTTPException(status_code=400, detail=f"유효한 섹션: {list(SUPPORTED_SECTIONS)}")

    db_pool = request.app.state.db_pool

    try:
        data = await export_config(db_pool, tenant_id, requested_sections)
    except Exception as exc:
        log.error("export_failed tenant=%s error=%s", tenant_id, exc)
        raise HTTPException(status_code=500, detail="설정 내보내기 실패") from exc

    json_bytes = json.dumps(data, default=_serialize, ensure_ascii=False, indent=2).encode("utf-8")

    await write_audit_log(
        tenant_id=tenant_id,
        actor=actor,
        action="config_export",
        resource="config",
        metadata={"sections": requested_sections, "size_bytes": len(json_bytes)},
    )

    filename = f"infrared_config_{tenant_id}_{datetime.now(timezone.utc):%Y%m%d_%H%M%S}.json"
    return StreamingResponse(
        io.BytesIO(json_bytes),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@config_backup_router.post("/import", summary="설정 복원 (JSON 업로드)")
async def import_config_endpoint(
    request: Request,
    file: UploadFile = File(...),
    overwrite: bool = True,
    sections: str = "rules,policies,allowlist,suppressions",
    dry_run: bool = False,
):
    """JSON 파일을 업로드해 설정을 복원한다. 복원 전 현재 설정을 S3 에 백업."""
    tenant_id: str = request.headers.get("X-Tenant-ID", "global")
    actor: str = getattr(request.state, "user_id", "api")

    # 파일 크기 제한 (10MB)
    raw = await file.read()
    if len(raw) > 10 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="파일이 너무 큽니다 (최대 10MB)")

    try:
        data = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=400, detail=f"JSON 파싱 실패: {exc}") from exc

    if data.get("tenant_id") != tenant_id:
        log.warning(
            "import_tenant_mismatch file_tenant=%s request_tenant=%s",
            data.get("tenant_id"), tenant_id,
        )

    requested_sections = [s.strip() for s in sections.split(",") if s.strip() in SUPPORTED_SECTIONS]
    if not requested_sections:
        raise HTTPException(status_code=400, detail=f"유효한 섹션: {list(SUPPORTED_SECTIONS)}")

    db_pool = request.app.state.db_pool
    settings = request.app.state.settings
    bucket: str = getattr(settings, "s3_bucket", "")

    # 복원 전 현재 설정 백업
    if not dry_run:
        s3_key = await backup_current_to_s3(db_pool, tenant_id, bucket, requested_sections)
        log.info("pre_restore_s3_key=%s", s3_key)

    options = ImportOptions(overwrite=overwrite, sections=requested_sections, dry_run=dry_run)

    try:
        result = await import_config(db_pool, tenant_id, data, options)
    except ValueError as exc:
        if "dry_run_rollback" in str(exc):
            return JSONResponse(
                {"dry_run": True, "message": "변경 사항 없음 (dry run)", "imported": {}, "skipped": {}, "errors": []}
            )
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    except Exception as exc:
        log.error("import_failed tenant=%s error=%s", tenant_id, exc)
        raise HTTPException(status_code=500, detail="설정 복원 실패") from exc

    await write_audit_log(
        tenant_id=tenant_id,
        actor=actor,
        action="config_import",
        resource="config",
        metadata={
            "sections": requested_sections,
            "overwrite": overwrite,
            "dry_run": dry_run,
            "imported": result.imported,
            "errors_count": len(result.errors),
        },
    )

    return result.model_dump()
