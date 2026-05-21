"""포렌식 수집기 — 인시던트 발생 시 시스템 상태 스냅샷을 수집하고 S3 WORM에 저장."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import subprocess
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import text

from app.common.logging import get_logger
from app.config import get_settings
from app.db.connection import get_session

log = get_logger(__name__)


# ── 데이터 모델 ────────────────────────────────────────────────────────────── #

@dataclass
class ForensicItem:
    name: str
    content_b64: str
    sha256: str


@dataclass
class ForensicBundle:
    incident_id: str
    tenant_id: str
    asset_id: Optional[str]
    collected_at: str          # ISO 8601
    items: list[ForensicItem]
    manifest_sig: str          # HMAC-SHA256 over all item hashes

    def to_dict(self) -> dict:
        return {
            "incident_id": self.incident_id,
            "tenant_id": self.tenant_id,
            "asset_id": self.asset_id,
            "collected_at": self.collected_at,
            "items": [
                {
                    "name": item.name,
                    "content_b64": item.content_b64,
                    "sha256": item.sha256,
                }
                for item in self.items
            ],
            "manifest_sig": self.manifest_sig,
        }


# ── 수집 명령 정의 ─────────────────────────────────────────────────────────── #

_COLLECTION_COMMANDS: list[tuple[str, list[str]]] = [
    ("ps_aux",        ["ps", "aux"]),
    ("netstat_an",    ["netstat", "-an"]),
    ("last_50",       ["last", "-n50"]),
    ("who",           ["who"]),
]

_COLLECTION_FILES: list[tuple[str, str]] = [
    ("proc_net_tcp",  "/proc/net/tcp"),
]


# ── ForensicCollector ────────────────────────────────────────────────────── #

class ForensicCollector:
    """인시던트 포렌식 데이터를 수집하고 S3 WORM 버킷에 저장."""

    def __init__(self) -> None:
        self._settings = get_settings()

    # ── 공개 메서드 ──────────────────────────────────────────────────────────

    async def collect(
        self,
        tenant_id: str,
        incident_id: str,
        asset_id: Optional[str] = None,
    ) -> dict:
        """포렌식 데이터를 수집하고 ForensicBundle dict 반환.

        흐름:
        1. 시스템 명령/파일 수집 → ForensicItem 목록
        2. 각 항목 SHA256 해시 계산
        3. HMAC-SHA256(key=FORENSIC_HMAC_KEY, msg=모든해시 이어붙임) → manifest_sig
        4. S3 WORM 업로드
        5. DB에 forensic_bundles INSERT
        """
        collected_at = datetime.now(timezone.utc).isoformat()
        items: list[ForensicItem] = []

        # 명령 수집
        for name, cmd in _COLLECTION_COMMANDS:
            item = self._run_command(name, cmd)
            items.append(item)

        # 파일 수집
        for name, path in _COLLECTION_FILES:
            item = self._read_file(name, path)
            items.append(item)

        # HMAC manifest 서명 계산
        manifest_sig = self._compute_manifest_sig(items)

        bundle = ForensicBundle(
            incident_id=incident_id,
            tenant_id=tenant_id,
            asset_id=asset_id,
            collected_at=collected_at,
            items=items,
            manifest_sig=manifest_sig,
        )

        # S3 WORM 업로드
        s3_key = await self._upload_to_s3_worm(bundle)

        # DB 저장
        await self._save_to_db(bundle, s3_key)

        log.info(
            "forensic_collected",
            incident_id=incident_id,
            tenant_id=tenant_id,
            items=len(items),
            s3_key=s3_key,
        )

        return bundle.to_dict()

    # ── 내부 메서드 ──────────────────────────────────────────────────────────

    def _run_command(self, name: str, cmd: list[str]) -> ForensicItem:
        """subprocess로 명령 실행, 결과를 base64 인코딩 후 SHA256 해시."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            raw = (result.stdout + result.stderr).encode("utf-8", errors="replace")
        except subprocess.TimeoutExpired:
            raw = f"[timeout] command {' '.join(cmd)} timed out after 30s".encode()
        except FileNotFoundError:
            raw = f"[not_found] command {cmd[0]} not found".encode()
        except Exception as exc:
            raw = f"[error] {exc}".encode()

        content_b64 = base64.b64encode(raw).decode()
        sha256 = hashlib.sha256(raw).hexdigest()
        return ForensicItem(name=name, content_b64=content_b64, sha256=sha256)

    def _read_file(self, name: str, path: str) -> ForensicItem:
        """파일 읽기, 결과를 base64 인코딩 후 SHA256 해시."""
        try:
            with open(path, "rb") as f:
                raw = f.read()
        except FileNotFoundError:
            raw = f"[not_found] {path}".encode()
        except PermissionError:
            raw = f"[permission_denied] {path}".encode()
        except Exception as exc:
            raw = f"[error] {exc}".encode()

        content_b64 = base64.b64encode(raw).decode()
        sha256 = hashlib.sha256(raw).hexdigest()
        return ForensicItem(name=name, content_b64=content_b64, sha256=sha256)

    def _compute_manifest_sig(self, items: list[ForensicItem]) -> str:
        """HMAC-SHA256(key=FORENSIC_HMAC_KEY, msg=모든 아이템 SHA256 해시 이어붙임)."""
        key_str = getattr(self._settings, "forensic_hmac_key", "") or "CHANGE_ME_FORENSIC_HMAC"
        key = key_str.encode()
        combined = "".join(item.sha256 for item in items).encode()
        return hmac.new(key, combined, hashlib.sha256).hexdigest()

    async def _upload_to_s3_worm(self, bundle: ForensicBundle) -> str:
        """S3 Object Lock COMPLIANCE 모드로 포렌식 번들 업로드.

        키 패턴: forensics/{tenant_id}/{incident_id}/{timestamp}.json
        보존 기간: 365일 (COMPLIANCE 모드 — 삭제 불가)
        """
        settings = self._settings
        bucket = settings.s3_bucket
        if not bucket:
            log.warning("s3_bucket not configured — skipping S3 upload")
            return f"local://forensics/{bundle.tenant_id}/{bundle.incident_id}/{bundle.collected_at}.json"

        timestamp = bundle.collected_at.replace(":", "-").replace("+", "Z")
        s3_key = f"forensics/{bundle.tenant_id}/{bundle.incident_id}/{timestamp}.json"

        try:
            import boto3  # type: ignore[import]

            session_kwargs: dict = {"region_name": settings.s3_region}
            if settings.aws_access_key_id and settings.aws_secret_access_key:
                session_kwargs["aws_access_key_id"] = settings.aws_access_key_id
                session_kwargs["aws_secret_access_key"] = settings.aws_secret_access_key
                if settings.aws_session_token:
                    session_kwargs["aws_session_token"] = settings.aws_session_token

            s3 = boto3.client("s3", **session_kwargs)
            body = json.dumps(bundle.to_dict(), ensure_ascii=False).encode("utf-8")

            retain_until = datetime.now(timezone.utc) + timedelta(days=365)
            s3.put_object(
                Bucket=bucket,
                Key=s3_key,
                Body=body,
                ContentType="application/json",
                ObjectLockMode="COMPLIANCE",
                ObjectLockRetainUntilDate=retain_until,
            )
            log.info("forensic_s3_uploaded s3_key=%s retain_until=%s", s3_key, retain_until.isoformat())
        except Exception as exc:
            log.error("forensic_s3_upload_failed: %s", exc)
            # 업로드 실패해도 DB 저장은 진행 (s3_key에 오류 표시)
            s3_key = f"error://upload_failed/{bundle.incident_id}"

        return s3_key

    async def _save_to_db(self, bundle: ForensicBundle, s3_key: str) -> None:
        """forensic_bundles 테이블에 메타데이터 INSERT."""
        try:
            async with get_session() as session:
                await session.execute(
                    text("""
                        INSERT INTO forensic_bundles
                          (tenant_id, incident_id, asset_id, collected_at, s3_key, manifest_sig, item_count)
                        VALUES
                          (:tenant_id, :incident_id, :asset_id, :collected_at, :s3_key, :manifest_sig, :item_count)
                    """),
                    {
                        "tenant_id": bundle.tenant_id,
                        "incident_id": bundle.incident_id,
                        "asset_id": bundle.asset_id,
                        "collected_at": bundle.collected_at,
                        "s3_key": s3_key,
                        "manifest_sig": bundle.manifest_sig,
                        "item_count": len(bundle.items),
                    },
                )
                await session.commit()
            log.info("forensic_bundle_saved incident_id=%s", bundle.incident_id)
        except Exception as exc:
            log.warning("forensic_bundle_db_save_failed: %s", exc)
