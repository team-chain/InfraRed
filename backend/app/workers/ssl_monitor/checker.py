"""SSL 인증서 만료 모니터링.

도메인별로 SSL 인증서를 조회해 만료일과 남은 일수를 계산하고,
임계값에 따라 경고 알림을 생성한다.

  days_remaining < 7  → CRITICAL
  days_remaining < 14 → HIGH
  days_remaining < 30 → WARNING
"""
from __future__ import annotations

import logging
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import text

from app.db.connection import get_session

log = logging.getLogger(__name__)

_WARN_DAYS = 30
_HIGH_DAYS = 14
_CRIT_DAYS = 7


@dataclass
class CertInfo:
    domain: str
    expires_at: datetime
    issuer: Optional[str]
    days_remaining: int
    severity: Optional[str]   # None | "WARNING" | "HIGH" | "CRITICAL"
    error: Optional[str] = None


@dataclass
class CertCheckResult:
    domain: str
    success: bool
    cert_info: Optional[CertInfo]
    error: Optional[str] = None


class SSLCertificateMonitor:
    """도메인 SSL 인증서 만료를 모니터링한다."""

    # ------------------------------------------------------------------ #
    # 단일 도메인 점검
    # ------------------------------------------------------------------ #

    def check_domain(self, domain: str, port: int = 443) -> CertInfo:
        """단일 도메인의 SSL 인증서 정보를 가져와 만료일을 계산한다."""
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
        except Exception as exc:
            raise RuntimeError(f"SSL 연결 실패 ({domain}:{port}): {exc}") from exc

        # 만료일 파싱
        not_after_str = cert.get("notAfter", "")
        try:
            expires_at = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        except ValueError as exc:
            raise RuntimeError(f"인증서 만료일 파싱 실패: {not_after_str}") from exc

        # 발급자 추출
        issuer_parts = cert.get("issuer", ())
        issuer_dict = {k: v for tup in issuer_parts for k, v in tup}
        issuer = issuer_dict.get("organizationName") or issuer_dict.get("commonName")

        now = datetime.now(tz=timezone.utc)
        days_remaining = max(0, (expires_at - now).days)

        # 심각도 결정
        if days_remaining < _CRIT_DAYS:
            severity = "CRITICAL"
        elif days_remaining < _HIGH_DAYS:
            severity = "HIGH"
        elif days_remaining < _WARN_DAYS:
            severity = "WARNING"
        else:
            severity = None

        return CertInfo(
            domain=domain,
            expires_at=expires_at,
            issuer=issuer,
            days_remaining=days_remaining,
            severity=severity,
        )

    # ------------------------------------------------------------------ #
    # 전체 도메인 점검
    # ------------------------------------------------------------------ #

    async def run_all_checks(self, tenant_id: str) -> list[CertCheckResult]:
        """DB에 등록된 모든 도메인의 인증서를 점검한다."""
        domains = await self._get_domains(tenant_id)
        results: list[CertCheckResult] = []

        for domain in domains:
            try:
                cert_info = self.check_domain(domain)
                await self._upsert_cert(tenant_id, cert_info)
                results.append(CertCheckResult(domain=domain, success=True, cert_info=cert_info))
                if cert_info.severity:
                    log.warning(
                        "SSL cert expiry alert: domain=%s days_remaining=%d severity=%s",
                        domain, cert_info.days_remaining, cert_info.severity,
                    )
            except Exception as exc:
                log.warning("SSL check failed for %s: %s", domain, exc)
                results.append(CertCheckResult(domain=domain, success=False,
                                               cert_info=None, error=str(exc)))

        return results

    # ------------------------------------------------------------------ #
    # DB 헬퍼
    # ------------------------------------------------------------------ #

    async def add_domain(self, tenant_id: str, domain: str) -> None:
        """모니터링 대상 도메인을 DB에 추가한다."""
        sql = text("""
            INSERT INTO ssl_certificates (tenant_id, domain, expires_at, last_checked)
            VALUES (:tenant_id, :domain, NOW() + INTERVAL '1 day', NOW())
            ON CONFLICT (tenant_id, domain) DO NOTHING
        """)
        async with get_session() as session:
            await session.execute(sql, {"tenant_id": tenant_id, "domain": domain})

    async def _get_domains(self, tenant_id: str) -> list[str]:
        """DB에서 모니터링 대상 도메인 목록을 가져온다."""
        try:
            sql = text("""
                SELECT domain FROM ssl_certificates
                WHERE tenant_id = :tenant_id
                ORDER BY domain
            """)
            async with get_session() as session:
                rows = (await session.execute(sql, {"tenant_id": tenant_id})).all()
            return [row.domain for row in rows]
        except Exception as exc:
            log.warning("도메인 목록 조회 실패: %s", exc)
            return []

    async def _upsert_cert(self, tenant_id: str, cert_info: CertInfo) -> None:
        """인증서 점검 결과를 DB에 upsert한다."""
        try:
            sql = text("""
                INSERT INTO ssl_certificates
                    (tenant_id, domain, expires_at, last_checked, issuer)
                VALUES
                    (:tenant_id, :domain, :expires_at, NOW(), :issuer)
                ON CONFLICT (tenant_id, domain) DO UPDATE SET
                    expires_at   = EXCLUDED.expires_at,
                    last_checked = EXCLUDED.last_checked,
                    issuer       = EXCLUDED.issuer
            """)
            async with get_session() as session:
                await session.execute(sql, {
                    "tenant_id": tenant_id,
                    "domain": cert_info.domain,
                    "expires_at": cert_info.expires_at,
                    "issuer": cert_info.issuer,
                })
        except Exception as exc:
            log.warning("인증서 DB 저장 실패 domain=%s: %s", cert_info.domain, exc)

    async def get_all_status(self, tenant_id: str) -> list[dict]:
        """DB에 저장된 모든 도메인의 인증서 상태를 반환한다."""
        try:
            sql = text("""
                SELECT domain, expires_at, last_checked, issuer, days_remaining
                FROM ssl_certificates
                WHERE tenant_id = :tenant_id
                ORDER BY days_remaining ASC NULLS LAST
            """)
            async with get_session() as session:
                rows = (await session.execute(sql, {"tenant_id": tenant_id})).all()

            result = []
            for row in rows:
                days = row.days_remaining
                if days is not None:
                    if days < _CRIT_DAYS:
                        severity = "CRITICAL"
                    elif days < _HIGH_DAYS:
                        severity = "HIGH"
                    elif days < _WARN_DAYS:
                        severity = "WARNING"
                    else:
                        severity = "OK"
                else:
                    severity = "UNKNOWN"

                result.append({
                    "domain": row.domain,
                    "expires_at": row.expires_at.isoformat() if row.expires_at else None,
                    "last_checked": row.last_checked.isoformat() if row.last_checked else None,
                    "issuer": row.issuer,
                    "days_remaining": days,
                    "severity": severity,
                })
            return result
        except Exception as exc:
            log.warning("SSL 상태 조회 실패: %s", exc)
            return []
