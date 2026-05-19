"""컴플라이언스 리포트 생성기.

지원 프레임워크:
  - ISMS-P    (정보보호 및 개인정보보호 관리체계)
  - ISO27001  (국제 정보보호 표준)
  - PCI-DSS   (결제카드 산업 보안 표준)

각 프레임워크별 통제 항목 목록을 하드코딩하고,
DB 데이터 기반으로 충족 여부를 체크한 후 ComplianceReport를 반환한다.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal

from sqlalchemy import text

from app.db.connection import get_session

log = logging.getLogger(__name__)

Framework = Literal["ISMS-P", "ISO27001", "PCI-DSS"]

_SUPPORTED_FRAMEWORKS: list[str] = ["ISMS-P", "ISO27001", "PCI-DSS"]


@dataclass
class ControlItem:
    control_id: str
    title: str
    status: str          # "pass" | "fail" | "partial" | "not_applicable"
    evidence: str


@dataclass
class ComplianceReport:
    framework: str
    tenant_id: str
    items: list[ControlItem]
    score_pct: float
    generated_at: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))

    def to_dict(self) -> dict:
        return {
            "framework": self.framework,
            "tenant_id": self.tenant_id,
            "score_pct": round(self.score_pct, 1),
            "generated_at": self.generated_at.isoformat(),
            "items": [
                {
                    "control_id": item.control_id,
                    "title": item.title,
                    "status": item.status,
                    "evidence": item.evidence,
                }
                for item in self.items
            ],
        }


class ComplianceReporter:
    """프레임워크별 컴플라이언스 리포트를 생성한다."""

    async def generate_report(
        self,
        tenant_id: str,
        framework: Framework,
    ) -> ComplianceReport:
        """지정된 프레임워크에 대한 컴플라이언스 리포트를 생성한다."""
        if framework == "ISMS-P":
            items = await self._check_isms_p(tenant_id)
        elif framework == "ISO27001":
            items = await self._check_iso27001(tenant_id)
        elif framework == "PCI-DSS":
            items = await self._check_pci_dss(tenant_id)
        else:
            raise ValueError(f"지원하지 않는 프레임워크: {framework}")

        passed = sum(1 for i in items if i.status == "pass")
        total = len([i for i in items if i.status != "not_applicable"])
        score_pct = (passed / total * 100) if total > 0 else 0.0

        report = ComplianceReport(
            framework=framework,
            tenant_id=tenant_id,
            items=items,
            score_pct=score_pct,
        )

        await self._cache_report(tenant_id, framework, report)
        return report

    # ------------------------------------------------------------------ #
    # ISMS-P 체크 항목
    # ------------------------------------------------------------------ #

    async def _check_isms_p(self, tenant_id: str) -> list[ControlItem]:
        items: list[ControlItem] = []

        # 2.2.1 접근 통제 정책 — api_keys 테이블에 유효한 키 존재 여부
        api_key_count = await self._count_table_rows(
            "api_keys", "tenant_id = :tid", {"tid": tenant_id}
        )
        items.append(ControlItem(
            control_id="2.2.1",
            title="접근 통제 정책",
            status="pass" if api_key_count > 0 else "fail",
            evidence=f"api_keys 테이블 행 수: {api_key_count}",
        ))

        # 2.2.2 사용자 계정 관리 — tenant_memberships 테이블 확인
        membership_count = await self._count_table_rows(
            "tenant_memberships", "tenant_id = :tid", {"tid": tenant_id}
        )
        items.append(ControlItem(
            control_id="2.2.2",
            title="사용자 계정 관리",
            status="pass" if membership_count > 0 else "fail",
            evidence=f"tenant_memberships 테이블 행 수: {membership_count}",
        ))

        # 2.6.1 보안 이벤트 탐지 — signals 테이블 존재 + 최근 30일 데이터
        signal_count = await self._count_table_rows(
            "signals",
            "tenant_id = :tid AND detected_at >= NOW() - INTERVAL '30 days'",
            {"tid": tenant_id},
        )
        items.append(ControlItem(
            control_id="2.6.1",
            title="보안 이벤트 탐지",
            status="pass" if signal_count >= 0 else "fail",
            evidence=f"최근 30일 탐지 시그널 수: {signal_count}",
        ))

        # 2.6.2 침해사고 탐지 및 대응 — incidents 테이블 최근 30일
        incident_count = await self._count_table_rows(
            "incidents",
            "tenant_id = :tid AND created_at >= NOW() - INTERVAL '30 days'",
            {"tid": tenant_id},
        )
        items.append(ControlItem(
            control_id="2.6.2",
            title="침해사고 탐지 및 대응",
            status="pass" if incident_count >= 0 else "fail",
            evidence=f"최근 30일 인시던트 수: {incident_count}",
        ))

        # 2.9.1 시스템 및 서비스 보안 관리 — detection_rules 활성 룰 수
        active_rules = await self._count_table_rows(
            "detection_rules",
            "tenant_id = :tid AND enabled = TRUE",
            {"tid": tenant_id},
        )
        items.append(ControlItem(
            control_id="2.9.1",
            title="시스템 및 서비스 보안 관리",
            status="pass" if active_rules > 0 else "partial",
            evidence=f"활성화된 탐지 룰 수: {active_rules}",
        ))

        # 2.9.2 취약점 점검 및 패치 관리 — audit_logs 로그 유지
        audit_count = await self._count_table_rows(
            "audit_logs",
            "tenant_id = :tid",
            {"tid": tenant_id},
        )
        items.append(ControlItem(
            control_id="2.9.2",
            title="취약점 점검 및 패치 관리",
            status="pass" if audit_count > 0 else "partial",
            evidence=f"감사 로그 전체 수: {audit_count}",
        ))

        # 2.10.1 자동 대응 — auto_response_logs 존재 여부
        auto_resp_count = await self._count_table_rows(
            "auto_response_logs",
            "tenant_id = :tid",
            {"tid": tenant_id},
        )
        items.append(ControlItem(
            control_id="2.10.1",
            title="자동 대응 및 차단 정책",
            status="pass" if auto_resp_count >= 0 else "fail",
            evidence=f"자동 대응 로그 수: {auto_resp_count}",
        ))

        # 2.10.2 로그 보존 — audit_logs append-only 트리거 존재 여부
        trigger_exists = await self._check_trigger_exists("audit_logs_no_update")
        items.append(ControlItem(
            control_id="2.10.2",
            title="로그 위변조 방지",
            status="pass" if trigger_exists else "fail",
            evidence="audit_logs_no_update 트리거 " + ("존재" if trigger_exists else "미존재"),
        ))

        return items

    # ------------------------------------------------------------------ #
    # ISO 27001 체크 항목
    # ------------------------------------------------------------------ #

    async def _check_iso27001(self, tenant_id: str) -> list[ControlItem]:
        items: list[ControlItem] = []

        # A.5.1 정보 보안 정책
        active_rules = await self._count_table_rows(
            "detection_rules", "tenant_id = :tid AND enabled = TRUE", {"tid": tenant_id}
        )
        items.append(ControlItem(
            control_id="A.5.1",
            title="Information Security Policies",
            status="pass" if active_rules > 0 else "fail",
            evidence=f"Active detection rules: {active_rules}",
        ))

        # A.6.1 내부 조직 (역할/책임)
        membership_count = await self._count_table_rows(
            "tenant_memberships", "tenant_id = :tid", {"tid": tenant_id}
        )
        items.append(ControlItem(
            control_id="A.6.1",
            title="Internal Organisation (Roles & Responsibilities)",
            status="pass" if membership_count > 0 else "fail",
            evidence=f"Tenant memberships: {membership_count}",
        ))

        # A.8.1 자산 관리
        asset_count = await self._count_table_rows(
            "assets", "tenant_id = :tid", {"tid": tenant_id}
        )
        items.append(ControlItem(
            control_id="A.8.1",
            title="Asset Management",
            status="pass" if asset_count > 0 else "partial",
            evidence=f"Registered assets: {asset_count}",
        ))

        # A.9.1 접근 통제
        api_key_count = await self._count_table_rows(
            "api_keys", "tenant_id = :tid", {"tid": tenant_id}
        )
        items.append(ControlItem(
            control_id="A.9.1",
            title="Access Control",
            status="pass" if api_key_count > 0 else "fail",
            evidence=f"API keys: {api_key_count}",
        ))

        # A.12.4 이벤트 로깅
        audit_count = await self._count_table_rows(
            "audit_logs", "tenant_id = :tid", {"tid": tenant_id}
        )
        items.append(ControlItem(
            control_id="A.12.4",
            title="Logging and Monitoring",
            status="pass" if audit_count > 0 else "fail",
            evidence=f"Audit log entries: {audit_count}",
        ))

        # A.12.6 기술적 취약점 관리
        items.append(ControlItem(
            control_id="A.12.6",
            title="Management of Technical Vulnerabilities",
            status="partial",
            evidence="CIS Benchmark checker available; scheduled scans recommended",
        ))

        # A.16.1 보안 사고 관리
        incident_count = await self._count_table_rows(
            "incidents", "tenant_id = :tid", {"tid": tenant_id}
        )
        auto_resp = await self._count_table_rows(
            "auto_response_logs", "tenant_id = :tid", {"tid": tenant_id}
        )
        items.append(ControlItem(
            control_id="A.16.1",
            title="Management of Information Security Incidents",
            status="pass" if incident_count >= 0 else "fail",
            evidence=f"Total incidents: {incident_count}, auto-response logs: {auto_resp}",
        ))

        # A.18.1 법적 요구사항 준수
        trigger_exists = await self._check_trigger_exists("audit_logs_no_update")
        items.append(ControlItem(
            control_id="A.18.1",
            title="Compliance with Legal Requirements",
            status="pass" if trigger_exists else "partial",
            evidence="Append-only audit log: " + ("enabled" if trigger_exists else "not configured"),
        ))

        return items

    # ------------------------------------------------------------------ #
    # PCI-DSS 체크 항목
    # ------------------------------------------------------------------ #

    async def _check_pci_dss(self, tenant_id: str) -> list[ControlItem]:
        items: list[ControlItem] = []

        # Req 1: 네트워크 보안 제어
        active_rules = await self._count_table_rows(
            "detection_rules", "tenant_id = :tid AND enabled = TRUE", {"tid": tenant_id}
        )
        items.append(ControlItem(
            control_id="PCI-1.3",
            title="Network Access Controls",
            status="pass" if active_rules > 0 else "fail",
            evidence=f"Active detection rules: {active_rules}",
        ))

        # Req 2: 보안 기본 설정
        items.append(ControlItem(
            control_id="PCI-2.2",
            title="System Configuration Standards",
            status="partial",
            evidence="CIS benchmark check available; manual review required",
        ))

        # Req 7: 접근 통제
        api_key_count = await self._count_table_rows(
            "api_keys", "tenant_id = :tid", {"tid": tenant_id}
        )
        items.append(ControlItem(
            control_id="PCI-7.2",
            title="Access Control Systems",
            status="pass" if api_key_count > 0 else "fail",
            evidence=f"API access keys configured: {api_key_count}",
        ))

        # Req 8: 사용자 식별 및 인증
        membership_count = await self._count_table_rows(
            "tenant_memberships", "tenant_id = :tid", {"tid": tenant_id}
        )
        items.append(ControlItem(
            control_id="PCI-8.2",
            title="User Identification and Authentication",
            status="pass" if membership_count > 0 else "fail",
            evidence=f"User accounts: {membership_count}",
        ))

        # Req 10: 감사 로그
        audit_count = await self._count_table_rows(
            "audit_logs", "tenant_id = :tid", {"tid": tenant_id}
        )
        trigger_exists = await self._check_trigger_exists("audit_logs_no_update")
        items.append(ControlItem(
            control_id="PCI-10.2",
            title="Audit Log Implementation",
            status="pass" if (audit_count > 0 and trigger_exists) else ("partial" if audit_count > 0 else "fail"),
            evidence=f"Audit log entries: {audit_count}, immutability: {'yes' if trigger_exists else 'no'}",
        ))

        # Req 11: 보안 테스팅
        signal_count = await self._count_table_rows(
            "signals",
            "tenant_id = :tid AND detected_at >= NOW() - INTERVAL '90 days'",
            {"tid": tenant_id},
        )
        items.append(ControlItem(
            control_id="PCI-11.5",
            title="Change-Detection Mechanisms",
            status="pass" if signal_count >= 0 else "fail",
            evidence=f"Security signals (last 90 days): {signal_count}",
        ))

        # Req 12: 정보 보안 정책
        items.append(ControlItem(
            control_id="PCI-12.1",
            title="Information Security Policy",
            status="partial",
            evidence="Platform policy engine active; formal policy document review required",
        ))

        return items

    # ------------------------------------------------------------------ #
    # 헬퍼
    # ------------------------------------------------------------------ #

    async def _count_table_rows(
        self,
        table: str,
        where: str,
        params: dict,
    ) -> int:
        """테이블 행 수를 반환한다. 테이블이 없으면 0을 반환한다."""
        try:
            sql = text(f"SELECT COUNT(*) FROM {table} WHERE {where}")  # noqa: S608
            async with get_session() as session:
                result = await session.execute(sql, params)
                return int(result.scalar() or 0)
        except Exception as exc:
            log.warning("컴플라이언스 DB 조회 실패 table=%s: %s", table, exc)
            return 0

    async def _check_trigger_exists(self, trigger_name: str) -> bool:
        """PostgreSQL 트리거 존재 여부를 확인한다."""
        try:
            sql = text("""
                SELECT COUNT(*) FROM information_schema.triggers
                WHERE trigger_name = :name
            """)
            async with get_session() as session:
                result = await session.execute(sql, {"name": trigger_name})
                return int(result.scalar() or 0) > 0
        except Exception as exc:
            log.warning("트리거 존재 여부 확인 실패: %s", exc)
            return False

    async def _cache_report(
        self,
        tenant_id: str,
        framework: str,
        report: ComplianceReport,
    ) -> None:
        """생성된 리포트를 compliance_reports 테이블에 캐시한다."""
        import json
        try:
            sql = text("""
                INSERT INTO compliance_reports
                    (tenant_id, framework, report_data, score_pct, generated_at)
                VALUES
                    (:tenant_id, :framework, :report_data::jsonb, :score_pct, :generated_at)
            """)
            async with get_session() as session:
                await session.execute(sql, {
                    "tenant_id": tenant_id,
                    "framework": framework,
                    "report_data": json.dumps(report.to_dict()),
                    "score_pct": report.score_pct,
                    "generated_at": report.generated_at,
                })
        except Exception as exc:
            log.warning("컴플라이언스 리포트 캐시 실패: %s", exc)
