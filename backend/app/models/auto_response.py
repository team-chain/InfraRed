"""Policy-based Auto-Response 모델 (설계서 6.7).

LLM은 설명만 생성, 실행은 이 정책 기반으로만 수행.
모든 대응은 auto_response_logs에 append-only 기록.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional
from uuid import uuid4

from pydantic import BaseModel, Field


def _new_ar_id() -> str:
    ts = datetime.utcnow().strftime("%Y%m%d")
    return f"AR-{ts}-{uuid4().hex[:6].upper()}"


class SeverityPolicy(BaseModel):
    """severity 등급별 자동 대응 정책 플래그 (설계서 6.7 정책 설정)."""
    watchlist: bool = False
    block_ip: bool = False
    discord_notify: bool = True


class AutoResponsePolicy(BaseModel):
    """테넌트별 Policy-based Auto-Response 설정 (설계서 6.7).

    MVP 기본값:
        critical → watchlist + discord_notify (block_ip=false, dry_run)
        high     → watchlist + discord_notify
        medium   → discord_notify만
        info     → 아무것도 안 함
    """
    critical: SeverityPolicy = Field(
        default_factory=lambda: SeverityPolicy(watchlist=True, block_ip=False, discord_notify=True)
    )
    high: SeverityPolicy = Field(
        default_factory=lambda: SeverityPolicy(watchlist=True, block_ip=False, discord_notify=True)
    )
    medium: SeverityPolicy = Field(
        default_factory=lambda: SeverityPolicy(watchlist=False, block_ip=False, discord_notify=True)
    )
    info: SeverityPolicy = Field(
        default_factory=lambda: SeverityPolicy(watchlist=False, block_ip=False, discord_notify=False)
    )

    def for_severity(self, severity: str) -> SeverityPolicy:
        return getattr(self, severity.lower(), SeverityPolicy())


class AutoResponseLog(BaseModel):
    """자동 대응 실행 이력 — append-only 불변 감사 로그 (설계서 6.7).

    reversed=true로 롤백 가능.
    MVP 기본값: dry_run=true (실제 차단 없음, 로그만 기록).
    """
    auto_response_id: str = Field(default_factory=_new_ar_id)
    tenant_id: str
    incident_id: Optional[str] = None   # demo_signal은 incident 없을 수 있음
    rule_id: Optional[str] = None
    severity: Optional[str] = None

    # 실행된 액션 목록 — 예: ["watchlist", "discord_notify"]
    actions_taken: list[str] = Field(default_factory=list)

    # MVP: dry_run=true → 로그만 기록, 실제 enforcement 없음
    dry_run: bool = True

    triggered_by: Optional[str] = None    # 예: "severity=high, rule=WEB-HNY-001"
    policy_reason: Optional[str] = None   # 예: "High severity WEB-HNY-001 matched. Watchlist policy enabled."
    policy_version: Optional[int] = None

    executed_at: datetime = Field(default_factory=datetime.utcnow)

    # 롤백 정보
    reversed: bool = False
    reversed_at: Optional[datetime] = None
    reversed_by: Optional[str] = None

    # v3.0 TTL / 승인 워크플로우 확장 필드 (설계서 Section 6.1)
    action_level: Optional[str] = None          # iptables_block | approval_iptables | service_block | watchlist
    ttl_seconds: Optional[int] = None           # 차단 유지 시간 (초)
    expires_at: Optional[datetime] = None       # 차단 만료 시각 (UTC)
    approval_required: bool = False             # 승인 필요 여부
    confidence_snapshot: Optional[float] = None # 실행 시점의 detection_confidence
    scenario_id: Optional[str] = None           # 매칭된 공격 시나리오 ID
