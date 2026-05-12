"""IP Policy Manager 모델 (설계서 6.6).

정책을 3개로 분리:
  1. agent_access   — Ingestion API에 이벤트를 보낼 수 있는 Agent 목록
  2. threat_ip      — 로그에서 탐지된 공격자 source_ip 차단/감시
  3. dashboard_access — 관리자 Dashboard 접근 IP 제한

CIDR 매칭은 Redis SISMEMBER가 아닌 Python ipaddress 모듈로 평가.
정책 변경 시 Redis Pub/Sub으로 캐시 즉시 무효화.

PUT  — 정책 전체 교체 (모든 필드 필수)
PATCH — 일부 필드만 수정 (미전송 필드는 현재 값 유지)
        add_* / remove_* 로 리스트 항목을 개별 추가/제거 가능.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, model_validator

from app.common.constants import PolicyType


class AgentAccessPolicy(BaseModel):
    """PUT /api/policy/agent-access — Ingestion API 접근 허용 Agent 목록."""
    allowed_agents: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _no_empty_agents(self) -> "AgentAccessPolicy":
        if len(self.allowed_agents) == 0:
            raise ValueError(
                "allowed_agents가 비어 있으면 모든 Agent가 차단됩니다. "
                "의도적이라면 명시적으로 확인 후 진행하세요."
            )
        return self


class AgentAccessPatch(BaseModel):
    """PATCH /api/policy/agent-access — 일부 필드만 수정.

    사용 방법 (둘 중 하나 or 조합):
      - allowed_agents: 목록 전체를 새 값으로 교체 (빈 배열 불가)
      - add_agents / remove_agents: 기존 목록에서 항목 추가/제거
    """
    allowed_agents: Optional[list[str]] = Field(
        default=None,
        description="지정 시 allowed_agents 전체를 이 값으로 교체.",
    )
    add_agents: Optional[list[str]] = Field(
        default=None,
        description="기존 목록에 추가할 agent ID 목록.",
    )
    remove_agents: Optional[list[str]] = Field(
        default=None,
        description="기존 목록에서 제거할 agent ID 목록.",
    )

    @model_validator(mode="after")
    def _at_least_one_field(self) -> "AgentAccessPatch":
        if self.allowed_agents is None and self.add_agents is None and self.remove_agents is None:
            raise ValueError("수정할 필드를 하나 이상 전달해야 합니다.")
        return self


class ThreatIpPolicy(BaseModel):
    """PUT /api/policy/threat-ip — 공격자 IP 차단/감시 정책."""
    mode: str = "allow_all"
    allowlist: list[str] = Field(default_factory=list)
    denylist: list[str] = Field(default_factory=list)
    country_block: list[str] = Field(default_factory=list)


class ThreatIpPatch(BaseModel):
    """PATCH /api/policy/threat-ip — 일부 필드만 수정.

    각 필드는 Optional — 전달된 필드만 현재 정책에 병합됨.
    리스트 필드는 add_* / remove_* 로 개별 항목 추가/제거 가능.
    """
    mode: Optional[str] = Field(
        default=None,
        description="'allow_all' | 'allowlist_only'. 미전송 시 현재 값 유지.",
    )
    allowlist: Optional[list[str]] = Field(
        default=None,
        description="allowlist 전체 교체. 미전송 시 현재 값 유지.",
    )
    add_allowlist: Optional[list[str]] = Field(
        default=None,
        description="allowlist에 추가할 IP/CIDR 목록.",
    )
    remove_allowlist: Optional[list[str]] = Field(
        default=None,
        description="allowlist에서 제거할 IP/CIDR 목록.",
    )
    denylist: Optional[list[str]] = Field(
        default=None,
        description="denylist 전체 교체. 미전송 시 현재 값 유지.",
    )
    add_denylist: Optional[list[str]] = Field(
        default=None,
        description="denylist에 추가할 IP/CIDR 목록.",
    )
    remove_denylist: Optional[list[str]] = Field(
        default=None,
        description="denylist에서 제거할 IP/CIDR 목록.",
    )
    country_block: Optional[list[str]] = Field(
        default=None,
        description="country_block 전체 교체. 미전송 시 현재 값 유지.",
    )
    add_country_block: Optional[list[str]] = Field(
        default=None,
        description="country_block에 추가할 국가 코드 목록.",
    )
    remove_country_block: Optional[list[str]] = Field(
        default=None,
        description="country_block에서 제거할 국가 코드 목록.",
    )

    @model_validator(mode="after")
    def _at_least_one_field(self) -> "ThreatIpPatch":
        fields = [
            self.mode, self.allowlist, self.add_allowlist, self.remove_allowlist,
            self.denylist, self.add_denylist, self.remove_denylist,
            self.country_block, self.add_country_block, self.remove_country_block,
        ]
        if all(f is None for f in fields):
            raise ValueError("수정할 필드를 하나 이상 전달해야 합니다.")
        return self


class DashboardAccessPolicy(BaseModel):
    """PUT /api/policy/dashboard-access — Dashboard 접근 IP 제한."""
    allowlist: list[str] = Field(default_factory=list)


class DashboardAccessPatch(BaseModel):
    """PATCH /api/policy/dashboard-access — 일부 필드만 수정."""
    allowlist: Optional[list[str]] = Field(
        default=None,
        description="allowlist 전체 교체. 미전송 시 현재 값 유지.",
    )
    add_allowlist: Optional[list[str]] = Field(
        default=None,
        description="allowlist에 추가할 IP/CIDR 목록.",
    )
    remove_allowlist: Optional[list[str]] = Field(
        default=None,
        description="allowlist에서 제거할 IP/CIDR 목록.",
    )

    @model_validator(mode="after")
    def _at_least_one_field(self) -> "DashboardAccessPatch":
        if self.allowlist is None and self.add_allowlist is None and self.remove_allowlist is None:
            raise ValueError("수정할 필드를 하나 이상 전달해야 합니다.")
        return self


class IpPolicy(BaseModel):
    """DB ip_policies 테이블과 1:1 대응하는 통합 정책 모델."""
    tenant_id: str
    policy_type: PolicyType
    policy_version: int = 1
    mode: str = "allow_all"
    allowlist: list[str] = Field(default_factory=list)
    denylist: list[str] = Field(default_factory=list)
    country_block: list[str] = Field(default_factory=list)
    allowed_agents: list[str] = Field(default_factory=list)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    updated_by: Optional[str] = None


class PolicyCacheEntry(BaseModel):
    """워커 로컬 메모리 LRU 캐시 항목 (TTL 1분)."""
    policy: IpPolicy
    policy_version: int
    cached_at: datetime = Field(default_factory=datetime.utcnow)


class PolicyVersionInfo(BaseModel):
    """Redis policy_version 정보 — 정책 변경 시 atomic increment."""
    policy_version: int
    updated_at: datetime
