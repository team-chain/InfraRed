"""IP Policy Manager 모델 (설계서 6.6).

정책을 3개로 분리:
  1. agent_access   — Ingestion API에 이벤트를 보낼 수 있는 Agent 목록
  2. threat_ip      — 로그에서 탐지된 공격자 source_ip 차단/감시
  3. dashboard_access — 관리자 Dashboard 접근 IP 제한

CIDR 매칭은 Redis SISMEMBER가 아닌 Python ipaddress 모듈로 평가.
정책 변경 시 Redis Pub/Sub으로 캐시 즉시 무효화.
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
        # 빈 배열 방지 안전장치 (설계서 6.6)
        if len(self.allowed_agents) == 0:
            raise ValueError(
                "allowed_agents가 비어 있으면 모든 Agent가 차단됩니다. "
                "의도적이라면 명시적으로 확인 후 진행하세요."
            )
        return self


class ThreatIpPolicy(BaseModel):
    """PUT /api/policy/threat-ip — 공격자 IP 차단/감시 정책."""
    mode: str = "allow_all"               # "allow_all" | "allowlist_only"
    allowlist: list[str] = Field(default_factory=list)   # CIDR 또는 단일 IP
    denylist: list[str] = Field(default_factory=list)    # 항상 차단
    country_block: list[str] = Field(default_factory=list)  # 예: ["CN", "RU", "KP"]


class DashboardAccessPolicy(BaseModel):
    """PUT /api/policy/dashboard-access — Dashboard 접근 IP 제한."""
    allowlist: list[str] = Field(default_factory=list)  # CIDR 또는 단일 IP


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
