"""LLM request/response contracts."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field

from app.common.constants import Confidence, KillChainStage, LLMStatus, Severity
from app.models.incident import CtiEnrichment, MitreAttack


class LLMInput(BaseModel):
    severity: Severity
    confidence: Confidence
    kill_chain_stage: KillChainStage
    mitre_attack: MitreAttack
    cti: Optional[CtiEnrichment] = None
    evidence_timeline: list[str] = Field(default_factory=list)
    playbook_context: str = ""


class LLMResult(BaseModel):
    """LLM 분석 결과 — DB llm_results 테이블과 1:1 대응."""
    incident_id: str
    # pending 상태에서는 None, 완료 후 채워짐
    plain_summary: Optional[str] = None
    attack_intent: Optional[str] = None
    kill_chain_analysis: Optional[str] = None
    recommended_actions: list[str] = Field(default_factory=list)
    confidence_note: str = ""
    model: str = "static-playbook"
    cached: bool = False
    # v5: pending/success/fallback 상태 흐름 (설계서 9.3)
    status: LLMStatus = LLMStatus.PENDING
    failure_reason: Optional[str] = None  # "timeout" | "api_error"
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class LLMPendingRow(BaseModel):
    """LLM 호출 시작 시 즉시 DB에 삽입하는 pending row (설계서 9.3)."""
    llm_result_id: str  # 예: LLM-{incident_id}-{timestamp}
    incident_id: str
    tenant_id: str
    status: LLMStatus = LLMStatus.PENDING
