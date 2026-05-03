"""LLM request/response contracts."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from app.common.constants import Confidence, KillChainStage, Severity
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
    incident_id: str
    plain_summary: str
    attack_intent: str
    kill_chain_analysis: str
    recommended_actions: list[str] = Field(default_factory=list)
    confidence_note: str = ""
    model: str = "static-playbook"
    cached: bool = False
    generated_at: datetime
