"""Incident contract produced by the correlation worker."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from app.common.constants import Confidence, KillChainStage, Priority, Severity


class MitreAttack(BaseModel):
    tactic: str
    technique: str


class CtiEnrichment(BaseModel):
    abuse_score: Optional[int] = None
    country: Optional[str] = None
    tags: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    note: Optional[str] = None


class EvidenceItem(BaseModel):
    timestamp: datetime
    description: str
    signal_id: Optional[str] = None
    rule_id: Optional[str] = None


class Incident(BaseModel):
    incident_id: str
    tenant_id: str
    asset_id: str

    severity: Severity
    confidence: Confidence
    priority: Priority
    kill_chain_stage: KillChainStage

    mitre_attack: MitreAttack
    cti_enrichment: Optional[CtiEnrichment] = None
    evidence_timeline: list[EvidenceItem] = Field(default_factory=list)
    signal_ids: list[str] = Field(default_factory=list)

    source_ip: Optional[str] = None
    username: Optional[str] = None

    created_at: datetime
    updated_at: datetime
