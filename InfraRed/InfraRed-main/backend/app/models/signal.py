"""Detection signal contract."""
from __future__ import annotations

from datetime import datetime
from typing import Optional
from uuid import uuid4

from pydantic import BaseModel, Field

from app.common.constants import KillChainStage, RuleId


class Signal(BaseModel):
    signal_id: str = Field(default_factory=lambda: f"SIG-{uuid4().hex[:12]}")

    tenant_id: str
    asset_id: str

    rule_id: RuleId
    rule_name: str

    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    mitre_subtechnique: Optional[str] = None
    kill_chain_stage: Optional[KillChainStage] = None

    source_ip: Optional[str] = None
    username: Optional[str] = None
    detected_count: int = 1

    detected_at: datetime
    window_start: Optional[datetime] = None
    window_end: Optional[datetime] = None

    triggering_event_ids: list[str] = Field(default_factory=list)
    notes: Optional[str] = None
