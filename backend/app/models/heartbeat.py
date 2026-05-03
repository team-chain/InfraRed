"""Agent heartbeat contract."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class Heartbeat(BaseModel):
    tenant_id: str
    agent_id: str
    asset_id: Optional[str] = None
    sent_at: datetime
    agent_version: str = "0.1.0"
    pending_buffered_events: int = 0
    last_event_id: Optional[str] = None
