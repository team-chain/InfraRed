"""Raw and normalized event contracts."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from app.common.constants import EventType


ENVELOPE_REQUIRED_FIELDS = ("event_id", "tenant_id", "agent_id", "timestamp")


class RawEventEnvelope(BaseModel):
    """Agent output accepted by the ingestion API."""

    model_config = ConfigDict(extra="allow")

    event_id: str = Field(..., min_length=8)
    tenant_id: str
    agent_id: str
    timestamp: datetime

    host: Optional[str] = None
    asset_id: Optional[str] = None
    event_type: Optional[str] = None
    raw_source: Optional[str] = "auth.log"
    raw_line: Optional[str] = None

    file_inode: Optional[str] = None
    file_offset: Optional[int] = None
    late_event: bool = False

    username: Optional[str] = None
    source_ip: Optional[str] = None
    result: Optional[str] = None


class NormalizedEvent(BaseModel):
    """Parsed auth event written by the detection worker."""

    event_id: str
    tenant_id: str
    asset_id: str
    agent_id: str
    timestamp: datetime
    event_type: EventType
    host: Optional[str] = None
    username: Optional[str] = None
    source_ip: Optional[str] = None
    result: Optional[str] = None
    raw_source: str = "auth.log"
    raw_line: Optional[str] = None
    late_event: bool = False
