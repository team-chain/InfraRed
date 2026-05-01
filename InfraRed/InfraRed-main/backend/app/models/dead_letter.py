"""Dead-letter stream contract."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from app.common.constants import MASKING_VERSION


class DeadLetter(BaseModel):
    event_id: str
    reason: str = Field(..., description="schema_validation_failed | jwt_invalid | ...")
    error_message: str
    failed_at: datetime
    retry_count: int = 0
    raw_payload: str
    masking_applied: bool = True
    masking_version: str = MASKING_VERSION
