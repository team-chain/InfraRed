"""Agent settings."""
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class AgentSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    tenant_id: str = "company-a"
    agent_id: str = "agent-001"
    asset_id: str = "asset-001"
    agent_token: str = ""
    backend_url: str = "http://ingestion:8000/ingest"
    heartbeat_url: str = "http://ingestion:8000/heartbeat"
    heartbeat_interval_sec: int = 30
    agent_offset_db: str = "/var/lib/infrared/offset.sqlite"
    agent_auth_log_path: str = "/host/var/log/auth.log"
    poll_interval_sec: float = 2.0
