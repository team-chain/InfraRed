"""Central settings shared by the API and all workers."""
from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    env: Literal["local", "dev", "prod"] = "local"
    log_level: str = "INFO"
    tz: str = "Asia/Seoul"

    tenant_id: str = "company-a"
    agent_id: str = "agent-001"
    asset_id: str = "asset-001"

    ingest_host: str = "0.0.0.0"
    ingest_port: int = 8000
    payload_max_bytes: int = 65536
    internal_api_base_url: str = "http://ingestion:8000"

    jwt_secret: str = "change-me-in-production-please"
    jwt_alg: str = "HS256"
    jwt_issuer: str = "infrared"
    jwt_audience: str = "infrared-ingest"
    jwt_agent_ttl_seconds: int = 86400
    jwt_user_ttl_seconds: int = 3600

    redis_url: str = "redis://redis:6379/0"
    redis_stream_maxlen: int = 100_000
    dedup_ttl_seconds: int = 3600

    database_url: str = (
        "postgresql+asyncpg://infrared:infrared-dev-pw@postgres:5432/infrared"
    )

    llm_provider: Literal["auto", "static", "bedrock"] = "auto"
    bedrock_region: str = "us-east-1"
    bedrock_model_id: str = "anthropic.claude-3-5-sonnet-20241022-v2:0"
    aws_access_key_id: str = ""
    aws_secret_access_key: str = ""
    aws_session_token: str = ""
    aws_profile: str = ""
    llm_cache_ttl_seconds: int = 3600

    discord_webhook_url: str = ""
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    alert_email_from: str = "alert@infrared.local"
    alert_email_to: str = ""

    cti_provider: Literal["mock", "abuseipdb"] = "mock"
    abuseipdb_api_key: str = ""
    cti_cache_ttl_seconds: int = 86400

    maxmind_license_key: str = ""
    maxmind_db_path: str = "/app/data/GeoLite2-City.mmdb"

    # Incident correlation
    incident_merge_window_minutes: int = 120  # group signals into one incident for 2 h

    # Dead Letter Queue
    dlq_max_retries: int = 3        # move to DLQ after this many failures
    dlq_idle_seconds: int = 60      # reclaim PEL messages idle longer than this

    # Detection rule thresholds (AUTH-001 ~ AUTH-005)
    auth_brute_force_threshold: int = 3          # failed attempts before AUTH-001 fires
    auth_brute_force_window_seconds: int = 300   # sliding window for brute-force
    auth_invalid_user_threshold: int = 2         # invalid-user probes for AUTH-003
    auth_invalid_user_window_seconds: int = 300  # sliding window for invalid-user
    auth_fail_then_success_window_seconds: int = 600  # look-back for AUTH-004

    cors_origins: str = "http://localhost:3000"
    late_event_threshold_seconds: int = 300
    late_event_max_seconds: int = 86400

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def llm_enabled(self) -> bool:
        if self.llm_provider == "static":
            return False
        if self.llm_provider == "bedrock":
            return True
        return bool(
            (self.aws_access_key_id and self.aws_secret_access_key)
            or self.aws_profile
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
