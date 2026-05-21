"""Central settings shared by the API and all workers."""
from __future__ import annotations

import logging
import warnings
from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict

_log = logging.getLogger(__name__)

_JWT_DEFAULT = "CHANGE_ME_IN_PRODUCTION"


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

    jwt_secret: str = _JWT_DEFAULT
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

    llm_provider: Literal["auto", "static", "bedrock", "anthropic"] = "auto"
    bedrock_region: str = "us-east-1"
    bedrock_model_id: str = "anthropic.claude-3-5-sonnet-20241022-v2:0"
    aws_access_key_id: str = ""
    aws_secret_access_key: str = ""
    aws_session_token: str = ""
    aws_profile: str = ""
    llm_cache_ttl_seconds: int = 3600

    # Anthropic Direct (Phase 3-A: 비용 최적화 환경)
    anthropic_api_key: str = ""
    anthropic_model_id: str = "claude-haiku-4-5-20251001"

    # SendGrid (Phase 4-D: 리포트 메일)
    sendgrid_api_key: str = ""
    report_email_from: str = "report@infrared.local"

    # AWS S3 (Phase 4-D: 리포트 저장)
    s3_bucket: str = ""
    s3_region: str = "ap-northeast-2"

    discord_webhook_url: str = ""
    slack_webhook_url: str = ""
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    alert_email_from: str = "alert@infrared.local"
    alert_email_to: str = ""

    # Sentry error tracking (no-op if dsn empty)
    sentry_dsn: str = ""
    sentry_environment: str = ""  # empty → falls back to `env` field
    sentry_traces_sample_rate: float = 0.1
    sentry_profiles_sample_rate: float = 0.0

    cti_provider: Literal["mock", "abuseipdb", "otx"] = "mock"
    abuseipdb_api_key: str = ""
    otx_api_key: str = ""          # AlienVault OTX API Key (CTI_PROVIDER=otx 시 사용)
    cti_cache_ttl_seconds: int = 86400

    maxmind_license_key: str = ""
    maxmind_db_path: str = "/app/data/GeoLite2-City.mmdb"

    # Incident correlation
    incident_merge_window_minutes: int = 120

    # Dead Letter Queue
    dlq_max_retries: int = 3
    dlq_idle_seconds: int = 60

    # Detection rule thresholds (AUTH-001 ~ AUTH-005)
    auth_brute_force_threshold: int = 3
    auth_brute_force_window_seconds: int = 300
    auth_invalid_user_threshold: int = 2
    auth_invalid_user_window_seconds: int = 300
    auth_fail_then_success_window_seconds: int = 600
    auth_fail_then_success_threshold: int = 3

    # Incident dedup
    incident_dedup_ttl_seconds: int = 600

    # WEB-001~004 thresholds
    web_admin_scan_threshold: int = 30
    web_admin_scan_window_seconds: int = 300
    web_404_threshold: int = 50
    web_404_window_seconds: int = 300

    prometheus_bearer_token: str = ""

    cors_origins: str = "http://localhost:3000"

    # 사용자 facing URL (인증/재설정 이메일 링크에 사용)
    frontend_base_url: str = "https://app.infrared.kr"

    # v3.0 Campaign Aggregation
    campaign_window_seconds: int = 600
    campaign_min_signals: int = 5
    campaign_min_targets: int = 2
    late_event_threshold_seconds: int = 300
    late_event_max_seconds: int = 86400

    # SQS (v4.0)
    sqs_events_url: str = ""      # SQS queue URL for infrared-events
    sqs_signals_url: str = ""     # SQS queue URL for infrared-signals
    sqs_incidents_url: str = ""   # SQS queue URL for infrared-incidents
    sqs_enabled: bool = False     # SQS 사용 여부 (False면 Redis만 사용)

    # WorkOS SSO (v4.0)
    workos_api_key: str = ""
    workos_client_id: str = ""

    # Stripe (v4.0)
    stripe_secret_key: str = ""
    stripe_webhook_secret: str = ""
    stripe_price_growth: str = ""
    stripe_price_enterprise: str = ""

    # UEBA (v4.0)
    ueba_enabled: bool = False
    ueba_model_bucket: str = "infrared-models"
    ueba_silent_days: int = 7   # 학습만 하는 기간

    # SIGMA (v4.0)
    sigma_sync_enabled: bool = False

    # Fernet encryption key for sensitive data
    fernet_key: str = ""

    # Status Page
    status_page_url: str = "https://status.infrared.io"
    dashboard_url: str = "http://localhost:3000"

    # v7.0: mTLS (상호 TLS 인증) 설정
    # Nginx/Traefik 프록시가 클라이언트 인증서 검증 후 헤더로 전달하는 방식 지원
    mtls_enabled: bool = False
    mtls_require_agent_cn: bool = False     # True이면 인증서 CN을 agent_id와 대조
    # uvicorn 직접 TLS 모드 (프록시 없이 직접 mTLS 처리할 때)
    tls_certfile: str = ""                  # 서버 인증서 경로
    tls_keyfile: str = ""                   # 서버 개인키 경로
    tls_ca_certs: str = ""                  # 클라이언트 인증서 검증용 CA 경로


    def model_post_init(self, __context: object) -> None:
        # JWT secret default value warning
        if self.jwt_secret == _JWT_DEFAULT:
            msg = (
                "JWT_SECRET is set to the insecure default value. "
                "Set a strong random secret in production via the JWT_SECRET env var."
            )
            if self.env == "prod":
                raise ValueError(msg)
            warnings.warn(msg, stacklevel=2)

    @property
    def cors_origin_list(self) -> list[str]:
        origins = [o.strip() for o in self.cors_origins.split(",") if o.strip()]
        # CORS wildcard defense: refuse * in non-local envs
        if "*" in origins and self.env != "local":
            _log.warning(
                "CORS wildcard (*) is not allowed in env=%s; origin ignored.", self.env
            )
            origins = [o for o in origins if o != "*"]
        return origins

    @property
    def llm_enabled(self) -> bool:
        if self.llm_provider == "static":
            return False
        if self.llm_provider == "bedrock":
            return True
        if self.llm_provider == "anthropic":
            return bool(self.anthropic_api_key)
        # auto: Bedrock 또는 Anthropic 설정 있으면 활성화
        return bool(
            (self.aws_access_key_id and self.aws_secret_access_key)
            or self.aws_profile
            or self.anthropic_api_key
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
