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
    agent_command_poll_interval_seconds: int = 30
    agent_poll_interval_seconds: float = 2.0
    agent_offset_db: str = "/var/lib/infrared/offset.sqlite"
    agent_auth_log_path: str = "/host/var/log/auth.log"
    # nginx access.log 수집 설정 (설계서 2.1 — auth.log + nginx.log 수집)
    agent_nginx_log_path: str = "/host/var/log/nginx/access.log"
    agent_nginx_enabled: bool = True
    poll_interval_sec: float = 2.0

    # S3 로그 업로드 설정 (선택, 미설정 시 비활성화)
    s3_enabled: bool = False
    s3_bucket: str = ""
    s3_prefix: str = "infrared/auth"
    s3_region: str = "ap-northeast-2"
    aws_access_key_id: str = ""
    aws_secret_access_key: str = ""
    aws_profile: str = ""
    s3_upload_interval_sec: int = 300    # 5분마다 업로드
    s3_max_lines_per_file: int = 10_000  # 파일당 최대 라인 수

    # Phase 4-A: FIM / auditd 설정
    agent_fim_enabled: bool = True
    agent_fim_interval_seconds: int = 60
    agent_auditd_enabled: bool = False
    agent_privileged_mode: bool = False
    fim_state_path: str = "/var/lib/infrared/fim_state.json"
    auditd_log_path: str = "/var/log/audit/audit.log"

    # v3.0: 실행 탐지 모니터 설정
    agent_exec_monitor_enabled: bool = True
    agent_exec_monitor_interval_seconds: int = 10

    # v3.0: Watchdog 설정
    watchdog_token: str = ""
    infrared_server_url: str = "http://localhost:8000"

    # v7.0: mTLS (상호 TLS 인증) 설정
    # 미설정 시 기존 Bearer 토큰 방식으로 폴백
    mtls_enabled: bool = False
    mtls_cert_path: str = "/etc/infrared/certs/agent.crt"    # 에이전트 클라이언트 인증서
    mtls_key_path: str = "/etc/infrared/certs/agent.key"     # 에이전트 클라이언트 개인키
    mtls_ca_path: str = "/etc/infrared/certs/ca.crt"         # 서버 인증서 검증용 CA
    mtls_verify_server: bool = True                           # 서버 인증서 검증 여부 (prod=True)

    # v7.0: 에이전트 버전 (Updater 컴포넌트 사용)
    agent_version: str = "0.0.0"
