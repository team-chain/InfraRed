"""Shared enums and constants used across InfraRed."""
from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    INFO = "info"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Priority(str, Enum):
    URGENT = "urgent"
    HIGH = "high"
    NORMAL = "normal"
    LOW = "low"


class KillChainStage(str, Enum):
    RECONNAISSANCE = "Reconnaissance"
    CREDENTIAL_ACCESS = "Credential Access"
    INITIAL_ACCESS = "Initial Access"
    EXECUTION = "Execution"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    EXFILTRATION = "Exfiltration"


class EventType(str, Enum):
    # SSH (auth.log)
    SSH_LOGIN_FAILED = "ssh_login_failed"
    SSH_LOGIN_SUCCESS = "ssh_login_success"
    SSH_INVALID_USER = "ssh_invalid_user"
    # Agent heartbeat
    AGENT_HEARTBEAT = "agent_heartbeat"
    # Web (nginx access.log)
    WEB_REQUEST = "web_request"          # generic web request


class RuleId(str, Enum):
    AUTH_BRUTE_FORCE = "AUTH-001"
    AUTH_ROOT_LOGIN = "AUTH-002"
    AUTH_INVALID_USER = "AUTH-003"
    AUTH_FAILED_THEN_SUCCESS = "AUTH-004"
    AUTH_SUSPICIOUS_LOGIN = "AUTH-005"
    AUTH_OFF_HOURS_LOGIN = "AUTH-006"   # 비업무 시간대 로그인 (새벽 00:00~06:00 KST)
    AUTH_FOREIGN_IP_LOGIN = "AUTH-007"  # 해외 IP 로그인 성공 (GeoIP 기반)
    WEB_SHELL_ACCESS = "WEB-001"
    WEB_ADMIN_SCAN = "WEB-002"
    WEB_AUTOMATION = "WEB-003"
    WEB_404_BURST = "WEB-004"
    WEB_SQL_INJECTION = "WEB-005"       # SQL Injection 패턴
    WEB_PATH_TRAVERSAL = "WEB-006"      # Path Traversal / LFI
    WEB_CVE_PROBE = "WEB-007"           # CVE 취약점 탐침 경로 접근
    WEB_HONEYPOT = "WEB-HNY-001"        # Honeypot 경로 접근 (MVP, 경로별 Severity 차등)
    # MVP-Stability
    AUTH_CRED_STUFFING = "AUTH-CS-A"    # Credential Stuffing — 동일 username에 1h 내 3개↑ 다른 IP
    AUTH_PASSWORD_SPRAYING = "AUTH-CS-B"  # Password Spraying — 동일 IP에서 1h 내 5개↑ 다른 username


class LLMStatus(str, Enum):
    """llm_results 테이블 / LLM 호출 상태값 (설계서 9.3)."""
    PENDING = "pending"    # LLM 호출 시작 시 즉시 pending row 생성
    SUCCESS = "success"    # 정상 응답 수신
    FALLBACK = "fallback"  # 실패/timeout → Static Playbook 유지


class SignalCategory(str, Enum):
    """Demo Signal vs Threat Signal 분류 (설계서 17.3)."""
    DEMO = "demo"      # /demo 접근 — Info, Incident 승격 안 함
    THREAT = "threat"  # 실제 위협 — Incident 승격 대상


class PolicyType(str, Enum):
    """IP Policy 3종 분리 (설계서 6.6)."""
    AGENT_ACCESS = "agent_access"        # Ingestion API 접근 허용 Agent 목록
    THREAT_IP = "threat_ip"              # 공격자 source_ip 차단/감시
    DASHBOARD_ACCESS = "dashboard_access"  # 관리자 Dashboard 접근 IP 제한


# Honeypot 경로별 Severity 매핑 (설계서 Table 6)
HONEYPOT_PATH_SEVERITY: dict[str, str] = {
    "/demo":           "info",      # Demo Signal (QR 데모)
    "/.env":           "high",      # Threat Signal
    "/wp-login.php":   "medium",    # Threat Signal
    "/phpmyadmin":     "high",      # Threat Signal
}
# /uploads/*.php + 200 응답 → critical (별도 WEB-001 처리)
HONEYPOT_DEMO_PATH = "/demo"

MASKING_VERSION = "v1"
