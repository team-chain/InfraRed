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
    SSH_LOGIN_FAILED = "ssh_login_failed"
    SSH_LOGIN_SUCCESS = "ssh_login_success"
    SSH_INVALID_USER = "ssh_invalid_user"
    AGENT_HEARTBEAT = "agent_heartbeat"
    WEB_REQUEST = "web_request"


class RuleId(str, Enum):
    AUTH_BRUTE_FORCE = "AUTH-001"
    AUTH_ROOT_LOGIN = "AUTH-002"
    AUTH_INVALID_USER = "AUTH-003"
    AUTH_FAILED_THEN_SUCCESS = "AUTH-004"
    AUTH_SUSPICIOUS_LOGIN = "AUTH-005"
    AUTH_OFF_HOURS_LOGIN = "AUTH-006"
    AUTH_FOREIGN_IP_LOGIN = "AUTH-007"
    WEB_SHELL_ACCESS = "WEB-001"
    WEB_ADMIN_SCAN = "WEB-002"
    WEB_AUTOMATION = "WEB-003"
    WEB_404_BURST = "WEB-004"
    WEB_SQL_INJECTION = "WEB-005"
    WEB_PATH_TRAVERSAL = "WEB-006"
    WEB_CVE_PROBE = "WEB-007"
    WEB_HONEYPOT = "WEB-HNY-001"
    # Credential Access 고급 룰 (설계서 3.1)
    AUTH_CRED_STUFFING = "AUTH-006A"
    AUTH_PASSWORD_SPRAYING = "AUTH-006B"
    # 네트워크 공격 탐지 (설계서 3.1)
    NET_HTTP_FLOOD = "NET-001"
    # Deception (설계서 v6)
    DECEPTION_HONEYTOKEN_FILE = "DECEPTION-001"
    DECEPTION_HONEYTOKEN_ACCOUNT = "DECEPTION-002"


class LLMStatus(str, Enum):
    PENDING = "pending"
    SUCCESS = "success"
    FALLBACK = "fallback"


class SignalCategory(str, Enum):
    DEMO = "demo"
    THREAT = "threat"


class PolicyType(str, Enum):
    AGENT_ACCESS = "agent_access"
    THREAT_IP = "threat_ip"
    DASHBOARD_ACCESS = "dashboard_access"


# Honeypot 경로별 Severity 매핑 (설계서 Table 6)
HONEYPOT_PATH_SEVERITY: dict[str, str] = {
    "/demo":            "info",
    "/.env":            "high",
    "/wp-login.php":    "medium",
    "/.git":            "high",
    "/actuator":        "high",
    "/wp-config.php":   "critical",
    "/phpmyadmin":      "high",
    "/admin":           "medium",
    "/config.php":      "high",
    "/backup":          "medium",
}

HONEYPOT_DEMO_PATH = "/demo"

# 마스킹 버전 (dead_letter 스키마 추적용)
MASKING_VERSION = "v1"
