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


class RuleId(str, Enum):
    AUTH_BRUTE_FORCE = "AUTH-001"
    AUTH_ROOT_LOGIN = "AUTH-002"
    AUTH_INVALID_USER = "AUTH-003"
    AUTH_FAILED_THEN_SUCCESS = "AUTH-004"
    AUTH_SUSPICIOUS_LOGIN = "AUTH-005"
    WEB_SHELL_ACCESS = "WEB-001"
    WEB_ADMIN_SCAN = "WEB-002"
    WEB_AUTOMATION = "WEB-003"
    WEB_404_BURST = "WEB-004"


MASKING_VERSION = "v1"
