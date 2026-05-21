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
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    INSTALLATION = "Installation"
    COMMAND_AND_CONTROL = "Command and Control"
    EXFILTRATION = "Exfiltration"
    IMPACT = "Impact"
    ACTIONS_ON_OBJECTIVES = "Actions on Objectives"


class EventType(str, Enum):
    SSH_LOGIN_FAILED = "ssh_login_failed"
    SSH_LOGIN_SUCCESS = "ssh_login_success"
    SSH_INVALID_USER = "ssh_invalid_user"
    AGENT_HEARTBEAT = "agent_heartbeat"
    WEB_REQUEST = "web_request"
    # Agent-side pre-classified events
    FIM_CHANGE = "fim_change"
    SUSPICIOUS_PROCESS_EXECUTION = "suspicious_process_execution"
    WEBSHELL_EXECUTION = "webshell_execution"
    BULK_FILE_MODIFICATION = "bulk_file_modification"


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
    # Agent-side rules (사전 분류된 이벤트, agent가 직접 rule_id 매김)
    EXEC_TMP = "EXEC-001"                # /tmp 계열에서 실행 중인 프로세스
    EXEC_WEBSHELL = "EXEC-002"           # 웹서버 child process가 shell
    EXEC_BULK_MOD = "EXEC-003"           # 대량 파일 변경
    FIM_AUTHORIZED_KEYS = "FIM-001"      # /root/.ssh/authorized_keys 변조
    FIM_SSHD_CONFIG = "FIM-002"          # sshd_config 변조
