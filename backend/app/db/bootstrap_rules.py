"""탐지 룰 카탈로그 보장 부트스트랩.

문제: detection_rules 카탈로그는 seed.sql로 깔리도록 돼 있으나, SQL 시드 로딩이
환경에 따라 불안정해 카탈로그가 빈 채로 뜨는 경우가 있었다. 그러면 에이전트/탐지가
신호를 저장할 때 signals.rule_id FK 위반으로 탐지가 통째로 막힌다.

해결: migrate 마지막에 코드로 전체 카탈로그를 멱등 upsert 한다. SQL 파싱에 의존하지
않으므로 어떤 배포에서도 항상 동일하게 룰이 보장된다. (bootstrap_admin 과 동일 패턴)

신규 룰을 코드에 추가하면 반드시 이 목록에도 추가할 것.
"""
from __future__ import annotations

import asyncpg

# (rule_id, name, source, mitre_tactic, mitre_technique)
_RULES: list[tuple[str, str, str, str, str]] = [
    # AUTH (auth.log)
    ("AUTH-001", "SSH Brute Force", "auth.log", "Credential Access", "T1110.001"),
    ("AUTH-002", "Root Login Attempt", "auth.log", "Initial Access", "T1078"),
    ("AUTH-003", "Invalid User Enumeration", "auth.log", "Reconnaissance", "T1592"),
    ("AUTH-004", "Failed Then Success", "auth.log", "Initial Access", "T1110.001 -> T1078"),
    ("AUTH-005", "Suspicious Login", "auth.log", "Initial Access", "T1078"),
    ("AUTH-006", "Off Hours Login", "auth.log", "Initial Access", "T1078"),
    ("AUTH-007", "Foreign IP Login", "auth.log", "Initial Access", "T1078"),
    ("AUTH-006A", "Credential Stuffing", "auth.log", "Credential Access", "T1110.004"),
    ("AUTH-006B", "Password Spraying", "auth.log", "Credential Access", "T1110.003"),
    # WEB (nginx)
    ("WEB-001", "Web Shell Access", "nginx", "Initial Access", "T1505.003"),
    ("WEB-002", "Admin Path Scan", "nginx", "Reconnaissance", "T1595"),
    ("WEB-003", "Automation Tool Access", "nginx", "Initial Access", "T1190"),
    ("WEB-004", "404 Burst", "nginx", "Reconnaissance", "T1595"),
    ("WEB-005", "SQL Injection", "nginx", "Initial Access", "T1190"),
    ("WEB-006", "Path Traversal", "nginx", "Initial Access", "T1190"),
    ("WEB-007", "CVE Probe", "nginx", "Initial Access", "T1190"),
    ("WEB-HNY-001", "Honeypot Access", "nginx", "Reconnaissance", "T1595"),
    ("NET-001", "HTTP Flood", "nginx", "Impact", "T1498"),
    # Deception
    ("DECEPTION-001", "Honeytoken File Access", "agent.fim", "Discovery", "T1083"),
    ("DECEPTION-002", "Honeytoken Account Use", "auth.log", "Credential Access", "T1110"),
    ("DECEPTION-003", "AWS Honey Key Use", "cloudtrail", "Credential Access", "T1078.004"),
    # EXEC / process (agent)
    ("EXEC-001", "Tmp Process Execution", "agent.exec", "Execution", "T1059"),
    ("EXEC-002", "Webshell Child Process", "agent.exec", "Initial Access", "T1505.003"),
    ("EXEC-003", "Bulk File Modification", "agent.exec", "Impact", "T1486"),
    ("EXEC-FIRST-001", "First-Seen Binary", "agent.exec", "Execution", "T1059"),
    ("EXEC-FIRST-002", "First-Seen Binary (priv)", "agent.exec", "Execution", "T1059"),
    ("EXEC-ANCESTRY-001", "Suspicious Process Ancestry", "agent.exec", "Execution", "T1059"),
    ("EXEC-ANCESTRY-002", "Suspicious Process Ancestry (critical)", "agent.exec", "Execution", "T1059"),
    # FIM / persistence (agent)
    ("FIM-001", "Authorized Keys Tamper", "agent.fim", "Persistence", "T1098.004"),
    ("FIM-002", "SSHD Config Tamper", "agent.fim", "Defense Evasion", "T1562.004"),
    ("FIM-003", "Crontab Tamper", "agent.fim", "Persistence", "T1053.003"),
    ("FIM-004", "Passwd Tamper", "agent.fim", "Persistence", "T1136.001"),
    ("FIM-005", "Sudoers Tamper", "agent.fim", "Privilege Escalation", "T1548.003"),
    ("FIM-005-SVC", "Systemd Service Tamper", "agent.fim", "Persistence", "T1543.002"),
    ("PERSIST-001", "Authorized Keys Monitor", "agent.fim", "Persistence", "T1098.004"),
    ("PERSIST-002", "Cron Monitor", "agent.fim", "Persistence", "T1053.003"),
    ("PERSIST-003", "Systemd Service Monitor", "agent.fim", "Persistence", "T1543.002"),
    ("ESCALATE-001", "Sensitive File Monitor", "agent.fim", "Privilege Escalation", "T1548"),
    # auditd (agent)
    ("AUDITD-001", "Suspicious Process (auditd)", "agent.auditd", "Execution", "T1059"),
    ("AUDITD-002", "Sensitive File Access", "agent.auditd", "Credential Access", "T1003"),
    # Advanced correlation / anomaly
    ("TRAVEL-001", "Impossible Travel", "correlation", "Initial Access", "T1078"),
    ("DRIFT-001", "UEBA Behavioral Drift", "ueba", "Discovery", "T1087"),
    ("TAMPER-NTP-001", "NTP Drift Detected", "agent.ntp", "Defense Evasion", "T1070.006"),
    ("TAMPER-NTP-002", "System Time Tamper", "agent.ntp", "Defense Evasion", "T1070.006"),
    ("TAMPER-LOG-001", "Log Entropy Anomaly", "log", "Impact", "T1486"),
    # Agent self-protection
    ("TAMPER-001", "Agent Watchdog", "agent", "Defense Evasion", "T1562.001"),
    ("TAMPER-002", "Log Integrity", "agent", "Defense Evasion", "T1070.002"),
    # Windows
    ("WIN-001", "Windows Failed Logon", "winevt", "Credential Access", "T1110"),
    ("WIN-002", "Windows Suspicious Process", "winevt", "Execution", "T1059"),
]


async def bootstrap_rules_on(conn: asyncpg.Connection) -> int:
    """전체 탐지 룰 카탈로그를 멱등 upsert. 삽입/보장된 개수 반환."""
    await conn.executemany(
        """
        INSERT INTO detection_rules (rule_id, name, source, mitre_tactic, mitre_technique, enabled)
        VALUES ($1, $2, $3, $4, $5, TRUE)
        ON CONFLICT (rule_id) DO NOTHING
        """,
        _RULES,
    )
    total = await conn.fetchval("SELECT count(*) FROM detection_rules")
    return int(total)
