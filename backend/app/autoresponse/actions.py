"""Action type definitions for AI auto-response."""
from __future__ import annotations
from enum import Enum


class ActionType(str, Enum):
    BLOCK_IP         = "block_ip"         # iptables DROP via Agent
    LOCK_ACCOUNT     = "lock_account"     # passwd -l via Agent
    ESCALATE         = "escalate"         # severity 상향, 추가 알림
    NOTIFY           = "notify"           # Discord/Email 알림만
    ISOLATE_SERVER   = "isolate_server"   # NIC 비활성화 또는 iptables ALL DROP
    KILL_PROCESS     = "kill_process"     # PID로 악성 프로세스 종료
    COLLECT_FORENSICS = "collect_forensics"  # 포렌식 수집 트리거
    RESTORE_FILE     = "restore_file"     # 파일 복원 (안전 정책 포함)


SEVERITY_RANK = {"info": 0, "medium": 1, "high": 2, "critical": 3}


def should_auto_execute(response_mode: str, severity: str, min_severity: str) -> bool:
    """완전 자동화 모드이고 심각도가 임계값 이상일 때만 자동 실행."""
    if response_mode != "auto":
        return False
    return SEVERITY_RANK.get(severity, 0) >= SEVERITY_RANK.get(min_severity, 3)


def should_queue_approval(response_mode: str, severity: str, min_severity: str) -> bool:
    """승인 후 실행 모드이고 심각도가 임계값 이상일 때 승인 큐에 적재."""
    if response_mode != "approval":
        return False
    return SEVERITY_RANK.get(severity, 0) >= SEVERITY_RANK.get(min_severity, 2)


def build_actions_from_llm(
    incident_id: str,
    source_ip: str | None,
    username: str | None,
    severity: str,
    recommended_actions: list[str],
) -> list[dict]:
    """LLM recommended_actions 텍스트를 구조화된 액션 목록으로 변환."""
    actions: list[dict] = []
    text = " ".join(recommended_actions).lower()

    if source_ip and any(k in text for k in ["차단", "block", "firewall", "방화벽"]):
        actions.append({
            "action_type": ActionType.BLOCK_IP,
            "target": source_ip,
            "payload": {"ip": source_ip, "incident_id": incident_id},
        })

    if username and any(k in text for k in ["잠금", "lock", "계정", "account"]):
        actions.append({
            "action_type": ActionType.LOCK_ACCOUNT,
            "target": username,
            "payload": {"username": username, "incident_id": incident_id},
        })

    if any(k in text for k in ["에스컬레이션", "escalat", "상향"]):
        actions.append({
            "action_type": ActionType.ESCALATE,
            "target": incident_id,
            "payload": {"incident_id": incident_id},
        })

    # 액션이 없으면 알림만
    if not actions:
        actions.append({
            "action_type": ActionType.NOTIFY,
            "target": incident_id,
            "payload": {"incident_id": incident_id},
        })

    return actions
