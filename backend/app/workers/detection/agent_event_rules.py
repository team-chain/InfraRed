"""Agent-side pre-classified event handler.

Agent (fim_watcher, TmpExecutionMonitor 등)가 사전에 rule_id를 매겨서
보낸 이벤트를 그대로 Signal로 변환한다. parser 분기에서 raw_source가
"fim" 또는 "exec"일 때 호출됨.

Agent가 보내는 envelope 형식 (RawEventEnvelope + extra fields):
  {
    "event_id": "FIM-...",
    "raw_source": "fim",
    "rule_id": "FIM-001" | "EXEC-001" | ...,
    "event_type": "fim_change" | "suspicious_process_execution" | ...,
    "mitre_technique": "T1098.001",
    "description": "...",
    "payload": {"path": "...", "pid": "...", "exe_path": "...", ...},
  }

대부분 즉시 INCIDENT로 escalation (이미 룰 매칭이 끝난 이벤트).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.common.constants import KillChainStage, RuleId
from app.models.envelope import RawEventEnvelope
from app.models.signal import Signal

# 룰 이름 + 기본 MITRE / Kill Chain 매핑
_RULE_META: dict[str, dict[str, Any]] = {
    "FIM-001": {
        "name": "/root/.ssh/authorized_keys 변조",
        "mitre_tactic": "Persistence",
        "mitre_technique": "T1098.004",
        "kill_chain_stage": KillChainStage.INSTALLATION,
    },
    "FIM-002": {
        "name": "sshd_config 변조",
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1562.004",
        "kill_chain_stage": KillChainStage.INSTALLATION,
    },
    "FIM-003": {
        "name": "/etc/crontab 변조",
        "mitre_tactic": "Persistence",
        "mitre_technique": "T1053.003",
        "kill_chain_stage": KillChainStage.INSTALLATION,
    },
    "FIM-004": {
        "name": "/etc/passwd 변조",
        "mitre_tactic": "Persistence",
        "mitre_technique": "T1136.001",
        "kill_chain_stage": KillChainStage.INSTALLATION,
    },
    "FIM-005": {
        "name": "/etc/sudoers 변조",
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "T1548.003",
        "kill_chain_stage": KillChainStage.PRIVILEGE_ESCALATION,
    },
    "EXEC-001": {
        "name": "/tmp 계열에서 실행 중인 프로세스",
        "mitre_tactic": "Execution",
        "mitre_technique": "T1059",
        "kill_chain_stage": KillChainStage.EXECUTION,
    },
    "EXEC-002": {
        "name": "웹서버 child process가 shell",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1505.003",
        "kill_chain_stage": KillChainStage.INSTALLATION,
    },
    "EXEC-003": {
        "name": "대량 파일 변경 (랜섬웨어 의심)",
        "mitre_tactic": "Impact",
        "mitre_technique": "T1486",
        "kill_chain_stage": KillChainStage.ACTIONS_ON_OBJECTIVES,
    },
}


def _extract_rule_id(envelope: RawEventEnvelope) -> str | None:
    """envelope.extra 또는 model_dump에서 rule_id 추출."""
    data = envelope.model_dump()
    return data.get("rule_id")


def _extract_payload(envelope: RawEventEnvelope) -> dict[str, Any]:
    data = envelope.model_dump()
    payload = data.get("payload")
    return payload if isinstance(payload, dict) else {}


def is_agent_event(envelope: RawEventEnvelope) -> bool:
    """raw_source가 agent-side 사전 분류 이벤트인지."""
    return (envelope.raw_source or "").lower() in {"fim", "exec", "agent.fim", "agent.exec"}


async def evaluate_agent_event(envelope: RawEventEnvelope) -> list[Signal]:
    """agent 사전 분류 이벤트 → Signal 변환.

    rule_id가 RuleId enum에 매칭되면 즉시 Signal 생성 (escalate=True).
    매칭 안 되면 빈 리스트 반환.
    """
    rule_id_str = _extract_rule_id(envelope)
    if not rule_id_str:
        return []

    # RuleId enum 매칭
    try:
        rule_id = RuleId(rule_id_str)
    except ValueError:
        # enum에 없는 룰 — 알 수 없는 agent 이벤트
        return []

    meta = _RULE_META.get(rule_id_str, {})
    payload = _extract_payload(envelope)

    # source_ip 우선순위: envelope.source_ip → payload.source_ip
    source_ip = envelope.source_ip or payload.get("source_ip")
    # username 우선: envelope → payload (예: passwd 변조 시 영향받은 user)
    username = envelope.username or payload.get("username")

    # notes에 핵심 페이로드 요약
    note_parts: list[str] = []
    for key in ("path", "exe_path", "cmdline", "pid", "old_hash", "new_hash",
                "parent_process", "child_process", "change_count"):
        if payload.get(key):
            note_parts.append(f"{key}={payload[key]}")
    notes = " · ".join(note_parts) or None

    signal = Signal(
        tenant_id=envelope.tenant_id,
        asset_id=envelope.asset_id or "",
        rule_id=rule_id,
        rule_name=meta.get("name") or rule_id_str,
        mitre_tactic=meta.get("mitre_tactic"),
        mitre_technique=meta.get("mitre_technique") or envelope.model_dump().get("mitre_technique"),
        kill_chain_stage=meta.get("kill_chain_stage"),
        source_ip=source_ip,
        username=username,
        detected_count=1,
        detected_at=envelope.timestamp or datetime.now(timezone.utc),
        triggering_event_ids=[envelope.event_id],
        notes=notes,
        escalate_to_incident=True,  # 사전 분류된 high-confidence 이벤트
    )
    return [signal]
