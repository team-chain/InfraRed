"""Static playbook used when Bedrock is disabled or unavailable."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.models.llm import LLMResult


def summarize_with_playbook(contract: dict[str, Any]) -> LLMResult:
    incident = contract["incident"]
    evidence = contract.get("evidence_timeline", [])
    first_evidence = evidence[0]["description"] if evidence else "No evidence timeline was recorded."
    severity = incident["severity"]
    signal_ids = incident.get("signal_ids") or []
    rule_hint = signal_ids if isinstance(signal_ids, str) else ", ".join(signal_ids)
    source_ip = incident.get('source_ip') or '알 수 없는 IP'
    username = incident.get('username') or '알 수 없는 사용자'
    summary = (
        f"{source_ip}에서 {username} 계정을 대상으로 SSH 인시던트가 감지되었습니다. "
        f"근거: {first_evidence}. "
        f"관련 시그널: {rule_hint or '없음'}."
    )
    return LLMResult(
        incident_id=incident["incident_id"],
        plain_summary=summary,
        attack_intent=(
            "탐지된 규칙 및 로그인 결과에 따라 자격증명 탈취, 무차별 대입 공격, "
            "또는 계정 탈취 시도와 일치하는 활동입니다."
        ),
        kill_chain_analysis=(
            f"현재 단계: {incident['kill_chain_stage']}. "
            f"ATT&CK 매핑: {incident.get('mitre_tactic')} / {incident.get('mitre_technique')}."
        ),
        recommended_actions=[
            "해당 소스 IP 및 대상 계정에 대한 SSH 인증 로그를 검토하세요.",
            "무단 활동으로 확인된 경우 소스 IP를 즉시 차단하세요.",
            "자격증명을 교체하고 권한 계정에 MFA 또는 키 기반 SSH 인증을 적용하세요.",
        ],
        confidence_note=f"스타터 상관관계 규칙 기반으로 신뢰도는 {incident['confidence']}입니다.",
        model="static-playbook",
        cached=False,
        generated_at=datetime.now(timezone.utc),
    )
