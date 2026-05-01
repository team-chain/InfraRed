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
    summary = (
        f"{severity.upper()} SSH incident from {incident.get('source_ip') or 'unknown IP'} "
        f"against user {incident.get('username') or 'unknown'}. "
        f"Evidence: {first_evidence}. "
        f"Signals: {rule_hint or 'n/a'}."
    )
    return LLMResult(
        incident_id=incident["incident_id"],
        plain_summary=summary,
        attack_intent=(
            "The activity is consistent with credential discovery, brute force, or account takeover "
            "depending on the matched rule and login outcome."
        ),
        kill_chain_analysis=(
            f"Current stage: {incident['kill_chain_stage']}. "
            f"Mapped ATT&CK: {incident.get('mitre_tactic')} / {incident.get('mitre_technique')}."
        ),
        recommended_actions=[
            "Review SSH authentication logs for the source IP and target user.",
            "Temporarily block the source IP if activity is unauthorized.",
            "Rotate credentials and verify MFA or key-only SSH for privileged accounts.",
        ],
        confidence_note=f"Confidence is {incident['confidence']} based on starter correlation rules.",
        model="static-playbook",
        cached=False,
        generated_at=datetime.now(timezone.utc),
    )
