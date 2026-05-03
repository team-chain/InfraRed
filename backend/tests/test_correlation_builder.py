"""Unit tests for the incident builder."""
from __future__ import annotations

from datetime import datetime, timezone

from app.common.constants import (
    Confidence,
    KillChainStage,
    Priority,
    RuleId,
    Severity,
)
from app.models.incident import CtiEnrichment
from app.models.signal import Signal
from app.workers.correlation.builder import build_incident


def _signal(
    *,
    rule_id: RuleId = RuleId.AUTH_BRUTE_FORCE,
    detected_count: int = 1,
    stage: KillChainStage = KillChainStage.CREDENTIAL_ACCESS,
    username: str = "root",
    source_ip: str = "185.12.34.56",
) -> Signal:
    return Signal(
        tenant_id="company-a",
        asset_id="asset-001",
        rule_id=rule_id,
        rule_name="test-rule",
        mitre_tactic="Credential Access",
        mitre_technique="T1110.001",
        kill_chain_stage=stage,
        source_ip=source_ip,
        username=username,
        detected_count=detected_count,
        detected_at=datetime(2026, 4, 30, 3, 12, 0, tzinfo=timezone.utc),
        triggering_event_ids=["evt-1"],
    )


def test_failed_then_success_high_severity_no_cti() -> None:
    sig = _signal(rule_id=RuleId.AUTH_FAILED_THEN_SUCCESS, detected_count=2)
    cti = CtiEnrichment(abuse_score=10)

    incident = build_incident(sig, cti)

    assert incident.severity == Severity.HIGH
    assert incident.confidence == Confidence.MEDIUM
    assert incident.priority in {Priority.HIGH, Priority.NORMAL}


def test_failed_then_success_critical_with_high_abuse_score() -> None:
    sig = _signal(rule_id=RuleId.AUTH_FAILED_THEN_SUCCESS, detected_count=5)
    cti = CtiEnrichment(abuse_score=88, country="NL")

    incident = build_incident(sig, cti)

    assert incident.severity == Severity.CRITICAL
    assert incident.priority == Priority.URGENT
    assert incident.confidence == Confidence.HIGH


def test_brute_force_high_when_count_high() -> None:
    sig = _signal(rule_id=RuleId.AUTH_BRUTE_FORCE, detected_count=6)
    cti = CtiEnrichment(abuse_score=20)

    incident = build_incident(sig, cti)
    assert incident.severity == Severity.HIGH


def test_evidence_includes_kill_chain_transition_when_advanced() -> None:
    sig = _signal(stage=KillChainStage.INITIAL_ACCESS)
    cti = CtiEnrichment()

    incident = build_incident(sig, cti, advanced_from="Reconnaissance")

    descriptions = [item.description for item in incident.evidence_timeline]
    assert any("Kill chain transition" in d for d in descriptions)
    assert any("Reconnaissance -> Initial Access" in d for d in descriptions)


def test_evidence_description_includes_country_when_available() -> None:
    sig = _signal()
    cti = CtiEnrichment(country="KR", abuse_score=42)

    incident = build_incident(sig, cti)

    description = incident.evidence_timeline[0].description
    assert "country=KR" in description
    assert "abuse_score=42" in description
