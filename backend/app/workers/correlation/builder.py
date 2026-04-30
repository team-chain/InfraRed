"""Incident builder for enriched signals."""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from app.common.constants import Confidence, Priority, RuleId, Severity
from app.models.incident import CtiEnrichment, EvidenceItem, Incident, MitreAttack
from app.models.signal import Signal


def _incident_id(now: datetime) -> str:
    return f"INC-{now.strftime('%Y%m%d')}-{uuid4().hex[:8].upper()}"


def _severity(signal: Signal, cti: CtiEnrichment) -> Severity:
    if signal.rule_id == RuleId.AUTH_FAILED_THEN_SUCCESS:
        return Severity.CRITICAL if (cti.abuse_score or 0) >= 70 else Severity.HIGH
    if signal.rule_id == RuleId.AUTH_ROOT_LOGIN:
        return Severity.HIGH
    if signal.rule_id == RuleId.AUTH_BRUTE_FORCE and signal.detected_count >= 5:
        return Severity.HIGH
    if signal.rule_id in {RuleId.AUTH_BRUTE_FORCE, RuleId.AUTH_INVALID_USER}:
        return Severity.MEDIUM
    return Severity.INFO


def _confidence(signal: Signal) -> Confidence:
    if signal.detected_count >= 5:
        return Confidence.HIGH
    if signal.detected_count >= 2:
        return Confidence.MEDIUM
    return Confidence.LOW


def _priority(severity: Severity, confidence: Confidence) -> Priority:
    if severity == Severity.CRITICAL:
        return Priority.URGENT
    if severity == Severity.HIGH and confidence in {Confidence.HIGH, Confidence.MEDIUM}:
        return Priority.HIGH
    if severity == Severity.MEDIUM:
        return Priority.NORMAL
    return Priority.LOW


def build_incident(signal: Signal, cti: CtiEnrichment) -> Incident:
    now = datetime.now(timezone.utc)
    severity = _severity(signal, cti)
    confidence = _confidence(signal)
    evidence = EvidenceItem(
        timestamp=signal.detected_at,
        description=(
            f"{signal.rule_id.value} {signal.rule_name}: "
            f"{signal.detected_count} event(s), user={signal.username or '-'}, "
            f"source_ip={signal.source_ip or '-'}"
        ),
        signal_id=signal.signal_id,
        rule_id=signal.rule_id.value,
    )
    return Incident(
        incident_id=_incident_id(now),
        tenant_id=signal.tenant_id,
        asset_id=signal.asset_id,
        severity=severity,
        confidence=confidence,
        priority=_priority(severity, confidence),
        kill_chain_stage=signal.kill_chain_stage,
        mitre_attack=MitreAttack(
            tactic=signal.mitre_tactic or "Unknown",
            technique=signal.mitre_technique or "Unknown",
        ),
        cti_enrichment=cti,
        evidence_timeline=[evidence],
        signal_ids=[signal.signal_id],
        source_ip=signal.source_ip,
        username=signal.username,
        created_at=now,
        updated_at=now,
    )
