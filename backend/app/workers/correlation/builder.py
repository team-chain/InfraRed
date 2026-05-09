"""Incident builder for enriched signals.

Pure function: takes a Signal + CTI enrichment (and an optional
``advanced_from`` kill-chain note) and returns an :class:`Incident`. The
correlation worker hands the result to ``save_or_merge_incident``. Severity /
confidence / priority logic lives here so it is easy to tune in isolation.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from app.common.constants import Confidence, KillChainStage, Priority, RuleId, Severity
from app.models.incident import CtiEnrichment, EvidenceItem, Incident, MitreAttack
from app.models.signal import Signal


def _incident_id(now: datetime) -> str:
    return f"INC-{now.strftime('%Y%m%d')}-{uuid4().hex[:8].upper()}"


def _severity(signal: Signal, cti: CtiEnrichment) -> Severity:
    abuse = cti.abuse_score or 0
    if signal.rule_id == RuleId.AUTH_FAILED_THEN_SUCCESS:
        return Severity.CRITICAL if abuse >= 70 else Severity.HIGH
    if signal.rule_id == RuleId.AUTH_ROOT_LOGIN:
        if signal.detected_count >= 1 and abuse >= 70:
            return Severity.CRITICAL
        return Severity.HIGH
    if signal.rule_id == RuleId.AUTH_BRUTE_FORCE and signal.detected_count >= 5:
        return Severity.HIGH
    if signal.rule_id in {RuleId.AUTH_BRUTE_FORCE, RuleId.AUTH_INVALID_USER}:
        return Severity.MEDIUM
    if signal.rule_id == RuleId.AUTH_SUSPICIOUS_LOGIN:
        return Severity.MEDIUM if abuse >= 40 else Severity.INFO
    return Severity.INFO


def _confidence(signal: Signal, cti: CtiEnrichment) -> Confidence:
    abuse = cti.abuse_score or 0
    if signal.detected_count >= 5 or abuse >= 70:
        return Confidence.HIGH
    if signal.detected_count >= 2 or abuse >= 40:
        return Confidence.MEDIUM
    return Confidence.LOW


def _priority(severity: Severity, confidence: Confidence) -> Priority:
    if severity == Severity.CRITICAL:
        return Priority.URGENT
    if severity == Severity.HIGH and confidence in {Confidence.HIGH, Confidence.MEDIUM}:
        return Priority.HIGH
    if severity == Severity.HIGH:
        return Priority.NORMAL
    if severity == Severity.MEDIUM:
        return Priority.NORMAL
    return Priority.LOW


def _evidence_description(signal: Signal, cti: CtiEnrichment) -> str:
    parts: list[str] = [
        f"{signal.rule_id.value} {signal.rule_name}",
        f"{signal.detected_count} event(s)",
        f"user={signal.username or '-'}",
        f"source_ip={signal.source_ip or '-'}",
    ]
    if cti.country:
        parts.append(f"country={cti.country}")
    if cti.abuse_score is not None:
        parts.append(f"abuse_score={cti.abuse_score}")
    return " | ".join(parts)


def build_incident(
    signal: Signal,
    cti: CtiEnrichment,
    *,
    advanced_from: Optional[str] = None,
) -> Incident:
    now = datetime.now(timezone.utc)
    severity = _severity(signal, cti)
    confidence = _confidence(signal, cti)

    evidence_items: list[EvidenceItem] = [
        EvidenceItem(
            timestamp=signal.detected_at,
            description=_evidence_description(signal, cti),
            signal_id=signal.signal_id,
            rule_id=signal.rule_id.value,
        )
    ]
    if advanced_from and signal.kill_chain_stage:
        evidence_items.append(
            EvidenceItem(
                timestamp=signal.detected_at,
                description=(
                    f"Kill chain transition: {advanced_from} "
                    f"-> {signal.kill_chain_stage.value} for "
                    f"source_ip={signal.source_ip or '-'}"
                ),
                signal_id=signal.signal_id,
                rule_id=signal.rule_id.value,
            )
        )

    stage = signal.kill_chain_stage or KillChainStage.RECONNAISSANCE

    # Attach user_agent from signal (web events) into cti if not already set
    enriched_cti = cti
    if getattr(signal, "user_agent", None) and not cti.user_agent:
        enriched_cti = cti.model_copy(update={"user_agent": signal.user_agent})

    return Incident(
        incident_id=_incident_id(now),
        tenant_id=signal.tenant_id,
        asset_id=signal.asset_id,
        severity=severity,
        confidence=confidence,
        priority=_priority(severity, confidence),
        kill_chain_stage=stage,
        mitre_attack=MitreAttack(
            tactic=signal.mitre_tactic or "Unknown",
            technique=signal.mitre_technique or "Unknown",
        ),
        cti_enrichment=enriched_cti,
        evidence_timeline=evidence_items,
        signal_ids=[signal.signal_id],
        source_ip=signal.source_ip,
        username=signal.username,
        created_at=now,
        updated_at=now,
    )
