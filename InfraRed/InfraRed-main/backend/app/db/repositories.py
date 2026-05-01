"""Small SQL helpers used by the starter workers and API."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import text

from app.db.connection import get_session
from app.models.envelope import NormalizedEvent
from app.models.heartbeat import Heartbeat
from app.models.incident import Incident
from app.models.llm import LLMResult
from app.models.signal import Signal


def _json(data: Any) -> str:
    return json.dumps(data, default=str, ensure_ascii=False)


def _scalar(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if value is None or isinstance(value, (str, int, float, bool, list, dict)):
        return value
    return str(value)


def _row(row: Any) -> dict[str, Any]:
    return {key: _scalar(value) for key, value in dict(row).items()}


async def save_normalized_event(event: NormalizedEvent) -> None:
    payload = {
        "raw_line": event.raw_line,
        "event_type": event.event_type.value,
        "result": event.result,
    }
    async with get_session() as session:
        await session.execute(
            text(
                """
                INSERT INTO normalized_events (
                    event_id, tenant_id, asset_id, agent_id, event_type, timestamp,
                    host, username, source_ip, result, raw_source, late_event, payload
                )
                VALUES (
                    :event_id, :tenant_id, :asset_id, :agent_id, :event_type, :timestamp,
                    :host, :username, :source_ip, :result, :raw_source, :late_event,
                    CAST(:payload AS JSONB)
                )
                ON CONFLICT (event_id) DO NOTHING
                """
            ),
            {
                "event_id": event.event_id,
                "tenant_id": event.tenant_id,
                "asset_id": event.asset_id,
                "agent_id": event.agent_id,
                "event_type": event.event_type.value,
                "timestamp": event.timestamp,
                "host": event.host,
                "username": event.username,
                "source_ip": event.source_ip,
                "result": event.result,
                "raw_source": event.raw_source,
                "late_event": event.late_event,
                "payload": _json(payload),
            },
        )


async def save_signal(signal: Signal) -> None:
    async with get_session() as session:
        await session.execute(
            text(
                """
                INSERT INTO signals (
                    signal_id, tenant_id, asset_id, rule_id, rule_name,
                    mitre_tactic, mitre_technique, mitre_subtechnique, kill_chain_stage,
                    source_ip, username, detected_count, detected_at, window_start,
                    window_end, triggering_event_ids, notes
                )
                VALUES (
                    :signal_id, :tenant_id, :asset_id, :rule_id, :rule_name,
                    :mitre_tactic, :mitre_technique, :mitre_subtechnique, :kill_chain_stage,
                    :source_ip, :username, :detected_count, :detected_at, :window_start,
                    :window_end, CAST(:triggering_event_ids AS JSONB), :notes
                )
                ON CONFLICT (signal_id) DO NOTHING
                """
            ),
            {
                "signal_id": signal.signal_id,
                "tenant_id": signal.tenant_id,
                "asset_id": signal.asset_id,
                "rule_id": signal.rule_id.value,
                "rule_name": signal.rule_name,
                "mitre_tactic": signal.mitre_tactic,
                "mitre_technique": signal.mitre_technique,
                "mitre_subtechnique": signal.mitre_subtechnique,
                "kill_chain_stage": signal.kill_chain_stage.value
                if signal.kill_chain_stage
                else None,
                "source_ip": signal.source_ip,
                "username": signal.username,
                "detected_count": signal.detected_count,
                "detected_at": signal.detected_at,
                "window_start": signal.window_start,
                "window_end": signal.window_end,
                "triggering_event_ids": _json(signal.triggering_event_ids),
                "notes": signal.notes,
            },
        )


async def save_incident(incident: Incident) -> None:
    cti = incident.cti_enrichment.model_dump(mode="json") if incident.cti_enrichment else None
    async with get_session() as session:
        await session.execute(
            text(
                """
                INSERT INTO incidents (
                    incident_id, tenant_id, asset_id, severity, confidence, priority,
                    kill_chain_stage, mitre_tactic, mitre_technique, cti_enrichment,
                    source_ip, username, signal_ids, status, created_at, updated_at
                )
                VALUES (
                    :incident_id, :tenant_id, :asset_id, :severity, :confidence, :priority,
                    :kill_chain_stage, :mitre_tactic, :mitre_technique,
                    CAST(:cti_enrichment AS JSONB), :source_ip, :username,
                    CAST(:signal_ids AS JSONB), 'open', :created_at, :updated_at
                )
                ON CONFLICT (incident_id) DO NOTHING
                """
            ),
            {
                "incident_id": incident.incident_id,
                "tenant_id": incident.tenant_id,
                "asset_id": incident.asset_id,
                "severity": incident.severity.value,
                "confidence": incident.confidence.value,
                "priority": incident.priority.value,
                "kill_chain_stage": incident.kill_chain_stage.value,
                "mitre_tactic": incident.mitre_attack.tactic,
                "mitre_technique": incident.mitre_attack.technique,
                "cti_enrichment": _json(cti),
                "source_ip": incident.source_ip,
                "username": incident.username,
                "signal_ids": _json(incident.signal_ids),
                "created_at": incident.created_at,
                "updated_at": incident.updated_at,
            },
        )
        for item in incident.evidence_timeline:
            await session.execute(
                text(
                    """
                    INSERT INTO incident_evidence (
                        incident_id, tenant_id, timestamp, description, signal_id, rule_id
                    )
                    VALUES (
                        :incident_id, :tenant_id, :timestamp, :description, :signal_id, :rule_id
                    )
                    """
                ),
                {
                    "incident_id": incident.incident_id,
                    "tenant_id": incident.tenant_id,
                    "timestamp": item.timestamp,
                    "description": item.description,
                    "signal_id": item.signal_id,
                    "rule_id": item.rule_id,
                },
            )


async def save_llm_result(result: LLMResult, tenant_id: str) -> None:
    async with get_session() as session:
        await session.execute(
            text(
                """
                INSERT INTO llm_results (
                    incident_id, tenant_id, plain_summary, attack_intent,
                    kill_chain_analysis, recommended_actions, confidence_note,
                    model, cached, generated_at
                )
                VALUES (
                    :incident_id, :tenant_id, :plain_summary, :attack_intent,
                    :kill_chain_analysis, CAST(:recommended_actions AS JSONB),
                    :confidence_note, :model, :cached, :generated_at
                )
                """
            ),
            {
                "incident_id": result.incident_id,
                "tenant_id": tenant_id,
                "plain_summary": result.plain_summary,
                "attack_intent": result.attack_intent,
                "kill_chain_analysis": result.kill_chain_analysis,
                "recommended_actions": _json(result.recommended_actions),
                "confidence_note": result.confidence_note,
                "model": result.model,
                "cached": result.cached,
                "generated_at": result.generated_at,
            },
        )


async def list_incidents(tenant_id: str, limit: int = 50) -> list[dict[str, Any]]:
    async with get_session() as session:
        result = await session.execute(
            text(
                """
                SELECT i.*,
                       latest_llm.plain_summary AS llm_summary,
                       latest_llm.generated_at AS llm_generated_at
                FROM incidents i
                LEFT JOIN LATERAL (
                    SELECT plain_summary, generated_at
                    FROM llm_results l
                    WHERE l.incident_id = i.incident_id
                    ORDER BY generated_at DESC
                    LIMIT 1
                ) latest_llm ON TRUE
                WHERE i.tenant_id = :tenant_id
                ORDER BY i.created_at DESC
                LIMIT :limit
                """
            ),
            {"tenant_id": tenant_id, "limit": limit},
        )
        return [_row(row) for row in result.mappings().all()]


async def get_incident_contract(incident_id: str) -> dict[str, Any] | None:
    async with get_session() as session:
        incident_result = await session.execute(
            text("SELECT * FROM incidents WHERE incident_id = :incident_id"),
            {"incident_id": incident_id},
        )
        incident = incident_result.mappings().first()
        if not incident:
            return None

        evidence_result = await session.execute(
            text(
                """
                SELECT timestamp, description, signal_id, rule_id
                FROM incident_evidence
                WHERE incident_id = :incident_id
                ORDER BY timestamp ASC
                """
            ),
            {"incident_id": incident_id},
        )
        llm_query_result = await session.execute(
            text(
                """
                SELECT *
                FROM llm_results
                WHERE incident_id = :incident_id
                ORDER BY generated_at DESC
                LIMIT 1
                """
            ),
            {"incident_id": incident_id},
        )
        llm_row = llm_query_result.mappings().first()
        return {
            "incident": _row(incident),
            "evidence_timeline": [_row(row) for row in evidence_result.mappings().all()],
            "llm_result": _row(llm_row) if llm_row else None,
        }


async def touch_heartbeat(heartbeat: Heartbeat) -> None:
    now = datetime.now(timezone.utc)
    async with get_session() as session:
        await session.execute(
            text(
                """
                UPDATE agents
                SET status = 'online',
                    last_heartbeat = :last_heartbeat,
                    agent_version = :agent_version
                WHERE tenant_id = :tenant_id AND agent_id = :agent_id
                """
            ),
            {
                "last_heartbeat": heartbeat.sent_at or now,
                "agent_version": heartbeat.agent_version,
                "tenant_id": heartbeat.tenant_id,
                "agent_id": heartbeat.agent_id,
            },
        )
