"""Small SQL helpers used by the starter workers and API."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import text

from app.common.constants import Confidence, KillChainStage, Priority, Severity
from app.db.connection import get_session
from app.models.auto_response import AutoResponseLog
from app.models.demo_signal import DemoSignal
from app.models.envelope import NormalizedEvent
from app.models.heartbeat import Heartbeat
from app.models.incident import CtiEnrichment, Incident
from app.models.llm import LLMPendingRow, LLMResult
from app.models.signal import Signal


def _incident_merge_window() -> timedelta:
    from app.config import get_settings
    return timedelta(minutes=get_settings().incident_merge_window_minutes)

_SEVERITY_RANK = {
    Severity.INFO.value: 0,
    Severity.MEDIUM.value: 1,
    Severity.HIGH.value: 2,
    Severity.CRITICAL.value: 3,
}
_CONFIDENCE_RANK = {
    Confidence.LOW.value: 0,
    Confidence.MEDIUM.value: 1,
    Confidence.HIGH.value: 2,
}
_PRIORITY_RANK = {
    Priority.LOW.value: 0,
    Priority.NORMAL.value: 1,
    Priority.HIGH.value: 2,
    Priority.URGENT.value: 3,
}
_STAGE_RANK = {
    KillChainStage.RECONNAISSANCE.value: 0,
    KillChainStage.CREDENTIAL_ACCESS.value: 1,
    KillChainStage.INITIAL_ACCESS.value: 2,
    KillChainStage.EXECUTION.value: 3,
    KillChainStage.PRIVILEGE_ESCALATION.value: 4,
    KillChainStage.DEFENSE_EVASION.value: 5,
    KillChainStage.EXFILTRATION.value: 6,
}


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


def _json_value(value: Any, fallback: Any) -> Any:
    if value is None:
        return fallback
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return fallback
    return value


def _json_list(value: Any) -> list[str]:
    parsed = _json_value(value, [])
    if not isinstance(parsed, list):
        return []
    return [str(item) for item in parsed]


def _json_dict(value: Any) -> dict[str, Any]:
    parsed = _json_value(value, {})
    return parsed if isinstance(parsed, dict) else {}


def _string_list(value: Any) -> list[str]:
    return [str(item) for item in value] if isinstance(value, list) else []


def _max_ranked(existing: str | None, incoming: str | None, rank: dict[str, int]) -> str:
    if not existing:
        return incoming or ""
    if not incoming:
        return existing
    return incoming if rank.get(incoming, -1) > rank.get(existing, -1) else existing


def _merge_signal_ids(existing: Any, incoming: list[str]) -> list[str]:
    merged = _json_list(existing)
    for signal_id in incoming:
        if signal_id not in merged:
            merged.append(signal_id)
    return merged


def _incident_anchor_time(incident: Incident) -> datetime:
    if not incident.evidence_timeline:
        return incident.created_at
    return min(item.timestamp for item in incident.evidence_timeline)


def _merge_cti(existing: Any, incoming: CtiEnrichment | None) -> dict[str, Any] | None:
    existing_cti = _json_dict(existing)
    incoming_cti = incoming.model_dump(mode="json") if incoming else {}
    if not existing_cti and not incoming_cti:
        return None

    abuse_score = max(
        int(existing_cti.get("abuse_score") or 0),
        int(incoming_cti.get("abuse_score") or 0),
    )
    tags = sorted(
        {*_string_list(existing_cti.get("tags")), *_string_list(incoming_cti.get("tags"))}
    )
    sources = sorted(
        {*_string_list(existing_cti.get("sources")), *_string_list(incoming_cti.get("sources"))}
    )
    prefer_incoming = int(incoming_cti.get("abuse_score") or 0) >= int(
        existing_cti.get("abuse_score") or 0
    )
    preferred = incoming_cti if prefer_incoming else existing_cti
    return {
        "abuse_score": abuse_score,
        "country": preferred.get("country"),
        "city": preferred.get("city") or existing_cti.get("city") or incoming_cti.get("city"),
        "asn_org": preferred.get("asn_org") or existing_cti.get("asn_org") or incoming_cti.get("asn_org"),
        "user_agent": existing_cti.get("user_agent") or incoming_cti.get("user_agent"),
        "tags": tags,
        "sources": sources,
        "note": preferred.get("note") or existing_cti.get("note") or incoming_cti.get("note"),
    }


async def _insert_incident_evidence(session: Any, incident: Incident, incident_id: str) -> None:
    for item in incident.evidence_timeline:
        params = {
            "incident_id": incident_id,
            "tenant_id": incident.tenant_id,
            "timestamp": item.timestamp,
            "description": item.description,
            "signal_id": item.signal_id,
            "rule_id": item.rule_id,
        }
        if item.signal_id:
            await session.execute(
                text(
                    """
                    INSERT INTO incident_evidence (
                        incident_id, tenant_id, timestamp, description, signal_id, rule_id
                    )
                    SELECT
                        :incident_id, :tenant_id, :timestamp, :description,
                        CAST(:signal_id AS TEXT), CAST(:rule_id AS TEXT)
                    WHERE NOT EXISTS (
                        SELECT 1
                        FROM incident_evidence
                        WHERE incident_id = :incident_id
                          AND signal_id = :signal_id
                    )
                    """
                ),
                params,
            )
            continue

        await session.execute(
            text(
                """
                INSERT INTO incident_evidence (
                    incident_id, tenant_id, timestamp, description, signal_id, rule_id
                )
                SELECT
                    :incident_id, :tenant_id, :timestamp, :description,
                    CAST(:signal_id AS TEXT), CAST(:rule_id AS TEXT)
                WHERE NOT EXISTS (
                    SELECT 1
                    FROM incident_evidence
                    WHERE incident_id = :incident_id
                      AND description = :description
                )
                """
            ),
            params,
        )


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
        await _insert_incident_evidence(session, incident, incident.incident_id)


async def save_or_merge_incident(incident: Incident) -> tuple[str, bool]:
    """Persist a new incident or merge the signal into an active correlated incident.

    B MVP correlation groups SSH activity by tenant, asset, and source IP. This keeps
    reconnaissance, brute-force, root-account, and failed-then-success signals in one
    investigation timeline instead of creating one incident per rule hit.
    """

    cti = incident.cti_enrichment.model_dump(mode="json") if incident.cti_enrichment else None
    anchor_at = _incident_anchor_time(incident)
    merge_window = _incident_merge_window()
    window_start = anchor_at - merge_window
    window_end = anchor_at + merge_window
    async with get_session() as session:
        existing_params = {
            "tenant_id": incident.tenant_id,
            "asset_id": incident.asset_id,
            "window_start": window_start,
            "window_end": window_end,
        }
        if incident.source_ip:
            existing_result = await session.execute(
                text(
                    """
                    SELECT i.*
                    FROM incidents i
                    WHERE i.tenant_id = :tenant_id
                      AND i.asset_id = :asset_id
                      AND i.status IN ('open', 'acknowledged')
                      AND i.source_ip = CAST(:source_ip AS INET)
                      AND EXISTS (
                          SELECT 1
                          FROM incident_evidence e
                          WHERE e.incident_id = i.incident_id
                            AND e.timestamp BETWEEN :window_start AND :window_end
                      )
                    ORDER BY i.updated_at DESC
                    LIMIT 1
                    FOR UPDATE OF i
                    """
                ),
                {**existing_params, "source_ip": incident.source_ip},
            )
        else:
            existing_result = await session.execute(
                text(
                    """
                    SELECT i.*
                    FROM incidents i
                    WHERE i.tenant_id = :tenant_id
                      AND i.asset_id = :asset_id
                      AND i.status IN ('open', 'acknowledged')
                      AND i.source_ip IS NULL
                      AND COALESCE(i.username, '') = COALESCE(:username, '')
                      AND EXISTS (
                          SELECT 1
                          FROM incident_evidence e
                          WHERE e.incident_id = i.incident_id
                            AND e.timestamp BETWEEN :window_start AND :window_end
                      )
                    ORDER BY i.updated_at DESC
                    LIMIT 1
                    FOR UPDATE OF i
                    """
                ),
                {**existing_params, "username": incident.username},
            )
        existing = existing_result.mappings().first()
        if existing is None:
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
            await _insert_incident_evidence(session, incident, incident.incident_id)
            return incident.incident_id, True

        existing_id = existing["incident_id"]
        merged_stage = _max_ranked(
            existing["kill_chain_stage"],
            incident.kill_chain_stage.value,
            _STAGE_RANK,
        )
        incoming_drives_mitre = (
            _STAGE_RANK.get(incident.kill_chain_stage.value, -1)
            >= _STAGE_RANK.get(existing["kill_chain_stage"], -1)
        )
        username = existing["username"]
        if not username or incident.username == "root":
            username = incident.username or username

        await session.execute(
            text(
                """
                UPDATE incidents
                SET severity = :severity,
                    confidence = :confidence,
                    priority = :priority,
                    kill_chain_stage = :kill_chain_stage,
                    mitre_tactic = :mitre_tactic,
                    mitre_technique = :mitre_technique,
                    cti_enrichment = CAST(:cti_enrichment AS JSONB),
                    username = :username,
                    signal_ids = CAST(:signal_ids AS JSONB),
                    updated_at = :updated_at
                WHERE incident_id = :incident_id
                """
            ),
            {
                "incident_id": existing_id,
                "severity": _max_ranked(
                    existing["severity"],
                    incident.severity.value,
                    _SEVERITY_RANK,
                ),
                "confidence": _max_ranked(
                    existing["confidence"],
                    incident.confidence.value,
                    _CONFIDENCE_RANK,
                ),
                "priority": _max_ranked(
                    existing["priority"],
                    incident.priority.value,
                    _PRIORITY_RANK,
                ),
                "kill_chain_stage": merged_stage,
                "mitre_tactic": (
                    incident.mitre_attack.tactic
                    if incoming_drives_mitre
                    else existing["mitre_tactic"]
                ),
                "mitre_technique": (
                    incident.mitre_attack.technique
                    if incoming_drives_mitre
                    else existing["mitre_technique"]
                ),
                "cti_enrichment": _json(
                    _merge_cti(existing["cti_enrichment"], incident.cti_enrichment)
                ),
                "username": username,
                "signal_ids": _json(
                    _merge_signal_ids(existing["signal_ids"], incident.signal_ids)
                ),
                "updated_at": incident.updated_at,
            },
        )
        await _insert_incident_evidence(session, incident, existing_id)
        return existing_id, False


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
                # asyncpg는 timezone-aware datetime을 요구함 (TIMESTAMPTZ)
                "generated_at": (
                    result.generated_at
                    if result.generated_at.tzinfo is not None
                    else result.generated_at.replace(tzinfo=timezone.utc)
                ),
            },
        )


async def authenticate_user(
    *,
    tenant_id: str,
    email: str,
    password: str,
) -> dict[str, Any] | None:
    async with get_session() as session:
        result = await session.execute(
            text(
                """
                SELECT user_id::text, tenant_id, email, role
                FROM users
                WHERE tenant_id = :tenant_id
                  AND email = :email
                  AND password_hash = crypt(:password, password_hash)
                """
            ),
            {"tenant_id": tenant_id, "email": email, "password": password},
        )
        row = result.mappings().first()
        return _row(row) if row else None


async def register_user(
    *,
    tenant_id: str,
    email: str,
    password: str,
    role: str = "analyst",
) -> dict[str, Any] | None:
    """신규 사용자 가입.

    가입 후 동일 이메일에 대한 pending_invitations (모든 테넌트)을 조회하여
    자동으로 tenant_memberships에 적용. 적용된 pending은 삭제.
    """
    async with get_session() as session:
        # Self-serve 가입 — tenant가 없으면 자동 생성 (첫 사용자가 곧 그 조직 owner).
        # 기존 tenant에 두 번째 사용자가 합류하는 경우엔 ON CONFLICT로 no-op.
        # 신규 tenant 생성 시에만 role을 "owner"로 강제 (페이로드의 role 무시).
        is_new_tenant_result = await session.execute(
            text(
                """
                INSERT INTO tenants (tenant_id, name, plan)
                VALUES (:tenant_id, :tenant_id, 'mvp')
                ON CONFLICT (tenant_id) DO NOTHING
                RETURNING tenant_id
                """
            ),
            {"tenant_id": tenant_id},
        )
        is_new_tenant = is_new_tenant_result.first() is not None
        effective_role = "owner" if is_new_tenant else role

        result = await session.execute(
            text(
                """
                INSERT INTO users (tenant_id, email, password_hash, role)
                VALUES (:tenant_id, :email, crypt(:password, gen_salt('bf')), :role)
                ON CONFLICT (tenant_id, email) DO NOTHING
                RETURNING user_id::text, tenant_id, email, role
                """
            ),
            {
                "tenant_id": tenant_id,
                "email": email,
                "password": password,
                "role": effective_role,
            },
        )
        row = result.mappings().first()
        if not row:
            # tenant는 있지만 동일 (tenant_id, email)이 이미 존재.
            return None

        user_id = row["user_id"]

        # 가입 tenant의 멤버십도 추가 (기존 사용자 흐름과 호환 위해 idempotent)
        await session.execute(
            text(
                """
                INSERT INTO tenant_memberships (tenant_id, user_id, role)
                VALUES (:tenant_id, :user_id, :role)
                ON CONFLICT (tenant_id, user_id) DO NOTHING
                """
            ),
            {"tenant_id": tenant_id, "user_id": user_id, "role": effective_role},
        )

        # pending_invitations 적용 (만료되지 않은 모든 테넌트의 초대)
        pending_result = await session.execute(
            text(
                """
                SELECT id, tenant_id, role
                FROM pending_invitations
                WHERE email = :email AND expires_at > NOW()
                """
            ),
            {"email": email},
        )
        pending_rows = pending_result.mappings().fetchall()

        for inv in pending_rows:
            await session.execute(
                text(
                    """
                    INSERT INTO tenant_memberships (tenant_id, user_id, role)
                    VALUES (:tenant_id, :user_id, :role)
                    ON CONFLICT (tenant_id, user_id) DO NOTHING
                    """
                ),
                {
                    "tenant_id": inv["tenant_id"],
                    "user_id": user_id,
                    "role": inv["role"],
                },
            )

        # 적용된 pending 모두 삭제
        await session.execute(
            text(
                "DELETE FROM pending_invitations WHERE email = :email"
            ),
            {"email": email},
        )

        return _row(row)


async def list_detection_rules(tenant_id: str | None = None) -> list[dict[str, Any]]:
    async with get_session() as session:
        result = await session.execute(
            text(
                """
                SELECT rule_id, name, source, mitre_tactic, mitre_technique,
                       enabled, config, created_at
                FROM detection_rules
                ORDER BY rule_id ASC
                """
            )
        )
        return [_row(row) for row in result.mappings().all()]


async def list_assets(tenant_id: str) -> list[dict[str, Any]]:
    async with get_session() as session:
        result = await session.execute(
            text("""
                SELECT a.asset_id, a.hostname, a.os,
                       ag.status, ag.last_heartbeat, ag.agent_version
                FROM assets a
                LEFT JOIN agents ag ON ag.asset_id = a.asset_id
                WHERE a.tenant_id = :tenant_id
                ORDER BY a.created_at DESC
            """),
            {"tenant_id": tenant_id},
        )
        return [_row(row) for row in result.mappings().all()]


async def list_audit_logs(tenant_id: str, limit: int = 100) -> list[dict[str, Any]]:
    async with get_session() as session:
        result = await session.execute(
            text(
                """
                SELECT id, tenant_id, actor, action, resource, ip, timestamp, metadata
                FROM audit_logs
                WHERE tenant_id = :tenant_id
                ORDER BY timestamp DESC
                LIMIT :limit
                """
            ),
            {"tenant_id": tenant_id, "limit": limit},
        )
        return [_row(row) for row in result.mappings().all()]


async def update_incident_status(
    *,
    tenant_id: str,
    incident_id: str,
    status: str,
) -> dict[str, Any] | None:
    async with get_session() as session:
        result = await session.execute(
            text(
                """
                UPDATE incidents
                SET status = :status,
                    updated_at = NOW()
                WHERE tenant_id = :tenant_id
                  AND incident_id = :incident_id
                RETURNING *
                """
            ),
            {"tenant_id": tenant_id, "incident_id": incident_id, "status": status},
        )
        row = result.mappings().first()
        return _row(row) if row else None


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


async def upsert_known_ip(
    tenant_id: str, asset_id: str, username: str, source_ip: str
) -> None:
    """Insert or update a known IP for the given user. Used by AUTH-005."""
    async with get_session() as session:
        await session.execute(
            text(
                """
                INSERT INTO known_ips (tenant_id, asset_id, username, source_ip, first_seen, last_seen)
                VALUES (:tenant_id, :asset_id, :username, CAST(:source_ip AS INET), NOW(), NOW())
                ON CONFLICT (tenant_id, asset_id, username, source_ip)
                DO UPDATE SET last_seen = NOW()
                """
            ),
            {
                "tenant_id": tenant_id,
                "asset_id": asset_id,
                "username": username,
                "source_ip": source_ip,
            },
        )


async def get_known_ip_count(tenant_id: str, asset_id: str, username: str) -> int:
    """Return how many distinct IPs have been seen for this user."""
    async with get_session() as session:
        result = await session.execute(
            text(
                """
                SELECT COUNT(*) FROM known_ips
                WHERE tenant_id = :tenant_id
                  AND asset_id = :asset_id
                  AND username = :username
                """
            ),
            {"tenant_id": tenant_id, "asset_id": asset_id, "username": username},
        )
        return int(result.scalar() or 0)


async def is_known_ip_for_user(
    tenant_id: str, asset_id: str, username: str, source_ip: str
) -> bool:
    """Check if this IP has been seen before for this user."""
    async with get_session() as session:
        result = await session.execute(
            text(
                """
                SELECT 1 FROM known_ips
                WHERE tenant_id = :tenant_id
                  AND asset_id = :asset_id
                  AND username = :username
                  AND source_ip = CAST(:source_ip AS INET)
                LIMIT 1
                """
            ),
            {
                "tenant_id": tenant_id,
                "asset_id": asset_id,
                "username": username,
                "source_ip": source_ip,
            },
        )
        return result.first() is not None


async def touch_heartbeat(heartbeat: Heartbeat) -> None:
    """Heartbeat 수신 처리.

    설계서 v2.0 Phase 3-D:
    - status="online"     → 정상 갱신 (last_heartbeat, agent_version 업데이트)
    - status="deactivated" → StartLimitBurst(5회) 초과 종료 직전 보고.
                             deactivated_at / deactivation_reason 기록,
                             헬스체크 대시보드에 즉시 반영.
    """
    now = datetime.now(timezone.utc)
    async with get_session() as session:
        if heartbeat.status == "deactivated":
            # 에이전트가 5회 연속 실패 후 systemd에 의해 Deactivated 되기 직전 보고
            reason = heartbeat.deactivation_reason or "StartLimitBurst exceeded (5 consecutive failures)"
            await session.execute(
                text(
                    """
                    UPDATE agents
                    SET status           = 'deactivated',
                        last_heartbeat   = :last_heartbeat,
                        agent_version    = :agent_version,
                        deactivated_at   = :deactivated_at,
                        deactivation_reason = :reason
                    WHERE tenant_id = :tenant_id AND agent_id = :agent_id
                    """
                ),
                {
                    "last_heartbeat": heartbeat.sent_at or now,
                    "agent_version": heartbeat.agent_version,
                    "tenant_id": heartbeat.tenant_id,
                    "agent_id": heartbeat.agent_id,
                    "deactivated_at": now,
                    "reason": reason,
                },
            )
        else:
            await session.execute(
                text(
                    """
                    UPDATE agents
                    SET status         = 'online',
                        last_heartbeat = :last_heartbeat,
                        agent_version  = :agent_version
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


async def save_demo_signal(signal: DemoSignal) -> None:
    """Honeypot /demo 방문자 정보 저장 (incidents와 물리 분리, 설계서 17.3)."""
    async with get_session() as session:
        await session.execute(
            text("""
                INSERT INTO demo_signals (
                    demo_signal_id, tenant_id, asset_id,
                    source_ip, source_ip_hash,
                    country, region, accuracy_radius,
                    device_type, os_family, browser_family, accept_language,
                    path, severity, detected_at, expires_at
                )
                VALUES (
                    :demo_signal_id, :tenant_id, :asset_id,
                    :source_ip, :source_ip_hash,
                    :country, :region, :accuracy_radius,
                    :device_type, :os_family, :browser_family, :accept_language,
                    :path, :severity, :detected_at,
                    :detected_at + INTERVAL '24 hours'
                )
                ON CONFLICT (demo_signal_id) DO NOTHING
            """),
            {
                "demo_signal_id": signal.demo_signal_id,
                "tenant_id": signal.tenant_id,
                "asset_id": signal.asset_id,
                "source_ip": signal.source_ip_masked,
                "source_ip_hash": signal.source_ip_hash,
                "country": signal.geo.country if signal.geo else None,
                "region": signal.geo.region if signal.geo else None,
                "accuracy_radius": signal.geo.accuracy_radius if signal.geo else None,
                "device_type": signal.device.device_type if signal.device else None,
                "os_family": signal.device.os_family if signal.device else None,
                "browser_family": signal.device.browser_family if signal.device else None,
                "accept_language": signal.device.accept_language if signal.device else None,
                "path": signal.path,
                "severity": signal.severity,
                "detected_at": signal.detected_at,
            },
        )
        await session.commit()


async def save_llm_pending(pending: LLMPendingRow) -> None:
    """LLM 호출 시작 시 즉시 pending row 생성 (설계서 9.3)."""
    async with get_session() as session:
        await session.execute(
            text("""
                INSERT INTO llm_results (
                    incident_id, tenant_id, status, plain_summary, model, cached, generated_at
                )
                VALUES (
                    :incident_id, :tenant_id, 'pending', NULL, 'pending', FALSE, NOW()
                )
                ON CONFLICT DO NOTHING
            """),
            {"incident_id": pending.incident_id, "tenant_id": pending.tenant_id},
        )
        await session.commit()


async def update_llm_status(
    incident_id: str,
    *,
    status: str,
    result: LLMResult | None = None,
    failure_reason: str | None = None,
) -> None:
    """LLM 완료/실패 시 status 업데이트 (success | fallback)."""
    async with get_session() as session:
        if status == "success" and result:
            await session.execute(
                text("""
                    UPDATE llm_results
                    SET status = 'success',
                        plain_summary = :plain_summary,
                        attack_intent = :attack_intent,
                        kill_chain_analysis = :kill_chain_analysis,
                        recommended_actions = CAST(:recommended_actions AS JSONB),
                        confidence_note = :confidence_note,
                        model = :model,
                        cached = :cached,
                        generated_at = NOW()
                    WHERE incident_id = :incident_id
                """),
                {
                    "incident_id": incident_id,
                    "plain_summary": result.plain_summary,
                    "attack_intent": result.attack_intent,
                    "kill_chain_analysis": result.kill_chain_analysis,
                    "recommended_actions": _json(result.recommended_actions),
                    "confidence_note": result.confidence_note,
                    "model": result.model,
                    "cached": result.cached,
                },
            )
        else:
            await session.execute(
                text("""
                    UPDATE llm_results
                    SET status = 'fallback',
                        failure_reason = :failure_reason,
                        generated_at = NOW()
                    WHERE incident_id = :incident_id
                """),
                {"incident_id": incident_id, "failure_reason": failure_reason or "unknown"},
            )
        await session.commit()


async def save_auto_response_log(log_entry: AutoResponseLog) -> None:
    """자동 대응 실행 이력 append-only 저장 (설계서 6.7)."""
    async with get_session() as session:
        await session.execute(
            text("""
                INSERT INTO auto_response_logs (
                    auto_response_id, tenant_id, incident_id, rule_id, severity,
                    actions_taken, dry_run, triggered_by, policy_reason,
                    policy_version, executed_at, reversed,
                    action_level, ttl_seconds, expires_at, approval_required,
                    confidence_snapshot, scenario_id
                )
                VALUES (
                    :auto_response_id, :tenant_id, :incident_id, :rule_id, :severity,
                    CAST(:actions_taken AS JSONB), :dry_run, :triggered_by, :policy_reason,
                    :policy_version, :executed_at, FALSE,
                    :action_level, :ttl_seconds, :expires_at, :approval_required,
                    :confidence_snapshot, :scenario_id
                )
            """),
            {
                "auto_response_id": log_entry.auto_response_id,
                "tenant_id": log_entry.tenant_id,
                "incident_id": log_entry.incident_id,
                "rule_id": log_entry.rule_id,
                "severity": log_entry.severity,
                "actions_taken": _json(log_entry.actions_taken),
                "dry_run": log_entry.dry_run,
                "triggered_by": log_entry.triggered_by,
                "policy_reason": log_entry.policy_reason,
                "policy_version": log_entry.policy_version,
                "executed_at": log_entry.executed_at,
                # v3.0 확장 필드
                "action_level": getattr(log_entry, "action_level", None),
                "ttl_seconds": getattr(log_entry, "ttl_seconds", None),
                "expires_at": getattr(log_entry, "expires_at", None),
                "approval_required": getattr(log_entry, "approval_required", False),
                "confidence_snapshot": getattr(log_entry, "confidence_snapshot", None),
                "scenario_id": getattr(log_entry, "scenario_id", None),
            },
        )
        await session.commit()
