"""Incident trigger consumer for LLM analysis and alert dispatch."""
from __future__ import annotations

import asyncio

import httpx

from app.common.logging import configure_logging, get_logger
from app.config import get_settings
from app.db.repositories import save_llm_pending, save_llm_result, update_llm_status
from app.dispatcher.service import dispatch_incident_alert
from app.iam.security import create_token
from app.models.llm import LLMPendingRow
from app.redis_kv import streams
from app.redis_kv.client import ensure_group, get_redis
from app.autoresponse.engine import run_autoresponse
from app.dispatcher.discord import send_discord_response_result
from app.workers.llm.service import analyze_contract_with_cache


configure_logging()
log = get_logger(__name__)

AUTO_ANALYZE_SEVERITIES = {"critical", "high"}
STATIC_PLAYBOOK_SEVERITIES = {"medium"}


def _truthy(value: object) -> bool:
    if value is None:
        return False
    if isinstance(value, bytes):
        value = value.decode()
    return str(value).lower() in {"1", "true", "yes"}


async def fetch_incident_contract(incident_id: str, tenant_id: str) -> dict:
    settings = get_settings()
    url = f"{settings.internal_api_base_url.rstrip('/')}/incidents/{incident_id}"
    token = create_token(
        subject="llm-worker",
        tenant_id=tenant_id,
        role="analyst",
        ttl_seconds=300,
    )
    async with httpx.AsyncClient(timeout=10) as client:
        response = await client.get(url, headers={"Authorization": f"Bearer {token}"})
        response.raise_for_status()
        return response.json()


async def process_incident(
    incident_id: str,
    tenant_id: str,
    *,
    refresh: bool = False,
) -> dict[str, object]:
    contract = await fetch_incident_contract(incident_id, tenant_id)
    severity = str(contract.get("incident", {}).get("severity", "info")).lower()

    if severity not in AUTO_ANALYZE_SEVERITIES | STATIC_PLAYBOOK_SEVERITIES:
        log.info("llm_skipped_by_policy", incident_id=incident_id, severity=severity)
        return {"severity": severity, "analysis_mode": "stored_only", "dispatch_attempted": False}

    # ── v5: LLM 호출 시작 시 pending row 즉시 생성 (설계서 9.3) ──────────────
    if not refresh:
        try:
            await save_llm_pending(LLMPendingRow(
                llm_result_id=f"LLM-{incident_id}",
                incident_id=incident_id,
                tenant_id=tenant_id,
            ))
        except Exception as exc:
            log.warning("llm_pending_save_failed", incident_id=incident_id, error=str(exc))

    force_static = severity in STATIC_PLAYBOOK_SEVERITIES
    result = None
    failure_reason = None
    try:
        result = await analyze_contract_with_cache(
            contract,
            refresh=refresh,
            force_static=force_static,
        )
        # ── success: status 업데이트 ──────────────────────────────────────────
        await update_llm_status(incident_id, status="success", result=result)
        await save_llm_result(result, tenant_id=tenant_id)
    except Exception as llm_exc:
        failure_reason = "timeout" if "timeout" in str(llm_exc).lower() else "api_error"
        log.warning("llm_analysis_failed", incident_id=incident_id, reason=failure_reason, error=str(llm_exc))
        # ── fallback: status 업데이트, Static Playbook 유지 ──────────────────
        await update_llm_status(incident_id, status="fallback", failure_reason=failure_reason)

    dispatch_attempted = severity in AUTO_ANALYZE_SEVERITIES and not refresh

    # ── 중복 발송 방지: 동일 incident_id에 대해 최초 1회만 dispatch ────────────
    # save_or_merge_incident가 여러 시그널을 같은 incident로 합칠 때
    # refresh=false 메시지가 중복 발행될 수 있음 → Redis NX로 차단
    if dispatch_attempted:
        _redis = get_redis()
        _dispatch_key = f"dispatch:done:{incident_id}"
        _is_first = await _redis.set(_dispatch_key, "1", nx=True, ex=3600)
        if not _is_first:
            dispatch_attempted = False
            log.info("dispatch_dedup_skipped", incident_id=incident_id)

    discord_sent = False
    email_sent = False
    autoresponse_summary: dict = {}

    if dispatch_attempted and result:
        # ── Discord 2차 알림: LLM 완료 후 비동기 발송 ─────────────────────────
        # (1차 즉시 알림은 Correlation Worker에서 발송 — Person B 영역)
        dispatch_result = await dispatch_incident_alert(tenant_id, result, severity=severity)
        discord_sent = dispatch_result.discord_sent
        email_sent = dispatch_result.email_sent

        incident = contract.get("incident", {})
        try:
            autoresponse_summary = await run_autoresponse(
                tenant_id=tenant_id,
                asset_id=incident.get("asset_id", "unknown"),
                incident_id=incident_id,
                severity=severity,
                result=result,
                source_ip=incident.get("source_ip"),
                username=incident.get("username"),
            )
            mode = autoresponse_summary.get("mode", "manual")
            if mode in ("auto", "approval"):
                try:
                    await send_discord_response_result(
                        incident_id=incident_id,
                        tenant_id=tenant_id,
                        severity=severity,
                        asset_name=incident.get("asset_id", ""),
                        mode=mode,
                        actions_taken=autoresponse_summary.get("actions_taken", []),
                        actions_queued=autoresponse_summary.get("actions_queued", []),
                    )
                except Exception as exc_discord:
                    log.warning("autoresponse_discord_failed", incident_id=incident_id, error=str(exc_discord))
        except Exception as exc:
            log.exception("autoresponse_failed", incident_id=incident_id, error=str(exc))

    return {
        "severity": severity,
        "analysis_mode": "static_playbook" if force_static else "bedrock",
        "llm_status": "success" if result else f"fallback:{failure_reason}",
        "dispatch_attempted": dispatch_attempted,
        "discord_sent": discord_sent,
        "email_sent": email_sent,
        "autoresponse": autoresponse_summary,
    }


async def main() -> None:
    settings = get_settings()
    redis = get_redis()
    stream = streams.incidents_new(settings.tenant_id)
    await ensure_group(redis, stream, streams.GROUP_LLM)
    consumer = f"llm-{settings.agent_id}"
    log.info("llm_worker_started", stream=stream)

    while True:
        messages = await redis.xreadgroup(
            streams.GROUP_LLM,
            consumer,
            {stream: ">"},
            count=10,
            block=5000,
        )
        if not messages:
            continue
        for _, entries in messages:
            for stream_id, fields in entries:
                try:
                    refresh = _truthy(fields.get("refresh"))
                    outcome = await process_incident(
                        fields["incident_id"],
                        fields["tenant_id"],
                        refresh=refresh,
                    )
                    await redis.xack(stream, streams.GROUP_LLM, stream_id)
                    log.info(
                        "llm_worker_processed",
                        incident_id=fields["incident_id"],
                        refresh=refresh,
                        **outcome,
                    )
                except Exception as exc:  # noqa: BLE001
                    log.exception("llm_worker_failed", stream_id=stream_id, error=str(exc))
                    await redis.xack(stream, streams.GROUP_LLM, stream_id)


if __name__ == "__main__":
    asyncio.run(main())
