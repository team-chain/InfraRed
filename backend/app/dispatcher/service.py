"""Combined dispatcher entrypoint — uses per-tenant Discord/email config."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass

from sqlalchemy import text

from app.common.logging import get_logger
from app.db.connection import get_session
from app.dispatcher.discord import send_discord_embed
from app.dispatcher.email import send_email_alert
from app.models.llm import LLMResult


log = get_logger(__name__)


@dataclass(frozen=True)
class DispatchResult:
    discord_sent: bool = False
    email_sent: bool = False
    errors: tuple[str, ...] = ()

    @property
    def dispatched(self) -> bool:
        return self.discord_sent or self.email_sent


async def _get_tenant_dispatch_config(tenant_id: str) -> dict:
    """테넌트별 Discord/Email 설정을 DB에서 조회. 없으면 빈 dict."""
    try:
        async with get_session() as session:
            row = await session.execute(
                text("SELECT discord_webhook_url, alert_email_to FROM tenant_settings WHERE tenant_id = :t"),
                {"t": tenant_id},
            )
            record = row.mappings().first()
        return dict(record) if record else {}
    except Exception as exc:
        log.warning("tenant_dispatch_config_fetch_failed tenant=%s error=%s", tenant_id, exc)
        return {}


async def dispatch_incident_alert(tenant_id: str, result: LLMResult, severity: str = "high") -> DispatchResult:
    normalized_severity = severity.lower()
    errors: list[str] = []
    discord_sent = False
    email_sent = False

    # 테넌트별 설정 우선, 없으면 전역 env 폴백
    tenant_cfg = await _get_tenant_dispatch_config(tenant_id)
    discord_url = tenant_cfg.get("discord_webhook_url") or None
    email_to    = tenant_cfg.get("alert_email_to") or None

    try:
        discord_sent = await send_discord_embed(
            incident_id=result.incident_id,
            tenant_id=tenant_id,
            severity=normalized_severity,
            plain_summary=result.plain_summary,
            attack_intent=result.attack_intent,
            kill_chain_analysis=result.kill_chain_analysis,
            recommended_actions=result.recommended_actions,
            confidence_note=result.confidence_note,
            webhook_url=discord_url,
        )
    except Exception as exc:  # noqa: BLE001
        errors.append(f"discord:{exc}")
        log.exception("discord_alert_dispatch_failed", incident_id=result.incident_id, error=str(exc))

    if normalized_severity == "critical":
        email_text = (
            f"[InfraRed] {tenant_id} {result.incident_id}\n"
            f"{result.plain_summary}\n"
            f"조치: {', '.join(result.recommended_actions[:3])}"
        )
        try:
            email_sent = await asyncio.to_thread(
                send_email_alert,
                f"InfraRed 인시던트 {result.incident_id}",
                email_text,
                to_override=email_to,
            )
        except Exception as exc:  # noqa: BLE001
            errors.append(f"email:{exc}")
            log.exception("email_alert_dispatch_failed", incident_id=result.incident_id, error=str(exc))

    dispatch_result = DispatchResult(
        discord_sent=discord_sent,
        email_sent=email_sent,
        errors=tuple(errors),
    )
    log.info(
        "incident_alert_dispatched",
        incident_id=result.incident_id,
        severity=normalized_severity,
        dispatched=dispatch_result.dispatched,
        discord_sent=dispatch_result.discord_sent,
        email_sent=dispatch_result.email_sent,
        errors=list(dispatch_result.errors),
    )
    return dispatch_result
