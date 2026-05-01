"""Combined dispatcher entrypoint."""
from __future__ import annotations

import asyncio

from app.common.logging import get_logger
from app.dispatcher.discord import send_discord_embed
from app.dispatcher.email import send_email_alert
from app.models.llm import LLMResult


log = get_logger(__name__)


async def dispatch_incident_alert(tenant_id: str, result: LLMResult, severity: str = "high") -> None:
    try:
        discord_sent = await send_discord_embed(
            incident_id=result.incident_id,
            tenant_id=tenant_id,
            severity=severity,
            plain_summary=result.plain_summary,
            attack_intent=result.attack_intent,
            kill_chain_analysis=result.kill_chain_analysis,
            recommended_actions=result.recommended_actions,
            confidence_note=result.confidence_note,
        )
        email_text = (
            f"[InfraRed] {tenant_id} {result.incident_id}\n"
            f"{result.plain_summary}\n"
            f"조치: {', '.join(result.recommended_actions[:3])}"
        )
        email_sent = await asyncio.to_thread(
            send_email_alert,
            f"InfraRed 인시던트 {result.incident_id}",
            email_text,
        )
        log.info(
            "incident_alert_dispatched",
            incident_id=result.incident_id,
            discord_sent=discord_sent,
            email_sent=email_sent,
        )
    except Exception as exc:  # noqa: BLE001
        log.exception("incident_alert_dispatch_failed", incident_id=result.incident_id, error=str(exc))
