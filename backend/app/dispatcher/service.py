"""Combined dispatcher entrypoint."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass

from app.common.logging import get_logger
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


async def dispatch_incident_alert(tenant_id: str, result: LLMResult, severity: str = "high") -> DispatchResult:
    normalized_severity = severity.lower()
    errors: list[str] = []
    discord_sent = False
    email_sent = False

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
