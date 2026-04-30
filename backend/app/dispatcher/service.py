"""Combined dispatcher entrypoint."""
from __future__ import annotations

import asyncio

from app.common.logging import get_logger
from app.dispatcher.email import send_email_alert
from app.dispatcher.slack import send_slack_alert
from app.models.llm import LLMResult


log = get_logger(__name__)


async def dispatch_incident_alert(tenant_id: str, result: LLMResult) -> None:
    text = (
        f"[InfraRed] {tenant_id} {result.incident_id}\n"
        f"{result.plain_summary}\n"
        f"Actions: {', '.join(result.recommended_actions[:3])}"
    )
    try:
        slack_sent = await send_slack_alert(text)
        email_sent = await asyncio.to_thread(
            send_email_alert,
            f"InfraRed incident {result.incident_id}",
            text,
        )
        log.info(
            "incident_alert_dispatched",
            incident_id=result.incident_id,
            slack_sent=slack_sent,
            email_sent=email_sent,
        )
    except Exception as exc:  # noqa: BLE001
        log.exception("incident_alert_dispatch_failed", incident_id=result.incident_id, error=str(exc))
