"""Discord webhook dispatcher.

Security note: the webhook URL token must never appear in logs.
  - httpx exceptions are caught and re-raised as safe RuntimeErrors (no URL).
  - common.logging._mask_event processor provides a second line of defense.
"""
from __future__ import annotations

import httpx

from app.config import get_settings


DISCORD_FIELD_LIMIT = 1024
DISCORD_DESC_LIMIT = 4096

_SEVERITY_COLOR = {
    "critical": 0xCC2200,
    "high":     0xFF6600,
    "medium":   0xFFAA00,
    "info":     0x3399FF,
}


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return f"{text[: limit - 3]}..."


def _safe_discord_error(exc: Exception) -> RuntimeError:
    """Return a RuntimeError without the webhook URL."""
    if isinstance(exc, httpx.HTTPStatusError):
        return RuntimeError(
            f"Discord webhook HTTP {exc.response.status_code}: {exc.response.text[:200]}"
        )
    if isinstance(exc, httpx.RequestError):
        return RuntimeError(f"Discord webhook request error: {type(exc).__name__}")
    return RuntimeError(f"Discord webhook error: {type(exc).__name__}: {exc}")


async def send_discord_alert(text: str) -> bool:
    """Legacy plain-text alert (fallback)."""
    settings = get_settings()
    if not settings.discord_webhook_url:
        return False
    payload = {"content": _truncate(text, 2000), "allowed_mentions": {"parse": []}}
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(settings.discord_webhook_url, json=payload)
            response.raise_for_status()
    except (httpx.HTTPStatusError, httpx.RequestError) as exc:
        raise _safe_discord_error(exc) from None
    return True


async def send_discord_embed(
    *,
    incident_id: str,
    tenant_id: str,
    severity: str,
    plain_summary: str,
    attack_intent: str,
    kill_chain_analysis: str,
    recommended_actions: list[str],
    confidence_note: str,
) -> bool:
    settings = get_settings()
    if not settings.discord_webhook_url:
        return False

    color = _SEVERITY_COLOR.get(severity.lower(), 0x888888)
    severity_emoji = {
        "critical": "🔴", "high": "🟠", "medium": "🟡", "info": "🔵",
    }.get(severity.lower(), "⚪")
    actions_text = "\n".join(f"> {i+1}. {a}" for i, a in enumerate(recommended_actions))

    embed = {
        "title": f"{severity_emoji} [{severity.upper()}] {incident_id}",
        "description": _truncate(plain_summary, DISCORD_DESC_LIMIT),
        "color": color,
        "fields": [
            {"name": "공격 의도", "value": _truncate(attack_intent, DISCORD_FIELD_LIMIT), "inline": False},
            {"name": "Kill Chain", "value": _truncate(kill_chain_analysis, DISCORD_FIELD_LIMIT), "inline": False},
            {"name": "권장 조치", "value": _truncate(actions_text or "없음", DISCORD_FIELD_LIMIT), "inline": False},
            {"name": "신뢰도", "value": _truncate(confidence_note or "-", DISCORD_FIELD_LIMIT), "inline": False},
        ],
        "footer": {"text": f"InfraRed SOC - {tenant_id}"},
    }
    payload = {"embeds": [embed], "allowed_mentions": {"parse": []}}
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(settings.discord_webhook_url, json=payload)
            response.raise_for_status()
    except (httpx.HTTPStatusError, httpx.RequestError) as exc:
        raise _safe_discord_error(exc) from None
    return True
