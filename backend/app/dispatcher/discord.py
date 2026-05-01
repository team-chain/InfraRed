"""Discord webhook dispatcher."""
from __future__ import annotations

import httpx

from app.config import get_settings


DISCORD_CONTENT_LIMIT = 2000


def _truncate_content(text: str) -> str:
    if len(text) <= DISCORD_CONTENT_LIMIT:
        return text
    return f"{text[: DISCORD_CONTENT_LIMIT - 3]}..."


async def send_discord_alert(text: str) -> bool:
    settings = get_settings()
    if not settings.discord_webhook_url:
        return False

    payload = {
        "content": _truncate_content(text),
        "allowed_mentions": {"parse": []},
    }
    async with httpx.AsyncClient(timeout=10) as client:
        response = await client.post(settings.discord_webhook_url, json=payload)
        response.raise_for_status()
    return True
