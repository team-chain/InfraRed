"""Slack webhook dispatcher."""
from __future__ import annotations

import httpx

from app.config import get_settings


async def send_slack_alert(text: str) -> bool:
    settings = get_settings()
    if not settings.slack_webhook_url:
        return False
    async with httpx.AsyncClient(timeout=10) as client:
        response = await client.post(settings.slack_webhook_url, json={"text": text})
        response.raise_for_status()
    return True
