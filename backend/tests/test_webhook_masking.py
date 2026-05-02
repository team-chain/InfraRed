"""Unit tests for Discord webhook URL masking in logging and dispatcher."""
from __future__ import annotations

import pytest

from app.common.logging import _mask_webhooks
from app.dispatcher.discord import _safe_discord_error

import httpx


# ── _mask_webhooks ─────────────────────────────────────────────────────────────

def test_discord_webhook_token_masked() -> None:
    url = "https://discord.com/api/webhooks/123456789/AbCdEfGhIjKlMnOpQrStUvWxYz"
    masked = _mask_webhooks(url)
    assert "AbCdEfGhIjKlMnOpQrStUvWxYz" not in masked
    assert "123456789" in masked   # channel id 는 유지
    assert "***" in masked


def test_discordapp_webhook_token_masked() -> None:
    url = "https://discordapp.com/api/webhooks/987/TOKEN_HERE_XYZ"
    masked = _mask_webhooks(url)
    assert "TOKEN_HERE_XYZ" not in masked


def test_slack_webhook_token_masked() -> None:
    url = "https://hooks.slack.com/services/T0001/B0001/TOKEN123ABC"
    masked = _mask_webhooks(url)
    assert "TOKEN123ABC" not in masked
    assert "***" in masked


def test_non_webhook_url_unchanged() -> None:
    url = "https://example.com/api/v1/health"
    assert _mask_webhooks(url) == url


def test_plain_text_unchanged() -> None:
    text = "Incident INC-20260430-001 created"
    assert _mask_webhooks(text) == text


def test_mask_event_processor_masks_nested_url() -> None:
    """structlog processor _mask_event 가 event_dict 안 webhook URL 을 마스킹."""
    from app.common.logging import _mask_event
    raw_url = "https://discord.com/api/webhooks/111/SECRET_TOKEN"
    event_dict = {
        "event": "discord_failed",
        "error": f"POST {raw_url} returned 400",
    }
    result = _mask_event(None, "error", event_dict)
    assert "SECRET_TOKEN" not in result["error"]
    assert "***" in result["error"]


# ── _safe_discord_error ────────────────────────────────────────────────────────

def test_safe_error_hides_url_from_http_status_error() -> None:
    raw_url = "https://discord.com/api/webhooks/999/MY_SECRET"
    mock_response = httpx.Response(429, text="rate limited")
    exc = httpx.HTTPStatusError("error", request=httpx.Request("POST", raw_url), response=mock_response)
    safe = _safe_discord_error(exc)
    assert "MY_SECRET" not in str(safe)
    assert "429" in str(safe)


def test_safe_error_hides_url_from_request_error() -> None:
    raw_url = "https://discord.com/api/webhooks/999/MY_SECRET"
    exc = httpx.ConnectTimeout("timeout", request=httpx.Request("POST", raw_url))
    safe = _safe_discord_error(exc)
    assert "MY_SECRET" not in str(safe)
    assert "ConnectTimeout" in str(safe)
