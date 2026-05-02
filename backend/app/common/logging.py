"""Structured logging setup."""
from __future__ import annotations

import logging
import re
import sys
from typing import Any

import structlog

from app.config import get_settings

_WEBHOOK_PATTERNS = [
    re.compile(
        r"(https://discord(?:app)?\.com/api/webhooks/\d+/)[A-Za-z0-9_\-]+",
        re.IGNORECASE,
    ),
    re.compile(
        r"(https://hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/)[A-Za-z0-9_\-]+",
        re.IGNORECASE,
    ),
]


def _mask_webhooks(text: str) -> str:
    """Mask webhook URL token with ***."""
    for pattern in _WEBHOOK_PATTERNS:
        text = pattern.sub(r"\1***", text)
    return text


def _mask_event(logger: Any, method: str, event_dict: dict) -> dict:
    """structlog processor: mask webhook URL tokens in all string fields."""
    for key, value in list(event_dict.items()):
        if isinstance(value, str):
            masked = _mask_webhooks(value)
            if masked != value:
                event_dict[key] = masked
        elif isinstance(value, Exception):
            event_dict[key] = _mask_webhooks(str(value))
    return event_dict


def configure_logging() -> None:
    settings = get_settings()
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
    )
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            _mask_event,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, settings.log_level.upper(), logging.INFO)
        ),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name)
