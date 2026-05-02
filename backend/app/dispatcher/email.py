"""SMTP email dispatcher with STARTTLS certificate validation."""
from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage

import certifi

from app.config import get_settings


def _ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=certifi.where())
    return ctx


def send_email_alert(subject: str, body: str) -> bool:
    settings = get_settings()
    if not settings.smtp_host or not settings.alert_email_to:
        return False

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = settings.alert_email_from
    message["To"] = settings.alert_email_to
    message.set_content(body)

    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as smtp:
        smtp.starttls(context=_ssl_context())
        if settings.smtp_user:
            smtp.login(settings.smtp_user, settings.smtp_password)
        smtp.send_message(message)
    return True
