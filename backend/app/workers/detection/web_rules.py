"""WEB-001..004 rule evaluator for nginx access.log events (design doc 6.4).

WEB-001  Web Shell Access      /uploads/*.php|*.jsp + 200 -> single event trigger
WEB-002  Admin Path Scan       /admin|/login 30+ hits / 5 min from same IP
WEB-003  Automation Tool       curl/python-requests/wget UA -> single event trigger
WEB-004  404 Burst             50+ 404 responses / 5 min from same IP
"""
from __future__ import annotations

import re

from redis.asyncio import Redis

from app.common.constants import KillChainStage, RuleId
from app.config import get_settings
from app.models.envelope import NormalizedEvent
from app.models.signal import Signal
from app.redis_kv import keys


# ── Patterns ──────────────────────────────────────────────────────────────────

# WEB-001: web-shell upload paths
_WEBSHELL_PATH_RE = re.compile(
    r"/(?:uploads?|files?|media|static|assets?|wp-content/uploads?)"
    r"/[^?\s]*\.(php\d?|jsp|jspx|asp|aspx|cfm|cgi|pl|py|rb|sh)",
    re.IGNORECASE,
)

# WEB-002: admin / sensitive paths
_ADMIN_PATH_RE = re.compile(
    r"^/(?:admin|login|wp-admin|phpmyadmin|manager|console|panel|dashboard|"
    r"administrator|backend|cms|control|cpanel|user/login|account/login)",
    re.IGNORECASE,
)

# WEB-003: automation / scanner User-Agents
_AUTOMATION_UA_RE = re.compile(
    r"(?:curl/|python-requests/|python-urllib/|wget/|scrapy/|"
    r"nikto|sqlmap|nmap|masscan|zgrab|nuclei|dirbuster|gobuster|"
    r"wfuzz|hydra|burpsuite|owasp[-_ ]zap)",
    re.IGNORECASE,
)

# paths that are "abnormal" for WEB-003 (not static assets or root)
_NORMAL_PATH_RE = re.compile(r"^/(?:$|favicon\.ico|robots\.txt|static/|assets/|css/|js/|img/)", re.IGNORECASE)


def _event_id(value: object) -> str:
    return value.decode() if isinstance(value, bytes) else str(value)


async def _window_event_ids(redis: Redis, key: str, start: float, end: float) -> list[str]:
    return [_event_id(e) for e in await redis.zrangebyscore(key, start, end)]


def _web_signal(
    rule_id: RuleId,
    event: NormalizedEvent,
    *,
    rule_name: str,
    tactic: str,
    technique: str,
    stage: KillChainStage,
    count: int = 1,
    note: str | None = None,
    triggering_event_ids: list[str] | None = None,
) -> Signal:
    return Signal(
        tenant_id=event.tenant_id,
        asset_id=event.asset_id,
        rule_id=rule_id,
        rule_name=rule_name,
        mitre_tactic=tactic,
        mitre_technique=technique,
        kill_chain_stage=stage,
        source_ip=event.source_ip,
        username=event.username,
        detected_count=count,
        detected_at=event.timestamp,
        triggering_event_ids=triggering_event_ids or [event.event_id],
        notes=note,
        escalate_to_incident=True,
    )


async def evaluate_web_rules(redis: Redis, event: NormalizedEvent) -> list[Signal]:
    """Evaluate WEB-001..004 rules for a WEB_REQUEST event."""
    signals: list[Signal] = []
    if not event.source_ip or not event.request_path:
        return signals

    cfg = get_settings()
    now_score = event.timestamp.timestamp()
    path = event.request_path
    status = event.status_code or 0
    ua = event.user_agent or ""

    # ── WEB-001: Web Shell Access ─────────────────────────────────────────────
    if status == 200 and _WEBSHELL_PATH_RE.search(path):
        signals.append(_web_signal(
            RuleId.WEB_SHELL_ACCESS, event,
            rule_name="Web Shell Access",
            tactic="Persistence",
            technique="T1505.003",
            stage=KillChainStage.EXECUTION,
            note=f"Possible web shell accessed: {path} (HTTP 200).",
        ))

    # ── WEB-002: Admin Path Scan ──────────────────────────────────────────────
    if _ADMIN_PATH_RE.match(path):
        admin_key = keys.web_admin_req(event.tenant_id, event.asset_id, event.source_ip)
        admin_window = cfg.web_admin_scan_window_seconds
        admin_threshold = cfg.web_admin_scan_threshold
        await redis.zadd(admin_key, {event.event_id: now_score})
        await redis.zremrangebyscore(admin_key, 0, now_score - admin_window)
        await redis.expire(admin_key, admin_window * 2)
        admin_count = int(await redis.zcard(admin_key))
        if admin_count >= admin_threshold:
            triggering = await _window_event_ids(redis, admin_key, now_score - admin_window, now_score)
            signals.append(_web_signal(
                RuleId.WEB_ADMIN_SCAN, event,
                rule_name="Admin Path Scan",
                tactic="Reconnaissance",
                technique="T1595",
                stage=KillChainStage.RECONNAISSANCE,
                count=admin_count,
                note=f"{admin_threshold}+ admin/login path hits from one IP in {admin_window}s.",
                triggering_event_ids=triggering,
            ))

    # ── WEB-003: Automation Tool Access ──────────────────────────────────────
    if _AUTOMATION_UA_RE.search(ua) and not _NORMAL_PATH_RE.match(path):
        signals.append(_web_signal(
            RuleId.WEB_AUTOMATION, event,
            rule_name="Automation Tool Access",
            tactic="Initial Access",
            technique="T1190",
            stage=KillChainStage.RECONNAISSANCE,
            note=f"Automation UA detected: {ua[:80]} on path {path}.",
        ))

    # ── WEB-004: 404 Burst ────────────────────────────────────────────────────
    if status == 404:
        burst_key = keys.web_404(event.tenant_id, event.asset_id, event.source_ip)
        burst_window = cfg.web_404_window_seconds
        burst_threshold = cfg.web_404_threshold
        await redis.zadd(burst_key, {event.event_id: now_score})
        await redis.zremrangebyscore(burst_key, 0, now_score - burst_window)
        await redis.expire(burst_key, burst_window * 2)
        burst_count = int(await redis.zcard(burst_key))
        if burst_count >= burst_threshold:
            triggering = await _window_event_ids(redis, burst_key, now_score - burst_window, now_score)
            signals.append(_web_signal(
                RuleId.WEB_404_BURST, event,
                rule_name="404 Burst",
                tactic="Reconnaissance",
                technique="T1595",
                stage=KillChainStage.RECONNAISSANCE,
                count=burst_count,
                note=f"{burst_threshold}+ 404 responses from one IP in {burst_window}s.",
                triggering_event_ids=triggering,
            ))

    return signals
