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


async def send_discord_alert(text: str, *, webhook_url: str | None = None) -> bool:
    """Plain-text alert (fallback). webhook_url overrides global config."""
    settings = get_settings()
    url = webhook_url or settings.discord_webhook_url
    if not url:
        return False
    payload = {"content": _truncate(text, 2000), "allowed_mentions": {"parse": []}}
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(url, json=payload)
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
    webhook_url: str | None = None,
) -> bool:
    """Rich embed alert — 문제 / 권장 조치 구조.
    webhook_url overrides global config (per-tenant support).
    """
    settings = get_settings()
    url = webhook_url or settings.discord_webhook_url
    if not url:
        return False

    color = _SEVERITY_COLOR.get(severity.lower(), 0x888888)
    severity_emoji = {
        "critical": "🔴", "high": "🟠", "medium": "🟡", "info": "🔵",
    }.get(severity.lower(), "⚪")

    # ── 🔴 문제 (Problem) ─────────────────────────────────────────────────────
    problem_parts: list[str] = [_truncate(plain_summary, 600)]
    if attack_intent:
        problem_parts.append(f"\n**공격 의도**\n{_truncate(attack_intent, 300)}")
    if kill_chain_analysis:
        problem_parts.append(f"\n**Kill Chain 분석**\n{_truncate(kill_chain_analysis, 300)}")
    problem_text = "\n".join(problem_parts)

    # ── ✅ 권장 조치 (Recommended Actions) ────────────────────────────────────
    if recommended_actions:
        actions_text = "\n".join(f"{i+1}. {a}" for i, a in enumerate(recommended_actions))
    else:
        actions_text = "AI 분석 결과를 기다리는 중입니다."

    fields = [
        {
            "name": "🔴 문제",
            "value": _truncate(problem_text, DISCORD_FIELD_LIMIT),
            "inline": False,
        },
        {
            "name": "✅ 권장 조치",
            "value": _truncate(actions_text, DISCORD_FIELD_LIMIT),
            "inline": False,
        },
    ]

    if confidence_note:
        fields.append({
            "name": "💡 신뢰도",
            "value": _truncate(confidence_note, 300),
            "inline": False,
        })

    embed = {
        "title": f"{severity_emoji} [{severity.upper()}] {incident_id} — 보안 인시던트 탐지",
        "color": color,
        "fields": fields,
        "footer": {"text": f"InfraRed SOC — {tenant_id}  |  대응 결과는 별도 메시지로 전송됩니다"},
    }
    payload = {"embeds": [embed], "allowed_mentions": {"parse": []}}
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()
    except (httpx.HTTPStatusError, httpx.RequestError) as exc:
        raise _safe_discord_error(exc) from None
    return True


async def send_discord_first_alert(
    *,
    incident_id: str,
    tenant_id: str,
    severity: str,
    rule_id: str,
    source_ip: str | None,
    playbook_summary: str,
    webhook_url: str | None = None,
) -> bool:
    """1차 즉시 알림 — Incident 생성 직후 발송 (설계서 4.3).

    LLM 분석 완료를 기다리지 않고 즉시 발송.
    rule_id 기반 Static Playbook 요약 포함.
    LLM 완료 후 send_discord_embed()로 2차 알림 발송.
    """
    settings = get_settings()
    url = webhook_url or settings.discord_webhook_url
    if not url:
        return False

    color = _SEVERITY_COLOR.get(severity.lower(), 0x888888)
    severity_emoji = {
        "critical": "🔴", "high": "🟠", "medium": "🟡", "info": "🔵",
    }.get(severity.lower(), "⚪")

    ip_text = f"`{source_ip}`" if source_ip else "알 수 없음"

    fields = [
        {
            "name": "🚨 탐지 룰",
            "value": f"`{rule_id}`",
            "inline": True,
        },
        {
            "name": "🌐 출발지 IP",
            "value": ip_text,
            "inline": True,
        },
        {
            "name": "📋 Static Playbook 요약",
            "value": _truncate(playbook_summary, DISCORD_FIELD_LIMIT),
            "inline": False,
        },
        {
            "name": "⏳ AI 분석",
            "value": "Bedrock Claude가 분석 중입니다. 완료 후 2차 알림이 발송됩니다.",
            "inline": False,
        },
    ]

    embed = {
        "title": f"{severity_emoji} [{severity.upper()}] {incident_id} — 인시던트 탐지 (1차 알림)",
        "color": color,
        "fields": fields,
        "footer": {"text": f"InfraRed SOC — {tenant_id}  |  AI 분석 완료 후 2차 알림 예정"},
    }
    payload = {"embeds": [embed], "allowed_mentions": {"parse": []}}
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()
    except (httpx.HTTPStatusError, httpx.RequestError) as exc:
        raise _safe_discord_error(exc) from None
    return True


async def send_discord_autoresponse_result(
    *,
    incident_id: str,
    tenant_id: str,
    severity: str,
    mode: str,
    actions_taken: list[dict],
    actions_queued: list[dict],
    webhook_url: str | None = None,
) -> bool:
    """자동 대응 처리 결과를 Discord로 전송.

    auto 모드: 즉시 실행된 조치 표시
    approval 모드: 승인 대기 중인 조치 표시
    """
    settings = get_settings()
    url = webhook_url or settings.discord_webhook_url
    if not url:
        return False

    # 알림만인 경우(actions_taken, actions_queued 모두 없으면) 전송 생략
    if not actions_taken and not actions_queued:
        return False

    color = _SEVERITY_COLOR.get(severity.lower(), 0x888888)
    mode_label = {
        "auto": "AI 완전 자동 대응 완료",
        "approval": "AI 대응 -- 승인 대기",
    }.get(mode, f"대응 모드: {mode}")

    def _fmt_actions(action_list: list[dict]) -> str:
        lines = []
        for a in action_list:
            atype = a.get("type", a.get("action_type", "?"))
            target = a.get("target", "-")
            label = {
                "block_ip": f"IP 차단: `{target}`",
                "lock_account": f"계정 잠금: `{target}`",
                "escalate": f"심각도 상향: `{target}`",
            }.get(atype, f"`{atype}` -> `{target}`")
            lines.append(label)
        return "\n".join(lines) or "없음"

    fields: list[dict] = [
        {
            "name": "대응",
            "value": (
                "AI가 분석 결과를 바탕으로 아래 조치를 처리했습니다."
                if mode == "auto"
                else "아래 조치가 승인 대기 중입니다. 대시보드에서 확인 후 승인 또는 거부하세요."
            ),
            "inline": False,
        }
    ]
    if actions_taken:
        fields.append({
            "name": "즉시 실행된 조치",
            "value": _truncate(_fmt_actions(actions_taken), DISCORD_FIELD_LIMIT),
            "inline": False,
        })
    if actions_queued:
        fields.append({
            "name": "승인 대기 중인 조치",
            "value": _truncate(_fmt_actions(actions_queued), DISCORD_FIELD_LIMIT),
            "inline": False,
        })

    embed = {
        "title": f"{mode_label} -- {incident_id}",
        "color": color,
        "fields": fields,
        "footer": {"text": f"InfraRed SOC -- {tenant_id}  |  {severity.upper()}"},
    }
    payload = {"embeds": [embed], "allowed_mentions": {"parse": []}}
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
    except (httpx.HTTPStatusError, httpx.RequestError) as exc:
        raise _safe_discord_error(exc) from None
    return True
