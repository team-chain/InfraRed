"""Discord webhook dispatcher.

설계 원칙:
  - 이모티콘 없이 임베드 색상 바만으로 severity 전달
  - 제목: [SEVERITY] 이벤트 유형 — 서버명  (메타 정보 제거)
  - 필드명 한글, 실제 값(IP·ID·룰 등)은 원본 그대로
  - AUTO / MANUAL 배지로 자동 처리 항목과 수동 처리 항목 명시 구분
  - 탐지(주황) → AI 분석 완료(주황 유지) → 대응 완료(초록) 색상 흐름

Security note:
  - Webhook URL은 절대 로그에 남기지 않음
  - httpx 예외는 URL 없이 안전한 RuntimeError로 변환
"""
from __future__ import annotations

from datetime import datetime, timezone

import httpx

from app.config import get_settings

DISCORD_FIELD_LIMIT = 1024

# 임베드 좌측 색상 바 — severity 유일한 시각 표시 수단
_SEVERITY_COLOR = {
    "critical": 0xCC2200,
    "high":     0xE07000,
    "medium":   0xD4A017,
    "info":     0x4A90D9,
}
_COLOR_RESOLVED = 0x2EA043   # 대응 완료 → 초록

# 행동 유형 한글 레이블
_ACTION_LABEL = {
    "block_ip":       "IP 차단",
    "lock_account":   "계정 잠금",
    "disable_user":   "계정 비활성화",
    "revoke_session": "세션 강제 만료",
    "watchlist":      "Watchlist 등록",
    "escalate":       "심각도 상향",
    "denylist":       "Denylist 등록",
    "notify":         "알림 발송",
    "notify_soc":     "SOC 알림 발송",
}


# ── 내부 유틸 ──────────────────────────────────────────────────────────────────

def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return f"{text[: limit - 3]}..."


def _now_kst() -> str:
    """현재 시각을 HH:MM:SS KST 형식으로 반환 (UTC+9 기준)."""
    from datetime import timedelta
    now = datetime.now(timezone.utc) + timedelta(hours=9)
    return now.strftime("%H:%M:%S KST")


def _fmt_kst(dt: datetime) -> str:
    """datetime 객체를 HH:MM:SS KST 형식으로 반환. tzinfo 없으면 UTC로 간주."""
    from datetime import timedelta
    kst_tz = timezone(timedelta(hours=9))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(kst_tz).strftime("%H:%M:%S KST")


def _fmt_kst_from_str(iso_str: str) -> str:
    """ISO 8601 문자열을 HH:MM:SS KST 형식으로 변환. 파싱 실패 시 현재 시각 반환."""
    try:
        return _fmt_kst(datetime.fromisoformat(iso_str))
    except (ValueError, TypeError):
        return _now_kst()


def _safe_discord_error(exc: Exception) -> RuntimeError:
    """Webhook URL 없이 안전한 RuntimeError 반환."""
    if isinstance(exc, httpx.HTTPStatusError):
        return RuntimeError(
            f"Discord webhook HTTP {exc.response.status_code}: {exc.response.text[:200]}"
        )
    if isinstance(exc, httpx.RequestError):
        return RuntimeError(f"Discord webhook 요청 오류: {type(exc).__name__}")
    return RuntimeError(f"Discord webhook 오류: {type(exc).__name__}: {exc}")


async def _post_embed(url: str, embed: dict) -> None:
    """단일 임베드 전송. 실패 시 _safe_discord_error로 URL 마스킹."""
    payload = {"embeds": [embed], "allowed_mentions": {"parse": []}}
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
    except (httpx.HTTPStatusError, httpx.RequestError) as exc:
        raise _safe_discord_error(exc) from None


def _severity_label(severity: str) -> str:
    """영문 대문자 severity 레이블."""
    return severity.upper()


def _fmt_action_line(action: dict, badge: str) -> str:
    """단일 조치 항목을 `[BADGE] 설명: 대상` 형태로 포맷."""
    atype  = action.get("type", action.get("action_type", "unknown"))
    target = action.get("target", "")
    label  = _ACTION_LABEL.get(atype, atype)
    target_fmt = f" — `{target}`" if target else ""
    return f"`[{badge}]` {label}{target_fmt}"


def _build_action_block(
    auto_done: list[dict],
    manual_needed: list[str],
    queued: list[dict] | None = None,
) -> str:
    """권장 조치 필드 텍스트 생성.

    - auto_done    : 이미 자동 실행 완료된 조치 목록
    - manual_needed: 운영자가 직접 수행해야 할 조치 설명 목록
    - queued       : 승인 대기 중인 조치 (approval 모드)
    """
    lines: list[str] = []
    for a in auto_done:
        lines.append(_fmt_action_line(a, "자동 완료"))
    for m in manual_needed:
        lines.append(f"`[수동 필요]` {m}")
    for q in (queued or []):
        lines.append(_fmt_action_line(q, "승인 대기"))
    return "\n".join(lines) if lines else "조치 없음"


# ── 공개 API ───────────────────────────────────────────────────────────────────

async def send_discord_alert(text: str, *, webhook_url: str | None = None) -> bool:
    """단순 텍스트 알림 (fallback 전용).

    임베드 전송이 실패하거나 빠른 plain-text 알림이 필요한 경우에만 사용.
    webhook_url 지정 시 전역 설정 대신 해당 URL 사용.
    """
    settings = get_settings()
    url = webhook_url or settings.discord_webhook_url
    if not url:
        return False
    payload = {"content": _truncate(text, 2000), "allowed_mentions": {"parse": []}}
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
    except (httpx.HTTPStatusError, httpx.RequestError) as exc:
        raise _safe_discord_error(exc) from None
    return True


async def send_discord_first_alert(
    *,
    incident_id: str,
    tenant_id: str,
    severity: str,
    rule_id: str,
    rule_description: str = "",
    asset_name: str = "",
    source_ip: str | None,
    playbook_summary: str,
    auto_actions_taken: list[dict] | None = None,
    detected_at: str | None = None,
    webhook_url: str | None = None,
) -> bool:
    """1차 즉시 알림 — Incident 생성 직후 발송 (설계서 4.3).

    LLM 분석 완료 전에 즉시 발송. 탐지 사실 + Static Playbook + 즉시 실행된 자동 조치 포함.
    LLM 완료 후 send_discord_ai_analysis()로 2차 알림 발송.

    파라미터:
        rule_description  : 룰 ID에 대한 한국어 설명 (예: "Honeypot 경로 접근")
        asset_name        : 탐지된 서버/자산 이름
        auto_actions_taken: Incident 생성 시 즉시 실행된 자동 조치 목록
        detected_at       : 실제 탐지 시각 (ISO 8601). 없으면 발송 시각으로 대체
    """
    settings = get_settings()
    url = webhook_url or settings.discord_webhook_url
    if not url:
        return False

    sev   = severity.lower()
    color = _SEVERITY_COLOR.get(sev, 0x888888)

    # 제목: [HIGH] Honeypot 경로 접근 — web-prod-01
    event_type = rule_description or rule_id
    asset_part = f" — {asset_name}" if asset_name else ""
    title = f"[{_severity_label(sev)}] {event_type}{asset_part}"

    # 탐지 내용 필드
    detection_lines = [f"`{rule_id}`"]
    if rule_description:
        detection_lines.append(rule_description)
    detection_value = " · ".join(detection_lines)
    if playbook_summary:
        detection_value += f"\n{_truncate(playbook_summary, 300)}"

    fields: list[dict] = [
        {
            "name": "서버",
            "value": f"`{asset_name}`" if asset_name else "알 수 없음",
            "inline": True,
        },
        {
            "name": "출발지 IP",
            "value": f"`{source_ip}`" if source_ip else "알 수 없음",
            "inline": True,
        },
        {
            "name": "탐지 시각",
            "value": _fmt_kst_from_str(detected_at) if detected_at else _now_kst(),
            "inline": True,
        },
        {
            "name": "탐지 내용",
            "value": _truncate(detection_value, DISCORD_FIELD_LIMIT),
            "inline": False,
        },
    ]

    # 즉시 실행된 자동 조치가 있으면 표시
    if auto_actions_taken:
        done_lines = "\n".join(_fmt_action_line(a, "자동 완료") for a in auto_actions_taken)
        fields.append({
            "name": "즉시 실행된 조치",
            "value": _truncate(done_lines + "\nAI 분석 완료 후 추가 조치 자동 판단", DISCORD_FIELD_LIMIT),
            "inline": False,
        })
    else:
        fields.append({
            "name": "분석 상태",
            "value": "AI 분석 진행 중 · 완료 시 후속 알림 발송",
            "inline": False,
        })

    embed = {
        "title": _truncate(title, 256),
        "color": color,
        "fields": fields,
        "footer": {"text": f"{incident_id} · InfraRed SOC · {tenant_id}"},
    }
    await _post_embed(url, embed)
    return True


async def send_discord_ai_analysis(
    *,
    incident_id: str,
    tenant_id: str,
    severity: str,
    asset_name: str = "",
    event_type: str,
    summary: str,
    kill_chain_stage: str = "",
    mitre_techniques: list[str] | None = None,
    auto_actions_taken: list[dict] | None = None,
    manual_actions_needed: list[str] | None = None,
    detection_confidence: float | None = None,
    ai_confidence: float | None = None,
    analysis_elapsed_sec: int | None = None,
    webhook_url: str | None = None,
) -> bool:
    """2차 알림 — AI 분석 완료 후 발송 (구 send_discord_embed).

    AI 판단 요약, Kill Chain 단계, MITRE ATT&CK, 권장 조치(AUTO/MANUAL 구분),
    탐지·AI 신뢰도를 포함한 구조화된 분석 결과 알림.

    파라미터:
        event_type             : 이벤트 유형 한국어 설명
        auto_actions_taken     : 이미 자동 실행된 조치 목록
        manual_actions_needed  : 운영자가 수동으로 처리해야 할 조치 설명 목록
        detection_confidence   : 룰/상관분석 기반 신뢰도 (0.0~1.0)
        ai_confidence          : AI 분석 신뢰도 (0.0~1.0)
        analysis_elapsed_sec   : 1차 알림 후 경과 시간(초)
    """
    settings = get_settings()
    url = webhook_url or settings.discord_webhook_url
    if not url:
        return False

    sev   = severity.lower()
    color = _SEVERITY_COLOR.get(sev, 0x888888)

    asset_part = f" / {asset_name}" if asset_name else ""
    title = f"[{_severity_label(sev)}] AI 분석 완료 — {event_type}{asset_part}"

    fields: list[dict] = [
        {
            "name": "AI 판단",
            "value": _truncate(summary, DISCORD_FIELD_LIMIT),
            "inline": False,
        },
    ]

    # Kill Chain + MITRE 가로 배치
    if kill_chain_stage or mitre_techniques:
        fields.append({
            "name": "공격 단계",
            "value": kill_chain_stage or "분석 중",
            "inline": True,
        })
        mitre_val = "  ".join(f"`{t}`" for t in (mitre_techniques or [])) or "—"
        fields.append({
            "name": "MITRE ATT&CK",
            "value": mitre_val,
            "inline": True,
        })

    # 권장 조치 — AUTO / MANUAL 명확히 구분
    action_text = _build_action_block(
        auto_done=auto_actions_taken or [],
        manual_needed=manual_actions_needed or [],
    )
    fields.append({
        "name": "권장 조치",
        "value": _truncate(action_text, DISCORD_FIELD_LIMIT),
        "inline": False,
    })

    # 신뢰도 (텍스트 바 + 퍼센트)
    def _conf_bar(value: float, width: int = 10) -> str:
        filled = round(value * width)
        bar = "█" * filled + "░" * (width - filled)
        return f"`{bar}` {round(value * 100)}%"

    conf_parts: list[str] = []
    if detection_confidence is not None:
        conf_parts.append(f"탐지 신뢰도  {_conf_bar(detection_confidence)}")
    if ai_confidence is not None:
        conf_parts.append(f"AI 분석 신뢰도  {_conf_bar(ai_confidence)}")
    if conf_parts:
        fields.append({
            "name": "신뢰도",
            "value": "\n".join(conf_parts),
            "inline": False,
        })

    elapsed = f" · 분석 소요 {analysis_elapsed_sec}초" if analysis_elapsed_sec is not None else ""
    embed = {
        "title": _truncate(title, 256),
        "color": color,
        "fields": fields,
        "footer": {"text": f"{incident_id} · {_now_kst()}{elapsed} · InfraRed SOC · {tenant_id}"},
    }
    await _post_embed(url, embed)
    return True


async def send_discord_response_result(
    *,
    incident_id: str,
    tenant_id: str,
    severity: str,
    asset_name: str = "",
    mode: str,
    actions_taken: list[dict],
    actions_queued: list[dict],
    response_elapsed_sec: int | None = None,
    webhook_url: str | None = None,
) -> bool:
    """대응 결과 알림 — Policy Engine 실행 완료 후 발송 (구 send_discord_autoresponse_result).

    auto 모드  : 즉시 실행된 조치 + 롤백 방법 안내
    approval 모드: 승인 대기 중인 조치 목록

    완료된 대응이 없으면 (actions_taken, actions_queued 모두 빈 경우) 전송 생략.
    """
    settings = get_settings()
    url = webhook_url or settings.discord_webhook_url
    if not url:
        return False
    if not actions_taken and not actions_queued:
        return False

    # 대응 완료는 초록, 승인 대기는 severity 색상 유지
    color = _COLOR_RESOLVED if mode == "auto" and actions_taken else _SEVERITY_COLOR.get(severity.lower(), 0x888888)

    asset_part = f" — {asset_name}" if asset_name else ""
    mode_label = {
        "auto":     "대응 완료",
        "approval": "대응 승인 대기",
    }.get(mode, "대응 처리")

    title = f"{mode_label}{asset_part} / {incident_id}"

    fields: list[dict] = []

    # 실행 완료된 조치
    if actions_taken:
        done_lines = []
        for a in actions_taken:
            atype  = a.get("type", a.get("action_type", "unknown"))
            target = a.get("target", "")
            label  = _ACTION_LABEL.get(atype, atype)
            success = a.get("success", True)
            status_mark = "✓" if success else "✗"
            target_fmt = f" — `{target}`" if target else ""
            done_lines.append(f"{status_mark} {label}{target_fmt}")

        elapsed_note = f" (탐지 후 +{response_elapsed_sec}초)" if response_elapsed_sec is not None else ""
        fields.append({
            "name": f"실행된 조치{elapsed_note}",
            "value": _truncate("\n".join(done_lines), DISCORD_FIELD_LIMIT),
            "inline": False,
        })

    # 승인 대기 조치
    if actions_queued:
        queued_lines = [
            _fmt_action_line(a, "승인 대기") for a in actions_queued
        ]
        fields.append({
            "name": "승인 대기 중인 조치",
            "value": _truncate(
                "\n".join(queued_lines) + "\n대시보드에서 승인 또는 거부하세요.",
                DISCORD_FIELD_LIMIT,
            ),
            "inline": False,
        })

    # 롤백 안내 (auto 모드 + 실제 차단이 있을 때만)
    block_targets = [
        a.get("target") for a in actions_taken
        if a.get("type", a.get("action_type")) in {"block_ip", "denylist"}
        and a.get("target")
    ]
    if block_targets and mode == "auto":
        fields.append({
            "name": "롤백",
            "value": f"대시보드 → Incidents → {incident_id} → Unblock IP",
            "inline": False,
        })

    embed = {
        "title": _truncate(title, 256),
        "color": color,
        "fields": fields,
        "footer": {"text": f"{incident_id} · {_now_kst()} · {severity.upper()} · InfraRed SOC · {tenant_id}"},
    }
    await _post_embed(url, embed)
    return True


async def send_discord_correlation_alert(
    *,
    tenant_id: str,
    asset_name: str,
    source_ips: list[str],
    first_seen_at: str,
    last_seen_at: str,
    duration_sec: int,
    incident_count: int,
    mitre_technique: str = "T1595",
    webhook_url: str | None = None,
) -> bool:
    """상관관계 경보 — 단시간 내 복수 IP가 동일 자산 공격 시 발송.

    alert_grouping.check_and_record_multi_ip() 가 threshold 초과를 감지하면 호출.

    파라미터:
        source_ips     : 공격에 참여한 출발지 IP 목록
        first_seen_at  : 최초 탐지 시각 (ISO 8601)
        last_seen_at   : 최근 탐지 시각 (ISO 8601)
        duration_sec   : first → last 경과 시간(초)
        incident_count : 연관 Incident 건수
        mitre_technique: 기본값 T1595 (Active Scanning)
    """
    settings = get_settings()
    url = webhook_url or settings.discord_webhook_url
    if not url:
        return False

    ip_list = "  ·  ".join(f"`{ip}`" for ip in source_ips)
    action_text = _build_action_block(
        auto_done=[],
        manual_needed=[
            f"아래 {len(source_ips)}개 IP를 방화벽/fail2ban으로 일괄 차단하세요",
            "동일 ASN·대역 차단 여부를 추가 검토하세요",
            "자산 접근 로그 전수 조사 후 비정상 세션 강제 종료하세요",
        ],
    )

    embed = {
        "title": _truncate(f"상관관계 경보 — {asset_name}", 256),
        "color": 0xB52929,
        "fields": [
            {"name": "공격 IP 수",    "value": f"**{len(source_ips)}개**", "inline": True},
            {"name": "시간 범위",     "value": f"{duration_sec}초 이내",   "inline": True},
            {"name": "MITRE ATT&CK", "value": f"`{mitre_technique}`",     "inline": True},
            {
                "name": "탐지 시각",
                "value": (
                    f"`{_fmt_kst_from_str(first_seen_at)}`"
                    f" → `{_fmt_kst_from_str(last_seen_at)}`"
                ),
                "inline": False,
            },
            {
                "name": "공격 참여 IP",
                "value": _truncate(ip_list, DISCORD_FIELD_LIMIT),
                "inline": False,
            },
            {
                "name": "위협 평가",
                "value": (
                    "단시간 내 복수 IP가 동일 자산을 공격 — "
                    "조율된 분산 스캐닝 또는 봇넷 공격 가능성"
                ),
                "inline": False,
            },
            {
                "name": "권장 조치",
                "value": _truncate(action_text, DISCORD_FIELD_LIMIT),
                "inline": False,
            },
        ],
        "footer": {
            "text": (
                f"CORR-{asset_name} · 연관 인시던트 {incident_count}건"
                f" · {_now_kst()} · InfraRed SOC · {tenant_id}"
            )
        },
    }
    await _post_embed(url, embed)
    return True


# ── 하위 호환 래퍼 ─────────────────────────────────────────────────────────────
# 기존 코드에서 send_discord_embed / send_discord_autoresponse_result 를 직접
# 호출하는 곳이 있을 경우를 위한 래퍼. 새 코드에서는 위 함수를 직접 사용할 것.

async def send_discord_embed(
    *,
    incident_id: str,
    tenant_id: str,
    severity: str,
    plain_summary: str,
    attack_intent: str = "",
    kill_chain_analysis: str = "",
    recommended_actions: list[str] | None = None,
    confidence_note: str = "",
    webhook_url: str | None = None,
) -> bool:
    """하위 호환 래퍼 → send_discord_ai_analysis() 로 위임."""
    summary_parts = [plain_summary]
    if attack_intent:
        summary_parts.append(attack_intent)
    if kill_chain_analysis:
        summary_parts.append(kill_chain_analysis)

    return await send_discord_ai_analysis(
        incident_id=incident_id,
        tenant_id=tenant_id,
        severity=severity,
        event_type="보안 인시던트",
        summary="\n".join(filter(None, summary_parts)),
        manual_actions_needed=recommended_actions or [],
        webhook_url=webhook_url,
    )


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
    """하위 호환 래퍼 → send_discord_response_result() 로 위임."""
    return await send_discord_response_result(
        incident_id=incident_id,
        tenant_id=tenant_id,
        severity=severity,
        mode=mode,
        actions_taken=actions_taken,
        actions_queued=actions_queued,
        webhook_url=webhook_url,
    )
