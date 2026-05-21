"""Combined dispatcher entrypoint — uses per-tenant Discord/email config."""
from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass

from sqlalchemy import text

from app.common.logging import get_logger
from app.db.connection import get_session
from app.dispatcher.discord import send_discord_ai_analysis
from app.dispatcher.email import send_email_alert
from app.dispatcher.slack import send_slack_ai_analysis
from app.models.llm import LLMResult

log = get_logger(__name__)


@dataclass(frozen=True)
class DispatchResult:
    discord_sent: bool = False
    slack_sent: bool = False
    email_sent: bool = False
    errors: tuple[str, ...] = ()

    @property
    def dispatched(self) -> bool:
        return self.discord_sent or self.slack_sent or self.email_sent


async def _get_tenant_dispatch_config(tenant_id: str) -> dict:
    """테넌트별 Discord/Slack/Email 설정을 DB에서 조회. 없으면 빈 dict.

    slack_webhook_url 컬럼은 migrate_v2.sql에서 추가됨. 없으면 SELECT 실패하니
    안전 fallback으로 한 번 더 조회.
    """
    try:
        async with get_session() as session:
            row = await session.execute(
                text(
                    "SELECT discord_webhook_url, slack_webhook_url, alert_email_to "
                    "FROM tenant_settings WHERE tenant_id = :t"
                ),
                {"t": tenant_id},
            )
            record = row.mappings().first()
        return dict(record) if record else {}
    except Exception as exc:
        # 컬럼 없으면 slack 빼고 재시도
        log.warning("tenant_dispatch_config_fetch_failed tenant=%s error=%s", tenant_id, exc)
        try:
            async with get_session() as session:
                row = await session.execute(
                    text(
                        "SELECT discord_webhook_url, alert_email_to "
                        "FROM tenant_settings WHERE tenant_id = :t"
                    ),
                    {"t": tenant_id},
                )
                record = row.mappings().first()
            return dict(record) if record else {}
        except Exception:
            return {}


def _extract_mitre_techniques(text_blob: str | None) -> list[str]:
    """텍스트에서 MITRE ATT&CK 기법 ID(T1xxx) 목록 추출."""
    if not text_blob:
        return []
    return list(dict.fromkeys(re.findall(r"T\d{4}(?:\.\d{3})?", text_blob)))


def _parse_confidence(note: str | None) -> float | None:
    """confidence_note 문자열에서 0~1 사이 float 추출. 없으면 None."""
    if not note:
        return None
    m = re.search(r"(\d+(?:\.\d+)?)\s*%", note)
    if m:
        return float(m.group(1)) / 100
    m = re.search(r"0?\.\d+", note)
    if m:
        val = float(m.group(0))
        return val if val <= 1.0 else None
    return None


async def dispatch_incident_alert(
    tenant_id: str,
    result: LLMResult,
    severity: str = "high",
    asset_name: str = "",
    analysis_elapsed_sec: int | None = None,
) -> DispatchResult:
    """AI 분석 완료 후 2차 Discord 알림 + Critical 이메일 발송.

    파라미터:
        asset_name           : 탐지된 서버/자산 이름 (1차 알림과 일관성 유지)
        analysis_elapsed_sec : 1차 알림 발송 후 AI 분석 완료까지 소요 시간(초)
    """
    normalized_severity = severity.lower()
    errors: list[str] = []
    discord_sent = False
    slack_sent = False
    email_sent = False

    tenant_cfg = await _get_tenant_dispatch_config(tenant_id)
    discord_url = tenant_cfg.get("discord_webhook_url") or None
    slack_url   = tenant_cfg.get("slack_webhook_url") or None
    email_to    = tenant_cfg.get("alert_email_to") or None

    # ── LLMResult에서 구조화된 필드 추출 ────────────────────────────────────
    # AI 판단 본문: plain_summary + attack_intent 결합
    summary_parts = [p for p in [result.plain_summary, result.attack_intent] if p]
    summary = "\n".join(summary_parts) or "AI 분석 결과 없음"

    # MITRE 기법: kill_chain_analysis / attack_intent 텍스트에서 추출
    mitre_blob = " ".join(filter(None, [result.kill_chain_analysis, result.attack_intent]))
    mitre_techniques = _extract_mitre_techniques(mitre_blob)

    # Kill Chain 단계: kill_chain_analysis 텍스트 첫 문장 사용
    kill_chain_stage = ""
    if result.kill_chain_analysis:
        kill_chain_stage = result.kill_chain_analysis.split(".")[0].strip()

    # 신뢰도: confidence_note 문자열에서 파싱 시도
    ai_conf = _parse_confidence(result.confidence_note)

    try:
        discord_sent = await send_discord_ai_analysis(
            incident_id=result.incident_id,
            tenant_id=tenant_id,
            severity=normalized_severity,
            asset_name=asset_name,
            event_type="보안 인시던트",
            summary=summary,
            kill_chain_stage=kill_chain_stage,
            mitre_techniques=mitre_techniques or None,
            manual_actions_needed=result.recommended_actions,
            ai_confidence=ai_conf,
            analysis_elapsed_sec=analysis_elapsed_sec,
            webhook_url=discord_url,
        )
    except Exception as exc:  # noqa: BLE001
        errors.append(f"discord:{exc}")
        log.exception("discord_alert_dispatch_failed", incident_id=result.incident_id, error=str(exc))

    # Slack — 같은 정보 모델, 풍성한 Block Kit attachment
    try:
        slack_sent = await send_slack_ai_analysis(
            incident_id=result.incident_id,
            tenant_id=tenant_id,
            severity=normalized_severity,
            asset_name=asset_name,
            event_type="보안 인시던트",
            summary=summary,
            kill_chain_stage=kill_chain_stage,
            mitre_techniques=mitre_techniques or None,
            manual_actions_needed=result.recommended_actions,
            ai_confidence=ai_conf,
            analysis_elapsed_sec=analysis_elapsed_sec,
            webhook_url=slack_url,
        )
    except Exception as exc:  # noqa: BLE001
        errors.append(f"slack:{exc}")
        log.exception("slack_alert_dispatch_failed", incident_id=result.incident_id, error=str(exc))

    if normalized_severity == "critical":
        email_text = (
            f"[InfraRed] {tenant_id} {result.incident_id}\n"
            f"{result.plain_summary}\n"
            f"조치: {', '.join(result.recommended_actions[:3])}"
        )
        try:
            email_sent = await asyncio.to_thread(
                send_email_alert,
                f"InfraRed 인시던트 {result.incident_id}",
                email_text,
                to_override=email_to,
            )
        except Exception as exc:  # noqa: BLE001
            errors.append(f"email:{exc}")
            log.exception("email_alert_dispatch_failed", incident_id=result.incident_id, error=str(exc))

    dispatch_result = DispatchResult(
        discord_sent=discord_sent,
        slack_sent=slack_sent,
        email_sent=email_sent,
        errors=tuple(errors),
    )
    log.info(
        "incident_alert_dispatched",
        incident_id=result.incident_id,
        severity=normalized_severity,
        dispatched=dispatch_result.dispatched,
        discord_sent=discord_sent,
        slack_sent=slack_sent,
        email_sent=email_sent,
        errors=list(errors),
    )
    return dispatch_result
