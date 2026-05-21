"""Break-Glass 비상 대응 핸들러 — v7.0.

비상 시 승인 없이 즉각 대응 실행을 허용하는 메커니즘.
모든 Break-Glass 사용은 audit_logs에 반드시 기록되고,
모든 ADMIN 역할 사용자에게 알림이 발송된다.
"""
from __future__ import annotations

import json
import logging
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy import text

from app.db.connection import get_session
from app.iam.audit import write_audit_log

log = logging.getLogger(__name__)

BREAK_GLASS_EVENT_TYPE = "BREAK_GLASS"


@dataclass
class BreakGlassEvent:
    """Break-Glass 실행 결과."""
    event_id: str
    tenant_id: str
    operator_id: str
    action: dict
    justification: str
    executed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "tenant_id": self.tenant_id,
            "operator_id": self.operator_id,
            "action": self.action,
            "justification": self.justification,
            "executed_at": self.executed_at,
        }


class BreakGlassHandler:
    """Break-Glass 비상 대응 핸들러.

    비상 시 승인 없이 대응 실행 허용.
    모든 Break-Glass 사용은 audit_logs에 반드시 기록.
    """

    async def execute_break_glass(
        self,
        tenant_id: str,
        operator_id: str,
        action: dict,
        justification: str,
    ) -> BreakGlassEvent:
        """Break-Glass 실행.

        1. approval_required 무시하고 즉시 실행
        2. audit_logs에 event_type="BREAK_GLASS" 기록
        3. 모든 ADMIN 역할 사용자에게 알림 발송
        4. BreakGlassEvent 반환

        Args:
            tenant_id: 테넌트 ID
            operator_id: 실행한 운영자 ID (ADMIN 사용자)
            action: 실행할 액션 정보 (action_type, target, payload 등)
            justification: 비상 실행 사유 (감사 기록용)

        Returns:
            BreakGlassEvent
        """
        event_id = secrets.token_hex(16)
        executed_at = datetime.now(timezone.utc).isoformat()

        event = BreakGlassEvent(
            event_id=event_id,
            tenant_id=tenant_id,
            operator_id=operator_id,
            action=action,
            justification=justification,
            executed_at=executed_at,
        )

        log.warning(
            "BREAK_GLASS_EXECUTED tenant=%s operator=%s event_id=%s action_type=%s justification=%r",
            tenant_id, operator_id, event_id,
            action.get("action_type", "unknown"), justification,
        )

        # 1. audit_logs에 BREAK_GLASS 이벤트 기록
        await write_audit_log(
            tenant_id=tenant_id,
            actor=operator_id,
            action=BREAK_GLASS_EVENT_TYPE,
            resource=action.get("target"),
            metadata={
                "event_id": event_id,
                "action": action,
                "justification": justification,
                "executed_at": executed_at,
                "event_type": BREAK_GLASS_EVENT_TYPE,
            },
        )

        # 2. 모든 ADMIN 역할 사용자에게 알림 발송
        await self._notify_admins(tenant_id, event)

        return event

    async def _notify_admins(self, tenant_id: str, event: BreakGlassEvent) -> None:
        """ADMIN 역할 사용자 목록 조회 후 알림 발송."""
        try:
            async with get_session() as session:
                result = await session.execute(
                    text("""
                        SELECT user_id, email
                        FROM users
                        WHERE tenant_id = :tenant_id
                          AND role = 'admin'
                          AND is_active = TRUE
                    """),
                    {"tenant_id": tenant_id},
                )
                admins = result.mappings().all()

            if not admins:
                log.warning(
                    "break_glass_no_admins_to_notify tenant=%s event_id=%s",
                    tenant_id, event.event_id,
                )
                return

            # 알림 발송 (Discord/이메일 등 설정된 채널 활용)
            from app.workers.alert.dispatcher import dispatch_alert
            message = (
                f"[BREAK-GLASS] 비상 대응이 실행됐습니다.\n"
                f"실행자: {event.operator_id}\n"
                f"액션: {event.action.get('action_type', 'unknown')} → {event.action.get('target', 'unknown')}\n"
                f"사유: {event.justification}\n"
                f"이벤트 ID: {event.event_id}\n"
                f"시각: {event.executed_at}"
            )
            try:
                await dispatch_alert(
                    tenant_id=tenant_id,
                    title="[BREAK-GLASS] 비상 대응 실행",
                    message=message,
                    severity="critical",
                )
            except Exception as alert_exc:
                log.warning(
                    "break_glass_alert_dispatch_failed tenant=%s error=%s",
                    tenant_id, alert_exc,
                )

        except Exception as exc:
            # 알림 실패가 Break-Glass 실행을 막으면 안 됨
            log.error(
                "break_glass_notify_admins_failed tenant=%s event_id=%s error=%s",
                tenant_id, event.event_id, exc,
            )

    async def list_break_glass_events(
        self,
        tenant_id: str,
        days: int = 30,
    ) -> list[BreakGlassEvent]:
        """Break-Glass 이벤트 이력 조회.

        audit_logs 테이블에서 event_type="BREAK_GLASS" 인 레코드 조회.

        Args:
            tenant_id: 테넌트 ID
            days: 조회 기간 (기본 30일)

        Returns:
            BreakGlassEvent 목록 (최신순)
        """
        try:
            async with get_session() as session:
                result = await session.execute(
                    text("""
                        SELECT
                            actor,
                            resource,
                            metadata,
                            created_at
                        FROM audit_logs
                        WHERE tenant_id = :tenant_id
                          AND action = :event_type
                          AND created_at >= NOW() - INTERVAL '1 day' * :days
                        ORDER BY created_at DESC
                        LIMIT 500
                    """),
                    {
                        "tenant_id": tenant_id,
                        "event_type": BREAK_GLASS_EVENT_TYPE,
                        "days": days,
                    },
                )
                rows = result.mappings().all()

            events: list[BreakGlassEvent] = []
            for row in rows:
                meta = row["metadata"] or {}
                if isinstance(meta, str):
                    meta = json.loads(meta)

                events.append(BreakGlassEvent(
                    event_id=meta.get("event_id", "unknown"),
                    tenant_id=tenant_id,
                    operator_id=row["actor"],
                    action=meta.get("action", {}),
                    justification=meta.get("justification", ""),
                    executed_at=meta.get("executed_at", str(row.get("created_at", ""))),
                ))

            return events

        except Exception as exc:
            log.error(
                "break_glass_list_events_failed tenant=%s error=%s", tenant_id, exc
            )
            return []
