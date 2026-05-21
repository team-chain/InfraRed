"""
Stripe 과금 연동 — v4.0 설계서 §11.2.
Trial → 유료 전환, 에이전트 수 기반 metered billing, 웹훅 처리.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

try:
    import stripe
    STRIPE_AVAILABLE = True
except ImportError:
    STRIPE_AVAILABLE = False
    logger.warning("stripe package not available. Run: pip install stripe")

from sqlalchemy import text  # noqa: E402

from app.config import get_settings  # noqa: E402
from app.db.connection import get_session  # noqa: E402


class BillingHandler:

    PLAN_TRIAL_DAYS = 14
    PLAN_AGENT_LIMITS = {"starter": 3, "growth": 9999, "enterprise": 9999}
    PLAN_RETENTION_DAYS = {"starter": 7, "growth": 90, "enterprise": 365}

    def __init__(self):
        self.settings = get_settings()
        if STRIPE_AVAILABLE and self.settings.stripe_secret_key:
            stripe.api_key = self.settings.stripe_secret_key

    async def create_subscription(
        self, tenant_id: str, email: str, company_name: str, plan: str
    ) -> dict:
        """Trial 시작 또는 유료 플랜 구독"""
        if not STRIPE_AVAILABLE or not self.settings.stripe_secret_key:
            # Mock: stripe 없이 DB만 업데이트
            trial_ends = datetime.now(timezone.utc) + timedelta(days=self.PLAN_TRIAL_DAYS)
            async with get_session() as session:
                await session.execute(text("""
                    UPDATE tenants SET
                        plan = :plan,
                        billing_email = :email,
                        trial_ends_at = :trial_ends,
                        plan_started_at = NOW(),
                        agent_limit = :limit
                    WHERE tenant_id = :tenant_id
                """), {
                    "plan": plan, "email": email,
                    "trial_ends": trial_ends,
                    "limit": self.PLAN_AGENT_LIMITS.get(plan, 3),
                    "tenant_id": tenant_id
                })
                await session.commit()
            return {"status": "mock_trial_started", "plan": plan, "trial_ends_at": trial_ends.isoformat()}

        # Stripe Customer 생성
        customer = stripe.Customer.create(
            email=email,
            name=company_name,
            metadata={"tenant_id": tenant_id},
        )

        price_id = (
            self.settings.stripe_price_enterprise
            if plan == "enterprise"
            else self.settings.stripe_price_growth
        )

        subscription = stripe.Subscription.create(
            customer=customer.id,
            items=[{"price": price_id}] if price_id else [],
            trial_period_days=self.PLAN_TRIAL_DAYS if plan == "growth" else None,
            metadata={"tenant_id": tenant_id, "plan": plan},
        )

        trial_ends = (
            datetime.fromtimestamp(subscription.trial_end, tz=timezone.utc)
            if subscription.trial_end else None
        )

        async with get_session() as session:
            await session.execute(text("""
                UPDATE tenants SET
                    plan = :plan,
                    billing_email = :email,
                    stripe_customer_id = :customer_id,
                    stripe_subscription_id = :sub_id,
                    stripe_subscription_item_id = :item_id,
                    plan_started_at = NOW(),
                    trial_ends_at = :trial_ends,
                    agent_limit = :limit
                WHERE tenant_id = :tenant_id
            """), {
                "plan": plan, "email": email,
                "customer_id": customer.id,
                "sub_id": subscription.id,
                "item_id": subscription["items"]["data"][0]["id"] if subscription.get("items") else None,
                "trial_ends": trial_ends,
                "limit": self.PLAN_AGENT_LIMITS.get(plan, 3),
                "tenant_id": tenant_id,
            })
            await session.commit()

        return {
            "status": "subscription_created",
            "plan": plan,
            "stripe_subscription_id": subscription.id,
            "trial_ends_at": trial_ends.isoformat() if trial_ends else None,
        }

    async def report_agent_usage(self, tenant_id: str) -> dict:
        """활성 에이전트 수를 Stripe metered billing에 보고 (매일 Lambda 실행)"""
        async with get_session() as session:
            result = await session.execute(text("""
                SELECT t.stripe_subscription_item_id, t.plan,
                       COUNT(a.id) AS agent_count
                FROM tenants t
                LEFT JOIN agents a ON a.tenant_id = t.id AND a.status = 'active'
                WHERE t.id = :tenant_id
                GROUP BY t.stripe_subscription_item_id, t.plan
            """), {"tenant_id": tenant_id})
            row = result.fetchone()

        if not row:
            return {"status": "tenant_not_found"}

        agent_count = row.agent_count or 0

        # DB에 usage 기록
        async with get_session() as session:
            await session.execute(text("""
                INSERT INTO agent_usage_reports (tenant_id, agent_count, stripe_reported)
                VALUES (:tenant_id, :count, :reported)
            """), {
                "tenant_id": tenant_id,
                "count": agent_count,
                "reported": bool(STRIPE_AVAILABLE and row.stripe_subscription_item_id and self.settings.stripe_secret_key),
            })
            await session.commit()

        if STRIPE_AVAILABLE and row.stripe_subscription_item_id and self.settings.stripe_secret_key:
            stripe.SubscriptionItem.create_usage_record(
                row.stripe_subscription_item_id,
                quantity=agent_count,
                timestamp=int(datetime.now(timezone.utc).timestamp()),
                action="set",
            )
            return {"status": "reported", "agent_count": agent_count}

        return {"status": "mock_reported", "agent_count": agent_count}

    async def get_subscription_status(self, tenant_id: str) -> dict:
        """현재 과금 상태 조회"""
        async with get_session() as session:
            result = await session.execute(text("""
                SELECT plan, plan_started_at, trial_ends_at,
                       stripe_customer_id, stripe_subscription_id,
                       billing_email, grace_period_ends_at, agent_limit
                FROM tenants WHERE tenant_id = :tenant_id
            """), {"tenant_id": tenant_id})
            row = result.fetchone()

        if not row:
            return {"status": "not_found"}

        now = datetime.now(timezone.utc)
        is_trial = bool(row.trial_ends_at and row.trial_ends_at > now)
        is_grace = bool(row.grace_period_ends_at and row.grace_period_ends_at > now)

        return {
            "plan": row.plan or "starter",
            "is_trial": is_trial,
            "trial_ends_at": row.trial_ends_at.isoformat() if row.trial_ends_at else None,
            "is_grace_period": is_grace,
            "grace_period_ends_at": row.grace_period_ends_at.isoformat() if row.grace_period_ends_at else None,
            "billing_email": row.billing_email,
            "stripe_customer_id": row.stripe_customer_id,
            "agent_limit": row.agent_limit or 3,
            "features": self._get_plan_features(row.plan or "starter"),
        }

    def _get_plan_features(self, plan: str) -> dict:
        return {
            "starter":    {"max_agents": 3, "retention_days": 7,   "ai_calls_monthly": 50,  "ueba": False, "sso": False, "siem": False},
            "growth":     {"max_agents": 9999, "retention_days": 90,  "ai_calls_monthly": -1, "ueba": True,  "sso": "oidc", "siem": False},
            "enterprise": {"max_agents": 9999, "retention_days": 365, "ai_calls_monthly": -1, "ueba": True,  "sso": "saml+ldap", "siem": True},
        }.get(plan, {"max_agents": 3, "retention_days": 7, "ai_calls_monthly": 50, "ueba": False, "sso": False, "siem": False})

    async def cancel_subscription(self, tenant_id: str) -> dict:
        """구독 취소 → Starter 다운그레이드"""
        async with get_session() as session:
            result = await session.execute(text(
                "SELECT stripe_subscription_id FROM tenants WHERE tenant_id = :tid"
            ), {"tid": tenant_id})
            row = result.fetchone()

        if row and row.stripe_subscription_id and STRIPE_AVAILABLE and self.settings.stripe_secret_key:
            stripe.Subscription.cancel(row.stripe_subscription_id)

        async with get_session() as session:
            await session.execute(text("""
                UPDATE tenants SET plan = 'starter', agent_limit = 3,
                    stripe_subscription_id = NULL, stripe_subscription_item_id = NULL
                WHERE tenant_id = :tenant_id
            """), {"tenant_id": tenant_id})
            await session.commit()

        return {"status": "cancelled", "downgraded_to": "starter"}

    async def handle_webhook(self, payload_bytes: bytes, sig_header: str) -> dict:
        """Stripe 웹훅 이벤트 처리"""
        if not STRIPE_AVAILABLE or not self.settings.stripe_webhook_secret:
            return {"status": "stripe_not_configured"}

        try:
            event = stripe.Webhook.construct_event(
                payload_bytes, sig_header, self.settings.stripe_webhook_secret
            )
        except stripe.error.SignatureVerificationError:
            return {"status": "invalid_signature"}

        tenant_id = event.data.object.metadata.get("tenant_id") if hasattr(event.data.object, "metadata") else None

        # 중복 처리 방지: billing_events에 저장
        async with get_session() as session:
            exists = await session.execute(text(
                "SELECT id FROM billing_events WHERE stripe_event_id = :eid"
            ), {"eid": event.id})
            if exists.fetchone():
                return {"status": "already_processed"}

            await session.execute(text("""
                INSERT INTO billing_events (tenant_id, stripe_event_id, event_type, payload)
                VALUES (:tid, :eid, :etype, :payload::jsonb)
            """), {
                "tid": tenant_id or "unknown",
                "eid": event.id,
                "etype": event.type,
                "payload": str(event),
            })
            await session.commit()

        if event.type == "invoice.payment_failed" and tenant_id:
            # 7일 유예 기간 설정
            grace_ends = datetime.now(timezone.utc) + timedelta(days=7)
            async with get_session() as session:
                await session.execute(text(
                    "UPDATE tenants SET grace_period_ends_at = :grace WHERE tenant_id = :tid"
                ), {"grace": grace_ends, "tid": tenant_id})
                await session.commit()

        elif event.type == "customer.subscription.deleted" and tenant_id:
            async with get_session() as session:
                await session.execute(text("""
                    UPDATE tenants SET plan = 'starter', agent_limit = 3,
                        stripe_subscription_id = NULL
                    WHERE tenant_id = :tid
                """), {"tid": tenant_id})
                await session.commit()

        elif event.type == "customer.subscription.updated" and tenant_id:
            sub = event.data.object
            new_plan = sub.metadata.get("plan", "growth")
            async with get_session() as session:
                await session.execute(text(
                    "UPDATE tenants SET plan = :plan, agent_limit = :limit WHERE tenant_id = :tid"
                ), {"plan": new_plan, "limit": self.PLAN_AGENT_LIMITS.get(new_plan, 3), "tid": tenant_id})
                await session.commit()

        return {"status": "processed", "event_type": event.type}
