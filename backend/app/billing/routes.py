"""Stripe 과금 API 라우터 — v4.0 §11."""
from __future__ import annotations
import logging
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from app.billing.stripe_handler import BillingHandler
from app.iam.rbac_v2 import require_any_role

router = APIRouter(prefix="/api/v1/billing", tags=["billing"])
logger = logging.getLogger(__name__)

class SubscribeRequest(BaseModel):
    plan: str  # starter / growth / enterprise
    email: str
    company_name: str = ""

@router.post("/subscribe")
async def subscribe(
    body: SubscribeRequest,
    claims: dict = Depends(require_any_role("owner")),
):
    handler = BillingHandler()
    result = await handler.create_subscription(
        tenant_id=claims["tenant_id"],
        email=body.email,
        company_name=body.company_name,
        plan=body.plan,
    )
    return result

@router.get("/status")
async def billing_status(claims: dict = Depends(require_any_role("owner", "security_manager"))):
    handler = BillingHandler()
    return await handler.get_subscription_status(claims["tenant_id"])

@router.post("/cancel")
async def cancel(claims: dict = Depends(require_any_role("owner"))):
    handler = BillingHandler()
    return await handler.cancel_subscription(claims["tenant_id"])

@router.post("/webhook")
async def stripe_webhook(request: Request):
    """Stripe 웹훅 — 서명 검증으로 인증"""
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature", "")
    handler = BillingHandler()
    result = await handler.handle_webhook(payload, sig_header)
    if result.get("status") == "invalid_signature":
        raise HTTPException(status_code=400, detail="Invalid Stripe signature")
    return result

@router.get("/usage")
async def usage(claims: dict = Depends(require_any_role("owner", "security_manager"))):
    """이번 달 에이전트 사용량 + 과금 현황"""
    from app.db.connection import get_session
    from sqlalchemy import text
    async with get_session() as session:
        result = await session.execute(text("""
            SELECT agent_count, reported_at, stripe_reported
            FROM agent_usage_reports
            WHERE tenant_id = :tid
            ORDER BY reported_at DESC LIMIT 30
        """), {"tid": claims["tenant_id"]})
        rows = result.fetchall()
    return {
        "usage_history": [
            {"agent_count": r.agent_count, "reported_at": r.reported_at.isoformat(), "stripe_reported": r.stripe_reported}
            for r in rows
        ]
    }
