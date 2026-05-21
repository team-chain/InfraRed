"""Email verification + password reset routes.

엔드포인트:
  POST /auth/request-verification          - 인증 메일 재발송 (로그인된 본인)
  GET  /auth/verify-email/{token}          - 인증 토큰 검증 (이메일 링크 클릭)
  POST /auth/forgot-password               - 비번 재설정 메일 요청 (비로그인)
  POST /auth/reset-password                - 새 비번 설정 (토큰 + new password)

토큰
====
- verification_token : 단순 URL-safe 32-byte secret. 사용 시 DB에서 NULL로 클리어.
- password_reset_token : 동일 방식. 1시간 TTL.
보안 노트: 이메일은 단순 한 번 발송용 토큰. JWT 미사용 (revoke 즉시 필요).
"""
from __future__ import annotations

import secrets
from asyncio import to_thread
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import text

from app.common.logging import get_logger
from app.config import get_settings
from app.db.connection import get_session
from app.dispatcher.email import send_email_alert
from app.iam.audit import write_audit_log
from app.iam.security import verify_user_token
from app.iam.token_revocation import revoke_user_tokens
from app.middleware.rate_limit import (
    limit_forgot_pw,
    limit_request_verif,
    limit_reset_pw,
    limit_verify_email,
)

router = APIRouter(tags=["auth-verification"])
log = get_logger(__name__)

PASSWORD_RESET_TTL_SECONDS = 60 * 60  # 1시간
VERIFICATION_TOKEN_RESEND_INTERVAL_SECONDS = 60  # 메일 재발송 throttle


def _new_token() -> str:
    """URL-safe 32-byte random token (URL에 그대로 들어가도 안전)."""
    return secrets.token_urlsafe(32)


async def _send_verification_email(email: str, token: str, tenant_id: str) -> None:
    """인증 메일 발송. SES wiring 완성되면 실제 발송, 지금은 dispatcher 통해 best-effort."""
    settings = get_settings()
    base = settings.frontend_base_url or "https://app.infrared.kr"
    link = f"{base}/?verify_email={token}"
    body = (
        f"InfraRed 가입을 환영합니다.\n\n"
        f"다음 링크로 이메일을 인증해주세요 (24시간 유효):\n"
        f"{link}\n\n"
        f"본인이 가입한 적이 없다면 이 메일을 무시하세요."
    )
    # Best-effort 발송 — 실패해도 가입은 진행 (사용자가 나중에 재발송 요청 가능)
    try:
        # email 모듈은 동기 — to_thread 로 wrap
        await to_thread(send_email_alert, "[InfraRed] 이메일 인증", body, to_override=email)
        log.info("verification_email_sent", email_hash=hash(email), tenant_id=tenant_id)
    except Exception as exc:  # noqa: BLE001
        log.warning("verification_email_send_failed", error=str(exc), email_hash=hash(email))


async def _send_reset_email(email: str, token: str) -> None:
    settings = get_settings()
    base = settings.frontend_base_url or "https://app.infrared.kr"
    link = f"{base}/?reset_token={token}"
    body = (
        f"InfraRed 비밀번호 재설정 요청을 받았습니다.\n\n"
        f"다음 링크에서 새 비밀번호를 설정해주세요 (1시간 유효):\n"
        f"{link}\n\n"
        f"본인이 요청하지 않았다면 이 메일을 무시하세요. 비밀번호는 변경되지 않습니다."
    )
    try:
        await to_thread(send_email_alert, "[InfraRed] 비밀번호 재설정", body, to_override=email)
        log.info("reset_email_sent", email_hash=hash(email))
    except Exception as exc:  # noqa: BLE001
        log.warning("reset_email_send_failed", error=str(exc), email_hash=hash(email))


# ── 모델 ─────────────────────────────────────────────────────────────────────

class ForgotPasswordRequest(BaseModel):
    email: EmailStr
    tenant_id: str | None = None  # 비우면 모든 tenant에서 동일 email 검색 (한 명일 가능성 큼)


class ResetPasswordRequest(BaseModel):
    token: str = Field(..., min_length=20)
    new_password: str = Field(..., min_length=8)


# ── 라우트 ────────────────────────────────────────────────────────────────────

@router.post("/auth/request-verification", status_code=202)
async def request_verification_email(
    claims: dict = Depends(verify_user_token),
    _rate: None = Depends(limit_request_verif),
) -> dict[str, Any]:
    """현재 로그인된 사용자의 이메일 인증 메일 재발송.

    이미 verified면 no-op. throttle: 60초당 1회.
    """
    user_id = str(claims.get("sub"))
    async with get_session() as session:
        row = await session.execute(
            text(
                "SELECT email, tenant_id, email_verified, verification_sent_at "
                "FROM users WHERE user_id = :uid"
            ),
            {"uid": user_id},
        )
        user = row.mappings().first()
        if not user:
            raise HTTPException(status_code=404, detail="user_not_found")
        if user["email_verified"]:
            return {"status": "already_verified"}

        now = datetime.now(timezone.utc)
        last_sent = user["verification_sent_at"]
        if last_sent and (now - last_sent).total_seconds() < VERIFICATION_TOKEN_RESEND_INTERVAL_SECONDS:
            raise HTTPException(status_code=429, detail="too_many_requests")

        token = _new_token()
        await session.execute(
            text(
                "UPDATE users SET verification_token = :t, verification_sent_at = :now "
                "WHERE user_id = :uid"
            ),
            {"t": token, "now": now, "uid": user_id},
        )
        await session.commit()
        email = user["email"]
        tenant_id = user["tenant_id"]

    await _send_verification_email(email, token, tenant_id)
    return {"status": "sent", "email": email}


@router.get("/auth/verify-email/{token}")
async def verify_email(
    token: str,
    _rate: None = Depends(limit_verify_email),
) -> dict[str, Any]:
    """이메일 링크 클릭 — 토큰으로 사용자 활성화."""
    if len(token) < 20:
        raise HTTPException(status_code=400, detail="invalid_token")
    async with get_session() as session:
        row = await session.execute(
            text(
                "SELECT user_id::text, email, tenant_id, email_verified "
                "FROM users WHERE verification_token = :t"
            ),
            {"t": token},
        )
        user = row.mappings().first()
        if not user:
            raise HTTPException(status_code=404, detail="invalid_or_expired_token")
        if user["email_verified"]:
            # idempotent
            return {"status": "already_verified", "email": user["email"]}

        await session.execute(
            text(
                "UPDATE users SET email_verified = TRUE, email_verified_at = NOW(), "
                "verification_token = NULL WHERE user_id = :uid::uuid"
            ),
            {"uid": user["user_id"]},
        )
        await session.commit()

    await write_audit_log(
        tenant_id=user["tenant_id"],
        actor=user["email"],
        action="auth.verify_email",
        resource="user",
        metadata={"user_id": user["user_id"]},
    )
    return {"status": "verified", "email": user["email"]}


@router.post("/auth/forgot-password", status_code=202)
async def forgot_password(
    payload: ForgotPasswordRequest,
    _rate: None = Depends(limit_forgot_pw),
) -> dict[str, Any]:
    """비밀번호 재설정 메일 발송.

    보안: 이메일이 DB에 있든 없든 항상 202 반환 (사용자 enumeration 방지).
    실제 발송은 user가 있을 때만.
    """
    async with get_session() as session:
        query = "SELECT user_id::text, email, tenant_id FROM users WHERE email = :email"
        params: dict[str, Any] = {"email": payload.email}
        if payload.tenant_id:
            query += " AND tenant_id = :tid"
            params["tid"] = payload.tenant_id
        row = await session.execute(text(query + " LIMIT 1"), params)
        user = row.mappings().first()

        if user:
            token = _new_token()
            expires_at = datetime.now(timezone.utc) + timedelta(seconds=PASSWORD_RESET_TTL_SECONDS)
            await session.execute(
                text(
                    "UPDATE users SET password_reset_token = :t, password_reset_expires_at = :exp "
                    "WHERE user_id = :uid::uuid"
                ),
                {"t": token, "exp": expires_at, "uid": user["user_id"]},
            )
            await session.commit()
            await _send_reset_email(user["email"], token)
            await write_audit_log(
                tenant_id=user["tenant_id"],
                actor=user["email"],
                action="auth.forgot_password",
                resource="user",
                metadata={"user_id": user["user_id"]},
            )
        else:
            # enumeration 방지 — 항상 발송한 것처럼 보임
            log.info("forgot_password_no_user", email_hash=hash(payload.email))

    return {"status": "if_account_exists_email_sent"}


@router.post("/auth/reset-password")
async def reset_password(
    payload: ResetPasswordRequest,
    _rate: None = Depends(limit_reset_pw),
) -> dict[str, Any]:
    """토큰으로 새 비밀번호 설정 + 모든 기존 토큰 revoke."""
    async with get_session() as session:
        row = await session.execute(
            text(
                "SELECT user_id::text, email, tenant_id, password_reset_expires_at "
                "FROM users WHERE password_reset_token = :t"
            ),
            {"t": payload.token},
        )
        user = row.mappings().first()
        if not user:
            raise HTTPException(status_code=404, detail="invalid_or_expired_token")

        expires_at = user["password_reset_expires_at"]
        if not expires_at or expires_at < datetime.now(timezone.utc):
            raise HTTPException(status_code=400, detail="token_expired")

        await session.execute(
            text(
                "UPDATE users SET "
                "  password_hash = crypt(:pw, gen_salt('bf')), "
                "  password_reset_token = NULL, "
                "  password_reset_expires_at = NULL "
                "WHERE user_id = :uid::uuid"
            ),
            {"pw": payload.new_password, "uid": user["user_id"]},
        )
        await session.commit()

    # 모든 기존 토큰 revoke (security best practice)
    try:
        await revoke_user_tokens(user["user_id"])
    except Exception as exc:  # noqa: BLE001
        log.warning("revoke_after_reset_failed", error=str(exc))

    await write_audit_log(
        tenant_id=user["tenant_id"],
        actor=user["email"],
        action="auth.reset_password",
        resource="user",
        metadata={"user_id": user["user_id"]},
    )
    return {"status": "password_updated", "email": user["email"]}
