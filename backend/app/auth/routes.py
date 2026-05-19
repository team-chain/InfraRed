"""
SSO / MFA 인증 라우터.
v4.0 설계서 §9.1–9.2 참조.
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel

from app.auth.mfa import get_mfa_handler
from app.auth.sso import get_sso_handler
from app.config import get_settings
from app.iam.rbac_v2 import require_any_role
from app.iam.security import create_token

router = APIRouter(prefix="/auth", tags=["auth-enterprise"])
logger = logging.getLogger(__name__)


# ─── MFA 요청/응답 모델 ────────────────────────────────────────────────────────

class MFASetupRequest(BaseModel):
    user_email: str


class MFAVerifyRequest(BaseModel):
    encrypted_secret: str
    token: str


class BackupCodeVerifyRequest(BaseModel):
    backup_codes: list[str]
    code: str


# ─── MFA 엔드포인트 ────────────────────────────────────────────────────────────

@router.post("/mfa/setup", summary="TOTP MFA 등록 (QR 코드 + 백업 코드)")
async def setup_mfa(req: MFASetupRequest) -> dict:
    """MFA 등록 — QR 코드 Base64 + 백업 코드 10개 + 암호화된 시크릿 반환."""
    handler = get_mfa_handler()
    try:
        result = handler.setup_mfa(req.user_email)
        return {
            "qr_code_base64": result.qr_code_base64,
            "encrypted_secret": result.encrypted_secret,
            "backup_codes": result.backup_codes,
            "totp_uri": result.totp_uri,
        }
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail=str(exc))


@router.post("/mfa/verify", summary="TOTP 토큰 검증")
async def verify_mfa(req: MFAVerifyRequest) -> dict:
    """30초 윈도우(±1) TOTP 토큰 검증."""
    handler = get_mfa_handler()
    valid = handler.verify_totp(req.encrypted_secret, req.token)
    if not valid:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid_totp_token")
    return {"status": "verified"}


@router.post("/mfa/verify-backup", summary="백업 코드 검증")
async def verify_backup_code(req: BackupCodeVerifyRequest) -> dict:
    """백업 코드 1회 사용 후 제거, 남은 코드 목록 반환."""
    handler = get_mfa_handler()
    valid, remaining = handler.verify_backup_code(req.backup_codes, req.code)
    if not valid:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid_backup_code")
    return {
        "status": "verified",
        "remaining_codes": len(remaining),
        "updated_codes": remaining,
    }


# ─── SSO 엔드포인트 ────────────────────────────────────────────────────────────

@router.get("/sso/authorize", summary="SSO 인증 URL 반환")
async def sso_authorize(
    tenant_id: str = Query(..., description="테넌트 식별자"),
    org_id: Optional[str] = Query(None, description="WorkOS Organization ID"),
) -> dict:
    """WorkOS SSO 인증 URL 생성."""
    settings = get_settings()
    if not settings.workos_api_key:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="SSO not configured. Set WORKOS_API_KEY environment variable.",
        )
    handler = get_sso_handler()
    try:
        url = handler.get_authorization_url(tenant_id, org_id)
        return {"authorization_url": url}
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        logger.exception("sso_authorize_error tenant=%s", tenant_id)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.get("/sso/callback", summary="SSO 콜백 처리 → JWT 발급")
async def sso_callback(
    code: str = Query(...),
    state: str = Query(..., description="tenant_id"),
) -> dict:
    """SSO 인증 코드를 사용자 정보로 교환하고 InfraRed JWT를 발급합니다."""
    handler = get_sso_handler()
    try:
        user_info = await handler.handle_callback(code, state)
    except Exception as exc:
        logger.error("sso_callback_failed state=%s error=%s", state, exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="sso_callback_failed",
        )

    # SSO 인증 성공 → InfraRed JWT 발급
    token = create_token(
        subject=user_info.get("email", "sso-user"),
        tenant_id=user_info.get("tenant_id", state),
        role="analyst",  # SSO 기본 역할; 실제 역할은 WorkOS Directory로 결정
        ttl_seconds=3600 * 8,
    )

    return {
        "status": "authenticated",
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "email": user_info.get("email"),
            "name": user_info.get("name"),
            "sso_provider": user_info.get("sso_provider"),
            "tenant_id": user_info.get("tenant_id"),
        },
    }


@router.get("/sso/ldap/status", summary="LDAP 동기화 상태 조회")
async def ldap_sync_status(
    claims: dict = Depends(require_any_role("owner", "security_manager")),
) -> dict:
    """LDAP 디렉터리 동기화 상태 반환."""
    handler = get_sso_handler()
    return handler.get_ldap_sync_status()
