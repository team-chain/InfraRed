"""
WorkOS 기반 SSO (SAML 2.0 / OIDC).
v4.0 설계서 §9.1 참조.
WorkOS SDK가 없을 시 직접 OAuth2 플로우 사용.
"""
from __future__ import annotations

import logging
import urllib.parse
from typing import Optional

from app.config import get_settings

logger = logging.getLogger(__name__)

try:
    import workos  # type: ignore
    WORKOS_AVAILABLE = True
except ImportError:
    WORKOS_AVAILABLE = False
    logger.warning("WorkOS SDK not available. SSO will use fallback OAuth2.")


class SSOHandler:
    """WorkOS 기반 SSO 핸들러"""

    WORKOS_AUTHORIZE_URL = "https://api.workos.com/sso/authorize"
    WORKOS_TOKEN_URL = "https://api.workos.com/sso/token"

    def __init__(self) -> None:
        self.settings = get_settings()

    # ─── Authorization URL ────────────────────────────────────────────────────

    def get_authorization_url(
        self,
        tenant_id: str,
        org_id: Optional[str] = None,
    ) -> str:
        """SSO 인증 URL 생성."""
        if not self.settings.workos_api_key:
            raise ValueError(
                "WorkOS API key not configured. Set WORKOS_API_KEY env var."
            )

        redirect_uri = (
            f"{self.settings.dashboard_url.rstrip('/')}/auth/sso/callback"
        )

        if WORKOS_AVAILABLE:
            client = workos.WorkOS(api_key=self.settings.workos_api_key)
            return client.user_management.get_authorization_url(
                provider=None,
                redirect_uri=redirect_uri,
                state=tenant_id,
                organization_id=org_id,
            )

        # Fallback: 직접 WorkOS OAuth2 엔드포인트 구성
        params: dict[str, str] = {
            "client_id": getattr(self.settings, "workos_client_id", ""),
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "state": tenant_id,
        }
        if org_id:
            params["organization"] = org_id
        return f"{self.WORKOS_AUTHORIZE_URL}?{urllib.parse.urlencode(params)}"

    # ─── Callback handling ────────────────────────────────────────────────────

    async def handle_callback(self, code: str, state: str) -> dict:
        """SSO 콜백 처리 → 사용자 정보 반환.

        WorkOS SDK 존재 시 SDK로, 없으면 직접 토큰 교환.
        """
        if WORKOS_AVAILABLE:
            client = workos.WorkOS(api_key=self.settings.workos_api_key)
            try:
                profile = client.user_management.get_profile_and_token(code)
                return {
                    "email": getattr(profile, "email", ""),
                    "name": (
                        f"{getattr(profile, 'first_name', '')} "
                        f"{getattr(profile, 'last_name', '')}".strip()
                    ),
                    "sso_provider": getattr(
                        profile, "connection_type", "sso"
                    ),
                    "sso_id": getattr(profile, "id", ""),
                    "tenant_id": state,
                }
            except Exception as exc:
                logger.error("WorkOS SSO callback failed: %s", exc)
                raise RuntimeError(f"SSO callback failed: {exc}") from exc

        # Fallback: 직접 토큰 교환 (WorkOS REST API)
        import httpx  # lazy import

        redirect_uri = (
            f"{self.settings.dashboard_url.rstrip('/')}/auth/sso/callback"
        )
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(
                    self.WORKOS_TOKEN_URL,
                    json={
                        "client_id": getattr(
                            self.settings, "workos_client_id", ""
                        ),
                        "client_secret": self.settings.workos_api_key,
                        "grant_type": "authorization_code",
                        "code": code,
                        "redirect_uri": redirect_uri,
                    },
                )
                resp.raise_for_status()
                data = resp.json()

            profile = data.get("profile", {})
            return {
                "email": profile.get("email", ""),
                "name": (
                    f"{profile.get('first_name', '')} "
                    f"{profile.get('last_name', '')}".strip()
                ),
                "sso_provider": profile.get("connection_type", "sso"),
                "sso_id": profile.get("id", ""),
                "tenant_id": state,
            }
        except Exception as exc:
            logger.error("SSO token exchange failed: %s", exc)
            raise RuntimeError(f"SSO callback failed: {exc}") from exc

    # ─── LDAP sync delegation ─────────────────────────────────────────────────

    def get_ldap_sync_status(self) -> dict:
        """LDAP 디렉터리 동기화 상태 조회."""
        try:
            from app.auth.ldap_sync import LdapSyncHandler  # lazy
            handler = LdapSyncHandler()
            return handler.get_status()
        except Exception as exc:
            logger.warning("LDAP sync status unavailable: %s", exc)
            return {"status": "unavailable", "detail": str(exc)}


# ─── Singleton ────────────────────────────────────────────────────────────────

_sso_handler: Optional[SSOHandler] = None


def get_sso_handler() -> SSOHandler:
    global _sso_handler
    if _sso_handler is None:
        _sso_handler = SSOHandler()
    return _sso_handler
