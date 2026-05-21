"""
LDAP / Active Directory 동기화.
기업 AD 그룹 → InfraRed RBAC 역할 자동 매핑.
v4.0 설계서 §9.3 참조.
"""
from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger(__name__)

try:
    from ldap3 import ALL, NTLM, SIMPLE, Connection, Server
    LDAP_AVAILABLE = True
except ImportError:
    LDAP_AVAILABLE = False
    logger.warning("ldap3 not available. LDAP sync disabled.")

from app.config import get_settings  # noqa: E402

GROUP_TO_ROLE_MAPPING = {
    "CN=InfraRed-Admins,OU=Groups": "owner",
    "CN=InfraRed-SecTeam,OU=Groups": "security_manager",
    "CN=InfraRed-Analysts,OU=Groups": "analyst",
    "CN=InfraRed-Viewers,OU=Groups": "viewer",
}


class LDAPSyncWorker:
    """
    LDAP/AD 그룹 → InfraRed RBAC 역할 자동 동기화.
    Lambda EventBridge 1시간 주기 실행.
    """

    def __init__(
        self,
        ldap_url: str,
        bind_dn: str,
        bind_password: str,
        base_dn: str,
        role_mapping: dict[str, str] = None,
        use_ntlm: bool = False,
    ):
        self.ldap_url = ldap_url
        self.bind_dn = bind_dn
        self.bind_password = bind_password
        self.base_dn = base_dn
        self.role_mapping = role_mapping or GROUP_TO_ROLE_MAPPING
        self.use_ntlm = use_ntlm

    def _connect(self) -> Optional["Connection"]:
        if not LDAP_AVAILABLE:
            logger.error("ldap3 not installed. Run: pip install ldap3")
            return None
        try:
            server = Server(self.ldap_url, get_info=ALL)
            auth = NTLM if self.use_ntlm else SIMPLE
            conn = Connection(
                server,
                user=self.bind_dn,
                password=self.bind_password,
                authentication=auth,
                auto_bind=True,
            )
            return conn
        except Exception as e:
            logger.error(f"LDAP connection failed: {e}")
            return None

    def get_group_members(self, group_dn: str) -> list[str]:
        """그룹 멤버 DN 목록 조회"""
        conn = self._connect()
        if not conn:
            return []

        try:
            conn.search(
                search_base=group_dn,
                search_filter="(objectClass=group)",
                attributes=["member"],
            )
            if not conn.entries:
                return []
            members = []
            for entry in conn.entries:
                for member_dn in (entry.member.values if hasattr(entry, "member") else []):
                    members.append(str(member_dn))
            return members
        except Exception as e:
            logger.error(f"Group member query failed for {group_dn}: {e}")
            return []
        finally:
            try:
                conn.unbind()
            except Exception:
                pass

    def get_user_email(self, user_dn: str) -> Optional[str]:
        """사용자 DN → 이메일 조회"""
        conn = self._connect()
        if not conn:
            return None
        try:
            conn.search(
                search_base=user_dn,
                search_filter="(objectClass=person)",
                attributes=["mail", "userPrincipalName"],
            )
            if conn.entries:
                entry = conn.entries[0]
                if hasattr(entry, "mail") and entry.mail.value:
                    return str(entry.mail.value)
                if hasattr(entry, "userPrincipalName") and entry.userPrincipalName.value:
                    return str(entry.userPrincipalName.value)
        except Exception as e:
            logger.error(f"User email query failed for {user_dn}: {e}")
        finally:
            try:
                conn.unbind()
            except Exception:
                pass
        return None

    def sync(self, update_role_fn=None) -> dict:
        """
        AD 그룹 → RBAC 역할 동기화.
        update_role_fn: (email, role) → None
        """
        results = {"synced": 0, "errors": 0, "roles": {}}

        for group_dn, role in self.role_mapping.items():
            members = self.get_group_members(group_dn)
            for member_dn in members:
                email = self.get_user_email(member_dn)
                if email:
                    if update_role_fn:
                        try:
                            update_role_fn(email, role)
                            results["synced"] += 1
                            results["roles"][email] = role
                        except Exception as e:
                            logger.error(f"Role update failed for {email}: {e}")
                            results["errors"] += 1
                    else:
                        logger.info(f"Would assign role={role} to {email}")
                        results["synced"] += 1

        return results


# Lambda 진입점
def lambda_handler(event, context):
    # event에서 테넌트별 LDAP 설정 로드
    tenant_configs = event.get("tenants", [])
    results = []

    for config in tenant_configs:
        worker = LDAPSyncWorker(
            ldap_url=config.get("ldap_url", ""),
            bind_dn=config.get("bind_dn", ""),
            bind_password=config.get("bind_password", ""),
            base_dn=config.get("base_dn", ""),
        )
        result = worker.sync()
        results.append({"tenant_id": config.get("tenant_id", ""), **result})

    return {"results": results}


# ─── 상태 조회 래퍼 (SSO 라우터에서 호출) ─────────────────────────────────────

class LdapSyncHandler:
    """LDAP 동기화 상태 조회 래퍼."""

    def get_status(self) -> dict:
        if not LDAP_AVAILABLE:
            return {
                "status": "disabled",
                "detail": "ldap3 not installed",
                "available": False,
            }
        settings = get_settings()
        ldap_url = getattr(settings, "ldap_url", "")
        if not ldap_url:
            return {
                "status": "not_configured",
                "detail": "LDAP_URL not set",
                "available": False,
            }
        return {
            "status": "configured",
            "ldap_url": ldap_url,
            "available": True,
            "role_mapping": GROUP_TO_ROLE_MAPPING,
        }
