"""HTTP client for ingestion and heartbeat.

v7.0: mTLS (상호 TLS 인증) 지원.
  - settings.mtls_enabled=True 이면 클라이언트 인증서 + CA 검증을 사용
  - 미설정 시 기존 Bearer 토큰 방식으로 폴백
"""
from __future__ import annotations

import logging
import ssl
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from infrared_agent import __version__
from infrared_agent.config import AgentSettings

log = logging.getLogger("infrared.client")


def _build_ssl_context(settings: AgentSettings) -> ssl.SSLContext | bool:
    """mTLS용 SSLContext 생성.

    Returns:
      - SSLContext: mTLS 활성화 + 설정 완료
      - True: mTLS 비활성화 (기본 TLS 검증)
      - False: TLS 검증 비활성화 (mtls_verify_server=False인 비프로덕션)
    """
    if not settings.mtls_enabled:
        return True  # 기본 TLS 검증

    cert_path = Path(settings.mtls_cert_path)
    key_path = Path(settings.mtls_key_path)
    ca_path = Path(settings.mtls_ca_path)

    if not cert_path.exists() or not key_path.exists():
        log.warning(
            "mtls_cert_missing cert=%s key=%s — mTLS 비활성화 (Bearer 토큰 폴백)",
            cert_path, key_path,
        )
        return True

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    # 클라이언트 인증서 로드
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))

    # CA 인증서로 서버 검증
    if settings.mtls_verify_server and ca_path.exists():
        ctx.load_verify_locations(cafile=str(ca_path))
        ctx.verify_mode = ssl.CERT_REQUIRED
        log.info("mtls_enabled cert=%s ca=%s verify_server=True", cert_path, ca_path)
    elif not settings.mtls_verify_server:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        log.warning("mtls_server_verify_disabled — 비프로덕션 환경에서만 사용하세요")
    else:
        # CA 파일 없으면 시스템 CA 번들 사용
        ctx.load_default_certs()
        log.info("mtls_enabled cert=%s ca=system_default", cert_path)

    return ctx


class AgentClient:
    def __init__(self, settings: AgentSettings) -> None:
        self.settings = settings
        ssl_context = _build_ssl_context(settings)
        self._client = httpx.AsyncClient(timeout=10, verify=ssl_context)
        self._mtls_active = (
            settings.mtls_enabled
            and Path(settings.mtls_cert_path).exists()
            and Path(settings.mtls_key_path).exists()
        )
        if self._mtls_active:
            log.info("agent_client_mtls_active")

    @property
    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.settings.agent_token}"}

    async def close(self) -> None:
        await self._client.aclose()

    async def send_event(self, envelope: dict[str, Any]) -> None:
        response = await self._client.post(
            self.settings.backend_url,
            headers=self._headers,
            json=envelope,
        )
        response.raise_for_status()

    async def send_heartbeat(
        self,
        last_event_id: str | None = None,
        status: str = "online",
        deactivation_reason: str | None = None,
    ) -> None:
        """Heartbeat 전송.

        설계서 v2.0 Phase 3-D:
        - status="online"      : 정상 Heartbeat (기본값)
        - status="deactivated" : StartLimitBurst(5회) 초과 종료 직전 최종 보고
        """
        payload: dict = {
            "tenant_id": self.settings.tenant_id,
            "agent_id": self.settings.agent_id,
            "asset_id": self.settings.asset_id,
            "sent_at": datetime.now(timezone.utc).isoformat(),
            "agent_version": __version__,
            "pending_buffered_events": 0,
            "last_event_id": last_event_id,
            "status": status,
        }
        if deactivation_reason:
            payload["deactivation_reason"] = deactivation_reason
        response = await self._client.post(
            self.settings.heartbeat_url,
            headers=self._headers,
            json=payload,
        )
        response.raise_for_status()

    async def poll_commands(self) -> list[dict[str, Any]]:
        """backend에서 pending 명령 목록 폴링."""
        base = self.settings.backend_url.rstrip("/").rsplit("/", 1)[0]
        url = f"{base}/commands/pending"
        try:
            response = await self._client.get(
                url,
                headers=self._headers,
                params={
                    "agent_id": self.settings.agent_id,
                    "tenant_id": self.settings.tenant_id,
                },
            )
            response.raise_for_status()
            data = response.json()
            return data if isinstance(data, list) else data.get("commands", [])
        except Exception:
            log.exception("poll_commands_failed url=%s", url)
            return []

    async def report_command_result(
        self,
        command_id: str,
        result: dict[str, Any],
    ) -> None:
        """backend에 명령 실행 결과 보고."""
        if not command_id:
            return
        base = self.settings.backend_url.rstrip("/").rsplit("/", 1)[0]
        url = f"{base}/commands/{command_id}/complete"
        try:
            response = await self._client.post(
                url,
                headers=self._headers,
                json={"result": result},
            )
            response.raise_for_status()
        except Exception:
            log.exception("report_command_result_failed cmd_id=%s", command_id)
