"""Agent 컴포넌트 간 UDS(Unix Domain Socket) 통신 브릿지 — v7.0 설계서

설계 배경:
  v7.0 보안 고도화 설계서 §4: Agent 권한 분리 5컴포넌트 구조
  각 컴포넌트는 최소 권한으로 실행되며, UDS를 통해 메시지를 교환한다.

  collector  (비특권): 로그 수집 → backend 전송
  sensor     (루트):   /proc 스캔, FIM, eBPF 이벤트 수집
  responder  (루트):   iptables/SSH 명령 실행
  forensic   (루트):   포렌식 수집 + S3 업로드
  updater    (루트):   에이전트 자동 업데이트

통신 방식:
  JSON 줄바꿈 구분 메시지 (newline-delimited JSON)
  소켓 경로: /run/infrared/<component>.sock
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Any, AsyncIterator, Awaitable, Callable

log = logging.getLogger("infrared.bridge")

SOCKET_DIR = Path(os.environ.get("INFRARED_SOCKET_DIR", "/run/infrared"))

COMPONENT_SOCKETS: dict[str, Path] = {
    "collector": SOCKET_DIR / "collector.sock",
    "sensor":    SOCKET_DIR / "sensor.sock",
    "responder": SOCKET_DIR / "responder.sock",
    "forensic":  SOCKET_DIR / "forensic.sock",
    "updater":   SOCKET_DIR / "updater.sock",
}

# 메시지 타입 상수
MSG_EVENT        = "event"          # sensor → collector (수집된 이벤트)
MSG_COMMAND      = "command"        # collector → responder (명령 전달)
MSG_FORENSIC_REQ = "forensic_req"   # collector → forensic (포렌식 요청)
MSG_UPDATE_CHECK = "update_check"   # collector → updater (업데이트 확인)
MSG_ACK          = "ack"            # 범용 응답
MSG_ERROR        = "error"          # 오류 응답


# ---------------------------------------------------------------------------
# 저수준 UDS 클라이언트
# ---------------------------------------------------------------------------

class UDSClient:
    """단일 컴포넌트 소켓에 연결하는 클라이언트."""

    def __init__(self, component: str) -> None:
        self.component = component
        self.sock_path = COMPONENT_SOCKETS[component]
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None

    async def connect(self, retries: int = 5, delay: float = 0.5) -> None:
        for attempt in range(retries):
            try:
                self._reader, self._writer = await asyncio.open_unix_connection(
                    str(self.sock_path)
                )
                log.debug("uds_connected component=%s", self.component)
                return
            except (FileNotFoundError, ConnectionRefusedError) as exc:
                if attempt == retries - 1:
                    raise ConnectionError(
                        f"{self.component} 소켓 연결 실패: {self.sock_path}"
                    ) from exc
                await asyncio.sleep(delay * (2 ** attempt))

    async def send(self, msg: dict[str, Any]) -> None:
        if self._writer is None:
            raise RuntimeError("연결되지 않은 상태에서 send() 호출")
        data = json.dumps(msg, ensure_ascii=False) + "\n"
        self._writer.write(data.encode())
        await self._writer.drain()

    async def recv(self) -> dict[str, Any]:
        if self._reader is None:
            raise RuntimeError("연결되지 않은 상태에서 recv() 호출")
        line = await self._reader.readline()
        if not line:
            raise EOFError("소켓 연결이 닫혔습니다")
        return json.loads(line.decode())

    async def request(self, msg: dict[str, Any]) -> dict[str, Any]:
        """단일 요청 → 단일 응답."""
        await self.send(msg)
        return await self.recv()

    async def close(self) -> None:
        if self._writer:
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except Exception:
                pass
            self._writer = None
            self._reader = None


# ---------------------------------------------------------------------------
# 저수준 UDS 서버
# ---------------------------------------------------------------------------

class UDSServer:
    """단일 컴포넌트용 UDS 서버."""

    def __init__(
        self,
        component: str,
        handler: Callable[[dict[str, Any]], Awaitable[dict[str, Any] | None]],
    ) -> None:
        self.component = component
        self.sock_path = COMPONENT_SOCKETS[component]
        self.handler = handler
        self._server: asyncio.Server | None = None

    async def start(self) -> None:
        SOCKET_DIR.mkdir(parents=True, exist_ok=True)
        # 기존 소켓 파일 제거
        if self.sock_path.exists():
            self.sock_path.unlink()

        self._server = await asyncio.start_unix_server(
            self._handle_client,
            path=str(self.sock_path),
        )
        # 소켓 권한: 소유자만 읽기/쓰기 (600)
        os.chmod(self.sock_path, 0o600)
        log.info("uds_server_started component=%s path=%s", self.component, self.sock_path)

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        peer = writer.get_extra_info("peername", "<unknown>")
        try:
            async for line in self._read_lines(reader):
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError as exc:
                    log.warning(
                        "uds_invalid_json component=%s peer=%s err=%s",
                        self.component, peer, exc,
                    )
                    continue

                response = await self.handler(msg)
                if response is not None:
                    data = json.dumps(response, ensure_ascii=False) + "\n"
                    writer.write(data.encode())
                    await writer.drain()

        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("uds_handler_error component=%s peer=%s", self.component, peer)
        finally:
            writer.close()

    @staticmethod
    async def _read_lines(reader: asyncio.StreamReader) -> AsyncIterator[bytes]:
        while True:
            line = await reader.readline()
            if not line:
                return
            yield line

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        if self.sock_path.exists():
            self.sock_path.unlink()


# ---------------------------------------------------------------------------
# 고수준 컴포넌트 브릿지 (sensor → collector 이벤트 전달)
# ---------------------------------------------------------------------------

class ComponentBridge:
    """
    collector 컴포넌트에서 사용하는 고수준 브릿지.
    sensor/responder/forensic/updater와의 통신을 추상화한다.
    """

    def __init__(self) -> None:
        self._clients: dict[str, UDSClient] = {}

    async def connect_all(self) -> None:
        """사용 가능한 모든 컴포넌트에 연결 (연결 실패 시 경고만 출력)."""
        for name in ("sensor", "responder", "forensic", "updater"):
            client = UDSClient(name)
            try:
                await client.connect(retries=3)
                self._clients[name] = client
            except ConnectionError:
                log.warning(
                    "component_unavailable name=%s path=%s — 해당 기능 비활성화",
                    name,
                    COMPONENT_SOCKETS[name],
                )

    async def send_command_to_responder(self, command: dict[str, Any]) -> dict[str, Any]:
        """collector → responder: 명령 전달 (block_ip, inject_temp_ssh_key 등)."""
        client = self._clients.get("responder")
        if client is None:
            return {"type": MSG_ERROR, "reason": "responder not connected"}
        return await client.request({
            "type": MSG_COMMAND,
            "payload": command,
        })

    async def request_forensic_collection(
        self,
        incident_id: str,
        target_paths: list[str],
    ) -> dict[str, Any]:
        """collector → forensic: 포렌식 수집 요청."""
        client = self._clients.get("forensic")
        if client is None:
            return {"type": MSG_ERROR, "reason": "forensic not connected"}
        return await client.request({
            "type": MSG_FORENSIC_REQ,
            "incident_id": incident_id,
            "target_paths": target_paths,
        })

    async def check_for_update(self, current_version: str) -> dict[str, Any]:
        """collector → updater: 업데이트 가능 여부 확인."""
        client = self._clients.get("updater")
        if client is None:
            return {"type": MSG_ACK, "update_available": False}
        return await client.request({
            "type": MSG_UPDATE_CHECK,
            "current_version": current_version,
        })

    async def close_all(self) -> None:
        for client in self._clients.values():
            await client.close()
        self._clients.clear()
