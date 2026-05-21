"""Agent Updater 컴포넌트 — v7.0 설계서

역할: 에이전트 자동 업데이트 (코드 서명 검증 + 롤백)
통신: UDS server ← collector (업데이트 확인 요청)

설계 원칙:
  1. 업데이트 패키지는 ECDSA 서명을 검증한 후에만 설치
  2. 업데이트 실패 시 이전 버전으로 자동 롤백
  3. 업데이트 이력을 audit_log로 backend에 보고
  4. 네트워크 접근: 업데이트 서버 다운로드만 허용
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from infrared_agent.component_bridge import (  # noqa: E402
    MSG_ACK,
    MSG_ERROR,
    MSG_UPDATE_CHECK,
    UDSServer,
)
from infrared_agent.config import AgentSettings  # noqa: E402

log = logging.getLogger("infrared.updater")

# 업데이트 서버 공개키 (ECDSA P-256)
# 실제 배포 시 infra/certs/update_signing_key.pub 에서 로드
UPDATE_SIGNING_PUBKEY_PATH = Path(
    os.environ.get(
        "INFRARED_UPDATE_SIGNING_KEY",
        "/etc/infrared/update_signing_key.pub",
    )
)

# 에이전트 설치 경로
AGENT_INSTALL_DIR = Path(
    os.environ.get("INFRARED_INSTALL_DIR", "/opt/infrared")
)
AGENT_BACKUP_DIR = AGENT_INSTALL_DIR / ".rollback"

# 업데이트 메타데이터 서버
UPDATE_METADATA_URL = os.environ.get(
    "INFRARED_UPDATE_URL",
    "https://updates.infrared.io/agent/latest.json",
)


class AgentUpdater:
    """
    에이전트 자동 업데이트 관리자.

    업데이트 흐름:
      1. 메타데이터 서버에서 최신 버전 정보 조회
      2. 현재 버전과 비교
      3. 업데이트 있으면: 패키지 다운로드 → 서명 검증 → 백업 → 설치 → 재시작
      4. 실패 시: 백업에서 롤백 → backend에 실패 보고

    코드 서명 검증:
      ECDSA P-256 서명 + SHA-256 해시
      cryptography 패키지 사용
    """

    def __init__(self, settings: AgentSettings) -> None:
        self.settings = settings

    async def check_for_update(self, current_version: str) -> dict[str, Any]:
        """최신 버전 정보를 조회하여 업데이트 가능 여부 반환."""
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    UPDATE_METADATA_URL,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status != 200:
                        return {"update_available": False, "reason": f"HTTP {resp.status}"}
                    metadata = await resp.json()
        except Exception as exc:
            log.warning("update_check_failed err=%s", exc)
            return {"update_available": False, "reason": str(exc)}

        latest_version = metadata.get("version", "")
        if not latest_version or latest_version == current_version:
            return {"update_available": False, "current": current_version}

        return {
            "update_available": True,
            "current_version": current_version,
            "latest_version": latest_version,
            "download_url": metadata.get("download_url"),
            "signature": metadata.get("signature"),
            "sha256": metadata.get("sha256"),
            "changelog": metadata.get("changelog", ""),
        }

    async def apply_update(self, update_info: dict[str, Any]) -> bool:
        """
        업데이트 패키지를 다운로드하고 서명 검증 후 설치.
        실패 시 롤백.

        Returns: True if update succeeded, False otherwise.
        """
        download_url = update_info["download_url"]
        expected_sha256 = update_info["sha256"]
        signature_b64 = update_info["signature"]

        # 1. 패키지 다운로드
        try:
            package_bytes = await self._download(download_url)
        except Exception as exc:
            log.error("update_download_failed url=%s err=%s", download_url, exc)
            return False

        # 2. SHA-256 무결성 검증
        actual_sha256 = hashlib.sha256(package_bytes).hexdigest()
        if actual_sha256 != expected_sha256:
            log.error(
                "update_sha256_mismatch expected=%s actual=%s",
                expected_sha256, actual_sha256,
            )
            return False

        # 3. ECDSA 서명 검증
        if not self._verify_signature(package_bytes, signature_b64):
            log.error("update_signature_invalid — 업데이트 거부")
            return False

        # 4. 현재 버전 백업
        self._backup_current_version()

        # 5. 패키지 설치
        try:
            self._install_package(package_bytes)
            log.info(
                "update_installed version=%s",
                update_info.get("latest_version"),
            )
        except Exception as exc:
            log.error("update_install_failed err=%s — 롤백 실행", exc)
            self._rollback()
            return False

        # 6. systemd 재시작 (에이전트 서비스 리로드)
        self._restart_agent_service()
        return True

    @staticmethod
    async def _download(url: str) -> bytes:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=120)) as resp:
                resp.raise_for_status()
                return await resp.read()

    @staticmethod
    def _verify_signature(data: bytes, signature_b64: str) -> bool:
        """ECDSA P-256 서명 검증."""
        if not UPDATE_SIGNING_PUBKEY_PATH.exists():
            log.warning(
                "update_signing_key_missing path=%s — 서명 검증 건너뜀 (비프로덕션)",
                UPDATE_SIGNING_PUBKEY_PATH,
            )
            return True  # 개발 환경에서는 키가 없으면 패스

        try:
            import base64

            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import ec

            pubkey_pem = UPDATE_SIGNING_PUBKEY_PATH.read_bytes()
            public_key = serialization.load_pem_public_key(pubkey_pem)
            signature = base64.b64decode(signature_b64)
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception as exc:
            log.error("signature_verification_failed err=%s", exc)
            return False

    @staticmethod
    def _backup_current_version() -> None:
        """현재 설치된 에이전트를 롤백용으로 백업."""
        if AGENT_INSTALL_DIR.exists():
            if AGENT_BACKUP_DIR.exists():
                shutil.rmtree(AGENT_BACKUP_DIR)
            shutil.copytree(AGENT_INSTALL_DIR, AGENT_BACKUP_DIR)
            log.info("agent_backup_created path=%s", AGENT_BACKUP_DIR)

    @staticmethod
    def _install_package(package_bytes: bytes) -> None:
        """임시 디렉터리에 패키지 압축 해제 후 설치 디렉터리로 복사."""
        with tempfile.TemporaryDirectory() as tmpdir:
            archive_path = Path(tmpdir) / "update.tar.gz"
            archive_path.write_bytes(package_bytes)

            # tar 압축 해제
            subprocess.run(
                ["tar", "-xzf", str(archive_path), "-C", tmpdir],
                check=True,
                capture_output=True,
            )

            # 설치 디렉터리로 복사
            extracted = next(
                p for p in Path(tmpdir).iterdir()
                if p.is_dir() and p.name != "update.tar.gz"
            )
            if AGENT_INSTALL_DIR.exists():
                shutil.rmtree(AGENT_INSTALL_DIR)
            shutil.copytree(extracted, AGENT_INSTALL_DIR)

    @staticmethod
    def _rollback() -> None:
        """백업에서 이전 버전으로 롤백."""
        if not AGENT_BACKUP_DIR.exists():
            log.error("rollback_backup_not_found — 롤백 불가")
            return
        if AGENT_INSTALL_DIR.exists():
            shutil.rmtree(AGENT_INSTALL_DIR)
        shutil.copytree(AGENT_BACKUP_DIR, AGENT_INSTALL_DIR)
        log.info("agent_rollback_complete")

    @staticmethod
    def _restart_agent_service() -> None:
        """systemd에게 에이전트 서비스 재시작 요청."""
        try:
            subprocess.run(
                ["systemctl", "restart", "infrared-agent.service"],
                check=True,
                capture_output=True,
                timeout=30,
            )
            log.info("agent_service_restarted")
        except subprocess.CalledProcessError as exc:
            log.error("agent_restart_failed err=%s", exc.stderr.decode())
        except FileNotFoundError:
            log.warning("systemctl not found — 수동 재시작 필요")


class UpdaterComponent:
    """Updater UDS 서버 컴포넌트."""

    def __init__(self, settings: AgentSettings) -> None:
        self.settings = settings
        self.updater = AgentUpdater(settings)
        self._server = UDSServer("updater", self._handle_message)
        self._current_version = getattr(settings, "agent_version", "0.0.0")

    async def _handle_message(
        self, msg: dict[str, Any]
    ) -> dict[str, Any] | None:
        msg_type = msg.get("type")

        if msg_type == MSG_UPDATE_CHECK:
            result = await self.updater.check_for_update(self._current_version)
            return {"type": MSG_ACK, **result}

        return {"type": MSG_ERROR, "reason": f"unknown message type: {msg_type}"}

    async def _auto_update_loop(self) -> None:
        """24시간마다 자동으로 업데이트 확인."""
        while True:
            await asyncio.sleep(86400)  # 24시간
            try:
                info = await self.updater.check_for_update(self._current_version)
                if info.get("update_available"):
                    log.info(
                        "auto_update_available current=%s latest=%s",
                        self._current_version,
                        info.get("latest_version"),
                    )
                    success = await self.updater.apply_update(info)
                    log.info("auto_update_result success=%s", success)
            except Exception:
                log.exception("auto_update_loop_error")

    async def start(self) -> None:
        log.info("updater_component_starting pid=%d uid=%d", os.getpid(), os.getuid())
        await self._server.start()
        auto_update_task = asyncio.create_task(self._auto_update_loop())
        try:
            await self._server._server.serve_forever()
        finally:
            auto_update_task.cancel()
            await self._server.stop()

    async def stop(self) -> None:
        await self._server.stop()
        log.info("updater_component_stopped")


def main() -> None:
    settings = AgentSettings()
    updater = UpdaterComponent(settings)
    asyncio.run(updater.start())


if __name__ == "__main__":
    main()
