"""에이전트 측 포렌식 수집기 — commander.py의 collect_forensics 액션에서 호출."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import subprocess
from datetime import datetime, timezone
from typing import Optional

import httpx

from infrared_agent.config import AgentSettings


import logging
log = logging.getLogger("infrared_agent.forensic_collector")


_COLLECTION_COMMANDS: list[tuple[str, list[str]]] = [
    ("ps_aux",       ["ps", "aux"]),
    ("netstat_an",   ["netstat", "-an"]),
    ("last_50",      ["last", "-n50"]),
    ("who",          ["who"]),
]

_COLLECTION_FILES: list[tuple[str, str]] = [
    ("proc_net_tcp", "/proc/net/tcp"),
]


class ForensicCollector:
    """에이전트 호스트에서 포렌식 데이터를 수집하고 백엔드로 전송."""

    def __init__(self, settings: AgentSettings) -> None:
        self.settings = settings

    async def collect(
        self,
        tenant_id: str,
        incident_id: str,
        asset_id: Optional[str] = None,
    ) -> dict:
        """포렌식 수집 후 백엔드 /forensic/collect 엔드포인트로 업로드."""
        collected_at = datetime.now(timezone.utc).isoformat()
        items = []

        for name, cmd in _COLLECTION_COMMANDS:
            items.append(self._run_command(name, cmd))

        for name, path in _COLLECTION_FILES:
            items.append(self._read_file(name, path))

        manifest_sig = self._compute_manifest_sig(items)

        bundle = {
            "incident_id": incident_id,
            "tenant_id": tenant_id,
            "asset_id": asset_id or self.settings.asset_id,
            "collected_at": collected_at,
            "items": items,
            "manifest_sig": manifest_sig,
        }

        # 백엔드에 업로드
        await self._upload_to_backend(bundle)

        log.info(
            "forensics_collected_agent incident=%s items=%d",
            incident_id, len(items),
        )
        return bundle

    def _run_command(self, name: str, cmd: list[str]) -> dict:
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30, check=False,
            )
            raw = (result.stdout + result.stderr).encode("utf-8", errors="replace")
        except subprocess.TimeoutExpired:
            raw = f"[timeout] {' '.join(cmd)}".encode()
        except FileNotFoundError:
            raw = f"[not_found] {cmd[0]}".encode()
        except Exception as exc:
            raw = f"[error] {exc}".encode()

        content_b64 = base64.b64encode(raw).decode()
        sha256 = hashlib.sha256(raw).hexdigest()
        return {"name": name, "content_b64": content_b64, "sha256": sha256}

    def _read_file(self, name: str, path: str) -> dict:
        try:
            with open(path, "rb") as f:
                raw = f.read()
        except FileNotFoundError:
            raw = f"[not_found] {path}".encode()
        except PermissionError:
            raw = f"[permission_denied] {path}".encode()
        except Exception as exc:
            raw = f"[error] {exc}".encode()

        content_b64 = base64.b64encode(raw).decode()
        sha256 = hashlib.sha256(raw).hexdigest()
        return {"name": name, "content_b64": content_b64, "sha256": sha256}

    def _compute_manifest_sig(self, items: list[dict]) -> str:
        key = b"CHANGE_ME_FORENSIC_HMAC"
        combined = "".join(item["sha256"] for item in items).encode()
        return hmac.new(key, combined, hashlib.sha256).hexdigest()

    async def _upload_to_backend(self, bundle: dict) -> None:
        """수집된 포렌식 데이터를 백엔드 API에 전송."""
        backend_base = self.settings.backend_url.rstrip("/").removesuffix("/ingest")
        url = f"{backend_base}/forensic/collect"
        try:
            async with httpx.AsyncClient(timeout=30) as http:
                resp = await http.post(
                    url,
                    json={
                        "incident_id": bundle["incident_id"],
                        "asset_id": bundle.get("asset_id"),
                    },
                    headers={"Authorization": f"Bearer {self.settings.agent_token}"},
                )
                resp.raise_for_status()
                log.info("forensics_uploaded incident=%s status=%s", bundle["incident_id"], resp.status_code)
        except Exception as exc:
            log.warning("forensics_upload_failed: %s", exc)
