"""S3 로그 업로더.

수집된 auth.log 라인을 gzip 압축 후 S3에 주기적으로 업로드합니다.

  - s3_enabled=False(기본) 이면 완전히 비활성화됩니다.
  - AWS 자격증명은 환경변수(AWS_ACCESS_KEY_ID 등) 또는 IAM 역할로 자동 감지됩니다.
  - 업로드 경로: s3://{bucket}/{prefix}/{YYYY}/{MM}/{DD}/{HH}/{tenant_id}_{agent_id}_{seq:05d}.log.gz
"""
from __future__ import annotations

import asyncio
import gzip
import io
import logging
import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from infrared_agent.config import AgentSettings

log = logging.getLogger("infrared_agent.s3")


class S3LogUploader:
    """수집된 로그 라인을 버퍼링했다가 S3에 일괄 업로드."""

    def __init__(self, settings: "AgentSettings") -> None:
        self._settings = settings
        self._buffer: list[str] = []
        self._seq: int = 0
        self._last_upload: float = 0.0
        self._client = None  # boto3 client (lazy init)

    def _get_client(self):
        if self._client is not None:
            return self._client
        import boto3

        s = self._settings
        kwargs: dict = {"region_name": s.s3_region}
        if s.aws_access_key_id and s.aws_secret_access_key:
            kwargs["aws_access_key_id"] = s.aws_access_key_id
            kwargs["aws_secret_access_key"] = s.aws_secret_access_key
        elif s.aws_profile:
            import boto3.session
            session = boto3.session.Session(profile_name=s.aws_profile)
            self._client = session.client("s3", region_name=s.s3_region)
            return self._client

        self._client = boto3.client("s3", **kwargs)
        return self._client

    def push(self, raw_line: str) -> None:
        """로그 한 줄을 버퍼에 추가."""
        self._buffer.append(raw_line)

    def _should_upload(self) -> bool:
        elapsed = time.monotonic() - self._last_upload
        return (
            elapsed >= self._settings.s3_upload_interval_sec
            or len(self._buffer) >= self._settings.s3_max_lines_per_file
        )

    def _build_s3_key(self, now: datetime) -> str:
        s = self._settings
        self._seq += 1
        ts = now.strftime("%Y/%m/%d/%H")
        return (
            f"{s.s3_prefix.rstrip('/')}/"
            f"{ts}/"
            f"{s.tenant_id}_{s.agent_id}_{self._seq:05d}.log.gz"
        )

    def _compress(self, lines: list[str]) -> bytes:
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
            gz.write("\n".join(lines).encode("utf-8"))
        return buf.getvalue()

    async def flush_if_ready(self) -> bool:
        """버퍼가 충분히 쌓였거나 인터벌이 지났으면 S3에 업로드."""
        if not self._settings.s3_enabled or not self._buffer:
            return False
        if not self._should_upload():
            return False

        lines = self._buffer[:]
        self._buffer.clear()
        self._last_upload = time.monotonic()

        now = datetime.now(timezone.utc)
        key = self._build_s3_key(now)
        data = self._compress(lines)

        try:
            client = self._get_client()
            # run_in_executor로 블로킹 boto3 호출을 비동기 처리
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                lambda: client.put_object(
                    Bucket=self._settings.s3_bucket,
                    Key=key,
                    Body=data,
                    ContentEncoding="gzip",
                    ContentType="text/plain",
                    Metadata={
                        "tenant_id": self._settings.tenant_id,
                        "agent_id": self._settings.agent_id,
                        "lines": str(len(lines)),
                        "uploaded_at": now.isoformat(),
                    },
                ),
            )
            log.info(
                "s3_upload_ok bucket=%s key=%s lines=%d bytes=%d",
                self._settings.s3_bucket,
                key,
                len(lines),
                len(data),
            )
            return True
        except Exception:
            # 업로드 실패 시 버퍼를 복원해 다음 주기에 재시도
            self._buffer = lines + self._buffer
            log.exception("s3_upload_failed bucket=%s key=%s", self._settings.s3_bucket, key)
            return False
