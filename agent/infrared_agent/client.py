"""HTTP client for ingestion and heartbeat.

Failure policy
--------------
* Network errors (ConnectError, TimeoutException, …) → buffer event in SQLite,
  return False so the caller does NOT advance the offset.
* 4xx client errors (bad JWT, schema error) → raise immediately; the event
  is not worth retrying as-is.
* 5xx server errors → buffer for retry, same as network errors.

Buffered events are flushed in FIFO order via ``flush_buffer`` before each
new event is sent, so ordering is preserved across restarts.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

import httpx

from infrared_agent import __version__
from infrared_agent.buffer_store import BufferStore
from infrared_agent.config import AgentSettings


log = logging.getLogger("infrared_agent.client")

# How many buffered events to attempt per flush cycle
_FLUSH_BATCH = 50


class AgentClient:
    def __init__(self, settings: AgentSettings, buffer: BufferStore) -> None:
        self.settings = settings
        self._buffer = buffer
        self._client = httpx.AsyncClient(timeout=10)

    @property
    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.settings.agent_token}"}

    async def close(self) -> None:
        await self._client.aclose()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _post_event(self, envelope: dict[str, Any]) -> None:
        """Raw POST — raises on any error."""
        response = await self._client.post(
            self.settings.backend_url,
            headers=self._headers,
            json=envelope,
        )
        response.raise_for_status()

    def _is_retriable(self, exc: Exception) -> bool:
        """Return True for transient errors that warrant buffering."""
        if isinstance(exc, httpx.HTTPStatusError):
            # 5xx: server-side; 429: rate-limited → retry later
            return exc.response.status_code >= 500 or exc.response.status_code == 429
        # Network / timeout errors
        return isinstance(exc, (httpx.TransportError, httpx.TimeoutException))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def flush_buffer(self) -> int:
        """Attempt to send buffered events in FIFO order.

        Returns the number of events successfully flushed.
        Stops at the first failure to preserve ordering.
        """
        flushed = 0
        for buffered in self._buffer.pending(limit=_FLUSH_BATCH):
            try:
                await self._post_event(buffered.payload)
                self._buffer.ack(buffered.row_id)
                flushed += 1
                log.info(
                    "flushed buffered event event_id=%s row_id=%d",
                    buffered.payload.get("event_id"),
                    buffered.row_id,
                )
            except Exception as exc:
                if self._is_retriable(exc):
                    log.debug("buffer flush blocked, will retry later: %s", exc)
                    break
                # Non-retriable (4xx): drop the event so it doesn't block the queue
                log.warning(
                    "dropping non-retriable buffered event event_id=%s: %s",
                    buffered.payload.get("event_id"),
                    exc,
                )
                self._buffer.ack(buffered.row_id)
        return flushed

    async def send_event(self, envelope: dict[str, Any]) -> bool:
        """Send a single event.

        Returns True if the backend accepted the event, False if it was
        queued in the local SQLite buffer (network down / 5xx).

        The caller should only advance the log offset when True is returned
        (the event was successfully delivered or is safely buffered).
        Actually: we buffer on failure so offset IS advanced—the event won't
        be lost.  We return False so the caller can log the situation.
        """
        try:
            await self._post_event(envelope)
            return True
        except Exception as exc:
            if self._is_retriable(exc):
                self._buffer.push(envelope)
                log.warning(
                    "network error, buffered event event_id=%s (buffer size=%d): %s",
                    envelope.get("event_id"),
                    self._buffer.size(),
                    exc,
                )
                return False
            # 4xx: surface immediately, don't buffer
            raise

    async def send_heartbeat(self, last_event_id: str | None = None) -> None:
        response = await self._client.post(
            self.settings.heartbeat_url,
            headers=self._headers,
            json={
                "tenant_id": self.settings.tenant_id,
                "agent_id": self.settings.agent_id,
                "asset_id": self.settings.asset_id,
                "sent_at": datetime.now(timezone.utc).isoformat(),
                "agent_version": __version__,
                "pending_buffered_events": self._buffer.size(),
                "last_event_id": last_event_id,
            },
        )
        response.raise_for_status()
