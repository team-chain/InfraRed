"""InfraRed agent entrypoint."""
from __future__ import annotations

import asyncio
import logging
import os
import time

from infrared_agent.buffer_store import BufferStore
from infrared_agent.client import AgentClient
from infrared_agent.config import AgentSettings
from infrared_agent.offset_store import OffsetStore
from infrared_agent.tailer import AuthLogTailer


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("infrared_agent")


async def run() -> None:
    settings = AgentSettings()
    if not settings.agent_token:
        raise RuntimeError("AGENT_TOKEN is required")

    # Ensure persistent storage directories exist
    for path in (settings.agent_offset_db, settings.agent_buffer_db):
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)

    store = OffsetStore(settings.agent_offset_db)
    buffer = BufferStore(settings.agent_buffer_db)
    tailer = AuthLogTailer(settings, store)
    client = AgentClient(settings, buffer)
    last_heartbeat = 0.0
    last_event_id: str | None = None

    try:
        while True:
            # ── 1. 버퍼에 쌓인 미전송 이벤트 먼저 재전송 ──────────────────
            if buffer.size() > 0:
                flushed = await client.flush_buffer()
                if flushed:
                    log.info("flushed %d buffered event(s)", flushed)

            # ── 2. 새 로그 이벤트 읽어 전송 ────────────────────────────────
            try:
                for envelope, new_offset, inode in tailer.read_new_events():
                    sent = await client.send_event(envelope)
                    # offset은 전송 성공/실패 무관하게 진행
                    # (실패 시 버퍼에 저장되므로 이벤트가 유실되지 않음)
                    store.set(settings.agent_auth_log_path, inode, new_offset)
                    last_event_id = envelope["event_id"]
                    if sent:
                        log.info("sent event_id=%s offset=%s", last_event_id, new_offset)
                    else:
                        log.warning(
                            "buffered event_id=%s offset=%s (network down)",
                            last_event_id,
                            new_offset,
                        )
            except FileNotFoundError:
                log.warning("auth log not found path=%s", settings.agent_auth_log_path)
            except Exception:
                log.exception("event send loop failed")

            # ── 3. Heartbeat (30초마다) ─────────────────────────────────────
            if time.monotonic() - last_heartbeat >= settings.heartbeat_interval_sec:
                try:
                    await client.send_heartbeat(last_event_id=last_event_id)
                    last_heartbeat = time.monotonic()
                    log.info("heartbeat sent (buffered=%d)", buffer.size())
                except Exception:
                    log.exception("heartbeat failed")

            await asyncio.sleep(settings.poll_interval_sec)
    finally:
        await client.close()


if __name__ == "__main__":
    asyncio.run(run())
