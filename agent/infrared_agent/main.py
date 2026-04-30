"""InfraRed agent entrypoint."""
from __future__ import annotations

import asyncio
import logging
import os
import time

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

    offset_dir = os.path.dirname(settings.agent_offset_db)
    if offset_dir:
        os.makedirs(offset_dir, exist_ok=True)
    store = OffsetStore(settings.agent_offset_db)
    tailer = AuthLogTailer(settings, store)
    client = AgentClient(settings)
    last_heartbeat = 0.0
    last_event_id: str | None = None

    try:
        while True:
            try:
                for envelope, new_offset, inode in tailer.read_new_events():
                    await client.send_event(envelope)
                    store.set(settings.agent_auth_log_path, inode, new_offset)
                    last_event_id = envelope["event_id"]
                    log.info("sent event_id=%s offset=%s", last_event_id, new_offset)
            except FileNotFoundError:
                log.warning("auth log not found path=%s", settings.agent_auth_log_path)
            except Exception:
                log.exception("event send loop failed")

            if time.monotonic() - last_heartbeat >= settings.heartbeat_interval_sec:
                try:
                    await client.send_heartbeat(last_event_id=last_event_id)
                    last_heartbeat = time.monotonic()
                    log.info("heartbeat sent")
                except Exception:
                    log.exception("heartbeat failed")

            await asyncio.sleep(settings.poll_interval_sec)
    finally:
        await client.close()


if __name__ == "__main__":
    asyncio.run(run())
