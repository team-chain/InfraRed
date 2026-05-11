"""InfraRed agent entrypoint."""
from __future__ import annotations

import asyncio
import logging
import os
import time

from infrared_agent.client import AgentClient
from infrared_agent.commander import Commander
from infrared_agent.config import AgentSettings
from infrared_agent.offset_store import OffsetStore
from infrared_agent.s3_uploader import S3LogUploader
from infrared_agent.tailer import AuthLogTailer, NginxLogTailer


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("infrared_agent")


async def _tail_log(tailer: AuthLogTailer | NginxLogTailer, log_path: str,
                    client: AgentClient, store: OffsetStore, s3: S3LogUploader,
                    settings: AgentSettings, last_event_id_ref: list) -> None:
    """단일 로그 파일 tailing 루프 (auth.log / nginx access.log 공용)."""
    try:
        for envelope, new_offset, inode in tailer.read_new_events():
            await client.send_event(envelope)
            store.set(log_path, inode, new_offset)
            last_event_id_ref[0] = envelope["event_id"]
            log.info("sent event_id=%s source=%s offset=%s",
                     last_event_id_ref[0], envelope.get("raw_source"), new_offset)
            if settings.s3_enabled:
                raw_line = envelope.get("raw_line") or str(envelope.get("timestamp", ""))
                s3.push(raw_line)
    except FileNotFoundError:
        log.warning("log not found path=%s", log_path)
    except Exception:
        log.exception("tail loop failed path=%s", log_path)


async def run() -> None:
    settings = AgentSettings()
    if not settings.agent_token:
        raise RuntimeError("AGENT_TOKEN is required")

    offset_dir = os.path.dirname(settings.agent_offset_db)
    if offset_dir:
        os.makedirs(offset_dir, exist_ok=True)
    store = OffsetStore(settings.agent_offset_db)
    auth_tailer = AuthLogTailer(settings, store)
    nginx_tailer = NginxLogTailer(settings, store) if settings.agent_nginx_enabled else None
    client = AgentClient(settings)
    commander = Commander(settings, client)
    s3 = S3LogUploader(settings)
    last_heartbeat = 0.0
    last_command_poll = 0.0
    last_event_id_ref: list = [None]   # mutable ref shared across tail calls

    if settings.s3_enabled:
        log.info("s3_upload_enabled bucket=%s prefix=%s", settings.s3_bucket, settings.s3_prefix)
    else:
        log.info("s3_upload_disabled")

    if nginx_tailer:
        log.info("nginx_tailing_enabled path=%s", settings.agent_nginx_log_path)
    else:
        log.info("nginx_tailing_disabled")

    try:
        while True:
            # auth.log + nginx access.log 병렬 tailing
            tail_tasks = [
                _tail_log(auth_tailer, settings.agent_auth_log_path,
                          client, store, s3, settings, last_event_id_ref),
            ]
            if nginx_tailer:
                tail_tasks.append(
                    _tail_log(nginx_tailer, settings.agent_nginx_log_path,
                              client, store, s3, settings, last_event_id_ref)
                )
            await asyncio.gather(*tail_tasks)

            # S3 주기 업로드
            if settings.s3_enabled:
                try:
                    await s3.flush_if_ready()
                except Exception:
                    log.exception("s3 flush failed")

            if time.monotonic() - last_heartbeat >= settings.heartbeat_interval_sec:
                try:
                    await client.send_heartbeat(last_event_id=last_event_id_ref[0])
                    last_heartbeat = time.monotonic()
                    log.info("heartbeat sent")
                except Exception:
                    log.exception("heartbeat failed")

            if time.monotonic() - last_command_poll >= 5:
                try:
                    await commander.poll_and_execute()
                    last_command_poll = time.monotonic()
                except Exception:
                    log.exception("command poll failed")

            await asyncio.sleep(settings.poll_interval_sec)
    finally:
        await client.close()


if __name__ == "__main__":
    asyncio.run(run())
