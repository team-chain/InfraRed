"""InfraRed agent entrypoint.

수집 소스 (설계서 v2.0 Phase 4-A / v3.0):
  - auth.log       → SSH 이상 행위 탐지 (AUTH-001~006)
  - nginx.log      → 웹 공격 탐지 (WEB-HNY-001, WEB-001~007, NET-001)
  - FIM 감시       → authorized_keys / sshd_config / cron / sudoers 변경 감지
  - auditd (opt)   → 의심 프로세스 실행 / 민감 파일 접근 (privileged mode)
  - Windows (opt)  → 이벤트 ID 4625/4720 (Windows 에이전트)
  - EXEC 모니터    → /tmp 실행 탐지 / 웹셸 탐지 / 랜섬웨어 전조 (v3.0)
"""
from __future__ import annotations

import asyncio
import logging
import os
import signal
import time
import uuid

from infrared_agent.client import AgentClient
from infrared_agent.commander import Commander
from infrared_agent.config import AgentSettings
from infrared_agent.fim_watcher import (
    AuditdWatcher,
    BulkFileModificationMonitor,
    FIMWatcher,
    TmpExecutionMonitor,
    WebServerChildProcessMonitor,
    WindowsEventLogWatcher,
)
from infrared_agent.nginx_tailer import NginxLogTailer
from infrared_agent.offset_store import OffsetStore
from infrared_agent.s3_uploader import S3LogUploader
from infrared_agent.tailer import AuthLogTailer


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("infrared_agent")

# 설계서 v2.0 Phase 3-D: StartLimitBurst=5 대응
# systemd가 이 값을 초과하는 연속 실패를 감지하면 재시작을 중단(Deactivated)함.
# Python 레벨에서도 동일 임계값을 추적해 조기 경고 로그를 남기고
# 종료 직전 status=deactivated heartbeat를 전송함.
_CONSECUTIVE_FAILURE_LIMIT = 5


async def _send_log_events(
    tailer: AuthLogTailer | NginxLogTailer,
    client: AgentClient,
    store: OffsetStore,
    log_path: str,
    s3: S3LogUploader | None = None,
    s3_enabled: bool = False,
) -> str | None:
    """로그 타일러에서 새 이벤트를 읽어 백엔드로 전송. 마지막 event_id 반환."""
    last_event_id = None
    try:
        for envelope, new_offset, inode in tailer.read_new_events():
            await client.send_event(envelope)
            store.set(log_path, inode, new_offset)
            last_event_id = envelope["event_id"]
            log.info(
                "sent source=%s event_id=%s offset=%s",
                envelope.get("raw_source", "unknown"),
                last_event_id,
                new_offset,
            )
            if s3_enabled and s3:
                raw_line = envelope.get("raw_line") or str(envelope.get("timestamp", ""))
                s3.push(raw_line)
    except FileNotFoundError as exc:
        log.warning("log file not found path=%s", exc.filename)
    except Exception:
        log.exception("event send loop failed source=%s", log_path)
    return last_event_id


async def _report_deactivated(client: AgentClient, reason: str) -> None:
    """설계서 v2.0 Phase 3-D: 종료 직전 status=deactivated heartbeat 전송.

    systemd의 StartLimitBurst(5회 연속 실패) 초과로 재시작이 중단될 때,
    백엔드 DB에 deactivated_at / deactivation_reason을 기록해
    헬스체크 대시보드에 즉시 반영함.
    """
    try:
        log.warning("agent_deactivating reason=%s", reason)
        await client.send_heartbeat(
            status="deactivated",
            deactivation_reason=reason,
        )
        log.warning("deactivated_heartbeat_sent")
    except Exception:
        log.exception("deactivated_heartbeat_failed — backend may mark agent offline via timeout")


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
    # v3.0: TTL 기반 차단 만료 루프 백그라운드 태스크
    ttl_task = asyncio.create_task(commander.ttl_expiry_loop())
    s3 = S3LogUploader(settings)

    # Phase 4-A: FIM / auditd / Windows 감시자 초기화
    fim_enabled = getattr(settings, "agent_fim_enabled", True)
    fim_watcher = FIMWatcher(settings) if fim_enabled else None
    auditd_enabled = getattr(settings, "agent_auditd_enabled", False)
    auditd_watcher = AuditdWatcher(settings) if auditd_enabled else None
    windows_watcher = WindowsEventLogWatcher(settings)

    # v3.0: 실행 탐지 모니터 초기화
    exec_enabled = getattr(settings, "agent_exec_monitor_enabled", True)
    tmp_exec_monitor = TmpExecutionMonitor() if exec_enabled else None
    webshell_monitor = WebServerChildProcessMonitor() if exec_enabled else None
    bulk_mod_monitor = BulkFileModificationMonitor() if exec_enabled else None

    last_heartbeat = 0.0
    last_command_poll = 0.0
    last_fim_check = 0.0
    last_tmp_exec_check = 0.0
    last_webshell_check = 0.0
    last_bulk_mod_check = 0.0
    last_event_id: str | None = None

    _fim_check_interval = getattr(settings, "agent_fim_interval_seconds", 60)
    # v3.0 실행 탐지 폴링 간격
    _tmp_exec_interval = 10    # EXEC-001: 10초
    _webshell_interval = 15    # EXEC-002: 15초
    _bulk_mod_interval = 30    # EXEC-003: 30초

    # 설계서 v2.0 Phase 3-D: 연속 실패 카운터
    consecutive_failures = 0

    # ── SIGTERM / SIGINT 핸들러 ────────────────────────────────────────────────
    # systemd가 StartLimitBurst(5회) 초과 후 SIGTERM을 보내기 전,
    # 또는 운영자가 `systemctl stop`을 실행할 때 호출됨.
    # 최종 heartbeat(status=deactivated)를 전송해 헬스체크 대시보드에 즉시 반영.
    shutdown_event = asyncio.Event()

    def _handle_shutdown(sig_name: str) -> None:
        log.info("signal_received signal=%s initiating_graceful_shutdown", sig_name)
        shutdown_event.set()

    loop = asyncio.get_event_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, _handle_shutdown, sig.name)
        except (NotImplementedError, RuntimeError):
            # Windows 환경에서는 add_signal_handler 미지원 — 무시
            pass

    log.info(
        "agent_started auth_log=%s nginx_log=%s nginx_enabled=%s s3=%s fim=%s auditd=%s exec=%s",
        settings.agent_auth_log_path,
        settings.agent_nginx_log_path,
        settings.agent_nginx_enabled,
        settings.s3_enabled,
        fim_enabled,
        auditd_enabled,
        exec_enabled,
    )

    try:
        while not shutdown_event.is_set():
            loop_failed = False

            try:
                # ── auth.log 수집 ─────────────────────────────────────────────
                ev_id = await _send_log_events(
                    auth_tailer, client, store,
                    settings.agent_auth_log_path,
                    s3=s3, s3_enabled=settings.s3_enabled,
                )
                if ev_id:
                    last_event_id = ev_id

                # -- nginx.log 수집 --------------------------------------------
                if nginx_tailer is not None:
                    ev_id = await _send_log_events(
                        nginx_tailer, client, store,
                        settings.agent_nginx_log_path,
                        s3=s3, s3_enabled=settings.s3_enabled,
                    )
                    if ev_id:
                        last_event_id = ev_id

                # -- Heartbeat (설정 간격마다) -----------------------------------
                now = time.monotonic()
                if now - last_heartbeat >= settings.heartbeat_interval_sec:
                    try:
                        await client.send_heartbeat(last_event_id=last_event_id)
                        last_heartbeat = now
                    except Exception:
                        log.exception("heartbeat failed")

                # -- Command poll -----------------------------------------------
                if now - last_command_poll >= settings.agent_command_poll_interval_seconds:
                    try:
                        await commander.poll_and_execute()
                        last_command_poll = now
                    except Exception:
                        log.exception("command poll failed")

                # -- Phase 4-A: FIM 감시 (60초 간격) ----------------------------
                if fim_watcher and (now - last_fim_check >= _fim_check_interval):
                    try:
                        changes = fim_watcher.check_changes()
                        for change in changes:
                            envelope = _build_fim_envelope(change, settings)
                            await client.send_event(envelope)
                            log.warning(
                                "fim_change_detected rule=%s path=%s",
                                change.get("rule_id"),
                                change.get("path"),
                            )
                        last_fim_check = now
                    except Exception:
                        log.exception("fim check failed")

                # -- Phase 4-A: auditd 감시 (있으면) -----------------------------
                if auditd_watcher:
                    try:
                        auditd_events = auditd_watcher.read_new_events()
                        for evt in auditd_events:
                            envelope = _build_fim_envelope(evt, settings)
                            await client.send_event(envelope)
                    except Exception:
                        log.exception("auditd watch failed")

                # -- Phase 4-A: Windows Event Log --------------------------------
                try:
                    win_events = windows_watcher.read_new_events()
                    for evt in win_events:
                        envelope = _build_fim_envelope(evt, settings)
                        await client.send_event(envelope)
                except Exception:
                    pass  # Windows 이벤트는 선택적

                # -- v3.0 EXEC-001: /tmp 실행 탐지 (10초 간격) ------------------
                if tmp_exec_monitor and (now - last_tmp_exec_check >= _tmp_exec_interval):
                    try:
                        exec_events = tmp_exec_monitor.check()
                        for evt in exec_events:
                            envelope = _build_fim_envelope(evt, settings)
                            await client.send_event(envelope)
                            log.warning(
                                "exec_001_detected pid=%s exe=%s",
                                evt.get("pid"),
                                evt.get("exe_path"),
                            )
                        last_tmp_exec_check = now
                    except Exception:
                        log.exception("exec-001 tmp monitor failed")

                # -- v3.0 EXEC-002: 웹셸 탐지 (15초 간격) -----------------------
                if webshell_monitor and (now - last_webshell_check >= _webshell_interval):
                    try:
                        shell_events = webshell_monitor.check()
                        for evt in shell_events:
                            envelope = _build_fim_envelope(evt, settings)
                            await client.send_event(envelope)
                            log.warning(
                                "exec_002_detected parent=%s(%s) child=%s(%s)",
                                evt.get("parent_process"),
                                evt.get("parent_pid"),
                                evt.get("child_process"),
                                evt.get("child_pid"),
                            )
                        last_webshell_check = now
                    except Exception:
                        log.exception("exec-002 webshell monitor failed")

                # -- v3.0 EXEC-003: 대량 파일 변경 감지 (30초 간격) -------------
                if bulk_mod_monitor and (now - last_bulk_mod_check >= _bulk_mod_interval):
                    try:
                        bulk_events = bulk_mod_monitor.check()
                        for evt in bulk_events:
                            envelope = _build_fim_envelope(evt, settings)
                            await client.send_event(envelope)
                            log.warning(
                                "exec_003_detected change_count=%s window=%ss",
                                evt.get("change_count"),
                                evt.get("window_seconds"),
                            )
                        last_bulk_mod_check = now
                    except Exception:
                        log.exception("exec-003 bulk mod monitor failed")

                # 정상 실행 — 연속 실패 카운터 초기화
                consecutive_failures = 0

            except Exception:
                loop_failed = True
                consecutive_failures += 1
                log.exception(
                    "main_loop_error consecutive_failures=%d limit=%d",
                    consecutive_failures,
                    _CONSECUTIVE_FAILURE_LIMIT,
                )

                # 설계서 v2.0 Phase 3-D: StartLimitBurst=5 임박 경고
                if consecutive_failures >= _CONSECUTIVE_FAILURE_LIMIT:
                    reason = (
                        f"Consecutive failure limit reached "
                        f"({consecutive_failures}/{_CONSECUTIVE_FAILURE_LIMIT}). "
                        "Agent will be deactivated by systemd (StartLimitBurst exceeded)."
                    )
                    await _report_deactivated(client, reason)
                    # systemd가 재시작을 중단하도록 비정상 종료 코드로 exit
                    raise SystemExit(1)

            if not loop_failed:
                await asyncio.sleep(settings.agent_poll_interval_seconds)
            else:
                # 실패 시 재시작 전 짧은 대기 (백오프)
                backoff = min(5.0 * consecutive_failures, 30.0)
                log.info("retry_backoff seconds=%.1f", backoff)
                await asyncio.sleep(backoff)

    except asyncio.CancelledError:
        log.info("agent_cancelled")
    finally:
        # v3.0: TTL 만료 루프 태스크 취소
        ttl_task.cancel()
        try:
            await ttl_task
        except asyncio.CancelledError:
            pass
        # ── 종료 시 최종 heartbeat 전송 ───────────────────────────────────────
        # shutdown_event가 설정된 경우: 정상 종료(systemctl stop 등) → 별도 보고 불필요
        # 그 외(예외 등): deactivated 보고는 루프 내에서 이미 처리됨
        log.info("agent_stopping closing_client")
        try:
            await client.close()
        except Exception:
            pass


def _build_fim_envelope(change: dict, settings: AgentSettings) -> dict:
    """FIM/auditd 이벤트를 Ingestion API 형식으로 변환."""
    return {
        "event_id": f"FIM-{uuid.uuid4().hex[:12]}",
        "agent_id": settings.agent_id,
        "tenant_id": settings.tenant_id,
        "asset_id": settings.asset_id,
        "event_type": change.get("event_type", "fim_change"),
        "timestamp": change.get("detected_at"),
        "raw_source": "fim",
        "rule_id": change.get("rule_id"),
        "mitre_technique": change.get("mitre_technique"),
        "description": change.get("description"),
        "payload": {
            k: v for k, v in change.items()
            if k not in {"detected_at", "event_type", "rule_id", "mitre_technique", "description"}
        },
    }


def main() -> None:
    asyncio.run(run())


if __name__ == "__main__":
    main()
