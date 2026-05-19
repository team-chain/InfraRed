"""
InfraRed Windows Agent Entry Point — v4 ETW 구독 지원
배포: PyInstaller -> infrared-agent-windows.exe
사용법:
  infrared-agent-windows.exe --server-url https://api.infrared.io --token <TOKEN>
  infrared-agent-windows.exe --server-url ... --token ... --etw   # ETW 실시간 구독 모드
"""
import argparse
import logging
import sys
import threading

from collectors.event_log_collector import WindowsEventLogCollector

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(description="InfraRed Windows Security Agent")
    parser.add_argument("--server-url", required=True, help="InfraRed server URL")
    parser.add_argument("--token", required=True, help="Agent JWT token")
    parser.add_argument("--agent-id", default="windows-agent-001", help="Agent ID")
    parser.add_argument("--tenant-id", default="", help="Tenant ID")
    parser.add_argument(
        "--etw",
        action="store_true",
        default=False,
        help="ETW 실시간 구독 모드 사용 (기본: win32evtlog 폴링 모드)",
    )
    parser.add_argument("install", nargs="?", help="Windows 서비스로 설치")
    args = parser.parse_args()

    common_kwargs = dict(
        server_url=args.server_url,
        agent_jwt=args.token,
        agent_id=args.agent_id,
        tenant_id=args.tenant_id,
    )

    if args.install:
        _install_service()
        return

    if args.etw:
        # v4: ETW 실시간 구독 모드
        try:
            from collectors.etw_subscriber import ETWSubscriber  # noqa: PLC0415
            logger.info("ETW 실시간 구독 모드로 시작합니다.")
            subscriber = ETWSubscriber(**common_kwargs)
            subscriber.start()
            # 메인 스레드가 종료되지 않도록 대기
            threading.Event().wait()
        except ImportError as exc:
            logger.error("ETW 구독 모듈 로드 실패: %s — 폴링 모드로 전환합니다.", exc)
            _start_polling_mode(common_kwargs)
    else:
        # 기본: win32evtlog 폴링 모드
        _start_polling_mode(common_kwargs)


def _start_polling_mode(kwargs: dict):
    """기존 win32evtlog 10초 폴링 모드로 시작한다."""
    logger.info("win32evtlog 폴링 모드로 시작합니다.")
    collector = WindowsEventLogCollector(**kwargs)
    collector.start()


def _install_service():
    """InfraRed 에이전트를 Windows 서비스로 등록한다."""
    try:
        import win32serviceutil  # type: ignore  # noqa: PLC0415
        import win32service  # type: ignore  # noqa: PLC0415
        import win32con  # type: ignore  # noqa: PLC0415
        import servicemanager  # type: ignore  # noqa: PLC0415

        class InfraRedAgentService(win32serviceutil.ServiceFramework):
            _svc_name_ = "InfraRedAgent"
            _svc_display_name_ = "InfraRed Security Agent"
            _svc_description_ = "InfraRed real-time security monitoring agent"

            def SvcDoRun(self):
                servicemanager.LogInfoMsg("InfraRed Agent service starting...")
                main()

            def SvcStop(self):
                self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
                servicemanager.LogInfoMsg("InfraRed Agent service stopping...")

        win32serviceutil.HandleCommandLine(InfraRedAgentService)
        print("서비스 등록 완료. 시작: net start InfraRedAgent")
    except ImportError:
        print("pywin32 미설치 — 서비스 등록을 건너뜁니다.")
        print("설치: pip install pywin32")
    except Exception as exc:
        print(f"서비스 등록 실패: {exc}")


if __name__ == "__main__":
    main()
