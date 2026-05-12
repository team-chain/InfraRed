"""InfraRed PyQt6 Tray App — 운영자 알림 클라이언트 (설계서 6장).

기능:
  - SSE 기반 실시간 Incident 수신
  - High/Critical 발생 시 OS 알림 팝업
  - 최근 Incident 3개 트레이 메뉴 표시
  - 클릭 시 웹 대시보드 바로가기
  - 연결 상태 표시 (Connected / Disconnected)

실행:
  pip install PyQt6 httpx
  python tray_app/main.py
"""
from __future__ import annotations

import json
import os
import sys
import threading
import webbrowser
from datetime import datetime
from typing import Optional

import httpx
from PyQt6.QtCore import QThread, pyqtSignal, QTimer, Qt
from PyQt6.QtGui import QIcon, QColor, QPixmap
from PyQt6.QtWidgets import (
    QApplication,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QMenu,
    QSystemTrayIcon,
    QVBoxLayout,
    QWidget,
)


# ── 설정 ─────────────────────────────────────────────────────────────────────

DEFAULT_API_URL = os.environ.get("INFRARED_API_URL", "http://localhost:8000")
DEFAULT_TOKEN   = os.environ.get("INFRARED_TOKEN", "")
DEFAULT_DASHBOARD_URL = os.environ.get("INFRARED_DASHBOARD_URL", "http://localhost:3000")

SEVERITY_NOTIFY = {"critical", "high"}   # OS 팝업 대상
MAX_RECENT = 3                            # 트레이 메뉴 최근 항목 수

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "info":     "🔵",
}


# ── SSE Worker Thread ─────────────────────────────────────────────────────────

class SseWorker(QThread):
    """백그라운드 스레드에서 SSE 스트림을 수신해 시그널로 전달."""

    incident_received = pyqtSignal(dict)   # Incident 수신
    connected = pyqtSignal()               # 연결 성공
    disconnected = pyqtSignal(str)         # 연결 끊김 (reason)

    def __init__(self, api_url: str, token: str, tenant_id: str = "company-a") -> None:
        super().__init__()
        self.api_url = api_url.rstrip("/")
        self.token = token
        self.tenant_id = tenant_id
        self._running = True

    def stop(self) -> None:
        self._running = False
        self.quit()

    def run(self) -> None:
        url = f"{self.api_url}/events/stream"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "text/event-stream",
            "Cache-Control": "no-cache",
        }
        retry_delay = 3  # seconds

        while self._running:
            try:
                with httpx.Client(timeout=None) as client:
                    with client.stream("GET", url, headers=headers) as response:
                        response.raise_for_status()
                        self.connected.emit()
                        retry_delay = 3

                        event_type = None
                        data_lines: list[str] = []

                        for line in response.iter_lines():
                            if not self._running:
                                break
                            if line.startswith("event:"):
                                event_type = line[6:].strip()
                            elif line.startswith("data:"):
                                data_lines.append(line[5:].strip())
                            elif line == "":
                                # 이벤트 완성
                                if data_lines:
                                    raw = "\n".join(data_lines)
                                    try:
                                        payload = json.loads(raw)
                                        payload["_event_type"] = event_type or "message"
                                        self.incident_received.emit(payload)
                                    except json.JSONDecodeError:
                                        pass
                                event_type = None
                                data_lines = []

            except httpx.HTTPStatusError as exc:
                self.disconnected.emit(f"HTTP {exc.response.status_code}")
            except Exception as exc:
                self.disconnected.emit(str(type(exc).__name__))

            if self._running:
                import time
                time.sleep(retry_delay)
                retry_delay = min(retry_delay * 2, 60)  # 최대 60초


# ── 설정 다이얼로그 ───────────────────────────────────────────────────────────

class SettingsDialog(QDialog):
    def __init__(self, api_url: str, token: str, dashboard_url: str, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("InfraRed — 연결 설정")
        self.setMinimumWidth(400)

        layout = QVBoxLayout(self)
        form = QFormLayout()

        self.api_url_edit = QLineEdit(api_url)
        self.token_edit = QLineEdit(token)
        self.token_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.dashboard_edit = QLineEdit(dashboard_url)

        form.addRow("API URL:", self.api_url_edit)
        form.addRow("Token:", self.token_edit)
        form.addRow("대시보드 URL:", self.dashboard_edit)
        layout.addLayout(form)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    @property
    def values(self) -> tuple[str, str, str]:
        return (
            self.api_url_edit.text().strip(),
            self.token_edit.text().strip(),
            self.dashboard_edit.text().strip(),
        )


# ── Tray 아이콘 색상 픽셀맵 생성 ──────────────────────────────────────────────

def _make_icon(color: str) -> QIcon:
    """단색 원형 아이콘 생성."""
    px = QPixmap(22, 22)
    px.fill(Qt.GlobalColor.transparent)
    from PyQt6.QtGui import QPainter, QBrush
    painter = QPainter(px)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setBrush(QBrush(QColor(color)))
    painter.setPen(Qt.PenStyle.NoPen)
    painter.drawEllipse(2, 2, 18, 18)
    painter.end()
    return QIcon(px)


_ICON_CONNECTED    = None
_ICON_DISCONNECTED = None
_ICON_ALERT        = None


def _init_icons():
    global _ICON_CONNECTED, _ICON_DISCONNECTED, _ICON_ALERT
    _ICON_CONNECTED    = _make_icon("#22c55e")   # green
    _ICON_DISCONNECTED = _make_icon("#6b7280")   # gray
    _ICON_ALERT        = _make_icon("#ef4444")   # red


# ── 메인 트레이 앱 ─────────────────────────────────────────────────────────────

class InfraRedTrayApp:
    def __init__(self, app: QApplication) -> None:
        self.app = app
        self.api_url = DEFAULT_API_URL
        self.token = DEFAULT_TOKEN
        self.dashboard_url = DEFAULT_DASHBOARD_URL
        self.is_connected = False
        self.recent_incidents: list[dict] = []
        self.sse_worker: Optional[SseWorker] = None

        _init_icons()

        self.tray = QSystemTrayIcon()
        self.tray.setIcon(_ICON_DISCONNECTED)
        self.tray.setToolTip("InfraRed — 연결 중...")
        self.tray.activated.connect(self._on_tray_activated)

        self._build_menu()
        self.tray.setContextMenu(self.menu)
        self.tray.show()

        # 자동 연결 시도
        QTimer.singleShot(500, self._start_sse)

    def _build_menu(self) -> None:
        self.menu = QMenu()

        # 상태
        self.status_action = self.menu.addAction("⚫ 연결 끊김")
        self.status_action.setEnabled(False)
        self.menu.addSeparator()

        # 최근 인시던트 (최대 3개)
        self.incident_actions = []
        for _ in range(MAX_RECENT):
            a = self.menu.addAction("")
            a.setVisible(False)
            self.incident_actions.append(a)

        self.menu.addSeparator()

        # 메뉴 항목
        dashboard_action = self.menu.addAction("🌐 대시보드 열기")
        dashboard_action.triggered.connect(self._open_dashboard)

        settings_action = self.menu.addAction("⚙️ 연결 설정")
        settings_action.triggered.connect(self._open_settings)

        reconnect_action = self.menu.addAction("🔄 재연결")
        reconnect_action.triggered.connect(self._restart_sse)

        self.menu.addSeparator()

        quit_action = self.menu.addAction("✖ 종료")
        quit_action.triggered.connect(self.app.quit)

    def _update_menu_incidents(self) -> None:
        for i, action in enumerate(self.incident_actions):
            if i < len(self.recent_incidents):
                inc = self.recent_incidents[i]
                sev = inc.get("severity", "info").lower()
                emoji = SEVERITY_EMOJI.get(sev, "⚪")
                inc_id = inc.get("incident_id", "?")[:12]
                ts = inc.get("detected_at", "")[:16].replace("T", " ")
                label = f"{emoji} {inc_id}  {ts}"
                action.setText(label)
                action.setVisible(True)
                # 클릭 시 대시보드로
                action.triggered.disconnect() if action.receivers(action.triggered) > 0 else None
                action.triggered.connect(self._open_dashboard)
            else:
                action.setVisible(False)

    def _set_connected(self, connected: bool) -> None:
        self.is_connected = connected
        if connected:
            self.tray.setIcon(_ICON_CONNECTED)
            self.tray.setToolTip("InfraRed — Connected ✅")
            self.status_action.setText("🟢 Connected")
        else:
            self.tray.setIcon(_ICON_DISCONNECTED)
            self.tray.setToolTip("InfraRed — Disconnected")
            self.status_action.setText("⚫ 연결 끊김")

    def _on_incident(self, payload: dict) -> None:
        """SSE 이벤트 수신 처리."""
        event_type = payload.get("_event_type", "")
        if event_type not in ("incident_created", "incident_updated", "message"):
            return

        # 최근 인시던트 업데이트
        inc_id = payload.get("incident_id") or payload.get("id")
        if inc_id:
            # 중복 제거
            self.recent_incidents = [x for x in self.recent_incidents if x.get("incident_id") != inc_id]
            self.recent_incidents.insert(0, payload)
            self.recent_incidents = self.recent_incidents[:MAX_RECENT]
            self._update_menu_incidents()

        # High/Critical OS 알림 팝업 (설계서 6.2)
        severity = payload.get("severity", "").lower()
        if severity in SEVERITY_NOTIFY:
            emoji = SEVERITY_EMOJI.get(severity, "⚠️")
            title = f"InfraRed {emoji} {severity.upper()} 인시던트"
            body = payload.get("plain_summary") or f"Incident {inc_id} 탐지됨"
            if len(body) > 200:
                body = body[:197] + "..."

            self.tray.setIcon(_ICON_ALERT)
            self.tray.showMessage(
                title,
                body,
                QSystemTrayIcon.MessageIcon.Critical if severity == "critical"
                else QSystemTrayIcon.MessageIcon.Warning,
                msecs=8000,
            )
            # 알림 클릭 시 대시보드 열기
            try:
                self.tray.messageClicked.disconnect()
            except Exception:
                pass
            self.tray.messageClicked.connect(self._open_dashboard)

            # 3초 후 아이콘 복구
            QTimer.singleShot(3000, lambda: self.tray.setIcon(
                _ICON_CONNECTED if self.is_connected else _ICON_DISCONNECTED
            ))

    def _on_connected(self) -> None:
        self._set_connected(True)

    def _on_disconnected(self, reason: str) -> None:
        self._set_connected(False)
        self.tray.setToolTip(f"InfraRed — 재연결 중... ({reason})")

    def _start_sse(self) -> None:
        if not self.token:
            self.tray.showMessage(
                "InfraRed — 설정 필요",
                "토큰이 설정되지 않았습니다. 연결 설정을 열어주세요.",
                QSystemTrayIcon.MessageIcon.Information,
                msecs=4000,
            )
            return

        self.sse_worker = SseWorker(self.api_url, self.token)
        self.sse_worker.incident_received.connect(self._on_incident)
        self.sse_worker.connected.connect(self._on_connected)
        self.sse_worker.disconnected.connect(self._on_disconnected)
        self.sse_worker.start()

    def _restart_sse(self) -> None:
        if self.sse_worker:
            self.sse_worker.stop()
            self.sse_worker.wait(2000)
        self._start_sse()

    def _open_dashboard(self) -> None:
        webbrowser.open(self.dashboard_url)

    def _open_settings(self) -> None:
        dialog = SettingsDialog(self.api_url, self.token, self.dashboard_url)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.api_url, self.token, self.dashboard_url = dialog.values
            self._restart_sse()

    def _on_tray_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self._open_dashboard()


def main() -> None:
    app = QApplication(sys.argv)
    app.setApplicationName("InfraRed Tray")
    app.setQuitOnLastWindowClosed(False)

    if not QSystemTrayIcon.isSystemTrayAvailable():
        print("시스템 트레이를 사용할 수 없습니다.")
        sys.exit(1)

    tray_app = InfraRedTrayApp(app)
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
