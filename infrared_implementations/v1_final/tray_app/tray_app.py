"""
InfraRed v1 — PyQt6 시스템 트레이 앱
설계서_최종.docx 구현 순서 #5

기능:
  - 로그인 / API URL / JWT 토큰 저장 (QSettings)
  - SSE 기반 실시간 Incident 수신 (백그라운드 스레드)
  - High/Critical 발생 시 OS 알림 팝업 (QSystemTrayIcon)
  - 최근 Incident 3개 표시
  - 클릭 시 웹 대시보드 바로가기
  - 연결 상태 표시 (Connected / Disconnected)

실행: python tray_app.py
의존성: pip install PyQt6 httpx keyring
"""

from __future__ import annotations

import json
import sys
import threading
import time
import webbrowser
from datetime import datetime
from typing import Optional

import httpx

try:
    from PyQt6.QtCore import QSettings, QThread, pyqtSignal, QTimer
    from PyQt6.QtGui import QAction, QColor, QIcon, QPainter, QPixmap
    from PyQt6.QtWidgets import (
        QApplication, QDialog, QFormLayout, QHBoxLayout,
        QLabel, QLineEdit, QMenu, QMessageBox, QPushButton,
        QSystemTrayIcon, QVBoxLayout, QWidget,
    )
except ImportError:
    print("PyQt6가 설치되지 않았습니다. 설치: pip install PyQt6")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────
# 상수
# ─────────────────────────────────────────────────────────────
APP_NAME    = "InfraRed"
ORG_NAME    = "InfraRed Security"
SETTINGS_KEY_API_URL = "api_url"
SETTINGS_KEY_TOKEN   = "api_token"
SETTINGS_KEY_TENANT  = "tenant_id"

SEVERITY_COLORS = {
    "CRITICAL": "#ef4444",
    "HIGH":     "#f97316",
    "MEDIUM":   "#eab308",
    "LOW":      "#22c55e",
}


# ─────────────────────────────────────────────────────────────
# 아이콘 생성 (파일 없이 인라인 생성)
# ─────────────────────────────────────────────────────────────
def _make_icon(color: str = "#3b82f6") -> QIcon:
    """단색 원형 아이콘 생성"""
    px = QPixmap(22, 22)
    px.fill(QColor("transparent"))
    painter = QPainter(px)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setBrush(QColor(color))
    painter.setPen(QColor("transparent"))
    painter.drawEllipse(1, 1, 20, 20)
    painter.end()
    return QIcon(px)


# ─────────────────────────────────────────────────────────────
# SSE 수신 스레드
# ─────────────────────────────────────────────────────────────
class SSEWorker(QThread):
    """
    백그라운드 스레드에서 SSE 연결 유지.
    새 인시던트 수신 시 incident_received 시그널 발생.
    """
    incident_received  = pyqtSignal(dict)
    connection_changed = pyqtSignal(bool)   # True=connected, False=disconnected

    def __init__(self, api_url: str, token: str, tenant_id: str):
        super().__init__()
        self.api_url   = api_url.rstrip("/")
        self.token     = token
        self.tenant_id = tenant_id
        self._stop     = threading.Event()

    def stop(self):
        self._stop.set()

    def run(self):
        url = f"{self.api_url}/api/v1/events/incidents"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "X-Tenant-ID":   self.tenant_id,
            "Accept":        "text/event-stream",
            "Cache-Control": "no-cache",
        }

        while not self._stop.is_set():
            try:
                with httpx.stream("GET", url, headers=headers, timeout=None) as resp:
                    self.connection_changed.emit(True)
                    for line in resp.iter_lines():
                        if self._stop.is_set():
                            break
                        line = line.strip()
                        if not line or line.startswith(":"):
                            continue
                        if line.startswith("data:"):
                            payload = line[5:].strip()
                            try:
                                data = json.loads(payload)
                                self.incident_received.emit(data)
                            except json.JSONDecodeError:
                                pass
            except Exception:
                self.connection_changed.emit(False)
                # 재연결 대기 (5초)
                for _ in range(50):
                    if self._stop.is_set():
                        return
                    time.sleep(0.1)


# ─────────────────────────────────────────────────────────────
# 로그인 다이얼로그
# ─────────────────────────────────────────────────────────────
class LoginDialog(QDialog):
    def __init__(self, settings: QSettings, parent=None):
        super().__init__(parent)
        self.settings = settings
        self.setWindowTitle(f"{APP_NAME} — 연결 설정")
        self.setFixedWidth(420)

        layout = QVBoxLayout(self)
        form   = QFormLayout()

        self.url_edit    = QLineEdit(settings.value(SETTINGS_KEY_API_URL, "https://your-infrared.example.com"))
        self.token_edit  = QLineEdit(settings.value(SETTINGS_KEY_TOKEN, ""))
        self.tenant_edit = QLineEdit(settings.value(SETTINGS_KEY_TENANT, "default"))
        self.token_edit.setEchoMode(QLineEdit.EchoMode.Password)

        form.addRow("API URL:", self.url_edit)
        form.addRow("JWT 토큰:", self.token_edit)
        form.addRow("테넌트 ID:", self.tenant_edit)
        layout.addLayout(form)

        btns = QHBoxLayout()
        save_btn   = QPushButton("저장 &연결")
        cancel_btn = QPushButton("취소")
        save_btn.clicked.connect(self._save)
        cancel_btn.clicked.connect(self.reject)
        btns.addStretch()
        btns.addWidget(cancel_btn)
        btns.addWidget(save_btn)
        layout.addLayout(btns)

    def _save(self):
        self.settings.setValue(SETTINGS_KEY_API_URL, self.url_edit.text().strip())
        self.settings.setValue(SETTINGS_KEY_TOKEN,   self.token_edit.text().strip())
        self.settings.setValue(SETTINGS_KEY_TENANT,  self.tenant_edit.text().strip())
        self.accept()


# ─────────────────────────────────────────────────────────────
# 최근 인시던트 팝업
# ─────────────────────────────────────────────────────────────
class RecentIncidentsDialog(QDialog):
    def __init__(self, incidents: list[dict], api_url: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"{APP_NAME} — 최근 인시던트")
        self.setFixedWidth(500)
        self.api_url = api_url

        layout = QVBoxLayout(self)

        if not incidents:
            layout.addWidget(QLabel("최근 인시던트가 없습니다."))
        else:
            for inc in incidents:
                card = self._make_card(inc)
                layout.addWidget(card)

        layout.addStretch()
        close_btn = QPushButton("닫기")
        close_btn.clicked.connect(self.accept)
        layout.addWidget(close_btn)

    def _make_card(self, inc: dict) -> QWidget:
        widget = QWidget()
        widget.setStyleSheet(
            "background:#f9fafb; border:1px solid #e5e7eb; border-radius:8px; margin:4px;"
        )
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(12, 10, 12, 10)

        severity = inc.get("severity", "UNKNOWN")
        color    = SEVERITY_COLORS.get(severity, "#6b7280")

        top = QHBoxLayout()
        sev_label = QLabel(f"● {severity}")
        sev_label.setStyleSheet(f"color:{color}; font-weight:bold;")
        rule_label = QLabel(inc.get("primary_rule_id", "UNKNOWN"))
        rule_label.setStyleSheet("color:#374151; font-weight:600;")
        ts = inc.get("created_at", "")
        ts_label = QLabel(_format_ts(ts))
        ts_label.setStyleSheet("color:#9ca3af; font-size:11px;")
        top.addWidget(sev_label)
        top.addWidget(rule_label)
        top.addStretch()
        top.addWidget(ts_label)
        layout.addLayout(top)

        desc = QLabel(inc.get("summary", inc.get("source_ip", "상세 없음")))
        desc.setStyleSheet("color:#6b7280; font-size:12px;")
        desc.setWordWrap(True)
        layout.addWidget(desc)

        open_btn = QPushButton("대시보드에서 열기 →")
        open_btn.setStyleSheet("color:#3b82f6; background:none; border:none; text-align:left;")
        open_btn.setCursor(open_btn.cursor())
        inc_id = inc.get("id", "")
        open_btn.clicked.connect(
            lambda: webbrowser.open(f"{self.api_url}/incidents/{inc_id}")
        )
        layout.addWidget(open_btn)

        return widget


def _format_ts(ts_str: str) -> str:
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        return dt.strftime("%m/%d %H:%M")
    except Exception:
        return ts_str[:16] if ts_str else ""


# ─────────────────────────────────────────────────────────────
# 트레이 앱 메인
# ─────────────────────────────────────────────────────────────
class InfraRedTrayApp(QSystemTrayIcon):
    MAX_RECENT = 3

    def __init__(self, app: QApplication):
        super().__init__(app)
        self.app      = app
        self.settings = QSettings(ORG_NAME, APP_NAME)
        self.worker:  Optional[SSEWorker] = None
        self.recent:  list[dict]          = []
        self.connected = False

        self._build_menu()
        self.setIcon(_make_icon("#6b7280"))
        self.setToolTip(f"{APP_NAME} — 연결 안됨")
        self.activated.connect(self._on_activated)
        self.show()

        # 저장된 설정이 있으면 자동 연결
        if (self.settings.value(SETTINGS_KEY_TOKEN)
                and self.settings.value(SETTINGS_KEY_API_URL)):
            QTimer.singleShot(500, self._connect)

    # ── 메뉴 ──────────────────────────────────────────────
    def _build_menu(self):
        menu = QMenu()

        self.status_action = QAction("⚪ 연결 안됨")
        self.status_action.setEnabled(False)
        menu.addAction(self.status_action)
        menu.addSeparator()

        self.recent_action = QAction("최근 인시던트 보기")
        self.recent_action.triggered.connect(self._show_recent)
        menu.addAction(self.recent_action)

        dashboard_action = QAction("🌐 웹 대시보드 열기")
        dashboard_action.triggered.connect(self._open_dashboard)
        menu.addAction(dashboard_action)

        menu.addSeparator()

        settings_action = QAction("⚙️ 연결 설정")
        settings_action.triggered.connect(self._open_settings)
        menu.addAction(settings_action)

        reconnect_action = QAction("🔄 재연결")
        reconnect_action.triggered.connect(self._connect)
        menu.addAction(reconnect_action)

        menu.addSeparator()

        quit_action = QAction("종료")
        quit_action.triggered.connect(self._quit)
        menu.addAction(quit_action)

        self.setContextMenu(menu)

    # ── SSE 연결 ──────────────────────────────────────────
    def _connect(self):
        api_url   = self.settings.value(SETTINGS_KEY_API_URL, "")
        token     = self.settings.value(SETTINGS_KEY_TOKEN, "")
        tenant_id = self.settings.value(SETTINGS_KEY_TENANT, "default")

        if not api_url or not token:
            self._open_settings()
            return

        if self.worker:
            self.worker.stop()
            self.worker.wait(3000)

        self.worker = SSEWorker(api_url, token, tenant_id)
        self.worker.incident_received.connect(self._on_incident)
        self.worker.connection_changed.connect(self._on_connection)
        self.worker.start()

    def _on_connection(self, connected: bool):
        self.connected = connected
        if connected:
            self.setIcon(_make_icon("#10b981"))   # 초록
            self.setToolTip(f"{APP_NAME} — 연결됨")
            self.status_action.setText("🟢 연결됨")
        else:
            self.setIcon(_make_icon("#ef4444"))   # 빨강
            self.setToolTip(f"{APP_NAME} — 연결 끊김 (재연결 중...)")
            self.status_action.setText("🔴 연결 끊김 — 재연결 중")

    # ── 인시던트 수신 ──────────────────────────────────────
    def _on_incident(self, data: dict):
        severity = data.get("severity", "LOW")

        # 최근 목록 갱신
        self.recent.insert(0, data)
        self.recent = self.recent[:self.MAX_RECENT]

        # High/Critical → OS 알림
        if severity in ("HIGH", "CRITICAL"):
            rule_id = data.get("primary_rule_id", data.get("rule_id", "UNKNOWN"))
            source  = data.get("source_ip", "unknown")
            self.showMessage(
                f"🚨 [{severity}] {rule_id}",
                f"공격자 IP: {source}\n클릭해서 상세 확인",
                QSystemTrayIcon.MessageIcon.Critical if severity == "CRITICAL"
                else QSystemTrayIcon.MessageIcon.Warning,
                8000,
            )

    # ── UI 이벤트 ──────────────────────────────────────────
    def _on_activated(self, reason):
        if reason == QSystemTrayIcon.ActivationReason.Trigger:
            self._show_recent()

    def _show_recent(self):
        api_url = self.settings.value(SETTINGS_KEY_API_URL, "")
        dlg = RecentIncidentsDialog(self.recent, api_url)
        dlg.exec()

    def _open_dashboard(self):
        api_url = self.settings.value(SETTINGS_KEY_API_URL, "")
        webbrowser.open(f"{api_url}/dashboard" if api_url else "about:blank")

    def _open_settings(self):
        dlg = LoginDialog(self.settings)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self._connect()

    def _quit(self):
        if self.worker:
            self.worker.stop()
            self.worker.wait(3000)
        QApplication.quit()


# ─────────────────────────────────────────────────────────────
# 엔트리포인트
# ─────────────────────────────────────────────────────────────
def main():
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)
    app.setApplicationName(APP_NAME)
    app.setOrganizationName(ORG_NAME)

    if not QSystemTrayIcon.isSystemTrayAvailable():
        QMessageBox.critical(None, APP_NAME, "시스템 트레이를 사용할 수 없는 환경입니다.")
        sys.exit(1)

    tray = InfraRedTrayApp(app)  # noqa: F841 (keep reference)
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
