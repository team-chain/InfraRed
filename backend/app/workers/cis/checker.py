"""CIS Benchmark Level 1 점검기.

Linux 서버에서 35개 항목을 점검하고 CISReport를 반환한다.
각 항목은 OS 파일/명령어를 직접 읽어 체크한다.
실행 환경이 컨테이너이거나 권한이 없으면 not_applicable로 처리한다.
"""
from __future__ import annotations

import grp
import logging
import os
import pwd
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

log = logging.getLogger(__name__)


@dataclass
class CISItem:
    item_id: str
    title: str
    status: str           # "pass" | "fail" | "not_applicable" | "error"
    detail: str
    level: int = 1        # CIS Level (1 or 2)


@dataclass
class CISReport:
    tenant_id: str
    generated_at: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))
    items: list[CISItem] = field(default_factory=list)
    pass_count: int = 0
    fail_count: int = 0
    na_count: int = 0
    score_pct: float = 0.0

    def compute_score(self) -> None:
        self.pass_count = sum(1 for i in self.items if i.status == "pass")
        self.fail_count = sum(1 for i in self.items if i.status == "fail")
        self.na_count = sum(1 for i in self.items if i.status == "not_applicable")
        checked = self.pass_count + self.fail_count
        self.score_pct = round((self.pass_count / checked * 100) if checked > 0 else 0.0, 1)

    def to_dict(self) -> dict:
        return {
            "tenant_id": self.tenant_id,
            "generated_at": self.generated_at.isoformat(),
            "score_pct": self.score_pct,
            "pass_count": self.pass_count,
            "fail_count": self.fail_count,
            "na_count": self.na_count,
            "items": [
                {
                    "item_id": i.item_id,
                    "title": i.title,
                    "status": i.status,
                    "detail": i.detail,
                    "level": i.level,
                }
                for i in self.items
            ],
        }


# ------------------------------------------------------------------ #
# 헬퍼
# ------------------------------------------------------------------ #

def _read_file(path: str) -> Optional[str]:
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return None


def _run(cmd: list[str], timeout: int = 5) -> Optional[str]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None


def _grep_config(path: str, pattern: str) -> list[str]:
    """설정 파일에서 패턴에 매칭되는 비-주석 줄 목록을 반환한다."""
    content = _read_file(path)
    if content is None:
        return []
    matches = []
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            continue
        if re.search(pattern, stripped, re.IGNORECASE):
            matches.append(stripped)
    return matches


# ------------------------------------------------------------------ #
# CISBenchmarkChecker
# ------------------------------------------------------------------ #

class CISBenchmarkChecker:
    """CIS Benchmark Level 1 (35 항목) 점검기.

    v7 설계서의 scan() 메서드에서 호출하는 그룹 메서드:
      _check_network_config()    — 섹션 3 네트워크 설정 항목 집계
      _check_user_accounts_cis() — 섹션 5~6 사용자/계정 보안 항목 집계
    """

    def check_all(self, tenant_id: str) -> CISReport:
        """모든 CIS 항목을 점검하고 CISReport를 반환한다."""
        report = CISReport(tenant_id=tenant_id)
        report.items = [
            self._check_1_1_1(),
            self._check_1_1_2(),
            self._check_1_1_3(),
            self._check_1_1_4(),
            self._check_1_3_1(),
            self._check_2_1_1(),
            self._check_2_2_1(),
            self._check_2_2_2(),
            *self._check_network_config(),
            self._check_4_1_1(),
            self._check_4_1_2(),
            *self._check_user_accounts_cis(),
        ]
        report.compute_score()
        return report

    # ------------------------------------------------------------------ #
    # v7: 그룹 메서드 — scan() 호환
    # ------------------------------------------------------------------ #

    def _check_network_config(self) -> list[CISItem]:
        """섹션 3 — 네트워크 설정 항목 전체를 반환한다.

        v7 설계서의 scan() 메서드에서 호출된다.
        항목: 3.1.1, 3.1.2, 3.2.1, 3.3.1, 3.4.1
        """
        return [
            self._check_3_1_1(),
            self._check_3_1_2(),
            self._check_3_2_1(),
            self._check_3_3_1(),
            self._check_3_4_1(),
        ]

    def _check_user_accounts_cis(self) -> list[CISItem]:
        """섹션 5~6 — 사용자 계정 및 접근 보안 항목 전체를 반환한다.

        v7 설계서의 scan() 메서드에서 호출된다.
        항목: 5.1.1, 5.1.2, 5.2.2, 5.2.4~5.2.9, 5.3.1, 5.4.1, 5.4.2,
              6.1.1~6.1.3, 6.2.1~6.2.5
        """
        return [
            self._check_5_1_1(),
            self._check_5_1_2(),
            self._check_5_2_2(),
            self._check_5_2_4(),
            self._check_5_2_5(),
            self._check_5_2_6(),
            self._check_5_2_7(),
            self._check_5_2_8(),
            self._check_5_2_9(),
            self._check_5_3_1(),
            self._check_5_4_1(),
            self._check_5_4_2(),
            self._check_6_1_1(),
            self._check_6_1_2(),
            self._check_6_1_3(),
            self._check_6_2_1(),
            self._check_6_2_2(),
            self._check_6_2_3(),
            self._check_6_2_4(),
            self._check_6_2_5(),
        ]

    # ------------------------------------------------------------------ #
    # 1.x Filesystem Configuration
    # ------------------------------------------------------------------ #

    def _check_1_1_1(self) -> CISItem:
        """1.1.1 /tmp 파티션 분리 여부."""
        mounts = _read_file("/proc/mounts") or ""
        for line in mounts.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[1] == "/tmp":
                return CISItem("1.1.1", "/tmp separate partition", "pass",
                               f"Mounted as: {parts[0]}")
        return CISItem("1.1.1", "/tmp separate partition", "fail",
                       "/tmp is not on a separate partition")

    def _check_1_1_2(self) -> CISItem:
        """/tmp nodev 마운트 옵션 확인."""
        mounts = _read_file("/proc/mounts") or ""
        for line in mounts.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[1] == "/tmp":
                opts = parts[3]
                if "nodev" in opts:
                    return CISItem("1.1.2", "/tmp nodev option", "pass", f"options: {opts}")
                return CISItem("1.1.2", "/tmp nodev option", "fail",
                               f"/tmp missing nodev; options: {opts}")
        return CISItem("1.1.2", "/tmp nodev option", "not_applicable",
                       "/tmp not on separate partition")

    def _check_1_1_3(self) -> CISItem:
        """/tmp nosuid 마운트 옵션 확인."""
        mounts = _read_file("/proc/mounts") or ""
        for line in mounts.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[1] == "/tmp":
                opts = parts[3]
                if "nosuid" in opts:
                    return CISItem("1.1.3", "/tmp nosuid option", "pass", f"options: {opts}")
                return CISItem("1.1.3", "/tmp nosuid option", "fail",
                               f"/tmp missing nosuid; options: {opts}")
        return CISItem("1.1.3", "/tmp nosuid option", "not_applicable",
                       "/tmp not on separate partition")

    def _check_1_1_4(self) -> CISItem:
        """/tmp noexec 마운트 옵션 확인."""
        mounts = _read_file("/proc/mounts") or ""
        for line in mounts.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[1] == "/tmp":
                opts = parts[3]
                if "noexec" in opts:
                    return CISItem("1.1.4", "/tmp noexec option", "pass", f"options: {opts}")
                return CISItem("1.1.4", "/tmp noexec option", "fail",
                               f"/tmp missing noexec; options: {opts}")
        return CISItem("1.1.4", "/tmp noexec option", "not_applicable",
                       "/tmp not on separate partition")

    def _check_1_3_1(self) -> CISItem:
        """1.3.1 AIDE 파일 무결성 도구 설치 여부."""
        aide = _run(["which", "aide"])
        if aide and aide.strip():
            return CISItem("1.3.1", "AIDE installed", "pass", f"Path: {aide.strip()}")
        return CISItem("1.3.1", "AIDE installed", "fail", "aide not found in PATH")

    # ------------------------------------------------------------------ #
    # 2.x Services
    # ------------------------------------------------------------------ #

    def _check_2_1_1(self) -> CISItem:
        """2.1.1 xinetd 비설치 확인."""
        out = _run(["systemctl", "is-enabled", "xinetd"])
        if out is None:
            return CISItem("2.1.1", "xinetd not installed", "not_applicable",
                           "systemctl not available")
        if "enabled" in (out or ""):
            return CISItem("2.1.1", "xinetd not installed", "fail", "xinetd is enabled")
        return CISItem("2.1.1", "xinetd not installed", "pass", "xinetd not enabled")

    def _check_2_2_1(self) -> CISItem:
        """2.2.1 X Window System 비설치 확인."""
        out = _run(["dpkg", "-l", "xserver-xorg*"])
        if out and "ii" in out:
            return CISItem("2.2.1", "X Window System not installed", "fail",
                           "X11 packages found")
        out2 = _run(["rpm", "-q", "xorg-x11-server-Xorg"])
        if out2 and "not installed" not in out2:
            return CISItem("2.2.1", "X Window System not installed", "fail",
                           "X11 packages found (rpm)")
        return CISItem("2.2.1", "X Window System not installed", "pass",
                       "X11 server not detected")

    def _check_2_2_2(self) -> CISItem:
        """2.2.2 Avahi Server 비활성화 확인."""
        out = _run(["systemctl", "is-enabled", "avahi-daemon"])
        if out and "enabled" in out:
            return CISItem("2.2.2", "Avahi Server disabled", "fail", "avahi-daemon is enabled")
        return CISItem("2.2.2", "Avahi Server disabled", "pass",
                       "avahi-daemon not enabled or not installed")

    # ------------------------------------------------------------------ #
    # 3.x Network Configuration
    # ------------------------------------------------------------------ #

    def _check_3_1_1(self) -> CISItem:
        """3.1.1 IP Forwarding 비활성화."""
        val = _read_file("/proc/sys/net/ipv4/ip_forward")
        if val is None:
            return CISItem("3.1.1", "IP forwarding disabled", "not_applicable",
                           "Cannot read /proc/sys/net/ipv4/ip_forward")
        if val.strip() == "0":
            return CISItem("3.1.1", "IP forwarding disabled", "pass",
                           "ip_forward = 0")
        return CISItem("3.1.1", "IP forwarding disabled", "fail",
                       f"ip_forward = {val.strip()} (expected 0)")

    def _check_3_1_2(self) -> CISItem:
        """3.1.2 패킷 리다이렉트 전송 비활성화."""
        val = _read_file("/proc/sys/net/ipv4/conf/all/send_redirects")
        if val is None:
            return CISItem("3.1.2", "Packet redirect sending disabled", "not_applicable",
                           "Cannot read send_redirects")
        if val.strip() == "0":
            return CISItem("3.1.2", "Packet redirect sending disabled", "pass",
                           "send_redirects = 0")
        return CISItem("3.1.2", "Packet redirect sending disabled", "fail",
                       f"send_redirects = {val.strip()}")

    def _check_3_2_1(self) -> CISItem:
        """3.2.1 소스 라우팅 패킷 수락 거부."""
        val = _read_file("/proc/sys/net/ipv4/conf/all/accept_source_route")
        if val is None:
            return CISItem("3.2.1", "Source routed packets not accepted", "not_applicable",
                           "Cannot read accept_source_route")
        if val.strip() == "0":
            return CISItem("3.2.1", "Source routed packets not accepted", "pass",
                           "accept_source_route = 0")
        return CISItem("3.2.1", "Source routed packets not accepted", "fail",
                       f"accept_source_route = {val.strip()}")

    def _check_3_3_1(self) -> CISItem:
        """3.3.1 IPv6 라우터 광고 수락 거부."""
        val = _read_file("/proc/sys/net/ipv6/conf/all/accept_ra")
        if val is None:
            return CISItem("3.3.1", "IPv6 router advertisements not accepted",
                           "not_applicable", "IPv6 not configured")
        if val.strip() == "0":
            return CISItem("3.3.1", "IPv6 router advertisements not accepted", "pass",
                           "accept_ra = 0")
        return CISItem("3.3.1", "IPv6 router advertisements not accepted", "fail",
                       f"accept_ra = {val.strip()}")

    def _check_3_4_1(self) -> CISItem:
        """3.4.1 TCP Wrappers 설치 여부."""
        out = _run(["which", "tcpd"])
        if out and out.strip():
            return CISItem("3.4.1", "TCP Wrappers installed", "pass", out.strip())
        return CISItem("3.4.1", "TCP Wrappers installed", "fail", "tcpd not found in PATH")

    # ------------------------------------------------------------------ #
    # 4.x Logging and Auditing
    # ------------------------------------------------------------------ #

    def _check_4_1_1(self) -> CISItem:
        """4.1.1 auditd 설치 및 활성화 여부."""
        out = _run(["systemctl", "is-active", "auditd"])
        if out and "active" in out:
            return CISItem("4.1.1", "auditd active", "pass", "auditd is active")
        return CISItem("4.1.1", "auditd active", "fail",
                       "auditd is not active or not installed")

    def _check_4_1_2(self) -> CISItem:
        """4.1.2 rsyslog 설치 및 활성화 여부."""
        out = _run(["systemctl", "is-active", "rsyslog"])
        if out and "active" in out:
            return CISItem("4.1.2", "rsyslog active", "pass", "rsyslog is active")
        out2 = _run(["systemctl", "is-active", "syslog"])
        if out2 and "active" in out2:
            return CISItem("4.1.2", "rsyslog active", "pass", "syslog is active")
        return CISItem("4.1.2", "rsyslog active", "fail",
                       "rsyslog/syslog is not active or not installed")

    # ------------------------------------------------------------------ #
    # 5.x Access, Authentication and Authorization
    # ------------------------------------------------------------------ #

    def _check_5_1_1(self) -> CISItem:
        """5.1.1 cron 데몬 활성화 여부."""
        for svc in ("cron", "crond"):
            out = _run(["systemctl", "is-active", svc])
            if out and "active" in out:
                return CISItem("5.1.1", "cron daemon active", "pass", f"{svc} is active")
        return CISItem("5.1.1", "cron daemon active", "fail",
                       "cron/crond is not active or not installed")

    def _check_5_1_2(self) -> CISItem:
        """5.1.2 /etc/crontab 권한 (root만 읽기/쓰기)."""
        path = "/etc/crontab"
        try:
            st = os.stat(path)
            mode = oct(st.st_mode)
            if st.st_uid == 0 and (st.st_mode & 0o022) == 0:
                return CISItem("5.1.2", "/etc/crontab permissions", "pass",
                               f"owner=root, mode={mode}")
            return CISItem("5.1.2", "/etc/crontab permissions", "fail",
                           f"owner uid={st.st_uid}, mode={mode}")
        except OSError:
            return CISItem("5.1.2", "/etc/crontab permissions", "not_applicable",
                           "/etc/crontab not found")

    def _check_5_2_2(self) -> CISItem:
        """5.2.2 SSH Protocol 2 사용 확인."""
        matches = _grep_config("/etc/ssh/sshd_config", r"^\s*Protocol\s+")
        if not matches:
            # 최신 OpenSSH는 Protocol 지시어 없음 = 기본 2
            return CISItem("5.2.2", "SSH Protocol 2", "pass",
                           "Protocol directive absent (OpenSSH default is 2)")
        for m in matches:
            if re.search(r"Protocol\s+2", m):
                return CISItem("5.2.2", "SSH Protocol 2", "pass", m)
        return CISItem("5.2.2", "SSH Protocol 2", "fail",
                       f"Protocol not set to 2: {matches}")

    def _check_5_2_4(self) -> CISItem:
        """5.2.4 SSH PermitRootLogin no 확인."""
        matches = _grep_config("/etc/ssh/sshd_config", r"^\s*PermitRootLogin\s+")
        for m in matches:
            if re.search(r"PermitRootLogin\s+no", m, re.IGNORECASE):
                return CISItem("5.2.4", "SSH PermitRootLogin no", "pass", m)
        if matches:
            return CISItem("5.2.4", "SSH PermitRootLogin no", "fail",
                           f"PermitRootLogin value: {matches}")
        return CISItem("5.2.4", "SSH PermitRootLogin no", "fail",
                       "PermitRootLogin not explicitly set to 'no'")

    def _check_5_2_5(self) -> CISItem:
        """5.2.5 SSH MaxAuthTries 4 이하 확인."""
        matches = _grep_config("/etc/ssh/sshd_config", r"^\s*MaxAuthTries\s+")
        for m in matches:
            found = re.search(r"MaxAuthTries\s+(\d+)", m, re.IGNORECASE)
            if found:
                val = int(found.group(1))
                status = "pass" if val <= 4 else "fail"
                return CISItem("5.2.5", "SSH MaxAuthTries <= 4", status,
                               f"MaxAuthTries = {val}")
        return CISItem("5.2.5", "SSH MaxAuthTries <= 4", "fail",
                       "MaxAuthTries not configured")

    def _check_5_2_6(self) -> CISItem:
        """5.2.6 SSH IgnoreRhosts yes 확인."""
        matches = _grep_config("/etc/ssh/sshd_config", r"^\s*IgnoreRhosts\s+")
        for m in matches:
            if re.search(r"IgnoreRhosts\s+yes", m, re.IGNORECASE):
                return CISItem("5.2.6", "SSH IgnoreRhosts yes", "pass", m)
        return CISItem("5.2.6", "SSH IgnoreRhosts yes", "fail",
                       "IgnoreRhosts not set to yes")

    def _check_5_2_7(self) -> CISItem:
        """5.2.7 SSH HostbasedAuthentication no 확인."""
        matches = _grep_config("/etc/ssh/sshd_config", r"^\s*HostbasedAuthentication\s+")
        for m in matches:
            if re.search(r"HostbasedAuthentication\s+no", m, re.IGNORECASE):
                return CISItem("5.2.7", "SSH HostbasedAuthentication no", "pass", m)
        return CISItem("5.2.7", "SSH HostbasedAuthentication no", "fail",
                       "HostbasedAuthentication not set to no")

    def _check_5_2_8(self) -> CISItem:
        """5.2.8 SSH X11Forwarding no 확인."""
        matches = _grep_config("/etc/ssh/sshd_config", r"^\s*X11Forwarding\s+")
        for m in matches:
            if re.search(r"X11Forwarding\s+no", m, re.IGNORECASE):
                return CISItem("5.2.8", "SSH X11Forwarding no", "pass", m)
        return CISItem("5.2.8", "SSH X11Forwarding no", "fail",
                       "X11Forwarding not set to no")

    def _check_5_2_9(self) -> CISItem:
        """5.2.9 SSH PermitEmptyPasswords no 확인."""
        matches = _grep_config("/etc/ssh/sshd_config", r"^\s*PermitEmptyPasswords\s+")
        for m in matches:
            if re.search(r"PermitEmptyPasswords\s+no", m, re.IGNORECASE):
                return CISItem("5.2.9", "SSH PermitEmptyPasswords no", "pass", m)
        return CISItem("5.2.9", "SSH PermitEmptyPasswords no", "fail",
                       "PermitEmptyPasswords not explicitly set to no")

    def _check_5_3_1(self) -> CISItem:
        """5.3.1 패스워드 복잡도 요구사항 (pwquality.conf)."""
        content = _read_file("/etc/security/pwquality.conf")
        if content is None:
            return CISItem("5.3.1", "Password complexity requirements", "not_applicable",
                           "/etc/security/pwquality.conf not found")
        has_minlen = bool(re.search(r"^\s*minlen\s*=\s*\d+", content, re.MULTILINE))
        has_dcredit = bool(re.search(r"^\s*dcredit\s*=\s*-?\d+", content, re.MULTILINE))
        has_ucredit = bool(re.search(r"^\s*ucredit\s*=\s*-?\d+", content, re.MULTILINE))
        if has_minlen and has_dcredit and has_ucredit:
            return CISItem("5.3.1", "Password complexity requirements", "pass",
                           "minlen, dcredit, ucredit configured")
        missing = []
        if not has_minlen:
            missing.append("minlen")
        if not has_dcredit:
            missing.append("dcredit")
        if not has_ucredit:
            missing.append("ucredit")
        return CISItem("5.3.1", "Password complexity requirements", "fail",
                       f"Missing: {', '.join(missing)}")

    def _check_5_4_1(self) -> CISItem:
        """5.4.1 패스워드 만료 기간 (최대 365일)."""
        content = _read_file("/etc/login.defs")
        if content is None:
            return CISItem("5.4.1", "Password expiration <= 365 days", "not_applicable",
                           "/etc/login.defs not found")
        for line in content.splitlines():
            m = re.match(r"^\s*PASS_MAX_DAYS\s+(\d+)", line)
            if m:
                days = int(m.group(1))
                if days <= 365:
                    return CISItem("5.4.1", "Password expiration <= 365 days", "pass",
                                   f"PASS_MAX_DAYS = {days}")
                return CISItem("5.4.1", "Password expiration <= 365 days", "fail",
                               f"PASS_MAX_DAYS = {days} (> 365)")
        return CISItem("5.4.1", "Password expiration <= 365 days", "fail",
                       "PASS_MAX_DAYS not configured in /etc/login.defs")

    def _check_5_4_2(self) -> CISItem:
        """5.4.2 패스워드 최소 사용 기간 (1일 이상)."""
        content = _read_file("/etc/login.defs")
        if content is None:
            return CISItem("5.4.2", "Password minimum age >= 1 day", "not_applicable",
                           "/etc/login.defs not found")
        for line in content.splitlines():
            m = re.match(r"^\s*PASS_MIN_DAYS\s+(\d+)", line)
            if m:
                days = int(m.group(1))
                if days >= 1:
                    return CISItem("5.4.2", "Password minimum age >= 1 day", "pass",
                                   f"PASS_MIN_DAYS = {days}")
                return CISItem("5.4.2", "Password minimum age >= 1 day", "fail",
                               f"PASS_MIN_DAYS = {days} (< 1)")
        return CISItem("5.4.2", "Password minimum age >= 1 day", "fail",
                       "PASS_MIN_DAYS not configured")

    # ------------------------------------------------------------------ #
    # 6.x System Maintenance
    # ------------------------------------------------------------------ #

    def _check_6_1_1(self) -> CISItem:
        """6.1.1 /etc/passwd 권한 (644)."""
        path = "/etc/passwd"
        try:
            st = os.stat(path)
            mode = st.st_mode & 0o777
            if mode == 0o644:
                return CISItem("6.1.1", "/etc/passwd permissions 644", "pass",
                               f"mode={oct(mode)}")
            return CISItem("6.1.1", "/etc/passwd permissions 644", "fail",
                           f"mode={oct(mode)} (expected 0o644)")
        except OSError:
            return CISItem("6.1.1", "/etc/passwd permissions 644", "not_applicable",
                           "/etc/passwd not accessible")

    def _check_6_1_2(self) -> CISItem:
        """6.1.2 /etc/shadow 권한 (000 또는 640)."""
        path = "/etc/shadow"
        try:
            st = os.stat(path)
            mode = st.st_mode & 0o777
            if mode in (0o000, 0o640):
                return CISItem("6.1.2", "/etc/shadow permissions 000/640", "pass",
                               f"mode={oct(mode)}")
            return CISItem("6.1.2", "/etc/shadow permissions 000/640", "fail",
                           f"mode={oct(mode)}")
        except PermissionError:
            return CISItem("6.1.2", "/etc/shadow permissions 000/640", "pass",
                           "Permission denied reading shadow (expected for non-root)")
        except OSError:
            return CISItem("6.1.2", "/etc/shadow permissions 000/640", "not_applicable",
                           "/etc/shadow not found")

    def _check_6_1_3(self) -> CISItem:
        """6.1.3 /etc/group 권한 (644)."""
        path = "/etc/group"
        try:
            st = os.stat(path)
            mode = st.st_mode & 0o777
            if mode == 0o644:
                return CISItem("6.1.3", "/etc/group permissions 644", "pass",
                               f"mode={oct(mode)}")
            return CISItem("6.1.3", "/etc/group permissions 644", "fail",
                           f"mode={oct(mode)} (expected 0o644)")
        except OSError:
            return CISItem("6.1.3", "/etc/group permissions 644", "not_applicable",
                           "/etc/group not accessible")

    def _check_6_2_1(self) -> CISItem:
        """6.2.1 빈 패스워드 계정 없음."""
        try:
            out = _run(["getent", "shadow"])
            if out is None:
                raise RuntimeError("getent shadow failed")
            empty_pw_users = []
            for line in out.splitlines():
                parts = line.split(":")
                if len(parts) >= 2 and parts[1] in ("", "!!", "*"):
                    continue  # locked or no password (normal)
                if len(parts) >= 2 and parts[1] == "":
                    empty_pw_users.append(parts[0])
            if empty_pw_users:
                return CISItem("6.2.1", "No empty password accounts", "fail",
                               f"Empty passwords: {empty_pw_users}")
            return CISItem("6.2.1", "No empty password accounts", "pass",
                           "No accounts with empty passwords found")
        except Exception as exc:
            return CISItem("6.2.1", "No empty password accounts", "not_applicable",
                           f"Cannot check: {exc}")

    def _check_6_2_2(self) -> CISItem:
        """6.2.2 /etc/passwd에 레거시 '+' 엔트리 없음."""
        content = _read_file("/etc/passwd") or ""
        for line in content.splitlines():
            if line.startswith("+"):
                return CISItem("6.2.2", "No legacy '+' entries in /etc/passwd", "fail",
                               f"Found: {line}")
        return CISItem("6.2.2", "No legacy '+' entries in /etc/passwd", "pass",
                       "No legacy '+' entries found")

    def _check_6_2_3(self) -> CISItem:
        """6.2.3 /etc/shadow에 레거시 '+' 엔트리 없음."""
        try:
            content = _read_file("/etc/shadow") or ""
            for line in content.splitlines():
                if line.startswith("+"):
                    return CISItem("6.2.3", "No legacy '+' entries in /etc/shadow", "fail",
                                   f"Found: {line}")
            return CISItem("6.2.3", "No legacy '+' entries in /etc/shadow", "pass",
                           "No legacy '+' entries found")
        except Exception:
            return CISItem("6.2.3", "No legacy '+' entries in /etc/shadow", "not_applicable",
                           "Cannot read /etc/shadow")

    def _check_6_2_4(self) -> CISItem:
        """6.2.4 root 계정 UID=0 (오직 root만)."""
        content = _read_file("/etc/passwd") or ""
        uid0_users = []
        for line in content.splitlines():
            parts = line.split(":")
            if len(parts) >= 4 and parts[2] == "0":
                uid0_users.append(parts[0])
        if uid0_users == ["root"]:
            return CISItem("6.2.4", "Only root has UID 0", "pass", "UID=0: root only")
        return CISItem("6.2.4", "Only root has UID 0", "fail",
                       f"UID=0 accounts: {uid0_users}")

    def _check_6_2_5(self) -> CISItem:
        """6.2.5 root PATH에 빈 디렉터리 또는 '.' 없음."""
        path_env = os.environ.get("PATH", "")
        dirs = path_env.split(":")
        bad = [d for d in dirs if d in ("", ".")]
        if bad:
            return CISItem("6.2.5", "root PATH integrity", "fail",
                           f"Insecure PATH components: {bad}")
        return CISItem("6.2.5", "root PATH integrity", "pass",
                       f"PATH looks clean: {path_env[:80]}")
