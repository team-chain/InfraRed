#!/usr/bin/env python3
"""
InfraRed 라이브 로그 생성기
auth.log 파일에 실시간으로 SSH 이벤트를 추가합니다.
에이전트가 2초마다 파일을 polling하므로 --interval 2~10 권장.

사용법:
    # 기본 (5초 간격, 표준 샘플 경로)
    python scripts/generate_logs.py

    # 커스텀 경로 + 빠른 간격
    python scripts/generate_logs.py --output /var/log/auth.log --interval 2

    # 공격 패턴만 집중 생성
    python scripts/generate_logs.py --mode attack --interval 3
"""
from __future__ import annotations

import argparse
import random
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# ──────────────────────────────────────────────
# 데이터 풀
# ──────────────────────────────────────────────

ATTACKER_IPS = [
    "185.12.34.56",
    "103.44.21.89",
    "91.200.12.5",
    "45.33.32.156",
    "194.165.16.99",
    "167.94.138.60",
    "80.82.77.33",
]

INTERNAL_IPS = [
    "10.0.1.5",
    "10.0.1.10",
    "10.0.2.20",
    "192.168.1.100",
]

VALID_USERS = ["ubuntu", "deployer", "ubuntu", "app", "ops"]
INVALID_USERS = [
    "admin", "test", "oracle", "pi", "git", "jenkins",
    "postgres", "mysql", "ftpuser", "user", "guest",
    "nagios", "hadoop", "zabbix", "tomcat",
]
ROOT_VARIANTS = ["root"]
HOSTNAME = "web-01"

_pid_counter = 10000


def _next_pid() -> int:
    global _pid_counter
    _pid_counter += 1
    return _pid_counter


def _port() -> int:
    return random.randint(40000, 65000)


def _now() -> str:
    """auth.log 형식 타임스탬프: 'May  1 14:23:01'"""
    now = datetime.now()
    # strftime %e 는 공백 패딩된 day-of-month
    return now.strftime("%b %e %H:%M:%S").replace("  ", " ")


def _line(pid: int, message: str) -> str:
    return f"{_now()} {HOSTNAME} sshd[{pid}]: {message}"


# ──────────────────────────────────────────────
# 이벤트 생성 함수
# ──────────────────────────────────────────────

def evt_invalid_user(ip: str) -> list[str]:
    """AUTH-003: Invalid user 열거"""
    user = random.choice(INVALID_USERS)
    pid = _next_pid()
    port = _port()
    return [
        _line(pid, f"Invalid user {user} from {ip} port {port}"),
        _line(pid, f"Connection closed by invalid user {user} {ip} port {port} [preauth]"),
    ]


def evt_failed_password(ip: str, username: str | None = None) -> str:
    """AUTH-001/002: Failed password"""
    user = username or random.choice(ROOT_VARIANTS + VALID_USERS)
    pid = _next_pid()
    port = _port()
    if user in INVALID_USERS:
        return _line(pid, f"Failed password for invalid user {user} from {ip} port {port} ssh2")
    return _line(pid, f"Failed password for {user} from {ip} port {port} ssh2")


def evt_accepted(ip: str, username: str | None = None) -> list[str]:
    """AUTH-004/005: Accepted password (성공)"""
    user = username or random.choice(VALID_USERS)
    pid = _next_pid()
    port = _port()
    uid = 0 if user == "root" else random.randint(1000, 1010)
    return [
        _line(pid, f"Accepted password for {user} from {ip} port {port} ssh2"),
        _line(pid + 1, f"pam_unix(sshd:session): session opened for user {user} by (uid={uid})"),
    ]


def evt_normal_login() -> list[str]:
    """정상 내부 로그인 (알람 없어야 함)"""
    ip = random.choice(INTERNAL_IPS)
    user = random.choice(VALID_USERS)
    pid = _next_pid()
    port = _port()
    uid = random.randint(1000, 1010)
    return [
        _line(pid, f"Accepted publickey for {user} from {ip} port {port} ssh2"),
        _line(pid + 1, f"pam_unix(sshd:session): session opened for user {user} by (uid={uid})"),
    ]


def evt_disconnect(ip: str) -> str:
    pid = _next_pid()
    port = _port()
    return _line(pid, f"Disconnected from {ip} port {port}")


# ──────────────────────────────────────────────
# 시나리오: Attack wave
# AUTH-001 ~ AUTH-005 순환 트리거
# ──────────────────────────────────────────────

class AttackWave:
    """하나의 공격 IP가 수행하는 단계별 공격 시뮬레이션."""

    def __init__(self, ip: str) -> None:
        self.ip = ip
        self.stage = 0  # 0=recon, 1=brute, 2=success, 3=done
        self.brute_count = 0
        self.brute_target = random.randint(5, 8)
        self.username = random.choice(ROOT_VARIANTS + VALID_USERS)

    def next_events(self) -> list[str]:
        events: list[str] = []
        if self.stage == 0:
            # AUTH-003: Invalid user 열거
            events.extend(evt_invalid_user(self.ip))
            if random.random() < 0.6:
                events.extend(evt_invalid_user(self.ip))
            self.stage = 1

        elif self.stage == 1:
            # AUTH-001 / AUTH-002: Brute force
            events.append(evt_failed_password(self.ip, self.username))
            self.brute_count += 1
            if self.brute_count >= self.brute_target:
                self.stage = 2

        elif self.stage == 2:
            # AUTH-004 / AUTH-005: Failed → Success
            events.extend(evt_accepted(self.ip, self.username))
            events.append(evt_disconnect(self.ip))
            self.stage = 3

        return events

    @property
    def done(self) -> bool:
        return self.stage == 3


# ──────────────────────────────────────────────
# 메인 루프
# ──────────────────────────────────────────────

def run(output: Path, interval: float, mode: str) -> None:
    print(f"[generate_logs] 출력 파일: {output}")
    print(f"[generate_logs] 이벤트 간격: {interval}초  모드: {mode}")
    print("[generate_logs] Ctrl+C 로 중지\n")

    output.parent.mkdir(parents=True, exist_ok=True)
    active_waves: list[AttackWave] = []
    tick = 0

    def _append(lines: list[str]) -> None:
        with output.open("a", encoding="utf-8") as f:
            for line in lines:
                f.write(line + "\n")
                print(line)

    while True:
        tick += 1
        lines_to_write: list[str] = []

        # ── 새 공격 Wave 시작 (확률적) ──────────────────
        if mode in ("attack", "mixed"):
            if not active_waves or (len(active_waves) < 3 and random.random() < 0.3):
                ip = random.choice(ATTACKER_IPS)
                active_waves.append(AttackWave(ip))
                print(f"[generate_logs] 새 공격 Wave 시작: {ip}")

        # ── 진행 중인 Wave 이벤트 생성 ──────────────────
        for wave in active_waves:
            if not wave.done:
                lines_to_write.extend(wave.next_events())

        # 완료된 Wave 제거
        active_waves = [w for w in active_waves if not w.done]

        # ── 정상 로그인 (mixed / normal 모드) ───────────
        if mode in ("normal", "mixed"):
            if random.random() < 0.25:
                lines_to_write.extend(evt_normal_login())

        # ── 아무것도 없으면 disconnect 라인 하나 ─────────
        if not lines_to_write:
            ip = random.choice(INTERNAL_IPS)
            lines_to_write.append(evt_disconnect(ip))

        _append(lines_to_write)
        time.sleep(interval)


# ──────────────────────────────────────────────
# Entrypoint
# ──────────────────────────────────────────────

def _handle_sigint(sig, frame):
    print("\n[generate_logs] 중지됨")
    sys.exit(0)


def main() -> None:
    signal.signal(signal.SIGINT, _handle_sigint)
    signal.signal(signal.SIGTERM, _handle_sigint)

    parser = argparse.ArgumentParser(description="InfraRed 라이브 로그 생성기")
    parser.add_argument(
        "--output",
        default="infra/sample-logs/auth.log",
        help="출력할 auth.log 경로 (기본: infra/sample-logs/auth.log)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=5.0,
        help="이벤트 생성 간격(초) (기본: 5)",
    )
    parser.add_argument(
        "--mode",
        choices=["attack", "normal", "mixed"],
        default="mixed",
        help="생성 모드: attack(공격만), normal(정상만), mixed(혼합, 기본)",
    )
    args = parser.parse_args()
    run(Path(args.output), args.interval, args.mode)


if __name__ == "__main__":
    main()
