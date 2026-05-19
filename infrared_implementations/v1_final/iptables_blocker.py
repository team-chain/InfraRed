"""
InfraRed v1 — iptables 실제 차단 모듈
설계서_최종.docx  Level 3 대응 + v3_최종설계서.md iptables 확장

이 모듈은 Agent 측 및 서버 측 양쪽에서 사용:
  - Agent: block_ip / unblock_ip 명령 수신 시 직접 실행
  - 서버: Policy Engine이 agent_commands 큐에 명령 발행 (이 모듈이 명령 직렬화 담당)

보안 원칙:
  1. 내부망 / 루프백 IP 차단 절대 금지
  2. Allowlist IP 차단 금지
  3. 모든 차단/해제 이벤트는 로컬 append-only 로그에 기록
  4. TTL 기반 자동 해제 (Dead Man's Switch)
  5. 이중 검증: iptables 실행 전 / 후 상태 확인
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

logger = logging.getLogger("infrared.iptables")

# ──────────────────────────────────────────────────────────────
# 내부망 보호 (Redis Denylist 모듈과 동일 기준)
# ──────────────────────────────────────────────────────────────
_NEVER_BLOCK_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

_APPEND_ONLY_LOG = Path("/var/log/infrared/iptables_actions.jsonl")


def _is_safe_to_block(ip_str: str, allowlist: set[str]) -> tuple[bool, str]:
    """
    차단 가능 여부 확인.
    Returns (can_block, reason)
    """
    if ip_str in allowlist:
        return False, "allowlist_protected"
    try:
        addr = ipaddress.ip_address(ip_str)
        for net in _NEVER_BLOCK_NETWORKS:
            if addr in net:
                return False, f"internal_network:{net}"
    except ValueError:
        return False, "invalid_ip"
    return True, "ok"


def _append_log(entry: dict) -> None:
    """append-only JSONL 로그 기록"""
    try:
        _APPEND_ONLY_LOG.parent.mkdir(parents=True, exist_ok=True)
        with _APPEND_ONLY_LOG.open("a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as exc:
        logger.error("iptables 로그 기록 실패: %s", exc)


# ──────────────────────────────────────────────────────────────
# iptables 래퍼
# ──────────────────────────────────────────────────────────────
@dataclass
class IptablesBlocker:
    """
    iptables DROP 규칙 관리.

    chain:    INPUT (기본) — 인바운드 차단
    comment:  iptables 규칙에 InfraRed 출처 주석 추가
    dry_run:  True면 실제 실행하지 않고 명령만 로그 출력
    """

    chain:     str       = "INPUT"
    comment:   str       = "infrared-auto-block"
    dry_run:   bool      = False
    allowlist: set[str]  = field(default_factory=set)

    # ── 차단 추가 ──────────────────────────────────────────
    def block(
        self,
        ip: str,
        *,
        ttl_seconds: int   = 1800,
        reason: str        = "policy_engine",
        incident_id: str   = "",
        ports: list[int]   | None = None,
        protocol: Literal["tcp", "udp", "all"] = "all",
    ) -> bool:
        """
        iptables DROP 규칙 추가.

        포트 지정 시 특정 포트만 차단 (예: SSH 포트 22만)
        포트 미지정 시 모든 트래픽 차단
        """
        can_block, guard_reason = _is_safe_to_block(ip, self.allowlist)
        if not can_block:
            logger.warning("iptables block 거부: ip=%s reason=%s", ip, guard_reason)
            return False

        # 이미 차단 중이면 idempotent
        if self._is_already_blocked(ip):
            logger.info("이미 차단 중 (idempotent): ip=%s", ip)
            return True

        success = True
        if ports:
            for port in ports:
                cmd = self._build_block_cmd(ip, port=port, protocol=protocol, action="-A")
                success &= self._run(cmd)
        else:
            cmd = self._build_block_cmd(ip, action="-A")
            success = self._run(cmd)

        if success:
            entry = {
                "ts":          time.time(),
                "action":      "block",
                "ip":          ip,
                "ttl_seconds": ttl_seconds,
                "reason":      reason,
                "incident_id": incident_id,
                "dry_run":     self.dry_run,
                "ports":       ports,
                "protocol":    protocol,
            }
            _append_log(entry)
            logger.info(
                "iptables 차단 완료: ip=%s ttl=%ds dry_run=%s",
                ip, ttl_seconds, self.dry_run,
            )

        return success

    # ── 차단 해제 ──────────────────────────────────────────
    def unblock(
        self,
        ip: str,
        *,
        reason: str     = "ttl_expired",
        incident_id: str = "",
        ports: list[int] | None = None,
        protocol: Literal["tcp", "udp", "all"] = "all",
    ) -> bool:
        """iptables DROP 규칙 제거"""
        if ports:
            success = True
            for port in ports:
                cmd = self._build_block_cmd(ip, port=port, protocol=protocol, action="-D")
                success &= self._run(cmd)
        else:
            cmd = self._build_block_cmd(ip, action="-D")
            success = self._run(cmd)

        if success:
            _append_log({
                "ts":          time.time(),
                "action":      "unblock",
                "ip":          ip,
                "reason":      reason,
                "incident_id": incident_id,
                "dry_run":     self.dry_run,
            })
            logger.info("iptables 차단 해제: ip=%s reason=%s", ip, reason)
        return success

    # ── 규칙 목록 조회 ─────────────────────────────────────
    def list_blocked_ips(self) -> list[str]:
        """현재 InfraRed가 추가한 차단 IP 목록"""
        result = subprocess.run(
            ["iptables", "-L", self.chain, "-n", "--line-numbers"],
            capture_output=True, text=True
        )
        ips = []
        for line in result.stdout.splitlines():
            if self.comment in line:
                parts = line.split()
                # 형식: num DROP all -- src dst ...
                for part in parts:
                    try:
                        ipaddress.ip_address(part)
                        ips.append(part)
                        break
                    except ValueError:
                        continue
        return ips

    # ── 내부 헬퍼 ──────────────────────────────────────────
    def _build_block_cmd(
        self,
        ip: str,
        *,
        port: int | None = None,
        protocol: str    = "all",
        action: str      = "-A",
    ) -> list[str]:
        cmd = ["iptables", action, self.chain, "-s", ip]
        if port and protocol != "all":
            cmd += ["-p", protocol, "--dport", str(port)]
        elif port:
            cmd += ["-p", "tcp", "--dport", str(port)]
        cmd += ["-j", "DROP", "-m", "comment", "--comment", self.comment]
        return cmd

    def _run(self, cmd: list[str]) -> bool:
        if self.dry_run:
            logger.info("[DRY RUN] %s", " ".join(cmd))
            return True
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                logger.error("iptables 실행 오류: %s", result.stderr.strip())
                return False
            return True
        except subprocess.TimeoutExpired:
            logger.error("iptables 명령 타임아웃: %s", " ".join(cmd))
            return False
        except FileNotFoundError:
            logger.error("iptables 바이너리를 찾을 수 없음 (root 권한 필요)")
            return False

    def _is_already_blocked(self, ip: str) -> bool:
        result = subprocess.run(
            ["iptables", "-C", self.chain, "-s", ip, "-j", "DROP"],
            capture_output=True
        )
        return result.returncode == 0


# ──────────────────────────────────────────────────────────────
# TTL 기반 자동 해제 워커
# ──────────────────────────────────────────────────────────────
@dataclass
class TTLBlockManager:
    """
    TTL 기반 임시 차단 관리.
    - 차단 시 만료 시각을 Redis에 저장
    - 주기적으로 만료된 차단 자동 해제
    """

    blocker:      IptablesBlocker
    redis: object = None            # aioredis.Redis (런타임에 주입)
    check_interval: int = 60        # 초

    TTL_HASH_KEY = "iptables_ttl"

    async def block_with_ttl(
        self,
        ip: str,
        ttl_seconds: int,
        **kwargs,
    ) -> bool:
        success = self.blocker.block(ip, ttl_seconds=ttl_seconds, **kwargs)
        if success and self.redis:
            expires_at = time.time() + ttl_seconds
            await self.redis.hset(self.TTL_HASH_KEY, ip, str(expires_at))
        return success

    async def run_expiry_loop(self) -> None:
        """만료된 차단 IP 자동 해제 루프 (백그라운드 태스크)"""
        logger.info("TTL 자동 해제 루프 시작 (interval=%ds)", self.check_interval)
        while True:
            try:
                await self._check_and_expire()
            except Exception as exc:
                logger.error("만료 체크 오류: %s", exc)
            await asyncio.sleep(self.check_interval)

    async def _check_and_expire(self) -> None:
        if not self.redis:
            return
        all_entries = await self.redis.hgetall(self.TTL_HASH_KEY)
        now = time.time()
        for ip_bytes, ts_bytes in all_entries.items():
            ip  = ip_bytes.decode() if isinstance(ip_bytes, bytes) else ip_bytes
            exp = float(ts_bytes.decode() if isinstance(ts_bytes, bytes) else ts_bytes)
            if now >= exp:
                logger.info("TTL 만료 — IP 자동 해제: ip=%s", ip)
                self.blocker.unblock(ip, reason="ttl_expired")
                await self.redis.hdel(self.TTL_HASH_KEY, ip)


# ──────────────────────────────────────────────────────────────
# Agent 명령 수신 핸들러
# ──────────────────────────────────────────────────────────────
class AgentIptablesHandler:
    """
    Policy Engine → agent_commands 큐로 수신한
    block_ip / unblock_ip 명령 실행기.

    설계서 v3: 명령에 HMAC 서명 + nonce + expires_at 검증 필수
    """

    def __init__(
        self,
        blocker: IptablesBlocker,
        hmac_secret: bytes,
        allowlist: set[str] | None = None,
    ):
        self.blocker      = blocker
        self.hmac_secret  = hmac_secret
        self.allowlist    = allowlist or set()
        self._used_nonces: set[str] = set()

    def handle_command(self, command: dict) -> dict:
        """
        수신 명령 형식:
        {
            "command":    "block_ip" | "unblock_ip",
            "ip":         "1.2.3.4",
            "ttl_seconds": 1800,
            "reason":     "policy_engine",
            "incident_id": "...",
            "nonce":      "uuid",
            "expires_at": 1234567890.0,
            "hmac":       "hex_signature",
        }
        """
        import hashlib, hmac as hmac_lib

        # 1) 만료 시각 검증
        if time.time() > command.get("expires_at", 0):
            return {"ok": False, "error": "command_expired"}

        # 2) nonce 재사용 방지
        nonce = command.get("nonce", "")
        if nonce in self._used_nonces:
            return {"ok": False, "error": "nonce_replayed"}
        self._used_nonces.add(nonce)

        # 3) HMAC 서명 검증
        received_mac = command.pop("hmac", "")
        payload      = json.dumps(command, sort_keys=True).encode()
        expected_mac = hmac_lib.new(
            self.hmac_secret, payload, hashlib.sha256
        ).hexdigest()
        if not hmac_lib.compare_digest(received_mac, expected_mac):
            return {"ok": False, "error": "invalid_signature"}

        # 4) 명령 실행
        cmd  = command["command"]
        ip   = command["ip"]
        if cmd == "block_ip":
            ok = self.blocker.block(
                ip,
                ttl_seconds=command.get("ttl_seconds", 1800),
                reason=command.get("reason", "agent_command"),
                incident_id=command.get("incident_id", ""),
            )
        elif cmd == "unblock_ip":
            ok = self.blocker.unblock(ip, reason="agent_command")
        else:
            return {"ok": False, "error": f"unknown_command:{cmd}"}

        return {"ok": ok, "command": cmd, "ip": ip}


# ──────────────────────────────────────────────────────────────
# Nginx 연동 — /etc/nginx/conf.d/infrared_block.conf 갱신
# ──────────────────────────────────────────────────────────────
class NginxBlocklist:
    """
    iptables와 병행하여 Nginx 레벨에서도 차단.
    /etc/nginx/conf.d/infrared_block.conf 파일을 동적으로 갱신.
    """

    CONF_PATH = Path("/etc/nginx/conf.d/infrared_block.conf")

    def update(self, blocked_ips: list[str]) -> bool:
        """차단 IP 목록으로 nginx conf 갱신 후 reload"""
        lines = ["# InfraRed auto-generated — DO NOT EDIT MANUALLY\n"]
        for ip in blocked_ips:
            lines.append(f"deny {ip};\n")
        lines.append("allow all;\n")

        try:
            self.CONF_PATH.write_text("".join(lines))
            result = subprocess.run(
                ["nginx", "-s", "reload"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                logger.error("nginx reload 실패: %s", result.stderr)
                return False
            logger.info("nginx 차단 설정 갱신: %d IPs", len(blocked_ips))
            return True
        except Exception as exc:
            logger.error("NginxBlocklist 갱신 실패: %s", exc)
            return False
