"""TAMPER-LOG-001/002 Log Entropy Sentinel — v8.0 설계서 §3

역할:
  로그 파일의 Shannon 엔트로피와 크기를 주기적으로 측정하여
  랜섬웨어 암호화(엔트로피 폭등)와 로그 삭제(크기 급감)를 탐지.

탐지 룰 (설계서 §3.2):
  TAMPER-LOG-001: 엔트로피 ≥ 7.5  → 랜섬웨어 암호화 또는 무작위 데이터 주입 (T1486, CRITICAL)
  TAMPER-LOG-002: 파일 크기가 이전의 30% 미만으로 급감 → 공격자 흔적 삭제 (T1070.002, CRITICAL)

Shannon 엔트로피 범위:
  정상 로그:        H = 3.5 ~ 5.5  (영문+숫자+특수문자 조합)
  랜섬웨어 암호화:  H = 7.5 ~ 8.0  (완전 무작위 → 정보 이론 최대치)
  반복 문자 와이핑: H = 0   ~ 1.0  (단조로운 패턴)

MITRE ATT&CK:
  T1486      — Data Encrypted for Impact (랜섬웨어)
  T1070.002  — Indicator Removal: Clear Linux or Mac System Logs
"""
from __future__ import annotations

import logging
import math
import os
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

log = logging.getLogger("infrared.log_entropy_sentinel")

# ── 설계서 §3.2 임계값 ──────────────────────────────────────────────────────
HIGH_ENTROPY_THRESHOLD = 7.5    # 이상: 랜섬웨어 암호화 의심 → TAMPER-LOG-001
LOW_ENTROPY_THRESHOLD  = 1.0    # 이하: 반복 문자 와이핑 의심 → TAMPER-LOG-001 보조
WIPE_SIZE_DROP_RATIO   = 0.3    # 이전 크기의 30% 미만으로 급감 → TAMPER-LOG-002
SAMPLE_SIZE_BYTES      = 4096   # 설계서: 4096 bytes 샘플로 빠르게 계산
CHECK_INTERVAL_SECONDS = 60.0   # 1분마다 체크
MIN_FILE_SIZE_BYTES    = 10_000 # 10KB 미만 소형 파일 크기 급감 검사 제외

# 기본 감시 대상 파일 목록
WATCH_FILES = [
    "/var/log/auth.log",
    "/var/log/nginx/access.log",
    "/var/log/nginx/error.log",
    "/var/log/syslog",
    "/var/log/kern.log",
    "/var/log/secure",
    "/var/log/messages",
    "/var/log/audit/audit.log",
]


# ── 엔트로피 계산 ────────────────────────────────────────────────────────────

def shannon_entropy(data: bytes) -> float:
    """
    바이트 시퀀스의 Shannon 엔트로피를 계산 (bit/byte).

    H(X) = -Σ p(x) * log₂(p(x))

    Returns:
      0.0(완전 동일) ~ 8.0(완전 무작위)
    """
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum(
        (c / total) * math.log2(c / total)
        for c in counts.values()
    )


# ── 상태 캐시 ─────────────────────────────────────────────────────────────────

@dataclass
class LogState:
    path: str
    size_bytes: int
    entropy: float
    sampled_at: datetime


# ── 탐지 이벤트 ──────────────────────────────────────────────────────────────

def _make_event(
    rule_id: str,
    mitre: str,
    severity: str,
    confidence: float,
    path: str,
    description: str,
    details: dict[str, Any],
) -> dict[str, Any]:
    return {
        "rule_id":         rule_id,
        "event_type":      "log_tampering_detected",
        "mitre_technique": mitre,
        "severity":        severity,
        "confidence":      confidence,
        "description":     description,
        "detected_at":     datetime.now(timezone.utc).isoformat(),
        "log_path":        path,
        "details":         details,
    }


# ── 감시 클래스 ──────────────────────────────────────────────────────────────

class LogEntropySentinel:
    """
    로그 파일의 Shannon 엔트로피와 크기를 주기적으로 측정.

    TAMPER-LOG-001: 엔트로피 ≥ HIGH_ENTROPY_THRESHOLD(7.5) → 랜섬웨어 암호화 의심
    TAMPER-LOG-002: 파일 크기 < 이전의 WIPE_SIZE_DROP_RATIO(30%) → 흔적 삭제 의심

    설계서 §3.3: sensor 컴포넌트에 백그라운드 태스크로 통합.
    """

    def __init__(
        self,
        log_paths: list[str] | None = None,
        high_entropy_threshold: float = HIGH_ENTROPY_THRESHOLD,
        low_entropy_threshold: float  = LOW_ENTROPY_THRESHOLD,
        wipe_size_drop_ratio: float   = WIPE_SIZE_DROP_RATIO,
        sample_size_bytes: int        = SAMPLE_SIZE_BYTES,
        check_interval: float         = CHECK_INTERVAL_SECONDS,
    ) -> None:
        self.log_paths            = log_paths or WATCH_FILES
        self.high_entropy_threshold = high_entropy_threshold
        self.low_entropy_threshold  = low_entropy_threshold
        self.wipe_size_drop_ratio   = wipe_size_drop_ratio
        self.sample_size_bytes      = sample_size_bytes
        self.check_interval         = check_interval

        self._prev_state: dict[str, LogState] = {}
        self._last_check: float = 0.0

    # ── 상태 수집 ─────────────────────────────────────────────────────────────

    def _get_log_state(self, path: str) -> Optional[LogState]:
        """파일 끝 sample_size_bytes 읽어 엔트로피·크기 계산."""
        try:
            size = os.path.getsize(path)
            with open(path, "rb") as f:
                # 설계서: 파일 끝 샘플 (최근 기록된 내용 기준)
                f.seek(max(0, size - self.sample_size_bytes))
                sample = f.read(self.sample_size_bytes)
        except (FileNotFoundError, PermissionError, OSError) as exc:
            log.debug("log_read_failed path=%s err=%s", path, exc)
            return None

        return LogState(
            path=path,
            size_bytes=size,
            entropy=shannon_entropy(sample),
            sampled_at=datetime.now(timezone.utc),
        )

    # ── 핵심 검사 루프 ─────────────────────────────────────────────────────────

    def check(self) -> list[dict[str, Any]]:
        """
        모든 감시 대상 로그를 검사하고 탐지 이벤트 목록 반환.
        check_interval 이내 재호출 시 빈 리스트 반환 (쓰로틀).
        """
        import time
        now = time.monotonic()
        if now - self._last_check < self.check_interval:
            return []
        self._last_check = now

        events: list[dict[str, Any]] = []

        for path in self.log_paths:
            curr = self._get_log_state(path)
            if curr is None:
                continue

            prev = self._prev_state.get(path)

            # ── TAMPER-LOG-001: 엔트로피 폭등 (랜섬웨어 암호화) ────────────
            # 설계서: 엔트로피 ≥ 7.5 → 랜섬웨어 암호화 또는 무작위 데이터 주입
            if curr.entropy >= self.high_entropy_threshold:
                log.critical(
                    "TAMPER-LOG-001 랜섬웨어 의심 path=%s entropy=%.2f",
                    path, curr.entropy,
                )
                events.append(_make_event(
                    rule_id="TAMPER-LOG-001",
                    mitre="T1486",          # Data Encrypted for Impact
                    severity="CRITICAL",
                    confidence=0.90,
                    path=path,
                    description=(
                        f"로그 파일 엔트로피 이상: {path} "
                        f"(엔트로피={curr.entropy:.2f}, 정상범위 3.5~5.5). "
                        "랜섬웨어 암호화 또는 무작위 데이터 주입 의심."
                    ),
                    details={
                        "entropy":     round(curr.entropy, 3),
                        "threshold":   self.high_entropy_threshold,
                        "sample_size": self.sample_size_bytes,
                        "file_size":   curr.size_bytes,
                    },
                ))

            # ── TAMPER-LOG-001 보조: 엔트로피 극저하 (반복 문자 와이핑) ────
            elif curr.entropy <= self.low_entropy_threshold and curr.size_bytes > 0:
                log.warning(
                    "TAMPER-LOG-001(wipe) 반복 문자 와이핑 의심 path=%s entropy=%.2f",
                    path, curr.entropy,
                )
                events.append(_make_event(
                    rule_id="TAMPER-LOG-001",
                    mitre="T1070.002",
                    severity="CRITICAL",
                    confidence=0.85,
                    path=path,
                    description=(
                        f"로그 파일 엔트로피 극저하: {path} "
                        f"(엔트로피={curr.entropy:.2f}, 정상범위 3.5~5.5). "
                        "반복 문자로 덮어쓴 로그 와이핑 의심."
                    ),
                    details={
                        "entropy":     round(curr.entropy, 3),
                        "threshold":   self.low_entropy_threshold,
                        "sample_size": self.sample_size_bytes,
                        "file_size":   curr.size_bytes,
                    },
                ))

            # ── TAMPER-LOG-002: 파일 크기 급감 (흔적 삭제) ─────────────────
            # 설계서: prev_size > 10KB이고 curr_size < prev_size * 0.3
            if (
                prev is not None
                and prev.size_bytes > MIN_FILE_SIZE_BYTES
                and curr.size_bytes < prev.size_bytes * self.wipe_size_drop_ratio
            ):
                drop_pct = 100 * (1 - curr.size_bytes / prev.size_bytes)
                log.critical(
                    "TAMPER-LOG-002 크기 급감 path=%s %d→%d (%.0f%%↓)",
                    path, prev.size_bytes, curr.size_bytes, drop_pct,
                )
                events.append(_make_event(
                    rule_id="TAMPER-LOG-002",
                    mitre="T1070.002",      # Indicator Removal: Clear Logs
                    severity="CRITICAL",
                    confidence=0.92,
                    path=path,
                    description=(
                        f"로그 파일 크기 급감: {path} "
                        f"({prev.size_bytes:,} → {curr.size_bytes:,} bytes, "
                        f"{drop_pct:.0f}% 감소). "
                        "공격자의 흔적 삭제 의심."
                    ),
                    details={
                        "prev_size":  prev.size_bytes,
                        "curr_size":  curr.size_bytes,
                        "drop_pct":   round(drop_pct, 1),
                        "drop_ratio": self.wipe_size_drop_ratio,
                    },
                ))

            # 상태 갱신
            self._prev_state[path] = curr

        return events

    # ── sensor 컴포넌트 통합용 비동기 루프 ──────────────────────────────────

    async def run_loop(self, event_queue=None) -> None:
        """
        sensor 컴포넌트에서 백그라운드 태스크로 실행.
        설계서 §3.3: 기존 FIM 루프와 병렬 실행 (독립적, 충돌 없음).
        """
        import asyncio
        while True:
            events = self.check()
            if event_queue is not None:
                for evt in events:
                    await event_queue.put(evt)
            await asyncio.sleep(self.check_interval)
