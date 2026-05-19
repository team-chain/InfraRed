"""
EXEC-FIRST-001/002 — First-Execution Alert
===========================================
실행 파일의 SHA-256 해시를 known_binary_hashes DB와 대조.
처음 보는 해시 = 신규 바이너리 또는 교체된 바이너리.

설계서: InfraRed_v8_보안심화_설계서.md §5

탐지 규칙:
    EXEC-FIRST-001  시스템 경로(/usr/bin 등)의 알려지지 않은 해시 → CRITICAL (T1554)
    EXEC-FIRST-002  일반 경로의 처음 보는 바이너리 → MEDIUM (T1059)
"""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from uuid import UUID

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 이벤트 구조체
# ---------------------------------------------------------------------------

@dataclass
class ExecEvent:
    exe_path: str
    pid: int
    parent_name: str
    cmdline: str = ""
    tenant_id: Optional[UUID] = None


@dataclass
class ExecFirstAlert:
    rule_id: str           # "EXEC-FIRST-001" | "EXEC-FIRST-002"
    severity: str          # "CRITICAL" | "MEDIUM"
    confidence: float
    mitre: str
    description: str
    data: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# 경로 설정
# ---------------------------------------------------------------------------

# 시스템 바이너리가 처음 보이면 즉시 CRITICAL
SYSTEM_PATHS: tuple[str, ...] = (
    "/usr/bin/",
    "/usr/sbin/",
    "/bin/",
    "/sbin/",
    "/usr/local/bin/",
)

# 학습 대상에서 제외 (항상 변경 가능한 경로 — FIM이 처리)
EXCLUDE_PATHS: tuple[str, ...] = (
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/proc/",
    "/run/",
)

# 베이스라인 구축 대상 경로
BASELINE_PATHS: list[str] = [
    "/usr/bin/",
    "/usr/sbin/",
    "/bin/",
    "/sbin/",
    "/usr/local/bin/",
    "/opt/",
]


# ---------------------------------------------------------------------------
# DB 헬퍼
# ---------------------------------------------------------------------------

async def _is_known_hash(pool, tenant_id: UUID, sha256: str) -> bool:
    """known_binary_hashes 테이블에 해시 존재 여부 확인."""
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT 1 FROM known_binary_hashes WHERE tenant_id=$1 AND sha256=$2",
            str(tenant_id), sha256,
        )
        return row is not None


async def _record_hash(pool, tenant_id: UUID, sha256: str, exe_path: str) -> None:
    """known_binary_hashes 테이블에 새로운 해시 등록 (중복 무시)."""
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO known_binary_hashes (tenant_id, sha256, exe_path)
            VALUES ($1, $2, $3)
            ON CONFLICT (tenant_id, sha256) DO NOTHING
            """,
            str(tenant_id), sha256, exe_path,
        )


# ---------------------------------------------------------------------------
# 해시 계산
# ---------------------------------------------------------------------------

async def _hash_binary(path: str) -> str:
    """파일의 SHA-256 해시를 계산해 반환."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65_536):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# 탐지기
# ---------------------------------------------------------------------------

class FirstExecutionDetector:
    """
    실행 파일의 SHA-256 해시를 known_binary_hashes DB와 대조.
    처음 보는 해시 = 신규 바이너리 또는 교체된 바이너리.

    EXEC-FIRST-001: 시스템 경로(/usr/bin 등)의 알려지지 않은 해시 → CRITICAL
    EXEC-FIRST-002: 일반 경로의 처음 보는 바이너리 → MEDIUM

    설계서와 달리 Pool 의존성을 직접 주입받아 테스트 편의성을 높임.
    """

    def __init__(self, pool=None):
        self._pool = pool

    # ------------------------------------------------------------------
    # 공개 API
    # ------------------------------------------------------------------

    async def on_exec(
        self,
        tenant_id: UUID,
        event: ExecEvent,
    ) -> Optional[ExecFirstAlert]:
        """
        실행 이벤트 처리. 처음 보는 해시면 경보 반환, 알려진 해시면 None.
        pool이 None이면 메모리 내 집합으로 폴백(단위 테스트용).
        """
        # 제외 경로는 FIM이 처리
        if any(event.exe_path.startswith(p) for p in EXCLUDE_PATHS):
            return None

        try:
            binary_hash = await _hash_binary(event.exe_path)
        except (FileNotFoundError, PermissionError, OSError):
            return None

        # 알려진 해시인지 확인
        if self._pool:
            is_known = await _is_known_hash(self._pool, tenant_id, binary_hash)
        else:
            # fallback: 단위 테스트용 메모리 집합
            if not hasattr(self, "_memory_hashes"):
                self._memory_hashes: set[str] = set()
            is_known = binary_hash in self._memory_hashes

        if is_known:
            return None

        # 새로운 해시 등록
        if self._pool:
            await _record_hash(self._pool, tenant_id, binary_hash, event.exe_path)
        else:
            self._memory_hashes.add(binary_hash)  # type: ignore[attr-defined]

        is_system_path = any(event.exe_path.startswith(p) for p in SYSTEM_PATHS)

        if is_system_path:
            return ExecFirstAlert(
                rule_id="EXEC-FIRST-001",
                severity="CRITICAL",
                confidence=0.88,
                mitre="T1554",
                description=(
                    f"시스템 바이너리 첫 실행 (알려지지 않은 해시): "
                    f"{event.exe_path} "
                    f"(SHA-256: {binary_hash[:16]}...). "
                    "시스템 바이너리 교체 또는 공급망 공격 의심."
                ),
                data={
                    "exe_path":    event.exe_path,
                    "sha256":      binary_hash,
                    "pid":         event.pid,
                    "parent_name": event.parent_name,
                    "cmdline":     event.cmdline[:200],
                },
            )

        return ExecFirstAlert(
            rule_id="EXEC-FIRST-002",
            severity="MEDIUM",
            confidence=0.70,
            mitre="T1059",
            description=(
                f"처음 실행된 바이너리: {event.exe_path} "
                f"(SHA-256: {binary_hash[:16]}...). "
                "신규 배포 또는 비정상 실행 경로 검토 필요."
            ),
            data={
                "exe_path":    event.exe_path,
                "sha256":      binary_hash,
                "pid":         event.pid,
                "parent_name": event.parent_name,
            },
        )


# ---------------------------------------------------------------------------
# 베이스라인 구축기
# ---------------------------------------------------------------------------

class FirstExecutionBaselineBuilder:
    """
    에이전트 설치 직후 현재 설치된 바이너리 해시를 모두 학습.
    이후 새로운 해시 = 새로 추가된 바이너리.

    사용법:
        builder = FirstExecutionBaselineBuilder(pool)
        count = await builder.build_baseline(tenant_id)
    """

    def __init__(self, pool):
        self._pool = pool

    async def build_baseline(self, tenant_id: UUID) -> int:
        """
        BASELINE_PATHS를 재귀 탐색하여 모든 실행 파일 해시를 학습.
        수집된 해시 수 반환.
        """
        count = 0
        for base_path in BASELINE_PATHS:
            base = Path(base_path)
            if not base.exists():
                continue
            for path in base.rglob("*"):
                if not path.is_file():
                    continue
                try:
                    binary_hash = await _hash_binary(str(path))
                    await _record_hash(self._pool, tenant_id, binary_hash, str(path))
                    count += 1
                except (PermissionError, OSError):
                    continue

        logger.info(
            "FirstExecution 베이스라인 구축 완료: %d개 바이너리 학습 (tenant=%s)",
            count, tenant_id,
        )
        return count

    async def get_hash_count(self, tenant_id: UUID) -> int:
        """학습된 해시 수 반환."""
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT COUNT(*) AS cnt FROM known_binary_hashes WHERE tenant_id=$1",
                str(tenant_id),
            )
            return row["cnt"] if row else 0
