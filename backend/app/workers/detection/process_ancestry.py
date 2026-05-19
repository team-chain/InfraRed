"""Process Ancestry Tripwire — v8 Security Hardening.

탐지 룰:
  EXEC-ANCESTRY-001 : 웹서버/DB 프로세스가 의심스러운 자식 프로세스 생성
  EXEC-ANCESTRY-002 : 학습된 정상 페어에서 벗어난 비정상 부모-자식 관계

Redis 사용:
  - 정상 페어 학습: SADD ir:ancestry:{tenant}:{parent} {child}
  - 이미 본 적 없는 페어 감지: SISMEMBER 로 비교
"""
from __future__ import annotations

import logging
import os
from typing import Optional

log = logging.getLogger(__name__)

# ------------------------------------------------------------------ #
# Redis 클라이언트 초기화
# ------------------------------------------------------------------ #

try:
    import redis.asyncio as aioredis
    _REDIS_AVAILABLE = True
except ImportError:
    _REDIS_AVAILABLE = False

_redis_client: Optional["aioredis.Redis"] = None  # type: ignore[type-arg]


async def _get_redis() -> Optional["aioredis.Redis"]:  # type: ignore[type-arg]
    """Redis 클라이언트를 싱글톤으로 반환한다.

    REDIS_URL 환경변수가 없거나 접속에 실패하면 None을 반환하며,
    이 경우 ancestry 학습은 건너뛰고 탐지만 ALWAYS_SUSPICIOUS 기준으로 수행한다.
    """
    global _redis_client
    if not _REDIS_AVAILABLE:
        return None
    if _redis_client is not None:
        return _redis_client

    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    try:
        client = aioredis.from_url(
            redis_url,
            encoding="utf-8",
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=2,
        )
        await client.ping()
        _redis_client = client
        log.info("process_ancestry: Redis 연결 성공 url=%s", redis_url)
        return _redis_client
    except Exception as exc:
        log.warning("process_ancestry: Redis 연결 실패(%s) — 인메모리 모드로 폴백", exc)
        return None


# ------------------------------------------------------------------ #
# 인메모리 폴백 저장소 (Redis 없을 때)
# ------------------------------------------------------------------ #

_in_memory_pairs: dict[str, set[str]] = {}


# ------------------------------------------------------------------ #
# 설계서 v8.0 §2.2: 확정 위험 부모→자식 쌍 (ALWAYS_SUSPICIOUS_PAIRS)
# 이 목록에 있으면 학습 여부와 무관하게 즉시 EXEC-ANCESTRY-001 (CRITICAL)
# ------------------------------------------------------------------ #

ALWAYS_SUSPICIOUS_PAIRS: frozenset[tuple[str, str]] = frozenset({
    ("nginx",        "bash"),
    ("nginx",        "sh"),
    ("nginx",        "dash"),
    ("apache2",      "bash"),
    ("apache2",      "sh"),
    ("httpd",        "bash"),
    ("php-fpm",      "bash"),
    ("php-fpm",      "wget"),   # 설계서 §2.2 명시
    ("php-fpm",      "curl"),   # 설계서 §2.2 명시
    ("php-fpm",      "nc"),     # 설계서 §2.2 명시
    ("tomcat",       "bash"),
    ("tomcat",       "sh"),
    ("node",         "bash"),
    ("python3",      "bash"),
    ("java",         "bash"),
    ("mysql",        "curl"),   # 설계서 §2.2 명시
    ("mysqld",       "bash"),
    ("postgres",     "sh"),
    ("redis-server", "bash"),
    ("sshd",         "wget"),   # 설계서 §2.2 명시
    ("sshd",         "curl"),   # 설계서 §2.2 명시
})

# ------------------------------------------------------------------ #
# 항상 의심스러운 자식 프로세스 목록 (범용 — SENSITIVE_PARENTS 조합용)
# ------------------------------------------------------------------ #

ALWAYS_SUSPICIOUS: frozenset[str] = frozenset({
    "bash", "sh", "dash", "zsh", "ksh",
    "python", "python3", "python2",
    "perl", "ruby", "php",
    "nc", "ncat", "netcat", "nmap",
    "curl", "wget",
    "socat", "telnet",
    "xterm", "gnome-terminal",
    "msfconsole", "meterpreter",
})

# 웹·DB 서버 등 외부 요청을 받는 프로세스 — 이 목록에서 쉘/스크립트 생성 시 경보
SENSITIVE_PARENTS: frozenset[str] = frozenset({
    "nginx", "apache2", "httpd", "lighttpd", "caddy",
    "postgres", "mysqld", "mongod", "redis-server",
    "java",  # Tomcat, Spring 등
    "node", "ruby",
    "php-fpm", "uwsgi", "gunicorn",
})


# ------------------------------------------------------------------ #
# 핵심 로직
# ------------------------------------------------------------------ #

class ProcessAncestryTripwire:
    """부모-자식 프로세스 관계를 학습하고 이상 관계를 탐지한다."""

    KEY_TTL = 60 * 60 * 24 * 90  # 90일간 학습 데이터 보관

    # ---------------------------------------------------------------- #
    # 공개 인터페이스
    # ---------------------------------------------------------------- #

    async def check(
        self,
        tenant_id: str,
        parent_name: str,
        child_name: str,
    ) -> Optional[dict]:
        """부모-자식 페어를 검사한다.

        Returns:
            탐지된 경우 rule_id / detail 딕셔너리, 아니면 None.
        """
        parent = parent_name.lower()
        child = child_name.lower()

        # 규칙 0: 설계서 §2.2 확정 위험 쌍 — ALWAYS_SUSPICIOUS_PAIRS 우선 체크
        # sshd→wget/curl, mysql→curl 등 SENSITIVE_PARENTS에 없는 프로세스도 커버
        if (parent, child) in ALWAYS_SUSPICIOUS_PAIRS:
            return {
                "rule_id": "EXEC-ANCESTRY-001",
                "severity": "critical",
                "confidence": 0.95,
                "mitre": "T1059",
                "detail": (
                    f"확정 위험 프로세스 계보: {parent} → {child}. "
                    "웹셸·RCE 또는 백도어 실행 징후입니다."
                ),
                "parent": parent,
                "child": child,
            }

        # 규칙 1: 민감 부모 + 항상 의심스러운 자식 (범용 탐지)
        if parent in SENSITIVE_PARENTS and child in ALWAYS_SUSPICIOUS:
            return {
                "rule_id": "EXEC-ANCESTRY-001",
                "severity": "critical",
                "detail": (
                    f"의심스러운 자식 프로세스 생성: {parent} → {child}. "
                    "웹·DB 서버에서 쉘/스크립트 실행은 웹셸·RCE 징후입니다."
                ),
                "parent": parent,
                "child": child,
            }

        # 규칙 2: 학습된 정상 페어와 비교
        if not await self._seen_before(tenant_id, parent, child):
            await self._record_pair(tenant_id, parent, child)
            # 첫 등장이면 경보 (ALWAYS_SUSPICIOUS가 아니어도 학습 외 페어)
            return {
                "rule_id": "EXEC-ANCESTRY-002",
                "severity": "medium",
                "detail": (
                    f"학습된 적 없는 부모-자식 관계: {parent} → {child}. "
                    "베이스라인 외 신규 실행 패턴."
                ),
                "parent": parent,
                "child": child,
            }

        return None

    async def learn(
        self,
        tenant_id: str,
        parent_name: str,
        child_name: str,
    ) -> None:
        """Learn a normal pair without raising an alert."""
        await self._record_pair(tenant_id, parent_name.lower(), child_name.lower())

    async def _seen_before(
        self, tenant_id: str, parent: str, child: str
    ) -> bool:
        key = f"ir:ancestry:{tenant_id}:{parent}"
        redis = await _get_redis()
        if redis is not None:
            try:
                return bool(await redis.sismember(key, child))
            except Exception as exc:
                log.debug("ancestry redis sismember failed: %s", exc)
        return child in _in_memory_pairs.get(key, set())

    async def _record_pair(
        self, tenant_id: str, parent: str, child: str
    ) -> None:
        key = f"ir:ancestry:{tenant_id}:{parent}"
        redis = await _get_redis()
        if redis is not None:
            try:
                await redis.sadd(key, child)
                await redis.expire(key, self.KEY_TTL)
                return
            except Exception as exc:
                log.debug("ancestry redis sadd failed: %s", exc)
        if key not in _in_memory_pairs:
            _in_memory_pairs[key] = set()
        _in_memory_pairs[key].add(child)


_tripwire = ProcessAncestryTripwire()


async def check_process_ancestry(
    tenant_id: str,
    parent_name: str,
    child_name: str,
) -> Optional[dict]:
    return await _tripwire.check(tenant_id, parent_name, child_name)


async def learn_process_ancestry(
    tenant_id: str,
    parent_name: str,
    child_name: str,
) -> None:
    await _tripwire.learn(tenant_id, parent_name, child_name)
