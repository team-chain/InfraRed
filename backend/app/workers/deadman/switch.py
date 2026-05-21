"""Dead Man's Switch — v7.0.

서버 격리(isolate_server) 후 지정된 TTL 내에 수동 해제가 없으면 자동으로 격리 해제.
Redis TTL 기반 구현으로 만료 시 keyspace notification 또는 주기적 폴링으로 처리.
"""
from __future__ import annotations

import json
import logging
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

log = logging.getLogger(__name__)

# Redis key 패턴
_KEY_TEMPLATE = "deadman:{tenant_id}:{asset_id}"
_ALL_KEYS_PATTERN = "deadman:*"


@dataclass
class SwitchStatus:
    """Dead Man's Switch 현재 상태."""
    switch_id: str
    tenant_id: str
    asset_id: str
    armed_at: float
    ttl_seconds: int
    remaining_seconds: Optional[int]   # None이면 만료됨
    is_armed: bool

    def to_dict(self) -> dict:
        return {
            "switch_id": self.switch_id,
            "tenant_id": self.tenant_id,
            "asset_id": self.asset_id,
            "armed_at": datetime.fromtimestamp(self.armed_at, tz=timezone.utc).isoformat(),
            "ttl_seconds": self.ttl_seconds,
            "remaining_seconds": self.remaining_seconds,
            "is_armed": self.is_armed,
        }


class DeadManSwitch:
    """Dead Man's Switch.

    서버 격리(isolate_server) 후 자동으로 TTL 내에 격리 해제.
    Redis TTL 기반 구현.

    사용 흐름:
    1. arm()       — 격리 명령과 동시에 스위치 설정
    2. disarm()    — 운영자가 수동으로 격리 해제 확인
    3. (자동)       — TTL 만료 시 Redis keyspace notification → 격리 해제 명령 발행
    """

    DEFAULT_TTL_SECONDS = 4 * 3600  # 4시간

    def __init__(self, redis=None):
        self._redis = redis

    def _get_redis(self):
        if self._redis:
            return self._redis
        from app.redis_kv.client import get_redis
        return get_redis()

    def _key(self, tenant_id: str, asset_id: str) -> str:
        return _KEY_TEMPLATE.format(tenant_id=tenant_id, asset_id=asset_id)

    async def arm(
        self,
        tenant_id: str,
        asset_id: str,
        ttl_seconds: Optional[int] = None,
    ) -> str:
        """격리 스위치 설정.

        Args:
            tenant_id: 테넌트 ID
            asset_id: 격리된 자산 ID
            ttl_seconds: TTL (초). None이면 DEFAULT_TTL_SECONDS 사용.

        Returns:
            switch_id (수동 해제 시 필요)
        """
        redis = self._get_redis()
        switch_id = secrets.token_hex(8)
        ttl = ttl_seconds or self.DEFAULT_TTL_SECONDS
        key = self._key(tenant_id, asset_id)
        data = {
            "switch_id": switch_id,
            "tenant_id": tenant_id,
            "asset_id": asset_id,
            "armed_at": time.time(),
            "ttl": ttl,
        }

        await redis.setex(key, ttl, json.dumps(data))

        log.info(
            "deadman_switch_armed tenant=%s asset=%s switch_id=%s ttl=%ds",
            tenant_id, asset_id, switch_id, ttl,
        )

        # DB에 이력 기록 (비동기, 실패해도 스위치 설정은 성공)
        try:
            await self._record_armed(tenant_id, asset_id, switch_id, ttl)
        except Exception as exc:
            log.warning("deadman_switch_db_record_failed: %s", exc)

        return switch_id

    async def disarm(
        self,
        tenant_id: str,
        asset_id: str,
        switch_id: str,
    ) -> bool:
        """수동으로 격리 해제 확인.

        Args:
            tenant_id: 테넌트 ID
            asset_id: 자산 ID
            switch_id: arm() 반환값

        Returns:
            True — 성공적으로 해제됨
            False — 스위치 없음 또는 switch_id 불일치
        """
        redis = self._get_redis()
        key = self._key(tenant_id, asset_id)
        raw = await redis.get(key)

        if not raw:
            log.info(
                "deadman_switch_disarm_not_found tenant=%s asset=%s",
                tenant_id, asset_id,
            )
            return False

        data = json.loads(raw)
        if data.get("switch_id") != switch_id:
            log.warning(
                "deadman_switch_disarm_id_mismatch tenant=%s asset=%s provided=%s stored=%s",
                tenant_id, asset_id, switch_id, data.get("switch_id"),
            )
            return False

        await redis.delete(key)

        log.info(
            "deadman_switch_disarmed tenant=%s asset=%s switch_id=%s",
            tenant_id, asset_id, switch_id,
        )

        # DB 이력 업데이트
        try:
            await self._record_disarmed(tenant_id, asset_id, switch_id)
        except Exception as exc:
            log.warning("deadman_switch_db_disarm_failed: %s", exc)

        return True

    async def get_status(
        self,
        tenant_id: str,
        asset_id: str,
    ) -> Optional[SwitchStatus]:
        """현재 스위치 상태 조회.

        Returns:
            SwitchStatus (armed) 또는 None (스위치 없음 / 만료됨)
        """
        redis = self._get_redis()
        key = self._key(tenant_id, asset_id)
        raw = await redis.get(key)

        if not raw:
            return None

        data = json.loads(raw)

        # 남은 TTL 조회
        remaining = await redis.ttl(key)
        if remaining < 0:
            # 만료됐지만 아직 Redis에서 삭제 안 됨
            remaining = None
            is_armed = False
        else:
            is_armed = True

        return SwitchStatus(
            switch_id=data["switch_id"],
            tenant_id=tenant_id,
            asset_id=asset_id,
            armed_at=data["armed_at"],
            ttl_seconds=data["ttl"],
            remaining_seconds=remaining,
            is_armed=is_armed,
        )

    async def check_expired_switches(self) -> list[str]:
        """만료된 스위치 목록 확인.

        Redis TTL 만료는 자동으로 처리되지만,
        이 메서드는 keyspace notification 대신 주기적 폴링 방식으로
        만료 직전(TTL <= 60s) 스위치를 조회해 사전 처리할 수 있다.

        Returns:
            만료 임박 또는 만료된 스위치 key 목록
        """
        redis = self._get_redis()
        pattern = _ALL_KEYS_PATTERN
        expiring_keys: list[str] = []

        try:
            cursor = 0
            while True:
                cursor, keys = await redis.scan(cursor, match=pattern, count=100)
                for key in keys:
                    ttl = await redis.ttl(key)
                    # TTL <= 0이면 만료됨 (Redis가 아직 삭제 안 한 경우)
                    # TTL <= 60이면 만료 임박
                    if ttl <= 60:
                        expiring_keys.append(key.decode() if isinstance(key, bytes) else key)
                if cursor == 0:
                    break
        except Exception as exc:
            log.error("check_expired_switches_failed: %s", exc)

        return expiring_keys

    async def issue_unisolate_command(
        self,
        tenant_id: str,
        asset_id: str,
    ) -> bool:
        """TTL 만료 후 자동 격리 해제 명령 발행.

        Redis 명령 큐에 unisolate 명령을 push한다.

        Returns:
            True — 명령 발행 성공
        """
        import hashlib as _hashlib
        import hmac as _hmac
        import secrets as _secrets
        import time as _time

        from app.config import get_settings

        redis = self._get_redis()
        settings = get_settings()

        command = {
            "action_type": "unisolate_server",
            "target": asset_id,
            "payload": {"reason": "deadman_switch_expired"},
            "issued_at": datetime.now(timezone.utc).isoformat(),
        }

        # nonce + HMAC 서명 추가 (command_routes.sign_command 와 동일 로직)
        nonce = _secrets.token_hex(16)
        timestamp = int(_time.time())
        payload_str = f"{command['action_type']}:{command.get('target','')}:{nonce}:{timestamp}"
        sig = _hmac.new(
            settings.jwt_secret.encode("utf-8"),
            payload_str.encode("utf-8"),
            _hashlib.sha256,
        ).hexdigest()
        command.update({"nonce": nonce, "timestamp": timestamp, "signature": sig})

        key = f"tenant:{tenant_id}:commands:{asset_id}"
        await redis.lpush(key, json.dumps(command))
        await redis.expire(key, 3600)

        log.info(
            "deadman_switch_unisolate_issued tenant=%s asset=%s",
            tenant_id, asset_id,
        )

        # DB 이력 상태 expired로 업데이트
        try:
            await self._record_expired(tenant_id, asset_id)
        except Exception as exc:
            log.warning("deadman_switch_db_expire_failed: %s", exc)

        return True

    # ------------------------------------------------------------------
    # DB 이력 기록 헬퍼
    # ------------------------------------------------------------------

    async def _record_armed(
        self,
        tenant_id: str,
        asset_id: str,
        switch_id: str,
        ttl_seconds: int,
    ) -> None:

        from sqlalchemy import text

        from app.db.connection import get_session

        async with get_session() as session:
            await session.execute(
                text("""
                    INSERT INTO deadman_switches
                        (tenant_id, asset_id, switch_id, armed_at, ttl_seconds, status)
                    VALUES
                        (:tenant_id, :asset_id, :switch_id, NOW(), :ttl, 'armed')
                    ON CONFLICT DO NOTHING
                """),
                {
                    "tenant_id": tenant_id,
                    "asset_id": asset_id,
                    "switch_id": switch_id,
                    "ttl": ttl_seconds,
                },
            )
            await session.commit()

    async def _record_disarmed(
        self,
        tenant_id: str,
        asset_id: str,
        switch_id: str,
    ) -> None:
        from sqlalchemy import text

        from app.db.connection import get_session

        async with get_session() as session:
            await session.execute(
                text("""
                    UPDATE deadman_switches
                    SET status = 'disarmed', disarmed_at = NOW()
                    WHERE tenant_id = :tenant_id
                      AND asset_id = :asset_id
                      AND switch_id = :switch_id
                      AND status = 'armed'
                """),
                {
                    "tenant_id": tenant_id,
                    "asset_id": asset_id,
                    "switch_id": switch_id,
                },
            )
            await session.commit()

    async def _record_expired(
        self,
        tenant_id: str,
        asset_id: str,
    ) -> None:
        from sqlalchemy import text

        from app.db.connection import get_session

        async with get_session() as session:
            await session.execute(
                text("""
                    UPDATE deadman_switches
                    SET status = 'expired', disarmed_at = NOW()
                    WHERE tenant_id = :tenant_id
                      AND asset_id = :asset_id
                      AND status = 'armed'
                """),
                {
                    "tenant_id": tenant_id,
                    "asset_id": asset_id,
                },
            )
            await session.commit()
