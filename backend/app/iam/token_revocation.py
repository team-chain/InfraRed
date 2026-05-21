"""Token revocation — Redis deny-list 기반.

JWT는 stateless라 한 번 발급되면 exp까지 유효. 침해된 토큰을 즉시 무효화하려면
별도 deny-list가 필요.

설계:
- 각 JWT에 `jti` (JWT ID) claim 포함 (create_token에서 자동 생성)
- revoke_jti(jti, ttl) → Redis SET revoked:jti:{jti} = "1" EX {ttl}
- verify_token 직후 is_jti_revoked(jti) 체크 → True면 401
- TTL은 토큰의 남은 수명 (exp - now). 만료된 후엔 Redis 키도 사라짐.

추가 — 사용자 단위 revoke (모든 토큰 무효화):
- revoke_user(user_id) → Redis ZADD revoked:user:{user_id} score=now
- verify_token에서 token.iat < revoked_at 이면 401
"""
from __future__ import annotations

from datetime import datetime, timezone

from app.redis_kv.client import get_redis

_JTI_PREFIX = "revoked:jti:"
_USER_PREFIX = "revoked:user:"


async def revoke_jti(jti: str, ttl_seconds: int) -> bool:
    """단일 토큰(JTI) revoke. TTL은 토큰 남은 수명. 0 이하면 이미 만료라 no-op."""
    if not jti or ttl_seconds <= 0:
        return False
    redis = get_redis()
    key = f"{_JTI_PREFIX}{jti}"
    await redis.set(key, "1", ex=int(ttl_seconds))
    return True


async def is_jti_revoked(jti: str | None) -> bool:
    if not jti:
        return False
    redis = get_redis()
    key = f"{_JTI_PREFIX}{jti}"
    return bool(await redis.exists(key))


async def revoke_user_tokens(user_id: str, *, max_ttl_seconds: int = 86400 * 7) -> int:
    """사용자의 모든 활성 토큰 무효화 — revoke 이전 발급된 모든 토큰 거부.

    토큰의 iat (issued-at)이 이 revoke 시각보다 작으면 거부됨.
    Returns: 저장된 revoke 시각 (epoch).
    """
    if not user_id:
        return 0
    redis = get_redis()
    key = f"{_USER_PREFIX}{user_id}"
    revoked_at = int(datetime.now(timezone.utc).timestamp())
    await redis.set(key, str(revoked_at), ex=int(max_ttl_seconds))
    return revoked_at


async def user_revoked_at(user_id: str | None) -> int:
    """해당 사용자의 마지막 revoke 시각 (epoch). 없으면 0."""
    if not user_id:
        return 0
    redis = get_redis()
    val = await redis.get(f"{_USER_PREFIX}{user_id}")
    if not val:
        return 0
    try:
        return int(val)
    except (TypeError, ValueError):
        return 0
