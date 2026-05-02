"""Starter AUTH-001..005 rule evaluator."""
from __future__ import annotations

from datetime import timedelta

from redis.asyncio import Redis

from app.common.constants import EventType, KillChainStage, RuleId
from app.config import get_settings
from app.models.envelope import NormalizedEvent
from app.models.signal import Signal
from app.redis_kv import keys


RULE_META = {
    RuleId.AUTH_BRUTE_FORCE: {
        "name": "SSH Brute Force",
        "tactic": "Credential Access",
        "technique": "T1110.001",
        "stage": KillChainStage.CREDENTIAL_ACCESS,
    },
    RuleId.AUTH_ROOT_LOGIN: {
        "name": "Root Login Attempt",
        "tactic": "Initial Access",
        "technique": "T1078",
        "stage": KillChainStage.INITIAL_ACCESS,
    },
    RuleId.AUTH_INVALID_USER: {
        "name": "Invalid User Enumeration",
        "tactic": "Reconnaissance",
        "technique": "T1592",
        "stage": KillChainStage.RECONNAISSANCE,
    },
    RuleId.AUTH_FAILED_THEN_SUCCESS: {
        "name": "Failed Then Success",
        "tactic": "Initial Access",
        "technique": "T1110.001 -> T1078",
        "stage": KillChainStage.INITIAL_ACCESS,
    },
    RuleId.AUTH_SUSPICIOUS_LOGIN: {
        "name": "Suspicious Login",
        "tactic": "Initial Access",
        "technique": "T1078",
        "stage": KillChainStage.INITIAL_ACCESS,
    },
}


def _event_id(value: object) -> str:
    if isinstance(value, bytes):
        return value.decode()
    return str(value)


async def _window_event_ids(
    redis: Redis,
    key: str,
    window_start: float,
    window_end: float,
) -> list[str]:
    event_ids = await redis.zrangebyscore(key, window_start, window_end)
    return [_event_id(event_id) for event_id in event_ids]


def _signal(
    rule_id: RuleId,
    event: NormalizedEvent,
    count: int = 1,
    note: str | None = None,
    triggering_event_ids: list[str] | None = None,
) -> Signal:
    meta = RULE_META[rule_id]
    return Signal(
        tenant_id=event.tenant_id,
        asset_id=event.asset_id,
        rule_id=rule_id,
        rule_name=meta["name"],
        mitre_tactic=meta["tactic"],
        mitre_technique=meta["technique"],
        kill_chain_stage=meta["stage"],
        source_ip=event.source_ip,
        username=event.username,
        detected_count=count,
        detected_at=event.timestamp,
        window_start=event.timestamp - timedelta(minutes=5),
        window_end=event.timestamp,
        triggering_event_ids=triggering_event_ids or [event.event_id],
        notes=note,
    )


async def evaluate_rules(redis: Redis, event: NormalizedEvent) -> list[Signal]:
    signals: list[Signal] = []
    if not event.source_ip:
        return signals

    cfg = get_settings()
    bf_window = cfg.auth_brute_force_window_seconds
    bf_threshold = cfg.auth_brute_force_threshold
    inv_window = cfg.auth_invalid_user_window_seconds
    inv_threshold = cfg.auth_invalid_user_threshold
    fts_window = cfg.auth_fail_then_success_window_seconds

    now_score = event.timestamp.timestamp()
    fail_ip_key = keys.auth_fail_ip(event.tenant_id, event.asset_id, event.source_ip)
    invalid_key = keys.auth_invalid_user(event.tenant_id, event.asset_id, event.source_ip)

    if event.result == "failed":
        await redis.zadd(fail_ip_key, {event.event_id: now_score})
        await redis.zremrangebyscore(fail_ip_key, 0, now_score - bf_window)
        await redis.expire(fail_ip_key, bf_window * 2)
        failed_count = await redis.zcard(fail_ip_key)
        if failed_count >= bf_threshold:
            triggering_event_ids = await _window_event_ids(
                redis, fail_ip_key, now_score - bf_window, now_score
            )
            signals.append(
                _signal(
                    RuleId.AUTH_BRUTE_FORCE,
                    event,
                    int(failed_count),
                    f"{bf_threshold}+ SSH failures from one IP within {bf_window}s.",
                    triggering_event_ids,
                )
            )

    if event.event_type == EventType.SSH_INVALID_USER:
        await redis.zadd(invalid_key, {event.event_id: now_score})
        await redis.zremrangebyscore(invalid_key, 0, now_score - inv_window)
        await redis.expire(invalid_key, inv_window * 2)
        invalid_count = await redis.zcard(invalid_key)
        if invalid_count >= inv_threshold:
            triggering_event_ids = await _window_event_ids(
                redis, invalid_key, now_score - inv_window, now_score
            )
            signals.append(
                _signal(
                    RuleId.AUTH_INVALID_USER,
                    event,
                    int(invalid_count),
                    f"{inv_threshold}+ invalid-user probes from one IP within {inv_window}s.",
                    triggering_event_ids,
                )
            )

    if event.username == "root":
        signals.append(_signal(RuleId.AUTH_ROOT_LOGIN, event, note="Root account was used."))

    if event.event_type == EventType.SSH_LOGIN_SUCCESS and event.username:
        fail_user_key = keys.auth_fail_user_ip(
            event.tenant_id,
            event.asset_id,
            event.username,
            event.source_ip,
        )
        failure_count = await redis.zcard(fail_user_key)
        if failure_count:
            triggering_event_ids = await _window_event_ids(
                redis, fail_user_key, now_score - fts_window, now_score
            )
            triggering_event_ids.append(event.event_id)
            signals.append(
                _signal(
                    RuleId.AUTH_FAILED_THEN_SUCCESS,
                    event,
                    int(failure_count) + 1,
                    "Successful SSH login after prior failures from the same user/IP.",
                    triggering_event_ids,
                )
            )

        known_ip_key = keys.auth_known_ip(event.tenant_id, event.asset_id, event.username)

        # Fast path: Redis cache
        seen_before = await redis.scard(known_ip_key)
        is_known = bool(await redis.sismember(known_ip_key, event.source_ip))

        # Persistence fallback: if Redis is empty (e.g. after restart), check DB
        if not seen_before:
            try:
                from app.db.repositories import get_known_ip_count, is_known_ip_for_user
                db_count = await get_known_ip_count(
                    event.tenant_id, event.asset_id, event.username
                )
                if db_count > 0:
                    seen_before = db_count
                    is_known = await is_known_ip_for_user(
                        event.tenant_id, event.asset_id, event.username, event.source_ip
                    )
                    # Warm up Redis cache from DB
                    await redis.sadd(known_ip_key, event.source_ip)
                    await redis.expire(known_ip_key, 86400)
            except Exception:
                pass  # DB unavailable (e.g. unit tests) — use Redis result only

        # Update Redis cache
        await redis.sadd(known_ip_key, event.source_ip)
        await redis.expire(known_ip_key, 86400)

        # Persist to DB (survives container restarts)
        try:
            from app.db.repositories import upsert_known_ip
            await upsert_known_ip(
                event.tenant_id, event.asset_id, event.username, event.source_ip
            )
        except Exception:
            pass  # DB unavailable (e.g. unit tests)

        if seen_before and not is_known:
            signals.append(
                _signal(
                    RuleId.AUTH_SUSPICIOUS_LOGIN,
                    event,
                    note="Login from a source IP not previously seen for this user.",
                )
            )

    if event.result == "failed" and event.username:
        fail_user_key = keys.auth_fail_user_ip(
            event.tenant_id,
            event.asset_id,
            event.username,
            event.source_ip,
        )
        await redis.zadd(fail_user_key, {event.event_id: now_score})
        await redis.zremrangebyscore(fail_user_key, 0, now_score - fts_window)
        await redis.expire(fail_user_key, fts_window + 300)

    return signals
