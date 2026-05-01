"""Starter AUTH-001..005 rule evaluator."""
from __future__ import annotations

from datetime import timedelta

from redis.asyncio import Redis

from app.common.constants import EventType, KillChainStage, RuleId
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


def _signal(rule_id: RuleId, event: NormalizedEvent, count: int = 1, note: str | None = None) -> Signal:
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
        triggering_event_ids=[event.event_id],
        notes=note,
    )


async def evaluate_rules(redis: Redis, event: NormalizedEvent) -> list[Signal]:
    signals: list[Signal] = []
    if not event.source_ip:
        return signals

    now_score = event.timestamp.timestamp()
    fail_ip_key = keys.auth_fail_ip(event.tenant_id, event.asset_id, event.source_ip)
    invalid_key = keys.auth_invalid_user(event.tenant_id, event.asset_id, event.source_ip)

    if event.result == "failed":
        await redis.zadd(fail_ip_key, {event.event_id: now_score})
        await redis.zremrangebyscore(fail_ip_key, 0, now_score - 300)
        await redis.expire(fail_ip_key, 600)
        failed_count = await redis.zcard(fail_ip_key)
        if failed_count >= 3:
            signals.append(
                _signal(
                    RuleId.AUTH_BRUTE_FORCE,
                    event,
                    int(failed_count),
                    "Three or more SSH failures from one IP within five minutes.",
                )
            )

    if event.event_type == EventType.SSH_INVALID_USER:
        await redis.zadd(invalid_key, {event.event_id: now_score})
        await redis.zremrangebyscore(invalid_key, 0, now_score - 300)
        await redis.expire(invalid_key, 600)
        invalid_count = await redis.zcard(invalid_key)
        if invalid_count >= 2:
            signals.append(
                _signal(
                    RuleId.AUTH_INVALID_USER,
                    event,
                    int(invalid_count),
                    "Two or more invalid-user probes from one IP within five minutes.",
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
            signals.append(
                _signal(
                    RuleId.AUTH_FAILED_THEN_SUCCESS,
                    event,
                    int(failure_count) + 1,
                    "Successful SSH login after prior failures from the same user/IP.",
                )
            )

        known_ip_key = keys.auth_known_ip(event.tenant_id, event.asset_id, event.username)
        seen_before = await redis.scard(known_ip_key)
        is_known = await redis.sismember(known_ip_key, event.source_ip)
        await redis.sadd(known_ip_key, event.source_ip)
        await redis.expire(known_ip_key, 86400 * 90)
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
        await redis.zremrangebyscore(fail_user_key, 0, now_score - 600)
        await redis.expire(fail_user_key, 900)

    return signals
