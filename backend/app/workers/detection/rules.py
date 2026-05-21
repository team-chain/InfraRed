"""AUTH-001..007 rule evaluator.

AUTH-004 Incident escalation conditions (design doc 6.2):
  - Same source_ip + username with failure_count >= auth_fail_then_success_threshold
  - At least one of:
      1) username in PRIVILEGED_ACCOUNTS (root/admin/deploy)
      2) source IP not in known_ips
      3) Preceding AUTH-001 or AUTH-003 signal (Redis marker check)
  - If conditions not met: Signal saved for audit, escalate_to_incident=False
  - If conditions met: escalate_to_incident=True -> Incident + auto LLM
"""
from __future__ import annotations

from datetime import timedelta, timezone

from redis.asyncio import Redis

from app.common.constants import EventType, KillChainStage, RuleId
from app.models.envelope import NormalizedEvent
from app.models.signal import Signal
from app.redis_kv import keys
from app.workers.detection.rule_settings import get_rule_settings

PRIVILEGED_ACCOUNTS: frozenset[str] = frozenset({"root", "admin", "deploy"})
_PRIOR_SIGNAL_TTL = 3600

RULE_META = {
    RuleId.AUTH_BRUTE_FORCE: {
        "name": "SSH Brute Force",
        "tactic": "Credential Access",
        "technique": "T1110.001",
        "subtechnique": "T1110.001",
        "stage": KillChainStage.CREDENTIAL_ACCESS,
    },
    RuleId.AUTH_ROOT_LOGIN: {
        "name": "Root Login Attempt",
        "tactic": "Initial Access",
        "technique": "T1078",
        "subtechnique": None,
        "stage": KillChainStage.INITIAL_ACCESS,
    },
    RuleId.AUTH_INVALID_USER: {
        "name": "Invalid User Enumeration",
        "tactic": "Reconnaissance",
        "technique": "T1592",
        "subtechnique": None,
        "stage": KillChainStage.RECONNAISSANCE,
    },
    RuleId.AUTH_FAILED_THEN_SUCCESS: {
        "name": "Failed Then Success",
        "tactic": "Initial Access",
        "technique": "T1110.001 -> T1078",
        "subtechnique": "T1110.001",
        "stage": KillChainStage.INITIAL_ACCESS,
    },
    RuleId.AUTH_SUSPICIOUS_LOGIN: {
        "name": "Suspicious Login",
        "tactic": "Initial Access",
        "technique": "T1078",
        "subtechnique": None,
        "stage": KillChainStage.INITIAL_ACCESS,
    },
    RuleId.AUTH_OFF_HOURS_LOGIN: {
        "name": "Off-Hours Login",
        "tactic": "Initial Access",
        "technique": "T1078",
        "subtechnique": None,
        "stage": KillChainStage.INITIAL_ACCESS,
    },
    RuleId.AUTH_FOREIGN_IP_LOGIN: {
        "name": "Foreign Country Login",
        "tactic": "Initial Access",
        "technique": "T1078",
        "subtechnique": None,
        "stage": KillChainStage.INITIAL_ACCESS,
    },
    RuleId.AUTH_CRED_STUFFING: {
        "name": "Credential Stuffing",
        "tactic": "Credential Access",
        "technique": "T1110.004",
        "subtechnique": "T1110.004",
        "stage": KillChainStage.CREDENTIAL_ACCESS,
    },
    RuleId.AUTH_PASSWORD_SPRAYING: {
        "name": "Password Spraying",
        "tactic": "Credential Access",
        "technique": "T1110.004",
        "subtechnique": "T1110.004",
        "stage": KillChainStage.CREDENTIAL_ACCESS,
    },
    # DECEPTION 룰 (설계서 v6)
    RuleId.DECEPTION_HONEYTOKEN_FILE: {
        "name": "Honeytoken File Access",
        "tactic": "Discovery",
        "technique": "T1083",
        "subtechnique": None,
        "stage": KillChainStage.RECONNAISSANCE,
    },
    RuleId.DECEPTION_HONEYTOKEN_ACCOUNT: {
        "name": "Honeytoken Account Login",
        "tactic": "Initial Access",
        "technique": "T1078",
        "subtechnique": None,
        "stage": KillChainStage.INITIAL_ACCESS,
    },
}


def _prior_signal_key(tenant_id: str, asset_id: str, source_ip: str, rule_id: RuleId) -> str:
    return f"tenant:{tenant_id}:prior_signal:{asset_id}:{source_ip}:{rule_id.value}"


def _event_id(value: object) -> str:
    if isinstance(value, bytes):
        return value.decode()
    return str(value)


async def _window_event_ids(redis, key, window_start, window_end):
    event_ids = await redis.zrangebyscore(key, window_start, window_end)
    return [_event_id(e) for e in event_ids]


def _signal(rule_id, event, count=1, note=None, triggering_event_ids=None, *, escalate=True):
    meta = RULE_META[rule_id]
    return Signal(
        tenant_id=event.tenant_id,
        asset_id=event.asset_id,
        rule_id=rule_id,
        rule_name=meta["name"],
        mitre_tactic=meta["tactic"],
        mitre_technique=meta["technique"],
        mitre_subtechnique=meta.get("subtechnique"),
        kill_chain_stage=meta["stage"],
        source_ip=event.source_ip,
        username=event.username,
        detected_count=count,
        detected_at=event.timestamp,
        window_start=event.timestamp - timedelta(minutes=5),
        window_end=event.timestamp,
        triggering_event_ids=triggering_event_ids or [event.event_id],
        notes=note,
        escalate_to_incident=escalate,
    )


async def _check_auth004_escalation(redis, event, failure_count, is_known_ip, fts_threshold):
    """Evaluate AUTH-004 Incident escalation conditions (design doc 6.2).
    Returns (should_escalate, reason_note).
    """
    if failure_count < fts_threshold:
        return False, (
            f"AUTH-004 signal only (failure_count={failure_count} < threshold={fts_threshold})."
        )

    reasons = []

    if event.username in PRIVILEGED_ACCOUNTS:
        reasons.append(f"privileged account ({event.username})")

    if not is_known_ip:
        reasons.append("source IP not in known_ips")

    for prior_rule in (RuleId.AUTH_BRUTE_FORCE, RuleId.AUTH_INVALID_USER):
        key = _prior_signal_key(event.tenant_id, event.asset_id, event.source_ip, prior_rule)
        if await redis.exists(key):
            reasons.append(f"preceded by {prior_rule.value}")
            break

    if not reasons:
        return False, (
            f"AUTH-004 signal only (count={failure_count}, known_ip={is_known_ip}, "
            "no preceding AUTH-001/003)."
        )

    note = "Failed then success - escalated: " + "; ".join(reasons) + "."
    return True, note


async def _resolve_known_ip(redis, event):
    """Return (seen_before, is_known) for the current source_ip/username pair."""
    known_ip_key = keys.auth_known_ip(event.tenant_id, event.asset_id, event.username)
    seen_before = int(await redis.scard(known_ip_key))
    is_known = bool(await redis.sismember(known_ip_key, event.source_ip))

    if not seen_before:
        try:
            from app.db.repositories import get_known_ip_count, is_known_ip_for_user
            db_count = await get_known_ip_count(event.tenant_id, event.asset_id, event.username)
            if db_count > 0:
                seen_before = db_count
                is_known = await is_known_ip_for_user(
                    event.tenant_id, event.asset_id, event.username, event.source_ip
                )
                await redis.sadd(known_ip_key, event.source_ip)
                await redis.expire(known_ip_key, 86400)
        except Exception:
            pass

    return seen_before, is_known


async def _persist_known_ip(redis, event):
    """Add source_ip to known_ips Redis set and DB."""
    known_ip_key = keys.auth_known_ip(event.tenant_id, event.asset_id, event.username)
    await redis.sadd(known_ip_key, event.source_ip)
    await redis.expire(known_ip_key, 86400)
    try:
        from app.db.repositories import upsert_known_ip
        await upsert_known_ip(event.tenant_id, event.asset_id, event.username, event.source_ip)
    except Exception:
        pass


async def evaluate_rules(redis: Redis, event: NormalizedEvent) -> list[Signal]:
    signals: list[Signal] = []
    if not event.source_ip:
        return signals

    cfg = await get_rule_settings(redis, event.tenant_id)
    bf_window = cfg.auth_brute_force_window_seconds
    bf_threshold = cfg.auth_brute_force_threshold
    inv_window = cfg.auth_invalid_user_window_seconds
    inv_threshold = cfg.auth_invalid_user_threshold
    fts_window = cfg.auth_fail_then_success_window_seconds
    fts_threshold = cfg.auth_fail_then_success_threshold

    now_score = event.timestamp.timestamp()
    fail_ip_key = keys.auth_fail_ip(event.tenant_id, event.asset_id, event.source_ip)
    invalid_key = keys.auth_invalid_user(event.tenant_id, event.asset_id, event.source_ip)

    # AUTH-001: SSH Brute Force
    if event.result == "failed":
        await redis.zadd(fail_ip_key, {event.event_id: now_score})
        await redis.zremrangebyscore(fail_ip_key, 0, now_score - bf_window)
        await redis.expire(fail_ip_key, bf_window * 2)
        failed_count = await redis.zcard(fail_ip_key)
        if failed_count >= bf_threshold:
            triggering = await _window_event_ids(redis, fail_ip_key, now_score - bf_window, now_score)
            signals.append(_signal(
                RuleId.AUTH_BRUTE_FORCE, event, int(failed_count),
                f"{bf_threshold}+ SSH failures from one IP within {bf_window}s.",
                triggering,
            ))
            await redis.set(
                _prior_signal_key(event.tenant_id, event.asset_id, event.source_ip, RuleId.AUTH_BRUTE_FORCE),
                "1", ex=_PRIOR_SIGNAL_TTL,
            )

    # AUTH-003: Invalid User Enumeration
    if event.event_type == EventType.SSH_INVALID_USER:
        await redis.zadd(invalid_key, {event.event_id: now_score})
        await redis.zremrangebyscore(invalid_key, 0, now_score - inv_window)
        await redis.expire(invalid_key, inv_window * 2)
        invalid_count = await redis.zcard(invalid_key)
        if invalid_count >= inv_threshold:
            triggering = await _window_event_ids(redis, invalid_key, now_score - inv_window, now_score)
            signals.append(_signal(
                RuleId.AUTH_INVALID_USER, event, int(invalid_count),
                f"{inv_threshold}+ invalid-user probes from one IP within {inv_window}s.",
                triggering,
            ))
            await redis.set(
                _prior_signal_key(event.tenant_id, event.asset_id, event.source_ip, RuleId.AUTH_INVALID_USER),
                "1", ex=_PRIOR_SIGNAL_TTL,
            )

    # AUTH-002: Root Login Attempt
    if event.username == "root":
        signals.append(_signal(RuleId.AUTH_ROOT_LOGIN, event, note="Root account was used."))

    # AUTH-004 / AUTH-005 on login success
    if event.event_type == EventType.SSH_LOGIN_SUCCESS and event.username:
        fail_user_key = keys.auth_fail_user_ip(
            event.tenant_id, event.asset_id, event.username, event.source_ip,
        )
        failure_count = int(await redis.zcard(fail_user_key))

        if failure_count:
            triggering = await _window_event_ids(redis, fail_user_key, now_score - fts_window, now_score)
            triggering.append(event.event_id)

            seen_before, is_known = await _resolve_known_ip(redis, event)

            should_escalate, reason_note = await _check_auth004_escalation(
                redis, event,
                failure_count=failure_count,
                is_known_ip=is_known,
                fts_threshold=fts_threshold,
            )
            signals.append(_signal(
                RuleId.AUTH_FAILED_THEN_SUCCESS, event, failure_count + 1,
                reason_note, triggering, escalate=should_escalate,
            ))

            await _persist_known_ip(redis, event)

            if seen_before and not is_known:
                signals.append(_signal(
                    RuleId.AUTH_SUSPICIOUS_LOGIN, event,
                    note="Login from a source IP not previously seen for this user.",
                ))
        else:
            seen_before, is_known = await _resolve_known_ip(redis, event)
            await _persist_known_ip(redis, event)
            if seen_before and not is_known:
                signals.append(_signal(
                    RuleId.AUTH_SUSPICIOUS_LOGIN, event,
                    note="Login from a source IP not previously seen for this user.",
                ))

    # Accumulate fail_user_ip for AUTH-004 look-back
    if event.result == "failed" and event.username:
        fail_user_key = keys.auth_fail_user_ip(
            event.tenant_id, event.asset_id, event.username, event.source_ip,
        )
        await redis.zadd(fail_user_key, {event.event_id: now_score})
        await redis.zremrangebyscore(fail_user_key, 0, now_score - fts_window)
        await redis.expire(fail_user_key, fts_window + 300)

    # AUTH-006: 비업무 시간대 로그인 (KST 00:00~06:00 = UTC 15:00~21:00)
    if event.event_type == EventType.SSH_LOGIN_SUCCESS and cfg.off_hours_enabled:
        kst_hour = (event.timestamp.astimezone(timezone.utc).hour + 9) % 24
        off_start = cfg.off_hours_start_kst   # 기본 0 (자정)
        off_end = cfg.off_hours_end_kst       # 기본 6 (오전 6시)
        in_off_hours = (
            (off_start < off_end and off_start <= kst_hour < off_end)
            or (off_start >= off_end and (kst_hour >= off_start or kst_hour < off_end))
        )
        if in_off_hours:
            signals.append(_signal(
                RuleId.AUTH_OFF_HOURS_LOGIN, event,
                note=(
                    f"Login at KST {kst_hour:02d}:xx — outside business hours "
                    f"({off_start:02d}:00~{off_end:02d}:00 flagged)."
                ),
            ))

    # AUTH-006A / AUTH-006B: Credential Stuffing / Password Spraying (설계서 3.1)
    if event.result == "failed" and event.username:
        stuffing_user_key = keys.auth_stuffing_user_to_ips(event.tenant_id, event.asset_id, event.username)
        stuffing_ip_key   = keys.auth_stuffing_ip_to_users(event.tenant_id, event.asset_id, event.source_ip)
        _STUFFING_TTL = 3600  # 1h window

        await redis.sadd(stuffing_user_key, event.source_ip)
        await redis.expire(stuffing_user_key, _STUFFING_TTL)

        await redis.sadd(stuffing_ip_key, event.username)
        await redis.expire(stuffing_ip_key, _STUFFING_TTL)

        # AUTH-006A: Credential Stuffing — 동일 username, 1h 내 3개 이상 다른 source_ip
        ip_count = int(await redis.scard(stuffing_user_key))
        if ip_count >= 3:
            signals.append(_signal(
                RuleId.AUTH_CRED_STUFFING, event, ip_count,
                note=f"Credential Stuffing (AUTH-006A): {ip_count} different IPs tried username '{event.username}' within 1h.",
            ))

        # AUTH-006B: Password Spraying — 동일 source_ip, 1h 내 5개 이상 다른 username
        user_count = int(await redis.scard(stuffing_ip_key))
        if user_count >= 5:
            signals.append(_signal(
                RuleId.AUTH_PASSWORD_SPRAYING, event, user_count,
                note=f"Password Spraying (AUTH-006B): {user_count} different usernames tried from {event.source_ip} within 1h.",
            ))

    # AUTH-007: 해외 IP 로그인 (GeoIP 기반, 허용 국가 외)
    if event.event_type == EventType.SSH_LOGIN_SUCCESS and cfg.foreign_login_enabled:
        try:
            import geoip2.database  # type: ignore

            from app.config import get_settings as _get_settings
            db_path = _get_settings().maxmind_db_path
            with geoip2.database.Reader(db_path) as reader:
                geo = reader.city(event.source_ip)
                country = geo.country.iso_code or "XX"
            allowed = {c.strip().upper() for c in cfg.allowed_countries.split(",")}
            if country not in allowed:
                signals.append(_signal(
                    RuleId.AUTH_FOREIGN_IP_LOGIN, event,
                    note=f"Login from foreign country: {country} (allowed: {cfg.allowed_countries}).",
                ))
        except Exception:
            pass  # GeoIP DB 없거나 사설 IP면 조용히 스킵

    return signals
