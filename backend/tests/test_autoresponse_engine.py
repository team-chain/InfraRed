"""Auto-Response Engine 단위 테스트.

설계서 v3 §5 기반 — 정책 기반 대응, 사설IP 안전장치, 승인 큐.

⚠️ stub 설정은 setup_module/teardown_module으로 격리.
   모듈 레벨 코드가 다른 테스트를 오염하지 않도록 함.
"""
from __future__ import annotations

import sys
from types import ModuleType
from unittest.mock import AsyncMock, MagicMock

import pytest

# 저장해 둘 원본 모듈 참조
_SAVED: dict = {}

_STUB_NAMES = [
    "app.db", "app.db.connection", "app.db.repositories",
    "app.redis_kv", "app.redis_kv.client", "app.redis_kv.keys",
    "app.iam.security", "asyncpg", "app.models.auto_response",
    "app.models.llm",
]


def setup_module(module) -> None:  # noqa: ANN001
    """테스트 모듈 시작 전 stub 설정."""
    # 1. 기존 모듈 상태 저장
    for name in _STUB_NAMES:
        _SAVED[name] = sys.modules.get(name)

    # 2. stub 주입
    def _stub(name: str) -> ModuleType:
        m = ModuleType(name)
        m.__spec__ = None
        return m

    for name in _STUB_NAMES:
        if sys.modules.get(name) is None or not hasattr(sys.modules.get(name, None), "__file__"):
            sys.modules[name] = _stub(name)

    # DB session stub
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=MagicMock())
    cm.__aexit__ = AsyncMock(return_value=False)
    sys.modules["app.db.connection"].get_session = MagicMock(return_value=cm)

    # repository stubs
    sys.modules["app.db.repositories"].save_auto_response_log = AsyncMock()
    sys.modules["app.db.repositories"].save_or_merge_incident = AsyncMock()

    # redis stub
    redis = MagicMock()
    redis.get = AsyncMock(return_value=None)
    redis.set = AsyncMock(return_value=True)
    redis.sadd = AsyncMock(return_value=1)
    redis.srem = AsyncMock(return_value=1)
    redis.sismember = AsyncMock(return_value=False)
    redis.lpush = AsyncMock()
    redis.expire = AsyncMock()
    sys.modules["app.redis_kv.client"].get_redis = MagicMock(return_value=redis)

    # keys stubs
    sys.modules["app.redis_kv.keys"].policy_autoresponse = lambda t: f"policy:{t}"
    sys.modules["app.redis_kv.keys"].policy_version     = lambda t: f"version:{t}"
    sys.modules["app.redis_kv.keys"].policy_allowlist   = lambda t: f"allowlist:{t}"
    sys.modules["app.redis_kv.keys"].policy_watchlist   = lambda t: f"watchlist:{t}"
    sys.modules["app.redis_kv.keys"].policy_denylist    = lambda t: f"denylist:{t}"

    # models stubs
    sys.modules["app.models.auto_response"].AutoResponseLog = type(
        "AutoResponseLog", (), {"__init__": lambda self, **kw: None}
    )
    if not hasattr(sys.modules.get("app.models.llm", _stub("x")), "LLMResult"):
        sys.modules["app.models.llm"].LLMResult = type(
            "LLMResult", (), {"recommended_actions": []}
        )
        sys.modules["app.models.llm"].LLMInput = type("LLMInput", (), {})
        sys.modules["app.models.llm"].LLMPendingRow = type("LLMPendingRow", (), {})

    # sqlalchemy.text stub
    if "sqlalchemy" not in sys.modules or not hasattr(sys.modules.get("sqlalchemy"), "text"):
        sq = _stub("sqlalchemy")
        sq.text = lambda s: s
        sys.modules["sqlalchemy"] = sq

    # iam.security stub
    sys.modules["app.iam.security"].get_current_user = MagicMock()

    # autoresponse 모듈 캐시 제거 (재로딩 보장)
    for mod in list(sys.modules.keys()):
        if "app.autoresponse" in mod:
            del sys.modules[mod]


def teardown_module(module) -> None:  # noqa: ANN001
    """테스트 모듈 종료 후 원본 모듈 복원."""
    # autoresponse 모듈 캐시 제거
    for mod in list(sys.modules.keys()):
        if "app.autoresponse" in mod:
            del sys.modules[mod]

    # 원본 복원
    for name, original in _SAVED.items():
        if original is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = original
    _SAVED.clear()


# ─── _is_safe_ip 단위 테스트 ──────────────────────────────────────────────────

def test_private_ips_are_safe() -> None:
    """사설 IP는 안전 IP로 판별돼야 한다 (설계서 6.7)."""
    from app.autoresponse.engine import _is_safe_ip
    for ip in ("10.0.0.1", "172.16.5.1", "192.168.1.100", "127.0.0.1"):
        assert _is_safe_ip(ip) is True, f"{ip} should be safe"


def test_public_ips_are_not_safe() -> None:
    """공인 IP는 안전 IP가 아니어야 한다."""
    from app.autoresponse.engine import _is_safe_ip
    for ip in ("203.0.113.1", "8.8.8.8", "1.1.1.1"):
        assert _is_safe_ip(ip) is False, f"{ip} should not be safe"


def test_none_ip_is_safe() -> None:
    from app.autoresponse.engine import _is_safe_ip
    assert _is_safe_ip(None) is True


def test_invalid_ip_is_safe() -> None:
    from app.autoresponse.engine import _is_safe_ip
    assert _is_safe_ip("not-an-ip") is True


# ─── _get_v3_action 정책 매트릭스 ─────────────────────────────────────────────

def test_critical_high_confidence_blocks_via_iptables() -> None:
    from app.autoresponse.engine import _get_v3_action
    r = _get_v3_action("critical", 0.90, False)
    assert r["action"] == "iptables_block"
    assert r["approval_required"] is False
    assert r["ttl_seconds"] == 1800


def test_critical_low_confidence_queues_approval() -> None:
    from app.autoresponse.engine import _get_v3_action
    r = _get_v3_action("critical", 0.70, False)
    assert r["action"] == "service_block_pending_approval"
    assert r["approval_required"] is True


def test_high_severity_service_block() -> None:
    from app.autoresponse.engine import _get_v3_action
    r = _get_v3_action("high", 0.80, False)
    assert r["action"] == "service_block"
    assert r["ttl_seconds"] == 900


def test_allowlist_ip_gets_watchlist_only() -> None:
    from app.autoresponse.engine import _get_v3_action
    r = _get_v3_action("critical", 0.95, in_allowlist=True)
    assert r["action"] == "watchlist_only"
    assert r["approval_required"] is False


def test_medium_severity_watchlist_notify() -> None:
    from app.autoresponse.engine import _get_v3_action
    r = _get_v3_action("medium", 0.60, False)
    assert r["action"] == "watchlist_notify"


# ─── build_actions_from_llm 테스트 ───────────────────────────────────────────

def test_block_ip_action_from_llm_text() -> None:
    from app.autoresponse.actions import build_actions_from_llm, ActionType
    actions = build_actions_from_llm(
        incident_id="INC-001", source_ip="1.2.3.4",
        username=None, severity="critical",
        recommended_actions=["해당 IP를 즉시 차단하세요."],
    )
    assert ActionType.BLOCK_IP in [a["action_type"] for a in actions]


def test_lock_account_action_from_llm_text() -> None:
    from app.autoresponse.actions import build_actions_from_llm, ActionType
    actions = build_actions_from_llm(
        incident_id="INC-002", source_ip=None,
        username="admin", severity="high",
        recommended_actions=["해당 계정을 잠금 처리하십시오."],
    )
    assert ActionType.LOCK_ACCOUNT in [a["action_type"] for a in actions]


def test_no_actions_defaults_to_notify() -> None:
    from app.autoresponse.actions import build_actions_from_llm, ActionType
    actions = build_actions_from_llm(
        incident_id="INC-003", source_ip="2.2.2.2",
        username="user", severity="medium",
        recommended_actions=["로그를 분석하세요."],
    )
    assert ActionType.NOTIFY in [a["action_type"] for a in actions]


def test_should_auto_execute_in_auto_mode() -> None:
    from app.autoresponse.actions import should_auto_execute
    assert should_auto_execute("auto", "critical", "critical") is True
    assert should_auto_execute("auto", "high", "critical") is False
    assert should_auto_execute("manual", "critical", "critical") is False


def test_should_queue_approval_in_approval_mode() -> None:
    from app.autoresponse.actions import should_queue_approval
    assert should_queue_approval("approval", "high", "high") is True
    assert should_queue_approval("manual", "critical", "critical") is False
