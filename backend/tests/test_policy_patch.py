"""PATCH /api/policy/* 엔드포인트 단위 테스트 (설계서 6.6).

DB·Redis를 sys.modules + monkeypatch로 격리해 외부 의존성 없이 실행.
"""
from __future__ import annotations

import sys
from types import ModuleType, SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest


# ── DB / Redis / Config 모듈을 import 전에 stub으로 교체 ─────────────────────
# app.db.connection이 import 시점에 asyncpg engine을 생성하므로 미리 격리.

def _make_stub(name: str) -> ModuleType:
    mod = ModuleType(name)
    mod.__spec__ = None
    return mod


for _stub_name in [
    "app.db",
    "app.db.connection",
    "app.db.repositories",
    "app.redis_kv",
    "app.redis_kv.client",
    "app.redis_kv.keys",
    "app.iam.security",
    "asyncpg",
]:
    if _stub_name not in sys.modules:
        sys.modules[_stub_name] = _make_stub(_stub_name)

# get_session stub (async context manager)
_cm = MagicMock()
_cm.__aenter__ = AsyncMock(return_value=MagicMock())
_cm.__aexit__ = AsyncMock(return_value=False)
sys.modules["app.db.connection"].get_session = MagicMock(return_value=_cm)

# get_redis stub (async context manager)
_redis_cm = MagicMock()
_redis_cm.__aenter__ = AsyncMock(return_value=MagicMock())
_redis_cm.__aexit__ = AsyncMock(return_value=False)
sys.modules["app.redis_kv.client"].get_redis = MagicMock(return_value=_redis_cm)

# get_current_user stub (policy_routes.py imports as `verify_user_token as get_current_user`)
sys.modules["app.iam.security"].verify_user_token = MagicMock()
sys.modules["app.iam.security"].get_current_user = MagicMock()

# ── 이제 안전하게 import ──────────────────────────────────────────────────────
from app.common.constants import PolicyType          # noqa: E402
from app.models.ip_policy import (                   # noqa: E402
    AgentAccessPatch,
    DashboardAccessPatch,
    IpPolicy,
    ThreatIpPatch,
)
from app.ingestion import policy_routes              # noqa: E402


# ── 공통 헬퍼 ─────────────────────────────────────────────────────────────────

TENANT = "company-a"
USER   = {"tenant_id": TENANT, "email": "admin@test.com", "role": "admin"}


def _policy(policy_type: PolicyType, **kw) -> IpPolicy:
    return IpPolicy(tenant_id=TENANT, policy_type=policy_type, **kw)


class _Req:
    """최소 Request stub — 요청자 IP = 127.0.0.1."""
    headers: dict = {}
    client = SimpleNamespace(host="127.0.0.1")


class _RemoteReq:
    """요청자 IP = 외부망 (lockout warning 테스트용)."""
    headers: dict = {}
    client = SimpleNamespace(host="203.0.113.99")


def _fake_sync(version: int = 2):
    async def _inner(tenant_id, policy): return version
    return _inner


def _fake_save():
    async def _inner(tenant_id, policy, updated_by): pass
    return _inner


# ── AgentAccess PATCH ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_patch_agent_add(monkeypatch):
    """add_agents → 기존 목록에 항목 추가."""
    cur = _policy(PolicyType.AGENT_ACCESS, allowed_agents=["agent-001", "agent-002"])
    monkeypatch.setattr(policy_routes, "_load_policy_from_db", AsyncMock(return_value=cur))
    monkeypatch.setattr(policy_routes, "_sync_policy_to_redis", _fake_sync(3))
    monkeypatch.setattr(policy_routes, "_save_policy_to_db", _fake_save())

    res = await policy_routes.patch_agent_access_policy(
        AgentAccessPatch(add_agents=["agent-003"]), _Req(), USER
    )
    assert res["allowed_agents"] == ["agent-001", "agent-002", "agent-003"]
    assert res["policy_version"] == 3
    assert res["previous_count"] == 2 and res["current_count"] == 3


@pytest.mark.asyncio
async def test_patch_agent_remove(monkeypatch):
    """remove_agents → 기존 목록에서 항목 제거."""
    cur = _policy(PolicyType.AGENT_ACCESS, allowed_agents=["agent-001", "agent-002", "agent-003"])
    monkeypatch.setattr(policy_routes, "_load_policy_from_db", AsyncMock(return_value=cur))
    monkeypatch.setattr(policy_routes, "_sync_policy_to_redis", _fake_sync(4))
    monkeypatch.setattr(policy_routes, "_save_policy_to_db", _fake_save())

    res = await policy_routes.patch_agent_access_policy(
        AgentAccessPatch(remove_agents=["agent-002"]), _Req(), USER
    )
    assert res["allowed_agents"] == ["agent-001", "agent-003"]
    assert res["current_count"] == 2


@pytest.mark.asyncio
async def test_patch_agent_replace(monkeypatch):
    """allowed_agents → 목록 전체 교체."""
    cur = _policy(PolicyType.AGENT_ACCESS, allowed_agents=["agent-001"])
    monkeypatch.setattr(policy_routes, "_load_policy_from_db", AsyncMock(return_value=cur))
    monkeypatch.setattr(policy_routes, "_sync_policy_to_redis", _fake_sync(5))
    monkeypatch.setattr(policy_routes, "_save_policy_to_db", _fake_save())

    res = await policy_routes.patch_agent_access_policy(
        AgentAccessPatch(allowed_agents=["agent-010", "agent-020"]), _Req(), USER
    )
    assert res["allowed_agents"] == ["agent-010", "agent-020"]


@pytest.mark.asyncio
async def test_patch_agent_empty_result_raises_400(monkeypatch):
    """remove 결과가 빈 배열 → 400."""
    from fastapi import HTTPException
    cur = _policy(PolicyType.AGENT_ACCESS, allowed_agents=["agent-001"])
    monkeypatch.setattr(policy_routes, "_load_policy_from_db", AsyncMock(return_value=cur))
    monkeypatch.setattr(policy_routes, "_sync_policy_to_redis", _fake_sync())
    monkeypatch.setattr(policy_routes, "_save_policy_to_db", _fake_save())

    with pytest.raises(HTTPException) as exc:
        await policy_routes.patch_agent_access_policy(
            AgentAccessPatch(remove_agents=["agent-001"]), _Req(), USER
        )
    assert exc.value.status_code == 400


@pytest.mark.asyncio
async def test_patch_agent_no_duplicate(monkeypatch):
    """add_agents에 이미 있는 항목은 중복 추가 안 됨."""
    cur = _policy(PolicyType.AGENT_ACCESS, allowed_agents=["agent-001", "agent-002"])
    monkeypatch.setattr(policy_routes, "_load_policy_from_db", AsyncMock(return_value=cur))
    monkeypatch.setattr(policy_routes, "_sync_policy_to_redis", _fake_sync())
    monkeypatch.setattr(policy_routes, "_save_policy_to_db", _fake_save())

    res = await policy_routes.patch_agent_access_policy(
        AgentAccessPatch(add_agents=["agent-001", "agent-003"]), _Req(), USER
    )
    assert res["allowed_agents"].count("agent-001") == 1
    assert "agent-003" in res["allowed_agents"]


# ── ThreatIp PATCH ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_patch_threat_ip_mode_only(monkeypatch):
    """mode만 변경 — 나머지 필드는 그대로 유지."""
    cur = _policy(PolicyType.THREAT_IP,
                  mode="allow_all", allowlist=["192.168.1.0/24"],
                  denylist=["1.2.3.4"], country_block=["CN"])
    monkeypatch.setattr(policy_routes, "_load_policy_from_db", AsyncMock(return_value=cur))
    monkeypatch.setattr(policy_routes, "_sync_policy_to_redis", _fake_sync(6))
    monkeypatch.setattr(policy_routes, "_save_policy_to_db", _fake_save())

    res = await policy_routes.patch_threat_ip_policy(
        ThreatIpPatch(mode="allowlist_only"), _Req(), USER
    )
    assert res["mode"] == "allowlist_only"
    assert res["allowlist_count"] == 1
    assert res["denylist_count"] == 1
    assert res["country_block_count"] == 1


@pytest.mark.asyncio
async def test_patch_threat_ip_add_denylist(monkeypatch):
    """add_denylist → denylist에 항목 추가."""
    cur = _policy(PolicyType.THREAT_IP, denylist=["1.2.3.4"])
    monkeypatch.setattr(policy_routes, "_load_policy_from_db", AsyncMock(return_value=cur))
    monkeypatch.setattr(policy_routes, "_sync_policy_to_redis", _fake_sync(7))
    monkeypatch.setattr(policy_routes, "_save_policy_to_db", _fake_save())

    res = await policy_routes.patch_threat_ip_policy(
        ThreatIpPatch(add_denylist=["5.6.7.8", "9.10.11.12"]), _Req(), USER
    )
    assert res["denylist_count"] == 3


@pytest.mark.asyncio
async def test_patch_threat_ip_country_block_uppercase(monkeypatch):
    """소문자 국가 코드 입력 → 자동 대문자 정규화."""
    cur = _policy(PolicyType.THREAT_IP, country_block=["CN"])
    monkeypatch.setattr(policy_routes, "_load_policy_from_db", AsyncMock(return_value=cur))
    monkeypatch.setattr(policy_routes, "_sync_policy_to_redis", _fake_sync())
    monkeypatch.setattr(policy_routes, "_save_policy_to_db", _fake_save())

    res = await policy_routes.patch_threat_ip_policy(
        ThreatIpPatch(add_country_block=["ru", "kp"]), _Req(), USER
    )
    assert res["country_block_count"] == 3  # CN + RU + KP


@pytest.mark.asyncio
async def test_patch_threat_ip_remove_allowlist(monkeypatch):
    """remove_allowlist → allowlist에서 항목 제거."""
    cur = _policy(PolicyType.THREAT_IP,
                  allowlist=["192.168.1.0/24", "10.0.0.1", "172.16.0.0/12"])
    monkeypatch.setattr(policy_routes, "_load_policy_from_db", AsyncMock(return_value=cur))
    monkeypatch.setattr(policy_routes, "_sync_policy_to_redis", _fake_sync())
    monkeypatch.setattr(policy_routes, "_save_policy_to_db", _fake_save())

    res = await policy_routes.patch_threat_ip_policy(
        ThreatIpPatch(remove_allowlist=["10.0.0.1"]), _Req(), USER
    )
    assert res["allowlist_count"] == 2


@pytest.mark.asyncio
async def test_patch_threat_ip_invalid_cidr_raises_400(monkeypatch):
    """잘못된 CIDR 형식 → 400."""
    from fastapi import HTTPException
    cur = _policy(PolicyType.THREAT_IP)
    monkeypatch.setattr(policy_routes, "_load_policy_from_db", AsyncMock(return_value=cur))
    monkeypatch.setattr(policy_routes, "_sync_policy_to_redis", _fake_sync())
    monkeypatch.setattr(policy_routes, "_save_policy_to_db", _fake_save())

    with pytest.raises(HTTPException) as exc:
        await policy_routes.patch_threat_ip_policy(
            ThreatIpPatch(add_denylist=["not-an-ip"]), _Req(), USER
        )
    assert exc.value.status_code == 400


# ── DashboardAccess PATCH ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_patch_dashboard_add(monkeypatch):
    """add_allowlist → 기존 목록에 항목 추가."""
    cur = _policy(PolicyType.DASHBOARD_ACCESS, allowlist=["192.168.1.0/24"])
    monkeypatch.setattr(policy_routes, "_load_policy_from_db", AsyncMock(return_value=cur))
    monkeypatch.setattr(policy_routes, "_sync_policy_to_redis", _fake_sync(8))
    monkeypatch.setattr(policy_routes, "_save_policy_to_db", _fake_save())

    res = await policy_routes.patch_dashboard_access_policy(
        DashboardAccessPatch(add_allowlist=["10.0.0.0/8"]), _Req(), USER
    )
    assert res["current_count"] == 2 and res["previous_count"] == 1
    assert "10.0.0.0/8" in res["allowlist"]


@pytest.mark.asyncio
async def test_patch_dashboard_remove(monkeypatch):
    """remove_allowlist → 기존 목록에서 항목 제거."""
    cur = _policy(PolicyType.DASHBOARD_ACCESS, allowlist=["192.168.1.0/24", "10.0.0.1"])
    monkeypatch.setattr(policy_routes, "_load_policy_from_db", AsyncMock(return_value=cur))
    monkeypatch.setattr(policy_routes, "_sync_policy_to_redis", _fake_sync())
    monkeypatch.setattr(policy_routes, "_save_policy_to_db", _fake_save())

    res = await policy_routes.patch_dashboard_access_policy(
        DashboardAccessPatch(remove_allowlist=["10.0.0.1"]), _Req(), USER
    )
    assert res["current_count"] == 1
    assert "10.0.0.1" not in res["allowlist"]


@pytest.mark.asyncio
async def test_patch_dashboard_replace(monkeypatch):
    """allowlist → 전체 교체."""
    cur = _policy(PolicyType.DASHBOARD_ACCESS, allowlist=["1.2.3.4"])
    monkeypatch.setattr(policy_routes, "_load_policy_from_db", AsyncMock(return_value=cur))
    monkeypatch.setattr(policy_routes, "_sync_policy_to_redis", _fake_sync())
    monkeypatch.setattr(policy_routes, "_save_policy_to_db", _fake_save())

    res = await policy_routes.patch_dashboard_access_policy(
        DashboardAccessPatch(allowlist=["192.168.0.0/16"]), _Req(), USER
    )
    assert res["allowlist"] == ["192.168.0.0/16"]


@pytest.mark.asyncio
async def test_patch_dashboard_lockout_warning(monkeypatch):
    """요청자 IP가 변경 후 allowlist에 없으면 warning 반환."""
    cur = _policy(PolicyType.DASHBOARD_ACCESS, allowlist=[])
    monkeypatch.setattr(policy_routes, "_load_policy_from_db", AsyncMock(return_value=cur))
    monkeypatch.setattr(policy_routes, "_sync_policy_to_redis", _fake_sync())
    monkeypatch.setattr(policy_routes, "_save_policy_to_db", _fake_save())

    res = await policy_routes.patch_dashboard_access_policy(
        DashboardAccessPatch(allowlist=["192.168.1.0/24"]), _RemoteReq(), USER
    )
    assert res["warning"] is not None
    assert "203.0.113.99" in res["warning"]


@pytest.mark.asyncio
async def test_patch_dashboard_no_lockout_when_ip_included(monkeypatch):
    """요청자 IP가 CIDR 안에 포함되면 warning 없음."""
    class _LocalReq:
        headers: dict = {}
        client = SimpleNamespace(host="192.168.1.10")

    cur = _policy(PolicyType.DASHBOARD_ACCESS, allowlist=[])
    monkeypatch.setattr(policy_routes, "_load_policy_from_db", AsyncMock(return_value=cur))
    monkeypatch.setattr(policy_routes, "_sync_policy_to_redis", _fake_sync())
    monkeypatch.setattr(policy_routes, "_save_policy_to_db", _fake_save())

    res = await policy_routes.patch_dashboard_access_policy(
        DashboardAccessPatch(allowlist=["192.168.1.0/24"]), _LocalReq(), USER
    )
    assert res["warning"] is None


# ── 순수 로직 테스트 (_apply_list_patch) ─────────────────────────────────────

def test_apply_list_patch_replace_wins():
    """replace와 add/remove 동시 전달 시 replace 우선."""
    assert policy_routes._apply_list_patch(
        ["a", "b"], replace=["x"], add=["y"], remove=["a"]
    ) == ["x"]


def test_apply_list_patch_dedup_on_replace():
    """replace 시 중복 제거, 순서 유지."""
    assert policy_routes._apply_list_patch(
        [], replace=["c", "a", "b", "a", "c"], add=None, remove=None
    ) == ["c", "a", "b"]


def test_apply_list_patch_add_skips_existing():
    """add 시 이미 있는 항목은 추가 안 됨."""
    assert policy_routes._apply_list_patch(
        ["a", "b"], replace=None, add=["b", "c"], remove=None
    ) == ["a", "b", "c"]


def test_apply_list_patch_noop():
    """add/remove 모두 None → 현재 목록 그대로."""
    assert policy_routes._apply_list_patch(
        ["a", "b"], replace=None, add=None, remove=None
    ) == ["a", "b"]


# ── Pydantic validator 테스트 ─────────────────────────────────────────────────

def test_patch_model_rejects_empty_body():
    """아무 필드도 없는 body는 validator에서 거부."""
    from pydantic import ValidationError
    for cls in [AgentAccessPatch, ThreatIpPatch, DashboardAccessPatch]:
        with pytest.raises((ValidationError, ValueError)):
            cls()
