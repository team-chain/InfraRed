"""Suppression / Allowlist / Maintenance Window 라우터 단위 테스트.

설계서 Phase 2-C §6 기반.
stub 설정을 setup_module/teardown_module로 격리.
"""
from __future__ import annotations

import sys
from types import ModuleType
from unittest.mock import AsyncMock, MagicMock

import pytest

_SAVED: dict = {}
_STUBS = ["app.db", "app.db.connection", "app.db.repositories",
          "app.redis_kv", "app.redis_kv.client", "app.redis_kv.keys",
          "app.iam.security", "asyncpg"]


def setup_module(module) -> None:  # noqa: ANN001
    for n in _STUBS:
        _SAVED[n] = sys.modules.get(n)
        if n not in sys.modules:
            m = ModuleType(n); m.__spec__ = None; sys.modules[n] = m

    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=MagicMock())
    cm.__aexit__ = AsyncMock(return_value=False)
    sys.modules["app.db.connection"].get_session = MagicMock(return_value=cm)

    async def _fake_verify() -> dict:
        return {"tenant_id": "t1", "role": "admin", "email": "admin@test.com"}
    def _fake_require_permission(perm: str):
        async def dep() -> dict:
            return {"tenant_id": "t1", "role": "admin"}
        return dep

    sys.modules["app.iam.security"].get_current_user = _fake_verify
    sys.modules["app.iam.security"].require_permission = _fake_require_permission
    sys.modules["app.iam.security"].verify_user_token = _fake_verify
    sys.modules["app.redis_kv.client"].get_redis = MagicMock()

    for mod in list(sys.modules.keys()):
        if "app.ingestion.suppression_routes" in mod or "app.iam.rbac_v2" in mod:
            del sys.modules[mod]


def teardown_module(module) -> None:  # noqa: ANN001
    for mod in list(sys.modules.keys()):
        if "app.ingestion.suppression_routes" in mod or "app.iam.rbac_v2" in mod:
            del sys.modules[mod]
    for n, v in _SAVED.items():
        if v is None: sys.modules.pop(n, None)
        else: sys.modules[n] = v
    _SAVED.clear()


# ─── 테스트 ───────────────────────────────────────────────────────────────────

def test_suppression_module_importable() -> None:
    from app.ingestion import suppression_routes
    assert suppression_routes is not None
    assert hasattr(suppression_routes, "router")


def test_router_has_allowlist_routes() -> None:
    from app.ingestion import suppression_routes
    paths = [r.path for r in suppression_routes.router.routes]
    assert any("allowlist" in p for p in paths), f"allowlist 경로 없음: {paths}"


def test_router_has_suppression_routes() -> None:
    from app.ingestion import suppression_routes
    paths = [r.path for r in suppression_routes.router.routes]
    assert any("suppression" in p for p in paths), f"suppression 경로 없음: {paths}"


def test_router_has_maintenance_window_routes() -> None:
    from app.ingestion import suppression_routes
    paths = [r.path for r in suppression_routes.router.routes]
    assert any("maintenance" in p for p in paths), f"maintenance-window 경로 없음: {paths}"


def test_allowlist_entry_model_has_value_field() -> None:
    from app.ingestion.suppression_routes import AllowlistEntry
    import inspect
    fields = inspect.signature(AllowlistEntry).parameters
    assert any(f in fields for f in ("value", "ip_cidr", "pattern", "entry_type")), \
        f"AllowlistEntry 필드 부족: {list(fields)}"


def test_suppression_create_model_exists() -> None:
    from app.ingestion.suppression_routes import SuppressionCreate
    import inspect
    params = inspect.signature(SuppressionCreate).parameters
    assert len(params) >= 1, f"SuppressionCreate 필드 없음: {list(params)}"
