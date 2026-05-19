"""Rule 관리 라우터 단위 테스트. 설계서 Phase 2 §5."""
from __future__ import annotations
import sys
from types import ModuleType
from unittest.mock import AsyncMock, MagicMock
import pytest

_SAVED: dict = {}
_STUBS = ["app.db", "app.db.connection", "app.db.repositories",
          "app.redis_kv", "app.redis_kv.client", "app.redis_kv.keys",
          "app.iam.security", "asyncpg"]

def setup_module(module) -> None:
    for n in _STUBS:
        _SAVED[n] = sys.modules.get(n)
        if n not in sys.modules:
            m = ModuleType(n); m.__spec__ = None; sys.modules[n] = m
    cm = MagicMock(); cm.__aenter__ = AsyncMock(return_value=MagicMock()); cm.__aexit__ = AsyncMock(return_value=False)
    sys.modules["app.db.connection"].get_session = MagicMock(return_value=cm)
    async def _fake(): return {"tenant_id": "t1", "role": "admin"}
    def _req_perm(p):
        async def dep(): return {"tenant_id": "t1", "role": "admin"}
        return dep
    sys.modules["app.iam.security"].get_current_user = _fake
    sys.modules["app.iam.security"].require_permission = _req_perm
    sys.modules["app.iam.security"].verify_user_token = _fake
    sys.modules["app.redis_kv.client"].get_redis = MagicMock()
    for mod in list(sys.modules.keys()):
        if "app.ingestion.rule_mgmt" in mod or "app.iam.rbac_v2" in mod:
            del sys.modules[mod]

def teardown_module(module) -> None:
    for mod in list(sys.modules.keys()):
        if "app.ingestion.rule_mgmt" in mod or "app.iam.rbac_v2" in mod:
            del sys.modules[mod]
    for n, v in _SAVED.items():
        if v is None: sys.modules.pop(n, None)
        else: sys.modules[n] = v
    _SAVED.clear()

def test_rule_mgmt_importable() -> None:
    from app.ingestion import rule_mgmt_routes
    assert hasattr(rule_mgmt_routes, "router")

def test_router_has_rules_route() -> None:
    from app.ingestion import rule_mgmt_routes
    paths = {r.path for r in rule_mgmt_routes.router.routes}
    assert any("/rules" in p for p in paths), f"rules 경로 없음: {paths}"

def test_router_has_lifecycle_routes() -> None:
    from app.ingestion import rule_mgmt_routes
    paths = {r.path for r in rule_mgmt_routes.router.routes}
    for kw in ["activate", "dry-run", "rollback", "versions"]:
        assert any(kw in p for p in paths), f"Rule lifecycle 경로 누락 '{kw}': {paths}"

def test_rule_create_model_has_required_fields() -> None:
    from app.ingestion.rule_mgmt_routes import RuleCreateRequest
    import inspect
    fields = inspect.signature(RuleCreateRequest).parameters
    assert len(fields) >= 2, f"RuleCreateRequest 필수 필드 부족: {list(fields)}"

def test_status_transitions_in_source() -> None:
    import inspect
    from app.ingestion import rule_mgmt_routes
    src = inspect.getsource(rule_mgmt_routes)
    for stage in ("draft", "active", "disabled"):
        assert stage in src, f"룰 상태 '{stage}' 누락"
