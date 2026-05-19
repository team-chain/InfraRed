"""헬스체크 라우터 단위 테스트.

설계서 Phase 1-B §4 기반.
"""
from __future__ import annotations

import sys
from types import ModuleType
from unittest.mock import AsyncMock, MagicMock

import pytest


# ── 격리 헬퍼 ────────────────────────────────────────────────────────────────

_STUBS = [
    "app.db", "app.db.connection", "app.db.repositories",
    "app.redis_kv", "app.redis_kv.client", "app.redis_kv.keys",
    "app.iam.security", "asyncpg", "prometheus_client",
]
_SAVED: dict = {}


def setup_module(module) -> None:  # noqa: ANN001
    for n in _STUBS:
        _SAVED[n] = sys.modules.get(n)
        if n not in sys.modules:
            m = ModuleType(n)
            m.__spec__ = None
            sys.modules[n] = m

    # DB 세션 컨텍스트 매니저 stub
    _cm = MagicMock()
    _cm.__aenter__ = AsyncMock(return_value=MagicMock())
    _cm.__aexit__ = AsyncMock(return_value=False)
    sys.modules["app.db.connection"].get_session = MagicMock(return_value=_cm)

    # IAM security stubs
    async def _fake_verify() -> dict:
        return {"tenant_id": "t1", "role": "admin", "email": "admin@test.com"}

    def _fake_require_permission(perm: str):
        async def dep() -> dict:
            return {"tenant_id": "t1", "role": "admin", "email": "admin@test.com"}
        return dep

    sys.modules["app.iam.security"].get_current_user = _fake_verify
    sys.modules["app.iam.security"].require_permission = _fake_require_permission
    sys.modules["app.iam.security"].verify_user_token = _fake_verify
    sys.modules["app.redis_kv.client"].get_redis = MagicMock()

    # prometheus_client 메트릭 stubs
    for _metric in ["Counter", "Gauge", "Histogram", "Summary"]:
        setattr(sys.modules["prometheus_client"], _metric, MagicMock(return_value=MagicMock()))

    # 모듈 캐시 제거 후 재로드
    for mod in list(sys.modules.keys()):
        if "app.ingestion.health_routes" in mod:
            del sys.modules[mod]


def teardown_module(module) -> None:  # noqa: ANN001
    for mod in list(sys.modules.keys()):
        if "app.ingestion.health_routes" in mod:
            del sys.modules[mod]
    for n, v in _SAVED.items():
        if v is None:
            sys.modules.pop(n, None)
        else:
            sys.modules[n] = v
    _SAVED.clear()


# ─── 기본 라우터 구조 검증 ─────────────────────────────────────────────────────

def test_health_routes_importable() -> None:
    from app.ingestion import health_routes
    assert health_routes is not None
    assert hasattr(health_routes, "router")


def test_dashboard_route_exists() -> None:
    """GET /health/dashboard 경로가 있어야 한다."""
    from app.ingestion import health_routes
    paths = {r.path for r in health_routes.router.routes}
    assert any("dashboard" in p for p in paths), (
        f"dashboard 경로 없음: {paths}"
    )


def test_agents_route_exists() -> None:
    """GET /health/agents 경로가 있어야 한다."""
    from app.ingestion import health_routes
    paths = {r.path for r in health_routes.router.routes}
    assert any("agents" in p for p in paths), (
        f"agents 경로 없음: {paths}"
    )


def test_health_check_components_in_source() -> None:
    """헬스체크 구성 요소들이 소스에 포함돼야 한다."""
    import inspect
    from app.ingestion import health_routes
    src = inspect.getsource(health_routes)
    components = ["agent_connectivity", "detection_stream", "llm_queue"]
    for component in components:
        assert component in src, (
            f"헬스체크 구성 요소 '{component}' 누락"
        )
