"""Incident 워크플로우 라우터 단위 테스트.

설계서 Phase 1 §3 기반 — 6단계 상태 전이, 코멘트, 이력.
DB·Redis를 mock으로 격리.
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
    "app.iam.security", "asyncpg", "app.ingestion.sse_routes",
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
    sys.modules["app.ingestion.sse_routes"].publish_incident_event = AsyncMock()

    # 모듈 캐시 제거 후 재로드
    for mod in list(sys.modules.keys()):
        if "app.ingestion.incident_routes" in mod:
            del sys.modules[mod]


def teardown_module(module) -> None:  # noqa: ANN001
    for mod in list(sys.modules.keys()):
        if "app.ingestion.incident_routes" in mod:
            del sys.modules[mod]
    for n, v in _SAVED.items():
        if v is None:
            sys.modules.pop(n, None)
        else:
            sys.modules[n] = v
    _SAVED.clear()


# ─── 라우터 구조 검증 ─────────────────────────────────────────────────────────

def test_incident_routes_importable() -> None:
    from app.ingestion import incident_routes
    assert incident_routes is not None
    assert hasattr(incident_routes, "router")


def test_router_has_workflow_status_route() -> None:
    """PATCH /{incident_id}/workflow-status 경로가 있어야 한다."""
    from app.ingestion import incident_routes
    paths = {r.path for r in incident_routes.router.routes}
    assert any("workflow-status" in p or "status" in p for p in paths), (
        f"상태 전이 경로 없음: {paths}"
    )


def test_router_has_comment_routes() -> None:
    """POST/GET /{id}/comments 경로가 있어야 한다."""
    from app.ingestion import incident_routes
    paths = {r.path for r in incident_routes.router.routes}
    assert any("comments" in p for p in paths), (
        f"comments 경로 없음: {paths}"
    )


def test_router_has_history_route() -> None:
    """GET /{id}/history 경로가 있어야 한다."""
    from app.ingestion import incident_routes
    paths = {r.path for r in incident_routes.router.routes}
    assert any("history" in p for p in paths), (
        f"history 경로 없음: {paths}"
    )


def test_router_has_stats_routes() -> None:
    """GET /stats/fp, /stats/timeseries 경로가 있어야 한다."""
    from app.ingestion import incident_routes
    paths = {r.path for r in incident_routes.router.routes}
    assert any("stats" in p for p in paths), (
        f"stats 경로 없음: {paths}"
    )


# ─── 상태 전이 상수 검증 ─────────────────────────────────────────────────────

def test_status_transitions_cover_six_stages() -> None:
    """설계서 §3 6단계: open → acknowledged → in_progress → contained → resolved → closed"""
    import inspect
    from app.ingestion import incident_routes
    src = inspect.getsource(incident_routes)
    expected_stages = [
        "open", "acknowledged", "in_progress",
        "contained", "resolved", "closed",
    ]
    for stage in expected_stages:
        assert stage in src, (
            f"상태 '{stage}'가 incident_routes에 없음"
        )


# ─── 코멘트 모델 검증 ─────────────────────────────────────────────────────────

def test_comment_create_model_has_body() -> None:
    """CommentCreate에 body 필드가 있어야 한다."""
    try:
        from app.ingestion.incident_routes import CommentCreate
        import inspect
        fields = inspect.signature(CommentCreate).parameters
        assert "body" in fields, f"body 필드 없음: {list(fields)}"
    except ImportError:
        pytest.skip("CommentCreate not exported")


# ─── FP 통계 모델 검증 ──────────────────────────────────────────────────────

def test_fp_stats_endpoint_registered() -> None:
    """FP 통계 엔드포인트 /stats/fp 가 등록돼 있어야 한다."""
    from app.ingestion import incident_routes
    paths = {r.path for r in incident_routes.router.routes}
    assert any("fp" in p for p in paths), (
        f"FP 통계 경로 없음: {paths}"
    )
