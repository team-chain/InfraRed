"""Shared pytest fixtures for the InfraRed test suite.

These tests are intentionally small and pure: they exercise the parser, rule
engine, and incident builder in isolation so they run without Postgres or a
real Redis. Tests that need an async Redis use ``fakeredis.aioredis``.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Generator

import pytest

# Make ``backend/app/...`` importable when running ``pytest`` from the repo root.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture
def fake_redis():
    """Async ``fakeredis`` client used in detection-rule tests."""
    fakeredis = pytest.importorskip("fakeredis.aioredis")
    return fakeredis.FakeRedis(decode_responses=True)


# ── sys.modules 격리 픽스처 ────────────────────────────────────────────────────
# 일부 테스트 파일이 app.common.logging 등을 stub으로 교체한다.
# autouse 픽스처로 테스트 간 모듈 누출을 방지한다.

_ISOLATION_MODULES = [
    "app.workers.ueba.autoencoder",
    "app.workers.ueba.features",
    "app.workers.ueba.worker",
    "app.autoresponse.engine",
    "app.autoresponse.actions",
    "app.auth.mfa",
    "app.auth.sso",
    "app.ingestion.suppression_routes",
    "app.ingestion.rule_mgmt_routes",
    "app.ingestion.incident_routes",
    "app.ingestion.health_routes",
    "app.models.auto_response",
    "app.models.llm",
    "app.db.repositories",
    "app.db.connection",
    "app.redis_kv.client",
    "app.redis_kv.keys",
]


@pytest.fixture(autouse=True)
def _isolate_stub_modules() -> Generator[None, None, None]:
    """각 테스트 전후로 stub 교체된 모듈을 제거해 격리를 보장한다."""
    # 테스트 전 상태 스냅샷 (실제 모듈이 이미 로딩된 경우 보존)
    before = {k: v for k, v in sys.modules.items() if k in _ISOLATION_MODULES}

    yield

    # 테스트 후: stub 제거 후 원래 상태 복원
    for mod in _ISOLATION_MODULES:
        sys.modules.pop(mod, None)
    sys.modules.update(before)
