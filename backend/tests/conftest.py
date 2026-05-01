"""Shared pytest fixtures for the B (detection / enrichment / correlation) suite.

These tests are intentionally small and pure: they exercise the parser, rule
engine, and incident builder in isolation so they run without Postgres or a
real Redis. Tests that need an async Redis use ``fakeredis.aioredis``.
"""
from __future__ import annotations

import sys
from pathlib import Path

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
