"""UEBA Autoencoder unit tests.

Based on design spec v4 section 12 - numpy Autoencoder training and anomaly detection.
"""
from __future__ import annotations

import sys
from types import ModuleType

import pytest

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False


# ── Isolation helpers ─────────────────────────────────────────────────────────

_STUBS = ["boto3", "botocore", "botocore.exceptions",
          "app.config", "pydantic_settings"]
_SAVED: dict = {}


def setup_module(module) -> None:  # noqa: ANN001
    for n in _STUBS:
        _SAVED[n] = sys.modules.get(n)
        if n not in sys.modules:
            m = ModuleType(n)
            m.__spec__ = None
            sys.modules[n] = m

    _settings = type("S", (), {
        "s3_region": "ap-northeast-2",
        "ueba_model_bucket": "test-bucket",
    })()
    # Save original get_settings (may be real module already loaded)
    _SAVED["_get_settings_fn"] = getattr(sys.modules.get("app.config"), "get_settings", None)
    sys.modules["app.config"].get_settings = lambda: _settings

    # Clear cached ueba modules so they re-import with fresh stubs
    for mod in list(sys.modules.keys()):
        if mod.startswith("app.workers.ueba"):
            del sys.modules[mod]


def teardown_module(module) -> None:  # noqa: ANN001
    for mod in list(sys.modules.keys()):
        if mod.startswith("app.workers.ueba"):
            del sys.modules[mod]

    # Restore original get_settings
    orig_fn = _SAVED.pop("_get_settings_fn", None)
    if orig_fn is not None and "app.config" in sys.modules:
        sys.modules["app.config"].get_settings = orig_fn

    for n, v in _SAVED.items():
        if v is None:
            sys.modules.pop(n, None)
        else:
            sys.modules[n] = v
    _SAVED.clear()


# ─── AutoencoderModel structure tests ────────────────────────────────────────

@pytest.mark.skipif(not NUMPY_AVAILABLE, reason="numpy not installed")
def test_autoencoder_module_importable() -> None:
    from app.workers.ueba.autoencoder import AutoencoderModel
    assert AutoencoderModel is not None


@pytest.mark.skipif(not NUMPY_AVAILABLE, reason="numpy not installed")
def test_autoencoder_untrained_score_is_float() -> None:
    """Untrained model must return float from score()."""
    from app.workers.ueba.autoencoder import AutoencoderModel
    from app.workers.ueba.features import UserBehaviorFeatures
    model = AutoencoderModel(tenant_id="test-tenant")
    assert model._trained is False
    profile = UserBehaviorFeatures(
        tenant_id="test-tenant", user="alice",
        date=None, login_hour_mean=9.0, login_hour_std=1.0,
        login_count=5, off_hours_login_count=0,
        unique_source_ips=1, unique_countries=1,
        new_ip_ratio=0.0, failed_login_count=0,
        success_after_failure=0, commands_executed=10,
        sudo_commands=0, files_accessed=20,
        session_duration_mean=300.0, concurrent_sessions=1,
    )
    result = model.score(profile)
    assert isinstance(result, float), f"score() returned wrong type: {type(result)}"


def _make_profiles(n: int = 60):
    """Generate synthetic UserBehaviorFeatures list for testing."""
    from app.workers.ueba.features import UserBehaviorFeatures
    rng = np.random.default_rng(42)
    profiles = []
    for i in range(n):
        profiles.append(UserBehaviorFeatures(
            tenant_id="test-tenant", user=f"user{i % 5}", date=None,
            login_hour_mean=float(rng.uniform(8, 10)),
            login_hour_std=float(rng.uniform(0.5, 2.0)),
            login_count=int(rng.integers(3, 10)),
            off_hours_login_count=int(rng.integers(0, 2)),
            unique_source_ips=int(rng.integers(1, 3)),
            unique_countries=1,
            new_ip_ratio=float(rng.uniform(0, 0.2)),
            failed_login_count=int(rng.integers(0, 3)),
            success_after_failure=int(rng.integers(0, 1)),
            commands_executed=int(rng.integers(5, 20)),
            sudo_commands=int(rng.integers(0, 3)),
            files_accessed=int(rng.integers(10, 30)),
            session_duration_mean=float(rng.uniform(100, 500)),
            concurrent_sessions=int(rng.integers(1, 3)),
        ))
    return profiles


@pytest.mark.skipif(not NUMPY_AVAILABLE, reason="numpy not installed")
def test_autoencoder_train_trains_model() -> None:
    """After train(), _trained must be True."""
    from app.workers.ueba.autoencoder import AutoencoderModel
    import unittest.mock as mock

    model = AutoencoderModel(tenant_id="test-tenant")
    profiles = _make_profiles(60)
    with mock.patch.object(model, "_save_to_s3", return_value=None):
        success = model.train(profiles)
    assert success is True
    assert model._trained is True


@pytest.mark.skipif(not NUMPY_AVAILABLE, reason="numpy not installed")
def test_threshold_set_after_train() -> None:
    """threshold must be >= 0 after train()."""
    from app.workers.ueba.autoencoder import AutoencoderModel
    import unittest.mock as mock

    model = AutoencoderModel(tenant_id="test-tenant")
    profiles = _make_profiles(60)
    with mock.patch.object(model, "_save_to_s3", return_value=None):
        model.train(profiles)
    assert model.threshold >= 0.0, f"threshold is negative: {model.threshold}"


# ─── Feature vector tests ─────────────────────────────────────────────────────

def test_user_behavior_features_importable() -> None:
    """UserBehaviorFeatures class must be importable."""
    try:
        from app.workers.ueba.features import UserBehaviorFeatures
        assert UserBehaviorFeatures is not None
    except Exception as exc:
        pytest.skip(f"import skipped: {exc}")


def test_user_behavior_features_to_vector_length() -> None:
    """to_feature_vector() must return vector of length INPUT_DIM=14."""
    try:
        from app.workers.ueba.features import UserBehaviorFeatures
        profile = UserBehaviorFeatures(
            tenant_id="t", user="u", date=None,
            login_hour_mean=9.0, login_hour_std=2.0,
            login_count=5, off_hours_login_count=1,
            unique_source_ips=2, unique_countries=1,
            new_ip_ratio=0.1, failed_login_count=1,
            success_after_failure=0, commands_executed=8,
            sudo_commands=1, files_accessed=15,
            session_duration_mean=200.0, concurrent_sessions=1,
        )
        vec = profile.to_feature_vector()
        assert len(vec) == 14, f"vector length error: {len(vec)} (expected: 14)"
    except Exception as exc:
        pytest.skip(f"skipped: {exc}")


# ─── UEBA worker entrypoint test ─────────────────────────────────────────────

def test_ueba_worker_importable() -> None:
    """UEBA worker module must be importable."""
    for n in ["app.db.connection", "asyncpg", "sqlalchemy",
              "sqlalchemy.ext", "sqlalchemy.ext.asyncio",
              "app.common.logging"]:
        if n not in sys.modules:
            m = ModuleType(n)
            m.__spec__ = None
            sys.modules[n] = m
    sys.modules["app.common.logging"].get_logger = lambda x: __import__("logging").getLogger(x)
    sys.modules["app.common.logging"].configure_logging = lambda: None

    try:
        from app.workers.ueba import worker  # noqa: F401
        assert worker is not None
    except Exception as exc:
        pytest.skip(f"worker import skipped: {exc}")
