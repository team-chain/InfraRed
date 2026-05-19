"""MFA handler unit tests.

Based on design spec v4 section 9.2 - TOTP registration, verification, backup codes.
Requires pyotp and cryptography.
"""
from __future__ import annotations

import sys
from types import ModuleType

import pytest

try:
    import pyotp
    PYOTP_AVAILABLE = True
except ImportError:
    PYOTP_AVAILABLE = False

try:
    from cryptography.fernet import Fernet
    FERNET_AVAILABLE = True
except ImportError:
    FERNET_AVAILABLE = False


# ── Isolation helpers ─────────────────────────────────────────────────────────

_STUBS = ["app.config", "pydantic_settings"]
_SAVED: dict = {}


def setup_module(module) -> None:  # noqa: ANN001
    for n in _STUBS:
        _SAVED[n] = sys.modules.get(n)
        if n not in sys.modules:
            m = ModuleType(n)
            m.__spec__ = None
            sys.modules[n] = m

    settings_mock = type("Settings", (), {
        "fernet_key": None,
        "workos_api_key": "",
        "dashboard_url": "http://localhost:3000",
    })()

    # Save original get_settings (may be real module already loaded)
    _SAVED["_get_settings_fn"] = getattr(sys.modules.get("app.config"), "get_settings", None)
    sys.modules["app.config"].get_settings = lambda: settings_mock

    # Clear cached app.auth.mfa so it re-imports with fresh stub
    for mod in list(sys.modules.keys()):
        if "app.auth.mfa" in mod:
            del sys.modules[mod]


def teardown_module(module) -> None:  # noqa: ANN001
    for mod in list(sys.modules.keys()):
        if "app.auth.mfa" in mod:
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


# ─── MFA setup tests ─────────────────────────────────────────────────────────

@pytest.mark.skipif(not PYOTP_AVAILABLE, reason="pyotp not installed")
def test_mfa_setup_returns_all_fields() -> None:
    """setup_mfa() must return qr_code, encrypted_secret, backup_codes, totp_uri."""
    from app.auth.mfa import MFAHandler
    handler = MFAHandler()
    result = handler.setup_mfa("admin@infrared.local")
    assert result.qr_code_base64, "QR code is empty"
    assert result.encrypted_secret, "encrypted_secret is empty"
    assert len(result.backup_codes) == 10, f"backup code count error: {len(result.backup_codes)}"
    assert "otpauth://" in result.totp_uri, "totp_uri format error"


@pytest.mark.skipif(not PYOTP_AVAILABLE, reason="pyotp not installed")
def test_backup_codes_are_unique() -> None:
    """All 10 backup codes must be unique."""
    from app.auth.mfa import MFAHandler
    handler = MFAHandler()
    result = handler.setup_mfa("user@test.com")
    assert len(set(result.backup_codes)) == 10, "Duplicate backup codes found"


@pytest.mark.skipif(not PYOTP_AVAILABLE, reason="pyotp not installed")
def test_backup_code_format() -> None:
    """Backup codes must follow XXXXXX-XXXXXX format."""
    from app.auth.mfa import MFAHandler
    handler = MFAHandler()
    result = handler.setup_mfa("user@test.com")
    for code in result.backup_codes:
        parts = code.split("-")
        assert len(parts) == 2, f"format error: {code}"
        assert len(parts[0]) == 6, f"first part length error: {code}"
        assert len(parts[1]) == 6, f"second part length error: {code}"


@pytest.mark.skipif(not PYOTP_AVAILABLE, reason="pyotp not installed")
def test_totp_verify_with_current_token() -> None:
    """verify_totp must return True for the current TOTP token.
    Uses base64 encoding when fernet_key is None.
    """
    import base64
    from app.auth.mfa import MFAHandler

    secret = pyotp.random_base32()
    # fernet_key=None so base64 path is used
    encrypted = base64.b64encode(secret.encode()).decode()

    handler = MFAHandler()
    totp = pyotp.TOTP(secret)
    current_token = totp.now()

    result = handler.verify_totp(encrypted, current_token)
    assert result is True, f"verify_totp failed - encrypted={encrypted[:20]}... token={current_token}"


@pytest.mark.skipif(not PYOTP_AVAILABLE, reason="pyotp not installed")
def test_totp_verify_with_wrong_token() -> None:
    """verify_totp must return False for an invalid token."""
    import base64
    from app.auth.mfa import MFAHandler
    handler = MFAHandler()

    secret = pyotp.random_base32()
    encrypted = base64.b64encode(secret.encode()).decode()
    result = handler.verify_totp(encrypted, "000000")
    assert result is False


def test_backup_code_verify_removes_used_code() -> None:
    """Used backup code must be removed from the list."""
    from app.auth.mfa import MFAHandler
    handler = MFAHandler()
    codes = ["AABBCC-DDEEFF", "112233-445566", "AABBCC-FFFFFF"]
    valid, remaining = handler.verify_backup_code(codes, "AABBCC-DDEEFF")
    assert valid is True
    assert "AABBCC-DDEEFF" not in remaining
    assert len(remaining) == 2


def test_backup_code_verify_rejects_invalid_code() -> None:
    """Non-existent backup code must be rejected."""
    from app.auth.mfa import MFAHandler
    handler = MFAHandler()
    codes = ["AABBCC-DDEEFF", "112233-445566"]
    valid, remaining = handler.verify_backup_code(codes, "ZZZZZZ-ZZZZZZ")
    assert valid is False
    assert len(remaining) == 2
