from app.iam.api_key import _bearer_token


def test_bearer_token_extracts_api_key() -> None:
    assert _bearer_token("Bearer ir_demo_key") == "ir_demo_key"


def test_bearer_token_ignores_non_bearer_scheme() -> None:
    assert _bearer_token("Basic abc") is None
