"""Generate a local InfraRed JWT for agents or users."""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

def load_env(path: Path) -> None:
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip())


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def encode_hs256(payload: dict, secret: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    signing_input = ".".join(
        [
            _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8")),
            _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8")),
        ]
    )
    signature = hmac.new(secret.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256).digest()
    return f"{signing_input}.{_b64url(signature)}"


def main() -> int:
    load_env(Path(".env"))
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", choices=["agent", "admin", "analyst", "viewer"], default="agent")
    parser.add_argument("--tenant-id", default=os.getenv("TENANT_ID", "company-a"))
    parser.add_argument("--agent-id", default=os.getenv("AGENT_ID", "agent-001"))
    parser.add_argument("--subject", default=None)
    parser.add_argument("--ttl", type=int, default=None)
    args = parser.parse_args()

    secret = os.getenv("JWT_SECRET", "change-me-in-production-please")
    alg = os.getenv("JWT_ALG", "HS256")
    if alg != "HS256":
        raise SystemExit("scripts/generate_jwt.py only supports HS256 for local setup")
    issuer = os.getenv("JWT_ISSUER", "infrared")
    audience = os.getenv("JWT_AUDIENCE", "infrared-ingest")
    ttl = args.ttl or int(
        os.getenv("JWT_AGENT_TTL_SECONDS" if args.role == "agent" else "JWT_USER_TTL_SECONDS", "86400")
    )
    now = datetime.now(timezone.utc)
    subject = args.subject or (args.agent_id if args.role == "agent" else "local-user")
    payload = {
        "sub": subject,
        "tenant_id": args.tenant_id,
        "role": args.role,
        "iss": issuer,
        "aud": audience,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=ttl)).timestamp()),
    }
    if args.role == "agent":
        payload["agent_id"] = args.agent_id
    print(encode_hs256(payload, secret))
    return 0


if __name__ == "__main__":
    sys.exit(main())
