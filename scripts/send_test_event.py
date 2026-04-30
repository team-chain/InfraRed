"""Send sample auth.log events to the local ingestion API."""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from urllib import request


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


def make_token() -> str:
    now = datetime.now(timezone.utc)
    tenant_id = os.getenv("TENANT_ID", "company-a")
    agent_id = os.getenv("AGENT_ID", "agent-001")
    payload = {
        "sub": agent_id,
        "tenant_id": tenant_id,
        "agent_id": agent_id,
        "role": "agent",
        "iss": os.getenv("JWT_ISSUER", "infrared"),
        "aud": os.getenv("JWT_AUDIENCE", "infrared-ingest"),
        "iat": int(now.timestamp()),
        "exp": int(now.timestamp()) + int(os.getenv("JWT_AGENT_TTL_SECONDS", "86400")),
    }
    alg = os.getenv("JWT_ALG", "HS256")
    if alg != "HS256":
        raise SystemExit("scripts/send_test_event.py only supports HS256 for local setup")
    return encode_hs256(payload, os.getenv("JWT_SECRET", "change-me-in-production-please"))


def event_id(line: str, index: int) -> str:
    digest = hashlib.sha256(f"{index}:{line}".encode()).hexdigest()
    return f"evt-test-{digest[:24]}"


def main() -> int:
    load_env(Path(".env"))
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://localhost:8000/ingest")
    env_token = os.getenv("AGENT_TOKEN", "")
    default_token = make_token() if not env_token or env_token.startswith("replace-with") else env_token
    parser.add_argument("--token", default=default_token)
    parser.add_argument("--sample", default="infra/sample-logs/auth.log")
    args = parser.parse_args()

    tenant_id = os.getenv("TENANT_ID", "company-a")
    agent_id = os.getenv("AGENT_ID", "agent-001")
    asset_id = os.getenv("ASSET_ID", "asset-001")
    lines = Path(args.sample).read_text(encoding="utf-8").splitlines()

    headers = {
        "Authorization": f"Bearer {args.token}",
        "Content-Type": "application/json",
    }
    for index, line in enumerate(lines):
        envelope = {
            "event_id": event_id(line, index),
            "tenant_id": tenant_id,
            "agent_id": agent_id,
            "asset_id": asset_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "raw_source": "auth.log",
            "raw_line": line,
            "file_inode": "sample",
            "file_offset": index,
        }
        body = json.dumps(envelope).encode("utf-8")
        req = request.Request(args.url, data=body, headers=headers, method="POST")
        with request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode("utf-8"))
        print(f"sent {envelope['event_id']} -> {data.get('stream_id')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
