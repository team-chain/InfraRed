"""JS SDK ingestion endpoint + sdk.js serving.

Customers embed one script tag:
  <script src="https://api.infrared.io/sdk.js"
          data-token="TENANT_API_KEY"></script>

The SDK fires a POST to /ingest/web on every page load.
The server extracts the real IP from X-Forwarded-For and converts the
payload into a RawEventEnvelope pushed to Redis Streams.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import PlainTextResponse

from app.config import get_settings
from app.iam.api_key import verify_api_key
from app.models.envelope import RawEventEnvelope
from app.redis_kv import streams
from app.redis_kv.client import get_redis


router = APIRouter()

# --------------------------------------------------------------------------- #
# sdk.js — served directly by the API so customers don't need a separate CDN  #
# --------------------------------------------------------------------------- #

_SDK_JS = r"""
(function () {
  var script = document.currentScript;
  if (!script) return;
  var token = script.getAttribute('data-token');
  if (!token) return;

  var base = script.src.replace('/sdk.js', '');

  function send() {
    var payload = {
      page_url:      window.location.href,
      referrer:      document.referrer || null,
      user_agent:    navigator.userAgent,
      language:      navigator.language,
      screen_width:  screen.width,
      screen_height: screen.height,
      timezone:      Intl.DateTimeFormat().resolvedOptions().timeZone,
      timestamp:     new Date().toISOString()
    };
    var xhr = new XMLHttpRequest();
    xhr.open('POST', base + '/ingest/web', true);
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.setRequestHeader('X-Tenant-Token', token);
    xhr.send(JSON.stringify(payload));
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', send);
  } else {
    send();
  }
})();
""".strip()


@router.get("/sdk.js", include_in_schema=False)
async def serve_sdk() -> Response:
    return Response(
        content=_SDK_JS,
        media_type="application/javascript",
        headers={"Cache-Control": "public, max-age=300"},
    )


# --------------------------------------------------------------------------- #
# /ingest/web — receives events from the JS SDK                               #
# --------------------------------------------------------------------------- #

def _real_ip(request: Request) -> str | None:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


@router.post("/ingest/web", status_code=202)
async def ingest_web(
    request: Request,
    claims: dict = Depends(verify_api_key),
) -> dict:
    settings = get_settings()
    body = await request.json()

    source_ip = _real_ip(request)
    tenant_id = claims["tenant_id"]
    now = datetime.now(timezone.utc)

    envelope = RawEventEnvelope(
        event_id=f"web:{uuid.uuid4().hex}",
        tenant_id=tenant_id,
        agent_id=f"sdk-web-{tenant_id}",
        timestamp=now,
        event_type="web_request",
        raw_source="sdk",
        source_ip=source_ip,
        user_agent=body.get("user_agent"),
        request_path=body.get("page_url", "/"),
        host=request.headers.get("Host"),
    )

    redis = get_redis()
    stream_id = await redis.xadd(
        streams.events_raw(tenant_id),
        {"payload": envelope.model_dump_json()},
        maxlen=settings.redis_stream_maxlen,
        approximate=True,
    )
    return {"accepted": True, "stream_id": stream_id}
