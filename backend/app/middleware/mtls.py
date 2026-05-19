"""mTLS (Mutual TLS) 클라이언트 인증 미들웨어 — v7.0 설계서

역할:
  에이전트 → 백엔드 HTTP 요청에서 클라이언트 인증서를 검증.
  Nginx/Traefik 리버스 프록시가 mTLS를 처리하고
  검증된 인증서 정보를 헤더로 전달하는 방식을 지원.

설계:
  1. 직접 mTLS 모드: uvicorn ssl_certfile/ssl_keyfile + ssl_ca_certs 설정
  2. 프록시 헤더 모드: X-SSL-Client-Verify, X-SSL-Client-DN 헤더 검증
     (Nginx: ssl_verify_client on; proxy_set_header X-SSL-Client-Verify $ssl_client_verify;)

사용법:
  from app.middleware.mtls import MTLSMiddleware
  app.add_middleware(MTLSMiddleware, agent_path_prefix="/ingest")
"""
from __future__ import annotations

import logging
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

log = logging.getLogger("infrared.mtls")

# mTLS 검증이 필요한 경로 프리픽스
_MTLS_PATHS = {"/ingest", "/heartbeat", "/commands"}

# 프록시가 설정하는 헤더 이름 (Nginx ssl_verify_client on 기준)
_HDR_VERIFY = "X-SSL-Client-Verify"       # "SUCCESS" | "FAILED" | "NONE"
_HDR_CLIENT_DN = "X-SSL-Client-DN"        # "/CN=agent-001/O=infrared/..."
_HDR_CLIENT_CERT = "X-SSL-Client-Cert"    # PEM 인증서 (URL-encoded)


class MTLSMiddleware(BaseHTTPMiddleware):
    """
    에이전트 경로에 대한 mTLS 클라이언트 인증서 검증 미들웨어.

    mtls_enabled=False 이면 미들웨어가 투명하게 패스스루.
    """

    def __init__(
        self,
        app,
        mtls_enabled: bool = False,
        agent_path_prefix: str = "/ingest",
        require_agent_cn: bool = False,
    ) -> None:
        super().__init__(app)
        self.mtls_enabled = mtls_enabled
        self.agent_path_prefix = agent_path_prefix
        self.require_agent_cn = require_agent_cn
        if mtls_enabled:
            log.info(
                "mtls_middleware_active prefix=%s require_agent_cn=%s",
                agent_path_prefix, require_agent_cn,
            )
        else:
            log.info("mtls_middleware_disabled — Bearer 토큰 인증만 사용")

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if not self.mtls_enabled:
            return await call_next(request)

        # mTLS 검증이 필요한 경로인지 확인
        path = request.url.path
        needs_mtls = any(path.startswith(p) for p in _MTLS_PATHS)
        if not needs_mtls:
            return await call_next(request)

        # 1. 프록시 헤더 방식 검증
        verify_result = request.headers.get(_HDR_VERIFY)
        client_dn = request.headers.get(_HDR_CLIENT_DN, "")

        if verify_result is not None:
            # 프록시 헤더 방식 (Nginx mTLS 프록시 뒤에서 동작)
            if verify_result != "SUCCESS":
                log.warning(
                    "mtls_client_cert_invalid verify=%s path=%s remote=%s",
                    verify_result, path, request.client,
                )
                return JSONResponse(
                    status_code=401,
                    content={
                        "error": "client_certificate_required",
                        "detail": f"mTLS 클라이언트 인증서 검증 실패: {verify_result}",
                    },
                )

            # CN 검증 (선택)
            if self.require_agent_cn and client_dn:
                cn = _extract_cn(client_dn)
                if not cn:
                    log.warning("mtls_cn_missing dn=%s", client_dn)
                    return JSONResponse(
                        status_code=401,
                        content={"error": "client_cn_missing"},
                    )
                # request.state에 CN 저장 (라우터에서 사용 가능)
                request.state.agent_cn = cn
                log.debug("mtls_client_authenticated cn=%s path=%s", cn, path)

            return await call_next(request)

        # 2. 직접 TLS 모드: uvicorn이 ssl_ca_certs로 검증 — 별도 헤더 없음
        #    이 경우 미들웨어 레벨에서 추가 검증 불필요 (uvicorn이 보장)
        #    하지만 프록시 헤더도 없고 직접 TLS도 아닌 경우 → 거부
        #
        #    실제 프로덕션에서는 Nginx/Traefik이 헤더를 주입하므로
        #    이 분기에 도달하면 잘못된 요청임.
        log.warning(
            "mtls_header_missing path=%s remote=%s — mTLS 헤더 없음",
            path, request.client,
        )
        return JSONResponse(
            status_code=401,
            content={
                "error": "mtls_header_missing",
                "detail": "mTLS 클라이언트 인증서 헤더가 없습니다. 리버스 프록시 설정을 확인하세요.",
            },
        )


def _extract_cn(dn: str) -> str | None:
    """
    Distinguished Name에서 CN 값 추출.
    예: "/CN=agent-001/O=infrared/C=KR" → "agent-001"
    """
    for part in dn.split("/"):
        if part.upper().startswith("CN="):
            return part[3:].strip()
    return None
