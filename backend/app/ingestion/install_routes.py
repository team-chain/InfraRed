"""Agent 설치 자원 서빙 — 인증 없는 public 엔드포인트.

목적: 신규 사용자가 자기 서버에서 `curl api.infrared.kr/install-agent.sh | bash`
실행 시 스크립트와 agent 소스 tarball을 우리 백엔드 도메인 하나로 받게 함.
GitHub 의존성 제거 → 폐쇄망 고객 대응 + URL 1개 화이트리스트.

빌드 시 CI(deploy.yml prepare step)에서 다음을 backend/_static/ 에 복사함:
  - install-agent.sh         (scripts/install-agent.sh 원본)
  - agent-source.tar.gz      (agent/ 디렉토리를 tar czf)

런타임에 backend 컨테이너의 /app/_static/ 에 위 두 파일이 존재.

엔드포인트:
  GET /install-agent.sh        - 설치 스크립트 (text/x-shellscript)
  GET /agent-source.tar.gz     - agent 소스 tarball (application/gzip)
"""
from __future__ import annotations

import logging
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse

logger = logging.getLogger(__name__)

router = APIRouter(tags=["install"])

# 컨테이너 안 정적 자원 경로. CI prepare step에서 채워짐.
_STATIC_DIR = Path(__file__).resolve().parents[2] / "_static"
_INSTALL_SCRIPT = _STATIC_DIR / "install-agent.sh"
_AGENT_TARBALL = _STATIC_DIR / "agent-source.tar.gz"


@router.get("/install-agent.sh", include_in_schema=False)
async def serve_install_script() -> FileResponse:
    """Agent 설치 스크립트 서빙.

    사용자 명령:
      curl -fsSL https://api.infrared.kr/install-agent.sh | sudo bash -s -- \\
        --token <TOKEN> --tenant <TENANT_ID>
    """
    if not _INSTALL_SCRIPT.is_file():
        logger.error("install-agent.sh missing at %s", _INSTALL_SCRIPT)
        # 빈 경로일 때 사용자가 빈 응답을 받으면 디버깅 어려움 → 안내 메시지로 폴백.
        return PlainTextResponse(  # type: ignore[return-value]
            "echo 'InfraRed install script is not bundled in this backend image. "
            "Please contact support.' >&2; exit 99\n",
            media_type="text/x-shellscript",
            status_code=503,
        )
    return FileResponse(
        path=str(_INSTALL_SCRIPT),
        media_type="text/x-shellscript",
        filename="install-agent.sh",
        headers={
            # CDN/Nginx 캐싱 가능 (스크립트 변경 시 백엔드 재배포 → 새 이미지)
            "Cache-Control": "public, max-age=300",
        },
    )


@router.get("/agent-source.tar.gz", include_in_schema=False)
async def serve_agent_tarball() -> FileResponse:
    """Agent 소스 tarball 서빙.

    install-agent.sh의 native 모드에서 git clone 대신 이걸 다운로드.
    tarball은 `tar czf agent-source.tar.gz agent/` 결과 — 압축 해제 시 `agent/` 디렉토리 생성.
    """
    if not _AGENT_TARBALL.is_file():
        logger.error("agent-source.tar.gz missing at %s", _AGENT_TARBALL)
        raise HTTPException(
            status_code=503,
            detail="Agent source bundle not packaged in this backend image.",
        )
    return FileResponse(
        path=str(_AGENT_TARBALL),
        media_type="application/gzip",
        filename="agent-source.tar.gz",
        headers={"Cache-Control": "public, max-age=300"},
    )
