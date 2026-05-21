"""Honeytoken(허니토큰) / Canary Pack 배포 및 이벤트 조회 API 라우터.

엔드포인트:
  POST /deception/deploy-file          — 파일 허니토큰 배포
  POST /deception/deploy-account       — 계정 허니토큰 배포
  GET  /deception/events               — 허니토큰 트리거 이벤트 목록
  POST /deception/canary/s3            — S3 Decoy Object 배포 (v8)
  DELETE /deception/canary/s3          — S3 Decoy Object 제거 (v8)
  POST /deception/canary/docker        — Docker 미끼 자격증명 배포 (v8)
  POST /deception/canary/k8s           — Kubernetes 가짜 kubeconfig 배포 (v8)
  GET  /deception/canary/status        — 배포된 Canary Pack 상태 확인 (v8)
  GET  /deception/canary/s3/poll       — S3 Decoy 접근 이벤트 CloudTrail 조회 (v8)
"""
from __future__ import annotations

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from app.config import get_settings
from app.iam.rbac_v2 import require_role
from app.workers.deception.canary_pack import get_canary_pack_manager
from app.workers.deception.honeytoken import HoneytokenManager

router = APIRouter(prefix="/deception", tags=["deception"])
log = logging.getLogger(__name__)
settings = get_settings()

_manager = HoneytokenManager()


class DeployFileRequest(BaseModel):
    path: Optional[str] = None


class DeployAccountRequest(BaseModel):
    username: Optional[str] = None


@router.post("/deploy-file")
async def deploy_file_token(
    body: DeployFileRequest = DeployFileRequest(),
    claims: dict = Depends(require_role("security_manager")),
) -> dict:
    """파일 허니토큰을 배포한다."""
    tenant_id = claims.get("tenant_id", settings.tenant_id)
    try:
        token_id = await _manager.deploy_file_token(tenant_id, path=body.path)
    except Exception as exc:
        log.exception("파일 허니토큰 배포 실패")
        raise HTTPException(status_code=500, detail=f"배포 실패: {exc}") from exc

    return {
        "status": "deployed",
        "token_id": token_id,
        "token_type": "file",
        "tenant_id": tenant_id,
    }


@router.post("/deploy-account")
async def deploy_account_token(
    body: DeployAccountRequest = DeployAccountRequest(),
    claims: dict = Depends(require_role("security_manager")),
) -> dict:
    """계정 허니토큰을 배포한다."""
    tenant_id = claims.get("tenant_id", settings.tenant_id)
    try:
        token_id = await _manager.deploy_account_token(tenant_id, username=body.username)
    except Exception as exc:
        log.exception("계정 허니토큰 배포 실패")
        raise HTTPException(status_code=500, detail=f"배포 실패: {exc}") from exc

    return {
        "status": "deployed",
        "token_id": token_id,
        "token_type": "account",
        "tenant_id": tenant_id,
    }


@router.get("/events")
async def list_honeytoken_events(
    limit: int = Query(default=100, ge=1, le=1000),
    claims: dict = Depends(require_role("analyst")),
) -> dict:
    """허니토큰 트리거 이벤트 목록을 반환한다."""
    tenant_id = claims.get("tenant_id", settings.tenant_id)
    events = await _manager.list_events(tenant_id, limit=limit)
    return {
        "tenant_id": tenant_id,
        "count": len(events),
        "events": events,
    }


# ─────────────────────────── Canary Pack (v8) ────────────────────────────── #

class S3DecoyRequest(BaseModel):
    bucket: str
    key: str = ".env"
    content_template: str = "fake_env_file"
    region: str = "ap-northeast-2"


class S3DecoyRemoveRequest(BaseModel):
    bucket: str
    key: str
    region: str = "ap-northeast-2"


class DockerCanaryRequest(BaseModel):
    target_path: Optional[str] = None


class K8sCanaryRequest(BaseModel):
    target_path: Optional[str] = None


class CanaryStatusRequest(BaseModel):
    paths: List[str] = []
    s3_configs: Optional[List[dict]] = None


@router.post("/canary/s3")
async def deploy_s3_decoy(
    body: S3DecoyRequest,
    claims: dict = Depends(require_role("security_manager")),
) -> dict:
    """S3 버킷에 미끼 오브젝트를 배포한다 (v8: aws 프로필 s3_decoy_object)."""
    cp = get_canary_pack_manager()
    result = cp.deploy_s3_decoy(
        bucket=body.bucket,
        key=body.key,
        content_template=body.content_template,
        region=body.region,
    )
    if not result.get("ok"):
        raise HTTPException(status_code=500, detail=result.get("error", "S3 배포 실패"))
    return result


@router.delete("/canary/s3")
async def remove_s3_decoy(
    body: S3DecoyRemoveRequest,
    claims: dict = Depends(require_role("security_manager")),
) -> dict:
    """S3 미끼 오브젝트를 제거한다."""
    cp = get_canary_pack_manager()
    result = cp.remove_s3_decoy(bucket=body.bucket, key=body.key, region=body.region)
    if not result.get("ok"):
        raise HTTPException(status_code=500, detail=result.get("error", "S3 제거 실패"))
    return result


@router.get("/canary/s3/poll")
async def poll_s3_decoy(
    bucket: str = Query(...),
    key: str = Query(default=".env"),
    region: str = Query(default="ap-northeast-2"),
    lookback_minutes: int = Query(default=15, ge=1, le=1440),
    claims: dict = Depends(require_role("analyst")),
) -> dict:
    """CloudTrail에서 S3 미끼 오브젝트 접근 이벤트를 조회한다."""
    cp = get_canary_pack_manager()
    events = cp.poll_s3_decoy_access(
        bucket=bucket,
        key=key,
        region=region,
        lookback_minutes=lookback_minutes,
    )
    return {
        "s3_uri": f"s3://{bucket}/{key}",
        "lookback_minutes": lookback_minutes,
        "count": len(events),
        "events": events,
    }


@router.post("/canary/docker")
async def deploy_docker_canary(
    body: DockerCanaryRequest,
    claims: dict = Depends(require_role("security_manager")),
) -> dict:
    """~/.docker/config.json에 가짜 Docker 자격증명을 배포한다 (v8: docker 프로필)."""
    cp = get_canary_pack_manager()
    result = cp.deploy_docker(target_path=body.target_path)
    if not result.get("ok"):
        raise HTTPException(status_code=500, detail=result.get("error", "Docker canary 배포 실패"))
    return result


@router.post("/canary/k8s")
async def deploy_k8s_canary(
    body: K8sCanaryRequest,
    claims: dict = Depends(require_role("security_manager")),
) -> dict:
    """~/.kube/config에 가짜 kubeconfig를 배포한다 (v8: k8s 프로필)."""
    cp = get_canary_pack_manager()
    result = cp.deploy_k8s(target_path=body.target_path)
    if not result.get("ok"):
        raise HTTPException(status_code=500, detail=result.get("error", "K8s canary 배포 실패"))
    return result


@router.post("/canary/status")
async def canary_status(
    body: CanaryStatusRequest,
    claims: dict = Depends(require_role("analyst")),
) -> dict:
    """배포된 Canary Pack 자산의 현재 존재 여부를 확인한다."""
    cp = get_canary_pack_manager()
    return cp.status(paths=body.paths, s3_configs=body.s3_configs)
