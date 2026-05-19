"""Canary Pack — v8 보안심화 미끼 자산 관리.

지원 프로필:
  linux   : /tmp 파일 + auditd 감시
  aws     : IAM Honey Access Key + S3 Decoy Object
  docker  : fake_docker_credentials (~/.docker/config.json 미끼)
  k8s     : fake_kubeconfig (~/.kube/config 미끼)

S3 Decoy Object:
  - 버킷 내 .env / credentials.json 등 이름의 미끼 오브젝트 생성
  - CloudTrail GetObject 이벤트 폴링으로 접근 탐지

콘텐츠 템플릿:
  fake_docker_credentials  : Docker Hub 가짜 인증 정보 JSON
  fake_kubeconfig          : 가짜 Kubernetes kubeconfig YAML
"""
from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

log = logging.getLogger(__name__)

# ------------------------------------------------------------------ #
# 콘텐츠 템플릿
# ------------------------------------------------------------------ #

CONTENT_TEMPLATES: dict[str, str] = {
    # Docker Hub 가짜 인증 정보
    "fake_docker_credentials": json.dumps(
        {
            "auths": {
                "https://index.docker.io/v1/": {
                    "auth": "aW5mcmFyZWRfaG9uZXk6aHR0cHM6Ly9pbmZyYXJlZC5pby9ob25leXRva2Vu",
                    "email": "deploy@infrared-honeypot.internal",
                },
                "registry.infrared.internal:5000": {
                    "auth": "Y2FuYXJ5X3VzZXI6Y2FuYXJ5X3Bhc3M=",
                },
            },
            "credsStore": "desktop",
            "_infrared_canary": True,
        },
        indent=2,
    ),

    # 가짜 Kubernetes kubeconfig
    "fake_kubeconfig": """\
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://k8s-api.infrared-honeypot.internal:6443
    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNwRENDQVl3Q0NRRGFBQUFBQUFBQUFEQUhCZ05WaEJZd0FBQUE...
  name: honeypot-cluster
contexts:
- context:
    cluster: honeypot-cluster
    user: canary-admin
  name: honeypot-context
current-context: honeypot-context
users:
- name: canary-admin
  user:
    token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.INFRARED_CANARY_TOKEN.signature_placeholder
# _infrared_canary: true
""",

    # AWS 가짜 자격증명
    "fake_aws_credentials": """\
[default]
aws_access_key_id = AKIAIOSFODNN7INFRARED
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYINFRAREDCANARY
region = ap-northeast-2
# _infrared_canary = true
""",

    # 가짜 .env 파일 (S3 decoy용)
    "fake_env_file": """\
# Application Environment — INFRARED CANARY
DATABASE_URL=postgresql://admin:INFRARED_CANARY_PASSWORD@db.internal:5432/prod
SECRET_KEY=infrared_canary_secret_key_do_not_use_in_production
JWT_SECRET=infrared_canary_jwt_secret_eyJhbGciOiJIUzI1NiJ9
STRIPE_SECRET_KEY=sk_live_INFRARED_CANARY_KEY_000000000000
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7INFRARED
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYINFRAREDCANARY
# _infrared_canary=true
""",

    # 가짜 GitHub Personal Access Token 목록
    "fake_github_tokens": """\
# GitHub Tokens — INFRARED CANARY — DO NOT USE
PROD_DEPLOY_TOKEN=ghp_INFRARED_CANARY_TOKEN_aaaaaaaaaaaaaaaaaaaaa
CI_BOT_TOKEN=ghp_INFRARED_CANARY_TOKEN_bbbbbbbbbbbbbbbbbbbbbbb
ADMIN_PAT=github_pat_INFRARED_CANARY_111111111111111111111111111111111111111111111
# _infrared_canary: true
""",
}


# ------------------------------------------------------------------ #
# Canary Pack 배포 / 회수
# ------------------------------------------------------------------ #

class CanaryPackManager:
    """프로필별 미끼 자산을 배포·회수·점검한다."""

    # -------------------- Linux 파일 미끼 --------------------

    def deploy_linux(self, path: str, content_template: str = "fake_env_file") -> dict:
        """Linux 파일시스템에 미끼 파일을 배포한다."""
        content = CONTENT_TEMPLATES.get(content_template, CONTENT_TEMPLATES["fake_env_file"])
        token_id = uuid.uuid4().hex[:16]
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True) if os.path.dirname(path) else None
            with open(path, "w") as fh:
                fh.write(content)
            os.chmod(path, 0o644)
            log.info("canary linux deployed: path=%s template=%s", path, content_template)
            return {"ok": True, "token_id": token_id, "path": path}
        except OSError as exc:
            log.warning("canary linux deploy failed: %s", exc)
            return {"ok": False, "error": str(exc)}

    def remove_linux(self, path: str) -> dict:
        """Linux 파일 미끼를 제거한다."""
        try:
            os.remove(path)
            return {"ok": True, "removed": path}
        except OSError as exc:
            return {"ok": False, "error": str(exc)}

    # -------------------- Docker 미끼 --------------------

    def deploy_docker(self, target_path: Optional[str] = None) -> dict:
        """~/.docker/config.json에 가짜 Docker 자격증명을 배포한다."""
        if target_path is None:
            target_path = os.path.expanduser("~/.docker/config.json")
        return self.deploy_linux(target_path, "fake_docker_credentials")

    # -------------------- Kubernetes 미끼 --------------------

    def deploy_k8s(self, target_path: Optional[str] = None) -> dict:
        """~/.kube/config에 가짜 kubeconfig를 배포한다."""
        if target_path is None:
            target_path = os.path.expanduser("~/.kube/config")
        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        return self.deploy_linux(target_path, "fake_kubeconfig")

    # -------------------- AWS S3 Decoy Object --------------------

    def deploy_s3_decoy(
        self,
        bucket: str,
        key: str = ".env",
        content_template: str = "fake_env_file",
        region: str = "ap-northeast-2",
    ) -> dict:
        """S3 버킷에 미끼 오브젝트를 업로드한다.

        오브젝트 메타데이터에 x-amz-meta-infrared-canary: true 태그를 달아
        실수로 사용되더라도 식별 가능하게 한다.
        """
        content = CONTENT_TEMPLATES.get(content_template, CONTENT_TEMPLATES["fake_env_file"])
        token_id = uuid.uuid4().hex[:16]

        try:
            import boto3  # noqa: PLC0415
            s3 = boto3.client("s3", region_name=region)
            s3.put_object(
                Bucket=bucket,
                Key=key,
                Body=content.encode("utf-8"),
                ContentType="text/plain",
                Metadata={
                    "infrared-canary": "true",
                    "token-id": token_id,
                    "deployed-at": datetime.now(tz=timezone.utc).isoformat(),
                },
                ServerSideEncryption="AES256",
            )
            log.info(
                "canary s3 decoy deployed: bucket=%s key=%s token_id=%s",
                bucket, key, token_id,
            )
            return {
                "ok": True,
                "token_id": token_id,
                "bucket": bucket,
                "key": key,
                "s3_uri": f"s3://{bucket}/{key}",
            }
        except ImportError:
            log.warning("boto3 not available — S3 decoy skipped")
            return {"ok": False, "error": "boto3_not_installed"}
        except Exception as exc:
            log.error("canary s3 decoy deploy failed: %s", exc)
            return {"ok": False, "error": str(exc)}

    def remove_s3_decoy(
        self,
        bucket: str,
        key: str,
        region: str = "ap-northeast-2",
    ) -> dict:
        """S3 미끼 오브젝트를 삭제한다."""
        try:
            import boto3  # noqa: PLC0415
            s3 = boto3.client("s3", region_name=region)
            s3.delete_object(Bucket=bucket, Key=key)
            log.info("canary s3 decoy removed: bucket=%s key=%s", bucket, key)
            return {"ok": True, "removed": f"s3://{bucket}/{key}"}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def poll_s3_decoy_access(
        self,
        bucket: str,
        key: str,
        region: str = "ap-northeast-2",
        lookback_minutes: int = 15,
    ) -> list[dict[str, Any]]:
        """CloudTrail에서 S3 오브젝트 GetObject 이벤트를 조회한다.

        Returns:
            감지된 접근 이벤트 목록 (각 항목에 source_ip, user_agent, event_time 포함).
        """
        try:
            import boto3  # noqa: PLC0415
            from datetime import timedelta  # noqa: PLC0415
            ct = boto3.client("cloudtrail", region_name=region)
            start = datetime.now(tz=timezone.utc) - timedelta(minutes=lookback_minutes)

            paginator = ct.get_paginator("lookup_events")
            events = []
            for page in paginator.paginate(
                LookupAttributes=[
                    {"AttributeKey": "ResourceName", "AttributeValue": f"arn:aws:s3:::{bucket}/{key}"}
                ],
                StartTime=start,
            ):
                for evt in page.get("Events", []):
                    if evt.get("EventName") in ("GetObject", "HeadObject"):
                        raw = json.loads(evt.get("CloudTrailEvent", "{}"))
                        events.append({
                            "event_time": evt.get("EventTime", "").isoformat()
                            if hasattr(evt.get("EventTime", ""), "isoformat")
                            else str(evt.get("EventTime", "")),
                            "source_ip": raw.get("sourceIPAddress", ""),
                            "user_agent": raw.get("userAgent", ""),
                            "user_identity": raw.get("userIdentity", {}).get("arn", ""),
                            "event_name": evt.get("EventName", ""),
                        })
            return events
        except Exception as exc:
            log.warning("cloudtrail poll failed: %s", exc)
            return []

    # -------------------- 상태 점검 --------------------

    def status(self, paths: list[str], s3_configs: Optional[list[dict]] = None) -> dict:
        """배포된 미끼 자산의 존재 여부를 확인한다."""
        result: dict[str, Any] = {"files": {}, "s3": []}
        for p in paths:
            result["files"][p] = os.path.exists(p)

        if s3_configs:
            try:
                import boto3  # noqa: PLC0415
                for cfg in s3_configs:
                    bucket = cfg["bucket"]
                    key = cfg["key"]
                    region = cfg.get("region", "ap-northeast-2")
                    s3 = boto3.client("s3", region_name=region)
                    try:
                        s3.head_object(Bucket=bucket, Key=key)
                        result["s3"].append({"s3_uri": f"s3://{bucket}/{key}", "exists": True})
                    except Exception:
                        result["s3"].append({"s3_uri": f"s3://{bucket}/{key}", "exists": False})
            except ImportError:
                pass

        return result


# v8.0 Canary Pack profiles: web-server | aws | docker | minimal
CANARY_PROFILES: dict = {
    "web-server": {
        "description": "Linux web server (Nginx/Apache) decoy set",
        "files": [
            {"path": "/var/www/html/.env",                   "template": "fake_env_file"},
            {"path": "/opt/app/config-prod.bak",             "template": "fake_env_file"},
            {"path": "/home/deploy/.aws/credentials_backup", "template": "fake_aws_credentials"},
        ],
    },
    "aws": {
        "description": "AWS environment (EC2 + IAM) decoy set",
        "files": [
            {"path": "/home/deploy/.aws/credentials_backup", "template": "fake_aws_credentials"},
            {"path": "/opt/app/.env.backup",                 "template": "fake_env_file"},
        ],
        "s3_decoys": [
            {"key": "backups/db_backup_2026.sql", "template": "fake_env_file"},
        ],
    },
    "docker": {
        "description": "Docker/K8s environment decoy set",
        "files": [
            {"path": "/root/.docker/config_backup.json",  "template": "fake_docker_credentials"},
            {"path": "/etc/kubernetes/admin_backup.conf", "template": "fake_kubeconfig"},
        ],
    },
    "minimal": {
        "description": "File-only decoys without cloud accounts",
        "files": [
            {"path": "/home/deploy/.aws/credentials_backup", "template": "fake_aws_credentials"},
            {"path": "/opt/app/.env.backup",                 "template": "fake_env_file"},
        ],
    },
}


def deploy_profile(
    profile_name: str,
    manager: "Optional[CanaryPackManager]" = None,
    dry_run: bool = False,
) -> dict:
    """Deploy all decoys for a named profile (v8 design doc section 8.3)."""
    if manager is None:
        manager = _manager
    profile = CANARY_PROFILES.get(profile_name)
    if not profile:
        raise ValueError(
            f"Unknown profile: {profile_name!r}. "
            f"Available: {list(CANARY_PROFILES)}"
        )
    results: list = []
    for fc in profile.get("files", []):
        if dry_run:
            results.append({"type": "file", "path": fc["path"], "dry_run": True})
        else:
            res = manager.deploy_linux(fc["path"], fc.get("template", "fake_env_file"))
            results.append({"type": "file", "path": fc["path"], **res})
    for s3c in profile.get("s3_decoys", []):
        results.append({"type": "s3_decoy", "note": "requires bucket config", **s3c})
    ok_count = sum(1 for r in results if r.get("ok", r.get("dry_run", False)))
    log.info(
        "canary deploy_profile profile=%s dry_run=%s total=%d ok=%d",
        profile_name, dry_run, len(results), ok_count,
    )
    return {
        "profile": profile_name,
        "description": profile["description"],
        "results": results,
        "total": len(results),
        "success": ok_count,
    }


# module-level singleton
_manager = CanaryPackManager()


def get_canary_pack_manager() -> CanaryPackManager:
    return _manager
