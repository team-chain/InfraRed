"""
Canary Pack CLI — 미끼 자산 일괄 배포/제거/조회
=================================================
설계서: InfraRed_v8_보안심화_설계서.md §8

사용법:
    infrared canary install --profile web-server
    infrared canary install --profile aws --dry-run
    infrared canary status
    infrared canary uninstall

프로필:
    web-server  — Linux 웹서버(Nginx/Apache) 기준 미끼 세트
    aws         — AWS 환경(EC2+IAM) 기준 미끼 세트
    docker      — Docker/K8s 환경 기준 미끼 세트
    minimal     — AWS 계정 없이 파일만 배포 (보수적 고객용)
"""
from __future__ import annotations

import json
import logging
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# typer는 선택적 의존성 — 없으면 안내 메시지 출력
try:
    import typer
    _TYPER_OK = True
except ImportError:
    _TYPER_OK = False
    typer = None  # type: ignore[assignment]

logger = logging.getLogger("infrared.canary_cli")

# ---------------------------------------------------------------------------
# 배포 이력 저장 경로
# ---------------------------------------------------------------------------

DEPLOYED_MANIFEST_PATH = Path("/etc/infrared/canary_deployed.json")
PROFILES_CONFIG_PATH = Path("/etc/infrared/canary-profiles.yaml")

# ---------------------------------------------------------------------------
# 콘텐츠 템플릿 (설계서 §6.4, §8.2)
# ---------------------------------------------------------------------------

def _fake_aws_credentials(access_key_id: str = "AKIAXXX_HONEYFAKE_000",
                           secret_key: str = "FakeSecretKey+HoneyToken/XXXXXXXXXXXXXXXX") -> str:
    return (
        f"[default]\n"
        f"aws_access_key_id = {access_key_id}\n"
        f"aws_secret_access_key = {secret_key}\n"
        f"region = ap-northeast-2\n\n"
        f"# backup credentials - do not delete\n"
        f"[production]\n"
        f"aws_access_key_id = {access_key_id}\n"
        f"aws_secret_access_key = {secret_key}\n"
    )


def _fake_env_web() -> str:
    return (
        "DEBUG=false\n"
        "APP_ENV=production\n"
        "SECRET_KEY=fake-production-secret-key-do-not-use-xxxx\n"
        "DATABASE_URL=postgresql://app_user:FakeP@ss123@10.99.99.99:5432/appdb\n"
        "REDIS_URL=redis://10.99.99.99:6379\n"
        "AWS_ACCESS_KEY_ID=AKIAXXX_HONEYFAKE_WEB\n"
        "AWS_SECRET_ACCESS_KEY=FakeSecretKey+HoneyToken/WebServer+xxxxx\n"
        "STRIPE_SECRET_KEY=sk_live_FakeStripeSecretKey000000000000000\n"
    )


def _fake_env_app() -> str:
    return (
        "APP_VERSION=2.3.1\n"
        "ENVIRONMENT=production\n"
        "JWT_SECRET=fake-jwt-secret-honey-xxxxxxxxxxxxxxxxxxx\n"
        "DATABASE_URL=postgresql://prod_user:FakeP@ss999@db.internal:5432/proddb\n"
        "AWS_ACCESS_KEY_ID=AKIAXXX_HONEYFAKE_APP\n"
        "AWS_SECRET_ACCESS_KEY=FakeSecretKey+HoneyToken/AppServer+xxxxx\n"
        "SMTP_PASSWORD=FakeSmtpP@ss_Honey_000000000\n"
    )


def _fake_docker_credentials() -> str:
    import base64
    encoded = base64.b64encode(b"canary_user:canary_pass_honey_token_xxx").decode()
    return json.dumps({
        "auths": {
            "https://index.docker.io/v1/": {
                "auth": encoded,
                "email": "deploy@infrared-honeypot.internal",
            },
            "registry.internal:5000": {"auth": encoded},
        },
        "credsStore": "desktop",
        "_infrared_canary": True,
    }, indent=2)


def _fake_kubeconfig() -> str:
    return (
        "apiVersion: v1\n"
        "kind: Config\n"
        "clusters:\n"
        "- cluster:\n"
        "    server: https://k8s-api.infrared-honeypot.internal:6443\n"
        "    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0t\n"
        "  name: honeypot-cluster\n"
        "contexts:\n"
        "- context:\n"
        "    cluster: honeypot-cluster\n"
        "    user: admin\n"
        "  name: honeypot-context\n"
        "current-context: honeypot-context\n"
        "users:\n"
        "- name: admin\n"
        "  user:\n"
        "    token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.HONEYFAKE.HONEYFAKE\n"
    )


TEMPLATE_GENERATORS = {
    "fake_aws_credentials": _fake_aws_credentials,
    "fake_env_web":         _fake_env_web,
    "fake_env_app":         _fake_env_app,
    "fake_docker_credentials": _fake_docker_credentials,
    "fake_kubeconfig":      _fake_kubeconfig,
    "fake_binary":          lambda: "HONEYFAKE_BINARY_CANARY_INFRARED\x00\x01\x02",
}


# ---------------------------------------------------------------------------
# 프로필 정의 (설계서 §8.2)
# ---------------------------------------------------------------------------

@dataclass
class HoneytokenSpec:
    path: str
    content_template: str


@dataclass
class CanaryProfile:
    name: str
    description: str
    honeytokens: list[HoneytokenSpec] = field(default_factory=list)


PROFILES: dict[str, CanaryProfile] = {
    "web-server": CanaryProfile(
        name="web-server",
        description="Linux 웹서버 (Nginx/Apache) 기준 미끼 세트",
        honeytokens=[
            HoneytokenSpec("/var/www/html/.env",             "fake_env_web"),
            HoneytokenSpec("/var/www/html/backup.zip.bak",   "fake_binary"),
            HoneytokenSpec("/opt/app/config-prod.bak",       "fake_env_app"),
            HoneytokenSpec("/home/deploy/.aws/credentials_backup", "fake_aws_credentials"),
        ],
    ),
    "aws": CanaryProfile(
        name="aws",
        description="AWS 환경 (EC2 + IAM) 기준 미끼 세트",
        honeytokens=[
            HoneytokenSpec("/home/deploy/.aws/credentials_backup", "fake_aws_credentials"),
            HoneytokenSpec("/opt/app/.env.backup",           "fake_env_app"),
            HoneytokenSpec("/root/.aws/credentials_backup",  "fake_aws_credentials"),
        ],
    ),
    "docker": CanaryProfile(
        name="docker",
        description="Docker/K8s 환경 기준 미끼 세트",
        honeytokens=[
            HoneytokenSpec("/root/.docker/config_backup.json",    "fake_docker_credentials"),
            HoneytokenSpec("/etc/kubernetes/admin_backup.conf",    "fake_kubeconfig"),
            HoneytokenSpec("/home/deploy/.kube/config_backup",    "fake_kubeconfig"),
        ],
    ),
    "minimal": CanaryProfile(
        name="minimal",
        description="계정 생성 없이 파일만 배포 (보수적 고객용)",
        honeytokens=[
            HoneytokenSpec("/home/deploy/.aws/credentials_backup", "fake_aws_credentials"),
            HoneytokenSpec("/opt/app/.env.backup",                 "fake_env_app"),
        ],
    ),
}


# ---------------------------------------------------------------------------
# 배포/제거 로직
# ---------------------------------------------------------------------------

@dataclass
class DeployResult:
    path: str
    success: bool
    error: str = ""


def _load_manifest() -> list[dict]:
    """배포 이력 로드."""
    if not DEPLOYED_MANIFEST_PATH.exists():
        return []
    try:
        return json.loads(DEPLOYED_MANIFEST_PATH.read_text())
    except Exception:
        return []


def _save_manifest(entries: list[dict]) -> None:
    """배포 이력 저장."""
    DEPLOYED_MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    DEPLOYED_MANIFEST_PATH.write_text(json.dumps(entries, indent=2))


def deploy_profile(profile: CanaryProfile, dry_run: bool = False) -> list[DeployResult]:
    """프로필의 모든 미끼 파일을 배포."""
    results: list[DeployResult] = []
    manifest = _load_manifest()

    for spec in profile.honeytokens:
        if dry_run:
            results.append(DeployResult(path=spec.path, success=True))
            continue

        try:
            generator = TEMPLATE_GENERATORS.get(spec.content_template)
            content = generator() if generator else f"# CANARY_TOKEN: {spec.path}\n"

            path = Path(spec.path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
            path.chmod(0o644)

            manifest.append({
                "path": spec.path,
                "template": spec.content_template,
                "profile": profile.name,
                "deployed_at": datetime.now(timezone.utc).isoformat(),
                "_infrared_canary": True,
            })
            results.append(DeployResult(path=spec.path, success=True))
            logger.info("Canary 배포: %s", spec.path)

        except Exception as exc:
            logger.warning("Canary 배포 실패 %s: %s", spec.path, exc)
            results.append(DeployResult(path=spec.path, success=False, error=str(exc)))

    if not dry_run:
        _save_manifest(manifest)

    return results


def remove_all_canaries() -> list[str]:
    """InfraRed가 배포한 미끼 파일만 삭제 (기존 서비스 파일 건드리지 않음)."""
    manifest = _load_manifest()
    removed: list[str] = []

    for entry in manifest:
        if not entry.get("_infrared_canary"):
            continue
        path = Path(entry["path"])
        try:
            if path.exists():
                path.unlink()
                removed.append(str(path))
                logger.info("Canary 삭제: %s", path)
        except Exception as exc:
            logger.warning("Canary 삭제 실패 %s: %s", path, exc)

    _save_manifest([e for e in manifest if not e.get("_infrared_canary")])
    return removed


def list_deployed() -> list[dict]:
    """현재 배포된 미끼 파일 목록 반환."""
    manifest = _load_manifest()
    active = []
    for entry in manifest:
        if not entry.get("_infrared_canary"):
            continue
        exists = Path(entry["path"]).exists()
        active.append({**entry, "file_exists": exists})
    return active


# ---------------------------------------------------------------------------
# Typer CLI
# ---------------------------------------------------------------------------

if _TYPER_OK:
    app = typer.Typer(
        name="canary",
        help="InfraRed Canary Pack — 미끼 자산 일괄 배포/제거/조회",
        no_args_is_help=True,
    )

    @app.command()
    def install(
        profile: str = typer.Option("web-server", "--profile", "-p",
                                    help="배포 프로필: web-server | aws | docker | minimal"),
        dry_run: bool = typer.Option(False, "--dry-run",
                                     help="실제 배포 없이 미리보기"),
    ):
        """
        Canary Pack을 설치합니다.
        기존 서비스 파일은 절대 수정하지 않습니다.
        InfraRed가 생성한 미끼 파일만 배포됩니다.
        """
        if profile not in PROFILES:
            typer.echo(
                f"❌ 알 수 없는 프로필: {profile}\n"
                f"   사용 가능: {', '.join(PROFILES.keys())}",
                err=True,
            )
            raise typer.Exit(1)

        config = PROFILES[profile]

        if dry_run:
            typer.echo(f"[DRY RUN] 프로필: {profile} — {config.description}")
            for spec in config.honeytokens:
                typer.echo(f"  생성 예정: {spec.path}  (template={spec.content_template})")
            return

        results = deploy_profile(config, dry_run=False)
        success_count = sum(1 for r in results if r.success)

        for r in results:
            icon = "✓" if r.success else "✗"
            line = f"  {icon} {r.path}"
            if not r.success:
                line += f"  ({r.error})"
            typer.echo(line)

        typer.echo(
            f"\nCanary Pack 설치 완료 ({profile}). "
            f"총 {success_count}/{len(results)}개 미끼 배포됨."
        )

    @app.command()
    def uninstall():
        """
        InfraRed가 생성한 미끼 파일만 제거합니다.
        기존 서비스 파일은 건드리지 않습니다.
        """
        removed = remove_all_canaries()

        if not removed:
            typer.echo("배포된 Canary Pack 없음.")
            return

        for path in removed:
            typer.echo(f"  삭제: {path}")

        typer.echo(f"\nCanary Pack 제거 완료. {len(removed)}개 미끼 삭제됨.")

    @app.command()
    def status():
        """현재 배포된 Canary Pack 현황을 출력합니다."""
        tokens = list_deployed()

        if not tokens:
            typer.echo("배포된 Canary Pack 없음.")
            return

        typer.echo(f"{'프로필':<15} {'타입':<25} {'경로':<45} {'파일존재'}")
        typer.echo("─" * 95)
        for t in tokens:
            exists_mark = "✓" if t.get("file_exists") else "✗ (삭제됨)"
            typer.echo(
                f"{t.get('profile', '-'):<15} "
                f"{t.get('template', '-'):<25} "
                f"{t['path']:<45} "
                f"{exists_mark}"
            )


def main():
    """CLI 진입점: `infrared canary` 서브커맨드."""
    if not _TYPER_OK:
        print(
            "❌ typer가 설치되지 않았습니다.\n"
            "   pip install typer 후 다시 시도하세요.",
            file=sys.stderr,
        )
        sys.exit(1)
    app()


if __name__ == "__main__":
    main()
