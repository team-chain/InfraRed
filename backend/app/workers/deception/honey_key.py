"""
DECEPTION-003 — AWS Honey Access Key + CloudTrail Monitor
==========================================================
v8.0 신규 기만 탐지 모듈.

기존 v7.0 Honeytoken(DECEPTION-001/002)은 서버 내 파일 접근(inotify)을 탐지한다.
이 모듈은 공격자가 미끼 파일을 외부로 탈취하여 실제 AWS API를 호출하는 순간을 탐지한다.

구조:
    AWSHoneyKeyManager      — Honey Key 생성/삭제 (IAM Deny* 정책)
    CloudTrailHoneyKeyMonitor — CloudTrail 폴링으로 키 사용 감지
    HoneyKeyAlert           — 탐지 결과

설계서: InfraRed_v8_보안심화_설계서.md §6
MITRE:  T1552.005 (Cloud Instance Metadata API)
신뢰도: 0.99 (키를 실제로 사용했다 = 탈취 확정에 가까움)
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 데이터 구조체
# ---------------------------------------------------------------------------

@dataclass
class HoneyKeyConfig:
    tenant_id: UUID
    iam_user: str
    access_key_id: str
    secret_access_key: str          # 배포용 (미끼 파일에 삽입)
    decoy_locations: list[str] = field(default_factory=list)


@dataclass
class HoneyKeyAlert:
    rule_id: str = "DECEPTION-003"
    severity: str = "CRITICAL"
    confidence: float = 0.99
    mitre: str = "T1552.005"
    description: str = ""
    data: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Honey Key 콘텐츠 템플릿
# ---------------------------------------------------------------------------

def _make_credentials_file(access_key_id: str, secret_key: str) -> str:
    """AWS credentials 형식의 미끼 파일 콘텐츠."""
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


def _make_env_file(access_key_id: str, secret_key: str) -> str:
    """환경변수 파일 형식의 미끼 파일 콘텐츠."""
    return (
        f"AWS_ACCESS_KEY_ID={access_key_id}\n"
        f"AWS_SECRET_ACCESS_KEY={secret_key}\n"
        f"DATABASE_URL=postgresql://app_user:FakeP@ss123@10.99.99.99:5432/appdb\n"
        f"REDIS_URL=redis://10.99.99.99:6379\n"
        f"SECRET_KEY=fake-secret-key-do-not-use-xxxxxxxxxxxx\n"
    )


# ---------------------------------------------------------------------------
# Honey Key 생성/관리
# ---------------------------------------------------------------------------

class AWSHoneyKeyManager:
    """
    테넌트별 Honey AWS Access Key 생성 및 관리.

    핵심 원칙:
      1. 실제 권한 없음: IAM Policy에서 명시적 Deny *
      2. 접근 시 CloudTrail에 기록됨 (권한 없어도 기록됨)
      3. 미끼 파일 안에 삽입: 가짜 .env, 가짜 credentials, 가짜 백업

    boto3 iam 클라이언트를 주입받아 단위 테스트에서 Mock 교체 가능.
    """

    def __init__(self, iam_client=None, pool=None):
        self._iam = iam_client
        self._pool = pool

    # ------------------------------------------------------------------
    # Honey Key 생성
    # ------------------------------------------------------------------

    async def create_honey_key(self, tenant_id: UUID) -> HoneyKeyConfig:
        """
        Honey Access Key 생성 + 권한 없는 IAM User에 연결.

        Steps:
          1. IAM User 생성 (권한 없음)
          2. 명시적 Deny * 정책 부착
          3. Access Key 생성
          4. DB에 설정 저장
        """
        user_name = f"infrared-honey-{str(tenant_id)[:8]}"

        # IAM 클라이언트가 없으면 더미 키 반환 (개발/테스트 환경)
        if self._iam is None:
            logger.warning(
                "IAM 클라이언트가 없습니다. 더미 Honey Key를 반환합니다. (tenant=%s)",
                tenant_id,
            )
            dummy_access_key = f"AKIAFAKE{str(tenant_id)[:8].upper()}"
            dummy_secret = "FakeSecretKeyForTestingPurposesOnly00000000"
            config = HoneyKeyConfig(
                tenant_id=tenant_id,
                iam_user=user_name,
                access_key_id=dummy_access_key,
                secret_access_key=dummy_secret,
                decoy_locations=[
                    "/home/deploy/.aws/credentials_backup",
                    "/opt/app/.env.backup",
                    "/backup/deploy_config.bak",
                ],
            )
            await self._save_to_db(config)
            return config

        # 1. IAM User 생성
        try:
            self._iam.create_user(UserName=user_name)
        except self._iam.exceptions.EntityAlreadyExistsException:
            logger.info("IAM User '%s' 이미 존재함, 재사용", user_name)

        # 2. Deny * 정책 부착
        deny_policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
            }],
        })
        self._iam.put_user_policy(
            UserName=user_name,
            PolicyName="HoneyKeyDenyAll",
            PolicyDocument=deny_policy,
        )

        # 3. Access Key 생성
        key_response = self._iam.create_access_key(UserName=user_name)
        access_key_id = key_response["AccessKey"]["AccessKeyId"]
        secret_access_key = key_response["AccessKey"]["SecretAccessKey"]

        config = HoneyKeyConfig(
            tenant_id=tenant_id,
            iam_user=user_name,
            access_key_id=access_key_id,
            secret_access_key=secret_access_key,
            decoy_locations=[
                "/home/deploy/.aws/credentials_backup",
                "/opt/app/.env.backup",
                "/backup/deploy_config.bak",
            ],
        )

        await self._save_to_db(config)
        logger.info("Honey Key 생성 완료: user=%s, key_id=%s...", user_name, access_key_id[:12])
        return config

    # ------------------------------------------------------------------
    # Honey Key 삭제
    # ------------------------------------------------------------------

    async def delete_honey_key(self, tenant_id: UUID) -> bool:
        """Honey Key 비활성화 (DB 플래그 + IAM User 비활성화)."""
        config = await self.get_honey_key(tenant_id)
        if not config:
            return False

        if self._iam:
            try:
                self._iam.update_access_key(
                    UserName=config["iam_user"],
                    AccessKeyId=config["access_key_id"],
                    Status="Inactive",
                )
            except Exception as exc:
                logger.warning("IAM 키 비활성화 실패: %s", exc)

        if self._pool:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    "UPDATE honey_key_configs SET is_active=false WHERE tenant_id=$1",
                    str(tenant_id),
                )

        return True

    # ------------------------------------------------------------------
    # DB 조회
    # ------------------------------------------------------------------

    async def get_honey_key(self, tenant_id: UUID) -> Optional[dict]:
        """테넌트의 활성 Honey Key 설정 반환."""
        if not self._pool:
            return None
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM honey_key_configs WHERE tenant_id=$1 AND is_active=true",
                str(tenant_id),
            )
        if not row:
            return None
        return dict(row)

    # ------------------------------------------------------------------
    # 미끼 파일 콘텐츠 생성
    # ------------------------------------------------------------------

    def get_decoy_content(
        self,
        config: HoneyKeyConfig,
        template: str = "credentials",
    ) -> str:
        """미끼 파일에 삽입할 콘텐츠 반환."""
        if template == "env":
            return _make_env_file(config.access_key_id, config.secret_access_key)
        return _make_credentials_file(config.access_key_id, config.secret_access_key)

    # ------------------------------------------------------------------
    # 내부 헬퍼
    # ------------------------------------------------------------------

    async def _save_to_db(self, config: HoneyKeyConfig) -> None:
        """Honey Key 설정을 DB에 저장."""
        if not self._pool:
            return
        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO honey_key_configs (tenant_id, iam_user, access_key_id)
                VALUES ($1, $2, $3)
                ON CONFLICT DO NOTHING
                """,
                str(config.tenant_id), config.iam_user, config.access_key_id,
            )


# ---------------------------------------------------------------------------
# CloudTrail 폴링 모니터
# ---------------------------------------------------------------------------

class CloudTrailHoneyKeyMonitor:
    """
    CloudTrail 이벤트를 폴링하여 Honey Key 사용 여부 감지.
    키가 사용됐다는 것 = 미끼 파일이 외부로 유출되어 실제 사용됨.

    POLL_INTERVAL_SECONDS 간격으로 실행. 중복 보고 방지는 Redis TTL 활용.
    """

    POLL_INTERVAL_SECONDS = 60
    DEDUP_TTL_SECONDS = 3600  # 이미 보고한 CloudTrail 이벤트 ID는 1시간 캐시

    def __init__(
        self,
        cloudtrail_client=None,
        honey_key_manager: Optional[AWSHoneyKeyManager] = None,
        redis=None,
        pool=None,
    ):
        self._ct = cloudtrail_client
        self._manager = honey_key_manager or AWSHoneyKeyManager(pool=pool)
        self._redis = redis

    # ------------------------------------------------------------------
    # 공개 API
    # ------------------------------------------------------------------

    async def poll_cloudtrail(self, tenant_id: UUID) -> list[HoneyKeyAlert]:
        """
        최근 2분간 CloudTrail 이벤트에서 Honey Key 사용 여부를 검색.
        새로운 사용 이벤트마다 HoneyKeyAlert를 반환.
        """
        honey_key = await self._manager.get_honey_key(tenant_id)
        if not honey_key:
            return []

        if self._ct is None:
            logger.debug("CloudTrail 클라이언트 없음 — polling 건너뜀 (tenant=%s)", tenant_id)
            return []

        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(minutes=2)

        try:
            response = self._ct.lookup_events(
                LookupAttributes=[{
                    "AttributeKey": "AccessKeyId",
                    "AttributeValue": honey_key["access_key_id"],
                }],
                StartTime=start_time,
                EndTime=end_time,
            )
        except Exception as exc:
            logger.warning("CloudTrail 폴링 실패 (tenant=%s): %s", tenant_id, exc)
            return []

        alerts: list[HoneyKeyAlert] = []
        for ct_event in response.get("Events", []):
            event_id = ct_event.get("EventId", "unknown")

            if await self._already_reported(tenant_id, event_id):
                continue

            await self._mark_reported(tenant_id, event_id)

            source_ip = ct_event.get("SourceIPAddress", "unknown")
            event_name = ct_event.get("EventName", "unknown")

            logger.critical(
                "Honey AWS Key 외부 사용 감지! tenant=%s key=%s api=%s ip=%s",
                tenant_id, honey_key["access_key_id"][:12], event_name, source_ip,
            )

            alerts.append(HoneyKeyAlert(
                description=(
                    f"Honey AWS Access Key 외부 사용 감지: "
                    f"AccessKeyId={honey_key['access_key_id'][:12]}... "
                    f"API={event_name}, SourceIP={source_ip}. "
                    "서버 내 미끼 파일이 탈취되어 외부에서 사용됨."
                ),
                data={
                    "access_key_id": honey_key["access_key_id"],
                    "source_ip":     source_ip,
                    "event_name":    event_name,
                    "ct_event_id":   event_id,
                    "raw_event":     ct_event,
                },
            ))

        return alerts

    # ------------------------------------------------------------------
    # 중복 보고 방지 (Redis)
    # ------------------------------------------------------------------

    async def _already_reported(self, tenant_id: UUID, event_id: str) -> bool:
        if not self._redis:
            return False
        key = f"honey_key_reported:{tenant_id}:{event_id}"
        return bool(await self._redis.exists(key))

    async def _mark_reported(self, tenant_id: UUID, event_id: str) -> None:
        if not self._redis:
            return
        key = f"honey_key_reported:{tenant_id}:{event_id}"
        await self._redis.setex(key, self.DEDUP_TTL_SECONDS, "1")
