"""
InfraRed v1 — S3 장기 보관 연동 완성
설계서_최종.docx 구현 순서 #7

Fluent Bit S3 파이프라인 + Python 보조 아카이버:
  1. fluent_bit.conf 완성본 (stdout 구성 포함)
  2. Python S3Archiver — Fluent Bit가 올리지 못한 로그 직접 아카이빙
  3. 로그 불변성 보장: S3 Object Lock (Governance 모드)
  4. 오래된 로그 자동 압축 + Glacier 전환
  5. PostgreSQL 장기 보관 파티션 → S3 덤프
"""

from __future__ import annotations

import asyncio
import gzip
import io
import json
import logging
import os
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger("infrared.s3_archiver")

# ──────────────────────────────────────────────────────────────
# 설정
# ──────────────────────────────────────────────────────────────
S3_BUCKET     = os.getenv("S3_LOG_BUCKET", "infrared-logs")
AWS_REGION    = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
RETENTION_DAYS = int(os.getenv("S3_RETENTION_DAYS", "365"))


# ──────────────────────────────────────────────────────────────
# Fluent Bit 설정 완성본
# ──────────────────────────────────────────────────────────────
FLUENT_BIT_CONF = """
[SERVICE]
    Flush         5
    Daemon        Off
    Log_Level     info
    Parsers_File  parsers.conf
    HTTP_Server   On
    HTTP_Listen   0.0.0.0
    HTTP_Port     2020

# ── Nginx 액세스 로그 수집 ──────────────────────────────────
[INPUT]
    Name              tail
    Path              /var/log/nginx/access.log
    Parser            nginx
    Tag               infrared.nginx.access
    Refresh_Interval  5
    Mem_Buf_Limit     10MB
    Skip_Long_Lines   On

# ── Nginx 에러 로그 수집 ───────────────────────────────────
[INPUT]
    Name              tail
    Path              /var/log/nginx/error.log
    Tag               infrared.nginx.error
    Refresh_Interval  5

# ── InfraRed API 로그 수집 ─────────────────────────────────
[INPUT]
    Name              tail
    Path              /var/log/infrared/*.log
    Tag               infrared.app
    Parser            docker
    Refresh_Interval  5
    Mem_Buf_Limit     10MB

# ── syslog 수집 ────────────────────────────────────────────
[INPUT]
    Name          syslog
    Path          /tmp/fluent-bit-syslog
    Tag           infrared.syslog
    Mode          unix_tcp

# ── auditd 로그 수집 (ENABLE_AUDITD=true 일 때) ─────────────
[INPUT]
    Name              tail
    Path              /var/log/audit/audit.log
    Tag               infrared.auditd
    Refresh_Interval  2

# ── 필터: 민감정보 마스킹 ──────────────────────────────────
[FILTER]
    Name    lua
    Match   infrared.*
    Script  mask_secrets.lua
    call    mask_secrets

# ── 필터: 레코드 공통 메타데이터 추가 ─────────────────────
[FILTER]
    Name         record_modifier
    Match        infrared.*
    Record       host ${HOSTNAME}
    Record       environment ${ENVIRONMENT}
    Record       version 1.0

# ── 출력: S3 장기 보관 ────────────────────────────────────
[OUTPUT]
    Name                         s3
    Match                        infrared.*
    bucket                       ${S3_LOG_BUCKET}
    region                       ${AWS_DEFAULT_REGION}
    total_file_size              50M
    upload_timeout               10m
    s3_key_format                /logs/%Y/%m/%d/%H/$TAG[1]/%Y%m%d%H%M%S_${HOSTNAME}.gz
    s3_key_format_tag_delimiters .
    compression                  gzip
    use_put_object               Off
    store_dir                    /tmp/fluent-bit-s3
    store_dir_limit_size         500M
    retry_limit                  5

# ── 출력: stdout (디버그용) ────────────────────────────────
[OUTPUT]
    Name   stdout
    Match  infrared.*
    Format json_lines
"""

FLUENT_BIT_PARSERS = """
[PARSER]
    Name        nginx
    Format      regex
    Regex       ^(?<remote>[^ ]*) (?<host>[^ ]*) (?<user>[^ ]*) \\[(?<time>[^\\]]*)\\] "(?<method>\\S+)(?: +(?<path>[^\\\"]*?)(?: +\\S*)?)?" (?<code>[^ ]*) (?<size>[^ ]*)(?: "(?<referer>[^\\\"]*)" "(?<agent>[^\\\"]*)")?.*$
    Time_Key    time
    Time_Format %d/%b/%Y:%H:%M:%S %z

[PARSER]
    Name        docker
    Format      json
    Time_Key    time
    Time_Format %Y-%m-%dT%H:%M:%S.%L
    Time_Keep   On
"""

FLUENT_BIT_LUA_MASK = """
-- mask_secrets.lua — 민감정보 마스킹
local patterns = {
    {pattern = "Bearer%s+[A-Za-z0-9%.%-_]+",         replacement = "Bearer [REDACTED]"},
    {pattern = "[Pp]assword[\"']?%s*[:=]%s*[\"']?[^%s,\"']+", replacement = "password=[REDACTED]"},
    {pattern = "AKIA[0-9A-Z]{16}",                    replacement = "[AWS_KEY_REDACTED]"},
    {pattern = "[0-9A-Za-z/+]{40}",                   replacement = "[SECRET_REDACTED]"},
    {pattern = "token=[^&%s]+",                       replacement = "token=[REDACTED]"},
}

function mask_secrets(tag, timestamp, record)
    for key, value in pairs(record) do
        if type(value) == "string" then
            local masked = value
            for _, p in ipairs(patterns) do
                masked = masked:gsub(p.pattern, p.replacement)
            end
            record[key] = masked
        end
    end
    return 1, timestamp, record
end
"""


# ──────────────────────────────────────────────────────────────
# Python S3 아카이버
# ──────────────────────────────────────────────────────────────
class S3LogArchiver:
    """
    Fluent Bit 보조 직접 아카이버.
    - DB 쿼리 결과를 S3에 직접 업로드
    - 오래된 로그 파일 수동 업로드
    - S3 Object Lock 적용 (불변성 보장)
    """

    def __init__(
        self,
        bucket:     str = S3_BUCKET,
        region:     str = AWS_REGION,
        db_pool:    Any = None,
    ):
        self.bucket  = bucket
        self.region  = region
        self.db_pool = db_pool
        self.s3      = boto3.client("s3", region_name=region)

    # ── S3 업로드 ──────────────────────────────────────────
    def upload_logs(
        self,
        logs: list[dict],
        *,
        prefix: str = "logs",
        source: str = "api",
    ) -> str:
        """
        로그 배열을 gzip 압축하여 S3에 업로드.
        Returns: S3 key
        """
        now = datetime.utcnow()
        key = (
            f"{prefix}/{now:%Y/%m/%d/%H}/"
            f"{source}_{now:%Y%m%d%H%M%S}_{int(time.time()*1000)}.jsonl.gz"
        )

        # gzip 압축
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
            for log in logs:
                gz.write((json.dumps(log, ensure_ascii=False, default=str) + "\n").encode())
        buf.seek(0)

        self.s3.put_object(
            Bucket      = self.bucket,
            Key         = key,
            Body        = buf.read(),
            ContentType = "application/gzip",
            ContentEncoding = "gzip",
            Metadata    = {
                "source":    source,
                "count":     str(len(logs)),
                "timestamp": now.isoformat(),
            },
        )
        logger.info("S3 업로드: s3://%s/%s (%d records)", self.bucket, key, len(logs))
        return key

    def upload_file(self, local_path: Path, s3_prefix: str = "logs") -> str:
        """로컬 파일을 S3에 직접 업로드"""
        now = datetime.utcnow()
        key = f"{s3_prefix}/{now:%Y/%m/%d}/{local_path.name}"
        self.s3.upload_file(
            str(local_path),
            self.bucket,
            key,
            ExtraArgs={"ServerSideEncryption": "AES256"},
        )
        logger.info("파일 업로드: %s → s3://%s/%s", local_path, self.bucket, key)
        return key

    # ── PostgreSQL → S3 덤프 ───────────────────────────────
    async def dump_old_incidents(self, days_old: int = 90) -> int:
        """
        N일 이상 된 인시던트를 S3에 덤프 후 DB에서 삭제.
        (DB 용량 관리)
        """
        if not self.db_pool:
            return 0

        cutoff = datetime.utcnow() - timedelta(days=days_old)
        async with self.db_pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT * FROM incidents
                WHERE created_at < $1 AND status = 'closed'
                ORDER BY created_at
                LIMIT 10000
                """,
                cutoff,
            )

        if not rows:
            return 0

        logs     = [dict(row) for row in rows]
        s3_key   = self.upload_logs(logs, prefix="archives/incidents", source="db_dump")
        incident_ids = [str(row["id"]) for row in rows]

        async with self.db_pool.acquire() as conn:
            await conn.execute(
                "DELETE FROM incidents WHERE id = ANY($1::uuid[])",
                [r["id"] for r in rows],
            )
            # 아카이브 기록
            await conn.execute(
                """
                INSERT INTO archive_records (entity_type, s3_key, record_count, archived_at)
                VALUES ('incidents', $1, $2, NOW())
                """,
                s3_key, len(logs),
            )

        logger.info("인시던트 %d건 S3 아카이브 완료: %s", len(logs), s3_key)
        return len(logs)

    # ── S3 버킷 초기화 ─────────────────────────────────────
    def ensure_bucket(self) -> None:
        """버킷 생성 + Object Lock + 수명 주기 정책 설정"""
        try:
            self.s3.head_bucket(Bucket=self.bucket)
            logger.info("S3 버킷 확인: %s", self.bucket)
        except ClientError as e:
            if e.response["Error"]["Code"] == "404":
                self._create_bucket_with_lock()
            else:
                raise

    def _create_bucket_with_lock(self) -> None:
        create_kwargs: dict[str, Any] = {
            "Bucket":                    self.bucket,
            "ObjectLockEnabledForBucket": True,
        }
        if self.region != "us-east-1":
            create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": self.region}

        self.s3.create_bucket(**create_kwargs)

        # 버전 관리 활성화 (Object Lock 필수 조건)
        self.s3.put_bucket_versioning(
            Bucket=self.bucket,
            VersioningConfiguration={"Status": "Enabled"},
        )

        # 기본 Object Lock (Governance 90일)
        self.s3.put_object_lock_configuration(
            Bucket=self.bucket,
            ObjectLockConfiguration={
                "ObjectLockEnabled": "Enabled",
                "Rule": {
                    "DefaultRetention": {
                        "Mode": "GOVERNANCE",
                        "Days": 90,
                    }
                },
            },
        )

        # 수명 주기 정책
        self.s3.put_bucket_lifecycle_configuration(
            Bucket=self.bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID":     "archive-logs",
                        "Status": "Enabled",
                        "Filter": {"Prefix": "logs/"},
                        "Transitions": [
                            {"Days": 30,  "StorageClass": "STANDARD_IA"},
                            {"Days": 90,  "StorageClass": "GLACIER"},
                        ],
                        "Expiration": {"Days": RETENTION_DAYS},
                    },
                    {
                        "ID":     "keep-archives",
                        "Status": "Enabled",
                        "Filter": {"Prefix": "archives/"},
                        "Transitions": [
                            {"Days": 7, "StorageClass": "GLACIER"},
                        ],
                    },
                ]
            },
        )

        # 퍼블릭 액세스 차단
        self.s3.put_public_access_block(
            Bucket=self.bucket,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls":       True,
                "IgnorePublicAcls":      True,
                "BlockPublicPolicy":     True,
                "RestrictPublicBuckets": True,
            },
        )

        # 서버 사이드 암호화
        self.s3.put_bucket_encryption(
            Bucket=self.bucket,
            ServerSideEncryptionConfiguration={
                "Rules": [{
                    "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}
                }]
            },
        )

        logger.info("S3 버킷 생성 완료: %s (Object Lock, Lifecycle, 암호화)", self.bucket)


# ──────────────────────────────────────────────────────────────
# 주기적 아카이브 태스크
# ──────────────────────────────────────────────────────────────
async def run_archive_scheduler(archiver: S3LogArchiver, interval_hours: int = 24) -> None:
    """매일 오래된 로그 자동 아카이브"""
    while True:
        try:
            count = await archiver.dump_old_incidents(days_old=90)
            if count:
                logger.info("일일 아카이브 완료: %d건", count)
        except Exception as exc:
            logger.error("아카이브 스케줄러 오류: %s", exc)
        await asyncio.sleep(interval_hours * 3600)


# ──────────────────────────────────────────────────────────────
# 설정 파일 생성 유틸리티
# ──────────────────────────────────────────────────────────────
def write_fluent_bit_configs(base_dir: Path = Path("/etc/fluent-bit")) -> None:
    """Fluent Bit 설정 파일 생성"""
    base_dir.mkdir(parents=True, exist_ok=True)
    (base_dir / "fluent-bit.conf").write_text(FLUENT_BIT_CONF)
    (base_dir / "parsers.conf").write_text(FLUENT_BIT_PARSERS)
    (base_dir / "mask_secrets.lua").write_text(FLUENT_BIT_LUA_MASK)
    logger.info("Fluent Bit 설정 파일 생성: %s", base_dir)
