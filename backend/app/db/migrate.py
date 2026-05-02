"""
InfraRed DB 마이그레이션 러너
schema.sql + seed.sql을 순서대로 실행합니다.

사용법:
    # 로컬 (DATABASE_URL 환경변수 기반)
    DATABASE_URL="postgresql+asyncpg://..." python backend/app/db/migrate.py

    # aws-deploy.sh 에서 자동 호출됨
"""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

import asyncpg


DB_DIR = Path(__file__).parent
SCHEMA_SQL = DB_DIR / "schema.sql"
SEED_SQL   = Path(__file__).parent.parent.parent.parent / "infra" / "postgres" / "seed.sql"


def _asyncpg_url(url: str) -> str:
    """SQLAlchemy URL → asyncpg URL 변환."""
    return url.replace("postgresql+asyncpg://", "postgresql://")


async def run_migration(database_url: str) -> None:
    url = _asyncpg_url(database_url)
    print(f"[migrate] 접속 중: {url.split('@')[-1]}")  # 호스트만 출력

    conn = await asyncpg.connect(url)
    try:
        # ── schema.sql ──────────────────────────────────────
        if not SCHEMA_SQL.exists():
            raise FileNotFoundError(f"schema.sql 없음: {SCHEMA_SQL}")

        schema = SCHEMA_SQL.read_text(encoding="utf-8")
        print("[migrate] schema.sql 실행 중...")
        await conn.execute(schema)
        print("[migrate] schema.sql 완료")

        # ── seed.sql (존재할 때만) ───────────────────────────
        if SEED_SQL.exists():
            seed = SEED_SQL.read_text(encoding="utf-8")
            print("[migrate] seed.sql 실행 중...")
            await conn.execute(seed)
            print("[migrate] seed.sql 완료")
        else:
            print(f"[migrate] seed.sql 없음 ({SEED_SQL}) — 건너뜀")

    finally:
        await conn.close()

    print("[migrate] ✔ 마이그레이션 완료")


def main() -> int:
    database_url = os.getenv("DATABASE_URL", "")
    if not database_url:
        print("[migrate] ERROR: DATABASE_URL 환경변수가 설정되지 않았습니다.", file=sys.stderr)
        return 1

    asyncio.run(run_migration(database_url))
    return 0


if __name__ == "__main__":
    sys.exit(main())
