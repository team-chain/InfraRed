"""InfraRed first-admin bootstrap.

매번 fresh deploy 후에도 첫 admin 계정이 자동으로 존재하도록 보장한다.
환경변수 기반 — 멱등(idempotent) — migrate 직후 또는 독립 실행 둘 다 가능.

환경변수
========
INITIAL_ADMIN_EMAIL       필수 — 첫 admin 이메일 (예: ops@infrared.kr)
INITIAL_ADMIN_PASSWORD    필수 — 첫 admin 평문 비밀번호 (bcrypt로 저장)
INITIAL_ADMIN_TENANT_ID   선택 — 기본값 'default'
INITIAL_ADMIN_TENANT_NAME 선택 — 기본값 '<tenant_id> Tenant'
INITIAL_ADMIN_PLAN        선택 — 기본값 'mvp'

사용
====
- CLI:      python -m app.db.bootstrap_admin
- Migrate:  migrate.py가 마지막에 자동 호출 (env 변수 있을 때만)
- Makefile: make bootstrap-admin
"""
from __future__ import annotations

import asyncio
import os
import sys
from typing import Any

import asyncpg

from .migrate import _asyncpg_url  # 같은 URL 파싱 사용

REQUIRED_ENV = ("INITIAL_ADMIN_EMAIL", "INITIAL_ADMIN_PASSWORD")


async def bootstrap_admin_on(conn: asyncpg.Connection) -> dict[str, Any] | None:
    """이미 열려있는 연결에 admin을 부트스트랩.

    Returns:
        생성/확인된 admin 사용자 row dict, env 변수가 없거나 skip 됐으면 None.
    """
    email = os.getenv("INITIAL_ADMIN_EMAIL", "").strip()
    password = os.getenv("INITIAL_ADMIN_PASSWORD", "")
    tenant_id = os.getenv("INITIAL_ADMIN_TENANT_ID", "default").strip()
    tenant_name = os.getenv("INITIAL_ADMIN_TENANT_NAME", "").strip() or f"{tenant_id} Tenant"
    plan = os.getenv("INITIAL_ADMIN_PLAN", "mvp").strip()

    if not email or not password:
        print(
            "[bootstrap_admin] skip — INITIAL_ADMIN_EMAIL or INITIAL_ADMIN_PASSWORD not set",
            file=sys.stderr,
        )
        return None

    if len(password) < 8:
        print(
            "[bootstrap_admin] ERROR — INITIAL_ADMIN_PASSWORD must be >= 8 chars",
            file=sys.stderr,
        )
        raise SystemExit(2)

    # 1) 테넌트 확보 (없으면 생성)
    await conn.execute(
        """
        INSERT INTO tenants (tenant_id, name, plan)
        VALUES ($1, $2, $3)
        ON CONFLICT (tenant_id) DO NOTHING
        """,
        tenant_id,
        tenant_name,
        plan,
    )
    await conn.execute(
        """
        INSERT INTO tenant_settings (tenant_id)
        VALUES ($1)
        ON CONFLICT (tenant_id) DO NOTHING
        """,
        tenant_id,
    )

    # 2) 기존 admin 확인 (이메일 + 테넌트 둘 다 일치)
    existing = await conn.fetchrow(
        """
        SELECT user_id::text AS user_id, tenant_id, email, role
        FROM users
        WHERE tenant_id = $1 AND email = $2
        """,
        tenant_id,
        email,
    )
    if existing is not None:
        print(
            f"[bootstrap_admin] OK — admin '{email}' on tenant '{tenant_id}' already exists "
            f"(user_id={existing['user_id']})"
        )
        # 멤버십도 확실하게
        await conn.execute(
            """
            INSERT INTO tenant_memberships (tenant_id, user_id, role)
            VALUES ($1, $2::uuid, 'owner')
            ON CONFLICT (tenant_id, user_id) DO NOTHING
            """,
            tenant_id,
            existing["user_id"],
        )
        return dict(existing)

    # 3) 새 admin 생성 (bcrypt — pgcrypto crypt() 사용, seed.sql과 동일 방식)
    row = await conn.fetchrow(
        """
        INSERT INTO users (tenant_id, email, password_hash, role)
        VALUES ($1, $2, crypt($3, gen_salt('bf')), 'owner')
        ON CONFLICT (tenant_id, email) DO NOTHING
        RETURNING user_id::text AS user_id, tenant_id, email, role
        """,
        tenant_id,
        email,
        password,
    )
    if row is None:
        # race condition — 동시에 다른 프로세스가 만든 경우
        row = await conn.fetchrow(
            """
            SELECT user_id::text AS user_id, tenant_id, email, role
            FROM users
            WHERE tenant_id = $1 AND email = $2
            """,
            tenant_id,
            email,
        )
        if row is None:
            print(
                f"[bootstrap_admin] ERROR — failed to insert and lookup admin '{email}'",
                file=sys.stderr,
            )
            raise SystemExit(3)

    # 4) 멤버십 등록 (admin role)
    await conn.execute(
        """
        INSERT INTO tenant_memberships (tenant_id, user_id, role)
        VALUES ($1, $2::uuid, 'owner')
        ON CONFLICT (tenant_id, user_id) DO NOTHING
        """,
        tenant_id,
        row["user_id"],
    )

    print(
        f"[bootstrap_admin] OK — created admin '{email}' on tenant '{tenant_id}' "
        f"(user_id={row['user_id']})"
    )
    return dict(row)


async def bootstrap_admin(database_url: str) -> dict[str, Any] | None:
    """독립 실행용 — 새 연결을 열어 부트스트랩 수행."""
    url, connect_kwargs = _asyncpg_url(database_url)
    conn = await asyncpg.connect(url, **connect_kwargs)
    try:
        return await bootstrap_admin_on(conn)
    finally:
        await conn.close()


def main() -> int:
    database_url = os.getenv("DATABASE_URL", "")
    if not database_url:
        print("[bootstrap_admin] ERROR: DATABASE_URL is not set", file=sys.stderr)
        return 1

    missing = [k for k in REQUIRED_ENV if not os.getenv(k)]
    if missing:
        print(
            f"[bootstrap_admin] ERROR: missing env vars: {', '.join(missing)}",
            file=sys.stderr,
        )
        return 1

    asyncio.run(bootstrap_admin(database_url))
    return 0


if __name__ == "__main__":
    sys.exit(main())
