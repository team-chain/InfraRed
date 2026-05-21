"""InfraRed database migration runner.

Executes backend/app/db/schema.sql and infra/postgres/seed.sql in order.
"""
from __future__ import annotations

import asyncio
import os
import ssl
import sys
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import asyncpg

DB_DIR = Path(__file__).parent
SCHEMA_SQL = DB_DIR / "schema.sql"
MIGRATE_V2_SQL = DB_DIR / "migrate_v2.sql"
MIGRATE_V3_SQL = DB_DIR / "migrate_v3_freetier.sql"   # FTS GIN + Lambda AI 테이블
MIGRATE_V4_SQL = DB_DIR / "migrate_v4_v3_schema.sql"  # v3.0 설계서: 캠페인/Watchdog/자산 중요도
MIGRATE_V5_SQL  = DB_DIR / "migrate_v5_billing.sql"    # v4.0 Billing: Stripe 과금 + UEBA 테이블
MIGRATE_V6_SQL  = DB_DIR / "migrate_v6_response.sql"  # 자동 대응 로그
MIGRATE_V7_SQL  = DB_DIR / "migrate_v7_gdpr.sql"      # GDPR 데이터 거버넌스
MIGRATE_V7B_SQL = DB_DIR / "migrate_v7_ops_quality.sql"  # OPS 품질
MIGRATE_V8_SQL  = DB_DIR / "migrate_v8_security.sql"  # v7 Dead Man's Switch, UEBA Drift
MIGRATE_V9_SQL  = DB_DIR / "migrate_v9_timescale.sql" # TimescaleDB hypertable
MIGRATE_V10_SQL = DB_DIR / "migrate_v10_v8_tables.sql" # v8.0 심화: TRAVEL/EXEC-FIRST/JIT-SSH/HoneyKey/CanaryPack
MIGRATE_V11_SQL = DB_DIR / "migrate_v11_pending_invitations.sql" # 미가입 사용자 초대
SEED_SQL = Path(__file__).parent.parent.parent.parent / "infra" / "postgres" / "seed.sql"
DEFAULT_SEED_SQL = """
INSERT INTO tenant_settings (tenant_id)
VALUES ('company-a')
ON CONFLICT (tenant_id) DO NOTHING;

INSERT INTO api_keys (tenant_id, key_hash, name, source)
VALUES (
  'company-a',
  encode(digest('ir_demo_key_company_a_000000000000', 'sha256'), 'hex'),
  'Demo SDK / API Key',
  'api'
)
ON CONFLICT (key_hash) DO NOTHING;
"""


def _asyncpg_url(url: str) -> tuple[str, dict[str, object]]:
    """Convert SQLAlchemy asyncpg URLs into asyncpg.connect arguments."""
    raw_url = url.replace("postgresql+asyncpg://", "postgresql://")
    parsed = urlsplit(raw_url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    ssl_value = query.pop("ssl", None) or query.pop("sslmode", None)
    clean_url = urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, urlencode(query), parsed.fragment)
    )
    kwargs: dict[str, object] = {}
    if ssl_value and ssl_value.lower() not in {"disable", "false", "0"}:
        mode = ssl_value.lower()
        if mode in {"require", "allow", "prefer", "true", "1"}:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            kwargs["ssl"] = context
        else:
            kwargs["ssl"] = True
    return clean_url, kwargs


def _split_sql_statements(sql: str) -> list[str]:
    """Split SQL into statements, respecting $$ dollar-quoted blocks and string literals."""
    statements: list[str] = []
    current: list[str] = []
    i = 0
    in_dollar_quote = False
    dollar_tag = ""
    in_single_quote = False

    while i < len(sql):
        ch = sql[i]

        # Handle single-quoted strings
        if in_single_quote:
            current.append(ch)
            if ch == "'" and (i + 1 >= len(sql) or sql[i + 1] != "'"):
                in_single_quote = False
            elif ch == "'" and sql[i + 1] == "'":
                current.append(sql[i + 1])
                i += 2
                continue
            i += 1
            continue

        # Handle dollar-quoted strings (e.g. $$ or $tag$)
        if in_dollar_quote:
            # Look for matching closing tag
            if sql[i:].startswith(dollar_tag):
                current.append(dollar_tag)
                i += len(dollar_tag)
                in_dollar_quote = False
                dollar_tag = ""
            else:
                current.append(ch)
                i += 1
            continue

        # Check for start of dollar-quote
        if ch == "$":
            end = sql.find("$", i + 1)
            if end != -1:
                tag = sql[i : end + 1]
                # Valid dollar-quote tag: only letters, digits, underscore between $'s
                inner = tag[1:-1]
                if all(c.isalnum() or c == "_" for c in inner):
                    in_dollar_quote = True
                    dollar_tag = tag
                    current.append(tag)
                    i = end + 1
                    continue

        if ch == "'":
            in_single_quote = True
            current.append(ch)
            i += 1
            continue

        if ch == ";":
            stmt = "".join(current).strip()
            if stmt:
                statements.append(stmt)
            current = []
            i += 1
            continue

        # Line comment
        if ch == "-" and i + 1 < len(sql) and sql[i + 1] == "-":
            end = sql.find("\n", i)
            if end == -1:
                break
            current.append(sql[i:end])
            i = end
            continue

        current.append(ch)
        i += 1

    # Flush any remaining
    stmt = "".join(current).strip()
    if stmt:
        statements.append(stmt)

    return statements


async def _execute_script(
    conn: asyncpg.Connection, sql: str, label: str, skip_errors: bool = False
) -> None:
    for statement in _split_sql_statements(sql):
        if not statement:
            continue
        # 주석만 있는 statement 건너뜀
        stripped = "\n".join(
            line for line in statement.splitlines() if not line.strip().startswith("--")
        ).strip()
        if not stripped:
            continue
        try:
            await conn.execute(statement)
        except asyncpg.exceptions.InsufficientPrivilegeError:
            relaxed = _relaxed_create_table(statement)
            if relaxed != statement:
                first_line = statement.splitlines()[0]
                print(f"[migrate] retrying without foreign keys: {first_line}")
                await conn.execute(relaxed)
                continue
            if statement.upper().startswith("CREATE INDEX IF NOT EXISTS"):
                first_line = statement.splitlines()[0]
                print(f"[migrate] skipped privilege-limited index: {first_line}")
                continue
            raise
        except Exception as e:
            first_line = statement.splitlines()[0].strip()
            if skip_errors:
                print(f"[migrate] WARN skipped [{label}]: {first_line!r} — {e}")
                continue
            raise
    print(f"[migrate] {label} complete")


def _relaxed_create_table(statement: str) -> str:
    upper = statement.upper()
    if not upper.startswith("CREATE TABLE IF NOT EXISTS"):
        return statement
    if not any(name in upper for name in {"API_KEYS", "TENANT_SETTINGS", "PENDING_ACTIONS"}):
        return statement
    relaxed = statement
    relaxed = relaxed.replace(
        "tenant_id    TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE",
        "tenant_id    TEXT NOT NULL",
    )
    relaxed = relaxed.replace(
        "tenant_id      TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE",
        "tenant_id      TEXT NOT NULL",
    )
    relaxed = relaxed.replace(
        "tenant_id          TEXT PRIMARY KEY REFERENCES tenants(tenant_id) ON DELETE CASCADE",
        "tenant_id          TEXT PRIMARY KEY",
    )
    relaxed = relaxed.replace(
        "incident_id    TEXT REFERENCES incidents(incident_id) ON DELETE SET NULL",
        "incident_id    TEXT",
    )
    return relaxed


async def run_migration(database_url: str) -> None:
    url, connect_kwargs = _asyncpg_url(database_url)
    print(f"[migrate] connecting to {url.split('@')[-1]}")

    conn = await asyncpg.connect(url, **connect_kwargs)
    try:
        if not SCHEMA_SQL.exists():
            raise FileNotFoundError(f"schema.sql not found: {SCHEMA_SQL}")

        schema = SCHEMA_SQL.read_text(encoding="utf-8")
        print("[migrate] applying schema.sql")
        await _execute_script(conn, schema, "schema.sql")

        if MIGRATE_V2_SQL.exists():
            migrate_v2 = MIGRATE_V2_SQL.read_text(encoding="utf-8")
            print("[migrate] applying migrate_v2.sql (고도화 v2.0)")
            await _execute_script(conn, migrate_v2, "migrate_v2.sql")

        if MIGRATE_V3_SQL.exists():
            migrate_v3 = MIGRATE_V3_SQL.read_text(encoding="utf-8")
            print("[migrate] applying migrate_v3_freetier.sql (FTS GIN + Lambda AI 테이블)")
            await _execute_script(conn, migrate_v3, "migrate_v3_freetier.sql")

        if MIGRATE_V4_SQL.exists():
            migrate_v4 = MIGRATE_V4_SQL.read_text(encoding="utf-8")
            print("[migrate] applying migrate_v4_v3_schema.sql (v3.0 설계서: 캠페인/Watchdog/자산 중요도)")
            await _execute_script(conn, migrate_v4, "migrate_v4_v3_schema.sql")

        if MIGRATE_V5_SQL.exists():
            migrate_v5 = MIGRATE_V5_SQL.read_text(encoding="utf-8")
            print("[migrate] applying migrate_v5_billing.sql (v4.0 Billing: Stripe 과금 + UEBA 테이블)")
            await _execute_script(conn, migrate_v5, "migrate_v5_billing.sql")

        if MIGRATE_V6_SQL.exists():
            print("[migrate] applying migrate_v6_response.sql (자동 대응 로그)")
            await _execute_script(conn, MIGRATE_V6_SQL.read_text(encoding="utf-8"), "migrate_v6_response.sql")

        if MIGRATE_V7_SQL.exists():
            print("[migrate] applying migrate_v7_gdpr.sql (GDPR 데이터 거버넌스)")
            await _execute_script(conn, MIGRATE_V7_SQL.read_text(encoding="utf-8"), "migrate_v7_gdpr.sql")

        if MIGRATE_V7B_SQL.exists():
            print("[migrate] applying migrate_v7_ops_quality.sql (OPS 품질)")
            await _execute_script(conn, MIGRATE_V7B_SQL.read_text(encoding="utf-8"), "migrate_v7_ops_quality.sql")

        if MIGRATE_V8_SQL.exists():
            print("[migrate] applying migrate_v8_security.sql (v7 Dead Man's Switch, UEBA Drift)")
            await _execute_script(conn, MIGRATE_V8_SQL.read_text(encoding="utf-8"), "migrate_v8_security.sql")

        if MIGRATE_V9_SQL.exists():
            print("[migrate] applying migrate_v9_timescale.sql (TimescaleDB hypertable)")
            await _execute_script(conn, MIGRATE_V9_SQL.read_text(encoding="utf-8"), "migrate_v9_timescale.sql")

        if MIGRATE_V10_SQL.exists():
            print("[migrate] applying migrate_v10_v8_tables.sql (v8.0: TRAVEL/EXEC-FIRST/JIT-SSH/HoneyKey/CanaryPack)")
            await _execute_script(conn, MIGRATE_V10_SQL.read_text(encoding="utf-8"), "migrate_v10_v8_tables.sql")

        if MIGRATE_V11_SQL.exists():
            print("[migrate] applying migrate_v11_pending_invitations.sql (미가입 사용자 초대)")
            await _execute_script(conn, MIGRATE_V11_SQL.read_text(encoding="utf-8"), "migrate_v11_pending_invitations.sql")

        seed = SEED_SQL.read_text(encoding="utf-8") if SEED_SQL.exists() else DEFAULT_SEED_SQL
        print("[migrate] applying seed.sql")
        await _execute_script(conn, seed, "seed.sql", skip_errors=True)

    finally:
        await conn.close()

    print("[migrate] complete")


def main() -> int:
    database_url = os.getenv("DATABASE_URL", "")
    if not database_url:
        print("[migrate] ERROR: DATABASE_URL is not set", file=sys.stderr)
        return 1

    asyncio.run(run_migration(database_url))
    return 0


if __name__ == "__main__":
    sys.exit(main())
