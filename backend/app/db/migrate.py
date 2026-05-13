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


async def _execute_script(conn: asyncpg.Connection, sql: str, label: str) -> None:
    for statement in _split_sql_statements(sql):
        if not statement:
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

        seed = SEED_SQL.read_text(encoding="utf-8") if SEED_SQL.exists() else DEFAULT_SEED_SQL
        print("[migrate] applying seed.sql")
        await _execute_script(conn, seed, "seed.sql")

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
