"""SQLAlchemy async engine + session factory, and asyncpg pool.

사용 예:

    from app.db.connection import get_session
    async with get_session() as session:
        await session.execute(...)

    # asyncpg raw pool (get_pool)
    from app.db.connection import get_pool
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.fetch(...)
"""
from __future__ import annotations

import ssl
from contextlib import asynccontextmanager
from typing import AsyncIterator
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import asyncpg
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.config import get_settings

_settings = get_settings()


def _ensure_async_driver(url: str) -> str:
    """Normalize PostgreSQL URL to use the asyncpg driver.

    SQLAlchemy's ``create_async_engine`` requires an async driver. If the
    ``DATABASE_URL`` is provided with the plain ``postgresql://`` scheme
    (as is common in CI / 12-factor configs), SQLAlchemy defaults to the
    sync ``psycopg2`` driver, which ``AsyncEngine`` then rejects. We swap
    the scheme to ``postgresql+asyncpg://`` so the URL works in both
    production and tests regardless of how it's written.
    """
    if url.startswith("postgresql+"):
        # Driver already specified — leave it alone.
        return url
    if url.startswith("postgresql://"):
        return "postgresql+asyncpg://" + url[len("postgresql://"):]
    if url.startswith("postgres://"):
        # Some hosted providers (Heroku-style) emit postgres:// — normalize too.
        return "postgresql+asyncpg://" + url[len("postgres://"):]
    return url


engine = create_async_engine(_ensure_async_driver(_settings.database_url), pool_pre_ping=True, echo=False)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

# asyncpg connection pool (lazy-initialised, shared across requests)
_asyncpg_pool: asyncpg.Pool | None = None


def _asyncpg_dsn(url: str) -> tuple[str, dict]:
    """SQLAlchemy asyncpg URL → plain asyncpg DSN + connect kwargs."""
    raw = url.replace("postgresql+asyncpg://", "postgresql://")
    parsed = urlsplit(raw)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    ssl_val = query.pop("ssl", None) or query.pop("sslmode", None)
    clean = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), ""))
    kwargs: dict = {}
    if ssl_val and ssl_val.lower() not in {"disable", "false", "0"}:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        kwargs["ssl"] = ctx
    return clean, kwargs


async def get_pool() -> asyncpg.Pool:
    """Return a shared asyncpg connection pool (create on first call)."""
    global _asyncpg_pool
    if _asyncpg_pool is None or _asyncpg_pool._closed:
        dsn, kwargs = _asyncpg_dsn(_settings.database_url)
        _asyncpg_pool = await asyncpg.create_pool(dsn, min_size=1, max_size=5, **kwargs)
    return _asyncpg_pool


@asynccontextmanager
async def get_session() -> AsyncIterator[AsyncSession]:
    async with SessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
