"""SQLAlchemy async engine + session factory.

사용 예:

    from app.db.connection import get_session
    async with get_session() as session:
        await session.execute(...)
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

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


@asynccontextmanager
async def get_session() -> AsyncIterator[AsyncSession]:
    async with SessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
