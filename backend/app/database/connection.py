import os
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase

from app.core.config import get_settings

settings = get_settings()

# Local/demo default: SQLite. Use PostgreSQL only when DATABASE_URL is set
# or NETGUARD_USE_POSTGRES=1 is explicitly enabled.
_explicit = os.environ.get("DATABASE_URL")
_force_postgres = os.environ.get("NETGUARD_USE_POSTGRES", "").lower() in {"1", "true", "yes"}

if _explicit:
    _db_url = _explicit
elif _force_postgres:
    _db_url = settings.database_url
else:
    _db_path = os.path.join(os.path.dirname(__file__), "..", "..", "netguard.db")
    _db_url = f"sqlite+aiosqlite:///{os.path.abspath(_db_path).replace(os.sep, '/')}"

engine = create_async_engine(
    _db_url,
    echo=settings.debug,
    **({"pool_size": 10, "max_overflow": 20} if _db_url.startswith("postgresql") else {}),
)

async_session_factory = async_sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncSession:
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db() -> None:
    await engine.dispose()
