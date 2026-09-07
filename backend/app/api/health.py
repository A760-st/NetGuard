from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from app.core.config import get_settings
from app.core.logging import get_logger
from app.database.connection import get_db
from app.schemas.responses import HealthResponse

logger = get_logger("health")
router = APIRouter(tags=["health"])
settings = get_settings()


@router.get("/health", response_model=HealthResponse)
async def health_check(db: AsyncSession = Depends(get_db)):
    db_status = "healthy"
    redis_status = "healthy"

    try:
        await db.execute(text("SELECT 1"))
    except Exception as e:
        logger.error("database_health_check_failed", error=str(e))
        db_status = "unhealthy"

    try:
        import redis.asyncio as aioredis
        r = aioredis.from_url(settings.redis_url)
        await r.ping()
        await r.aclose()
    except Exception as e:
        logger.error("redis_health_check_failed", error=str(e))
        redis_status = "unhealthy"

    status = "healthy"
    if db_status != "healthy" or redis_status != "healthy":
        status = "degraded"

    return HealthResponse(
        status=status,
        version=settings.app_version,
        environment=settings.environment,
        database=db_status,
        redis=redis_status,
    )
