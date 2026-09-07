from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.database.connection import get_db
from app.models.analysis_job import AnalysisJob
from app.models.flow import Flow
from app.models.alert import Alert
from app.models.incident import Incident
from app.core.config import get_settings
from app.core.logging import get_logger
from app.schemas.responses import SystemStatusResponse

logger = get_logger("analytics")
router = APIRouter(prefix="/api/v1", tags=["analytics"])
settings = get_settings()


@router.get("/analytics/overview")
async def analytics_overview(db: AsyncSession = Depends(get_db)):
    total_flows = (await db.execute(select(func.count(Flow.id)))).scalar() or 0
    total_alerts = (await db.execute(select(func.count(Alert.id)))).scalar() or 0
    total_incidents = (
        await db.execute(select(func.count(Incident.id)))
    ).scalar() or 0
    total_jobs = (
        await db.execute(select(func.count(AnalysisJob.id)))
    ).scalar() or 0
    completed_jobs = (
        await db.execute(
            select(func.count(AnalysisJob.id)).where(
                AnalysisJob.status == "completed"
            )
        )
    ).scalar() or 0

    critical_alerts = (
        await db.execute(
            select(func.count(Alert.id)).where(Alert.severity == "CRITICAL")
        )
    ).scalar() or 0
    high_alerts = (
        await db.execute(
            select(func.count(Alert.id)).where(Alert.severity == "HIGH")
        )
    ).scalar() or 0
    medium_alerts = (
        await db.execute(
            select(func.count(Alert.id)).where(Alert.severity == "MEDIUM")
        )
    ).scalar() or 0
    low_alerts = (
        await db.execute(
            select(func.count(Alert.id)).where(Alert.severity == "LOW")
        )
    ).scalar() or 0

    return {
        "total_flows": total_flows,
        "total_alerts": total_alerts,
        "total_incidents": total_incidents,
        "total_jobs": total_jobs,
        "completed_jobs": completed_jobs,
        "critical_alerts": critical_alerts,
        "high_alerts": high_alerts,
        "medium_alerts": medium_alerts,
        "low_alerts": low_alerts,
    }


@router.get("/analytics/threats")
async def analytics_threats(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(
            Alert.threat_class,
            func.count(Alert.id).label("count"),
        ).group_by(Alert.threat_class)
    )
    threats = [{"threat_class": row[0], "count": row[1]} for row in result.all()]
    return {"threats": threats}


@router.get("/analytics/protocols")
async def analytics_protocols(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(
            Flow.protocol,
            func.count(Flow.id).label("count"),
        ).group_by(Flow.protocol)
    )
    protocols = [{"protocol": row[0], "count": row[1]} for row in result.all()]
    return {"protocols": protocols}


@router.get("/analytics/top-talkers")
async def analytics_top_talkers(
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(
            Flow.source_ip,
            func.count(Flow.id).label("flow_count"),
            func.sum(Flow.forward_bytes).label("total_bytes"),
        )
        .group_by(Flow.source_ip)
        .order_by(func.count(Flow.id).desc())
        .limit(20)
    )
    talkers = [
        {
            "ip": row[0],
            "flow_count": row[1],
            "total_bytes": int(row[2] or 0),
        }
        for row in result.all()
    ]
    return {"top_talkers": talkers}


@router.get("/system/status", response_model=SystemStatusResponse)
async def system_status(db: AsyncSession = Depends(get_db)):
    db_status = "healthy"
    try:
        await db.execute(select(func.count(AnalysisJob.id)))
    except Exception:
        db_status = "unhealthy"

    redis_status = "healthy"
    try:
        import redis.asyncio as aioredis

        r = aioredis.from_url(settings.redis_url)
        await r.ping()
        await r.aclose()
    except Exception:
        redis_status = "unhealthy"

    active_jobs = (
        await db.execute(
            select(func.count(AnalysisJob.id)).where(
                AnalysisJob.status.in_(["queued", "processing"])
            )
        )
    ).scalar() or 0
    total_flows = (await db.execute(select(func.count(Flow.id)))).scalar() or 0
    total_alerts = (await db.execute(select(func.count(Alert.id)))).scalar() or 0
    total_incidents = (
        await db.execute(select(func.count(Incident.id)))
    ).scalar() or 0

    return SystemStatusResponse(
        version=settings.app_version,
        environment=settings.environment,
        database=db_status,
        redis=redis_status,
        packet_engine="unknown",
        active_jobs=active_jobs,
        total_flows=total_flows,
        total_alerts=total_alerts,
        total_incidents=total_incidents,
    )
