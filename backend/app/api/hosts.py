from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.database.connection import get_db
from app.models.flow import Flow
from app.models.alert import Alert
from app.models.host_risk import HostRiskScore
from app.schemas.responses import HostRiskResponse

router = APIRouter(prefix="/api/v1/hosts", tags=["hosts"])


@router.get("/{ip}/risk", response_model=HostRiskResponse)
async def get_host_risk(ip: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(HostRiskScore)
        .where(HostRiskScore.ip_address == ip)
        .order_by(HostRiskScore.created_at.desc())
        .limit(1)
    )
    score = result.scalar_one_or_none()
    if not score:
        raise HTTPException(status_code=404, detail="No risk data for this host")
    return score


@router.get("/{ip}/timeline")
async def get_host_timeline(ip: str, db: AsyncSession = Depends(get_db)):
    flow_count = (
        await db.execute(
            select(func.count(Flow.id)).where(
                (Flow.source_ip == ip) | (Flow.destination_ip == ip)
            )
        )
    ).scalar() or 0

    alert_count = (
        await db.execute(
            select(func.count(Alert.id)).where(
                (Alert.source_ip == ip) | (Alert.destination_ip == ip)
            )
        )
    ).scalar() or 0

    return {
        "ip_address": ip,
        "flow_count": flow_count,
        "alert_count": alert_count,
        "timeline": [],
    }
