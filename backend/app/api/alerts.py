from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.database.connection import get_db
from app.models.alert import Alert
from app.schemas.responses import AlertResponse, PaginatedResponse

router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"])


@router.get("", response_model=PaginatedResponse)
async def list_alerts(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    job_id: str | None = None,
    severity: str | None = None,
    threat_class: str | None = None,
    source_ip: str | None = None,
    status: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    query = select(Alert)
    count_query = select(func.count(Alert.id))

    filters = []
    if job_id:
        filters.append(Alert.job_id == job_id)
    if severity:
        filters.append(Alert.severity == severity)
    if threat_class:
        filters.append(Alert.threat_class == threat_class)
    if source_ip:
        filters.append(Alert.source_ip == source_ip)
    if status:
        filters.append(Alert.status == status)

    for f in filters:
        query = query.where(f)
        count_query = count_query.where(f)

    total = (await db.execute(count_query)).scalar() or 0
    offset = (page - 1) * page_size
    query = query.order_by(Alert.created_at.desc()).offset(offset).limit(page_size)
    result = await db.execute(query)
    alerts = result.scalars().all()

    return PaginatedResponse(
        items=[AlertResponse.model_validate(a) for a in alerts],
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size,
    )


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(alert_id: str, db: AsyncSession = Depends(get_db)):
    from uuid import UUID

    try:
        uid = UUID(alert_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid alert ID format")

    result = await db.execute(select(Alert).where(Alert.id == uid))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert
