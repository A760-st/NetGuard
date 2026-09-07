from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.database.connection import get_db
from app.models.incident import Incident
from app.schemas.responses import IncidentResponse, PaginatedResponse

router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])


@router.get("", response_model=PaginatedResponse)
async def list_incidents(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    job_id: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    query = select(Incident)
    count_query = select(func.count(Incident.id))

    filters = []
    if job_id:
        filters.append(Incident.job_id == job_id)
    if severity:
        filters.append(Incident.severity == severity)
    if status:
        filters.append(Incident.status == status)

    for f in filters:
        query = query.where(f)
        count_query = count_query.where(f)

    total = (await db.execute(count_query)).scalar() or 0
    offset = (page - 1) * page_size
    query = query.order_by(Incident.created_at.desc()).offset(offset).limit(page_size)
    result = await db.execute(query)
    incidents = result.scalars().all()

    return PaginatedResponse(
        items=[IncidentResponse.model_validate(i) for i in incidents],
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size,
    )


@router.get("/{incident_id}", response_model=IncidentResponse)
async def get_incident(incident_id: str, db: AsyncSession = Depends(get_db)):
    from uuid import UUID

    try:
        uid = UUID(incident_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid incident ID format")

    result = await db.execute(select(Incident).where(Incident.id == uid))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident
