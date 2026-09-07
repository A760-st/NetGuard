from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.database.connection import get_db
from app.models.flow import Flow
from app.schemas.responses import FlowResponse, PaginatedResponse

router = APIRouter(prefix="/api/v1/flows", tags=["flows"])


@router.get("", response_model=PaginatedResponse)
async def list_flows(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    job_id: str | None = None,
    source_ip: str | None = None,
    destination_ip: str | None = None,
    protocol: int | None = None,
    db: AsyncSession = Depends(get_db),
):
    query = select(Flow)
    count_query = select(func.count(Flow.id))

    if job_id:
        query = query.where(Flow.job_id == job_id)
        count_query = count_query.where(Flow.job_id == job_id)
    if source_ip:
        query = query.where(Flow.source_ip == source_ip)
        count_query = count_query.where(Flow.source_ip == source_ip)
    if destination_ip:
        query = query.where(Flow.destination_ip == destination_ip)
        count_query = count_query.where(Flow.destination_ip == destination_ip)
    if protocol is not None:
        query = query.where(Flow.protocol == protocol)
        count_query = count_query.where(Flow.protocol == protocol)

    total = (await db.execute(count_query)).scalar() or 0
    offset = (page - 1) * page_size
    query = query.order_by(Flow.first_seen.desc()).offset(offset).limit(page_size)
    result = await db.execute(query)
    flows = result.scalars().all()

    return PaginatedResponse(
        items=[FlowResponse.model_validate(f) for f in flows],
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size,
    )


@router.get("/{flow_id}", response_model=FlowResponse)
async def get_flow(flow_id: str, db: AsyncSession = Depends(get_db)):
    from uuid import UUID

    try:
        uid = UUID(flow_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid flow ID format")

    result = await db.execute(select(Flow).where(Flow.id == uid))
    flow = result.scalar_one_or_none()
    if not flow:
        raise HTTPException(status_code=404, detail="Flow not found")
    return flow
