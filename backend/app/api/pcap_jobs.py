from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.database.connection import get_db
from app.models.analysis_job import AnalysisJob
from app.schemas.responses import AnalysisJobResponse, PaginatedResponse

router = APIRouter(prefix="/api/v1/pcap", tags=["pcap-jobs"])


@router.post("/jobs", response_model=AnalysisJobResponse, status_code=201)
async def create_job(
    filename: str = Query(..., description="PCAP filename"),
    file_size: int = Query(0, description="File size in bytes"),
    db: AsyncSession = Depends(get_db),
):
    job = AnalysisJob(filename=filename, file_size=file_size, status="queued")
    db.add(job)
    await db.flush()
    await db.refresh(job)
    return job


@router.get("/jobs", response_model=PaginatedResponse)
async def list_jobs(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    query = select(AnalysisJob)
    count_query = select(func.count(AnalysisJob.id))

    if status:
        query = query.where(AnalysisJob.status == status)
        count_query = count_query.where(AnalysisJob.status == status)

    total = (await db.execute(count_query)).scalar() or 0
    offset = (page - 1) * page_size
    query = query.order_by(AnalysisJob.created_at.desc()).offset(offset).limit(page_size)
    result = await db.execute(query)
    jobs = result.scalars().all()

    return PaginatedResponse(
        items=[AnalysisJobResponse.model_validate(j) for j in jobs],
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size,
    )


@router.get("/jobs/{job_id}", response_model=AnalysisJobResponse)
async def get_job(job_id: str, db: AsyncSession = Depends(get_db)):
    from uuid import UUID

    try:
        uid = UUID(job_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid job ID format")

    result = await db.execute(select(AnalysisJob).where(AnalysisJob.id == uid))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job
