import os
import uuid
import asyncio
import json
from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, update

from app.core.config import get_settings
from app.core.logging import get_logger
from app.database.connection import get_db, async_session_factory
from app.models.analysis_job import AnalysisJob
from app.schemas.responses import AnalysisJobResponse, PaginatedResponse
from app.services.job_processor import (
    create_job,
    start_job_processing,
    cancel_job_processing,
    get_job_progress,
)

logger = get_logger("pcap_jobs")
router = APIRouter(prefix="/api/v1/pcap", tags=["pcap-jobs"])
settings = get_settings()

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}
MAX_FILE_SIZE = settings.max_upload_size_mb * 1024 * 1024


@router.post("/upload", response_model=AnalysisJobResponse, status_code=201)
async def upload_pcap(file: UploadFile = File(...), db: AsyncSession = Depends(get_db)):
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")

    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type: {ext}. Allowed: {', '.join(ALLOWED_EXTENSIONS)}",
        )

    content = await file.read()
    file_size = len(content)
    if file_size > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"File too large: {file_size} bytes. Maximum: {MAX_FILE_SIZE} bytes",
        )
    if file_size == 0:
        raise HTTPException(status_code=400, detail="Empty file")

    file_id = str(uuid.uuid4())
    safe_name = os.path.basename(file.filename)
    file_path = os.path.join(UPLOAD_DIR, f"{file_id}_{safe_name}")

    with open(file_path, "wb") as f:
        f.write(content)

    job_id = await create_job(file_path, file_size, safe_name)

    await start_job_processing(job_id, file_path)

    async with async_session_factory() as session:
        result = await session.execute(
            select(AnalysisJob).where(AnalysisJob.id == uuid.UUID(job_id))
        )
        job = result.scalar_one()

    return job


@router.post("/jobs", response_model=AnalysisJobResponse, status_code=201)
async def create_job_manual(
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

    progress = get_job_progress(job_id)
    if progress > 0:
        job.progress = progress

    return job


@router.post("/jobs/{job_id}/cancel", response_model=AnalysisJobResponse)
async def cancel_job(job_id: str, db: AsyncSession = Depends(get_db)):
    from uuid import UUID

    try:
        uid = UUID(job_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid job ID format")

    cancelled = await cancel_job_processing(job_id)
    if not cancelled:
        raise HTTPException(
            status_code=400, detail="Job not found or not cancellable"
        )

    result = await db.execute(select(AnalysisJob).where(AnalysisJob.id == uid))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


@router.get("/jobs/{job_id}/progress")
async def job_progress_sse(job_id: str):
    from uuid import UUID

    try:
        UUID(job_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid job ID format")

    async def event_generator():
        while True:
            async with async_session_factory() as db:
                result = await db.execute(
                    select(AnalysisJob).where(AnalysisJob.id == uuid.UUID(job_id))
                )
                job = result.scalar_one_or_none()

            if not job:
                yield f"data: {json.dumps({'status': 'not_found'})}\n\n"
                break

            progress = get_job_progress(job_id)

            data = {
                "job_id": job_id,
                "status": job.status,
                "progress": progress or job.progress,
                "packet_count": job.packet_count,
                "flow_count": job.flow_count,
                "alert_count": job.alert_count,
            }
            yield f"data: {json.dumps(data)}\n\n"

            if job.status in ("completed", "failed", "cancelled"):
                break

            await asyncio.sleep(1)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
