import uuid
from datetime import datetime

from sqlalchemy import String, DateTime, Float, ForeignKey, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database.connection import Base
from app.database.types import GUID, JSONType


class DetectorResult(Base):
    __tablename__ = "detector_results"

    id: Mapped[uuid.UUID] = mapped_column(
        GUID(), primary_key=True, default=uuid.uuid4
    )
    job_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("analysis_jobs.id"), nullable=False
    )
    detector_name: Mapped[str] = mapped_column(String(100), nullable=False)
    threat_class: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="completed")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    detections_count: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    execution_time: Mapped[float | None] = mapped_column(Float, nullable=True)
    error_message: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    metadata_: Mapped[dict | None] = mapped_column("metadata", JSONType(), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
