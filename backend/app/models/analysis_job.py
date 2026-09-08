import uuid
from datetime import datetime

from sqlalchemy import String, DateTime, Text, Integer, Float, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database.connection import Base
from app.database.types import GUID, JSONType

PARSER_VERSION = "0.1.0"
FEATURE_SCHEMA_VERSION = "1.0.0"
DETECTOR_CONFIG_VERSION = "1.0.0"


class AnalysisJob(Base):
    __tablename__ = "analysis_jobs"

    id: Mapped[uuid.UUID] = mapped_column(
        GUID(), primary_key=True, default=uuid.uuid4
    )
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    file_size: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="queued")
    progress: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    packet_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    flow_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    alert_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    processing_duration: Mapped[float | None] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    file_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    parser_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    feature_schema_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    detector_config_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    data_quality: Mapped[dict | None] = mapped_column(JSONType(), nullable=True)
