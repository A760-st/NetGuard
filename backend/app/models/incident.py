import uuid
from datetime import datetime

from sqlalchemy import String, DateTime, Float, Integer, Text, ForeignKey, func
from sqlalchemy.dialects.postgresql import UUID, JSONB, ARRAY
from sqlalchemy.orm import Mapped, mapped_column

from app.database.connection import Base


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("analysis_jobs.id"), nullable=False
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    threat_types: Mapped[list | None] = mapped_column(ARRAY(String), nullable=True)
    affected_ips: Mapped[list | None] = mapped_column(ARRAY(String), nullable=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="LOW")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    related_alert_ids: Mapped[list | None] = mapped_column(
        ARRAY(UUID(as_uuid=True)), nullable=True
    )
    evidence: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="open")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
