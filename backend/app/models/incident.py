import uuid
from datetime import datetime

from sqlalchemy import String, DateTime, Float, ForeignKey, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database.connection import Base
from app.database.types import GUID, JSONType


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[uuid.UUID] = mapped_column(
        GUID(), primary_key=True, default=uuid.uuid4
    )
    job_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("analysis_jobs.id"), nullable=False
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    threat_types: Mapped[list | None] = mapped_column(JSONType(), nullable=True)
    affected_ips: Mapped[list | None] = mapped_column(JSONType(), nullable=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="LOW")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    related_alert_ids: Mapped[list | None] = mapped_column(JSONType(), nullable=True)
    evidence: Mapped[dict | None] = mapped_column(JSONType(), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="open")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
