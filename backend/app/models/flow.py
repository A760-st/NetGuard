import uuid
from datetime import datetime

from sqlalchemy import String, DateTime, Integer, Float, Text, ForeignKey, func
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database.connection import Base


class Flow(Base):
    __tablename__ = "flows"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("analysis_jobs.id"), nullable=False
    )
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    destination_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    source_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    destination_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    duration: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    forward_packets: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    backward_packets: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    forward_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    backward_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    features: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    anomaly_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
