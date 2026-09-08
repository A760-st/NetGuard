import uuid
from datetime import datetime
from pydantic import BaseModel


class HealthResponse(BaseModel):
    status: str
    version: str
    environment: str
    database: str
    redis: str


class AnalysisJobCreate(BaseModel):
    filename: str
    file_size: int


class AnalysisJobResponse(BaseModel):
    id: uuid.UUID
    filename: str
    file_size: int
    status: str
    progress: float
    packet_count: int | None = None
    flow_count: int | None = None
    alert_count: int | None = None
    error_message: str | None = None
    processing_duration: float | None = None
    created_at: datetime
    updated_at: datetime
    completed_at: datetime | None = None
    file_sha256: str | None = None
    parser_version: str | None = None
    feature_schema_version: str | None = None
    detector_config_version: str | None = None
    data_quality: dict | None = None
    pipeline_stage: str | None = None
    pipeline: dict | None = None
    is_demo: bool = False
    data_mode: str | None = None
    processing_message: str | None = None

    model_config = {"from_attributes": True}


class FlowResponse(BaseModel):
    id: uuid.UUID
    job_id: uuid.UUID
    source_ip: str
    destination_ip: str
    source_port: int | None = None
    destination_port: int | None = None
    protocol: int
    first_seen: datetime
    last_seen: datetime
    duration: float
    forward_packets: int
    backward_packets: int
    forward_bytes: int
    backward_bytes: int
    features: dict | None = None
    anomaly_score: float | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


class AlertResponse(BaseModel):
    id: uuid.UUID
    job_id: uuid.UUID
    flow_id: uuid.UUID | None = None
    source_ip: str
    destination_ip: str
    source_port: int | None = None
    destination_port: int | None = None
    protocol: int | None = None
    threat_class: str
    confidence: float
    risk_score: float
    severity: str
    supporting_evidence: list | dict | None = None
    detector_name: str
    model_version: str | None = None
    status: str
    occurrence_count: int = 1
    created_at: datetime

    model_config = {"from_attributes": True}


class IncidentResponse(BaseModel):
    id: uuid.UUID
    job_id: uuid.UUID
    title: str
    threat_types: list[str] | None = None
    affected_ips: list[str] | None = None
    severity: str
    confidence: float
    related_alert_ids: list[uuid.UUID] | list[str] | None = None
    evidence: dict | None = None
    first_seen: datetime
    last_seen: datetime
    status: str
    created_at: datetime

    model_config = {"from_attributes": True}


class HostRiskResponse(BaseModel):
    ip_address: str
    risk_score: float
    severity: str
    alert_count: float
    flow_count: float
    anomaly_score: float

    model_config = {"from_attributes": True}


class SystemStatusResponse(BaseModel):
    version: str
    environment: str
    database: str
    redis: str
    packet_engine: str
    active_jobs: int
    total_flows: int
    total_alerts: int
    total_incidents: int


class PaginatedResponse(BaseModel):
    items: list
    total: int
    page: int
    page_size: int
    pages: int
