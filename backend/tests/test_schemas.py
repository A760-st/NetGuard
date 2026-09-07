import pytest
from app.schemas.responses import (
    HealthResponse,
    AnalysisJobResponse,
    FlowResponse,
    AlertResponse,
    IncidentResponse,
    HostRiskResponse,
    SystemStatusResponse,
    PaginatedResponse,
)
import uuid
from datetime import datetime, timezone


def test_health_response():
    r = HealthResponse(
        status="healthy", version="0.1.0", environment="test", database="healthy", redis="healthy"
    )
    assert r.status == "healthy"
    assert r.version == "0.1.0"


def test_system_status_response():
    r = SystemStatusResponse(
        version="0.1.0",
        environment="test",
        database="healthy",
        redis="healthy",
        packet_engine="healthy",
        active_jobs=0,
        total_flows=0,
        total_alerts=0,
        total_incidents=0,
    )
    assert r.version == "0.1.0"
    assert r.active_jobs == 0


def test_paginated_response():
    r = PaginatedResponse(items=[], total=0, page=1, page_size=20, pages=0)
    assert r.items == []
    assert r.total == 0


def test_analysis_job_response():
    now = datetime.now(timezone.utc)
    r = AnalysisJobResponse(
        id=uuid.uuid4(),
        filename="test.pcap",
        file_size=1024,
        status="queued",
        progress=0.0,
        created_at=now,
        updated_at=now,
    )
    assert r.filename == "test.pcap"
    assert r.status == "queued"


def test_flow_response():
    now = datetime.now(timezone.utc)
    r = FlowResponse(
        id=uuid.uuid4(),
        job_id=uuid.uuid4(),
        source_ip="192.168.1.1",
        destination_ip="10.0.0.1",
        protocol=6,
        first_seen=now,
        last_seen=now,
        duration=1.0,
        forward_packets=10,
        backward_packets=5,
        forward_bytes=1000,
        backward_bytes=500,
    )
    assert r.source_ip == "192.168.1.1"
    assert r.forward_packets == 10


def test_alert_response():
    now = datetime.now(timezone.utc)
    r = AlertResponse(
        id=uuid.uuid4(),
        job_id=uuid.uuid4(),
        source_ip="192.168.1.1",
        destination_ip="10.0.0.1",
        threat_class="DDoS",
        confidence=0.85,
        risk_score=72.0,
        severity="HIGH",
        detector_name="DDoSDetector",
        status="new",
        created_at=now,
    )
    assert r.threat_class == "DDoS"
    assert r.severity == "HIGH"
