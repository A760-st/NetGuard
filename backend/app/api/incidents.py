from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from pydantic import BaseModel
from uuid import UUID

from app.database.connection import get_db
from app.models.incident import Incident
from app.models.alert import Alert
from app.models.flow import Flow
from app.models.analysis_job import AnalysisJob
from app.schemas.responses import IncidentResponse, PaginatedResponse
from app.services.report import build_incident_report
from app.xai.engine import explain_incident
from app.xai.chat import answer_analyst_question
from app.xai.llm import complete_analyst_text, llm_configured

router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])

ALLOWED_STATUSES = {"open", "investigating", "triaged", "resolved"}


class StatusUpdate(BaseModel):
    status: str


class AnalystChatRequest(BaseModel):
    question: str


@router.get("", response_model=PaginatedResponse)
async def list_incidents(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    job_id: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    threat_type: str | None = None,
    source: str | None = None,
    destination: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    query = select(Incident)
    count_query = select(func.count(Incident.id))

    filters = []
    if job_id:
        filters.append(Incident.job_id == job_id)
    if severity:
        filters.append(Incident.severity == severity)
    if status:
        filters.append(Incident.status == status)

    for f in filters:
        query = query.where(f)
        count_query = count_query.where(f)

    total = (await db.execute(count_query)).scalar() or 0
    offset = (page - 1) * page_size
    query = query.order_by(Incident.created_at.desc()).offset(offset).limit(page_size)
    result = await db.execute(query)
    incidents = list(result.scalars().all())

    # Lightweight in-memory filters for JSON list fields
    if threat_type:
        incidents = [
            i for i in incidents
            if i.threat_types and threat_type in (i.threat_types or [])
        ]
    if source:
        incidents = [
            i for i in incidents
            if i.affected_ips and any(source in (ip or "") for ip in (i.affected_ips or []))
        ]
    if destination:
        incidents = [
            i for i in incidents
            if i.affected_ips and any(destination in (ip or "") for ip in (i.affected_ips or []))
        ]

    if threat_type or source or destination:
        total = len(incidents)

    return PaginatedResponse(
        items=[IncidentResponse.model_validate(i) for i in incidents],
        total=total,
        page=page,
        page_size=page_size,
        pages=max(1, (total + page_size - 1) // page_size) if total else 0,
    )


@router.get("/{incident_id}", response_model=IncidentResponse)
async def get_incident(incident_id: str, db: AsyncSession = Depends(get_db)):
    try:
        uid = UUID(incident_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid incident ID format")

    result = await db.execute(select(Incident).where(Incident.id == uid))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.patch("/{incident_id}/status", response_model=IncidentResponse)
async def update_incident_status(
    incident_id: str,
    body: StatusUpdate,
    db: AsyncSession = Depends(get_db),
):
    status = body.status.strip().lower()
    if status not in ALLOWED_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status. Allowed: {', '.join(sorted(ALLOWED_STATUSES))}",
        )
    try:
        uid = UUID(incident_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid incident ID format")

    result = await db.execute(select(Incident).where(Incident.id == uid))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    incident.status = status
    await db.flush()
    await db.refresh(incident)
    return incident


async def _related_alerts(incident: Incident, db: AsyncSession) -> list[dict]:
    alerts: list[Alert] = []
    related = incident.related_alert_ids or []
    for aid in related:
        try:
            uid = UUID(str(aid))
        except (ValueError, TypeError):
            continue
        row = await db.execute(select(Alert).where(Alert.id == uid))
        alert = row.scalar_one_or_none()
        if alert:
            alerts.append(alert)

    if not alerts and incident.job_id:
        # Fallback: alerts for this job matching affected IPs / threat types
        rows = await db.execute(
            select(Alert).where(Alert.job_id == incident.job_id).limit(100)
        )
        candidates = list(rows.scalars().all())
        affected = set(incident.affected_ips or [])
        threats = set(incident.threat_types or [])
        alerts = [
            a
            for a in candidates
            if (a.source_ip in affected or a.destination_ip in affected)
            and (not threats or a.threat_class in threats)
        ][:20]

    return [_alert_to_dict(a) for a in alerts]


def _alert_to_dict(a: Alert) -> dict:
    return {
        "id": str(a.id),
        "threat_class": a.threat_class,
        "confidence": a.confidence,
        "risk_score": a.risk_score,
        "severity": a.severity,
        "source_ip": a.source_ip,
        "destination_ip": a.destination_ip,
        "source_port": a.source_port,
        "destination_port": a.destination_port,
        "protocol": a.protocol,
        "detector_name": a.detector_name,
        "supporting_evidence": a.supporting_evidence,
        "occurrence_count": a.occurrence_count,
        "created_at": a.created_at.isoformat() if a.created_at else None,
        "flow_id": str(a.flow_id) if a.flow_id else None,
    }


def _flow_to_dict(f: Flow) -> dict:
    return {
        "id": str(f.id),
        "job_id": str(f.job_id),
        "source_ip": f.source_ip,
        "destination_ip": f.destination_ip,
        "source_port": f.source_port,
        "destination_port": f.destination_port,
        "protocol": f.protocol,
        "first_seen": f.first_seen.isoformat() if f.first_seen else None,
        "last_seen": f.last_seen.isoformat() if f.last_seen else None,
        "duration": f.duration,
        "forward_packets": f.forward_packets,
        "backward_packets": f.backward_packets,
        "forward_bytes": f.forward_bytes,
        "backward_bytes": f.backward_bytes,
        "features": f.features,
        "anomaly_score": f.anomaly_score,
    }


def _incident_dict(incident: Incident) -> dict:
    return {
        "id": str(incident.id),
        "job_id": str(incident.job_id) if incident.job_id else None,
        "title": incident.title,
        "threat_types": incident.threat_types,
        "affected_ips": incident.affected_ips,
        "severity": incident.severity,
        "confidence": incident.confidence,
        "evidence": incident.evidence,
        "status": incident.status,
        "first_seen": incident.first_seen.isoformat() if incident.first_seen else None,
        "last_seen": incident.last_seen.isoformat() if incident.last_seen else None,
        "related_alert_ids": incident.related_alert_ids,
    }


async def _related_flows(incident: Incident, db: AsyncSession) -> list[dict]:
    if not incident.job_id:
        return []
    affected = [ip for ip in (incident.affected_ips or []) if ip]
    query = select(Flow).where(Flow.job_id == incident.job_id).limit(200)
    rows = await db.execute(query)
    flows = list(rows.scalars().all())
    if affected:
        matched = [
            f
            for f in flows
            if f.source_ip in affected or f.destination_ip in affected
        ]
        if matched:
            flows = matched
    return [_flow_to_dict(f) for f in flows[:80]]


async def _job_dict(incident: Incident, db: AsyncSession) -> dict | None:
    if not incident.job_id:
        return None
    row = await db.execute(select(AnalysisJob).where(AnalysisJob.id == incident.job_id))
    job = row.scalar_one_or_none()
    if not job:
        return None
    return {"id": str(job.id), "filename": job.filename, "status": job.status}


async def _build_xai(incident: Incident, db: AsyncSession) -> dict:
    alerts = await _related_alerts(incident, db)
    flows = await _related_flows(incident, db)
    job = await _job_dict(incident, db)
    return explain_incident(
        incident=_incident_dict(incident),
        alerts=alerts,
        flows=flows,
        job=job,
    )


async def _load_incident(incident_id: str, db: AsyncSession) -> Incident:
    try:
        uid = UUID(incident_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid incident ID format")
    result = await db.execute(select(Incident).where(Incident.id == uid))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.get("/{incident_id}/xai")
async def get_incident_xai(incident_id: str, db: AsyncSession = Depends(get_db)):
    incident = await _load_incident(incident_id, db)
    return await _build_xai(incident, db)


@router.get("/{incident_id}/analyst")
async def get_incident_analyst(incident_id: str, db: AsyncSession = Depends(get_db)):
    incident = await _load_incident(incident_id, db)
    xai = await _build_xai(incident, db)
    payload = dict(xai.get("analyst") or {})
    if llm_configured():
        llm = complete_analyst_text(xai)
        if llm and llm.get("text"):
            payload["source"] = "llm"
            payload["label"] = "AI-generated (evidence-constrained)"
            payload["disclaimer"] = (
                "Generated by a configured LLM using only this incident's XAI context. "
                "The model was instructed not to invent facts."
            )
            payload["llm_text"] = llm["text"]
            payload["model"] = llm.get("model")
    payload["xai"] = {
        "why_flagged": xai.get("why_flagged"),
        "risk": xai.get("risk"),
        "contributions": xai.get("contributions"),
        "confidence": xai.get("confidence"),
        "transparency": xai.get("transparency"),
        "dataset": xai.get("dataset"),
        "insufficient_evidence": xai.get("insufficient_evidence"),
    }
    return payload


@router.post("/{incident_id}/analyst/chat")
async def incident_analyst_chat(
    incident_id: str,
    body: AnalystChatRequest,
    db: AsyncSession = Depends(get_db),
):
    incident = await _load_incident(incident_id, db)
    xai = await _build_xai(incident, db)
    return answer_analyst_question(xai, body.question)


@router.get("/{incident_id}/report")
async def get_incident_report(incident_id: str, db: AsyncSession = Depends(get_db)):
    incident = await _load_incident(incident_id, db)
    alerts = await _related_alerts(incident, db)
    xai = await _build_xai(incident, db)
    report = build_incident_report(
        incident=_incident_dict(incident),
        alerts=alerts,
        analyst_summary=xai.get("analyst"),
        xai=xai,
    )
    return JSONResponse(content=report)
