import uuid
from datetime import datetime, timezone
from collections import defaultdict

from app.core.logging import get_logger
from app.database.connection import async_session_factory
from app.models.incident import Incident

logger = get_logger("incident_correlator")

SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _build_explanation(group_alerts: list[dict]) -> str:
    parts: list[str] = []
    for alert in group_alerts:
        threat = alert.get("threat_class", "Unknown")
        detector = alert.get("detector_name", "detector")
        evidence = alert.get("supporting_evidence") or []
        interpretations = []
        if isinstance(evidence, list):
            interpretations = [
                e.get("interpretation")
                for e in evidence
                if isinstance(e, dict) and e.get("interpretation")
            ]
        elif isinstance(evidence, dict) and evidence.get("interpretation"):
            interpretations = [evidence["interpretation"]]

        if interpretations:
            parts.append(
                f"{threat} ({detector}): " + "; ".join(interpretations[:3])
            )
        else:
            parts.append(
                f"{threat} flagged by {detector} with confidence "
                f"{float(alert.get('confidence', 0)):.0%}."
            )
    return " ".join(parts) if parts else "Correlated detections on shared hosts."


async def correlate_alerts(
    job_id: str, alerts: list[dict]
) -> list[dict]:
    """Create incidents from alerts.

    Groups by source IP. Creates an incident for every IP that has at least
    one alert so detections are visible on the Incidents page.
    """
    if not alerts:
        return []

    ip_groups: dict[str, list[dict]] = defaultdict(list)
    for alert in alerts:
        src = alert.get("source_ip", "") or "unknown"
        ip_groups[src].append(alert)

    incidents: list[dict] = []

    for ip, group_alerts in ip_groups.items():
        threat_types = list(
            dict.fromkeys(
                a.get("threat_class", "Unknown") for a in group_alerts
            )
        )

        affected_ips = sorted(
            {
                addr
                for a in group_alerts
                for addr in (a.get("source_ip", ""), a.get("destination_ip", ""))
                if addr
            }
        )

        timestamps = [
            a.get("timestamp", 0)
            for a in group_alerts
            if a.get("timestamp", 0) > 0
        ]

        confidences = [float(a.get("confidence", 0) or 0) for a in group_alerts]
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0

        severities = [a.get("severity", "LOW") for a in group_alerts]
        max_severity = max(severities, key=lambda s: SEVERITY_ORDER.get(s, 0))

        risk_scores = [float(a.get("risk_score", 0) or 0) for a in group_alerts]
        max_risk = max(risk_scores) if risk_scores else 0.0

        title = f"Correlated Activity: {', '.join(threat_types)} on {ip}"
        explanation = _build_explanation(group_alerts)

        related_ids = []
        for a in group_alerts:
            aid = a.get("id")
            if not aid:
                continue
            try:
                related_ids.append(uuid.UUID(str(aid)))
            except (ValueError, TypeError):
                continue

        evidence = {
            "alert_count": len(group_alerts),
            "threat_types": threat_types,
            "max_severity": max_severity,
            "max_risk_score": max_risk,
            "detectors": list(
                dict.fromkeys(a.get("detector_name", "") for a in group_alerts if a.get("detector_name"))
            ),
            "explanations": [
                {
                    "threat_class": a.get("threat_class"),
                    "detector": a.get("detector_name"),
                    "confidence": a.get("confidence"),
                    "risk_score": a.get("risk_score"),
                    "evidence": a.get("supporting_evidence"),
                }
                for a in group_alerts
            ],
            "why_flagged": explanation,
        }

        incident = {
            "title": title,
            "threat_types": threat_types,
            "affected_ips": affected_ips,
            "severity": max_severity,
            "confidence": round(avg_confidence, 3),
            "evidence": evidence,
            "first_seen": datetime.fromtimestamp(
                min(timestamps), tz=timezone.utc
            ) if timestamps else datetime.now(timezone.utc),
            "last_seen": datetime.fromtimestamp(
                max(timestamps), tz=timezone.utc
            ) if timestamps else datetime.now(timezone.utc),
            "related_alert_ids": related_ids,
        }
        incidents.append(incident)

    async with async_session_factory() as db:
        for inc in incidents:
            related_ids = inc.pop("related_alert_ids", [])
            db_incident = Incident(
                job_id=uuid.UUID(job_id),
                title=inc["title"],
                threat_types=inc["threat_types"],
                affected_ips=inc["affected_ips"],
                severity=inc["severity"],
                confidence=inc["confidence"],
                evidence=inc["evidence"],
                first_seen=inc["first_seen"],
                last_seen=inc["last_seen"],
                related_alert_ids=[str(x) for x in related_ids],
                status="open",
            )
            db.add(db_incident)
        await db.commit()

    logger.info(
        "incidents_correlated",
        job_id=job_id,
        incident_count=len(incidents),
    )

    return incidents
