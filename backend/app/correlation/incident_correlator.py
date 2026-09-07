import uuid
from datetime import datetime, timezone
from collections import defaultdict

from app.core.logging import get_logger
from app.database.connection import async_session_factory
from app.models.incident import Incident

logger = get_logger("incident_correlator")


async def correlate_alerts(
    job_id: str, alerts: list[dict]
) -> list[dict]:
    if not alerts:
        return []

    ip_groups = defaultdict(list)
    for alert in alerts:
        src = alert.get("source_ip", "")
        dst = alert.get("destination_ip", "")
        ip_groups[src].append(alert)
        if dst != src:
            ip_groups[dst].append(alert)

    incidents: list[dict] = []

    for ip, group_alerts in ip_groups.items():
        if len(group_alerts) < 2:
            continue

        threat_types = list(
            set(
                a.get("threat_class", "Unknown")
                for a in group_alerts
            )
        )

        affected_ips = sorted(
            {
                ip
                for a in group_alerts
                for ip in (a.get("source_ip", ""), a.get("destination_ip", ""))
                if ip
            }
        )

        timestamps = [
            a.get("timestamp", 0)
            for a in group_alerts
            if a.get("timestamp", 0) > 0
        ]

        confidences = [a.get("confidence", 0) for a in group_alerts]
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0

        severity_order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        severities = [a.get("severity", "LOW") for a in group_alerts]
        max_severity = max(severities, key=lambda s: severity_order.get(s, 0))

        title = f"Correlated Activity: {', '.join(threat_types)} on {ip}"

        incident = {
            "title": title,
            "threat_types": threat_types,
            "affected_ips": affected_ips,
            "severity": max_severity,
            "confidence": round(avg_confidence, 3),
            "evidence": {
                "alert_count": len(group_alerts),
                "threat_types": threat_types,
                "max_severity": max_severity,
            },
            "first_seen": datetime.fromtimestamp(
                min(timestamps), tz=timezone.utc
            ) if timestamps else datetime.now(timezone.utc),
            "last_seen": datetime.fromtimestamp(
                max(timestamps), tz=timezone.utc
            ) if timestamps else datetime.now(timezone.utc),
            "related_alert_ids": [
                a.get("id") for a in group_alerts if a.get("id")
            ],
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
                related_alert_ids=related_ids,
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
