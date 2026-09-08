"""Deterministic evidence-grounded analyst summaries (no fabricated AI claims)."""

from __future__ import annotations

from typing import Any


def build_analyst_summary(
    *,
    incident: dict[str, Any] | None = None,
    alerts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a structured analyst summary from real incident/alert evidence.

    Clearly labeled as a deterministic rule-based summary, not an LLM response.
    """
    alerts = alerts or []
    evidence_block = (incident or {}).get("evidence") or {}
    threat_types = (incident or {}).get("threat_types") or evidence_block.get("threat_types") or []
    if not threat_types and alerts:
        threat_types = list({a.get("threat_class") for a in alerts if a.get("threat_class")})

    severity = (incident or {}).get("severity") or _max_severity(alerts)
    confidence = float((incident or {}).get("confidence") or _avg([a.get("confidence") for a in alerts]) or 0)
    affected = (incident or {}).get("affected_ips") or []
    why = evidence_block.get("why_flagged") or _why_from_alerts(alerts)

    indicators: list[str] = []
    evidence_items: list[dict[str, Any]] = []

    for entry in evidence_block.get("explanations") or []:
        if not isinstance(entry, dict):
            continue
        for ev in entry.get("evidence") or []:
            if isinstance(ev, dict):
                evidence_items.append(ev)
                if ev.get("interpretation"):
                    indicators.append(str(ev["interpretation"]))

    if not evidence_items:
        for alert in alerts:
            for ev in alert.get("supporting_evidence") or []:
                if isinstance(ev, dict):
                    evidence_items.append(ev)
                    if ev.get("interpretation"):
                        indicators.append(str(ev["interpretation"]))

    title = (incident or {}).get("title") or (
        f"Activity involving {', '.join(threat_types) or 'unknown threats'}"
    )

    summary = (
        f"Incident '{title}' involves threat type(s) {', '.join(threat_types) or 'unspecified'} "
        f"affecting host(s) {', '.join(affected) or 'unknown'}. "
        f"Assessed severity is {severity} with confidence {confidence:.0%}."
    )

    why_it_matters = _why_it_matters(threat_types, severity)

    investigation_steps = _investigation_steps(threat_types, affected)

    return {
        "source": "deterministic_fallback",
        "disclaimer": (
            "This summary was generated deterministically from detection evidence. "
            "It is not an LLM/AI model response."
        ),
        "incident_summary": summary,
        "why_it_matters": why_it_matters,
        "evidence": evidence_items[:20],
        "suspicious_indicators": indicators[:15] or ([why] if why else []),
        "recommended_investigation_steps": investigation_steps,
        "severity_assessment": {
            "severity": severity,
            "confidence": round(confidence, 3),
            "risk_score": evidence_block.get("max_risk_score"),
        },
        "why_flagged": why,
        "threat_types": threat_types,
        "affected_ips": affected,
    }


def _avg(values: list) -> float:
    nums = [float(v) for v in values if v is not None]
    return sum(nums) / len(nums) if nums else 0.0


def _max_severity(alerts: list[dict]) -> str:
    order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    if not alerts:
        return "LOW"
    return max(
        (a.get("severity") or "LOW" for a in alerts),
        key=lambda s: order.get(s, 0),
    )


def _why_from_alerts(alerts: list[dict]) -> str:
    parts = []
    for a in alerts:
        for ev in a.get("supporting_evidence") or []:
            if isinstance(ev, dict) and ev.get("interpretation"):
                parts.append(ev["interpretation"])
    return " ".join(parts[:5]) if parts else "Detection rules matched observed flow features."


def _why_it_matters(threat_types: list[str], severity: str) -> str:
    mapping = {
        "Exfiltration": "May indicate sensitive data leaving the network.",
        "C2_Beacon": "Periodic beacons often indicate malware command-and-control.",
        "Reconnaissance": "Scanning activity can precede targeted exploitation.",
        "DNS_Tunnel": "DNS tunnelling can hide data transfer inside DNS queries.",
        "DDoS": "Volumetric or SYN flood patterns can disrupt availability.",
        "DGA": "Algorithmically generated domains are common in malware campaigns.",
        "Encrypted_Threat": "Anomalous encrypted sessions can hide malicious payloads.",
    }
    reasons = [mapping[t] for t in threat_types if t in mapping]
    base = " ".join(reasons) if reasons else "Matched rule-based detectors on recorded traffic."
    return f"{base} Current severity ranking: {severity}."


def _investigation_steps(threat_types: list[str], affected: list[str]) -> list[str]:
    steps = [
        "Review related flows and packet/feature evidence for the affected hosts.",
        "Confirm the destination endpoints are unexpected for this environment.",
        "Check whether similar patterns appear in adjacent time windows.",
    ]
    if affected:
        steps.insert(0, f"Investigate hosts: {', '.join(affected[:8])}.")
    if "Exfiltration" in threat_types:
        steps.append("Quantify outbound volume and identify transferred data categories if logs exist.")
    if "C2_Beacon" in threat_types:
        steps.append("Measure inter-arrival timing consistency and destination rarity.")
    if "Reconnaissance" in threat_types:
        steps.append("Map scanned ports/hosts and compare against known scanners.")
    if "DNS_Tunnel" in threat_types:
        steps.append("Inspect DNS query length, entropy, and subdomain structure.")
    steps.append("Update incident status after triage (Investigating → Triaged → Resolved).")
    return steps
