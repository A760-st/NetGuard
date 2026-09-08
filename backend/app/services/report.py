"""Build exportable incident reports from stored detection evidence."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def build_incident_report(
    *,
    incident: dict[str, Any],
    alerts: list[dict[str, Any]] | None = None,
    analyst_summary: dict[str, Any] | None = None,
    xai: dict[str, Any] | None = None,
) -> dict[str, Any]:
    evidence = incident.get("evidence") or {}
    xai = xai or {}
    contrib = (xai.get("contributions") or {})
    return {
        "title": "NetGuard Incident Report",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "incident_id": incident.get("id"),
        "threat_type": (incident.get("threat_types") or [None])[0],
        "threat_types": incident.get("threat_types") or [],
        "severity": incident.get("severity"),
        "risk_score": (xai.get("risk") or {}).get("score", evidence.get("max_risk_score")),
        "confidence": incident.get("confidence"),
        "source": (incident.get("affected_ips") or [None])[0],
        "destinations": (incident.get("affected_ips") or [])[1:],
        "affected_ips": incident.get("affected_ips") or [],
        "status": incident.get("status"),
        "first_seen": incident.get("first_seen"),
        "last_seen": incident.get("last_seen"),
        "detection_engine": evidence.get("detectors") or [],
        "detection_rules": xai.get("detection_rules") or [],
        "relevant_features": _collect_features(alerts or [], evidence),
        "feature_contributions": contrib.get("increasing") or [],
        "risk_reducing_factors": contrib.get("reducing") or [],
        "attribution_method": contrib.get("attribution_method"),
        "detection_evidence": evidence.get("explanations") or alerts or [],
        "explanation": xai.get("why_flagged") or evidence.get("why_flagged") or "",
        "why_flagged": xai.get("why_flagged") or evidence.get("why_flagged") or "",
        "recommended_investigation": xai.get("recommendations") or [],
        "confidence_explanation": xai.get("confidence"),
        "dataset": xai.get("dataset"),
        "transparency": xai.get("transparency"),
        "analyst_summary": analyst_summary,
        "xai": {
            "risk": xai.get("risk"),
            "contributions": contrib,
            "timeline": xai.get("timeline"),
            "uncertainty": xai.get("uncertainty"),
        },
        "disclaimer": (
            "Risk scores and detections are produced by NetGuard rule-based detectors "
            "on recorded traffic. Feature contributions are rule-weighted allocations "
            "of the actual risk score, not SHAP/LIME. Optional ML anomaly scores are "
            "reported only when a trained model artifact is available."
        ),
    }


def _collect_features(alerts: list[dict], evidence: dict) -> list[dict]:
    features: list[dict] = []
    for alert in alerts:
        for ev in alert.get("supporting_evidence") or []:
            if isinstance(ev, dict):
                features.append(ev)
    for entry in evidence.get("explanations") or []:
        if isinstance(entry, dict):
            for ev in entry.get("evidence") or []:
                if isinstance(ev, dict):
                    features.append(ev)
    # de-dupe by feature+value
    seen = set()
    unique = []
    for f in features:
        key = (f.get("feature"), str(f.get("value")))
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    return unique
