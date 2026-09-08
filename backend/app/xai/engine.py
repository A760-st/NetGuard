"""Assemble a full XAI explanation from incident, alerts, and related flows."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from app.xai.contributions import (
    calculate_feature_contributions,
    mitigating_factors,
)
from app.xai.label_map import map_dataset_label
from app.xai.reasoning import (
    build_timeline,
    generate_confidence_explanation,
    generate_narrative,
    generate_recommendation,
    generate_why_flagged,
    protocol_name,
    severity_from_score,
)

UNAVAILABLE = "Not available from the observed traffic."


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _first_present(*values: Any) -> Any:
    for value in values:
        if value is None or value == "":
            continue
        if isinstance(value, (list, dict)) and not value:
            continue
        return value
    return None


def _aggregate_traffic(flows: list[dict[str, Any]]) -> dict[str, Any]:
    if not flows:
        return {}
    primary = max(
        flows,
        key=lambda f: int(f.get("forward_bytes") or 0) + int(f.get("backward_bytes") or 0),
    )
    fwd_b = sum(int(f.get("forward_bytes") or 0) for f in flows)
    bwd_b = sum(int(f.get("backward_bytes") or 0) for f in flows)
    fwd_p = sum(int(f.get("forward_packets") or 0) for f in flows)
    bwd_p = sum(int(f.get("backward_packets") or 0) for f in flows)
    duration = float(primary.get("duration") or 0)
    total_bytes = fwd_b + bwd_b
    total_pkts = fwd_p + bwd_p
    dns: list[str] = []
    labels: list[str] = []
    for flow in flows:
        feat = flow.get("features") or {}
        if isinstance(feat, dict):
            names = feat.get("dns_query_names") or []
            if isinstance(names, list):
                dns.extend(str(n) for n in names if n)
            label = feat.get("traffic_label") or feat.get("original_label")
            if label:
                labels.append(str(label))
    dests = {f.get("destination_ip") for f in flows if f.get("destination_ip")}
    srcs = {f.get("source_ip") for f in flows if f.get("source_ip")}
    ports = {f.get("destination_port") for f in flows if f.get("destination_port") is not None}
    packet_rate = (total_pkts / duration) if duration > 0 else None
    byte_rate = (total_bytes / duration) if duration > 0 else None
    asymmetry = ((fwd_b - bwd_b) / (total_bytes + 1)) if total_bytes else None
    return {
        "source_ip": primary.get("source_ip"),
        "destination_ip": primary.get("destination_ip"),
        "source_port": primary.get("source_port"),
        "destination_port": primary.get("destination_port"),
        "protocol": primary.get("protocol"),
        "protocol_name": protocol_name(primary.get("protocol")),
        "timestamp": _iso(primary.get("first_seen")),
        "last_seen": _iso(primary.get("last_seen")),
        "duration": primary.get("duration"),
        "forward_packets": fwd_p,
        "backward_packets": bwd_p,
        "forward_bytes": fwd_b,
        "backward_bytes": bwd_b,
        "total_packets": total_pkts,
        "total_bytes": total_bytes,
        "packet_rate": round(packet_rate, 4) if packet_rate is not None else None,
        "byte_rate": round(byte_rate, 4) if byte_rate is not None else None,
        "byte_asymmetry": round(asymmetry, 4) if asymmetry is not None else None,
        "destination_fanout": len(dests),
        "unique_destinations": len(dests),
        "unique_sources": len(srcs),
        "unique_destination_ports": len(ports),
        "connection_frequency": len(flows),
        "flow_count": len(flows),
        "dns_query_names": list(dict.fromkeys(dns))[:8],
        "original_labels": list(dict.fromkeys(labels)),
        "primary_flow_id": str(primary.get("id")) if primary.get("id") else None,
        "features": primary.get("features") if isinstance(primary.get("features"), dict) else {},
    }


def _available_fields(incident: dict[str, Any], stats: dict[str, Any], alerts: list[dict[str, Any]]) -> list[str]:
    names = []
    mapping = {
        "incident_id": incident.get("id"),
        "threat_type": (incident.get("threat_types") or [None])[0],
        "severity": incident.get("severity"),
        "confidence": incident.get("confidence"),
        "source_ip": stats.get("source_ip"),
        "destination_ip": stats.get("destination_ip"),
        "source_port": stats.get("source_port"),
        "destination_port": stats.get("destination_port"),
        "protocol": stats.get("protocol"),
        "timestamp": stats.get("timestamp"),
        "duration": stats.get("duration"),
        "forward_packets": stats.get("forward_packets"),
        "backward_packets": stats.get("backward_packets"),
        "forward_bytes": stats.get("forward_bytes"),
        "backward_bytes": stats.get("backward_bytes"),
        "dns_query_names": stats.get("dns_query_names"),
    }
    for key, value in mapping.items():
        if value not in (None, "", [], {}):
            names.append(key)
    if alerts:
        names.append("detection_alerts")
    return names


def _detection_rules(alerts: list[dict[str, Any]], evidence_items: list[dict[str, Any]]) -> list[str]:
    rules: list[str] = []
    for alert in alerts:
        detector = alert.get("detector_name") or "detector"
        threat = alert.get("threat_class") or "unknown"
        rules.append(f"{detector}:{threat}")
    for item in evidence_items:
        feat = item.get("feature")
        if feat:
            rules.append(str(feat))
    return list(dict.fromkeys(rules))


def _uncertainty(context: dict[str, Any], alerts: list[dict[str, Any]]) -> list[str]:
    notes: list[str] = []
    stats = context.get("traffic_stats") or {}
    if not alerts:
        notes.append("No related detection alerts were stored for this incident.")
    if not stats.get("flow_count"):
        notes.append("No related flows were found; volume/rate features may be missing.")
    if stats.get("features") and stats["features"].get("anomaly_score") is None:
        notes.append("ML anomaly score is unavailable (no loaded model artifact).")
    if not stats.get("dns_query_names") and context.get("threat_type") in {"DNS_Tunnel", "DGA"}:
        notes.append("DNS query names were not stored on related flows.")
    notes.append("Payload contents are not available; NetGuard does not decrypt traffic.")
    notes.append("IP reputation, malware family, and threat-actor identity are not inferred.")
    return notes


def explain_incident(
    *,
    incident: dict[str, Any],
    alerts: list[dict[str, Any]] | None = None,
    flows: list[dict[str, Any]] | None = None,
    job: dict[str, Any] | None = None,
) -> dict[str, Any]:
    alerts = alerts or []
    flows = flows or []
    evidence_block = incident.get("evidence") or {}
    stats = _aggregate_traffic(flows)

    if not stats.get("source_ip"):
        ips = incident.get("affected_ips") or []
        stats["source_ip"] = ips[0] if ips else None
        stats["destination_ip"] = ips[1] if len(ips) > 1 else stats.get("destination_ip")

    threat_types = incident.get("threat_types") or evidence_block.get("threat_types") or []
    if not threat_types and alerts:
        threat_types = list(dict.fromkeys(a.get("threat_class") for a in alerts if a.get("threat_class")))
    threat_type = threat_types[0] if threat_types else None

    risk = evidence_block.get("max_risk_score")
    if risk is None and alerts:
        risk = max((float(a.get("risk_score") or 0) for a in alerts), default=None)
    risk_score = float(risk) if risk is not None else 0.0
    severity = incident.get("severity") or severity_from_score(risk_score)
    confidence = float(incident.get("confidence") or 0.0)

    original_label = None
    if stats.get("original_labels"):
        original_label = stats["original_labels"][0]
    dataset_meta = map_dataset_label(original_label)
    filename = (job or {}).get("filename")
    dataset_name = None
    if filename:
        dataset_name = "Recorded Traffic / Demo Dataset" if "DEMO" in str(filename).upper() else str(filename)

    context = {
        "id": str(incident.get("id")) if incident.get("id") else None,
        "threat_type": threat_type,
        "threat_types": threat_types,
        "severity": severity,
        "risk_score": round(risk_score, 2),
        "confidence": confidence,
        "source_ip": stats.get("source_ip"),
        "destination_ip": stats.get("destination_ip"),
        "traffic_stats": stats,
        "available_fields": _available_fields(incident, stats, alerts),
    }

    contributions = calculate_feature_contributions(
        alerts=alerts,
        incident_evidence=evidence_block if isinstance(evidence_block, dict) else {},
        risk_score=risk_score,
    )
    reducing = mitigating_factors(context, contributions)
    contributions["reducing"] = reducing
    why = generate_why_flagged(context, contributions)
    conf = generate_confidence_explanation(context, alerts)
    recs = generate_recommendation(context, contributions)
    narrative = generate_narrative(context, contributions, conf, why)
    timeline = build_timeline(flows, alerts)
    rules = _detection_rules(alerts, contributions.get("increasing") or [])
    available = context["available_fields"]
    insufficient = not (contributions.get("increasing") or []) and not alerts

    incident_view = {
        "incident_id": context["id"],
        "threat_type": threat_type or UNAVAILABLE,
        "threat_types": threat_types,
        "severity": severity,
        "risk_score": round(risk_score, 2),
        "confidence": confidence,
        "source_ip": _first_present(stats.get("source_ip"), UNAVAILABLE),
        "destination_ip": _first_present(stats.get("destination_ip"), UNAVAILABLE),
        "source_port": stats.get("source_port"),
        "destination_port": stats.get("destination_port"),
        "protocol": stats.get("protocol_name") or stats.get("protocol"),
        "timestamp": stats.get("timestamp"),
        "duration": stats.get("duration"),
        "forward_packets": stats.get("forward_packets"),
        "backward_packets": stats.get("backward_packets"),
        "forward_bytes": stats.get("forward_bytes"),
        "backward_bytes": stats.get("backward_bytes"),
        "total_packets": stats.get("total_packets"),
        "total_bytes": stats.get("total_bytes"),
        "packet_rate": stats.get("packet_rate"),
        "byte_rate": stats.get("byte_rate"),
        "byte_asymmetry": stats.get("byte_asymmetry"),
        "destination_fanout": stats.get("destination_fanout"),
        "connection_frequency": stats.get("connection_frequency"),
        "dns_query_names": stats.get("dns_query_names") or None,
        "affected_flow_count": stats.get("flow_count") or 0,
        "detection_engine": evidence_block.get("detectors") if isinstance(evidence_block, dict) else None,
        "traffic_stats": stats,
        "title": incident.get("title"),
        "status": incident.get("status"),
        "first_seen": _iso(incident.get("first_seen")),
        "last_seen": _iso(incident.get("last_seen")),
    }

    transparency = {
        "detection_method": "Explainable Rule-Based Detection",
        "evidence_count": len(contributions.get("increasing") or []),
        "attribution": "Rule-weighted feature contribution",
        "ai_analysis": "Evidence-grounded analyst summary",
        "not_used": ["SHAP", "LIME", "malware attribution", "live monitoring"],
    }

    analyst = {
        "source": "deterministic_fallback",
        "label": "Evidence-Based Analyst Summary",
        "disclaimer": (
            "This summary was generated deterministically from detection evidence. "
            "It is not an LLM/AI model response."
        ),
        "incident_summary": narrative["incident_summary"],
        "why_it_was_flagged": why,
        "important_evidence": narrative["important_evidence"],
        "risk_assessment": narrative["risk_assessment"],
        "recommended_investigation": recs,
        "confidence": narrative["confidence"],
        "why_it_matters": why,
        "why_flagged": why,
        "suspicious_indicators": [
            r.get("interpretation")
            for r in (contributions.get("increasing") or [])
            if r.get("interpretation")
        ][:15],
        "severity_assessment": {
            "severity": severity,
            "confidence": round(confidence, 3),
            "risk_score": round(risk_score, 2),
        },
        "threat_types": threat_types,
        "affected_ips": incident.get("affected_ips") or [],
        "evidence": contributions.get("increasing") or [],
    }

    return {
        "insufficient_evidence": insufficient,
        "insufficient_message": (
            "Insufficient evidence for a complete explanation."
            if insufficient
            else None
        ),
        "available_fields": available,
        "incident": incident_view,
        "dataset": {
            "name": dataset_name or UNAVAILABLE,
            "filename": filename,
            "mode": "Passive Analysis / Offline Analysis / Recorded Traffic",
            **dataset_meta,
        },
        "risk": {
            "score": round(risk_score, 2),
            "scale": "0-100",
            "severity": severity,
            "thresholds": {"LOW": "0-29", "MEDIUM": "30-59", "HIGH": "60-79", "CRITICAL": "80-100"},
            "formula": contributions.get("risk_formula"),
            "decomposition": contributions.get("risk_decomposition"),
        },
        "contributions": contributions,
        "why_flagged": why,
        "confidence": conf,
        "timeline": timeline,
        "detection_rules": rules,
        "uncertainty": _uncertainty(context, alerts),
        "transparency": transparency,
        "analyst": analyst,
        "recommendations": recs,
    }


def explain_flow(
    *,
    flow: dict[str, Any],
    alerts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    alerts = alerts or []
    dummy_incident = {
        "id": None,
        "title": f"Flow {flow.get('source_ip')} → {flow.get('destination_ip')}",
        "threat_types": list({a.get("threat_class") for a in alerts if a.get("threat_class")}),
        "affected_ips": [flow.get("source_ip"), flow.get("destination_ip")],
        "severity": None,
        "confidence": max((float(a.get("confidence") or 0) for a in alerts), default=0.0),
        "evidence": {},
        "status": None,
        "first_seen": flow.get("first_seen"),
        "last_seen": flow.get("last_seen"),
    }
    explanation = explain_incident(incident=dummy_incident, alerts=alerts, flows=[flow])
    features = flow.get("features") if isinstance(flow.get("features"), dict) else {}
    contrib_by_feature = {
        row["feature"]: row
        for row in (explanation.get("contributions") or {}).get("increasing") or []
        if row.get("feature")
    }
    explorer = []
    for name, value in features.items():
        if name in {"dns_query_names", "traffic_label", "original_label"}:
            continue
        row = contrib_by_feature.get(name)
        explorer.append(
            {
                "feature": name,
                "value": value,
                "baseline": row.get("baseline") if row else None,
                "baseline_label": (
                    row.get("baseline")
                    if row and row.get("baseline") is not None
                    else "Baseline unavailable"
                ),
                "contribution": row.get("contribution") if row else 0.0,
                "interpretation": (
                    row.get("interpretation")
                    if row
                    else "Observed value from processed traffic; this feature did not appear in triggered detection evidence."
                ),
                "detection_relevance": bool(row),
            }
        )
    for feat, row in contrib_by_feature.items():
        if feat not in features:
            explorer.append(
                {
                    "feature": feat,
                    "value": row.get("value"),
                    "baseline": row.get("baseline"),
                    "baseline_label": row.get("baseline") if row.get("baseline") is not None else "Baseline unavailable",
                    "contribution": row.get("contribution"),
                    "interpretation": row.get("interpretation"),
                    "detection_relevance": True,
                }
            )
    explanation["feature_explorer"] = explorer
    return explanation
