"""Natural-language reasoning generated only from supplied incident evidence."""

from __future__ import annotations

from typing import Any

PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}

SEVERITY_BANDS = (
    (80, "CRITICAL"),
    (60, "HIGH"),
    (30, "MEDIUM"),
    (0, "LOW"),
)


def severity_from_score(score: float) -> str:
    for threshold, label in SEVERITY_BANDS:
        if score >= threshold:
            return label
    return "LOW"


def protocol_name(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str) and value:
        return value
    try:
        return PROTO_NAMES.get(int(value), str(value))
    except (TypeError, ValueError):
        return str(value)


def generate_why_flagged(context: dict[str, Any], contributions: dict[str, Any]) -> str:
    threat = context.get("threat_type") or "suspicious activity"
    increasing = contributions.get("increasing") or []
    interpretations = [
        str(row.get("interpretation"))
        for row in increasing
        if row.get("interpretation") and row.get("feature") not in {"occurrence_bonus", "anomaly_bonus"}
    ]
    if not interpretations:
        available = context.get("available_fields") or []
        if not available:
            return "Insufficient evidence for a complete explanation."
        return (
            "Insufficient evidence for a complete explanation. "
            f"Available fields: {', '.join(available[:12])}."
        )

    lead = (
        f"NetGuard flagged this activity as {threat} because "
        + "; ".join(interpretations[:4])
    )
    if not lead.endswith("."):
        lead += "."

    extra = _threat_specific_clause(threat, increasing, context)
    if extra:
        lead = f"{lead} {extra}"
    return lead


def _threat_specific_clause(
    threat: str, increasing: list[dict[str, Any]], context: dict[str, Any]
) -> str:
    features = {str(r.get("feature")) for r in increasing}
    stats = context.get("traffic_stats") or {}
    clauses: list[str] = []

    if threat in {"Exfiltration"}:
        if "outbound_byte_ratio" in features or "large_outbound_flows" in features:
            clauses.append(
                "These signals match outbound-volume and asymmetry heuristics used by the exfiltration detector."
            )
    if threat in {"C2_Beacon"}:
        if "periodicity_score" in features or "inter_arrival_time_mean" in features:
            clauses.append(
                "Periodic inter-arrival timing and repeated same-destination connections are the C2 beaconing signals that fired."
            )
    if threat in {"Reconnaissance"}:
        if {"destination_port_fanout", "destination_host_fanout", "sequential_port_pattern", "short_lived_flows"} & features:
            clauses.append(
                "Fan-out across ports/hosts and short-lived probes are the reconnaissance signals that fired."
            )
    if threat in {"DNS_Tunnel"}:
        if {"dns_query_size", "dns_query_rate", "long_dns_label", "high_dns_entropy"} & features:
            clauses.append(
                "DNS size, rate, label length, and/or entropy exceeded the tunnelling detector thresholds."
            )
    if threat in {"DDoS"}:
        if {"source_ip_concentration", "destination_concentration", "high_packet_rate", "syn_flood_pattern"} & features:
            clauses.append(
                "Volume, packet rate, and/or destination concentration exceeded DDoS detector thresholds."
            )

    dns_names = stats.get("dns_query_names") or []
    if dns_names and threat in {"DNS_Tunnel", "DGA"}:
        clauses.append(
            f"Observed DNS query names include: {', '.join(str(n) for n in dns_names[:3])}."
        )
    return " ".join(clauses)


def generate_confidence_explanation(
    context: dict[str, Any], alerts: list[dict[str, Any]]
) -> dict[str, Any]:
    confidence = float(context.get("confidence") or 0.0)
    detectors = sorted(
        {str(a.get("detector_name")) for a in alerts if a.get("detector_name")}
    )
    threats = sorted({str(a.get("threat_class")) for a in alerts if a.get("threat_class")})
    evidence_count = 0
    for a in alerts:
        raw = a.get("supporting_evidence")
        if isinstance(raw, list):
            evidence_count += len(raw)
        elif isinstance(raw, dict):
            evidence_count += 1

    if len(detectors) >= 2 and len(threats) == 1:
        text = (
            f"Rule agreement confidence is {confidence:.0%} because "
            f"{len(detectors)} detectors ({', '.join(detectors)}) support the same "
            f"category ({threats[0]}) with {evidence_count} stored evidence items."
        )
    elif len(detectors) >= 2:
        text = (
            f"Rule agreement confidence is {confidence:.0%} from {len(detectors)} "
            f"detectors across categories {', '.join(threats) or 'unspecified'} "
            f"({evidence_count} evidence items)."
        )
    elif evidence_count >= 3:
        text = (
            f"Rule agreement confidence is {confidence:.0%} because "
            f"{evidence_count} independent behavioral indicators from "
            f"{detectors[0] if detectors else 'a detector'} support this detection."
        )
    elif evidence_count:
        text = (
            f"Rule agreement confidence is {confidence:.0%} from "
            f"{evidence_count} stored evidence item(s) produced by "
            f"{detectors[0] if detectors else 'the matching detector'}."
        )
    else:
        text = (
            f"Rule agreement confidence is {confidence:.0%}. "
            "No additional statistical confidence interval is available."
        )
    return {
        "label": "Rule agreement confidence",
        "value": round(confidence, 4),
        "percent": round(confidence * 100, 1),
        "independent_indicators": evidence_count,
        "detectors": detectors,
        "explanation": text,
    }


def generate_recommendation(context: dict[str, Any], contributions: dict[str, Any]) -> list[str]:
    threat = context.get("threat_type") or ""
    stats = context.get("traffic_stats") or {}
    src = stats.get("source_ip") or context.get("source_ip")
    dst = stats.get("destination_ip") or context.get("destination_ip")
    top = (contributions.get("increasing") or [None])[0]
    steps: list[str] = []
    if src:
        steps.append(f"Review other recorded flows from source {src} in this dataset.")
    if dst:
        steps.append(f"Confirm whether destination {dst} is expected for this environment using internal asset data (not inferred here).")
    if top and top.get("display_name"):
        steps.append(
            f"Inspect feature '{top['display_name']}' "
            f"(value={top.get('value')}) because it contributed {top.get('contribution')} risk points."
        )
    mapping = {
        "Exfiltration": "Quantify outbound bytes versus inbound bytes on related flows and identify the destination service port.",
        "C2_Beacon": "Measure inter-arrival times across the src/dst pair and check whether packet sizes stay consistent.",
        "Reconnaissance": "List distinct destination ports/hosts contacted by the source and compare against a short duration pattern.",
        "DNS_Tunnel": "Inspect DNS query names, label length, and entropy on UDP/53 flows in this job.",
        "DDoS": "Check packet rate and whether many sources concentrate on one destination in the recorded window.",
        "DGA": "Review queried domain structure and entropy; do not assume a malware family.",
        "Encrypted_Threat": "Review TLS-port flows for volume and asymmetry only; payloads are not decrypted.",
    }
    if threat in mapping:
        steps.append(mapping[threat])
    steps.append("Do not contact observed hosts from this console — NetGuard is passive recorded-traffic analysis.")
    return steps


def generate_narrative(context: dict[str, Any], contributions: dict[str, Any], confidence: dict[str, Any], why: str) -> dict[str, str]:
    threat = context.get("threat_type") or "unspecified"
    severity = context.get("severity") or severity_from_score(float(context.get("risk_score") or 0))
    stats = context.get("traffic_stats") or {}
    src = stats.get("source_ip") or "Not available from the observed traffic."
    dst = stats.get("destination_ip") or "Not available from the observed traffic."
    risk = context.get("risk_score")
    top_feats = ", ".join(
        f"{r.get('display_name')} ({r.get('contribution')})"
        for r in (contributions.get("increasing") or [])[:4]
        if r.get("feature") not in {"occurrence_bonus"}
    ) or "no ranked features"

    what = (
        f"Recorded traffic involving source {src} and destination {dst} was correlated "
        f"into this incident as {threat} with severity {severity}."
    )
    if stats.get("flow_count"):
        what += f" {stats['flow_count']} related flow(s) in this job were used for evidence."

    risk_text = (
        f"The risk score is {risk}/100 ({severity}). "
        f"{contributions.get('risk_formula')} "
        f"Top contributing signals: {top_feats}."
    )
    return {
        "incident_summary": what,
        "why_flagged": why,
        "important_evidence": (
            f"Stored detector evidence ranked by rule-weighted contribution: {top_feats}."
        ),
        "risk_assessment": risk_text,
        "confidence": confidence.get("explanation") or "",
    }


def build_timeline(flows: list[dict[str, Any]], alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for flow in flows:
        ts = flow.get("first_seen")
        if not ts:
            continue
        src = flow.get("source_ip")
        dst = flow.get("destination_ip")
        events.append(
            {
                "timestamp": ts,
                "event": "flow_observed",
                "detail": (
                    f"Flow {src}:{flow.get('source_port')} → {dst}:{flow.get('destination_port')} "
                    f"({protocol_name(flow.get('protocol')) or 'proto?'}, "
                    f"{flow.get('forward_bytes', 0)} fwd bytes, duration {flow.get('duration')}s)"
                ),
            }
        )
    for alert in alerts:
        ts = alert.get("created_at") or alert.get("timestamp")
        if not ts:
            continue
        events.append(
            {
                "timestamp": ts if not isinstance(ts, (int, float)) else ts,
                "event": "detection_recorded",
                "detail": (
                    f"{alert.get('threat_class')} by {alert.get('detector_name')} "
                    f"(risk {alert.get('risk_score')}, confidence {alert.get('confidence')})"
                ),
            }
        )
    def sort_key(item: dict[str, Any]):
        t = item.get("timestamp")
        return str(t)
    events.sort(key=sort_key)
    return events[:40]
