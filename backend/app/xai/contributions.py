"""Rule-weighted feature contributions derived from detector evidence and risk math.

Attribution method: "Rule-based feature contribution"
This is NOT SHAP, LIME, or neural-network attribution.
"""

from __future__ import annotations

import math
from typing import Any

from app.risk.risk_engine import calculate_risk_score

SEVERITY_WEIGHTS = {
    "LOW": 0.2,
    "MEDIUM": 0.4,
    "HIGH": 0.7,
    "CRITICAL": 1.0,
}

FEATURE_DISPLAY_NAMES: dict[str, str] = {
    "outbound_byte_ratio": "Outbound byte ratio",
    "large_outbound_flows": "Large outbound flows",
    "long_duration_transfer": "Long-duration transfer",
    "inter_arrival_time_mean": "Inter-arrival time (mean)",
    "periodicity_score": "Temporal periodicity",
    "repeated_connections": "Repeated destination connections",
    "destination_port_fanout": "Destination port fan-out",
    "destination_host_fanout": "Destination host fan-out",
    "short_lived_flows": "Short-lived connection attempts",
    "sequential_port_pattern": "Sequential port scanning",
    "dns_query_size": "DNS query size",
    "dns_query_rate": "DNS query rate",
    "long_dns_label": "Long DNS label",
    "high_dns_entropy": "DNS query entropy",
    "source_ip_concentration": "Source concentration",
    "destination_concentration": "Destination concentration",
    "syn_flood_pattern": "SYN-heavy pattern",
    "high_packet_rate": "Packet rate",
}


def _as_number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return None


def _evidence_weight(item: dict[str, Any]) -> float:
    value = _as_number(item.get("value"))
    baseline = _as_number(item.get("baseline"))
    if value is None:
        return 1.0
    if baseline is None:
        return 1.0 + min(abs(value) / (abs(value) + 1.0), 2.0)
    denom = max(abs(baseline), 1.0)
    deviation = abs(value - baseline) / denom
    return 1.0 + min(deviation, 4.0)


def collect_evidence_items(alerts: list[dict[str, Any]], incident_evidence: dict[str, Any]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    seen: set[tuple] = set()

    def add(ev: dict[str, Any], detector: str | None, threat: str | None) -> None:
        if not isinstance(ev, dict) or not ev.get("feature"):
            return
        key = (ev.get("feature"), str(ev.get("value")), detector)
        if key in seen:
            return
        seen.add(key)
        items.append(
            {
                "feature": str(ev.get("feature")),
                "display_name": FEATURE_DISPLAY_NAMES.get(str(ev.get("feature")), str(ev.get("feature")).replace("_", " ")),
                "value": ev.get("value"),
                "baseline": ev.get("baseline"),
                "interpretation": ev.get("interpretation") or "Matched a detection rule on observed traffic.",
                "detector": detector,
                "threat_class": threat,
            }
        )

    for alert in alerts:
        threat = alert.get("threat_class")
        detector = alert.get("detector_name")
        raw = alert.get("supporting_evidence")
        if isinstance(raw, list):
            for ev in raw:
                if isinstance(ev, dict):
                    add(ev, detector, threat)
        elif isinstance(raw, dict):
            add(raw, detector, threat)

    for entry in incident_evidence.get("explanations") or []:
        if not isinstance(entry, dict):
            continue
        for ev in entry.get("evidence") or []:
            if isinstance(ev, dict):
                add(ev, entry.get("detector"), entry.get("threat_class"))

    return items


def decompose_risk(alert: dict[str, Any]) -> dict[str, float]:
    confidence = float(alert.get("confidence") or 0.0)
    severity = str(alert.get("severity") or "LOW")
    occurrence = int(alert.get("occurrence_count") or 1)
    anomaly = float(alert.get("anomaly_score") or 0.0)
    stored = alert.get("risk_score")
    computed = calculate_risk_score(confidence, severity, occurrence, anomaly)
    risk = float(stored) if stored is not None else computed
    weight = SEVERITY_WEIGHTS.get(severity, 0.2)
    confidence_component = min(confidence * weight * 100.0, 100.0)
    occurrence_component = min(math.log2(max(occurrence, 1)) * 5.0, 20.0)
    anomaly_component = anomaly * 15.0
    return {
        "risk_score": round(min(max(risk, 0.0), 100.0), 2),
        "confidence_component": round(confidence_component, 2),
        "occurrence_component": round(occurrence_component, 2),
        "anomaly_component": round(anomaly_component, 2),
        "severity_weight": weight,
        "confidence": round(confidence, 4),
        "occurrence_count": float(occurrence),
    }


def calculate_feature_contributions(
    *,
    alerts: list[dict[str, Any]],
    incident_evidence: dict[str, Any],
    risk_score: float,
) -> dict[str, Any]:
    evidence = collect_evidence_items(alerts, incident_evidence)
    primary = max(alerts, key=lambda a: float(a.get("risk_score") or 0), default={})
    parts = decompose_risk(primary) if primary else {
        "risk_score": risk_score,
        "confidence_component": risk_score,
        "occurrence_component": 0.0,
        "anomaly_component": 0.0,
        "severity_weight": 0.0,
        "confidence": 0.0,
        "occurrence_count": 1.0,
    }

    feature_budget = max(parts["risk_score"] - parts["occurrence_component"] - parts["anomaly_component"], 0.0)
    if feature_budget <= 0 and parts["risk_score"] > 0:
        feature_budget = parts["risk_score"]

    weights = [_evidence_weight(ev) for ev in evidence]
    total_w = sum(weights) or 1.0

    increasing: list[dict[str, Any]] = []
    for ev, weight in zip(evidence, weights):
        points = round(feature_budget * (weight / total_w), 2) if evidence else 0.0
        increasing.append(
            {
                **ev,
                "direction": "increases_risk",
                "contribution": points,
                "weight": round(weight, 3),
            }
        )

    increasing.sort(key=lambda x: abs(float(x["contribution"])), reverse=True)

    extra_rows: list[dict[str, Any]] = []
    if parts["occurrence_component"] > 0:
        extra_rows.append(
            {
                "feature": "occurrence_bonus",
                "display_name": "Repeated detection occurrences",
                "value": int(parts["occurrence_count"]),
                "baseline": 1,
                "interpretation": (
                    f"Risk engine added {parts['occurrence_component']} points from "
                    f"{int(parts['occurrence_count'])} matching detections "
                    "(min(log2(count)*5, 20))."
                ),
                "direction": "increases_risk",
                "contribution": parts["occurrence_component"],
                "weight": 1.0,
                "detector": None,
                "threat_class": None,
            }
        )
    if parts["anomaly_component"] > 0:
        extra_rows.append(
            {
                "feature": "anomaly_bonus",
                "display_name": "Optional ML anomaly bonus",
                "value": parts["anomaly_component"] / 15.0 if parts["anomaly_component"] else None,
                "baseline": 0,
                "interpretation": "Added only when a trained autoencoder artifact scores the flow.",
                "direction": "increases_risk",
                "contribution": parts["anomaly_component"],
                "weight": 1.0,
                "detector": None,
                "threat_class": None,
            }
        )

    all_increasing = increasing + extra_rows
    total_positive = round(sum(float(r["contribution"]) for r in all_increasing), 2)

    return {
        "attribution_method": "Rule-based feature contribution",
        "attribution_disclaimer": (
            "Contributions allocate the actual risk score across triggered detection "
            "evidence using rule weights (deviation from detector baseline when numeric). "
            "This is not SHAP, LIME, or model-gradient attribution."
        ),
        "risk_formula": (
            "risk = min(confidence * severity_weight * 100 + min(log2(occurrences)*5, 20) "
            "+ anomaly_score*15, 100)"
        ),
        "risk_decomposition": parts,
        "increasing": all_increasing,
        "total_increasing": total_positive,
        "risk_score": round(float(risk_score), 2),
    }


def mitigating_factors(context: dict[str, Any], contributions: dict[str, Any]) -> list[dict[str, Any]]:
    """Signals present in traffic that did not increase this score."""
    factors: list[dict[str, Any]] = []
    stats = context.get("traffic_stats") or {}
    threat = (context.get("threat_type") or "") or ""
    risk = float(contributions.get("risk_score") or 0)
    headroom = max(0.0, 100.0 - risk)

    fwd = stats.get("forward_bytes")
    bwd = stats.get("backward_bytes")
    duration = stats.get("duration")
    dport = stats.get("destination_port")
    proto = stats.get("protocol")
    dest_count = stats.get("unique_destinations")
    occ = (contributions.get("risk_decomposition") or {}).get("occurrence_count", 1)

    if isinstance(fwd, (int, float)) and isinstance(bwd, (int, float)) and (fwd + bwd) > 0:
        asymmetry = (fwd - bwd) / (fwd + bwd)
        if threat in {"Exfiltration", "Encrypted_Threat"} and asymmetry < 0.4:
            factors.append(
                {
                    "feature": "byte_asymmetry_ratio",
                    "display_name": "Moderate byte asymmetry",
                    "value": round(asymmetry, 3),
                    "direction": "reduces_suspicion",
                    "contribution": 0.0,
                    "interpretation": (
                        "Observed byte asymmetry is not strongly outbound-dominant, "
                        "so it did not add extra exfiltration weight beyond triggered rules."
                    ),
                }
            )

    if isinstance(duration, (int, float)) and duration < 5 and threat == "Exfiltration":
        factors.append(
            {
                "feature": "flow_duration",
                "display_name": "Short transfer duration",
                "value": duration,
                "direction": "reduces_suspicion",
                "contribution": 0.0,
                "interpretation": (
                    "Duration is short relative to long-lived exfiltration heuristics "
                    "(> 600s). This signal did not increase the score."
                ),
            }
        )

    if dport in (80, 443) and threat in {"C2_Beacon", "Exfiltration"}:
        factors.append(
            {
                "feature": "destination_port",
                "display_name": "Common web port",
                "value": dport,
                "direction": "reduces_suspicion",
                "contribution": 0.0,
                "interpretation": (
                    f"Destination port {dport} is common for web traffic and is not "
                    "by itself evidence of compromise."
                ),
            }
        )

    if proto in (6, 17) and threat == "Reconnaissance" and isinstance(stats.get("backward_packets"), int) and stats["backward_packets"] == 0:
        factors.append(
            {
                "feature": "backward_packets",
                "display_name": "No recorded responses",
                "value": 0,
                "direction": "reduces_suspicion",
                "contribution": 0.0,
                "interpretation": (
                    "No backward packets are stored for these probes. That is consistent "
                    "with scanning but does not prove a successful compromise."
                ),
            }
        )

    if occ == 1:
        factors.append(
            {
                "feature": "occurrence_count",
                "display_name": "Single detection occurrence",
                "value": 1,
                "direction": "reduces_suspicion",
                "contribution": 0.0,
                "interpretation": (
                    "Occurrence bonus was not applied (requires repeated matching detections)."
                ),
            }
        )

    if dest_count == 1 and threat == "Reconnaissance":
        factors.append(
            {
                "feature": "destination_host_fanout",
                "display_name": "Single destination host",
                "value": 1,
                "direction": "reduces_suspicion",
                "contribution": 0.0,
                "interpretation": (
                    "Traffic concentrated on one host rather than a wide host scan. "
                    "Port fan-out may still indicate reconnaissance."
                ),
            }
        )

    if not factors and headroom > 0:
        factors.append(
            {
                "feature": "score_headroom",
                "display_name": "Unused risk headroom",
                "value": round(headroom, 2),
                "direction": "reduces_suspicion",
                "contribution": 0.0,
                "interpretation": (
                    f"The score is {risk:.1f}/100. Remaining headroom was not filled "
                    "because additional detector conditions did not fire."
                ),
            }
        )

    return factors
