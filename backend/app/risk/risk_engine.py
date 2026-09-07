import math
from datetime import datetime, timezone


def calculate_risk_score(
    confidence: float,
    severity: str,
    occurrence_count: int = 1,
    anomaly_score: float = 0.0,
) -> float:
    severity_weights = {
        "LOW": 0.2,
        "MEDIUM": 0.4,
        "HIGH": 0.7,
        "CRITICAL": 1.0,
    }
    severity_weight = severity_weights.get(severity, 0.2)

    base_score = confidence * severity_weight * 100

    occurrence_bonus = min(math.log2(max(occurrence_count, 1)) * 5, 20)
    anomaly_bonus = anomaly_score * 15

    risk = base_score + occurrence_bonus + anomaly_bonus
    return min(max(risk, 0.0), 100.0)


def classify_severity(risk_score: float) -> str:
    if risk_score >= 75:
        return "CRITICAL"
    elif risk_score >= 50:
        return "HIGH"
    elif risk_score >= 25:
        return "MEDIUM"
    else:
        return "LOW"


def calculate_host_risk(
    host_alerts: list[dict],
    host_flows: int,
    anomaly_scores: list[float],
) -> dict:
    if not host_alerts:
        return {
            "risk_score": 0.0,
            "severity": "LOW",
            "alert_count": 0,
            "flow_count": host_flows,
            "anomaly_score": 0.0,
        }

    total_risk = sum(a.get("risk_score", 0) for a in host_alerts)
    avg_risk = total_risk / len(host_alerts)

    max_confidence = max((a.get("confidence", 0) for a in host_alerts), default=0)

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for a in host_alerts:
        sev = a.get("severity", "LOW")
        if sev in severity_counts:
            severity_counts[sev] += 1

    severity_multiplier = 1.0
    if severity_counts["CRITICAL"] > 0:
        severity_multiplier = 1.5
    elif severity_counts["HIGH"] > 0:
        severity_multiplier = 1.3

    avg_anomaly = sum(anomaly_scores) / len(anomaly_scores) if anomaly_scores else 0.0

    risk_score = min(
        avg_risk * severity_multiplier + avg_anomaly * 10 + min(len(host_alerts) * 2, 20),
        100.0,
    )

    return {
        "risk_score": round(risk_score, 2),
        "severity": classify_severity(risk_score),
        "alert_count": len(host_alerts),
        "flow_count": host_flows,
        "anomaly_score": round(avg_anomaly, 3),
    }


def apply_risk_decay(current_risk: float, elapsed_hours: float, decay_rate: float = 0.05) -> float:
    decayed = current_risk * math.exp(-decay_rate * elapsed_hours)
    return max(decayed, 0.0)
