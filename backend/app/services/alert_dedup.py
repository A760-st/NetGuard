import hashlib
import json
from datetime import datetime, timezone
from collections import defaultdict

from app.detectors.base import DetectorResult


def deduplicate_alerts(
    results: list[DetectorResult],
    time_window_seconds: float = 60.0,
) -> list[dict]:
    fingerprint_groups: dict[str, list[DetectorResult]] = defaultdict(list)

    for result in results:
        fp = _compute_fingerprint(result)
        fingerprint_groups[fp].append(result)

    deduplicated = []
    for fp, group in fingerprint_groups.items():
        first = group[0]
        timestamps = [r.timestamp for r in group if r.timestamp > 0]
        occurrences = len(group)

        evidence_dicts = []
        for ev in first.supporting_evidence:
            evidence_dicts.append(
                {
                    "feature": ev.feature,
                    "value": ev.value,
                    "baseline": ev.baseline,
                    "interpretation": ev.interpretation,
                }
            )

        alert = {
            "source_ip": first.source_ip,
            "destination_ip": first.destination_ip,
            "threat_class": first.threat_class.value
            if hasattr(first.threat_class, "value")
            else str(first.threat_class),
            "confidence": first.confidence,
            "severity": first.severity.value
            if hasattr(first.severity, "value")
            else str(first.severity),
            "supporting_evidence": evidence_dicts,
            "detector_name": first.detector_name,
            "flow_id": first.flow_id,
            "timestamp": max(timestamps) if timestamps else first.timestamp,
            "occurrence_count": occurrences,
            "fingerprint": fp,
        }

        deduplicated.append(alert)

    return deduplicated


def _compute_fingerprint(result: DetectorResult) -> str:
    key_parts = [
        result.detector_name,
        result.source_ip,
        result.destination_ip,
        (
            result.threat_class.value
            if hasattr(result.threat_class, "value")
            else str(result.threat_class)
        ),
        str(round(result.confidence, 2)),
    ]
    raw = "|".join(key_parts)
    return hashlib.sha256(raw.encode()).hexdigest()[:32]
