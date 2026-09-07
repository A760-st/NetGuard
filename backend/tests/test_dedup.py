from app.services.alert_dedup import deduplicate_alerts
from app.detectors.base import DetectorResult, ThreatClass, Severity, Evidence


def test_deduplicate_empty():
    result = deduplicate_alerts([])
    assert result == []


def test_deduplicate_same_alerts():
    base = DetectorResult(
        detector_name="DDoSDetector",
        threat_class=ThreatClass.DDoS,
        confidence=0.8,
        severity=Severity.HIGH,
        source_ip="192.168.1.1",
        destination_ip="10.0.0.1",
        flow_id="flow-1",
        timestamp=1000.0,
        supporting_evidence=[Evidence(feature="syn_rate", value=100, baseline=10, interpretation="High SYN rate")],
    )

    results = [base, base, base]
    deduplicated = deduplicate_alerts(results)
    assert len(deduplicated) == 1
    assert deduplicated[0]["occurrence_count"] == 3


def test_deduplicate_different_alerts():
    r1 = DetectorResult(
        detector_name="DDoSDetector",
        threat_class=ThreatClass.DDoS,
        confidence=0.8,
        severity=Severity.HIGH,
        source_ip="192.168.1.1",
        destination_ip="10.0.0.1",
        flow_id="flow-1",
        timestamp=1000.0,
    )
    r2 = DetectorResult(
        detector_name="ReconDetector",
        threat_class=ThreatClass.RECON,
        confidence=0.6,
        severity=Severity.MEDIUM,
        source_ip="192.168.1.2",
        destination_ip="10.0.0.2",
        flow_id="flow-2",
        timestamp=2000.0,
    )

    deduplicated = deduplicate_alerts([r1, r2])
    assert len(deduplicated) == 2


def test_deduplicate_preserves_evidence():
    ev = Evidence(feature="test", value=42, baseline=10, interpretation="Test evidence")
    r = DetectorResult(
        detector_name="TestDetector",
        threat_class=ThreatClass.ANOMALY,
        confidence=0.5,
        severity=Severity.MEDIUM,
        source_ip="1.2.3.4",
        destination_ip="5.6.7.8",
        flow_id="test-flow",
        timestamp=100.0,
        supporting_evidence=[ev],
    )

    deduplicated = deduplicate_alerts([r])
    assert len(deduplicated) == 1
    assert len(deduplicated[0]["supporting_evidence"]) == 1
    assert deduplicated[0]["supporting_evidence"][0]["feature"] == "test"
