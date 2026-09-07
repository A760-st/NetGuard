from app.risk.risk_engine import calculate_risk_score, classify_severity, apply_risk_decay, calculate_host_risk


def test_risk_score_low():
    risk = calculate_risk_score(confidence=0.2, severity="LOW")
    assert 0 <= risk <= 100
    assert risk < 25


def test_risk_score_critical():
    risk = calculate_risk_score(confidence=0.95, severity="CRITICAL", occurrence_count=5)
    assert risk >= 50


def test_risk_score_occurrence_bonus():
    risk1 = calculate_risk_score(confidence=0.5, severity="MEDIUM", occurrence_count=1)
    risk10 = calculate_risk_score(confidence=0.5, severity="MEDIUM", occurrence_count=10)
    assert risk10 > risk1


def test_classify_severity():
    assert classify_severity(80) == "CRITICAL"
    assert classify_severity(60) == "HIGH"
    assert classify_severity(35) == "MEDIUM"
    assert classify_severity(10) == "LOW"


def test_risk_decay():
    risk = 80.0
    decayed = apply_risk_decay(risk, elapsed_hours=24, decay_rate=0.05)
    assert decayed < risk
    assert decayed > 0


def test_risk_decay_no_change():
    risk = 50.0
    decayed = apply_risk_decay(risk, elapsed_hours=0)
    assert abs(decayed - risk) < 0.01


def test_host_risk_no_alerts():
    result = calculate_host_risk(host_alerts=[], host_flows=10, anomaly_scores=[])
    assert result["risk_score"] == 0.0
    assert result["severity"] == "LOW"
    assert result["alert_count"] == 0
    assert result["flow_count"] == 10


def test_host_risk_with_alerts():
    alerts = [
        {"risk_score": 80, "confidence": 0.9, "severity": "CRITICAL"},
        {"risk_score": 60, "confidence": 0.7, "severity": "HIGH"},
    ]
    result = calculate_host_risk(host_alerts=alerts, host_flows=50, anomaly_scores=[0.8])
    assert result["risk_score"] > 0
    assert result["alert_count"] == 2
    assert result["severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
