from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any
from enum import Enum


class ThreatClass(str, Enum):
    DDoS = "DDoS"
    RECON = "Reconnaissance"
    C2_BEACON = "C2_Beacon"
    DGA = "DGA"
    DNS_TUNNEL = "DNS_Tunnel"
    ENCRYPTED_THREAT = "Encrypted_Threat"
    EXFILTRATION = "Exfiltration"
    ANOMALY = "Anomaly"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class Evidence:
    feature: str
    value: Any
    baseline: Any
    interpretation: str


@dataclass
class DetectorResult:
    detector_name: str
    threat_class: ThreatClass
    confidence: float
    severity: Severity
    source_ip: str
    destination_ip: str
    flow_id: str
    timestamp: float
    supporting_evidence: list[Evidence] = field(default_factory=list)
    status: str = "completed"
    features: dict = field(default_factory=dict)


class BaseDetector(ABC):
    def __init__(self):
        self.name: str = "BaseDetector"
        self.threat_class: ThreatClass = ThreatClass.ANOMALY
        self.enabled: bool = True

    @abstractmethod
    def detect(self, flows: list, features_map: dict) -> list[DetectorResult]:
        pass

    def _classify_severity(self, confidence: float) -> Severity:
        if confidence >= 0.85:
            return Severity.CRITICAL
        elif confidence >= 0.65:
            return Severity.HIGH
        elif confidence >= 0.40:
            return Severity.MEDIUM
        else:
            return Severity.LOW


def as_timestamp(value) -> float:
    if value is None:
        return 0.0
    if hasattr(value, "timestamp"):
        try:
            return value.timestamp()
        except Exception:
            return 0.0
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0
