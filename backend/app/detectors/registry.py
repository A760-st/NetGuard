from app.detectors.base import BaseDetector, DetectorResult, ThreatClass, Severity, Evidence
from app.detectors.ddos_detector import DDoSDetector
from app.detectors.recon_detector import ReconDetector
from app.detectors.c2_detector import C2BeaconDetector
from app.detectors.dga_detector import DGADetector
from app.detectors.dns_tunnel_detector import DNSTunnelDetector
from app.detectors.encrypted_threat_detector import EncryptedThreatDetector
from app.detectors.exfiltration_detector import ExfiltrationDetector

ALL_DETECTORS: list[BaseDetector] = [
    DDoSDetector(),
    ReconDetector(),
    C2BeaconDetector(),
    DGADetector(),
    DNSTunnelDetector(),
    EncryptedThreatDetector(),
    ExfiltrationDetector(),
]
