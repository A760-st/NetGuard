# SPEC.md - NETGUARD Complete Technical Specification

## 1. Core Objective

NETGUARD is a passive traffic-analysis and cyber-threat detection platform. It accepts PCAP files (and optionally CSV/NetFlow/IPFIX/sFlow) as input, extracts real traffic information, and detects threats using real packet/flow metadata.

## 2. Pipeline

```
REAL TRAFFIC DATA → TRAFFIC INGESTION → FLOW EXTRACTION → FEATURE ENGINEERING → ML + THREAT DETECTORS → EVIDENCE GENERATION → RISK ENGINE → ALERT GENERATION → INCIDENT CORRELATION → DATABASE → API → SOC DASHBOARD
```

## 3. Threat Classes

### A. Volumetric/Protocol DDoS
- SYN flood, UDP flood, reflection/amplification, spoofed-source flooding
- Signals: flow rate, packet rate, byte rate, SYN frequency, source-IP entropy, destination concentration, protocol distribution, asymmetric traffic

### B. Botnet C2 Beaconing
- Periodic communication detection
- Signals: inter-arrival times, periodicity, repeated src/dst pairs, small destination sets, recurring packet sizes, recurring connection intervals

### C. DGA Domain Detection
- DNS query metadata analysis
- Signals: domain/query entropy, query length, character distribution, n-gram characteristics, unusual label structure, NXDOMAIN ratio, query frequency

### D. DNS Tunnelling
- Query length, entropy, label length, request frequency, encoded-looking labels, TXT-heavy behavior, unusual record types, bidirectional DNS behavior

### E. TLS/QUIC Encrypted Malware Behavior
- Metadata only: TLS version, handshake metadata, JA3/JA3S/JA4, packet-size sequences, packet timing, flow duration, byte ratios, destination behavior
- NEVER decrypt payloads

### F. Reconnaissance/Port Scanning
- Many destination ports, many destination hosts, high fan-out, sequential port patterns, short-lived flows, connection attempt concentration

### G. Data Exfiltration
- Abnormal outbound volume, unusual outbound/inbound ratio, long-duration transfers, unusual destination concentration, persistent high-volume connections, per-host baseline deviations

## 4. Hybrid Detection Architecture

1. Deep anomaly detection (autoencoder)
2. Statistical detection
3. Temporal detection
4. Entropy-based detection
5. Behavioral baselines
6. Protocol metadata detection
7. Threat-specific rules
8. Correlation
9. Risk scoring

## 5. Feature Schema (Core 12)

1. Flow Duration
2. Total Fwd Packets
3. Total Bwd Packets
4. Total Length Fwd Packets
5. Total Length Bwd Packets
6. Fwd Packet Length Mean
7. Bwd Packet Length Mean
8. Flow IAT Mean
9. Flow IAT Std
10. SYN Flag Count
11. ACK Flag Count
12. Byte Asymmetry Ratio

## 6. Autoencoder Architecture

- Input: 12 features
- Layers: 12 → 8 → 4 → 8 → 12
- Activation: ReLU
- Loss: MSE reconstruction
- Training: on benign/normal traffic only
- Artifacts: flow_autoencoder.pt, netguard_flow_scaler.pkl, threshold.json

## 7. Detector Interface

Every detector produces a `DetectorResult`:
- detector_name, threat_class, confidence, severity, evidence, source_ip, destination_ip, flow_id, timestamp, features, status

## 8. Risk Scoring

- Risk score: 0-100
- Severity: LOW (0-24), MEDIUM (25-49), HIGH (50-74), CRITICAL (75-100)
- Factors: confidence, severity, repetition, temporal persistence, correlated alerts, host behavior, anomaly score
- Risk decay for stale activity

## 9. Alert Schema

- alert_id, timestamp, flow_id, source_ip, destination_ip, source_port, destination_port, protocol, threat_class, confidence, risk_score, severity, supporting_evidence, detector_name, model_version, status
- Statuses: new, acknowledged, investigating, resolved, false_positive

## 10. Alert Deduplication

- Fingerprinting, time-window deduplication, alert aggregation, occurrence count

## 11. Incident Correlation

- incident_id, title, threat_types, affected_ips, timeline, severity, confidence, related_alerts, evidence, first_seen, last_seen, status

## 12. Database Tables (PostgreSQL)

- analysis_jobs, packets_summary, flows, alerts, incidents, host_risk_scores, dns_observations, tls_observations, detector_results, model_versions, processing_errors

## 13. API Endpoints

- GET /health
- POST /api/v1/pcap/jobs
- GET /api/v1/pcap/jobs/{job_id}
- GET /api/v1/flows
- GET /api/v1/flows/{flow_id}
- GET /api/v1/alerts
- GET /api/v1/alerts/{alert_id}
- GET /api/v1/incidents
- GET /api/v1/incidents/{incident_id}
- GET /api/v1/hosts/{ip}/risk
- GET /api/v1/hosts/{ip}/timeline
- GET /api/v1/analytics/overview
- GET /api/v1/analytics/threats
- GET /api/v1/analytics/protocols
- GET /api/v1/analytics/top-talkers
- GET /api/v1/system/status

All endpoints support filtering, pagination, and sorting.

## 14. Frontend Pages

1. Overview
2. Traffic Analysis
3. PCAP Jobs
4. Alerts
5. Incidents
6. Hosts
7. Network Graph
8. DNS Intelligence
9. TLS Intelligence
10. Threat Analytics
11. ML/Model Evaluation
12. Research & Validation
13. System Health
14. Settings

## 15. Real-time Updates

WebSocket/SSE for job progress, processing status, newly generated alerts, incident updates during PCAP analysis jobs. NOT live network monitoring.

## 16. Dataset Strategy

| Detector | Dataset |
|----------|---------|
| DDoS | CIC-DDoS2019 |
| Intrusion | CIC-IDS2017, CSE-CIC-IDS2018 |
| Botnet/C2 | CTU-13 |
| DGA | DGA datasets |
| DNS | CIC-Bell-DNS2021, DNS-EXF |
| VPN | ISCX VPN/nonVPN |

## 17. Security

- Input validation, file size limits, safe file handling, path traversal protection
- API validation, environment-based secrets, CORS, rate limiting
- Structured logging, error sanitization
- Never expose secrets, never commit .env
