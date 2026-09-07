# Architecture

## System Architecture

NETGUARD follows a modular pipeline architecture:

```
PCAP/CSV Input
    ↓
Traffic Parser (Python — dpkt-based custom parser)
    ↓
Flow Engine (bidirectional flow construction)
    ↓
Feature Engineering (12 core features)
    ↓
┌─────────────────────────────────────────┐
│  Autoencoder (ML anomaly detection)     │
│  + 7 Threat Detectors (rule-based)      │
└─────────────────────────────────────────┘
    ↓
Evidence Engine (feature-value-baseline)
    ↓
Risk Engine (0-100 scoring)
    ↓
Alert Generation + Deduplication
    ↓
Incident Correlation
    ↓
PostgreSQL (persistent storage)
    ↓
FastAPI REST API
    ↓
React SOC Dashboard
```

## Components

### Packet Parser
- Custom Python PCAP parser (supports libpcap format)
- Handles Ethernet, IPv4, IPv6, TCP, UDP
- Fault-tolerant: continues on malformed packets

### Flow Engine
- Bidirectional 5-tuple flow construction
- (src_ip, dst_ip, src_port, dst_port, protocol)
- Computes per-flow TCP flags, byte counts, packet counts

### Feature Engine
- 12 core features for ML input
- 22 total features for detector evidence
- Deterministic computation, handles NaN/zero-division

### ML Models
- Flow Anomaly Autoencoder (PyTorch)
- Architecture: 12 → 8 → 4 → 8 → 12
- Trained on benign traffic
- Reconstruction error as anomaly score

### Detectors
- DDoSDetector — volumetric/protocol DDoS
- ReconDetector — port scanning, host enumeration
- C2BeaconDetector — periodic beaconing
- DGADetector — domain generation algorithms
- DNSTunnelDetector — DNS tunnelling
- EncryptedThreatDetector — TLS metadata anomalies
- ExfiltrationDetector — data exfiltration

### Risk Engine
- Combines confidence, severity, repetition, anomaly score
- Risk decay for stale activity
- Host-level risk aggregation

### Database
- PostgreSQL with async SQLAlchemy
- Key tables: analysis_jobs, flows, alerts, incidents, host_risk_scores

### API
- FastAPI with async endpoints
- Pagination, filtering, sorting on all list endpoints
- SSE for job progress updates
