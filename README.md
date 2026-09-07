<div align="center">

# NETGUARD

### AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

**Built for SIH 2026**

[![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=flat&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104-009688?style=flat&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=flat&logo=react&logoColor=black)](https://react.dev)
[![Go](https://img.shields.io/badge/Go-1.21-00ADD8?style=flat&logo=go&logoColor=white)](https://go.dev)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?style=flat&logo=postgresql&logoColor=white)](https://postgresql.org)
[![PyTorch](https://img.shields.io/badge/PyTorch-2.0-EE4C2C?style=flat&logo=pytorch&logoColor=white)](https://pytorch.org)

---

NETGUARD is a **passive traffic-analysis and cyber-threat detection platform** that analyzes PCAP files offline to identify threats using machine learning and rule-based detectors.

**NETGUARD does NOT monitor live network traffic.** It processes recorded PCAP files through a complete detection pipeline.

</div>

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                      NETGUARD Pipeline                           │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  PCAP File ──► Parser ──► Flow Engine ──► Feature Engineering    │
│                                              │                   │
│                     ┌────────────────────────┼──────────────┐    │
│                     │                        │              │    │
│              ┌──────▼──────┐    ┌────────────▼───┐   ┌─────▼──┐│
│              │  Autoencoder │    │   7 Threat     │   │ Host   ││
│              │  (ML Anomaly)│    │   Detectors    │   │ Baseline││
│              └──────┬──────┘    └────────┬───────┘   └─────┬──┘│
│                     │                    │                  │    │
│                     └────────────┬───────┘                  │    │
│                                  ▼                          │    │
│                         Evidence Engine                     │    │
│                                  │                          │    │
│                         Risk Engine (0-100)                 │    │
│                                  │                          │    │
│                    Alert Gen + Deduplication                 │    │
│                                  │                          │    │
│                    Incident Correlation                      │    │
│                                  │                          │    │
│                         PostgreSQL ◄─────────────────────────┘    │
│                                  │                               │
│                          FastAPI REST API                         │
│                                  │                               │
│                      React SOC Dashboard                         │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

## Features

### Threat Detection

| Detector | What It Detects | Signals Used |
|----------|----------------|--------------|
| **DDoS Detector** | SYN floods, UDP floods, volumetric attacks | Flow rate, SYN frequency, source concentration, destination concentration |
| **Recon Detector** | Port scanning, host enumeration | Destination port fan-out, host fan-out, short-lived flows |
| **C2 Beacon Detector** | Command & control periodic communication | Inter-arrival time periodicity, repeated src/dst pairs, packet size consistency |
| **DGA Detector** | Domain generation algorithm domains | Domain entropy, character distribution, label structure |
| **DNS Tunnel Detector** | DNS-based data exfiltration | Query length, entropy, label length, query rate |
| **Encrypted Threat Detector** | Anomalous TLS/QUIC behavior | Byte asymmetry, long-duration transfers, RST flag patterns |
| **Exfiltration Detector** | Data exfiltration | Outbound volume ratio, large transfers, long-duration connections |
| **Autoencoder** | Novel anomaly detection | Reconstruction error from 12-feature flow representation |

### ML Model

```
Architecture: 12 → 8 → 4 → 8 → 12
Activation:   ReLU
Loss:         MSE Reconstruction
Training:     Benign traffic only
Scoring:      Reconstruction error vs learned threshold
```

**12 Core Features:**
1. Flow Duration
2. Total Forward Packets
3. Total Backward Packets
4. Total Forward Bytes
5. Total Backward Bytes
6. Forward Packet Length Mean
7. Backward Packet Length Mean
8. Flow IAT Mean
9. Flow IAT Std
10. SYN Flag Count
11. ACK Flag Count
12. Byte Asymmetry Ratio

### SOC Dashboard

- **Overview** — Real-time statistics, threat distribution charts
- **Traffic Analysis** — Filterable flow table with anomaly scores
- **Alerts** — Severity-classified alerts with evidence
- **Incidents** — Correlated multi-alert incidents
- **Host Investigation** — Per-IP risk, flows, alerts, timeline
- **PCAP Jobs** — Upload, monitor, and review analysis jobs
- **Threat Analytics** — Threat distribution, top talkers
- **ML Models** — Model status, architecture, detection coverage
- **System Health** — Service status, database, Redis

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | Python 3.11, FastAPI, Pydantic, SQLAlchemy, PostgreSQL, Redis |
| **Packet Engine** | Go 1.21, Gin, gopacket (skeleton for Phase 2+ PCAP parsing) |
| **ML** | Python, PyTorch, scikit-learn, NumPy |
| **Frontend** | React 18, Vite, TypeScript, Tailwind CSS, Recharts |
| **Infrastructure** | Docker, Docker Compose |
| **Testing** | pytest, Go tests, Vitest |

## Project Structure

```
NETGUARD/
├── backend/                  Python FastAPI backend
│   ├── app/
│   │   ├── api/              REST API endpoints
│   │   ├── core/             Configuration, logging
│   │   ├── database/         SQLAlchemy async connection
│   │   ├── models/           ORM models (11 tables)
│   │   ├── schemas/          Pydantic response schemas
│   │   ├── services/         PCAP parser, flow engine, features, job processor
│   │   ├── detectors/        7 threat detectors + base class
│   │   ├── risk/             Risk scoring engine
│   │   └── correlation/      Incident correlation
│   └── tests/                7 test modules
├── packet-engine/            Go packet engine (skeleton)
├── frontend/                 React/Vite SPA
│   └── src/
│       ├── components/       Sidebar, Header, StatCard, SeverityBadge, EmptyState
│       ├── pages/            9 pages (Overview, Flows, Alerts, etc.)
│       ├── services/         API client
│       └── types/            TypeScript type definitions
├── ml/                       Machine learning
│   ├── models/               Autoencoder architecture
│   ├── training/             Training pipeline
│   ├── inference/            Anomaly inference engine
│   └── evaluation/           Metrics calculation
├── data/                     Sample PCAPs
├── docs/                     Architecture and API docs
└── tests/                    Integration and E2E test stubs
```

## Quick Start

### Prerequisites

- Docker & Docker Compose
- Python 3.11+ (for local development)
- Go 1.21+ (for packet engine development)
- Node.js 18+ (for frontend development)

### Docker (Recommended)

```bash
git clone https://github.com/A760-st/NetGuard.git
cd NetGuard
git checkout adithya_version
cp .env.example .env
docker-compose up --build
```

### Local Development

**Backend:**
```bash
cd backend
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

**Frontend:**
```bash
cd frontend
npm install
npm run dev
```

**Packet Engine:**
```bash
cd packet-engine
go build ./cmd/server
./server
```

### Services

| Service | URL | Purpose |
|---------|-----|---------|
| Frontend | http://localhost:5173 | SOC Dashboard |
| Backend API | http://localhost:8000 | REST API |
| API Docs | http://localhost:8000/docs | Swagger UI |
| Packet Engine | http://localhost:8001 | PCAP Parser |
| PostgreSQL | localhost:5432 | Database |
| Redis | localhost:6379 | Cache |

## API Endpoints

### Health & System

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health check (DB, Redis status) |
| `GET` | `/api/v1/system/status` | Full system status |

### PCAP Analysis

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/pcap/upload` | Upload PCAP and start analysis |
| `GET` | `/api/v1/pcap/jobs` | List all analysis jobs |
| `GET` | `/api/v1/pcap/jobs/{id}` | Get job details |
| `POST` | `/api/v1/pcap/jobs/{id}/cancel` | Cancel a job |
| `GET` | `/api/v1/pcap/jobs/{id}/progress` | SSE progress stream |

### Data

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/flows` | List flows (filterable) |
| `GET` | `/api/v1/flows/{id}` | Get flow details |
| `GET` | `/api/v1/alerts` | List alerts (filterable) |
| `GET` | `/api/v1/alerts/{id}` | Get alert with evidence |
| `GET` | `/api/v1/incidents` | List incidents |
| `GET` | `/api/v1/incidents/{id}` | Get incident details |
| `GET` | `/api/v1/hosts/{ip}/risk` | Host risk score |
| `GET` | `/api/v1/hosts/{ip}/timeline` | Host timeline |

### Analytics

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/analytics/overview` | Overview statistics |
| `GET` | `/api/v1/analytics/threats` | Threat distribution |
| `GET` | `/api/v1/analytics/protocols` | Protocol distribution |
| `GET` | `/api/v1/analytics/top-talkers` | Top source IPs |

## Usage Workflow

```
1. Start the application (Docker or local)
2. Open http://localhost:5173
3. Navigate to "PCAP Jobs"
4. Upload a PCAP file
5. Watch real-time processing progress
6. View extracted flows in "Traffic Analysis"
7. Review detections in "Alerts"
8. Investigate correlated incidents in "Incidents"
9. Drill into specific hosts in "Host Investigation"
10. Analyze threat patterns in "Analytics"
```

## Data Provenance

Every analysis job stores full provenance:

- **File SHA-256** — Immutable file fingerprint
- **Parser version** — PCAP parser used
- **Feature schema version** — Feature engineering version
- **Detector config version** — Detector configuration version
- **Data quality** — Packet statistics, protocol distribution, parsing errors

## Risk Scoring

Risk scores (0-100) are calculated from:

| Factor | Weight |
|--------|--------|
| Detector confidence | Primary |
| Threat severity | Multiplier |
| Occurrence count | Log bonus |
| Anomaly score | ML contribution |
| Temporal decay | Stale activity penalty |

**Severity Classification:**
- 0-24: LOW
- 25-49: MEDIUM
- 50-74: HIGH
- 75-100: CRITICAL

## Testing

```bash
# Backend tests
cd backend
pip install -r requirements-dev.txt
pytest -v

# Frontend tests
cd frontend
npm test

# Packet engine tests
cd packet-engine
go test ./...
```

## Design Principles

1. **No Fake Data** — Every visible result originates from real processed input
2. **No Live Monitoring** — File-driven analysis only
3. **No Payload Decryption** — TLS/QUIC metadata analysis only
4. **No Network Interaction** — Never contacts observed hosts
5. **Modular Detectors** — Each detector is independently replaceable
6. **Graceful Degradation** — Detector failure does not crash the pipeline
7. **Full Traceability** — Every alert traces back to its source PCAP

## Development Phases

| Phase | Status | Focus |
|-------|--------|-------|
| 1 | Complete | Repository setup, Docker, health checks |
| 2 | Complete | PCAP upload, parsing, flow extraction, DB storage |
| 3 | Complete | Feature engineering, validation |
| 4 | Complete | Autoencoder, training, inference, thresholding |
| 5 | Complete | DDoS, Recon, C2 detectors |
| 6 | Complete | DGA, DNS Tunnel, TLS, Exfiltration detectors |
| 7 | Complete | Risk engine, evidence, alerts, deduplication |
| 8 | Complete | Incident correlation, host investigation |
| 9 | Complete | SOC dashboard, analytics, model pages |
| 10 | Complete | Tests, documentation, Docker deployment |

## License

Internal project for Smart India Hackathon 2026.

---

<div align="center">

**NETGUARD** — Passive Traffic Intelligence & Threat Detection Platform

Built with care for SIH 2026

</div>
