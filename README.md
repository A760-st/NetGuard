# NETGUARD

## AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

NETGUARD is a passive traffic-analysis and cyber-threat detection platform built for SIH 2026. It accepts PCAP files as input, extracts real traffic flows, engineers features, runs ML models and threat detectors, and presents results through a professional SOC dashboard.

**NETGUARD does NOT monitor live network traffic.** It analyzes recorded PCAP files offline.

## Quick Start

### Prerequisites

- Docker & Docker Compose
- Go 1.21+ (for packet-engine development)
- Python 3.11+ (for backend/ML development)
- Node.js 18+ (for frontend development)

### Start with Docker

```bash
cp .env.example .env
docker-compose up --build
```

Services:
- Frontend: http://localhost:5173
- Backend API: http://localhost:8000
- Packet Engine: http://localhost:8001
- PostgreSQL: localhost:5432
- Redis: localhost:6379

### Verify

```bash
curl http://localhost:8000/health
curl http://localhost:8001/health
```

## Architecture

```
PCAP/CSV → Traffic Parser → Flow Engine → Feature Engine → ML + Threat Detectors → Evidence → Risk → Alerts → Incidents → PostgreSQL → FastAPI → React Dashboard
```

## Project Structure

```
NETGUARD/
├── backend/          Python FastAPI backend
├── packet-engine/    Go packet parser (gopacket)
├── frontend/         React/Vite TypeScript SPA
├── ml/               ML training, inference, artifacts
├── data/             Sample PCAPs and test fixtures
├── docs/             Documentation
└── tests/            Integration and E2E tests
```

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python, FastAPI, Pydantic, SQLAlchemy, PostgreSQL, Redis |
| Packet Engine | Go, gopacket, libpcap |
| ML | Python, PyTorch, scikit-learn, pandas, NumPy |
| Frontend | React, Vite, TypeScript, Tailwind CSS, Recharts |
| Infra | Docker, Docker Compose |

## Threat Classes

- Volumetric/Protocol DDoS
- Botnet C2 Beaconing
- DGA Domain Detection
- DNS Tunnelling
- TLS/QUIC Encrypted Malware Behavior
- Reconnaissance/Port Scanning
- Data Exfiltration

## Development

See `AGENTS.md` for AI agent instructions and development phases.

## License

Internal project for SIH 2026.
