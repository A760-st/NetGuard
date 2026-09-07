# AGENTS.md - AI Agent Instructions for NETGUARD

## Project Overview

NETGUARD is an AI-based passive traffic-analysis and cyber-threat detection platform for unidirectional IP traffic. It is FILE/DATA DRIVEN — no live monitoring, no packet injection, no traffic generation.

## Architecture

```
PCAP/CSV → Traffic Parser → Flow Engine → Feature Engine → ML + Threat Detectors → Evidence → Risk → Alerts → Incidents → PostgreSQL → FastAPI → React Dashboard
```

## Codebase Structure

- `backend/` — Python FastAPI backend (REST API, services, detectors, ML inference, DB)
- `packet-engine/` — Go packet parser (PCAP offline parsing via gopacket)
- `frontend/` — React/Vite TypeScript SPA (SOC dashboard)
- `ml/` — ML training, inference, preprocessing, model artifacts
- `data/` — Sample PCAPs and test fixtures
- `docs/` — Architecture, API, ML, research documentation
- `tests/` — Integration and E2E tests

## Critical Rules

1. **NO FAKE DATA** — Every visible result must originate from real processed input data.
2. **NO LIVE MONITORING** — The system analyzes recorded files only.
3. **NO PAYLOAD DECRYPTION** — TLS/QUIC payloads must never be decrypted.
4. **NO NETWORK INTERACTION** — Never contact observed hosts or send mitigation commands.
5. **MODULAR** — Each detector must be independently replaceable. A single detector failure must not crash the pipeline.

## Development Phases

| Phase | Focus |
|-------|-------|
| 1 | Repo setup, Docker, PostgreSQL, Redis, FastAPI, React/Vite, Go skeleton, health checks |
| 2 | PCAP upload, validation, Go offline parser, flow extraction, DB storage |
| 3 | Feature engineering, feature validation, flow API, Traffic Analysis UI |
| 4 | Autoencoder, training pipeline, inference, thresholding, evaluation |
| 5 | DDoS detector, Recon detector, C2 detector |
| 6 | DGA detector, DNS tunnelling detector, TLS metadata detector, Exfiltration detector |
| 7 | Risk engine, evidence engine, alert generation, deduplication |
| 8 | Incident correlation, host investigation, network graph |
| 9 | Complete SOC dashboard, analytics, research & validation, model pages |
| 10 | Testing, benchmarking, performance, security, docs, Docker deployment |

## Phase Rule

After EVERY phase: inspect implementation, run tests, start services, verify features, fix errors, check regressions. Only then move to the next phase. Do not rewrite working code.

## Before Modifying Code

1. Inspect the repository.
2. Understand existing architecture.
3. Identify dependencies.
4. Determine what is already implemented.
5. Plan the smallest correct change.
6. Do not blindly overwrite files.
7. Do not create duplicate implementations.
8. Do not invent APIs or data schemas without documenting them.

## Testing Requirements

- Backend: `pytest`
- Packet engine: `go test`
- Frontend: `npm test` / `vitest`
- All code must pass lint and typecheck before merge.

## Git Workflow

- Never commit secrets or `.env` files.
- Write concise commit messages.
- Only commit when explicitly asked.

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python, FastAPI, Pydantic, SQLAlchemy, PostgreSQL, Redis |
| Packet | Go, gopacket, libpcap |
| ML | Python, PyTorch, scikit-learn, pandas, NumPy |
| Frontend | React, Vite, TypeScript, Tailwind CSS, Recharts |
| Infra | Docker, Docker Compose |
| Testing | pytest, Go tests, vitest |

## Coding Standards

- Type hints on all Python code.
- Clear variable/function names.
- Small focused functions.
- Structured logging.
- Explicit error handling.
- No magic numbers or hard-coded paths.
- No hard-coded credentials.
- Production-quality code at all times.
