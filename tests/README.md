# Tests

This directory contains top-level integration and end-to-end test scaffolding.

| Directory | Purpose |
|-----------|---------|
| `integration/` | Cross-service integration tests (backend + packet engine + database) |
| `e2e/` | End-to-end UI workflows against a running stack |

## Running Tests

```bash
# Backend unit/integration tests (requires PostgreSQL)
cd backend
pip install -r requirements-dev.txt
pytest -v

# Packet engine tests
cd packet-engine
go test ./...

# Frontend tests
cd frontend
npm test
```

Backend tests exercise the real async SQLAlchemy layer and expect a reachable
PostgreSQL instance (defaults: `localhost:5432`, user `netguard`, password
`netguard_secret_change_me`, database `netguard`). The Docker stack provides
these automatically.

No fabricated results are used in any test — assertions validate real
computation from synthetic-but-real PCAP structures.