# NTRO Non-IoC Network Flow Anomaly Detection Engine

A real-time network traffic anomaly detection system built for **Smart India Hackathon 2026**. It captures live network flows, scores them through a Deep Autoencoder trained on benign traffic, maintains per-IP risk scores, and exposes a REST API — all without relying on traditional IoC (Indicator of Compromise) signature lists.

---

## Architecture

```
            LIVE INTERNET / NETWORK TRAFFIC
                          │
                          ▼
                 ┌─────────────────┐
                 │   Go Sniffer    │  sniffer.go
                 │  (gopacket)     │  captures raw packets → computes
                 │                 │  12 flow-level features per window
                 └────────┬────────┘
                          │  JSON → Redis list  (ntro:flow_queue)
                          ▼
                 ┌─────────────────┐
                 │      Redis      │  decoupled, durable queue
                 │  localhost:6379 │
                 └────────┬────────┘
                          │
                          ▼
                 ┌─────────────────┐
                 │ Python Worker   │  worker.py
                 │  (asyncio)      │  batch-dequeues flows, runs ML
                 └────────┬────────┘
                          │
                          ▼
                 ┌─────────────────┐
                 │ FlowAutoencoder │  model.py / inference.py
                 │  12→8→4→8→12   │  reconstruction loss → anomaly flag
                 └────────┬────────┘
                          │
               ┌──────────┴──────────┐
               ▼                     ▼
        Risk Scoring           Flow Results
        (EMA, α=0.85)          (loss, flag, confidence)
               │                     │
               └──────────┬──────────┘
                          ▼
                 ┌─────────────────┐
                 │ Neon PostgreSQL │  Prisma ORM
                 │  network_flow_  │  network_flow_logs
                 │  logs / scores  │  host_risk_scores
                 └─────────────────┘

                 ┌─────────────────┐
                 │  FastAPI  :8000 │  main.py
                 │  REST API       │  POST /api/v1/flows/evaluate
                 └─────────────────┘  GET  /api/v1/risk/{ip}
```

---

## Project Structure

```
sih2026/
├── data_loader.py        # CIC-IDS2017 CSV ingestion & 12-feature extraction
├── preprocessing.py      # StandardScaler pipeline (fit + transform)
├── model.py              # FlowAutoencoder: symmetric encoder-decoder (PyTorch)
├── train.py              # Training loop — produces artifacts/
├── inference.py          # AnomalyDetector: loads artifacts, exposes predict()
├── schema.prisma         # Prisma schema — NetworkFlowLog + HostRiskScore
├── database.py           # Prisma async client lifecycle
├── risk_engine.py        # RiskScorer: exponential-decay per-IP risk (0-100)
├── main.py               # FastAPI app — /flows/evaluate, /risk/{ip}
├── redis_client.py       # Async Redis helpers (enqueue / dequeue)
├── worker.py             # Background batch worker (Redis → ML → PostgreSQL)
├── sniffer.go            # Go packet capture (gopacket + libpcap)
├── go.mod                # Go module (gopacket v1.1.19, go-redis v9)
├── requirements.txt      # Python dependencies
├── Dockerfile            # Container build
├── artifacts/
│   ├── autoencoder.pt    # Trained model weights
│   ├── scaler.joblib     # Fitted StandardScaler
│   └── model_meta.json   # Threshold τ and training metadata
└── Monday-WorkingHours.pcap_ISCX.csv   # CIC-IDS2017 training data
```

---

## The 12 Core ML Features

The autoencoder is trained on these 12 network-flow statistics derived from the CIC-IDS2017 dataset:

| # | Feature | Description |
|---|---------|-------------|
| 1 | `Flow Duration` | Total duration of the flow (µs) |
| 2 | `Tot Fwd Pkts` | Total forward packets |
| 3 | `Tot Bwd Pkts` | Total backward packets |
| 4 | `TotLen Fwd Pkts` | Total bytes in forward direction |
| 5 | `TotLen Bwd Pkts` | Total bytes in backward direction |
| 6 | `Fwd Pkt Len Mean` | Mean forward packet length |
| 7 | `Bwd Pkt Len Mean` | Mean backward packet length |
| 8 | `Flow IAT Mean` | Mean inter-arrival time |
| 9 | `Flow IAT Std` | Std dev of inter-arrival time |
| 10 | `SYN Flag Cnt` | SYN flag count |
| 11 | `ACK Flag Cnt` | ACK flag count |
| 12 | `Byte_Asymmetry_Ratio` | Engineered: `(fwd_bytes - bwd_bytes) / (fwd_bytes + bwd_bytes + 1)` |

---

## Prerequisites

### System-level

| Dependency | Version | Purpose |
|-----------|---------|---------|
| Python | 3.11 | ML, FastAPI, worker |
| Redis | 6+ (8.x tested) | Flow queue |
| Go | 1.22+ | Build the packet sniffer |
| libpcap / libpcap-dev | any | Required by gopacket |

Install on macOS:

```bash
brew install go libpcap redis
```

### Python packages

```bash
pip install --extra-index-url https://download.pytorch.org/whl/cpu -r requirements.txt
```

Key dependencies: `fastapi`, `uvicorn`, `torch==2.3.1`, `numpy`, `pandas`, `scikit-learn`, `joblib`, `prisma`, `asyncpg`, `redis[asyncio]`, `pydantic`, `python-dotenv`.

---

## Environment Variables

Create a `.env` file in the project root:

```env
DATABASE_URL="postgresql://<user>:<password>@<host>/<db>?sslmode=require"
REDIS_URL="redis://localhost:6379/0"
```

> **Neon PostgreSQL** is the recommended hosted database. Copy your connection string from the Neon console.

---

## First-Time Setup

```bash
# 1. Create and activate virtual environment
python3.11 -m venv .venv
source .venv/bin/activate

# 2. Install Python dependencies
pip install --extra-index-url https://download.pytorch.org/whl/cpu -r requirements.txt

# 3. Generate Prisma client and push schema to Neon
prisma generate
prisma db push

# 4. Train the autoencoder on CIC-IDS2017 data
python train.py --epochs 25
```

After training, `artifacts/` will contain:

```
artifacts/
├── autoencoder.pt     # model weights
├── scaler.joblib      # fitted scaler
└── model_meta.json    # threshold τ ≈ 0.533
```

> You only need to retrain when you want to update the model. Pre-trained artifacts are already included in the repo.

---

## Running the Full System (4 Terminals)

### Terminal 1 — Redis

```bash
redis-server
```

Verify it's running:

```bash
redis-cli ping   # should return: PONG
```

---

### Terminal 2 — FastAPI Backend

```bash
cd ~/Documents/sih2026
source .venv/bin/activate
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

API docs available at: `http://localhost:8000/docs`

---

### Terminal 3 — Background Worker

```bash
cd ~/Documents/sih2026
source .venv/bin/activate
python worker.py --batch-size 100
```

The worker continuously dequeues from Redis, runs inference, and writes results + risk scores to Neon PostgreSQL.

---

### Terminal 4 — Go Packet Sniffer

```bash
cd ~/Documents/sih2026
go mod tidy
go build -o sniffer sniffer.go
sudo ./sniffer --iface en0 --window 5 --redis redis://localhost:6379/0
```

- `--iface` — your network interface (`en0` for Wi-Fi on macOS; check with `ifconfig`)
- `--window` — aggregation window in seconds (default: 5)
- `--redis` — Redis URL

> `sudo` is required for raw packet capture via libpcap.

---

## REST API Reference

### `GET /health`

Liveness probe.

```json
{ "status": "ok", "service": "NTRO Anomaly Detection API" }
```

---

### `POST /api/v1/flows/evaluate`

Evaluate a JSON batch of network flows.

**Request body:**

```json
{
  "flows": [
    {
      "srcIp": "192.168.1.10",
      "dstIp": "10.0.0.5",
      "srcPort": 443,
      "dstPort": 54321,
      "protocol": "TCP",
      "Flow Duration": 123456.0,
      "Tot Fwd Pkts": 10,
      "Tot Bwd Pkts": 8,
      "TotLen Fwd Pkts": 4096,
      "TotLen Bwd Pkts": 2048,
      "Fwd Pkt Len Mean": 409.6,
      "Bwd Pkt Len Mean": 256.0,
      "Flow IAT Mean": 12345.0,
      "Flow IAT Std": 3000.0,
      "SYN Flag Cnt": 1,
      "ACK Flag Cnt": 9,
      "Byte_Asymmetry_Ratio": 0.33
    }
  ]
}
```

**Response:**

```json
{
  "total_flows": 1,
  "anomaly_count": 0,
  "anomaly_rate": 0.0,
  "results": [
    {
      "srcIp": "192.168.1.10",
      "dstIp": "10.0.0.5",
      "srcPort": 443,
      "dstPort": 54321,
      "protocol": "TCP",
      "reconstructionLoss": 0.021,
      "isAnomaly": false,
      "anomalyConfidence": 0.12,
      "updatedRiskScore": 1.5
    }
  ],
  "risk_scores": { "192.168.1.10": 1.5 }
}
```

---

### `POST /api/v1/flows/evaluate/csv`

Upload a `.csv` file. Must include `srcIp`, `dstIp`, `srcPort`, `dstPort`, `protocol` columns plus the 12 feature columns.

---

### `GET /api/v1/risk/{ip}`

Get the current risk score for a source IP.

```json
{
  "ipAddress": "192.168.1.10",
  "riskScore": 72.4,
  "anomalyCount": 14,
  "lastUpdated": "2026-08-15T17:00:00Z",
  "severity": "HIGH"
}
```

**Severity thresholds:**

| Score | Severity |
|-------|----------|
| ≥ 75  | `CRITICAL` |
| ≥ 50  | `HIGH` |
| ≥ 25  | `MEDIUM` |
| < 25  | `LOW` |

---

## Model Details

**Architecture:** `FlowAutoencoder` — symmetric encoder-decoder

```
Input (12) → Linear(12→8) → ReLU → Linear(8→4) → ReLU
           → Linear(4→8)  → ReLU → Linear(8→12)
Output (12)
```

| Property | Value |
|----------|-------|
| Total parameters | ~424 |
| Training loss | MSE reconstruction (benign flows only) |
| Anomaly threshold τ | `mean + 3σ` of training losses ≈ 0.533 |
| Anomaly confidence | sigmoid-normalised distance from τ |
| Risk scoring | EMA with α = 0.85, scaled 0–100 |

---

## Database Schema

Two tables managed via Prisma ORM:

### `network_flow_logs`

One row per evaluated flow: timestamp, 5-tuple (srcIp, dstIp, ports, protocol), reconstruction loss, anomaly flag, and confidence score.

### `host_risk_scores`

One upserted row per source IP with its current EMA risk score (0–100) and cumulative anomaly count.

---

## Docker

```bash
docker build -t ntro-anomaly .
docker run -p 8000:8000 --env-file .env ntro-anomaly
```

---

## Training Data

Trained on the **CIC-IDS2017** dataset (Canadian Institute for Cybersecurity):

- `Monday-WorkingHours.pcap_ISCX.csv` — benign traffic baseline
- `Tuesday-WorkingHours.pcap_ISCX.csv` — additional benign + attack flows

Only **benign** flows are used during training so the autoencoder learns the normal manifold. Attack flows produce high reconstruction loss at inference time.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Packet capture | Go + gopacket + libpcap |
| Message queue | Redis 8.x |
| ML model | PyTorch 2.3 (CPU) |
| API server | FastAPI + Uvicorn |
| ORM | Prisma (Python asyncio client) |
| Database | Neon PostgreSQL (serverless) |
| Data processing | Pandas, NumPy, scikit-learn |

---

## Development Status

| Component | Status |
|-----------|--------|
| ML training (CIC-IDS2017) | ✅ Complete |
| Model artifacts | ✅ Generated (`τ ≈ 0.533`) |
| Neon / PostgreSQL connection | ✅ Working |
| Prisma schema + client | ✅ Working |
| FastAPI backend | ✅ Running |
| Redis queue | ✅ Running |
| Python worker | ✅ Running |
| Go sniffer (binary) | ✅ Compiled |
| Go sniffer (live capture) | ⚠️ Requires `sudo` + `libpcap` |
