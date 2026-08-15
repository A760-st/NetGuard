"""
main.py
-------
Phase 3 — FastAPI Backend Service
NTRO Non-IoC Network Flow Anomaly Detection Project

Exposes two REST endpoints:

  POST /api/v1/flows/evaluate
    Accepts a batch of raw network flow records (JSON or CSV upload).
    Runs AnomalyDetector.predict(), updates per-IP risk scores via
    RiskScorer, persists everything to Neon, and returns a summary.

  GET /api/v1/risk/{ip}
    Returns the current risk score and anomaly count for a source IP.

Run locally
-----------
    uvicorn main:app --host 0.0.0.0 --port 8000 --reload

Environment
-----------
    DATABASE_URL   — Neon PostgreSQL connection string (required)
    ARTIFACTS_DIR  — path to model/scaler/meta artifacts (default: artifacts/)
"""

from __future__ import annotations

from dotenv import load_dotenv
load_dotenv()  # Loads variables from .env into os.environ

import io
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd
from fastapi import FastAPI, File, HTTPException, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from database import connect_db, disconnect_db, get_db_client
from data_loader import CORE_FEATURES
from inference import AnomalyDetector
from risk_engine import RiskScorer

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Application state (singletons loaded at startup)
# ---------------------------------------------------------------------------

class AppState:
    detector: Optional[AnomalyDetector] = None
    risk_scorer: Optional[RiskScorer] = None

_state = AppState()


# ---------------------------------------------------------------------------
# Lifespan (replaces deprecated @app.on_event)
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Connect DB and load ML artifacts on startup; clean up on shutdown."""
    logger.info("=== Application startup ===")

    # Connect Prisma → Neon
    await connect_db()

    # Load AnomalyDetector artifacts
    artifacts_dir = os.getenv("ARTIFACTS_DIR", "artifacts")
    _state.detector = AnomalyDetector(
        model_path=f"{artifacts_dir}/autoencoder.pt",
        scaler_path=f"{artifacts_dir}/scaler.joblib",
        meta_path=f"{artifacts_dir}/model_meta.json",
    )

    # Initialise RiskScorer (alpha=0.85 as per design)
    _state.risk_scorer = RiskScorer(alpha=0.85)

    logger.info("Startup complete — API ready.")
    yield

    # Shutdown
    logger.info("=== Application shutdown ===")
    await disconnect_db()


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="NTRO Non-IoC Anomaly Detection API",
    version="1.0.0",
    description=(
        "Real-time network flow anomaly detection using a Deep Autoencoder. "
        "Flags flows that deviate from learned benign baselines and "
        "maintains per-IP sliding-window risk scores."
    ),
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class FlowRecord(BaseModel):
    """A single raw network flow record for evaluation."""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    srcIp: str = Field(..., example="192.168.1.10")
    dstIp: str = Field(..., example="10.0.0.5")
    srcPort: int = Field(..., ge=0, le=65535)
    dstPort: int = Field(..., ge=0, le=65535)
    protocol: str = Field(..., example="TCP")

    # The 12 core ML features (must match CORE_FEATURES)
    flow_duration: float = Field(..., alias="Flow Duration")
    tot_fwd_pkts: float = Field(..., alias="Tot Fwd Pkts")
    tot_bwd_pkts: float = Field(..., alias="Tot Bwd Pkts")
    tot_len_fwd_pkts: float = Field(..., alias="TotLen Fwd Pkts")
    tot_len_bwd_pkts: float = Field(..., alias="TotLen Bwd Pkts")
    fwd_pkt_len_mean: float = Field(..., alias="Fwd Pkt Len Mean")
    bwd_pkt_len_mean: float = Field(..., alias="Bwd Pkt Len Mean")
    flow_iat_mean: float = Field(..., alias="Flow IAT Mean")
    flow_iat_std: float = Field(..., alias="Flow IAT Std")
    syn_flag_cnt: float = Field(..., alias="SYN Flag Cnt")
    ack_flag_cnt: float = Field(..., alias="ACK Flag Cnt")
    byte_asymmetry_ratio: float = Field(..., alias="Byte_Asymmetry_Ratio")

    model_config = {"populate_by_name": True}


class FlowBatchRequest(BaseModel):
    flows: List[FlowRecord]


class FlowResult(BaseModel):
    srcIp: str
    dstIp: str
    srcPort: int
    dstPort: int
    protocol: str
    reconstructionLoss: float
    isAnomaly: bool
    anomalyConfidence: float
    updatedRiskScore: float


class EvaluateResponse(BaseModel):
    total_flows: int
    anomaly_count: int
    anomaly_rate: float
    results: List[FlowResult]
    risk_scores: Dict[str, float]


class RiskScoreResponse(BaseModel):
    ipAddress: str
    riskScore: float
    anomalyCount: int
    lastUpdated: str
    severity: str


# ---------------------------------------------------------------------------
# Helper: records → DataFrame
# ---------------------------------------------------------------------------

def _records_to_dataframe(flows: List[FlowRecord]) -> pd.DataFrame:
    """Convert a list of FlowRecord Pydantic models to a feature DataFrame."""
    rows = []
    for f in flows:
        rows.append({col: getattr(f, col.replace(" ", "_").lower(), None)
                     for col in CORE_FEATURES})
    # Use alias-mapped values via model_dump
    rows = []
    for f in flows:
        d = f.model_dump(by_alias=True)
        rows.append({col: d[col] for col in CORE_FEATURES})
    return pd.DataFrame(rows)


def _severity_label(score: float) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health", tags=["Health"])
async def health_check() -> Dict[str, str]:
    """Liveness probe."""
    return {"status": "ok", "service": "NTRO Anomaly Detection API"}


# ---------------------------------------------------------------------------
# POST /api/v1/flows/evaluate  (JSON batch)
# ---------------------------------------------------------------------------

@app.post(
    "/api/v1/flows/evaluate",
    response_model=EvaluateResponse,
    status_code=status.HTTP_200_OK,
    summary="Evaluate a batch of network flows for anomalies",
    tags=["Flows"],
)
async def evaluate_flows(request: FlowBatchRequest) -> EvaluateResponse:
    """
    Accepts a JSON batch of raw network flow records, scores them through
    the Deep Autoencoder, updates per-IP risk scores, and persists
    everything to Neon PostgreSQL.
    """
    if not request.flows:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Flow batch must contain at least one record.",
        )

    return await _run_evaluation(request.flows)


# ---------------------------------------------------------------------------
# POST /api/v1/flows/evaluate/csv  (CSV upload)
# ---------------------------------------------------------------------------

@app.post(
    "/api/v1/flows/evaluate/csv",
    response_model=EvaluateResponse,
    status_code=status.HTTP_200_OK,
    summary="Evaluate a CSV upload of network flows",
    tags=["Flows"],
)
async def evaluate_flows_csv(file: UploadFile = File(...)) -> EvaluateResponse:
    """
    Accepts a CSV file upload (must include the 12 core feature columns
    plus srcIp, dstIp, srcPort, dstPort, protocol).
    """
    if not file.filename.endswith(".csv"):
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Only .csv files are accepted.",
        )

    contents = await file.read()
    try:
        df_raw = pd.read_csv(io.StringIO(contents.decode("utf-8")))
        df_raw.columns = df_raw.columns.str.strip()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to parse CSV: {exc}",
        ) from exc

    # Build FlowRecord list from the CSV rows
    required_meta = {"srcIp", "dstIp", "srcPort", "dstPort", "protocol"}
    missing_meta = required_meta - set(df_raw.columns)
    if missing_meta:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"CSV missing required metadata columns: {missing_meta}",
        )

    flows: List[FlowRecord] = []
    for _, row in df_raw.iterrows():
        try:
            flows.append(FlowRecord(**{col: row[col] for col in
                                       list(required_meta) + CORE_FEATURES
                                       if col in row}))
        except Exception:
            continue  # skip malformed rows

    if not flows:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="No valid flow records could be parsed from the CSV.",
        )

    return await _run_evaluation(flows)


# ---------------------------------------------------------------------------
# GET /api/v1/risk/{ip}
# ---------------------------------------------------------------------------

@app.get(
    "/api/v1/risk/{ip}",
    response_model=RiskScoreResponse,
    summary="Get the current risk score for a source IP",
    tags=["Risk Scores"],
)
async def get_risk_score(ip: str) -> RiskScoreResponse:
    """
    Returns the current exponential-decay risk score (0-100), cumulative
    anomaly count, and last-updated timestamp for the given IP address.
    """
    scorer: RiskScorer = _state.risk_scorer
    record = await scorer.get_score(ip)

    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No risk record found for IP: {ip}",
        )

    return RiskScoreResponse(
        **record,
        severity=_severity_label(record["riskScore"]),
    )


# ---------------------------------------------------------------------------
# Core evaluation logic (shared between JSON + CSV endpoints)
# ---------------------------------------------------------------------------

async def _run_evaluation(flows: List[FlowRecord]) -> EvaluateResponse:
    """Run the full evaluate pipeline for a list of FlowRecord objects."""
    detector: AnomalyDetector = _state.detector
    scorer: RiskScorer = _state.risk_scorer

    if detector is None or scorer is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="ML models are not yet loaded. Retry in a moment.",
        )

    # ---- 1. Build feature DataFrame and run inference --------------------
    feature_df = _records_to_dataframe(flows)
    predictions: pd.DataFrame = detector.predict(feature_df)

    recon_losses: np.ndarray = predictions["reconstruction_loss"].to_numpy()
    is_anomalies: np.ndarray = predictions["is_anomaly"].to_numpy()
    confidences: np.ndarray = predictions["anomaly_confidence"].to_numpy()

    src_ips = [f.srcIp for f in flows]

    # ---- 2. Update risk scores (DB upsert) --------------------------------
    scorer.clear_cache()   # fresh cache per request
    updated_scores = await scorer.update_batch(
        src_ips=src_ips,
        confidences=confidences.tolist(),
        is_anomalies=is_anomalies.tolist(),
    )

    # ---- 3. Persist flow logs to Neon asynchronously ----------------------
    db = get_db_client()
    now = datetime.now(timezone.utc)
    log_data = [
        {
            "timestamp": f.timestamp if f.timestamp.tzinfo else f.timestamp.replace(tzinfo=timezone.utc),
            "srcIp": f.srcIp,
            "dstIp": f.dstIp,
            "srcPort": f.srcPort,
            "dstPort": f.dstPort,
            "protocol": f.protocol,
            "reconstructionLoss": float(recon_losses[i]),
            "isAnomaly": bool(is_anomalies[i]),
            "confidence": float(confidences[i]),
        }
        for i, f in enumerate(flows)
    ]
    await db.networkflowlog.create_many(data=log_data)
    logger.info("Persisted %d flow log(s) to Neon.", len(log_data))

    # ---- 4. Assemble response ---------------------------------------------
    results: List[FlowResult] = [
        FlowResult(
            srcIp=f.srcIp,
            dstIp=f.dstIp,
            srcPort=f.srcPort,
            dstPort=f.dstPort,
            protocol=f.protocol,
            reconstructionLoss=float(recon_losses[i]),
            isAnomaly=bool(is_anomalies[i]),
            anomalyConfidence=float(confidences[i]),
            updatedRiskScore=updated_scores.get(f.srcIp, 0.0),
        )
        for i, f in enumerate(flows)
    ]

    anomaly_count = int(is_anomalies.sum())
    return EvaluateResponse(
        total_flows=len(flows),
        anomaly_count=anomaly_count,
        anomaly_rate=round(anomaly_count / max(len(flows), 1), 4),
        results=results,
        risk_scores=updated_scores,
    )
