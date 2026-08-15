"""
worker.py
---------
Phase 4 — Async Background Inference Worker
NTRO Non-IoC Network Flow Anomaly Detection Project

Runs a continuous async loop that:
  1. Pops batches of raw flow records from the Redis queue.
  2. Converts them to a feature DataFrame.
  3. Scores them through AnomalyDetector (reconstruction loss, is_anomaly,
     anomaly_confidence).
  4. Updates per-IP risk scores in Neon via RiskScorer.update_batch().
  5. Persists flow logs to Neon via Prisma create_many().
  6. Handles errors gracefully: bad records go to the DLQ; transient errors
     trigger exponential back-off rather than crashing the worker.

Run standalone
--------------
    python worker.py

Environment variables
---------------------
    REDIS_URL          — Redis connection string (default: redis://localhost:6379/0)
    REDIS_QUEUE_NAME   — Queue key (default: ntro:flow_queue)
    DATABASE_URL       — Neon PostgreSQL connection string (required)
    ARTIFACTS_DIR      — Path to model artifacts (default: artifacts/)
    WORKER_BATCH_SIZE  — Max flows per processing cycle (default: 100)
    WORKER_POLL_TIMEOUT— Seconds to block waiting for queue item (default: 2)
    WORKER_BACKOFF_MAX — Max back-off seconds on repeated errors (default: 30)
"""

from __future__ import annotations
from dotenv import load_dotenv
load_dotenv()
import asyncio
import json
import logging
import os
import signal
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd

from data_loader import CORE_FEATURES
from database import connect_db, disconnect_db, get_db_client
from inference import AnomalyDetector
from redis_client import FlowQueueManager, close_pool, ping
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
# Configuration from environment
# ---------------------------------------------------------------------------

ARTIFACTS_DIR: str = os.getenv("ARTIFACTS_DIR", "artifacts")
BATCH_SIZE: int = int(os.getenv("WORKER_BATCH_SIZE", "100"))
POLL_TIMEOUT: float = float(os.getenv("WORKER_POLL_TIMEOUT", "2"))
BACKOFF_MAX: float = float(os.getenv("WORKER_BACKOFF_MAX", "30"))

# Metadata fields that must be present alongside feature columns
_META_FIELDS = {"srcIp", "dstIp", "srcPort", "dstPort", "protocol", "timestamp"}
_ALL_REQUIRED = _META_FIELDS | set(CORE_FEATURES)

# Default placeholder values for optional/missing meta fields
_META_DEFAULTS: Dict[str, Any] = {
    "dstIp": "0.0.0.0",
    "srcPort": 0,
    "dstPort": 0,
    "protocol": "UNKNOWN",
}


# ---------------------------------------------------------------------------
# Utility: parse & validate a raw flow dict
# ---------------------------------------------------------------------------

def _parse_flow(raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Validate and coerce a raw flow dict from the queue.

    Returns the cleaned dict or ``None`` if mandatory fields are missing.
    """
    # srcIp is the minimum required field (needed for risk scoring)
    if "srcIp" not in raw:
        logger.warning("Flow missing 'srcIp' — skipping: %s", raw)
        return None

    # Fill optional meta fields with defaults
    for field, default in _META_DEFAULTS.items():
        raw.setdefault(field, default)

    # Ensure timestamp is a datetime
    ts = raw.get("timestamp")
    if ts is None:
        raw["timestamp"] = datetime.now(timezone.utc)
    elif isinstance(ts, str):
        try:
            raw["timestamp"] = datetime.fromisoformat(ts)
        except ValueError:
            raw["timestamp"] = datetime.now(timezone.utc)

    # Coerce feature values to float
    for col in CORE_FEATURES:
        if col not in raw:
            logger.warning("Flow from %s missing feature '%s' — skipping.", raw["srcIp"], col)
            return None
        try:
            raw[col] = float(raw[col])
        except (TypeError, ValueError):
            logger.warning("Non-numeric value for '%s' in flow from %s.", col, raw["srcIp"])
            return None

    return raw


def _flows_to_dataframe(flows: List[Dict[str, Any]]) -> pd.DataFrame:
    """Extract the 12 CORE_FEATURES from a list of parsed flow dicts."""
    return pd.DataFrame([{col: f[col] for col in CORE_FEATURES} for f in flows])


# ---------------------------------------------------------------------------
# Core processing logic (single batch)
# ---------------------------------------------------------------------------

async def _process_batch(
    batch: List[Dict[str, Any]],
    detector: AnomalyDetector,
    scorer: RiskScorer,
) -> Dict[str, int]:
    """Process one batch of flow records end-to-end.

    Parameters
    ----------
    batch:
        List of raw (un-validated) flow dicts popped from Redis.
    detector:
        Loaded AnomalyDetector instance.
    scorer:
        RiskScorer instance (cache will be cleared per batch).

    Returns
    -------
    dict
        Counts: ``{"total", "valid", "anomalies", "db_persisted"}``.
    """
    # ---- 1. Parse & validate -----------------------------------------
    valid_flows: List[Dict[str, Any]] = []
    for raw in batch:
        parsed = _parse_flow(raw)
        if parsed is not None:
            valid_flows.append(parsed)

    if not valid_flows:
        logger.warning("Entire batch of %d was invalid — nothing to process.", len(batch))
        return {"total": len(batch), "valid": 0, "anomalies": 0, "db_persisted": 0}

    # ---- 2. ML inference ---------------------------------------------
    feature_df = _flows_to_dataframe(valid_flows)
    predictions: pd.DataFrame = detector.predict(feature_df)

    recon_losses: np.ndarray = predictions["reconstruction_loss"].to_numpy()
    is_anomalies: np.ndarray = predictions["is_anomaly"].to_numpy()
    confidences: np.ndarray = predictions["anomaly_confidence"].to_numpy()

    src_ips: List[str] = [f["srcIp"] for f in valid_flows]

    # ---- 3. Update risk scores in Neon (upsert) ----------------------
    scorer.clear_cache()
    await scorer.update_batch(
        src_ips=src_ips,
        confidences=confidences.tolist(),
        is_anomalies=is_anomalies.tolist(),
    )

    # ---- 4. Persist flow logs to Neon --------------------------------
    db = get_db_client()
    now = datetime.now(timezone.utc)
    log_data = []
    for i, flow in enumerate(valid_flows):
        ts = flow["timestamp"]
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        log_data.append({
            "timestamp": ts,
            "srcIp": flow["srcIp"],
            "dstIp": flow["dstIp"],
            "srcPort": int(flow["srcPort"]),
            "dstPort": int(flow["dstPort"]),
            "protocol": str(flow["protocol"]),
            "reconstructionLoss": float(recon_losses[i]),
            "isAnomaly": bool(is_anomalies[i]),
            "confidence": float(confidences[i]),
        })

    await db.networkflowlog.create_many(data=log_data)

    anomaly_count = int(is_anomalies.sum())
    logger.info(
        "Batch processed: %d valid / %d total | anomalies: %d (%.1f%%) | persisted: %d",
        len(valid_flows),
        len(batch),
        anomaly_count,
        100.0 * anomaly_count / max(len(valid_flows), 1),
        len(log_data),
    )

    return {
        "total": len(batch),
        "valid": len(valid_flows),
        "anomalies": anomaly_count,
        "db_persisted": len(log_data),
    }


# ---------------------------------------------------------------------------
# Main worker loop
# ---------------------------------------------------------------------------

async def run_flow_worker(
    batch_size: int = BATCH_SIZE,
    poll_timeout: float = POLL_TIMEOUT,
    backoff_max: float = BACKOFF_MAX,
) -> None:
    """Async worker loop — runs until a SIGTERM / SIGINT is received.

    Parameters
    ----------
    batch_size:
        Maximum flows to dequeue per processing cycle.
    poll_timeout:
        Seconds to block on the Redis queue when it is empty.
    backoff_max:
        Maximum seconds to wait between retries after repeated errors.
    """
    logger.info(
        "Worker starting | batch_size=%d | poll_timeout=%.1fs | backoff_max=%.1fs",
        batch_size, poll_timeout, backoff_max,
    )

    # ---- Initialise dependencies -------------------------------------
    await connect_db()

    if not await ping():
        raise ConnectionError(
            f"Cannot reach Redis at {os.getenv('REDIS_URL', 'redis://localhost:6379/0')}. "
            "Is Redis running?"
        )

    detector = AnomalyDetector(
        model_path=f"{ARTIFACTS_DIR}/autoencoder.pt",
        scaler_path=f"{ARTIFACTS_DIR}/scaler.joblib",
        meta_path=f"{ARTIFACTS_DIR}/model_meta.json",
    )
    scorer = RiskScorer(alpha=0.85)
    queue = FlowQueueManager()

    # ---- Graceful shutdown via asyncio Event -------------------------
    shutdown_event = asyncio.Event()

    def _handle_signal(sig: signal.Signals) -> None:
        logger.info("Received signal %s — initiating graceful shutdown...", sig.name)
        shutdown_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, _handle_signal, sig)

    # ---- Counters for periodic stats log -----------------------------
    total_processed = 0
    total_anomalies = 0
    consecutive_errors = 0
    backoff_seconds = 1.0
    last_stats_time = time.monotonic()

    logger.info("Worker is RUNNING. Polling queue: '%s'", queue.queue_name)

    # ---- Main polling loop -------------------------------------------
    while not shutdown_event.is_set():
        try:
            batch = await queue.pop_batch(
                batch_size=batch_size,
                timeout=poll_timeout,
            )

            if not batch:
                # Queue was empty — no error, just idle
                consecutive_errors = 0
                backoff_seconds = 1.0
                continue

            stats = await _process_batch(batch, detector, scorer)
            total_processed += stats["valid"]
            total_anomalies += stats["anomalies"]
            consecutive_errors = 0
            backoff_seconds = 1.0

        except asyncio.CancelledError:
            logger.info("Worker task cancelled.")
            break

        except Exception as exc:
            consecutive_errors += 1
            backoff_seconds = min(backoff_seconds * 2, backoff_max)
            logger.error(
                "Worker error (attempt %d) — backing off %.1fs: %s",
                consecutive_errors,
                backoff_seconds,
                exc,
                exc_info=True,
            )
            await asyncio.sleep(backoff_seconds)
            continue

        # Periodic stats log every 60 seconds
        now = time.monotonic()
        if now - last_stats_time >= 60:
            q_len = await queue.queue_length()
            logger.info(
                "Worker stats | processed: %d | anomalies: %d | queue_len: %d",
                total_processed,
                total_anomalies,
                q_len,
            )
            last_stats_time = now

    # ---- Shutdown cleanup --------------------------------------------
    logger.info(
        "Worker shutting down. Total processed: %d | Total anomalies: %d",
        total_processed,
        total_anomalies,
    )
    await close_pool()
    await disconnect_db()
    logger.info("Worker stopped cleanly.")


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Run the NTRO background flow inference worker."
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=BATCH_SIZE,
        help=f"Max flows per processing cycle (default: {BATCH_SIZE})",
    )
    parser.add_argument(
        "--poll-timeout",
        type=float,
        default=POLL_TIMEOUT,
        help=f"Seconds to block on empty queue (default: {POLL_TIMEOUT})",
    )
    args = parser.parse_args()

    asyncio.run(
        run_flow_worker(
            batch_size=args.batch_size,
            poll_timeout=args.poll_timeout,
        )
    )
