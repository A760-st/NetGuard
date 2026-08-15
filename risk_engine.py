"""
risk_engine.py
--------------
Phase 3 — Sliding-Window Exponential Decay Risk Scorer
NTRO Non-IoC Network Flow Anomaly Detection Project

Maintains a per-IP risk score in the range [0, 100] using an exponential
time-decay formula so that stale anomalies gradually fade while fresh
anomalies immediately push the score upward.

Formula
-------
    R_new = min(100, alpha * R_previous + (1 - alpha) * (confidence * 100))

    where:
        alpha      — decay / memory factor (0 < alpha < 1, default 0.85)
        R_previous — the host's current score from the database (0 if unseen)
        confidence — AnomalyDetector anomaly_confidence for the new flow

For benign flows (confidence ≈ 0) the contribution is near zero, so the
score decays toward 0 over time.  A sustained burst of high-confidence
anomalies saturates the score toward 100.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional

from database import get_db_client

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# RiskScorer
# ---------------------------------------------------------------------------

class RiskScorer:
    """Computes and persists exponential-decay risk scores per source IP.

    Parameters
    ----------
    alpha:
        Decay factor controlling how much weight past history carries
        (default 0.85).  Higher alpha → slower forgetting.
    """

    def __init__(self, alpha: float = 0.85) -> None:
        if not (0.0 < alpha < 1.0):
            raise ValueError(f"alpha must be in (0, 1), got {alpha}")
        self.alpha = alpha

        # In-memory cache: ip -> {"riskScore": float, "anomalyCount": int}
        # Populated lazily from the DB and used to avoid redundant DB reads
        # within a single request batch.
        self._cache: Dict[str, Dict] = {}

    # ------------------------------------------------------------------
    # Core formula
    # ------------------------------------------------------------------

    def compute(
        self,
        previous_score: float,
        confidence: float,
        is_anomaly: bool,
    ) -> float:
        """Apply the exponential decay update for a single flow event.

        Parameters
        ----------
        previous_score:
            Host's current risk score (0-100).  Use 0.0 for new/unseen IPs.
        confidence:
            AnomalyDetector's ``anomaly_confidence`` for this flow [0, 1].
        is_anomaly:
            Whether the flow was flagged as anomalous.  If ``False``, the
            contribution term is zeroed so benign flows only drive decay.

        Returns
        -------
        float
            Updated score clamped to [0, 100].
        """
        contribution = (confidence * 100.0) if is_anomaly else 0.0
        new_score = self.alpha * previous_score + (1.0 - self.alpha) * contribution
        return float(min(100.0, max(0.0, new_score)))

    # ------------------------------------------------------------------
    # Batch update (DB-backed)
    # ------------------------------------------------------------------

    async def update_batch(
        self,
        src_ips: List[str],
        confidences: List[float],
        is_anomalies: List[bool],
    ) -> Dict[str, float]:
        """Update risk scores for a batch of flows and persist to Neon.

        Flows are grouped by source IP so that multiple flows from the same
        host within a single batch are applied sequentially (oldest first).

        Parameters
        ----------
        src_ips:
            Source IP address for each flow (parallel to the other lists).
        confidences:
            Anomaly confidence for each flow.
        is_anomalies:
            Boolean anomaly flag for each flow.

        Returns
        -------
        Dict[str, float]
            Mapping of ``{ip: updated_risk_score}`` for every unique IP
            that appeared in the batch.
        """
        if not (len(src_ips) == len(confidences) == len(is_anomalies)):
            raise ValueError("src_ips, confidences, and is_anomalies must have equal length.")

        db = get_db_client()

        # ---- 1. Fetch existing scores for all unique IPs (one query) ------
        unique_ips = list(set(src_ips))
        existing_records = await db.hostriskscore.find_many(
            where={"ipAddress": {"in": unique_ips}}
        )
        existing_map = {r.ipAddress: r for r in existing_records}

        # Seed cache with current DB values
        for ip in unique_ips:
            if ip not in self._cache:
                rec = existing_map.get(ip)
                self._cache[ip] = {
                    "riskScore": rec.riskScore if rec else 0.0,
                    "anomalyCount": rec.anomalyCount if rec else 0,
                }

        # ---- 2. Apply formula sequentially per flow -----------------------
        updated_scores: Dict[str, float] = {}
        for ip, conf, is_anom in zip(src_ips, confidences, is_anomalies):
            prev = self._cache[ip]["riskScore"]
            new_score = self.compute(prev, conf, is_anom)
            self._cache[ip]["riskScore"] = new_score
            if is_anom:
                self._cache[ip]["anomalyCount"] += 1
            updated_scores[ip] = new_score

        # ---- 3. Upsert all touched IPs into Neon in parallel --------------
        now = datetime.now(timezone.utc)
        upsert_tasks = [
            db.hostriskscore.upsert(
                where={"ipAddress": ip},
                data={
                    "create": {
                        "ipAddress": ip,
                        "riskScore": self._cache[ip]["riskScore"],
                        "anomalyCount": self._cache[ip]["anomalyCount"],
                        "lastUpdated": now,
                    },
                    "update": {
                        "riskScore": self._cache[ip]["riskScore"],
                        "anomalyCount": self._cache[ip]["anomalyCount"],
                        "lastUpdated": now,
                    },
                },
            )
            for ip in set(src_ips)
        ]
        await asyncio.gather(*upsert_tasks)

        logger.info(
            "RiskScorer: updated %d unique IPs. Top risks: %s",
            len(set(src_ips)),
            sorted(updated_scores.items(), key=lambda kv: kv[1], reverse=True)[:5],
        )
        return updated_scores

    # ------------------------------------------------------------------
    # Single-IP query helper
    # ------------------------------------------------------------------

    async def get_score(self, ip: str) -> Optional[Dict]:
        """Fetch the current risk record for a single IP from Neon.

        Returns ``None`` if the IP has never been seen.
        """
        db = get_db_client()
        record = await db.hostriskscore.find_unique(where={"ipAddress": ip})
        if record is None:
            return None
        return {
            "ipAddress": record.ipAddress,
            "riskScore": record.riskScore,
            "anomalyCount": record.anomalyCount,
            "lastUpdated": record.lastUpdated.isoformat(),
        }

    def clear_cache(self) -> None:
        """Evict the in-memory IP score cache (useful between request batches)."""
        self._cache.clear()
