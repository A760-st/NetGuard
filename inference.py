"""
inference.py
------------
Phase 2 — Anomaly Inference Wrapper
NTRO Non-IoC Network Flow Anomaly Detection Project

Loads the trained FlowAutoencoder, the fitted StandardScaler, and the
threshold metadata computed during training, then exposes a clean
`predict()` API for scoring raw network-flow DataFrames.

Usage example
-------------
    from inference import AnomalyDetector
    import pandas as pd

    detector = AnomalyDetector()   # loads artifacts automatically
    df_live = pd.read_csv("live_flows.csv")

    results = detector.predict(df_live)
    # results is a pd.DataFrame with columns:
    #   reconstruction_loss  |  is_anomaly  |  anomaly_confidence

    # Or retrieve as plain dict of arrays:
    result_dict = detector.predict(df_live, return_dataframe=False)
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Dict, Union

import numpy as np
import pandas as pd
import torch

from model import FlowAutoencoder
from preprocessing import FlowPreprocessor

# ---------------------------------------------------------------------------
# Module-level logger
# ---------------------------------------------------------------------------
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default artifact paths (match train.py)
# ---------------------------------------------------------------------------
_ARTIFACTS_DIR = Path("artifacts")
_DEFAULT_MODEL_PATH = _ARTIFACTS_DIR / "autoencoder.pt"
_DEFAULT_SCALER_PATH = _ARTIFACTS_DIR / "scaler.joblib"
_DEFAULT_META_PATH = _ARTIFACTS_DIR / "model_meta.json"


# ---------------------------------------------------------------------------
# AnomalyDetector
# ---------------------------------------------------------------------------

class AnomalyDetector:
    """Inference wrapper for the trained FlowAutoencoder.

    On instantiation, loads:
    * the saved model state-dict (``autoencoder.pt``),
    * the fitted StandardScaler (``scaler.joblib``),
    * the anomaly threshold τ and metadata (``model_meta.json``).

    Parameters
    ----------
    model_path:
        Path to ``autoencoder.pt``.
    scaler_path:
        Path to ``scaler.joblib``.
    meta_path:
        Path to ``model_meta.json``.
    device:
        Torch device to run inference on.  Defaults to CPU; GPU is
        automatically selected when available.
    """

    def __init__(
        self,
        model_path: Union[str, Path] = _DEFAULT_MODEL_PATH,
        scaler_path: Union[str, Path] = _DEFAULT_SCALER_PATH,
        meta_path: Union[str, Path] = _DEFAULT_META_PATH,
        device: torch.device | None = None,
    ) -> None:
        self._device = device or torch.device(
            "cuda" if torch.cuda.is_available() else "cpu"
        )

        self._meta = self._load_meta(Path(meta_path))
        self._tau: float = float(self._meta["tau"])

        # Reconstruct architecture dims from metadata (future-proof)
        arch = self._meta.get("model_architecture", {})
        self._model = self._load_model(
            Path(model_path),
            input_dim=arch.get("input_dim", 12),
            bottleneck_dim=arch.get("bottleneck_dim", 4),
        )

        self._preprocessor = FlowPreprocessor.load_scaler(Path(scaler_path))

        logger.info(
            "AnomalyDetector ready | device=%s | τ=%.6f",
            self._device, self._tau,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def tau(self) -> float:
        """The anomaly threshold τ loaded from training metadata."""
        return self._tau

    @property
    def metadata(self) -> dict:
        """Full training metadata dictionary."""
        return self._meta

    def predict(
        self,
        df: pd.DataFrame,
        return_dataframe: bool = True,
    ) -> Union[pd.DataFrame, Dict[str, np.ndarray]]:
        """Score a batch of network flows for anomalies.

        Parameters
        ----------
        df:
            Raw (unscaled) flow DataFrame.  Must contain all 12
            ``CORE_FEATURES`` columns (``Byte_Asymmetry_Ratio`` may
            already be pre-computed, or the caller should pass raw flows
            through ``CSVFlowLoader`` first).
        return_dataframe:
            If ``True`` (default), return a ``pd.DataFrame`` indexed
            identically to ``df``.  If ``False``, return a plain dict of
            NumPy arrays.

        Returns
        -------
        pd.DataFrame or dict containing:
            * **reconstruction_loss** – per-sample MSE (float32 ndarray).
            * **is_anomaly** – boolean flag: ``loss > τ``.
            * **anomaly_confidence** – normalised score in [0, 1]:
              ``sigmoid((loss - τ) / τ)`` so that samples exactly at the
              threshold score 0.5 and scores grow smoothly above it.
        """
        if df.empty:
            raise ValueError("predict() received an empty DataFrame.")

        # 1. Scale features → float32 tensor
        X_tensor: torch.Tensor = self._preprocessor.transform(df)
        X_tensor = X_tensor.to(self._device)

        # 2. Run autoencoder reconstruction
        self._model.eval()
        with torch.no_grad():
            losses: torch.Tensor = self._model.reconstruction_loss(
                X_tensor, reduction="none"
            )  # shape (N,)

        losses_np: np.ndarray = losses.cpu().numpy()           # float32 (N,)

        # 3. Binary anomaly flag
        is_anomaly: np.ndarray = losses_np > self._tau         # bool (N,)

        # 4. Anomaly confidence via sigmoid centred on τ
        #    confidence = sigmoid((loss - τ) / τ)
        #    → 0.5 at loss == τ, approaches 1 for loss >> τ
        confidence: np.ndarray = self._sigmoid(
            (losses_np - self._tau) / max(self._tau, 1e-9)
        )

        logger.info(
            "predict(): %d samples | %d anomalies (%.1f%%) | "
            "loss range [%.4f, %.4f]",
            len(df),
            int(is_anomaly.sum()),
            100.0 * is_anomaly.mean(),
            float(losses_np.min()),
            float(losses_np.max()),
        )

        result: dict = {
            "reconstruction_loss": losses_np,
            "is_anomaly": is_anomaly,
            "anomaly_confidence": confidence.astype(np.float32),
        }

        if return_dataframe:
            return pd.DataFrame(result, index=df.index)
        return result

    def score_tensor(self, x: torch.Tensor) -> Dict[str, np.ndarray]:
        """Low-level scoring directly from a pre-scaled float32 tensor.

        This bypasses the DataFrame validation and scaler step — useful
        when the upstream pipeline already produces tensors (e.g. the
        Redis worker in Phase 4).

        Parameters
        ----------
        x:
            Pre-scaled float32 tensor, shape ``(N, 12)``.

        Returns
        -------
        dict
            Same keys as :meth:`predict`.
        """
        x = x.to(self._device)
        self._model.eval()
        with torch.no_grad():
            losses_np = self._model.reconstruction_loss(x, reduction="none").cpu().numpy()

        is_anomaly = losses_np > self._tau
        confidence = self._sigmoid(
            (losses_np - self._tau) / max(self._tau, 1e-9)
        ).astype(np.float32)

        return {
            "reconstruction_loss": losses_np,
            "is_anomaly": is_anomaly,
            "anomaly_confidence": confidence,
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _load_meta(path: Path) -> dict:
        if not path.exists():
            raise FileNotFoundError(
                f"Model metadata not found: {path}. "
                "Run train.py first to generate artifacts."
            )
        with open(path) as f:
            meta = json.load(f)
        logger.info("Loaded metadata from %s | τ=%.6f", path, meta["tau"])
        return meta

    @staticmethod
    def _load_model(
        path: Path,
        input_dim: int = 12,
        bottleneck_dim: int = 4,
    ) -> FlowAutoencoder:
        if not path.exists():
            raise FileNotFoundError(
                f"Model weights not found: {path}. "
                "Run train.py first."
            )
        model = FlowAutoencoder(
            input_dim=input_dim,
            bottleneck_dim=bottleneck_dim,
        )
        state = torch.load(path, map_location="cpu", weights_only=True)
        model.load_state_dict(state)
        model.eval()
        logger.info(
            "Loaded autoencoder weights from %s (%d params)",
            path,
            sum(p.numel() for p in model.parameters()),
        )
        return model

    @staticmethod
    def _sigmoid(x: np.ndarray) -> np.ndarray:
        """Numerically stable sigmoid."""
        return np.where(
            x >= 0,
            1.0 / (1.0 + np.exp(-x)),
            np.exp(x) / (1.0 + np.exp(x)),
        )
