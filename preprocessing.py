"""
preprocessing.py
----------------
Phase 1 — Feature Scaling & Tensor Preparation
NTRO Non-IoC Network Flow Anomaly Detection Project

Fits a StandardScaler strictly on 100% benign training traffic (Monday's
CSV) to avoid data leakage, then transforms both training and test sets
into normalised NumPy arrays and PyTorch float32 tensors ready for the
Deep Autoencoder in Phase 2.

Usage example
-------------
    from data_loader import load_benign_only, CSVFlowLoader
    from preprocessing import FlowPreprocessor

    # 1. Load benign training data (fit scaler on this only)
    train_df = load_benign_only("Monday-WorkingHours.pcap_ISCX.csv")

    # 2. Fit preprocessor and save scaler artifact
    preprocessor = FlowPreprocessor()
    X_train_tensor = preprocessor.fit_transform(train_df)
    preprocessor.save_scaler("artifacts/scaler.joblib")

    # 3. Transform test / mixed-traffic data (no refitting)
    test_df  = CSVFlowLoader(["Tuesday-WorkingHours.pcap_ISCX.csv"]).load()
    X_test_tensor = preprocessor.transform(test_df)

    # 4. Reload in a separate process (e.g. inference)
    infer_preprocessor = FlowPreprocessor.load_scaler("artifacts/scaler.joblib")
    X_live_tensor = infer_preprocessor.transform(live_df)
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

import joblib
import numpy as np
import pandas as pd
import torch
from sklearn.preprocessing import StandardScaler

from data_loader import CORE_FEATURES

# ---------------------------------------------------------------------------
# Module-level logger
# ---------------------------------------------------------------------------
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# FlowPreprocessor
# ---------------------------------------------------------------------------


class FlowPreprocessor:
    """Scales network-flow feature DataFrames and converts them to PyTorch
    float32 tensors for use with the Phase 2 Deep Autoencoder.

    The scaler is fitted **once** on 100% benign traffic to ensure that the
    learned mean/std values are not contaminated by attack samples.

    Parameters
    ----------
    scaler:
        An already-fitted ``StandardScaler`` instance.  Pass ``None``
        (default) to start with an unfitted preprocessor that must be
        initialised via :meth:`fit` or :meth:`fit_transform` before use.
    """

    def __init__(self, scaler: Optional[StandardScaler] = None) -> None:
        self._scaler: Optional[StandardScaler] = scaler
        self._is_fitted: bool = scaler is not None

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def is_fitted(self) -> bool:
        """``True`` if the scaler has been fitted on training data."""
        return self._is_fitted

    @property
    def scaler(self) -> StandardScaler:
        """Return the fitted scaler, raising if not yet fitted."""
        if not self._is_fitted or self._scaler is None:
            raise RuntimeError(
                "FlowPreprocessor: scaler has not been fitted yet. "
                "Call fit() or fit_transform() first."
            )
        return self._scaler

    # ------------------------------------------------------------------
    # Core API
    # ------------------------------------------------------------------

    def fit(self, df: pd.DataFrame) -> "FlowPreprocessor":
        """Fit the ``StandardScaler`` on the provided benign-only DataFrame.

        Parameters
        ----------
        df:
            DataFrame whose columns must be a superset of ``CORE_FEATURES``.
            Only the 12 core feature columns are used for fitting.

        Returns
        -------
        self
            Enables method chaining (``preprocessor.fit(df).transform(df)``).
        """
        X = self._extract_feature_array(df)
        logger.info(
            "Fitting StandardScaler on %d benign samples (%d features).",
            X.shape[0],
            X.shape[1],
        )
        self._scaler = StandardScaler()
        self._scaler.fit(X)
        self._is_fitted = True
        logger.info(
            "Scaler fitted. Feature means: %s",
            dict(zip(CORE_FEATURES, self._scaler.mean_.round(4))),
        )
        return self

    def transform(self, df: pd.DataFrame) -> torch.Tensor:
        """Scale features and return a PyTorch float32 tensor.

        Parameters
        ----------
        df:
            DataFrame with at least the 12 ``CORE_FEATURES`` columns.

        Returns
        -------
        torch.Tensor
            Shape ``(N, 12)`` — float32, CPU tensor ready for autoencoder
            input.
        """
        X = self._extract_feature_array(df)
        X_scaled: np.ndarray = self.scaler.transform(X)
        logger.info(
            "Transformed %d samples -> tensor shape %s.",
            X.shape[0],
            (X.shape[0], X.shape[1]),
        )
        return torch.tensor(X_scaled, dtype=torch.float32)

    def fit_transform(self, df: pd.DataFrame) -> torch.Tensor:
        """Convenience method: fit on ``df``, then transform and return it.

        **Only call this on the benign training set.**  For all other splits,
        use :meth:`transform` to prevent data leakage.

        Parameters
        ----------
        df:
            100% benign training DataFrame.

        Returns
        -------
        torch.Tensor
            Scaled training tensor, shape ``(N, 12)``, dtype float32.
        """
        return self.fit(df).transform(df)

    def transform_numpy(self, df: pd.DataFrame) -> np.ndarray:
        """Same as :meth:`transform` but returns a NumPy ``float32`` array.

        Useful for scikit-learn pipelines or quick inspection without a
        PyTorch dependency.
        """
        X = self._extract_feature_array(df)
        return self.scaler.transform(X).astype(np.float32)

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save_scaler(self, path: str | Path) -> None:
        """Serialise the fitted scaler to disk using joblib.

        Parameters
        ----------
        path:
            Destination file path (e.g. ``"artifacts/scaler.joblib"``).
            Parent directories are created automatically.
        """
        dest = Path(path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.scaler, dest)
        logger.info("Scaler artifact saved to: %s", dest.resolve())

    @classmethod
    def load_scaler(cls, path: str | Path) -> "FlowPreprocessor":
        """Deserialise a previously-saved scaler and return a fitted instance.

        Parameters
        ----------
        path:
            Path to the ``.joblib`` scaler artifact.

        Returns
        -------
        FlowPreprocessor
            A ready-to-use preprocessor that can immediately call
            :meth:`transform` on new data.
        """
        src = Path(path)
        if not src.exists():
            raise FileNotFoundError(
                f"Scaler artifact not found: {src}. "
                "Run fit() or fit_transform() to generate it first."
            )
        scaler: StandardScaler = joblib.load(src)
        logger.info("Scaler artifact loaded from: %s", src.resolve())
        return cls(scaler=scaler)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _extract_feature_array(self, df: pd.DataFrame) -> np.ndarray:
        """Validate presence of CORE_FEATURES and return a float64 NumPy array.

        Raises
        ------
        KeyError
            If any of the 12 required columns are absent from ``df``.
        ValueError
            If the extracted array still contains NaN or Inf values that
            slipped through the loader's cleaning step.
        """
        missing = [c for c in CORE_FEATURES if c not in df.columns]
        if missing:
            raise KeyError(
                f"FlowPreprocessor: DataFrame is missing required feature "
                f"column(s): {missing}"
            )

        X: np.ndarray = df[CORE_FEATURES].to_numpy(dtype=np.float64)

        # Defensive check — should have been handled by CSVFlowLoader
        if not np.isfinite(X).all():
            bad_rows = int((~np.isfinite(X)).any(axis=1).sum())
            raise ValueError(
                f"FlowPreprocessor: {bad_rows} row(s) still contain NaN / Inf "
                "after loading. Ensure CSVFlowLoader._handle_bad_values() ran "
                "before calling FlowPreprocessor."
            )

        return X
