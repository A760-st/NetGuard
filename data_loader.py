"""
data_loader.py
--------------
Phase 1 — Data Ingestion Pipeline
NTRO Non-IoC Network Flow Anomaly Detection Project

Ingests CIC-IDS2017 CSV flow logs, cleans column names, handles
bad values (NaN / Inf), computes the derived `Byte_Asymmetry_Ratio`
feature, and returns a DataFrame restricted to the 12 core runtime
features used by the downstream ML pipeline.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Optional

import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# Module-level logger
# ---------------------------------------------------------------------------
logging.basicConfig(
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Raw CIC-IDS2017 column names for the numerator / denominator of the
# derived feature — kept separate so they are not accidentally dropped
# before the ratio is computed.
# NOTE: these are the *stripped* names (leading/trailing whitespace removed
#       by _clean_columns() before this lookup is performed).
_TOT_FWD_COL: str = "Total Length of Fwd Packets"
_TOT_BWD_COL: str = "Total Length of Bwd Packets"

# The 12 core runtime features expected by the ML pipeline.
# All names match the CIC-IDS2017 CSV headers after whitespace-stripping.
CORE_FEATURES: List[str] = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "Flow IAT Mean",
    "Flow IAT Std",
    "SYN Flag Count",
    "ACK Flag Count",
    "Byte_Asymmetry_Ratio",  # derived — computed inside the loader
]

# Raw columns required to be present before feature selection.
# `Byte_Asymmetry_Ratio` is derived, so its two source columns must exist.
_REQUIRED_RAW_COLS: List[str] = [
    c for c in CORE_FEATURES if c != "Byte_Asymmetry_Ratio"
] + [_TOT_FWD_COL, _TOT_BWD_COL]


# ---------------------------------------------------------------------------
# CSVFlowLoader
# ---------------------------------------------------------------------------

class CSVFlowLoader:
    """Loads and cleans one or more CIC-IDS2017 CSV flow-log files.

    Parameters
    ----------
    file_paths:
        One or more paths to CIC-IDS2017 CSV files.  Multiple files are
        concatenated into a single DataFrame in the order given.
    label_col:
        Name of the label column (default ``"Label"``).  If present it is
        retained in the output so callers can split benign / attack rows.
    chunksize:
        If set, CSVs are read in chunks of this many rows to limit peak
        memory usage on large files.  Set to ``None`` (default) to read
        each file entirely in one shot.
    """

    def __init__(
        self,
        file_paths: List[str | Path],
        label_col: str = "Label",
        chunksize: Optional[int] = None,
    ) -> None:
        self.file_paths: List[Path] = [Path(p) for p in file_paths]
        self.label_col: str = label_col
        self.chunksize: Optional[int] = chunksize

        self._validate_paths()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load(self) -> pd.DataFrame:
        """Read, clean, and merge all configured CSV files.

        Returns
        -------
        pd.DataFrame
            DataFrame with exactly the 12 ``CORE_FEATURES`` columns plus
            the label column (if it existed in the source data).
            Index is reset and contiguous.
        """
        frames: List[pd.DataFrame] = []
        for path in self.file_paths:
            logger.info("Loading file: %s", path.name)
            df = self._read_csv(path)
            df = self._clean_columns(df)
            df = self._compute_derived_features(df)
            df = self._handle_bad_values(df)
            df = self._select_features(df)
            logger.info(
                "  -> %d rows, %d cols after cleaning", len(df), df.shape[1]
            )
            frames.append(df)

        combined = pd.concat(frames, ignore_index=True)
        logger.info(
            "Total loaded: %d rows across %d file(s)",
            len(combined),
            len(self.file_paths),
        )
        return combined

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _validate_paths(self) -> None:
        """Raise FileNotFoundError early if any configured path is missing."""
        for path in self.file_paths:
            if not path.exists():
                raise FileNotFoundError(
                    f"CIC-IDS2017 CSV not found: {path}"
                )

    def _read_csv(self, path: Path) -> pd.DataFrame:
        """Read a single CSV, optionally in chunks."""
        if self.chunksize is not None:
            chunks = pd.read_csv(
                path,
                chunksize=self.chunksize,
                low_memory=False,
            )
            return pd.concat(chunks, ignore_index=True)
        return pd.read_csv(path, low_memory=False)

    def _clean_columns(self, df: pd.DataFrame) -> pd.DataFrame:
        """Strip leading/trailing whitespace from every column name."""
        original = list(df.columns)
        df.columns = df.columns.str.strip()
        renamed = [
            (o, n) for o, n in zip(original, df.columns) if o != n
        ]
        if renamed:
            logger.debug(
                "Stripped whitespace from %d column name(s): %s",
                len(renamed),
                renamed[:5],
            )
        return df

    def _compute_derived_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Compute ``Byte_Asymmetry_Ratio`` from the raw packet-length columns.

        Formula:
            Byte_Asymmetry_Ratio = (TotLen Fwd Pkts + 1) / (TotLen Bwd Pkts + 1)

        Adding +1 avoids division-by-zero when either column is zero.
        """
        missing = [c for c in [_TOT_FWD_COL, _TOT_BWD_COL] if c not in df.columns]
        if missing:
            raise KeyError(
                f"Cannot compute Byte_Asymmetry_Ratio - missing columns: {missing}. "
                "Check that the CSV column names match the CIC-IDS2017 schema."
            )

        df["Byte_Asymmetry_Ratio"] = (df[_TOT_FWD_COL] + 1.0) / (
            df[_TOT_BWD_COL] + 1.0
        )
        logger.debug("Derived feature 'Byte_Asymmetry_Ratio' computed.")
        return df

    def _handle_bad_values(self, df: pd.DataFrame) -> pd.DataFrame:
        """Replace Inf / -Inf with NaN, then drop rows that contain NaN.

        CIC-IDS2017 is known to contain rows where flow-rate features are
        recorded as infinity.  Dropping these rows is safer than imputing
        them for an anomaly-detection baseline.
        """
        before = len(df)

        numeric_cols = df.select_dtypes(include=[np.number]).columns
        df[numeric_cols] = df[numeric_cols].replace(
            [np.inf, -np.inf], np.nan
        )

        df = df.dropna(
            subset=[c for c in CORE_FEATURES if c in df.columns]
        )

        dropped = before - len(df)
        if dropped:
            logger.warning(
                "Dropped %d row(s) containing NaN / Inf values (%.2f%% of input).",
                dropped,
                100.0 * dropped / max(before, 1),
            )
        return df

    def _select_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Keep only the 12 CORE_FEATURES plus the label column (if present)."""
        missing_features = [c for c in CORE_FEATURES if c not in df.columns]
        if missing_features:
            raise KeyError(
                f"The following required features are absent from the CSV: "
                f"{missing_features}"
            )

        keep = list(CORE_FEATURES)
        if self.label_col in df.columns:
            keep.append(self.label_col)
        else:
            logger.warning(
                "Label column '%s' not found - output will not include labels.",
                self.label_col,
            )

        return df[keep].reset_index(drop=True)


# ---------------------------------------------------------------------------
# Convenience helper
# ---------------------------------------------------------------------------

def load_benign_only(
    file_path: str | Path,
    label_col: str = "Label",
    benign_label: str = "BENIGN",
) -> pd.DataFrame:
    """Load a single CIC-IDS2017 CSV and return only the benign rows.

    This is the entry-point used by ``preprocessing.py`` to fit the scaler
    strictly on clean, attack-free traffic (Monday's CSV is 100% benign,
    but this filter is applied defensively for safety).

    Parameters
    ----------
    file_path:
        Path to the CIC-IDS2017 CSV (e.g. Monday-WorkingHours...csv).
    label_col:
        Name of the label column.
    benign_label:
        String label used for normal traffic in the dataset.

    Returns
    -------
    pd.DataFrame
        Feature DataFrame containing only benign-labelled rows.
    """
    loader = CSVFlowLoader(file_paths=[file_path], label_col=label_col)
    df = loader.load()

    if label_col in df.columns:
        benign_df = df[df[label_col].str.strip().str.upper() == benign_label.upper()]
        n_filtered = len(df) - len(benign_df)
        if n_filtered:
            logger.warning(
                "load_benign_only: filtered out %d non-benign rows.", n_filtered
            )
        return benign_df[CORE_FEATURES].reset_index(drop=True)

    # If no label column exists, assume the file is 100% benign (e.g. Monday)
    logger.info(
        "No label column found - treating entire file as benign traffic."
    )
    return df[CORE_FEATURES].reset_index(drop=True)
