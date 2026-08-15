"""
model.py
--------
Phase 2 — Deep Autoencoder Architecture
NTRO Non-IoC Network Flow Anomaly Detection Project

Defines the FlowAutoencoder: a symmetric encoder-decoder network trained
exclusively on benign network flows.  At inference time, the reconstruction
error (MSE) serves as the anomaly signal — high loss implies the flow
deviates significantly from the learned "normal" manifold.

Architecture
------------
    Input  (12)
    Encoder:  Linear(12→8) → ReLU → Linear(8→4) → ReLU   [bottleneck: 4]
    Decoder:  Linear(4→8)  → ReLU → Linear(8→12)
    Output (12)  ← reconstruction of the input

The final decoder layer has NO activation so that reconstruction values
are unbounded, matching the StandardScaler-normalised input range.
"""

from __future__ import annotations

import logging
from typing import Tuple

import torch
import torch.nn as nn

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

INPUT_DIM: int = 12          # number of CORE_FEATURES
BOTTLENECK_DIM: int = 4      # latent representation size


# ---------------------------------------------------------------------------
# FlowAutoencoder
# ---------------------------------------------------------------------------

class FlowAutoencoder(nn.Module):
    """Symmetric deep autoencoder for network-flow anomaly detection.

    Parameters
    ----------
    input_dim:
        Number of input/output features.  Must match ``len(CORE_FEATURES)``
        (default 12).
    bottleneck_dim:
        Dimensionality of the compressed latent code (default 4).

    Examples
    --------
    >>> model = FlowAutoencoder()
    >>> x = torch.randn(32, 12)   # batch of 32 flows
    >>> x_hat = model(x)
    >>> x_hat.shape
    torch.Size([32, 12])
    """

    def __init__(
        self,
        input_dim: int = INPUT_DIM,
        bottleneck_dim: int = BOTTLENECK_DIM,
    ) -> None:
        super().__init__()

        hidden_dim: int = input_dim * 2 // 3 + bottleneck_dim  # = 8 for defaults

        # ---- Encoder -------------------------------------------------------
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),   # 12 → 8
            nn.ReLU(),
            nn.Linear(hidden_dim, bottleneck_dim),  # 8 → 4
            nn.ReLU(),
        )

        # ---- Decoder -------------------------------------------------------
        self.decoder = nn.Sequential(
            nn.Linear(bottleneck_dim, hidden_dim),  # 4 → 8
            nn.ReLU(),
            nn.Linear(hidden_dim, input_dim),       # 8 → 12  (no activation)
        )

        self._log_architecture(input_dim, hidden_dim, bottleneck_dim)

    # ------------------------------------------------------------------
    # Forward pass
    # ------------------------------------------------------------------

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Encode then decode the input batch.

        Parameters
        ----------
        x:
            Float32 tensor of shape ``(N, input_dim)``.

        Returns
        -------
        torch.Tensor
            Reconstructed tensor of the same shape as ``x``.
        """
        z = self.encoder(x)
        return self.decoder(z)

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    def encode(self, x: torch.Tensor) -> torch.Tensor:
        """Return only the bottleneck (latent) representation."""
        return self.encoder(x)

    def reconstruction_loss(
        self,
        x: torch.Tensor,
        reduction: str = "none",
    ) -> torch.Tensor:
        """Compute per-sample mean-squared reconstruction error.

        Parameters
        ----------
        x:
            Input tensor, shape ``(N, input_dim)``.
        reduction:
            ``"none"`` → returns shape ``(N,)`` (one loss per sample).
            ``"mean"`` → scalar batch mean.

        Returns
        -------
        torch.Tensor
        """
        x_hat = self.forward(x)
        loss_per_feature = (x - x_hat) ** 2          # (N, D)
        loss_per_sample = loss_per_feature.mean(dim=1)  # (N,)

        if reduction == "mean":
            return loss_per_sample.mean()
        if reduction == "none":
            return loss_per_sample
        raise ValueError(f"Unknown reduction: '{reduction}'. Use 'none' or 'mean'.")

    def parameter_count(self) -> Tuple[int, int]:
        """Return (total_params, trainable_params) counts."""
        total = sum(p.numel() for p in self.parameters())
        trainable = sum(p.numel() for p in self.parameters() if p.requires_grad)
        return total, trainable

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    def _log_architecture(
        self, input_dim: int, hidden_dim: int, bottleneck_dim: int
    ) -> None:
        logger.info(
            "FlowAutoencoder initialised: %d → %d → %d → %d → %d",
            input_dim,
            hidden_dim,
            bottleneck_dim,
            hidden_dim,
            input_dim,
        )
