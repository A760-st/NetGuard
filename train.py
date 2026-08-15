"""
train.py
--------
Phase 2 — Autoencoder Training Script
NTRO Non-IoC Network Flow Anomaly Detection Project

Pipeline
--------
1. Load 100% benign traffic from Monday's CSV via load_benign_only().
2. Fit StandardScaler on it (no leakage) and save artifact.
3. Split 80/20 into train / validation PyTorch tensors.
4. Train FlowAutoencoder with Adam + MSELoss.
5. Evaluate validation losses → derive anomaly threshold τ.
6. Save model weights and metadata JSON.

Run
---
    python train.py
    python train.py --csv "Monday-WorkingHours.pcap_ISCX.csv" --epochs 30
"""

from __future__ import annotations

import argparse
import json
import logging
import time
from pathlib import Path
from typing import Tuple

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset, random_split

from data_loader import load_benign_only
from model import FlowAutoencoder
from preprocessing import FlowPreprocessor

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
# Defaults
# ---------------------------------------------------------------------------
DEFAULT_CSV = "Monday-WorkingHours.pcap_ISCX.csv"
ARTIFACTS_DIR = Path("artifacts")
SCALER_PATH = ARTIFACTS_DIR / "scaler.joblib"
MODEL_PATH = ARTIFACTS_DIR / "autoencoder.pt"
META_PATH = ARTIFACTS_DIR / "model_meta.json"

TRAIN_RATIO: float = 0.80
BATCH_SIZE: int = 256
LEARNING_RATE: float = 1e-3
DEFAULT_EPOCHS: int = 25
SEED: int = 42


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def set_seed(seed: int) -> None:
    """Fix all relevant RNGs for reproducibility."""
    torch.manual_seed(seed)
    np.random.seed(seed)


def build_dataloaders(
    tensor: torch.Tensor,
    train_ratio: float = TRAIN_RATIO,
    batch_size: int = BATCH_SIZE,
    seed: int = SEED,
) -> Tuple[DataLoader, DataLoader]:
    """Split a tensor into train/val DataLoaders.

    Parameters
    ----------
    tensor:
        Float32 tensor of shape ``(N, 12)``.
    train_ratio:
        Fraction of samples used for training (default 0.80).
    batch_size:
        Mini-batch size for both loaders.
    seed:
        RNG seed for the random split.

    Returns
    -------
    Tuple[DataLoader, DataLoader]
        ``(train_loader, val_loader)``
    """
    dataset = TensorDataset(tensor)
    n_train = int(len(dataset) * train_ratio)
    n_val = len(dataset) - n_train

    generator = torch.Generator().manual_seed(seed)
    train_ds, val_ds = random_split(dataset, [n_train, n_val], generator=generator)

    train_loader = DataLoader(
        train_ds, batch_size=batch_size, shuffle=True, drop_last=True
    )
    val_loader = DataLoader(
        val_ds, batch_size=batch_size * 2, shuffle=False
    )

    logger.info(
        "Dataset split: %d train / %d val  (batch_size=%d)",
        n_train, n_val, batch_size,
    )
    return train_loader, val_loader


def compute_threshold(val_losses: np.ndarray) -> Tuple[float, float, float]:
    """Derive the anomaly threshold τ from validation reconstruction losses.

    Uses the 99th-percentile rule AND the mean + 3σ rule; returns both so
    that the stricter (higher) value can be chosen for a conservative
    low-false-positive deployment.

    Parameters
    ----------
    val_losses:
        1-D array of per-sample MSE losses on the validation set.

    Returns
    -------
    Tuple[float, float, float]
        ``(tau, tau_p99, tau_mean3std)`` where ``tau`` is the chosen
        threshold (max of the two rules).
    """
    tau_p99 = float(np.percentile(val_losses, 99))
    tau_mean3std = float(val_losses.mean() + 3.0 * val_losses.std())
    tau = max(tau_p99, tau_mean3std)
    logger.info(
        "Threshold candidates → p99: %.6f  |  mean+3σ: %.6f  |  chosen τ: %.6f",
        tau_p99, tau_mean3std, tau,
    )
    return tau, tau_p99, tau_mean3std


# ---------------------------------------------------------------------------
# Training loop
# ---------------------------------------------------------------------------

def train(
    model: FlowAutoencoder,
    train_loader: DataLoader,
    val_loader: DataLoader,
    epochs: int = DEFAULT_EPOCHS,
    lr: float = LEARNING_RATE,
    device: torch.device = torch.device("cpu"),
) -> dict:
    """Full training loop with epoch-level logging.

    Parameters
    ----------
    model:
        Uninitialised (randomly-weighted) ``FlowAutoencoder``.
    train_loader / val_loader:
        DataLoaders produced by :func:`build_dataloaders`.
    epochs:
        Number of full passes over the training set.
    lr:
        Adam learning rate.
    device:
        Target device (CPU for Phase 2 baseline).

    Returns
    -------
    dict
        Training history ``{"train_loss": [...], "val_loss": [...]}``.
    """
    model = model.to(device)
    criterion = nn.MSELoss(reduction="mean")
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)

    # Learning-rate scheduler: halve LR if val loss stagnates for 5 epochs
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
        optimizer, mode="min", factor=0.5, patience=5, verbose=False
    )

    history: dict = {"train_loss": [], "val_loss": []}
    best_val_loss = float("inf")
    best_state: dict = {}

    total_params, _ = model.parameter_count()
    logger.info(
        "Starting training: %d epochs | lr=%.0e | device=%s | params=%d",
        epochs, lr, device, total_params,
    )

    t0 = time.time()
    for epoch in range(1, epochs + 1):
        # ---- Training phase -----------------------------------------------
        model.train()
        running_loss = 0.0
        n_batches = 0
        for (batch,) in train_loader:
            batch = batch.to(device)
            optimizer.zero_grad()
            x_hat = model(batch)
            loss = criterion(x_hat, batch)
            loss.backward()
            optimizer.step()
            running_loss += loss.item()
            n_batches += 1

        train_loss = running_loss / max(n_batches, 1)

        # ---- Validation phase ---------------------------------------------
        model.eval()
        val_running = 0.0
        n_val_batches = 0
        with torch.no_grad():
            for (batch,) in val_loader:
                batch = batch.to(device)
                x_hat = model(batch)
                loss = criterion(x_hat, batch)
                val_running += loss.item()
                n_val_batches += 1

        val_loss = val_running / max(n_val_batches, 1)
        scheduler.step(val_loss)

        history["train_loss"].append(round(train_loss, 8))
        history["val_loss"].append(round(val_loss, 8))

        # Track best checkpoint
        if val_loss < best_val_loss:
            best_val_loss = val_loss
            best_state = {k: v.cpu().clone() for k, v in model.state_dict().items()}

        if epoch % 5 == 0 or epoch == 1:
            elapsed = time.time() - t0
            logger.info(
                "Epoch %3d/%d | train_loss: %.6f | val_loss: %.6f | "
                "best_val: %.6f | elapsed: %.1fs",
                epoch, epochs, train_loss, val_loss, best_val_loss, elapsed,
            )

    # Restore best weights
    model.load_state_dict(best_state)
    logger.info(
        "Training complete. Best val_loss: %.6f (total time: %.1fs)",
        best_val_loss, time.time() - t0,
    )
    return history


# ---------------------------------------------------------------------------
# Validation-set threshold computation
# ---------------------------------------------------------------------------

def compute_val_losses(
    model: FlowAutoencoder,
    val_loader: DataLoader,
    device: torch.device,
) -> np.ndarray:
    """Collect per-sample reconstruction losses over the validation set."""
    model.eval()
    all_losses: list[float] = []
    with torch.no_grad():
        for (batch,) in val_loader:
            batch = batch.to(device)
            losses = model.reconstruction_loss(batch, reduction="none")
            all_losses.extend(losses.cpu().numpy().tolist())
    return np.array(all_losses, dtype=np.float32)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(csv_path: str, epochs: int) -> None:
    set_seed(SEED)
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    device = torch.device("cpu")

    # -----------------------------------------------------------------------
    # Step 1: Load & preprocess benign data
    # -----------------------------------------------------------------------
    logger.info("=== Step 1: Loading benign training data ===")
    benign_df = load_benign_only(csv_path)
    logger.info("Benign rows loaded: %d", len(benign_df))

    preprocessor = FlowPreprocessor()
    X_tensor = preprocessor.fit_transform(benign_df)   # float32 tensor (N, 12)
    preprocessor.save_scaler(SCALER_PATH)

    # -----------------------------------------------------------------------
    # Step 2: Build DataLoaders
    # -----------------------------------------------------------------------
    logger.info("=== Step 2: Building DataLoaders ===")
    train_loader, val_loader = build_dataloaders(X_tensor)

    # -----------------------------------------------------------------------
    # Step 3: Train model
    # -----------------------------------------------------------------------
    logger.info("=== Step 3: Training FlowAutoencoder ===")
    model = FlowAutoencoder()
    history = train(model, train_loader, val_loader, epochs=epochs, device=device)

    # -----------------------------------------------------------------------
    # Step 4: Compute anomaly threshold τ from validation losses
    # -----------------------------------------------------------------------
    logger.info("=== Step 4: Computing anomaly threshold τ ===")
    val_losses = compute_val_losses(model, val_loader, device)
    tau, tau_p99, tau_mean3std = compute_threshold(val_losses)

    # -----------------------------------------------------------------------
    # Step 5: Save model weights and metadata
    # -----------------------------------------------------------------------
    logger.info("=== Step 5: Saving artifacts ===")
    torch.save(model.state_dict(), MODEL_PATH)
    logger.info("Model weights saved → %s", MODEL_PATH)

    total_params, trainable_params = model.parameter_count()
    meta = {
        "tau": tau,
        "tau_p99": tau_p99,
        "tau_mean_3std": tau_mean3std,
        "val_loss_mean": float(val_losses.mean()),
        "val_loss_std": float(val_losses.std()),
        "val_loss_max": float(val_losses.max()),
        "model_architecture": {
            "input_dim": 12,
            "hidden_dim": 8,
            "bottleneck_dim": 4,
            "output_dim": 12,
        },
        "training": {
            "epochs": epochs,
            "batch_size": BATCH_SIZE,
            "learning_rate": LEARNING_RATE,
            "train_ratio": TRAIN_RATIO,
            "optimizer": "Adam",
            "loss": "MSELoss",
            "seed": SEED,
        },
        "params": {
            "total": total_params,
            "trainable": trainable_params,
        },
        "history": history,
        "artifacts": {
            "model_weights": str(MODEL_PATH),
            "scaler": str(SCALER_PATH),
            "meta": str(META_PATH),
        },
        "training_csv": csv_path,
    }

    with open(META_PATH, "w") as f:
        json.dump(meta, f, indent=2)
    logger.info("Model metadata saved → %s", META_PATH)
    logger.info("=== Phase 2 training complete. τ = %.6f ===", tau)


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Train the FlowAutoencoder on benign CIC-IDS2017 traffic."
    )
    parser.add_argument(
        "--csv",
        default=DEFAULT_CSV,
        help=f"Path to the benign CSV file (default: {DEFAULT_CSV})",
    )
    parser.add_argument(
        "--epochs",
        type=int,
        default=DEFAULT_EPOCHS,
        help=f"Number of training epochs (default: {DEFAULT_EPOCHS})",
    )
    args = parser.parse_args()
    main(csv_path=args.csv, epochs=args.epochs)
