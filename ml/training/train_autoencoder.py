import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
import numpy as np
import json
import os
import pickle
from sklearn.preprocessing import StandardScaler

from ml.models.autoencoder import FlowAutoencoder

FEATURE_NAMES = [
    "flow_duration",
    "total_fwd_packets",
    "total_bwd_packets",
    "total_fwd_bytes",
    "total_bwd_bytes",
    "fwd_packet_length_mean",
    "bwd_packet_length_mean",
    "flow_iat_mean",
    "flow_iat_std",
    "syn_flag_count",
    "ack_flag_count",
    "byte_asymmetry_ratio",
]

INPUT_DIM = len(FEATURE_NAMES)


def train_autoencoder(
    X_train: np.ndarray,
    X_val: np.ndarray,
    epochs: int = 100,
    batch_size: int = 64,
    learning_rate: float = 1e-3,
    device: str = "cpu",
) -> tuple[FlowAutoencoder, StandardScaler, dict]:
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)

    X_train_tensor = torch.FloatTensor(X_train_scaled).to(device)
    X_val_tensor = torch.FloatTensor(X_val_scaled).to(device)

    train_dataset = TensorDataset(X_train_tensor, X_train_tensor)
    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)

    model = FlowAutoencoder(input_dim=INPUT_DIM).to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=learning_rate)
    criterion = nn.MSELoss()

    train_losses = []
    val_losses = []

    for epoch in range(epochs):
        model.train()
        epoch_loss = 0.0
        for batch_x, _ in train_loader:
            optimizer.zero_grad()
            reconstructed = model(batch_x)
            loss = criterion(reconstructed, batch_x)
            loss.backward()
            optimizer.step()
            epoch_loss += loss.item()

        avg_train_loss = epoch_loss / len(train_loader)
        train_losses.append(avg_train_loss)

        model.eval()
        with torch.no_grad():
            val_reconstructed = model(X_val_tensor)
            val_loss = criterion(val_reconstructed, X_val_tensor).item()
            val_losses.append(val_loss)

        if (epoch + 1) % 20 == 0:
            print(
                f"Epoch {epoch + 1}/{epochs} - Train Loss: {avg_train_loss:.6f} - Val Loss: {val_loss:.6f}"
            )

    model.eval()
    with torch.no_grad():
        val_reconstructed = model(X_val_tensor)
        reconstruction_errors = torch.mean(
            (X_val_tensor - val_reconstructed) ** 2, dim=1
        ).cpu().numpy()

    mean_error = float(np.mean(reconstruction_errors))
    std_error = float(np.std(reconstruction_errors))
    threshold = mean_error + 3 * std_error

    metrics = {
        "train_losses": train_losses,
        "val_losses": val_losses,
        "val_mean_error": mean_error,
        "val_std_error": std_error,
        "threshold": threshold,
        "epochs": epochs,
    }

    return model, scaler, metrics


def save_model(
    model: FlowAutoencoder,
    scaler: StandardScaler,
    metrics: dict,
    output_dir: str = "./ml/artifacts",
) -> dict[str, str]:
    os.makedirs(output_dir, exist_ok=True)

    model_path = os.path.join(output_dir, "flow_autoencoder.pt")
    scaler_path = os.path.join(output_dir, "netguard_flow_scaler.pkl")
    threshold_path = os.path.join(output_dir, "threshold.json")
    metrics_path = os.path.join(output_dir, "training_metrics.json")

    torch.save(model.state_dict(), model_path)

    with open(scaler_path, "wb") as f:
        pickle.dump(scaler, f)

    threshold_data = {
        "threshold": metrics["threshold"],
        "mean_error": metrics["val_mean_error"],
        "std_error": metrics["val_std_error"],
    }
    with open(threshold_path, "w") as f:
        json.dump(threshold_data, f, indent=2)

    training_meta = {
        "model_name": "flow_autoencoder",
        "version": "1.0.0",
        "input_dim": INPUT_DIM,
        "architecture": "12-8-4-8-12",
        "epochs": metrics["epochs"],
        "threshold": metrics["threshold"],
        "val_mean_error": metrics["val_mean_error"],
        "val_std_error": metrics["val_std_error"],
        "feature_names": FEATURE_NAMES,
    }
    with open(metrics_path, "w") as f:
        json.dump(training_meta, f, indent=2)

    return {
        "model": model_path,
        "scaler": scaler_path,
        "threshold": threshold_path,
        "metrics": metrics_path,
    }
