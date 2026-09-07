import os
import json
import pickle
import numpy as np
import torch

from ml.models.autoencoder import FlowAutoencoder


class AnomalyInferenceEngine:
    def __init__(self, artifacts_dir: str = "./ml/artifacts"):
        self.artifacts_dir = artifacts_dir
        self.model: FlowAutoencoder | None = None
        self.scaler = None
        self.threshold: float = 0.0
        self.loaded = False

    def load(self) -> bool:
        model_path = os.path.join(self.artifacts_dir, "flow_autoencoder.pt")
        scaler_path = os.path.join(self.artifacts_dir, "netguard_flow_scaler.pkl")
        threshold_path = os.path.join(self.artifacts_dir, "threshold.json")

        if not all(os.path.exists(p) for p in [model_path, scaler_path, threshold_path]):
            return False

        try:
            self.model = FlowAutoencoder(input_dim=12)
            state_dict = torch.load(model_path, map_location="cpu")
            self.model.load_state_dict(state_dict)
            self.model.eval()

            with open(scaler_path, "rb") as f:
                self.scaler = pickle.load(f)

            with open(threshold_path, "r") as f:
                data = json.load(f)
                self.threshold = data.get("threshold", 0.5)

            self.loaded = True
            return True
        except Exception as e:
            print(f"Failed to load anomaly model: {e}")
            return False

    def predict(self, feature_vectors: list[list[float]]) -> list[dict]:
        if not self.loaded or self.model is None or self.scaler is None:
            return [
                {"anomaly_score": 0.0, "is_anomaly": False, "reconstruction_error": 0.0}
                for _ in feature_vectors
            ]

        X = np.array(feature_vectors, dtype=np.float32)
        X_scaled = self.scaler.transform(X)
        X_tensor = torch.FloatTensor(X_scaled)

        with torch.no_grad():
            reconstructed = self.model(X_tensor)
            errors = torch.mean((X_tensor - reconstructed) ** 2, dim=1).numpy()

        results = []
        for error in errors:
            score = min(float(error / self.threshold), 1.0) if self.threshold > 0 else 0.0
            results.append(
                {
                    "anomaly_score": round(score, 4),
                    "is_anomaly": bool(error > self.threshold),
                    "reconstruction_error": round(float(error), 6),
                }
            )

        return results

    def predict_single(self, features: list[float]) -> dict:
        results = self.predict([features])
        return results[0] if results else {"anomaly_score": 0.0, "is_anomaly": False}
