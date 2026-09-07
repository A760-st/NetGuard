# ML Models

## Flow Anomaly Autoencoder

### Architecture
- Input: 12 flow features
- Encoder: 12 → 8 → 4 (ReLU)
- Decoder: 4 → 8 → 12
- Loss: MSE reconstruction

### Feature Schema

| # | Feature | Name |
|---|---------|------|
| 1 | Flow Duration | `flow_duration` |
| 2 | Total Fwd Packets | `total_fwd_packets` |
| 3 | Total Bwd Packets | `total_bwd_packets` |
| 4 | Total Fwd Bytes | `total_fwd_bytes` |
| 5 | Total Bwd Bytes | `total_bwd_bytes` |
| 6 | Fwd Packet Length Mean | `fwd_packet_length_mean` |
| 7 | Bwd Packet Length Mean | `bwd_packet_length_mean` |
| 8 | Flow IAT Mean | `flow_iat_mean` |
| 9 | Flow IAT Std | `flow_iat_std` |
| 10 | SYN Flag Count | `syn_flag_count` |
| 11 | ACK Flag Count | `ack_flag_count` |
| 12 | Byte Asymmetry Ratio | `byte_asymmetry_ratio` |

### Training Pipeline

```
dataset → feature selection → cleaning → train/validation split
       → StandardScaler → autoencoder → validation errors
       → threshold (mean + 3*std) → evaluation
```

### Artifacts

| File | Purpose |
|------|---------|
| `flow_autoencoder.pt` | PyTorch model weights |
| `netguard_flow_scaler.pkl` | Fitted StandardScaler |
| `threshold.json` | Anomaly threshold from validation |
| `training_metrics.json` | Training metadata |

### Threshold

Threshold is derived from validation reconstruction errors (mean + 3σ). Never hard-coded.

### Inference

The `AnomalyInferenceEngine` normalizes features with the saved scaler, reconstructs
through the autoencoder, and computes an anomaly score as `reconstruction_error / threshold`
(clipped to [0, 1]).

### Evaluation

The `ml/evaluation/metrics.py` module computes:
- Accuracy, Precision, Recall, F1, FPR
- Confusion matrix
- ROC-AUC, PR-AUC
- Class-level metrics for imbalanced datasets

All metrics are computed from actual predictions — no fabricated benchmark numbers.