# Research & Validation

## Dataset Strategy

Detectors are trained/evaluated against datasets appropriate to each threat class.
NETGUARD does **not** train every detector on a single dataset.

| Threat Class | Recommended Dataset |
|--------------|---------------------|
| DDoS | CIC-DDoS2019 |
| Intrusion Detection | CIC-IDS2017, CSE-CIC-IDS2018 |
| Botnet/C2 | CTU-13 |
| DGA | Public DGA datasets |
| DNS | CIC-Bell-DNS2021, DNS-EXF datasets |
| Encrypted Traffic | ISCX VPN/nonVPN |

## Known Limitations & Mitigations

| Concern | NETGUARD Mitigation |
|---------|---------------------|
| Class imbalance | Class-level metrics, threshold from validation only |
| Dataset bias | Per-threat-class dataset selection |
| Cross-dataset generalization | Detectors use protocol-agnostic statistical signals |
| Redundant features | Minimal 12-feature schema, deterministic computation |
| Data quality | Per-job data-quality statistics exposed in job record |
| False positives | Evidence-based alerts, deduplication, risk decay |
| Static thresholds | Automencoder threshold derived from validation data |
| Temporal blindness | IAT-based features, periodicity detection, risk decay |
| Explainability | Every alert carries evidence: feature, value, baseline, interpretation |
| Lab-generated traffic | Preference for real-world PCAP corpora |
| Poor minority-class performance | Explicit class-level metric reporting |
| Data leakage | Attack data excluded from benign training sets |

## Validation Process

For every model/detector change:

1. Choose the dataset appropriate to the threat class.
2. Split into train/validation/test.
3. Train on benign data only (for the autoencoder).
4. Derive threshold from validation data.
5. Evaluate on held-out test data.
6. Record precision, recall, F1, accuracy, FPR, confusion matrix.
7. Report class-level metrics for imbalanced datasets.

## Verification

Currently, detector logic is verified via unit tests with synthetic flow structures
(`backend/tests/test_detectors.py`). Model evaluation utilities are covered in
`ml/tests/`. Running full dataset validation requires obtaining the public datasets;
results will be recorded in this directory.