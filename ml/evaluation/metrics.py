import numpy as np
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    accuracy_score,
    confusion_matrix,
    roc_auc_score,
    average_precision_score,
)


def evaluate_model(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_scores: np.ndarray | None = None,
) -> dict:
    metrics = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "confusion_matrix": confusion_matrix(y_true, y_pred).tolist(),
    }

    unique_classes = np.unique(y_true)
    if len(unique_classes) > 1 and y_scores is not None:
        try:
            metrics["roc_auc"] = float(roc_auc_score(y_true, y_scores))
        except ValueError:
            metrics["roc_auc"] = 0.0
        try:
            metrics["pr_auc"] = float(average_precision_score(y_true, y_scores))
        except ValueError:
            metrics["pr_auc"] = 0.0
    else:
        metrics["roc_auc"] = 0.0
        metrics["pr_auc"] = 0.0

    total = len(y_true)
    tp = int(((y_pred == 1) & (y_true == 1)).sum())
    fp = int(((y_pred == 1) & (y_true == 0)).sum())
    tn = int(((y_pred == 0) & (y_true == 0)).sum())
    fn = int(((y_pred == 0) & (y_true == 1)).sum())

    metrics["true_positives"] = tp
    metrics["false_positives"] = fp
    metrics["true_negatives"] = tn
    metrics["false_negatives"] = fn
    metrics["fpr"] = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    metrics["total_samples"] = total

    if len(unique_classes) > 1:
        class_metrics = {}
        for cls in unique_classes:
            cls_name = str(int(cls))
            cls_mask = y_true == cls
            cls_pred = y_pred == cls
            class_metrics[cls_name] = {
                "support": int(cls_mask.sum()),
                "precision": float(
                    precision_score(y_true == cls, y_pred == cls, zero_division=0)
                ),
                "recall": float(
                    recall_score(y_true == cls, y_pred == cls, zero_division=0)
                ),
                "f1": float(
                    f1_score(y_true == cls, y_pred == cls, zero_division=0)
                ),
            }
        metrics["class_metrics"] = class_metrics

    return metrics
