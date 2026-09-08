"""Map job progress to the visible NetGuard analysis pipeline."""

from __future__ import annotations

from typing import Any

PIPELINE_STAGES: list[tuple[str, str]] = [
    ("dataset_loaded", "Dataset Loaded"),
    ("traffic_parsed", "Traffic Parsed"),
    ("features_extracted", "Features Extracted"),
    ("threat_detection", "Threat Detection"),
    ("risk_scoring", "Risk Scoring"),
    ("incidents_generated", "Incidents Generated"),
]

STAGE_MESSAGES = {
    "dataset_loaded": "Loading recorded traffic...",
    "traffic_parsed": "Processing recorded traffic...",
    "features_extracted": "Extracting features...",
    "threat_detection": "Running threat detection...",
    "risk_scoring": "Calculating risk scores...",
    "incidents_generated": "Generating incidents...",
}

# Progress thresholds at which a stage is considered completed.
STAGE_COMPLETE_AT: dict[str, float] = {
    "dataset_loaded": 0.08,
    "traffic_parsed": 0.22,
    "features_extracted": 0.48,
    "threat_detection": 0.70,
    "risk_scoring": 0.82,
    "incidents_generated": 0.95,
}

STAGE_ORDER = [key for key, _ in PIPELINE_STAGES]


def is_demo_filename(filename: str | None) -> bool:
    if not filename:
        return False
    upper = filename.upper()
    return "DEMO" in upper or "SAMPLE" in upper


def data_mode_label(filename: str | None) -> str:
    if is_demo_filename(filename):
        return "Recorded Traffic / Demo Dataset"
    if filename:
        return "Recorded Traffic / Offline Analysis"
    return "Passive Analysis"


def build_pipeline(
    *,
    status: str | None,
    progress: float,
    current_stage: str | None = None,
    error_message: str | None = None,
) -> dict[str, Any]:
    status = (status or "queued").lower()
    progress = float(progress or 0.0)

    stages: list[dict[str, str]] = []
    if status == "completed":
        for key, label in PIPELINE_STAGES:
            stages.append({"key": key, "label": label, "status": "completed"})
        return {
            "current_stage": "incidents_generated",
            "message": "Analysis complete.",
            "stages": stages,
        }

    if status in ("queued",) and progress <= 0:
        for key, label in PIPELINE_STAGES:
            stages.append({"key": key, "label": label, "status": "pending"})
        return {
            "current_stage": None,
            "message": "Waiting to process recorded traffic.",
            "stages": stages,
        }

    failed = status == "failed"
    active = current_stage if current_stage in STAGE_ORDER else _stage_from_progress(progress, status)

    for key, label in PIPELINE_STAGES:
        complete_at = STAGE_COMPLETE_AT[key]
        if failed and key == active:
            stage_status = "error"
        elif progress >= complete_at and not (failed and STAGE_ORDER.index(key) >= STAGE_ORDER.index(active or key)):
            stage_status = "completed"
        elif key == active and status in ("processing", "queued", "failed"):
            stage_status = "error" if failed else "processing"
        elif active and STAGE_ORDER.index(key) < STAGE_ORDER.index(active):
            stage_status = "completed"
        else:
            stage_status = "pending"
        stages.append({"key": key, "label": label, "status": stage_status})

    message = STAGE_MESSAGES.get(active or "", "Processing recorded traffic...")
    if failed:
        message = error_message or "Unable to process dataset."

    return {
        "current_stage": active,
        "message": message,
        "stages": stages,
    }


def _stage_from_progress(progress: float, status: str) -> str:
    if status in ("queued",) and progress < 0.05:
        return "dataset_loaded"
    for key in reversed(STAGE_ORDER):
        if progress >= STAGE_COMPLETE_AT[key]:
            idx = STAGE_ORDER.index(key)
            if idx + 1 < len(STAGE_ORDER) and progress < 1.0:
                return STAGE_ORDER[min(idx + 1, len(STAGE_ORDER) - 1)]
            return key
    return "dataset_loaded"
