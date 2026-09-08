"""Optional LLM completion. Never send API keys to the frontend."""

from __future__ import annotations

import os
from typing import Any

import httpx

from app.core.logging import get_logger

logger = get_logger("xai.llm")

SYSTEM_PROMPT = (
    "You are NetGuard's evidence-grounded analyst. "
    "Use only the supplied evidence. Do not invent network events, IP reputation, "
    "malware families, threat actors, geographic attribution, CVEs, organizations, "
    "attack campaigns, compromised hosts, commands, or payload contents. "
    "If a fact is missing, say 'Not available from the observed traffic.' "
    "NetGuard analyzes recorded traffic only (passive / offline)."
)


def llm_configured() -> bool:
    return bool(os.environ.get("NETGUARD_LLM_API_KEY") or os.environ.get("OPENAI_API_KEY"))


def _settings() -> tuple[str, str, str]:
    api_key = os.environ.get("NETGUARD_LLM_API_KEY") or os.environ.get("OPENAI_API_KEY") or ""
    base = os.environ.get("NETGUARD_LLM_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    model = os.environ.get("NETGUARD_LLM_MODEL", "gpt-4o-mini")
    return api_key, base, model


def complete_analyst_text(xai_payload: dict[str, Any], question: str | None = None) -> dict[str, Any] | None:
    if not llm_configured():
        return None
    api_key, base, model = _settings()
    context = {
        "incident": xai_payload.get("incident"),
        "threat_type": xai_payload.get("incident", {}).get("threat_type"),
        "risk_score": xai_payload.get("risk", {}).get("score"),
        "feature_contributions": xai_payload.get("contributions", {}).get("increasing"),
        "detection_rules": xai_payload.get("detection_rules"),
        "evidence": xai_payload.get("evidence"),
        "why_flagged": xai_payload.get("why_flagged"),
        "traffic": xai_payload.get("incident", {}).get("traffic_stats"),
        "dataset": xai_payload.get("dataset"),
    }
    user = (
        "Structured NetGuard XAI context (JSON-like):\n"
        f"{context}\n\n"
        "Write the analyst sections: Incident Summary, Why It Was Flagged, "
        "Important Evidence, Risk Assessment, Recommended Investigation, Confidence."
    )
    if question:
        user += f"\n\nAnalyst question: {question}\nAnswer using only the context."

    try:
        with httpx.Client(timeout=20.0) as client:
            response = client.post(
                f"{base}/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": model,
                    "temperature": 0,
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": user},
                    ],
                },
            )
        if response.status_code >= 400:
            logger.error("llm_http_error", status=response.status_code)
            return None
        data = response.json()
        text = (
            data.get("choices", [{}])[0]
            .get("message", {})
            .get("content")
        )
        if not text:
            return None
        return {
            "source": "llm",
            "provider": "openai_compatible",
            "model": model,
            "text": text,
        }
    except Exception as exc:
        logger.error("llm_failed", error=str(exc))
        return None
