"""Incident-grounded Q&A over an XAI explanation (no generic cyber advice)."""

from __future__ import annotations

import re
from typing import Any

from app.xai.llm import complete_analyst_text, llm_configured

UNAVAILABLE = "Not available from the observed traffic."


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip().lower())


def answer_analyst_question(xai: dict[str, Any], question: str) -> dict[str, Any]:
    q = _norm(question or "")
    if not q:
        return {
            "source": "deterministic_fallback",
            "label": "Evidence-Based Analyst Summary",
            "answer": "Ask a question about the selected incident's evidence, features, or risk score.",
        }

    if llm_configured():
        llm = complete_analyst_text(xai, question=question)
        if llm and llm.get("text"):
            return {
                "source": "llm",
                "label": "AI-generated (evidence-constrained)",
                "answer": llm["text"],
                "model": llm.get("model"),
            }

    return {
        "source": "deterministic_fallback",
        "label": "Evidence-Based Analyst Summary",
        "answer": _deterministic_answer(xai, q),
    }


def _deterministic_answer(xai: dict[str, Any], q: str) -> str:
    if xai.get("insufficient_evidence"):
        fields = ", ".join(xai.get("available_fields") or []) or "none"
        return (
            "Insufficient evidence for a complete explanation. "
            f"Available fields: {fields}."
        )

    incident = xai.get("incident") or {}
    contrib = xai.get("contributions") or {}
    increasing = contrib.get("increasing") or []
    reducing = contrib.get("reducing") or []
    risk = xai.get("risk") or {}
    conf = xai.get("confidence") or {}
    threat = incident.get("threat_type") or UNAVAILABLE
    top = increasing[0] if increasing else None

    if any(k in q for k in ("flagged", "why was", "why is this", "classified", "detection")):
        return xai.get("why_flagged") or UNAVAILABLE

    if any(k in q for k in ("contributed most", "top feature", "most to the risk", "highest contribution")):
        if not top:
            return "No ranked feature contributions are stored for this incident."
        return (
            f"{top.get('display_name')} contributed the most "
            f"({top.get('contribution')} of {risk.get('score')}/100), "
            f"with observed value {top.get('value')}. "
            f"{top.get('interpretation')}"
        )

    if "score" in q or "risk" in q and ("why" in q or "how" in q or re.search(r"\d", q)):
        lines = [
            f"The risk score is {risk.get('score')}/100 "
            f"({risk.get('severity')}). Formula: {risk.get('formula')}."
        ]
        for row in increasing[:5]:
            lines.append(
                f"{row.get('display_name')}: {row.get('contribution')} "
                f"(value={row.get('value')})"
            )
        decomp = risk.get("decomposition") or {}
        if decomp:
            lines.append(
                "Components: "
                f"confidence×severity_weight={decomp.get('confidence_component')}, "
                f"occurrence={decomp.get('occurrence_component')}, "
                f"anomaly={decomp.get('anomaly_component')}."
            )
        return " ".join(lines)

    if "severity" in q:
        return (
            f"Severity is {incident.get('severity')} from thresholds "
            f"{risk.get('thresholds')} applied to score {risk.get('score')}/100. "
            f"{xai.get('analyst', {}).get('risk_assessment') or ''}"
        )

    if "investigate" in q or "what should" in q or "next" in q:
        recs = xai.get("recommendations") or []
        if not recs:
            return "No investigation steps could be derived from stored evidence."
        return "Recommended investigation: " + " ".join(f"{i+1}. {s}" for i, s in enumerate(recs))

    if "evidence" in q or "support" in q:
        if not increasing:
            return "No structured detection evidence items are stored for this incident."
        parts = [
            f"{r.get('display_name')}={r.get('value')} ({r.get('interpretation')})"
            for r in increasing[:6]
        ]
        return "Supporting evidence from triggered rules: " + "; ".join(parts)

    if "confidence" in q:
        return conf.get("explanation") or UNAVAILABLE

    if "reduc" in q or "less confident" in q or "weaken" in q or "negative" in q:
        if not reducing:
            return (
                "No risk-reducing observations were derived. "
                "Confidence would drop if the triggering features were absent or within detector baselines."
            )
        return "Factors that did not increase this score: " + "; ".join(
            f"{r.get('display_name')}: {r.get('interpretation')}" for r in reducing[:5]
        )

    if "feature" in q:
        if not top:
            return "No contributing features are stored for this incident."
        ranked = ", ".join(
            f"{r.get('display_name')} ({r.get('contribution')})" for r in increasing[:5]
        )
        return f"Ranked contributing features for this {threat} incident: {ranked}."

    if "destination" in q or "source" in q or "ip" in q:
        return (
            f"Source {incident.get('source_ip')}, destination {incident.get('destination_ip')}, "
            f"ports {incident.get('source_port')}→{incident.get('destination_port')}, "
            f"protocol {incident.get('protocol')}."
        )

    if "dataset" in q or "label" in q or "ground truth" in q:
        ds = xai.get("dataset") or {}
        return (
            f"Dataset: {ds.get('name')}. Original label: {ds.get('original_label')}. "
            f"NetGuard class: {ds.get('netguard_class')}. {ds.get('mapping_reason') or ''}"
        )

    # Default: stay on this incident rather than generic advice
    return (
        f"Selected incident {incident.get('incident_id')} is {threat} "
        f"with risk {risk.get('score')}/100. {xai.get('why_flagged') or ''} "
        "Ask about features, risk score, evidence, confidence, or investigation steps."
    )
