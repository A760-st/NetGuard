"""NetGuard explainability (XAI) package.

Rule-weighted, evidence-grounded explanations. Not SHAP/LIME unless a model
attribution implementation is added later.
"""

from app.xai.engine import explain_incident, explain_flow
from app.xai.chat import answer_analyst_question

__all__ = ["explain_incident", "explain_flow", "answer_analyst_question"]
