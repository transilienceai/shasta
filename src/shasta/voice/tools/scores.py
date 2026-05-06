"""Tool functions for compliance scores."""
from typing import Any

from shasta.voice.store import Store

_VALID_FRAMEWORKS = {"soc2", "iso27001", "hipaa", "iso42001", "eu_ai_act", "ai_governance"}


def get_compliance_score(*, store: Store, framework: str) -> dict[str, Any]:
    if framework not in _VALID_FRAMEWORKS:
        return {"error": "invalid_framework", "framework": framework, "valid": sorted(_VALID_FRAMEWORKS)}
    score = store.get_compliance_score(framework)  # type: ignore[arg-type]
    if score is None:
        return {"error": "framework_not_applicable", "framework": framework, "reason": "no_findings_or_scorer_unavailable"}
    return score.model_dump(mode="json")


def get_multi_framework_score(*, store: Store) -> dict[str, Any]:
    return store.get_multi_framework_score().model_dump(mode="json")


def get_score_trend(*, store: Store, framework: str, limit: int = 10) -> dict[str, Any]:
    if framework not in _VALID_FRAMEWORKS:
        return {"error": "invalid_framework", "framework": framework}
    return store.get_score_trend(framework, limit=limit).model_dump(mode="json")  # type: ignore[arg-type]
