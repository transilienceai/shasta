"""Shared control-status decision walker.

Every framework mapper (SOC 2, ISO 27001, HIPAA) ends its
``get_*_control_summary`` function by walking the per-control aggregate
dict and writing an ``overall_status`` string. The logic was copy-pasted
across all three files, which meant any stability fix had to be applied
in three places.

Bug #9 from 2026-04-11: a control with ``requires_policy=True`` was
flipping from ``requires_policy`` to ``fail`` between two otherwise
identical scans the moment one failing finding got tagged to it — even
though the control is a policy-only one with no automated checks in the
framework. That produced a spurious score regression between reruns.

The fix here: if the control declares ``requires_policy=True`` AND the
framework has no automated checks mapped to it (``has_automated_checks=False``),
then ad-hoc finding tags do not downgrade it. A control that the
framework considers policy-only stays ``requires_policy`` regardless of
whether some heuristic mapper tagged a technical failing finding against
it. This stabilises scores across reruns without masking real failures:
controls that legitimately have automated checks still fail when those
checks fail.
"""

from __future__ import annotations

_ControlAggregate = (
    dict  # keys: fail_count, partial_count, pass_count, requires_policy, has_automated_checks
)


def decide_control_status(data: _ControlAggregate) -> str:
    """Return the overall_status string for one control aggregate.

    Precedence:
      1. Policy-only controls (requires_policy=True, has_automated_checks=False)
         stay at "requires_policy" — they cannot be failed by technical findings.
      2. Any failing finding → "fail".
      3. Any partial finding → "partial".
      4. Any passing finding → "pass".
      5. Otherwise, if the control requires a policy and has no automated
         checks → "requires_policy".
      6. Otherwise → "not_assessed".
    """
    requires_policy = bool(data.get("requires_policy"))
    has_automated_checks = bool(data.get("has_automated_checks"))

    if requires_policy and not has_automated_checks:
        return "requires_policy"
    if data.get("fail_count", 0) > 0:
        return "fail"
    if data.get("partial_count", 0) > 0:
        return "partial"
    if data.get("pass_count", 0) > 0:
        return "pass"
    if requires_policy and not has_automated_checks:
        return "requires_policy"
    return "not_assessed"


def apply_control_status(summary: dict[str, dict]) -> dict[str, dict]:
    """Mutate each control aggregate in ``summary`` to set overall_status."""
    for data in summary.values():
        data["overall_status"] = decide_control_status(data)
    return summary
