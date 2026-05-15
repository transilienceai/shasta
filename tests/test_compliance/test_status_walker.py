"""Bug #9 regression tests for the shared control-status walker.

A policy-only control (``requires_policy=True`` and
``has_automated_checks=False``) must stay at ``requires_policy`` regardless
of whether ad-hoc failing findings get tagged to it. Otherwise identical
scans produce different scores depending on which check modules happened
to populate which control IDs — the score regresses between reruns even
though nothing in the environment changed.
"""

from __future__ import annotations

from shasta.compliance._status import apply_control_status, decide_control_status


def _agg(**kwargs) -> dict:
    base = {
        "pass_count": 0,
        "fail_count": 0,
        "partial_count": 0,
        "requires_policy": False,
        "has_automated_checks": False,
    }
    base.update(kwargs)
    return base


def test_policy_only_control_stays_requires_policy_despite_failing_finding():
    """Policy-only control with an ad-hoc fail finding does NOT flip to fail."""
    data = _agg(requires_policy=True, has_automated_checks=False, fail_count=1)
    assert decide_control_status(data) == "requires_policy"


def test_policy_only_control_stays_requires_policy_with_passes_too():
    data = _agg(
        requires_policy=True,
        has_automated_checks=False,
        pass_count=3,
        partial_count=1,
    )
    assert decide_control_status(data) == "requires_policy"


def test_automated_control_still_fails_on_failing_finding():
    """Controls with automated checks mapped in the framework still fail normally."""
    data = _agg(requires_policy=True, has_automated_checks=True, fail_count=1, pass_count=2)
    assert decide_control_status(data) == "fail"


def test_automated_control_passes_when_all_pass():
    data = _agg(has_automated_checks=True, pass_count=5)
    assert decide_control_status(data) == "pass"


def test_partial_beats_pass():
    data = _agg(has_automated_checks=True, pass_count=3, partial_count=1)
    assert decide_control_status(data) == "partial"


def test_not_assessed_when_nothing_tagged():
    assert decide_control_status(_agg()) == "not_assessed"


def test_apply_control_status_mutates_in_place():
    summary = {
        "A": _agg(fail_count=1, has_automated_checks=True),
        "B": _agg(requires_policy=True),
    }
    apply_control_status(summary)
    assert summary["A"]["overall_status"] == "fail"
    assert summary["B"]["overall_status"] == "requires_policy"


def test_status_stable_across_reruns_with_identical_input():
    """Same aggregate → same status, byte-for-byte."""
    data = _agg(
        requires_policy=True,
        has_automated_checks=False,
        fail_count=2,
        pass_count=1,
    )
    first = decide_control_status(data)
    second = decide_control_status(dict(data))
    assert first == second == "requires_policy"
