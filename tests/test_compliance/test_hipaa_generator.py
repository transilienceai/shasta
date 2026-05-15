"""Bug #5 regression tests for HIPAA policy generator."""

from __future__ import annotations

import pytest

from shasta.policies.hipaa_generator import (
    HIPAA_POLICIES,
    generate_all_hipaa_policies,
    generate_hipaa_policy,
    list_hipaa_policies,
)

EXPECTED_POLICY_IDS = {
    "hipaa_breach_notification",
    "hipaa_business_associate_management",
    "hipaa_workforce_training",
    "hipaa_security_management",
    "hipaa_minimum_necessary_access",
    "hipaa_contingency_plan",
}


def test_expected_policies_exist():
    """No stubs, no surprises — exactly six HIPAA policies are registered."""
    assert set(HIPAA_POLICIES.keys()) == EXPECTED_POLICY_IDS


def test_every_policy_has_non_stub_template():
    """Every template must be substantive (≥ 500 chars, many sections) —
    prevents anyone from landing a ``pass`` / empty-string policy."""
    for pid, policy in HIPAA_POLICIES.items():
        body = policy["template"]
        assert len(body) > 500, f"{pid} template is suspiciously short ({len(body)} chars)"
        assert body.count("##") >= 4, f"{pid} template should have ≥4 sections"
        assert policy["hipaa_controls"], f"{pid} has empty hipaa_controls list"
        assert policy["filename"].endswith(".md"), f"{pid} filename must be .md"
        assert policy["title"], f"{pid} has empty title"


@pytest.mark.parametrize("policy_id", sorted(EXPECTED_POLICY_IDS))
def test_render_contains_company_and_citation(policy_id):
    out = generate_hipaa_policy(policy_id, company_name="Testaco Health")
    assert "Testaco Health" in out
    assert "HIPAA" in out
    # At least one of the declared HIPAA control citations must appear in
    # the rendered text — protects against someone removing the citation
    # line from a template.
    citations = HIPAA_POLICIES[policy_id]["hipaa_controls"]
    assert any(c in out for c in citations), (
        f"{policy_id}: none of {citations} appeared in rendered output"
    )


def test_unknown_policy_raises():
    with pytest.raises(ValueError, match="Unknown HIPAA policy"):
        generate_hipaa_policy("not_a_real_policy")


def test_list_hipaa_policies_shape():
    entries = list_hipaa_policies()
    assert len(entries) == 6
    assert all({"id", "title", "hipaa_controls", "filename"} <= e.keys() for e in entries)


def test_generate_all_writes_six_files(tmp_path):
    paths = generate_all_hipaa_policies(company_name="Testaco Health", output_path=tmp_path)
    assert len(paths) == 6
    assert all(p.exists() and p.stat().st_size > 0 for p in paths)
