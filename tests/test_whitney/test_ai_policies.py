"""Tests for Whitney AI governance policy generator."""

from __future__ import annotations

from datetime import datetime

import pytest

from whitney.policies.generator import (
    POLICIES,
    generate_policy,
    generate_all_policies,
    list_policies,
)


# All controls/obligations that require policy documents
REQUIRES_POLICY_IDS = {"AI-5.2", "AI-6.1", "AI-8.2", "AI-A.2", "EUAI-9", "EUAI-11", "EUAI-14", "EUAI-52"}


class TestPoliciesDict:
    """Verify the POLICIES dictionary is well-formed."""

    def test_total_policies_count(self):
        assert len(POLICIES) == 7

    def test_all_policies_have_required_fields(self):
        for pid, policy in POLICIES.items():
            assert "title" in policy, f"{pid} missing title"
            assert "controls" in policy, f"{pid} missing controls"
            assert "filename" in policy, f"{pid} missing filename"
            assert "template" in policy, f"{pid} missing template"

    def test_all_filenames_end_with_md(self):
        for pid, policy in POLICIES.items():
            assert policy["filename"].endswith(".md"), f"{pid} filename doesn't end with .md"

    def test_all_templates_contain_company_name(self):
        for pid, policy in POLICIES.items():
            assert "{{ company_name }}" in policy["template"], (
                f"{pid} template missing company_name variable"
            )

    def test_all_templates_contain_effective_date(self):
        for pid, policy in POLICIES.items():
            assert "{{ effective_date }}" in policy["template"], (
                f"{pid} template missing effective_date variable"
            )

    def test_controls_cover_all_requires_policy(self):
        """Every requires_policy control/obligation must be covered by at least one policy."""
        all_controls = set()
        for policy in POLICIES.values():
            all_controls.update(policy["controls"])
        missing = REQUIRES_POLICY_IDS - all_controls
        assert not missing, f"Controls not covered by any policy: {missing}"

    def test_all_templates_start_with_heading(self):
        for pid, policy in POLICIES.items():
            assert policy["template"].lstrip().startswith("# "), (
                f"{pid} template doesn't start with a markdown heading"
            )


class TestGeneratePolicy:
    """Test single policy generation."""

    def test_generate_known_policy(self):
        result = generate_policy("ai_acceptable_use", company_name="TestCorp")
        assert "TestCorp" in result
        assert "AI Acceptable Use Policy" in result

    def test_company_name_substitution(self):
        result = generate_policy("ai_governance_framework", company_name="Acme Inc")
        assert "Acme Inc" in result
        # Should not contain the template variable
        assert "{{ company_name }}" not in result

    def test_effective_date_substitution(self):
        result = generate_policy("ai_risk_assessment", effective_date="2026-04-08")
        assert "2026-04-08" in result
        assert "{{ effective_date }}" not in result

    def test_default_effective_date_is_today(self):
        result = generate_policy("ai_acceptable_use")
        today = datetime.now().strftime("%Y-%m-%d")
        assert today in result

    def test_unknown_policy_raises(self):
        with pytest.raises(ValueError, match="Unknown policy"):
            generate_policy("nonexistent_policy")

    def test_each_policy_renders_without_error(self):
        for pid in POLICIES:
            result = generate_policy(pid, company_name="TestCorp")
            assert isinstance(result, str)
            assert len(result) > 100


class TestGenerateAllPolicies:
    """Test bulk policy generation."""

    def test_generates_all_files(self, tmp_path):
        paths = generate_all_policies(company_name="TestCorp", output_path=tmp_path)
        assert len(paths) == 7
        for p in paths:
            assert p.exists()
            assert p.suffix == ".md"

    def test_output_files_contain_company_name(self, tmp_path):
        generate_all_policies(company_name="MyCo", output_path=tmp_path)
        for p in tmp_path.iterdir():
            content = p.read_text(encoding="utf-8")
            assert "MyCo" in content

    def test_output_files_are_valid_markdown(self, tmp_path):
        generate_all_policies(company_name="TestCorp", output_path=tmp_path)
        for p in tmp_path.iterdir():
            content = p.read_text(encoding="utf-8")
            assert content.startswith("# ")

    def test_creates_output_directory(self, tmp_path):
        out = tmp_path / "nested" / "dir"
        generate_all_policies(company_name="TestCorp", output_path=out)
        assert out.is_dir()
        assert len(list(out.iterdir())) == 7


class TestListPolicies:
    """Test policy listing."""

    def test_returns_all_policies(self):
        result = list_policies()
        assert len(result) == 7

    def test_each_entry_has_expected_keys(self):
        for entry in list_policies():
            assert "id" in entry
            assert "title" in entry
            assert "controls" in entry
            assert "filename" in entry

    def test_ids_match_policies_dict(self):
        ids = {e["id"] for e in list_policies()}
        assert ids == set(POLICIES.keys())
