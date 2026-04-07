"""Tests for ISO 42001 AI management system control definitions."""

from whitney.compliance.iso42001 import (
    ISO42001_CONTROLS,
    ISO42001Control,
    get_iso42001_control,
    get_iso42001_controls_for_check,
    get_automated_iso42001_controls,
    get_policy_required_iso42001_controls,
)


class TestISO42001Controls:
    """Verify the control definitions are complete and well-formed."""

    def test_total_controls_count(self):
        assert len(ISO42001_CONTROLS) == 11

    def test_all_controls_have_required_fields(self):
        for ctrl_id, ctrl in ISO42001_CONTROLS.items():
            assert isinstance(ctrl, ISO42001Control)
            assert ctrl.id == ctrl_id
            assert ctrl.title
            assert ctrl.description
            assert ctrl.clause

    def test_control_ids_follow_pattern(self):
        for ctrl_id in ISO42001_CONTROLS:
            assert ctrl_id.startswith("AI-"), f"Control {ctrl_id} doesn't start with AI-"

    def test_automated_controls_have_check_ids(self):
        automated = [c for c in ISO42001_CONTROLS.values() if c.check_ids]
        for ctrl in automated:
            assert len(ctrl.check_ids) > 0
            for cid in ctrl.check_ids:
                assert isinstance(cid, str)


class TestGetISO42001Control:
    """Test single control lookup."""

    def test_lookup_valid_id(self):
        ctrl = get_iso42001_control("AI-5.2")
        assert ctrl is not None
        assert ctrl.title == "AI Policy"

    def test_lookup_invalid_id(self):
        assert get_iso42001_control("AI-99.99") is None

    def test_lookup_all_ids(self):
        for ctrl_id in ISO42001_CONTROLS:
            assert get_iso42001_control(ctrl_id) is not None


class TestGetISO42001ControlsForCheck:
    """Test check_id to control mapping."""

    def test_known_check_maps_to_control(self):
        controls = get_iso42001_controls_for_check("code-prompt-injection-risk")
        assert len(controls) >= 1
        control_ids = [c.id for c in controls]
        assert "AI-A.8" in control_ids

    def test_unknown_check_returns_empty(self):
        controls = get_iso42001_controls_for_check("nonexistent-check-id")
        assert controls == []

    def test_pii_check_maps_to_data_controls(self):
        controls = get_iso42001_controls_for_check("code-pii-in-prompts")
        control_ids = [c.id for c in controls]
        assert "AI-8.4" in control_ids


class TestGetAutomatedControls:
    """Test filtering for automated controls."""

    def test_returns_only_automated(self):
        automated = get_automated_iso42001_controls()
        assert len(automated) > 0
        for ctrl in automated:
            assert len(ctrl.check_ids) > 0

    def test_excludes_policy_only(self):
        automated = get_automated_iso42001_controls()
        automated_ids = {c.id for c in automated}
        # AI-5.2 is policy-only, no check_ids
        assert "AI-5.2" not in automated_ids


class TestGetPolicyRequiredControls:
    """Test filtering for policy-required controls."""

    def test_returns_only_policy_required(self):
        policy = get_policy_required_iso42001_controls()
        assert len(policy) > 0
        for ctrl in policy:
            assert ctrl.requires_policy is True

    def test_includes_ai_policy(self):
        policy = get_policy_required_iso42001_controls()
        policy_ids = {c.id for c in policy}
        assert "AI-5.2" in policy_ids
