"""Doc-vs-code drift integrity tests.

These tests catch the failure mode that produced the "22 Azure Terraform
templates" phantom: a numeric claim in README.md / TRUST.md that was
correct on the day it was written and silently drifted as the codebase
evolved.

Each test:
  1. Reads a marker line from a doc file
  2. Extracts the claimed number with a tight regex
  3. Computes the *actual* number from the source tree (AST counts,
     registry lengths, or `pytest --collect-only`)
  4. Asserts they match — within a small tolerance for "X+" forms.

When one of these fails, the failure message tells you exactly which
file:line to update and what the new number should be. This is a
load-bearing test: keep it green and the README cannot lie about counts.

Historical narrative lines (build logs, "Session 2 added X" recaps) are
intentionally NOT covered — only live, current claims.
"""

from __future__ import annotations

import ast
import re
import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------------------
# Code-side counters — single source of truth for "what the code actually is"
# ---------------------------------------------------------------------------


def _ast_count_functions(directory: Path, prefix: str) -> int:
    """Count top-level functions whose name starts with `prefix`."""
    n = 0
    for py in directory.rglob("*.py"):
        try:
            tree = ast.parse(py.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name.startswith(prefix):
                n += 1
    return n


def aws_check_count() -> int:
    return _ast_count_functions(REPO_ROOT / "src" / "shasta" / "aws", "check_")


def azure_check_count() -> int:
    return _ast_count_functions(REPO_ROOT / "src" / "shasta" / "azure", "check_")


def whitney_check_count() -> int:
    return _ast_count_functions(REPO_ROOT / "src" / "whitney", "check_")


def shasta_check_count() -> int:
    return aws_check_count() + azure_check_count()


def total_check_count() -> int:
    return shasta_check_count() + whitney_check_count()


def finding_to_risk_count() -> int:
    from shasta.workflows.risk_register import FINDING_TO_RISK

    return len(FINDING_TO_RISK)


def aws_terraform_template_count() -> int:
    from shasta.remediation.engine import TERRAFORM_TEMPLATES

    return sum(1 for k in TERRAFORM_TEMPLATES if not k.startswith("azure-"))


def azure_terraform_template_count() -> int:
    from shasta.remediation.engine import TERRAFORM_TEMPLATES

    return sum(1 for k in TERRAFORM_TEMPLATES if k.startswith("azure-"))


def total_terraform_template_count() -> int:
    from shasta.remediation.engine import TERRAFORM_TEMPLATES

    return len(TERRAFORM_TEMPLATES)


def policy_template_count() -> int:
    from shasta.policies.generator import POLICIES

    return len(POLICIES)


def pytest_collected_count() -> int:
    """Run pytest --collect-only and return the number of tests discovered.

    Excludes tests/test_rainier (untracked sibling project, not part of
    Shasta or Whitney) so the local and CI counts agree.
    """
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "--collect-only",
            "-q",
            "--ignore=tests/test_rainier",
        ],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        timeout=120,
    )
    # The summary line looks like: "640 tests collected in 5.21s"
    m = re.search(r"(\d+)\s+tests?\s+collected", result.stdout)
    if not m:
        raise RuntimeError(f"Could not parse pytest --collect-only output:\n{result.stdout[-500:]}")
    return int(m.group(1))


def whitney_collected_count() -> int:
    """Tests inside tests/test_whitney/."""
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/test_whitney/", "--collect-only", "-q"],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        timeout=60,
    )
    m = re.search(r"(\d+)\s+tests?\s+collected", result.stdout)
    if not m:
        raise RuntimeError(
            f"Could not parse Whitney test collection:\n{result.stdout[-500:]}"
        )
    return int(m.group(1))


# ---------------------------------------------------------------------------
# Claim extractor — pull a numeric claim from a doc file
# ---------------------------------------------------------------------------


def extract_claim(doc_path: Path, regex: str) -> tuple[int, bool, int]:
    """Return (claimed_value, has_plus_suffix, line_number).

    The regex must contain exactly one capturing group around the number.
    Lines wrapped in `~~strikethrough~~` are skipped (historical / done-and-
    crossed-out items).
    """
    text = doc_path.read_text(encoding="utf-8")
    pat = re.compile(regex)
    for lineno, line in enumerate(text.splitlines(), start=1):
        if "~~" in line:
            # Strikethrough = historical / completed marker, skip
            continue
        m = pat.search(line)
        if m:
            num = int(m.group(1))
            has_plus = "+" in (m.group(0) or "")
            return num, has_plus, lineno
    raise AssertionError(
        f"Pattern {regex!r} not found in {doc_path}. Either the doc was rewritten "
        "or the regex needs updating."
    )


def assert_claim(
    doc_path: Path,
    regex: str,
    actual: int,
    *,
    description: str,
    tolerance: int = 0,
) -> None:
    """Assert a doc claim matches the actual code count.

    If the doc says "X+" the actual must be ≥ X.
    Otherwise actual must be within ±tolerance of X.
    """
    claimed, has_plus, lineno = extract_claim(doc_path, regex)
    rel = doc_path.relative_to(REPO_ROOT)

    if has_plus:
        assert actual >= claimed, (
            f"{rel}:{lineno} claims '{claimed}+' for {description}, but actual is {actual}. "
            f"Either fix the doc to '{actual}+' or restore the missing items."
        )
    else:
        assert abs(actual - claimed) <= tolerance, (
            f"{rel}:{lineno} claims {claimed} for {description}, but actual is {actual} "
            f"(tolerance ±{tolerance}). Update the doc to {actual}."
        )


# ---------------------------------------------------------------------------
# Tests — README.md
# ---------------------------------------------------------------------------


README = REPO_ROOT / "README.md"


def test_readme_total_check_count() -> None:
    """Top-of-file 'X Checks' headline must reflect total check_* function count."""
    # Matches '5 Domains, 138+ Checks' / 'Multi-Cloud Security Scanning (5 Domains, X+ Checks)'
    assert_claim(
        README,
        r"Multi-Cloud Security Scanning \(\d+ Domains, (\d+)\+? Checks\)",
        actual=shasta_check_count(),
        description="Shasta check_* function count (AWS + Azure)",
        tolerance=2,
    )


def test_readme_technical_controls_check_count() -> None:
    """The 'Technical cloud controls' table row must match total checks."""
    # Matches: '125+ automated checks across AWS and Azure'
    assert_claim(
        README,
        r"\| (\d+)\+? automated checks across AWS and Azure",
        actual=shasta_check_count(),
        description="Shasta automated checks (technical-controls table row)",
        tolerance=2,
    )


def test_readme_intro_total_check_count() -> None:
    """The intro paragraph 'N automated checks' free-text claim must match grand total.

    This catches the failure mode where the headline at line 25 is integrity-tested
    but the prose intro at line 5 drifts independently. The intro claim references
    Shasta + Whitney combined ('Together, they cover ...'), so it should match the
    grand total, not just the Shasta-only count.
    """
    text = README.read_text(encoding="utf-8")
    pattern = re.compile(r"(\d+)\s+automated checks(?!\s+across AWS and Azure)")
    for lineno, line in enumerate(text.splitlines(), start=1):
        if "~~" in line:
            continue
        if "Together, they cover" not in line:
            continue
        m = pattern.search(line)
        if m:
            claimed = int(m.group(1))
            actual = total_check_count()
            assert claimed == actual, (
                f"README.md:{lineno} 'Together, they cover ... {claimed} automated checks' "
                f"is stale. Actual grand total = {actual} ({shasta_check_count()} cloud "
                f"+ {whitney_check_count()} AI). Update the line to {actual}."
            )
            return
    raise AssertionError(
        "README intro 'Together, they cover ... N automated checks' line not found. "
        "Either the README was rewritten or this test needs updating."
    )


def test_readme_intro_terraform_template_count() -> None:
    """Same intro paragraph must also match the live Terraform template count."""
    text = README.read_text(encoding="utf-8")
    pattern = re.compile(r"(\d+)\s+Terraform remediation templates")
    for lineno, line in enumerate(text.splitlines(), start=1):
        if "~~" in line or "Together, they cover" not in line:
            continue
        m = pattern.search(line)
        if m:
            claimed = int(m.group(1))
            actual = total_terraform_template_count()
            assert claimed == actual, (
                f"README.md:{lineno} intro claims {claimed} Terraform templates, "
                f"actual is {actual}. Update the line to {actual}."
            )
            return
    # Optional — only fail if the line was supposed to mention TF templates
    # and doesn't anymore. Not an assertion for this iteration.


def test_readme_check_to_risk_mapping_count() -> None:
    """`FINDING_TO_RISK` table size must match the README claim."""
    assert_claim(
        README,
        r"\((\d+) check-to-risk mappings",
        actual=finding_to_risk_count(),
        description="FINDING_TO_RISK registry size",
        tolerance=0,
    )


def test_readme_test_count_in_tree_block() -> None:
    """The directory-tree 'pytest test suite (N+ tests)' annotation must reflect reality.

    Tolerance is loose because the test count grows on every commit; the
    purpose of this assertion is to catch order-of-magnitude drift, not
    enforce exactness.
    """
    assert_claim(
        README,
        r"pytest test suite \((\d+)\+? tests?\)",
        actual=pytest_collected_count(),
        description="pytest collected test count",
        tolerance=50,
    )


def test_readme_ai_check_count() -> None:
    """The 'X AI checks (code + cloud)' row must match Whitney's check_* count."""
    assert_claim(
        README,
        r"(\d+) AI checks \(code \+ cloud\)",
        actual=whitney_check_count(),
        description="Whitney check_* function count",
        tolerance=2,
    )


def test_readme_terraform_template_breakdown() -> None:
    """The remediation-row 'X Terraform templates (Y AWS + Z Azure)' must match registry."""
    text = README.read_text(encoding="utf-8")
    pattern = re.compile(
        r"(\d+)\s+Terraform templates?\s+\((\d+)\s+AWS\s*\+\s*(\d+)\s+Azure"
    )
    matches = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if "~~" in line:
            continue
        m = pattern.search(line)
        if m:
            matches.append((lineno, m))
    assert matches, "README has no live 'X Terraform templates (Y AWS + Z Azure)' claim"

    actual_total = total_terraform_template_count()
    actual_aws = aws_terraform_template_count()
    actual_az = azure_terraform_template_count()

    for lineno, m in matches:
        total, aws, az = (int(m.group(i)) for i in (1, 2, 3))
        assert (total, aws, az) == (actual_total, actual_aws, actual_az), (
            f"README.md:{lineno} claims {total} templates ({aws} AWS + {az} Azure) "
            f"but registry has {actual_total} ({actual_aws} AWS + {actual_az} Azure)."
        )


def test_readme_policy_template_count() -> None:
    """'X SOC 2 policy documents' must match POLICIES registry."""
    # Matches 'Generate 8 SOC 2 policy documents' / '8 generated policy documents'
    assert_claim(
        README,
        r"(\d+)\s+(?:generated\s+)?(?:SOC 2\s+)?policy documents",
        actual=policy_template_count(),
        description="POLICIES registry size",
        tolerance=0,
    )


# ---------------------------------------------------------------------------
# Tests — Whitney README.md and TRUST.md
# ---------------------------------------------------------------------------


WHITNEY_README = REPO_ROOT / "src" / "whitney" / "README.md"
WHITNEY_TRUST = REPO_ROOT / "src" / "whitney" / "TRUST.md"
ROOT_TRUST = REPO_ROOT / "TRUST.md"


def test_whitney_readme_test_count() -> None:
    """Whitney README's 'X tests' status line must match collected Whitney tests."""
    assert_claim(
        WHITNEY_README,
        r"\[x\]\s+(\d+)\s+tests?\b",
        actual=whitney_collected_count(),
        description="tests/test_whitney/ collected count",
        tolerance=10,
    )


def test_whitney_trust_unit_test_count() -> None:
    """Whitney TRUST.md 'Whitney unit tests: X' summary must match reality."""
    assert_claim(
        WHITNEY_TRUST,
        r"Whitney unit tests:\s+(\d+)",
        actual=whitney_collected_count(),
        description="Whitney unit-test collected count",
        tolerance=10,
    )


# ---------------------------------------------------------------------------
# Tests — root TRUST.md (project-wide trust story)
# ---------------------------------------------------------------------------


def test_root_trust_total_check_count() -> None:
    """Root TRUST.md TL;DR claim of '220 check functions (174 cloud + 46 AI)'."""
    text = ROOT_TRUST.read_text(encoding="utf-8")
    pattern = re.compile(
        r"\*\*(\d+)\s+check functions\*\*\s*\((\d+)\s+cloud compliance\s*\+\s*(\d+)\s+AI"
    )
    for lineno, line in enumerate(text.splitlines(), start=1):
        if "~~" in line:
            continue
        m = pattern.search(line)
        if m:
            total, shasta, whit = (int(m.group(i)) for i in (1, 2, 3))
            actual_shasta = shasta_check_count()
            actual_whit = whitney_check_count()
            actual_total = total_check_count()
            assert (total, shasta, whit) == (actual_total, actual_shasta, actual_whit), (
                f"TRUST.md:{lineno} claims {total} ({shasta} cloud + {whit} AI) "
                f"but registry has {actual_total} ({actual_shasta} + {actual_whit})."
            )
            return
    raise AssertionError("TRUST.md TL;DR check-function pattern not found")


def test_root_trust_terraform_template_count() -> None:
    """Root TRUST.md TL;DR claim of 'X Terraform remediation templates'."""
    assert_claim(
        ROOT_TRUST,
        r"\*\*(\d+)\s+Terraform remediation templates\*\*",
        actual=total_terraform_template_count(),
        description="root TRUST.md Terraform template count",
        tolerance=0,
    )


def test_root_trust_test_count() -> None:
    """Root TRUST.md TL;DR bullet of '- **N tests** that all pass'."""
    assert_claim(
        ROOT_TRUST,
        r"\*\*(\d+)\s+tests\*\*\s+that all pass",
        actual=pytest_collected_count(),
        description="root TRUST.md total test count",
        tolerance=50,
    )


def test_root_trust_layer1_test_breakdown() -> None:
    """Root TRUST.md Layer 1 table rows must match collected sub-suite counts."""
    text = ROOT_TRUST.read_text(encoding="utf-8")
    # Whitney row
    m = re.search(r"`tests/test_whitney/`\s*\|\s*(\d+)", text)
    assert m, "Whitney row not found in Layer 1 table"
    claimed = int(m.group(1))
    actual = whitney_collected_count()
    assert abs(claimed - actual) <= 10, (
        f"TRUST.md Layer 1 claims {claimed} Whitney tests but actual is {actual}. "
        f"Update the table cell to {actual}."
    )


def test_root_trust_integrity_test_count() -> None:
    """Root TRUST.md claim of '11 parametrized assertions' in integrity tests."""
    # Count tests/test_integrity collected
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/test_integrity/", "--collect-only", "-q"],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        timeout=60,
    )
    m = re.search(r"(\d+)\s+tests?\s+collected", result.stdout)
    actual = int(m.group(1)) if m else 0
    assert_claim(
        ROOT_TRUST,
        r"\*\*(\d+)\s+parametrized\s+assertions\*\*",
        actual=actual,
        description="root TRUST.md integrity test count",
        tolerance=2,
    )


# ---------------------------------------------------------------------------
# Self-test — make sure the helpers themselves are working
# ---------------------------------------------------------------------------


def test_counters_return_positive_numbers() -> None:
    """Sanity check that the AST counters and registry imports actually work."""
    assert shasta_check_count() > 0
    assert whitney_check_count() > 0
    assert finding_to_risk_count() > 0
    assert total_terraform_template_count() > 0
    assert policy_template_count() == 8


def test_pytest_collector_works() -> None:
    """The collected-test counter must return a sensible number."""
    n = pytest_collected_count()
    assert n > 100, f"Pytest only collected {n} tests — collector misconfigured?"
