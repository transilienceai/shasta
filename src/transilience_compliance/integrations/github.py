"""GitHub integration for SOC 2 change management (CC8.1).

Checks repository security settings that auditors care about:
  - Branch protection on main/default branch
  - Required PR reviews before merge
  - Required status checks (CI/CD)
  - Signed commits (optional but good)
  - No direct pushes to main
"""

from __future__ import annotations

import json
from typing import Any
from urllib import request, error

from transilience_compliance.evidence.models import CheckDomain, ComplianceStatus, Finding, Severity


class GitHubClient:
    """Minimal GitHub API client using urllib (no external dependency)."""

    API_BASE = "https://api.github.com"

    def __init__(self, token: str):
        self._token = token

    def _get(self, path: str) -> dict:
        req = request.Request(
            f"{self.API_BASE}{path}",
            headers={
                "Authorization": f"Bearer {self._token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        resp = request.urlopen(req, timeout=15)
        return json.loads(resp.read())


def run_github_checks(token: str, repos: list[str]) -> list[Finding]:
    """Run GitHub compliance checks on specified repositories.

    Args:
        token: GitHub personal access token
        repos: List of "owner/repo" strings
    """
    gh = GitHubClient(token)
    findings = []

    for repo_full_name in repos:
        findings.extend(_check_repo(gh, repo_full_name))

    return findings


def _check_repo(gh: GitHubClient, repo: str) -> list[Finding]:
    """Check a single repository's security settings."""
    findings = []

    try:
        repo_info = gh._get(f"/repos/{repo}")
    except error.URLError as e:
        return [
            Finding(
                check_id="github-repo-access",
                title=f"Cannot access repository '{repo}'",
                description=f"Failed to access {repo}: {e}. Check token permissions.",
                severity=Severity.MEDIUM,
                status=ComplianceStatus.NOT_ASSESSED,
                domain=CheckDomain.MONITORING,
                resource_type="GitHub::Repository",
                resource_id=repo,
                region="github.com",
                account_id="github",
                soc2_controls=["CC8.1"],
            )
        ]

    default_branch = repo_info.get("default_branch", "main")

    # Check branch protection
    try:
        protection = gh._get(f"/repos/{repo}/branches/{default_branch}/protection")
        findings.extend(_evaluate_branch_protection(repo, default_branch, protection))
    except error.HTTPError as e:
        if e.code == 404:
            findings.append(
                Finding(
                    check_id="github-branch-protection",
                    title=f"No branch protection on '{repo}' ({default_branch})",
                    description=f"Repository '{repo}' has no branch protection rules on the '{default_branch}' branch. Anyone with write access can push directly, bypassing code review.",
                    severity=Severity.HIGH,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.MONITORING,
                    resource_type="GitHub::Repository",
                    resource_id=repo,
                    region="github.com",
                    account_id="github",
                    remediation=f"Enable branch protection on '{default_branch}' in {repo}: require PR reviews, status checks, and prevent force pushes.",
                    soc2_controls=["CC8.1"],
                    details={"repo": repo, "branch": default_branch, "protection": None},
                )
            )
        else:
            raise

    return findings


def _evaluate_branch_protection(repo: str, branch: str, protection: dict) -> list[Finding]:
    """Evaluate branch protection settings."""
    findings = []

    # Required PR reviews
    pr_reviews = protection.get("required_pull_request_reviews")
    if pr_reviews:
        required_count = pr_reviews.get("required_approving_review_count", 0)
        if required_count >= 1:
            findings.append(
                Finding(
                    check_id="github-pr-reviews",
                    title=f"PR reviews required on '{repo}' ({required_count} reviewer(s))",
                    description=f"Repository '{repo}' requires {required_count} approving review(s) before merging to '{branch}'.",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.MONITORING,
                    resource_type="GitHub::Repository",
                    resource_id=repo,
                    region="github.com",
                    account_id="github",
                    soc2_controls=["CC8.1"],
                    details={"required_reviewers": required_count, "dismiss_stale": pr_reviews.get("dismiss_stale_reviews", False)},
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="github-pr-reviews",
                    title=f"PR reviews not effectively required on '{repo}'",
                    description=f"Repository '{repo}' has PR review settings but requires 0 approving reviews.",
                    severity=Severity.HIGH,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.MONITORING,
                    resource_type="GitHub::Repository",
                    resource_id=repo,
                    region="github.com",
                    account_id="github",
                    remediation=f"Set required approving reviews to at least 1 on '{branch}' in {repo}.",
                    soc2_controls=["CC8.1"],
                )
            )
    else:
        findings.append(
            Finding(
                check_id="github-pr-reviews",
                title=f"PR reviews NOT required on '{repo}'",
                description=f"Repository '{repo}' does not require pull request reviews before merging to '{branch}'. Changes can be merged without peer review, violating change management controls.",
                severity=Severity.HIGH,
                status=ComplianceStatus.FAIL,
                domain=CheckDomain.MONITORING,
                resource_type="GitHub::Repository",
                resource_id=repo,
                region="github.com",
                account_id="github",
                remediation=f"Enable required PR reviews (minimum 1 reviewer) on '{branch}' in {repo}.",
                soc2_controls=["CC8.1"],
            )
        )

    # Required status checks (CI/CD)
    status_checks = protection.get("required_status_checks")
    if status_checks and status_checks.get("contexts"):
        findings.append(
            Finding(
                check_id="github-status-checks",
                title=f"CI/CD status checks required on '{repo}'",
                description=f"Repository '{repo}' requires status checks ({', '.join(status_checks['contexts'])}) to pass before merging.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.MONITORING,
                resource_type="GitHub::Repository",
                resource_id=repo,
                region="github.com",
                account_id="github",
                soc2_controls=["CC8.1"],
                details={"required_checks": status_checks.get("contexts", [])},
            )
        )
    else:
        findings.append(
            Finding(
                check_id="github-status-checks",
                title=f"No CI/CD status checks required on '{repo}'",
                description=f"Repository '{repo}' does not require CI/CD checks to pass before merging. Code could be merged without tests running.",
                severity=Severity.MEDIUM,
                status=ComplianceStatus.FAIL,
                domain=CheckDomain.MONITORING,
                resource_type="GitHub::Repository",
                resource_id=repo,
                region="github.com",
                account_id="github",
                remediation=f"Add required status checks (test suite, linting) on '{branch}' in {repo}.",
                soc2_controls=["CC8.1"],
            )
        )

    # Enforce admins (no bypass)
    enforce_admins = protection.get("enforce_admins", {})
    if enforce_admins.get("enabled", False):
        findings.append(
            Finding(
                check_id="github-enforce-admins",
                title=f"Branch protection enforced for admins on '{repo}'",
                description=f"Repository '{repo}' enforces branch protection rules for administrators — no one can bypass.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.MONITORING,
                resource_type="GitHub::Repository",
                resource_id=repo,
                region="github.com",
                account_id="github",
                soc2_controls=["CC8.1"],
            )
        )

    # Allow force pushes (should be false)
    allow_force = protection.get("allow_force_pushes", {})
    if allow_force.get("enabled", False):
        findings.append(
            Finding(
                check_id="github-no-force-push",
                title=f"Force pushes allowed on '{repo}' ({branch})",
                description=f"Repository '{repo}' allows force pushes to '{branch}', which can rewrite history and destroy audit trail.",
                severity=Severity.HIGH,
                status=ComplianceStatus.FAIL,
                domain=CheckDomain.MONITORING,
                resource_type="GitHub::Repository",
                resource_id=repo,
                region="github.com",
                account_id="github",
                remediation=f"Disable force pushes on '{branch}' in {repo}.",
                soc2_controls=["CC8.1"],
            )
        )

    return findings
