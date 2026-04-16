"""Auditor-grade control testing framework.

Transforms Shasta's automated checks into structured "control tests" that
auditors expect to see. Each test has:
  - A formal test ID and procedure
  - Expected outcome
  - Actual evidence collected
  - Pass/fail determination
  - Remediation if failed
  - SOC 2 control mapping

This is the bridge between "security scanner" and "compliance platform."
An auditor reviewing these tests should be able to form an opinion on each
control without touching the cloud console.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from shasta.evidence.models import CloudProvider, ComplianceStatus, Finding, ScanResult


@dataclass
class ControlTest:
    """A single auditor-grade control test."""

    test_id: str  # e.g., "CT-IAM-001"
    title: str
    soc2_controls: list[str]
    category: str  # "Access Control", "Network Security", etc.
    objective: str  # What this test verifies
    procedure: str  # How the test was performed
    expected_result: str  # What a compliant state looks like
    actual_result: str  # What was actually found
    status: str  # "pass", "fail", "partial", "not_tested"
    evidence: list[dict] = field(default_factory=list)  # Evidence artifacts
    findings: list[Finding] = field(default_factory=list)  # Raw findings
    remediation: str = ""
    tested_at: str = ""
    tested_by: str = "Shasta Automated Testing"


@dataclass
class ControlTestSuite:
    """A complete set of control tests for an audit period."""

    suite_id: str
    account_id: str
    test_period: str  # e.g., "2026-Q1"
    tested_at: str
    total_tests: int = 0
    passed: int = 0
    failed: int = 0
    partial: int = 0
    not_tested: int = 0
    tests: list[ControlTest] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Test definitions — each maps findings to a formal control test
# ---------------------------------------------------------------------------

TEST_DEFINITIONS: list[dict[str, Any]] = [
    # --- CC6.1: Logical Access Security ---
    {
        "test_id": "CT-IAM-001",
        "title": "Account Password Policy Meets Minimum Standards",
        "soc2_controls": ["CC6.1"],
        "category": "Access Control",
        "objective": "Verify that the account password policy enforces strong passwords per organizational standards.",
        "procedure": "Query the IAM account password policy via API. Evaluate minimum length (>=14), complexity requirements (upper, lower, number, symbol), expiration (<=90 days), and reuse prevention (>=12).",
        "expected_result": "Password policy exists with: minimum 14 characters, all four complexity types required, 90-day expiration, and 12-password reuse prevention.",
        "check_ids": ["iam-password-policy"],
    },
    {
        "test_id": "CT-IAM-002",
        "title": "Root Account MFA Enabled",
        "soc2_controls": ["CC6.1"],
        "category": "Access Control",
        "objective": "Verify that the root account has multi-factor authentication enabled.",
        "procedure": "Query IAM account summary for AccountMFAEnabled flag. Check credential report for root account access key status.",
        "expected_result": "Root account MFA is enabled. Root account has no active access keys.",
        "check_ids": ["iam-root-mfa", "iam-root-access-keys"],
    },
    {
        "test_id": "CT-IAM-003",
        "title": "All Console Users Have MFA Enabled",
        "soc2_controls": ["CC6.1"],
        "category": "Access Control",
        "objective": "Verify that all IAM users with console (password) access have MFA devices assigned.",
        "procedure": "Enumerate all IAM users. For each user with a login profile (console access), verify that at least one MFA device is assigned.",
        "expected_result": "100% of users with console access have MFA enabled.",
        "check_ids": ["iam-user-mfa"],
    },
    # --- CC6.2: Access Provisioning ---
    {
        "test_id": "CT-IAM-004",
        "title": "No Users Have Direct Policy Attachments",
        "soc2_controls": ["CC6.2"],
        "category": "Access Control",
        "objective": "Verify that IAM permissions are managed through groups or roles, not attached directly to users.",
        "procedure": "Enumerate all IAM users. For each, check for directly attached managed policies and inline policies.",
        "expected_result": "No IAM users have policies attached directly. All permissions are inherited through groups or roles.",
        "check_ids": ["iam-no-direct-policies"],
    },
    {
        "test_id": "CT-IAM-005",
        "title": "No Users Have Overly Broad Permissions",
        "soc2_controls": ["CC6.2"],
        "category": "Access Control",
        "objective": "Verify that no IAM users have administrative-level permissions (AdministratorAccess, IAMFullAccess, PowerUserAccess) unless documented and justified.",
        "procedure": "Enumerate all IAM users. Check directly attached and group-inherited policies for admin-level managed policies.",
        "expected_result": "No users have admin-level policies, or all such access is documented with business justification.",
        "check_ids": ["iam-overprivileged-user"],
    },
    # --- CC6.3: Access Removal ---
    {
        "test_id": "CT-IAM-006",
        "title": "Access Keys Are Rotated Within Policy",
        "soc2_controls": ["CC6.3"],
        "category": "Access Control",
        "objective": "Verify that all active IAM access keys are younger than 90 days.",
        "procedure": "Enumerate all IAM users and their access keys. Calculate the age of each active key.",
        "expected_result": "All active access keys are less than 90 days old.",
        "check_ids": ["iam-access-key-rotation"],
    },
    {
        "test_id": "CT-IAM-007",
        "title": "No Inactive User Accounts",
        "soc2_controls": ["CC6.3"],
        "category": "Access Control",
        "objective": "Verify that no IAM user accounts have been inactive for more than 90 days.",
        "procedure": "Generate IAM credential report. Check last console login and access key usage dates for all users.",
        "expected_result": "All user accounts show activity within the last 90 days, or inactive accounts have been flagged for removal.",
        "check_ids": ["iam-inactive-user"],
    },
    # --- CC6.6: System Boundaries ---
    {
        "test_id": "CT-NET-001",
        "title": "No Security Groups Allow Unrestricted Ingress",
        "soc2_controls": ["CC6.6"],
        "category": "Network Security",
        "objective": "Verify that no security groups allow inbound traffic from 0.0.0.0/0 or ::/0 on sensitive ports (SSH, RDP, databases).",
        "procedure": "Enumerate all security groups across all VPCs. Check each ingress rule for unrestricted CIDR blocks.",
        "expected_result": "No security groups allow unrestricted inbound access on management or database ports. Only public-facing load balancers may allow 0.0.0.0/0 on ports 80/443.",
        "check_ids": ["sg-no-unrestricted-ingress"],
    },
    {
        "test_id": "CT-NET-002",
        "title": "VPC Flow Logs Enabled on All VPCs",
        "soc2_controls": ["CC6.6"],
        "category": "Network Security",
        "objective": "Verify that VPC flow logs are enabled on all VPCs for network traffic monitoring.",
        "procedure": "Enumerate all VPCs and flow log configurations. Verify each VPC has at least one active flow log.",
        "expected_result": "All VPCs have flow logs enabled capturing ALL traffic with minimum 90-day retention.",
        "check_ids": ["vpc-flow-logs-enabled"],
    },
    # --- CC6.7: Data Protection ---
    {
        "test_id": "CT-DATA-001",
        "title": "All S3 Buckets Have Encryption at Rest",
        "soc2_controls": ["CC6.7"],
        "category": "Data Protection",
        "objective": "Verify that all S3 buckets have server-side encryption configured.",
        "procedure": "Enumerate all S3 buckets. Check each bucket's default encryption configuration.",
        "expected_result": "All S3 buckets have SSE-KMS or SSE-S3 encryption enabled by default.",
        "check_ids": ["s3-encryption-at-rest"],
    },
    {
        "test_id": "CT-DATA-002",
        "title": "All S3 Buckets Enforce SSL-Only Access",
        "soc2_controls": ["CC6.7"],
        "category": "Data Protection",
        "objective": "Verify that all S3 buckets have a policy denying non-SSL requests.",
        "procedure": "Enumerate all S3 buckets. Check each bucket's policy for a Deny statement on aws:SecureTransport=false.",
        "expected_result": "All S3 buckets enforce SSL-only access via bucket policy.",
        "check_ids": ["s3-ssl-only"],
    },
    {
        "test_id": "CT-DATA-003",
        "title": "All S3 Buckets Block Public Access",
        "soc2_controls": ["CC6.7"],
        "category": "Data Protection",
        "objective": "Verify that all S3 buckets have the public access block enabled (all four settings).",
        "procedure": "Enumerate all S3 buckets. Check each bucket's public access block configuration.",
        "expected_result": "All S3 buckets have BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, and RestrictPublicBuckets set to true.",
        "check_ids": ["s3-public-access-block"],
    },
    {
        "test_id": "CT-DATA-004",
        "title": "All S3 Buckets Have Versioning Enabled",
        "soc2_controls": ["CC6.7"],
        "category": "Data Protection",
        "objective": "Verify that all S3 buckets have versioning enabled for data integrity and recovery.",
        "procedure": "Enumerate all S3 buckets. Check each bucket's versioning status.",
        "expected_result": "All S3 buckets have versioning enabled.",
        "check_ids": ["s3-versioning"],
    },
    # --- CC7.1: Detection and Monitoring ---
    {
        "test_id": "CT-MON-001",
        "title": "CloudTrail Is Enabled and Properly Configured",
        "soc2_controls": ["CC7.1", "CC8.1"],
        "category": "Monitoring",
        "objective": "Verify that CloudTrail is enabled with multi-region logging, log file validation, and global service events.",
        "procedure": "Query CloudTrail trails. Verify multi-region, log validation, logging status, and global events.",
        "expected_result": "At least one trail is multi-region, actively logging, with log file validation enabled and global service events included.",
        "check_ids": ["cloudtrail-enabled"],
    },
    {
        "test_id": "CT-MON-002",
        "title": "GuardDuty Is Enabled and Active",
        "soc2_controls": ["CC7.1", "CC7.2"],
        "category": "Monitoring",
        "objective": "Verify that Amazon GuardDuty is enabled for continuous threat detection.",
        "procedure": "Query GuardDuty detectors. Verify at least one is enabled and actively monitoring.",
        "expected_result": "GuardDuty is enabled with status ENABLED. Any active findings have been reviewed.",
        "check_ids": ["guardduty-enabled", "guardduty-no-active-findings"],
    },
    {
        "test_id": "CT-MON-003",
        "title": "Resource Configuration Recording Is Active",
        "soc2_controls": ["CC7.1", "CC8.1"],
        "category": "Monitoring",
        "objective": "Verify that resource configuration recording is enabled and capturing all supported resource types including global resources.",
        "procedure": "Query Config recorders and their status. Verify recording is active with all-supported and global resource types.",
        "expected_result": "Resource configuration recorder is active, recording all supported resource types including global resources.",
        "check_ids": ["config-enabled"],
    },
    # --- CC7.1: Vulnerability Management ---
    {
        "test_id": "CT-VULN-001",
        "title": "Vulnerability Scanning Is Enabled",
        "soc2_controls": ["CC7.1"],
        "category": "Vulnerability Management",
        "objective": "Verify that vulnerability scanning is enabled for continuous scanning of compute resources, functions, and container images.",
        "procedure": "Query Inspector status. Verify scanning is active and check for critical/high findings.",
        "expected_result": "Vulnerability scanning is enabled. No critical or high severity unresolved vulnerabilities exist.",
        "check_ids": ["inspector-enabled"],
    },
]


def generate_control_tests(scan: ScanResult) -> ControlTestSuite:
    """Generate auditor-grade control tests from scan findings."""
    now = datetime.now(timezone.utc)
    findings_by_check = _index_findings(scan.findings)

    tests = []
    for defn in TEST_DEFINITIONS:
        test = _evaluate_test(defn, findings_by_check, now)
        tests.append(test)

    suite = ControlTestSuite(
        suite_id=f"CTS-{scan.account_id}-{now.strftime('%Y%m%d')}",
        account_id=scan.account_id,
        test_period=f"{now.year}-Q{(now.month - 1) // 3 + 1}",
        tested_at=now.isoformat(),
        total_tests=len(tests),
        passed=sum(1 for t in tests if t.status == "pass"),
        failed=sum(1 for t in tests if t.status == "fail"),
        partial=sum(1 for t in tests if t.status == "partial"),
        not_tested=sum(1 for t in tests if t.status == "not_tested"),
        tests=tests,
    )

    return suite


def _index_findings(findings: list[Finding]) -> dict[str, list[Finding]]:
    """Index findings by check_id for quick lookup."""
    index: dict[str, list[Finding]] = {}
    for f in findings:
        index.setdefault(f.check_id, []).append(f)
    return index


def _evaluate_test(defn: dict, findings_by_check: dict, now: datetime) -> ControlTest:
    """Evaluate a test definition against collected findings."""
    check_ids = defn["check_ids"]
    related_findings = []
    for cid in check_ids:
        related_findings.extend(findings_by_check.get(cid, []))

    if not related_findings:
        return ControlTest(
            test_id=defn["test_id"],
            title=defn["title"],
            soc2_controls=defn["soc2_controls"],
            category=defn["category"],
            objective=defn["objective"],
            procedure=defn["procedure"],
            expected_result=defn["expected_result"],
            actual_result="No data collected. The relevant checks did not produce findings — this may indicate the service is not in use or the check was not executed.",
            status="not_tested",
            tested_at=now.isoformat(),
        )

    # Determine overall status
    failed = [f for f in related_findings if f.status == ComplianceStatus.FAIL]
    partial = [f for f in related_findings if f.status == ComplianceStatus.PARTIAL]
    passed = [f for f in related_findings if f.status == ComplianceStatus.PASS]

    if failed:
        status = "fail"
    elif partial:
        status = "partial"
    elif passed:
        status = "pass"
    else:
        status = "not_tested"

    # Build actual result narrative
    actual_parts = []
    if passed:
        actual_parts.append(f"{len(passed)} resource(s) compliant")
    if failed:
        actual_parts.append(f"{len(failed)} resource(s) non-compliant")
    if partial:
        actual_parts.append(f"{len(partial)} resource(s) partially compliant")

    actual_result = f"Tested {len(related_findings)} resource(s): {', '.join(actual_parts)}."
    if failed:
        actual_result += " Non-compliant resources: " + "; ".join(
            f"{f.resource_id} — {f.description}" for f in failed
        )

    # Build evidence list
    evidence = [
        {
            "resource": f.resource_id,
            "status": f.status.value,
            "description": f.description,
            "severity": f.severity.value,
            "timestamp": f.timestamp.isoformat()
            if isinstance(f.timestamp, datetime)
            else str(f.timestamp),
        }
        for f in related_findings
    ]

    # Build remediation
    remediation = ""
    if failed:
        remediation = " | ".join(f.remediation for f in failed if f.remediation)

    return ControlTest(
        test_id=defn["test_id"],
        title=defn["title"],
        soc2_controls=defn["soc2_controls"],
        category=defn["category"],
        objective=defn["objective"],
        procedure=defn["procedure"],
        expected_result=defn["expected_result"],
        actual_result=actual_result,
        status=status,
        evidence=evidence,
        findings=related_findings,
        remediation=remediation,
        tested_at=now.isoformat(),
    )


def save_control_test_report(
    suite: ControlTestSuite,
    output_path: Path | str = "data/reports",
    cloud_provider: CloudProvider = CloudProvider.AWS,
) -> Path:
    """Save the control test suite as a formal Markdown report for auditors."""
    from shasta.reports.generator import _provider_labels

    labels = _provider_labels(cloud_provider)
    output_dir = Path(output_path)
    output_dir.mkdir(parents=True, exist_ok=True)
    filepath = output_dir / f"control-tests-{suite.account_id}-{suite.test_period}.md"

    lines = [
        "# SOC 2 Control Test Report",
        "",
        f"**Suite ID:** {suite.suite_id}",
        f"**{labels['account_label']}:** {suite.account_id}",
        f"**Test Period:** {suite.test_period}",
        f"**Tested At:** {suite.tested_at}",
        f"**Tested By:** Shasta Automated Compliance Testing",
        "",
        "## Summary",
        "",
        f"| Result | Count |",
        f"|--------|-------|",
        f"| Total Tests | {suite.total_tests} |",
        f"| Passed | {suite.passed} |",
        f"| Failed | {suite.failed} |",
        f"| Partial | {suite.partial} |",
        f"| Not Tested | {suite.not_tested} |",
        "",
        "## Test Results Overview",
        "",
        "| ID | Title | Controls | Status |",
        "|-----|-------|----------|--------|",
    ]

    status_icons = {"pass": "PASS", "fail": "FAIL", "partial": "PARTIAL", "not_tested": "N/T"}
    for t in suite.tests:
        lines.append(
            f"| {t.test_id} | {t.title} | {', '.join(t.soc2_controls)} | {status_icons.get(t.status, t.status)} |"
        )

    lines.extend(["", "---", ""])

    # Detailed test results
    lines.append("## Detailed Test Results")
    lines.append("")

    for t in suite.tests:
        lines.extend(
            [
                f"### {t.test_id}: {t.title}",
                "",
                f"**SOC 2 Controls:** {', '.join(t.soc2_controls)}",
                f"**Category:** {t.category}",
                f"**Status:** {status_icons.get(t.status, t.status)}",
                "",
                f"**Objective:** {t.objective}",
                "",
                f"**Test Procedure:** {t.procedure}",
                "",
                f"**Expected Result:** {t.expected_result}",
                "",
                f"**Actual Result:** {t.actual_result}",
                "",
            ]
        )

        if t.remediation:
            lines.append(f"**Remediation:** {t.remediation}")
            lines.append("")

        if t.evidence:
            lines.append("**Evidence:**")
            lines.append("")
            lines.append("| Resource | Status | Severity | Description |")
            lines.append("|----------|--------|----------|-------------|")
            for e in t.evidence:
                desc = (
                    e["description"][:80] + "..."
                    if len(e["description"]) > 80
                    else e["description"]
                )
                lines.append(
                    f"| `{e['resource'][-50:]}` | {e['status']} | {e['severity']} | {desc} |"
                )
            lines.append("")

        lines.extend(["---", ""])

    lines.extend(
        [
            "## Auditor Notes",
            "",
            "| Field | Value |",
            "|-------|-------|",
            "| Reviewed by | ___________________ |",
            "| Review date | ___________________ |",
            "| Opinion | ___________________ |",
            "",
            "*This report was generated by Shasta Automated Compliance Testing. All tests were performed programmatically against the live cloud environment. Evidence artifacts are available in the evidence store for detailed review.*",
        ]
    )

    filepath.write_text("\n".join(lines), encoding="utf-8")
    return filepath
