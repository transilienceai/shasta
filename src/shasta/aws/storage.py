"""Storage security checks for SOC 2 compliance.

Covers:
  CC6.7 — Data protection in transit and at rest (S3 encryption, versioning, public access, SSL)
"""

from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from shasta.aws.client import AWSClient
from shasta.evidence.models import CheckDomain, ComplianceStatus, Finding, Severity


def run_all_storage_checks(client: AWSClient) -> list[Finding]:
    """Run all storage compliance checks."""
    findings: list[Finding] = []
    account_id = client.account_info.account_id if client.account_info else "unknown"
    region = client.account_info.region if client.account_info else "us-east-1"

    s3 = client.client("s3")

    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except ClientError:
        return []

    for bucket in buckets:
        bucket_name = bucket["Name"]
        findings.extend(check_s3_encryption(s3, bucket_name, account_id, region))
        findings.extend(check_s3_versioning(s3, bucket_name, account_id, region))
        findings.extend(check_s3_public_access_block(s3, bucket_name, account_id, region))
        findings.extend(check_s3_ssl_only(s3, bucket_name, account_id, region))
        findings.extend(check_s3_object_ownership_enforced(s3, bucket_name, account_id, region))
        findings.extend(check_s3_access_logging(s3, bucket_name, account_id, region))
        findings.extend(check_s3_kms_cmk_encryption(s3, bucket_name, account_id, region))

    return findings


# ---------------------------------------------------------------------------
# CIS AWS v3.0 Stage 2 — S3 Object Ownership / Access Logging / KMS CMK
# ---------------------------------------------------------------------------


def check_s3_object_ownership_enforced(
    s3: Any, bucket_name: str, account_id: str, region: str
) -> list[Finding]:
    """[CIS AWS 2.x] S3 Object Ownership should be set to BucketOwnerEnforced.

    BucketOwnerEnforced disables ACLs entirely. Without it, objects uploaded
    by other accounts can have ACLs that exclude the bucket owner — making
    auditing and lifecycle management harder.
    """
    try:
        resp = s3.get_bucket_ownership_controls(Bucket=bucket_name)
        rules = resp.get("OwnershipControls", {}).get("Rules", [])
        ownership = rules[0].get("ObjectOwnership", "ObjectWriter") if rules else "ObjectWriter"
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code == "OwnershipControlsNotFoundError":
            ownership = "ObjectWriter"  # Legacy default
        else:
            return []

    if ownership == "BucketOwnerEnforced":
        return [
            Finding(
                check_id="s3-object-ownership",
                title=f"S3 bucket '{bucket_name}' has ACLs disabled (BucketOwnerEnforced)",
                description="Object Ownership = BucketOwnerEnforced; ACLs are disabled and the bucket owner owns every object.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.STORAGE,
                resource_type="AWS::S3::Bucket",
                resource_id=f"arn:aws:s3:::{bucket_name}",
                region=region,
                account_id=account_id,
                soc2_controls=["CC6.1", "CC6.7"],
                cis_aws_controls=["2.x"],
            )
        ]
    return [
        Finding(
            check_id="s3-object-ownership",
            title=f"S3 bucket '{bucket_name}' allows ACLs (Object Ownership = {ownership})",
            description=(
                f"Object Ownership is {ownership}. Per-object ACLs are still allowed. The "
                "modern AWS recommendation is BucketOwnerEnforced — it disables ACLs entirely "
                "and forces all access control through bucket policies and IAM, which are "
                "easier to audit."
            ),
            severity=Severity.LOW,
            status=ComplianceStatus.PARTIAL,
            domain=CheckDomain.STORAGE,
            resource_type="AWS::S3::Bucket",
            resource_id=f"arn:aws:s3:::{bucket_name}",
            region=region,
            account_id=account_id,
            remediation=(
                f"aws s3api put-bucket-ownership-controls --bucket {bucket_name} "
                "--ownership-controls Rules=[{ObjectOwnership=BucketOwnerEnforced}]"
            ),
            soc2_controls=["CC6.1", "CC6.7"],
            cis_aws_controls=["2.x"],
        )
    ]


def check_s3_access_logging(
    s3: Any, bucket_name: str, account_id: str, region: str
) -> list[Finding]:
    """[CIS AWS 2.x] S3 buckets should have server access logging enabled.

    Mirrors check_elb_access_logs. Without S3 access logs, you can't
    reconstruct who accessed which objects during an incident — no source
    IPs, no requester ARNs, no operation history beyond CloudTrail data
    events (which most accounts don't enable for cost reasons).
    """
    try:
        resp = s3.get_bucket_logging(Bucket=bucket_name)
        logging_enabled = resp.get("LoggingEnabled")
    except ClientError:
        return []

    if logging_enabled and logging_enabled.get("TargetBucket"):
        target = logging_enabled.get("TargetBucket")
        return [
            Finding(
                check_id="s3-access-logging",
                title=f"S3 bucket '{bucket_name}' has access logging enabled",
                description=f"Access logs delivered to s3://{target}/{logging_enabled.get('TargetPrefix', '')}",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.LOGGING,
                resource_type="AWS::S3::Bucket",
                resource_id=f"arn:aws:s3:::{bucket_name}",
                region=region,
                account_id=account_id,
                soc2_controls=["CC7.1"],
                cis_aws_controls=["2.x"],
            )
        ]
    return [
        Finding(
            check_id="s3-access-logging",
            title=f"S3 bucket '{bucket_name}' has no server access logging",
            description=(
                "Without access logs, you can't reconstruct who accessed objects in this "
                "bucket during a security incident. CloudTrail data events are the alternative "
                "but cost ~10x more for the same coverage."
            ),
            severity=Severity.LOW,
            status=ComplianceStatus.PARTIAL,
            domain=CheckDomain.LOGGING,
            resource_type="AWS::S3::Bucket",
            resource_id=f"arn:aws:s3:::{bucket_name}",
            region=region,
            account_id=account_id,
            remediation=(
                "Create a dedicated log destination bucket with Object Lock + lifecycle rules, "
                f"then aws s3api put-bucket-logging --bucket {bucket_name} --bucket-logging-status "
                "'{\"LoggingEnabled\":{\"TargetBucket\":\"<log-bucket>\",\"TargetPrefix\":"
                f"\"{bucket_name}/\"}}'"
            ),
            soc2_controls=["CC7.1"],
            cis_aws_controls=["2.x"],
        )
    ]


def check_s3_kms_cmk_encryption(
    s3: Any, bucket_name: str, account_id: str, region: str
) -> list[Finding]:
    """[CIS AWS 2.x] S3 buckets holding compliance-relevant data should use KMS-CMK encryption.

    The existing check_s3_encryption accepts SSE-S3 (AES-256 with the
    AWS-owned key). This stricter check requires SSE-KMS with a customer-
    managed KMS key, which gives key-level audit and the ability to revoke
    decrypt access independently of the bucket policy.
    """
    try:
        enc = s3.get_bucket_encryption(Bucket=bucket_name)
        rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
        if not rules:
            return [
                Finding(
                    check_id="s3-kms-cmk",
                    title=f"S3 bucket '{bucket_name}' has no encryption configured",
                    description="No SSE configuration at all — covered separately by check_s3_encryption.",
                    severity=Severity.HIGH,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.ENCRYPTION,
                    resource_type="AWS::S3::Bucket",
                    resource_id=f"arn:aws:s3:::{bucket_name}",
                    region=region,
                    account_id=account_id,
                    soc2_controls=["CC6.7"],
                    cis_aws_controls=["2.x"],
                )
            ]
        first_rule = rules[0]
        sse_default = first_rule.get("ApplyServerSideEncryptionByDefault", {})
        algo = sse_default.get("SSEAlgorithm", "")
        kms_key = sse_default.get("KMSMasterKeyID", "")
    except ClientError:
        return []

    if algo == "aws:kms" and kms_key and "alias/aws/s3" not in kms_key:
        return [
            Finding(
                check_id="s3-kms-cmk",
                title=f"S3 bucket '{bucket_name}' uses customer-managed KMS",
                description=f"SSE-KMS with key {kms_key}.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.ENCRYPTION,
                resource_type="AWS::S3::Bucket",
                resource_id=f"arn:aws:s3:::{bucket_name}",
                region=region,
                account_id=account_id,
                soc2_controls=["CC6.7"],
                cis_aws_controls=["2.x"],
            )
        ]
    return [
        Finding(
            check_id="s3-kms-cmk",
            title=f"S3 bucket '{bucket_name}' uses AWS-managed encryption only ({algo or 'AES-256'})",
            description=(
                f"Bucket has {algo or 'AES-256'} encryption with no customer-managed KMS key. "
                "Compliance frameworks (SOC 2, PCI, HIPAA) increasingly require customer-"
                "managed keys so the customer can audit decrypt calls and revoke access "
                "independently of the bucket policy."
            ),
            severity=Severity.LOW,
            status=ComplianceStatus.PARTIAL,
            domain=CheckDomain.ENCRYPTION,
            resource_type="AWS::S3::Bucket",
            resource_id=f"arn:aws:s3:::{bucket_name}",
            region=region,
            account_id=account_id,
            remediation=(
                "Create a customer-managed KMS key with rotation enabled, then "
                f"aws s3api put-bucket-encryption --bucket {bucket_name} "
                "--server-side-encryption-configuration "
                "'{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":"
                "{\"SSEAlgorithm\":\"aws:kms\",\"KMSMasterKeyID\":\"<key-arn>\"}}]}'"
            ),
            soc2_controls=["CC6.7"],
            cis_aws_controls=["2.x"],
        )
    ]


def check_s3_encryption(s3: Any, bucket_name: str, account_id: str, region: str) -> list[Finding]:
    """CC6.7 — Check that S3 bucket has server-side encryption configured."""
    try:
        enc = s3.get_bucket_encryption(Bucket=bucket_name)
        rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])

        if rules:
            algo = (
                rules[0]
                .get("ApplyServerSideEncryptionByDefault", {})
                .get("SSEAlgorithm", "unknown")
            )
            algo_display = "KMS" if "kms" in algo.lower() else "AES-256" if "AES" in algo else algo

            return [
                Finding(
                    check_id="s3-encryption-at-rest",
                    title=f"S3 bucket '{bucket_name}' has encryption enabled ({algo_display})",
                    description=f"Bucket '{bucket_name}' has server-side encryption configured using {algo_display}.",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.STORAGE,
                    resource_type="AWS::S3::Bucket",
                    resource_id=f"arn:aws:s3:::{bucket_name}",
                    region=region,
                    account_id=account_id,
                    soc2_controls=["CC6.7"],
                    details={"bucket": bucket_name, "algorithm": algo, "rules": str(rules)},
                )
            ]
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code == "ServerSideEncryptionConfigurationNotFoundError":
            return [
                Finding(
                    check_id="s3-encryption-at-rest",
                    title=f"S3 bucket '{bucket_name}' has NO encryption configured",
                    description=f"Bucket '{bucket_name}' does not have server-side encryption enabled. Data at rest is not protected, violating SOC 2 data protection requirements.",
                    severity=Severity.HIGH,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.STORAGE,
                    resource_type="AWS::S3::Bucket",
                    resource_id=f"arn:aws:s3:::{bucket_name}",
                    region=region,
                    account_id=account_id,
                    remediation=f"Enable server-side encryption on bucket '{bucket_name}'. Use SSE-KMS for stronger key management or SSE-S3 (AES-256) as minimum.",
                    soc2_controls=["CC6.7"],
                    details={"bucket": bucket_name, "encryption": None},
                )
            ]

    return []


def check_s3_versioning(s3: Any, bucket_name: str, account_id: str, region: str) -> list[Finding]:
    """CC6.7 — Check that S3 bucket has versioning enabled for data integrity."""
    try:
        versioning = s3.get_bucket_versioning(Bucket=bucket_name)
        status = versioning.get("Status", "Disabled")

        if status == "Enabled":
            return [
                Finding(
                    check_id="s3-versioning",
                    title=f"S3 bucket '{bucket_name}' has versioning enabled",
                    description=f"Bucket '{bucket_name}' has versioning enabled, protecting against accidental deletion or overwrite.",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.STORAGE,
                    resource_type="AWS::S3::Bucket",
                    resource_id=f"arn:aws:s3:::{bucket_name}",
                    region=region,
                    account_id=account_id,
                    soc2_controls=["CC6.7"],
                    details={"bucket": bucket_name, "versioning": status},
                )
            ]
        else:
            return [
                Finding(
                    check_id="s3-versioning",
                    title=f"S3 bucket '{bucket_name}' does NOT have versioning enabled",
                    description=f"Bucket '{bucket_name}' does not have versioning enabled (status: {status}). Without versioning, deleted or overwritten objects cannot be recovered.",
                    severity=Severity.MEDIUM,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.STORAGE,
                    resource_type="AWS::S3::Bucket",
                    resource_id=f"arn:aws:s3:::{bucket_name}",
                    region=region,
                    account_id=account_id,
                    remediation=f"Enable versioning on bucket '{bucket_name}' to protect against accidental data loss.",
                    soc2_controls=["CC6.7"],
                    details={"bucket": bucket_name, "versioning": status},
                )
            ]
    except ClientError:
        return []


def check_s3_public_access_block(
    s3: Any, bucket_name: str, account_id: str, region: str
) -> list[Finding]:
    """CC6.7 — Check that S3 bucket has public access blocked."""
    try:
        pab = s3.get_public_access_block(Bucket=bucket_name)["PublicAccessBlockConfiguration"]

        all_blocked = (
            pab.get("BlockPublicAcls", False)
            and pab.get("IgnorePublicAcls", False)
            and pab.get("BlockPublicPolicy", False)
            and pab.get("RestrictPublicBuckets", False)
        )

        if all_blocked:
            return [
                Finding(
                    check_id="s3-public-access-block",
                    title=f"S3 bucket '{bucket_name}' blocks all public access",
                    description=f"Bucket '{bucket_name}' has all four public access block settings enabled.",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.STORAGE,
                    resource_type="AWS::S3::Bucket",
                    resource_id=f"arn:aws:s3:::{bucket_name}",
                    region=region,
                    account_id=account_id,
                    soc2_controls=["CC6.7"],
                    details={"bucket": bucket_name, "public_access_block": pab},
                )
            ]
        else:
            missing = []
            if not pab.get("BlockPublicAcls"):
                missing.append("BlockPublicAcls")
            if not pab.get("IgnorePublicAcls"):
                missing.append("IgnorePublicAcls")
            if not pab.get("BlockPublicPolicy"):
                missing.append("BlockPublicPolicy")
            if not pab.get("RestrictPublicBuckets"):
                missing.append("RestrictPublicBuckets")

            return [
                Finding(
                    check_id="s3-public-access-block",
                    title=f"S3 bucket '{bucket_name}' has incomplete public access blocking",
                    description=f"Bucket '{bucket_name}' is missing public access block settings: {', '.join(missing)}. This could allow public access to objects.",
                    severity=Severity.HIGH,
                    status=ComplianceStatus.PARTIAL,
                    domain=CheckDomain.STORAGE,
                    resource_type="AWS::S3::Bucket",
                    resource_id=f"arn:aws:s3:::{bucket_name}",
                    region=region,
                    account_id=account_id,
                    remediation=f"Enable all four public access block settings on bucket '{bucket_name}'.",
                    soc2_controls=["CC6.7"],
                    details={"bucket": bucket_name, "public_access_block": pab, "missing": missing},
                )
            ]

    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code == "NoSuchPublicAccessBlockConfiguration":
            return [
                Finding(
                    check_id="s3-public-access-block",
                    title=f"S3 bucket '{bucket_name}' has NO public access block",
                    description=f"Bucket '{bucket_name}' has no public access block configuration. Without this, the bucket or its objects could potentially be made public.",
                    severity=Severity.HIGH,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.STORAGE,
                    resource_type="AWS::S3::Bucket",
                    resource_id=f"arn:aws:s3:::{bucket_name}",
                    region=region,
                    account_id=account_id,
                    remediation=f"Enable public access block on bucket '{bucket_name}' with all four settings set to true.",
                    soc2_controls=["CC6.7"],
                    details={"bucket": bucket_name, "public_access_block": None},
                )
            ]
        return []


def check_s3_ssl_only(s3: Any, bucket_name: str, account_id: str, region: str) -> list[Finding]:
    """CC6.7 — Check that S3 bucket enforces SSL/TLS for data in transit."""
    try:
        policy_str = s3.get_bucket_policy(Bucket=bucket_name)["Policy"]
        import json

        policy = json.loads(policy_str)

        # Look for a deny statement on aws:SecureTransport = false
        has_ssl_enforcement = False
        for statement in policy.get("Statement", []):
            if statement.get("Effect") == "Deny":
                condition = statement.get("Condition", {})
                bool_cond = condition.get("Bool", {})
                if bool_cond.get("aws:SecureTransport") == "false":
                    has_ssl_enforcement = True
                    break

        if has_ssl_enforcement:
            return [
                Finding(
                    check_id="s3-ssl-only",
                    title=f"S3 bucket '{bucket_name}' enforces SSL-only access",
                    description=f"Bucket '{bucket_name}' has a policy denying non-SSL requests, ensuring data in transit is encrypted.",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.STORAGE,
                    resource_type="AWS::S3::Bucket",
                    resource_id=f"arn:aws:s3:::{bucket_name}",
                    region=region,
                    account_id=account_id,
                    soc2_controls=["CC6.7"],
                    details={"bucket": bucket_name, "ssl_enforced": True},
                )
            ]
        else:
            return [
                Finding(
                    check_id="s3-ssl-only",
                    title=f"S3 bucket '{bucket_name}' does not enforce SSL-only access",
                    description=f"Bucket '{bucket_name}' has a policy but does not deny non-SSL requests. Data could be transmitted unencrypted.",
                    severity=Severity.MEDIUM,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.STORAGE,
                    resource_type="AWS::S3::Bucket",
                    resource_id=f"arn:aws:s3:::{bucket_name}",
                    region=region,
                    account_id=account_id,
                    remediation=f"Add a bucket policy to '{bucket_name}' that denies requests where aws:SecureTransport is false.",
                    soc2_controls=["CC6.7"],
                    details={"bucket": bucket_name, "ssl_enforced": False},
                )
            ]

    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code == "NoSuchBucketPolicy":
            return [
                Finding(
                    check_id="s3-ssl-only",
                    title=f"S3 bucket '{bucket_name}' has no bucket policy (SSL not enforced)",
                    description=f"Bucket '{bucket_name}' has no bucket policy, so SSL-only access is not enforced. Non-encrypted HTTP requests are allowed.",
                    severity=Severity.MEDIUM,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.STORAGE,
                    resource_type="AWS::S3::Bucket",
                    resource_id=f"arn:aws:s3:::{bucket_name}",
                    region=region,
                    account_id=account_id,
                    remediation=f"Add a bucket policy to '{bucket_name}' that denies all requests where aws:SecureTransport is false.",
                    soc2_controls=["CC6.7"],
                    details={"bucket": bucket_name, "ssl_enforced": False, "policy_exists": False},
                )
            ]
        return []
