"""AWS CloudFront security checks (GLOBAL service).

CloudFront is a global AWS service. Distributions live in the global
namespace and the SDK requires region_name='us-east-1' by convention but
the resources are NOT regional. This module is marked IS_GLOBAL = True
so the structural multi-region smoke test in
tests/test_aws/test_aws_sweep_smoke.py knows to skip the region-iteration
assertion.
"""

from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from shasta.aws.client import AWSClient
from shasta.evidence.models import (
    CheckDomain,
    ComplianceStatus,
    Finding,
    Severity,
)


# CloudFront is global. The structural smoke test honors this marker and
# skips the multi-region iteration assertion. See ENGINEERING_PRINCIPLES.md #3.
IS_GLOBAL = True


# Modern TLS policy minimums for CloudFront viewer certs.
# CloudFront uses named "security policies" — anything below TLSv1.2_2021
# is considered weak by CIS / SOC 2.
WEAK_TLS_POLICIES = {
    "SSLv3",
    "TLSv1",
    "TLSv1_2016",
    "TLSv1.1_2016",
}


def run_all_aws_cloudfront_checks(client: AWSClient) -> list[Finding]:
    """Run all CloudFront checks. Single SDK call — CloudFront is global."""
    findings: list[Finding] = []
    account_id = client.account_info.account_id if client.account_info else "unknown"
    region = "us-east-1"  # CloudFront API endpoint convention; not a regional scoping

    findings.extend(check_cloudfront_https_only(client, account_id, region))
    findings.extend(check_cloudfront_min_tls_version(client, account_id, region))
    findings.extend(check_cloudfront_waf_attached(client, account_id, region))
    findings.extend(check_cloudfront_geo_restrictions(client, account_id, region))
    findings.extend(check_cloudfront_origin_access_control(client, account_id, region))

    return findings


def _list_distributions(client: AWSClient) -> list[dict]:
    try:
        cf = client.client("cloudfront")
    except ClientError:
        return []
    try:
        paginator = cf.get_paginator("list_distributions")
        out: list[dict] = []
        for page in paginator.paginate():
            dist_list = page.get("DistributionList", {})
            out.extend(dist_list.get("Items", []) or [])
        return out
    except ClientError:
        return []


def check_cloudfront_https_only(
    client: AWSClient, account_id: str, region: str
) -> list[Finding]:
    """[CIS AWS] CloudFront distributions must enforce HTTPS for viewer requests.

    The default cache behavior + every additional behavior must use either
    'redirect-to-https' or 'https-only'. 'allow-all' lets viewers connect
    over plain HTTP, which exposes credentials and session cookies.
    """
    distributions = _list_distributions(client)
    if not distributions:
        return []

    findings: list[Finding] = []
    for dist in distributions:
        dist_id = dist.get("Id", "unknown")
        dist_arn = dist.get("ARN", "")
        domain = dist.get("DomainName", "")
        default_behavior = dist.get("DefaultCacheBehavior", {}) or {}
        viewer_protocol = default_behavior.get("ViewerProtocolPolicy", "allow-all")

        # Also check additional cache behaviors
        cache_behaviors = (dist.get("CacheBehaviors", {}) or {}).get("Items", []) or []
        weak_behaviors: list[dict] = []
        if viewer_protocol == "allow-all":
            weak_behaviors.append(
                {"path": "default", "policy": viewer_protocol}
            )
        for cb in cache_behaviors:
            if cb.get("ViewerProtocolPolicy") == "allow-all":
                weak_behaviors.append(
                    {
                        "path": cb.get("PathPattern", "?"),
                        "policy": cb.get("ViewerProtocolPolicy"),
                    }
                )

        if not weak_behaviors:
            findings.append(
                Finding(
                    check_id="cloudfront-https-only",
                    title=f"CloudFront '{dist_id}' enforces HTTPS",
                    description=f"All cache behaviors on {domain} use redirect-to-https or https-only.",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.NETWORKING,
                    resource_type="AWS::CloudFront::Distribution",
                    resource_id=dist_arn,
                    region=region,
                    account_id=account_id,
                    soc2_controls=["CC6.1", "CC6.7"],
                    cis_aws_controls=["2.x"],
                    details={"distribution": dist_id, "domain": domain},
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="cloudfront-https-only",
                    title=f"CloudFront '{dist_id}' allows HTTP on {len(weak_behaviors)} behavior(s)",
                    description=(
                        f"Distribution {domain} has cache behaviors with ViewerProtocolPolicy=allow-all. "
                        "Plain HTTP requests are accepted, exposing credentials, session cookies, "
                        "and request bodies in transit."
                    ),
                    severity=Severity.HIGH,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.NETWORKING,
                    resource_type="AWS::CloudFront::Distribution",
                    resource_id=dist_arn,
                    region=region,
                    account_id=account_id,
                    remediation=(
                        f"Update each weak cache behavior to ViewerProtocolPolicy=redirect-to-https. "
                        f"Via the console: CloudFront > Distributions > {dist_id} > Behaviors > "
                        "Edit > Viewer protocol policy > Redirect HTTP to HTTPS."
                    ),
                    soc2_controls=["CC6.1", "CC6.7"],
                    cis_aws_controls=["2.x"],
                    details={"distribution": dist_id, "weak_behaviors": weak_behaviors},
                )
            )

    return findings


def check_cloudfront_min_tls_version(
    client: AWSClient, account_id: str, region: str
) -> list[Finding]:
    """[CIS AWS] CloudFront distributions must use TLSv1.2_2021 or newer security policy.

    CloudFront viewer certs are bound to a "security policy" that pins the
    minimum TLS version + cipher suite. Anything below TLSv1.2_2021 allows
    legacy cipher suites with known weaknesses.
    """
    distributions = _list_distributions(client)
    if not distributions:
        return []

    findings: list[Finding] = []
    for dist in distributions:
        dist_id = dist.get("Id", "unknown")
        dist_arn = dist.get("ARN", "")
        viewer_cert = dist.get("ViewerCertificate", {}) or {}
        # If using the default *.cloudfront.net cert, no TLS policy is configurable
        if viewer_cert.get("CloudFrontDefaultCertificate"):
            findings.append(
                Finding(
                    check_id="cloudfront-min-tls",
                    title=f"CloudFront '{dist_id}' uses default *.cloudfront.net cert",
                    description=(
                        "Distribution uses the default CloudFront certificate. The TLS policy "
                        "is managed by AWS — currently TLSv1 minimum, which is below CIS "
                        "expectations. Consider attaching a custom ACM certificate for prod."
                    ),
                    severity=Severity.LOW,
                    status=ComplianceStatus.PARTIAL,
                    domain=CheckDomain.NETWORKING,
                    resource_type="AWS::CloudFront::Distribution",
                    resource_id=dist_arn,
                    region=region,
                    account_id=account_id,
                    remediation=(
                        "For production workloads, attach a custom ACM certificate (us-east-1) "
                        "and set MinimumProtocolVersion to TLSv1.2_2021."
                    ),
                    soc2_controls=["CC6.1", "CC6.7"],
                    cis_aws_controls=["2.x"],
                )
            )
            continue

        min_protocol = viewer_cert.get("MinimumProtocolVersion", "")
        if min_protocol in WEAK_TLS_POLICIES:
            findings.append(
                Finding(
                    check_id="cloudfront-min-tls",
                    title=f"CloudFront '{dist_id}' uses weak TLS policy: {min_protocol}",
                    description=(
                        f"MinimumProtocolVersion={min_protocol}. This allows legacy ciphers "
                        "vulnerable to BEAST/POODLE/etc. CIS expects TLSv1.2_2021 or newer."
                    ),
                    severity=Severity.MEDIUM,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.NETWORKING,
                    resource_type="AWS::CloudFront::Distribution",
                    resource_id=dist_arn,
                    region=region,
                    account_id=account_id,
                    remediation=(
                        f"aws cloudfront update-distribution --id {dist_id} ... with "
                        "ViewerCertificate.MinimumProtocolVersion = 'TLSv1.2_2021'"
                    ),
                    soc2_controls=["CC6.1", "CC6.7"],
                    cis_aws_controls=["2.x"],
                    details={"distribution": dist_id, "min_protocol": min_protocol},
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="cloudfront-min-tls",
                    title=f"CloudFront '{dist_id}' uses TLS policy {min_protocol}",
                    description=f"MinimumProtocolVersion={min_protocol} meets the modern TLS bar.",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.NETWORKING,
                    resource_type="AWS::CloudFront::Distribution",
                    resource_id=dist_arn,
                    region=region,
                    account_id=account_id,
                    soc2_controls=["CC6.1", "CC6.7"],
                    cis_aws_controls=["2.x"],
                )
            )

    return findings


def check_cloudfront_waf_attached(
    client: AWSClient, account_id: str, region: str
) -> list[Finding]:
    """[CIS AWS] Public-facing CloudFront distributions should have a WAF Web ACL attached."""
    distributions = _list_distributions(client)
    if not distributions:
        return []

    findings: list[Finding] = []
    for dist in distributions:
        dist_id = dist.get("Id", "unknown")
        dist_arn = dist.get("ARN", "")
        web_acl_id = dist.get("WebACLId", "")
        if web_acl_id:
            findings.append(
                Finding(
                    check_id="cloudfront-waf",
                    title=f"CloudFront '{dist_id}' has a WAF Web ACL attached",
                    description=f"WebACL: {web_acl_id}",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.NETWORKING,
                    resource_type="AWS::CloudFront::Distribution",
                    resource_id=dist_arn,
                    region=region,
                    account_id=account_id,
                    soc2_controls=["CC6.6"],
                    cis_aws_controls=["2.x"],
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="cloudfront-waf",
                    title=f"CloudFront '{dist_id}' has no WAF Web ACL",
                    description=(
                        "Distribution has no WAF attached. Public-facing edges without WAF are "
                        "exposed to OWASP Top 10, bot scraping, and credential stuffing. Even "
                        "with origin auth, you need WAF for rate limiting at the edge."
                    ),
                    severity=Severity.MEDIUM,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.NETWORKING,
                    resource_type="AWS::CloudFront::Distribution",
                    resource_id=dist_arn,
                    region=region,
                    account_id=account_id,
                    remediation=(
                        "Create a WAFv2 Web ACL with scope=CLOUDFRONT (must be in us-east-1), "
                        "attach the AWS Managed Rules Common Rule Set + Bot Control rule group, "
                        "then associate it with the distribution."
                    ),
                    soc2_controls=["CC6.6"],
                    cis_aws_controls=["2.x"],
                )
            )

    return findings


def check_cloudfront_geo_restrictions(
    client: AWSClient, account_id: str, region: str
) -> list[Finding]:
    """CloudFront distributions can use geo restrictions to allow/deny by country.

    This is informational — geo restrictions are appropriate for some
    workloads (compliance, sanctions enforcement) and not for others.
    """
    distributions = _list_distributions(client)
    if not distributions:
        return []

    findings: list[Finding] = []
    for dist in distributions:
        dist_id = dist.get("Id", "unknown")
        dist_arn = dist.get("ARN", "")
        restrictions = dist.get("Restrictions", {}) or {}
        geo = restrictions.get("GeoRestriction", {}) or {}
        restriction_type = geo.get("RestrictionType", "none")

        findings.append(
            Finding(
                check_id="cloudfront-geo-restrictions",
                title=f"CloudFront '{dist_id}' geo restriction: {restriction_type}",
                description=(
                    f"Distribution geo restriction type is {restriction_type}. "
                    "If your service is sanctions-restricted or has data residency "
                    "requirements, consider using geo restrictions to enforce them at the edge."
                ),
                severity=Severity.INFO,
                status=ComplianceStatus.PASS if restriction_type != "none" else ComplianceStatus.PARTIAL,
                domain=CheckDomain.NETWORKING,
                resource_type="AWS::CloudFront::Distribution",
                resource_id=dist_arn,
                region=region,
                account_id=account_id,
                soc2_controls=["CC6.6"],
                cis_aws_controls=["2.x"],
                details={"distribution": dist_id, "restriction_type": restriction_type},
            )
        )

    return findings


def check_cloudfront_origin_access_control(
    client: AWSClient, account_id: str, region: str
) -> list[Finding]:
    """CloudFront distributions with S3 origins should use Origin Access Control (OAC).

    Without OAC (or the legacy OAI), the S3 bucket must be publicly readable
    so CloudFront can fetch objects — which means anyone can also bypass
    CloudFront and hit the bucket directly, defeating WAF / signed URLs / etc.
    """
    distributions = _list_distributions(client)
    if not distributions:
        return []

    findings: list[Finding] = []
    for dist in distributions:
        dist_id = dist.get("Id", "unknown")
        dist_arn = dist.get("ARN", "")
        origins = (dist.get("Origins", {}) or {}).get("Items", []) or []
        s3_origins_without_oac: list[str] = []
        s3_origin_count = 0
        for origin in origins:
            domain = origin.get("DomainName", "")
            # S3 origins look like bucket.s3.region.amazonaws.com or bucket.s3.amazonaws.com
            if ".s3" not in domain:
                continue
            s3_origin_count += 1
            oac_id = origin.get("OriginAccessControlId", "")
            s3_config = origin.get("S3OriginConfig", {}) or {}
            oai = s3_config.get("OriginAccessIdentity", "")
            if not oac_id and not oai:
                s3_origins_without_oac.append(domain)

        if s3_origin_count == 0:
            continue  # No S3 origins → check is N/A

        if not s3_origins_without_oac:
            findings.append(
                Finding(
                    check_id="cloudfront-oac",
                    title=f"CloudFront '{dist_id}' S3 origins use OAC/OAI",
                    description=f"All {s3_origin_count} S3 origin(s) use Origin Access Control or legacy OAI.",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.NETWORKING,
                    resource_type="AWS::CloudFront::Distribution",
                    resource_id=dist_arn,
                    region=region,
                    account_id=account_id,
                    soc2_controls=["CC6.6"],
                    cis_aws_controls=["2.x"],
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="cloudfront-oac",
                    title=f"CloudFront '{dist_id}' has {len(s3_origins_without_oac)} S3 origin(s) without OAC",
                    description=(
                        "These S3 origins have neither Origin Access Control nor a legacy "
                        "Origin Access Identity. The S3 bucket must therefore be publicly "
                        "readable for CloudFront to fetch objects — which means anyone can "
                        "bypass CloudFront entirely and hit the bucket directly, defeating "
                        "WAF, signed URLs, and any other edge controls."
                    ),
                    severity=Severity.HIGH,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.NETWORKING,
                    resource_type="AWS::CloudFront::Distribution",
                    resource_id=dist_arn,
                    region=region,
                    account_id=account_id,
                    remediation=(
                        "Create an Origin Access Control: aws cloudfront create-origin-access-control "
                        "--origin-access-control-config Name=oac,SigningBehavior=always,"
                        "SigningProtocol=sigv4,OriginAccessControlOriginType=s3. Attach to the "
                        "distribution origin, then update the S3 bucket policy to allow only the "
                        "CloudFront service principal with aws:SourceArn condition."
                    ),
                    soc2_controls=["CC6.6"],
                    cis_aws_controls=["2.x"],
                    details={
                        "distribution": dist_id,
                        "s3_origins_without_oac": s3_origins_without_oac,
                    },
                )
            )

    return findings
