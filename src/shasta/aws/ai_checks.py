"""AWS AI/ML security checks for Whitney.

Implements 15 security checks for AWS AI services (Bedrock, SageMaker,
Lambda, S3 training data, CloudTrail) mapped to AI governance controls.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from botocore.exceptions import ClientError

from shasta.aws.client import AWSClient
from shasta.evidence.models import (
    CheckDomain,
    CloudProvider,
    ComplianceStatus,
    Finding,
    Severity,
)

logger = logging.getLogger(__name__)

# AI API key env var names that should not be stored as plaintext
AI_API_KEY_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"OPENAI_API_KEY", re.IGNORECASE),
    re.compile(r"ANTHROPIC_API_KEY", re.IGNORECASE),
    re.compile(r"COHERE_API_KEY", re.IGNORECASE),
    re.compile(r"HUGGING_FACE_HUB_TOKEN", re.IGNORECASE),
    re.compile(r"HF_TOKEN", re.IGNORECASE),
    re.compile(r"REPLICATE_API_TOKEN", re.IGNORECASE),
    re.compile(r"GOOGLE_AI_API_KEY", re.IGNORECASE),
    re.compile(r"PALM_API_KEY", re.IGNORECASE),
    re.compile(r"STABILITY_API_KEY", re.IGNORECASE),
    re.compile(r"AI21_API_KEY", re.IGNORECASE),
    re.compile(r"MISTRAL_API_KEY", re.IGNORECASE),
    re.compile(r"TOGETHER_API_KEY", re.IGNORECASE),
    re.compile(r"GROQ_API_KEY", re.IGNORECASE),
]

# Bucket name/tag patterns indicating ML training data
ML_BUCKET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"train", re.IGNORECASE),
    re.compile(r"dataset", re.IGNORECASE),
    re.compile(r"model", re.IGNORECASE),
    re.compile(r"\bml\b", re.IGNORECASE),
    re.compile(r"\bai\b", re.IGNORECASE),
    re.compile(r"sagemaker", re.IGNORECASE),
]


def run_full_aws_ai_scan(client: AWSClient) -> list[Finding]:
    """Run all 15 AWS AI security checks and return findings.

    Named to match Shasta's ``run_full_scan`` convention. The former name
    ``run_all_aws_ai_checks`` was renamed on 2026-04-11 — update any caller
    that still uses the old spelling.

    Iterates all enabled regions (Bedrock and SageMaker are regional services).
    """
    findings: list[Finding] = []
    account_id = client.account_info.account_id if client.account_info else "unknown"
    default_region = client.account_info.region if client.account_info else "us-east-1"

    try:
        regions = client.get_enabled_regions()
    except ClientError:
        regions = [default_region]

    checks = [
        check_bedrock_guardrails_configured,
        check_bedrock_model_invocation_logging,
        check_bedrock_vpc_endpoint,
        check_bedrock_content_filter,
        check_bedrock_agent_guardrails,
        check_sagemaker_model_registry_access,
        check_sagemaker_endpoint_encryption,
        check_sagemaker_training_vpc,
        check_sagemaker_model_approval,
        check_sagemaker_data_capture,
        check_sagemaker_notebook_root_access,
        check_lambda_ai_api_keys_not_hardcoded,
        check_s3_training_data_encrypted,
        check_s3_training_data_versioned,
        check_cloudtrail_ai_events,
    ]

    for r in regions:
        try:
            rc = client.for_region(r)
            for check_fn in checks:
                try:
                    findings.extend(check_fn(rc, account_id, r))
                except Exception as e:
                    logger.warning("Check %s failed in %s: %s", check_fn.__name__, r, e)
        except ClientError:
            continue

    return findings


# ---------------------------------------------------------------------------
# Bedrock checks
# ---------------------------------------------------------------------------


def check_bedrock_guardrails_configured(
    client: AWSClient, account_id: str, region: str
) -> list[Finding]:
    """Check that at least one Bedrock guardrail is configured."""
    try:
        bedrock = client.client("bedrock")
        resp = bedrock.list_guardrails(maxResults=100)
        guardrails = resp.get("guardrails", [])
    except ClientError as e:
        return [
            _not_assessed(
                "bedrock-guardrails-configured",
                "Unable to check Bedrock guardrails",
                f"API call failed: {e}",
                "AWS::Bedrock::Guardrail",
                account_id,
                region,
            )
        ]
    except Exception as e:
        return [
            _not_assessed(
                "bedrock-guardrails-configured",
                "Bedrock guardrails check error",
                f"Unexpected error: {e}",
                "AWS::Bedrock::Guardrail",
                account_id,
                region,
            )
        ]

    if not guardrails:
        return [
            Finding(
                check_id="bedrock-guardrails-configured",
                title="No Bedrock guardrails configured",
                description=(
                    "No Amazon Bedrock guardrails found. Guardrails provide content filtering, "
                    "topic avoidance, and PII redaction for foundation model invocations."
                ),
                severity=Severity.HIGH,
                status=ComplianceStatus.FAIL,
                domain=CheckDomain.AI_GOVERNANCE,
                resource_type="AWS::Bedrock::Guardrail",
                resource_id=f"arn:aws:bedrock:{region}:{account_id}:guardrails",
                region=region,
                account_id=account_id,
                cloud_provider=CloudProvider.AWS,
                remediation="Create a Bedrock guardrail with content filters, denied topics, and PII handling.",
                details={"guardrail_count": 0},
                soc2_controls=["CC6.1", "CC7.2"],
            )
        ]

    return [
        Finding(
            check_id="bedrock-guardrails-configured",
            title=f"Bedrock guardrails configured ({len(guardrails)} found)",
            description=f"Found {len(guardrails)} Bedrock guardrail(s) in the account.",
            severity=Severity.INFO,
            status=ComplianceStatus.PASS,
            domain=CheckDomain.AI_GOVERNANCE,
            resource_type="AWS::Bedrock::Guardrail",
            resource_id=f"arn:aws:bedrock:{region}:{account_id}:guardrails",
            region=region,
            account_id=account_id,
            cloud_provider=CloudProvider.AWS,
            details={
                "guardrail_count": len(guardrails),
                "guardrail_names": [g.get("name", "") for g in guardrails],
            },
            soc2_controls=["CC6.1", "CC7.2"],
        )
    ]


def check_bedrock_model_invocation_logging(
    client: AWSClient, account_id: str, region: str
) -> list[Finding]:
    """Check that Bedrock model invocation logging is enabled."""
    try:
        bedrock = client.client("bedrock")
        resp = bedrock.get_model_invocation_logging_configuration()
        config = resp.get("loggingConfig", {})
    except ClientError as e:
        return [
            _not_assessed(
                "bedrock-model-invocation-logging",
                "Unable to check Bedrock invocation logging",
                f"API call failed: {e}",
                "AWS::Bedrock::ModelInvocationLogging",
                account_id,
                region,
            )
        ]
    except Exception as e:
        return [
            _not_assessed(
                "bedrock-model-invocation-logging",
                "Bedrock invocation logging check error",
                f"Unexpected error: {e}",
                "AWS::Bedrock::ModelInvocationLogging",
                account_id,
                region,
            )
        ]

    s3_enabled = bool(config.get("s3Config", {}).get("bucketName"))
    cw_enabled = bool(config.get("cloudWatchConfig", {}).get("logGroupName"))
    text_enabled = config.get("textDataDeliveryEnabled", False)
    image_enabled = config.get("imageDataDeliveryEnabled", False)

    if s3_enabled or cw_enabled:
        return [
            Finding(
                check_id="bedrock-model-invocation-logging",
                title="Bedrock model invocation logging is enabled",
                description=(
                    f"Invocation logging configured: S3={s3_enabled}, CloudWatch={cw_enabled}, "
                    f"text_delivery={text_enabled}, image_delivery={image_enabled}."
                ),
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.AI_GOVERNANCE,
                resource_type="AWS::Bedrock::ModelInvocationLogging",
                resource_id=f"arn:aws:bedrock:{region}:{account_id}:logging",
                region=region,
                account_id=account_id,
                cloud_provider=CloudProvider.AWS,
                details={
                    "s3_enabled": s3_enabled,
                    "cloudwatch_enabled": cw_enabled,
                    "text_delivery": text_enabled,
                    "image_delivery": image_enabled,
                },
                soc2_controls=["CC7.1", "CC7.2"],
            )
        ]

    return [
        Finding(
            check_id="bedrock-model-invocation-logging",
            title="Bedrock model invocation logging is not enabled",
            description=(
                "Model invocation logging is not configured for Amazon Bedrock. "
                "Without logging, you cannot audit model inputs/outputs or detect misuse."
            ),
            severity=Severity.HIGH,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.AI_GOVERNANCE,
            resource_type="AWS::Bedrock::ModelInvocationLogging",
            resource_id=f"arn:aws:bedrock:{region}:{account_id}:logging",
            region=region,
            account_id=account_id,
            cloud_provider=CloudProvider.AWS,
            remediation="Enable Bedrock model invocation logging to S3 or CloudWatch Logs.",
            details={"logging_config": config},
            soc2_controls=["CC7.1", "CC7.2"],
        )
    ]


def check_bedrock_vpc_endpoint(client: AWSClient, account_id: str, region: str) -> list[Finding]:
    """Check that a VPC endpoint exists for Bedrock (private connectivity)."""
    try:
        ec2 = client.client("ec2")
        resp = ec2.describe_vpc_endpoints(
            Filters=[
                {"Name": "service-name", "Values": [f"com.amazonaws.{region}.bedrock-runtime"]}
            ]
        )
        endpoints = resp.get("VpcEndpoints", [])
    except ClientError as e:
        return [
            _not_assessed(
                "bedrock-vpc-endpoint",
                "Unable to check Bedrock VPC endpoints",
                f"API call failed: {e}",
                "AWS::EC2::VPCEndpoint",
                account_id,
                region,
            )
        ]
    except Exception as e:
        return [
            _not_assessed(
                "bedrock-vpc-endpoint",
                "Bedrock VPC endpoint check error",
                f"Unexpected error: {e}",
                "AWS::EC2::VPCEndpoint",
                account_id,
                region,
            )
        ]

    active = [ep for ep in endpoints if ep.get("State") == "available"]

    if active:
        return [
            Finding(
                check_id="bedrock-vpc-endpoint",
                title=f"Bedrock VPC endpoint configured ({len(active)} active)",
                description=f"Found {len(active)} active VPC endpoint(s) for Bedrock runtime.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.AI_GOVERNANCE,
                resource_type="AWS::EC2::VPCEndpoint",
                resource_id=active[0].get("VpcEndpointId", "unknown"),
                region=region,
                account_id=account_id,
                cloud_provider=CloudProvider.AWS,
                details={"endpoint_ids": [ep.get("VpcEndpointId") for ep in active]},
                soc2_controls=["CC6.6"],
            )
        ]

    return [
        Finding(
            check_id="bedrock-vpc-endpoint",
            title="No VPC endpoint for Bedrock runtime",
            description=(
                "No VPC endpoint found for the Bedrock runtime service. Without a VPC endpoint, "
                "Bedrock API calls traverse the public internet."
            ),
            severity=Severity.MEDIUM,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.AI_GOVERNANCE,
            resource_type="AWS::EC2::VPCEndpoint",
            resource_id=f"arn:aws:ec2:{region}:{account_id}:vpc-endpoint/none",
            region=region,
            account_id=account_id,
            cloud_provider=CloudProvider.AWS,
            remediation="Create a VPC endpoint for com.amazonaws.<region>.bedrock-runtime.",
            soc2_controls=["CC6.6"],
        )
    ]


def check_bedrock_content_filter(client: AWSClient, account_id: str, region: str) -> list[Finding]:
    """Check that Bedrock guardrails have content filters with appropriate strength."""
    try:
        bedrock = client.client("bedrock")
        resp = bedrock.list_guardrails(maxResults=100)
        guardrails = resp.get("guardrails", [])
    except ClientError as e:
        return [
            _not_assessed(
                "bedrock-content-filter",
                "Unable to check Bedrock content filters",
                f"API call failed: {e}",
                "AWS::Bedrock::Guardrail",
                account_id,
                region,
            )
        ]
    except Exception as e:
        return [
            _not_assessed(
                "bedrock-content-filter",
                "Bedrock content filter check error",
                f"Unexpected error: {e}",
                "AWS::Bedrock::Guardrail",
                account_id,
                region,
            )
        ]

    if not guardrails:
        return [
            Finding(
                check_id="bedrock-content-filter",
                title="No Bedrock content filters (no guardrails exist)",
                description="No guardrails exist, so no content filters are configured.",
                severity=Severity.HIGH,
                status=ComplianceStatus.FAIL,
                domain=CheckDomain.AI_GOVERNANCE,
                resource_type="AWS::Bedrock::Guardrail",
                resource_id=f"arn:aws:bedrock:{region}:{account_id}:guardrails",
                region=region,
                account_id=account_id,
                cloud_provider=CloudProvider.AWS,
                remediation="Create a Bedrock guardrail with content filtering enabled.",
                soc2_controls=["CC6.1"],
            )
        ]

    findings: list[Finding] = []
    for g in guardrails:
        guardrail_id = g.get("id", "unknown")
        try:
            detail = bedrock.get_guardrail(guardrailIdentifier=guardrail_id)
            content_policy = detail.get("contentPolicy", {})
            filters = content_policy.get("filters", [])

            if not filters:
                findings.append(
                    Finding(
                        check_id="bedrock-content-filter",
                        title=f"Guardrail '{g.get('name', guardrail_id)}' has no content filters",
                        description="This guardrail has no content filter policies configured.",
                        severity=Severity.HIGH,
                        status=ComplianceStatus.FAIL,
                        domain=CheckDomain.AI_GOVERNANCE,
                        resource_type="AWS::Bedrock::Guardrail",
                        resource_id=f"arn:aws:bedrock:{region}:{account_id}:guardrail/{guardrail_id}",
                        region=region,
                        account_id=account_id,
                        cloud_provider=CloudProvider.AWS,
                        remediation="Add content filter policies to this guardrail.",
                        details={"guardrail_id": guardrail_id},
                        soc2_controls=["CC6.1"],
                    )
                )
            else:
                findings.append(
                    Finding(
                        check_id="bedrock-content-filter",
                        title=f"Guardrail '{g.get('name', guardrail_id)}' has content filters",
                        description=f"Content filter policy has {len(filters)} filter(s) configured.",
                        severity=Severity.INFO,
                        status=ComplianceStatus.PASS,
                        domain=CheckDomain.AI_GOVERNANCE,
                        resource_type="AWS::Bedrock::Guardrail",
                        resource_id=f"arn:aws:bedrock:{region}:{account_id}:guardrail/{guardrail_id}",
                        region=region,
                        account_id=account_id,
                        cloud_provider=CloudProvider.AWS,
                        details={"guardrail_id": guardrail_id, "filter_count": len(filters)},
                        soc2_controls=["CC6.1"],
                    )
                )
        except ClientError as e:
            logger.debug("Failed to get guardrail %s detail: %s", guardrail_id, e)
            findings.append(
                _not_assessed(
                    "bedrock-content-filter",
                    f"Unable to inspect guardrail {guardrail_id}",
                    f"API call failed: {e}",
                    "AWS::Bedrock::Guardrail",
                    account_id,
                    region,
                )
            )

    return findings


def check_bedrock_agent_guardrails(
    client: AWSClient, account_id: str, region: str
) -> list[Finding]:
    """Check that Bedrock agents have guardrails attached."""
    try:
        bedrock_agent = client.client("bedrock-agent")
        resp = bedrock_agent.list_agents(maxResults=100)
        agents = resp.get("agentSummaries", [])
    except ClientError as e:
        return [
            _not_assessed(
                "bedrock-agent-guardrails",
                "Unable to check Bedrock agents",
                f"API call failed: {e}",
                "AWS::Bedrock::Agent",
                account_id,
                region,
            )
        ]
    except Exception as e:
        return [
            _not_assessed(
                "bedrock-agent-guardrails",
                "Bedrock agent guardrails check error",
                f"Unexpected error: {e}",
                "AWS::Bedrock::Agent",
                account_id,
                region,
            )
        ]

    if not agents:
        return [
            Finding(
                check_id="bedrock-agent-guardrails",
                title="No Bedrock agents found",
                description="No Bedrock agents configured in this region.",
                severity=Severity.INFO,
                status=ComplianceStatus.NOT_APPLICABLE,
                domain=CheckDomain.AI_GOVERNANCE,
                resource_type="AWS::Bedrock::Agent",
                resource_id=f"arn:aws:bedrock:{region}:{account_id}:agents",
                region=region,
                account_id=account_id,
                cloud_provider=CloudProvider.AWS,
                soc2_controls=["CC6.1"],
            )
        ]

    findings: list[Finding] = []
    for agent in agents:
        agent_id = agent.get("agentId", "unknown")
        agent_name = agent.get("agentName", agent_id)
        try:
            detail = bedrock_agent.get_agent(agentId=agent_id)
            agent_detail = detail.get("agent", {})
            guardrail_config = agent_detail.get("guardrailConfiguration", {})
            guardrail_id = guardrail_config.get("guardrailIdentifier")

            if guardrail_id:
                findings.append(
                    Finding(
                        check_id="bedrock-agent-guardrails",
                        title=f"Agent '{agent_name}' has guardrail attached",
                        description=f"Agent has guardrail '{guardrail_id}' configured.",
                        severity=Severity.INFO,
                        status=ComplianceStatus.PASS,
                        domain=CheckDomain.AI_GOVERNANCE,
                        resource_type="AWS::Bedrock::Agent",
                        resource_id=f"arn:aws:bedrock:{region}:{account_id}:agent/{agent_id}",
                        region=region,
                        account_id=account_id,
                        cloud_provider=CloudProvider.AWS,
                        details={"agent_id": agent_id, "guardrail_id": guardrail_id},
                        soc2_controls=["CC6.1"],
                    )
                )
            else:
                findings.append(
                    Finding(
                        check_id="bedrock-agent-guardrails",
                        title=f"Agent '{agent_name}' has no guardrail",
                        description="This Bedrock agent does not have a guardrail attached.",
                        severity=Severity.HIGH,
                        status=ComplianceStatus.FAIL,
                        domain=CheckDomain.AI_GOVERNANCE,
                        resource_type="AWS::Bedrock::Agent",
                        resource_id=f"arn:aws:bedrock:{region}:{account_id}:agent/{agent_id}",
                        region=region,
                        account_id=account_id,
                        cloud_provider=CloudProvider.AWS,
                        remediation="Attach a guardrail to this Bedrock agent.",
                        details={"agent_id": agent_id},
                        soc2_controls=["CC6.1"],
                    )
                )
        except ClientError as e:
            logger.debug("Failed to get agent %s: %s", agent_id, e)

    return findings or [
        _not_assessed(
            "bedrock-agent-guardrails",
            "Unable to inspect Bedrock agent details",
            "Could not retrieve agent configurations.",
            "AWS::Bedrock::Agent",
            account_id,
            region,
        )
    ]


# ---------------------------------------------------------------------------
# SageMaker checks
# ---------------------------------------------------------------------------


def check_sagemaker_model_registry_access(
    client: AWSClient, account_id: str, region: str
) -> list[Finding]:
    """Check SageMaker model package groups have restrictive resource policies."""
    try:
        sm = client.client("sagemaker")
        resp = sm.list_model_package_groups(MaxResults=100)
        groups = resp.get("ModelPackageGroupSummaryList", [])
    except ClientError as e:
        return [
            _not_assessed(
                "sagemaker-model-registry-access",
                "Unable to check SageMaker model registry",
                f"API call failed: {e}",
                "AWS::SageMaker::ModelPackageGroup",
                account_id,
                region,
            )
        ]
    except Exception as e:
        return [
            _not_assessed(
                "sagemaker-model-registry-access",
                "SageMaker model registry check error",
                f"Unexpected error: {e}",
                "AWS::SageMaker::ModelPackageGroup",
                account_id,
                region,
            )
        ]

    if not groups:
        return [
            Finding(
                check_id="sagemaker-model-registry-access",
                title="No SageMaker model package groups found",
                description="No model package groups in the SageMaker model registry.",
                severity=Severity.INFO,
                status=ComplianceStatus.NOT_APPLICABLE,
                domain=CheckDomain.AI_GOVERNANCE,
                resource_type="AWS::SageMaker::ModelPackageGroup",
                resource_id=f"arn:aws:sagemaker:{region}:{account_id}:model-package-groups",
                region=region,
                account_id=account_id,
                cloud_provider=CloudProvider.AWS,
                soc2_controls=["CC6.1", "CC6.3"],
            )
        ]

    findings: list[Finding] = []
    for group in groups:
        group_name = group.get("ModelPackageGroupName", "unknown")
        try:
            policy_resp = sm.get_model_package_group_policy(ModelPackageGroupName=group_name)
            # If a policy exists, check for overly permissive access
            import json

            policy = json.loads(policy_resp.get("ResourcePolicy", "{}"))
            statements = policy.get("Statement", [])
            has_wildcard = any(
                stmt.get("Principal") in ("*", {"AWS": "*"}) and stmt.get("Effect") == "Allow"
                for stmt in statements
            )
            if has_wildcard:
                findings.append(
                    Finding(
                        check_id="sagemaker-model-registry-access",
                        title=f"Model package group '{group_name}' has public access",
                        description="Resource policy allows access from any AWS principal.",
                        severity=Severity.HIGH,
                        status=ComplianceStatus.FAIL,
                        domain=CheckDomain.AI_GOVERNANCE,
                        resource_type="AWS::SageMaker::ModelPackageGroup",
                        resource_id=group.get("ModelPackageGroupArn", group_name),
                        region=region,
                        account_id=account_id,
                        cloud_provider=CloudProvider.AWS,
                        remediation="Restrict the resource policy to specific accounts/roles.",
                        details={"group_name": group_name, "wildcard_principal": True},
                        soc2_controls=["CC6.1", "CC6.3"],
                    )
                )
            else:
                findings.append(
                    Finding(
                        check_id="sagemaker-model-registry-access",
                        title=f"Model package group '{group_name}' has restricted access",
                        description="Resource policy does not grant wildcard access.",
                        severity=Severity.INFO,
                        status=ComplianceStatus.PASS,
                        domain=CheckDomain.AI_GOVERNANCE,
                        resource_type="AWS::SageMaker::ModelPackageGroup",
                        resource_id=group.get("ModelPackageGroupArn", group_name),
                        region=region,
                        account_id=account_id,
                        cloud_provider=CloudProvider.AWS,
                        details={"group_name": group_name},
                        soc2_controls=["CC6.1", "CC6.3"],
                    )
                )
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in ("ResourceNotFoundException", "ValidationException"):
                # No resource policy set — this is acceptable (IAM-only access)
                findings.append(
                    Finding(
                        check_id="sagemaker-model-registry-access",
                        title=f"Model package group '{group_name}' uses IAM-only access",
                        description="No resource policy set; access controlled by IAM only.",
                        severity=Severity.INFO,
                        status=ComplianceStatus.PASS,
                        domain=CheckDomain.AI_GOVERNANCE,
                        resource_type="AWS::SageMaker::ModelPackageGroup",
                        resource_id=group.get("ModelPackageGroupArn", group_name),
                        region=region,
                        account_id=account_id,
                        cloud_provider=CloudProvider.AWS,
                        details={"group_name": group_name, "iam_only": True},
                        soc2_controls=["CC6.1", "CC6.3"],
                    )
                )
            else:
                logger.debug("Failed to get policy for %s: %s", group_name, e)

    return findings or [
        _not_assessed(
            "sagemaker-model-registry-access",
            "Unable to evaluate model registry access policies",
            "Could not retrieve model package group policies.",
            "AWS::SageMaker::ModelPackageGroup",
            account_id,
            region,
        )
    ]


def check_sagemaker_endpoint_encryption(
    client: AWSClient, account_id: str, region: str
) -> list[Finding]:
    """Check SageMaker endpoints use KMS encryption."""
    try:
        sm = client.client("sagemaker")
        resp = sm.list_endpoints(MaxResults=100)
        endpoints = resp.get("Endpoints", [])
    except ClientError as e:
        return [
            _not_assessed(
                "sagemaker-endpoint-encryption",
                "Unable to check SageMaker endpoints",
                f"API call failed: {e}",
                "AWS::SageMaker::Endpoint",
                account_id,
                region,
            )
        ]
    except Exception as e:
        return [
            _not_assessed(
                "sagemaker-endpoint-encryption",
                "SageMaker endpoint encryption check error",
                f"Unexpected error: {e}",
                "AWS::SageMaker::Endpoint",
                account_id,
                region,
            )
        ]

    if not endpoints:
        return [
            Finding(
                check_id="sagemaker-endpoint-encryption",
                title="No SageMaker endpoints found",
                description="No SageMaker inference endpoints deployed.",
                severity=Severity.INFO,
                status=ComplianceStatus.NOT_APPLICABLE,
                domain=CheckDomain.AI_GOVERNANCE,
                resource_type="AWS::SageMaker::Endpoint",
                resource_id=f"arn:aws:sagemaker:{region}:{account_id}:endpoints",
                region=region,
                account_id=account_id,
                cloud_provider=CloudProvider.AWS,
                soc2_controls=["CC6.1"],
            )
        ]

    findings: list[Finding] = []
    for ep in endpoints:
        ep_name = ep["EndpointName"]
        try:
            detail = sm.describe_endpoint(EndpointName=ep_name)
            ep_arn = detail.get(
                "EndpointArn", f"arn:aws:sagemaker:{region}:{account_id}:endpoint/{ep_name}"
            )

            # KmsKeyId lives on the endpoint config, not the endpoint itself
            kms_key = None
            ep_config_name = detail.get("EndpointConfigName")
            if ep_config_name:
                try:
                    config_detail = sm.describe_endpoint_config(
                        EndpointConfigName=ep_config_name
                    )
                    kms_key = config_detail.get("KmsKeyId")
                except ClientError:
                    pass

            if kms_key:
                findings.append(
                    Finding(
                        check_id="sagemaker-endpoint-encryption",
                        title=f"Endpoint '{ep_name}' has KMS encryption",
                        description=f"Endpoint encrypted with KMS key: {kms_key}",
                        severity=Severity.INFO,
                        status=ComplianceStatus.PASS,
                        domain=CheckDomain.AI_GOVERNANCE,
                        resource_type="AWS::SageMaker::Endpoint",
                        resource_id=ep_arn,
                        region=region,
                        account_id=account_id,
                        cloud_provider=CloudProvider.AWS,
                        details={"endpoint_name": ep_name, "kms_key_id": kms_key},
                        soc2_controls=["CC6.1"],
                    )
                )
            else:
                findings.append(
                    Finding(
                        check_id="sagemaker-endpoint-encryption",
                        title=f"Endpoint '{ep_name}' lacks KMS encryption",
                        description="SageMaker endpoint does not have a customer-managed KMS key.",
                        severity=Severity.MEDIUM,
                        status=ComplianceStatus.FAIL,
                        domain=CheckDomain.AI_GOVERNANCE,
                        resource_type="AWS::SageMaker::Endpoint",
                        resource_id=ep_arn,
                        region=region,
                        account_id=account_id,
                        cloud_provider=CloudProvider.AWS,
                        remediation="Configure a KMS key for this SageMaker endpoint.",
                        details={"endpoint_name": ep_name},
                        soc2_controls=["CC6.1"],
                    )
                )
        except ClientError as e:
            logger.debug("Failed to describe endpoint %s: %s", ep_name, e)

    return findings


def check_sagemaker_training_vpc(client: AWSClient, account_id: str, region: str) -> list[Finding]:
    """Check SageMaker training jobs run within a VPC."""
    try:
        sm = client.client("sagemaker")
        resp = sm.list_training_jobs(MaxResults=50, SortBy="CreationTime", SortOrder="Descending")
        jobs = resp.get("TrainingJobSummaries", [])
    except ClientError as e:
        return [
            _not_assessed(
                "sagemaker-training-vpc",
                "Unable to check SageMaker training jobs",
                f"API call failed: {e}",
                "AWS::SageMaker::TrainingJob",
                account_id,
                region,
            )
        ]
    except Exception as e:
        return [
            _not_assessed(
                "sagemaker-training-vpc",
                "SageMaker training VPC check error",
                f"Unexpected error: {e}",
                "AWS::SageMaker::TrainingJob",
                account_id,
                region,
            )
        ]

    if not jobs:
        return [
            Finding(
                check_id="sagemaker-training-vpc",
                title="No SageMaker training jobs found",
                description="No recent training jobs to evaluate.",
                severity=Severity.INFO,
                status=ComplianceStatus.NOT_APPLICABLE,
                domain=CheckDomain.AI_GOVERNANCE,
                resource_type="AWS::SageMaker::TrainingJob",
                resource_id=f"arn:aws:sagemaker:{region}:{account_id}:training-jobs",
                region=region,
                account_id=account_id,
                cloud_provider=CloudProvider.AWS,
                soc2_controls=["CC6.6"],
            )
        ]

    findings: list[Finding] = []
    for job in jobs:
        job_name = job["TrainingJobName"]
        try:
            detail = sm.describe_training_job(TrainingJobName=job_name)
            vpc_config = detail.get("VpcConfig")
            job_arn = detail.get(
                "TrainingJobArn", f"arn:aws:sagemaker:{region}:{account_id}:training-job/{job_name}"
            )

            if vpc_config and vpc_config.get("Subnets"):
                findings.append(
                    Finding(
                        check_id="sagemaker-training-vpc",
                        title=f"Training job '{job_name}' runs in a VPC",
                        description="Training job is configured with VPC networking.",
                        severity=Severity.INFO,
                        status=ComplianceStatus.PASS,
                        domain=CheckDomain.AI_GOVERNANCE,
                        resource_type="AWS::SageMaker::TrainingJob",
                        resource_id=job_arn,
                        region=region,
                        account_id=account_id,
                        cloud_provider=CloudProvider.AWS,
                        details={
                            "job_name": job_name,
                            "vpc_subnets": vpc_config.get("Subnets", []),
                        },
                        soc2_controls=["CC6.6"],
                    )
                )
            else:
                findings.append(
                    Finding(
                        check_id="sagemaker-training-vpc",
                        title=f"Training job '{job_name}' is not in a VPC",
                        description="Training job runs without VPC isolation.",
                        severity=Severity.MEDIUM,
                        status=ComplianceStatus.FAIL,
                        domain=CheckDomain.AI_GOVERNANCE,
                        resource_type="AWS::SageMaker::TrainingJob",
                        resource_id=job_arn,
                        region=region,
                        account_id=account_id,
                        cloud_provider=CloudProvider.AWS,
                        remediation="Configure VPC subnets and security groups for training jobs.",
                        details={"job_name": job_name},
                        soc2_controls=["CC6.6"],
                    )
                )
        except ClientError as e:
            logger.debug("Failed to describe training job %s: %s", job_name, e)

    return findings


def check_sagemaker_model_approval(
    client: AWSClient, account_id: str, region: str
) -> list[Finding]:
    """Check that SageMaker model packages require approval before deployment."""
    try:
        sm = client.client("sagemaker")
        resp = sm.list_model_package_groups(MaxResults=100)
        groups = resp.get("ModelPackageGroupSummaryList", [])
    except ClientError as e:
        return [
            _not_assessed(
                "sagemaker-model-approval",
                "Unable to check SageMaker model approval",
                f"API call failed: {e}",
                "AWS::SageMaker::ModelPackageGroup",
                account_id,
                region,
            )
        ]
    except Exception as e:
        return [
            _not_assessed(
                "sagemaker-model-approval",
                "SageMaker model approval check error",
                f"Unexpected error: {e}",
                "AWS::SageMaker::ModelPackageGroup",
                account_id,
                region,
            )
        ]

    if not groups:
        return [
            Finding(
                check_id="sagemaker-model-approval",
                title="No SageMaker model package groups found",
                description="No model registry groups to evaluate for approval workflows.",
                severity=Severity.INFO,
                status=ComplianceStatus.NOT_APPLICABLE,
                domain=CheckDomain.AI_GOVERNANCE,
                resource_type="AWS::SageMaker::ModelPackageGroup",
                resource_id=f"arn:aws:sagemaker:{region}:{account_id}:model-package-groups",
                region=region,
                account_id=account_id,
                cloud_provider=CloudProvider.AWS,
                soc2_controls=["CC8.1"],
            )
        ]

    findings: list[Finding] = []
    for group in groups:
        group_name = group.get("ModelPackageGroupName", "unknown")
        group_arn = group.get("ModelPackageGroupArn", group_name)
        try:
            # Check most recent model package in this group
            pkgs = sm.list_model_packages(
                ModelPackageGroupName=group_name,
                MaxResults=5,
                SortBy="CreationTime",
                SortOrder="Descending",
            )
            packages = pkgs.get("ModelPackageSummaryList", [])

            has_pending = any(
                p.get("ModelApprovalStatus") == "PendingManualApproval" for p in packages
            )
            has_approved = any(p.get("ModelApprovalStatus") == "Approved" for p in packages)
            all_auto = all(p.get("ModelApprovalStatus") in (None, "") for p in packages)

            if not packages:
                findings.append(
                    Finding(
                        check_id="sagemaker-model-approval",
                        title=f"Group '{group_name}' has no model packages",
                        description="Model package group exists but contains no packages.",
                        severity=Severity.INFO,
                        status=ComplianceStatus.NOT_APPLICABLE,
                        domain=CheckDomain.AI_GOVERNANCE,
                        resource_type="AWS::SageMaker::ModelPackageGroup",
                        resource_id=group_arn,
                        region=region,
                        account_id=account_id,
                        cloud_provider=CloudProvider.AWS,
                        soc2_controls=["CC8.1"],
                    )
                )
            elif has_pending or has_approved:
                findings.append(
                    Finding(
                        check_id="sagemaker-model-approval",
                        title=f"Group '{group_name}' uses approval workflow",
                        description="Model packages in this group use manual approval status.",
                        severity=Severity.INFO,
                        status=ComplianceStatus.PASS,
                        domain=CheckDomain.AI_GOVERNANCE,
                        resource_type="AWS::SageMaker::ModelPackageGroup",
                        resource_id=group_arn,
                        region=region,
                        account_id=account_id,
                        cloud_provider=CloudProvider.AWS,
                        details={"group_name": group_name, "package_count": len(packages)},
                        soc2_controls=["CC8.1"],
                    )
                )
            elif all_auto:
                findings.append(
                    Finding(
                        check_id="sagemaker-model-approval",
                        title=f"Group '{group_name}' has no approval workflow",
                        description="Model packages do not use the approval status field.",
                        severity=Severity.MEDIUM,
                        status=ComplianceStatus.FAIL,
                        domain=CheckDomain.AI_GOVERNANCE,
                        resource_type="AWS::SageMaker::ModelPackageGroup",
                        resource_id=group_arn,
                        region=region,
                        account_id=account_id,
                        cloud_provider=CloudProvider.AWS,
                        remediation="Use ModelApprovalStatus in your ML pipeline to enforce human review.",
                        details={"group_name": group_name},
                        soc2_controls=["CC8.1"],
                    )
                )
        except ClientError as e:
            logger.debug("Failed to list packages for %s: %s", group_name, e)

    return findings


def check_sagemaker_data_capture(client: AWSClient, account_id: str, region: str) -> list[Finding]:
    """Check SageMaker endpoints have data capture enabled for monitoring."""
    try:
        sm = client.client("sagemaker")
        resp = sm.list_endpoints(MaxResults=100)
        endpoints = resp.get("Endpoints", [])
    except ClientError as e:
        return [
            _not_assessed(
                "sagemaker-data-capture",
                "Unable to check SageMaker data capture",
                f"API call failed: {e}",
                "AWS::SageMaker::Endpoint",
                account_id,
                region,
            )
        ]
    except Exception as e:
        return [
            _not_assessed(
                "sagemaker-data-capture",
                "SageMaker data capture check error",
                f"Unexpected error: {e}",
                "AWS::SageMaker::Endpoint",
                account_id,
                region,
            )
        ]

    if not endpoints:
        return [
            Finding(
                check_id="sagemaker-data-capture",
                title="No SageMaker endpoints found",
                description="No endpoints to evaluate for data capture.",
                severity=Severity.INFO,
                status=ComplianceStatus.NOT_APPLICABLE,
                domain=CheckDomain.AI_GOVERNANCE,
                resource_type="AWS::SageMaker::Endpoint",
                resource_id=f"arn:aws:sagemaker:{region}:{account_id}:endpoints",
                region=region,
                account_id=account_id,
                cloud_provider=CloudProvider.AWS,
                soc2_controls=["CC7.1", "CC7.2"],
            )
        ]

    findings: list[Finding] = []
    for ep in endpoints:
        ep_name = ep["EndpointName"]
        try:
            detail = sm.describe_endpoint(EndpointName=ep_name)
            ep_arn = detail.get(
                "EndpointArn", f"arn:aws:sagemaker:{region}:{account_id}:endpoint/{ep_name}"
            )

            dc_config = detail.get("DataCaptureConfig", {})
            capture_enabled = dc_config.get("EnableCapture", False)

            if capture_enabled:
                findings.append(
                    Finding(
                        check_id="sagemaker-data-capture",
                        title=f"Endpoint '{ep_name}' has data capture enabled",
                        description="Data capture is enabled for model monitoring.",
                        severity=Severity.INFO,
                        status=ComplianceStatus.PASS,
                        domain=CheckDomain.AI_GOVERNANCE,
                        resource_type="AWS::SageMaker::Endpoint",
                        resource_id=ep_arn,
                        region=region,
                        account_id=account_id,
                        cloud_provider=CloudProvider.AWS,
                        details={
                            "endpoint_name": ep_name,
                            "capture_percentage": dc_config.get("CurrentSamplingPercentage"),
                        },
                        soc2_controls=["CC7.1", "CC7.2"],
                    )
                )
            else:
                findings.append(
                    Finding(
                        check_id="sagemaker-data-capture",
                        title=f"Endpoint '{ep_name}' lacks data capture",
                        description="Data capture is not enabled — model drift and bias cannot be monitored.",
                        severity=Severity.MEDIUM,
                        status=ComplianceStatus.FAIL,
                        domain=CheckDomain.AI_GOVERNANCE,
                        resource_type="AWS::SageMaker::Endpoint",
                        resource_id=ep_arn,
                        region=region,
                        account_id=account_id,
                        cloud_provider=CloudProvider.AWS,
                        remediation="Enable data capture on this endpoint for model monitoring.",
                        details={"endpoint_name": ep_name},
                        soc2_controls=["CC7.1", "CC7.2"],
                    )
                )
        except ClientError as e:
            logger.debug("Failed to describe endpoint %s: %s", ep_name, e)

    return findings


def check_sagemaker_notebook_root_access(
    client: AWSClient, account_id: str, region: str
) -> list[Finding]:
    """Check SageMaker notebook instances do not have root access enabled."""
    try:
        sm = client.client("sagemaker")
        resp = sm.list_notebook_instances(MaxResults=100)
        notebooks = resp.get("NotebookInstances", [])
    except ClientError as e:
        return [
            _not_assessed(
                "sagemaker-notebook-root-access",
                "Unable to check SageMaker notebooks",
                f"API call failed: {e}",
                "AWS::SageMaker::NotebookInstance",
                account_id,
                region,
            )
        ]
    except Exception as e:
        return [
            _not_assessed(
                "sagemaker-notebook-root-access",
                "SageMaker notebook root access check error",
                f"Unexpected error: {e}",
                "AWS::SageMaker::NotebookInstance",
                account_id,
                region,
            )
        ]

    if not notebooks:
        return [
            Finding(
                check_id="sagemaker-notebook-root-access",
                title="No SageMaker notebook instances found",
                description="No notebook instances to evaluate.",
                severity=Severity.INFO,
                status=ComplianceStatus.NOT_APPLICABLE,
                domain=CheckDomain.AI_GOVERNANCE,
                resource_type="AWS::SageMaker::NotebookInstance",
                resource_id=f"arn:aws:sagemaker:{region}:{account_id}:notebook-instances",
                region=region,
                account_id=account_id,
                cloud_provider=CloudProvider.AWS,
                soc2_controls=["CC6.1", "CC6.3"],
            )
        ]

    findings: list[Finding] = []
    for nb in notebooks:
        nb_name = nb["NotebookInstanceName"]
        try:
            detail = sm.describe_notebook_instance(NotebookInstanceName=nb_name)
            nb_arn = detail.get(
                "NotebookInstanceArn",
                f"arn:aws:sagemaker:{region}:{account_id}:notebook-instance/{nb_name}",
            )
            root_access = detail.get("RootAccess", "Enabled")

            if root_access == "Disabled":
                findings.append(
                    Finding(
                        check_id="sagemaker-notebook-root-access",
                        title=f"Notebook '{nb_name}' has root access disabled",
                        description="Root access is disabled on this notebook instance.",
                        severity=Severity.INFO,
                        status=ComplianceStatus.PASS,
                        domain=CheckDomain.AI_GOVERNANCE,
                        resource_type="AWS::SageMaker::NotebookInstance",
                        resource_id=nb_arn,
                        region=region,
                        account_id=account_id,
                        cloud_provider=CloudProvider.AWS,
                        details={"notebook_name": nb_name},
                        soc2_controls=["CC6.1", "CC6.3"],
                    )
                )
            else:
                findings.append(
                    Finding(
                        check_id="sagemaker-notebook-root-access",
                        title=f"Notebook '{nb_name}' has root access enabled",
                        description="Root access is enabled, which may allow privilege escalation.",
                        severity=Severity.MEDIUM,
                        status=ComplianceStatus.FAIL,
                        domain=CheckDomain.AI_GOVERNANCE,
                        resource_type="AWS::SageMaker::NotebookInstance",
                        resource_id=nb_arn,
                        region=region,
                        account_id=account_id,
                        cloud_provider=CloudProvider.AWS,
                        remediation="Disable root access on SageMaker notebook instances.",
                        details={"notebook_name": nb_name, "root_access": root_access},
                        soc2_controls=["CC6.1", "CC6.3"],
                    )
                )
        except ClientError as e:
            logger.debug("Failed to describe notebook %s: %s", nb_name, e)

    return findings


# ---------------------------------------------------------------------------
# Lambda AI API key check
# ---------------------------------------------------------------------------


def check_lambda_ai_api_keys_not_hardcoded(
    client: AWSClient, account_id: str, region: str
) -> list[Finding]:
    """Check Lambda functions do not store AI API keys as plaintext env vars."""
    try:
        lam = client.client("lambda")
        paginator = lam.get_paginator("list_functions")
    except ClientError as e:
        return [
            _not_assessed(
                "lambda-ai-api-keys-not-hardcoded",
                "Unable to check Lambda functions",
                f"API call failed: {e}",
                "AWS::Lambda::Function",
                account_id,
                region,
            )
        ]
    except Exception as e:
        return [
            _not_assessed(
                "lambda-ai-api-keys-not-hardcoded",
                "Lambda AI key check error",
                f"Unexpected error: {e}",
                "AWS::Lambda::Function",
                account_id,
                region,
            )
        ]

    findings: list[Finding] = []
    functions_checked = 0

    try:
        for page in paginator.paginate(MaxItems=500):
            for fn in page.get("Functions", []):
                functions_checked += 1
                fn_name = fn["FunctionName"]
                fn_arn = fn.get(
                    "FunctionArn", f"arn:aws:lambda:{region}:{account_id}:function:{fn_name}"
                )
                env_vars = fn.get("Environment", {}).get("Variables", {})
                if not env_vars:
                    continue

                hardcoded_keys: list[str] = []
                for var_name, var_value in env_vars.items():
                    for pattern in AI_API_KEY_PATTERNS:
                        if pattern.search(var_name):
                            # Check if value looks like a Secrets Manager / SSM reference
                            if not _is_secrets_reference(var_value):
                                hardcoded_keys.append(var_name)
                            break

                if hardcoded_keys:
                    findings.append(
                        Finding(
                            check_id="lambda-ai-api-keys-not-hardcoded",
                            title=f"Lambda '{fn_name}' has hardcoded AI API keys",
                            description=(
                                f"Found {len(hardcoded_keys)} AI API key(s) stored as plaintext "
                                f"environment variables: {', '.join(hardcoded_keys)}"
                            ),
                            severity=Severity.CRITICAL,
                            status=ComplianceStatus.FAIL,
                            domain=CheckDomain.AI_GOVERNANCE,
                            resource_type="AWS::Lambda::Function",
                            resource_id=fn_arn,
                            region=region,
                            account_id=account_id,
                            cloud_provider=CloudProvider.AWS,
                            remediation=(
                                "Move AI API keys to AWS Secrets Manager or SSM Parameter Store "
                                "and reference them at runtime instead of env vars."
                            ),
                            details={"function_name": fn_name, "hardcoded_vars": hardcoded_keys},
                            soc2_controls=["CC6.1", "CC6.7"],
                        )
                    )
    except ClientError as e:
        logger.debug("Error paginating Lambda functions: %s", e)

    if not findings:
        findings.append(
            Finding(
                check_id="lambda-ai-api-keys-not-hardcoded",
                title=f"No hardcoded AI API keys in Lambda ({functions_checked} functions checked)",
                description="No Lambda functions found with plaintext AI API keys in environment variables.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.AI_GOVERNANCE,
                resource_type="AWS::Lambda::Function",
                resource_id=f"arn:aws:lambda:{region}:{account_id}:functions",
                region=region,
                account_id=account_id,
                cloud_provider=CloudProvider.AWS,
                details={"functions_checked": functions_checked},
                soc2_controls=["CC6.1", "CC6.7"],
            )
        )

    return findings


def _is_secrets_reference(value: str) -> bool:
    """Check if a value looks like a reference to Secrets Manager or SSM."""
    if not value:
        return False
    # Common patterns for referencing secrets
    lower = value.lower()
    return any(
        indicator in lower
        for indicator in [
            "arn:aws:secretsmanager:",
            "arn:aws:ssm:",
            "{{resolve:",
            "ssm:",
            "secretsmanager:",
        ]
    )


# ---------------------------------------------------------------------------
# S3 training data checks
# ---------------------------------------------------------------------------


def _find_ml_buckets(client: AWSClient) -> list[dict[str, Any]]:
    """Find S3 buckets whose name or tags suggest ML/training data."""
    try:
        s3 = client.client("s3")
        buckets = s3.list_buckets().get("Buckets", [])
    except ClientError:
        return []

    ml_buckets: list[dict[str, Any]] = []
    for bucket in buckets:
        name = bucket["Name"]
        is_ml_name = any(p.search(name) for p in ML_BUCKET_PATTERNS)

        # Check tags if name doesn't match
        is_ml_tagged = False
        if not is_ml_name:
            try:
                tags_resp = s3.get_bucket_tagging(Bucket=name)
                tags = tags_resp.get("TagSet", [])
                for tag in tags:
                    tag_str = f"{tag.get('Key', '')} {tag.get('Value', '')}"
                    if any(p.search(tag_str) for p in ML_BUCKET_PATTERNS):
                        is_ml_tagged = True
                        break
            except ClientError:
                # No tags or access denied
                pass

        if is_ml_name or is_ml_tagged:
            ml_buckets.append({"name": name, "matched_by": "name" if is_ml_name else "tags"})

    return ml_buckets


def check_s3_training_data_encrypted(
    client: AWSClient, account_id: str, region: str
) -> list[Finding]:
    """Check S3 buckets with ML training data have encryption enabled."""
    ml_buckets = _find_ml_buckets(client)

    if not ml_buckets:
        return [
            Finding(
                check_id="s3-training-data-encrypted",
                title="No ML/training data S3 buckets found",
                description="No S3 buckets with names or tags matching ML/training data patterns.",
                severity=Severity.INFO,
                status=ComplianceStatus.NOT_APPLICABLE,
                domain=CheckDomain.AI_GOVERNANCE,
                resource_type="AWS::S3::Bucket",
                resource_id=f"arn:aws:s3:::{account_id}",
                region=region,
                account_id=account_id,
                cloud_provider=CloudProvider.AWS,
                soc2_controls=["CC6.1"],
            )
        ]

    findings: list[Finding] = []
    s3 = client.client("s3")

    for bucket_info in ml_buckets:
        bucket_name = bucket_info["name"]
        try:
            enc_resp = s3.get_bucket_encryption(Bucket=bucket_name)
            rules = enc_resp.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            has_kms = any(
                rule.get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm") == "aws:kms"
                for rule in rules
            )
            has_any_enc = len(rules) > 0

            if has_kms:
                findings.append(
                    Finding(
                        check_id="s3-training-data-encrypted",
                        title=f"Bucket '{bucket_name}' has KMS encryption",
                        description="ML data bucket is encrypted with AWS KMS.",
                        severity=Severity.INFO,
                        status=ComplianceStatus.PASS,
                        domain=CheckDomain.AI_GOVERNANCE,
                        resource_type="AWS::S3::Bucket",
                        resource_id=f"arn:aws:s3:::{bucket_name}",
                        region=region,
                        account_id=account_id,
                        cloud_provider=CloudProvider.AWS,
                        details={"bucket_name": bucket_name, "encryption": "aws:kms"},
                        soc2_controls=["CC6.1"],
                    )
                )
            elif has_any_enc:
                findings.append(
                    Finding(
                        check_id="s3-training-data-encrypted",
                        title=f"Bucket '{bucket_name}' uses SSE-S3 (not KMS)",
                        description="ML data bucket has S3-managed encryption but not KMS.",
                        severity=Severity.LOW,
                        status=ComplianceStatus.PARTIAL,
                        domain=CheckDomain.AI_GOVERNANCE,
                        resource_type="AWS::S3::Bucket",
                        resource_id=f"arn:aws:s3:::{bucket_name}",
                        region=region,
                        account_id=account_id,
                        cloud_provider=CloudProvider.AWS,
                        remediation="Upgrade to KMS encryption for training data buckets.",
                        details={"bucket_name": bucket_name, "encryption": "AES256"},
                        soc2_controls=["CC6.1"],
                    )
                )
            else:
                findings.append(
                    Finding(
                        check_id="s3-training-data-encrypted",
                        title=f"Bucket '{bucket_name}' has no encryption configured",
                        description="ML data bucket has no server-side encryption.",
                        severity=Severity.HIGH,
                        status=ComplianceStatus.FAIL,
                        domain=CheckDomain.AI_GOVERNANCE,
                        resource_type="AWS::S3::Bucket",
                        resource_id=f"arn:aws:s3:::{bucket_name}",
                        region=region,
                        account_id=account_id,
                        cloud_provider=CloudProvider.AWS,
                        remediation="Enable KMS encryption on this training data bucket.",
                        details={"bucket_name": bucket_name},
                        soc2_controls=["CC6.1"],
                    )
                )
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "ServerSideEncryptionConfigurationNotFoundError":
                findings.append(
                    Finding(
                        check_id="s3-training-data-encrypted",
                        title=f"Bucket '{bucket_name}' has no encryption configured",
                        description="ML data bucket has no server-side encryption configuration.",
                        severity=Severity.HIGH,
                        status=ComplianceStatus.FAIL,
                        domain=CheckDomain.AI_GOVERNANCE,
                        resource_type="AWS::S3::Bucket",
                        resource_id=f"arn:aws:s3:::{bucket_name}",
                        region=region,
                        account_id=account_id,
                        cloud_provider=CloudProvider.AWS,
                        remediation="Enable KMS encryption on this training data bucket.",
                        details={"bucket_name": bucket_name},
                        soc2_controls=["CC6.1"],
                    )
                )
            else:
                logger.debug("Failed to check encryption for %s: %s", bucket_name, e)

    return findings


def check_s3_training_data_versioned(
    client: AWSClient, account_id: str, region: str
) -> list[Finding]:
    """Check S3 buckets with ML training data have versioning enabled."""
    ml_buckets = _find_ml_buckets(client)

    if not ml_buckets:
        return [
            Finding(
                check_id="s3-training-data-versioned",
                title="No ML/training data S3 buckets found",
                description="No S3 buckets with names or tags matching ML/training data patterns.",
                severity=Severity.INFO,
                status=ComplianceStatus.NOT_APPLICABLE,
                domain=CheckDomain.AI_GOVERNANCE,
                resource_type="AWS::S3::Bucket",
                resource_id=f"arn:aws:s3:::{account_id}",
                region=region,
                account_id=account_id,
                cloud_provider=CloudProvider.AWS,
                soc2_controls=["CC8.1"],
            )
        ]

    findings: list[Finding] = []
    s3 = client.client("s3")

    for bucket_info in ml_buckets:
        bucket_name = bucket_info["name"]
        try:
            ver_resp = s3.get_bucket_versioning(Bucket=bucket_name)
            status = ver_resp.get("Status", "Disabled")

            if status == "Enabled":
                findings.append(
                    Finding(
                        check_id="s3-training-data-versioned",
                        title=f"Bucket '{bucket_name}' has versioning enabled",
                        description="ML data bucket has versioning enabled for data lineage.",
                        severity=Severity.INFO,
                        status=ComplianceStatus.PASS,
                        domain=CheckDomain.AI_GOVERNANCE,
                        resource_type="AWS::S3::Bucket",
                        resource_id=f"arn:aws:s3:::{bucket_name}",
                        region=region,
                        account_id=account_id,
                        cloud_provider=CloudProvider.AWS,
                        details={"bucket_name": bucket_name, "versioning": status},
                        soc2_controls=["CC8.1"],
                    )
                )
            elif status == "Suspended":
                findings.append(
                    Finding(
                        check_id="s3-training-data-versioned",
                        title=f"Bucket '{bucket_name}' has versioning suspended",
                        description="Versioning was previously enabled but is now suspended.",
                        severity=Severity.MEDIUM,
                        status=ComplianceStatus.FAIL,
                        domain=CheckDomain.AI_GOVERNANCE,
                        resource_type="AWS::S3::Bucket",
                        resource_id=f"arn:aws:s3:::{bucket_name}",
                        region=region,
                        account_id=account_id,
                        cloud_provider=CloudProvider.AWS,
                        remediation="Re-enable versioning on this training data bucket.",
                        details={"bucket_name": bucket_name, "versioning": status},
                        soc2_controls=["CC8.1"],
                    )
                )
            else:
                findings.append(
                    Finding(
                        check_id="s3-training-data-versioned",
                        title=f"Bucket '{bucket_name}' has no versioning",
                        description="ML data bucket does not have versioning enabled.",
                        severity=Severity.MEDIUM,
                        status=ComplianceStatus.FAIL,
                        domain=CheckDomain.AI_GOVERNANCE,
                        resource_type="AWS::S3::Bucket",
                        resource_id=f"arn:aws:s3:::{bucket_name}",
                        region=region,
                        account_id=account_id,
                        cloud_provider=CloudProvider.AWS,
                        remediation="Enable versioning on this training data bucket for data lineage.",
                        details={"bucket_name": bucket_name, "versioning": "Disabled"},
                        soc2_controls=["CC8.1"],
                    )
                )
        except ClientError as e:
            logger.debug("Failed to check versioning for %s: %s", bucket_name, e)

    return findings


# ---------------------------------------------------------------------------
# CloudTrail AI events check
# ---------------------------------------------------------------------------


def check_cloudtrail_ai_events(client: AWSClient, account_id: str, region: str) -> list[Finding]:
    """Check CloudTrail is configured to log SageMaker and Bedrock data events."""
    try:
        ct = client.client("cloudtrail")
        trails_resp = ct.describe_trails()
        trails = trails_resp.get("trailList", [])
    except ClientError as e:
        return [
            _not_assessed(
                "cloudtrail-ai-events",
                "Unable to check CloudTrail configuration",
                f"API call failed: {e}",
                "AWS::CloudTrail::Trail",
                account_id,
                region,
            )
        ]
    except Exception as e:
        return [
            _not_assessed(
                "cloudtrail-ai-events",
                "CloudTrail AI events check error",
                f"Unexpected error: {e}",
                "AWS::CloudTrail::Trail",
                account_id,
                region,
            )
        ]

    if not trails:
        return [
            Finding(
                check_id="cloudtrail-ai-events",
                title="No CloudTrail trails configured",
                description="Cannot evaluate AI event logging without CloudTrail.",
                severity=Severity.HIGH,
                status=ComplianceStatus.FAIL,
                domain=CheckDomain.AI_GOVERNANCE,
                resource_type="AWS::CloudTrail::Trail",
                resource_id=f"arn:aws:cloudtrail:{region}:{account_id}:trail",
                region=region,
                account_id=account_id,
                cloud_provider=CloudProvider.AWS,
                remediation="Enable CloudTrail with data events for SageMaker and Bedrock.",
                soc2_controls=["CC7.1", "CC8.1"],
            )
        ]

    # Check each trail for AI service data event selectors
    ai_event_sources = {"sagemaker.amazonaws.com", "bedrock.amazonaws.com"}
    trails_with_ai_events: list[str] = []

    for trail in trails:
        trail_arn = trail.get("TrailARN", "")
        trail_name = trail.get("Name", "unknown")
        try:
            # Check event selectors (basic)
            selectors_resp = ct.get_event_selectors(TrailName=trail_name)

            # Check basic event selectors
            for selector in selectors_resp.get("EventSelectors", []):
                data_resources = selector.get("DataResources", [])
                for dr in data_resources:
                    dr_type = dr.get("Type", "")
                    # Data events for SageMaker / Bedrock
                    if "SageMaker" in dr_type or "Bedrock" in dr_type:
                        trails_with_ai_events.append(trail_name)
                        break

            # Check advanced event selectors
            for adv_selector in selectors_resp.get("AdvancedEventSelectors", []):
                field_selectors = adv_selector.get("FieldSelectors", [])
                for fs in field_selectors:
                    field = fs.get("Field", "")
                    equals = fs.get("Equals", [])
                    if field == "eventSource" and any(src in ai_event_sources for src in equals):
                        trails_with_ai_events.append(trail_name)
                        break
                    # Check for resource type selectors
                    if field == "resources.type" and any(
                        "SageMaker" in v or "Bedrock" in v for v in equals
                    ):
                        trails_with_ai_events.append(trail_name)
                        break

        except ClientError as e:
            logger.debug("Failed to get event selectors for %s: %s", trail_name, e)

    if trails_with_ai_events:
        return [
            Finding(
                check_id="cloudtrail-ai-events",
                title=f"CloudTrail logs AI service events ({len(set(trails_with_ai_events))} trail(s))",
                description=(
                    f"Trail(s) {', '.join(set(trails_with_ai_events))} are configured "
                    "to capture SageMaker and/or Bedrock data events."
                ),
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.AI_GOVERNANCE,
                resource_type="AWS::CloudTrail::Trail",
                resource_id=trails[0].get("TrailARN", ""),
                region=region,
                account_id=account_id,
                cloud_provider=CloudProvider.AWS,
                details={"trails_with_ai_events": list(set(trails_with_ai_events))},
                soc2_controls=["CC7.1", "CC8.1"],
            )
        ]

    return [
        Finding(
            check_id="cloudtrail-ai-events",
            title="CloudTrail not logging AI service data events",
            description=(
                "No CloudTrail trail is configured to capture SageMaker or Bedrock data events. "
                "Management events are logged, but data-plane activity is not auditable."
            ),
            severity=Severity.MEDIUM,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.AI_GOVERNANCE,
            resource_type="AWS::CloudTrail::Trail",
            resource_id=trails[0].get("TrailARN", ""),
            region=region,
            account_id=account_id,
            cloud_provider=CloudProvider.AWS,
            remediation=(
                "Add advanced event selectors for SageMaker and Bedrock data events "
                "to at least one CloudTrail trail."
            ),
            details={"trails_checked": [t.get("Name") for t in trails]},
            soc2_controls=["CC7.1", "CC8.1"],
        )
    ]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _not_assessed(
    check_id: str,
    title: str,
    description: str,
    resource_type: str,
    account_id: str,
    region: str,
) -> Finding:
    """Create a NOT_ASSESSED finding for checks that could not run."""
    return Finding(
        check_id=check_id,
        title=title,
        description=description,
        severity=Severity.MEDIUM,
        status=ComplianceStatus.NOT_ASSESSED,
        domain=CheckDomain.AI_GOVERNANCE,
        resource_type=resource_type,
        resource_id=f"arn:aws:{resource_type.split('::')[1].lower() if '::' in resource_type else 'unknown'}:{region}:{account_id}",
        region=region,
        account_id=account_id,
        cloud_provider=CloudProvider.AWS,
    )
