"""AWS AI/ML service discovery for Whitney.

Discovers SageMaker, Bedrock, Comprehend, and Lambda functions with
AI-related environment variables in the connected AWS account.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from botocore.exceptions import ClientError

from shasta.aws.client import AWSClient

logger = logging.getLogger(__name__)

# Environment variable patterns that indicate AI API key usage
AI_ENV_VAR_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"OPENAI_API_KEY", re.IGNORECASE),
    re.compile(r"ANTHROPIC_API_KEY", re.IGNORECASE),
    re.compile(r"COHERE_API_KEY", re.IGNORECASE),
    re.compile(r"HUGGING_FACE", re.IGNORECASE),
    re.compile(r"HF_TOKEN", re.IGNORECASE),
    re.compile(r"REPLICATE_API_TOKEN", re.IGNORECASE),
    re.compile(r"GOOGLE_AI_API_KEY", re.IGNORECASE),
    re.compile(r"PALM_API_KEY", re.IGNORECASE),
    re.compile(r"STABILITY_API_KEY", re.IGNORECASE),
    re.compile(r"AI21_API_KEY", re.IGNORECASE),
    re.compile(r"MISTRAL_API_KEY", re.IGNORECASE),
    re.compile(r"TOGETHER_API_KEY", re.IGNORECASE),
    re.compile(r"GROQ_API_KEY", re.IGNORECASE),
    re.compile(r"AZURE_OPENAI", re.IGNORECASE),
    re.compile(r"BEDROCK", re.IGNORECASE),
]


def discover_aws_ai_services(client: AWSClient) -> dict[str, Any]:
    """Discover AI/ML services in the AWS account.

    Returns a dict with service names as keys and discovery details
    (counts, resource lists) as values. Iterates all enabled regions
    since Bedrock and SageMaker are regional services.
    """
    default_region = client.account_info.region if client.account_info else "us-east-1"

    try:
        regions = client.get_enabled_regions()
    except ClientError:
        regions = [default_region]

    results: dict[str, Any] = {
        "sagemaker": {"available": False, "endpoints": [], "training_jobs": [], "models": [], "total_resources": 0},
        "bedrock": {"available": False, "models": [], "total_resources": 0},
        "comprehend": {"available": False, "endpoints": [], "total_resources": 0},
        "lambda_ai": {"available": False, "functions": [], "total_resources": 0},
    }

    for r in regions:
        try:
            rc = client.for_region(r)
            for key, discover_fn in [
                ("sagemaker", _discover_sagemaker),
                ("bedrock", _discover_bedrock),
                ("comprehend", _discover_comprehend),
                ("lambda_ai", _discover_lambda_ai),
            ]:
                try:
                    regional = discover_fn(rc)
                    if isinstance(regional, dict) and regional.get("available"):
                        results[key]["available"] = True
                        results[key]["total_resources"] += regional.get("total_resources", 0)
                        # Merge list fields
                        for field_key, field_val in regional.items():
                            if isinstance(field_val, list) and field_key in results[key]:
                                results[key][field_key].extend(field_val)
                except Exception as e:
                    logger.warning("Discovery %s failed in %s: %s", key, r, e)
        except ClientError:
            continue

    # Compute totals
    total = 0
    for svc, info in results.items():
        if isinstance(info, dict):
            total += info.get("total_resources", 0)
    results["total_ai_resources"] = total

    return results


def _discover_sagemaker(client: AWSClient) -> dict[str, Any]:
    """Discover SageMaker endpoints, training jobs, and models."""
    result: dict[str, Any] = {
        "available": False,
        "endpoints": [],
        "training_jobs": [],
        "models": [],
        "total_resources": 0,
    }

    try:
        sm = client.client("sagemaker")

        # List endpoints
        try:
            resp = sm.list_endpoints(MaxResults=100)
            endpoints = resp.get("Endpoints", [])
            result["endpoints"] = [
                {
                    "name": ep["EndpointName"],
                    "status": ep.get("EndpointStatus", "Unknown"),
                    "creation_time": str(ep.get("CreationTime", "")),
                }
                for ep in endpoints
            ]
        except ClientError as e:
            logger.debug("SageMaker list_endpoints failed: %s", e)

        # List training jobs
        try:
            resp = sm.list_training_jobs(MaxResults=100)
            jobs = resp.get("TrainingJobSummaries", [])
            result["training_jobs"] = [
                {
                    "name": j["TrainingJobName"],
                    "status": j.get("TrainingJobStatus", "Unknown"),
                    "creation_time": str(j.get("CreationTime", "")),
                }
                for j in jobs
            ]
        except ClientError as e:
            logger.debug("SageMaker list_training_jobs failed: %s", e)

        # List models
        try:
            resp = sm.list_models(MaxResults=100)
            models = resp.get("Models", [])
            result["models"] = [
                {
                    "name": m["ModelName"],
                    "creation_time": str(m.get("CreationTime", "")),
                }
                for m in models
            ]
        except ClientError as e:
            logger.debug("SageMaker list_models failed: %s", e)

        total = len(result["endpoints"]) + len(result["training_jobs"]) + len(result["models"])
        result["total_resources"] = total
        result["available"] = True

    except ClientError as e:
        logger.debug("SageMaker service not accessible: %s", e)
    except Exception as e:
        logger.warning("Unexpected error discovering SageMaker: %s", e)

    return result


def _discover_bedrock(client: AWSClient) -> dict[str, Any]:
    """Discover Bedrock foundation models and guardrails."""
    result: dict[str, Any] = {
        "available": False,
        "foundation_models": [],
        "guardrails": [],
        "total_resources": 0,
    }

    try:
        bedrock = client.client("bedrock")

        # List foundation models
        try:
            resp = bedrock.list_foundation_models()
            models = resp.get("modelSummaries", [])
            result["foundation_models"] = [
                {
                    "model_id": m.get("modelId", ""),
                    "model_name": m.get("modelName", ""),
                    "provider": m.get("providerName", ""),
                }
                for m in models
            ]
        except ClientError as e:
            logger.debug("Bedrock list_foundation_models failed: %s", e)

        # List guardrails
        try:
            resp = bedrock.list_guardrails(maxResults=100)
            guardrails = resp.get("guardrails", [])
            result["guardrails"] = [
                {
                    "id": g.get("id", ""),
                    "name": g.get("name", ""),
                    "status": g.get("status", ""),
                }
                for g in guardrails
            ]
        except ClientError as e:
            logger.debug("Bedrock list_guardrails failed: %s", e)

        total = len(result["foundation_models"]) + len(result["guardrails"])
        result["total_resources"] = total
        result["available"] = True

    except ClientError as e:
        logger.debug("Bedrock service not accessible: %s", e)
    except Exception as e:
        logger.warning("Unexpected error discovering Bedrock: %s", e)

    return result


def _discover_comprehend(client: AWSClient) -> dict[str, Any]:
    """Discover Comprehend endpoints."""
    result: dict[str, Any] = {
        "available": False,
        "endpoints": [],
        "total_resources": 0,
    }

    try:
        comp = client.client("comprehend")

        try:
            resp = comp.list_endpoints(MaxResults=100)
            endpoints = resp.get("EndpointPropertiesList", [])
            result["endpoints"] = [
                {
                    "arn": ep.get("EndpointArn", ""),
                    "status": ep.get("Status", "Unknown"),
                    "model_arn": ep.get("ModelArn", ""),
                }
                for ep in endpoints
            ]
            result["total_resources"] = len(endpoints)
            result["available"] = True
        except ClientError as e:
            logger.debug("Comprehend list_endpoints failed: %s", e)

    except ClientError as e:
        logger.debug("Comprehend service not accessible: %s", e)
    except Exception as e:
        logger.warning("Unexpected error discovering Comprehend: %s", e)

    return result


def _discover_lambda_ai(client: AWSClient) -> dict[str, Any]:
    """Discover Lambda functions with AI-related environment variables."""
    result: dict[str, Any] = {
        "available": False,
        "functions_with_ai_vars": [],
        "total_resources": 0,
    }

    try:
        lam = client.client("lambda")
        paginator = lam.get_paginator("list_functions")

        for page in paginator.paginate(MaxItems=500):
            for fn in page.get("Functions", []):
                env_vars = fn.get("Environment", {}).get("Variables", {})
                if not env_vars:
                    continue

                matched_vars = []
                for var_name in env_vars:
                    for pattern in AI_ENV_VAR_PATTERNS:
                        if pattern.search(var_name):
                            matched_vars.append(var_name)
                            break

                if matched_vars:
                    result["functions_with_ai_vars"].append(
                        {
                            "function_name": fn["FunctionName"],
                            "function_arn": fn.get("FunctionArn", ""),
                            "runtime": fn.get("Runtime", ""),
                            "ai_env_vars": matched_vars,
                        }
                    )

        result["total_resources"] = len(result["functions_with_ai_vars"])
        result["available"] = True

    except ClientError as e:
        logger.debug("Lambda not accessible: %s", e)
    except Exception as e:
        logger.warning("Unexpected error discovering Lambda AI functions: %s", e)

    return result
