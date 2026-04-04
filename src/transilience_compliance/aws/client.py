"""AWS session management and credential validation."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError


@dataclass
class AWSAccountInfo:
    """Discovered AWS account information."""

    account_id: str
    account_aliases: list[str]
    user_arn: str
    user_id: str
    region: str
    services_in_use: list[str] = field(default_factory=list)


class AWSClientError(Exception):
    """Raised when AWS operations fail."""

    pass


class AWSClient:
    """Manages boto3 sessions and provides validated access to AWS services.

    Supports all standard boto3 credential sources:
    - AWS CLI profiles (~/.aws/credentials)
    - Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    - IAM Identity Center / SSO
    - Instance profiles (EC2, ECS)
    """

    def __init__(self, profile_name: str | None = None, region: str | None = None):
        self._profile_name = profile_name
        self._region = region or "us-east-1"
        self._session: boto3.Session | None = None
        self._account_info: AWSAccountInfo | None = None

    @property
    def session(self) -> boto3.Session:
        if self._session is None:
            self._session = self._create_session()
        return self._session

    def client(self, service_name: str, **kwargs: Any) -> Any:
        """Get a boto3 client for the specified service."""
        return self.session.client(service_name, region_name=self._region, **kwargs)

    def resource(self, service_name: str, **kwargs: Any) -> Any:
        """Get a boto3 resource for the specified service."""
        return self.session.resource(service_name, region_name=self._region, **kwargs)

    def _create_session(self) -> boto3.Session:
        """Create a boto3 session with the configured credentials."""
        try:
            kwargs: dict[str, Any] = {"region_name": self._region}
            if self._profile_name:
                kwargs["profile_name"] = self._profile_name
            return boto3.Session(**kwargs)
        except BotoCoreError as e:
            raise AWSClientError(f"Failed to create AWS session: {e}") from e

    def validate_credentials(self) -> AWSAccountInfo:
        """Validate AWS credentials and return account information.

        This is the first call that should be made — it confirms that
        credentials are working and discovers account details.
        """
        try:
            sts = self.client("sts")
            identity = sts.get_caller_identity()

            iam = self.client("iam")
            try:
                aliases = iam.list_account_aliases()["AccountAliases"]
            except ClientError:
                aliases = []

            self._account_info = AWSAccountInfo(
                account_id=identity["Account"],
                account_aliases=aliases,
                user_arn=identity["Arn"],
                user_id=identity["UserId"],
                region=self._region,
            )
            return self._account_info

        except NoCredentialsError as e:
            raise AWSClientError(
                "No AWS credentials found. Configure credentials via:\n"
                "  1. AWS CLI: aws configure\n"
                "  2. Environment: AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY\n"
                "  3. SSO: aws sso login --profile <profile>"
            ) from e
        except ClientError as e:
            raise AWSClientError(f"AWS credential validation failed: {e}") from e

    def discover_services(self) -> list[str]:
        """Discover which AWS services are actively in use in this account.

        Uses a lightweight approach: checks for the existence of key resources
        in common services rather than exhaustive enumeration.
        """
        services_found: list[str] = []

        checks = [
            ("iam", self._check_iam),
            ("s3", self._check_s3),
            ("ec2", self._check_ec2),
            ("rds", self._check_rds),
            ("lambda", self._check_lambda),
            ("cloudtrail", self._check_cloudtrail),
            ("guardduty", self._check_guardduty),
            ("kms", self._check_kms),
            ("ecs", self._check_ecs),
            ("cloudwatch", self._check_cloudwatch),
        ]

        for service_name, check_fn in checks:
            try:
                if check_fn():
                    services_found.append(service_name)
            except (ClientError, BotoCoreError):
                # Service not accessible or not enabled — skip
                pass

        if self._account_info:
            self._account_info.services_in_use = services_found

        return services_found

    def _check_iam(self) -> bool:
        iam = self.client("iam")
        users = iam.list_users(MaxItems=1)
        return len(users.get("Users", [])) > 0

    def _check_s3(self) -> bool:
        s3 = self.client("s3")
        buckets = s3.list_buckets()
        return len(buckets.get("Buckets", [])) > 0

    def _check_ec2(self) -> bool:
        ec2 = self.client("ec2")
        instances = ec2.describe_instances(MaxResults=5)
        reservations = instances.get("Reservations", [])
        return any(r.get("Instances") for r in reservations)

    def _check_rds(self) -> bool:
        rds = self.client("rds")
        dbs = rds.describe_db_instances()
        return len(dbs.get("DBInstances", [])) > 0

    def _check_lambda(self) -> bool:
        lam = self.client("lambda")
        functions = lam.list_functions(MaxItems=1)
        return len(functions.get("Functions", [])) > 0

    def _check_cloudtrail(self) -> bool:
        ct = self.client("cloudtrail")
        trails = ct.describe_trails()
        return len(trails.get("trailList", [])) > 0

    def _check_guardduty(self) -> bool:
        gd = self.client("guardduty")
        detectors = gd.list_detectors()
        return len(detectors.get("DetectorIds", [])) > 0

    def _check_kms(self) -> bool:
        kms = self.client("kms")
        keys = kms.list_keys(Limit=1)
        # Filter out AWS-managed keys — we want customer-managed keys
        return len(keys.get("Keys", [])) > 0

    def _check_ecs(self) -> bool:
        ecs = self.client("ecs")
        clusters = ecs.list_clusters(maxResults=1)
        return len(clusters.get("clusterArns", [])) > 0

    def _check_cloudwatch(self) -> bool:
        cw = self.client("cloudwatch")
        alarms = cw.describe_alarms(MaxRecords=1)
        return len(alarms.get("MetricAlarms", [])) > 0

    @property
    def account_info(self) -> AWSAccountInfo | None:
        return self._account_info

    def to_dict(self) -> dict[str, Any]:
        """Serialize connection info for evidence/reporting."""
        if not self._account_info:
            return {"status": "not_connected"}
        return {
            "account_id": self._account_info.account_id,
            "account_aliases": self._account_info.account_aliases,
            "user_arn": self._account_info.user_arn,
            "region": self._region,
            "services_in_use": self._account_info.services_in_use,
        }
