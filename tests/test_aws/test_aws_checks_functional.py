"""Functional tests for AWS check modules using moto.

Tests the actual check functions against mocked AWS services to verify
they return correct Finding objects with accurate status, severity, and
check_id values for both compliant and non-compliant scenarios.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import boto3
import pytest
from moto import mock_aws

from shasta.aws.client import AWSClient
from shasta.aws.iam import (
    check_access_key_rotation,
    check_password_policy,
    check_root_account,
    check_user_direct_policies,
    check_user_mfa,
)
from shasta.aws.storage import (
    check_s3_encryption,
    check_s3_public_access_block,
    check_s3_ssl_only,
    check_s3_versioning,
)
from shasta.aws.encryption import (
    check_ebs_volumes,
    check_rds_encryption,
)
from shasta.aws.networking import (
    check_default_security_groups,
    check_security_groups,
    check_vpc_flow_logs,
)
from shasta.evidence.models import ComplianceStatus


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

REGION = "us-east-1"
ACCOUNT_ID = "123456789012"


def _make_aws_client() -> AWSClient:
    """Create and validate an AWSClient inside a mock_aws context."""
    client = AWSClient(region=REGION)
    client.validate_credentials()
    return client


# ===================================================================
# IAM checks
# ===================================================================


class TestPasswordPolicy:
    """Tests for check_password_policy."""

    @mock_aws
    def test_compliant_password_policy(self):
        """A password policy meeting all thresholds should PASS."""
        iam = boto3.client("iam", region_name=REGION)
        iam.update_account_password_policy(
            MinimumPasswordLength=14,
            RequireSymbols=True,
            RequireNumbers=True,
            RequireUppercaseCharacters=True,
            RequireLowercaseCharacters=True,
            MaxPasswordAge=90,
            PasswordReusePrevention=12,
        )

        account_id = _make_aws_client().account_info.account_id
        findings = check_password_policy(iam, account_id, REGION)

        assert len(findings) == 1
        assert findings[0].status == ComplianceStatus.PASS
        assert findings[0].check_id == "iam-password-policy"

    @mock_aws
    def test_weak_password_policy_fails(self):
        """A policy with many issues (>=3) should FAIL."""
        iam = boto3.client("iam", region_name=REGION)
        iam.update_account_password_policy(
            MinimumPasswordLength=8,
            RequireSymbols=False,
            RequireNumbers=False,
            RequireUppercaseCharacters=False,
            RequireLowercaseCharacters=False,
            MaxPasswordAge=365,
            PasswordReusePrevention=1,
        )

        account_id = _make_aws_client().account_info.account_id
        findings = check_password_policy(iam, account_id, REGION)

        assert len(findings) == 1
        assert findings[0].status == ComplianceStatus.FAIL
        assert findings[0].check_id == "iam-password-policy"

    @mock_aws
    def test_partial_password_policy(self):
        """A policy with 1-2 issues should be PARTIAL."""
        iam = boto3.client("iam", region_name=REGION)
        iam.update_account_password_policy(
            MinimumPasswordLength=14,
            RequireSymbols=True,
            RequireNumbers=True,
            RequireUppercaseCharacters=True,
            RequireLowercaseCharacters=True,
            MaxPasswordAge=90,
            PasswordReusePrevention=5,  # Only this one is below threshold
        )

        account_id = _make_aws_client().account_info.account_id
        findings = check_password_policy(iam, account_id, REGION)

        assert len(findings) == 1
        # 1 issue => PARTIAL (less than 3)
        assert findings[0].status == ComplianceStatus.PARTIAL
        assert findings[0].check_id == "iam-password-policy"

    @mock_aws
    def test_no_password_policy(self):
        """No custom password policy should FAIL."""
        iam = boto3.client("iam", region_name=REGION)
        # Don't set any policy — moto may have a default.
        # Delete it to ensure NoSuchEntity.
        try:
            iam.delete_account_password_policy()
        except Exception:
            pass

        account_id = _make_aws_client().account_info.account_id
        findings = check_password_policy(iam, account_id, REGION)

        assert len(findings) == 1
        assert findings[0].status == ComplianceStatus.FAIL
        assert "No IAM password policy" in findings[0].title


class TestRootAccount:
    """Tests for check_root_account (root MFA)."""

    @mock_aws
    def test_root_mfa_status(self):
        """Root MFA check should return a finding with iam-root-mfa check_id."""
        iam = boto3.client("iam", region_name=REGION)
        account_id = _make_aws_client().account_info.account_id

        findings = check_root_account(iam, account_id, REGION)

        # Should always have at least one finding for root MFA
        mfa_findings = [f for f in findings if f.check_id == "iam-root-mfa"]
        assert len(mfa_findings) == 1
        # moto does not enable root MFA by default
        assert mfa_findings[0].status in (ComplianceStatus.PASS, ComplianceStatus.FAIL)


class TestUserMfa:
    """Tests for check_user_mfa."""

    @mock_aws
    def test_user_with_console_no_mfa_fails(self):
        """A console user without MFA should FAIL."""
        iam = boto3.client("iam", region_name=REGION)
        iam.create_user(UserName="console-user")
        iam.create_login_profile(UserName="console-user", Password="P@ssw0rd123!")

        account_id = _make_aws_client().account_info.account_id
        findings = check_user_mfa(iam, account_id, REGION)

        assert len(findings) == 1
        assert findings[0].status == ComplianceStatus.FAIL
        assert findings[0].check_id == "iam-user-mfa"
        assert "console-user" in findings[0].title

    @mock_aws
    def test_user_with_console_and_mfa_passes(self):
        """A console user with MFA should PASS."""
        iam = boto3.client("iam", region_name=REGION)
        iam.create_user(UserName="secure-user")
        iam.create_login_profile(UserName="secure-user", Password="P@ssw0rd123!")
        iam.create_virtual_mfa_device(VirtualMFADeviceName="secure-user-mfa")
        iam.enable_mfa_device(
            UserName="secure-user",
            SerialNumber=f"arn:aws:iam::{_make_aws_client().account_info.account_id}:mfa/secure-user-mfa",
            AuthenticationCode1="123456",
            AuthenticationCode2="654321",
        )

        account_id = _make_aws_client().account_info.account_id
        findings = check_user_mfa(iam, account_id, REGION)

        mfa_findings = [f for f in findings if "secure-user" in f.title]
        assert len(mfa_findings) == 1
        assert mfa_findings[0].status == ComplianceStatus.PASS

    @mock_aws
    def test_user_without_console_skipped(self):
        """A user with no console access (API-only) should not generate a finding."""
        iam = boto3.client("iam", region_name=REGION)
        iam.create_user(UserName="api-only-user")
        # No login profile created

        account_id = _make_aws_client().account_info.account_id
        findings = check_user_mfa(iam, account_id, REGION)

        # No findings because user has no console access
        assert len(findings) == 0


class TestAccessKeyRotation:
    """Tests for check_access_key_rotation."""

    @mock_aws
    def test_fresh_key_passes(self):
        """An access key created today should PASS (within 90-day threshold)."""
        iam = boto3.client("iam", region_name=REGION)
        iam.create_user(UserName="fresh-key-user")
        iam.create_access_key(UserName="fresh-key-user")

        account_id = _make_aws_client().account_info.account_id
        findings = check_access_key_rotation(iam, account_id, REGION)

        key_findings = [f for f in findings if f.check_id == "iam-access-key-rotation"]
        assert len(key_findings) == 1
        assert key_findings[0].status == ComplianceStatus.PASS

    @mock_aws
    def test_no_keys_no_findings(self):
        """A user with no access keys should produce no findings."""
        iam = boto3.client("iam", region_name=REGION)
        iam.create_user(UserName="no-key-user")

        account_id = _make_aws_client().account_info.account_id
        findings = check_access_key_rotation(iam, account_id, REGION)

        assert len(findings) == 0


class TestUserDirectPolicies:
    """Tests for check_user_direct_policies."""

    @mock_aws
    def test_user_with_direct_policy_fails(self):
        """A user with a directly attached policy should FAIL."""
        iam = boto3.client("iam", region_name=REGION)
        iam.create_user(UserName="policy-user")
        # Create a custom policy (moto doesn't ship AWS managed policies)
        policy_resp = iam.create_policy(
            PolicyName="TestReadOnly",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
            }),
        )
        iam.attach_user_policy(
            UserName="policy-user",
            PolicyArn=policy_resp["Policy"]["Arn"],
        )

        account_id = _make_aws_client().account_info.account_id
        findings = check_user_direct_policies(iam, account_id, REGION)

        policy_findings = [f for f in findings if "policy-user" in f.title]
        assert len(policy_findings) == 1
        assert policy_findings[0].status == ComplianceStatus.FAIL
        assert policy_findings[0].check_id == "iam-no-direct-policies"

    @mock_aws
    def test_user_without_direct_policy_no_finding(self):
        """A user with no direct policies should produce no finding."""
        iam = boto3.client("iam", region_name=REGION)
        iam.create_user(UserName="clean-user")

        account_id = _make_aws_client().account_info.account_id
        findings = check_user_direct_policies(iam, account_id, REGION)

        # No direct policies, so no findings for this user
        assert len(findings) == 0


# ===================================================================
# Storage checks (S3)
# ===================================================================


class TestS3Encryption:
    """Tests for check_s3_encryption."""

    @mock_aws
    def test_encrypted_bucket_passes(self):
        """A bucket with SSE-S3 encryption should PASS."""
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(Bucket="encrypted-bucket")
        s3.put_bucket_encryption(
            Bucket="encrypted-bucket",
            ServerSideEncryptionConfiguration={
                "Rules": [
                    {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
                ]
            },
        )

        account_id = _make_aws_client().account_info.account_id
        findings = check_s3_encryption(s3, "encrypted-bucket", account_id, REGION)

        assert len(findings) == 1
        assert findings[0].status == ComplianceStatus.PASS
        assert findings[0].check_id == "s3-encryption-at-rest"


class TestS3Versioning:
    """Tests for check_s3_versioning."""

    @mock_aws
    def test_versioned_bucket_passes(self):
        """A bucket with versioning enabled should PASS."""
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(Bucket="versioned-bucket")
        s3.put_bucket_versioning(
            Bucket="versioned-bucket",
            VersioningConfiguration={"Status": "Enabled"},
        )

        account_id = _make_aws_client().account_info.account_id
        findings = check_s3_versioning(s3, "versioned-bucket", account_id, REGION)

        assert len(findings) == 1
        assert findings[0].status == ComplianceStatus.PASS
        assert findings[0].check_id == "s3-versioning"

    @mock_aws
    def test_unversioned_bucket_fails(self):
        """A bucket without versioning should FAIL."""
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(Bucket="unversioned-bucket")

        account_id = _make_aws_client().account_info.account_id
        findings = check_s3_versioning(s3, "unversioned-bucket", account_id, REGION)

        assert len(findings) == 1
        assert findings[0].status == ComplianceStatus.FAIL
        assert findings[0].check_id == "s3-versioning"


class TestS3PublicAccessBlock:
    """Tests for check_s3_public_access_block."""

    @mock_aws
    def test_fully_blocked_passes(self):
        """A bucket with all four public access block settings should PASS."""
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(Bucket="private-bucket")
        s3.put_public_access_block(
            Bucket="private-bucket",
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )

        account_id = _make_aws_client().account_info.account_id
        findings = check_s3_public_access_block(s3, "private-bucket", account_id, REGION)

        assert len(findings) == 1
        assert findings[0].status == ComplianceStatus.PASS
        assert findings[0].check_id == "s3-public-access-block"

    @mock_aws
    def test_partial_block_is_partial(self):
        """A bucket with only some public access block settings should be PARTIAL."""
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(Bucket="partial-bucket")
        s3.put_public_access_block(
            Bucket="partial-bucket",
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": False,
            },
        )

        account_id = _make_aws_client().account_info.account_id
        findings = check_s3_public_access_block(s3, "partial-bucket", account_id, REGION)

        assert len(findings) == 1
        assert findings[0].status == ComplianceStatus.PARTIAL
        assert findings[0].check_id == "s3-public-access-block"


class TestS3SslOnly:
    """Tests for check_s3_ssl_only."""

    @mock_aws
    def test_ssl_enforced_passes(self):
        """A bucket with a deny-non-SSL policy should PASS."""
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(Bucket="ssl-bucket")
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DenyNonSSL",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:*",
                    "Resource": [
                        "arn:aws:s3:::ssl-bucket",
                        "arn:aws:s3:::ssl-bucket/*",
                    ],
                    "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                }
            ],
        }
        s3.put_bucket_policy(Bucket="ssl-bucket", Policy=json.dumps(policy))

        account_id = _make_aws_client().account_info.account_id
        findings = check_s3_ssl_only(s3, "ssl-bucket", account_id, REGION)

        assert len(findings) == 1
        assert findings[0].status == ComplianceStatus.PASS
        assert findings[0].check_id == "s3-ssl-only"

    @mock_aws
    def test_no_policy_fails(self):
        """A bucket with no bucket policy should FAIL (SSL not enforced)."""
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(Bucket="no-policy-bucket")

        account_id = _make_aws_client().account_info.account_id
        findings = check_s3_ssl_only(s3, "no-policy-bucket", account_id, REGION)

        assert len(findings) == 1
        assert findings[0].status == ComplianceStatus.FAIL
        assert findings[0].check_id == "s3-ssl-only"

    @mock_aws
    def test_policy_without_ssl_deny_fails(self):
        """A bucket policy that does not deny non-SSL should FAIL."""
        s3 = boto3.client("s3", region_name=REGION)
        s3.create_bucket(Bucket="weak-policy-bucket")
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowPublicRead",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::weak-policy-bucket/*",
                }
            ],
        }
        s3.put_bucket_policy(Bucket="weak-policy-bucket", Policy=json.dumps(policy))

        account_id = _make_aws_client().account_info.account_id
        findings = check_s3_ssl_only(s3, "weak-policy-bucket", account_id, REGION)

        assert len(findings) == 1
        assert findings[0].status == ComplianceStatus.FAIL


# ===================================================================
# Encryption checks (EBS, RDS)
# ===================================================================


class TestEBSVolumes:
    """Tests for check_ebs_volumes."""

    @mock_aws
    def test_encrypted_volume_passes(self):
        """An encrypted EBS volume should produce a PASS finding."""
        ec2 = boto3.client("ec2", region_name=REGION)
        # Enable encryption by default so volumes are auto-encrypted
        ec2.enable_ebs_encryption_by_default()
        ec2.create_volume(
            AvailabilityZone=f"{REGION}a",
            Size=10,
            Encrypted=True,
        )

        aws_client = _make_aws_client()
        findings = check_ebs_volumes(aws_client, aws_client.account_info.account_id, REGION)

        pass_findings = [f for f in findings if f.status == ComplianceStatus.PASS]
        assert len(pass_findings) >= 1
        assert all(f.check_id == "ebs-volume-encrypted" for f in pass_findings)

    @mock_aws
    def test_unencrypted_volume_fails(self):
        """An unencrypted EBS volume should produce a FAIL finding."""
        ec2 = boto3.client("ec2", region_name=REGION)
        ec2.create_volume(
            AvailabilityZone=f"{REGION}a",
            Size=10,
            Encrypted=False,
        )

        aws_client = _make_aws_client()
        findings = check_ebs_volumes(aws_client, aws_client.account_info.account_id, REGION)

        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert len(fail_findings) >= 1
        assert all(f.check_id == "ebs-volume-encrypted" for f in fail_findings)

    @mock_aws
    def test_no_volumes_no_findings(self):
        """An account with no EBS volumes should produce no findings."""
        aws_client = _make_aws_client()
        findings = check_ebs_volumes(aws_client, aws_client.account_info.account_id, REGION)

        assert len(findings) == 0


class TestRDSEncryption:
    """Tests for check_rds_encryption."""

    @mock_aws
    def test_encrypted_rds_passes(self):
        """An encrypted RDS instance should PASS."""
        rds = boto3.client("rds", region_name=REGION)
        rds.create_db_instance(
            DBInstanceIdentifier="encrypted-db",
            DBInstanceClass="db.t3.micro",
            Engine="mysql",
            MasterUsername="admin",
            MasterUserPassword="password123!",
            StorageEncrypted=True,
        )

        aws_client = _make_aws_client()
        findings = check_rds_encryption(aws_client, aws_client.account_info.account_id, REGION)

        pass_findings = [f for f in findings if f.status == ComplianceStatus.PASS]
        assert len(pass_findings) == 1
        assert pass_findings[0].check_id == "rds-encryption-at-rest"

    @mock_aws
    def test_unencrypted_rds_fails(self):
        """An unencrypted RDS instance should FAIL."""
        rds = boto3.client("rds", region_name=REGION)
        rds.create_db_instance(
            DBInstanceIdentifier="unencrypted-db",
            DBInstanceClass="db.t3.micro",
            Engine="mysql",
            MasterUsername="admin",
            MasterUserPassword="password123!",
            StorageEncrypted=False,
        )

        aws_client = _make_aws_client()
        findings = check_rds_encryption(aws_client, aws_client.account_info.account_id, REGION)

        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert len(fail_findings) == 1
        assert fail_findings[0].check_id == "rds-encryption-at-rest"

    @mock_aws
    def test_no_rds_no_findings(self):
        """An account with no RDS instances should produce no findings."""
        aws_client = _make_aws_client()
        findings = check_rds_encryption(aws_client, aws_client.account_info.account_id, REGION)

        assert len(findings) == 0


# ===================================================================
# Networking checks
# ===================================================================


class TestSecurityGroups:
    """Tests for check_security_groups."""

    @mock_aws
    def test_restricted_sg_passes(self):
        """A security group with no 0.0.0.0/0 ingress should PASS."""
        ec2 = boto3.client("ec2", region_name=REGION)
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = vpc["Vpc"]["VpcId"]

        sg = ec2.create_security_group(
            GroupName="restricted-sg",
            Description="Restricted SG",
            VpcId=vpc_id,
        )
        sg_id = sg["GroupId"]

        # Add a rule restricted to a private CIDR
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                }
            ],
        )

        account_id = _make_aws_client().account_info.account_id
        findings = check_security_groups(ec2, account_id, REGION)

        # Find the finding for our SG (skip default SGs)
        sg_findings = [f for f in findings if f.resource_id == sg_id]
        assert len(sg_findings) == 1
        assert sg_findings[0].status == ComplianceStatus.PASS

    @mock_aws
    def test_open_ssh_fails(self):
        """A security group allowing SSH from 0.0.0.0/0 should FAIL."""
        ec2 = boto3.client("ec2", region_name=REGION)
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = vpc["Vpc"]["VpcId"]

        sg = ec2.create_security_group(
            GroupName="open-ssh-sg",
            Description="Open SSH SG",
            VpcId=vpc_id,
        )
        sg_id = sg["GroupId"]

        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        )

        account_id = _make_aws_client().account_info.account_id
        findings = check_security_groups(ec2, account_id, REGION)

        sg_findings = [f for f in findings if f.resource_id == sg_id]
        assert len(sg_findings) == 1
        assert sg_findings[0].status == ComplianceStatus.FAIL
        assert sg_findings[0].check_id == "sg-no-unrestricted-ingress"
        # SSH is a dangerous port => HIGH severity
        assert sg_findings[0].severity.value == "high"

    @mock_aws
    def test_all_traffic_open_is_critical(self):
        """A security group allowing all traffic from 0.0.0.0/0 should be CRITICAL."""
        ec2 = boto3.client("ec2", region_name=REGION)
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = vpc["Vpc"]["VpcId"]

        sg = ec2.create_security_group(
            GroupName="wide-open-sg",
            Description="Wide open SG",
            VpcId=vpc_id,
        )
        sg_id = sg["GroupId"]

        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        )

        account_id = _make_aws_client().account_info.account_id
        findings = check_security_groups(ec2, account_id, REGION)

        sg_findings = [f for f in findings if f.resource_id == sg_id]
        assert len(sg_findings) == 1
        assert sg_findings[0].status == ComplianceStatus.FAIL
        assert sg_findings[0].severity.value == "critical"


class TestVPCFlowLogs:
    """Tests for check_vpc_flow_logs."""

    @mock_aws
    def test_vpc_without_flow_logs_fails(self):
        """A VPC with no flow logs should FAIL."""
        ec2 = boto3.client("ec2", region_name=REGION)
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = vpc["Vpc"]["VpcId"]

        account_id = _make_aws_client().account_info.account_id
        findings = check_vpc_flow_logs(ec2, account_id, REGION)

        vpc_findings = [f for f in findings if f.resource_id == vpc_id]
        assert len(vpc_findings) == 1
        assert vpc_findings[0].status == ComplianceStatus.FAIL
        assert vpc_findings[0].check_id == "vpc-flow-logs-enabled"

    @mock_aws
    def test_vpc_with_flow_logs_passes(self):
        """A VPC with flow logs enabled should PASS."""
        ec2 = boto3.client("ec2", region_name=REGION)
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = vpc["Vpc"]["VpcId"]

        # Create a flow log for the VPC
        ec2.create_flow_logs(
            ResourceIds=[vpc_id],
            ResourceType="VPC",
            TrafficType="ALL",
            LogDestinationType="cloud-watch-logs",
            LogGroupName="/aws/vpc/flow-logs",
            DeliverLogsPermissionArn="arn:aws:iam::123456789012:role/flow-log-role",
        )

        account_id = _make_aws_client().account_info.account_id
        findings = check_vpc_flow_logs(ec2, account_id, REGION)

        vpc_findings = [f for f in findings if f.resource_id == vpc_id]
        assert len(vpc_findings) == 1
        assert vpc_findings[0].status == ComplianceStatus.PASS


class TestDefaultSecurityGroups:
    """Tests for check_default_security_groups."""

    @mock_aws
    def test_default_sg_with_ingress_fails(self):
        """A default SG with ingress rules should FAIL."""
        ec2 = boto3.client("ec2", region_name=REGION)
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = vpc["Vpc"]["VpcId"]

        # Get the default SG for the VPC
        sgs = ec2.describe_security_groups(
            Filters=[
                {"Name": "vpc-id", "Values": [vpc_id]},
                {"Name": "group-name", "Values": ["default"]},
            ]
        )["SecurityGroups"]
        assert len(sgs) == 1
        default_sg_id = sgs[0]["GroupId"]

        # Add an ingress rule to the default SG
        ec2.authorize_security_group_ingress(
            GroupId=default_sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 80,
                    "ToPort": 80,
                    "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                }
            ],
        )

        account_id = _make_aws_client().account_info.account_id
        findings = check_default_security_groups(ec2, account_id, REGION)

        # Find findings for our VPC's default SG
        sg_findings = [f for f in findings if f.resource_id == default_sg_id]
        assert len(sg_findings) == 1
        assert sg_findings[0].status == ComplianceStatus.FAIL
        assert sg_findings[0].check_id == "sg-default-restricted"
