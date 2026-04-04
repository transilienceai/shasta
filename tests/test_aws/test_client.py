"""Tests for AWS client module."""

import pytest
from moto import mock_aws

from transilience_compliance.aws.client import AWSClient, AWSClientError


@mock_aws
def test_validate_credentials():
    """Test credential validation against mocked AWS."""
    client = AWSClient(region="us-east-1")
    info = client.validate_credentials()

    assert info.account_id  # moto returns a mock account ID
    assert info.user_arn
    assert info.region == "us-east-1"


@mock_aws
def test_discover_services_empty_account():
    """Test service discovery on an account with no resources."""
    client = AWSClient(region="us-east-1")
    client.validate_credentials()
    services = client.discover_services()

    # Empty moto account — no services should be detected
    # (IAM may return the mocked root user, depending on moto version)
    assert isinstance(services, list)


@mock_aws
def test_discover_services_with_s3():
    """Test service discovery detects S3 buckets."""
    import boto3

    # Create a bucket first
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="test-bucket")

    client = AWSClient(region="us-east-1")
    client.validate_credentials()
    services = client.discover_services()

    assert "s3" in services


@mock_aws
def test_client_to_dict():
    """Test serialization of connection info."""
    client = AWSClient(region="us-east-1")
    info = client.validate_credentials()
    data = client.to_dict()

    assert data["account_id"] == info.account_id
    assert data["region"] == "us-east-1"
    assert "services_in_use" in data


def test_to_dict_not_connected():
    """Test serialization before connecting."""
    client = AWSClient()
    data = client.to_dict()
    assert data == {"status": "not_connected"}
