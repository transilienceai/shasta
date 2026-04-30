"""Shared fixtures for GCP tests."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from shasta.evidence.models import CheckDomain, CloudProvider


@pytest.fixture()
def mock_gcp_client():
    """A minimal GCPClient mock sufficient for smoke and unit tests."""
    client = MagicMock()
    client.project_id = "test-project"
    client.region = "us-central1"

    # account_info
    client.account_info = MagicMock()
    client.account_info.project_id = "test-project"
    client.account_info.region = "us-central1"
    client.account_info.project_number = "123456789"

    # Helpers
    client.get_enabled_regions.return_value = ["us-central1", "us-east1"]
    client.for_region.return_value = client
    client.for_project.return_value = client
    client.list_projects.return_value = [{"project_id": "test-project"}]

    # GCP service mock — returns a chainable mock for .execute()
    svc = MagicMock()
    svc.execute.return_value = {}
    client.service.return_value = svc

    # Storage client
    storage = MagicMock()
    storage.list_buckets.return_value = []
    client.storage_client.return_value = storage

    return client
