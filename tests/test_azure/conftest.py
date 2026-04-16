"""Azure mock testing infrastructure.

Provides reusable fixtures and helpers for mocking Azure SDK calls
so that Azure check modules can be tested without hitting Azure APIs.
"""

from __future__ import annotations

from unittest.mock import MagicMock, PropertyMock

import pytest

from shasta.azure.client import AzureAccountInfo, AzureClient


def make_mock_azure_client(
    subscription_id: str = "test-sub-123",
    tenant_id: str = "test-tenant-456",
    region: str = "eastus",
) -> MagicMock:
    """Create a mocked AzureClient with account_info pre-populated.

    The returned mock has ``spec=AzureClient`` so attribute access is
    validated, and ``account_info`` returns a real ``AzureAccountInfo``
    instance so that the check modules can read ``subscription_id`` etc.
    without additional mocking.
    """
    client = MagicMock(spec=AzureClient)
    client.subscription_id = subscription_id
    client.account_info = AzureAccountInfo(
        subscription_id=subscription_id,
        subscription_name="Test Subscription",
        tenant_id=tenant_id,
        user_principal="testuser@example.com",
        region=region,
    )
    # credential is needed by check_keyvault_key_expiry
    client.credential = MagicMock()
    return client


def make_mock_storage_account(
    name: str = "teststorage",
    resource_group: str = "rg-test",
    location: str = "eastus",
    min_tls: str = "TLS1_2",
    https_only: bool = True,
    allow_blob_public_access: bool = False,
    allow_shared_key_access: bool | None = None,
    allow_cross_tenant_replication: bool | None = None,
    network_default_action: str = "Allow",
    network_bypass: str = "AzureServices",
) -> MagicMock:
    """Create a mock Azure Storage Account object."""
    account = MagicMock()
    account.name = name
    account.id = (
        f"/subscriptions/test-sub-123/resourceGroups/{resource_group}"
        f"/providers/Microsoft.Storage/storageAccounts/{name}"
    )
    account.location = location
    account.minimum_tls_version = min_tls

    # HTTPS enforcement
    account.enable_https_traffic_only = https_only
    account.https_traffic_only_enabled = https_only

    # Public blob access
    account.allow_blob_public_access = allow_blob_public_access
    account.allow_nested_items_to_be_public = allow_blob_public_access

    # Shared key access
    account.allow_shared_key_access = allow_shared_key_access

    # Cross-tenant replication
    account.allow_cross_tenant_replication = allow_cross_tenant_replication

    # Encryption (Azure always has SSE)
    account.encryption = MagicMock()
    account.encryption.services.blob.enabled = True
    account.encryption.services.file.enabled = True

    # Network rules
    rules = MagicMock()
    rules.default_action = network_default_action
    rules.bypass = network_bypass
    account.network_rule_set = rules

    return account


def make_mock_nsg(
    name: str = "test-nsg",
    resource_group: str = "rg-test",
    location: str = "eastus",
    rules: list | None = None,
) -> MagicMock:
    """Create a mock Network Security Group."""
    nsg = MagicMock()
    nsg.name = name
    nsg.id = (
        f"/subscriptions/test-sub-123/resourceGroups/{resource_group}"
        f"/providers/Microsoft.Network/networkSecurityGroups/{name}"
    )
    nsg.location = location
    nsg.security_rules = rules or []
    return nsg


def make_nsg_rule(
    name: str = "test-rule",
    direction: str = "Inbound",
    access: str = "Allow",
    source_prefix: str = "10.0.0.0/8",
    source_prefixes: list | None = None,
    dest_port_range: str = "443",
    dest_port_ranges: list | None = None,
    protocol: str = "Tcp",
    priority: int = 100,
) -> MagicMock:
    """Create a mock NSG security rule."""
    rule = MagicMock()
    rule.name = name
    rule.direction = direction
    rule.access = access
    rule.source_address_prefix = source_prefix
    rule.source_address_prefixes = source_prefixes or []
    rule.destination_port_range = dest_port_range
    rule.destination_port_ranges = dest_port_ranges or []
    rule.protocol = protocol
    rule.priority = priority
    return rule


def make_mock_disk(
    name: str = "test-disk",
    location: str = "eastus",
    encryption_type: str | None = "EncryptionAtRestWithPlatformKey",
) -> MagicMock:
    """Create a mock Azure Managed Disk."""
    disk = MagicMock()
    disk.name = name
    disk.id = (
        f"/subscriptions/test-sub-123/resourceGroups/rg-test"
        f"/providers/Microsoft.Compute/disks/{name}"
    )
    disk.location = location
    if encryption_type:
        disk.encryption = MagicMock()
        disk.encryption.type = encryption_type
    else:
        disk.encryption = None
    disk.encryption_settings_collection = None
    return disk


def make_mock_keyvault(
    name: str = "test-kv",
    location: str = "eastus",
    soft_delete: bool = True,
    purge_protection: bool = True,
    rbac: bool = True,
    public_network_access: str = "Disabled",
    net_default_action: str = "Deny",
) -> MagicMock:
    """Create a mock Azure Key Vault."""
    vault = MagicMock()
    vault.name = name
    vault.id = (
        f"/subscriptions/test-sub-123/resourceGroups/rg-test"
        f"/providers/Microsoft.KeyVault/vaults/{name}"
    )
    vault.location = location
    vault.properties = MagicMock()
    vault.properties.enable_soft_delete = soft_delete
    vault.properties.enable_purge_protection = purge_protection
    vault.properties.enable_rbac_authorization = rbac
    vault.properties.public_network_access = public_network_access
    vault.properties.vault_uri = f"https://{name}.vault.azure.net"

    net_acls = MagicMock()
    net_acls.default_action = net_default_action
    vault.properties.network_acls = net_acls

    return vault


def make_mock_sql_server(
    name: str = "test-sqlserver",
    resource_group: str = "rg-test",
    location: str = "eastus",
    min_tls: str = "1.2",
    public_network_access: str = "Disabled",
) -> MagicMock:
    """Create a mock Azure SQL Server."""
    server = MagicMock()
    server.name = name
    server.id = (
        f"/subscriptions/test-sub-123/resourceGroups/{resource_group}"
        f"/providers/Microsoft.Sql/servers/{name}"
    )
    server.location = location
    server.minimal_tls_version = min_tls
    server.public_network_access = public_network_access
    return server


@pytest.fixture
def mock_azure_client() -> MagicMock:
    """Pytest fixture returning a pre-built mock AzureClient."""
    return make_mock_azure_client()
