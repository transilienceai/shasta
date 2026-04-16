"""Functional tests for Azure check modules.

These tests mock Azure SDK calls and exercise the actual check logic,
verifying that findings are produced with correct ComplianceStatus,
severity, check_id, and control mappings for both passing and failing
scenarios.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from shasta.evidence.models import ComplianceStatus, Severity

from tests.test_azure.conftest import (
    make_mock_azure_client,
    make_mock_disk,
    make_mock_keyvault,
    make_mock_nsg,
    make_mock_sql_server,
    make_mock_storage_account,
    make_nsg_rule,
)


# ---------------------------------------------------------------------------
# Storage checks
# ---------------------------------------------------------------------------


class TestStorageEncryption:
    """Tests for _check_storage_encryption (TLS version check)."""

    def test_tls12_passes(self):
        acct = make_mock_storage_account(min_tls="TLS1_2")
        from shasta.azure.storage import _check_storage_encryption

        findings = _check_storage_encryption(
            acct, acct.name, acct.id, "rg-test", "test-sub-123", "eastus"
        )
        assert len(findings) == 1
        assert findings[0].status == ComplianceStatus.PASS
        assert findings[0].check_id == "azure-storage-encryption"

    def test_tls10_fails(self):
        acct = make_mock_storage_account(min_tls="TLS1_0")
        from shasta.azure.storage import _check_storage_encryption

        findings = _check_storage_encryption(
            acct, acct.name, acct.id, "rg-test", "test-sub-123", "eastus"
        )
        assert len(findings) == 1
        assert findings[0].status == ComplianceStatus.FAIL
        assert findings[0].severity == Severity.HIGH

    def test_tls13_passes(self):
        acct = make_mock_storage_account(min_tls="TLS1_3")
        from shasta.azure.storage import _check_storage_encryption

        findings = _check_storage_encryption(
            acct, acct.name, acct.id, "rg-test", "test-sub-123", "eastus"
        )
        assert findings[0].status == ComplianceStatus.PASS


class TestStorageHttpsOnly:
    """Tests for _check_storage_https_only."""

    def test_https_enforced_passes(self):
        acct = make_mock_storage_account(https_only=True)
        from shasta.azure.storage import _check_storage_https_only

        findings = _check_storage_https_only(
            acct, acct.name, acct.id, "rg-test", "test-sub-123", "eastus"
        )
        assert findings[0].status == ComplianceStatus.PASS

    def test_https_not_enforced_fails(self):
        acct = make_mock_storage_account(https_only=False)
        from shasta.azure.storage import _check_storage_https_only

        findings = _check_storage_https_only(
            acct, acct.name, acct.id, "rg-test", "test-sub-123", "eastus"
        )
        assert findings[0].status == ComplianceStatus.FAIL
        assert findings[0].severity == Severity.HIGH
        assert "CC6.7" in findings[0].soc2_controls


class TestBlobPublicAccess:
    """Tests for _check_blob_public_access."""

    def test_public_access_disabled_passes(self):
        acct = make_mock_storage_account(allow_blob_public_access=False)
        from shasta.azure.storage import _check_blob_public_access

        findings = _check_blob_public_access(
            acct, acct.name, acct.id, "rg-test", "test-sub-123", "eastus"
        )
        assert findings[0].status == ComplianceStatus.PASS

    def test_public_access_enabled_fails(self):
        acct = make_mock_storage_account(allow_blob_public_access=True)
        from shasta.azure.storage import _check_blob_public_access

        findings = _check_blob_public_access(
            acct, acct.name, acct.id, "rg-test", "test-sub-123", "eastus"
        )
        assert findings[0].status == ComplianceStatus.FAIL
        assert findings[0].severity == Severity.HIGH


class TestSharedKeyAccess:
    """Tests for _check_shared_key_access."""

    def test_shared_key_disabled_passes(self):
        acct = make_mock_storage_account(allow_shared_key_access=False)
        from shasta.azure.storage import _check_shared_key_access

        findings = _check_shared_key_access(
            acct, acct.name, acct.id, "rg-test", "test-sub-123", "eastus"
        )
        assert findings[0].status == ComplianceStatus.PASS
        assert "3.3" in findings[0].cis_azure_controls

    def test_shared_key_enabled_fails(self):
        acct = make_mock_storage_account(allow_shared_key_access=True)
        from shasta.azure.storage import _check_shared_key_access

        findings = _check_shared_key_access(
            acct, acct.name, acct.id, "rg-test", "test-sub-123", "eastus"
        )
        assert findings[0].status == ComplianceStatus.FAIL

    def test_shared_key_none_defaults_to_fail(self):
        """When allow_shared_key_access is None, Azure defaults allow it -- should fail."""
        acct = make_mock_storage_account(allow_shared_key_access=None)
        from shasta.azure.storage import _check_shared_key_access

        findings = _check_shared_key_access(
            acct, acct.name, acct.id, "rg-test", "test-sub-123", "eastus"
        )
        assert findings[0].status == ComplianceStatus.FAIL


class TestCrossTenantReplication:
    """Tests for _check_cross_tenant_replication."""

    def test_disabled_passes(self):
        acct = make_mock_storage_account(allow_cross_tenant_replication=False)
        from shasta.azure.storage import _check_cross_tenant_replication

        findings = _check_cross_tenant_replication(
            acct, acct.name, acct.id, "rg-test", "test-sub-123", "eastus"
        )
        assert findings[0].status == ComplianceStatus.PASS
        assert "3.15" in findings[0].cis_azure_controls

    def test_enabled_fails(self):
        acct = make_mock_storage_account(allow_cross_tenant_replication=True)
        from shasta.azure.storage import _check_cross_tenant_replication

        findings = _check_cross_tenant_replication(
            acct, acct.name, acct.id, "rg-test", "test-sub-123", "eastus"
        )
        assert findings[0].status == ComplianceStatus.FAIL
        assert findings[0].severity == Severity.MEDIUM


class TestNetworkDefaultDeny:
    """Tests for _check_network_default_deny."""

    def test_deny_passes(self):
        acct = make_mock_storage_account(network_default_action="Deny")
        from shasta.azure.storage import _check_network_default_deny

        findings = _check_network_default_deny(
            acct, acct.name, acct.id, "rg-test", "test-sub-123", "eastus"
        )
        assert findings[0].status == ComplianceStatus.PASS
        assert "3.8" in findings[0].cis_azure_controls

    def test_allow_fails(self):
        acct = make_mock_storage_account(network_default_action="Allow")
        from shasta.azure.storage import _check_network_default_deny

        findings = _check_network_default_deny(
            acct, acct.name, acct.id, "rg-test", "test-sub-123", "eastus"
        )
        assert findings[0].status == ComplianceStatus.FAIL
        assert findings[0].severity == Severity.HIGH


class TestStorageSoftDelete:
    """Tests for _check_storage_soft_delete."""

    def test_soft_delete_and_versioning_passes(self):
        from shasta.azure.storage import _check_storage_soft_delete

        acct = make_mock_storage_account()
        mock_storage_client = MagicMock()
        blob_props = MagicMock()
        blob_props.delete_retention_policy = MagicMock(enabled=True)
        blob_props.is_versioning_enabled = True
        mock_storage_client.blob_services.get_service_properties.return_value = blob_props

        findings = _check_storage_soft_delete(
            mock_storage_client, acct, acct.name, acct.id, "rg-test", "test-sub-123", "eastus"
        )
        assert findings[0].status == ComplianceStatus.PASS

    def test_no_soft_delete_fails(self):
        from shasta.azure.storage import _check_storage_soft_delete

        acct = make_mock_storage_account()
        mock_storage_client = MagicMock()
        blob_props = MagicMock()
        blob_props.delete_retention_policy = MagicMock(enabled=False)
        blob_props.is_versioning_enabled = False
        mock_storage_client.blob_services.get_service_properties.return_value = blob_props

        findings = _check_storage_soft_delete(
            mock_storage_client, acct, acct.name, acct.id, "rg-test", "test-sub-123", "eastus"
        )
        assert findings[0].status == ComplianceStatus.FAIL
        assert "soft delete" in findings[0].title


# ---------------------------------------------------------------------------
# Networking checks
# ---------------------------------------------------------------------------


class TestNsgUnrestrictedIngress:
    """Tests for check_nsg_unrestricted_ingress."""

    def test_no_dangerous_rules_passes(self):
        client = make_mock_azure_client()
        nsg = make_mock_nsg(
            rules=[
                make_nsg_rule(
                    name="allow-https",
                    source_prefix="10.0.0.0/8",
                    dest_port_range="443",
                )
            ]
        )
        mock_network = MagicMock()
        mock_network.network_security_groups.list_all.return_value = [nsg]
        client.mgmt_client.return_value = mock_network

        from shasta.azure.networking import check_nsg_unrestricted_ingress

        findings = check_nsg_unrestricted_ingress(client, "test-sub-123", "eastus")
        assert len(findings) == 1
        assert findings[0].status == ComplianceStatus.PASS

    def test_ssh_open_to_internet_fails(self):
        client = make_mock_azure_client()
        nsg = make_mock_nsg(
            rules=[
                make_nsg_rule(
                    name="allow-ssh-all",
                    source_prefix="*",
                    dest_port_range="22",
                )
            ]
        )
        mock_network = MagicMock()
        mock_network.network_security_groups.list_all.return_value = [nsg]
        client.mgmt_client.return_value = mock_network

        from shasta.azure.networking import check_nsg_unrestricted_ingress

        findings = check_nsg_unrestricted_ingress(client, "test-sub-123", "eastus")
        assert len(findings) == 1
        assert findings[0].status == ComplianceStatus.FAIL
        assert findings[0].severity in (Severity.HIGH, Severity.CRITICAL)
        assert "SSH" in findings[0].description

    def test_all_ports_open_fails_with_high_or_critical(self):
        """Wildcard port range open to internet should fail with HIGH or CRITICAL."""
        client = make_mock_azure_client()
        nsg = make_mock_nsg(
            rules=[
                make_nsg_rule(
                    name="allow-all",
                    source_prefix="0.0.0.0/0",
                    dest_port_range="*",
                    protocol="*",
                )
            ]
        )
        mock_network = MagicMock()
        mock_network.network_security_groups.list_all.return_value = [nsg]
        client.mgmt_client.return_value = mock_network

        from shasta.azure.networking import check_nsg_unrestricted_ingress

        findings = check_nsg_unrestricted_ingress(client, "test-sub-123", "eastus")
        assert findings[0].status == ComplianceStatus.FAIL
        # Wildcard matches all dangerous ports including management ports (SSH/RDP),
        # so severity is at least HIGH
        assert findings[0].severity in (Severity.HIGH, Severity.CRITICAL)

    def test_rdp_from_internet_via_prefix_list(self):
        """Source is unrestricted via source_address_prefixes (list), not prefix (scalar)."""
        client = make_mock_azure_client()
        nsg = make_mock_nsg(
            rules=[
                make_nsg_rule(
                    name="allow-rdp-list",
                    source_prefix="",
                    source_prefixes=["Internet"],
                    dest_port_range="3389",
                )
            ]
        )
        mock_network = MagicMock()
        mock_network.network_security_groups.list_all.return_value = [nsg]
        client.mgmt_client.return_value = mock_network

        from shasta.azure.networking import check_nsg_unrestricted_ingress

        findings = check_nsg_unrestricted_ingress(client, "test-sub-123", "eastus")
        assert findings[0].status == ComplianceStatus.FAIL


class TestNetworkWatcherCoverage:
    """Tests for check_network_watcher_per_region."""

    def test_watcher_in_all_vnet_regions_passes(self):
        client = make_mock_azure_client()
        mock_network = MagicMock()

        vnet = MagicMock()
        vnet.location = "eastus"
        vnet.id = "/subscriptions/test-sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet1"

        watcher = MagicMock()
        watcher.location = "eastus"
        watcher.id = "/subscriptions/test-sub/resourceGroups/NetworkWatcherRG/providers/Microsoft.Network/networkWatchers/nw-eastus"

        mock_network.virtual_networks.list_all.return_value = [vnet]
        mock_network.network_watchers.list_all.return_value = [watcher]
        client.mgmt_client.return_value = mock_network

        from shasta.azure.networking import check_network_watcher_per_region

        findings = check_network_watcher_per_region(client, "test-sub-123", "eastus")
        assert len(findings) == 1
        assert findings[0].status == ComplianceStatus.PASS

    def test_missing_watcher_in_region_fails(self):
        client = make_mock_azure_client()
        mock_network = MagicMock()

        vnet_east = MagicMock()
        vnet_east.location = "eastus"
        vnet_west = MagicMock()
        vnet_west.location = "westus"

        watcher = MagicMock()
        watcher.location = "eastus"

        mock_network.virtual_networks.list_all.return_value = [vnet_east, vnet_west]
        mock_network.network_watchers.list_all.return_value = [watcher]
        client.mgmt_client.return_value = mock_network

        from shasta.azure.networking import check_network_watcher_per_region

        findings = check_network_watcher_per_region(client, "test-sub-123", "eastus")
        assert len(findings) == 1
        assert findings[0].status == ComplianceStatus.FAIL
        assert "westus" in findings[0].description


# ---------------------------------------------------------------------------
# Encryption checks
# ---------------------------------------------------------------------------


class TestDiskEncryption:
    """Tests for check_disk_encryption."""

    def test_all_disks_encrypted_passes(self):
        client = make_mock_azure_client()
        mock_compute = MagicMock()
        mock_compute.disks.list.return_value = [
            make_mock_disk("disk1", encryption_type="EncryptionAtRestWithPlatformKey"),
            make_mock_disk("disk2", encryption_type="EncryptionAtRestWithCustomerKey"),
        ]
        client.mgmt_client.return_value = mock_compute

        from shasta.azure.encryption import check_disk_encryption

        findings = check_disk_encryption(client, "test-sub-123", "eastus")
        assert len(findings) == 1
        assert findings[0].status == ComplianceStatus.PASS
        assert findings[0].details["encrypted_count"] == 2

    def test_unencrypted_disk_fails(self):
        client = make_mock_azure_client()
        mock_compute = MagicMock()
        mock_compute.disks.list.return_value = [
            make_mock_disk("disk-bad", encryption_type="None"),
        ]
        client.mgmt_client.return_value = mock_compute

        from shasta.azure.encryption import check_disk_encryption

        findings = check_disk_encryption(client, "test-sub-123", "eastus")
        assert len(findings) == 1
        assert findings[0].status == ComplianceStatus.FAIL
        assert findings[0].severity == Severity.HIGH

    def test_no_disks_not_applicable(self):
        client = make_mock_azure_client()
        mock_compute = MagicMock()
        mock_compute.disks.list.return_value = []
        client.mgmt_client.return_value = mock_compute

        from shasta.azure.encryption import check_disk_encryption

        findings = check_disk_encryption(client, "test-sub-123", "eastus")
        assert len(findings) == 1
        assert findings[0].status == ComplianceStatus.NOT_APPLICABLE


class TestKeyvaultConfig:
    """Tests for check_keyvault_config."""

    def test_soft_delete_and_purge_protection_passes(self):
        client = make_mock_azure_client()
        vault = make_mock_keyvault(soft_delete=True, purge_protection=True)
        mock_kv = MagicMock()
        mock_kv.vaults.list_by_subscription.return_value = [vault]
        client.mgmt_client.return_value = mock_kv

        from shasta.azure.encryption import check_keyvault_config

        findings = check_keyvault_config(client, "test-sub-123", "eastus")
        assert len(findings) == 1
        assert findings[0].status == ComplianceStatus.PASS

    def test_missing_purge_protection_fails(self):
        client = make_mock_azure_client()
        vault = make_mock_keyvault(soft_delete=True, purge_protection=False)
        mock_kv = MagicMock()
        mock_kv.vaults.list_by_subscription.return_value = [vault]
        client.mgmt_client.return_value = mock_kv

        from shasta.azure.encryption import check_keyvault_config

        findings = check_keyvault_config(client, "test-sub-123", "eastus")
        assert findings[0].status == ComplianceStatus.FAIL
        assert "purge protection" in findings[0].title


class TestKeyvaultRbacMode:
    """Tests for check_keyvault_rbac_mode."""

    def test_rbac_enabled_passes(self):
        client = make_mock_azure_client()
        vault = make_mock_keyvault(rbac=True)
        mock_kv = MagicMock()
        mock_kv.vaults.list_by_subscription.return_value = [vault]
        client.mgmt_client.return_value = mock_kv

        with patch("shasta.azure.encryption._iter_keyvaults") as mock_iter:
            mock_iter.return_value = iter([(mock_kv, vault)])
            from shasta.azure.encryption import check_keyvault_rbac_mode

            findings = check_keyvault_rbac_mode(client, "test-sub-123", "eastus")
        assert findings[0].status == ComplianceStatus.PASS
        assert "8.5" in findings[0].cis_azure_controls

    def test_legacy_access_policies_fails(self):
        client = make_mock_azure_client()
        vault = make_mock_keyvault(rbac=False)
        mock_kv = MagicMock()
        mock_kv.vaults.list_by_subscription.return_value = [vault]
        client.mgmt_client.return_value = mock_kv

        with patch("shasta.azure.encryption._iter_keyvaults") as mock_iter:
            mock_iter.return_value = iter([(mock_kv, vault)])
            from shasta.azure.encryption import check_keyvault_rbac_mode

            findings = check_keyvault_rbac_mode(client, "test-sub-123", "eastus")
        assert findings[0].status == ComplianceStatus.FAIL
        assert findings[0].severity == Severity.MEDIUM


class TestKeyvaultPublicAccess:
    """Tests for check_keyvault_public_access."""

    def test_public_access_disabled_passes(self):
        client = make_mock_azure_client()
        vault = make_mock_keyvault(public_network_access="Disabled", net_default_action="Deny")

        with patch("shasta.azure.encryption._iter_keyvaults") as mock_iter:
            mock_iter.return_value = iter([(MagicMock(), vault)])
            from shasta.azure.encryption import check_keyvault_public_access

            findings = check_keyvault_public_access(client, "test-sub-123", "eastus")
        assert findings[0].status == ComplianceStatus.PASS

    def test_public_access_enabled_fails(self):
        client = make_mock_azure_client()
        vault = make_mock_keyvault(public_network_access="Enabled", net_default_action="Allow")

        with patch("shasta.azure.encryption._iter_keyvaults") as mock_iter:
            mock_iter.return_value = iter([(MagicMock(), vault)])
            from shasta.azure.encryption import check_keyvault_public_access

            findings = check_keyvault_public_access(client, "test-sub-123", "eastus")
        assert findings[0].status == ComplianceStatus.FAIL
        assert findings[0].severity == Severity.HIGH


class TestSqlMinTls:
    """Tests for check_sql_min_tls."""

    def test_tls12_passes(self):
        client = make_mock_azure_client()
        server = make_mock_sql_server(min_tls="1.2")

        with patch("shasta.azure.encryption._iter_sql_servers") as mock_iter:
            mock_iter.return_value = iter([(MagicMock(), server, "rg-test")])
            from shasta.azure.encryption import check_sql_min_tls

            findings = check_sql_min_tls(client, "test-sub-123", "eastus")
        assert findings[0].status == ComplianceStatus.PASS

    def test_tls10_fails(self):
        client = make_mock_azure_client()
        server = make_mock_sql_server(min_tls="1.0")

        with patch("shasta.azure.encryption._iter_sql_servers") as mock_iter:
            mock_iter.return_value = iter([(MagicMock(), server, "rg-test")])
            from shasta.azure.encryption import check_sql_min_tls

            findings = check_sql_min_tls(client, "test-sub-123", "eastus")
        assert findings[0].status == ComplianceStatus.FAIL


class TestSqlAuditing:
    """Tests for check_sql_auditing."""

    def test_auditing_enabled_with_90d_retention_passes(self):
        client = make_mock_azure_client()
        server = make_mock_sql_server()
        mock_sql = MagicMock()
        audit = MagicMock()
        audit.state = "Enabled"
        audit.retention_days = 90
        mock_sql.server_blob_auditing_policies.get.return_value = audit

        with patch("shasta.azure.encryption._iter_sql_servers") as mock_iter:
            mock_iter.return_value = iter([(mock_sql, server, "rg-test")])
            from shasta.azure.encryption import check_sql_auditing

            findings = check_sql_auditing(client, "test-sub-123", "eastus")
        assert findings[0].status == ComplianceStatus.PASS

    def test_auditing_disabled_fails(self):
        client = make_mock_azure_client()
        server = make_mock_sql_server()
        mock_sql = MagicMock()
        audit = MagicMock()
        audit.state = "Disabled"
        audit.retention_days = 0
        mock_sql.server_blob_auditing_policies.get.return_value = audit

        with patch("shasta.azure.encryption._iter_sql_servers") as mock_iter:
            mock_iter.return_value = iter([(mock_sql, server, "rg-test")])
            from shasta.azure.encryption import check_sql_auditing

            findings = check_sql_auditing(client, "test-sub-123", "eastus")
        assert findings[0].status == ComplianceStatus.FAIL


class TestSqlPublicAccess:
    """Tests for check_sql_public_access."""

    def test_public_access_disabled_passes(self):
        client = make_mock_azure_client()
        server = make_mock_sql_server(public_network_access="Disabled")
        mock_sql = MagicMock()
        mock_sql.servers.list.return_value = [server]
        client.mgmt_client.return_value = mock_sql

        from shasta.azure.encryption import check_sql_public_access

        findings = check_sql_public_access(client, "test-sub-123", "eastus")
        assert findings[0].status == ComplianceStatus.PASS

    def test_public_access_with_allow_all_is_critical(self):
        client = make_mock_azure_client()
        server = make_mock_sql_server(public_network_access="Enabled")
        mock_sql = MagicMock()
        mock_sql.servers.list.return_value = [server]

        # Firewall rule that allows all IPs
        fw_rule = MagicMock()
        fw_rule.start_ip_address = "0.0.0.0"
        fw_rule.end_ip_address = "255.255.255.255"
        mock_sql.firewall_rules.list_by_server.return_value = [fw_rule]
        client.mgmt_client.return_value = mock_sql

        from shasta.azure.encryption import check_sql_public_access

        findings = check_sql_public_access(client, "test-sub-123", "eastus")
        assert findings[0].status == ComplianceStatus.FAIL
        assert findings[0].severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# Runner-level integration: run_all_azure_storage_checks
# ---------------------------------------------------------------------------


class TestStorageRunnerIntegration:
    """Test the top-level runner wiring with mocked SDK imports."""

    def test_no_storage_accounts_returns_not_applicable(self):
        client = make_mock_azure_client()
        mock_storage = MagicMock()
        mock_storage.storage_accounts.list.return_value = []
        client.mgmt_client.return_value = mock_storage

        with patch("shasta.azure.storage.StorageManagementClient", create=True):
            from shasta.azure.storage import run_all_azure_storage_checks

            # Patch the import inside the function
            with patch.dict(
                "sys.modules",
                {"azure.mgmt.storage": MagicMock(StorageManagementClient=MagicMock())},
            ):
                # Re-mock mgmt_client to return our controlled mock
                client.mgmt_client.return_value = mock_storage
                findings = run_all_azure_storage_checks(client)

        na_findings = [f for f in findings if f.status == ComplianceStatus.NOT_APPLICABLE]
        assert len(na_findings) >= 1

    def test_api_error_returns_not_assessed(self):
        client = make_mock_azure_client()
        client.mgmt_client.side_effect = Exception("Azure SDK not installed")

        with patch.dict(
            "sys.modules",
            {"azure.mgmt.storage": MagicMock(StorageManagementClient=MagicMock())},
        ):
            from shasta.azure.storage import run_all_azure_storage_checks

            client.mgmt_client.side_effect = Exception("Unauthorized")
            findings = run_all_azure_storage_checks(client)

        not_assessed = [f for f in findings if f.status == ComplianceStatus.NOT_ASSESSED]
        assert len(not_assessed) >= 1, "API errors must produce NOT_ASSESSED, not empty results"
