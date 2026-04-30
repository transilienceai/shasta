"""Functional tests for GCP check modules using mocks.

Tests the actual check functions against mocked GCP service responses to
verify they return correct Finding objects with accurate status, severity,
and check_id values for both compliant and non-compliant scenarios.

No live GCP credentials are needed — all API calls are intercepted via
unittest.mock.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from shasta.evidence.models import ComplianceStatus, Finding


PROJECT_ID = "test-project"
REGION = "us-central1"


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _make_client(project_id: str = PROJECT_ID, region: str = REGION) -> MagicMock:
    client = MagicMock()
    client.project_id = project_id
    client.region = region
    client.account_info = MagicMock()
    client.account_info.project_id = project_id
    client.account_info.region = region
    client.get_enabled_regions.return_value = [region]
    client.for_region.return_value = client
    return client


# ===========================================================================
# IAM checks
# ===========================================================================


class TestCheckPrimitiveRoles:
    def _setup_iam_policy(self, client, bindings):
        crm = MagicMock()
        crm.projects.return_value.getIamPolicy.return_value.execute.return_value = {
            "bindings": bindings
        }
        client.service.return_value = crm

    def test_no_primitive_roles_pass(self):
        from shasta.gcp.iam import check_primitive_roles_not_used

        client = _make_client()
        self._setup_iam_policy(client, [
            {"role": "roles/compute.instanceAdmin", "members": ["user:alice@example.com"]}
        ])
        findings = check_primitive_roles_not_used(client, PROJECT_ID, "global")
        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert not fail_findings

    def test_owner_binding_fails(self):
        from shasta.gcp.iam import check_primitive_roles_not_used

        client = _make_client()
        self._setup_iam_policy(client, [
            {"role": "roles/owner", "members": ["user:alice@example.com"]}
        ])
        findings = check_primitive_roles_not_used(client, PROJECT_ID, "global")
        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert fail_findings, "Should flag owner binding as FAIL"

    def test_editor_binding_fails(self):
        from shasta.gcp.iam import check_primitive_roles_not_used

        client = _make_client()
        self._setup_iam_policy(client, [
            {"role": "roles/editor", "members": ["user:bob@example.com"]}
        ])
        findings = check_primitive_roles_not_used(client, PROJECT_ID, "global")
        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert fail_findings

    def test_api_error_not_assessed(self):
        from shasta.gcp.iam import check_primitive_roles_not_used

        client = _make_client()
        crm = MagicMock()
        crm.projects.return_value.getIamPolicy.return_value.execute.side_effect = Exception(
            "Permission denied"
        )
        client.service.return_value = crm
        findings = check_primitive_roles_not_used(client, PROJECT_ID, "global")
        assert findings
        assert all(f.status == ComplianceStatus.NOT_ASSESSED for f in findings)


class TestCheckServiceAccountAdmin:
    def _setup_iam_policy(self, client, bindings):
        crm = MagicMock()
        crm.projects.return_value.getIamPolicy.return_value.execute.return_value = {
            "bindings": bindings
        }
        client.service.return_value = crm

    def test_sa_with_editor_fails(self):
        from shasta.gcp.iam import check_service_account_not_admin

        client = _make_client()
        self._setup_iam_policy(client, [
            {
                "role": "roles/editor",
                "members": ["serviceAccount:my-sa@test-project.iam.gserviceaccount.com"],
            }
        ])
        findings = check_service_account_not_admin(client, PROJECT_ID, "global")
        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert fail_findings

    def test_sa_with_narrow_role_passes(self):
        from shasta.gcp.iam import check_service_account_not_admin

        client = _make_client()
        self._setup_iam_policy(client, [
            {
                "role": "roles/storage.objectViewer",
                "members": ["serviceAccount:my-sa@test-project.iam.gserviceaccount.com"],
            }
        ])
        findings = check_service_account_not_admin(client, PROJECT_ID, "global")
        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert not fail_findings


class TestCheckNoAllUsersAccess:
    def _setup_iam_policy(self, client, bindings):
        crm = MagicMock()
        crm.projects.return_value.getIamPolicy.return_value.execute.return_value = {
            "bindings": bindings
        }
        client.service.return_value = crm

    def test_allusers_binding_fails(self):
        from shasta.gcp.iam import check_iam_no_allusers_access

        client = _make_client()
        self._setup_iam_policy(client, [
            {"role": "roles/viewer", "members": ["allUsers"]}
        ])
        findings = check_iam_no_allusers_access(client, PROJECT_ID, "global")
        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert fail_findings

    def test_allauthenticated_binding_fails(self):
        from shasta.gcp.iam import check_iam_no_allusers_access

        client = _make_client()
        self._setup_iam_policy(client, [
            {"role": "roles/viewer", "members": ["allAuthenticatedUsers"]}
        ])
        findings = check_iam_no_allusers_access(client, PROJECT_ID, "global")
        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert fail_findings

    def test_no_allusers_passes(self):
        from shasta.gcp.iam import check_iam_no_allusers_access

        client = _make_client()
        self._setup_iam_policy(client, [
            {"role": "roles/viewer", "members": ["user:alice@example.com"]}
        ])
        findings = check_iam_no_allusers_access(client, PROJECT_ID, "global")
        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert not fail_findings


# ===========================================================================
# Networking checks
# ===========================================================================


class TestCheckFirewallNoSSH:
    def _setup_firewall(self, client, items):
        compute = MagicMock()
        compute.firewalls.return_value.list.return_value.execute.return_value = (
            {"items": items} if items is not None else {}
        )
        client.service.return_value = compute

    def test_open_ssh_fails(self):
        from shasta.gcp.networking import check_firewall_no_unrestricted_ssh

        client = _make_client()
        self._setup_firewall(client, [
            {
                "name": "allow-ssh",
                "direction": "INGRESS",
                "disabled": False,
                "sourceRanges": ["0.0.0.0/0"],
                "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
            }
        ])
        findings = check_firewall_no_unrestricted_ssh(client, PROJECT_ID)
        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert fail_findings

    def test_restricted_ssh_passes(self):
        from shasta.gcp.networking import check_firewall_no_unrestricted_ssh

        client = _make_client()
        self._setup_firewall(client, [
            {
                "name": "allow-ssh-corp",
                "direction": "INGRESS",
                "disabled": False,
                "sourceRanges": ["10.0.0.0/8"],
                "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
            }
        ])
        findings = check_firewall_no_unrestricted_ssh(client, PROJECT_ID)
        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert not fail_findings

    def test_no_firewall_rules_passes(self):
        from shasta.gcp.networking import check_firewall_no_unrestricted_ssh

        client = _make_client()
        self._setup_firewall(client, None)
        findings = check_firewall_no_unrestricted_ssh(client, PROJECT_ID)
        assert findings
        # No rules that match = PASS (no offenders found)
        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert not fail_findings

    def test_disabled_rule_passes(self):
        from shasta.gcp.networking import check_firewall_no_unrestricted_ssh

        client = _make_client()
        self._setup_firewall(client, [
            {
                "name": "allow-ssh-disabled",
                "direction": "INGRESS",
                "disabled": True,
                "sourceRanges": ["0.0.0.0/0"],
                "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
            }
        ])
        findings = check_firewall_no_unrestricted_ssh(client, PROJECT_ID)
        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert not fail_findings


class TestCheckFirewallNoRDP:
    def test_open_rdp_fails(self):
        from shasta.gcp.networking import check_firewall_no_unrestricted_rdp

        client = _make_client()
        compute = MagicMock()
        compute.firewalls.return_value.list.return_value.execute.return_value = {
            "items": [
                {
                    "name": "allow-rdp",
                    "direction": "INGRESS",
                    "disabled": False,
                    "sourceRanges": ["0.0.0.0/0"],
                    "allowed": [{"IPProtocol": "tcp", "ports": ["3389"]}],
                }
            ]
        }
        client.service.return_value = compute
        findings = check_firewall_no_unrestricted_rdp(client, PROJECT_ID)
        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert fail_findings

    def test_no_rdp_rules_passes(self):
        from shasta.gcp.networking import check_firewall_no_unrestricted_rdp

        client = _make_client()
        compute = MagicMock()
        compute.firewalls.return_value.list.return_value.execute.return_value = {}
        client.service.return_value = compute
        findings = check_firewall_no_unrestricted_rdp(client, PROJECT_ID)
        # No matching rules = PASS
        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert not fail_findings


class TestCheckSubnetFlowLogs:
    def test_subnet_without_flow_logs_fails(self):
        from shasta.gcp.networking import check_subnet_flow_logs_enabled

        client = _make_client()
        compute = MagicMock()
        compute.subnetworks.return_value.list.return_value.execute.return_value = {
            "items": [
                {
                    "name": "default",
                    "selfLink": "https://compute.googleapis.com/compute/v1/projects/test-project/regions/us-central1/subnetworks/default",
                    # No logConfig → flow logs disabled
                }
            ]
        }
        client.service.return_value = compute
        findings = check_subnet_flow_logs_enabled(client, PROJECT_ID, REGION)
        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert fail_findings

    def test_subnet_with_flow_logs_passes(self):
        from shasta.gcp.networking import check_subnet_flow_logs_enabled

        client = _make_client()
        compute = MagicMock()
        compute.subnetworks.return_value.list.return_value.execute.return_value = {
            "items": [
                {
                    "name": "default",
                    "selfLink": "...",
                    "logConfig": {"enable": True},
                }
            ]
        }
        client.service.return_value = compute
        findings = check_subnet_flow_logs_enabled(client, PROJECT_ID, REGION)
        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert not fail_findings

    def test_no_subnets_returns_empty(self):
        from shasta.gcp.networking import check_subnet_flow_logs_enabled

        client = _make_client()
        compute = MagicMock()
        compute.subnetworks.return_value.list.return_value.execute.return_value = {}
        client.service.return_value = compute
        findings = check_subnet_flow_logs_enabled(client, PROJECT_ID, REGION)
        # Code returns [] (empty list) when no subnets — not NOT_APPLICABLE
        assert isinstance(findings, list)
        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert not fail_findings


# ===========================================================================
# Storage checks
# ===========================================================================


class TestCheckBucketPublicAccess:
    def test_public_bucket_fails(self):
        from shasta.gcp.storage import check_bucket_no_public_access

        client = _make_client()

        mock_bucket = MagicMock()
        mock_bucket.name = "my-public-bucket"

        mock_policy = MagicMock()
        # policy.bindings must be iterable with dicts that have "members" key
        mock_policy.bindings = [
            {"role": "roles/storage.objectViewer", "members": ["allUsers"]},
        ]
        mock_bucket.get_iam_policy.return_value = mock_policy

        storage_client = MagicMock()
        storage_client.list_buckets.return_value = [mock_bucket]
        client.storage_client.return_value = storage_client

        findings = check_bucket_no_public_access(client, PROJECT_ID)
        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert fail_findings

    def test_private_bucket_passes(self):
        from shasta.gcp.storage import check_bucket_no_public_access

        client = _make_client()

        mock_bucket = MagicMock()
        mock_bucket.name = "my-private-bucket"

        mock_policy = MagicMock()
        mock_policy.bindings = [
            {"role": "roles/storage.objectViewer", "members": ["user:alice@example.com"]},
        ]
        mock_bucket.get_iam_policy.return_value = mock_policy

        storage_client = MagicMock()
        storage_client.list_buckets.return_value = [mock_bucket]
        client.storage_client.return_value = storage_client

        findings = check_bucket_no_public_access(client, PROJECT_ID)
        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert not fail_findings

    def test_no_buckets_not_applicable(self):
        from shasta.gcp.storage import check_bucket_no_public_access

        client = _make_client()
        storage_client = MagicMock()
        storage_client.list_buckets.return_value = []
        client.storage_client.return_value = storage_client

        findings = check_bucket_no_public_access(client, PROJECT_ID)
        assert findings
        assert all(f.status == ComplianceStatus.NOT_APPLICABLE for f in findings)


class TestCheckBucketVersioning:
    def test_bucket_without_versioning_fails(self):
        from shasta.gcp.storage import check_bucket_versioning_enabled

        client = _make_client()

        mock_bucket = MagicMock()
        mock_bucket.name = "my-bucket"
        mock_bucket.versioning_enabled = False

        storage_client = MagicMock()
        storage_client.list_buckets.return_value = [mock_bucket]
        client.storage_client.return_value = storage_client

        findings = check_bucket_versioning_enabled(client, PROJECT_ID)
        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert fail_findings

    def test_bucket_with_versioning_passes(self):
        from shasta.gcp.storage import check_bucket_versioning_enabled

        client = _make_client()

        mock_bucket = MagicMock()
        mock_bucket.name = "my-bucket"
        mock_bucket.versioning_enabled = True

        storage_client = MagicMock()
        storage_client.list_buckets.return_value = [mock_bucket]
        client.storage_client.return_value = storage_client

        findings = check_bucket_versioning_enabled(client, PROJECT_ID)
        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert not fail_findings


# ===========================================================================
# Encryption checks
# ===========================================================================


class TestCheckKmsKeyRotation:
    def test_key_without_rotation_fails(self):
        from shasta.gcp.encryption import check_kms_key_rotation_period

        client = _make_client()

        # The code calls:
        # kms.projects().locations().keyRings().list(parent=parent).execute()
        #   → returns {"keyRings": [...]}
        # kms.projects().locations().keyRings().cryptoKeys().list(parent=ring_name).execute()
        #   → returns {"cryptoKeys": [...]}
        kms = MagicMock()
        chain = kms.projects.return_value.locations.return_value.keyRings.return_value

        # keyRings().list() → execute() returns keyRings list
        chain.list.return_value.execute.return_value = {
            "keyRings": [
                {"name": "projects/test-project/locations/global/keyRings/my-ring"}
            ]
        }
        # keyRings().cryptoKeys().list() → execute() returns cryptoKeys list
        chain.cryptoKeys.return_value.list.return_value.execute.return_value = {
            "cryptoKeys": [
                {
                    "name": "projects/test-project/locations/global/keyRings/my-ring/cryptoKeys/my-key",
                    "purpose": "ENCRYPT_DECRYPT",
                    # No rotationPeriod → non-compliant
                }
            ]
        }
        client.service.return_value = kms

        findings = check_kms_key_rotation_period(client, PROJECT_ID)
        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert fail_findings

    def test_key_with_90day_rotation_passes(self):
        from shasta.gcp.encryption import check_kms_key_rotation_period

        client = _make_client()

        kms = MagicMock()
        chain = kms.projects.return_value.locations.return_value.keyRings.return_value
        chain.list.return_value.execute.return_value = {
            "keyRings": [
                {"name": "projects/test-project/locations/global/keyRings/my-ring"}
            ]
        }
        chain.cryptoKeys.return_value.list.return_value.execute.return_value = {
            "cryptoKeys": [
                {
                    "name": "projects/test-project/locations/global/keyRings/my-ring/cryptoKeys/my-key",
                    "purpose": "ENCRYPT_DECRYPT",
                    "rotationPeriod": "7776000s",  # 90 days exactly
                }
            ]
        }
        client.service.return_value = kms

        findings = check_kms_key_rotation_period(client, PROJECT_ID)
        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert not fail_findings

    def test_key_with_too_long_rotation_fails(self):
        from shasta.gcp.encryption import check_kms_key_rotation_period

        client = _make_client()

        kms = MagicMock()
        chain = kms.projects.return_value.locations.return_value.keyRings.return_value
        chain.list.return_value.execute.return_value = {
            "keyRings": [{"name": "projects/test-project/locations/global/keyRings/my-ring"}]
        }
        chain.cryptoKeys.return_value.list.return_value.execute.return_value = {
            "cryptoKeys": [
                {
                    "name": "projects/test-project/locations/global/keyRings/my-ring/cryptoKeys/my-key",
                    "purpose": "ENCRYPT_DECRYPT",
                    "rotationPeriod": "31536000s",  # 365 days — too long
                }
            ]
        }
        client.service.return_value = kms

        findings = check_kms_key_rotation_period(client, PROJECT_ID)
        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert fail_findings

    def test_no_keyrings_not_applicable(self):
        from shasta.gcp.encryption import check_kms_key_rotation_period

        client = _make_client()

        kms = MagicMock()
        chain = kms.projects.return_value.locations.return_value.keyRings.return_value
        chain.list.return_value.execute.return_value = {}  # No keyRings key
        client.service.return_value = kms

        findings = check_kms_key_rotation_period(client, PROJECT_ID)
        assert findings
        assert all(f.status == ComplianceStatus.NOT_APPLICABLE for f in findings)


# ===========================================================================
# Logging / monitoring checks
# ===========================================================================


class TestCheckAuditConfig:
    def test_no_data_access_logging_fails(self):
        from shasta.gcp.logging_checks import check_audit_config_data_access

        client = _make_client()
        crm = MagicMock()
        crm.projects.return_value.getIamPolicy.return_value.execute.return_value = {
            "bindings": []
            # missing auditConfigs
        }
        client.service.return_value = crm
        findings = check_audit_config_data_access(client, PROJECT_ID)
        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert fail_findings

    def test_data_access_logging_enabled_passes(self):
        from shasta.gcp.logging_checks import check_audit_config_data_access

        client = _make_client()
        crm = MagicMock()
        crm.projects.return_value.getIamPolicy.return_value.execute.return_value = {
            "auditConfigs": [
                {
                    "service": "allServices",
                    "auditLogConfigs": [
                        {"logType": "DATA_READ"},
                        {"logType": "DATA_WRITE"},
                        {"logType": "ADMIN_READ"},
                    ],
                }
            ]
        }
        client.service.return_value = crm
        findings = check_audit_config_data_access(client, PROJECT_ID)
        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert not fail_findings


class TestCheckLogSink:
    def test_no_sink_fails(self):
        from shasta.gcp.logging_checks import check_log_sink_configured

        client = _make_client()
        logging_svc = MagicMock()
        logging_svc.projects.return_value.sinks.return_value.list.return_value.execute.return_value = {
            "sinks": []
        }
        client.service.return_value = logging_svc
        findings = check_log_sink_configured(client, PROJECT_ID)
        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert fail_findings

    def test_sink_configured_passes(self):
        from shasta.gcp.logging_checks import check_log_sink_configured

        client = _make_client()
        logging_svc = MagicMock()
        logging_svc.projects.return_value.sinks.return_value.list.return_value.execute.return_value = {
            "sinks": [
                {
                    "name": "projects/test-project/sinks/all-logs",
                    "destination": "storage.googleapis.com/my-logs-bucket",
                    "filter": "",
                }
            ]
        }
        client.service.return_value = logging_svc
        findings = check_log_sink_configured(client, PROJECT_ID)
        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert not fail_findings


# ===========================================================================
# Compute checks
# ===========================================================================


class TestCheckOsLogin:
    def test_no_os_login_fails(self):
        from shasta.gcp.compute import check_os_login_project_enabled

        client = _make_client()
        compute = MagicMock()
        compute.projects.return_value.get.return_value.execute.return_value = {
            "name": PROJECT_ID,
            "commonInstanceMetadata": {
                "items": [{"key": "enable-oslogin", "value": "FALSE"}]
            },
        }
        client.service.return_value = compute
        findings = check_os_login_project_enabled(client, PROJECT_ID)
        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert fail_findings

    def test_os_login_enabled_passes(self):
        from shasta.gcp.compute import check_os_login_project_enabled

        client = _make_client()
        compute = MagicMock()
        compute.projects.return_value.get.return_value.execute.return_value = {
            "name": PROJECT_ID,
            "commonInstanceMetadata": {
                "items": [{"key": "enable-oslogin", "value": "TRUE"}]
            },
        }
        client.service.return_value = compute
        findings = check_os_login_project_enabled(client, PROJECT_ID)
        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert not fail_findings

    def test_missing_metadata_fails(self):
        from shasta.gcp.compute import check_os_login_project_enabled

        client = _make_client()
        compute = MagicMock()
        compute.projects.return_value.get.return_value.execute.return_value = {
            "name": PROJECT_ID,
            "commonInstanceMetadata": {"items": []},
        }
        client.service.return_value = compute
        findings = check_os_login_project_enabled(client, PROJECT_ID)
        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert fail_findings


class TestCheckSerialPort:
    def test_serial_port_enabled_fails(self):
        from shasta.gcp.compute import check_serial_port_disabled_project

        client = _make_client()
        compute = MagicMock()
        compute.projects.return_value.get.return_value.execute.return_value = {
            "name": PROJECT_ID,
            "commonInstanceMetadata": {
                "items": [{"key": "serial-port-enable", "value": "1"}]
            },
        }
        client.service.return_value = compute
        findings = check_serial_port_disabled_project(client, PROJECT_ID)
        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert fail_findings

    def test_serial_port_disabled_passes(self):
        from shasta.gcp.compute import check_serial_port_disabled_project

        client = _make_client()
        compute = MagicMock()
        compute.projects.return_value.get.return_value.execute.return_value = {
            "name": PROJECT_ID,
            "commonInstanceMetadata": {
                "items": [{"key": "serial-port-enable", "value": "false"}]
            },
        }
        client.service.return_value = compute
        findings = check_serial_port_disabled_project(client, PROJECT_ID)
        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert not fail_findings


class TestCheckInstanceNoExternalIP:
    def test_instance_with_external_ip_fails(self):
        from shasta.gcp.compute import check_instance_no_external_ip

        client = _make_client()
        compute = MagicMock()
        # Code uses aggregatedList then iterates items.values() → zone_data.get("instances")
        compute.instances.return_value.aggregatedList.return_value.execute.return_value = {
            "items": {
                "zones/us-central1-a": {
                    "instances": [
                        {
                            "name": "my-vm",
                            "status": "RUNNING",
                            "zone": "zones/us-central1-a",
                            "networkInterfaces": [
                                {
                                    "name": "nic0",
                                    "accessConfigs": [
                                        {"type": "ONE_TO_ONE_NAT", "natIP": "34.100.200.1"}
                                    ],
                                }
                            ],
                        }
                    ]
                }
            }
        }
        client.service.return_value = compute
        findings = check_instance_no_external_ip(client, PROJECT_ID, REGION)
        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert fail_findings

    def test_instance_without_external_ip_passes(self):
        from shasta.gcp.compute import check_instance_no_external_ip

        client = _make_client()
        compute = MagicMock()
        compute.instances.return_value.aggregatedList.return_value.execute.return_value = {
            "items": {
                "zones/us-central1-a": {
                    "instances": [
                        {
                            "name": "my-internal-vm",
                            "status": "RUNNING",
                            "zone": "zones/us-central1-a",
                            "networkInterfaces": [{"name": "nic0"}],
                        }
                    ]
                }
            }
        }
        client.service.return_value = compute
        findings = check_instance_no_external_ip(client, PROJECT_ID, REGION)
        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert not fail_findings

    def test_no_instances_returns_empty(self):
        from shasta.gcp.compute import check_instance_no_external_ip

        client = _make_client()
        compute = MagicMock()
        compute.instances.return_value.aggregatedList.return_value.execute.return_value = {
            "items": {}
        }
        client.service.return_value = compute
        # Code returns [] (not NOT_APPLICABLE) when no instances found
        findings = check_instance_no_external_ip(client, PROJECT_ID, REGION)
        assert isinstance(findings, list)
        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert not fail_findings


# ===========================================================================
# Finding shape tests — verify control fields are populated
# ===========================================================================


class TestFindingShape:
    def test_iam_findings_have_cis_controls(self):
        from shasta.gcp.iam import check_iam_no_allusers_access

        client = _make_client()
        crm = MagicMock()
        crm.projects.return_value.getIamPolicy.return_value.execute.return_value = {
            "bindings": [{"role": "roles/viewer", "members": ["allUsers"]}]
        }
        client.service.return_value = crm

        findings = check_iam_no_allusers_access(client, PROJECT_ID, "global")
        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert fail_findings
        for f in fail_findings:
            assert f.cis_gcp_controls, f"{f.check_id} should have cis_gcp_controls populated"
            assert f.cloud_provider.value == "gcp"

    def test_storage_findings_have_compliance_controls(self):
        from shasta.gcp.storage import check_bucket_no_public_access

        client = _make_client()

        mock_bucket = MagicMock()
        mock_bucket.name = "public-bucket"
        mock_policy = MagicMock()
        mock_policy.bindings = [
            {"role": "roles/storage.objectViewer", "members": ["allUsers"]}
        ]
        mock_bucket.get_iam_policy.return_value = mock_policy

        storage_client = MagicMock()
        storage_client.list_buckets.return_value = [mock_bucket]
        client.storage_client.return_value = storage_client

        findings = check_bucket_no_public_access(client, PROJECT_ID)
        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert fail_findings
        for f in fail_findings:
            assert f.soc2_controls or f.cis_gcp_controls, (
                f"{f.check_id} should have compliance controls populated"
            )

    def test_networking_findings_cloud_provider_is_gcp(self):
        from shasta.gcp.networking import check_firewall_no_unrestricted_ssh

        client = _make_client()
        compute = MagicMock()
        compute.firewalls.return_value.list.return_value.execute.return_value = {
            "items": [
                {
                    "name": "allow-ssh",
                    "direction": "INGRESS",
                    "disabled": False,
                    "sourceRanges": ["0.0.0.0/0"],
                    "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
                }
            ]
        }
        client.service.return_value = compute
        findings = check_firewall_no_unrestricted_ssh(client, PROJECT_ID)
        for f in findings:
            assert f.cloud_provider.value == "gcp"


# ===========================================================================
# Cloud Run checks
# ===========================================================================


def _setup_cloud_run_services(client, services):
    """Helper: set up the Cloud Run list mock to return the given services."""
    run = MagicMock()
    chain = run.projects.return_value.locations.return_value.services.return_value
    chain.list.return_value.execute.return_value = {
        "services": services,
    }
    # getIamPolicy returns empty bindings unless overridden per-test
    chain.getIamPolicy.return_value.execute.return_value = {"bindings": []}
    client.service.return_value = run
    return run


class TestCloudRunNoUnauthAccess:
    def test_allusers_invoker_fails(self):
        from shasta.gcp.cloud_run import check_cloud_run_no_unauthenticated_access

        client = _make_client()
        svc_name = f"projects/{PROJECT_ID}/locations/{REGION}/services/my-api"
        run = _setup_cloud_run_services(client, [{"name": svc_name}])

        # Override getIamPolicy to return allUsers binding
        run.projects.return_value.locations.return_value.services.return_value.getIamPolicy.return_value.execute.return_value = {
            "bindings": [
                {"role": "roles/run.invoker", "members": ["allUsers"]}
            ]
        }

        findings = check_cloud_run_no_unauthenticated_access(client, PROJECT_ID, REGION)
        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert fail_findings
        assert fail_findings[0].check_id == "gcp-cloudrun-no-unauth-access"

    def test_authenticated_only_passes(self):
        from shasta.gcp.cloud_run import check_cloud_run_no_unauthenticated_access

        client = _make_client()
        svc_name = f"projects/{PROJECT_ID}/locations/{REGION}/services/my-api"
        run = _setup_cloud_run_services(client, [{"name": svc_name}])
        run.projects.return_value.locations.return_value.services.return_value.getIamPolicy.return_value.execute.return_value = {
            "bindings": [
                {"role": "roles/run.invoker", "members": ["serviceAccount:caller@proj.iam.gserviceaccount.com"]}
            ]
        }

        findings = check_cloud_run_no_unauthenticated_access(client, PROJECT_ID, REGION)
        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert not fail_findings

    def test_no_services_returns_empty(self):
        from shasta.gcp.cloud_run import check_cloud_run_no_unauthenticated_access

        client = _make_client()
        _setup_cloud_run_services(client, [])
        findings = check_cloud_run_no_unauthenticated_access(client, PROJECT_ID, REGION)
        assert findings == []

    def test_api_error_not_assessed(self):
        from shasta.gcp.cloud_run import check_cloud_run_no_unauthenticated_access

        client = _make_client()
        run = MagicMock()
        run.projects.return_value.locations.return_value.services.return_value.list.return_value.execute.side_effect = Exception(
            "API error"
        )
        client.service.return_value = run
        findings = check_cloud_run_no_unauthenticated_access(client, PROJECT_ID, REGION)
        assert findings
        assert all(f.status == ComplianceStatus.NOT_ASSESSED for f in findings)


class TestCloudRunNoDefaultSA:
    def test_default_compute_sa_fails(self):
        from shasta.gcp.cloud_run import check_cloud_run_no_default_service_account

        client = _make_client()
        svc_name = f"projects/{PROJECT_ID}/locations/{REGION}/services/my-svc"
        _setup_cloud_run_services(client, [
            {
                "name": svc_name,
                "template": {
                    "serviceAccount": "123456789-compute@developer.gserviceaccount.com"
                },
            }
        ])
        findings = check_cloud_run_no_default_service_account(client, PROJECT_ID, REGION)
        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert fail_findings

    def test_dedicated_sa_passes(self):
        from shasta.gcp.cloud_run import check_cloud_run_no_default_service_account

        client = _make_client()
        svc_name = f"projects/{PROJECT_ID}/locations/{REGION}/services/my-svc"
        _setup_cloud_run_services(client, [
            {
                "name": svc_name,
                "template": {
                    "serviceAccount": f"my-svc-sa@{PROJECT_ID}.iam.gserviceaccount.com"
                },
            }
        ])
        findings = check_cloud_run_no_default_service_account(client, PROJECT_ID, REGION)
        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert not fail_findings

    def test_no_sa_specified_fails(self):
        from shasta.gcp.cloud_run import check_cloud_run_no_default_service_account

        client = _make_client()
        svc_name = f"projects/{PROJECT_ID}/locations/{REGION}/services/my-svc"
        _setup_cloud_run_services(client, [
            {"name": svc_name, "template": {}}  # No serviceAccount key
        ])
        findings = check_cloud_run_no_default_service_account(client, PROJECT_ID, REGION)
        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert fail_findings


class TestCloudRunIngressRestricted:
    def test_all_traffic_ingress_fails(self):
        from shasta.gcp.cloud_run import check_cloud_run_ingress_restricted

        client = _make_client()
        svc_name = f"projects/{PROJECT_ID}/locations/{REGION}/services/my-svc"
        _setup_cloud_run_services(client, [
            {"name": svc_name, "ingress": "INGRESS_TRAFFIC_ALL"}
        ])
        findings = check_cloud_run_ingress_restricted(client, PROJECT_ID, REGION)
        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert fail_findings

    def test_internal_only_passes(self):
        from shasta.gcp.cloud_run import check_cloud_run_ingress_restricted

        client = _make_client()
        svc_name = f"projects/{PROJECT_ID}/locations/{REGION}/services/my-svc"
        _setup_cloud_run_services(client, [
            {"name": svc_name, "ingress": "INGRESS_TRAFFIC_INTERNAL_ONLY"}
        ])
        findings = check_cloud_run_ingress_restricted(client, PROJECT_ID, REGION)
        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert not fail_findings

    def test_lb_only_passes(self):
        from shasta.gcp.cloud_run import check_cloud_run_ingress_restricted

        client = _make_client()
        svc_name = f"projects/{PROJECT_ID}/locations/{REGION}/services/my-svc"
        _setup_cloud_run_services(client, [
            {"name": svc_name, "ingress": "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"}
        ])
        findings = check_cloud_run_ingress_restricted(client, PROJECT_ID, REGION)
        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert not fail_findings


class TestCloudRunBinaryAuthorization:
    def test_no_binauthz_fails(self):
        from shasta.gcp.cloud_run import check_cloud_run_binary_authorization

        client = _make_client()
        svc_name = f"projects/{PROJECT_ID}/locations/{REGION}/services/my-svc"
        _setup_cloud_run_services(client, [
            {"name": svc_name}  # No binaryAuthorization key
        ])
        findings = check_cloud_run_binary_authorization(client, PROJECT_ID, REGION)
        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert fail_findings

    def test_use_default_passes(self):
        from shasta.gcp.cloud_run import check_cloud_run_binary_authorization

        client = _make_client()
        svc_name = f"projects/{PROJECT_ID}/locations/{REGION}/services/my-svc"
        _setup_cloud_run_services(client, [
            {"name": svc_name, "binaryAuthorization": {"useDefault": True}}
        ])
        findings = check_cloud_run_binary_authorization(client, PROJECT_ID, REGION)
        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert not fail_findings

    def test_custom_policy_passes(self):
        from shasta.gcp.cloud_run import check_cloud_run_binary_authorization

        client = _make_client()
        svc_name = f"projects/{PROJECT_ID}/locations/{REGION}/services/my-svc"
        _setup_cloud_run_services(client, [
            {
                "name": svc_name,
                "binaryAuthorization": {"policy": f"projects/{PROJECT_ID}/platforms/cloudRun/policies/default"}
            }
        ])
        findings = check_cloud_run_binary_authorization(client, PROJECT_ID, REGION)
        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert not fail_findings


class TestCloudRunNoPlaintextSecrets:
    def test_plaintext_api_key_fails(self):
        from shasta.gcp.cloud_run import check_cloud_run_no_plaintext_secrets

        client = _make_client()
        svc_name = f"projects/{PROJECT_ID}/locations/{REGION}/services/my-svc"
        _setup_cloud_run_services(client, [
            {
                "name": svc_name,
                "template": {
                    "containers": [
                        {
                            "image": "gcr.io/project/image:latest",
                            "env": [
                                {"name": "API_KEY", "value": "super-secret-value"},
                            ],
                        }
                    ]
                },
            }
        ])
        findings = check_cloud_run_no_plaintext_secrets(client, PROJECT_ID, REGION)
        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert fail_findings

    def test_secret_manager_ref_passes(self):
        from shasta.gcp.cloud_run import check_cloud_run_no_plaintext_secrets

        client = _make_client()
        svc_name = f"projects/{PROJECT_ID}/locations/{REGION}/services/my-svc"
        _setup_cloud_run_services(client, [
            {
                "name": svc_name,
                "template": {
                    "containers": [
                        {
                            "image": "gcr.io/project/image:latest",
                            "env": [
                                {
                                    "name": "API_KEY",
                                    "valueSource": {
                                        "secretKeyRef": {"secret": "my-api-key", "version": "latest"}
                                    },
                                },
                            ],
                        }
                    ]
                },
            }
        ])
        findings = check_cloud_run_no_plaintext_secrets(client, PROJECT_ID, REGION)
        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert not fail_findings

    def test_non_secret_env_var_passes(self):
        from shasta.gcp.cloud_run import check_cloud_run_no_plaintext_secrets

        client = _make_client()
        svc_name = f"projects/{PROJECT_ID}/locations/{REGION}/services/my-svc"
        _setup_cloud_run_services(client, [
            {
                "name": svc_name,
                "template": {
                    "containers": [
                        {
                            "image": "gcr.io/project/image:latest",
                            "env": [
                                {"name": "LOG_LEVEL", "value": "INFO"},
                                {"name": "PORT", "value": "8080"},
                            ],
                        }
                    ]
                },
            }
        ])
        findings = check_cloud_run_no_plaintext_secrets(client, PROJECT_ID, REGION)
        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert not fail_findings

    def test_password_env_var_fails(self):
        from shasta.gcp.cloud_run import check_cloud_run_no_plaintext_secrets

        client = _make_client()
        svc_name = f"projects/{PROJECT_ID}/locations/{REGION}/services/my-svc"
        _setup_cloud_run_services(client, [
            {
                "name": svc_name,
                "template": {
                    "containers": [
                        {
                            "image": "gcr.io/project/image:latest",
                            "env": [
                                {"name": "DB_PASSWORD", "value": "p@ssw0rd"},
                            ],
                        }
                    ]
                },
            }
        ])
        findings = check_cloud_run_no_plaintext_secrets(client, PROJECT_ID, REGION)
        fail_findings = [f for f in findings if f.status == ComplianceStatus.FAIL]
        assert fail_findings
