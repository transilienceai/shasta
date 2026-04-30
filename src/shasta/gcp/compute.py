"""GCP Compute Engine and GKE security checks for SOC 2 and CIS GCP Benchmark v2.0.

Covers:
  CC6.6 — System boundaries (compute instance hardening, GKE security)

CIS GCP v2.0 Section 4 (Compute Engine) and CIS GKE Benchmark.
Regional resources (instances, GKE clusters) use get_enabled_regions() + for_region()
per Engineering Principle #3.
"""

from __future__ import annotations

from typing import Any

from shasta.gcp.client import GCPClient
from shasta.evidence.models import (
    CheckDomain,
    CloudProvider,
    ComplianceStatus,
    Finding,
    Severity,
)

IS_GLOBAL = False  # Compute instance and GKE cluster checks are per-region


def run_all_gcp_compute_checks(client: GCPClient) -> list[Finding]:
    """Run all GCP Compute Engine and GKE compliance checks.

    Project-level metadata checks run once.
    Per-region instance and GKE cluster checks iterate enabled regions.
    """
    project_id = client.project_id if client.account_info else (client._project_id or "unknown")

    findings: list[Finding] = []

    # Project-level checks (not per-region)
    findings.extend(check_os_login_project_enabled(client, project_id))
    findings.extend(check_serial_port_disabled_project(client, project_id))

    # Regional checks
    for region in client.get_enabled_regions():
        regional_client = client.for_region(region)
        findings.extend(check_instance_no_external_ip(regional_client, project_id, region))
        findings.extend(check_instance_no_default_service_account_full_scope(regional_client, project_id, region))
        findings.extend(check_instance_shielded_vm(regional_client, project_id, region))
        findings.extend(check_gke_private_cluster(regional_client, project_id, region))
        findings.extend(check_gke_workload_identity(regional_client, project_id, region))
        findings.extend(check_gke_network_policy(regional_client, project_id, region))
        findings.extend(check_gke_node_auto_upgrade(regional_client, project_id, region))

    return findings


def check_os_login_project_enabled(
    client: GCPClient, project_id: str
) -> list[Finding]:
    """[CIS 4.4] OS Login should be enabled at the project level.

    OS Login ties SSH access to Google Account credentials and supports
    IAM-based authorization for SSH. Without it, instance SSH access is controlled
    by manually managed SSH keys stored in metadata — easy to misconfigure and
    hard to revoke project-wide.
    """
    region = "global"
    try:
        compute = client.service("compute", "v1")
        project = compute.projects().get(project=project_id).execute()
        metadata = project.get("commonInstanceMetadata", {})
        items = metadata.get("items", [])
    except Exception as e:
        return [
            Finding.not_assessed(
                check_id="gcp-compute-os-login",
                title="Unable to read project metadata for OS Login check",
                description=f"API call failed: {e}",
                domain=CheckDomain.COMPUTE,
                resource_type="GCP::Compute::Project",
                account_id=project_id,
                region=region,
                cloud_provider=CloudProvider.GCP,
            )
        ]

    os_login_enabled = any(
        item.get("key") == "enable-oslogin" and item.get("value", "").lower() == "true"
        for item in items
    )

    if os_login_enabled:
        return [
            Finding(
                check_id="gcp-compute-os-login",
                title="OS Login is enabled at the project level",
                description=(
                    "Project metadata has `enable-oslogin=true`. All instances inherit OS Login "
                    "unless overridden at the instance level."
                ),
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.COMPUTE,
                resource_type="GCP::Compute::Project",
                resource_id=f"projects/{project_id}",
                region=region,
                account_id=project_id,
                cloud_provider=CloudProvider.GCP,
                soc2_controls=["CC6.1"],
                cis_gcp_controls=["4.4"],
            )
        ]

    return [
        Finding(
            check_id="gcp-compute-os-login",
            title="OS Login is NOT enabled at the project level",
            description=(
                "Project metadata does not set `enable-oslogin=true`. SSH access to instances "
                "is controlled by manually managed public keys in metadata, which are hard to "
                "audit and revoke. OS Login provides IAM-controlled SSH with audit trails."
            ),
            severity=Severity.MEDIUM,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.COMPUTE,
            resource_type="GCP::Compute::Project",
            resource_id=f"projects/{project_id}",
            region=region,
            account_id=project_id,
            cloud_provider=CloudProvider.GCP,
            remediation=(
                "Enable OS Login: `gcloud compute project-info add-metadata "
                f"--metadata=enable-oslogin=TRUE --project={project_id}`. "
                "Grant users `roles/compute.osLogin` (non-admin) or "
                "`roles/compute.osAdminLogin` (with sudo) to control access."
            ),
            soc2_controls=["CC6.1"],
            cis_gcp_controls=["4.4"],
            iso27001_controls=["A.8.5"],
        )
    ]


def check_serial_port_disabled_project(
    client: GCPClient, project_id: str
) -> list[Finding]:
    """[CIS 4.5] Serial port access should be disabled at the project level.

    The serial console provides interactive access to a VM without SSH and bypasses
    firewall rules. It should be disabled at the project level to prevent abuse.
    """
    region = "global"
    try:
        compute = client.service("compute", "v1")
        project = compute.projects().get(project=project_id).execute()
        metadata = project.get("commonInstanceMetadata", {})
        items = metadata.get("items", [])
    except Exception as e:
        return [
            Finding.not_assessed(
                check_id="gcp-compute-serial-port",
                title="Unable to read project metadata for serial port check",
                description=f"API call failed: {e}",
                domain=CheckDomain.COMPUTE,
                resource_type="GCP::Compute::Project",
                account_id=project_id,
                region=region,
                cloud_provider=CloudProvider.GCP,
            )
        ]

    serial_enabled = any(
        item.get("key") == "serial-port-enable" and item.get("value", "").lower() in ("true", "1")
        for item in items
    )

    if not serial_enabled:
        return [
            Finding(
                check_id="gcp-compute-serial-port",
                title="Serial port access is disabled at the project level",
                description="Project metadata does not enable serial port access. Instances cannot access the interactive serial console.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.COMPUTE,
                resource_type="GCP::Compute::Project",
                resource_id=f"projects/{project_id}",
                region=region,
                account_id=project_id,
                cloud_provider=CloudProvider.GCP,
                soc2_controls=["CC6.6"],
                cis_gcp_controls=["4.5"],
            )
        ]

    return [
        Finding(
            check_id="gcp-compute-serial-port",
            title="Serial port access is ENABLED at the project level",
            description=(
                "Project metadata sets `serial-port-enable=true`. All instances allow "
                "serial console access by default, bypassing SSH and firewall controls."
            ),
            severity=Severity.HIGH,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.COMPUTE,
            resource_type="GCP::Compute::Project",
            resource_id=f"projects/{project_id}",
            region=region,
            account_id=project_id,
            cloud_provider=CloudProvider.GCP,
            remediation=(
                "Disable serial port access: `gcloud compute project-info add-metadata "
                f"--metadata=serial-port-enable=false --project={project_id}`. "
                "Also disable it per-instance if it's enabled at the instance level."
            ),
            soc2_controls=["CC6.6"],
            cis_gcp_controls=["4.5"],
            iso27001_controls=["A.8.9"],
        )
    ]


def check_instance_no_external_ip(
    client: GCPClient, project_id: str, region: str
) -> list[Finding]:
    """[CIS 4.6] Compute Engine instances should not have external IP addresses.

    Instances with public IPs are directly reachable from the internet. Use
    Cloud NAT for outbound traffic and IAP for inbound administrative access
    to eliminate the need for public IPs on most workloads.
    """
    try:
        compute = client.service("compute", "v1")
        response = (
            compute.instances()
            .aggregatedList(
                project=project_id,
                filter=f"region eq .*/regions/{region}$",
            )
            .execute()
        )
        items = response.get("items", {})
        instances = []
        for zone_data in items.values():
            instances.extend(zone_data.get("instances", []))
    except Exception as e:
        return [
            Finding.not_assessed(
                check_id="gcp-compute-no-external-ip",
                title=f"Unable to list compute instances in {region}",
                description=f"API call failed: {e}",
                domain=CheckDomain.COMPUTE,
                resource_type="GCP::Compute::Instance",
                account_id=project_id,
                region=region,
                cloud_provider=CloudProvider.GCP,
            )
        ]

    if not instances:
        return []

    with_external: list[dict[str, str]] = []
    for inst in instances:
        if inst.get("status") not in ("RUNNING", "STAGING"):
            continue
        for nic in inst.get("networkInterfaces", []):
            access_configs = nic.get("accessConfigs", [])
            has_external = any(ac.get("natIP") for ac in access_configs)
            if has_external:
                with_external.append(
                    {
                        "instance": inst.get("name", ""),
                        "zone": inst.get("zone", "").split("/")[-1],
                        "external_ip": next(
                            (ac.get("natIP") for ac in access_configs if ac.get("natIP")), ""
                        ),
                    }
                )
                break

    if not with_external:
        return [
            Finding(
                check_id="gcp-compute-no-external-ip",
                title=f"No instances in {region} have external IP addresses",
                description=f"All running instances in {region} use only private IP addresses.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.COMPUTE,
                resource_type="GCP::Compute::Instance",
                resource_id=f"projects/{project_id}/regions/{region}/instances",
                region=region,
                account_id=project_id,
                cloud_provider=CloudProvider.GCP,
                soc2_controls=["CC6.6"],
                cis_gcp_controls=["4.6"],
            )
        ]

    return [
        Finding(
            check_id="gcp-compute-no-external-ip",
            title=f"{len(with_external)} instance(s) in {region} have external IP addresses",
            description=(
                f"{len(with_external)} running instance(s) in {region} have public IP addresses. "
                "These instances are directly reachable from the internet."
            ),
            severity=Severity.MEDIUM,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.COMPUTE,
            resource_type="GCP::Compute::Instance",
            resource_id=f"projects/{project_id}/regions/{region}/instances",
            region=region,
            account_id=project_id,
            cloud_provider=CloudProvider.GCP,
            remediation=(
                "Remove external IPs: `gcloud compute instances delete-access-config INSTANCE_NAME "
                f"--access-config-name='External NAT' --zone=ZONE --project={project_id}`. "
                "Configure Cloud NAT for outbound internet access and IAP for SSH/RDP."
            ),
            soc2_controls=["CC6.6"],
            cis_gcp_controls=["4.6"],
            iso27001_controls=["A.8.20"],
            details={"instances_with_external_ip": with_external[:20]},
        )
    ]


def check_instance_no_default_service_account_full_scope(
    client: GCPClient, project_id: str, region: str
) -> list[Finding]:
    """[CIS 4.1] Instances should not use the default service account with full API scope.

    The default compute service account has the `editor` role, and running instances
    with it + the `cloud-platform` (full) scope grants the instance full project access.
    This violates least privilege and means any code running on the instance has
    full GCP project control.
    """
    FULL_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
    DEFAULT_SA_SUFFIX = "-compute@developer.gserviceaccount.com"

    try:
        compute = client.service("compute", "v1")
        response = (
            compute.instances()
            .aggregatedList(
                project=project_id,
                filter=f"region eq .*/regions/{region}$",
            )
            .execute()
        )
        items = response.get("items", {})
        instances = []
        for zone_data in items.values():
            instances.extend(zone_data.get("instances", []))
    except Exception as e:
        return [
            Finding.not_assessed(
                check_id="gcp-compute-default-sa-full-scope",
                title=f"Unable to list compute instances in {region} for SA scope check",
                description=f"API call failed: {e}",
                domain=CheckDomain.COMPUTE,
                resource_type="GCP::Compute::Instance",
                account_id=project_id,
                region=region,
                cloud_provider=CloudProvider.GCP,
            )
        ]

    if not instances:
        return []

    offenders: list[dict[str, str]] = []
    for inst in instances:
        if inst.get("status") not in ("RUNNING", "STAGING"):
            continue
        for sa in inst.get("serviceAccounts", []):
            email = sa.get("email", "")
            scopes = sa.get("scopes", [])
            is_default = email.endswith(DEFAULT_SA_SUFFIX)
            has_full_scope = FULL_SCOPE in scopes
            if is_default and has_full_scope:
                offenders.append(
                    {
                        "instance": inst.get("name", ""),
                        "zone": inst.get("zone", "").split("/")[-1],
                        "service_account": email,
                    }
                )

    if not offenders:
        return [
            Finding(
                check_id="gcp-compute-default-sa-full-scope",
                title=f"No instances in {region} use default SA with full cloud-platform scope",
                description=f"No running instances in {region} combine the default compute SA with full API scope.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.COMPUTE,
                resource_type="GCP::Compute::Instance",
                resource_id=f"projects/{project_id}/regions/{region}/instances",
                region=region,
                account_id=project_id,
                cloud_provider=CloudProvider.GCP,
                soc2_controls=["CC6.1", "CC6.2"],
                cis_gcp_controls=["4.1"],
            )
        ]

    return [
        Finding(
            check_id="gcp-compute-default-sa-full-scope",
            title=f"{len(offenders)} instance(s) in {region} use default SA with full API scope",
            description=(
                f"{len(offenders)} instance(s) in {region} run with the default compute "
                "service account and the `cloud-platform` scope. Any code running on these "
                "instances effectively has full GCP project access."
            ),
            severity=Severity.HIGH,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.COMPUTE,
            resource_type="GCP::Compute::Instance",
            resource_id=f"projects/{project_id}/regions/{region}/instances",
            region=region,
            account_id=project_id,
            cloud_provider=CloudProvider.GCP,
            remediation=(
                "Create a purpose-specific service account with minimal IAM roles, "
                "and update the instance: `gcloud compute instances set-service-account "
                "INSTANCE_NAME --service-account=CUSTOM_SA_EMAIL "
                "--scopes=cloud-platform --zone=ZONE`. "
                "Remove the default SA's editor role from the project."
            ),
            soc2_controls=["CC6.1", "CC6.2"],
            cis_gcp_controls=["4.1"],
            iso27001_controls=["A.5.15"],
            details={"offending_instances": offenders[:20]},
        )
    ]


def check_instance_shielded_vm(
    client: GCPClient, project_id: str, region: str
) -> list[Finding]:
    """[CIS 4.8] Compute instances should have Shielded VM enabled.

    Shielded VM provides verifiable integrity of Compute Engine VM instances using
    Secure Boot, vTPM, and Integrity Monitoring. This hardens against boot-level
    malware and rootkits.
    """
    try:
        compute = client.service("compute", "v1")
        response = (
            compute.instances()
            .aggregatedList(
                project=project_id,
                filter=f"region eq .*/regions/{region}$",
            )
            .execute()
        )
        items = response.get("items", {})
        instances = []
        for zone_data in items.values():
            instances.extend(zone_data.get("instances", []))
    except Exception as e:
        return [
            Finding.not_assessed(
                check_id="gcp-compute-shielded-vm",
                title=f"Unable to list compute instances in {region} for Shielded VM check",
                description=f"API call failed: {e}",
                domain=CheckDomain.COMPUTE,
                resource_type="GCP::Compute::Instance",
                account_id=project_id,
                region=region,
                cloud_provider=CloudProvider.GCP,
            )
        ]

    if not instances:
        return []

    not_shielded: list[dict[str, str]] = []
    for inst in instances:
        if inst.get("status") not in ("RUNNING", "STAGING"):
            continue
        shielded = inst.get("shieldedInstanceConfig", {})
        if not shielded.get("enableSecureBoot") or not shielded.get("enableVtpm"):
            not_shielded.append(
                {
                    "instance": inst.get("name", ""),
                    "zone": inst.get("zone", "").split("/")[-1],
                    "secure_boot": str(shielded.get("enableSecureBoot", False)),
                    "vtpm": str(shielded.get("enableVtpm", False)),
                }
            )

    if not not_shielded:
        return [
            Finding(
                check_id="gcp-compute-shielded-vm",
                title=f"All instances in {region} have Shielded VM (Secure Boot + vTPM) enabled",
                description=f"All running instances in {region} have Shielded VM configuration.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.COMPUTE,
                resource_type="GCP::Compute::Instance",
                resource_id=f"projects/{project_id}/regions/{region}/instances",
                region=region,
                account_id=project_id,
                cloud_provider=CloudProvider.GCP,
                soc2_controls=["CC6.6"],
                cis_gcp_controls=["4.8"],
            )
        ]

    return [
        Finding(
            check_id="gcp-compute-shielded-vm",
            title=f"{len(not_shielded)} instance(s) in {region} lack full Shielded VM protection",
            description=(
                f"{len(not_shielded)} running instance(s) in {region} do not have both Secure "
                "Boot and vTPM enabled. Shielded VM provides cryptographic guarantees about the "
                "integrity of boot firmware, kernel, and loaded drivers."
            ),
            severity=Severity.MEDIUM,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.COMPUTE,
            resource_type="GCP::Compute::Instance",
            resource_id=f"projects/{project_id}/regions/{region}/instances",
            region=region,
            account_id=project_id,
            cloud_provider=CloudProvider.GCP,
            remediation=(
                "Enable Shielded VM (requires stopping the instance): "
                "`gcloud compute instances update INSTANCE_NAME "
                "--shielded-secure-boot --shielded-vtpm --shielded-integrity-monitoring "
                f"--zone=ZONE --project={project_id}`."
            ),
            soc2_controls=["CC6.6"],
            cis_gcp_controls=["4.8"],
            iso27001_controls=["A.8.9"],
            details={"instances_without_shielded_vm": not_shielded[:20]},
        )
    ]


def check_gke_private_cluster(
    client: GCPClient, project_id: str, region: str
) -> list[Finding]:
    """[CIS 7.1] GKE clusters should use private nodes (no public IP on nodes).

    Private clusters ensure worker nodes have no external IP addresses, preventing
    direct internet access to nodes. The control plane remains reachable via
    authorized networks and Private Google Access.
    """
    try:
        container = client.service("container", "v1")
        response = (
            container.projects()
            .locations()
            .clusters()
            .list(parent=f"projects/{project_id}/locations/{region}")
            .execute()
        )
        clusters = response.get("clusters", [])
    except Exception as e:
        return [
            Finding.not_assessed(
                check_id="gcp-gke-private-cluster",
                title=f"Unable to list GKE clusters in {region}",
                description=f"API call failed: {e}",
                domain=CheckDomain.COMPUTE,
                resource_type="GCP::GKE::Cluster",
                account_id=project_id,
                region=region,
                cloud_provider=CloudProvider.GCP,
            )
        ]

    if not clusters:
        return []

    non_private: list[str] = []
    for cluster in clusters:
        private_cfg = cluster.get("privateClusterConfig") or {}
        if not private_cfg.get("enablePrivateNodes", False):
            non_private.append(cluster.get("name", "unknown"))

    if not non_private:
        return [
            Finding(
                check_id="gcp-gke-private-cluster",
                title=f"All {len(clusters)} GKE cluster(s) in {region} use private nodes",
                description=f"All GKE clusters in {region} have private nodes enabled.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.COMPUTE,
                resource_type="GCP::GKE::Cluster",
                resource_id=f"projects/{project_id}/locations/{region}/clusters",
                region=region,
                account_id=project_id,
                cloud_provider=CloudProvider.GCP,
                soc2_controls=["CC6.6"],
                cis_gcp_controls=["7.1"],
            )
        ]

    return [
        Finding(
            check_id="gcp-gke-private-cluster",
            title=f"{len(non_private)} GKE cluster(s) in {region} have public nodes",
            description=(
                f"{len(non_private)} GKE cluster(s) in {region} do not use private nodes: "
                f"{', '.join(non_private[:5])}. Worker nodes with public IPs are directly "
                "reachable from the internet if firewall rules are misconfigured."
            ),
            severity=Severity.HIGH,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.COMPUTE,
            resource_type="GCP::GKE::Cluster",
            resource_id=f"projects/{project_id}/locations/{region}/clusters",
            region=region,
            account_id=project_id,
            cloud_provider=CloudProvider.GCP,
            remediation=(
                "Private nodes cannot be enabled on existing clusters — create a new cluster "
                "with `--enable-private-nodes --master-ipv4-cidr=172.16.0.0/28`. "
                "Migrate workloads to the new cluster and delete the non-private cluster."
            ),
            soc2_controls=["CC6.6"],
            cis_gcp_controls=["7.1"],
            iso27001_controls=["A.8.20"],
            details={"clusters_without_private_nodes": non_private},
        )
    ]


def check_gke_workload_identity(
    client: GCPClient, project_id: str, region: str
) -> list[Finding]:
    """[CIS 7.4] GKE clusters should use Workload Identity for GCP API access.

    Without Workload Identity, pods must use mounted service account key files or
    the node's service account (which may have broad permissions). Workload Identity
    binds a Kubernetes service account to a GCP service account, scoping access
    to exactly what each pod needs.
    """
    try:
        container = client.service("container", "v1")
        response = (
            container.projects()
            .locations()
            .clusters()
            .list(parent=f"projects/{project_id}/locations/{region}")
            .execute()
        )
        clusters = response.get("clusters", [])
    except Exception as e:
        return [
            Finding.not_assessed(
                check_id="gcp-gke-workload-identity",
                title=f"Unable to list GKE clusters in {region} for Workload Identity check",
                description=f"API call failed: {e}",
                domain=CheckDomain.COMPUTE,
                resource_type="GCP::GKE::Cluster",
                account_id=project_id,
                region=region,
                cloud_provider=CloudProvider.GCP,
            )
        ]

    if not clusters:
        return []

    without_wi: list[str] = []
    for cluster in clusters:
        wi_config = cluster.get("workloadIdentityConfig") or {}
        workload_pool = wi_config.get("workloadPool", "")
        if not workload_pool:
            without_wi.append(cluster.get("name", "unknown"))

    if not without_wi:
        return [
            Finding(
                check_id="gcp-gke-workload-identity",
                title=f"All {len(clusters)} GKE cluster(s) in {region} have Workload Identity",
                description=f"Workload Identity is enabled on all GKE clusters in {region}.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.COMPUTE,
                resource_type="GCP::GKE::Cluster",
                resource_id=f"projects/{project_id}/locations/{region}/clusters",
                region=region,
                account_id=project_id,
                cloud_provider=CloudProvider.GCP,
                soc2_controls=["CC6.2"],
                cis_gcp_controls=["7.4"],
            )
        ]

    return [
        Finding(
            check_id="gcp-gke-workload-identity",
            title=f"{len(without_wi)} GKE cluster(s) in {region} lack Workload Identity",
            description=(
                f"{len(without_wi)} GKE cluster(s) in {region} do not have Workload Identity "
                f"enabled: {', '.join(without_wi[:5])}. Pods must use node SA or mounted key "
                "files, granting broader-than-needed GCP API access."
            ),
            severity=Severity.HIGH,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.COMPUTE,
            resource_type="GCP::GKE::Cluster",
            resource_id=f"projects/{project_id}/locations/{region}/clusters",
            region=region,
            account_id=project_id,
            cloud_provider=CloudProvider.GCP,
            remediation=(
                "Enable Workload Identity: `gcloud container clusters update CLUSTER_NAME "
                f"--region={region} --workload-pool={project_id}.svc.id.goog --project={project_id}`. "
                "Then update node pools: `gcloud container node-pools update POOL_NAME "
                "--cluster=CLUSTER_NAME --workload-metadata=GKE_METADATA`."
            ),
            soc2_controls=["CC6.2"],
            cis_gcp_controls=["7.4"],
            iso27001_controls=["A.5.15"],
            details={"clusters_without_workload_identity": without_wi},
        )
    ]


def check_gke_network_policy(
    client: GCPClient, project_id: str, region: str
) -> list[Finding]:
    """[CIS 7.5] GKE clusters should have a Network Policy enabled.

    Without a network policy, all pods can communicate with all other pods across
    all namespaces. Network policies implement micro-segmentation at the pod level,
    preventing lateral movement if a pod is compromised.
    """
    try:
        container = client.service("container", "v1")
        response = (
            container.projects()
            .locations()
            .clusters()
            .list(parent=f"projects/{project_id}/locations/{region}")
            .execute()
        )
        clusters = response.get("clusters", [])
    except Exception as e:
        return [
            Finding.not_assessed(
                check_id="gcp-gke-network-policy",
                title=f"Unable to list GKE clusters in {region} for Network Policy check",
                description=f"API call failed: {e}",
                domain=CheckDomain.COMPUTE,
                resource_type="GCP::GKE::Cluster",
                account_id=project_id,
                region=region,
                cloud_provider=CloudProvider.GCP,
            )
        ]

    if not clusters:
        return []

    without_np: list[str] = []
    for cluster in clusters:
        # addonsConfig.networkPolicyConfig.disabled == False means Calico is installed
        # networkPolicy.enabled must also be True for the policy engine to be active
        addons = cluster.get("addonsConfig", {})
        np_config = addons.get("networkPolicyConfig", {})
        np = cluster.get("networkPolicy", {})
        calico_installed = not np_config.get("disabled", True)
        np_enabled = np.get("enabled", False)
        if not (calico_installed and np_enabled):
            without_np.append(cluster.get("name", "unknown"))

    if not without_np:
        return [
            Finding(
                check_id="gcp-gke-network-policy",
                title=f"All {len(clusters)} GKE cluster(s) in {region} have Network Policy enabled",
                description=f"Network Policy (Calico) is enabled on all GKE clusters in {region}.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.COMPUTE,
                resource_type="GCP::GKE::Cluster",
                resource_id=f"projects/{project_id}/locations/{region}/clusters",
                region=region,
                account_id=project_id,
                cloud_provider=CloudProvider.GCP,
                soc2_controls=["CC6.6"],
                cis_gcp_controls=["7.5"],
            )
        ]

    return [
        Finding(
            check_id="gcp-gke-network-policy",
            title=f"{len(without_np)} GKE cluster(s) in {region} have no Network Policy",
            description=(
                f"{len(without_np)} GKE cluster(s) in {region} do not enforce Network Policy: "
                f"{', '.join(without_np[:5])}. All pods communicate freely across namespaces, "
                "enabling lateral movement after a pod compromise."
            ),
            severity=Severity.MEDIUM,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.COMPUTE,
            resource_type="GCP::GKE::Cluster",
            resource_id=f"projects/{project_id}/locations/{region}/clusters",
            region=region,
            account_id=project_id,
            cloud_provider=CloudProvider.GCP,
            remediation=(
                "Enable Network Policy: `gcloud container clusters update CLUSTER_NAME "
                f"--enable-network-policy --zone=ZONE --project={project_id}`. "
                "Deploy NetworkPolicy objects to restrict pod-to-pod communication. "
                "Alternatively, use GKE Dataplane V2 which has NetworkPolicy built in."
            ),
            soc2_controls=["CC6.6"],
            cis_gcp_controls=["7.5"],
            iso27001_controls=["A.8.20"],
            details={"clusters_without_network_policy": without_np},
        )
    ]


def check_gke_node_auto_upgrade(
    client: GCPClient, project_id: str, region: str
) -> list[Finding]:
    """GKE node pools should have automatic node upgrades enabled.

    Auto-upgrade keeps node pools on the latest patched Kubernetes minor version,
    reducing exposure to known CVEs. Manual upgrade processes are often delayed,
    leaving nodes on vulnerable versions for months.
    """
    try:
        container = client.service("container", "v1")
        response = (
            container.projects()
            .locations()
            .clusters()
            .list(parent=f"projects/{project_id}/locations/{region}")
            .execute()
        )
        clusters = response.get("clusters", [])
    except Exception as e:
        return [
            Finding.not_assessed(
                check_id="gcp-gke-node-auto-upgrade",
                title=f"Unable to list GKE clusters in {region} for auto-upgrade check",
                description=f"API call failed: {e}",
                domain=CheckDomain.COMPUTE,
                resource_type="GCP::GKE::Cluster",
                account_id=project_id,
                region=region,
                cloud_provider=CloudProvider.GCP,
            )
        ]

    if not clusters:
        return []

    pools_without_upgrade: list[dict[str, str]] = []
    for cluster in clusters:
        cluster_name = cluster.get("name", "")
        for pool in cluster.get("nodePools", []):
            mgmt = pool.get("management", {})
            if not mgmt.get("autoUpgrade", False):
                pools_without_upgrade.append(
                    {
                        "cluster": cluster_name,
                        "pool": pool.get("name", ""),
                    }
                )

    if not pools_without_upgrade:
        return [
            Finding(
                check_id="gcp-gke-node-auto-upgrade",
                title=f"All GKE node pools in {region} have auto-upgrade enabled",
                description=f"Automatic node upgrades are enabled on all node pools in {region}.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.COMPUTE,
                resource_type="GCP::GKE::Cluster",
                resource_id=f"projects/{project_id}/locations/{region}/clusters",
                region=region,
                account_id=project_id,
                cloud_provider=CloudProvider.GCP,
                soc2_controls=["CC6.6"],
                cis_gcp_controls=["7.9"],
            )
        ]

    return [
        Finding(
            check_id="gcp-gke-node-auto-upgrade",
            title=f"{len(pools_without_upgrade)} node pool(s) in {region} have auto-upgrade disabled",
            description=(
                f"{len(pools_without_upgrade)} node pool(s) in {region} do not have auto-upgrade "
                "enabled. Nodes on outdated Kubernetes versions may be exposed to known CVEs."
            ),
            severity=Severity.MEDIUM,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.COMPUTE,
            resource_type="GCP::GKE::Cluster",
            resource_id=f"projects/{project_id}/locations/{region}/clusters",
            region=region,
            account_id=project_id,
            cloud_provider=CloudProvider.GCP,
            remediation=(
                "Enable auto-upgrade: `gcloud container node-pools update POOL_NAME "
                "--cluster=CLUSTER_NAME --enable-autoupgrade "
                f"--region={region} --project={project_id}`."
            ),
            soc2_controls=["CC6.6"],
            cis_gcp_controls=["7.9"],
            details={"pools_without_auto_upgrade": pools_without_upgrade[:20]},
        )
    ]
