"""GCP networking security checks for SOC 2 and CIS GCP Benchmark v2.0.

Covers:
  CC6.6 — System boundaries (firewall rules, VPC flow logs, network exposure)

CIS GCP v2.0 Section 3 (Networking).
Regional resources (subnets) use get_enabled_regions() + for_region() per
Engineering Principle #3.
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

IS_GLOBAL = False  # Subnet flow-log and Private Google Access checks are per-region

# Ports that should never be open to 0.0.0.0/0 or ::/0 on the internet
DANGEROUS_PORTS: dict[str, str] = {
    "22": "SSH",
    "3389": "RDP",
    "3306": "MySQL",
    "5432": "PostgreSQL",
    "1433": "MSSQL",
    "27017": "MongoDB",
    "6379": "Redis",
    "11211": "Memcached",
    "9200": "Elasticsearch",
    "445": "SMB",
    "23": "Telnet",
    "21": "FTP",
}

_INTERNET_RANGES = {"0.0.0.0/0", "::/0"}


def run_all_gcp_networking_checks(client: GCPClient) -> list[Finding]:
    """Run all GCP networking compliance checks.

    Global checks (firewall rules, default network, DNS) run once.
    Per-region checks (subnet flow logs, Private Google Access) iterate regions.
    """
    project_id = client.project_id if client.account_info else (client._project_id or "unknown")

    findings: list[Finding] = []

    # Global checks
    findings.extend(check_default_network_not_created(client, project_id))
    findings.extend(check_firewall_no_unrestricted_ssh(client, project_id))
    findings.extend(check_firewall_no_unrestricted_rdp(client, project_id))
    findings.extend(check_firewall_no_unrestricted_admin_ports(client, project_id))
    findings.extend(check_dns_logging_enabled(client, project_id))

    # Regional checks
    for region in client.get_enabled_regions():
        regional_client = client.for_region(region)
        findings.extend(check_subnet_flow_logs_enabled(regional_client, project_id, region))
        findings.extend(check_private_google_access_enabled(regional_client, project_id, region))

    return findings


def check_default_network_not_created(
    client: GCPClient, project_id: str
) -> list[Finding]:
    """[CIS 3.1] The default VPC network should be deleted from all projects.

    The default network comes pre-configured with permissive firewall rules (allow SSH, RDP,
    ICMP from anywhere) and is shared across all regions. Production workloads should run
    in custom VPCs with tightly scoped firewall rules.
    """
    region = "global"
    try:
        compute = client.service("compute", "v1")
        response = compute.networks().list(project=project_id).execute()
        networks = response.get("items", [])
    except Exception as e:
        return [
            Finding.not_assessed(
                check_id="gcp-network-default-not-created",
                title="Unable to list VPC networks",
                description=f"API call failed: {e}",
                domain=CheckDomain.NETWORKING,
                resource_type="GCP::Compute::Network",
                account_id=project_id,
                region=region,
                cloud_provider=CloudProvider.GCP,
            )
        ]

    default_net = next((n for n in networks if n.get("name") == "default"), None)

    if default_net is None:
        return [
            Finding(
                check_id="gcp-network-default-not-created",
                title="Default VPC network has been deleted",
                description="The default VPC network does not exist in this project. Custom VPCs are in use.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.NETWORKING,
                resource_type="GCP::Compute::Network",
                resource_id=f"projects/{project_id}/global/networks",
                region=region,
                account_id=project_id,
                cloud_provider=CloudProvider.GCP,
                soc2_controls=["CC6.6"],
                cis_gcp_controls=["3.1"],
            )
        ]

    return [
        Finding(
            check_id="gcp-network-default-not-created",
            title="Default VPC network exists in project",
            description=(
                "The default VPC network still exists. It ships with permissive firewall rules "
                "(allow-internal, allow-ssh, allow-rdp, allow-icmp) that apply to all VMs "
                "in the default network. Production workloads should use custom VPCs."
            ),
            severity=Severity.MEDIUM,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.NETWORKING,
            resource_type="GCP::Compute::Network",
            resource_id=default_net.get("selfLink", f"projects/{project_id}/global/networks/default"),
            region=region,
            account_id=project_id,
            cloud_provider=CloudProvider.GCP,
            remediation=(
                "Delete the default network: `gcloud compute networks delete default --project=PROJECT_ID`. "
                "Ensure all workloads use custom VPCs with explicit, minimal firewall rules."
            ),
            soc2_controls=["CC6.6"],
            cis_gcp_controls=["3.1"],
            iso27001_controls=["A.8.20"],
        )
    ]


def check_firewall_no_unrestricted_ssh(
    client: GCPClient, project_id: str
) -> list[Finding]:
    """[CIS 3.6] No firewall rule should allow SSH (port 22) from 0.0.0.0/0 or ::/0."""
    return _check_unrestricted_port(client, project_id, "22", "SSH", "gcp-firewall-unrestricted-ssh", "3.6")


def check_firewall_no_unrestricted_rdp(
    client: GCPClient, project_id: str
) -> list[Finding]:
    """[CIS 3.7] No firewall rule should allow RDP (port 3389) from 0.0.0.0/0 or ::/0."""
    return _check_unrestricted_port(client, project_id, "3389", "RDP", "gcp-firewall-unrestricted-rdp", "3.7")


def _check_unrestricted_port(
    client: GCPClient,
    project_id: str,
    port: str,
    service_name: str,
    check_id: str,
    cis_id: str,
) -> list[Finding]:
    """Shared implementation for unrestricted-port firewall checks."""
    region = "global"
    try:
        compute = client.service("compute", "v1")
        response = compute.firewalls().list(project=project_id).execute()
        rules = response.get("items", [])
    except Exception as e:
        return [
            Finding.not_assessed(
                check_id=check_id,
                title=f"Unable to list firewall rules for {service_name} check",
                description=f"API call failed: {e}",
                domain=CheckDomain.NETWORKING,
                resource_type="GCP::Compute::Firewall",
                account_id=project_id,
                region=region,
                cloud_provider=CloudProvider.GCP,
            )
        ]

    offenders: list[dict[str, Any]] = []
    for rule in rules:
        if rule.get("direction") != "INGRESS":
            continue
        if rule.get("disabled", False):
            continue
        src_ranges = set(rule.get("sourceRanges", []))
        if not src_ranges.intersection(_INTERNET_RANGES):
            continue
        for allowed in rule.get("allowed", []):
            proto = allowed.get("IPProtocol", "")
            ports = allowed.get("ports", [])
            if proto in ("all", "tcp"):
                if not ports or port in ports or any(
                    "-" in p and int(p.split("-")[0]) <= int(port) <= int(p.split("-")[1])
                    for p in ports
                    if "-" in p
                ):
                    offenders.append(
                        {
                            "name": rule.get("name"),
                            "source_ranges": list(src_ranges.intersection(_INTERNET_RANGES)),
                            "network": rule.get("network", "").split("/")[-1],
                        }
                    )

    if not offenders:
        return [
            Finding(
                check_id=check_id,
                title=f"No firewall rules allow unrestricted {service_name} (port {port}) access",
                description=f"No VPC firewall rules allow {service_name} from 0.0.0.0/0 or ::/0.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.NETWORKING,
                resource_type="GCP::Compute::Firewall",
                resource_id=f"projects/{project_id}/global/firewalls",
                region=region,
                account_id=project_id,
                cloud_provider=CloudProvider.GCP,
                soc2_controls=["CC6.6"],
                cis_gcp_controls=[cis_id],
            )
        ]

    return [
        Finding(
            check_id=check_id,
            title=f"{len(offenders)} firewall rule(s) allow unrestricted {service_name} access",
            description=(
                f"{len(offenders)} firewall rule(s) allow {service_name} (port {port}) from "
                f"0.0.0.0/0 or ::/0. This exposes instances to brute-force attacks from "
                "the entire internet."
            ),
            severity=Severity.HIGH,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.NETWORKING,
            resource_type="GCP::Compute::Firewall",
            resource_id=f"projects/{project_id}/global/firewalls",
            region=region,
            account_id=project_id,
            cloud_provider=CloudProvider.GCP,
            remediation=(
                f"Restrict {service_name} access to known IP ranges using Cloud Identity-Aware "
                f"Proxy (IAP) for administrative access instead of opening {port} to the internet. "
                f"To update: `gcloud compute firewall-rules update RULE_NAME "
                f"--source-ranges=YOUR_IP/32 --project={project_id}`."
            ),
            soc2_controls=["CC6.6"],
            cis_gcp_controls=[cis_id],
            iso27001_controls=["A.8.20"],
            details={"offending_rules": offenders[:20]},
        )
    ]


def check_firewall_no_unrestricted_admin_ports(
    client: GCPClient, project_id: str
) -> list[Finding]:
    """No firewall rule should allow common database/admin ports from 0.0.0.0/0.

    Beyond SSH and RDP, exposing database ports (MySQL 3306, PostgreSQL 5432,
    MongoDB 27017, etc.) to the internet is a common misconfiguration that
    leads to data breaches.
    """
    region = "global"
    try:
        compute = client.service("compute", "v1")
        response = compute.firewalls().list(project=project_id).execute()
        rules = response.get("items", [])
    except Exception as e:
        return [
            Finding.not_assessed(
                check_id="gcp-firewall-admin-ports",
                title="Unable to list firewall rules for admin-port check",
                description=f"API call failed: {e}",
                domain=CheckDomain.NETWORKING,
                resource_type="GCP::Compute::Firewall",
                account_id=project_id,
                region=region,
                cloud_provider=CloudProvider.GCP,
            )
        ]

    offenders: list[dict[str, Any]] = []
    for rule in rules:
        if rule.get("direction") != "INGRESS":
            continue
        if rule.get("disabled", False):
            continue
        src_ranges = set(rule.get("sourceRanges", []))
        if not src_ranges.intersection(_INTERNET_RANGES):
            continue
        for allowed in rule.get("allowed", []):
            proto = allowed.get("IPProtocol", "")
            ports = allowed.get("ports", [])
            if proto not in ("all", "tcp"):
                continue
            for danger_port, service in DANGEROUS_PORTS.items():
                if danger_port in ("22", "3389"):
                    continue  # Covered by dedicated checks above
                if not ports or danger_port in ports or any(
                    "-" in p and int(p.split("-")[0]) <= int(danger_port) <= int(p.split("-")[1])
                    for p in ports
                    if "-" in p
                ):
                    offenders.append(
                        {
                            "name": rule.get("name"),
                            "port": danger_port,
                            "service": service,
                            "network": rule.get("network", "").split("/")[-1],
                        }
                    )

    if not offenders:
        return [
            Finding(
                check_id="gcp-firewall-admin-ports",
                title="No firewall rules expose admin/database ports to the internet",
                description="No VPC firewall rules open database or admin ports to 0.0.0.0/0.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.NETWORKING,
                resource_type="GCP::Compute::Firewall",
                resource_id=f"projects/{project_id}/global/firewalls",
                region=region,
                account_id=project_id,
                cloud_provider=CloudProvider.GCP,
                soc2_controls=["CC6.6"],
                cis_gcp_controls=["3.6"],
            )
        ]

    return [
        Finding(
            check_id="gcp-firewall-admin-ports",
            title=f"{len(offenders)} firewall rule(s) expose admin/database ports to internet",
            description=(
                f"{len(offenders)} rule(s) expose admin or database ports to 0.0.0.0/0. "
                "Exposed services: " + ", ".join({o['service'] for o in offenders}) + ". "
                "These ports should be behind VPN or Cloud IAP, not exposed to the internet."
            ),
            severity=Severity.CRITICAL,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.NETWORKING,
            resource_type="GCP::Compute::Firewall",
            resource_id=f"projects/{project_id}/global/firewalls",
            region=region,
            account_id=project_id,
            cloud_provider=CloudProvider.GCP,
            remediation=(
                "Remove internet-facing firewall rules for database and admin ports. "
                "Use Cloud VPN or Cloud Interconnect for private connectivity, or Cloud IAP "
                "for TCP forwarding to internal services."
            ),
            soc2_controls=["CC6.6"],
            cis_gcp_controls=["3.6"],
            iso27001_controls=["A.8.20"],
            details={"offending_rules": offenders[:20]},
        )
    ]


def check_subnet_flow_logs_enabled(
    client: GCPClient, project_id: str, region: str
) -> list[Finding]:
    """[CIS 3.8] VPC subnet flow logs should be enabled for all subnets.

    Flow logs capture metadata about network flows (source, destination, protocol,
    bytes) and are essential for security investigations, anomaly detection,
    and compliance audit trails.
    """
    try:
        compute = client.service("compute", "v1")
        response = compute.subnetworks().list(project=project_id, region=region).execute()
        subnets = response.get("items", [])
    except Exception as e:
        return [
            Finding.not_assessed(
                check_id="gcp-subnet-flow-logs",
                title=f"Unable to list subnets in {region}",
                description=f"API call failed: {e}",
                domain=CheckDomain.NETWORKING,
                resource_type="GCP::Compute::Subnetwork",
                account_id=project_id,
                region=region,
                cloud_provider=CloudProvider.GCP,
            )
        ]

    if not subnets:
        return []  # No subnets in this region — NOT_APPLICABLE at region level is noise

    missing: list[str] = []
    for subnet in subnets:
        log_config = subnet.get("logConfig") or {}
        if not log_config.get("enable", False):
            missing.append(subnet.get("name", "unknown"))

    if not missing:
        return [
            Finding(
                check_id="gcp-subnet-flow-logs",
                title=f"All {len(subnets)} subnet(s) in {region} have flow logs enabled",
                description=f"VPC flow logs are enabled on all subnets in {region}.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.NETWORKING,
                resource_type="GCP::Compute::Subnetwork",
                resource_id=f"projects/{project_id}/regions/{region}/subnetworks",
                region=region,
                account_id=project_id,
                cloud_provider=CloudProvider.GCP,
                soc2_controls=["CC6.6", "CC7.1"],
                cis_gcp_controls=["3.8"],
            )
        ]

    return [
        Finding(
            check_id="gcp-subnet-flow-logs",
            title=f"{len(missing)} subnet(s) in {region} have flow logs disabled",
            description=(
                f"{len(missing)} subnet(s) in {region} do not have VPC flow logs enabled: "
                f"{', '.join(missing[:10])}{'...' if len(missing) > 10 else ''}. "
                "Without flow logs, you cannot investigate network security incidents, "
                "detect lateral movement, or audit traffic patterns."
            ),
            severity=Severity.MEDIUM,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.NETWORKING,
            resource_type="GCP::Compute::Subnetwork",
            resource_id=f"projects/{project_id}/regions/{region}/subnetworks",
            region=region,
            account_id=project_id,
            cloud_provider=CloudProvider.GCP,
            remediation=(
                f"Enable flow logs: `gcloud compute networks subnets update SUBNET_NAME "
                f"--region={region} --enable-flow-logs --project={project_id}`. "
                "Set an appropriate aggregation interval and flow sampling rate (0.5 recommended)."
            ),
            soc2_controls=["CC6.6", "CC7.1"],
            cis_gcp_controls=["3.8"],
            iso27001_controls=["A.8.15"],
            details={"subnets_without_flow_logs": missing},
        )
    ]


def check_private_google_access_enabled(
    client: GCPClient, project_id: str, region: str
) -> list[Finding]:
    """[CIS 3.9] Private Google Access should be enabled on all subnets.

    Private Google Access lets VMs without external IPs reach Google APIs and
    services (Cloud Storage, BigQuery, etc.) through the internal Google network
    rather than over the internet. Without it, VMs need public IPs to use GCP
    services, expanding your attack surface.
    """
    try:
        compute = client.service("compute", "v1")
        response = compute.subnetworks().list(project=project_id, region=region).execute()
        subnets = response.get("items", [])
    except Exception as e:
        return [
            Finding.not_assessed(
                check_id="gcp-subnet-private-google-access",
                title=f"Unable to list subnets in {region} for Private Google Access check",
                description=f"API call failed: {e}",
                domain=CheckDomain.NETWORKING,
                resource_type="GCP::Compute::Subnetwork",
                account_id=project_id,
                region=region,
                cloud_provider=CloudProvider.GCP,
            )
        ]

    if not subnets:
        return []

    missing: list[str] = []
    for subnet in subnets:
        if not subnet.get("privateIpGoogleAccess", False):
            missing.append(subnet.get("name", "unknown"))

    if not missing:
        return [
            Finding(
                check_id="gcp-subnet-private-google-access",
                title=f"All {len(subnets)} subnet(s) in {region} have Private Google Access",
                description=f"Private Google Access is enabled on all subnets in {region}.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.NETWORKING,
                resource_type="GCP::Compute::Subnetwork",
                resource_id=f"projects/{project_id}/regions/{region}/subnetworks",
                region=region,
                account_id=project_id,
                cloud_provider=CloudProvider.GCP,
                soc2_controls=["CC6.6"],
                cis_gcp_controls=["3.9"],
            )
        ]

    return [
        Finding(
            check_id="gcp-subnet-private-google-access",
            title=f"{len(missing)} subnet(s) in {region} lack Private Google Access",
            description=(
                f"{len(missing)} subnet(s) in {region} do not have Private Google Access "
                f"enabled: {', '.join(missing[:10])}{'...' if len(missing) > 10 else ''}. "
                "VMs in these subnets need public IPs to reach GCP APIs, expanding your "
                "network attack surface."
            ),
            severity=Severity.LOW,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.NETWORKING,
            resource_type="GCP::Compute::Subnetwork",
            resource_id=f"projects/{project_id}/regions/{region}/subnetworks",
            region=region,
            account_id=project_id,
            cloud_provider=CloudProvider.GCP,
            remediation=(
                f"Enable Private Google Access: `gcloud compute networks subnets update SUBNET_NAME "
                f"--region={region} --enable-private-ip-google-access --project={project_id}`."
            ),
            soc2_controls=["CC6.6"],
            cis_gcp_controls=["3.9"],
            details={"subnets_without_pga": missing},
        )
    ]


def check_dns_logging_enabled(
    client: GCPClient, project_id: str
) -> list[Finding]:
    """[CIS 3.10] Cloud DNS logging should be enabled for all managed zones.

    DNS query logs reveal which domains workloads resolve, enabling detection
    of data exfiltration via DNS tunneling and command-and-control domains.
    """
    region = "global"
    try:
        dns = client.service("dns", "v1")
        response = dns.managedZones().list(project=project_id).execute()
        zones = response.get("managedZones", [])
    except Exception as e:
        return [
            Finding.not_assessed(
                check_id="gcp-dns-logging",
                title="Unable to list Cloud DNS managed zones",
                description=f"API call failed: {e}",
                domain=CheckDomain.NETWORKING,
                resource_type="GCP::DNS::ManagedZone",
                account_id=project_id,
                region=region,
                cloud_provider=CloudProvider.GCP,
            )
        ]

    if not zones:
        return [
            Finding(
                check_id="gcp-dns-logging",
                title="No Cloud DNS managed zones in project",
                description="No Cloud DNS managed zones found — DNS logging check not applicable.",
                severity=Severity.INFO,
                status=ComplianceStatus.NOT_APPLICABLE,
                domain=CheckDomain.NETWORKING,
                resource_type="GCP::DNS::ManagedZone",
                resource_id=f"projects/{project_id}/managedZones",
                region=region,
                account_id=project_id,
                cloud_provider=CloudProvider.GCP,
                soc2_controls=["CC7.1"],
                cis_gcp_controls=["3.10"],
            )
        ]

    missing: list[str] = []
    for zone in zones:
        logging_config = zone.get("cloudLoggingConfig") or {}
        if not logging_config.get("enableLogging", False):
            missing.append(zone.get("name", "unknown"))

    if not missing:
        return [
            Finding(
                check_id="gcp-dns-logging",
                title=f"DNS logging enabled on all {len(zones)} managed zone(s)",
                description="Cloud DNS query logging is enabled on all managed zones.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.NETWORKING,
                resource_type="GCP::DNS::ManagedZone",
                resource_id=f"projects/{project_id}/managedZones",
                region=region,
                account_id=project_id,
                cloud_provider=CloudProvider.GCP,
                soc2_controls=["CC7.1"],
                cis_gcp_controls=["3.10"],
            )
        ]

    return [
        Finding(
            check_id="gcp-dns-logging",
            title=f"DNS logging disabled on {len(missing)} managed zone(s)",
            description=(
                f"DNS logging is not enabled on {len(missing)} managed zone(s): "
                f"{', '.join(missing[:10])}. Without DNS logs, DNS tunneling and "
                "C2 communication to known-malicious domains go undetected."
            ),
            severity=Severity.MEDIUM,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.NETWORKING,
            resource_type="GCP::DNS::ManagedZone",
            resource_id=f"projects/{project_id}/managedZones",
            region=region,
            account_id=project_id,
            cloud_provider=CloudProvider.GCP,
            remediation=(
                "Enable DNS logging: `gcloud dns managed-zones update ZONE_NAME "
                f"--log-dns-queries --project={project_id}`."
            ),
            soc2_controls=["CC7.1"],
            cis_gcp_controls=["3.10"],
            iso27001_controls=["A.8.15"],
            details={"zones_without_logging": missing},
        )
    ]
