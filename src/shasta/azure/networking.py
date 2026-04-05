"""Azure networking security checks for SOC 2 and ISO 27001.

Checks Network Security Groups, VNet flow logs, and public IP exposure
for compliance with CC6.6 (System Boundaries) and ISO A.8.20.
"""

from __future__ import annotations

from shasta.azure.client import AzureClient
from shasta.evidence.models import (
    CheckDomain,
    CloudProvider,
    ComplianceStatus,
    Finding,
    Severity,
)

# Ports that should never be open to the internet
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


def run_all_azure_networking_checks(client: AzureClient) -> list[Finding]:
    """Run all Azure networking compliance checks."""
    findings: list[Finding] = []
    sub_id = client.account_info.subscription_id if client.account_info else "unknown"
    region = client.account_info.region if client.account_info else "unknown"

    findings.extend(check_nsg_unrestricted_ingress(client, sub_id, region))
    findings.extend(check_nsg_default_restricted(client, sub_id, region))
    findings.extend(check_vnet_flow_logs(client, sub_id, region))
    findings.extend(check_public_ip_exposure(client, sub_id, region))

    return findings


def _is_unrestricted_source(source_prefix: str) -> bool:
    """Check if a source address prefix is open to the world."""
    return source_prefix in ("*", "0.0.0.0/0", "Internet", "Any", "::/0")


def _port_in_range(port_str: str, dangerous_port: str) -> bool:
    """Check if a dangerous port falls within a port range string."""
    if port_str == "*":
        return True
    if "-" in port_str:
        try:
            low, high = port_str.split("-")
            return int(low) <= int(dangerous_port) <= int(high)
        except ValueError:
            return False
    return port_str == dangerous_port


def check_nsg_unrestricted_ingress(
    client: AzureClient, subscription_id: str, region: str
) -> list[Finding]:
    """[CC6.6] Check NSGs for unrestricted inbound rules on dangerous ports."""
    findings: list[Finding] = []

    try:
        from azure.mgmt.network import NetworkManagementClient

        network = client.mgmt_client(NetworkManagementClient)

        nsgs = list(network.network_security_groups.list_all())

        for nsg in nsgs:
            nsg_name = nsg.name or "unknown"
            nsg_id = nsg.id or ""
            nsg_rg = (
                nsg_id.split("/resourceGroups/")[1].split("/")[0]
                if "/resourceGroups/" in nsg_id
                else "unknown"
            )

            bad_rules = []
            for rule in nsg.security_rules or []:
                if rule.direction != "Inbound" or rule.access != "Allow":
                    continue

                source = rule.source_address_prefix or ""
                if not _is_unrestricted_source(source):
                    # Also check source_address_prefixes (list)
                    source_prefixes = rule.source_address_prefixes or []
                    if not any(_is_unrestricted_source(p) for p in source_prefixes):
                        continue

                # Check destination ports
                dest_port = rule.destination_port_range or ""
                dest_ports = rule.destination_port_ranges or []
                all_ports = [dest_port] + list(dest_ports) if dest_port else list(dest_ports)

                for dp in all_ports:
                    for port, service in DANGEROUS_PORTS.items():
                        if _port_in_range(dp, port):
                            bad_rules.append(
                                {
                                    "rule_name": rule.name,
                                    "port": port,
                                    "service": service,
                                    "source": source or str(rule.source_address_prefixes),
                                    "protocol": rule.protocol,
                                    "priority": rule.priority,
                                }
                            )

                    # Also flag if all ports are open
                    if dp == "*" and not any(
                        dp == "*" for entry in bad_rules if entry.get("rule_name") == rule.name
                    ):
                        bad_rules.append(
                            {
                                "rule_name": rule.name,
                                "port": "*",
                                "service": "ALL PORTS",
                                "source": source or str(rule.source_address_prefixes),
                                "protocol": rule.protocol,
                                "priority": rule.priority,
                            }
                        )

            if bad_rules:
                # Determine severity based on what's exposed
                has_all_ports = any(r["port"] == "*" for r in bad_rules)
                has_mgmt_ports = any(r["service"] in ("SSH", "RDP") for r in bad_rules)
                severity = (
                    Severity.CRITICAL
                    if has_all_ports
                    else (Severity.HIGH if has_mgmt_ports else Severity.MEDIUM)
                )

                findings.append(
                    Finding(
                        check_id="azure-nsg-unrestricted-ingress",
                        title=f"NSG '{nsg_name}' has unrestricted inbound rules",
                        description=f"NSG '{nsg_name}' allows inbound traffic from the internet on "
                        f"{len(bad_rules)} dangerous port(s): "
                        f"{', '.join(set(r['service'] for r in bad_rules))}",
                        severity=severity,
                        status=ComplianceStatus.FAIL,
                        domain=CheckDomain.NETWORKING,
                        resource_type="Azure::Network::NetworkSecurityGroup",
                        resource_id=nsg_id,
                        region=nsg.location or region,
                        account_id=subscription_id,
                        cloud_provider=CloudProvider.AZURE,
                        remediation=f"Restrict inbound rules on NSG '{nsg_name}' to specific source IPs. "
                        "Remove rules that allow * or 0.0.0.0/0 on management ports.",
                        soc2_controls=["CC6.6"],
                        details={
                            "nsg_name": nsg_name,
                            "resource_group": nsg_rg,
                            "bad_rules": bad_rules,
                        },
                    )
                )
            else:
                findings.append(
                    Finding(
                        check_id="azure-nsg-unrestricted-ingress",
                        title=f"NSG '{nsg_name}' has no unrestricted inbound rules",
                        description=f"NSG '{nsg_name}' does not allow unrestricted internet ingress on dangerous ports.",
                        severity=Severity.INFO,
                        status=ComplianceStatus.PASS,
                        domain=CheckDomain.NETWORKING,
                        resource_type="Azure::Network::NetworkSecurityGroup",
                        resource_id=nsg_id,
                        region=nsg.location or region,
                        account_id=subscription_id,
                        cloud_provider=CloudProvider.AZURE,
                        soc2_controls=["CC6.6"],
                        details={"nsg_name": nsg_name, "resource_group": nsg_rg},
                    )
                )

    except Exception as e:
        findings.append(
            Finding(
                check_id="azure-nsg-unrestricted-ingress",
                title="NSG check failed",
                description=f"Could not check Network Security Groups: {e}",
                severity=Severity.MEDIUM,
                status=ComplianceStatus.NOT_ASSESSED,
                domain=CheckDomain.NETWORKING,
                resource_type="Azure::Network::NetworkSecurityGroup",
                resource_id=f"/subscriptions/{subscription_id}/nsgs",
                region=region,
                account_id=subscription_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC6.6"],
            )
        )

    return findings


def check_nsg_default_restricted(
    client: AzureClient, subscription_id: str, region: str
) -> list[Finding]:
    """[CC6.6] Check that NSGs have explicit deny-all rules or rely on Azure defaults."""
    findings: list[Finding] = []

    try:
        from azure.mgmt.network import NetworkManagementClient

        network = client.mgmt_client(NetworkManagementClient)

        nsgs = list(network.network_security_groups.list_all())

        for nsg in nsgs:
            nsg_name = nsg.name or "unknown"
            nsg_id = nsg.id or ""

            # Check if there's a custom allow-all rule that overrides Azure's default deny
            has_allow_all = False
            for rule in nsg.security_rules or []:
                if (
                    rule.direction == "Inbound"
                    and rule.access == "Allow"
                    and (
                        rule.source_address_prefix == "*"
                        or rule.source_address_prefix == "0.0.0.0/0"
                    )
                    and rule.destination_port_range == "*"
                    and rule.protocol == "*"
                ):
                    has_allow_all = True
                    break

            if has_allow_all:
                findings.append(
                    Finding(
                        check_id="azure-nsg-default-restricted",
                        title=f"NSG '{nsg_name}' has allow-all inbound rule",
                        description=f"NSG '{nsg_name}' has a custom rule that allows ALL inbound traffic, "
                        "overriding Azure's default deny behavior.",
                        severity=Severity.HIGH,
                        status=ComplianceStatus.FAIL,
                        domain=CheckDomain.NETWORKING,
                        resource_type="Azure::Network::NetworkSecurityGroup",
                        resource_id=nsg_id,
                        region=nsg.location or region,
                        account_id=subscription_id,
                        cloud_provider=CloudProvider.AZURE,
                        remediation="Remove the allow-all inbound rule. Azure NSGs deny all inbound "
                        "traffic by default — add only specific allow rules as needed.",
                        soc2_controls=["CC6.6"],
                        details={"nsg_name": nsg_name},
                    )
                )

    except Exception:
        pass  # Non-critical — covered by nsg-unrestricted-ingress

    return findings


def check_vnet_flow_logs(client: AzureClient, subscription_id: str, region: str) -> list[Finding]:
    """[CC6.6] Check if NSG flow logs are enabled for all NSGs."""
    findings: list[Finding] = []

    try:
        from azure.mgmt.network import NetworkManagementClient

        network = client.mgmt_client(NetworkManagementClient)

        nsgs = list(network.network_security_groups.list_all())

        # Get all flow logs across network watchers
        flow_log_nsg_ids: set[str] = set()
        try:
            # List network watchers to find flow logs
            watchers = list(network.network_watchers.list_all())
            for watcher in watchers:
                watcher_rg = (
                    (watcher.id or "").split("/resourceGroups/")[1].split("/")[0]
                    if "/resourceGroups/" in (watcher.id or "")
                    else ""
                )
                if watcher_rg and watcher.name:
                    flow_logs = list(network.flow_logs.list(watcher_rg, watcher.name))
                    for fl in flow_logs:
                        if fl.enabled and fl.target_resource_id:
                            flow_log_nsg_ids.add(fl.target_resource_id.lower())
        except Exception:
            pass  # Network Watcher may not exist in all regions

        for nsg in nsgs:
            nsg_id = (nsg.id or "").lower()
            nsg_name = nsg.name or "unknown"

            if nsg_id in flow_log_nsg_ids:
                findings.append(
                    Finding(
                        check_id="azure-vnet-flow-logs",
                        title=f"Flow logs enabled for NSG '{nsg_name}'",
                        description=f"NSG '{nsg_name}' has flow logs enabled.",
                        severity=Severity.INFO,
                        status=ComplianceStatus.PASS,
                        domain=CheckDomain.NETWORKING,
                        resource_type="Azure::Network::NetworkSecurityGroup",
                        resource_id=nsg.id or "",
                        region=nsg.location or region,
                        account_id=subscription_id,
                        cloud_provider=CloudProvider.AZURE,
                        soc2_controls=["CC6.6"],
                        details={"nsg_name": nsg_name},
                    )
                )
            else:
                findings.append(
                    Finding(
                        check_id="azure-vnet-flow-logs",
                        title=f"No flow logs for NSG '{nsg_name}'",
                        description=f"NSG '{nsg_name}' does not have flow logs enabled. "
                        "Flow logs are essential for network traffic visibility and forensics.",
                        severity=Severity.MEDIUM,
                        status=ComplianceStatus.FAIL,
                        domain=CheckDomain.NETWORKING,
                        resource_type="Azure::Network::NetworkSecurityGroup",
                        resource_id=nsg.id or "",
                        region=nsg.location or region,
                        account_id=subscription_id,
                        cloud_provider=CloudProvider.AZURE,
                        remediation="Enable NSG flow logs via Network Watcher. "
                        "Network Watcher > NSG flow logs > Select NSG > Enable.",
                        soc2_controls=["CC6.6"],
                        details={"nsg_name": nsg_name},
                    )
                )

    except Exception as e:
        findings.append(
            Finding(
                check_id="azure-vnet-flow-logs",
                title="Flow log check failed",
                description=f"Could not check NSG flow logs: {e}",
                severity=Severity.MEDIUM,
                status=ComplianceStatus.NOT_ASSESSED,
                domain=CheckDomain.NETWORKING,
                resource_type="Azure::Network::FlowLog",
                resource_id=f"/subscriptions/{subscription_id}/flowLogs",
                region=region,
                account_id=subscription_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC6.6"],
            )
        )

    return findings


def check_public_ip_exposure(
    client: AzureClient, subscription_id: str, region: str
) -> list[Finding]:
    """[CC6.6] Check for public IP addresses attached to resources."""
    findings: list[Finding] = []

    try:
        from azure.mgmt.network import NetworkManagementClient

        network = client.mgmt_client(NetworkManagementClient)

        public_ips = list(network.public_ip_addresses.list_all())

        attached_pips = []
        unattached_pips = []

        for pip in public_ips:
            pip_info = {
                "name": pip.name,
                "ip_address": pip.ip_address,
                "location": pip.location,
                "allocation_method": pip.public_ip_allocation_method,
                "attached_to": None,
            }

            if pip.ip_configuration and pip.ip_configuration.id:
                pip_info["attached_to"] = pip.ip_configuration.id
                attached_pips.append(pip_info)
            else:
                unattached_pips.append(pip_info)

        if attached_pips:
            findings.append(
                Finding(
                    check_id="azure-public-ip-exposure",
                    title=f"Public IPs attached to resources ({len(attached_pips)})",
                    description=f"{len(attached_pips)} public IP address(es) are attached to resources, "
                    "creating internet exposure. Review whether public access is necessary.",
                    severity=Severity.MEDIUM,
                    status=ComplianceStatus.PARTIAL,
                    domain=CheckDomain.NETWORKING,
                    resource_type="Azure::Network::PublicIPAddress",
                    resource_id=f"/subscriptions/{subscription_id}/publicIPs",
                    region=region,
                    account_id=subscription_id,
                    cloud_provider=CloudProvider.AZURE,
                    remediation="Review each public IP and determine if internet exposure is necessary. "
                    "Use Private Endpoints or Azure Bastion instead of public IPs where possible.",
                    soc2_controls=["CC6.6"],
                    details={"attached": attached_pips, "unattached": len(unattached_pips)},
                )
            )
        elif public_ips:
            findings.append(
                Finding(
                    check_id="azure-public-ip-exposure",
                    title=f"Public IPs exist but are unattached ({len(unattached_pips)})",
                    description=f"{len(unattached_pips)} public IP address(es) exist but are not attached to any resource.",
                    severity=Severity.LOW,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.NETWORKING,
                    resource_type="Azure::Network::PublicIPAddress",
                    resource_id=f"/subscriptions/{subscription_id}/publicIPs",
                    region=region,
                    account_id=subscription_id,
                    cloud_provider=CloudProvider.AZURE,
                    soc2_controls=["CC6.6"],
                    details={"unattached": unattached_pips},
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="azure-public-ip-exposure",
                    title="No public IP addresses found",
                    description="No public IP addresses allocated in the subscription.",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.NETWORKING,
                    resource_type="Azure::Network::PublicIPAddress",
                    resource_id=f"/subscriptions/{subscription_id}/publicIPs",
                    region=region,
                    account_id=subscription_id,
                    cloud_provider=CloudProvider.AZURE,
                    soc2_controls=["CC6.6"],
                )
            )

    except Exception as e:
        findings.append(
            Finding(
                check_id="azure-public-ip-exposure",
                title="Public IP check failed",
                description=f"Could not check public IP addresses: {e}",
                severity=Severity.MEDIUM,
                status=ComplianceStatus.NOT_ASSESSED,
                domain=CheckDomain.NETWORKING,
                resource_type="Azure::Network::PublicIPAddress",
                resource_id=f"/subscriptions/{subscription_id}/publicIPs",
                region=region,
                account_id=subscription_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC6.6"],
            )
        )

    return findings
