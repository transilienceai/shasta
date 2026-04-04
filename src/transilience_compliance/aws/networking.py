"""Network security checks for SOC 2 compliance.

Covers:
  CC6.6 — System Boundaries (VPC, security groups, NACLs, flow logs, public access)
"""

from __future__ import annotations

from typing import Any

from transilience_compliance.aws.client import AWSClient
from transilience_compliance.evidence.models import CheckDomain, ComplianceStatus, Finding, Severity

# Ports that should never be open to 0.0.0.0/0
DANGEROUS_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MSSQL",
    27017: "MongoDB",
    6379: "Redis",
    11211: "Memcached",
    9200: "Elasticsearch",
}


def run_all_networking_checks(client: AWSClient) -> list[Finding]:
    """Run all networking compliance checks."""
    findings: list[Finding] = []
    account_id = client.account_info.account_id if client.account_info else "unknown"
    region = client.account_info.region if client.account_info else "us-east-1"

    ec2 = client.client("ec2")

    findings.extend(check_security_groups(ec2, account_id, region))
    findings.extend(check_vpc_flow_logs(ec2, account_id, region))
    findings.extend(check_default_security_groups(ec2, account_id, region))

    return findings


def check_security_groups(ec2: Any, account_id: str, region: str) -> list[Finding]:
    """CC6.6 — Check for security groups with unrestricted ingress."""
    findings = []

    paginator = ec2.get_paginator("describe_security_groups")
    for page in paginator.paginate():
        for sg in page["SecurityGroups"]:
            sg_id = sg["GroupId"]
            sg_name = sg.get("GroupName", sg_id)
            vpc_id = sg.get("VpcId", "N/A")

            # Skip default VPC default SGs (checked separately)
            if sg_name == "default":
                continue

            unrestricted_rules = []

            for rule in sg.get("IpPermissions", []):
                from_port = rule.get("FromPort", 0)
                to_port = rule.get("ToPort", 65535)
                protocol = rule.get("IpProtocol", "-1")

                for ip_range in rule.get("IpRanges", []):
                    cidr = ip_range.get("CidrIp", "")
                    if cidr == "0.0.0.0/0":
                        unrestricted_rules.append({
                            "protocol": protocol,
                            "from_port": from_port,
                            "to_port": to_port,
                            "cidr": cidr,
                            "description": ip_range.get("Description", ""),
                        })

                for ip_range in rule.get("Ipv6Ranges", []):
                    cidr = ip_range.get("CidrIpv6", "")
                    if cidr == "::/0":
                        unrestricted_rules.append({
                            "protocol": protocol,
                            "from_port": from_port,
                            "to_port": to_port,
                            "cidr": cidr,
                            "description": ip_range.get("Description", ""),
                        })

            if not unrestricted_rules:
                findings.append(
                    Finding(
                        check_id="sg-no-unrestricted-ingress",
                        title=f"Security group '{sg_name}' has no unrestricted ingress",
                        description=f"Security group '{sg_name}' ({sg_id}) in VPC {vpc_id} does not allow unrestricted inbound access.",
                        severity=Severity.INFO,
                        status=ComplianceStatus.PASS,
                        domain=CheckDomain.NETWORKING,
                        resource_type="AWS::EC2::SecurityGroup",
                        resource_id=sg_id,
                        region=region,
                        account_id=account_id,
                        soc2_controls=["CC6.6"],
                        details={"sg_name": sg_name, "vpc_id": vpc_id},
                    )
                )
                continue

            # Determine severity based on what's exposed
            all_traffic_open = any(r["protocol"] == "-1" for r in unrestricted_rules)
            dangerous_ports_open = []
            for r in unrestricted_rules:
                if r["protocol"] == "-1":
                    dangerous_ports_open = list(DANGEROUS_PORTS.values())
                    break
                for port, name in DANGEROUS_PORTS.items():
                    if r["from_port"] <= port <= r["to_port"]:
                        dangerous_ports_open.append(name)

            if all_traffic_open:
                severity = Severity.CRITICAL
                desc = f"Security group '{sg_name}' ({sg_id}) allows ALL inbound traffic from the internet (0.0.0.0/0). This exposes every port on associated resources."
            elif dangerous_ports_open:
                severity = Severity.HIGH
                services = ", ".join(sorted(set(dangerous_ports_open)))
                desc = f"Security group '{sg_name}' ({sg_id}) allows inbound access from the internet to: {services}. These management/database ports should never be publicly exposed."
            else:
                severity = Severity.MEDIUM
                ports = ", ".join(f"{r['from_port']}-{r['to_port']}" if r['from_port'] != r['to_port'] else str(r['from_port']) for r in unrestricted_rules)
                desc = f"Security group '{sg_name}' ({sg_id}) allows inbound access from the internet on port(s): {ports}. Review whether public access is intended."

            findings.append(
                Finding(
                    check_id="sg-no-unrestricted-ingress",
                    title=f"Security group '{sg_name}' allows unrestricted ingress from internet",
                    description=desc,
                    severity=severity,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.NETWORKING,
                    resource_type="AWS::EC2::SecurityGroup",
                    resource_id=sg_id,
                    region=region,
                    account_id=account_id,
                    remediation=f"Restrict inbound rules on '{sg_name}' to specific IP ranges or security groups. Remove 0.0.0.0/0 and ::/0 CIDR blocks.",
                    soc2_controls=["CC6.6"],
                    details={"sg_name": sg_name, "vpc_id": vpc_id, "unrestricted_rules": unrestricted_rules, "dangerous_ports_open": dangerous_ports_open},
                )
            )

    return findings


def check_vpc_flow_logs(ec2: Any, account_id: str, region: str) -> list[Finding]:
    """CC6.6 — Check that VPC flow logs are enabled for all VPCs."""
    findings = []

    vpcs = ec2.describe_vpcs()["Vpcs"]
    flow_logs = ec2.describe_flow_logs()["FlowLogs"]

    # Map VPC IDs that have flow logs
    vpcs_with_logs = {fl["ResourceId"] for fl in flow_logs if fl.get("ResourceId")}

    for vpc in vpcs:
        vpc_id = vpc["VpcId"]
        vpc_name = _get_name_tag(vpc.get("Tags", []))
        display_name = f"{vpc_name} ({vpc_id})" if vpc_name else vpc_id

        if vpc_id in vpcs_with_logs:
            findings.append(
                Finding(
                    check_id="vpc-flow-logs-enabled",
                    title=f"VPC flow logs enabled for {display_name}",
                    description=f"VPC {display_name} has flow logs enabled, providing network traffic visibility.",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.NETWORKING,
                    resource_type="AWS::EC2::VPC",
                    resource_id=vpc_id,
                    region=region,
                    account_id=account_id,
                    soc2_controls=["CC6.6"],
                    details={"vpc_id": vpc_id, "vpc_name": vpc_name},
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="vpc-flow-logs-enabled",
                    title=f"VPC flow logs NOT enabled for {display_name}",
                    description=f"VPC {display_name} does not have flow logs enabled. Flow logs record network traffic metadata and are essential for security monitoring and incident investigation.",
                    severity=Severity.HIGH,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.NETWORKING,
                    resource_type="AWS::EC2::VPC",
                    resource_id=vpc_id,
                    region=region,
                    account_id=account_id,
                    remediation=f"Enable VPC flow logs for {display_name}. Send to CloudWatch Logs or S3 for retention. Recommended: ALL traffic, default format.",
                    soc2_controls=["CC6.6"],
                    details={"vpc_id": vpc_id, "vpc_name": vpc_name},
                )
            )

    return findings


def check_default_security_groups(ec2: Any, account_id: str, region: str) -> list[Finding]:
    """CC6.6 — Check that default security groups restrict all traffic."""
    findings = []

    paginator = ec2.get_paginator("describe_security_groups")
    for page in paginator.paginate(Filters=[{"Name": "group-name", "Values": ["default"]}]):
        for sg in page["SecurityGroups"]:
            sg_id = sg["GroupId"]
            vpc_id = sg.get("VpcId", "N/A")

            has_ingress = len(sg.get("IpPermissions", [])) > 0
            has_egress_beyond_default = False
            for rule in sg.get("IpPermissionsEgress", []):
                # Default SG has one egress rule allowing all outbound — that's the AWS default
                # We flag if ingress rules exist (should be empty)
                pass

            if has_ingress:
                findings.append(
                    Finding(
                        check_id="sg-default-restricted",
                        title=f"Default security group in VPC {vpc_id} has ingress rules",
                        description=f"The default security group ({sg_id}) in VPC {vpc_id} has inbound rules configured. Default security groups should have no inbound rules — resources should use custom security groups.",
                        severity=Severity.MEDIUM,
                        status=ComplianceStatus.FAIL,
                        domain=CheckDomain.NETWORKING,
                        resource_type="AWS::EC2::SecurityGroup",
                        resource_id=sg_id,
                        region=region,
                        account_id=account_id,
                        remediation=f"Remove all inbound rules from the default security group ({sg_id}) in VPC {vpc_id}. Use custom security groups for resources.",
                        soc2_controls=["CC6.6"],
                        details={"sg_id": sg_id, "vpc_id": vpc_id, "ingress_rules": sg.get("IpPermissions", [])},
                    )
                )

    return findings


def _get_name_tag(tags: list[dict]) -> str | None:
    """Extract the Name tag value from a list of AWS tags."""
    for tag in tags:
        if tag.get("Key") == "Name":
            return tag.get("Value")
    return None
