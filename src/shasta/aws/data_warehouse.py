"""AWS data warehouse + cache + graph database checks: Redshift, ElastiCache, Neptune.

Closes a major coverage gap relative to the Azure scanner: until this
module existed, Shasta had no checks for Redshift (the AWS analytic data
warehouse), ElastiCache (Redis/Memcached), or Neptune (graph database).
These services routinely hold sensitive customer data and are common
audit findings.
"""

from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from shasta.aws.client import AWSClient
from shasta.evidence.models import (
    CheckDomain,
    ComplianceStatus,
    Finding,
    Severity,
)


# Regional. Iterates client.get_enabled_regions() per Engineering Principle #3.
IS_GLOBAL = False


def run_all_aws_data_warehouse_checks(client: AWSClient) -> list[Finding]:
    """Run all data-warehouse / cache / graph DB checks across enabled regions."""
    findings: list[Finding] = []
    account_id = client.account_info.account_id if client.account_info else "unknown"
    region = client.account_info.region if client.account_info else "us-east-1"

    try:
        regions = client.get_enabled_regions()
    except ClientError:
        regions = [region]

    for r in regions:
        try:
            rc = client.for_region(r)
            findings.extend(check_redshift_encryption(rc, account_id, r))
            findings.extend(check_redshift_public_access(rc, account_id, r))
            findings.extend(check_redshift_audit_logging(rc, account_id, r))
            findings.extend(check_redshift_require_ssl(rc, account_id, r))
            findings.extend(check_elasticache_encryption_in_transit(rc, account_id, r))
            findings.extend(check_elasticache_encryption_at_rest(rc, account_id, r))
            findings.extend(check_elasticache_auth_token(rc, account_id, r))
            findings.extend(check_neptune_encryption(rc, account_id, r))
        except ClientError:
            continue

    return findings


# ---------------------------------------------------------------------------
# Redshift
# ---------------------------------------------------------------------------


def _redshift_clusters(client: AWSClient) -> list[dict]:
    try:
        rs = client.client("redshift")
        paginator = rs.get_paginator("describe_clusters")
        out: list[dict] = []
        for page in paginator.paginate():
            out.extend(page.get("Clusters", []))
        return out
    except ClientError:
        return []


def check_redshift_encryption(
    client: AWSClient, account_id: str, region: str
) -> list[Finding]:
    """Redshift clusters must be encrypted at rest."""
    findings: list[Finding] = []
    for cluster in _redshift_clusters(client):
        cid = cluster.get("ClusterIdentifier", "unknown")
        encrypted = bool(cluster.get("Encrypted", False))
        kms = cluster.get("KmsKeyId", "")
        arn = f"arn:aws:redshift:{region}:{account_id}:cluster:{cid}"
        if encrypted:
            findings.append(
                Finding(
                    check_id="redshift-encryption",
                    title=f"Redshift cluster '{cid}' is encrypted",
                    description=f"At-rest encryption enabled with KMS key {kms or 'AWS-managed'}.",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.ENCRYPTION,
                    resource_type="AWS::Redshift::Cluster",
                    resource_id=arn,
                    region=region,
                    account_id=account_id,
                    soc2_controls=["CC6.7"],
                    cis_aws_controls=["2.x"],
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="redshift-encryption",
                    title=f"Redshift cluster '{cid}' is NOT encrypted",
                    description=(
                        "Cluster storage is unencrypted. Redshift encryption can be enabled "
                        "after creation but the migration is non-trivial — AWS performs a "
                        "background snapshot + restore which can take hours for large clusters."
                    ),
                    severity=Severity.HIGH,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.ENCRYPTION,
                    resource_type="AWS::Redshift::Cluster",
                    resource_id=arn,
                    region=region,
                    account_id=account_id,
                    remediation=(
                        f"aws redshift modify-cluster --cluster-identifier {cid} --encrypted "
                        "--kms-key-id <key-arn>. The cluster will be unavailable during the "
                        "encryption operation; schedule a maintenance window."
                    ),
                    soc2_controls=["CC6.7"],
                    cis_aws_controls=["2.x"],
                )
            )
    return findings


def check_redshift_public_access(
    client: AWSClient, account_id: str, region: str
) -> list[Finding]:
    """Redshift clusters should not be publicly accessible."""
    findings: list[Finding] = []
    for cluster in _redshift_clusters(client):
        cid = cluster.get("ClusterIdentifier", "unknown")
        public = bool(cluster.get("PubliclyAccessible", False))
        arn = f"arn:aws:redshift:{region}:{account_id}:cluster:{cid}"
        if not public:
            findings.append(
                Finding(
                    check_id="redshift-public-access",
                    title=f"Redshift cluster '{cid}' is not publicly accessible",
                    description="PubliclyAccessible=false; cluster only reachable from within VPC.",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.NETWORKING,
                    resource_type="AWS::Redshift::Cluster",
                    resource_id=arn,
                    region=region,
                    account_id=account_id,
                    soc2_controls=["CC6.6"],
                    cis_aws_controls=["2.x"],
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="redshift-public-access",
                    title=f"Redshift cluster '{cid}' is publicly accessible",
                    description=(
                        "PubliclyAccessible=true; the cluster has an internet-routable endpoint. "
                        "Even with strong authentication, this is a credential-spray surface and "
                        "common audit finding."
                    ),
                    severity=Severity.HIGH,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.NETWORKING,
                    resource_type="AWS::Redshift::Cluster",
                    resource_id=arn,
                    region=region,
                    account_id=account_id,
                    remediation=(
                        f"aws redshift modify-cluster --cluster-identifier {cid} "
                        "--no-publicly-accessible. Provide alternative access via VPN, "
                        "AWS Client VPN, or a bastion host in the same VPC."
                    ),
                    soc2_controls=["CC6.6"],
                    cis_aws_controls=["2.x"],
                )
            )
    return findings


def check_redshift_audit_logging(
    client: AWSClient, account_id: str, region: str
) -> list[Finding]:
    """Redshift clusters should have audit logging enabled."""
    findings: list[Finding] = []
    try:
        rs = client.client("redshift")
    except ClientError:
        return []
    for cluster in _redshift_clusters(client):
        cid = cluster.get("ClusterIdentifier", "unknown")
        arn = f"arn:aws:redshift:{region}:{account_id}:cluster:{cid}"
        try:
            logging_status = rs.describe_logging_status(ClusterIdentifier=cid)
        except ClientError:
            continue
        enabled = bool(logging_status.get("LoggingEnabled", False))
        if enabled:
            findings.append(
                Finding(
                    check_id="redshift-audit-logging",
                    title=f"Redshift cluster '{cid}' has audit logging enabled",
                    description=(
                        f"Logs delivered to {logging_status.get('BucketName', '')} / "
                        f"{logging_status.get('S3KeyPrefix', '')}."
                    ),
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.LOGGING,
                    resource_type="AWS::Redshift::Cluster",
                    resource_id=arn,
                    region=region,
                    account_id=account_id,
                    soc2_controls=["CC7.1"],
                    cis_aws_controls=["3.x"],
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="redshift-audit-logging",
                    title=f"Redshift cluster '{cid}' has audit logging DISABLED",
                    description=(
                        "Without audit logging, you cannot reconstruct who ran which queries "
                        "during an incident — and Redshift connection-log + user-activity-log "
                        "are required by SOC 2 audit trail expectations."
                    ),
                    severity=Severity.MEDIUM,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.LOGGING,
                    resource_type="AWS::Redshift::Cluster",
                    resource_id=arn,
                    region=region,
                    account_id=account_id,
                    remediation=(
                        f"aws redshift enable-logging --cluster-identifier {cid} "
                        "--bucket-name <log-bucket> --s3-key-prefix redshift-audit/"
                    ),
                    soc2_controls=["CC7.1"],
                    cis_aws_controls=["3.x"],
                )
            )
    return findings


def check_redshift_require_ssl(
    client: AWSClient, account_id: str, region: str
) -> list[Finding]:
    """Redshift cluster parameter group should set require_ssl=true."""
    findings: list[Finding] = []
    try:
        rs = client.client("redshift")
    except ClientError:
        return []

    for cluster in _redshift_clusters(client):
        cid = cluster.get("ClusterIdentifier", "unknown")
        arn = f"arn:aws:redshift:{region}:{account_id}:cluster:{cid}"
        param_groups = cluster.get("ClusterParameterGroups", []) or []
        require_ssl_set = False
        for pg in param_groups:
            pg_name = pg.get("ParameterGroupName")
            if not pg_name:
                continue
            try:
                params_resp = rs.describe_cluster_parameters(ParameterGroupName=pg_name)
                for param in params_resp.get("Parameters", []):
                    if param.get("ParameterName") == "require_ssl" and param.get("ParameterValue") in ("true", "1"):
                        require_ssl_set = True
                        break
            except ClientError:
                continue
            if require_ssl_set:
                break

        if require_ssl_set:
            findings.append(
                Finding(
                    check_id="redshift-require-ssl",
                    title=f"Redshift cluster '{cid}' requires SSL connections",
                    description="Parameter group has require_ssl=true.",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.ENCRYPTION,
                    resource_type="AWS::Redshift::Cluster",
                    resource_id=arn,
                    region=region,
                    account_id=account_id,
                    soc2_controls=["CC6.1", "CC6.7"],
                    cis_aws_controls=["2.x"],
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="redshift-require-ssl",
                    title=f"Redshift cluster '{cid}' does not require SSL",
                    description=(
                        "require_ssl is not set in the parameter group. Clients can connect over "
                        "plaintext, and credentials/queries traverse the wire in clear."
                    ),
                    severity=Severity.MEDIUM,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.ENCRYPTION,
                    resource_type="AWS::Redshift::Cluster",
                    resource_id=arn,
                    region=region,
                    account_id=account_id,
                    remediation=(
                        "Edit the cluster parameter group: aws redshift modify-cluster-parameter-group "
                        "--parameter-group-name <pg> --parameters ParameterName=require_ssl,ParameterValue=true "
                        "--apply-type dynamic. Reboot may be required."
                    ),
                    soc2_controls=["CC6.1", "CC6.7"],
                    cis_aws_controls=["2.x"],
                )
            )
    return findings


# ---------------------------------------------------------------------------
# ElastiCache
# ---------------------------------------------------------------------------


def _elasticache_clusters(client: AWSClient) -> list[dict]:
    """Returns Redis replication groups (preferred over node-level cache clusters)."""
    try:
        ec = client.client("elasticache")
        paginator = ec.get_paginator("describe_replication_groups")
        out: list[dict] = []
        for page in paginator.paginate():
            out.extend(page.get("ReplicationGroups", []))
        return out
    except ClientError:
        return []


def check_elasticache_encryption_in_transit(
    client: AWSClient, account_id: str, region: str
) -> list[Finding]:
    """[CIS AWS] ElastiCache Redis replication groups must have transit encryption enabled."""
    findings: list[Finding] = []
    for rg in _elasticache_clusters(client):
        rg_id = rg.get("ReplicationGroupId", "unknown")
        arn = rg.get("ARN", "")
        in_transit = bool(rg.get("TransitEncryptionEnabled", False))
        if in_transit:
            findings.append(
                Finding(
                    check_id="elasticache-transit-encryption",
                    title=f"ElastiCache '{rg_id}' encrypts traffic in transit",
                    description="TransitEncryptionEnabled=true.",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.ENCRYPTION,
                    resource_type="AWS::ElastiCache::ReplicationGroup",
                    resource_id=arn,
                    region=region,
                    account_id=account_id,
                    soc2_controls=["CC6.7"],
                    cis_aws_controls=["2.x"],
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="elasticache-transit-encryption",
                    title=f"ElastiCache '{rg_id}' does NOT encrypt in transit",
                    description=(
                        "Redis traffic between clients and the cluster is in plaintext. Cached "
                        "session data, API tokens, and PII traversing the cache are exposed to "
                        "anyone on the network path."
                    ),
                    severity=Severity.HIGH,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.ENCRYPTION,
                    resource_type="AWS::ElastiCache::ReplicationGroup",
                    resource_id=arn,
                    region=region,
                    account_id=account_id,
                    remediation=(
                        "Transit encryption can only be enabled at replication group creation. "
                        "Create a new replication group with TransitEncryptionEnabled=true, "
                        "migrate data via online migration or application-level dual-write, "
                        "then cut over."
                    ),
                    soc2_controls=["CC6.7"],
                    cis_aws_controls=["2.x"],
                )
            )
    return findings


def check_elasticache_encryption_at_rest(
    client: AWSClient, account_id: str, region: str
) -> list[Finding]:
    """[CIS AWS] ElastiCache Redis replication groups must have at-rest encryption enabled."""
    findings: list[Finding] = []
    for rg in _elasticache_clusters(client):
        rg_id = rg.get("ReplicationGroupId", "unknown")
        arn = rg.get("ARN", "")
        at_rest = bool(rg.get("AtRestEncryptionEnabled", False))
        if at_rest:
            findings.append(
                Finding(
                    check_id="elasticache-at-rest-encryption",
                    title=f"ElastiCache '{rg_id}' encrypts at rest",
                    description="AtRestEncryptionEnabled=true.",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.ENCRYPTION,
                    resource_type="AWS::ElastiCache::ReplicationGroup",
                    resource_id=arn,
                    region=region,
                    account_id=account_id,
                    soc2_controls=["CC6.7"],
                    cis_aws_controls=["2.x"],
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="elasticache-at-rest-encryption",
                    title=f"ElastiCache '{rg_id}' does NOT encrypt at rest",
                    description=(
                        "Snapshots and node-level disk storage are unencrypted. Same caveat as "
                        "transit encryption: at-rest encryption can only be enabled at creation."
                    ),
                    severity=Severity.HIGH,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.ENCRYPTION,
                    resource_type="AWS::ElastiCache::ReplicationGroup",
                    resource_id=arn,
                    region=region,
                    account_id=account_id,
                    remediation=(
                        "Recreate the replication group with AtRestEncryptionEnabled=true and "
                        "a customer-managed KMS key. Migrate data and cut over."
                    ),
                    soc2_controls=["CC6.7"],
                    cis_aws_controls=["2.x"],
                )
            )
    return findings


def check_elasticache_auth_token(
    client: AWSClient, account_id: str, region: str
) -> list[Finding]:
    """[CIS AWS] ElastiCache Redis with transit encryption should also have AUTH token enabled."""
    findings: list[Finding] = []
    for rg in _elasticache_clusters(client):
        rg_id = rg.get("ReplicationGroupId", "unknown")
        arn = rg.get("ARN", "")
        auth_enabled = bool(rg.get("AuthTokenEnabled", False))
        in_transit = bool(rg.get("TransitEncryptionEnabled", False))
        # Auth tokens only work with transit encryption — skip if no TLS
        if not in_transit:
            continue
        if auth_enabled:
            findings.append(
                Finding(
                    check_id="elasticache-auth-token",
                    title=f"ElastiCache '{rg_id}' has AUTH token enabled",
                    description="Redis AUTH password configured for client authentication.",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.IAM,
                    resource_type="AWS::ElastiCache::ReplicationGroup",
                    resource_id=arn,
                    region=region,
                    account_id=account_id,
                    soc2_controls=["CC6.1"],
                    cis_aws_controls=["2.x"],
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="elasticache-auth-token",
                    title=f"ElastiCache '{rg_id}' has no AUTH token",
                    description=(
                        "Transit encryption is enabled but no AUTH token is configured. Anyone "
                        "in the same VPC subnet can connect to Redis without credentials. The "
                        "AUTH token adds a password layer on top of TLS."
                    ),
                    severity=Severity.MEDIUM,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.IAM,
                    resource_type="AWS::ElastiCache::ReplicationGroup",
                    resource_id=arn,
                    region=region,
                    account_id=account_id,
                    remediation=(
                        "Set an AUTH token on the replication group: "
                        "aws elasticache modify-replication-group --replication-group-id <id> "
                        "--auth-token <strong-secret> --auth-token-update-strategy ROTATE."
                    ),
                    soc2_controls=["CC6.1"],
                    cis_aws_controls=["2.x"],
                )
            )
    return findings


# ---------------------------------------------------------------------------
# Neptune
# ---------------------------------------------------------------------------


def check_neptune_encryption(
    client: AWSClient, account_id: str, region: str
) -> list[Finding]:
    """Neptune clusters must be encrypted at rest."""
    try:
        neptune = client.client("neptune")
        clusters = neptune.describe_db_clusters().get("DBClusters", [])
    except ClientError:
        return []

    findings: list[Finding] = []
    for cluster in clusters:
        if cluster.get("Engine") != "neptune":
            continue
        cid = cluster.get("DBClusterIdentifier", "unknown")
        arn = cluster.get("DBClusterArn", "")
        encrypted = bool(cluster.get("StorageEncrypted", False))
        if encrypted:
            findings.append(
                Finding(
                    check_id="neptune-encryption",
                    title=f"Neptune cluster '{cid}' is encrypted",
                    description=f"StorageEncrypted=true with KMS key {cluster.get('KmsKeyId', '')}.",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.ENCRYPTION,
                    resource_type="AWS::Neptune::DBCluster",
                    resource_id=arn,
                    region=region,
                    account_id=account_id,
                    soc2_controls=["CC6.7"],
                    cis_aws_controls=["2.x"],
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="neptune-encryption",
                    title=f"Neptune cluster '{cid}' is NOT encrypted",
                    description=(
                        "Cluster storage is unencrypted. Neptune encryption can only be enabled "
                        "at cluster creation; existing unencrypted clusters require a snapshot, "
                        "encrypted-restore, and cutover."
                    ),
                    severity=Severity.HIGH,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.ENCRYPTION,
                    resource_type="AWS::Neptune::DBCluster",
                    resource_id=arn,
                    region=region,
                    account_id=account_id,
                    remediation=(
                        "Snapshot the cluster, restore the snapshot with --storage-encrypted "
                        "--kms-key-id <key>, then cut over and delete the old cluster."
                    ),
                    soc2_controls=["CC6.7"],
                    cis_aws_controls=["2.x"],
                )
            )
    return findings
