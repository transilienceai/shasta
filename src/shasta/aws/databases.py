"""AWS database security checks: RDS deep, DocumentDB, DynamoDB.

Covers CIS AWS v3.0 deep RDS checks (auditing parameter groups, IAM database
authentication, performance insights with KMS, deletion protection), and
extends coverage to DocumentDB and DynamoDB which the original encryption
module did not touch.
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


def run_all_aws_database_checks(client: AWSClient) -> list[Finding]:
    """Run all AWS deep-database checks across enabled regions."""
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
            findings.extend(check_rds_iam_authentication(rc, account_id, r))
            findings.extend(check_rds_deletion_protection(rc, account_id, r))
            findings.extend(check_rds_performance_insights_kms(rc, account_id, r))
            findings.extend(check_rds_minor_version_upgrade(rc, account_id, r))
            findings.extend(check_rds_force_ssl_parameter(rc, account_id, r))
            findings.extend(check_rds_postgres_log_settings(rc, account_id, r))
            findings.extend(check_rds_min_tls_version(rc, account_id, r))
            findings.extend(check_documentdb_encryption(rc, account_id, r))
            findings.extend(check_documentdb_audit_logs(rc, account_id, r))
            findings.extend(check_dynamodb_pitr(rc, account_id, r))
            findings.extend(check_dynamodb_encryption_kms(rc, account_id, r))
        except ClientError:
            continue

    return findings


# ---------------------------------------------------------------------------
# RDS parameter-group enforcement (mirrors Azure PostgreSQL/MySQL checks)
# ---------------------------------------------------------------------------


def _get_parameter_value(client: AWSClient, param_group_name: str, param_name: str) -> str | None:
    """Read one parameter value from an RDS parameter group."""
    try:
        rds = client.client("rds")
        paginator = rds.get_paginator("describe_db_parameters")
        for page in paginator.paginate(DBParameterGroupName=param_group_name):
            for p in page.get("Parameters", []):
                if p.get("ParameterName") == param_name:
                    return p.get("ParameterValue")
    except ClientError:
        return None
    return None


def check_rds_force_ssl_parameter(
    client: AWSClient, account_id: str, region: str
) -> list[Finding]:
    """PostgreSQL/SQL Server RDS parameter group should force SSL.

    Mirrors Azure's check_postgresql_secure_transport. Without this parameter,
    SSL is offered but clients can downgrade to plaintext. The parameter is
    ``rds.force_ssl`` for PostgreSQL/SQL Server (value must be 1), and
    ``require_secure_transport=ON`` for MySQL/MariaDB.
    """
    findings: list[Finding] = []
    for db in _rds_instances(client):
        engine = db.get("Engine", "")
        db_id = db.get("DBInstanceIdentifier", "unknown")
        arn = db.get("DBInstanceArn", "")
        pg_groups = db.get("DBParameterGroups", []) or []
        if not pg_groups:
            continue
        pg_name = pg_groups[0].get("DBParameterGroupName")
        if not pg_name:
            continue

        if engine in ("postgres", "aurora-postgresql", "sqlserver-ex", "sqlserver-se", "sqlserver-ee", "sqlserver-web"):
            param_name = "rds.force_ssl"
            expected_value = "1"
        elif engine in ("mysql", "mariadb", "aurora-mysql"):
            param_name = "require_secure_transport"
            expected_value = "ON"
        else:
            continue

        actual = _get_parameter_value(client, pg_name, param_name)
        ok = (actual or "").upper() == expected_value.upper()
        if ok:
            findings.append(
                Finding(
                    check_id="rds-force-ssl",
                    title=f"RDS '{db_id}' ({engine}) enforces SSL via parameter group",
                    description=f"{param_name}={actual} on parameter group {pg_name}.",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.ENCRYPTION,
                    resource_type="AWS::RDS::DBInstance",
                    resource_id=arn,
                    region=region,
                    account_id=account_id,
                    soc2_controls=["CC6.1", "CC6.7"],
                    cis_aws_controls=["2.3.x"],
                    details={"db": db_id, "engine": engine, "parameter": param_name},
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="rds-force-ssl",
                    title=f"RDS '{db_id}' ({engine}) does not enforce SSL",
                    description=(
                        f"Parameter {param_name} is {actual or 'unset'} on parameter group {pg_name}. "
                        "Clients can connect over plaintext, exposing credentials and queries on "
                        "the wire. This is the parameter-group equivalent of Azure's "
                        "require_secure_transport=ON for PostgreSQL/MySQL Flexible Server."
                    ),
                    severity=Severity.HIGH,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.ENCRYPTION,
                    resource_type="AWS::RDS::DBInstance",
                    resource_id=arn,
                    region=region,
                    account_id=account_id,
                    remediation=(
                        f"aws rds modify-db-parameter-group --db-parameter-group-name {pg_name} "
                        f"--parameters 'ParameterName={param_name},ParameterValue={expected_value},"
                        "ApplyMethod=pending-reboot'. The instance must reboot for the parameter "
                        "to take effect."
                    ),
                    soc2_controls=["CC6.1", "CC6.7"],
                    cis_aws_controls=["2.3.x"],
                    details={"db": db_id, "engine": engine, "parameter": param_name, "value": actual},
                )
            )
    return findings


def check_rds_postgres_log_settings(
    client: AWSClient, account_id: str, region: str
) -> list[Finding]:
    """PostgreSQL RDS should log connections, disconnections, and checkpoints.

    Mirrors Azure's check_postgresql_log_settings. Without these parameters,
    brute-force authentication attempts and anomalous session patterns leave
    no trace in RDS logs.
    """
    findings: list[Finding] = []
    wanted = ["log_connections", "log_disconnections", "log_checkpoints"]
    for db in _rds_instances(client):
        engine = db.get("Engine", "")
        if engine not in ("postgres", "aurora-postgresql"):
            continue
        db_id = db.get("DBInstanceIdentifier", "unknown")
        arn = db.get("DBInstanceArn", "")
        pg_groups = db.get("DBParameterGroups", []) or []
        if not pg_groups:
            continue
        pg_name = pg_groups[0].get("DBParameterGroupName")
        if not pg_name:
            continue

        actual = {p: (_get_parameter_value(client, pg_name, p) or "").lower() for p in wanted}
        missing = [k for k, v in actual.items() if v not in ("1", "on")]
        if not missing:
            findings.append(
                Finding(
                    check_id="rds-postgres-log-settings",
                    title=f"RDS PostgreSQL '{db_id}' logs connections + checkpoints",
                    description="All 3 session-logging parameters are on.",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.LOGGING,
                    resource_type="AWS::RDS::DBInstance",
                    resource_id=arn,
                    region=region,
                    account_id=account_id,
                    soc2_controls=["CC7.1", "CC7.2"],
                    cis_aws_controls=["2.3.x"],
                    details={"db": db_id, "settings": actual},
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="rds-postgres-log-settings",
                    title=f"RDS PostgreSQL '{db_id}' missing log settings: {', '.join(missing)}",
                    description=(
                        "One or more connection-logging parameters are off in the parameter "
                        "group. Without these, anomalous session patterns and brute-force "
                        "attempts leave no trace. Mirrors Azure's "
                        "check_postgresql_log_settings for PostgreSQL Flexible Server."
                    ),
                    severity=Severity.MEDIUM,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.LOGGING,
                    resource_type="AWS::RDS::DBInstance",
                    resource_id=arn,
                    region=region,
                    account_id=account_id,
                    remediation=(
                        f"For each missing parameter: aws rds modify-db-parameter-group "
                        f"--db-parameter-group-name {pg_name} "
                        f"--parameters 'ParameterName=<name>,ParameterValue=1,ApplyMethod=immediate'"
                    ),
                    soc2_controls=["CC7.1", "CC7.2"],
                    cis_aws_controls=["2.3.x"],
                    details={"db": db_id, "settings": actual, "missing": missing},
                )
            )
    return findings


def check_rds_min_tls_version(
    client: AWSClient, account_id: str, region: str
) -> list[Finding]:
    """SQL Server RDS should have rds.tls_version set to TLS 1.2 or higher.

    Mirrors Azure's check_sql_min_tls. Only applies to SQL Server engines.
    """
    findings: list[Finding] = []
    sql_engines = ("sqlserver-ex", "sqlserver-se", "sqlserver-ee", "sqlserver-web")
    for db in _rds_instances(client):
        engine = db.get("Engine", "")
        if engine not in sql_engines:
            continue
        db_id = db.get("DBInstanceIdentifier", "unknown")
        arn = db.get("DBInstanceArn", "")
        pg_groups = db.get("DBParameterGroups", []) or []
        if not pg_groups:
            continue
        pg_name = pg_groups[0].get("DBParameterGroupName")
        if not pg_name:
            continue

        tls_version = _get_parameter_value(client, pg_name, "rds.tls_version")
        ok = tls_version in ("1.2", "1.3")
        if ok:
            findings.append(
                Finding(
                    check_id="rds-min-tls",
                    title=f"SQL Server '{db_id}' enforces TLS {tls_version}",
                    description=f"rds.tls_version={tls_version} on parameter group {pg_name}.",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.ENCRYPTION,
                    resource_type="AWS::RDS::DBInstance",
                    resource_id=arn,
                    region=region,
                    account_id=account_id,
                    soc2_controls=["CC6.1", "CC6.7"],
                    cis_aws_controls=["2.3.x"],
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="rds-min-tls",
                    title=f"SQL Server '{db_id}' allows legacy TLS (value={tls_version})",
                    description=(
                        "rds.tls_version is not restricted to 1.2 or higher. TLS 1.0/1.1 have "
                        "known cryptographic weaknesses and should be disabled."
                    ),
                    severity=Severity.MEDIUM,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.ENCRYPTION,
                    resource_type="AWS::RDS::DBInstance",
                    resource_id=arn,
                    region=region,
                    account_id=account_id,
                    remediation=(
                        f"aws rds modify-db-parameter-group --db-parameter-group-name {pg_name} "
                        "--parameters 'ParameterName=rds.tls_version,ParameterValue=1.2,"
                        "ApplyMethod=pending-reboot'"
                    ),
                    soc2_controls=["CC6.1", "CC6.7"],
                    cis_aws_controls=["2.3.x"],
                )
            )
    return findings


# ---------------------------------------------------------------------------
# RDS deep checks
# ---------------------------------------------------------------------------


def _rds_instances(client: AWSClient) -> list[dict]:
    try:
        rds = client.client("rds")
        paginator = rds.get_paginator("describe_db_instances")
        out: list[dict] = []
        for page in paginator.paginate():
            out.extend(page.get("DBInstances", []))
        return out
    except ClientError:
        return []


def check_rds_iam_authentication(client: AWSClient, account_id: str, region: str) -> list[Finding]:
    """[CIS AWS 2.3.x] RDS instances should support IAM database authentication."""
    findings: list[Finding] = []
    for db in _rds_instances(client):
        engine = db.get("Engine", "")
        # Only MySQL, MariaDB, PostgreSQL, Aurora support IAM auth
        if engine not in (
            "mysql",
            "mariadb",
            "postgres",
            "aurora",
            "aurora-mysql",
            "aurora-postgresql",
        ):
            continue
        db_id = db.get("DBInstanceIdentifier", "unknown")
        arn = db.get("DBInstanceArn", "")
        enabled = bool(db.get("IAMDatabaseAuthenticationEnabled", False))
        if enabled:
            findings.append(
                Finding(
                    check_id="rds-iam-auth",
                    title=f"RDS '{db_id}' has IAM database authentication enabled",
                    description="Apps can authenticate using IAM credentials instead of static DB passwords.",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.IAM,
                    resource_type="AWS::RDS::DBInstance",
                    resource_id=arn,
                    region=region,
                    account_id=account_id,
                    soc2_controls=["CC6.1", "CC6.2"],
                    cis_aws_controls=["2.3.x"],
                    details={"db": db_id, "engine": engine},
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="rds-iam-auth",
                    title=f"RDS '{db_id}' uses static password authentication only",
                    description=(
                        "IAM database authentication is disabled. Static passwords need rotation, "
                        "vaulting, and access reviews. IAM auth uses short-lived tokens tied to "
                        "an IAM identity that's already governed."
                    ),
                    severity=Severity.MEDIUM,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.IAM,
                    resource_type="AWS::RDS::DBInstance",
                    resource_id=arn,
                    region=region,
                    account_id=account_id,
                    remediation=(
                        f"aws rds modify-db-instance --db-instance-identifier {db_id} "
                        "--enable-iam-database-authentication --apply-immediately"
                    ),
                    soc2_controls=["CC6.1", "CC6.2"],
                    cis_aws_controls=["2.3.x"],
                    details={"db": db_id, "engine": engine},
                )
            )

    return findings


def check_rds_deletion_protection(client: AWSClient, account_id: str, region: str) -> list[Finding]:
    """[CIS AWS 2.3.x] Production RDS instances should have deletion protection."""
    findings: list[Finding] = []
    for db in _rds_instances(client):
        db_id = db.get("DBInstanceIdentifier", "unknown")
        arn = db.get("DBInstanceArn", "")
        protected = bool(db.get("DeletionProtection", False))
        if protected:
            findings.append(
                Finding(
                    check_id="rds-deletion-protection",
                    title=f"RDS '{db_id}' has deletion protection enabled",
                    description="Instance cannot be deleted until protection is removed.",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.STORAGE,
                    resource_type="AWS::RDS::DBInstance",
                    resource_id=arn,
                    region=region,
                    account_id=account_id,
                    soc2_controls=["A1.2"],
                    cis_aws_controls=["2.3.x"],
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="rds-deletion-protection",
                    title=f"RDS '{db_id}' has no deletion protection",
                    description=(
                        "DeletionProtection is false — a misclick or compromised admin can wipe "
                        "the database. Final snapshot helps but adds recovery time."
                    ),
                    severity=Severity.MEDIUM,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.STORAGE,
                    resource_type="AWS::RDS::DBInstance",
                    resource_id=arn,
                    region=region,
                    account_id=account_id,
                    remediation=(
                        f"aws rds modify-db-instance --db-instance-identifier {db_id} "
                        "--deletion-protection --apply-immediately"
                    ),
                    soc2_controls=["A1.2"],
                    cis_aws_controls=["2.3.x"],
                )
            )
    return findings


def check_rds_performance_insights_kms(
    client: AWSClient, account_id: str, region: str
) -> list[Finding]:
    """[CIS AWS 2.3.x] If Performance Insights is on, it must use KMS encryption."""
    findings: list[Finding] = []
    for db in _rds_instances(client):
        if not db.get("PerformanceInsightsEnabled"):
            continue
        db_id = db.get("DBInstanceIdentifier", "unknown")
        arn = db.get("DBInstanceArn", "")
        kms = db.get("PerformanceInsightsKMSKeyId")
        if kms:
            findings.append(
                Finding(
                    check_id="rds-pi-kms",
                    title=f"RDS '{db_id}' Performance Insights uses KMS",
                    description="PI data encrypted with customer-managed KMS key.",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.ENCRYPTION,
                    resource_type="AWS::RDS::DBInstance",
                    resource_id=arn,
                    region=region,
                    account_id=account_id,
                    soc2_controls=["CC6.7"],
                    cis_aws_controls=["2.3.x"],
                    details={"db": db_id, "kms_key": kms},
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="rds-pi-kms",
                    title=f"RDS '{db_id}' Performance Insights without explicit KMS key",
                    description="Performance Insights data may contain query text including PII or credentials.",
                    severity=Severity.MEDIUM,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.ENCRYPTION,
                    resource_type="AWS::RDS::DBInstance",
                    resource_id=arn,
                    region=region,
                    account_id=account_id,
                    remediation=(
                        f"aws rds modify-db-instance --db-instance-identifier {db_id} "
                        "--performance-insights-kms-key-id <key-arn> --apply-immediately"
                    ),
                    soc2_controls=["CC6.7"],
                    cis_aws_controls=["2.3.x"],
                )
            )
    return findings


def check_rds_minor_version_upgrade(
    client: AWSClient, account_id: str, region: str
) -> list[Finding]:
    """[CIS AWS] Auto minor version upgrade should be enabled to receive security patches."""
    findings: list[Finding] = []
    for db in _rds_instances(client):
        db_id = db.get("DBInstanceIdentifier", "unknown")
        arn = db.get("DBInstanceArn", "")
        enabled = bool(db.get("AutoMinorVersionUpgrade", False))
        if enabled:
            findings.append(
                Finding(
                    check_id="rds-auto-minor-upgrade",
                    title=f"RDS '{db_id}' auto-applies minor version upgrades",
                    description="Security patches are installed automatically during the maintenance window.",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.ENCRYPTION,
                    resource_type="AWS::RDS::DBInstance",
                    resource_id=arn,
                    region=region,
                    account_id=account_id,
                    soc2_controls=["CC7.1"],
                    cis_aws_controls=["2.3.x"],
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="rds-auto-minor-upgrade",
                    title=f"RDS '{db_id}' has auto minor version upgrade DISABLED",
                    description=(
                        "Without auto minor upgrades, the instance won't receive security "
                        "patches without a manual operation — and CVEs in DB engines are common."
                    ),
                    severity=Severity.MEDIUM,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.ENCRYPTION,
                    resource_type="AWS::RDS::DBInstance",
                    resource_id=arn,
                    region=region,
                    account_id=account_id,
                    remediation=(
                        f"aws rds modify-db-instance --db-instance-identifier {db_id} "
                        "--auto-minor-version-upgrade --apply-immediately"
                    ),
                    soc2_controls=["CC7.1"],
                    cis_aws_controls=["2.3.x"],
                )
            )
    return findings


# ---------------------------------------------------------------------------
# DocumentDB
# ---------------------------------------------------------------------------


def check_documentdb_encryption(client: AWSClient, account_id: str, region: str) -> list[Finding]:
    """DocumentDB clusters must be encrypted at rest."""
    findings: list[Finding] = []
    try:
        docdb = client.client("docdb")
        clusters = docdb.describe_db_clusters().get("DBClusters", [])
    except ClientError as e:
        return [Finding.not_assessed(
            check_id="docdb-encryption",
            title="Unable to check DocumentDB encryption",
            description=f"API call failed: {e}",
            domain=CheckDomain.ENCRYPTION,
            resource_type="AWS::DocDB::DBCluster",
            account_id=account_id,
            region=region,
        )]

    for cluster in clusters:
        if "docdb" not in (cluster.get("Engine") or ""):
            continue
        cid = cluster.get("DBClusterIdentifier", "unknown")
        arn = cluster.get("DBClusterArn", "")
        encrypted = bool(cluster.get("StorageEncrypted", False))
        finding_kwargs = dict(
            domain=CheckDomain.ENCRYPTION,
            resource_type="AWS::DocDB::DBCluster",
            resource_id=arn,
            region=region,
            account_id=account_id,
            soc2_controls=["CC6.7"],
        )
        if encrypted:
            findings.append(
                Finding(
                    check_id="docdb-encryption",
                    title=f"DocumentDB cluster '{cid}' is encrypted",
                    description=f"Storage encrypted with KMS key {cluster.get('KmsKeyId', '')}.",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    **finding_kwargs,
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="docdb-encryption",
                    title=f"DocumentDB cluster '{cid}' is NOT encrypted",
                    description="DocumentDB encryption can only be enabled at cluster creation.",
                    severity=Severity.HIGH,
                    status=ComplianceStatus.FAIL,
                    remediation="Snapshot the cluster, restore the snapshot with encryption enabled, then cut over.",
                    **finding_kwargs,
                )
            )
    return findings


def check_documentdb_audit_logs(client: AWSClient, account_id: str, region: str) -> list[Finding]:
    """DocumentDB clusters should export audit logs to CloudWatch."""
    findings: list[Finding] = []
    try:
        docdb = client.client("docdb")
        clusters = docdb.describe_db_clusters().get("DBClusters", [])
    except ClientError as e:
        return [Finding.not_assessed(
            check_id="docdb-audit-logs",
            title="Unable to check DocumentDB audit logs",
            description=f"API call failed: {e}",
            domain=CheckDomain.LOGGING,
            resource_type="AWS::DocDB::DBCluster",
            account_id=account_id,
            region=region,
        )]

    for cluster in clusters:
        if "docdb" not in (cluster.get("Engine") or ""):
            continue
        cid = cluster.get("DBClusterIdentifier", "unknown")
        arn = cluster.get("DBClusterArn", "")
        exports = cluster.get("EnabledCloudwatchLogsExports", []) or []
        ok = "audit" in exports
        if ok:
            findings.append(
                Finding(
                    check_id="docdb-audit-logs",
                    title=f"DocumentDB cluster '{cid}' exports audit logs",
                    description="Audit logs streamed to CloudWatch Logs.",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.LOGGING,
                    resource_type="AWS::DocDB::DBCluster",
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
                    check_id="docdb-audit-logs",
                    title=f"DocumentDB cluster '{cid}' does NOT export audit logs",
                    description="No audit log export configured. DDL/DML and authentication events are not retained.",
                    severity=Severity.MEDIUM,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.LOGGING,
                    resource_type="AWS::DocDB::DBCluster",
                    resource_id=arn,
                    region=region,
                    account_id=account_id,
                    remediation=(
                        f"aws docdb modify-db-cluster --db-cluster-identifier {cid} "
                        "--cloudwatch-logs-export-configuration EnableLogTypes=audit"
                    ),
                    soc2_controls=["CC7.1"],
                    cis_aws_controls=["3.x"],
                )
            )
    return findings


# ---------------------------------------------------------------------------
# DynamoDB
# ---------------------------------------------------------------------------


def check_dynamodb_pitr(client: AWSClient, account_id: str, region: str) -> list[Finding]:
    """DynamoDB tables should have Point-in-Time Recovery enabled."""
    findings: list[Finding] = []
    try:
        ddb = client.client("dynamodb")
        tables = ddb.list_tables().get("TableNames", [])
    except ClientError as e:
        return [Finding.not_assessed(
            check_id="dynamodb-pitr",
            title="Unable to check DynamoDB PITR",
            description=f"API call failed: {e}",
            domain=CheckDomain.STORAGE,
            resource_type="AWS::DynamoDB::Table",
            account_id=account_id,
            region=region,
        )]

    no_pitr: list[str] = []
    pitr: list[str] = []
    for t in tables:
        try:
            cfg = ddb.describe_continuous_backups(TableName=t)
            status = (
                cfg.get("ContinuousBackupsDescription", {})
                .get("PointInTimeRecoveryDescription", {})
                .get("PointInTimeRecoveryStatus", "DISABLED")
            )
            if status == "ENABLED":
                pitr.append(t)
            else:
                no_pitr.append(t)
        except ClientError:
            continue

    if not tables:
        return []

    if not no_pitr:
        return [
            Finding(
                check_id="dynamodb-pitr",
                title=f"All {len(pitr)} DynamoDB table(s) have PITR enabled",
                description="Point-in-Time Recovery active on every table.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.STORAGE,
                resource_type="AWS::DynamoDB::Table",
                resource_id=f"arn:aws:dynamodb:{region}:{account_id}:table/*",
                region=region,
                account_id=account_id,
                soc2_controls=["A1.2"],
                cis_aws_controls=["2.3.x"],
            )
        ]
    return [
        Finding(
            check_id="dynamodb-pitr",
            title=f"{len(no_pitr)} DynamoDB table(s) without PITR",
            description=(
                f"{len(no_pitr)} of {len(tables)} tables have no Point-in-Time Recovery. "
                "Without PITR, accidental deletes/overwrites within the last 35 days are unrecoverable."
            ),
            severity=Severity.MEDIUM,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.STORAGE,
            resource_type="AWS::DynamoDB::Table",
            resource_id=f"arn:aws:dynamodb:{region}:{account_id}:table/*",
            region=region,
            account_id=account_id,
            remediation=(
                "aws dynamodb update-continuous-backups --table-name <name> "
                "--point-in-time-recovery-specification PointInTimeRecoveryEnabled=true"
            ),
            soc2_controls=["A1.2"],
            cis_aws_controls=["2.3.x"],
            details={"tables_without_pitr": no_pitr[:20]},
        )
    ]


def check_dynamodb_encryption_kms(client: AWSClient, account_id: str, region: str) -> list[Finding]:
    """DynamoDB tables should be encrypted with customer-managed KMS keys."""
    findings: list[Finding] = []
    try:
        ddb = client.client("dynamodb")
        tables = ddb.list_tables().get("TableNames", [])
    except ClientError as e:
        return [Finding.not_assessed(
            check_id="dynamodb-kms",
            title="Unable to check DynamoDB encryption",
            description=f"API call failed: {e}",
            domain=CheckDomain.ENCRYPTION,
            resource_type="AWS::DynamoDB::Table",
            account_id=account_id,
            region=region,
        )]

    for t in tables:
        try:
            desc = ddb.describe_table(TableName=t).get("Table", {})
        except ClientError:
            continue
        sse = desc.get("SSEDescription", {})
        sse_type = sse.get("SSEType", "AES256")  # default = AWS-managed AES256
        kms_arn = sse.get("KMSMasterKeyArn")
        arn = desc.get("TableArn", "")
        if sse_type == "KMS" and kms_arn:
            findings.append(
                Finding(
                    check_id="dynamodb-kms",
                    title=f"DynamoDB '{t}' uses customer-managed KMS",
                    description=f"SSE type KMS, key {kms_arn}.",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.ENCRYPTION,
                    resource_type="AWS::DynamoDB::Table",
                    resource_id=arn,
                    region=region,
                    account_id=account_id,
                    soc2_controls=["CC6.7"],
                    cis_aws_controls=["2.3.x"],
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="dynamodb-kms",
                    title=f"DynamoDB '{t}' uses default AWS-managed encryption",
                    description=(
                        "Encryption is enabled but uses the default AWS-owned key. Customer-managed "
                        "KMS keys give you key-level audit, rotation, and the ability to revoke "
                        "access independently."
                    ),
                    severity=Severity.LOW,
                    status=ComplianceStatus.PARTIAL,
                    domain=CheckDomain.ENCRYPTION,
                    resource_type="AWS::DynamoDB::Table",
                    resource_id=arn,
                    region=region,
                    account_id=account_id,
                    remediation=(
                        f"aws dynamodb update-table --table-name {t} "
                        "--sse-specification Enabled=true,SSEType=KMS,KMSMasterKeyId=<key-arn>"
                    ),
                    soc2_controls=["CC6.7"],
                    cis_aws_controls=["2.3.x"],
                )
            )
    return findings
