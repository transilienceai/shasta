"""Remediation engine — generates prioritized fix recommendations and Terraform code.

For each failing finding, produces:
  1. Plain-English explanation of what's wrong and why it matters
  2. Step-by-step remediation instructions
  3. Terraform code to fix the issue (where applicable)
  4. Priority score for ordering the remediation roadmap
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from shasta.evidence.models import ComplianceStatus, Finding, Severity

SEVERITY_PRIORITY = {
    Severity.CRITICAL: 1,
    Severity.HIGH: 2,
    Severity.MEDIUM: 3,
    Severity.LOW: 4,
    Severity.INFO: 5,
}


@dataclass
class Remediation:
    """A remediation recommendation for a finding."""

    finding: Finding
    priority: int
    explanation: str  # Why this matters (founder-friendly)
    steps: list[str]  # Step-by-step instructions
    terraform: str = ""  # Terraform code to fix, if applicable
    effort: str = ""  # "quick" (<30min), "moderate" (1-4hrs), "significant" (>4hrs)
    category: str = ""  # "iam", "networking", "storage", "monitoring"


# ---------------------------------------------------------------------------
# Terraform template registry — maps check_id to a Terraform generator
# ---------------------------------------------------------------------------

TERRAFORM_TEMPLATES: dict[str, callable] = {}


def _tf(check_id: str):
    """Decorator to register a Terraform template generator."""

    def decorator(fn):
        TERRAFORM_TEMPLATES[check_id] = fn
        return fn

    return decorator


@_tf("iam-password-policy")
def _tf_password_policy(f: Finding) -> str:
    return """\
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 14
  require_lowercase_characters   = true
  require_uppercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  max_password_age               = 90
  password_reuse_prevention      = 12
  hard_expiry                    = false
}"""


@_tf("iam-user-mfa")
def _tf_user_mfa(f: Finding) -> str:
    username = f.details.get("username", "USERNAME")
    return f"""\
# MFA must be enabled manually or via CLI — Terraform cannot create virtual MFA devices.
# Run the following AWS CLI commands:

# 1. Create a virtual MFA device:
#    aws iam create-virtual-mfa-device --virtual-mfa-device-name {username}-mfa \\
#        --outfile /tmp/{username}-qr.png --bootstrap-method QRCodePNG

# 2. Scan the QR code with an authenticator app (Google Authenticator, Authy, etc.)

# 3. Enable MFA for the user (replace CODE1 and CODE2 with two consecutive codes):
#    aws iam enable-mfa-device --user-name {username} \\
#        --serial-number arn:aws:iam::ACCOUNT_ID:mfa/{username}-mfa \\
#        --authentication-code1 CODE1 --authentication-code2 CODE2"""


@_tf("iam-no-direct-policies")
def _tf_no_direct_policies(f: Finding) -> str:
    username = f.details.get("username", "USERNAME")
    attached = f.details.get("attached_policies", [])
    policies_block = "\n".join(f"  # - {p}" for p in attached)
    return f'''\
# Move direct policies from user '{username}' to a group.
# Currently attached directly:
{policies_block}

resource "aws_iam_group" "{username}_group" {{
  name = "{username}-role-group"
}}

resource "aws_iam_group_membership" "{username}_membership" {{
  name  = "{username}-membership"
  users = ["{username}"]
  group = aws_iam_group.{username}_group.name
}}

# Attach the policies to the group instead of the user.
# Then remove direct user policy attachments.'''


@_tf("iam-overprivileged-user")
def _tf_overprivileged(f: Finding) -> str:
    username = f.details.get("username", "USERNAME")
    return f'''\
# Replace AdministratorAccess for user '{username}' with scoped policies.
# Step 1: Identify what the user actually needs access to.
# Step 2: Create a custom policy with minimum required permissions.
# Step 3: Remove the admin policy and attach the scoped one.

# Example: If the user only needs S3 and EC2 read access:
resource "aws_iam_policy" "{username}_scoped" {{
  name        = "{username}-scoped-access"
  description = "Scoped permissions for {username} — replaces AdministratorAccess"

  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [
      {{
        Effect   = "Allow"
        Action   = [
          "s3:Get*",
          "s3:List*",
          "ec2:Describe*",
        ]
        Resource = "*"
      }}
    ]
  }})
}}

# IMPORTANT: Customize the actions and resources above based on
# what '{username}' actually needs to do.'''


@_tf("sg-no-unrestricted-ingress")
def _tf_restrict_sg(f: Finding) -> str:
    sg_name = f.details.get("sg_name", "SECURITY_GROUP")
    sg_id = f.resource_id
    rules = f.details.get("unrestricted_rules", [])

    rules_desc = []
    for r in rules:
        if r.get("protocol") == "-1":
            rules_desc.append("all traffic")
        else:
            rules_desc.append(f"port {r.get('from_port')}-{r.get('to_port')}")

    return f'''\
# Security group '{sg_name}' ({sg_id}) currently allows unrestricted
# ingress for: {", ".join(rules_desc)}
#
# Replace 0.0.0.0/0 with your specific IP ranges:

# Option 1: Restrict to your office/VPN IP
# Find your IP: curl -s ifconfig.me
resource "aws_vpc_security_group_ingress_rule" "{sg_name}_restricted" {{
  security_group_id = "{sg_id}"
  from_port         = 443  # Adjust port as needed
  to_port           = 443
  ip_protocol       = "tcp"
  cidr_ipv4         = "YOUR_OFFICE_IP/32"  # Replace with your actual IP
  description       = "HTTPS from office"
}}

# Option 2: If this SG is no longer needed, delete it:
# aws ec2 delete-security-group --group-id {sg_id}
#
# First check nothing is using it:
# aws ec2 describe-network-interfaces --filters Name=group-id,Values={sg_id}'''


@_tf("vpc-flow-logs-enabled")
def _tf_vpc_flow_logs(f: Finding) -> str:
    vpc_id = f.resource_id
    vpc_name = f.details.get("vpc_name", "")
    safe_name = (vpc_name or vpc_id).replace("-", "_").replace(" ", "_")
    return f'''\
resource "aws_flow_log" "{safe_name}_flow_log" {{
  vpc_id          = "{vpc_id}"
  traffic_type    = "ALL"
  log_destination = aws_cloudwatch_log_group.{safe_name}_flow.arn
  iam_role_arn    = aws_iam_role.flow_log_role.arn
}}

resource "aws_cloudwatch_log_group" "{safe_name}_flow" {{
  name              = "/aws/vpc/flow-logs/{vpc_id}"
  retention_in_days = 90
}}

resource "aws_iam_role" "flow_log_role" {{
  name = "vpc-flow-log-role"
  assume_role_policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [{{
      Effect    = "Allow"
      Principal = {{ Service = "vpc-flow-logs.amazonaws.com" }}
      Action    = "sts:AssumeRole"
    }}]
  }})
}}

resource "aws_iam_role_policy" "flow_log_policy" {{
  name = "vpc-flow-log-policy"
  role = aws_iam_role.flow_log_role.id
  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [{{
      Effect = "Allow"
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ]
      Resource = "*"
    }}]
  }})
}}'''


@_tf("s3-versioning")
def _tf_s3_versioning(f: Finding) -> str:
    bucket = f.details.get("bucket", "BUCKET_NAME")
    return f'''\
resource "aws_s3_bucket_versioning" "{bucket.replace("-", "_")}" {{
  bucket = "{bucket}"
  versioning_configuration {{
    status = "Enabled"
  }}
}}'''


@_tf("s3-ssl-only")
def _tf_s3_ssl(f: Finding) -> str:
    bucket = f.details.get("bucket", "BUCKET_NAME")
    safe = bucket.replace("-", "_")
    return f'''\
resource "aws_s3_bucket_policy" "{safe}_ssl_only" {{
  bucket = "{bucket}"
  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [{{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [
        "arn:aws:s3:::{bucket}",
        "arn:aws:s3:::{bucket}/*"
      ]
      Condition = {{
        Bool = {{ "aws:SecureTransport" = "false" }}
      }}
    }}]
  }})
}}'''


@_tf("s3-public-access-block")
def _tf_s3_public_block(f: Finding) -> str:
    bucket = f.details.get("bucket", "BUCKET_NAME")
    safe = bucket.replace("-", "_")
    return f'''\
resource "aws_s3_bucket_public_access_block" "{safe}" {{
  bucket                  = "{bucket}"
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}}'''


@_tf("s3-encryption-at-rest")
def _tf_s3_encryption(f: Finding) -> str:
    bucket = f.details.get("bucket", "BUCKET_NAME")
    safe = bucket.replace("-", "_")
    return f'''\
resource "aws_s3_bucket_server_side_encryption_configuration" "{safe}" {{
  bucket = "{bucket}"
  rule {{
    apply_server_side_encryption_by_default {{
      sse_algorithm = "aws:kms"
    }}
    bucket_key_enabled = true
  }}
}}'''


# ---------------------------------------------------------------------------
# Azure (azurerm) Terraform templates — covers the Stage 1/2/3 CIS Azure
# v3.0 checks. Each template is a focused snippet that the operator drops
# into the matching resource block; full resource definitions are intentionally
# avoided so we don't overwrite unrelated configuration.
# ---------------------------------------------------------------------------


def _safe(name: str) -> str:
    """Sanitize a resource name for use as a Terraform identifier."""
    return (name or "RESOURCE").replace("-", "_").replace(".", "_").replace("/", "_")


# ----- Storage Account checks -----


@_tf("azure-storage-shared-key-access")
def _tf_az_storage_shared_key(f: Finding) -> str:
    name = f.details.get("storage_account", "STORAGE_ACCOUNT")
    rg = f.details.get("resource_group", "RESOURCE_GROUP")
    return f'''\
resource "azurerm_storage_account" "{_safe(name)}" {{
  name                = "{name}"
  resource_group_name = "{rg}"
  # ... existing config ...

  # Disable account-key auth — force Entra ID-only access (CIS 3.3)
  shared_access_key_enabled = false
}}'''


@_tf("azure-storage-cross-tenant-replication")
def _tf_az_storage_cross_tenant(f: Finding) -> str:
    name = f.details.get("storage_account", "STORAGE_ACCOUNT")
    rg = f.details.get("resource_group", "RESOURCE_GROUP")
    return f'''\
resource "azurerm_storage_account" "{_safe(name)}" {{
  name                = "{name}"
  resource_group_name = "{rg}"
  # ... existing config ...

  # Block cross-tenant object replication (CIS 3.15)
  cross_tenant_replication_enabled = false
}}'''


@_tf("azure-storage-network-default-deny")
def _tf_az_storage_default_deny(f: Finding) -> str:
    name = f.details.get("storage_account", "STORAGE_ACCOUNT")
    rg = f.details.get("resource_group", "RESOURCE_GROUP")
    return f'''\
resource "azurerm_storage_account" "{_safe(name)}" {{
  name                = "{name}"
  resource_group_name = "{rg}"
  # ... existing config ...

  # Network default-Deny with explicit allowlist (CIS 3.8)
  network_rules {{
    default_action             = "Deny"
    bypass                     = ["AzureServices", "Logging", "Metrics"]
    ip_rules                   = []  # Add trusted IPs here
    virtual_network_subnet_ids = []  # Add trusted subnet IDs here
  }}
}}'''


# ----- Key Vault checks -----


@_tf("azure-keyvault-rbac-mode")
def _tf_az_kv_rbac(f: Finding) -> str:
    name = f.details.get("vault", "KEY_VAULT")
    return f'''\
resource "azurerm_key_vault" "{_safe(name)}" {{
  name = "{name}"
  # ... existing config ...

  # Use Azure RBAC instead of legacy access policies (CIS 8.5)
  enable_rbac_authorization = true
}}

# Re-grant access via RBAC role assignments after switching modes:
resource "azurerm_role_assignment" "{_safe(name)}_admin" {{
  scope                = azurerm_key_vault.{_safe(name)}.id
  role_definition_name = "Key Vault Administrator"
  principal_id         = "PRINCIPAL_OBJECT_ID"
}}'''


@_tf("azure-keyvault-public-access")
def _tf_az_kv_public_access(f: Finding) -> str:
    name = f.details.get("vault", "KEY_VAULT")
    return f'''\
resource "azurerm_key_vault" "{_safe(name)}" {{
  name = "{name}"
  # ... existing config ...

  # Disable public network access (CIS 8.7)
  public_network_access_enabled = false

  # Default-Deny network ACLs (CIS 8.6)
  network_acls {{
    default_action = "Deny"
    bypass         = "AzureServices"
    ip_rules       = []
  }}
}}

# Pair with a Private Endpoint:
resource "azurerm_private_endpoint" "{_safe(name)}_pe" {{
  name                = "{name}-pe"
  location            = "LOCATION"
  resource_group_name = "RESOURCE_GROUP"
  subnet_id           = "SUBNET_ID"

  private_service_connection {{
    name                           = "{name}-psc"
    private_connection_resource_id = azurerm_key_vault.{_safe(name)}.id
    subresource_names              = ["vault"]
    is_manual_connection           = false
  }}
}}'''


# ----- SQL Server checks -----


@_tf("azure-sql-min-tls")
def _tf_az_sql_min_tls(f: Finding) -> str:
    server = f.details.get("server", "SQL_SERVER")
    return f'''\
resource "azurerm_mssql_server" "{_safe(server)}" {{
  name = "{server}"
  # ... existing config ...

  # Enforce TLS 1.2 (CIS 4.1.7)
  minimum_tls_version = "1.2"
}}'''


@_tf("azure-sql-auditing")
def _tf_az_sql_auditing(f: Finding) -> str:
    server = f.details.get("server", "SQL_SERVER")
    return f'''\
# Server-level auditing with ≥90-day retention (CIS 4.1.1, 4.1.6)
resource "azurerm_mssql_server_extended_auditing_policy" "{_safe(server)}" {{
  server_id                               = azurerm_mssql_server.{_safe(server)}.id
  storage_endpoint                        = "https://AUDITSTORAGE.blob.core.windows.net/"
  storage_account_access_key              = ""  # Use managed identity instead
  storage_account_access_key_is_secondary = false
  retention_in_days                       = 90
  log_monitoring_enabled                  = true
}}

# Also send to Log Analytics for query + alerting:
resource "azurerm_monitor_diagnostic_setting" "{_safe(server)}_audit" {{
  name                       = "{server}-audit"
  target_resource_id         = "${{azurerm_mssql_server.{_safe(server)}.id}}/databases/master"
  log_analytics_workspace_id = "LOG_ANALYTICS_WORKSPACE_ID"

  enabled_log {{ category = "SQLSecurityAuditEvents" }}
  enabled_log {{ category = "DevOpsOperationsAudit" }}
}}'''


@_tf("azure-sql-entra-admin")
def _tf_az_sql_entra_admin(f: Finding) -> str:
    server = f.details.get("server", "SQL_SERVER")
    return f'''\
resource "azurerm_mssql_server" "{_safe(server)}" {{
  name = "{server}"
  # ... existing config ...

  # Entra ID admin (CIS 4.1.3) — prefer an Entra group for break-glass
  azuread_administrator {{
    login_username              = "sql-admins"
    object_id                   = "ENTRA_GROUP_OBJECT_ID"
    azuread_authentication_only = true
  }}
}}'''


# ----- PostgreSQL Flexible Server -----


@_tf("azure-postgres-secure-transport")
def _tf_az_pg_secure_transport(f: Finding) -> str:
    server = f.details.get("server", "PG_SERVER")
    return f'''\
# Force TLS-only connections (CIS 4.3.1)
resource "azurerm_postgresql_flexible_server_configuration" "{_safe(server)}_secure_transport" {{
  name      = "require_secure_transport"
  server_id = azurerm_postgresql_flexible_server.{_safe(server)}.id
  value     = "ON"
}}'''


@_tf("azure-postgres-log-settings")
def _tf_az_pg_log_settings(f: Finding) -> str:
    server = f.details.get("server", "PG_SERVER")
    safe = _safe(server)
    return f'''\
# Connection logging (CIS 4.3.2 - 4.3.4)
resource "azurerm_postgresql_flexible_server_configuration" "{safe}_log_connections" {{
  name      = "log_connections"
  server_id = azurerm_postgresql_flexible_server.{safe}.id
  value     = "ON"
}}

resource "azurerm_postgresql_flexible_server_configuration" "{safe}_log_disconnections" {{
  name      = "log_disconnections"
  server_id = azurerm_postgresql_flexible_server.{safe}.id
  value     = "ON"
}}

resource "azurerm_postgresql_flexible_server_configuration" "{safe}_log_checkpoints" {{
  name      = "log_checkpoints"
  server_id = azurerm_postgresql_flexible_server.{safe}.id
  value     = "ON"
}}'''


# ----- MySQL Flexible Server -----


@_tf("azure-mysql-secure-transport")
def _tf_az_mysql_secure_transport(f: Finding) -> str:
    server = f.details.get("server", "MYSQL_SERVER")
    return f'''\
# Force TLS-only connections (CIS 4.4.1)
resource "azurerm_mysql_flexible_server_configuration" "{_safe(server)}_secure_transport" {{
  name                = "require_secure_transport"
  resource_group_name = "RESOURCE_GROUP"
  server_name         = azurerm_mysql_flexible_server.{_safe(server)}.name
  value               = "ON"
}}'''


@_tf("azure-mysql-tls-version")
def _tf_az_mysql_tls_version(f: Finding) -> str:
    server = f.details.get("server", "MYSQL_SERVER")
    return f'''\
# Restrict to TLS 1.2 / 1.3 (CIS 4.4.2)
resource "azurerm_mysql_flexible_server_configuration" "{_safe(server)}_tls_version" {{
  name                = "tls_version"
  resource_group_name = "RESOURCE_GROUP"
  server_name         = azurerm_mysql_flexible_server.{_safe(server)}.name
  value               = "TLSv1.2,TLSv1.3"
}}'''


@_tf("azure-mysql-audit-log")
def _tf_az_mysql_audit_log(f: Finding) -> str:
    server = f.details.get("server", "MYSQL_SERVER")
    return f'''\
# Enable audit logging (CIS 4.4.3)
resource "azurerm_mysql_flexible_server_configuration" "{_safe(server)}_audit" {{
  name                = "audit_log_enabled"
  resource_group_name = "RESOURCE_GROUP"
  server_name         = azurerm_mysql_flexible_server.{_safe(server)}.name
  value               = "ON"
}}'''


# ----- Cosmos DB -----


@_tf("azure-cosmos-disable-local-auth")
def _tf_az_cosmos_local_auth(f: Finding) -> str:
    name = f.details.get("account", "COSMOS_ACCOUNT")
    return f'''\
resource "azurerm_cosmosdb_account" "{_safe(name)}" {{
  name = "{name}"
  # ... existing config ...

  # Force Entra ID-only access (CIS 4.5.1)
  local_authentication_disabled = true
}}'''


@_tf("azure-cosmos-public-access")
def _tf_az_cosmos_public(f: Finding) -> str:
    name = f.details.get("account", "COSMOS_ACCOUNT")
    return f'''\
resource "azurerm_cosmosdb_account" "{_safe(name)}" {{
  name = "{name}"
  # ... existing config ...

  # Disable public network access (CIS 4.5.2)
  public_network_access_enabled = false
  is_virtual_network_filter_enabled = true
}}'''


@_tf("azure-cosmos-firewall")
def _tf_az_cosmos_firewall(f: Finding) -> str:
    name = f.details.get("account", "COSMOS_ACCOUNT")
    return f'''\
resource "azurerm_cosmosdb_account" "{_safe(name)}" {{
  name = "{name}"
  # ... existing config ...

  # Restrict network access — explicit IP / VNet rules (CIS 4.5.3)
  is_virtual_network_filter_enabled = true
  ip_range_filter                   = ["198.51.100.0/24"]  # replace with trusted CIDRs

  virtual_network_rule {{
    id                                   = "SUBNET_ID"
    ignore_missing_vnet_service_endpoint = false
  }}
}}'''


# ----- App Service -----


@_tf("azure-appservice-https-only")
def _tf_az_appsvc_https(f: Finding) -> str:
    name = f.details.get("app", "APP_SERVICE")
    return f'''\
resource "azurerm_linux_web_app" "{_safe(name)}" {{
  name = "{name}"
  # ... existing config ...

  # Enforce HTTPS-only (CIS 9.2)
  https_only = true
}}'''


@_tf("azure-appservice-min-tls")
def _tf_az_appsvc_min_tls(f: Finding) -> str:
    name = f.details.get("app", "APP_SERVICE")
    return f'''\
resource "azurerm_linux_web_app" "{_safe(name)}" {{
  name = "{name}"
  # ... existing config ...

  site_config {{
    # Enforce TLS 1.2+ (CIS 9.3)
    minimum_tls_version     = "1.2"
    scm_minimum_tls_version = "1.2"
  }}
}}'''


@_tf("azure-appservice-ftps")
def _tf_az_appsvc_ftps(f: Finding) -> str:
    name = f.details.get("app", "APP_SERVICE")
    return f'''\
resource "azurerm_linux_web_app" "{_safe(name)}" {{
  name = "{name}"
  # ... existing config ...

  site_config {{
    # Block plain FTP (CIS 9.10)
    ftps_state = "Disabled"  # or "FtpsOnly" if FTPS uploads are required
  }}
}}'''


@_tf("azure-appservice-remote-debug")
def _tf_az_appsvc_remote_debug(f: Finding) -> str:
    name = f.details.get("app", "APP_SERVICE")
    return f'''\
resource "azurerm_linux_web_app" "{_safe(name)}" {{
  name = "{name}"
  # ... existing config ...

  site_config {{
    # Disable remote debugging in production (CIS 9.5)
    remote_debugging_enabled = false
  }}
}}'''


@_tf("azure-appservice-managed-identity")
def _tf_az_appsvc_msi(f: Finding) -> str:
    name = f.details.get("app", "APP_SERVICE")
    return f'''\
resource "azurerm_linux_web_app" "{_safe(name)}" {{
  name = "{name}"
  # ... existing config ...

  # Use managed identity instead of stored credentials (CIS 9.11)
  identity {{
    type = "SystemAssigned"
  }}
}}

# Then grant the identity access to the resources it needs:
resource "azurerm_role_assignment" "{_safe(name)}_kv_access" {{
  scope                = "KEY_VAULT_ID"
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_linux_web_app.{_safe(name)}.identity[0].principal_id
}}'''


# ----- Recovery Services Vault -----


@_tf("azure-rsv-soft-delete")
def _tf_az_rsv_soft_delete(f: Finding) -> str:
    name = f.details.get("vault", "RSV")
    return f'''\
resource "azurerm_recovery_services_vault" "{_safe(name)}" {{
  name = "{name}"
  # ... existing config ...

  # Enable irreversible soft delete (MCSB BR-2)
  soft_delete_enabled = true
}}'''


@_tf("azure-rsv-immutability")
def _tf_az_rsv_immutability(f: Finding) -> str:
    name = f.details.get("vault", "RSV")
    return f'''\
resource "azurerm_recovery_services_vault" "{_safe(name)}" {{
  name = "{name}"
  # ... existing config ...

  # Enable immutability and lock it (MCSB BR-2.3)
  immutability = "Locked"  # WARNING: irreversible once Locked
}}'''


@_tf("azure-rsv-redundancy")
def _tf_az_rsv_redundancy(f: Finding) -> str:
    name = f.details.get("vault", "RSV")
    return f'''\
resource "azurerm_recovery_services_vault" "{_safe(name)}" {{
  name = "{name}"
  # ... existing config ...

  # Geo-redundant storage (MCSB BR-2)
  storage_mode_type            = "GeoRedundant"
  cross_region_restore_enabled = true
}}'''


# ----- Networking / Monitoring -----


@_tf("azure-vnet-flow-logs-modern")
def _tf_az_vnet_flow_logs(f: Finding) -> str:
    return '''\
# VNet flow logs — successor to NSG flow logs (CIS 6.4)
resource "azurerm_network_watcher_flow_log" "vnet_flow" {
  network_watcher_name = "NetworkWatcher_LOCATION"
  resource_group_name  = "NetworkWatcherRG"
  name                 = "vnet-flow-log"

  target_resource_id = azurerm_virtual_network.main.id
  storage_account_id = azurerm_storage_account.flowlogs.id
  enabled            = true

  retention_policy {
    enabled = true
    days    = 90
  }

  traffic_analytics {
    enabled               = true
    workspace_id          = azurerm_log_analytics_workspace.main.workspace_id
    workspace_region      = azurerm_log_analytics_workspace.main.location
    workspace_resource_id = azurerm_log_analytics_workspace.main.id
    interval_in_minutes   = 10
  }
}'''


@_tf("azure-network-watcher-coverage")
def _tf_az_network_watcher(f: Finding) -> str:
    missing = f.details.get("missing_regions", ["LOCATION"])
    blocks = []
    for r in missing[:5]:
        safe = _safe(r)
        blocks.append(
            f'''resource "azurerm_network_watcher" "{safe}" {{
  name                = "NetworkWatcher_{r}"
  location            = "{r}"
  resource_group_name = "NetworkWatcherRG"
}}'''
        )
    return "\n\n".join(blocks)


@_tf("azure-defender-per-plan")
def _tf_az_defender_per_plan(f: Finding) -> str:
    disabled = f.details.get("disabled", [])
    plans = [d.get("plan") if isinstance(d, dict) else d for d in disabled[:8]]
    if not plans:
        plans = ["VirtualMachines", "StorageAccounts", "KeyVaults", "Containers", "Arm"]
    blocks = []
    for plan in plans:
        blocks.append(
            f'''resource "azurerm_security_center_subscription_pricing" "{_safe(plan).lower()}" {{
  tier          = "Standard"
  resource_type = "{plan}"
}}'''
        )
    return "\n\n".join(blocks)


@_tf("azure-activity-log-alerts")
def _tf_az_activity_alerts(f: Finding) -> str:
    return '''\
# CIS 5.2.x — alert on critical control-plane changes
locals {
  critical_operations = [
    "Microsoft.Network/networkSecurityGroups/write",
    "Microsoft.Network/networkSecurityGroups/delete",
    "Microsoft.Network/networkSecurityGroups/securityRules/write",
    "Microsoft.Network/networkSecurityGroups/securityRules/delete",
    "Microsoft.Sql/servers/firewallRules/write",
    "Microsoft.Authorization/policyAssignments/write",
    "Microsoft.Authorization/policyAssignments/delete",
    "Microsoft.KeyVault/vaults/write",
    "Microsoft.KeyVault/vaults/delete",
  ]
}

resource "azurerm_monitor_action_group" "secops" {
  name                = "secops-page"
  resource_group_name = "monitoring"
  short_name          = "secops"

  email_receiver {
    name          = "secops"
    email_address = "secops@example.com"
  }
}

resource "azurerm_monitor_activity_log_alert" "critical_changes" {
  for_each            = toset(local.critical_operations)
  name                = "alert-${replace(each.key, "/", "-")}"
  resource_group_name = "monitoring"
  scopes              = [data.azurerm_subscription.current.id]
  description         = "CIS 5.2.x — control-plane change alert"

  criteria {
    category       = "Administrative"
    operation_name = each.key
  }

  action {
    action_group_id = azurerm_monitor_action_group.secops.id
  }
}'''


# ----- Governance -----


@_tf("azure-resource-locks")
def _tf_az_resource_locks(f: Finding) -> str:
    rg = f.details.get("resource_group", "RESOURCE_GROUP")
    return f'''\
resource "azurerm_management_lock" "{_safe(rg)}_protect" {{
  name       = "protect-{rg}"
  scope      = "/subscriptions/SUBSCRIPTION_ID/resourceGroups/{rg}"
  lock_level = "CanNotDelete"
  notes      = "Protects sensitive resources (Key Vault / RSV / Log Analytics) from accidental deletion."
}}'''


@_tf("azure-required-tags")
def _tf_az_required_tags(f: Finding) -> str:
    return '''\
# Built-in policy: 'Require a tag and its value on resource groups'
data "azurerm_policy_definition" "require_tag" {
  display_name = "Require a tag and its value on resource groups"
}

resource "azurerm_subscription_policy_assignment" "require_owner_tag" {
  name                 = "require-owner-tag"
  subscription_id      = data.azurerm_subscription.current.id
  policy_definition_id = data.azurerm_policy_definition.require_tag.id

  parameters = jsonencode({
    tagName  = { value = "owner" }
    tagValue = { value = "REQUIRED_VALUE" }
  })
}

resource "azurerm_subscription_policy_assignment" "require_env_tag" {
  name                 = "require-environment-tag"
  subscription_id      = data.azurerm_subscription.current.id
  policy_definition_id = data.azurerm_policy_definition.require_tag.id

  parameters = jsonencode({
    tagName  = { value = "environment" }
    tagValue = { value = "production" }
  })
}'''


@_tf("azure-security-initiative")
def _tf_az_security_initiative(f: Finding) -> str:
    return '''\
# Assign the Microsoft Cloud Security Benchmark initiative (CIS 2.x)
data "azurerm_policy_set_definition" "mcsb" {
  display_name = "Microsoft cloud security benchmark"
}

resource "azurerm_subscription_policy_assignment" "mcsb" {
  name                 = "mcsb-baseline"
  subscription_id      = data.azurerm_subscription.current.id
  policy_definition_id = data.azurerm_policy_set_definition.mcsb.id
  display_name         = "Microsoft Cloud Security Benchmark"
  description          = "Continuous compliance against the MCSB."
}'''


# ---------------------------------------------------------------------------
# Explanation and steps registry
# ---------------------------------------------------------------------------

EXPLANATIONS: dict[str, dict] = {
    "iam-password-policy": {
        "explanation": "Your AWS password policy is like the rules for building keys to your office. Right now, the rules are too lax — allowing short, simple passwords that are easy to guess. An attacker who cracks one password gets into your AWS console.",
        "steps": [
            "Go to IAM > Account settings > Password policy in the AWS Console",
            "Set minimum length to 14 characters",
            "Require uppercase, lowercase, numbers, AND symbols",
            "Set password expiration to 90 days",
            "Set password reuse prevention to 12",
            "Or apply the Terraform template below",
        ],
        "effort": "quick",
    },
    "iam-user-mfa": {
        "explanation": "Multi-factor authentication (MFA) is a second lock on the door. Even if someone steals a password, they can't get in without the second factor (usually a phone app). Without MFA, a single leaked password means full account access.",
        "steps": [
            "Log into the AWS Console as the user (or an admin)",
            "Go to IAM > Users > select the user > Security credentials",
            "Click 'Assign MFA device'",
            "Choose 'Authenticator app' and scan the QR code",
            "Enter two consecutive codes to activate",
        ],
        "effort": "quick",
    },
    "iam-root-mfa": {
        "explanation": "The root account is the master key to your entire AWS account. If compromised without MFA, an attacker has unrestricted access to everything — they could delete all your data, spin up expensive resources, or lock you out entirely.",
        "steps": [
            "Sign in as root (email + password) at https://console.aws.amazon.com/",
            "Go to Security credentials in the top-right dropdown",
            "Assign an MFA device — hardware key is ideal, authenticator app is acceptable",
            "Store backup codes securely",
        ],
        "effort": "quick",
    },
    "iam-no-direct-policies": {
        "explanation": "Attaching policies directly to users is like giving each employee a unique set of keys instead of a role-based keycard. It becomes unmanageable — when someone changes roles, you have to update each user individually. Groups make access easy to audit and update.",
        "steps": [
            "Create an IAM group for the user's role (e.g., 'developers', 'ops')",
            "Attach the necessary policies to the group",
            "Add the user to the group",
            "Remove the direct policy attachments from the user",
        ],
        "effort": "quick",
    },
    "iam-overprivileged-user": {
        "explanation": "Giving a user AdministratorAccess is like giving an intern the CEO's master key. If their credentials are compromised, the attacker gets unlimited access. The principle of least privilege means each person gets only the access they actually need.",
        "steps": [
            "Identify what the user actually needs to do (which services, which actions)",
            "Create a scoped IAM policy with only those permissions",
            "Attach the scoped policy to a group",
            "Remove AdministratorAccess",
            "Test that the user can still do their work",
        ],
        "effort": "moderate",
    },
    "sg-no-unrestricted-ingress": {
        "explanation": "A security group open to 0.0.0.0/0 means anyone on the internet can reach that port. For SSH or RDP, this means anyone can try to brute-force their way in. For databases, it means your data could be directly exposed.",
        "steps": [
            "Identify who actually needs access to this resource",
            "Find your office/VPN IP address (curl ifconfig.me)",
            "Update the security group to only allow that IP range",
            "If the SG is unused, check for attached resources and delete it",
        ],
        "effort": "quick",
    },
    "vpc-flow-logs-enabled": {
        "explanation": "VPC flow logs are like security cameras for your network. Without them, if someone breaks in, you have no way to see what traffic came and went. They're essential for incident investigation and audit trail.",
        "steps": [
            "Go to VPC > Your VPCs in the AWS Console",
            "Select the VPC and click 'Flow logs' tab",
            "Create flow log: ALL traffic, send to CloudWatch Logs",
            "Set retention to 90 days minimum",
            "Or apply the Terraform template below",
        ],
        "effort": "quick",
    },
    "s3-versioning": {
        "explanation": "Without versioning, if someone accidentally deletes a file or overwrites it with bad data, it's gone forever. Versioning keeps a history of every change, letting you recover from accidents or ransomware.",
        "steps": [
            "Go to S3 > select the bucket > Properties tab",
            "Under Bucket Versioning, click Edit and enable it",
            "Consider adding a lifecycle rule to expire old versions after 90 days to control costs",
        ],
        "effort": "quick",
    },
    "s3-ssl-only": {
        "explanation": "Without an SSL-only policy, data can be sent to or from your S3 bucket over unencrypted HTTP. This means anyone monitoring the network could read your data in transit — like sending a postcard instead of a sealed envelope.",
        "steps": [
            "Go to S3 > select the bucket > Permissions > Bucket policy",
            "Add a policy that denies all requests where aws:SecureTransport is false",
            "Or apply the Terraform template below",
        ],
        "effort": "quick",
    },
    "s3-encryption-at-rest": {
        "explanation": "Encryption at rest means your data is scrambled on disk. If someone steals the physical drive or gets unauthorized access to the storage layer, they can't read anything without the encryption key.",
        "steps": [
            "Go to S3 > select the bucket > Properties tab",
            "Under Default encryption, enable SSE-KMS (preferred) or SSE-S3",
            "This only affects new objects — existing objects keep their current encryption",
        ],
        "effort": "quick",
    },
    "s3-public-access-block": {
        "explanation": "The public access block is a safety net that prevents anyone from accidentally making your bucket or objects public. Without it, a single misconfigured policy or ACL could expose your data to the entire internet.",
        "steps": [
            "Go to S3 > select the bucket > Permissions",
            "Under 'Block public access', click Edit",
            "Enable all four settings",
            "Click Save changes",
        ],
        "effort": "quick",
    },
    "sg-default-restricted": {
        "explanation": "Default security groups often have permissive rules left over from initial setup. Any resource that doesn't explicitly specify a security group will use the default — meaning those leftover rules apply unexpectedly.",
        "steps": [
            "Go to VPC > Security Groups in the AWS Console",
            "Find the default security group for each VPC",
            "Remove all inbound rules (leave outbound as-is if needed)",
            "Ensure all resources use custom security groups instead",
        ],
        "effort": "quick",
    },
    "iam-access-key-rotation": {
        "explanation": "Access keys are like passwords for programmatic access. The longer they exist, the more likely they've been accidentally committed to a repo, shared in a message, or logged somewhere insecure. Regular rotation limits the damage window.",
        "steps": [
            "Create a new access key for the user",
            "Update all applications using the old key",
            "Verify everything works with the new key",
            "Deactivate the old key, wait a few days, then delete it",
        ],
        "effort": "moderate",
    },
    "iam-inactive-user": {
        "explanation": "Unused accounts are a risk because they can be compromised without anyone noticing. If an ex-employee's credentials are leaked or brute-forced, there's no active user to notice the suspicious activity.",
        "steps": [
            "Review whether the user still needs access",
            "If not: disable their console password and deactivate access keys",
            "After confirming no automated processes depend on the user, delete the account",
        ],
        "effort": "quick",
    },
    "guardduty-no-active-findings": {
        "explanation": "GuardDuty has found potential security threats in your environment. These could range from unusual API calls to possible credential compromise. Each finding needs to be investigated — some may be false positives, but some could be real attacks.",
        "steps": [
            "Go to GuardDuty > Findings in the AWS Console",
            "Review each active finding",
            "For each: determine if it's a real threat or expected behavior",
            "Archive false positives, remediate real threats",
            "Set up SNS notifications for future findings",
        ],
        "effort": "moderate",
    },
    # ----- Azure CIS v3.0 explanations -----
    "azure-storage-shared-key-access": {
        "explanation": "Storage account keys are like a master password — anyone holding the key bypasses Entra ID identity, RBAC, Conditional Access, and audit attribution. Disable shared-key access so every read/write must come through an authenticated Entra ID identity.",
        "steps": [
            "Audit which apps still use the storage account key (search app settings, env vars, secrets)",
            "Migrate each consumer to managed identity + Entra ID auth",
            "Set allowSharedKeyAccess = false on the storage account",
            "Confirm via the audit logs that no SharedKey requests remain",
        ],
        "effort": "moderate",
    },
    "azure-storage-cross-tenant-replication": {
        "explanation": "Object replication across tenants is a stealth exfiltration channel — a user with replication permissions can configure your storage to mirror blobs into a foreign Entra ID tenant, and the data leaves without triggering normal data-movement alerts.",
        "steps": [
            "Set allowCrossTenantReplication = false on every production storage account",
            "Audit existing object replication policies for foreign-tenant targets",
        ],
        "effort": "quick",
    },
    "azure-storage-network-default-deny": {
        "explanation": "By default, a storage account is reachable from anywhere on the internet — a leaked SAS or stolen identity becomes immediately exploitable. Default-Deny + explicit allowlist limits the blast radius to known networks.",
        "steps": [
            "Set network rules default action to Deny",
            "Add explicit IP rules for trusted office/VPN ranges",
            "Add VNet subnet rules for internal apps",
            "Allow only AzureServices, Logging, Metrics in the bypass list",
        ],
        "effort": "quick",
    },
    "azure-keyvault-rbac-mode": {
        "explanation": "Legacy Key Vault access policies are a parallel permission system that doesn't integrate with PIM, Conditional Access, or central access reviews. Switching to RBAC mode makes Key Vault permissions visible alongside every other Azure resource and lets you use Key Vault Administrator / Secrets User / Crypto User roles.",
        "steps": [
            "Document who currently has access via the access policy list",
            "Set enable_rbac_authorization = true on the vault",
            "Create RBAC role assignments mirroring the previous access policy grants",
            "Remove the legacy access_policy blocks",
        ],
        "effort": "moderate",
    },
    "azure-keyvault-public-access": {
        "explanation": "A Key Vault reachable from the public internet means a stolen workload identity can be used from anywhere — there's no network boundary on top of the identity check. Combined with token theft, this is the shortest path from compromised credential to leaked secrets.",
        "steps": [
            "Set publicNetworkAccess = Disabled on the vault",
            "Set network ACL default action to Deny",
            "Create a Private Endpoint in the VNet that needs vault access",
            "Add a Private DNS zone (privatelink.vaultcore.azure.net) linked to the VNet",
        ],
        "effort": "moderate",
    },
    "azure-sql-min-tls": {
        "explanation": "TLS 1.0 and 1.1 have known cryptographic weaknesses (BEAST, POODLE) and are deprecated by every major security framework. SQL Server's minimal_tls_version controls what the server will accept on the wire.",
        "steps": [
            "Set minimal_tls_version = '1.2' on every SQL server",
            "Verify clients are using a recent driver that supports TLS 1.2+",
        ],
        "effort": "quick",
    },
    "azure-sql-auditing": {
        "explanation": "Server-level auditing captures every login, query, and DDL change. Without it, anomalous queries and brute-force attempts leave no record — you have no incident-response trail and no detection signal for SQL injection or data exfil.",
        "steps": [
            "Create or pick a Log Analytics workspace for security data",
            "Enable extended auditing on each SQL server pointing at the workspace",
            "Set retention to ≥ 90 days (365 ideal)",
        ],
        "effort": "moderate",
    },
    "azure-sql-entra-admin": {
        "explanation": "Without an Entra ID admin, the only way to manage SQL Server is SQL authentication — meaning no MFA, no Conditional Access, and credentials cycling outside identity governance. An Entra group as admin lets you use PIM for break-glass.",
        "steps": [
            "Create an Entra group like 'sql-admins' with one or two members",
            "Set the group as the SQL server's Entra admin",
            "Enable azuread_authentication_only = true to disable mixed-mode",
        ],
        "effort": "quick",
    },
    "azure-postgres-secure-transport": {
        "explanation": "PostgreSQL Flexible Server lets clients connect over plaintext unless require_secure_transport is ON. Plaintext means anyone on the network path can read every query and credential.",
        "steps": [
            "Set require_secure_transport = ON via az postgres flexible-server parameter set",
            "Verify clients use SSL connection strings",
        ],
        "effort": "quick",
    },
    "azure-postgres-log-settings": {
        "explanation": "Connection logging is the audit trail for every authentication attempt and session. Without log_connections / log_disconnections / log_checkpoints, brute-force attempts and anomalous session patterns are invisible.",
        "steps": [
            "Set each parameter to ON via az postgres flexible-server parameter set",
            "Forward server logs to Log Analytics via diagnostic settings",
        ],
        "effort": "quick",
    },
    "azure-mysql-secure-transport": {
        "explanation": "Same as PostgreSQL: MySQL Flexible Server can accept plaintext connections unless require_secure_transport = ON. Force TLS server-side so a misconfigured client can't downgrade.",
        "steps": [
            "az mysql flexible-server parameter set --name require_secure_transport --value ON",
        ],
        "effort": "quick",
    },
    "azure-mysql-tls-version": {
        "explanation": "MySQL accepts older TLS versions by default. Restrict to TLS 1.2 / 1.3 only.",
        "steps": [
            "az mysql flexible-server parameter set --name tls_version --value 'TLSv1.2,TLSv1.3'",
        ],
        "effort": "quick",
    },
    "azure-mysql-audit-log": {
        "explanation": "MySQL audit log captures connection events and DDL/DML statements for incident investigation. It's disabled by default.",
        "steps": [
            "Enable audit_log_enabled = ON",
            "Configure audit_log_events to include CONNECTION, ADMIN, DDL at minimum",
        ],
        "effort": "quick",
    },
    "azure-cosmos-disable-local-auth": {
        "explanation": "Cosmos DB account keys are full-access bearer tokens that bypass Entra ID, RBAC, and audit attribution. Disabling local auth forces every operation through Entra ID identity, which is logged and CA-controlled.",
        "steps": [
            "Migrate apps to use DefaultAzureCredential / managed identity",
            "Grant the identity Cosmos DB Built-in Data Reader/Contributor RBAC roles",
            "Set disableLocalAuth = true on the account",
        ],
        "effort": "moderate",
    },
    "azure-cosmos-public-access": {
        "explanation": "A Cosmos account with public network access enabled is reachable from anywhere on the internet, so any leaked identity becomes immediately exploitable.",
        "steps": [
            "Set publicNetworkAccess = Disabled",
            "Create Private Endpoint for the SQL/Mongo/Cassandra subresource the app uses",
        ],
        "effort": "moderate",
    },
    "azure-cosmos-firewall": {
        "explanation": "An empty IP firewall with public access enabled means any IP can attempt to authenticate — combined with shared keys this is a direct exfiltration path.",
        "steps": [
            "Add explicit IP rules for trusted ranges, or",
            "Add VNet rules for internal apps, or",
            "Disable public network access entirely and use Private Endpoints",
        ],
        "effort": "quick",
    },
    "azure-appservice-https-only": {
        "explanation": "An App Service that accepts HTTP serves credentials and session cookies in plaintext over the wire — anyone on the network path can capture them.",
        "steps": [
            "az webapp update --https-only true -g <rg> -n <app>",
        ],
        "effort": "quick",
    },
    "azure-appservice-min-tls": {
        "explanation": "App Service defaults to TLS 1.0 in older deployments. Force TLS 1.2+ both for the app endpoint and the Kudu (SCM) deployment endpoint.",
        "steps": [
            "az webapp config set --min-tls-version 1.2 -g <rg> -n <app>",
            "Also update scm_minimum_tls_version via ARM/Terraform",
        ],
        "effort": "quick",
    },
    "azure-appservice-ftps": {
        "explanation": "Plain FTP transmits the deployment credential in clear text. Disable it entirely, or restrict to FTPS-only if FTPS uploads are required.",
        "steps": [
            "az webapp config set --ftps-state Disabled -g <rg> -n <app>",
        ],
        "effort": "quick",
    },
    "azure-appservice-remote-debug": {
        "explanation": "Remote debugging exposes a debug endpoint that lets developers attach Visual Studio to a running production process. It should only be on briefly during a debug session, never permanently.",
        "steps": [
            "az webapp config set --remote-debugging-enabled false -g <rg> -n <app>",
        ],
        "effort": "quick",
    },
    "azure-appservice-managed-identity": {
        "explanation": "Without a managed identity, the app must store credentials in app settings or config files — which then need rotation, vaulting, and access reviews. A managed identity is identity-bound to the app instance, with no secrets to leak.",
        "steps": [
            "az webapp identity assign -g <rg> -n <app>",
            "Grant the identity RBAC on the resources it needs (Key Vault, Storage, SQL, etc.)",
            "Remove static credentials from app settings",
        ],
        "effort": "moderate",
    },
    "azure-rsv-soft-delete": {
        "explanation": "Without soft delete, an attacker (or careless admin) with vault access can delete recovery points and there's no recovery — your backups are gone. Soft delete keeps them in a recoverable state for 14 days, AlwaysON makes the protection irreversible.",
        "steps": [
            "Set soft_delete_enabled = true on every Recovery Services Vault",
            "Set the soft delete state to AlwaysON via the portal for irreversibility",
        ],
        "effort": "quick",
    },
    "azure-rsv-immutability": {
        "explanation": "Immutable vaults prevent recovery points from being deleted before their retention expires — the only true protection against ransomware that targets backups. Locking the immutability setting makes the protection irreversible.",
        "steps": [
            "Enable immutability on the vault (Properties > Immutability)",
            "Test recovery on a non-production vault first",
            "Lock the setting once you're confident — this cannot be undone",
        ],
        "effort": "moderate",
    },
    "azure-rsv-redundancy": {
        "explanation": "Locally-redundant storage (LRS) means a regional outage destroys your backups along with your primary data. GRS / GZRS replicates backup data to a paired Azure region.",
        "steps": [
            "Set storage_mode_type = 'GeoRedundant' on the vault",
            "Note: redundancy can only be changed before any backup item is registered",
            "Enable cross_region_restore = true",
        ],
        "effort": "quick",
    },
    "azure-vnet-flow-logs-modern": {
        "explanation": "NSG flow logs are deprecated — no new ones can be created after June 2025, and all existing ones retire September 2027. VNet flow logs are the post-2025 successor and capture richer data including encrypted traffic patterns.",
        "steps": [
            "Create a Storage account in the same region as the VNet for flow log storage",
            "Configure VNet flow logs in Network Watcher targeting the VNet",
            "Set retention to ≥ 90 days",
            "Enable Traffic Analytics linked to a Log Analytics workspace",
        ],
        "effort": "moderate",
    },
    "azure-network-watcher-coverage": {
        "explanation": "Network Watcher is the per-region service that powers VNet flow logs, connection troubleshooter, and Traffic Analytics. Without it in a region, you can't capture flow logs for VNets in that region.",
        "steps": [
            "Create a Network Watcher resource in each region that hosts a VNet",
            "Network Watcher is normally auto-created — manual creation is only needed if it was deleted",
        ],
        "effort": "quick",
    },
    "azure-defender-per-plan": {
        "explanation": "Defender for Cloud charges per resource type ('plan'), and each plan covers a different attack surface — Defender for Servers detects malware on VMs, Defender for SQL detects SQL injection, Defender for Containers scans images, etc. Enabling only some plans leaves blind spots.",
        "steps": [
            "Identify which Defender plans are missing",
            "Enable each one via Defender for Cloud > Environment settings > Defender plans",
            "Set up email notifications for new alerts",
        ],
        "effort": "moderate",
    },
    "azure-activity-log-alerts": {
        "explanation": "CIS Azure 5.2.x requires real-time alerts on critical control-plane changes — NSG rule edits, SQL firewall changes, Policy assignment changes, Key Vault create/delete. Without these, security-relevant changes happen silently and only show up in retrospective audits.",
        "steps": [
            "Create an Action Group with email + SMS for SecOps",
            "Create one Activity Log alert per CIS-required operation",
            "Verify alerts trigger by making a test change",
        ],
        "effort": "moderate",
    },
    "azure-resource-locks": {
        "explanation": "A misclick in the Portal or a compromised admin can wipe an entire resource group containing your Key Vault, Recovery Services Vault, or log storage. CanNotDelete locks block deletion until the lock is explicitly removed — a small speed bump that prevents catastrophic mistakes.",
        "steps": [
            "Identify resource groups containing sensitive resources (KV, RSV, log Storage, Log Analytics)",
            "Apply a CanNotDelete lock to each",
            "Document the lock removal procedure for change windows",
        ],
        "effort": "quick",
    },
    "azure-required-tags": {
        "explanation": "Without owner / environment tags, incident response and access reviews are guesswork — you don't know who owns a resource or whether it's production. Azure Policy with deny effect prevents new resources from being created without the required tags.",
        "steps": [
            "Backfill missing tags on existing resource groups",
            "Assign the built-in 'Require a tag and its value on resource groups' policy",
            "Set the deny effect to enforce going forward",
        ],
        "effort": "moderate",
    },
    "azure-security-initiative": {
        "explanation": "The Microsoft Cloud Security Benchmark initiative is a pre-built bundle of security policies that maps to CIS, NIST, ISO, and PCI. Assigning it gives you a continuous compliance score in Defender for Cloud's Regulatory Compliance dashboard without writing a single policy.",
        "steps": [
            "Find the 'Microsoft cloud security benchmark' built-in initiative",
            "Assign it at the tenant root management group (or top-level MG)",
            "Review the compliance score in Defender for Cloud",
        ],
        "effort": "quick",
    },
}


def generate_remediation(finding: Finding) -> Remediation:
    """Generate a full remediation recommendation for a finding."""
    check_id = finding.check_id
    info = EXPLANATIONS.get(check_id, {})

    # Generate Terraform if available
    tf_generator = TERRAFORM_TEMPLATES.get(check_id)
    terraform = tf_generator(finding) if tf_generator else ""

    return Remediation(
        finding=finding,
        priority=SEVERITY_PRIORITY.get(finding.severity, 5),
        explanation=info.get("explanation", finding.description),
        steps=info.get("steps", [finding.remediation] if finding.remediation else []),
        terraform=terraform,
        effort=info.get("effort", "moderate"),
        category=finding.domain.value,
    )


def generate_all_remediations(findings: list[Finding]) -> list[Remediation]:
    """Generate remediations for all failing findings, sorted by priority."""
    failing = [f for f in findings if f.status in (ComplianceStatus.FAIL, ComplianceStatus.PARTIAL)]
    remediations = [generate_remediation(f) for f in failing]
    remediations.sort(key=lambda r: (r.priority, r.category))
    return remediations


def save_terraform_bundle(
    remediations: list[Remediation],
    output_path: Path | str = "data/remediation",
) -> Path:
    """Save all Terraform remediations as a single .tf file."""
    output_dir = Path(output_path)
    output_dir.mkdir(parents=True, exist_ok=True)
    filepath = output_dir / "remediation.tf"

    blocks = []
    blocks.append("# Shasta Auto-Generated Remediation Terraform")
    blocks.append("# Review each resource before applying!\n")

    seen_check_ids = set()
    for r in remediations:
        if r.terraform and r.finding.check_id not in seen_check_ids:
            blocks.append(f"# --- {r.finding.title} ---")
            blocks.append(f"# SOC 2: {', '.join(r.finding.soc2_controls)}")
            blocks.append(f"# Severity: {r.finding.severity.value}")
            blocks.append(r.terraform)
            blocks.append("")
            seen_check_ids.add(r.finding.check_id)

    filepath.write_text("\n".join(blocks), encoding="utf-8")
    return filepath
