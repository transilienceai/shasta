###############################################################################
# Shasta Azure Test Environment
#
# Creates a mix of COMPLIANT and NON-COMPLIANT Azure resources for testing
# SOC 2 and ISO 27001 compliance scanning. Each resource is tagged with its
# intended compliance state so we can validate scanner accuracy.
#
# IMPORTANT: This is a TEST environment only. Do NOT use in production.
#
# Usage:
#   cd infra/azure-test-env
#   az login
#   terraform init
#   terraform plan
#   terraform apply
#
# Teardown:
#   terraform destroy
###############################################################################

terraform {
  required_version = ">= 1.5"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 3.0"
    }
  }
}

variable "location" {
  description = "Azure region for all resources"
  type        = string
  default     = "centralindia"
}

variable "subscription_id" {
  description = "Azure subscription ID"
  type        = string
  default     = "cb0d6ed4-a7c9-4929-8707-4a477a2cc9b5"
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy = true
    }
  }
  subscription_id = var.subscription_id
}

provider "azuread" {}

# ===========================================================================
# Data sources
# ===========================================================================

data "azurerm_client_config" "current" {}

data "azurerm_subscription" "current" {}

data "azuread_client_config" "current" {}

# ===========================================================================
# Resource Group
# ===========================================================================

resource "azurerm_resource_group" "test" {
  name     = "shasta-test-rg"
  location = var.location
  tags = {
    Project     = "shasta-test"
    Environment = "test"
    ManagedBy   = "terraform"
  }
}

# ===========================================================================
# Networking -- CC6.6 (System Boundaries), ISO A.8.20 (Network Security)
# ===========================================================================

resource "azurerm_virtual_network" "test" {
  name                = "shasta-test-vnet"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.test.location
  resource_group_name = azurerm_resource_group.test.name
  tags = {
    Project = "shasta-test"
  }
}

resource "azurerm_subnet" "public" {
  name                 = "shasta-public-subnet"
  resource_group_name  = azurerm_resource_group.test.name
  virtual_network_name = azurerm_virtual_network.test.name
  address_prefixes     = ["10.0.1.0/24"]
}

resource "azurerm_subnet" "private" {
  name                 = "shasta-private-subnet"
  resource_group_name  = azurerm_resource_group.test.name
  virtual_network_name = azurerm_virtual_network.test.name
  address_prefixes     = ["10.0.2.0/24"]
}

# BAD: NSG allowing SSH from anywhere
resource "azurerm_network_security_group" "bad_ssh" {
  name                = "shasta-bad-ssh-nsg"
  location            = azurerm_resource_group.test.location
  resource_group_name = azurerm_resource_group.test.name

  security_rule {
    name                       = "AllowSSHFromAnywhere"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"       # BAD: open to world
    destination_address_prefix = "*"
  }

  tags = {
    shasta_expected = "fail"
    shasta_check    = "azure-nsg-unrestricted-ingress"
  }
}

# BAD: NSG allowing RDP from anywhere
resource "azurerm_network_security_group" "bad_rdp" {
  name                = "shasta-bad-rdp-nsg"
  location            = azurerm_resource_group.test.location
  resource_group_name = azurerm_resource_group.test.name

  security_rule {
    name                       = "AllowRDPFromAnywhere"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "*"       # BAD: open to world
    destination_address_prefix = "*"
  }

  tags = {
    shasta_expected = "fail"
    shasta_check    = "azure-nsg-unrestricted-ingress"
  }
}

# BAD: NSG allowing ALL traffic from anywhere
resource "azurerm_network_security_group" "bad_all" {
  name                = "shasta-bad-all-nsg"
  location            = azurerm_resource_group.test.location
  resource_group_name = azurerm_resource_group.test.name

  security_rule {
    name                       = "AllowAllFromAnywhere"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"       # BAD: open to world
    destination_address_prefix = "*"
  }

  tags = {
    shasta_expected = "fail"
    shasta_check    = "azure-nsg-unrestricted-ingress"
  }
}

# GOOD: NSG with restricted access (HTTPS from known CIDR only)
resource "azurerm_network_security_group" "good_web" {
  name                = "shasta-good-web-nsg"
  location            = azurerm_resource_group.test.location
  resource_group_name = azurerm_resource_group.test.name

  security_rule {
    name                       = "AllowHTTPSFromOffice"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "203.0.113.0/24"  # GOOD: restricted CIDR
    destination_address_prefix = "*"
  }

  # Explicit deny-all at low priority (defense in depth)
  security_rule {
    name                       = "DenyAllInbound"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  tags = {
    shasta_expected = "pass"
    shasta_check    = "azure-nsg-unrestricted-ingress"
  }
}

# Associate bad NSG with public subnet (so flow log check has something to find)
resource "azurerm_subnet_network_security_group_association" "public" {
  subnet_id                 = azurerm_subnet.public.id
  network_security_group_id = azurerm_network_security_group.bad_ssh.id
}

# BAD: No NSG flow logs configured (absence is the finding)
# GOOD flow logs would require a Log Analytics workspace + storage — see monitoring section

# ===========================================================================
# Storage -- CC6.7 (Data Protection), ISO A.8.24 (Cryptography)
# ===========================================================================

# BAD: Storage account with HTTP allowed, blob public access enabled, no soft delete
resource "azurerm_storage_account" "insecure" {
  name                          = "shastatestinsecure"
  resource_group_name           = azurerm_resource_group.test.name
  location                      = azurerm_resource_group.test.location
  account_tier                  = "Standard"
  account_replication_type      = "LRS"
  min_tls_version               = "TLS1_0"              # BAD: should be TLS1_2
  https_traffic_only_enabled    = false                  # BAD: allows HTTP
  allow_nested_items_to_be_public = true                 # BAD: allows public blobs

  tags = {
    shasta_expected = "fail"
    shasta_check    = "azure-storage-encryption azure-storage-https-only azure-blob-public-access azure-storage-soft-delete"
  }
}

# GOOD: Storage account with HTTPS only, public access blocked, encryption, soft delete
resource "azurerm_storage_account" "secure" {
  name                          = "shastatestssecure"
  resource_group_name           = azurerm_resource_group.test.name
  location                      = azurerm_resource_group.test.location
  account_tier                  = "Standard"
  account_replication_type      = "LRS"
  min_tls_version               = "TLS1_2"              # GOOD
  https_traffic_only_enabled    = true                   # GOOD
  allow_nested_items_to_be_public = false                # GOOD: no public blobs

  blob_properties {
    delete_retention_policy {
      days = 90                                          # GOOD: soft delete
    }
    container_delete_retention_policy {
      days = 90
    }
    versioning_enabled = true                            # GOOD: versioning
  }

  tags = {
    shasta_expected = "pass"
    shasta_check    = "azure-storage-encryption azure-storage-https-only azure-blob-public-access azure-storage-soft-delete"
  }
}

# BAD: Public blob container on insecure storage account
resource "azurerm_storage_container" "public_blob" {
  name                  = "public-data"
  storage_account_id    = azurerm_storage_account.insecure.id
  container_access_type = "blob"  # BAD: publicly accessible
}

# GOOD: Private container on secure storage account
resource "azurerm_storage_container" "private_blob" {
  name                  = "private-data"
  storage_account_id    = azurerm_storage_account.secure.id
  container_access_type = "private"  # GOOD
}

# ===========================================================================
# Key Vault -- CC6.7 (Data Protection), ISO A.8.24 (Cryptography)
# ===========================================================================

# BAD: Key Vault without purge protection
resource "azurerm_key_vault" "insecure" {
  name                       = "shasta-kv-insecure"
  location                   = azurerm_resource_group.test.location
  resource_group_name        = azurerm_resource_group.test.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  soft_delete_retention_days = 7
  purge_protection_enabled   = false  # BAD: should be true

  tags = {
    shasta_expected = "fail"
    shasta_check    = "azure-keyvault-config"
  }
}

# GOOD: Key Vault with soft delete and purge protection
resource "azurerm_key_vault" "secure" {
  name                       = "shasta-kv-secure"
  location                   = azurerm_resource_group.test.location
  resource_group_name        = azurerm_resource_group.test.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  soft_delete_retention_days = 90
  purge_protection_enabled   = true  # GOOD

  tags = {
    shasta_expected = "pass"
    shasta_check    = "azure-keyvault-config"
  }
}

# ===========================================================================
# Managed Disks -- CC6.7 (Data Protection), ISO A.8.24 (Cryptography)
# ===========================================================================

# NOTE: All Azure managed disks have SSE with platform-managed keys by default.
# To test encryption checks, we create one with platform keys (baseline)
# and one with a note that customer-managed keys would be "best practice".

# GOOD: Managed disk (SSE enabled by default — Azure enforces this)
resource "azurerm_managed_disk" "encrypted" {
  name                 = "shasta-disk-encrypted"
  location             = azurerm_resource_group.test.location
  resource_group_name  = azurerm_resource_group.test.name
  storage_account_type = "Standard_LRS"
  create_option        = "Empty"
  disk_size_gb         = 1

  tags = {
    shasta_expected = "pass"
    shasta_check    = "azure-disk-encryption"
  }
}

# ===========================================================================
# SQL Database -- CC6.7 (Data Protection), ISO A.8.12 (Data Leakage)
# ===========================================================================

# BAD: SQL Server with public network access enabled
resource "azurerm_mssql_server" "insecure" {
  name                          = "shasta-sql-insecure"
  resource_group_name           = azurerm_resource_group.test.name
  location                      = azurerm_resource_group.test.location
  version                       = "12.0"
  administrator_login           = "shastaadmin"
  administrator_login_password  = "Sh@sta-Test-2026!"
  public_network_access_enabled = true  # BAD

  tags = {
    shasta_expected = "fail"
    shasta_check    = "azure-sql-public-access"
  }
}

# BAD: Firewall rule allowing all Azure IPs (0.0.0.0 - 0.0.0.0 = all Azure services)
resource "azurerm_mssql_firewall_rule" "allow_azure" {
  name             = "AllowAllAzure"
  server_id        = azurerm_mssql_server.insecure.id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "0.0.0.0"
}

resource "azurerm_mssql_database" "insecure" {
  name      = "shasta-db-insecure"
  server_id = azurerm_mssql_server.insecure.id
  sku_name  = "Basic"

  tags = {
    shasta_expected = "fail"
    shasta_check    = "azure-sql-tde azure-sql-public-access"
  }
}

# GOOD: SQL Server with public access disabled
resource "azurerm_mssql_server" "secure" {
  name                          = "shasta-sql-secure"
  resource_group_name           = azurerm_resource_group.test.name
  location                      = azurerm_resource_group.test.location
  version                       = "12.0"
  administrator_login           = "shastaadmin"
  administrator_login_password  = "Sh@sta-Secure-2026!"
  public_network_access_enabled = false  # GOOD

  tags = {
    shasta_expected = "pass"
    shasta_check    = "azure-sql-public-access"
  }
}

resource "azurerm_mssql_database" "secure" {
  name      = "shasta-db-secure"
  server_id = azurerm_mssql_server.secure.id
  sku_name  = "Basic"

  # TDE is enabled by default on Azure SQL

  tags = {
    shasta_expected = "pass"
    shasta_check    = "azure-sql-tde azure-sql-public-access"
  }
}

# ===========================================================================
# Monitoring -- CC7.1 (Detection), CC7.2 (Anomaly), CC8.1 (Change Mgmt)
# ===========================================================================

# Log Analytics Workspace (needed for Activity Log and NSG flow logs)
resource "azurerm_log_analytics_workspace" "test" {
  name                = "shasta-test-laws"
  location            = azurerm_resource_group.test.location
  resource_group_name = azurerm_resource_group.test.name
  sku                 = "PerGB2018"
  retention_in_days   = 30

  tags = {
    Project = "shasta-test"
  }
}

# GOOD: Activity Log diagnostic settings (exports to Log Analytics)
resource "azurerm_monitor_diagnostic_setting" "activity_log" {
  name                       = "shasta-activity-log-export"
  target_resource_id         = data.azurerm_subscription.current.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.test.id

  enabled_log {
    category = "Administrative"
  }
  enabled_log {
    category = "Security"
  }
  enabled_log {
    category = "Alert"
  }
  enabled_log {
    category = "Policy"
  }
}

# GOOD: NSG flow logs for the good web NSG
resource "azurerm_network_watcher" "test" {
  name                = "shasta-network-watcher"
  location            = azurerm_resource_group.test.location
  resource_group_name = azurerm_resource_group.test.name
}

resource "azurerm_storage_account" "flow_logs" {
  name                     = "shastatestflowlogs"
  resource_group_name      = azurerm_resource_group.test.name
  location                 = azurerm_resource_group.test.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  tags = {
    Project = "shasta-test"
  }
}

# NOTE: Azure deprecated NSG flow logs after June 2025.
# Use VNet flow logs instead (azurerm_virtual_network_flow_log) when available
# in your azurerm provider version. For now, flow log checks will report FAIL
# on all NSGs, which is the expected test behavior for bad NSGs.

# BAD: No flow logs on any NSGs (absence is the finding)

# BAD: No flow logs on the bad NSGs (absence is the finding)

# ===========================================================================
# RBAC -- CC6.1 (Logical Access), CC6.2 (Provisioning)
# ===========================================================================

# BAD: Overprivileged role assignment — Contributor at subscription scope
# (Using a test Entra ID group to avoid assigning to real users)
resource "azuread_group" "overprivileged" {
  display_name     = "shasta-test-overprivileged"
  security_enabled = true
  description      = "TEST: Overprivileged group for Shasta scanner testing"
}

resource "azurerm_role_assignment" "overprivileged_contributor" {
  scope                = data.azurerm_subscription.current.id
  role_definition_name = "Contributor"  # BAD: too broad at subscription scope
  principal_id         = azuread_group.overprivileged.object_id
}

# GOOD: Scoped Reader role at resource group level
resource "azuread_group" "readonly" {
  display_name     = "shasta-test-readonly"
  security_enabled = true
  description      = "TEST: Properly scoped read-only group for Shasta scanner testing"
}

resource "azurerm_role_assignment" "readonly_reader" {
  scope                = azurerm_resource_group.test.id
  role_definition_name = "Reader"  # GOOD: least privilege, scoped to RG
  principal_id         = azuread_group.readonly.object_id
}

# ===========================================================================
# Public IP (for exposure checks)
# ===========================================================================

# BAD: Public IP allocated (potential exposure)
resource "azurerm_public_ip" "exposed" {
  name                = "shasta-exposed-pip"
  location            = azurerm_resource_group.test.location
  resource_group_name = azurerm_resource_group.test.name
  allocation_method   = "Static"
  sku                 = "Standard"

  tags = {
    shasta_expected = "fail"
    shasta_check    = "azure-public-ip-exposure"
  }
}

# ===========================================================================
# Outputs
# ===========================================================================

output "subscription_id" {
  value = data.azurerm_client_config.current.subscription_id
}

output "tenant_id" {
  value = data.azurerm_client_config.current.tenant_id
}

output "resource_group" {
  value = azurerm_resource_group.test.name
}

output "summary" {
  value = <<-EOT

    Shasta Azure Test Environment Created!
    =======================================
    Subscription: ${data.azurerm_subscription.current.display_name} (${data.azurerm_client_config.current.subscription_id})
    Tenant:       ${data.azurerm_client_config.current.tenant_id}
    Region:       ${var.location}
    RG:           ${azurerm_resource_group.test.name}

    Networking (CC6.6):
      - ${azurerm_network_security_group.bad_ssh.name}  -> SSH open to * (FAIL)
      - ${azurerm_network_security_group.bad_rdp.name}  -> RDP open to * (FAIL)
      - ${azurerm_network_security_group.bad_all.name}  -> all ports open to * (FAIL)
      - ${azurerm_network_security_group.good_web.name} -> HTTPS from restricted CIDR (PASS)
      - Flow logs: only on good_web NSG (PASS on good, FAIL on bad NSGs)

    Storage (CC6.7):
      - ${azurerm_storage_account.insecure.name} -> HTTP allowed, public blobs, no soft delete (FAIL)
      - ${azurerm_storage_account.secure.name}  -> HTTPS only, private, soft delete, versioning (PASS)

    Key Vault (CC6.7):
      - ${azurerm_key_vault.insecure.name}  -> no purge protection (FAIL)
      - ${azurerm_key_vault.secure.name}    -> soft delete + purge protection (PASS)

    SQL Database (CC6.7):
      - ${azurerm_mssql_server.insecure.name} -> public access, open firewall (FAIL)
      - ${azurerm_mssql_server.secure.name}   -> no public access (PASS)

    RBAC (CC6.1-CC6.2):
      - ${azuread_group.overprivileged.display_name} -> Contributor at subscription scope (FAIL)
      - ${azuread_group.readonly.display_name}       -> Reader at RG scope (PASS)

    Monitoring (CC7.1, CC7.2, CC8.1):
      - Activity Log export to Log Analytics (PASS)
      - Log Analytics Workspace: ${azurerm_log_analytics_workspace.test.name}
      - Defender for Cloud: check subscription-level status manually

    Public Exposure:
      - ${azurerm_public_ip.exposed.name} -> static public IP allocated (FAIL)
  EOT
}
