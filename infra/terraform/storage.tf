# Raw security-log archive. Access uses Microsoft Entra ID (managed identity);
# the application never uses account keys.
resource "azurerm_storage_account" "logs" {
  name                            = substr("${var.project}${var.environment}${local.suffix}", 0, 24)
  resource_group_name             = azurerm_resource_group.main.name
  location                        = azurerm_resource_group.main.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  account_kind                    = "StorageV2"
  access_tier                     = "Hot"
  min_tls_version                 = "TLS1_2"
  https_traffic_only_enabled      = true
  allow_nested_items_to_be_public = false
  tags                            = local.tags

  blob_properties {
    # Recover accidentally deleted raw logs or containers for 7 days.
    delete_retention_policy {
      days = 7
    }
    container_delete_retention_policy {
      days = 7
    }
  }

  network_rules {
    default_action             = "Deny"
    bypass                     = ["AzureServices", "Logging", "Metrics"]
    ip_rules                   = [local.admin_ip]
    virtual_network_subnet_ids = [azurerm_subnet.app.id]
  }
}

resource "azurerm_storage_container" "raw_logs" {
  name                  = "raw-logs"
  storage_account_id    = azurerm_storage_account.logs.id
  container_access_type = "private"
}

# Retention: Hot -> Cool after N days, delete after M days.
resource "azurerm_storage_management_policy" "raw_logs" {
  storage_account_id = azurerm_storage_account.logs.id

  rule {
    name    = "raw-log-retention"
    enabled = true
    filters {
      blob_types   = ["blockBlob"]
      prefix_match = ["raw-logs/raw/"]
    }
    actions {
      base_blob {
        tier_to_cool_after_days_since_modification_greater_than = var.raw_log_cool_after_days
        delete_after_days_since_modification_greater_than       = var.raw_log_delete_after_days
      }
    }
  }
}

# Least privilege: the app identity may read/write blobs in this container only.
resource "azurerm_role_assignment" "app_blob_writer" {
  scope                = azurerm_storage_container.raw_logs.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_user_assigned_identity.app.principal_id
  principal_type       = "ServicePrincipal"
}
