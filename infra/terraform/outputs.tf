# No secrets are output: authentication uses managed identities and OIDC.

output "resource_group" {
  value = azurerm_resource_group.main.name
}

output "vm_name" {
  value = azurerm_linux_virtual_machine.app.name
}

output "vm_public_ip" {
  value = azurerm_public_ip.vm.ip_address
}

output "ssh_command" {
  value = "ssh ${var.admin_username}@${azurerm_public_ip.vm.ip_address}"
}

output "dashboard_url" {
  value = "http://${azurerm_public_ip.vm.ip_address}:8501"
}

output "postgres_fqdn" {
  description = "Private hostname; resolvable only inside the VNet (use an SSH tunnel from your laptop)."
  value       = azurerm_postgresql_flexible_server.main.fqdn
}

output "postgres_app_user" {
  value = azurerm_user_assigned_identity.app.name
}

output "storage_account" {
  value = azurerm_storage_account.logs.name
}

output "raw_log_container_url" {
  value = "${azurerm_storage_account.logs.primary_blob_endpoint}${azurerm_storage_container.raw_logs.name}"
}

output "log_analytics_workspace" {
  value = azurerm_log_analytics_workspace.main.name
}

output "log_analytics_workspace_id" {
  description = "Workspace (customer) ID, used by `az monitor log-analytics query`."
  value       = azurerm_log_analytics_workspace.main.workspace_id
}

output "app_identity_client_id" {
  value = azurerm_user_assigned_identity.app.client_id
}

output "github_actions_settings" {
  description = "Values for the GitHub repository (Settings > Environments > production)."
  value = var.github_repository == "" ? null : {
    AZURE_CLIENT_ID       = azurerm_user_assigned_identity.github[0].client_id
    AZURE_TENANT_ID       = data.azurerm_client_config.current.tenant_id
    AZURE_SUBSCRIPTION_ID = var.subscription_id
    AZURE_RESOURCE_GROUP  = azurerm_resource_group.main.name
    AZURE_VM_NAME         = azurerm_linux_virtual_machine.app.name
  }
}
