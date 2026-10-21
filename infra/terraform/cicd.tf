# GitHub Actions deploys through OpenID Connect: GitHub exchanges a short-lived
# token for this identity, so no Azure secret is stored in GitHub. Only the
# named repository + environment can use it, and it can only manage this VM
# (to run the deployment script via Azure Run Command).
resource "azurerm_user_assigned_identity" "github" {
  count               = var.github_repository == "" ? 0 : 1
  name                = "id-${local.name}-github-deploy"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  tags                = local.tags
}

resource "azurerm_federated_identity_credential" "github" {
  count                     = var.github_repository == "" ? 0 : 1
  name                      = "github-${var.github_environment}"
  resource_group_name       = azurerm_resource_group.main.name
  user_assigned_identity_id = azurerm_user_assigned_identity.github[0].id
  audience                  = ["api://AzureADTokenExchange"]
  issuer                    = "https://token.actions.githubusercontent.com"
  subject                   = "repo:${var.github_repository}:environment:${var.github_environment}"
}

# Newer GitHub OIDC tokens identify the repository by immutable IDs
# ("repo:owner@<owner_id>/name@<repo_id>:..."), so a deleted and re-created
# repository with the same name cannot inherit access. Trust that form too.
resource "azurerm_federated_identity_credential" "github_immutable" {
  count                     = var.github_repository == "" || var.github_repository_ids == null ? 0 : 1
  name                      = "github-${var.github_environment}-immutable"
  resource_group_name       = azurerm_resource_group.main.name
  user_assigned_identity_id = azurerm_user_assigned_identity.github[0].id
  audience                  = ["api://AzureADTokenExchange"]
  issuer                    = "https://token.actions.githubusercontent.com"
  subject = format(
    "repo:%s@%s/%s@%s:environment:%s",
    split("/", var.github_repository)[0], var.github_repository_ids.owner_id,
    split("/", var.github_repository)[1], var.github_repository_ids.repo_id,
    var.github_environment,
  )
}

resource "azurerm_role_assignment" "github_vm" {
  count                = var.github_repository == "" ? 0 : 1
  scope                = azurerm_linux_virtual_machine.app.id
  role_definition_name = "Virtual Machine Contributor"
  principal_id         = azurerm_user_assigned_identity.github[0].principal_id
  principal_type       = "ServicePrincipal"
}

# `az vm run-command create` reads the resource group (for its location)
# before acting on the VM; Reader is view-only.
resource "azurerm_role_assignment" "github_rg_reader" {
  count                = var.github_repository == "" ? 0 : 1
  scope                = azurerm_resource_group.main.id
  role_definition_name = "Reader"
  principal_id         = azurerm_user_assigned_identity.github[0].principal_id
  principal_type       = "ServicePrincipal"
}
