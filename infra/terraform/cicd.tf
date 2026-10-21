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

resource "azurerm_role_assignment" "github_vm" {
  count                = var.github_repository == "" ? 0 : 1
  scope                = azurerm_linux_virtual_machine.app.id
  role_definition_name = "Virtual Machine Contributor"
  principal_id         = azurerm_user_assigned_identity.github[0].principal_id
  principal_type       = "ServicePrincipal"
}
