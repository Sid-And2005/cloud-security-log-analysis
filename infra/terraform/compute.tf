# Identity used by the application on the VM for Blob Storage and PostgreSQL.
resource "azurerm_user_assigned_identity" "app" {
  name                = "id-${local.name}-app"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  tags                = local.tags
}

resource "azurerm_public_ip" "vm" {
  name                = "pip-${local.name}-vm"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  allocation_method   = "Static"
  sku                 = "Standard"
  # Stable hostname, e.g. seclog-o895zm.eastasia.cloudapp.azure.com (also works on IPv6-only networks via DNS64)
  domain_name_label = "seclog-${local.suffix}"
  tags              = local.tags
}

resource "azurerm_network_interface" "vm" {
  name                = "nic-${local.name}-vm"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  tags                = local.tags

  ip_configuration {
    name                          = "primary"
    subnet_id                     = azurerm_subnet.app.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.vm.id
  }
}

locals {
  # Non-secret runtime configuration written to /etc/seclog/seclog.env.
  app_env = {
    APP_ENV                   = "azure"
    DATA_DIR                  = "/var/lib/seclog"
    PGHOST                    = azurerm_postgresql_flexible_server.main.fqdn
    PGDATABASE                = "seclog"
    PGUSER                    = azurerm_user_assigned_identity.app.name
    PGSSLMODE                 = "require"
    AZURE_CLIENT_ID           = azurerm_user_assigned_identity.app.client_id
    AZURE_STORAGE_ACCOUNT_URL = azurerm_storage_account.logs.primary_blob_endpoint
    AZURE_STORAGE_CONTAINER   = azurerm_storage_container.raw_logs.name
    LOG_FORMAT                = "json"
    LOG_LEVEL                 = "INFO"
  }
}

resource "azurerm_linux_virtual_machine" "app" {
  name                            = "vm-${local.name}"
  location                        = azurerm_resource_group.main.location
  resource_group_name             = azurerm_resource_group.main.name
  size                            = var.vm_size
  admin_username                  = var.admin_username
  disable_password_authentication = true
  network_interface_ids           = [azurerm_network_interface.vm.id]
  custom_data = base64encode(templatefile("${path.module}/templates/cloud-init.yaml.tftpl", {
    app_env = local.app_env
  }))
  tags = local.tags

  admin_ssh_key {
    username   = var.admin_username
    public_key = file(pathexpand(var.ssh_public_key_path))
  }

  # System-assigned identity: used by the Azure Monitor Agent.
  # User-assigned identity: used by the application (AZURE_CLIENT_ID).
  identity {
    type         = "SystemAssigned, UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.app.id]
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
    disk_size_gb         = 30
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "ubuntu-24_04-lts"
    sku       = "server"
    version   = "latest"
  }

  boot_diagnostics {}
}
