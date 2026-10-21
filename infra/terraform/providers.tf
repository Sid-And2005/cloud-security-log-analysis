terraform {
  required_version = ">= 1.6"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.14"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # State is local by default and is git-ignored. It contains resource IDs but
  # no application secrets (PostgreSQL uses Entra authentication only).
  # For a shared team state, create a storage account manually and use:
  # backend "azurerm" {
  #   resource_group_name  = "rg-tfstate"
  #   storage_account_name = "<unique-name>"
  #   container_name       = "tfstate"
  #   key                  = "seclog.tfstate"
  #   use_azuread_auth     = true
  # }
}

provider "azurerm" {
  features {
    resource_group {
      # Refuse to delete the group if something outside Terraform lives in it.
      prevent_deletion_if_contains_resources = true
    }
  }
  # Authenticates with `az login` (or ARM_* environment variables).
  subscription_id = var.subscription_id
}
