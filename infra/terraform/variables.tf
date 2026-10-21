variable "subscription_id" {
  description = "Azure subscription ID to deploy into (az account show --query id -o tsv)."
  type        = string
}

variable "project" {
  description = "Short lowercase project name used in resource names."
  type        = string
  default     = "seclog"

  validation {
    condition     = can(regex("^[a-z][a-z0-9]{2,10}$", var.project))
    error_message = "project must be 3-11 lowercase letters/digits, starting with a letter."
  }
}

variable "environment" {
  description = "Environment name, e.g. dev or demo."
  type        = string
  default     = "dev"
}

variable "location" {
  description = "Azure region. Must be allowed by any subscription policy and support every service used (run scripts/azure_preflight.sh). The MAHE Azure for Students policy allows uaenorth, malaysiawest, eastasia, indiasouthcentral and koreacentral; indiasouthcentral lacks data collection rules, so eastasia is the default."
  type        = string
  default     = "eastasia"
}

variable "admin_ip_cidr" {
  description = "Your public IP as x.x.x.x/32 (curl -s https://api.ipify.org), or your network's range (/24 to /32) if its NAT address changes, as on campus networks. Only these addresses may SSH to the VM, open the dashboard and browse the blob container."
  type        = string

  validation {
    condition = (
      can(cidrhost(var.admin_ip_cidr, 0)) &&
      can(regex("/(2[4-9]|3[0-2])$", var.admin_ip_cidr)) &&
      cidrhost(var.admin_ip_cidr, 0) == split("/", var.admin_ip_cidr)[0]
    )
    error_message = "admin_ip_cidr must be an IPv4 network from /24 to /32 written at its base address, e.g. 203.0.113.7/32 or 203.0.113.0/24."
  }
}

variable "dashboard_allowed_cidrs" {
  description = "Additional CIDRs allowed to reach the dashboard on port 8501 (e.g. the examiner's network). The dashboard has no login, so keep this list short."
  type        = list(string)
  default     = []
}

variable "admin_username" {
  description = "Linux administrator user on the VM (SSH key authentication only)."
  type        = string
  default     = "azureuser"
}

variable "ssh_public_key_path" {
  description = "Path to the SSH public key installed for admin_username."
  type        = string
  default     = "~/.ssh/id_ed25519.pub"
}

variable "vm_size" {
  description = "VM size. Standard_B2als_v2 (2 vCPU, 4 GiB) fits the model, consumer and dashboard."
  type        = string
  default     = "Standard_B2als_v2"
}

variable "postgres_sku" {
  description = "PostgreSQL Flexible Server SKU (Burstable B1ms is the cheapest)."
  type        = string
  default     = "B_Standard_B1ms"
}

variable "postgres_version" {
  description = "PostgreSQL major version."
  type        = string
  default     = "16"
}

variable "postgres_storage_mb" {
  description = "PostgreSQL storage in MB (32768 is the minimum)."
  type        = number
  default     = 32768
}

variable "postgres_human_admin" {
  description = "Optional Microsoft Entra user to add as a PostgreSQL admin for troubleshooting (object_id from `az ad signed-in-user show --query id`, principal_name = your UPN). Leave null to skip."
  type = object({
    object_id      = string
    principal_name = string
  })
  default = null
}

variable "raw_log_cool_after_days" {
  description = "Move raw log blobs to the Cool tier after this many days."
  type        = number
  default     = 30
}

variable "raw_log_delete_after_days" {
  description = "Delete raw log blobs after this many days (retention policy)."
  type        = number
  default     = 180
}

variable "log_retention_days" {
  description = "Log Analytics retention in days (30 is included in the base price)."
  type        = number
  default     = 30
}

variable "log_daily_quota_gb" {
  description = "Daily ingestion cap for Log Analytics, to protect student credits. -1 disables the cap."
  type        = number
  default     = 1
}

variable "alert_email" {
  description = "E-mail address for Azure Monitor alert notifications (high-severity threats, application errors, high CPU). Empty disables alert rules."
  type        = string
  default     = ""
}

variable "github_repository" {
  description = "GitHub repository as owner/name allowed to deploy via OIDC (no stored Azure secret). Empty disables the deployment identity."
  type        = string
  default     = ""
}

variable "github_environment" {
  description = "GitHub Actions environment that is allowed to deploy."
  type        = string
  default     = "production"
}

variable "tags" {
  description = "Extra tags applied to all resources."
  type        = map(string)
  default     = {}
}
