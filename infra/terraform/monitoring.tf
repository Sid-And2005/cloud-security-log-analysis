resource "azurerm_log_analytics_workspace" "main" {
  name                = "log-${local.name}-${local.suffix}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "PerGB2018"
  retention_in_days   = var.log_retention_days
  daily_quota_gb      = var.log_daily_quota_gb
  tags                = local.tags
}

# --- VM telemetry: Azure Monitor Agent + Data Collection Rule ---------------

resource "azurerm_virtual_machine_extension" "ama" {
  name                       = "AzureMonitorLinuxAgent"
  virtual_machine_id         = azurerm_linux_virtual_machine.app.id
  publisher                  = "Microsoft.Azure.Monitor"
  type                       = "AzureMonitorLinuxAgent"
  type_handler_version       = "1.0"
  auto_upgrade_minor_version = true
  automatic_upgrade_enabled  = true
  tags                       = local.tags
}

resource "azurerm_monitor_data_collection_rule" "vm" {
  name                = "dcr-${local.name}-vm"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  kind                = "Linux"
  tags                = local.tags

  destinations {
    log_analytics {
      name                  = "workspace"
      workspace_resource_id = azurerm_log_analytics_workspace.main.id
    }
  }

  data_flow {
    streams      = ["Microsoft-Syslog", "Microsoft-Perf"]
    destinations = ["workspace"]
  }

  data_sources {
    # Application services log JSON to journald -> rsyslog (facility daemon);
    # auth/authpriv capture SSH logins to the VM itself.
    syslog {
      name           = "syslog"
      streams        = ["Microsoft-Syslog"]
      facility_names = ["daemon", "auth", "authpriv", "syslog", "user"]
      log_levels     = ["Info", "Notice", "Warning", "Error", "Critical", "Alert", "Emergency"]
    }

    performance_counter {
      name                          = "vm-perf"
      streams                       = ["Microsoft-Perf"]
      sampling_frequency_in_seconds = 60
      counter_specifiers = [
        "Processor(*)\\% Processor Time",
        "Memory(*)\\% Used Memory",
        "Memory(*)\\Available MBytes Memory",
        "Logical Disk(*)\\% Used Space",
        "Logical Disk(*)\\Free Megabytes",
        "Network(*)\\Total Bytes Transmitted",
        "Network(*)\\Total Bytes Received",
      ]
    }
  }
}

resource "azurerm_monitor_data_collection_rule_association" "vm" {
  name                    = "dcra-${local.name}-vm"
  target_resource_id      = azurerm_linux_virtual_machine.app.id
  data_collection_rule_id = azurerm_monitor_data_collection_rule.vm.id
  depends_on              = [azurerm_virtual_machine_extension.ama]
}

# --- Platform diagnostics -------------------------------------------------------

resource "azurerm_monitor_diagnostic_setting" "postgres" {
  name                       = "diag-to-log-analytics"
  target_resource_id         = azurerm_postgresql_flexible_server.main.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "PostgreSQLLogs"
  }

  enabled_metric {
    category = "AllMetrics"
  }
}

resource "azurerm_monitor_diagnostic_setting" "blob" {
  name                       = "diag-to-log-analytics"
  target_resource_id         = "${azurerm_storage_account.logs.id}/blobServices/default"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "StorageWrite"
  }

  enabled_log {
    category = "StorageDelete"
  }

  enabled_metric {
    category = "Transaction"
  }
}

# --- Saved queries (Log Analytics > Logs > Queries > "Security Log Platform") ---

locals {
  app_logs = <<-KQL
    Syslog
    | where ProcessName startswith "seclog-"
    | extend d = parse_json(SyslogMessage)
    | extend level = tostring(d.level), service = tostring(d.service), operation = tostring(d.operation), msg = tostring(d.msg)
  KQL

  saved_queries = {
    app_errors = {
      name  = "Application errors"
      query = "${local.app_logs}| where level in ('ERROR', 'CRITICAL')\n| project TimeGenerated, Computer, service, operation, msg, error_type = tostring(d.error_type), batch_id = tostring(d.batch_id), event_id = tostring(d.event_id)\n| order by TimeGenerated desc"
    }
    threat_alerts = {
      name  = "High-severity threat alerts"
      query = "${local.app_logs}| where operation == 'threat_alert'\n| project TimeGenerated, severity = tostring(d.severity), source_ip = tostring(d.source_ip), detection_source = tostring(d.detection_source), rf_score = todouble(d.anomaly_probability), msg\n| order by TimeGenerated desc"
    }
    throughput = {
      name  = "Ingestion throughput (events per 5 min)"
      query = "${local.app_logs}| where operation == 'batch_processed'\n| summarize events = sum(toint(d['count'])), batches = count() by bin(TimeGenerated, 5m)\n| render timechart"
    }
    blob_failures = {
      name  = "Blob upload failures and batch retries"
      query = "${local.app_logs}| where operation in ('blob_upload', 'batch_retry') and level in ('ERROR', 'CRITICAL')\n| project TimeGenerated, operation, msg, error_type = tostring(d.error_type), batch_id = tostring(d.batch_id)"
    }
    db_failures = {
      name  = "Database failures (application side)"
      query = "${local.app_logs}| where operation startswith 'db_' and level == 'ERROR'\n| project TimeGenerated, service, operation, msg, error_type = tostring(d.error_type)"
    }
    service_restarts = {
      name  = "Service starts, stops and failures"
      query = "Syslog\n| where ProcessName == 'systemd' and SyslogMessage has 'seclog-'\n| where SyslogMessage has_any ('Started', 'Stopped', 'Failed', 'Scheduled restart', 'exited')\n| project TimeGenerated, Computer, SyslogMessage\n| order by TimeGenerated desc"
    }
    vm_performance = {
      name  = "VM CPU, memory and disk"
      query = "Perf\n| where CounterName in ('% Processor Time', '% Used Memory', '% Used Space')\n| where InstanceName in ('_Total', 'total', '/') or ObjectName == 'Memory'\n| summarize avg(CounterValue) by bin(TimeGenerated, 5m), CounterName\n| render timechart"
    }
    postgres_logs = {
      name  = "PostgreSQL errors (server side)"
      query = "AzureDiagnostics\n| where ResourceProvider == 'MICROSOFT.DBFORPOSTGRESQL'\n| where errorLevel_s in ('ERROR', 'FATAL', 'PANIC')\n| project TimeGenerated, errorLevel_s, Message\n| order by TimeGenerated desc"
    }
  }
}

resource "azurerm_log_analytics_saved_search" "queries" {
  for_each                   = local.saved_queries
  name                       = "seclog_${each.key}"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
  category                   = "Security Log Platform"
  display_name               = each.value.name
  query                      = each.value.query
}

# --- Alert notifications (optional: set alert_email) -----------------------

resource "azurerm_monitor_action_group" "email" {
  count               = var.alert_email == "" ? 0 : 1
  name                = "ag-${local.name}-email"
  resource_group_name = azurerm_resource_group.main.name
  short_name          = "seclog"
  tags                = local.tags

  email_receiver {
    name                    = "admin"
    email_address           = var.alert_email
    use_common_alert_schema = true
  }
}

resource "azurerm_monitor_scheduled_query_rules_alert_v2" "threats" {
  count                = var.alert_email == "" ? 0 : 1
  name                 = "alert-${local.name}-high-severity-threats"
  location             = azurerm_resource_group.main.location
  resource_group_name  = azurerm_resource_group.main.name
  description          = "The ML/rule detector raised a HIGH or CRITICAL security alert."
  severity             = 1
  evaluation_frequency = "PT5M"
  window_duration      = "PT5M"
  scopes               = [azurerm_log_analytics_workspace.main.id]
  tags                 = local.tags

  criteria {
    query                   = "${local.app_logs}| where operation == 'threat_alert'\n| extend severity = tostring(d.severity)\n| where severity in ('HIGH', 'CRITICAL')"
    time_aggregation_method = "Count"
    threshold               = 0
    operator                = "GreaterThan"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  action {
    action_groups = [azurerm_monitor_action_group.email[0].id]
  }
}

resource "azurerm_monitor_scheduled_query_rules_alert_v2" "app_errors" {
  count                = var.alert_email == "" ? 0 : 1
  name                 = "alert-${local.name}-application-errors"
  location             = azurerm_resource_group.main.location
  resource_group_name  = azurerm_resource_group.main.name
  description          = "Repeated application errors (blob uploads, database writes, processing)."
  severity             = 2
  evaluation_frequency = "PT5M"
  window_duration      = "PT15M"
  scopes               = [azurerm_log_analytics_workspace.main.id]
  tags                 = local.tags

  criteria {
    query                   = "${local.app_logs}| where level in ('ERROR', 'CRITICAL')"
    time_aggregation_method = "Count"
    threshold               = 5
    operator                = "GreaterThan"

    failing_periods {
      minimum_failing_periods_to_trigger_alert = 1
      number_of_evaluation_periods             = 1
    }
  }

  action {
    action_groups = [azurerm_monitor_action_group.email[0].id]
  }
}

resource "azurerm_monitor_metric_alert" "vm_cpu" {
  count               = var.alert_email == "" ? 0 : 1
  name                = "alert-${local.name}-vm-cpu"
  resource_group_name = azurerm_resource_group.main.name
  scopes              = [azurerm_linux_virtual_machine.app.id]
  description         = "VM CPU above 85% for 15 minutes."
  severity            = 2
  frequency           = "PT5M"
  window_size         = "PT15M"
  tags                = local.tags

  criteria {
    metric_namespace = "Microsoft.Compute/virtualMachines"
    metric_name      = "Percentage CPU"
    aggregation      = "Average"
    operator         = "GreaterThan"
    threshold        = 85
  }

  action {
    action_group_id = azurerm_monitor_action_group.email[0].id
  }
}
