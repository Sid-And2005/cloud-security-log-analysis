# Deployment and operations on Azure

> **Status:** everything here was validated locally: `terraform validate`,
> a systemd Ubuntu 24.04 VM simulation running the real install, rollback and
> reboot paths against PostgreSQL and the Blob emulator, and the full test
> suite. **It has not yet been applied to a real Azure subscription.** The steps
> that only Azure can confirm are marked ☁️ and listed in section 9.

## 0. Prerequisites

* An Azure subscription (Azure for Students works) where you can create
  resources and role assignments (Owner, or Contributor plus User Access Administrator).
* [Azure CLI](https://learn.microsoft.com/cli/azure/install-azure-cli) and Terraform ≥ 1.6 (tested with 1.9.8).
* An SSH key: `ssh-keygen -t ed25519` (creates `~/.ssh/id_ed25519.pub`).
* Your public IP: `curl -s https://api.ipify.org`.

## 1. Provision the infrastructure with Terraform

```bash
az login
az account set --subscription "<subscription name or id>"
./scripts/azure_preflight.sh                  # read-only: region/SKU/quota/role checks
cd infra/terraform
cp terraform.tfvars.example terraform.tfvars   # git-ignored; set subscription_id, admin_ip_cidr, ...

terraform init        # downloads the azurerm/random providers
terraform fmt         # formats the files
terraform validate    # static checks
terraform plan -out tfplan    # review: about 30 resources to add, 0 to destroy
terraform apply tfplan        # about 10-20 minutes (PostgreSQL is the slowest)
terraform output              # names, IPs, dashboard URL (no secrets)
```

Region choice: the MAHE Azure for Students subscription has an *Allowed
resource deployment regions* policy (uaenorth, malaysiawest, eastasia,
indiasouthcentral, koreacentral). India South Central does not support data
collection rules or log alert rules, so the project uses **East Asia**, where
`Standard_B2s` is not offered: the VM is the equivalent `Standard_B2als_v2`
(2 vCPU, 4 GiB). `scripts/azure_preflight.sh` checks all of this before
anything is created; re-run it if you change `location` or `vm_size`.

What gets created (see [ARCHITECTURE.md](ARCHITECTURE.md) section 4):

| Resource | Purpose | Ongoing cost |
|---|---|---|
| Resource group, VNet, 2 subnets, NSG | network isolation | free |
| Public IP (Standard, static) | SSH + dashboard | **yes** (small, hourly) |
| Linux VM `Standard_B2als_v2` + 30 GB disk | hosts consumer and dashboard | **yes**, the largest item (compute stops when deallocated; the disk still bills) |
| PostgreSQL Flexible Server B1ms + 32 GB | events, alerts, batches | **yes** (compute + storage) |
| Private DNS zone + VNet link | private PostgreSQL name resolution | **yes** (cents/month) |
| Storage account + `raw-logs` container | raw log archive | **yes**, by usage (very small here) |
| Log Analytics workspace (1 GB/day cap) | logs and metrics | **yes**, by ingestion volume |
| Data collection rule, AMA extension, diagnostic settings, saved queries | monitoring config | free (data ingested is billed above) |
| Managed identities, role assignments, federated credential | passwordless auth | free |
| Action group + 3 alert rules (only if `alert_email` set) | notifications | **yes** (small per-rule charge) |

Use the [Azure pricing calculator](https://azure.microsoft.com/pricing/calculator/)
for your region. VM and PostgreSQL are billed **per hour whether or not you use
them**; do not assume student credits make this free.

Inspect what was created:

```bash
az resource list -g "$(terraform output -raw resource_group)" -o table
terraform state list
```

Portal: **Resource groups → rg-seclog-dev**.

## 2. First deployment (from your laptop)

Wait about 3 minutes after `apply` for cloud-init to finish (`ssh` in and run
`cloud-init status --wait`), then:

```bash
cd ../..          # repository root
VM_HOST=$(terraform -chdir=infra/terraform output -raw vm_public_ip) ./deploy/deploy_via_ssh.sh
```

The script packages the source (no venv, data, secrets or state), copies it to
`/opt/seclog/releases/<id>`, and runs `deploy/install_release.sh`. That script:

1. creates a per-release virtualenv and installs the pinned requirements;
2. runs `manage.py check-model` and then `manage.py init-db`. On first run this
   creates the `seclog` database (owned by the app identity) and the tables ☁️;
3. installs the systemd units and atomically switches `/opt/seclog/current`;
4. restarts `seclog-consumer` and `seclog-dashboard`;
5. **health check**: both services active, Streamlit `/_stcore/health`, and
   `manage.py health` (config, model, PostgreSQL, Blob container, a fresh
   consumer heartbeat). It retries for up to about 2 minutes;
6. on failure, it **rolls back** to the previous release, deletes the failed one,
   and exits non-zero. It prints `DEPLOY_RESULT=SUCCESS` only when healthy.

Then open `terraform output -raw dashboard_url` and start demo traffic:

```bash
ssh azureuser@<vm-ip> sudo systemctl start seclog-producer
```

## 3. Continuous deployment with GitHub Actions

1. Push the repository to GitHub (the model file is included; see `models/README.md`).
2. In `terraform.tfvars`, set `github_repository = "<owner>/<repo>"` and run
   `terraform apply`. This creates a deploy identity that trusts **only** that
   repository's `production` environment through OIDC. GitHub stores no Azure secret.
3. In GitHub, go to **Settings → Environments → New environment →
   `production`**. Optionally add yourself as a *required reviewer*, which gives
   you a manual approval gate. Add the values from
   `terraform output github_actions_settings`:
   * Environment **secrets**: `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`
   * **Repository** variables (Settings → Secrets and variables → Actions →
     Variables): `AZURE_RESOURCE_GROUP`, `AZURE_VM_NAME`. The deploy job is
     skipped until `AZURE_VM_NAME` exists, so CI stays green before Azure is set up.
4. Push to `main`.

What runs:

* **CI** (`.github/workflows/ci.yml`) runs on every push and every pull request to `main`:
  compile check, model/feature-schema validation, unit and integration tests
  against PostgreSQL 16 and Azurite service containers (no Azure credentials),
  the synthetic evaluation (uploaded as an artifact), `terraform fmt -check` /
  `validate`, and ShellCheck. Any failure fails the workflow.
* **Deploy** (`.github/workflows/deploy.yml`) runs only after CI succeeds for a
  **push** to `main` (never for pull requests), or manually from `main`. It logs
  in with OIDC and calls **Azure Run Command** on the VM with
  `deploy/fetch_and_install.sh`. The VM downloads exactly the tested commit,
  using the workflow's short-lived `GITHUB_TOKEN` passed as a *protected*
  parameter, and runs the same install, health check and rollback as above.
  The job fails unless the VM reports `DEPLOY_RESULT=SUCCESS`.

To test a deliberate failure, push a commit that breaks `consumer.py` (for
example `raise RuntimeError("test")` at the top). CI fails at the test stage and
nothing is deployed. To test rollback itself, deploy a broken commit manually
with `deploy_via_ssh.sh`: you get `DEPLOY_RESULT=ROLLED_BACK` and the previous
release keeps serving. Both behaviours were verified in the local VM simulation.

## 4. Operating the services (on the VM)

```bash
sudo systemctl status  seclog-consumer seclog-dashboard
sudo systemctl restart seclog-consumer          # or seclog-dashboard
sudo systemctl stop    seclog-consumer
sudo systemctl start   seclog-producer          # demo traffic on
sudo systemctl stop    seclog-producer          # demo traffic off
journalctl -u seclog-consumer -f                # live logs (JSON)
journalctl -u seclog-dashboard --since "10 min ago"
cd /opt/seclog/current && sudo systemd-run --quiet --wait --pipe --collect \
  --uid=seclog --gid=seclog --property=EnvironmentFile=/etc/seclog/seclog.env \
  --working-directory=/opt/seclog/current .venv/bin/python manage.py health
sudo bash /opt/seclog/current/deploy/rollback.sh   # previous release
ls /var/lib/seclog/incoming /var/lib/seclog/quarantine   # backlog / rejected events
```

Both services are `enabled`, so they start after a VM restart. `Restart=always`
restarts them after crashes. The consumer stops gracefully on SIGTERM after
finishing its current batch.

Layout: code in `/opt/seclog/releases/<id>` (read-only to the app),
`/opt/seclog/current` symlink, config in `/etc/seclog/seclog.env` (non-secret),
data in `/var/lib/seclog`, service user `seclog` (no login shell).

Sending real logs: any process that writes one JSON event per file into
`/var/lib/seclog/incoming/` works. Write to a temporary name, then rename, as
`producer.py:write_event` does. Required fields are `event_id`, `timestamp`
(ISO-8601) and `source_ip`. The optional fields (`user_id`, `country`, `city`,
`event_type`, `endpoint`, `method`, `status_code`, `response_bytes`,
`user_agent`) are listed in `src/storage.py:EVENT_FIELDS`. See
`producer.py:make_event` for an example event.

### PostgreSQL access for troubleshooting

The server is private, so connect through the VM. If you set
`postgres_human_admin`, from your laptop run:

```bash
ssh -L 6432:$(terraform -chdir=infra/terraform output -raw postgres_fqdn):5432 azureuser@<vm-ip>
export PGPASSWORD=$(az account get-access-token --resource-type oss-rdbms --query accessToken -o tsv)
psql "host=127.0.0.1 port=6432 dbname=seclog user=<your UPN> sslmode=require"
```

Note that `sslmode=require` with a tunnel does not verify the hostname.

## 5. Verifying monitoring (Azure Monitor / Log Analytics)

Data appears 5–15 minutes after the first deployment ☁️.

Portal: **Log Analytics workspace → Logs → Queries → "Security Log Platform"**.
That category contains 8 saved queries: application errors, high-severity
threat alerts, ingestion throughput, Blob failures, database failures,
service restarts, VM CPU/memory/disk, and PostgreSQL server errors.

Quick checks (paste into **Logs**):

```kusto
// 1. Application logs are arriving (journald -> rsyslog -> AMA)
Syslog | where ProcessName startswith "seclog-" | take 20

// 2. VM performance counters are arriving
Perf | summarize count() by ObjectName, CounterName

// 3. PostgreSQL diagnostics are arriving
AzureDiagnostics | where ResourceProvider == "MICROSOFT.DBFORPOSTGRESQL" | take 20

// 4. Blob writes are being logged
StorageBlobLogs | where OperationName == "PutBlob" | take 20
```

From the CLI:

```bash
az monitor log-analytics query -w "$(terraform -chdir=infra/terraform output -raw log_analytics_workspace_id)" \
  --analytics-query 'Syslog | where ProcessName startswith "seclog-" | summarize count() by ProcessName' -o table
```

If `Syslog` is empty, check on the VM: `systemctl status azuremonitoragent`,
`grep seclog /var/log/syslog | tail`, and in the portal under **Monitor → Data
Collection Rules → dcr-seclog-dev-vm → Resources** that the VM is associated.

E-mail alerts (if `alert_email` is set): **Monitor → Alerts → Alert rules**.
The "high-severity threats" rule fires within about 5–10 minutes of a HIGH or
CRITICAL detection. Running the producer triggers one roughly every minute.

## 6. Credentials and rotation

* **No passwords or keys exist** for the application. PostgreSQL uses Microsoft
  Entra tokens for the VM's managed identity, and password authentication is
  disabled on the server. Blob Storage uses the same identity, with a role
  scoped to the container. GitHub uses OIDC.
* Rotate the SSH key: change `ssh_public_key_path`, then `terraform apply`
  (Azure updates the key in place), or add the key to `~/.ssh/authorized_keys`
  first, then apply.
* Revoke GitHub deployment access: delete the federated credential
  (`github_repository = ""`, then `terraform apply`).
* Revoke application access: remove the role assignment or Entra admin entry,
  or delete and recreate the identity with `terraform apply -replace=azurerm_user_assigned_identity.app`.
* Local credentials are separate: the Docker PostgreSQL password `localdev` and
  the public Azurite development key are used only on your machine and in CI.
* Terraform state (`terraform.tfstate`, git-ignored) contains resource IDs but
  no application secrets. Still, keep it private.

Hardening left as optional: disable storage shared-key access entirely
(`shared_access_key_enabled = false` also requires the provider setting
`storage_use_azuread = true`), put the dashboard behind authentication, and
replace the app identity's admin role with a least-privilege PostgreSQL role.

## 7. Clean up (stop the charges)

```bash
cd infra/terraform
terraform destroy          # review the plan, type "yes"
```

Then confirm in the portal that `rg-seclog-dev` is gone, or run
`az group show -n rg-seclog-dev` (it should report not found).

To pause without destroying: `az vm deallocate -g rg-seclog-dev -n vm-seclog-dev`
stops VM compute charges (the disk and public IP still bill), and
`az postgres flexible-server stop -g rg-seclog-dev -n <server>` stops database
compute. **Azure restarts a stopped PostgreSQL server automatically after 7 days.**

## 8. Troubleshooting

| Symptom | Fix |
|---|---|
| `terraform plan` gets 403 on the storage account | Your public IP changed: update `admin_ip_cidr` and apply. |
| SSH times out | Same cause (NSG). |
| `manage.py health` reports storage `PoolTimeout` | Check private DNS resolution: `getent hosts <postgres_fqdn>` on the VM. |
| `password authentication failed for user "id-seclog-dev-app"` | Entra admin assignment not yet propagated (wait a few minutes), or `PGUSER` doesn't match the identity name. |
| Blob `AuthorizationPermissionMismatch` | Role assignments take up to about 5 minutes to propagate after `apply`. |
| Dashboard says "Storage backend unavailable" | Intended behaviour when PostgreSQL is down: no stale data is shown. |

## 9. Still to do in Azure (needs your subscription)

These steps could not be performed or verified from the development machine:

1. ☁️ `terraform plan/apply` against your subscription. Region and SKU
   availability, and student-subscription policy limits, are only known there.
2. ☁️ Managed-identity token authentication to PostgreSQL and Blob. It is unit
   tested with mocks, and the code paths match Microsoft's documented flow, but
   it has not been exercised against Azure.
3. ☁️ Azure Monitor Agent ingestion. Locally verified only up to the point where
   the JSON logs land in `/var/log/syslog`, which is what the agent reads.
4. ☁️ The GitHub Actions deploy job. Its VM-side script and its success/rollback
   logic were exercised in the simulation; the `az vm run-command` call itself
   needs a real VM.
5. Screenshots of the running dashboard and Azure resources for the report.
