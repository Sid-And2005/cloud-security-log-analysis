# Cloud-Based Security Log Analysis and ML Threat Detection Platform

Cloud Computing and DevOps Lab mini-project (School of Computer Engineering, 2026-27).

Security events are archived raw in **Azure Blob Storage**, grouped into five-minute
source-IP windows, scored by a trained **Random Forest** (the primary detector,
backed by explainable supplementary rules), and stored in **Azure Database for
PostgreSQL**. A Streamlit dashboard shows them. Everything runs on an **Azure
Linux VM** provisioned with **Terraform**, deployed by **GitHub Actions**, and
monitored with **Azure Monitor / Log Analytics**.

```
log source / producer ─► incoming/ ─► consumer ─┬─► Blob Storage (raw JSONL archive)
                                                ├─► features ─► Random Forest ─► rules (evidence)
                                                └─► PostgreSQL (events, alerts, batches) ─► dashboard
VM + services ─► Azure Monitor Agent ─► Log Analytics (app logs, VM metrics, PG/Blob diagnostics) ─► e-mail alerts
```

| Document | Contents |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Architecture, data-flow, Azure resource and database diagrams; how detection works |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | Terraform, first deployment, GitHub Actions, operating the services, monitoring, costs, cleanup |
| [docs/TESTING.md](docs/TESTING.md) | Test suite, test results, synthetic evaluation and its limitations |
| [docs/CHANGES.md](docs/CHANGES.md) | Every changed file and why; bugs found and fixed |

## Detection in one paragraph

For every event, the consumer builds that source IP's five-minute window and
computes the 18 features the model was trained on (request counts, unique
users/endpoints/user agents, failed logins, HTTP errors, sensitive-path
requests, bytes, rates, and country features from the user's successful-login
history). The Random Forest (`models/random_forest_model_v2.joblib`) gives the
anomaly score and prediction. Supplementary rules add human-readable evidence
(brute force, request flood, scanning and so on). Every alert records **who
detected it**: `ml`, `ml+rules`, or `rules` (supplementary only). The dashboard
keeps these separate, so a rule match is never presented as an ML detection.

**Known limitation (measured, see [docs/TESTING.md](docs/TESTING.md)):** on
synthetic data the Random Forest misses large request floods (score ≈0.43) and
flags legitimately busy users. The supplementary rules cover the floods. The
model was not retrained because its training pipeline is not in this repository.

## Quick start (local, no Azure needed)

Requires Python 3.12 (3.10–3.13 work).

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env            # optional; defaults work
python manage.py check-model    # validates the model bundle and feature schema
```

Run in three terminals:

```bash
python consumer.py                       # archive -> score -> store
python producer.py --interval 0.5        # synthetic traffic + attack campaigns
streamlit run app.py                     # http://localhost:8501
```

By default, local mode stores data in CSV/JSONL under `data/` and archives raw
batches to `data/archive/`, which mirrors the Blob layout.

### Local cloud emulation (same code paths as Azure)

```bash
docker compose up -d                     # PostgreSQL 16 + Azurite (Blob emulator)
# in .env, uncomment the "Cloud emulation" block, then:
python manage.py init-db && python manage.py init-archive
python manage.py health --skip-consumer
```

## Tests

```bash
python -m pytest -q                      # unit tests; integration tests skip
docker compose up -d                     # then run everything, as CI does:
TEST_DATABASE_URL=postgresql://seclog:localdev@127.0.0.1:55432/seclog \
TEST_AZURITE_CONNECTION_STRING="$(grep -o 'DefaultEndpointsProtocol=.*' .env.example)" \
python -m pytest -q
python eval.py                           # synthetic detection evaluation
```

## Deploy to Azure (summary)

1. `cd infra/terraform && cp terraform.tfvars.example terraform.tfvars` and fill in the values.
2. `az login`, then `terraform init && terraform plan -out tfplan && terraform apply tfplan`.
3. First deployment from your laptop: `VM_HOST=$(terraform output -raw vm_public_ip) ./deploy/deploy_via_ssh.sh`.
4. Optional: set `github_repository` in Terraform and the GitHub settings it outputs; pushes to `main` then deploy automatically after CI.
5. Open `terraform output -raw dashboard_url`. Start demo traffic with `sudo systemctl start seclog-producer`.
6. **When finished: `terraform destroy`.** The VM, PostgreSQL and public IP bill by the hour.

Full instructions, verification steps and troubleshooting are in [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## Repository layout

```
app.py              Streamlit dashboard (reads through the storage interface)
consumer.py         consumer service (loop, retries, graceful shutdown, heartbeat)
producer.py         synthetic event generator (normal traffic + attack campaigns)
eval.py             synthetic evaluation: ML only / rules only / combined
manage.py           init-db | init-archive | health | check-model
src/config.py       environment-based settings + validation
src/features.py     window features (model inputs + rule indicators)
src/detector.py     model loading/validation, scoring, rules, detection source
src/pipeline.py     archive -> dedupe -> window -> score -> persist -> delete
src/storage.py      storage interface + local CSV backend
src/cloud/          blob_storage.py, postgres_storage.py, credentials.py, migrations/
models/             random_forest_model_v2.joblib (versioned)
tests/              unit + integration tests
infra/terraform/    Azure infrastructure as code
deploy/             systemd units, VM install/rollback scripts
.github/workflows/  ci.yml, deploy.yml
scripts/            one-off repair tools for the old local CSV files
```

Synthetic demonstration data only. An alert indicates suspicious behaviour,
not proof of an attack. This is a student project, not production security software.
