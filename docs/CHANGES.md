# Changes from the original project

The original ZIP is kept untouched. Its contents, minus the Windows `.venv`,
are also extracted next to this folder as `original_extract/`.

## Bugs found in the original code and fixed

| # | Where | Problem | Fix |
|---|---|---|---|
| 1 | `consumer.py` | `finally: path.unlink()` deleted the incoming file **even when processing failed**, so a failed event was lost permanently. | Files are deleted only after the event is committed. Failures leave files in place for retry, and malformed files go to `quarantine/`. |
| 2 | `consumer.py` | Every event rebuilt a flat list of **all users'** login history (O(total logins) per event). | Only the history of users with successful logins in the current window is used (identical features), loaded lazily per user and cached. PostgreSQL serves it from a partial index. |
| 3 | `consumer.py` | Window state was memory-only and was lost on every restart. | Windows for the last 6 minutes are rebuilt from storage at startup. |
| 4 | `consumer.py` | Out-of-order events could include *later* events in an earlier event's window. | Each event is scored on `[ts − 5 min, ts]` only. Windows are kept sorted and pruned by the latest timestamp seen. |
| 5 | `.env.example`, `.gitignore`, `requirements.txt` | Written with literal `\n` text, so each was a single line: **`.gitignore` ignored nothing correctly** (risking `.env`, data and models being committed). | Rewritten with real line breaks and complete ignore rules. |
| 6 | `app.py` | `DASHBOARD_REFRESH_SECONDS` was never used (the interval was hard-coded to 3 s). `st_autorefresh` ran before `set_page_config`. `use_container_width` is deprecated. | Uses the setting, calls `set_page_config` first, uses `width="stretch"`. |
| 7 | `src/detector.py` | Severity inconsistency: an ML-only alert was MEDIUM, but ML plus a weak LOW rule became LOW. More evidence gave lower severity. | ML-flagged windows are at least MEDIUM. The model score still never raises severity beyond MEDIUM. |
| 8 | `src/detector.py` | A missing model silently switched to rules-only. | In Azure the consumer refuses to start without a valid model (`REQUIRE_MODEL`). Locally the fallback is kept but logged as a warning. |
| 9 | `src/features.py` | Timestamps parsed without a format fell back to per-element `dateutil` parsing (slow, with a warning on every window). | `format="ISO8601"`; feature definitions unchanged. |
| 10 | model inference | `n_jobs=-1` created a thread pool for every single-row prediction (about 30 ms per event). | `n_jobs=1` at load time: about 3–7 ms per event, identical predictions (verified on 500 random rows). |

## Files

### Changed

| File | Why |
|---|---|
| `src/config.py` | Environment-based settings (local/azure, backends, PostgreSQL, Blob, identity, batching, logging), `validate_settings()` with clear errors, no silent CSV fallback in Azure, `describe()` for safe logging |
| `src/storage.py` | `StorageBackend` interface + `CsvStorage` (wraps the original CSV functions, unchanged) + `get_storage()` factory; shared helpers for detection source and dashboard statistics |
| `src/detector.py` | Validated `ModelBundle` (schema, `feature_names_in_`, anomaly class by label), model version (file hash), `Score`, `detection_source`, pure `evaluate_window()`; the rules themselves are unchanged |
| `src/stream_utils.py` | `validate_event()`, UTC normalisation, `InvalidEventError` |
| `src/features.py` | ISO-8601 timestamp parsing only |
| `consumer.py` | Thin service loop around `src/pipeline.py`: startup validation, retries with exponential backoff, SIGTERM handling, heartbeat |
| `app.py` | Reads through the storage interface (CSV or PostgreSQL). Shows "ML-detected", "ML-only", "Rule detections", "Rules-only" tiles, a detection-source chart, a "Detected by" filter, the RF score as a bar, model version, and a system-health sidebar. Shows an error instead of stale data when PostgreSQL is down. The original layout and charts are kept. |
| `eval.py` | Uses the production scoring path, adds the extended scenario set, reports ML-only / rules-only / combined metrics, `--json` output |
| `requirements.txt` | Pinned, tested versions; scikit-learn 1.7.2 to match the pickled model; psycopg 3 + pool; azure-storage-blob + azure-identity |
| `tests/test_features.py` | Original two tests kept; four added |
| `README.md`, `models/README.md`, `.env.example`, `.gitignore` | Rewritten |

### Added

| File | Purpose |
|---|---|
| `src/pipeline.py` | Durable ingestion: validate → archive → dedupe → window → score → persist → delete |
| `src/logging_setup.py` | JSON structured logs with service/operation/event/batch fields and secret redaction |
| `src/cloud/blob_storage.py` | `BlobArchiver` (managed identity, no overwrite, retries, MD5-checked idempotent retry) and `LocalArchiver` |
| `src/cloud/postgres_storage.py` | `PostgresStorage`: connection pool, per-connection Entra token, transactions, idempotent inserts, alert upsert, migrations, health |
| `src/cloud/credentials.py` | `DefaultAzureCredential` with the VM's user-assigned identity |
| `src/cloud/migrations/001_initial_schema.sql` | Tables, constraints and indexes |
| `manage.py` | `init-db`, `init-archive`, `health`, `check-model` |
| `docker-compose.yml` | Local PostgreSQL 16 + Azurite |
| `requirements-dev.txt` | Adds pytest |
| `tests/conftest.py`, `tests/fakes.py`, `tests/test_*.py` | 82 tests (see TESTING.md) |
| `infra/terraform/*` | All Azure infrastructure (see DEPLOYMENT.md) |
| `deploy/systemd/*.service` | consumer, dashboard, optional producer |
| `deploy/install_release.sh`, `fetch_and_install.sh`, `deploy_via_ssh.sh`, `rollback.sh` | Release install with health check and automatic rollback |
| `.github/workflows/ci.yml`, `deploy.yml` | CI and controlled OIDC deployment |
| `docs/*.md`, `docs/evaluation_results.json` | Documentation and evaluation output |

### Moved or removed

| File | Change |
|---|---|
| `repair_alerts.py`, `repair_events.py` | Moved to `scripts/` (one-off tools for the old local CSV files) |
| `cleanup_alerts.py` | Removed: alert de-duplication per (IP, window) is done by both storage backends |
| `instructions.txt` | Removed: superseded by README.md (Windows PowerShell commands still work: `py -3.12 -m venv .venv`, `.\.venv\Scripts\Activate.ps1`) |
| `.venv/` (Windows, 22k files), `__pycache__/`, `data/` contents | Not included in the new package (local environment and data) |

## Behaviour that intentionally did not change

* The 18 model features, their definitions, and the five-minute IP windowing.
* The trained model and its decision rule (highest class score). No retraining, no threshold change.
* All rule thresholds and texts in `detect_threats`.
* One alert per (source IP, five-minute bucket), updated with the latest state.
* The local CSV workflow (`python consumer.py`, `producer.py`, `streamlit run app.py`).
