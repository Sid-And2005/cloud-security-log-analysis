# Testing and evaluation

## 1. Test suite

| File | What it covers |
|---|---|
| `tests/test_features.py` | feature extraction, rates/counts, mixed ISO-8601 formats, country-baseline features from login history |
| `tests/test_stream_utils.py` | event validation (required fields, bad timestamps), UTC normalisation, five-minute bucketing |
| `tests/test_detector.py` | model input column order and NaN/invalid handling; anomaly probability looked up by class **label** (tested with classes stored as `[1, 0]`); bundle/schema validation; detection-source classification; ML-only labelling; rule-only alerts never reported as ML; severity floor; missing-model behaviour; the real model loads, matches the schema, and agrees with `sklearn.predict` |
| `tests/test_config_logging.py` | Azure-mode validation fails clearly for each missing or unsafe setting; no secrets in `describe()`; log redaction of passwords, keys, tokens and SAS signatures; structured JSON log fields |
| `tests/test_blob_storage.py` | lossless JSONL serialisation; date-partitioned names; no overwrite; identical retry accepted; conflicting blob and network failures raise `ArchiveError` (Azure SDK mocked) |
| `tests/test_storage.py` | CSV backend round trip; alert upsert/dedup per (IP, window); duplicate IDs across restarts; per-user chronological login history; window-restore query; legacy rows without `detection_source`; backend selection; Entra token fetched for **every** new PostgreSQL connection; TLS/UTC connection settings |
| `tests/test_pipeline.py` | archive before delete; Blob outage keeps files; database outage keeps unprocessed files and does **not** update window state (no double counting on retry); duplicate events skipped; invalid events quarantined; out-of-order windows; window pruning; restart restores windows; login history feeds country features; one HIGH/CRITICAL notification per escalation; batch linger |
| `tests/test_integration.py` | **real PostgreSQL 16 and Azurite**: idempotent migrations, idempotent inserts, alert upsert with `peak_probability`/`evaluation_count`, UTC storage, unknown fields kept in `extra`, login history via the partial index, health; **end to end**: 22 brute-force events → raw batch archived unchanged in Blob → features → Random Forest → PostgreSQL → **Streamlit dashboard** (rendered with `AppTest`) shows the record; PostgreSQL down → clear `StorageError`, files kept, dashboard shows an error instead of stale data; Blob down → files kept |

Integration tests skip automatically unless `TEST_DATABASE_URL` and
`TEST_AZURITE_CONNECTION_STRING` are set. CI always sets them.

### Results (21 Oct 2026)

| Environment | Result |
|---|---|
| macOS, Python 3.13.5, PostgreSQL 16 + Azurite in Docker | **82 passed** (25 s) |
| Ubuntu 24.04, Python 3.12.3 (the VM/CI platform), same services | **82 passed** (20 s) |
| Unit tests only, no services | 78 passed, 4 skipped (the integration tests that need PostgreSQL/Azurite) |
| `terraform fmt -check` / `validate` (Terraform 1.9.8, azurerm 4.81.0) | clean / valid |
| ShellCheck on `deploy/*.sh`, actionlint on both workflows | clean |

A mutation check confirmed the tests catch real regressions: reintroducing the
original "delete the file even when processing failed" behaviour fails
`test_database_failure_keeps_unprocessed_files_and_state`.

### Deployment simulation (systemd Ubuntu 24.04 container)

A Docker container running real systemd was provisioned like `cloud-init`
(service user, directories, env file). It used local PostgreSQL and Azurite in
place of Azure, because managed-identity authentication only exists in Azure.

| Scenario | Outcome |
|---|---|
| Fresh install with `install_release.sh` | `DEPLOY_RESULT=SUCCESS`; consumer + dashboard active as user `seclog`; health check green |
| Producer service on for 75 s | events and alerts in PostgreSQL, raw batches in the Blob emulator, dashboard HTTP 200, JSON logs in `/var/log/syslog` tagged `seclog-consumer` (what the Azure Monitor Agent collects) |
| Deliberately broken release (consumer crashes on start) | health check failed, automatic **rollback** to the previous release, failed release removed, exit code 1, services healthy |
| Container restart (VM reboot) | both services back automatically; consumer restored its IP windows from PostgreSQL |

These runs found three deployment bugs that are now fixed:

1. After a crash loop, systemd's start limit blocked the rollback restart. Fixed with `systemctl reset-failed`.
2. Failed releases were kept, so a manual rollback could pick one.
3. macOS `tar` metadata ended up in release archives.

## 2. Synthetic detection evaluation (`python eval.py`)

### Method

`eval.py` generates labelled five-minute IP windows with fixed seeds and scores
each window three ways: Random Forest only, supplementary rules only, and both
combined (an alert if either fires, which is what the deployed system does).
**Labels are attached by the generator and never passed to the detector.**
No login history is supplied, so the country features are 0.

* **Baseline set** (seed 42) reproduces the original 130-window test: 100 sparse
  benign windows (1–3 events from one stable user/agent profile), plus 10 each of
  brute force (16–22 failed logins), request flood (125–145 requests) and
  endpoint scan (12–18 scanner paths).
* **Extended set** (seed 43, 200 windows) adds harder cases. The benign side
  adds occasional failed logins (4–8 events with one failure) and normal
  high-traffic bursts (25–50 ordinary requests from one user). The suspicious
  side adds moderate repeated failed logins (8–12), HTTP error spikes (15–25
  mostly 5xx/404) and sensitive-endpoint access (6–12 requests to `/admin`,
  `/.env`, `/backup.sql`, ...).

### Results

Full output is in `docs/evaluation_results.json` (model `random_forest_model_v2@f15baf3a3307`).

| Set | Detector | Precision | Recall | F1 | FPR | TP/FP/FN/TN |
|---|---|---|---|---|---|---|
| Baseline (130) | Random Forest only | 1.000 | **0.667** | 0.800 | 0.000 | 20/0/10/100 |
| Baseline (130) | Rules only | 1.000 | 1.000 | 1.000 | 0.000 | 30/0/0/100 |
| Baseline (130) | RF + rules (deployed) | 1.000 | 1.000 | 1.000 | 0.000 | 30/0/0/100 |
| Extended (200) | Random Forest only | 0.714 | 0.833 | 0.769 | **0.143** | 50/20/10/120 |
| Extended (200) | Rules only | 0.750 | 1.000 | 0.857 | 0.143 | 60/20/0/120 |
| Extended (200) | RF + rules (deployed) | 0.741 | 1.000 | 0.851 | 0.150 | 60/21/0/119 |

Windows flagged per scenario (extended set):

| Scenario | Truth | n | RF | Rules | Combined | Mean RF score |
|---|---|---|---|---|---|---|
| normal (sparse) | benign | 100 | 0 | 0 | 0 | 0.005 |
| occasional failed logins | benign | 20 | 0 | 1 | 1 | 0.193 |
| normal high-traffic burst | benign | 20 | **20** | 19 | 20 | 0.609 |
| brute force | attack | 10 | 10 | 10 | 10 | 0.801 |
| repeated failed logins | attack | 10 | 10 | 10 | 10 | 0.788 |
| request flood | attack | 10 | **0** | 10 | 10 | 0.431 |
| endpoint scan | attack | 10 | 10 | 10 | 10 | 0.855 |
| HTTP error spike | attack | 10 | 10 | 10 | 10 | 0.728 |
| sensitive endpoint access | attack | 10 | 10 | 10 | 10 | 0.853 |

### Interpretation and limitations

* The earlier "perfect precision and recall" figure was for **Random Forest +
  rules** on the baseline set. **The Random Forest alone** misses every request
  flood: these windows score about 0.43, below the 0.5 decision point. The rules
  catch them, which is why the deployed system keeps them as a documented
  supplementary layer.
* On the extended set, the model also flags every legitimately busy user (25–50
  requests): an FPR of 14% on that harder benign mix. So did the rules (19 of 20),
  so the problem is not specific to the model. Very large floods score low,
  while medium-volume bursts score high. That suggests the training data did
  not cover these volume ranges, but the training pipeline is not in this
  repository, so this could not be confirmed.
* No threshold or feature changes were made, and the model was not retrained.
  Improving it would mean retraining with realistic busy-but-benign traffic and
  high-volume floods, keeping the previous model, and evaluating on held-out data.
* Every figure comes from small synthetic sets built by the same authors who
  chose the scenarios. They show behaviour on these constructed patterns only
  and **do not establish real-world detection accuracy**.
* Country-change features are untested in this evaluation, because the
  synthetic producer uses a single country. They are covered by unit tests.
