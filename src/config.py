"""Application configuration loaded from environment variables.

Local development works with no environment at all (CSV storage, local raw
archive). Azure deployments set APP_ENV=azure and the settings validated in
``validate_settings``. Secrets are never hard-coded here.
"""

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

ROOT_DIR = Path(__file__).resolve().parents[1]


def _env(name, default=None):
    value = os.getenv(name)
    return default if value is None or value.strip() == "" else value.strip()


def _env_bool(name, default=False):
    value = _env(name)
    if value is None:
        return default
    return value.lower() in {"1", "true", "yes", "on"}


def _env_int(name, default):
    value = _env(name)
    return int(value) if value is not None else default


def _env_float(name, default):
    value = _env(name)
    return float(value) if value is not None else default


APP_ENV = (_env("APP_ENV", "local") or "local").lower()
IS_AZURE = APP_ENV == "azure"
SERVICE_NAME = _env("SERVICE_NAME", "seclog")

# --- Paths -----------------------------------------------------------------
DATA_DIR = Path(_env("DATA_DIR", str(ROOT_DIR / "data")))
INCOMING_DIR = Path(_env("INCOMING_DIR", str(DATA_DIR / "incoming")))
QUARANTINE_DIR = Path(_env("QUARANTINE_DIR", str(DATA_DIR / "quarantine")))
LOCAL_ARCHIVE_DIR = Path(_env("LOCAL_ARCHIVE_DIR", str(DATA_DIR / "archive")))
HEARTBEAT_FILE = Path(_env("HEARTBEAT_FILE", str(DATA_DIR / "consumer_heartbeat.json")))
MODEL_PATH = Path(
    _env("MODEL_PATH", str(ROOT_DIR / "models" / "random_forest_model_v2.joblib"))
)

# Local (CSV) backend files.
EVENTS_CSV = DATA_DIR / "events.csv"
ALERTS_CSV = DATA_DIR / "alerts.csv"
PROCESSED_JSONL = DATA_DIR / "processed_events.jsonl"
BATCHES_JSONL = DATA_DIR / "ingestion_batches.jsonl"

# --- Backends ----------------------------------------------------------------
# storage: "csv" (local development) or "postgres" (Azure Database for PostgreSQL)
STORAGE_BACKEND = (_env("STORAGE_BACKEND", "postgres" if IS_AZURE else "csv")).lower()
# raw archive: "local" (data/archive) or "azure_blob" (Azure Blob Storage)
ARCHIVE_BACKEND = (_env("ARCHIVE_BACKEND", "azure_blob" if IS_AZURE else "local")).lower()

# --- Detection -------------------------------------------------------------
# The Random Forest is the primary detector. Without a model the consumer
# refuses to start unless the labelled rules-only fallback is allowed.
REQUIRE_MODEL = _env_bool("REQUIRE_MODEL", IS_AZURE)
ANOMALY_LABEL = _env_int("ANOMALY_LABEL", 1)
WINDOW_MINUTES = _env_int("WINDOW_MINUTES", 5)
ALLOWED_LATENESS_SECONDS = _env_int("ALLOWED_LATENESS_SECONDS", 60)

# --- Consumer --------------------------------------------------------------
BATCH_SIZE = _env_int("BATCH_SIZE", 200)
# Wait up to this long for a batch to fill before archiving it, so a slow
# trickle of events produces a few larger blobs instead of one per event.
BATCH_LINGER_SECONDS = _env_float("BATCH_LINGER_SECONDS", 5.0)
POLL_INTERVAL_SECONDS = _env_float("POLL_INTERVAL_SECONDS", 0.5)
RETRY_BACKOFF_SECONDS = _env_float("RETRY_BACKOFF_SECONDS", 5.0)
HEARTBEAT_MAX_AGE_SECONDS = _env_int("HEARTBEAT_MAX_AGE_SECONDS", 90)

# --- PostgreSQL --------------------------------------------------------------
# Either DATABASE_URL (local Docker) or the PG* parts (Azure).
DATABASE_URL = _env("DATABASE_URL")
PGHOST = _env("PGHOST")
PGPORT = _env_int("PGPORT", 5432)
PGDATABASE = _env("PGDATABASE", "seclog")
PGUSER = _env("PGUSER")
PGPASSWORD = _env("PGPASSWORD")
PGSSLMODE = _env("PGSSLMODE", "require" if IS_AZURE else "prefer")
# "entra": short-lived Microsoft Entra tokens from the managed identity.
# "password": PGPASSWORD / DATABASE_URL (local development only).
PG_AUTH = (_env("PG_AUTH", "entra" if IS_AZURE else "password")).lower()
PG_POOL_MIN = _env_int("PG_POOL_MIN", 1)
PG_POOL_MAX = _env_int("PG_POOL_MAX", 5)
PG_CONNECT_TIMEOUT = _env_int("PG_CONNECT_TIMEOUT", 10)

# --- Azure identity and Blob Storage -----------------------------------------
# Client ID of the VM's user-assigned managed identity (DefaultAzureCredential
# reads AZURE_CLIENT_ID itself; it is repeated here for validation/logging).
AZURE_CLIENT_ID = _env("AZURE_CLIENT_ID")
AZURE_STORAGE_ACCOUNT_URL = _env("AZURE_STORAGE_ACCOUNT_URL")
AZURE_STORAGE_CONTAINER = _env("AZURE_STORAGE_CONTAINER", "raw-logs")
# Only for the local Azurite emulator. Never set this on the Azure VM.
AZURE_STORAGE_CONNECTION_STRING = _env("AZURE_STORAGE_CONNECTION_STRING")
BLOB_PREFIX = _env("BLOB_PREFIX", "raw")
BLOB_MAX_RETRIES = _env_int("BLOB_MAX_RETRIES", 5)

# --- Dashboard / logging -----------------------------------------------------
DASHBOARD_REFRESH_SECONDS = _env_int("DASHBOARD_REFRESH_SECONDS", 3)
DASHBOARD_ALERT_LIMIT = _env_int("DASHBOARD_ALERT_LIMIT", 5000)
DASHBOARD_EVENT_LIMIT = _env_int("DASHBOARD_EVENT_LIMIT", 200)
LOG_LEVEL = _env("LOG_LEVEL", "INFO").upper()
LOG_FORMAT = (_env("LOG_FORMAT", "json" if IS_AZURE else "text")).lower()


class ConfigError(RuntimeError):
    """Raised when the configuration is incomplete or inconsistent."""


def validate_settings():
    """Fail fast with a clear message instead of running half-configured."""
    problems = []

    if APP_ENV not in {"local", "azure"}:
        problems.append(f"APP_ENV must be 'local' or 'azure', got {APP_ENV!r}")
    if STORAGE_BACKEND not in {"csv", "postgres"}:
        problems.append(f"STORAGE_BACKEND must be 'csv' or 'postgres', got {STORAGE_BACKEND!r}")
    if ARCHIVE_BACKEND not in {"local", "azure_blob"}:
        problems.append(f"ARCHIVE_BACKEND must be 'local' or 'azure_blob', got {ARCHIVE_BACKEND!r}")
    if PG_AUTH not in {"entra", "password"}:
        problems.append(f"PG_AUTH must be 'entra' or 'password', got {PG_AUTH!r}")

    if IS_AZURE:
        # A cloud deployment must never quietly write to local CSV files.
        if STORAGE_BACKEND != "postgres":
            problems.append("APP_ENV=azure requires STORAGE_BACKEND=postgres")
        if ARCHIVE_BACKEND != "azure_blob":
            problems.append("APP_ENV=azure requires ARCHIVE_BACKEND=azure_blob")
        if AZURE_STORAGE_CONNECTION_STRING:
            problems.append(
                "AZURE_STORAGE_CONNECTION_STRING must not be set in Azure; "
                "the VM uses its managed identity"
            )
        if PGSSLMODE not in {"require", "verify-ca", "verify-full"}:
            problems.append("APP_ENV=azure requires PGSSLMODE=require (or stricter)")

    if STORAGE_BACKEND == "postgres":
        if not DATABASE_URL and not (PGHOST and PGUSER):
            problems.append("PostgreSQL storage needs DATABASE_URL or PGHOST and PGUSER")
        if PG_AUTH == "password" and not DATABASE_URL and not PGPASSWORD:
            problems.append("PG_AUTH=password needs PGPASSWORD or DATABASE_URL")

    if ARCHIVE_BACKEND == "azure_blob":
        if not (AZURE_STORAGE_ACCOUNT_URL or AZURE_STORAGE_CONNECTION_STRING):
            problems.append(
                "ARCHIVE_BACKEND=azure_blob needs AZURE_STORAGE_ACCOUNT_URL "
                "(or AZURE_STORAGE_CONNECTION_STRING for the local Azurite emulator)"
            )
        if not AZURE_STORAGE_CONTAINER:
            problems.append("AZURE_STORAGE_CONTAINER must not be empty")

    if BATCH_SIZE < 1:
        problems.append("BATCH_SIZE must be at least 1")

    if problems:
        raise ConfigError("Invalid configuration:\n  - " + "\n  - ".join(problems))


def ensure_local_dirs():
    for path in (DATA_DIR, INCOMING_DIR, QUARANTINE_DIR):
        path.mkdir(parents=True, exist_ok=True)


def describe():
    """Non-secret summary of the active configuration, safe to log."""
    return {
        "app_env": APP_ENV,
        "storage_backend": STORAGE_BACKEND,
        "archive_backend": ARCHIVE_BACKEND,
        "model_path": str(MODEL_PATH),
        "incoming_dir": str(INCOMING_DIR),
        "pg_host": PGHOST or ("<DATABASE_URL>" if DATABASE_URL else None),
        "pg_database": PGDATABASE,
        "pg_auth": PG_AUTH,
        "pg_sslmode": PGSSLMODE,
        "blob_account_url": AZURE_STORAGE_ACCOUNT_URL
        or ("<emulator>" if AZURE_STORAGE_CONNECTION_STRING else None),
        "blob_container": AZURE_STORAGE_CONTAINER,
        "managed_identity_client_id_set": bool(AZURE_CLIENT_ID),
    }


ensure_local_dirs()
