"""Storage interface with a local CSV backend and a PostgreSQL backend.

The consumer, detector and dashboard use ``get_storage()`` and never touch a
specific backend. Configuration selects the backend; in Azure mode there is
no silent fallback to CSV (see config.validate_settings).
"""

import csv
import json
import os
import tempfile
import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from . import config
from .config import EVENTS_CSV, ALERTS_CSV, PROCESSED_JSONL

# Original event schema; anything else is kept as "extra" metadata.
EVENT_FIELDS = (
    "event_id", "timestamp", "source_ip", "user_id", "country", "city",
    "event_type", "endpoint", "method", "status_code", "response_bytes",
    "user_agent",
)
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


class StorageError(RuntimeError):
    """Persistence failed; the caller must not treat the event as processed."""


# Fields added by the detector/pipeline on top of the original event.
RESULT_FIELDS = {
    "window", "prediction", "anomaly_probability", "detector", "model_version",
    "detection_source", "alert", "threat_types", "reason", "priority",
    "window_event_count", "features", "processed_at", "batch_id",
}


def raw_event(record):
    """The original event (including unknown extra fields) of a processed record."""
    return {k: v for k, v in record.items() if k not in RESULT_FIELDS}


def is_successful_login(event):
    try:
        status = int(event.get("status_code", 0))
    except (TypeError, ValueError):
        return False
    return str(event.get("event_type", "")).lower() == "login" and 200 <= status < 400


def infer_detection_source(row):
    """Detection source for alert rows written before it was recorded."""
    value = str(row.get("detection_source", "") or "")
    if value in {"ml", "ml+rules", "rules"}:
        return value
    if "ML-only anomaly" in str(row.get("threat_types", "")):
        return "ml"
    try:
        predicted = int(float(row.get("prediction", 0) or 0)) == 1
    except (TypeError, ValueError):
        predicted = False
    return "ml+rules" if predicted else "rules"


def summarise_alerts(alerts, events_total):
    """Dashboard statistics computed from an alerts frame."""
    priority = alerts.get("priority", pd.Series(dtype=str)).astype(str).str.upper()
    sources = (
        alerts.apply(infer_detection_source, axis=1)
        if not alerts.empty else pd.Series(dtype=str)
    )
    return {
        "events_total": int(events_total),
        "alerts_total": int(len(alerts)),
        "by_severity": {s: int((priority == s).sum()) for s in SEVERITIES},
        "by_source": {s: int((sources == s).sum()) for s in ("ml", "ml+rules", "rules")},
    }


class StorageBackend(ABC):
    name = "abstract"

    def init_schema(self):
        """Create tables or files if needed (idempotent)."""

    @abstractmethod
    def health(self):
        """Return {'ok': bool, 'backend': str, ...}; never raises."""

    @abstractmethod
    def existing_event_ids(self, event_ids):
        """Subset of ``event_ids`` that has already been processed."""

    @abstractmethod
    def save_result(self, record, batch_id=None):
        """Persist a processed event and, if it is an alert, upsert the alert."""

    @abstractmethod
    def record_batch(self, batch_id, blob_uri, event_count, status, error=None):
        """Insert or update an ingestion batch."""

    @abstractmethod
    def login_history(self, user_ids):
        """{user_id: [successful login events, chronological]} for these users."""

    @abstractmethod
    def recent_events(self, since):
        """Raw events with timestamp >= since (to rebuild windows on restart)."""

    @abstractmethod
    def load_alerts(self, limit=None):
        """Alerts as a DataFrame using the dashboard's column names."""

    @abstractmethod
    def load_events(self, limit=None):
        """Most recent processed events as a DataFrame."""

    @abstractmethod
    def stats(self):
        """Aggregate counts for the dashboard (see summarise_alerts)."""

    def last_batch(self):
        return None

    def close(self):
        pass


# ---------------------------------------------------------------------------
# Local CSV backend (development). These module-level functions are the
# original implementation and are kept unchanged in behaviour.
# ---------------------------------------------------------------------------

def _serialize(value):
    """Convert values into CSV-safe scalar values."""
    if value is None:
        return ""

    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, ensure_ascii=False)

    return value


def _read_csv(path):
    """Read a CSV and return its header and records."""
    if not path.exists() or path.stat().st_size == 0:
        return [], []

    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)

        if not reader.fieldnames:
            return [], []

        header = list(reader.fieldnames)
        records = []

        for row in reader:
            # Reject malformed rows rather than silently corrupting data.
            if None in row:
                raise ValueError(
                    f"Malformed CSV row in {path}: "
                    "more fields than the header. Repair this file first."
                )

            records.append({
                column: row.get(column, "")
                for column in header
            })

    return header, records


def _atomic_write_csv(path, header, records):
    """Write a complete CSV to a temporary file, then replace the original."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    fd, temp_name = tempfile.mkstemp(
        prefix=f"{path.stem}_",
        suffix=".tmp",
        dir=str(path.parent),
    )
    os.close(fd)

    temp_path = Path(temp_name)

    try:
        with temp_path.open(
            "w", encoding="utf-8", newline=""
        ) as f:
            writer = csv.DictWriter(
                f,
                fieldnames=header,
                extrasaction="ignore",
            )
            writer.writeheader()

            for record in records:
                writer.writerow({
                    column: _serialize(record.get(column, ""))
                    for column in header
                })

            f.flush()
            os.fsync(f.fileno())

        # The temporary file is on the same filesystem.
        os.replace(temp_path, path)

    finally:
        if temp_path.exists():
            temp_path.unlink()


def _append_csv(path, record):
    """Append one record, expanding the header when new fields appear."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    record = {
        str(key): _serialize(value)
        for key, value in record.items()
    }

    header, records = _read_csv(path)

    if not header:
        header = list(record.keys())
        _atomic_write_csv(path, header, [record])
        return

    # Preserve existing column order and add any new fields at the end.
    new_columns = [
        column for column in record.keys()
        if column not in header
    ]

    if new_columns:
        header.extend(new_columns)

        # Rewrite existing rows with blank values for new columns.
        _atomic_write_csv(path, header, records)

    # Use the current header so every row has the correct number of fields.
    with path.open("a", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=header,
            extrasaction="ignore",
        )
        writer.writerow({
            column: record.get(column, "")
            for column in header
        })
        f.flush()


def append_event(event):
    """Store a processed event with a consistent CSV schema."""
    _append_csv(EVENTS_CSV, event)


def append_alert(alert):
    """Keep one alert per source IP and window, updating its latest state."""
    path = Path(ALERTS_CSV)

    header, records = _read_csv(path)

    alert = {
        str(key): _serialize(value)
        for key, value in alert.items()
    }

    if not header:
        _atomic_write_csv(path, list(alert.keys()), [alert])
        return

    # Expand the schema before updating or adding a record.
    for column in alert:
        if column not in header:
            header.append(column)

    source_ip = str(alert.get("source_ip", ""))
    window = str(alert.get("window", ""))

    matching_index = None

    for index, existing in enumerate(records):
        if (
            str(existing.get("source_ip", "")) == source_ip
            and str(existing.get("window", "")) == window
        ):
            matching_index = index

    if matching_index is not None:
        # Replace stale counts/reasons with the latest assessment.
        records[matching_index].update(alert)
    else:
        records.append(alert)

    # Also remove historical duplicates for this key.
    deduplicated = []
    seen = {}

    for record in records:
        key = (
            str(record.get("source_ip", "")),
            str(record.get("window", "")),
        )

        if key in seen:
            deduplicated[seen[key]].update(record)
        else:
            seen[key] = len(deduplicated)
            deduplicated.append(dict(record))

    _atomic_write_csv(path, header, deduplicated)


def mark_processed(event):
    """Append the processed event to the JSONL processing history."""
    path = Path(PROCESSED_JSONL)
    path.parent.mkdir(parents=True, exist_ok=True)

    record = dict(event)
    record["_processed_at"] = datetime.now(
        timezone.utc
    ).isoformat()

    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
        f.flush()


def _read_frame(path):
    if not path.exists() or path.stat().st_size == 0:
        return pd.DataFrame()
    last_error = None
    for _ in range(3):
        try:
            return pd.read_csv(path)
        except (pd.errors.EmptyDataError, pd.errors.ParserError, PermissionError) as exc:
            last_error = exc
            time.sleep(0.1)
    raise StorageError(f"Could not read {path.name}: {last_error}")


class CsvStorage(StorageBackend):
    """Local development backend: CSV + JSONL files under DATA_DIR."""

    name = "csv"

    def __init__(self):
        self._event_ids = None
        self._logins = None

    def health(self):
        try:
            config.DATA_DIR.mkdir(parents=True, exist_ok=True)
            writable = os.access(config.DATA_DIR, os.W_OK)
            return {"ok": writable, "backend": self.name, "detail": str(config.DATA_DIR)}
        except OSError as exc:
            return {"ok": False, "backend": self.name, "detail": str(exc)}

    def _load_event_ids(self):
        if self._event_ids is None:
            self._event_ids = set()
            for path in (PROCESSED_JSONL,):
                if not path.exists():
                    continue
                with path.open("r", encoding="utf-8") as f:
                    for line in f:
                        try:
                            event_id = json.loads(line).get("event_id")
                        except (json.JSONDecodeError, AttributeError):
                            continue
                        if event_id:
                            self._event_ids.add(str(event_id))
        return self._event_ids

    def existing_event_ids(self, event_ids):
        known = self._load_event_ids()
        return {str(e) for e in event_ids if str(e) in known}

    def save_result(self, record, batch_id=None):
        try:
            record = dict(record)
            if batch_id:
                record["batch_id"] = batch_id
            features = record.pop("features", None)
            event = raw_event(record)

            append_event(record)
            mark_processed(event)
            if record.get("alert"):
                append_alert({**record, "features": features})
        except (OSError, ValueError) as exc:
            raise StorageError(f"CSV write failed: {exc}") from exc

        self._load_event_ids().add(str(record.get("event_id", "")))
        if self._logins is not None and is_successful_login(record):
            self._logins.setdefault(str(record.get("user_id", "unknown")), []).append(event)

    def record_batch(self, batch_id, blob_uri, event_count, status, error=None):
        entry = {
            "batch_id": batch_id, "blob_uri": blob_uri, "event_count": event_count,
            "status": status, "error": error,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        with config.BATCHES_JSONL.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

    def last_batch(self):
        path = config.BATCHES_JSONL
        if not path.exists() or path.stat().st_size == 0:
            return None
        with path.open("rb") as f:
            f.seek(max(0, path.stat().st_size - 4096))
            lines = f.read().decode("utf-8", errors="ignore").strip().splitlines()
        try:
            return json.loads(lines[-1]) if lines else None
        except json.JSONDecodeError:
            return None

    def _load_logins(self):
        if self._logins is None:
            from .stream_utils import parse_timestamp

            self._logins = {}
            seen = set()
            if PROCESSED_JSONL.exists():
                with PROCESSED_JSONL.open("r", encoding="utf-8") as f:
                    for line in f:
                        try:
                            event = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        if not is_successful_login(event):
                            continue
                        event_id = str(event.get("event_id", ""))
                        if event_id and event_id in seen:
                            continue
                        seen.add(event_id)
                        self._logins.setdefault(str(event.get("user_id", "unknown")), []).append(event)
            for events in self._logins.values():
                events.sort(key=lambda e: (parse_timestamp(e["timestamp"]), str(e.get("event_id", ""))))
        return self._logins

    def login_history(self, user_ids):
        logins = self._load_logins()
        return {str(u): list(logins.get(str(u), [])) for u in user_ids}

    def recent_events(self, since):
        events = self.load_events(limit=None)
        if events.empty or "timestamp" not in events.columns:
            return []
        ts = pd.to_datetime(events["timestamp"], utc=True, errors="coerce", format="ISO8601")
        recent = events[ts >= pd.Timestamp(since)]
        columns = [c for c in EVENT_FIELDS if c in recent.columns]
        return [
            {k: v for k, v in row.items() if not (isinstance(v, float) and pd.isna(v))}
            for row in recent[columns].to_dict("records")
        ]

    def load_alerts(self, limit=None):
        alerts = _read_frame(ALERTS_CSV)
        if limit and len(alerts) > limit and "processed_at" in alerts.columns:
            alerts = alerts.sort_values("processed_at").tail(limit)
        return alerts

    def load_events(self, limit=None):
        events = _read_frame(EVENTS_CSV)
        if limit and len(events) > limit:
            events = events.tail(limit)
        return events

    def stats(self):
        events_total = 0
        if EVENTS_CSV.exists() and EVENTS_CSV.stat().st_size:
            with EVENTS_CSV.open("r", encoding="utf-8") as f:
                events_total = max(0, sum(1 for _ in csv.reader(f)) - 1)
        return summarise_alerts(self.load_alerts(), events_total)


_storage = None


def get_storage():
    """Return the configured backend (one instance per process)."""
    global _storage
    if _storage is None:
        if config.STORAGE_BACKEND == "postgres":
            from .cloud.postgres_storage import PostgresStorage

            _storage = PostgresStorage()
        elif config.STORAGE_BACKEND == "csv":
            _storage = CsvStorage()
        else:
            raise config.ConfigError(f"Unknown STORAGE_BACKEND {config.STORAGE_BACKEND!r}")
    return _storage
