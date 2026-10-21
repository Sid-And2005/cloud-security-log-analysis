import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# Unit tests never need Azure credentials or a real database.
os.environ.setdefault("APP_ENV", "local")

from src import config, storage  # noqa: E402


def make_event(event_id, ts, ip="10.0.0.1", **overrides):
    event = {
        "event_id": event_id,
        "timestamp": ts,
        "source_ip": ip,
        "user_id": "alice",
        "country": "India",
        "city": "Synthetic",
        "event_type": "request",
        "endpoint": "/home",
        "method": "GET",
        "status_code": 200,
        "response_bytes": 500,
        "user_agent": "pytest",
    }
    event.update(overrides)
    return event


@pytest.fixture
def local_data(tmp_path, monkeypatch):
    """Point every local path at a temporary directory."""
    for name, value in {
        "DATA_DIR": tmp_path,
        "INCOMING_DIR": tmp_path / "incoming",
        "QUARANTINE_DIR": tmp_path / "quarantine",
        "LOCAL_ARCHIVE_DIR": tmp_path / "archive",
        "HEARTBEAT_FILE": tmp_path / "heartbeat.json",
        "EVENTS_CSV": tmp_path / "events.csv",
        "ALERTS_CSV": tmp_path / "alerts.csv",
        "PROCESSED_JSONL": tmp_path / "processed_events.jsonl",
        "BATCHES_JSONL": tmp_path / "ingestion_batches.jsonl",
    }.items():
        monkeypatch.setattr(config, name, value)
    for name in ("EVENTS_CSV", "ALERTS_CSV", "PROCESSED_JSONL"):
        monkeypatch.setattr(storage, name, getattr(config, name))
    monkeypatch.setattr(config, "BATCH_LINGER_SECONDS", 0)
    (tmp_path / "incoming").mkdir()
    monkeypatch.setattr(storage, "_storage", None)
    return tmp_path
