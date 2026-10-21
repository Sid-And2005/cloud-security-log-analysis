"""Integration tests against real PostgreSQL and Azurite (the Blob emulator).

Run with `docker compose up -d` and:
    TEST_DATABASE_URL=postgresql://seclog:localdev@127.0.0.1:55432/seclog
    TEST_AZURITE_CONNECTION_STRING=<Azurite connection string, see .env.example>
They are skipped when these variables are absent. CI provides both services.
"""

import json
import os
import uuid

import pytest

from src import config, storage as storage_module
from conftest import make_event

DB_URL = os.getenv("TEST_DATABASE_URL")
AZURITE = os.getenv("TEST_AZURITE_CONNECTION_STRING")

needs_db = pytest.mark.skipif(not DB_URL, reason="TEST_DATABASE_URL not set")
needs_cloud = pytest.mark.skipif(not (DB_URL and AZURITE), reason="PostgreSQL/Azurite not configured")


@pytest.fixture
def pg(monkeypatch, local_data):
    from src.cloud.postgres_storage import PostgresStorage

    monkeypatch.setattr(config, "STORAGE_BACKEND", "postgres")
    monkeypatch.setattr(config, "DATABASE_URL", DB_URL)
    monkeypatch.setattr(config, "PG_AUTH", "password")
    monkeypatch.setattr(config, "PGPASSWORD", None)
    store = PostgresStorage()
    store._run("reset", lambda c: c.execute(
        "DROP TABLE IF EXISTS alerts, security_events, ingestion_batches, schema_migrations CASCADE"
    ))
    assert store.init_schema() == ["001_initial_schema"]
    assert store.init_schema() == []          # idempotent
    monkeypatch.setattr(storage_module, "_storage", store)
    yield store
    store.close()


@pytest.fixture
def blob(monkeypatch):
    from src.cloud.blob_storage import BlobArchiver

    monkeypatch.setattr(config, "ARCHIVE_BACKEND", "azure_blob")
    monkeypatch.setattr(config, "AZURE_STORAGE_CONNECTION_STRING", AZURITE)
    monkeypatch.setattr(config, "AZURE_STORAGE_CONTAINER", f"test-{uuid.uuid4().hex[:12]}")
    archiver = BlobArchiver()
    archiver.container.create_container()
    yield archiver
    archiver.container.delete_container()


def _result(event_id, ts, *, alert=True, priority="HIGH", probability=0.9, **kw):
    return {
        **make_event(event_id, ts, **kw),
        "window": "2026-10-20T10:00:00+00:00", "prediction": 1,
        "anomaly_probability": probability, "detector": "random_forest", "model_version": "m@1",
        "detection_source": "ml+rules" if alert else "none", "alert": alert,
        "threat_types": "Possible request flood", "reason": "evidence", "priority": priority,
        "window_event_count": 1, "features": {"request_count": 1},
        "processed_at": "2026-10-20T10:00:05+00:00", "unexpected_field": "kept",
    }


@needs_db
def test_save_is_idempotent_and_alerts_upsert(pg):
    pg.record_batch("b1", "memory://b1", 3, "archived")
    assert pg.save_result(_result("e1", "2026-10-20T10:00:01Z", probability=0.7), "b1") is True
    assert pg.save_result(_result("e1", "2026-10-20T10:00:01Z"), "b1") is False   # duplicate
    pg.save_result(_result("e2", "2026-10-20T10:00:02Z", priority="CRITICAL", probability=0.6), "b1")

    alerts = pg.load_alerts()
    assert len(alerts) == 1
    row = alerts.iloc[0]
    assert row["priority"] == "CRITICAL" and row["evaluation_count"] == 2
    assert row["peak_probability"] == pytest.approx(0.7)
    assert pg.existing_event_ids(["e1", "e2", "nope"]) == {"e1", "e2"}
    assert pg.stats()["events_total"] == 2
    extra = pg._run("x", lambda c: c.execute(
        "SELECT extra->>'unexpected_field', event_ts::text FROM security_events WHERE event_id='e1'"
    ).fetchone())
    assert extra == ("kept", "2026-10-20 10:00:01+00")      # stored in UTC


@needs_db
def test_login_history_and_recent_events(pg):
    pg.save_result(_result("l1", "2026-10-20T10:00:01Z", alert=False, event_type="LOGIN",
                           endpoint="/login", status_code=200, user_id="alice"))
    pg.save_result(_result("l2", "2026-10-20T10:00:02Z", alert=False, event_type="login",
                           endpoint="/login", status_code=401, user_id="alice"))
    history = pg.login_history(["alice", "bob"])
    assert [e["event_id"] for e in history["alice"]] == ["l1"] and history["bob"] == []
    recent = pg.recent_events("2026-10-20T10:00:02Z")
    assert [e["event_id"] for e in recent] == ["l2"]


@needs_db
def test_health_reports_schema(pg):
    health = pg.health()
    assert health["ok"] and health["schema_version"] == "001_initial_schema"


def test_unavailable_postgres_fails_clearly_and_keeps_files(monkeypatch, local_data):
    from src.cloud.postgres_storage import PostgresStorage
    from src.pipeline import Pipeline
    from src.storage import StorageError
    from fakes import RecordingArchiver

    monkeypatch.setattr(config, "DATABASE_URL", "postgresql://nobody@127.0.0.1:1/none")
    monkeypatch.setattr(config, "PG_AUTH", "password")
    monkeypatch.setattr(config, "PG_CONNECT_TIMEOUT", 1)
    store = PostgresStorage()
    try:
        assert store.health()["ok"] is False
        (local_data / "incoming" / "e1.json").write_text(json.dumps(make_event("e1", "2026-10-20T10:00:00Z")))
        with pytest.raises(StorageError, match="unavailable"):
            Pipeline(store, RecordingArchiver(), None).poll_once()
        assert (local_data / "incoming" / "e1.json").exists()
    finally:
        store.close()


def test_unavailable_blob_storage_keeps_files(monkeypatch, local_data):
    from src.cloud.blob_storage import ArchiveError, BlobArchiver
    from src.pipeline import Pipeline
    from fakes import MemoryStorage

    monkeypatch.setattr(config, "AZURE_STORAGE_CONNECTION_STRING",
                        "DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;AccountKey=a2V5;"
                        "BlobEndpoint=http://127.0.0.1:1/devstoreaccount1;")
    monkeypatch.setattr(config, "BLOB_MAX_RETRIES", 0)
    (local_data / "incoming" / "e1.json").write_text(json.dumps(make_event("e1", "2026-10-20T10:00:00Z")))
    with pytest.raises(ArchiveError):
        Pipeline(MemoryStorage(), BlobArchiver(), None).poll_once()
    assert (local_data / "incoming" / "e1.json").exists()


@needs_cloud
@pytest.mark.skipif(not config.MODEL_PATH.exists(), reason="trained model not present")
def test_end_to_end_ingest_archive_score_persist_display(pg, blob, local_data):
    """Event -> Blob archive -> features -> Random Forest -> PostgreSQL -> dashboard."""
    from streamlit.testing.v1 import AppTest

    from src.detector import load_bundle
    from src.pipeline import Pipeline

    events = [
        make_event(f"bf{i:02d}", f"2026-10-20T10:00:{i:02d}+00:00", ip="192.0.2.50",
                   event_type="login", endpoint="/login", status_code=401, user_id="user3",
                   user_agent="SyntheticAttackSimulator/1.0")
        for i in range(22)
    ]
    for e in events:
        (local_data / "incoming" / f"{e['event_id']}.json").write_text(json.dumps(e))

    pipeline = Pipeline(pg, blob, load_bundle())
    assert pipeline.poll_once() == 22

    # 1. raw events archived unchanged in Blob Storage
    (blob_item,) = list(blob.container.list_blobs())
    lines = blob.container.download_blob(blob_item.name).readall().decode().splitlines()
    assert [json.loads(line) for line in lines] == events

    # 2-4. structured events, Random Forest scores and the alert are in PostgreSQL
    stats = pg.stats()
    assert stats["events_total"] == 22 and stats["alerts_total"] == 1
    alert = pg.load_alerts().iloc[0]
    assert alert["detection_source"] == "ml+rules"
    assert alert["priority"] == "CRITICAL"
    assert alert["anomaly_probability"] > 0.5
    assert alert["model_version"].startswith("random_forest_model_v2@")
    batch = pg.last_batch()
    assert batch["status"] == "processed" and batch["blob_uri"].endswith(".jsonl")

    # 5. the dashboard renders the record from PostgreSQL
    at = AppTest.from_file(str(config.ROOT_DIR / "app.py"), default_timeout=60).run()
    assert not at.exception
    metrics = {m.label: m.value for m in at.metric}
    assert metrics["Events processed"] == "22"
    assert metrics["Alert records"] == "1"
    assert metrics["ML-detected alerts"] == "1"
    table = at.dataframe[0].value
    assert table.iloc[0]["source_ip"] == "192.0.2.50"


def test_dashboard_shows_error_when_postgres_unavailable(monkeypatch, local_data):
    from streamlit.testing.v1 import AppTest

    from src.cloud.postgres_storage import PostgresStorage

    monkeypatch.setattr(config, "STORAGE_BACKEND", "postgres")
    monkeypatch.setattr(config, "DATABASE_URL", "postgresql://nobody@127.0.0.1:1/none")
    monkeypatch.setattr(config, "PG_AUTH", "password")
    monkeypatch.setattr(config, "PG_CONNECT_TIMEOUT", 1)
    store = PostgresStorage()
    monkeypatch.setattr(storage_module, "_storage", store)
    try:
        at = AppTest.from_file(str(config.ROOT_DIR / "app.py"), default_timeout=60).run()
        assert any("Storage backend unavailable" in e.value for e in at.error)
        assert len(at.metric) == 0          # no stale numbers displayed
    finally:
        store.close()


def test_dashboard_renders_local_csv(local_data, monkeypatch):
    from streamlit.testing.v1 import AppTest

    from src.storage import CsvStorage
    from test_storage import result

    monkeypatch.setattr(config, "STORAGE_BACKEND", "csv")
    store = CsvStorage()
    store.save_result(result("e1", "2026-10-20T10:00:01+00:00"))
    monkeypatch.setattr(storage_module, "_storage", store)
    at = AppTest.from_file(str(config.ROOT_DIR / "app.py"), default_timeout=60).run()
    assert not at.exception
    assert {m.label: m.value for m in at.metric}["Alert records"] == "1"
