import json

import pytest

from src.cloud.blob_storage import ArchiveError, LocalArchiver
from src.pipeline import Pipeline
from src.storage import StorageError
from conftest import make_event
from fakes import MemoryStorage, RecordingArchiver
from test_detector import FakeModel, bundle_for


def write(incoming, event, name=None):
    path = incoming / (name or f"{event['timestamp'].replace(':', '')}_{event['event_id']}.json")
    path.write_text(json.dumps(event))
    return path


@pytest.fixture
def pipe(local_data):
    return Pipeline(MemoryStorage(), RecordingArchiver(), bundle_for(FakeModel(anomaly_score=0.1)),
                    incoming_dir=local_data / "incoming", quarantine_dir=local_data / "quarantine")


def test_archive_then_persist_then_delete(pipe, local_data):
    events = [make_event(f"e{i}", f"2026-10-20T10:00:0{i}+00:00") for i in range(3)]
    for e in events:
        write(local_data / "incoming", e)
    assert pipe.poll_once() == 3
    (batch_id, archived), = pipe.archiver.batches.items()
    assert archived == events                       # raw originals, untouched
    assert set(pipe.storage.events) == {"e0", "e1", "e2"}
    assert pipe.storage.batches[batch_id]["status"] == "processed"
    assert all(e["batch_id"] == batch_id for e in pipe.storage.events.values())
    assert not list((local_data / "incoming").glob("*.json"))


def test_archive_failure_keeps_files_and_processes_nothing(pipe, local_data):
    pipe.archiver.fail = True
    write(local_data / "incoming", make_event("e1", "2026-10-20T10:00:00Z"))
    with pytest.raises(ArchiveError):
        pipe.poll_once()
    assert len(list((local_data / "incoming").glob("*.json"))) == 1
    assert pipe.storage.events == {}


def test_database_failure_keeps_unprocessed_files_and_state(pipe, local_data):
    for i in range(3):
        write(local_data / "incoming", make_event(f"e{i}", f"2026-10-20T10:00:0{i}Z"))
    pipe.storage.fail_saves_after = 1
    with pytest.raises(StorageError):
        pipe.poll_once()
    remaining = sorted(p.name for p in (local_data / "incoming").glob("*.json"))
    assert len(remaining) == 2 and set(pipe.storage.events) == {"e0"}
    # The failed event must not have entered the in-memory window.
    assert [eid for _, eid, _ in pipe.windows["10.0.0.1"]] == ["e0"]
    assert list(pipe.storage.batches.values())[0]["status"] == "partial"

    pipe.storage.fail_saves_after = None            # database recovers
    assert pipe.poll_once() == 2
    assert set(pipe.storage.events) == {"e0", "e1", "e2"}
    assert pipe.storage.events["e2"]["window_event_count"] == 3  # no double counting


def test_duplicates_are_skipped(pipe, local_data):
    event = make_event("dup", "2026-10-20T10:00:00Z")
    write(local_data / "incoming", event, "a.json")
    write(local_data / "incoming", event, "b.json")
    pipe.poll_once()
    write(local_data / "incoming", event, "c.json")
    pipe.poll_once()
    assert pipe.storage.saves == 1
    assert not list((local_data / "incoming").glob("*.json"))


def test_invalid_events_are_quarantined_not_deleted(pipe, local_data):
    (local_data / "incoming" / "broken.json").write_text("{nope")
    bad = make_event("x", "2026-10-20T10:00:00Z")
    del bad["source_ip"]
    write(local_data / "incoming", bad, "nosrc.json")
    pipe.poll_once()
    quarantined = sorted(p.name for p in (local_data / "quarantine").iterdir())
    assert quarantined == ["broken.json", "broken.json.error.txt", "nosrc.json", "nosrc.json.error.txt"]
    assert pipe.archiver.batches == {}


def test_out_of_order_events_use_only_their_own_window(pipe, local_data):
    write(local_data / "incoming", make_event("late", "2026-10-20T10:20:00Z"))
    pipe.poll_once()
    write(local_data / "incoming", make_event("early", "2026-10-20T10:19:00Z"))
    pipe.poll_once()
    # The earlier event's window must not include the later one.
    assert pipe.storage.events["early"]["window_event_count"] == 1
    write(local_data / "incoming", make_event("after", "2026-10-20T10:21:00Z"))
    pipe.poll_once()
    assert pipe.storage.events["after"]["window_event_count"] == 3


def test_old_events_are_pruned_from_windows(pipe, local_data):
    write(local_data / "incoming", make_event("a", "2026-10-20T10:00:00Z"))
    pipe.poll_once()
    write(local_data / "incoming", make_event("b", "2026-10-20T10:30:00Z"))
    pipe.poll_once()
    assert [eid for _, eid, _ in pipe.windows["10.0.0.1"]] == ["b"]
    assert pipe.storage.events["b"]["window_event_count"] == 1


def test_restart_restores_windows(local_data):
    storage = MemoryStorage()
    first = Pipeline(storage, RecordingArchiver(), bundle_for(FakeModel(anomaly_score=0.1)),
                     incoming_dir=local_data / "incoming", quarantine_dir=local_data / "quarantine")
    from datetime import datetime, timezone, timedelta

    now = datetime.now(timezone.utc)
    for i in range(3):
        write(local_data / "incoming", make_event(f"e{i}", (now - timedelta(seconds=10 - i)).isoformat()))
    first.poll_once()

    second = Pipeline(storage, RecordingArchiver(), first.bundle,
                      incoming_dir=local_data / "incoming", quarantine_dir=local_data / "quarantine")
    assert second.restore_windows() == 3
    write(local_data / "incoming", make_event("e3", now.isoformat()))
    second.poll_once()
    assert storage.events["e3"]["window_event_count"] == 4


def test_successful_logins_feed_history(pipe, local_data):
    for i in range(4):
        write(local_data / "incoming", make_event(
            f"l{i}", f"2026-10-20T0{i}:00:00Z", event_type="login", endpoint="/login",
            status_code=200, country="India"))
    pipe.poll_once()
    write(local_data / "incoming", make_event(
        "l9", "2026-10-20T09:00:00Z", event_type="login", endpoint="/login",
        status_code=200, country="Brazil"))
    pipe.poll_once()
    record = pipe.storage.events["l9"]
    assert record["features"]["country_mismatches"] == 1
    assert "Unusual login country" in record["threat_types"]


def test_high_severity_alert_logs_once_per_escalation(pipe, local_data, caplog):
    pipe.bundle = bundle_for(FakeModel(anomaly_score=0.1))
    for i in range(65):
        write(local_data / "incoming", make_event(f"f{i:03d}", f"2026-10-20T10:00:{i % 60:02d}.{i:03d}Z"))
    with caplog.at_level("WARNING"):
        pipe.poll_once()
    threat_logs = [r for r in caplog.records if getattr(r, "operation", "") == "threat_alert"]
    assert len(threat_logs) == 1 and threat_logs[0].severity == "HIGH"


def test_local_archiver_layout(local_data):
    p = Pipeline(MemoryStorage(), LocalArchiver(local_data / "archive"), bundle_for(FakeModel()),
                 incoming_dir=local_data / "incoming", quarantine_dir=local_data / "quarantine")
    write(local_data / "incoming", make_event("e1", "2026-10-20T10:00:00Z"))
    p.poll_once()
    files = list((local_data / "archive").rglob("*.jsonl"))
    assert len(files) == 1 and json.loads(files[0].read_text())["event_id"] == "e1"


def test_small_batches_linger_until_old_enough(pipe, local_data, monkeypatch):
    import os
    import time

    from src import config

    monkeypatch.setattr(config, "BATCH_LINGER_SECONDS", 5)
    path = write(local_data / "incoming", make_event("e1", "2026-10-20T10:00:00Z"))
    assert pipe.poll_once() == 0 and path.exists()          # too fresh: wait
    old = time.time() - 10
    os.utime(path, (old, old))
    assert pipe.poll_once() == 1 and not path.exists()       # old enough: process
