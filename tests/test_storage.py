import pandas as pd
import pytest

from src import storage
from src.storage import CsvStorage, infer_detection_source, summarise_alerts
from conftest import make_event


def result(event_id, ts, *, alert=True, source="ml+rules", priority="HIGH", window="2026-10-20T10:00:00+00:00", **kw):
    return {
        **make_event(event_id, ts, **kw),
        "window": window, "prediction": int(source.startswith("ml")),
        "anomaly_probability": 0.9, "detector": "random_forest", "model_version": "m@1",
        "detection_source": source if alert else "none", "alert": alert,
        "threat_types": "Possible request flood" if alert else "", "reason": "r",
        "priority": priority if alert else "NONE", "window_event_count": 1,
        "features": {"request_count": 1}, "processed_at": ts,
    }


def test_csv_storage_round_trip_and_alert_dedup(local_data):
    s = CsvStorage()
    s.save_result(result("e1", "2026-10-20T10:00:01+00:00", priority="MEDIUM"), batch_id="b1")
    s.save_result(result("e2", "2026-10-20T10:00:02+00:00", priority="HIGH"), batch_id="b1")
    s.save_result(result("e3", "2026-10-20T10:00:03+00:00", alert=False), batch_id="b1")

    alerts = s.load_alerts()
    assert len(alerts) == 1  # one alert per (source_ip, window), latest state wins
    assert alerts.iloc[0]["priority"] == "HIGH"
    assert len(s.load_events()) == 3
    assert s.existing_event_ids(["e1", "e3", "zzz"]) == {"e1", "e3"}
    stats = s.stats()
    assert stats["events_total"] == 3 and stats["alerts_total"] == 1
    assert stats["by_source"]["ml+rules"] == 1


def test_existing_ids_survive_restart(local_data):
    CsvStorage().save_result(result("e1", "2026-10-20T10:00:01+00:00"))
    assert CsvStorage().existing_event_ids(["e1"]) == {"e1"}


def test_login_history_is_per_user_and_chronological(local_data):
    s = CsvStorage()
    for event_id, ts, user, status in [
        ("l2", "2026-10-20T10:00:02+00:00", "alice", 200),
        ("l1", "2026-10-20T10:00:01+00:00", "alice", 200),
        ("lf", "2026-10-20T10:00:03+00:00", "alice", 401),
        ("lb", "2026-10-20T10:00:04+00:00", "bob", 200),
    ]:
        s.save_result(result(event_id, ts, alert=False, user_id=user, event_type="login",
                             endpoint="/login", status_code=status))
    history = CsvStorage().login_history(["alice"])
    assert [e["event_id"] for e in history["alice"]] == ["l1", "l2"]
    assert "bob" not in history


def test_recent_events_for_window_restore(local_data):
    s = CsvStorage()
    s.save_result(result("old", "2026-10-20T09:00:00+00:00", alert=False))
    s.save_result(result("new", "2026-10-20T10:00:00+00:00", alert=False))
    recent = s.recent_events("2026-10-20T09:55:00+00:00")
    assert [e["event_id"] for e in recent] == ["new"]
    assert "anomaly_probability" not in recent[0]


@pytest.mark.parametrize("row, expected", [
    ({"detection_source": "rules"}, "rules"),
    ({"threat_types": "ML-only anomaly"}, "ml"),
    ({"threat_types": "Possible request flood", "prediction": 1}, "ml+rules"),
    ({"threat_types": "Possible request flood", "prediction": "0"}, "rules"),
])
def test_infer_detection_source_for_legacy_rows(row, expected):
    assert infer_detection_source(row) == expected


def test_summarise_alerts_counts():
    alerts = pd.DataFrame([
        {"priority": "critical", "detection_source": "rules"},
        {"priority": "HIGH", "detection_source": "ml"},
    ])
    stats = summarise_alerts(alerts, 10)
    assert stats["by_severity"]["CRITICAL"] == 1
    assert stats["by_source"] == {"ml": 1, "ml+rules": 0, "rules": 1}


def test_get_storage_selects_backend(local_data, monkeypatch):
    from src import config

    monkeypatch.setattr(config, "STORAGE_BACKEND", "csv")
    assert storage.get_storage().name == "csv"
    monkeypatch.setattr(storage, "_storage", None)
    monkeypatch.setattr(config, "STORAGE_BACKEND", "postgres")
    assert storage.get_storage().name == "postgres"  # constructed lazily, no connection yet


def test_postgres_entra_auth_fetches_a_fresh_token_per_connection(monkeypatch):
    from src import config
    from src.cloud import credentials, postgres_storage

    tokens = iter(["token-1", "token-2"])
    monkeypatch.setattr(config, "PG_AUTH", "entra")
    monkeypatch.setattr(credentials, "postgres_access_token", lambda: next(tokens))
    assert postgres_storage._connection_kwargs() == {"password": "token-1"}
    assert postgres_storage._connection_kwargs() == {"password": "token-2"}


def test_postgres_conninfo_from_parts_enforces_settings(monkeypatch):
    from src import config
    from src.cloud import postgres_storage

    monkeypatch.setattr(config, "DATABASE_URL", None)
    monkeypatch.setattr(config, "PGHOST", "db.example")
    monkeypatch.setattr(config, "PGUSER", "id-app")
    monkeypatch.setattr(config, "PGSSLMODE", "require")
    info = postgres_storage._conninfo()
    assert "sslmode=require" in info and "host=db.example" in info
    assert "TimeZone=UTC" in info and "password" not in info
