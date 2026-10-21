import importlib
import json
import logging

import pytest

from src import config, logging_setup

AZURE_ENV = {
    "APP_ENV": "azure",
    "PGHOST": "seclog-pg.postgres.database.azure.com",
    "PGUSER": "id-seclog-app",
    "AZURE_STORAGE_ACCOUNT_URL": "https://example.blob.core.windows.net",
    "AZURE_CLIENT_ID": "00000000-0000-0000-0000-000000000000",
}


@pytest.fixture
def reload_config(monkeypatch):
    """Reload src.config under a controlled environment, restore afterwards."""
    for key in list(AZURE_ENV) + ["STORAGE_BACKEND", "ARCHIVE_BACKEND", "PGSSLMODE",
                                  "AZURE_STORAGE_CONNECTION_STRING", "DATABASE_URL", "PG_AUTH"]:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr("dotenv.load_dotenv", lambda *a, **k: False)

    def _reload(**env):
        for key, value in env.items():
            monkeypatch.setenv(key, value)
        return importlib.reload(config)

    yield _reload
    monkeypatch.undo()
    importlib.reload(config)


def test_local_defaults_need_no_cloud_settings(reload_config):
    cfg = reload_config()
    assert cfg.STORAGE_BACKEND == "csv" and cfg.ARCHIVE_BACKEND == "local"
    cfg.validate_settings()


def test_complete_azure_settings_validate(reload_config):
    cfg = reload_config(**AZURE_ENV)
    assert cfg.STORAGE_BACKEND == "postgres"
    assert cfg.ARCHIVE_BACKEND == "azure_blob"
    assert cfg.PG_AUTH == "entra" and cfg.PGSSLMODE == "require"
    assert cfg.REQUIRE_MODEL is True
    cfg.validate_settings()


@pytest.mark.parametrize("override, message", [
    ({"PGHOST": ""}, "PGHOST"),
    ({"AZURE_STORAGE_ACCOUNT_URL": ""}, "AZURE_STORAGE_ACCOUNT_URL"),
    ({"STORAGE_BACKEND": "csv"}, "STORAGE_BACKEND=postgres"),
    ({"PGSSLMODE": "disable"}, "PGSSLMODE"),
    ({"AZURE_STORAGE_CONNECTION_STRING": "UseDevelopmentStorage=true"}, "managed identity"),
])
def test_incomplete_azure_settings_fail_clearly(reload_config, override, message):
    cfg = reload_config(**{**AZURE_ENV, **override})
    with pytest.raises(cfg.ConfigError, match=message):
        cfg.validate_settings()


def test_describe_never_contains_passwords(reload_config):
    cfg = reload_config(STORAGE_BACKEND="postgres", PGHOST="h", PGUSER="u",
                        PGPASSWORD="SuperSecret123", PG_AUTH="password")
    assert "SuperSecret123" not in json.dumps(cfg.describe())


@pytest.mark.parametrize("text", [
    "password=hunter2 failed",
    "postgresql://app:hunter2@db:5432/x",
    "AccountKey=hunter2;EndpointSuffix",
    "Authorization: Bearer hunter2",
    "url?sv=1&sig=hunter2&se=2",
])
def test_redaction(text):
    assert "hunter2" not in logging_setup.redact(text)


def test_json_log_contains_context_fields():
    record = logging.LogRecord("x", logging.WARNING, __file__, 1, "Threat alert password=abc", None, None)
    record.operation = "threat_alert"
    record.event_id = "e1"
    payload = json.loads(logging_setup.JsonFormatter().format(record))
    assert payload["level"] == "WARNING"
    assert payload["operation"] == "threat_alert"
    assert payload["event_id"] == "e1"
    assert "abc" not in payload["msg"]
