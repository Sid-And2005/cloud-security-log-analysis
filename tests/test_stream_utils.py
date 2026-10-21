import pytest

from src.stream_utils import InvalidEventError, parse_timestamp, validate_event, window_start
from conftest import make_event


def test_timestamps_normalised_to_utc():
    assert parse_timestamp("2026-10-20T15:30:00+05:30").isoformat() == "2026-10-20T10:00:00+00:00"
    assert parse_timestamp("2026-10-20T10:00:00Z").isoformat() == "2026-10-20T10:00:00+00:00"
    # Naive timestamps are treated as UTC (original behaviour).
    assert parse_timestamp("2026-10-20T10:00:00").isoformat() == "2026-10-20T10:00:00+00:00"


def test_window_start_buckets_five_minutes():
    assert window_start("2026-10-20T10:07:59Z") == "2026-10-20T10:05:00+00:00"
    assert window_start("2026-10-20T10:04:59Z") == "2026-10-20T10:00:00+00:00"


def test_validate_event_normalises():
    event = validate_event(make_event(123, "2026-10-20T15:30:00+05:30"))
    assert event["event_id"] == "123"
    assert event["timestamp"] == "2026-10-20T10:00:00+00:00"


@pytest.mark.parametrize("missing", ["event_id", "timestamp", "source_ip"])
def test_validate_event_requires_fields(missing):
    event = make_event("e1", "2026-10-20T10:00:00Z")
    del event[missing]
    with pytest.raises(InvalidEventError):
        validate_event(event)


@pytest.mark.parametrize("bad", ["not-a-date", "", None])
def test_validate_event_rejects_bad_timestamp(bad):
    with pytest.raises(InvalidEventError):
        validate_event(make_event("e1", bad))


def test_validate_event_rejects_non_object():
    with pytest.raises(InvalidEventError):
        validate_event(["not", "a", "dict"])
