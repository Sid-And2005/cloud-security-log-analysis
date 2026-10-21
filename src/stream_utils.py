import json
from datetime import timezone
from pathlib import Path

import pandas as pd

# Fields without which an event cannot be windowed or de-duplicated. The
# remaining schema fields are optional and receive defaults in features.py.
REQUIRED_FIELDS = ("event_id", "timestamp", "source_ip")


class InvalidEventError(ValueError):
    """The event cannot be processed and should be quarantined."""


def parse_timestamp(value):
    """Parse an ISO-8601 timestamp into an aware UTC datetime."""
    ts = pd.Timestamp(value)
    if pd.isna(ts):
        raise InvalidEventError(f"Invalid timestamp: {value!r}")
    ts = ts.to_pydatetime()
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)


def read_event(path: Path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def validate_event(event):
    """Check the minimum schema and normalise the timestamp to UTC ISO-8601."""
    if not isinstance(event, dict):
        raise InvalidEventError("Event must be a JSON object")

    missing = [
        field for field in REQUIRED_FIELDS
        if event.get(field) in (None, "")
    ]
    if missing:
        raise InvalidEventError(f"Missing required field(s): {', '.join(missing)}")

    try:
        ts = parse_timestamp(event["timestamp"])
    except (ValueError, TypeError) as exc:
        raise InvalidEventError(f"Invalid timestamp {event['timestamp']!r}") from exc

    normalised = dict(event)
    normalised["event_id"] = str(event["event_id"])
    normalised["source_ip"] = str(event["source_ip"])
    normalised["timestamp"] = ts.isoformat()
    return normalised


def window_start(timestamp, minutes=5):
    ts = parse_timestamp(timestamp)
    minute = (ts.minute // minutes) * minutes
    return ts.replace(minute=minute, second=0, microsecond=0).isoformat()
