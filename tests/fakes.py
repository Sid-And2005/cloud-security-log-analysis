"""In-memory test doubles for the storage backend and archive."""

import pandas as pd

from src.storage import StorageBackend, StorageError, is_successful_login, summarise_alerts


class MemoryStorage(StorageBackend):
    name = "memory"

    def __init__(self):
        self.events = {}
        self.alerts = {}
        self.batches = {}
        self.fail_saves_after = None
        self.saves = 0

    def health(self):
        return {"ok": True, "backend": self.name}

    def existing_event_ids(self, event_ids):
        return {e for e in event_ids if e in self.events}

    def save_result(self, record, batch_id=None):
        if self.fail_saves_after is not None and self.saves >= self.fail_saves_after:
            raise StorageError("simulated database outage")
        self.saves += 1
        if record["event_id"] in self.events:
            return False
        self.events[record["event_id"]] = {**record, "batch_id": batch_id}
        if record["alert"]:
            key = (record["source_ip"], record["window"])
            previous = self.alerts.get(key)
            count = previous["evaluation_count"] + 1 if previous else 1
            self.alerts[key] = {**record, "evaluation_count": count}
        return True

    def record_batch(self, batch_id, blob_uri, event_count, status, error=None):
        self.batches[batch_id] = {
            "blob_uri": blob_uri, "event_count": event_count, "status": status, "error": error,
        }

    def login_history(self, user_ids):
        out = {u: [] for u in user_ids}
        for e in self.events.values():
            if is_successful_login(e) and e["user_id"] in out:
                out[e["user_id"]].append(e)
        return out

    def recent_events(self, since):
        import pandas as pd

        return [e for e in self.events.values() if pd.Timestamp(e["timestamp"]) >= pd.Timestamp(since)]

    def load_alerts(self, limit=None):
        return pd.DataFrame(list(self.alerts.values()))

    def load_events(self, limit=None):
        return pd.DataFrame(list(self.events.values()))

    def stats(self):
        return summarise_alerts(self.load_alerts(), len(self.events))


class RecordingArchiver:
    name = "recording"

    def __init__(self, fail=False):
        self.batches = {}
        self.fail = fail

    def archive_batch(self, batch_id, events):
        from src.cloud.blob_storage import ArchiveError

        if self.fail:
            raise ArchiveError("simulated blob outage")
        self.batches[batch_id] = list(events)
        return f"memory://raw/{batch_id}.jsonl"

    def health(self):
        return {"ok": not self.fail, "backend": self.name}
