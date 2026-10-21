"""Durable ingestion pipeline used by consumer.py.

For each poll of the incoming directory:

1. read and validate up to BATCH_SIZE event files (invalid -> quarantine/)
2. archive the raw batch (Blob Storage in Azure)          - before any deletion
3. record the batch in storage
4. per event, in timestamp order: skip duplicates, build the five-minute IP
   window, score it (Random Forest + supplementary rules), persist the event
   and alert in one transaction
5. delete an incoming file only after its event has been persisted

If archiving or persistence fails, the remaining files stay in the incoming
directory and are retried on the next poll, so events are never lost.
"""

import bisect
import json
import logging
import os
import shutil
import time
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import config
from .cloud.blob_storage import ArchiveError
from .detector import SEVERITY_ORDER, evaluate_window
from .storage import StorageError, is_successful_login
from .stream_utils import InvalidEventError, parse_timestamp, validate_event

log = logging.getLogger(__name__)


def new_batch_id():
    return f"{datetime.now(timezone.utc):%Y%m%dT%H%M%S%fZ}-{uuid.uuid4().hex[:8]}"


class Pipeline:
    def __init__(self, storage, archiver, bundle=None, incoming_dir=None, quarantine_dir=None):
        self.storage = storage
        self.archiver = archiver
        self.bundle = bundle
        self.incoming_dir = Path(incoming_dir or config.INCOMING_DIR)
        self.quarantine_dir = Path(quarantine_dir or config.QUARANTINE_DIR)
        self.window = timedelta(minutes=config.WINDOW_MINUTES)
        self.retention = self.window + timedelta(seconds=config.ALLOWED_LATENESS_SECONDS)

        # ip -> sorted list of (timestamp, event_id, event)
        self.windows = defaultdict(list)
        self.max_seen = None
        # user_id -> chronological successful logins (lazy-loaded from storage)
        self.logins = {}
        # (ip, window) -> highest severity already logged as a threat alert
        self._notified = {}
        self.processed_total = 0
        self.last_batch_id = None

    # -- state -------------------------------------------------------------------
    def restore_windows(self, now=None):
        """Rebuild recent IP windows from storage after a restart."""
        now = now or datetime.now(timezone.utc)
        events = self.storage.recent_events(now - self.retention)
        for event in events:
            self._remember(event)
        log.info(
            "Restored %d recent events into IP windows", len(events),
            extra={"operation": "restore_windows", "count": len(events)},
        )
        return len(events)

    def _remember(self, event):
        ts = parse_timestamp(event["timestamp"])
        bisect.insort(
            self.windows[event["source_ip"]],
            (ts, str(event["event_id"]), event),
            key=lambda e: (e[0], e[1]),
        )
        if self.max_seen is None or ts > self.max_seen:
            self.max_seen = ts
        self._prune()

    def _prune(self):
        cutoff = self.max_seen - self.retention
        for ip in list(self.windows):
            entries = self.windows[ip]
            keep = bisect.bisect_left(entries, cutoff, key=lambda e: e[0])
            if keep:
                del entries[:keep]
            if not entries:
                del self.windows[ip]

    def window_events(self, event):
        ts = parse_timestamp(event["timestamp"])
        cutoff = ts - self.window
        events = [
            e for t, _, e in self.windows.get(event["source_ip"], [])
            if cutoff <= t <= ts and str(e["event_id"]) != str(event["event_id"])
        ]
        return events + [event]

    def _history_for(self, window):
        users = {
            str(e.get("user_id", "unknown")) for e in window if is_successful_login(e)
        }
        missing = [u for u in users if u not in self.logins]
        if missing:
            self.logins.update(self.storage.login_history(missing))
        return [e for u in users for e in self.logins.get(u, [])]

    # -- processing --------------------------------------------------------------
    def process_event(self, event, batch_id=None):
        window = self.window_events(event)
        history = self._history_for(window)
        record = evaluate_window(event, window, history, self.bundle)

        # Raises StorageError; in-memory state is only updated after success.
        self.storage.save_result(record, batch_id)

        self._remember(event)
        if is_successful_login(event):
            user = str(event.get("user_id", "unknown"))
            self.logins.setdefault(user, []).append(event)
            self.logins[user].sort(
                key=lambda e: (parse_timestamp(e["timestamp"]), str(e.get("event_id", "")))
            )
        self.processed_total += 1
        self._log_result(record, batch_id)
        return record

    def _log_result(self, record, batch_id):
        level = logging.INFO if record["alert"] else logging.DEBUG
        log.log(
            level,
            "%s | %s | score=%.3f | %s | %s",
            "ALERT" if record["alert"] else "OK", record["source_ip"],
            record["anomaly_probability"], record["priority"], record["reason"],
            extra={
                "operation": "event_processed", "event_id": record["event_id"],
                "batch_id": batch_id, "source_ip": record["source_ip"],
                "severity": record["priority"], "detection_source": record["detection_source"],
                "anomaly_probability": record["anomaly_probability"],
            },
        )

        # One notification-worthy log line per window each time it escalates
        # to HIGH/CRITICAL; Azure Monitor alerts on these records.
        if record["alert"] and SEVERITY_ORDER[record["priority"]] >= SEVERITY_ORDER["HIGH"]:
            key = (record["source_ip"], record["window"])
            previous = self._notified.get(key, "NONE")
            if SEVERITY_ORDER[record["priority"]] > SEVERITY_ORDER[previous]:
                self._notified[key] = record["priority"]
                log.warning(
                    "Threat alert: %s from %s (%s)",
                    record["threat_types"], record["source_ip"], record["priority"],
                    extra={
                        "operation": "threat_alert", "event_id": record["event_id"],
                        "source_ip": record["source_ip"], "severity": record["priority"],
                        "detection_source": record["detection_source"],
                        "anomaly_probability": record["anomaly_probability"],
                        "model_version": record["model_version"],
                    },
                )
            if len(self._notified) > 10_000:
                self._notified.clear()

    def _quarantine(self, path, reason):
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        target = self.quarantine_dir / path.name
        shutil.move(str(path), target)
        target.with_suffix(target.suffix + ".error.txt").write_text(reason, encoding="utf-8")
        log.error(
            "Quarantined %s: %s", path.name, reason,
            extra={"operation": "quarantine", "status": "invalid"},
        )

    def poll_once(self):
        """Process one batch. Returns the number of files handled.

        Raises ArchiveError/StorageError when the batch must be retried later.
        """
        files = sorted(self.incoming_dir.glob("*.json"))[: config.BATCH_SIZE]
        if not files:
            return 0
        if len(files) < config.BATCH_SIZE and config.BATCH_LINGER_SECONDS > 0:
            try:
                oldest = min(path.stat().st_mtime for path in files)
            except FileNotFoundError:
                return 0
            if time.time() - oldest < config.BATCH_LINGER_SECONDS:
                return 0  # let the batch fill up a little longer

        raw, valid = [], []
        for path in files:
            try:
                original = json.loads(path.read_text(encoding="utf-8"))
                valid.append((path, validate_event(original)))
                raw.append(original)
            except (json.JSONDecodeError, UnicodeDecodeError, InvalidEventError) as exc:
                self._quarantine(path, f"{exc.__class__.__name__}: {exc}")
            except FileNotFoundError:
                continue

        if not valid:
            return len(files)

        batch_id = new_batch_id()
        # Archive the untouched originals before anything can delete them.
        blob_uri = self.archiver.archive_batch(batch_id, raw)
        self.storage.record_batch(batch_id, blob_uri, len(valid), "archived")
        self.last_batch_id = batch_id

        already = self.storage.existing_event_ids([e["event_id"] for _, e in valid])
        valid.sort(key=lambda item: (parse_timestamp(item[1]["timestamp"]), item[0].name))

        handled = len(files) - len(valid)
        duplicates = 0
        seen = set()
        try:
            for path, event in valid:
                event_id = event["event_id"]
                if event_id in already or event_id in seen:
                    duplicates += 1
                    log.info(
                        "Skipping duplicate event", extra={
                            "operation": "duplicate_event", "event_id": event_id,
                            "batch_id": batch_id,
                        },
                    )
                else:
                    try:
                        self.process_event(event, batch_id)
                    except StorageError:
                        raise
                    except Exception as exc:  # a poison event must not block the queue
                        log.exception(
                            "Event processing failed", extra={
                                "operation": "event_failed", "event_id": event_id,
                                "batch_id": batch_id,
                            },
                        )
                        self._quarantine(path, f"processing error: {exc!r}")
                        handled += 1
                        continue
                seen.add(event_id)
                path.unlink(missing_ok=True)
                handled += 1
        except StorageError as exc:
            try:
                self.storage.record_batch(batch_id, blob_uri, len(valid), "partial", str(exc)[:500])
            except StorageError:
                pass
            raise

        self.storage.record_batch(batch_id, blob_uri, len(valid), "processed")
        log.info(
            "Batch processed", extra={
                "operation": "batch_processed", "batch_id": batch_id,
                "count": len(valid) - duplicates, "blob_uri": blob_uri, "status": "processed",
            },
        )
        return handled

    # -- liveness ----------------------------------------------------------------
    def write_heartbeat(self, path=None, status="running", error=None):
        path = Path(path or config.HEARTBEAT_FILE)
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "pid": os.getpid(),
            "status": status,
            "processed_total": self.processed_total,
            "last_batch_id": self.last_batch_id,
            "error": error,
        }
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload), encoding="utf-8")
        os.replace(tmp, path)


__all__ = ["Pipeline", "ArchiveError", "StorageError", "new_batch_id"]
