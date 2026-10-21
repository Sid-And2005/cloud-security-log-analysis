"""Raw log archival.

Raw events are archived in batches (one JSONL blob per batch) *before* they
are processed or deleted from the incoming directory. Blob Storage is the
long-term raw archive; PostgreSQL holds the structured records.

Layout: ``<prefix>/YYYY/MM/DD/HH/<batch_id>.jsonl``
"""

import hashlib
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path

from .. import config

log = logging.getLogger(__name__)


class ArchiveError(RuntimeError):
    """Raw logs could not be archived; the source files must be kept."""


def serialize_batch(events):
    """One compact JSON object per line; keys and values are unchanged."""
    return "".join(
        json.dumps(event, ensure_ascii=False, separators=(",", ":"), default=str) + "\n"
        for event in events
    ).encode("utf-8")


def blob_name(batch_id, when=None, prefix=None):
    when = when or datetime.now(timezone.utc)
    prefix = (prefix if prefix is not None else config.BLOB_PREFIX).strip("/")
    path = f"{when:%Y/%m/%d/%H}/{batch_id}.jsonl"
    return f"{prefix}/{path}" if prefix else path


class LocalArchiver:
    """Development stand-in for Blob Storage using the same layout on disk."""

    name = "local"

    def __init__(self, root=None):
        self.root = Path(root or config.LOCAL_ARCHIVE_DIR)

    def archive_batch(self, batch_id, events):
        data = serialize_batch(events)
        path = self.root / blob_name(batch_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            # "x" refuses to overwrite an existing archive file.
            with path.open("xb") as f:
                f.write(data)
        except FileExistsError:
            if path.read_bytes() != data:
                raise ArchiveError(f"Archive {path} already exists with different content")
        except OSError as exc:
            raise ArchiveError(f"Local archive write failed: {exc}") from exc
        return path.resolve().as_uri()

    def health(self):
        try:
            self.root.mkdir(parents=True, exist_ok=True)
            return {"ok": True, "backend": self.name, "detail": str(self.root)}
        except OSError as exc:
            return {"ok": False, "backend": self.name, "detail": str(exc)}


class BlobArchiver:
    """Azure Blob Storage archive authenticated with the managed identity."""

    name = "azure_blob"

    def __init__(self, container_client=None):
        self._container = container_client

    @property
    def container(self):
        if self._container is None:
            from azure.storage.blob import BlobServiceClient

            options = {"retry_total": config.BLOB_MAX_RETRIES, "connection_timeout": 10}
            if config.AZURE_STORAGE_CONNECTION_STRING:
                # Local Azurite emulator only (rejected by validate_settings in Azure).
                service = BlobServiceClient.from_connection_string(
                    config.AZURE_STORAGE_CONNECTION_STRING, **options
                )
            else:
                from .credentials import get_credential

                service = BlobServiceClient(
                    config.AZURE_STORAGE_ACCOUNT_URL, credential=get_credential(), **options
                )
            self._container = service.get_container_client(config.AZURE_STORAGE_CONTAINER)
        return self._container

    def archive_batch(self, batch_id, events):
        from azure.core.exceptions import AzureError, ResourceExistsError
        from azure.storage.blob import ContentSettings

        data = serialize_batch(events)
        name = blob_name(batch_id)
        blob = self.container.get_blob_client(name)
        md5 = hashlib.md5(data).digest()
        started = time.monotonic()

        try:
            blob.upload_blob(
                data,
                overwrite=False,
                content_settings=ContentSettings(
                    content_type="application/x-ndjson", content_md5=bytearray(md5)
                ),
                metadata={"batch_id": batch_id, "event_count": str(len(events))},
            )
        except ResourceExistsError:
            # A retry after a lost response: accept only an identical blob.
            existing = blob.get_blob_properties().content_settings.content_md5
            if existing is None or bytes(existing) != md5:
                raise ArchiveError(f"Blob {name} already exists with different content")
        except AzureError as exc:
            log.error(
                "Blob upload failed",
                extra={
                    "operation": "blob_upload", "batch_id": batch_id,
                    "count": len(events), "error_type": exc.__class__.__name__,
                },
            )
            raise ArchiveError(f"Blob upload failed for {name}: {exc.__class__.__name__}: {exc}") from exc

        log.info(
            "Archived raw batch",
            extra={
                "operation": "blob_upload", "batch_id": batch_id, "count": len(events),
                "blob_uri": blob.url,
                "duration_ms": round((time.monotonic() - started) * 1000, 1),
            },
        )
        return blob.url

    def health(self):
        try:
            exists = self.container.exists()
            return {
                "ok": bool(exists),
                "backend": self.name,
                "detail": "container reachable" if exists else "container not found",
            }
        except Exception as exc:  # health checks report, never raise
            return {"ok": False, "backend": self.name, "detail": str(exc).splitlines()[0]}


_archiver = None


def get_archiver():
    global _archiver
    if _archiver is None:
        if config.ARCHIVE_BACKEND == "azure_blob":
            _archiver = BlobArchiver()
        elif config.ARCHIVE_BACKEND == "local":
            _archiver = LocalArchiver()
        else:
            raise config.ConfigError(f"Unknown ARCHIVE_BACKEND {config.ARCHIVE_BACKEND!r}")
    return _archiver
