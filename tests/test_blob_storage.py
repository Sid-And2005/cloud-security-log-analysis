import hashlib
import json
from unittest import mock

import pytest
from azure.core.exceptions import ResourceExistsError, ServiceRequestError

from src.cloud.blob_storage import ArchiveError, BlobArchiver, LocalArchiver, blob_name, serialize_batch

EVENTS = [{"event_id": "a", "msg": "héllo"}, {"event_id": "b", "nested": {"x": 1}}]


def test_serialize_batch_is_lossless_jsonl():
    lines = serialize_batch(EVENTS).decode("utf-8").splitlines()
    assert [json.loads(line) for line in lines] == EVENTS


def test_blob_name_is_date_partitioned():
    from datetime import datetime, timezone

    when = datetime(2026, 10, 21, 7, 5, tzinfo=timezone.utc)
    assert blob_name("b1", when, prefix="raw") == "raw/2026/10/21/07/b1.jsonl"


def make_archiver():
    container = mock.MagicMock()
    blob = container.get_blob_client.return_value
    blob.url = "https://acct.blob.core.windows.net/raw-logs/raw/x.jsonl"
    return BlobArchiver(container_client=container), blob


def test_upload_never_overwrites_and_returns_uri():
    archiver, blob = make_archiver()
    uri = archiver.archive_batch("b1", EVENTS)
    assert uri == blob.url
    kwargs = blob.upload_blob.call_args.kwargs
    assert kwargs["overwrite"] is False
    assert kwargs["metadata"] == {"batch_id": "b1", "event_count": "2"}


def test_retry_of_identical_blob_is_accepted():
    archiver, blob = make_archiver()
    blob.upload_blob.side_effect = ResourceExistsError("exists")
    blob.get_blob_properties.return_value.content_settings.content_md5 = bytearray(
        hashlib.md5(serialize_batch(EVENTS)).digest()
    )
    assert archiver.archive_batch("b1", EVENTS) == blob.url


def test_existing_blob_with_different_content_is_an_error():
    archiver, blob = make_archiver()
    blob.upload_blob.side_effect = ResourceExistsError("exists")
    blob.get_blob_properties.return_value.content_settings.content_md5 = bytearray(b"0" * 16)
    with pytest.raises(ArchiveError, match="different content"):
        archiver.archive_batch("b1", EVENTS)


def test_network_failure_raises_archive_error():
    archiver, blob = make_archiver()
    blob.upload_blob.side_effect = ServiceRequestError("connection reset")
    with pytest.raises(ArchiveError, match="upload failed"):
        archiver.archive_batch("b1", EVENTS)


def test_local_archiver_refuses_to_overwrite(tmp_path):
    archiver = LocalArchiver(tmp_path)
    uri = archiver.archive_batch("b1", EVENTS)
    assert uri.startswith("file://")
    assert archiver.archive_batch("b1", EVENTS) == uri  # identical retry is fine
    with mock.patch("src.cloud.blob_storage.serialize_batch", return_value=b"different"):
        with pytest.raises(ArchiveError):
            archiver.archive_batch("b1", EVENTS)
