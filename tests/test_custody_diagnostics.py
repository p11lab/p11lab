"""Streaming custody failures keep safe categories without secret material."""

import json
from urllib.error import HTTPError, URLError

import pytest

from p11lab.round_core import artifacts

_CANARY = "canary-9f2b7c1e-4a6d-4e8f-9c0a-1b2c3d4e5f60"
_REDIRECT = "https://store.blob.core.windows.net/object?sig=" + _CANARY

_RECORD_KEYS = {
    "error_category",
    "http_status",
    "artifact_id",
    "expected_bytes",
    "observed_bytes",
}


def _client(monkeypatch):
    client = artifacts.GitHubTransport("owner/repo", _CANARY)
    monkeypatch.setattr(
        client, "_request", lambda *args: (302, {"location": _REDIRECT}, b"")
    )
    return client


def _metadata(artifact_id=1, size=4):
    return artifacts.CustodyArtifactBytes(artifact_id, size, "sha256:" + "a" * 64)


def test_custody_http_status_is_reported_not_collapsed(tmp_path, monkeypatch):
    class Opener:
        def open(self, request, timeout):
            raise HTTPError(request.full_url, 403, "Forbidden", {}, None)

    monkeypatch.setattr(artifacts, "build_opener", lambda *args: Opener())
    client = _client(monkeypatch)
    with pytest.raises(artifacts.TransientTransportError) as error:
        client.download_custody(_metadata(), tmp_path / "custody.zip")
    assert error.value.failure_record == {
        "error_category": "http-fatal",
        "http_status": 403,
        "artifact_id": 1,
        "expected_bytes": 4,
        "observed_bytes": 0,
    }
    assert error.value.error_category == "http-fatal"
    assert error.value.http_status == 403
    assert (
        str(error.value)
        == "custody transport failed: http-fatal http 403 artifact 1 bytes 0/4"
    )


def test_custody_reset_mid_stream_reports_observed_bytes(tmp_path, monkeypatch):
    class Response:
        status = 200
        headers = {}

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read1(self, size):
            if not getattr(self, "done", False):
                self.done = True
                return b"bad"
            raise ConnectionResetError("reset")

    class Opener:
        def open(self, request, timeout):
            return Response()

    monkeypatch.setattr(artifacts, "build_opener", lambda *args: Opener())
    client = _client(monkeypatch)
    path = tmp_path / "partial.zip"
    with pytest.raises(artifacts.TransientTransportError) as error:
        client.download_custody(_metadata(), path)
    assert error.value.failure_record == {
        "error_category": "network-reset",
        "http_status": None,
        "artifact_id": 1,
        "expected_bytes": 4,
        "observed_bytes": 3,
    }
    assert (
        str(error.value)
        == "custody transport failed: network-reset artifact 1 bytes 3/4"
    )
    assert path.read_bytes() == b"bad"


def test_custody_timeout_is_reported_not_collapsed(tmp_path, monkeypatch):
    class Opener:
        def open(self, request, timeout):
            raise TimeoutError("timed out")

    monkeypatch.setattr(artifacts, "build_opener", lambda *args: Opener())
    client = _client(monkeypatch)
    with pytest.raises(artifacts.TransientTransportError) as error:
        client.download_custody(_metadata(), tmp_path / "custody.zip")
    assert error.value.failure_record == {
        "error_category": "timeout",
        "http_status": None,
        "artifact_id": 1,
        "expected_bytes": 4,
        "observed_bytes": 0,
    }
    assert (
        str(error.value)
        == "custody transport failed: timeout artifact 1 bytes 0/4"
    )


def _failure(outcome):
    if outcome == "http-fatal":
        return HTTPError(_REDIRECT, 403, "Forbidden " + _CANARY, {}, None)
    if outcome == "http-transient":
        return HTTPError(_REDIRECT, 503, "Unavailable " + _CANARY, {}, None)
    if outcome == "http-unknown":
        return HTTPError(_REDIRECT, 99, "Weird " + _CANARY, {}, None)
    if outcome == "timeout":
        return TimeoutError("timed out: " + _CANARY)
    if outcome == "network-reset":
        return ConnectionResetError("reset: " + _CANARY)
    if outcome == "network":
        return URLError("lookup failed: " + _CANARY)
    raise AssertionError("unknown outcome")


@pytest.mark.parametrize(
    ("outcome", "category", "status"),
    [
        ("http-fatal", "http-fatal", 403),
        ("http-transient", "http-transient", 503),
        ("http-unknown", "http-unknown", None),
        ("timeout", "timeout", None),
        ("network-reset", "network-reset", None),
        ("network", "network", None),
    ],
)
def test_custody_diagnostics_carry_no_secret_material(
    tmp_path, monkeypatch, outcome, category, status
):
    failure = _failure(outcome)

    class Opener:
        def open(self, request, timeout):
            raise failure

    monkeypatch.setattr(artifacts, "build_opener", lambda *args: Opener())
    client = _client(monkeypatch)
    expected = {
        "error_category": category,
        "http_status": status,
        "artifact_id": 1,
        "expected_bytes": 4,
        "observed_bytes": 0,
    }
    message = "custody transport failed: " + category
    if status is not None:
        message += f" http {status}"
    message += " artifact 1 bytes 0/4"
    with pytest.raises(artifacts.TransientTransportError) as error:
        client.download_custody(_metadata(), tmp_path / "first.zip")
    assert error.value.failure_record == expected
    assert set(error.value.failure_record) == _RECORD_KEYS
    assert str(error.value) == message
    assert _CANARY not in str(error.value)
    assert _CANARY not in json.dumps(error.value.failure_record, sort_keys=True)
    journal = tmp_path / "failure.json"
    with pytest.raises(artifacts.TransientTransportError) as journaled:
        client.download_custody(
            _metadata(), tmp_path / "second.zip", journal_path=journal
        )
    assert journaled.value.failure_record == expected
    assert journaled.value.error_category == category
    assert journaled.value.http_status == status
    assert str(journaled.value) == message
    persisted = json.loads(journal.read_bytes())
    assert persisted == expected
    assert set(persisted) == _RECORD_KEYS
    assert _CANARY not in journal.read_bytes().decode()
