"""_request funnel failures keep safe categories without secret material."""

import json
import time
from urllib.error import HTTPError, URLError

import pytest

from p11lab.round_core import artifacts

_CANARY = "canary-7d3a1f9e-2b4c-4d8a-9e0f-5a6b7c8d9e01"
_STORAGE = "https://store.blob.core.windows.net/object?sig=" + _CANARY

_RECORD_KEYS = {
    "error_category",
    "http_status",
    "artifact_id",
    "expected_bytes",
    "observed_bytes",
}


class _Response:
    """Opener response fake: status/headers/read + context manager (NOT read1)."""

    def __init__(self, status, headers=None, body=b"", read_error=None):
        self.status = status
        self.headers = dict(headers or {})
        self._body = body
        self._read_error = read_error

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, size=-1):
        if self._read_error is not None:
            raise self._read_error
        if size is None or size < 0:
            return self._body
        return self._body[:size]


class _Opener:
    def __init__(self, handler):
        self._handler = handler
        self.requests = []

    def open(self, request, timeout):
        self.requests.append(request)
        return self._handler(request, timeout)


def _client(monkeypatch, handler):
    opener = _Opener(handler)
    monkeypatch.setattr(artifacts, "build_opener", lambda *args: opener)
    return artifacts.GitHubTransport("owner/repo", _CANARY), opener


def _raising(failure):
    def handler(request, timeout):
        raise failure

    return handler


def _deadline():
    return time.monotonic() + 60


def test_s1_metadata_timeout_reports_record(monkeypatch):
    client, _ = _client(monkeypatch, _raising(TimeoutError("timed out")))
    with pytest.raises(artifacts.TransientTransportError) as error:
        client._metadata("/actions/runs/1/attempts/1", _deadline())
    assert error.value.failure_record == {
        "error_category": "timeout",
        "http_status": None,
        "artifact_id": 0,
        "expected_bytes": 2097152,
        "observed_bytes": 0,
    }
    assert error.value.error_category == "timeout"
    assert error.value.http_status is None
    assert (
        str(error.value)
        == "GitHub transport failed: timeout artifact 0 bytes 0/2097152"
    )


def test_s1_transient_status_reports_record(monkeypatch):
    def handler(request, timeout):
        raise HTTPError(request.full_url, 503, "Unavailable", {}, None)

    client, _ = _client(monkeypatch, handler)
    with pytest.raises(artifacts.TransientTransportError) as error:
        client._metadata("/actions/runs/1/attempts/1", _deadline())
    assert error.value.failure_record == {
        "error_category": "http-transient",
        "http_status": 503,
        "artifact_id": 0,
        "expected_bytes": 2097152,
        "observed_bytes": 0,
    }
    assert error.value.error_category == "http-transient"
    assert error.value.http_status == 503
    assert (
        str(error.value)
        == "GitHub transient response: http-transient http 503 artifact 0 bytes 0/2097152"
    )


def test_s1_after_download_still_reports_artifact_zero(monkeypatch):
    def handler(request, timeout):
        if request.full_url.endswith("/actions/artifacts/3/zip"):
            return _Response(302, {"location": _STORAGE})
        if request.full_url == _STORAGE:
            return _Response(200, {}, b"zip-bytes")
        raise TimeoutError("timed out")

    client, _ = _client(monkeypatch, handler)
    assert client.download(3) == b"zip-bytes"
    with pytest.raises(artifacts.TransientTransportError) as error:
        client._metadata("/actions/runs/1/attempts/1", _deadline())
    assert error.value.failure_record["artifact_id"] == 0
    assert (
        str(error.value)
        == "GitHub transport failed: timeout artifact 0 bytes 0/2097152"
    )


def test_s2_source_file_reset_reports_record_and_sends_no_token(monkeypatch):
    client, opener = _client(monkeypatch, _raising(ConnectionResetError("reset")))
    with pytest.raises(artifacts.TransientTransportError) as error:
        client.source_file("a" * 40, "src/x.py")
    assert error.value.failure_record == {
        "error_category": "network-reset",
        "http_status": None,
        "artifact_id": 0,
        "expected_bytes": 2097152,
        "observed_bytes": 0,
    }
    assert (
        str(error.value)
        == "GitHub transport failed: network-reset artifact 0 bytes 0/2097152"
    )
    assert opener.requests
    assert all(
        "authorization"
        not in {name.lower() for name, _ in request.header_items()}
        for request in opener.requests
    )


def test_s3_download_redirect_dns_reports_record(monkeypatch):
    client, _ = _client(monkeypatch, _raising(URLError("lookup failed")))
    with pytest.raises(artifacts.TransientTransportError) as error:
        client.download(3)
    assert error.value.failure_record == {
        "error_category": "network",
        "http_status": None,
        "artifact_id": 3,
        "expected_bytes": 0,
        "observed_bytes": 0,
    }
    assert str(error.value) == "GitHub transport failed: network artifact 3 bytes 0/0"


def test_s4_download_storage_timeout_reports_record(monkeypatch):
    def handler(request, timeout):
        if request.full_url.endswith("/actions/artifacts/9/zip"):
            return _Response(302, {"location": _STORAGE})
        assert request.full_url == _STORAGE
        raise TimeoutError("timed out")

    client, _ = _client(monkeypatch, handler)
    with pytest.raises(artifacts.TransientTransportError) as error:
        client.download(9)
    assert error.value.failure_record == {
        "error_category": "timeout",
        "http_status": None,
        "artifact_id": 9,
        "expected_bytes": 41943040,
        "observed_bytes": 0,
    }
    assert (
        str(error.value)
        == "GitHub transport failed: timeout artifact 9 bytes 0/41943040"
    )
    assert _CANARY not in str(error.value)
    assert _CANARY not in json.dumps(error.value.failure_record, sort_keys=True)


def test_s4_download_storage_transient_status_reports_record(monkeypatch):
    def handler(request, timeout):
        if request.full_url.endswith("/actions/artifacts/9/zip"):
            return _Response(302, {"location": _STORAGE})
        assert request.full_url == _STORAGE
        return _Response(429, {}, b"")

    client, _ = _client(monkeypatch, handler)
    with pytest.raises(artifacts.TransientTransportError) as error:
        client.download(9)
    assert error.value.failure_record == {
        "error_category": "http-transient",
        "http_status": 429,
        "artifact_id": 9,
        "expected_bytes": 41943040,
        "observed_bytes": 0,
    }
    assert (
        str(error.value)
        == "GitHub transient response: http-transient http 429 artifact 9 bytes 0/41943040"
    )


def _custody_metadata(artifact_id, digest_word):
    return artifacts.CustodyArtifactBytes(
        artifact_id, 4, "sha256:" + digest_word * 64
    )


def test_s5_custody_redirect_reports_record(tmp_path, monkeypatch):
    client, _ = _client(monkeypatch, _raising(URLError("lookup failed")))
    with pytest.raises(artifacts.TransientTransportError) as error:
        client.download_custody(_custody_metadata(5, "b"), tmp_path / "custody.zip")
    assert error.value.failure_record == {
        "error_category": "network",
        "http_status": None,
        "artifact_id": 5,
        "expected_bytes": 0,
        "observed_bytes": 0,
    }
    assert str(error.value) == "GitHub transport failed: network artifact 5 bytes 0/0"
    assert not (tmp_path / "custody.zip").exists()


def test_s6_control_redirect_reports_record(monkeypatch):
    client, _ = _client(monkeypatch, _raising(URLError("lookup failed")))
    with pytest.raises(artifacts.TransientTransportError) as error:
        client.download_custody_control(_custody_metadata(7, "c"))
    assert error.value.failure_record == {
        "error_category": "network",
        "http_status": None,
        "artifact_id": 7,
        "expected_bytes": 0,
        "observed_bytes": 0,
    }
    assert str(error.value) == "GitHub transport failed: network artifact 7 bytes 0/0"


def test_s7_control_storage_timeout_reports_record(monkeypatch):
    def handler(request, timeout):
        if request.full_url.endswith("/actions/artifacts/7/zip"):
            return _Response(302, {"location": _STORAGE})
        assert request.full_url == _STORAGE
        raise TimeoutError("timed out")

    client, _ = _client(monkeypatch, handler)
    with pytest.raises(artifacts.TransientTransportError) as error:
        client.download_custody_control(_custody_metadata(7, "c"))
    assert error.value.failure_record == {
        "error_category": "timeout",
        "http_status": None,
        "artifact_id": 7,
        "expected_bytes": 2097152,
        "observed_bytes": 0,
    }
    assert (
        str(error.value)
        == "GitHub transport failed: timeout artifact 7 bytes 0/2097152"
    )
    assert _CANARY not in str(error.value)
    assert _CANARY not in json.dumps(error.value.failure_record, sort_keys=True)


def test_s8_approval_leg_reports_record(monkeypatch):
    from p11lab import delivery_authority

    def handler(request, timeout):
        url = request.full_url
        if "deployment-branch-policies" in url:
            return _Response(200, {}, b"{}")
        if url.endswith("/environments/source-delivery"):
            return _Response(200, {}, b"{}")
        assert url.endswith("/actions/runs/11/approvals")
        raise TimeoutError("timed out")

    client, _ = _client(monkeypatch, handler)
    with pytest.raises(artifacts.TransientTransportError) as error:
        delivery_authority._load_protection(client, {}, 11, {}, _deadline())
    assert error.value.failure_record == {
        "error_category": "timeout",
        "http_status": None,
        "artifact_id": 0,
        "expected_bytes": 2097152,
        "observed_bytes": 0,
    }
    assert (
        str(error.value)
        == "GitHub transport failed: timeout artifact 0 bytes 0/2097152"
    )


def _canary_failure(outcome):
    if outcome == "http-transient":
        return HTTPError(_STORAGE, 503, "Unavailable " + _CANARY, {}, None)
    if outcome == "http-fatal":
        return HTTPError(_STORAGE, 403, "Forbidden " + _CANARY, {}, None)
    if outcome == "http-unknown":
        return HTTPError(_STORAGE, 99, "Weird " + _CANARY, {}, None)
    if outcome == "http-unknown-bool":
        return HTTPError(_STORAGE, True, "Weird " + _CANARY, {}, None)
    if outcome == "timeout":
        return TimeoutError("timed out: " + _CANARY)
    if outcome == "timeout-wrapped":
        return URLError(TimeoutError("timed out: " + _CANARY))
    if outcome == "network-reset":
        return ConnectionResetError("reset: " + _CANARY)
    if outcome == "reset-wrapped":
        return URLError(ConnectionResetError("reset: " + _CANARY))
    if outcome == "network":
        return URLError("lookup failed: " + _CANARY)
    raise AssertionError("unknown outcome")


_READ_RAISED = ("http-transient", "http-fatal", "http-unknown", "http-unknown-bool")


@pytest.mark.parametrize(
    ("outcome", "category", "status"),
    [
        ("status-transient", "http-transient", 503),
        ("http-transient", "http-transient", 503),
        ("http-fatal", "http-fatal", 403),
        ("http-unknown", "http-unknown", None),
        ("http-unknown-bool", "http-unknown", None),
        ("timeout", "timeout", None),
        ("timeout-wrapped", "timeout", None),
        ("network-reset", "network-reset", None),
        ("reset-wrapped", "network-reset", None),
        ("network", "network", None),
    ],
)
def test_request_diagnostics_carry_no_secret_material(
    monkeypatch, outcome, category, status
):
    if outcome == "status-transient":
        handler = lambda request, timeout: _Response(503, {}, b"")  # noqa: E731
    elif outcome in _READ_RAISED:
        failure = _canary_failure(outcome)

        def handler(request, timeout):
            return _Response(200, {}, b"{}", read_error=failure)
    else:
        handler = _raising(_canary_failure(outcome))
    client, _ = _client(monkeypatch, handler)
    expected = {
        "error_category": category,
        "http_status": status,
        "artifact_id": 0,
        "expected_bytes": 2097152,
        "observed_bytes": 0,
    }
    if outcome == "status-transient":
        message = (
            "GitHub transient response: http-transient http 503 artifact 0 bytes 0/2097152"
        )
    else:
        message = "GitHub transport failed: " + category
        if status is not None:
            message += f" http {status}"
        message += " artifact 0 bytes 0/2097152"
    with pytest.raises(artifacts.TransientTransportError) as error:
        client._metadata("/actions/runs/1/attempts/1", _deadline())
    assert type(error.value) is artifacts.TransientTransportError
    assert error.value.failure_record == expected
    assert set(error.value.failure_record) == _RECORD_KEYS
    assert error.value.error_category == category
    assert error.value.http_status == status
    assert str(error.value) == message
    assert _CANARY not in str(error.value)
    assert _CANARY not in json.dumps(error.value.failure_record, sort_keys=True)


def test_request_transport_helpers_are_pinned():
    assert artifacts._TRANSPORT_CATEGORIES == (
        "http-transient",
        "http-fatal",
        "http-unknown",
        "timeout",
        "network-reset",
        "network",
    )
    assert callable(artifacts._validate_transport_status)
    assert callable(artifacts._classify_transport_error)


def test_direct_storage_request_without_redirect_reports_artifact_zero(monkeypatch):
    client, _ = _client(monkeypatch, _raising(TimeoutError("timed out")))
    with pytest.raises(artifacts.TransientTransportError) as error:
        client._request(_STORAGE, None, 41943040, _deadline())
    assert error.value.failure_record == {
        "error_category": "timeout",
        "http_status": None,
        "artifact_id": 0,
        "expected_bytes": 41943040,
        "observed_bytes": 0,
    }
    assert (
        str(error.value)
        == "GitHub transport failed: timeout artifact 0 bytes 0/41943040"
    )


def test_fatal_bound_and_redirect_shapes_are_unchanged(monkeypatch):
    for code in (403, 404):
        client, _ = _client(
            monkeypatch, lambda request, timeout, c=code: _Response(c, {}, b"")
        )
        with pytest.raises(ValueError) as error:
            client._metadata("/actions/runs/1/attempts/1", _deadline())
        assert type(error.value) is ValueError
        assert str(error.value) == f"GitHub request failed with HTTP {code}"
        assert not hasattr(error.value, "failure_record")
        assert not hasattr(error.value, "error_category")
        assert not hasattr(error.value, "http_status")
    client, _ = _client(monkeypatch, lambda request, timeout: _Response(200, {}, b'{"a":1}'))
    with pytest.raises(ValueError) as error:
        client._request(
            client._base + "/actions/runs/1", client._token, 0, _deadline()
        )
    assert type(error.value) is ValueError
    assert str(error.value) == "GitHub response byte/time bound"
    assert not hasattr(error.value, "failure_record")
    for code in (301, 302, 303, 307, 308):
        location = "https://x.blob.core.windows.net/a"
        client, _ = _client(
            monkeypatch,
            lambda request, timeout, c=code: _Response(c, {"location": location}),
        )
        assert client._request(
            client._base + "/x", client._token, 0, _deadline()
        ) == (code, {"location": location}, b"")
    client, _ = _client(
        monkeypatch, lambda request, timeout: _Response(302, {"location": _STORAGE})
    )
    with pytest.raises(ValueError) as error:
        client._metadata("/actions/runs/1/attempts/1", _deadline())
    assert str(error.value) == "unexpected GitHub metadata redirect"
    client, _ = _client(
        monkeypatch, lambda request, timeout: _Response(200, {}, b"")
    )
    with pytest.raises(ValueError) as error:
        client.download(3)
    assert str(error.value) == "expected artifact download redirect"
    client, _ = _client(monkeypatch, _s4_redirect_handler())
    with pytest.raises(ValueError) as error:
        client.download(3)
    assert str(error.value) == "unexpected artifact storage redirect"
    from p11lab import delivery_authority

    client, _ = _client(monkeypatch, _s8_redirect_handler())
    with pytest.raises(ValueError) as error:
        delivery_authority._load_protection(client, {}, 11, {}, _deadline())
    assert str(error.value) == "unexpected approval history redirect"


def _s4_redirect_handler():
    def handler(request, timeout):
        if request.full_url.endswith("/actions/artifacts/3/zip"):
            return _Response(302, {"location": _STORAGE})
        assert request.full_url == _STORAGE
        return _Response(302, {"location": _STORAGE})

    return handler


def _s8_redirect_handler():
    def handler(request, timeout):
        url = request.full_url
        if "deployment-branch-policies" in url:
            return _Response(200, {}, b"{}")
        if url.endswith("/environments/source-delivery"):
            return _Response(200, {}, b"{}")
        assert url.endswith("/actions/runs/11/approvals")
        return _Response(302, {"location": _STORAGE})

    return handler


def test_acquire_retry_partition_ignores_enrichment(monkeypatch):
    client = artifacts.GitHubTransport("owner/repo", "token")
    calls = []

    def resolve(identity):
        calls.append("resolve")
        if len(calls) == 1:
            failure = artifacts.TransientTransportError(
                "GitHub transport failed: timeout artifact 0 bytes 0/2097152"
            )
            failure.failure_record = {
                "error_category": "timeout",
                "http_status": None,
                "artifact_id": 0,
                "expected_bytes": 2097152,
                "observed_bytes": 0,
            }
            failure.error_category = "timeout"
            failure.http_status = None
            raise failure
        return {
            "id": 3,
            "digest": "sha256:4a70fe9aa6436e02c2dea340fbd1e352e4ef2d8ce6ca52ad25d4b95471fc8bf2",
        }

    monkeypatch.setattr(client, "resolve", resolve)
    monkeypatch.setattr(client, "download", lambda artifact_id: b"zip")
    sleeps = []
    assert client.acquire({}, sleep=sleeps.append)[1] == b"zip"
    assert sleeps == [10]
    monkeypatch.setattr(
        client,
        "resolve",
        lambda identity: (_ for _ in ()).throw(
            ValueError("GitHub request failed with HTTP 404")
        ),
    )
    sleeps.clear()
    with pytest.raises(ValueError, match="404"):
        client.acquire({}, sleep=sleeps.append)
    assert sleeps == []
