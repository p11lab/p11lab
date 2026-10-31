"""Event-lineage producer-run resolution + real staging (P0-G).

Hermetic: fixture events + stubbed transport only. No network, Docker, or
gh anywhere in this file. Sockets are blocked process-wide to prove it.
"""
import hashlib
import io
import json
import os
import socket
import subprocess
import sys
import zipfile
from pathlib import Path
from urllib.error import HTTPError, URLError

import pytest

from p11lab.round_core.inputs import digest, load_json

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).parent / "fixtures"

FRAMEWORK_SHA = "a" * 40
PRODUCER_HEAD_SHA = "e" * 40
CONSUMER_SHA = "d" * 40
REPO = "mingulov/p11lab-round-caller"
REPO_ID = 1439580215
OWNER_ID = 1794540
WORKFLOW_ID = 401625989
WORKFLOW_PATH = ".github/workflows/producer.yml"
PRODUCER_JOB = "produce-framework-dist"
RUN_ID = 777
ATTEMPT_NR = 1
CONSUMER_RUN_ID = 456
CONSUMER_ATTEMPT = 1
TIER = "pr-smoke"
CONTROL_SHA = "10017b195e46ffd152a398970ed5412ae8c37f0a"
INPUTS_NAME = f"producer-context-inputs-{RUN_ID}-{ATTEMPT_NR}"
ARTIFACT_ID = 999
TITLE = "produce-framework-dist-" + FRAMEWORK_SHA
LOCK_RAW = b'{"schema_version":1,"build_roots":["hatchling"],"runtime_extras":[],"build_wheels":[],"runtime_wheels":[]}'
WF_BYTES = b"producer workflow bytes v1\n"
BOUNDARY_BYTES = b"producer boundary bytes v1\n"
DATA_SHA = "f7116a85c40fd6b5026890d5fe7d15ffb000f8d978d66d88259d5865eeeea0e9"

T_STARTED = "2026-10-31T10:00:00Z"
T_JOB_START = "2026-10-31T10:01:00Z"
T_CREATED = "2026-10-31T10:02:00Z"
T_JOB_END = "2026-10-31T10:03:00Z"


@pytest.fixture(autouse=True)
def _no_sockets(monkeypatch):
    import http.client
    import ssl
    import urllib.request

    import p11lab.tool_downloads

    assert http.client is not None and ssl is not None
    assert urllib.request is not None and p11lab.tool_downloads is not None

    def blocked(*args, **kwargs):
        raise AssertionError("network used during hermetic resolution test")

    monkeypatch.setattr(socket, "socket", blocked)


@pytest.fixture()
def _first_attempt(monkeypatch):
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")


def _policy_digest():
    from p11lab.round_core.policy import load_policy

    return load_policy(ROOT / "src/p11lab/data/rounds", TIER).policy_digest


def _fixture_target():
    return json.loads((FIXTURES / "valid-context.json").read_bytes())["target"]


def make_profile(**overrides):
    data_sources = [{
        "path": "disabled.json",
        "url": "https://raw.githubusercontent.com/mingulov/p11lab-round-caller/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee/data/disabled.json",
        "size": 16,
        "sha256": DATA_SHA,
        "redirect_origin": "raw.githubusercontent.com",
    }]
    profile = {
        "repository": REPO,
        "repository_id": REPO_ID,
        "owner_id": OWNER_ID,
        "workflow_id": WORKFLOW_ID,
        "producer_job": PRODUCER_JOB,
        "control_sha": CONTROL_SHA,
        "policy_sha256": _policy_digest(),
        "target_sha256": digest(_fixture_target()),
        "data_sources_sha256": digest(data_sources),
        "data_sources": data_sources,
        "workflow_path": WORKFLOW_PATH,
        "boundary_path": "README.md",
        "graph": [
            {"path": WORKFLOW_PATH,
             "sha256": hashlib.sha256(WF_BYTES).hexdigest()},
            {"path": "README.md",
             "sha256": hashlib.sha256(BOUNDARY_BYTES).hexdigest()},
        ],
    }
    profile.update(overrides)
    return profile


def make_event(**overrides):
    event = {"workflow_run": {
        "id": RUN_ID,
        "run_attempt": ATTEMPT_NR,
        "repository": {"id": REPO_ID, "full_name": REPO,
                       "owner": {"id": OWNER_ID}},
        "workflow_id": WORKFLOW_ID,
    }}
    event.update(overrides)
    return event


def make_run_meta(**overrides):
    meta = {"id": RUN_ID, "run_attempt": ATTEMPT_NR,
            "head_sha": PRODUCER_HEAD_SHA, "head_branch": "main",
            "event": "workflow_dispatch", "status": "completed",
            "conclusion": "success", "display_title": TITLE,
            "workflow_id": WORKFLOW_ID, "path": WORKFLOW_PATH,
            "repository": {"id": REPO_ID, "full_name": REPO,
                           "owner": {"id": OWNER_ID}},
            "run_started_at": T_STARTED}
    meta.update(overrides)
    return meta


def make_attempt_meta(**overrides):
    return make_run_meta(**overrides)


def make_jobs(**overrides):
    jobs = {"total_count": 2, "jobs": [
        {"id": 11, "run_id": RUN_ID, "name": PRODUCER_JOB,
         "head_sha": PRODUCER_HEAD_SHA, "status": "completed",
         "conclusion": "success", "started_at": T_JOB_START,
         "completed_at": T_JOB_END},
        {"id": 12, "run_id": RUN_ID, "name": "upload-round-context",
         "head_sha": PRODUCER_HEAD_SHA, "status": "completed",
         "conclusion": "success", "started_at": T_JOB_START,
         "completed_at": T_JOB_END},
    ]}
    jobs.update(overrides)
    return jobs


def make_inputs_zip(*, lock_raw=LOCK_RAW, identity=None, numeric=None,
                    policy_digest=None, extra=None, drop=()):
    identity = {"repository_id": REPO_ID, "run_id": RUN_ID,
                "attempt": ATTEMPT_NR, "candidate_sha": FRAMEWORK_SHA,
                "target_sha": FRAMEWORK_SHA,
                "merge_base_sha": FRAMEWORK_SHA} if identity is None else identity
    numeric = {"repository_id": REPO_ID,
               "workflow_id": WORKFLOW_ID} if numeric is None else numeric
    if policy_digest is None:
        policy_digest = _policy_digest()
    members = {"dependency-lock.json": lock_raw,
               "identity.json": json.dumps(identity).encode(),
               "numeric.json": json.dumps(numeric).encode(),
               "policy_digest.txt": policy_digest.encode()}
    if extra is not None:
        members.update(extra)
    for name in drop:
        del members[name]
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, raw in members.items():
            archive.writestr(name, raw)
    return buffer.getvalue()


def make_listing(zip_raw, **overrides):
    row = {"id": ARTIFACT_ID, "name": INPUTS_NAME,
           "size_in_bytes": len(zip_raw),
           "digest": "sha256:" + hashlib.sha256(zip_raw).hexdigest(),
           "expired": False, "created_at": T_CREATED,
           "workflow_run": {"id": RUN_ID, "repository_id": REPO_ID,
                            "head_sha": PRODUCER_HEAD_SHA}}
    listing = {"total_count": 1, "artifacts": [row]}
    listing.update(overrides)
    return listing


class StubTransport:
    """Hermetic GitHubTransport stand-in with an exact-endpoint allowlist.

    Any run-listing/discovery endpoint raises: resolution must never list
    runs. Per-path scripts allow changed-metadata sequencing.
    """

    def __init__(self, *, run=None, attempt=None, jobs=None, listing=None,
                 zip_raw=None, graph=None, scripts=None, failures=None,
                 downloads=None):
        self._zip_raw = make_inputs_zip() if zip_raw is None else zip_raw
        self._payloads = {
            f"/actions/runs/{RUN_ID}":
                make_run_meta() if run is None else run,
            f"/actions/runs/{RUN_ID}/attempts/{ATTEMPT_NR}":
                make_attempt_meta() if attempt is None else attempt,
            f"/actions/runs/{RUN_ID}/attempts/{ATTEMPT_NR}/jobs?per_page=100":
                make_jobs() if jobs is None else jobs,
            f"/actions/runs/{RUN_ID}/artifacts?per_page=100&name={INPUTS_NAME}":
                make_listing(self._zip_raw) if listing is None else listing,
        }
        self._graph = {WORKFLOW_PATH: WF_BYTES,
                        "README.md": BOUNDARY_BYTES} if graph is None else graph
        self._scripts = scripts or {}
        self._failures = failures or {}
        self._downloads = downloads or {}
        self.calls = []

    def _metadata(self, path, deadline):
        self.calls.append(("metadata", path))
        if path in self._failures:
            raise self._failures[path]
        if path in self._scripts and self._scripts[path]:
            scripted = self._scripts[path].pop(0)
            if isinstance(scripted, BaseException):
                raise scripted
            return scripted
        if path not in self._payloads:
            raise AssertionError("run listing/discovery is forbidden: " + path)
        return json.loads(json.dumps(self._payloads[path]))

    def download(self, artifact_id):
        self.calls.append(("download", artifact_id))
        if artifact_id in self._downloads:
            scripted = self._downloads[artifact_id]
            if isinstance(scripted, BaseException):
                raise scripted
            return scripted
        if artifact_id != ARTIFACT_ID:
            raise AssertionError("unexpected artifact download")
        return self._zip_raw

    def source_file(self, revision, path):
        self.calls.append(("source_file", revision, path))
        if revision != PRODUCER_HEAD_SHA:
            raise AssertionError("graph fetched at wrong revision")
        return self._graph[path]


def _resolve(event=None, profile=None, transport=None, framework_sha=FRAMEWORK_SHA,
             tier=TIER):
    from p11lab.round_core.producer_resolution import resolve_producer_run

    return resolve_producer_run(
        event=make_event() if event is None else event,
        profile=make_profile() if profile is None else profile,
        framework_sha=framework_sha, tier=tier,
        transport=StubTransport() if transport is None else transport)


def _write_inputs(tmp_path, event=None, profiles=None):
    event_path = tmp_path / "event.json"
    event_path.write_text(json.dumps(make_event() if event is None else event))
    profiles_path = tmp_path / "producer-profiles.json"
    profiles_path.write_text(json.dumps(
        {"schema_version": 1,
         "profiles": [make_profile()] if profiles is None else profiles}))
    return event_path, profiles_path


def _run_cli(event_path, profiles_path, output_dir, *, run_id=CONSUMER_RUN_ID,
             attempt=CONSUMER_ATTEMPT, framework_sha=FRAMEWORK_SHA,
             tier=TIER, extra_env=None):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src")
    env.pop("CI", None)
    env.pop("GITHUB_ACTIONS", None)
    env.pop("GITHUB_TOKEN", None)
    if extra_env is not None:
        env.update(extra_env)
    return subprocess.run(
        [sys.executable, "-B", "-m", "p11lab", "round", "resolve-producer",
         "--event-path", str(event_path), "--profile", str(profiles_path),
         "--framework-sha", framework_sha, "--tier", tier,
         "--run-id", str(run_id), "--attempt", str(attempt),
         "--output-dir", str(output_dir)],
        capture_output=True, text=True, env=env, cwd=tmp_path_parent(output_dir),
        timeout=120)


def tmp_path_parent(path):
    return Path(path).parent


def test_valid_lineage_stages_real_context(tmp_path, _first_attempt):
    from p11lab.round_core.producer_resolution import run_resolve_producer

    event_path, profiles_path = _write_inputs(tmp_path)
    output_dir = tmp_path / "round-staged"
    summary = run_resolve_producer(
        event_path=event_path, profile_path=profiles_path,
        framework_sha=FRAMEWORK_SHA, tier=TIER,
        consumer_run_id=CONSUMER_RUN_ID, consumer_attempt=CONSUMER_ATTEMPT,
        output_dir=output_dir, transport=StubTransport())
    staged_path = output_dir / "round-github-context.json"
    assert staged_path.is_file()
    staged = json.loads(staged_path.read_bytes())
    assert set(staged) == {"transport", "tier", "identity", "repository",
                           "run_head_sha", "workflow_id", "producer_job",
                           "dependency_lock_sha256", "data_root",
                           "data_files", "disabled_path", "target",
                           "control_sha"}
    assert staged["transport"] == "github" and staged["tier"] == TIER
    assert staged["identity"] == {"repository_id": REPO_ID, "run_id": RUN_ID,
                                  "attempt": ATTEMPT_NR,
                                  "candidate_sha": FRAMEWORK_SHA,
                                  "target_sha": FRAMEWORK_SHA,
                                  "merge_base_sha": FRAMEWORK_SHA}
    assert staged["repository"] == REPO
    assert staged["run_head_sha"] == PRODUCER_HEAD_SHA
    assert staged["run_head_sha"] != CONSUMER_SHA
    assert staged["workflow_id"] == WORKFLOW_ID
    assert staged["producer_job"] == PRODUCER_JOB
    assert staged["dependency_lock_sha256"] == hashlib.sha256(LOCK_RAW).hexdigest()
    assert staged["dependency_lock_sha256"] != "0" * 64
    assert staged["data_files"] == [{"path": "disabled.json", "size": 16,
                                     "sha256": DATA_SHA}]
    assert staged["disabled_path"] == "disabled.json"
    assert staged["target"] == _fixture_target()
    assert staged["control_sha"] == CONTROL_SHA
    assert "minted" not in staged_path.read_text()
    assert not Path(staged["data_root"]).exists()
    evidence = json.loads((output_dir / f"producer-resolution-{CONSUMER_RUN_ID}-{CONSUMER_ATTEMPT}.json").read_bytes())
    assert evidence["status"] == "resolved"
    assert evidence["consumer"] == {"run_id": CONSUMER_RUN_ID,
                                    "run_attempt": CONSUMER_ATTEMPT}
    assert evidence["producer"]["run_id"] == RUN_ID
    assert summary["status"] == "resolved"


def test_valid_lineage_reaches_prepare_pins_gate(tmp_path, _first_attempt):
    from p11lab.round_core.inputs import prepare as prepare_inputs
    from p11lab.round_core.producer_resolution import run_resolve_producer

    event_path, profiles_path = _write_inputs(tmp_path)
    output_dir = tmp_path / "round-staged"
    run_resolve_producer(
        event_path=event_path, profile_path=profiles_path,
        framework_sha=FRAMEWORK_SHA, tier=TIER,
        consumer_run_id=CONSUMER_RUN_ID, consumer_attempt=CONSUMER_ATTEMPT,
        output_dir=output_dir, transport=StubTransport())
    staged = json.loads((output_dir / "round-github-context.json").read_bytes())
    with pytest.raises(ValueError, match="protected dependency lock pins unresolved"):
        prepare_inputs(staged, ROOT / "src/p11lab/data/rounds",
                       tmp_path / "prepare-out")
    assert not (tmp_path / "prepare-out").exists()


def test_duplicate_historical_names_select_exact_run(_first_attempt):
    transport = StubTransport()
    resolution = _resolve(transport=transport)
    assert resolution["producer"]["run_id"] == RUN_ID
    assert resolution["producer"]["attempt"] == ATTEMPT_NR
    for kind, path, *_ in transport.calls:
        assert kind != "metadata" or path.startswith(f"/actions/runs/{RUN_ID}")
    assert transport.calls, "resolution must consult the API metadata"


def _refused_text(excinfo):
    from p11lab.round_core.producer_resolution import ProducerResolutionRefused

    error = excinfo.value
    assert isinstance(error, ProducerResolutionRefused)
    assert error.cause == "EXECUTE_TRANSPORT_REFUSED"
    assert error.phase == "prepare"
    assert error.exit_code == 3
    return str(error)


def test_consumer_rerun_refuses(monkeypatch):
    from p11lab.round_core.producer_resolution import ProducerResolutionRefused

    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "2")
    with pytest.raises(ProducerResolutionRefused) as excinfo:
        _resolve()
    assert _refused_text(excinfo) == "refused: rerun requires producer"


@pytest.mark.parametrize("value", ["0", "-1", "abc", ""])
def test_consumer_attempt_unavailable_refuses(monkeypatch, value):
    from p11lab.round_core.producer_resolution import ProducerResolutionRefused

    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", value)
    with pytest.raises(ProducerResolutionRefused) as excinfo:
        _resolve()
    assert _refused_text(excinfo) == (
        "refused: producer run resolution: producer association unavailable")


def test_consumer_attempt_missing_refuses(monkeypatch):
    from p11lab.round_core.producer_resolution import ProducerResolutionRefused

    monkeypatch.delenv("GITHUB_RUN_ATTEMPT", raising=False)
    with pytest.raises(ProducerResolutionRefused) as excinfo:
        _resolve()
    assert _refused_text(excinfo) == (
        "refused: producer run resolution: producer association unavailable")


def test_event_without_lineage_refuses(_first_attempt):
    from p11lab.round_core.producer_resolution import ProducerResolutionRefused

    with pytest.raises(ProducerResolutionRefused) as excinfo:
        _resolve(event={"action": "completed"})
    assert _refused_text(excinfo) == (
        "refused: producer run resolution: producer association unavailable")


@pytest.mark.parametrize("workflow_run", [
    {"id": "777", "run_attempt": 1},
    {"id": 777, "run_attempt": "1"},
    {"id": 0, "run_attempt": 1},
    {"id": 777, "run_attempt": -1},
    {"id": 777},
    {"run_attempt": 1},
    {"id": True, "run_attempt": 1},
])
def test_malformed_lineage_refuses(_first_attempt, workflow_run):
    from p11lab.round_core.producer_resolution import ProducerResolutionRefused

    with pytest.raises(ProducerResolutionRefused) as excinfo:
        _resolve(event={"workflow_run": workflow_run})
    assert _refused_text(excinfo) == (
        "refused: producer run resolution: malformed metadata")


@pytest.mark.parametrize("field", ["full_name", "id", "owner"])
def test_wrong_repository_refuses(_first_attempt, field):
    from p11lab.round_core.producer_resolution import ProducerResolutionRefused

    attempt = make_attempt_meta()
    if field == "full_name":
        attempt["repository"]["full_name"] = "fork/evil"
    elif field == "id":
        attempt["repository"]["id"] = REPO_ID + 1
    else:
        attempt["repository"]["owner"]["id"] = OWNER_ID + 1
    with pytest.raises(ProducerResolutionRefused) as excinfo:
        _resolve(transport=StubTransport(attempt=attempt))
    assert _refused_text(excinfo) == (
        "refused: producer run resolution: identity mismatch")


@pytest.mark.parametrize("field", ["workflow_id", "path"])
def test_wrong_workflow_refuses(_first_attempt, field):
    from p11lab.round_core.producer_resolution import ProducerResolutionRefused

    attempt = make_attempt_meta()
    attempt[field] = 1 if field == "workflow_id" else ".github/workflows/evil.yml"
    with pytest.raises(ProducerResolutionRefused) as excinfo:
        _resolve(transport=StubTransport(attempt=attempt))
    assert _refused_text(excinfo) == (
        "refused: producer run resolution: identity mismatch")


def test_wrong_event_refuses(_first_attempt):
    from p11lab.round_core.producer_resolution import ProducerResolutionRefused

    attempt = make_attempt_meta(event="push")
    with pytest.raises(ProducerResolutionRefused) as excinfo:
        _resolve(transport=StubTransport(attempt=attempt))
    assert _refused_text(excinfo) == (
        "refused: producer run resolution: identity mismatch")


def test_wrong_title_candidate_refuses(_first_attempt):
    from p11lab.round_core.producer_resolution import ProducerResolutionRefused

    attempt = make_attempt_meta(display_title="produce-framework-dist-" + "f" * 40)
    with pytest.raises(ProducerResolutionRefused) as excinfo:
        _resolve(transport=StubTransport(attempt=attempt))
    assert _refused_text(excinfo) == (
        "refused: producer run resolution: identity mismatch")


def test_wrong_head_refuses(_first_attempt):
    from p11lab.round_core.producer_resolution import ProducerResolutionRefused

    transport = StubTransport(graph={WORKFLOW_PATH: b"other bytes",
                                     "README.md": BOUNDARY_BYTES})
    with pytest.raises(ProducerResolutionRefused) as excinfo:
        _resolve(transport=transport)
    assert _refused_text(excinfo) == (
        "refused: producer run resolution: identity mismatch")


def test_malformed_head_refuses(_first_attempt):
    from p11lab.round_core.producer_resolution import ProducerResolutionRefused

    attempt = make_attempt_meta(head_sha="not-a-sha")
    with pytest.raises(ProducerResolutionRefused) as excinfo:
        _resolve(transport=StubTransport(attempt=attempt))
    assert _refused_text(excinfo) == (
        "refused: producer run resolution: malformed metadata")


@pytest.mark.parametrize("status,conclusion", [
    ("in_progress", None), ("completed", "failure"),
    ("completed", "cancelled"), ("completed", None),
])
def test_producer_not_successful_refuses(_first_attempt, status, conclusion):
    from p11lab.round_core.producer_resolution import ProducerResolutionRefused

    attempt = make_attempt_meta(status=status, conclusion=conclusion)
    with pytest.raises(ProducerResolutionRefused) as excinfo:
        _resolve(transport=StubTransport(attempt=attempt))
    assert _refused_text(excinfo) == (
        "refused: producer run resolution: producer run not successful")


def test_superseded_attempt_refuses(_first_attempt):
    from p11lab.round_core.producer_resolution import ProducerResolutionRefused

    run = make_run_meta(run_attempt=ATTEMPT_NR + 1)
    with pytest.raises(ProducerResolutionRefused) as excinfo:
        _resolve(transport=StubTransport(run=run))
    assert _refused_text(excinfo) == (
        "refused: producer run resolution: producer attempt superseded")


def test_changed_metadata_before_acquisition_refuses(_first_attempt):
    from p11lab.round_core.producer_resolution import ProducerResolutionRefused

    changed = make_attempt_meta(display_title=TITLE + "-changed")
    scripts = {f"/actions/runs/{RUN_ID}/attempts/{ATTEMPT_NR}":
               [make_attempt_meta(), changed]}
    with pytest.raises(ProducerResolutionRefused) as excinfo:
        _resolve(transport=StubTransport(scripts=scripts))
    assert _refused_text(excinfo) == (
        "refused: producer run resolution: metadata changed")


def test_changed_metadata_after_acquisition_refuses(tmp_path, _first_attempt):
    from p11lab.round_core.producer_resolution import (
        ProducerResolutionRefused, run_resolve_producer)

    path = f"/actions/runs/{RUN_ID}/attempts/{ATTEMPT_NR}"
    scripts = {path: [make_attempt_meta(), make_attempt_meta(),
                      make_attempt_meta(display_title=TITLE + "-late")]}
    event_path, profiles_path = _write_inputs(tmp_path)
    output_dir = tmp_path / "round-staged"
    with pytest.raises(ProducerResolutionRefused) as excinfo:
        run_resolve_producer(
            event_path=event_path, profile_path=profiles_path,
            framework_sha=FRAMEWORK_SHA, tier=TIER,
            consumer_run_id=CONSUMER_RUN_ID, consumer_attempt=CONSUMER_ATTEMPT,
            output_dir=output_dir, transport=StubTransport(scripts=scripts))
    assert _refused_text(excinfo) == (
        "refused: producer run resolution: metadata changed")
    assert not (output_dir / "round-github-context.json").exists()
    refusal = json.loads((output_dir / f"producer-resolution-{CONSUMER_RUN_ID}-{CONSUMER_ATTEMPT}.json").read_bytes())
    assert refusal["status"] == "refused"
    assert refusal["cause"] == "EXECUTE_TRANSPORT_REFUSED"
    assert refusal["exit_code"] == 3


def test_transient_transport_failure_refuses(_first_attempt):
    from p11lab.round_core.artifacts import TransientTransportError
    from p11lab.round_core.producer_resolution import ProducerResolutionRefused

    failure = TransientTransportError("GitHub transport failed: timeout")
    failure.failure_record = {"error_category": "timeout", "http_status": None}
    failure.error_category = "timeout"
    failure.http_status = None
    transport = StubTransport(
        failures={f"/actions/runs/{RUN_ID}": failure})
    with pytest.raises(ProducerResolutionRefused) as excinfo:
        _resolve(transport=transport)
    assert _refused_text(excinfo) == (
        "refused: producer run resolution: API transport failure")
    assert excinfo.value.error_category == "timeout"
    assert excinfo.value.http_status is None


def test_http_failure_refuses_as_request_failed(_first_attempt):
    from p11lab.round_core.producer_resolution import ProducerResolutionRefused

    transport = StubTransport(failures={
        f"/actions/runs/{RUN_ID}": ValueError("GitHub request failed with HTTP 403")})
    with pytest.raises(ProducerResolutionRefused) as excinfo:
        _resolve(transport=transport)
    assert _refused_text(excinfo) == (
        "refused: producer run resolution: API request failed")
    assert excinfo.value.http_status == 403


def test_raw_http_error_refuses_as_request_failed(_first_attempt):
    from p11lab.round_core.producer_resolution import ProducerResolutionRefused

    error = HTTPError("https://api.github.com/x", 404, "Not Found", {}, None)
    transport = StubTransport(failures={f"/actions/runs/{RUN_ID}": error})
    with pytest.raises(ProducerResolutionRefused) as excinfo:
        _resolve(transport=transport)
    assert _refused_text(excinfo) == (
        "refused: producer run resolution: API request failed")
    assert excinfo.value.http_status == 404


def test_network_error_refuses_as_transport_failure(_first_attempt):
    from p11lab.round_core.producer_resolution import ProducerResolutionRefused

    transport = StubTransport(failures={
        f"/actions/runs/{RUN_ID}": URLError(TimeoutError("timed out"))})
    with pytest.raises(ProducerResolutionRefused) as excinfo:
        _resolve(transport=transport)
    assert _refused_text(excinfo) == (
        "refused: producer run resolution: API transport failure")


def test_metadata_bound_refuses(_first_attempt):
    from p11lab.round_core.producer_resolution import ProducerResolutionRefused

    transport = StubTransport(failures={
        f"/actions/runs/{RUN_ID}": ValueError("GitHub response byte/time bound")})
    with pytest.raises(ProducerResolutionRefused) as excinfo:
        _resolve(transport=transport)
    assert _refused_text(excinfo) == (
        "refused: producer run resolution: metadata bound exceeded")


def test_oversized_download_refuses(tmp_path, _first_attempt):
    from p11lab.round_core.producer_resolution import (
        ProducerResolutionRefused, run_resolve_producer)

    zip_raw = make_inputs_zip()
    listing = make_listing(zip_raw)
    listing["artifacts"][0]["size_in_bytes"] = 3 * 1024 * 1024
    transport = StubTransport(
        listing=listing, downloads={ARTIFACT_ID: b"x" * (3 * 1024 * 1024)})
    event_path, profiles_path = _write_inputs(tmp_path)
    with pytest.raises(ProducerResolutionRefused) as excinfo:
        run_resolve_producer(
            event_path=event_path, profile_path=profiles_path,
            framework_sha=FRAMEWORK_SHA, tier=TIER,
            consumer_run_id=CONSUMER_RUN_ID, consumer_attempt=CONSUMER_ATTEMPT,
            output_dir=tmp_path / "round-staged", transport=transport)
    assert _refused_text(excinfo) == (
        "refused: producer run resolution: metadata bound exceeded")


def test_missing_inputs_artifact_refuses_no_match(_first_attempt):
    from p11lab.round_core.producer_resolution import ProducerResolutionRefused

    listing = {"total_count": 0, "artifacts": []}
    with pytest.raises(ProducerResolutionRefused) as excinfo:
        _resolve(transport=StubTransport(listing=listing))
    assert _refused_text(excinfo) == (
        "refused: producer run resolution: no match")


def test_filter_ignored_listing_refuses_malformed(_first_attempt):
    from p11lab.round_core.producer_resolution import ProducerResolutionRefused

    zip_raw = make_inputs_zip()
    listing = make_listing(zip_raw)
    listing["artifacts"][0]["name"] = "other-artifact"
    listing["total_count"] = 1
    with pytest.raises(ProducerResolutionRefused) as excinfo:
        _resolve(transport=StubTransport(listing=listing, zip_raw=zip_raw))
    assert _refused_text(excinfo) == (
        "refused: producer run resolution: malformed metadata")


def test_truncated_listing_refuses_malformed(_first_attempt):
    from p11lab.round_core.producer_resolution import ProducerResolutionRefused

    listing = {"total_count": 2, "artifacts": []}
    with pytest.raises(ProducerResolutionRefused) as excinfo:
        _resolve(transport=StubTransport(listing=listing))
    assert _refused_text(excinfo) == (
        "refused: producer run resolution: malformed metadata")


def test_duplicate_inputs_artifact_refuses_ambiguous(_first_attempt):
    from p11lab.round_core.producer_resolution import ProducerResolutionRefused

    zip_raw = make_inputs_zip()
    listing = make_listing(zip_raw)
    listing["artifacts"].append(dict(listing["artifacts"][0], id=ARTIFACT_ID + 1))
    listing["total_count"] = 2
    with pytest.raises(ProducerResolutionRefused) as excinfo:
        _resolve(transport=StubTransport(listing=listing, zip_raw=zip_raw))
    assert _refused_text(excinfo) == (
        "refused: producer run resolution: ambiguous match")


def test_unenrolled_repository_refuses_no_match(tmp_path, _first_attempt):
    from p11lab.round_core.producer_resolution import (
        ProducerResolutionRefused, run_resolve_producer)

    event = make_event()
    event["workflow_run"]["repository"]["full_name"] = "fork/evil"
    event_path, profiles_path = _write_inputs(tmp_path, event=event)
    with pytest.raises(ProducerResolutionRefused) as excinfo:
        run_resolve_producer(
            event_path=event_path, profile_path=profiles_path,
            framework_sha=FRAMEWORK_SHA, tier=TIER,
            consumer_run_id=CONSUMER_RUN_ID, consumer_attempt=CONSUMER_ATTEMPT,
            output_dir=tmp_path / "round-staged", transport=StubTransport())
    assert _refused_text(excinfo) == (
        "refused: producer run resolution: no match")


def test_duplicate_enrolled_profiles_refuse_ambiguous(tmp_path, _first_attempt):
    from p11lab.round_core.producer_resolution import (
        ProducerResolutionRefused, run_resolve_producer)

    event_path, profiles_path = _write_inputs(
        tmp_path, profiles=[make_profile(), make_profile()])
    with pytest.raises(ProducerResolutionRefused) as excinfo:
        run_resolve_producer(
            event_path=event_path, profile_path=profiles_path,
            framework_sha=FRAMEWORK_SHA, tier=TIER,
            consumer_run_id=CONSUMER_RUN_ID, consumer_attempt=CONSUMER_ATTEMPT,
            output_dir=tmp_path / "round-staged", transport=StubTransport())
    assert _refused_text(excinfo) == (
        "refused: producer run resolution: ambiguous match")


def _run_stage(tmp_path, transport, profile=None):
    from p11lab.round_core.producer_resolution import run_resolve_producer

    event_path, profiles_path = _write_inputs(
        tmp_path, profiles=None if profile is None else [profile])
    return run_resolve_producer(
        event_path=event_path, profile_path=profiles_path,
        framework_sha=FRAMEWORK_SHA, tier=TIER,
        consumer_run_id=CONSUMER_RUN_ID, consumer_attempt=CONSUMER_ATTEMPT,
        output_dir=tmp_path / "round-staged", transport=transport)


@pytest.mark.parametrize("field", ["target_sha", "merge_base_sha"])
def test_target_divergence_refuses(tmp_path, _first_attempt, field):
    from p11lab.round_core.producer_resolution import ProducerResolutionRefused

    identity = {"repository_id": REPO_ID, "run_id": RUN_ID, "attempt": ATTEMPT_NR,
                "candidate_sha": FRAMEWORK_SHA, "target_sha": FRAMEWORK_SHA,
                "merge_base_sha": FRAMEWORK_SHA}
    identity[field] = "b" * 40
    zip_raw = make_inputs_zip(identity=identity)
    transport = StubTransport(zip_raw=zip_raw, listing=make_listing(zip_raw))
    with pytest.raises(ProducerResolutionRefused) as excinfo:
        _run_stage(tmp_path, transport)
    assert _refused_text(excinfo) == (
        "refused: producer run resolution: identity mismatch")


def test_inputs_candidate_mismatch_refuses(tmp_path, _first_attempt):
    from p11lab.round_core.producer_resolution import ProducerResolutionRefused

    identity = {"repository_id": REPO_ID, "run_id": RUN_ID, "attempt": ATTEMPT_NR,
                "candidate_sha": "f" * 40, "target_sha": "f" * 40,
                "merge_base_sha": "f" * 40}
    zip_raw = make_inputs_zip(identity=identity)
    transport = StubTransport(zip_raw=zip_raw, listing=make_listing(zip_raw))
    with pytest.raises(ProducerResolutionRefused) as excinfo:
        _run_stage(tmp_path, transport)
    assert _refused_text(excinfo) == (
        "refused: producer run resolution: identity mismatch")


def test_numeric_mismatch_refuses(tmp_path, _first_attempt):
    from p11lab.round_core.producer_resolution import ProducerResolutionRefused

    zip_raw = make_inputs_zip(numeric={"repository_id": REPO_ID,
                                       "workflow_id": WORKFLOW_ID + 1})
    transport = StubTransport(zip_raw=zip_raw, listing=make_listing(zip_raw))
    with pytest.raises(ProducerResolutionRefused) as excinfo:
        _run_stage(tmp_path, transport)
    assert _refused_text(excinfo) == (
        "refused: producer run resolution: identity mismatch")


def test_policy_digest_mismatch_refuses(tmp_path, _first_attempt):
    from p11lab.round_core.producer_resolution import ProducerResolutionRefused

    zip_raw = make_inputs_zip(policy_digest="0" * 64)
    transport = StubTransport(zip_raw=zip_raw, listing=make_listing(zip_raw))
    with pytest.raises(ProducerResolutionRefused) as excinfo:
        _run_stage(tmp_path, transport)
    assert _refused_text(excinfo) == (
        "refused: producer run resolution: identity mismatch")


@pytest.mark.parametrize("kind", ["extra", "drop", "bad-json", "bad-lock"])
def test_malformed_inputs_archive_refuses(tmp_path, _first_attempt, kind):
    from p11lab.round_core.producer_resolution import ProducerResolutionRefused

    if kind == "extra":
        zip_raw = make_inputs_zip(extra={"evil.sh": b"echo evil"})
    elif kind == "drop":
        zip_raw = make_inputs_zip(drop=("numeric.json",))
    elif kind == "bad-json":
        zip_raw = make_inputs_zip(extra={"identity.json": b"{oops"})
    else:
        zip_raw = make_inputs_zip(lock_raw=b"not json")
    transport = StubTransport(zip_raw=zip_raw, listing=make_listing(zip_raw))
    with pytest.raises(ProducerResolutionRefused) as excinfo:
        _run_stage(tmp_path, transport)
    assert _refused_text(excinfo) == (
        "refused: producer run resolution: malformed metadata")


def test_multi_entry_roster_refuses_ambiguous(tmp_path, _first_attempt):
    from p11lab.round_core.producer_resolution import ProducerResolutionRefused

    profile = make_profile()
    profile["data_sources"] = [dict(profile["data_sources"][0]),
                               dict(profile["data_sources"][0], path="second.json")]
    profile["data_sources_sha256"] = digest(profile["data_sources"])
    with pytest.raises(ProducerResolutionRefused) as excinfo:
        _run_stage(tmp_path, StubTransport(), profile=profile)
    assert _refused_text(excinfo) == (
        "refused: producer run resolution: ambiguous match")


def test_empty_roster_refuses_no_match(tmp_path, _first_attempt):
    from p11lab.round_core.producer_resolution import ProducerResolutionRefused

    profile = make_profile(data_sources=[], data_sources_sha256=digest([]))
    with pytest.raises(ProducerResolutionRefused) as excinfo:
        _run_stage(tmp_path, StubTransport(), profile=profile)
    assert _refused_text(excinfo) == (
        "refused: producer run resolution: no match")


def test_malformed_roster_entry_refuses(tmp_path, _first_attempt):
    from p11lab.round_core.producer_resolution import ProducerResolutionRefused

    profile = make_profile()
    profile["data_sources"] = [dict(profile["data_sources"][0], size="16")]
    profile["data_sources_sha256"] = digest(profile["data_sources"])
    with pytest.raises(ProducerResolutionRefused) as excinfo:
        _run_stage(tmp_path, StubTransport(), profile=profile)
    assert _refused_text(excinfo) == (
        "refused: producer run resolution: producer association unavailable")


@pytest.mark.parametrize("field", ["target_sha256", "data_sources_sha256",
                                   "policy_sha256"])
def test_enrollment_pin_incoherence_refuses(tmp_path, _first_attempt, field):
    from p11lab.round_core.producer_resolution import ProducerResolutionRefused

    profile = make_profile(**{field: "0" * 64})
    with pytest.raises(ProducerResolutionRefused) as excinfo:
        _run_stage(tmp_path, StubTransport(), profile=profile)
    assert _refused_text(excinfo) == (
        "refused: producer run resolution: producer association unavailable")


def test_malformed_profile_refuses(tmp_path, _first_attempt):
    from p11lab.round_core.producer_resolution import ProducerResolutionRefused

    profile = make_profile()
    del profile["graph"]
    with pytest.raises(ProducerResolutionRefused) as excinfo:
        _run_stage(tmp_path, StubTransport(), profile=profile)
    assert _refused_text(excinfo) == (
        "refused: producer run resolution: producer association unavailable")


def _minted_context(data_root):
    """Frozen bytes of the removed B-C2x minted builder (regression pin).

    Structurally well formed, yet never staged-valid: zeros, workflow_id 1,
    and placeholder markers must fail the staged validation path.
    """
    return {
        "control_sha": "b" * 40,
        "data_files": [{"path": "minted/non-hc-placeholder.bin", "size": 0,
                        "sha256": hashlib.sha256(b"").hexdigest()}],
        "data_root": str(data_root),
        "dependency_lock_sha256": "0" * 64,
        "disabled_path": "minted-disabled.json",
        "identity": {"attempt": 2, "candidate_sha": "a" * 40,
                     "merge_base_sha": "0" * 40, "repository_id": 123456,
                     "run_id": 456, "target_sha": "0" * 40},
        "producer_job": "minted-non-hc-producer",
        "repository": "minted-org/minted-repo",
        "run_head_sha": "d" * 40,
        "target": {"marker_environment": {"python_full_version": "3.12.14"},
                   "minted": "B-C2x-non-hc-placeholder"},
        "tier": "pr-smoke",
        "transport": "github",
        "workflow_id": 1,
    }


def test_minted_shape_fails_staged_validation(tmp_path):
    from p11lab.round_core.inputs import prepare as prepare_inputs

    context = _minted_context(tmp_path / "round-data")
    with pytest.raises(ValueError, match="protected dependency lock pins unresolved"):
        prepare_inputs(context, ROOT / "src/p11lab/data/rounds",
                       tmp_path / "prepare-out")
    assert not (tmp_path / "prepare-out").exists()


def test_staged_output_has_no_minted_markers(tmp_path, _first_attempt):
    from p11lab.round_core.producer_resolution import run_resolve_producer

    event_path, profiles_path = _write_inputs(tmp_path)
    output_dir = tmp_path / "round-staged"
    run_resolve_producer(
        event_path=event_path, profile_path=profiles_path,
        framework_sha=FRAMEWORK_SHA, tier=TIER,
        consumer_run_id=CONSUMER_RUN_ID, consumer_attempt=CONSUMER_ATTEMPT,
        output_dir=output_dir, transport=StubTransport())
    raw = (output_dir / "round-github-context.json").read_bytes()
    assert b"minted" not in raw
    assert b"0" * 64 not in raw
    staged = json.loads(raw)
    assert staged["workflow_id"] != 1
    assert staged["identity"]["target_sha"] == FRAMEWORK_SHA
    assert staged["identity"]["merge_base_sha"] == FRAMEWORK_SHA
    assert "minted" not in staged["target"]


def test_pilot_target_matches_fixture_bytes():
    from importlib.resources import files

    raw = files("p11lab").joinpath("data/rounds/pilot-target.json").read_bytes()
    assert load_json(raw) == _fixture_target()
    assert digest(load_json(raw)) == digest(_fixture_target())


def test_cli_refuses_without_lineage(tmp_path, _first_attempt):
    event_path, profiles_path = _write_inputs(tmp_path, event={"action": "x"})
    completed = _run_cli(event_path, profiles_path, tmp_path / "round-staged")
    assert completed.returncode == 3, completed.stderr
    assert completed.stderr.strip() == (
        "refused: producer run resolution: producer association unavailable")
    evidence = tmp_path / f"round-staged/producer-resolution-{CONSUMER_RUN_ID}-{CONSUMER_ATTEMPT}.json"
    assert evidence.is_file()
    assert not (tmp_path / "round-staged/round-github-context.json").exists()


def test_cli_refuses_consumer_rerun(tmp_path, _first_attempt):
    event_path, profiles_path = _write_inputs(tmp_path)
    completed = _run_cli(event_path, profiles_path, tmp_path / "round-staged",
                         attempt=2, extra_env={"GITHUB_RUN_ATTEMPT": "2"})
    assert completed.returncode == 3, completed.stderr
    assert completed.stderr.strip() == "refused: rerun requires producer"
    evidence = json.loads((tmp_path / "round-staged/producer-resolution-456-2.json").read_bytes())
    assert evidence["status"] == "refused"
    assert evidence["text"] == "refused: rerun requires producer"
    assert not (tmp_path / "round-staged/round-github-context.json").exists()


def test_cli_rejects_bad_framework_sha(tmp_path, _first_attempt):
    event_path, profiles_path = _write_inputs(tmp_path)
    completed = _run_cli(event_path, profiles_path, tmp_path / "round-staged",
                         framework_sha="main")
    assert completed.returncode == 2, completed.stderr
    assert "framework_sha" in completed.stderr


def test_cli_requires_token_before_network(tmp_path, _first_attempt):
    event_path, profiles_path = _write_inputs(tmp_path)
    completed = _run_cli(event_path, profiles_path, tmp_path / "round-staged",
                         extra_env={"GITHUB_RUN_ATTEMPT": "1"})
    assert completed.returncode == 2, completed.stderr
    assert "token" in completed.stderr.lower()
