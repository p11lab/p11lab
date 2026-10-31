"""Proxy distributed cells + aggregate (P1c): per-cell CLI-capable operations.

Each workflow job invokes exactly one cell through `execute_proxy_cell`
(gates admission reused from P1a, then one `CellExecutor` run, then a
frozen cell-observation artifact); `aggregate_proxy_experiment` merges
the uploaded observations through the REAL `evaluate_proxy_verdict`
oracle and writes the experiment row plus capsule. No whole-experiment
re-execution exists in any job: each cell runs once, exactly once.

Hermetic by construction: static staged cell-observation fixtures
(`cellobs_*.json`, generated once from real gate rows) plus an
injected fake executor drive the crash matrix through the real
oracle. The staged production payload path is proven at the adapter
boundary with monkeypatched runners plus one real-Docker local proof
(docker-presence skip, never blocking hermetic green). Full live
dispatch is env-gated by design and not run.

Independence rule: this module never imports from other test modules.
Staging builders are re-authored from the production contract; fixture
IDs are invented here and differ from every other suite on purpose.
"""

import copy
import hashlib
import inspect
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from p11lab import bundle as bundle_module
from p11lab import native as native_module
from p11lab import proxy_derivative as derivative_module
from p11lab import proxy_policy
from p11lab import run as run_module
from p11lab.cli import main
from p11lab.models import ArtifactRef, ProxyBuildIdentityV1, RunResult, RunSpec
from p11lab.round_core.inputs import canonical
from p11lab import tls as tls_module

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "proxy_execute"
RUN_ID = 666661
RUN_ATTEMPT = 4
AUTHORITY = {
    "repository_id": 6666,
    "repository_full_name": "example/proxy-dist-cells",
    "producer_job_id": "666662",
    "artifact_id": 666663,
}
CONTROLS = (
    "PX-AUTH",
    "PX-STATE",
    "PX-REPLAY",
    "PX-CLIENT-CRASH",
    "PX-DAEMON-DEATH",
    "PX-DAEMON-STOP",
    "PX-LIMIT",
)
CELL_OBS_FILES = {
    "direct": "cellobs_direct_clean.json",
    "accepted-proxy": "cellobs_accepted_clean.json",
    "candidate-proxy": "cellobs_candidate_clean.json",
}


def _pe():
    """Import the production cells module lazily (RED-countable)."""
    from p11lab.round_core import proxy_execute

    return proxy_execute


def _read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n",
                          encoding="utf-8")


def _record(sha, run_id, attempt, **overrides):
    row = {"sha": sha, "run_id": run_id, "run_attempt": attempt,
           "name": "p11lab-proxy-dist-%s-%d" % (sha, attempt), **AUTHORITY}
    row.update(overrides)
    return row


def _default_record():
    """Fresh pinned-default identity record (absolute default, never wildcard)."""
    return tls_module.DEFAULT_PROXY_BUILD_IDENTITY().to_dict()


def _payload_digests():
    """Real (size, sha256) of the static P1a fixture payload bytes (read-only)."""
    return {
        role: (len(data), hashlib.sha256(data).hexdigest())
        for role, data in (
            ("daemon", (FIXTURES / "daemon.bin").read_bytes()),
            ("cli", (FIXTURES / "cli.bin").read_bytes()),
            ("shim", (FIXTURES / "shim.bin").read_bytes()))}


def _synthetic(record):
    """Record variant whose product digests equal the fixture payloads.

    sha256 has no preimage shortcut, so the honest staged identity
    re-roots product (size, sha256) at the fixture bytes while keeping
    every other field. Staged as the artifact's explicit expected
    identity (caller-staged, test-only authority).
    """
    digests = _payload_digests()
    record = copy.deepcopy(record)
    for role in ("daemon", "cli", "shim"):
        size, sha256 = digests[role]
        record[role] = dict(record[role])
        record[role]["size"] = size
        record[role]["sha256"] = sha256
    return ProxyBuildIdentityV1.from_dict(record).to_dict()


def _daemon_claim(record):
    return {"schema_version": 1, "source_revision": record["source_commit"],
            "cargo_lock_sha256": record["cargo_lock_sha256"],
            "binaries": {
                "pkcs11-proxy-ng": record["daemon"]["sha256"],
                "pkcs11-proxy-ng-cli": record["cli"]["sha256"],
                "proxy-entrypoint.sh": record["entrypoint_sha256"]}}


def _client_abi(record):
    """Client-path restriction of a record ABI (what a build observes)."""
    abi = record["abi"]
    paths = (native_module.CLIENT_CLI, native_module.CLIENT_MODULE)
    return {"decision": abi["decision"],
            "runtime_qualification": abi["runtime_qualification"],
            "floors": {path: copy.deepcopy(abi["floors"][path]) for path in paths},
            "needed": {path: copy.deepcopy(abi["needed"][path]) for path in paths},
            "interpreters": {path: abi["interpreters"][path] for path in paths},
            "shim_exports": list(abi["shim_exports"]),
            "version_requirements": {
                path: copy.deepcopy(abi["version_requirements"][path])
                for path in paths},
            "symbol_versions": {
                path: copy.deepcopy(abi["symbol_versions"][path])
                for path in paths}}


def _client_manifest(record, abi=None):
    """Full native-client manifest section matching a record."""
    archive = record["source_archive"]
    proxy = {"source_revision": record["source_commit"],
             "source_archive_sha256": archive["sha256"] if archive else None,
             "cargo_lock_sha256": record["cargo_lock_sha256"],
             "shim_sha256": record["shim"]["sha256"],
             "cli_sha256": record["cli"]["sha256"],
             "identity": copy.deepcopy(record),
             "abi_observed": (copy.deepcopy(abi) if abi is not None
                              else _client_abi(record))}
    return {"role": "native-client", "target": native_module.CLIENT_TARGET,
            "module": native_module.CLIENT_MODULE,
            "host_requirements": copy.deepcopy(
                native_module.CLIENT_HOST_REQUIREMENTS),
            "source": {"proxy": proxy},
            "files": [
                {"path": native_module.CLIENT_MODULE,
                 "sha256": record["shim"]["sha256"]},
                {"path": native_module.CLIENT_CLI,
                 "sha256": record["cli"]["sha256"]}],
            "environment": "softhsm2", "channel": "release"}


def _launch_rehashes(record):
    return {"shim_sha256": record["shim"]["sha256"],
            "cli_sha256": record["cli"]["sha256"]}


def _daemon_image(*, observed=None):
    reference = "sha256:" + "a" * 64
    return {"selected": reference,
            "observed": reference if observed is None else observed}


def _child_inspection(*, layers=None):
    if layers is None:
        layers = (list(derivative_module.load_parent_selection()["layers"])
                  + ["sha256:" + "8" * 64])
    return {"RootFS": {"Layers": layers}}


def _stage_artifact(root, name, **overrides):
    """Write one honest caller-built artifact directory under root/name."""
    record = _synthetic(_default_record())
    staged = Path(root) / name
    staged.mkdir(parents=True)
    _write_json(staged / "records.json", overrides.get("records", [
        _record(record["source_commit"], RUN_ID, RUN_ATTEMPT)]))
    _write_json(staged / "authority.json",
                overrides.get("authority", dict(AUTHORITY)))
    manifest = overrides.get("manifest")
    if manifest is None:
        manifest = _read_json(FIXTURES / "manifest.json")
        manifest["source_commit"] = record["source_commit"]
        manifest["run_id"] = RUN_ID
        manifest["run_attempt"] = RUN_ATTEMPT
        manifest["caller_repository_id"] = AUTHORITY["repository_id"]
        manifest["caller_repository_full_name"] = (
            AUTHORITY["repository_full_name"])
        manifest["build_job_id"] = AUTHORITY["producer_job_id"]
    _write_json(staged / "manifest.json", manifest)
    for role in ("daemon", "cli", "shim"):
        path = manifest[role + "_path"]
        assert ".." not in path.split("/") and not path.startswith("/")
        (staged / path).write_bytes((FIXTURES / path).read_bytes())
    _write_json(staged / "daemon_build.json",
                overrides.get("daemon_build", _daemon_claim(record)))
    _write_json(staged / "client_manifest.json",
                overrides.get("client_manifest", _client_manifest(record)))
    _write_json(staged / "launch_rehashes.json",
                overrides.get("rehashes", _launch_rehashes(record)))
    _write_json(staged / "abi_observed.json",
                overrides.get("abi", _client_abi(record)))
    _write_json(staged / "daemon_image.json",
                overrides.get("daemon_image", _daemon_image()))
    _write_json(staged / "child_inspection.json",
                overrides.get("child_inspection", _child_inspection()))
    (staged / "parent_ref.txt").write_text(
        overrides.get("parent_ref",
                      derivative_module.load_parent_selection()["local_engine_id"]),
        encoding="utf-8")
    _write_json(staged / "expected_identity.json",
                overrides.get("expected_identity", record))
    return staged


def _honest_name():
    sha = _default_record()["source_commit"]
    return "p11lab-proxy-dist-%s-%d" % (sha, RUN_ATTEMPT)


def _cellobs(name):
    """Load one static staged cell-observation fixture."""
    return _read_json(FIXTURES / name)


def _cellobs_observation(name, *, run_id=RUN_ID, run_attempt=RUN_ATTEMPT):
    """Bind one static staged observation to this invocation's run."""
    pe = _pe()
    row = {key: value for key, value in _cellobs(name)["observation"].items()
           if key not in ("run_id", "run_attempt")}
    return pe.CellObservation.from_dict(row, run_id=run_id,
                                       run_attempt=run_attempt)


def _comparison(**overrides):
    row = {"performed": True, "positive": True, "coverage_positive": True}
    row.update(overrides)
    return row


def _budgets(**overrides):
    row = {"within_budget": True}
    row.update(overrides)
    return row


class FakeExecutor:
    """Scripted CellExecutor double: static staged observations in."""

    def __init__(self, script, *, explode=None):
        self.script = dict(script)
        self.explode = explode
        self.calls = []

    def run_cell(self, request):
        pe = _pe()
        self.calls.append(request.cell)
        if self.explode is not None and request.cell == self.explode:
            raise RuntimeError("fake boom %s" % request.cell)
        scripted = self.script[request.cell]
        if isinstance(scripted, str):
            row = {key: value
                   for key, value in _cellobs(scripted)["observation"].items()
                   if key not in ("run_id", "run_attempt")}
        else:
            row = copy.deepcopy(scripted)
        return pe.CellObservation.from_dict(
            row, run_id=request.run_id, run_attempt=request.run_attempt)


class MisboundRunExecutor:
    """Double returning an observation bound to the wrong run."""

    def __init__(self, name):
        self.name = name
        self.calls = []

    def run_cell(self, request):
        self.calls.append(request.cell)
        return _cellobs_observation(self.name, run_id=request.run_id + 999,
                                    run_attempt=request.run_attempt)


def _run_cell(tmp_path, cell, script, **kwargs):
    pe = _pe()
    staged = _stage_artifact(tmp_path / "in", _honest_name(),
                             **kwargs.pop("stage", {}))
    params = {"executor": FakeExecutor(script, **kwargs.pop("fake", {})),
              "cell_payload": kwargs.pop("cell_payload",
                                         {"scope": "p1c-fake"})}
    params.update(kwargs)
    return pe.execute_proxy_cell(
        staged, cell=cell, run_id=RUN_ID, run_attempt=RUN_ATTEMPT,
        output_dir=tmp_path / "out", output_json=tmp_path / "row.json",
        **params)


def _write_cells(directory, mapping):
    """Stage one cells dir: frozen <cell>.json roster (literals, not prod)."""
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    for cell, value in mapping.items():
        target = root / ("%s.json" % cell)
        if isinstance(value, str):
            target.write_bytes((FIXTURES / value).read_bytes())
        else:
            _write_json(target, value)
    return root


def _run_aggregate(tmp_path, mapping, **kwargs):
    pe = _pe()
    cells = _write_cells(tmp_path / "cells", mapping)
    for extra in kwargs.pop("extras", []):
        path = cells / extra
        if extra.endswith("/"):
            path.mkdir(parents=True, exist_ok=True)
            (path / "junk.log").write_text("stray\n", encoding="utf-8")
        else:
            path.write_text("stray\n", encoding="utf-8")
    _write_json(tmp_path / "comparison.json",
                _comparison(**kwargs.pop("comparison", {})))
    budgets_overrides = kwargs.pop("budgets", {})
    params = {"comparison": _read_json(tmp_path / "comparison.json")}
    if budgets_overrides is None:
        params["budgets"] = None
    else:
        _write_json(tmp_path / "budgets.json",
                    _budgets(**budgets_overrides))
        params["budgets"] = _read_json(tmp_path / "budgets.json")
    params.update(kwargs)
    return pe.aggregate_proxy_experiment(
        cells, run_id=RUN_ID, run_attempt=RUN_ATTEMPT,
        output_dir=tmp_path / "out", output_json=tmp_path / "row.json",
        **params)


def _spec_doc(**overrides):
    doc = {"environment": "softhsm2", "channel": "release", "mode": "proxy",
           "artifact": {"kind": "image",
                        "reference": "sha256:" + "0" * 64,
                        "sha256": "0" * 64, "platform": "linux/amd64"},
           "execution_location": "container",
           "consumer_artifact": None, "client_artifact": None,
           "argv": ["crash-harness", "--cell", "candidate-proxy"],
           "inputs": {"P11LAB_HARNESS_SEED": "p1c-synthetic"},
           "timeout_seconds": 300}
    doc.update(overrides)
    return doc


def _proxy_payload_doc(**overrides):
    doc = {"spec": _spec_doc(**overrides.pop("spec", {})),
           "plan": {"descriptor": {"inputs": {}}, "host": True},
           "log_refs": ["cell-logs/candidate-proxy/client.log"]}
    doc.update(overrides)
    return doc


def _direct_payload_doc(prefix, **overrides):
    doc = {"spec": _spec_doc(**dict({"mode": "direct"}, **overrides.pop(
        "spec", {}))),
           "installed_prefix": str(prefix),
           "log_refs": ["cell-logs/direct/client.log"]}
    doc.update(overrides)
    return doc


def _result(returncode, *, lifecycle=(), cleanup=(), tmp_path=None):
    root = Path(tmp_path) if tmp_path is not None else Path(".")
    return RunResult(app_returncode=returncode,
                     lifecycle_errors=tuple(lifecycle),
                     cleanup_errors=tuple(cleanup), exit_code=0,
                     receipt_path=root / "receipt.json")


def _rebuild_oracle_inputs(row):
    """Rebuild oracle inputs from the row's own evidence (no-fork proof)."""
    pe = _pe()
    observations = {
        entry["cell"]: pe.CellObservation(
            cell=entry["cell"], run_id=entry["run_id"],
            run_attempt=entry["run_attempt"], admitted=entry["admitted"],
            complete=entry["complete"],
            attribution_usable=entry["attribution_usable"],
            findings=tuple(entry["findings"]),
            unexpected_death=entry["unexpected_death"],
            logs_available=entry["logs_available"],
            log_refs=tuple(entry["log_refs"]),
            terminal_evidence_complete=entry["terminal_evidence_complete"])
        for entry in row["observations"]}
    built = pe.build_verdict_inputs(
        observations, comparison=row["comparison"], budgets=row["budgets"],
        uploads_complete=row["uploads_complete"], cancelled=row["cancelled"],
        infrastructure_error=row["infrastructure_error"])
    return built["cells"], built["controls"], built["budgets"]


# Static staged fixtures: real gate rows, invocation-bound runs.

def test_cellobs_fixtures_bind_run_cell_logs():
    for cell, name in CELL_OBS_FILES.items():
        doc = _cellobs(name)
        assert doc["schema"] == "p11lab-proxy-cell-observation-v1"
        assert doc["run_id"] == RUN_ID
        assert doc["run_attempt"] == RUN_ATTEMPT
        assert doc["cell"] == cell
        assert doc["status"] == "executed"
        assert doc["infrastructure_error"] is None
        obs = doc["observation"]
        assert obs["cell"] == cell
        assert obs["run_id"] == RUN_ID
        assert obs["run_attempt"] == RUN_ATTEMPT
        assert doc["log_refs"] == obs["log_refs"]
        assert [entry["gate"] for entry in doc["gates"]] == [
            "selection", "bytes", "install", "identity", "derivative"]
        assert all(entry["cause"] == "PROXY_GATE_OK"
                   for entry in doc["gates"])
        assert doc["selection"]["run_id"] == RUN_ID
        assert doc["selection"]["run_attempt"] == RUN_ATTEMPT


def test_cellobs_crash_matrix_typed():
    crash = _cellobs("cellobs_candidate_crash.json")["observation"]
    assert crash["unexpected_death"] is True
    assert crash["logs_available"] is True
    assert crash["terminal_evidence_complete"] is True
    no_logs = _cellobs("cellobs_candidate_no_logs.json")["observation"]
    assert no_logs["unexpected_death"] is True
    assert no_logs["logs_available"] is False
    assert no_logs["terminal_evidence_complete"] is False
    accept = _cellobs("cellobs_accepted_crash.json")["observation"]
    assert accept["cell"] == "accepted-proxy"
    assert accept["unexpected_death"] is True


def test_cell_observation_filenames_frozen():
    pe = _pe()
    assert pe.cell_observation_filename("direct") == "direct.json"
    assert pe.cell_observation_filename("accepted-proxy") == (
        "accepted-proxy.json")
    assert pe.cell_observation_filename("candidate-proxy") == (
        "candidate-proxy.json")
    with pytest.raises(ValueError, match="unknown experiment cell"):
        pe.cell_observation_filename("second-candidate")


# Cell entry: exactly one named cell, gates first, artifact out.

@pytest.mark.parametrize("cell", ["direct", "accepted-proxy",
                                  "candidate-proxy"])
def test_cell_runs_exactly_one_named_cell(tmp_path, cell):
    pe = _pe()
    executor = FakeExecutor(CELL_OBS_FILES)
    staged = _stage_artifact(tmp_path / "in", _honest_name())
    row = pe.execute_proxy_cell(
        staged, cell=cell, run_id=RUN_ID, run_attempt=RUN_ATTEMPT,
        output_dir=tmp_path / "out", output_json=tmp_path / "row.json",
        executor=executor, cell_payload={"scope": "p1c-fake"})
    assert executor.calls == [cell]
    assert row["cell"] == cell
    assert row["exit_code"] == 0
    assert (tmp_path / "out" / ("%s.json" % cell)).exists()
    for other in ("direct", "accepted-proxy", "candidate-proxy"):
        if other != cell:
            assert not (tmp_path / "out" / ("%s.json" % other)).exists()
    assert _read_json(tmp_path / "row.json") == row


def test_cell_observation_artifact_frozen_roster(tmp_path):
    row = _run_cell(tmp_path, "candidate-proxy", CELL_OBS_FILES)
    doc = _read_json(tmp_path / "out" / "candidate-proxy.json")
    assert set(doc) == {"schema", "artifact", "proxy_sha", "run_id",
                        "run_attempt", "cell", "status", "observation",
                        "log_refs", "infrastructure_error", "gates",
                        "selection"}
    assert doc["schema"] == "p11lab-proxy-cell-observation-v1"
    assert doc["artifact"] == row["artifact"]
    assert doc["proxy_sha"] == row["proxy_sha"]
    assert doc["run_id"] == RUN_ID
    assert doc["run_attempt"] == RUN_ATTEMPT
    assert doc["cell"] == "candidate-proxy"
    assert doc["status"] == "executed"
    assert doc["infrastructure_error"] is None
    assert doc["observation"] == row["observations"][0]
    assert doc["observation"]["unexpected_death"] is False
    assert doc["log_refs"] == doc["observation"]["log_refs"]
    assert doc["log_refs"]
    assert doc["gates"] == row["gates"]
    assert doc["selection"] == row["selection"]


def test_cell_row_shape_pending_verdict(tmp_path):
    row = _run_cell(tmp_path, "candidate-proxy", CELL_OBS_FILES)
    assert row["lane"] == "proxy"
    assert row["phase"] == "cell-executed"
    assert row["status"] == "executed"
    assert row["cause"] == "PROXY_CELL_OK"
    assert row["cause_detail"] is None
    assert row["exit_code"] == 0
    assert row["experiment_positive"] is False
    assert row["live_qualified"] is False
    assert row["image_usable"] is False
    assert row["evidence_complete"] is False
    assert row["evidence_admitted"] is False
    assert row["comparison_positive"] is None
    assert row["infrastructure_error"] is None
    assert row["typed_cause"] is None
    assert row["verdict"] == "pending"
    assert row["verdict_mirror"] is None
    assert row["observation_artifact"] == "candidate-proxy.json"
    assert len(row["observations"]) == 1
    assert row["observations"][0]["cell"] == "candidate-proxy"
    assert row["cells"]["candidate-proxy"]["status"] == "executed"
    assert row["cells"]["direct"] == {"status": "not-run"}
    assert row["cells"]["accepted-proxy"] == {"status": "not-run"}
    assert [entry["gate"] for entry in row["gates"]] == [
        "selection", "bytes", "install", "identity", "derivative"]
    assert any("sibling cells" in note for note in row["limitations"])
    assert any("live qualification" in note for note in row["limitations"])


def test_cell_writes_no_capsule(tmp_path):
    _run_cell(tmp_path, "direct", CELL_OBS_FILES)
    assert (tmp_path / "out" / "proxy-gated.json").exists()
    assert (tmp_path / "out" / "direct.json").exists()
    assert not (tmp_path / "out" / "proxy-capsule.json").exists()


def test_cell_refusal_runs_zero_cells(tmp_path):
    pe = _pe()
    executor = FakeExecutor(CELL_OBS_FILES)
    staged = _stage_artifact(tmp_path / "in", _honest_name(), authority=dict(
        AUTHORITY, repository_id=AUTHORITY["repository_id"] + 1))
    row = pe.execute_proxy_cell(
        staged, cell="candidate-proxy", run_id=RUN_ID,
        run_attempt=RUN_ATTEMPT, output_dir=tmp_path / "out",
        output_json=tmp_path / "row.json", executor=executor,
        cell_payload={"scope": "p1c-fake"})
    assert executor.calls == []
    assert row["cause"] == "PROXY_GATE_SELECTION_REFUSED"
    assert row["exit_code"] == 1
    assert row["verdict_mirror"] == {"typed_cause": "missing-evidence",
                                     "exit_code": 1}
    assert not (tmp_path / "out" / "candidate-proxy.json").exists()
    assert not (tmp_path / "out" / "proxy-capsule.json").exists()
    assert _read_json(tmp_path / "row.json") == row


def test_cell_t8_on_executor_failure(tmp_path):
    row = _run_cell(tmp_path, "candidate-proxy", CELL_OBS_FILES,
                    fake={"explode": "candidate-proxy"})
    assert row["phase"] == "cell-executor-failed"
    assert row["status"] == "executor-failed"
    assert row["exit_code"] == 2
    assert row["cause_detail"] == (
        "cell candidate-proxy executor failed: "
        "fake boom candidate-proxy")
    assert row["infrastructure_error"] == row["cause_detail"]
    assert row["typed_cause"] == "usage-or-infrastructure"
    assert row["verdict"] == "pending"
    assert row["verdict_mirror"] == {
        "typed_cause": "usage-or-infrastructure", "exit_code": 2}
    assert row["observations"] == []
    assert row["cells"]["candidate-proxy"]["status"] == "executor-failed"
    doc = _read_json(tmp_path / "out" / "candidate-proxy.json")
    assert doc["status"] == "executor-failed"
    assert doc["observation"] is None
    assert doc["log_refs"] == []
    assert doc["infrastructure_error"] == row["cause_detail"]


def test_cell_t8_on_misbound_observation(tmp_path):
    script = dict(CELL_OBS_FILES, **{
        "candidate-proxy": "cellobs_accepted_clean.json"})
    row = _run_cell(tmp_path, "candidate-proxy", script)
    assert row["exit_code"] == 2
    assert row["cause_detail"] == (
        "cell candidate-proxy executor returned a misbound observation "
        "(cell accepted-proxy)")
    assert row["typed_cause"] == "usage-or-infrastructure"
    doc = _read_json(tmp_path / "out" / "candidate-proxy.json")
    assert doc["status"] == "executor-failed"
    assert doc["infrastructure_error"] == row["cause_detail"]


def test_cell_t8_on_wrong_run_observation(tmp_path):
    pe = _pe()
    staged = _stage_artifact(tmp_path / "in", _honest_name())
    executor = MisboundRunExecutor("cellobs_candidate_clean.json")
    row = pe.execute_proxy_cell(
        staged, cell="candidate-proxy", run_id=RUN_ID,
        run_attempt=RUN_ATTEMPT, output_dir=tmp_path / "out",
        output_json=tmp_path / "row.json", executor=executor,
        cell_payload={"scope": "p1c-fake"})
    assert executor.calls == ["candidate-proxy"]
    assert row["exit_code"] == 2
    assert "misbound observation" in row["cause_detail"]


@pytest.mark.parametrize("cell", ["no-such-cell", "", "Direct"])
def test_cell_rejects_unknown_cell_before_admission(tmp_path, cell):
    pe = _pe()
    executor = FakeExecutor(CELL_OBS_FILES)
    staged = _stage_artifact(tmp_path / "in", _honest_name())
    with pytest.raises(ValueError, match="unknown experiment cell"):
        pe.execute_proxy_cell(
            staged, cell=cell, run_id=RUN_ID, run_attempt=RUN_ATTEMPT,
            output_dir=tmp_path / "out", output_json=tmp_path / "row.json",
            executor=executor, cell_payload={"scope": "p1c-fake"})
    assert executor.calls == []
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("run_id,attempt", [(0, 1), (1, 0), (-3, 2)])
def test_cell_rejects_bad_run_ids_before_cells(tmp_path, run_id, attempt):
    pe = _pe()
    executor = FakeExecutor(CELL_OBS_FILES)
    staged = _stage_artifact(tmp_path / "in", _honest_name())
    with pytest.raises(ValueError, match="positive int"):
        pe.execute_proxy_cell(
            staged, cell="direct", run_id=run_id, run_attempt=attempt,
            output_dir=tmp_path / "out", output_json=tmp_path / "row.json",
            executor=executor, cell_payload={"scope": "p1c-fake"})
    assert executor.calls == []


def test_cell_rejects_bad_executor_before_cells(tmp_path):
    pe = _pe()
    staged = _stage_artifact(tmp_path / "in", _honest_name())
    with pytest.raises(ValueError, match="run_cell"):
        pe.execute_proxy_cell(
            staged, cell="direct", run_id=RUN_ID, run_attempt=RUN_ATTEMPT,
            output_dir=tmp_path / "out", output_json=tmp_path / "row.json",
            executor=object(), cell_payload={"scope": "p1c-fake"})
    assert not (tmp_path / "out").exists()


def test_cell_rejects_bad_payload_before_cells(tmp_path):
    pe = _pe()
    executor = FakeExecutor(CELL_OBS_FILES)
    staged = _stage_artifact(tmp_path / "in", _honest_name())
    with pytest.raises(ValueError, match="payload"):
        pe.execute_proxy_cell(
            staged, cell="direct", run_id=RUN_ID, run_attempt=RUN_ATTEMPT,
            output_dir=tmp_path / "out", output_json=tmp_path / "row.json",
            executor=executor, cell_payload=["not-a-mapping"])
    assert executor.calls == []


def test_cell_stale_output_dir_raises(tmp_path):
    pe = _pe()
    staged = _stage_artifact(tmp_path / "in", _honest_name())
    (tmp_path / "out").mkdir()
    with pytest.raises(OSError):
        pe.execute_proxy_cell(
            staged, cell="direct", run_id=RUN_ID, run_attempt=RUN_ATTEMPT,
            output_dir=tmp_path / "out", output_json=tmp_path / "row.json",
            executor=FakeExecutor(CELL_OBS_FILES),
            cell_payload={"scope": "p1c-fake"})


# Staged production payloads: bounded JSON in, real adapter, runners owned.

def _run_staged(tmp_path, cell, payload, **kwargs):
    pe = _pe()
    staged = _stage_artifact(tmp_path / "in", _honest_name(),
                             **kwargs.pop("stage", {}))
    payload_path = tmp_path / "payload.json"
    if isinstance(payload, bytes):
        payload_path.write_bytes(payload)
    else:
        _write_json(payload_path, payload)
    return pe.execute_proxy_cell_staged(
        staged, cell=cell, run_id=RUN_ID, run_attempt=RUN_ATTEMPT,
        output_dir=tmp_path / "out", output_json=tmp_path / "row.json",
        cell_payload_path=payload_path, **kwargs)


def test_staged_proxy_payload_reaches_run_proxy(monkeypatch, tmp_path):
    seen = {}

    def fake_run_proxy(spec, plan):
        seen["spec"] = spec
        seen["plan"] = plan
        return _result(0, tmp_path=tmp_path)

    monkeypatch.setattr(run_module, "run_proxy", fake_run_proxy)
    payload = _proxy_payload_doc()
    row = _run_staged(tmp_path, "candidate-proxy", payload)
    assert row["exit_code"] == 0
    assert row["observations"][0]["cell"] == "candidate-proxy"
    assert row["observations"][0]["complete"] is True
    spec = seen["spec"]
    assert isinstance(spec, RunSpec)
    assert spec.environment == "softhsm2"
    assert spec.channel == "release"
    assert spec.mode == "proxy"
    assert spec.artifact == ArtifactRef(
        kind="image", reference="sha256:" + "0" * 64, sha256="0" * 64,
        platform="linux/amd64")
    assert spec.execution_location == "container"
    assert spec.consumer_artifact is None
    assert spec.client_artifact is None
    assert spec.argv == ("crash-harness", "--cell", "candidate-proxy")
    assert spec.inputs == {"P11LAB_HARNESS_SEED": "p1c-synthetic"}
    assert spec.timeout_seconds == 300
    assert spec.output_dir == tmp_path / "out" / "cell-run"
    assert spec.cwd == tmp_path / "out" / "cell-run"
    assert spec.installed_prefix is None
    assert spec.expected_proxy_identity is None
    assert seen["plan"] == {"descriptor": {"inputs": {}}, "host": True}
    assert row["observations"][0]["log_refs"] == [
        "cell-logs/candidate-proxy/client.log"]


def test_staged_direct_payload_reaches_run_native(monkeypatch, tmp_path):
    seen = {}
    sentinel = object()

    def fake_read_installation(prefix, *, environment, channel, platform):
        seen["prefix"] = prefix
        seen["selection"] = (environment, channel, platform)
        return sentinel

    def fake_run_native(spec, installed):
        seen["spec"] = spec
        seen["installed"] = installed
        return _result(0, tmp_path=tmp_path)

    monkeypatch.setattr(bundle_module, "read_installation",
                        fake_read_installation)
    monkeypatch.setattr(native_module, "run_native_softhsm", fake_run_native)
    prefix = tmp_path / "installed"
    row = _run_staged(tmp_path, "direct", _direct_payload_doc(prefix))
    assert row["exit_code"] == 0
    assert seen["prefix"] == prefix
    assert seen["selection"] == ("softhsm2", "release", "linux/amd64")
    assert seen["installed"] is sentinel
    assert seen["spec"].mode == "direct"
    assert row["observations"][0]["cell"] == "direct"


def test_staged_wrapper_refusal_runs_no_runner(monkeypatch, tmp_path):
    def exploding_run_proxy(spec, plan):
        raise AssertionError("runner must stay untouched on refusal")

    monkeypatch.setattr(run_module, "run_proxy", exploding_run_proxy)
    row = _run_staged(tmp_path, "candidate-proxy", _proxy_payload_doc(),
                      stage={"records": []})
    assert row["cause"] == "PROXY_GATE_SELECTION_REFUSED"
    assert row["exit_code"] == 1
    assert not (tmp_path / "out" / "candidate-proxy.json").exists()


def test_staged_runner_error_is_t8_exact(monkeypatch, tmp_path):
    def failing_run_proxy(spec, plan):
        raise RuntimeError("runner boom")

    monkeypatch.setattr(run_module, "run_proxy", failing_run_proxy)
    row = _run_staged(tmp_path, "candidate-proxy", _proxy_payload_doc())
    assert row["exit_code"] == 2
    assert row["cause_detail"] == (
        "cell candidate-proxy executor failed: runner boom")
    assert row["typed_cause"] == "usage-or-infrastructure"
    doc = _read_json(tmp_path / "out" / "candidate-proxy.json")
    assert doc["infrastructure_error"] == row["cause_detail"]


def test_staged_rejects_missing_file_before_gates(tmp_path):
    pe = _pe()
    staged = _stage_artifact(tmp_path / "in", _honest_name())
    with pytest.raises(ValueError, match="cell payload file is missing"):
        pe.execute_proxy_cell_staged(
            staged, cell="candidate-proxy", run_id=RUN_ID,
            run_attempt=RUN_ATTEMPT, output_dir=tmp_path / "out",
            output_json=tmp_path / "row.json",
            cell_payload_path=tmp_path / "absent.json")
    assert not (tmp_path / "out").exists()


def test_staged_rejects_invalid_json_before_gates(tmp_path):
    with pytest.raises(ValueError, match="not valid JSON"):
        _run_staged(tmp_path, "candidate-proxy", b"{nope")
    assert not (tmp_path / "out").exists()


def test_staged_usage_before_gates_on_refusing_artifact(tmp_path):
    with pytest.raises(ValueError, match="not valid JSON"):
        _run_staged(tmp_path, "candidate-proxy", b"{nope",
                    stage={"records": []})
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("edit", [
    {"extra": True},
    {"plan": None},
    {"log_refs": "cell-logs/x.log"},
    {"log_refs": ["kept.log", 7]},
    {"log_refs": [""]},
    {"spec": None},
    {"spec": {"mode": "proxy"}},
])
def test_staged_rejects_bad_proxy_shapes(tmp_path, edit):
    payload = _proxy_payload_doc()
    payload.update(edit)
    if edit == {"plan": None}:
        del payload["plan"]
    with pytest.raises(ValueError, match="payload|log_refs|spec"):
        _run_staged(tmp_path, "candidate-proxy", payload)


@pytest.mark.parametrize("plan", [
    {"host": True},
    {"descriptor": {}, "host": "yes"},
    {"descriptor": [], "host": True},
    {"descriptor": {}, "host": True, "extra": 1},
])
def test_staged_rejects_bad_plan_shapes(tmp_path, plan):
    with pytest.raises(ValueError, match="plan"):
        _run_staged(tmp_path, "candidate-proxy",
                    _proxy_payload_doc(plan=plan))


@pytest.mark.parametrize("cell,payload,phrase", [
    ("candidate-proxy", _proxy_payload_doc(spec={"mode": "direct"}),
     "mismatches cell"),
    ("direct", _direct_payload_doc("/prefix", spec={"mode": "proxy"}),
     "mismatches cell"),
    ("direct", _proxy_payload_doc(), "keys must be exactly"),
    ("candidate-proxy", _direct_payload_doc("/prefix"), "keys must be exactly"),
])
def test_staged_rejects_mode_and_shape_mismatch(tmp_path, cell, payload,
                                                phrase):
    with pytest.raises(ValueError, match=phrase):
        _run_staged(tmp_path, cell, payload)


@pytest.mark.parametrize("spec", [
    {"artifact": None},
    {"artifact": {"kind": "image"}},
    {"artifact": {"kind": "", "reference": "r", "sha256": "0" * 64,
                  "platform": "linux/amd64"}},
    {"artifact": {"kind": "image", "reference": "r", "sha256": "zz",
                  "platform": "linux/amd64"}},
    {"argv": "crash-harness"},
    {"argv": ["ok", 7]},
    {"inputs": ["seed"]},
    {"inputs": {"seed": 7}},
    {"timeout_seconds": 0},
    {"timeout_seconds": 86401},
    {"timeout_seconds": "300"},
    {"environment": ""},
    {"channel": 7},
    {"execution_location": ""},
    {"consumer_artifact": {"kind": "image"}},
])
def test_staged_rejects_bad_spec_fields(tmp_path, spec):
    with pytest.raises(ValueError, match="spec|artifact|argv|inputs|timeout"):
        _run_staged(tmp_path, "candidate-proxy",
                    _proxy_payload_doc(spec=spec))


def test_staged_accepts_null_consumer_and_client(tmp_path):
    payload = _proxy_payload_doc(
        spec={"consumer_artifact": None, "client_artifact": None})
    row = _run_staged(tmp_path, "candidate-proxy", payload,
                      stage={"records": []})
    assert row["cause"] == "PROXY_GATE_SELECTION_REFUSED"


def test_staged_rejects_bad_prefix_before_gates(tmp_path):
    with pytest.raises(ValueError, match="installed_prefix"):
        _run_staged(tmp_path, "direct",
                    _direct_payload_doc(tmp_path / "absent-prefix"))
    assert not (tmp_path / "out").exists()


def test_staged_rejects_bad_prefix_on_refusing_artifact(tmp_path):
    with pytest.raises(ValueError, match="installed_prefix"):
        _run_staged(tmp_path, "direct",
                    _direct_payload_doc(tmp_path / "absent-prefix"),
                    stage={"records": []})
    assert not (tmp_path / "out").exists()


# Aggregate: staged merge, real oracle, row + capsule, no re-execution.

def test_aggregate_clean_is_t1_exact_but_unclaimed(tmp_path):
    row = _run_aggregate(tmp_path, CELL_OBS_FILES)
    oracle = {"experiment_positive": True, "exit_code": 0,
              "evidence_complete": True, "typed_cause": None}
    assert row["phase"] == "executed"
    assert row["status"] == "executed"
    assert row["cause"] == "PROXY_EXECUTE_OK"
    assert row["cause_detail"] is None
    assert row["verdict"] == oracle
    assert row["verdict"] == proxy_policy.evaluate_proxy_verdict(
        *_rebuild_oracle_inputs(row))
    assert row["exit_code"] == 0
    assert row["experiment_positive"] is False
    assert row["live_qualified"] is False
    assert row["image_usable"] is False
    assert row["evidence_complete"] is True
    assert row["evidence_admitted"] is True
    assert row["capsule"] == "proxy-capsule.json"
    assert (tmp_path / "out" / "proxy-capsule.json").exists()
    assert row["controls"] == {
        control: {"accepted-proxy": "pass", "candidate-proxy": "pass"}
        for control in CONTROLS}
    assert row["gates"] == _cellobs(
        "cellobs_direct_clean.json")["gates"]
    assert row["selection"] == _cellobs(
        "cellobs_direct_clean.json")["selection"]
    assert row["attempt_roster"] == [
        {"cell": "direct", "attempt": 1},
        {"cell": "accepted-proxy", "attempt": 1},
        {"cell": "candidate-proxy", "attempt": 1}]
    assert row["shard_roster"] == []
    assert any("re-executes nothing" in note
               for note in row["limitations"])
    capsule = _read_json(tmp_path / "out" / "proxy-capsule.json")
    assert capsule["schema"] == "p11lab-proxy-experiment-result-v1"
    assert capsule["diagnostic_only"] is True
    assert capsule["experiment_kind"] == "proxy-round"
    assert capsule["experiment_positive"] is False
    assert capsule["experiment_live_qualified"] is False
    assert capsule["verdict"] == oracle
    assert capsule["selection"] == row["selection"]


def test_aggregate_capsule_self_hash_verifies(tmp_path):
    _run_aggregate(tmp_path, CELL_OBS_FILES)
    capsule = _read_json(tmp_path / "out" / "proxy-capsule.json")
    digest = capsule["capsule_sha256"]
    assert isinstance(digest, str) and len(digest) == 64
    recomputed = hashlib.sha256(canonical(
        {**capsule, "capsule_sha256": None})).hexdigest()
    assert recomputed == digest


def test_aggregate_matches_loop_verdict_clean(tmp_path):
    pe = _pe()
    staged = _stage_artifact(tmp_path / "loop", _honest_name())
    loop = pe.execute_proxy_experiment(
        staged, run_id=RUN_ID, run_attempt=RUN_ATTEMPT,
        output_dir=tmp_path / "loop-out",
        output_json=tmp_path / "loop.json",
        executor=FakeExecutor(CELL_OBS_FILES), comparison=_comparison(),
        budgets=_budgets())
    merged = _run_aggregate(tmp_path, CELL_OBS_FILES)
    assert merged["verdict"] == loop["verdict"]
    assert merged["controls"] == loop["controls"]
    assert merged["observations"] == loop["observations"]


def test_aggregate_matches_loop_verdict_crash(tmp_path):
    pe = _pe()
    script = dict(CELL_OBS_FILES, **{
        "candidate-proxy": "cellobs_candidate_crash.json"})
    staged = _stage_artifact(tmp_path / "loop", _honest_name())
    loop = pe.execute_proxy_experiment(
        staged, run_id=RUN_ID, run_attempt=RUN_ATTEMPT,
        output_dir=tmp_path / "loop-out",
        output_json=tmp_path / "loop.json",
        executor=FakeExecutor(script), comparison=_comparison(),
        budgets=_budgets())
    merged = _run_aggregate(tmp_path, script)
    assert merged["verdict"] == loop["verdict"]
    assert merged["verdict"]["typed_cause"] == "completed-negative"
    assert merged["exit_code"] == 1
    assert merged["evidence_complete"] is True
    assert merged["experiment_positive"] is False


def test_distributed_round_trip_matches_loop(tmp_path):
    pe = _pe()
    arts = {}
    for cell in ("direct", "accepted-proxy", "candidate-proxy"):
        job = tmp_path / ("job-" + cell)
        staged = _stage_artifact(job / "in", _honest_name())
        row = pe.execute_proxy_cell(
            staged, cell=cell, run_id=RUN_ID, run_attempt=RUN_ATTEMPT,
            output_dir=job / "out", output_json=job / "row.json",
            executor=FakeExecutor(CELL_OBS_FILES),
            cell_payload={"scope": "p1c-fake"})
        assert row["exit_code"] == 0
        arts[cell] = _read_json(job / "out" / ("%s.json" % cell))
    merged = _run_aggregate(tmp_path, arts)
    staged = _stage_artifact(tmp_path / "loop", _honest_name())
    loop = pe.execute_proxy_experiment(
        staged, run_id=RUN_ID, run_attempt=RUN_ATTEMPT,
        output_dir=tmp_path / "loop-out",
        output_json=tmp_path / "loop.json",
        executor=FakeExecutor(CELL_OBS_FILES), comparison=_comparison(),
        budgets=_budgets())
    assert merged["verdict"] == loop["verdict"]
    assert merged["observations"] == loop["observations"]
    assert merged["exit_code"] == 0
    assert merged["experiment_positive"] is False


def test_aggregate_f_noterm_is_terminal_evidence_unavailable(tmp_path):
    mapping = dict(CELL_OBS_FILES, **{
        "candidate-proxy": "cellobs_candidate_no_logs.json"})
    row = _run_aggregate(tmp_path, mapping)
    assert row["verdict"] == {
        "experiment_positive": False, "exit_code": 1,
        "evidence_complete": False,
        "typed_cause": "terminal-evidence-unavailable"}
    assert row["exit_code"] == 1
    assert row["experiment_positive"] is False


def test_aggregate_f_accept_is_control_unqualified(tmp_path):
    mapping = dict(CELL_OBS_FILES, **{
        "accepted-proxy": "cellobs_accepted_crash.json"})
    row = _run_aggregate(tmp_path, mapping)
    assert row["verdict"] == {
        "experiment_positive": False, "exit_code": 1,
        "evidence_complete": False, "typed_cause": "control-unqualified"}
    assert row["exit_code"] == 1


def test_aggregate_dual_crash_is_t4_not_t2(tmp_path):
    mapping = {"direct": "cellobs_direct_clean.json",
               "accepted-proxy": "cellobs_accepted_crash.json",
               "candidate-proxy": "cellobs_candidate_crash.json"}
    row = _run_aggregate(tmp_path, mapping)
    assert row["verdict"]["typed_cause"] == "control-unqualified"
    assert row["controls"]["PX-CLIENT-CRASH"] == {
        "accepted-proxy": "fail", "candidate-proxy": "fail"}


@pytest.mark.parametrize("missing,cause", [
    ("accepted-proxy", "missing-evidence"),
    ("candidate-proxy", "missing-evidence"),
    # Direct-cell absence is T3 per the oracle truth table
    # (proxy_policy: direct absence is attribution-unknown); the
    # aggregate reports the real verdict verbatim, never coerced.
    ("direct", "attribution-unknown"),
])
def test_aggregate_missing_cell_is_t6_or_t3(tmp_path, missing, cause):
    mapping = {cell: name for cell, name in CELL_OBS_FILES.items()
               if cell != missing}
    row = _run_aggregate(tmp_path, mapping)
    assert row["verdict"] == {
        "experiment_positive": False, "exit_code": 1,
        "evidence_complete": False, "typed_cause": cause}
    assert row["exit_code"] == 1
    assert row["cells"][missing] == {"status": "not-run"}
    for cell in CELL_OBS_FILES:
        if cell != missing:
            assert row["cells"][cell]["status"] == "executed"
    assert (tmp_path / "out" / "proxy-capsule.json").exists()


def test_aggregate_empty_dir_is_t6(tmp_path):
    row = _run_aggregate(tmp_path, {})
    assert row["verdict"]["typed_cause"] == "missing-evidence"
    assert row["exit_code"] == 1
    assert row["cells"] == {cell: {"status": "not-run"}
                            for cell in CELL_OBS_FILES}
    assert row["observations"] == []
    assert row["artifact"] is None
    assert row["proxy_sha"] is None
    assert row["gates"] == []
    assert row["selection"] is None
    assert (tmp_path / "out" / "proxy-capsule.json").exists()


def test_aggregate_ignores_extra_uploads(tmp_path):
    row = _run_aggregate(tmp_path, CELL_OBS_FILES,
                         extras=["notes.txt", "candidate-proxy.log",
                                 "cell-logs/"])
    assert row["verdict"]["typed_cause"] is None
    assert row["exit_code"] == 0


def _failed_cell(name, text):
    doc = _cellobs(name)
    doc["status"] = "executor-failed"
    doc["observation"] = None
    doc["log_refs"] = []
    doc["infrastructure_error"] = text
    return doc


def test_aggregate_failed_cell_is_t8_verbatim(tmp_path):
    text = "cell candidate-proxy executor failed: fake boom candidate-proxy"
    mapping = dict(CELL_OBS_FILES, **{
        "candidate-proxy": _failed_cell("cellobs_candidate_clean.json",
                                       text)})
    row = _run_aggregate(tmp_path, mapping)
    assert row["verdict"] == {
        "experiment_positive": False, "exit_code": 2,
        "evidence_complete": False, "typed_cause": "usage-or-infrastructure"}
    assert row["exit_code"] == 2
    assert row["infrastructure_error"] == text
    assert row["cause_detail"] == text
    assert row["cells"]["candidate-proxy"]["status"] == "executor-failed"
    assert row["cells"]["direct"]["status"] == "executed"
    assert row["cells"]["accepted-proxy"]["status"] == "executed"
    assert [entry["cell"] for entry in row["observations"]] == [
        "direct", "accepted-proxy"]
    assert (tmp_path / "out" / "proxy-capsule.json").exists()


def test_aggregate_corrupt_cell_is_t8_with_evidence(tmp_path):
    cells = _write_cells(tmp_path / "cells", CELL_OBS_FILES)
    (cells / "candidate-proxy.json").write_bytes(b"{nope")
    row = _run_aggregate(tmp_path, {})
    assert row["verdict"]["typed_cause"] == "usage-or-infrastructure"
    assert row["exit_code"] == 2
    assert row["infrastructure_error"].startswith(
        "cell candidate-proxy staged observation is not valid JSON")
    assert row["cells"]["candidate-proxy"]["status"] == "executor-failed"
    assert [entry["cell"] for entry in row["observations"]] == [
        "direct", "accepted-proxy"]


def test_aggregate_wrong_cell_file_is_t8(tmp_path):
    mapping = dict(CELL_OBS_FILES, **{
        "candidate-proxy": "cellobs_accepted_clean.json"})
    row = _run_aggregate(tmp_path, mapping)
    assert row["verdict"]["typed_cause"] == "usage-or-infrastructure"
    assert row["infrastructure_error"] == (
        "cell candidate-proxy staged observation misbound: expected cell "
        "candidate-proxy, found accepted-proxy")
    assert [entry["cell"] for entry in row["observations"]] == [
        "direct", "accepted-proxy"]


def test_aggregate_run_mismatch_is_t8(tmp_path):
    doc = _cellobs("cellobs_candidate_clean.json")
    doc["run_id"] = RUN_ID + 1
    doc["observation"]["run_id"] = RUN_ID + 1
    row = _run_aggregate(tmp_path, dict(CELL_OBS_FILES, **{
        "candidate-proxy": doc}))
    assert row["verdict"]["typed_cause"] == "usage-or-infrastructure"
    assert row["infrastructure_error"] == (
        "cell candidate-proxy staged observation misbound: expected run "
        "%d/%d, found %d/%d" % (RUN_ID, RUN_ATTEMPT, RUN_ID + 1,
                                RUN_ATTEMPT))


def test_aggregate_selection_disagreement_is_t8(tmp_path):
    doc = _cellobs("cellobs_candidate_clean.json")
    doc["selection"] = dict(doc["selection"])
    doc["selection"]["manifest_sha256"] = "0" * 64
    row = _run_aggregate(tmp_path, dict(CELL_OBS_FILES, **{
        "candidate-proxy": doc}))
    assert row["verdict"]["typed_cause"] == "usage-or-infrastructure"
    assert row["infrastructure_error"] == (
        "cell candidate-proxy staged observation misbound: staged "
        "selection disagrees with cell direct: manifest_sha256")


@pytest.mark.parametrize("edit,phrase", [
    ({"schema": "p11lab-proxy-cell-observation-v9"}, "schema"),
    ({"status": "running"}, "status"),
    ({"observation": {}}, "observation"),
    ({"log_refs": ["other.log"]}, "log_refs"),
    ({"infrastructure_error": "x"}, "infrastructure_error"),
    ({"gates": {}}, "gates"),
    ({"selection": []}, "selection"),
    ({"extra": 1}, "keys must be exactly"),
])
def test_aggregate_bad_cell_schema_is_t8(tmp_path, edit, phrase):
    doc = _cellobs("cellobs_candidate_clean.json")
    doc.update(edit)
    row = _run_aggregate(tmp_path, dict(CELL_OBS_FILES, **{
        "candidate-proxy": doc}))
    assert row["verdict"]["typed_cause"] == "usage-or-infrastructure"
    assert phrase in row["infrastructure_error"]
    assert "cell candidate-proxy staged observation invalid" in row[
        "infrastructure_error"]


def test_aggregate_first_error_wins_gap_closed(tmp_path):
    accepted_text = "cell accepted-proxy executor failed: fake boom"
    mapping = {
        "direct": "cellobs_direct_clean.json",
        "accepted-proxy": _failed_cell("cellobs_accepted_clean.json",
                                      accepted_text),
        "candidate-proxy": "garbage-marker",
    }
    cells = _write_cells(tmp_path / "cells",
                         {cell: value for cell, value in mapping.items()
                          if value != "garbage-marker"})
    (cells / "candidate-proxy.json").write_bytes(b"{nope")
    _write_json(tmp_path / "comparison.json", _comparison())
    _write_json(tmp_path / "budgets.json", _budgets())
    pe = _pe()
    row = pe.aggregate_proxy_experiment(
        cells, run_id=RUN_ID, run_attempt=RUN_ATTEMPT,
        output_dir=tmp_path / "out", output_json=tmp_path / "row.json",
        comparison=_comparison(), budgets=_budgets())
    assert row["verdict"]["typed_cause"] == "usage-or-infrastructure"
    assert row["infrastructure_error"] == accepted_text
    assert [entry["cell"] for entry in row["observations"]] == ["direct"]
    assert row["cells"]["candidate-proxy"]["status"] == "executor-failed"


def test_aggregate_touches_no_runner(monkeypatch, tmp_path):
    def exploding_runner(*args, **kwargs):
        raise AssertionError("aggregate must never execute a cell")

    monkeypatch.setattr(run_module, "run_proxy", exploding_runner)
    monkeypatch.setattr(native_module, "run_native_softhsm", exploding_runner)
    row = _run_aggregate(tmp_path, CELL_OBS_FILES)
    assert row["exit_code"] == 0
    assert row["verdict"]["typed_cause"] is None


def test_aggregate_verdict_matches_rebuilt_oracle(tmp_path):
    mapping = dict(CELL_OBS_FILES, **{
        "candidate-proxy": "cellobs_candidate_crash.json"})
    row = _run_aggregate(tmp_path, mapping)
    rebuilt = proxy_policy.evaluate_proxy_verdict(*_rebuild_oracle_inputs(row))
    assert row["verdict"] == rebuilt


@pytest.mark.parametrize("kwargs,phrase", [
    ({"comparison": {"performed": True}}, "comparison"),
    ({"budgets": {"within_budget": "yes"}}, "budget"),
    ({"uploads_complete": "yes"}, "uploads_complete"),
    ({"cancelled": 1}, "cancelled"),
])
def test_aggregate_rejects_bad_params(tmp_path, kwargs, phrase):
    pe = _pe()
    cells = _write_cells(tmp_path / "cells", CELL_OBS_FILES)
    params = {"comparison": _comparison(), "budgets": _budgets()}
    params.update(kwargs)
    with pytest.raises(ValueError, match=phrase):
        pe.aggregate_proxy_experiment(
            cells, run_id=RUN_ID, run_attempt=RUN_ATTEMPT,
            output_dir=tmp_path / "out", output_json=tmp_path / "row.json",
            **params)


def test_aggregate_rejects_bad_run_ids(tmp_path):
    pe = _pe()
    cells = _write_cells(tmp_path / "cells", CELL_OBS_FILES)
    with pytest.raises(ValueError, match="run identity must be positive"):
        pe.aggregate_proxy_experiment(
            cells, run_id=0, run_attempt=RUN_ATTEMPT,
            output_dir=tmp_path / "out", output_json=tmp_path / "row.json",
            comparison=_comparison(), budgets=_budgets())


def test_aggregate_rejects_missing_cells_dir(tmp_path):
    pe = _pe()
    with pytest.raises(ValueError, match="cells directory is missing"):
        pe.aggregate_proxy_experiment(
            tmp_path / "absent", run_id=RUN_ID, run_attempt=RUN_ATTEMPT,
            output_dir=tmp_path / "out", output_json=tmp_path / "row.json",
            comparison=_comparison(), budgets=_budgets())


def test_aggregate_comparison_required_budgets_default(tmp_path):
    pe = _pe()
    cells = _write_cells(tmp_path / "cells", CELL_OBS_FILES)
    with pytest.raises(TypeError):
        pe.aggregate_proxy_experiment(
            cells, run_id=RUN_ID, run_attempt=RUN_ATTEMPT,
            output_dir=tmp_path / "out", output_json=tmp_path / "row.json",
            budgets=_budgets())
    row = _run_aggregate(tmp_path, CELL_OBS_FILES, budgets=None)
    assert row["budgets"] == {"within_budget": True}
    assert row["verdict"]["typed_cause"] is None


@pytest.mark.parametrize("kwargs,cause", [
    ({"comparison": {"performed": False}}, "missing-evidence"),
    ({"comparison": {"positive": False}}, "completed-negative"),
    ({"budgets": {"within_budget": False}}, "budget-exceeded"),
    ({"uploads_complete": False}, "missing-evidence"),
    ({"cancelled": True}, "missing-evidence"),
])
def test_aggregate_caller_inputs_matrix(tmp_path, kwargs, cause):
    row = _run_aggregate(tmp_path, CELL_OBS_FILES, **kwargs)
    assert row["verdict"]["typed_cause"] == cause
    assert (tmp_path / "out" / "proxy-capsule.json").exists()


def test_aggregate_missing_direct_with_uploads_incomplete_merges_proxies(
        tmp_path):
    mapping = {cell: name for cell, name in CELL_OBS_FILES.items()
               if cell != "direct"}
    row = _run_aggregate(tmp_path, mapping, uploads_complete=False)
    assert row["uploads_complete"] is False
    assert row["verdict"] == {
        "experiment_positive": False, "exit_code": 1,
        "evidence_complete": False, "typed_cause": "missing-evidence"}
    assert row["exit_code"] == 1
    assert row["cells"]["direct"] == {"status": "not-run"}
    assert row["cells"]["accepted-proxy"]["status"] == "executed"
    assert row["cells"]["candidate-proxy"]["status"] == "executed"
    assert [entry["cell"] for entry in row["observations"]] == [
        "accepted-proxy", "candidate-proxy"]
    assert (tmp_path / "out" / "proxy-capsule.json").exists()


# CLI: exact 0/1/2 propagation for both operations.

def test_cli_execute_cell_refusal_returns_one(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    staged = _stage_artifact(tmp_path, _honest_name(), records=[])
    _write_json(tmp_path / "payload.json", _proxy_payload_doc())
    code = main(["proxy", "execute-cell", "--cell", "candidate-proxy",
                 "--artifact", str(staged), "--run-id", str(RUN_ID),
                 "--attempt", str(RUN_ATTEMPT),
                 "--cell-payload", "payload.json",
                 "--output-dir", "out", "--output-json", "row.json"])
    assert code == 1
    row = _read_json(tmp_path / "row.json")
    assert row["cause"] == "PROXY_GATE_SELECTION_REFUSED"
    assert row["experiment_positive"] is False
    assert "PROXY_GATE_SELECTION_REFUSED" in capsys.readouterr().out


def test_cli_execute_cell_missing_flag_exits_two(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit) as status:
        main(["proxy", "execute-cell", "--cell", "candidate-proxy"])
    assert status.value.code == 2


def test_cli_execute_cell_bad_choice_exits_two(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    staged = _stage_artifact(tmp_path, _honest_name())
    with pytest.raises(SystemExit) as status:
        main(["proxy", "execute-cell", "--cell", "second-candidate",
              "--artifact", str(staged), "--run-id", str(RUN_ID),
              "--attempt", str(RUN_ATTEMPT), "--cell-payload", "payload.json",
              "--output-dir", "out", "--output-json", "row.json"])
    assert status.value.code == 2


def test_cli_execute_cell_corrupt_payload_exits_two(tmp_path, monkeypatch,
                                                    capsys):
    monkeypatch.chdir(tmp_path)
    staged = _stage_artifact(tmp_path, _honest_name())
    (tmp_path / "payload.json").write_bytes(b"{nope")
    code = main(["proxy", "execute-cell", "--cell", "candidate-proxy",
                 "--artifact", str(staged), "--run-id", str(RUN_ID),
                 "--attempt", str(RUN_ATTEMPT),
                 "--cell-payload", "payload.json",
                 "--output-dir", "out", "--output-json", "row.json"])
    assert code == 2
    assert "p11lab: " in capsys.readouterr().err


def test_cli_execute_cell_nonpositive_attempt_exits_two(tmp_path, monkeypatch,
                                                        capsys):
    monkeypatch.chdir(tmp_path)
    staged = _stage_artifact(tmp_path, _honest_name())
    _write_json(tmp_path / "payload.json", _proxy_payload_doc())
    code = main(["proxy", "execute-cell", "--cell", "candidate-proxy",
                 "--artifact", str(staged), "--run-id", str(RUN_ID),
                 "--attempt", "0", "--cell-payload", "payload.json",
                 "--output-dir", "out", "--output-json", "row.json"])
    assert code == 2
    assert "p11lab: " in capsys.readouterr().err


def test_cli_execute_cell_missing_prefix_exits_two_no_row(tmp_path, monkeypatch,
                                                          capsys):
    monkeypatch.chdir(tmp_path)
    staged = _stage_artifact(tmp_path, _honest_name())
    _write_json(tmp_path / "payload.json",
                _direct_payload_doc(tmp_path / "absent-prefix"))
    code = main(["proxy", "execute-cell", "--cell", "direct",
                 "--artifact", str(staged), "--run-id", str(RUN_ID),
                 "--attempt", str(RUN_ATTEMPT),
                 "--cell-payload", "payload.json",
                 "--output-dir", "out", "--output-json", "row.json"])
    assert code == 2
    assert capsys.readouterr().err.strip() == (
        "p11lab: staged installed_prefix invalid: "
        "installation prefix is not a directory")
    assert not (tmp_path / "row.json").exists()
    assert not (tmp_path / "out").exists()


def _stage_cli_cells(tmp_path):
    cells = tmp_path / "cells"
    for cell, name in CELL_OBS_FILES.items():
        target = cells / ("%s.json" % cell)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((FIXTURES / name).read_bytes())
    _write_json(tmp_path / "comparison.json", _comparison())
    _write_json(tmp_path / "budgets.json", _budgets())
    return cells


def _aggregate_argv(cells, *extra):
    return ["proxy", "aggregate", "--cells-dir", str(cells),
            "--run-id", str(RUN_ID), "--attempt", str(RUN_ATTEMPT),
            "--comparison", "comparison.json", "--budgets", "budgets.json",
            "--output-dir", "out", "--output-json", "row.json", *extra]


def test_cli_aggregate_clean_returns_zero(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    cells = _stage_cli_cells(tmp_path)
    code = main(_aggregate_argv(cells))
    assert code == 0
    row = _read_json(tmp_path / "row.json")
    assert row["exit_code"] == 0
    assert row["verdict"]["typed_cause"] is None
    assert json.loads(capsys.readouterr().out)["exit_code"] == 0
    assert (tmp_path / "out" / "proxy-capsule.json").exists()


def test_cli_aggregate_missing_cell_returns_one(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    cells = _stage_cli_cells(tmp_path)
    (cells / "candidate-proxy.json").unlink()
    code = main(_aggregate_argv(cells))
    assert code == 1
    row = _read_json(tmp_path / "row.json")
    assert row["verdict"]["typed_cause"] == "missing-evidence"
    assert row["evidence_complete"] is False
    assert "missing-evidence" in capsys.readouterr().out


def test_cli_aggregate_corrupt_cell_returns_two_row_written(
        tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    cells = _stage_cli_cells(tmp_path)
    (cells / "candidate-proxy.json").write_bytes(b"{nope")
    code = main(_aggregate_argv(cells))
    assert code == 2
    row = _read_json(tmp_path / "row.json")
    assert row["verdict"]["typed_cause"] == "usage-or-infrastructure"
    assert "usage-or-infrastructure" in capsys.readouterr().out
    assert (tmp_path / "out" / "proxy-capsule.json").exists()


@pytest.mark.parametrize("extra,cause", [
    (["--cancelled"], "missing-evidence"),
    (["--uploads-incomplete"], "missing-evidence"),
])
def test_cli_aggregate_flags(tmp_path, monkeypatch, extra, cause):
    monkeypatch.chdir(tmp_path)
    cells = _stage_cli_cells(tmp_path)
    code = main(_aggregate_argv(cells, *extra))
    assert code == 1
    assert _read_json(tmp_path / "row.json")["verdict"][
        "typed_cause"] == cause


def test_cli_aggregate_missing_flag_exits_two(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit) as status:
        main(["proxy", "aggregate", "--cells-dir", "cells"])
    assert status.value.code == 2


def test_cli_proxy_help_lists_three_ops(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit) as status:
        main(["proxy", "--help"])
    assert status.value.code == 0
    out = capsys.readouterr().out
    assert "execute-cell" in out
    assert "aggregate" in out


# Regression pins: P1a/P1b entries unchanged; new entries shaped.

def test_execute_proxy_signature_unchanged():
    pe = _pe()
    assert list(inspect.signature(pe.execute_proxy).parameters) == [
        "artifact", "run_id", "run_attempt", "output_dir", "output_json",
        "expected_proxy_identity"]


def test_execute_proxy_experiment_signature_unchanged():
    pe = _pe()
    assert list(inspect.signature(
        pe.execute_proxy_experiment).parameters) == [
        "artifact", "run_id", "run_attempt", "output_dir", "output_json",
        "executor", "cell_payloads", "comparison", "budgets",
        "uploads_complete", "cancelled", "expected_proxy_identity"]


def test_new_entry_signatures_exact():
    pe = _pe()
    assert list(inspect.signature(pe.execute_proxy_cell).parameters) == [
        "artifact", "cell", "run_id", "run_attempt", "output_dir",
        "output_json", "executor", "cell_payload",
        "expected_proxy_identity"]
    assert list(inspect.signature(
        pe.execute_proxy_cell_staged).parameters) == [
        "artifact", "cell", "run_id", "run_attempt", "output_dir",
        "output_json", "cell_payload_path", "expected_proxy_identity"]
    assert list(inspect.signature(
        pe.aggregate_proxy_experiment).parameters) == [
        "cells_dir", "run_id", "run_attempt", "output_dir", "output_json",
        "comparison", "budgets", "uploads_complete", "cancelled"]
    assert list(inspect.signature(
        pe.aggregate_proxy_experiment_staged).parameters) == [
        "cells_dir", "run_id", "run_attempt", "output_dir", "output_json",
        "comparison_path", "budgets_path", "uploads_complete", "cancelled"]


def test_aggregate_takes_no_executor():
    pe = _pe()
    params = inspect.signature(pe.aggregate_proxy_experiment).parameters
    assert "executor" not in params
    assert "cell_payloads" not in params
    assert "cell_payload" not in params


def test_oracle_identity_shared():
    pe = _pe()
    assert pe.evaluate_proxy_verdict is proxy_policy.evaluate_proxy_verdict


def test_docs_carry_p1c_operational_section():
    text = (Path(__file__).resolve().parent.parent / "docs"
            / "proxy-ci.md").read_text(encoding="utf-8")
    for phrase in ("execute-cell", "proxy aggregate",
                   "p11lab-proxy-cell-observation-v1", "re-executes nothing",
                   "usage-or-infrastructure", "selection agreement"):
        assert phrase in text


# Local proof (real Docker, docker-presence skip) + env-gated live design.

def _docker_ready():
    if shutil.which("docker") is None:
        return False
    probe = subprocess.run(["docker", "info"], capture_output=True, timeout=60)
    return probe.returncode == 0


def test_local_proof_cli_cell_hits_real_production_path(tmp_path, monkeypatch):
    if not _docker_ready():
        pytest.skip("no local Docker daemon")
    monkeypatch.chdir(tmp_path)
    staged = _stage_artifact(tmp_path, _honest_name())
    _write_json(tmp_path / "payload.json", _proxy_payload_doc())
    code = main(["proxy", "execute-cell", "--cell", "candidate-proxy",
                 "--artifact", str(staged), "--run-id", str(RUN_ID),
                 "--attempt", str(RUN_ATTEMPT), "--cell-payload", "payload.json",
                 "--output-dir", "out", "--output-json", "row.json"])
    assert code == 2
    row = _read_json(tmp_path / "row.json")
    assert row["exit_code"] == 2
    assert "Docker operation failed: image" in row["cause_detail"]
    doc = _read_json(tmp_path / "out" / "candidate-proxy.json")
    assert doc["status"] == "executor-failed"


def test_live_distributed_cells_env_gated(tmp_path):
    """Live distributed dispatch: designed here, never run in this slice.

    Requires P11LAB_PROXY_CELLS_LIVE=1 plus a qualified live environment
    (reachable daemon images, installed native bundle, retained cell
    logs); without the gate it skips and the hermetic suite stays green.
    The staged bogus images below can never resolve, so the honest live
    outcome is T8 at the cell job, surfaced verbatim at the aggregate.
    """
    if os.environ.get("P11LAB_PROXY_CELLS_LIVE") != "1":
        pytest.skip("live dispatch not enabled")
    if not _docker_ready():
        pytest.skip("no local Docker daemon")
    pe = _pe()
    staged = _stage_artifact(tmp_path / "in", _honest_name())
    payload_path = tmp_path / "payload.json"
    _write_json(payload_path, _proxy_payload_doc())
    row = pe.execute_proxy_cell_staged(
        staged, cell="candidate-proxy", run_id=RUN_ID,
        run_attempt=RUN_ATTEMPT, output_dir=tmp_path / "out",
        output_json=tmp_path / "row.json", cell_payload_path=payload_path)
    assert row["exit_code"] == 2
    assert row["typed_cause"] == "usage-or-infrastructure"
    cells = _write_cells(tmp_path / "cells", {
        "candidate-proxy": _read_json(
            tmp_path / "out" / "candidate-proxy.json")})
    merged = pe.aggregate_proxy_experiment(
        cells, run_id=RUN_ID, run_attempt=RUN_ATTEMPT,
        output_dir=tmp_path / "merge-out",
        output_json=tmp_path / "merge.json", comparison=_comparison(),
        budgets=_budgets())
    assert merged["verdict"]["typed_cause"] == "usage-or-infrastructure"
    assert merged["infrastructure_error"] == row["cause_detail"]
