"""Proxy execute cells + verdict + capsule (P1b): executor seam past the gates.

Hermetic by construction: scripted cell-observation fixtures under
tests/fixtures/proxy_execute/ plus an injected fake executor drive the
crash matrix (F-CRASH/F-NOTERM/F-ACCEPT) through the REAL
`evaluate_proxy_verdict` oracle. The production executor delegates to
the real runners (`run_proxy`/`run_native_softhsm`) and is proven at
the adapter boundary with monkeypatched runners plus one real-Docker
local proof (docker-presence skip, never env-gated, never blocking
hermetic green). Full live dispatch is env-gated by design and not run.

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

from p11lab import native as native_module
from p11lab import proxy_derivative as derivative_module
from p11lab import proxy_policy
from p11lab import run as run_module
from p11lab.models import ArtifactRef, ProxyBuildIdentityV1, RunResult, RunSpec
from p11lab.round_core.inputs import canonical
from p11lab import tls as tls_module

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "proxy_execute"
RUN_ID = 888881
RUN_ATTEMPT = 3
AUTHORITY = {
    "repository_id": 8888,
    "repository_full_name": "example/proxy-cells-caller",
    "producer_job_id": "888882",
    "artifact_id": 888883,
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


def _obs(name, *, run_id=RUN_ID, run_attempt=RUN_ATTEMPT):
    """Load one scripted observation fixture, bound to this invocation."""
    pe = _pe()
    return pe.CellObservation.from_dict(_read_json(FIXTURES / name),
                                       run_id=run_id, run_attempt=run_attempt)


def _comparison(**overrides):
    row = {"performed": True, "positive": True, "coverage_positive": True}
    row.update(overrides)
    return row


def _budgets(**overrides):
    row = {"within_budget": True}
    row.update(overrides)
    return row


class FakeExecutor:
    """Scripted CellExecutor double (FlowEngine idiom): fixture cells in."""

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
        row = _read_json(FIXTURES / scripted) if isinstance(scripted, str) \
            else copy.deepcopy(scripted)
        return pe.CellObservation.from_dict(
            row, run_id=request.run_id, run_attempt=request.run_attempt)


CLEAN_SCRIPT = {
    "direct": "cell_direct_clean.json",
    "accepted-proxy": "cell_accepted_clean.json",
    "candidate-proxy": "cell_candidate_clean.json",
}


def _run_experiment(tmp_path, script, **kwargs):
    pe = _pe()
    staged = _stage_artifact(tmp_path / "in", _honest_name(),
                             **kwargs.pop("stage", {}))
    params = {"executor": FakeExecutor(script, **kwargs.pop("fake", {})),
              "comparison": _comparison(**kwargs.pop("comparison", {})),
              "budgets": _budgets(**kwargs.pop("budgets", {}))}
    params.update(kwargs)
    return pe.execute_proxy_experiment(
        staged, run_id=RUN_ID, run_attempt=RUN_ATTEMPT,
        output_dir=tmp_path / "out", output_json=tmp_path / "row.json",
        **params)


# Seam vocabulary: roster, requests, observation binding.

def test_cells_roster_exact_order():
    pe = _pe()
    assert pe.CELLS == ("direct", "accepted-proxy", "candidate-proxy")


def test_crash_control_pin():
    pe = _pe()
    assert pe.CRASH_CONTROL == "PX-CLIENT-CRASH"


@pytest.mark.parametrize("name", [
    "cell_direct_clean.json",
    "cell_accepted_clean.json",
    "cell_candidate_clean.json",
    "cell_candidate_crash.json",
    "cell_candidate_no_logs.json",
    "cell_accepted_crash.json",
])
def test_observation_fixture_binds_run_cell_logs(name):
    obs = _obs(name)
    assert obs.run_id == RUN_ID
    assert obs.run_attempt == RUN_ATTEMPT
    assert obs.cell == _read_json(FIXTURES / name)["cell"]
    assert obs.logs_available == bool(obs.log_refs)
    record = obs.to_dict()
    assert record["run_id"] == RUN_ID
    assert record["run_attempt"] == RUN_ATTEMPT
    assert record["cell"] == obs.cell
    assert record["log_refs"] == list(obs.log_refs)


def test_observation_crash_triple_typed():
    crash = _obs("cell_candidate_crash.json")
    assert crash.unexpected_death is True
    assert crash.logs_available is True
    assert crash.terminal_evidence_complete is True
    no_logs = _obs("cell_candidate_no_logs.json")
    assert no_logs.unexpected_death is True
    assert no_logs.logs_available is False
    assert no_logs.terminal_evidence_complete is False
    assert no_logs.log_refs == ()


def test_observation_rejects_available_logs_without_refs():
    pe = _pe()
    row = _read_json(FIXTURES / "cell_candidate_clean.json")
    row["log_refs"] = []
    with pytest.raises(ValueError, match="unbound"):
        pe.CellObservation.from_dict(row, run_id=RUN_ID,
                                     run_attempt=RUN_ATTEMPT)


def test_observation_rejects_refs_without_available_logs():
    pe = _pe()
    row = _read_json(FIXTURES / "cell_candidate_no_logs.json")
    row["log_refs"] = ["cell-logs/candidate-proxy/client.log"]
    with pytest.raises(ValueError, match="unbound"):
        pe.CellObservation.from_dict(row, run_id=RUN_ID,
                                     run_attempt=RUN_ATTEMPT)


@pytest.mark.parametrize("edit", [
    {"cell": "second-candidate"},
    {"cell": "direct", "admitted": 1},
    {"cell": "direct", "complete": "yes"},
    {"cell": "direct", "findings": "app-exit:1"},
    {"cell": "direct", "findings": [7]},
    {"cell": "direct", "log_refs": ["ok", 7]},
    {"cell": "direct", "unexpected_death": "no"},
])
def test_observation_rejects_bad_shapes(edit):
    pe = _pe()
    row = _read_json(FIXTURES / "cell_direct_clean.json")
    row.update(edit)
    with pytest.raises(ValueError):
        pe.CellObservation.from_dict(row, run_id=RUN_ID,
                                     run_attempt=RUN_ATTEMPT)


def test_observation_rejects_self_asserted_run():
    pe = _pe()
    row = _read_json(FIXTURES / "cell_direct_clean.json")
    row["run_id"] = RUN_ID
    with pytest.raises(ValueError, match="run"):
        pe.CellObservation.from_dict(row, run_id=RUN_ID,
                                     run_attempt=RUN_ATTEMPT)


def test_observation_rejects_extra_keys():
    pe = _pe()
    row = _read_json(FIXTURES / "cell_direct_clean.json")
    row["verdict"] = "pass"
    with pytest.raises(ValueError, match="keys"):
        pe.CellObservation.from_dict(row, run_id=RUN_ID,
                                     run_attempt=RUN_ATTEMPT)


def test_cell_request_binds_invocation():
    pe = _pe()
    request = pe.CellRequest("candidate-proxy", RUN_ID, RUN_ATTEMPT,
                             payload={"note": "fake-only"})
    assert request.cell == "candidate-proxy"
    assert request.run_id == RUN_ID
    assert request.run_attempt == RUN_ATTEMPT
    assert request.payload == {"note": "fake-only"}


@pytest.mark.parametrize("kwargs", [
    {"cell": "no-such-cell", "run_id": RUN_ID, "run_attempt": RUN_ATTEMPT},
    {"cell": "direct", "run_id": 0, "run_attempt": RUN_ATTEMPT},
    {"cell": "direct", "run_id": RUN_ID, "run_attempt": -1},
    {"cell": "direct", "run_id": "888881", "run_attempt": RUN_ATTEMPT},
    {"cell": "direct", "run_id": RUN_ID, "run_attempt": RUN_ATTEMPT,
     "payload": ["not-a-mapping"]},
])
def test_cell_request_rejects_bad_bind(kwargs):
    pe = _pe()
    with pytest.raises(ValueError):
        pe.CellRequest(**kwargs)


# Production conversion: real RunResult in, bound observation out.

def _result(returncode, *, lifecycle=(), cleanup=(), tmp_path=None):
    root = Path(tmp_path) if tmp_path is not None else Path(".")
    return RunResult(app_returncode=returncode,
                     lifecycle_errors=tuple(lifecycle),
                     cleanup_errors=tuple(cleanup), exit_code=0,
                     receipt_path=root / "receipt.json")


def _request(cell="candidate-proxy"):
    pe = _pe()
    return pe.CellRequest(cell, RUN_ID, RUN_ATTEMPT)


def test_conversion_clean_result_is_clean_observation(tmp_path):
    pe = _pe()
    obs = pe.observation_from_result(
        _request(), _result(0, tmp_path=tmp_path),
        log_refs=["cell-logs/candidate-proxy/client.log"])
    assert obs.cell == "candidate-proxy"
    assert (obs.run_id, obs.run_attempt) == (RUN_ID, RUN_ATTEMPT)
    assert obs.admitted is True
    assert obs.complete is True
    assert obs.unexpected_death is False
    assert obs.findings == ()
    assert obs.logs_available is True
    assert obs.terminal_evidence_complete is True


def test_conversion_signal_death_with_logs_is_crash(tmp_path):
    pe = _pe()
    obs = pe.observation_from_result(
        _request(), _result(137, tmp_path=tmp_path),
        log_refs=["cell-logs/candidate-proxy/client.log"])
    assert obs.complete is True
    assert obs.unexpected_death is True
    assert obs.terminal_evidence_complete is True
    assert obs.findings == ("app-exit:137",)


def test_conversion_signal_death_without_logs_is_noterm(tmp_path):
    pe = _pe()
    obs = pe.observation_from_result(_request(), _result(137, tmp_path=tmp_path),
                                     log_refs=[])
    assert obs.unexpected_death is True
    assert obs.logs_available is False
    assert obs.terminal_evidence_complete is False


def test_conversion_timeout_counts_as_death(tmp_path):
    pe = _pe()
    obs = pe.observation_from_result(
        _request(), _result(124, tmp_path=tmp_path), log_refs=["kept.log"])
    assert obs.unexpected_death is True
    assert obs.complete is True


def test_conversion_nonzero_exit_is_finding_not_death(tmp_path):
    pe = _pe()
    obs = pe.observation_from_result(
        _request("direct"), _result(1, tmp_path=tmp_path),
        log_refs=["cell-logs/direct/client.log"])
    assert obs.unexpected_death is False
    assert obs.complete is True
    assert obs.findings == ("app-exit:1",)
    assert obs.attribution_usable is False


def test_conversion_unobserved_app_is_incomplete(tmp_path):
    pe = _pe()
    obs = pe.observation_from_result(_request(), _result(None, tmp_path=tmp_path),
                                     log_refs=["kept.log"])
    assert obs.complete is False
    assert obs.unexpected_death is False
    assert obs.terminal_evidence_complete is False


def test_conversion_lifecycle_errors_incomplete_but_retained(tmp_path):
    pe = _pe()
    obs = pe.observation_from_result(
        _request(), _result(0, lifecycle=["volume-leak:vol-1"], tmp_path=tmp_path),
        log_refs=["kept.log"])
    assert obs.complete is False
    assert "lifecycle:volume-leak:vol-1" in obs.findings
    assert obs.unexpected_death is False


def test_conversion_rejects_bad_log_refs(tmp_path):
    pe = _pe()
    with pytest.raises(ValueError, match="log_refs"):
        pe.observation_from_result(_request(), _result(0, tmp_path=tmp_path),
                                   log_refs=["kept.log", 7])


# Production executor: thin adapter over the real runners.

def _proxy_payload():
    return {"spec": object(), "plan": {"descriptor": {}, "host": True},
            "log_refs": ["cell-logs/x/client.log"]}


def _direct_payload():
    return {"spec": object(), "installed": object(),
            "log_refs": ["cell-logs/direct/client.log"]}


@pytest.mark.parametrize("cell", ["accepted-proxy", "candidate-proxy"])
def test_production_executor_calls_run_proxy(monkeypatch, tmp_path, cell):
    pe = _pe()
    seen = {}

    def fake_run_proxy(spec, plan):
        seen["spec"] = spec
        seen["plan"] = plan
        return _result(0, tmp_path=tmp_path)

    monkeypatch.setattr(run_module, "run_proxy", fake_run_proxy)
    payload = _proxy_payload()
    request = pe.CellRequest(cell, RUN_ID, RUN_ATTEMPT, payload=payload)
    obs = pe.ProductionCellExecutor().run_cell(request)
    assert seen["spec"] is payload["spec"]
    assert seen["plan"] == payload["plan"]
    assert obs.cell == cell
    assert (obs.run_id, obs.run_attempt) == (RUN_ID, RUN_ATTEMPT)
    assert obs.complete is True
    assert obs.unexpected_death is False


def test_production_executor_calls_run_native_for_direct(monkeypatch, tmp_path):
    pe = _pe()
    seen = {}

    def fake_run_native(spec, installed):
        seen["spec"] = spec
        seen["installed"] = installed
        return _result(0, tmp_path=tmp_path)

    monkeypatch.setattr(native_module, "run_native_softhsm", fake_run_native)
    payload = _direct_payload()
    request = pe.CellRequest("direct", RUN_ID, RUN_ATTEMPT, payload=payload)
    obs = pe.ProductionCellExecutor().run_cell(request)
    assert seen["spec"] is payload["spec"]
    assert seen["installed"] is payload["installed"]
    assert obs.cell == "direct"
    assert obs.attribution_usable is True


def test_production_executor_converts_runner_crash(monkeypatch, tmp_path):
    pe = _pe()
    monkeypatch.setattr(run_module, "run_proxy",
                        lambda spec, plan: _result(137, tmp_path=tmp_path))
    request = pe.CellRequest("candidate-proxy", RUN_ID, RUN_ATTEMPT,
                             payload=_proxy_payload())
    obs = pe.ProductionCellExecutor().run_cell(request)
    assert obs.unexpected_death is True
    assert obs.terminal_evidence_complete is True
    assert obs.log_refs == ("cell-logs/x/client.log",)


@pytest.mark.parametrize("payload", [
    None,
    {"plan": {}},
    {"spec": object()},
    {"spec": object(), "plan": {}, "log_refs": "kept.log"},
])
def test_production_executor_rejects_bad_payload(payload):
    pe = _pe()
    request = pe.CellRequest("candidate-proxy", RUN_ID, RUN_ATTEMPT,
                             payload=payload)
    with pytest.raises(ValueError, match="payload|log_refs"):
        pe.ProductionCellExecutor().run_cell(request)


def test_production_executor_rejects_direct_without_installed():
    pe = _pe()
    request = pe.CellRequest("direct", RUN_ID, RUN_ATTEMPT,
                             payload={"spec": object()})
    with pytest.raises(ValueError, match="payload"):
        pe.ProductionCellExecutor().run_cell(request)


# Controls and verdict inputs: real oracle, no fork.

def _observations(**overrides):
    obs = {"direct": _obs("cell_direct_clean.json"),
           "accepted-proxy": _obs("cell_accepted_clean.json"),
           "candidate-proxy": _obs("cell_candidate_clean.json")}
    obs.update(overrides)
    return obs


def test_controls_default_all_pass_seven_roster():
    pe = _pe()
    controls = pe.build_controls(_observations())
    assert set(controls) == set(CONTROLS)
    for control in CONTROLS:
        assert controls[control] == {"accepted-proxy": "pass",
                                     "candidate-proxy": "pass"}


def test_controls_candidate_crash_fails_candidate_only():
    pe = _pe()
    controls = pe.build_controls(_observations(
        **{"candidate-proxy": _obs("cell_candidate_crash.json")}))
    assert controls["PX-CLIENT-CRASH"] == {"accepted-proxy": "pass",
                                          "candidate-proxy": "fail"}
    for control in CONTROLS:
        if control != "PX-CLIENT-CRASH":
            assert controls[control]["candidate-proxy"] == "pass"


def test_controls_accepted_crash_fails_accepted():
    pe = _pe()
    controls = pe.build_controls(_observations(
        **{"accepted-proxy": _obs("cell_accepted_crash.json")}))
    assert controls["PX-CLIENT-CRASH"] == {"accepted-proxy": "fail",
                                          "candidate-proxy": "pass"}


def test_controls_death_without_logs_still_fails_that_proxy():
    pe = _pe()
    controls = pe.build_controls(_observations(
        **{"candidate-proxy": _obs("cell_candidate_no_logs.json")}))
    assert controls["PX-CLIENT-CRASH"]["candidate-proxy"] == "fail"


def test_controls_rejects_unknown_cells():
    pe = _pe()
    obs = _observations()
    obs["second-candidate"] = obs["direct"]
    with pytest.raises(ValueError, match="cell"):
        pe.build_controls(obs)


def test_verdict_function_is_the_oracle():
    pe = _pe()
    assert pe.evaluate_proxy_verdict is proxy_policy.evaluate_proxy_verdict


def test_module_defines_no_verdict_fork():
    source = Path(_pe().__file__).read_text(encoding="utf-8")
    assert "def evaluate_proxy_verdict" not in source


def test_verdict_inputs_shape_for_oracle():
    pe = _pe()
    built = pe.build_verdict_inputs(_observations(),
                                    comparison=_comparison(),
                                    budgets=_budgets())
    assert set(built) == {"cells", "controls", "budgets"}
    assert built["cells"]["direct"] == {
        "admitted": True, "complete": True, "attribution_usable": True,
        "findings": []}
    assert built["cells"]["candidate-proxy"] == {
        "admitted": True, "complete": True,
        "terminal_evidence_complete": True}
    assert built["cells"]["comparison"] == _comparison()
    assert built["cells"]["cancelled"] is False
    assert built["cells"]["uploads_complete"] is True
    assert built["cells"]["infrastructure_error"] is None
    assert built["budgets"] == {"within_budget": True}


@pytest.mark.parametrize("edit", [
    {"performed": 1},
    {"positive": "yes"},
    {"coverage_positive": None},
    {"extra": True},
])
def test_verdict_inputs_reject_bad_comparison(edit):
    pe = _pe()
    comparison = _comparison()
    comparison.update(edit)
    with pytest.raises(ValueError, match="comparison"):
        pe.build_verdict_inputs(_observations(), comparison=comparison,
                                budgets=_budgets())


def test_verdict_inputs_reject_bad_budgets():
    pe = _pe()
    with pytest.raises(ValueError, match="budget"):
        pe.build_verdict_inputs(_observations(), comparison=_comparison(),
                                budgets={"within_budget": "yes"})


def _obs_edit(name, *, run_id=RUN_ID, run_attempt=RUN_ATTEMPT, **edits):
    """One scripted observation with explicit field edits (test-visible)."""
    pe = _pe()
    row = _read_json(FIXTURES / name)
    row.update(edits)
    return pe.CellObservation.from_dict(row, run_id=run_id,
                                       run_attempt=run_attempt)


def _oracle_cases():
    t1 = (_observations(), _comparison(), _budgets(), {},
          {"experiment_positive": True, "exit_code": 0,
           "evidence_complete": True, "typed_cause": None})
    t2 = (_observations(**{"candidate-proxy": _obs("cell_candidate_crash.json")}),
          _comparison(), _budgets(), {},
          {"experiment_positive": False, "exit_code": 1,
           "evidence_complete": True, "typed_cause": "completed-negative"})
    t3 = (_observations(**{"direct": _obs_edit(
        "cell_direct_clean.json", attribution_usable=False)}),
        _comparison(), _budgets(), {},
        {"experiment_positive": False, "exit_code": 1,
         "evidence_complete": False, "typed_cause": "attribution-unknown"})
    return [t1, t2, t3]


def test_verdict_passthrough_t1_exact():
    pe = _pe()
    observations, comparison, budgets, extra, expected = _oracle_cases()[0]
    built = pe.build_verdict_inputs(observations, comparison=comparison,
                                    budgets=budgets, **extra)
    assert pe.evaluate_proxy_verdict(
        built["cells"], built["controls"], built["budgets"]) == expected
    assert proxy_policy.evaluate_proxy_verdict(
        built["cells"], built["controls"], built["budgets"]) == expected


def test_verdict_passthrough_t2_exact():
    pe = _pe()
    observations, comparison, budgets, extra, expected = _oracle_cases()[1]
    built = pe.build_verdict_inputs(observations, comparison=comparison,
                                    budgets=budgets, **extra)
    assert pe.evaluate_proxy_verdict(
        built["cells"], built["controls"], built["budgets"]) == expected
    assert proxy_policy.evaluate_proxy_verdict(
        built["cells"], built["controls"], built["budgets"]) == expected


def test_verdict_passthrough_t3_exact():
    pe = _pe()
    observations, comparison, budgets, extra, expected = _oracle_cases()[2]
    built = pe.build_verdict_inputs(observations, comparison=comparison,
                                    budgets=budgets, **extra)
    assert pe.evaluate_proxy_verdict(
        built["cells"], built["controls"], built["budgets"]) == expected
    assert proxy_policy.evaluate_proxy_verdict(
        built["cells"], built["controls"], built["budgets"]) == expected


# Experiment matrix: fake executor, staged artifact, real verdict, capsule.

def _crash_script():
    return dict(CLEAN_SCRIPT, **{
        "candidate-proxy": "cell_candidate_crash.json"})


def _capsule(tmp_path):
    return _read_json(tmp_path / "out" / "proxy-capsule.json")


def test_experiment_f_crash_is_completed_negative(tmp_path):
    row = _run_experiment(tmp_path, _crash_script())
    assert row["phase"] == "executed"
    assert row["status"] == "executed"
    assert row["cause"] == "PROXY_EXECUTE_OK"
    assert row["exit_code"] == 1
    assert row["verdict"] == {
        "experiment_positive": False, "exit_code": 1,
        "evidence_complete": True, "typed_cause": "completed-negative"}
    assert row["evidence_complete"] is True
    assert row["experiment_positive"] is False
    assert row["live_qualified"] is False
    assert row["image_usable"] is False
    capsule = _capsule(tmp_path)
    assert capsule["experiment_positive"] is False
    assert capsule["verdict"] == row["verdict"]
    assert capsule["evidence_complete"] is True


def test_experiment_f_crash_binds_run_cell_logs(tmp_path):
    row = _run_experiment(tmp_path, _crash_script())
    bound = [entry for entry in row["observations"]
             if entry["cell"] == "candidate-proxy"]
    assert len(bound) == 1
    assert bound[0]["run_id"] == RUN_ID
    assert bound[0]["run_attempt"] == RUN_ATTEMPT
    assert bound[0]["unexpected_death"] is True
    assert bound[0]["logs_available"] is True
    assert bound[0]["log_refs"] == [
        "cell-logs/candidate-proxy/client.log",
        "cell-logs/candidate-proxy/daemon.log"]
    capsule = _capsule(tmp_path)
    assert capsule["cells"]["candidate-proxy"]["unexpected_death"] is True
    assert capsule["cells"]["candidate-proxy"]["log_refs"] == (
        bound[0]["log_refs"])
    assert row["controls"]["PX-CLIENT-CRASH"] == {
        "accepted-proxy": "pass", "candidate-proxy": "fail"}


def test_experiment_f_noterm_is_terminal_evidence_unavailable(tmp_path):
    script = dict(CLEAN_SCRIPT, **{
        "candidate-proxy": "cell_candidate_no_logs.json"})
    row = _run_experiment(tmp_path, script)
    assert row["verdict"] == {
        "experiment_positive": False, "exit_code": 1,
        "evidence_complete": False,
        "typed_cause": "terminal-evidence-unavailable"}
    assert row["exit_code"] == 1
    assert row["evidence_complete"] is False
    assert row["experiment_positive"] is False


def test_experiment_f_accept_is_control_unqualified(tmp_path):
    script = dict(CLEAN_SCRIPT, **{
        "accepted-proxy": "cell_accepted_crash.json"})
    row = _run_experiment(tmp_path, script)
    assert row["verdict"] == {
        "experiment_positive": False, "exit_code": 1,
        "evidence_complete": False, "typed_cause": "control-unqualified"}
    assert row["exit_code"] == 1
    assert row["experiment_positive"] is False


def test_experiment_tpx_first_candidate_claim_needs_accepted_pass(tmp_path):
    script = {"direct": "cell_direct_clean.json",
              "accepted-proxy": "cell_accepted_crash.json",
              "candidate-proxy": "cell_candidate_crash.json"}
    row = _run_experiment(tmp_path, script)
    assert row["verdict"]["typed_cause"] == "control-unqualified"
    assert row["verdict"]["evidence_complete"] is False
    assert row["controls"]["PX-CLIENT-CRASH"] == {
        "accepted-proxy": "fail", "candidate-proxy": "fail"}


def test_experiment_t6_on_incomplete_cell(tmp_path):
    edited = _read_json(FIXTURES / "cell_candidate_clean.json")
    edited.update({"complete": False, "terminal_evidence_complete": False})
    script = dict(CLEAN_SCRIPT, **{"candidate-proxy": edited})
    row = _run_experiment(tmp_path, script)
    assert row["verdict"] == {
        "experiment_positive": False, "exit_code": 1,
        "evidence_complete": False, "typed_cause": "missing-evidence"}


def test_experiment_t6_on_unperformed_comparison(tmp_path):
    row = _run_experiment(tmp_path, CLEAN_SCRIPT, comparison={"performed": False})
    assert row["verdict"]["typed_cause"] == "missing-evidence"
    assert row["comparison_positive"] is None


def test_experiment_t6_on_incomplete_uploads(tmp_path):
    row = _run_experiment(tmp_path, CLEAN_SCRIPT, uploads_complete=False)
    assert row["verdict"]["typed_cause"] == "missing-evidence"


def test_experiment_t6_on_cancelled(tmp_path):
    row = _run_experiment(tmp_path, CLEAN_SCRIPT, cancelled=True)
    assert row["verdict"]["typed_cause"] == "missing-evidence"


def test_experiment_t3_on_direct_unusable(tmp_path):
    edited = _read_json(FIXTURES / "cell_direct_clean.json")
    edited["attribution_usable"] = False
    script = dict(CLEAN_SCRIPT, **{"direct": edited})
    row = _run_experiment(tmp_path, script)
    assert row["verdict"]["typed_cause"] == "attribution-unknown"
    assert row["exit_code"] == 1


def test_experiment_t7_on_budget_exceeded(tmp_path):
    row = _run_experiment(tmp_path, CLEAN_SCRIPT,
                          budgets={"within_budget": False})
    assert row["verdict"] == {
        "experiment_positive": False, "exit_code": 1,
        "evidence_complete": False, "typed_cause": "budget-exceeded"}


def test_experiment_t2_on_negative_comparison(tmp_path):
    row = _run_experiment(tmp_path, CLEAN_SCRIPT,
                          comparison={"positive": False})
    assert row["verdict"]["typed_cause"] == "completed-negative"
    assert row["evidence_complete"] is True
    assert row["comparison_positive"] is False


def test_experiment_t1_shaped_verdict_exact_but_unclaimed(tmp_path):
    row = _run_experiment(tmp_path, CLEAN_SCRIPT)
    oracle = proxy_policy.evaluate_proxy_verdict(
        *_rebuild_oracle_inputs(row))
    assert oracle == {"experiment_positive": True, "exit_code": 0,
                      "evidence_complete": True, "typed_cause": None}
    assert row["verdict"] == oracle
    assert row["exit_code"] == 0
    assert row["experiment_positive"] is False
    assert row["live_qualified"] is False
    assert row["evidence_admitted"] is True
    capsule = _capsule(tmp_path)
    assert capsule["experiment_positive"] is False
    assert capsule["verdict"] == oracle
    assert any("live qualification" in note.lower()
               for note in capsule["limitations"])


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


def test_experiment_verdict_matches_rebuilt_oracle(tmp_path):
    row = _run_experiment(tmp_path, _crash_script())
    rebuilt = proxy_policy.evaluate_proxy_verdict(*_rebuild_oracle_inputs(row))
    assert row["verdict"] == rebuilt


def test_experiment_t8_on_executor_failure(tmp_path):
    row = _run_experiment(tmp_path, CLEAN_SCRIPT,
                          fake={"explode": "candidate-proxy"})
    assert row["verdict"] == {
        "experiment_positive": False, "exit_code": 2,
        "evidence_complete": False, "typed_cause": "usage-or-infrastructure"}
    assert row["exit_code"] == 2
    assert row["cause_detail"] == (
        "cell candidate-proxy executor failed: fake boom candidate-proxy")
    assert row["infrastructure_error"] == row["cause_detail"]
    assert row["cells"]["candidate-proxy"]["status"] == "executor-failed"
    assert row["cells"]["direct"]["status"] == "executed"
    capsule = _capsule(tmp_path)
    assert capsule["verdict"]["typed_cause"] == "usage-or-infrastructure"


def test_experiment_t8_on_misbound_observation(tmp_path):
    script = dict(CLEAN_SCRIPT, **{
        "candidate-proxy": "cell_accepted_clean.json"})
    row = _run_experiment(tmp_path, script)
    assert row["verdict"]["typed_cause"] == "usage-or-infrastructure"
    assert "candidate-proxy" in row["cause_detail"]
    assert "accepted-proxy" in row["cause_detail"]


def test_experiment_refusal_runs_no_cells(tmp_path):
    pe = _pe()
    executor = FakeExecutor(CLEAN_SCRIPT)
    staged = _stage_artifact(tmp_path / "in", _honest_name(), authority=dict(
        AUTHORITY, repository_id=AUTHORITY["repository_id"] + 1))
    row = pe.execute_proxy_experiment(
        staged, run_id=RUN_ID, run_attempt=RUN_ATTEMPT,
        output_dir=tmp_path / "out", output_json=tmp_path / "row.json",
        executor=executor, comparison=_comparison(), budgets=_budgets())
    assert executor.calls == []
    assert row["cause"] == "PROXY_GATE_SELECTION_REFUSED"
    assert row["exit_code"] == 1
    assert row["verdict_mirror"] == {"typed_cause": "missing-evidence",
                                     "exit_code": 1}
    assert not (tmp_path / "out" / "proxy-capsule.json").exists()
    assert _read_json(tmp_path / "row.json") == row


def test_experiment_runs_accepted_before_candidate(tmp_path):
    pe = _pe()
    executor = FakeExecutor(CLEAN_SCRIPT)
    staged = _stage_artifact(tmp_path / "in", _honest_name())
    pe.execute_proxy_experiment(
        staged, run_id=RUN_ID, run_attempt=RUN_ATTEMPT,
        output_dir=tmp_path / "out", output_json=tmp_path / "row.json",
        executor=executor, comparison=_comparison(), budgets=_budgets())
    assert executor.calls == ["direct", "accepted-proxy", "candidate-proxy"]


def test_experiment_rejects_bad_comparison_before_cells(tmp_path):
    pe = _pe()
    executor = FakeExecutor(CLEAN_SCRIPT)
    staged = _stage_artifact(tmp_path / "in", _honest_name())
    with pytest.raises(ValueError, match="comparison"):
        pe.execute_proxy_experiment(
            staged, run_id=RUN_ID, run_attempt=RUN_ATTEMPT,
            output_dir=tmp_path / "out", output_json=tmp_path / "row.json",
            executor=executor, comparison={"performed": True},
            budgets=_budgets())
    assert executor.calls == []


def test_experiment_stale_output_dir_raises(tmp_path):
    pe = _pe()
    staged = _stage_artifact(tmp_path / "in", _honest_name())
    (tmp_path / "out").mkdir()
    with pytest.raises(OSError):
        pe.execute_proxy_experiment(
            staged, run_id=RUN_ID, run_attempt=RUN_ATTEMPT,
            output_dir=tmp_path / "out", output_json=tmp_path / "row.json",
            executor=FakeExecutor(CLEAN_SCRIPT), comparison=_comparison(),
            budgets=_budgets())


def test_experiment_row_embeds_gates_and_selection(tmp_path):
    row = _run_experiment(tmp_path, CLEAN_SCRIPT)
    assert [entry["gate"] for entry in row["gates"]] == [
        "selection", "bytes", "install", "identity", "derivative"]
    assert all(entry["cause"] == "PROXY_GATE_OK" for entry in row["gates"])
    assert row["selection"]["run_id"] == RUN_ID
    assert row["selection"]["run_attempt"] == RUN_ATTEMPT
    assert row["proxy_sha"] == _default_record()["source_commit"]
    assert row["attempt_roster"] == [
        {"cell": "direct", "attempt": 1},
        {"cell": "accepted-proxy", "attempt": 1},
        {"cell": "candidate-proxy", "attempt": 1}]
    assert row["shard_roster"] == []


def test_capsule_shape_native_with_shared_leaves(tmp_path):
    row = _run_experiment(tmp_path, _crash_script())
    capsule = _capsule(tmp_path)
    assert capsule["schema"] == "p11lab-proxy-experiment-result-v1"
    assert capsule["diagnostic_only"] is True
    assert capsule["experiment_kind"] == "proxy-round"
    assert capsule["proxy_sha"] == row["proxy_sha"]
    assert capsule["run_id"] == RUN_ID
    assert capsule["run_attempt"] == RUN_ATTEMPT
    assert set(capsule["cells"]) == {"direct", "accepted-proxy",
                                     "candidate-proxy"}
    assert set(capsule["controls"]) == set(CONTROLS)
    assert capsule["comparison"] == row["comparison"]
    assert capsule["budgets"] == row["budgets"]
    assert capsule["image_usable"] is False
    assert capsule["evidence_complete"] is True
    assert capsule["evidence_admitted"] is True
    assert capsule["comparison_positive"] is True
    assert isinstance(capsule["limitations"], list)
    assert capsule["limitations"]
    assert capsule["capsule_artifact"] == "proxy-capsule.json"


def test_capsule_self_hash_verifies(tmp_path):
    _run_experiment(tmp_path, CLEAN_SCRIPT)
    capsule = _capsule(tmp_path)
    digest = capsule["capsule_sha256"]
    assert isinstance(digest, str) and len(digest) == 64
    recomputed = hashlib.sha256(canonical(
        {**capsule, "capsule_sha256": None})).hexdigest()
    assert recomputed == digest


def test_execute_proxy_signature_unchanged():
    pe = _pe()
    assert list(inspect.signature(pe.execute_proxy).parameters) == [
        "artifact", "run_id", "run_attempt", "output_dir", "output_json",
        "expected_proxy_identity"]


def test_docs_carry_p1b_operational_section():
    text = (Path(__file__).resolve().parent.parent / "docs"
            / "proxy-ci.md").read_text(encoding="utf-8")
    for phrase in ("CellExecutor", "accepted-before-candidate",
                   "live qualification", "proxy-capsule.json",
                   "completed-negative", "control-unqualified",
                   "terminal-evidence-unavailable"):
        assert phrase in text


# Local proof (real Docker, docker-presence skip) + env-gated live design.

def _docker_ready():
    if shutil.which("docker") is None:
        return False
    probe = subprocess.run(["docker", "info"], capture_output=True, timeout=60)
    return probe.returncode == 0


def test_local_proof_production_cell_hits_real_docker(tmp_path):
    from p11lab.docker import DockerError

    if not _docker_ready():
        pytest.skip("no local Docker daemon")
    pe = _pe()
    bogus = ArtifactRef(kind="image", reference="sha256:" + "0" * 64,
                        sha256="0" * 64, platform="linux/amd64")
    spec = RunSpec(environment="softhsm2", channel="release", mode="proxy",
                   artifact=bogus, execution_location="container",
                   consumer_artifact=None, client_artifact=None, argv=("app",),
                   inputs={}, output_dir=tmp_path / "out", cwd=tmp_path,
                   timeout_seconds=60)
    request = pe.CellRequest("candidate-proxy", RUN_ID, RUN_ATTEMPT,
                             payload={"spec": spec,
                                      "plan": {"descriptor": {"inputs": {}},
                                               "host": True},
                                      "log_refs": []})
    with pytest.raises(DockerError, match="Docker operation failed: image"):
        pe.ProductionCellExecutor().run_cell(request)


def test_live_full_experiment_env_gated(tmp_path):
    """Full live dispatch: designed here, never run in this slice.

    Requires P11LAB_PROXY_LIVE=1 plus a qualified live environment
    (real daemon images, native SoftHSM bundle, retained cell logs);
    without the gate it skips and the hermetic suite stays green.
    """
    if os.environ.get("P11LAB_PROXY_LIVE") != "1":
        pytest.skip("live dispatch not enabled")
    if not _docker_ready():
        pytest.skip("no local Docker daemon")
    pe = _pe()
    staged = _stage_artifact(tmp_path / "in", _honest_name())
    row = pe.execute_proxy_experiment(
        staged, run_id=RUN_ID, run_attempt=RUN_ATTEMPT,
        output_dir=tmp_path / "out", output_json=tmp_path / "row.json",
        executor=pe.ProductionCellExecutor(), cell_payloads=None,
        comparison=_comparison(), budgets=_budgets())
    assert row["verdict"]["typed_cause"] == "usage-or-infrastructure"
