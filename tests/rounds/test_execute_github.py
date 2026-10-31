"""`p11lab round execute` github-transport chain; network boundary mocked, no live runs."""
import hashlib
import http.client
import io
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
POLICY_ROOT = FIXTURES / "policy"
GITHUB_FIXTURES = FIXTURES / "execute-github"
COMPARISON = Path(__file__).parents[1] / "fixtures/comparison/checker-direct"
PROFILE_REPOSITORY = "mingulov/p11lab-round-caller"
PROFILE_WORKFLOW_ID = 401625989
EXPECTED_POLICY_DIGEST = "a3f00031dfb25dbf26399c1ab696663dcc1515b45274d97370eeaf372b77d745"
EXPECTED_RUNTIME_MAX_OUTPUT = 100663296
# Enrolled runtime.source_date_epoch (B-C1c): committer timestamp of
# p11lab/p11lab@10017b19 (2026-10-27T13:03:33Z per public commit metadata).
EXPECTED_SOURCE_DATE_EPOCH = 1793106213
APP_WHEEL_FILENAME = "fixture_app-0.0.1-py3-none-any.whl"
GITHUB_LIMITATION = (
    "GitHub transport: producer authority established by round owner proof "
    "over the prepared dist; comparison evidence staged by caller; builder "
    "source epoch bound from the enrolled profile runtime.")

EXPECTED_ROW_FIELDS = {
    "lane", "provider", "transport", "tier", "attempt", "phase", "status",
    "cause", "cause_detail", "exit_code", "comparison_positive",
    "coverage_positive", "regressions", "improvements", "selected_count",
    "observed_count", "missing_selected", "image_usable", "evidence_complete",
    "evidence_admitted", "producer_status", "evaluator_receipt_sha256",
    "expectation_sha256", "policy_digest", "attempt_roster", "shard_roster",
    "coverage",
}
EXPECTED_CAPSULE_FIELDS = {
    "schema", "diagnostic_only", "tier", "framework_sha", "p11lab_ref",
    "round_positive", "policy", "expectation_sha256", "observations_sha256",
    "evaluator_receipt_sha256", "endpoints", "verdict_row", "image_promotable",
    "receipt_artifact", "capsule_artifact", "capsule_sha256",
    "raw_artifacts_manifest", "image_usable", "evidence_complete",
    "evidence_admitted", "comparison_positive", "limitations",
}
EXPECTED_RECEIPT_FIELDS = {
    "schema", "kind", "inputs", "phases", "artifacts", "acceptance",
    "verdict_sha256",
}


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    # Stdlib net modules are pre-imported above so subclass statements at
    # import time never run under the patch; only fresh sockets are blocked.
    assert ssl is not None and http is not None and urllib is not None

    def blocked(*args, **kwargs):
        raise AssertionError("network is forbidden in github unit tests")

    monkeypatch.setattr(socket, "socket", blocked)


def _env():
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[2] / "src")
    env.pop("CI", None)
    env.pop("GITHUB_ACTIONS", None)
    env.pop("GH_TOKEN", None)
    env.pop("GITHUB_TOKEN", None)
    return env


def _run_execute(context, evaluator_root, output_dir, output_json, cwd, tier=None):
    argv = [sys.executable, "-m", "p11lab", "round", "execute",
           "--context", str(context), "--policy-root", str(POLICY_ROOT),
           "--evaluator-root", str(evaluator_root),
           "--output-dir", str(output_dir), "--output-json", str(output_json)]
    if tier is not None:
        argv += ["--tier", tier]
    return subprocess.run(argv, capture_output=True, text=True, env=_env(), cwd=cwd)


def _candidate_sha():
    envelope = json.loads((COMPARISON / "envelope.json").read_bytes())
    return envelope["protected"]["selected_candidate_source_sha"]


def _github_context(directory, name, mutation=None):
    context = json.loads((FIXTURES / "valid-context.json").read_bytes())
    context.pop("artifact_path", None)
    context.pop("fixture_metadata_path", None)
    context.update(transport="github", repository=PROFILE_REPOSITORY,
                   workflow_id=PROFILE_WORKFLOW_ID, control_sha="e" * 40,
                   producer_job="produce-framework-dist")
    context["identity"] = {
        "attempt": 2, "candidate_sha": _candidate_sha(),
        "merge_base_sha": "c" * 40, "repository_id": 123, "run_id": 456,
        "target_sha": "b" * 40}
    if mutation is not None:
        mutation(context)
    path = directory / name
    path.write_text(json.dumps(context))
    return path


def _mint_dist_bytes(identity):
    """Mint transport-agnostic dist bytes bound to the given identity."""
    from p11lab.round_core.inputs import canonical, digest

    with zipfile.ZipFile(FIXTURES / "fixture-dist.zip") as previous:
        wheels = {name: previous.read(name) for name in (
            "primary_wheel/fixture_app-0.0.1-py3-none-any.whl",
            "sdist_probe_wheel/fixture_app-0.0.1-py3-none-any.whl",
            "replay_base_wheel/fixture_app-0.0.1-py3-none-any.whl",
            "deps/fixture_pkg-0.0.1-py3-none-any.whl")}
        lock_raw = previous.read("dependency-lock.json")
    sdist_raw = io.BytesIO()
    with tarfile.open(fileobj=sdist_raw, mode="w:gz") as bundle:
        for name, content in (
                ("pyproject.toml", b'[build-system]\nrequires=[]\nbuild-backend="backend"\nbackend-path=["."]\n'),
                ("backend.py", b'raise AssertionError("must never run on host")\n')):
            entry = tarfile.TarInfo(name)
            entry.size = len(content)
            entry.mode = 0o644
            entry.mtime = 1
            bundle.addfile(entry, io.BytesIO(content))
    sdist = sdist_raw.getvalue()
    roles = {role: {"path": path,
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "size": len(content)}
             for role, path, content in (
                 ("primary_wheel", "primary_wheel/fixture_app-0.0.1-py3-none-any.whl",
                  wheels["primary_wheel/fixture_app-0.0.1-py3-none-any.whl"]),
                 ("sdist_probe_wheel", "sdist_probe_wheel/fixture_app-0.0.1-py3-none-any.whl",
                  wheels["sdist_probe_wheel/fixture_app-0.0.1-py3-none-any.whl"]),
                 ("replay_base_wheel", "replay_base_wheel/fixture_app-0.0.1-py3-none-any.whl",
                  wheels["replay_base_wheel/fixture_app-0.0.1-py3-none-any.whl"]),
                 ("sdist", "sdist/fixture-pkg-0.0.1.tar.gz", sdist))}
    source_raw = canonical({"revision": identity["candidate_sha"]})
    build_raw = canonical({"identity": identity, "roles_sha256": digest(roles)})
    manifest = {"schema_version": 1, "identity": identity, "roles": roles,
                "dependency_lock_sha256": hashlib.sha256(lock_raw).hexdigest(),
                "source_receipt_sha256": hashlib.sha256(source_raw).hexdigest(),
                "build_receipt_sha256": hashlib.sha256(build_raw).hexdigest()}
    raw = io.BytesIO()
    with zipfile.ZipFile(raw, "w", zipfile.ZIP_DEFLATED) as out:
        out.writestr("candidate-manifest.json", canonical(manifest))
        out.writestr("dependency-lock.json", lock_raw)
        out.writestr("source-receipt.json", source_raw)
        out.writestr("build-receipt.json", build_raw)
        for row in roles.values():
            content = sdist if row["path"].endswith(".tar.gz") else wheels[row["path"]]
            out.writestr(row["path"], content)
        out.writestr("deps/fixture_pkg-0.0.1-py3-none-any.whl",
                     wheels["deps/fixture_pkg-0.0.1-py3-none-any.whl"])
    return raw.getvalue(), hashlib.sha256(lock_raw).hexdigest()


def _canned_owner_proof():
    return {
        "attestation_artifact": {
            "id": 11, "name": "p11lab-round-attestation-456-2",
            "digest": "sha256:" + "0" * 64},
        "source_ref": "refs/heads/main",
        "premise": {"premise": "human-review-of-pinned-bytes",
                    "workflow_path": ".github/workflows/diagnostic.yml",
                    "workflow_sha256": "7" * 64,
                    "producer_job": "produce-framework-dist"}}


def _fake_prepare_factory(calls, *, authority="round-owner-proof-verified",
                          include_owner_proof=True, profile_pin=None, error=None):
    """Build a `run_prepare` seam double: the mocked network boundary.

    Dist bytes are verified and materialized with the real
    `verify_dist_bytes`; only the GitHub acquisition is canned.
    """

    def run_prepare(context, policy_root, output):
        from p11lab.round_core.execute import github_producer_profile
        from p11lab.round_core.inputs import canonical, digest, verify_dist_bytes

        calls.append({"context": context, "policy_root": policy_root,
                      "output": Path(output)})
        if error is not None:
            raise error
        out = Path(output).absolute()
        out.mkdir(parents=True, exist_ok=False)
        raw, lock_sha = _mint_dist_bytes(context["identity"])
        dist = verify_dist_bytes(raw, context["identity"], lock_sha,
                                 out / "dist.zip", materialize=True)
        profile = github_producer_profile(context["repository"],
                                          context["workflow_id"])
        prepared = {
            "schema_version": 1, "kind": "round-input-diagnostic",
            "transport": "github", "authority": authority,
            "protected_profile_sha256": (profile_pin if profile_pin is not None
                                         else digest(profile)),
            "round_positive": False, "identity": dict(context["identity"]),
            "policy_sha256": EXPECTED_POLICY_DIGEST,
            "target": context["target"],
            "target_sha256": digest(context["target"]),
            "caller": {"repository": context["repository"],
                       "run_head_sha": context["run_head_sha"],
                       "workflow_id": context["workflow_id"],
                       "producer_job": context["producer_job"],
                       "control_sha": context.get("control_sha")},
            "artifact_metadata": {"classification": "mocked-network-boundary"},
            "dist": dist,
            "context_artifact_metadata": {"classification": "mocked-network-boundary"},
            "pre_provider_transport_retries": 0,
            "artifact_input": "mocked-acquisition",
        }
        if include_owner_proof:
            prepared["owner_proof"] = _canned_owner_proof()
        (out / "round-inputs.json").write_bytes(canonical(prepared) + b"\n")
        return prepared

    return run_prepare


def _make_tools(toolroot):
    from p11lab.round_core.bootstrap import inventory
    from p11lab.round_core.inputs import SealedToolInputs, canonical

    (toolroot / "python/bin").mkdir(parents=True)
    (toolroot / "python/bin/python3").write_bytes(b"no host execution")
    (toolroot / "downloads/build-wheels").mkdir(parents=True)
    wheel = toolroot / "downloads/build-wheels/pip.whl"
    wheel.write_bytes(b"inert test-only sealed input")
    spec = {"name": "pip", "version": "1", "filename": "pip.whl",
            "size": wheel.stat().st_size,
            "sha256": hashlib.sha256(wheel.read_bytes()).hexdigest()}
    return SealedToolInputs(
        toolroot, "a" * 64,
        tuple(canonical(row) for row in inventory(toolroot, toolroot / "python")),
        (canonical(spec),),
        f"pip==1 --hash=sha256:{spec['sha256']}\n".encode(), ("pip==1",))


class SucceedingDocker:
    """Fake engine that completes every phase; `docker cp` bytes come from PATH."""

    def __init__(self, layers, env):
        self.identity = "d" * 64
        self.layers = list(layers)
        self.env = dict(env)
        self.resources = {}
        self.volumes = {}

    def image(self, artifact):
        return {"RootFS": {"Layers": list(self.layers)},
                "Config": {"Env": ["PATH=/usr/bin:/bin"]}}

    def create(self, image, argv, options, labels, name):
        from p11lab.docker import DockerError

        holder = name.endswith("-holder")
        identity = "e" * 64 if holder else self.identity
        if not holder and self.identity in self.resources:
            raise DockerError("test engine allows one live candidate")
        self.resources[identity] = {
            "Id": identity, "Image": image,
            "Config": {"Labels": dict(labels), "User": "65532:65532",
                       "Entrypoint": ["/bin/sleep"] if holder else ["/inputs/python/bin/python3"]},
            "HostConfig": {"PidMode": ""},
            "State": {"Running": False, "Pid": 0}}
        return identity

    def execute(self, identity, timeout, interrupted):
        from p11lab.docker import CommandResult

        self.resources[identity]["State"] = {"Running": True, "Pid": 1}
        return CommandResult(0, "", "", False)

    def stop(self, identity, labels):
        assert self.resources[identity]["Config"]["Labels"] == labels
        self.resources[identity]["State"] = {"Running": False, "Pid": 0}

    def remove(self, kind, identity, labels):
        if kind == "container":
            assert not self.resources[identity]["State"]["Running"]
            assert self.resources[identity]["Config"]["Labels"] == labels
            del self.resources[identity]
        else:
            assert self.volumes[identity]["Labels"] == labels
            del self.volumes[identity]

    def command(self, args):
        from p11lab.docker import CommandResult

        if args[:2] == ["volume", "create"]:
            name = args[args.index("--name") + 1]
            options, labels = {}, {}
            for index, item in enumerate(args[:-1]):
                if item in ("--opt", "--label"):
                    key, value = args[index + 1].split("=", 1)
                    (options if item == "--opt" else labels)[key] = value
            self.volumes[name] = {"Name": name, "Driver": "local",
                                  "Options": options, "Labels": labels}
            return CommandResult(0, name, "")
        if args[:2] == ["volume", "inspect"]:
            return CommandResult(0, json.dumps([self.volumes[args[-1]]]), "")
        if args[0] == "start":
            self.resources[args[1]]["State"] = {"Running": True, "Pid": 1}
            return CommandResult(0, args[1], "")
        return CommandResult(0, json.dumps([self.resources[args[-1]]]), "")


def _write_docker_shim(directory, tars):
    bindir = directory / "fakebin"
    queue = bindir / "cp-queue"
    queue.mkdir(parents=True)
    for index, raw in enumerate(tars):
        (queue / f"{index:02d}.tar").write_bytes(raw)
    script = bindir / "docker"
    script.write_text("#!/usr/bin/env python3\n"
                      "import pathlib, sys\n"
                      "assert sys.argv[1] == 'cp' and sys.argv[3] == '-', sys.argv\n"
                      "queue = pathlib.Path(__file__).parent / 'cp-queue'\n"
                      "items = sorted(p for p in queue.iterdir() if p.is_file())\n"
                      "sys.stdout.buffer.write(items[0].read_bytes())\n"
                      "items[0].unlink()\n")
    script.chmod(0o755)
    return {"PATH": str(bindir) + ":" + os.environ.get("PATH", ""),
            "HOME": str(directory), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}


def _make_wheel_bytes():
    raw = io.BytesIO()
    with zipfile.ZipFile(raw, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("fixture_pkg/__init__.py", b"VALUE = 1\n")
        archive.writestr("fixture_pkg-0.0.1.dist-info/METADATA",
                         b"Metadata-Version: 2.1\nName: fixture-pkg\nVersion: 0.0.1\n")
        archive.writestr("fixture_pkg-0.0.1.dist-info/RECORD", b"")
    return raw.getvalue()


def _make_tar(mapping):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as bundle:
        directories = {str(parent) for name in mapping
                       for parent in Path(name).parents if str(parent) != "."}
        for name in sorted(directories, key=lambda item: len(Path(item).parts)):
            entry = tarfile.TarInfo(name)
            entry.type = tarfile.DIRTYPE
            entry.mode = 0o755
            entry.mtime = 1
            bundle.addfile(entry)
        for name in sorted(mapping):
            entry = tarfile.TarInfo(name)
            entry.size = len(mapping[name])
            entry.mode = 0o644
            entry.mtime = 1
            bundle.addfile(entry, io.BytesIO(mapping[name]))
    return raw.getvalue()


def _install_mapping(wheel_bytes):
    archive = zipfile.ZipFile(io.BytesIO(wheel_bytes))
    members = [item.filename for item in archive.infolist() if not item.is_dir()]
    metadata = next(name.rsplit("/", 1)[0] for name in members
                    if name.endswith(".dist-info/METADATA"))
    mapping = {"site/" + name: archive.read(name) for name in members}
    for name in ("INSTALLER", "REQUESTED", "direct_url.json"):
        mapping[f"site/{metadata}/{name}"] = b"canned\n"
    return mapping


def _authority_and_endpoints(directory):
    from p11lab.comparison import LocalComparisonWitness
    from p11lab.round_core.inputs import freeze_comparison_expectation

    root = directory / "endpoints"
    shutil.copytree(COMPARISON / "baseline", root / "baseline")
    shutil.copytree(COMPARISON / "candidate", root / "candidate")
    envelope = json.loads((COMPARISON / "envelope.json").read_bytes())
    authority = LocalComparisonWitness(
        freeze_comparison_expectation(envelope),
        (COMPARISON / "witness.json").read_bytes())
    return authority, envelope, root / "baseline", root / "candidate"


def _endpoint_rows(directory):
    rows = []
    for path in sorted(directory.rglob("*")):
        if path.is_file():
            raw = path.read_bytes()
            rows.append({"path": path.relative_to(directory).as_posix(),
                         "size": len(raw),
                         "sha256": hashlib.sha256(raw).hexdigest()})
    return rows


def _fake_binding(envelope, authority, tools, baseline, candidate, *, nodes=None):
    observations_sha = hashlib.sha256(authority.observations).hexdigest()
    endpoints = {}
    for role, root in (("baseline", baseline), ("candidate", candidate)):
        expected = envelope["endpoints"][role]
        observed = list(expected["selected"]) if nodes is None else list(nodes)
        endpoints[role] = {
            "files": _endpoint_rows(root), "selected": list(expected["selected"]),
            "attempts": ["outer1"], "shards": ["s1"],
            "admission": {"header": dict(expected["header"]),
                          "nodes": observed, "shards": ["s1"],
                          "selected": list(expected["selected"]),
                          "unselected": list(expected["unselected"]),
                          "exitstatus": 0, "warnings": [],
                          "admitted": True}}
    from p11lab.round_core.inputs import digest

    return {"schema_version": 1, "scope": "local-controller",
            "operation": envelope["operation"],
            "expectation_sha256": digest(envelope),
            "observations_sha256": observations_sha,
            "evaluator_receipt_sha256": tools.receipt_sha256,
            "endpoints": endpoints}


def _full_github_chain(directory, *, compare_fixture="compare-clean.json",
                       coverage_fixture="coverage-clean.json", nodes=None,
                       prepare_options=None, use_real_binder=False):
    """Assemble hermetic github material plus seams for one full API run."""
    from p11lab.round_core.execute import (
        BuilderIdentity, parse_compare_output, parse_coverage_output)
    from p11lab.round_core.inputs import digest
    from p11lab.round_core.worker import SandboxPolicy

    context_path = _github_context(directory, "github-context.json")
    tools = _make_tools(directory / "tools")
    authority, envelope, baseline, candidate = _authority_and_endpoints(directory)
    wheel_bytes = _make_wheel_bytes()
    tars = [_make_tar({APP_WHEEL_FILENAME: wheel_bytes}),
            _make_tar(_install_mapping(wheel_bytes)),
            _make_tar({"startup.json": b'{"ok": true}'})]
    engine = SucceedingDocker(("sha256:" + "c" * 64,),
                              _write_docker_shim(directory, tars))
    binding = _fake_binding(envelope, authority, tools, baseline, candidate,
                            nodes=nodes)
    prepare_calls = []
    run_prepare = _fake_prepare_factory(prepare_calls, **(prepare_options or {}))
    calls = []

    def bind_evaluator(root):
        calls.append(("evaluator", root))
        return tools

    def bind_produce_inputs(profile, prepared, *, source_date_epoch,
                            build_reports, startup_reports, timeout_seconds):
        calls.append(("produce-inputs", source_date_epoch, build_reports,
                      startup_reports, timeout_seconds))
        assert source_date_epoch is None
        builder = BuilderIdentity(
            image="sha256:" + "b" * 64, layers=("sha256:" + "c" * 64,),
            config_sha256=digest({"Env": ["PATH=/usr/bin:/bin"]}),
            # The seam pins its own test epoch; the real binder binds the
            # enrolled profile leaf (covered by test_bind_github_produce_inputs_ok).
            source_date_epoch=1)
        sandbox = SandboxPolicy(APP_WHEEL_FILENAME,
                                startup_reports=("startup.json",))
        return builder, sandbox

    def bind_envelope(given_envelope, endpoints):
        calls.append(("bind", endpoints))
        assert given_envelope == envelope
        assert set(endpoints) == {"authority", "evaluator", "baseline", "candidate"}
        assert endpoints["authority"] is authority
        assert endpoints["evaluator"] is tools
        assert endpoints["baseline"] == baseline
        assert endpoints["candidate"] == candidate
        return binding

    def run_compare(sealed, first, second, given_binding, workdir):
        calls.append(("compare", first, second, workdir))
        assert sealed is tools
        assert given_binding == binding
        raw = (GITHUB_FIXTURES / compare_fixture).read_bytes()
        (workdir / "verdict-compare.json").write_bytes(raw)
        return parse_compare_output(raw)

    def run_coverage(sealed, first, second, given_binding, workdir):
        calls.append(("coverage", first, second, workdir))
        assert sealed is tools
        assert given_binding == binding
        raw = (GITHUB_FIXTURES / coverage_fixture).read_bytes()
        (workdir / "verdict-coverage.json").write_bytes(raw)
        return parse_coverage_output(raw)

    material = {"run_prepare": run_prepare, "authority": authority,
                "baseline": baseline, "candidate": candidate, "engine": engine,
                "bind_evaluator": bind_evaluator,
                "bind_envelope": bind_envelope, "run_compare": run_compare,
                "run_coverage": run_coverage}
    if not use_real_binder:
        material["bind_produce_inputs"] = bind_produce_inputs
    return context_path, tools, envelope, binding, calls, prepare_calls, material


def _run_api(tmp_path, material, context_path):
    from p11lab.round_core.execute import execute_round

    evaluator_root = tmp_path / "evaluator"
    evaluator_root.mkdir(exist_ok=True)
    output_dir = tmp_path / "output"
    output_json = tmp_path / "row.json"
    row = execute_round(context_path, POLICY_ROOT, evaluator_root, output_dir,
                        output_json, **material)
    assert json.loads(output_json.read_text()) == row
    return row, output_dir


def _expected_coverage_map():
    payload = json.loads((COMPARISON / "candidate/coverage.json").read_bytes())
    mechanisms = payload["mechanism_coverage"]
    states = ("advertised", "accepted", "attempted", "rejected_cleanly",
              "skipped_by_capability", "crashed", "timeout", "selected",
              "selection_rejected", "invoked")
    return {state + "_names": list(mechanisms[state + "_names"][:10])
            for state in states}


def test_cli_github_without_staging_refused_before_prepare(tmp_path):
    context = _github_context(tmp_path, "github-context.json")
    evaluator = tmp_path / "evaluator"
    evaluator.mkdir()
    output_dir = tmp_path / "output"
    output_json = tmp_path / "row.json"
    completed = _run_execute(context, evaluator, output_dir, output_json, tmp_path)
    assert completed.returncode == 3, completed.stderr
    row = json.loads(output_json.read_text())
    assert set(row) == EXPECTED_ROW_FIELDS
    assert (row["phase"], row["status"], row["cause"], row["exit_code"]) == (
        "prepare", "refused", "EXECUTE_TRANSPORT_REFUSED", 3)
    assert "staged" in row["cause_detail"]
    assert row["transport"] == "github"
    assert row["tier"] == "pr-smoke"
    assert row["comparison_positive"] is None
    assert row["coverage_positive"] is False
    assert json.loads(completed.stdout) == row
    assert not (output_dir / "prepare").exists()
    assert not (output_dir / "dist.zip").exists()
    capsule = json.loads((output_dir / "round-capsule.json").read_text())
    assert set(capsule) == EXPECTED_CAPSULE_FIELDS
    assert capsule["round_positive"] is False
    assert capsule["verdict_row"] == row
    assert capsule["limitations"][0] == GITHUB_LIMITATION
    receipt = json.loads((output_dir / "round-receipt.json").read_text())
    assert set(receipt) == EXPECTED_RECEIPT_FIELDS


def test_github_profile_selects_shipped_enrollment():
    from importlib.resources import files

    from p11lab.round_core.execute import github_producer_profile

    raw = files("p11lab").joinpath("data/rounds/producer-profiles.json").read_bytes()
    enrolled = json.loads(raw)["profiles"][0]
    profile = github_producer_profile(PROFILE_REPOSITORY, PROFILE_WORKFLOW_ID)
    assert profile == enrolled
    assert profile["policy_sha256"] == EXPECTED_POLICY_DIGEST
    assert set(profile["runtime"]) == {
        "image", "layers", "config_sha256", "tool_identity_sha256",
        "python_version", "max_output_bytes", "source_date_epoch"}
    assert profile["runtime"]["source_date_epoch"] == EXPECTED_SOURCE_DATE_EPOCH


@pytest.mark.parametrize("repository,workflow_id", [
    ("unknown/owner", PROFILE_WORKFLOW_ID),
    (PROFILE_REPOSITORY, 1),
])
def test_github_profile_unknown_is_usage(repository, workflow_id):
    from p11lab.round_core.execute import github_producer_profile

    with pytest.raises(ValueError, match="protected producer profile"):
        github_producer_profile(repository, workflow_id)


def _binder_prepared(pin, wheel_path="primary_wheel/fixture_app-0.0.1-py3-none-any.whl"):
    return {"protected_profile_sha256": pin,
            "dist": {"roles": {"primary_wheel": {"path": wheel_path,
                                                "sha256": "0" * 64, "size": 8}}}}


def _shipped_profile_and_pin():
    from p11lab.round_core.execute import github_producer_profile
    from p11lab.round_core.inputs import digest

    profile = github_producer_profile(PROFILE_REPOSITORY, PROFILE_WORKFLOW_ID)
    return profile, digest(profile)


def test_bind_github_produce_inputs_ok():
    from p11lab.round_core.execute import bind_github_produce_inputs

    profile, pin = _shipped_profile_and_pin()
    builder, sandbox = bind_github_produce_inputs(
        profile, _binder_prepared(pin), source_date_epoch=None,
        build_reports=None, startup_reports=None, timeout_seconds=None)
    assert builder.image == profile["runtime"]["image"]
    assert builder.layers == tuple(profile["runtime"]["layers"])
    assert builder.config_sha256 == profile["runtime"]["config_sha256"]
    assert builder.source_date_epoch == EXPECTED_SOURCE_DATE_EPOCH
    assert builder.source_date_epoch == profile["runtime"]["source_date_epoch"]
    assert sandbox.wheel_filename == APP_WHEEL_FILENAME
    assert sandbox.max_output_bytes == EXPECTED_RUNTIME_MAX_OUTPUT
    assert sandbox.max_output_bytes == profile["runtime"]["max_output_bytes"]
    assert sandbox.build_reports == ()
    assert sandbox.startup_reports == ("startup.json",)
    assert sandbox.timeout_seconds == 60


def test_bind_github_produce_inputs_rejects_profile_pin_mismatch():
    from p11lab.round_core.execute import bind_github_produce_inputs

    profile, _ = _shipped_profile_and_pin()
    with pytest.raises(ValueError, match="profile"):
        bind_github_produce_inputs(
            profile, _binder_prepared("0" * 64), source_date_epoch=1,
            build_reports=None, startup_reports=None, timeout_seconds=None)


@pytest.mark.parametrize("mutation,match", [
    ({"image": None}, "image"),
    ({"image": "not-a-digest"}, "image"),
    ({"layers": []}, "layers"),
    ({"layers": ["sha256:" + "z" * 64]}, "layers"),
    ({"config_sha256": "short"}, "config"),
    ({"max_output_bytes": "big"}, "max_output_bytes"),
    ({"max_output_bytes": 512}, "max_output_bytes"),
])
def test_bind_github_produce_inputs_rejects_malformed_runtime(mutation, match):
    from p11lab.round_core.execute import bind_github_produce_inputs
    from p11lab.round_core.inputs import digest

    profile, _ = _shipped_profile_and_pin()
    profile = json.loads(json.dumps(profile))
    for key, value in mutation.items():
        if value is None:
            profile["runtime"].pop(key)
        else:
            profile["runtime"][key] = value
    with pytest.raises(ValueError, match=match):
        bind_github_produce_inputs(
            profile, _binder_prepared(digest(profile)), source_date_epoch=1,
            build_reports=None, startup_reports=None, timeout_seconds=None)


@pytest.mark.parametrize("wheel_path", [
    "primary_wheel/pkg-0.0.1.tar.gz",
    "primary_wheel/pkg.zip",
    "",
])
def test_bind_github_produce_inputs_rejects_bad_dist_wheel(wheel_path):
    from p11lab.round_core.execute import bind_github_produce_inputs

    profile, pin = _shipped_profile_and_pin()
    with pytest.raises(ValueError, match="wheel"):
        bind_github_produce_inputs(
            profile, _binder_prepared(pin, wheel_path), source_date_epoch=None,
            build_reports=None, startup_reports=None, timeout_seconds=None)


def test_bind_github_produce_inputs_honors_explicit_sandbox():
    from p11lab.round_core.execute import bind_github_produce_inputs

    profile, pin = _shipped_profile_and_pin()
    _, sandbox = bind_github_produce_inputs(
        profile, _binder_prepared(pin), source_date_epoch=None,
        build_reports=("build.json",), startup_reports=(),
        timeout_seconds=120)
    assert sandbox.build_reports == ("build.json",)
    assert sandbox.startup_reports == ()
    assert sandbox.timeout_seconds == 120
    assert sandbox.max_output_bytes == EXPECTED_RUNTIME_MAX_OUTPUT


@pytest.mark.parametrize("timeout_seconds", [0, 301])
def test_bind_github_produce_inputs_rejects_bad_timeout(timeout_seconds):
    from p11lab.round_core.execute import bind_github_produce_inputs

    profile, pin = _shipped_profile_and_pin()
    with pytest.raises(ValueError, match="sandbox bounds"):
        bind_github_produce_inputs(
            profile, _binder_prepared(pin), source_date_epoch=None,
            build_reports=None, startup_reports=None,
            timeout_seconds=timeout_seconds)


def test_bind_github_produce_inputs_rejects_bad_report_name():
    from p11lab.round_core.execute import bind_github_produce_inputs

    profile, pin = _shipped_profile_and_pin()
    with pytest.raises(ValueError, match="report"):
        bind_github_produce_inputs(
            profile, _binder_prepared(pin), source_date_epoch=None,
            build_reports=("notes.txt",), startup_reports=None,
            timeout_seconds=None)


def test_execute_github_executed_exit_zero(tmp_path):
    from p11lab.round_core.inputs import canonical, digest

    context_path, tools, envelope, binding, calls, prepare_calls, material = (
        _full_github_chain(tmp_path))
    row, output_dir = _run_api(tmp_path, material, context_path)
    assert set(row) == EXPECTED_ROW_FIELDS
    assert (row["phase"], row["status"], row["cause"], row["exit_code"]) == (
        "done", "executed", "EXECUTE_OK", 0)
    assert row["cause_detail"] is None
    assert row["comparison_positive"] is True
    assert row["coverage_positive"] is True
    assert row["regressions"] == [] and row["improvements"] == []
    assert (row["selected_count"], row["observed_count"]) == (1, 1)
    assert row["missing_selected"] == []
    assert row["image_usable"] is False
    assert row["evidence_complete"] is True
    assert row["evidence_admitted"] is True
    assert row["producer_status"] == "produced"
    assert row["evaluator_receipt_sha256"] == "a" * 64
    assert row["expectation_sha256"] == digest(envelope)
    assert row["policy_digest"] == EXPECTED_POLICY_DIGEST
    assert row["attempt_roster"] == ["outer1"]
    assert row["shard_roster"] == ["s1"]
    assert row["coverage"] == _expected_coverage_map()
    assert (row["lane"], row["transport"], row["tier"], row["attempt"]) == (
        "softhsm2", "github", "pr-smoke", 2)
    assert row["provider"] == {"family": "softhsm2", "channel": "release",
                               "platform": "linux/amd64"}
    assert [call[0] for call in calls] == [
        "evaluator", "produce-inputs", "bind", "compare", "coverage"]
    assert calls[1][1:] == (None, None, None, None)
    assert len(prepare_calls) == 1
    assert prepare_calls[0]["output"] == output_dir / "prepare"
    assert prepare_calls[0]["policy_root"] == POLICY_ROOT
    assert prepare_calls[0]["context"]["transport"] == "github"
    assert (output_dir / "produce" / "producer-observation.json").is_file()
    prepared = json.loads(
        (output_dir / "prepare" / "round-inputs.json").read_bytes())
    assert prepared["authority"] == "round-owner-proof-verified"
    assert prepared["owner_proof"] == _canned_owner_proof()
    assert prepared["round_positive"] is False
    capsule = json.loads((output_dir / "round-capsule.json").read_text())
    assert set(capsule) == EXPECTED_CAPSULE_FIELDS
    assert capsule["schema"] == "p11lab-round-execution-v1"
    assert capsule["diagnostic_only"] is True
    assert capsule["tier"] == "pr-smoke"
    assert capsule["framework_sha"] == _candidate_sha()
    assert capsule["p11lab_ref"] is None
    assert capsule["round_positive"] is False
    assert capsule["policy"]["policy_digest"] == EXPECTED_POLICY_DIGEST
    assert capsule["expectation_sha256"] == digest(envelope)
    assert capsule["observations_sha256"] == hashlib.sha256(
        material["authority"].observations).hexdigest()
    assert capsule["evaluator_receipt_sha256"] == "a" * 64
    assert capsule["endpoints"] == binding["endpoints"]
    assert capsule["verdict_row"] == row
    assert capsule["image_promotable"] is False
    assert capsule["receipt_artifact"] == "round-receipt.json"
    assert capsule["capsule_artifact"] == "round-capsule.json"
    recomputed = dict(capsule, capsule_sha256=None)
    assert capsule["capsule_sha256"] == hashlib.sha256(canonical(recomputed)).hexdigest()
    assert capsule["image_usable"] is False
    assert capsule["evidence_complete"] is True
    assert capsule["evidence_admitted"] is True
    assert capsule["comparison_positive"] is True
    manifest = {entry["path"]: entry for entry in capsule["raw_artifacts_manifest"]}
    assert "produce/producer-observation.json" in manifest
    assert "compare/verdict-compare.json" in manifest
    assert "coverage/verdict-coverage.json" in manifest
    assert "round-capsule.json" not in manifest
    receipt = json.loads((output_dir / "round-receipt.json").read_text())
    assert set(receipt) == EXPECTED_RECEIPT_FIELDS
    assert receipt["schema"] == "p11lab-round-receipt-v1"
    assert receipt["acceptance"] == {
        "blocked": True,
        "reason": "$.axes.image_usable: requires True (conditional rule: "
                  '{"properties":{"stage":{"enum":["accepted","promoted","published"]}}})'}
    assert receipt["verdict_sha256"] == hashlib.sha256(canonical(row)).hexdigest()
    assert [entry["phase"] for entry in receipt["phases"]] == [
        "prepare", "bootstrap", "produce", "bind", "compare", "coverage", "done"]
    assert {entry["cause"] for entry in receipt["phases"]} == {"EXECUTE_OK"}
    assert capsule["limitations"] == [
        GITHUB_LIMITATION,
        "Acceptance blocked: " + receipt["acceptance"]["reason"]]


@pytest.mark.parametrize("detail", [
    "policy bundle does not match protected producer profile",
    "protected caller context mismatch",
    "protected dependency wheel closure mismatch",
    "protected runtime selection mismatch",
])
def test_execute_github_prepare_mismatch_propagates(tmp_path, detail):
    context_path, tools, envelope, binding, calls, prepare_calls, material = (
        _full_github_chain(tmp_path, prepare_options={"error": ValueError(detail)}))
    evaluator_root = tmp_path / "evaluator"
    evaluator_root.mkdir()
    output_dir = tmp_path / "output"
    output_json = tmp_path / "row.json"
    from p11lab.round_core.execute import execute_round

    with pytest.raises(ValueError, match=detail):
        execute_round(context_path, POLICY_ROOT, evaluator_root, output_dir,
                      output_json, **material)
    assert len(prepare_calls) == 1
    assert not output_json.exists()


@pytest.mark.parametrize("prepare_options", [
    {"authority": "protected-profile-source-verified",
     "include_owner_proof": False},
    {"authority": "round-owner-proof-verified", "include_owner_proof": False},
    {"authority": "protected-profile-source-verified",
     "include_owner_proof": True},
])
def test_execute_github_without_owner_proof_refused(tmp_path, prepare_options):
    context_path, tools, envelope, binding, calls, prepare_calls, material = (
        _full_github_chain(tmp_path, prepare_options=prepare_options))
    row, output_dir = _run_api(tmp_path, material, context_path)
    assert set(row) == EXPECTED_ROW_FIELDS
    assert (row["phase"], row["status"], row["cause"], row["exit_code"]) == (
        "prepare", "refused", "EXECUTE_TRANSPORT_REFUSED", 3)
    assert "owner proof" in row["cause_detail"]
    assert row["transport"] == "github"
    assert row["producer_status"] is None
    assert len(prepare_calls) == 1
    assert [call[0] for call in calls] == []
    assert not (output_dir / "produce").exists()
    capsule = json.loads((output_dir / "round-capsule.json").read_text())
    assert set(capsule) == EXPECTED_CAPSULE_FIELDS
    assert capsule["round_positive"] is False
    assert capsule["limitations"][0] == GITHUB_LIMITATION
    receipt = json.loads((output_dir / "round-receipt.json").read_text())
    assert set(receipt) == EXPECTED_RECEIPT_FIELDS


@pytest.mark.parametrize("staged", ["builder", "sandbox"])
def test_execute_github_caller_builder_or_sandbox_rejected(tmp_path, staged):
    from p11lab.round_core.execute import BuilderIdentity
    from p11lab.round_core.worker import SandboxPolicy

    context_path, tools, envelope, binding, calls, prepare_calls, material = (
        _full_github_chain(tmp_path))
    if staged == "builder":
        material["builder"] = BuilderIdentity(
            image="sha256:" + "b" * 64, layers=("sha256:" + "c" * 64,),
            config_sha256="d" * 64, source_date_epoch=1)
    else:
        material["sandbox"] = SandboxPolicy(APP_WHEEL_FILENAME)
    evaluator_root = tmp_path / "evaluator"
    evaluator_root.mkdir()
    from p11lab.round_core.execute import execute_round

    with pytest.raises(TypeError, match="profile material"):
        execute_round(context_path, POLICY_ROOT, evaluator_root,
                      tmp_path / "output", tmp_path / "row.json", **material)
    assert prepare_calls == []


@pytest.mark.parametrize("param,value", [
    ("source_date_epoch", 1),
    ("sandbox_build_reports", ()),
    ("sandbox_startup_reports", ()),
    ("sandbox_timeout_seconds", 60),
])
def test_execute_fixture_rejects_github_only_params(tmp_path, param, value):
    def exploding_prepare(context, policy_root, output):
        raise AssertionError("prepare must not run for github-only params")

    evaluator_root = tmp_path / "evaluator"
    evaluator_root.mkdir()
    from p11lab.round_core.execute import execute_round

    with pytest.raises(TypeError, match="github-only"):
        execute_round(FIXTURES / "valid-context.json", POLICY_ROOT,
                      evaluator_root, tmp_path / "output", tmp_path / "row.json",
                      run_prepare=exploding_prepare, **{param: value})


@pytest.mark.parametrize("param,value", [
    ("sandbox_build_reports", ["build.json"]),
    ("sandbox_startup_reports", "startup.json"),
    ("sandbox_timeout_seconds", "60"),
])
def test_execute_github_mistyped_staging_is_usage(tmp_path, param, value):
    context_path, tools, envelope, binding, calls, prepare_calls, material = (
        _full_github_chain(tmp_path, use_real_binder=True))
    material[param] = value
    evaluator_root = tmp_path / "evaluator"
    evaluator_root.mkdir()
    output_json = tmp_path / "row.json"
    from p11lab.round_core.execute import execute_round

    with pytest.raises(TypeError, match="typed"):
        execute_round(context_path, POLICY_ROOT, evaluator_root,
                      tmp_path / "output", output_json, **material)
    assert not output_json.exists()


def test_execute_github_profile_pin_mismatch_refused(tmp_path):
    context_path, tools, envelope, binding, calls, prepare_calls, material = (
        _full_github_chain(tmp_path, prepare_options={"profile_pin": "0" * 64},
                           use_real_binder=True))
    row, _ = _run_api(tmp_path, material, context_path)
    assert (row["phase"], row["status"], row["cause"], row["exit_code"]) == (
        "produce", "refused", "EXECUTE_PRODUCE_INPUTS_MISSING", 3)
    assert "profile" in row["cause_detail"]
    assert [call[0] for call in calls] == ["evaluator"]


def test_execute_github_missing_authority_refused(tmp_path):
    context_path, tools, envelope, binding, calls, prepare_calls, material = (
        _full_github_chain(tmp_path))
    material["authority"] = None
    row, _ = _run_api(tmp_path, material, context_path)
    assert (row["phase"], row["status"], row["cause"], row["exit_code"]) == (
        "produce", "refused", "EXECUTE_PRODUCE_INPUTS_MISSING", 3)
    assert "authority" in row["cause_detail"]
    assert len(prepare_calls) == 1
    assert [call[0] for call in calls] == ["evaluator"]


def test_execute_github_default_binder_flows_profile_to_producer(tmp_path):
    context_path, tools, envelope, binding, calls, prepare_calls, material = (
        _full_github_chain(tmp_path, use_real_binder=True))
    row, output_dir = _run_api(tmp_path, material, context_path)
    assert (row["phase"], row["status"], row["cause"], row["exit_code"]) == (
        "produce", "infrastructure-error", "EXECUTE_PRODUCER_FAILED", 3)
    assert "builder config identity mismatch" in row["cause_detail"]
    assert row["producer_status"] == "infrastructure-error"
    assert (output_dir / "produce" / "producer-observation.json").is_file()
    assert [call[0] for call in calls] == ["evaluator"]


def test_execute_github_untyped_binder_is_producer_failure(tmp_path):
    context_path, tools, envelope, binding, calls, prepare_calls, material = (
        _full_github_chain(tmp_path))

    def untyped_binder(profile, prepared, **kwargs):
        calls.append(("produce-inputs",))
        return None, None

    material["bind_produce_inputs"] = untyped_binder
    row, _ = _run_api(tmp_path, material, context_path)
    assert (row["phase"], row["status"], row["cause"], row["exit_code"]) == (
        "produce", "infrastructure-error", "EXECUTE_PRODUCER_FAILED", 3)
    assert "untyped" in row["cause_detail"]


@pytest.mark.parametrize("missing", ["baseline", "candidate"])
def test_execute_github_missing_bind_inputs_refused(tmp_path, missing):
    context_path, tools, envelope, binding, calls, prepare_calls, material = (
        _full_github_chain(tmp_path))
    material[missing] = None
    row, _ = _run_api(tmp_path, material, context_path)
    assert (row["phase"], row["status"], row["cause"], row["exit_code"]) == (
        "bind", "refused", "EXECUTE_BIND_INPUTS_MISSING", 3)
    assert missing in row["cause_detail"]
    assert row["producer_status"] == "produced"
    assert row["evidence_admitted"] is False


def test_execute_github_missing_selected_is_fatal(tmp_path):
    context_path, tools, envelope, binding, calls, prepare_calls, material = (
        _full_github_chain(tmp_path, nodes=[]))
    row, _ = _run_api(tmp_path, material, context_path)
    assert (row["phase"], row["status"], row["cause"], row["exit_code"]) == (
        "bind", "refused", "EXECUTE_MISSING_SELECTED", 3)
    expected = sorted(set(envelope["endpoints"]["baseline"]["selected"])
                      | set(envelope["endpoints"]["candidate"]["selected"]))
    assert row["missing_selected"] == expected
    assert row["observed_count"] == 0
    assert [call[0] for call in calls] == [
        "evaluator", "produce-inputs", "bind"]


def test_execute_github_regressions_are_observed_not_normalized(tmp_path):
    context_path, tools, envelope, binding, calls, prepare_calls, material = (
        _full_github_chain(tmp_path, compare_fixture="compare-regressions.json"))
    row, _ = _run_api(tmp_path, material, context_path)
    assert (row["status"], row["cause"], row["exit_code"]) == (
        "executed", "EXECUTE_OK", 0)
    assert row["comparison_positive"] is False
    assert row["regressions"] == [{
        "node_id": "/executor/tests/test_a.py::test_one", "phase": "execute",
        "old": "pass", "new": "fail", "axis": "checker-direct"}]
    assert row["improvements"] == [{
        "node_id": "/executor/tests/test_b.py::test_two", "phase": "execute",
        "old": ["fail", "flaky"], "new": "pass", "axis": "checker-direct"}]


def test_execute_github_coverage_loss_vetoes_coverage_positive(tmp_path):
    context_path, tools, envelope, binding, calls, prepare_calls, material = (
        _full_github_chain(tmp_path, coverage_fixture="coverage-loss.json"))
    row, output_dir = _run_api(tmp_path, material, context_path)
    assert (row["status"], row["exit_code"]) == ("executed", 0)
    assert row["coverage_positive"] is False
    assert row["comparison_positive"] is True
    assert (output_dir / "coverage" / "verdict-coverage.json").read_bytes() == (
        GITHUB_FIXTURES / "coverage-loss.json").read_bytes()


def test_execute_github_provider_failure_carries_row_with_exit_zero(tmp_path):
    from p11lab.round_core.execute import CompareOutcome

    context_path, tools, envelope, binding, calls, prepare_calls, material = (
        _full_github_chain(tmp_path))
    base_compare = material["run_compare"]

    def failing_compare(*args):
        outcome = base_compare(*args)
        return CompareOutcome(outcome.regressions, outcome.improvements,
                              outcome.unstable, outcome.counts, positive=False,
                              provider_failure=True,
                              provider_failure_detail="candidate provider crashed")

    material["run_compare"] = failing_compare
    row, _ = _run_api(tmp_path, material, context_path)
    assert (row["phase"], row["status"], row["cause"], row["exit_code"]) == (
        "done", "provider-failure", "EXECUTE_PROVIDER_FAILED", 0)
    assert row["cause_detail"] == "candidate provider crashed"
    assert row["comparison_positive"] is False
    assert [call[0] for call in calls] == [
        "evaluator", "produce-inputs", "bind", "compare", "coverage"]


def test_execute_github_round_positive_never_true(tmp_path):
    (tmp_path / "executed").mkdir()
    (tmp_path / "refused").mkdir()
    executed = _full_github_chain(tmp_path / "executed")
    _, executed_dir = _run_api(tmp_path / "executed", executed[-1], executed[0])
    capsule = json.loads((executed_dir / "round-capsule.json").read_text())
    assert capsule["round_positive"] is False
    refused = _full_github_chain(
        tmp_path / "refused",
        prepare_options={"authority": "protected-profile-source-verified",
                         "include_owner_proof": False})
    _, refused_dir = _run_api(tmp_path / "refused", refused[-1], refused[0])
    capsule = json.loads((refused_dir / "round-capsule.json").read_text())
    assert capsule["round_positive"] is False
    prepare = json.loads(
        (refused_dir / "prepare" / "round-inputs.json").read_text())
    assert prepare["round_positive"] is False


@pytest.mark.skipif(os.environ.get("P11LAB_EXECUTE_GITHUB_LIVE") != "1",
                    reason="live github execution needs network, Docker and owner proof")
def test_live_github_execute_designed_not_run(tmp_path):
    """Env-gated live proof: real prepare, owner proof, Docker, sealed evaluator."""
    from p11lab.comparison import LocalComparisonWitness
    from p11lab.round_core.execute import execute_round
    from p11lab.round_core.inputs import freeze_comparison_expectation, load_json

    expectation = load_json(Path(os.environ["P11LAB_EXECUTE_GITHUB_EXPECTATION"]).read_bytes())
    authority = LocalComparisonWitness(
        freeze_comparison_expectation(expectation),
        Path(os.environ["P11LAB_EXECUTE_GITHUB_OBSERVATIONS"]).read_bytes())
    row = execute_round(
        Path(os.environ["P11LAB_EXECUTE_GITHUB_CONTEXT"]), None,
        Path(os.environ["P11LAB_W01_OUTPUT"]),
        tmp_path / "output", tmp_path / "row.json",
        authority=authority,
        baseline=Path(os.environ["P11LAB_EXECUTE_GITHUB_BASELINE"]),
        candidate=Path(os.environ["P11LAB_EXECUTE_GITHUB_CANDIDATE"]))
    assert set(row) == EXPECTED_ROW_FIELDS
    assert row["exit_code"] == 0
    assert row["transport"] == "github"
    capsule = json.loads((tmp_path / "output" / "round-capsule.json").read_text())
    assert capsule["round_positive"] is False
