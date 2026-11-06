"""`p11lab round execute` fixture-transport chain; hermetic, no network/Docker."""
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
POLICY_ROOT = FIXTURES / "policy"
EXECUTE_FIXTURES = FIXTURES / "execute"
COMPARISON = Path(__file__).parents[1] / "fixtures/comparison/checker-direct"

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
def _without_ci_markers(monkeypatch):
    # Mechanics tests exercise fixture transport in-process; without this
    # the runner's own CI markers trip the production guard. The guard
    # itself stays covered by test_prepare_refuses_fixture_transport_in_ci.
    # Mirrors the _env() scrubbing used for subprocess runs below.
    monkeypatch.delenv('CI', raising=False)
    monkeypatch.delenv('GITHUB_ACTIONS', raising=False)


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


def _write_context(directory, name, mutation=None):
    context = json.loads((FIXTURES / "valid-context.json").read_bytes())
    if mutation is not None:
        mutation(context)
    path = directory / name
    path.write_text(json.dumps(context))
    return path


def _candidate_sha():
    envelope = json.loads((COMPARISON / "envelope.json").read_bytes())
    return envelope["protected"]["selected_candidate_source_sha"]


def _mint_execute_dist(directory):
    """Mint a stage-compatible fixture dist bound to the comparison envelope."""
    from p11lab.round_core.inputs import canonical, digest

    target = directory / "execute-dist"
    target.mkdir()
    candidate_sha = _candidate_sha()
    identity = {"attempt": 2, "candidate_sha": candidate_sha,
                "merge_base_sha": "c" * 40, "repository_id": 123, "run_id": 456,
                "target_sha": "b" * 40}
    previous = zipfile.ZipFile(FIXTURES / "fixture-dist.zip")
    wheels = {name: previous.read(name) for name in (
        "primary_wheel/fixture_app-0.0.1-py3-none-any.whl",
        "sdist_probe_wheel/fixture_app-0.0.1-py3-none-any.whl",
        "replay_base_wheel/fixture_app-0.0.1-py3-none-any.whl",
        "deps/fixture_pkg-0.0.1-py3-none-any.whl")}
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
    lock_raw = previous.read("dependency-lock.json")
    source_raw = canonical({"revision": candidate_sha})
    build_raw = canonical({"identity": identity, "roles_sha256": digest(roles)})
    manifest = {"schema_version": 1, "identity": identity, "roles": roles,
                "dependency_lock_sha256": hashlib.sha256(lock_raw).hexdigest(),
                "source_receipt_sha256": hashlib.sha256(source_raw).hexdigest(),
                "build_receipt_sha256": hashlib.sha256(build_raw).hexdigest()}
    manifest_raw = canonical(manifest)
    archive = target / "execute-dist.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as out:
        out.writestr("candidate-manifest.json", manifest_raw)
        out.writestr("dependency-lock.json", lock_raw)
        out.writestr("source-receipt.json", source_raw)
        out.writestr("build-receipt.json", build_raw)
        for row in roles.values():
            content = sdist if row["path"].endswith(".tar.gz") else wheels[row["path"]]
            out.writestr(row["path"], content)
        out.writestr("deps/fixture_pkg-0.0.1-py3-none-any.whl",
                     wheels["deps/fixture_pkg-0.0.1-py3-none-any.whl"])
    metadata = json.loads((FIXTURES / "fixture-metadata.json").read_bytes())
    artifact = metadata["listing"]["artifacts"][0]
    artifact["name"] = f"p11lab-framework-dist-{candidate_sha}-2"
    artifact["digest"] = "sha256:" + hashlib.sha256(archive.read_bytes()).hexdigest()
    artifact["size_in_bytes"] = archive.stat().st_size
    metadata_path = target / "execute-metadata.json"
    metadata_path.write_text(json.dumps(metadata))
    context = json.loads((FIXTURES / "valid-context.json").read_bytes())
    context["identity"] = identity
    context["artifact_path"] = str(archive)
    context["fixture_metadata_path"] = str(metadata_path)
    context["data_root"] = str((FIXTURES / "input-data").resolve())
    context["dependency_lock_sha256"] = hashlib.sha256(lock_raw).hexdigest()
    context_path = target / "execute-context.json"
    context_path.write_text(json.dumps(context))
    return context_path


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


WHEEL_FILENAME = "fixture_pkg-0.0.1-py3-none-any.whl"


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


def _full_chain(directory, *, compare_fixture="compare-clean.json",
                coverage_fixture="coverage-clean.json", nodes=None,
                compare_error=None, coverage_error=None, bind_error=None,
                mutate_binding=None):
    """Assemble hermetic material plus seams for one full API run."""
    from p11lab.round_core.execute import (
        BuilderIdentity, parse_compare_output, parse_coverage_output)
    from p11lab.round_core.inputs import digest
    from p11lab.round_core.worker import SandboxPolicy

    context_path = _mint_execute_dist(directory)
    tools = _make_tools(directory / "tools")
    authority, envelope, baseline, candidate = _authority_and_endpoints(directory)
    builder = BuilderIdentity(
        image="sha256:" + "b" * 64, layers=("sha256:" + "c" * 64,),
        config_sha256=digest({"Env": ["PATH=/usr/bin:/bin"]}),
        source_date_epoch=1)
    sandbox = SandboxPolicy(WHEEL_FILENAME, startup_reports=("startup.json",))
    wheel_bytes = _make_wheel_bytes()
    tars = [_make_tar({WHEEL_FILENAME: wheel_bytes}),
            _make_tar(_install_mapping(wheel_bytes)),
            _make_tar({"startup.json": b'{"ok": true}'})]
    engine = SucceedingDocker(builder.layers,
                              _write_docker_shim(directory, tars))
    binding = _fake_binding(envelope, authority, tools, baseline, candidate,
                            nodes=nodes)
    if mutate_binding is not None:
        mutate_binding(binding)
    calls = []

    def bind_evaluator(root):
        calls.append(("evaluator", root))
        return tools

    def bind_envelope(given_envelope, endpoints):
        calls.append(("bind", endpoints))
        if bind_error is not None:
            raise bind_error
        assert given_envelope == envelope
        assert set(endpoints) == {"authority", "evaluator", "baseline", "candidate"}
        assert endpoints["authority"] is authority
        assert endpoints["evaluator"] is tools
        assert endpoints["baseline"] == baseline
        assert endpoints["candidate"] == candidate
        return binding

    def run_compare(sealed, first, second, given_binding, workdir):
        calls.append(("compare", first, second, workdir))
        if compare_error is not None:
            raise compare_error
        assert sealed is tools
        assert given_binding == binding
        raw = (EXECUTE_FIXTURES / compare_fixture).read_bytes()
        (workdir / "verdict-compare.json").write_bytes(raw)
        return parse_compare_output(raw)

    def run_coverage(sealed, first, second, given_binding, workdir):
        calls.append(("coverage", first, second, workdir))
        if coverage_error is not None:
            raise coverage_error
        assert sealed is tools
        assert given_binding == binding
        raw = (EXECUTE_FIXTURES / coverage_fixture).read_bytes()
        (workdir / "verdict-coverage.json").write_bytes(raw)
        return parse_coverage_output(raw)

    material = {"builder": builder, "authority": authority, "sandbox": sandbox,
                "baseline": baseline, "candidate": candidate, "engine": engine,
                "bind_evaluator": bind_evaluator, "bind_envelope": bind_envelope,
                "run_compare": run_compare, "run_coverage": run_coverage}
    return context_path, tools, envelope, binding, calls, material


def test_cli_missing_context_is_usage(tmp_path):
    completed = _run_execute(tmp_path / "absent.json", tmp_path / "evaluator",
                             tmp_path / "output", tmp_path / "row.json", tmp_path)
    assert completed.returncode == 2
    assert completed.stderr.strip().startswith("p11lab: ")
    assert not (tmp_path / "row.json").exists()


def test_cli_malformed_context_is_usage(tmp_path):
    context = tmp_path / "context.json"
    context.write_text("not json")
    completed = _run_execute(context, tmp_path / "evaluator",
                             tmp_path / "output", tmp_path / "row.json", tmp_path)
    assert completed.returncode == 2
    assert not (tmp_path / "row.json").exists()


def test_cli_tier_mismatch_is_usage(tmp_path):
    evaluator = tmp_path / "evaluator"
    evaluator.mkdir()
    completed = _run_execute(FIXTURES / "valid-context.json", evaluator,
                             tmp_path / "output", tmp_path / "row.json",
                             tmp_path, tier="nightly")
    assert completed.returncode == 2
    assert "tier" in completed.stderr


def test_cli_unknown_tier_is_usage(tmp_path):
    completed = _run_execute(FIXTURES / "valid-context.json", tmp_path / "evaluator",
                             tmp_path / "output", tmp_path / "row.json",
                             tmp_path, tier="bogus")
    assert completed.returncode == 2


def test_cli_existing_output_dir_is_usage(tmp_path):
    evaluator = tmp_path / "evaluator"
    evaluator.mkdir()
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    completed = _run_execute(FIXTURES / "valid-context.json", evaluator,
                             output_dir, tmp_path / "row.json", tmp_path)
    assert completed.returncode == 2
    assert not (tmp_path / "row.json").exists()


def test_cli_github_transport_refused_before_prepare(tmp_path):
    context = _write_context(tmp_path, "github-context.json", lambda c: c.update(
        transport="github", control_sha="e" * 40))
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
    receipt = json.loads((output_dir / "round-receipt.json").read_text())
    assert set(receipt) == EXPECTED_RECEIPT_FIELDS


def test_cli_fixture_without_evaluator_reaches_real_bootstrap_refusal(tmp_path):
    evaluator = tmp_path / "evaluator"
    evaluator.mkdir()
    output_dir = tmp_path / "output"
    output_json = tmp_path / "row.json"
    completed = _run_execute(FIXTURES / "valid-context.json", evaluator,
                             output_dir, output_json, tmp_path)
    assert completed.returncode == 3, completed.stderr
    row = json.loads(output_json.read_text())
    assert set(row) == EXPECTED_ROW_FIELDS
    assert (row["phase"], row["status"], row["cause"], row["exit_code"]) == (
        "bootstrap", "refused", "EXECUTE_EVALUATOR_REFUSED", 3)
    assert row["cause_detail"]
    assert row["transport"] == "fixture"
    assert (row["lane"], row["provider"], row["attempt"]) == (
        "softhsm2",
        {"family": "softhsm2", "channel": "release", "platform": "linux/amd64"}, 2)
    assert (output_dir / "prepare" / "dist.zip").is_file()
    assert (output_dir / "prepare" / "round-inputs.json").is_file()
    assert json.loads(completed.stdout) == row
    capsule = json.loads((output_dir / "round-capsule.json").read_text())
    assert capsule["round_positive"] is False
    assert capsule["verdict_row"] == row


def test_parse_compare_clean_is_positive():
    from p11lab.round_core.execute import parse_compare_output

    outcome = parse_compare_output((EXECUTE_FIXTURES / "compare-clean.json").read_bytes())
    assert outcome.positive is True
    assert outcome.provider_failure is False
    assert outcome.regressions == () and outcome.improvements == ()
    assert outcome.unstable == ()


def test_parse_compare_regressions_and_improvements():
    from p11lab.round_core.execute import parse_compare_output

    outcome = parse_compare_output(
        (EXECUTE_FIXTURES / "compare-regressions.json").read_bytes())
    assert outcome.positive is False
    assert outcome.provider_failure is False
    assert [dict(row) for row in outcome.regressions] == [{
        "node_id": "/executor/tests/test_a.py::test_one", "phase": "execute",
        "old": "pass", "new": "fail", "axis": "checker-direct"}]
    assert [dict(row) for row in outcome.improvements] == [{
        "node_id": "/executor/tests/test_b.py::test_two", "phase": "execute",
        "old": ["fail", "flaky"], "new": "pass", "axis": "checker-direct"}]
    assert outcome.counts == {"compared": 3, "improvements": 1,
                              "regressions": 1, "unstable": 0}


def test_parse_compare_unstable_vetoes_positive():
    from p11lab.round_core.execute import parse_compare_output

    outcome = parse_compare_output(
        (EXECUTE_FIXTURES / "compare-unstable.json").read_bytes())
    assert outcome.positive is False
    assert outcome.unstable == ("/executor/tests/test_a.py::test_one",)


@pytest.mark.parametrize("raw", [b"not json", b"[]", b"{}", b'{"regressions": []}'])
def test_parse_compare_rejects_malformed(raw):
    from p11lab.round_core.execute import parse_compare_output

    with pytest.raises(ValueError):
        parse_compare_output(raw)


def test_parse_compare_rejects_malformed_row():
    from p11lab.round_core.execute import parse_compare_output

    raw = json.dumps({"regressions": [{"node_id": 5}], "improvements": [],
                      "unstable": [], "counts": {}}).encode()
    with pytest.raises(ValueError):
        parse_compare_output(raw)


def test_parse_compare_empty_verdict_has_no_provider_attribution():
    from p11lab.round_core.execute import parse_compare_output

    raw = json.dumps({"regressions": [], "improvements": [],
                      "unstable": [], "counts": {}}).encode()
    outcome = parse_compare_output(raw)
    assert outcome.positive is True
    assert outcome.provider_failure is False
    assert outcome.provider_failure_detail is None


def test_parse_compare_checker_direct_regression_has_no_provider_attribution():
    from p11lab.round_core.execute import parse_compare_output

    outcome = parse_compare_output(
        (EXECUTE_FIXTURES / "compare-regressions.json").read_bytes())
    assert outcome.positive is False
    assert outcome.regressions[0]["phase"] == "execute"
    assert outcome.regressions[0]["axis"] == "checker-direct"
    assert outcome.provider_failure is False
    assert outcome.provider_failure_detail is None


def test_parse_compare_provider_named_row_has_no_provider_attribution():
    from p11lab.round_core.execute import parse_compare_output

    row = {"node_id": "provider/provider::test_flaky", "phase": "provider",
           "old": "pass", "new": "fail", "axis": "provider"}
    raw = json.dumps({"regressions": [row], "improvements": [],
                      "unstable": [], "counts": {"compared": 1}}).encode()
    outcome = parse_compare_output(raw)
    assert outcome.positive is False
    assert outcome.provider_failure is False
    assert outcome.provider_failure_detail is None


def test_parse_compare_unstable_only_has_no_provider_attribution():
    from p11lab.round_core.execute import parse_compare_output

    outcome = parse_compare_output(
        (EXECUTE_FIXTURES / "compare-unstable.json").read_bytes())
    assert outcome.positive is False
    assert outcome.regressions == ()
    assert outcome.unstable == ("/executor/tests/test_a.py::test_one",)
    assert outcome.provider_failure is False
    assert outcome.provider_failure_detail is None


def test_parse_compare_improvements_only_has_no_provider_attribution():
    from p11lab.round_core.execute import parse_compare_output

    outcome = parse_compare_output(
        (EXECUTE_FIXTURES / "compare-improvements.json").read_bytes())
    assert outcome.positive is True
    assert outcome.regressions == ()
    assert len(outcome.improvements) == 1
    assert outcome.provider_failure is False
    assert outcome.provider_failure_detail is None


def test_parse_compare_rejects_malformed_row_shape():
    from p11lab.round_core.execute import parse_compare_output

    raw = json.dumps({"regressions": [{"node_id": "x", "phase": "p",
                                       "old": "a", "new": "b",
                                       "axis": "c", "extra": 1}],
                      "improvements": [], "unstable": [],
                      "counts": {}}).encode()
    with pytest.raises(ValueError, match="invalid verdict row"):
        parse_compare_output(raw)


def test_parse_coverage_clean_is_positive():
    from p11lab.round_core.execute import parse_coverage_output

    outcome = parse_coverage_output(
        (EXECUTE_FIXTURES / "coverage-clean.json").read_bytes())
    assert (outcome.positive, outcome.has_loss) == (True, False)
    assert outcome.states_compared == ("attempted", "accepted")
    assert outcome.lost_by_state == {}


def test_parse_coverage_loss_vetoes_positive():
    from p11lab.round_core.execute import parse_coverage_output

    outcome = parse_coverage_output(
        (EXECUTE_FIXTURES / "coverage-loss.json").read_bytes())
    assert (outcome.positive, outcome.has_loss) == (False, True)
    assert outcome.lost_by_state == {"attempted": ["CKM_AES_ECB", "CKM_SHA256"]}


@pytest.mark.parametrize("raw", [b"not json", b"[]", b"{}",
                                 b'{"has_loss": false}'])
def test_parse_coverage_rejects_malformed(raw):
    from p11lab.round_core.execute import parse_coverage_output

    with pytest.raises(ValueError):
        parse_coverage_output(raw)


def test_cause_table_is_closed_over_exits_and_statuses():
    from p11lab.round_core.causes import CAUSE_EXIT, CAUSE_STATUS, ExecuteCause

    assert set(CAUSE_EXIT) == set(ExecuteCause)
    assert set(CAUSE_STATUS) == set(ExecuteCause)
    assert {cause.value for cause in ExecuteCause} == {
        "EXECUTE_OK", "EXECUTE_TRANSPORT_REFUSED", "EXECUTE_PRODUCE_INPUTS_MISSING",
        "EXECUTE_PRODUCER_FAILED", "EXECUTE_EVALUATOR_REFUSED",
        "EXECUTE_EVALUATOR_FAILED", "EXECUTE_BIND_INPUTS_MISSING",
        "EXECUTE_BIND_REFUSED", "EXECUTE_BIND_FAILED", "EXECUTE_ENDPOINT_DRIFT",
        "EXECUTE_COMPARE_FAILED", "EXECUTE_MISSING_SELECTED",
        "EXECUTE_COVERAGE_FAILED", "EXECUTE_PROVIDER_FAILED"}
    for cause, code in CAUSE_EXIT.items():
        assert code in (0, 3), cause
    assert {cause for cause, code in CAUSE_EXIT.items() if code == 0} == {
        ExecuteCause.EXECUTE_OK, ExecuteCause.EXECUTE_PROVIDER_FAILED}
    for cause, status in CAUSE_STATUS.items():
        assert status in ("executed", "provider-failure", "infrastructure-error",
                          "refused"), cause
    assert CAUSE_STATUS[ExecuteCause.EXECUTE_OK] == "executed"
    assert CAUSE_STATUS[ExecuteCause.EXECUTE_PROVIDER_FAILED] == "provider-failure"


def test_new_modules_use_no_private_internals():
    import re

    import p11lab

    root = Path(p11lab.__file__).parent
    for name in ("round_core/execute.py", "round_core/causes.py"):
        assert (root / name).is_file(), (root, name)
    pattern = re.compile(
        r"(worker|bootstrap|comparison|results|inputs)\._|"
        r"from p11lab\.(round_core\.)?(worker|bootstrap|comparison|results|inputs)"
        r" import [^\n]*\b_[A-Za-z]")
    for name in ("round_core/execute.py", "round_core/causes.py"):
        text = (root / name).read_text()
        assert pattern.search(text) is None, name
        for private in ("_snapshot", "_PUBLIC_EVIDENCE", "_PUBLIC_CLI",
                        "_API_PROBE", "_DRIVER", "_source_content", "_OutputVolume"):
            assert private not in text, (name, private)


EXPECTED_POLICY_DIGEST = "a3f00031dfb25dbf26399c1ab696663dcc1515b45274d97370eeaf372b77d745"
EXPECTED_COVERAGE_STATES = (
    "advertised", "accepted", "attempted", "rejected_cleanly",
    "skipped_by_capability", "crashed", "timeout", "selected",
    "selection_rejected", "invoked")


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
    return {state + "_names": list(mechanisms[state + "_names"][:10])
            for state in EXPECTED_COVERAGE_STATES}


def test_execute_clean_chain_is_executed_exit_zero(tmp_path):
    from p11lab.round_core.inputs import canonical, digest

    context_path, tools, envelope, binding, calls, material = _full_chain(tmp_path)
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
        "softhsm2", "fixture", "pr-smoke", 2)
    assert row["provider"] == {"family": "softhsm2", "channel": "release",
                               "platform": "linux/amd64"}
    assert [call[0] for call in calls] == ["evaluator", "bind", "compare", "coverage"]
    assert (output_dir / "produce" / "producer-observation.json").is_file()
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
        "Fixture transport is local-only and non-authoritative; no caller, "
        "producer, or publication authority is established.",
        "Acceptance blocked: " + receipt["acceptance"]["reason"]]


def test_execute_provider_failure_carries_row_with_exit_zero(tmp_path):
    from p11lab.round_core.execute import CompareOutcome

    context_path, tools, envelope, binding, calls, material = _full_chain(tmp_path)
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
    assert [call[0] for call in calls] == ["evaluator", "bind", "compare", "coverage"]


def test_execute_regressions_are_observed_not_normalized(tmp_path):
    context_path, tools, envelope, binding, calls, material = _full_chain(
        tmp_path, compare_fixture="compare-regressions.json")
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


def test_execute_improvements_only_preserves_positive(tmp_path):
    context_path, tools, envelope, binding, calls, material = _full_chain(
        tmp_path, compare_fixture="compare-improvements.json")
    row, _ = _run_api(tmp_path, material, context_path)
    assert (row["status"], row["exit_code"]) == ("executed", 0)
    assert row["comparison_positive"] is True
    assert len(row["improvements"]) == 1 and row["regressions"] == []


def test_execute_unstable_vetoes_comparison_positive(tmp_path):
    context_path, tools, envelope, binding, calls, material = _full_chain(
        tmp_path, compare_fixture="compare-unstable.json")
    row, _ = _run_api(tmp_path, material, context_path)
    assert (row["status"], row["exit_code"]) == ("executed", 0)
    assert row["comparison_positive"] is False


def test_execute_coverage_loss_vetoes_coverage_positive(tmp_path):
    context_path, tools, envelope, binding, calls, material = _full_chain(
        tmp_path, coverage_fixture="coverage-loss.json")
    row, output_dir = _run_api(tmp_path, material, context_path)
    assert (row["status"], row["exit_code"]) == ("executed", 0)
    assert row["coverage_positive"] is False
    assert row["comparison_positive"] is True
    assert (output_dir / "coverage" / "verdict-coverage.json").read_bytes() == (
        EXECUTE_FIXTURES / "coverage-loss.json").read_bytes()


def test_execute_missing_selected_is_fatal(tmp_path):
    context_path, tools, envelope, binding, calls, material = _full_chain(
        tmp_path, nodes=[])
    row, _ = _run_api(tmp_path, material, context_path)
    assert (row["phase"], row["status"], row["cause"], row["exit_code"]) == (
        "bind", "refused", "EXECUTE_MISSING_SELECTED", 3)
    expected = sorted(set(envelope["endpoints"]["baseline"]["selected"])
                      | set(envelope["endpoints"]["candidate"]["selected"]))
    assert row["missing_selected"] == expected
    assert row["observed_count"] == 0
    assert [call[0] for call in calls] == ["evaluator", "bind"]


def test_execute_compare_crash_is_infrastructure_error(tmp_path):
    context_path, tools, envelope, binding, calls, material = _full_chain(
        tmp_path, compare_error=RuntimeError("sealed compare crashed"))
    row, _ = _run_api(tmp_path, material, context_path)
    assert (row["phase"], row["status"], row["cause"], row["exit_code"]) == (
        "compare", "infrastructure-error", "EXECUTE_COMPARE_FAILED", 3)
    assert "sealed compare crashed" in row["cause_detail"]
    assert row["evidence_admitted"] is True
    assert row["evidence_complete"] is False


def test_execute_coverage_crash_is_infrastructure_error(tmp_path):
    context_path, tools, envelope, binding, calls, material = _full_chain(
        tmp_path, coverage_error=RuntimeError("sealed coverage crashed"))
    row, _ = _run_api(tmp_path, material, context_path)
    assert (row["phase"], row["status"], row["cause"], row["exit_code"]) == (
        "coverage", "infrastructure-error", "EXECUTE_COVERAGE_FAILED", 3)
    assert row["comparison_positive"] is True


def test_execute_endpoint_drift_fails_closed(tmp_path):
    context_path, tools, envelope, binding, calls, material = _full_chain(tmp_path)
    (material["candidate"] / "coverage.json").write_text('{"tampered": true}')
    row, _ = _run_api(tmp_path, material, context_path)
    assert (row["phase"], row["status"], row["cause"], row["exit_code"]) == (
        "compare", "infrastructure-error", "EXECUTE_ENDPOINT_DRIFT", 3)
    assert [call[0] for call in calls] == ["evaluator", "bind"]


def test_execute_producer_failure_is_infrastructure_error(tmp_path):
    from p11lab.docker import CommandResult

    context_path, tools, envelope, binding, calls, material = _full_chain(tmp_path)

    class FailingEngine(SucceedingDocker):
        def execute(self, identity, timeout, interrupted):
            self.resources[identity]["State"] = {"Running": True, "Pid": 1}
            return CommandResult(1, "", "", False)

    material["engine"] = FailingEngine(material["engine"].layers,
                                       material["engine"].env)
    row, output_dir = _run_api(tmp_path, material, context_path)
    assert (row["phase"], row["status"], row["cause"], row["exit_code"]) == (
        "produce", "infrastructure-error", "EXECUTE_PRODUCER_FAILED", 3)
    assert row["producer_status"] == "infrastructure-error"
    assert row["evaluator_receipt_sha256"] == "a" * 64
    assert (output_dir / "produce" / "producer-observation.json").is_file()
    assert [call[0] for call in calls] == ["evaluator"]


def test_execute_evaluator_pin_refusal_keeps_exact_text(tmp_path):
    context_path, tools, envelope, binding, calls, material = _full_chain(tmp_path)

    def refusing_binder(root):
        calls.append(("evaluator", root))
        raise ValueError("expected reviewed source pin and sealed dependency roster")

    material["bind_evaluator"] = refusing_binder
    row, output_dir = _run_api(tmp_path, material, context_path)
    assert (row["phase"], row["status"], row["cause"], row["exit_code"]) == (
        "bootstrap", "refused", "EXECUTE_EVALUATOR_REFUSED", 3)
    assert row["cause_detail"] == (
        "expected reviewed source pin and sealed dependency roster")
    assert not (output_dir / "produce").exists()


def test_execute_evaluator_crash_is_infrastructure_error(tmp_path):
    context_path, tools, envelope, binding, calls, material = _full_chain(tmp_path)

    def crashing_binder(root):
        raise OSError("evaluator disk gone")

    material["bind_evaluator"] = crashing_binder
    row, _ = _run_api(tmp_path, material, context_path)
    assert (row["phase"], row["status"], row["cause"], row["exit_code"]) == (
        "bootstrap", "infrastructure-error", "EXECUTE_EVALUATOR_FAILED", 3)


@pytest.mark.parametrize("missing", ["builder", "authority", "sandbox"])
def test_execute_missing_produce_inputs_refused(tmp_path, missing):
    context_path, tools, envelope, binding, calls, material = _full_chain(tmp_path)
    material[missing] = None
    row, _ = _run_api(tmp_path, material, context_path)
    assert (row["phase"], row["status"], row["cause"], row["exit_code"]) == (
        "produce", "refused", "EXECUTE_PRODUCE_INPUTS_MISSING", 3)
    assert missing in row["cause_detail"]
    assert row["producer_status"] is None
    assert [call[0] for call in calls] == ["evaluator"]


@pytest.mark.parametrize("missing", ["baseline", "candidate"])
def test_execute_missing_bind_inputs_refused(tmp_path, missing):
    context_path, tools, envelope, binding, calls, material = _full_chain(tmp_path)
    material[missing] = None
    row, _ = _run_api(tmp_path, material, context_path)
    assert (row["phase"], row["status"], row["cause"], row["exit_code"]) == (
        "bind", "refused", "EXECUTE_BIND_INPUTS_MISSING", 3)
    assert missing in row["cause_detail"]
    assert row["producer_status"] == "produced"
    assert row["evidence_admitted"] is False


def test_execute_bind_mismatch_refused_with_exact_text(tmp_path):
    context_path, tools, envelope, binding, calls, material = _full_chain(
        tmp_path, bind_error=ValueError(
            "protected endpoint file roster/length/hash mismatch"))
    row, _ = _run_api(tmp_path, material, context_path)
    assert (row["phase"], row["status"], row["cause"], row["exit_code"]) == (
        "bind", "refused", "EXECUTE_BIND_REFUSED", 3)
    assert row["cause_detail"] == "protected endpoint file roster/length/hash mismatch"


def test_execute_bind_crash_is_infrastructure_error(tmp_path):
    context_path, tools, envelope, binding, calls, material = _full_chain(
        tmp_path, bind_error=RuntimeError("binder crashed"))
    row, _ = _run_api(tmp_path, material, context_path)
    assert (row["phase"], row["status"], row["cause"], row["exit_code"]) == (
        "bind", "infrastructure-error", "EXECUTE_BIND_FAILED", 3)


def test_execute_round_positive_never_true(tmp_path):
    context_path, tools, envelope, binding, calls, material = _full_chain(tmp_path)
    _, output_dir = _run_api(tmp_path, material, context_path)
    capsule = json.loads((output_dir / "round-capsule.json").read_text())
    assert capsule["round_positive"] is False
    prepare = json.loads((output_dir / "prepare" / "round-inputs.json").read_text())
    assert prepare["round_positive"] is False


@pytest.mark.skipif(os.environ.get("P11LAB_EXECUTE_LIVE") != "1",
                    reason="live execution needs Docker, network and staged round inputs")
def test_live_execute_designed_not_run(tmp_path):
    """Env-gated live proof: real Docker, real sealed evaluator, staged inputs."""
    from p11lab.comparison import LocalComparisonWitness
    from p11lab.round_core.execute import BuilderIdentity, execute_round
    from p11lab.round_core.inputs import freeze_comparison_expectation, load_json
    from p11lab.round_core.worker import SandboxPolicy

    context_path = Path(os.environ["P11LAB_EXECUTE_CONTEXT"])
    builder_raw = json.loads(Path(os.environ["P11LAB_EXECUTE_BUILDER"]).read_text())
    builder = BuilderIdentity(
        image=builder_raw["image"], layers=tuple(builder_raw["layers"]),
        config_sha256=builder_raw["config_sha256"],
        source_date_epoch=builder_raw["source_date_epoch"])
    expectation = load_json(Path(os.environ["P11LAB_EXECUTE_EXPECTATION"]).read_bytes())
    authority = LocalComparisonWitness(
        freeze_comparison_expectation(expectation),
        Path(os.environ["P11LAB_EXECUTE_OBSERVATIONS"]).read_bytes())
    sandbox_raw = json.loads(Path(os.environ["P11LAB_EXECUTE_SANDBOX"]).read_text())
    sandbox = SandboxPolicy(
        sandbox_raw["wheel_filename"],
        build_reports=tuple(sandbox_raw.get("build_reports", ())),
        startup_reports=tuple(sandbox_raw.get("startup_reports", ())),
        timeout_seconds=sandbox_raw.get("timeout_seconds", 60),
        max_output_bytes=sandbox_raw.get("max_output_bytes", 96 * 1024 * 1024))
    row = execute_round(
        context_path, None, Path(os.environ["P11LAB_W01_OUTPUT"]),
        tmp_path / "output", tmp_path / "row.json", builder=builder,
        authority=authority, sandbox=sandbox,
        baseline=Path(os.environ["P11LAB_EXECUTE_BASELINE"]),
        candidate=Path(os.environ["P11LAB_EXECUTE_CANDIDATE"]))
    assert set(row) == EXPECTED_ROW_FIELDS
    assert row["exit_code"] == 0
    capsule = json.loads((tmp_path / "output" / "round-capsule.json").read_text())
    assert capsule["round_positive"] is False
