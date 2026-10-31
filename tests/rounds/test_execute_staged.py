"""B-C2x CLI bridge + staged-entry mechanics; hermetic, no network/Docker.

MECHANICS-COMPLETE / H-C-NOT-DEMONSTRATED: every staged run here uses
minted fixtures (see fixtures/execute-staged/_PROVENANCE.json). Parsing a
staged authority file into a typed witness never confers producer
authority; live honest-control proof waits on auth-gated enrollment plus
an authorized live dispatch. Run IDs below are minted, capsules stay
diagnostic, and ``round_positive`` is always false.
"""
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
STAGED_FIXTURES = FIXTURES / "execute-staged"
EXECUTE_FIXTURES = FIXTURES / "execute"
COMPARISON = Path(__file__).parents[1] / "fixtures/comparison/checker-direct"

# Row/capsule/receipt shapes are frozen: these sets must match the C1
# suites exactly (any row-schema change needs explicit root pre-approval).
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
EXPECTED_POLICY_DIGEST = ("a3f00031dfb25dbf26399c1ab696663dcc1515b45274d97370"
                          "eeaf372b77d745")
EXPECTED_COVERAGE_STATES = (
    "advertised", "accepted", "attempted", "rejected_cleanly",
    "skipped_by_capability", "crashed", "timeout", "selected",
    "selection_rejected", "invoked",
)
BRIDGE_TOGETHER = "requires --authority, --baseline and --candidate together"


def _env():
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[2] / "src")
    env.pop("CI", None)
    env.pop("GITHUB_ACTIONS", None)
    env.pop("GH_TOKEN", None)
    env.pop("GITHUB_TOKEN", None)
    return env


def _run_execute(context, evaluator_root, output_dir, output_json, cwd,
                 tier=None, authority=None, baseline=None, candidate=None):
    argv = [sys.executable, "-m", "p11lab", "round", "execute",
           "--context", str(context), "--policy-root", str(POLICY_ROOT),
           "--evaluator-root", str(evaluator_root),
           "--output-dir", str(output_dir), "--output-json", str(output_json)]
    if tier is not None:
        argv += ["--tier", tier]
    if authority is not None:
        argv += ["--authority", str(authority)]
    if baseline is not None:
        argv += ["--baseline", str(baseline)]
    if candidate is not None:
        argv += ["--candidate", str(candidate)]
    return subprocess.run(argv, capture_output=True, text=True, env=_env(),
                          cwd=cwd)


def _write_context(directory, name, mutation=None):
    context = json.loads((FIXTURES / "valid-context.json").read_bytes())
    if mutation is not None:
        mutation(context)
    path = directory / name
    path.write_text(json.dumps(context))
    return path


def _stage_bridge(directory, authority_fixture="authority.json"):
    """Stage minted bridge material; returns (authority, baseline, candidate)."""
    staged = directory / "staged"
    (staged / "baseline").mkdir(parents=True)
    (staged / "candidate").mkdir(parents=True)
    shutil.copytree(COMPARISON / "baseline", staged / "baseline",
                    dirs_exist_ok=True)
    shutil.copytree(COMPARISON / "candidate", staged / "candidate",
                    dirs_exist_ok=True)
    authority = staged / "authority.json"
    shutil.copyfile(STAGED_FIXTURES / authority_fixture, authority)
    return authority, staged / "baseline", staged / "candidate"


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


def _staged_witness_via_loader(directory, authority_fixture="authority.json"):
    """Stage minted bridge files and construct the witness via the bridge."""
    from p11lab.rounds import load_staged_comparison

    authority, baseline, candidate = _stage_bridge(directory, authority_fixture)
    witness, baseline, candidate = load_staged_comparison(
        authority, baseline, candidate)
    envelope = json.loads((COMPARISON / "envelope.json").read_bytes())
    return witness, envelope, baseline, candidate


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


def _full_mechanics_chain(directory, *, compare_fixture="compare-clean.json",
                          coverage_fixture="coverage-clean.json"):
    """Assemble minted staged material plus seams for one mechanics run."""
    from p11lab.round_core.execute import (
        BuilderIdentity, parse_compare_output, parse_coverage_output)
    from p11lab.round_core.inputs import digest
    from p11lab.round_core.worker import SandboxPolicy

    context_path = _mint_execute_dist(directory)
    tools = _make_tools(directory / "tools")
    authority, envelope, baseline, candidate = _staged_witness_via_loader(
        directory)
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
    binding = _fake_binding(envelope, authority, tools, baseline, candidate)
    calls = []

    def bind_evaluator(root):
        calls.append(("evaluator", root))
        return tools

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
        raw = (EXECUTE_FIXTURES / compare_fixture).read_bytes()
        (workdir / "verdict-compare.json").write_bytes(raw)
        return parse_compare_output(raw)

    def run_coverage(sealed, first, second, given_binding, workdir):
        calls.append(("coverage", first, second, workdir))
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


@pytest.mark.parametrize("subset", [
    ("authority",), ("baseline",), ("candidate",),
    ("authority", "baseline"), ("authority", "candidate"),
    ("baseline", "candidate"),
])
def test_c2x_bridge_partial_flags_refused_before_dispatch(tmp_path, subset):
    """Q-X1 all-or-none: any strict subset is usage; the executor is untouched."""
    authority, baseline, candidate = _stage_bridge(tmp_path)
    chosen = {"authority": authority, "baseline": baseline,
              "candidate": candidate}
    kwargs = {name: chosen[name] for name in subset}
    output_dir = tmp_path / "output"
    output_json = tmp_path / "row.json"
    completed = _run_execute(FIXTURES / "valid-context.json",
                             tmp_path / "evaluator", output_dir, output_json,
                             tmp_path, **kwargs)
    assert completed.returncode == 2, completed.stderr
    assert BRIDGE_TOGETHER in completed.stderr
    assert not output_json.exists()
    assert not output_dir.exists()


@pytest.mark.parametrize(("fixture", "match"), [
    ("authority-malformed.json", "not valid JSON"),
    ("authority-partial.json", "expectation/observations"),
    ("authority-observations-nondict.json", "observations"),
    ("authority-expectation-invalid.json", "lane not selected"),
])
def test_c2x_bridge_malformed_authority_is_usage(tmp_path, fixture, match):
    """Malformed staged authority is usage; parsing never confers authority."""
    authority, baseline, candidate = _stage_bridge(tmp_path, fixture)
    output_dir = tmp_path / "output"
    output_json = tmp_path / "row.json"
    completed = _run_execute(FIXTURES / "valid-context.json",
                             tmp_path / "evaluator", output_dir, output_json,
                             tmp_path, authority=authority, baseline=baseline,
                             candidate=candidate)
    assert completed.returncode == 2, completed.stderr
    assert match in completed.stderr
    assert not output_json.exists()
    assert not output_dir.exists()


def test_c2x_bridge_unsupported_provenance_stays_refused(tmp_path):
    """Q-X1: unsupported witness provenance is refused, never executed."""
    authority, baseline, candidate = _stage_bridge(
        tmp_path, "authority-unsupported-provenance.json")
    output_dir = tmp_path / "output"
    output_json = tmp_path / "row.json"
    completed = _run_execute(FIXTURES / "valid-context.json",
                             tmp_path / "evaluator", output_dir, output_json,
                             tmp_path, authority=authority, baseline=baseline,
                             candidate=candidate)
    assert completed.returncode == 2, completed.stderr
    assert "unsupported staged witness provenance" in completed.stderr
    assert not output_json.exists()
    assert not output_dir.exists()


@pytest.mark.parametrize("role", ["baseline", "candidate"])
def test_c2x_bridge_candidate_controlled_staging_refused(tmp_path, role):
    """Authority staged under a candidate-controlled endpoint root is refused."""
    authority, baseline, candidate = _stage_bridge(tmp_path)
    smuggled = {"baseline": baseline, "candidate": candidate}[role]
    smuggled_authority = smuggled / "authority.json"
    shutil.copyfile(authority, smuggled_authority)
    output_dir = tmp_path / "output"
    output_json = tmp_path / "row.json"
    completed = _run_execute(FIXTURES / "valid-context.json",
                             tmp_path / "evaluator", output_dir, output_json,
                             tmp_path, authority=smuggled_authority,
                             baseline=baseline, candidate=candidate)
    assert completed.returncode == 2, completed.stderr
    assert "candidate-controlled" in completed.stderr
    assert not output_json.exists()
    assert not output_dir.exists()


@pytest.mark.parametrize("mutation", [
    "baseline-is-file", "candidate-missing", "baseline-symlink",
])
def test_c2x_bridge_staged_root_shape_refused_before_dispatch(tmp_path, mutation):
    """Staged roots must be canonical directories; violations are usage."""
    authority, baseline, candidate = _stage_bridge(tmp_path)
    if mutation == "baseline-is-file":
        shutil.rmtree(baseline)
        baseline.write_text("not a directory")
    elif mutation == "candidate-missing":
        shutil.rmtree(candidate)
    else:
        real = tmp_path / "real-baseline"
        shutil.move(str(baseline), real)
        baseline.symlink_to(real, target_is_directory=True)
    output_dir = tmp_path / "output"
    output_json = tmp_path / "row.json"
    completed = _run_execute(FIXTURES / "valid-context.json",
                             tmp_path / "evaluator", output_dir, output_json,
                             tmp_path, authority=authority, baseline=baseline,
                             candidate=candidate)
    assert completed.returncode == 2, completed.stderr
    assert "staged bridge" in completed.stderr
    assert "endpoint" in completed.stderr
    assert not output_json.exists()
    assert not output_dir.exists()


def test_c2x_bridge_loader_builds_typed_witness(tmp_path):
    """Typed construction via existing contracts; witness is a boundary type."""
    from p11lab.comparison import LocalComparisonWitness
    from p11lab.round_core.inputs import (
        canonical, freeze_comparison_expectation)
    from p11lab.rounds import load_staged_comparison

    assert load_staged_comparison(None, None, None) is None
    authority, baseline, candidate = _stage_bridge(tmp_path)
    witness, staged_baseline, staged_candidate = load_staged_comparison(
        authority, baseline, candidate)
    assert type(witness) is LocalComparisonWitness
    envelope = json.loads((COMPARISON / "envelope.json").read_bytes())
    assert witness.expectation == freeze_comparison_expectation(envelope)
    staged = json.loads(authority.read_bytes())
    assert witness.observations == canonical(staged["observations"])
    assert staged_baseline == baseline.resolve()
    assert staged_candidate == candidate.resolve()
    with pytest.raises(ValueError, match="together"):
        load_staged_comparison(authority, None, None)
    with pytest.raises(TypeError, match="typed staged bridge paths"):
        load_staged_comparison(str(authority), baseline, candidate)


def test_c2x_bridge_github_gate_flip_proves_dispatch(tmp_path):
    """Staged github passes the transport gate (exit 2 at prepare) while
    unstaged github refuses pre-prepare (exit 3 with a row): the flip
    proves staged entries reached the executor. Hermetic: prepare raises
    on context shape before any network."""
    context = _write_context(tmp_path, "github-context.json", lambda c: c.update(
        transport="github", control_sha="e" * 40))
    evaluator = tmp_path / "evaluator"
    evaluator.mkdir()
    output_dir = tmp_path / "output-unstaged"
    output_json = tmp_path / "row-unstaged.json"
    unstaged = _run_execute(context, evaluator, output_dir, output_json,
                            tmp_path)
    assert unstaged.returncode == 3, unstaged.stderr
    row = json.loads(output_json.read_text())
    assert set(row) == EXPECTED_ROW_FIELDS
    assert (row["phase"], row["cause"]) == ("prepare", "EXECUTE_TRANSPORT_REFUSED")
    assert row["expectation_sha256"] is None
    authority, baseline, candidate = _stage_bridge(tmp_path)
    staged_dir = tmp_path / "output-staged"
    staged_json = tmp_path / "row-staged.json"
    staged = _run_execute(context, evaluator, staged_dir, staged_json,
                          tmp_path, authority=authority, baseline=baseline,
                          candidate=candidate)
    assert staged.returncode == 2, staged.stderr
    assert "invalid preparation context" in staged.stderr
    assert not staged_json.exists()
    assert staged_dir.is_dir()
    assert list(staged_dir.iterdir()) == []


def test_c2x_bridge_fixture_empty_evaluator_refused_mechanics(tmp_path):
    """Minted staged entries dispatch past prepare and refuse at the honest
    bootstrap gate; the row carries the staged expectation digest, proving
    the witness reached the executor. Non-H-C: minted IDs, diagnostic row."""
    from p11lab.round_core.inputs import digest

    context = _mint_execute_dist(tmp_path)
    authority, baseline, candidate = _stage_bridge(tmp_path)
    evaluator = tmp_path / "evaluator"
    evaluator.mkdir()
    output_dir = tmp_path / "output"
    output_json = tmp_path / "row.json"
    completed = _run_execute(context, evaluator, output_dir, output_json,
                             tmp_path, authority=authority, baseline=baseline,
                             candidate=candidate)
    assert completed.returncode == 3, completed.stderr
    row = json.loads(output_json.read_text())
    assert set(row) == EXPECTED_ROW_FIELDS
    assert (row["phase"], row["status"], row["cause"], row["exit_code"]) == (
        "bootstrap", "refused", "EXECUTE_EVALUATOR_REFUSED", 3)
    assert row["cause_detail"]
    assert row["transport"] == "fixture"
    envelope = json.loads((COMPARISON / "envelope.json").read_bytes())
    assert row["expectation_sha256"] == digest(envelope)
    assert json.loads(completed.stdout) == row
    receipt = json.loads((output_dir / "round-receipt.json").read_text())
    assert set(receipt) == EXPECTED_RECEIPT_FIELDS
    assert [(entry["phase"], entry["cause"]) for entry in receipt["phases"]] == [
        ("prepare", "EXECUTE_OK"), ("bootstrap", "EXECUTE_EVALUATOR_REFUSED")]
    capsule = json.loads((output_dir / "round-capsule.json").read_text())
    assert set(capsule) == EXPECTED_CAPSULE_FIELDS
    assert capsule["round_positive"] is False
    assert capsule["diagnostic_only"] is True
    assert capsule["verdict_row"] == row


def test_c2x_bridge_rounds_handoff_passes_typed_entries(tmp_path, monkeypatch):
    """rounds.execute hands typed staged entries to the staged-entry path."""
    import p11lab.round_core.execute as backend
    from p11lab.comparison import LocalComparisonWitness
    from p11lab.rounds import execute

    seen = {}

    def capture(context_path, policy_root, evaluator_root, output_dir,
                output_json, tier=None, **kwargs):
        seen.update(kwargs)
        return {"exit_code": 0}

    monkeypatch.setattr(backend, "execute_round", capture)
    context = _write_context(tmp_path, "context.json")
    output_dir = tmp_path / "output"
    output_json = tmp_path / "row.json"
    evaluator = tmp_path / "evaluator"
    evaluator.mkdir()
    execute(context, POLICY_ROOT, evaluator, output_dir, output_json)
    assert seen == {}
    authority, baseline, candidate = _stage_bridge(tmp_path)
    execute(context, POLICY_ROOT, evaluator, output_dir, output_json,
            authority=authority, baseline=baseline, candidate=candidate)
    assert type(seen["authority"]) is LocalComparisonWitness
    assert seen["baseline"] == baseline.resolve()
    assert seen["candidate"] == candidate.resolve()
    assert set(seen) == {"authority", "baseline", "candidate"}


def test_c2x_mechanics_minted_endpoints_exit_zero(tmp_path):
    """Bridge proof, labeled non-H-C: minted staged files reach exit 0 via
    the typed staged-entry path with injected verdict seams. Minted run
    IDs (456/2); H-C-NOT-DEMONSTRATED (no producer authority established)."""
    from p11lab.round_core.inputs import canonical, digest

    context_path, tools, envelope, binding, calls, material = (
        _full_mechanics_chain(tmp_path))
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
    assert [call[0] for call in calls] == ["evaluator", "bind", "compare",
                                           "coverage"]
    capsule = json.loads((output_dir / "round-capsule.json").read_text())
    assert set(capsule) == EXPECTED_CAPSULE_FIELDS
    assert capsule["schema"] == "p11lab-round-execution-v1"
    assert capsule["diagnostic_only"] is True
    assert capsule["round_positive"] is False
    assert capsule["expectation_sha256"] == digest(envelope)
    assert capsule["observations_sha256"] == hashlib.sha256(
        material["authority"].observations).hexdigest()
    assert capsule["verdict_row"] == row
    assert capsule["image_promotable"] is False
    recomputed = dict(capsule, capsule_sha256=None)
    assert capsule["capsule_sha256"] == hashlib.sha256(
        canonical(recomputed)).hexdigest()
    receipt = json.loads((output_dir / "round-receipt.json").read_text())
    assert set(receipt) == EXPECTED_RECEIPT_FIELDS
    assert receipt["acceptance"] == {
        "blocked": True,
        "reason": ("$.axes.image_usable: requires True (conditional rule: "
                   '{"properties":{"stage":{"enum":["accepted","promoted",'
                   '"published"]}}})')}
    assert [entry["phase"] for entry in receipt["phases"]] == [
        "prepare", "bootstrap", "produce", "bind", "compare", "coverage",
        "done"]
    assert capsule["limitations"] == [
        "Fixture transport is local-only and non-authoritative; no caller, "
        "producer, or publication authority is established.",
        "Acceptance blocked: " + receipt["acceptance"]["reason"]]


def test_c2x_mechanics_builder_absent_producer_failed(tmp_path):
    """Minted staged run whose builder is absent fails loudly at produce."""
    from p11lab.docker import CommandResult

    context_path, tools, envelope, binding, calls, material = (
        _full_mechanics_chain(tmp_path))

    class BuilderAbsentEngine(SucceedingDocker):
        def execute(self, identity, timeout, interrupted):
            self.resources[identity]["State"] = {"Running": True, "Pid": 1}
            return CommandResult(1, "", "builder image absent", False)

    material["engine"] = BuilderAbsentEngine(material["engine"].layers,
                                             material["engine"].env)
    row, output_dir = _run_api(tmp_path, material, context_path)
    assert set(row) == EXPECTED_ROW_FIELDS
    assert (row["phase"], row["status"], row["cause"], row["exit_code"]) == (
        "produce", "infrastructure-error", "EXECUTE_PRODUCER_FAILED", 3)
    assert row["producer_status"] == "infrastructure-error"
    assert row["expectation_sha256"] is not None
    assert (output_dir / "produce" / "producer-observation.json").is_file()
    assert [call[0] for call in calls] == ["evaluator"]
    capsule = json.loads((output_dir / "round-capsule.json").read_text())
    assert capsule["round_positive"] is False


def test_c2x_mechanics_launcher_missing_compare_failed(tmp_path):
    """The real sealed compare runner refuses loudly without a launcher."""
    context_path, tools, envelope, binding, calls, material = (
        _full_mechanics_chain(tmp_path))
    del material["run_compare"]
    row, output_dir = _run_api(tmp_path, material, context_path)
    assert set(row) == EXPECTED_ROW_FIELDS
    assert (row["phase"], row["status"], row["cause"], row["exit_code"]) == (
        "compare", "infrastructure-error", "EXECUTE_COMPARE_FAILED", 3)
    assert row["cause_detail"] == (
        "ValueError: sealed pkcs11-check launcher is missing")
    assert [call[0] for call in calls] == ["evaluator", "bind"]
    capsule = json.loads((output_dir / "round-capsule.json").read_text())
    assert capsule["round_positive"] is False


def test_c2x_mechanics_misbound_endpoints_bind_refused(tmp_path):
    """Staged authority plus a misbound endpoint refuses at the real binder
    with the exact roster text (binder executes; nothing is simulated)."""
    from p11lab.comparison import validate_comparison_envelope

    context_path, tools, envelope, binding, calls, material = (
        _full_mechanics_chain(tmp_path))
    victim = material["candidate"] / "ledger.jsonl"
    assert victim.is_file()
    victim.unlink()
    material["bind_envelope"] = validate_comparison_envelope
    row, output_dir = _run_api(tmp_path, material, context_path)
    assert set(row) == EXPECTED_ROW_FIELDS
    assert (row["phase"], row["status"], row["cause"], row["exit_code"]) == (
        "bind", "refused", "EXECUTE_BIND_REFUSED", 3)
    assert row["cause_detail"] == (
        "protected endpoint file roster/length/hash mismatch")
    capsule = json.loads((output_dir / "round-capsule.json").read_text())
    assert capsule["round_positive"] is False


def test_c2x_mechanics_changed_staging_refused(tmp_path):
    """Endpoint bytes changed after staging refuse: the bind re-checks the
    staged roster instead of trusting it."""
    from p11lab.comparison import validate_comparison_envelope

    context_path, tools, envelope, binding, calls, material = (
        _full_mechanics_chain(tmp_path))
    ledger = material["baseline"] / "ledger.jsonl"
    before = hashlib.sha256(ledger.read_bytes()).hexdigest()
    raw = bytearray(ledger.read_bytes())
    raw[0] ^= 1
    ledger.write_bytes(bytes(raw))
    after = hashlib.sha256(ledger.read_bytes()).hexdigest()
    assert before != after
    material["bind_envelope"] = validate_comparison_envelope
    row, output_dir = _run_api(tmp_path, material, context_path)
    assert (row["phase"], row["cause"]) == ("bind", "EXECUTE_BIND_REFUSED")
    assert row["cause_detail"] == (
        "protected endpoint file roster/length/hash mismatch")
    assert row["exit_code"] == 3


def test_c2x_mechanics_binder_runs_before_evaluator_check(tmp_path):
    """Control: unmutated staged endpoints pass the real binder's file
    checks and refuse at its sealed-evaluator re-verification (receipt
    read on the minted tools root), proving the binder executed through
    _bind instead of being simulated. Hermetic: no sealed code runs."""
    from p11lab.comparison import validate_comparison_envelope

    context_path, tools, envelope, binding, calls, material = (
        _full_mechanics_chain(tmp_path))
    material["bind_envelope"] = validate_comparison_envelope
    row, output_dir = _run_api(tmp_path, material, context_path)
    assert set(row) == EXPECTED_ROW_FIELDS
    assert (row["phase"], row["status"], row["cause"], row["exit_code"]) == (
        "bind", "refused", "EXECUTE_BIND_REFUSED", 3)
    assert row["cause_detail"] == "invalid source archive file"
    capsule = json.loads((output_dir / "round-capsule.json").read_text())
    assert capsule["round_positive"] is False


def test_c2x_mechanics_round_positive_never_true(tmp_path):
    """No mechanics row or capsule claims a positive, including exit 0."""
    context_path, tools, envelope, binding, calls, material = (
        _full_mechanics_chain(tmp_path))
    row, output_dir = _run_api(tmp_path, material, context_path)
    assert row["exit_code"] == 0
    capsule = json.loads((output_dir / "round-capsule.json").read_text())
    assert capsule["round_positive"] is False
    assert capsule["image_promotable"] is False
    assert capsule["limitations"] != []


def test_c2x_bridge_uses_no_private_internals():
    """The bridge (rounds.py) uses public contracts only: no
    worker/bootstrap/comparison/results/inputs privates, no underscore
    imports. (cli.py gains flags plus kwarg passthrough with no new
    imports; verified by diff.)"""
    import re

    import p11lab

    root = Path(p11lab.__file__).parent
    pattern = re.compile(
        r"(worker|bootstrap|comparison|results|inputs)\._|"
        r"from p11lab\.(round_core\.)?(worker|bootstrap|comparison|results|inputs)"
        r" import [^\n]*\b_[A-Za-z]")
    text = (root / "rounds.py").read_text()
    assert pattern.search(text) is None
    for private in ("_snapshot", "_PUBLIC_EVIDENCE", "_run_sealed_cli",
                    "_assert_inputs_stable", "_freeze_producer_inputs"):
        assert private not in text, private


@pytest.mark.skipif(os.environ.get("P11LAB_C2X_G7_EVALUATOR_ROOT") is None,
                    reason="G7 probe needs a retained sealed evaluator root")
def test_c2x_g7_launcher_probe_presence_and_command_shape(tmp_path):
    """G7 env-gated probe (mechanics, non-H-C): settles the prep/codex
    disagreement empirically. Observed: the launcher is present as a
    regular file; both verdict commands exist with the documented argv
    shape and `--output json`; compare-coverage accepts endpoint
    directories (rc 0, parses); evidence-compare requires ledger files
    (directories yield an rc-2 JSON error envelope), and its file-argv
    output parses. B-C2y fixes the P11Lab caller (`_run_sealed_compare`
    now passes the bound `ledger.jsonl` files); this probe still pins
    the raw tool contracts underneath. The gate stays hermetic
    (skipped without P11LAB_C2X_G7_EVALUATOR_ROOT)."""
    import time

    from p11lab.round_core.execute import (
        parse_compare_output, parse_coverage_output)

    root = Path(os.environ["P11LAB_C2X_G7_EVALUATOR_ROOT"]).resolve()
    launcher = root / "evaluator-install/bin/pkcs11-check"
    assert launcher.is_file(), "sealed launcher missing (owning-repo fix)"
    assert not launcher.is_symlink(), "launcher must be a regular file"
    authority, baseline, candidate = _stage_bridge(tmp_path)
    assert authority.is_file()

    def sealed_env(workdir):
        return {"PATH": "/usr/bin:/bin", "HOME": str(workdir),
                "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
                "LD_LIBRARY_PATH": str(root / "python/lib"),
                "PYTHONDONTWRITEBYTECODE": "1"}

    def run(argv, workdir):
        started = time.monotonic()
        completed = subprocess.run(
            argv, cwd=workdir, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300,
            check=False, env=sealed_env(workdir))
        return completed, time.monotonic() - started

    for command in ("evidence-compare", "compare-coverage"):
        workdir = tmp_path / f"g7-help-{command}"
        workdir.mkdir()
        completed, _ = run([str(launcher), command, "--help"], workdir)
        assert completed.returncode == 0, command
        text = completed.stdout.decode("utf-8", "replace")
        assert "BASELINE" in text and "CANDIDATE" in text, command
        assert "--output" in text, command
    workdir = tmp_path / "g7-coverage-dirs"
    workdir.mkdir()
    completed, elapsed = run([str(launcher), "compare-coverage", str(baseline),
                              str(candidate), "--output", "json"], workdir)
    assert completed.returncode in (0, 1), completed.returncode
    assert len(completed.stdout) <= 4 * 1024 * 1024
    coverage = parse_coverage_output(completed.stdout)
    print(f"G7 compare-coverage dirs: rc={completed.returncode} "
          f"positive={coverage.positive} elapsed={elapsed:.1f}s")
    workdir = tmp_path / "g7-compare-files"
    workdir.mkdir()
    completed, elapsed = run(
        [str(launcher), "evidence-compare", str(baseline / "ledger.jsonl"),
         str(candidate / "ledger.jsonl"), "--output", "json"], workdir)
    assert completed.returncode in (0, 1), completed.returncode
    assert len(completed.stdout) <= 4 * 1024 * 1024
    outcome = parse_compare_output(completed.stdout)
    print(f"G7 evidence-compare files: rc={completed.returncode} "
          f"positive={outcome.positive} elapsed={elapsed:.1f}s")
    workdir = tmp_path / "g7-compare-dirs"
    workdir.mkdir()
    completed, _ = run([str(launcher), "evidence-compare", str(baseline),
                        str(candidate), "--output", "json"], workdir)
    assert completed.returncode == 2, completed.returncode
    envelope = json.loads(completed.stdout.decode("utf-8"))
    assert envelope["status"] == "error"
    assert envelope["errors"] != []
    print(f"G7 evidence-compare dirs: rc=2 envelope={envelope['errors'][0][:80]}")


@pytest.mark.skipif(os.environ.get("P11LAB_C2X_BUILD_EVALUATOR") != "1",
                    reason="live sealed-evaluator build is expensive by design")
def test_c2x_live_evaluator_build_designed_not_run(tmp_path):
    """Env-gated live proof: build the exact reviewed evaluator in-job via
    anonymous fetches and assert the receipt plus launcher. Requires
    P11LAB_C2X_BUILD_EVALUATOR=1 plus network to the pinned origins;
    designed, not run, in this slice (no live dispatches)."""
    import p11lab
    from p11lab.round_core.bootstrap import acquire_evaluator
    from p11lab.round_core.inputs import SealedToolInputs, load_json

    package = Path(p11lab.__file__).parent
    lock_root = package / "data/rounds/evaluator"
    pin = load_json((lock_root / "source.json").read_bytes())
    output = tmp_path / "live-evaluator"
    receipt = acquire_evaluator(pin, lock_root, output)
    assert receipt["source"] == pin
    tools = SealedToolInputs.from_evaluator(output)
    launcher = tools.root / "evaluator-install/bin/pkcs11-check"
    assert launcher.is_file() and not launcher.is_symlink()
