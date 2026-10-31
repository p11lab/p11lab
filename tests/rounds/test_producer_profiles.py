"""First shipped producer profile: selection, verifier, and review locks (B-F1)."""

import hashlib
import io
import json
import shutil
import zipfile
from pathlib import Path

import pytest

from p11lab.round_core import inputs

FIXTURES = Path(__file__).parent / "fixtures"
CHECKOUT = Path(__file__).resolve().parents[2]

# Reviewed entry #1 values (B-F1 brief Q-F1-1..Q-F1-10). The policy digest was
# recomputed on this tree via load_policy(None, tier).policy_digest (identical
# for pr-smoke/nightly/release); target/data digests are mechanical digests of
# the brief-fixed canonical bytes below.
POLICY_SHA256 = "a3f00031dfb25dbf26399c1ab696663dcc1515b45274d97370eeaf372b77d745"
TARGET_SHA256 = "d3cee6e0c53c0a7bb7aae7c908e823ede53075008f277b2d6d172e41173dd908"
DATA_SOURCES_SHA256 = "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
# Hermetic sealed-evaluator identity: pin 09aabfec + verified_evaluator_identity,
# captured under a network-less namespace from two independent verified builds
# (identical identity_sha256 from both; see the B-F1 author report).
TOOL_IDENTITY_SHA256 = "84c9c4bbdccbf62259709bcbab77edad79f26c9c427419b7360c6191bdb2547a"
# Enrolled runtime.source_date_epoch (B-C1c): committer timestamp of the
# producer control commit p11lab/p11lab@10017b19 (2026-10-27T13:03:33Z per
# public commit metadata; review re-verifies live).
SOURCE_DATE_EPOCH = 1793106213

# Minimal canonical target: the valid-context target verbatim. No marker is
# test-only: closure_probe.MARKERS requires exactly this 11-marker set, and
# python_full_version must equal runtime.python_version (inputs.py:949).
CANONICAL_TARGET = {
    "abis": ["cp312"],
    "marker_environment": {
        "implementation_name": "cpython",
        "implementation_version": "3.12.14",
        "os_name": "posix",
        "platform_machine": "x86_64",
        "platform_python_implementation": "CPython",
        "platform_release": "",
        "platform_system": "Linux",
        "platform_version": "",
        "python_full_version": "3.12.14",
        "python_version": "3.12",
        "sys_platform": "linux",
    },
    "platforms": ["linux_x86_64"],
    "python_version": "3.12",
}

EXPECTED_ENTRY = {
    "repository": "mingulov/p11lab-round-caller",
    "repository_id": 1439580215,
    "owner_id": 1794540,
    "workflow_id": 401625989,
    "producer_job": "produce-framework-dist",
    "control_sha": "10017b195e46ffd152a398970ed5412ae8c37f0a",
    "policy_sha256": POLICY_SHA256,
    "target_sha256": TARGET_SHA256,
    "data_sources_sha256": DATA_SOURCES_SHA256,
    "data_sources": [],
    "runtime": {
        "image": "sha256:1e1a22175fbf1b32157ddaf0219e1db4e5401fab2b94ed285add64d18587cd2d",
        "layers": ["sha256:a5d6d345f6afa08d7c31272055746d60a838b290bfcc82c0a23e8e984d61a933"],
        "config_sha256": "d3a78b131efeb329b5ddea474d4a1946877e47c0700f2cd56d99ac9b389c78da",
        "tool_identity_sha256": TOOL_IDENTITY_SHA256,
        "python_version": "3.12.14",
        "max_output_bytes": 100663296,
        "source_date_epoch": SOURCE_DATE_EPOCH,
    },
    "context_artifact_name": "p11lab-round-context-{run_id}-{attempt}",
    "context_job": "upload-round-context",
    "root_sha256": "0" * 64,
    "attestation_artifact_name": "p11lab-round-attestation-{run_id}-{attempt}",
    "workflow_path": ".github/workflows/diagnostic.yml",
    "boundary_path": "README.md",
    "graph": [
        {
            "path": ".github/workflows/diagnostic.yml",
            "sha256": "7ae284aecdaa24d29873de2fc2447c4b4bd3c49194042d072b348438533456f2",
        },
        {
            "path": "README.md",
            "sha256": "3e3cfdf8ea4ea98b3f19a50c0b663c4035f1cad9481df2c8c0a5e81c3067f48c",
        },
    ],
}

# Pushed caller-repo README bytes (inline: no in-checkout copy exists). The R4
# shipped-entry test serves these through the fake transport and checks their
# shas against the profile graph.
README_BYTES = (
    b"# p11lab-round-caller (test caller repo, M09 pilots)\n"
    b"\n"
    b"Setup-only scaffold for M09 pilot (c) preparation. NOT an official caller;\n"
    b"SHAs from this repo never become upstream authority.\n"
    b"\n"
    b"- `.github/workflows/diagnostic.yml`: byte-exact copy of the P11Lab caller\n"
    b"  template (`examples/round-consumer/diagnostic.yml` at control `10017b1`).\n"
    b"  Placeholders are intact: no runs are possible until a compatible\n"
    b"  workflow is published (ASK-9, deferred). Producer jobs, if any, arrive\n"
    b"  with reviewed pilot scope.\n"
    b"\n"
    b"Trigger: `workflow_dispatch` only. No runs have been dispatched from setup.\n"
)


def _github_context(**overrides):
    context = json.loads((FIXTURES / "valid-context.json").read_bytes())
    context.pop("artifact_path")
    context.pop("fixture_metadata_path")
    context.update(transport="github", control_sha="e" * 40, data_root=str(FIXTURES / "input-data"),
                   owner_id=1794540)
    context.update(overrides)
    return context


def _live_policy(tmp_path, data_files):
    """Copy fixture policy roots and pin them to the roster + fixture lock."""
    for name in ("policy", "profiles", "ci"):
        shutil.copytree(FIXTURES / name, tmp_path / name)
    with zipfile.ZipFile(FIXTURES / "fixture-dist.zip") as archive:
        lock = json.loads(archive.read("dependency-lock.json"))
    sources_path = tmp_path / "policy/sources.json"
    sources = json.loads(sources_path.read_bytes())
    sources["pins"]["corpus"]["sha256"] = inputs.digest(data_files)
    sources["pins"]["checker-build-lock"]["sha256"] = inputs.digest(
        {"roots": lock["build_roots"], "wheels": lock["build_wheels"]})
    sources["pins"]["checker-runtime-lock"]["sha256"] = inputs.digest(
        {"extras": lock["runtime_extras"], "wheels": lock["runtime_wheels"]})
    sources_path.write_text(json.dumps(sources))
    profile_path = tmp_path / "profiles/round-pr-smoke-v1.json"
    tier_profile = json.loads(profile_path.read_bytes())
    tier_profile["disabled_inventory"]["sha256"] = next(
        row["sha256"] for row in data_files if row["path"] == "disabled.json")
    profile_path.write_text(json.dumps(tier_profile))
    from p11lab.round_core.policy import load_policy

    return tmp_path / "policy", load_policy(tmp_path / "policy", "pr-smoke").policy_digest


def _graph(source=b"protected-graph"):
    digest = hashlib.sha256(source).hexdigest()
    return [
        {"path": ".github/workflows/build.yml", "sha256": digest},
        {"path": "proof.json", "sha256": digest},
    ]


def _profile(context, policy_digest, graph, **overrides):
    profile = {
        "repository": context["repository"],
        "repository_id": context["identity"]["repository_id"],
        "owner_id": context["owner_id"],
        "workflow_id": context["workflow_id"],
        "producer_job": context["producer_job"],
        "control_sha": context["control_sha"],
        "policy_sha256": policy_digest,
        "target_sha256": inputs.digest(context["target"]),
        "data_sources_sha256": inputs.digest([]),
        "data_sources": [],
        "context_artifact_name": "control-{run_id}-{attempt}",
        "context_job": "context",
        "runtime": {
            "image": "sha256:" + "3" * 64,
            "layers": ["sha256:" + "4" * 64],
            "config_sha256": "5" * 64,
            "tool_identity_sha256": inputs.digest({"fixture": True}),
            "python_version": "3.12.14",
            "max_output_bytes": 16777216,
            "source_date_epoch": 1,
        },
        "workflow_path": graph[0]["path"],
        "boundary_path": graph[1]["path"],
        "graph": graph,
    }
    profile.update(overrides)
    return profile


class _Resource:
    def __init__(self, payload):
        self._payload = payload

    def joinpath(self, path):
        return self

    def read_bytes(self):
        return self._payload


def _serve(monkeypatch, profiles):
    import importlib.resources

    payload = inputs.canonical({"schema_version": 1, "profiles": profiles})
    monkeypatch.setattr(importlib.resources, "files", lambda name: _Resource(payload))


def _fake_transport(monkeypatch, context, policy_digest, calls, graph_fetcher, dist_bytes=None):
    from p11lab.round_core import artifacts

    if dist_bytes is None:
        dist_bytes = (FIXTURES / "fixture-dist.zip").read_bytes()
    metadata_row = json.loads((FIXTURES / "fixture-metadata.json").read_bytes())["listing"]["artifacts"][0]

    class FixtureGitHub:
        def __init__(self, repository, token):
            pass

        def source_file(self, revision, path):
            return graph_fetcher(path)

        def acquire(self, identity, **kwargs):
            calls.append(kwargs.get("artifact_name"))
            if kwargs.get("before_download"):
                kwargs["before_download"]({"id": 1})
            if kwargs.get("artifact_name") is None:
                return metadata_row, dist_bytes
            changed = {
                key: context[key]
                for key in ("identity", "repository", "run_head_sha", "workflow_id", "producer_job",
                            "control_sha", "target", "dependency_lock_sha256", "data_files", "disabled_path")
            }
            changed["policy_sha256"] = policy_digest
            out = io.BytesIO()
            with zipfile.ZipFile(out, "w") as archive:
                archive.writestr("context.json", inputs.canonical(changed))
            return metadata_row, out.getvalue()

    monkeypatch.setattr(artifacts, "GitHubTransport", FixtureGitHub)
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")


def _mock_evaluator_legs(monkeypatch, tmp_path):
    from p11lab.round_core import bootstrap, prebuilt

    def acquire(source_pin, lock_root, output):
        output.mkdir()
        (output / "evaluator-build-receipt.json").write_bytes(b"receipt")
        return {"python": {"platform": "fixture", "libc": ["fixture", "1"]}, "native_dependencies": []}

    monkeypatch.setattr(bootstrap, "acquire_evaluator", acquire)
    monkeypatch.setattr(inputs, "verify_dependency_origins", lambda root, lock, output: {"status": "mock-origin"})
    monkeypatch.setattr(inputs, "validate_offline_closures", lambda *args: {"status": "mock-closure"})
    fake_tools = inputs.SealedToolInputs(tmp_path, "6" * 64, (), (), b"", ())
    monkeypatch.setattr(inputs.SealedToolInputs, "from_evaluator", lambda root: fake_tools)
    tool_identity = inputs.digest({"fixture": True})
    monkeypatch.setattr(inputs, "verified_evaluator_identity",
                        lambda root: {"identity_sha256": tool_identity, "receipt_sha256": "6" * 64,
                                      "identity": {"fixture": True}})
    monkeypatch.setattr(prebuilt, "install_prebuilt_candidate",
                        lambda selection, output: {"status": "installed", "installed_manifest_sha256": "7" * 64})
    return tool_identity


def test_empty_profile_set_is_refused(tmp_path, monkeypatch):
    """R1: the empty profile set refuses selection without side effects."""
    context = _github_context()
    policy_root, policy_digest = _live_policy(tmp_path, context["data_files"])
    _serve(monkeypatch, [])
    calls = []
    _fake_transport(monkeypatch, context, policy_digest, calls, lambda path: b"protected-graph")
    with pytest.raises(ValueError, match="protected producer profile unavailable or ambiguous"):
        inputs.prepare(context, policy_root, tmp_path / "output")
    assert calls == []
    assert not (tmp_path / "output").exists()


def test_unlisted_repository_is_refused(tmp_path, monkeypatch):
    """R2: a context naming an unlisted repo refuses at selection."""
    context = _github_context()
    policy_root, policy_digest = _live_policy(tmp_path, context["data_files"])
    _serve(monkeypatch, [_profile(context, policy_digest, _graph())])
    context["repository"] = "other/repo"
    calls = []
    _fake_transport(monkeypatch, context, policy_digest, calls, lambda path: b"protected-graph")
    with pytest.raises(ValueError, match="protected producer profile unavailable or ambiguous"):
        inputs.prepare(context, policy_root, tmp_path / "output")
    assert calls == []
    assert not (tmp_path / "output").exists()


def test_ambiguous_profiles_are_refused(tmp_path, monkeypatch):
    """R2: two profiles sharing one (repository, workflow_id) refuse."""
    context = _github_context()
    policy_root, policy_digest = _live_policy(tmp_path, context["data_files"])
    profile = _profile(context, policy_digest, _graph())
    _serve(monkeypatch, [profile, dict(profile)])
    calls = []
    _fake_transport(monkeypatch, context, policy_digest, calls, lambda path: b"protected-graph")
    with pytest.raises(ValueError, match="protected producer profile unavailable or ambiguous"):
        inputs.prepare(context, policy_root, tmp_path / "output")
    assert calls == []
    assert not (tmp_path / "output").exists()


def test_repository_id_mismatch_fails_verifier(tmp_path, monkeypatch):
    """R2: same repo string but wrong numeric id passes selection, fails verifier."""
    context = _github_context()
    policy_root, policy_digest = _live_policy(tmp_path, context["data_files"])
    _serve(monkeypatch, [_profile(context, policy_digest, _graph(), repository_id=999)])
    calls = []
    _fake_transport(monkeypatch, context, policy_digest, calls, lambda path: b"protected-graph")
    with pytest.raises(ValueError, match="protected producer profile context mismatch"):
        inputs.prepare(context, policy_root, tmp_path / "output")
    assert calls == ["control-456-2"]
    assert not (tmp_path / "output").exists()


def test_policy_digest_mismatch_refuses_before_transport(tmp_path, monkeypatch):
    """R3: a stale policy_sha256 refuses before any transport use."""
    context = _github_context()
    policy_root, policy_digest = _live_policy(tmp_path, context["data_files"])
    _serve(monkeypatch, [_profile(context, policy_digest, _graph(), policy_sha256="0" * 64)])
    calls = []
    _fake_transport(monkeypatch, context, policy_digest, calls, lambda path: b"protected-graph")
    with pytest.raises(ValueError, match="policy bundle does not match protected producer profile"):
        inputs.prepare(context, policy_root, tmp_path / "output")
    assert calls == []
    assert not (tmp_path / "output").exists()


def test_matching_entry_proceeds_to_verified_authority(tmp_path, monkeypatch):
    """R4: a single matching entry proceeds through graph verification + acquires."""
    context = _github_context()
    policy_root, policy_digest = _live_policy(tmp_path, context["data_files"])
    tool_identity = _mock_evaluator_legs(monkeypatch, tmp_path)
    profile = _profile(context, policy_digest, _graph())
    assert profile["runtime"]["tool_identity_sha256"] == tool_identity
    _serve(monkeypatch, [profile])
    calls = []
    _fake_transport(monkeypatch, context, policy_digest, calls, lambda path: b"protected-graph")
    result = inputs.prepare(context, policy_root, tmp_path / "output")
    assert calls == ["control-456-2", None]
    assert result["authority"] == "protected-profile-source-verified"
    assert set(result["candidate_install"]["roles"]) == {"primary_wheel", "sdist_probe_wheel", "replay_base_wheel"}
    assert result["round_positive"] is False


def _rebuild_dist_for_identity(identity):
    with zipfile.ZipFile(FIXTURES / "fixture-dist.zip") as archive:
        members = {name: archive.read(name) for name in archive.namelist()}
    build = json.loads(members["build-receipt.json"])
    build["identity"] = identity
    members["build-receipt.json"] = inputs.canonical(build)
    manifest = json.loads(members["candidate-manifest.json"])
    manifest["identity"] = identity
    manifest["build_receipt_sha256"] = hashlib.sha256(members["build-receipt.json"]).hexdigest()
    members["candidate-manifest.json"] = inputs.canonical(manifest)
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as archive:
        for name, payload in members.items():
            archive.writestr(name, payload)
    return out.getvalue()


def test_shipped_entry_selects_and_verifies(tmp_path, monkeypatch):
    """R4: the shipped entry selects exactly one and passes graph verification.

    The served copy re-pins only the environment-specific policy digest and
    tool identity to the hermetic test doubles; every other shipped byte is
    verified verbatim. The digest-equality contracts themselves are locked by
    R3/R7.
    """
    import importlib.resources

    shipped = json.loads(importlib.resources.files("p11lab")
                         .joinpath("data/rounds/producer-profiles.json").read_bytes())
    context = _github_context(
        repository=EXPECTED_ENTRY["repository"],
        workflow_id=EXPECTED_ENTRY["workflow_id"],
        producer_job=EXPECTED_ENTRY["producer_job"],
        control_sha=EXPECTED_ENTRY["control_sha"],
        target=CANONICAL_TARGET,
    )
    context["identity"] = dict(context["identity"], repository_id=EXPECTED_ENTRY["repository_id"])
    policy_root, policy_digest = _live_policy(tmp_path, context["data_files"])
    tool_identity = _mock_evaluator_legs(monkeypatch, tmp_path)
    served = [dict(entry, policy_sha256=policy_digest,
                   runtime=dict(entry["runtime"], tool_identity_sha256=tool_identity))
              for entry in shipped["profiles"]]
    _serve(monkeypatch, served)
    graph_bytes = {
        ".github/workflows/diagnostic.yml": (CHECKOUT / "examples/round-consumer/diagnostic.yml").read_bytes(),
        "README.md": README_BYTES,
    }
    calls = []
    _fake_transport(monkeypatch, context, policy_digest, calls, graph_bytes.__getitem__,
                    _rebuild_dist_for_identity(context["identity"]))
    result = inputs.prepare(context, policy_root, tmp_path / "output")
    assert calls == ["p11lab-round-context-456-2", None]
    assert result["authority"] == "protected-profile-source-verified"
    assert result["target_sha256"] == EXPECTED_ENTRY["target_sha256"]
    assert result["data_sources_sha256"] == EXPECTED_ENTRY["data_sources_sha256"]
    assert result["round_positive"] is False
    assert served[0]["graph"] == EXPECTED_ENTRY["graph"]
    for row in served[0]["graph"]:
        assert hashlib.sha256(graph_bytes[row["path"]]).hexdigest() == row["sha256"]


@pytest.mark.parametrize("field,value", [("context_job", 123), ("data_sources", {})])
def test_malformed_profile_shape_rejected_at_precheck(tmp_path, monkeypatch, field, value):
    """R5: non-list sources / non-str job refuse at the shape precheck."""
    context = _github_context()
    policy_root, policy_digest = _live_policy(tmp_path, context["data_files"])
    profile = _profile(context, policy_digest, _graph())
    profile[field] = value
    _serve(monkeypatch, [profile])
    calls = []
    _fake_transport(monkeypatch, context, policy_digest, calls, lambda path: b"protected-graph")
    with pytest.raises(ValueError, match="malformed protected producer profile"):
        inputs.prepare(context, policy_root, tmp_path / "output")
    assert calls == []
    assert not (tmp_path / "output").exists()


@pytest.mark.parametrize("template,job", [("control-without-placeholders", "context"),
                                          ("control-{run_id}-{attempt}", "")])
def test_malformed_artifact_template_rejected_in_verifier(tmp_path, monkeypatch, template, job):
    """R5: bad template / empty job fails the in-verifier artifact check."""
    context = _github_context()
    policy_root, policy_digest = _live_policy(tmp_path, context["data_files"])
    _serve(monkeypatch, [_profile(context, policy_digest, _graph(),
                                  context_artifact_name=template, context_job=job)])
    calls = []
    _fake_transport(monkeypatch, context, policy_digest, calls, lambda path: b"protected-graph")
    with pytest.raises(ValueError, match="invalid protected context artifact profile"):
        inputs.prepare(context, policy_root, tmp_path / "output")
    assert not (tmp_path / "output").exists()


def test_graph_byte_mismatch_is_refused(tmp_path, monkeypatch):
    """R6: graph bytes differing from the pinned shas refuse."""
    context = _github_context()
    policy_root, policy_digest = _live_policy(tmp_path, context["data_files"])
    _serve(monkeypatch, [_profile(context, policy_digest, _graph())])
    calls = []
    _fake_transport(monkeypatch, context, policy_digest, calls, lambda path: b"tampered-graph")
    with pytest.raises(ValueError, match="protected source graph mismatch"):
        inputs.prepare(context, policy_root, tmp_path / "output")
    assert not (tmp_path / "output").exists()


@pytest.mark.parametrize("field", ["workflow_path", "boundary_path"])
def test_evidence_path_outside_graph_is_refused(tmp_path, monkeypatch, field):
    """R6: workflow/boundary paths absent from the graph refuse."""
    context = _github_context()
    policy_root, policy_digest = _live_policy(tmp_path, context["data_files"])
    profile = _profile(context, policy_digest, _graph())
    profile[field] = "elsewhere.md"
    _serve(monkeypatch, [profile])
    calls = []
    _fake_transport(monkeypatch, context, policy_digest, calls, lambda path: b"protected-graph")
    with pytest.raises(ValueError, match="protected profile lacks workflow or boundary evidence"):
        inputs.prepare(context, policy_root, tmp_path / "output")
    assert not (tmp_path / "output").exists()


def test_malformed_graph_is_refused(tmp_path, monkeypatch):
    """R6: empty or duplicate graph rosters refuse."""
    context = _github_context()
    policy_root, policy_digest = _live_policy(tmp_path, context["data_files"])
    rows = _graph()
    cases = [([], "invalid protected source graph"),
             ([rows[0], dict(rows[0])], "duplicate protected source graph entry")]
    for graph, message in cases:
        profile = _profile(context, policy_digest, _graph(),
                           workflow_path="proof.json", boundary_path="proof.json")
        profile["graph"] = graph
        _serve(monkeypatch, [profile])
        calls = []
        _fake_transport(monkeypatch, context, policy_digest, calls, lambda path: b"protected-graph")
        with pytest.raises(ValueError, match=message):
            inputs.prepare(context, policy_root, tmp_path / ("output-%d" % len(graph)))
        assert not (tmp_path / ("output-%d" % len(graph))).exists()


def test_shipped_entry_matches_reviewed_bytes():
    """R7: the shipped file deep-equals the reviewed entry bytes (no doubles)."""
    import importlib.resources

    raw = importlib.resources.files("p11lab").joinpath("data/rounds/producer-profiles.json").read_bytes()
    assert json.loads(raw) == {"schema_version": 1, "profiles": [EXPECTED_ENTRY]}


@pytest.mark.parametrize("tier", ["pr-smoke", "nightly", "release"])
def test_shipped_policy_digest_matches_every_tier(tier):
    """R7: the shipped policy_sha256 equals the loaded bundle digest per tier."""
    import importlib.resources

    from p11lab.round_core.policy import load_policy

    shipped = json.loads(importlib.resources.files("p11lab")
                         .joinpath("data/rounds/producer-profiles.json").read_bytes())
    assert len(shipped["profiles"]) == 1
    assert shipped["profiles"][0]["policy_sha256"] == load_policy(None, tier).policy_digest


# B-F2 Task 1: profile owner_id (appended rows; existing rows untouched).
# Live value: mingulov id 1794540 (ASK-2/3 auth log) owns
# mingulov/p11lab-round-caller (setup-record.json "owner"). Single-sourced;
# review must confirm against live repo metadata before any live use.
OWNER_ID = 1794540


def _owned_profile():
    """Self-contained profile+caller with owner_id (no shared-helper edits)."""
    context = {
        "repository": "owner/repo",
        "identity": {"repository_id": 123},
        "owner_id": OWNER_ID,
        "workflow_id": 789,
        "producer_job": "build",
        "control_sha": "e" * 40,
        "target": CANONICAL_TARGET,
    }
    profile = _profile(context, POLICY_SHA256, _graph())
    caller = dict(profile, owner_id=OWNER_ID, run_head_sha="d" * 40)
    return profile, caller


def test_profile_without_owner_id_refused():
    from p11lab.round_core.artifacts import verify_producer_profile

    profile, caller = _owned_profile()
    del profile["owner_id"]
    with pytest.raises(ValueError, match="invalid protected producer profile"):
        verify_producer_profile(profile, caller, lambda path: b"protected-graph")


def test_profile_owner_id_mismatch_refused():
    from p11lab.round_core.artifacts import verify_producer_profile

    profile, caller = _owned_profile()
    caller["owner_id"] = profile["owner_id"] + 1
    with pytest.raises(ValueError, match="context mismatch"):
        verify_producer_profile(profile, caller, lambda path: b"protected-graph")


def test_prepare_caller_owner_id_mismatch_refused(tmp_path, monkeypatch):
    """Caller-supplied owner_id must equal the profile value (prepare level)."""
    context = _github_context()
    context["owner_id"] = OWNER_ID + 1
    policy_root, policy_digest = _live_policy(tmp_path, context["data_files"])
    profile = _profile(context, policy_digest, _graph())
    profile["owner_id"] = OWNER_ID
    _serve(monkeypatch, [profile])
    calls = []
    _fake_transport(monkeypatch, context, policy_digest, calls, lambda path: b"protected-graph")
    with pytest.raises(ValueError, match="protected producer profile context mismatch"):
        inputs.prepare(context, policy_root, tmp_path / "output")
    assert not (tmp_path / "output").exists()


@pytest.mark.parametrize("bad", [0, -3, "mingulov"])
def test_prepare_owner_id_must_be_positive_int(tmp_path, monkeypatch, bad):
    """owner_id is a positive int; logins are display-only, never identity."""
    context = _github_context()
    context["owner_id"] = bad
    policy_root, policy_digest = _live_policy(tmp_path, context["data_files"])
    profile = _profile(context, policy_digest, _graph())
    profile["owner_id"] = OWNER_ID
    _serve(monkeypatch, [profile])
    calls = []
    _fake_transport(monkeypatch, context, policy_digest, calls, lambda path: b"protected-graph")
    with pytest.raises(ValueError, match="invalid preparation context fields"):
        inputs.prepare(context, policy_root, tmp_path / "output")
    assert calls == []
    assert not (tmp_path / "output").exists()
