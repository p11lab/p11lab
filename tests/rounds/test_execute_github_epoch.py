"""github-transport profile-bound source epoch: enrollment pin + completed binder (B-C1c)."""
import hashlib
import http.client
import json
import socket
import ssl
import urllib.request
from pathlib import Path

import pytest

from p11lab.round_core.execute import (
    bind_github_produce_inputs,
    execute_round,
    github_producer_profile,
)
from p11lab.round_core.inputs import digest

FIXTURES = Path(__file__).parent / "fixtures"
POLICY_ROOT = FIXTURES / "policy"
PROFILE_REPOSITORY = "mingulov/p11lab-round-caller"
PROFILE_WORKFLOW_ID = 401625989

# Enrolled runtime.source_date_epoch: the committer timestamp of the producer
# (framework control) commit p11lab/p11lab@10017b19 (committer.date
# 2026-10-27T13:03:33Z per public commit metadata; the same SHA resolves 404
# in mingulov/p11lab-round-caller, so the control revision is the framework
# commit, not a caller-repo commit). Review re-verifies this value live.
ENROLLED_SOURCE_DATE_EPOCH = 1793106213
ENROLLED_CONTROL_SHA = "10017b195e46ffd152a398970ed5412ae8c37f0a"
EPOCH_MAX = 2 ** 31 - 1
EXPECTED_RUNTIME_KEYS = {
    "image", "layers", "config_sha256", "tool_identity_sha256",
    "python_version", "max_output_bytes", "source_date_epoch"}


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    # Stdlib net modules are pre-imported above so subclass statements at
    # import time never run under the patch; only fresh sockets are blocked.
    assert ssl is not None and http is not None and urllib is not None

    def blocked(*args, **kwargs):
        raise AssertionError("network is forbidden in github unit tests")

    monkeypatch.setattr(socket, "socket", blocked)


def _shipped_profile_and_pin():
    profile = github_producer_profile(PROFILE_REPOSITORY, PROFILE_WORKFLOW_ID)
    return profile, digest(profile)


def _binder_prepared(pin, wheel_path="primary_wheel/fixture_app-0.0.1-py3-none-any.whl"):
    return {"protected_profile_sha256": pin,
            "dist": {"roles": {"primary_wheel": {"path": wheel_path,
                                                "sha256": "0" * 64, "size": 8}}}}


_POP = object()


def _mutated_profile(mutation):
    """Copy the shipped profile, apply one runtime mutation, re-pin."""
    profile, _ = _shipped_profile_and_pin()
    profile = json.loads(json.dumps(profile))
    key, value = mutation
    if value is _POP:
        profile["runtime"].pop(key, None)
    else:
        profile["runtime"][key] = value
    return profile, digest(profile)


def _verifier_profile_and_caller():
    """Shipped profile with a synthetic graph; caller matches its context."""
    from p11lab.round_core.execute import github_producer_profile

    profile = json.loads(json.dumps(
        github_producer_profile(PROFILE_REPOSITORY, PROFILE_WORKFLOW_ID)))
    graph_digest = hashlib.sha256(b"epoch-test-graph").hexdigest()
    graph = [{"path": ".github/workflows/build.yml", "sha256": graph_digest},
             {"path": "proof.json", "sha256": graph_digest}]
    profile["graph"] = graph
    profile["workflow_path"] = graph[0]["path"]
    profile["boundary_path"] = graph[1]["path"]
    caller = {name: profile[name] for name in (
        "repository", "repository_id", "owner_id", "workflow_id",
        "producer_job", "control_sha", "policy_sha256", "target_sha256",
        "data_sources_sha256")}
    caller["run_head_sha"] = "d" * 40
    return profile, caller


def _github_context(directory, name):
    context = json.loads((FIXTURES / "valid-context.json").read_bytes())
    context.pop("artifact_path", None)
    context.pop("fixture_metadata_path", None)
    context.update(transport="github")
    path = directory / name
    path.write_text(json.dumps(context))
    return path


def test_enrolled_epoch_pins_producer_commit_timestamp():
    profile, _ = _shipped_profile_and_pin()
    assert profile["control_sha"] == ENROLLED_CONTROL_SHA
    assert set(profile["runtime"]) == EXPECTED_RUNTIME_KEYS
    assert profile["runtime"]["source_date_epoch"] == ENROLLED_SOURCE_DATE_EPOCH


def test_binder_binds_enrolled_epoch_from_profile():
    profile, pin = _shipped_profile_and_pin()
    builder, sandbox = bind_github_produce_inputs(
        profile, _binder_prepared(pin), source_date_epoch=None,
        build_reports=None, startup_reports=None, timeout_seconds=None)
    assert builder.source_date_epoch == ENROLLED_SOURCE_DATE_EPOCH
    assert builder.source_date_epoch == profile["runtime"]["source_date_epoch"]
    assert builder.image == profile["runtime"]["image"]
    assert builder.layers == tuple(profile["runtime"]["layers"])
    assert builder.config_sha256 == profile["runtime"]["config_sha256"]
    assert sandbox.max_output_bytes == profile["runtime"]["max_output_bytes"]
    assert sandbox.wheel_filename == "fixture_app-0.0.1-py3-none-any.whl"
    assert sandbox.build_reports == ()
    assert sandbox.startup_reports == ("startup.json",)
    assert sandbox.timeout_seconds == 60


@pytest.mark.parametrize("staged", [1, 0, -5, "1"])
def test_binder_rejects_explicit_epoch_staging(staged):
    profile, pin = _shipped_profile_and_pin()
    with pytest.raises(TypeError, match="not caller staging"):
        bind_github_produce_inputs(
            profile, _binder_prepared(pin), source_date_epoch=staged,
            build_reports=None, startup_reports=None, timeout_seconds=None)


@pytest.mark.parametrize("staged", [1, 0, -1, "1"])
def test_execute_round_rejects_explicit_epoch_staging(tmp_path, staged):
    def exploding_prepare(context, policy_root, output):
        raise AssertionError("prepare must not run for caller-staged epoch")

    context_path = _github_context(tmp_path, "github-context.json")
    evaluator_root = tmp_path / "evaluator"
    evaluator_root.mkdir()
    output_json = tmp_path / "row.json"
    with pytest.raises(TypeError, match="not caller staging"):
        execute_round(context_path, POLICY_ROOT, evaluator_root,
                      tmp_path / "output", output_json,
                      run_prepare=exploding_prepare,
                      source_date_epoch=staged)
    assert not output_json.exists()


def test_binder_missing_epoch_leaf_is_fatal():
    profile, pin = _mutated_profile(("source_date_epoch", _POP))
    assert "source_date_epoch" not in profile["runtime"]
    with pytest.raises(ValueError, match="missing"):
        bind_github_produce_inputs(
            profile, _binder_prepared(pin), source_date_epoch=None,
            build_reports=None, startup_reports=None, timeout_seconds=None)


def test_binder_null_epoch_leaf_is_fatal():
    profile, pin = _mutated_profile(("source_date_epoch", None))
    with pytest.raises(ValueError, match="missing"):
        bind_github_produce_inputs(
            profile, _binder_prepared(pin), source_date_epoch=None,
            build_reports=None, startup_reports=None, timeout_seconds=None)


@pytest.mark.parametrize("leaf", ["1793106213", 1793106213.0, True])
def test_binder_mistyped_epoch_leaf_is_usage(leaf):
    profile, pin = _mutated_profile(("source_date_epoch", leaf))
    with pytest.raises(TypeError, match="typed"):
        bind_github_produce_inputs(
            profile, _binder_prepared(pin), source_date_epoch=None,
            build_reports=None, startup_reports=None, timeout_seconds=None)


@pytest.mark.parametrize("leaf", [-1, EPOCH_MAX + 1])
def test_binder_epoch_out_of_bounds_refused(leaf):
    profile, pin = _mutated_profile(("source_date_epoch", leaf))
    with pytest.raises(ValueError, match="invalid profile"):
        bind_github_produce_inputs(
            profile, _binder_prepared(pin), source_date_epoch=None,
            build_reports=None, startup_reports=None, timeout_seconds=None)


@pytest.mark.parametrize("leaf", [0, EPOCH_MAX])
def test_binder_epoch_edges_bind(leaf):
    profile, pin = _mutated_profile(("source_date_epoch", leaf))
    builder, _ = bind_github_produce_inputs(
        profile, _binder_prepared(pin), source_date_epoch=None,
        build_reports=None, startup_reports=None, timeout_seconds=None)
    assert builder.source_date_epoch == leaf


def test_artifacts_verifier_accepts_enrolled_epoch():
    from p11lab.round_core.artifacts import verify_producer_profile

    profile, caller = _verifier_profile_and_caller()
    assert profile["runtime"]["source_date_epoch"] == ENROLLED_SOURCE_DATE_EPOCH
    verify_producer_profile(profile, caller, lambda path: b"epoch-test-graph")


def test_artifacts_verifier_missing_epoch_refused():
    from p11lab.round_core.artifacts import verify_producer_profile

    def unreachable(path):
        raise AssertionError("graph must not be reached without an epoch leaf")

    profile, caller = _verifier_profile_and_caller()
    profile["runtime"].pop("source_date_epoch", None)
    with pytest.raises(ValueError, match="invalid protected runtime profile"):
        verify_producer_profile(profile, caller, unreachable)


@pytest.mark.parametrize("leaf", ["1793106213", -1, EPOCH_MAX + 1])
def test_artifacts_verifier_bad_epoch_refused(leaf):
    from p11lab.round_core.artifacts import verify_producer_profile

    def unreachable(path):
        raise AssertionError("graph must not be reached with a bad epoch leaf")

    profile, caller = _verifier_profile_and_caller()
    profile["runtime"]["source_date_epoch"] = leaf
    with pytest.raises(ValueError, match="invalid protected runtime profile"):
        verify_producer_profile(profile, caller, unreachable)
