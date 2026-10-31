"""Static same-run artifact/manifest/capsule/output/verdict-wiring tests.

Prep S1.3-value pins, S1.4, S1.5-capsule/outputs/verdict-wiring. All
fixtures are authored here with invented hashes; nothing reads outside
the checkout. Verdict rows reuse `proxy_policy.evaluate_proxy_verdict`
read-only as the predicate oracle; loader behavior itself stays covered
by test_proxy_policy.py and is not duplicated here.
"""

import copy
import hashlib
import json
import re
from importlib.resources import files
from pathlib import Path

import pytest

from p11lab import proxy_policy
from test_proxy_workflows import _loads

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "proxy-round.yml"
EXAMPLE = ROOT / "examples" / "proxy-consumer" / "workflow.yml"

PROXY_SHA = "c" * 40
OTHER_SHA = "d" * 40
RUN_ID = 424242
ROSTER = (
    "PX-AUTH",
    "PX-STATE",
    "PX-REPLAY",
    "PX-CLIENT-CRASH",
    "PX-DAEMON-DEATH",
    "PX-DAEMON-STOP",
    "PX-LIMIT",
)
MANIFEST_DIGEST = (
    "sha256:69cdeb9a74d13a3382547e184645ee18a7e9e2315246fd40ca814ef97b970d16"
)
CONFIG_DIGEST = (
    "sha256:e59ab297033cedfd8049f76bcf6d9e9c86f8df262be1c80ccbd7c1731437d24f"
)
ARTIFACT_PREFIX = "p11lab-proxy-dist-"

# Design L342-346 manifest field roster for the caller-built artifact.
MANIFEST_FIELDS = frozenset(
    {
        "schema_version",
        "caller_repository_id",
        "caller_repository_full_name",
        "source_commit",
        "source_tree",
        "source_archive_hash",
        "run_id",
        "run_attempt",
        "build_job_id",
        "cargo_lock_hash",
        "rustc_identity",
        "protoc_identity",
        "toolchain_identities",
        "target",
        "features",
        "flags",
        "dependency_closure",
        "vendored_closure",
        "daemon_path",
        "daemon_size",
        "daemon_sha256",
        "cli_path",
        "cli_size",
        "cli_sha256",
        "shim_path",
        "shim_size",
        "shim_sha256",
        "config_hashes",
        "hook_hashes",
        "build_context_digest",
    }
)

# ExperimentResultV1 capsule shape (design L495-501) the aggregate writes.
CAPSULE_FIELDS = (
    "schema",
    "diagnostic_only",
    "experiment_kind",
    "proxy_sha",
    "tier",
    "p11lab_ref",
    "tier_qualified",
    "unqualified_cause",
    "unqualified_detail",
    "caller",
    "run_id",
    "run_attempt",
    "job_id",
    "control_sha",
    "candidate_sha",
    "evaluator_id",
    "policy_digest",
    "input_hashes",
    "provider",
    "local_engine_ids",
    "derivative_identity",
    "client_identity",
    "source_identities",
    "profile",
    "shard_roster",
    "attempt_roster",
    "cells",
    "raw_artifacts",
    "raw_status",
    "raw_findings",
    "raw_skips",
    "image_usable",
    "lifecycle_complete",
    "evidence_complete",
    "evidence_admitted",
    "comparison_positive",
    "within_budget",
    "distribution_eligible",
    "experiment_positive",
    "bounds",
    "queue_seconds",
    "queue_note",
    "reproduction_command",
    "evidence_urls",
    "evidence_expiry",
    "limitations",
    "run_receipt_ref",
    "run_receipt_note",
    "result_artifact",
    "result_sha256",
)


def _workflow_text():
    return WORKFLOW.read_text()


def _aggregate_run():
    doc = _loads(_workflow_text())
    return next(
        x
        for x in doc["jobs"]["aggregate"]["steps"]
        if x.get("id") == "result"
    )["run"]


def _shipped_policy():
    return json.loads(
        files("p11lab").joinpath("data/ci/proxy-policy.json").read_bytes()
    )


def test_provider_identity_matches_shipped_policy_bytes():
    loaded = proxy_policy.load_proxy_policy()
    assert loaded.provider["family"] == "softhsm2"
    assert loaded.provider["channel"] == "release"
    assert loaded.provider["platform"] == "linux/amd64"
    assert loaded.provider["manifest_digest"] == MANIFEST_DIGEST
    assert loaded.provider["config_digest"] == CONFIG_DIGEST


def test_fixed_bound_inputs_match_shipped_policy_bytes():
    loaded = proxy_policy.load_proxy_policy()
    assert loaded.fixed_inputs["profile"] == "round-pr-smoke-v1"
    assert loaded.fixed_inputs["nodes"] == 23
    assert loaded.fixed_inputs["destructive"] is False
    assert loaded.attempts_per_cell == 1
    assert loaded.cells == ("direct", "accepted-proxy", "candidate-proxy")


def test_no_input_selects_tools_or_provider():
    doc = _loads(_workflow_text())
    inputs = doc["on"]["workflow_call"]["inputs"]
    assert set(inputs) == {"proxy_sha", "tier", "p11lab_ref"}
    assert "artifact" not in "".join(inputs).lower()


def test_tier_unqualified_fail_closed_posture():
    loaded = proxy_policy.load_proxy_policy()
    assert loaded.tier_qualified is False
    assert loaded.activation_state == "diagnostic"
    assert len(loaded.gates) == 2
    text = _workflow_text()
    assert text.count("'unqualified_cause': 'tier-unqualified'") == 2


def test_px_limit_rejection_stays_unbound(tmp_path):
    shipped = _shipped_policy()
    controls = {c["id"]: c for c in shipped["controls"]}
    assert controls["PX-LIMIT"]["expected"]["ck_rv"] is None
    assert "CKR_" not in _workflow_text()
    record = copy.deepcopy(shipped)
    for control in record["controls"]:
        if control["id"] == "PX-LIMIT":
            control["expected"]["ck_rv"] = {"second_client": "CKR_OK"}
    path = tmp_path / "proxy-policy.json"
    path.write_text(json.dumps(record))
    with pytest.raises(ValueError, match="refusing guessed rejection value"):
        proxy_policy.load_proxy_policy(path=path)


def test_unqualified_inputs_have_no_bound_values():
    fixed = proxy_policy.load_proxy_policy().fixed_inputs
    assert fixed["checker"] is None
    assert fixed["consumer"] is None
    assert fixed["dataset"] is None


def test_budgets_are_unqualified_targets():
    shipped = _shipped_policy()
    assert shipped["budgets_qualified"] is False
    assert shipped["no_retry_after_start"] is True
    loaded = proxy_policy.load_proxy_policy()
    run = _aggregate_run()
    match = re.search(
        r"'bounds': \{'raw_bytes_max': (\d+), 'diagnostics_bytes_max': (\d+), "
        r"'bounds_qualified': False\}",
        run,
    )
    assert match is not None, "diagnostic bounds stated and unqualified"
    assert int(match.group(1)) == loaded.budgets["raw_bytes"] == 2147483648
    assert int(match.group(2)) == loaded.budgets["diagnostics_bytes"] == 16777216
    doc = _loads(_workflow_text())
    assert doc["jobs"]["aggregate"]["timeout-minutes"] == loaded.budgets[
        "workflow_active_minutes"
    ]
    for job in doc["jobs"].values():
        for step in job.get("steps", []):
            if step.get("uses", "").startswith("actions/upload-artifact@"):
                assert step["with"]["retention-days"] == loaded.budgets[
                    "retention_days"
                ]
    assert "budgets are unqualified targets" in _workflow_text()


def _expected_artifact(proxy_sha, run_attempt):
    assert re.fullmatch(r"[0-9a-f]{40}", proxy_sha) is not None
    assert isinstance(run_attempt, int) and run_attempt >= 1
    return "%s%s-%d" % (ARTIFACT_PREFIX, proxy_sha, run_attempt)


def _parse_artifact(name):
    match = re.fullmatch(
        r"p11lab-proxy-dist-([0-9a-f]{40})-([1-9][0-9]*)", name
    )
    if match is None:
        return None
    return match.group(1), int(match.group(2))


# Authored authority metadata (invented fixtures, independent of the claimed
# SHA/run/attempt): read-only API metadata binds these IDs; a manifest's
# self-assertion is insufficient (design L433-435).
AUTHORITY_REPOSITORY_ID = 4242
AUTHORITY_REPOSITORY_FULL_NAME = "example/proxy-caller"
AUTHORITY_PRODUCER_JOB_ID = "424244"
AUTHORITY_ARTIFACT_ID = 424245


def _select_same_run(records, proxy_sha, run_id, run_attempt):
    matches = [
        r
        for r in records
        if r["sha"] == proxy_sha
        and r["run_id"] == run_id
        and r["run_attempt"] == run_attempt
        and r["repository_id"] == AUTHORITY_REPOSITORY_ID
        and r["repository_full_name"] == AUTHORITY_REPOSITORY_FULL_NAME
        and r["producer_job_id"] == AUTHORITY_PRODUCER_JOB_ID
        and r["artifact_id"] == AUTHORITY_ARTIFACT_ID
        and _parse_artifact(r["name"]) == (proxy_sha, run_attempt)
    ]
    assert len(matches) == 1, (
        "must resolve exactly the current-run current-attempt artifact"
    )
    return matches[0]


def _record(sha, run_id, run_attempt, **overrides):
    record = {
        "sha": sha,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "name": _expected_artifact(sha, run_attempt),
        "repository_id": AUTHORITY_REPOSITORY_ID,
        "repository_full_name": AUTHORITY_REPOSITORY_FULL_NAME,
        "producer_job_id": AUTHORITY_PRODUCER_JOB_ID,
        "artifact_id": AUTHORITY_ARTIFACT_ID,
    }
    record.update(overrides)
    return record


def test_artifact_name_pattern_is_pinned_in_workflow():
    assert "'p11lab-proxy-dist-'" in _workflow_text()


def test_artifact_name_round_trips():
    name = _expected_artifact(PROXY_SHA, 3)
    assert name == "p11lab-proxy-dist-%s-3" % PROXY_SHA
    assert _parse_artifact(name) == (PROXY_SHA, 3)


@pytest.mark.parametrize(
    "name",
    [
        "p11lab-proxy-dist-%s-3" % ("c" * 39),
        "p11lab-proxy-dist-%s-3" % ("C" * 40),
        "p11lab-proxy-dist-%s-0" % PROXY_SHA,
        "p11lab-proxy-dist-%s" % PROXY_SHA,
        "p11lab-proxy-dist-%s-3-extra" % PROXY_SHA,
        "p11lab-proxy-%s-3" % PROXY_SHA,
        "",
    ],
)
def test_malformed_artifact_names_reject(name):
    assert _parse_artifact(name) is None


def test_same_run_selection_accepts_only_current_run_current_attempt():
    wanted = _record(PROXY_SHA, RUN_ID, 2)
    records = [
        wanted,
        _record(OTHER_SHA, RUN_ID, 2),
        _record(PROXY_SHA, RUN_ID + 1, 2),
        _record(PROXY_SHA, RUN_ID, 1),
    ]
    assert _select_same_run(records, PROXY_SHA, RUN_ID, 2) == wanted


@pytest.mark.parametrize(
    "records",
    [
        [],
        [_record(OTHER_SHA, RUN_ID, 2)],
        [_record(PROXY_SHA, RUN_ID + 1, 2)],
        [_record(PROXY_SHA, RUN_ID, 1)],
        [_record(PROXY_SHA, RUN_ID, 2), _record(PROXY_SHA, RUN_ID, 2)],
    ],
)
def test_cross_run_old_attempt_and_duplicate_lookup_reject(records):
    with pytest.raises(AssertionError, match="exactly the current-run"):
        _select_same_run(records, PROXY_SHA, RUN_ID, 2)


def test_same_run_selection_binds_authority_metadata():
    wanted = _record(PROXY_SHA, RUN_ID, 2)
    assert wanted["repository_id"] == AUTHORITY_REPOSITORY_ID
    assert wanted["repository_full_name"] == AUTHORITY_REPOSITORY_FULL_NAME
    assert wanted["producer_job_id"] == AUTHORITY_PRODUCER_JOB_ID
    assert wanted["artifact_id"] == AUTHORITY_ARTIFACT_ID
    assert _select_same_run([wanted], PROXY_SHA, RUN_ID, 2) == wanted


@pytest.mark.parametrize(
    "overrides",
    [
        {"repository_id": 9999},
        {"repository_full_name": "attacker/relabeled-caller"},
        {"producer_job_id": "999999"},
        {"artifact_id": 999999999},
    ],
)
def test_authority_metadata_mismatch_rejects(overrides):
    records = [_record(PROXY_SHA, RUN_ID, 2, **overrides)]
    with pytest.raises(AssertionError, match="exactly the current-run"):
        _select_same_run(records, PROXY_SHA, RUN_ID, 2)


# Authored payload bytes (invented fixtures): the manifest's size/hash
# entries describe THESE bytes, so byte verification invokes a real check
# instead of comparing unrelated constants.
DAEMON_PAYLOAD = b"p11lab-proxy-daemon-payload-invented-v1"
CLI_PAYLOAD = b"p11lab-proxy-cli-payload-invented-v1"
SHIM_PAYLOAD = b"p11lab-proxy-shim-payload-invented-v1"


def _verify_payload_bytes(payload, size, sha256, role):
    assert isinstance(payload, (bytes, bytearray)), "bytes for " + role
    assert len(payload) == size, "size mismatch for " + role
    assert hashlib.sha256(bytes(payload)).hexdigest() == sha256, (
        "hash mismatch for " + role
    )


def _manifest_fixture(**overrides):
    record = {
        "schema_version": 1,
        "caller_repository_id": 4242,
        "caller_repository_full_name": "example/proxy-caller",
        "source_commit": PROXY_SHA,
        "source_tree": "e" * 40,
        "source_archive_hash": "f" * 64,
        "run_id": RUN_ID,
        "run_attempt": 2,
        "build_job_id": "424243",
        "cargo_lock_hash": "0" * 64,
        "rustc_identity": "rustc 1.82.0 invented",
        "protoc_identity": "protoc 25.1 invented",
        "toolchain_identities": ["gcc 13 invented"],
        "target": "x86_64-unknown-linux-gnu",
        "features": ["softHSM"],
        "flags": ["--locked"],
        "dependency_closure": ["a" * 64],
        "vendored_closure": [],
        "daemon_path": "bin/p11lab-daemon",
        "daemon_size": len(DAEMON_PAYLOAD),
        "daemon_sha256": hashlib.sha256(DAEMON_PAYLOAD).hexdigest(),
        "cli_path": "bin/p11lab",
        "cli_size": len(CLI_PAYLOAD),
        "cli_sha256": hashlib.sha256(CLI_PAYLOAD).hexdigest(),
        "shim_path": "lib/p11lab-shim.so",
        "shim_size": len(SHIM_PAYLOAD),
        "shim_sha256": hashlib.sha256(SHIM_PAYLOAD).hexdigest(),
        "config_hashes": {"daemon": "4" * 64},
        "hook_hashes": {},
        "build_context_digest": "sha256:" + "5" * 64,
    }
    assert set(record) == MANIFEST_FIELDS
    record.update(overrides)
    return record


def _validate_manifest(record):
    assert set(record) == MANIFEST_FIELDS, "missing or extra manifest fields"
    for key, value in record.items():
        if key.endswith("_path"):
            assert isinstance(value, str) and value, key
            assert ".." not in value.split("/"), "path traversal in " + key
            assert not value.startswith("/"), "absolute path in " + key
        if key.endswith("_sha256"):
            assert re.fullmatch(r"[0-9a-f]{64}", value) is not None, key
    roles = (record["daemon_path"], record["cli_path"], record["shim_path"])
    assert len(set(roles)) == 3, "role paths must be distinct"


def test_manifest_fixture_accepts():
    _validate_manifest(_manifest_fixture())


def test_manifest_missing_field_rejects():
    record = _manifest_fixture()
    del record["cargo_lock_hash"]
    with pytest.raises(AssertionError, match="missing or extra"):
        _validate_manifest(record)


def test_manifest_extra_field_rejects():
    record = _manifest_fixture(role="ambiguous-second-role")
    with pytest.raises(AssertionError, match="missing or extra"):
        _validate_manifest(record)


@pytest.mark.parametrize(
    "path", ["../escape/shim.so", "/absolute/daemon", "bin/../../etc/x"]
)
def test_manifest_traversal_rejects(path):
    record = _manifest_fixture(daemon_path=path)
    with pytest.raises(AssertionError, match="traversal|absolute"):
        _validate_manifest(record)


def test_manifest_altered_bytes_reject():
    record = _manifest_fixture()
    altered = bytearray(SHIM_PAYLOAD)
    altered[0] ^= 1
    with pytest.raises(AssertionError, match="hash mismatch"):
        _verify_payload_bytes(
            bytes(altered),
            record["shim_size"],
            record["shim_sha256"],
            "shim",
        )


def test_manifest_authored_bytes_verify():
    record = _manifest_fixture()
    _verify_payload_bytes(
        DAEMON_PAYLOAD,
        record["daemon_size"],
        record["daemon_sha256"],
        "daemon",
    )
    _verify_payload_bytes(
        CLI_PAYLOAD, record["cli_size"], record["cli_sha256"], "cli"
    )
    _verify_payload_bytes(
        SHIM_PAYLOAD, record["shim_size"], record["shim_sha256"], "shim"
    )


def test_manifest_size_mismatch_rejects():
    record = _manifest_fixture()
    with pytest.raises(AssertionError, match="size mismatch"):
        _verify_payload_bytes(
            DAEMON_PAYLOAD[:-1],
            record["daemon_size"],
            record["daemon_sha256"],
            "daemon",
        )


@pytest.mark.parametrize(
    "overrides",
    [
        {"cli_path": "bin/p11lab-daemon"},
        {"shim_path": "bin/p11lab"},
        {"daemon_path": "lib/p11lab-shim.so"},
    ],
)
def test_manifest_overlapping_role_paths_reject(overrides):
    record = _manifest_fixture(**overrides)
    with pytest.raises(AssertionError, match="distinct"):
        _validate_manifest(record)


def test_capsule_carries_experiment_result_shape():
    run = _aggregate_run()
    for field in CAPSULE_FIELDS:
        assert ("'%s'" % field) in run, "capsule keeps " + field


def test_capsule_axes_stay_separate_with_nulls_for_unperformed():
    run = _aggregate_run()
    for fragment in (
        "'image_usable': None",
        "'lifecycle_complete': False",
        "'evidence_complete': False",
        "'evidence_admitted': False",
        "'comparison_positive': None",
        "'within_budget': None",
        "'distribution_eligible': False",
        "'experiment_positive': False",
        "'cells':",
        "'not-executed'",
        "'repository_id': None",
        "'repository_full_name': None",
    ):
        assert fragment in run, "capsule keeps " + fragment


def test_run_receipt_stays_authoritative():
    assert (
        "'run_receipt_note': 'run receipt v1 stays authoritative; "
        "this result references its bytes rather than mutating it'"
    ) in _aggregate_run()


def test_queue_reported_never_bounded():
    run = _aggregate_run()
    assert "'queue_seconds': None" in run
    assert (
        "'queue_note': 'queue time is measured and reported separately; "
        "timeout-minutes never bounds queue'"
    ) in run


def test_outputs_name_only_a_validated_capsule_or_stay_empty():
    run = _aggregate_run()
    assert (
        "{\n"
        "  echo 'result-artifact='\n"
        "  echo 'result-sha256='\n"
        "  echo 'experiment-positive=false'\n"
        '} >> "$GITHUB_OUTPUT"'
    ) in run
    assert "'result_artifact': None" in run
    assert "'result_sha256': None" in run


def test_no_pull_request_target_execution():
    assert "pull_request_target" not in _workflow_text()
    assert "pull_request_target" not in EXAMPLE.read_text()


def test_example_trigger_is_pull_request_only():
    raw = EXAMPLE.read_text()
    assert "workflow_dispatch" not in raw, "no dispatch path in caller"
    substituted = raw.replace("<P11LAB_COMMIT_SHA>", "c" * 40).replace(
        "<PROXY_COMMIT_SHA>", "d" * 40
    )
    assert _loads(substituted)["on"] == {"pull_request": None}


def _cells(**overrides):
    cells = {
        "direct": {
            "admitted": True,
            "complete": True,
            "attribution_usable": True,
            "findings": [],
        },
        "accepted-proxy": {
            "admitted": True,
            "complete": True,
            "terminal_evidence_complete": True,
        },
        "candidate-proxy": {
            "admitted": True,
            "complete": True,
            "terminal_evidence_complete": True,
        },
        "comparison": {
            "performed": True,
            "positive": True,
            "coverage_positive": True,
        },
        "cancelled": False,
        "uploads_complete": True,
        "infrastructure_error": None,
    }
    aliases = {
        "accepted_proxy": "accepted-proxy",
        "candidate_proxy": "candidate-proxy",
    }
    for key, value in overrides.items():
        key = aliases.get(key, key)
        if isinstance(value, dict):
            cells[key].update(value)
        else:
            cells[key] = value
    return cells


def _controls(fail=(), fail_accepted=()):
    controls = {}
    for control in ROSTER:
        controls[control] = {
            "accepted-proxy": "fail" if control in fail_accepted else "pass",
            "candidate-proxy": "fail" if control in fail else "pass",
        }
    return controls


def _budgets(within=True):
    return {"within_budget": within}


def test_t1_clean_control_is_positive():
    verdict = proxy_policy.evaluate_proxy_verdict(
        _cells(), _controls(), _budgets()
    )
    assert verdict == {
        "experiment_positive": True,
        "exit_code": 0,
        "evidence_complete": True,
        "typed_cause": None,
    }


@pytest.mark.parametrize("flaw", ["comparison", "coverage", "candidate-control"])
def test_t2_completed_negative_keeps_complete_evidence(flaw):
    cells, controls = _cells(), _controls()
    if flaw == "comparison":
        cells["comparison"]["positive"] = False
    elif flaw == "coverage":
        cells["comparison"]["coverage_positive"] = False
    else:
        controls["PX-STATE"]["candidate-proxy"] = "fail"
    verdict = proxy_policy.evaluate_proxy_verdict(cells, controls, _budgets())
    assert verdict == {
        "experiment_positive": False,
        "exit_code": 1,
        "evidence_complete": True,
        "typed_cause": "completed-negative",
    }


def test_t3_direct_gap_is_attribution_unknown():
    verdict = proxy_policy.evaluate_proxy_verdict(
        _cells(direct={"attribution_usable": False}),
        _controls(),
        _budgets(),
    )
    assert verdict == {
        "experiment_positive": False,
        "exit_code": 1,
        "evidence_complete": False,
        "typed_cause": "attribution-unknown",
    }


def test_t4_accepted_control_failure_is_control_unqualified():
    verdict = proxy_policy.evaluate_proxy_verdict(
        _cells(), _controls(fail_accepted=("PX-AUTH",)), _budgets()
    )
    assert verdict == {
        "experiment_positive": False,
        "exit_code": 1,
        "evidence_complete": False,
        "typed_cause": "control-unqualified",
    }


def test_t5_lost_terminal_evidence_is_incomplete():
    verdict = proxy_policy.evaluate_proxy_verdict(
        _cells(candidate_proxy={"terminal_evidence_complete": False}),
        _controls(),
        _budgets(),
    )
    assert verdict == {
        "experiment_positive": False,
        "exit_code": 1,
        "evidence_complete": False,
        "typed_cause": "terminal-evidence-unavailable",
    }


@pytest.mark.parametrize(
    "cells",
    [
        _cells(candidate_proxy={"admitted": False, "complete": False}),
        _cells(cancelled=True),
        _cells(uploads_complete=False),
        _cells(
            comparison={
                "performed": False,
                "positive": False,
                "coverage_positive": False,
            }
        ),
    ],
)
def test_t6_missing_or_cancelled_evidence_is_incomplete(cells):
    verdict = proxy_policy.evaluate_proxy_verdict(
        cells, _controls(), _budgets()
    )
    assert verdict == {
        "experiment_positive": False,
        "exit_code": 1,
        "evidence_complete": False,
        "typed_cause": "missing-evidence",
    }


def test_t6_absent_control_is_incomplete():
    controls = _controls()
    del controls["PX-REPLAY"]
    verdict = proxy_policy.evaluate_proxy_verdict(
        _cells(), controls, _budgets()
    )
    assert verdict == {
        "experiment_positive": False,
        "exit_code": 1,
        "evidence_complete": False,
        "typed_cause": "missing-evidence",
    }


def test_t7_budget_exceeded_is_incomplete_negative():
    verdict = proxy_policy.evaluate_proxy_verdict(
        _cells(), _controls(), _budgets(within=False)
    )
    assert verdict == {
        "experiment_positive": False,
        "exit_code": 1,
        "evidence_complete": False,
        "typed_cause": "budget-exceeded",
    }


def test_t8_usage_or_infrastructure_is_exit_2():
    cells = _cells(infrastructure_error="runner unreachable: invented-fixture")
    verdict = proxy_policy.evaluate_proxy_verdict(
        cells, _controls(), _budgets()
    )
    assert verdict == {
        "experiment_positive": False,
        "exit_code": 2,
        "evidence_complete": False,
        "typed_cause": "usage-or-infrastructure",
    }


def test_t9_injected_ck_rv_mismatch_detected_candidate_only():
    observation = {
        "control": "PX-STATE",
        "proxy": "candidate-proxy",
        "ck_rv": "0x00000006",
        "expected_ck_rv": "CKR_OK",
        "match": False,
    }
    assert observation["match"] is False
    assert observation["proxy"] == "candidate-proxy"
    controls = _controls(fail=(observation["control"],))
    assert controls["PX-STATE"]["accepted-proxy"] == "pass"
    verdict = proxy_policy.evaluate_proxy_verdict(
        _cells(), controls, _budgets()
    )
    assert verdict == {
        "experiment_positive": False,
        "exit_code": 1,
        "evidence_complete": True,
        "typed_cause": "completed-negative",
    }


def test_t10_injected_post_start_crash_detected_candidate_only():
    observation = {
        "proxy": "candidate-proxy",
        "unexpected_death": True,
        "logs_available": True,
    }
    assert observation["unexpected_death"] is True
    assert observation["proxy"] == "candidate-proxy"
    controls = _controls(fail=("PX-CLIENT-CRASH",))
    assert controls["PX-CLIENT-CRASH"]["accepted-proxy"] == "pass"
    verdict = proxy_policy.evaluate_proxy_verdict(
        _cells(), controls, _budgets()
    )
    assert verdict == {
        "experiment_positive": False,
        "exit_code": 1,
        "evidence_complete": True,
        "typed_cause": "completed-negative",
    }


def test_t11_direct_findings_do_not_veto_a_clean_proxy():
    cells = _cells(direct={"findings": ["provider-finding:invented-only"]})
    verdict = proxy_policy.evaluate_proxy_verdict(
        cells, _controls(), _budgets()
    )
    assert verdict == {
        "experiment_positive": True,
        "exit_code": 0,
        "evidence_complete": True,
        "typed_cause": None,
    }


def test_evidence_complete_split_across_rows():
    complete = proxy_policy.evaluate_proxy_verdict(
        _cells(comparison={"positive": False}), _controls(), _budgets()
    )
    assert complete["typed_cause"] == "completed-negative"
    assert complete["evidence_complete"] is True
    incomplete = [
        proxy_policy.evaluate_proxy_verdict(
            _cells(direct={"attribution_usable": False}),
            _controls(),
            _budgets(),
        ),
        proxy_policy.evaluate_proxy_verdict(
            _cells(), _controls(fail_accepted=("PX-AUTH",)), _budgets()
        ),
        proxy_policy.evaluate_proxy_verdict(
            _cells(candidate_proxy={"terminal_evidence_complete": False}),
            _controls(),
            _budgets(),
        ),
        proxy_policy.evaluate_proxy_verdict(
            _cells(cancelled=True), _controls(), _budgets()
        ),
        proxy_policy.evaluate_proxy_verdict(
            _cells(), _controls(), _budgets(within=False)
        ),
        proxy_policy.evaluate_proxy_verdict(
            _cells(infrastructure_error="invented"), _controls(), _budgets()
        ),
    ]
    assert [v["typed_cause"] for v in incomplete] == [
        "attribution-unknown",
        "control-unqualified",
        "terminal-evidence-unavailable",
        "missing-evidence",
        "budget-exceeded",
        "usage-or-infrastructure",
    ]
    assert all(v["evidence_complete"] is False for v in incomplete)
