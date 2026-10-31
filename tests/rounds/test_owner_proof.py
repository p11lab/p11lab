"""Round-mode owner proof: job-binding attestation verification (B-F2-ext).

Hermetic suite for the custody-style round extension: per-run overlay pins,
C1-C4 signature checks, the code-enforced 2-job roster, the single-member
attestation envelope, and the prepare() github-path hook. The sealed gh
verifier is never executed: GH_EXECUTABLE_SHA256 is monkeypatched to the
fixture script digest and bounded_stream is stubbed per
tests/test_source_authority.py:415-448. No network, Docker, or GitHub API.
"""

import base64
import copy
import hashlib
import io
import json
import shutil
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from p11lab.round_core import inputs

OWNER_FIXTURES = Path(__file__).parent.parent / "fixtures" / "owner_proof"
ROUNDS_FIXTURES = Path(__file__).parent / "fixtures"

REPO = "mingulov/p11lab-round-caller"
REPO_ID = 1439580215
OWNER_ID = 1794540
WF_ID = 401625989
PRODUCER_JOB = "produce-framework-dist"
CONTEXT_JOB = "upload-round-context"
RUN_ID = 456
ATTEMPT = 2
RUN_HEAD_SHA = "10017b195e46ffd152a398970ed5412ae8c37f0a"
CANDIDATE_SHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
TARGET_SHA = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
MERGE_BASE_SHA = "cccccccccccccccccccccccccccccccccccccccc"
CONTROL_SHA = "e" * 40
HEAD_BRANCH = "main"
SOURCE_REF = "refs/heads/main"
ROUND_PREDICATE = "https://p11lab.org/attestations/round-artifact/v1"
ROUND_SUBJECT = "round-artifact.json"
ZEROS = "0" * 64


def _op():
    from p11lab.round_core import owner_proof

    return owner_proof


def _root_sha256():
    return hashlib.sha256((OWNER_FIXTURES / "trusted-root.jsonl").read_bytes()).hexdigest()


def _round_profile(root_sha256=None, **overrides):
    profile = {
        "repository": REPO,
        "repository_id": REPO_ID,
        "owner_id": OWNER_ID,
        "workflow_id": WF_ID,
        "producer_job": PRODUCER_JOB,
        "control_sha": CONTROL_SHA,
        "policy_sha256": "1" * 64,
        "target_sha256": "2" * 64,
        "data_sources_sha256": inputs.digest([]),
        "data_sources": [],
        "context_artifact_name": "p11lab-round-context-{run_id}-{attempt}",
        "context_job": CONTEXT_JOB,
        "runtime": {
            "image": "sha256:" + "3" * 64,
            "layers": ["sha256:" + "4" * 64],
            "config_sha256": "5" * 64,
            "tool_identity_sha256": "6" * 64,
            "python_version": "3.12.14",
            "max_output_bytes": 16777216,
            "source_date_epoch": 1,
        },
        "workflow_path": ".github/workflows/round.yml",
        "boundary_path": "boundary.md",
        "graph": [
            {"path": ".github/workflows/round.yml", "sha256": hashlib.sha256(b"workflow-bytes").hexdigest()},
            {"path": "boundary.md", "sha256": hashlib.sha256(b"boundary-bytes").hexdigest()},
        ],
        "root_sha256": _root_sha256() if root_sha256 is None else root_sha256,
        "attestation_artifact_name": "p11lab-round-attestation-{run_id}-{attempt}",
    }
    profile.update(overrides)
    return profile


def _context(**overrides):
    context = {"run_head_sha": RUN_HEAD_SHA}
    context.update(overrides)
    return context


def _attempt(**overrides):
    attempt = {
        "id": RUN_ID,
        "run_attempt": ATTEMPT,
        "head_sha": RUN_HEAD_SHA,
        "head_branch": HEAD_BRANCH,
        "workflow_id": WF_ID,
        "repository": {"id": REPO_ID},
        "run_started_at": "2024-01-01T00:00:00Z",
    }
    attempt.update(overrides)
    return attempt


def _job_times():
    now = datetime.now(timezone.utc)
    started = (now - timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    completed = now.isoformat().replace("+00:00", "Z")
    created = (now - timedelta(minutes=30)).isoformat().replace("+00:00", "Z")
    return started, completed, created


def _job_row(name, started, completed, **overrides):
    row = {
        "name": name,
        "run_id": RUN_ID,
        "head_sha": RUN_HEAD_SHA,
        "conclusion": "success",
        "status": "completed",
        "started_at": started,
        "completed_at": completed,
    }
    row.update(overrides)
    return row


def _jobs_payload(started, completed, extra=()):
    rows = [_job_row(PRODUCER_JOB, started, completed), _job_row(CONTEXT_JOB, started, completed)]
    rows.extend(extra)
    return {"total_count": len(rows), "jobs": rows}


def _artifact_row(name, created, artifact_id=999, raw=b"x"):
    return {
        "id": artifact_id,
        "name": name,
        "size_in_bytes": len(raw),
        "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
        "expired": False,
        "created_at": created,
        "workflow_run": {"id": RUN_ID, "repository_id": REPO_ID, "head_sha": RUN_HEAD_SHA},
    }


def _metadata_identity(**overrides):
    identity = {
        "repository_id": REPO_ID,
        "run_id": RUN_ID,
        "attempt": ATTEMPT,
        "candidate_sha": CANDIDATE_SHA,
        "target_sha": TARGET_SHA,
        "merge_base_sha": MERGE_BASE_SHA,
        "run_head_sha": RUN_HEAD_SHA,
        "workflow_id": WF_ID,
        "producer_job": PRODUCER_JOB,
    }
    identity.update(overrides)
    return identity


def _subject_bytes(dist_digest, run_id=RUN_ID, attempt=ATTEMPT):
    return inputs.canonical(
        {"schema_version": 1, "dist_digest": dist_digest, "run_id": run_id, "attempt": attempt}
    )


def _envelope_bytes(subject_raw, bundle_raw):
    member = inputs.canonical(
        {
            "subject_b64": base64.b64encode(subject_raw).decode(),
            "bundle_b64": base64.b64encode(bundle_raw).decode(),
        }
    )
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("round-attestation.json", member)
    return out.getvalue()


def _bundle_bytes():
    return inputs.canonical({"fixture": "owner-proof-bundle"})


def _round_result(overlay, run_id, attempt, subject_bytes, *, damage=None):
    repo = overlay["repository"]
    workflow = "https://github.com/" + repo + "/" + overlay["workflow_path"] + "@" + overlay["source_ref"]
    owner = repo.split("/")[0]
    cert = {
        "issuer": "https://token.actions.githubusercontent.com",
        "subjectAlternativeName": workflow,
        "buildSignerURI": workflow,
        "buildSignerDigest": overlay["signer_sha"],
        "sourceRepositoryURI": "https://github.com/" + repo,
        "sourceRepositoryIdentifier": str(overlay["repository_id"]),
        "sourceRepositoryOwnerURI": "https://github.com/" + owner,
        "sourceRepositoryOwnerIdentifier": str(overlay["owner_id"]),
        "sourceRepositoryDigest": overlay["source_sha"],
        "sourceRepositoryRef": overlay["source_ref"],
        "runnerEnvironment": "github-hosted",
        "runInvocationURI": (
            "https://github.com/" + repo + "/actions/runs/" + str(run_id) + "/attempts/" + str(attempt)
        ),
    }
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": ROUND_PREDICATE,
        "subject": [
            {"name": ROUND_SUBJECT, "digest": {"sha256": hashlib.sha256(subject_bytes).hexdigest()}}
        ],
        "predicate": {"schema_version": 1, "producer_job": overlay["producer_job"]},
    }
    now = datetime.now(timezone.utc)
    result = [
        {
            "verificationResult": {
                "signature": {"certificate": cert},
                "verifiedTimestamps": [
                    {"type": "Tlog", "timestamp": now.isoformat().replace("+00:00", "Z")}
                ],
                "statement": statement,
            }
        }
    ]
    if damage == "cert":
        result[0]["verificationResult"]["signature"]["certificate"]["issuer"] += "-forged"
    elif damage == "subject":
        result[0]["verificationResult"]["statement"]["subject"][0]["digest"]["sha256"] = "f" * 64
    elif damage == "predicate-type":
        result[0]["verificationResult"]["statement"]["predicateType"] += "/lookalike"
    elif damage == "predicate-job":
        result[0]["verificationResult"]["statement"]["predicate"]["producer_job"] = "intruder-job"
    elif damage == "timestamp":
        result[0]["verificationResult"]["verifiedTimestamps"][0]["timestamp"] = "2020-01-01T00:00:00Z"
    elif damage == "ambiguous":
        result.append(copy.deepcopy(result[0]))
    elif damage == "empty-timestamps":
        result[0]["verificationResult"]["verifiedTimestamps"] = []
    elif damage == "invalid-ts-type":
        result[0]["verificationResult"]["verifiedTimestamps"] = [
            {"type": "Bogus", "timestamp": now.isoformat().replace("+00:00", "Z")}
        ]
    elif damage == "malformed":
        result = [{"verificationResult": {}}]
    return result


def _stub_round_verifier(monkeypatch, overlay, run_id, attempt, *, damage=None, capture=None):
    from p11lab import delivery_authority as authority
    from p11lab import inspection_bounded

    exe = OWNER_FIXTURES / "verify-fixture.sh"
    monkeypatch.setattr(
        authority, "GH_EXECUTABLE_SHA256", hashlib.sha256(exe.read_bytes()).hexdigest()
    )

    def run(argv, destination, max_bytes, timeout, env, record):
        if capture is not None:
            capture.append(list(argv))
        subject_bytes = Path(argv[3]).read_bytes()
        destination.write_text(json.dumps(_round_result(overlay, run_id, attempt, subject_bytes, damage=damage)))
        record["returncode"] = 0

    monkeypatch.setattr(inspection_bounded, "bounded_stream", run)


def _write_proof_files(tmp_path, subject_raw, bundle_raw):
    subject_path = tmp_path / "round-artifact.json"
    bundle_path = tmp_path / "bundle.json"
    root_path = tmp_path / "trusted-root.jsonl"
    subject_path.write_bytes(subject_raw)
    bundle_path.write_bytes(bundle_raw)
    root_path.write_bytes((OWNER_FIXTURES / "trusted-root.jsonl").read_bytes())
    return subject_path, bundle_path, root_path


def test_module_constants_match_pinned_values():
    from p11lab import delivery_authority as authority

    assert authority.ROUND_PREDICATE_TYPE == ROUND_PREDICATE
    assert _op().ROUND_SUBJECT_NAME == ROUND_SUBJECT
    assert _op().ROUND_MAX_AGE_SECONDS == 86400


def test_overlay_pins_exact_grounded_values():
    profile = _round_profile()
    overlay = _op().round_verifier_overlay(profile, _context(), _attempt())
    assert overlay["source_sha"] == RUN_HEAD_SHA
    assert overlay["signer_sha"] == RUN_HEAD_SHA
    assert overlay["source_ref"] == SOURCE_REF
    assert overlay["max_age_seconds"] == 86400
    assert overlay["producer_job"] == PRODUCER_JOB
    assert overlay["repository"] == REPO
    assert "source_sha" not in profile


def test_overlay_unenrolled_root_refused():
    profile = _round_profile(root_sha256=ZEROS)
    with pytest.raises(ValueError, match="^round owner proof is not enrolled$"):
        _op().round_verifier_overlay(profile, _context(), _attempt())


def test_overlay_missing_root_refused():
    profile = _round_profile()
    del profile["root_sha256"]
    with pytest.raises(ValueError, match="^round owner proof is not enrolled$"):
        _op().round_verifier_overlay(profile, _context(), _attempt())


def test_overlay_malformed_root_refused():
    profile = _round_profile(root_sha256="not-hex")
    with pytest.raises(ValueError, match="^round owner proof is not enrolled$"):
        _op().round_verifier_overlay(profile, _context(), _attempt())


def test_overlay_head_branch_absent_refused():
    attempt = _attempt()
    del attempt["head_branch"]
    with pytest.raises(ValueError, match="^round attestation source ref unavailable$"):
        _op().round_verifier_overlay(_round_profile(), _context(), attempt)


@pytest.mark.parametrize("branch", ["", "a:b", "a b", 7, None])
def test_overlay_bad_branch_refused(branch):
    attempt = _attempt(head_branch=branch)
    with pytest.raises(ValueError, match="^round attestation source ref unavailable$"):
        _op().round_verifier_overlay(_round_profile(), _context(), attempt)


def test_overlay_head_mismatch_refused():
    attempt = _attempt(head_sha="f" * 40)
    with pytest.raises(ValueError, match="^round run head mismatch$"):
        _op().round_verifier_overlay(_round_profile(), _context(), attempt)


@pytest.mark.parametrize("head", ["xyz", "", None, 42])
def test_overlay_bad_run_head_refused(head):
    with pytest.raises(ValueError, match="^invalid round run head$"):
        _op().round_verifier_overlay(_round_profile(), _context(run_head_sha=head), _attempt())


def test_roster_accepts_exact_two_jobs():
    started, completed, _ = _job_times()
    assert _op().check_round_roster(_jobs_payload(started, completed), _round_profile()) is None


def test_roster_three_jobs_refused():
    started, completed, _ = _job_times()
    extra = (_job_row("intruder-job", started, completed),)
    with pytest.raises(ValueError, match="^round job roster mismatch$"):
        _op().check_round_roster(_jobs_payload(started, completed, extra), _round_profile())


def test_roster_wrong_name_refused():
    started, completed, _ = _job_times()
    jobs = _jobs_payload(started, completed)
    jobs["jobs"][1]["name"] = "other-job"
    with pytest.raises(ValueError, match="^round job roster mismatch$"):
        _op().check_round_roster(jobs, _round_profile())


def test_roster_count_mismatch_refused():
    started, completed, _ = _job_times()
    jobs = _jobs_payload(started, completed)
    jobs["total_count"] = 3
    with pytest.raises(ValueError, match="^round job roster mismatch$"):
        _op().check_round_roster(jobs, _round_profile())


@pytest.mark.parametrize("jobs", [{}, {"jobs": []}, {"total_count": 2}, None, []])
def test_roster_malformed_refused(jobs):
    with pytest.raises(ValueError, match="^malformed round job roster$"):
        _op().check_round_roster(jobs, _round_profile())


def _signature_case():
    profile = _round_profile()
    overlay = _op().round_verifier_overlay(profile, _context(), _attempt())
    raw = _subject_bytes("sha256:" + hashlib.sha256(b"dist-bytes").hexdigest())
    identity = {
        "run_id": RUN_ID,
        "attempt": ATTEMPT,
        "producer_job": PRODUCER_JOB,
        "run_head_sha": RUN_HEAD_SHA,
        "source_ref": SOURCE_REF,
    }
    started, completed, _ = _job_times()
    job = _job_row(PRODUCER_JOB, started, completed)
    return overlay, identity, raw, job


def test_signature_accepts_valid():
    overlay, identity, raw, job = _signature_case()
    result = _round_result(overlay, RUN_ID, ATTEMPT, raw)
    assert (
        _op().check_round_signature(result, overlay, identity, raw, job, datetime.now(timezone.utc))
        is None
    )


def test_signature_cert_mismatch_refused():
    overlay, identity, raw, job = _signature_case()
    result = _round_result(overlay, RUN_ID, ATTEMPT, raw, damage="cert")
    with pytest.raises(ValueError, match="^verified certificate identity mismatch$"):
        _op().check_round_signature(result, overlay, identity, raw, job, datetime.now(timezone.utc))


def test_signature_subject_mismatch_refused():
    overlay, identity, raw, job = _signature_case()
    result = _round_result(overlay, RUN_ID, ATTEMPT, raw, damage="subject")
    with pytest.raises(ValueError, match="^verified source context subject or predicate mismatch$"):
        _op().check_round_signature(result, overlay, identity, raw, job, datetime.now(timezone.utc))


def test_signature_predicate_type_mismatch_refused():
    overlay, identity, raw, job = _signature_case()
    result = _round_result(overlay, RUN_ID, ATTEMPT, raw, damage="predicate-type")
    with pytest.raises(ValueError, match="^verified source context subject or predicate mismatch$"):
        _op().check_round_signature(result, overlay, identity, raw, job, datetime.now(timezone.utc))


def test_signature_wrong_job_predicate_refused():
    overlay, identity, raw, job = _signature_case()
    result = _round_result(overlay, RUN_ID, ATTEMPT, raw, damage="predicate-job")
    with pytest.raises(ValueError, match="^verified source context subject or predicate mismatch$"):
        _op().check_round_signature(result, overlay, identity, raw, job, datetime.now(timezone.utc))


def test_signature_timestamp_outside_window_refused():
    overlay, identity, raw, job = _signature_case()
    result = _round_result(overlay, RUN_ID, ATTEMPT, raw, damage="timestamp")
    with pytest.raises(ValueError, match="^verified timestamp outside accepted window$"):
        _op().check_round_signature(result, overlay, identity, raw, job, datetime.now(timezone.utc))


def test_signature_ambiguous_refused():
    overlay, identity, raw, job = _signature_case()
    result = _round_result(overlay, RUN_ID, ATTEMPT, raw, damage="ambiguous")
    with pytest.raises(ValueError, match="^ambiguous verified attestations$"):
        _op().check_round_signature(result, overlay, identity, raw, job, datetime.now(timezone.utc))


def test_signature_malformed_refused():
    overlay, identity, raw, job = _signature_case()
    result = _round_result(overlay, RUN_ID, ATTEMPT, raw, damage="malformed")
    with pytest.raises(ValueError, match="^malformed verified attestation$"):
        _op().check_round_signature(result, overlay, identity, raw, job, datetime.now(timezone.utc))


def test_signature_naive_job_timestamp_refused():
    overlay, identity, raw, job = _signature_case()
    job["started_at"] = job["started_at"].replace("Z", "")
    result = _round_result(overlay, RUN_ID, ATTEMPT, raw)
    with pytest.raises(ValueError, match="^round job timestamp requires timezone$"):
        _op().check_round_signature(result, overlay, identity, raw, job, datetime.now(timezone.utc))


def test_signature_reversed_job_timing_refused():
    overlay, identity, raw, job = _signature_case()
    job["started_at"], job["completed_at"] = job["completed_at"], job["started_at"]
    result = _round_result(overlay, RUN_ID, ATTEMPT, raw)
    with pytest.raises(ValueError, match="^invalid round job timing$"):
        _op().check_round_signature(result, overlay, identity, raw, job, datetime.now(timezone.utc))


def test_signature_expired_window_refused():
    overlay, identity, raw, _job = _signature_case()
    old = (datetime.now(timezone.utc) - timedelta(days=20)).isoformat().replace("+00:00", "Z")
    job = _job_row(PRODUCER_JOB, old, old)
    result = _round_result(overlay, RUN_ID, ATTEMPT, raw)
    with pytest.raises(ValueError, match="^round attestation expired or premature$"):
        _op().check_round_signature(result, overlay, identity, raw, job, datetime.now(timezone.utc))


def test_signature_zeros_overlay_refused():
    overlay, identity, raw, job = _signature_case()
    overlay["root_sha256"] = ZEROS
    result = _round_result(overlay, RUN_ID, ATTEMPT, raw)
    with pytest.raises(ValueError, match="^round owner proof is not enrolled$"):
        _op().check_round_signature(result, overlay, identity, raw, job, datetime.now(timezone.utc))


def test_signature_naive_clock_refused():
    overlay, identity, raw, job = _signature_case()
    result = _round_result(overlay, RUN_ID, ATTEMPT, raw)
    with pytest.raises(ValueError, match="^verification clock requires timezone$"):
        _op().check_round_signature(result, overlay, identity, raw, job, datetime.now(timezone.utc).replace(tzinfo=None))


def test_subject_accepts_valid():
    dist_digest = "sha256:" + hashlib.sha256(b"dist-bytes").hexdigest()
    raw = _subject_bytes(dist_digest)
    identity = {"run_id": RUN_ID, "attempt": ATTEMPT}
    assert _op().check_round_subject(raw, dist_digest, identity) is None


def test_subject_dist_mismatch_refused():
    raw = _subject_bytes("sha256:" + "f" * 64)
    identity = {"run_id": RUN_ID, "attempt": ATTEMPT}
    with pytest.raises(ValueError, match="^round attestation subject mismatch$"):
        _op().check_round_subject(raw, "sha256:" + hashlib.sha256(b"dist-bytes").hexdigest(), identity)


def test_subject_run_mismatch_refused():
    dist_digest = "sha256:" + hashlib.sha256(b"dist-bytes").hexdigest()
    raw = _subject_bytes(dist_digest, run_id=RUN_ID + 1)
    identity = {"run_id": RUN_ID, "attempt": ATTEMPT}
    with pytest.raises(ValueError, match="^round attestation subject mismatch$"):
        _op().check_round_subject(raw, dist_digest, identity)


@pytest.mark.parametrize(
    "raw",
    [
        b"not-json",
        b"[]",
        inputs.canonical({"schema_version": 1}),
        inputs.canonical({"schema_version": 1, "dist_digest": "x", "run_id": 1, "attempt": 1, "extra": 0}),
        inputs.canonical({"schema_version": "1", "dist_digest": "sha256:" + "f" * 64, "run_id": 1, "attempt": 1}),
    ],
)
def test_subject_malformed_refused(raw):
    identity = {"run_id": RUN_ID, "attempt": ATTEMPT}
    with pytest.raises(ValueError, match="^malformed round attestation subject$"):
        _op().check_round_subject(raw, "sha256:" + "f" * 64, identity)


def _decode():
    from p11lab.round_core.artifacts import decode_round_attestation

    return decode_round_attestation


def test_decode_accepts_checked_in_fixture():
    raw = (OWNER_FIXTURES / "round-attestation.zip").read_bytes()
    subject_raw, bundle_raw = _decode()(raw)
    subject = json.loads(subject_raw)
    assert subject["schema_version"] == 1
    assert subject["run_id"] == 456
    assert subject["attempt"] == 2
    assert subject["dist_digest"] == "sha256:" + hashlib.sha256(
        (ROUNDS_FIXTURES / "fixture-dist.zip").read_bytes()
    ).hexdigest()
    assert json.loads(bundle_raw) == {"fixture": "owner-proof-bundle"}


def _zip_bytes(members):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, payload in members:
            archive.writestr(name, payload)
    return out.getvalue()


def test_decode_rejects_non_zip():
    with pytest.raises(ValueError, match="^invalid round attestation archive$"):
        _decode()(b"not-a-zip")


def test_decode_rejects_wrong_roster():
    member = inputs.canonical({"subject_b64": "eA==", "bundle_b64": "eQ=="})
    with pytest.raises(ValueError, match="^invalid round attestation archive$"):
        _decode()(_zip_bytes([("round-attestation.json", member), ("extra.json", b"{}")]))
    with pytest.raises(ValueError, match="^invalid round attestation archive$"):
        _decode()(_zip_bytes([("other.json", member)]))


@pytest.mark.parametrize(
    "member",
    [
        b"not-json",
        b"[]",
        inputs.canonical({"subject_b64": "eA=="}),
        inputs.canonical({"subject_b64": "!!!", "bundle_b64": "eQ=="}),
        inputs.canonical({"subject_b64": "", "bundle_b64": "eQ=="}),
        inputs.canonical({"subject_b64": "eA==", "bundle_b64": ""}),
    ],
)
def test_decode_rejects_bad_envelope(member):
    with pytest.raises(ValueError, match="^invalid round attestation envelope$"):
        _decode()(_zip_bytes([("round-attestation.json", member)]))


def test_decode_rejects_oversized_zip():
    with pytest.raises(ValueError, match="^round attestation archive bound$"):
        _decode()(b"z" * (2 * 1024 * 1024 + 1))


def _round_run_case(tmp_path):
    profile = _round_profile()
    overlay = _op().round_verifier_overlay(profile, _context(), _attempt())
    subject_raw = _subject_bytes("sha256:" + hashlib.sha256(b"dist-bytes").hexdigest())
    subject_path, bundle_path, root_path = _write_proof_files(tmp_path, subject_raw, _bundle_bytes())
    return overlay, subject_path, bundle_path, root_path


def test_run_round_verifier_accepts_live_shaped(tmp_path, monkeypatch):
    overlay, subject_path, bundle_path, root_path = _round_run_case(tmp_path)
    _stub_round_verifier(monkeypatch, overlay, RUN_ID, ATTEMPT)
    result, verified_raw = _op().run_round_verifier(
        OWNER_FIXTURES / "verify-fixture.sh",
        subject_path,
        bundle_path,
        root_path,
        overlay["root_sha256"],
        overlay,
        tmp_path / "attestation",
    )
    assert verified_raw == subject_path.read_bytes()
    started, completed, _ = _job_times()
    identity = {
        "run_id": RUN_ID,
        "attempt": ATTEMPT,
        "producer_job": PRODUCER_JOB,
        "run_head_sha": RUN_HEAD_SHA,
        "source_ref": SOURCE_REF,
    }
    assert (
        _op().check_round_signature(
            result, overlay, identity, verified_raw, _job_row(PRODUCER_JOB, started, completed),
            datetime.now(timezone.utc),
        )
        is None
    )


def test_run_round_verifier_zeros_refuses_without_executing(tmp_path, monkeypatch):
    from p11lab import inspection_bounded

    overlay, subject_path, bundle_path, root_path = _round_run_case(tmp_path)
    overlay["root_sha256"] = ZEROS
    calls = []
    monkeypatch.setattr(
        inspection_bounded, "bounded_stream", lambda *args: calls.append(args)
    )
    with pytest.raises(ValueError, match="^round owner proof is not enrolled$"):
        _op().run_round_verifier(
            OWNER_FIXTURES / "verify-fixture.sh",
            subject_path,
            bundle_path,
            root_path,
            ZEROS,
            overlay,
            tmp_path / "attestation",
        )
    assert calls == []


def test_run_round_verifier_root_mismatch_refused(tmp_path, monkeypatch):
    overlay, subject_path, bundle_path, _root_path = _round_run_case(tmp_path)
    bad_root = tmp_path / "bad-root.jsonl"
    bad_root.write_bytes(b"tampered-trust-root")
    _stub_round_verifier(monkeypatch, overlay, RUN_ID, ATTEMPT)
    with pytest.raises(ValueError, match="^protected trusted root digest mismatch$"):
        _op().run_round_verifier(
            OWNER_FIXTURES / "verify-fixture.sh",
            subject_path,
            bundle_path,
            bad_root,
            overlay["root_sha256"],
            overlay,
            tmp_path / "attestation",
        )


def test_run_round_verifier_exe_mismatch_refused(tmp_path, monkeypatch):
    overlay, subject_path, bundle_path, root_path = _round_run_case(tmp_path)
    other_exe = tmp_path / "other.sh"
    other_exe.write_bytes(b"#!/bin/sh\necho other\n")
    _stub_round_verifier(monkeypatch, overlay, RUN_ID, ATTEMPT)
    with pytest.raises(ValueError, match="^verifier executable digest mismatch$"):
        _op().run_round_verifier(
            other_exe, subject_path, bundle_path, root_path, overlay["root_sha256"], overlay,
            tmp_path / "attestation",
        )


def _delivery_profile():
    return {
        "repository": REPO,
        "workflow_path": ".github/workflows/round.yml",
        "source_ref": SOURCE_REF,
        "signer_sha": RUN_HEAD_SHA,
        "source_sha": RUN_HEAD_SHA,
    }


def _expected_argv(output, profile, *, subject_name, predicate):
    return [
        str((output / "gh").absolute()),
        "attestation",
        "verify",
        str((output / subject_name).absolute()),
        "--repo",
        profile["repository"],
        "--bundle",
        str((output / "bundle.json").absolute()),
        "--custom-trusted-root",
        str((output / "trusted-root.jsonl").absolute()),
        "--predicate-type",
        predicate,
        "--format",
        "json",
        "--signer-digest",
        profile["signer_sha"],
        "--source-digest",
        profile["source_sha"],
        "--source-ref",
        profile["source_ref"],
        "--cert-identity",
        "https://" + "github.com/" + profile["repository"] + "/" + profile["workflow_path"]
        + "@" + profile["source_ref"],
        "--deny-self-hosted-runners",
    ]


def _stub_capture(monkeypatch):
    from p11lab import delivery_authority as authority
    from p11lab import inspection_bounded

    exe = OWNER_FIXTURES / "verify-fixture.sh"
    monkeypatch.setattr(
        authority, "GH_EXECUTABLE_SHA256", hashlib.sha256(exe.read_bytes()).hexdigest()
    )
    capture = []

    def run(argv, destination, max_bytes, timeout, env, record):
        capture.append(list(argv))
        destination.write_text("[{}]")
        record["returncode"] = 0

    monkeypatch.setattr(inspection_bounded, "bounded_stream", run)
    return capture


def test_non_round_argv_byte_identical(tmp_path, monkeypatch):
    from p11lab import delivery_authority as authority

    profile = _delivery_profile()
    capture = _stub_capture(monkeypatch)
    context_path = tmp_path / "context.json"
    bundle_path = tmp_path / "bundle.json"
    root_path = tmp_path / "trusted-root.jsonl"
    context_path.write_bytes(b"{}")
    bundle_path.write_bytes(b"{}")
    root_path.write_bytes(b"root")
    output = tmp_path / "out"
    authority._run_verifier(
        OWNER_FIXTURES / "verify-fixture.sh", context_path, bundle_path, root_path,
        hashlib.sha256(b"root").hexdigest(), profile, output,
    )
    assert capture == [
        _expected_argv(output, profile, subject_name="source-context.json",
                       predicate=authority.PREDICATE_TYPE)
    ]


def test_custody_argv_byte_identical(tmp_path, monkeypatch):
    from p11lab import delivery_authority as authority

    profile = _delivery_profile()
    capture = _stub_capture(monkeypatch)
    context_path = tmp_path / "context.json"
    bundle_path = tmp_path / "bundle.json"
    root_path = tmp_path / "trusted-root.jsonl"
    context_path.write_bytes(b"{}")
    bundle_path.write_bytes(b"{}")
    root_path.write_bytes(b"root")
    output = tmp_path / "out"
    authority._run_verifier(
        OWNER_FIXTURES / "verify-fixture.sh", context_path, bundle_path, root_path,
        hashlib.sha256(b"root").hexdigest(), profile, output, custody=True,
    )
    assert capture == [
        _expected_argv(output, profile, subject_name="custody-finalization.json",
                       predicate="https://p11lab.org/attestations/image-custody/v1")
    ]


def test_round_argv_shape(tmp_path, monkeypatch):
    from p11lab import delivery_authority as authority

    profile = _delivery_profile()
    capture = _stub_capture(monkeypatch)
    context_path = tmp_path / "context.json"
    bundle_path = tmp_path / "bundle.json"
    root_path = tmp_path / "trusted-root.jsonl"
    context_path.write_bytes(b"{}")
    bundle_path.write_bytes(b"{}")
    root_path.write_bytes(b"root")
    output = tmp_path / "out"
    authority._run_verifier(
        OWNER_FIXTURES / "verify-fixture.sh", context_path, bundle_path, root_path,
        hashlib.sha256(b"root").hexdigest(), profile, output, round_artifact=True,
    )
    expected = _expected_argv(output, profile, subject_name="round-artifact.json",
                              predicate=authority.ROUND_PREDICATE_TYPE)
    assert capture == [expected]


def test_verifier_profile_mutual_exclusion(tmp_path, monkeypatch):
    from p11lab import delivery_authority as authority

    profile = _delivery_profile()
    _stub_capture(monkeypatch)
    context_path = tmp_path / "context.json"
    bundle_path = tmp_path / "bundle.json"
    root_path = tmp_path / "trusted-root.jsonl"
    context_path.write_bytes(b"{}")
    bundle_path.write_bytes(b"{}")
    root_path.write_bytes(b"root")
    with pytest.raises(ValueError, match="^invalid verifier profile$"):
        authority._run_verifier(
            OWNER_FIXTURES / "verify-fixture.sh", context_path, bundle_path, root_path,
            hashlib.sha256(b"root").hexdigest(), profile, tmp_path / "out-a",
            custody=True, round_artifact=True,
        )
    with pytest.raises(ValueError, match="^invalid verifier profile$"):
        authority._run_verifier(
            OWNER_FIXTURES / "verify-fixture.sh", context_path, bundle_path, root_path,
            hashlib.sha256(b"root").hexdigest(), profile, tmp_path / "out-b",
            round_artifact="yes",
        )


def test_round_bounds_differ_while_legacy_bounds_hold(tmp_path, monkeypatch):
    from p11lab import delivery_authority as authority

    profile = _delivery_profile()
    capture = _stub_capture(monkeypatch)
    big_context = tmp_path / "big-context.json"
    big_context.write_bytes(b"c" * (1024 * 1024 + 1))
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_bytes(b"{}")
    root_path = tmp_path / "trusted-root.jsonl"
    root_path.write_bytes(b"root")
    root_sha = hashlib.sha256(b"root").hexdigest()
    with pytest.raises(ValueError, match="^unsafe or oversized verifier input$"):
        authority._run_verifier(
            OWNER_FIXTURES / "verify-fixture.sh", big_context, bundle_path, root_path,
            root_sha, profile, tmp_path / "out-legacy",
        )
    authority._run_verifier(
        OWNER_FIXTURES / "verify-fixture.sh", big_context, bundle_path, root_path,
        root_sha, profile, tmp_path / "out-round", round_artifact=True,
    )
    assert len(capture) == 1
    big_bundle = tmp_path / "big-bundle.json"
    big_bundle.write_bytes(b"b" * (2 * 1024 * 1024 + 1))
    small_context = tmp_path / "small-context.json"
    small_context.write_bytes(b"{}")
    with pytest.raises(ValueError, match="^unsafe or oversized verifier input$"):
        authority._run_verifier(
            OWNER_FIXTURES / "verify-fixture.sh", small_context, big_bundle, root_path,
            root_sha, profile, tmp_path / "out-round-bundle", round_artifact=True,
        )
    authority._run_verifier(
        OWNER_FIXTURES / "verify-fixture.sh", small_context, big_bundle, root_path,
        root_sha, profile, tmp_path / "out-legacy-bundle",
    )
    assert len(capture) == 2


def _source_result(profile, context_bytes, *, predicate=None):
    repo = profile["repository"]
    workflow = "https://github.com/" + repo + "/" + profile["workflow_path"] + "@" + profile["source_ref"]
    owner = repo.split("/")[0]
    cert = {
        "issuer": "https://token.actions.githubusercontent.com",
        "subjectAlternativeName": workflow,
        "buildSignerURI": workflow,
        "buildSignerDigest": profile["signer_sha"],
        "sourceRepositoryURI": "https://github.com/" + repo,
        "sourceRepositoryIdentifier": str(profile["repository_id"]),
        "sourceRepositoryOwnerURI": "https://github.com/" + owner,
        "sourceRepositoryOwnerIdentifier": str(profile["owner_id"]),
        "sourceRepositoryDigest": profile["source_sha"],
        "sourceRepositoryRef": profile["source_ref"],
        "runnerEnvironment": "github-hosted",
        "runInvocationURI": "https://github.com/" + repo + "/actions/runs/7/attempts/1",
    }
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://p11lab.org/attestations/source-admission/v1",
        "subject": [
            {"name": "source-context.json",
             "digest": {"sha256": hashlib.sha256(context_bytes).hexdigest()}}
        ],
        "predicate": {"schema_version": 1} if predicate is None else predicate,
    }
    now = datetime.now(timezone.utc)
    return [
        {
            "verificationResult": {
                "signature": {"certificate": cert},
                "verifiedTimestamps": [
                    {"type": "Tlog", "timestamp": now.isoformat().replace("+00:00", "Z")}
                ],
                "statement": statement,
            }
        }
    ]


def _source_profile():
    return {
        "repository": REPO,
        "repository_id": REPO_ID,
        "owner_id": OWNER_ID,
        "workflow_path": ".github/workflows/round.yml",
        "signer_sha": RUN_HEAD_SHA,
        "source_sha": RUN_HEAD_SHA,
        "source_ref": SOURCE_REF,
        "max_age_seconds": 86400,
    }


def test_check_verified_default_arg_identical():
    from p11lab import delivery_authority as authority

    profile = _source_profile()
    identity = {"run_id": 7, "attempt": 1}
    raw = b'{"claim":true}'
    now = datetime.now(timezone.utc)
    valid = _source_result(profile, raw)
    assert (
        authority._check_verified(valid, profile, identity, raw, now) is None
    )
    assert (
        authority._check_verified(valid, profile, identity, raw, now, predicate={"schema_version": 1})
        is None
    )
    tampered = _source_result(profile, raw, predicate={"schema_version": 2})
    with pytest.raises(ValueError, match="^verified source context subject or predicate mismatch$"):
        authority._check_verified(tampered, profile, identity, raw, now)
    with pytest.raises(ValueError, match="^verified source context subject or predicate mismatch$"):
        authority._check_verified(
            tampered, profile, identity, raw, now, predicate={"schema_version": 1}
        )


def test_token_premise_returns_pinned_record():
    profile = _round_profile()
    record = _op().check_token_exclusivity_premise(profile)
    assert record["workflow_path"] == ".github/workflows/round.yml"
    assert record["workflow_sha256"] == hashlib.sha256(b"workflow-bytes").hexdigest()
    assert record["producer_job"] == PRODUCER_JOB
    assert "review" in record["premise"]


def test_token_premise_workflow_unpinned_refused():
    profile = _round_profile(workflow_path="elsewhere.yml")
    with pytest.raises(ValueError, match="^round token premise lacks pinned workflow$"):
        _op().check_token_exclusivity_premise(profile)


def _caller_for(profile):
    return dict(
        profile,
        repository_id=profile["repository_id"],
        target_sha256=profile["target_sha256"],
        data_sources_sha256=profile["data_sources_sha256"],
        policy_sha256=profile["policy_sha256"],
        run_head_sha="d" * 40,
    )


def _graph_fetch(profile):
    table = {row["path"]: row["sha256"] for row in profile["graph"]}
    bodies = {".github/workflows/round.yml": b"workflow-bytes", "boundary.md": b"boundary-bytes"}

    def fetch(path):
        assert hashlib.sha256(bodies[path]).hexdigest() == table[path]
        return bodies[path]

    return fetch


def test_profile_with_proof_fields_accepted():
    from p11lab.round_core.artifacts import verify_producer_profile

    profile = _round_profile()
    verify_producer_profile(profile, _caller_for(profile), _graph_fetch(profile))


def test_profile_zeros_proof_fields_accepted_at_admission():
    from p11lab.round_core.artifacts import verify_producer_profile

    profile = _round_profile(root_sha256=ZEROS)
    verify_producer_profile(profile, _caller_for(profile), _graph_fetch(profile))


def test_profile_half_enrolled_refused():
    from p11lab.round_core.artifacts import verify_producer_profile

    profile = _round_profile()
    del profile["attestation_artifact_name"]
    with pytest.raises(ValueError, match="^invalid protected producer profile$"):
        verify_producer_profile(profile, _caller_for(profile), _graph_fetch(profile))


def test_profile_bad_attestation_template_refused():
    from p11lab.round_core.artifacts import verify_producer_profile

    profile = _round_profile(attestation_artifact_name="no-placeholders")
    with pytest.raises(ValueError, match="^invalid round attestation artifact profile$"):
        verify_producer_profile(profile, _caller_for(profile), _graph_fetch(profile))


def test_profile_bad_trust_root_refused():
    from p11lab.round_core.artifacts import verify_producer_profile

    profile = _round_profile(root_sha256="not-hex")
    with pytest.raises(ValueError, match="^invalid round owner proof trust root$"):
        verify_producer_profile(profile, _caller_for(profile), _graph_fetch(profile))


def test_resolve_round_attestation_wiring(monkeypatch):
    from p11lab.round_core import artifacts

    started, completed, created = _job_times()
    attempt = _attempt()
    jobs = _jobs_payload(started, completed)
    att_name = "p11lab-round-attestation-456-2"
    envelope = _envelope_bytes(b"subject", b"bundle")
    listing = {
        "total_count": 1,
        "artifacts": [_artifact_row(att_name, created, artifact_id=555, raw=envelope)],
    }
    transport = artifacts.GitHubTransport(REPO, "token")
    seen = []

    def fake_metadata(path, deadline):
        seen.append(path)
        if path.endswith("/jobs?per_page=100"):
            return jobs
        if "/artifacts?per_page=100" in path:
            return listing
        return attempt

    monkeypatch.setattr(transport, "_metadata", fake_metadata)
    monkeypatch.setattr(artifacts, "stable_metadata", lambda fetch: fetch())
    proof = transport.resolve_round_attestation(_metadata_identity(), attestation_name=att_name)
    assert proof["artifact"]["id"] == 555
    assert proof["attempt"] == attempt
    assert proof["jobs"] == jobs
    assert len(seen) == 3


def test_resolve_round_attestation_stable_reads(monkeypatch):
    from p11lab.round_core import artifacts

    started, completed, created = _job_times()
    attempt = _attempt()
    jobs = _jobs_payload(started, completed)
    att_name = "p11lab-round-attestation-456-2"
    envelope = _envelope_bytes(b"subject", b"bundle")
    listing = {
        "total_count": 1,
        "artifacts": [_artifact_row(att_name, created, artifact_id=555, raw=envelope)],
    }
    transport = artifacts.GitHubTransport(REPO, "token")
    calls = []

    def fake_metadata(path, deadline):
        calls.append(path)
        if path.endswith("/jobs?per_page=100"):
            return jobs
        if "/artifacts?per_page=100" in path:
            return listing
        return attempt

    monkeypatch.setattr(transport, "_metadata", fake_metadata)
    proof = transport.resolve_round_attestation(_metadata_identity(), attestation_name=att_name)
    assert proof["artifact"]["id"] == 555
    assert len(calls) == 9


def test_resolve_round_attestation_invalid_name_refused():
    from p11lab.round_core import artifacts

    transport = artifacts.GitHubTransport(REPO, "token")
    with pytest.raises(ValueError, match="^invalid artifact name$"):
        transport.resolve_round_attestation(_metadata_identity(), attestation_name="bad/name!")


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


def _live_policy(tmp_path, data_files):
    for name in ("policy", "profiles", "ci"):
        shutil.copytree(ROUNDS_FIXTURES / name, tmp_path / name)
    with zipfile.ZipFile(ROUNDS_FIXTURES / "fixture-dist.zip") as archive:
        lock = json.loads(archive.read("dependency-lock.json"))
    sources_path = tmp_path / "policy/sources.json"
    sources = json.loads(sources_path.read_bytes())
    sources["pins"]["corpus"]["sha256"] = inputs.digest(data_files)
    sources["pins"]["checker-build-lock"]["sha256"] = inputs.digest(
        {"roots": lock["build_roots"], "wheels": lock["build_wheels"]}
    )
    sources["pins"]["checker-runtime-lock"]["sha256"] = inputs.digest(
        {"extras": lock["runtime_extras"], "wheels": lock["runtime_wheels"]}
    )
    sources_path.write_text(json.dumps(sources))
    profile_path = tmp_path / "profiles/round-pr-smoke-v1.json"
    tier_profile = json.loads(profile_path.read_bytes())
    tier_profile["disabled_inventory"]["sha256"] = next(
        row["sha256"] for row in data_files if row["path"] == "disabled.json"
    )
    profile_path.write_text(json.dumps(tier_profile))
    from p11lab.round_core.policy import load_policy

    return tmp_path / "policy", load_policy(tmp_path / "policy", "pr-smoke").policy_digest


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
    monkeypatch.setattr(
        inputs,
        "verified_evaluator_identity",
        lambda root: {"identity_sha256": tool_identity, "receipt_sha256": "6" * 64,
                      "identity": {"fixture": True}},
    )
    monkeypatch.setattr(
        prebuilt,
        "install_prebuilt_candidate",
        lambda selection, output: {"status": "installed", "installed_manifest_sha256": "7" * 64},
    )
    return tool_identity


def _prepare_context(**overrides):
    context = json.loads((ROUNDS_FIXTURES / "valid-context.json").read_bytes())
    context.pop("artifact_path")
    context.pop("fixture_metadata_path")
    context.update(
        transport="github",
        control_sha=CONTROL_SHA,
        data_root=str(ROUNDS_FIXTURES / "input-data"),
        owner_id=OWNER_ID,
    )
    context.update(overrides)
    return context


def _prepare_profile(context, policy_digest, tool_identity, **overrides):
    profile = _round_profile(
        repository=context["repository"],
        repository_id=context["identity"]["repository_id"],
        workflow_id=context["workflow_id"],
        producer_job=context["producer_job"],
        control_sha=context["control_sha"],
        policy_sha256=policy_digest,
        target_sha256=inputs.digest(context["target"]),
        context_job="context",
    )
    profile["runtime"] = dict(profile["runtime"], tool_identity_sha256=tool_identity)
    profile.update(overrides)
    return profile


class _ProofTransport:
    def __init__(self, context, policy_digest, profile, *, variant="valid"):
        self.context = context
        self.policy_digest = policy_digest
        self.profile = profile
        self.variant = variant
        self.calls = []
        self.resolves = 0
        self.dist_bytes = (ROUNDS_FIXTURES / "fixture-dist.zip").read_bytes()
        self.metadata_row = json.loads(
            (ROUNDS_FIXTURES / "fixture-metadata.json").read_bytes()
        )["listing"]["artifacts"][0]
        self.times = _job_times()

    def source_file(self, revision, path):
        bodies = {".github/workflows/round.yml": b"workflow-bytes", "boundary.md": b"boundary-bytes"}
        return bodies[path]

    def acquire(self, identity, **kwargs):
        self.calls.append(kwargs.get("artifact_name"))
        if kwargs.get("before_download"):
            kwargs["before_download"]({"id": 1})
        if kwargs.get("artifact_name") is None:
            return self.metadata_row, self.dist_bytes
        changed = {
            key: self.context[key]
            for key in (
                "identity", "repository", "run_head_sha", "workflow_id", "producer_job",
                "control_sha", "target", "dependency_lock_sha256", "data_files", "disabled_path",
            )
        }
        changed["policy_sha256"] = self.policy_digest
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w") as archive:
            archive.writestr("context.json", inputs.canonical(changed))
        return self.metadata_row, out.getvalue()

    def _payloads(self, identity, attestation_name):
        started, completed, created = self.times
        attempt = {
            "id": identity["run_id"],
            "run_attempt": identity["attempt"],
            "head_sha": identity["run_head_sha"],
            "head_branch": "main",
            "workflow_id": identity["workflow_id"],
            "repository": {"id": identity["repository_id"]},
            "run_started_at": "2024-01-01T00:00:00Z",
        }
        dist_digest = "sha256:" + hashlib.sha256(self.dist_bytes).hexdigest()
        envelope = _envelope_bytes(_subject_bytes(dist_digest, identity["run_id"], identity["attempt"]),
                                   _bundle_bytes())
        rows = [
            {
                "id": 555,
                "name": attestation_name,
                "size_in_bytes": len(envelope),
                "digest": "sha256:" + hashlib.sha256(envelope).hexdigest(),
                "expired": False,
                "created_at": created,
                "workflow_run": {
                    "id": identity["run_id"],
                    "repository_id": identity["repository_id"],
                    "head_sha": identity["run_head_sha"],
                },
            }
        ]
        jobs = {
            "total_count": 2,
            "jobs": [
                {
                    "name": identity["producer_job"],
                    "run_id": identity["run_id"],
                    "head_sha": identity["run_head_sha"],
                    "conclusion": "success",
                    "status": "completed",
                    "started_at": started,
                    "completed_at": completed,
                },
                {
                    "name": self.profile["context_job"],
                    "run_id": identity["run_id"],
                    "head_sha": identity["run_head_sha"],
                    "conclusion": "success",
                    "status": "completed",
                    "started_at": started,
                    "completed_at": completed,
                },
            ],
        }
        if self.variant == "missing":
            rows = []
        elif self.variant == "three-jobs":
            jobs["jobs"].append(
                {
                    "name": "intruder-job",
                    "run_id": identity["run_id"],
                    "head_sha": identity["run_head_sha"],
                    "conclusion": "success",
                    "status": "completed",
                    "started_at": started,
                    "completed_at": completed,
                }
            )
            jobs["total_count"] = 3
        elif self.variant == "digest-mismatch":
            rows[0]["digest"] = "sha256:" + hashlib.sha256(b"other").hexdigest()
        listing = {"total_count": len(rows), "artifacts": rows}
        if self.variant == "flip" and self.resolves > 1:
            attempt = dict(attempt, run_started_at="2024-02-02T00:00:00Z")
        return attempt, jobs, listing, envelope

    def resolve_round_attestation(self, identity, *, attestation_name):
        from p11lab.round_core.inputs import select_run_artifact

        self.resolves += 1
        self.calls.append("attestation:" + attestation_name)
        self.last_identity = dict(identity)
        attempt, jobs, listing, _envelope = self._payloads(identity, attestation_name)
        artifact = select_run_artifact(identity, attempt, jobs, listing, name=attestation_name)
        return {"attempt": attempt, "jobs": jobs, "artifact": artifact}

    def download(self, artifact_id):
        assert artifact_id == 555
        _attempt, _jobs, _listing, envelope = self._payloads(self.last_identity, "ignored")
        return envelope


class _MinimalTransport(_ProofTransport):
    resolve_round_attestation = None  # type: ignore[assignment]
    download = None  # type: ignore[assignment]


def _install_transport(monkeypatch, fake):
    from p11lab.round_core import artifacts

    monkeypatch.setattr(artifacts, "GitHubTransport", lambda repository, token: fake)
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")


def _proof_overlay(profile, context):
    return _op().round_verifier_overlay(
        profile,
        {"run_head_sha": context["run_head_sha"]},
        {"head_sha": context["run_head_sha"], "head_branch": "main"},
    )


def _prepare_case(tmp_path, monkeypatch, *, variant="valid", proof_inputs=True, damage=None,
                  root_sha256=None):
    context = _prepare_context()
    policy_root, policy_digest = _live_policy(tmp_path, context["data_files"])
    tool_identity = _mock_evaluator_legs(monkeypatch, tmp_path)
    profile = _prepare_profile(context, policy_digest, tool_identity)
    if root_sha256 is not None:
        profile["root_sha256"] = root_sha256
    _serve(monkeypatch, [profile])
    fake = _ProofTransport(context, policy_digest, profile, variant=variant)
    _install_transport(monkeypatch, fake)
    if proof_inputs:
        root_copy = tmp_path / "proof-root.jsonl"
        root_copy.write_bytes((OWNER_FIXTURES / "trusted-root.jsonl").read_bytes())
        context["owner_proof_executable"] = str(OWNER_FIXTURES / "verify-fixture.sh")
        context["owner_proof_trusted_root"] = str(root_copy)
    _stub_round_verifier(
        monkeypatch, _proof_overlay(profile, context),
        context["identity"]["run_id"], context["identity"]["attempt"], damage=damage,
    )
    return context, policy_root, profile, fake


def test_prepare_enrolled_verifies_owner_proof(tmp_path, monkeypatch):
    context, policy_root, profile, fake = _prepare_case(tmp_path, monkeypatch)
    result = inputs.prepare(context, policy_root, tmp_path / "output")
    assert result["authority"] == "round-owner-proof-verified"
    assert result["gates"][0] == "Round owner proof verified for the producing job."
    assert result["gates"][1] == (
        "Dependency licensing, provider delivery and later execution remain unqualified."
    )
    assert result["round_positive"] is False
    proof = result["owner_proof"]
    assert proof["attestation_artifact"]["id"] == 555
    assert proof["attestation_artifact"]["name"] == "p11lab-round-attestation-456-2"
    assert proof["source_ref"] == "refs/heads/main"
    assert proof["premise"]["workflow_path"] == ".github/workflows/round.yml"
    assert fake.calls.count("attestation:p11lab-round-attestation-456-2") == 2


def test_prepare_zeros_skips_proof(tmp_path, monkeypatch):
    context = _prepare_context()
    policy_root, policy_digest = _live_policy(tmp_path, context["data_files"])
    tool_identity = _mock_evaluator_legs(monkeypatch, tmp_path)
    profile = _prepare_profile(context, policy_digest, tool_identity, root_sha256=ZEROS)
    _serve(monkeypatch, [profile])
    fake = _MinimalTransport(context, policy_digest, profile)
    _install_transport(monkeypatch, fake)
    result = inputs.prepare(context, policy_root, tmp_path / "output")
    assert result["authority"] == "protected-profile-source-verified"
    assert "owner_proof" not in result
    assert result["gates"][0] == (
        "Independent protected caller and producer contract requires owner proof."
    )


def test_prepare_enrolled_missing_verifier_inputs_refused(tmp_path, monkeypatch):
    context, policy_root, _profile, _fake = _prepare_case(tmp_path, monkeypatch, proof_inputs=False)
    with pytest.raises(ValueError, match="^round owner proof verifier inputs unavailable$"):
        inputs.prepare(context, policy_root, tmp_path / "output")
    assert not (tmp_path / "output").exists()


def test_prepare_attestation_missing_refused(tmp_path, monkeypatch):
    context, policy_root, _profile, _fake = _prepare_case(tmp_path, monkeypatch, variant="missing")
    with pytest.raises(ValueError, match="rerun_requires_producer or ambiguous artifact"):
        inputs.prepare(context, policy_root, tmp_path / "output")
    assert not (tmp_path / "output").exists()


def test_prepare_attestation_digest_mismatch_refused(tmp_path, monkeypatch):
    context, policy_root, _profile, _fake = _prepare_case(
        tmp_path, monkeypatch, variant="digest-mismatch"
    )
    with pytest.raises(ValueError, match="^artifact digest mismatch or unavailable$"):
        inputs.prepare(context, policy_root, tmp_path / "output")
    assert not (tmp_path / "output").exists()


def test_prepare_reread_mismatch_refused(tmp_path, monkeypatch):
    context, policy_root, _profile, fake = _prepare_case(tmp_path, monkeypatch, variant="flip")
    with pytest.raises(ValueError, match="^round producer metadata changed during verification$"):
        inputs.prepare(context, policy_root, tmp_path / "output")
    assert not (tmp_path / "output").exists()
    assert fake.resolves == 2


def test_prepare_wrong_job_bundle_refused(tmp_path, monkeypatch):
    context, policy_root, _profile, _fake = _prepare_case(tmp_path, monkeypatch, damage="predicate-job")
    with pytest.raises(ValueError, match="^verified source context subject or predicate mismatch$"):
        inputs.prepare(context, policy_root, tmp_path / "output")
    assert not (tmp_path / "output").exists()


def test_prepare_three_job_roster_refused(tmp_path, monkeypatch):
    context, policy_root, _profile, _fake = _prepare_case(tmp_path, monkeypatch, variant="three-jobs")
    with pytest.raises(ValueError, match="^round job roster mismatch$"):
        inputs.prepare(context, policy_root, tmp_path / "output")
    assert not (tmp_path / "output").exists()
