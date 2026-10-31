"""Authenticated source-transport evidence + gate integration (B-G2a).

Hermetic only: fixture verifier + monkeypatched GH pin + stubbed
bounded_stream per tests/test_source_authority.py:415-448. Profile dicts
are built in-test; the installed catalog is never read (load_profile is
doubled at the test seam). No network, no Docker, no GitHub API.
"""
import copy
import hashlib
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from p11lab import publish

FIXTURES = Path(__file__).parent / "fixtures" / "acquisition"

R4 = "authenticated source transport evidence unavailable; acquisition blocked"
R7_FALLBACK = "authenticated source transport verification failed: bundle digest mismatch"
R8 = "attested source facts differ from the handoff digests; acquisition blocked"
R9 = "full image validation/promotion integration unavailable; acquisition blocked"

EXE_MISMATCH = "verifier executable digest mismatch"
ROOT_MISMATCH = "protected trusted root digest mismatch"
CERT_MISMATCH = "verified certificate identity mismatch"
SUBJECT_MISMATCH = "verified source context subject or predicate mismatch"
TIME_MISMATCH = "verified timestamp outside accepted window"
AMBIGUOUS = "ambiguous verified attestations"

MISSING_TIMESTAMPS = "missing verified timestamps"
CLOCK_NAIVE = "verification clock requires timezone"
BAD_TS_TYPE = "invalid verified timestamp type"
MALFORMED = "malformed verified attestation"
UNSAFE_INPUT = "unsafe or oversized verifier input"
CHANGED_INPUT = "verifier input changed or exceeded limit"
TRUNCATED_JSON = "Expecting value: line 1 column 1 (char 0)"


def v2_handoff():
    registry = "ghcr.io/p11lab/softhsm2"
    return dict(
        schema_version=2,
        registry=registry,
        catalogue=dict(environment="softhsm2", channel="release", runtime_role="runtime"),
        source=dict(
            reference=registry + "@sha256:" + "a" * 64,
            manifest_sha256="a" * 64,
            file_sha256="b" * 64,
            tag="src",
            content_companion=dict(
                reference=registry + "@sha256:" + "e" * 64,
                manifest_sha256="e" * 64,
                file_sha256="1" * 64,
                receipt_sha256="2" * 64,
                spdx_sha256="3" * 64,
                readback_proof_sha256="4" * 64,
            ),
        ),
        binary=dict(
            kind="docker-local",
            reference=registry + "@sha256:" + "c" * 64,
            manifest_sha256="c" * 64,
            engine_id="sha256:" + "d" * 64,
            tag="rt",
        ),
        admission=dict(status="eligible", blockers=[], content_status="eligible",
                       source_readback_status="verified"),
        readback={},
        producer={},
        exposure={},
    )


def fixture_profile():
    """In-test profile dict; controller/policy digests are the real installed ones."""
    from p11lab import delivery_authority as authority
    from importlib.resources import files
    root_bytes = (FIXTURES / "trusted-root.jsonl").read_bytes()
    policy_bytes = files("p11lab").joinpath("data/ci/delivery/validation-policy.json").read_bytes()
    return dict(
        repository="p11lab/controller",
        repository_id=1234,
        owner_id=5678,
        workflow_path=".github/workflows/provider-delivery.yml",
        workflow_id=123,
        signer_sha="a" * 40,
        source_sha="b" * 40,
        source_ref="refs/heads/main",
        job="trusted-producer",
        policy_sha256=hashlib.sha256(policy_bytes).hexdigest(),
        review_sha256="d" * 64,
        role="source-producer",
        root_sha256=hashlib.sha256(root_bytes).hexdigest(),
        controller_sha256=authority._controller_digest(Path(authority.__file__).parent),
        environment_id=77,
        reviewer_ids=[101, 102],
        max_age_seconds=3600,
    )


def fixture_context(profile, handoff):
    """Attestation context bytes binding handoff digests + profile pins.

    Nested producer shape (delivery_authority._source_facts): payload
    source.sealed/content. Sealed-receipt/inventory sentinels stay
    distinct from the handoff proof digest (anti-alias); the gate must
    never compare them (the proof is unauthenticated at this stage).
    """
    from p11lab import delivery_authority as authority
    value = json.loads((FIXTURES / "attestation-context.json").read_text())
    value["policy_sha256"] = profile["policy_sha256"]
    value["review_sha256"] = profile["review_sha256"]
    value["controller_sha256"] = profile["controller_sha256"]
    value["profile_sha256"] = authority._profile_digest(profile)
    source = handoff["source"]
    companion = source["content_companion"]
    value["payload"] = {
        "source": {
            "sealed": {
                "reference": source["reference"],
                "manifest_sha256": source["manifest_sha256"],
                "archive_sha256": source["file_sha256"],
                "receipt_sha256": "5" * 64,
            },
            "content": {
                "reference": companion["reference"],
                "manifest_sha256": companion["manifest_sha256"],
                "file_sha256": companion["file_sha256"],
                "receipt_sha256": companion["receipt_sha256"],
                "spdx_sha256": companion["spdx_sha256"],
                "inventory_sha256": "6" * 64,
            },
        },
    }
    return value


def make_evidence(tmp_path, *, context=None, bundle=None, root=None, journal=None,
                  manifest_extra=None, name="evidence"):
    directory = tmp_path / name
    directory.mkdir()
    (directory / "attestation-context.json").write_text(
        json.dumps(context if context is not None
                   else json.loads((FIXTURES / "attestation-context.json").read_text()),
                   sort_keys=True) + "\n")
    (directory / "bundle.json").write_bytes(
        bundle if bundle is not None else (FIXTURES / "bundle.json").read_bytes())
    (directory / "trusted-root.jsonl").write_bytes(
        root if root is not None else (FIXTURES / "trusted-root.jsonl").read_bytes())
    if journal is not None:
        (directory / "transport-journal.json").write_bytes(journal)
    manifest = {"schema_version": 1}
    if manifest_extra:
        manifest.update(manifest_extra)
    (directory / "evidence-manifest.json").write_text(json.dumps(manifest, sort_keys=True) + "\n")
    return directory


def stub_verifier(monkeypatch, profile, *, damage=None):
    """Monkeypatched GH pin + stubbed bounded_stream (dynamic verified.json)."""
    from p11lab import delivery_authority as authority
    from p11lab import inspection_bounded
    exe = FIXTURES / "verifier" / "verify-fixture.sh"
    monkeypatch.setattr(authority, "GH_EXECUTABLE_SHA256",
                        hashlib.sha256(exe.read_bytes()).hexdigest())
    monkeypatch.setattr(authority, "load_profile",
                        lambda environment, channel: profile)

    def run(argv, destination, max_bytes, timeout, env, record):
        subject_bytes = Path(argv[3]).read_bytes()
        bundle_arg = Path(argv[argv.index("--bundle") + 1])
        record["observed_bundle_path"] = str(bundle_arg)
        record["observed_bundle_sha256"] = hashlib.sha256(
            bundle_arg.read_bytes()).hexdigest()
        now = datetime.now(timezone.utc)
        ctx = json.loads(subject_bytes)
        run = ctx.get("run", {"run_id": 891, "attempt": 1})
        workflow = ("https://github.com/" + profile["repository"] + "/"
                    + profile["workflow_path"] + "@" + profile["source_ref"])
        owner = profile["repository"].split("/")[0]
        cert = {
            "issuer": "https://token.actions.githubusercontent.com",
            "subjectAlternativeName": workflow,
            "buildSignerURI": workflow,
            "buildSignerDigest": profile["signer_sha"],
            "sourceRepositoryURI": "https://github.com/" + profile["repository"],
            "sourceRepositoryIdentifier": str(profile["repository_id"]),
            "sourceRepositoryOwnerURI": "https://github.com/" + owner,
            "sourceRepositoryOwnerIdentifier": str(profile["owner_id"]),
            "sourceRepositoryDigest": profile["source_sha"],
            "sourceRepositoryRef": profile["source_ref"],
            "runnerEnvironment": "github-hosted",
            "runInvocationURI": ("https://github.com/" + profile["repository"]
                                 + "/actions/runs/" + str(run["run_id"])
                                 + "/attempts/" + str(run["attempt"])),
        }
        statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": authority.PREDICATE_TYPE,
            "subject": [{"name": "source-context.json",
                         "digest": {"sha256": hashlib.sha256(subject_bytes).hexdigest()}}],
            "predicate": {"schema_version": 1},
        }
        result = [{"verificationResult": {
            "signature": {"certificate": cert},
            "verifiedTimestamps": [{"type": "Tlog",
                                    "timestamp": now.isoformat().replace("+00:00", "Z")}],
            "statement": statement}}]
        if damage == "cert":
            result[0]["verificationResult"]["signature"]["certificate"]["issuer"] += "-forged"
        elif damage == "subject":
            result[0]["verificationResult"]["statement"]["subject"][0]["digest"]["sha256"] = "f" * 64
        elif damage == "predicate":
            result[0]["verificationResult"]["statement"]["predicateType"] += "/lookalike"
        elif damage == "timestamp":
            result[0]["verificationResult"]["verifiedTimestamps"][0]["timestamp"] = "2020-01-01T00:00:00Z"
        elif damage == "ambiguous":
            result.append(copy.deepcopy(result[0]))
        elif damage == "empty-timestamps":
            result[0]["verificationResult"]["verifiedTimestamps"] = []
        elif damage == "invalid-json":
            destination.write_text("truncated{")
            record["returncode"] = 0
            return
        elif damage == "invalid-ts-type":
            result[0]["verificationResult"]["verifiedTimestamps"] = [
                {"type": "Bogus",
                 "timestamp": now.isoformat().replace("+00:00", "Z")}]
        elif damage == "malformed-result":
            destination.write_text(json.dumps([{"verificationResult": {}}]))
            record["returncode"] = 0
            return
        elif damage == "oversized-verified":
            destination.write_bytes(b"[" + b"y" * (16 * 1024 * 1024) + b"]")
            record["returncode"] = 0
            return
        destination.write_text(json.dumps(result))
        record["returncode"] = 0

    monkeypatch.setattr(inspection_bounded, "bounded_stream", run)


def valid_call_args(tmp_path, monkeypatch, handoff=None, *, damage=None, journal=False):
    profile = fixture_profile()
    value = handoff if handoff is not None else v2_handoff()
    context = fixture_context(profile, value)
    journal_bytes = ((FIXTURES / "transport-journal.json").read_bytes() if journal else None)
    evidence = make_evidence(tmp_path, context=context, journal=journal_bytes)
    stub_verifier(monkeypatch, profile, damage=damage)
    return dict(value=value, evidence_dir=evidence,
                executable=FIXTURES / "verifier" / "verify-fixture.sh",
                trusted_root=evidence / "trusted-root.jsonl",
                output_dir=tmp_path / "verify-out")


def test_r1_schema_first_v1_with_evidence_still_requires_schema2(tmp_path, monkeypatch):
    args = valid_call_args(tmp_path, monkeypatch)
    args["value"] = dict(v2_handoff(), schema_version=1)
    with pytest.raises(publish.PublishError, match="public acquisition requires handoff schema2"):
        publish.require_eligible_handoff(**args)


def test_r2_admission_before_evidence(tmp_path, monkeypatch):
    args = valid_call_args(tmp_path, monkeypatch)
    args["value"]["admission"] = dict(status="blocked", blockers=["x"],
                                      content_status="eligible",
                                      source_readback_status="verified")
    with pytest.raises(publish.PublishError, match="handoff admission is not eligible"):
        publish.require_eligible_handoff(**args)


def test_r3_readback_before_evidence(tmp_path, monkeypatch):
    args = valid_call_args(tmp_path, monkeypatch)
    args["value"]["admission"] = dict(status="eligible", blockers=[],
                                      content_status="eligible",
                                      source_readback_status="missing")
    with pytest.raises(publish.PublishError,
                       match="handoff requires complete source/content readback admission"):
        publish.require_eligible_handoff(**args)


@pytest.mark.parametrize("shape", ["one-arg", "all-none", "partial-dir-only",
                                   "partial-missing-output", "str-paths"])
def test_r4_missing_evidence_is_refused(tmp_path, monkeypatch, shape):
    value = v2_handoff()
    if shape == "one-arg":
        with pytest.raises(publish.PublishError) as info:
            publish.require_eligible_handoff(value)
    elif shape == "all-none":
        with pytest.raises(publish.PublishError) as info:
            publish.require_eligible_handoff(value, None, executable=None,
                                             trusted_root=None, output_dir=None)
    elif shape == "partial-dir-only":
        evidence = make_evidence(tmp_path, context=fixture_context(fixture_profile(), value))
        with pytest.raises(publish.PublishError) as info:
            publish.require_eligible_handoff(value, evidence, executable=None,
                                             trusted_root=None, output_dir=None)
    elif shape == "partial-missing-output":
        profile = fixture_profile()
        evidence = make_evidence(tmp_path, context=fixture_context(profile, value))
        stub_verifier(monkeypatch, profile)
        with pytest.raises(publish.PublishError) as info:
            publish.require_eligible_handoff(
                value, evidence, executable=FIXTURES / "verifier" / "verify-fixture.sh",
                trusted_root=evidence / "trusted-root.jsonl", output_dir=None)
    else:
        evidence = make_evidence(tmp_path, context=fixture_context(fixture_profile(), value))
        with pytest.raises(publish.PublishError) as info:
            publish.require_eligible_handoff(
                value, str(evidence), executable=str(FIXTURES / "verifier" / "verify-fixture.sh"),
                trusted_root=str(evidence / "trusted-root.jsonl"),
                output_dir=str(tmp_path / "verify-out"))
    assert str(info.value) == R4


def test_r5_caller_booleans_are_inert_with_del_parity(tmp_path):
    plain = v2_handoff()
    with pytest.raises(publish.PublishError) as first:
        publish.require_eligible_handoff(plain)
    assert str(first.value) == R4
    flagged = v2_handoff()
    flagged["admission"].update(anonymous_source_available=True, image_promotable=True)
    flagged["approved"] = True
    with pytest.raises(publish.PublishError) as second:
        publish.require_eligible_handoff(flagged)
    assert str(second.value) == str(first.value) == R4
    del flagged["admission"]["anonymous_source_available"]
    del flagged["admission"]["image_promotable"]
    del flagged["approved"]
    with pytest.raises(publish.PublishError) as third:
        publish.require_eligible_handoff(flagged)
    assert str(third.value) == str(first.value) == R4


def test_r6_transcript_only_is_refused_and_journal_is_supplementary(tmp_path, monkeypatch):
    value = v2_handoff()
    journal_only = tmp_path / "journal-only"
    journal_only.mkdir()
    (journal_only / "transport-journal.json").write_bytes(
        (FIXTURES / "transport-journal.json").read_bytes())
    (journal_only / "evidence-manifest.json").write_text('{"schema_version": 1}\n')
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(
            value, journal_only, executable=FIXTURES / "verifier" / "verify-fixture.sh",
            trusted_root=FIXTURES / "trusted-root.jsonl",
            output_dir=tmp_path / "verify-out")
    assert str(info.value) == R4
    args = valid_call_args(tmp_path, monkeypatch, journal=True)
    with pytest.raises(publish.PublishError) as supplemented:
        publish.require_eligible_handoff(**args)
    assert str(supplemented.value) == R9


@pytest.mark.parametrize("damage,expected", [
    ("exe", EXE_MISMATCH),
    ("root", ROOT_MISMATCH),
])
def test_r7_wrong_verifier_inputs_are_refused(tmp_path, monkeypatch, damage, expected):
    """R7 input-efficacy: real verifier bytes drive these two refusals."""
    profile = fixture_profile()
    value = v2_handoff()
    context = fixture_context(profile, value)
    if damage == "exe":
        evidence = make_evidence(tmp_path, context=context)
        stub_verifier(monkeypatch, profile)
        wrong = tmp_path / "wrong-gh"
        wrong.write_bytes(b"not the fixture verifier")
        # G-F6: the entry guard requires an exec bit; this row pins wrong
        # BYTES (not the mode), so grant exec and keep asserting EXE_MISMATCH.
        wrong.chmod(0o755)
        with pytest.raises(publish.PublishError) as info:
            publish.require_eligible_handoff(
                value, evidence, executable=wrong,
                trusted_root=evidence / "trusted-root.jsonl",
                output_dir=tmp_path / "verify-out")
    else:
        evidence = make_evidence(tmp_path, context=context, root=b"forged root bytes")
        stub_verifier(monkeypatch, profile)
        with pytest.raises(publish.PublishError) as info:
            publish.require_eligible_handoff(
                value, evidence, executable=FIXTURES / "verifier" / "verify-fixture.sh",
                trusted_root=evidence / "trusted-root.jsonl",
                output_dir=tmp_path / "verify-out")
    assert str(info.value) == expected


@pytest.mark.parametrize("damage,expected", [
    ("cert", CERT_MISMATCH),
    ("subject", SUBJECT_MISMATCH),
    ("predicate", SUBJECT_MISMATCH),
    ("timestamp", TIME_MISMATCH),
    ("ambiguous", AMBIGUOUS),
    ("empty-timestamps", MISSING_TIMESTAMPS),
    ("invalid-json", TRUNCATED_JSON),
    ("invalid-ts-type", BAD_TS_TYPE),
    ("malformed-result", MALFORMED),
    ("oversized-verified", UNSAFE_INPUT),
])
def test_r7_verifier_policy_mapping_is_refused(tmp_path, monkeypatch, damage, expected):
    """Stub-selected policy mapping, not tamper-efficacy.

    The honest bundle proves the refusal is selected by `damage` alone;
    the stub observes bundle bytes without enforcing them (see the
    input-bound oracle pair). Bundle tamper-efficacy belongs to the
    real verifier; duplicating its crypto here is out of scope.
    """
    profile = fixture_profile()
    value = v2_handoff()
    context = fixture_context(profile, value)
    evidence = make_evidence(tmp_path, context=context)
    stub_verifier(monkeypatch, profile, damage=damage)
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(
            value, evidence, executable=FIXTURES / "verifier" / "verify-fixture.sh",
            trusted_root=evidence / "trusted-root.jsonl",
            output_dir=tmp_path / "verify-out")
    assert str(info.value) == expected


@pytest.mark.parametrize("text", [CLOCK_NAIVE, CHANGED_INPUT])
def test_gf7_t3_wrap_reuses_gate_unreachable_texts(text):
    """G-F7 T3: the two deterministic texts no gate damage can produce.

    CLOCK_NAIVE cannot fire here (acquisition always passes a tz-aware
    now); CHANGED_INPUT needs a TOCTOU growth race between size check
    and read. Both are pinned at the wrap — the exact T3 mechanism.
    """
    from p11lab import acquisition
    assert str(acquisition._wrap_verifier_error(ValueError(text))) == text


@pytest.mark.parametrize("direction", ["handoff-swapped", "bundle-swapped"])
def test_r8_binding_mismatch_is_refused(tmp_path, monkeypatch, direction):
    profile = fixture_profile()
    first, second = v2_handoff(), v2_handoff()
    second["source"]["manifest_sha256"] = "f" * 64
    second["source"]["reference"] = second["registry"] + "@sha256:" + "f" * 64
    second["source"]["content_companion"]["manifest_sha256"] = "f" * 64
    second["source"]["content_companion"]["reference"] = second["registry"] + "@sha256:" + "f" * 64
    if direction == "handoff-swapped":
        value, bound = second, first
    else:
        value, bound = first, second
    context = fixture_context(profile, bound)
    evidence = make_evidence(tmp_path, context=context)
    stub_verifier(monkeypatch, profile)
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(
            value, evidence, executable=FIXTURES / "verifier" / "verify-fixture.sh",
            trusted_root=evidence / "trusted-root.jsonl",
            output_dir=tmp_path / "verify-out")
    assert str(info.value) == R8


def test_r9_transport_pass_still_refuses_promotion(tmp_path, monkeypatch):
    args = valid_call_args(tmp_path, monkeypatch)
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(**args)
    assert str(info.value) == R9
    assert "authenticated source transport" not in str(info.value)


def test_evidence_manifest_decoys_never_supply_expected_digests(tmp_path, monkeypatch):
    args = valid_call_args(tmp_path, monkeypatch)
    manifest = args["evidence_dir"] / "evidence-manifest.json"
    manifest.write_text(json.dumps({"schema_version": 1, "source": {"manifest_sha256": "f" * 64},
                                    "content_companion": {"manifest_sha256": "f" * 64}}) + "\n")
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(**args)
    assert str(info.value) == R9


@pytest.mark.parametrize("bad", ["missing-manifest", "bad-version", "bad-version-true",
                                   "bad-version-float", "extra-member"])
def test_evidence_shape_failures_are_unavailable(tmp_path, monkeypatch, bad):
    profile = fixture_profile()
    value = v2_handoff()
    evidence = make_evidence(tmp_path, context=fixture_context(profile, value))
    stub_verifier(monkeypatch, profile)
    if bad == "missing-manifest":
        (evidence / "evidence-manifest.json").unlink()
    elif bad == "bad-version":
        (evidence / "evidence-manifest.json").write_text('{"schema_version": 99}\n')
    elif bad == "bad-version-true":
        (evidence / "evidence-manifest.json").write_text(json.dumps({"schema_version": True}) + "\n")
    elif bad == "bad-version-float":
        (evidence / "evidence-manifest.json").write_text(json.dumps({"schema_version": 1.0}) + "\n")
    else:
        (evidence / "caller-claim.json").write_text('{"approved": true}\n')
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(
            value, evidence, executable=FIXTURES / "verifier" / "verify-fixture.sh",
            trusted_root=evidence / "trusted-root.jsonl",
            output_dir=tmp_path / "verify-out")
    assert str(info.value) == R4


def test_r11_offline_token_independence(tmp_path, monkeypatch):
    import socket
    value = v2_handoff()
    with pytest.raises(publish.PublishError) as plain_r4:
        publish.require_eligible_handoff(value)
    args = valid_call_args(tmp_path, monkeypatch)
    with pytest.raises(publish.PublishError) as plain_r9:
        publish.require_eligible_handoff(**args)
    assert str(plain_r4.value) == R4
    assert str(plain_r9.value) == R9

    def forbidden(*items, **kwargs):
        raise AssertionError("acquisition path used a socket")

    monkeypatch.setenv("GH_TOKEN", "garbage-token-must-be-ignored")
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    with pytest.raises(publish.PublishError) as offline_r4:
        publish.require_eligible_handoff(v2_handoff())
    tmp_second = tmp_path / "second"
    tmp_second.mkdir()
    profile2 = fixture_profile()
    context2 = fixture_context(profile2, v2_handoff())
    evidence2 = make_evidence(tmp_second, context=context2, name="evidence2")
    stub_verifier(monkeypatch, profile2)
    with pytest.raises(publish.PublishError) as offline_r9:
        publish.require_eligible_handoff(
            v2_handoff(), evidence2, executable=FIXTURES / "verifier" / "verify-fixture.sh",
            trusted_root=evidence2 / "trusted-root.jsonl",
            output_dir=tmp_second / "verify-out2")
    assert str(offline_r4.value) == str(plain_r4.value) == R4
    assert str(offline_r9.value) == str(plain_r9.value) == R9


@pytest.mark.parametrize("version", [2, 99, True, 1.0, "missing"])
def test_t1_context_schema_version_is_refused(tmp_path, monkeypatch, version):
    """G-F1 T1: attested context must carry schema_version int 1 (R7 fallback else)."""
    profile = fixture_profile()
    value = v2_handoff()
    context = fixture_context(profile, value)
    assert context["schema_version"] == 1
    if version == "missing":
        del context["schema_version"]
    else:
        context["schema_version"] = version
    evidence = make_evidence(tmp_path, context=context)
    stub_verifier(monkeypatch, profile)
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(
            value, evidence, executable=FIXTURES / "verifier" / "verify-fixture.sh",
            trusted_root=evidence / "trusted-root.jsonl",
            output_dir=tmp_path / "verify-out")
    assert str(info.value) == R7_FALLBACK


@pytest.mark.parametrize("field", ["role", "policy_sha256", "review_sha256",
                                   "controller_sha256", "profile_sha256"])
def test_b1_profile_binding_mismatch_is_refused(tmp_path, monkeypatch, field):
    """G-F1 B1: each wrong binding field refuses with the exact R7 fallback text."""
    from p11lab import delivery_authority as authority
    profile = fixture_profile()
    value = v2_handoff()
    context = fixture_context(profile, value)
    if field == "role":
        context[field] = "forged-role"
    else:
        valid = context[field]
        context[field] = ("0" if not valid.startswith("0") else "1") + valid[1:]
        assert context[field] != valid
    if field == "profile_sha256":
        assert context[field] != authority._profile_digest(profile)
    evidence = make_evidence(tmp_path, context=context)
    stub_verifier(monkeypatch, profile)
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(
            value, evidence, executable=FIXTURES / "verifier" / "verify-fixture.sh",
            trusted_root=evidence / "trusted-root.jsonl",
            output_dir=tmp_path / "verify-out")
    assert str(info.value) == R7_FALLBACK


def test_b1_profile_binding_valid_control(tmp_path, monkeypatch):
    """G-F1 B1 control: all five fields bound passes the raise, reaches R9."""
    from p11lab import delivery_authority as authority
    profile = fixture_profile()
    value = v2_handoff()
    context = fixture_context(profile, value)
    assert context["role"] == profile["role"]
    assert context["policy_sha256"] == profile["policy_sha256"]
    assert context["review_sha256"] == profile["review_sha256"]
    assert context["controller_sha256"] == profile["controller_sha256"]
    assert context["profile_sha256"] == authority._profile_digest(profile)
    evidence = make_evidence(tmp_path, context=context)
    stub_verifier(monkeypatch, profile)
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(
            value, evidence, executable=FIXTURES / "verifier" / "verify-fixture.sh",
            trusted_root=evidence / "trusted-root.jsonl",
            output_dir=tmp_path / "verify-out")
    assert str(info.value) == R9


def _refuse_verifier(monkeypatch):
    """Fail the test if the shared verifier is invoked at all."""
    from p11lab import delivery_authority as authority

    def fail_if_called(*args, **kwargs):
        raise AssertionError("verifier must not run for this refusal")

    monkeypatch.setattr(authority, "_run_verifier", fail_if_called)


@pytest.mark.parametrize("spelling", ["independent", "relative"])
def test_q1_matching_supplied_root_reaches_verifier(tmp_path, monkeypatch, spelling):
    """Q1 row 1: byte-identical supplied root passes; the SUPPLIED path runs.

    Path spelling is not identity: an independent or relative Path with
    the correct bytes is valid, and the spy proves that path (not the
    package member) reaches _run_verifier.
    """
    from p11lab import delivery_authority as authority
    profile = fixture_profile()
    value = v2_handoff()
    evidence = make_evidence(tmp_path, context=fixture_context(profile, value))
    stub_verifier(monkeypatch, profile)
    member_bytes = (evidence / "trusted-root.jsonl").read_bytes()
    if spelling == "independent":
        supplied = tmp_path / "runtime-root.jsonl"
        supplied.write_bytes(member_bytes)
    else:
        monkeypatch.chdir(tmp_path)
        supplied = Path("runtime-root.jsonl")
        supplied.write_bytes(member_bytes)
    seen = {}
    real_run_verifier = authority._run_verifier

    def spy(executable, context_path, bundle_path, root_path, *args, **kwargs):
        seen["root_path"] = root_path
        return real_run_verifier(executable, context_path, bundle_path, root_path,
                                 *args, **kwargs)

    monkeypatch.setattr(authority, "_run_verifier", spy)
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(
            value, evidence, executable=FIXTURES / "verifier" / "verify-fixture.sh",
            trusted_root=supplied, output_dir=tmp_path / "verify-out")
    assert str(info.value) == R9
    assert seen["root_path"] == supplied


@pytest.mark.parametrize("variant", ["none", "str", "missing", "wrong-case", "dir",
                                     "symlink", "nlink"])
def test_q1_unusable_supplied_roots_are_refused_without_verifier(tmp_path, monkeypatch,
                                                                 variant):
    """Q1 row 2: unusable supplied roots refuse R4 before any verification."""
    profile = fixture_profile()
    value = v2_handoff()
    evidence = make_evidence(tmp_path, context=fixture_context(profile, value))
    stub_verifier(monkeypatch, profile)
    _refuse_verifier(monkeypatch)
    if variant == "none":
        supplied = None
    elif variant == "str":
        supplied = str(evidence / "trusted-root.jsonl")
    elif variant == "missing":
        supplied = tmp_path / "no-such-root.jsonl"
    elif variant == "wrong-case":
        supplied = evidence / "Trusted-Root.jsonl"
    elif variant == "dir":
        supplied = tmp_path / "root-dir"
        supplied.mkdir()
    elif variant == "symlink":
        supplied = tmp_path / "root-link.jsonl"
        supplied.symlink_to(evidence / "trusted-root.jsonl")
    else:
        supplied = tmp_path / "linked-root.jsonl"
        supplied.write_bytes((evidence / "trusted-root.jsonl").read_bytes())
        os.link(supplied, tmp_path / "linked-root-alias.jsonl")
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(
            value, evidence, executable=FIXTURES / "verifier" / "verify-fixture.sh",
            trusted_root=supplied, output_dir=tmp_path / "verify-out")
    assert str(info.value) == R4


def test_q1_unrelated_supplied_root_is_root_mismatch_without_verifier(tmp_path, monkeypatch):
    """Q1 row 3: unrelated supplied bytes refuse with the exact R7 root text."""
    profile = fixture_profile()
    value = v2_handoff()
    evidence = make_evidence(tmp_path, context=fixture_context(profile, value))
    stub_verifier(monkeypatch, profile)
    _refuse_verifier(monkeypatch)
    supplied = tmp_path / "unrelated-root.jsonl"
    supplied.write_bytes(b"unrelated root bytes\n")
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(
            value, evidence, executable=FIXTURES / "verifier" / "verify-fixture.sh",
            trusted_root=supplied, output_dir=tmp_path / "verify-out")
    assert str(info.value) == ROOT_MISMATCH


def test_q1_mismatched_member_is_root_mismatch_without_verifier(tmp_path, monkeypatch):
    """Q1 row 4: a differing package member refuses before any verification."""
    profile = fixture_profile()
    value = v2_handoff()
    evidence = make_evidence(tmp_path, context=fixture_context(profile, value),
                             root=b"other valid-looking root bytes\n")
    stub_verifier(monkeypatch, profile)
    _refuse_verifier(monkeypatch)
    supplied = tmp_path / "runtime-root.jsonl"
    supplied.write_bytes((FIXTURES / "trusted-root.jsonl").read_bytes())
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(
            value, evidence, executable=FIXTURES / "verifier" / "verify-fixture.sh",
            trusted_root=supplied, output_dir=tmp_path / "verify-out")
    assert str(info.value) == ROOT_MISMATCH


def test_q1_matching_unrelated_roots_reach_profile_pin_check(tmp_path, monkeypatch):
    """Q1 row 5: equal-but-unpinned bytes fail the shared profile-pin check.

    The byte cross-check passes, so the SUPPLIED path still reaches
    _run_verifier, whose profile digest pin raises the exact R7 root
    text before any subprocess starts.
    """
    from p11lab import delivery_authority as authority
    from p11lab import inspection_bounded
    profile = fixture_profile()
    value = v2_handoff()
    unrelated = b"unrelated but matching root bytes\n"
    evidence = make_evidence(tmp_path, context=fixture_context(profile, value),
                             root=unrelated)
    stub_verifier(monkeypatch, profile)
    supplied = tmp_path / "runtime-root.jsonl"
    supplied.write_bytes(unrelated)
    seen = {}
    real_run_verifier = authority._run_verifier

    def spy(executable, context_path, bundle_path, root_path, *args, **kwargs):
        seen["root_path"] = root_path
        return real_run_verifier(executable, context_path, bundle_path, root_path,
                                 *args, **kwargs)

    monkeypatch.setattr(authority, "_run_verifier", spy)
    calls = []
    real_stream = inspection_bounded.bounded_stream

    def stream_spy(*args, **kwargs):
        calls.append(args)
        return real_stream(*args, **kwargs)

    monkeypatch.setattr(inspection_bounded, "bounded_stream", stream_spy)
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(
            value, evidence, executable=FIXTURES / "verifier" / "verify-fixture.sh",
            trusted_root=supplied, output_dir=tmp_path / "verify-out")
    assert str(info.value) == ROOT_MISMATCH
    assert seen["root_path"] == supplied
    assert calls == []


@pytest.mark.parametrize("member", ["missing", "symlink", "dir"])
def test_q1_missing_or_unsafe_member_is_unavailable(tmp_path, monkeypatch, member):
    """Q1 row 6: a valid supplied root cannot rescue a missing/unsafe member."""
    profile = fixture_profile()
    value = v2_handoff()
    evidence = make_evidence(tmp_path, context=fixture_context(profile, value))
    stub_verifier(monkeypatch, profile)
    _refuse_verifier(monkeypatch)
    packaged = evidence / "trusted-root.jsonl"
    if member == "missing":
        packaged.unlink()
    elif member == "symlink":
        valid = packaged.read_bytes()
        packaged.unlink()
        packaged.symlink_to(FIXTURES / "trusted-root.jsonl")
        assert packaged.read_bytes() == valid
    else:
        packaged.unlink()
        packaged.mkdir()
    supplied = tmp_path / "runtime-root.jsonl"
    supplied.write_bytes((FIXTURES / "trusted-root.jsonl").read_bytes())
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(
            value, evidence, executable=FIXTURES / "verifier" / "verify-fixture.sh",
            trusted_root=supplied, output_dir=tmp_path / "verify-out")
    assert str(info.value) == R4


def test_manifest_fifo_is_refused_without_hanging(tmp_path, monkeypatch):
    """#2: a FIFO manifest refuses R4 fast (no writer; never opened for read)."""
    if not hasattr(os, "mkfifo"):
        pytest.skip("no FIFO support")
    profile = fixture_profile()
    value = v2_handoff()
    evidence = make_evidence(tmp_path, context=fixture_context(profile, value))
    stub_verifier(monkeypatch, profile)
    (evidence / "evidence-manifest.json").unlink()
    os.mkfifo(evidence / "evidence-manifest.json")
    start = time.monotonic()
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(
            value, evidence, executable=FIXTURES / "verifier" / "verify-fixture.sh",
            trusted_root=evidence / "trusted-root.jsonl",
            output_dir=tmp_path / "verify-out")
    assert str(info.value) == R4
    assert time.monotonic() - start < 30


@pytest.mark.parametrize("target", [
    pytest.param("fifo", marks=pytest.mark.skipif(not hasattr(os, "mkfifo"),
                                                 reason="no FIFO support")),
    "file",
])
def test_manifest_symlink_is_refused_without_following(tmp_path, monkeypatch, target):
    """#2: a symlink manifest refuses R4 via lstat, never by reading through."""
    profile = fixture_profile()
    value = v2_handoff()
    evidence = make_evidence(tmp_path, context=fixture_context(profile, value))
    stub_verifier(monkeypatch, profile)
    pointed = tmp_path / "manifest-target"
    if target == "fifo":
        os.mkfifo(pointed)
    else:
        pointed.write_text('{"schema_version": 1}\n')
    (evidence / "evidence-manifest.json").unlink()
    (evidence / "evidence-manifest.json").symlink_to(pointed)
    start = time.monotonic()
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(
            value, evidence, executable=FIXTURES / "verifier" / "verify-fixture.sh",
            trusted_root=evidence / "trusted-root.jsonl",
            output_dir=tmp_path / "verify-out")
    assert str(info.value) == R4
    assert time.monotonic() - start < 30


def test_oversized_manifest_is_refused(tmp_path, monkeypatch):
    """#2: a schema-valid manifest over 1MiB refuses R4 (bounded read)."""
    profile = fixture_profile()
    value = v2_handoff()
    evidence = make_evidence(tmp_path, context=fixture_context(profile, value))
    stub_verifier(monkeypatch, profile)
    manifest = evidence / "evidence-manifest.json"
    manifest.write_text(json.dumps({"schema_version": 1, "pad": "x" * 1024 * 1024}))
    assert manifest.stat().st_size > 1024 * 1024
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(
            value, evidence, executable=FIXTURES / "verifier" / "verify-fixture.sh",
            trusted_root=evidence / "trusted-root.jsonl",
            output_dir=tmp_path / "verify-out")
    assert str(info.value) == R4


def test_dotfile_members_are_refused(tmp_path, monkeypatch):
    """#5: the closed roster refuses hidden files, dirs, and symlinks alike."""
    profile = fixture_profile()
    value = v2_handoff()
    evidence = make_evidence(tmp_path, context=fixture_context(profile, value))
    stub_verifier(monkeypatch, profile)
    (evidence / ".caller-claim.json").write_text('{"approved": true}\n')
    (evidence / ".hidden-dir").mkdir()
    (evidence / ".hidden-link").symlink_to("attestation-context.json")
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(
            value, evidence, executable=FIXTURES / "verifier" / "verify-fixture.sh",
            trusted_root=evidence / "trusted-root.jsonl",
            output_dir=tmp_path / "verify-out")
    assert str(info.value) == R4


def test_checked_in_context_fixture_has_nested_producer_shape():
    """Q2 guard: the checked-in fixture keeps the nested producer shape."""
    value = json.loads((FIXTURES / "attestation-context.json").read_text())
    sealed = value["payload"]["source"]["sealed"]
    content = value["payload"]["source"]["content"]
    assert set(sealed) >= {"reference", "manifest_sha256", "archive_sha256",
                           "receipt_sha256"}
    assert set(content) >= {"reference", "manifest_sha256", "file_sha256",
                            "receipt_sha256", "spdx_sha256", "inventory_sha256"}
    handoff = v2_handoff()
    assert sealed["reference"] == handoff["source"]["reference"]
    assert sealed["manifest_sha256"] == handoff["source"]["manifest_sha256"]
    assert sealed["archive_sha256"] == handoff["source"]["file_sha256"]
    companion = handoff["source"]["content_companion"]
    for name in ("reference", "manifest_sha256", "file_sha256", "receipt_sha256",
                 "spdx_sha256"):
        assert content[name] == companion[name]
    proof = companion["readback_proof_sha256"]
    assert len({sealed["receipt_sha256"], content["inventory_sha256"], proof}) == 3


def test_q2_honest_nested_producer_context_reaches_r9(tmp_path, monkeypatch):
    """Q2: honest nested producer-shaped context reaches exact R9."""
    args = valid_call_args(tmp_path, monkeypatch)
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(**args)
    assert str(info.value) == R9
    assert "authenticated source transport" not in str(info.value)


@pytest.mark.parametrize("section,field", [
    ("sealed", "reference"),
    ("sealed", "manifest_sha256"),
    ("sealed", "archive_sha256"),
    ("content", "reference"),
    ("content", "manifest_sha256"),
    ("content", "file_sha256"),
    ("content", "receipt_sha256"),
    ("content", "spdx_sha256"),
])
def test_q2_single_field_mutations_are_binding_mismatches(tmp_path, monkeypatch,
                                                          section, field):
    """Q2: each mapped field binds; one differing field refuses exact R8.

    Mutations land context-side so the handoff stays schema-valid
    untouched (reference/manifest schema coupling forbids single-field
    handoff-side reference mutation).
    """
    profile = fixture_profile()
    value = v2_handoff()
    context = fixture_context(profile, value)
    if field == "reference":
        context["payload"]["source"][section][field] = (
            value["registry"] + "@sha256:" + "f" * 64)
    else:
        context["payload"]["source"][section][field] = "f" * 64
    evidence = make_evidence(tmp_path, context=context)
    stub_verifier(monkeypatch, profile)
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(
            value, evidence, executable=FIXTURES / "verifier" / "verify-fixture.sh",
            trusted_root=evidence / "trusted-root.jsonl",
            output_dir=tmp_path / "verify-out")
    assert str(info.value) == R8


@pytest.mark.parametrize("damage", ["source-missing", "sealed-missing", "content-missing",
                                    "sealed-field-missing", "source-nondict",
                                    "sealed-nondict", "content-nondict", "flat-shape"])
def test_q2_nesting_damage_is_binding_mismatch(tmp_path, monkeypatch, damage):
    """Q2: missing/malformed nesting and the retired flat shape refuse R8."""
    profile = fixture_profile()
    value = v2_handoff()
    context = fixture_context(profile, value)
    payload = context["payload"]
    if damage == "source-missing":
        del payload["source"]
    elif damage == "sealed-missing":
        del payload["source"]["sealed"]
    elif damage == "content-missing":
        del payload["source"]["content"]
    elif damage == "sealed-field-missing":
        del payload["source"]["sealed"]["archive_sha256"]
    elif damage == "source-nondict":
        payload["source"] = "not-an-object"
    elif damage == "sealed-nondict":
        payload["source"]["sealed"] = ["not-an-object"]
    elif damage == "content-nondict":
        payload["source"]["content"] = 42
    else:
        context["payload"] = {
            "source": {
                "manifest_sha256": value["source"]["manifest_sha256"],
                "file_sha256": value["source"]["file_sha256"],
            },
            "content_companion": {
                name: value["source"]["content_companion"][name]
                for name in ("manifest_sha256", "file_sha256", "receipt_sha256",
                             "spdx_sha256", "readback_proof_sha256")
            },
        }
    evidence = make_evidence(tmp_path, context=context)
    stub_verifier(monkeypatch, profile)
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(
            value, evidence, executable=FIXTURES / "verifier" / "verify-fixture.sh",
            trusted_root=evidence / "trusted-root.jsonl",
            output_dir=tmp_path / "verify-out")
    assert str(info.value) == R8


def test_q2_proof_only_change_still_reaches_r9(tmp_path, monkeypatch):
    """Q2 boundary: a proof-only handoff change still reaches R9 here.

    readback_proof_sha256 stays required by handoff schema2 but is not
    authenticated by B-G2a; B-G2b must verify+bind the proof bytes
    before admission. This test proves the deferral.
    """
    args = valid_call_args(tmp_path, monkeypatch)
    args["value"]["source"]["content_companion"]["readback_proof_sha256"] = "9" * 64
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(**args)
    assert str(info.value) == R9
    assert "authenticated source transport" not in str(info.value)


def test_q2_unmapped_digests_are_not_aliased(tmp_path, monkeypatch):
    """Q2 anti-alias: inventory/receipt sentinels float free of the proof.

    All three identities are pairwise distinct, and mutating the two
    unmapped producer digests still reaches R9 — an implementation
    aliasing either to readback_proof_sha256 would refuse R8 instead.
    """
    profile = fixture_profile()
    value = v2_handoff()
    context = fixture_context(profile, value)
    sealed = context["payload"]["source"]["sealed"]
    content = context["payload"]["source"]["content"]
    proof = value["source"]["content_companion"]["readback_proof_sha256"]
    assert len({sealed["receipt_sha256"], content["inventory_sha256"], proof}) == 3
    sealed["receipt_sha256"] = "8" * 64
    content["inventory_sha256"] = "7" * 64
    evidence = make_evidence(tmp_path, context=context)
    stub_verifier(monkeypatch, profile)
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(
            value, evidence, executable=FIXTURES / "verifier" / "verify-fixture.sh",
            trusted_root=evidence / "trusted-root.jsonl",
            output_dir=tmp_path / "verify-out")
    assert str(info.value) == R9
    assert "authenticated source transport" not in str(info.value)


@pytest.mark.parametrize("bundle_variant", ["honest", "tampered"])
def test_oracle_records_actual_bundle_bytes(tmp_path, monkeypatch, bundle_variant):
    """#6 input-bound oracle: the stub hashes the bundle argument bytes.

    Paired honest/tampered cases prove the oracle saw the respective
    input hash. The stub observes without enforcing (damage=None), so
    both reach R9; enforcement belongs to the real verifier.
    """
    profile = fixture_profile()
    value = v2_handoff()
    context = fixture_context(profile, value)
    honest_bytes = (FIXTURES / "bundle.json").read_bytes()
    tampered_bytes = (FIXTURES / "bundle-tampered.json").read_bytes()
    assert honest_bytes != tampered_bytes
    bundle_bytes = honest_bytes if bundle_variant == "honest" else tampered_bytes
    evidence = make_evidence(tmp_path, context=context, bundle=bundle_bytes)
    stub_verifier(monkeypatch, profile)
    output = tmp_path / "verify-out"
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(
            value, evidence, executable=FIXTURES / "verifier" / "verify-fixture.sh",
            trusted_root=evidence / "trusted-root.jsonl", output_dir=output)
    assert str(info.value) == R9
    journal = json.loads((output / "verifier-journal.json").read_text())
    assert journal["observed_bundle_path"] == str(output / "bundle.json")
    assert journal["observed_bundle_sha256"] == hashlib.sha256(bundle_bytes).hexdigest()
    assert journal["observed_bundle_sha256"] == hashlib.sha256(
        (evidence / "bundle.json").read_bytes()).hexdigest()


# G-F6 entry guards: output usability, executable regularity + exec bit, and
# the evidence member-count ceiling refuse R4 before any verifier I/O. The
# brief's missing-output_dir→R4 case is NOT pinned here: the verifier creates
# a missing output dir (mkdir exist_ok=False), so refusing missing outputs
# would make R9 unreachable and break every frozen verifier-reaching row
# (see the G-F6 report; parent adjudication required).


def test_gf6_file_as_output_dir_is_refused_without_verifier(tmp_path, monkeypatch):
    """G-F6: a file-as-output_dir refuses R4 before the verifier runs."""
    profile = fixture_profile()
    value = v2_handoff()
    evidence = make_evidence(tmp_path, context=fixture_context(profile, value))
    stub_verifier(monkeypatch, profile)
    _refuse_verifier(monkeypatch)
    output_file = tmp_path / "verify-out"
    output_file.write_text("not a directory\n")
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(
            value, evidence, executable=FIXTURES / "verifier" / "verify-fixture.sh",
            trusted_root=evidence / "trusted-root.jsonl", output_dir=output_file)
    assert str(info.value) == R4


def test_gf6_dir_as_executable_is_refused_without_verifier(tmp_path, monkeypatch):
    """G-F6: a directory-as-executable refuses R4 before the verifier runs."""
    profile = fixture_profile()
    value = v2_handoff()
    evidence = make_evidence(tmp_path, context=fixture_context(profile, value))
    stub_verifier(monkeypatch, profile)
    _refuse_verifier(monkeypatch)
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(
            value, evidence, executable=tmp_path,
            trusted_root=evidence / "trusted-root.jsonl",
            output_dir=tmp_path / "verify-out")
    assert str(info.value) == R4


def test_gf6_nonexec_executable_is_refused_without_verifier(tmp_path, monkeypatch):
    """G-F6: correct bytes without any exec bit refuse R4 (mode, not bytes)."""
    import stat
    profile = fixture_profile()
    value = v2_handoff()
    evidence = make_evidence(tmp_path, context=fixture_context(profile, value))
    stub_verifier(monkeypatch, profile)
    _refuse_verifier(monkeypatch)
    candidate = tmp_path / "verifier-noexec.sh"
    candidate.write_bytes((FIXTURES / "verifier" / "verify-fixture.sh").read_bytes())
    candidate.chmod(0o644)
    status = candidate.lstat()
    assert stat.S_ISREG(status.st_mode)
    assert status.st_nlink == 1
    assert status.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH) == 0
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(
            value, evidence, executable=candidate,
            trusted_root=evidence / "trusted-root.jsonl",
            output_dir=tmp_path / "verify-out")
    assert str(info.value) == R4


@pytest.mark.parametrize("field", ["evidence_dir", "executable", "trusted_root",
                                   "output_dir"])
def test_gf6_str_inputs_are_refused(tmp_path, monkeypatch, field):
    """G-F6: each path input as str refuses R4 (pins isinstance rejection)."""
    args = valid_call_args(tmp_path, monkeypatch)
    args[field] = str(args[field])
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(**args)
    assert str(info.value) == R4


def test_gf6_member_count_bound_sixteen_is_allowed(tmp_path):
    """G-F6: 16 members (files + dotfile + dir + symlink) pass the helper."""
    from p11lab import acquisition
    directory = tmp_path / "sixteen"
    directory.mkdir()
    for index in range(13):
        (directory / f"member-{index:02d}.json").write_text("{}\n")
    (directory / ".dotfile-member").write_text("{}\n")
    (directory / "subdir-member").mkdir()
    (directory / "link-member").symlink_to("member-00.json")
    assert len(list(directory.iterdir())) == 16
    acquisition._check_member_bound(directory)


def test_gf6_member_count_bound_seventeen_is_refused(tmp_path):
    """G-F6: 17 members refuse exact R4 via the count helper (early stop)."""
    from p11lab import acquisition
    directory = tmp_path / "seventeen"
    directory.mkdir()
    for index in range(17):
        (directory / f"member-{index:02d}.json").write_text("{}\n")
    assert len(list(directory.iterdir())) == 17
    with pytest.raises(ValueError) as info:
        acquisition._check_member_bound(directory)
    assert str(info.value) == R4


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no FIFO support")
def test_gf6_fifo_executable_is_refused_without_hanging(tmp_path, monkeypatch):
    """G-F6: a FIFO executable refuses R4 fast (lstat-only, never opened)."""
    profile = fixture_profile()
    value = v2_handoff()
    evidence = make_evidence(tmp_path, context=fixture_context(profile, value))
    stub_verifier(monkeypatch, profile)
    _refuse_verifier(monkeypatch)
    fifo = tmp_path / "verifier-fifo"
    os.mkfifo(fifo)
    start = time.monotonic()
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(
            value, evidence, executable=fifo,
            trusted_root=evidence / "trusted-root.jsonl",
            output_dir=tmp_path / "verify-out")
    assert str(info.value) == R4
    assert time.monotonic() - start < 30


def test_gf7_a1_real_exec_canned_shape_is_malformed_attestation(tmp_path, monkeypatch):
    """G-F7 A1: the REAL bounded_stream runs the fixture exe end-to-end.

    Unstubbed subprocess on the pinned fixture, which emits the canned
    [{"verificationResult": {"fixture": true}}] shape; argv construction +
    real-subprocess handling are proven by the verified.json marker the
    stub never emits. Post-T3 the shape refuses with the exact
    deterministic text (pre-T3 it collapsed to R7_FALLBACK). Hermetic
    (fixture bytes only; in-process sockets forbidden); timeout-guarded
    by bounded_stream's own bound plus an elapsed assert.
    """
    import socket
    from p11lab import delivery_authority as authority
    profile = fixture_profile()
    value = v2_handoff()
    evidence = make_evidence(tmp_path, context=fixture_context(profile, value))
    exe = FIXTURES / "verifier" / "verify-fixture.sh"
    monkeypatch.setattr(authority, "GH_EXECUTABLE_SHA256",
                        hashlib.sha256(exe.read_bytes()).hexdigest())
    monkeypatch.setattr(authority, "load_profile",
                        lambda environment, channel: profile)

    def forbidden(*items, **kwargs):
        raise AssertionError("real-exec path used a socket")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    output = tmp_path / "verify-out"
    start = time.monotonic()
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(
            value, evidence, executable=exe,
            trusted_root=evidence / "trusted-root.jsonl", output_dir=output)
    assert str(info.value) == MALFORMED
    assert time.monotonic() - start < 30
    assert '"fixture": true' in (output / "verified.json").read_text()


CONTROLLER_MISMATCH = "installed controller package identity mismatch"


@pytest.mark.parametrize("leg,expected", [
    ("bundle-symlink", R4),
    ("bundle-nlink", R4),
    ("manifest-list", R4),
    ("manifest-malformed", R4),
    ("env-mismatch", R8),
    ("channel-mismatch", R8),
    ("output-exists", R4),
    ("run-missing", R7_FALLBACK),
    ("controller-mismatch", CONTROLLER_MISMATCH),
])
def test_gf7_a2_gate_sweep(tmp_path, monkeypatch, leg, expected):
    """G-F7 A2: defensive-branch sweep; each leg pins its exact refusal.

    Live line pins (acquisition.py): symlink/nlink members via
    _regular_file/_check_roster; manifest shape via _read_manifest;
    env/channel via _check_handoff_binding; pre-created output via the
    _run_verifier OSError catch; missing run identity via the inline
    type check; controller mismatch via _check_local_controller
    (unwrapped, exact delivery_authority text, verifier never runs).
    Non-dict payload legs are already exact-pinned by the Q2 nesting
    rows, so this sweep does not duplicate them.
    """
    profile = fixture_profile()
    value = v2_handoff()
    context = fixture_context(profile, value)
    if leg in ("env-mismatch", "channel-mismatch"):
        context["channel" if leg == "channel-mismatch" else "environment"] = "forged"
    if leg == "run-missing":
        del context["run"]
    evidence = make_evidence(tmp_path, context=context)
    if leg == "bundle-symlink":
        valid = (evidence / "bundle.json").read_bytes()
        (evidence / "bundle.json").unlink()
        (evidence / "bundle.json").symlink_to(FIXTURES / "bundle.json")
        assert (evidence / "bundle.json").read_bytes() == valid
    elif leg == "bundle-nlink":
        member = evidence / "bundle.json"
        alias = tmp_path / "bundle-alias.json"
        os.link(member, alias)
        assert member.lstat().st_nlink == 2
    elif leg == "manifest-list":
        (evidence / "evidence-manifest.json").write_text("[1, 2]\n")
    elif leg == "manifest-malformed":
        (evidence / "evidence-manifest.json").write_bytes(b"truncated{")
    output = tmp_path / "verify-out"
    if leg == "output-exists":
        output.mkdir()
    stub_profile = profile
    if leg == "controller-mismatch":
        stub_profile = dict(profile, controller_sha256="0" * 64)
        assert stub_profile["controller_sha256"] != profile["controller_sha256"]
    stub_verifier(monkeypatch, stub_profile)
    if leg == "controller-mismatch":
        _refuse_verifier(monkeypatch)
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(
            value, evidence, executable=FIXTURES / "verifier" / "verify-fixture.sh",
            trusted_root=evidence / "trusted-root.jsonl", output_dir=output)
    assert str(info.value) == expected


@pytest.mark.parametrize("raw", [
    b"truncated{",
    b"\xff\xfe binary",
    b"[1, 2]",
    b'{"schema_version": 1}',
    b'{"schema_version": 1, "payload": 42}',
])
def test_gf7_a2_context_bytes_are_verification_failed(raw):
    """G-F7 A2: malformed attested-context bytes refuse the R7 fallback.

    Pinned at _load_context directly: gate-level malformed context
    crashes the test stub's own subject parse before _load_context
    runs, so only the direct pin proves this leg's text.
    """
    from p11lab import acquisition
    with pytest.raises(ValueError) as info:
        acquisition._load_context(raw)
    assert str(info.value) == R7_FALLBACK
