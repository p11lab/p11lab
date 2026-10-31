"""Full image validation/promotion evidence + gate completion (B-G2b).

Hermetic only: fixture verifier + monkeypatched GH pin + stubbed
bounded_stream per tests/test_source_authority.py:415-448. Profile dicts
are built in-test (base B-G2a pins plus a promotion_signer entry); the
installed catalog is never read (load_profile is doubled at the test
seam). No network, no Docker, no GitHub API.

Both legs reuse the same sealed verifier executable (one GH pin, no new
root infrastructure); the combined stub dispatches on the attested
subject role. Transport helpers are reused from test_acquisition.
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

PROMO = Path(__file__).parent / "fixtures" / "promotion"
ACQ = Path(__file__).parent / "fixtures" / "acquisition"
EXE = ACQ / "verifier" / "verify-fixture.sh"

P_UNAVAILABLE = "full image validation/promotion integration unavailable; acquisition blocked"
P_VERIFY = "authenticated promotion verification failed: bundle digest mismatch"
P_BINDING = "promotion evidence differs from the handoff digests; acquisition blocked"
P_POLICY = "promotion validation policy mismatch; acquisition blocked"
T_UNAVAILABLE = "authenticated source transport evidence unavailable; acquisition blocked"

PROMO_PREDICATE = "https://p11lab.org/attestations/image-promotion/v1"
PROMO_SUBJECT = "promotion-context.json"

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


def v2p_handoff():
    """Eligible v2 handoff whose proof pin matches the fixture proof bytes."""
    registry = "ghcr.io/p11lab/softhsm2"
    proof_sha = hashlib.sha256((PROMO / "readback-proof.json").read_bytes()).hexdigest()
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
                readback_proof_sha256=proof_sha,
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


def bundle_handoff():
    """Eligible v2 handoff with a bundle (file-bound) binary."""
    value = v2p_handoff()
    value["binary"] = dict(
        kind="bundle",
        reference=value["registry"] + "@sha256:" + "c" * 64,
        manifest_sha256="c" * 64,
        file_sha256="f" * 64,
        platform="linux/amd64",
        tag="rt",
    )
    return value


def fixture_promotion_profile():
    """In-test profile: B-G2a pins plus the promotion_signer entry."""
    from test_acquisition import fixture_profile
    profile = fixture_profile()
    profile["promotion_signer"] = dict(
        repository=profile["repository"],
        repository_id=profile["repository_id"],
        owner_id=profile["owner_id"],
        workflow_path=profile["workflow_path"],
        signer_sha=profile["signer_sha"],
        source_sha=profile["source_sha"],
        source_ref=profile["source_ref"],
    )
    return profile


def fixture_promotion_context(profile, handoff, *, validation_bytes=None, proof_bytes=None):
    """Promotion context binding handoff digests + profile pins + member hashes."""
    from p11lab import delivery_authority as authority
    value = json.loads((PROMO / "promotion-context.json").read_text())
    value["policy_sha256"] = profile["policy_sha256"]
    value["review_sha256"] = profile["review_sha256"]
    value["controller_sha256"] = profile["controller_sha256"]
    value["profile_sha256"] = authority._profile_digest(profile)
    value["environment"] = handoff["catalogue"]["environment"]
    value["channel"] = handoff["catalogue"]["channel"]
    binary = handoff["binary"]
    bound = {"reference": binary["reference"], "manifest_sha256": binary["manifest_sha256"]}
    if binary["kind"] == "bundle":
        bound["file_sha256"] = binary["file_sha256"]
    else:
        bound["engine_id"] = binary["engine_id"]
    if validation_bytes is None:
        validation_bytes = (PROMO / "validation-result.json").read_bytes()
    if proof_bytes is None:
        proof_bytes = (PROMO / "readback-proof.json").read_bytes()
    value["payload"] = {"promotion": {
        "binary": bound,
        "source": {"manifest_sha256": handoff["source"]["manifest_sha256"],
                   "file_sha256": handoff["source"]["file_sha256"]},
        "validation_result_sha256": hashlib.sha256(validation_bytes).hexdigest(),
        "readback_proof_sha256": handoff["source"]["content_companion"]["readback_proof_sha256"],
    }}
    assert value["payload"]["promotion"]["readback_proof_sha256"] == hashlib.sha256(
        proof_bytes).hexdigest()
    return value


def make_promotion_evidence(tmp_path, *, context=None, validation=None, proof=None,
                            bundle=None, root=None, manifest_extra=None,
                            name="promotion-evidence"):
    directory = tmp_path / name
    directory.mkdir()
    (directory / "promotion-context.json").write_text(
        json.dumps(context if context is not None
                   else json.loads((PROMO / "promotion-context.json").read_text()),
                   sort_keys=True) + "\n")
    (directory / "promotion-bundle.json").write_bytes(
        bundle if bundle is not None else (PROMO / "promotion-bundle.json").read_bytes())
    (directory / "promotion-trusted-root.jsonl").write_bytes(
        root if root is not None else (PROMO / "promotion-trusted-root.jsonl").read_bytes())
    (directory / "validation-result.json").write_bytes(
        validation if validation is not None
        else (PROMO / "validation-result.json").read_bytes())
    (directory / "readback-proof.json").write_bytes(
        proof if proof is not None else (PROMO / "readback-proof.json").read_bytes())
    manifest = {"schema_version": 1}
    if manifest_extra:
        manifest.update(manifest_extra)
    (directory / "promotion-manifest.json").write_text(
        json.dumps(manifest, sort_keys=True) + "\n")
    return directory


def stub_gate_verifiers(monkeypatch, profile, *, promotion_damage=None):
    """One sealed exe for both legs; damage applies to the promotion leg only.

    The stub dispatches on the attested subject role: transport subjects
    verify against the base profile pins, promotion subjects against the
    promotion_signer overlay (falling back to base pins when the entry is
    absent so the missing-signer refusal is selected by promotion.py).
    """
    from p11lab import delivery_authority as authority
    from p11lab import inspection_bounded
    monkeypatch.setattr(authority, "GH_EXECUTABLE_SHA256",
                        hashlib.sha256(EXE.read_bytes()).hexdigest())
    monkeypatch.setattr(authority, "load_profile",
                        lambda environment, channel: profile)

    def run(argv, destination, max_bytes, timeout, env, record):
        subject_bytes = Path(argv[3]).read_bytes()
        ctx = json.loads(subject_bytes)
        promotion = ctx.get("role") == "image-promotion"
        pins = dict(profile)
        if promotion:
            signer = profile.get("promotion_signer")
            if type(signer) is dict:
                for key in ("repository", "repository_id", "owner_id", "workflow_path",
                            "signer_sha", "source_sha", "source_ref"):
                    if key in signer:
                        pins[key] = signer[key]
        run_id = ctx.get("run", {"run_id": 891, "attempt": 1})
        workflow = ("https://github.com/" + pins["repository"] + "/"
                    + pins["workflow_path"] + "@" + pins["source_ref"])
        owner = pins["repository"].split("/")[0]
        cert = {
            "issuer": "https://token.actions.githubusercontent.com",
            "subjectAlternativeName": workflow,
            "buildSignerURI": workflow,
            "buildSignerDigest": pins["signer_sha"],
            "sourceRepositoryURI": "https://github.com/" + pins["repository"],
            "sourceRepositoryIdentifier": str(pins["repository_id"]),
            "sourceRepositoryOwnerURI": "https://github.com/" + owner,
            "sourceRepositoryOwnerIdentifier": str(pins["owner_id"]),
            "sourceRepositoryDigest": pins["source_sha"],
            "sourceRepositoryRef": pins["source_ref"],
            "runnerEnvironment": "github-hosted",
            "runInvocationURI": ("https://github.com/" + pins["repository"]
                                 + "/actions/runs/" + str(run_id["run_id"])
                                 + "/attempts/" + str(run_id["attempt"])),
        }
        now = datetime.now(timezone.utc)
        subject_name = PROMO_SUBJECT if promotion else "source-context.json"
        predicate = PROMO_PREDICATE if promotion else authority.PREDICATE_TYPE
        statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": predicate,
            "subject": [{"name": subject_name,
                         "digest": {"sha256": hashlib.sha256(subject_bytes).hexdigest()}}],
            "predicate": {"schema_version": 1},
        }
        result = [{"verificationResult": {
            "signature": {"certificate": cert},
            "verifiedTimestamps": [{"type": "Tlog",
                                    "timestamp": now.isoformat().replace("+00:00", "Z")}],
            "statement": statement}}]
        damage = promotion_damage if promotion else None
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


def valid_gate_args(tmp_path, monkeypatch, handoff=None, *, promotion_damage=None):
    from test_acquisition import fixture_context, make_evidence
    profile = fixture_promotion_profile()
    value = handoff if handoff is not None else v2p_handoff()
    transport = make_evidence(tmp_path, context=fixture_context(profile, value),
                              name="evidence")
    promo = make_promotion_evidence(
        tmp_path, context=fixture_promotion_context(profile, value))
    stub_gate_verifiers(monkeypatch, profile, promotion_damage=promotion_damage)
    return dict(value=value, evidence_dir=transport, executable=EXE,
                trusted_root=transport / "trusted-root.jsonl",
                output_dir=tmp_path / "verify-out",
                promotion_dir=promo, promotion_executable=EXE,
                promotion_trusted_root=promo / "promotion-trusted-root.jsonl",
                promotion_output_dir=tmp_path / "promotion-out")


def test_g2b_r5_valid_pair_passes(tmp_path, monkeypatch):
    """First gate pass ever: eligible handoff + both evidence kinds."""
    args = valid_gate_args(tmp_path, monkeypatch)
    assert publish.require_eligible_handoff(**args) == args["value"]


def test_g2b_r5_bundle_kind_pair_passes(tmp_path, monkeypatch):
    args = valid_gate_args(tmp_path, monkeypatch, bundle_handoff())
    assert publish.require_eligible_handoff(**args) == args["value"]


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
def test_g2b_r1_forged_promotion_is_refused(tmp_path, monkeypatch, damage, expected):
    args = valid_gate_args(tmp_path, monkeypatch, promotion_damage=damage)
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(**args)
    assert str(info.value) == expected


@pytest.mark.parametrize("member", ["validation-result", "readback-proof", "context-digest"])
def test_g2b_r2_tampered_member_is_binding_mismatch(tmp_path, monkeypatch, member):
    from test_acquisition import fixture_context, make_evidence
    profile = fixture_promotion_profile()
    value = v2p_handoff()
    transport = make_evidence(tmp_path, context=fixture_context(profile, value),
                              name="evidence")
    context = fixture_promotion_context(profile, value)
    validation = proof = None
    if member == "validation-result":
        raw = bytearray((PROMO / "validation-result.json").read_bytes())
        raw[10] ^= 0x01
        validation = bytes(raw)
    elif member == "readback-proof":
        raw = bytearray((PROMO / "readback-proof.json").read_bytes())
        raw[10] ^= 0x01
        proof = bytes(raw)
    else:
        context["payload"]["promotion"]["source"]["file_sha256"] = "f" * 64
    promo = make_promotion_evidence(tmp_path, context=context,
                                    validation=validation, proof=proof)
    stub_gate_verifiers(monkeypatch, profile)
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(
            value, transport, executable=EXE,
            trusted_root=transport / "trusted-root.jsonl",
            output_dir=tmp_path / "verify-out", promotion_dir=promo,
            promotion_executable=EXE,
            promotion_trusted_root=promo / "promotion-trusted-root.jsonl",
            promotion_output_dir=tmp_path / "promotion-out")
    assert str(info.value) == P_BINDING


def test_g2b_r2_wrong_promotion_executable_is_refused(tmp_path, monkeypatch):
    args = valid_gate_args(tmp_path, monkeypatch)
    wrong = tmp_path / "wrong-gh"
    wrong.write_bytes(b"not the fixture verifier")
    wrong.chmod(0o755)
    args["promotion_executable"] = wrong
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(**args)
    assert str(info.value) == EXE_MISMATCH


def test_g2b_r2_forged_promotion_root_is_refused(tmp_path, monkeypatch):
    from test_acquisition import fixture_context, make_evidence
    profile = fixture_promotion_profile()
    value = v2p_handoff()
    transport = make_evidence(tmp_path, context=fixture_context(profile, value),
                              name="evidence")
    promo = make_promotion_evidence(
        tmp_path, context=fixture_promotion_context(profile, value),
        root=b"forged promotion root bytes")
    stub_gate_verifiers(monkeypatch, profile)
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(
            value, transport, executable=EXE,
            trusted_root=transport / "trusted-root.jsonl",
            output_dir=tmp_path / "verify-out", promotion_dir=promo,
            promotion_executable=EXE,
            promotion_trusted_root=promo / "promotion-trusted-root.jsonl",
            promotion_output_dir=tmp_path / "promotion-out")
    assert str(info.value) == ROOT_MISMATCH


@pytest.mark.parametrize("damage", ["promotable-false", "scope", "authority", "role",
                                    "schema_version", "malformed", "not-object"])
def test_g2b_r3_policy_mismatch_is_refused(tmp_path, monkeypatch, damage):
    from test_acquisition import fixture_context, make_evidence
    profile = fixture_promotion_profile()
    value = v2p_handoff()
    transport = make_evidence(tmp_path, context=fixture_context(profile, value),
                              name="evidence")
    if damage == "malformed":
        validation = b"{not json"
    elif damage == "not-object":
        validation = b"[1, 2]\n"
    else:
        result = json.loads((PROMO / "validation-result.json").read_text())
        if damage == "promotable-false":
            result["promotable"] = False
        elif damage == "scope":
            result["scope"] = "local-only"
        elif damage == "authority":
            result["authority"] = "local-unauthenticated"
        elif damage == "role":
            result["role"] = "local-image-validation"
        else:
            result["schema_version"] = True
        validation = (json.dumps(result, sort_keys=True) + "\n").encode()
    context = fixture_promotion_context(profile, value, validation_bytes=validation)
    promo = make_promotion_evidence(tmp_path, context=context, validation=validation)
    stub_gate_verifiers(monkeypatch, profile)
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(
            value, transport, executable=EXE,
            trusted_root=transport / "trusted-root.jsonl",
            output_dir=tmp_path / "verify-out", promotion_dir=promo,
            promotion_executable=EXE,
            promotion_trusted_root=promo / "promotion-trusted-root.jsonl",
            promotion_output_dir=tmp_path / "promotion-out")
    assert str(info.value) == P_POLICY


@pytest.mark.parametrize("damage", ["handoff-binary", "handoff-source", "handoff-proof",
                                    "context-binary", "context-source",
                                    "context-validation-hash", "context-proof-hash"])
def test_g2b_r4_unbound_digest_is_refused(tmp_path, monkeypatch, damage):
    from test_acquisition import fixture_context, make_evidence
    profile = fixture_promotion_profile()
    value = v2p_handoff()
    other = v2p_handoff()
    if damage == "handoff-binary":
        value["binary"]["manifest_sha256"] = "f" * 64
        value["binary"]["reference"] = value["registry"] + "@sha256:" + "f" * 64
    elif damage == "handoff-source":
        value["source"]["file_sha256"] = "f" * 64
    elif damage == "handoff-proof":
        value["source"]["content_companion"]["readback_proof_sha256"] = "f" * 64
    context = fixture_promotion_context(profile, other)
    if damage == "context-binary":
        context["payload"]["promotion"]["binary"]["manifest_sha256"] = "f" * 64
    elif damage == "context-source":
        context["payload"]["promotion"]["source"]["manifest_sha256"] = "f" * 64
    elif damage == "context-validation-hash":
        context["payload"]["promotion"]["validation_result_sha256"] = "f" * 64
    elif damage == "context-proof-hash":
        context["payload"]["promotion"]["readback_proof_sha256"] = "f" * 64
    transport = make_evidence(tmp_path, context=fixture_context(profile, value),
                              name="evidence")
    promo = make_promotion_evidence(tmp_path, context=context)
    stub_gate_verifiers(monkeypatch, profile)
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(
            value, transport, executable=EXE,
            trusted_root=transport / "trusted-root.jsonl",
            output_dir=tmp_path / "verify-out", promotion_dir=promo,
            promotion_executable=EXE,
            promotion_trusted_root=promo / "promotion-trusted-root.jsonl",
            promotion_output_dir=tmp_path / "promotion-out")
    assert str(info.value) == P_BINDING


def test_g2b_r6_booleans_inert_for_pass_and_refusal(tmp_path, monkeypatch):
    flagged = v2p_handoff()
    flagged["admission"].update(anonymous_source_available=True, image_promotable=True)
    flagged["approved"] = True
    args = valid_gate_args(tmp_path, monkeypatch, flagged)
    assert publish.require_eligible_handoff(**args) == flagged
    stripped = copy.deepcopy(flagged)
    del stripped["admission"]["anonymous_source_available"]
    del stripped["admission"]["image_promotable"]
    del stripped["approved"]
    assert publish.require_eligible_handoff(**dict(
        args, value=stripped, output_dir=tmp_path / "verify-out-2",
        promotion_output_dir=tmp_path / "promotion-out-2")) == stripped
    refused = dict(args, value=v2p_handoff(), output_dir=tmp_path / "verify-out-3",
                   promotion_dir=None, promotion_executable=None,
                   promotion_trusted_root=None, promotion_output_dir=None)
    with pytest.raises(publish.PublishError) as plain:
        publish.require_eligible_handoff(**refused)
    assert str(plain.value) == P_UNAVAILABLE
    assert "authenticated source transport" not in str(plain.value)


@pytest.mark.parametrize("damage,expected", [
    ("v1", "public acquisition requires handoff schema2"),
    ("admission", "handoff admission is not eligible"),
    ("readback", "handoff requires complete source/content readback admission"),
    ("binary-reference", "handoff binary reference must bind its manifest digest"),
])
def test_g2b_r7_handoff_checks_before_evidence(tmp_path, monkeypatch, damage, expected):
    args = valid_gate_args(tmp_path, monkeypatch)
    if damage == "v1":
        args["value"] = dict(args["value"], schema_version=1)
    elif damage == "admission":
        args["value"]["admission"] = dict(status="blocked", blockers=["x"],
                                          content_status="eligible",
                                          source_readback_status="verified")
    elif damage == "readback":
        args["value"]["admission"] = dict(status="eligible", blockers=[],
                                          content_status="eligible",
                                          source_readback_status="missing")
    else:
        args["value"]["binary"]["reference"] += "-forged"
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(**args)
    assert str(info.value) == expected


@pytest.mark.parametrize("shape", ["all-none", "dir-only", "missing-output", "str-paths"])
def test_g2b_r8_promotion_inputs_refused(tmp_path, monkeypatch, shape):
    from test_acquisition import fixture_context, make_evidence
    profile = fixture_promotion_profile()
    value = v2p_handoff()
    transport = make_evidence(tmp_path, context=fixture_context(profile, value),
                              name="evidence")
    promo = make_promotion_evidence(tmp_path,
                                    context=fixture_promotion_context(profile, value))
    stub_gate_verifiers(monkeypatch, profile)
    base = dict(value=value, evidence_dir=transport, executable=EXE,
                trusted_root=transport / "trusted-root.jsonl",
                output_dir=tmp_path / "verify-out")
    if shape == "all-none":
        call = dict(base, promotion_dir=None, promotion_executable=None,
                    promotion_trusted_root=None, promotion_output_dir=None)
    elif shape == "dir-only":
        call = dict(base, promotion_dir=promo, promotion_executable=None,
                    promotion_trusted_root=None, promotion_output_dir=None)
    elif shape == "missing-output":
        call = dict(base, promotion_dir=promo, promotion_executable=EXE,
                    promotion_trusted_root=promo / "promotion-trusted-root.jsonl",
                    promotion_output_dir=None)
    else:
        call = dict(base, promotion_dir=str(promo), promotion_executable=str(EXE),
                    promotion_trusted_root=str(promo / "promotion-trusted-root.jsonl"),
                    promotion_output_dir=str(tmp_path / "promotion-out"))
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(**call)
    assert str(info.value) == P_UNAVAILABLE


def test_g2b_transport_failure_surfaces_before_promotion(tmp_path, monkeypatch):
    from test_acquisition import make_evidence
    profile = fixture_promotion_profile()
    value = v2p_handoff()
    transport = make_evidence(tmp_path, name="evidence")
    promo = make_promotion_evidence(tmp_path,
                                    context=fixture_promotion_context(profile, value))
    stub_gate_verifiers(monkeypatch, profile)
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(
            value, transport, executable=EXE,
            trusted_root=transport / "trusted-root.jsonl",
            output_dir=tmp_path / "verify-out", promotion_dir=promo,
            promotion_executable=EXE,
            promotion_trusted_root=promo / "promotion-trusted-root.jsonl",
            promotion_output_dir=tmp_path / "promotion-out")
    assert str(info.value) == \
        "authenticated source transport verification failed: bundle digest mismatch"


@pytest.mark.parametrize("version", [True, False, 1.0, "1", 2, None])
def test_g2b_manifest_schema_version_strict(tmp_path, monkeypatch, version):
    from test_acquisition import fixture_context, make_evidence
    profile = fixture_promotion_profile()
    value = v2p_handoff()
    transport = make_evidence(tmp_path, context=fixture_context(profile, value),
                              name="evidence")
    promo = make_promotion_evidence(
        tmp_path, context=fixture_promotion_context(profile, value))
    if version is None:
        manifest = {}
    else:
        manifest = {"schema_version": version}
    (promo / "promotion-manifest.json").write_text(
        json.dumps(manifest, sort_keys=True) + "\n")
    stub_gate_verifiers(monkeypatch, profile)
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(
            value, transport, executable=EXE,
            trusted_root=transport / "trusted-root.jsonl",
            output_dir=tmp_path / "verify-out", promotion_dir=promo,
            promotion_executable=EXE,
            promotion_trusted_root=promo / "promotion-trusted-root.jsonl",
            promotion_output_dir=tmp_path / "promotion-out")
    assert str(info.value) == P_UNAVAILABLE


@pytest.mark.parametrize("damage", ["dotfile", "unknown", "missing-validation",
                                    "missing-proof", "missing-manifest"])
def test_g2b_roster_is_closed(tmp_path, monkeypatch, damage):
    from test_acquisition import fixture_context, make_evidence
    profile = fixture_promotion_profile()
    value = v2p_handoff()
    transport = make_evidence(tmp_path, context=fixture_context(profile, value),
                              name="evidence")
    promo = make_promotion_evidence(
        tmp_path, context=fixture_promotion_context(profile, value))
    if damage == "dotfile":
        (promo / ".dotfile-member").write_text("{}\n")
    elif damage == "unknown":
        (promo / "extra-transcript.json").write_text("{}\n")
    else:
        (promo / {"missing-validation": "validation-result.json",
                  "missing-proof": "readback-proof.json",
                  "missing-manifest": "promotion-manifest.json"}[damage]).unlink()
    stub_gate_verifiers(monkeypatch, profile)
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(
            value, transport, executable=EXE,
            trusted_root=transport / "trusted-root.jsonl",
            output_dir=tmp_path / "verify-out", promotion_dir=promo,
            promotion_executable=EXE,
            promotion_trusted_root=promo / "promotion-trusted-root.jsonl",
            promotion_output_dir=tmp_path / "promotion-out")
    assert str(info.value) == P_UNAVAILABLE


def test_g2b_member_count_bound_sixteen_allowed(tmp_path):
    from p11lab import promotion
    directory = tmp_path / "sixteen"
    directory.mkdir()
    for index in range(13):
        (directory / f"member-{index:02d}.json").write_text("{}\n")
    (directory / ".dotfile-member").write_text("{}\n")
    (directory / "subdir-member").mkdir()
    (directory / "link-member").symlink_to("member-00.json")
    assert len(list(directory.iterdir())) == 16
    promotion._check_member_bound(directory)


def test_g2b_member_count_bound_seventeen_refused(tmp_path):
    from p11lab import promotion
    directory = tmp_path / "seventeen"
    directory.mkdir()
    for index in range(17):
        (directory / f"member-{index:02d}.json").write_text("{}\n")
    assert len(list(directory.iterdir())) == 17
    with pytest.raises(ValueError) as info:
        promotion._check_member_bound(directory)
    assert str(info.value) == P_UNAVAILABLE


def test_g2b_manifest_decoys_never_supply_expected_digests(tmp_path, monkeypatch):
    args = valid_gate_args(tmp_path, monkeypatch)
    (args["promotion_dir"] / "promotion-manifest.json").write_text(
        json.dumps({"schema_version": 1,
                    "binary_manifest_sha256": "f" * 64,
                    "validation_result_sha256": "f" * 64}, sort_keys=True) + "\n")
    assert publish.require_eligible_handoff(**args) == args["value"]


def test_g2b_missing_promotion_signer_is_unavailable(tmp_path, monkeypatch):
    from test_acquisition import fixture_context, make_evidence
    profile = fixture_promotion_profile()
    del profile["promotion_signer"]
    value = v2p_handoff()
    transport = make_evidence(tmp_path, context=fixture_context(profile, value),
                              name="evidence")
    promo = make_promotion_evidence(
        tmp_path, context=fixture_promotion_context(profile, value))
    stub_gate_verifiers(monkeypatch, profile)
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(
            value, transport, executable=EXE,
            trusted_root=transport / "trusted-root.jsonl",
            output_dir=tmp_path / "verify-out", promotion_dir=promo,
            promotion_executable=EXE,
            promotion_trusted_root=promo / "promotion-trusted-root.jsonl",
            promotion_output_dir=tmp_path / "promotion-out")
    assert str(info.value) == P_UNAVAILABLE


@pytest.mark.parametrize("damage", ["not-object", "missing-key", "wrong-type"])
def test_g2b_malformed_promotion_signer_is_unavailable(tmp_path, monkeypatch, damage):
    from test_acquisition import fixture_context, make_evidence
    profile = fixture_promotion_profile()
    if damage == "not-object":
        profile["promotion_signer"] = "ghcr.io/p11lab/signer"
    elif damage == "missing-key":
        del profile["promotion_signer"]["signer_sha"]
    else:
        profile["promotion_signer"]["signer_sha"] = 42
    value = v2p_handoff()
    transport = make_evidence(tmp_path, context=fixture_context(profile, value),
                              name="evidence")
    promo = make_promotion_evidence(
        tmp_path, context=fixture_promotion_context(profile, value))
    stub_gate_verifiers(monkeypatch, profile)
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(
            value, transport, executable=EXE,
            trusted_root=transport / "trusted-root.jsonl",
            output_dir=tmp_path / "verify-out", promotion_dir=promo,
            promotion_executable=EXE,
            promotion_trusted_root=promo / "promotion-trusted-root.jsonl",
            promotion_output_dir=tmp_path / "promotion-out")
    assert str(info.value) == P_UNAVAILABLE


@pytest.mark.parametrize("field", ["registry", "reference", "manifest_sha256", "file_sha256",
                                   "receipt_sha256", "spdx_sha256", "role", "schema_version"])
def test_g2b_readback_proof_relation_is_bound(tmp_path, monkeypatch, field):
    """The proof bytes must relate to the authenticated companion identities."""
    from test_acquisition import fixture_context, make_evidence
    profile = fixture_promotion_profile()
    value = v2p_handoff()
    proof_value = json.loads((PROMO / "readback-proof.json").read_text())
    if field == "schema_version":
        proof_value[field] = "1"
    elif field == "role":
        proof_value[field] = "readback-proof"
    elif field == "registry":
        proof_value[field] = "ghcr.io/p11lab/other"
    elif field == "reference":
        proof_value[field] += "-forged"
    else:
        proof_value[field] = "f" * 64
    proof = (json.dumps(proof_value, sort_keys=True) + "\n").encode()
    # Pin the handoff to the DAMAGED bytes so both hash checks pass and the
    # content-relation check alone selects the refusal.
    value["source"]["content_companion"]["readback_proof_sha256"] = hashlib.sha256(
        proof).hexdigest()
    transport = make_evidence(tmp_path, context=fixture_context(profile, value),
                              name="evidence")
    context = fixture_promotion_context(profile, value, proof_bytes=proof)
    promo = make_promotion_evidence(tmp_path, context=context, proof=proof)
    stub_gate_verifiers(monkeypatch, profile)
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(
            value, transport, executable=EXE,
            trusted_root=transport / "trusted-root.jsonl",
            output_dir=tmp_path / "verify-out", promotion_dir=promo,
            promotion_executable=EXE,
            promotion_trusted_root=promo / "promotion-trusted-root.jsonl",
            promotion_output_dir=tmp_path / "promotion-out")
    assert str(info.value) == P_BINDING


def test_g2b_profile_binding_mismatch_is_verification_failed(tmp_path, monkeypatch):
    args = valid_gate_args(tmp_path, monkeypatch)
    context = json.loads((args["promotion_dir"] / "promotion-context.json").read_text())
    context["policy_sha256"] = "f" * 64
    (args["promotion_dir"] / "promotion-context.json").write_text(
        json.dumps(context, sort_keys=True) + "\n")
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(**args)
    assert str(info.value) == P_VERIFY


def test_g2b_checked_in_fixtures_have_promotion_shape():
    context = json.loads((PROMO / "promotion-context.json").read_text())
    assert context["role"] == "image-promotion"
    assert type(context["schema_version"]) is int and context["schema_version"] == 1
    promotion = context["payload"]["promotion"]
    assert set(promotion) >= {"binary", "source", "validation_result_sha256",
                              "readback_proof_sha256"}
    assert set(promotion["binary"]) >= {"reference", "manifest_sha256", "engine_id"}
    assert set(promotion["source"]) >= {"manifest_sha256", "file_sha256"}
    assert promotion["validation_result_sha256"] == hashlib.sha256(
        (PROMO / "validation-result.json").read_bytes()).hexdigest()
    assert promotion["readback_proof_sha256"] == hashlib.sha256(
        (PROMO / "readback-proof.json").read_bytes()).hexdigest()
    result = json.loads((PROMO / "validation-result.json").read_text())
    assert (result["role"], result["scope"], result["authority"]) == (
        "image-validation-result", "producer-ci", "producer-attested")
    assert result["promotable"] is True
    proof = json.loads((PROMO / "readback-proof.json").read_text())
    assert (proof["role"], proof["schema_version"]) == ("content-readback-proof", 1)


def test_g2b_checked_in_bundle_tamper_is_one_byte(tmp_path):
    honest = (PROMO / "promotion-bundle.json").read_bytes()
    forged = (PROMO / "promotion-bundle-tampered.json").read_bytes()
    assert len(honest) == len(forged)
    assert sum(a != b for a, b in zip(honest, forged)) == 1


def test_g2b_promotion_texts_stay_in_frozen_family():
    for text in (P_UNAVAILABLE, P_VERIFY, P_BINDING, P_POLICY):
        assert any(word in text for word in
                   ("unavailable", "unverified", "authentication", "promotion"))
        assert "authenticated source transport" not in text
    assert P_UNAVAILABLE == T_UNAVAILABLE.replace(
        "authenticated source transport evidence unavailable",
        "full image validation/promotion integration unavailable")


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no FIFO support")
def test_g2b_promotion_manifest_fifo_is_refused_without_hanging(tmp_path, monkeypatch):
    args = valid_gate_args(tmp_path, monkeypatch)
    manifest = args["promotion_dir"] / "promotion-manifest.json"
    manifest.unlink()
    os.mkfifo(manifest)
    start = time.monotonic()
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(**args)
    assert str(info.value) == P_UNAVAILABLE
    assert time.monotonic() - start < 30


def test_g2b_promotion_manifest_symlink_is_refused(tmp_path, monkeypatch):
    args = valid_gate_args(tmp_path, monkeypatch)
    manifest = args["promotion_dir"] / "promotion-manifest.json"
    target = tmp_path / "manifest-target.json"
    target.write_text(manifest.read_text())
    manifest.unlink()
    manifest.symlink_to(target)
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(**args)
    assert str(info.value) == P_UNAVAILABLE


def test_g2b_oversized_promotion_manifest_is_refused(tmp_path, monkeypatch):
    args = valid_gate_args(tmp_path, monkeypatch)
    (args["promotion_dir"] / "promotion-manifest.json").write_bytes(
        b'{"schema_version": 1, "pad": "' + b"p" * (1024 * 1024) + b'"}\n')
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(**args)
    assert str(info.value) == P_UNAVAILABLE


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no FIFO support")
def test_g2b_fifo_promotion_executable_is_refused_without_hanging(tmp_path, monkeypatch):
    args = valid_gate_args(tmp_path, monkeypatch)
    fifo = tmp_path / "promotion-fifo"
    os.mkfifo(fifo)
    args["promotion_executable"] = fifo
    start = time.monotonic()
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(**args)
    assert str(info.value) == P_UNAVAILABLE
    assert time.monotonic() - start < 30


# P0-A: promotion verifier live fix. The promotion leg must invoke the
# sealed verifier in promotion mode (promotion predicate + subject) so a
# live `gh` verification against genuine producer-CI attestations can
# pass; the controller profile may carry a strictly-shaped
# `promotion_signer` entry. Pure appends; no existing test is touched.


def _p0a_divergent_signer(**overrides):
    """Promotion signer with every pin divergent from the base profile."""
    signer = dict(
        repository="p11lab/promoter",
        repository_id=4321,
        owner_id=8765,
        workflow_path=".github/workflows/promote.yml",
        signer_sha="c" * 40,
        source_sha="d" * 40,
        source_ref="refs/heads/promote",
    )
    signer.update(overrides)
    return signer


def _p0a_divergent_profile():
    profile = fixture_promotion_profile()
    profile["promotion_signer"] = _p0a_divergent_signer()
    return profile


def _p0a_capture_verifier_argv(monkeypatch):
    """Wrap the installed bounded_stream stub; record each argv.

    The existing stub still builds verified.json; this wrapper only
    observes argv. `_run_verifier` itself is never stubbed.
    """
    from p11lab import inspection_bounded
    seen = []
    inner = inspection_bounded.bounded_stream

    def recording(argv, destination, max_bytes, timeout, env, record):
        seen.append(list(argv))
        return inner(argv, destination, max_bytes, timeout, env, record)

    monkeypatch.setattr(inspection_bounded, "bounded_stream", recording)
    return seen


def test_p0a_promotion_predicate_const_is_pinned():
    from p11lab import delivery_authority as authority
    from p11lab import promotion
    assert authority.PROMOTION_PREDICATE_TYPE == promotion.PROMOTION_PREDICATE
    assert promotion.PROMOTION_PREDICATE == PROMO_PREDICATE


def test_p0a_promotion_argv_carries_promotion_predicate_subject_and_signer(
        tmp_path, monkeypatch):
    """P0-A core: the promotion leg invokes the verifier in promotion mode."""
    from p11lab import delivery_authority as authority
    from p11lab import promotion
    profile = _p0a_divergent_profile()
    value = v2p_handoff()
    promo = make_promotion_evidence(
        tmp_path, context=fixture_promotion_context(profile, value))
    stub_gate_verifiers(monkeypatch, profile)
    seen = _p0a_capture_verifier_argv(monkeypatch)
    out = tmp_path / "promotion-out"
    context = promotion.verify_promotion_evidence(
        value, promo, EXE, promo / "promotion-trusted-root.jsonl", out)
    assert context["role"] == "image-promotion"
    assert len(seen) == 1
    argv = seen[0]
    predicate = argv[argv.index("--predicate-type") + 1]
    assert predicate == PROMO_PREDICATE
    assert predicate == authority.PROMOTION_PREDICATE_TYPE
    assert Path(argv[3]).name == "promotion-context.json"
    assert argv[3] == str((out / "promotion-context.json").absolute())
    signer = profile["promotion_signer"]
    assert argv[argv.index("--repo") + 1] == signer["repository"]
    assert argv[argv.index("--signer-digest") + 1] == signer["signer_sha"]
    assert argv[argv.index("--source-digest") + 1] == signer["source_sha"]
    assert argv[argv.index("--source-ref") + 1] == signer["source_ref"]
    assert argv[argv.index("--cert-identity") + 1] == (
        "https://github.com/" + signer["repository"] + "/"
        + signer["workflow_path"] + "@" + signer["source_ref"])
    for flag, base_key in (("--signer-digest", "signer_sha"),
                           ("--source-digest", "source_sha"),
                           ("--source-ref", "source_ref")):
        assert argv[argv.index(flag) + 1] != profile[base_key]
    assert argv[argv.index("--repo") + 1] != profile["repository"]
    assert argv == [
        str((out / "gh").absolute()), "attestation", "verify",
        str((out / "promotion-context.json").absolute()),
        "--repo", signer["repository"],
        "--bundle", str((out / "bundle.json").absolute()),
        "--custom-trusted-root", str((out / "trusted-root.jsonl").absolute()),
        "--predicate-type", PROMO_PREDICATE,
        "--format", "json",
        "--signer-digest", signer["signer_sha"],
        "--source-digest", signer["source_sha"],
        "--source-ref", signer["source_ref"],
        "--cert-identity", "https://github.com/" + signer["repository"] + "/"
        + signer["workflow_path"] + "@" + signer["source_ref"],
        "--deny-self-hosted-runners",
    ]


@pytest.mark.parametrize("flags", [
    {"custody": True, "promotion": True},
    {"round_artifact": True, "promotion": True},
    {"custody": True, "round_artifact": True, "promotion": True},
    {"promotion": "yes"},
])
def test_p0a_run_verifier_rejects_stacked_or_untyped_promotion_flags(
        tmp_path, monkeypatch, flags):
    from p11lab import delivery_authority as authority
    from p11lab import inspection_bounded
    exe = tmp_path / "gh"
    exe.write_bytes(b"fixture-gh")
    subject = tmp_path / "context"
    subject.write_bytes(b"{}")
    bundle = tmp_path / "bundle"
    bundle.write_bytes(b"{}")
    root = tmp_path / "root"
    root.write_bytes(b"{}")
    monkeypatch.setattr(authority, "GH_EXECUTABLE_SHA256",
                        hashlib.sha256(b"fixture-gh").hexdigest())

    def refused(argv, destination, max_bytes, timeout, env, record):
        raise AssertionError("verifier must not run")

    monkeypatch.setattr(inspection_bounded, "bounded_stream", refused)
    profile = dict(repository="p11lab/controller",
                   workflow_path=".github/workflows/provider-delivery.yml",
                   source_ref="refs/heads/main",
                   signer_sha="a" * 40, source_sha="b" * 40)
    with pytest.raises(ValueError) as info:
        authority._run_verifier(
            exe, subject, bundle, root,
            hashlib.sha256(b"{}").hexdigest(), profile,
            tmp_path / "output", **flags)
    assert str(info.value) == "invalid verifier profile"


def test_p0a_run_verifier_promotion_mode_subject_and_predicate(
        tmp_path, monkeypatch):
    from p11lab import delivery_authority as authority
    from p11lab import inspection_bounded
    exe = tmp_path / "gh"
    exe.write_bytes(b"fixture-gh")
    subject = tmp_path / "context"
    subject.write_bytes(b"{}")
    bundle = tmp_path / "bundle"
    bundle.write_bytes(b"{}")
    root = tmp_path / "root"
    root.write_bytes(b"{}")
    monkeypatch.setattr(authority, "GH_EXECUTABLE_SHA256",
                        hashlib.sha256(b"fixture-gh").hexdigest())
    seen = []

    def run(argv, destination, max_bytes, timeout, env, record):
        seen.append(list(argv))
        destination.write_text("[]")
        record["returncode"] = 0

    monkeypatch.setattr(inspection_bounded, "bounded_stream", run)
    profile = dict(repository="p11lab/controller",
                   workflow_path=".github/workflows/provider-delivery.yml",
                   source_ref="refs/heads/main",
                   signer_sha="a" * 40, source_sha="b" * 40)
    out = tmp_path / "output"
    result, raw = authority._run_verifier(
        exe, subject, bundle, root, hashlib.sha256(b"{}").hexdigest(),
        profile, out, promotion=True)
    assert result == []
    assert raw == b"{}"
    assert seen[0][3] == str((out / "promotion-context.json").absolute())
    assert seen[0][seen[0].index("--predicate-type") + 1] == \
        authority.PROMOTION_PREDICATE_TYPE
    assert (out / "promotion-context.json").read_bytes() == b"{}"


def _p0a_damaged_signer_profile(damage):
    profile = fixture_promotion_profile()
    signer = _p0a_divergent_signer()
    if damage == "absent":
        del profile["promotion_signer"]
        return profile
    if damage == "not-object":
        profile["promotion_signer"] = "p11lab/promoter"
        return profile
    if damage == "missing-key":
        del signer["signer_sha"]
    elif damage == "extra-key":
        signer["owner_login"] = "promoter"
    elif damage == "bad-repo":
        signer["repository"] = "not-a-repo"
    elif damage == "repo-three-parts":
        signer["repository"] = "a/b/c"
    elif damage == "zero-repo-id":
        signer["repository_id"] = 0
    elif damage == "negative-owner-id":
        signer["owner_id"] = -7
    elif damage == "bool-id":
        signer["repository_id"] = True
    elif damage == "str-id":
        signer["owner_id"] = "8765"
    elif damage == "bad-signer-sha":
        signer["signer_sha"] = "z" * 40
    elif damage == "short-sha":
        signer["source_sha"] = "d" * 39
    elif damage == "upper-sha":
        signer["signer_sha"] = "C" * 40
    elif damage == "bad-ref":
        signer["source_ref"] = "promote"
    elif damage == "tag-ref":
        signer["source_ref"] = "refs/tags/v1"
    elif damage == "bad-workflow":
        signer["workflow_path"] = "promote.yml"
    elif damage == "yaml-workflow":
        signer["workflow_path"] = ".github/workflows/promote.yaml"
    elif damage == "wrong-type":
        signer["signer_sha"] = 42
    else:
        raise AssertionError("unknown damage: " + damage)
    profile["promotion_signer"] = signer
    return profile


@pytest.mark.parametrize("damage", [
    "absent", "not-object", "missing-key", "extra-key", "bad-repo",
    "repo-three-parts", "zero-repo-id", "negative-owner-id", "bool-id",
    "str-id", "bad-signer-sha", "short-sha", "upper-sha", "bad-ref",
    "tag-ref", "bad-workflow", "yaml-workflow", "wrong-type",
])
def test_p0a_promotion_profile_refuses_absent_or_malformed_signer(damage):
    from p11lab import promotion
    with pytest.raises(ValueError) as info:
        promotion._promotion_profile(_p0a_damaged_signer_profile(damage))
    assert str(info.value) == P_UNAVAILABLE


def test_p0a_promotion_profile_overlays_valid_divergent_signer():
    from p11lab import promotion
    profile = fixture_promotion_profile()
    profile["promotion_signer"] = _p0a_divergent_signer()
    overlaid = promotion._promotion_profile(profile)
    for key in ("repository", "repository_id", "owner_id", "workflow_path",
                "signer_sha", "source_sha", "source_ref"):
        assert overlaid[key] == profile["promotion_signer"][key]
    assert overlaid["policy_sha256"] == profile["policy_sha256"]
    assert overlaid["job"] == profile["job"]


def _p0a_full_profile():
    paths = [".github/workflows/provider-delivery.yml"] + [
        "src/p11lab/" + name for name in (
            "publish.py", "cli.py", "sources.py", "licenses.py",
            "source_transport.py", "delivery_authority.py",
            "inspection_bounded.py", "bounded_run.py",
            "image_validation.py", "round_core/artifacts.py",
            "round_core/inputs.py",
            "data/ci/delivery/validation-policy.json")]
    return dict(
        enabled=True,
        environment="softhsm2",
        channel="release",
        repository="p11lab/controller",
        repository_id=1234,
        owner_id=5678,
        workflow_path=".github/workflows/provider-delivery.yml",
        workflow_id=123,
        signer_sha="a" * 40,
        source_sha="b" * 40,
        source_ref="refs/heads/main",
        job="trusted-producer",
        policy_sha256="c" * 64,
        review_sha256="d" * 64,
        controller_sha256="e" * 64,
        role="source-producer",
        root_sha256="f" * 64,
        max_age_seconds=3600,
        environment_id=77,
        reviewer_ids=[101, 102],
        graph=[{"path": path, "sha256": "e" * 64} for path in paths],
    )


def test_p0a_validate_profile_without_signer_is_accepted():
    from p11lab import delivery_authority as authority
    profile = _p0a_full_profile()
    assert authority._validate_profile(profile) is profile


def test_p0a_validate_profile_with_signer_is_accepted():
    from p11lab import delivery_authority as authority
    profile = _p0a_full_profile()
    profile["promotion_signer"] = _p0a_divergent_signer()
    assert authority._validate_profile(profile) is profile
    assert profile["promotion_signer"]["repository"] == "p11lab/promoter"


@pytest.mark.parametrize("damage", [
    "not-object", "missing-key", "extra-key", "bad-repo", "zero-id",
    "bad-sha", "bad-ref", "bad-workflow",
])
def test_p0a_validate_profile_refuses_malformed_signer(damage):
    from p11lab import delivery_authority as authority
    profile = _p0a_full_profile()
    if damage == "not-object":
        profile["promotion_signer"] = ["p11lab/promoter"]
    else:
        signer = _p0a_divergent_signer()
        if damage == "missing-key":
            del signer["source_sha"]
        elif damage == "extra-key":
            signer["owner_login"] = "promoter"
        elif damage == "bad-repo":
            signer["repository"] = "not-a-repo"
        elif damage == "zero-id":
            signer["repository_id"] = 0
        elif damage == "bad-sha":
            signer["signer_sha"] = "z" * 40
        elif damage == "bad-ref":
            signer["source_ref"] = "promote"
        elif damage == "bad-workflow":
            signer["workflow_path"] = "promote.yml"
        profile["promotion_signer"] = signer
    with pytest.raises(ValueError) as info:
        authority._validate_profile(profile)
    assert str(info.value) == "invalid protected source profile"


def test_p0a_transport_leg_ignores_promotion_signer(tmp_path, monkeypatch):
    """The signer entry must not perturb the source-admission leg."""
    from test_acquisition import fixture_context, fixture_profile, make_evidence
    from test_acquisition import stub_verifier
    from p11lab import acquisition
    from p11lab import delivery_authority as authority
    plain = fixture_profile()
    extended = fixture_profile()
    extended["promotion_signer"] = _p0a_divergent_signer()
    value = v2p_handoff()
    results = []
    for tag, profile in (("plain", plain), ("extended", extended)):
        evidence = make_evidence(tmp_path, context=fixture_context(profile, value),
                                 name="evidence-" + tag)
        stub_verifier(monkeypatch, profile)
        seen = _p0a_capture_verifier_argv(monkeypatch)
        out = tmp_path / ("verify-out-" + tag)
        results.append((acquisition.verify_transport_evidence(
            value, evidence, EXE, evidence / "trusted-root.jsonl", out),
            seen, out))
    (plain_context, plain_seen, plain_out), (ext_context, ext_seen, ext_out) = results
    assert len(plain_seen) == len(ext_seen) == 1
    plain_argv = [entry.replace(str(plain_out), "<OUT>") for entry in plain_seen[0]]
    ext_argv = [entry.replace(str(ext_out), "<OUT>") for entry in ext_seen[0]]
    assert ext_argv == plain_argv
    argv = ext_seen[0]
    assert argv[argv.index("--predicate-type") + 1] == authority.PREDICATE_TYPE
    assert Path(argv[3]).name == "source-context.json"
    assert argv[argv.index("--signer-digest") + 1] == plain["signer_sha"]
    assert argv[argv.index("--repo") + 1] == plain["repository"]
    assert {key: val for key, val in ext_context.items()
            if key != "profile_sha256"} == {
        key: val for key, val in plain_context.items() if key != "profile_sha256"}
    assert ext_context["profile_sha256"] != plain_context["profile_sha256"]


@pytest.mark.parametrize("bundle_variant", ["honest", "tampered"])
def test_p0a_promotion_oracle_records_fed_bundle_bytes(
        tmp_path, monkeypatch, bundle_variant):
    """Promotion input-bound oracle: the stub hashes the bundle argument bytes."""
    from p11lab import inspection_bounded
    args = valid_gate_args(tmp_path, monkeypatch)
    honest_bytes = (PROMO / "promotion-bundle.json").read_bytes()
    tampered_bytes = (PROMO / "promotion-bundle-tampered.json").read_bytes()
    assert honest_bytes != tampered_bytes
    fed = honest_bytes if bundle_variant == "honest" else tampered_bytes
    (args["promotion_dir"] / "promotion-bundle.json").write_bytes(fed)
    inner = inspection_bounded.bounded_stream

    def oracle(argv, destination, max_bytes, timeout, env, record):
        if json.loads(Path(argv[3]).read_bytes()).get("role") == "image-promotion":
            bundle_arg = Path(argv[argv.index("--bundle") + 1])
            record["observed_bundle_path"] = str(bundle_arg)
            record["observed_bundle_sha256"] = hashlib.sha256(
                bundle_arg.read_bytes()).hexdigest()
        return inner(argv, destination, max_bytes, timeout, env, record)

    monkeypatch.setattr(inspection_bounded, "bounded_stream", oracle)
    assert publish.require_eligible_handoff(**args) == args["value"]
    journal = json.loads(
        (args["promotion_output_dir"] / "verifier-journal.json").read_text())
    assert journal["observed_bundle_path"] == str(
        args["promotion_output_dir"] / "bundle.json")
    assert journal["observed_bundle_sha256"] == hashlib.sha256(fed).hexdigest()
    assert journal["observed_bundle_sha256"] == hashlib.sha256(
        (args["promotion_dir"] / "promotion-bundle.json").read_bytes()
    ).hexdigest()
