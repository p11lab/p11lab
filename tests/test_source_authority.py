"""Local authority-boundary fixtures; they do not mint hosted authorization."""

import copy
import hashlib
from datetime import datetime, timezone

import pytest

from p11lab import delivery_authority as authority


def fixture():
    context = b'{"local":"fixture"}\n'
    profile = dict(
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
        role="source-producer",
        root_sha256="d" * 64,
        controller_sha256="e" * 64,
        environment_id=77,
        reviewer_ids=[101, 102],
        max_age_seconds=3600,
    )
    identity = dict(run_id=891, attempt=1, job="trusted-producer")
    workflow = "https://github.com/p11lab/controller/.github/workflows/provider-delivery.yml@refs/heads/main"
    cert = dict(
        issuer="https://token.actions.githubusercontent.com",
        subjectAlternativeName=workflow,
        buildSignerURI=workflow,
        buildSignerDigest="a" * 40,
        sourceRepositoryURI="https://github.com/p11lab/controller",
        sourceRepositoryIdentifier="1234",
        sourceRepositoryOwnerURI="https://github.com/p11lab",
        sourceRepositoryOwnerIdentifier="5678",
        sourceRepositoryDigest="b" * 40,
        sourceRepositoryRef="refs/heads/main",
        runnerEnvironment="github-hosted",
        runInvocationURI="https://github.com/p11lab/controller/actions/runs/891/attempts/1",
    )
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": authority.PREDICATE_TYPE,
        "subject": [
            {
                "name": "source-context.json",
                "digest": {"sha256": hashlib.sha256(context).hexdigest()},
            }
        ],
        "predicate": {"schema_version": 1},
    }
    result = [
        {
            "verificationResult": {
                "signature": {"certificate": cert},
                "verifiedTimestamps": [
                    {"type": "Tlog", "timestamp": "2026-10-28T12:00:00Z"}
                ],
                "statement": statement,
            }
        }
    ]
    return profile, identity, context, result


def test_verified_certificate_subject_and_run_are_bound():
    profile, identity, context, result = fixture()
    assert (
        authority._check_verified(
            result,
            profile,
            identity,
            context,
            datetime(2026, 10, 28, 12, 1, tzinfo=timezone.utc),
        )
        is None
    )


@pytest.mark.parametrize(
    "field",
    [
        "subjectAlternativeName",
        "buildSignerURI",
        "buildSignerDigest",
        "sourceRepositoryURI",
        "sourceRepositoryIdentifier",
        "sourceRepositoryOwnerIdentifier",
        "sourceRepositoryDigest",
        "sourceRepositoryRef",
        "runnerEnvironment",
        "runInvocationURI",
        "issuer",
    ],
)
def test_forged_certificate_identity_is_refused(field):
    profile, identity, context, result = fixture()
    result[0]["verificationResult"]["signature"]["certificate"][field] += "-lookalike"
    with pytest.raises(ValueError):
        authority._check_verified(
            result,
            profile,
            identity,
            context,
            datetime(2026, 10, 28, 12, 1, tzinfo=timezone.utc),
        )


@pytest.mark.parametrize(
    "damage",
    ["subject", "extra-subject", "predicate", "timestamp", "future", "extra-result"],
)
def test_ambiguous_or_changed_attestation_is_refused(damage):
    profile, identity, context, result = fixture()
    v = result[0]["verificationResult"]
    if damage == "subject":
        v["statement"]["subject"][0]["digest"]["sha256"] = "f" * 64
    if damage == "extra-subject":
        v["statement"]["subject"].append(copy.deepcopy(v["statement"]["subject"][0]))
    if damage == "predicate":
        v["statement"]["predicateType"] += "/lookalike"
    if damage == "timestamp":
        v["verifiedTimestamps"][0]["timestamp"] = "2026-10-27T12:00:00Z"
    if damage == "future":
        v["verifiedTimestamps"][0]["timestamp"] = "2026-10-29T12:00:00Z"
    if damage == "extra-result":
        result.append(copy.deepcopy(result[0]))
    with pytest.raises(ValueError):
        authority._check_verified(
            result,
            profile,
            identity,
            context,
            datetime(2026, 10, 28, 12, 1, tzinfo=timezone.utc),
        )


def test_unpinned_verifier_is_refused_before_execution(tmp_path):
    executable = tmp_path / "gh"
    executable.write_bytes(b"not the reviewed verifier")
    context = tmp_path / "source-context.json"
    context.write_bytes(b"{}")
    bundle = tmp_path / "bundle.json"
    bundle.write_bytes(b"{}")
    root = tmp_path / "root.jsonl"
    root.write_bytes(b"{}")
    with pytest.raises(ValueError, match="verifier.*digest"):
        authority._run_verifier(
            executable,
            context,
            bundle,
            root,
            hashlib.sha256(root.read_bytes()).hexdigest(),
            fixture()[0],
            tmp_path / "output",
        )
    assert not (tmp_path / "output").exists()


def test_missing_protected_profile_refuses_paired_or_forged_approval():
    with pytest.raises(ValueError, match="protected.*profile"):
        authority.load_profile("softhsm2", "release")
    with pytest.raises(TypeError):
        authority.load_profile("softhsm2", "release", profile={"approved": True})


def test_active_producer_api_metadata_requires_exact_identity_and_running_job():
    profile, identity, _, _ = fixture()
    attempt = {
        "id": 891,
        "run_attempt": 1,
        "workflow_id": 123,
        "head_sha": "b" * 40,
        "status": "in_progress",
        "repository": {"id": 1234, "owner": {"id": 5678}},
    }
    jobs = {
        "total_count": 1,
        "jobs": [
            {
                "name": "trusted-producer",
                "run_id": 891,
                "head_sha": "b" * 40,
                "status": "in_progress",
            }
        ],
    }
    authority._check_active_metadata(profile, identity, attempt, jobs)
    for altered in (
        "wrong-repo",
        "wrong-attempt",
        "wrong-job",
        "completed-job",
        "duplicate",
    ):
        a, j = copy.deepcopy(attempt), copy.deepcopy(jobs)
        if altered == "wrong-repo":
            a["repository"]["owner"]["id"] += 1
        if altered == "wrong-attempt":
            a["run_attempt"] += 1
        if altered == "wrong-job":
            j["jobs"][0]["name"] += "-lookalike"
        if altered == "completed-job":
            j["jobs"][0]["status"] = "completed"
        if altered == "duplicate":
            j["jobs"].append(copy.deepcopy(j["jobs"][0]))
            j["total_count"] = 2
        with pytest.raises(ValueError):
            authority._check_active_metadata(profile, identity, a, j)


def test_verified_context_requires_active_metadata_and_independent_controller_graph(
    tmp_path, monkeypatch
):
    import json

    profile, identity, _, result = fixture()
    profile.update(
        environment="softhsm2",
        channel="release",
        review_sha256="d" * 64,
        graph=[
            {"path": "workflow.yml", "sha256": hashlib.sha256(b"workflow").hexdigest()}
        ],
    )
    context = {
        "schema_version": 1,
        "environment": "softhsm2",
        "channel": "release",
        "role": "source-producer",
        "run": identity,
        "policy_sha256": profile["policy_sha256"],
        "review_sha256": profile["review_sha256"],
        "profile_sha256": authority._profile_digest(profile),
        "controller_sha256": profile["controller_sha256"],
        "payload": {"source": "local-fixture-only"},
    }
    raw = json.dumps(context, sort_keys=True).encode()
    result[0]["verificationResult"]["statement"]["subject"][0]["digest"]["sha256"] = (
        hashlib.sha256(raw).hexdigest()
    )
    attempt = {
        "id": 891,
        "run_attempt": 1,
        "workflow_id": 123,
        "head_sha": "b" * 40,
        "status": "in_progress",
        "repository": {"id": 1234, "owner": {"id": 5678}},
    }
    jobs = {
        "total_count": 1,
        "jobs": [
            {
                "name": "trusted-producer",
                "run_id": 891,
                "head_sha": "b" * 40,
                "status": "in_progress",
            }
        ],
    }

    class Transport:
        def __init__(self, repository, token):
            assert (
                repository == profile["repository"] and token == "fixture-actions-token"
            )

        def _metadata(self, path, deadline):
            return jobs if "/jobs?" in path else attempt

        def source_file(self, revision, path):
            assert revision == "b" * 40 and path == "workflow.yml"
            return b"workflow"

    monkeypatch.setattr(authority, "load_profile", lambda environment, channel: profile)
    monkeypatch.setattr(authority, "_run_verifier", lambda *args: (result, raw))
    monkeypatch.setattr(
        authority, "_clock", lambda: datetime(2026, 10, 28, 12, 1, tzinfo=timezone.utc)
    )
    monkeypatch.setattr(authority, "_github_transport", Transport)
    monkeypatch.setattr(
        authority,
        "_load_protection",
        lambda *args: {"environment_id": 77, "reviewer_id": 101},
    )
    monkeypatch.setattr(authority, "_check_local_controller", lambda profile: None)
    value = authority.verify_active_context(
        environment="softhsm2",
        channel="release",
        context_path=tmp_path / "context",
        bundle_path=tmp_path / "bundle",
        executable=tmp_path / "gh",
        trusted_root=tmp_path / "root",
        run_id=891,
        attempt=1,
        token="fixture-actions-token",
        output_dir=tmp_path / "out",
    )
    assert value == context
    attempt["head_sha"] = "f" * 40
    with pytest.raises(ValueError, match="identity"):
        authority.verify_active_context(
            environment="softhsm2",
            channel="release",
            context_path=tmp_path / "context",
            bundle_path=tmp_path / "bundle",
            executable=tmp_path / "gh",
            trusted_root=tmp_path / "root",
            run_id=891,
            attempt=1,
            token="fixture-actions-token",
            output_dir=tmp_path / "out",
        )
    monkeypatch.setattr(
        authority,
        "_check_local_controller",
        lambda profile: (_ for _ in ()).throw(
            ValueError("controller package mismatch")
        ),
    )
    with pytest.raises(ValueError, match="controller package"):
        authority.verify_active_context(
            environment="softhsm2",
            channel="release",
            context_path=tmp_path / "context",
            bundle_path=tmp_path / "bundle",
            executable=tmp_path / "gh",
            trusted_root=tmp_path / "root",
            run_id=891,
            attempt=1,
            token="fixture-actions-token",
            output_dir=tmp_path / "out",
        )


def test_protected_review_digest_covers_source_rights_not_private_cache_location():
    reference = {
        "kind": "docker-local",
        "reference": "sha256:" + "a" * 64,
        "sha256": "a" * 64,
    }
    inventory = {
        "artifact": reference,
        "observation": {"artifact": reference, "file": "candidate"},
        "build_key": "b" * 64,
        "reviews": [{"status": "reviewed", "source_redistribution": True}],
        "content_reviews": [],
        "patches": [],
        "sources": [],
        "components": [],
        "payloads": [
            {"path": "source.tar", "local_path": "/tmp/private-a", "sha256": "c" * 64}
        ],
    }
    changed = copy.deepcopy(inventory)
    changed["payloads"][0]["local_path"] = "/tmp/private-b"
    assert authority._review_digest(inventory) == authority._review_digest(changed)
    changed["reviews"][0]["source_redistribution"] = False
    assert authority._review_digest(inventory) != authority._review_digest(changed)


def test_controller_graph_rechecks_running_installed_code_against_selected_source(
    monkeypatch,
):
    from p11lab.round_core.artifacts import verify_profile_graph

    raw = b"protected controller code"
    graph = [
        {"path": "src/p11lab/publish.py", "sha256": hashlib.sha256(raw).hexdigest()}
    ]
    monkeypatch.setattr(authority, "_installed_control_file", lambda name: raw)
    authority._check_controller_graph(graph, lambda name: raw)
    monkeypatch.setattr(
        authority, "_installed_control_file", lambda name: b"candidate replacement"
    )
    with pytest.raises(ValueError, match="controller.*mismatch"):
        authority._check_controller_graph(graph, lambda name: raw)
    with pytest.raises(ValueError):
        verify_profile_graph(graph, lambda name: b"changed source")


def test_profile_cannot_authenticate_only_workflow_while_omitting_controller():
    profile, _, _, _ = fixture()
    profile.update(
        enabled=True,
        environment="softhsm2",
        channel="release",
        review_sha256="d" * 64,
        graph=[{"path": profile["workflow_path"], "sha256": "e" * 64}],
    )
    with pytest.raises(ValueError, match="controller"):
        authority._validate_profile(profile)


def test_controller_digest_covers_all_packaged_code_without_self_reference(tmp_path):
    (tmp_path / "module.py").write_bytes(b"one")
    profile = tmp_path / "data/ci/delivery/source-authority-profiles.json"
    profile.parent.mkdir(parents=True)
    profile.write_bytes(b"first profile")
    original = authority._controller_digest(tmp_path)
    profile.write_bytes(b"second profile")
    assert authority._controller_digest(tmp_path) == original
    (tmp_path / "module.py").write_bytes(b"two")
    assert authority._controller_digest(tmp_path) != original


def test_verifier_uses_supported_exact_identity_flags(tmp_path, monkeypatch):
    from p11lab import inspection_bounded

    executable = tmp_path / "gh"
    executable.write_bytes(b"fixture-gh")
    subject = tmp_path / "context"
    subject.write_bytes(b"{}")
    bundle = tmp_path / "bundle"
    bundle.write_bytes(b"{}")
    root = tmp_path / "root"
    root.write_bytes(b"{}")
    monkeypatch.setattr(
        authority, "GH_EXECUTABLE_SHA256", hashlib.sha256(b"fixture-gh").hexdigest()
    )
    seen = []

    def run(argv, destination, max_bytes, timeout, env, record):
        seen.extend(argv)
        destination.write_text("[]")
        record["returncode"] = 0

    monkeypatch.setattr(inspection_bounded, "bounded_stream", run)
    authority._run_verifier(
        executable,
        subject,
        bundle,
        root,
        hashlib.sha256(b"{}").hexdigest(),
        fixture()[0],
        tmp_path / "output",
    )
    assert "--cert-identity" in seen
    assert "--signer-workflow" not in seen
    assert "--signer-digest" in seen


def test_validation_rejects_self_consistent_but_empty_evidence(tmp_path, monkeypatch):
    import io
    import json
    import tarfile
    from p11lab import image_validation
    from p11lab.image_validation import _source_digest
    from p11lab.models import ArtifactRef

    artifact = ArtifactRef(
        "docker-local", "sha256:" + "a" * 64, "a" * 64, "linux/amd64"
    )
    observation = {
        "distribution": {"config_sha256": "b" * 64, "layers": [{"sha256": "c" * 64}]}
    }
    data = b"raw evaluator evidence"
    validation = {
        "schema_version": 1,
        "kind": "local-image-validation",
        "artifact": vars(artifact),
        "status": "observations-complete",
        "infrastructure_errors": [],
        "sharing": "local-evidence-package",
        "fixed_policy_sha256": "d" * 64,
        "control_source_sha256": _source_digest(),
        "control_base_revision_declared": "c" * 40,
        "image_binding": {
            "engine_id": artifact.reference,
            "config_sha256": "b" * 64,
            "layers": [{"sha256": "c" * 64}],
            "build_key_label": "e" * 64,
        },
        "checker": {"summary": {"incomplete": False}},
        "consumer": {"app_returncode": 0},
        "admission": {"admission": {"admitted": True}},
        "oracle": {
            "cleanup_errors": [],
            "controls": {
                n: {
                    "returncode": code,
                    "timed_out": False,
                    "cleanup": "removed-exact-owned-container",
                }
                for n, code in [
                    ("positive", 0),
                    ("altered_message", 1),
                    ("altered_signature", 1),
                ]
            },
        },
    }
    body_raw = json.dumps(validation, sort_keys=True).encode()
    roster = {
        "files": [
            {
                "path": "checker/raw.json",
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            },
            {
                "path": "validation-body.json",
                "size": len(body_raw),
                "sha256": hashlib.sha256(body_raw).hexdigest(),
            },
        ]
    }
    manifest = json.dumps(roster, sort_keys=True).encode()
    archive = tmp_path / "package.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        for name, raw in [
            ("checker/raw.json", data),
            ("validation-body.json", body_raw),
            ("evidence-manifest.json", manifest),
        ]:
            item = tarfile.TarInfo(name)
            item.size = len(raw)
            tar.addfile(item, io.BytesIO(raw))
    validation["package"] = {
        "path": archive.name,
        "size": archive.stat().st_size,
        "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
    }
    validation["body"] = {
        "path": "validation-body.json",
        "size": len(body_raw),
        "sha256": hashlib.sha256(body_raw).hexdigest(),
    }
    path = tmp_path / "validation.json"
    path.write_text(json.dumps(validation))
    with pytest.raises(ValueError, match="evidence roster"):
        authority._verify_validation_package(
            tmp_path, artifact, observation, "d" * 64, "e" * 64, "c" * 40
        )
    # The small fixture cannot satisfy the fixed roster; bypass it so the
    # gate mutants below reach the body-compare layer they pin.
    monkeypatch.setattr(image_validation, "check_evidence_roster", lambda entries, selected: None)
    for key in ("candidate", "policy", "layer", "archive", "readiness", "controller", "revision"):
        changed = copy.deepcopy(validation)
        if key == "candidate":
            changed["artifact"]["sha256"] = "f" * 64
        if key == "policy":
            changed["fixed_policy_sha256"] = "f" * 64
        if key == "layer":
            changed["image_binding"]["layers"] = []
        if key == "archive":
            changed["package"]["sha256"] = "f" * 64
        if key == "readiness":
            changed["infrastructure_errors"] = ["lost cleanup"]
        if key == "controller":
            changed["control_source_sha256"] = "f" * 64
        if key == "revision":
            changed["control_base_revision_declared"] = "f" * 40
        path.write_text(json.dumps(changed))
        expected = "package digest" if key == "archive" else "body differs from envelope"
        with pytest.raises(ValueError, match=expected):
            authority._verify_validation_package(
                tmp_path, artifact, observation, "d" * 64, "e" * 64, "c" * 40
            )
    # The outer package hash can be recomputed after tampering; the inner
    # declared manifest must still match the actual member bytes.
    wrong_manifest = copy.deepcopy(roster)
    wrong_manifest["files"][0]["sha256"] = "0" * 64
    with tarfile.open(archive, "w:gz") as tar:
        for name, raw in [("checker/raw.json", data),
                          ("evidence-manifest.json", json.dumps(wrong_manifest).encode())]:
            item = tarfile.TarInfo(name)
            item.size = len(raw)
            tar.addfile(item, io.BytesIO(raw))
    validation["package"]["size"] = archive.stat().st_size
    validation["package"]["sha256"] = hashlib.sha256(archive.read_bytes()).hexdigest()
    path.write_text(json.dumps(validation))
    with pytest.raises(ValueError, match="package roster mismatch"):
        authority._verify_validation_package(
            tmp_path, artifact, observation, "d" * 64, "e" * 64, "c" * 40
        )


def test_installed_policy_must_match_protected_profile(monkeypatch):
    profile, _, _, _ = fixture()
    monkeypatch.setattr(
        authority, "_controller_digest", lambda root: profile["controller_sha256"]
    )
    monkeypatch.setattr(
        authority, "_installed_control_file", lambda name: b"different policy"
    )
    with pytest.raises(ValueError, match="policy"):
        authority._check_local_controller(profile)


def test_source_prepublication_refuses_unreviewed_or_changed_review_before_collection(
    tmp_path, monkeypatch
):
    import json
    from p11lab.models import ArtifactRef
    from p11lab import sources

    artifact = ArtifactRef(
        "docker-local", "sha256:" + "a" * 64, "a" * 64, "linux/amd64"
    )
    reference = vars(artifact)
    inventory = {
        "artifact": reference,
        "observation": {"artifact": reference},
        "reviews": [{"source_redistribution": False}],
        "payloads": [],
    }
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps(inventory))
    profile = {"review_sha256": "f" * 64}
    monkeypatch.setattr(authority, "load_profile", lambda environment, channel: profile)
    monkeypatch.setattr(authority, "_authenticate_live_run", lambda *args, **kwargs: None)
    calls = []
    monkeypatch.setattr(
        sources,
        "collect_source_bundle",
        lambda *args, **kwargs: calls.append("collect"),
    )
    with pytest.raises(ValueError, match="review"):
        authority.prepare_source(
            environment="softhsm2",
            channel="release",
            artifact=artifact,
            inventory_path=path,
            validation_dir=tmp_path / "validation",
            build_receipt=tmp_path / "build",
            sealed_dir=tmp_path / "seal",
            output_dir=tmp_path / "output",
            run_id=9,
            attempt=1,
            token="fixture",
        )
    assert calls == []


def test_context_builder_binds_exact_runtime_and_has_no_eligibility_waiver():
    profile, identity, _, _ = fixture()
    facts = {
        "artifact": {"kind": "docker-local", "sha256": "a" * 64},
        "build_key": "b" * 64,
        "source": {"sealed": "c" * 64, "content": "d" * 64},
    }
    context = authority._make_context("softhsm2", "release", profile, identity, facts)
    assert context["payload"] == facts
    assert context["profile_sha256"] == authority._profile_digest(profile)
    assert context["controller_sha256"] == profile["controller_sha256"]
    assert "eligible" not in context and "promotable" not in context


def test_source_facts_recompute_both_readbacks_and_refuse_changed_content(
    tmp_path, monkeypatch
):
    import json
    import shutil
    from dataclasses import asdict
    from p11lab import licenses, publish, sources, source_transport
    from p11lab.models import ArtifactRef
    from test_publish import admission_inventory, seal_fixture, build_receipt_for
    from test_source_delivery import oci_manifest

    spec, seal_receipt, sealed = seal_fixture(tmp_path)
    artifact = ArtifactRef(
        "docker-local", "sha256:" + "a" * 64, "a" * 64, "linux/amd64"
    )
    _, inventory = admission_inventory(tmp_path)
    inventory["artifact"] = asdict(artifact)
    inventory["observation"]["artifact"] = asdict(artifact)
    inventory["build_key"] = sealed["build_key"]
    monkeypatch.setattr(
        licenses, "inspect_artifact", lambda *args, **kwargs: inventory["observation"]
    )
    evidence = tmp_path / "evidence"
    sources.collect_source_bundle(artifact, inventory, evidence)
    build = build_receipt_for(
        tmp_path, spec, seal_receipt, sealed, artifact=asdict(artifact)
    )
    manifests = {}
    for role, root, roster in [
        ("seal", tmp_path / "seal", publish.SEAL_FILES),
        ("content", evidence, publish.CONTENT_FILES),
    ]:
        path = oci_manifest(tmp_path / (role + ".json"), root, roster)
        manifests[role] = (hashlib.sha256(path.read_bytes()).hexdigest(), path, root)

    def fetch(repository, digest, expected, *, artifact_type, output_dir):
        selected = next(v for v in manifests.values() if v[0] == digest)
        output_dir.mkdir(parents=True)
        shutil.copyfile(selected[1], output_dir / "manifest.json")
        (output_dir / "files").mkdir()
        for name in expected:
            shutil.copyfile(selected[2] / name, output_dir / "files" / name)
        (output_dir / "transport-journal.json").write_text('{"fixture": true}')

    monkeypatch.setattr(source_transport, "acquire", fetch)
    monkeypatch.setattr(
        authority,
        "_verify_validation_package",
        lambda *args: {"validation_sha256": "d" * 64},
    )
    profile = {
        "review_sha256": authority._review_digest(inventory),
        "policy_sha256": "e" * 64,
        "source_sha": "c" * 40,
    }
    facts = authority._source_facts(
        environment="softhsm2",
        channel="release",
        artifact=artifact,
        evidence_dir=evidence,
        validation_dir=tmp_path / "validation",
        build_receipt=build,
        sealed_dir=tmp_path / "seal",
        registry="ghcr.io/p11lab/softhsm2",
        seal_digest=manifests["seal"][0],
        content_digest=manifests["content"][0],
        output_dir=tmp_path / "facts",
        profile=profile,
    )
    assert facts["artifact"] == asdict(artifact)
    assert facts["source"]["content"]["manifest_sha256"] == manifests["content"][0]
    receipt = json.loads((evidence / "source-companion.json").read_text())
    receipt["inventory_sha256"] = "f" * 64
    (evidence / "source-companion.json").write_text(json.dumps(receipt))
    with pytest.raises(ValueError):
        authority._source_facts(
            environment="softhsm2",
            channel="release",
            artifact=artifact,
            evidence_dir=evidence,
            validation_dir=tmp_path / "validation",
            build_receipt=build,
            sealed_dir=tmp_path / "seal",
            registry="ghcr.io/p11lab/softhsm2",
            seal_digest=manifests["seal"][0],
            content_digest=manifests["content"][0],
            output_dir=tmp_path / "damaged",
            profile=profile,
        )


def test_source_admission_requires_recomputed_facts_and_never_grants_promotion(
    tmp_path, monkeypatch
):
    from p11lab.models import ArtifactRef

    artifact = ArtifactRef(
        "docker-local", "sha256:" + "a" * 64, "a" * 64, "linux/amd64"
    )
    profile, identity, _, _ = fixture()
    profile.update(review_sha256="d" * 64)
    facts = {
        "artifact": vars(artifact),
        "build_key": "b" * 64,
        "source": {"content": "c" * 64},
    }
    attested = authority._make_context("softhsm2", "release", profile, identity, facts)
    import json

    (tmp_path / "context").write_text(json.dumps(attested))
    monkeypatch.setattr(authority, "load_profile", lambda environment, channel: profile)

    def verified(**kwargs):
        kwargs["output_dir"].mkdir()
        (kwargs["output_dir"] / "source-context.json").write_bytes(
            (tmp_path / "context").read_bytes()
        )
        return attested

    monkeypatch.setattr(authority, "verify_active_context", verified)
    monkeypatch.setattr(authority, "_authenticate_live_run", lambda *args, **kwargs: None)
    monkeypatch.setattr(authority, "_source_facts", lambda **kwargs: facts)
    kwargs = dict(
        environment="softhsm2",
        channel="release",
        artifact=artifact,
        evidence_dir=tmp_path / "evidence",
        validation_dir=tmp_path / "validation",
        build_receipt=tmp_path / "build",
        sealed_dir=tmp_path / "seal",
        registry="ghcr.io/p11lab/softhsm2",
        seal_digest="c" * 64,
        content_digest="d" * 64,
        context_path=tmp_path / "context",
        bundle_path=tmp_path / "bundle",
        executable=tmp_path / "gh",
        trusted_root=tmp_path / "root",
        run_id=891,
        attempt=1,
        token="fixture-actions-token",
    )
    result = authority.admit_source(output_dir=tmp_path / "good", **kwargs)
    assert result["source_status"] == "eligible"
    assert result["image_promotion_status"] == "blocked"
    assert result["handoff_eligible"] is False
    monkeypatch.setattr(
        authority, "_source_facts", lambda **kwargs: facts | {"build_key": "f" * 64}
    )
    with pytest.raises(ValueError, match="recomputed"):
        authority.admit_source(output_dir=tmp_path / "bad", **kwargs)
    assert not (tmp_path / "bad" / "source-admission.json").exists()


def test_cli_exposes_source_preparation_with_no_profile_selection_bypass(
    tmp_path, monkeypatch, capsys
):
    import json
    from p11lab import cli

    artifact = tmp_path / "artifact.json"
    artifact.write_text(
        json.dumps(
            {
                "artifact": {
                    "kind": "docker-local",
                    "reference": "sha256:" + "a" * 64,
                    "sha256": "a" * 64,
                    "platform": "linux/amd64",
                }
            }
        )
    )
    monkeypatch.setenv("GITHUB_RUN_ID", "9")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")
    monkeypatch.setenv("GH_TOKEN", "fixture-token")
    policy = tmp_path / "policy.json"
    policy.write_text("{}")
    code = cli.main(
        [
            "publish",
            "prepare-source",
            "softhsm2",
            "--channel",
            "release",
            "--artifact",
            str(artifact),
            "--inventory",
            str(tmp_path / "inventory"),
            "--validation-dir",
            str(tmp_path / "validation"),
            "--validation-policy",
            str(policy),
            "--build-receipt",
            str(tmp_path / "build"),
            "--sealed-dir",
            str(tmp_path / "seal"),
            "--output-dir",
            str(tmp_path / "out"),
        ]
    )
    assert code != 0
    assert "protected source producer profile" in capsys.readouterr().err


def test_tool_preparation_refuses_unconfigured_profile_before_any_build(
    tmp_path, monkeypatch
):
    from p11lab import tool_builds

    builds = []
    monkeypatch.setattr(
        tool_builds, "build_tool", lambda *args, **kwargs: builds.append(True)
    )
    with pytest.raises(ValueError, match="protected source producer profile"):
        authority.prepare_validation_tools(tmp_path / "tools")
    assert not builds
    assert not (tmp_path / "tools").exists()


def test_producer_preflight_fails_closed_without_enrollment(monkeypatch, capsys):
    from p11lab import cli

    monkeypatch.setenv("GITHUB_RUN_ID", "9")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "1")
    monkeypatch.setenv("GH_TOKEN", "fixture-token")
    assert (
        cli.main(["publish", "check-producer", "softhsm2", "--channel", "release"]) != 0
    )
    assert "protected source producer profile" in capsys.readouterr().err


def test_delivery_workflow_uploads_custody_only_after_actual_source_d():
    from pathlib import Path

    workflow = (
        Path(__file__).resolve().parents[1] / ".github/workflows/provider-delivery.yml"
    ).read_text()
    source_d = workflow.index("p11lab publish admit-source")
    first_upload = workflow.index("actions/upload-artifact@")
    assert source_d < first_upload
    assert "always()" not in workflow and "failure()" not in workflow
    assert "actions/cache@" not in workflow
    assert "docker save" not in workflow and "docker image save" not in workflow
    assert workflow.count("runs-on:") == 1
    markers = [
        "p11lab image validate-local",
        "p11lab publish prepare-source",
        "application/vnd.p11lab.sealed-source.v1",
        "application/vnd.p11lab.source-companion.v1",
        "p11lab publish source-context",
        "actions/attest@",
        "p11lab publish admit-source",
    ]
    positions = [workflow.index(marker) for marker in markers]
    assert positions == sorted(positions)
    policy = '--validation-policy "$RUNNER_TEMP/p11lab-tools/validation-policy.json"'
    assert workflow.count(policy) >= 3
    for operation in ("prepare-source", "source-context", "admit-source"):
        command = workflow.split("p11lab publish " + operation, 1)[1].split("\n\n", 1)[0]
        assert policy in command
    assert "p11lab custody component-sources" in workflow
    assert "p11lab custody prepare" in workflow
    assert "p11lab custody finalize" in workflow
    assert "https://p11lab.org/attestations/image-custody/v1" in workflow
    assert "retention-days: 14" in workflow
    assert "id-token: write" in workflow and "attestations: write" in workflow
    assert "persist-credentials: false" in workflow
    assert "runtime exposure and handoff remain blocked" in workflow


def test_inventory_materialization_refuses_unenrolled_profile_before_inspection(
    tmp_path, monkeypatch
):
    from p11lab import licenses
    from p11lab.models import ArtifactRef

    artifact = ArtifactRef(
        "docker-local", "sha256:" + "a" * 64, "a" * 64, "linux/amd64"
    )
    observed = []
    monkeypatch.setattr(
        licenses, "inspect_artifact", lambda *args, **kwargs: observed.append(True)
    )
    with pytest.raises(ValueError, match="protected source producer profile"):
        authority.materialize_inventory(
            artifact=artifact,
            build_receipt=tmp_path / "build",
            output_dir=tmp_path / "out",
        )
    assert not observed


def test_protected_environment_and_real_run_approval_must_match_owner_pins():
    profile, identity, _, _ = fixture()
    profile.update(environment_id=77, reviewer_ids=[101, 102])
    environment = {
        "id": 77,
        "name": "source-delivery",
        "deployment_branch_policy": {
            "protected_branches": False,
            "custom_branch_policies": True,
        },
        "protection_rules": [
            {
                "type": "required_reviewers",
                "prevent_self_review": True,
                "reviewers": [
                    {"type": "User", "reviewer": {"id": 101}},
                    {"type": "User", "reviewer": {"id": 102}},
                ],
            }
        ],
    }
    branches = {"total_count": 1, "branch_policies": [{"id": 5, "name": "main"}]}
    approvals = [
        {
            "state": "approved",
            "user": {"id": 101},
            "environments": [{"id": 77, "name": "source-delivery"}],
        }
    ]
    run = {"triggering_actor": {"id": 900}}
    authority._check_protection(profile, environment, branches, approvals, run)
    for damage in (
        "unprotected",
        "self-review",
        "wrong-reviewer",
        "wrong-branch",
        "forged-approval",
        "ambiguous",
    ):
        env, branch, approval = (
            copy.deepcopy(environment),
            copy.deepcopy(branches),
            copy.deepcopy(approvals),
        )
        if damage == "unprotected":
            env["protection_rules"] = []
        if damage == "self-review":
            env["protection_rules"][0]["prevent_self_review"] = False
        if damage == "wrong-reviewer":
            env["protection_rules"][0]["reviewers"][0]["reviewer"]["id"] = 999
        if damage == "wrong-branch":
            branch["branch_policies"][0]["name"] = "*"
        if damage == "forged-approval":
            approval[0]["user"]["id"] = 900
        if damage == "ambiguous":
            approval.append(copy.deepcopy(approval[0]))
        with pytest.raises(ValueError):
            authority._check_protection(profile, env, branch, approval, run)


def test_rerun_attempt_cannot_reuse_run_level_approval(monkeypatch):
    profile, _, _, _ = fixture()
    calls = []
    monkeypatch.setattr(authority, '_github_transport', lambda *args: calls.append(True))
    with pytest.raises(ValueError, match='run identity'):
        authority._authenticate_live_run(profile, 891, 2, 'fixture-token')
    assert calls == []


def test_template_review_identity_is_stable_when_candidate_observation_is_added():
    template = {'schema_version': 1, 'artifact': None, 'observation': None, 'build_key': None,
        'payloads': [{'path': 'src.tar', 'sha256': 'a'*64, 'local_path': '/tmp/source'}],
        'reviews': [{'source': 'demo=1', 'status': 'unreviewed'}]}
    materialized = copy.deepcopy(template)
    ref = {'kind': 'docker-local', 'reference': 'sha256:'+'b'*64, 'sha256': 'b'*64}
    materialized.update(artifact=ref, observation={'artifact': ref}, build_key='c'*64)
    assert authority._review_digest(template) == authority._review_digest(materialized)


def test_controller_identity_is_diagnostic_and_does_not_invent_review():
    value = authority.controller_identity()
    assert len(value['controller_sha256']) == 64
    assert len(value['review_sha256']) == 64
    assert value['configured_profiles'] == 0
    assert value['authority'] == 'unverified-local-identities'


def test_workflow_cross_checks_environment_scoped_pin_before_installing_controller():
    from pathlib import Path
    workflow = (Path(__file__).resolve().parents[1] / '.github/workflows/provider-delivery.yml').read_text()
    api = '/environments/source-delivery/variables/'
    assert api in workflow
    assert 'P11LAB_ENVIRONMENT_READER_TOKEN' in workflow
    assert 'unset P11LAB_ENVIRONMENT_READER_TOKEN' in workflow
    assert workflow.index(api) < workflow.index('python -m pip install --no-index --no-deps')
    assert 'class NoRedirect(HTTPRedirectHandler)' in workflow
    assert 'ProxyHandler({})' in workflow
    assert 'environment: source-delivery' in workflow


def test_source_admission_rejects_unreviewed_other_catalogue_until_supported(tmp_path, monkeypatch):
    from p11lab.models import ArtifactRef
    artifact = ArtifactRef('docker-local', 'sha256:' + 'a'*64, 'a'*64, 'linux/amd64')
    monkeypatch.setattr(authority, 'load_profile', lambda *args: {'review_sha256': 'b'*64})
    monkeypatch.setattr(authority, '_authenticate_live_run', lambda *args, **kwargs: None)
    with pytest.raises(ValueError, match='softhsm2'):
        authority.prepare_source(environment='other', channel='release', artifact=artifact,
            inventory_path=tmp_path/'inventory', validation_dir=tmp_path/'validation', build_receipt=tmp_path/'build',
            sealed_dir=tmp_path/'seal', output_dir=tmp_path/'out', run_id=1, attempt=1, token='fixture')


def test_unrepresented_build_context_asset_blocks_source_admission():
    from p11lab.catalog import load_environment
    spec = load_environment('softhsm2', 'release')
    authority._require_covered_build_assets(spec)
    modified = copy.deepcopy(spec)
    modified['lock']['assets'].append({'role': 'dependency-lock', 'path': 'new.lock', 'sha256': 'a'*64})
    with pytest.raises(ValueError, match='build input'):
        authority._require_covered_build_assets(modified)


def test_custody_workflow_freezes_and_uploads_exact_parts(tmp_path):
    import json
    import os
    from pathlib import Path
    import subprocess
    import sys
    import textwrap

    from p11lab.image_custody import SEGMENT_ROLES

    workflow = (Path(__file__).resolve().parents[1] / '.github/workflows/provider-delivery.yml').read_text()
    plan = workflow.split('id: custody_plan', 1)[1].split('      - name:', 1)[0]
    script = textwrap.dedent(plan.split("          python - <<'PYCODE'\n", 1)[1].split('          PYCODE\n', 1)[0])
    parts = [{'role': role, 'part': part} for role in SEGMENT_ROLES for part in ((1, 2) if role == 'checker-tool' else (1,))]
    (tmp_path / 'custody-prepared.json').write_text(json.dumps({'parts': parts}))
    env = dict(os.environ, GITHUB_OUTPUT=str(tmp_path / 'output'))
    completed = subprocess.run([sys.executable, '-I', '-B', '-c', script], cwd=tmp_path, env=env, capture_output=True, text=True)
    assert completed.returncode == 0, completed.stderr
    assert (tmp_path / 'output').read_text().splitlines() == [
        role.replace('-', '_') + '_part2=' + ('yes' if role == 'checker-tool' else 'no') for role in SEGMENT_ROLES
    ]
    parts.append(parts[0])
    (tmp_path / 'custody-prepared.json').write_text(json.dumps({'parts': parts}))
    assert subprocess.run([sys.executable, '-I', '-B', '-c', script], cwd=tmp_path, env=env, capture_output=True).returncode != 0
    for role in SEGMENT_ROLES:
        for part in (1, 2):
            block = workflow.split(f'      - name: Upload fixed custody {role} part {part}\n', 1)[1].split('      - name:', 1)[0]
            assert 'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02' in block
            assert f'path: custody-out/parts/{role}-part{part}/' in block
            assert 'if-no-files-found: error' in block and 'retention-days: 14' in block
            if part == 2:
                assert f"success() && steps.custody_plan.outputs.{role.replace('-', '_')}_part2 == 'yes'" in block
    assert workflow.index('p11lab custody finalize') > workflow.index('Upload fixed custody tool-inputs part 2')
    assert workflow.index('Attest the checked custody finalization') > workflow.index('p11lab custody finalize')


def test_custody_workflow_forwards_upload_ids_and_checks_digest_format(tmp_path):
    import json
    import os
    from pathlib import Path
    import subprocess
    import sys
    import textwrap

    workflow = (Path(__file__).resolve().parents[1] / '.github/workflows/provider-delivery.yml').read_text()
    step = workflow.split('      - name: Verify uploaded bytes and prepare external finalization\n', 1)[1]
    script = textwrap.dedent(step.split("          python - <<'PYCODE'\n", 1)[1].split('          PYCODE\n', 1)[0])
    parts = [{'role': 'image', 'part': 1, 'name': 'fixed-image'},
             {'role': 'checker-tool', 'part': 2, 'name': 'fixed-checker'}]
    (tmp_path / 'custody-prepared.json').write_text(json.dumps({'parts': parts}))
    env = dict(os.environ, IMAGE_1_ID='123', IMAGE_1_DIGEST='a' * 64,
               CHECKER_TOOL_2_ID='456', CHECKER_TOOL_2_DIGEST='b' * 64)
    def run():
        return subprocess.run([sys.executable, '-I', '-B', '-c', script], cwd=tmp_path,
                              env=env, capture_output=True, text=True)
    result = run()
    assert result.returncode == 0, result.stderr
    assert json.loads((tmp_path / 'custody-uploads.json').read_text()) == [
        {'name': 'fixed-image', 'id': 123, 'digest': 'sha256:' + 'a' * 64},
        {'name': 'fixed-checker', 'id': 456, 'digest': 'sha256:' + 'b' * 64},
    ]
    env['CHECKER_TOOL_2_DIGEST'] = 'bad'
    assert run().returncode != 0
    env['CHECKER_TOOL_2_DIGEST'] = 'b' * 64
    env['IMAGE_1_ID'] = '0'
    assert run().returncode != 0
