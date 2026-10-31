"""Bounded custody transport refuses unsafe archives and preserves source limits."""

import hashlib
import stat
import zipfile

import pytest

from p11lab.round_core import artifacts, inputs


def _entry(raw):
    return {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def test_custody_streams_above_source_limit_without_forwarding_token(
    tmp_path, monkeypatch
):
    block = b"x" * 65536
    count = 641
    digest = hashlib.sha256()
    for _ in range(count):
        digest.update(block)

    class Response:
        status = 200
        headers = {}

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read1(self, size):
            assert size <= 65536
            self.calls += 1
            return block if self.calls <= count else b""

        calls = 0

    requests = []

    class Opener:
        def open(self, request, timeout):
            requests.append(dict(request.header_items()))
            assert timeout <= 15
            return Response()

    monkeypatch.setattr(artifacts, "build_opener", lambda *args: Opener())
    client = artifacts.GitHubTransport("owner/repo", "secret")
    monkeypatch.setattr(
        client,
        "_request",
        lambda *args: (
            302,
            {"location": "https://store.blob.core.windows.net/object?secret=hidden"},
            b"",
        ),
    )
    path = tmp_path / "custody.zip"
    metadata = artifacts.CustodyArtifactBytes(
        9, len(block) * count, "sha256:" + digest.hexdigest()
    )
    client.download_custody(metadata, path)
    assert path.stat().st_size > inputs.SOURCE_ARCHIVE_LIMIT
    assert not any(key.lower() == "authorization" for key in requests[0])
    with pytest.raises(FileExistsError):
        client.download_custody(metadata, path)
    with pytest.raises(ValueError, match="source archive"):
        inputs.read_source_archive(path)


def test_custody_zip_extracts_only_closed_regular_roster(tmp_path):
    raw = b"image bytes"
    path = tmp_path / "custody.zip"
    with zipfile.ZipFile(path, "w") as out:
        out.writestr("image.tar", raw)
    target = tmp_path / "payload"
    inputs.extract_custody_archive(path, {"image.tar": _entry(raw)}, target)
    assert (target / "image.tar").read_bytes() == raw


@pytest.mark.parametrize(
    "mutation", ["traversal", "duplicate", "link", "wrong", "extra", "crc"]
)
def test_custody_zip_rejects_unsafe_or_changed_members(tmp_path, mutation):
    path = tmp_path / "custody.zip"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as out:
        if mutation == "link":
            info = zipfile.ZipInfo("image.tar")
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            out.writestr(info, b"image bytes")
        else:
            out.writestr(
                "image.tar", b"wrong bytes" if mutation == "wrong" else b"image bytes"
            )
        if mutation == "traversal":
            out.writestr("../escape", b"x")
        if mutation == "extra":
            out.writestr("extra", b"x")
        if mutation == "duplicate":
            with pytest.warns(UserWarning):
                out.writestr("image.tar", b"image bytes")
    if mutation == "crc":
        content = path.read_bytes().replace(b"image bytes", b"IMAGE bytes", 1)
        path.write_bytes(content)
    with pytest.raises(ValueError):
        inputs.extract_custody_archive(
            path, {"image.tar": _entry(b"image bytes")}, tmp_path / "payload"
        )


def test_custody_stream_refuses_partial_or_wrong_bytes(tmp_path, monkeypatch):
    class Response:
        status = 200
        headers = {}

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read1(self, size):
            if not getattr(self, "done", False):
                self.done = True
                return b"bad"
            return b""

    class Opener:
        def open(self, request, timeout):
            return Response()

    monkeypatch.setattr(artifacts, "build_opener", lambda *args: Opener())
    client = artifacts.GitHubTransport("owner/repo", "secret")
    monkeypatch.setattr(
        client,
        "_request",
        lambda *args: (
            302,
            {"location": "https://store.blob.core.windows.net/object"},
            b"",
        ),
    )
    path = tmp_path / "partial.zip"
    with pytest.raises(ValueError, match="size, digest or deadline"):
        client.download_custody(
            artifacts.CustodyArtifactBytes(1, 4, "sha256:" + "a" * 64), path
        )
    assert path.read_bytes() == b"bad"


def test_custody_stream_refuses_unapproved_redirect_without_output(
    tmp_path, monkeypatch
):
    client = artifacts.GitHubTransport("owner/repo", "secret")
    monkeypatch.setattr(
        client,
        "_request",
        lambda *args: (
            302,
            {"location": "https://evil.example/object?token=secret"},
            b"",
        ),
    )
    with pytest.raises(
        ValueError, match="unapproved artifact redirect origin"
    ) as error:
        client.download_custody(
            artifacts.CustodyArtifactBytes(1, 3, "sha256:" + "a" * 64),
            tmp_path / "partial.zip",
        )
    assert "secret" not in str(error.value)
    assert not (tmp_path / "partial.zip").exists()


def test_custody_transport_rejects_untyped_metadata(tmp_path, monkeypatch):
    client = artifacts.GitHubTransport("owner/repo", "secret")
    monkeypatch.setattr(
        client,
        "_request",
        lambda *args: (_ for _ in ()).throw(
            AssertionError("network must not be reached")
        ),
    )
    with pytest.raises(ValueError, match="typed custody artifact"):
        client.download_custody(
            {"id": 1, "size_in_bytes": 3, "digest": "sha256:" + "a" * 64},
            tmp_path / "x",
        )


def test_custody_zip_rejects_nul_filename_alias(tmp_path):
    path = tmp_path / "custody.zip"
    with zipfile.ZipFile(path, "w") as out:
        out.writestr("aXfile", b"x")
    path.write_bytes(path.read_bytes().replace(b"aXfile", b"a\x00file"))
    with pytest.raises(ValueError):
        inputs.extract_custody_archive(path, {"a": _entry(b"x")}, tmp_path / "payload")


@pytest.mark.parametrize(
    "id_,size,digest",
    [
        (True, 1, "sha256:" + "a" * 64),
        (1, True, "sha256:" + "a" * 64),
        (1, inputs.CUSTODY_ZIP_LIMIT + 1, "sha256:" + "a" * 64),
        (1, 1, "a" * 64),
    ],
)
def test_custody_byte_identity_has_fixed_policy(id_, size, digest):
    with pytest.raises(ValueError, match="invalid custody artifact identity"):
        artifacts.CustodyArtifactBytes(id_, size, digest)


def test_custody_zip_refuses_oversized_roster_before_extract(tmp_path):
    path = tmp_path / "not-used.zip"
    path.write_bytes(b"x")
    with pytest.raises(ValueError, match="invalid custody roster entry"):
        inputs.extract_custody_archive(
            path,
            {
                "image.tar": {
                    "size": inputs.CUSTODY_MEMBER_LIMIT + 1,
                    "sha256": "a" * 64,
                }
            },
            tmp_path / "payload",
        )
    assert not (tmp_path / "payload").exists()


def _metadata_fixture():
    from datetime import datetime, timezone

    identity = {
        "run_id": 100,
        "attempt": 1,
        "workflow_id": 20,
        "repository_id": 30,
        "owner_id": 40,
        "head_sha": "a" * 40,
        "job_name": "trusted-producer",
        "job_id": 50,
        "artifact_id": 60,
        "name": "custody-100-1",
    }
    run = {
        "id": 100,
        "run_attempt": 1,
        "workflow_id": 20,
        "head_sha": "a" * 40,
        "repository": {"id": 30, "owner": {"id": 40}},
        "status": "completed",
        "conclusion": "success",
        "run_started_at": "2026-10-28T10:00:00Z",
    }
    job = {
        "id": 50,
        "run_id": 100,
        "head_sha": "a" * 40,
        "name": "trusted-producer",
        "status": "completed",
        "conclusion": "success",
        "started_at": "2026-10-28T10:01:00Z",
        "completed_at": "2026-10-28T11:00:00Z",
    }
    artifact = {
        "id": 60,
        "name": "custody-100-1",
        "size_in_bytes": 10,
        "digest": "sha256:" + "b" * 64,
        "expired": False,
        "created_at": "2026-10-28T10:30:00Z",
        "expires_at": "2026-11-11T10:30:00Z",
        "workflow_run": {"id": 100, "repository_id": 30, "head_sha": "a" * 40},
    }
    return (
        identity,
        run,
        {"total_count": 1, "jobs": [job]},
        {"total_count": 1, "artifacts": [artifact]},
        datetime(2026, 10, 29, tzinfo=timezone.utc),
    )


def test_completed_custody_metadata_selects_exact_unexpired_artifact():
    identity, run, jobs, listing, now = _metadata_fixture()
    assert (
        inputs.select_custody_artifact(identity, run, jobs, listing, now=now)
        == listing["artifacts"][0]
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "run_failure",
        "job_running",
        "job_id",
        "owner",
        "artifact_id",
        "expired",
        "expiry",
        "digest",
        "time",
        "ambiguous",
    ],
)
def test_completed_custody_metadata_refuses_inconsistent_observations(mutation):
    identity, run, jobs, listing, now = _metadata_fixture()
    artifact = listing["artifacts"][0]
    job = jobs["jobs"][0]
    if mutation == "run_failure":
        run["conclusion"] = "failure"
    if mutation == "job_running":
        job["status"] = "in_progress"
    if mutation == "job_id":
        job["id"] = 51
    if mutation == "owner":
        run["repository"]["owner"]["id"] = 41
    if mutation == "artifact_id":
        artifact["id"] = 61
    if mutation == "expired":
        artifact["expired"] = True
    if mutation == "expiry":
        artifact["expires_at"] = "2026-10-28T12:00:00Z"
    if mutation == "digest":
        artifact["digest"] = None
    if mutation == "time":
        artifact["created_at"] = "2026-10-28T12:00:00Z"
    if mutation == "ambiguous":
        jobs["jobs"].append(job.copy())
        jobs["total_count"] = 2
    with pytest.raises(ValueError):
        inputs.select_custody_artifact(identity, run, jobs, listing, now=now)


def _signature_fixture():
    from datetime import datetime, timezone
    from p11lab import delivery_authority
    import importlib.util
    from pathlib import Path

    spec = importlib.util.spec_from_file_location(
        "source_authority_fixture", Path(__file__).with_name("test_source_authority.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    profile, identity, raw, result = module.fixture()
    result[0]["verificationResult"]["statement"]["predicateType"] = (
        "https://p11lab.org/attestations/image-custody/v1"
    )
    result[0]["verificationResult"]["statement"]["subject"][0]["name"] = (
        "custody-finalization.json"
    )
    job = {"started_at": "2026-10-28T11:55:00Z", "completed_at": "2026-10-28T12:10:00Z"}
    return (
        profile,
        identity,
        raw,
        result,
        job,
        datetime(2026, 11, 5, tzinfo=timezone.utc),
        delivery_authority,
    )


def test_completed_signature_is_bound_to_job_and_not_active_age():
    from p11lab import custody_authority

    profile, identity, raw, result, job, now, active = _signature_fixture()
    import copy

    active_result = copy.deepcopy(result)
    statement = active_result[0]["verificationResult"]["statement"]
    statement["predicateType"] = active.PREDICATE_TYPE
    statement["subject"][0]["name"] = "source-context.json"
    with pytest.raises(ValueError, match="outside accepted window"):
        active._check_verified(active_result, profile, identity, raw, now)
    custody_authority.check_completed_signature(
        result, profile, identity, raw, job, now
    )


@pytest.mark.parametrize(
    "mutation", ["issuer", "subject", "predicate", "before_job", "after_job", "expired"]
)
def test_completed_signature_refuses_wrong_identity_subject_or_time(mutation):
    from datetime import timedelta
    from p11lab import custody_authority

    profile, identity, raw, result, job, now, _ = _signature_fixture()
    verified = result[0]["verificationResult"]
    if mutation == "issuer":
        verified["signature"]["certificate"]["issuer"] = "https://evil.example"
    if mutation == "subject":
        verified["statement"]["subject"][0]["digest"]["sha256"] = "0" * 64
    if mutation == "predicate":
        verified["statement"]["predicateType"] = "https://example.org/other"
    if mutation == "before_job":
        verified["verifiedTimestamps"][0]["timestamp"] = "2026-10-28T11:49:59Z"
    if mutation == "after_job":
        verified["verifiedTimestamps"][0]["timestamp"] = "2026-10-28T12:15:01Z"
    if mutation == "expired":
        now += timedelta(days=10)
    with pytest.raises(ValueError):
        custody_authority.check_completed_signature(
            result, profile, identity, raw, job, now
        )


def test_custody_validity_never_exceeds_14_days_even_when_metadata_expires_later():
    from datetime import datetime, timezone

    identity, run, jobs, listing, _ = _metadata_fixture()
    listing["artifacts"][0]["expires_at"] = "2026-11-11T10:34:00Z"
    now = datetime(2026, 11, 11, 10, 31, tzinfo=timezone.utc)
    with pytest.raises(ValueError, match="timing or retention"):
        inputs.select_custody_artifact(identity, run, jobs, listing, now=now)


def test_custody_verifier_uses_custody_subject_and_predicate(tmp_path, monkeypatch):
    from p11lab import custody_authority, delivery_authority

    executable = tmp_path / "gh"
    executable.write_text(
        '#!/bin/sh\nprintf "%s\\n" "$@" > "$HOME/argv"\nprintf "[]"\n'
    )
    executable.chmod(0o700)
    monkeypatch.setattr(
        delivery_authority,
        "GH_EXECUTABLE_SHA256",
        hashlib.sha256(executable.read_bytes()).hexdigest(),
    )
    subject = tmp_path / "statement"
    subject.write_bytes(b"{}")
    bundle = tmp_path / "bundle"
    bundle.write_bytes(b"{}")
    root = tmp_path / "root"
    root.write_bytes(b"root")
    profile, _, _, _, _, _, _ = _signature_fixture()
    output = tmp_path / "verification"
    result, raw = custody_authority.run_custody_verifier(
        executable,
        subject,
        bundle,
        root,
        hashlib.sha256(root.read_bytes()).hexdigest(),
        profile,
        output,
    )
    argv = (output / "home/argv").read_text().splitlines()
    assert result == [] and raw == b"{}"
    assert str(output / "custody-finalization.json") in argv
    assert argv[argv.index("--predicate-type") + 1] == custody_authority.PREDICATE_TYPE


def test_custody_verifier_bounds_control_bundle_at_two_mib(tmp_path, monkeypatch):
    from p11lab import custody_authority, delivery_authority

    executable = tmp_path / "gh"
    executable.write_bytes(b"fixture")
    monkeypatch.setattr(
        delivery_authority,
        "GH_EXECUTABLE_SHA256",
        hashlib.sha256(b"fixture").hexdigest(),
    )
    subject = tmp_path / "statement"
    subject.write_bytes(b"{}")
    bundle = tmp_path / "bundle"
    with bundle.open("wb") as stream:
        stream.truncate(2 * 1024 * 1024 + 1)
    root = tmp_path / "root"
    root.write_bytes(b"root")
    profile, _, _, _, _, _, _ = _signature_fixture()
    with pytest.raises(ValueError, match="oversized verifier input"):
        custody_authority.run_custody_verifier(
            executable,
            subject,
            bundle,
            root,
            hashlib.sha256(b"root").hexdigest(),
            profile,
            tmp_path / "out",
        )


def test_custody_metadata_is_read_three_times_and_must_stabilize(monkeypatch):
    from datetime import datetime, timezone

    identity, run, jobs, listing, now = _metadata_fixture()
    client = artifacts.GitHubTransport("owner/repo", "fixture")
    calls = []

    def metadata(path, deadline):
        calls.append(path)
        if "/jobs?" in path:
            return jobs
        if "/artifacts?" in path:
            return listing
        return run

    monkeypatch.setattr(client, "_metadata", metadata)
    clock = [0.0]

    def sleep(seconds):
        clock[0] += seconds

    monkeypatch.setattr(
        artifacts,
        "stable_metadata",
        lambda fetch: inputs.stable_metadata(
            fetch, clock=lambda: clock[0], sleep=sleep
        ),
    )
    result = client.resolve_custody(identity, now=now)
    assert result["artifact"]["id"] == identity["artifact_id"]
    assert result["job"]["id"] == identity["job_id"]
    assert len(calls) == 9 and clock[0] == 4
    assert now == datetime(2026, 10, 29, tzinfo=timezone.utc)


def test_custody_metadata_refuses_unstable_reads(monkeypatch):
    import copy

    identity, run, jobs, listing, now = _metadata_fixture()
    client = artifacts.GitHubTransport("owner/repo", "fixture")
    reads = [0]

    def metadata(path, deadline):
        if "/jobs?" in path:
            return jobs
        if "/artifacts?" in path:
            reads[0] += 1
            value = copy.deepcopy(listing)
            value["artifacts"][0]["digest"] = (
                "sha256:" + ("a" if reads[0] % 2 else "b") * 64
            )
            return value
        return run

    monkeypatch.setattr(client, "_metadata", metadata)
    clock = [0.0]

    def sleep(seconds):
        clock[0] += seconds

    monkeypatch.setattr(
        artifacts,
        "stable_metadata",
        lambda fetch: inputs.stable_metadata(
            fetch, clock=lambda: clock[0], sleep=sleep
        ),
    )
    with pytest.raises(ValueError, match="did not stabilize"):
        client.resolve_custody(identity, now=now)
    assert reads[0] > 3


def test_custody_metadata_rejects_duplicate_numeric_job_identity():
    identity, run, jobs, listing, now = _metadata_fixture()
    other = dict(jobs["jobs"][0], name="other-job")
    jobs["jobs"].append(other)
    jobs["total_count"] = 2
    with pytest.raises(ValueError):
        inputs.select_custody_artifact(identity, run, jobs, listing, now=now)


def _fixture_evaluator_observation():
    import importlib.util
    from pathlib import Path

    spec = importlib.util.spec_from_file_location(
        "evaluator_replay_fixture", Path(__file__).with_name("test_evaluator_replay.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module._observation_fixture(Path("/producer"))


def _bound_manifest(statement):
    import json

    value = _manifest_fixture()
    value['components'] = statement['components']
    for key in ("producer", "run", "profile_sha256", "controller_sha256"):
        value[key] = statement[key]
    value["image_archive"] = statement["image_archive"].copy()
    value["files"]["image"][0]["files"]["image.tar"] = statement["image_archive"].copy()
    value["evaluator_receipt_sha256"] = statement["evaluator"]["receipt_sha256"]
    value["evaluator_identity_sha256"] = statement["evaluator"]["identity_sha256"]
    value["files"]["evaluator-original"][0]["files"]["evaluator-build-receipt.json"][
        "sha256"
    ] = statement["evaluator"]["receipt_sha256"]
    if any(
        row["role"] == "checker-tool" and row["part"] == 2
        for row in statement["artifacts"]
    ):
        entries = value["files"]["checker-tool"][0]["files"]
        value["files"]["checker-tool"] = [
            {"part": 1, "files": {"tool-root.tar.gz": entries["tool-root.tar.gz"]}},
            {
                "part": 2,
                "files": {
                    name: entries[name]
                    for name in ("installed-image.tar.gz", "derived-image.tar.gz")
                },
            },
        ]
    return json.dumps(value, sort_keys=True).encode()


def _materialize_fixture_parts(statement, payloads, image_fixture=None, image_distribution=None):
    import io
    import json

    value = json.loads(_bound_manifest(statement))
    contents = {}
    for role, parts in value["files"].items():
        for part in parts:
            for name in part["files"]:
                raw = image_fixture if role == 'image' and name == 'image.tar' and image_fixture is not None else ("synthetic " + role + "/" + name).encode()
                contents[(role, part["part"], name)] = raw
                part["files"][name] = {
                    "size": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                }
    flat = {
        role: {
            name: identity for part in parts for name, identity in part["files"].items()
        }
        for role, parts in value["files"].items()
    }
    value["image_archive"] = flat["image"]["image.tar"]
    statement["image_archive"] = value["image_archive"].copy()
    if image_distribution is not None:
        digest = image_distribution['config_sha256']
        candidate = {'kind': 'docker-local', 'reference': 'sha256:' + digest, 'sha256': digest, 'platform': 'linux/amd64'}
        value['artifact'] = value['facts']['artifact'] = candidate
        value['engine_id'] = candidate['reference']
        value['config_sha256'] = value['facts']['validation']['config_sha256'] = digest
        value['layers'] = value['facts']['validation']['layers'] = image_distribution['layers']
    receipt_sha = flat["evaluator-original"]["evaluator-build-receipt.json"]["sha256"]
    statement["evaluator"]["receipt_sha256"] = receipt_sha
    statement["evaluator"]["planner"]["evaluator_receipt_sha256"] = receipt_sha
    value["evaluator_receipt_sha256"] = receipt_sha
    statement['components'] = _component_facts_fixture(receipt_sha)
    value['components'] = statement['components']
    value["facts"]["build_receipt_sha256"] = flat["source-records"][
        "build-receipt.json"
    ]["sha256"]
    value["facts"]["source"]["sealed"]["receipt_sha256"] = flat["source-records"][
        "sealed-source.json"
    ]["sha256"]
    value["facts"]["source"]["content"]["receipt_sha256"] = flat["source-records"][
        "source-companion.json"
    ]["sha256"]
    value["facts"]["source"]["content"]["spdx_sha256"] = flat["source-records"][
        "sbom.spdx.json"
    ]["sha256"]
    value["facts"]["validation"]["validation_sha256"] = flat["validation"][
        "validation.json"
    ]["sha256"]
    value["facts"]["validation"]["package_sha256"] = flat["validation"][
        "package.tar.gz"
    ]["sha256"]
    value["facts"]["validation"]["body_sha256"] = "6" * 64
    manifest = json.dumps(value, sort_keys=True).encode()
    statement["manifest_sha256"] = hashlib.sha256(manifest).hexdigest()
    archives = {}
    for row, metadata in zip(statement["artifacts"], payloads):
        sink = io.BytesIO()
        with zipfile.ZipFile(sink, "w") as archive:
            for name in value["files"][row["role"]][row["part"] - 1]["files"]:
                archive.writestr(name, contents[(row["role"], row["part"], name)])
            if row["role"] == "image" and row["part"] == 1:
                archive.writestr("custody-manifest.json", manifest)
        raw = sink.getvalue()
        archives[row["id"]] = raw
        metadata["size_in_bytes"] = row["size"] = len(raw)
        metadata["digest"] = row["digest"] = "sha256:" + hashlib.sha256(raw).hexdigest()
    return manifest, archives


def _finalization_fixture():
    from p11lab import delivery_authority

    profile, identity, _, _, _, _, _ = _signature_fixture()
    profile.update(environment="softhsm2", channel="release", graph=[])
    selector, run, jobs, listing, now = _metadata_fixture()
    run["workflow_id"] = profile["workflow_id"]
    run["repository"] = {
        "id": profile["repository_id"],
        "owner": {"id": profile["owner_id"]},
    }
    run["head_sha"] = profile["source_sha"]
    jobs["jobs"][0]["head_sha"] = profile["source_sha"]
    listing["artifacts"][0]["workflow_run"].update(
        repository_id=profile["repository_id"], head_sha=profile["source_sha"]
    )
    identity = {
        "run_id": selector["run_id"],
        "attempt": 1,
        "job": profile["job"],
        "job_id": selector["job_id"],
    }
    manifest = (
        b'{"schema_version":1,"image_archive":{"sha256":"'
        + b"a" * 64
        + b'","size":123}}'
    )
    statement = {
        "schema_version": 1,
        "kind": "image-custody-finalization",
        "role": "image-custody-producer",
        "environment": "softhsm2",
        "channel": "release",
        "retention_days": 14,
        "evaluator": _fixture_evaluator_observation(),
        "components": _component_facts_fixture(),
        "profile_sha256": delivery_authority._profile_digest(profile),
        "controller_sha256": profile["controller_sha256"],
        "run": identity,
        "producer": {
            key: profile[key]
            for key in (
                "repository",
                "repository_id",
                "owner_id",
                "workflow_id",
                "workflow_path",
                "source_sha",
                "source_ref",
                "signer_sha",
            )
        }
        | {"graph_sha256": inputs.digest(profile["graph"])},
        "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
        "image_archive": {"sha256": "a" * 64, "size": 123},
        "artifacts": _segments_fixture(),
    }
    statement['components'] = _component_facts_fixture(statement['evaluator']['receipt_sha256'])
    manifest = _bound_manifest(statement)
    statement["manifest_sha256"] = hashlib.sha256(manifest).hexdigest()
    return (
        profile,
        statement,
        manifest,
        {
            "run": run,
            "job": jobs["jobs"][0],
            "segments": [
                listing["artifacts"][0]
                | {
                    "id": row["id"],
                    "name": row["name"],
                    "size_in_bytes": row["size"],
                    "digest": row["digest"],
                }
                for row in statement["artifacts"]
            ],
        },
        now,
    )


def test_finalization_binds_manifest_protected_profile_and_exact_upload():
    from p11lab import custody_authority

    profile, statement, manifest, observed, _ = _finalization_fixture()
    custody_authority.check_finalization(statement, manifest, profile, observed)


@pytest.mark.parametrize(
    "damage",
    [
        "manifest",
        "profile",
        "controller",
        "role",
        "run",
        "job",
        "id",
        "size",
        "digest",
        "extra",
    ],
)
def test_finalization_refuses_changed_identity_or_payload(damage):
    from p11lab import custody_authority

    profile, statement, manifest, observed, _ = _finalization_fixture()
    if damage == "manifest":
        manifest += b" "
    if damage == "profile":
        statement["profile_sha256"] = "0" * 64
    if damage == "controller":
        statement["controller_sha256"] = "0" * 64
    if damage == "role":
        statement["role"] = "source-producer"
    if damage == "run":
        statement["run"]["run_id"] += 1
    if damage == "job":
        statement["run"]["job_id"] += 1
    if damage == "id":
        statement["artifacts"][0]["id"] += 1
    if damage == "size":
        statement["artifacts"][0]["size"] += 1
    if damage == "digest":
        statement["artifacts"][0]["digest"] = "sha256:" + "f" * 64
    if damage == "extra":
        statement["admitted"] = True
    with pytest.raises(ValueError):
        custody_authority.check_finalization(statement, manifest, profile, observed)


def test_finalization_rejects_boolean_as_numeric_attempt():
    from p11lab import custody_authority

    profile, statement, manifest, observed, _ = _finalization_fixture()
    statement["run"]["attempt"] = True
    with pytest.raises(ValueError):
        custody_authority.check_finalization(statement, manifest, profile, observed)


def test_stream_uses_single_bounded_read1_per_iteration(tmp_path, monkeypatch):
    class Response:
        status = 200
        headers = {}

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self, size):
            raise AssertionError("unbounded buffered read")

        def read1(self, size):
            assert size <= 65536
            if not getattr(self, "done", False):
                self.done = True
                return b"x"
            return b""

    class Opener:
        def open(self, request, timeout):
            return Response()

    monkeypatch.setattr(artifacts, "build_opener", lambda *args: Opener())
    client = artifacts.GitHubTransport("owner/repo", "fixture")
    monkeypatch.setattr(
        client,
        "_request",
        lambda *args: (302, {"location": "https://store.blob.core.windows.net/x"}, b""),
    )
    client.download_custody(
        artifacts.CustodyArtifactBytes(
            1, 1, "sha256:" + hashlib.sha256(b"x").hexdigest()
        ),
        tmp_path / "bytes",
    )


def test_custody_rejects_encoded_storage_response(tmp_path, monkeypatch):
    class Response:
        status = 200
        headers = {"Content-Encoding": "gzip"}

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read1(self, size):
            return b""

    class Opener:
        def open(self, request, timeout):
            return Response()

    monkeypatch.setattr(artifacts, "build_opener", lambda *args: Opener())
    client = artifacts.GitHubTransport("owner/repo", "fixture")
    monkeypatch.setattr(
        client,
        "_request",
        lambda *args: (302, {"location": "https://store.blob.core.windows.net/x"}, b""),
    )
    with pytest.raises(ValueError, match="storage content encoding"):
        client.download_custody(
            artifacts.CustodyArtifactBytes(1, 1, "sha256:" + "a" * 64),
            tmp_path / "bytes",
        )


def test_control_download_uses_separate_two_mib_cap_and_digest(monkeypatch):
    client = artifacts.GitHubTransport("owner/repo", "fixture")
    raw = b"control zip"
    calls = []

    def request(url, token, limit, deadline):
        calls.append((token, limit))
        if token is not None:
            return (
                302,
                {"location": "https://store.blob.core.windows.net/x?signature=private"},
                b"",
            )
        return 200, {}, raw

    monkeypatch.setattr(client, "_request", request)
    identity = artifacts.CustodyArtifactBytes(
        9, len(raw), "sha256:" + hashlib.sha256(raw).hexdigest()
    )
    assert client.download_custody_control(identity) == raw
    assert calls == [("fixture", 0), (None, 2 * 1024 * 1024)]
    with pytest.raises(ValueError):
        client.download_custody_control(
            artifacts.CustodyArtifactBytes(9, 2 * 1024 * 1024 + 1, "sha256:" + "a" * 64)
        )


def test_control_archive_has_exact_two_regular_members(tmp_path):
    import io

    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as archive:
        archive.writestr("custody-finalization.json", b"{}")
        archive.writestr("bundle.json", b"{}")
    assert artifacts.decode_custody_control(out.getvalue()) == (b"{}", b"{}")
    with zipfile.ZipFile(out, "a") as archive:
        archive.writestr("extra", b"bad")
    with pytest.raises(ValueError):
        artifacts.decode_custody_control(out.getvalue())


def test_finalization_must_bind_inner_archive_separately_from_zip():
    from p11lab import custody_authority

    profile, statement, manifest, observed, _ = _finalization_fixture()
    custody_authority.check_finalization(statement, manifest, profile, observed)
    statement["image_archive"]["sha256"] = "b" * 64
    with pytest.raises(ValueError):
        custody_authority.check_finalization(statement, manifest, profile, observed)


def test_custody_zip_entry_limit_precedes_central_directory_allocation(
    tmp_path, monkeypatch
):
    path = tmp_path / "many.zip"
    with zipfile.ZipFile(path, "w") as archive:
        for number in range(inputs.CUSTODY_ENTRY_LIMIT + 1):
            archive.writestr(f"{number:05d}", b"")
    monkeypatch.setattr(
        inputs.zipfile,
        "ZipFile",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("central directory allocated")
        ),
    )
    with pytest.raises(ValueError, match="custody ZIP entry bound"):
        inputs.extract_custody_archive(
            path, {"00000": _entry(b"")}, tmp_path / "payload"
        )


def test_custody_zip_rejects_underreported_central_count_before_allocation(
    tmp_path, monkeypatch
):
    import struct

    path = tmp_path / "many.zip"
    with zipfile.ZipFile(path, "w") as archive:
        for number in range(inputs.CUSTODY_ENTRY_LIMIT + 1):
            archive.writestr(f"{number:05d}", b"")
    data = bytearray(path.read_bytes())
    end = data.rfind(b"PK\x05\x06")
    struct.pack_into("<HH", data, end + 8, 1, 1)
    path.write_bytes(data)
    monkeypatch.setattr(
        inputs.zipfile,
        "ZipFile",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("central directory allocated")
        ),
    )
    with pytest.raises(ValueError, match="custody ZIP entry bound"):
        inputs.extract_custody_archive(
            path, {"00000": _entry(b"")}, tmp_path / "payload"
        )


def test_finalization_explicitly_binds_numeric_control_identity_and_graph():
    from p11lab import custody_authority

    profile, statement, manifest, observed, _ = _finalization_fixture()
    profile["graph"] = [{"path": "workflow.yml", "sha256": "c" * 64}]
    from p11lab import delivery_authority

    statement["profile_sha256"] = delivery_authority._profile_digest(profile)
    statement["producer"] = {
        "repository": profile["repository"],
        "repository_id": profile["repository_id"],
        "owner_id": profile["owner_id"],
        "workflow_id": profile["workflow_id"],
        "workflow_path": profile["workflow_path"],
        "source_sha": profile["source_sha"],
        "source_ref": profile["source_ref"],
        "signer_sha": profile["signer_sha"],
        "graph_sha256": inputs.digest(profile["graph"]),
    }
    manifest = _bound_manifest(statement)
    statement["manifest_sha256"] = hashlib.sha256(manifest).hexdigest()
    custody_authority.check_finalization(statement, manifest, profile, observed)
    statement["producer"]["owner_id"] += 1
    with pytest.raises(ValueError):
        custody_authority.check_finalization(statement, manifest, profile, observed)


def test_finalization_explicitly_binds_fourteen_day_retention():
    from p11lab import custody_authority

    profile, statement, manifest, observed, _ = _finalization_fixture()
    statement["retention_days"] = 14
    custody_authority.check_finalization(statement, manifest, profile, observed)
    statement["retention_days"] = 15
    with pytest.raises(ValueError):
        custody_authority.check_finalization(statement, manifest, profile, observed)


@pytest.mark.parametrize("damage", ["duplicate", "link", "traversal", "crc"])
def test_control_archive_rejects_unsafe_closed_roster(damage):
    import io

    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_STORED) as archive:
        if damage == "link":
            info = zipfile.ZipInfo("bundle.json")
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, b"{}")
        else:
            archive.writestr("bundle.json", b"{}")
        archive.writestr("custody-finalization.json", b"{}")
        if damage == "duplicate":
            with pytest.warns(UserWarning):
                archive.writestr("bundle.json", b"{}")
        if damage == "traversal":
            archive.writestr("../outside", b"x")
    raw = out.getvalue()
    if damage == "crc":
        raw = raw.replace(b"{}", b"[]", 1)
    with pytest.raises(ValueError):
        artifacts.decode_custody_control(raw)


def test_completed_authority_refuses_unenrolled_profile_before_transport(
    tmp_path, monkeypatch
):
    from p11lab import custody_authority, delivery_authority

    monkeypatch.setattr(
        delivery_authority,
        "_github_transport",
        lambda *args: (_ for _ in ()).throw(AssertionError("transport reached")),
    )
    with pytest.raises(ValueError, match="protected source producer profile"):
        custody_authority.verify_completed_finalization(
            environment="softhsm2",
            channel="release",
            run_id=100,
            attempt=1,
            job_id=50,
            control_id=70,
            token="fixture",
            executable=tmp_path / "gh",
            trusted_root=tmp_path / "root",
            output_dir=tmp_path / "out",
        )
    assert not (tmp_path / "out").exists()


def test_completed_authority_cannot_be_constructed_from_caller_json():
    from p11lab import custody_authority

    with pytest.raises(TypeError, match="verified factory"):
        custody_authority.VerifiedCompletedFinalization(None, {}, {}, {})


def _completed_factory_fixture(
    tmp_path, monkeypatch, mutation=None, *, two_parts=False, with_payload=False, image_fixture=None
):
    import io
    import json
    from datetime import datetime, timezone
    from pathlib import Path
    from p11lab import custody_authority as custody, delivery_authority as source

    profile, _, _, _, _, _, _ = _signature_fixture()
    profile.update(enabled=True, environment="softhsm2", channel="release")
    package = Path(source.__file__).parent
    graph_paths = {profile["workflow_path"]} | {
        "src/p11lab/" + name
        for name in (
            "publish.py",
            "cli.py",
            "sources.py",
            "licenses.py",
            "source_transport.py",
            "delivery_authority.py",
            "inspection_bounded.py",
            "bounded_run.py",
            "image_validation.py",
            "custody_authority.py",
            "image_custody.py",
            "round_core/artifacts.py",
            "round_core/inputs.py",
            "round_core/evaluator_replay.py",
            "data/ci/delivery/evaluator-replay-driver.py",
            "data/ci/delivery/custody-policy.json",
            "data/ci/image-custody.schema.json",
            "data/ci/delivery/image-evidence.py",
            "data/ci/delivery/validation-policy.json",
        )
    }
    content = {
        name: (
            Path(name).read_bytes()
            if name.startswith(".github/")
            else package.joinpath(name.removeprefix("src/p11lab/")).read_bytes()
        )
        for name in graph_paths
    }
    profile["graph"] = [
        {"path": name, "sha256": hashlib.sha256(content[name]).hexdigest()}
        for name in sorted(graph_paths)
    ]
    profile["controller_sha256"] = source._controller_digest(package)
    profile["policy_sha256"] = hashlib.sha256(
        content["src/p11lab/data/ci/delivery/validation-policy.json"]
    ).hexdigest()
    root = tmp_path / "trusted-root"
    root.write_bytes(b"fixture trusted root")
    profile["root_sha256"] = hashlib.sha256(root.read_bytes()).hexdigest()
    source._validate_profile(profile)
    monkeypatch.setattr(source, "load_profile", lambda environment, channel: profile)
    monkeypatch.setattr(
        source, "_clock", lambda: datetime(2026, 10, 29, tzinfo=timezone.utc)
    )
    identity, run, jobs, listing, _ = _metadata_fixture()
    run.update(
        workflow_id=profile["workflow_id"],
        head_sha=profile["source_sha"],
        repository={
            "id": profile["repository_id"],
            "owner": {"id": profile["owner_id"]},
        },
        triggering_actor={"id": 99},
    )
    job = jobs["jobs"][0]
    job["head_sha"] = profile["source_sha"]
    payload = listing["artifacts"][0]
    payload.update(name="p11lab-image-custody-image-part1-100-1")
    payload["workflow_run"].update(
        repository_id=profile["repository_id"], head_sha=profile["source_sha"]
    )
    from p11lab.image_custody import SEGMENT_ROLES

    payloads = [
        dict(
            payload,
            id=60 + index,
            name=f"p11lab-image-custody-{role}-part1-100-1",
            digest="sha256:" + f"{60 + index:064x}",
        )
        for index, role in enumerate(SEGMENT_ROLES)
    ]
    roles = [(role, 1) for role in SEGMENT_ROLES]
    if two_parts:
        index = SEGMENT_ROLES.index("checker-tool") + 1
        payloads.insert(
            index,
            dict(
                payload,
                id=68,
                name="p11lab-image-custody-checker-tool-part2-100-1",
                digest="sha256:" + f"{68:064x}",
            ),
        )
        roles.insert(index, ("checker-tool", 2))
    manifest = b'{"image_archive":{"sha256":"' + b"a" * 64 + b'","size":123}}'
    statement = {
        "schema_version": 1,
        "kind": "image-custody-finalization",
        "role": "image-custody-producer",
        "environment": "softhsm2",
        "channel": "release",
        "profile_sha256": source._profile_digest(profile),
        "controller_sha256": profile["controller_sha256"],
        "producer": custody._producer_identity(profile),
        "run": {"run_id": 100, "attempt": 1, "job": profile["job"], "job_id": 50},
        "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
        "image_archive": {"sha256": "a" * 64, "size": 123},
        "retention_days": 14,
        "evaluator": _fixture_evaluator_observation(),
        "components": _component_facts_fixture(),
        "artifacts": [
            {
                "role": role,
                "part": part,
                "id": row["id"],
                "name": row["name"],
                "size": row["size_in_bytes"],
                "digest": row["digest"],
            }
            for (role, part), row in zip(roles, payloads)
        ],
    }
    statement['components'] = _component_facts_fixture(statement['evaluator']['receipt_sha256'])
    archives = {}
    if with_payload:
        distribution = None
        if image_fixture is not None:
            from p11lab import image_custody
            fixture_path = tmp_path / 'inert-fixture-image.tar'
            fixture_path.write_bytes(image_fixture)
            distribution, _ = image_custody._inspect_saved_image(fixture_path)
        manifest, archives = _materialize_fixture_parts(statement, payloads, image_fixture, distribution)
    else:
        manifest = _bound_manifest(statement)
        statement["manifest_sha256"] = hashlib.sha256(manifest).hexdigest()
    if mutation == "role":
        statement["role"] = "source-producer"
    if mutation == "segment_digest":
        statement["artifacts"][4]["digest"] = "sha256:" + "f" * 64
    statement_raw = json.dumps(statement, sort_keys=True).encode()
    _, _, _, verifier_output, _, _, _ = _signature_fixture()
    verified = verifier_output[0]["verificationResult"]
    verified["statement"]["subject"][0]["digest"]["sha256"] = hashlib.sha256(
        statement_raw
    ).hexdigest()
    cert = verified["signature"]["certificate"]
    cert["runInvocationURI"] = (
        "https://github.com/p11lab/controller/actions/runs/100/attempts/1"
    )
    verified["verifiedTimestamps"][0]["timestamp"] = "2026-10-28T10:30:00Z"
    if mutation == "signer":
        cert["sourceRepositoryOwnerIdentifier"] = "9999"
    executable = tmp_path / "gh"
    executable.write_text(
        "#!/bin/sh\nprintf %s " + repr(json.dumps(verifier_output)) + "\n"
    )
    executable.chmod(0o700)
    monkeypatch.setattr(
        source,
        "GH_EXECUTABLE_SHA256",
        hashlib.sha256(executable.read_bytes()).hexdigest(),
    )
    control_zip = io.BytesIO()
    with zipfile.ZipFile(control_zip, "w") as archive:
        archive.writestr("custody-finalization.json", statement_raw)
        archive.writestr("bundle.json", b"{}")
    control_raw = control_zip.getvalue()
    control = dict(
        payload,
        id=70,
        name="p11lab-image-custody-control-100-1",
        size_in_bytes=len(control_raw),
        digest="sha256:" + hashlib.sha256(control_raw).hexdigest(),
    )
    environment = {
        "id": profile["environment_id"],
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
                    {"type": "User", "reviewer": {"id": n}}
                    for n in profile["reviewer_ids"]
                ],
            }
        ],
    }
    branches = {
        "total_count": 1,
        "branch_policies": [{"name": "main", "type": "branch"}],
    }
    approvals = [
        {
            "state": "approved",
            "user": {"id": profile["reviewer_ids"][0]},
            "environments": [
                {"id": profile["environment_id"], "name": "source-delivery"}
            ],
        }
    ]
    if mutation == "approval":
        approvals[0]["user"]["id"] = 99
    if mutation == "job":
        job["id"] = 51

    class Transport(artifacts.GitHubTransport):
        def _metadata(self, path, deadline):
            if path == "/environments/source-delivery":
                return environment
            if path.startswith(
                "/environments/source-delivery/deployment-branch-policies"
            ):
                return branches
            if "/jobs?" in path:
                return jobs
            if "/artifacts?" in path:
                if "&name=" not in path:
                    all_rows = [*payloads, control]
                    return {"total_count": len(all_rows), "artifacts": all_rows}
                if mutation == "missing_segment" and "consumer-tool" in path:
                    return {"total_count": 0, "artifacts": []}
                chosen = (
                    control
                    if "custody-control-" in path
                    else next(row for row in payloads if row["name"] in path)
                )
                return {"total_count": 1, "artifacts": [chosen]}
            return run

        def _request(self, url, token, limit, deadline):
            if url.endswith("/approvals"):
                return 200, {}, json.dumps(approvals).encode()
            if token is not None:
                if with_payload and "/actions/artifacts/" in url:
                    artifact_id = url.split("/actions/artifacts/")[1].split("/")[0]
                    return (
                        302,
                        {
                            "location": "https://store.blob.core.windows.net/"
                            + artifact_id
                        },
                        b"",
                    )
                return (
                    302,
                    {"location": "https://store.blob.core.windows.net/control"},
                    b"",
                )
            return 200, {}, control_raw

        def source_file(self, revision, path):
            assert revision == profile["source_sha"]
            return content[path]

    monkeypatch.setattr(
        source,
        "_github_transport",
        lambda repository, token: Transport(repository, token),
    )
    if with_payload:

        class Response(io.BytesIO):
            status = 200
            headers = {}

            def __enter__(self):
                return self

            def __exit__(self, *args):
                self.close()

            def read1(self, size):
                return self.read(size)

        class Opener:
            def open(self, request, timeout):
                assert not any(
                    key.lower() == "authorization" for key, _ in request.header_items()
                )
                artifact_id = int(request.full_url.rsplit("/", 1)[1])
                raw = archives[artifact_id]
                if mutation == "corrupt_payload" and artifact_id == 63:
                    raw = raw[:-1] + bytes([raw[-1] ^ 1])
                return Response(raw)

        monkeypatch.setattr(artifacts, "build_opener", lambda *args: Opener())

    def stable(fetch):
        clock = [0.0]
        return inputs.stable_metadata(
            fetch,
            clock=lambda: clock[0],
            sleep=lambda seconds: clock.__setitem__(0, clock[0] + seconds),
        )

    monkeypatch.setattr(artifacts, "stable_metadata", stable)
    return dict(
        environment="softhsm2",
        channel="release",
        run_id=100,
        attempt=1,
        job_id=50,
        control_id=70,
        token="fixture",
        executable=executable,
        trusted_root=root,
        output_dir=tmp_path / "out",
    ), manifest


def test_completed_factory_checks_real_boundaries_with_synthetic_signer(
    tmp_path, monkeypatch
):
    from p11lab import custody_authority

    args, manifest = _completed_factory_fixture(tmp_path, monkeypatch)
    verified = custody_authority.verify_completed_finalization(**args)
    assert type(verified) is custody_authority.VerifiedCompletedFinalization
    custody_authority.check_finalization(
        verified.statement(), manifest, verified.profile(), verified.observed()
    )
    assert verified.statement()["artifacts"][0]["id"] == 60


@pytest.mark.parametrize(
    "mutation",
    ["role", "signer", "approval", "job", "segment_digest", "missing_segment"],
)
def test_completed_factory_refuses_forged_or_inconsistent_identity(
    tmp_path, monkeypatch, mutation
):
    from p11lab import custody_authority

    args, _ = _completed_factory_fixture(tmp_path, monkeypatch, mutation)
    with pytest.raises(ValueError):
        custody_authority.verify_completed_finalization(**args)


def test_completed_authority_freezes_verified_snapshot(tmp_path, monkeypatch):
    from p11lab import custody_authority

    args, _ = _completed_factory_fixture(tmp_path, monkeypatch)
    verified = custody_authority.verify_completed_finalization(**args)
    with pytest.raises((AttributeError, TypeError)):
        verified._statement = b"{}"


def test_custody_manifest_reads_only_after_exact_zip_byte_verification(tmp_path):
    path = tmp_path / "custody.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("custody-manifest.json", b'{"schema_version":1}')
        archive.writestr("image.tar", b"image")
    raw = path.read_bytes()
    identity = artifacts.CustodyArtifactBytes(
        9, len(raw), "sha256:" + hashlib.sha256(raw).hexdigest()
    )
    assert artifacts.read_custody_manifest(path, identity) == b'{"schema_version":1}'
    path.write_bytes(raw.replace(b"image", b"IMAGE"))
    with pytest.raises(ValueError, match="custody ZIP byte identity"):
        artifacts.read_custody_manifest(path, identity)


def test_completed_job_cannot_finish_far_in_the_future():
    identity, run, jobs, listing, now = _metadata_fixture()
    jobs["jobs"][0]["completed_at"] = "2026-10-29T01:00:00Z"
    with pytest.raises(ValueError, match="timing or retention"):
        inputs.select_custody_artifact(identity, run, jobs, listing, now=now)


def test_custody_refuses_large_central_directory_before_zip_allocation(
    tmp_path, monkeypatch
):
    path = tmp_path / "large-central.zip"
    with zipfile.ZipFile(path, "w") as archive:
        for number in range(129):
            entry = zipfile.ZipInfo(f"{number:05d}")
            entry.extra = b"x" * 65500
            archive.writestr(entry, b"")
    monkeypatch.setattr(
        inputs.zipfile,
        "ZipFile",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("central directory allocated")
        ),
    )
    with pytest.raises(ValueError, match="central directory byte bound"):
        inputs.extract_custody_archive(
            path, {"00000": _entry(b"")}, tmp_path / "payload"
        )


def test_custody_zip64_end_record_supported_within_fixed_bounds(tmp_path):
    import struct

    path = tmp_path / "zip64.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("image.tar", b"image bytes")
    data = path.read_bytes()
    end_offset = data.rfind(b"PK\x05\x06")
    end = list(struct.unpack("<4s4H2IH", data[end_offset : end_offset + 22]))
    count, central_size, central_offset = end[4], end[5], end[6]
    zip64 = struct.pack(
        "<4sQHHIIQQQQ",
        b"PK\x06\x06",
        44,
        45,
        45,
        0,
        0,
        count,
        count,
        central_size,
        central_offset,
    )
    locator = struct.pack("<4sIQI", b"PK\x06\x07", 0, end_offset, 1)
    end[3:7] = [0xFFFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFF]
    path.write_bytes(
        data[:end_offset] + zip64 + locator + struct.pack("<4s4H2IH", *end)
    )
    inputs.extract_custody_archive(
        path, {"image.tar": _entry(b"image bytes")}, tmp_path / "payload"
    )
    assert (tmp_path / "payload/image.tar").read_bytes() == b"image bytes"


def test_custody_zip_rejects_trailing_bytes(tmp_path):
    path = tmp_path / "trailing.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("image.tar", b"image bytes")
    with path.open("ab") as stream:
        stream.write(b"trailing")
    with pytest.raises(ValueError, match="end record"):
        inputs.extract_custody_archive(
            path, {"image.tar": _entry(b"image bytes")}, tmp_path / "payload"
        )


def _segments_fixture():
    from p11lab import image_custody

    return [
        {
            "role": role,
            "part": 1,
            "id": number,
            "name": f"p11lab-image-custody-{role}-part1-100-1",
            "size": 10,
            "digest": "sha256:" + f"{number:064x}",
        }
        for number, role in enumerate(image_custody.SEGMENT_ROLES, start=1)
    ]


def test_segment_roster_is_closed_ordered_and_numeric():
    from p11lab import image_custody

    rows = _segments_fixture()
    image_custody.check_segment_roster(rows, run_id=100, attempt=1)


@pytest.mark.parametrize(
    "damage", ["missing", "extra", "order", "id", "name", "digest", "size", "bool"]
)
def test_segment_roster_rejects_mixed_or_incomplete_parts(damage):
    from p11lab import image_custody

    rows = _segments_fixture()
    if damage == "missing":
        rows.pop()
    if damage == "extra":
        rows.append(rows[0].copy())
    if damage == "order":
        rows.reverse()
    if damage == "id":
        rows[1]["id"] = rows[0]["id"]
    if damage == "name":
        rows[0]["name"] = "p11lab-image-custody-image-99-1"
    if damage == "digest":
        rows[0]["digest"] = "a" * 64
    if damage == "size":
        rows[0]["size"] = inputs.CUSTODY_ZIP_LIMIT + 1
    if damage == "bool":
        rows[0]["id"] = True
    with pytest.raises(ValueError):
        image_custody.check_segment_roster(rows, run_id=100, attempt=1)


def test_finalization_binds_every_segment_to_independent_metadata():
    from p11lab import custody_authority

    profile, statement, manifest, observed, _ = _finalization_fixture()
    custody_authority.check_finalization(statement, manifest, profile, observed)
    observed["segments"][3]["id"] += 1000
    with pytest.raises(ValueError):
        custody_authority.check_finalization(statement, manifest, profile, observed)


def test_segment_roster_refuses_reused_zip_digest():
    from p11lab import image_custody

    rows = _segments_fixture()
    rows[1]["digest"] = rows[0]["digest"]
    with pytest.raises(ValueError, match="reused"):
        image_custody.check_segment_roster(rows, run_id=100, attempt=1)


def test_completed_factory_refuses_control_artifact_id_reuse(tmp_path, monkeypatch):
    from p11lab import custody_authority

    args, _ = _completed_factory_fixture(tmp_path, monkeypatch)
    args["control_id"] = 60
    with pytest.raises(ValueError):
        custody_authority.verify_completed_finalization(**args)


def test_signed_finalization_requires_original_evaluator_observation():
    import importlib.util
    from pathlib import Path
    from p11lab import custody_authority

    spec = importlib.util.spec_from_file_location(
        "evaluator_replay_fixture", Path(__file__).with_name("test_evaluator_replay.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    profile, statement, manifest, observed, _ = _finalization_fixture()
    statement["evaluator"] = module._observation_fixture(Path("/producer"))
    custody_authority.check_finalization(statement, manifest, profile, observed)
    statement.pop("evaluator")
    with pytest.raises(ValueError):
        custody_authority.check_finalization(statement, manifest, profile, observed)


def _manifest_fixture():
    from p11lab import image_custody

    files = {
        role: {
            name: {"size": 1, "sha256": f"{n:064x}"}
            for n, name in enumerate(names, start=1)
        }
        for role, names in image_custody.SEGMENT_FILES.items()
    }
    artifact = {
        "kind": "docker-local",
        "reference": "sha256:" + "a" * 64,
        "sha256": "a" * 64,
        "platform": "linux/amd64",
    }
    files["image"]["image.tar"] = {"size": 10, "sha256": "1" * 64}
    facts = {
        "artifact": artifact,
        "build_key": "b" * 64,
        "build_receipt_sha256": files["source-records"]["build-receipt.json"]["sha256"],
        "source": {
            "sealed": {
                "reference": "ghcr.io/p11lab/softhsm2@sha256:" + "c" * 64,
                "manifest_sha256": "c" * 64,
                "archive_sha256": "d" * 64,
                "receipt_sha256": files["source-records"]["sealed-source.json"][
                    "sha256"
                ],
            },
            "content": {
                "reference": "ghcr.io/p11lab/softhsm2@sha256:" + "e" * 64,
                "manifest_sha256": "e" * 64,
                "file_sha256": "f" * 64,
                "receipt_sha256": files["source-records"]["source-companion.json"][
                    "sha256"
                ],
                "spdx_sha256": files["source-records"]["sbom.spdx.json"]["sha256"],
                "inventory_sha256": "9" * 64,
            },
        },
        "validation": {
            "validation_sha256": files["validation"]["validation.json"]["sha256"],
            "package_sha256": files["validation"]["package.tar.gz"]["sha256"],
            "body_sha256": "6" * 64,
            "config_sha256": "8" * 64,
            "layers": [{"diff_id": "sha256:" + "7" * 64}],
        },
    }
    evaluator_receipt_sha = files["evaluator-original"]["evaluator-build-receipt.json"][
        "sha256"
    ]
    files = {role: [{"part": 1, "files": entries}] for role, entries in files.items()}
    return {
        "schema_version": 1,
        "kind": "image-qualification-custody",
        "qualification_only": True,
        "image_promotable": False,
        "producer": {
            "repository": "p11lab/controller",
            "repository_id": 1234,
            "owner_id": 5678,
            "workflow_id": 123,
            "workflow_path": ".github/workflows/provider-delivery.yml",
            "source_sha": "b" * 40,
            "source_ref": "refs/heads/main",
            "signer_sha": "a" * 40,
            "graph_sha256": "c" * 64,
        },
        "run": {"run_id": 100, "attempt": 1, "job": "trusted-producer", "job_id": 50},
        "profile_sha256": "d" * 64,
        "controller_sha256": "e" * 64,
        "evaluator_receipt_sha256": evaluator_receipt_sha,
        "evaluator_identity_sha256": "f" * 64,
        "component_rights_tree_sha256": "b" * 64,
        "components": _component_facts_fixture(evaluator_receipt_sha),
        "retention_days": 14,
        "artifact": artifact,
        "engine_id": artifact["reference"],
        "config_sha256": "8" * 64,
        "layers": facts["validation"]["layers"],
        "build_key": facts["build_key"],
        "facts": facts,
        "image_archive": {"size": 10, "sha256": "1" * 64},
        "files": files,
        "source_archives": {
            "sealed": {
                "size": 20,
                "sha256": "d" * 64,
                "media_type": "application/gzip",
            },
            "content": {
                "size": 30,
                "sha256": "f" * 64,
                "media_type": "application/gzip",
            },
        },
    }


def test_custody_manifest_binds_fixed_durable_rosters_and_source_facts():
    from p11lab import image_custody

    image_custody.check_custody_manifest(_manifest_fixture())


@pytest.mark.parametrize(
    "damage",
    [
        "missing-file",
        "extra-file",
        "extra-role",
        "archive",
        "candidate",
        "build",
        "validation",
        "validation-body",
        "source",
        "flags",
        "size",
        "type",
    ],
)
def test_custody_manifest_rejects_incomplete_or_changed_durable_inputs(damage):
    from p11lab import image_custody

    value = _manifest_fixture()
    if damage == "missing-file":
        value["files"]["validation"][0]["files"].pop("package.tar.gz")
    if damage == "extra-file":
        value["files"]["image"][0]["files"]["surprise"] = {
            "size": 1,
            "sha256": "a" * 64,
        }
    if damage == "extra-role":
        value["files"]["other"] = {}
    if damage == "archive":
        value["image_archive"]["sha256"] = "2" * 64
    if damage == "candidate":
        value["artifact"]["platform"] = "linux/arm64"
    if damage == "build":
        value["build_key"] = "f" * 64
    if damage == "validation":
        value["facts"]["validation"]["package_sha256"] = "f" * 64
    if damage == "validation-body":
        value["facts"]["validation"]["body_sha256"] = "not-a-digest"
    if damage == "source":
        value["source_archives"]["content"]["sha256"] = "a" * 64
    if damage == "flags":
        value["image_promotable"] = True
    if damage == "size":
        value["files"]["image"][0]["files"]["image.tar"]["size"] = (
            inputs.CUSTODY_MEMBER_LIMIT + 1
        )
    if damage == "type":
        value["retention_days"] = True
    with pytest.raises(ValueError):
        image_custody.check_custody_manifest(value)


def test_custody_manifest_requires_protected_producer_and_original_evaluator():
    from p11lab import image_custody

    value = _manifest_fixture()
    value["producer"] = {
        "repository": "p11lab/controller",
        "repository_id": 1234,
        "owner_id": 5678,
        "workflow_id": 123,
        "workflow_path": ".github/workflows/provider-delivery.yml",
        "source_sha": "b" * 40,
        "source_ref": "refs/heads/main",
        "signer_sha": "a" * 40,
        "graph_sha256": "c" * 64,
    }
    value["run"] = {
        "run_id": 100,
        "attempt": 1,
        "job": "trusted-producer",
        "job_id": 50,
    }
    value["profile_sha256"] = "d" * 64
    value["controller_sha256"] = "e" * 64
    value["evaluator_receipt_sha256"] = value["files"]["evaluator-original"][0][
        "files"
    ]["evaluator-build-receipt.json"]["sha256"]
    value["evaluator_identity_sha256"] = "f" * 64
    image_custody.check_custody_manifest(value)
    value["run"]["attempt"] = True
    with pytest.raises(ValueError):
        image_custody.check_custody_manifest(value)


def test_finalization_refuses_incomplete_preupload_manifest_even_when_signed_hash_matches():
    from p11lab import custody_authority

    profile, statement, manifest, observed, _ = _finalization_fixture()
    manifest = (
        b'{"schema_version":1,"image_archive":{"sha256":"'
        + b"a" * 64
        + b'","size":123}}'
    )
    statement["manifest_sha256"] = hashlib.sha256(manifest).hexdigest()
    with pytest.raises(ValueError, match="custody manifest"):
        custody_authority.check_finalization(statement, manifest, profile, observed)


def test_closed_role_roster_accepts_two_numbered_parts_per_role():
    from p11lab import image_custody

    rows = _segments_fixture()
    for row in rows:
        row["part"] = 1
        row["name"] = f"p11lab-image-custody-{row['role']}-part1-100-1"
    second = {
        "role": "checker-tool",
        "part": 2,
        "id": 90,
        "name": "p11lab-image-custody-checker-tool-part2-100-1",
        "size": 10,
        "digest": "sha256:" + "f" * 64,
    }
    index = next(i for i, row in enumerate(rows) if row["role"] == "checker-tool")
    rows.insert(index + 1, second)
    image_custody.check_segment_roster(rows, run_id=100, attempt=1)
    rows[index + 1]["part"] = 3
    with pytest.raises(ValueError):
        image_custody.check_segment_roster(rows, run_id=100, attempt=1)


def test_custody_manifest_accepts_two_frozen_checker_parts_and_rejects_overlap():
    from p11lab import image_custody

    value = _manifest_fixture()
    entries = value["files"]["checker-tool"][0]["files"]
    value["files"]["checker-tool"] = [
        {"part": 1, "files": {"tool-root.tar.gz": entries["tool-root.tar.gz"]}},
        {
            "part": 2,
            "files": {
                "installed-image.tar.gz": entries["installed-image.tar.gz"],
                "derived-image.tar.gz": entries["derived-image.tar.gz"],
            },
        },
    ]
    image_custody.check_custody_manifest(value)
    value["files"]["checker-tool"][1]["files"]["tool-root.tar.gz"] = entries[
        "tool-root.tar.gz"
    ]
    with pytest.raises(ValueError):
        image_custody.check_custody_manifest(value)


def test_signed_finalization_requires_exact_frozen_part_roster():
    import json
    from p11lab import custody_authority

    profile, statement, manifest, observed, _ = _finalization_fixture()
    value = json.loads(manifest)
    original = value["files"]["checker-tool"][0]["files"]
    value["files"]["checker-tool"] = [
        {"part": 1, "files": {"tool-root.tar.gz": original["tool-root.tar.gz"]}},
        {
            "part": 2,
            "files": {
                "installed-image.tar.gz": original["installed-image.tar.gz"],
                "derived-image.tar.gz": original["derived-image.tar.gz"],
            },
        },
    ]
    manifest = json.dumps(value, sort_keys=True).encode()
    statement["manifest_sha256"] = hashlib.sha256(manifest).hexdigest()
    with pytest.raises(ValueError, match="part roster"):
        custody_authority.check_finalization(statement, manifest, profile, observed)


def test_completed_factory_authenticates_all_parts_from_signed_roster(
    tmp_path, monkeypatch
):
    from p11lab import custody_authority

    args, manifest = _completed_factory_fixture(tmp_path, monkeypatch, two_parts=True)
    verified = custody_authority.verify_completed_finalization(**args)
    assert len(verified.statement()["artifacts"]) == 9
    custody_authority.check_finalization(
        verified.statement(), manifest, verified.profile(), verified.observed()
    )


def test_custody_full_listing_rejects_unexpected_named_artifact(monkeypatch):
    client = artifacts.GitHubTransport("owner/repo", "fixture")
    expected = [
        {"id": 60, "name": "p11lab-image-custody-image-part1-100-1"},
        {"id": 70, "name": "p11lab-image-custody-control-100-1"},
    ]
    listing = {
        "total_count": 3,
        "artifacts": [
            {"id": 60, "name": expected[0]["name"]},
            {"id": 70, "name": expected[1]["name"]},
            {"id": 99, "name": "p11lab-image-custody-image-part2-100-1"},
        ],
    }
    monkeypatch.setattr(client, "_metadata", lambda path, deadline: listing)
    monkeypatch.setattr(artifacts, "stable_metadata", lambda fetch: fetch())
    with pytest.raises(ValueError, match="artifact roster"):
        client.resolve_custody_roster(100, expected)


def test_custody_full_listing_rejects_malformed_unrelated_row(monkeypatch):
    client = artifacts.GitHubTransport("owner/repo", "fixture")
    expected = [{"id": 60, "name": "p11lab-image-custody-image-part1-100-1"}]
    listing = {"total_count": 2, "artifacts": [expected[0], None]}
    monkeypatch.setattr(client, "_metadata", lambda path, deadline: listing)
    monkeypatch.setattr(artifacts, "stable_metadata", lambda fetch: fetch())
    with pytest.raises(ValueError, match="artifact listing"):
        client.resolve_custody_roster(100, expected)


def test_payload_acquisition_rejects_json_authority_before_output(tmp_path):
    from p11lab import image_custody

    with pytest.raises(TypeError, match="verified completed finalization"):
        image_custody.acquire_custody_payload(
            {"authenticated": True},
            token="fixture",
            executable=tmp_path / "gh",
            trusted_root=tmp_path / "root",
            output_dir=tmp_path / "out",
        )
    assert not (tmp_path / "out").exists()


def test_authenticated_synthetic_parts_acquire_complete_inert_payload(
    tmp_path, monkeypatch
):
    from p11lab import custody_authority, image_custody

    args, manifest = _completed_factory_fixture(
        tmp_path, monkeypatch, two_parts=True, with_payload=True
    )
    authority = custody_authority.verify_completed_finalization(**args)
    result = image_custody.acquire_custody_payload(
        authority,
        token="fixture",
        executable=args["executable"],
        trusted_root=args["trusted_root"],
        output_dir=tmp_path / "acquired",
    )
    assert type(result) is image_custody.VerifiedCustodyBytes
    assert result.as_dict()["qualification_only"] is True
    assert result.as_dict()["image_promotable"] is False
    assert (
        tmp_path / "acquired/payload/image-part1/image.tar"
    ).read_bytes() == b"synthetic image/image.tar"
    assert (
        tmp_path / "acquired/payload/image-part1/custody-manifest.json"
    ).read_bytes() == manifest
    assert (
        tmp_path / "acquired/payload/checker-tool-part2/derived-image.tar.gz"
    ).is_file()


def test_authenticated_parts_keep_corrupt_download_incomplete(tmp_path, monkeypatch):
    from p11lab import custody_authority, image_custody

    args, _ = _completed_factory_fixture(
        tmp_path, monkeypatch, mutation="corrupt_payload", with_payload=True
    )
    authority = custody_authority.verify_completed_finalization(**args)
    with pytest.raises(
        ValueError, match="custody artifact size, digest or deadline mismatch"
    ):
        image_custody.acquire_custody_payload(
            authority,
            token="fixture",
            executable=args["executable"],
            trusted_root=args["trusted_root"],
            output_dir=tmp_path / "acquired",
        )
    assert not (tmp_path / "acquired/authority-after").exists()


def test_acquisition_refuses_extracted_bytes_changed_before_completion(
    tmp_path, monkeypatch
):
    from p11lab import custody_authority, image_custody

    args, _ = _completed_factory_fixture(tmp_path, monkeypatch, with_payload=True)
    authority = custody_authority.verify_completed_finalization(**args)
    original = image_custody.extract_custody_archive

    def alter_after_extract(archive, expected, destination):
        original(archive, expected, destination)
        if destination.name == "image-part1":
            (destination / "image.tar").write_bytes(b"changed")

    monkeypatch.setattr(image_custody, "extract_custody_archive", alter_after_extract)
    with pytest.raises(ValueError, match="extracted custody"):
        image_custody.acquire_custody_payload(
            authority,
            token="fixture",
            executable=args["executable"],
            trusted_root=args["trusted_root"],
            output_dir=tmp_path / "acquired",
        )


def test_recheck_acquired_payload_refuses_later_member_or_zip_mutation(tmp_path, monkeypatch):
    from p11lab import custody_authority, image_custody

    args, _ = _completed_factory_fixture(tmp_path, monkeypatch, two_parts=True, with_payload=True)
    authority = custody_authority.verify_completed_finalization(**args)
    payload = image_custody.acquire_custody_payload(
        authority, token="fixture", executable=args["executable"],
        trusted_root=args["trusted_root"], output_dir=tmp_path / "acquired",
    )
    image_custody.verify_acquired_custody(authority, payload)
    image = tmp_path / "acquired/payload/image-part1/image.tar"
    original = image.read_bytes()
    image.write_bytes(b"changed")
    with pytest.raises(ValueError, match="extracted custody"):
        image_custody.verify_acquired_custody(authority, payload)
    image.write_bytes(original)
    archive = tmp_path / "acquired/zips/image-part1.zip"
    archive.write_bytes(b"changed")
    with pytest.raises(ValueError, match="custody"):
        image_custody.verify_acquired_custody(authority, payload)


def test_recheck_requires_both_typed_authority_and_acquired_bytes(tmp_path):
    from p11lab import image_custody

    with pytest.raises(TypeError):
        image_custody.verify_acquired_custody({}, {})


def test_recheck_refuses_extra_retained_part_or_member(tmp_path, monkeypatch):
    from p11lab import custody_authority, image_custody

    args, _ = _completed_factory_fixture(tmp_path, monkeypatch, with_payload=True)
    authority = custody_authority.verify_completed_finalization(**args)
    payload = image_custody.acquire_custody_payload(
        authority, token="fixture", executable=args["executable"],
        trusted_root=args["trusted_root"], output_dir=tmp_path / "acquired",
    )
    extra = tmp_path / "acquired/payload/image-part1/extra"
    extra.write_bytes(b"unexpected")
    with pytest.raises(ValueError, match="roster changed"):
        image_custody.verify_acquired_custody(authority, payload)
    extra.unlink()
    (tmp_path / "acquired/zips/extra.zip").write_bytes(b"unexpected")
    with pytest.raises(ValueError, match="roster changed"):
        image_custody.verify_acquired_custody(authority, payload)


def test_completed_factory_requires_protected_custody_policy(tmp_path, monkeypatch):
    from p11lab import custody_authority, delivery_authority

    args, _ = _completed_factory_fixture(tmp_path, monkeypatch)
    original = delivery_authority.load_profile

    def missing_policy(*args):
        profile = original(*args)
        profile["graph"] = [row for row in profile["graph"] if row["path"] != "src/p11lab/data/ci/delivery/custody-policy.json"]
        return profile

    monkeypatch.setattr(delivery_authority, "load_profile", missing_policy)
    with pytest.raises(ValueError, match="graph is incomplete"):
        custody_authority.verify_completed_finalization(**args)


def _component_facts_fixture(evaluator_receipt_sha=None):
    from p11lab import image_custody

    rows = []
    for number, (name, kind) in enumerate(sorted(image_custody.COMPONENTS.items()), 1):
        if name == "package-cache":
            continue
        digest = f"{number:064x}"
        if name == 'evaluator-original' and evaluator_receipt_sha is not None:
            digest = evaluator_receipt_sha
        rows.append({"name": name, "artifact": {"kind": kind, "reference": "sha256:" + digest,
                    "sha256": digest, "platform": "linux/amd64"}, "review_sha256": "a" * 64,
                    "source": {"reference": "ghcr.io/p11lab/softhsm2@sha256:" + "b" * 64,
                        "manifest_sha256": "b" * 64, "file_sha256": "c" * 64,
                        "receipt_sha256": "d" * 64, "spdx_sha256": "e" * 64,
                        "inventory_sha256": "f" * 64, "source_archive_size": 123}})
    return rows


def test_manifest_requires_complete_separately_reviewed_component_facts():
    import copy
    from p11lab import image_custody

    value = _manifest_fixture()
    value["components"] = _component_facts_fixture(value['evaluator_receipt_sha256'])
    value["files"]["source-records"][0]["files"]["component-rights.tar.gz"] = {"size": 3, "sha256": "1" * 64}
    image_custody.check_custody_manifest(value)
    for damage in ("missing", "duplicate", "source", "artifact"):
        changed = copy.deepcopy(value)
        if damage == "missing":
            changed["components"].pop()
        if damage == "duplicate":
            changed["components"].append(copy.deepcopy(changed["components"][0]))
        if damage == "source":
            changed["components"][0]["source"]["reference"] = "latest"
        if damage == "artifact":
            changed["components"][0]["artifact"]["reference"] = "sha256:" + "0" * 64
        with pytest.raises(ValueError):
            image_custody.check_custody_manifest(changed)


def test_signed_finalization_refuses_changed_component_source_fact():
    from p11lab import custody_authority

    profile, statement, manifest, observed, _ = _finalization_fixture()
    statement["components"][0]["source"]["file_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="manifest differs"):
        custody_authority.check_finalization(statement, manifest, profile, observed)


def test_validation_composition_reader_binds_exact_archive_and_candidate(tmp_path):
    import io
    import json
    import tarfile
    from p11lab import image_custody
    from p11lab.models import ArtifactRef

    artifact = ArtifactRef("docker-local", "sha256:" + "a" * 64, "a" * 64, "linux/amd64")
    entries = {}
    for name, digit in (("checker", "b"), ("consumer", "c")):
        derived = {"kind": "docker-local", "reference": "sha256:" + digit * 64,
                   "sha256": digit * 64, "platform": "linux/amd64"}
        entries[name + "-composition/composition.json"] = json.dumps({"tool": name,
            "parent": {"kind": artifact.kind, "reference": artifact.reference, "sha256": artifact.sha256,
                       "platform": artifact.platform}, "derived": derived}).encode()
    entries["checker-run/checker/report.jsonl"] = b"original checker bytes"
    entries["frozen-plan.json"] = b"original frozen plan bytes"
    entries["planning/planner.json"] = b"{}"
    entries["admission/admission.json"] = b"{}"
    entries["admission/ledger.jsonl"] = b"original ledger"
    path = tmp_path / "package.tar.gz"
    with tarfile.open(path, "w:gz") as archive:
        for name, raw in entries.items():
            member = tarfile.TarInfo(name)
            member.size = len(raw)
            archive.addfile(member, io.BytesIO(raw))
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    result = image_custody.read_validation_compositions(path, digest, artifact, evaluator_inputs_dir=tmp_path / "inputs")
    assert result["checker"].reference == "sha256:" + "b" * 64
    assert result["consumer"].reference == "sha256:" + "c" * 64
    assert (tmp_path / "inputs/checker-input/checker/report.jsonl").read_bytes() == entries["checker-run/checker/report.jsonl"]
    assert (tmp_path / "inputs/frozen-plan.json").read_bytes() == entries["frozen-plan.json"]
    with pytest.raises(ValueError, match="archive"):
        image_custody.read_validation_compositions(path, "0" * 64, artifact)
    foreign = ArtifactRef("docker-local", "sha256:" + "f" * 64, "f" * 64, "linux/amd64")
    with pytest.raises(ValueError, match="composition"):
        image_custody.read_validation_compositions(path, digest, foreign)


@pytest.mark.parametrize("damage", ["traversal", "link", "duplicate"])
def test_validation_composition_reader_refuses_unsafe_member_roster(tmp_path, damage):
    import io
    import tarfile
    from p11lab import image_custody
    from p11lab.models import ArtifactRef

    artifact = ArtifactRef("docker-local", "sha256:" + "a" * 64, "a" * 64, "linux/amd64")
    path = tmp_path / "package.tar.gz"
    with tarfile.open(path, "w:gz") as bundle:
        name = "../escape" if damage == "traversal" else "checker-composition/composition.json"
        entry = tarfile.TarInfo(name)
        if damage == "link":
            entry.type = tarfile.SYMTYPE
            entry.linkname = "elsewhere"
            bundle.addfile(entry)
        else:
            entry.size = 2
            bundle.addfile(entry, io.BytesIO(b"{}"))
            if damage == "duplicate":
                bundle.addfile(entry, io.BytesIO(b"{}"))
    with pytest.raises(ValueError):
        image_custody.read_validation_compositions(path, hashlib.sha256(path.read_bytes()).hexdigest(), artifact)


def test_validation_composition_reader_accepts_sealed_body_member(tmp_path):
    import io
    import json
    import tarfile
    from p11lab import image_custody
    from p11lab.models import ArtifactRef

    artifact = ArtifactRef("docker-local", "sha256:" + "a" * 64, "a" * 64, "linux/amd64")
    entries = {}
    for name, digit in (("checker", "b"), ("consumer", "c")):
        derived = {"kind": "docker-local", "reference": "sha256:" + digit * 64,
                   "sha256": digit * 64, "platform": "linux/amd64"}
        entries[name + "-composition/composition.json"] = json.dumps({"tool": name,
            "parent": {"kind": artifact.kind, "reference": artifact.reference, "sha256": artifact.sha256,
                       "platform": artifact.platform}, "derived": derived}).encode()
    entries["validation-body.json"] = b'{"sealed":true}'
    entries["checker-run/checker/report.jsonl"] = b"original checker bytes"
    entries["frozen-plan.json"] = b"original frozen plan bytes"
    entries["planning/planner.json"] = b"{}"
    entries["admission/admission.json"] = b"{}"
    entries["admission/ledger.jsonl"] = b"original ledger"
    path = tmp_path / "package.tar.gz"
    with tarfile.open(path, "w:gz") as archive:
        for name, raw in entries.items():
            member = tarfile.TarInfo(name)
            member.size = len(raw)
            archive.addfile(member, io.BytesIO(raw))
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    result = image_custody.read_validation_compositions(path, digest, artifact, evaluator_inputs_dir=tmp_path / "inputs")
    assert result["checker"].reference == "sha256:" + "b" * 64
    assert result["consumer"].reference == "sha256:" + "c" * 64
    assert (tmp_path / "inputs/frozen-plan.json").read_bytes() == entries["frozen-plan.json"]
    assert list((tmp_path / "inputs").rglob("validation-body.json")) == []


def test_validation_body_digest_restream_binds_facts_claim_to_package_bytes(tmp_path):
    import io
    import tarfile
    from p11lab import image_custody

    body = b'{"sealed":true}'
    path = tmp_path / "package.tar.gz"
    with tarfile.open(path, "w:gz") as archive:
        for name, raw in (("checker-composition/composition.json", b"{}"), ("validation-body.json", body)):
            member = tarfile.TarInfo(name)
            member.size = len(raw)
            archive.addfile(member, io.BytesIO(raw))
    digest = hashlib.sha256(body).hexdigest()
    image_custody._check_validation_body_digest(path, digest)
    with pytest.raises(ValueError, match="body digest mismatch"):
        image_custody._check_validation_body_digest(path, "f" * 64)
    bare = tmp_path / "bare.tar.gz"
    with tarfile.open(bare, "w:gz") as archive:
        member = tarfile.TarInfo("checker-composition/composition.json")
        member.size = 2
        archive.addfile(member, io.BytesIO(b"{}"))
    with pytest.raises(ValueError, match="body missing"):
        image_custody._check_validation_body_digest(bare, digest)


def test_custody_schema_tracks_closed_manifest_and_component_roles():
    import json
    from importlib.resources import files
    from p11lab import image_custody

    schema = json.loads(files("p11lab").joinpath("data/ci/image-custody.schema.json").read_bytes())
    assert schema["$id"] == "urn:p11lab:schema:image-custody:v1"
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == set(_manifest_fixture()) == set(schema["properties"])
    assert set(schema["$defs"]["files"]["properties"]) == set(image_custody.SEGMENT_ROLES)
    assert set(schema["$defs"]["component"]["properties"]["name"]["enum"]) == set(image_custody.COMPONENTS)
    assert set(schema["$defs"]["validation"]["required"]) == set(_manifest_fixture()["facts"]["validation"])


def test_completed_factory_requires_protected_custody_schema(tmp_path, monkeypatch):
    from p11lab import custody_authority, delivery_authority

    args, _ = _completed_factory_fixture(tmp_path, monkeypatch)
    original = delivery_authority.load_profile

    def missing_schema(*args):
        profile = original(*args)
        profile["graph"] = [row for row in profile["graph"] if row["path"] != "src/p11lab/data/ci/image-custody.schema.json"]
        return profile

    monkeypatch.setattr(delivery_authority, "load_profile", missing_schema)
    with pytest.raises(ValueError, match="graph is incomplete"):
        custody_authority.verify_completed_finalization(**args)


def test_producer_requires_actual_source_admission_before_tool_or_save(tmp_path, monkeypatch):
    from p11lab import delivery_authority, image_custody
    from p11lab.models import ArtifactRef

    artifact = ArtifactRef("docker-local", "sha256:" + "a" * 64, "a" * 64, "linux/amd64")
    calls = []

    def reject_source(**kwargs):
        calls.append("source")
        raise ValueError("actual source admission refused")

    monkeypatch.setattr(delivery_authority, "admit_source", reject_source)
    monkeypatch.setattr(image_custody, "_producer_component_artifacts", lambda *args: calls.append("tools"))
    with pytest.raises(ValueError, match="actual source admission refused"):
        image_custody.verify_custody_producer(
            environment="softhsm2", channel="release", artifact=artifact,
            evidence_dir=tmp_path / "evidence", validation_dir=tmp_path / "validation",
            build_receipt=tmp_path / "build", sealed_dir=tmp_path / "sealed",
            registry="ghcr.io/p11lab/softhsm2", seal_digest="b" * 64, content_digest="c" * 64,
            context_path=tmp_path / "context", bundle_path=tmp_path / "bundle", executable=tmp_path / "gh",
            trusted_root=tmp_path / "root", run_id=100, attempt=1, token="fixture",
            validation_policy={}, component_sources={}, output_dir=tmp_path / "out",
        )
    assert calls == ["source"]


def test_producer_preconditions_cannot_be_constructed_from_caller_json():
    from p11lab import image_custody

    with pytest.raises(TypeError):
        image_custody.VerifiedCustodyProducer(None, {"status": "eligible"})


def test_custody_image_save_never_starts_when_actual_source_admission_fails(tmp_path, monkeypatch):
    from p11lab import delivery_authority, docker, image_custody
    from p11lab.models import ArtifactRef

    artifact = ArtifactRef("docker-local", "sha256:" + "a" * 64, "a" * 64, "linux/amd64")
    calls = []

    def reject_source(**kwargs):
        raise ValueError("source admission rejected")

    monkeypatch.setattr(delivery_authority, "admit_source", reject_source)
    monkeypatch.setattr(docker, "Docker", lambda: calls.append("docker"))
    with pytest.raises(ValueError, match="source admission rejected"):
        image_custody.prepare_custody_image(
            environment="softhsm2", channel="release", artifact=artifact,
            evidence_dir=tmp_path / "evidence", validation_dir=tmp_path / "validation",
            build_receipt=tmp_path / "build", sealed_dir=tmp_path / "sealed",
            registry="ghcr.io/p11lab/softhsm2", seal_digest="b" * 64, content_digest="c" * 64,
            context_path=tmp_path / "context", bundle_path=tmp_path / "bundle", executable=tmp_path / "gh",
            trusted_root=tmp_path / "root", run_id=100, attempt=1, token="fixture",
            validation_policy={}, component_sources={}, output_dir=tmp_path / "out",
        )
    assert calls == []
    assert not (tmp_path / "out/image.tar").exists()


def test_manifest_component_metadata_binds_original_evaluator_receipt():
    from p11lab import image_custody

    value = _manifest_fixture()
    component = next(row for row in value["components"] if row["name"] == "evaluator-original")
    component["artifact"]["sha256"] = value["evaluator_receipt_sha256"]
    component["artifact"]["reference"] = "sha256:" + value["evaluator_receipt_sha256"]
    image_custody.check_custody_manifest(value)
    component["artifact"]["sha256"] = "0" * 64
    component["artifact"]["reference"] = "sha256:" + "0" * 64
    with pytest.raises(ValueError, match="evaluator"):
        image_custody.check_custody_manifest(value)


def test_saved_image_inspection_binds_opened_file_and_config_layer_bytes(tmp_path):
    import io
    import json
    import tarfile
    from p11lab import image_custody

    layer = io.BytesIO()
    with tarfile.open(fileobj=layer, mode="w") as contents:
        info = tarfile.TarInfo("fixture.txt")
        info.size = 7
        contents.addfile(info, io.BytesIO(b"fixture"))
    layer_bytes = layer.getvalue()
    diff = "sha256:" + hashlib.sha256(layer_bytes).hexdigest()
    config = json.dumps({"rootfs": {"type": "layers", "diff_ids": [diff]},
                         "os": "linux", "architecture": "amd64"}).encode()
    manifest = json.dumps([{"Config": "config.json", "Layers": ["layer.tar"]}]).encode()
    archive = tmp_path / "image.tar"
    with tarfile.open(archive, "w") as saved:
        for name, raw in (("manifest.json", manifest), ("config.json", config), ("layer.tar", layer_bytes)):
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            saved.addfile(info, io.BytesIO(raw))
    distribution, observed = image_custody._inspect_saved_image(archive)
    assert distribution["config_sha256"] == hashlib.sha256(config).hexdigest()
    assert distribution["layers"][0]["diff_id"] == diff
    assert observed["sha256"] == hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.write_bytes(b"not an image")
    with pytest.raises(ValueError):
        image_custody._inspect_saved_image(archive)


def test_saved_image_refuses_transporting_mutable_repo_tags(tmp_path):
    import io
    import json
    import tarfile
    from p11lab import image_custody

    layer = io.BytesIO()
    with tarfile.open(fileobj=layer, mode="w") as contents:
        info = tarfile.TarInfo("fixture.txt")
        info.size = 1
        contents.addfile(info, io.BytesIO(b"x"))
    blob = layer.getvalue()
    config = json.dumps({"rootfs": {"type": "layers", "diff_ids": ["sha256:" + hashlib.sha256(blob).hexdigest()]},
                         "os": "linux", "architecture": "amd64"}).encode()
    manifest = json.dumps([{"Config": "config.json", "Layers": ["layer.tar"], "RepoTags": ["foreign:latest"]}]).encode()
    archive = tmp_path / "tagged.tar"
    with tarfile.open(archive, "w") as saved:
        for name, raw in (("manifest.json", manifest), ("config.json", config), ("layer.tar", blob)):
            item = tarfile.TarInfo(name)
            item.size = len(raw)
            saved.addfile(item, io.BytesIO(raw))
    with pytest.raises(ValueError, match="tag"):
        image_custody._inspect_saved_image(archive)


def test_candidate_load_rejects_untyped_authority_before_output_or_docker(tmp_path, monkeypatch):
    from p11lab import docker, image_custody

    calls = []
    monkeypatch.setattr(docker, "Docker", lambda: calls.append("docker"))
    with pytest.raises(TypeError, match="verified completed authority"):
        image_custody.load_custody_image(
            {"authenticated": True}, {}, token="fixture", executable=tmp_path / "gh",
            trusted_root=tmp_path / "root", output_dir=tmp_path / "loaded",
        )
    assert calls == []
    assert not (tmp_path / "loaded").exists()


def test_saved_image_binding_requires_engine_descriptor_reach_exact_config_and_layers():
    from p11lab import image_custody
    from p11lab.models import ArtifactRef

    candidate = ArtifactRef("docker-local", "sha256:" + "a" * 64, "a" * 64, "linux/amd64")
    distribution = {"config_sha256": "b" * 64, "platform": "linux/amd64",
                    "layers": [{"sha256": "c" * 64, "diff_id": "sha256:" + "d" * 64}],
                    "raw_descriptors": [{"sha256": "a" * 64, "document": {
                        "config": {"digest": "sha256:" + "b" * 64},
                        "layers": [{"digest": "sha256:" + "c" * 64}]}}]}
    image_custody._check_saved_image_binding(candidate, distribution)
    distribution["raw_descriptors"][0]["document"]["config"]["digest"] = "sha256:" + "f" * 64
    with pytest.raises(ValueError, match="descriptor"):
        image_custody._check_saved_image_binding(candidate, distribution)


def test_synthetic_authenticated_payload_loads_exact_inert_bytes_before_source_replay(tmp_path, monkeypatch):
    import io
    import json
    import tarfile
    from pathlib import Path
    from p11lab import custody_authority, docker, image_custody

    layer = io.BytesIO()
    with tarfile.open(fileobj=layer, mode="w") as contents:
        item = tarfile.TarInfo("fixture.txt")
        item.size = 7
        contents.addfile(item, io.BytesIO(b"fixture"))
    layer_bytes = layer.getvalue()
    config = json.dumps({"rootfs": {"type": "layers", "diff_ids": ["sha256:" + hashlib.sha256(layer_bytes).hexdigest()]},
                         "os": "linux", "architecture": "amd64"}).encode()
    image = io.BytesIO()
    with tarfile.open(fileobj=image, mode="w") as saved:
        manifest = json.dumps([{"Config": "config.json", "Layers": ["layer.tar"]}]).encode()
        for name, data in (("manifest.json", manifest), ("config.json", config), ("layer.tar", layer_bytes)):
            item = tarfile.TarInfo(name)
            item.size = len(data)
            saved.addfile(item, io.BytesIO(data))
    args, _ = _completed_factory_fixture(tmp_path, monkeypatch, with_payload=True, image_fixture=image.getvalue())
    authority = custody_authority.verify_completed_finalization(**args)
    acquired = image_custody.acquire_custody_payload(authority, token="fixture", executable=args["executable"],
        trusted_root=args["trusted_root"], output_dir=tmp_path / "acquired")
    expected = acquired.as_dict()["manifest"]
    seen = []

    class FakeDocker:
        env = {"DOCKER_HOST": "unix:///fixture"}

        def command(self, argv, timeout=15, **kwargs):
            assert argv[:3] == ["image", "load", "--input"]
            seen.append(Path(argv[3]).read_bytes())
            return docker.CommandResult(0, "loaded fixture", "")

        def image(self, artifact):
            assert artifact.reference == expected["engine_id"]
            return {"Id": artifact.reference, "Os": "linux", "Architecture": "amd64",
                    "RootFS": {"Layers": [row["diff_id"] for row in expected["layers"]]}}

    monkeypatch.setattr(docker, "Docker", FakeDocker)
    loaded = image_custody.load_custody_image(authority, acquired, token="fixture", executable=args["executable"],
        trusted_root=args["trusted_root"], output_dir=tmp_path / "loaded")
    assert seen == [image.getvalue()]
    assert type(loaded) is image_custody.InertLoadedCustodyImage
    assert loaded.as_dict()["source_status"] == "not-yet-replayed"
    assert loaded.as_dict()["image_promotable"] is False
    (tmp_path / "acquired/payload/image-part1/image.tar").write_bytes(b"changed")
    with pytest.raises(ValueError, match="extracted custody"):
        image_custody.load_custody_image(authority, acquired, token="fixture", executable=args["executable"],
            trusted_root=args["trusted_root"], output_dir=tmp_path / "changed-load")
    assert seen == [image.getvalue()]


def test_active_custody_job_id_is_independently_observed_and_unique(monkeypatch):
    from p11lab import delivery_authority, image_custody

    profile, _, _, _, _, _, _ = _signature_fixture()
    selector, run, jobs, _, _ = _metadata_fixture()
    run.update(status="in_progress", workflow_id=profile["workflow_id"], head_sha=profile["source_sha"],
               repository={"id": profile["repository_id"], "owner": {"id": profile["owner_id"]}})
    jobs["jobs"][0].update(status="in_progress", name=profile["job"], head_sha=profile["source_sha"])
    monkeypatch.setattr(delivery_authority, "load_profile", lambda *args: profile)
    monkeypatch.setattr(delivery_authority, "_authenticate_live_run", lambda *args, **kwargs: {"fixture": True})

    class Transport:
        def _metadata(self, path, deadline):
            return jobs if "/jobs?" in path else run

    monkeypatch.setattr(delivery_authority, "_github_transport", lambda *args: Transport())
    monkeypatch.setattr(inputs, "stable_metadata", lambda fetch: fetch())
    result = image_custody._active_custody_job("softhsm2", "release", 100, 1, "fixture")
    assert result["job_id"] == selector["job_id"]
    jobs["jobs"].append(dict(jobs["jobs"][0], name="different-job"))
    jobs["total_count"] = len(jobs["jobs"])
    with pytest.raises(ValueError, match="job"):
        image_custody._active_custody_job("softhsm2", "release", 100, 1, "fixture")


def test_segment_plan_freezes_complete_fixed_member_roster_with_two_parts():
    import copy
    from p11lab import image_custody

    files = {role: {name: {"size": 1, "sha256": f"{index:064x}"}
                    for index, name in enumerate(names, 1)}
             for role, names in image_custody.SEGMENT_FILES.items()}
    for name in list(files["source-records"])[:3]:
        files["source-records"][name]["size"] = 400 * 1024**2
    result = image_custody._plan_custody_parts(files)
    assert len(result["source-records"]) == 2
    assert set().union(*(set(part["files"]) for part in result["source-records"])) == set(files["source-records"])
    assert result == image_custody._plan_custody_parts(copy.deepcopy(files))
    damaged = copy.deepcopy(files)
    for name in list(damaged["source-records"])[:5]:
        damaged["source-records"][name]["size"] = 500 * 1024**2
    with pytest.raises(ValueError, match="part"):
        image_custody._plan_custody_parts(damaged)
    damaged = copy.deepcopy(files)
    damaged["image"].pop("image.tar")
    with pytest.raises(ValueError, match="roster"):
        image_custody._plan_custody_parts(damaged)


def test_payload_prepare_stops_before_any_save_without_actual_d(tmp_path, monkeypatch):
    from p11lab import delivery_authority, docker, image_custody
    from p11lab.models import ArtifactRef

    calls = []
    monkeypatch.setattr(delivery_authority, "admit_source", lambda **kwargs: (_ for _ in ()).throw(ValueError("source D refused")))
    monkeypatch.setattr(docker, "Docker", lambda: calls.append("docker"))
    artifact = ArtifactRef("docker-local", "sha256:" + "a" * 64, "a" * 64, "linux/amd64")
    with pytest.raises(ValueError, match="source D refused"):
        image_custody.prepare_custody_payload(
            environment="softhsm2", channel="release", artifact=artifact,
            evidence_dir=tmp_path / "evidence", validation_dir=tmp_path / "validation",
            build_receipt=tmp_path / "build", sealed_dir=tmp_path / "sealed",
            registry="ghcr.io/p11lab/softhsm2", seal_digest="b" * 64, content_digest="c" * 64,
            context_path=tmp_path / "context", bundle_path=tmp_path / "bundle", executable=tmp_path / "gh",
            trusted_root=tmp_path / "root", run_id=100, attempt=1, token="fixture",
            validation_policy={}, component_sources={}, output_dir=tmp_path / "out",
        )
    assert calls == []
    assert not (tmp_path / "out/parts").exists()


def test_manifest_requires_exact_component_rights_tree_identity():
    from p11lab import image_custody

    value = _manifest_fixture()
    value["component_rights_tree_sha256"] = "c" * 64
    image_custody.check_custody_manifest(value)
    value["component_rights_tree_sha256"] = "not-a-digest"
    with pytest.raises(ValueError):
        image_custody.check_custody_manifest(value)


def test_fresh_source_replay_requires_all_three_typed_boundaries(tmp_path, monkeypatch):
    from p11lab import docker, image_custody

    calls = []
    monkeypatch.setattr(docker, "Docker", lambda: calls.append("docker"))
    with pytest.raises(TypeError, match="typed"):
        image_custody.replay_custody_source(
            {"verified": True}, {}, {}, evaluator_root=tmp_path / "evaluator", token="fixture",
            executable=tmp_path / "gh", trusted_root=tmp_path / "root", output_dir=tmp_path / "replay",
        )
    assert calls == []
    assert not (tmp_path / "replay").exists()


def test_active_custody_artifact_is_not_completed_authority_and_requires_exact_identity():
    identity, run, jobs, listing, now = _metadata_fixture()
    run["status"], run["conclusion"] = "in_progress", None
    jobs["jobs"][0]["status"], jobs["jobs"][0]["conclusion"] = "in_progress", None
    jobs["jobs"][0]["completed_at"] = None
    result = inputs.select_active_custody_artifact(identity, run, jobs, listing, now=now)
    assert result["id"] == identity["artifact_id"]
    changed = dict(identity, artifact_id=identity["artifact_id"] + 1)
    with pytest.raises(ValueError):
        inputs.select_active_custody_artifact(changed, run, jobs, listing, now=now)
    with pytest.raises(ValueError):
        inputs.select_custody_artifact(identity, run, jobs, listing, now=now)


def test_active_artifact_transport_uses_stable_separate_active_selector(monkeypatch):
    identity, run, jobs, listing, now = _metadata_fixture()
    run["status"], run["conclusion"] = "in_progress", None
    jobs["jobs"][0].update(status="in_progress", conclusion=None, completed_at=None)
    client = artifacts.GitHubTransport("owner/repo", "fixture")

    def metadata(path, deadline):
        if "/jobs?" in path:
            return jobs
        if "/artifacts?" in path:
            return listing
        return run

    monkeypatch.setattr(client, "_metadata", metadata)
    monkeypatch.setattr(artifacts, "stable_metadata", lambda fetch: fetch())
    result = client.resolve_active_custody(identity, now=now)
    assert result["artifact"]["id"] == identity["artifact_id"]
    assert result["job"]["id"] == identity["job_id"]
    with pytest.raises(ValueError):
        client.resolve_custody(identity, now=now)


def test_active_uploads_recheck_every_signed_part_and_reject_corruption(tmp_path):
    import copy
    from p11lab import image_custody

    profile, statement, _, observed, _ = _finalization_fixture()
    metadata = copy.deepcopy(observed["segments"])
    manifest, archives = _materialize_fixture_parts(statement, metadata)
    value = inputs.load_json(manifest)
    uploads = [{"name": row["name"], "id": row["id"], "digest": row["digest"]} for row in statement["artifacts"]]

    class FakeTransport:
        def resolve_custody_roster(self, run_id, expected):
            assert run_id == 100
            return {"artifacts": expected}

        def resolve_active_custody(self, selector, *, now):
            row = next(item for item in metadata if item["id"] == selector["artifact_id"])
            return {"run": observed["run"], "job": observed["job"], "job_count": 1, "artifact": row}

        def download_custody(self, identity, destination):
            destination.write_bytes(archives[identity.id])

    rows = image_custody._verify_active_uploads(FakeTransport(), profile, statement["run"], value, manifest,
                                                 uploads, tmp_path / "check")
    assert rows == statement["artifacts"]
    archives[uploads[0]["id"]] = b"corrupt"
    with pytest.raises(ValueError):
        image_custody._verify_active_uploads(FakeTransport(), profile, statement["run"], value, manifest,
                                             uploads, tmp_path / "bad")


def test_finalization_refuses_without_new_actual_source_admission(tmp_path, monkeypatch):
    from p11lab import delivery_authority, image_custody
    from p11lab.models import ArtifactRef

    calls = []
    monkeypatch.setattr(delivery_authority, "admit_source", lambda **kwargs: (_ for _ in ()).throw(ValueError("source D refused")))
    monkeypatch.setattr(delivery_authority, "_github_transport", lambda *args: calls.append("transport"))
    artifact = ArtifactRef("docker-local", "sha256:" + "a" * 64, "a" * 64, "linux/amd64")
    with pytest.raises(ValueError, match="source D refused"):
        image_custody.finalize_custody_payload(
            payload_dir=tmp_path / "payload", uploads=[], environment="softhsm2", channel="release", artifact=artifact,
            evidence_dir=tmp_path / "evidence", validation_dir=tmp_path / "validation", build_receipt=tmp_path / "build",
            sealed_dir=tmp_path / "sealed", registry="ghcr.io/p11lab/softhsm2", seal_digest="b" * 64,
            content_digest="c" * 64, context_path=tmp_path / "context", bundle_path=tmp_path / "bundle",
            executable=tmp_path / "gh", trusted_root=tmp_path / "root", run_id=100, attempt=1, token="fixture",
            validation_policy={}, component_sources={}, output_dir=tmp_path / "out",
        )
    assert not calls
    assert not (tmp_path / "out/custody-finalization.json").exists()


def test_component_source_preparation_checks_actual_d_before_component_inspection(tmp_path, monkeypatch):
    from p11lab import delivery_authority, image_custody
    from p11lab.models import ArtifactRef

    calls = []
    monkeypatch.setattr(delivery_authority, "admit_source", lambda **kwargs: (_ for _ in ()).throw(ValueError("source D refused")))
    monkeypatch.setattr(image_custody, "_producer_component_artifacts", lambda *args: calls.append("inspect"))
    artifact = ArtifactRef("docker-local", "sha256:" + "a" * 64, "a" * 64, "linux/amd64")
    with pytest.raises(ValueError, match="source D refused"):
        image_custody.materialize_custody_components(
            environment="softhsm2", channel="release", artifact=artifact,
            evidence_dir=tmp_path / "evidence", validation_dir=tmp_path / "validation", build_receipt=tmp_path / "build",
            sealed_dir=tmp_path / "sealed", registry="ghcr.io/p11lab/softhsm2", seal_digest="b" * 64,
            content_digest="c" * 64, context_path=tmp_path / "context", bundle_path=tmp_path / "bundle",
            executable=tmp_path / "gh", trusted_root=tmp_path / "root", run_id=100, attempt=1, token="fixture",
            validation_policy={}, output_dir=tmp_path / "out",
        )
    assert not calls


def test_installed_custody_cli_exposes_operations_and_default_owner_profile_stays_disabled(tmp_path, monkeypatch, capsys):
    from p11lab import cli, docker

    for operation in ("component-sources", "prepare", "finalize", "acquire", "prepare-evaluator"):
        with pytest.raises(SystemExit) as exit_result:
            cli.main(["custody", operation, "--help"])
        assert exit_result.value.code == 0
        capsys.readouterr()
    calls = []
    monkeypatch.setattr(docker, "Docker", lambda: calls.append("docker"))
    monkeypatch.setenv("GH_TOKEN", "fixture")
    result = cli.main(["custody", "acquire", "--environment", "softhsm2", "--channel", "release",
        "--run-id", "100", "--attempt", "1", "--job-id", "50", "--control-id", "70",
        "--gh", str(tmp_path / "gh"), "--trusted-root", str(tmp_path / "root"),
        "--evaluator-root", str(tmp_path / "evaluator"), "--output-dir", str(tmp_path / "result")])
    assert result == 2
    assert "protected source producer profile unavailable" in capsys.readouterr().err
    assert not calls
    assert not (tmp_path / "result").exists()


def test_producer_planner_replay_preserves_path_specific_stdout_and_compares_selection():
    from p11lab.image_custody import _same_planner_selection

    original = {'files': ['test_digest.py'], 'evaluator_source_sha256': {'test_digest.py': 'a' * 64},
                'stdout_sha256': 'b' * 64, 'evaluator_receipt_sha256': 'c' * 64}
    replay = dict(original, stdout_sha256='d' * 64)
    assert _same_planner_selection(original, replay)
    assert not _same_planner_selection(original, dict(replay, files=['test_sign.py']))
    assert not _same_planner_selection(original, dict(replay, evaluator_source_sha256={'test_digest.py': 'e' * 64}))
    assert not _same_planner_selection(original, dict(replay, evaluator_receipt_sha256='f' * 64))
    assert not _same_planner_selection(original, dict(replay, unexpected=True))


def test_validation_composition_reader_bounds_extended_metadata_before_allocation(tmp_path):
    import gzip
    import tarfile
    from p11lab import image_custody
    from p11lab.models import ArtifactRef

    entry = tarfile.TarInfo('oversized-pax')
    entry.type = tarfile.XHDTYPE
    entry.size = 8 * 1024**2 + 1
    path = tmp_path / 'package.tar.gz'
    path.write_bytes(gzip.compress(entry.tobuf(format=tarfile.USTAR_FORMAT) + b'\0' * 1024))
    artifact = ArtifactRef('docker-local', 'sha256:' + 'a' * 64, 'a' * 64, 'linux/amd64')
    with pytest.raises(ValueError, match='metadata record byte bound'):
        image_custody.read_validation_compositions(path, hashlib.sha256(path.read_bytes()).hexdigest(), artifact)


def test_original_source_attestation_replay_checks_actual_verifier_subject_and_job_window(tmp_path, monkeypatch):
    import json
    from p11lab import custody_authority, delivery_authority, image_custody
    from test_source_authority import fixture as source_fixture

    args, _ = _completed_factory_fixture(tmp_path, monkeypatch)
    authority = custody_authority.verify_completed_finalization(**args)
    profile, statement = authority.profile(), authority.statement()
    run = statement['run']
    identity = {'run_id': run['run_id'], 'attempt': run['attempt'], 'job': run['job']}
    facts = {'fixture': 'original facts'}
    context = json.dumps(delivery_authority._make_context('softhsm2', 'release', profile, identity, facts), sort_keys=True).encode()
    bundle = b'{}'
    payload = tmp_path / 'source-replay-fixture/payload/source-records-part1'
    payload.mkdir(parents=True)
    (payload / 'source-context.json').write_bytes(context)
    (payload / 'source-bundle.json').write_bytes(bundle)
    records = {name: {'size': len(value), 'sha256': hashlib.sha256(value).hexdigest()}
               for name, value in [('source-context.json', context), ('source-bundle.json', bundle)]}
    data = {'output_dir': str(payload.parents[1]), 'manifest': {'facts': facts,
            'files': {'source-records': [{'part': 1, 'files': records}]}}}
    _, _, _, result = source_fixture()
    verified = result[0]['verificationResult']
    verified['statement']['subject'][0]['digest']['sha256'] = hashlib.sha256(context).hexdigest()
    verified['signature']['certificate']['runInvocationURI'] = 'https://github.com/p11lab/controller/actions/runs/100/attempts/1'
    verified['verifiedTimestamps'][0]['timestamp'] = '2026-10-28T10:30:00Z'
    executable = tmp_path / 'fixture-source-verifier'

    def install_verifier():
        executable.write_text('#!/bin/sh\nprintf %s ' + repr(json.dumps(result)) + '\n')
        executable.chmod(0o700)
        monkeypatch.setattr(delivery_authority, 'GH_EXECUTABLE_SHA256', hashlib.sha256(executable.read_bytes()).hexdigest())

    install_verifier()
    image_custody._verify_original_source_attestation(authority, data, executable=executable,
        trusted_root=args['trusted_root'], output_dir=tmp_path / 'source-attestation-good')
    verified['verifiedTimestamps'][0]['timestamp'] = '2026-10-28T08:00:00Z'
    install_verifier()
    with pytest.raises(ValueError, match='outside accepted window'):
        image_custody._verify_original_source_attestation(authority, data, executable=executable,
            trusted_root=args['trusted_root'], output_dir=tmp_path / 'source-attestation-bad-time')


def _image_tar_for_bounded_layer(raw_layer):
    import gzip
    import io
    import json
    import tarfile

    compressed = gzip.compress(raw_layer)
    config = json.dumps({'rootfs': {'type': 'layers', 'diff_ids': ['sha256:' + hashlib.sha256(raw_layer).hexdigest()]},
                         'os': 'linux', 'architecture': 'amd64'}).encode()
    manifest = json.dumps([{'Config': 'config.json', 'Layers': ['layer.tar.gz']}]).encode()
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w') as archive:
        for name, raw in [('manifest.json', manifest), ('config.json', config), ('layer.tar.gz', compressed)]:
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            archive.addfile(info, io.BytesIO(raw))
    return stream.getvalue()


@pytest.mark.parametrize('location', ['outer', 'layer'])
@pytest.mark.parametrize('kind', ['pax', 'gnu'])
def test_saved_image_bounds_outer_and_layer_metadata_before_stdlib_allocation(tmp_path, monkeypatch, location, kind):
    import tarfile
    from p11lab import image_custody

    limit = 8 * 1024**2
    info = tarfile.TarInfo('oversized-extension')
    info.type = tarfile.XHDTYPE if kind == 'pax' else tarfile.GNUTYPE_LONGNAME
    info.size = limit + 1
    damaged = info.tobuf(format=tarfile.USTAR_FORMAT) + b'\0' * 1024
    path = tmp_path / 'image.tar'
    path.write_bytes(damaged if location == 'outer' else _image_tar_for_bounded_layer(damaged))
    method = '_proc_pax' if kind == 'pax' else '_proc_gnulong'
    original = getattr(tarfile.TarInfo, method)

    class Guard:
        def __init__(self, wrapped):
            self.wrapped = wrapped
        def read(self, size=-1):
            if size < 0 or size > limit:
                raise AssertionError('unbounded stdlib metadata allocation')
            return self.wrapped.read(size)
        def __getattr__(self, name):
            return getattr(self.wrapped, name)

    def guarded(self, archive):
        archive.fileobj = Guard(archive.fileobj)
        return original(self, archive)

    monkeypatch.setattr(tarfile.TarInfo, method, guarded)
    with pytest.raises(ValueError, match='metadata record byte bound'):
        image_custody._inspect_saved_image(path)


def _bounded_test_layer(*, pax=False, payload_size=0):
    import io
    import tarfile

    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=tarfile.PAX_FORMAT) as layer:
        entry = tarfile.TarInfo('fixture')
        if pax:
            entry.pax_headers = {'path': 'fixture-long-name'}
        entry.size = payload_size
        layer.addfile(entry, io.BytesIO(b'\0' * payload_size))
    return output.getvalue()


def _image_tar_for_bounded_layers(layers):
    import gzip
    import io
    import json
    import tarfile

    names = [f'layer-{index}.tar.gz' for index in range(len(layers))]
    manifest = json.dumps([{'Config': 'config.json', 'Layers': names}]).encode()
    config = json.dumps({'rootfs': {'type': 'layers', 'diff_ids': ['sha256:' + hashlib.sha256(layer).hexdigest()
                                                                     for layer in layers]},
                         'os': 'linux', 'architecture': 'amd64'}).encode()
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w') as archive:
        for name, raw in [('manifest.json', manifest), ('config.json', config),
                          *[(name, gzip.compress(layer)) for name, layer in zip(names, layers)]]:
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            archive.addfile(info, io.BytesIO(raw))
    return output.getvalue()


def test_saved_image_bounds_aggregate_metadata_across_layers(tmp_path, monkeypatch):
    from p11lab import image_custody

    layer = _bounded_test_layer(pax=True)
    path = tmp_path / 'image.tar'
    path.write_bytes(_image_tar_for_bounded_layers([layer, layer]))
    monkeypatch.setattr(image_custody, '_TAR_METADATA_TOTAL_LIMIT', 35)
    with pytest.raises(ValueError, match='aggregate metadata'):
        image_custody._inspect_saved_image(path)


@pytest.mark.parametrize('limit', [2, 5])
def test_saved_image_bounds_outer_and_layer_header_counts(tmp_path, monkeypatch, limit):
    from p11lab import image_custody

    path = tmp_path / 'image.tar'
    path.write_bytes(_image_tar_for_bounded_layer(_bounded_test_layer()))
    monkeypatch.setattr(image_custody, '_TAR_HEADER_LIMIT', limit)
    with pytest.raises(ValueError, match='header count'):
        image_custody._inspect_saved_image(path)


@pytest.mark.parametrize('location', ['outer', 'layer'])
def test_saved_image_refuses_nonzero_tar_trailing_data(tmp_path, location):
    from p11lab import image_custody

    layer = _bounded_test_layer()
    raw = _image_tar_for_bounded_layer(layer + (b'bad' if location == 'layer' else b''))
    path = tmp_path / 'image.tar'
    path.write_bytes(raw + (b'bad' if location == 'outer' else b''))
    with pytest.raises(ValueError, match='trailing'):
        image_custody._inspect_saved_image(path)


def test_saved_image_bounds_decompressed_layer_stream(tmp_path, monkeypatch):
    from p11lab import image_custody

    path = tmp_path / 'image.tar'
    path.write_bytes(_image_tar_for_bounded_layer(_bounded_test_layer(payload_size=65536)))
    assert path.stat().st_size < 32768
    monkeypatch.setattr(image_custody, '_TAR_STREAM_LIMIT', 32768)
    with pytest.raises(ValueError, match='stream byte'):
        image_custody._inspect_saved_image(path)


@pytest.mark.parametrize('format_name', ['PAX_FORMAT', 'GNU_FORMAT'])
def test_saved_image_accepts_bounded_long_layer_paths(tmp_path, format_name):
    import io
    import tarfile
    from p11lab import image_custody

    layer_bytes = io.BytesIO()
    with tarfile.open(fileobj=layer_bytes, mode='w', format=getattr(tarfile, format_name)) as layer:
        member = tarfile.TarInfo('a' * 130)
        member.size = 1
        layer.addfile(member, io.BytesIO(b'x'))
    path = tmp_path / 'image.tar'
    path.write_bytes(_image_tar_for_bounded_layer(layer_bytes.getvalue()))
    observed, identity = image_custody._inspect_saved_image(path)
    assert observed['layers'][0]['diff_id'] == 'sha256:' + hashlib.sha256(layer_bytes.getvalue()).hexdigest()
    assert identity['sha256'] == hashlib.sha256(path.read_bytes()).hexdigest()


def test_saved_image_accepts_standard_bounded_pax_timestamp(tmp_path):
    import io
    import tarfile
    from p11lab import image_custody

    layer_bytes = io.BytesIO()
    with tarfile.open(fileobj=layer_bytes, mode='w', format=tarfile.PAX_FORMAT) as layer:
        member = tarfile.TarInfo('fixture')
        member.pax_headers = {'mtime': '123.5'}
        member.size = 1
        layer.addfile(member, io.BytesIO(b'x'))
    path = tmp_path / 'image.tar'
    path.write_bytes(_image_tar_for_bounded_layer(layer_bytes.getvalue()))
    observed, _ = image_custody._inspect_saved_image(path)
    assert observed['layers'][0]['diff_id'] == 'sha256:' + hashlib.sha256(layer_bytes.getvalue()).hexdigest()


@pytest.mark.parametrize('location', ['outer', 'layer'])
@pytest.mark.parametrize('damage', ['sparse', 'duplicate', 'global'])
def test_saved_image_rejects_unsupported_or_ambiguous_extended_headers(tmp_path, location, damage):
    import tarfile
    from p11lab import image_custody

    def pax_record(key, value):
        body = b' ' + key + b'=' + value + b'\n'
        size = len(body) + 1
        while len(str(size)) + len(body) != size:
            size = len(str(size)) + len(body)
        return str(size).encode() + body

    payload = pax_record(b'GNU.sparse.map' if damage == 'sparse' else b'path', b'fixture')
    if damage == 'duplicate':
        payload += pax_record(b'path', b'other')
    extension = tarfile.TarInfo('pax')
    extension.type = tarfile.XGLTYPE if damage == 'global' else tarfile.XHDTYPE
    extension.size = len(payload)
    raw = extension.tobuf(format=tarfile.USTAR_FORMAT) + payload + b'\0' * (-len(payload) % 512)
    raw += tarfile.TarInfo('fixture').tobuf(format=tarfile.USTAR_FORMAT) + b'\0' * 1024
    path = tmp_path / 'image.tar'
    path.write_bytes(raw if location == 'outer' else _image_tar_for_bounded_layer(raw))
    with pytest.raises(ValueError, match='metadata'):
        image_custody._inspect_saved_image(path)


def _image_tar_for_encoded_layer(encoded, original):
    import io
    import json
    import tarfile

    config = json.dumps({'rootfs': {'type': 'layers', 'diff_ids': ['sha256:' + hashlib.sha256(original).hexdigest()]},
                         'os': 'linux', 'architecture': 'amd64'}).encode()
    manifest = json.dumps([{'Config': 'config.json', 'Layers': ['layer.tar.xz']}]).encode()
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w') as archive:
        for name, raw in [('manifest.json', manifest), ('config.json', config), ('layer.tar.xz', encoded)]:
            entry = tarfile.TarInfo(name)
            entry.size = len(raw)
            archive.addfile(entry, io.BytesIO(raw))
    return output.getvalue()


def test_saved_image_bounds_xz_decoder_memory_before_allocation(tmp_path, monkeypatch):
    import lzma
    import zlib
    from p11lab import image_custody

    original = _bounded_test_layer()
    encoded = bytearray(lzma.compress(original, format=lzma.FORMAT_XZ,
        filters=[{'id': lzma.FILTER_LZMA2, 'dict_size': 1 << 20}]))
    assert encoded[12:16] == bytes.fromhex('02002101')
    encoded[16] = 40  # XZ LZMA2 property: 4 GiB dictionary.
    encoded[20:24] = zlib.crc32(encoded[12:20]).to_bytes(4, 'little')
    with pytest.raises(lzma.LZMAError, match='Memory usage limit'):
        lzma.LZMADecompressor(memlimit=128 * 1024**2).decompress(encoded)
    path = tmp_path / 'image.tar'
    path.write_bytes(_image_tar_for_encoded_layer(bytes(encoded), original))
    monkeypatch.setattr(lzma, 'LZMAFile', lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError('unbounded XZ decoder')))
    with pytest.raises(ValueError, match='XZ.*memory'):
        image_custody._inspect_saved_image(path)


def test_saved_image_accepts_bounded_xz_layer(tmp_path):
    import lzma
    from p11lab import image_custody

    original = _bounded_test_layer(payload_size=1)
    path = tmp_path / 'image.tar'
    path.write_bytes(_image_tar_for_encoded_layer(lzma.compress(original), original))
    observed, _ = image_custody._inspect_saved_image(path)
    assert observed['layers'][0]['diff_id'] == 'sha256:' + hashlib.sha256(original).hexdigest()


@pytest.mark.parametrize('damage', ['truncated', 'concatenated', 'trailing', 'bad-padding'])
def test_saved_image_rejects_incomplete_or_ambiguous_xz_stream(tmp_path, damage):
    import lzma
    from p11lab import image_custody

    original = _bounded_test_layer(payload_size=1)
    encoded = lzma.compress(original)
    if damage == 'truncated':
        encoded = encoded[:-4]
    elif damage == 'concatenated':
        encoded += lzma.compress(original)
    elif damage == 'bad-padding':
        encoded += b'\0'
    else:
        encoded += b'foreign'
    path = tmp_path / 'image.tar'
    path.write_bytes(_image_tar_for_encoded_layer(encoded, original))
    with pytest.raises(ValueError, match='XZ'):
        image_custody._inspect_saved_image(path)
