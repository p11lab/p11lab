"""Source-first delivery gates: pins, seals, readback, admission, handoff.

No network, no registry, no Docker: the heavy end-to-end proof runs against
a local registry with evidence, not in this suite.
"""
import hashlib
import io
import json
import re
import tarfile
from pathlib import Path

import pytest

from p11lab import publish
from p11lab.catalog import load_environment
from test_native_lifecycle import installed as native_receipt_installation

ROOT = Path(__file__).resolve().parent.parent


def tiny_tar(path: Path, name="payload.txt", data=b"sealed bytes"):
    with tarfile.open(path, "w") as contents:
        item = tarfile.TarInfo(name)
        item.size = len(data)
        contents.addfile(item, io.BytesIO(data))
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_tag_scheme_binds_digest_short_and_parses():
    digest = "ab" * 32
    tag = publish.artifact_tag("rt", "softhsm2", "release", digest)
    assert tag == "rt-softhsm2-release-" + "ab" * 6
    assert publish.parse_tag(tag) == {"role": "rt", "environment": "softhsm2",
        "channel": "release", "target": None, "short": "ab" * 6}
    native = publish.artifact_tag("native", "softhsm2", "rolling", digest, "debian13-amd64")
    assert publish.parse_tag(native)["target"] == "debian13-amd64"
    with pytest.raises(ValueError):
        publish.artifact_tag("native", "softhsm2", "release", digest)
    with pytest.raises(ValueError):
        publish.artifact_tag("rt", "softhsm2", "release", digest, "debian13-amd64")
    with pytest.raises(ValueError):
        publish.artifact_tag("rt", "softhsm2", "release", "xyz")
    with pytest.raises(ValueError):
        publish.parse_tag("latest")


def test_acquisition_requires_digest_references():
    parsed = publish.require_digest_reference("ghcr.io/p11lab/softhsm2@sha256:" + "cd" * 32)
    assert parsed["repository"] == "ghcr.io/p11lab/softhsm2"
    local = publish.require_digest_reference("127.0.0.1:5050/p11lab@sha256:" + "cd" * 32)
    assert local["repository"] == "127.0.0.1:5050/p11lab"
    for alias in ("ghcr.io/p11lab/softhsm2:latest",
                  "ghcr.io/p11lab/softhsm2:2.7.0",
                  "ghcr.io/p11lab/softhsm2:rt-softhsm2-release-aabbccddee12",
                  "ghcr.io/p11lab/softhsm2@sha256:xyz",
                  "not a reference"):
        with pytest.raises(ValueError):
            publish.require_digest_reference(alias)


def test_validate_action_inputs_defaults_and_failures():
    base = {"environment": "softhsm2", "channel": "release",
            "handoff-digest": "sha256:" + "ef" * 32, "command": '["app", "--x"]'}
    normalized = publish.validate_action_inputs(base)
    assert normalized["mode"] == "direct" and normalized["timeout_seconds"] == 300
    assert normalized["command_argv"] == ["app", "--x"] and normalized["input_entries"] == []
    assert normalized["registry"] == "ghcr.io/p11lab/softhsm2"
    full = publish.validate_action_inputs(base | {"mode": "native", "inputs": "A=1\nB=2",
        "state-dir": "/tmp/state", "timeout": "45", "working-directory": "caller"})
    assert full["input_entries"] == ["A=1", "B=2"] and full["timeout_seconds"] == 45
    bad = [base | {"channel": "stable"}, base | {"mode": "proxy"}, base | {"command": "app"},
           base | {"command": '[""]'}, base | {"command": '["a", 1]'},
           base | {"inputs": "NOEQUALS"}, base | {"timeout": "0"}, base | {"timeout": "soon"},
           base | {"handoff-digest": "latest"}, base | {"environment": "Soft HSM"},
           base | {"unknown": "x"}, {"channel": "release"}]
    for values in bad:
        with pytest.raises(ValueError):
            publish.validate_action_inputs(values)


def test_validate_action_inputs_rejects_parent_traversal():
    """M6: working-directory must stay inside the caller checkout."""
    base = {"environment": "softhsm2", "channel": "release",
            "handoff-digest": "sha256:" + "ef" * 32, "command": '["app"]'}
    for bad in ("..", "../x", "a/../../x", "a/..", "..\\x", "a\\..\\x"):
        with pytest.raises(ValueError):
            publish.validate_action_inputs(base | {"working-directory": bad})
    for good in (".", "caller", "a/b", "a..b", "..x", "x.."):
        assert publish.validate_action_inputs(base | {"working-directory": good})["working-directory"] == good


def test_validate_action_inputs_hardens_input_lines():
    """M8-code: padded names and empty values fail fast; bytes pass through."""
    base = {"environment": "softhsm2", "channel": "release",
            "handoff-digest": "sha256:" + "ef" * 32, "command": '["app"]'}
    for bad in ("A=1\n FOO=x", "A=1\n\tFOO=x", "FOO =x", "A=", "A= ",
                "A=1\n\nB=2", "=x", "NOEQUALS"):
        with pytest.raises(ValueError):
            publish.validate_action_inputs(base | {"inputs": bad})
    # Boundary: the whole-block strip normalizes first-line padding (and the
    # YAML trailing newline); inner padding is rejected, never normalized.
    assert publish.validate_action_inputs(base | {"inputs": " FOO=x"})["input_entries"] == ["FOO=x"]
    # Duplicates stay the CLI's job (caught downstream); values keep exact bytes.
    assert publish.validate_action_inputs(base | {"inputs": "A=1\nA=2"})["input_entries"] == ["A=1", "A=2"]
    assert publish.validate_action_inputs(
        base | {"inputs": "A=x y\nP11LAB_STATE_DIR=/tmp/x"})["input_entries"] == ["A=x y", "P11LAB_STATE_DIR=/tmp/x"]
    assert publish.validate_action_inputs(base | {"inputs": "A=x "})["input_entries"] == ["A=x"]
    assert publish.validate_action_inputs(
        base | {"inputs": "A=x \nB=2"})["input_entries"] == ["A=x ", "B=2"]


def test_action_yml_matches_canonical_inputs():
    parsed = publish.action_inputs_from_yml((ROOT / "action.yml").read_text())
    assert set(parsed) == set(publish.ACTION_INPUTS)
    for name, spec in publish.ACTION_INPUTS.items():
        assert parsed[name].get("required", False) == spec.get("required", False), name
        assert parsed[name].get("default", "") == spec.get("default", ""), name
        assert parsed[name]["description"].strip(), name


def test_action_yml_parser_pins_adversarial_but_valid_subset():
    """A12: comments, quoting, and reordering pin the accepted subset."""
    text = """# leading comment
name: 'x'

inputs:
# column-zero comment inside the block
  timeout:
    default: "300"
    required: false
    description: Run timeout in seconds.

  environment:
    required: true
    description: 'Catalogue environment ID (e.g. softhsm2).'

# another column-zero comment
  channel:
    description: Locked channel: release or rolling.
    required: true

  mode:
    description: 'Execution mode: direct or native.'
    required: false
    default: direct

  registry:
    default: ''
    description: Registry repository holding the handoff (default ghcr.io/p11lab/<environment>).
    required: false

  handoff-digest:
    required: true
    description: Immutable handoff digest (sha256:<hex>).

  command:
    description: Application argv as a JSON array of strings.
    required: true

  inputs:
    required: false
    default: ''
    description: Newline-separated NAME=VALUE provider inputs.

  state-dir:
    description: Caller-owned persistent state directory (else ephemeral).
    default: ''
    required: false

  working-directory:
    required: false
    description: Caller application cwd, relative to the caller checkout.
    default: "."

outputs:
  exit-code:
    description: 'x'
"""
    parsed = publish.action_inputs_from_yml(text)
    assert set(parsed) == set(publish.ACTION_INPUTS)
    for name, spec in publish.ACTION_INPUTS.items():
        assert parsed[name].get("required", False) == spec.get("required", False), name
        assert parsed[name].get("default", "") == spec.get("default", ""), name
    # Subset boundaries: indented comments, duplicates, unknown fields fail.
    # (A tab-indented line silently terminates the block instead; the
    # parity test above is the backstop, since truncation drops inputs.)
    bad_indented_comment = text.replace("# another column-zero comment", "  # indented comment")
    with pytest.raises(ValueError):
        publish.action_inputs_from_yml(bad_indented_comment)
    with pytest.raises(ValueError):
        publish.action_inputs_from_yml(text.replace("outputs:", "  mode:\n    required: false\n\noutputs:"))
    with pytest.raises(ValueError):
        publish.action_inputs_from_yml(text.replace("    required: true", "    unknown: true", 1))


def test_tar_posture_rationale_is_recorded_in_publish():
    """A8/A9: the bound-based posture here vs roster-strict in bundle.py."""
    text = (ROOT / "src" / "p11lab" / "publish.py").read_text()
    for keyword in ("bound-based", "roster-strict", "bundle.py", "seal receipt digest"):
        assert keyword in text, keyword


def test_t13_workflows_and_action_pin_every_used_action():
    checked = []
    for name in (*publish.PUBLISH_WORKFLOWS,):
        text = (ROOT / ".github" / "workflows" / name).read_text()
        uses = re.findall(r"^\s*uses:\s*(\S+)", text, re.M)
        assert uses, name
        for entry in uses:
            if entry in {"./"} or entry.startswith("./"):
                continue
            repo, _, sha = entry.partition("@")
            assert repo in publish.ACTION_PINS, (name, entry)
            assert sha == publish.ACTION_PINS[repo]["sha"], (name, entry)
            checked.append((name, entry))
    action_uses = re.findall(r"^\s*uses:\s*(\S+)", (ROOT / "action.yml").read_text(), re.M)
    assert action_uses
    for entry in action_uses:
        repo, _, sha = entry.partition("@")
        assert sha == publish.ACTION_PINS[repo]["sha"], entry
        checked.append(("action.yml", entry))
    assert ("provider-delivery.yml", "actions/checkout@" + publish.ACTION_PINS["actions/checkout"]["sha"]) in checked
    assert any(repo == "ilammy/msvc-dev-cmd" for _, entry in checked for repo in [entry.partition("@")[0]])


def test_provider_delivery_is_the_single_channel_workflow():
    """A5: release+rolling collapsed into one channel-parametrized workflow."""
    workflows = ROOT / ".github" / "workflows"
    assert not (workflows / "provider-release.yml").exists()
    assert not (workflows / "provider-rolling.yml").exists()
    text = (workflows / "provider-delivery.yml").read_text()
    assert "provider-${{ inputs.channel }}-${{ inputs.environment }}" in text
    assert "default: 'release'" in text
    for literal in ("--channel release", "--channel rolling", "provider-release-", "provider-rolling-",
                    "t13-staging-release-", "t13-staging-rolling-", "'release', '", "'rolling', '"):
        assert literal not in text, literal
    assert publish.PUBLISH_WORKFLOWS.count("provider-delivery.yml") == 1


def test_windows_native_workflow_is_pin_gated():
    """I3-gate: the Windows native workflow sits inside the action-pin gate."""
    assert "windows-native-bouncyhsm.yml" in publish.PUBLISH_WORKFLOWS


def test_delivery_workflows_pin_toolchain_versions():
    floats = []
    for path in [*sorted((ROOT / ".github" / "workflows").glob("*.yml")), ROOT / "action.yml"]:
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            match = re.search(r"python-version:\s*['\"]?([\d.]+)", line)
            if match and not re.fullmatch(r"\d+\.\d+\.\d+", match.group(1)):
                floats.append(f"{path.name}:{lineno}:{line.strip()}")
            if re.match(r"\s*\d+\.\d+\.x\s*$", line) and path.name != "windows-native-bouncyhsm.yml":
                floats.append(f"{path.name}:{lineno}:{line.strip()}")
    assert not floats, floats


def test_installers_embed_oras_pins():
    pin = publish.ORAS_PIN
    shell = (ROOT / "src" / "p11lab" / "data" / "delivery" / "install-oras.sh").read_text()
    assert f"ORAS_VERSION={pin['version']}" in shell
    assert f"ORAS_REVISION={pin['source']['revision']}" in shell
    linux = pin["artifacts"]["linux/amd64"]
    assert f"ORAS_URL={linux['url']}" in shell and f"ORAS_SHA256={linux['sha256']}" in shell
    assert f"ORAS_SIZE={linux['size']}" in shell
    pwsh = (ROOT / "src" / "p11lab" / "data" / "delivery" / "install-oras.ps1").read_text()
    windows = pin["artifacts"]["windows/amd64"]
    assert f"$OrasVersion = '{pin['version']}'" in pwsh
    assert f"$OrasRevision = '{pin['source']['revision']}'" in pwsh
    assert f"$OrasUrl = '{windows['url']}'" in pwsh and f"$OrasSha256 = '{windows['sha256']}'" in pwsh
    assert f"$OrasSize = {windows['size']}" in pwsh


def seal_fixture(tmp_path):
    spec = load_environment("softhsm2", "release")
    archive = tmp_path / "source.tar"
    digest = tiny_tar(archive)
    resolved = {"sources": [{"source": spec["lock"]["sources"][0], "archive": str(archive),
                             "sha256": digest, "checkout": str(tmp_path)}],
                "dependencies": [], "patches": []}
    receipt = publish.seal_sources(spec, resolved, tmp_path / "seal")
    manifest = publish.verify_sealed_archive(tmp_path / "seal" / "sealed-source.tar.gz", tmp_path / "extract")
    return spec, receipt, manifest


def build_receipt_for(tmp_path, spec, receipt, manifest, *, name="artifact.json", artifact=None):
    from p11lab.build import runtime_inputs
    from p11lab.identity import artifact_key
    lock = spec["lock"]
    resolved_sources = {"sources": [{"source": lock["sources"][0], "sha256": manifest["sources"][0]["sha256"]}],
                        "dependencies": []}
    assert artifact_key("runtime", runtime_inputs(spec)) == manifest["build_key"]
    record = {"schema_version": 1, "build_key": manifest["build_key"], "resolved_sources": resolved_sources}
    if artifact is not None:
        record["artifact"] = artifact
    path = tmp_path / name
    path.write_text(json.dumps(record))
    return path


def readback_proof_for(tmp_path, spec, receipt, manifest, *, name="proof"):
    pulled = tmp_path / f"{name}-pulled"
    pulled.mkdir()
    (pulled / "sealed-source.tar.gz").write_bytes((tmp_path / "seal" / "sealed-source.tar.gz").read_bytes())
    (pulled / "sealed-source.json").write_text((tmp_path / "seal" / "sealed-source.json").read_text())
    transcript = tmp_path / f"{name}-transcript.log"
    transcript.write_text("empty credential state\nanonymous pull ok\n")
    return publish.verify_readback(tmp_path / "seal" / "sealed-source.json", pulled,
                                   transcript_path=transcript, extract_dir=tmp_path / f"{name}-extract")


def pushed_manifest_for(tmp_path, *, name="pushed"):
    import hashlib as _hashlib
    receipt_path = tmp_path / "seal" / "sealed-source.json"
    archive_sha = json.loads(receipt_path.read_text())["archive_sha256"]
    document = {"schemaVersion": 2, "layers": [
        {"digest": "sha256:" + archive_sha, "size": 10},
        {"digest": "sha256:" + _hashlib.sha256(receipt_path.read_bytes()).hexdigest(), "size": 20}]}
    path = tmp_path / f"{name}-manifest.json"
    path.write_text(json.dumps(document))
    return _hashlib.sha256(path.read_bytes()).hexdigest(), path


def test_seal_and_verify_roundtrip(tmp_path):
    spec, receipt, manifest = seal_fixture(tmp_path)
    assert receipt["role"] == "sealed-source" and receipt["runtime_role"] == "runtime"
    assert receipt["environment"] == "softhsm2" and receipt["channel"] == "release"
    assert manifest["build_key"] == receipt["build_key"] and manifest["sources"][0]["size"] > 0
    assert manifest["provider_sha256"] and manifest["lock_sha256"]
    assert str(tmp_path) not in (tmp_path / "extract" / "sealed.json").read_text()


def test_seal_member_names_count_sources_and_dependencies_separately(tmp_path):
    spec = load_environment("tpm2", "release")
    assert len(spec["lock"]["sources"]) == 1 and len(spec["lock"]["dependencies"]) == 1
    resolved = {"sources": [], "dependencies": [], "patches": []}
    for roster, path in (("sources", tmp_path / "source.tar"), ("dependencies", tmp_path / "dep.tar")):
        digest = tiny_tar(path, data=roster.encode())
        resolved[roster].append({"source": spec["lock"][roster][0], "archive": str(path),
                                "sha256": digest, "checkout": str(tmp_path)})
    publish.seal_sources(spec, resolved, tmp_path / "seal-kinds")
    manifest = publish.verify_sealed_archive(tmp_path / "seal-kinds" / "sealed-source.tar.gz",
                                             tmp_path / "extract-kinds")
    assert [(entry["kind"], entry["archive"]) for entry in manifest["sources"]] == [
        ("source", "source-0.tar"), ("dependency", "dependency-0.tar")]


def test_seal_refuses_to_overwrite(tmp_path):
    spec, receipt, manifest = seal_fixture(tmp_path)
    archive = tmp_path / "source.tar"
    resolved = {"sources": [{"source": spec["lock"]["sources"][0], "archive": str(archive),
                             "sha256": manifest["sources"][0]["sha256"], "checkout": str(tmp_path)}],
                "dependencies": [], "patches": []}
    with pytest.raises(ValueError, match="fresh attempt"):
        publish.seal_sources(spec, resolved, tmp_path / "seal")


def test_seal_rejects_roster_drift(tmp_path):
    spec, receipt, manifest = seal_fixture(tmp_path)
    archive = tmp_path / "other.tar"
    digest = tiny_tar(archive, data=b"other")
    resolved = {"sources": [{"source": spec["lock"]["sources"][0] | {"revision": "f" * 40},
                             "archive": str(archive), "sha256": digest, "checkout": str(tmp_path)}],
                "dependencies": [], "patches": []}
    with pytest.raises(ValueError):
        publish.seal_sources(spec, resolved, tmp_path / "seal-drift")


def test_readback_detects_altered_or_missing_bytes(tmp_path):
    spec, receipt, manifest = seal_fixture(tmp_path)
    pulled = tmp_path / "evil-pulled"
    pulled.mkdir()
    (pulled / "sealed-source.tar.gz").write_bytes((tmp_path / "seal" / "sealed-source.tar.gz").read_bytes() + b"x")
    (pulled / "sealed-source.json").write_text((tmp_path / "seal" / "sealed-source.json").read_text())
    transcript = tmp_path / "transcript.log"
    transcript.write_text("anonymous pull ok\n")
    with pytest.raises(ValueError, match="mismatch"):
        publish.verify_readback(tmp_path / "seal" / "sealed-source.json", pulled,
                                transcript_path=transcript, extract_dir=tmp_path / "evil-extract")
    (pulled / "sealed-source.tar.gz").unlink()
    with pytest.raises(ValueError, match="missing"):
        publish.verify_readback(tmp_path / "seal" / "sealed-source.json", pulled,
                                transcript_path=transcript, extract_dir=tmp_path / "missing-extract")


def test_readback_requires_transcript(tmp_path):
    spec, receipt, manifest = seal_fixture(tmp_path)
    pulled = tmp_path / "no-transcript-pulled"
    pulled.mkdir()
    (pulled / "sealed-source.tar.gz").write_bytes((tmp_path / "seal" / "sealed-source.tar.gz").read_bytes())
    (pulled / "sealed-source.json").write_text((tmp_path / "seal" / "sealed-source.json").read_text())
    with pytest.raises(ValueError, match="transcript"):
        publish.verify_readback(tmp_path / "seal" / "sealed-source.json", pulled,
                                transcript_path=tmp_path / "absent.log", extract_dir=tmp_path / "extract-2")


def test_input_match_accepts_exact_build(tmp_path):
    spec, receipt, manifest = seal_fixture(tmp_path)
    build = build_receipt_for(tmp_path, spec, receipt, manifest)
    match = publish.check_input_match(manifest, build, spec)
    assert match["matched_inputs"] == 1 and match["build_key"] == manifest["build_key"]


def test_input_mismatch_and_new_input_stop_upload(tmp_path):
    spec, receipt, manifest = seal_fixture(tmp_path)
    build = build_receipt_for(tmp_path, spec, receipt, manifest)
    tampered = json.loads(build.read_text())
    tampered["resolved_sources"]["sources"][0]["sha256"] = "0" * 64
    tampered_path = tmp_path / "tampered.json"
    tampered_path.write_text(json.dumps(tampered))
    with pytest.raises(ValueError, match="input mismatch"):
        publish.check_input_match(manifest, tampered_path, spec)
    added = json.loads(build.read_text())
    added["resolved_sources"]["dependencies"] = [{"source": {"id": "sneaky", "kind": "git",
        "url": "https://example.invalid/x.git", "revision": "e" * 40, "license_status": "unreviewed"},
        "sha256": "1" * 64}]
    added_path = tmp_path / "added.json"
    added_path.write_text(json.dumps(added))
    with pytest.raises(ValueError, match="newly discovered"):
        publish.check_input_match(manifest, added_path, spec)
    rekeyed = json.loads(build.read_text())
    rekeyed["build_key"] = "2" * 64
    rekeyed_path = tmp_path / "rekeyed.json"
    rekeyed_path.write_text(json.dumps(rekeyed))
    with pytest.raises(ValueError, match="build key"):
        publish.check_input_match(manifest, rekeyed_path, spec)


def test_native_input_match_compares_manifest_and_parent(tmp_path):
    sealed = {"runtime_role": "native", "environment": "softhsm2", "channel": "release",
              "sources": [{"sha256": "aa" * 32, "source": {"archive_sha256": "aa" * 32}}],
              "patches": [], "binaries": [{"path": "lib/libsofthsm2.so", "sha256": "bb" * 32}],
              "parent": {"reference": "sha256:" + "cc" * 32}, "target_lock_sha256": "dd" * 32}
    manifest = {"source": {"sources": [{"archive_sha256": "aa" * 32}], "patches": []},
                "build": {"identity": {"inputs": {"features": {"target_lock_sha256": "dd" * 32}}}}}
    receipt = {"build_key": "ee" * 32, "parent": {"reference": "sha256:" + "cc" * 32},
               "files": [{"path": "lib/libsofthsm2.so", "sha256": "bb" * 32}]}
    receipt_path = tmp_path / "native-artifact.json"
    receipt_path.write_text(json.dumps(receipt))
    spec = {"id": "softhsm2", "channel": "release"}
    assert publish.check_input_match(sealed, receipt_path, spec, manifest=manifest)["role"] == "native"
    changed = dict(receipt, files=[{"path": "lib/libsofthsm2.so", "sha256": "ff" * 32}])
    changed_path = tmp_path / "native-changed.json"
    changed_path.write_text(json.dumps(changed))
    with pytest.raises(ValueError, match="input mismatch"):
        publish.check_input_match(sealed, changed_path, spec, manifest=manifest)
    with pytest.raises(ValueError, match="manifest"):
        publish.check_input_match(sealed, receipt_path, spec)


def test_admit_blocks_without_evidence_and_stamps_verdict(tmp_path):
    from p11lab.catalog import packaged_asset
    spec, receipt, manifest = seal_fixture(tmp_path)
    build = build_receipt_for(tmp_path, spec, receipt, manifest)
    proof = readback_proof_for(tmp_path, spec, receipt, manifest)
    binary = tmp_path / "binary.tar"
    tiny_tar(binary)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    manifest_digest, manifest_path = pushed_manifest_for(tmp_path)
    result = publish.admit(artifact_kind="bundle", artifact_reference=str(binary), artifact_digest=digest,
        platform="linux/amd64", sealed_receipt_path=tmp_path / "seal" / "sealed-source.json",
        sealed_manifest=manifest, readback_proof=proof, build_receipt_path=build, spec=spec,
        registry="127.0.0.1:5050/p11lab", evidence_dir=None, out_dir=tmp_path / "admission",
        producer={"p11lab_wheel_sha256": "ab" * 32},
        source_manifest_digest=manifest_digest, source_manifest_path=manifest_path)
    assert result["status"] == "blocked"
    assert any("unreviewed" in blocker for blocker in result["blockers"])
    admission = json.loads(Path(result["admission"]).read_text())
    assert admission["catalogue"]["environment"] == "softhsm2"
    assert admission["catalogue"]["provider_sha256"] == hashlib.sha256(
        packaged_asset("softhsm2", "provider.json").read_bytes()).hexdigest()
    assert admission["verdict"]["status"] == "blocked"
    verdict = json.loads(Path(result["verdict"]).read_text())
    assert verdict["status"] == "blocked" and verdict["blockers"]


def test_admit_binds_claimed_runtime_artifact_to_build_receipt(tmp_path):
    """H1: a swapped engine ID is blocked even with otherwise-valid inputs."""
    spec, receipt, manifest = seal_fixture(tmp_path)
    built_engine = "aa" * 32
    build = build_receipt_for(tmp_path, spec, receipt, manifest, artifact={
        "kind": "docker-local", "reference": "sha256:" + built_engine,
        "sha256": built_engine, "platform": "linux/amd64"})
    proof = readback_proof_for(tmp_path, spec, receipt, manifest, name="h1rt")
    manifest_digest, manifest_path = pushed_manifest_for(tmp_path)
    swapped = "bb" * 32
    result = publish.admit(artifact_kind="docker-local", artifact_reference="sha256:" + swapped,
        artifact_digest=swapped, platform="linux/amd64",
        sealed_receipt_path=tmp_path / "seal" / "sealed-source.json", sealed_manifest=manifest,
        readback_proof=proof, build_receipt_path=build, spec=spec,
        registry="127.0.0.1:5050/p11lab", evidence_dir=None, out_dir=tmp_path / "admission-h1rt",
        producer={"p11lab_wheel_sha256": "ab" * 32},
        source_manifest_digest=manifest_digest, source_manifest_path=manifest_path)
    assert result["status"] == "blocked"
    assert any("built artifact" in blocker for blocker in result["blockers"]), result["blockers"]


def test_admit_accepts_honest_runtime_artifact_binding(tmp_path):
    """H1: the honestly claimed engine ID carries no artifact blocker."""
    spec, receipt, manifest = seal_fixture(tmp_path)
    built_engine = "aa" * 32
    build = build_receipt_for(tmp_path, spec, receipt, manifest, artifact={
        "kind": "docker-local", "reference": "sha256:" + built_engine,
        "sha256": built_engine, "platform": "linux/amd64"})
    proof = readback_proof_for(tmp_path, spec, receipt, manifest, name="h1rt-ok")
    manifest_digest, manifest_path = pushed_manifest_for(tmp_path)
    result = publish.admit(artifact_kind="docker-local", artifact_reference="sha256:" + built_engine,
        artifact_digest=built_engine, platform="linux/amd64",
        sealed_receipt_path=tmp_path / "seal" / "sealed-source.json", sealed_manifest=manifest,
        readback_proof=proof, build_receipt_path=build, spec=spec,
        registry="127.0.0.1:5050/p11lab", evidence_dir=None, out_dir=tmp_path / "admission-h1rt-ok",
        producer={"p11lab_wheel_sha256": "ab" * 32},
        source_manifest_digest=manifest_digest, source_manifest_path=manifest_path)
    assert result["status"] == "blocked"  # no content evidence
    assert not any("built artifact" in blocker or "unbound" in blocker
                   for blocker in result["blockers"]), result["blockers"]


def _native_admit_fixture(tmp_path):
    spec, receipt, manifest = seal_fixture(tmp_path)
    binary = tmp_path / "binary.tar"
    tiny_tar(binary)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    native_sealed = dict(manifest, runtime_role="native", target="debian13-amd64", binaries=[],
                         parent={"reference": "sha256:" + "cc" * 32}, target_lock_sha256="dd" * 32,
                         sources=[{"sha256": manifest["sources"][0]["sha256"],
                                   "source": {"archive_sha256": manifest["sources"][0]["sha256"], "id": "demo"}}])
    bundle_manifest = {"source": {"sources": [dict(native_sealed["sources"][0]["source"])],
        "patches": []}, "build": {"identity": {"inputs": {"features": {"target_lock_sha256": "dd" * 32}}}},
        "platform": "linux/amd64"}
    native_spec = {"id": "softhsm2", "channel": "release", "native_target": "debian13-amd64"}
    proof = readback_proof_for(tmp_path, spec, receipt, manifest, name="h1native")
    proof["runtime_role"] = "native"
    (tmp_path / "seal" / "sealed-source.json").write_text(json.dumps(
        json.loads((tmp_path / "seal" / "sealed-source.json").read_text()) | {"runtime_role": "native"}))
    manifest_digest, manifest_path = pushed_manifest_for(tmp_path)
    return {"spec": native_spec, "sealed": native_sealed, "bundle_manifest": bundle_manifest,
            "proof": proof, "binary": binary, "digest": digest, "build_key": manifest["build_key"],
            "parent": {"reference": "sha256:" + "cc" * 32},
            "manifest_digest": manifest_digest, "manifest_path": manifest_path}


def _native_build_receipt(tmp_path, fixture, *, name, artifact):
    path = tmp_path / name
    path.write_text(json.dumps({"build_key": fixture["build_key"], "parent": fixture["parent"],
                                "files": [], "artifact": artifact}))
    return path


def test_admit_binds_claimed_bundle_to_native_build_receipt(tmp_path):
    """H1 (native): a swapped bundle digest is blocked."""
    fixture = _native_admit_fixture(tmp_path)
    claimed = tmp_path / "claimed.tar"
    tiny_tar(claimed, data=b"attacker bytes")
    swapped = hashlib.sha256(claimed.read_bytes()).hexdigest()
    assert swapped != fixture["digest"]
    build = _native_build_receipt(tmp_path, fixture, name="native-build-h1.json", artifact={
        "kind": "bundle", "reference": str(fixture["binary"]), "sha256": fixture["digest"],
        "platform": "linux/amd64"})
    result = publish.admit(artifact_kind="bundle", artifact_reference=str(claimed),
        artifact_digest=swapped, platform="linux/amd64",
        sealed_receipt_path=tmp_path / "seal" / "sealed-source.json",
        sealed_manifest=fixture["sealed"], readback_proof=fixture["proof"],
        build_receipt_path=build, spec=fixture["spec"],
        registry="127.0.0.1:5050/p11lab", evidence_dir=None, out_dir=tmp_path / "admission-h1native",
        producer={"p11lab_wheel_sha256": "ab" * 32}, manifest=fixture["bundle_manifest"],
        source_manifest_digest=fixture["manifest_digest"], source_manifest_path=fixture["manifest_path"])
    assert result["status"] == "blocked"
    assert any("built artifact" in blocker for blocker in result["blockers"]), result["blockers"]


def test_admit_accepts_honest_native_bundle_binding(tmp_path):
    """H1 (native): the honestly claimed bundle digest carries no artifact blocker."""
    fixture = _native_admit_fixture(tmp_path)
    build = _native_build_receipt(tmp_path, fixture, name="native-build-h1-ok.json", artifact={
        "kind": "bundle", "reference": str(fixture["binary"]), "sha256": fixture["digest"],
        "platform": "linux/amd64"})
    result = publish.admit(artifact_kind="bundle", artifact_reference=str(fixture["binary"]),
        artifact_digest=fixture["digest"], platform="linux/amd64",
        sealed_receipt_path=tmp_path / "seal" / "sealed-source.json",
        sealed_manifest=fixture["sealed"], readback_proof=fixture["proof"],
        build_receipt_path=build, spec=fixture["spec"],
        registry="127.0.0.1:5050/p11lab", evidence_dir=None, out_dir=tmp_path / "admission-h1native-ok",
        producer={"p11lab_wheel_sha256": "ab" * 32}, manifest=fixture["bundle_manifest"],
        source_manifest_digest=fixture["manifest_digest"], source_manifest_path=fixture["manifest_path"])
    assert result["status"] == "blocked"  # no content evidence
    assert not any("built artifact" in blocker or "unbound" in blocker
                   for blocker in result["blockers"]), result["blockers"]


def test_admit_rejects_malformed_platform(tmp_path):
    """M7-lib: the claimed platform must be os/arch, never garbage."""
    spec, receipt, manifest = seal_fixture(tmp_path)
    build = build_receipt_for(tmp_path, spec, receipt, manifest)
    proof = readback_proof_for(tmp_path, spec, receipt, manifest, name="m7shape")
    binary = tmp_path / "binary.tar"
    tiny_tar(binary)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    manifest_digest, manifest_path = pushed_manifest_for(tmp_path)
    for index, bad in enumerate(["../../", "linux", "", "Linux/amd64", "linux/amd64 ",
                                "linux//amd64", "linux/amd64\n", "x/y/z"]):
        with pytest.raises(ValueError, match="platform"):
            publish.admit(artifact_kind="bundle", artifact_reference=str(binary),
                artifact_digest=digest, platform=bad,
                sealed_receipt_path=tmp_path / "seal" / "sealed-source.json",
                sealed_manifest=manifest, readback_proof=proof, build_receipt_path=build,
                spec=spec, registry="127.0.0.1:5050/p11lab", evidence_dir=None,
                out_dir=tmp_path / f"admission-m7shape-{index}",
                producer={"p11lab_wheel_sha256": "ab" * 32},
                source_manifest_digest=manifest_digest, source_manifest_path=manifest_path)


def test_admit_binds_native_platform_to_bundle_manifest(tmp_path):
    """M7-lib: a wrong-default platform never reaches the native record."""
    fixture = _native_admit_fixture(tmp_path)
    build = _native_build_receipt(tmp_path, fixture, name="native-build-m7.json", artifact={
        "kind": "bundle", "reference": str(fixture["binary"]), "sha256": fixture["digest"],
        "platform": "linux/amd64"})
    with pytest.raises(ValueError, match="platform"):
        publish.admit(artifact_kind="bundle", artifact_reference=str(fixture["binary"]),
            artifact_digest=fixture["digest"], platform="windows/amd64",
            sealed_receipt_path=tmp_path / "seal" / "sealed-source.json",
            sealed_manifest=fixture["sealed"], readback_proof=fixture["proof"],
            build_receipt_path=build, spec=fixture["spec"],
            registry="127.0.0.1:5050/p11lab", evidence_dir=None,
            out_dir=tmp_path / "admission-m7native",
            producer={"p11lab_wheel_sha256": "ab" * 32}, manifest=fixture["bundle_manifest"],
            source_manifest_digest=fixture["manifest_digest"],
            source_manifest_path=fixture["manifest_path"])


def test_admit_refuses_readback_mismatch(tmp_path):
    spec, receipt, manifest = seal_fixture(tmp_path)
    build = build_receipt_for(tmp_path, spec, receipt, manifest)
    proof = readback_proof_for(tmp_path, spec, receipt, manifest)
    proof["pulled_archive_sha256"] = "9" * 64
    binary = tmp_path / "binary.tar"
    tiny_tar(binary)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    manifest_digest, manifest_path = pushed_manifest_for(tmp_path)
    with pytest.raises(ValueError, match="readback"):
        publish.admit(artifact_kind="bundle", artifact_reference=str(binary), artifact_digest=digest,
            platform="linux/amd64", sealed_receipt_path=tmp_path / "seal" / "sealed-source.json",
            sealed_manifest=manifest, readback_proof=proof, build_receipt_path=build, spec=spec,
            registry="127.0.0.1:5050/p11lab", evidence_dir=None, out_dir=tmp_path / "admission-bad",
            producer={"p11lab_wheel_sha256": "ab" * 32},
        source_manifest_digest=manifest_digest, source_manifest_path=manifest_path)


def admission_inventory(tmp_path):
    import dataclasses
    from p11lab.models import ArtifactRef
    binary = tmp_path / "binary.tar"
    with tarfile.open(binary, "w") as tar:
        item = tarfile.TarInfo("demo.txt")
        item.size = 4
        tar.addfile(item, io.BytesIO(b"demo"))
    artifact = ArtifactRef("bundle", str(binary), hashlib.sha256(binary.read_bytes()).hexdigest(), "linux/amd64")
    payloads = []
    for path, role, text in [("sources/demo.tar", "source", "complete source"),
                             ("notices/demo.txt", "notice", "original grant"),
                             ("BUILD.md", "build", "portable build instructions")]:
        local = tmp_path / Path(path).name
        local.write_text(text)
        payloads.append({"path": path, "role": role, "local_path": str(local),
                         "sha256": hashlib.sha256(local.read_bytes()).hexdigest(), "size": local.stat().st_size})
    inventory = {"schema_version": 1, "artifact": dataclasses.asdict(artifact), "role": "runtime",
        "observation": {"artifact": dataclasses.asdict(artifact), "packages": [], "binaries": [],
                        "linked_libraries": [], "files": [{"path": "/demo.txt",
                        "sha256": hashlib.sha256(b"demo").hexdigest(), "size": 4, "mode": 420, "package": None}]},
        "content_reviews": [{"path": "/demo.txt", "sha256": hashlib.sha256(b"demo").hexdigest(),
                             "source": "demo=1", "status": "reviewed"}],
        "sources": [{"id": "demo=1", "name": "demo", "version": "1", "payloads": ["sources/demo.tar"]}],
        "components": [{"id": "demo=1", "source": "demo=1", "scope": "runtime"}],
        "reviews": [{"source": "demo=1", "status": "reviewed", "grant_known": True, "source_redistribution": True,
                     "license_declared": "MIT", "license_concluded": "MIT",
                     "chosen_route": "retain grant and complete source",
                     "notices": ["notices/demo.txt"], "grant_evidence": ["notices/demo.txt"],
                     "obligations": ["source", "notice"], "modifications": "unmodified"}],
        "patches": [], "payloads": payloads, "build_instructions": "BUILD.md", "limitations": []}
    return artifact, inventory


def test_admit_eligible_with_complete_evidence(tmp_path):
    import dataclasses
    from p11lab import sources
    spec, receipt, manifest = seal_fixture(tmp_path)
    artifact, inventory = admission_inventory(tmp_path)
    evidence = tmp_path / "evidence"
    sources.collect_source_bundle(artifact, inventory, evidence)
    build = build_receipt_for(tmp_path, spec, receipt, manifest, artifact=dataclasses.asdict(artifact))
    proof = readback_proof_for(tmp_path, spec, receipt, manifest, name="ok")
    manifest_digest, manifest_path = pushed_manifest_for(tmp_path)
    result = publish.admit(artifact_kind="bundle", artifact_reference=str(artifact.reference),
        artifact_digest=artifact.sha256, platform="linux/amd64",
        sealed_receipt_path=tmp_path / "seal" / "sealed-source.json", sealed_manifest=manifest,
        readback_proof=proof, build_receipt_path=build, spec=spec,
        registry="127.0.0.1:5050/p11lab", evidence_dir=evidence, out_dir=tmp_path / "admission-ok",
        producer={"p11lab_wheel_sha256": "ab" * 32},
        source_manifest_digest=manifest_digest, source_manifest_path=manifest_path)
    assert result["status"] == "eligible", result["blockers"]
    assert json.loads(Path(result["verdict"]).read_text())["status"] == "eligible"


def test_expose_binds_pushed_bundle_after_readback(tmp_path):
    spec, receipt, manifest = seal_fixture(tmp_path)
    binary = tmp_path / "binary.tar"
    tiny_tar(binary)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    native_manifest = dict(manifest, runtime_role="native", target="debian13-amd64",
                           binaries=[], parent={"reference": "sha256:" + "cc" * 32})
    native_sealed = dict(native_manifest, sources=[{"sha256": manifest["sources"][0]["sha256"],
        "source": {"archive_sha256": manifest["sources"][0]["sha256"], "id": "demo"}}])
    native_build = {"build_key": manifest["build_key"], "parent": {"reference": "sha256:" + "cc" * 32},
                    "files": []}
    native_build_path = tmp_path / "native-build.json"
    native_build_path.write_text(json.dumps(native_build))
    bundle_manifest = {"source": {"sources": [dict(native_sealed["sources"][0]["source"])],
        "patches": []}, "build": {"identity": {"inputs": {"features": {"target_lock_sha256": "dd" * 32}}}},
        "platform": "linux/amd64"}
    native_sealed["target_lock_sha256"] = "dd" * 32
    native_spec = {"id": "softhsm2", "channel": "release", "native_target": "debian13-amd64"}
    proof = readback_proof_for(tmp_path, spec, receipt, manifest, name="native")
    proof["runtime_role"] = "native"
    (tmp_path / "seal" / "sealed-source.json").write_text(json.dumps(
        json.loads((tmp_path / "seal" / "sealed-source.json").read_text()) | {"runtime_role": "native"}))
    manifest_digest, manifest_path = pushed_manifest_for(tmp_path)
    result = publish.admit(artifact_kind="bundle", artifact_reference=str(binary), artifact_digest=digest,
        platform="linux/amd64", sealed_receipt_path=tmp_path / "seal" / "sealed-source.json",
        sealed_manifest=native_sealed, readback_proof=proof, build_receipt_path=native_build_path,
        spec=native_spec, registry="127.0.0.1:5050/p11lab", evidence_dir=None,
        out_dir=tmp_path / "admission-native", producer={"p11lab_wheel_sha256": "ab" * 32},
        manifest=bundle_manifest,
        source_manifest_digest=manifest_digest, source_manifest_path=manifest_path)
    assert result["status"] == "blocked"
    pushed = "9f" * 32
    tag = publish.artifact_tag("native", "softhsm2", "release", digest, "debian13-amd64")
    exposed = publish.expose(admission_path=Path(result["admission"]), pushed_digest=pushed,
        pushed_tag=tag, pushed_size=binary.stat().st_size, local_inspect_path=None,
        pulled_inspect_path=None, pulled_bundle_path=binary,
        registry="127.0.0.1:5050/p11lab", out_dir=tmp_path / "handoff")
    handoff = publish.show_handoff(Path(exposed["handoff"]))
    assert handoff["binary"]["reference"] == "127.0.0.1:5050/p11lab@sha256:" + pushed
    assert handoff["binary"]["manifest_sha256"] == pushed
    assert handoff["binary"]["file_sha256"] == digest
    assert handoff["binary"]["aliases"] == []
    assert handoff["admission"]["status"] == "blocked"
    assert "digest" not in handoff and "handoff_sha256" not in handoff and "self_digest" not in handoff
    assert exposed["reference"].endswith(pushed)


def test_expose_refuses_mismatched_bytes_or_tag(tmp_path):
    spec, receipt, manifest = seal_fixture(tmp_path)
    binary = tmp_path / "binary.tar"
    tiny_tar(binary)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    native_sealed = dict(manifest, runtime_role="native", target="debian13-amd64", binaries=[],
                         parent={"reference": "sha256:" + "cc" * 32}, target_lock_sha256="dd" * 32,
                         sources=[{"sha256": manifest["sources"][0]["sha256"],
                                   "source": {"archive_sha256": manifest["sources"][0]["sha256"], "id": "demo"}}])
    native_build_path = tmp_path / "native-build.json"
    native_build_path.write_text(json.dumps({"build_key": manifest["build_key"],
        "parent": {"reference": "sha256:" + "cc" * 32}, "files": []}))
    bundle_manifest = {"source": {"sources": [dict(native_sealed["sources"][0]["source"])],
        "patches": []}, "build": {"identity": {"inputs": {"features": {"target_lock_sha256": "dd" * 32}}}},
        "platform": "linux/amd64"}
    proof = readback_proof_for(tmp_path, spec, receipt, manifest, name="refuse")
    proof["runtime_role"] = "native"
    (tmp_path / "seal" / "sealed-source.json").write_text(json.dumps(
        json.loads((tmp_path / "seal" / "sealed-source.json").read_text()) | {"runtime_role": "native"}))
    manifest_digest, manifest_path = pushed_manifest_for(tmp_path)
    result = publish.admit(artifact_kind="bundle", artifact_reference=str(binary), artifact_digest=digest,
        platform="linux/amd64", sealed_receipt_path=tmp_path / "seal" / "sealed-source.json",
        sealed_manifest=native_sealed, readback_proof=proof, build_receipt_path=native_build_path,
        spec={"id": "softhsm2", "channel": "release", "native_target": "debian13-amd64"},
        registry="127.0.0.1:5050/p11lab", evidence_dir=None, out_dir=tmp_path / "admission-refuse",
        producer={"p11lab_wheel_sha256": "ab" * 32}, manifest=bundle_manifest,
        source_manifest_digest=manifest_digest, source_manifest_path=manifest_path)
    tag = publish.artifact_tag("native", "softhsm2", "release", digest, "debian13-amd64")
    other = tmp_path / "other.tar"
    tiny_tar(other, data=b"different")
    with pytest.raises(ValueError, match="differ"):
        publish.expose(admission_path=Path(result["admission"]), pushed_digest=digest, pushed_tag=tag,
            pushed_size=10, local_inspect_path=None, pulled_inspect_path=None,
            pulled_bundle_path=other, registry="127.0.0.1:5050/p11lab",
            out_dir=tmp_path / "handoff-bad-bytes")
    with pytest.raises(ValueError, match="alias"):
        publish.expose(admission_path=Path(result["admission"]), pushed_digest=digest, pushed_tag="latest",
            pushed_size=binary.stat().st_size, local_inspect_path=None, pulled_inspect_path=None,
            pulled_bundle_path=binary, registry="127.0.0.1:5050/p11lab",
            out_dir=tmp_path / "handoff-bad-tag")


def test_expose_compares_engine_inspects_for_runtimes(tmp_path):
    spec, receipt, manifest = seal_fixture(tmp_path)
    build = build_receipt_for(tmp_path, spec, receipt, manifest)
    proof = readback_proof_for(tmp_path, spec, receipt, manifest, name="rt")
    engine = "aa" * 32
    manifest_digest, manifest_path = pushed_manifest_for(tmp_path)
    result = publish.admit(artifact_kind="docker-local", artifact_reference="sha256:" + engine,
        artifact_digest=engine, platform="linux/amd64",
        sealed_receipt_path=tmp_path / "seal" / "sealed-source.json", sealed_manifest=manifest,
        readback_proof=proof, build_receipt_path=build, spec=spec,
        registry="127.0.0.1:5050/p11lab", evidence_dir=None, out_dir=tmp_path / "admission-rt",
        producer={"p11lab_wheel_sha256": "ab" * 32},
        source_manifest_digest=manifest_digest, source_manifest_path=manifest_path)
    pushed = "bb" * 32
    tag = publish.artifact_tag("rt", "softhsm2", "release", pushed)
    before = {"Id": "sha256:" + engine, "Os": "linux", "Architecture": "amd64",
              "RootFS": {"Layers": ["sha256:" + "cc" * 32]}}
    after = dict(before, RepoDigests=["127.0.0.1:5050/p11lab@sha256:" + pushed])
    before_path, after_path = tmp_path / "before.json", tmp_path / "after.json"
    before_path.write_text(json.dumps([before]))
    after_path.write_text(json.dumps([after]))
    exposed = publish.expose(admission_path=Path(result["admission"]), pushed_digest=pushed,
        pushed_tag=tag, pushed_size=1234, local_inspect_path=before_path,
        pulled_inspect_path=after_path, pulled_bundle_path=None,
        registry="127.0.0.1:5050/p11lab", out_dir=tmp_path / "handoff-rt")
    handoff = publish.show_handoff(Path(exposed["handoff"]))
    assert handoff["binary"]["engine_id"] == "sha256:" + engine
    assert handoff["binary"]["manifest_sha256"] == pushed
    assert handoff["binary"]["aliases"] == ["2.7.0", "latest"]
    drifted = dict(after, RootFS={"Layers": ["sha256:" + "dd" * 32]})
    drifted_path = tmp_path / "drifted.json"
    drifted_path.write_text(json.dumps([drifted]))
    with pytest.raises(ValueError, match="layers differ"):
        publish.expose(admission_path=Path(result["admission"]), pushed_digest=pushed, pushed_tag=tag,
            pushed_size=1234, local_inspect_path=before_path, pulled_inspect_path=drifted_path,
            pulled_bundle_path=None, registry="127.0.0.1:5050/p11lab",
            out_dir=tmp_path / "handoff-rt-drift")


def test_show_handoff_rejects_self_digest(tmp_path):
    document = {"schema_version": 1, "registry": "127.0.0.1:5050/p11lab",
        "catalogue": {"environment": "softhsm2"},
        "source": {"manifest_sha256": "aa" * 32, "file_sha256": "aa" * 32, "tag": "t",
                   "reference": "127.0.0.1:5050/p11lab@sha256:" + "aa" * 32},
        "binary": {"kind": "bundle", "manifest_sha256": "bb" * 32, "file_sha256": "bb" * 32,
                   "tag": "t", "reference": "127.0.0.1:5050/p11lab@sha256:" + "bb" * 32},
        "admission": {"status": "blocked", "blockers": ["x"]}, "readback": {}, "producer": {},
        "exposure": {}, "self_digest": "cc" * 32}
    path = tmp_path / "handoff.json"
    path.write_text(json.dumps(document))
    with pytest.raises(ValueError, match="self-digest"):
        publish.show_handoff(path)


def test_publish_cli_wiring(tmp_path, capsys):
    from p11lab.cli import main
    spec, receipt, manifest = seal_fixture(tmp_path)
    build = build_receipt_for(tmp_path, spec, receipt, manifest)
    manifest_path = tmp_path / "sealed.json"
    manifest_path.write_text(json.dumps(manifest))
    assert main(["publish", "check-inputs", "softhsm2", "--channel", "release",
                 "--sealed-manifest", str(manifest_path), "--build-receipt", str(build)]) == 0
    proof = readback_proof_for(tmp_path, spec, receipt, manifest, name="cli")
    proof_path = tmp_path / "proof.json"
    proof_path.write_text(json.dumps(proof))
    binary = tmp_path / "binary.tar"
    tiny_tar(binary)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    assert main(["publish", "admit", "softhsm2", "--channel", "release",
                 "--sealed-receipt", str(tmp_path / "seal" / "sealed-source.json"),
                 "--sealed-manifest", str(manifest_path), "--readback-proof", str(proof_path),
                 "--build-receipt", str(build), "--artifact-kind", "bundle",
                 "--artifact-reference", str(binary), "--artifact-digest", digest,
                 "--registry", "127.0.0.1:5050/p11lab", "--output-dir", str(tmp_path / "cli-admission"),
                 "--producer-wheel-sha256", "ab" * 32,
                 "--source-manifest-digest", pushed_manifest_for(tmp_path, name="cli")[0],
                 "--source-manifest", str(pushed_manifest_for(tmp_path, name="cli")[1])]) == 3
    assert main(["publish", "show-handoff"]) == 2
    capsys.readouterr()


def _action_run_module():
    import importlib.util
    path = ROOT / "src/p11lab/data/delivery/action-run.py"
    spec = importlib.util.spec_from_file_location("action_run", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_local_proof_refused_on_ci(monkeypatch):
    """H3: --local-proof is a local-mechanics hatch; CI must never use it."""
    module = _action_run_module()
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    assert module._local_proof_allowed()
    monkeypatch.setenv("CI", "true")
    assert not module._local_proof_allowed()
    monkeypatch.delenv("CI")
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    assert not module._local_proof_allowed()


def test_action_run_echo_redacts_input_values():
    import importlib.util
    path = ROOT / "src/p11lab/data/delivery/action-run.py"
    spec = importlib.util.spec_from_file_location("action_run", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    shown = module._display(["p11lab", "run", "softhsm2", "--input", "P11LAB_PIN=1234",
                             "--input=P11LAB_SO_PIN_FILE=/run/so", "--", "my-app"])
    assert shown == ["p11lab", "run", "softhsm2", "--input", "P11LAB_PIN=***",
                     "--input=P11LAB_SO_PIN_FILE=***", "--", "my-app", "(0 args)"]
    assert "1234" not in " ".join(shown) and "/run/so" not in " ".join(shown)


def test_action_run_echo_hides_consumer_argv():
    import importlib.util
    path = ROOT / "src/p11lab/data/delivery/action-run.py"
    spec = importlib.util.spec_from_file_location("action_run", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    shown = module._display(["p11lab", "run", "x", "--", "app", "--pin", "1234"])
    assert shown == ["p11lab", "run", "x", "--", "app", "(2 args)"]
    assert "1234" not in " ".join(shown) and "--pin" not in " ".join(shown)


@pytest.mark.parametrize("platform", ["linux/amd64", "windows/amd64"])
def test_action_run_native_round_trip_keeps_handoff_platform(tmp_path, monkeypatch, platform):
    """Sol-4: install and run must both use the handoff platform.

    `p11lab run --platform` defaults to linux/amd64 and reverifies the
    installed tree against that tuple, so a run argv without the handoff
    platform rejects an eligible windows/amd64 installation before the
    application executes. Transports are stubbed; handoff validation,
    digest binding, and argv construction run unmodified.
    """
    from types import SimpleNamespace

    module = _action_run_module()
    work = tmp_path / "work"
    work.mkdir()
    bundle_bytes = b"native bundle bytes"
    bundle_digest = hashlib.sha256(bundle_bytes).hexdigest()
    registry = "127.0.0.1:5050/p11lab"
    binary_manifest = "cc" * 32
    source_manifest = "dd" * 32
    handoff = {
        "schema_version": publish.SCHEMA_VERSION,
        "registry": registry,
        "catalogue": {"environment": "softhsm2", "channel": "release", "runtime_role": "native"},
        "source": {"manifest_sha256": source_manifest, "tag": "source-tag",
                   "reference": f"{registry}@sha256:{source_manifest}", "file_sha256": "ee" * 32},
        "binary": {"kind": "bundle", "manifest_sha256": binary_manifest, "tag": "binary-tag",
                   "reference": f"{registry}@sha256:{binary_manifest}",
                   "file_sha256": bundle_digest, "platform": platform},
        "admission": {"status": "eligible", "blockers": []},
        "readback": {}, "producer": {}, "exposure": {},
    }
    calls = {}

    def fake_run(argv, *, env, cwd):
        if argv[1:3] == ["-m", "p11lab"]:
            calls["run"] = list(argv)
            output = Path(argv[argv.index("--output-dir") + 1])
            output.mkdir()
            record = _action_receipt_record(mode="native")
            record["artifacts"]["provider"] = {
                "kind": "bundle", "reference": str((output.parent / "bundle/bundle.tar.gz").resolve()),
                "sha256": bundle_digest, "platform": platform}
            (output / "receipt.json").write_text(json.dumps(record))
            return 0
        target = Path(argv[argv.index("-o") + 1])
        if target.name == "handoff":
            (target / "handoff.json").write_text(json.dumps(handoff))
        else:
            (target / "bundle.tar.gz").write_bytes(bundle_bytes)
        return 0

    def fake_subprocess_run(argv, **kwargs):
        calls["install"] = list(argv)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(module, "_run", fake_run)
    monkeypatch.setattr(module.subprocess, "run", fake_subprocess_run)
    code = module.main([
        "--environment", "softhsm2", "--channel", "release", "--mode", "native",
        "--registry", registry, "--handoff-digest", "sha256:" + "ff" * 32,
        "--command", '["app"]', "--timeout", "600",
        "--working-directory", str(work), "--oras", "oras", "--run-dir", str(tmp_path / "rundir")])
    assert code == 0
    install = calls["install"]
    assert install[install.index("--platform") + 1] == platform
    run = calls["run"]
    assert run[run.index("--installed-prefix") + 1].endswith("prefix")
    assert run[run.index("--platform") + 1] == platform
    assert run.count("--platform") == 1
    outputs = dict(line.split("=", 1) for line in (tmp_path / "rundir/action-outputs.env").read_text().splitlines())
    assert outputs["receipt-path"] == str(tmp_path / "rundir/run-output/receipt.json")
    assert outputs["app-returncode"] == "0"


def test_malformed_documents_fail_as_gate_messages(tmp_path):
    spec, receipt, manifest = seal_fixture(tmp_path)
    broken_receipt = tmp_path / "broken-receipt.json"
    record = json.loads((tmp_path / "seal" / "sealed-source.json").read_text())
    del record["archive"]
    broken_receipt.write_text(json.dumps(record))
    pulled = tmp_path / "malformed-pulled"
    pulled.mkdir()
    transcript = tmp_path / "malformed-transcript.log"
    transcript.write_text("anonymous pull ok\n")
    with pytest.raises(publish.PublishError, match="lacks the sealed archive name"):
        publish.verify_readback(broken_receipt, pulled, transcript_path=transcript,
                                extract_dir=tmp_path / "malformed-extract")
    broken_manifest = dict(manifest)
    del broken_manifest["sources"]
    build = build_receipt_for(tmp_path, spec, receipt, manifest)
    with pytest.raises(publish.PublishError, match="lacks the source roster"):
        publish.check_input_match(broken_manifest, build, spec)
    no_digest = json.loads(json.dumps(manifest))
    del no_digest["sources"][0]["sha256"]
    with pytest.raises(publish.PublishError, match="lacks its digest"):
        publish.check_input_match(no_digest, build, spec)


def test_admit_malformed_proof_fails_as_gate_message(tmp_path):
    spec, receipt, manifest = seal_fixture(tmp_path)
    build = build_receipt_for(tmp_path, spec, receipt, manifest)
    proof = readback_proof_for(tmp_path, spec, receipt, manifest)
    del proof["transcript_sha256"]
    binary = tmp_path / "binary.tar"
    tiny_tar(binary)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    manifest_digest, manifest_path = pushed_manifest_for(tmp_path)
    with pytest.raises(publish.PublishError, match="lacks the transcript digest"):
        publish.admit(artifact_kind="bundle", artifact_reference=str(binary), artifact_digest=digest,
            platform="linux/amd64", sealed_receipt_path=tmp_path / "seal" / "sealed-source.json",
            sealed_manifest=manifest, readback_proof=proof, build_receipt_path=build, spec=spec,
            registry="127.0.0.1:5050/p11lab", evidence_dir=None, out_dir=tmp_path / "admission-malformed",
            producer={"p11lab_wheel_sha256": "ab" * 32},
            source_manifest_digest=manifest_digest, source_manifest_path=manifest_path)


def _composite_run_step(name="Run the caller application"):
    """Split a composite step into env bindings and the bash body."""
    lines = (ROOT / "action.yml").read_text().splitlines()
    start = next(i for i, line in enumerate(lines) if line.strip() == f"- name: {name}")
    env, body, mode = {}, [], None
    for line in lines[start + 1:]:
        if re.match(r"    - name: ", line):
            break
        if line.strip() == "env:":
            mode = "env"
        elif line.strip() == "run: |":
            mode = "run"
        elif mode == "env" and (match := re.match(r"        (\w+): ", line)):
            env[match.group(1)] = line.split(": ", 1)[1].strip()
        elif mode == "run" and line.startswith("        "):
            body.append(line[8:])
    assert body
    return env, "\n".join(body) + "\n"


def test_composite_run_step_binds_no_caller_input_into_shell_source():
    """Sol re-check 1: no ${{ inputs.* }} may reach composite bash source."""
    _, body = _composite_run_step()
    assert "${{ inputs." not in body


def test_composite_run_step_passes_caller_inputs_literally(tmp_path):
    """Sol re-check 1: JSON argv, quotes, $(), backticks, newlines survive."""
    import os
    import shutil
    import subprocess
    import sys

    bash = shutil.which("bash")
    if not bash:
        pytest.skip("bash required")
    command = '["python", "consumer-smoke.py", "$(touch SHOULD-NOT-EXIST)", "`touch SHOULD-NOT-EXIST-2`"]'
    inputs = "P11LAB_PIN_FILE=/run/pin\nEMPTY_OK=x\n"
    fixtures = {"environment": "softhsm2", "channel": "release", "mode": "direct",
                "registry": "127.0.0.1:5050/p11lab", "handoff-digest": "sha256:" + "ab" * 32,
                "command": command, "inputs": inputs, "state-dir": "", "timeout": "300",
                "working-directory": "."}
    env_bindings, body = _composite_run_step()
    stubroot = tmp_path / "action"
    stub = stubroot / "src/p11lab/data/delivery/action-run.py"
    stub.parent.mkdir(parents=True)
    argv_out = tmp_path / "argv.json"
    stub.write_text("import json, sys\n"
                    f"open({str(argv_out)!r}, 'w').write(json.dumps(sys.argv[1:]))\n")
    # Mimic GitHub substitution in the step source, then run it like bash does.
    for name, value in fixtures.items():
        body = body.replace("${{ inputs." + name + " }}", value)
    body = body.replace("${{ github.action_path }}", str(stubroot))
    body = body.replace("${{ github.workspace }}", str(tmp_path / "ws"))
    env = dict(os.environ)
    for var, bound in env_bindings.items():
        match = re.fullmatch(r"\$\{\{ inputs\.([a-z-]+) \}\}", bound)
        assert match, bound
        env[var] = fixtures[match.group(1)]
    bindir = tmp_path / "bin"
    bindir.mkdir()
    bindir.joinpath("python").symlink_to(Path(sys.executable))
    env.update(PATH=str(bindir) + os.pathsep + env.get("PATH", ""),
               GITHUB_WORKSPACE=str(tmp_path / "ws"), RUNNER_TEMP=str(tmp_path),
               P11LAB_ORAS=str(tmp_path / "oras"), GITHUB_OUTPUT=str(tmp_path / "github-output"))
    completed = subprocess.run([bash, "-c", body], cwd=tmp_path, env=env,
                               capture_output=True, text=True, timeout=60)
    assert completed.returncode == 0, completed.stderr
    assert not (tmp_path / "SHOULD-NOT-EXIST").exists()
    assert not (tmp_path / "SHOULD-NOT-EXIST-2").exists()
    received = json.loads(argv_out.read_text())
    got = dict(zip(received[::2], received[1::2]))
    assert got["--command"] == command
    assert got["--inputs"] == inputs
    assert got["--working-directory"] == str(tmp_path / "ws") + "/."
    assert json.loads(got["--command"])[0] == "python"


@pytest.mark.parametrize("second_code", [0, 37, None, "missing-receipt"])
def test_composite_repeated_runs_collect_only_their_own_receipts(tmp_path, second_code):
    """Exercise real run/collect shells and wrapper; stub only acquisition/run.

    Both calls share RUNNER_TEMP, as repeated `uses:` steps do. A failed
    application still yields its own receipt; an acquisition failure must
    never report the successful first call's receipt or return code.
    """
    import os
    import shutil
    import subprocess
    import sys
    import textwrap

    bash = shutil.which("bash")
    if not bash:
        pytest.skip("bash required")
    runner_temp = tmp_path / "runner temp with spaces '$(touch ALLOCATION-INJECTED)'"
    runner_temp.mkdir()
    work = tmp_path / "workspace"
    work.mkdir()
    action = tmp_path / "action"
    stub = action / "src/p11lab/data/delivery/action-run.py"
    stub.parent.mkdir(parents=True)
    real_wrapper = ROOT / "src/p11lab/data/delivery/action-run.py"
    stub.write_text(textwrap.dedent(f"""\
        import hashlib, importlib.util, json, os, sys
        from pathlib import Path
        from types import SimpleNamespace

        spec = importlib.util.spec_from_file_location("action_run", {str(real_wrapper)!r})
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        bundle = b"native bundle"
        registry = "127.0.0.1:5050/p11lab"
        handoff = {{
            "schema_version": 1, "registry": registry,
            "catalogue": {{"environment": "softhsm2", "channel": "release", "runtime_role": "native"}},
            "source": {{"manifest_sha256": "dd" * 32, "tag": "source",
                       "reference": registry + "@sha256:" + "dd" * 32, "file_sha256": "ee" * 32}},
            "binary": {{"kind": "bundle", "manifest_sha256": "cc" * 32, "tag": "binary",
                       "reference": registry + "@sha256:" + "cc" * 32,
                       "file_sha256": hashlib.sha256(bundle).hexdigest(), "platform": "linux/amd64"}},
            "admission": {{"status": "eligible", "blockers": []}},
            "readback": {{}}, "producer": {{}}, "exposure": {{}},
        }}

        def fake_run(argv, *, env, cwd):
            if argv[1:4] == ["-m", "p11lab", "run"]:
                assert "GITHUB_OUTPUT" not in env and "P11LAB_ACTION_INPUTS" not in env
                if os.environ["TEST_APP_CODE"] == "missing-receipt":
                    return 2
                output = Path(argv[argv.index("--output-dir") + 1])
                output.mkdir(exist_ok=False)
                code = int(os.environ["TEST_APP_CODE"])
                record = {_action_receipt_record(mode="native")!r}
                record.update(app_returncode=code, exit_code=code)
                record["artifacts"]["provider"] = {{"kind": "bundle",
                    "reference": str((output.parent / "bundle/bundle.tar.gz").resolve()),
                    "sha256": hashlib.sha256(bundle).hexdigest(), "platform": "linux/amd64"}}
                (output / "receipt.json").write_text(json.dumps(record))
                (output / "private-token-state").write_text("not an artifact")
                return code
            if os.environ["TEST_APP_CODE"] == "fetch-failure":
                return 1
            target = Path(argv[argv.index("-o") + 1])
            if target.name == "handoff":
                (target / "handoff.json").write_text(json.dumps(handoff))
            else:
                (target / "bundle.tar.gz").write_bytes(bundle)
            return 0

        module._run = fake_run
        module.subprocess.run = lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="", stderr="")
        sys.exit(module.main())
        """))
    bindir = tmp_path / "bin"
    bindir.mkdir()
    bindir.joinpath("python").symlink_to(Path(sys.executable))
    fixtures = {"environment": "softhsm2", "channel": "release", "mode": "native",
                "registry": "127.0.0.1:5050/p11lab", "handoff-digest": "sha256:" + "ab" * 32,
                "command": '["app"]', "inputs": "P11LAB_PIN_FILE=/private/pin", "state-dir": "",
                "timeout": "300", "working-directory": "."}
    run_bindings, run_body = _composite_run_step()
    collect_bindings, collect_body = _composite_run_step("Collect receipts")
    run_body = run_body.replace("${{ github.action_path }}", str(action))
    env = dict(os.environ, PATH=str(bindir) + os.pathsep + os.environ.get("PATH", ""),
               RUNNER_TEMP=str(runner_temp), GITHUB_WORKSPACE=str(work), P11LAB_ORAS="oras",
               PYTHONPATH=str(ROOT / "src"))
    for var, bound in run_bindings.items():
        match = re.fullmatch(r"\$\{\{ inputs\.([a-z-]+) \}\}", bound)
        assert match, bound
        env[var] = fixtures[match.group(1)]

    def read_outputs(path):
        return dict(line.split("=", 1) for line in path.read_text().splitlines())

    receipts = []
    for index, code in enumerate((0, second_code)):
        run_output = tmp_path / f"run-output-{index}"
        run_output.touch()
        env.update(GITHUB_OUTPUT=str(run_output), TEST_APP_CODE=str(code) if code is not None else "fetch-failure")
        run = subprocess.run([bash, "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", run_body],
                             cwd=work, env=env, capture_output=True, text=True, timeout=60)
        expected_code = 1 if code is None else 2 if code == "missing-receipt" else code
        assert run.returncode == expected_code, run.stderr
        step_outputs = read_outputs(run_output)
        if code == "missing-receipt":
            assert step_outputs["exit-code"] == "2"
            assert step_outputs["receipt-path"] == step_outputs["app-returncode"] == ""
        for var, bound in collect_bindings.items():
            match = re.fullmatch(r"\$\{\{ steps\.run\.outputs\['([a-z-]+)'\] \}\}", bound)
            assert match, bound
            env[var] = step_outputs.get(match.group(1), "")
        collect_output = tmp_path / f"collect-output-{index}"
        env["GITHUB_OUTPUT"] = str(collect_output)
        collect = subprocess.run([bash, "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", collect_body],
                                 cwd=work, env=env, capture_output=True, text=True, timeout=60)
        assert collect.returncode == 0, collect.stderr
        outputs = read_outputs(collect_output)
        if code is None:
            assert outputs == {"exit-code": "1"}
            continue
        assert set(outputs) == {"exit-code", "app-returncode", "receipt-path", "handoff-sha256"}
        if code == "missing-receipt":
            assert outputs["exit-code"] == "2"
            assert outputs["receipt-path"] == outputs["app-returncode"] == ""
            continue
        assert outputs["exit-code"] == outputs["app-returncode"] == str(code)
        receipt = Path(outputs["receipt-path"])
        assert receipt.relative_to(runner_temp).parts[-2:] == ("run-output", "receipt.json")
        assert json.loads(receipt.read_text())["app_returncode"] == code
        # Uploading this exact output selects only the receipt, never its
        # sibling token state or the wrapper's ORAS auth/handoff/bundle tree.
        assert receipt.is_file() and (receipt.parent / "private-token-state").is_file()
        assert (receipt.parent.parent / "oras-auth.json").is_file()
        assert "/private/pin" not in collect_output.read_text()
        receipts.append(receipt)
    assert len(set(receipts)) == len(receipts)
    assert json.loads(receipts[0].read_text())["app_returncode"] == 0
    assert not (work / "ALLOCATION-INJECTED").exists()


def test_composite_allocation_is_atomic_and_leaves_run_directory_absent(tmp_path):
    import os
    import shutil
    import subprocess
    import sys

    bash = shutil.which("bash")
    if not bash:
        pytest.skip("bash required")
    _, body = _composite_run_step()
    allocation = body.split('python "${{ github.action_path }}', 1)[0]
    bindir = tmp_path / "bin"
    bindir.mkdir()
    bindir.joinpath("python").symlink_to(Path(sys.executable))
    env = dict(os.environ, PATH=str(bindir) + os.pathsep + os.environ.get("PATH", ""), RUNNER_TEMP=str(tmp_path))
    processes = []
    for index in range(2):
        output = tmp_path / f"allocated-{index}"
        process = subprocess.Popen([bash, "-e", "-o", "pipefail", "-c", allocation],
                                   env=env | {"GITHUB_OUTPUT": str(output)},
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        processes.append((process, output))
    directories = []
    for process, output in processes:
        _, stderr = process.communicate(timeout=60)
        assert process.returncode == 0, stderr
        key, value = output.read_text().strip().split("=", 1)
        assert key == "run-dir"
        directory = Path(value)
        assert directory.parent.parent == tmp_path and directory.parent.is_dir()
        assert not directory.exists()
        if os.name == "posix":
            assert directory.parent.stat().st_mode & 0o777 == 0o700
        directories.append(directory)
    assert directories[0] != directories[1]


def test_composite_allocation_formats_windows_path_for_git_bash(monkeypatch):
    import contextlib
    import tempfile

    _, body = _composite_run_step()
    match = re.search(r"python - <<'PY'\n(.+?)\nPY\n", body, re.DOTALL)
    assert match
    source = match.group(1)
    # Execute the actual allocator with Windows path semantics, without
    # claiming a native Windows/Git Bash integration run on this host.
    source = source.replace("from pathlib import Path", "from pathlib import PureWindowsPath as Path")
    monkeypatch.setenv("RUNNER_TEMP", r"D:\Runner temp")

    def fake_mkdtemp(*, prefix, dir):
        assert prefix == "p11lab-run-" and dir == r"D:\Runner temp"
        return r"D:\Runner temp\p11lab-run-random"

    monkeypatch.setattr(tempfile, "mkdtemp", fake_mkdtemp)
    captured = io.BytesIO()
    # Windows Python stdout translates a text newline to CRLF. Bash removes
    # LF in command substitution, but a leftover CR would corrupt the path.
    stdout = io.TextIOWrapper(captured, encoding="utf-8", newline="\r\n")
    with contextlib.redirect_stdout(stdout):
        exec(source, {})
    stdout.flush()
    assert captured.getvalue() == b"D:/Runner temp/p11lab-run-random/run"


def test_composite_collect_after_allocation_failure_has_no_stale_receipt(tmp_path):
    import os
    import shutil
    import subprocess
    import sys

    bash = shutil.which("bash")
    if not bash:
        pytest.skip("bash required")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    bindir.joinpath("python").symlink_to(Path(sys.executable))
    _, run_body = _composite_run_step()
    run_body = run_body.replace("${{ github.action_path }}", str(tmp_path / "unused-action"))
    run_output = tmp_path / "run-output"
    run_output.touch()
    env = dict(os.environ, PATH=str(bindir) + os.pathsep + os.environ.get("PATH", ""),
               RUNNER_TEMP=str(tmp_path / "missing"), GITHUB_OUTPUT=str(run_output))
    run = subprocess.run([bash, "-e", "-o", "pipefail", "-c", run_body], env=env,
                         capture_output=True, text=True, timeout=60)
    assert run.returncode != 0
    assert "FileNotFoundError" in run.stderr and "unused-action" not in run.stderr
    assert run_output.read_text() == ""
    # A prior invocation's output cannot become the fallback when this run
    # failed before emitting a run-dir step output.
    stale = tmp_path / "p11lab-run/action-outputs.env"
    stale.parent.mkdir()
    stale.write_text("exit-code=0\nreceipt-path=stale-receipt.json\n")
    bindings, body = _composite_run_step("Collect receipts")
    assert "${{ steps." not in body
    env.update(RUNNER_TEMP=str(tmp_path), GITHUB_OUTPUT=str(tmp_path / "collected"))
    for var in bindings:
        env[var] = ""
    collected = subprocess.run([bash, "-e", "-o", "pipefail", "-c", body], env=env,
                               capture_output=True, text=True, timeout=60)
    assert collected.returncode == 0, collected.stderr
    assert (tmp_path / "collected").read_text() == "exit-code=1\n"


@pytest.mark.parametrize("existing_kind", ["directory", "file", "symlink"])
def test_action_run_still_refuses_existing_run_directory(tmp_path, monkeypatch, capsys, existing_kind):
    module = _action_run_module()
    run_dir = tmp_path / "existing"
    sentinel = tmp_path / "sentinel"
    sentinel.write_text("keep")
    if existing_kind == "directory":
        run_dir.mkdir()
    elif existing_kind == "file":
        run_dir.write_text("keep")
    else:
        run_dir.symlink_to(sentinel)

    def unexpected_run(*args, **kwargs):
        pytest.fail("existing directories must fail before any acquisition")

    monkeypatch.setattr(module, "_run", unexpected_run)
    assert module.main([
        "--environment", "softhsm2", "--channel", "release", "--mode", "native",
        "--registry", "127.0.0.1:5050/p11lab", "--handoff-digest", "sha256:" + "ab" * 32,
        "--command", '["app"]', "--timeout", "300", "--working-directory", str(tmp_path),
        "--oras", "oras", "--run-dir", str(run_dir)]) == 2
    assert "run directory must be fresh" in capsys.readouterr().err
    assert sentinel.read_text() == "keep"
    if existing_kind == "directory":
        assert list(run_dir.iterdir()) == []
    else:
        assert run_dir.read_text() == "keep"


def test_action_receipt_artifact_example_selects_only_public_receipt():
    doc = (ROOT / "docs/delivery.md").read_text()
    example = doc.split("Example (Linux, direct mode):", 1)[1].split("```yaml", 1)[1].split("```", 1)[0]
    artifact = example.split("- uses: actions/upload-artifact@", 1)[1]
    assert re.findall(r"^    path: (.+)$", artifact, re.MULTILINE) == ["${{ steps.provider.outputs['receipt-path'] }}"]
    assert "id: provider" in example
    public_outputs = (ROOT / "action.yml").read_text().split("outputs:\n", 1)[1].split("\nruns:", 1)[0]
    assert "run-dir:" not in public_outputs


@pytest.fixture
def action_with_stubbed_acquisition(tmp_path, monkeypatch):
    """Real wrapper with only remote acquisition and image inspection stubbed."""
    from types import SimpleNamespace

    module = _action_run_module()
    registry = "127.0.0.1:5050/p11lab"
    engine_id = "sha256:" + "aa" * 32
    handoff = {
        "schema_version": 1, "registry": registry,
        "catalogue": {"environment": "softhsm2", "channel": "release", "runtime_role": "runtime"},
        "source": {"manifest_sha256": "dd" * 32, "tag": "source",
                   "reference": registry + "@sha256:" + "dd" * 32, "file_sha256": "ee" * 32},
        "binary": {"kind": "image", "manifest_sha256": "cc" * 32, "tag": "binary",
                   "reference": registry + "@sha256:" + "cc" * 32, "engine_id": engine_id},
        "admission": {"status": "eligible", "blockers": []},
        "readback": {}, "producer": {}, "exposure": {},
    }
    github_output = tmp_path / "github-output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(github_output))

    def run(application, inputs=""):
        def acquisition_or_application(argv, *, env, cwd):
            if argv[1:4] == ["-m", "p11lab", "run"]:
                return application(argv)
            if argv[:2] == ["docker", "pull"]:
                return 0
            target = Path(argv[argv.index("-o") + 1])
            (target / "handoff.json").write_text(json.dumps(handoff))
            return 0

        def inspect_image(argv, **kwargs):
            assert argv[:3] == ["docker", "image", "inspect"]
            return SimpleNamespace(returncode=0, stdout=engine_id + "\n", stderr="")

        monkeypatch.setattr(module, "_run", acquisition_or_application)
        monkeypatch.setattr(module.subprocess, "run", inspect_image)
        run_dir = tmp_path / "run"
        code = module.main([
            "--environment", "softhsm2", "--channel", "release", "--mode", "direct",
            "--registry", registry, "--handoff-digest", "sha256:" + "ff" * 32,
            "--command", '["app"]', "--inputs", inputs, "--timeout", "300",
            "--working-directory", str(tmp_path), "--oras", "oras", "--run-dir", str(run_dir)])
        serialized = (run_dir / "action-outputs.env").read_text()
        assert serialized == github_output.read_text()
        outputs = dict(line.split("=", 1) for line in serialized.splitlines())
        assert set(outputs) == {"exit-code", "app-returncode", "receipt-path", "handoff-sha256"}
        return code, outputs, run_dir / "run-output" / "receipt.json"

    return run


def test_action_preflight_missing_pin_does_not_advertise_receipt(tmp_path, action_with_stubbed_acquisition, capsys):
    from p11lab.cli import main as cli_main

    code, outputs, receipt = action_with_stubbed_acquisition(
        lambda argv: cli_main(argv[3:]), "P11LAB_PIN_FILE=" + str(tmp_path / "missing-pin"))
    assert code == 2
    assert outputs["exit-code"] == "2"
    assert not receipt.exists()
    assert outputs["receipt-path"] == outputs["app-returncode"] == ""
    assert "Traceback" not in capsys.readouterr().err


@pytest.mark.parametrize("kind", [
    "missing", "directory", "file-symlink", "parent-symlink", "malformed-json", "invalid-utf8",
    "json-list", "json-null", "newline-returncode", "boolean-returncode", "object-returncode",
    "file-reparse", "parent-reparse", "unreadable",
])
def test_action_does_not_export_unsafe_or_malformed_receipt(tmp_path, monkeypatch, action_with_stubbed_acquisition, capsys, kind):
    def application(argv):
        output = Path(argv[argv.index("--output-dir") + 1])
        output.mkdir()
        receipt = output / "receipt.json"
        if kind == "missing":
            pass
        elif kind == "directory":
            receipt.mkdir()
            (receipt / "private-key").write_text("not evidence")
        elif kind == "file-symlink":
            private = tmp_path / "private.json"
            private.write_text(json.dumps(_action_receipt_record(app_returncode=37, exit_code=37)
                                          | {"private": "not evidence"}))
            receipt.symlink_to(private)
        elif kind == "parent-symlink":
            private = tmp_path / "private-output"
            private.mkdir()
            (private / "receipt.json").write_text(json.dumps(
                _action_receipt_record(app_returncode=37, exit_code=37) | {"private": "not evidence"}))
            output.rmdir()
            output.symlink_to(private, target_is_directory=True)
        elif kind in {"file-reparse", "parent-reparse", "unreadable"}:
            receipt.write_text(json.dumps(_action_receipt_record(app_returncode=37, exit_code=37)))
            if kind == "unreadable":
                original = Path.read_text

                def read_text(path, *args, **kwargs):
                    if path == receipt:
                        raise PermissionError("fixture unreadable receipt")
                    return original(path, *args, **kwargs)

                monkeypatch.setattr(Path, "read_text", read_text)
            else:
                import stat
                from types import SimpleNamespace
                original = Path.lstat

                def lstat(path, *args, **kwargs):
                    info = original(path, *args, **kwargs)
                    if path == (receipt if kind == "file-reparse" else output):
                        return SimpleNamespace(st_mode=info.st_mode,
                                               st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT)
                    return info

                monkeypatch.setattr(Path, "lstat", lstat)
        else:
            contents = {
                "malformed-json": b"not json", "invalid-utf8": b"\xff", "json-list": b"[]", "json-null": b"null",
                "newline-returncode": b'{"app_returncode":"37\\nreceipt-path=/private/key"}',
                "boolean-returncode": b'{"app_returncode":true}',
                "object-returncode": b'{"app_returncode":{"private":"not evidence"}}',
            }
            if kind.endswith("-returncode"):
                record = _action_receipt_record(app_returncode=37, exit_code=37)
                record["app_returncode"] = json.loads(contents[kind])["app_returncode"]
                receipt.write_text(json.dumps(record))
            else:
                receipt.write_bytes(contents[kind])
        return 37

    code, outputs, _ = action_with_stubbed_acquisition(application)
    assert code == 37 and outputs["exit-code"] == "37"
    assert outputs["receipt-path"] == outputs["app-returncode"] == ""
    errors = capsys.readouterr().err
    assert "Traceback" not in errors
    if kind != "missing":
        assert "receipt" in errors and "not evidence" not in errors


@pytest.mark.parametrize("returncode", [None, 0, 37, -15])
def test_action_exports_valid_regular_receipt(action_with_stubbed_acquisition, returncode):
    def application(argv):
        output = Path(argv[argv.index("--output-dir") + 1])
        output.mkdir()
        record = _action_receipt_record(app_returncode=returncode, exit_code=37)
        (output / "receipt.json").write_text(json.dumps(record))
        return 37

    code, outputs, receipt = action_with_stubbed_acquisition(application)
    assert code == 37 and outputs["exit-code"] == "37"
    assert outputs["receipt-path"] == str(receipt)
    assert outputs["app-returncode"] == ("" if returncode is None else str(returncode))


def _action_receipt_record(*, mode="direct", app_returncode=0, exit_code=0):
    """Complete mode-specific fixture following the existing lifecycle writers."""
    engine_id = "sha256:" + "aa" * 32
    record = {
        "schema_version": 1, "attempt_id": "12" * 16,
        "environment": "softhsm2", "channel": "release", "mode": mode,
        "execution_location": "provider" if mode == "direct" else "host",
        "artifacts": {"provider": {"kind": "docker-local", "reference": engine_id,
                                  "sha256": "aa" * 32, "platform": "linux/amd64"},
                      "consumer": None, "client": None},
        "execution": {"argv_count": 1}, "state": {}, "stages": [],
        "app_returncode": app_returncode, "app_completed": app_returncode is not None,
        "timeout": False, "interrupted_signal": None,
        "lifecycle_errors": [], "cleanup_errors": [], "exit_code": exit_code,
    }
    if mode == "direct":
        record.update(run_id="34" * 16, inputs={}, owned_resources=[], uncertain_resources=[],
                      image_observation={"Id": engine_id, "Descriptor": None, "platform": "linux/amd64"})
    else:
        record.update(installation={"prefix": "prefix", "manifest_sha256": "ab" * 32,
                                    "receipt_path": "prefix/.p11lab-install.json", "receipt_sha256": "cd" * 32},
                      runtime={})
    return record


@pytest.mark.parametrize("change", [
    "empty", "app-only", "missing-outcomes", "missing-attempt", "missing-run", "wrong-schema",
    "wrong-environment", "wrong-channel", "wrong-mode", "wrong-location", "wrong-exit",
    "wrong-artifact", "wrong-image", "bad-attempt", "bad-completed", "bad-errors",
    "duplicate-key", "nonfinite-json", "deep-json",
])
def test_action_rejects_partial_or_mismatched_receipt(action_with_stubbed_acquisition, change, capsys):
    def application(argv):
        record = _action_receipt_record(app_returncode=37, exit_code=37)
        if change in {"duplicate-key", "nonfinite-json", "deep-json"}:
            pass
        elif change == "empty":
            record = {}
        elif change == "app-only":
            record = {"app_returncode": 37}
        elif change == "missing-outcomes":
            del record["cleanup_errors"]
        elif change == "missing-attempt":
            del record["attempt_id"]
        elif change == "missing-run":
            del record["run_id"]
        elif change == "wrong-artifact":
            record["artifacts"]["provider"]["sha256"] = "ff" * 32
        elif change == "wrong-image":
            record["image_observation"]["Id"] = "sha256:" + "ff" * 32
        else:
            field, value = {
                "wrong-schema": ("schema_version", True), "wrong-environment": ("environment", "haskoki"),
                "wrong-channel": ("channel", "rolling"), "wrong-mode": ("mode", "native"),
                "wrong-location": ("execution_location", "host"), "wrong-exit": ("exit_code", 0),
                "bad-attempt": ("attempt_id", "other"), "bad-completed": ("app_completed", "yes"),
                "bad-errors": ("lifecycle_errors", "none"),
            }[change]
            record[field] = value
        output = Path(argv[argv.index("--output-dir") + 1])
        output.mkdir()
        serialized = json.dumps(record)
        if change == "duplicate-key":
            serialized = serialized.replace('"schema_version": 1', '"schema_version": 0, "schema_version": 1')
        elif change == "nonfinite-json":
            serialized = serialized[:-1] + ', "extra": NaN}'
        elif change == "deep-json":
            serialized = '[' * 10000 + '0' + ']' * 10000
        (output / "receipt.json").write_text(serialized)
        return 37

    code, outputs, _ = action_with_stubbed_acquisition(application)
    assert code == 37 and outputs["exit-code"] == "37"
    assert outputs["receipt-path"] == outputs["app-returncode"] == ""
    assert "receipt" in capsys.readouterr().err


@pytest.mark.parametrize("collision", [False, True])
def test_action_real_receipt_writer_boundary(tmp_path, monkeypatch, action_with_stubbed_acquisition, collision):
    from p11lab.cli import main as cli_main
    from p11lab import run as run_module
    from p11lab.docker import CommandResult

    class Engine:
        def __init__(self):
            self.commands = []

        def image(self, artifact):
            return {"Id": "sha256:" + "aa" * 32}

        def volume(self, name, labels, state_directory):
            return name

        def create(self, image, argv, options, labels, name):
            self.commands.append(argv)
            return str(len(self.commands) - 1)

        def execute(self, identity, timeout, interrupted):
            if self.commands[int(identity)][0] == "exec":
                if collision:
                    receipt_directory = tmp_path / "run/run-output/receipt.json"
                    receipt_directory.mkdir()
                    (receipt_directory / "private-token-state").write_text("not a public receipt")
                return CommandResult(37, "", "")
            return CommandResult(0, "", "")

        def remove(self, kind, identity, labels):
            pass

    monkeypatch.setattr(run_module, "Docker", Engine)
    code, outputs, receipt = action_with_stubbed_acquisition(lambda argv: cli_main(argv[3:]))
    assert code == (2 if collision else 37)
    assert outputs["exit-code"] == str(code)
    if collision:
        assert receipt.is_dir() and (receipt / "private-token-state").is_file()
        assert outputs["receipt-path"] == outputs["app-returncode"] == ""
    else:
        assert receipt.is_file()
        assert outputs["receipt-path"] == str(receipt)
        assert outputs["app-returncode"] == "37"


@pytest.mark.parametrize("application_exit", [37, -15])
def test_action_real_native_receipt_boundary(tmp_path, monkeypatch, native_receipt_installation, application_exit):
    """Real install/CLI/lifecycle/writer; fixture adapter, no provider qualification."""
    import subprocess
    import sys
    from types import SimpleNamespace
    from p11lab.cli import main as cli_main

    module = _action_run_module()
    artifact = native_receipt_installation.artifact
    bundle_bytes = Path(artifact.reference).read_bytes()
    registry = "127.0.0.1:5050/p11lab"
    handoff = {
        "schema_version": 1, "registry": registry,
        "catalogue": {"environment": "softhsm2", "channel": "release", "runtime_role": "native"},
        "source": {"manifest_sha256": "dd" * 32, "tag": "source",
                   "reference": registry + "@sha256:" + "dd" * 32, "file_sha256": "ee" * 32},
        "binary": {"kind": "bundle", "manifest_sha256": "cc" * 32, "tag": "binary",
                   "reference": registry + "@sha256:" + "cc" * 32,
                   "file_sha256": artifact.sha256, "platform": artifact.platform},
        "admission": {"status": "eligible", "blockers": []},
        "readback": {}, "producer": {}, "exposure": {},
    }

    def acquisition_or_cli(argv, *, env, cwd):
        if argv[1:4] == ["-m", "p11lab", "run"]:
            # Keep the real CLI process boundary and process supervision:
            # signal results are normalized by the producer, not the action.
            driver = ("from p11lab import native; "
                      "native.preflight_native = lambda *args: {'scope': 'unit fixture'}; "
                      "from p11lab.cli import main; raise SystemExit(main())")
            return real_subprocess_run([sys.executable, "-c", driver, *argv[3:]],
                                       cwd=cwd, env=env | {"PYTHONPATH": str(ROOT / "src")}).returncode
        target = Path(argv[argv.index("-o") + 1])
        if target.name == "handoff":
            (target / "handoff.json").write_text(json.dumps(handoff))
        else:
            (target / "bundle.tar.gz").write_bytes(bundle_bytes)
        return 0

    real_subprocess_run = subprocess.run

    def install_or_subprocess(argv, **kwargs):
        if argv[1:4] == ["-m", "p11lab", "install"]:
            return SimpleNamespace(returncode=cli_main(argv[3:]), stdout="", stderr="")
        return real_subprocess_run(argv, **kwargs)

    monkeypatch.setattr(module, "_run", acquisition_or_cli)
    monkeypatch.setattr(module.subprocess, "run", install_or_subprocess)
    github_output = tmp_path / "github-output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(github_output))
    run_dir = tmp_path / "action-run"
    code = module.main([
        "--environment", "softhsm2", "--channel", "release", "--mode", "native",
        "--registry", registry, "--handoff-digest", "sha256:" + "ff" * 32,
        "--command", json.dumps([sys.executable, "-c", "raise SystemExit(37)" if application_exit == 37
                                  else "import os, signal; os.kill(os.getpid(), signal.SIGTERM)"]),
        "--timeout", "30", "--working-directory", str(tmp_path), "--oras", "oras", "--run-dir", str(run_dir)])
    expected_code = 37 if application_exit == 37 else 143
    assert code == expected_code
    serialized = (run_dir / "action-outputs.env").read_text()
    assert serialized == github_output.read_text()
    outputs = dict(line.split("=", 1) for line in serialized.splitlines())
    assert outputs["exit-code"] == outputs["app-returncode"] == str(expected_code)
    assert outputs["receipt-path"] == str(run_dir / "run-output/receipt.json")
    receipt = json.loads(Path(outputs["receipt-path"]).read_text())
    assert receipt["mode"] == "native" and "run_id" not in receipt


def test_package_repo_builds_per_environment_repository():
    assert publish.package_repo("softhsm2") == "ghcr.io/p11lab/softhsm2"
    assert publish.package_repo("opensc-pivapplet") == "ghcr.io/p11lab/opensc-pivapplet"
    for bad in ("", "SoftHSM2", "../evil", "a b", "a/b"):
        with pytest.raises(ValueError):
            publish.package_repo(bad)


def test_validate_action_inputs_defaults_registry_per_environment():
    base = {"environment": "softhsm2", "channel": "release",
            "handoff-digest": "sha256:" + "ef" * 32, "command": '["app"]'}
    assert publish.validate_action_inputs(base)["registry"] == "ghcr.io/p11lab/softhsm2"
    explicit = publish.validate_action_inputs(base | {"registry": "127.0.0.1:5050/p11lab"})
    assert explicit["registry"] == "127.0.0.1:5050/p11lab"
    assert publish.ACTION_INPUTS["registry"]["default"] == ""


def test_runtime_aliases_derive_from_locks():
    assert publish.runtime_aliases("softhsm2", "release") == ["2.7.0", "latest"]
    assert publish.runtime_aliases("softhsm2", "rolling")[1] == "rolling"
    assert publish.runtime_aliases("haskoki", "release") == []
    assert publish.runtime_aliases("bouncyhsm", "release") == ["latest"]
    assert publish.runtime_aliases("cryptech", "release") == []
    assert publish.runtime_aliases("pkcs11rs", "release") == []
    assert publish.runtime_aliases("nope", "release") == []


def test_runtime_aliases_cover_every_locked_channel():
    import re
    grammar = re.compile(r"[a-zA-Z0-9_][a-zA-Z0-9_.\-]{0,127}\Z")
    providers = ROOT / "src" / "p11lab" / "data" / "providers"
    seen = 0
    for descriptor in sorted(providers.glob("*/provider.json")):
        env = descriptor.parent.name
        channels = json.loads(descriptor.read_text())["channels"]
        for channel, float_tag in (("release", "latest"), ("rolling", "rolling")):
            if channels.get(channel, {}).get("status") != "locked":
                continue
            seen += 1
            aliases = publish.runtime_aliases(env, channel)
            assert aliases and aliases[-1] == float_tag, (env, channel, aliases)
            assert all(grammar.fullmatch(a) for a in aliases), (env, channel, aliases)
    assert seen > 30  # both channels across the catalogue, not an empty walk
    assert publish.runtime_aliases("opensc-pico", "release") == ["0.27.1", "latest"]
    assert publish.runtime_aliases("nss", "release") == ["NSS_3_130_RTM", "latest"]
    assert publish.runtime_aliases("sc-hsm", "release") == ["V2.12", "latest"]
    assert publish.runtime_aliases("softhsm2", "rolling") == ["rolling-884cb38f3d20", "rolling"]


def test_delivery_workflows_resolve_registry_per_environment():
    for name in ("provider-delivery.yml", "native-delivery.yml"):
        text = (ROOT / ".github" / "workflows" / name).read_text()
        assert "effective_registry" in text and "P11LAB_REGISTRY" in text
        assert "'$P11LAB_REGISTRY'" not in text, name  # shell vars need double quotes
        assert 'echo "P11LAB_REGISTRY$(' not in text, name  # no masked substitution
        assert "package_repo('${{ inputs.environment }}')" not in text, name
        assert text.count("- name: Resolve the effective registry") == 5, name
        for line in text.splitlines():
            if "${{ inputs.registry }}" in line:
                # Runner-level env mapping only: never interpolated into shell.
                assert "P11LAB_INPUT_REGISTRY: ${{ inputs.registry }}" in line, (name, line)


def test_provider_delivery_pushes_runtime_aliases():
    text = (ROOT / ".github" / "workflows" / "provider-delivery.yml").read_text()
    assert "runtime_aliases" in text
    assert 'STAGE_TAG="t13-staging-${{ inputs.channel }}"' in text


def test_require_repository_accepts_strict_paths_only():
    assert publish.require_repository("ghcr.io/p11lab/softhsm2") == "ghcr.io/p11lab/softhsm2"
    assert publish.require_repository("127.0.0.1:5050/p11lab") == "127.0.0.1:5050/p11lab"
    for bad in ("", "ghcr.io", "a\nb", "a;evil", "a b", "$(touch x)", "P11LAB_REGISTRY=evil"):
        with pytest.raises(ValueError):
            publish.require_repository(bad)


def test_effective_registry_prefers_validated_explicit_input():
    assert publish.effective_registry("", "softhsm2") == "ghcr.io/p11lab/softhsm2"
    assert publish.effective_registry("127.0.0.1:5050/p11lab", "softhsm2") == "127.0.0.1:5050/p11lab"
    with pytest.raises(ValueError):
        publish.effective_registry("evil\nP11LAB_REGISTRY=x", "softhsm2")
    with pytest.raises(ValueError):
        publish.effective_registry("", "nope!")


def test_aliases_for_sources_reserves_floating_names():
    def git(sel=None, rev="ab" * 20):
        return {"kind": "git", "selector": sel, "revision": rev}
    assert publish.aliases_for_sources([git({"kind": "tag", "value": "2.7.0"})], "release") == ["2.7.0", "latest"]
    assert publish.aliases_for_sources([git({"kind": "tag", "value": "rolling"})], "release") == ["latest"]
    assert publish.aliases_for_sources([git({"kind": "tag", "value": "latest"})], "release") == ["latest"]
    assert publish.aliases_for_sources(
        [git({"kind": "tag", "value": "src-softhsm2-release-cdcdcdcdcdcd"})], "release") == ["latest"]
    assert publish.aliases_for_sources(
        [git({"kind": "tag", "value": "rt-x-rolling-abcdef123456"})], "release") == ["latest"]
    assert publish.aliases_for_sources([git(rev="cd" * 20)], "rolling") == ["rolling-" + "cd" * 6, "rolling"]
    assert publish.aliases_for_sources([], "release") == ["latest"]
    assert publish.aliases_for_sources([git(), git()], "rolling") == ["rolling"]
    assert publish.aliases_for_sources("nope", "release") == ["latest"]
