"""Proxy execute gate chain (P1a): selection -> bytes -> install/identity/derivative.

Hermetic by construction: static fixtures under
tests/fixtures/proxy_execute/ cover selection + byte verification with
invented IDs, while identity/install/derivative material is rebuilt at
runtime from installed libraries only (pinned-default record, protected
parent roster). No live runs, no Docker, no network.

Independence rule: this module never imports from other test modules.
Every builder below is authored from the production contract, not copied
from precedent test helpers; fixture IDs are invented here and differ
from every other suite on purpose.
"""

import ast
import copy
import hashlib
import json
from pathlib import Path

import pytest

from p11lab import native as native_module
from p11lab import proxy_derivative as derivative_module
from p11lab.cli import main
from p11lab.models import ProxyBuildIdentityV1
from p11lab import tls as tls_module

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "proxy_execute"
PROXY_SHA = "e8" * 20
OTHER_SHA = "f7" * 20
RUN_ID = 777771
RUN_ATTEMPT = 2
AUTHORITY = {
    "repository_id": 7777,
    "repository_full_name": "example/proxy-gates-caller",
    "producer_job_id": "777778",
    "artifact_id": 777779,
}


def _pe():
    """Import the production gate chain lazily (RED-countable, GREEN-direct)."""
    from p11lab.round_core import proxy_execute

    return proxy_execute


def _read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n",
                          encoding="utf-8")


def _record(sha, run_id, attempt, **overrides):
    row = {"sha": sha, "run_id": run_id, "run_attempt": attempt,
           "name": "p11lab-proxy-dist-%s-%d" % (sha, attempt), **AUTHORITY}
    row.update(overrides)
    return row


def _default_record():
    """Fresh pinned-default identity record (absolute default, never wildcard)."""
    return tls_module.DEFAULT_PROXY_BUILD_IDENTITY().to_dict()


def _flip_first(value):
    table = "123456789abcdef0"
    return table["0123456789abcdef".index(value[0])] + value[1:]


def _variant_record():
    """Second valid record: same toolchain/config shape, distinct source.

    Only hash-identity fields move (formats preserved), so from_dict still
    accepts it while every sameness check against the default refuses.
    """
    record = _default_record()
    for key in ("source_commit", "source_tree", "cargo_lock_sha256",
                "build_context_digest"):
        record[key] = _flip_first(record[key])
    record["source_archive"] = dict(record["source_archive"])
    record["source_archive"]["sha256"] = _flip_first(
        record["source_archive"]["sha256"])
    for key in ("daemon", "cli", "shim"):
        record[key] = dict(record[key])
        record[key]["sha256"] = _flip_first(record[key]["sha256"])
    return ProxyBuildIdentityV1.from_dict(record).to_dict()


def _payload_digests():
    """Real (size, sha256) of the static fixture payload bytes."""
    return {
        role: (data, len(data), hashlib.sha256(data).hexdigest())
        for role, data in (
            ("daemon", (FIXTURES / "daemon.bin").read_bytes()),
            ("cli", (FIXTURES / "cli.bin").read_bytes()),
            ("shim", (FIXTURES / "shim.bin").read_bytes()))}


def _synthetic(record):
    """Record variant whose product digests equal the fixture payloads.

    sha256 has no preimage shortcut: chain/CLI fixtures cannot stage
    bytes matching the pinned-default digests, so the honest staged
    identity re-roots product (size, sha256) at the fixture bytes while
    keeping every other field (commit, toolchain, ABI, caller). Valid
    per from_dict (sizes have no minimum); staged as the artifact's
    explicit expected identity (caller-staged, test-only authority).
    """
    digests = _payload_digests()
    record = copy.deepcopy(record)
    for role in ("daemon", "cli", "shim"):
        _, size, sha256 = digests[role]
        record[role] = dict(record[role])
        record[role]["size"] = size
        record[role]["sha256"] = sha256
    return ProxyBuildIdentityV1.from_dict(record).to_dict()


def _daemon_claim(record):
    return {"schema_version": 1, "source_revision": record["source_commit"],
            "cargo_lock_sha256": record["cargo_lock_sha256"],
            "binaries": {
                "pkcs11-proxy-ng": record["daemon"]["sha256"],
                "pkcs11-proxy-ng-cli": record["cli"]["sha256"],
                "proxy-entrypoint.sh": record["entrypoint_sha256"]}}


def _client_abi(record):
    """Client-path restriction of a record ABI (what a build observes)."""
    abi = record["abi"]
    paths = (native_module.CLIENT_CLI, native_module.CLIENT_MODULE)
    return {"decision": abi["decision"],
            "runtime_qualification": abi["runtime_qualification"],
            "floors": {path: copy.deepcopy(abi["floors"][path]) for path in paths},
            "needed": {path: copy.deepcopy(abi["needed"][path]) for path in paths},
            "interpreters": {path: abi["interpreters"][path] for path in paths},
            "shim_exports": list(abi["shim_exports"]),
            "version_requirements": {
                path: copy.deepcopy(abi["version_requirements"][path])
                for path in paths},
            "symbol_versions": {
                path: copy.deepcopy(abi["symbol_versions"][path])
                for path in paths}}


def _client_manifest(record, abi=None):
    """Full native-client manifest section matching a record."""
    archive = record["source_archive"]
    proxy = {"source_revision": record["source_commit"],
             "source_archive_sha256": archive["sha256"] if archive else None,
             "cargo_lock_sha256": record["cargo_lock_sha256"],
             "shim_sha256": record["shim"]["sha256"],
             "cli_sha256": record["cli"]["sha256"],
             "identity": copy.deepcopy(record),
             "abi_observed": (copy.deepcopy(abi) if abi is not None
                              else _client_abi(record))}
    return {"role": "native-client", "target": native_module.CLIENT_TARGET,
            "module": native_module.CLIENT_MODULE,
            "host_requirements": copy.deepcopy(
                native_module.CLIENT_HOST_REQUIREMENTS),
            "source": {"proxy": proxy},
            "files": [
                {"path": native_module.CLIENT_MODULE,
                 "sha256": record["shim"]["sha256"]},
                {"path": native_module.CLIENT_CLI,
                 "sha256": record["cli"]["sha256"]}],
            "environment": "softhsm2", "channel": "release"}


def _launch_rehashes(record):
    return {"shim_sha256": record["shim"]["sha256"],
            "cli_sha256": record["cli"]["sha256"]}


def _daemon_image(*, observed=None):
    reference = "sha256:" + "e" * 64
    return {"selected": reference,
            "observed": reference if observed is None else observed}


def _parent_selection():
    return derivative_module.load_parent_selection()


def _child_inspection(*, layers=None):
    if layers is None:
        layers = list(_parent_selection()["layers"]) + ["sha256:" + "9" * 64]
    return {"RootFS": {"Layers": layers}}


def _stage_artifact(root, name, *, records=None, authority=None,
                    manifest=None, payloads=None, daemon_build=None,
                    client_manifest=None, rehashes=None, abi=None,
                    daemon_image=None, child_inspection=None, parent_ref=None,
                    expected_identity="synthetic", omit=()):
    """Write one caller-built artifact directory under root/basename=name."""
    record = _synthetic(_default_record())
    staged = Path(root) / name
    staged.mkdir(parents=True)
    if "records.json" not in omit:
        _write_json(staged / "records.json",
                    records if records is not None else [
                        _record(record["source_commit"], RUN_ID, RUN_ATTEMPT)])
    if "authority.json" not in omit:
        _write_json(staged / "authority.json",
                    authority if authority is not None else dict(AUTHORITY))
    if manifest is None:
        manifest = _read_json(FIXTURES / "manifest.json")
        manifest["source_commit"] = record["source_commit"]
        manifest["run_id"] = RUN_ID
        manifest["run_attempt"] = RUN_ATTEMPT
    _write_json(staged / "manifest.json", manifest)
    payloads = dict(payloads) if payloads is not None else {
        "daemon.bin": (FIXTURES / "daemon.bin").read_bytes(),
        "cli.bin": (FIXTURES / "cli.bin").read_bytes(),
        "shim.bin": (FIXTURES / "shim.bin").read_bytes()}
    for role in ("daemon", "cli", "shim"):
        path = manifest[role + "_path"]
        assert ".." not in path.split("/") and not path.startswith("/")
        (staged / path).write_bytes(payloads[path])
    _write_json(staged / "daemon_build.json",
                daemon_build if daemon_build is not None
                else _daemon_claim(record))
    _write_json(staged / "client_manifest.json",
                client_manifest if client_manifest is not None
                else _client_manifest(record))
    _write_json(staged / "launch_rehashes.json",
                rehashes if rehashes is not None
                else _launch_rehashes(record))
    _write_json(staged / "abi_observed.json",
                abi if abi is not None else _client_abi(record))
    _write_json(staged / "daemon_image.json",
                daemon_image if daemon_image is not None
                else _daemon_image())
    _write_json(staged / "child_inspection.json",
                child_inspection if child_inspection is not None
                else _child_inspection())
    (staged / "parent_ref.txt").write_text(
        parent_ref if parent_ref is not None
        else _parent_selection()["local_engine_id"], encoding="utf-8")
    if "expected_identity.json" not in omit:
        _write_json(staged / "expected_identity.json",
                    record if expected_identity == "synthetic"
                    else expected_identity)
    return staged


def _honest_name(record=None):
    sha = (record or _default_record())["source_commit"]
    return "p11lab-proxy-dist-%s-%d" % (sha, RUN_ATTEMPT)


def _refusal_details(status):
    pe = _pe()
    assert isinstance(status.value, pe.ProxyGateRefusal)
    return status.value.cause, status.value.detail


# Selection: promoted same-run current-attempt binding (never test imports).


def test_selection_accepts_only_current_run_current_attempt():
    pe = _pe()
    records = _read_json(FIXTURES / "records.json")
    wanted = _record(PROXY_SHA, RUN_ID, RUN_ATTEMPT)
    assert records[0] == wanted
    assert pe.select_same_run(records, AUTHORITY, PROXY_SHA, RUN_ID,
                              RUN_ATTEMPT) == wanted


def test_selection_name_round_trips():
    pe = _pe()
    name = pe.expected_artifact_name(PROXY_SHA, 3)
    assert name == "p11lab-proxy-dist-%s-3" % PROXY_SHA
    assert pe.parse_artifact_name(name) == (PROXY_SHA, 3)


@pytest.mark.parametrize("name", [
    "p11lab-proxy-dist-%s-3" % ("e" * 39),
    "p11lab-proxy-dist-%s-3" % ("E" * 40),
    "p11lab-proxy-dist-%s-0" % PROXY_SHA,
    "p11lab-proxy-dist-%s" % PROXY_SHA,
    "p11lab-proxy-dist-%s-3-extra" % PROXY_SHA,
    "p11lab-proxy-%s-3" % PROXY_SHA,
    "",
])
def test_selection_malformed_names_reject(name):
    pe = _pe()
    with pytest.raises(pe.ProxyGateRefusal) as status:
        pe.parse_artifact_name(name)
    cause, detail = _refusal_details(status)
    assert cause is pe.ProxyGateCause.PROXY_GATE_SELECTION_REFUSED
    assert detail == "malformed proxy artifact name: %s" % name


@pytest.mark.parametrize("records", [
    [],
    [_record(OTHER_SHA, RUN_ID, RUN_ATTEMPT)],
    [_record(PROXY_SHA, RUN_ID + 1, RUN_ATTEMPT)],
    [_record(PROXY_SHA, RUN_ID, RUN_ATTEMPT - 1)],
    [_record(PROXY_SHA, RUN_ID, RUN_ATTEMPT),
     _record(PROXY_SHA, RUN_ID, RUN_ATTEMPT)],
])
def test_selection_cross_run_old_attempt_and_duplicate_reject(records):
    pe = _pe()
    with pytest.raises(pe.ProxyGateRefusal) as status:
        pe.select_same_run(records, AUTHORITY, PROXY_SHA, RUN_ID, RUN_ATTEMPT)
    cause, detail = _refusal_details(status)
    assert cause is pe.ProxyGateCause.PROXY_GATE_SELECTION_REFUSED
    assert detail == "rerun_requires_producer or ambiguous artifact"


def test_selection_binds_authority_metadata():
    pe = _pe()
    wanted = _record(PROXY_SHA, RUN_ID, RUN_ATTEMPT)
    assert wanted["repository_id"] == AUTHORITY["repository_id"]
    assert wanted["repository_full_name"] == AUTHORITY["repository_full_name"]
    assert wanted["producer_job_id"] == AUTHORITY["producer_job_id"]
    assert wanted["artifact_id"] == AUTHORITY["artifact_id"]
    assert pe.select_same_run([wanted], AUTHORITY, PROXY_SHA, RUN_ID,
                              RUN_ATTEMPT) == wanted


@pytest.mark.parametrize("overrides", [
    {"repository_id": 9999},
    {"repository_full_name": "attacker/relabeled-caller"},
    {"producer_job_id": "999999"},
    {"artifact_id": 999999999},
])
def test_selection_authority_mismatch_rejects(overrides):
    pe = _pe()
    records = [_record(PROXY_SHA, RUN_ID, RUN_ATTEMPT, **overrides)]
    with pytest.raises(pe.ProxyGateRefusal) as status:
        pe.select_same_run(records, AUTHORITY, PROXY_SHA, RUN_ID, RUN_ATTEMPT)
    cause, detail = _refusal_details(status)
    assert cause is pe.ProxyGateCause.PROXY_GATE_SELECTION_REFUSED
    assert detail == "rerun_requires_producer or ambiguous artifact"


def test_selection_invoked_attempt_must_match_artifact_name():
    pe = _pe()
    with pytest.raises(pe.ProxyGateRefusal) as status:
        pe.require_attempt_binding(3, RUN_ATTEMPT)
    cause, detail = _refusal_details(status)
    assert cause is pe.ProxyGateCause.PROXY_GATE_SELECTION_REFUSED
    assert detail == "proxy artifact mismatch: invoked attempt %d != artifact attempt 3" % RUN_ATTEMPT


def test_selection_partial_rerun_without_current_producer_rejects():
    """Full-rerun rule: stale-attempt records alone never select."""
    pe = _pe()
    stale = [_record(PROXY_SHA, RUN_ID, RUN_ATTEMPT - 1)]
    with pytest.raises(pe.ProxyGateRefusal) as status:
        pe.select_same_run(stale, AUTHORITY, PROXY_SHA, RUN_ID, RUN_ATTEMPT)
    assert _refusal_details(status)[1] == "rerun_requires_producer or ambiguous artifact"


def test_selection_nonlist_records_raise_as_usage():
    pe = _pe()
    with pytest.raises(ValueError, match="records must be a list"):
        pe.select_same_run({"not": "a list"}, AUTHORITY, PROXY_SHA, RUN_ID,
                           RUN_ATTEMPT)


def test_selection_malformed_authority_raises_as_usage():
    pe = _pe()
    records = [_record(PROXY_SHA, RUN_ID, RUN_ATTEMPT)]
    with pytest.raises(ValueError, match="authority must bind"):
        pe.select_same_run(records, {"repository_id": 7777}, PROXY_SHA,
                           RUN_ID, RUN_ATTEMPT)


# Byte verification: promoted manifest roster + size/hash checks.


def _honest_manifest(**overrides):
    manifest = _read_json(FIXTURES / "manifest.json")
    manifest.update(overrides)
    return manifest


def test_bytes_honest_manifest_and_payloads_verify(tmp_path):
    pe = _pe()
    manifest = _honest_manifest()
    checked = pe.verify_manifest(manifest, proxy_sha=PROXY_SHA, run_id=RUN_ID,
                                 run_attempt=RUN_ATTEMPT)
    assert checked == manifest
    digests = pe.verify_payload_bytes(FIXTURES, manifest)
    for role in ("daemon", "cli", "shim"):
        data = (FIXTURES / manifest[role + "_path"]).read_bytes()
        assert digests[role] == hashlib.sha256(data).hexdigest()
        assert digests[role] == manifest[role + "_sha256"]


def test_bytes_manifest_missing_field_rejects():
    pe = _pe()
    manifest = _honest_manifest()
    del manifest["cargo_lock_hash"]
    with pytest.raises(pe.ProxyGateRefusal) as status:
        pe.verify_manifest(manifest, proxy_sha=PROXY_SHA, run_id=RUN_ID,
                           run_attempt=RUN_ATTEMPT)
    cause, detail = _refusal_details(status)
    assert cause is pe.ProxyGateCause.PROXY_GATE_BYTES_REFUSED
    assert detail == "proxy manifest invalid: missing or extra manifest fields"


def test_bytes_manifest_extra_field_rejects():
    pe = _pe()
    manifest = _honest_manifest(role="ambiguous-second-role")
    with pytest.raises(pe.ProxyGateRefusal) as status:
        pe.verify_manifest(manifest, proxy_sha=PROXY_SHA, run_id=RUN_ID,
                           run_attempt=RUN_ATTEMPT)
    assert _refusal_details(status) == (
        pe.ProxyGateCause.PROXY_GATE_BYTES_REFUSED,
        "proxy manifest invalid: missing or extra manifest fields")


@pytest.mark.parametrize("path", ["../escape/shim.so", "/absolute/daemon",
                                  "bin/../../etc/x"])
def test_bytes_manifest_traversal_rejects(path):
    pe = _pe()
    manifest = _honest_manifest(daemon_path=path)
    with pytest.raises(pe.ProxyGateRefusal) as status:
        pe.verify_manifest(manifest, proxy_sha=PROXY_SHA, run_id=RUN_ID,
                           run_attempt=RUN_ATTEMPT)
    cause, detail = _refusal_details(status)
    assert cause is pe.ProxyGateCause.PROXY_GATE_BYTES_REFUSED
    if path.startswith("/"):
        assert detail == "proxy manifest invalid: absolute path in daemon_path"
    else:
        assert detail == "proxy manifest invalid: path traversal in daemon_path"


@pytest.mark.parametrize("overrides", [
    {"cli_path": "daemon.bin"},
    {"shim_path": "cli.bin"},
    {"daemon_path": "shim.bin"},
])
def test_bytes_manifest_overlapping_role_paths_reject(overrides):
    pe = _pe()
    manifest = _honest_manifest(**overrides)
    with pytest.raises(pe.ProxyGateRefusal) as status:
        pe.verify_manifest(manifest, proxy_sha=PROXY_SHA, run_id=RUN_ID,
                           run_attempt=RUN_ATTEMPT)
    assert _refusal_details(status) == (
        pe.ProxyGateCause.PROXY_GATE_BYTES_REFUSED,
        "proxy manifest invalid: role paths must be distinct")


def test_bytes_altered_payload_rejects(tmp_path):
    pe = _pe()
    manifest = _honest_manifest()
    altered = bytearray((FIXTURES / "shim.bin").read_bytes())
    altered[0] ^= 1
    (tmp_path / "daemon.bin").write_bytes((FIXTURES / "daemon.bin").read_bytes())
    (tmp_path / "cli.bin").write_bytes((FIXTURES / "cli.bin").read_bytes())
    (tmp_path / "shim.bin").write_bytes(bytes(altered))
    with pytest.raises(pe.ProxyGateRefusal) as status:
        pe.verify_payload_bytes(tmp_path, manifest)
    assert _refusal_details(status) == (
        pe.ProxyGateCause.PROXY_GATE_BYTES_REFUSED,
        "proxy payload hash mismatch: shim")


def test_bytes_truncated_payload_rejects(tmp_path):
    pe = _pe()
    manifest = _honest_manifest()
    (tmp_path / "daemon.bin").write_bytes(
        (FIXTURES / "daemon.bin").read_bytes()[:-1])
    (tmp_path / "cli.bin").write_bytes((FIXTURES / "cli.bin").read_bytes())
    (tmp_path / "shim.bin").write_bytes((FIXTURES / "shim.bin").read_bytes())
    with pytest.raises(pe.ProxyGateRefusal) as status:
        pe.verify_payload_bytes(tmp_path, manifest)
    assert _refusal_details(status) == (
        pe.ProxyGateCause.PROXY_GATE_BYTES_REFUSED,
        "proxy payload size mismatch: daemon")


def test_bytes_missing_payload_rejects(tmp_path):
    pe = _pe()
    manifest = _honest_manifest()
    (tmp_path / "daemon.bin").write_bytes((FIXTURES / "daemon.bin").read_bytes())
    (tmp_path / "cli.bin").write_bytes((FIXTURES / "cli.bin").read_bytes())
    with pytest.raises(pe.ProxyGateRefusal) as status:
        pe.verify_payload_bytes(tmp_path, manifest)
    assert _refusal_details(status) == (
        pe.ProxyGateCause.PROXY_GATE_BYTES_REFUSED,
        "proxy payload missing: shim")


@pytest.mark.parametrize("field,value", [
    ("source_commit", OTHER_SHA),
    ("run_id", RUN_ID + 1),
    ("run_attempt", RUN_ATTEMPT + 1),
])
def test_bytes_manifest_authority_crosscheck_rejects(field, value):
    """Metadata-over-manifest authority: self-assertion never wins."""
    pe = _pe()
    manifest = _honest_manifest(**{field: value})
    with pytest.raises(pe.ProxyGateRefusal) as status:
        pe.verify_manifest(manifest, proxy_sha=PROXY_SHA, run_id=RUN_ID,
                           run_attempt=RUN_ATTEMPT)
    assert _refusal_details(status) == (
        pe.ProxyGateCause.PROXY_GATE_BYTES_REFUSED,
        "proxy manifest mismatch: %s" % field)


@pytest.mark.parametrize("field", ["caller_repository_id",
                                   "caller_repository_full_name"])
def test_bytes_manifest_caller_mismatch_rejects(field):
    """Relabeling refuses: manifest caller IDs must match staged authority."""
    pe = _pe()
    manifest = _honest_manifest(**{field: "attacker-relabeled"})
    with pytest.raises(pe.ProxyGateRefusal) as status:
        pe.verify_manifest(manifest, proxy_sha=PROXY_SHA, run_id=RUN_ID,
                           run_attempt=RUN_ATTEMPT, authority=AUTHORITY)
    assert _refusal_details(status) == (
        pe.ProxyGateCause.PROXY_GATE_BYTES_REFUSED,
        "proxy manifest mismatch: %s" % field)


@pytest.mark.parametrize("size", [True, "30", 0, -4])
def test_bytes_manifest_noninteger_size_rejects(size):
    pe = _pe()
    manifest = _honest_manifest(daemon_size=size)
    with pytest.raises(pe.ProxyGateRefusal) as status:
        pe.verify_manifest(manifest, proxy_sha=PROXY_SHA, run_id=RUN_ID,
                           run_attempt=RUN_ATTEMPT)
    assert _refusal_details(status) == (
        pe.ProxyGateCause.PROXY_GATE_BYTES_REFUSED,
        "proxy manifest invalid: daemon_size must be a positive int")


# Digest agreement: manifest descriptions bound to claim/roster digests.
#
# Authority chain (steer-proven): API metadata (records + staged authority)
# binds WHICH artifact is under test; the manifest only DESCRIBES its
# bytes (integrity via rehash); these agreement checks bind the manifest's
# digest claims to the build claim (daemon) and client roster (shim/CLI),
# which the install/identity gates authenticate against the selected
# record. Within-side binding stays MS-safe: mixed mutants disagree
# across sides (caught at install/identity gates), never within.


def _recorded_manifest(daemon_record, client_record, **overrides):
    manifest = _honest_manifest()
    manifest["daemon_sha256"] = daemon_record["daemon"]["sha256"]
    manifest["cli_sha256"] = client_record["cli"]["sha256"]
    manifest["shim_sha256"] = client_record["shim"]["sha256"]
    manifest.update(overrides)
    return manifest


def test_bytes_digest_agreement_honest_passes():
    pe = _pe()
    record = _default_record()
    assert pe.verify_digest_agreement(
        _recorded_manifest(record, record),
        daemon_build=_daemon_claim(record),
        client_manifest=_client_manifest(record)) is None


@pytest.mark.parametrize("direction", ["dir-1", "dir-2"])
def test_bytes_digest_agreement_stays_ms_safe(direction):
    """Mixed sides agree within sides; install/identity gates own the mix."""
    pe = _pe()
    record_a = _default_record()
    record_b = _variant_record()
    if direction == "dir-1":
        manifest = _recorded_manifest(record_a, record_b)
        claim, roster = _daemon_claim(record_a), _client_manifest(record_b)
    else:
        manifest = _recorded_manifest(record_b, record_a)
        claim, roster = _daemon_claim(record_b), _client_manifest(record_a)
    assert pe.verify_digest_agreement(
        manifest, daemon_build=claim, client_manifest=roster) is None


def test_bytes_digest_agreement_daemon_claim_mismatch_rejects():
    pe = _pe()
    record = _default_record()
    manifest = _recorded_manifest(record, record, daemon_sha256="0" * 64)
    with pytest.raises(pe.ProxyGateRefusal) as status:
        pe.verify_digest_agreement(
            manifest, daemon_build=_daemon_claim(record),
            client_manifest=_client_manifest(record))
    assert _refusal_details(status) == (
        pe.ProxyGateCause.PROXY_GATE_BYTES_REFUSED,
        "proxy manifest mismatch: daemon_sha256")


@pytest.mark.parametrize("role", ["shim", "cli"])
def test_bytes_digest_agreement_roster_mismatch_rejects(role):
    pe = _pe()
    record = _default_record()
    manifest = _recorded_manifest(record, record, **{role + "_sha256": "0" * 64})
    with pytest.raises(pe.ProxyGateRefusal) as status:
        pe.verify_digest_agreement(
            manifest, daemon_build=_daemon_claim(record),
            client_manifest=_client_manifest(record))
    assert _refusal_details(status) == (
        pe.ProxyGateCause.PROXY_GATE_BYTES_REFUSED,
        "proxy manifest mismatch: %s_sha256" % role)


def test_bytes_digest_agreement_defers_malformed_claim():
    """A malformed build claim belongs to the identity gate, not bytes."""
    pe = _pe()
    record = _default_record()
    assert pe.verify_digest_agreement(
        _recorded_manifest(record, record), daemon_build={"garbage": True},
        client_manifest=_client_manifest(record)) is None


def test_bytes_digest_agreement_defers_malformed_roster():
    """A malformed client roster belongs to the install gate, not bytes."""
    pe = _pe()
    record = _default_record()
    assert pe.verify_digest_agreement(
        _recorded_manifest(record, record),
        daemon_build=_daemon_claim(record),
        client_manifest={"files": "not-a-list"}) is None


# Install gate (MS-B): native-client validation before any container.


def test_install_honest_manifest_passes():
    pe = _pe()
    record = _default_record()
    assert pe.check_install_gate(_client_manifest(record)) is not None


def test_install_ms_b_direction2_rejects_with_zero_containers(monkeypatch):
    """Direction 2 refuses in install; no engine may be constructed."""
    from p11lab import docker as docker_module

    def _exploding_docker(*args, **kwargs):
        raise AssertionError("gates must not construct a container engine")

    monkeypatch.setattr(docker_module, "Docker", _exploding_docker)
    pe = _pe()
    record_a = _default_record()
    record_b = _variant_record()
    with pytest.raises(pe.ProxyGateRefusal) as status:
        pe.check_install_gate(_client_manifest(record_a),
                              expected_proxy_identity=record_b)
    assert _refusal_details(status) == (
        pe.ProxyGateCause.PROXY_GATE_INSTALL_REFUSED,
        "proxy identity mismatch: client_manifest.identity.source_commit")


def _install_mutant(kind):
    record = _default_record()
    manifest = _client_manifest(record)
    proxy = manifest["source"]["proxy"]
    if kind == "role":
        manifest["role"] = "daemon"
    elif kind == "target":
        manifest["target"] = "other-target"
    elif kind == "module":
        manifest["module"] = "lib/other.so"
    elif kind == "host":
        manifest["host_requirements"] = {}
    elif kind == "identity-missing":
        del proxy["identity"]
    elif kind == "claim-drift":
        proxy["cli_sha256"] = "0" * 64
    elif kind == "abi-missing":
        del proxy["abi_observed"]
    elif kind == "roster-drift":
        manifest["files"][0]["sha256"] = "0" * 64
    else:  # pragma: no cover - parametrized idiom guard
        raise AssertionError("unknown install mutant: " + kind)
    return manifest


@pytest.mark.parametrize("kind,detail", [
    ("role", "native manifest does not match the client target/host requirements"),
    ("target", "native manifest does not match the client target/host requirements"),
    ("module", "native manifest does not match the client target/host requirements"),
    ("host", "native manifest does not match the client target/host requirements"),
    ("identity-missing", "native client proxy identity is missing"),
    ("claim-drift",
     "native client proxy claim differs from recorded identity: cli_sha256"),
    ("abi-missing", "native client proxy ABI observation is missing"),
    ("roster-drift", "native client component bytes differ from declared proxy"),
])
def test_install_mutants_reject_with_exact_texts(kind, detail):
    pe = _pe()
    with pytest.raises(pe.ProxyGateRefusal) as status:
        pe.check_install_gate(_install_mutant(kind))
    assert _refusal_details(status) == (
        pe.ProxyGateCause.PROXY_GATE_INSTALL_REFUSED, detail)


# Identity gate (MS-A): daemon/client/record sameness at the check gate.


def test_identity_honest_material_passes():
    pe = _pe()
    record = _default_record()
    claim = _daemon_claim(record)
    binding = pe.check_identity_gate(
        claim, _client_manifest(record),
        launch_rehashes=_launch_rehashes(record),
        abi_observed=_client_abi(record), daemon_image=_daemon_image())
    assert binding == claim


def test_identity_ms_a_direction1_rejects():
    """Direction 1 refuses at the check gate (daemon-A claim, selected B)."""
    pe = _pe()
    record_a = _default_record()
    record_b = _variant_record()
    with pytest.raises(pe.ProxyGateRefusal) as status:
        pe.check_identity_gate(
            _daemon_claim(record_a), _client_manifest(record_b),
            launch_rehashes=_launch_rehashes(record_b),
            abi_observed=_client_abi(record_b), daemon_image=_daemon_image(),
            expected_proxy_identity=record_b)
    assert _refusal_details(status) == (
        pe.ProxyGateCause.PROXY_GATE_IDENTITY_REFUSED,
        "proxy identity mismatch: daemon.source_revision")


def test_identity_daemon_image_naming_mismatch_rejects():
    pe = _pe()
    record = _default_record()
    with pytest.raises(pe.ProxyGateRefusal) as status:
        pe.check_identity_gate(
            _daemon_claim(record), _client_manifest(record),
            launch_rehashes=_launch_rehashes(record),
            abi_observed=_client_abi(record),
            daemon_image=_daemon_image(observed="sha256:" + "0" * 64))
    assert _refusal_details(status) == (
        pe.ProxyGateCause.PROXY_GATE_IDENTITY_REFUSED,
        "proxy identity mismatch: daemon_image.observed")


def test_identity_wrong_parent_naming_rejects():
    """WP at naming level: recorded provider_parent differs from selected."""
    pe = _pe()
    record_b = _variant_record()
    wrong = _variant_record()
    wrong["provider_parent"] = {
        "family": "wrong-provider", "platform": "linux/amd64",
        "manifest_digest": "1" * 64, "config_digest": "2" * 64}
    with pytest.raises(pe.ProxyGateRefusal) as status:
        pe.check_identity_gate(
            _daemon_claim(record_b), _client_manifest(wrong),
            launch_rehashes=_launch_rehashes(record_b),
            abi_observed=_client_abi(record_b), daemon_image=_daemon_image(),
            expected_proxy_identity=record_b)
    cause, detail = _refusal_details(status)
    assert cause is pe.ProxyGateCause.PROXY_GATE_IDENTITY_REFUSED
    assert detail == ("proxy identity mismatch: "
                      "client_manifest.identity.provider_parent")


def test_identity_staged_abi_must_match_manifest_recorded():
    """The separately staged ABI observation must agree with the manifest.

    check_proxy_identities reads abi_observed from the client manifest;
    without this agreement check a divergent staged file would be
    silently ignored.
    """
    pe = _pe()
    record_b = _variant_record()
    staged_abi = _client_abi(record_b)
    staged_abi["shim_exports"] = ["C_ForgedExport"]
    with pytest.raises(pe.ProxyGateRefusal) as status:
        pe.check_identity_gate(
            _daemon_claim(record_b), _client_manifest(record_b),
            launch_rehashes=_launch_rehashes(record_b),
            abi_observed=staged_abi,
            daemon_image=_daemon_image(),
            expected_proxy_identity=record_b)
    assert _refusal_details(status) == (
        pe.ProxyGateCause.PROXY_GATE_IDENTITY_REFUSED,
        "proxy identity actual invalid: "
        "staged abi_observed differs from client manifest")


def test_identity_malformed_manifest_defers_to_library():
    pe = _pe()
    record = _default_record()
    with pytest.raises(pe.ProxyGateRefusal) as status:
        pe.check_identity_gate(
            _daemon_claim(record), {"not": "a manifest"},
            launch_rehashes=_launch_rehashes(record),
            abi_observed=_client_abi(record),
            daemon_image=_daemon_image())
    cause, detail = _refusal_details(status)
    assert cause is pe.ProxyGateCause.PROXY_GATE_IDENTITY_REFUSED
    assert detail == ("proxy identity actual invalid: client_manifest requires "
                      "a recorded abi_observed")


@pytest.mark.parametrize("role", ["shim", "cli"])
def test_identity_altered_launch_rehashes_reject(role):
    pe = _pe()
    record = _default_record()
    rehashes = _launch_rehashes(record)
    rehashes[role + "_sha256"] = "0" * 64
    with pytest.raises(pe.ProxyGateRefusal) as status:
        pe.check_identity_gate(
            _daemon_claim(record), _client_manifest(record),
            launch_rehashes=rehashes, abi_observed=_client_abi(record),
            daemon_image=_daemon_image())
    assert _refusal_details(status) == (
        pe.ProxyGateCause.PROXY_GATE_IDENTITY_REFUSED,
        "proxy identity mismatch: launch_rehashes.%s_sha256" % role)


# Derivative gate (WP): install/derivative binding without Docker.


def test_derivative_honest_binding_passes():
    pe = _pe()
    selection = _parent_selection()
    binding = pe.check_derivative_gate(
        parent_ref=selection["local_engine_id"],
        child_inspection=_child_inspection())
    assert binding["child_layers_prefix_ok"] is True
    assert binding["manifest_digest"] == selection["manifest_digest"]


def test_derivative_parent_ref_mismatch_matches_build_order_text(tmp_path):
    """Build-order refusal text is byte-identical to the real builder gate."""
    pe = _pe()
    try:
        derivative_module.build_proxy_derivative(
            parent_ref="sha256:" + "0" * 64, products={}, notices={},
            build_args={}, output=tmp_path / "unused", engine=object())
    except ValueError as error:
        builder_text = str(error)
    else:  # pragma: no cover - builder must refuse first
        raise AssertionError("real builder accepted a wrong parent_ref")
    assert builder_text == "proxy derivative build mismatch: parent_ref"
    assert not (tmp_path / "unused").exists()
    with pytest.raises(pe.ProxyGateRefusal) as status:
        pe.check_derivative_gate(parent_ref="sha256:" + "0" * 64,
                                 child_inspection=_child_inspection())
    assert _refusal_details(status) == (
        pe.ProxyGateCause.PROXY_GATE_DERIVATIVE_REFUSED, builder_text)


def test_derivative_child_prefix_mismatch_rejects():
    pe = _pe()
    layers = list(_parent_selection()["layers"])
    layers[0] = "sha256:" + "0" * 64
    with pytest.raises(pe.ProxyGateRefusal) as status:
        pe.check_derivative_gate(
            parent_ref=_parent_selection()["local_engine_id"],
            child_inspection=_child_inspection(layers=layers))
    assert _refusal_details(status) == (
        pe.ProxyGateCause.PROXY_GATE_DERIVATIVE_REFUSED,
        "proxy derivative parent mismatch: child.RootFS.Layers")


# Chain: gated material or typed refusal rows (cells/verdict/capsule are P1b).


def _execute(artifact, run_id=RUN_ID, attempt=RUN_ATTEMPT, output_dir=None,
             output_json=None, **kwargs):
    pe = _pe()
    output_dir = Path(output_dir)
    output_json = Path(output_json)
    return pe.execute_proxy(artifact, run_id=run_id, run_attempt=attempt,
                            output_dir=output_dir, output_json=output_json,
                            **kwargs)


def test_chain_honest_artifact_gates_with_pending_verdict(tmp_path):
    staged = _stage_artifact(tmp_path, _honest_name())
    row = _execute(staged, output_dir=tmp_path / "out",
                   output_json=tmp_path / "row.json")
    assert row["lane"] == "proxy"
    assert row["phase"] == "gated"
    assert row["status"] == "gated"
    assert row["cause"] == "PROXY_GATE_OK"
    assert row["cause_detail"] is None
    assert row["exit_code"] == 0
    assert row["experiment_positive"] is False
    assert row["image_usable"] is False
    assert row["evidence_complete"] is False
    assert row["evidence_admitted"] is False
    assert row["comparison_positive"] is None
    assert row["cells"] == {"direct": "not-run", "accepted-proxy": "not-run",
                            "candidate-proxy": "not-run"}
    assert row["verdict"] == "pending"
    assert row["verdict_mirror"] is None
    assert [entry["gate"] for entry in row["gates"]] == [
        "selection", "bytes", "install", "identity", "derivative"]
    assert all(entry["cause"] == "PROXY_GATE_OK" for entry in row["gates"])
    assert row["selection"]["sha"] == _default_record()["source_commit"]
    assert row["selection"]["run_id"] == RUN_ID
    assert row["limitations"] != []
    assert (tmp_path / "out").is_dir()
    assert list((tmp_path / "out").iterdir()) == []
    assert _read_json(tmp_path / "row.json") == row


def _chain_mutant(kind, tmp_path):
    """Stage one artifact whose first refusal is the requested gate."""
    record_a = _synthetic(_default_record())
    record_b = _synthetic(_variant_record())
    name = _honest_name()
    if kind == "selection":
        return _stage_artifact(tmp_path, name, records=[])
    if kind == "bytes":
        manifest = _read_json(FIXTURES / "manifest.json")
        manifest["source_commit"] = record_a["source_commit"]
        manifest["run_id"] = RUN_ID + 1
        manifest["run_attempt"] = RUN_ATTEMPT
        return _stage_artifact(tmp_path, name, manifest=manifest)
    if kind == "install":
        return _stage_artifact(
            tmp_path, name, daemon_build=_daemon_claim(record_b),
            client_manifest=_client_manifest(record_a),
            rehashes=_launch_rehashes(record_b), abi=_client_abi(record_b))
    if kind == "identity":
        manifest = _client_manifest(record_b)
        return _stage_artifact(
            tmp_path, name, daemon_build=_daemon_claim(record_a),
            client_manifest=manifest, rehashes=_launch_rehashes(record_b),
            abi=_client_abi(record_b))
    assert kind == "derivative"
    return _stage_artifact(tmp_path, name, parent_ref="sha256:" + "0" * 64)


@pytest.mark.parametrize("kind,cause,phase,detail", [
    ("selection", "PROXY_GATE_SELECTION_REFUSED", "selection",
     "rerun_requires_producer or ambiguous artifact"),
    ("bytes", "PROXY_GATE_BYTES_REFUSED", "bytes",
     "proxy manifest mismatch: run_id"),
    ("install", "PROXY_GATE_INSTALL_REFUSED", "install",
     "proxy identity mismatch: client_manifest.identity.source_commit"),
    ("identity", "PROXY_GATE_IDENTITY_REFUSED", "identity",
     "proxy identity mismatch: daemon.source_revision"),
    ("derivative", "PROXY_GATE_DERIVATIVE_REFUSED", "derivative",
     "proxy derivative build mismatch: parent_ref"),
])
def test_chain_refusals_return_typed_rows(kind, cause, phase, detail, tmp_path):
    staged = _chain_mutant(kind, tmp_path)
    kwargs = {}
    if kind in ("install", "identity"):
        kwargs["expected_proxy_identity"] = _synthetic(_variant_record())
    row = _execute(staged, output_dir=tmp_path / "out",
                   output_json=tmp_path / "row.json", **kwargs)
    assert row["phase"] == phase
    assert row["status"] == "refused"
    assert row["cause"] == cause
    assert row["cause_detail"] == detail
    assert row["exit_code"] == 1
    assert row["experiment_positive"] is False
    assert row["evidence_complete"] is False
    assert row["verdict"] == "pending"
    assert row["verdict_mirror"] == {"typed_cause": "missing-evidence",
                                     "exit_code": 1}
    assert row["gates"][-1] == {"gate": phase, "cause": cause,
                                "cause_detail": detail}
    assert _read_json(tmp_path / "row.json") == row


def test_chain_malformed_artifact_name_refuses(tmp_path):
    staged = _stage_artifact(tmp_path, "not-a-proxy-artifact")
    row = _execute(staged, output_dir=tmp_path / "out",
                   output_json=tmp_path / "row.json")
    assert row["cause"] == "PROXY_GATE_SELECTION_REFUSED"
    assert row["cause_detail"] == ("malformed proxy artifact name: "
                                   "not-a-proxy-artifact")
    assert row["exit_code"] == 1
    assert row["experiment_positive"] is False


def test_chain_invoked_attempt_must_match_name(tmp_path):
    staged = _stage_artifact(tmp_path, _honest_name())
    row = _execute(staged, attempt=RUN_ATTEMPT + 1,
                   output_dir=tmp_path / "out",
                   output_json=tmp_path / "row.json")
    assert row["cause"] == "PROXY_GATE_SELECTION_REFUSED"
    assert row["cause_detail"] == (
        "proxy artifact mismatch: invoked attempt %d != artifact attempt %d"
        % (RUN_ATTEMPT + 1, RUN_ATTEMPT))
    assert row["exit_code"] == 1


def test_chain_self_consistent_byte_swap_rejects(tmp_path):
    """A swapped shim (+matching manifest edit) disagrees with the roster."""
    manifest = _read_json(FIXTURES / "manifest.json")
    manifest["source_commit"] = _default_record()["source_commit"]
    manifest["run_id"] = RUN_ID
    manifest["run_attempt"] = RUN_ATTEMPT
    swapped = bytearray((FIXTURES / "shim.bin").read_bytes())
    swapped[0] ^= 1
    manifest["shim_sha256"] = hashlib.sha256(bytes(swapped)).hexdigest()
    assert manifest["shim_size"] == len(bytes(swapped))
    payloads = {"daemon.bin": (FIXTURES / "daemon.bin").read_bytes(),
                "cli.bin": (FIXTURES / "cli.bin").read_bytes(),
                "shim.bin": bytes(swapped)}
    staged = _stage_artifact(tmp_path, _honest_name(), manifest=manifest,
                             payloads=payloads)
    row = _execute(staged, output_dir=tmp_path / "out",
                   output_json=tmp_path / "row.json")
    assert row["cause"] == "PROXY_GATE_BYTES_REFUSED"
    assert row["cause_detail"] == "proxy manifest mismatch: shim_sha256"
    assert row["exit_code"] == 1


def test_chain_default_expected_rejects_fixture_roster(tmp_path):
    """Without staged expected identity, fixture digests refuse (fail-closed).

    No preimage shortcut exists: fixture bytes cannot match the pinned
    default digests, so the default path must refuse loudly, never pass.
    """
    staged = _stage_artifact(tmp_path, _honest_name(),
                             omit=("expected_identity.json",))
    row = _execute(staged, output_dir=tmp_path / "out",
                   output_json=tmp_path / "row.json")
    assert row["cause"] == "PROXY_GATE_INSTALL_REFUSED"
    assert row["cause_detail"] == ("proxy identity mismatch: "
                                   "client_manifest.identity.daemon")
    assert row["exit_code"] == 1
    assert row["experiment_positive"] is False


def test_chain_explicit_expected_overrides_staged(tmp_path):
    staged = _stage_artifact(tmp_path, _honest_name())
    staged_expected = _read_json(staged / "expected_identity.json")
    assert staged_expected["source_commit"] == _default_record()["source_commit"]
    row = _execute(staged, output_dir=tmp_path / "out",
                   output_json=tmp_path / "row.json",
                   expected_proxy_identity=_synthetic(_variant_record()))
    assert row["cause"] == "PROXY_GATE_INSTALL_REFUSED"
    assert row["cause_detail"] == ("proxy identity mismatch: "
                                   "client_manifest.identity.source_commit")


def test_chain_missing_authority_raises_as_usage(tmp_path):
    pe = _pe()
    staged = _stage_artifact(tmp_path, _honest_name(), omit=("authority.json",))
    with pytest.raises(ValueError, match="authority.json is missing"):
        pe.execute_proxy(staged, run_id=RUN_ID, run_attempt=RUN_ATTEMPT,
                         output_dir=tmp_path / "out",
                         output_json=tmp_path / "row.json")


def test_chain_malformed_expected_identity_raises_as_usage(tmp_path):
    pe = _pe()
    staged = _stage_artifact(tmp_path, _honest_name(),
                             expected_identity={"not": "a record"})
    with pytest.raises(ValueError, match="not a valid identity record"):
        pe.execute_proxy(staged, run_id=RUN_ID, run_attempt=RUN_ATTEMPT,
                         output_dir=tmp_path / "out",
                         output_json=tmp_path / "row.json")


def test_chain_stale_output_dir_raises_without_row(tmp_path):
    pe = _pe()
    staged = _stage_artifact(tmp_path, _honest_name())
    output_dir = tmp_path / "out"
    output_dir.mkdir()
    with pytest.raises(OSError):
        pe.execute_proxy(staged, run_id=RUN_ID, run_attempt=RUN_ATTEMPT,
                         output_dir=output_dir,
                         output_json=tmp_path / "row.json")
    assert not (tmp_path / "row.json").exists()


def test_chain_missing_artifact_dir_raises(tmp_path):
    pe = _pe()
    with pytest.raises(ValueError, match="proxy artifact is missing"):
        pe.execute_proxy(tmp_path / "absent", run_id=RUN_ID,
                         run_attempt=RUN_ATTEMPT, output_dir=tmp_path / "out",
                         output_json=tmp_path / "row.json")


def test_chain_invalid_json_raises_as_usage(tmp_path):
    pe = _pe()
    staged = _stage_artifact(tmp_path, _honest_name())
    (staged / "records.json").write_text("{invalid", encoding="utf-8")
    with pytest.raises(ValueError, match="records.json is not valid JSON"):
        pe.execute_proxy(staged, run_id=RUN_ID, run_attempt=RUN_ATTEMPT,
                         output_dir=tmp_path / "out",
                         output_json=tmp_path / "row.json")


@pytest.mark.parametrize("run_id,attempt", [(0, 1), (1, 0), (-3, 2), (5, -1)])
def test_chain_nonpositive_ids_raise_as_usage(tmp_path, run_id, attempt):
    pe = _pe()
    staged = _stage_artifact(tmp_path, _honest_name())
    with pytest.raises(ValueError, match="run identity must be positive"):
        pe.execute_proxy(staged, run_id=run_id, run_attempt=attempt,
                         output_dir=tmp_path / "out",
                         output_json=tmp_path / "row.json")


def test_chain_production_imports_no_test_modules():
    """Static pin: the gate chain never imports from tests (fail-back rule)."""
    root = Path(__file__).resolve().parent.parent
    source = (root / "src" / "p11lab" / "round_core"
              / "proxy_execute.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            modules = [node.module or ""]
        else:
            continue
        for module in modules:
            segments = module.split(".")
            assert not any(segment == "tests" or segment.startswith("test_")
                           for segment in segments), module


# CLI: proxy execute registration + verdict-mirrored exits.


def test_cli_execute_honest_returns_zero(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    staged = _stage_artifact(tmp_path, _honest_name())
    code = main(["proxy", "execute", "--artifact", str(staged),
                 "--run-id", str(RUN_ID), "--attempt", str(RUN_ATTEMPT),
                 "--output-dir", "out", "--output-json", "row.json"])
    assert code == 0
    row = _read_json(tmp_path / "row.json")
    assert row["exit_code"] == 0
    assert json.loads(capsys.readouterr().out)["exit_code"] == 0


def test_cli_execute_refusal_returns_one(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    staged = _stage_artifact(tmp_path, _honest_name(), records=[])
    code = main(["proxy", "execute", "--artifact", str(staged),
                 "--run-id", str(RUN_ID), "--attempt", str(RUN_ATTEMPT),
                 "--output-dir", "out", "--output-json", "row.json"])
    assert code == 1
    row = _read_json(tmp_path / "row.json")
    assert row["cause"] == "PROXY_GATE_SELECTION_REFUSED"
    assert row["experiment_positive"] is False
    assert "PROXY_GATE_SELECTION_REFUSED" in capsys.readouterr().out


def test_cli_execute_mixed_shim_reaches_identity_gate(tmp_path, monkeypatch,
                                                      capsys):
    """The CLI exercises deep gates: staged MS-A refuses with identity text."""
    monkeypatch.chdir(tmp_path)
    record_a = _synthetic(_default_record())
    record_b = _synthetic(_variant_record())
    staged = _stage_artifact(
        tmp_path, _honest_name(), daemon_build=_daemon_claim(record_a),
        client_manifest=_client_manifest(record_b),
        rehashes=_launch_rehashes(record_b), abi=_client_abi(record_b),
        expected_identity=record_b)
    code = main(["proxy", "execute", "--artifact", str(staged),
                 "--run-id", str(RUN_ID), "--attempt", str(RUN_ATTEMPT),
                 "--output-dir", "out", "--output-json", "row.json"])
    assert code == 1
    row = _read_json(tmp_path / "row.json")
    assert row["cause"] == "PROXY_GATE_IDENTITY_REFUSED"
    assert row["cause_detail"] == "proxy identity mismatch: daemon.source_revision"
    assert "daemon.source_revision" in capsys.readouterr().out


def test_cli_execute_missing_flag_exits_two(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit) as status:
        main(["proxy", "execute", "--artifact", "a"])
    assert status.value.code == 2


def test_cli_execute_stale_output_dir_exits_two(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    staged = _stage_artifact(tmp_path, _honest_name())
    (tmp_path / "out").mkdir()
    code = main(["proxy", "execute", "--artifact", str(staged),
                 "--run-id", str(RUN_ID), "--attempt", str(RUN_ATTEMPT),
                 "--output-dir", "out", "--output-json", "row.json"])
    assert code == 2
    assert "p11lab: " in capsys.readouterr().err


def test_cli_execute_nonpositive_attempt_exits_two(tmp_path, monkeypatch,
                                                   capsys):
    monkeypatch.chdir(tmp_path)
    staged = _stage_artifact(tmp_path, _honest_name())
    code = main(["proxy", "execute", "--artifact", str(staged),
                 "--run-id", str(RUN_ID), "--attempt", "0",
                 "--output-dir", "out", "--output-json", "row.json"])
    assert code == 2
    assert "run identity must be positive" in capsys.readouterr().err


# Docs: the operational section states the gate contract.


def test_docs_operational_section_states_gate_contract():
    root = Path(__file__).resolve().parent.parent
    text = (root / "docs" / "proxy-ci.md").read_text(encoding="utf-8")
    for phrase in ("p11lab proxy execute",
                   "PROXY_GATE_SELECTION_REFUSED",
                   "PROXY_GATE_BYTES_REFUSED",
                   "PROXY_GATE_INSTALL_REFUSED",
                   "PROXY_GATE_IDENTITY_REFUSED",
                   "PROXY_GATE_DERIVATIVE_REFUSED",
                   "missing-evidence",
                   "experiment_positive stays false",
                   "cells+verdict+capsule"):
        assert phrase in text, "doc states " + phrase
