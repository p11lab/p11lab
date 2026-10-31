"""Same-run proxy artifact gates: selection -> bytes -> install/identity/derivative.

P1a ends here: this module admits caller-built material to (future) cells
or refuses it with a typed cause and the exact gate text. It never runs a
cell, never computes a verdict, never writes a capsule (P1b owns cells,
verdict, and capsule), never builds a candidate (caller-built only per
the M05 boundary), and never touches Docker or the network.

Promotion note: same-run selection, the caller-manifest roster, and byte
verification are re-implemented here from the test-only precedent. This
module must never import from tests. Identity, install, and derivative
gates reuse the owning libraries (run/proxy_inputs, native,
proxy_derivative) unmodified, so their refusal texts are byte-exact by
construction.

Digest authority chain (root-steer proven): API metadata (the staged
records listing plus the staged authority bind) selects WHICH artifact is
under test; the caller manifest only DESCRIBES its bytes (integrity via
per-record rehash in the verify_proxy_payload idiom); digest agreement
binds the manifest's digest claims to the build claim (daemon) and the
client roster (shim/CLI); the install/identity gates authenticate those
claims against the selected record. Within-side binding stays MS-safe:
mixed-shim mutants disagree across sides (caught with library texts at
the install/identity gates), never within.

Execution boundary: every gate is inert validation over caller-staged
bytes and observations. Preflight, install, build, and run entry points
execute and are forbidden here; P1b execution rehashes installed bytes.
"""
from __future__ import annotations

from enum import Enum
from pathlib import Path
import hashlib
import json
import re
from typing import Any

from .. import native as _native
from .. import run as _run
from ..jsonutil import loads as _strict_json_loads
from ..models import ProxyBuildIdentityV1
from ..proxy_derivative import load_parent_selection, verify_derivative_parent
from ..tool_downloads import safe_directory
# P1b additions (appended; the P1a import block above is byte-untouched).
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

from ..proxy_policy import evaluate_proxy_verdict, load_proxy_policy
from .inputs import canonical
# P1c additions (appended; the P1a/P1b import blocks above are byte-untouched).
from .. import bundle as _bundle
from ..models import ArtifactRef, RunSpec

ARTIFACT_PREFIX = "p11lab-proxy-dist-"
_ARTIFACT_RE = re.compile(r"p11lab-proxy-dist-([0-9a-f]{40})-([1-9][0-9]*)\Z")
_SHA1_RE = re.compile(r"[0-9a-f]{40}\Z")
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_JSON_LIMIT = 1024 * 1024

# Promoted caller-manifest roster (design L342-346): exact, closed, pinned.
MANIFEST_FIELDS = frozenset({
    "schema_version", "caller_repository_id", "caller_repository_full_name",
    "source_commit", "source_tree", "source_archive_hash", "run_id",
    "run_attempt", "build_job_id", "cargo_lock_hash", "rustc_identity",
    "protoc_identity", "toolchain_identities", "target", "features", "flags",
    "dependency_closure", "vendored_closure", "daemon_path", "daemon_size",
    "daemon_sha256", "cli_path", "cli_size", "cli_sha256", "shim_path",
    "shim_size", "shim_sha256", "config_hashes", "hook_hashes",
    "build_context_digest",
})

_AUTHORITY_KEYS = ("repository_id", "repository_full_name", "producer_job_id",
                   "artifact_id")
_ROLES = ("daemon", "cli", "shim")

_LIMITATIONS = (
    "proxy gates only: no cell executed, no verdict computed, no capsule "
    "written; cells+verdict+capsule belong to P1b",
    "caller-built material only: no candidate build, no retries, "
    "no cross-run lookup",
)


class ProxyGateCause(str, Enum):
    """Closed refusal vocabulary for the P1a gate chain."""

    PROXY_GATE_OK = "PROXY_GATE_OK"
    PROXY_GATE_SELECTION_REFUSED = "PROXY_GATE_SELECTION_REFUSED"
    PROXY_GATE_BYTES_REFUSED = "PROXY_GATE_BYTES_REFUSED"
    PROXY_GATE_INSTALL_REFUSED = "PROXY_GATE_INSTALL_REFUSED"
    PROXY_GATE_IDENTITY_REFUSED = "PROXY_GATE_IDENTITY_REFUSED"
    PROXY_GATE_DERIVATIVE_REFUSED = "PROXY_GATE_DERIVATIVE_REFUSED"


PROXY_GATE_STATUS: dict[ProxyGateCause, str] = {
    ProxyGateCause.PROXY_GATE_OK: "gated",
    ProxyGateCause.PROXY_GATE_SELECTION_REFUSED: "refused",
    ProxyGateCause.PROXY_GATE_BYTES_REFUSED: "refused",
    ProxyGateCause.PROXY_GATE_INSTALL_REFUSED: "refused",
    ProxyGateCause.PROXY_GATE_IDENTITY_REFUSED: "refused",
    ProxyGateCause.PROXY_GATE_DERIVATIVE_REFUSED: "refused",
}

# Verdict mirror (binding): every gate refusal exits 1, coherent with the
# T6 missing-evidence verdict P1b would emit for unrun cells. Usage errors
# raise instead and the CLI reports exit 2 (T8 shape).
PROXY_GATE_EXIT: dict[ProxyGateCause, int] = {
    ProxyGateCause.PROXY_GATE_OK: 0,
    ProxyGateCause.PROXY_GATE_SELECTION_REFUSED: 1,
    ProxyGateCause.PROXY_GATE_BYTES_REFUSED: 1,
    ProxyGateCause.PROXY_GATE_INSTALL_REFUSED: 1,
    ProxyGateCause.PROXY_GATE_IDENTITY_REFUSED: 1,
    ProxyGateCause.PROXY_GATE_DERIVATIVE_REFUSED: 1,
}

VERDICT_MIRROR_REFUSED = {"typed_cause": "missing-evidence", "exit_code": 1}

_GATE_BY_CAUSE = {
    ProxyGateCause.PROXY_GATE_SELECTION_REFUSED: "selection",
    ProxyGateCause.PROXY_GATE_BYTES_REFUSED: "bytes",
    ProxyGateCause.PROXY_GATE_INSTALL_REFUSED: "install",
    ProxyGateCause.PROXY_GATE_IDENTITY_REFUSED: "identity",
    ProxyGateCause.PROXY_GATE_DERIVATIVE_REFUSED: "derivative",
}


class ProxyGateRefusal(Exception):
    """One typed gate refusal; the chain catches it into a row, never escapes."""

    def __init__(self, cause: ProxyGateCause, detail: str) -> None:
        super().__init__("%s: %s" % (cause.value, detail))
        self.cause = cause
        self.detail = detail


def expected_artifact_name(proxy_sha: str, run_attempt: int) -> str:
    """Return the same-run artifact name for one SHA/attempt pair."""
    if not isinstance(proxy_sha, str) or _SHA1_RE.fullmatch(proxy_sha) is None:
        raise ValueError("proxy artifact sha must be 40 hex")
    if type(run_attempt) is not int or run_attempt < 1:
        raise ValueError("proxy artifact attempt must be a positive int")
    return "%s%s-%d" % (ARTIFACT_PREFIX, proxy_sha, run_attempt)


def parse_artifact_name(name: str) -> tuple[str, int]:
    """Split a claimed artifact name, refusing malformed names with a row."""
    match = _ARTIFACT_RE.fullmatch(name) if isinstance(name, str) else None
    if match is None:
        raise ProxyGateRefusal(ProxyGateCause.PROXY_GATE_SELECTION_REFUSED,
                               "malformed proxy artifact name: %s" % (name,))
    return match.group(1), int(match.group(2))


def require_attempt_binding(name_attempt: int, run_attempt: int) -> None:
    """Refuse when the invoked attempt disagrees with the artifact name."""
    if name_attempt != run_attempt:
        raise ProxyGateRefusal(
            ProxyGateCause.PROXY_GATE_SELECTION_REFUSED,
            "proxy artifact mismatch: invoked attempt %d != artifact attempt %d"
            % (run_attempt, name_attempt))


def _checked_authority(authority: Any) -> dict[str, Any]:
    """Require the staged API-metadata authority bind (exact keys + types)."""
    if (type(authority) is not dict or set(authority) != set(_AUTHORITY_KEYS)
            or type(authority.get("repository_id")) is not int
            or type(authority.get("artifact_id")) is not int
            or not isinstance(authority.get("repository_full_name"), str)
            or not authority["repository_full_name"]
            or not isinstance(authority.get("producer_job_id"), str)
            or not authority["producer_job_id"]):
        raise ValueError("proxy authority must bind {repository_id, "
                         "repository_full_name, producer_job_id, artifact_id}")
    assert isinstance(authority, dict)
    return authority


def _is_current(row: Any, authority: dict[str, Any], proxy_sha: str,
                run_id: int, run_attempt: int) -> bool:
    """Match one listing row against the current-run current-attempt bind."""
    if type(row) is not dict:
        return False
    assert isinstance(row, dict)
    name = row.get("name")
    if not isinstance(name, str):
        return False
    match = _ARTIFACT_RE.fullmatch(name)
    if match is None or match.group(1) != proxy_sha:
        return False
    if int(match.group(2)) != run_attempt:
        return False
    if type(row.get("sha")) is not str or row["sha"] != proxy_sha:
        return False
    for key, want in (("run_id", run_id), ("run_attempt", run_attempt),
                      ("repository_id", authority["repository_id"]),
                      ("artifact_id", authority["artifact_id"])):
        if type(row.get(key)) is not int or row[key] != want:
            return False
    for key in ("repository_full_name", "producer_job_id"):
        if not isinstance(row.get(key), str) or row[key] != authority[key]:
            return False
    return True


def select_same_run(records: list[dict[str, Any]], authority: dict[str, Any],
                    proxy_sha: str, run_id: int,
                    run_attempt: int) -> dict[str, Any]:
    """Select the one current-run current-attempt artifact record.

    Promoted from the test-only precedent: same-run binding only, no
    cross-run lookup, metadata-over-manifest authority. Zero or duplicate
    matches refuse with the shared rerun text (full reruns only: a partial
    rerun lacking a current producer never selects).
    """
    if type(records) is not list:
        raise ValueError("proxy artifact records must be a list")
    assert isinstance(records, list)
    authority = _checked_authority(authority)
    matches = [row for row in records
               if _is_current(row, authority, proxy_sha, run_id, run_attempt)]
    if len(matches) != 1:
        raise ProxyGateRefusal(ProxyGateCause.PROXY_GATE_SELECTION_REFUSED,
                               "rerun_requires_producer or ambiguous artifact")
    return matches[0]


def verify_manifest(manifest: dict[str, Any], *, proxy_sha: str, run_id: int,
                    run_attempt: int,
                    authority: dict[str, Any] | None = None) -> dict[str, Any]:
    """Validate the caller-manifest roster, paths, and authority cross-checks.

    The manifest's self-assertion never wins: source/run/attempt/caller
    IDs must equal the metadata bind, else the manifest mismatches.
    """
    if type(manifest) is not dict:
        raise ValueError("proxy manifest must be a mapping")
    assert isinstance(manifest, dict)
    if set(manifest) != MANIFEST_FIELDS:
        raise ProxyGateRefusal(ProxyGateCause.PROXY_GATE_BYTES_REFUSED,
                               "proxy manifest invalid: "
                               "missing or extra manifest fields")
    for key in sorted(manifest):
        value = manifest[key]
        if key.endswith("_path"):
            if not isinstance(value, str) or not value:
                raise ProxyGateRefusal(
                    ProxyGateCause.PROXY_GATE_BYTES_REFUSED,
                    "proxy manifest invalid: %s must be a relative path" % key)
            if value.startswith("/"):
                raise ProxyGateRefusal(
                    ProxyGateCause.PROXY_GATE_BYTES_REFUSED,
                    "proxy manifest invalid: absolute path in %s" % key)
            if ".." in value.split("/"):
                raise ProxyGateRefusal(
                    ProxyGateCause.PROXY_GATE_BYTES_REFUSED,
                    "proxy manifest invalid: path traversal in %s" % key)
        if key.endswith("_sha256"):
            if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
                raise ProxyGateRefusal(
                    ProxyGateCause.PROXY_GATE_BYTES_REFUSED,
                    "proxy manifest invalid: %s must be 64 hex" % key)
    for role in _ROLES:
        size = manifest[role + "_size"]
        if type(size) is not int or size <= 0:
            raise ProxyGateRefusal(
                ProxyGateCause.PROXY_GATE_BYTES_REFUSED,
                "proxy manifest invalid: %s_size must be a positive int" % role)
    roles = (manifest["daemon_path"], manifest["cli_path"], manifest["shim_path"])
    if len(set(roles)) != 3:
        raise ProxyGateRefusal(ProxyGateCause.PROXY_GATE_BYTES_REFUSED,
                               "proxy manifest invalid: role paths must be distinct")
    for key, want in (("source_commit", proxy_sha), ("run_id", run_id),
                      ("run_attempt", run_attempt)):
        if manifest[key] != want:
            raise ProxyGateRefusal(ProxyGateCause.PROXY_GATE_BYTES_REFUSED,
                                   "proxy manifest mismatch: %s" % key)
    if authority is not None:
        for manifest_key, auth_key in (
                ("caller_repository_id", "repository_id"),
                ("caller_repository_full_name", "repository_full_name")):
            if manifest[manifest_key] != authority[auth_key]:
                raise ProxyGateRefusal(
                    ProxyGateCause.PROXY_GATE_BYTES_REFUSED,
                    "proxy manifest mismatch: %s" % manifest_key)
    return manifest


def verify_payload_bytes(payload_root: Path,
                         manifest: dict[str, Any]) -> dict[str, str]:
    """Rehash staged payload bytes against the manifest description.

    Per-record size+sha rehash in the verify_proxy_payload idiom. This
    proves integrity (bytes match the description); correctness of the
    digests is authorized transitively via digest agreement plus the
    install/identity gates, never by the manifest alone.
    """
    digests = {}
    for role in _ROLES:
        try:
            data = (Path(payload_root) / manifest[role + "_path"]).read_bytes()
        except OSError:
            raise ProxyGateRefusal(ProxyGateCause.PROXY_GATE_BYTES_REFUSED,
                                   "proxy payload missing: %s" % role) from None
        if len(data) != manifest[role + "_size"]:
            raise ProxyGateRefusal(ProxyGateCause.PROXY_GATE_BYTES_REFUSED,
                                   "proxy payload size mismatch: %s" % role)
        digest = hashlib.sha256(data).hexdigest()
        if digest != manifest[role + "_sha256"]:
            raise ProxyGateRefusal(ProxyGateCause.PROXY_GATE_BYTES_REFUSED,
                                   "proxy payload hash mismatch: %s" % role)
        digests[role] = digest
    return digests


def verify_digest_agreement(manifest: dict[str, Any], *,
                            daemon_build: dict[str, Any],
                            client_manifest: dict[str, Any]) -> None:
    """Bind manifest digest claims to the build claim and client roster.

    Daemon binds manifest-to-claim; shim/CLI bind manifest-to-roster. A
    manifest/cli-to-claim check is deliberately absent: mixed-shim mutants
    carry claim-side CLI digests against manifest-side CLI bytes by
    construction, and binding them here would misroute MS-A/MS-B away
    from the install/identity gates. Malformed staged shapes defer to
    those gates (which refuse with library texts) instead of crashing.
    """
    binaries = daemon_build.get("binaries") if type(daemon_build) is dict else None
    if type(binaries) is dict:
        daemon_sha = binaries.get("pkcs11-proxy-ng")
        if (isinstance(daemon_sha, str)
                and manifest.get("daemon_sha256") != daemon_sha):
            raise ProxyGateRefusal(ProxyGateCause.PROXY_GATE_BYTES_REFUSED,
                                   "proxy manifest mismatch: daemon_sha256")
    roster: dict[str, str] = {}
    files = client_manifest.get("files") if type(client_manifest) is dict else None
    if type(files) is list:
        for entry in files:
            if (type(entry) is dict and isinstance(entry.get("path"), str)
                    and isinstance(entry.get("sha256"), str)):
                roster[entry["path"]] = entry["sha256"]
    for role, path in (("shim", _native.CLIENT_MODULE),
                       ("cli", _native.CLIENT_CLI)):
        if path in roster and manifest.get(role + "_sha256") != roster[path]:
            raise ProxyGateRefusal(ProxyGateCause.PROXY_GATE_BYTES_REFUSED,
                                   "proxy manifest mismatch: %s_sha256" % role)
    return None


def check_install_gate(client_manifest: dict[str, Any], *,
                       expected_proxy_identity: Any = None) -> dict[str, Any]:
    """Validate the staged client manifest (MS-B install gate, inert).

    No public pure validator exists and native.py is untouchable in P1a,
    so this calls the owning private validator directly (reuse, never a
    fork); a public wrapper stays a follow-up residual.
    """
    environment = client_manifest.get("environment") if type(
        client_manifest) is dict else None
    channel = client_manifest.get("channel") if type(
        client_manifest) is dict else None
    try:
        return _native._validate_client_manifest(
            client_manifest, environment, channel,
            expected_proxy_identity=expected_proxy_identity)
    except ValueError as error:
        raise ProxyGateRefusal(ProxyGateCause.PROXY_GATE_INSTALL_REFUSED,
                               str(error)) from error


def check_identity_gate(daemon_build: dict[str, Any],
                        client_manifest: dict[str, Any], *,
                        launch_rehashes: dict[str, Any],
                        abi_observed: dict[str, Any],
                        daemon_image: dict[str, Any],
                        expected_proxy_identity: Any = None) -> dict[str, Any]:
    """Check daemon/client/record sameness (MS-A check gate, inert)."""
    embedded: Any = None
    if type(client_manifest) is dict:
        source = client_manifest.get("source")
        proxy = source.get("proxy") if type(source) is dict else None
        embedded = proxy.get("abi_observed") if type(proxy) is dict else None
    if embedded is not None and abi_observed != embedded:
        raise ProxyGateRefusal(
            ProxyGateCause.PROXY_GATE_IDENTITY_REFUSED,
            "proxy identity actual invalid: "
            "staged abi_observed differs from client manifest")
    try:
        return _run.check_proxy_identities(
            daemon_build, client_manifest,
            expected=expected_proxy_identity,
            launch_rehashes=launch_rehashes, daemon_image=daemon_image)
    except ValueError as error:
        raise ProxyGateRefusal(ProxyGateCause.PROXY_GATE_IDENTITY_REFUSED,
                               str(error)) from error


def check_derivative_gate(*, parent_ref: str,
                          child_inspection: dict[str, Any]) -> dict[str, Any]:
    """Bind the derivative parent (WP gate, inert: no Docker, no build).

    The build-order parent_ref guard is promoted from build_proxy_derivative
    (which refuses before touching Docker); the committed suite pins the
    text byte-identical against the real builder. The prefix check reuses
    verify_derivative_parent unmodified.
    """
    selection = load_parent_selection()
    if parent_ref != selection["local_engine_id"]:
        raise ProxyGateRefusal(ProxyGateCause.PROXY_GATE_DERIVATIVE_REFUSED,
                               "proxy derivative build mismatch: parent_ref")
    try:
        return verify_derivative_parent(child_inspection, selection)
    except ValueError as error:
        raise ProxyGateRefusal(ProxyGateCause.PROXY_GATE_DERIVATIVE_REFUSED,
                               str(error)) from error


def _read_staged_bytes(artifact: Path, name: str) -> bytes:
    try:
        with (artifact / name).open("rb") as stream:
            raw = stream.read(_JSON_LIMIT + 1)
    except OSError:
        raise ValueError("proxy artifact %s is missing" % name) from None
    if len(raw) > _JSON_LIMIT:
        raise ValueError("proxy artifact %s exceeds 1 MiB" % name)
    return raw


def _read_staged_json(artifact: Path, name: str, expect: str) -> Any:
    raw = _read_staged_bytes(artifact, name)
    try:
        value = _strict_json_loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise ValueError("proxy artifact %s is not valid JSON: %s"
                         % (name, error)) from error
    except RecursionError as error:
        raise ValueError("proxy artifact %s is not valid JSON: excessive "
                         "nesting" % name) from error
    want = list if expect == "list" else dict
    if type(value) is not want:
        raise ValueError("proxy artifact %s must be a JSON %s" % (name, expect))
    return value


def _resolve_expected(staged: Any, override: Any) -> Any:
    """Resolve the expected identity: explicit param, staged file, default."""
    if override is not None:
        return override
    if staged is None:
        return None
    try:
        return ProxyBuildIdentityV1.from_dict(staged)
    except ValueError as error:
        raise ValueError("proxy artifact expected_identity.json is not a "
                         "valid identity record: %s" % error) from error
    except RecursionError as error:
        raise ValueError("proxy artifact expected_identity.json is not a "
                         "valid identity record: excessive nesting") from error


def execute_proxy(artifact: Path, *, run_id: int, run_attempt: int,
                  output_dir: Path, output_json: Path,
                  expected_proxy_identity: Any = None) -> dict[str, Any]:
    """Gate one caller-built artifact; return the gated/refusal row.

    Usage errors (bad IDs, missing artifact, stale output directory,
    unreadable staged inputs) raise and the CLI reports exit 2. Every
    gate halt instead returns a refusal row with a typed cause, the
    exact gate text, and exit 1. experiment_positive is always False:
    gates never emit a positive.
    """
    if (type(run_id) is not int or type(run_attempt) is not int
            or run_id <= 0 or run_attempt <= 0):
        raise ValueError("proxy run identity must be positive integers")
    artifact = Path(artifact)
    output_dir = Path(output_dir)
    output_json = Path(output_json)
    if not artifact.is_dir():
        raise ValueError("proxy artifact is missing: %s" % artifact)
    safe_directory(output_dir)
    output_dir.mkdir(parents=True, exist_ok=False)
    if not output_json.parent.exists():
        raise ValueError("invalid output JSON path")
    records = _read_staged_json(artifact, "records.json", "list")
    authority = _read_staged_json(artifact, "authority.json", "dict")
    manifest_raw = _read_staged_bytes(artifact, "manifest.json")
    try:
        manifest = _strict_json_loads(manifest_raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise ValueError("proxy artifact manifest.json is not valid JSON: %s"
                         % error) from error
    except RecursionError as error:
        raise ValueError("proxy artifact manifest.json is not valid JSON: "
                         "excessive nesting") from error
    daemon_build = _read_staged_json(artifact, "daemon_build.json", "dict")
    staged_manifest = _read_staged_json(artifact, "client_manifest.json", "dict")
    rehashes = _read_staged_json(artifact, "launch_rehashes.json", "dict")
    abi = _read_staged_json(artifact, "abi_observed.json", "dict")
    daemon_image = _read_staged_json(artifact, "daemon_image.json", "dict")
    child_inspection = _read_staged_json(artifact, "child_inspection.json", "dict")
    try:
        parent_ref = (artifact / "parent_ref.txt").read_text(
            encoding="utf-8").strip()
    except OSError:
        raise ValueError("proxy artifact parent_ref.txt is missing") from None
    staged_expected = None
    if (artifact / "expected_identity.json").exists():
        staged_expected = _read_staged_json(artifact, "expected_identity.json",
                                            "dict")
    expected = _resolve_expected(staged_expected, expected_proxy_identity)

    name = artifact.name
    gates: list[dict[str, Any]] = []
    proxy_sha: str | None = None
    selection: dict[str, Any] | None = None

    def note(gate: str, cause: ProxyGateCause, detail: str | None) -> None:
        gates.append({"gate": gate, "cause": cause.value,
                      "cause_detail": detail})

    def finish(phase: str, cause: ProxyGateCause,
               detail: str | None) -> dict[str, Any]:
        row: dict[str, Any] = {
            "lane": "proxy", "artifact": name, "proxy_sha": proxy_sha,
            "run_id": run_id, "run_attempt": run_attempt, "phase": phase,
            "status": PROXY_GATE_STATUS[cause], "cause": cause.value,
            "cause_detail": detail, "exit_code": PROXY_GATE_EXIT[cause],
            "experiment_positive": False, "image_usable": False,
            "evidence_complete": False, "evidence_admitted": False,
            "comparison_positive": None,
            "cells": {"direct": "not-run", "accepted-proxy": "not-run",
                      "candidate-proxy": "not-run"},
            "verdict": "pending",
            "verdict_mirror": (None if cause is ProxyGateCause.PROXY_GATE_OK
                               else dict(VERDICT_MIRROR_REFUSED)),
            "gates": [dict(entry) for entry in gates],
            "selection": selection,
            "limitations": list(_LIMITATIONS),
        }
        output_json.write_text(json.dumps(row, indent=2, sort_keys=True) + "\n",
                               encoding="utf-8")
        return row

    try:
        proxy_sha, name_attempt = parse_artifact_name(name)
        require_attempt_binding(name_attempt, run_attempt)
        selected = select_same_run(records, authority, proxy_sha, run_id,
                                   run_attempt)
        note("selection", ProxyGateCause.PROXY_GATE_OK, None)
        selection = {"name": selected["name"], "sha": selected["sha"],
                     "run_id": selected["run_id"],
                     "run_attempt": selected["run_attempt"],
                     "repository_id": selected["repository_id"],
                     "repository_full_name": selected["repository_full_name"],
                     "producer_job_id": selected["producer_job_id"],
                     "artifact_id": selected["artifact_id"]}
        checked = verify_manifest(manifest, proxy_sha=proxy_sha, run_id=run_id,
                                  run_attempt=run_attempt, authority=authority)
        digests = verify_payload_bytes(artifact, checked)
        verify_digest_agreement(checked, daemon_build=daemon_build,
                                client_manifest=staged_manifest)
        note("bytes", ProxyGateCause.PROXY_GATE_OK, None)
        assert selection is not None
        selection["manifest_sha256"] = hashlib.sha256(manifest_raw).hexdigest()
        selection["daemon_sha256"] = digests["daemon"]
        selection["cli_sha256"] = digests["cli"]
        selection["shim_sha256"] = digests["shim"]
        # Run order mirrored: install validates recorded-vs-selected before
        # the check gate, so direction-2 surfaces the install text (MS-B).
        check_install_gate(staged_manifest, expected_proxy_identity=expected)
        note("install", ProxyGateCause.PROXY_GATE_OK, None)
        check_identity_gate(daemon_build, staged_manifest,
                            launch_rehashes=rehashes, abi_observed=abi,
                            daemon_image=daemon_image,
                            expected_proxy_identity=expected)
        note("identity", ProxyGateCause.PROXY_GATE_OK, None)
        check_derivative_gate(parent_ref=parent_ref,
                              child_inspection=child_inspection)
        note("derivative", ProxyGateCause.PROXY_GATE_OK, None)
        return finish("gated", ProxyGateCause.PROXY_GATE_OK, None)
    except ProxyGateRefusal as refused:
        gate = _GATE_BY_CAUSE[refused.cause]
        note(gate, refused.cause, refused.detail)
        return finish(gate, refused.cause, refused.detail)


# ---------------------------------------------------------------------------
# P1b: cells + verdict + capsule past the P1a gates.
#
# Everything below this banner is additive: the gate chain above keeps its
# byte behavior (execute_proxy's signature and row shapes are pinned by
# the untouched P1a suite). execute_proxy_experiment reuses
# execute_proxy for admission, then runs the three cells through an
# injected CellExecutor, converts typed crash observations into verdict
# inputs, calls the REAL evaluate_proxy_verdict oracle (no fork), and
# writes a proxy-native capsule with the shared Q-P1-2 leaves.
#
# Crash qualification (T-PX-first): cells run accepted-before-candidate;
# a candidate crash claim surfaces as completed-negative only when the
# accepted control passes, because honest controls plus the real
# verdict's precedence yield control-unqualified (T4) whenever the
# accepted control fails. Crash observations always bind run/cell/logs.
#
# Live qualification: every row and capsule in this slice carries
# experiment_positive False with live_qualified False. The verdict
# sub-object stays the oracle output verbatim (T-series texts, exits,
# and flags exact), while the slice's own positive claim waits for a
# live-qualified run. A T1-shaped verdict is therefore reported exact
# but never claimed.
# ---------------------------------------------------------------------------

CELLS = ("direct", "accepted-proxy", "candidate-proxy")
CRASH_CONTROL = "PX-CLIENT-CRASH"
PROXY_EXECUTE_OK = "PROXY_EXECUTE_OK"
CAPSULE_SCHEMA = "p11lab-proxy-experiment-result-v1"
CAPSULE_NAME = "proxy-capsule.json"
GATED_NAME = "proxy-gated.json"

_COMPARISON_KEYS = ("performed", "positive", "coverage_positive")
_PROXY_CELLS = ("accepted-proxy", "candidate-proxy")
# Signal deaths: Docker reports 128+signal, 124 on timeout; a negative
# return code is the same death in direct-executor spelling. Any other
# nonzero exit is a provider finding, never a crash claim.
_DEATH_EXITS = frozenset({124})

_P1B_LIMITATIONS = (
    "controls unqualified by construction: scripted cells via an injected "
    "executor; live qualification required before any positive claim "
    "(experiment_positive stays false)",
    "comparison is caller-performed; budgets are unqualified targets; "
    "proxy runs unsharded (attempts_per_cell 1, no retry after start)",
    "caller-built material only: no candidate build, no retries, "
    "no cross-run lookup",
)


def _is_death(returncode: int) -> bool:
    return (returncode < 0 or returncode in _DEATH_EXITS
            or returncode > 128)


@dataclass(frozen=True)
class CellRequest:
    """One admitted cell invocation: WHICH cell of WHICH run/attempt."""

    cell: str
    run_id: int
    run_attempt: int
    payload: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        if self.cell not in CELLS:
            raise ValueError("unknown experiment cell: %r" % (self.cell,))
        if type(self.run_id) is not int or self.run_id <= 0:
            raise ValueError("cell run_id must be a positive int")
        if type(self.run_attempt) is not int or self.run_attempt <= 0:
            raise ValueError("cell run_attempt must be a positive int")
        if self.payload is not None and not isinstance(self.payload, Mapping):
            raise ValueError("cell payload must be a mapping or null")


_OBSERVATION_KEYS = frozenset({
    "cell", "admitted", "complete", "attribution_usable", "findings",
    "unexpected_death", "logs_available", "log_refs",
    "terminal_evidence_complete",
})


@dataclass(frozen=True)
class CellObservation:
    """Typed crash observation bound to run/cell/retained logs.

    logs_available is structural: true requires nonempty log_refs,
    false requires empty log_refs, so an observation can never claim
    retained logs it does not name.
    """

    cell: str
    run_id: int
    run_attempt: int
    admitted: bool
    complete: bool
    attribution_usable: bool
    findings: tuple[str, ...]
    unexpected_death: bool
    logs_available: bool
    log_refs: tuple[str, ...]
    terminal_evidence_complete: bool

    def __post_init__(self) -> None:
        if self.cell not in CELLS:
            raise ValueError("unknown experiment cell: %r" % (self.cell,))
        if type(self.run_id) is not int or self.run_id <= 0:
            raise ValueError("observation run_id must be a positive int")
        if type(self.run_attempt) is not int or self.run_attempt <= 0:
            raise ValueError("observation run_attempt must be a positive int")
        for key in ("admitted", "complete", "attribution_usable",
                    "unexpected_death", "logs_available",
                    "terminal_evidence_complete"):
            if type(getattr(self, key)) is not bool:
                raise ValueError("observation %s must be a boolean" % key)
        if (type(self.findings) is not tuple
                or any(not isinstance(entry, str) for entry in self.findings)):
            raise ValueError("observation findings must be a string tuple")
        if (type(self.log_refs) is not tuple
                or any(not isinstance(ref, str) or not ref
                       for ref in self.log_refs)):
            raise ValueError("observation log_refs must be a nonempty-path "
                             "tuple")
        if self.logs_available and not self.log_refs:
            raise ValueError("observation claims available logs with "
                             "unbound (empty) log_refs")
        if not self.logs_available and self.log_refs:
            raise ValueError("observation names log_refs with logs "
                             "unavailable (unbound)")

    @classmethod
    def from_dict(cls, value: Any, *, run_id: int,
                  run_attempt: int) -> CellObservation:
        """Parse a scripted/staged observation; run binds from invocation."""
        if type(value) is not dict:
            raise ValueError("cell observation must be a mapping")
        assert isinstance(value, dict)
        if {"run_id", "run_attempt"} & set(value):
            raise ValueError("cell observation run binds from the "
                             "invocation, never the record")
        if set(value) != _OBSERVATION_KEYS:
            raise ValueError("cell observation keys must be exactly %s"
                             % sorted(_OBSERVATION_KEYS))
        for key in ("findings", "log_refs"):
            if type(value[key]) is not list:
                raise ValueError("cell observation %s must be an array" % key)
        return cls(cell=value["cell"], run_id=run_id, run_attempt=run_attempt,
                   admitted=value["admitted"], complete=value["complete"],
                   attribution_usable=value["attribution_usable"],
                   findings=tuple(value["findings"]),
                   unexpected_death=value["unexpected_death"],
                   logs_available=value["logs_available"],
                   log_refs=tuple(value["log_refs"]),
                   terminal_evidence_complete=value[
                       "terminal_evidence_complete"])

    def to_dict(self) -> dict[str, Any]:
        """Return the bound JSON-ready record (run/cell/logs together)."""
        return {"cell": self.cell, "run_id": self.run_id,
                "run_attempt": self.run_attempt, "admitted": self.admitted,
                "complete": self.complete,
                "attribution_usable": self.attribution_usable,
                "findings": list(self.findings),
                "unexpected_death": self.unexpected_death,
                "logs_available": self.logs_available,
                "log_refs": list(self.log_refs),
                "terminal_evidence_complete":
                    self.terminal_evidence_complete}


class CellExecutor(Protocol):
    """Injectable cell-execution seam (Q-P1-1 adapter+seam).

    The production executor calls the real runners; hermetic tests
    inject fakes. Payloads are opaque to the seam: the production
    executor interprets them, fakes ignore them.
    """

    def run_cell(self, request: CellRequest) -> CellObservation:
        """Run one cell and return its bound observation."""
        ...


def _checked_log_refs(log_refs: Any) -> tuple[str, ...]:
    """Require retained-log refs as a sequence of nonempty paths."""
    if (not isinstance(log_refs, (list, tuple))
            or any(not isinstance(ref, str) or not ref
                   for ref in log_refs)):
        raise ValueError("observation log_refs must be a sequence of "
                         "nonempty paths")
    return tuple(log_refs)


def observation_from_result(request: CellRequest, result: Any, *,
                            log_refs: Any) -> CellObservation:
    """Convert a real runner result into a bound observation.

    This is the production conversion (D11): a pure function over the
    real RunResult shape, so adapter-boundary tests prove the mapping
    instead of constructing observations by hand. Signal deaths
    (128+signal, 124 timeout, negative) mark unexpected_death; any
    other nonzero exit is a finding, never a crash. Lifecycle errors
    leave the cell incomplete but stay retained in findings. Terminal
    evidence is complete only when the cell completed AND logs were
    retained; a death with logs is complete evidence of the crash.
    """
    if not isinstance(request, CellRequest):
        raise ValueError("observation conversion needs a CellRequest")
    refs = _checked_log_refs(log_refs)
    app_returncode = result.app_returncode
    if app_returncode is not None and type(app_returncode) is not int:
        raise ValueError("run result app_returncode must be an int or null")
    death = app_returncode is not None and _is_death(app_returncode)
    complete = (app_returncode is not None
                and not result.lifecycle_errors)
    findings = []
    if app_returncode is None:
        findings.append("app-exit:unobserved")
    elif app_returncode != 0:
        findings.append("app-exit:%d" % app_returncode)
    findings.extend("lifecycle:%s" % entry
                    for entry in result.lifecycle_errors)
    findings.extend("cleanup:%s" % entry for entry in result.cleanup_errors)
    return CellObservation(
        cell=request.cell, run_id=request.run_id,
        run_attempt=request.run_attempt, admitted=True, complete=complete,
        attribution_usable=app_returncode == 0,
        findings=tuple(findings), unexpected_death=death,
        logs_available=bool(refs), log_refs=refs,
        terminal_evidence_complete=bool(complete and refs))


class ProductionCellExecutor:
    """Thin adapter over the real cell runners (no runner edits).

    Direct cells delegate to native.run_native_softhsm; proxy cells
    delegate to run.run_proxy. Runner errors propagate with their exact
    text; the experiment entry records them as infrastructure errors.
    """

    def run_cell(self, request: CellRequest) -> CellObservation:
        """Run one cell via the owning runner and convert its result."""
        if not isinstance(request, CellRequest):
            raise ValueError("cell executor needs a CellRequest")
        payload = request.payload
        if not isinstance(payload, Mapping):
            raise ValueError("cell %s missing production payload"
                             % request.cell)
        refs = _checked_log_refs(payload.get("log_refs", ()))
        if request.cell == "direct":
            spec, installed = payload.get("spec"), payload.get("installed")
            if spec is None or installed is None:
                raise ValueError("cell direct missing production payload: "
                                 "spec+installed required")
            result = _native.run_native_softhsm(spec, installed)
        else:
            spec, plan = payload.get("spec"), payload.get("plan")
            if spec is None or plan is None:
                raise ValueError("cell %s missing production payload: "
                                 "spec+plan required" % request.cell)
            result = _run.run_proxy(spec, plan)
        return observation_from_result(request, result, log_refs=refs)


def _policy_control_ids() -> list[str]:
    """Return the control roster from the shipped policy bytes."""
    return [str(entry["id"]) for entry in load_proxy_policy().controls]


def build_controls(
        observations: Mapping[str, CellObservation]) -> dict[str, Any]:
    """Map typed crash observations onto the 7-control verdict roster.

    Every control defaults to pass/pass: fixture cells stimulate only
    the crash control, and unstimulated controls stay passing but
    unqualified (live_qualified False on the row). A death on one proxy
    fails that proxy's PX-CLIENT-CRASH entry with or without logs; the
    logs question routes separately through terminal_evidence_complete
    (F-NOTERM T5 vs F-CRASH T2). The accepted entry is honest: an
    accepted death fails the accepted control, so the real verdict's
    precedence yields control-unqualified (T4) ahead of any candidate
    crash claim (T-PX-first).
    """
    if not isinstance(observations, Mapping):
        raise ValueError("crash observations must map cells to observations")
    unknown = set(observations) - set(CELLS)
    if unknown:
        raise ValueError("unknown experiment cell: %s" % sorted(unknown)[0])
    for cell, obs in observations.items():
        if not isinstance(obs, CellObservation):
            raise ValueError("cell %s observation must be a CellObservation"
                             % cell)
        if obs.cell != cell:
            raise ValueError("misbound observation: key %s holds cell %s"
                             % (cell, obs.cell))
    roster = _policy_control_ids()
    if CRASH_CONTROL not in roster:
        raise ValueError("crash control %s missing from the policy roster"
                         % CRASH_CONTROL)
    controls = {control: {"accepted-proxy": "pass", "candidate-proxy": "pass"}
                for control in roster}
    for proxy in _PROXY_CELLS:
        crash = observations.get(proxy)
        if crash is not None and crash.unexpected_death:
            controls[CRASH_CONTROL][proxy] = "fail"
    return controls


def _checked_comparison(comparison: Any) -> dict[str, bool]:
    """Require the caller-performed comparison record (exact keys+bools)."""
    if type(comparison) is not dict or set(comparison) != set(
            _COMPARISON_KEYS):
        raise ValueError("experiment comparison must bind {performed, "
                         "positive, coverage_positive}")
    assert isinstance(comparison, dict)
    for key in _COMPARISON_KEYS:
        if type(comparison[key]) is not bool:
            raise ValueError("experiment comparison %s must be a boolean"
                             % key)
    return {key: comparison[key] for key in _COMPARISON_KEYS}


def _checked_budgets(budgets: Any) -> dict[str, bool]:
    """Require the budgets record (exact keys+bools)."""
    if type(budgets) is not dict or set(budgets) != {"within_budget"}:
        raise ValueError("experiment budgets must bind {within_budget}")
    assert isinstance(budgets, dict)
    if type(budgets["within_budget"]) is not bool:
        raise ValueError("experiment budgets within_budget must be a boolean")
    return {"within_budget": budgets["within_budget"]}


def build_verdict_inputs(
        observations: Mapping[str, CellObservation], *,
        comparison: Any, budgets: Any, uploads_complete: bool = True,
        cancelled: bool = False,
        infrastructure_error: str | None = None) -> dict[str, Any]:
    """Assemble cells/controls/budgets for the real verdict oracle.

    Missing cells (executor failures, T8 path) enter as
    not-admitted/not-complete so the inputs stay total; the verdict's
    own precedence then decides (T8 wins when infrastructure_error is
    set, else T6 for the missing cell).
    """
    checked_comparison = _checked_comparison(comparison)
    checked_budgets = _checked_budgets(budgets)
    if type(uploads_complete) is not bool:
        raise ValueError("experiment uploads_complete must be a boolean")
    if type(cancelled) is not bool:
        raise ValueError("experiment cancelled must be a boolean")
    if infrastructure_error is not None and not (
            isinstance(infrastructure_error, str)
            and infrastructure_error.strip()):
        raise ValueError("experiment infrastructure_error must be null or "
                         "a nonempty detail")
    controls = build_controls(observations)
    direct = observations.get("direct")
    cells: dict[str, Any] = {
        "direct": {"admitted": direct.admitted, "complete": direct.complete,
                   "attribution_usable": direct.attribution_usable,
                   "findings": list(direct.findings)}
        if direct is not None else
        {"admitted": False, "complete": False, "attribution_usable": False,
         "findings": []},
        "comparison": checked_comparison, "cancelled": cancelled,
        "uploads_complete": uploads_complete,
        "infrastructure_error": infrastructure_error,
    }
    for name in _PROXY_CELLS:
        obs = observations.get(name)
        cells[name] = {"admitted": obs.admitted, "complete": obs.complete,
                       "terminal_evidence_complete":
                           obs.terminal_evidence_complete} \
            if obs is not None else \
            {"admitted": False, "complete": False,
             "terminal_evidence_complete": False}
    return {"cells": cells, "controls": controls,
            "budgets": checked_budgets}


def _error_text(error: Exception) -> str:
    detail = str(error)
    return detail if detail else type(error).__name__


def execute_proxy_experiment(
        artifact: Path, *, run_id: int, run_attempt: int, output_dir: Path,
        output_json: Path, executor: CellExecutor,
        cell_payloads: Mapping[str, Any] | None = None, comparison: Any,
        budgets: Any = None, uploads_complete: bool = True,
        cancelled: bool = False,
        expected_proxy_identity: Any = None) -> dict[str, Any]:
    """Run gates, then cells, verdict, and capsule for one artifact.

    Admission reuses execute_proxy unchanged: refusals return the same
    row (written to output_json) with no cell executed and no capsule.
    Usage errors (bad comparison/budgets/flags, bad run IDs, missing
    artifact, stale output directory, unreadable staged inputs) raise
    before any cell runs. Cells execute in CELLS order
    (accepted-before-candidate); the first executor failure becomes
    the infrastructure error (T8) with its exact text, remaining cells
    stay not-run, and the row plus capsule still record the evidence.
    The verdict is the real evaluate_proxy_verdict output verbatim;
    experiment_positive stays False (live qualification pending).
    """
    checked_comparison = _checked_comparison(comparison)
    checked_budgets = _checked_budgets(
        {"within_budget": True} if budgets is None else budgets)
    if type(uploads_complete) is not bool:
        raise ValueError("experiment uploads_complete must be a boolean")
    if type(cancelled) is not bool:
        raise ValueError("experiment cancelled must be a boolean")
    if cell_payloads is not None:
        if not isinstance(cell_payloads, Mapping):
            raise ValueError("experiment cell payloads must map cells to "
                             "payloads")
        unknown = set(cell_payloads) - set(CELLS)
        if unknown:
            raise ValueError("unknown experiment cell: %s"
                             % sorted(unknown)[0])
    if not hasattr(executor, "run_cell"):
        raise ValueError("experiment executor must provide run_cell")
    output_dir = Path(output_dir)
    output_json = Path(output_json)
    gated = execute_proxy(
        artifact, run_id=run_id, run_attempt=run_attempt,
        output_dir=output_dir, output_json=output_dir / GATED_NAME,
        expected_proxy_identity=expected_proxy_identity)
    if gated["cause"] != ProxyGateCause.PROXY_GATE_OK.value:
        output_json.write_text(json.dumps(gated, indent=2, sort_keys=True)
                               + "\n", encoding="utf-8")
        return gated
    observations: dict[str, CellObservation] = {}
    cell_rows: dict[str, Any] = {}
    infrastructure_error: str | None = None
    for cell in CELLS:
        if infrastructure_error is not None:
            cell_rows[cell] = {"status": "not-run"}
            continue
        payload = cell_payloads.get(cell) if cell_payloads is not None else None
        try:
            obs = executor.run_cell(CellRequest(
                cell, run_id, run_attempt, payload=payload))
        except Exception as error:
            infrastructure_error = "cell %s executor failed: %s" % (
                cell, _error_text(error))
            cell_rows[cell] = {"status": "executor-failed",
                               "error": infrastructure_error}
            continue
        if (not isinstance(obs, CellObservation) or obs.cell != cell
                or (obs.run_id, obs.run_attempt) != (run_id, run_attempt)):
            seen = obs.cell if isinstance(obs, CellObservation) else type(
                obs).__name__
            infrastructure_error = (
                "cell %s executor returned a misbound observation "
                "(cell %s)" % (cell, seen))
            cell_rows[cell] = {"status": "executor-failed",
                               "error": infrastructure_error}
            continue
        observations[cell] = obs
        cell_rows[cell] = {"status": "executed", **obs.to_dict()}
    built = build_verdict_inputs(
        observations, comparison=checked_comparison,
        budgets=checked_budgets, uploads_complete=uploads_complete,
        cancelled=cancelled, infrastructure_error=infrastructure_error)
    verdict = evaluate_proxy_verdict(
        built["cells"], built["controls"], built["budgets"])
    admitted = (len(observations) == len(CELLS)
                and all(obs.admitted for obs in observations.values()))
    row: dict[str, Any] = {
        "lane": "proxy", "artifact": gated["artifact"],
        "proxy_sha": gated["proxy_sha"], "run_id": run_id,
        "run_attempt": run_attempt, "phase": "executed", "status": "executed",
        "cause": PROXY_EXECUTE_OK, "cause_detail": infrastructure_error,
        "exit_code": verdict["exit_code"], "experiment_positive": False,
        "live_qualified": False, "image_usable": False,
        "evidence_complete": verdict["evidence_complete"],
        "evidence_admitted": admitted,
        "comparison_positive": checked_comparison["positive"]
        if checked_comparison["performed"] else None,
        "uploads_complete": uploads_complete, "cancelled": cancelled,
        "infrastructure_error": infrastructure_error, "cells": cell_rows,
        "observations": [observations[cell].to_dict() for cell in CELLS
                         if cell in observations],
        "controls": built["controls"], "comparison": checked_comparison,
        "budgets": checked_budgets, "verdict": verdict,
        "capsule": CAPSULE_NAME, "gates": gated["gates"],
        "selection": gated["selection"],
        "attempt_roster": [{"cell": cell, "attempt": 1} for cell in CELLS
                           if cell in observations],
        "shard_roster": [], "limitations": list(_P1B_LIMITATIONS),
    }
    capsule: dict[str, Any] = {
        "schema": CAPSULE_SCHEMA, "diagnostic_only": True,
        "experiment_kind": "proxy-round", "proxy_sha": gated["proxy_sha"],
        "run_id": run_id, "run_attempt": run_attempt,
        "artifact": gated["artifact"], "selection": gated["selection"],
        "cells": {cell: cell_rows[cell] for cell in CELLS},
        "experiment_positive": False, "experiment_live_qualified": False,
        "controls": built["controls"], "comparison": checked_comparison,
        "budgets": checked_budgets, "verdict": verdict,
        "image_usable": False,
        "evidence_complete": verdict["evidence_complete"],
        "evidence_admitted": admitted,
        "comparison_positive": row["comparison_positive"],
        "within_budget": checked_budgets["within_budget"],
        "attempt_roster": row["attempt_roster"],
        "shard_roster": [], "limitations": list(_P1B_LIMITATIONS),
        "capsule_artifact": CAPSULE_NAME, "capsule_sha256": None,
    }
    capsule["capsule_sha256"] = hashlib.sha256(
        canonical({**capsule, "capsule_sha256": None})).hexdigest()
    (output_dir / CAPSULE_NAME).write_bytes(canonical(capsule) + b"\n")
    output_json.write_text(json.dumps(row, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    return row


# ---------------------------------------------------------------------------
# P1c: distributed cells + aggregate (per-cell CLI-capable operations).
#
# Everything below this banner is additive: the P1a gate chain and the P1b
# experiment loop keep their byte behavior (both suites stay byte-identical
# and green; execute_proxy/execute_proxy_experiment signatures are pinned).
# Each workflow job invokes exactly one cell through execute_proxy_cell
# (admission reuses execute_proxy unchanged, then one CellExecutor run,
# then a frozen cell-observation artifact); execute_proxy_cell_staged
# binds the same entry to the production adapter from a bounded staged
# payload file so `proxy execute-cell` needs no inline orchestration.
# aggregate_proxy_experiment merges uploaded cell observations through the
# REAL evaluate_proxy_verdict oracle and writes the experiment row plus
# capsule; it takes no executor and re-executes nothing. Unlike the P1b
# loop (which stops after an infrastructure error), the aggregate admits
# every well-formed staged cell and records only the first failure.
# ---------------------------------------------------------------------------

CELL_OBSERVATION_SCHEMA = "p11lab-proxy-cell-observation-v1"
PROXY_CELL_OK = "PROXY_CELL_OK"

_CELL_OBSERVATION_KEYS = frozenset({
    "schema", "artifact", "proxy_sha", "run_id", "run_attempt", "cell",
    "status", "observation", "log_refs", "infrastructure_error", "gates",
    "selection",
})

_STAGED_SPEC_KEYS = frozenset({
    "environment", "channel", "mode", "artifact", "execution_location",
    "consumer_artifact", "client_artifact", "argv", "inputs",
    "timeout_seconds",
})
_STAGED_REF_KEYS = frozenset({"kind", "reference", "sha256", "platform"})
_STAGED_PLAN_KEYS = frozenset({"descriptor", "host"})

_CELL_LIMITATIONS = (
    "single-cell row: sibling cells execute in separate jobs; experiment "
    "evidence completes at aggregate (verdict pending here)",
    "live qualification required before any positive claim "
    "(experiment_positive stays false)",
    "caller-built material only: no candidate build, no retries, "
    "no cross-run lookup",
)

_AGGREGATE_LIMITATIONS = (
    "distributed aggregate: each cell ran once in its own job; this entry "
    "re-executes nothing (staged observations bound to run/attempt/cell "
    "with selection agreement checked)",
    "controls unqualified by construction: staged scripted cells; live "
    "qualification required before any positive claim "
    "(experiment_positive stays false)",
    "comparison is caller-performed; budgets are unqualified targets; "
    "proxy cells run unsharded (attempts_per_cell 1, no retry after start)",
    "caller-built material only: no candidate build, no retries, "
    "no cross-run lookup",
)


def cell_observation_filename(cell: str) -> str:
    """Return the frozen staged filename for one cell slot."""
    if cell not in CELLS:
        raise ValueError("unknown experiment cell: %r" % (cell,))
    return cell + ".json"


def _read_bounded_json(path: Path, what: str) -> Any:
    """Read one caller-staged JSON document (path-anchored, 1 MiB bound).

    Same idiom as the P1a staged readers (strict loads, shared size
    cap); usage errors carry the caller's WHAT for exact CLI text.
    """
    path = Path(path)
    try:
        with path.open("rb") as stream:
            raw = stream.read(_JSON_LIMIT + 1)
    except OSError:
        raise ValueError("%s is missing" % what) from None
    if len(raw) > _JSON_LIMIT:
        raise ValueError("%s exceeds 1 MiB" % what)
    try:
        value = _strict_json_loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise ValueError("%s is not valid JSON: %s" % (what, error)) from error
    except RecursionError as error:
        raise ValueError("%s is not valid JSON: excessive nesting"
                         % what) from error
    if type(value) is not dict:
        raise ValueError("%s must be a JSON dict" % what)
    return value


def _checked_staged_artifact_ref(value: Any) -> dict[str, Any]:
    """Require one staged artifact reference (exact keys, typed fields)."""
    if type(value) is not dict or set(value) != _STAGED_REF_KEYS:
        raise ValueError("staged artifact ref keys must be exactly %s"
                         % sorted(_STAGED_REF_KEYS))
    assert isinstance(value, dict)
    for key in ("kind", "reference", "platform"):
        if not isinstance(value[key], str) or not value[key]:
            raise ValueError("staged artifact ref %s must be a nonempty "
                             "string" % key)
    if (not isinstance(value["sha256"], str)
            or _SHA256_RE.fullmatch(value["sha256"]) is None):
        raise ValueError("staged artifact ref sha256 must be 64 hex")
    return dict(value)


def _checked_staged_run_spec(value: Any, *, cell: str) -> dict[str, Any]:
    """Require one staged runner spec; the mode must match the cell."""
    if type(value) is not dict or set(value) != _STAGED_SPEC_KEYS:
        raise ValueError("staged run spec keys must be exactly %s"
                         % sorted(_STAGED_SPEC_KEYS))
    assert isinstance(value, dict)
    for key in ("environment", "channel", "mode", "execution_location"):
        if not isinstance(value[key], str) or not value[key]:
            raise ValueError("staged run spec %s must be a nonempty string"
                             % key)
    if cell == "direct":
        matched = value["mode"] in ("direct", "native")
    else:
        matched = value["mode"] == "proxy"
    if not matched:
        raise ValueError("staged run spec mode %r mismatches cell %s"
                         % (value["mode"], cell))
    artifact = _checked_staged_artifact_ref(value["artifact"])
    checked: dict[str, Any] = {}
    for key in ("consumer_artifact", "client_artifact"):
        ref = value[key]
        if ref is None:
            checked[key] = None
        elif type(ref) is not dict:
            raise ValueError("staged run spec %s must be null or an "
                             "artifact record" % key)
        else:
            checked[key] = _checked_staged_artifact_ref(ref)
    argv = value["argv"]
    if (type(argv) is not list
            or any(not isinstance(entry, str) for entry in argv)):
        raise ValueError("staged run spec argv must be a string array")
    inputs = value["inputs"]
    if (type(inputs) is not dict
            or any(not isinstance(key, str)
                   or not isinstance(entry, str)
                   for key, entry in inputs.items())):
        raise ValueError("staged run spec inputs must be a string map")
    timeout = value["timeout_seconds"]
    if type(timeout) is not int or not 1 <= timeout <= 86400:
        raise ValueError("staged run spec timeout_seconds must be 1..86400")
    checked.update(environment=value["environment"], channel=value["channel"],
                   mode=value["mode"], artifact=artifact,
                   execution_location=value["execution_location"],
                   argv=list(argv), inputs=dict(inputs),
                   timeout_seconds=timeout)
    return checked


def _staged_production_payload(doc: Any, *, cell: str,
                               run_dir: Path) -> dict[str, Any]:
    """Validate one staged cell payload and build production runner inputs.

    Shapes are exact per cell kind (proxy cells take a plan, direct
    takes an installed prefix); the mode must match the cell. Runner
    scratch derives under the entry output dir. A bad installed prefix
    is caller-staging usage (raised before admission), never T8: the
    staged path always builds complete payloads or refuses them.
    """
    want = {"spec", "installed_prefix", "log_refs"} if cell == "direct" else {
        "spec", "plan", "log_refs"}
    if type(doc) is not dict or set(doc) != want:
        raise ValueError("staged cell payload keys must be exactly %s"
                         % sorted(want))
    assert isinstance(doc, dict)
    spec = _checked_staged_run_spec(doc["spec"], cell=cell)
    refs = _checked_log_refs(doc["log_refs"])
    built = RunSpec(
        environment=spec["environment"], channel=spec["channel"],
        mode=spec["mode"], artifact=ArtifactRef(**spec["artifact"]),
        execution_location=spec["execution_location"],
        consumer_artifact=(None if spec["consumer_artifact"] is None
                           else ArtifactRef(**spec["consumer_artifact"])),
        client_artifact=(None if spec["client_artifact"] is None
                         else ArtifactRef(**spec["client_artifact"])),
        argv=tuple(spec["argv"]), inputs=dict(spec["inputs"]),
        output_dir=run_dir, cwd=run_dir,
        timeout_seconds=spec["timeout_seconds"])
    if cell == "direct":
        prefix = doc["installed_prefix"]
        if not isinstance(prefix, str) or not prefix:
            raise ValueError("staged installed_prefix must be a nonempty "
                             "path")
        try:
            installed = _bundle.read_installation(
                Path(prefix), environment=spec["environment"],
                channel=spec["channel"],
                platform=spec["artifact"]["platform"])
        except (ValueError, OSError) as error:
            raise ValueError("staged installed_prefix invalid: %s"
                             % error) from error
        return {"spec": built, "installed": installed,
                "log_refs": list(refs)}
    plan = doc["plan"]
    if type(plan) is not dict or set(plan) != _STAGED_PLAN_KEYS:
        raise ValueError("staged cell plan keys must be exactly %s"
                         % sorted(_STAGED_PLAN_KEYS))
    assert isinstance(plan, dict)
    if not isinstance(plan["descriptor"], Mapping):
        raise ValueError("staged cell plan descriptor must be a mapping")
    if type(plan["host"]) is not bool:
        raise ValueError("staged cell plan host must be a boolean")
    return {"spec": built,
            "plan": {"descriptor": plan["descriptor"], "host": plan["host"]},
            "log_refs": list(refs)}


def _attempt_cell(executor: CellExecutor, request: CellRequest
                  ) -> tuple[CellObservation | None, str | None]:
    """Run one bound cell; failures become T8 texts, never raises.

    Same shape as one P1b loop iteration (exact executor-failed and
    misbound-observation texts); the P1b inline loop is untouched.
    """
    try:
        obs = executor.run_cell(request)
    except Exception as error:
        return None, "cell %s executor failed: %s" % (
            request.cell, _error_text(error))
    if (not isinstance(obs, CellObservation) or obs.cell != request.cell
            or (obs.run_id, obs.run_attempt)
            != (request.run_id, request.run_attempt)):
        seen = obs.cell if isinstance(obs, CellObservation) else type(
            obs).__name__
        return None, (
            "cell %s executor returned a misbound observation "
            "(cell %s)" % (request.cell, seen))
    return obs, None


def execute_proxy_cell(
        artifact: Path, *, cell: str, run_id: int, run_attempt: int,
        output_dir: Path, output_json: Path, executor: CellExecutor,
        cell_payload: Mapping[str, Any] | None = None,
        expected_proxy_identity: Any = None) -> dict[str, Any]:
    """Gate one artifact, run exactly one named cell, write its artifact.

    Admission reuses execute_proxy unchanged: refusals return the same
    row (written to output_json) with no cell executed and no
    observation file. Params (cell/run/attempt/payload/executor)
    validate before admission with the P1b texts. Executor failures
    and misbound returns become T8 rows (exit 2) that still write the
    frozen cell-observation artifact so the aggregate can cite the
    failure. The row keeps verdict pending and writes no capsule: a
    single cell never completes experiment evidence.
    """
    request = CellRequest(cell, run_id, run_attempt, payload=cell_payload)
    if not hasattr(executor, "run_cell"):
        raise ValueError("experiment executor must provide run_cell")
    output_dir = Path(output_dir)
    output_json = Path(output_json)
    gated = execute_proxy(
        artifact, run_id=run_id, run_attempt=run_attempt,
        output_dir=output_dir, output_json=output_dir / GATED_NAME,
        expected_proxy_identity=expected_proxy_identity)
    if gated["cause"] != ProxyGateCause.PROXY_GATE_OK.value:
        output_json.write_text(json.dumps(gated, indent=2, sort_keys=True)
                               + "\n", encoding="utf-8")
        return gated
    obs, infrastructure_error = _attempt_cell(executor, request)
    filename = cell_observation_filename(cell)
    observations: list[dict[str, Any]] = []
    mirror: dict[str, Any] | None
    if infrastructure_error is not None:
        record: dict[str, Any] = {
            "schema": CELL_OBSERVATION_SCHEMA, "artifact": gated["artifact"],
            "proxy_sha": gated["proxy_sha"], "run_id": run_id,
            "run_attempt": run_attempt, "cell": cell,
            "status": "executor-failed", "observation": None, "log_refs": [],
            "infrastructure_error": infrastructure_error,
            "gates": gated["gates"], "selection": gated["selection"]}
        mine: dict[str, Any] = {"status": "executor-failed",
                               "error": infrastructure_error}
        exit_code = 2
        typed: str | None = "usage-or-infrastructure"
        mirror = {"typed_cause": "usage-or-infrastructure", "exit_code": 2}
        phase, status = "cell-executor-failed", "executor-failed"
    else:
        assert obs is not None
        bound = obs.to_dict()
        record = {
            "schema": CELL_OBSERVATION_SCHEMA, "artifact": gated["artifact"],
            "proxy_sha": gated["proxy_sha"], "run_id": run_id,
            "run_attempt": run_attempt, "cell": cell, "status": "executed",
            "observation": bound, "log_refs": list(obs.log_refs),
            "infrastructure_error": None, "gates": gated["gates"],
            "selection": gated["selection"]}
        mine = {"status": "executed", **bound}
        observations = [bound]
        exit_code = 0
        typed = None
        mirror = None
        phase, status = "cell-executed", "executed"
    (output_dir / filename).write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    row: dict[str, Any] = {
        "lane": "proxy", "artifact": gated["artifact"],
        "proxy_sha": gated["proxy_sha"], "run_id": run_id,
        "run_attempt": run_attempt, "phase": phase, "status": status,
        "cause": PROXY_CELL_OK, "cause_detail": infrastructure_error,
        "exit_code": exit_code, "experiment_positive": False,
        "live_qualified": False, "image_usable": False,
        "evidence_complete": False, "evidence_admitted": False,
        "comparison_positive": None, "cell": cell,
        "observation_artifact": filename, "observations": observations,
        "cells": {name: (mine if name == cell else {"status": "not-run"})
                  for name in CELLS},
        "infrastructure_error": infrastructure_error, "typed_cause": typed,
        "verdict": "pending", "verdict_mirror": mirror,
        "gates": gated["gates"], "selection": gated["selection"],
        "limitations": list(_CELL_LIMITATIONS),
    }
    output_json.write_text(json.dumps(row, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    return row


def execute_proxy_cell_staged(
        artifact: Path, *, cell: str, run_id: int, run_attempt: int,
        output_dir: Path, output_json: Path, cell_payload_path: Path,
        expected_proxy_identity: Any = None) -> dict[str, Any]:
    """Run one named cell with the production adapter from staged JSON.

    CLI binding for execute_proxy_cell: the staged payload file carries
    bounded runner inputs (usage errors raise before admission, with
    the executor untouched); runner scratch derives under the entry
    output dir. Delegates to execute_proxy_cell, never re-implements
    admission, the cell attempt, or the artifact write.
    """
    if cell not in CELLS:
        raise ValueError("unknown experiment cell: %r" % (cell,))
    doc = _read_bounded_json(cell_payload_path, "cell payload file")
    output_dir = Path(output_dir)
    payload = _staged_production_payload(doc, cell=cell,
                                         run_dir=output_dir / "cell-run")
    return execute_proxy_cell(
        artifact, cell=cell, run_id=run_id, run_attempt=run_attempt,
        output_dir=output_dir, output_json=output_json,
        executor=ProductionCellExecutor(), cell_payload=payload,
        expected_proxy_identity=expected_proxy_identity)


class _StagedCellError(Exception):
    """Internal: one staged cell record is unusable; the text becomes T8."""


def _read_staged_cell(cells_dir: Path, cell: str, *, run_id: int,
                      run_attempt: int
                      ) -> tuple[CellObservation | None, str | None,
                                 dict[str, Any]]:
    """Parse one staged cell record; raise _StagedCellError when unusable.

    Run/attempt/cell bind from the invocation, never the record; the
    embedded observation parses through CellObservation.from_dict, so
    its exact-keys and logs-available-iff-refs rules are reused, not
    re-implemented. Returns (observation-or-None, slot-infra-or-None,
    meta): a valid executor-failed record yields its failure text as
    evidence, not a parse problem.
    """
    filename = cell_observation_filename(cell)
    try:
        doc = _read_bounded_json(cells_dir / filename,
                                 "cell %s staged observation" % cell)
    except ValueError as error:
        raise _StagedCellError(str(error)) from None
    bad = "cell %s staged observation invalid: " % cell
    misbound = "cell %s staged observation misbound: " % cell
    if set(doc) != _CELL_OBSERVATION_KEYS:
        raise _StagedCellError(bad + "keys must be exactly %s"
                               % sorted(_CELL_OBSERVATION_KEYS))
    if (type(doc["run_id"]) is not int or type(doc["run_attempt"]) is not int
            or doc["run_id"] <= 0 or doc["run_attempt"] <= 0):
        raise _StagedCellError(
            bad + "run_id and run_attempt must be positive integers")
    if doc["cell"] != cell:
        raise _StagedCellError(misbound + "expected cell %s, found %s"
                               % (cell, doc["cell"]))
    if (doc["run_id"], doc["run_attempt"]) != (run_id, run_attempt):
        raise _StagedCellError(
            misbound + "expected run %d/%d, found %s/%s"
            % (run_id, run_attempt, doc["run_id"], doc["run_attempt"]))
    if doc["schema"] != CELL_OBSERVATION_SCHEMA:
        raise _StagedCellError(bad + "schema must be %s"
                               % CELL_OBSERVATION_SCHEMA)
    if not isinstance(doc["artifact"], str) or not doc["artifact"]:
        raise _StagedCellError(bad + "artifact must be a nonempty name")
    if (not isinstance(doc["proxy_sha"], str)
            or _SHA1_RE.fullmatch(doc["proxy_sha"]) is None):
        raise _StagedCellError(bad + "proxy_sha must be 40 hex")
    if doc["status"] not in ("executed", "executor-failed"):
        raise _StagedCellError(
            bad + "status must be executed or executor-failed")
    if type(doc["gates"]) is not list:
        raise _StagedCellError(bad + "gates must be an array")
    if type(doc["selection"]) is not dict:
        raise _StagedCellError(bad + "selection must be a mapping")
    refs = doc["log_refs"]
    if (type(refs) is not list
            or any(not isinstance(ref, str) or not ref for ref in refs)):
        raise _StagedCellError(
            bad + "log_refs must be an array of nonempty paths")
    meta = {"artifact": doc["artifact"], "proxy_sha": doc["proxy_sha"],
            "selection": doc["selection"], "gates": doc["gates"]}
    if doc["status"] == "executor-failed":
        if doc["observation"] is not None:
            raise _StagedCellError(
                bad + "observation must be null when the executor failed")
        if refs:
            raise _StagedCellError(
                bad + "log_refs must be empty when the executor failed")
        detail = doc["infrastructure_error"]
        if not isinstance(detail, str) or not detail.strip():
            raise _StagedCellError(
                bad + "infrastructure_error must be a nonempty detail "
                "when the executor failed")
        return None, detail, meta
    if doc["infrastructure_error"] is not None:
        raise _StagedCellError(
            bad + "infrastructure_error must be null when the cell executed")
    embedded = doc["observation"]
    if type(embedded) is not dict:
        raise _StagedCellError(
            bad + "observation must be a bound observation record")
    assert isinstance(embedded, dict)
    if "run_id" not in embedded or "run_attempt" not in embedded:
        raise _StagedCellError(
            bad + "observation must bind run_id and run_attempt")
    if (embedded["run_id"], embedded["run_attempt"]) != (run_id, run_attempt):
        raise _StagedCellError(
            misbound + "embedded run %s/%s disagrees with staged run "
            "%d/%d" % (embedded["run_id"], embedded["run_attempt"],
                       run_id, run_attempt))
    stripped = {key: value for key, value in embedded.items()
                if key not in ("run_id", "run_attempt")}
    try:
        obs = CellObservation.from_dict(stripped, run_id=run_id,
                                        run_attempt=run_attempt)
    except ValueError as error:
        raise _StagedCellError(bad + "observation invalid: %s"
                               % error) from None
    if obs.cell != cell:
        raise _StagedCellError(misbound + "expected cell %s, found %s"
                               % (cell, obs.cell))
    if list(refs) != list(obs.log_refs):
        raise _StagedCellError(
            bad + "log_refs must mirror the observation log_refs")
    return obs, None, meta


def _selection_disagreement(reference: dict[str, Any],
                            candidate: dict[str, Any]) -> str | None:
    """Name the first admitted-selection field two staged cells differ on."""
    if reference["artifact"] != candidate["artifact"]:
        return "artifact"
    if reference["proxy_sha"] != candidate["proxy_sha"]:
        return "proxy_sha"
    ref_selection = reference["selection"]
    staged_selection = candidate["selection"]
    for key in sorted(set(ref_selection) | set(staged_selection)):
        if ref_selection.get(key) != staged_selection.get(key):
            return str(key)
    return None


def aggregate_proxy_experiment(
        cells_dir: Path, *, run_id: int, run_attempt: int, output_dir: Path,
        output_json: Path, comparison: Any, budgets: Any = None,
        uploads_complete: bool = True,
        cancelled: bool = False) -> dict[str, Any]:
    """Merge staged cell observations through the real verdict oracle.

    Reads cells_dir/<cell>.json for the frozen three-cell roster (extra
    uploads alongside are ignored); missing files are missing evidence
    (T6), never usage errors. Run/attempt/cell bind from the
    invocation; corrupt or misbound staged records and cross-cell
    selection disagreements become T8 with exact texts, while every
    well-formed sibling still aggregates (first failure wins the
    infrastructure error). Params validate before any read. Writes the
    experiment row plus capsule in the P1b shapes (gates/selection
    cited from the first admitted cell); experiment_positive stays
    False. Takes no executor and re-executes nothing.
    """
    if (type(run_id) is not int or type(run_attempt) is not int
            or run_id <= 0 or run_attempt <= 0):
        raise ValueError("proxy run identity must be positive integers")
    checked_comparison = _checked_comparison(comparison)
    checked_budgets = _checked_budgets(
        {"within_budget": True} if budgets is None else budgets)
    if type(uploads_complete) is not bool:
        raise ValueError("experiment uploads_complete must be a boolean")
    if type(cancelled) is not bool:
        raise ValueError("experiment cancelled must be a boolean")
    cells_dir = Path(cells_dir)
    if not cells_dir.is_dir():
        raise ValueError("proxy cells directory is missing: %s" % cells_dir)
    output_dir = Path(output_dir)
    output_json = Path(output_json)
    safe_directory(output_dir)
    output_dir.mkdir(parents=True, exist_ok=False)
    if not output_json.parent.exists():
        raise ValueError("invalid output JSON path")
    observations: dict[str, CellObservation] = {}
    cell_rows: dict[str, Any] = {}
    metas: dict[str, dict[str, Any]] = {}
    slot_errors: dict[str, str] = {}
    for cell in CELLS:
        if not (cells_dir / cell_observation_filename(cell)).exists():
            cell_rows[cell] = {"status": "not-run"}
            continue
        try:
            obs, slot_infra, meta = _read_staged_cell(
                cells_dir, cell, run_id=run_id, run_attempt=run_attempt)
        except _StagedCellError as bad:
            slot_errors[cell] = str(bad)
            cell_rows[cell] = {"status": "executor-failed",
                               "error": slot_errors[cell]}
            continue
        metas[cell] = meta
        if obs is None:
            assert slot_infra is not None
            slot_errors[cell] = slot_infra
            cell_rows[cell] = {"status": "executor-failed",
                               "error": slot_infra}
        else:
            observations[cell] = obs
            cell_rows[cell] = {"status": "executed", **obs.to_dict()}
    reference: dict[str, Any] | None = None
    ref_cell = ""
    for cell in CELLS:
        if cell not in metas:
            continue
        if reference is None:
            reference = metas[cell]
            ref_cell = cell
            continue
        field = _selection_disagreement(reference, metas[cell])
        if field is not None and cell not in slot_errors:
            slot_errors[cell] = (
                "cell %s staged observation misbound: staged selection "
                "disagrees with cell %s: %s" % (cell, ref_cell, field))
            observations.pop(cell, None)
            cell_rows[cell] = {"status": "executor-failed",
                               "error": slot_errors[cell]}
    infrastructure_error = next(
        (slot_errors[cell] for cell in CELLS if cell in slot_errors), None)
    built = build_verdict_inputs(
        observations, comparison=checked_comparison,
        budgets=checked_budgets, uploads_complete=uploads_complete,
        cancelled=cancelled, infrastructure_error=infrastructure_error)
    verdict = evaluate_proxy_verdict(
        built["cells"], built["controls"], built["budgets"])
    admitted = (len(observations) == len(CELLS)
                and all(obs.admitted for obs in observations.values()))
    cited = reference if reference is not None else None
    row: dict[str, Any] = {
        "lane": "proxy",
        "artifact": cited["artifact"] if cited is not None else None,
        "proxy_sha": cited["proxy_sha"] if cited is not None else None,
        "run_id": run_id, "run_attempt": run_attempt, "phase": "executed",
        "status": "executed", "cause": PROXY_EXECUTE_OK,
        "cause_detail": infrastructure_error,
        "exit_code": verdict["exit_code"], "experiment_positive": False,
        "live_qualified": False, "image_usable": False,
        "evidence_complete": verdict["evidence_complete"],
        "evidence_admitted": admitted,
        "comparison_positive": checked_comparison["positive"]
        if checked_comparison["performed"] else None,
        "uploads_complete": uploads_complete, "cancelled": cancelled,
        "infrastructure_error": infrastructure_error, "cells": cell_rows,
        "observations": [observations[cell].to_dict() for cell in CELLS
                         if cell in observations],
        "controls": built["controls"], "comparison": checked_comparison,
        "budgets": checked_budgets, "verdict": verdict,
        "capsule": CAPSULE_NAME,
        "gates": cited["gates"] if cited is not None else [],
        "selection": cited["selection"] if cited is not None else None,
        "attempt_roster": [{"cell": cell, "attempt": 1} for cell in CELLS
                           if cell in observations],
        "shard_roster": [], "limitations": list(_AGGREGATE_LIMITATIONS),
    }
    capsule: dict[str, Any] = {
        "schema": CAPSULE_SCHEMA, "diagnostic_only": True,
        "experiment_kind": "proxy-round", "proxy_sha": row["proxy_sha"],
        "run_id": run_id, "run_attempt": run_attempt,
        "artifact": row["artifact"], "selection": row["selection"],
        "cells": {cell: cell_rows[cell] for cell in CELLS},
        "experiment_positive": False, "experiment_live_qualified": False,
        "controls": built["controls"], "comparison": checked_comparison,
        "budgets": checked_budgets, "verdict": verdict,
        "image_usable": False,
        "evidence_complete": verdict["evidence_complete"],
        "evidence_admitted": admitted,
        "comparison_positive": row["comparison_positive"],
        "within_budget": checked_budgets["within_budget"],
        "attempt_roster": row["attempt_roster"],
        "shard_roster": [], "limitations": list(_AGGREGATE_LIMITATIONS),
        "capsule_artifact": CAPSULE_NAME, "capsule_sha256": None,
    }
    capsule["capsule_sha256"] = hashlib.sha256(
        canonical({**capsule, "capsule_sha256": None})).hexdigest()
    (output_dir / CAPSULE_NAME).write_bytes(canonical(capsule) + b"\n")
    output_json.write_text(json.dumps(row, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    return row


def aggregate_proxy_experiment_staged(
        cells_dir: Path, *, run_id: int, run_attempt: int, output_dir: Path,
        output_json: Path, comparison_path: Path, budgets_path: Path,
        uploads_complete: bool = True,
        cancelled: bool = False) -> dict[str, Any]:
    """Merge staged cell observations with caller-staged comparison/budgets.

    CLI binding for aggregate_proxy_experiment: comparison and budgets
    arrive as staged JSON files (usage errors raise before any read,
    with no row written). Delegates to aggregate_proxy_experiment,
    never re-implements the merge, the verdict call, or the writes.
    """
    comparison = _read_bounded_json(comparison_path, "comparison file")
    budgets = _read_bounded_json(budgets_path, "budgets file")
    return aggregate_proxy_experiment(
        cells_dir, run_id=run_id, run_attempt=run_attempt,
        output_dir=output_dir, output_json=output_json,
        comparison=comparison, budgets=budgets,
        uploads_complete=uploads_complete, cancelled=cancelled)
