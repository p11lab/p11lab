"""Authenticated source-transport evidence verification (B-G2a).

Offline-only acquisition helper: verifies a handoff-pinned evidence
directory against a sealed verifier and a controller-installed profile.
No GH_TOKEN is read and no live GitHub API reads run on this path; the
gate reuses delivery_authority._run_verifier + _check_verified +
load_profile + _check_local_controller and never the live-run half of
verify_active_context. Expected source/content digests always derive
from the handoff, never from the manifest inside the evidence dir.

B-G2a's gate signature and evidence semantics are append-only. B-G2b
adds evidence inputs and promotion checks; it MUST NOT change the
meaning, requiredness, or refusal texts of any B-G2a parameter, and
MUST NOT weaken any B-G2a RED hook (§5).
"""
from datetime import datetime, timezone
from pathlib import Path

from . import delivery_authority
from .jsonutil import loads as strict_json_loads

EVIDENCE_SCHEMA_VERSION = 1

EVIDENCE_MANIFEST = "evidence-manifest.json"
ATTESTATION_CONTEXT = "attestation-context.json"
BUNDLE = "bundle.json"
TRUSTED_ROOT = "trusted-root.jsonl"
TRANSPORT_JOURNAL = "transport-journal.json"

REQUIRED_MEMBERS = (ATTESTATION_CONTEXT, BUNDLE, TRUSTED_ROOT, EVIDENCE_MANIFEST)
OPTIONAL_MEMBERS = (TRANSPORT_JOURNAL,)

EVIDENCE_UNAVAILABLE = "authenticated source transport evidence unavailable; acquisition blocked"
VERIFICATION_FAILED = "authenticated source transport verification failed: bundle digest mismatch"
BINDING_MISMATCH = "attested source facts differ from the handoff digests; acquisition blocked"
PROMOTION_UNAVAILABLE = "full image validation/promotion integration unavailable; acquisition blocked"

_REUSED_VERIFIER_TEXTS = frozenset({
    "verifier executable digest mismatch",
    "protected trusted root digest mismatch",
    "verified certificate identity mismatch",
    "verified source context subject or predicate mismatch",
    "verified timestamp outside accepted window",
    "ambiguous verified attestations",
    "missing verified timestamps",
    "verification clock requires timezone",
    "invalid verified timestamp type",
    "malformed verified attestation",
    "unsafe or oversized verifier input",
    "verifier input changed or exceeded limit",
    # Toolchain-pinned truncated-output literal for the pinned stub shape
    # ("truncated{"); any other decode offset still collapses to the
    # fallback. Contains no paths, hashes, or digests.
    "Expecting value: line 1 column 1 (char 0)",
})

# Q2 producer mapping: sealed.archive_sha256 binds handoff source.file_sha256
# and the five content fields bind their content_companion namesakes.
# readback_proof_sha256 is required by handoff schema2 but NOT compared
# here (explicit coverage boundary; promotion.verify_promotion_evidence
# independently verifies and hash-binds the proof bytes before admission).
# inventory_sha256 and sealed receipt_sha256 are never aliases for the proof.
_COMPARED_CONTENT_FIELDS = ("reference", "manifest_sha256", "file_sha256",
                            "receipt_sha256", "spdx_sha256")


def _regular_file(path: Path, description: str) -> Path:
    import stat
    try:
        status = path.lstat()
    except OSError as error:
        raise ValueError(EVIDENCE_UNAVAILABLE) from error
    if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
        raise ValueError(EVIDENCE_UNAVAILABLE)
    return path


# Ceiling-only evidence-member bound (G-F6): 16 = closed roster (4 required
# + 1 optional, counted with headroom as 6) + margin for future optional
# members. Enforced with early-stop iteration BEFORE _check_roster
# materializes the full listing; valid dirs (at most 5 members) are
# unaffected.
MAX_EVIDENCE_MEMBERS = 16


def _check_member_bound(directory: Path) -> None:
    count = 0
    try:
        for _member in directory.iterdir():
            count += 1
            if count > MAX_EVIDENCE_MEMBERS:
                break
    except OSError as error:
        raise ValueError(EVIDENCE_UNAVAILABLE) from error
    if count > MAX_EVIDENCE_MEMBERS:
        raise ValueError(EVIDENCE_UNAVAILABLE)


def _check_output_dir(path: Path) -> None:
    """Best-effort pre-check: an existing non-dir output refuses R4.

    A missing output still flows to the verifier, which creates the
    directory (mkdir exist_ok=False) — refusing missing outputs here
    would make R9 unreachable (see the G-F6 report). The verifier's
    mkdir stays authoritative for creation failures.
    """
    import stat
    try:
        status = path.stat()
    except OSError:
        return
    if not stat.S_ISDIR(status.st_mode):
        raise ValueError(EVIDENCE_UNAVAILABLE)


def _check_executable(path: Path) -> None:
    """Best-effort pre-check: regular file with any exec bit, else R4.

    Single-lstat discipline: regularity (the same S_ISREG + nlink==1
    terms as _regular_file) and the S_IXUSR|S_IXGRP|S_IXOTH bits come
    from one lstat result — no open() before the check (FIFO-safe) and
    no os.access TOCTOU double-check. The verifier's spawn stays
    authoritative; this only refuses early what it cannot run.
    """
    import stat
    try:
        status = path.lstat()
    except OSError as error:
        raise ValueError(EVIDENCE_UNAVAILABLE) from error
    if (
        not stat.S_ISREG(status.st_mode)
        or status.st_nlink != 1
        or (status.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)) == 0
    ):
        raise ValueError(EVIDENCE_UNAVAILABLE)


def _read_manifest(directory: Path) -> None:
    manifest = _regular_file(directory / EVIDENCE_MANIFEST, EVIDENCE_MANIFEST)
    try:
        raw = delivery_authority._read_bounded_file(manifest, 1024 * 1024)
    except (OSError, ValueError) as error:
        raise ValueError(EVIDENCE_UNAVAILABLE) from error
    try:
        value = strict_json_loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise ValueError(EVIDENCE_UNAVAILABLE) from error
    if (type(value) is not dict or type(value.get("schema_version")) is not int
            or value.get("schema_version") != EVIDENCE_SCHEMA_VERSION):
        raise ValueError(EVIDENCE_UNAVAILABLE)


def _check_roster(directory: Path) -> None:
    try:
        names = sorted(path.name for path in directory.iterdir())
    except OSError as error:
        raise ValueError(EVIDENCE_UNAVAILABLE) from error
    allowed = set(REQUIRED_MEMBERS) | set(OPTIONAL_MEMBERS)
    if any(name not in allowed for name in names):
        raise ValueError(EVIDENCE_UNAVAILABLE)
    if any(name not in names for name in REQUIRED_MEMBERS):
        raise ValueError(EVIDENCE_UNAVAILABLE)
    for name in names:
        _regular_file(directory / name, name)


def _wrap_verifier_error(error: ValueError) -> ValueError:
    if str(error) in _REUSED_VERIFIER_TEXTS:
        return ValueError(str(error))
    return ValueError(VERIFICATION_FAILED)


def _load_context(raw: bytes) -> dict:
    try:
        value = strict_json_loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise ValueError(VERIFICATION_FAILED) from error
    if (type(value) is not dict or type(value.get("payload")) is not dict
            or type(value.get("schema_version")) is not int
            or value.get("schema_version") != 1):
        raise ValueError(VERIFICATION_FAILED)
    return value


def _check_profile_binding(context: dict, profile: dict) -> None:
    if (context.get("role") != profile["role"]
            or context.get("policy_sha256") != profile["policy_sha256"]
            or context.get("review_sha256") != profile["review_sha256"]
            or context.get("controller_sha256") != profile["controller_sha256"]
            or context.get("profile_sha256") != delivery_authority._profile_digest(profile)):
        raise ValueError(VERIFICATION_FAILED)


def _check_handoff_binding(context: dict, handoff: dict) -> None:
    catalogue = handoff["catalogue"]
    if context.get("environment") != catalogue["environment"] or context.get("channel") != catalogue["channel"]:
        raise ValueError(BINDING_MISMATCH)
    payload = context["payload"]
    source = payload.get("source")
    if type(source) is not dict:
        raise ValueError(BINDING_MISMATCH)
    sealed = source.get("sealed")
    content = source.get("content")
    if type(sealed) is not dict or type(content) is not dict:
        raise ValueError(BINDING_MISMATCH)
    expected_source = handoff["source"]
    expected_companion = expected_source["content_companion"]
    if (sealed.get("reference") != expected_source["reference"]
            or sealed.get("manifest_sha256") != expected_source["manifest_sha256"]
            or sealed.get("archive_sha256") != expected_source["file_sha256"]):
        raise ValueError(BINDING_MISMATCH)
    if any(content.get(name) != expected_companion[name] for name in _COMPARED_CONTENT_FIELDS):
        raise ValueError(BINDING_MISMATCH)


def verify_transport_evidence(handoff: dict, evidence_dir, executable,
                              trusted_root, output_dir) -> dict:
    """Verify transport evidence; return the verified context on success.

    Every shape/absence failure raises the R4 text; verifier failures
    reuse the delivery_authority texts where they fire else the R7
    fallback; handoff-digest differences raise the R8 text. Paths must
    be pathlib.Path (str is rejected); None means refused, never skipped.
    """
    for candidate in (evidence_dir, executable, trusted_root, output_dir):
        if candidate is None or not isinstance(candidate, Path):
            raise ValueError(EVIDENCE_UNAVAILABLE)
    if not evidence_dir.is_dir():
        raise ValueError(EVIDENCE_UNAVAILABLE)
    _check_output_dir(output_dir)
    _check_executable(executable)
    _check_member_bound(evidence_dir)
    _read_manifest(evidence_dir)
    _check_roster(evidence_dir)
    catalogue = handoff["catalogue"]
    profile = delivery_authority.load_profile(catalogue["environment"], catalogue["channel"])
    delivery_authority._check_local_controller(profile)
    context_path = evidence_dir / ATTESTATION_CONTEXT
    bundle_path = evidence_dir / BUNDLE
    try:
        supplied_root = delivery_authority._read_bounded_file(
            trusted_root, 4 * 1024 * 1024)
        packaged_root = delivery_authority._read_bounded_file(
            evidence_dir / TRUSTED_ROOT, 4 * 1024 * 1024)
    except (OSError, ValueError) as error:
        raise ValueError(EVIDENCE_UNAVAILABLE) from error
    if supplied_root != packaged_root:
        raise ValueError("protected trusted root digest mismatch")
    try:
        result, raw = delivery_authority._run_verifier(
            executable, context_path, bundle_path, trusted_root,
            profile["root_sha256"], profile, output_dir)
    except ValueError as error:
        raise _wrap_verifier_error(error) from error
    except OSError as error:
        raise ValueError(EVIDENCE_UNAVAILABLE) from error
    context = _load_context(raw)
    identity = context.get("run")
    if type(identity) is not dict:
        raise ValueError(VERIFICATION_FAILED)
    try:
        delivery_authority._check_verified(result, profile, identity, raw,
                                           datetime.now(timezone.utc))
    except ValueError as error:
        raise _wrap_verifier_error(error) from error
    _check_profile_binding(context, profile)
    _check_handoff_binding(context, handoff)
    return context
