"""Authenticated image-promotion evidence verification (B-G2b).

Offline-only promotion helper: verifies a handoff-pinned promotion
evidence directory against the sealed verifier and a
controller-installed profile extended with a promotion_signer entry.
The same sealed gh verifier and trusted-root infrastructure as B-G2a
are reused (no wholly-new root); the promotion attestation carries its
own predicate and subject so source evidence can never double as
promotion evidence. No GH_TOKEN is read and no live GitHub API reads
run on this path; the gate reuses delivery_authority._run_verifier +
_check_verified + load_profile + _check_local_controller and never the
live-run half of verify_active_context. Expected binary/source digests
always derive from the handoff, never from the manifest inside the
evidence dir. The validation-result member hash binds the attested
producer-CI validation bytes; the readback-proof member closes the
B-G2a coverage boundary (acquisition.py) by obtaining, independently
verifying, and hash-binding the proof bytes.
"""
import hashlib
from datetime import datetime, timezone
from pathlib import Path

from . import delivery_authority
from .acquisition import PROMOTION_UNAVAILABLE
from .jsonutil import loads as strict_json_loads

PROMOTION_SCHEMA_VERSION = 1
PROMOTION_PREDICATE = "https://p11lab.org/attestations/image-promotion/v1"
PROMOTION_SUBJECT = "promotion-context.json"
PROMOTION_ROLE = "image-promotion"

PROMOTION_MANIFEST = "promotion-manifest.json"
PROMOTION_CONTEXT = "promotion-context.json"
PROMOTION_BUNDLE = "promotion-bundle.json"
PROMOTION_TRUSTED_ROOT = "promotion-trusted-root.jsonl"
VALIDATION_RESULT = "validation-result.json"
READBACK_PROOF = "readback-proof.json"

REQUIRED_MEMBERS = (PROMOTION_MANIFEST, PROMOTION_CONTEXT, PROMOTION_BUNDLE,
                    PROMOTION_TRUSTED_ROOT, VALIDATION_RESULT, READBACK_PROOF)

VERIFICATION_FAILED = "authenticated promotion verification failed: bundle digest mismatch"
BINDING_MISMATCH = "promotion evidence differs from the handoff digests; acquisition blocked"
POLICY_MISMATCH = "promotion validation policy mismatch; acquisition blocked"

# Same sealed-verifier texts as the transport leg (one verifier, two
# attestation kinds); anything else collapses to the promotion fallback.
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
    "Expecting value: line 1 column 1 (char 0)",
})

_PROMOTION_SIGNER_KEYS = ("repository", "repository_id", "owner_id", "workflow_path",
                          "signer_sha", "source_sha", "source_ref")

_PROOF_COMPARED_FIELDS = ("reference", "manifest_sha256", "file_sha256",
                           "receipt_sha256", "spdx_sha256")


def _regular_file(path: Path, description: str) -> Path:
    import stat
    try:
        status = path.lstat()
    except OSError as error:
        raise ValueError(PROMOTION_UNAVAILABLE) from error
    if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
        raise ValueError(PROMOTION_UNAVAILABLE)
    return path


# Ceiling-only promotion-member bound (E4 mirror): 16 = closed roster
# (6 required) + margin for future optional members. Enforced with
# early-stop iteration BEFORE _check_roster materializes the listing.
MAX_PROMOTION_MEMBERS = 16


def _check_member_bound(directory: Path) -> None:
    count = 0
    try:
        for _member in directory.iterdir():
            count += 1
            if count > MAX_PROMOTION_MEMBERS:
                break
    except OSError as error:
        raise ValueError(PROMOTION_UNAVAILABLE) from error
    if count > MAX_PROMOTION_MEMBERS:
        raise ValueError(PROMOTION_UNAVAILABLE)


def _check_output_dir(path: Path) -> None:
    """Best-effort pre-check: an existing non-dir output refuses unavailable."""
    import stat
    try:
        status = path.stat()
    except OSError:
        return
    if not stat.S_ISDIR(status.st_mode):
        raise ValueError(PROMOTION_UNAVAILABLE)


def _check_executable(path: Path) -> None:
    """Best-effort pre-check: regular file with any exec bit, else unavailable."""
    import stat
    try:
        status = path.lstat()
    except OSError as error:
        raise ValueError(PROMOTION_UNAVAILABLE) from error
    if (
        not stat.S_ISREG(status.st_mode)
        or status.st_nlink != 1
        or (status.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)) == 0
    ):
        raise ValueError(PROMOTION_UNAVAILABLE)


def _read_manifest(directory: Path) -> None:
    manifest = _regular_file(directory / PROMOTION_MANIFEST, PROMOTION_MANIFEST)
    try:
        raw = delivery_authority._read_bounded_file(manifest, 1024 * 1024)
    except (OSError, ValueError) as error:
        raise ValueError(PROMOTION_UNAVAILABLE) from error
    try:
        value = strict_json_loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise ValueError(PROMOTION_UNAVAILABLE) from error
    if (type(value) is not dict or type(value.get("schema_version")) is not int
            or value.get("schema_version") != PROMOTION_SCHEMA_VERSION):
        raise ValueError(PROMOTION_UNAVAILABLE)


def _check_roster(directory: Path) -> None:
    try:
        names = sorted(path.name for path in directory.iterdir())
    except OSError as error:
        raise ValueError(PROMOTION_UNAVAILABLE) from error
    allowed = set(REQUIRED_MEMBERS)
    if any(name not in allowed for name in names):
        raise ValueError(PROMOTION_UNAVAILABLE)
    if any(name not in names for name in REQUIRED_MEMBERS):
        raise ValueError(PROMOTION_UNAVAILABLE)
    for name in names:
        _regular_file(directory / name, name)


def _wrap_verifier_error(error: ValueError) -> ValueError:
    if str(error) in _REUSED_VERIFIER_TEXTS:
        return ValueError(str(error))
    return ValueError(VERIFICATION_FAILED)


def _promotion_profile(profile: dict) -> dict:
    """Overlay the promotion_signer entry onto the base profile pins."""
    signer = profile.get("promotion_signer")
    if type(signer) is not dict:
        raise ValueError(PROMOTION_UNAVAILABLE)
    try:
        delivery_authority._validate_promotion_signer(signer)
    except ValueError as error:
        raise ValueError(PROMOTION_UNAVAILABLE) from error
    overlaid = dict(profile)
    for key in _PROMOTION_SIGNER_KEYS:
        overlaid[key] = signer[key]
    return overlaid


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
    if (context.get("role") != PROMOTION_ROLE
            or context.get("policy_sha256") != profile["policy_sha256"]
            or context.get("review_sha256") != profile["review_sha256"]
            or context.get("controller_sha256") != profile["controller_sha256"]
            or context.get("profile_sha256") != delivery_authority._profile_digest(profile)):
        raise ValueError(VERIFICATION_FAILED)


def _check_handoff_binding(context: dict, handoff: dict) -> dict:
    catalogue = handoff["catalogue"]
    if context.get("environment") != catalogue["environment"]:
        raise ValueError(BINDING_MISMATCH)
    if context.get("channel") != catalogue["channel"]:
        raise ValueError(BINDING_MISMATCH)
    promotion = context["payload"].get("promotion")
    if type(promotion) is not dict:
        raise ValueError(BINDING_MISMATCH)
    binary = promotion.get("binary")
    source = promotion.get("source")
    if type(binary) is not dict or type(source) is not dict:
        raise ValueError(BINDING_MISMATCH)
    expected_binary = handoff["binary"]
    if (binary.get("reference") != expected_binary["reference"]
            or binary.get("manifest_sha256") != expected_binary["manifest_sha256"]):
        raise ValueError(BINDING_MISMATCH)
    if expected_binary["kind"] == "bundle":
        if binary.get("file_sha256") != expected_binary["file_sha256"]:
            raise ValueError(BINDING_MISMATCH)
    elif binary.get("engine_id") != expected_binary["engine_id"]:
        raise ValueError(BINDING_MISMATCH)
    expected_source = handoff["source"]
    if (source.get("manifest_sha256") != expected_source["manifest_sha256"]
            or source.get("file_sha256") != expected_source["file_sha256"]):
        raise ValueError(BINDING_MISMATCH)
    return promotion


def _check_validation_result(raw: bytes, attested: object) -> None:
    """Bind the producer-CI validation bytes, then enforce result policy."""
    if type(attested) is not str or len(attested) != 64:
        raise ValueError(BINDING_MISMATCH)
    if hashlib.sha256(raw).hexdigest() != attested:
        raise ValueError(BINDING_MISMATCH)
    try:
        value = strict_json_loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise ValueError(POLICY_MISMATCH) from error
    if type(value) is not dict:
        raise ValueError(POLICY_MISMATCH)
    if (type(value.get("schema_version")) is not int
            or value.get("schema_version") != 1
            or value.get("role") != "image-validation-result"
            or value.get("scope") != "producer-ci"
            or value.get("authority") != "producer-attested"
            or value.get("promotable") is not True):
        raise ValueError(POLICY_MISMATCH)


def _check_readback_proof(raw: bytes, handoff: dict, attested: object) -> None:
    """Obtain, independently verify, and hash-bind the readback proof bytes."""
    companion = handoff["source"]["content_companion"]
    if type(attested) is not str or len(attested) != 64:
        raise ValueError(BINDING_MISMATCH)
    if attested != companion["readback_proof_sha256"]:
        raise ValueError(BINDING_MISMATCH)
    if hashlib.sha256(raw).hexdigest() != companion["readback_proof_sha256"]:
        raise ValueError(BINDING_MISMATCH)
    try:
        value = strict_json_loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise ValueError(BINDING_MISMATCH) from error
    if (type(value) is not dict or type(value.get("schema_version")) is not int
            or value.get("schema_version") != 1
            or value.get("role") != "content-readback-proof"
            or value.get("registry") != handoff["registry"]
            or any(value.get(name) != companion[name]
                   for name in _PROOF_COMPARED_FIELDS)):
        raise ValueError(BINDING_MISMATCH)


def verify_promotion_evidence(handoff: dict, promotion_dir, executable,
                              trusted_root, output_dir) -> dict:
    """Verify promotion evidence; return the verified context on success.

    Every shape/absence failure raises the promotion-unavailable text;
    verifier failures reuse the sealed-verifier texts where they fire
    else the promotion fallback; handoff-digest differences raise the
    binding text; producer-CI result policy failures raise the policy
    text. Paths must be pathlib.Path (str is rejected); None means
    refused, never skipped.
    """
    for candidate in (promotion_dir, executable, trusted_root, output_dir):
        if candidate is None or not isinstance(candidate, Path):
            raise ValueError(PROMOTION_UNAVAILABLE)
    if not promotion_dir.is_dir():
        raise ValueError(PROMOTION_UNAVAILABLE)
    _check_output_dir(output_dir)
    _check_executable(executable)
    _check_member_bound(promotion_dir)
    _read_manifest(promotion_dir)
    _check_roster(promotion_dir)
    catalogue = handoff["catalogue"]
    profile = delivery_authority.load_profile(catalogue["environment"], catalogue["channel"])
    delivery_authority._check_local_controller(profile)
    promotion_profile = _promotion_profile(profile)
    context_path = promotion_dir / PROMOTION_CONTEXT
    bundle_path = promotion_dir / PROMOTION_BUNDLE
    try:
        supplied_root = delivery_authority._read_bounded_file(
            trusted_root, 4 * 1024 * 1024)
        packaged_root = delivery_authority._read_bounded_file(
            promotion_dir / PROMOTION_TRUSTED_ROOT, 4 * 1024 * 1024)
    except (OSError, ValueError) as error:
        raise ValueError(PROMOTION_UNAVAILABLE) from error
    if supplied_root != packaged_root:
        raise ValueError("protected trusted root digest mismatch")
    try:
        validation_raw = delivery_authority._read_bounded_file(
            promotion_dir / VALIDATION_RESULT, 1024 * 1024)
        proof_raw = delivery_authority._read_bounded_file(
            promotion_dir / READBACK_PROOF, 1024 * 1024)
    except (OSError, ValueError) as error:
        raise ValueError(PROMOTION_UNAVAILABLE) from error
    try:
        result, raw = delivery_authority._run_verifier(
            executable, context_path, bundle_path, trusted_root,
            promotion_profile["root_sha256"], promotion_profile, output_dir,
            promotion=True)
    except ValueError as error:
        raise _wrap_verifier_error(error) from error
    except OSError as error:
        raise ValueError(PROMOTION_UNAVAILABLE) from error
    context = _load_context(raw)
    identity = context.get("run")
    if type(identity) is not dict:
        raise ValueError(VERIFICATION_FAILED)
    try:
        delivery_authority._check_verified(
            result, promotion_profile, identity, raw, datetime.now(timezone.utc),
            predicate_type=PROMOTION_PREDICATE, subject_name=PROMOTION_SUBJECT)
    except ValueError as error:
        raise _wrap_verifier_error(error) from error
    _check_profile_binding(context, profile)
    promotion = _check_handoff_binding(context, handoff)
    _check_validation_result(validation_raw, promotion.get("validation_result_sha256"))
    _check_readback_proof(proof_raw, handoff, promotion.get("readback_proof_sha256"))
    return context
