"""Source-first delivery gates: sealed sources, anonymous readback, admission, handoff.

Pure local verification over bytes on disk: no network access and no registry
writes. Transport (docker/ORAS push and pull) lives in the delivery workflows
and scripts; this module decides whether each gate passes and binds catalogue
entries to artifact digests. Every gate raises PublishError with the reason on
failure; callers must stop binary upload/cache export when a gate fails.

Sequence: seal licensed sources -> publish the sealed source -> read it back
anonymously -> build/test the exact binary -> admit actual content -> write the
binary handoff. The handoff is a factual digest binding plus the admission
verdict; it never authorizes publication by itself. Public exposure additionally
requires admission status ``eligible``. Digests are identities; registry tags
are recorded only as discovery aliases.
"""

import hashlib
import io
import json
import re
import tarfile
from pathlib import Path

from .catalog import locked_asset, packaged_asset, validate_build_inputs
from .receipts import write_receipt
from .sources import checksum


class PublishError(ValueError):
    """A delivery gate failed; binary upload/cache export must stop."""


SCHEMA_VERSION = 1
REGISTRY_NAMESPACE = "ghcr.io/p11lab"


def package_repo(environment: str) -> str:
    """Default delivery repository for one catalogue environment."""
    _require(isinstance(environment, str) and _TAG_ENV.fullmatch(environment),
             "invalid catalogue environment for repository")
    return REGISTRY_NAMESPACE + "/" + environment


def require_repository(value: str) -> str:
    """Accept only strict repository paths (explicit registry inputs)."""
    _require(isinstance(value, str) and _REPO.fullmatch(value), "registry must be a repository path")
    return value


def effective_registry(raw: str, environment: str) -> str:
    """Resolve an explicit registry input or the per-environment default."""
    if raw:
        return require_repository(raw)
    return package_repo(environment)

# Pinned acquisition tool. The installer scripts embed these same values;
# tests enforce parity. Resolved 2026-10-05: v1.3.4 is the latest stable
# ORAS release; the pinned revision is the peeled tag commit and matches the
# `oras version` self-report; artifact hashes match the release checksums file
# (sha256 19d479e4...). License bytes in the release tarball are Apache-2.0.
ORAS_PIN = {
    "version": "1.3.4",
    "source": {
        "url": "https://github.com/oras-project/oras.git",
        "revision": "db9e29505c3059f2b8fde34ae8cae266c5c765e9",
        "license_observation": "Apache-2.0",
    },
    "artifacts": {
        "linux/amd64": {
            "url": "https://github.com/oras-project/oras/releases/download/v1.3.4/oras_1.3.4_linux_amd64.tar.gz",
            "sha256": "f27adb935022d94df8dc77719c322dda592c78a0d57a6f7dcdd8d900b248c454",
            "size": 4679642,
        },
        "windows/amd64": {
            "url": "https://github.com/oras-project/oras/releases/download/v1.3.4/oras_1.3.4_windows_amd64.zip",
            "sha256": "ffdb6aa40267686b5d507da1f21a57fc502a9a7c86b90c54557d335644c99dbd",
            "size": 4834833,
        },
    },
}

# Pinned GitHub Actions for T13-owned workflows (tag tips resolved 2026-10-05).
# Tests require the exact `uses: repo@sha` form in every listed workflow.
ACTION_PINS = {
    "actions/checkout": {"tag": "v4", "sha": "11d5960a326750d5838078e36cf38b85af677262"},
    "actions/setup-python": {"tag": "v5", "sha": "a26af69be951a213d495a4c3e4e4022e16d87065"},
    "actions/upload-artifact": {"tag": "v4", "sha": "ea165f8d65b6e75b540449e92b4886f43607fa02"},
    "actions/download-artifact": {"tag": "v4", "sha": "d3f86a106a0bac45b974a628896c90dbdf5c8093"},
    "actions/setup-dotnet": {"tag": "v4", "sha": "67a3573c9a986a3f9c594539f4ab511d57bb3ce9"},
    # Third-party MSVC environment helper (same helper the existing Windows
    # workflow uses unpinned); pinned here by full commit SHA.
    "ilammy/msvc-dev-cmd": {"tag": "v1", "sha": "0b201ec74fa43914dc39ae48a89fd1d8cb592756"},
}
PUBLISH_WORKFLOWS = (
    "provider-delivery.yml",
    "native-delivery.yml",
    "clean-consumer-windows.yml",
    "windows-native-bouncyhsm.yml",
)

# Registry tag roles inside each environment repository. Tags are aliases;
# only the recorded digest identifies an artifact for acquisition.
TAG_ROLES = ("src", "rt", "sbom", "native", "handoff")
_TAG_ENV = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_PLATFORM = re.compile(r"[a-z0-9]+/[a-z0-9]+\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_DIGEST_REF = re.compile(r"(?P<repo>[a-z0-9._/-]+(?::[0-9]+)?/[a-z0-9._/-]+)@sha256:(?P<digest>[0-9a-f]{64})\Z")
_REPO = re.compile(r"[a-z0-9._/-]+(?::[0-9]+)?/[a-z0-9._/-]+\Z")

# Canonical reusable-action inputs. action.yml must declare exactly these;
# tests enforce parity. The action runs the caller application through
# `p11lab run` only; it never forwards the host environment or publisher
# credentials into providers.
ACTION_INPUTS = {
    "environment": {"required": True, "description": "Catalogue environment ID (e.g. softhsm2)."},
    "channel": {"required": True, "description": "Locked channel: release or rolling."},
    "mode": {"required": False, "default": "direct", "description": "Execution mode: direct or native."},
    "registry": {"required": False, "default": "",
                 "description": "Registry repository holding the handoff (default ghcr.io/p11lab/<environment>)."},
    "handoff-digest": {"required": True, "description": "Immutable handoff digest (sha256:<hex>)."},
    "command": {"required": True, "description": "Application argv as a JSON array of strings."},
    "inputs": {"required": False, "default": "", "description": "Newline-separated NAME=VALUE provider inputs."},
    "state-dir": {"required": False, "default": "", "description": "Caller-owned persistent state directory (else ephemeral)."},
    "timeout": {"required": False, "default": "300", "description": "Run timeout in seconds."},
    "working-directory": {"required": False, "default": ".", "description": "Caller application cwd, relative to the caller checkout."},
}


def _require(condition, message):
    if not condition:
        raise PublishError(message)


def _need(mapping, key, message):
    """Fetch a required key as a gate message, never a KeyError traceback."""
    _require(isinstance(mapping, dict) and key in mapping, message)
    return mapping[key]


def _read_json(path: Path):
    try:
        result = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise PublishError(f"invalid JSON document: {path}") from error
    _require(isinstance(result, dict), f"JSON document must be an object: {path}")
    return result


def artifact_tag(role: str, environment: str, channel: str, digest: str, target: str | None = None) -> str:
    """Build a registry tag alias; the digest stays the artifact identity."""
    _require(role in TAG_ROLES, f"unknown tag role: {role}")
    _require(isinstance(environment, str) and _TAG_ENV.fullmatch(environment), "invalid tag environment")
    _require(channel in {"release", "rolling"}, "tag channel must be release or rolling")
    _require(isinstance(digest, str) and _SHA256.fullmatch(digest), "tag digest must be full lowercase SHA-256")
    parts = [role, environment, channel]
    if role == "native":
        _require(target in {"debian13-amd64", "windows-amd64"}, "native tag requires an explicit target")
        parts.append(target)
    elif target is not None:
        raise PublishError("only native tags carry a target")
    parts.append(digest[:12])
    return "-".join(parts)


def parse_tag(tag: str) -> dict:
    """Parse a tag alias back into its components; never an identity proof."""
    match = re.fullmatch(r"(src|rt|sbom|native|handoff)-([a-z0-9]+(?:-[a-z0-9]+)*)-(release|rolling)-(?:(debian13-amd64|windows-amd64)-)?([0-9a-f]{12})\Z", tag)
    _require(match is not None, f"tag is not a delivery alias: {tag}")
    role, environment, channel, target, short = match.groups()
    if role == "native":
        _require(target is not None, f"native tag lacks a target: {tag}")
    else:
        _require(target is None, f"non-native tag carries a target: {tag}")
    return {"role": role, "environment": environment, "channel": channel, "target": target, "short": short}


_TAG_ALIAS = re.compile(r"[a-zA-Z0-9_][a-zA-Z0-9_.\-]{0,127}\Z")
_GIT_REV = re.compile(r"[0-9a-f]{40}\Z")
# Floating names stay channel-owned: a versioned alias that spells one is
# dropped so a release build can never overwrite the rolling discovery tag
# (or vice versa) in the shared per-environment repository.
_RESERVED_ALIASES = frozenset({"latest", "rolling"})


def aliases_for_sources(sources, channel: str) -> list[str]:
    """Version/floating aliases for one lock source roster (pure)."""
    floats = {"release": "latest", "rolling": "rolling"}
    if channel not in floats:
        return []
    aliases: list[str] = []
    if isinstance(sources, list) and len(sources) == 1 and isinstance(sources[0], dict):
        only = sources[0]
        if channel == "release":
            selector = only.get("selector") if isinstance(only.get("selector"), dict) else {}
            if only.get("kind") == "git" and selector.get("kind") == "tag":
                aliases.append(selector.get("value"))
        else:
            revision = only.get("revision")
            if only.get("kind") == "git" and isinstance(revision, str) and _GIT_REV.fullmatch(revision):
                aliases.append("rolling-" + revision[:12])
    aliases.append(floats[channel])
    kept: list[str] = []
    for alias in aliases:
        if not (isinstance(alias, str) and _TAG_ALIAS.fullmatch(alias)) or alias in kept:
            continue
        if alias != floats[channel] and (alias in _RESERVED_ALIASES or _is_canonical_alias(alias)):
            continue
        kept.append(alias)
    return kept


def _is_canonical_alias(value: str) -> bool:
    """Whether a version string spells a delivery alias (must not shadow one)."""
    try:
        parse_tag(value)
    except PublishError:
        return False
    return True


def runtime_aliases(environment: str, channel: str) -> list[str]:
    """Human-friendly runtime tags derived from the locked channel bytes.

    Pure over packaged lock bytes: the same lock always yields the same
    aliases. Release floats ``latest`` (plus the verbatim upstream tag
    when the lock pins exactly one); rolling floats ``rolling`` (plus
    ``rolling-<rev12>`` when the lock pins exactly one git revision).
    Discovery aliases only; never acquisition identity.
    """
    if channel not in {"release", "rolling"}:
        return []
    try:
        descriptor = json.loads(packaged_asset(environment, "provider.json").read_bytes())
        channels = descriptor.get("channels") if isinstance(descriptor, dict) else None
        entry = channels.get(channel) if isinstance(channels, dict) else None
        if (not isinstance(entry, dict) or entry.get("status") != "locked"
                or not isinstance(entry.get("lock"), str) or not entry["lock"]):
            return []
        lock = json.loads(packaged_asset(environment, entry["lock"]).read_bytes())
        sources = lock.get("sources") if isinstance(lock, dict) else None
    except (OSError, ValueError):
        return []
    return aliases_for_sources(sources, channel)


def require_digest_reference(reference: str) -> dict:
    """Accept only immutable digest references; tag aliases are rejected."""
    _require(isinstance(reference, str), "artifact reference must be a string")
    match = _DIGEST_REF.fullmatch(reference.strip())
    _require(match is not None, f"acquisition requires a digest reference (repo@sha256:<hex>); refusing alias: {reference}")
    return {"repository": match["repo"], "digest": "sha256:" + match["digest"], "sha256": match["digest"]}


def validate_action_inputs(values: dict) -> dict:
    """Validate reusable-action inputs; fail closed on unknown or bad values."""
    _require(isinstance(values, dict), "action inputs must be an object")
    unknown = set(values) - set(ACTION_INPUTS)
    _require(not unknown, "unknown action inputs: " + ", ".join(sorted(unknown)))
    normalized = {}
    for name, spec in ACTION_INPUTS.items():
        value = values.get(name, spec.get("default", ""))
        _require(isinstance(value, str), f"action input must be a string: {name}")
        value = value.strip()
        if spec.get("required"):
            _require(bool(value), f"action input is required: {name}")
        normalized[name] = value
    _require(_TAG_ENV.fullmatch(normalized["environment"]), "action environment must be a catalogue ID")
    _require(normalized["channel"] in {"release", "rolling"}, "action channel must be release or rolling")
    _require(normalized["mode"] in {"direct", "native"}, "action mode must be direct or native")
    normalized["registry"] = effective_registry(normalized["registry"], normalized["environment"])
    _require(re.fullmatch(r"sha256:[0-9a-f]{64}", normalized["handoff-digest"]), "action handoff-digest must be sha256:<hex>")
    try:
        command = json.loads(normalized["command"])
    except ValueError as error:
        raise PublishError("action command must be a JSON array of strings") from error
    _require(isinstance(command, list) and command and all(isinstance(a, str) and a and "\0" not in a for a in command),
             "action command must be a non-empty JSON array of literal argv strings")
    normalized["command_argv"] = command
    entries = []
    if normalized["inputs"]:
        # Names fail fast on padding (a padded name would fail opaquely in
        # the runner); values pass through byte-identical unless empty.
        # Duplicate names stay the CLI's job and are caught downstream.
        for line in normalized["inputs"].splitlines():
            name, sep, value = line.partition("=")
            _require(sep, "action inputs must be NAME=VALUE lines")
            _require(name and name == name.strip(), "action inputs names must not carry whitespace")
            _require(value.strip(), "action inputs values must not be empty")
            entries.append(line)
    normalized["input_entries"] = entries
    try:
        timeout = int(normalized["timeout"])
    except ValueError as error:
        raise PublishError("action timeout must be an integer number of seconds") from error
    _require(timeout > 0, "action timeout must be positive")
    normalized["timeout_seconds"] = timeout
    _require("\0" not in normalized["state-dir"] and "\0" not in normalized["working-directory"],
             "action paths must not contain NUL bytes")
    _require(".." not in normalized["working-directory"].replace("\\", "/").split("/"),
             "action working-directory must stay inside the caller checkout")
    return normalized


def action_inputs_from_yml(text: str) -> dict:
    """Parse the `inputs:` block of the authored action.yml (strict shape).

    The block uses two-space indentation with scalar description/required/
    default lines only. Anything else fails closed so drift cannot hide.
    """
    lines = text.splitlines()
    try:
        start = next(i for i, line in enumerate(lines) if line == "inputs:")
    except StopIteration as error:
        raise PublishError("action.yml has no inputs block") from error
    found = {}
    current = None
    for line in lines[start + 1:]:
        if not line.strip() or line.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()
        if indent == 0:
            break
        if indent == 2:
            _require(stripped.endswith(":") and " " not in stripped[:-1], f"unexpected action.yml input line: {stripped}")
            current = stripped[:-1]
            _require(current not in found, f"duplicate action.yml input: {current}")
            found[current] = {}
        elif indent == 4 and current is not None:
            key, sep, value = stripped.partition(":")
            _require(sep and key.strip() in {"description", "required", "default"}, f"unexpected action.yml input field: {stripped}")
            value = value.strip().strip("'\"")
            if key.strip() == "required":
                _require(value in {"true", "false"}, f"action.yml required must be true/false: {stripped}")
                found[current][key.strip()] = value == "true"
            else:
                found[current][key.strip()] = value
        else:
            raise PublishError(f"unexpected action.yml shape: {stripped}")
    _require(found, "action.yml inputs block is empty")
    return found


def _write_tar_gz(files: dict[str, bytes], archive: Path) -> None:
    import gzip
    with archive.open("wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0, filename="") as zipped, \
            tarfile.open(fileobj=zipped, mode="w") as contents:
        for name in sorted(files):
            entry = tarfile.TarInfo(name)
            entry.size = len(files[name])
            entry.mode = 0o644
            entry.mtime = 0
            contents.addfile(entry, io.BytesIO(files[name]))


def _seal_common(output_dir: Path, files: dict[str, bytes], manifest: dict, role: str) -> dict:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    for sentinel in ("sealed-source.tar.gz", "sealed-source.json", "files.sha256"):
        if (output_dir / sentinel).exists():
            raise PublishError("seal output must be a fresh attempt directory")
    payload = dict(files)
    payload["sealed.json"] = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()
    manifest_digest = hashlib.sha256(payload["sealed.json"]).hexdigest()
    sums = "".join(hashlib.sha256(payload[name]).hexdigest() + "  " + name + "\n" for name in sorted(payload))
    payload["SHA256SUMS"] = sums.encode()
    archive = output_dir / "sealed-source.tar.gz"
    _write_tar_gz(payload, archive)
    digest = checksum(archive)
    (output_dir / "files.sha256").write_text(digest + "  sealed-source.tar.gz\n")
    receipt = {"schema_version": SCHEMA_VERSION, "role": "sealed-source", "runtime_role": role,
               "environment": manifest["environment"], "channel": manifest["channel"],
               "archive": archive.name, "archive_sha256": digest, "size_bytes": archive.stat().st_size,
               "manifest_sha256": manifest_digest, "member_count": len(payload),
               "source_count": len(manifest["sources"]), "publication_status": "not-published"}
    if manifest.get("build_key"):
        receipt["build_key"] = manifest["build_key"]
    (output_dir / "sealed-source.json").write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
    return receipt


def seal_sources(spec: dict, resolved: dict, output_dir: Path) -> dict:
    """Seal exact build-input bytes: retained archives, patches, lock, recipe.

    `resolved` is a resolve_sources result whose roster must match the locked
    inputs exactly. The seal carries bytes, never acquisition paths.
    """
    from .build import runtime_inputs
    from .identity import artifact_key
    validate_build_inputs(spec)
    _require(isinstance(resolved, dict), "resolved sources must be an object")
    lock = spec["lock"]
    acquired = list(resolved.get("sources", [])) + list(resolved.get("dependencies", []))
    _require([r.get("source") for r in resolved.get("sources", [])] == lock["sources"]
             and [r.get("source") for r in resolved.get("dependencies", [])] == lock["dependencies"],
             "resolved source roster differs from locked inputs")
    _require(resolved.get("patches") == lock["patches"], "resolved patch roster differs from locked inputs")
    files: dict[str, bytes] = {}
    entries = []
    counters = {"source": 0, "dependency": 0}
    for index, record in enumerate(acquired):
        kind = "source" if index < len(lock["sources"]) else "dependency"
        archive = Path(record["archive"])
        data = archive.read_bytes()
        _require(hashlib.sha256(data).hexdigest() == record["sha256"], "acquired archive digest mismatch")
        # Per-kind index: unique seal member names that match their roster.
        name = f"{kind}-{counters[kind]}.tar"
        counters[kind] += 1
        files[name] = data
        entries.append({"kind": kind, "id": record["source"].get("id", ""), "archive": name,
                        "sha256": record["sha256"], "size": len(data), "source": record["source"]})
    for patch in lock["patches"]:
        target = locked_asset(spec["id"], patch)
        data = target.read_bytes()
        _require(hashlib.sha256(data).hexdigest() == patch.get("sha256"), "sealed patch digest mismatch")
        files["patches/" + Path(patch["path"]).name] = data
    provider_bytes = packaged_asset(spec["id"], "provider.json").read_bytes()
    lock_bytes = packaged_asset(spec["id"], spec["channel_spec"]["lock"]).read_bytes()
    files["provider.json"] = provider_bytes
    files["lock.json"] = lock_bytes
    inputs = runtime_inputs(spec)
    manifest = {"schema_version": SCHEMA_VERSION, "role": "sealed-source", "runtime_role": "runtime",
                "environment": spec["id"], "channel": spec["channel"],
                "build_key": artifact_key("runtime", inputs), "inputs": inputs,
                "sources": entries, "patches": lock["patches"],
                "provider_sha256": hashlib.sha256(provider_bytes).hexdigest(),
                "lock_sha256": hashlib.sha256(lock_bytes).hexdigest()}
    return _seal_common(Path(output_dir), files, manifest, "runtime")


def seal_native_source(spec: dict, output_dir: Path) -> dict:
    """Seal exact native build inputs: upstream archives, target lock, parent.

    The upstream git archives are fetched and hash-verified against the native
    target lock, so the seal holds real source bytes rather than references.
    """
    from .catalog import load_native_target
    from .sources import acquire_source
    _require(isinstance(spec, dict) and spec.get("id"), "native seal requires a loaded environment spec")
    target = spec.get("native_target", "debian13-amd64")
    loaded = load_native_target(spec["id"], spec["channel"], target)
    lock = loaded["native_lock"]
    output_dir = Path(output_dir)
    staging = output_dir / "acquire"
    staging.mkdir(parents=True, exist_ok=False)
    files: dict[str, bytes] = {}
    entries = []
    for index, source in enumerate(lock["sources"]):
        record = acquire_source(source, staging / f"source-{index}")
        data = Path(record["archive"]).read_bytes()
        if source.get("archive_sha256"):
            _require(hashlib.sha256(data).hexdigest() == source["archive_sha256"],
                     "native upstream archive differs from the target lock")
        name = f"source-{index}.tar"
        files[name] = data
        entries.append({"kind": "source", "archive": name, "sha256": hashlib.sha256(data).hexdigest(),
                        "size": len(data), "source": source})
    target_lock_path = loaded["native_target_spec"]["channels"][spec["channel"]]["lock"]
    lock_bytes = packaged_asset(spec["id"], target_lock_path).read_bytes()
    provider_bytes = packaged_asset(spec["id"], "provider.json").read_bytes()
    files["target-lock.json"] = lock_bytes
    files["provider.json"] = provider_bytes
    files["native.recipe.json"] = packaged_asset(spec["id"], "native.recipe.json").read_bytes()
    for asset in lock.get("assets", []):
        data = packaged_asset(spec["id"], asset["path"]).read_bytes()
        _require(hashlib.sha256(data).hexdigest() == asset.get("sha256"), "sealed native asset digest mismatch")
        files["assets/" + Path(asset["path"]).name] = data
    manifest = {"schema_version": SCHEMA_VERSION, "role": "sealed-source", "runtime_role": "native",
                "environment": spec["id"], "channel": spec["channel"], "target": target,
                "sources": entries, "patches": lock.get("patches", []),
                "parent": lock["parent"], "binaries": lock["binaries"],
                "source_companion": lock.get("source_companion"),
                "provider_sha256": hashlib.sha256(provider_bytes).hexdigest(),
                "target_lock_sha256": hashlib.sha256(lock_bytes).hexdigest()}
    return _seal_common(output_dir, files, manifest, "native")


# Tar-posture note (arch #8): this verifier is bound-based (1 GiB/member,
# 4 GiB total, 50k members) rather than roster-strict like bundle.py
# because the roster itself ships inside the archive: the caller first
# authenticates the whole bytes against the seal receipt digest, and this
# function then checks SHA256SUMS/sealed.json manifest-equality within
# extraction bounds. bundle.py instead checks an externally declared
# expected roster. sources.py shares these bounds for the same
# inside-roster reason during companion verification.
def verify_sealed_archive(archive: Path, output_dir: Path) -> dict:
    """Extract a sealed source into a new owned directory and verify every byte."""
    from .licenses import relative_path
    archive, output_dir = Path(archive), Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=False)
    seen: set[str] = set()
    total = 0
    try:
        with tarfile.open(archive) as contents:
            for member in contents:
                name = relative_path(member.name)
                if not member.isfile() or name in seen or member.size > 1024**3:
                    raise PublishError("unsafe/duplicate/oversized sealed source member")
                total += member.size
                if total > 4 * 1024**3 or len(seen) >= 50000:
                    raise PublishError("sealed source exceeds extraction bounds")
                seen.add(name)
                destination = output_dir / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                import shutil
                with contents.extractfile(member) as source, destination.open("xb") as target:
                    shutil.copyfileobj(source, target)
        expected = {}
        for line in (output_dir / "SHA256SUMS").read_text().splitlines():
            digest, name = line.split("  ", 1)
            relative_path(name)
            if name in expected:
                raise PublishError("duplicate sealed manifest entry")
            expected[name] = digest
        if set(expected) != seen - {"SHA256SUMS"}:
            raise PublishError("sealed source manifest roster mismatch")
        for name, digest in expected.items():
            if checksum(output_dir / name) != digest:
                raise PublishError("sealed source checksum mismatch: " + name)
        manifest = json.loads((output_dir / "sealed.json").read_text())
        if manifest.get("role") != "sealed-source" or manifest.get("schema_version") != SCHEMA_VERSION:
            raise PublishError("sealed source manifest identity mismatch")
        for entry in manifest["sources"]:
            name = relative_path(entry["archive"])
            if expected.get(name) != entry["sha256"] or (output_dir / name).stat().st_size != entry["size"]:
                raise PublishError("sealed source payload manifest mismatch: " + name)
        return manifest
    except (tarfile.TarError, OSError, KeyError, ValueError) as error:
        if isinstance(error, PublishError):
            raise
        raise PublishError("invalid sealed source: " + str(error)) from error


def verify_readback(sealed_receipt_path: Path, pulled_dir: Path, *, transcript_path: Path,
                    extract_dir: Path) -> dict:
    """Verify anonymously pulled bytes against the sealed receipt, byte for byte.

    The transcript must show the anonymous transport (fresh empty credential
    directories plus the pull output). This function binds the transcript bytes
    to the proof; reviewers inspect the transcript itself for the anonymity
    evidence. A missing, private, expired, or altered companion fails here.
    """
    receipt = _read_json(sealed_receipt_path)
    _require(receipt.get("role") == "sealed-source", "readback requires a sealed-source receipt")
    sealed_name = _need(receipt, "archive", "sealed receipt lacks the sealed archive name")
    sealed_digest = _need(receipt, "archive_sha256", "sealed receipt lacks the sealed archive digest")
    pulled_dir, extract_dir = Path(pulled_dir), Path(extract_dir)
    archive = pulled_dir / sealed_name
    _require(archive.is_file() and not archive.is_symlink(), "pulled sealed archive is missing")
    pulled_digest = checksum(archive)
    _require(pulled_digest == sealed_digest,
             f"anonymous readback digest mismatch: pulled {pulled_digest} != sealed {sealed_digest}")
    pulled_receipt = pulled_dir / "sealed-source.json"
    _require(pulled_receipt.is_file(), "pulled sealed receipt is missing")
    _require(pulled_receipt.read_bytes() == Path(sealed_receipt_path).read_bytes(),
             "pulled sealed receipt bytes differ from the sealed receipt")
    manifest = verify_sealed_archive(archive, extract_dir)
    manifest_env = _need(manifest, "environment", "sealed manifest lacks the environment identity")
    manifest_channel = _need(manifest, "channel", "sealed manifest lacks the channel identity")
    receipt_env = _need(receipt, "environment", "sealed receipt lacks the environment identity")
    receipt_channel = _need(receipt, "channel", "sealed receipt lacks the channel identity")
    _require(manifest_env == receipt_env and manifest_channel == receipt_channel,
             "readback manifest catalogue identity mismatch")
    transcript = Path(transcript_path)
    _require(transcript.is_file() and not transcript.is_symlink() and transcript.stat().st_size > 0,
             "anonymous-transport transcript is missing or empty")
    receipt_role = _need(receipt, "runtime_role", "sealed receipt lacks the runtime role")
    proof = {"schema_version": SCHEMA_VERSION, "role": "readback-proof",
             "sealed_archive_sha256": sealed_digest, "pulled_archive_sha256": pulled_digest,
             "manifest_sha256": _need(receipt, "manifest_sha256", "sealed receipt lacks the manifest digest"),
             "member_count": _need(receipt, "member_count", "sealed receipt lacks the member count"),
             "environment": receipt_env, "channel": receipt_channel,
             "runtime_role": receipt_role,
             "transcript_sha256": checksum(transcript), "transcript_bytes": transcript.stat().st_size,
             "anonymous_transport": "caller-executed with fresh empty credential directories; see transcript bytes"}
    write_receipt(extract_dir.parent / "readback-proof.json", proof)
    return proof


def check_input_match(sealed_manifest: dict, build_receipt_path: Path, spec: dict, *, manifest: dict | None = None) -> dict:
    """Require the built binary's inputs to equal the sealed inputs exactly.

    A renamed/missing/extra input is reported as newly discovered or missing;
    a digest difference on a known input is an input mismatch. Either stops
    binary upload. Native receipts carry the manifest in a sibling file, so
    native callers pass it explicitly.
    """
    receipt = _read_json(build_receipt_path)
    _require(isinstance(sealed_manifest, dict), "sealed manifest must be an object")
    role = sealed_manifest.get("runtime_role")
    _require(role in {"runtime", "native"}, "sealed manifest lacks a runtime role")
    _require(sealed_manifest.get("environment") == spec.get("id"), "sealed environment differs from selected spec")
    _require(sealed_manifest.get("channel") == spec.get("channel"), "sealed channel differs from selected spec")
    if role == "runtime":
        return _check_runtime_inputs(sealed_manifest, receipt, spec)
    return _check_native_inputs(sealed_manifest, receipt, spec, manifest)


def _check_runtime_inputs(sealed: dict, receipt: dict, spec: dict) -> dict:
    from .build import runtime_inputs
    from .identity import artifact_key
    resolved = list(receipt.get("resolved_sources", {}).get("sources", [])) + \
        list(receipt.get("resolved_sources", {}).get("dependencies", []))
    _require(resolved, "build receipt carries no resolved sources")
    sealed_entries = _need(sealed, "sources", "sealed manifest lacks the source roster")
    _require(isinstance(sealed_entries, list), "sealed manifest source roster must be a list")
    if len(resolved) != len(sealed_entries):
        if len(resolved) > len(sealed_entries):
            raise PublishError(f"newly discovered inputs: {len(resolved) - len(sealed_entries)} extra resolved source(s)")
        raise PublishError(f"missing sealed inputs: {len(sealed_entries) - len(resolved)} resolved source(s) absent")
    for position, entry in enumerate(sealed_entries):
        _require(isinstance(entry, dict), f"sealed manifest source record {position} must be an object")
    sealed_sources = [_need(e, "source", f"sealed manifest source record {n} lacks its declaration")
                      for n, e in enumerate(sealed_entries)]
    for position, record in enumerate(resolved):
        _require(isinstance(record, dict) and isinstance(record.get("source"), dict),
                 f"build receipt source record mismatch at position {position}")
        expected = sealed_entries[position]
        expected_source = _need(expected, "source", f"sealed manifest source record {position} lacks its declaration")
        label = record["source"].get("id") or f"position {position}"
        if record["source"] != expected_source:
            if record["source"] not in sealed_sources:
                raise PublishError(f"newly discovered input: {label}")
            raise PublishError(f"input declaration mismatch: {label}")
        expected_digest = _need(expected, "sha256", f"sealed manifest source record {position} lacks its digest")
        if record.get("sha256") != expected_digest:
            raise PublishError(f"input mismatch: {label} built {record.get('sha256')} != sealed {expected_digest}")
    if receipt.get("build_key") != sealed.get("build_key"):
        raise PublishError("input mismatch: build key differs from the sealed build key")
    live_key = artifact_key("runtime", runtime_inputs(spec))
    if live_key != receipt.get("build_key"):
        raise PublishError("input mismatch: live catalogue inputs differ from the built key")
    build_key = _need(receipt, "build_key", "build receipt lacks the build key")
    return {"role": "runtime", "matched_inputs": len(sealed_entries), "build_key": build_key}


def _check_native_inputs(sealed: dict, receipt: dict, spec: dict, manifest: dict | None) -> dict:
    _require(isinstance(manifest, dict), "native input match requires the bundle manifest")
    built_sources = manifest.get("source", {}).get("sources", [])
    sealed_entries = _need(sealed, "sources", "sealed manifest lacks the source roster")
    _require(isinstance(sealed_entries, list), "sealed manifest source roster must be a list")
    sealed_sources = []
    for position, entry in enumerate(sealed_entries):
        _require(isinstance(entry, dict), f"sealed manifest source record {position} must be an object")
        sealed_sources.append(_need(entry, "source",
                                    f"sealed manifest source record {position} lacks its declaration"))
    if len(built_sources) != len(sealed_sources):
        raise PublishError("newly discovered or missing native source inputs")
    for position, (built, expected) in enumerate(zip(built_sources, sealed_sources)):
        if built != expected:
            raise PublishError(f"input mismatch: native source {position} differs from sealed inputs")
        expected_digest = _need(sealed_entries[position], "sha256",
                                f"sealed manifest source record {position} lacks its digest")
        if not isinstance(built, dict) or built.get("archive_sha256") != expected_digest:
            raise PublishError(f"input mismatch: native source {position} bytes differ from sealed inputs")
    if manifest.get("source", {}).get("patches") != sealed.get("patches"):
        raise PublishError("input mismatch: native patches differ from sealed inputs")
    _require(isinstance(receipt.get("files", []), list), "build receipt file roster must be a list")
    roster = {}
    for entry in receipt.get("files", []):
        path = _need(entry, "path", "build receipt file record lacks its path")
        roster[path] = _need(entry, "sha256", f"build receipt file record {path} lacks its digest")
    for binary in sealed.get("binaries", []):
        path = _need(binary, "path", "sealed manifest binary record lacks its path")
        digest = _need(binary, "sha256", f"sealed manifest binary record {path} lacks its digest")
        if roster.get(path) != digest:
            raise PublishError(f"input mismatch: native binary {path} differs from sealed inputs")
    if receipt.get("parent") != sealed.get("parent"):
        raise PublishError("input mismatch: native parent differs from sealed inputs")
    features = manifest.get("build", {}).get("identity", {}).get("inputs", {}).get("features", {})
    if features.get("target_lock_sha256") != sealed.get("target_lock_sha256"):
        raise PublishError("input mismatch: native target lock differs from sealed inputs")
    return {"role": "native", "matched_inputs": len(sealed_sources), "build_key": receipt.get("build_key", "")}


def _catalogue_binding(spec: dict) -> dict:
    provider_bytes = packaged_asset(spec["id"], "provider.json").read_bytes()
    binding = {"environment": spec["id"], "channel": spec["channel"],
               "provider_sha256": hashlib.sha256(provider_bytes).hexdigest()}
    lock_path = spec.get("channel_spec", {}).get("lock")
    if lock_path:
        binding["lock"] = lock_path
        binding["lock_sha256"] = hashlib.sha256(packaged_asset(spec["id"], lock_path).read_bytes()).hexdigest()
    native_lock = spec.get("native_target_spec", {}).get("channels", {}).get(spec.get("channel"), {}).get("lock")
    if native_lock:
        binding["native_lock"] = native_lock
        binding["native_lock_sha256"] = hashlib.sha256(packaged_asset(spec["id"], native_lock).read_bytes()).hexdigest()
    if spec.get("native_target"):
        binding["target"] = spec["native_target"]
    return binding


def _handoff_schema(value: dict) -> None:
    _require(isinstance(value, dict), "handoff must be an object")
    _require(value.get("schema_version") == SCHEMA_VERSION, "unsupported handoff schema_version")
    for key in ("registry", "catalogue", "source", "binary", "admission", "readback", "producer", "exposure"):
        _require(key in value, f"handoff requires {key}")
    _require("digest" not in value and "handoff_sha256" not in value and "self_digest" not in value,
             "handoff must not embed its own digest (circular self-digest refused)")
    _require(_REPO.fullmatch(value["registry"]), "handoff registry must be a repository path")
    for key in ("source", "binary"):
        entry = value[key]
        _require(_SHA256.fullmatch(entry.get("manifest_sha256", "")),
                 f"handoff {key} requires its registry manifest digest")
        _require(entry.get("tag"), f"handoff {key} requires its recorded tag alias")
        _require(entry.get("reference", "") == value["registry"] + "@sha256:" + entry["manifest_sha256"],
                 f"handoff {key} reference must bind its manifest digest")
    _require(_SHA256.fullmatch(value["source"].get("file_sha256", "")),
             "handoff source requires the sealed file digest")
    if value["binary"]["kind"] == "bundle":
        _require(_SHA256.fullmatch(value["binary"].get("file_sha256", "")),
                 "handoff bundle binary requires its file digest")
    else:
        _require(value["binary"].get("engine_id", "").startswith("sha256:"),
                 "handoff image binary requires its engine ID")
    admission = value["admission"]
    _require(admission.get("status") in {"eligible", "blocked"}, "handoff admission requires an eligible/blocked verdict")
    _require(isinstance(admission.get("blockers"), list), "handoff admission requires a blockers list")


def show_handoff(path: Path) -> dict:
    """Validate a handoff file strictly and return its digest bindings."""
    value = _read_json(path)
    _handoff_schema(value)
    return value


def _claimed_artifact_blocker(*, artifact_kind: str, artifact_reference: str, artifact_digest: str,
                             build_receipt_path: Path) -> str | None:
    """Bind the claimed artifact to the build receipt's own artifact field.

    Input matching alone cannot catch a swapped claim: the sealed inputs
    describe what was built, not which bytes the claim names. Images bind
    by engine reference (an engine ID is the identity); bundles bind by
    file digest only, since the claim path legitimately differs from the
    build output path across CI jobs while the bytes must not.
    """
    built = _read_json(build_receipt_path).get("artifact")
    if not isinstance(built, dict):
        return "claimed artifact is unbound: build receipt carries no artifact identity"
    if artifact_kind == "docker-local":
        if built.get("reference") != artifact_reference or built.get("sha256") != artifact_digest:
            return ("claimed artifact differs from the built artifact: "
                    f"claim {artifact_reference} != receipt {built.get('reference')}")
        return None
    if built.get("sha256") != artifact_digest:
        return ("claimed artifact differs from the built artifact: "
                f"claim sha256:{artifact_digest} != receipt sha256:{built.get('sha256')}")
    return None


def admit(*, artifact_kind: str, artifact_reference: str, artifact_digest: str, platform: str,
         sealed_receipt_path: Path, sealed_manifest: dict, readback_proof: dict,
         build_receipt_path: Path, spec: dict, registry: str, evidence_dir: Path | None,
         out_dir: Path, producer: dict, manifest: dict | None = None,
         source_manifest_digest: str, source_manifest_path: Path) -> dict:
    """Run the delivery gate and write the admission plus the verdict.

    The admission records the factual bindings and the verdict; the verdict
    file exists for workflow gating. A blocked verdict means binary
    upload/cache export must stop. The handoff is written later by expose(),
    once the (gated) upload fixes the registry digest.
    """
    _require(artifact_kind in {"docker-local", "bundle"}, "admission artifact kind must be docker-local or bundle")
    _require(_SHA256.fullmatch(artifact_digest), "admission artifact digest must be full lowercase SHA-256")
    _require(isinstance(platform, str) and _PLATFORM.fullmatch(platform),
             "admission platform must be os/arch in lowercase alphanumerics")
    if artifact_kind == "docker-local":
        _require(artifact_reference == "sha256:" + artifact_digest, "docker-local admission requires the exact engine image ID")
    else:
        _require(Path(artifact_reference).is_file(), "bundle admission requires the local artifact bytes")
    _require(isinstance(producer, dict) and _SHA256.fullmatch(producer.get("p11lab_wheel_sha256", "")),
             "admission requires the producer wheel identity")
    receipt = _read_json(sealed_receipt_path)
    _require(receipt.get("role") == "sealed-source", "admission requires a sealed-source receipt")
    _require(readback_proof.get("role") == "readback-proof", "admission requires a readback proof")
    _require(readback_proof.get("pulled_archive_sha256") == receipt.get("archive_sha256"),
             "source companion missing or readback does not match the sealed source")
    _require(readback_proof.get("manifest_sha256") == receipt.get("manifest_sha256"),
             "readback manifest differs from the sealed manifest")
    _require(_SHA256.fullmatch(source_manifest_digest or ""),
             "admission requires the pushed source manifest digest")
    try:
        pushed_manifest = json.loads(Path(source_manifest_path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise PublishError("invalid pushed source manifest") from error
    _require(checksum(source_manifest_path) == source_manifest_digest,
             "pushed source manifest bytes differ from their digest")
    _require(isinstance(pushed_manifest, dict) and isinstance(pushed_manifest.get("layers"), list)
             and all(isinstance(layer, dict) for layer in pushed_manifest["layers"]),
             "pushed source manifest shape mismatch")
    layer_digests = {layer.get("digest") for layer in pushed_manifest["layers"]}
    sealed_digest = _need(receipt, "archive_sha256", "sealed receipt lacks the sealed archive digest")
    _require("sha256:" + sealed_digest in layer_digests
             and "sha256:" + checksum(sealed_receipt_path) in layer_digests,
             "pushed source manifest does not carry the sealed bytes")
    match = check_input_match(sealed_manifest, build_receipt_path, spec, manifest=manifest)
    if sealed_manifest.get("runtime_role") == "native":
        # The native record keeps the verified value: a forgotten --platform
        # (or garbage that passed the shape check) must not flow into the
        # admission. The runtime role is cross-checked later against the
        # pulled engine inspect at expose time instead.
        built_platform = manifest.get("platform") if isinstance(manifest, dict) else None
        _require(built_platform == platform,
                 f"admission platform {platform} differs from the native manifest platform {built_platform}")
    blockers: list[str] = []
    binding = _claimed_artifact_blocker(artifact_kind=artifact_kind, artifact_reference=artifact_reference,
                                        artifact_digest=artifact_digest, build_receipt_path=build_receipt_path)
    if binding is not None:
        blockers.append(binding)
    content: dict = {"status": "blocked", "blockers": ["actual-content source/license evidence absent; distribution unreviewed"]}
    if evidence_dir is not None and (Path(evidence_dir) / "source-companion.json").is_file():
        from .licenses import assess_distribution
        from .models import ArtifactRef
        artifact = ArtifactRef(artifact_kind, artifact_reference, artifact_digest, platform)
        content = assess_distribution(artifact, Path(evidence_dir))
        if content.get("status") != "eligible":
            blockers.extend(content.get("blockers", ["content admission refused"]))
    else:
        blockers.extend(content["blockers"])
    _require(_REPO.fullmatch(registry), "admission registry must be a repository path")
    role = _need(sealed_manifest, "runtime_role", "sealed manifest lacks the runtime role")
    environment = _need(sealed_manifest, "environment", "sealed manifest lacks the environment identity")
    channel = _need(sealed_manifest, "channel", "sealed manifest lacks the channel identity")
    proof_pulled = _need(readback_proof, "pulled_archive_sha256", "readback proof lacks the pulled archive digest")
    proof_transcript = _need(readback_proof, "transcript_sha256", "readback proof lacks the transcript digest")
    proof_transport = _need(readback_proof, "anonymous_transport", "readback proof lacks the transport record")
    admission = {"schema_version": SCHEMA_VERSION, "role": "admission", "registry": registry,
                 "catalogue": _catalogue_binding(spec) | {"build_key": match["build_key"], "runtime_role": role},
                 "source": {"manifest_sha256": source_manifest_digest, "file_sha256": sealed_digest,
                            "size_bytes": _need(receipt, "size_bytes", "sealed receipt lacks the archive size"),
                            "tag": artifact_tag("src", environment, channel, sealed_digest),
                            "reference": registry + "@sha256:" + source_manifest_digest},
                 "local_binary": {"kind": artifact_kind, "sha256": artifact_digest, "platform": platform},
                 "verdict": {"status": "eligible" if not blockers else "blocked", "blockers": sorted(set(blockers)),
                             "content_status": content.get("status"), "matched_inputs": match["matched_inputs"],
                             "readback_transcript_sha256": proof_transcript},
                 "readback": {"pulled_archive_sha256": proof_pulled,
                              "transcript_sha256": proof_transcript,
                              "anonymous_transport": proof_transport},
                 "producer": producer}
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=False)
    write_receipt(out / "admission.json", admission)
    verdict = {"schema_version": SCHEMA_VERSION, "status": admission["verdict"]["status"],
               "blockers": admission["verdict"]["blockers"]}
    (out / "verdict.json").write_text(json.dumps(verdict, sort_keys=True, indent=2) + "\n")
    return {"status": verdict["status"], "blockers": verdict["blockers"],
            "admission": str(out / "admission.json"), "verdict": str(out / "verdict.json")}


def expose(*, admission_path: Path, pushed_digest: str, pushed_tag: str, pushed_size: int,
           local_inspect_path: Path | None, pulled_inspect_path: Path | None,
           pulled_bundle_path: Path | None, registry: str, out_dir: Path) -> dict:
    """Bind an uploaded binary to its admission after anonymous binary readback.

    The registry index digest is only known after the push, so this step runs
    after the (verdict-gated) upload. Byte identity is proven by comparing the
    anonymously pulled bytes against the local pre-push identity: engine Id
    plus layer DiffIDs for images, exact file bytes for bundles. The handoff
    stamps the admission verdict; a blocked verdict must still stop public
    exposure at the workflow/action layer.
    """
    admission = _read_json(admission_path)
    _require(admission.get("role") == "admission", "exposure requires an admission record")
    for key in ("registry", "catalogue", "source", "local_binary", "verdict", "readback", "producer"):
        _require(key in admission, f"admission record requires {key}")
    _require(isinstance(admission["catalogue"], dict) and isinstance(admission["local_binary"], dict)
             and isinstance(admission["verdict"], dict), "admission record shape mismatch")
    _require(admission["catalogue"].get("runtime_role") in {"runtime", "native"},
             "admission record lacks a runtime role")
    _require(_SHA256.fullmatch(pushed_digest or ""), "exposed digest must be full lowercase SHA-256")
    _require(registry == admission["registry"], "exposure registry differs from the admitted registry")
    _require(_REPO.fullmatch(registry), "exposure registry must be a repository path")
    catalogue = admission["catalogue"]
    role = catalogue["runtime_role"]
    local = admission["local_binary"]
    _require(local.get("kind") in {"docker-local", "bundle"}
             and _SHA256.fullmatch(local.get("sha256", "")) and isinstance(local.get("platform"), str),
             "admission local binary identity mismatch")
    if role == "runtime":
        _require(local["kind"] == "docker-local", "runtime exposure requires a docker-local binary")
        _require(pulled_bundle_path is None, "runtime exposure compares engine inspects, not bundle bytes")
        _require(local_inspect_path is not None and pulled_inspect_path is not None,
                 "runtime exposure requires local and pulled engine inspects")
        try:
            before = json.loads(Path(local_inspect_path).read_text())
            after = json.loads(Path(pulled_inspect_path).read_text())
        except (OSError, ValueError) as error:
            raise PublishError("invalid engine inspect document") from error
        before, after = (before[0] if isinstance(before, list) else before,
                         after[0] if isinstance(after, list) else after)
        _require(isinstance(before, dict) and isinstance(after, dict), "engine inspect must describe one image")
        _require(before.get("Id") == "sha256:" + local["sha256"], "local engine identity differs from admission")
        _require(after.get("Id") == before.get("Id"), "pulled binary engine ID differs from the local binary")
        _require(after.get("RootFS", {}).get("Layers") == before.get("RootFS", {}).get("Layers"),
                 "pulled binary layers differ from the local binary")
        _require(registry + "@sha256:" + pushed_digest in (after.get("RepoDigests") or []),
                 "pulled binary does not carry the exposed registry digest")
        _require(isinstance(after.get("Os"), str) and isinstance(after.get("Architecture"), str)
                 and after["Os"] + "/" + after["Architecture"] == local["platform"],
                 "pulled binary platform differs from admission")
        binary = {"kind": "docker-local", "manifest_sha256": pushed_digest, "platform": local["platform"],
                  "engine_id": before["Id"], "size_bytes": pushed_size}
    else:
        _require(role == "native" and local["kind"] == "bundle", "native exposure requires a bundle binary")
        _require(local_inspect_path is None and pulled_inspect_path is None,
                 "native exposure compares bundle bytes, not engine inspects")
        _require(pulled_bundle_path is not None and Path(pulled_bundle_path).is_file(),
                 "native exposure requires the anonymously pulled bundle bytes")
        pulled_digest = checksum(pulled_bundle_path)
        _require(pulled_digest == local["sha256"], "pulled bundle bytes differ from the admitted binary")
        binary = {"kind": "bundle", "manifest_sha256": pushed_digest, "file_sha256": local["sha256"],
                  "platform": local["platform"], "size_bytes": pushed_size}
    _require(isinstance(pushed_size, int) and pushed_size > 0, "exposed size must be positive")
    # Tag aliases embed the digest the consumer verifies next: the registry
    # index digest for images, the file digest for ORAS artifacts.
    tag_digest = pushed_digest if role == "runtime" else local["sha256"]
    catalogue_env = _need(catalogue, "environment", "admission catalogue lacks the environment identity")
    catalogue_channel = _need(catalogue, "channel", "admission catalogue lacks the channel identity")
    expected_tag = artifact_tag("rt" if role == "runtime" else "native", catalogue_env,
                                catalogue_channel, tag_digest,
                                catalogue.get("target") if role == "native" else None)
    _require(pushed_tag == expected_tag, f"exposed tag {pushed_tag} is not the delivery alias {expected_tag}")
    binary["tag"] = pushed_tag
    # Runtime images carry human-friendly aliases (version/floating tags)
    # pushed alongside the canonical digest alias; native bundles keep the
    # canonical alias only (OCI tags share one namespace per repository).
    binary["aliases"] = runtime_aliases(catalogue_env, catalogue_channel) if role == "runtime" else []
    binary["reference"] = registry + "@sha256:" + pushed_digest
    handoff = {"schema_version": SCHEMA_VERSION, "registry": registry, "catalogue": catalogue,
               "source": admission["source"], "binary": binary, "admission": admission["verdict"],
               "readback": admission["readback"], "producer": admission["producer"],
               "exposure": {"pushed_digest": pushed_digest, "pushed_tag": pushed_tag,
                            "byte_identity": "anonymous binary readback matches the admitted binary"}}
    _handoff_schema(handoff)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=False)
    write_receipt(out / "handoff.json", handoff)
    return {"handoff": str(out / "handoff.json"), "reference": binary["reference"],
            "status": admission["verdict"]["status"]}
