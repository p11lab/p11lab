"""Shared lifecycle contracts for subsequent build and run integrations."""

from dataclasses import dataclass, fields
import json
from pathlib import Path
import re
from types import MappingProxyType
from typing import Any, Literal


_IDENTITY_SCHEMA = 'p11lab.proxy-build-identity.v1'
_DAEMON_PATH = 'bin/pkcs11-proxy-ng'
_CLI_PATH = 'bin/pkcs11-proxy-ng-cli'
_SHIM_PATH = 'lib/libpkcs11_proxy_ng_shim.so'
_PRODUCT_PATHS = (_DAEMON_PATH, _CLI_PATH, _SHIM_PATH)
_CLIENT_PATHS = (_CLI_PATH, _SHIM_PATH)
_SHA256 = re.compile(r'[0-9a-f]{64}\Z')
_SHA1 = re.compile(r'[0-9a-f]{40}\Z')
_SAFE_NAME = re.compile(r'[A-Za-z0-9_.+\-]+\Z')
_CALLER_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:\-]{0,127}\Z')


def canonical_json_bytes(value: object) -> bytes:
    """Canonical JSON bytes shared by identity digests and record conversion.

    Same form as the producer observation canonicalization (sorted keys,
    compact separators): digest stability must never depend on dict order.
    """
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def _record_error(field: str, detail: str) -> ValueError:
    return ValueError('proxy identity record invalid: field %r %s' % (field, detail))


def _freeze_record_value(value: object) -> object:
    """Recursively freeze validated JSON-shaped record data.

    Mappings become read-only proxies and sequences become tuples, so a
    validated record refuses in-place mutation at any depth. Every mapping
    or sequence the validators accept — including dict/list subclasses —
    freezes here, and already-frozen inputs re-freeze into fresh,
    independent containers (idempotent). Only applied to fully validated
    field values, whose nesting depth is schema-bounded.
    """
    if isinstance(value, dict):
        return MappingProxyType(
            {key: _freeze_record_value(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_record_value(item) for item in value)
    if isinstance(value, MappingProxyType):
        return MappingProxyType(
            {key: _freeze_record_value(item) for key, item in value.items()})
    if isinstance(value, tuple):
        return tuple(_freeze_record_value(item) for item in value)
    return value


def _thaw_record_value(value: object) -> Any:
    """Return independent plain JSON-shaped data for a frozen record value.

    Frozen mappings/sequences become fresh exact dicts/lists; any plain or
    subclass containers reaching this helper are likewise copied, so
    exports never alias record storage or caller inputs.
    """
    if isinstance(value, MappingProxyType):
        return {key: _thaw_record_value(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_record_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _thaw_record_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_thaw_record_value(item) for item in value]
    return value


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _is_sha1(value: object) -> bool:
    return isinstance(value, str) and _SHA1.fullmatch(value) is not None


def _is_text(value: object, limit: int) -> bool:
    return isinstance(value, str) and 0 < len(value) <= limit


def _check_product(value: object, field: str, path: str) -> None:
    if not isinstance(value, dict) or set(value) != {'path', 'size', 'mode', 'sha256'}:
        raise _record_error(field, 'requires {path, size, mode, sha256}')
    assert isinstance(value, dict)
    if value['path'] != path:
        raise _record_error(field, 'path must be %r' % path)
    if type(value['size']) is not int or value['size'] < 0:
        raise _record_error(field, 'size must be a non-negative int')
    if type(value['mode']) is not int or not 0 <= value['mode'] <= 0o777:
        raise _record_error(field, 'mode must be an int 0..0o777')
    if not _is_sha256(value['sha256']):
        raise _record_error(field, 'sha256 must be 64 hex')


def _check_abi(value: object) -> None:
    keys = {'decision', 'runtime_qualification', 'floors', 'needed', 'interpreters',
            'shim_exports', 'version_requirements', 'symbol_versions'}
    if not isinstance(value, dict) or set(value) != keys:
        raise _record_error('abi', 'requires %s' % sorted(keys))
    assert isinstance(value, dict)
    if value['decision'] != 'conforming-recorded':
        raise _record_error('abi', 'decision must be conforming-recorded')
    if value['runtime_qualification'] != 'not-performed':
        raise _record_error('abi', 'runtime_qualification must be not-performed')
    for sub in ('floors', 'needed', 'interpreters', 'version_requirements', 'symbol_versions'):
        if not isinstance(value[sub], dict) or set(value[sub]) != set(_PRODUCT_PATHS):
            raise _record_error('abi', '%s must cover exactly the three product paths' % sub)
    for path, files in value['floors'].items():
        if not isinstance(files, dict) or not all(
                _is_text(name, 256) and isinstance(libs, dict) and bool(libs) and all(
                    _is_text(lib, 256) and _is_text(version, 64)
                    for lib, version in libs.items()) for name, libs in files.items()):
            raise _record_error('abi', 'floors %s must map file to {lib: version}' % path)
    for path, names in value['needed'].items():
        if not isinstance(names, list) or not all(_is_text(name, 256) for name in names):
            raise _record_error('abi', 'needed %s must be a string list' % path)
    for path, interpreter in value['interpreters'].items():
        if interpreter is not None and not _is_text(interpreter, 256):
            raise _record_error('abi', 'interpreters %s must be null or a string' % path)
    exports = value['shim_exports']
    if (not isinstance(exports, list) or not all(_is_text(name, 256) for name in exports)
            or sorted(exports) != exports or len(set(exports)) != len(exports)):
        raise _record_error('abi', 'shim_exports must be a sorted unique string list')
    for path, rows in value['version_requirements'].items():
        if (not isinstance(rows, list) or not all(
                isinstance(row, dict) and set(row) == {'file', 'name'}
                and _is_text(row['file'], 256) and _is_text(row['name'], 256) for row in rows)):
            raise _record_error('abi', 'version_requirements %s rows must be {file, name}' % path)
    for path, rows in value['symbol_versions'].items():
        if (not isinstance(rows, list) or not all(
                isinstance(row, dict) and set(row) == {'symbol', 'file', 'version'}
                and _is_text(row['symbol'], 256) and _is_text(row['file'], 256)
                and _is_text(row['version'], 256) for row in rows)):
            raise _record_error('abi', 'symbol_versions %s rows must be {symbol, file, version}' % path)


@dataclass(frozen=True)
class ProxyBuildIdentityV1:
    """Immutable selected proxy-build identity (daemon/CLI/shim as one build).

    Every field is JSON-shaped plain data validated at construction; use
    from_dict for untrusted dicts (CLI manifests, recorded claims) and to_dict
    for receipts and validator boundaries. Validated fields are stored
    recursively immutable (read-only mappings, tuples), so sharing one
    instance through RunSpec, resolvers, and gates is safe: in-place mutation
    raises at any depth, and to_dict exports independent plain containers.
    """

    schema: str
    schema_version: int
    origin: str
    source_commit: str | None
    source_tree: str
    source_archive: dict | None
    source_members: dict
    content_seal: str | None
    cargo_lock_sha256: str
    vendor_packages: list
    toolchain_manifest_sha256: str
    toolchain_image: dict
    rust_protoc: dict
    target: str
    packages: list
    features: str
    profile: dict
    rustflags: list
    cargo_args: list
    controller_cargo_config_sha256: str
    build_script_sha256: str
    daemon: dict
    cli: dict
    shim: dict
    abi: dict
    daemon_config_sha256: str
    entrypoint_sha256: str
    hook_hashes: list
    build_context_digest: str
    caller: dict
    provider_parent: dict

    def __post_init__(self) -> None:
        if self.schema != _IDENTITY_SCHEMA:
            raise _record_error('schema', 'must be %r' % _IDENTITY_SCHEMA)
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise _record_error('schema_version', 'must be 1')
        if self.origin not in ('installed-default', 'local-dirty-snapshot', 'local-test-fixture'):
            raise _record_error('origin', 'must be installed-default, local-dirty-snapshot, or local-test-fixture')
        if self.origin == 'installed-default':
            if not _is_sha1(self.source_commit):
                raise _record_error('source_commit', 'default origin must bind a 40-hex commit')
        elif self.source_commit is not None:
            raise _record_error('source_commit', 'local origins must not fabricate a commit')
        if not _is_sha1(self.source_tree):
            raise _record_error('source_tree', 'must be 40 hex')
        archive = self.source_archive
        if self.origin == 'installed-default':
            if (not isinstance(archive, dict) or set(archive) != {'sha256', 'size', 'prefix'}
                    or not _is_sha256(archive['sha256']) or type(archive['size']) is not int
                    or not 0 <= archive['size'] <= 256 * 1024 * 1024
                    or not isinstance(archive['prefix'], str)
                    or _SAFE_NAME.fullmatch(archive['prefix']) is None):
                raise _record_error('source_archive', 'default origin must bind {sha256, size, prefix}')
        elif archive is not None:
            raise _record_error('source_archive', 'local origins must not bind an archive')
        members = self.source_members
        if (not isinstance(members, dict) or set(members) != {'count', 'canonical_roster_sha256'}
                or type(members['count']) is not int or members['count'] < 0
                or not _is_sha256(members['canonical_roster_sha256'])):
            raise _record_error('source_members', 'requires {count, canonical_roster_sha256}')
        seal = self.content_seal
        if seal is not None and (not isinstance(seal, str) or not seal or len(seal) > 4096 or '\0' in seal):
            raise _record_error('content_seal', 'must be null or a bounded opaque string')
        if self.origin == 'installed-default' and seal is not None:
            raise _record_error('content_seal', 'default origin carries no seal')
        if self.origin == 'local-dirty-snapshot' and seal is None:
            raise _record_error('content_seal', 'dirty snapshots require a seal')
        if not _is_sha256(self.cargo_lock_sha256):
            raise _record_error('cargo_lock_sha256', 'must be 64 hex')
        vendor = self.vendor_packages
        if (type(vendor) is not list or not vendor or not all(
                isinstance(row, dict) and set(row) == {'identity', 'sha256'}
                and isinstance(row['identity'], str) and _SAFE_NAME.fullmatch(row['identity'])
                and _is_sha256(row['sha256']) for row in vendor)
                or len({row['identity'] for row in vendor}) != len(vendor)):
            raise _record_error('vendor_packages', 'requires a non-empty unique [{identity, sha256}] roster')
        if not _is_sha256(self.toolchain_manifest_sha256):
            raise _record_error('toolchain_manifest_sha256', 'must be 64 hex')
        image = self.toolchain_image
        if (not isinstance(image, dict) or set(image) != {'engine_id', 'layers'}
                or not isinstance(image['engine_id'], str)
                or not image['engine_id'].startswith('sha256:')
                or not _is_sha256(image['engine_id'].removeprefix('sha256:'))
                or type(image['layers']) is not list or not image['layers'] or not all(
                    isinstance(layer, str) and layer.startswith('sha256:')
                    and _is_sha256(layer.removeprefix('sha256:')) for layer in image['layers'])):
            raise _record_error('toolchain_image', 'requires {engine_id, layers[]} of sha256 ids')
        rust = self.rust_protoc
        if (not isinstance(rust, dict)
                or set(rust) != {'rustc_version', 'cargo_version', 'protoc_version',
                                 'rust_record_sha256', 'protoc_record_sha256', 'crates_record_sha256'}
                or not all(_is_text(rust[key], 256) for key in
                           ('rustc_version', 'cargo_version', 'protoc_version'))
                or not all(_is_sha256(rust[key]) for key in
                           ('rust_record_sha256', 'protoc_record_sha256', 'crates_record_sha256'))):
            raise _record_error('rust_protoc', 'requires versions plus three record digests')
        if not _is_text(self.target, 128):
            raise _record_error('target', 'must be a bounded string')
        if (type(self.packages) is not list or not self.packages
                or not all(_is_text(name, 128) for name in self.packages)):
            raise _record_error('packages', 'must be a non-empty string list')
        if not _is_text(self.features, 128):
            raise _record_error('features', 'must be a bounded string')
        profile = self.profile
        if (not isinstance(profile, dict) or set(profile) != {'name', 'lto', 'codegen-units', 'strip'}
                or not all(_is_text(profile[key], 64) for key in ('name', 'lto', 'strip'))
                or type(profile['codegen-units']) is not int or profile['codegen-units'] < 1):
            raise _record_error('profile', 'requires {name, lto, codegen-units, strip}')
        if type(self.rustflags) is not list or not all(_is_text(flag, 256) for flag in self.rustflags):
            raise _record_error('rustflags', 'must be a string list')
        if (type(self.cargo_args) is not list or not self.cargo_args
                or not all(_is_text(arg, 256) for arg in self.cargo_args)):
            raise _record_error('cargo_args', 'must be a non-empty string list')
        if not _is_sha256(self.controller_cargo_config_sha256):
            raise _record_error('controller_cargo_config_sha256', 'must be 64 hex')
        if not _is_sha256(self.build_script_sha256):
            raise _record_error('build_script_sha256', 'must be 64 hex')
        _check_product(self.daemon, 'daemon', _DAEMON_PATH)
        _check_product(self.cli, 'cli', _CLI_PATH)
        _check_product(self.shim, 'shim', _SHIM_PATH)
        _check_abi(self.abi)
        if not _is_sha256(self.daemon_config_sha256):
            raise _record_error('daemon_config_sha256', 'must be 64 hex')
        if not _is_sha256(self.entrypoint_sha256):
            raise _record_error('entrypoint_sha256', 'must be 64 hex')
        if self.hook_hashes != []:
            raise _record_error('hook_hashes', 'must be []; unknown hooks fail closed')
        if not _is_sha256(self.build_context_digest):
            raise _record_error('build_context_digest', 'must be 64 hex')
        caller = self.caller
        if (not isinstance(caller, dict) or set(caller) != {'origin', 'run_id', 'job_id'}
                or caller['origin'] != 'local-controller'
                or not all(value is None or (isinstance(value, str) and _CALLER_ID.fullmatch(value))
                           for value in (caller['run_id'], caller['job_id']))):
            raise _record_error('caller', 'requires local-controller {origin, run_id, job_id}')
        parent = self.provider_parent
        if (not isinstance(parent, dict)
                or set(parent) != {'family', 'platform', 'manifest_digest', 'config_digest'}
                or not all(value is None or _is_text(value, 256)
                           for value in (parent['family'], parent['platform']))
                or not all(value is None or _is_sha256(value)
                           for value in (parent['manifest_digest'], parent['config_digest']))):
            raise _record_error('provider_parent', 'requires {family, platform, manifest_digest, config_digest}')
        for field in fields(self):
            object.__setattr__(self, field.name, _freeze_record_value(getattr(self, field.name)))

    @classmethod
    def from_dict(cls, data: dict) -> 'ProxyBuildIdentityV1':
        """Validate an untrusted record dict strictly; unknown fields reject."""
        if type(data) is not dict:
            raise ValueError('proxy identity record invalid: record must be a dict')
        names = [field.name for field in fields(cls)]
        unknown = [key for key in data if key not in names]
        if unknown:
            raise ValueError('proxy identity record invalid: unknown field %r' % sorted(unknown)[0])
        missing = [name for name in names if name not in data]
        if missing:
            raise ValueError('proxy identity record invalid: missing field %r' % missing[0])
        return cls(**{name: data[name] for name in names})

    def to_dict(self) -> dict:
        """Return a deep plain-dict copy of this record."""
        return {field.name: _thaw_record_value(getattr(self, field.name)) for field in fields(self)}

    def to_canonical_json(self) -> bytes:
        """Return canonical JSON bytes of this record."""
        return canonical_json_bytes(self.to_dict())

    def require_same_record(self, other: 'ProxyBuildIdentityV1', *, where: str) -> None:
        """Require exact record equality, naming the first mismatching field."""
        if type(other) is not ProxyBuildIdentityV1:
            raise TypeError('proxy identity comparison requires a record')
        for field in fields(self):
            if (_thaw_record_value(getattr(self, field.name))
                    != _thaw_record_value(getattr(other, field.name))):
                raise ValueError('proxy identity mismatch: %s.%s' % (where, field.name))

    def check_client_abi_observed(self, observed: dict) -> None:
        """Require exact equality of observed client ABI maps with this record.

        The observation covers exactly the installed shim/CLI paths (daemon
        byte extraction is deferred); daemon ABI stays claim-bound through the
        recorded identity. No policy input: identity re-verifies sameness.
        """
        keys = {'decision', 'runtime_qualification', 'floors', 'needed', 'interpreters',
                'shim_exports', 'version_requirements', 'symbol_versions'}
        if type(observed) is not dict or set(observed) != keys:
            raise ValueError('proxy identity actual invalid: abi_observed requires %s' % sorted(keys))
        for sub in ('floors', 'needed', 'interpreters', 'version_requirements', 'symbol_versions'):
            if type(observed[sub]) is not dict or set(observed[sub]) != set(_CLIENT_PATHS):
                raise ValueError(
                    'proxy identity actual invalid: abi_observed %s must cover exactly shim/CLI' % sub)
        mine = _thaw_record_value(self.abi)
        for key in ('decision', 'runtime_qualification', 'shim_exports'):
            if observed[key] != mine[key]:
                raise ValueError('proxy identity mismatch: abi.%s' % key)
        for sub in ('floors', 'needed', 'interpreters', 'version_requirements', 'symbol_versions'):
            for path in _CLIENT_PATHS:
                if observed[sub][path] != mine[sub][path]:
                    raise ValueError('proxy identity mismatch: abi.%s.%s' % (sub, path))


@dataclass(frozen=True)
class ArtifactRef:
    kind: str
    reference: str
    sha256: str
    platform: str


@dataclass(frozen=True)
class BoundedRunPolicy:
    """Physical limits for a disposable direct provider execution."""

    state_bytes: int = 64 * 1024 * 1024
    output_bytes: int = 256 * 1024 * 1024
    inodes: int = 10000
    tmp_bytes: int = 128 * 1024 * 1024
    run_bytes: int = 16 * 1024 * 1024
    memory_bytes: int = 1024 * 1024 * 1024
    pids: int = 128


@dataclass(frozen=True)
class RunSpec:
    environment: str
    channel: str
    mode: str
    artifact: ArtifactRef
    execution_location: str
    consumer_artifact: ArtifactRef | None
    client_artifact: ArtifactRef | None
    argv: tuple[str, ...]
    inputs: dict[str, str]
    output_dir: Path
    cwd: Path
    timeout_seconds: int
    installed_prefix: Path | None = None
    bounded: BoundedRunPolicy | None = None
    fixed_validation: Literal['checker', 'consumer'] | None = None
    expected_proxy_identity: ProxyBuildIdentityV1 | None = None


@dataclass(frozen=True)
class RunResult:
    app_returncode: int | None
    lifecycle_errors: tuple[str, ...]
    cleanup_errors: tuple[str, ...]
    exit_code: int
    receipt_path: Path
