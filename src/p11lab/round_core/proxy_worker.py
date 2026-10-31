"""Bounded offline Rust candidate production (producer-only slice).

The producer builds the daemon, CLI, and shim from controller-sealed source
bytes with one fixed offline Cargo invocation inside the warm-verified proxy
toolchain image. Candidate build scripts, procedural macros, and tools execute
only inside that inspected container boundary, never on the controller.

This slice binds inputs, runs the build, and records a local untrusted output
observation. It grants no source, rights, caller, or runtime authority:
qualification stays false, durable receipts stay provisional/unconfirmed, and
only a successful caller-observed API return carries a local witness.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
import hashlib
import heapq
import json
import os
import posixpath
import re
import shutil
import signal
import stat
import struct
import threading
import time
import tomllib
from typing import Any, Callable
from uuid import uuid4

from ..catalog import package_data
from ..docker import Docker, DockerError
from ..models import ArtifactRef
from ..proxy_inputs import (
    ProxyInputCache,
    _registry_roster,
    _regular_bytes,
    inspect_source_members,
    load_proxy_build_selection,
    load_proxy_source_selection,
    load_proxy_tool_records,
    materialize_locked_crates,
    validate_workspace_mapping,
)
from ..proxy_toolchain import verify_proxy_toolchain
from ..tool_downloads import safe_directory
from .evidence import read_products
from .inputs import canonical
from .worker import _OutputVolume, _inspection


class ProxyProducerError(ValueError):
    """The proxy candidate cannot be produced from the selected inputs."""


JsonObject = dict[str, Any]

_SHA256 = re.compile(r'[0-9a-f]{64}\Z')
_SHA1 = re.compile(r'[0-9a-f]{40}\Z')
_SAFE_NAME = re.compile(r'[A-Za-z0-9_.+\-]+\Z')
_CALLER_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:\-]{0,127}\Z')

_PRODUCER_ROLE_POLICY_SHA256 = '522b8a04812040c5d83aa7f94176afac75f14a13a43a294c33a1948389dc4f17'

_BUILD_SCRIPT = """\
set -eu
/bin/mkdir -p /scratch/home /scratch/cargo-home /scratch/target /out/bin /out/lib
cd /inputs
status=0
/opt/rust/bin/cargo build --locked --offline --release --target x86_64-unknown-linux-gnu -p pkcs11-proxy-ng -p pkcs11-proxy-ng-cli -p pkcs11-proxy-ng-shim > /scratch/cargo.log 2>&1 || status=$?
/usr/bin/tail -c 49152 /scratch/cargo.log
if [ "$status" -ne 0 ]; then exit "$status"; fi
/bin/cp /scratch/target/x86_64-unknown-linux-gnu/release/pkcs11-proxy-ng /out/bin/pkcs11-proxy-ng
/bin/cp /scratch/target/x86_64-unknown-linux-gnu/release/pkcs11-proxy-ng-cli /out/bin/pkcs11-proxy-ng-cli
/bin/cp /scratch/target/x86_64-unknown-linux-gnu/release/libpkcs11_proxy_ng_shim.so /out/lib/libpkcs11_proxy_ng_shim.so
/bin/chmod 755 /out/bin/pkcs11-proxy-ng /out/bin/pkcs11-proxy-ng-cli /out/lib/libpkcs11_proxy_ng_shim.so
"""

_CONTROLLER_CARGO_CONFIG = """\
# Controller-owned offline configuration. The candidate .cargo tree is never
# staged, so no registry, credential provider, or hook here can be influenced
# by candidate bytes.
[net]
offline = true

[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
"""


def _clock() -> float:
    return time.monotonic()


def _require(value: object, message: str) -> None:
    if not value:
        raise ProxyProducerError(message)


def validate_role_policy_bytes(raw: bytes) -> JsonObject:
    """Require the exact installed producer role policy, never caller policy."""
    _require(isinstance(raw, bytes) and hashlib.sha256(raw).hexdigest() == _PRODUCER_ROLE_POLICY_SHA256,
             'installed producer role policy changed')
    try:
        value = json.loads(raw)
    except ValueError as error:
        raise ProxyProducerError('invalid producer role policy') from error
    _require(isinstance(value, dict) and value.get('schema') == 'p11lab.proxy-producer-role.v1',
             'invalid producer role policy')
    _require(hashlib.sha256(_BUILD_SCRIPT.encode()).hexdigest() == value.get('build_script_sha256')
             and hashlib.sha256(_CONTROLLER_CARGO_CONFIG.encode()).hexdigest()
             == value.get('controller_cargo_config_sha256'),
             'producer fixed texts differ from role policy')
    return value


def load_producer_role_policy() -> JsonObject:
    """Return the digest-pinned installed role policy for this slice."""
    return validate_role_policy_bytes(package_data('rounds/proxy-producer-v1.json').read_bytes())


def _check_members(members: object) -> tuple[dict, ...]:
    _require(isinstance(members, tuple) and 0 < len(members) <= 30000, 'invalid source roster')
    assert isinstance(members, tuple)
    seen: set[str] = set()
    for row in members:
        _require(isinstance(row, dict) and row.keys() == {'path', 'mode', 'size', 'sha256', 'git_blob'},
                 'invalid source record')
        path = row['path']
        _require(isinstance(path, str) and all(part not in ('', '.', '..') and bool(_SAFE_NAME.fullmatch(part))
                                               for part in path.split('/')) and path not in seen,
                 'unsafe or duplicate source path')
        seen.add(path)
        _require(row['mode'] in ('100644', '100755', '120000') and type(row['size']) is int
                 and 0 <= row['size'] <= 256 * 1024 * 1024 and isinstance(row['sha256'], str)
                 and bool(_SHA256.fullmatch(row['sha256'])) and isinstance(row['git_blob'], str)
                 and bool(_SHA1.fullmatch(row['git_blob'])), 'invalid source identity')
    return members


def _check_vendor_roster(packages: object) -> tuple[dict, ...]:
    _require(isinstance(packages, tuple) and len(packages) <= 10000, 'invalid vendor roster')
    assert isinstance(packages, tuple)
    seen: set[str] = set()
    for row in packages:
        _require(isinstance(row, dict) and row.keys() == {'identity', 'sha256'}
                 and isinstance(row['identity'], str) and bool(_SAFE_NAME.fullmatch(row['identity']))
                 and row['identity'] not in seen and isinstance(row['sha256'], str)
                 and bool(_SHA256.fullmatch(row['sha256'])), 'invalid vendor record')
        seen.add(row['identity'])
    return packages


def _check_caller_id(value: object) -> str | None:
    _require(value is None or (isinstance(value, str) and bool(_CALLER_ID.fullmatch(value))),
             'invalid caller context')
    assert value is None or isinstance(value, str)
    return value


@dataclass(frozen=True)
class SnapshotBase:
    """Pinned lock/manifest/vendor closure that a code snapshot must preserve."""
    members: tuple[dict, ...]
    cargo_lock_sha256: str
    vendor_roster: tuple[dict, ...]

    def __post_init__(self) -> None:
        _check_members(self.members)
        _require(isinstance(self.cargo_lock_sha256, str)
                 and bool(_SHA256.fullmatch(self.cargo_lock_sha256)), 'invalid lock identity')
        _check_vendor_roster(self.vendor_roster)


@dataclass(frozen=True)
class ProxyProducerSelection:
    """Controller-frozen candidate binding; candidate bytes never mint this."""
    origin: str
    source_commit: str | None
    source_archive_sha256: str | None
    source_archive_size: int | None
    source_prefix: str | None
    source_tree: str
    source_members: tuple[dict, ...]
    cargo_lock_sha256: str
    vendor_packages: tuple[dict, ...]
    toolchain_manifest_sha256: str
    provider_parent: dict
    caller_origin: str
    caller_run_id: str | None
    caller_job_id: str | None

    def __post_init__(self) -> None:
        _require(self.origin in ('installed-default', 'local-dirty-snapshot', 'local-test-fixture'),
                 'unsupported selection origin')
        _require(self.source_commit is None or
                 (isinstance(self.source_commit, str) and bool(_SHA1.fullmatch(self.source_commit))),
                 'invalid source commit')
        archived = [self.source_archive_sha256, self.source_archive_size, self.source_prefix]
        _require(all(v is None for v in archived)
                 or (isinstance(self.source_archive_sha256, str)
                     and bool(_SHA256.fullmatch(self.source_archive_sha256))
                     and type(self.source_archive_size) is int
                     and 0 <= self.source_archive_size <= 256 * 1024 * 1024
                     and isinstance(self.source_prefix, str)
                     and bool(_SAFE_NAME.fullmatch(self.source_prefix))),
                 'invalid source archive binding')
        _require(isinstance(self.source_tree, str) and bool(_SHA1.fullmatch(self.source_tree)),
                 'invalid source tree')
        _check_members(self.source_members)
        _require(isinstance(self.cargo_lock_sha256, str)
                 and bool(_SHA256.fullmatch(self.cargo_lock_sha256)), 'invalid lock identity')
        _check_vendor_roster(self.vendor_packages)
        _require(isinstance(self.toolchain_manifest_sha256, str)
                 and bool(_SHA256.fullmatch(self.toolchain_manifest_sha256)),
                 'invalid toolchain manifest binding')
        _require(isinstance(self.provider_parent, dict)
                 and self.provider_parent.get('status') == 'unselected',
                 'unsupported provider parent')
        _require(self.caller_origin == 'local-controller', 'unsupported caller origin')
        _check_caller_id(self.caller_run_id)
        _check_caller_id(self.caller_job_id)
        if self.origin == 'installed-default':
            _require(self.source_commit is not None and self.source_archive_sha256 is not None,
                     'default selection must bind commit and archive')
        else:
            _require(self.source_commit is None, 'local selection must not fabricate a commit')


@dataclass(frozen=True)
class VerifiedProducerSource:
    """Selection-bound source bytes with lock, workspace, and inert links."""
    selection: ProxyProducerSelection
    lock_bytes: bytes
    workspace: dict[str, str]
    links: dict[str, dict[str, str]]
    members: dict[str, bytes]

    def __post_init__(self) -> None:
        _require(type(self.selection) is ProxyProducerSelection, 'typed selection required')
        _require(isinstance(self.lock_bytes, bytes) and bool(self.lock_bytes),
                 'invalid lock bytes')
        _require(isinstance(self.workspace, dict) and all(
            isinstance(k, str) and isinstance(v, str) for k, v in self.workspace.items()),
                 'invalid workspace mapping')
        _require(isinstance(self.links, dict), 'invalid source links')
        _require(isinstance(self.members, dict) and all(
            isinstance(k, str) and isinstance(v, bytes) for k, v in self.members.items()),
                 'invalid source member bytes')


def _installed_vendor_roster() -> tuple[dict, ...]:
    rows = [{'identity': PurePosixPath(record.path).name[:-len('.crate')], 'sha256': record.sha256}
            for record in load_proxy_tool_records() if record.kind == 'proxy-crate']
    return tuple(sorted(rows, key=lambda row: row['identity']))


def default_proxy_selection(*, toolchain_manifest_sha256: str, caller_run_id: str | None = None,
                            caller_job_id: str | None = None) -> ProxyProducerSelection:
    """Bind the exact installed default source, lock, and vendor closure."""
    source = load_proxy_source_selection()
    return ProxyProducerSelection(
        origin='installed-default', source_commit=source.commit,
        source_archive_sha256=source.archive_sha256, source_archive_size=source.archive_size,
        source_prefix=source.archive_prefix, source_tree=source.tree,
        source_members=tuple(dict(row) for row in source.members),
        cargo_lock_sha256=source.cargo_lock_sha256, vendor_packages=_installed_vendor_roster(),
        toolchain_manifest_sha256=toolchain_manifest_sha256,
        provider_parent={'status': 'unselected', 'detail': 'later-integration-slice'},
        caller_origin='local-controller', caller_run_id=caller_run_id, caller_job_id=caller_job_id)


def default_snapshot_base() -> SnapshotBase:
    """Return the installed default closure that dirty snapshots must preserve."""
    source = load_proxy_source_selection()
    return SnapshotBase(members=tuple(dict(row) for row in source.members),
                        cargo_lock_sha256=source.cargo_lock_sha256,
                        vendor_roster=_installed_vendor_roster())


def _git_tree(members: tuple[dict, ...]) -> str:
    tree: dict = {}
    for row in members:
        node = tree
        parts = row['path'].split('/')
        for part in parts[:-1]:
            child = node.setdefault(part, {})
            _require(isinstance(child, dict), 'source file/directory collision')
            node = child
        _require(parts[-1] not in node, 'source file/directory collision')
        node[parts[-1]] = (row['mode'], row['git_blob'])

    def tree_hash(node: dict) -> str:
        result = bytearray()
        for name, value in sorted(node.items(),
                                  key=lambda item: (item[0] + ('/' if isinstance(item[1], dict)
                                                              else '')).encode()):
            mode, oid = ('40000', tree_hash(value)) if isinstance(value, dict) else value
            result.extend(mode.encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(oid))
        return hashlib.sha1(b'tree ' + str(len(result)).encode() + b'\0' + bytes(result)).hexdigest()

    return tree_hash(tree)


def _walk_snapshot_tree(root: Path) -> tuple[dict[str, bytes], dict[str, int], dict[str, str]]:
    """Read one bounded worktree export; links stay inert target text."""
    limits = load_producer_role_policy()['source_limits']
    root = Path(root).absolute()
    _require(not root.is_symlink() and root.is_dir(), 'snapshot root must be a directory')
    files: dict[str, bytes] = {}
    modes: dict[str, int] = {}
    links: dict[str, str] = {}
    state = {'total': 0}

    def visit(directory: Path, depth: int) -> None:
        _require(depth <= 32, 'snapshot depth bound')
        with os.scandir(directory) as entries:
            for entry in sorted(entries, key=lambda item: item.name):
                relative = entry.path[len(str(root)) + 1:].replace(os.sep, '/')
                _require('.git' not in Path(relative).parts, 'snapshot must be a .git-free export')
                _require(relative != 'vendor' and not relative.startswith('vendor/'),
                         'snapshot reserves vendor/ for the build view')
                _require(len(files) + len(links) < limits['max_members'], 'snapshot member bound')
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    visit(Path(entry.path), depth + 1)
                elif stat.S_ISREG(info.st_mode):
                    _require(all(part not in ('', '.', '..') and bool(_SAFE_NAME.fullmatch(part))
                                   for part in relative.split('/')), 'unsafe snapshot path')
                    fd = os.open(entry.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                    with os.fdopen(fd, 'rb') as stream:
                        opened = os.fstat(stream.fileno())
                        _require(stat.S_ISREG(opened.st_mode) and opened.st_ino == info.st_ino
                                 and opened.st_dev == info.st_dev, 'snapshot member changed')
                        data = stream.read(limits['max_expanded_bytes'] + 1)
                    state['total'] += len(data)
                    _require(state['total'] <= limits['max_expanded_bytes'], 'snapshot byte bound')
                    files[relative] = data
                    modes[relative] = 0o755 if info.st_mode & 0o111 else 0o644
                elif stat.S_ISLNK(info.st_mode):
                    _require(all(part not in ('', '.', '..') and bool(_SAFE_NAME.fullmatch(part))
                                   for part in relative.split('/')), 'unsafe snapshot path')
                    links[relative] = os.readlink(entry.path)
                else:
                    raise ProxyProducerError('snapshot member type is unsupported: ' + relative)

    try:
        visit(root, 0)
    except OSError as error:
        raise ProxyProducerError('cannot read snapshot tree') from error
    _require(bool(files), 'empty snapshot')
    for path, target in links.items():
        _require(target and not target.startswith('/') and '\\' not in target and '\0' not in target,
                 'unsafe snapshot link target: ' + path)
        resolved = posixpath.normpath(posixpath.join(posixpath.dirname(path), target))
        _require(resolved in files or resolved in links, 'snapshot link escapes or dangles: ' + path)
    for path in links:
        visited: set[str] = set()
        target = path
        while target in links:
            _require(target not in visited, 'cyclic snapshot link')
            visited.add(target)
            target = posixpath.normpath(posixpath.join(posixpath.dirname(target), links[target]))
    return files, modes, links


def _workspace_subset(root_manifest: bytes, pinned: dict[str, str]) -> dict[str, str]:
    """Derive the member manifest roster from the pinned root manifest."""
    try:
        parsed = tomllib.loads(root_manifest.decode('utf-8'))
    except (UnicodeError, tomllib.TOMLDecodeError) as error:
        raise ProxyProducerError('invalid workspace manifest') from error
    workspace = parsed.get('workspace')
    _require(isinstance(workspace, dict) and isinstance(workspace.get('members'), list),
             'invalid workspace')
    assert isinstance(workspace, dict)
    members = workspace['members']
    _require(all(isinstance(m, str) for m in members), 'invalid workspace member')
    paths = {'Cargo.toml'} | {member + '/Cargo.toml' for member in members}
    _require(paths <= set(pinned), 'workspace member outside pinned manifests')
    return {path: pinned[path] for path in paths}


def _check_lock_closure(lock_bytes: bytes, lock_sha256: str, manifests: dict[str, bytes],
                        expected: dict[str, str], vendor: tuple[dict, ...]) -> tuple[dict[str, str], dict[str, str]]:
    from ..proxy_inputs import ProxyInputError
    try:
        workspace = validate_workspace_mapping(lock_bytes, lock_sha256, manifests, expected)
        roster = _registry_roster(lock_bytes, lock_sha256, workspace)
    except ProxyInputError as error:
        raise ProxyProducerError('producer lock/vendor closure mismatch: ' + str(error)) from error
    _require(roster == {row['identity']: row['sha256'] for row in vendor},
             'lock registry roster differs from selected vendor closure')
    return workspace, roster


def seal_code_snapshot(tree_root: Path, *, base: SnapshotBase, origin: str,
                       toolchain_manifest_sha256: str, caller_run_id: str | None = None,
                       caller_job_id: str | None = None) -> ProxyProducerSelection:
    """Seal a .git-free worktree export against a pinned lock/manifest base.

    Every base Cargo.toml and the base Cargo.lock must match byte for byte;
    only other files may differ. No Git commit is fabricated.
    """
    _require(type(base) is SnapshotBase, 'typed snapshot base required')
    _require(origin in ('local-dirty-snapshot', 'local-test-fixture'), 'unsupported snapshot origin')
    files, modes, links = _walk_snapshot_tree(Path(tree_root))
    pinned = {row['path']: row['sha256'] for row in base.members
              if row['path'] == 'Cargo.toml' or row['path'].endswith('/Cargo.toml')}
    _require('Cargo.lock' in files
             and hashlib.sha256(files['Cargo.lock']).hexdigest() == base.cargo_lock_sha256,
             'snapshot lock differs from pinned base')
    for path, digest in pinned.items():
        _require(path in files and hashlib.sha256(files[path]).hexdigest() == digest,
                 'snapshot manifest differs from pinned base: ' + path)
    _require('Cargo.toml' in files, 'snapshot tree omits Cargo.toml')
    subset = _workspace_subset(files['Cargo.toml'], pinned)
    _check_lock_closure(files['Cargo.lock'], base.cargo_lock_sha256,
                        {path: files[path] for path in subset}, subset, base.vendor_roster)
    members = []
    for path in sorted(set(files) | set(links)):
        if path in links:
            payload = links[path].encode('utf-8')
            members.append({'path': path, 'mode': '120000', 'size': len(payload),
                            'sha256': hashlib.sha256(payload).hexdigest(),
                            'git_blob': hashlib.sha1(b'blob ' + str(len(payload)).encode()
                                                     + b'\0' + payload).hexdigest()})
        else:
            data = files[path]
            members.append({'path': path, 'mode': '100755' if modes[path] == 0o755 else '100644',
                            'size': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
                            'git_blob': hashlib.sha1(b'blob ' + str(len(data)).encode()
                                                     + b'\0' + data).hexdigest()})
    roster = tuple(members)
    return ProxyProducerSelection(
        origin=origin, source_commit=None, source_archive_sha256=None, source_archive_size=None,
        source_prefix=None, source_tree=_git_tree(roster), source_members=roster,
        cargo_lock_sha256=base.cargo_lock_sha256, vendor_packages=base.vendor_roster,
        toolchain_manifest_sha256=toolchain_manifest_sha256,
        provider_parent={'status': 'unselected', 'detail': 'later-integration-slice'},
        caller_origin='local-controller', caller_run_id=caller_run_id, caller_job_id=caller_job_id)


def seal_dirty_snapshot(tree_root: Path, *, toolchain_manifest_sha256: str,
                        caller_run_id: str | None = None,
                        caller_job_id: str | None = None) -> ProxyProducerSelection:
    """Seal a local dirty worktree export against the installed default base."""
    return seal_code_snapshot(tree_root, base=default_snapshot_base(),
                              origin='local-dirty-snapshot',
                              toolchain_manifest_sha256=toolchain_manifest_sha256,
                              caller_run_id=caller_run_id, caller_job_id=caller_job_id)


def verify_producer_source(selection: ProxyProducerSelection, archive: Path) -> VerifiedProducerSource:
    """Verify archive bytes against an archive-bound selection, inertly."""
    from ..proxy_inputs import ProxyInputError
    if type(selection) is not ProxyProducerSelection:
        raise TypeError('typed producer selection required')
    _require(selection.source_archive_sha256 is not None and selection.source_archive_size is not None
             and selection.source_prefix is not None,
             'snapshot selection needs a tree directory, not an archive')
    assert selection.source_archive_sha256 is not None and selection.source_archive_size is not None
    assert selection.source_prefix is not None
    try:
        raw = _regular_bytes(Path(archive), selection.source_archive_size)
        _require(len(raw) == selection.source_archive_size, 'selected source archive size mismatch')
        pinned = {row['path']: row['sha256'] for row in selection.source_members
                  if row['path'] == 'Cargo.toml' or row['path'].endswith('/Cargo.toml')}
        contents = tuple(sorted(row['path'] for row in selection.source_members
                                if row['mode'] != '120000'))
        observed = inspect_source_members(raw, selection.source_archive_sha256, selection.source_prefix,
                                          selection.source_tree,
                                          [dict(row) for row in selection.source_members],
                                          contents=contents)
        selected = observed['contents']
        _require('Cargo.lock' in selected and 'Cargo.toml' in selected,
                 'selected source omits Cargo.toml/Cargo.lock')
        lock_bytes = selected['Cargo.lock']
        subset = _workspace_subset(selected['Cargo.toml'], pinned)
        workspace, _ = _check_lock_closure(lock_bytes, selection.cargo_lock_sha256,
                                           {path: selected[path] for path in subset}, subset,
                                           selection.vendor_packages)
        return VerifiedProducerSource(selection, lock_bytes, workspace, observed['links'], selected)
    except ProxyInputError as error:
        raise ProxyProducerError('producer source verification failed: ' + str(error)) from error


def verify_snapshot_source(selection: ProxyProducerSelection, tree_root: Path) -> VerifiedProducerSource:
    """Re-verify a sealed snapshot tree byte for byte against its selection."""
    if type(selection) is not ProxyProducerSelection:
        raise TypeError('typed producer selection required')
    _require(selection.source_archive_sha256 is None and selection.source_archive_size is None
             and selection.source_prefix is None,
             'archive selection needs an archive file, not a tree')
    files, modes, links = _walk_snapshot_tree(Path(tree_root))
    rebuilt = []
    for path in sorted(set(files) | set(links)):
        payload = links[path].encode('utf-8') if path in links else files[path]
        git_blob = hashlib.sha1(b'blob ' + str(len(payload)).encode() + b'\0' + payload).hexdigest()
        rebuilt.append({'path': path,
                        'mode': '120000' if path in links
                        else ('100755' if modes[path] == 0o755 else '100644'),
                        'size': len(payload), 'sha256': hashlib.sha256(payload).hexdigest(),
                        'git_blob': git_blob})
    _require(rebuilt == [dict(row) for row in selection.source_members],
             'snapshot bytes differ from sealed selection')
    _require(_git_tree(selection.source_members) == selection.source_tree,
             'sealed snapshot tree mismatch')
    _require('Cargo.lock' in files
             and hashlib.sha256(files['Cargo.lock']).hexdigest() == selection.cargo_lock_sha256,
             'snapshot lock differs from sealed selection')
    pinned = {row['path']: row['sha256'] for row in selection.source_members
              if row['path'] == 'Cargo.toml' or row['path'].endswith('/Cargo.toml')}
    _require('Cargo.toml' in files, 'sealed snapshot tree omits Cargo.toml')
    subset = _workspace_subset(files['Cargo.toml'], pinned)
    workspace, _ = _check_lock_closure(files['Cargo.lock'], selection.cargo_lock_sha256,
                                       {path: files[path] for path in subset}, subset,
                                       selection.vendor_packages)
    resolved = {}
    for path, target in links.items():
        resolved[path] = {'target': target,
                          'resolved': posixpath.normpath(posixpath.join(posixpath.dirname(path), target))}
    return VerifiedProducerSource(selection, files['Cargo.lock'], workspace, resolved, files)


def check_release_profile(root_manifest: bytes) -> dict[str, object]:
    """Require the installed release profile settings in a workspace root."""
    expected = load_proxy_build_selection()['profile_settings']
    try:
        parsed = tomllib.loads(root_manifest.decode('utf-8'))
    except (UnicodeError, tomllib.TOMLDecodeError) as error:
        raise ProxyProducerError('invalid workspace manifest') from error
    profile = parsed.get('profile', {}).get('release') if isinstance(parsed.get('profile'), dict) else None
    _require(isinstance(profile, dict), 'workspace release profile is not selected')
    assert isinstance(profile, dict)
    _require(set(profile) == set(expected),
             'workspace release profile carries unselected keys: '
             + str(sorted(set(profile) - set(expected))))
    observed = {key: profile.get(key) for key in ('lto', 'strip', 'codegen-units')}
    _require(type(observed['lto']) is str and type(observed['strip']) is str
             and type(observed['codegen-units']) is int and observed == expected,
             'workspace release profile differs from selected build')
    return dict(observed)


_MAX_RECORDED_SYMBOLS = 16384
_MAX_SYMBOLS = 16 * 1024 * 1024

_DT_STRTAB = 5
_DT_SYMTAB = 6
_DT_HASH = 4
_DT_GNU_HASH = 0x6ffffef5
_DT_VERSYM = 0x6ffffff0
_DT_VERNEED = 0x6ffffffe
_DT_VERNEEDNUM = 0x6fffffff
_DT_FILTER = 0x7fffffff
_DT_AUXILIARY = 0x7ffffffd
_DT_AUDIT = 0x6ffffefc
_DT_DEPAUDIT = 0x6ffffefb
_DT_LOADER_DIRECTIVES = frozenset({_DT_FILTER, _DT_AUXILIARY, _DT_AUDIT, _DT_DEPAUDIT})
_DT_LOADER_DIRECTIVE_NAMES = {_DT_FILTER: 'DT_FILTER', _DT_AUXILIARY: 'DT_AUXILIARY',
                              _DT_AUDIT: 'DT_AUDIT', _DT_DEPAUDIT: 'DT_DEPAUDIT'}
_MAX_ELF_STRING_BYTES = 64 * 1024 * 1024
_ELF_CANCEL_STRIDE = 4096


class _ReverseName:
    """Reverse-order wrapper so heapq keeps the largest retained export on top.

    The heap holds the lexicographically smallest capped exports; the root is
    the largest among them (latest on ties, so earlier wins like a stable sort).
    """

    __slots__ = ('name',)

    def __init__(self, name: str) -> None:
        self.name = name

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, _ReverseName):
            return NotImplemented
        return self.name > other.name

    def __eq__(self, other: object) -> bool:
        return isinstance(other, _ReverseName) and self.name == other.name


def _elf_segments(raw: bytes) -> tuple[int, list[tuple[int, int, int, int, int]]]:
    """Return the ELF type and bounded (kind, offset, vaddr, filesz, flags) segments."""
    _require(len(raw) >= 64, 'truncated producer ELF')
    header = struct.unpack_from('<HHIQQQIHHHHHH', raw, 16)
    _require(header[1] == 62 and header[7] == 64 and header[8] == 56 and header[9] <= 256,
             'unsupported producer ELF headers')
    segments = []
    for index in range(header[9]):
        kind, flags, offset, vaddr, _, filesz, _, _ = struct.unpack_from(
            '<IIQQQQQQ', raw, header[4] + index * 56)
        _require(0 <= offset and 0 <= filesz and offset + filesz <= len(raw),
                 'truncated producer ELF segment')
        segments.append((kind, offset, vaddr, filesz, flags))
    return header[0], segments


def _elf_resolve(segments: list[tuple[int, int, int, int, int]], size: int,
                 address: int, span: int) -> int:
    _require(0 <= address and 0 <= span and span <= size, 'unmapped producer ELF address')
    for kind, offset, vaddr, filesz, _ in segments:
        if kind == 1 and vaddr <= address and address + span <= vaddr + filesz:
            return offset + address - vaddr
    raise ProxyProducerError('unmapped producer ELF address')


def _elf_cstr(raw: bytes, start: int, size: int, at: int,
              string_bytes: list[int] | None = None) -> str:
    _require(0 <= at < size, 'producer ELF string offset out of range')
    end = raw.find(b'\0', start + at, start + size)
    _require(end != -1, 'unterminated producer ELF string')
    try:
        text = raw[start + at:end].decode('ascii')
    except UnicodeError as error:
        raise ProxyProducerError('non-ascii producer ELF string') from error
    if string_bytes is not None:
        string_bytes[0] += len(text)
        _require(string_bytes[0] <= _MAX_ELF_STRING_BYTES,
                 'producer ELF string bytes out of range')
    return text


def _elf_symbol_count(raw: bytes, segments: list[tuple[int, int, int, int, int]],
                      dynamic: dict[int, int],
                      cancelled: Callable[[], int | None] | None = None) -> int:
    ceiling = (len(raw) - _elf_resolve(segments, len(raw), dynamic[_DT_SYMTAB], 24)) // 24
    if _DT_HASH in dynamic:
        at = _elf_resolve(segments, len(raw), dynamic[_DT_HASH], 8)
        _, nchain = struct.unpack_from('<II', raw, at)
        _require(1 <= nchain <= _MAX_SYMBOLS, 'producer ELF hash count out of range')
        count = nchain
    else:
        at = _elf_resolve(segments, len(raw), dynamic[_DT_GNU_HASH], 16)
        nbuckets, symoffset, bloom_size, _ = struct.unpack_from('<IIII', raw, at)
        _require(0 < nbuckets <= 1024 * 1024 and 0 < symoffset <= _MAX_SYMBOLS
                 and 0 < bloom_size <= 1024 * 1024, 'producer ELF hash header out of range')
        buckets_at = at + 16 + bloom_size * 8
        chains_at = buckets_at + nbuckets * 4
        _require(chains_at <= len(raw), 'truncated producer ELF hash')
        highest = symoffset - 1
        visited: set[int] = set()
        for bucket in range(nbuckets):
            if cancelled is not None and bucket and bucket % _ELF_CANCEL_STRIDE == 0 \
                    and cancelled():
                raise InterruptedError('producer attempt cancelled')
            index = struct.unpack_from('<I', raw, buckets_at + bucket * 4)[0]
            if index == 0:
                continue
            _require(symoffset <= index <= _MAX_SYMBOLS, 'producer ELF hash bucket out of range')
            steps = 0
            while True:
                # Valid GNU-hash bucket chains are disjoint index runs; a
                # revisit is malformed and would repeat unbounded work.
                _require(index not in visited, 'producer ELF hash chain revisits symbols')
                visited.add(index)
                cell = chains_at + (index - symoffset) * 4
                _require(cell + 4 <= len(raw), 'truncated producer ELF hash chain')
                highest = max(highest, index)
                steps += 1
                _require(steps <= ceiling, 'producer ELF hash chain out of range')
                if cancelled is not None and steps % _ELF_CANCEL_STRIDE == 0 and cancelled():
                    raise InterruptedError('producer attempt cancelled')
                if struct.unpack_from('<I', raw, cell)[0] & 1:
                    break
                index += 1
        count = highest + 1
    _require(1 <= count <= ceiling and count <= _MAX_SYMBOLS, 'producer ELF symbol count out of range')
    return count


def _elf_version_names(value: str) -> tuple[str, tuple[int, ...]] | None:
    lib, _, tail = value.rpartition('_')
    parts = tail.split('.') if lib and tail else []
    if not lib or not parts or any(not part.isdigit() or len(part) > 6 for part in parts):
        return None
    return lib, tuple(int(part) for part in parts)


def inspect_producer_elf(raw: bytes,
                         cancelled: Callable[[], int | None] | None = None) -> JsonObject:
    """Parse one candidate ELF64 inertly: kinds, exports, needs, floors.

    Section headers are never trusted; every address resolves through program
    headers with explicit bounds. Nothing here executes candidate bytes.
    Long loops honor the optional cancellation callback at a fixed stride.
    """
    from ..tool_builds import ToolBuildError, inspect_elf
    _require(isinstance(raw, bytes), 'producer ELF must be bytes')
    try:
        base = inspect_elf(raw)
    except ToolBuildError as error:
        raise ProxyProducerError('unsupported producer ELF: ' + str(error)) from error
    try:
        elf_type, segments = _elf_segments(raw)
        for name in base['needed']:
            _require(bool(name) and '/' not in name, 'unsafe producer ELF dependency')
        info: JsonObject = {
            'elf_type': elf_type, 'machine': 62, 'class': 64 if raw[4] == 2 else 0,
            'data': 'lsb' if raw[5] == 1 else 'unknown',
            'interpreter': base['interpreter'], 'needed': list(base['needed']),
            'soname': base['soname'], 'search_paths': list(base['search_paths'])}
        _require(info['class'] == 64 and info['data'] == 'lsb', 'unsupported producer ELF encoding')
        if elf_type == 3 and base['interpreter'] is not None:
            info['kind'] = 'pie-executable'
        elif elf_type == 3:
            info['kind'] = 'shared-object'
        elif elf_type == 2:
            info['kind'] = 'executable'
        else:
            info['kind'] = 'other'
        entries: list[tuple[int, int]] = []
        for kind, offset, _, filesz, _ in segments:
            if kind != 2:
                continue
            _require(filesz % 16 == 0, 'invalid producer ELF dynamic table')
            for at in range(offset, offset + filesz, 16):
                tag, value = struct.unpack_from('<QQ', raw, at)
                if tag == 0:
                    break
                _require(tag not in _DT_LOADER_DIRECTIVES,
                         'producer ELF loading directive is unsupported: '
                         + _DT_LOADER_DIRECTIVE_NAMES.get(tag, hex(tag)))
                entries.append((tag, value))
        dynamic = dict(entries)
        cap = _MAX_RECORDED_SYMBOLS
        exports_heap: list[tuple[_ReverseName, int, dict[str, str]]] = []
        export_count = 0
        undefined: list[str] = []
        undefined_count = 0
        requirements: list[dict[str, str]] = []
        requirement_count = 0
        symbol_versions: list[dict[str, str]] = []
        symbol_version_count = 0
        floors: dict[str, dict[str, str]] = {}
        version_index: dict[int, tuple[str, str]] = {}
        if entries:
            _require(_DT_STRTAB in dynamic and dynamic.get(10) is not None and _DT_SYMTAB in dynamic
                     and (_DT_HASH in dynamic or _DT_GNU_HASH in dynamic),
                     'incomplete producer ELF dynamic section')
            strtab_size = dynamic[10]
            _require(0 < strtab_size <= len(raw), 'producer ELF string table out of range')
            strtab = _elf_resolve(segments, len(raw), dynamic[_DT_STRTAB], strtab_size)
            symtab = _elf_resolve(segments, len(raw), dynamic[_DT_SYMTAB], 24)
            count = _elf_symbol_count(raw, segments, dynamic, cancelled)
            symtab = _elf_resolve(segments, len(raw), dynamic[_DT_SYMTAB], count * 24)
            string_bytes = [0]
            if _DT_VERNEED in dynamic:
                verneed_at = _elf_resolve(segments, len(raw), dynamic[_DT_VERNEED], 16)
                expected = dynamic.get(_DT_VERNEEDNUM, 0)
                _require(type(expected) is int and 0 <= expected <= 4096,
                         'producer ELF version/entry count out of range')
                seen: set[int] = set()
                cursor: int | None = verneed_at
                verneed_work = 0
                for file_number in range(expected + 1):
                    if cancelled is not None and file_number \
                            and file_number % _ELF_CANCEL_STRIDE == 0 and cancelled():
                        raise InterruptedError('producer attempt cancelled')
                    _require(cursor is not None and cursor not in seen, 'producer ELF version loop')
                    assert cursor is not None
                    seen.add(cursor)
                    _require(cursor + 16 <= len(raw), 'truncated producer ELF version entry')
                    _, aux_count, file_off, aux_off, next_off = struct.unpack_from('<HHIII', raw, cursor)
                    _require(0 < aux_count <= 4096 and 0 < aux_off <= 1024 * 1024,
                             'producer ELF version/entry count out of range')
                    filename = _elf_cstr(raw, strtab, strtab_size, file_off, string_bytes)
                    aux_seen: set[int] = set()
                    aux: int | None = cursor + aux_off
                    for aux_number in range(aux_count):
                        # Aggregate polling across files: aux_count <= 4096 makes a
                        # per-file stride unreachable, so 2x2500 would never poll.
                        # Counting every requirement bounds the whole traversal.
                        verneed_work += 1
                        if cancelled is not None \
                                and verneed_work % _ELF_CANCEL_STRIDE == 0 and cancelled():
                            raise InterruptedError('producer attempt cancelled')
                        _require(aux is not None and aux not in aux_seen, 'producer ELF version loop')
                        assert aux is not None
                        aux_seen.add(aux)
                        _require(aux + 16 <= len(raw), 'truncated producer ELF version entry')
                        _, _, other, name_off, aux_next = struct.unpack_from('<IHHIi', raw, aux)
                        version_name = _elf_cstr(raw, strtab, strtab_size, name_off, string_bytes)
                        requirement_count += 1
                        if len(requirements) < cap:
                            requirements.append({'file': filename, 'name': version_name})
                        if other in version_index:
                            _require(version_index[other] == (filename, version_name),
                                     'producer ELF version index is conflicting')
                        else:
                            version_index[other] = (filename, version_name)
                        parsed = _elf_version_names(version_name)
                        if parsed is not None:
                            lib, version = parsed
                            current = floors.setdefault(filename, {}).get(lib)
                            if current is None or tuple(int(p) for p in current.split('.')) < version:
                                floors[filename][lib] = version_name[len(lib) + 1:]
                        aux = aux + aux_next if aux_next else None
                        _require(aux is None or aux > 0, 'producer ELF version loop')
                    _require(requirement_count <= 65536, 'producer ELF version/entry count out of range')
                    cursor = cursor + next_off if next_off else None
                    if cursor is None:
                        break
                _require(cursor is None, 'producer ELF version/entry count out of range')
            versym = _elf_resolve(segments, len(raw), dynamic[_DT_VERSYM], count * 2) \
                if _DT_VERSYM in dynamic else None
            for index in range(count):
                if cancelled is not None and index and index % _ELF_CANCEL_STRIDE == 0 \
                        and cancelled():
                    raise InterruptedError('producer attempt cancelled')
                name_off, details, other, shndx, _, _ = struct.unpack_from(
                    '<IBBHQQ', raw, symtab + index * 24)
                bind, typ = details >> 4, details & 0xF
                if bind not in (1, 2):
                    continue
                name = _elf_cstr(raw, strtab, strtab_size, name_off, string_bytes)
                if not name:
                    continue
                if shndx != 0:
                    export_count += 1
                    row = {
                        'name': name, 'bind': 'global' if bind == 1 else 'weak',
                        'type': {0: 'notype', 1: 'object', 2: 'func'}.get(typ, 'other'),
                        'visibility': {0: 'default', 1: 'internal', 2: 'hidden',
                                       3: 'protected'}[other & 3]}
                    # Bounded lexicographic retention: keep the smallest capped
                    # names so a required export beyond the first window (Z... x
                    # cap before C_GetFunctionList) still validates like the base
                    # sort-then-truncate behavior, without storing all rows.
                    entry = (_ReverseName(row['name']), -export_count, row)
                    if len(exports_heap) < cap:
                        heapq.heappush(exports_heap, entry)
                    elif cap and exports_heap[0] < entry:
                        heapq.heapreplace(exports_heap, entry)
                else:
                    undefined_count += 1
                    if len(undefined) < cap:
                        undefined.append(name)
                    if versym is not None:
                        need = struct.unpack_from('<H', raw, versym + index * 2)[0] & 0x7FFF
                        if need >= 2:
                            _require(need in version_index,
                                     'producer ELF version reference is unresolved')
                            symbol_version_count += 1
                            if len(symbol_versions) < cap:
                                symbol_versions.append(
                                    {'symbol': name, 'file': version_index[need][0],
                                     'version': version_index[need][1]})
        exports = [row for _, _, row in exports_heap]
        exports.sort(key=lambda row: row['name'])
        undefined.sort()
        requirements.sort(key=lambda row: (row['file'], row['name']))
        symbol_versions.sort(key=lambda row: (row['symbol'], row['file'], row['version']))
        info['exports'] = exports
        info['export_count'] = export_count
        info['exports_truncated'] = export_count > cap
        info['undefined'] = undefined
        info['undefined_count'] = undefined_count
        info['undefined_truncated'] = undefined_count > cap
        info['version_requirements'] = requirements
        info['requirement_count'] = requirement_count
        info['requirements_truncated'] = requirement_count > cap
        info['symbol_versions'] = symbol_versions
        info['symbol_version_count'] = symbol_version_count
        info['symbol_versions_truncated'] = symbol_version_count > cap
        info['floors'] = floors
        return info
    except (struct.error, UnicodeError) as error:
        raise ProxyProducerError('malformed producer ELF') from error


def _parse_ceiling(value: object) -> tuple[int, ...]:
    _require(isinstance(value, str), 'invalid ABI version ceiling')
    assert isinstance(value, str)
    parts = value.split('.')
    _require(bool(parts) and all(part.isdigit() and len(part) <= 6 for part in parts),
             'invalid ABI version ceiling')
    return tuple(int(part) for part in parts)


def check_producer_abi(elfs: dict[str, JsonObject], policy: JsonObject) -> JsonObject:
    """Decide the explicit ABI policy over parsed products; record actuals.

    Unsupported kinds, loaders, search paths, dependencies, floors, or shim
    exports are an explicit unqualified result, never a silent relaxation.
    Runtime matching stays a later slice: no ceiling selected means the floor
    is recorded only.
    """
    _require(isinstance(elfs, dict) and set(elfs) == set(policy.get('outputs', [])),
             'producer ABI roster differs from selected outputs')
    needed_allowlist = set(policy.get('needed_allowlist', []))
    record: JsonObject = {'decision': 'conforming-recorded', 'runtime_qualification': 'not-performed',
                          'floors': {}, 'needed': {}, 'interpreters': {}, 'shim_exports': [],
                          'shim_exports_truncated': False,
                          'version_requirements': {}, 'symbol_versions': {},
                          'version_requirements_truncated': {}, 'symbol_versions_truncated': {}}
    for path in policy.get('executables', []):
        info = elfs[path]
        _require(info.get('kind') in ('executable', 'pie-executable'),
                 'producer executable kind is unsupported: ' + path)
        _require(info.get('interpreter') == policy.get('interpreter'),
                 'producer loader is unsupported: ' + path)
        _require(info.get('search_paths') == [], 'producer search path is unsupported: ' + path)
        for name in info.get('needed', []):
            _require(name in needed_allowlist, 'producer dependency is unsupported: ' + path + ': ' + name)
        record['floors'][path] = info.get('floors', {})
        record['needed'][path] = list(info.get('needed', []))
        record['interpreters'][path] = info.get('interpreter')
        record['version_requirements'][path] = [dict(row) for row in info.get('version_requirements', [])]
        record['symbol_versions'][path] = [dict(row) for row in info.get('symbol_versions', [])]
        record['version_requirements_truncated'][path] = bool(info.get('requirements_truncated'))
        record['symbol_versions_truncated'][path] = bool(info.get('symbol_versions_truncated'))
    for path in policy.get('shared_objects', []):
        info = elfs[path]
        _require(info.get('kind') == 'shared-object', 'producer shim kind is unsupported: ' + path)
        _require(info.get('interpreter') is None, 'producer shim loader is unsupported: ' + path)
        _require(info.get('search_paths') == [], 'producer search path is unsupported: ' + path)
        for name in info.get('needed', []):
            _require(name in needed_allowlist, 'producer dependency is unsupported: ' + path + ': ' + name)
        exported = {row['name'] for row in info.get('exports', [])}
        callable_exports = {row['name'] for row in info.get('exports', [])
                            if row.get('type') == 'func'
                            and row.get('visibility') in ('default', 'protected')}
        for name in policy.get('shim_required_exports', []):
            _require(name in exported, 'producer shim export is missing: ' + path + ': ' + name)
            _require(name in callable_exports,
                     'producer shim export is not externally callable: ' + path + ': ' + name)
        record['floors'][path] = info.get('floors', {})
        record['needed'][path] = list(info.get('needed', []))
        record['interpreters'][path] = None
        record['shim_exports'] = sorted(exported)
        record['shim_exports_truncated'] = bool(info.get('exports_truncated'))
        record['version_requirements'][path] = [dict(row) for row in info.get('version_requirements', [])]
        record['symbol_versions'][path] = [dict(row) for row in info.get('symbol_versions', [])]
        record['version_requirements_truncated'][path] = bool(info.get('requirements_truncated'))
        record['symbol_versions_truncated'][path] = bool(info.get('symbol_versions_truncated'))
    ceilings = policy.get('version_ceilings')
    _require(ceilings is None or isinstance(ceilings, dict), 'invalid ABI version ceilings')
    if ceilings:
        for path, files in record['floors'].items():
            for filename, libs in files.items():
                for lib, actual in libs.items():
                    allowed = ceilings.get(filename, {}).get(lib)
                    if allowed is None:
                        continue
                    _require(_parse_ceiling(actual) <= _parse_ceiling(allowed),
                             'producer version floor is unsupported: %s: %s %s' % (path, filename, actual))
    return record


def _docker_bytes(value: int) -> str:
    if value % 1024 ** 3 == 0:
        return '%dg' % (value // 1024 ** 3)
    if value % 1024 ** 2 == 0:
        return '%dm' % (value // 1024 ** 2)
    return str(value)


def producer_run_spec(*, staging_source: Path, output_volume: str) -> JsonObject:
    """Build the exact fixed container run: options, scrubbed argv, mounts."""
    policy = load_producer_role_policy()
    src = str(Path(staging_source))
    _require(Path(src).is_absolute() and ',' not in src and '\n' not in src,
             'unsafe producer staging mount path')
    _require(isinstance(output_volume, str)
             and bool(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.\-]{0,127}', output_volume)),
             'unsafe producer output volume name')
    environment = policy['environment']
    command = ['-i']
    for key, value in environment.items():
        command.append(key + '=' + value)
    command += [policy['shell'], *policy['shell_args'], _BUILD_SCRIPT]
    mounts = ['type=bind,src=' + src + ',dst=' + policy['mounts']['inputs'] + ',readonly',
              'type=volume,src=' + output_volume + ',dst=' + policy['mounts']['output']]
    options = ['--pull=never', '--user', policy['user'], '--read-only',
               '--network', policy['network_mode'], '--ipc', policy['ipc_mode'],
               '--cap-drop', 'ALL', '--security-opt', policy['security_opt'][0],
               '--pids-limit', str(policy['pids_limit']),
               '--memory', _docker_bytes(policy['memory_bytes']),
               '--memory-swap', _docker_bytes(policy['memory_swap_bytes']),
               '--cpus', str(policy['cpus']),
               '--ulimit', 'nofile=%d:%d' % (policy['nofile_soft'], policy['nofile_hard']),
               '--log-driver', policy['log_driver']]
    for path, spec in policy['tmpfs'].items():
        options += ['--tmpfs', path + ':' + spec]
    for mount in mounts:
        options += ['--mount', mount]
    options += ['--entrypoint', *policy['entrypoint']]
    return {'image_role': 'warm-verified-toolchain', 'command': command, 'options': options,
            'mounts': mounts, 'build_timeout_seconds': policy['build_seconds']}


# Daemon-reported mount options pinned 2026-10-30 on the local daemon with
# equivalent --mount flags (hello-world create+inspect+rm; volume removed
# after). Live reconfirmation required at the next live producer run.
_BIND_MOUNT_MODE = ''
_BIND_MOUNT_PROPAGATION = 'rprivate'
_VOLUME_MOUNT_DRIVER = 'local'
_VOLUME_MOUNT_MODE = 'z'


def verify_producer_boundary(observed: JsonObject, image: str, command: list[str],
                             mounts: list[str]) -> None:
    """Verify the actual created container matches the pinned role boundary."""
    policy = load_producer_role_policy()
    try:
        config, host = observed['Config'], observed['HostConfig']
        failures = []
        if observed.get('Image') != image:
            failures.append('image')
        if config.get('User') != policy['user']:
            failures.append('user')
        if config.get('Entrypoint') != policy['entrypoint'] or config.get('Cmd') != command:
            failures.append('argv')
        expected = {'NetworkMode': policy['network_mode'], 'CapDrop': policy['cap_drop'],
                    'CapAdd': policy['cap_add'], 'ReadonlyRootfs': policy['readonly_root'],
                    'Privileged': policy['privileged'], 'PidsLimit': policy['pids_limit'],
                    'Memory': policy['memory_bytes'], 'MemorySwap': policy['memory_swap_bytes'],
                    'NanoCpus': policy['nano_cpus'], 'SecurityOpt': policy['security_opt'],
                    'IpcMode': policy['ipc_mode'], 'Tmpfs': policy['tmpfs'],
                    'Ulimits': [{'Name': 'nofile', 'Soft': policy['nofile_soft'],
                                 'Hard': policy['nofile_hard']}]}
        for field, value in expected.items():
            if host.get(field) != value:
                failures.append(field)
        if host.get('PidMode') not in ('', policy['pid_mode']):
            failures.append('PidMode')
        if not isinstance(host.get('LogConfig'), dict) or host['LogConfig'].get('Type') != 'none':
            failures.append('LogConfig')
        if any(host.get(key) for key in ('Binds', 'Devices', 'VolumesFrom')):
            failures.append('devices')
        wanted = []
        for mount in mounts:
            fields = dict(part.split('=', 1) for part in mount.split(',') if '=' in part)
            if fields['type'] == 'volume':
                wanted.append((fields['type'], fields['src'], fields['dst'],
                               'readonly' not in mount.split(','),
                               _VOLUME_MOUNT_DRIVER, _VOLUME_MOUNT_MODE))
            else:
                wanted.append((fields['type'], fields['src'], fields['dst'],
                               'readonly' not in mount.split(','),
                               _BIND_MOUNT_MODE, _BIND_MOUNT_PROPAGATION))
        actual = []
        for entry in observed.get('Mounts', []):
            if entry['Type'] == 'volume':
                actual.append((entry['Type'], entry.get('Name'), entry['Destination'], entry['RW'],
                               entry.get('Driver'), entry.get('Mode')))
            else:
                actual.append((entry['Type'], entry['Source'], entry['Destination'], entry['RW'],
                               entry.get('Mode'), entry.get('Propagation')))
        if sorted(actual) != sorted(wanted):
            failures.append('Mounts')
        _require(not failures, 'actual producer boundary differs: ' + ','.join(failures))
    except (KeyError, TypeError, AttributeError) as error:
        raise ProxyProducerError('producer boundary inspection is incomplete') from error


def _inventory_tree(root: Path, limits: JsonObject) -> tuple[list[JsonObject], JsonObject]:
    """Hash one bounded controller tree: files, inert links, directory modes."""
    root = Path(root).absolute()
    _require(not root.is_symlink() and root.is_dir(), 'inventory root must be a directory')
    rows: list[JsonObject] = []
    counts = {'files': 0, 'bytes': 0, 'entries': 0, 'links': 0}

    def visit(directory: Path, depth: int) -> None:
        _require(depth <= 32, 'inventory depth bound')
        with os.scandir(directory) as entries:
            for entry in sorted(entries, key=lambda item: item.name):
                relative = entry.path[len(str(root)) + 1:].replace(os.sep, '/')
                counts['entries'] += 1
                _require(counts['entries'] <= limits['max_entries'], 'inventory entry bound')
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    rows.append({'path': relative, 'kind': 'dir', 'mode': stat.S_IMODE(info.st_mode)})
                    visit(Path(entry.path), depth + 1)
                elif stat.S_ISREG(info.st_mode):
                    fd = os.open(entry.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                    with os.fdopen(fd, 'rb') as stream:
                        opened = os.fstat(stream.fileno())
                        _require(stat.S_ISREG(opened.st_mode) and opened.st_ino == info.st_ino
                                 and opened.st_dev == info.st_dev, 'inventory member changed')
                        data = stream.read(limits['max_bytes'] + 1)
                    counts['files'] += 1
                    counts['bytes'] += len(data)
                    _require(counts['bytes'] <= limits['max_bytes'], 'inventory byte bound')
                    rows.append({'path': relative, 'kind': 'file', 'size': len(data),
                                 'mode': stat.S_IMODE(opened.st_mode),
                                 'sha256': hashlib.sha256(data).hexdigest(),
                                 'git_blob': hashlib.sha1(b'blob ' + str(len(data)).encode()
                                                          + b'\0' + data).hexdigest()})
                elif stat.S_ISLNK(info.st_mode):
                    target = os.readlink(entry.path)
                    payload = target.encode('utf-8')
                    counts['links'] += 1
                    rows.append({'path': relative, 'kind': 'link', 'target': target,
                                 'sha256': hashlib.sha256(payload).hexdigest(),
                                 'git_blob': hashlib.sha1(b'blob ' + str(len(payload)).encode()
                                                          + b'\0' + payload).hexdigest()})
                else:
                    raise ProxyProducerError('inventory member type is unsupported: ' + relative)

    try:
        visit(root, 0)
    except OSError as error:
        raise ProxyProducerError('cannot inventory controller tree') from error
    rows.sort(key=lambda row: row['path'])
    summary = {'digest': hashlib.sha256(canonical(rows)).hexdigest(), **counts}
    return rows, summary


def _stage_build_view(verified: VerifiedProducerSource, vendor_archives: Path, dest: Path) -> JsonObject:
    """Materialize the effective build view from verified in-memory bytes.

    The candidate .cargo tree is dropped and replaced by the controller-owned
    offline vendored-sources configuration; every other byte is staged exactly
    as verified. No verified byte is re-read from mutable inputs here.
    """
    from ..proxy_inputs import ProxyInputError
    if type(verified) is not VerifiedProducerSource:
        raise TypeError('verified producer source required')
    dest = Path(dest).absolute()
    _require(not dest.exists() and not dest.is_symlink(), 'staging destination must be fresh')
    selection = verified.selection
    modes = {row['path']: row['mode'] for row in selection.source_members}
    removed = sorted(path for path in list(verified.members) + list(verified.links)
                     if path == '.cargo' or path.startswith('.cargo/'))
    source = dest / 'source'
    source.mkdir(parents=True, mode=0o755)
    for path in sorted(verified.members):
        if path in removed:
            continue
        target = source.joinpath(*PurePosixPath(path).parts)
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        with target.open('xb') as stream:
            stream.write(verified.members[path])
        target.chmod(0o755 if modes[path] == '100755' else 0o644)
    for path in sorted(verified.links):
        if path in removed:
            continue
        target = source.joinpath(*PurePosixPath(path).parts)
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        link = verified.links[path]['target']
        resolved = posixpath.normpath(posixpath.join(posixpath.dirname(path), link))
        _require(resolved not in removed, 'staged link reaches the removed candidate cargo tree')
        os.symlink(link, target)
    cargo_dir = source / '.cargo'
    cargo_dir.mkdir(mode=0o755)
    (cargo_dir / 'config.toml').write_bytes(_CONTROLLER_CARGO_CONFIG.encode())
    (cargo_dir / 'config.toml').chmod(0o644)
    try:
        materialize_locked_crates(verified.lock_bytes, selection.cargo_lock_sha256,
                                  Path(vendor_archives), source / 'vendor',
                                  workspace=verified.workspace)
    except ProxyInputError as error:
        raise ProxyProducerError('producer vendor materialization failed: ' + str(error)) from error
    for entry in sorted(source.rglob('*')):
        if entry.is_symlink():
            continue
        if entry.is_dir():
            entry.chmod(0o755)
        elif entry.is_file() and entry.stat().st_mode & 0o444 != 0o444:
            # Registry archives may restrict group/other read bits; the sandbox
            # UID still needs exactly these verified bytes, world-readable.
            entry.chmod(entry.stat().st_mode | 0o444)
    limits = load_producer_role_policy()['staging_limits']
    _, summary = _inventory_tree(source, limits)
    return {'removed_candidate_cargo': removed,
            'added_controller_paths': ['.cargo/config.toml', 'vendor/'],
            'workspace': dict(verified.workspace),
            'source_tree': selection.source_tree,
            'cargo_lock_sha256': selection.cargo_lock_sha256,
            'vendor_packages': len(selection.vendor_packages),
            'inventory': summary}


def _check_vendor_archives(vendor: tuple[dict, ...], directory: Path) -> dict[str, JsonObject]:
    """Re-verify the exact registry archive roster against the selection."""
    from ..proxy_inputs import ProxyInputError
    directory = Path(directory).absolute()
    _require(not directory.is_symlink() and directory.is_dir(), 'vendor archives must be a directory')
    try:
        names = sorted(path.name for path in directory.iterdir())
    except OSError as error:
        raise ProxyProducerError('cannot read vendor archives') from error
    expected = sorted(row['identity'] + '.crate' for row in vendor)
    _require(names == expected, 'vendor archive roster differs from selection')
    observed = {}
    for row in vendor:
        try:
            raw = _regular_bytes(directory / (row['identity'] + '.crate'), 256 * 1024 * 1024)
        except ProxyInputError as error:
            raise ProxyProducerError('producer vendor archive unavailable: ' + row['identity']) from error
        _require(hashlib.sha256(raw).hexdigest() == row['sha256'],
                 'vendor archive differs from selection: ' + row['identity'])
        observed[row['identity']] = {'size': len(raw), 'sha256': row['sha256']}
    return observed


def _check_originals(selection: ProxyProducerSelection, *, archive: Path | None,
                     snapshot: Path | None, vendor_archives: Path) -> JsonObject:
    """Re-verify protected originals against the selection, never the staging."""
    if archive is not None:
        verified = verify_producer_source(selection, archive)
        source: JsonObject = {'kind': 'archive', 'verified': True,
                              'archive_sha256': selection.source_archive_sha256,
                              'tree': selection.source_tree,
                              'members': len(verified.members)}
    else:
        assert snapshot is not None
        verified = verify_snapshot_source(selection, snapshot)
        source = {'kind': 'snapshot', 'verified': True, 'tree': selection.source_tree,
                  'members': len(verified.members)}
    return {'source': source, 'vendor_archives': _check_vendor_archives(
        selection.vendor_packages, vendor_archives)}


def _error_record(error: BaseException) -> JsonObject:
    record: JsonObject = {'type': type(error).__name__, 'message': str(error)}
    cause = error.__cause__
    if cause is not None:
        record['cause'] = {'type': type(cause).__name__, 'message': str(cause)}
    return record


_RECEIPT_HEADROOM_BYTES = 1024 * 1024


def _require_receipt_headroom(dirpath: Path, size: int) -> None:
    """Refuse a receipt write unless the filesystem holds data plus 1MiB free."""
    _require(shutil.disk_usage(dirpath).free >= size + _RECEIPT_HEADROOM_BYTES,
             'insufficient receipt headroom')


def _bounded_write_bytes(path: Path, data: bytes, timeout: float) -> bool:
    """Write bytes with bounded abandonment under the remaining phase budget.

    A truly stuck syscall cannot be preempted; after ``timeout`` seconds the
    write is abandoned (daemon thread, never joined again) with explicit
    uncertainty, never silent tolerance and never false success. Returns True
    when the write completed (propagating any write error), False when it was
    abandoned or when ``timeout`` left no time to attempt it.
    """
    if timeout <= 0:
        return False
    outcome: dict[str, Any] = {}

    def _target() -> None:
        try:
            path.write_bytes(data)
            with open(path, 'rb') as stream:
                os.fsync(stream.fileno())
            if path.read_bytes() != data:
                raise ProxyProducerError('receipt readback mismatch')
            outcome['ok'] = True
        except BaseException as failure:  # noqa: BLE001 - re-raised below
            outcome['error'] = failure

    worker = threading.Thread(target=_target, daemon=True)
    worker.start()
    worker.join(timeout=timeout)
    if worker.is_alive():
        return False
    if 'error' in outcome:
        raise outcome['error']
    return True


def produce_proxy_candidate(selection: ProxyProducerSelection, *, source_archive: Path | None = None,
                            snapshot_dir: Path | None = None, vendor_archives: Path | None = None,
                            cache: ProxyInputCache | None = None, toolchain_output: Path | None = None,
                            output_dir: Path | None = None, engine: Docker | None = None,
                            interrupted: Callable[[], int | None] | None = None) -> JsonObject:
    """Produce the three proxy artifacts from sealed inputs under local control.

    Every attempt needs a fresh output directory. The warm toolchain check, one
    fixed offline Cargo build, stop-before-readback, and inert product checks
    all run inside the whole-attempt budget. Failures keep bounded evidence and
    exact cleanup outcomes; nothing here retries, publishes, or attests.

    ``cache`` is always the retained toolchain input cache: the warm check
    re-verifies the exact selected toolchain inputs against the sealed
    manifest, independent of which candidate selection is being built. For the
    default selection the candidate inputs are derived from it; fixture and
    snapshot selections carry their own candidate inputs alongside it.
    """
    if type(selection) is not ProxyProducerSelection:
        raise TypeError('typed producer selection required')
    if type(cache) is not ProxyInputCache:
        raise TypeError('typed proxy cache required')
    if interrupted is not None and not callable(interrupted):
        raise TypeError('interrupted callback required')
    policy = load_producer_role_policy()
    archived = selection.source_archive_sha256 is not None
    archive: Path | None
    snapshot: Path | None
    vendor: Path
    if selection.origin == 'installed-default':
        _require(source_archive is None and snapshot_dir is None and vendor_archives is None,
                 'default selection uses only retained cache inputs')
        archive = cache.source_archive
        snapshot = None
        vendor = cache.payload_root / 'crates'
    elif archived:
        _require(source_archive is not None and snapshot_dir is None and vendor_archives is not None,
                 'archive selection needs an archive file and vendor archives')
        assert source_archive is not None and vendor_archives is not None
        archive = Path(source_archive)
        snapshot = None
        vendor = Path(vendor_archives)
    else:
        _require(snapshot_dir is not None and source_archive is None and vendor_archives is not None,
                 'snapshot selection needs a tree directory and vendor archives')
        assert snapshot_dir is not None and vendor_archives is not None
        archive = None
        snapshot = Path(snapshot_dir)
        vendor = Path(vendor_archives)
    _require(toolchain_output is not None and output_dir is not None, 'output paths required')
    assert toolchain_output is not None and output_dir is not None
    tools = Path(toolchain_output).absolute()
    _require(not tools.is_symlink() and tools.is_dir(), 'toolchain output must be a directory')
    output = Path(output_dir).absolute()
    safe_directory(output.parent)
    _require(not output.exists() and not output.is_symlink(), 'output directory must be fresh')
    output.mkdir(mode=0o755)
    start = _clock()
    phases: JsonObject = {}
    attempt_id = uuid4().hex
    nonce = uuid4().hex
    selection_dict = asdict(selection)
    context_sha = hashlib.sha256(canonical(selection_dict)).hexdigest()
    labels = {'p11lab.proxy-producer': nonce, 'p11lab.proxy-context': context_sha}
    result: JsonObject = {
        'schema': 'p11lab.proxy-producer-observation.v1', 'scope': 'local-controller',
        'attempt_id': attempt_id, 'context_sha256': context_sha,
        'selection': selection_dict, 'status': 'incomplete', 'stages': [],
        'cleanup_errors': [], 'integrity_errors': [], 'qualification': False,
        'rights': 'unreviewed', 'authority': 'not-established',
        'attempt_completion': 'unconfirmed',
    }
    stop_state: dict[str, int | None] = {'signal': None}
    old_handlers: dict = {}

    def receive(signum: int, frame: object) -> None:
        stop_state['signal'] = stop_state['signal'] or signum

    latched: dict[str, int | None] = {'signal': None}

    def cancelled() -> int | None:
        # Latch the first observed request: a transient callback must not
        # clear a cancellation that an earlier gate already acted on, and
        # every observation below is enforced before any success return.
        if latched['signal'] is None:
            latched['signal'] = stop_state['signal'] or (interrupted() if interrupted else None)
        return latched['signal']

    if threading.current_thread() is threading.main_thread():
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            old_handlers[signum] = signal.signal(signum, receive)
    owned: str | None = None
    output_sandbox: _OutputVolume | None = None
    try:
        phase = _clock()
        if archive is not None:
            verified = verify_producer_source(selection, archive)
        else:
            assert snapshot is not None
            verified = verify_snapshot_source(selection, snapshot)
        _require('Cargo.toml' in verified.members, 'verified source omits Cargo.toml')
        result['profile'] = check_release_profile(verified.members['Cargo.toml'])
        phases['verify_seconds'] = _clock() - phase
        phase = _clock()
        warm = verify_proxy_toolchain(tools, manifest_sha256=selection.toolchain_manifest_sha256,
                                      cache=cache, verification_dir=output / 'toolchain-verification')
        phases['warm_seconds'] = _clock() - phase
        _require(warm.get('status') == 'local-byte-verification-observed',
                 'toolchain warm verification is unusable')
        _require(not warm.get('cleanup_errors'),
                 'toolchain warm verification cleanup is unconfirmed')
        try:
            engine_id = warm['image']['engine_id']
            warm_layers = warm['image']['layers']
        except (KeyError, TypeError) as error:
            raise ProxyProducerError('toolchain warm observation is incomplete') from error
        _require(isinstance(engine_id, str) and engine_id.startswith('sha256:')
                 and isinstance(warm_layers, list), 'toolchain warm observation is incomplete')
        result['toolchain'] = {'warm_status': warm['status'],
                               'manifest_sha256': selection.toolchain_manifest_sha256,
                               'image': {'engine_id': engine_id, 'layers': list(warm_layers)},
                               'source_attempt_completion': warm.get('source_attempt_completion')}
        phase = _clock()
        result['build_view'] = _stage_build_view(verified, vendor, output / 'staging')
        result['staging'] = {'before': result['build_view'].pop('inventory')}
        result['originals'] = {'before': _check_originals(selection, archive=archive,
                                                           snapshot=snapshot, vendor_archives=vendor)}
        phases['stage_seconds'] = _clock() - phase
        remaining = policy['whole_attempt_seconds'] - (_clock() - start)
        _require(remaining >= policy['pre_build_minimum_remaining_seconds'],
                 'insufficient remaining budget for producer build')
        build_timeout = min(policy['build_seconds'], int(remaining))
        result['build_timeout_seconds'] = build_timeout
        driver = engine or Docker()
        observed_image = driver.image(ArtifactRef('docker', engine_id,
                                                  engine_id.removeprefix('sha256:'), 'linux/amd64'))
        _require(observed_image.get('RootFS', {}).get('Layers') == warm_layers,
                 'toolchain image layers differ from warm observation')
        _require(not observed_image.get('Config', {}).get('Volumes'),
                 'toolchain image carries implicit volumes')
        result['builder_inspection'] = observed_image
        volume_name = 'p11lab-proxy-' + nonce + '-build-output'
        spec = producer_run_spec(staging_source=output / 'staging' / 'source',
                                 output_volume=volume_name)
        result['spec'] = spec
        volume_record: JsonObject = {}
        result['output_volume'] = volume_record
        output_sandbox = _OutputVolume(driver, engine_id, labels, volume_name,
                                       policy['output_volume_bytes'], volume_record)
        output_sandbox.open()
        name = 'p11lab-proxy-' + nonce + '-build'
        record: JsonObject = {'phase': 'build', 'name': name}
        result['stages'].append(record)
        try:
            owned = driver.create(engine_id, spec['command'], spec['options'], labels, name)
        except DockerError as error:
            if error.resource and error.resource[0] == 'container':
                owned = error.resource[1]
            record['uncertain_resource'] = error.uncertain_resource
            raise
        record['container_id'] = owned
        before = _inspection(driver, owned, labels)
        record['inspect_before'] = before
        verify_producer_boundary(before, engine_id, spec['command'], spec['mounts'])
        if cancelled():
            raise InterruptedError('producer attempt cancelled')
        phase = _clock()
        execution = driver.execute(owned, build_timeout, cancelled)
        phases['build_seconds'] = _clock() - phase
        record['execution'] = {'returncode': execution.returncode, 'stdout': execution.stdout,
                               'stderr': execution.stderr, 'timed_out': execution.timed_out,
                               'stdout_truncated': execution.stdout_truncated,
                               'stderr_truncated': execution.stderr_truncated}
        result['native'] = dict(record['execution'])
        driver.stop(owned, labels)
        stopped = _inspection(driver, owned, labels)
        record['inspect_stopped'] = stopped
        if stopped['State']['Running'] or stopped['State']['Pid'] != 0:
            raise DockerError('producer still running before readback')
        result['stop'] = {'running': False, 'pid': 0}
        if cancelled():
            raise InterruptedError('producer attempt cancelled')
        if execution.timed_out:
            raise TimeoutError('producer build timed out')
        if execution.returncode:
            raise ProxyProducerError('producer build failed: native exit %d' % execution.returncode)
        if execution.stdout_truncated or execution.stderr_truncated:
            raise ProxyProducerError('producer log limit exceeded')
        products = output / 'products'
        products.mkdir(mode=0o755)
        phase = _clock()
        output_sandbox.readback(products, tuple(policy['outputs']), cancelled)
        result['products'] = read_products(products, tuple(policy['outputs']),
                                           max_bytes=policy['output_volume_bytes'], max_files=10000)
        elfs = {}
        for row in result['products']:
            raw = (products / row['path']).read_bytes()
            _require(len(raw) == row['size']
                     and hashlib.sha256(raw).hexdigest() == row['sha256'],
                     'product bytes changed after readback')
            elfs[row['path']] = inspect_producer_elf(raw, cancelled=cancelled)
        result['abi'] = check_producer_abi(elfs, policy)
        phases['readback_seconds'] = _clock() - phase
        if cancelled():
            raise InterruptedError('producer attempt cancelled')
        try:
            driver.remove('container', owned, labels)
        except DockerError as error:
            result['cleanup_errors'].append('remove: ' + str(error))
            raise ProxyProducerError('producer cleanup unconfirmed') from error
        record['cleanup'] = 'removed-exact-owned-container'
        owned = None
        assert output_sandbox is not None
        result['cleanup_errors'].extend(output_sandbox.close())
        output_sandbox = None
        if result['cleanup_errors']:
            raise ProxyProducerError('producer cleanup unconfirmed')
        _, staging_after = _inventory_tree(output / 'staging' / 'source',
                                           policy['staging_limits'])
        result['staging']['after'] = staging_after
        _require(staging_after == result['staging']['before'], 'protected staged bytes changed')
        result['originals']['after'] = _check_originals(selection, archive=archive,
                                                        snapshot=snapshot, vendor_archives=vendor)
        _require(result['originals']['after'] == result['originals']['before'],
                 'protected original bytes changed')
        absence_filter = 'label=p11lab.proxy-producer=' + nonce
        containers_left = driver.command(['container', 'list', '--all', '--filter', absence_filter,
                                          '--format', '{{.ID}}']).stdout
        volumes_left = driver.command(['volume', 'list', '--filter', absence_filter,
                                       '--format', '{{.Name}}']).stdout
        result['absence'] = {'containers': containers_left[:2048], 'volumes': volumes_left[:2048]}
        if containers_left.strip() or volumes_left.strip():
            result['cleanup_errors'].append('owned resources remain listed')
            raise ProxyProducerError('producer cleanup unconfirmed: owned resources remain')
        if cancelled():
            raise InterruptedError('producer attempt cancelled')
        elapsed = _clock() - start
        result['deadline'] = {'limit_seconds': policy['whole_attempt_seconds'],
                              'elapsed_seconds': elapsed,
                              'verdict': ('within-budget'
                                          if elapsed <= policy['whole_attempt_seconds']
                                          else 'over-budget'),
                              'cleanup_reserve_seconds': policy['cleanup_reserve_seconds'],
                              'failure_receipt_reserve_seconds':
                                  policy['failure_receipt_reserve_seconds']}
        _require(elapsed <= policy['whole_attempt_seconds'],
                 'producer whole-attempt budget exceeded')
        result['status'] = 'observation-prepared'
        observed_cancel = cancelled()
        result['interrupted_signal'] = observed_cancel
        if observed_cancel is not None:
            raise InterruptedError('producer attempt cancelled')
        result['phases'] = phases | {'elapsed_seconds': elapsed}
        receipt = canonical(result) + b'\n'
        _require(len(receipt) <= 16 * 1024 * 1024, 'producer receipt exceeds bound')
        remaining_before_publish = policy['whole_attempt_seconds'] - (_clock() - start)
        if remaining_before_publish <= 0:
            raise ProxyProducerError('producer whole-attempt budget exceeded')
        _require_receipt_headroom(output, len(receipt))
        if not _bounded_write_bytes(output / 'proxy-producer-observation.json', receipt,
                                    remaining_before_publish):
            raise ProxyProducerError(
                'producer receipt write abandoned: receipt unconfirmed after %.3f seconds'
                % remaining_before_publish)
        published = _clock() - start
        if cancelled() is not None:
            raise InterruptedError('producer attempt cancelled')
        result['deadline'] = {'limit_seconds': policy['whole_attempt_seconds'],
                              'elapsed_seconds': published,
                              'verdict': ('within-budget'
                                          if published <= policy['whole_attempt_seconds']
                                          else 'over-budget'),
                              'cleanup_reserve_seconds': policy['cleanup_reserve_seconds'],
                              'failure_receipt_reserve_seconds':
                                  policy['failure_receipt_reserve_seconds']}
        result['phases'] = phases | {'elapsed_seconds': published}
        _require(published <= policy['whole_attempt_seconds'],
                 'producer whole-attempt budget exceeded')
        witness = {'kind': 'bounded-api-return', 'operation': 'production-observation',
                   'receipt_sha256': hashlib.sha256(receipt).hexdigest(),
                   'caller_observation': 'return-must-be-observed-by-caller',
                   'authority': 'not-established', 'prior_attempt_completion': 'unconfirmed'}
        return {**result, 'status': 'local-production-observed', 'completion_witness': witness}
    except BaseException as error:
        result['error'] = _error_record(error)
        driver = engine or Docker()
        failure_start = _clock()
        cleanup_state = {'exhausted': False}

        def _cleanup_open(step: str) -> bool:
            if cleanup_state['exhausted']:
                return False
            if _clock() - failure_start > policy['cleanup_reserve_seconds']:
                cleanup_state['exhausted'] = True
                result['cleanup_errors'].append(
                    'cleanup reserve exhausted: ' + step + ' and later cleanup unconfirmed')
                return False
            return True

        # Clamp every Docker control call in cleanup to the remaining reserve.
        # Shared stop/remove/inspection helpers all funnel through
        # driver.command, so wrapping it bounds each of their five commands
        # without duplicating ownership checks or touching shared modules.
        # Only installed when Docker cleanup may run, so input-refusal paths
        # never touch the engine.
        reserve_cleanup = policy['cleanup_reserve_seconds']
        needs_docker_cleanup = owned is not None or output_sandbox is not None or any(
            'container_id' in stage for stage in result['stages'])
        original_cleanup_command = driver.command if needs_docker_cleanup else None

        def _clamped_cleanup_command(args: list[str], timeout: float = 15,
                                     **kwargs: Any) -> Any:
            assert original_cleanup_command is not None
            remaining = reserve_cleanup - (_clock() - failure_start)
            if remaining <= 0:
                raise DockerError(
                    'cleanup reserve exhausted: Docker operation abandoned, '
                    'cleanup unconfirmed')
            clamped = timeout if timeout <= remaining else remaining
            return original_cleanup_command(args, timeout=clamped, **kwargs)

        if needs_docker_cleanup:
            driver.command = _clamped_cleanup_command  # type: ignore[method-assign]
        try:
            if owned is not None and _cleanup_open('container stop'):
                try:
                    driver.stop(owned, labels)
                except Exception as failure:
                    result['cleanup_errors'].append('stop: ' + str(failure))
            if owned is not None and _cleanup_open('container terminal inspection'):
                try:
                    result['terminal_inspection'] = _inspection(driver, owned, labels)
                except Exception as failure:
                    result['cleanup_errors'].append('stop: ' + str(failure))
            if owned is not None and _cleanup_open('container remove'):
                try:
                    driver.remove('container', owned, labels)
                    result['terminal_cleanup'] = 'removed-exact-owned-container'
                except Exception as failure:
                    result['cleanup_errors'].append('remove: ' + str(failure))
            if output_sandbox is not None and _cleanup_open('output volume close'):
                try:
                    result['cleanup_errors'].extend(output_sandbox.close())
                except Exception as failure:
                    result['cleanup_errors'].append('output: ' + str(failure))
            staged = output / 'staging' / 'source'
            if 'staging' in result and 'after' not in result['staging'] and staged.is_dir() \
                    and _cleanup_open('staging re-inventory'):
                try:
                    _, staging_after = _inventory_tree(staged, policy['staging_limits'])
                    result['staging']['after'] = staging_after
                except Exception as failure:
                    result['integrity_errors'].append('staging-after: ' + str(failure))
            if 'originals' in result and 'after' not in result['originals'] \
                    and _cleanup_open('originals re-verification'):
                try:
                    result['originals']['after'] = _check_originals(
                        selection, archive=archive, snapshot=snapshot, vendor_archives=vendor)
                except Exception as failure:
                    result['integrity_errors'].append('originals-after: ' + str(failure))
            touched = output_sandbox is not None or any(
                'container_id' in stage for stage in result['stages'])
            if touched and 'absence' not in result and _cleanup_open(
                    'owned resource absence listing'):
                try:
                    absence_filter = 'label=p11lab.proxy-producer=' + nonce
                    containers_left = driver.command(
                        ['container', 'list', '--all', '--filter',
                         absence_filter, '--format', '{{.ID}}']).stdout
                    volumes_left = driver.command(
                        ['volume', 'list', '--filter', absence_filter,
                         '--format', '{{.Name}}']).stdout
                    result['absence'] = {'containers': containers_left[:2048],
                                         'volumes': volumes_left[:2048]}
                    if containers_left.strip() or volumes_left.strip():
                        result['cleanup_errors'].append('owned resources remain listed')
                except Exception as failure:
                    result['cleanup_errors'].append('absence: ' + str(failure))
        finally:
            if needs_docker_cleanup:
                assert original_cleanup_command is not None
                driver.command = original_cleanup_command  # type: ignore[method-assign]
        cleanup_elapsed = _clock() - failure_start
        cleanup_exceeded = cleanup_state['exhausted'] \
            or cleanup_elapsed > policy['cleanup_reserve_seconds']
        result['cleanup_budget'] = {'limit_seconds': policy['cleanup_reserve_seconds'],
                                    'elapsed_seconds': cleanup_elapsed,
                                    'verdict': 'reserve-exceeded' if cleanup_exceeded
                                    else 'within-reserve'}
        result['status'] = 'failed-cleanup' if result['cleanup_errors'] else 'failed'
        result['interrupted_signal'] = cancelled()
        result['phases'] = phases | {'elapsed_seconds': _clock() - start}
        receipt_start = _clock()
        receipt_reserve = policy['failure_receipt_reserve_seconds']
        try:
            receipt = canonical(result) + b'\n'
            _require(len(receipt) <= 16 * 1024 * 1024, 'producer receipt exceeds bound')
            try:
                _require_receipt_headroom(output, len(receipt))
            except ProxyProducerError:
                error.add_note('failure receipt unavailable: insufficient headroom')
            else:
                receipt_remaining = receipt_reserve - (_clock() - receipt_start)
                if not _bounded_write_bytes(output / 'proxy-producer-observation.json', receipt,
                                            receipt_remaining):
                    error.add_note('failure receipt write abandoned after %.3f seconds: '
                                   'receipt unconfirmed' % max(receipt_remaining, 0.0))
                else:
                    receipt_elapsed = _clock() - receipt_start
                    if receipt_elapsed > receipt_reserve:
                        error.add_note('failure receipt exceeded reserve: %.3f seconds'
                                       % receipt_elapsed)
        except BaseException as failure:
            error.add_note('failure receipt unavailable: ' + type(failure).__name__)
        raise
    finally:
        for signum, handler in old_handlers.items():
            signal.signal(signum, handler)
