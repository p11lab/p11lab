"""Inert Cargo registry input materialization; acquisition is not build authority."""
from __future__ import annotations

from dataclasses import dataclass
import copy
import hashlib
import io
import json
import os
import posixpath
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import tomllib
import zlib

from .tool_downloads import ProxyInputRecord, safe_directory
from .catalog import package_data
from .models import ProxyBuildIdentityV1
from . import tls as tls_module
from .proxy_derivative import load_parent_selection, verify_derivative_parent
from .tool_inputs import _file, _json


class ProxyInputError(ValueError):
    """Proxy input verification failed."""


_MAX_BYTES = 256 * 1024 * 1024
_MAX_VENDOR_BYTES = 512 * 1024 * 1024
_MAX_MEMBERS = 30000
_REGISTRY = 'registry+https://github.com/rust-lang/crates.io-index'
_SAFE = re.compile(r'[A-Za-z0-9_.+\-]+\Z')
_SHA = re.compile(r'[0-9a-f]{64}\Z')


@dataclass(frozen=True)
class ProxySourceSelection:
    """Fixed package-selected source identity, not caller or release authority."""
    commit: str
    commit_object: bytes
    tree: str
    archive_sha256: str
    archive_size: int
    archive_prefix: str
    cargo_lock_sha256: str
    members: tuple[dict, ...]


@dataclass(frozen=True)
class VerifiedProxySource:
    selection: ProxySourceSelection
    lock_bytes: bytes
    workspace: dict[str, str]
    links: dict[str, dict[str, str]]


@dataclass(frozen=True)
class ProxyInputCache:
    """Locations of retained inputs; the installed selection supplies identities."""
    source_archive: Path
    payload_root: Path
    vendor_root: Path
    debian_receipt: Path
    acquisition_receipt: Path | None = None


def load_proxy_source_selection() -> ProxySourceSelection:
    raw = package_data('tool-inputs/proxy/source-v1.json').read_bytes()
    _require(_digest(raw) == 'b0356ac609612816605f426165c48ea73da192f6e96abbecf7f2ec3c33b50a3d',
             'installed proxy source selection changed')
    data = _json(raw)
    commit_object = data['commit_object'].encode('utf-8')
    _require(_git_digest('commit', commit_object) == data['commit']
             and commit_object.startswith(('tree ' + data['tree'] + '\n').encode()), 'proxy commit/tree mismatch')
    return ProxySourceSelection(commit=data['commit'], commit_object=commit_object, tree=data['tree'], archive_sha256=data['archive_sha256'],
                                archive_size=data['archive_size'], archive_prefix=data['archive_prefix'],
                                cargo_lock_sha256=data['cargo_lock_sha256'], members=tuple(data['members']))


def verify_selected_proxy_source(archive: Path) -> VerifiedProxySource:
    selection = load_proxy_source_selection()
    names = ('Cargo.lock', 'Cargo.toml', *(f'crates/{name}/Cargo.toml' for name in
             ('audit', 'types', 'proto', 'backend', 'server', 'client', 'cli', 'shim')))
    raw = _regular_bytes(Path(archive), selection.archive_size)
    _require(len(raw) == selection.archive_size, 'selected source archive size mismatch')
    observed = inspect_source_members(raw, selection.archive_sha256, selection.archive_prefix,
                                      selection.tree, list(selection.members), contents=names)
    contents = observed['contents']
    lock = contents.pop('Cargo.lock')
    expected = {member['path']: member['sha256'] for member in selection.members if member['path'] in contents}
    workspace = validate_workspace_mapping(lock, selection.cargo_lock_sha256, contents, expected)
    return VerifiedProxySource(selection, lock, workspace, observed['links'])


def load_proxy_tool_records() -> tuple[ProxyInputRecord, ...]:
    """Return the fixed installed tool roster; source/build/rights remain separate."""
    assets = (('rust-v1.json', 'cd0da947db9fe2044b0bf8d0817d727d3bf3678d109f42697c43ec32f03ea2e5'),
              ('protoc-v1.json', '2b99d40ed3960abcdbfefafa515325e61faf63be909e3fa25657edad69ea3bce'),
              ('crates-v1.json', '7e2369937225fbbffcc75355247b6a5191c03f28d4378b1d9fe4ad8bca91f1a3'))
    rows: list[dict] = []
    for name, digest in assets:
        raw = package_data('tool-inputs/proxy/' + name).read_bytes()
        _require(_digest(raw) == digest, 'installed proxy tool selection changed')
        data = _json(raw)
        if name == 'rust-v1.json':
            for support in data['supporting_files']:
                _file(support)
                retained = package_data(support['path']).read_bytes()
                _require(len(retained) == support['size'] and _digest(retained) == support['sha256'],
                         'installed Rust signature evidence changed')
        rows.extend([data['record']] if 'record' in data else data['records'])
    records = tuple(ProxyInputRecord(**row) for row in rows)
    _require(len(records) == 286 and len({r.path for r in records}) == len(records)
             and sum(r.size for r in records) <= 1024**3, 'invalid proxy tool roster')
    for record in records:
        _file(vars(record))
    return records


def load_proxy_build_selection() -> dict:
    """Return fixed intended build settings, with no claim of execution."""
    raw = package_data('tool-inputs/proxy/build-selection-v1.json').read_bytes()
    _require(_digest(raw) == '9667b71f83b65061f5b5edb5d68d42c724df7c70daf691bac697222e873e1932',
             'installed proxy build selection changed')
    return _json(raw)


def verify_proxy_payload(record: ProxyInputRecord, root: Path) -> dict:
    """Rehash one typed opaque record; caller-provided records grant no authority."""
    _require(type(record) is ProxyInputRecord and record.kind in
             {'proxy-source', 'proxy-rust-dist', 'proxy-crate', 'proxy-protobuf'}, 'typed proxy input required')
    _file(vars(record))
    path = Path(root).absolute().joinpath(*PurePosixPath(record.path).parts)
    safe_directory(path.parent)
    raw = _regular_bytes(path, record.size)
    _require(len(raw) == record.size and _digest(raw) == record.sha256, 'proxy payload identity mismatch')
    return {'path': record.path, 'size': len(raw), 'sha256': record.sha256}


def _validate_acquisition_observations(receipt: dict) -> dict:
    """Check a closed observation roster; a mutable receipt is not authority."""
    from urllib.parse import urlsplit
    from .tool_downloads import _target
    selection = load_proxy_source_selection()
    source_url = 'https://codeload.github.com/mingulov/pkcs11-proxy-ng/tar.gz/' + selection.commit
    source = receipt.get('source_observation')
    _require(isinstance(source, dict) and source.keys() == {'sha256', 'size', 'final_url'}
             and type(source['size']) is int and source['size'] == selection.archive_size
             and source['sha256'] == selection.archive_sha256 and isinstance(source['final_url'], str),
             'source acquisition observation mismatch')
    assert isinstance(source, dict)
    _target(source['final_url'])
    _require(urlsplit(source['final_url']).netloc == urlsplit(source_url).netloc, 'source acquisition origin mismatch')
    records = load_proxy_tool_records()
    observations = receipt.get('observations')
    _require(isinstance(observations, list) and len(observations) == len(records), 'incomplete acquisition observations')
    assert isinstance(observations, list)
    for record, observation in zip(records, observations):
        _require(isinstance(observation, dict) and observation.keys() == {'path', 'size', 'sha256', 'final_url'}
                 and observation['path'] == record.path and type(observation['size']) is int
                 and observation['size'] == record.size and observation['sha256'] == record.sha256
                 and isinstance(observation['final_url'], str), 'payload acquisition observation mismatch')
        if record.kind == 'proxy-protobuf':
            _require(observation['final_url'] == 'https://release-assets.githubusercontent.com',
                     'protobuf acquisition origin mismatch')
        else:
            _target(observation['final_url'])
            _require(urlsplit(observation['final_url']).netloc == urlsplit(record.url).netloc,
                     'payload acquisition origin mismatch')
    return {'selected_origin': 'receipt-consistent-unattested', 'acquisition_provenance': 'unattested-receipt'}


def verify_proxy_acquisition_receipt(receipt_path: Path) -> dict:
    """Check unattested origins, including provisional manifests, without granting authority."""
    path = Path(receipt_path).absolute()
    safe_directory(path.parent)
    value = _json(_regular_bytes(path, 4 * 1024 * 1024))
    _require(isinstance(value, dict), 'invalid proxy acquisition receipt')
    if 'schema' in value or 'state' in value:
        _require(value.keys() == {'schema', 'state', 'manifest'}
                 and value['schema'] == 'p11lab.proxy-input-observations.v1'
                 and value['state'] == 'provisional' and isinstance(value['manifest'], dict),
                 'invalid provisional proxy observations')
        return _validate_acquisition_observations(value['manifest']) | {
            'acquisition_provenance': 'unattested-provisional-observation',
            'attempt_completion': 'unconfirmed'}
    return _validate_acquisition_observations(value) | {'attempt_completion': 'unconfirmed'}


def verify_selected_proxy_inputs(cache: ProxyInputCache) -> dict:
    """Verify selected opaque inputs and vendor tree; never claim build readiness."""
    from .tool_inputs import _verify_debian_inputs, load_tool_input_lock, verify_resolved_tool_inputs
    _require(type(cache) is ProxyInputCache, 'typed proxy cache required')
    source = verify_selected_proxy_source(cache.source_archive)
    records = load_proxy_tool_records()
    roster = _registry_roster(source.lock_bytes, source.selection.cargo_lock_sha256, source.workspace)
    crates = {PurePosixPath(r.path).name[:-6]: r.sha256 for r in records if r.kind == 'proxy-crate'}
    _require(crates == roster, 'selected crate records differ from source lock')
    observed = [verify_proxy_payload(record, cache.payload_root) for record in records]
    vendor = verify_materialized_crates(source.lock_bytes, source.selection.cargo_lock_sha256,
                                        cache.payload_root / 'crates', cache.vendor_root, workspace=source.workspace)
    debian = verify_resolved_tool_inputs('consumer', target='debian13-amd64', receipt_path=cache.debian_receipt)
    lock = load_tool_input_lock('consumer', target='debian13-amd64')
    _verify_debian_inputs(lock, cache.debian_receipt.parent)
    provenance = (verify_proxy_acquisition_receipt(cache.acquisition_receipt) if cache.acquisition_receipt is not None
                  else {'selected_origin': 'unverified-no-acquisition-receipt', 'acquisition_provenance': 'unverified'})
    return {'status': 'partial-input-bytes-verified', 'byte_verification': 'verified', **provenance,
            'source_commit': source.selection.commit,
            'source_tree': source.selection.tree, 'source_archive_sha256': source.selection.archive_sha256,
            'cargo_lock_sha256': source.selection.cargo_lock_sha256, 'workspace': source.workspace,
            'source_links': source.links, 'payloads': observed, 'vendor': vendor,
            'build_selection': load_proxy_build_selection(),
            'debian_lock_sha256': debian['lock_sha256'], 'debian_base_image': lock['base_image'],
            'build': 'not-run', 'compiler_signatures': 'retained-evidence-not-reverified',
            'protoc_signer': 'unverified', 'protobuf_redirect_identity': 'unverified-redacted-final-path',
            'builder_image': 'unresolved',
            'license_review': 'unreviewed', 'authority': 'not-established'}


_JOURNAL_LIMIT = 1024 * 1024


def _journal(root: Path, attempt_id: str, event: str, started: float, **fields) -> None:
    import time
    line = (json.dumps({'attempt_id': attempt_id, 'event': event,
                        'elapsed_seconds': round(max(0.0, time.monotonic() - started), 6), **fields},
                       sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()
    _require(len(line) <= 4096, 'proxy journal event limit')
    safe_directory(root)
    fd = os.open(root / 'attempt.jsonl', os.O_CREAT | os.O_APPEND | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        _require(stat.S_ISREG(info.st_mode) and info.st_size + len(line) <= _JOURNAL_LIMIT, 'proxy journal limit')
        _require(os.write(fd, line) == len(line), 'incomplete proxy journal write')
        os.fsync(fd)
    finally:
        os.close(fd)


def _observation(record: ProxyInputRecord, value: object) -> dict:
    from urllib.parse import urlsplit
    from .tool_downloads import _target
    _require(isinstance(value, dict) and value.keys() == {'sha256', 'size', 'final_url'}
             and value['sha256'] == record.sha256 and type(value['size']) is int and value['size'] == record.size
             and isinstance(value['final_url'], str), 'invalid proxy download observation')
    assert isinstance(value, dict)
    final_url = value['final_url']
    if record.kind == 'proxy-protobuf':
        _require(final_url == 'https://release-assets.githubusercontent.com', 'protobuf observation mismatch')
    else:
        _target(final_url)
        _require(urlsplit(final_url).netloc == urlsplit(record.url).netloc, 'proxy observation origin mismatch')
    return {'sha256': record.sha256, 'size': record.size, 'final_url': final_url}


def _resolve_attempt(root: Path, debian_receipt: Path, attempt_id: str, started: float, deadline: float) -> dict:
    import time
    from . import tool_downloads
    safe_directory(root.parent)
    root.mkdir(mode=0o700)
    _journal(root, attempt_id, 'attempt-start', started)
    selection = load_proxy_source_selection()
    source_record = ProxyInputRecord('source/proxy.tar.gz',
        'https://codeload.github.com/mingulov/pkcs11-proxy-ng/tar.gz/a348a5f59b535b1ca309ea9f0a722e3bec692f72',
        selection.archive_sha256, selection.archive_size, 'proxy-source')
    records = load_proxy_tool_records()
    _require(source_record.size + sum(r.size for r in records) <= 1024**3, 'proxy acquisition aggregate limit')
    _journal(root, attempt_id, 'download-start', started, path=source_record.path)
    source_observation = _observation(source_record, tool_downloads.download_proxy_file(
        source_record, root / source_record.path, deadline=deadline))
    _journal(root, attempt_id, 'download-complete', started, path=source_record.path, **source_observation)
    _journal(root, attempt_id, 'source-verification-start', started)
    source = verify_selected_proxy_source(root / source_record.path)
    roster = _registry_roster(source.lock_bytes, source.selection.cargo_lock_sha256, source.workspace)
    _require({PurePosixPath(r.path).name[:-6]: r.sha256 for r in records if r.kind == 'proxy-crate'} == roster,
             'selected crate records differ from source lock')
    _journal(root, attempt_id, 'source-verification-complete', started)
    payload = root / 'payload'
    payload.mkdir(mode=0o700)
    observations = []
    for record in records:
        _require(time.monotonic() < deadline, 'proxy acquisition deadline exceeded')
        _journal(root, attempt_id, 'download-start', started, path=record.path)
        observation = _observation(record, tool_downloads.download_proxy_file(record, payload / record.path, deadline=deadline))
        observations.append({'path': record.path} | observation)
        _journal(root, attempt_id, 'download-complete', started, path=record.path, **observation)
    _require(time.monotonic() < deadline, 'proxy acquisition deadline exceeded')
    _journal(root, attempt_id, 'materialization-start', started)
    materialize_locked_crates(source.lock_bytes, source.selection.cargo_lock_sha256, payload / 'crates',
                              root / 'vendor', workspace=source.workspace)
    _journal(root, attempt_id, 'materialization-complete', started)
    _journal(root, attempt_id, 'verification-start', started)
    cache = ProxyInputCache(root / source_record.path, payload, root / 'vendor', Path(debian_receipt))
    verified = verify_selected_proxy_inputs(cache)
    _require(time.monotonic() < deadline, 'proxy acquisition deadline exceeded')
    observation_receipt = {'source_observation': source_observation, 'observations': observations}
    receipt = verified | observation_receipt | _validate_acquisition_observations(observation_receipt) | {
        'elapsed_seconds': time.monotonic() - started, 'attempt_id': attempt_id}
    _journal(root, attempt_id, 'verification-complete', started)
    return receipt


def _finish_attempt(root: Path, attempt_id: str, started: float, status: str,
                    worker_pid: int, reaped: bool | None, wait_status: int | None,
                    error_kind: str, native_errno: int | None, reaper_cleanup: str,
                    operation_category: str, result: dict | None = None) -> dict:
    from .receipts import write_receipt
    path = root / 'attempt.jsonl'
    try:
        lines = _read_journal(path)
    except (OSError, ValueError):
        return {'journal': 'unavailable', 'receipt': 'not-written'}
    if not lines or lines[0].get('attempt_id') != attempt_id or lines[0].get('event') != 'attempt-start':
        return {'journal': 'unavailable', 'receipt': 'not-written'}
    stage_names = {'download-start': 'download', 'source-verification-start': 'source-verification',
                   'materialization-start': 'materialization', 'verification-start': 'verification'}
    stage = 'initialization'
    for line in lines:
        if line.get('event') in stage_names:
            stage = stage_names[line['event']]
    receipt_path = root / 'proxy-inputs-provisional.json'
    if result is not None:
        write_receipt(receipt_path, {'schema': 'p11lab.proxy-input-observations.v1',
                                     'state': 'provisional', 'manifest': result})
    try:
        if result is not None:
            _journal(root, attempt_id, 'finalization-prepared', started, status='provisional', worker_pid=worker_pid,
                     worker_reaped=reaped, wait_status=wait_status, stage=stage, error_kind=error_kind,
                     native_errno=native_errno, acquisition_reaper_cleanup=reaper_cleanup,
                     reaper_cleanup='unconfirmed', operation_category='provisional')
        else:
            _journal(root, attempt_id, 'terminal', started, status=status, worker_pid=worker_pid,
                     worker_reaped=reaped, wait_status=wait_status, stage=stage, error_kind=error_kind, native_errno=native_errno,
                     reaper_cleanup=reaper_cleanup, operation_category=operation_category)
    except BaseException:
        if result is not None:
            receipt_path.unlink(missing_ok=True)
        raise
    return {'journal': 'retained', 'receipt': 'written' if result is not None else 'not-written'}


def _read_journal(path: Path) -> list[dict]:
    raw = _regular_bytes(path, _JOURNAL_LIMIT)
    result = [_json(line) for line in raw.splitlines()]
    _require(all(isinstance(line, dict) for line in result), 'invalid proxy journal')
    return result


def resolve_selected_proxy_inputs(output_dir: Path, *, debian_receipt: Path, timeout_seconds: float = 600) -> dict:
    """Run the complete inert acquisition under one hard bounded process boundary."""
    import math
    import time
    from uuid import uuid4
    from .proxy_supervisor import ProxyCleanupUnconfirmed, ProxyDeadlineExceeded, ProxyWorkerError, run_proxy_worker
    _require(type(timeout_seconds) in (int, float) and math.isfinite(timeout_seconds)
             and 0 < timeout_seconds <= 600, 'invalid acquisition timeout')
    started = time.monotonic()
    deadline = started + timeout_seconds
    root, attempt_id = Path(output_dir).absolute(), uuid4().hex
    try:
        witness = run_proxy_worker(lambda: _resolve_attempt(root, Path(debian_receipt), attempt_id, started, deadline),
                                   deadline=deadline, include_witness=True)
        result = witness.pop('result')
        result['supervision'] = witness
    except BaseException as error:
        operation = getattr(error, 'operation_category', getattr(error, 'category', 'interrupted'))
        status = 'timeout' if isinstance(error, ProxyDeadlineExceeded) or operation == 'timeout' else ('failed' if isinstance(error, ProxyWorkerError) else 'interrupted')
        pid = getattr(error, 'worker_pid', 0)
        reaped = getattr(error, 'worker_reaped', None)
        wait_status = getattr(error, 'wait_status', None)
        kind = getattr(error, 'category', 'interrupted')
        native_errno = getattr(error, 'native_errno', None)
        reaper_cleanup = getattr(error, 'lease_cleanup', 'confirmed')
        try:
            final = run_proxy_worker(lambda: _finish_attempt(root, attempt_id, started, status, pid, reaped, wait_status, kind, native_errno, reaper_cleanup, operation),
                                     deadline=time.monotonic() + 2)
            if final['journal'] != 'retained':
                error.add_note('proxy attempt journal unavailable')
        except BaseException:
            error.add_note('proxy attempt journal/cleanup status unavailable')
        if isinstance(error, ProxyCleanupUnconfirmed):
            raise
        if isinstance(error, ProxyWorkerError):
            failure = ProxyInputError('proxy acquisition failed: ' + error.category)
            for note in getattr(error, '__notes__', ()):
                failure.add_note(note)
            raise failure from None
        raise
    try:
        final_witness = run_proxy_worker(lambda: _finish_attempt(root, attempt_id, started, 'completed', witness['worker_pid'],
                                                        witness['worker_reaped'], witness['wait_status'], 'none', None,
                                                        'confirmed', 'completed', result),
                                         deadline=deadline, include_witness=True)
        final = final_witness.pop('result')
        _require(final['journal'] == 'retained' and final['receipt'] == 'written', 'proxy attempt finalization incomplete')
    except BaseException as error:
        operation = getattr(error, 'operation_category', getattr(error, 'category', 'interrupted'))
        status = 'timeout' if isinstance(error, ProxyDeadlineExceeded) or operation == 'timeout' else ('failed' if isinstance(error, ProxyWorkerError) else 'interrupted')
        pid = getattr(error, 'worker_pid', 0)
        reaped = getattr(error, 'worker_reaped', None)
        wait_status = getattr(error, 'wait_status', None)
        kind = getattr(error, 'category', 'interrupted')
        native_errno = getattr(error, 'native_errno', None)
        reaper_cleanup = getattr(error, 'lease_cleanup', 'confirmed')
        try:
            run_proxy_worker(lambda: _abort_finalization(root, attempt_id, started, status, pid, reaped, wait_status, kind, native_errno, reaper_cleanup, operation),
                             deadline=time.monotonic() + 2)
        except BaseException:
            error.add_note('proxy finalization journal status unavailable; observations remain provisional')
        raise
    result['finalization_supervision'] = final_witness
    return result


def _abort_finalization(root: Path, attempt_id: str, started: float, status: str,
                        worker_pid: int, reaped: bool | None, wait_status: int | None, error_kind: str,
                        native_errno: int | None, reaper_cleanup: str, operation_category: str) -> dict:
    lines = _read_journal(root / 'attempt.jsonl')
    _require(bool(lines) and lines[0].get('attempt_id') == attempt_id, 'unknown proxy attempt')
    _journal(root, attempt_id, 'terminal', started, status=status, stage='finalization', error_kind=error_kind,
             worker_pid=worker_pid, worker_reaped=reaped, wait_status=wait_status, native_errno=native_errno,
             reaper_cleanup=reaper_cleanup, operation_category=operation_category)
    return {'receipt': 'provisional', 'journal': 'retained'}


def _require(value: object, message: str) -> None:
    if not value:
        raise ProxyInputError(message)


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_segment(value: str) -> bool:
    return bool(value) and value not in ('.', '..') and all(32 < ord(c) < 127 and c not in '\\:' for c in value)


def _git_digest(kind: str, data: bytes) -> str:
    return hashlib.sha1(kind.encode() + b' ' + str(len(data)).encode() + b'\0' + data).hexdigest()


def _expand_source(raw: bytes) -> bytes:
    _require(len(raw) <= _MAX_BYTES, 'source archive too large')
    decoder = zlib.decompressobj(31)
    output = bytearray()
    try:
        for offset in range(0, len(raw), 65536):
            chunk = raw[offset:offset + 65536]
            while chunk:
                output.extend(decoder.decompress(chunk, 128 * 1024 * 1024 + 1 - len(output)))
                _require(len(output) <= 128 * 1024 * 1024, 'source expansion limit')
                chunk = decoder.unconsumed_tail
        output.extend(decoder.flush(128 * 1024 * 1024 + 1 - len(output)))
        _require(len(output) <= 128 * 1024 * 1024 and decoder.eof and not decoder.unused_data,
                 'invalid or trailing compressed source')
    except zlib.error as error:
        raise ProxyInputError('invalid compressed source') from error
    return bytes(output)


def _preflight_tar(raw: bytes, *, allow_symlinks: bool) -> None:
    """Frame every bounded tar record before the generic parser sees metadata."""
    from .round_core.worker import _pax_fields
    _require(len(raw) % 512 == 0, 'invalid tar frame length')
    offset = records = metadata = extensions = 0
    while offset < len(raw):
        header = raw[offset:offset + 512]
        offset += 512
        if not any(header):
            _require(len(raw) - offset >= 512 and not any(raw[offset:]), 'nonzero or short tar terminator')
            return
        records += 1
        _require(records <= _MAX_MEMBERS, 'tar record limit')
        try:
            info = tarfile.TarInfo.frombuf(header, 'utf-8', 'strict')
        except (tarfile.HeaderError, ValueError, UnicodeError) as error:
            raise ProxyInputError('invalid tar header') from error
        size, kind = info.size, info.type
        _require(0 <= size <= _MAX_BYTES, 'tar record size limit')
        padded = (size + 511) // 512 * 512
        _require(offset + padded <= len(raw), 'truncated tar record')
        payload = raw[offset:offset + size]
        _require(not any(raw[offset + size:offset + padded]), 'nonzero tar padding')
        offset += padded
        if kind in (b'x', b'g', b'L', b'K'):
            metadata += size
            extensions += 1
            _require(size <= 65536 and metadata <= 1024 * 1024 and extensions <= 8, 'tar metadata limit')
            if kind in (b'x', b'g'):
                try:
                    _pax_fields(payload)
                except (ValueError, UnicodeError) as error:
                    raise ProxyInputError('unsafe tar metadata') from error
            else:
                _require(size <= 4096, 'tar long name limit')
        else:
            extensions = 0
            _require(kind in (b'0', b'\0', b'5') or (allow_symlinks and kind == b'2'), 'unsupported tar type')
            _require(kind not in (b'5', b'2') or size == 0, 'directory or symlink payload')
    raise ProxyInputError('missing tar terminator')


def inspect_source_members(raw: bytes, archive_sha256: str, prefix: str, tree_sha1: str,
                           records: list[dict], *, contents: tuple[str, ...] = ()) -> dict:
    """Verify a closed Git source archive, retaining links as inert target text.

    Selection data must be independently trusted. This function never creates
    files or links and does not authorize executing any candidate content.
    """
    _require(isinstance(raw, bytes) and bool(_SHA.fullmatch(archive_sha256)) and _digest(raw) == archive_sha256,
             'source archive identity mismatch')
    _require(isinstance(prefix, str) and bool(_SAFE.fullmatch(prefix))
             and isinstance(tree_sha1, str) and bool(re.fullmatch(r'[0-9a-f]{40}', tree_sha1)), 'invalid source selector')
    _require(isinstance(records, list) and 0 < len(records) <= _MAX_MEMBERS, 'invalid source roster')
    expected = {}
    directories = {''}
    for record in records:
        _require(isinstance(record, dict) and record.keys() == {'path', 'mode', 'size', 'sha256', 'git_blob'},
                 'invalid source record')
        path = record['path']
        _require(isinstance(path, str) and all(p not in ('', '.', '..') and bool(_SAFE.fullmatch(p))
                                               for p in path.split('/')) and path not in expected, 'unsafe source path')
        _require(record['mode'] in ('100644', '100755', '120000') and type(record['size']) is int
                 and 0 <= record['size'] <= _MAX_BYTES and isinstance(record['sha256'], str)
                 and bool(_SHA.fullmatch(record['sha256'])) and isinstance(record['git_blob'], str)
                 and bool(re.fullmatch(r'[0-9a-f]{40}', record['git_blob'])), 'invalid source identity')
        expected[path] = record
        parts = path.split('/')
        directories.update('/'.join(parts[:i]) for i in range(1, len(parts)))
    _require(isinstance(contents, tuple) and len(set(contents)) == len(contents)
             and all(p in expected and expected[p]['mode'] != '120000' for p in contents), 'invalid source content selector')
    seen, seen_dirs, links, selected = set(), set(), {}, {}
    try:
        expanded = _expand_source(raw)
        _preflight_tar(expanded, allow_symlinks=True)
        with tarfile.open(fileobj=io.BytesIO(expanded), mode='r:') as archive:
            for member in archive:
                parts = member.name.rstrip('/').split('/')
                _require(parts[0] == prefix and all(p not in ('', '.', '..') and bool(_SAFE.fullmatch(p))
                                                     for p in parts), 'unsafe source archive path')
                path = '/'.join(parts[1:])
                if member.isdir():
                    _require(path in directories and path not in seen_dirs, 'unknown or duplicate source directory')
                    seen_dirs.add(path)
                    continue
                _require(path in expected and path not in seen, 'source member roster mismatch')
                record = expected[path]
                if member.issym():
                    _require(record['mode'] == '120000' and member.size == 0, 'source link mode mismatch')
                    data = member.linkname.encode('utf-8')
                    _require(member.linkname and not member.linkname.startswith('/') and '\\' not in member.linkname,
                             'unsafe source link target')
                    target = posixpath.normpath(posixpath.join(posixpath.dirname(path), member.linkname))
                    _require(target in expected, 'source link escapes or has no selected target')
                    links[path] = {'target': member.linkname, 'resolved': target}
                else:
                    _require(member.isfile() and record['mode'] == ('100755' if member.mode & 0o111 else '100644')
                             and member.size == record['size'], 'source file mode or size mismatch')
                    stream = archive.extractfile(member)
                    _require(stream is not None, 'source member unavailable')
                    assert stream is not None
                    data = stream.read(member.size + 1)
                _require(len(data) == record['size'] and _digest(data) == record['sha256']
                         and _git_digest('blob', data) == record['git_blob'], 'source member identity mismatch')
                if path in contents:
                    selected[path] = data
                seen.add(path)
    except (tarfile.TarError, OSError, UnicodeError) as error:
        raise ProxyInputError('invalid source archive') from error
    _require(seen == set(expected), 'missing source member')
    for path in links:
        visited = set()
        target = path
        while target in links:
            _require(target not in visited, 'cyclic source link')
            visited.add(target)
            target = links[target]['resolved']
    tree: dict = {}
    for path, record in expected.items():
        directory = tree
        parts = path.split('/')
        for part in parts[:-1]:
            _require(part not in directory or isinstance(directory[part], dict), 'source file/directory collision')
            directory = directory.setdefault(part, {})
        _require(parts[-1] not in directory, 'source file/directory collision')
        directory[parts[-1]] = (record['mode'], record['git_blob'])

    def tree_hash(directory: dict) -> str:
        result = bytearray()
        for name, value in sorted(directory.items(), key=lambda item: (item[0] + ('/' if isinstance(item[1], dict) else '')).encode()):
            mode, oid = ('40000', tree_hash(value)) if isinstance(value, dict) else value
            result.extend(mode.encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(oid))
        return _git_digest('tree', bytes(result))

    _require(tree_hash(tree) == tree_sha1, 'source tree identity mismatch')
    return {'archive_sha256': archive_sha256, 'tree': tree_sha1, 'links': links,
            'contents': selected, 'member_count': len(seen)}


def _regular_bytes(path: Path, maximum: int) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            _require(stat.S_ISREG(info.st_mode) and info.st_size <= maximum, 'unsafe or oversized input')
            data = stream.read(maximum + 1)
            _require(len(data) == info.st_size, 'input changed or exceeded size limit')
            return data
    except OSError as error:
        raise ProxyInputError('cannot read input safely') from error


def _lock(raw: bytes, expected: str) -> dict:
    _require(len(raw) <= 2 * 1024 * 1024 and bool(_SHA.fullmatch(expected))
             and _digest(raw) == expected, 'Cargo.lock identity mismatch')
    try:
        lock = tomllib.loads(raw.decode('utf-8'))
    except (UnicodeError, tomllib.TOMLDecodeError) as error:
        raise ProxyInputError('invalid Cargo.lock') from error
    _require(lock.get('version') in (3, 4) and isinstance(lock.get('package'), list), 'unsupported lock format')
    return lock


def _registry_roster(raw: bytes, expected: str, workspace: dict[str, str] | None) -> dict[str, str]:
    lock = _lock(raw, expected)
    result: dict[str, str] = {}
    local = set()
    for package in lock['package']:
        _require(isinstance(package, dict), 'invalid lock package')
        name, version = package.get('name'), package.get('version')
        _require(isinstance(name, str) and isinstance(version, str)
                 and bool(_SAFE.fullmatch(name)) and bool(_SAFE.fullmatch(version)), 'unsafe package identity')
        if 'source' not in package:
            _require('checksum' not in package, 'unexpected local package checksum')
            key = name + ' ' + version
            _require(key not in local, 'duplicate local package')
            local.add(key)
            continue
        _require(package.get('source') == _REGISTRY, 'unsupported git, path or registry source')
        checksum = package.get('checksum')
        _require(isinstance(checksum, str) and bool(_SHA.fullmatch(checksum)), 'missing registry checksum')
        identity = name + '-' + version
        _require(identity not in result, 'duplicate package identity')
        result[identity] = checksum
    _require(bool(result), 'empty registry roster')
    _require(local == set(workspace or {}), 'workspace roster mismatch')
    return result


def validate_workspace_mapping(lock_bytes: bytes, expected_lock_sha256: str,
                               manifests: dict[str, bytes], expected_sha256: dict[str, str]) -> dict[str, str]:
    """Bind local lock packages to selected workspace manifests without executing them.

    The caller must obtain the expected digests from an independently selected
    source tree; these arguments do not themselves grant candidate authority.
    """
    lock = _lock(lock_bytes, expected_lock_sha256)
    _require(manifests.keys() == expected_sha256.keys() and 'Cargo.toml' in manifests,
             'workspace manifest roster mismatch')
    parsed = {}
    for name, raw in manifests.items():
        _require(isinstance(name, str) and isinstance(raw, bytes) and len(raw) <= 1024 * 1024
                 and isinstance(expected_sha256[name], str) and bool(_SHA.fullmatch(expected_sha256[name]))
                 and _digest(raw) == expected_sha256[name], 'workspace manifest identity mismatch')
        try:
            parsed[name] = tomllib.loads(raw.decode('utf-8'))
        except (UnicodeError, tomllib.TOMLDecodeError) as error:
            raise ProxyInputError('invalid workspace manifest') from error
        _require('patch' not in parsed[name] and 'replace' not in parsed[name], 'unsupported source substitution')
    root = parsed['Cargo.toml'].get('workspace')
    _require(isinstance(root, dict) and isinstance(root.get('members'), list), 'invalid workspace')
    assert isinstance(root, dict)
    members = root['members']
    _require(all(isinstance(m, str) and m and not m.startswith('/')
                 and all(p not in ('', '.', '..') and bool(_SAFE.fullmatch(p)) for p in m.split('/'))
                 for m in members) and len(set(members)) == len(members), 'unsupported workspace member')
    _require(set(parsed) == {'Cargo.toml'} | {m + '/Cargo.toml' for m in members}, 'workspace member roster mismatch')
    mapping: dict[str, str] = {}
    by_directory: dict[str, str] = {}
    workspace_package = root.get('package', {})
    _require(isinstance(workspace_package, dict), 'invalid workspace package')
    for member in members:
        package = parsed[member + '/Cargo.toml'].get('package')
        _require(isinstance(package, dict), 'missing workspace package')
        assert isinstance(package, dict)
        pkg_name, pkg_version = package.get('name'), package.get('version')
        if pkg_version == {'workspace': True}:
            pkg_version = workspace_package.get('version')
        _require(isinstance(pkg_name, str) and bool(_SAFE.fullmatch(pkg_name))
                 and isinstance(pkg_version, str) and bool(_SAFE.fullmatch(pkg_version)), 'invalid workspace identity')
        assert isinstance(pkg_name, str) and isinstance(pkg_version, str)
        key = pkg_name + ' ' + pkg_version
        _require(key not in mapping, 'duplicate workspace identity')
        mapping[key] = member
        by_directory[member] = pkg_name
    local = []
    for package in lock['package']:
        _require(isinstance(package, dict), 'invalid lock package')
        if 'source' not in package:
            name, version = package.get('name'), package.get('version')
            _require(isinstance(name, str) and isinstance(version, str) and 'checksum' not in package,
                     'invalid local package')
            local.append(name + ' ' + version)
        else:
            _require(package['source'] == _REGISTRY, 'unsupported git or registry source')
    _require(len(local) == len(set(local)) and set(local) == set(mapping), 'workspace lock roster mismatch')

    def dependencies(table: object, directory: str) -> None:
        _require(isinstance(table, dict), 'invalid dependency table')
        assert isinstance(table, dict)
        for name, spec in table.items():
            if isinstance(spec, str):
                continue
            _require(isinstance(spec, dict) and not ({'git', 'registry', 'registry-index'} & spec.keys()),
                     'unsupported dependency source')
            if 'workspace' in spec:
                _require(spec['workspace'] is True and name in root.get('dependencies', {}),
                         'unbound workspace dependency')
            if 'path' in spec:
                path = spec['path']
                _require(isinstance(path, str) and path and not path.startswith('/') and '\\' not in path,
                         'unsafe path dependency')
                target = posixpath.normpath(posixpath.join(directory, path))
                _require(target in by_directory and by_directory[target] == spec.get('package', name),
                         'path dependency outside selected workspace')

    for manifest, content in parsed.items():
        directory = posixpath.dirname(manifest)
        for kind in ('dependencies', 'dev-dependencies', 'build-dependencies'):
            if kind in content:
                dependencies(content[kind], directory)
        targets = content.get('target', {})
        _require(isinstance(targets, dict), 'invalid target dependencies')
        for target in targets.values():
            _require(isinstance(target, dict), 'invalid target dependency table')
            for kind in ('dependencies', 'dev-dependencies', 'build-dependencies'):
                if kind in target:
                    dependencies(target[kind], directory)
    if 'dependencies' in root:
        dependencies(root['dependencies'], '')
    return mapping


def _inspect_crate(raw: bytes, identity: str) -> tuple[dict[str, bytes], dict[str, int], int]:
    files: dict[str, bytes] = {}
    modes: dict[str, int] = {}
    seen: set[str] = set()
    total = 0
    try:
        expanded = _expand_source(raw)
        _preflight_tar(expanded, allow_symlinks=False)
        with tarfile.open(fileobj=io.BytesIO(expanded), mode='r:') as archive:
            for member in archive:
                _require(len(seen) < _MAX_MEMBERS, 'crate member limit exceeded')
                name = member.name.rstrip('/')
                parts = name.split('/')
                _require(parts[0] == identity and all(_safe_segment(p) for p in parts), 'unsafe crate member path')
                _require(name not in seen, 'duplicate crate member')
                seen.add(name)
                _require(member.isdir() or member.isfile(), 'crate member type is unsupported')
                if member.isdir():
                    continue
                _require(len(parts) > 1 and member.size >= 0, 'invalid crate file')
                _require(not member.mode & 0o7000 and member.mode & 0o400, 'unsupported crate file mode')
                relative = '/'.join(parts[1:])
                _require(relative != '.cargo-checksum.json', 'crate supplies checksum metadata')
                total += member.size
                _require(total <= _MAX_BYTES, 'crate expansion limit exceeded')
                stream = archive.extractfile(member)
                _require(stream is not None, 'crate file unavailable')
                assert stream is not None
                data = stream.read(member.size + 1)
                _require(len(data) == member.size, 'crate file length mismatch')
                files[relative] = data
                modes[relative] = member.mode & 0o777
    except (tarfile.TarError, EOFError, OSError) as error:
        raise ProxyInputError('invalid crate archive') from error
    _require(bool(files), 'empty crate')
    for name in seen:
        parts = name.split('/')
        for end in range(2, len(parts)):
            _require('/'.join(parts[1:end]) not in files, 'crate file/directory collision')
    paths = set(files)
    for path in files:
        parts = path.split('/')
        paths.update('/'.join(parts[:i]) for i in range(1, len(parts)))
    return files, modes, len(paths) + 2


def _checksum_metadata(files: dict[str, bytes], package: str) -> bytes:
    metadata = {'files': {p: _digest(data) for p, data in sorted(files.items())}, 'package': package}
    return json.dumps(metadata, sort_keys=True, separators=(',', ':')).encode()


def materialize_locked_crates(lock_bytes: bytes, expected_lock_sha256: str,
                              archives: Path, output: Path, *, workspace: dict[str, str] | None = None) -> dict:
    """Materialize a registry-only lock; caller must authenticate the lock separately.

    A receipt documents bytes, not authority, license admission, compilation or execution.
    Workspace entries require an independently authenticated mapping. Git and
    external path packages remain unsupported.
    """
    roster = _registry_roster(lock_bytes, expected_lock_sha256, workspace)
    archives, output = Path(archives).absolute(), Path(output).absolute()
    try:
        safe_directory(archives)
        safe_directory(output.parent)
        _require(not output.exists() and not output.is_symlink(), 'output must be absent')
        _require({p.name for p in archives.iterdir()} == {p + '.crate' for p in roster}, 'crate roster mismatch')
        packages: dict[str, dict[str, bytes]] = {}
        package_modes: dict[str, dict[str, int]] = {}
        expanded, inode_count = 0, 1
        for identity, checksum in sorted(roster.items()):
            raw = _regular_bytes(archives / (identity + '.crate'), _MAX_BYTES)
            _require(_digest(raw) == checksum, 'crate checksum mismatch')
            packages[identity], package_modes[identity], count = _inspect_crate(raw, identity)
            expanded += sum(map(len, packages[identity].values()))
            inode_count += count
            _require(expanded <= _MAX_VENDOR_BYTES and inode_count <= _MAX_MEMBERS, 'total crate expansion or inode limit exceeded')
        output.mkdir(mode=0o700)
        for identity, files in packages.items():
            root = output / identity
            root.mkdir(mode=0o700)
            for relative, data in sorted(files.items()):
                destination = root.joinpath(*PurePosixPath(relative).parts)
                destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                with destination.open('xb') as stream:
                    stream.write(data)
                destination.chmod(package_modes[identity][relative])
            (root / '.cargo-checksum.json').write_bytes(_checksum_metadata(files, roster[identity]))
            (root / '.cargo-checksum.json').chmod(0o644)
    except OSError as error:
        raise ProxyInputError('cannot materialize crate inputs') from error
    return {'status': 'materialized-inputs-only', 'lock_sha256': expected_lock_sha256,
            'packages': [{'identity': name, 'sha256': checksum} for name, checksum in sorted(roster.items())],
            'build': 'not-run', 'license_review': 'unreviewed', 'authority': 'not-established'}


def verify_materialized_crates(lock_bytes: bytes, expected_lock_sha256: str, archives: Path, output: Path,
                               *, workspace: dict[str, str] | None = None) -> dict:
    """Recompute the complete vendor roster and hashes from lock-matched archives."""
    roster = _registry_roster(lock_bytes, expected_lock_sha256, workspace)
    archives, output = Path(archives).absolute(), Path(output).absolute()
    safe_directory(archives)
    safe_directory(output)
    _require(output.is_dir() and not output.is_symlink(), 'missing vendor directory')
    _require({p.name for p in archives.iterdir()} == {p + '.crate' for p in roster}, 'crate roster mismatch')
    expected_files: dict[str, tuple[int, str, int]] = {}
    expected_dirs = {''}
    expanded, inode_count = 0, 1
    for identity, checksum in sorted(roster.items()):
        raw = _regular_bytes(archives / (identity + '.crate'), _MAX_BYTES)
        _require(_digest(raw) == checksum, 'crate checksum mismatch')
        files, modes, count = _inspect_crate(raw, identity)
        expanded += sum(map(len, files.values()))
        inode_count += count
        _require(expanded <= _MAX_VENDOR_BYTES and inode_count <= _MAX_MEMBERS, 'total crate expansion or inode limit exceeded')
        files['.cargo-checksum.json'] = _checksum_metadata(files, checksum)
        modes['.cargo-checksum.json'] = 0o644
        expected_dirs.add(identity)
        for relative, data in files.items():
            name = identity + '/' + relative
            expected_files[name] = (len(data), _digest(data), modes[relative])
            parts = name.split('/')
            expected_dirs.update('/'.join(parts[:i]) for i in range(1, len(parts)))
    found_files, found_dirs = set(), {''}
    try:
        for parent, dirs, names in os.walk(output, followlinks=False, onerror=lambda error: (_ for _ in ()).throw(error)):
            base = Path(parent)
            for name in dirs:
                path = base / name
                _require(stat.S_ISDIR(path.lstat().st_mode), 'unsafe vendor directory')
                found_dirs.add(path.relative_to(output).as_posix())
            for name in names:
                path = base / name
                info = path.lstat()
                _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'unsafe vendor file')
                relative = path.relative_to(output).as_posix()
                _require(relative in expected_files, 'unexpected vendor file')
                size, checksum, mode = expected_files[relative]
                _require(stat.S_IMODE(info.st_mode) == mode, 'vendor file mode mismatch')
                data = _regular_bytes(path, size)
                _require(len(data) == size and _digest(data) == checksum, 'vendor file identity mismatch')
                found_files.add(relative)
            _require(len(found_files) + len(found_dirs) <= _MAX_MEMBERS, 'vendor inode limit exceeded')
    except OSError as error:
        raise ProxyInputError('cannot verify vendor tree') from error
    _require(found_files == set(expected_files) and found_dirs == expected_dirs, 'vendor roster mismatch')
    return {'status': 'verified-materialized-inputs-only', 'lock_sha256': expected_lock_sha256,
            'packages': len(roster), 'files': len(found_files), 'bytes': expanded,
            'build': 'not-run', 'license_review': 'unreviewed', 'authority': 'not-established'}


def _actual_error(detail: str) -> ValueError:
    return ValueError('proxy identity actual invalid: %s' % detail)


def _mismatch_error(path: str) -> ValueError:
    return ValueError('proxy identity mismatch: %s' % path)


def _require_daemon_claim(daemon: object) -> dict:
    if type(daemon) is not dict or set(daemon) != {'schema_version', 'source_revision',
                                                  'cargo_lock_sha256', 'binaries'}:
        raise _actual_error('daemon_build_json requires {schema_version, source_revision, cargo_lock_sha256, binaries}')
    assert type(daemon) is dict
    if type(daemon['schema_version']) is not int or daemon['schema_version'] != 1:
        raise _actual_error('daemon_build_json schema_version must be 1')
    revision = daemon['source_revision']
    if revision is not None and (not isinstance(revision, str) or len(revision) != 40
                                 or not all(c in '0123456789abcdef' for c in revision)):
        raise _actual_error('daemon_build_json source_revision must be null or 40 hex')
    if not isinstance(daemon['cargo_lock_sha256'], str) or _SHA.fullmatch(daemon['cargo_lock_sha256']) is None:
        raise _actual_error('daemon_build_json cargo_lock_sha256 must be 64 hex')
    binaries = daemon['binaries']
    names = {'pkcs11-proxy-ng', 'pkcs11-proxy-ng-cli', 'proxy-entrypoint.sh'}
    if (type(binaries) is not dict or set(binaries) != names
            or not all(isinstance(value, str) and _SHA.fullmatch(value) for value in binaries.values())):
        raise _actual_error('daemon_build_json binaries must be exactly the three pinned digests')
    return copy.deepcopy(daemon)


def _check_daemon_parent(evidence, selected):
    """Verify observed daemon parent evidence: admission, then expectation.

    Q3R decomposition (admission vs expectation are distinct checks with
    distinct failure rules):

    - ROSTER-ANCHORED ADMISSION applies to EVERY run carrying parent
      evidence, default or explicit, fail-closed always: evidence digests
      and parent layers must equal the protected roster pins exactly, and
      the child layers must carry the exact ordered DiffID prefix. A wrong
      parent is outside the slice's bound world and is refused here, since
      recording it unverified would silently admit an unbound parent.
    - F28 EXPECTATION MATCHING applies to bound records only: the
      roster-validated binding is compared to the selected record's
      provider_parent exactly. Records with an unbound (all-None) F28
      record the roster-validated binding without F28 comparison (nothing
      to compare against; never a wildcard, never vacuous-verified).

    None evidence means no parent observation (exactly the pre-derivative
    behavior). Observed vs expected stay distinct in all paths.
    """
    if evidence is None:
        return None
    if type(evidence) is not dict or set(evidence) != {
            'family', 'platform', 'manifest_digest', 'config_digest',
            'parent_layers', 'child_layers'}:
        raise _actual_error('daemon_parent requires {family, platform, manifest_digest, '
                            'config_digest, parent_layers, child_layers}')
    for key in ('family', 'platform'):
        if not isinstance(evidence[key], str) or not evidence[key]:
            raise _actual_error('daemon_parent %s must be a nonempty string' % key)
    for key in ('manifest_digest', 'config_digest'):
        value = evidence[key]
        if (not isinstance(value, str) or not value.startswith('sha256:')
                or _SHA.fullmatch(value.removeprefix('sha256:')) is None):
            raise _actual_error('daemon_parent %s must be a sha256 digest' % key)
    for key in ('parent_layers', 'child_layers'):
        rows = evidence[key]
        if (type(rows) is not list or not rows or not all(
                isinstance(entry, str) and entry.startswith('sha256:')
                and _SHA.fullmatch(entry.removeprefix('sha256:')) is not None for entry in rows)):
            raise _actual_error('daemon_parent %s must be a non-empty DiffID list' % key)
    selection = load_parent_selection(family=evidence['family'], platform=evidence['platform'])
    for key in ('manifest_digest', 'config_digest'):
        if evidence[key] != selection[key]:
            raise _mismatch_error('daemon_parent.%s' % key)
    if list(evidence['parent_layers']) != selection['layers']:
        raise _mismatch_error('daemon_parent.parent_layers')
    binding = verify_derivative_parent({'RootFS': {'Layers': list(evidence['child_layers'])}},
                                       selection)
    parent = selected.provider_parent
    if all(value is None for value in parent.values()):
        return binding
    for key in ('family', 'platform'):
        if evidence[key] != parent[key]:
            raise _mismatch_error('daemon_parent.%s' % key)
    for key in ('manifest_digest', 'config_digest'):
        if evidence[key].removeprefix('sha256:') != parent[key]:
            raise _mismatch_error('daemon_parent.%s' % key)
    return binding


def validate_proxy_identity(actual: dict, expected: dict | None) -> dict:
    """Validate merged proxy-build evidence against a selected identity record.

    actual carries exactly {daemon_build_json, client_manifest, launch_rehashes,
    abi_observed} plus the optional observed daemon_parent evidence; expected
    None resolves to the absolute pinned default (never a wildcard) and
    otherwise must be a complete record dict. Every branch is exact sameness
    (no policy input); the first mismatch raises ValueError naming the field
    path. Returns the validated selection with evidence.
    """
    keys = set(actual) if type(actual) is dict else set()
    if keys != {'daemon_build_json', 'client_manifest', 'launch_rehashes', 'abi_observed'} \
            and keys != {'daemon_build_json', 'client_manifest', 'launch_rehashes',
                         'abi_observed', 'daemon_parent'}:
        raise _actual_error('actual requires {daemon_build_json, client_manifest, launch_rehashes, abi_observed}')
    if expected is None:
        selected = tls_module.DEFAULT_PROXY_BUILD_IDENTITY()
    elif type(expected) is dict:
        selected = ProxyBuildIdentityV1.from_dict(expected)
    else:
        raise ValueError('proxy identity expected must be a dict or None')
    daemon = _require_daemon_claim(actual['daemon_build_json'])
    if daemon['source_revision'] != selected.source_commit:
        raise _mismatch_error('daemon.source_revision')
    if daemon['cargo_lock_sha256'] != selected.cargo_lock_sha256:
        raise _mismatch_error('daemon.cargo_lock_sha256')
    binaries = daemon['binaries']
    assert type(binaries) is dict
    if binaries['pkcs11-proxy-ng'] != selected.daemon['sha256']:
        raise _mismatch_error('daemon.binaries.pkcs11-proxy-ng')
    if binaries['pkcs11-proxy-ng-cli'] != selected.cli['sha256']:
        raise _mismatch_error('daemon.binaries.pkcs11-proxy-ng-cli')
    if binaries['proxy-entrypoint.sh'] != selected.entrypoint_sha256:
        raise _mismatch_error('daemon.binaries.proxy-entrypoint.sh')
    observed_parent = _check_daemon_parent(actual.get('daemon_parent'), selected)
    manifest = actual['client_manifest']
    if type(manifest) is not dict or type(manifest.get('source')) is not dict:
        raise _actual_error('client_manifest requires a source mapping')
    proxy = manifest['source'].get('proxy')
    if type(proxy) is not dict or 'identity' not in proxy:
        raise _actual_error('client_manifest requires a recorded source.proxy.identity')
    recorded = ProxyBuildIdentityV1.from_dict(proxy['identity'])
    recorded.require_same_record(selected, where='client_manifest.identity')
    rehashes = actual['launch_rehashes']
    if type(rehashes) is not dict or set(rehashes) != {'shim_sha256', 'cli_sha256'}:
        raise _actual_error('launch_rehashes requires exactly {shim_sha256, cli_sha256}')
    if rehashes['shim_sha256'] != selected.shim['sha256']:
        raise _mismatch_error('launch_rehashes.shim_sha256')
    if rehashes['cli_sha256'] != selected.cli['sha256']:
        raise _mismatch_error('launch_rehashes.cli_sha256')
    selected.check_client_abi_observed(actual['abi_observed'])
    return {'expected': selected.to_dict(), 'daemon': daemon, 'client_identity': recorded.to_dict(),
            'launch_rehashes': dict(rehashes), 'abi_decision': selected.abi['decision'],
            'observed_parent': observed_parent}
