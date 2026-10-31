"""Bounded GitHub Actions read-only artifact transport.

Transport metadata is observation, not producer or caller authority. A caller
must verify a separately protected producer contract before admitting its bytes.
"""
from __future__ import annotations

import re
import time
import hashlib
import base64
import io
import os
import stat
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from ..tool_downloads import _HTTPS
from . import JsonObject
from .inputs import CUSTODY_ZIP_LIMIT, SOURCE_ARCHIVE_LIMIT, SHA, _preflight_custody_zip, load_json, read_source_archive, safe_path, select_active_custody_artifact, select_custody_artifact, select_run_artifact, stable_metadata


class TransientTransportError(ValueError):
    """A pre-provider transport failure that may be retried once."""

    failure_record: dict
    error_category: str
    http_status: int | None


@dataclass(frozen=True)
class CustodyArtifactBytes:
    """Expected ZIP bytes, not proof of producer authority or admission."""

    id: int
    size: int
    digest: str

    def __post_init__(self) -> None:
        if (type(self.id) is not int or self.id <= 0
                or type(self.size) is not int or not 0 < self.size <= CUSTODY_ZIP_LIMIT
                or type(self.digest) is not str or not re.fullmatch(r'sha256:[0-9a-f]{64}', self.digest)):
            raise ValueError('invalid custody artifact identity')


def verify_custody_zip(path: Path, expected: CustodyArtifactBytes) -> None:
    """Rehash one bounded regular custody ZIP without loading it into memory."""
    if type(expected) is not CustodyArtifactBytes:
        raise ValueError('typed custody artifact required')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size != expected.size:
            raise ValueError('custody ZIP byte identity mismatch')
        digest, total = hashlib.sha256(), 0
        while block := stream.read(65536):
            total += len(block)
            if total > expected.size:
                raise ValueError('custody ZIP byte identity mismatch')
            digest.update(block)
        after = os.fstat(stream.fileno())
        current = os.stat(path, follow_symlinks=False)
        def identity(value):
            return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns, value.st_mode, value.st_nlink)
        if (identity(before) != identity(after) or identity(after) != identity(current)
                or total != expected.size or 'sha256:' + digest.hexdigest() != expected.digest):
            raise ValueError('custody ZIP byte identity mismatch')


def read_custody_manifest(path: Path, expected: CustodyArtifactBytes) -> bytes:
    """Rehash the full ZIP, then read its unique bounded manifest."""
    if type(expected) is not CustodyArtifactBytes:
        raise ValueError('typed custody artifact required')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size != expected.size):
            raise ValueError('custody ZIP byte identity mismatch')
        observed = hashlib.sha256()
        total = 0
        while block := stream.read(65536):
            total += len(block)
            if total > expected.size:
                raise ValueError('custody ZIP byte identity mismatch')
            observed.update(block)
        if total != expected.size or 'sha256:' + observed.hexdigest() != expected.digest:
            raise ValueError('custody ZIP byte identity mismatch')
        _preflight_custody_zip(stream, info.st_size)
        try:
            with zipfile.ZipFile(stream) as archive:
                matches = [item for item in archive.infolist() if item.filename == 'custody-manifest.json']
                if len(matches) != 1:
                    raise ValueError('missing or ambiguous custody manifest')
                item = matches[0]
                if (item.orig_filename != item.filename or item.is_dir() or item.flag_bits & 1
                        or stat.S_IFMT(item.external_attr >> 16) not in (0, stat.S_IFREG)
                        or (item.create_system == 0 and item.external_attr & 0x10)
                        or item.file_size > 2 * 1024 * 1024):
                    raise ValueError('unsafe or oversized custody manifest')
                return archive.read(item)
        except (zipfile.BadZipFile, RuntimeError, NotImplementedError) as error:
            raise ValueError('invalid custody ZIP') from error


def verify_artifact_digest(raw: bytes, metadata: JsonObject) -> None:
    digest = metadata.get('digest')
    if (type(digest) is not str or not re.fullmatch(r'sha256:[0-9a-f]{64}', digest)
            or 'sha256:' + hashlib.sha256(raw).hexdigest() != digest):
        raise ValueError('artifact digest mismatch or unavailable')


def decode_control_artifact(raw: bytes) -> JsonObject:
    """Decode the independently acquired closed protected-context artifact."""
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError('protected context archive bound')
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            members = archive.infolist()
            if (len(members) != 1 or members[0].filename != 'context.json'
                    or members[0].file_size > 1024 * 1024
                    or stat.S_IFMT(members[0].external_attr >> 16) not in (0, stat.S_IFREG)):
                raise ValueError('invalid protected context archive')
            return load_json(archive.read(members[0]), max_bytes=1024 * 1024)
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError) as error:
        raise ValueError('invalid protected context archive') from error


def decode_custody_control(raw: bytes) -> tuple[bytes, bytes]:
    """Read only the two separately attestable custody control files."""
    if type(raw) is not bytes or len(raw) > 2 * 1024 * 1024:
        raise ValueError('custody control archive bound')
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            members = archive.infolist()
            names = {'custody-finalization.json', 'bundle.json'}
            if (len(members) != 2 or {item.filename for item in members} != names
                    or any(item.orig_filename != item.filename or item.is_dir() or item.flag_bits & 1
                           or stat.S_IFMT(item.external_attr >> 16) not in (0, stat.S_IFREG)
                           or (item.create_system == 0 and item.external_attr & 0x10) for item in members)
                    or sum(item.file_size for item in members) > 2 * 1024 * 1024):
                raise ValueError('invalid custody control archive roster')
            return archive.read('custody-finalization.json'), archive.read('bundle.json')
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError) as error:
        raise ValueError('invalid custody control archive') from error


def decode_round_attestation(raw: bytes) -> tuple[bytes, bytes]:
    """Decode the single-file round attestation artifact into (subject, bundle) bytes.

    The producer uploads one envelope file, `round-attestation.json`, carrying
    the exact attested subject bytes (base64) and the Sigstore bundle
    (base64). Exact bytes are preserved so the subject digest binding holds.
    """
    if type(raw) is not bytes or len(raw) > 2 * 1024 * 1024:
        raise ValueError('round attestation archive bound')
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            members = archive.infolist()
            if (len(members) != 1 or members[0].filename != 'round-attestation.json'
                    or members[0].orig_filename != members[0].filename or members[0].is_dir()
                    or members[0].flag_bits & 1
                    or stat.S_IFMT(members[0].external_attr >> 16) not in (0, stat.S_IFREG)
                    or (members[0].create_system == 0 and members[0].external_attr & 0x10)
                    or members[0].file_size > 2 * 1024 * 1024):
                raise ValueError('invalid round attestation archive')
            member_bytes = archive.read(members[0])
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError) as error:
        raise ValueError('invalid round attestation archive') from error
    try:
        envelope = load_json(member_bytes, max_bytes=2 * 1024 * 1024)
    except ValueError as error:
        raise ValueError('invalid round attestation envelope') from error
    if (type(envelope) is not dict or set(envelope) != {'subject_b64', 'bundle_b64'}
            or type(envelope['subject_b64']) is not str or type(envelope['bundle_b64']) is not str):
        raise ValueError('invalid round attestation envelope')
    try:
        subject = base64.b64decode(envelope['subject_b64'], validate=True)
        bundle = base64.b64decode(envelope['bundle_b64'], validate=True)
    except ValueError as error:
        raise ValueError('invalid round attestation envelope') from error
    if not 0 < len(subject) <= 2 * 1024 * 1024 or not 0 < len(bundle) <= 2 * 1024 * 1024:
        raise ValueError('invalid round attestation envelope')
    return subject, bundle


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def _storage_redirect(location: str) -> None:
    target = urlsplit(location)
    host = target.hostname or ''
    if (target.scheme != 'https' or target.username or target.password or target.port not in (None, 443)
            or target.fragment or not (host.endswith('.blob.core.windows.net')
                                       or host.endswith('.actions.githubusercontent.com'))):
        raise ValueError('unapproved artifact redirect origin')


_TRANSPORT_CATEGORIES = ('http-transient', 'http-fatal', 'http-unknown',
                         'timeout', 'network-reset', 'network')


def _validate_transport_status(code: object) -> int | None:
    """Return an int 100-599 HTTP status, else None (never raises)."""
    if type(code) is int and 100 <= code <= 599:
        return code
    return None


def _classify_transport_error(error: BaseException) -> tuple[str, int | None]:
    """Classify a funnel transport failure as (category, http_status).

    The one-level reason unwrap is classification-only: reason and message
    text never enter records or messages.
    """
    if isinstance(error, HTTPError):
        http_status = _validate_transport_status(error.code)
        if http_status is None:
            category = 'http-unknown'
        elif http_status == 429 or 500 <= http_status <= 599:
            category = 'http-transient'
        else:
            category = 'http-fatal'
    else:
        http_status = None
        candidate = error.reason if isinstance(error, URLError) else error
        if isinstance(candidate, TimeoutError):
            category = 'timeout'
        elif isinstance(candidate, ConnectionError):
            category = 'network-reset'
        else:
            category = 'network'
    return category, http_status


def verify_profile_graph(graph: list[JsonObject], fetch: Callable[[str], bytes]) -> list[JsonObject]:
    """Verify protected-profile source graph bytes; this does not review a graph."""
    if type(graph) is not list or not graph or len(graph) > 100:
        raise ValueError('invalid protected source graph')
    seen: set[str] = set()
    for item in graph:
        if (type(item) is not dict or set(item) != {'path', 'sha256'}
                or type(item['sha256']) is not str or not SHA.fullmatch(item['sha256'])):
            raise ValueError('invalid protected source graph entry')
        name = safe_path(item['path'])
        if name in seen:
            raise ValueError('duplicate protected source graph entry')
        seen.add(name)
        if hashlib.sha256(fetch(name)).hexdigest() != item['sha256']:
            raise ValueError('protected source graph mismatch')
    return graph


def verify_producer_profile(profile: JsonObject, context: JsonObject,
                            fetch: Callable[[str], bytes]) -> None:
    """Bind an independently installed protected profile to actual caller bytes.

    The profile must be admitted by protected P11Lab control, not supplied by
    a candidate. Its review owns the semantic boundary evidence and graph.
    """
    fields = {'repository', 'repository_id', 'owner_id', 'workflow_id', 'producer_job',
              'control_sha', 'policy_sha256', 'target_sha256', 'data_sources_sha256', 'data_sources', 'runtime',
              'context_artifact_name', 'context_job',
              'workflow_path', 'boundary_path', 'graph'}
    proof_fields = fields | {'root_sha256', 'attestation_artifact_name'}
    if type(profile) is not dict or set(profile) not in (fields, proof_fields):
        raise ValueError('invalid protected producer profile')
    for name in ('repository', 'repository_id', 'owner_id', 'workflow_id', 'producer_job', 'control_sha', 'policy_sha256', 'target_sha256', 'data_sources_sha256'):
        if profile[name] != context.get(name) or type(profile[name]) is not type(context.get(name)):
            raise ValueError('protected producer profile context mismatch')
    for name in ('control_sha',):
        if type(profile[name]) is not str or not re.fullmatch(r'[0-9a-f]{40}', profile[name]):
            raise ValueError('invalid protected producer profile revision')
    if type(context.get('run_head_sha')) is not str or not re.fullmatch(r'[0-9a-f]{40}', context['run_head_sha']):
        raise ValueError('invalid authenticated caller head')
    for name in ('policy_sha256', 'target_sha256', 'data_sources_sha256'):
        if type(profile[name]) is not str or not SHA.fullmatch(profile[name]):
            raise ValueError('invalid protected target/data identity')
    if type(profile['data_sources']) is not list:
        raise ValueError('invalid protected data sources')
    template = profile['context_artifact_name']
    if (type(template) is not str or template.count('{run_id}') != 1 or template.count('{attempt}') != 1
            or not re.fullmatch(r'[A-Za-z0-9_.-]+', template.replace('{run_id}', '1').replace('{attempt}', '1'))
            or type(profile['context_job']) is not str or not profile['context_job']):
        raise ValueError('invalid protected context artifact profile')
    if 'root_sha256' in profile:
        # The unenrolled zeros sentinel is admitted here; owner proof refuses it.
        if type(profile['root_sha256']) is not str or not SHA.fullmatch(profile['root_sha256']):
            raise ValueError('invalid round owner proof trust root')
        attestation_template = profile['attestation_artifact_name']
        if (type(attestation_template) is not str or attestation_template.count('{run_id}') != 1
                or attestation_template.count('{attempt}') != 1
                or not re.fullmatch(r'[A-Za-z0-9_.-]+', attestation_template.replace('{run_id}', '1').replace('{attempt}', '1'))):
            raise ValueError('invalid round attestation artifact profile')
    runtime = profile['runtime']
    if (type(runtime) is not dict or set(runtime) != {'image', 'layers', 'config_sha256', 'tool_identity_sha256', 'python_version', 'max_output_bytes', 'source_date_epoch'}
            or type(runtime['image']) is not str or not re.fullmatch(r'sha256:[0-9a-f]{64}', runtime['image'])
            or type(runtime['layers']) is not list or not runtime['layers']
            or any(type(v) is not str or not re.fullmatch(r'sha256:[0-9a-f]{64}', v) for v in runtime['layers'])
            or any(type(runtime[k]) is not str or not SHA.fullmatch(runtime[k]) for k in ('config_sha256', 'tool_identity_sha256'))
            or type(runtime['python_version']) is not str or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', runtime['python_version'])
            or type(runtime['max_output_bytes']) is not int or not 1024 <= runtime['max_output_bytes'] <= 128 * 1024 * 1024
            or type(runtime['source_date_epoch']) is not int or not 0 <= runtime['source_date_epoch'] <= 2 ** 31 - 1):
        raise ValueError('invalid protected runtime profile')
    graph = verify_profile_graph(profile['graph'], fetch)
    paths = {row['path'] for row in graph}
    if profile['workflow_path'] not in paths or profile['boundary_path'] not in paths:
        raise ValueError('protected profile lacks workflow or boundary evidence')


_CUSTODY_SHARD_BYTES_KEY = object()
_CUSTODY_SHARD_TIMEOUT = 120.0


@dataclass(frozen=True, slots=True, init=False)
class VerifiedCustodySourceShards:
    """Actual bounded shard bytes; they do not grant source or owner authority."""
    _records: tuple[tuple[str, str, int], ...]
    _bytes: tuple[bytes, ...]
    _revision: str
    _repository: str

    def __init__(self, key, repository, revision, selectors, rows):
        if key is not _CUSTODY_SHARD_BYTES_KEY:
            raise TypeError('custody shard bytes require the bounded transport')
        object.__setattr__(self, '_repository', repository)
        object.__setattr__(self, '_revision', revision)
        object.__setattr__(self, '_records', tuple((row['path'], row['sha256'], row['size_bytes']) for row in selectors))
        object.__setattr__(self, '_bytes', tuple(rows))

    def bytes_for(self, path):
        for index, row in enumerate(self._records):
            if row[0] == path:
                return self._bytes[index]
        raise ValueError('unselected custody source shard')

    def facts(self):
        return {'repository': self._repository, 'revision': self._revision,
                'selectors': [{'path': path, 'sha256': digest, 'size_bytes': size}
                              for path, digest, size in self._records]}


class GitHubTransport:
    def __init__(self, repository: str, token: str):
        if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository):
            raise ValueError('invalid caller repository')
        if not token or '\n' in token or '\r' in token:
            raise ValueError('missing/invalid Actions token')
        self.repository = repository
        self._token = token
        self._base = 'https://api.github.com/repos/' + repository

    def _request(self, url: str, token: str | None, limit: int,
                 deadline: float) -> tuple[int, dict[str, str], bytes]:
        # Addressed artifact id for diagnostics (0 = not artifact-addressed).
        # Storage legs carry no id in their signed URL, so they reuse the id
        # remembered from the immediately preceding redirect leg, if any.
        artifact_id = 0
        prefix = self._base + '/actions/artifacts/'
        if url.startswith(prefix) and url.endswith('/zip'):
            digits = url[len(prefix):-len('/zip')]
            if digits.isdigit() and len(digits) <= 19 and (value := int(digits)) > 0:
                artifact_id = value
                self._last_request_artifact = value
        elif not url.startswith(self._base):
            artifact_id = getattr(self, '_last_request_artifact', 0) or 0
        headers = {'Accept': 'application/vnd.github+json',
                   'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'p11lab-round'}
        if token is not None:
            headers['Authorization'] = 'Bearer ' + token
        opener = build_opener(ProxyHandler({}), _HTTPS(deadline), _NoRedirect())
        request = Request(url, headers=headers, method='GET')
        try:
            try:
                response = opener.open(request, timeout=max(0.01, min(15, deadline - time.monotonic())))
            except HTTPError as error:
                response = error
            with response:
                status = response.status
                response_headers = {k.lower(): v for k, v in response.headers.items()}
                if status in (301, 302, 303, 307, 308):
                    return status, response_headers, b''
                if status == 429 or 500 <= status <= 599:
                    record = {'error_category': 'http-transient', 'http_status': status,
                              'artifact_id': artifact_id, 'expected_bytes': limit, 'observed_bytes': 0}
                    failure = TransientTransportError(
                        f'GitHub transient response: http-transient http {status} artifact {artifact_id} bytes 0/{limit}')
                    failure.failure_record = record
                    failure.error_category = 'http-transient'
                    failure.http_status = status
                    raise failure
                if status != 200:
                    raise ValueError(f'GitHub request failed with HTTP {status}')
                raw = response.read(limit + 1)
                if len(raw) > limit or time.monotonic() > deadline:
                    raise ValueError('GitHub response byte/time bound')
                return status, response_headers, raw
        except (URLError, TimeoutError, ConnectionError) as error:
            category, http_status = _classify_transport_error(error)
            record = {'error_category': category, 'http_status': http_status,
                      'artifact_id': artifact_id, 'expected_bytes': limit, 'observed_bytes': 0}
            message = 'GitHub transport failed: ' + category
            if http_status is not None:
                message += f' http {http_status}'
            message += f' artifact {artifact_id} bytes 0/{limit}'
            failure = TransientTransportError(message)
            failure.failure_record = record
            failure.error_category = category
            failure.http_status = http_status
            raise failure from None

    def _metadata(self, path: str, deadline: float) -> JsonObject:
        status, _, raw = self._request(self._base + path, self._token, 2 * 1024 * 1024, deadline)
        if status != 200:
            raise ValueError('unexpected GitHub metadata redirect')
        return load_json(raw)

    def source_custody_shards(self, revision, selectors, *, journal_path=None):
        """Fetch only frozen custody shards inside an owned hard-deadline worker."""
        import json
        import shutil
        import tempfile
        from ..image_custody import COMPONENTS
        from ..proxy_supervisor import run_proxy_worker
        prefix = 'src/p11lab/data/ci/delivery/custody-components/'
        expected = [prefix + name + '.json' for name in sorted(COMPONENTS)]
        if (type(revision) is not str or not re.fullmatch(r'[0-9a-f]{40}', revision)
                or type(selectors) is not list or len(selectors) != len(expected)
                or any(type(row) is not dict or set(row) != {'path', 'sha256', 'size_bytes'}
                       or type(row['path']) is not str or type(row['sha256']) is not str
                       or not re.fullmatch(r'[0-9a-f]{64}', row['sha256'])
                       or type(row['size_bytes']) is not int or not 0 < row['size_bytes'] <= 16 * 1024 * 1024
                       for row in selectors)
                or [row['path'] for row in selectors] != expected
                or sum(row['size_bytes'] for row in selectors) > 32 * 1024 * 1024):
            raise ValueError('invalid fixed custody source shard selectors')
        started = time.monotonic()
        deadline = started + _CUSTODY_SHARD_TIMEOUT
        root = Path(tempfile.mkdtemp(prefix='p11lab-custody-source-shards-'))
        progress_path = root / 'progress.json'
        journal = {'repository': self.repository, 'revision': revision, 'authentication': 'actions-read-token',
                   'selectors': selectors, 'category': 'incomplete', 'files': [], 'worker_pid': None,
                   'worker_reaped': None, 'wait_status': None, 'native_errno': None, 'cleanup': 'not-yet-confirmed',
                   'temporary_directory': str(root), 'deadline_seconds': _CUSTODY_SHARD_TIMEOUT}
        def save_progress(progress):
            temporary = root / 'progress.new'
            with temporary.open('w') as stream:
                json.dump(progress, stream, sort_keys=True, separators=(',', ':'))
            os.replace(temporary, progress_path)
        def worker():
            progress = {'files': [], 'category': 'incomplete'}
            save_progress(progress)
            try:
                for row in selectors:
                    item = {'path': row['path'], 'expected_sha256': row['sha256'], 'expected_size_bytes': row['size_bytes'],
                            'actual_sha256': None, 'actual_size_bytes': 0, 'http_status': None, 'category': 'incomplete'}
                    progress['files'].append(item)
                    save_progress(progress)
                    if time.monotonic() > deadline:
                        raise ValueError('custody source shard time bound')
                    url = self._base + '/contents/' + quote(row['path'], safe='/') + '?ref=' + revision
                    headers = {'Accept': 'application/vnd.github.raw+json', 'X-GitHub-Api-Version': '2022-11-28',
                               'User-Agent': 'p11lab-round', 'Authorization': 'Bearer ' + self._token}
                    opener = build_opener(ProxyHandler({}), _HTTPS(deadline), _NoRedirect())
                    request = Request(url, headers=headers, method='GET')
                    try:
                        response = opener.open(request, timeout=max(0.01, min(15, deadline - time.monotonic())))
                    except HTTPError as error:
                        response = error
                    with response:
                        status = response.status
                        item['http_status'] = status if type(status) is int and 100 <= status <= 599 else None
                        save_progress(progress)
                        if status in (301, 302, 303, 307, 308):
                            raise ValueError('unexpected custody source shard redirect')
                        if status == 429 or 500 <= status <= 599:
                            raise TransientTransportError('GitHub transient response')
                        if status != 200:
                            raise ValueError(f'GitHub request failed with HTTP {status}')
                        path = root / Path(row['path']).name
                        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
                        digest = hashlib.sha256()
                        with os.fdopen(descriptor, 'wb') as stream:
                            while True:
                                if time.monotonic() > deadline:
                                    raise ValueError('custody source shard time bound')
                                chunk = response.read(min(65536, row['size_bytes'] + 1 - item['actual_size_bytes']))
                                if time.monotonic() > deadline:
                                    raise ValueError('custody source shard time bound')
                                if not chunk:
                                    break
                                item['actual_size_bytes'] += len(chunk)
                                if item['actual_size_bytes'] > row['size_bytes']:
                                    raise ValueError('custody source shard byte bound')
                                digest.update(chunk)
                                stream.write(chunk)
                                save_progress(progress)
                        item['actual_sha256'] = digest.hexdigest()
                    if item['actual_size_bytes'] != row['size_bytes'] or item['actual_sha256'] != row['sha256']:
                        raise ValueError('custody source shard size or hash mismatch')
                    with path.open('rb') as stream:
                        if stream.read(64).startswith(b'version https://git-lfs.github.com/spec/v1'):
                            raise ValueError('custody source shard LFS pointer refused')
                    item['category'] = 'complete'
                    save_progress(progress)
                progress['category'] = 'complete'
                save_progress(progress)
                return progress
            except BaseException as error:
                progress['category'] = ('timeout' if isinstance(error, TimeoutError) else
                    'network' if isinstance(error, (URLError, ConnectionError, TransientTransportError)) else
                    'input' if isinstance(error, ValueError) else 'internal-error')
                if progress['files'] and progress['files'][-1]['category'] != 'complete':
                    progress['files'][-1]['category'] = progress['category']
                save_progress(progress)
                raise
        failure = None
        result = None
        try:
            witness = run_proxy_worker(worker, deadline=deadline, include_witness=True)
            journal.update({key: witness[key] for key in ('worker_pid', 'worker_reaped', 'wait_status')})
            journal['group_cleanup'] = witness['group_cleanup']
            journal['files'] = witness['result']['files']
            if (witness['result'].get('category') != 'complete' or len(journal['files']) != len(selectors)):
                raise ValueError('custody source shard worker roster incomplete')
            expected_files = {Path(row['path']).name for row in selectors} | {'progress.json'}
            if {path.name for path in root.iterdir()} != expected_files:
                raise ValueError('custody source shard temporary roster mismatch')
            rows = []
            for row, item in zip(selectors, journal['files']):
                path = root / Path(row['path']).name
                descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
                with os.fdopen(descriptor, 'rb') as stream:
                    before = os.fstat(stream.fileno())
                    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size != row['size_bytes']:
                        raise ValueError('custody source shard temporary file mismatch')
                    chunks, total = [], 0
                    digest = hashlib.sha256()
                    while True:
                        if time.monotonic() > deadline:
                            raise TimeoutError('custody source shard parent deadline')
                        chunk = stream.read(min(65536, row['size_bytes'] + 1 - total))
                        if time.monotonic() > deadline:
                            raise TimeoutError('custody source shard parent deadline')
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > row['size_bytes']:
                            raise ValueError('custody source shard temporary file grew')
                        digest.update(chunk)
                        chunks.append(chunk)
                    after, current = os.fstat(stream.fileno()), os.stat(path, follow_symlinks=False)
                    def identity(value):
                        return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
                                value.st_size, value.st_mtime_ns, value.st_ctime_ns)
                    if (total != row['size_bytes'] or digest.hexdigest() != row['sha256']
                            or item['path'] != row['path'] or item['expected_sha256'] != row['sha256']
                            or item['expected_size_bytes'] != row['size_bytes'] or item['http_status'] != 200
                            or item['category'] != 'complete' or item['actual_sha256'] != row['sha256']
                            or item['actual_size_bytes'] != row['size_bytes']
                            or identity(before) != identity(after) or identity(after) != identity(current)):
                        raise ValueError('custody source shard changed during parent verification')
                    rows.append(b''.join(chunks))
            result = VerifiedCustodySourceShards(_CUSTODY_SHARD_BYTES_KEY, self.repository, revision, selectors, rows)
            journal['category'] = 'complete'
        except BaseException as error:
            failure = error
            journal['category'] = getattr(error, 'category', 'timeout' if isinstance(error, TimeoutError) else
                                          'input' if isinstance(error, ValueError) else 'internal-error')
            journal['worker_pid'] = getattr(error, 'worker_pid', journal['worker_pid'])
            journal['worker_reaped'] = getattr(error, 'worker_reaped', journal['worker_reaped'])
            journal['wait_status'] = getattr(error, 'wait_status', journal['wait_status'])
            journal['native_errno'] = getattr(error, 'native_errno', None)
            try:
                with progress_path.open('rb') as stream:
                    progress = load_json(stream.read(2 * 1024 * 1024 + 1))
                journal['files'] = progress.get('files', [])
                journal['worker_category'] = progress.get('category')
            except (OSError, ValueError):
                journal['worker_category'] = 'unavailable'
        finally:
            if journal['worker_reaped'] is True or journal['worker_pid'] in (None, 0):
                try:
                    if root.is_symlink() or not root.is_dir():
                        raise ValueError('custody source shard temporary directory changed')
                    shutil.rmtree(root)
                    if root.exists() or root.is_symlink():
                        raise ValueError('custody source shard temporary directory remains')
                    journal['cleanup'] = 'confirmed'
                except (OSError, ValueError):
                    journal['cleanup'] = 'unconfirmed'
            journal['elapsed_seconds'] = round(time.monotonic() - started, 6)
            if journal_path is not None:
                from ..receipts import write_receipt
                try:
                    write_receipt(Path(journal_path), journal)
                except (OSError, ValueError) as error:
                    if failure is None:
                        raise
                    failure.add_note('custody source shard journal write failed: ' + type(error).__name__)
        if failure is not None:
            raise failure
        if journal['cleanup'] != 'confirmed':
            raise ValueError('custody source shard cleanup unconfirmed')
        return result

    def source_file(self, revision: str, path: str) -> bytes:
        """Fetch one immutable caller-repository file through the Actions controller."""
        if not re.fullmatch(r'[0-9a-f]{40}', revision):
            raise ValueError('invalid source revision')
        name = safe_path(path)
        url = self._base + '/contents/' + quote(name, safe='/') + '?ref=' + revision
        status, _, raw_metadata = self._request(url, None, 2 * 1024 * 1024, time.monotonic() + 60)
        if status != 200:
            raise ValueError('unexpected protected source redirect')
        data = load_json(raw_metadata)
        if data.get('type') != 'file' or data.get('encoding') != 'base64':
            raise ValueError('invalid protected source file')
        try:
            raw = base64.b64decode(data['content'].replace('\n', ''), validate=True)
        except (KeyError, TypeError, ValueError):
            raise ValueError('invalid protected source file encoding') from None
        if len(raw) > 1024 * 1024:
            raise ValueError('protected source file byte bound')
        return raw

    def resolve(self, identity: JsonObject, *, artifact_name: str | None = None) -> JsonObject:
        run, attempt = identity['run_id'], identity['attempt']
        if type(run) is not int or run <= 0 or type(attempt) is not int or attempt <= 0:
            raise ValueError('invalid run/attempt')
        sha = identity['candidate_sha']
        if type(sha) is not str or not re.fullmatch(r'[0-9a-f]{40}', sha):
            raise ValueError('invalid candidate revision')
        artifact_name = artifact_name or f'p11lab-framework-dist-{sha}-{attempt}'
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,255}', artifact_name):
            raise ValueError('invalid artifact name')
        name = quote(artifact_name, safe='')
        deadline = time.monotonic() + 60
        def fetch() -> JsonObject:
            attempt_data = self._metadata(f'/actions/runs/{run}/attempts/{attempt}', deadline)
            jobs = self._metadata(f'/actions/runs/{run}/attempts/{attempt}/jobs?per_page=100', deadline)
            listing = self._metadata(f'/actions/runs/{run}/artifacts?per_page=100&name={name}', deadline)
            return select_run_artifact(identity, attempt_data, jobs, listing, name=artifact_name)
        return stable_metadata(fetch)

    def resolve_round_attestation(self, identity: JsonObject, *, attestation_name: str) -> JsonObject:
        """Stable-resolve the producer-uploaded attestation artifact with its run context.

        Selection reuses the run-artifact consistency boundary; the returned
        attempt/jobs payloads feed the roster, overlay, and timing checks.
        This resolves metadata only and authenticates nothing by itself.
        """
        run, attempt = identity.get('run_id'), identity.get('attempt')
        if type(run) is not int or run <= 0 or type(attempt) is not int or attempt <= 0:
            raise ValueError('invalid run/attempt')
        if type(attestation_name) is not str or not re.fullmatch(r'[A-Za-z0-9_.-]{1,255}', attestation_name):
            raise ValueError('invalid artifact name')
        name = quote(attestation_name, safe='')
        deadline = time.monotonic() + 60
        def fetch() -> JsonObject:
            attempt_data = self._metadata(f'/actions/runs/{run}/attempts/{attempt}', deadline)
            jobs = self._metadata(f'/actions/runs/{run}/attempts/{attempt}/jobs?per_page=100', deadline)
            listing = self._metadata(f'/actions/runs/{run}/artifacts?per_page=100&name={name}', deadline)
            artifact = select_run_artifact(identity, attempt_data, jobs, listing, name=attestation_name)
            return {'attempt': attempt_data, 'jobs': jobs, 'artifact': artifact}
        return stable_metadata(fetch)

    def download(self, artifact_id: int) -> bytes:
        if type(artifact_id) is not int or artifact_id <= 0:
            raise ValueError('invalid artifact id')
        deadline = time.monotonic() + 60
        status, headers, _ = self._request(
            f'{self._base}/actions/artifacts/{artifact_id}/zip', self._token, 0, deadline)
        if status not in (301, 302, 303, 307, 308):
            raise ValueError('expected artifact download redirect')
        location = headers.get('location', '')
        _storage_redirect(location)
        status, _, raw = self._request(location, None, SOURCE_ARCHIVE_LIMIT, deadline)
        if status != 200:
            raise ValueError('unexpected artifact storage redirect')
        return raw

    def resolve_custody(self, identity: JsonObject, *, now) -> JsonObject:
        """Read completed-run custody metadata to stability, without asserting authority."""
        return self._resolve_custody(identity, now=now, active=False)

    def resolve_active_custody(self, identity: JsonObject, *, now) -> JsonObject:
        """Read active upload metadata; this does not authenticate the uploader."""
        return self._resolve_custody(identity, now=now, active=True)

    def _resolve_custody(self, identity: JsonObject, *, now, active: bool) -> JsonObject:
        run, attempt, name = identity.get('run_id'), identity.get('attempt'), identity.get('name')
        if (type(run) is not int or run <= 0 or type(attempt) is not int or attempt != 1
                or type(name) is not str or not re.fullmatch(r'[A-Za-z0-9_.-]{1,255}', name)):
            raise ValueError('invalid custody metadata selector')
        deadline = time.monotonic() + 60
        def fetch() -> JsonObject:
            attempt_data = self._metadata(f'/actions/runs/{run}/attempts/{attempt}', deadline)
            jobs = self._metadata(f'/actions/runs/{run}/attempts/{attempt}/jobs?per_page=100', deadline)
            listing = self._metadata(f'/actions/runs/{run}/artifacts?per_page=100&name={quote(name, safe="")}', deadline)
            selector = select_active_custody_artifact if active else select_custody_artifact
            artifact = selector(identity, attempt_data, jobs, listing, now=now)
            job = next(row for row in jobs['jobs'] if row['id'] == identity['job_id'])
            return {'run': attempt_data, 'job': job, 'job_count': len(jobs['jobs']), 'artifact': artifact}
        return stable_metadata(fetch)

    def resolve_custody_roster(self, run_id: int, expected: list[JsonObject]) -> JsonObject:
        """Check a signed expected roster against the complete run listing."""
        if (type(run_id) is not int or run_id <= 0 or type(expected) is not list or not 1 <= len(expected) <= 17
                or any(type(row) is not dict or set(row) != {'id', 'name'} or type(row['id']) is not int
                       or row['id'] <= 0 or type(row['name']) is not str
                       or not re.fullmatch(r'p11lab-image-custody-[A-Za-z0-9_.-]{1,220}', row['name']) for row in expected)
                or len({row['id'] for row in expected}) != len(expected)
                or len({row['name'] for row in expected}) != len(expected)):
            raise ValueError('invalid expected custody artifact roster')
        wanted = sorted(expected, key=lambda row: row['name'])
        deadline = time.monotonic() + 60
        def fetch() -> JsonObject:
            listing = self._metadata(f'/actions/runs/{run_id}/artifacts?per_page=100', deadline)
            try:
                rows = listing['artifacts']
                if (type(rows) is not list or type(listing['total_count']) is not int
                        or listing['total_count'] != len(rows) or len(rows) > 100
                        or any(type(row) is not dict or type(row.get('id')) is not int or row['id'] <= 0
                               or type(row.get('name')) is not str for row in rows)):
                    raise ValueError('incomplete custody artifact listing')
                selected = [{'id': row['id'], 'name': row['name']} for row in rows
                            if type(row) is dict and type(row.get('name')) is str
                            and row['name'].startswith('p11lab-image-custody-')]
                if (any(type(row['id']) is not int or row['id'] <= 0 for row in selected)
                        or sorted(selected, key=lambda row: row['name']) != wanted):
                    raise ValueError('custody artifact roster mismatch')
                return {'artifacts': wanted}
            except (KeyError, TypeError, AttributeError) as error:
                raise ValueError('malformed custody artifact listing') from error
        return stable_metadata(fetch)

    def download_custody(self, metadata: CustodyArtifactBytes, destination: Path, *, journal_path=None) -> None:
        """Stream one separately authenticated custody artifact to a new file.

        This validates bytes only. The caller must independently authenticate
        the metadata and producer before calling it.
        """
        if type(metadata) is not CustodyArtifactBytes:
            raise ValueError('typed custody artifact required')
        artifact_id, size, digest = metadata.id, metadata.size, metadata.digest
        deadline = time.monotonic() + 120
        status, headers, _ = self._request(
            f'{self._base}/actions/artifacts/{artifact_id}/zip', self._token, 0, deadline)
        if status not in (301, 302, 303, 307, 308):
            raise ValueError('expected artifact download redirect')
        location = headers.get('location', '')
        _storage_redirect(location)
        request = Request(location, headers={'User-Agent': 'p11lab-round', 'Accept-Encoding': 'identity'}, method='GET')
        opener = build_opener(ProxyHandler({}), _HTTPS(deadline), _NoRedirect())
        total = 0
        observed = hashlib.sha256()
        with destination.open('xb') as output:
            try:
                with opener.open(request, timeout=max(.01, min(15, deadline - time.monotonic()))) as response:
                    if response.status != 200:
                        raise ValueError(f'custody storage request failed with HTTP {response.status}')
                    if response.headers.get('Content-Encoding', 'identity').lower() != 'identity':
                        raise ValueError('unexpected custody storage content encoding')
                    while block := response.read1(65536):
                        total += len(block)
                        if total > size or total > CUSTODY_ZIP_LIMIT or time.monotonic() > deadline:
                            raise ValueError('custody storage byte/time bound')
                        observed.update(block)
                        output.write(block)
                    if time.monotonic() > deadline or total != size or 'sha256:' + observed.hexdigest() != digest:
                        raise ValueError('custody artifact size, digest or deadline mismatch')
            except (URLError, TimeoutError, ConnectionError) as error:
                if isinstance(error, HTTPError):
                    code = error.code
                    http_status = code if type(code) is int and 100 <= code <= 599 else None
                    if http_status is None:
                        category = 'http-unknown'
                    elif http_status == 429 or 500 <= http_status <= 599:
                        category = 'http-transient'
                    else:
                        category = 'http-fatal'
                else:
                    http_status = None
                    candidate = error.reason if isinstance(error, URLError) else error
                    if isinstance(candidate, TimeoutError):
                        category = 'timeout'
                    elif isinstance(candidate, ConnectionError):
                        category = 'network-reset'
                    else:
                        category = 'network'
                record = {'error_category': category, 'http_status': http_status,
                          'artifact_id': artifact_id, 'expected_bytes': size, 'observed_bytes': total}
                message = 'custody transport failed: ' + category
                if http_status is not None:
                    message += f' http {http_status}'
                message += f' artifact {artifact_id} bytes {total}/{size}'
                failure = TransientTransportError(message)
                failure.failure_record = record
                failure.error_category = category
                failure.http_status = http_status
                if journal_path is not None:
                    from ..receipts import write_receipt
                    try:
                        write_receipt(journal_path, record)
                    except (OSError, ValueError) as journal_error:
                        failure.add_note('custody failure journal write failed: ' + type(journal_error).__name__)
                raise failure from None

    def download_custody_control(self, metadata: CustodyArtifactBytes) -> bytes:
        """Acquire the separately selected, bounded control ZIP, never authority."""
        if type(metadata) is not CustodyArtifactBytes or metadata.size > 2 * 1024 * 1024:
            raise ValueError('invalid custody control artifact identity')
        deadline = time.monotonic() + 120
        status, headers, _ = self._request(
            f'{self._base}/actions/artifacts/{metadata.id}/zip', self._token, 0, deadline)
        if status not in (301, 302, 303, 307, 308):
            raise ValueError('expected artifact download redirect')
        location = headers.get('location', '')
        _storage_redirect(location)
        status, _, raw = self._request(location, None, 2 * 1024 * 1024, deadline)
        if status != 200 or len(raw) != metadata.size or 'sha256:' + hashlib.sha256(raw).hexdigest() != metadata.digest:
            raise ValueError('custody control artifact bytes mismatch')
        return raw

    def acquire(self, identity: JsonObject, *, cache_file: Path | None = None,
                artifact_name: str | None = None, retries: int = 1,
                before_download: Callable[[JsonObject], None] | None = None,
                sleep: Callable[[float], None] = time.sleep
                ) -> tuple[JsonObject, bytes]:
        """At most one retry for transport failures, before any execution."""
        if type(retries) is not int or retries not in (0, 1):
            raise ValueError('invalid transport retry count')
        for attempt in range(retries + 1):
            try:
                metadata = self.resolve(identity) if artifact_name is None else self.resolve(identity, artifact_name=artifact_name)
                if before_download is not None:
                    before_download(metadata)
                raw = self.download(metadata['id']) if cache_file is None else read_source_archive(cache_file)
                verify_artifact_digest(raw, metadata)
                return metadata, raw
            except TransientTransportError:
                if attempt == retries:
                    raise
                sleep(10)
        raise AssertionError('unreachable')
