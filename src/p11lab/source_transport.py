"""Anonymous, bounded GHCR source artifact readback.

These bytes are network observations, not producer or rights authority.  The
caller must independently authenticate the expected roster and context.
"""
from __future__ import annotations

import hashlib
import json
import re
import ssl
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from .jsonutil import loads
from .publish import CONTENT_FILES, SEAL_FILES, verify_artifact_roster
from .tool_downloads import _HTTPS

_DIGEST = re.compile(r'[0-9a-f]{64}\Z')
_REPOSITORY = re.compile(r'ghcr\.io/p11lab/[a-z0-9]+(?:-[a-z0-9]+)*\Z')
_TYPES = {'application/vnd.p11lab.sealed-source.v1': SEAL_FILES,
          'application/vnd.p11lab.source-companion.v1': CONTENT_FILES}
_MANIFEST_LIMIT = 1024 * 1024
_CONFIG_LIMIT = 64 * 1024
# Source archives can contain up to 4 GiB of uncompressed payloads; reserve
# headroom for tar/gzip framing without weakening member extraction bounds.
_LAYER_LIMIT = 5 * 1024**3
_TOTAL_LIMIT = 5 * 1024**3


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _opener(deadline):
    # Do not use ambient proxy, HOME, netrc, client certs, or SSL_CERT_FILE.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile='/etc/ssl/certs/ca-certificates.crt')
    handler = _HTTPS(deadline)
    handler._context = context
    return build_opener(ProxyHandler({}), handler, _NoRedirect())


def _request(url, *, token, limit, destination, record):
    deadline = time.monotonic() + (900 if limit > 64 * 1024**2 else 120)
    opener = _opener(deadline)
    current = url
    for hop in range(4):
        target = urlsplit(current)
        host = target.hostname or ''
        if (target.scheme != 'https' or target.username or target.password or target.port not in (None, 443)
                or target.fragment or not (host == 'ghcr.io' or host == 'pkg-containers.githubusercontent.com'
                    or host.endswith('.blob.core.windows.net'))):
            raise ValueError('unapproved source registry redirect origin')
        headers = {'User-Agent': 'p11lab-source-readback',
                   'Accept': 'application/vnd.oci.image.manifest.v1+json, application/octet-stream'}
        if token and host == 'ghcr.io' and hop == 0:
            headers['Authorization'] = 'Bearer ' + token
        try:
            try:
                response = opener.open(Request(current, headers=headers), timeout=15)
            except HTTPError as error:
                response = error
            with response:
                record.setdefault('statuses', []).append(response.status)
                if response.status in (301, 302, 303, 307, 308):
                    current = response.headers.get('Location', '')
                    if not current or hop == 3:
                        raise ValueError('invalid source registry redirect')
                    continue
                if response.status != 200:
                    raise ValueError('source registry HTTP status ' + str(response.status))
                count = 0
                with destination.open('xb') as output:
                    while True:
                        if time.monotonic() > deadline:
                            raise ValueError('source registry deadline exceeded')
                        chunk = response.read(min(65536, limit + 1 - count))
                        if not chunk:
                            break
                        count += len(chunk)
                        if count > limit:
                            raise ValueError('source registry byte bound exceeded')
                        output.write(chunk)
                record.update(status=response.status, bytes=count)
                return
        except (URLError, TimeoutError, ConnectionError) as error:
            raise ValueError('source registry transport failed: ' + type(error).__name__) from None
    raise ValueError('source registry redirect limit exceeded')


def _anonymous_token(repository, record):
    import tempfile
    name = repository.removeprefix('ghcr.io/')
    url = 'https://ghcr.io/token?service=ghcr.io&scope=' + quote('repository:' + name + ':pull', safe=':')
    with tempfile.TemporaryDirectory(prefix='p11lab-anonymous-token-') as tmp:
        path = Path(tmp) / 'token.json'
        _request(url, token=None, limit=64 * 1024, destination=path, record=record)
        value = loads(path.read_bytes())
    token = value.get('token') if isinstance(value, dict) else None
    if type(token) is not str or not token or len(token) > 32768 or '\n' in token or '\r' in token:
        raise ValueError('invalid anonymous registry token response')
    return token


def _fetch(repository, path, destination, *, token, limit, record):
    _request('https://ghcr.io/v2/' + repository.removeprefix('ghcr.io/') + path,
             token=token, limit=limit, destination=destination, record=record)


def _digest(path):
    h = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def acquire(repository, manifest_sha256, expected, *, artifact_type, output_dir):
    """Acquire a fixed GHCR source roster by digest without inherited credentials."""
    if type(repository) is not str or not _REPOSITORY.fullmatch(repository):
        raise ValueError('source repository is not a selected P11Lab GHCR repository')
    if type(manifest_sha256) is not str or not _DIGEST.fullmatch(manifest_sha256):
        raise ValueError('source manifest requires immutable SHA256')
    roster = _TYPES.get(artifact_type)
    if roster is None or type(expected) is not dict or set(expected) != set(roster):
        raise ValueError('source type or exact expected source roster mismatch')
    total = 0
    for name, record in expected.items():
        if (type(record) is not dict or set(record) != {'sha256', 'size_bytes', 'media_type'}
                or type(record['sha256']) is not str or not _DIGEST.fullmatch(record['sha256'])
                or type(record['size_bytes']) is not int or not 0 <= record['size_bytes'] <= _LAYER_LIMIT
                or record['media_type'] != roster[name]):
            raise ValueError('invalid expected source descriptor')
        total += record['size_bytes']
    if total > _TOTAL_LIMIT:
        raise ValueError('source roster byte bound exceeded')
    expected = {name: dict(record) for name, record in expected.items()}
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=False)
    observations = {'token': {}, 'manifest': {}, 'config': {}, 'layers': {}}
    status = 'failed'
    try:
        token = _anonymous_token(repository, observations['token'])
        manifest_path = output / 'manifest.json'
        _fetch(repository, '/manifests/sha256:' + manifest_sha256, manifest_path,
               token=token, limit=_MANIFEST_LIMIT, record=observations['manifest'])
        verify_artifact_roster(manifest_path, manifest_sha256, expected)
        manifest = loads(manifest_path.read_bytes())
        if manifest.get('artifactType') != artifact_type:
            raise ValueError('source manifest artifact type mismatch')
        config = manifest.get('config')
        if (type(config) is not dict or config.get('mediaType') != 'application/vnd.oci.empty.v1+json'
                or type(config.get('digest')) is not str or not re.fullmatch(r'sha256:[0-9a-f]{64}', config['digest'])
                or config.get('size') != 2
                or config.get('digest') != 'sha256:' + hashlib.sha256(b'{}').hexdigest()
                or 'urls' in config or ('data' in config and config['data'] != 'e30=')):
            raise ValueError('invalid source manifest config descriptor')
        config_path = output / 'config.json'
        if 'data' in config:
            config_path.write_bytes(b'{}')
            observations['config']['embedded'] = True
        else:
            _fetch(repository, '/blobs/' + config['digest'], config_path, token=token,
                   limit=config['size'], record=observations['config'])
        if config_path.stat().st_size != config['size'] or 'sha256:' + _digest(config_path) != config['digest']:
            raise ValueError('source config digest or size mismatch')
        files = output / 'files'
        files.mkdir()
        for name, record in expected.items():
            observations['layers'][name] = {}
            _fetch(repository, '/blobs/sha256:' + record['sha256'], files / name,
                   token=token, limit=record['size_bytes'], record=observations['layers'][name])
        verify_artifact_roster(manifest_path, manifest_sha256, expected, pulled_dir=files)
        status = 'complete'
        return {'reference': repository + '@sha256:' + manifest_sha256, 'manifest_sha256': manifest_sha256,
                'artifact_type': artifact_type, 'config_sha256': config['digest'].removeprefix('sha256:'),
                'files': expected, 'native_transport': observations,
                'scope': 'anonymous source bytes only; producer and rights authority not established'}
    finally:
        journal = {'status': status, 'native_transport': observations}
        (output / 'transport-journal.json').write_text(json.dumps(journal, sort_keys=True) + '\n')
