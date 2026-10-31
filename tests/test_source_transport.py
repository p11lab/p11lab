"""Source transport mechanics are local fixtures, not hosted authority."""
import hashlib
import json

import pytest

from p11lab import source_transport


def sha(value):
    return hashlib.sha256(value).hexdigest()


def source_fixture():
    files = {'sealed-source.tar.gz': b'archive', 'sealed-source.json': b'receipt'}
    expected = {name: {'sha256': sha(data), 'size_bytes': len(data), 'media_type': media}
                for (name, data), media in zip(files.items(), ('application/gzip', 'application/json'))}
    config = b'{}'
    manifest = json.dumps({'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.manifest.v1+json',
        'artifactType': 'application/vnd.p11lab.sealed-source.v1',
        'config': {'digest': 'sha256:' + sha(config), 'size': len(config), 'mediaType': 'application/vnd.oci.empty.v1+json'},
        'layers': [{'digest': 'sha256:' + sha(value), 'size': len(value), 'mediaType': expected[name]['media_type'],
                    'annotations': {'org.opencontainers.image.title': name}} for name, value in files.items()]}).encode()
    return files, expected, config, manifest


def test_source_readback_fetches_exact_immutable_manifest_before_config_and_files(tmp_path, monkeypatch):
    files, expected, config, manifest = source_fixture()
    bodies = {'manifest': manifest, 'sha256:' + sha(config): config}
    bodies.update({'sha256:' + sha(data): data for data in files.values()})
    calls = []

    def fetch(repository, path, destination, *, token, limit, record):
        calls.append(path)
        body = bodies['manifest' if '/manifests/' in path else path.rsplit('/', 1)[-1]]
        assert len(body) <= limit
        destination.write_bytes(body)
        record.update(status=200, bytes=len(body))

    monkeypatch.setattr(source_transport, '_anonymous_token', lambda repository, record: 'fixture-token')
    monkeypatch.setattr(source_transport, '_fetch', fetch)
    result = source_transport.acquire('ghcr.io/p11lab/softhsm2', sha(manifest), expected,
        artifact_type='application/vnd.p11lab.sealed-source.v1', output_dir=tmp_path / 'result')
    assert '/manifests/sha256:' + sha(manifest) in calls[0]
    assert calls[1].endswith('sha256:' + sha(config))
    assert {p.name: p.read_bytes() for p in (tmp_path / 'result' / 'files').iterdir()} == files
    assert result['manifest_sha256'] == sha(manifest)
    assert 'fixture-token' not in json.dumps(result)
    assert 'source_authorized' not in result


def test_bad_manifest_never_fetches_layers(tmp_path, monkeypatch):
    files, expected, config, manifest = source_fixture()
    altered = json.loads(manifest)
    altered['layers'][0]['annotations']['org.opencontainers.image.title'] = '../escape'
    manifest = json.dumps(altered).encode()
    calls = []

    def fetch(repository, path, destination, *, token, limit, record):
        calls.append(path)
        destination.write_bytes(manifest)
        record.update(status=200, bytes=len(manifest))

    monkeypatch.setattr(source_transport, '_anonymous_token', lambda repository, record: 'fixture-token')
    monkeypatch.setattr(source_transport, '_fetch', fetch)
    with pytest.raises(ValueError):
        source_transport.acquire('ghcr.io/p11lab/softhsm2', sha(manifest), expected,
            artifact_type='application/vnd.p11lab.sealed-source.v1', output_dir=tmp_path / 'result')
    assert len(calls) == 1
    assert not (tmp_path / 'escape').exists()


def test_redirect_never_forwards_registry_bearer_or_query_into_diagnostics(tmp_path, monkeypatch):
    class Response:
        def __init__(self, status, headers=None, body=b''):
            self.status, self.headers, self.body = status, headers or {}, body
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def read(self, limit):
            body, self.body = self.body[:limit], self.body[limit:]
            return body

    requests = []
    class Opener:
        def open(self, request, timeout):
            requests.append(request)
            if len(requests) == 1:
                return Response(302, {'Location': 'https://ghcr.io/elsewhere?sig=secret'})
            return Response(200, body=b'blob')

    monkeypatch.setattr(source_transport, '_opener', lambda deadline: Opener())
    record = {}
    source_transport._request('https://ghcr.io/v2/p11lab/softhsm2/blobs/sha256:abc',
        token='credential', limit=8, destination=tmp_path / 'blob', record=record)
    assert requests[0].get_header('Authorization') == 'Bearer credential'
    assert requests[1].get_header('Authorization') is None
    assert 'secret' not in json.dumps(record) and 'credential' not in json.dumps(record)


def test_failed_fetch_retains_bounded_native_status_without_secrets(tmp_path, monkeypatch):
    files, expected, config, manifest = source_fixture()
    def fail(repository, path, destination, *, token, limit, record):
        record['statuses'] = [403]
        raise ValueError('native failure carrying secret')
    monkeypatch.setattr(source_transport, '_anonymous_token', lambda repository, record: 'secret')
    monkeypatch.setattr(source_transport, '_fetch', fail)
    with pytest.raises(ValueError):
        source_transport.acquire('ghcr.io/p11lab/softhsm2', sha(manifest), expected,
            artifact_type='application/vnd.p11lab.sealed-source.v1', output_dir=tmp_path / 'result')
    journal = json.loads((tmp_path / 'result' / 'transport-journal.json').read_text())
    assert journal['native_transport']['manifest']['statuses'] == [403]
    assert journal['status'] == 'failed'
    assert 'secret' not in json.dumps(journal)


def test_inline_oci_empty_config_is_verified_without_blob_fetch(tmp_path, monkeypatch):
    files, expected, config, manifest = source_fixture()
    value = json.loads(manifest)
    value['config']['data'] = 'e30='
    manifest = json.dumps(value).encode()
    bodies = {'manifest': manifest}
    bodies.update({'sha256:' + sha(data): data for data in files.values()})
    calls = []
    def fetch(repository, path, destination, *, token, limit, record):
        calls.append(path)
        body = bodies['manifest' if '/manifests/' in path else path.rsplit('/', 1)[-1]]
        destination.write_bytes(body)
        record.update(status=200, bytes=len(body))
    monkeypatch.setattr(source_transport, '_anonymous_token', lambda repository, record: 'fixture-token')
    monkeypatch.setattr(source_transport, '_fetch', fetch)
    result = source_transport.acquire('ghcr.io/p11lab/softhsm2', sha(manifest), expected,
        artifact_type='application/vnd.p11lab.sealed-source.v1', output_dir=tmp_path / 'result')
    assert result['config_sha256'] == sha(b'{}')
    assert not any(path.endswith('sha256:' + sha(config)) for path in calls)
    assert (tmp_path / 'result' / 'config.json').read_bytes() == b'{}'


@pytest.mark.parametrize('damage', ['missing', 'extra', 'title', 'media', 'size', 'digest', 'artifact-type', 'config', 'layer'])
def test_source_readback_refuses_changed_oci_bytes(tmp_path, monkeypatch, damage):
    files, expected, config, manifest = source_fixture()
    value = json.loads(manifest)
    if damage == 'missing':
        value['layers'].pop()
    elif damage == 'extra':
        value['layers'].append(value['layers'][0].copy())
    elif damage == 'title':
        value['layers'][0]['annotations']['org.opencontainers.image.title'] = '../escape'
    elif damage == 'media':
        value['layers'][0]['mediaType'] = 'application/octet-stream'
    elif damage == 'size':
        value['layers'][0]['size'] += 1
    elif damage == 'digest':
        value['layers'][0]['digest'] = 'sha256:' + 'f' * 64
    elif damage == 'artifact-type':
        value['artifactType'] = 'application/other'
    elif damage == 'config':
        value['config']['digest'] = 'sha256:' + 'f' * 64
    manifest = json.dumps(value).encode()
    bodies = {'manifest': manifest, 'sha256:' + sha(config): config}
    bodies.update({'sha256:' + sha(data): data for data in files.values()})
    if damage == 'layer':
        bodies['sha256:' + sha(next(iter(files.values())))] = b'corrupt'
    def fetch(repository, path, destination, *, token, limit, record):
        body = bodies['manifest' if '/manifests/' in path else path.rsplit('/', 1)[-1]]
        destination.write_bytes(body)
        record.update(status=200, bytes=len(body))
    monkeypatch.setattr(source_transport, '_anonymous_token', lambda repository, record: 'fixture-token')
    monkeypatch.setattr(source_transport, '_fetch', fetch)
    with pytest.raises(ValueError):
        source_transport.acquire('ghcr.io/p11lab/softhsm2', sha(manifest), expected,
            artifact_type='application/vnd.p11lab.sealed-source.v1', output_dir=tmp_path / 'result')
    assert json.loads((tmp_path / 'result' / 'transport-journal.json').read_text())['status'] == 'failed'


@pytest.mark.parametrize('status', [401, 403, 404])
def test_private_expired_or_missing_registry_response_preserves_native_status(tmp_path, monkeypatch, status):
    class Response:
        headers = {}
        def __enter__(self): return self
        def __exit__(self, *args): pass
    class Opener:
        def open(self, request, timeout):
            response = Response()
            response.status = status
            return response
    monkeypatch.setattr(source_transport, '_opener', lambda deadline: Opener())
    record = {}
    with pytest.raises(ValueError, match=str(status)):
        source_transport._request('https://ghcr.io/v2/p11lab/softhsm2/blobs/sha256:abc',
            token='secret', limit=4, destination=tmp_path / 'blob', record=record)
    assert record['statuses'] == [status]
    assert 'secret' not in json.dumps(record)


def test_expected_roster_is_frozen_before_acquisition(tmp_path, monkeypatch):
    files, expected, config, manifest = source_fixture()
    bodies = {'manifest': manifest, 'sha256:' + sha(config): config}
    bodies.update({'sha256:' + sha(data): data for data in files.values()})
    def fetch(repository, path, destination, *, token, limit, record):
        expected['sealed-source.tar.gz']['sha256'] = 'f' * 64
        body = bodies['manifest' if '/manifests/' in path else path.rsplit('/', 1)[-1]]
        destination.write_bytes(body)
        record.update(status=200, bytes=len(body))
    monkeypatch.setattr(source_transport, '_anonymous_token', lambda repository, record: 'fixture-token')
    monkeypatch.setattr(source_transport, '_fetch', fetch)
    result = source_transport.acquire('ghcr.io/p11lab/softhsm2', sha(manifest), expected,
        artifact_type='application/vnd.p11lab.sealed-source.v1', output_dir=tmp_path / 'result')
    assert result['files']['sealed-source.tar.gz']['sha256'] == sha(files['sealed-source.tar.gz'])


def test_large_source_companion_allowed_within_source_bundle_bound(tmp_path, monkeypatch):
    expected = {name: {'sha256': digest * 64, 'size_bytes': size, 'media_type': media}
        for name, digest, size, media in [('source-companion.tar.gz', 'a', 512 * 1024**2 + 1, 'application/gzip'),
            ('source-companion.json', 'b', 10, 'application/json'),
            ('sbom.spdx.json', 'c', 10, 'application/spdx+json')]}
    def stop(repository, record):
        raise RuntimeError('reached bounded acquisition')
    monkeypatch.setattr(source_transport, '_anonymous_token', stop)
    with pytest.raises(RuntimeError, match='reached bounded acquisition'):
        source_transport.acquire('ghcr.io/p11lab/softhsm2', 'd'*64, expected,
            artifact_type='application/vnd.p11lab.source-companion.v1', output_dir=tmp_path/'result')


_CA_PIN = '/etc/ssl/certs/ca-certificates.crt'


def test_opener_pins_debian_controller_ca_bundle(monkeypatch):
    import ssl
    seen = {}
    def record(self, cafile=None, capath=None, cadata=None):
        seen.update(cafile=cafile, capath=capath, cadata=cadata)
    monkeypatch.setattr(ssl.SSLContext, 'load_verify_locations', record)
    source_transport._opener(0.0)
    assert seen == {'cafile': _CA_PIN, 'capath': None, 'cadata': None}


def test_opener_ca_load_failure_propagates_without_fallback(monkeypatch):
    import ssl
    def fail(self, cafile=None, capath=None, cadata=None):
        raise FileNotFoundError(cafile)
    monkeypatch.setattr(ssl.SSLContext, 'load_verify_locations', fail)
    with pytest.raises(FileNotFoundError):
        source_transport._opener(0.0)


def test_opener_ignores_ssl_cert_file_env(monkeypatch):
    import ssl
    seen = {}
    def record(self, cafile=None, capath=None, cadata=None):
        seen['cafile'] = cafile
    monkeypatch.setattr(ssl.SSLContext, 'load_verify_locations', record)
    monkeypatch.setenv('SSL_CERT_FILE', '/nonexistent-bogus-ca.crt')
    source_transport._opener(0.0)
    assert seen['cafile'] == _CA_PIN
