import importlib
import json
from pathlib import Path

import pytest

from tool_input_fixtures import synthetic_assets, install_assets, fake_network


@pytest.fixture
def resolved_fixture(monkeypatch):
    assets, payloads = synthetic_assets()
    install_assets(monkeypatch, assets)
    calls = fake_network(monkeypatch, payloads)
    return importlib.import_module('p11lab.tool_inputs'), assets, payloads, calls


def test_resolve_and_independent_reverify_match_exact_installed_authority(resolved_fixture, tmp_path):
    m, _, _, calls = resolved_fixture
    first = m.resolve_tool_inputs('consumer', target='debian13-amd64', output_dir=tmp_path/'first')
    second = m.resolve_tool_inputs('consumer', target='debian13-amd64', output_dir=tmp_path/'second')
    assert len(calls) == 200
    assert len(first['records']) == 108
    assert first['lock_sha256'] == second['lock_sha256']
    assert first['admission'] == 'unreviewed' and first['installation'] == 'not-executed'
    assert 'artifact' not in first and 'build_key' not in first
    assert m.verify_resolved_tool_inputs('consumer', target='debian13-amd64', receipt_path=tmp_path/'first/resolved-inputs.json') == first


@pytest.mark.parametrize('operation', ['resolve', 'verify'])
def test_selected_lock_and_receipt_hash_use_one_checked_snapshot(resolved_fixture, monkeypatch, tmp_path, operation):
    import hashlib
    m, assets, _, _ = resolved_fixture
    output = tmp_path/'attempt'
    if operation == 'verify':
        m.resolve_tool_inputs('consumer', target='debian13-amd64', output_dir=output)
    name = 'tool-inputs/consumer.debian13-amd64.lock.json'
    expected = hashlib.sha256(assets[name]).hexdigest()
    original = m.package_data
    reads = []
    class Swapped:
        def read_bytes(self):
            reads.append(name)
            return assets[name] + (b'\n' if len(reads) > 1 else b'')
    monkeypatch.setattr(m, 'package_data', lambda asset: Swapped() if asset == name else original(asset))
    if operation == 'resolve':
        result = m.resolve_tool_inputs('consumer', target='debian13-amd64', output_dir=output)
    else:
        result = m.verify_resolved_tool_inputs('consumer', target='debian13-amd64', receipt_path=output/'resolved-inputs.json')
    assert result['lock_sha256'] == expected
    assert reads == [name]


@pytest.mark.parametrize('field', ['network_bytes', 'resource_bytes', 'record_size'])
def test_receipt_numeric_types_are_not_coerced(resolved_fixture, tmp_path, field):
    m, _, _, _ = resolved_fixture
    output = tmp_path/'attempt'
    result = m.resolve_tool_inputs('consumer', target='debian13-amd64', output_dir=output)
    if field == 'record_size':
        result['records'][0]['size'] = float(result['records'][0]['size'])
    else:
        result[field] = float(result[field])
    (output/'resolved-inputs.json').write_text(json.dumps(result))
    with pytest.raises(ValueError):
        m.verify_resolved_tool_inputs('consumer', target='debian13-amd64', receipt_path=output/'resolved-inputs.json')


def test_real_receipt_helper_preserves_primary_failure_and_resolver_invalidates(resolved_fixture, monkeypatch, tmp_path):
    import os
    import sys
    import p11lab.receipts as receipts
    if sys.platform != 'linux': pytest.skip('directory fsync is Linux-only')
    m, _, _, _ = resolved_fixture
    original_fsync = os.fsync
    original_unlink = Path.unlink
    import stat
    def fail_fsync(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError('PRIMARY directory fsync failed')
        return original_fsync(fd)
    def fail_unlink(path, *args, **kwargs):
        if path.name.startswith('.resolved-inputs.json-'):
            raise OSError('SECONDARY temporary cleanup failed')
        return original_unlink(path, *args, **kwargs)
    monkeypatch.setattr(receipts.os, 'fsync', fail_fsync)
    monkeypatch.setattr(Path, 'unlink', fail_unlink)
    with pytest.raises(OSError, match='PRIMARY') as caught:
        m.resolve_tool_inputs('consumer', target='debian13-amd64', output_dir=tmp_path/'attempt')
    assert any('SECONDARY' in note for note in caught.value.__notes__)
    assert not (tmp_path/'attempt/resolved-inputs.json').exists()


@pytest.mark.parametrize('wire', [
    b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\na',
    b'HTTP/1.1 200 OK\r\nX-Large: ' + b'x'*65536 + b'\r\n\r\n',
], ids=['truncated-chunk', 'oversized-header'])
def test_real_http_protocol_errors_are_handled_cli_failures(resolved_fixture, monkeypatch, tmp_path, wire):
    import http.client
    import io
    import p11lab.tool_downloads as downloads
    from p11lab.cli import main
    class Socket:
        def makefile(self, *args): return io.BytesIO(wire)
    class Opener:
        def open(self, request, timeout):
            response = http.client.HTTPResponse(Socket())
            try: response.begin()
            except BaseException:
                response.close()
                raise
            response.geturl = lambda: request.full_url
            return response
    monkeypatch.setattr(downloads, 'build_opener', lambda *handlers: Opener())
    output = tmp_path/'failed'
    assert main(['tools', 'resolve', 'consumer', '--target', 'debian13-amd64', '--output-dir', str(output)]) == 2
    assert not (output/'resolved-inputs.json').exists()


@pytest.mark.parametrize('change', ['bytes-and-receipt', 'toolset', 'target', 'source', 'url', 'license', 'absolute',
                                   'missing', 'extra', 'duplicate', 'symlink', 'empty-dir', 'fifo', 'lock'])
def test_reverify_rejects_self_authorized_receipt_and_tree(resolved_fixture, monkeypatch, tmp_path, change):
    m, assets, _, _ = resolved_fixture
    output = tmp_path/'attempt'
    result = m.resolve_tool_inputs('consumer', target='debian13-amd64', output_dir=output)
    record = result['records'][0]
    if change == 'bytes-and-receipt':
        import hashlib
        (output/record['path']).write_bytes(b'forged')
        record.update(size=6, sha256=hashlib.sha256(b'forged').hexdigest())
    elif change in {'toolset', 'target'}: result[change] = 'forged'
    elif change in {'source', 'url'}: record[change] = 'forged'
    elif change == 'license': record['license_status'] = 'reviewed'
    elif change == 'absolute': record['path'] = str(output/record['path'])
    elif change == 'missing': (output/record['path']).unlink()
    elif change == 'extra': (output/'extra').write_bytes(b'x')
    elif change == 'duplicate': result['records'].append(dict(record))
    elif change == 'symlink':
        (output/record['path']).unlink(); (output/record['path']).symlink_to(tmp_path/'missing')
    elif change == 'empty-dir': (output/'undeclared').mkdir()
    elif change == 'fifo':
        import os
        if not hasattr(os, 'mkfifo'): pytest.skip('FIFO unavailable')
        os.mkfifo(output/'pipe')
    elif change == 'lock':
        name = 'tool-inputs/consumer.debian13-amd64.lock.json'
        assets[name] += b'\n'  # Same semantic lock, different installed authoritative bytes.
    (output/'resolved-inputs.json').write_text(json.dumps(result))
    with pytest.raises(ValueError):
        m.verify_resolved_tool_inputs('consumer', target='debian13-amd64', receipt_path=output/'resolved-inputs.json')


@pytest.mark.parametrize('fail_at', [1, 44, 92, 100])
def test_failure_keeps_partial_attempt_without_success_and_requires_fresh_retry(resolved_fixture, monkeypatch, tmp_path, fail_at):
    m, _, payloads, _ = resolved_fixture
    fake_network(monkeypatch, payloads, fail_at=fail_at)
    output = tmp_path/'failed'
    with pytest.raises((OSError, ValueError)):
        m.resolve_tool_inputs('consumer', target='debian13-amd64', output_dir=output)
    assert output.is_dir() and not (output/'resolved-inputs.json').exists()
    with pytest.raises((OSError, ValueError)):
        m.resolve_tool_inputs('consumer', target='debian13-amd64', output_dir=output)
    fake_network(monkeypatch, payloads)
    assert m.resolve_tool_inputs('consumer', target='debian13-amd64', output_dir=tmp_path/'fresh')['installation'] == 'not-executed'


def test_cli_only_exposes_implemented_resolve(resolved_fixture, tmp_path, capsys):
    from p11lab.cli import main
    assert main(['tools', 'resolve', 'consumer', '--target', 'debian13-amd64', '--output-dir', str(tmp_path/'ok')]) == 0
    assert json.loads(capsys.readouterr().out)['admission'] == 'unreviewed'
    assert main(['tools', 'resolve', 'proxy', '--target', 'debian13-amd64', '--output-dir', str(tmp_path/'bad')]) == 2
    assert not (tmp_path/'bad').exists()
    with pytest.raises(SystemExit) as error: main(['tools', 'build'])
    assert error.value.code == 2


def test_resource_corruption_before_copy_emits_no_receipt(resolved_fixture, monkeypatch, tmp_path):
    m, _, _, _ = resolved_fixture
    original = m.package_data
    count = [0]
    class Changed:
        def read_bytes(self): return b'changed after lock load'
    def asset(name):
        if name == 'consumer/smoke.c':
            count[0] += 1
            if count[0] > 1: return Changed()
        return original(name)
    monkeypatch.setattr(m, 'package_data', asset)
    with pytest.raises(ValueError):
        m.resolve_tool_inputs('consumer', target='debian13-amd64', output_dir=tmp_path/'bad')
    assert not (tmp_path/'bad/resolved-inputs.json').exists()


def test_receipt_write_failure_after_replace_does_not_leave_success(resolved_fixture, monkeypatch, tmp_path):
    m, _, _, _ = resolved_fixture
    import p11lab.receipts
    def failed_write(path, record):
        Path(path).write_text(json.dumps(record))
        raise OSError('synthetic directory fsync failure after replacement')
    monkeypatch.setattr(p11lab.receipts, 'write_receipt', failed_write)
    with pytest.raises(OSError, match='fsync'):
        m.resolve_tool_inputs('consumer', target='debian13-amd64', output_dir=tmp_path/'bad')
    assert not (tmp_path/'bad/resolved-inputs.json').exists()


def test_unsafe_output_parent_is_rejected_without_network(resolved_fixture, tmp_path):
    m, _, _, calls = resolved_fixture
    (tmp_path/'target').mkdir()
    (tmp_path/'link').symlink_to(tmp_path/'target', target_is_directory=True)
    with pytest.raises(ValueError):
        m.resolve_tool_inputs('consumer', target='debian13-amd64', output_dir=tmp_path/'link'/'attempt')
    assert not calls


def test_final_rehash_detects_bytes_changed_after_download(resolved_fixture, monkeypatch, tmp_path):
    m, _, _, _ = resolved_fixture
    import p11lab.tool_downloads as downloads
    original = downloads.download_locked_file
    first = []
    count = [0]
    def download(record, destination, **kwargs):
        result = original(record, destination, **kwargs)
        if not first: first.append(destination)
        count[0] += 1
        if count[0] == 100: first[0].write_bytes(b'changed after download verification')
        return result
    monkeypatch.setattr(downloads, 'download_locked_file', download)
    with pytest.raises(ValueError, match='checksum|size'):
        m.resolve_tool_inputs('consumer', target='debian13-amd64', output_dir=tmp_path/'bad')
    assert not (tmp_path/'bad/resolved-inputs.json').exists()


def test_failed_receipt_cleanup_preserves_primary_error(resolved_fixture, monkeypatch, tmp_path):
    m, _, _, _ = resolved_fixture
    import p11lab.receipts
    original_unlink = Path.unlink
    def failed_write(path, record):
        Path(path).write_text(json.dumps(record))
        raise OSError('primary post-replace error')
    def failed_unlink(path, *args, **kwargs):
        if path.name == 'resolved-inputs.json': raise OSError('secondary cleanup denied')
        return original_unlink(path, *args, **kwargs)
    monkeypatch.setattr(p11lab.receipts, 'write_receipt', failed_write)
    monkeypatch.setattr(Path, 'unlink', failed_unlink)
    with pytest.raises(OSError, match='primary') as caught:
        m.resolve_tool_inputs('consumer', target='debian13-amd64', output_dir=tmp_path/'bad')
    assert any('secondary cleanup denied' in note for note in caught.value.__notes__)
