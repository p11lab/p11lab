"""Proxy caller mounts and controller logs preserve the application contract."""
import csv
from dataclasses import replace
import io
import json
import os
from pathlib import Path
import re

import pytest

from p11lab import native, run
from p11lab.docker import CommandResult
from test_proxy_lifecycle import IMAGE, client, spec
from test_proxy_terminal import TerminalEngine


def read_without_atime(path):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOATIME), 'rb') as stream:
        return stream.read()


def metadata(path):
    state = path.stat()
    return tuple(getattr(state, name) for name in
                 ('st_mode', 'st_uid', 'st_gid', 'st_size', 'st_atime_ns', 'st_mtime_ns', 'st_ctime_ns', 'st_nlink'))


class AppEngine(TerminalEngine):
    """Only Docker is substituted; production placement/log/finalization runs."""
    def __init__(self, manifest, *, status=0, plant=None):
        super().__init__(manifest)
        self.status = status
        self.plant = plant
        self.created = []

    def create(self, image, argv, options, labels, name):
        self.created.append((image, tuple(argv), list(options), dict(labels), name))
        return super().create(image, argv, options, labels, name)

    def execute(self, identity, *args):
        if identity.endswith('-app'):
            if self.plant:
                self.plant()
            return CommandResult(self.status, 'application secret-test-pin output', 'application secret-test-so error')
        return super().execute(identity, *args)


def attempt(tmp_path, client, monkeypatch, engine, **changes):
    monkeypatch.setattr(run, 'Docker', lambda: engine)
    monkeypatch.setattr(run, '_create_proxy_network', lambda *args: 'fixture-network')
    selected = replace(spec(tmp_path, client), execution_location='container', consumer_artifact=IMAGE,
                       installed_prefix=None, timeout_seconds=30, argv=('/caller', 'literal " $(); argument'), **changes)
    result = run.run_application(selected)
    return result, json.loads(result.receipt_path.read_text())


def assert_clean(engine, receipt):
    assert not receipt['cleanup_errors']
    assert not engine.post_ran_while_live
    assert {('container', item[4]) for item in engine.created} <= set(engine.removed)
    assert ('network', 'fixture-network') in engine.removed
    assert any(kind == 'volume' for kind, _ in engine.removed)
    assert not receipt['state']['owned_directory_retained']


@pytest.mark.parametrize('status', [0, 37])
def test_proxy_quoted_bind_paths_roundtrip_and_preserve_mount_contract(tmp_path, client, monkeypatch, status):
    quoted = tmp_path / 'space \'";$()'
    quoted.mkdir()
    cwd = quoted / 'caller'
    cwd.mkdir()
    monkeypatch.setattr(native, 'staging_parent', lambda path: quoted)
    engine = AppEngine(client.manifest, status=status)
    result, receipt = attempt(tmp_path, client, monkeypatch, engine, cwd=cwd, output_dir=quoted / 'output')
    assert result.exit_code == status
    all_mounts = {}
    for _, _, options, _, name in engine.created:
        decoded = []
        for index, word in enumerate(options):
            if word != '--mount':
                continue
            encoded = options[index + 1]
            # Go's CSV reader rejects bare double quotes that Python accepts.
            field = r'(?:[^,"\r\n]*|"(?:[^"]|"")*")'
            assert re.fullmatch(field + '(?:,' + field + ')*', encoded), encoded
            decoded.append(next(csv.reader(io.StringIO(encoded), strict=True)))
        all_mounts[name.rsplit('-', 1)[-1]] = decoded
    mounts = all_mounts['app']
    assert len(mounts) == 6
    assert ['type=bind', f'src={cwd}', 'dst=/workspace'] in mounts
    assert ['type=bind', f'src={quoted / "output"}', 'dst=/p11lab-output'] in mounts
    assert sum(fields[-1] == 'readonly' for fields in mounts) == 4
    assert all('dst=/var/lib/p11lab' not in fields for fields in mounts)
    assert {next(field for field in fields if field.startswith('dst=')) for fields in all_mounts['daemon']} == {
        'dst=/var/lib/p11lab', 'dst=/run/p11lab-tls/ca.crt', 'dst=/run/p11lab-tls/server.crt',
        'dst=/run/p11lab-tls/server.key', 'dst=/etc/p11lab/proxy.toml'}
    assert len(all_mounts['daemon']) == 5 and sum(fields[-1] == 'readonly' for fields in all_mounts['daemon']) == 4
    assert {fields[2] for fields in all_mounts['health']} == {
        'dst=/run/p11lab-client-tls/ca.crt', 'dst=/run/p11lab-client-tls/client.crt',
        'dst=/run/p11lab-client-tls/client.key'}
    assert all(fields[-1] == 'readonly' for fields in all_mounts['health'])
    app = next(item for item in engine.created if item[4].endswith('-app'))
    assert app[1] == ('literal " $(); argument',)
    assert app[2][app[2].index('--entrypoint') + 1] == '/caller'
    assert receipt['app_completed'] and receipt['app_returncode'] == status
    assert receipt['proxy']['daemon_terminal']['logs']['available']
    assert_clean(engine, receipt)


@pytest.mark.parametrize('status', [0, 37])
@pytest.mark.parametrize('link_kind', ['symlink', 'hardlink'])
@pytest.mark.parametrize('log_name', ['application.stdout.log', 'application.stderr.log',
                                    'daemon.stdout.log', 'daemon.stderr.log',
                                    'post-health.stdout.log', 'post-health.stderr.log'])
def test_proxy_application_cannot_redirect_controller_logs(tmp_path, client, monkeypatch, status, link_kind, log_name):
    sentinel = tmp_path / 'outside-sentinel'
    original = b'preserve external bytes and metadata'
    sentinel.write_bytes(original)
    after_plant = []
    def plant():
        target = tmp_path / 'output' / log_name
        if link_kind == 'symlink':
            target.symlink_to(sentinel)
        else:
            os.link(sentinel, target)
        # Hardlink creation itself changes nlink/ctime; compare after planting.
        after_plant.append(metadata(sentinel))
    engine = AppEngine(client.manifest, status=status, plant=plant)
    result, receipt = attempt(tmp_path, client, monkeypatch, engine)
    assert read_without_atime(sentinel) == original
    assert metadata(sentinel) == after_plant[0]
    assert result.exit_code == (status or 1)
    assert receipt['app_returncode'] == status and receipt['app_completed']
    assert result.lifecycle_errors
    app_stage = next(item for item in receipt['stages'] if item['phase'] == 'application')
    assert app_stage['returncode'] == status and not app_stage['timed_out']
    if log_name.startswith('post-health.'):
        post_stage = next(item for item in receipt['stages'] if item['phase'] == 'post-health')
        assert post_stage['returncode'] == 0 and not post_stage['timed_out']
    terminal = receipt['proxy']['daemon_terminal']
    if log_name.startswith('daemon.'):
        assert terminal['logs']['available'] is False
        assert terminal['logs']['returncode'] == 0  # native command succeeded, output unsafe
        assert 'FileExistsError' in terminal['logs']['error']
    else:
        assert terminal['logs']['available'] is True
        assert any('evidence incomplete' in error for error in result.lifecycle_errors)
    assert_clean(engine, receipt)


@pytest.mark.parametrize('status', [0, 37])
@pytest.mark.parametrize('stream', ['stdout', 'stderr'])
@pytest.mark.parametrize('link_kind', ['symlink', 'hardlink'])
def test_host_proxy_safe_capture_preserves_real_process_status(tmp_path, client, monkeypatch, status, stream, link_kind):
    import sys
    sentinel = tmp_path / 'host-outside-sentinel'
    sentinel.write_bytes(b'host owned control')
    metadata_record = tmp_path / 'sentinel-metadata.json'
    script = '''import json, os, pathlib, sys
output = pathlib.Path(os.environ['P11LAB_OUTPUT_DIR'])
sentinel, metadata_record, stream, link_kind, status = sys.argv[1:]
target = output / ('application.' + stream + '.log')
if link_kind == 'symlink': target.symlink_to(sentinel)
else: os.link(sentinel, target)
st = pathlib.Path(sentinel).stat()
pathlib.Path(metadata_record).write_text(json.dumps([getattr(st, n) for n in ('st_mode','st_uid','st_gid','st_size','st_atime_ns','st_mtime_ns','st_ctime_ns','st_nlink')]))
print('secret-test-pin captured output')
print('secret-test-so captured error', file=sys.stderr)
sys.exit(int(status))
'''
    engine = AppEngine(client.manifest)
    monkeypatch.setattr(run, 'Docker', lambda: engine)
    monkeypatch.setattr(run, '_create_proxy_network', lambda *args: 'fixture-network')
    selected = replace(spec(tmp_path, client), timeout_seconds=30,
                       argv=(sys.executable, '-c', script, str(sentinel), str(metadata_record), stream, link_kind, str(status)))
    result = run.run_application(selected)
    receipt = json.loads(result.receipt_path.read_text())
    assert read_without_atime(sentinel) == b'host owned control'
    assert metadata(sentinel) == tuple(json.loads(metadata_record.read_text()))
    assert result.exit_code == (status or 1)
    assert receipt['app_returncode'] == status and receipt['app_completed']
    stage = next(item for item in receipt['stages'] if item['phase'] == 'application')
    assert stage['returncode'] == status and stage['drain_complete']
    assert not stage['supervision_errors'] and not stage['stragglers_remaining']
    assert any('evidence incomplete' in error for error in result.lifecycle_errors)
    assert receipt['proxy']['daemon_terminal']['logs']['available']
    assert_clean(engine, receipt)


@pytest.mark.parametrize('status', [0, 37])
def test_host_proxy_clean_capture_retains_redaction_bounds_and_status(tmp_path, client, monkeypatch, status):
    import sys
    from p11lab.process import LIMIT
    engine = AppEngine(client.manifest)
    monkeypatch.setattr(run, 'Docker', lambda: engine)
    monkeypatch.setattr(run, '_create_proxy_network', lambda *args: 'fixture-network')
    script = "import sys; print('secret-test-pin'); print('x' * (2 * 1024 * 1024)); print('secret-test-so', file=sys.stderr); sys.exit(int(sys.argv[1]))"
    selected = replace(spec(tmp_path, client), timeout_seconds=30, argv=(sys.executable, '-c', script, str(status)))
    result = run.run_application(selected)
    receipt = json.loads(result.receipt_path.read_text())
    assert result.exit_code == status and receipt['app_completed']
    assert not result.lifecycle_errors
    stage = next(item for item in receipt['stages'] if item['phase'] == 'application')
    assert stage['stdout_truncated'] and not stage['stderr_truncated']
    assert stage['log_errors'] == []
    for stream in ('stdout', 'stderr'):
        data = (selected.output_dir / ('application.' + stream + '.log')).read_bytes()
        assert len(data) <= LIMIT
        assert b'[REDACTED]' in data and b'secret-test-' not in data
    assert_clean(engine, receipt)


@pytest.mark.parametrize('bad', [',', '\n', '\r', '\0'])
def test_proxy_invalid_declared_inputs_still_reject_before_output(tmp_path, client, monkeypatch, bad):
    engine = AppEngine(client.manifest)
    monkeypatch.setattr(run, 'Docker', lambda: engine)
    selected = spec(tmp_path, client)
    if bad == ',':
        selected = replace(selected, output_dir=tmp_path / 'comma,output')
    else:
        selected = replace(selected, inputs={'P11LAB_PIN': 'value' + bad})
    with pytest.raises(ValueError):
        run.run_application(selected)
    assert not selected.output_dir.exists() and not engine.created


def test_unsafe_post_health_log_retains_native_timeout(tmp_path, client, monkeypatch):
    sentinel = tmp_path / 'post-timeout-sentinel'
    sentinel.write_bytes(b'untouched')
    class PostTimeoutEngine(AppEngine):
        def execute(self, identity, *args):
            result = super().execute(identity, *args)
            if self.argv[identity] == ('health',):
                return CommandResult(124, 'post timeout', '', True)
            return result
    engine = PostTimeoutEngine(client.manifest, status=37,
                               plant=lambda: (tmp_path / 'output' / 'post-health.stdout.log').symlink_to(sentinel))
    result, receipt = attempt(tmp_path, client, monkeypatch, engine)
    assert result.exit_code == 37 and receipt['app_completed']
    assert receipt['timeout'] is True
    post = next(stage for stage in receipt['stages'] if stage['phase'] == 'post-health')
    assert post['returncode'] == 124 and post['timed_out']
    assert read_without_atime(sentinel) == b'untouched'
    assert_clean(engine, receipt)


def test_host_proxy_unsafe_log_keeps_actual_timeout_and_cleanup(tmp_path, client, monkeypatch):
    import sys
    sentinel = tmp_path / 'host-timeout-sentinel'
    sentinel.write_bytes(b'untouched')
    engine = AppEngine(client.manifest)
    monkeypatch.setattr(run, 'Docker', lambda: engine)
    monkeypatch.setattr(run, '_create_proxy_network', lambda *args: 'fixture-network')
    script = "import os,pathlib,sys,time; pathlib.Path(os.environ['P11LAB_OUTPUT_DIR'],'application.stdout.log').symlink_to(sys.argv[1]); time.sleep(20)"
    selected = replace(spec(tmp_path, client), timeout_seconds=2,
                       argv=(sys.executable, '-c', script, str(sentinel)))
    result = run.run_application(selected)
    receipt = json.loads(result.receipt_path.read_text())
    assert result.exit_code == 124 and receipt['timeout']
    assert receipt['app_returncode'] == 124 and not receipt['app_completed']
    stage = next(item for item in receipt['stages'] if item['phase'] == 'application')
    assert stage['timed_out'] and stage['drain_complete'] and stage['log_errors']
    assert not stage['stragglers_remaining'] and not stage['supervision_errors']
    assert read_without_atime(sentinel) == b'untouched'
    assert receipt['proxy']['daemon_terminal']['logs']['available']
    assert_clean(engine, receipt)
