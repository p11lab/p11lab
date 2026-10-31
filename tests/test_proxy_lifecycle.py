"""Proxy placement, durable diagnostics and credential refusal regressions."""
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import struct

import pytest

from p11lab import native, run, tls
from p11lab.bundle import install_bundle
from p11lab.docker import CommandResult, DockerError
from p11lab.models import ArtifactRef, ProxyBuildIdentityV1, RunSpec


IMAGE = ArtifactRef('docker-local', 'sha256:' + 'a' * 64, 'a' * 64, 'linux/amd64')
CLI_PATH = 'bin/pkcs11-proxy-ng-cli'
SHIM_PATH = 'lib/libpkcs11_proxy_ng_shim.so'


def stub_elf(*, elf_type, tag):
    """Minimal parseable ELF64 fixture bytes (struct-built, no dynamic section)."""
    payload = tag + b'\0' * (64 - len(tag))
    header = (b'\x7fELF' + bytes([2, 1, 1, 0]) + b'\0' * 8
              + struct.pack('<HHIQQQIHHHHHH', elf_type, 62, 1, 0, 64, 0, 0, 64, 56, 1, 0, 0, 0))
    total = 64 + 56 + len(payload)
    return header + struct.pack('<IIQQQQQQ', 1, 5, 0, 0x400000, 0x400000, total, total, 0x1000) + payload


def selected_record(shim_bytes, cli_bytes):
    """Authored explicit-expected record matching fixture bytes (B-style)."""
    base = tls.DEFAULT_PROXY_BUILD_IDENTITY().to_dict()
    empty = {CLI_PATH: {}, 'lib/libpkcs11_proxy_ng_shim.so': {}, 'bin/pkcs11-proxy-ng': {}}
    base.update({
        'source_commit': 'd' * 40, 'source_tree': 'd1' * 20,
        'source_archive': {'sha256': 'd2' * 32, 'size': 111, 'prefix': 'pkcs11-proxy-ng-fixture-d'},
        'source_members': {'count': 7, 'canonical_roster_sha256': 'd3' * 32},
        'cargo_lock_sha256': 'd4' * 32,
        'vendor_packages': [{'identity': 'fixture-a-1.0.0', 'sha256': 'd5' * 32}],
        'daemon': {'path': 'bin/pkcs11-proxy-ng', 'size': 4242, 'mode': 0o755, 'sha256': 'd6' * 32},
        'cli': {'path': CLI_PATH, 'size': len(cli_bytes), 'mode': 0o755,
                'sha256': hashlib.sha256(cli_bytes).hexdigest()},
        'shim': {'path': SHIM_PATH, 'size': len(shim_bytes), 'mode': 0o755,
                 'sha256': hashlib.sha256(shim_bytes).hexdigest()},
        'abi': {'decision': 'conforming-recorded', 'runtime_qualification': 'not-performed',
                'floors': {path: {} for path in empty},
                'needed': {path: [] for path in empty},
                'interpreters': {path: None for path in empty}, 'shim_exports': [],
                'version_requirements': {path: [] for path in empty},
                'symbol_versions': {path: [] for path in empty}},
        'build_context_digest': 'd7' * 32,
        'caller': {'origin': 'local-controller', 'run_id': 'fixture-run-d', 'job_id': 'fixture-job-d'},
        'provider_parent': {'family': 'fixture-provider-d', 'platform': 'linux/amd64',
                            'manifest_digest': 'd8' * 32, 'config_digest': 'd9' * 32},
    })
    return ProxyBuildIdentityV1.from_dict(base).to_dict()


def daemon_claim(record):
    return {'schema_version': 1, 'source_revision': record['source_commit'],
            'cargo_lock_sha256': record['cargo_lock_sha256'],
            'binaries': {'pkcs11-proxy-ng': record['daemon']['sha256'],
                         'pkcs11-proxy-ng-cli': record['cli']['sha256'],
                         'proxy-entrypoint.sh': record['entrypoint_sha256']}}


@pytest.fixture
def client(tmp_path, monkeypatch):
    shim_bytes = stub_elf(elf_type=3, tag=b'lifecycle-shim')
    cli_bytes = stub_elf(elf_type=2, tag=b'lifecycle-cli')
    (tmp_path / 'shim').write_bytes(shim_bytes)
    (tmp_path / 'cli').write_bytes(cli_bytes)
    (tmp_path / 'license').write_bytes(b'fixture-license')
    record = selected_record(shim_bytes, cli_bytes)
    proxy = {'source_revision': record['source_commit'], 'cargo_lock_sha256': record['cargo_lock_sha256'],
             'source_archive_sha256': record['source_archive']['sha256'],
             'shim_sha256': record['shim']['sha256'], 'cli_sha256': record['cli']['sha256']}
    artifact = native.build_native_client_bundle(
        proxy=proxy, shim=tmp_path / 'shim', cli=tmp_path / 'cli',
        licenses={f'share/licenses/proxy-ng/{name}': tmp_path / 'license' for name in ('LICENSE-APACHE', 'LICENSE-MIT')},
        output_dir=tmp_path / 'build', environment='softhsm2', channel='release',
        expected_proxy_identity=ProxyBuildIdentityV1.from_dict(record))
    installed = install_bundle(artifact, tmp_path / 'prefix', environment='softhsm2', channel='release', platform='linux/amd64')
    monkeypatch.setattr(native, 'preflight_native_client', lambda *args, **kwargs: {
        'loader': 'fixture', 'architecture': 'x86_64', 'cli_version': 'fixture', 'closure': {'fixture': {'resolved': {}}}})
    return installed


def spec(tmp_path, client):
    expected = ProxyBuildIdentityV1.from_dict(client.manifest['source']['proxy']['identity'])
    return RunSpec('softhsm2', 'release', 'proxy', IMAGE, 'host', None, client.artifact,
                   ('true',), {'P11LAB_PIN': 'secret-test-pin', 'P11LAB_SO_PIN': 'secret-test-so'},
                   tmp_path / 'output', tmp_path, 0.5, client.prefix, expected_proxy_identity=expected)


def snapshot(root):
    return {str(p.relative_to(root)): p.read_bytes() if p.is_file() else None for p in root.rglob('*')}


@pytest.mark.parametrize('alias', [False, True])
def test_proxy_output_overlap_preserves_installed_prefix(tmp_path, client, monkeypatch, alias):
    class Engine:
        def image(self, artifact):
            return {'Id': artifact.reference}
    monkeypatch.setattr(run, 'Docker', Engine)
    prefix = client.prefix
    if alias:
        prefix = tmp_path / 'alias'
        prefix.symlink_to(client.prefix, target_is_directory=True)
    selected = replace(spec(tmp_path, client), output_dir=prefix / 'new-output')
    before = snapshot(client.prefix)
    with pytest.raises(ValueError, match='overlap'):
        run.run_application(selected)
    assert snapshot(client.prefix) == before


@pytest.mark.parametrize('temporary', [False, True])
def test_proxy_retained_receipt_matches_placement(tmp_path, client, monkeypatch, temporary):
    class Engine:
        def image(self, artifact):
            return {'Id': artifact.reference}
        def create(self, *args):
            return 'fixture'
        def execute(self, *args):
            return CommandResult(1, '', '', False)
        def remove(self, *args):
            pass
    monkeypatch.setattr(run, 'Docker', Engine)
    selected = spec(tmp_path, client)
    if temporary:
        selected = replace(selected, installed_prefix=None)
    result = run.run_application(selected)
    record = json.loads(result.receipt_path.read_text())['proxy']['installation']
    assert record['temporary'] is temporary
    assert record['retained'] is (not temporary)
    assert Path(record['prefix']).exists() is (not temporary)


@pytest.mark.skipif(not hasattr(os, 'mkfifo'), reason='requires FIFO')
@pytest.mark.parametrize('mode', ['direct', 'proxy'])
def test_container_fifo_after_precheck_refuses_without_output(tmp_path, client, monkeypatch, mode):
    import multiprocessing
    fifo = tmp_path / 'fifo'
    os.mkfifo(fifo)
    original = Path.is_file
    # Models replacement after the stat pre-check; opened-fd validation is required.
    monkeypatch.setattr(Path, 'is_file', lambda path: True if path == fifo else original(path))
    class Engine:
        def image(self, artifact):
            return {'Id': artifact.reference, 'Os': 'linux', 'Architecture': 'amd64'}
        def create(self, *args):
            return 'fixture'
        def execute(self, *args):
            record = client.manifest['source']['proxy']['identity']
            return CommandResult(0, json.dumps(daemon_claim(record)), '', False)
        def remove(self, *args):
            pass
    monkeypatch.setattr(run, 'Docker', Engine)
    material = {'server_names': [], 'openssl_version': 'fixture', 'evidence': {'server': {}, 'client': {}}}
    for name in ('ca_cert', 'server_cert', 'server_key', 'client_cert', 'client_key'):
        material[name] = str(tmp_path / name)
    monkeypatch.setattr(tls, 'create_test_tls', lambda *args: material)
    monkeypatch.setattr(tls, 'cert_sha256', lambda *args: 'b' * 64)
    selected = replace(spec(tmp_path, client), inputs={'P11LAB_PIN_FILE': str(fifo)})
    if mode == 'direct':
        selected = replace(selected, mode='direct', execution_location='provider', installed_prefix=None,
                           client_artifact=None, expected_proxy_identity=None)
    def attempt():
        try:
            run.run_application(selected)
        except ValueError as error:
            assert 'regular' in str(error)
            return
        raise AssertionError('FIFO intake reached resource creation')
    process = multiprocessing.get_context('fork').Process(target=attempt)
    process.start()
    process.join(1)
    blocked = process.is_alive()
    if blocked:
        process.terminate()
        process.join(2)
        if process.is_alive():
            process.kill()
            process.join(2)
    assert not blocked, 'credential intake blocked'
    assert process.exitcode == 0
    assert not selected.output_dir.exists()


def test_proxy_failure_diagnostics_use_secret_redactor(tmp_path, client, monkeypatch):
    class Engine:
        def __init__(self):
            self.argv = {}
        def volume(self, name, *args):
            return name
        def image(self, artifact):
            return {'Id': artifact.reference}
        def create(self, image, argv, options, labels, name):
            self.argv[name] = argv
            return name
        def execute(self, identity, *args):
            if self.argv[identity][0] == 'proxy-build':
                record = client.manifest['source']['proxy']['identity']
                return CommandResult(0, json.dumps(daemon_claim(record)), '')
            if self.argv[identity][0] == 'init':
                return CommandResult(0, '', '')
            return CommandResult(2, 'secret-test-pin health', 'secret-test-so TLS failure', False, False, True)
        def command(self, args, **kwargs):
            if args[0] == 'port':
                return CommandResult(0, '127.0.0.1:12345', '')
            if args[0] == 'logs':
                return CommandResult(0, 'secret-test-pin daemon', 'secret-test-so error', False, True, False)
            if args[0] == 'inspect':
                return CommandResult(0, json.dumps({'Running': False, 'ExitCode': 2}), '')
            return CommandResult(0, '', '')
        def stop(self, *args):
            pass
        def remove(self, *args):
            pass
    monkeypatch.setattr(run, 'Docker', Engine)
    monkeypatch.setattr(run, '_create_proxy_network', lambda *args: 'fixture-network')
    result = run.run_application(replace(spec(tmp_path, client), timeout_seconds=1.5))
    assert result.exit_code != 0
    for name in ('proxy-health.stdout.log', 'proxy-health.stderr.log', 'daemon.stdout.log', 'daemon.stderr.log'):
        data = (result.receipt_path.parent / name).read_text()
        assert 'secret-test-pin' not in data and 'secret-test-so' not in data
    receipt = json.loads(result.receipt_path.read_text())
    assert any(stage['phase'] == 'daemon-diagnosis' and stage['stdout_truncated'] for stage in receipt['stages'])


class _LeasedEngine:
    """Fake proxy engine where post-health takes the daemon's state lease.

    Models the provider entrypoint flock: the post-health container fails
    with the lease refusal while the daemon container still exists and
    passes once the daemon has been reaped.
    """

    def __init__(self, manifest, stop_error=False):
        self.manifest = manifest
        self.stop_error = stop_error
        self.argv = {}
        self.removed = []
        self.post_ran_while_live = False

    def volume(self, name, *args):
        return name

    def image(self, artifact):
        return {'Id': artifact.reference}

    def create(self, image, argv, options, labels, name):
        self.argv[name] = argv
        return name

    def execute(self, identity, *args):
        argv = self.argv[identity]
        if argv[0] == 'proxy-build':
            record = self.manifest['source']['proxy']['identity']
            return CommandResult(0, json.dumps(daemon_claim(record)), '')
        if argv == ('health',):
            daemon = next(name for name, seen in self.argv.items() if seen[:1] == ('daemon',))
            if ('container', daemon) not in self.removed:
                self.post_ran_while_live = True
                return CommandResult(1, '', 'p11lab-test: state is unsafe or already in use')
            return CommandResult(0, 'healthy', '')
        return CommandResult(0, 'SERVING' if argv[0] == 'cli' else '', '')

    def command(self, args, **kwargs):
        if args[0] == 'port':
            return CommandResult(0, '127.0.0.1:12345', '')
        if args[0] == 'inspect':
            return CommandResult(0, json.dumps({'Running': not getattr(self, 'stopped', False),
                                               'ExitCode': 0}), '')
        return CommandResult(0, '', '')

    def stop(self, identity, labels):
        if self.stop_error:
            raise DockerError('daemon stop failed')
        self.stopped = True

    def remove(self, kind, identity, labels):
        self.removed.append((kind, identity))
        if self.stop_error and self.argv.get(identity, ())[:1] == ('daemon',):
            raise DockerError('daemon stop failed')


def test_proxy_post_health_runs_after_daemon_stop(tmp_path, client, monkeypatch):
    engine = _LeasedEngine(client.manifest)
    monkeypatch.setattr(run, 'Docker', lambda: engine)
    monkeypatch.setattr(run, '_create_proxy_network', lambda *args: 'fixture-network')
    result = run.run_application(replace(spec(tmp_path, client), timeout_seconds=30))
    assert result.exit_code == 0, result
    assert not result.lifecycle_errors
    assert not result.cleanup_errors
    assert not engine.post_ran_while_live
    receipt = json.loads(result.receipt_path.read_text())
    phases = [stage['phase'] for stage in receipt['stages']]
    assert phases.index('daemon-stop') < phases.index('post-health')
    daemon_removals = [entry for entry in engine.removed if entry[0] == 'container' and
                       engine.argv[entry[1]][:1] == ('daemon',)]
    assert len(daemon_removals) == 1


def test_proxy_daemon_stop_failure_skips_post_health(tmp_path, client, monkeypatch):
    engine = _LeasedEngine(client.manifest, stop_error=True)
    monkeypatch.setattr(run, 'Docker', lambda: engine)
    monkeypatch.setattr(run, '_create_proxy_network', lambda *args: 'fixture-network')
    result = run.run_application(replace(spec(tmp_path, client), timeout_seconds=30))
    assert result.exit_code == 1
    assert result.cleanup_errors[0] == 'daemon stop failed (DockerError)'
    assert len(result.cleanup_errors) == 2  # finally retries the still-owned daemon
    assert not result.lifecycle_errors
    receipt = json.loads(result.receipt_path.read_text())
    assert [stage['phase'] for stage in receipt['stages']].count('post-health') == 0
    assert not (result.receipt_path.parent / 'post-health.stdout.log').exists()
