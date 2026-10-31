"""Required bounded-direct-run controls and hostile output readback."""
import io
import json
from pathlib import Path
import tarfile

import pytest

from p11lab import models, run
from p11lab.models import ArtifactRef, RunSpec
from p11lab.run import run_application


def test_bounded_contract_is_available():
    assert hasattr(models, 'BoundedRunPolicy')


@pytest.fixture(autouse=True)
def contract(request):
    if request.node.name != 'test_bounded_contract_is_available' and not hasattr(models, 'BoundedRunPolicy'):
        pytest.skip('bounded contract not implemented yet')


IMAGE = ArtifactRef('docker-local', 'sha256:' + 'a' * 64, 'a' * 64, 'linux/amd64')


def archive(name, payload=b'x', kind=tarfile.REGTYPE):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w') as tar:
        item = tarfile.TarInfo(name)
        item.type = kind
        item.size = len(payload) if kind == tarfile.REGTYPE else 0
        if kind == tarfile.SYMTYPE:
            item.linkname = '/etc/passwd'
        tar.addfile(item, io.BytesIO(payload) if item.size else None)
    return buffer.getvalue()


@pytest.mark.parametrize('name,kind', [('../escape', tarfile.REGTYPE), ('link', tarfile.SYMTYPE)])
def test_unsafe_output_is_refused_before_writing(tmp_path, name, kind):
    from p11lab.bounded_run import retain_output
    with pytest.raises(ValueError):
        retain_output(archive(name, kind=kind), tmp_path, 1024, 10)
    assert list(tmp_path.iterdir()) == []


def test_output_cannot_overwrite_controller_log(tmp_path):
    from p11lab.bounded_run import retain_output
    log = tmp_path / 'application.stdout.log'
    log.write_text('original')
    with pytest.raises(ValueError, match='collision'):
        retain_output(archive(log.name), tmp_path, 1024, 10)
    assert log.read_text() == 'original'


def test_credential_in_original_is_private_and_blocks_retention(tmp_path, monkeypatch):
    from p11lab.bounded_run import CredentialTaintError, retain_scanned_output
    import tempfile
    secret = b'p11lab-test-credential-78c8bde1'
    raw = archive('candidate.txt', b'prefix ' + secret + b' suffix')
    output = tmp_path / 'public'
    output.mkdir()
    # A caller-controlled temporary directory must not put the private raw
    # original inside the output tree that a caller could later share.
    monkeypatch.setattr(tempfile, 'tempdir', str(output))
    record = {}
    with pytest.raises(CredentialTaintError, match='credential'):
        retain_scanned_output(raw, output, 1024 * 1024, 100, [secret], record)
    assert not list(output.iterdir())
    assert record['tainted'] is True
    private = Path(record['private_original'])
    try:
        assert not private.is_relative_to(output)
        assert private.read_bytes() == raw and private.stat().st_mode & 0o777 == 0o600
        assert private.parent.stat().st_mode & 0o777 == 0o700
    finally:
        private.unlink(missing_ok=True)
        private.parent.rmdir()


def test_clean_original_is_retained_without_rewriting(tmp_path):
    from p11lab.bounded_run import retain_scanned_output
    raw = archive('candidate.txt', b'public observation')
    record = {}
    retain_scanned_output(raw, tmp_path, 1024 * 1024, 100, [b'not-present'], record)
    assert (tmp_path / 'bounded-output.tar').read_bytes() == raw
    assert (tmp_path / 'candidate.txt').read_bytes() == b'public observation'
    assert record['tainted'] is False


@pytest.mark.parametrize('stream', ['stdout', 'stderr'])
@pytest.mark.parametrize('phase', ['init', 'ready', 'application', 'post-health'])
@pytest.mark.parametrize('failure,app_code', [('none', 0), ('readback', 7), ('runtime', 7), ('log', 7)])
def test_stream_only_credential_taint_survives_clean_or_failed_readback(
        tmp_path, monkeypatch, stream, phase, failure, app_code):
    from p11lab import bounded_run
    from p11lab.docker import CommandResult
    from p11lab.image_validation import reject_tainted_run
    from p11lab.round_core import worker
    from test_run_failures import Engine

    secret = 'private-test-pin-8426'
    pin = tmp_path / 'pin'
    pin.write_text(secret)
    spec = RunSpec('softhsm2', 'release', 'direct', IMAGE, 'provider', None, None,
                   ('true',), {'P11LAB_PIN_FILE': str(pin)}, tmp_path / 'out', tmp_path, 10,
                   bounded=models.BoundedRunPolicy())

    class FakeEngine(Engine):
        def __init__(self):
            super().__init__(app=app_code)

        def command(self, args):
            return CommandResult(0, json.dumps([{'Id': args[-1], 'Image': IMAGE.reference,
                                                 'HostConfig': {}, 'Mounts': []}]), '')

        def execute(self, identity, timeout, interrupted):
            result = super().execute(identity, timeout, interrupted)
            current = ('init', 'ready', 'application', 'post-health')[len(self.operations) - 1]
            if current == phase:
                return CommandResult(app_code if current == 'application' else 0,
                                     secret if stream == 'stdout' else '', secret if stream == 'stderr' else '')
            return result

    class Storage:
        def __init__(self, name, record):
            self.volume = name
            self.record = record
        def close(self):
            return []

    def read_output(storage, output, interrupted, credentials):
        if failure == 'readback':
            raise ValueError('readback failed')
        if failure == 'runtime':
            raise RuntimeError('readback failed')
        storage.record['readback'] = {'tainted': False}
        (output / 'bounded-output.tar').write_bytes(b'clean archive')

    monkeypatch.setattr(run, 'Docker', FakeEngine)
    monkeypatch.setattr(bounded_run, 'open_storage', lambda engine, labels, name, size, record: Storage(name, record))
    monkeypatch.setattr(bounded_run, 'verify_container', lambda *args: None)
    monkeypatch.setattr(bounded_run, 'read_output', read_output)
    monkeypatch.setattr(worker, '_inspection', lambda *args: {'State': {'Running': False}})
    if failure == 'log':
        write = run._write_stage_log
        def fail_log(path, text):
            if path.name == phase + '.stdout.log':
                raise OSError('stage log unavailable')
            return write(path, text)
        monkeypatch.setattr(run, '_write_stage_log', fail_log)
    result = run_application(spec)
    expected_app = None if failure == 'log' and phase in ('init', 'ready') else app_code
    assert result.app_returncode == expected_app
    assert result.exit_code == (expected_app or 1)
    with pytest.raises(bounded_run.CredentialTaintError):
        reject_tainted_run(result.receipt_path)
    log = spec.output_dir / (phase + '.' + stream + '.log')
    assert not log.exists() or secret not in log.read_text()
    assert secret not in result.receipt_path.read_text()
    receipt = json.loads(result.receipt_path.read_text())
    assert all('fixed_validation_observation' not in row
               for row in receipt['bounded_execution']['stages'].values())
    private = Path(receipt['bounded_execution']['stages'][phase]['private_captured_streams'][stream])
    try:
        assert private.read_text() == secret
        assert private.stat().st_mode & 0o777 == 0o600
        assert private.parent.stat().st_mode & 0o777 == 0o700
        assert not private.is_relative_to(spec.output_dir)
    finally:
        private.unlink()
        private.parent.rmdir()


@pytest.mark.parametrize('phase,prior_exposure', [('init', False), ('application', False),
                                                   ('post-health', False), ('post-health', True)])
@pytest.mark.parametrize('error_type', ['DockerError', 'RuntimeError'])
@pytest.mark.parametrize('receipt_failure', [False, True])
@pytest.mark.parametrize('secret', ['credential-in-exception-c7fc2', 'RuntimeError', ':'])
@pytest.mark.parametrize('cleanup_failure', [False, True])
def test_failed_execute_marks_stream_unavailable_and_blocks_export(
        tmp_path, monkeypatch, phase, prior_exposure, error_type, receipt_failure, secret, cleanup_failure):
    from p11lab import bounded_run
    from p11lab.docker import CommandResult, DockerError
    from p11lab.image_validation import reject_tainted_run
    from test_run_failures import Engine

    pin = tmp_path / 'pin'
    pin.write_text(secret)
    spec = RunSpec('softhsm2', 'release', 'direct', IMAGE, 'provider', None, None,
                   ('true',), {'P11LAB_PIN_FILE': str(pin)}, tmp_path / 'out', tmp_path, 10,
                   bounded=models.BoundedRunPolicy())

    class FakeEngine(Engine):
        def __init__(self):
            super().__init__(app=7)

        def command(self, args):
            return CommandResult(0, json.dumps([{'Id': args[-1], 'Image': IMAGE.reference,
                                                 'HostConfig': {}, 'Mounts': []}]), '')

        def execute(self, identity, timeout, interrupted):
            current = ('init', 'ready', 'application', 'post-health')[int(identity.split('-')[1])]
            if current == phase:
                raise (DockerError if error_type == 'DockerError' else RuntimeError)('failure ' + secret)
            if current == 'init' and prior_exposure:
                return CommandResult(0, secret, '')
            return super().execute(identity, timeout, interrupted)

        def remove(self, kind, identity, labels):
            if cleanup_failure:
                raise RuntimeError('cleanup failure ' + secret)
            return super().remove(kind, identity, labels)

    class Storage:
        def __init__(self, name):
            self.volume = name
        def close(self):
            if cleanup_failure:
                raise RuntimeError('storage cleanup failure ' + secret)
            return []

    monkeypatch.setattr(run, 'Docker', FakeEngine)
    monkeypatch.setattr(bounded_run, 'open_storage', lambda engine, labels, name, size, record: Storage(name))
    monkeypatch.setattr(bounded_run, 'verify_container', lambda *args: None)
    if secret == ':':
        with pytest.raises(Exception) as error:
            run_application(spec)
        assert type(error.value).__name__ == ('CredentialTaintError' if prior_exposure else 'CaptureUnavailableError')
        assert secret not in str(error.value)
        assert not (spec.output_dir / 'receipt.json').exists()
        return
    if receipt_failure:
        def fail_receipt(*args):
            raise OSError('receipt failure ' + secret)
        monkeypatch.setattr(run, 'write_receipt', fail_receipt)
        with pytest.raises(Exception) as error:
            run_application(spec)
        assert type(error.value).__name__ == ('CredentialTaintError' if prior_exposure else 'CaptureUnavailableError')
        if not prior_exposure and error_type != secret:
            assert phase in str(error.value) and error_type in str(error.value)
        assert secret not in str(error.value)
        assert not (spec.output_dir / 'receipt.json').exists()
        return
    result = run_application(spec)
    receipt = json.loads(result.receipt_path.read_text())
    expected_app = 7 if phase == 'post-health' else None
    assert result.app_returncode == expected_app and result.exit_code == (expected_app or 1)
    assert bool(result.cleanup_errors) is cleanup_failure
    assert secret not in str(result.cleanup_errors) and secret not in str(result.lifecycle_errors)
    if cleanup_failure:
        assert any('container cleanup failed' in item for item in result.cleanup_errors)
        assert any('storage cleanup failed' in item for item in result.cleanup_errors)
    assert receipt['bounded_execution']['stream_capture_unavailable'] is True
    assert receipt['bounded_execution']['stream_capture_phase'] == phase
    if error_type == secret:
        assert receipt['bounded_execution']['stream_capture_error'] != error_type
    else:
        assert receipt['bounded_execution']['stream_capture_error'] == error_type
    assert (receipt['bounded_execution'].get('stream_tainted') is True) == prior_exposure
    if error_type != secret:
        assert error_type in str(receipt['lifecycle_errors'])
    assert secret not in result.receipt_path.read_text()
    assert not (spec.output_dir / (phase + '.stdout.log')).exists()
    with pytest.raises(Exception) as error:
        reject_tainted_run(result.receipt_path)
    assert type(error.value).__name__ == ('CredentialTaintError' if prior_exposure else 'CaptureUnavailableError')
    if prior_exposure:
        private = Path(receipt['bounded_execution']['stages']['init']['private_captured_streams']['stdout'])
        private.unlink()
        private.parent.rmdir()


def test_unbounded_execute_runtime_error_keeps_default_behavior(tmp_path, monkeypatch):
    from test_run_failures import Engine

    class FakeEngine(Engine):
        def execute(self, identity, timeout, interrupted):
            raise RuntimeError('default failure')

    monkeypatch.setattr(run, 'Docker', FakeEngine)
    spec = RunSpec('softhsm2', 'release', 'direct', IMAGE, 'provider', None, None,
                   ('true',), {}, tmp_path / 'out', tmp_path, 10)
    with pytest.raises(RuntimeError, match='default failure'):
        run_application(spec)
    assert not (spec.output_dir / 'receipt.json').exists()


def test_credential_in_inspection_metadata_is_redacted():
    secret = 'p11lab-test-credential-78c8bde1'
    record = {'host': {'mounts': [{'Source': '/tmp/' + secret + '/pin'}]}}
    sanitized = run.redact_record(record, [secret])
    assert secret not in str(sanitized)
    assert '[REDACTED]' in sanitized['host']['mounts'][0]['Source']
    numeric = run.redact_record({'bytes': 12345}, ['234'])
    assert '234' not in str(numeric)
    marker_secret = 'REDACTED'
    assert marker_secret not in run.redact_text('value ' + marker_secret, False, [marker_secret], safe_marker=True)
    assert marker_secret not in str(run.redact_record({'number': 12345}, [marker_secret, '234']))
    with pytest.raises(ValueError, match='metadata'):
        run.safe_metadata({'value': 1}, [':'])


def test_bounded_policy_rejects_unsupported_route_before_resources(tmp_path):
    spec = RunSpec('softhsm2', 'release', 'native', IMAGE, 'host', None, None,
                   ('true',), {}, tmp_path / 'out', tmp_path, 10,
                   bounded=models.BoundedRunPolicy())
    with pytest.raises(ValueError, match='bounded'):
        run_application(spec)
    assert not spec.output_dir.exists()


def test_bounded_policy_rejects_caller_state_before_resources(tmp_path):
    spec = RunSpec('softhsm2', 'release', 'direct', IMAGE, 'provider', None, None,
                   ('true',), {'P11LAB_STATE_DIR': str(tmp_path)}, tmp_path / 'out',
                   tmp_path, 10, bounded=models.BoundedRunPolicy())
    with pytest.raises(ValueError, match='bounded'):
        run_application(spec)
    assert not spec.output_dir.exists()


@pytest.mark.parametrize('identity', ['getuid', 'geteuid'])
def test_root_caller_is_refused_before_bounded_resources(tmp_path, monkeypatch, identity):
    monkeypatch.setattr('os.' + identity, lambda: 0)
    spec = RunSpec('softhsm2', 'release', 'direct', IMAGE, 'provider', None, None,
                   ('true',), {}, tmp_path / 'out', tmp_path, 10, bounded=models.BoundedRunPolicy())
    monkeypatch.setattr(run, 'Docker', lambda: pytest.fail('Docker must not be reached'))
    with pytest.raises(ValueError, match='nonroot'):
        run_application(spec)
    assert not spec.output_dir.exists()


def test_actual_container_memory_drift_is_rejected():
    from p11lab.bounded_run import verify_container
    inspection = {'Id': 'a', 'Image': 'image', 'State': {'Running': False, 'Pid': 0},
                  'Config': {'User': '1:1', 'Labels': {'owner': 'x'}},
                  'HostConfig': {'Memory': 1, 'MemorySwap': 1, 'PidsLimit': 128}}
    with pytest.raises(ValueError, match='boundary'):
        verify_container(inspection, 'a', 'image', {'owner': 'x'}, models.BoundedRunPolicy(), '1:1', [], ['init'], ['/provider'])


def test_actual_container_matching_boundary_is_admitted():
    from p11lab.bounded_run import verify_container
    policy = models.BoundedRunPolicy()
    inspection = {'Id': 'a', 'Image': 'image', 'State': {'Running': False, 'Pid': 0},
                  'Config': {'User': '1:1', 'Labels': {'owner': 'x'}, 'Cmd': ['init'], 'Entrypoint': ['/provider']},
                  'Mounts': [], 'HostConfig': {
                      'Memory': policy.memory_bytes, 'MemorySwap': policy.memory_bytes,
                      'PidsLimit': policy.pids, 'NanoCpus': 1_000_000_000,
                      'ReadonlyRootfs': True, 'NetworkMode': 'none', 'CapDrop': ['ALL'],
                      'CapAdd': None, 'SecurityOpt': ['no-new-privileges=true'],
                      'Privileged': False, 'PidMode': '', 'IpcMode': 'private', 'Tmpfs': {
                          '/tmp': f'rw,nosuid,nodev,size={policy.tmp_bytes},nr_inodes={policy.inodes}',
                          '/dev/shm': f'rw,nosuid,nodev,size={policy.run_bytes},nr_inodes={policy.inodes},mode=1777',
                          '/run/p11lab': f'rw,nosuid,nodev,uid=1,gid=1,mode=0700,size={policy.run_bytes},nr_inodes={policy.inodes}'}}}
    verify_container(inspection, 'a', 'image', {'owner': 'x'}, policy, '1:1', [], ['init'], ['/provider'])
    inspection['Config']['Cmd'] = ['health']
    with pytest.raises(ValueError, match='boundary'):
        verify_container(inspection, 'a', 'image', {'owner': 'x'}, policy, '1:1', [], ['init'], ['/provider'])


def test_actual_kernel_tmpfs_stat_is_checked():
    from p11lab.bounded_run import check_tmpfs_stat
    check_tmpfs_stat('tmpfs 4096 16384 10000', 64 * 1024 * 1024)
    with pytest.raises(ValueError, match='quota'):
        check_tmpfs_stat('tmpfs 4096 16384 9999', 64 * 1024 * 1024)


def test_fixed_validation_command_observation_uses_inspection_and_blocks_secrets():
    from p11lab.bounded_run import (CredentialTaintError, fixed_validation_command,
                                    fixed_validation_observation)

    command = fixed_validation_command('consumer', 'application')
    config = {'Cmd': command, 'Entrypoint': ['/usr/local/bin/p11lab-provider'], 'User': '1001:1001'}
    observed = fixed_validation_observation(config, 'consumer', 'application', '1001:1001', ['private-pin'])
    assert observed['user'] == '1001:1001'
    assert len(observed['command_sha256']) == 64
    assert '/usr/local/bin/p11lab-provider' not in json.dumps(observed)
    with pytest.raises(ValueError, match='fixed validation'):
        fixed_validation_observation(config | {'Cmd': ['exec', '--', 'unexpected']},
                                     'consumer', 'application', '1001:1001', [])
    with pytest.raises(ValueError, match='fixed validation'):
        fixed_validation_observation(config | {'User': '0:0'}, 'consumer', 'application', '1001:1001', [])
    with pytest.raises(CredentialTaintError):
        fixed_validation_observation(config | {'Entrypoint': ['/private-pin']},
                                     'consumer', 'application', '1001:1001', ['private-pin'])
    with pytest.raises(CredentialTaintError):
        fixed_validation_observation(config, 'consumer', 'application', '1001:1001', ['p11lab-smoke'])
    with pytest.raises(CredentialTaintError):
        fixed_validation_observation(config | {'Entrypoint': ['/secret\nvalue']},
                                     'consumer', 'application', '1001:1001', ['secret\nvalue'])
    changed = fixed_validation_observation(config | {'Entrypoint': ['/alternate']},
                                           'consumer', 'application', '1001:1001', [])
    assert changed['command_sha256'] != observed['command_sha256']


def test_fixed_validation_observation_is_opt_in_and_rejects_unknown_role():
    from p11lab.bounded_run import fixed_validation_command

    assert models.RunSpec.__dataclass_fields__['fixed_validation'].default is None
    with pytest.raises(ValueError, match='fixed validation'):
        fixed_validation_command('unreviewed', 'application')


@pytest.mark.parametrize('role,argv,bounded', [
    ('consumer', ('unrelated',), models.BoundedRunPolicy()),
    ('checker', ('unrelated',), models.BoundedRunPolicy()),
    ('consumer', ('unrelated',), None),
    ('other', ('unrelated',), models.BoundedRunPolicy()),
])
def test_fixed_validation_rejects_unbounded_or_unlisted_commands_before_resources(tmp_path, role, argv, bounded):
    spec = RunSpec('softhsm2', 'release', 'direct', IMAGE, 'provider', None, None,
                   argv, {}, tmp_path / 'out', tmp_path, 10, bounded=bounded, fixed_validation=role)
    with pytest.raises(ValueError, match='fixed validation'):
        run_application(spec)
    assert not spec.output_dir.exists()
