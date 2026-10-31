"""Owned runner status, preflight and isolation contracts."""
from dataclasses import replace
import json
from pathlib import Path
import signal
import sys

import pytest

from p11lab.models import ArtifactRef, RunSpec
from p11lab import run
from p11lab.docker import CommandResult, DockerError, capture
from p11lab.receipts import write_receipt

IMAGE = ArtifactRef('docker-local', 'sha256:' + 'a' * 64, 'a' * 64, 'linux/amd64')


class Engine:
    def __init__(self, app=0, cleanup=False, death=False):
        self.app, self.cleanup, self.death = app, cleanup, death
        self.created = []
        self.removed = []
        self.operations = []
        self.labels = {}
        self.envfiles = []

    def image(self, artifact):
        return {'Id': artifact.reference, 'Os': 'linux', 'Architecture': 'amd64',
                'Config': {'User': ''}, 'Descriptor': {'digest': artifact.reference, 'mediaType': 'test/index'}}

    def volume(self, name, labels, state_dir=None):
        self.labels[name] = labels
        return name

    def create(self, image, argv, options, labels, name):
        identity = f'container-{len(self.created)}'
        self.created.append((image, argv, options, labels, name))
        self.envfiles.append(Path(options[options.index('--env-file') + 1]).read_text())
        self.labels[identity] = labels
        return identity

    def execute(self, identity, timeout, interrupted):
        argv = self.created[int(identity.split('-')[1])][1]
        self.operations.append(argv)
        if argv[0] == 'exec':
            return CommandResult(self.app, 'caller output', '', self.app == 124)
        if argv[0] == 'health' and self.death and len(self.operations) > 2:
            return CommandResult(1, '', 'service died', False)
        return CommandResult(0, '', '', False)

    def remove(self, kind, identity, labels):
        assert self.labels[identity] == labels
        self.removed.append((kind, identity))
        if self.cleanup:
            raise DockerError('cleanup failed')


@pytest.fixture
def spec(tmp_path):
    return RunSpec('softhsm2', 'release', 'direct', IMAGE, 'provider', None, None,
                   ('printf', '%s', 'literal $(touch bad); spaces'),
                   {'P11LAB_PIN': '1234', 'P11LAB_SO_PIN': '12345678'},
                   tmp_path / 'output', tmp_path, 10)


def execute(monkeypatch, spec, engine):
    monkeypatch.setattr(run, 'Docker', lambda: engine)
    return run.run_application(spec)


@pytest.mark.parametrize('app,cleanup,death,exit_code', [(7, True, False, 7), (0, True, False, 1), (0, False, True, 1), (124, False, False, 124)])
def test_primary_caller_status_and_secondary_failures(monkeypatch, spec, app, cleanup, death, exit_code):
    engine = Engine(app, cleanup, death)
    result = execute(monkeypatch, spec, engine)
    assert result.app_returncode == app
    assert result.exit_code == exit_code
    assert bool(result.cleanup_errors) == cleanup
    assert bool(result.lifecycle_errors) == death
    receipt = json.loads(result.receipt_path.read_text())
    assert receipt['timeout'] == (app == 124)
    assert '12345678' not in result.receipt_path.read_text()
    assert '1234' not in result.receipt_path.read_text()
    assert receipt['artifacts']['provider']['kind'] == 'docker-local'
    assert receipt['artifacts']['consumer'] is None
    assert receipt['artifacts']['client'] is None
    assert receipt['image_observation']['Descriptor']['mediaType'] == 'test/index'


def test_owned_ids_and_literal_argv(monkeypatch, spec):
    engine = Engine()
    result = execute(monkeypatch, spec, engine)
    assert result.exit_code == 0
    assert engine.operations[2] == ('exec', '--', *spec.argv)
    assert len(engine.removed) == 5  # four owned stages plus state
    assert all(identity in engine.labels for _, identity in engine.removed)
    application = engine.created[2]
    assert application[0] == IMAGE.reference
    assert '/workspace' in application[2]
    assert str(spec.cwd) in ' '.join(application[2])
    assert str(spec.output_dir) in ' '.join(application[2])


@pytest.mark.parametrize('changes', [
    {'mode': 'proxy'}, {'mode': 'native'}, {'execution_location': 'host'},
    {'execution_location': 'container', 'consumer_artifact': IMAGE},
    {'consumer_artifact': IMAGE}, {'client_artifact': IMAGE},
    {'artifact': replace(IMAGE, kind='oci-manifest')},
    {'artifact': replace(IMAGE, kind='native-bundle')},
    {'artifact': replace(IMAGE, sha256='b' * 64)},
    {'inputs': {'UNAPPROVED_SECRET': 'bad'}}, {'timeout_seconds': 0},
])
def test_invalid_combinations_fail_before_resources(monkeypatch, spec, changes):
    engine = Engine()
    with pytest.raises(ValueError):
        execute(monkeypatch, replace(spec, **changes), engine)
    assert not engine.created and not engine.labels
    assert not spec.output_dir.exists()


def test_absent_and_empty_are_distinct(monkeypatch, spec):
    engine = Engine()
    spec = replace(spec, inputs={'P11LAB_PIN': ''})
    execute(monkeypatch, spec, engine)
    env = (spec.output_dir / 'receipt.json').read_text()
    assert 'P11LAB_PIN' in env and 'P11LAB_SO_PIN' not in env
    assert 'P11LAB_PIN=\n' in engine.envfiles[0]  # private env file snapshot below


def test_atomic_receipt_replaces_whole_record(tmp_path):
    path = tmp_path / 'receipt.json'
    write_receipt(path, {'complete': False})
    write_receipt(path, {'complete': True})
    assert json.loads(path.read_text()) == {'complete': True}
    assert list(tmp_path.iterdir()) == [path]


def test_atomic_receipt_cleanup_preserves_original_consumer_write_failure(tmp_path, monkeypatch):
    import p11lab.receipts as receipts
    def failed_dump(*args, **kwargs):
        raise ValueError('primary JSON write failure')
    def failed_cleanup(*args, **kwargs):
        raise OSError('secondary temporary cleanup failure')
    monkeypatch.setattr(receipts.json, 'dump', failed_dump)
    monkeypatch.setattr(Path, 'unlink', failed_cleanup)
    path = tmp_path / 'receipt.json'
    with pytest.raises(ValueError, match='primary JSON') as caught:
        write_receipt(path, {'complete': True})
    assert any('secondary temporary' in note for note in caught.value.__notes__)
    assert not path.exists()


@pytest.mark.parametrize('primary', [True, False])
def test_atomic_receipt_directory_close_cannot_mask_primary(tmp_path, monkeypatch, primary):
    import p11lab.receipts as receipts
    import stat
    if sys.platform != 'linux': pytest.skip('directory fsync is Linux-only')
    original_fsync, original_close = receipts.os.fsync, receipts.os.close
    def fsync(fd):
        if primary and stat.S_ISDIR(receipts.os.fstat(fd).st_mode):
            raise OSError('PRIMARY directory fsync failure')
        return original_fsync(fd)
    def close(fd):
        directory = stat.S_ISDIR(receipts.os.fstat(fd).st_mode)
        original_close(fd)
        if directory: raise OSError('SECONDARY directory close failure')
    monkeypatch.setattr(receipts.os, 'fsync', fsync)
    monkeypatch.setattr(receipts.os, 'close', close)
    with pytest.raises(OSError, match='PRIMARY' if primary else 'SECONDARY') as caught:
        write_receipt(tmp_path/'receipt.json', {'complete': True})
    if primary:
        assert any('SECONDARY' in note for note in caught.value.__notes__)


@pytest.mark.parametrize('primary', [True, False])
def test_atomic_receipt_stream_close_cannot_mask_primary(tmp_path, monkeypatch, primary):
    import p11lab.receipts as receipts
    original = receipts.tempfile.NamedTemporaryFile
    class Stream:
        def __init__(self, *args, **kwargs): self.stream = original(*args, **kwargs)
        def __getattr__(self, name): return getattr(self.stream, name)
        def __enter__(self): return self
        def __exit__(self, *args): self.close()
        def close(self):
            self.stream.close()
            raise OSError('SECONDARY stream close failure')
    def failed_dump(*args, **kwargs): raise ValueError('PRIMARY JSON write failure')
    monkeypatch.setattr(receipts.tempfile, 'NamedTemporaryFile', Stream)
    if primary: monkeypatch.setattr(receipts.json, 'dump', failed_dump)
    with pytest.raises((ValueError, OSError), match='PRIMARY' if primary else 'SECONDARY') as caught:
        write_receipt(tmp_path/'receipt.json', {'complete': True})
    if primary:
        assert any('SECONDARY' in note for note in caught.value.__notes__)
    assert not (tmp_path/'receipt.json').exists()


def test_capture_drains_large_output_with_bound():
    result = capture([sys.executable, '-c', 'import sys; sys.stdout.write("x"*200000); sys.stderr.write("y"*200000)'], 5, limit=1024)
    assert result.returncode == 0
    assert len(result.stdout) == len(result.stderr) == 1024
    assert result.stdout_truncated and result.stderr_truncated


def test_capture_timeout_retains_identity():
    result = capture([sys.executable, '-c', 'import time; time.sleep(10)'], .05)
    assert result.timed_out and result.returncode != 0


def test_cli_preserves_argument_boundary(monkeypatch, tmp_path):
    from p11lab.cli import main
    from p11lab.models import RunResult
    seen = []
    def application(spec):
        seen.append(spec)
        return RunResult(7, (), (), 7, tmp_path / 'receipt.json')
    monkeypatch.setattr(run, 'run_application', application)
    result = main(['run', 'softhsm2', '--channel', 'release', '--artifact', IMAGE.reference,
                   '--output-dir', str(tmp_path / 'out'), '--input', 'P11LAB_PIN=',
                   '--', 'my application', '$(literal); argument', '--flag'])
    assert result == 7
    assert seen[0].argv == ('my application', '$(literal); argument', '--flag')
    assert seen[0].inputs == {'P11LAB_PIN': ''}


def test_docker_refuses_unowned_delete():
    from p11lab.docker import Docker
    engine = Docker()
    engine.command = lambda args, **kw: CommandResult(0, json.dumps([{'Id': 'exact', 'Config': {'Labels': {'org.p11lab.run': 'other'}}}]), '')
    with pytest.raises(DockerError, match='ownership'):
        engine.remove('container', 'exact', {'org.p11lab.run': 'ours'})


def test_capture_forwards_interruption_to_owned_process():
    stopped = []
    result = capture([sys.executable, '-c', 'import time; time.sleep(10)'], 5,
                     interrupted=lambda: signal.SIGTERM, on_stop=stopped.append)
    assert not result.timed_out and result.returncode == -signal.SIGTERM
    assert stopped == [signal.SIGTERM]


def test_private_credential_snapshot_is_container_readable(monkeypatch, spec):
    pin = spec.cwd / 'private-pin'
    pin.write_bytes(b'1234')
    pin.chmod(0o600)
    class InspectEngine(Engine):
        def create(self, image, argv, options, labels, name):
            credential_mount = next(v for v in options if v.startswith('type=bind,src=') and 'P11LAB_PIN_FILE' in v)
            source = Path(credential_mount.split('src=', 1)[1].split(',dst=', 1)[0])
            assert source != pin
            assert source.read_bytes() == b'1234'
            assert source.stat().st_mode & 0o004
            assert source.parent.stat().st_mode & 0o077 == 0
            return super().create(image, argv, options, labels, name)
    result = execute(monkeypatch, replace(spec, inputs={'P11LAB_PIN_FILE': str(pin)}), InspectEngine())
    assert result.exit_code == 0
    assert pin.stat().st_mode & 0o777 == 0o600


def test_caller_uid_and_owned_state_bind(monkeypatch, spec):
    import os
    class OwnershipEngine(Engine):
        def volume(self, name, labels, state_dir=None):
            assert state_dir.is_dir()
            assert state_dir.stat().st_mode & 0o077 == 0
            self.state_dir = state_dir
            return super().volume(name, labels)
    engine = OwnershipEngine()
    result = execute(monkeypatch, spec, engine)
    options = engine.created[2][2]
    assert options[options.index('--user') + 1] == f'{os.getuid()}:{os.getgid()}'
    assert not engine.state_dir.exists()
    assert json.loads(result.receipt_path.read_text())['execution']['uid_gid'] == f'{os.getuid()}:{os.getgid()}'


def test_control_tmpfs_uses_caller_permissions(monkeypatch, spec):
    import os
    engine = Engine()
    execute(monkeypatch, spec, engine)
    assert f'/run/p11lab:rw,nosuid,nodev,uid={os.getuid()},gid={os.getgid()},mode=0700' in engine.created[0][2]


@pytest.mark.parametrize('endpoint', ['ssh://other-host', 'tcp://127.0.0.1:2375', 'tcp://other-host:2376'])
def test_remote_daemon_rejected_before_image_or_resource_lookup(endpoint):
    from p11lab.docker import Docker
    engine = Docker()
    engine.env = {'DOCKER_HOST': endpoint}
    engine.command = lambda *a, **kw: pytest.fail('remote endpoint must reject before commands')
    with pytest.raises(DockerError, match='local Unix'):
        engine.image(IMAGE)


def test_named_volume_does_not_copy_image_directory_ownership(monkeypatch, spec):
    engine = Engine()
    execute(monkeypatch, spec, engine)
    state_mount = next(v for v in engine.created[0][2] if v.startswith('type=volume'))
    assert 'volume-nocopy' in state_mount


def test_secret_prefix_at_output_bound_is_redacted(monkeypatch, spec):
    from dataclasses import replace
    class TruncatedEngine(Engine):
        def execute(self, identity, timeout, interrupted):
            result = super().execute(identity, timeout, interrupted)
            if self.operations[-1][0] == 'exec':
                return replace(result, stdout='public output:' + 'private-creden', stdout_truncated=True)
            return result
    spec = replace(spec, inputs={'P11LAB_PIN': 'private-credential'})
    result = execute(monkeypatch, spec, TruncatedEngine())
    assert result.exit_code == 0
    assert 'private-' not in (spec.output_dir / 'application.stdout.log').read_text()


def test_native_exit_124_is_not_timeout(monkeypatch, spec):
    class NativeExitEngine(Engine):
        def execute(self, identity, timeout, interrupted):
            result = super().execute(identity, timeout, interrupted)
            return replace(result, timed_out=False)
    result = execute(monkeypatch, spec, NativeExitEngine(app=124))
    assert result.exit_code == 124
    assert not json.loads(result.receipt_path.read_text())['timeout']


def test_created_container_is_owned_when_creation_readback_fails(monkeypatch, spec):
    class FailingCreateEngine(Engine):
        def create(self, *args):
            identity = super().create(*args)
            raise DockerError('creation CLI failed after resource creation', resource=('container', identity))
    engine = FailingCreateEngine()
    result = execute(monkeypatch, spec, engine)
    assert result.exit_code == 1 and result.app_returncode is None
    assert ('container', 'container-0') in engine.removed
    assert not result.cleanup_errors


def test_docker_recovers_exact_created_id_after_cli_failure():
    from p11lab.docker import Docker
    engine = Docker()
    identity = 'a' * 64
    labels = {'org.p11lab.run': 'owned'}
    def command(args, **kwargs):
        if args[0] == 'create':
            raise DockerError('CLI failed')
        return CommandResult(0, json.dumps([{'Id': identity, 'Name': '/owned-name', 'Config': {'Labels': labels}}]), '')
    engine.command = command
    with pytest.raises(DockerError) as caught:
        engine.create(IMAGE.reference, ('init',), [], labels, 'owned-name')
    assert caught.value.resource == ('container', identity)


def test_creation_readback_never_adopts_other_owners_resource():
    from p11lab.docker import Docker
    engine = Docker()
    def command(args, **kwargs):
        if args[0] == 'create':
            raise DockerError('CLI failed')
        return CommandResult(0, json.dumps([{'Id': 'a' * 64, 'Name': '/nonce', 'Config': {'Labels': {'org.p11lab.run': 'other'}}}]), '')
    engine.command = command
    with pytest.raises(DockerError) as caught:
        engine.create(IMAGE.reference, ('init',), [], {'org.p11lab.run': 'ours'}, 'nonce')
    assert caught.value.resource is None
    assert caught.value.uncertain_resource == ('container', 'nonce')


def test_unknown_creation_is_explicit_and_retains_backing_state(monkeypatch, spec):
    class UnknownEngine(Engine):
        def create(self, *args):
            raise DockerError('creation outcome unavailable', uncertain_resource=('container', 'our-nonce'))
    result = execute(monkeypatch, spec, UnknownEngine())
    receipt = json.loads(result.receipt_path.read_text())
    assert result.exit_code == 1 and result.cleanup_errors
    assert receipt['uncertain_resources'] == [{'kind': 'container', 'name': 'our-nonce'}]
    assert receipt['state']['owned_directory_retained']
    # The fake engine created no actual Docker resource; remove only its known
    # empty test directory after checking the production retention contract.
    Path(receipt['state']['owned_directory']).rmdir()


@pytest.mark.parametrize('app,expected', [(7, 7), (0, 124)])
def test_completed_application_status_survives_post_health_timeout(monkeypatch, spec, app, expected):
    class PostTimeoutEngine(Engine):
        def execute(self, identity, timeout, interrupted):
            result = super().execute(identity, timeout, interrupted)
            if len(self.operations) == 4:
                return replace(result, returncode=124, timed_out=True)
            return result
    result = execute(monkeypatch, spec, PostTimeoutEngine(app=app))
    receipt = json.loads(result.receipt_path.read_text())
    assert result.app_returncode == app
    assert result.exit_code == expected
    assert receipt['timeout'] and receipt['interrupted_signal'] is None
    assert result.lifecycle_errors == ('post-health failed',)
    assert not result.cleanup_errors


@pytest.mark.parametrize('app,expected', [(7, 7), (0, 143)])
@pytest.mark.parametrize('phase', ['post-health', 'cleanup'])
def test_completed_application_status_survives_later_signal(monkeypatch, spec, app, expected, phase):
    class PostSignalEngine(Engine):
        def execute(self, identity, timeout, interrupted):
            result = super().execute(identity, timeout, interrupted)
            if phase == 'post-health' and len(self.operations) == 4:
                # Invoke the installed handler at the lifecycle boundary;
                # the completed application status must stay primary.
                signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
                return replace(result, returncode=143)
            return result

        def remove(self, kind, identity, labels):
            if phase == 'cleanup':
                signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
            return super().remove(kind, identity, labels)
    result = execute(monkeypatch, spec, PostSignalEngine(app=app))
    receipt = json.loads(result.receipt_path.read_text())
    assert result.app_returncode == app
    assert result.exit_code == expected
    assert receipt['interrupted_signal'] == signal.SIGTERM and not receipt['timeout']
    assert not result.cleanup_errors


@pytest.mark.parametrize('timed_out,signum,expected', [(True, None, 124), (False, signal.SIGTERM, 143)])
def test_known_attach_outcome_survives_unavailable_status(monkeypatch, spec, timed_out, signum, expected):
    from p11lab.docker import Docker
    class UnavailableStatusEngine(Engine):
        def command(self, args, *a, **kwargs):
            if args[0] == 'start':
                if signum:
                    signal.getsignal(signum)(signum, None)
                return CommandResult(-15, 'drained application output', '', timed_out)
            raise DockerError('status inspect unavailable')

        def execute(self, identity, timeout, interrupted):
            argv = self.created[int(identity.split('-')[1])][1]
            if argv[0] == 'exec':
                self.operations.append(argv)
                return Docker.execute(self, identity, timeout, interrupted)
            return super().execute(identity, timeout, interrupted)
    result = execute(monkeypatch, spec, UnavailableStatusEngine())
    receipt = json.loads(result.receipt_path.read_text())
    assert result.app_returncode == result.exit_code == expected
    assert receipt['timeout'] == timed_out
    assert receipt['interrupted_signal'] == signum
    assert not result.cleanup_errors
    assert (spec.output_dir / 'application.stdout.log').read_text() == 'drained application output'


@pytest.mark.parametrize('app,expected', [(7, 7), (0, 143)])
def test_completed_application_status_survives_signal_while_saving_output(monkeypatch, spec, app, expected):
    original = run._write_stage_log
    def write(path, text):
        if path.name == 'application.stdout.log':
            signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
        return original(path, text)
    monkeypatch.setattr(run, '_write_stage_log', write)
    result = execute(monkeypatch, spec, Engine(app=app))
    receipt = json.loads(result.receipt_path.read_text())
    assert result.app_returncode == app and result.exit_code == expected
    assert receipt['app_completed'] and receipt['interrupted_signal'] == signal.SIGTERM


def test_bind_mounts_roundtrip_literal_quotes_through_docker_csv(monkeypatch, spec, tmp_path):
    """Docker consumes CSV inside each argv element, including source quotes."""
    import csv
    import io
    selected = {}
    for kind in ('cwd', 'output', 'state'):
        path = tmp_path / (kind + ' space \'";$()')
        if kind != 'output':
            path.mkdir()
        selected[kind] = path
    scoped = replace(spec, cwd=selected['cwd'], output_dir=selected['output'],
                     inputs={'P11LAB_STATE_DIR': str(selected['state'])})
    engine = Engine()
    assert execute(monkeypatch, scoped, engine).exit_code == 0
    options = engine.created[2][2]
    mounts = []
    for index, word in enumerate(options):
        if word == '--mount':
            encoded = options[index + 1]
            # Python csv.reader permits bare quotes in unquoted fields even
            # with strict=True; Docker's Go reader rejects that RFC-invalid form.
            import re
            field = r'(?:[^,"\r\n]*|"(?:[^"]|"")*")'
            assert re.fullmatch(field + '(?:,' + field + ')*', encoded)
            fields = next(csv.reader(io.StringIO(encoded), strict=True))
            mounts.append(dict(field.split('=', 1) for field in fields if '=' in field))
    assert {'type': 'bind', 'src': str(selected['cwd']), 'dst': '/workspace'} in mounts
    assert {'type': 'bind', 'src': str(selected['output']), 'dst': '/p11lab-output'} in mounts
    assert {'type': 'bind', 'src': str(selected['state']), 'dst': '/var/lib/p11lab'} in mounts


@pytest.mark.parametrize('log_name', ['application.stdout.log', 'application.stderr.log', 'post-health.stdout.log', 'post-health.stderr.log'])
@pytest.mark.parametrize('link_kind', ['symlink', 'hardlink'])
@pytest.mark.parametrize('application_code', [0, 37])
def test_application_cannot_redirect_controller_logs_outside_output(monkeypatch, spec, tmp_path, log_name, link_kind, application_code):
    import os
    sentinel = tmp_path / 'outside-control-sentinel'
    original = b'preserve outside host control bytes'
    sentinel.write_bytes(original)
    class LinkedLogEngine(Engine):
        def execute(self, identity, timeout, interrupted):
            argv = self.created[int(identity.split('-')[1])][1]
            if argv[0] == 'exec':
                path = spec.output_dir / log_name
                if link_kind == 'symlink':
                    path.symlink_to(sentinel)
                else:
                    os.link(sentinel, path)
            return super().execute(identity, timeout, interrupted)
    engine = LinkedLogEngine(app=application_code)
    try:
        result = execute(monkeypatch, spec, engine)
        assert sentinel.read_bytes() == original
        assert result.exit_code == (1 if application_code == 0 else 37)
        assert any("evidence incomplete" in error for error in result.lifecycle_errors)
        assert not result.cleanup_errors
        assert len(engine.removed) == len(engine.created) + 1
    finally:
        # The deliberately vulnerable red run must not leave even this
        # disposable external control changed after observing the failure.
        sentinel.write_bytes(original)
