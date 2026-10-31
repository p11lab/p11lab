"""Owned direct/provider lifecycle. Future transports use the same RunResult."""
from dataclasses import asdict
import csv
import io
from pathlib import Path
import json
import re
import os
import shutil
import signal
import tempfile
import threading
import time
from typing import Any
from uuid import uuid4

from .catalog import load_environment
from .docker import Docker, DockerError
from .models import ProxyBuildIdentityV1, RunSpec, RunResult
from .proxy_derivative import load_parent_selection, verify_derivative_parent
from .receipts import write_receipt
from .secrets import snapshot_credentials
from .process import supervised_exec, bounded_redacted


def _validate(spec):
    descriptor = load_environment(spec.environment, spec.channel)
    if descriptor['channel_spec']['status'] != 'locked':
        raise ValueError('run requires an implemented locked provider channel')
    if spec.mode != 'direct' or spec.execution_location != 'provider':
        raise ValueError('only direct/provider execution is available')
    if spec.consumer_artifact is not None or spec.client_artifact is not None:
        raise ValueError('direct/provider cannot use separate consumer/client artifacts; select a derivative via artifact')
    artifact = spec.artifact
    if (artifact.kind != 'docker-local' or not re.fullmatch(r'sha256:[0-9a-f]{64}', artifact.reference)
            or artifact.sha256 != artifact.reference.removeprefix('sha256:')
            or artifact.platform not in descriptor['runtime_platforms']):
        raise ValueError('direct/provider requires an exact supported docker-local engine image ID')
    if not spec.argv or any(not isinstance(a, str) or '\0' in a for a in spec.argv):
        raise ValueError('application requires literal argv without NUL bytes')
    if spec.timeout_seconds <= 0 or not spec.cwd.is_dir():
        raise ValueError('positive timeout and existing caller cwd are required')
    unknown = set(spec.inputs) - set(descriptor['inputs']) - {'P11LAB_STATE_DIR'}
    if unknown or any(not isinstance(v, str) or '\n' in v or '\r' in v or '\0' in v for v in spec.inputs.values()):
        raise ValueError('inputs must be allowlisted single-line strings')
    for key, value in spec.inputs.items():
        if key.endswith('_FILE') and not Path(value).is_file():
            raise ValueError('credential input file must be readable')
        if key == 'P11LAB_STATE_DIR' and not Path(value).is_dir():
            raise ValueError('explicit persistent state directory must already exist')
    if spec.output_dir.exists():
        raise ValueError('output directory must be a fresh attempt directory')
    for key in spec.inputs:
        if key.endswith('_FILE') and key.removesuffix('_FILE') in spec.inputs:
            raise ValueError('conflicting scalar/file credential inputs')
    return descriptor


def _safe_redaction_marker(secrets):
    used = set(''.join(secrets))
    if not used.intersection('[REDACTED]'):
        return '[REDACTED]'
    for codepoint in range(33, 127):
        if chr(codepoint) not in {'"', '\\'} and chr(codepoint) not in used:
            return chr(codepoint) * 3
    raise ValueError('cannot choose credential-safe redaction marker')


def redact_text(text, truncated, secrets, *, safe_marker=False):
    """Redact retained engine log text against snapshot credentials.

    Shared by the direct and proxy runners so timeout/interrupt precedence
    and redaction trimming cannot diverge across the two critical paths.
    This stays separate from process.redacted deliberately: the Docker
    engine returns text, so trimming counts characters, while process
    capture works on bytes and counts credential byte lengths.
    """
    if truncated and secrets:
        # Drop the boundary where a retained prefix could end
        # halfway through a credential before value redaction.
        trim = max(len(secret) for secret in secrets) - 1
        if trim:
            text = text[:-trim]
    marker = _safe_redaction_marker(secrets) if safe_marker else '[REDACTED]'
    for secret in sorted(secrets, key=len, reverse=True):
        text = text.replace(secret, marker)
    return text


def redact_record(value, secrets):
    """Redact credential text from controller metadata without mutating originals."""
    if isinstance(value, str):
        return redact_text(value, False, secrets, safe_marker=True)
    if isinstance(value, list):
        return [redact_record(item, secrets) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_record(item, secrets) for item in value)
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            clean_key = redact_record(key, secrets)
            if clean_key in result:
                raise ValueError('credential redaction caused metadata key collision')
            result[clean_key] = redact_record(item, secrets)
        return result
    if any(secret and secret in json.dumps(value, ensure_ascii=False) for secret in secrets):
        return _safe_redaction_marker(secrets)
    return value


def safe_metadata(record, secrets):
    sanitized = redact_record(record, secrets)
    representations = (json.dumps(sanitized, ensure_ascii=True, indent=2, sort_keys=True, allow_nan=False) + '\n',
                       json.dumps(sanitized, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + '\n')
    if any(secret and any(secret in text for text in representations) for secret in secrets):
        raise ValueError('credential cannot be excluded from metadata serialization')
    return sanitized


def compute_exit_code(*, app_returncode, app_completed, interrupted_signal, timed_out,
                      lifecycle, cleanup):
    """One exit-code formula for the direct and proxy runners.

    A completed application return code wins; interruption, timeout and
    runner errors follow in that precedence; 0 requires a clean run.
    """
    return (app_returncode if app_completed and app_returncode else
            128 + interrupted_signal if interrupted_signal else 124 if timed_out else
            app_returncode if app_returncode else 1 if lifecycle or cleanup else 0)


def _bind_mount(source, destination, *, readonly=False):
    """Docker parses --mount as CSV independently of shell/argv quoting."""
    rendered = io.StringIO()
    fields = ['type=bind', f'src={source}', f'dst={destination}']
    if readonly:
        fields.append('readonly')
    csv.writer(rendered).writerow(fields)
    return rendered.getvalue().removesuffix('\r\n')


def _write_stage_log(path, text):
    # The application can preplant output entries; never follow or truncate one.
    with path.open('x', encoding='utf-8') as stream:
        stream.write(text)


def stage_credential_inputs(spec, descriptor, credentials, staging):
    """Snapshot secret file inputs and render the container env file.

    staging is a caller-owned private directory; snapshots are world-readable
    single files (only each file is mounted) and the env file is 0600.
    Returns (inputs, mounts, envfile).
    """
    staging = Path(staging)
    envfile = staging / 'environment'
    inputs = {}
    mounts = []
    for key, value in spec.inputs.items():
        if key == 'P11LAB_STATE_DIR':
            continue
        if descriptor['inputs'][key]['secret']:
            if key.endswith('_FILE'):
                source = Path(value).resolve(strict=True)
                secret = credentials[key]
                destination = '/run/p11lab-input/' + key
                if ',' in str(source):
                    raise ValueError('Docker bind mount paths cannot contain commas')
                snapshot = staging / key
                snapshot.write_bytes(secret)
                snapshot.chmod(0o444)  # parent is 0700; only this file is mounted
                mounts.extend(['--mount', _bind_mount(snapshot, destination, readonly=True)])
                inputs[key] = destination
            else:
                secret = value.encode()
                inputs[key] = value
        else:
            inputs[key] = value
    envfile.write_text(''.join(f'{k}={v}\n' for k, v in inputs.items()))
    envfile.chmod(0o600)
    return inputs, mounts, envfile


def prepare_state_mount(spec, engine, run_id, labels, owned, box):
    """Resolve the token state mount: caller bind or owned volume.

    Fills box with state_mount/state_directory/state_ownership progressively
    and appends the owned volume entry on success, so a mid-step engine
    failure keeps the same partial state the inline code left behind.
    """
    if 'P11LAB_STATE_DIR' in spec.inputs:
        state = Path(spec.inputs['P11LAB_STATE_DIR']).resolve()
        if ',' in str(state):
            raise ValueError('Docker bind mount paths cannot contain commas')
        box['state_directory'] = None
        box['state_ownership'] = {'uid': state.stat().st_uid, 'gid': state.stat().st_gid,
                                  'mode': oct(state.stat().st_mode & 0o777)}
        box['state_mount'] = _bind_mount(state, '/var/lib/p11lab')
        return
    state_directory = Path(tempfile.mkdtemp(prefix='p11lab-state-'))
    box['state_directory'] = state_directory
    box['state_ownership'] = {'uid': state_directory.stat().st_uid, 'gid': state_directory.stat().st_gid,
                              'mode': oct(state_directory.stat().st_mode & 0o777)}
    state = engine.volume('p11lab-' + run_id, labels, state_directory)
    owned.append(('volume', state))
    box['state_mount'] = f'type=volume,src={state},dst=/var/lib/p11lab,volume-nocopy'


def receipt_outcome_fields(*, spec, descriptor, state_directory, state_ownership, stages,
                           owned, uncertain, app_returncode, app_completed, lifecycle,
                           cleanup, exit_code, timed_out, interrupted_signal):
    """Shared receipt tail for the direct and proxy runners.

    Inputs presence, state ownership, stage roster, resource accounting and
    the outcome triple are identical across modes; each runner adds its own
    artifacts/observation/execution sections around these fields.
    """
    return {'inputs': {key: {'present': True, 'secret': descriptor['inputs'][key]['secret']}
                       for key in spec.inputs if key != 'P11LAB_STATE_DIR'},
            'state': {'persistent_caller_directory': 'P11LAB_STATE_DIR' in spec.inputs,
                      'owned_directory': str(state_directory) if state_directory else None,
                      'directory_ownership': state_ownership,
                      'control_uid_gid': f'{os.getuid()}:{os.getgid()}', 'control_mode': '0700',
                      'owned_directory_retained': state_directory.exists() if state_directory else False},
            'stages': stages, 'owned_resources': [{'kind': k, 'identity': i} for k, i in owned],
            'uncertain_resources': [{'kind': k, 'name': n} for k, n in uncertain],
            'app_returncode': app_returncode, 'app_completed': app_completed,
            'lifecycle_errors': lifecycle, 'cleanup_errors': cleanup,
            'exit_code': exit_code, 'timeout': timed_out, 'interrupted_signal': interrupted_signal}


def run_application(spec: RunSpec) -> RunResult:
    if spec.mode != 'proxy' and spec.expected_proxy_identity is not None:
        raise ValueError('proxy build identity requires proxy mode')
    if spec.fixed_validation is not None:
        from .bounded_run import fixed_validation_command
        if (spec.bounded is None or spec.environment != 'softhsm2' or spec.channel != 'release'
                or spec.mode != 'direct' or spec.execution_location != 'provider'
                or list(spec.argv) != fixed_validation_command(spec.fixed_validation, 'application')[2:]):
            raise ValueError('fixed validation requires its exact bounded local invocation')
    if spec.bounded is not None:
        if (spec.mode != 'direct' or spec.execution_location != 'provider'
                or 'P11LAB_STATE_DIR' in spec.inputs or spec.installed_prefix is not None):
            raise ValueError('bounded execution requires direct provider with disposable state')
        from .bounded_run import require_nonroot, validate_policy
        require_nonroot()
        validate_policy(spec.bounded, spec.timeout_seconds)
    if spec.mode == 'native':
        from .native import native_lifecycle, staging_parent
        from .bundle import read_installation
        install_native, _, run_native = native_lifecycle(spec.environment)
        if spec.installed_prefix is not None:
            installed = read_installation(spec.installed_prefix, environment=spec.environment,
                                          channel=spec.channel, platform=spec.artifact.platform)
            return run_native(spec, installed)
        # Validate routing before even temporary installation/resource creation.
        if spec.execution_location != 'host' or spec.consumer_artifact or spec.client_artifact:
            raise ValueError('native requires host without container options')
        with tempfile.TemporaryDirectory(prefix='.p11lab-native-run-', dir=staging_parent(spec.output_dir)) as temporary:
            installed = install_native(spec.artifact, Path(temporary) / 'prefix',
                                       environment=spec.environment, channel=spec.channel)
            return run_native(spec, installed)
    if spec.mode == 'proxy':
        return run_proxy(spec, prepare_proxy(spec))
    if spec.installed_prefix is not None:
        raise ValueError('installed-prefix requires native mode')
    descriptor = _validate(spec)
    if spec.bounded is not None and any(
            descriptor['inputs'][key]['secret'] and not key.endswith('_FILE') for key in spec.inputs):
        raise ValueError('bounded execution requires file-based secret inputs')
    credentials, secrets = snapshot_credentials(spec.inputs, descriptor)
    engine = Docker()
    observed = engine.image(spec.artifact)  # no resource created before preflight
    if spec.bounded is not None and observed.get('Config', {}).get('Volumes'):
        raise ValueError('bounded execution rejects implicit image volumes')
    if spec.bounded is not None and any(
            entry.split('=', 1)[0] not in {'PATH', 'LANG', 'LC_ALL', 'TZ'}
            for entry in (observed.get('Config', {}).get('Env') or [])):
        raise ValueError('bounded execution rejects inherited image environment')
    output = spec.output_dir.resolve()
    cwd = spec.cwd.resolve()
    if any(',' in str(path) for path in (output, cwd)):
        raise ValueError('Docker bind mount paths cannot contain commas')
    output.mkdir(parents=True)
    run_id, attempt_id = uuid4().hex, uuid4().hex
    labels = {'org.p11lab.run': run_id, 'org.p11lab.attempt': attempt_id}
    owned = []
    uncertain = []
    lifecycle, cleanup, stages = [], [], []
    app_returncode = None
    app_completed = False
    timed_out = False
    interrupted_signal = None
    deadline = time.monotonic() + spec.timeout_seconds
    old_handlers = {}

    def receive(signum, frame):
        nonlocal interrupted_signal
        interrupted_signal = interrupted_signal or signum

    if threading.current_thread() is threading.main_thread():
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            old_handlers[sig] = signal.signal(sig, receive)
    state_directory = None
    state_ownership = None
    state_storage = output_storage = None
    bounded_records: dict[str, Any] = {}
    try:
        with tempfile.TemporaryDirectory(prefix='p11lab-input-') as private:
            inputs, mounts, envfile = stage_credential_inputs(spec, descriptor, credentials, Path(private))
            if spec.bounded is None:
                state_box = {}
                try:
                    prepare_state_mount(spec, engine, run_id, labels, owned, state_box)
                finally:
                    state_mount = state_box.get('state_mount')
                    state_directory = state_box.get('state_directory')
                    state_ownership = state_box.get('state_ownership')
            else:
                from .bounded_run import open_storage
                bounded_records = {'state': {}, 'output': {}, 'stages': {}}
                state_storage = open_storage(engine, labels, 'p11lab-' + run_id + '-state',
                                             spec.bounded.state_bytes, bounded_records['state'])
                output_storage = open_storage(engine, labels, 'p11lab-' + run_id + '-output',
                                              spec.bounded.output_bytes, bounded_records['output'])
                state_mount = f'type=volume,src={state_storage.volume},dst=/var/lib/p11lab,volume-nocopy'
            options = ['--user', f'{os.getuid()}:{os.getgid()}', '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                       '--tmpfs', f'/run/p11lab:rw,nosuid,nodev,uid={os.getuid()},gid={os.getgid()},mode=0700', '--tmpfs', '/tmp:rw,nosuid,nodev',
                       '--mount', state_mount, '--env-file', str(envfile), *mounts]
            if spec.bounded is not None:
                options = ['--pull=never', '--user', f'{os.getuid()}:{os.getgid()}', '--network', 'none', '--ipc', 'private',
                           '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges=true',
                           '--memory', str(spec.bounded.memory_bytes), '--memory-swap', str(spec.bounded.memory_bytes),
                           '--cpus', '1', '--pids-limit', str(spec.bounded.pids), '--log-driver', 'none',
                           '--tmpfs', f'/run/p11lab:rw,nosuid,nodev,uid={os.getuid()},gid={os.getgid()},mode=0700,size={spec.bounded.run_bytes},nr_inodes={spec.bounded.inodes}',
                           '--tmpfs', f'/tmp:rw,nosuid,nodev,size={spec.bounded.tmp_bytes},nr_inodes={spec.bounded.inodes}',
                           '--tmpfs', f'/dev/shm:rw,nosuid,nodev,size={spec.bounded.run_bytes},nr_inodes={spec.bounded.inodes},mode=1777',
                           '--mount', state_mount, '--env-file', str(envfile), *mounts]
            for index, argv in enumerate((('init',), ('health',), ('exec', '--', *spec.argv), ('health',))):
                phase = ('init', 'ready', 'application', 'post-health')[index]
                if interrupted_signal or time.monotonic() >= deadline:
                    timed_out = not bool(interrupted_signal)
                    lifecycle.append('interrupted' if interrupted_signal else 'timeout')
                    break
                stage_options = list(options)
                if phase == 'application':
                    workspace = _bind_mount(cwd, '/workspace', readonly=spec.bounded is not None)
                    app_output = (_bind_mount(output, '/p11lab-output') if output_storage is None else
                                  f'type=volume,src={output_storage.volume},dst=/p11lab-output,volume-nocopy')
                    stage_options.extend(['--mount', workspace, '--mount', app_output,
                                          '--workdir', '/workspace', '--env', 'P11LAB_OUTPUT_DIR=/p11lab-output'])
                identity = engine.create(spec.artifact.reference, argv, stage_options, labels, 'p11lab-' + run_id + '-' + str(index))
                owned.append(('container', identity))
                if spec.bounded is not None:
                    from .bounded_run import verify_container
                    expected_mounts = []
                    for pos, option in enumerate(stage_options):
                        if option != '--mount':
                            continue
                        fields = next(csv.reader([stage_options[pos + 1]]))
                        pairs = dict(field.split('=', 1) for field in fields if '=' in field)
                        kind = pairs['type']
                        expected_mounts.append((kind, pairs['dst'], pairs['src'], 'readonly' not in fields))
                    inspection = json.loads(engine.command(['container', 'inspect', identity]).stdout)[0]
                    verify_container(inspection, identity, spec.artifact.reference, labels, spec.bounded,
                                     f'{os.getuid()}:{os.getgid()}', expected_mounts, list(argv),
                                     observed.get('Config', {}).get('Entrypoint'))
                    bounded_records['stages'][phase] = {
                        'id': inspection['Id'], 'image': inspection['Image'],
                        'host_config': inspection['HostConfig'], 'mounts': inspection['Mounts']}
                    if spec.fixed_validation is not None:
                        from .bounded_run import CredentialTaintError, fixed_validation_observation
                        try:
                            observation = fixed_validation_observation(inspection['Config'], spec.fixed_validation,
                                                                       phase, f'{os.getuid()}:{os.getgid()}', secrets)
                        except CredentialTaintError:
                            bounded_records['stream_tainted'] = True
                            raise
                        bounded_records['stages'][phase]['fixed_validation_observation'] = observation
                if spec.bounded is not None:
                    bounded_records['stream_capture_unavailable'] = True
                    bounded_records['stream_capture_phase'] = phase
                result = engine.execute(identity, max(.01, deadline - time.monotonic()), lambda: interrupted_signal)
                if spec.bounded is not None:
                    del bounded_records['stream_capture_unavailable']
                    del bounded_records['stream_capture_phase']
                if phase == 'application':
                    app_returncode = result.returncode
                    app_completed = not result.timed_out and not interrupted_signal
                timed_out = timed_out or result.timed_out
                if spec.bounded is not None:
                    exposed = [(name, text) for name, text in (('stdout', result.stdout), ('stderr', result.stderr))
                               if any(secret and secret in text for secret in secrets)]
                    if exposed:
                        # Set this before any further I/O: a later failure cannot clear it.
                        bounded_records['stream_tainted'] = True
                        private = Path(tempfile.mkdtemp(prefix='p11lab-private-streams-', dir='/tmp'))
                        if private.resolve().is_relative_to(output):
                            private.rmdir()
                            raise ValueError('private retention overlaps output')
                        private.chmod(0o700)
                        retained = {}
                        for name, text in exposed:
                            path = private / (phase + '.' + name + '.log')
                            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                            with os.fdopen(fd, 'w', encoding='utf-8') as saved:
                                saved.write(text)
                            retained[name] = str(path)
                        bounded_records['stages'][phase]['private_captured_streams'] = retained
                _write_stage_log(output / (phase + '.stdout.log'), redact_text(result.stdout, result.stdout_truncated, secrets,
                                                                             safe_marker=spec.bounded is not None))
                _write_stage_log(output / (phase + '.stderr.log'), redact_text(result.stderr, result.stderr_truncated, secrets,
                                                                             safe_marker=spec.bounded is not None))
                stages.append({'phase': phase, 'container_id': identity, 'returncode': result.returncode,
                               'timed_out': result.timed_out, 'stdout_truncated': result.stdout_truncated,
                               'stderr_truncated': result.stderr_truncated})
                if phase != 'application' and result.returncode:
                    lifecycle.append(phase + ' failed')
                    break
                if result.timed_out or interrupted_signal:
                    break
            if output_storage is not None:
                from .bounded_run import read_output
                from .round_core.worker import _inspection
                for kind, identity in owned:
                    if kind == 'container' and _inspection(engine, identity, labels).get('State', {}).get('Running') is not False:
                        raise ValueError('candidate still running before output readback')
                read_output(output_storage, output, lambda: interrupted_signal, credentials)
    except Exception as error:
        if (not isinstance(error, (DockerError, OSError, ValueError)) and
                not (spec.bounded is not None and
                     (bounded_records.get('stream_tainted') is True or
                      bounded_records.get('stream_capture_unavailable') is True))):
            raise
        # Do not expose subprocess arguments, environment or credential paths.
        if bounded_records.get('stream_capture_unavailable') is True:
            bounded_records['stream_capture_error'] = type(error).__name__
        if isinstance(error, DockerError):
            if error.resource is not None:
                owned.append(error.resource)
            if error.uncertain_resource is not None:
                uncertain.append(error.uncertain_resource)
                cleanup.append('creation status unknown: ' + ' '.join(error.uncertain_resource))
        if isinstance(error, FileExistsError):
            lifecycle.append('stage log evidence incomplete: output path already exists')
        lifecycle.append('runner operation failed (' + type(error).__name__ + ')')
    finally:
        for kind, identity in reversed(owned):
            try:
                engine.remove(kind, identity, labels)
            except Exception as error:
                if spec.bounded is None and not isinstance(error, (DockerError, OSError, ValueError)):
                    raise
                detail = ' (' + type(error).__name__ + ')' if spec.bounded is not None else ''
                cleanup.append(kind + ' cleanup failed' + detail + ': ' + identity)
        for storage in (output_storage, state_storage):
            if storage is not None:
                try:
                    cleanup.extend(storage.close())
                except Exception as error:
                    if spec.bounded is None:
                        raise
                    cleanup.append('bounded storage cleanup failed (' + type(error).__name__ + ')')
        for record in bounded_records.values():
            if isinstance(record, dict):
                cleanup.extend(record.get('cleanup_errors', []))
        if state_directory is not None and not cleanup:
            try:
                shutil.rmtree(state_directory)
            except OSError:
                cleanup.append('private state directory cleanup failed')
        for sig, handler in old_handlers.items():
            signal.signal(sig, handler)
    if bounded_records.get('stream_tainted') is True:
        lifecycle.append('credential-tainted stream')
    exit_code = compute_exit_code(app_returncode=app_returncode, app_completed=app_completed,
                                  interrupted_signal=interrupted_signal, timed_out=timed_out,
                                  lifecycle=lifecycle, cleanup=cleanup)
    receipt_path = output / 'receipt.json'
    record = {'schema_version': 1, 'run_id': run_id, 'attempt_id': attempt_id,
              'environment': spec.environment, 'channel': spec.channel, 'mode': spec.mode,
              'execution_location': spec.execution_location,
              'artifacts': {'provider': asdict(spec.artifact), 'consumer': None, 'client': None},
              'image_observation': {'Id': observed['Id'], 'Descriptor': observed.get('Descriptor'),
                                    'platform': spec.artifact.platform},
              'execution': {'container_cwd': '/workspace', 'output_mount': '/p11lab-output',
                            'uid_gid': f'{os.getuid()}:{os.getgid()}',
                            'capabilities': [], 'network': 'none', 'root_readonly': True,
                            'writable': ['/var/lib/p11lab', '/run/p11lab', '/tmp', '/workspace', '/p11lab-output'],
                            'argv_count': len(spec.argv)},
              **receipt_outcome_fields(spec=spec, descriptor=descriptor, state_directory=state_directory,
                                       state_ownership=state_ownership, stages=stages, owned=owned,
                                       uncertain=uncertain, app_returncode=app_returncode,
                                       app_completed=app_completed, lifecycle=lifecycle, cleanup=cleanup,
                                       exit_code=exit_code, timed_out=timed_out,
                                       interrupted_signal=interrupted_signal)}
    if spec.bounded is not None:
        record['bounded_execution'] = bounded_records
        record['bounded_policy'] = asdict(spec.bounded)
        record['execution']['writable'] = ['/var/lib/p11lab', '/run/p11lab', '/tmp', '/p11lab-output']
        metadata = (json.dumps(record, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + '\n',
                    json.dumps(record, ensure_ascii=True, indent=2, sort_keys=True, allow_nan=False) + '\n')
        if any(secret and any(secret in text for text in metadata) for secret in secrets):
            unknown_only = (bounded_records.get('stream_capture_unavailable') is True and
                            bounded_records.get('stream_tainted') is not True and
                            bounded_records.get('output', {}).get('readback', {}).get('tainted') is not True)
            if not unknown_only:
                bounded_records.setdefault('output', {}).setdefault('readback', {})['tainted'] = True
                lifecycle.append('credential-tainted metadata')
                record['lifecycle_errors'] = lifecycle
                exit_code = compute_exit_code(app_returncode=app_returncode, app_completed=app_completed,
                                              interrupted_signal=interrupted_signal, timed_out=timed_out,
                                              lifecycle=lifecycle, cleanup=cleanup)
                record['exit_code'] = exit_code
            try:
                record = safe_metadata(record, secrets)
                if unknown_only and record.get('bounded_execution', {}).get('stream_capture_unavailable') is not True:
                    raise ValueError('unavailable capture marker cannot be retained safely')
            except ValueError:
                if unknown_only:
                    from .bounded_run import CaptureUnavailableError
                    raise CaptureUnavailableError('candidate stream unavailable; safe receipt unavailable; export blocked') from None
                from .bounded_run import CredentialTaintError
                raise CredentialTaintError('credential-tainted metadata; export blocked') from None
    try:
        write_receipt(receipt_path, record)
    except Exception:
        if (spec.bounded is not None and
                (bounded_records.get('stream_tainted') is True or
                 bounded_records.get('output', {}).get('readback', {}).get('tainted') is True)):
            from .bounded_run import CredentialTaintError
            raise CredentialTaintError('candidate output contains staged credential; export blocked') from None
        if spec.bounded is not None and bounded_records.get('stream_capture_unavailable') is True:
            from .bounded_run import CaptureUnavailableError
            safe = record.get('bounded_execution', {})
            phase = safe.get('stream_capture_phase', 'unknown')
            cause = safe.get('stream_capture_error', 'unknown')
            raise CaptureUnavailableError(
                f'candidate stream unavailable ({phase}; {cause}); receipt write failed; export blocked') from None
        raise
    if spec.bounded is not None:
        safe_lifecycle = record.get('lifecycle_errors')
        safe_cleanup = record.get('cleanup_errors')
        if not isinstance(safe_lifecycle, list) or not isinstance(safe_cleanup, list):
            if bounded_records.get('stream_capture_unavailable') is True and bounded_records.get('stream_tainted') is not True:
                from .bounded_run import CaptureUnavailableError
                raise CaptureUnavailableError('candidate stream unavailable; safe outcome unavailable; export blocked') from None
            from .bounded_run import CredentialTaintError
            raise CredentialTaintError('credential-safe outcome unavailable; export blocked') from None
        return RunResult(app_returncode, tuple(safe_lifecycle), tuple(safe_cleanup), exit_code, receipt_path)
    return RunResult(app_returncode, tuple(lifecycle), tuple(cleanup), exit_code, receipt_path)


PROXY_PORT = 7512
PROXY_TOML_PATH = '/etc/p11lab/proxy.toml'
DAEMON_TLS_DIR = '/run/p11lab-tls'
CLIENT_TLS_DIR = '/run/p11lab-client-tls'
PROXY_IDENTITY_MODULE_PLACEHOLDER = '<provider-module>'
CLIENT_SHIM_PATH = '/run/p11lab-client/libpkcs11_proxy_ng_shim.so'
DAEMON_DNS = 'provider-daemon'


def render_proxy_toml(*, module_path: str) -> str:
    """Exact daemon configuration per the public transport contract.

    lease_seconds=1 reclaims contexts orphaned by short-lived helpers that
    exit without C_Finalize (observed: checker preflight). Live contexts are
    unaffected: reaping needs an expired lease plus a new admission, and
    max_contexts=1 still refuses a second live context.
    """
    # The identity placeholder renders the canonical daemon config whose digest
    # the identity record binds; it is never a real backend path.
    if module_path != PROXY_IDENTITY_MODULE_PLACEHOLDER and (
            not module_path.startswith('/') or any(c in module_path for c in '\0\n\r"\\')):
        raise ValueError('daemon backend module path is not representable in TOML')
    return (
        '[backend]\n'
        f'module = "{module_path}"\n'
        '\n[proxy]\nmax_contexts = 1\nmechanism_discovery = "transparent"\n'
        'lease_seconds = 1\n'
        'request_timeout_secs = 60\nstartup_timeout_secs = 30\n'
        '\n[listener.remote]\nbind = "0.0.0.0:7512"\nauth = "mtls"\n'
        'allow_insecure_tcp = false\n'
        f'ca_cert = "{DAEMON_TLS_DIR}/ca.crt"\n'
        f'server_cert = "{DAEMON_TLS_DIR}/server.crt"\n'
        f'server_key = "{DAEMON_TLS_DIR}/server.key"\n'
        '\n[auth]\nallow_all_authenticated = true\n'
    )


def prepare_proxy(spec: RunSpec) -> dict:
    """Validate proxy/container and proxy/host selection; no resources created."""
    descriptor = load_environment(spec.environment, spec.channel)
    if descriptor['channel_spec']['status'] != 'locked':
        raise ValueError('run requires an implemented locked provider channel')
    if spec.mode != 'proxy':
        raise ValueError('proxy selection requires proxy mode')
    if spec.expected_proxy_identity is not None and not isinstance(
            spec.expected_proxy_identity, ProxyBuildIdentityV1):
        raise ValueError('proxy run expected_proxy_identity must be a ProxyBuildIdentityV1 record or None')
    host = spec.execution_location == 'host'
    if spec.execution_location not in ('container', 'host'):
        raise ValueError('proxy requires container or host execution')
    if (spec.artifact.kind != 'docker-local' or not re.fullmatch(r'sha256:[0-9a-f]{64}', spec.artifact.reference)
            or spec.artifact.sha256 != spec.artifact.reference.removeprefix('sha256:')
            or spec.artifact.platform not in descriptor['runtime_platforms']):
        raise ValueError('proxy requires an exact supported docker-local daemon image ID')
    if host:
        if spec.consumer_artifact is not None:
            raise ValueError('proxy/host runs the caller application on the host without a consumer image')
    elif (spec.consumer_artifact is None or spec.consumer_artifact.kind != 'docker-local'
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', spec.consumer_artifact.reference)
            or spec.consumer_artifact.sha256 != spec.consumer_artifact.reference.removeprefix('sha256:')
            or spec.consumer_artifact.platform not in descriptor['client_platforms']):
        raise ValueError('proxy/container requires an exact supported docker-local caller image')
    client = spec.client_artifact
    if (client is None or client.kind != 'bundle' or not client.reference
            or not re.fullmatch(r'[0-9a-f]{64}', client.sha256)
            or client.platform != 'linux/amd64'):
        raise ValueError('proxy requires an exact compatible native-client bundle')
    if spec.installed_prefix is not None and not host:
        raise ValueError('installed client prefix requires proxy/host execution')
    if not spec.argv or any(not isinstance(a, str) or '\0' in a for a in spec.argv):
        raise ValueError('application requires literal argv without NUL bytes')
    if spec.timeout_seconds <= 0 or not spec.cwd.is_dir():
        raise ValueError('positive timeout and existing caller cwd are required')
    unknown = set(spec.inputs) - set(descriptor['inputs']) - {'P11LAB_STATE_DIR'}
    if unknown or any(not isinstance(v, str) or '\n' in v or '\r' in v or '\0' in v for v in spec.inputs.values()):
        raise ValueError('inputs must be allowlisted single-line strings')
    for key, value in spec.inputs.items():
        if key.endswith('_FILE') and not Path(value).is_file():
            raise ValueError('credential input file must be readable')
        if key == 'P11LAB_STATE_DIR' and not Path(value).is_dir():
            raise ValueError('explicit persistent state directory must already exist')
    if spec.output_dir.exists():
        raise ValueError('output directory must be a fresh attempt directory')
    for key in spec.inputs:
        if key.endswith('_FILE') and key.removesuffix('_FILE') in spec.inputs:
            raise ValueError('conflicting scalar/file credential inputs')
    return {'descriptor': descriptor, 'host': host}


def _rehash_launch_bytes(prefix: Path) -> dict:
    """Rehash installed shim/CLI payload bytes before identity checks and launch."""
    from .native import CLIENT_CLI, CLIENT_MODULE
    from .sources import checksum
    try:
        return {'shim_sha256': checksum(prefix / 'payload' / CLIENT_MODULE),
                'cli_sha256': checksum(prefix / 'payload' / CLIENT_CLI)}
    except OSError as error:
        raise ValueError('proxy launch bytes are missing: %s' % error) from error


def _absent_derivative_parent():
    """Explicit absent/unverified derivative-parent receipt field."""
    return {'family': None, 'platform': None, 'manifest_digest': None, 'config_digest': None,
            'parent_layers': [], 'child_layers_prefix_ok': False}


def _derivative_parent_evidence(child_inspection):
    """Observed daemon_parent evidence, or None when unobservable.

    Never raises: engines without RootFS evidence (or any selection load
    failure) yield no parent key, preserving the pre-derivative gate.
    """
    try:
        if type(child_inspection) is not dict:
            return None
        layers = child_inspection['RootFS']['Layers']
        if type(layers) is not list or not layers:
            return None
        selection = load_parent_selection()
    except (ValueError, KeyError, TypeError):
        return None
    return {'family': selection['family'], 'platform': selection['platform'],
            'manifest_digest': selection['manifest_digest'],
            'config_digest': selection['config_digest'],
            'parent_layers': list(selection['layers']), 'child_layers': list(layers)}


def _derivative_parent_receipt(child_inspection):
    """Observed derivative-parent receipt field; explicit when unverifiable."""
    try:
        if type(child_inspection) is not dict:
            return _absent_derivative_parent()
        layers = child_inspection['RootFS']['Layers']
        if type(layers) is not list or not layers:
            return _absent_derivative_parent()
        binding = verify_derivative_parent({'RootFS': {'Layers': list(layers)}},
                                           load_parent_selection())
    except (ValueError, KeyError, TypeError):
        return _absent_derivative_parent()
    return {'family': binding['family'], 'platform': binding['platform'],
            'manifest_digest': binding['manifest_digest'],
            'config_digest': binding['config_digest'],
            'parent_layers': list(binding['parent_layers']),
            'child_layers_prefix_ok': binding['child_layers_prefix_ok']}


def check_proxy_identities(derivative: dict, client_manifest: dict, *, expected=None,
                           launch_rehashes: dict, daemon_image: dict) -> dict:
    """Refuse derivative/client builds that were not built as one identity.

    expected None selects the absolute pinned default; launch_rehashes carries
    the post-install shim/CLI digests and daemon_image the selected-vs-observed
    engine naming plus the optional observed parent evidence. The recorded
    client identity, daemon claim, rehashes, and observed ABI must all equal
    the selection exactly.
    """
    from .proxy_inputs import validate_proxy_identity
    if type(daemon_image) is not dict or set(daemon_image) not in (
            {'selected', 'observed'}, {'selected', 'observed', 'parent'}):
        raise ValueError('proxy identity mismatch: daemon_image requires {selected, observed} plus optional parent')
    if daemon_image['observed'] != daemon_image['selected']:
        raise ValueError('proxy identity mismatch: daemon_image.observed')
    try:
        abi_observed = client_manifest['source']['proxy']['abi_observed']
    except (KeyError, TypeError):
        raise ValueError(
            'proxy identity actual invalid: client_manifest requires a recorded abi_observed') from None
    actual = {'daemon_build_json': derivative, 'client_manifest': client_manifest,
              'launch_rehashes': launch_rehashes, 'abi_observed': abi_observed}
    if daemon_image.get('parent') is not None:
        actual['daemon_parent'] = daemon_image['parent']
    validate_proxy_identity(
        actual, expected.to_dict() if isinstance(expected, ProxyBuildIdentityV1) else expected)
    return derivative


def _create_proxy_network(engine, name, labels):
    args = ['network', 'create', '--driver', 'bridge']
    for key, value in labels.items():
        args.extend(['--label', key + '=' + value])
    args.append(name)
    try:
        result = engine.command(args)
        if not result.stdout.strip():
            raise DockerError('unexpected created network identity')
    except (DockerError, OSError) as error:
        probe = engine.command(['network', 'inspect', name], timeout=5, check=False)
        try:
            inspected = json.loads(probe.stdout)[0] if probe.returncode == 0 else None
        except ValueError:
            inspected = None
        if (inspected is not None and inspected.get('Name') == name
                and all((inspected.get('Labels') or {}).get(k) == v for k, v in labels.items())):
            raise DockerError('Docker resource creation failed', resource=('network', name)) from error
        raise DockerError('Docker resource creation failed', uncertain_resource=('network', name)) from error
    return name


def _run_proxy_host_app(argv, *, cwd, env, output, timeout, interrupted, secrets):
    """Run the caller application on the host with bounded redacted logs."""
    status, timed_out, owner, evidence = supervised_exec(
        argv, cwd=cwd, env=env, timeout=timeout, interrupted=interrupted)
    evidence['log_errors'] = []
    for index, stream in enumerate(('stdout', 'stderr')):
        text, truncated = bounded_redacted(bytes(owner.capture.buffers[index]), secrets,
                                           owner.capture.truncated[index])
        evidence[stream + '_truncated'] = truncated
        try:
            _write_stage_log(output / ('application.' + stream + '.log'), text)
        except OSError as error:
            evidence['log_errors'].append('application ' + stream + ' log unavailable (' + type(error).__name__ + ')')
    return status, timed_out, evidence


def _proxy_daemon_state(engine, identity, secrets):
    """Retain Docker state only, never the inspect config/environment or mounts."""
    fields = ('Status', 'Running', 'Paused', 'Restarting', 'OOMKilled', 'Dead',
              'Pid', 'ExitCode', 'Error', 'StartedAt', 'FinishedAt')
    evidence = {'available': False, 'state': None, 'error': None, 'returncode': None,
                'timed_out': None, 'stdout_truncated': None, 'stderr_truncated': None,
                'signal': {'observed': None, 'encoded_exit_candidate': None,
                           'source': 'exit-code convention only; termination cause unobserved'}}
    try:
        result = engine.command(['inspect', '--format', '{{json .State}}', identity], timeout=5, check=False)
        evidence.update({'returncode': result.returncode, 'timed_out': result.timed_out,
                         'stdout_truncated': result.stdout_truncated, 'stderr_truncated': result.stderr_truncated})
        if result.returncode or result.timed_out or result.stdout_truncated:
            raise DockerError('daemon state unavailable')
        state = json.loads(result.stdout)
        if (not isinstance(state, dict) or type(state.get('Running')) is not bool
                or type(state.get('ExitCode')) is not int):
            raise ValueError('daemon state invalid')
        types = {key: bool for key in ('Running', 'Paused', 'Restarting', 'OOMKilled', 'Dead')}
        types.update({key: int for key in ('Pid', 'ExitCode')})
        if any(value is not None and type(value) is not types.get(key, str)
               for key in fields for value in (state.get(key),)):
            raise ValueError('daemon state field invalid')
        # The allowlist excludes configuration, TLS paths/keys and credentials.
        evidence['state'] = {key: redact_text(state[key], False, secrets)
                             if isinstance(state.get(key), str) else state.get(key)
                             for key in fields}
        evidence['available'] = True
        code = state['ExitCode']
        if not state['Running'] and 128 < code <= 192:
            evidence['signal']['encoded_exit_candidate'] = code - 128
    except (DockerError, OSError, ValueError, TypeError) as error:
        evidence['error'] = 'daemon inspect unavailable (' + type(error).__name__ + ')'
    return evidence


def run_proxy(spec: RunSpec, plan: dict) -> RunResult:
    """One logical mTLS client against a dedicated daemon; no operation replay."""
    from . import tls as proxy_tls
    from .native import CLIENT_MODULE, install_native_client_bundle, load_client_installation, preflight_native_client, staging_parent
    descriptor, host = plan['descriptor'], plan['host']
    credentials, secrets = snapshot_credentials(spec.inputs, descriptor)
    engine = Docker()
    observed_daemon = engine.image(spec.artifact)  # no resource created before preflight
    observed_consumer = engine.image(spec.consumer_artifact) if not host else None
    output = spec.output_dir.resolve()
    cwd = spec.cwd.resolve()
    if any(',' in str(path) for path in (output, cwd)):
        raise ValueError('Docker bind mount paths cannot contain commas')
    verified_client = None
    if spec.installed_prefix is not None:
        from .bundle import validate_writable_paths
        validate_writable_paths(spec.installed_prefix, (output, Path(spec.inputs.get('P11LAB_STATE_DIR', output / 'state'))))
        verified_client = load_client_installation(spec.installed_prefix, environment=spec.environment,
                                                  channel=spec.channel, platform=spec.client_artifact.platform,
                                                  expected_proxy_identity=spec.expected_proxy_identity)
        if verified_client.artifact != spec.client_artifact:
            raise ValueError('run client artifact differs from installed client')
    output.mkdir(parents=True)
    run_id, attempt_id = uuid4().hex, uuid4().hex
    labels = {'org.p11lab.run': run_id, 'org.p11lab.attempt': attempt_id}
    owned = []
    uncertain = []
    lifecycle, cleanup, stages = [], [], []
    app_returncode = None
    app_completed = False
    timed_out = False
    interrupted_signal = None
    deadline = time.monotonic() + spec.timeout_seconds
    old_handlers = {}

    def receive(signum, frame):
        nonlocal interrupted_signal
        interrupted_signal = interrupted_signal or signum

    if threading.current_thread() is threading.main_thread():
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            old_handlers[sig] = signal.signal(sig, receive)
    state_directory = None
    state_ownership = None
    network = None
    endpoint = None
    build_identity = None
    derivative_parent = _absent_derivative_parent()
    installed = None
    rehashes_post_install = None
    rehashes_pre_launch = None
    client_preflight = None
    tls_evidence = None
    daemon_id = None
    daemon_ready = False
    daemon_terminal = None

    def finish_daemon():
        nonlocal daemon_terminal
        if daemon_id is None or daemon_terminal is not None:
            return
        before = _proxy_daemon_state(engine, daemon_id, secrets)
        daemon_terminal = {'container_id': daemon_id, 'ready_observed': daemon_ready,
                           'before_stop': before, 'after_stop': None, 'stop_requested': False,
                           'stop_succeeded': False, 'unexpected_death': None,
                           'logs': {'available': False, 'returncode': None, 'timed_out': None,
                                    'stdout_truncated': None, 'stderr_truncated': None, 'error': None},
                           'errors': []}
        errors = daemon_terminal['errors']
        if not before['available']:
            errors.append(before['error'])
        else:
            daemon_terminal['unexpected_death'] = daemon_ready and not before['state']['Running']
            if daemon_terminal['unexpected_death']:
                lifecycle.append('daemon exited after readiness')
        if not before['available'] or before['state']['Running']:
            daemon_terminal['stop_requested'] = True
            try:
                engine.stop(daemon_id, labels)
                daemon_terminal['stop_succeeded'] = True
            except (DockerError, OSError, ValueError, IndexError, TypeError) as error:
                cleanup.append('daemon stop failed (' + type(error).__name__ + ')')
            after = _proxy_daemon_state(engine, daemon_id, secrets)
            daemon_terminal['after_stop'] = after
            if not after['available']:
                errors.append(after['error'])
            elif after['state']['Running'] and daemon_terminal['stop_succeeded']:
                cleanup.append('daemon still running after stop')
        try:
            diagnosis = engine.command(['logs', daemon_id], timeout=10, check=False)
            logs = daemon_terminal['logs']
            logs.update({'returncode': diagnosis.returncode, 'timed_out': diagnosis.timed_out,
                         'stdout_truncated': diagnosis.stdout_truncated,
                         'stderr_truncated': diagnosis.stderr_truncated})
            _write_stage_log(output / 'daemon.stdout.log', redact_text(diagnosis.stdout, diagnosis.stdout_truncated, secrets))
            _write_stage_log(output / 'daemon.stderr.log', redact_text(diagnosis.stderr, diagnosis.stderr_truncated, secrets))
            logs['available'] = not diagnosis.returncode and not diagnosis.timed_out
            if not logs['available']:
                logs['error'] = 'daemon logs unavailable'
                errors.append(logs['error'])
            stages.append({'phase': 'daemon-diagnosis', **logs})
        except (DockerError, OSError, ValueError) as error:
            daemon_terminal['logs']['error'] = 'daemon logs unavailable (' + type(error).__name__ + ')'
            errors.append(daemon_terminal['logs']['error'])
        if errors:
            lifecycle.append('daemon terminal evidence unavailable')

    try:
        with tempfile.TemporaryDirectory(prefix='p11lab-proxy-', dir=staging_parent(output)) as workspace:
            work = Path(workspace)
            if spec.installed_prefix is not None:
                installed = verified_client
            else:
                installed = install_native_client_bundle(spec.client_artifact, work / 'client-prefix',
                                                         environment=spec.environment, channel=spec.channel,
                                                         expected_proxy_identity=spec.expected_proxy_identity)
            if installed is None:
                raise ValueError('proxy client installation is missing')
            shim = installed.prefix / 'payload' / CLIENT_MODULE
            if ',' in str(shim):
                raise ValueError('Docker bind mount paths cannot contain commas')
            rehashes_post_install = _rehash_launch_bytes(installed.prefix)
            client_preflight = preflight_native_client(installed.prefix, installed.manifest,
                                                       expected_proxy_identity=spec.expected_proxy_identity)
            identity_options = ['--user', f'{os.getuid()}:{os.getgid()}', '--network', 'none', '--read-only',
                                '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                                '--tmpfs', '/tmp:rw,nosuid,nodev']
            identity = engine.create(spec.artifact.reference, ('proxy-build',), identity_options,
                                     labels, 'p11lab-' + run_id + '-identity')
            owned.append(('container', identity))
            built = engine.execute(identity, max(.01, deadline - time.monotonic()), lambda: interrupted_signal)
            stages.append({'phase': 'proxy-build', 'container_id': identity, 'returncode': built.returncode,
                           'timed_out': built.timed_out, 'stdout_truncated': built.stdout_truncated,
                           'stderr_truncated': built.stderr_truncated})
            if built.returncode or built.timed_out or interrupted_signal:
                raise ValueError('daemon proxy identity is unavailable')
            parent_evidence = _derivative_parent_evidence(observed_daemon)
            daemon_image = {'selected': spec.artifact.reference,
                            'observed': observed_daemon['Id']}
            if parent_evidence is not None:
                daemon_image['parent'] = parent_evidence
            try:
                build_identity = check_proxy_identities(
                    json.loads(built.stdout), installed.manifest, expected=spec.expected_proxy_identity,
                    launch_rehashes=rehashes_post_install, daemon_image=daemon_image)
            except ValueError:
                lifecycle.append('proxy identity failed')
            derivative_parent = _derivative_parent_receipt(observed_daemon)
            material = proxy_tls.create_test_tls(work / 'tls', (DAEMON_DNS, 'localhost', '127.0.0.1'))
            (work / 'proxy.toml').write_text(render_proxy_toml(module_path=descriptor['module_path']))
            (work / 'proxy.toml').chmod(0o644)
            tls_evidence = {'server_names': material['server_names'], 'openssl_version': material['openssl_version'],
                            'server': material['evidence']['server'], 'client': material['evidence']['client'],
                            'cert_sha256': {name: proxy_tls.cert_sha256(Path(material[name]))
                                            for name in ('ca_cert', 'server_cert', 'client_cert')}}
            inputs, mounts, envfile = stage_credential_inputs(spec, descriptor, credentials, work)
            state_box = {}
            try:
                prepare_state_mount(spec, engine, run_id, labels, owned, state_box)
            finally:
                state_mount = state_box.get('state_mount')
                state_directory = state_box.get('state_directory')
                state_ownership = state_box.get('state_ownership')
            base = ['--user', f'{os.getuid()}:{os.getgid()}', '--read-only', '--cap-drop', 'ALL',
                    '--security-opt', 'no-new-privileges',
                    '--tmpfs', f'/run/p11lab:rw,nosuid,nodev,uid={os.getuid()},gid={os.getgid()},mode=0700',
                    '--tmpfs', '/tmp:rw,nosuid,nodev',
                    '--env-file', str(envfile), *mounts]
            # Only daemon-side stages mount token state; the external consumer
            # reaches the token exclusively through the shim transport.
            state_options = ['--mount', state_mount]
            proceed = not lifecycle and not interrupted_signal and time.monotonic() < deadline

            def redact(text, truncated):
                return redact_text(text, truncated, secrets)

            if proceed:
                network = _create_proxy_network(engine, 'p11lab-proxy-' + run_id, labels)
                owned.append(('network', network))
                init_id = engine.create(spec.artifact.reference, ('init',), [*base, *state_options, '--network', 'none'],
                                        labels, 'p11lab-' + run_id + '-init')
                owned.append(('container', init_id))
                result = engine.execute(init_id, max(.01, deadline - time.monotonic()), lambda: interrupted_signal)
                (output / 'init.stdout.log').write_text(redact(result.stdout, result.stdout_truncated))
                (output / 'init.stderr.log').write_text(redact(result.stderr, result.stderr_truncated))
                stages.append({'phase': 'init', 'container_id': init_id, 'returncode': result.returncode,
                               'timed_out': result.timed_out, 'stdout_truncated': result.stdout_truncated,
                               'stderr_truncated': result.stderr_truncated})
                timed_out = timed_out or result.timed_out
                if result.returncode:
                    lifecycle.append('init failed')
                    proceed = False
                elif result.timed_out or interrupted_signal:
                    proceed = False
            if proceed:
                daemon_options = [*base, *state_options, '--network', network, '--network-alias', DAEMON_DNS,
                                  '--mount', _bind_mount(material["ca_cert"], f'{DAEMON_TLS_DIR}/ca.crt', readonly=True),
                                  '--mount', _bind_mount(material["server_cert"], f'{DAEMON_TLS_DIR}/server.crt', readonly=True),
                                  '--mount', _bind_mount(material["server_key"], f'{DAEMON_TLS_DIR}/server.key', readonly=True),
                                  '--mount', _bind_mount(work / "proxy.toml", PROXY_TOML_PATH, readonly=True)]
                if host:
                    daemon_options.extend(['--publish', f'127.0.0.1::{PROXY_PORT}'])
                try:
                    daemon_id = engine.create(spec.artifact.reference, ('daemon', PROXY_TOML_PATH), daemon_options,
                                              labels, 'p11lab-' + run_id + '-daemon')
                except DockerError as error:
                    if error.resource is not None and error.resource[0] == 'container':
                        daemon_id = error.resource[1]
                    raise
                owned.append(('container', daemon_id))
                engine.command(['start', daemon_id], timeout=max(.01, deadline - time.monotonic()))
                stages.append({'phase': 'daemon-start', 'container_id': daemon_id, 'started': True})
                if host:
                    port = engine.command(['port', daemon_id, str(PROXY_PORT)],
                                          timeout=max(.01, deadline - time.monotonic()))
                    published = port.stdout.strip().splitlines()
                    if len(published) != 1 or not published[0].startswith('127.0.0.1:'):
                        raise DockerError('proxy port publication is not loopback-only')
                    endpoint = f'https://127.0.0.1:{published[0].removeprefix("127.0.0.1:")}'
                else:
                    endpoint = f'https://{DAEMON_DNS}:{PROXY_PORT}'
            if proceed:
                # The context-free probe runs in a container on the owned
                # network, so it always uses the daemon DNS name; only the
                # host application uses the published loopback port.
                health_endpoint = f'https://{DAEMON_DNS}:{PROXY_PORT}'
                health_argv = ('cli', '--endpoint', health_endpoint,
                               '--tls-ca-cert', f'{CLIENT_TLS_DIR}/ca.crt',
                               '--tls-client-cert', f'{CLIENT_TLS_DIR}/client.crt',
                               '--tls-client-key', f'{CLIENT_TLS_DIR}/client.key', 'health')
                health_options = ['--user', f'{os.getuid()}:{os.getgid()}', '--network', network, '--read-only',
                                  '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                                  '--tmpfs', '/tmp:rw,nosuid,nodev',
                                  '--mount', _bind_mount(material["ca_cert"], f'{CLIENT_TLS_DIR}/ca.crt', readonly=True),
                                  '--mount', _bind_mount(material["client_cert"], f'{CLIENT_TLS_DIR}/client.crt', readonly=True),
                                  '--mount', _bind_mount(material["client_key"], f'{CLIENT_TLS_DIR}/client.key', readonly=True)]
                health_id = engine.create(spec.artifact.reference, health_argv, health_options,
                                          labels, 'p11lab-' + run_id + '-health')
                owned.append(('container', health_id))
                attempts, health = 0, None
                health_deadline = min(deadline, time.monotonic() + 30)
                while not interrupted_signal and time.monotonic() < health_deadline:
                    attempts += 1
                    health = engine.execute(health_id, max(.01, min(10, health_deadline - time.monotonic())),
                                            lambda: interrupted_signal)
                    if health.returncode == 0 or interrupted_signal:
                        break
                    time.sleep(1)
                stages.append({'phase': 'proxy-health', 'container_id': health_id, 'attempts': attempts,
                               'returncode': health.returncode if health else None,
                               'timed_out': health.timed_out if health else False,
                               'stdout_truncated': health.stdout_truncated if health else False,
                               'stderr_truncated': health.stderr_truncated if health else False})
                (output / 'proxy-health.stdout.log').write_text(redact(health.stdout, health.stdout_truncated) if health else '')
                (output / 'proxy-health.stderr.log').write_text(redact(health.stderr, health.stderr_truncated) if health else '')
                if health is None or health.returncode:
                    lifecycle.append('proxy health failed')
                    proceed = False
                elif interrupted_signal or time.monotonic() >= deadline:
                    timed_out = not bool(interrupted_signal)
                    proceed = False
                else:
                    daemon_ready = True
            if proceed and not host:
                # Re-verify launch bytes immediately before application launch;
                # drift after the post-install rehash refuses the launch.
                rehashes_pre_launch = _rehash_launch_bytes(installed.prefix)
                if rehashes_pre_launch != rehashes_post_install:
                    lifecycle.append('launch bytes changed before application launch')
                    proceed = False
            if proceed and not host:
                # The consumer runs exactly the caller argv: argv[0] overrides
                # any baked image entrypoint so provider-derived consumers
                # cannot reinterpret the application command.
                consumer_options = [*base, '--entrypoint', spec.argv[0], '--network', network,
                                    '--mount', _bind_mount(cwd, '/workspace'),
                                    '--mount', _bind_mount(output, '/p11lab-output'),
                                    '--mount', _bind_mount(shim, CLIENT_SHIM_PATH, readonly=True),
                                    '--mount', _bind_mount(material["ca_cert"], f'{CLIENT_TLS_DIR}/ca.crt', readonly=True),
                                    '--mount', _bind_mount(material["client_cert"], f'{CLIENT_TLS_DIR}/client.crt', readonly=True),
                                    '--mount', _bind_mount(material["client_key"], f'{CLIENT_TLS_DIR}/client.key', readonly=True),
                                    '--workdir', '/workspace', '--env', 'P11LAB_OUTPUT_DIR=/p11lab-output',
                                    '--env', f'P11LAB_MODULE={CLIENT_SHIM_PATH}',
                                    '--env', f'{proxy_tls.ENDPOINT_VAR}={endpoint}',
                                    '--env', f'{proxy_tls.CLIENT_ENV_VARS[0]}={CLIENT_TLS_DIR}/ca.crt',
                                    '--env', f'{proxy_tls.CLIENT_ENV_VARS[1]}={CLIENT_TLS_DIR}/client.crt',
                                    '--env', f'{proxy_tls.CLIENT_ENV_VARS[2]}={CLIENT_TLS_DIR}/client.key',
                                    '--env', f'{proxy_tls.CONNECT_TIMEOUT_VAR}=10']
                consumer_id = engine.create(spec.consumer_artifact.reference, spec.argv[1:], consumer_options,
                                            labels, 'p11lab-' + run_id + '-app')
                owned.append(('container', consumer_id))
                result = engine.execute(consumer_id, max(.01, deadline - time.monotonic()), lambda: interrupted_signal)
                app_returncode = result.returncode
                app_completed = not result.timed_out and not interrupted_signal
                timed_out = timed_out or result.timed_out
                stages.append({'phase': 'application', 'container_id': consumer_id, 'returncode': result.returncode,
                               'timed_out': result.timed_out, 'stdout_truncated': result.stdout_truncated,
                               'stderr_truncated': result.stderr_truncated})
                _write_stage_log(output / 'application.stdout.log', redact(result.stdout, result.stdout_truncated))
                _write_stage_log(output / 'application.stderr.log', redact(result.stderr, result.stderr_truncated))
                if result.timed_out or interrupted_signal:
                    proceed = False
            if proceed and host:
                # Re-verify launch bytes immediately before application launch;
                # drift after the post-install rehash refuses the launch.
                rehashes_pre_launch = _rehash_launch_bytes(installed.prefix)
                if rehashes_pre_launch != rehashes_post_install:
                    lifecycle.append('launch bytes changed before application launch')
                    proceed = False
            if proceed and host:
                host_env = {k: v for k, v in os.environ.items()
                            if not k.startswith(('P11LAB_', 'SOFTHSM', 'LD_', 'PKCS11_PROXY_'))}
                host_env.update({k: v for k, v in spec.inputs.items() if k in descriptor['inputs']})
                host_env.update(proxy_tls.build_consumer_env(endpoint=endpoint, ca_cert=material['ca_cert'],
                                                             client_cert=material['client_cert'],
                                                             client_key=material['client_key']))
                host_env.update({proxy_tls.CONNECT_TIMEOUT_VAR: '10', 'P11LAB_SHIM': str(shim),
                                'P11LAB_MODULE': str(shim), 'P11LAB_OUTPUT_DIR': str(output)})
                status, stage_timeout, logs = _run_proxy_host_app(
                    spec.argv, cwd=cwd, env=host_env, output=output,
                    timeout=max(.01, deadline - time.monotonic()),
                    interrupted=lambda: interrupted_signal, secrets=secrets)
                app_returncode = status
                app_completed = not stage_timeout and not interrupted_signal
                timed_out = timed_out or stage_timeout
                stages.append({'phase': 'application', 'host': True, 'returncode': status,
                               'timed_out': stage_timeout, **logs})
                if logs.get('log_errors'):
                    lifecycle.append('application log evidence incomplete')
                if not logs['drain_complete'] or logs['stragglers_remaining'] or logs['supervision_errors']:
                    app_completed = False
                    lifecycle.append('application supervision incomplete')
                    proceed = False
                if stage_timeout or interrupted_signal:
                    proceed = False
            if proceed:
                # The live daemon holds the state lease; post-health runs in
                # a fresh container on the same state and must take that
                # lease, so the daemon is reaped first. A stop failure fails
                # closed: post-health is skipped and the run reports it.
                finish_daemon()
                if cleanup:
                    proceed = False
                else:
                    try:
                        engine.remove('container', daemon_id, labels)
                    except (DockerError, OSError, ValueError) as error:
                        cleanup.append('daemon removal failed (' + type(error).__name__ + ')')
                        proceed = False
                    else:
                        owned.remove(('container', daemon_id))
                        stages.append({'phase': 'daemon-stop', 'container_id': daemon_id, 'stopped': True})
            if proceed:
                post_id = engine.create(spec.artifact.reference, ('health',), [*base, *state_options, '--network', 'none'],
                                        labels, 'p11lab-' + run_id + '-post')
                owned.append(('container', post_id))
                result = engine.execute(post_id, max(.01, deadline - time.monotonic()), lambda: interrupted_signal)
                stages.append({'phase': 'post-health', 'container_id': post_id, 'returncode': result.returncode,
                               'timed_out': result.timed_out, 'stdout_truncated': result.stdout_truncated,
                               'stderr_truncated': result.stderr_truncated})
                timed_out = timed_out or result.timed_out
                _write_stage_log(output / 'post-health.stdout.log', redact(result.stdout, result.stdout_truncated))
                _write_stage_log(output / 'post-health.stderr.log', redact(result.stderr, result.stderr_truncated))
                if result.returncode:
                    lifecycle.append('post-health failed')
                elif result.timed_out or interrupted_signal:
                    timed_out = timed_out or result.timed_out
            elif not lifecycle and (interrupted_signal or time.monotonic() >= deadline):
                timed_out = not bool(interrupted_signal)
                lifecycle.append('interrupted' if interrupted_signal else 'timeout')
    except (DockerError, OSError, ValueError) as error:
        if isinstance(error, DockerError):
            if error.resource is not None:
                owned.append(error.resource)
            if error.uncertain_resource is not None:
                uncertain.append(error.uncertain_resource)
                cleanup.append('creation status unknown: ' + ' '.join(error.uncertain_resource))
        if isinstance(error, FileExistsError):
            lifecycle.append('stage log evidence incomplete: output path already exists')
        lifecycle.append('runner operation failed (' + type(error).__name__ + ')')
    finally:
        finish_daemon()
        for kind, identity in reversed(owned):
            try:
                engine.remove(kind, identity, labels)
            except (DockerError, OSError, ValueError):
                cleanup.append(kind + ' cleanup failed: ' + identity)
        if state_directory is not None and not cleanup:
            try:
                shutil.rmtree(state_directory)
            except OSError:
                cleanup.append('private state directory cleanup failed')
        for sig, handler in old_handlers.items():
            signal.signal(sig, handler)
    exit_code = compute_exit_code(app_returncode=app_returncode, app_completed=app_completed,
                                  interrupted_signal=interrupted_signal, timed_out=timed_out,
                                  lifecycle=lifecycle, cleanup=cleanup)
    receipt_path = output / 'receipt.json'
    record = {'schema_version': 1, 'run_id': run_id, 'attempt_id': attempt_id,
              'environment': spec.environment, 'channel': spec.channel, 'mode': 'proxy',
              'execution_location': spec.execution_location,
              'artifacts': {'provider': asdict(spec.artifact),
                            'consumer': asdict(spec.consumer_artifact) if spec.consumer_artifact else None,
                            'client': asdict(spec.client_artifact)},
              'image_observation': {'daemon': {'Id': observed_daemon['Id'], 'Descriptor': observed_daemon.get('Descriptor'),
                                              'platform': spec.artifact.platform},
                                    'consumer': ({'Id': observed_consumer['Id'],
                                                  'Descriptor': observed_consumer.get('Descriptor'),
                                                  'platform': spec.consumer_artifact.platform}
                                                 if observed_consumer else None)},
              'proxy': {'derivative': build_identity,
                        'derivative_parent': derivative_parent,
                        'expected_proxy_identity': (
                            spec.expected_proxy_identity.to_dict()
                            if spec.expected_proxy_identity is not None
                            else {'selected': 'fixed-default'}),
                        'launch_rehashes': {'post_install': rehashes_post_install,
                                            'pre_launch': rehashes_pre_launch},
                        'client': installed.manifest['source']['proxy'] if installed else None,
                        'client_manifest_sha256': installed.manifest_sha256 if installed else None,
                        'installation': ({'prefix': str(installed.prefix), 'temporary': spec.installed_prefix is None,
                                          'receipt_sha256': installed.receipt_sha256, 'retained': installed.prefix.exists()}
                                         if installed else None),
                        'client_preflight': ({'loader': client_preflight['loader'],
                                              'architecture': client_preflight['architecture'],
                                              'cli_version': client_preflight['cli_version'],
                                              'resolved': client_preflight['closure'][next(iter(client_preflight['closure']))]['resolved']}
                                             if client_preflight else None),
                        'endpoint': endpoint, 'health_endpoint': f'https://{DAEMON_DNS}:{PROXY_PORT}',
                        'network': network, 'tls': tls_evidence, 'daemon_terminal': daemon_terminal},
              'execution': ({'container_cwd': '/workspace', 'output_mount': '/p11lab-output',
                             'uid_gid': f'{os.getuid()}:{os.getgid()}',
                             'capabilities': [], 'network': network, 'root_readonly': True,
                             'writable': ['/var/lib/p11lab', '/run/p11lab', '/tmp', '/workspace', '/p11lab-output'],
                             'argv_count': len(spec.argv)}
                            if not host else
                            {'cwd': str(cwd), 'endpoint': endpoint,
                             'uid_gid': f'{os.getuid()}:{os.getgid()}', 'argv_count': len(spec.argv)}),
              **receipt_outcome_fields(spec=spec, descriptor=descriptor, state_directory=state_directory,
                                       state_ownership=state_ownership, stages=stages, owned=owned,
                                       uncertain=uncertain, app_returncode=app_returncode,
                                       app_completed=app_completed, lifecycle=lifecycle, cleanup=cleanup,
                                       exit_code=exit_code, timed_out=timed_out,
                                       interrupted_signal=interrupted_signal)}
    write_receipt(receipt_path, record)
    return RunResult(app_returncode, tuple(lifecycle), tuple(cleanup), exit_code, receipt_path)
