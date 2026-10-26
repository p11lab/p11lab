"""Owned direct/provider lifecycle. Future transports use the same RunResult."""
from dataclasses import asdict
from pathlib import Path
import json
import re
import os
import shutil
import signal
import tempfile
import threading
import time
from uuid import uuid4

from .catalog import load_environment
from .docker import Docker, DockerError
from .models import RunSpec, RunResult
from .receipts import write_receipt
from .secrets import snapshot_credentials
from .process import supervised_exec, write_process_logs


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


def redact_text(text, truncated, secrets):
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
    for secret in sorted(secrets, key=len, reverse=True):
        text = text.replace(secret, '[REDACTED]')
    return text


def compute_exit_code(*, app_returncode, app_completed, interrupted_signal, timed_out,
                      lifecycle, cleanup):
    """One exit-code formula for the direct and proxy runners.

    A completed application return code wins; interruption, timeout and
    runner errors follow in that precedence; 0 requires a clean run.
    """
    return (app_returncode if app_completed and app_returncode else
            128 + interrupted_signal if interrupted_signal else 124 if timed_out else
            app_returncode if app_returncode else 1 if lifecycle or cleanup else 0)


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
                mounts.extend(['--mount', f'type=bind,src={snapshot},dst={destination},readonly'])
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
        box['state_mount'] = f'type=bind,src={state},dst=/var/lib/p11lab'
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
    credentials, secrets = snapshot_credentials(spec.inputs, descriptor)
    engine = Docker()
    observed = engine.image(spec.artifact)  # no resource created before preflight
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
    try:
        with tempfile.TemporaryDirectory(prefix='p11lab-input-') as private:
            inputs, mounts, envfile = stage_credential_inputs(spec, descriptor, credentials, Path(private))
            state_box = {}
            try:
                prepare_state_mount(spec, engine, run_id, labels, owned, state_box)
            finally:
                state_mount = state_box.get('state_mount')
                state_directory = state_box.get('state_directory')
                state_ownership = state_box.get('state_ownership')
            options = ['--user', f'{os.getuid()}:{os.getgid()}', '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                       '--tmpfs', f'/run/p11lab:rw,nosuid,nodev,uid={os.getuid()},gid={os.getgid()},mode=0700', '--tmpfs', '/tmp:rw,nosuid,nodev',
                       '--mount', state_mount, '--env-file', str(envfile), *mounts]
            for index, argv in enumerate((('init',), ('health',), ('exec', '--', *spec.argv), ('health',))):
                phase = ('init', 'ready', 'application', 'post-health')[index]
                if interrupted_signal or time.monotonic() >= deadline:
                    timed_out = not bool(interrupted_signal)
                    lifecycle.append('interrupted' if interrupted_signal else 'timeout')
                    break
                stage_options = list(options)
                if phase == 'application':
                    stage_options.extend(['--mount', f'type=bind,src={cwd},dst=/workspace',
                                          '--mount', f'type=bind,src={output},dst=/p11lab-output',
                                          '--workdir', '/workspace', '--env', 'P11LAB_OUTPUT_DIR=/p11lab-output'])
                identity = engine.create(spec.artifact.reference, argv, stage_options, labels, 'p11lab-' + run_id + '-' + str(index))
                owned.append(('container', identity))
                result = engine.execute(identity, max(.01, deadline - time.monotonic()), lambda: interrupted_signal)
                if phase == 'application':
                    app_returncode = result.returncode
                    app_completed = not result.timed_out and not interrupted_signal
                timed_out = timed_out or result.timed_out
                (output / (phase + '.stdout.log')).write_text(redact_text(result.stdout, result.stdout_truncated, secrets))
                (output / (phase + '.stderr.log')).write_text(redact_text(result.stderr, result.stderr_truncated, secrets))
                stages.append({'phase': phase, 'container_id': identity, 'returncode': result.returncode,
                               'timed_out': result.timed_out, 'stdout_truncated': result.stdout_truncated,
                               'stderr_truncated': result.stderr_truncated})
                if phase != 'application' and result.returncode:
                    lifecycle.append(phase + ' failed')
                    break
                if result.timed_out or interrupted_signal:
                    break
    except (DockerError, OSError, ValueError) as error:
        # Do not expose subprocess arguments, environment or credential paths.
        if isinstance(error, DockerError):
            if error.resource is not None:
                owned.append(error.resource)
            if error.uncertain_resource is not None:
                uncertain.append(error.uncertain_resource)
                cleanup.append('creation status unknown: ' + ' '.join(error.uncertain_resource))
        lifecycle.append('runner operation failed (' + type(error).__name__ + ')')
    finally:
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
    write_receipt(receipt_path, record)
    return RunResult(app_returncode, tuple(lifecycle), tuple(cleanup), exit_code, receipt_path)


PROXY_PORT = 7512
PROXY_TOML_PATH = '/etc/p11lab/proxy.toml'
DAEMON_TLS_DIR = '/run/p11lab-tls'
CLIENT_TLS_DIR = '/run/p11lab-client-tls'
CLIENT_SHIM_PATH = '/run/p11lab-client/libpkcs11_proxy_ng_shim.so'
DAEMON_DNS = 'provider-daemon'


def render_proxy_toml(*, module_path: str) -> str:
    """Exact daemon configuration per the public transport contract.

    lease_seconds=1 reclaims contexts orphaned by short-lived helpers that
    exit without C_Finalize (observed: checker preflight). Live contexts are
    unaffected: reaping needs an expired lease plus a new admission, and
    max_contexts=1 still refuses a second live context.
    """
    if not module_path.startswith('/') or any(c in module_path for c in '\0\n\r"\\'):
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


def check_proxy_identities(derivative: dict, client_manifest: dict) -> dict:
    """Require daemon derivative and client bundle to share pinned proxy components."""
    from .tls import PROXY_CARGO_LOCK_SHA256, PROXY_SOURCE_REVISION
    if (not isinstance(derivative, dict) or derivative.get('schema_version') != 1
            or derivative.get('source_revision') != PROXY_SOURCE_REVISION
            or derivative.get('cargo_lock_sha256') != PROXY_CARGO_LOCK_SHA256):
        raise ValueError('daemon derivative is not the pinned proxy build')
    binaries = derivative.get('binaries', {})
    proxy = client_manifest.get('source', {}).get('proxy', {})
    if (proxy.get('source_revision') != derivative['source_revision']
            or proxy.get('cargo_lock_sha256') != derivative['cargo_lock_sha256']
            or proxy.get('cli_sha256') != binaries.get('pkcs11-proxy-ng-cli')):
        raise ValueError('client bundle does not match the daemon proxy build')
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
    evidence.update(write_process_logs(owner, output, 'application', secrets))
    return status, timed_out, evidence


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
                                                  channel=spec.channel, platform=spec.client_artifact.platform)
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
    installed = None
    client_preflight = None
    tls_evidence = None
    try:
        with tempfile.TemporaryDirectory(prefix='p11lab-proxy-', dir=staging_parent(output)) as workspace:
            work = Path(workspace)
            if spec.installed_prefix is not None:
                installed = verified_client
            else:
                installed = install_native_client_bundle(spec.client_artifact, work / 'client-prefix',
                                                         environment=spec.environment, channel=spec.channel)
            shim = installed.prefix / 'payload' / CLIENT_MODULE
            if ',' in str(shim):
                raise ValueError('Docker bind mount paths cannot contain commas')
            client_preflight = preflight_native_client(installed.prefix, installed.manifest)
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
            try:
                build_identity = check_proxy_identities(json.loads(built.stdout), installed.manifest)
            except ValueError:
                lifecycle.append('proxy identity failed')
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
            daemon_id = None
            if proceed:
                daemon_options = [*base, *state_options, '--network', network, '--network-alias', DAEMON_DNS,
                                  '--mount', f'type=bind,src={material["ca_cert"]},dst={DAEMON_TLS_DIR}/ca.crt,readonly',
                                  '--mount', f'type=bind,src={material["server_cert"]},dst={DAEMON_TLS_DIR}/server.crt,readonly',
                                  '--mount', f'type=bind,src={material["server_key"]},dst={DAEMON_TLS_DIR}/server.key,readonly',
                                  '--mount', f'type=bind,src={work / "proxy.toml"},dst={PROXY_TOML_PATH},readonly']
                if host:
                    daemon_options.extend(['--publish', f'127.0.0.1::{PROXY_PORT}'])
                daemon_id = engine.create(spec.artifact.reference, ('daemon', PROXY_TOML_PATH), daemon_options,
                                          labels, 'p11lab-' + run_id + '-daemon')
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
                                  '--mount', f'type=bind,src={material["ca_cert"]},dst={CLIENT_TLS_DIR}/ca.crt,readonly',
                                  '--mount', f'type=bind,src={material["client_cert"]},dst={CLIENT_TLS_DIR}/client.crt,readonly',
                                  '--mount', f'type=bind,src={material["client_key"]},dst={CLIENT_TLS_DIR}/client.key,readonly']
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
                    diagnosis = engine.command(['logs', daemon_id], timeout=10, check=False)
                    (output / 'daemon.stdout.log').write_text(redact(diagnosis.stdout, diagnosis.stdout_truncated))
                    (output / 'daemon.stderr.log').write_text(redact(diagnosis.stderr, diagnosis.stderr_truncated))
                    stages.append({'phase': 'daemon-diagnosis', 'stdout_truncated': diagnosis.stdout_truncated,
                                   'stderr_truncated': diagnosis.stderr_truncated})
                elif interrupted_signal or time.monotonic() >= deadline:
                    timed_out = not bool(interrupted_signal)
                    proceed = False
            if proceed and not host:
                # The consumer runs exactly the caller argv: argv[0] overrides
                # any baked image entrypoint so provider-derived consumers
                # cannot reinterpret the application command.
                consumer_options = [*base, '--entrypoint', spec.argv[0], '--network', network,
                                    '--mount', f'type=bind,src={cwd},dst=/workspace',
                                    '--mount', f'type=bind,src={output},dst=/p11lab-output',
                                    '--mount', f'type=bind,src={shim},dst={CLIENT_SHIM_PATH},readonly',
                                    '--mount', f'type=bind,src={material["ca_cert"]},dst={CLIENT_TLS_DIR}/ca.crt,readonly',
                                    '--mount', f'type=bind,src={material["client_cert"]},dst={CLIENT_TLS_DIR}/client.crt,readonly',
                                    '--mount', f'type=bind,src={material["client_key"]},dst={CLIENT_TLS_DIR}/client.key,readonly',
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
                (output / 'application.stdout.log').write_text(redact(result.stdout, result.stdout_truncated))
                (output / 'application.stderr.log').write_text(redact(result.stderr, result.stderr_truncated))
                stages.append({'phase': 'application', 'container_id': consumer_id, 'returncode': result.returncode,
                               'timed_out': result.timed_out, 'stdout_truncated': result.stdout_truncated,
                               'stderr_truncated': result.stderr_truncated})
                if result.timed_out or interrupted_signal:
                    proceed = False
            elif proceed:
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
                try:
                    engine.remove('container', daemon_id, labels)
                except (DockerError, OSError, ValueError) as error:
                    cleanup.append('daemon stop failed (' + type(error).__name__ + ')')
                    proceed = False
                else:
                    owned.remove(('container', daemon_id))
                    stages.append({'phase': 'daemon-stop', 'container_id': daemon_id, 'stopped': True})
            if proceed:
                post_id = engine.create(spec.artifact.reference, ('health',), [*base, *state_options, '--network', 'none'],
                                        labels, 'p11lab-' + run_id + '-post')
                owned.append(('container', post_id))
                result = engine.execute(post_id, max(.01, deadline - time.monotonic()), lambda: interrupted_signal)
                (output / 'post-health.stdout.log').write_text(redact(result.stdout, result.stdout_truncated))
                (output / 'post-health.stderr.log').write_text(redact(result.stderr, result.stderr_truncated))
                stages.append({'phase': 'post-health', 'container_id': post_id, 'returncode': result.returncode,
                               'timed_out': result.timed_out, 'stdout_truncated': result.stdout_truncated,
                               'stderr_truncated': result.stderr_truncated})
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
        lifecycle.append('runner operation failed (' + type(error).__name__ + ')')
    finally:
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
                        'network': network, 'tls': tls_evidence},
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
