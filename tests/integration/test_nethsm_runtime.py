# SPDX-License-Identifier: Apache-2.0
"""Explicit frozen NetHSM images; no implicit builds or provider-error xfails.

P11LAB_NETHSM_{IMAGES,CONSUMERS,BUILDS,CHECKER_ATTEMPTS,PROXY_ATTEMPTS}
are JSON channel maps. EVIDENCE is a fresh private output directory. Integration
blockers are conditional on exact owning-component failure evidence, never on
native provider behavior. The unchanged generated-key consumer must fail.
"""
import hashlib
import itertools
import json
import os
import subprocess
import time
import uuid
from dataclasses import replace
from pathlib import Path

import pytest

from p11lab.build import BuildError, inventory_text, runtime_inputs, verify_inventory
from p11lab.catalog import load_environment, package_data, validate_build_inputs
from p11lab.identity import artifact_key
from p11lab.models import ArtifactRef, RunSpec
from p11lab.run import run_application

MODULE = '/usr/local/lib/p11lab/libnethsm_pkcs11.so'
IMAGES = json.loads(os.environ.get('P11LAB_NETHSM_IMAGES', '{}'))
CONSUMERS = json.loads(os.environ.get('P11LAB_NETHSM_CONSUMERS', '{}'))
BUILDS = json.loads(os.environ.get('P11LAB_NETHSM_BUILDS', '{}'))
CHECKER_ATTEMPTS = json.loads(os.environ.get('P11LAB_NETHSM_CHECKER_ATTEMPTS', '{}'))
PROXY_ATTEMPTS = json.loads(os.environ.get('P11LAB_NETHSM_PROXY_ATTEMPTS', '{}'))
DAEMONS = json.loads(os.environ.get('P11LAB_NETHSM_PROXIES', '{}'))
CLIENTS = json.loads(os.environ.get('P11LAB_NETHSM_CLIENTS', '{}'))
CALLER = os.environ.get('P11LAB_NETHSM_CALLER', '')
COMMANDS = itertools.count()
PIN = b'operator-passphrase-1'
SO = b'administrator-passphrase-1'


def docker(*args, check=True, env=None):
    argv = ['docker', *map(str, args)]
    result = subprocess.run(argv, capture_output=True, text=True, timeout=180, check=False,
                            env=os.environ | (env or {}))
    evidence = os.environ.get('P11LAB_NETHSM_EVIDENCE')
    if evidence:
        root = Path(evidence) / 'commands'
        root.mkdir(parents=True, exist_ok=True)
        (root / f'{next(COMMANDS):04d}.json').write_text(json.dumps({
            'argv': argv, 'env': {k: '<test secret omitted>' for k in (env or {})},
            'returncode': result.returncode, 'stdout': result.stdout,
            'stderr': result.stderr}, indent=2) + '\n')
    if check:
        assert result.returncode == 0, result.stderr
    return result


@pytest.fixture(params=list(IMAGES) or ['unconfigured'])
def runtime(request, tmp_path):
    if request.param not in IMAGES:
        pytest.skip('explicit NetHSM runtime IDs required')
    channel = request.param
    root = Path(os.environ.get('P11LAB_NETHSM_EVIDENCE', str(tmp_path))) / request.node.name
    root.mkdir(parents=True, exist_ok=False)
    state = root / 'state'
    state.mkdir(mode=0o700)
    secrets = root / 'secrets'
    secrets.mkdir(mode=0o700)
    for name, value in [('pin', PIN), ('so', SO)]:
        (secrets / name).write_bytes(value)
        (secrets / name).chmod(0o600)
    base = ['run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
            '--user', f'{os.getuid()}:{os.getgid()}',
            '--tmpfs', f'/run/p11lab:uid={os.getuid()},gid={os.getgid()},mode=0700',
            '--tmpfs', '/tmp', '--mount', f'type=bind,src={state},dst=/var/lib/p11lab',
            '--mount', f'type=bind,src={secrets},dst=/run/secrets,readonly']
    controls = ['-e', 'P11LAB_LABEL=acceptance', '-e', 'P11LAB_PIN_FILE=/run/secrets/pin',
                '-e', 'P11LAB_SO_PIN_FILE=/run/secrets/so']
    yield channel, root, state, secrets, IMAGES[channel], base, controls
    for child in secrets.iterdir():
        child.unlink()


def as_ref(image):
    return ArtifactRef('docker-local', image, image.removeprefix('sha256:'), 'linux/amd64')


def snapshot(state):
    return {str(p.relative_to(state)): ('symlink', os.readlink(p)) if p.is_symlink()
            else ('file', hashlib.sha256(p.read_bytes()).hexdigest()) if p.is_file()
            else ('directory', None) for p in state.rglob('*')}


def oracle(output):
    result = subprocess.run(['python3', str(package_data('consumer/verify.py')), str(output)],
                            capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    assert 'altered message rejected' in result.stdout
    (output.parent / 'oracle.txt').write_text(result.stdout)


@pytest.mark.parametrize('channel', ['release', 'rolling'])
def test_packaged_inputs_are_closed_and_channels_distinct(channel):
    spec = load_environment('nethsm', channel)
    validate_build_inputs(spec)
    inputs = runtime_inputs(spec)
    expected = {'release': 'fb3f448df6033a6406c9dc034ea729e930fc5fdc',
                'rolling': '49d0a21a83c031ad35f127f21db34de5116d5040'}
    assert inputs['sources'][0]['revision'] == expected[channel]
    assert inputs['patches'] == []
    assert inputs['features']['compile_jobs'] == 2
    assert inputs['features']['crate_count'] == 215
    assert inputs['features']['libc'] == 'musl'
    assert inputs['features']['module_tls'] == 'rustls/ring'
    assert inputs['features']['openssl']['module_static_link'] is False
    assert spec['services'] == ['etcd', 'keyfender']
    assert spec['backend']['simulated'] is True
    assert spec['distribution']['status'] == 'blocked'
    assert inputs['features']['server_input']['image_license_files_present'] == 0
    assert len(inputs['features']['server_input']['copied_binaries']) == 2
    assert [len(inputs['features']['package_inventories'][p]) for p in
            ['base', 'runtime', 'builder']] == [16, 27, 69]
    other = 'rolling' if channel == 'release' else 'release'
    assert artifact_key('runtime', inputs) != artifact_key('runtime', runtime_inputs(load_environment('nethsm', other)))


def test_native_lifecycle_credentials_and_argv(runtime):
    _channel, root, state, secrets, image, base, controls = runtime
    assert json.loads(docker('run', '--rm', '--network', 'none', image, 'describe').stdout)['module_path'] == MODULE
    assert docker(*base, image, 'init', check=False).returncode != 0
    assert list(state.iterdir()) == []
    docker(*base, *controls, image, 'init')
    protected = {p: (state / 'nethsm' / p).read_bytes() for p in ['complete', 'p11nethsm.conf', 'admin', 'unlock']}
    assert PIN not in protected['p11nethsm.conf'] and SO in protected['p11nethsm.conf']
    assert SO == protected['admin'] and protected['unlock'] not in (PIN, SO)
    (secrets / 'pin').write_bytes(b'changed-operator-passphrase')
    (secrets / 'so').write_bytes(b'changed-administrator-passphrase')
    docker(*base, *controls, image, 'init')
    assert protected == {p: (state / 'nethsm' / p).read_bytes() for p in protected}
    health = docker(*base, *controls, image, 'health')
    assert 'native_slot=0 token_present_index=0 label=acceptance server=Operational' in health.stdout
    incompatible = docker(*base, *controls, '-e', 'P11LAB_LABEL=different', image, 'init', check=False)
    assert incompatible.returncode != 0 and 'incompatible' in incompatible.stderr
    result = docker(*base, *controls, image, 'exec', '--', 'sh', '-c',
                    'printf "%s\n" "$P11LAB_MODULE" "$1"; exit 37', 'caller',
                    'literal $argument with spaces', check=False)
    assert result.returncode == 37
    assert result.stdout.splitlines() == [MODULE, 'literal $argument with spaces']
    assert PIN not in protected['complete'] and SO not in protected['complete']
    assert docker(*base, *controls, image, 'exec', '--', 'sh', '-c',
                  'command -v cc make python3 cargo pkcs11-tool; exit 0').stdout == ''
    # Scalar transport and native maximum bounds: argv contains names only.
    other = root / 'scalar-state'
    other.mkdir(mode=0o700)
    scalar_base = [a.replace(f'src={state},', f'src={other},') for a in base]
    docker(*scalar_base, '-e', 'P11LAB_PIN', '-e', 'P11LAB_SO_PIN', image, 'init',
           env={'P11LAB_PIN': 'x' * 200, 'P11LAB_SO_PIN': 'y' * 200})
    docker(*scalar_base, image, 'health')
    for path in (root / 'secrets').iterdir():
        assert path.stat().st_mode & 0o777 == 0o600


def test_persistent_crypto_restart_isolation_and_profile_falsification(runtime):
    channel, root, state, secrets, _image, _base, _controls = runtime
    assert channel in CONSUMERS, 'explicit compatible musl consumer required'
    inputs = {'P11LAB_STATE_DIR': str(state), 'P11LAB_PIN_FILE': str(secrets / 'pin'),
              'P11LAB_SO_PIN_FILE': str(secrets / 'so'), 'P11LAB_LABEL': 'acceptance'}
    argv = ('p11lab-smoke', '--module', MODULE, '--token-label', 'acceptance',
            '--pin-file', '/run/p11lab-input/P11LAB_PIN_FILE', '--output',
            '/p11lab-output/crypto', '--key-mode', 'generated')
    spec = RunSpec('nethsm', channel, 'direct', as_ref(CONSUMERS[channel]), 'provider',
                   None, None, argv, inputs, root / 'generated', root, 180)
    generated = run_application(spec)
    assert generated.app_returncode == 1 and generated.exit_code != 0
    assert not generated.cleanup_errors
    error = (spec.output_dir / 'application.stderr.log').read_text()
    assert 'C_DestroyObject(public cleanup): CK_RV=0x00000060' in error
    # This is a completed provider failure, never a conditional xfail or pass.
    print(f'general-token/{channel}: FALSIFIED; native public cleanup=0x60')
    provision = replace(spec, output_dir=root / 'persistent-create', argv=(
        'p11lab-token', '--module', MODULE, '--token-label', 'acceptance',
        '--pin-file', '/run/p11lab-input/P11LAB_PIN_FILE', '--key-id', '42'))
    result = run_application(provision)
    assert result.exit_code == 0 and not result.cleanup_errors, result
    public = []
    for n in range(2):
        reopened = replace(spec, output_dir=root / f'reopen-{n}', argv=(*argv[:-1], 'existing', '--key-id', '42'))
        result = run_application(reopened)
        assert result.exit_code == 0 and not result.cleanup_errors, result
        oracle(reopened.output_dir / 'crypto')
        public.append((reopened.output_dir / 'crypto/public-key.der').read_bytes())
    assert public[0] == public[1]
    other = root / 'other-state'
    other.mkdir(mode=0o700)
    absent = replace(spec, inputs=inputs | {'P11LAB_STATE_DIR': str(other)},
                     output_dir=root / 'isolated', argv=(*argv[:-1], 'existing', '--key-id', '42'))
    assert run_application(absent).exit_code != 0
    assert (other / 'nethsm/complete').is_file()
    # A failed auth is last: native rate limiting must not contaminate the
    # independent success observations, and no provider retry is inserted.
    (secrets / 'pin').write_bytes(b'wrong-operator-passphrase')
    failed = run_application(replace(spec, output_dir=root / 'wrong-pin'))
    assert failed.app_returncode == 1 and failed.exit_code != 0
    assert 'C_Login: CK_RV=0x00000103' in (root / 'wrong-pin/application.stderr.log').read_text()
    for path in root.rglob('*.log'):
        assert SO not in path.read_bytes() and PIN not in path.read_bytes()


def test_native_credential_and_administrator_model(runtime):
    channel, _root, _state, _secrets, image, base, controls = runtime
    assert channel in CONSUMERS
    consumer = CONSUMERS[channel]
    docker(*base, *controls, image, 'init')
    info = docker(*base, *controls, consumer, 'exec', '--', 'native-proof', 'init')
    assert 'C_InitToken: CK_RV=0x00000054' in info.stdout
    assert 'C_InitPIN: CK_RV=0x00000054' in info.stdout
    assert 'slot=0 count=1' in info.stdout
    good = docker(*base, *controls, consumer, 'exec', '--', 'native-proof', 'login', '/run/secrets/pin')
    assert 'C_Login: CK_RV=0x00000000' in good.stdout
    # An application can select a different config. This deliberate negative
    # native lane omits admin privileges while retaining the same server/user.
    script = ('printf \'log_level: Error\\nslots:\\n  - label: "acceptance"\\n'
              '    operator:\\n      username: "operator"\\n    retries:\\n'
              '      count: 0\\n      delay_seconds: 0\\n    instances:\\n'
              '      - url: "https://127.0.0.1:8443/api/v1"\\n'
              '        danger_insecure_cert: true\\n\' > /tmp/no-admin.conf; '
              'P11NETHSM_CONFIG_FILE=/tmp/no-admin.conf p11lab-smoke --module "$P11LAB_MODULE" '
              '--token-label acceptance --pin-file /run/secrets/pin --output /tmp/no-admin --key-mode generated')
    no_admin = docker(*base, *controls, consumer, 'exec', '--', 'sh', '-c', script, check=False)
    assert no_admin.returncode == 1
    assert 'C_GenerateKeyPair: CK_RV=0x00000006' in no_admin.stderr
    assert 'NotLoggedIn(Administrator)' in no_admin.stderr


@pytest.mark.parametrize('damage', [
    'missing-db', 'empty-db', 'missing-wal', 'missing-admin', 'missing-unlock',
    'missing-marker', 'marker-extra-lf', 'config-drift', 'hidden-file', 'data-link', 'busy-init'])
def test_damage_refused_before_native_launch(runtime, damage):
    _channel, _root, state, _secrets, image, base, controls = runtime
    docker(*base, *controls, image, 'init')
    owned = state / 'nethsm'
    db = owned / 'data/member/snap/db'
    if damage == 'missing-db':
        db.unlink()
    elif damage == 'empty-db':
        db.write_bytes(b'')
    elif damage == 'missing-wal':
        for file in (owned / 'data/member/wal').iterdir():
            file.unlink()
    elif damage == 'missing-admin':
        (owned / 'admin').unlink()
    elif damage == 'missing-unlock':
        (owned / 'unlock').unlink()
    elif damage == 'missing-marker':
        (owned / 'complete').unlink()
    elif damage == 'marker-extra-lf':
        with (owned / 'complete').open('ab') as file:
            file.write(b'\n')
    elif damage == 'config-drift':
        with (owned / 'p11nethsm.conf').open('ab') as file:
            file.write(b'\n')
    elif damage == 'hidden-file':
        (owned / 'data/.foreign').write_bytes(b'foreign')
    elif damage == 'data-link':
        db.rename(db.parent / 'original')
        db.symlink_to('original')
    else:
        (state / '.init-lock').mkdir()
    before = snapshot(state)
    for operation in ['init', 'health', 'exec']:
        argv = [operation] if operation != 'exec' else ['exec', '--', 'sh', '-c', 'echo APP-RAN']
        result = docker(*base, *controls, image, *argv, check=False)
        assert result.returncode != 0 and 'APP-RAN' not in result.stdout
        assert snapshot(state) == before, (damage, operation)


@pytest.mark.parametrize('bad', ['absent-pin', 'absent-so', 'empty', 'multiline', 'nul',
                                'too-large', 'conflict', 'too-short', 'too-long'])
def test_bad_credentials_do_not_create_state(runtime, bad):
    _channel, _root, state, secrets, image, base, controls = runtime
    if bad == 'absent-pin':
        controls = controls[:2] + controls[4:]
    elif bad == 'absent-so':
        controls = controls[:-2]
    elif bad == 'conflict':
        for name in ['P11LAB_PIN', 'P11LAB_SO_PIN']:
            result = docker(*base, *controls, '-e', name + '=', image, 'init', check=False)
            assert result.returncode != 0 and list(state.iterdir()) == []
        return
    else:
        (secrets / 'pin').write_bytes({
            'empty': b'', 'multiline': b'line-one\nline-two', 'nul': b'nul\0in-passphrase',
            'too-large': b'x' * 4097, 'too-short': b'x' * 9, 'too-long': b'x' * 201}[bad])
    result = docker(*base, *controls, image, 'init', check=False)
    assert result.returncode != 0 and list(state.iterdir()) == []


@pytest.mark.parametrize('label', ['', 'x' * 33, 'bad\nlabel'])
def test_invalid_label_never_creates_state(runtime, label):
    _channel, _root, state, _secrets, image, base, controls = runtime
    result = docker(*base, *controls, '-e', 'P11LAB_LABEL=' + label, image, 'init', check=False)
    assert result.returncode != 0 and list(state.iterdir()) == []


@pytest.mark.parametrize('override', ['P11NETHSM_CONFIG_FILE', 'RUST_LOG', 'LD_PRELOAD', 'ETCD_DATA_DIR'])
def test_native_redirects_are_refused(runtime, override):
    _channel, _root, state, _secrets, image, base, controls = runtime
    result = docker(*base, *controls, '-e', override + '=', image, 'init', check=False)
    assert result.returncode != 0 and list(state.iterdir()) == []
    assert 'unsupported native override' in result.stderr


def test_exact_artifact_readbacks_and_blocked_admission(runtime):
    from p11lab.licenses import assess_distribution, inspect_artifact
    channel, root, _state, _secrets, image, _base, _controls = runtime
    def read(path):
        return docker('run', '--rm', '--network', 'none', '--entrypoint', 'cat', image, path).stdout
    spec = load_environment('nethsm', channel)
    assert json.loads(read('/usr/share/p11lab/provider.json')) == {
        k: v for k, v in spec.items() if k not in ('lock', 'channel', 'channel_spec', 'asset_root')}
    assert read('/usr/share/p11lab/runtime-id') == artifact_key('runtime', runtime_inputs(spec)) + '\n'
    assert 'x86_64-unknown-linux-musl' in read('/usr/share/p11lab/build/rustc.txt')
    linked = read('/usr/share/p11lab/build/runtime-linked-dependencies.txt')
    assert 'not found' not in linked and 'libcurl.so.4' in linked and 'libgmp.so.10' in linked
    assert 'etcd Version: 3.6.13' in read('/usr/share/p11lab/build/etcd.txt')
    assert 'version 5.0 (fc28f32)' in read('/usr/share/p11lab/build/keyfender.txt')
    inv = inspect_artifact(as_ref(image))
    (root / 'actual-content-inventory.json').write_text(json.dumps(inv, indent=2) + '\n')
    forbidden = ['/start.sh', '/provision.sh', '/keyfender.tap', '/uinit', '/perftest',
                 '/usr/bin/python3', '/usr/bin/cc', '/usr/local/bin/cargo']
    assert not any(f['path'] in forbidden or f['path'].startswith('/var/lib/p11lab/') for f in inv['files'])
    assert 'embedded_platform_fallbacks' in json.loads(read('/usr/share/p11lab/build/server-input.json'))['keyfender']
    decision = assess_distribution(as_ref(image), root / 'admission')
    assert decision['status'] == decision['publication_status'] == 'blocked'
    assert decision['blockers'] and decision['source_companion'] is None


def start_long_application(runtime):
    _channel, _root, _state, _secrets, image, base, controls = runtime
    docker(*base, *controls, image, 'init')
    name = 'p11lab-nethsm-test-' + uuid.uuid4().hex[:12]
    # Keep an outer shell alive after the supervisor returns. Residual-process
    # assertions therefore cannot be satisfied by Docker's PID-1 cleanup.
    harness = ('/usr/local/bin/p11lab-provider exec -- sh -c '
               "'printf \"%s\\n\" \"$$\" > /run/p11lab/app.pid; "
               'sleep 300 & printf "%s\\n" "$!" > /run/p11lab/app-child.pid; '
               "touch /run/p11lab/app-started; wait' & "
               'supervisor=$!; printf "%s\\n" "$supervisor" > /run/p11lab/supervisor.pid; '
               'wait "$supervisor"; code=$?; printf "%s\\n" "$code" > /run/p11lab/supervisor-result; sleep 300')
    docker('run', '-d', '--name', name, *base[2:], *controls, '--entrypoint', 'sh', image, '-c', harness)
    for _ in range(200):
        if docker('exec', name, 'test', '-f', '/run/p11lab/app-started', check=False).returncode == 0:
            pids = {role: int(docker('exec', name, 'cat', path).stdout) for role, path in {
                'supervisor': '/run/p11lab/supervisor.pid', 'application': '/run/p11lab/app.pid',
                'app-child': '/run/p11lab/app-child.pid', 'etcd': '/run/p11lab/nethsm/etcd.pid',
                'keyfender': '/run/p11lab/nethsm/keyfender.pid'}.items()}
            return name, pids
        time.sleep(0.05)
    logs = docker('logs', name, check=False)
    docker('rm', '-f', name, check=False)
    pytest.fail('supervised app did not start: ' + logs.stdout + logs.stderr)


def supervisor_result(name):
    for _ in range(200):
        result = docker('exec', name, 'cat', '/run/p11lab/supervisor-result', check=False)
        if result.returncode == 0:
            return int(result.stdout)
        time.sleep(0.05)
    pytest.fail('supervisor did not complete its bounded cleanup')


def assert_reaped_inside_live_container(name, pids):
    for role, pid in pids.items():
        assert docker('exec', name, 'test', '-e', f'/proc/{pid}', check=False).returncode != 0, role
    for role in ['etcd', 'keyfender']:
        assert docker('exec', name, 'test', '-e', f'/run/p11lab/nethsm/{role}.pid', check=False).returncode != 0


def test_signal_shutdown_reaps_owned_processes(runtime):
    _channel, _root, _state, _secrets, image, base, controls = runtime
    name, pids = start_long_application(runtime)
    try:
        docker('exec', name, 'kill', '-TERM', str(pids['supervisor']))
        assert supervisor_result(name) == 143
        assert_reaped_inside_live_container(name, pids)
    finally:
        docker('rm', '-f', name, check=False)
    docker(*base, *controls, image, 'health')


@pytest.mark.parametrize('service', ['etcd', 'keyfender'])
def test_required_service_death_fails_and_reaps_application(runtime, service):
    _channel, _root, state, _secrets, image, base, controls = runtime
    name, pids = start_long_application(runtime)
    try:
        docker('exec', name, 'kill', '-KILL', str(pids[service]))
        assert supervisor_result(name) == 1
        assert f'required {service} exited' in docker('logs', name).stderr
        assert_reaped_inside_live_container(name, pids)
    finally:
        docker('rm', '-f', name, check=False)
    if service == 'etcd' and (state / 'nethsm/data/member/wal/0.tmp').exists():
        # Native etcd leaves an in-flight preallocation on SIGKILL. Do not
        # assert crash recovery, erase it, or weaken static state validation.
        before = snapshot(state)
        result = docker(*base, *controls, image, 'health', check=False)
        assert result.returncode == 1 and 'partial or unsafe native etcd data' in result.stderr
        assert snapshot(state) == before
    else:
        docker(*base, *controls, image, 'health')


def test_volume_lease_refuses_a_second_container(runtime):
    _channel, _root, state, _secrets, image, base, controls = runtime
    name, pids = start_long_application(runtime)
    try:
        before = snapshot(state)
        result = docker(*base, *controls, image, 'health', check=False)
        assert result.returncode != 0 and 'already in use' in result.stderr
        assert snapshot(state) == before
        docker('exec', name, 'kill', '-TERM', str(pids['supervisor']))
        assert supervisor_result(name) == 143
        assert_reaped_inside_live_container(name, pids)
    finally:
        docker('rm', '-f', name, check=False)


def test_native_endpoints_are_loopback_even_on_a_bridge(runtime):
    _channel, _root, _state, _secrets, image, base, controls = runtime
    # Bridge exposure changes only the namespace interface roster; actual
    # listener addresses must remain loopback, including native etcd peers.
    bridge_base = [a if a != 'none' else 'bridge' for a in base]
    docker(*bridge_base, *controls, image, 'init')
    text = docker(*bridge_base, *controls, image, 'exec', '--', 'cat', '/proc/net/tcp', '/proc/net/tcp6').stdout
    listeners = [line.split()[1] for line in text.splitlines() if len(line.split()) > 3 and line.split()[3] == '0A']
    for port in [8080, 8443, 2379, 2380]:
        assert f'0100007F:{port:04X}' in listeners
    assert not any(address.startswith('00000000:') or len(address.split(':')[0]) == 32 for address in listeners)


@pytest.mark.parametrize('channel', ['release', 'rolling'])
def test_shared_builder_preserves_the_actual_inventory_block(channel):
    if channel not in BUILDS:
        pytest.skip('explicit native build attempt required')
    out = Path(BUILDS[channel])
    spec = load_environment('nethsm', channel)
    record = json.loads((out / 'cli-command.json').read_text())
    if record['returncode'] == 0:
        assert (out / 'artifact.json').is_file()
        return
    assert record['returncode'] == 2
    assert not (out / 'artifact.json').exists()
    assert 'actual package/source inventory differs from locked inputs' in (out / 'cli.log').read_text()
    native = json.loads((out / 'native-artifact.json').read_text())
    assert native['artifact']['reference'] == IMAGES[channel]
    base = docker('run', '--rm', '--network', 'none', '--entrypoint', 'cat', IMAGES[channel],
                  '/usr/share/p11lab/build/actual-base.tsv').stdout
    assert base == inventory_text(spec['lock']['features']['package_inventories']['base'])
    with pytest.raises(BuildError, match='actual package/source inventory differs'):
        verify_inventory(base, [p for p in spec['lock']['packages'] if p['phase'] == 'runtime'])
    pytest.xfail('owning shared builder equates base and final inventories; true Alpine base=16, runtime=27')


def component_attempt(mapping, channel, role):
    if channel not in mapping:
        pytest.skip('explicit frozen ' + role + ' derivative attempt required')
    out = Path(mapping[channel])
    attempt = json.loads((out / 'attempt.json').read_text())
    assert attempt['runtime_image'] == IMAGES[channel]
    recipe = Path(attempt['context']) / 'Dockerfile'
    assert recipe.read_bytes() == package_data('runtime/' + role + '.Dockerfile').read_bytes()
    assert hashlib.sha256(recipe.read_bytes()).hexdigest() == attempt['recipe_sha256']
    return attempt, out


@pytest.mark.parametrize('channel', ['release', 'rolling'])
def test_installed_checker_lane_preserves_its_platform_block(channel):
    attempt, out = component_attempt(CHECKER_ATTEMPTS, channel, 'checker')
    assert attempt['returncode'] != 0
    assert not (out / 'image-id').exists()
    assert 'dpkg: not found' in (out / 'build.log').read_text()
    assert attempt['runtime_lock_sha256'] == '98a0341351b410b8ba6d732ae82ffef14442cded33caf8ab55e3958a0c407cab'
    # A compatible shared recipe must obtain a new complete installed smoke
    # run; no glibc wheels, fabricated observations or unpinned replacement.
    pytest.xfail('owning checker recipe requires Debian dpkg/CPython 3.13 and a glibc wheel lock; no installed observations')


@pytest.mark.parametrize('channel', ['release', 'rolling'])
def test_preferred_proxy_independent_crypto(channel, tmp_path):
    attempt, out = component_attempt(PROXY_ATTEMPTS, channel, 'proxy')
    assert attempt['source_revision'] == 'a348a5f59b535b1ca309ea9f0a722e3bec692f72'
    assert attempt['returncode'] == 0 and (out / 'image-id').read_text().strip() == DAEMONS[channel]
    assert channel in CLIENTS and CALLER
    root = Path(os.environ.get('P11LAB_NETHSM_EVIDENCE', str(tmp_path))) / 'proxy-crypto' / channel
    root.mkdir(parents=True)
    state, caller = root / 'state', root / 'caller'
    state.mkdir(mode=0o700)
    caller.mkdir()
    pin, so = root / 'pin', root / 'so'
    pin.write_bytes(PIN)
    so.write_bytes(SO)
    pin.chmod(0o600)
    so.chmod(0o600)
    inputs = {'P11LAB_STATE_DIR': str(state), 'P11LAB_PIN_FILE': str(pin),
              'P11LAB_SO_PIN_FILE': str(so), 'P11LAB_LABEL': 'acceptance'}
    try:
        provision = RunSpec('nethsm', channel, 'direct', as_ref(CONSUMERS[channel]), 'provider',
                            None, None, ('p11lab-token', '--module', MODULE,
                            '--token-label', 'acceptance', '--pin-file',
                            '/run/p11lab-input/P11LAB_PIN_FILE', '--key-id', '42'),
                            inputs, root / 'persistent-create', caller, 180)
        result = run_application(provision)
        assert result.exit_code == 0 and not result.cleanup_errors, result
        bundle = Path(CLIENTS[channel])
        client = ArtifactRef('bundle', str(bundle), hashlib.sha256(bundle.read_bytes()).hexdigest(), 'linux/amd64')
        spec = RunSpec('nethsm', channel, 'proxy', as_ref(DAEMONS[channel]), 'container',
                       as_ref(CALLER), client, ('p11lab-smoke', '--module',
                       '/run/p11lab-client/libpkcs11_proxy_ng_shim.so', '--token-label',
                       'acceptance', '--pin-file', '/run/p11lab-input/P11LAB_PIN_FILE',
                       '--output', '/p11lab-output/crypto', '--key-mode', 'existing', '--key-id', '42'),
                       inputs, root / 'output', caller, 180)
        result = run_application(spec)
        assert result.app_returncode == 0 and not result.cleanup_errors, result
        assert (spec.output_dir / 'proxy-health.stdout.log').read_text().strip() == 'SERVING'
        oracle(spec.output_dir / 'crypto')
        if result.exit_code != 0:
            receipt = json.loads(result.receipt_path.read_text())
            assert result.exit_code == 1 and receipt['app_completed']
            assert receipt['lifecycle_errors'] == ['post-health failed']
            post = [s for s in receipt['stages'] if s['phase'] == 'post-health']
            assert len(post) == 1 and post[0]['returncode'] == 1 and not post[0]['timed_out']
            assert 'state is unsafe or already in use' in (spec.output_dir / 'post-health.stderr.log').read_text()
            pytest.xfail('shared proxy runner starts post-health before stopping its live daemon; remote crypto succeeds, volume lease blocks lifecycle')
    finally:
        pin.unlink(missing_ok=True)
        so.unlink(missing_ok=True)
