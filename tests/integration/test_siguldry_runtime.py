# SPDX-License-Identifier: Apache-2.0
"""Explicit frozen Siguldry images; no implicit builds or provider-error xfails.

P11LAB_SIGULDRY_{IMAGES,CONSUMERS,BUILDS,CHECKER_ATTEMPTS,PROXY_ATTEMPTS}
are JSON channel maps. EVIDENCE is a fresh private output directory. Integration
blockers are conditional on exact owning-component failure evidence, never on
native provider behavior. The unchanged generated-key consumer must fail, and
there is no security officer: native C_Login(CKU_SO) is 0x103.
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

from p11lab.build import runtime_inputs
from p11lab.catalog import load_environment, package_data, validate_build_inputs
from p11lab.identity import artifact_key
from p11lab.models import ArtifactRef, RunSpec
from p11lab.run import run_application

MODULE = '/usr/local/lib/p11lab/libsiguldry_pkcs11.so'
IMAGES = json.loads(os.environ.get('P11LAB_SIGULDRY_IMAGES', '{}'))
CONSUMERS = json.loads(os.environ.get('P11LAB_SIGULDRY_CONSUMERS', '{}'))
BUILDS = json.loads(os.environ.get('P11LAB_SIGULDRY_BUILDS', '{}'))
CHECKER_ATTEMPTS = json.loads(os.environ.get('P11LAB_SIGULDRY_CHECKER_ATTEMPTS', '{}'))
PROXY_ATTEMPTS = json.loads(os.environ.get('P11LAB_SIGULDRY_PROXY_ATTEMPTS', '{}'))
DAEMONS = json.loads(os.environ.get('P11LAB_SIGULDRY_PROXIES', '{}'))
CLIENTS = json.loads(os.environ.get('P11LAB_SIGULDRY_CLIENTS', '{}'))
CALLER = os.environ.get('P11LAB_SIGULDRY_CALLER', '')
CHECKERS = json.loads(os.environ.get('P11LAB_SIGULDRY_CHECKERS', '{}'))
COMMANDS = itertools.count()
PIN = b'siguldry-acceptance-pin-0123456789abcdef'
MESSAGE = b'siguldry-acceptance-message-v1'
SECP256R1_PARAMS = '06082a8648ce3d030107'
SERVICES = ['siguldry-bridge', 'siguldry-signer', 'siguldry-server', 'siguldry-client']
assert len(PIN) == 40


def docker(*args, check=True, env=None):
    argv = ['docker', *map(str, args)]
    result = subprocess.run(argv, capture_output=True, text=True, timeout=180, check=False,
                            env=os.environ | (env or {}))
    evidence = os.environ.get('P11LAB_SIGULDRY_EVIDENCE')
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
        pytest.skip('explicit Siguldry runtime IDs required')
    channel = request.param
    root = Path(os.environ.get('P11LAB_SIGULDRY_EVIDENCE', str(tmp_path))) / request.node.name
    root.mkdir(parents=True, exist_ok=False)
    state = root / 'state'
    state.mkdir(mode=0o700)
    secrets = root / 'secrets'
    secrets.mkdir(mode=0o700)
    (secrets / 'pin').write_bytes(PIN)
    (secrets / 'pin').chmod(0o600)
    base = ['run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
            '--user', f'{os.getuid()}:{os.getgid()}',
            '--tmpfs', f'/run/p11lab:uid={os.getuid()},gid={os.getgid()},mode=0700',
            '--tmpfs', '/tmp', '--mount', f'type=bind,src={state},dst=/var/lib/p11lab',
            '--mount', f'type=bind,src={secrets},dst=/run/secrets,readonly']
    controls = ['-e', 'P11LAB_LABEL=acceptance', '-e', 'P11LAB_PIN_FILE=/run/secrets/pin']
    yield channel, root, state, secrets, IMAGES[channel], base, controls
    for child in secrets.iterdir():
        child.unlink()


def as_ref(image):
    return ArtifactRef('docker-local', image, image.removeprefix('sha256:'), 'linux/amd64')


def snapshot(state):
    return {str(p.relative_to(state)): ('symlink', os.readlink(p)) if p.is_symlink()
            else ('file', hashlib.sha256(p.read_bytes()).hexdigest()) if p.is_file()
            else ('directory', None) for p in state.rglob('*')}


_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
      0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)


def _add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    x1, y1, x2, y2 = *p, *q
    if x1 == x2 and (y1 + y2) % _P == 0:
        return None
    lam = ((3 * x1 * x1 - 3) * pow(2 * y1, -1, _P) % _P if p == q
           else (y2 - y1) * pow(x2 - x1, -1, _P) % _P)
    x3 = (lam * lam - x1 - x2) % _P
    return (x3, (lam * (x1 - x3) - y1) % _P)


def _mul(k, p):
    result = None
    while k:
        result, p, k = (_add(result, p) if k & 1 else result), _add(p, p), k >> 1
    return result


def ecdsa_verify(message, signature, ec_point):
    """Independent P-256 oracle over raw r||s and a DER EC_POINT."""
    point = bytes(ec_point)
    while len(point) != 65 or point[0] != 0x04:
        assert point[0] == 0x04 and len(point) >= 2 and point[1] < 0x80
        assert len(point) == 2 + point[1], point.hex()
        point = point[2:]
    x, y = int.from_bytes(point[1:33], 'big'), int.from_bytes(point[33:65], 'big')
    assert _mul(_N, (x, y)) is None, 'public key not in the P-256 subgroup'
    assert len(signature) == 64
    r, s = int.from_bytes(signature[:32], 'big'), int.from_bytes(signature[32:], 'big')
    assert 1 <= r < _N and 1 <= s < _N
    w = pow(s, -1, _N)
    digest = int.from_bytes(hashlib.sha256(message).digest(), 'big')
    found = _add(_mul(digest * w % _N, _G), _mul(r * w % _N, (x, y)))
    assert found is not None and found[0] % _N == r, 'signature does not verify'


@pytest.mark.parametrize('channel', ['release', 'rolling'])
def test_packaged_inputs_are_closed_and_channels_distinct(channel):
    spec = load_environment('siguldry', channel)
    validate_build_inputs(spec)
    inputs = runtime_inputs(spec)
    expected = {'release': '43a7acf3fa898e22ffd935c0a641bbae68e98363',
                'rolling': '8f22c77b26bf5bbdf81049fb100c05e2395d1c64'}
    assert inputs['sources'][0]['revision'] == expected[channel]
    assert inputs['patches'] == []
    assert inputs['features']['compile_jobs'] == 2
    assert inputs['features']['crate_freeze']['crates'] == 479
    assert inputs['features']['key_algorithm'] == 'p256'
    assert inputs['features']['min_unlock_length'] == 32
    assert inputs['features']['bridge_ports'] == [44333, 44334]
    assert inputs['features']['bridge_cn'] == 'localhost'
    assert inputs['features']['server_cn'] == 'siguldry-server'
    assert inputs['features']['service_user'] == 'siguldry-client'
    assert inputs['features']['token_slot'] == 0
    assert inputs['features']['token_present_index'] == 0
    assert inputs['features']['openssl']['linkage'] == 'dynamic-system'
    assert inputs['features']['sqlite']['linkage'] == 'dynamic-system'
    assert 'cargo build --locked --offline --release' in inputs['features']['build_command']
    assert spec['services'] == SERVICES
    assert spec['backend']['simulated'] is False
    assert spec['application_profile'] == 'signing'
    assert spec['distribution']['status'] == 'blocked'
    other = 'rolling' if channel == 'release' else 'release'
    assert artifact_key('runtime', inputs) != artifact_key('runtime', runtime_inputs(load_environment('siguldry', other)))


def test_native_lifecycle_credentials_and_argv(runtime):
    _channel, root, state, secrets, image, base, controls = runtime
    assert json.loads(docker('run', '--rm', '--network', 'none', image, 'describe').stdout)['module_path'] == MODULE
    assert docker(*base, image, 'init', check=False).returncode != 0
    assert list(state.iterdir()) == []
    docker(*base, *controls, image, 'init')
    owned = state / 'siguldry'
    protected = {p: (owned / p).read_bytes() for p in ['complete', 'bridge.toml', 'server.toml', 'client.toml']}
    assert b'label=acceptance' in protected['complete'] and b'key=p256' in protected['complete']
    for content in protected.values():
        assert PIN not in content
    for credential in owned.joinpath('creds').iterdir():
        assert PIN not in credential.read_bytes()
    assert (owned / 'state/siguldry.sqlite').stat().st_mode & 0o777 in (0o600, 0o640)
    (secrets / 'pin').write_bytes(b'changed-siguldry-acceptance-pin-01234567')
    docker(*base, *controls, image, 'init')
    assert protected == {p: (owned / p).read_bytes() for p in protected}
    health = docker(*base, *controls, image, 'health')
    assert health.stdout == 'ready: native_slot=0 token_present_index=0 label=acceptance key=p256 mech=ECDSA\n'
    incompatible = docker(*base, *controls, '-e', 'P11LAB_LABEL=different', image, 'init', check=False)
    assert incompatible.returncode != 0 and 'incompatible' in incompatible.stderr
    result = docker(*base, *controls, image, 'exec', '--', 'sh', '-c',
                    'printf "%s\n" "$P11LAB_MODULE" "$1"; exit 37', 'caller',
                    'literal $argument with spaces', check=False)
    assert result.returncode == 37
    assert result.stdout.splitlines() == [MODULE, 'literal $argument with spaces']
    assert docker(*base, *controls, image, 'exec', '--', 'sh', '-c',
                  'command -v cc make python3 cargo pkcs11-tool; exit 0').stdout == ''
    other = root / 'scalar-state'
    other.mkdir(mode=0o700)
    scalar_base = [a.replace(f'src={state},', f'src={other},') for a in base]
    docker(*scalar_base, '-e', 'P11LAB_PIN', image, 'init', env={'P11LAB_PIN': 'x' * 200})
    docker(*scalar_base, image, 'health')
    for path in (root / 'secrets').iterdir():
        assert path.stat().st_mode & 0o777 == 0o600


def proof_fields(stdout):
    return dict(line.split('=', 1) for line in stdout.splitlines() if '=' in line)


def run_proof(base, controls, consumer, mode):
    return docker(*base, *controls, consumer, 'exec', '--', 'siguldry-proof',
                  '--module', MODULE, '--token-label', 'acceptance',
                  '--pin-file', '/run/secrets/pin', '--mode', mode).stdout


def test_persistent_crypto_restart_isolation_and_profile_falsification(runtime):
    channel, root, state, secrets, _image, base, controls = runtime
    assert channel in CONSUMERS, 'explicit compatible consumer required'
    consumer = CONSUMERS[channel]
    inputs = {'P11LAB_STATE_DIR': str(state), 'P11LAB_PIN_FILE': str(secrets / 'pin'),
              'P11LAB_LABEL': 'acceptance'}
    argv = ('p11lab-smoke', '--module', MODULE, '--token-label', 'acceptance',
            '--pin-file', '/run/p11lab-input/P11LAB_PIN_FILE', '--output',
            '/p11lab-output/crypto', '--key-mode', 'generated')
    spec = RunSpec('siguldry', channel, 'direct', as_ref(consumer), 'provider',
                   None, None, argv, inputs, root / 'generated', root, 180)
    generated = run_application(spec)
    assert generated.app_returncode == 1 and generated.exit_code != 0
    assert not generated.cleanup_errors
    error = (spec.output_dir / 'application.stderr.log').read_text()
    assert 'required ECDSA mechanism unavailable' in error
    # The unchanged consumer's mechanism gate fires because the native
    # five-mechanism list offers ECDSA but no EC key-pair generation
    # (info mode proves ec_key_pair_gen=0; token-admin proves a direct
    # C_GenerateKeyPair is native 0x54). Completed provider observation,
    # never a conditional xfail or pass.
    print(f'general-token/{channel}: FALSIFIED; no native EC keygen mechanism')
    existing = run_application(replace(spec, output_dir=root / 'existing',
                                       argv=(*argv[:-1], 'existing', '--key-id', '01')))
    assert existing.app_returncode == 1 and existing.exit_code != 0
    assert not existing.cleanup_errors
    assert 'invalid DER OCTET STRING P256 EC point' in (
        root / 'existing/application.stderr.log').read_text()
    # The unchanged stock consumer cannot parse the native double-wrapped
    # CKA_EC_POINT. Completed interop observation, never normalized.
    print(f'stock-consumer/{channel}: native point shape rejected, see signing oracle below')
    main = proof_fields(run_proof(base, controls, consumer, 'sign'))
    assert main['ecparams'] == SECP256R1_PARAMS
    main_point = bytes.fromhex(main['ecpoint'])
    ecdsa_verify(MESSAGE, bytes.fromhex(main['sig']), main_point)
    other = root / 'other-state'
    other.mkdir(mode=0o700)
    other_base = [a.replace(f'src={state},', f'src={other},') for a in base]
    docker(*other_base, *controls, consumer, 'init')
    isolated = proof_fields(docker(*other_base, *controls, consumer, 'exec', '--', 'siguldry-proof',
                                   '--module', MODULE, '--token-label', 'acceptance',
                                   '--pin-file', '/run/secrets/pin', '--mode', 'sign').stdout)
    assert isolated['ecparams'] == SECP256R1_PARAMS
    assert bytes.fromhex(isolated['ecpoint']) != main_point
    ecdsa_verify(MESSAGE, bytes.fromhex(isolated['sig']), bytes.fromhex(isolated['ecpoint']))
    assert (other / 'siguldry/complete').is_file()
    # A failed auth is last: a failed unlock breaks that process proxy
    # connection natively, so it must not contaminate the success lanes,
    # and no provider retry is inserted.
    (secrets / 'pin').write_bytes(b'wrong-siguldry-acceptance-pin-0123456789')
    wrong = docker(*base, *controls, consumer, 'exec', '--', 'siguldry-proof',
                   '--module', MODULE, '--token-label', 'acceptance',
                   '--pin-file', '/run/secrets/pin', '--mode', 'login-wrong', check=False)
    assert wrong.returncode == 0
    assert 'C_Login(wrong): CK_RV=0x000000a0' in wrong.stdout
    for path in root.rglob('*.log'):
        assert PIN not in path.read_bytes()


def test_native_proof_sign_oracle_and_admin_model(runtime):
    channel, _root, _state, _secrets, image, base, controls = runtime
    assert channel in CONSUMERS
    consumer = CONSUMERS[channel]
    docker(*base, *controls, image, 'init')
    info = docker(*base, *controls, consumer, 'exec', '--', 'siguldry-proof',
                  '--module', MODULE, '--token-label', 'acceptance',
                  '--pin-file', '/run/secrets/pin', '--mode', 'info')
    assert 'mechanisms=5 ecdsa=1 ec_key_pair_gen=0' in info.stdout
    admin = docker(*base, *controls, consumer, 'exec', '--', 'siguldry-proof',
                   '--module', MODULE, '--token-label', 'acceptance',
                   '--pin-file', '/run/secrets/pin', '--mode', 'token-admin')
    assert 'C_InitToken: CK_RV=0x00000054' in admin.stdout
    assert 'C_InitPIN: CK_RV=0x00000054' in admin.stdout
    assert 'C_GenerateKeyPair: CK_RV=0x00000054' in admin.stdout
    so = docker(*base, *controls, consumer, 'exec', '--', 'siguldry-proof',
                '--module', MODULE, '--token-label', 'acceptance',
                '--pin-file', '/run/secrets/pin', '--mode', 'login-so')
    assert 'C_Login(SO): CK_RV=0x00000103' in so.stdout
    no_login = docker(*base, *controls, consumer, 'exec', '--', 'siguldry-proof',
                      '--module', MODULE, '--token-label', 'acceptance',
                      '--pin-file', '/run/secrets/pin', '--mode', 'no-login-sign')
    assert 'C_SignInit: CK_RV=0x00000000' in no_login.stdout
    assert 'C_Sign: CK_RV=0x00000006' in no_login.stdout
    runs = []
    for _ in range(2):
        signed = docker(*base, *controls, consumer, 'exec', '--', 'siguldry-proof',
                        '--module', MODULE, '--token-label', 'acceptance',
                        '--pin-file', '/run/secrets/pin', '--mode', 'sign')
        assert 'C_Login: CK_RV=0x00000000' in signed.stdout
        assert 'C_Sign: CK_RV=0x00000000 siglen=64' in signed.stdout
        fields = dict(line.split('=', 1) for line in signed.stdout.splitlines() if '=' in line)
        assert fields['ecparams'] == SECP256R1_PARAMS
        signature, point = bytes.fromhex(fields['sig']), bytes.fromhex(fields['ecpoint'])
        ecdsa_verify(MESSAGE, signature, point)
        with pytest.raises(AssertionError):
            ecdsa_verify(b'siguldry-acceptance-message-v2', signature, point)
        runs.append((signature, point))
    assert runs[0][1] == runs[1][1]
    assert runs[0][0] != runs[1][0]


@pytest.mark.parametrize('damage', [
    'missing-db', 'empty-db', 'missing-marker', 'marker-extra-lf', 'config-drift',
    'missing-server-cert', 'missing-client-key', 'hidden-file', 'data-link', 'busy-init'])
def test_damage_refused_before_native_launch(runtime, damage):
    _channel, _root, state, _secrets, image, base, controls = runtime
    docker(*base, *controls, image, 'init')
    owned = state / 'siguldry'
    db = owned / 'state/siguldry.sqlite'
    if damage == 'missing-db':
        db.unlink()
    elif damage == 'empty-db':
        db.write_bytes(b'')
    elif damage == 'missing-marker':
        (owned / 'complete').unlink()
    elif damage == 'marker-extra-lf':
        with (owned / 'complete').open('ab') as file:
            file.write(b'\n')
    elif damage == 'config-drift':
        with (owned / 'bridge.toml').open('ab') as file:
            file.write(b'\n')
    elif damage == 'missing-server-cert':
        (owned / 'creds/siguldry.server.certificate.pem').unlink()
    elif damage == 'missing-client-key':
        (owned / 'creds/siguldry.siguldry-client.private_key.pem').unlink()
    elif damage == 'hidden-file':
        (owned / 'state/.foreign').write_bytes(b'foreign')
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


@pytest.mark.parametrize('bad', ['absent-pin', 'empty', 'multiline', 'nul',
                                'too-large', 'too-short', 'too-long', 'conflict',
                                'so-scalar', 'so-file'])
def test_bad_credentials_do_not_create_state(runtime, bad):
    _channel, _root, state, secrets, image, base, controls = runtime
    if bad == 'absent-pin':
        controls = controls[:2]
    elif bad == 'conflict':
        result = docker(*base, *controls, '-e', 'P11LAB_PIN=x', image, 'init', check=False)
        assert result.returncode != 0 and list(state.iterdir()) == []
        return
    elif bad == 'so-scalar':
        result = docker(*base, *controls, '-e', 'P11LAB_SO_PIN=x', image, 'init', check=False)
        assert result.returncode != 0 and list(state.iterdir()) == []
        assert 'SO PIN has no native meaning' in result.stderr
        return
    elif bad == 'so-file':
        result = docker(*base, *controls, '-e', 'P11LAB_SO_PIN_FILE=/run/secrets/pin',
                        image, 'init', check=False)
        assert result.returncode != 0 and list(state.iterdir()) == []
        assert 'SO PIN has no native meaning' in result.stderr
        return
    else:
        (secrets / 'pin').write_bytes({
            'empty': b'', 'multiline': b'line-one\nline-two', 'nul': b'nul\0in-passphrase',
            'too-large': b'x' * 4097, 'too-short': b'x' * 31, 'too-long': b'x' * 201}[bad])
    result = docker(*base, *controls, image, 'init', check=False)
    assert result.returncode != 0 and list(state.iterdir()) == []


@pytest.mark.parametrize('label', ['', 'x' * 33, 'bad\nlabel'])
def test_invalid_label_never_creates_state(runtime, label):
    _channel, _root, state, _secrets, image, base, controls = runtime
    result = docker(*base, *controls, '-e', 'P11LAB_LABEL=' + label, image, 'init', check=False)
    assert result.returncode != 0 and list(state.iterdir()) == []


@pytest.mark.parametrize('override', ['LIBSIGULDRY_PKCS11_KEYS', 'LIBSIGULDRY_PKCS11_PROXY_PATH',
                                      'RUST_LOG', 'LD_PRELOAD'])
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
    spec = load_environment('siguldry', channel)
    assert json.loads(read('/usr/share/p11lab/provider.json')) == {
        k: v for k, v in spec.items() if k not in ('lock', 'channel', 'channel_spec', 'asset_root')}
    assert read('/usr/share/p11lab/runtime-id') == artifact_key('runtime', runtime_inputs(spec)) + '\n'
    assert 'rustc 1.98.1' in read('/usr/share/p11lab/build/rustc.txt')
    linked = read('/usr/share/p11lab/build/runtime-linked-dependencies.txt')
    assert 'not found' not in linked
    assert 'libssl.so.3' in linked and 'libcrypto.so.3' in linked and 'libsqlite3.so.0' in linked
    assert len(read('/usr/share/p11lab/build/cargo-tree.txt')) > 1000
    inv = inspect_artifact(as_ref(image))
    (root / 'actual-content-inventory.json').write_text(json.dumps(inv, indent=2) + '\n')
    forbidden = ['/usr/bin/python3', '/usr/bin/cc', '/usr/local/bin/cargo', '/usr/bin/openssl',
                 '/usr/bin/pkcs11-tool', '/opt/p11lab-checker']
    assert not any(f['path'] in forbidden or f['path'].startswith('/var/lib/p11lab/')
                   or f['path'].endswith('.pem') for f in inv['files'])
    decision = assess_distribution(as_ref(image), root / 'admission')
    assert decision['status'] == decision['publication_status'] == 'blocked'
    assert decision['blockers'] and decision['source_companion'] is None


def start_long_application(runtime):
    _channel, _root, _state, _secrets, image, base, controls = runtime
    docker(*base, *controls, image, 'init')
    name = 'p11lab-siguldry-test-' + uuid.uuid4().hex[:12]
    # Keep an outer shell alive after the supervisor returns. Residual-process
    # assertions therefore cannot be satisfied by Docker's PID-1 cleanup.
    harness = ('/usr/local/bin/p11lab-provider exec -- sh -c '
               "'printf \"%s\\n\" \"$$\" > /run/p11lab/app.pid; "
               'sleep 300 & printf "%s\\n" "$!" > /run/p11lab/app-child.pid; '
               "touch /run/p11lab/app-started; wait' & "
               'supervisor=$!; printf "%s\\n" "$supervisor" > /run/p11lab/supervisor.pid; '
               'wait "$supervisor"; code=$?; printf "%s\\n" "$code" > /run/p11lab/supervisor-result; sleep 300')
    docker('run', '-d', '--name', name, *base[2:], *controls, '--entrypoint', 'sh', image, '-c', harness)
    pids = {'supervisor': '/run/p11lab/supervisor.pid', 'application': '/run/p11lab/app.pid',
            'app-child': '/run/p11lab/app-child.pid'}
    pids |= {service: f'/run/p11lab/siguldry/{service}.pid' for service in SERVICES}
    # One docker invocation per poll: app-started is empty, so a clean read
    # yields exactly the pid lines in pids order. Any missing file fails
    # the read and the bounded loop retries.
    paths = ['/run/p11lab/app-started', *pids.values()]
    for _ in range(200):
        result = docker('exec', name, 'cat', *paths, check=False)
        if result.returncode == 0:
            try:
                values = [int(line) for line in result.stdout.splitlines()]
            except ValueError:
                values = []
            if len(values) == len(pids):
                return name, dict(zip(pids, values))
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
    for service in SERVICES:
        assert docker('exec', name, 'test', '-e', f'/run/p11lab/siguldry/{service}.pid',
                      check=False).returncode != 0


def test_signal_shutdown_reaps_owned_processes(runtime):
    _channel, _root, _state, _secrets, image, base, controls = runtime
    name, pids = start_long_application(runtime)
    try:
        docker('exec', name, 'sh', '-c', 'kill -TERM "$1"', 'caller', str(pids['supervisor']))
        assert supervisor_result(name) == 143
        assert_reaped_inside_live_container(name, pids)
    finally:
        docker('rm', '-f', name, check=False)
    docker(*base, *controls, image, 'health')


@pytest.mark.parametrize('service', SERVICES)
def test_required_service_death_fails_and_reaps_application(runtime, service):
    _channel, _root, _state, _secrets, image, base, controls = runtime
    name, pids = start_long_application(runtime)
    try:
        docker('exec', name, 'sh', '-c', 'kill -KILL "$1"', 'caller', str(pids[service]))
        assert supervisor_result(name) == 1
        assert f'required {service} exited' in docker('logs', name).stderr
        assert_reaped_inside_live_container(name, pids)
    finally:
        docker('rm', '-f', name, check=False)
    docker(*base, *controls, image, 'health')


def test_volume_lease_refuses_a_second_container(runtime):
    _channel, _root, state, _secrets, image, base, controls = runtime
    name, pids = start_long_application(runtime)
    try:
        before = snapshot(state)
        result = docker(*base, *controls, image, 'health', check=False)
        assert result.returncode != 0 and 'already in use' in result.stderr
        assert snapshot(state) == before
        docker('exec', name, 'sh', '-c', 'kill -TERM "$1"', 'caller', str(pids['supervisor']))
        assert supervisor_result(name) == 143
        assert_reaped_inside_live_container(name, pids)
    finally:
        docker('rm', '-f', name, check=False)


def test_native_endpoints_are_loopback_even_on_a_bridge(runtime):
    _channel, _root, _state, _secrets, image, base, controls = runtime
    # Bridge exposure changes only the namespace interface roster; actual
    # listener addresses must remain loopback.
    bridge_base = [a if a != 'none' else 'bridge' for a in base]
    docker(*bridge_base, *controls, image, 'init')
    text = docker(*bridge_base, *controls, image, 'exec', '--', 'cat', '/proc/net/tcp', '/proc/net/tcp6').stdout
    listeners = [line.split()[1] for line in text.splitlines() if len(line.split()) > 3 and line.split()[3] == '0A']
    for port in [44333, 44334]:
        assert f'0100007F:{port:04X}' in listeners
    assert not any(address.startswith('00000000:') or len(address.split(':')[0]) == 32 for address in listeners)


@pytest.mark.parametrize('channel', ['release', 'rolling'])
def test_shared_builder_native_build_observation(channel):
    if channel not in BUILDS:
        pytest.skip('explicit native build attempt required')
    out = Path(BUILDS[channel])
    record = json.loads((out / 'cli-command.json').read_text())
    assert record['returncode'] == 0
    assert (out / 'artifact.json').is_file()
    native = json.loads((out / 'native-artifact.json').read_text())
    assert native['artifact']['reference'] == IMAGES[channel]


def component_attempt(mapping, channel, role):
    if channel not in mapping:
        pytest.skip('explicit frozen ' + role + ' derivative attempt required')
    out = Path(mapping[channel])
    attempt = json.loads((out / 'attempt.json').read_text())
    assert attempt['runtime_image'] == IMAGES[channel]
    recipe = Path(attempt['context']) / 'Dockerfile'
    if role != 'consumer':
        assert recipe.read_bytes() == package_data('runtime/' + role + '.Dockerfile').read_bytes()
    assert hashlib.sha256(recipe.read_bytes()).hexdigest() == attempt['recipe_sha256']
    return attempt, out


@pytest.mark.parametrize('channel', ['release', 'rolling'])
def test_installed_checker_so_gap_blocks_observations(channel, tmp_path):
    from p11lab.checker import run_checker
    attempt, out = component_attempt(CHECKER_ATTEMPTS, channel, 'checker')
    assert attempt['returncode'] == 0 and (out / 'image-id').read_text().strip() == CHECKERS[channel]
    assert attempt['runtime_lock_sha256'] == '98a0341351b410b8ba6d732ae82ffef14442cded33caf8ab55e3958a0c407cab'
    root = Path(os.environ.get('P11LAB_SIGULDRY_EVIDENCE', str(tmp_path))) / 'direct-checker' / channel
    root.mkdir(parents=True)
    state, caller = root / 'state', root / 'caller'
    state.mkdir(mode=0o700)
    caller.mkdir()
    pin = root / 'pin'
    pin.write_bytes(PIN)
    pin.chmod(0o600)
    try:
        spec = RunSpec('siguldry', channel, 'direct', as_ref(CHECKERS[channel]), 'provider',
                       None, None, (),
                       {'P11LAB_STATE_DIR': str(state), 'P11LAB_PIN_FILE': str(pin)},
                       root / 'output', caller, 600)
        result = run_checker(spec, 'smoke-v1')
        assert result.exit_code == 1 and result.app_returncode == 1
        assert not result.cleanup_errors
        assert result.lifecycle_errors == ('checker observation evidence incomplete or unavailable',)
        assert "KeyError: 'P11LAB_SO_PIN'" in (spec.output_dir / 'application.stderr.log').read_text()
        assert not (spec.output_dir / 'checker/checker-receipt.json').exists()
    finally:
        pin.unlink(missing_ok=True)
    pytest.xfail('shared run_checker requires P11LAB_SO_PIN unconditionally; '
                 'Siguldry has no SO (native C_Login(CKU_SO)=0x103, SO inputs refused)')


@pytest.mark.parametrize('channel', ['release', 'rolling'])
def test_preferred_proxy_independent_crypto(channel, tmp_path):
    attempt, out = component_attempt(PROXY_ATTEMPTS, channel, 'proxy')
    assert attempt['source_revision'] == 'a348a5f59b535b1ca309ea9f0a722e3bec692f72'
    assert attempt['returncode'] == 0 and (out / 'image-id').read_text().strip() == DAEMONS[channel]
    assert channel in CLIENTS and CALLER
    root = Path(os.environ.get('P11LAB_SIGULDRY_EVIDENCE', str(tmp_path))) / 'proxy-crypto' / channel
    root.mkdir(parents=True)
    state, caller = root / 'state', root / 'caller'
    state.mkdir(mode=0o700)
    caller.mkdir()
    pin = root / 'pin'
    pin.write_bytes(PIN)
    pin.chmod(0o600)
    inputs = {'P11LAB_STATE_DIR': str(state), 'P11LAB_PIN_FILE': str(pin)}
    try:
        bundle = Path(CLIENTS[channel])
        client = ArtifactRef('bundle', str(bundle), hashlib.sha256(bundle.read_bytes()).hexdigest(), 'linux/amd64')
        spec = RunSpec('siguldry', channel, 'proxy', as_ref(DAEMONS[channel]), 'container',
                       as_ref(CALLER), client, ('p11lab-smoke', '--module',
                       '/run/p11lab-client/libpkcs11_proxy_ng_shim.so', '--token-label',
                       'P11Lab', '--pin-file', '/run/p11lab-input/P11LAB_PIN_FILE',
                       '--output', '/p11lab-output/crypto', '--key-mode', 'existing', '--key-id', '01'),
                       inputs, root / 'output', caller, 600)
        result = run_application(spec)
        assert (spec.output_dir / 'proxy-health.stdout.log').read_text().strip() == 'SERVING'
        assert result.app_returncode == 1 and result.exit_code == 1
        assert not result.cleanup_errors
        # The proxy transports the native interaction faithfully: the same
        # stock-consumer point-shape observation as the direct lane.
        assert 'invalid DER OCTET STRING P256 EC point' in (
            spec.output_dir / 'application.stderr.log').read_text()
        receipt = json.loads(result.receipt_path.read_text())
        assert receipt['app_completed'] and receipt['lifecycle_errors'] == ['post-health failed']
        post = [s for s in receipt['stages'] if s['phase'] == 'post-health']
        assert len(post) == 1 and post[0]['returncode'] == 1 and not post[0]['timed_out']
        assert 'state is unsafe or already in use' in (spec.output_dir / 'post-health.stderr.log').read_text()
        print(f'proxy/{channel}: SERVING; app observation identical to direct; '
              'post-health lifecycle blocked by live-daemon volume lease (shared runner)')
    finally:
        pin.unlink(missing_ok=True)
