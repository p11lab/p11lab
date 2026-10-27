# SPDX-License-Identifier: Apache-2.0
"""SWToken acceptance, with pinned channel images and no implicit builds.

P11LAB_OPENCRYPTOKI_{IMAGES,CONSUMERS,CHECKERS,PROXIES,CLIENTS} contain explicit
JSON channel maps; CALLER is an independent C caller image and EVIDENCE is a
fresh output directory. The qualified native primary GID is 1001.
"""
from dataclasses import replace
import hashlib
import json
import itertools
import time
import uuid
import os
from pathlib import Path
import subprocess

import pytest

from p11lab.build import runtime_inputs
from p11lab.catalog import load_environment, validate_build_inputs, package_data
from p11lab.identity import artifact_key
from p11lab.models import ArtifactRef, RunSpec
from p11lab.run import run_application

MODULE = '/usr/local/lib/p11lab/libopencryptoki.so'
IMAGES = json.loads(os.environ.get('P11LAB_OPENCRYPTOKI_IMAGES', '{}'))
CONSUMERS = json.loads(os.environ.get('P11LAB_OPENCRYPTOKI_CONSUMERS', '{}'))
CHECKERS = json.loads(os.environ.get('P11LAB_OPENCRYPTOKI_CHECKERS', '{}'))
DAEMONS = json.loads(os.environ.get('P11LAB_OPENCRYPTOKI_PROXIES', '{}'))
CLIENTS = json.loads(os.environ.get('P11LAB_OPENCRYPTOKI_CLIENTS', '{}'))
CALLER = os.environ.get('P11LAB_OPENCRYPTOKI_CALLER', '')
COMMANDS = itertools.count()




def docker(*args, check=True, env=None):
    argv = ['docker', *args]
    result = subprocess.run(argv, capture_output=True, text=True, timeout=300, env=os.environ | (env or {}))
    evidence = os.environ.get('P11LAB_OPENCRYPTOKI_EVIDENCE')
    if evidence:
        root = Path(evidence) / 'commands'
        root.mkdir(parents=True, exist_ok=True)
        path = root / f'{next(COMMANDS):04d}.json'
        path.write_text(json.dumps({'argv': argv, 'env': {k: '<test secret omitted>' for k in (env or {})}, 'returncode': result.returncode,
                                   'stdout': result.stdout, 'stderr': result.stderr}, indent=2) + '\n')
    if check:
        assert result.returncode == 0, result.stderr
    return result


@pytest.fixture(params=list(IMAGES) or ['unconfigured'])
def runtime(request, tmp_path):
    if request.param not in IMAGES:
        pytest.skip('explicit OpenCryptoki runtime IDs required')
    channel = request.param
    root = Path(os.environ.get('P11LAB_OPENCRYPTOKI_EVIDENCE', str(tmp_path))) / request.node.name
    root.mkdir(parents=True, exist_ok=False)
    state = root / 'state'
    state.mkdir(mode=0o700)
    secrets = root / 'secrets'
    secrets.mkdir(mode=0o700)
    for name, value in [('pin', b'1234'), ('so', b'12345678')]:
        (secrets / name).write_bytes(value)
        (secrets / name).chmod(0o600)
    image = IMAGES[channel]
    base = ['run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
            '--user', f'{os.getuid()}:{os.getgid()}', '--tmpfs', f'/run/p11lab:uid={os.getuid()},gid={os.getgid()},mode=0700',
            '--tmpfs', '/tmp', '--mount', f'type=bind,src={state},dst=/var/lib/p11lab',
            '--mount', f'type=bind,src={secrets},dst=/run/secrets,readonly']
    controls = ['-e', 'P11LAB_LABEL=acceptance', '-e', 'P11LAB_PIN_FILE=/run/secrets/pin', '-e', 'P11LAB_SO_PIN_FILE=/run/secrets/so']
    yield channel, root, state, secrets, image, base, controls
    # Test-only credentials are removed from durable evidence.
    for child in secrets.iterdir():
        child.unlink()



def as_ref(image):
    return ArtifactRef('docker-local', image, image.removeprefix('sha256:'), 'linux/amd64')


def lane_root(name, channel, tmp_path):
    evidence = os.environ.get('P11LAB_OPENCRYPTOKI_EVIDENCE')
    root = Path(evidence) / name / channel if evidence else tmp_path
    root.mkdir(parents=True, exist_ok=True)
    caller = root / 'caller'
    caller.mkdir()
    pin, so = root / 'pin', root / 'so'
    pin.write_bytes(b'1234')
    so.write_bytes(b'12345678')
    pin.chmod(0o600)
    so.chmod(0o600)
    return root, caller, pin, so


@pytest.mark.parametrize('channel', ['release', 'rolling'])
def test_installed_checker_observations(channel, tmp_path):
    if channel not in CHECKERS:
        pytest.skip('explicit installed OpenCryptoki checker derivative required')
    from p11lab.checker import run_checker
    root, caller, pin, so = lane_root('direct-checker', channel, tmp_path)
    try:
        spec = RunSpec('opencryptoki', channel, 'direct', as_ref(CHECKERS[channel]), 'provider', None, None, (),
                       {'P11LAB_PIN_FILE': str(pin), 'P11LAB_SO_PIN_FILE': str(so)}, root / 'output', caller, 1200)
        result = run_checker(spec, 'smoke-v1')
        assert not result.cleanup_errors
        record = json.loads((spec.output_dir / 'checker/checker-receipt.json').read_text())
        assert len(record['nodes']) == 23
        assert record['token']['native_slot_id'] == 0 and record['token']['token_present_index'] == 0
        assert record['token']['label'] == 'P11Lab'
        # A completed provider finding is valid evidence, never normalized.
        print(f'checker direct/{channel}: exit={result.exit_code} evidence={record["evidence"]}')
        if not record['evidence']['observations_complete']:
            # Owning-component defect: checker_environment drops the recipe's
            # trusted native account mapping after successful token preflight.
            # Preserve incomplete observations and the native error, never
            # count this as provider qualification or bypass that boundary.
            error = (spec.output_dir / 'checker/checker.stderr.log').read_text()
            assert result.exit_code == record['returncode'] == 3
            assert 'C_Initialize failed: 0x00000006' in error
            assert record['evidence']['provider_statuses'] == []
            assert record['evidence']['complete'] is False
            pytest.xfail('P11Lab checker_environment drops native NSS/preload mapping; zero completed observations')
    finally:
        pin.unlink(missing_ok=True)
        so.unlink(missing_ok=True)


@pytest.mark.parametrize('channel', ['release', 'rolling'])
def test_preferred_proxy_independent_crypto(channel, tmp_path):
    if channel not in DAEMONS or channel not in CLIENTS or not CALLER:
        pytest.skip('explicit pinned OpenCryptoki daemon, client bundle and caller required')
    root, caller, pin, so = lane_root('proxy-crypto', channel, tmp_path)
    try:
        bundle = Path(CLIENTS[channel])
        client = ArtifactRef('bundle', str(bundle), hashlib.sha256(bundle.read_bytes()).hexdigest(), 'linux/amd64')
        spec = RunSpec('opencryptoki', channel, 'proxy', as_ref(DAEMONS[channel]), 'container', as_ref(CALLER), client,
                       ('p11lab-smoke', '--module', '/run/p11lab-client/libpkcs11_proxy_ng_shim.so',
                        '--token-label', 'P11Lab', '--pin-file', '/run/p11lab-input/P11LAB_PIN_FILE',
                        '--output', '/p11lab-output/crypto', '--key-mode', 'generated'),
                       {'P11LAB_PIN_FILE': str(pin), 'P11LAB_SO_PIN_FILE': str(so)}, root / 'output', caller, 600)
        result = run_application(spec)
        assert result.app_returncode == 0, result
        assert not result.cleanup_errors
        assert (spec.output_dir / 'proxy-health.stdout.log').read_text().strip() == 'SERVING'
        oracle(spec.output_dir / 'crypto')
        if result.exit_code != 0:
            # The shared runner opens a second runtime for post-health before
            # stopping the live proxy/native daemon. Keep the volume lease and
            # report the lifecycle block despite successful remote crypto.
            receipt = json.loads(result.receipt_path.read_text())
            assert result.exit_code == 1 and receipt['app_completed']
            assert receipt['lifecycle_errors'] == ['post-health failed']
            post = [s for s in receipt['stages'] if s['phase'] == 'post-health']
            assert len(post) == 1 and post[0]['returncode'] == 1 and not post[0]['timed_out']
            assert 'state is unsafe or already in use' in (spec.output_dir / 'post-health.stderr.log').read_text()
            pytest.xfail('P11Lab proxy runner checks state before stopping its live daemon; crypto succeeds, lifecycle blocked')
    finally:
        pin.unlink(missing_ok=True)
        so.unlink(missing_ok=True)


@pytest.mark.parametrize('channel', ['release', 'rolling'])
def test_packaged_inputs_are_closed_and_channels_distinct(channel):
    spec = load_environment('opencryptoki', channel)
    validate_build_inputs(spec)
    inputs = runtime_inputs(spec)
    expected = {'release': '583d0128bb5ebfac263496bc8fe32d4aef440178',
                'rolling': 'b0769d6332d4d82b33991b89f2d2dc9d64142cbe'}
    assert inputs['sources'][0]['revision'] == expected[channel]
    assert inputs['features']['compile_jobs'] == 2
    assert inputs['features']['openssl']['from_source'] is False
    assert inputs['features']['native_group_gid'] == 1001
    assert inputs['features']['token_slot'] == 0
    assert spec['services'] == ['pkcsslotd']
    assert inputs['patches'] == inputs['dependencies'] == []
    assert all(item in inputs['features']['configure'] for item in
               ['--enable-swtok', '--disable-icatok', '--disable-ccatok', '--disable-ep11tok',
                '--disable-tpmtok', '--disable-icsftok', '--disable-p11sak'])
    other = 'rolling' if channel == 'release' else 'release'
    assert artifact_key('runtime', inputs) != artifact_key('runtime', runtime_inputs(load_environment('opencryptoki', other)))


def snapshot(state):
    return {str(p.relative_to(state)): ('symlink', os.readlink(p)) if p.is_symlink()
            else ('file', hashlib.sha256(p.read_bytes()).hexdigest()) if p.is_file()
            else ('directory', None) for p in state.rglob('*')}


def test_native_lifecycle_credentials_and_argv(runtime):
    channel, root, state, secrets, image, base, controls = runtime
    assert json.loads(docker('run', '--rm', image, 'describe').stdout)['module_path'] == MODULE
    assert docker(*base, image, 'init', check=False).returncode != 0
    assert list(state.iterdir()) == []
    docker(*base, *controls, image, 'init')
    before = snapshot(state)
    (secrets / 'pin').write_bytes(b'5678')
    (secrets / 'so').write_bytes(b'97531864')
    docker(*base, *controls, image, 'init')
    assert snapshot(state) == before
    health = docker(*base, *controls, image, 'health')
    assert 'native_slot=0 token_present_index=0 label=acceptance' in health.stdout
    changed = docker(*base, *controls, '-e', 'P11LAB_LABEL=different', image, 'init', check=False)
    assert changed.returncode != 0 and 'incompatible' in changed.stderr
    result = docker(*base, *controls, image, 'exec', '--', 'sh', '-c',
                    'printf "%s\n" "$P11LAB_MODULE" "$1"; exit 37', 'caller',
                    'literal $argument with spaces', check=False)
    assert result.returncode == 37
    assert result.stdout.splitlines() == [MODULE, 'literal $argument with spaces']
    assert 'pin' not in (state / 'opencryptoki/complete').read_text().lower()
    assert (state / 'opencryptoki/strength.conf').is_symlink()
    assert os.readlink(state / 'opencryptoki/strength.conf') == '/usr/share/p11lab/opencryptoki/strength.conf'
    assert docker(*base, *controls, image, 'exec', '--', 'sh', '-c',
                  'command -v cc make python3 pkcs11-tool pkcsconf p11sak; exit 0').stdout == ''
    assert snapshot(state) == before
    # Credentials in the native adapter come from either scalar environment
    # or private files. Docker argv and durable command records omit values.
    other = root / 'scalar-state'
    other.mkdir(mode=0o700)
    scalar_base = [x.replace(f'src={state},', f'src={other},') for x in base]
    docker(*scalar_base, '-e', 'P11LAB_PIN', '-e', 'P11LAB_SO_PIN', image, 'init',
           env={'P11LAB_PIN': '2468', 'P11LAB_SO_PIN': '13572468'})
    docker(*scalar_base, image, 'health')


def oracle(output):
    result = subprocess.run(['python3', str(package_data('consumer/verify.py')), str(output)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert 'altered message rejected' in result.stdout
    (output.parent / 'oracle.txt').write_text(result.stdout)


def test_application_crypto_persistence_isolation_and_native_errors(runtime):
    channel, root, state, secrets, image, base, controls = runtime
    assert channel in CONSUMERS, 'explicit compatible caller derivative required'
    inputs = {'P11LAB_STATE_DIR': str(state), 'P11LAB_PIN_FILE': str(secrets / 'pin'),
              'P11LAB_SO_PIN_FILE': str(secrets / 'so'), 'P11LAB_LABEL': 'acceptance'}
    argv = ('p11lab-smoke', '--module', MODULE, '--token-label', 'acceptance', '--pin-file', '/run/p11lab-input/P11LAB_PIN_FILE',
            '--output', '/p11lab-output/crypto', '--key-mode', 'generated')
    spec = RunSpec('opencryptoki', channel, 'direct', as_ref(CONSUMERS[channel]), 'provider', None, None,
                   argv, inputs, root / 'generated', root, 90)
    generated = run_application(spec)
    assert generated.exit_code == 0, generated
    oracle(spec.output_dir / 'crypto')
    provision = replace(spec, output_dir=root / 'provision', argv=('p11lab-token', '--module', MODULE,
                        '--token-label', 'acceptance', '--pin-file', '/run/p11lab-input/P11LAB_PIN_FILE', '--key-id', '42'))
    assert run_application(provision).exit_code == 0
    public = []
    for number in range(2):
        reopened = replace(spec, output_dir=root / f'reopen-{number}', argv=(*argv[:-1], 'existing', '--key-id', '42'))
        result = run_application(reopened)
        assert result.exit_code == 0 and not result.cleanup_errors, result
        oracle(reopened.output_dir / 'crypto')
        public.append((reopened.output_dir / 'crypto/public-key.der').read_bytes())
    assert public[0] == public[1]
    (secrets / 'pin').write_bytes(b'bad-pin')
    failed = run_application(replace(spec, output_dir=root / 'wrong-pin'))
    assert failed.app_returncode != 0 and failed.exit_code != 0
    assert 'C_Login: CK_RV=0x000000a0' in (root / 'wrong-pin/application.stderr.log').read_text()
    other = root / 'other-state'
    other.mkdir(mode=0o700)
    (secrets / 'pin').write_bytes(b'1234')
    absent = replace(spec, inputs=inputs | {'P11LAB_STATE_DIR': str(other)}, output_dir=root / 'separate',
                     argv=(*argv[:-1], 'existing', '--key-id', '42'))
    assert run_application(absent).exit_code != 0
    assert (other / 'opencryptoki/lib/opencryptoki/swtok/NVTOK.DAT').is_file()
    for path in root.rglob('*.log'):
        assert b'bad-pin' not in path.read_bytes() and b'12345678' not in path.read_bytes()


@pytest.mark.parametrize('damage', ['missing-data', 'empty-data', 'missing-so', 'missing-user', 'missing-marker',
                                   'marker-extra-lf', 'config-drift', 'hidden-file', 'dangling-link', 'data-link',
                                   'busy-init', 'policy-drift'])
def test_damage_refused_before_daemon_or_application(runtime, damage):
    channel, root, state, secrets, image, base, controls = runtime
    docker(*base, *controls, image, 'init')
    owned = state / 'opencryptoki'
    data = owned / 'lib/opencryptoki/swtok'
    if damage == 'missing-data':
        (data / 'NVTOK.DAT').unlink()
    elif damage == 'empty-data':
        (data / 'NVTOK.DAT').write_bytes(b'')
    elif damage in ('missing-so', 'missing-user'):
        (data / ('MK_SO' if damage == 'missing-so' else 'MK_USER')).unlink()
    elif damage == 'missing-marker':
        (owned / 'complete').unlink()
    elif damage == 'marker-extra-lf':
        with (owned / 'complete').open('ab') as f:
            f.write(b'\n')
    elif damage == 'config-drift':
        (owned / 'opencryptoki.conf').write_text('version opencryptoki-3.27\nslot 1 {}\n')
    elif damage == 'hidden-file':
        (data / 'TOK_OBJ/.foreign').write_bytes(b'foreign')
    elif damage == 'dangling-link':
        (data / 'TOK_OBJ/OBabcdef').symlink_to('absent')
    elif damage == 'data-link':
        (data / 'NVTOK.DAT').rename(data / 'original.dat')
        (data / 'NVTOK.DAT').symlink_to('original.dat')
    elif damage == 'busy-init':
        (state / '.init-lock').mkdir()
    else:
        (owned / 'strength.conf').unlink()
        (owned / 'strength.conf').symlink_to('/etc/passwd')
    before = snapshot(state)
    for operation in ('init', 'health', 'exec'):
        argv = [operation] if operation != 'exec' else ['exec', '--', 'sh', '-c', 'echo APP-RAN']
        result = docker(*base, *controls, image, *argv, check=False)
        assert result.returncode != 0 and 'APP-RAN' not in result.stdout
        assert snapshot(state) == before, (damage, operation)


@pytest.mark.parametrize('bad', ['absent-pin', 'absent-so', 'empty', 'multiline', 'nul', 'too-large',
                                'user-conflict', 'so-conflict', 'too-short', 'too-long', 'factory-so'])
def test_bad_credentials_never_create_state(runtime, bad):
    channel, root, state, secrets, image, base, controls = runtime
    if bad == 'absent-pin':
        controls = controls[:2] + controls[4:]
    elif bad == 'absent-so':
        controls = controls[:-2]
    elif bad in ('user-conflict', 'so-conflict'):
        controls = [*controls, '-e', 'P11LAB_PIN=' if bad == 'user-conflict' else 'P11LAB_SO_PIN=']
    elif bad == 'factory-so':
        (secrets / 'so').write_bytes(b'87654321')
    else:
        (secrets / 'pin').write_bytes({'empty': b'', 'multiline': b'line1\nline2', 'nul': b'nul\0byte',
                                      'too-large': b'x' * 4097, 'too-short': b'abc', 'too-long': b'x' * 9}[bad])
    result = docker(*base, *controls, image, 'init', check=False)
    assert result.returncode != 0
    assert list(state.iterdir()) == []


@pytest.mark.parametrize('label', ['', 'x' * 33, 'bad\nlabel'])
def test_invalid_label_never_creates_state(runtime, label):
    channel, root, state, secrets, image, base, controls = runtime
    result = docker(*base, *controls, '-e', 'P11LAB_LABEL=' + label, image, 'init', check=False)
    assert result.returncode != 0 and list(state.iterdir()) == []


@pytest.mark.parametrize('override', ['OPENSSL_MODULES', 'PKCS_APP_STORE', 'PKCS11_SHMEM_FILE', 'LD_PRELOAD'])
def test_native_redirects_refused(runtime, override):
    channel, root, state, secrets, image, base, controls = runtime
    result = docker(*base, *controls, '-e', override + '=', image, 'init', check=False)
    assert result.returncode != 0 and list(state.iterdir()) == []
    assert 'unsupported native override' in result.stderr


def test_exact_artifact_readbacks_and_admission_blocked(runtime):
    from p11lab.licenses import assess_distribution
    channel, root, state, secrets, image, base, controls = runtime
    def read(path):
        return docker('run', '--rm', '--network', 'none', '--entrypoint', 'cat', image, path).stdout
    spec = load_environment('opencryptoki', channel)
    assert json.loads(read('/usr/share/p11lab/provider.json')) == {k: v for k, v in spec.items()
                                                                 if k not in ('lock', 'channel', 'channel_spec', 'asset_root')}
    assert read('/usr/share/p11lab/runtime-id') == artifact_key('runtime', runtime_inputs(spec)) + '\n'
    assert 'libcrypto.so.3' in read('/usr/share/p11lab/build/runtime-linked-dependencies.txt')
    assert 'not found' not in read('/usr/share/p11lab/build/runtime-linked-dependencies.txt')
    assert 'version: 3.5.7' in read('/usr/share/p11lab/build/openssl.txt')
    decision = assess_distribution(as_ref(image), root / 'admission')
    assert decision['status'] == decision['publication_status'] == 'blocked' and decision['blockers']
    (root / 'admission-decision.json').write_text(json.dumps(decision, indent=2) + '\n')
    permission = docker('run', '--rm', '--network', 'none', '--entrypoint', 'stat', image,
                        '-c', '%u:%g %a', '/usr/share/p11lab/opencryptoki/strength.conf').stdout.strip()
    assert permission == '0:1001 640'


def start_long_application(runtime):
    channel, root, state, secrets, image, base, controls = runtime
    docker(*base, *controls, image, 'init')
    name = 'p11lab-opencryptoki-test-' + uuid.uuid4().hex[:12]
    args = ['-d', '--name', name, *base[2:], *controls, image, 'exec', '--', 'sh', '-c',
            'touch /run/p11lab/app-started; sleep 300']
    # base begins run --rm; detached instances are explicitly removed here.
    docker('run', *args)
    for _ in range(200):
        ready = docker('exec', name, 'test', '-f', '/run/p11lab/app-started', check=False)
        if ready.returncode == 0:
            return name
        time.sleep(0.05)
    docker('rm', '-f', name, check=False)
    pytest.fail('supervised application did not start')


def test_signal_shutdown_reaps_daemon_and_preserves_state(runtime):
    channel, root, state, secrets, image, base, controls = runtime
    name = start_long_application(runtime)
    before = snapshot(state)
    try:
        pid = docker('exec', name, 'cat', '/run/p11lab/opencryptoki/pkcsslotd.pid').stdout.strip()
        assert int(pid) > 1
        docker('kill', '--signal', 'TERM', name)
        assert docker('wait', name).stdout.strip() == '143'
        assert snapshot(state) == before
    finally:
        docker('rm', '-f', name, check=False)
    docker(*base, *controls, image, 'health')


def test_daemon_death_fails_operation_and_reaps_application(runtime):
    channel, root, state, secrets, image, base, controls = runtime
    name = start_long_application(runtime)
    before = snapshot(state)
    try:
        pid = docker('exec', name, 'cat', '/run/p11lab/opencryptoki/pkcsslotd.pid').stdout.strip()
        docker('exec', name, 'sh', '-c', 'kill -KILL "$1"', 'caller', pid)
        assert docker('wait', name).stdout.strip() == '1'
        assert 'required pkcsslotd exited' in docker('logs', name).stderr
        assert snapshot(state) == before
    finally:
        docker('rm', '-f', name, check=False)
    docker(*base, *controls, image, 'health')


def test_state_lease_refuses_second_container(runtime):
    channel, root, state, secrets, image, base, controls = runtime
    name = start_long_application(runtime)
    before = snapshot(state)
    try:
        failed = docker(*base, *controls, image, 'health', check=False)
        assert failed.returncode != 0 and 'already in use' in failed.stderr
        assert snapshot(state) == before
        docker('exec', name, 'test', '-S', '/run/p11lab/opencryptoki/pkcsslotd.socket')
        docker('kill', '--signal', 'TERM', name)
        assert docker('wait', name).stdout.strip() == '143'
    finally:
        docker('rm', '-f', name, check=False)


NATIVE_PROBE = r'''
#define _POSIX_C_SOURCE 200809L
#include <p11-kit/pkcs11.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    CK_FUNCTION_LIST_PTR f = NULL;
    CK_RV (*get)(CK_FUNCTION_LIST_PTR_PTR) = NULL;
    void *h = dlopen(getenv("P11LAB_MODULE"), RTLD_NOW | RTLD_LOCAL), *symbol;
    CK_RV rv;
    CK_SLOT_ID slot = 0;
    CK_ULONG count = 1;
    CK_TOKEN_INFO info;
    if (!h) return 2;
    symbol = dlsym(h, "C_GetFunctionList");
    memcpy(&get, &symbol, sizeof(get));
    if (!get || get(&f)) return 2;
    rv = f->C_Initialize(NULL);
    fprintf(stderr, "C_Initialize: CK_RV=0x%08lx\n", rv);
    if (rv) { dlclose(h); return 1; }
    rv = f->C_GetSlotList(CK_TRUE, &slot, &count);
    if (rv == CKR_OK) rv = f->C_GetTokenInfo(slot, &info);
    if (rv == CKR_OK) printf("slot=%lu count=%lu min=%lu max=%lu flags=0x%08lx\n",
                             slot, count, info.ulMinPinLen, info.ulMaxPinLen, info.flags);
    if (f->C_Finalize(NULL)) return 2;
    dlclose(h);
    return rv != CKR_OK;
}
'''


def test_native_daemon_and_system_legacy_are_required(runtime):
    channel, root, state, secrets, image, base, controls = runtime
    assert channel in CONSUMERS
    consumer = CONSUMERS[channel]
    docker(*base, *controls, image, 'init')
    before = snapshot(state)
    result = docker(*base, *controls, consumer, 'exec', '--', 'p11lab-native-probe')
    assert 'slot=0 count=1 min=4 max=8' in result.stdout
    missing_legacy = docker(*base, *controls, consumer, 'exec', '--', 'env',
                            'OPENSSL_MODULES=/tmp/absent-legacy', 'p11lab-native-probe', check=False)
    assert missing_legacy.returncode == 1 and 'C_Initialize: CK_RV=0x00000006' in missing_legacy.stderr
    # Bypass only the adapter in this negative native lane; identity mapping
    # remains identical, so missing daemon is the variable under test.
    direct = docker(*base, '--entrypoint', 'sh', '-e', 'P11LAB_MODULE=' + MODULE, consumer, '-c',
                    'mkdir -p /run/p11lab/opencryptoki/locks /run/p11lab/opencryptoki/logs; '
                    'printf "p11lab:x:%s:1001:P11Lab:/var/lib/p11lab:/bin/sh\n" "$(id -u)" > /run/p11lab/passwd; '
                    'printf "p11lab:x:1001:p11lab\n" > /run/p11lab/group; '
                    'NSS_WRAPPER_PASSWD=/run/p11lab/passwd NSS_WRAPPER_GROUP=/run/p11lab/group '
                    'LD_PRELOAD=/usr/local/lib/p11lab/libnss_wrapper.so p11lab-native-probe', check=False)
    assert direct.returncode == 1 and 'C_Initialize: CK_RV=0x00000006' in direct.stderr
    assert snapshot(state) == before


def test_reset_retains_credential_file_inside_owned_tree(runtime):
    # A PIN file inside the owned tree passes reset validation and is then
    # deleted with the tree: reset must retain the validated bytes outside
    # the wiped tree (beside locks/, never inside it) so re-init succeeds.
    channel, root, state, secrets, image, base, controls = runtime
    control = root / 'control'
    control.mkdir(mode=0o700)
    owned_base = ['run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
                  '--user', f'{os.getuid()}:{os.getgid()}',
                  '--mount', f'type=bind,src={state},dst=/var/lib/p11lab',
                  '--mount', f'type=bind,src={control},dst=/run/p11lab',
                  '--mount', f'type=bind,src={secrets},dst=/run/secrets,readonly',
                  '--tmpfs', '/tmp']
    assert docker(*owned_base, *controls, image, 'init').returncode == 0
    (state / 'opencryptoki' / 'tree-pin').write_bytes(b'1234')
    tree_controls = ['-e', 'P11LAB_LABEL=acceptance',
                     '-e', 'P11LAB_PIN_FILE=/var/lib/p11lab/opencryptoki/tree-pin',
                     '-e', 'P11LAB_SO_PIN_FILE=/run/secrets/so']
    assert docker(*owned_base, *tree_controls, image, 'reset').returncode == 0
    assert docker(*owned_base, '-e', 'P11LAB_LABEL=acceptance', image, 'health').returncode == 0
    assert list((control / 'opencryptoki').glob('reset-pin.*')) == []
    assert list((control / 'opencryptoki').glob('reset-so-pin.*')) == []
