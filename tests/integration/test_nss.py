"""NSS softoken anchor acceptance: real init/readiness/crypto/persistence/lanes.

Durable regression for the NSS provider (Task 8). Image lanes are env-gated;
only caller-owned inputs and output artifacts are mounted, never a reference
workspace:

- P11LAB_TEST_NSS_IMAGES: JSON channel -> exact runtime engine ID.
- P11LAB_TEST_NSS_CONSUMER_IMAGES: JSON channel -> exact test-only consumer
  derivative (provider + independent C smoke + OpenSC pkcs11-tool).
- P11LAB_TEST_NSS_CHECKER_IMAGES: JSON channel -> exact installed checker
  derivative engine ID.
- P11LAB_TEST_NSS_PROXY: JSON channel -> exact daemon derivative engine ID.
- P11LAB_TEST_NSS_CALLER: exact caller-owned application image.
- P11LAB_TEST_NSS_CLIENTS: JSON channel -> native-client bundle archive path.

The crypto oracle is the packaged independent verifier plus host OpenSSL;
its version is recorded with every verification.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from p11lab.catalog import load_environment, package_data
from p11lab.models import ArtifactRef, RunSpec
from p11lab.run import run_application

MODULE = '/usr/local/lib/p11lab/libsoftokn3.so'
TOKEN_LABEL = 'P11Lab'
CHANNELS = ('release', 'rolling')


@pytest.mark.parametrize('channel', CHANNELS)
def test_runtime_nspr_version(channel):
    if channel not in IMAGES:
        pytest.skip('P11LAB_TEST_NSS_IMAGES lacks ' + channel)
    version = docker('run', '--rm', '--network', 'none', '--entrypoint', 'cat', IMAGES[channel],
                     '/usr/share/p11lab/build/nspr.txt').stdout
    assert ('nspr_version=' + ('4.40' if channel == 'release' else '4.41 Beta')) in version.splitlines()


@pytest.mark.parametrize('channel', CHANNELS)
def test_runtime_hacl_grant(channel):
    if channel not in IMAGES:
        pytest.skip('P11LAB_TEST_NSS_IMAGES lacks ' + channel)
    grant = docker('run', '--rm', '--network', 'none', '--entrypoint', 'cat', IMAGES[channel],
                   '/usr/share/licenses/nss/HACL-MIT.txt').stdout
    for text in ('MIT License', 'Copyright (c) 2016-2022 INRIA, CMU and Microsoft Corporation',
                 'Copyright (c) 2022-2023 HACL* Contributors', 'Permission is hereby granted',
                 'The above copyright notice and this permission notice', 'THE SOFTWARE IS PROVIDED',
                 'SOFTWARE.'):
        assert text in grant

IMAGES = json.loads(os.environ.get('P11LAB_TEST_NSS_IMAGES', '{}'))
CONSUMERS = json.loads(os.environ.get('P11LAB_TEST_NSS_CONSUMER_IMAGES', '{}'))
CHECKERS = json.loads(os.environ.get('P11LAB_TEST_NSS_CHECKER_IMAGES', '{}'))
DAEMONS = json.loads(os.environ.get('P11LAB_TEST_NSS_PROXY', '{}'))
CALLER = os.environ.get('P11LAB_TEST_NSS_CALLER', '')
CLIENTS = json.loads(os.environ.get('P11LAB_TEST_NSS_CLIENTS', '{}'))


def docker(*args, check=True):
    return subprocess.run(['docker', *args], capture_output=True, text=True, check=check, timeout=300)


def openssl_version():
    completed = subprocess.run(['openssl', 'version'], capture_output=True, text=True, timeout=30)
    assert completed.returncode == 0
    return completed.stdout.strip()


def oracle(output_dir):
    verifier = output_dir.parent / 'verify-nss.py'
    verifier.write_bytes(package_data('consumer/verify.py').read_bytes())
    try:
        completed = subprocess.run([sys.executable, str(verifier), str(output_dir)],
                                   capture_output=True, text=True, timeout=120)
    finally:
        verifier.unlink(missing_ok=True)
    assert completed.returncode == 0, completed.stderr
    assert 'altered message rejected' in completed.stdout
    return completed.stdout.strip()


def write_pins(directory):
    pin, so_pin = directory / 'pin', directory / 'so-pin'
    pin.write_bytes(b'1234')
    so_pin.write_bytes(b'12345678')
    pin.chmod(0o600)
    so_pin.chmod(0o600)
    return pin, so_pin


def as_ref(image):
    return ArtifactRef('docker-local', image, image.removeprefix('sha256:'), 'linux/amd64')


@pytest.mark.parametrize('channel', CHANNELS)
def test_channels_locked(channel):
    spec = load_environment('nss', channel)
    assert spec['channel_spec']['status'] == 'locked'


@pytest.mark.parametrize('channel', CHANNELS)
def test_real_standalone_lifecycle(channel, tmp_path):
    if channel not in IMAGES:
        pytest.skip('P11LAB_TEST_NSS_IMAGES lacks ' + channel)
    image = IMAGES[channel]
    state, partial, secrets = tmp_path / 'state', tmp_path / 'partial', tmp_path / 'secrets'
    state.mkdir()
    partial.mkdir()
    secrets.mkdir()
    (secrets / 'pin').write_text('1234')
    (secrets / 'so-pin').write_text('12345678')
    base = ['run', '--rm', '--network', 'none',
            '--user', f'{os.getuid()}:{os.getgid()}', '--read-only', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges',
            '--tmpfs', f'/run/p11lab:rw,nosuid,nodev,uid={os.getuid()},gid={os.getgid()},mode=0700',
            '--tmpfs', '/tmp:rw,nosuid,nodev',
            '--mount', f'type=bind,src={state},dst=/var/lib/p11lab',
            '--mount', f'type=bind,src={secrets},dst=/run/secrets,readonly']
    controls = ['-e', 'P11LAB_PIN_FILE=/run/secrets/pin', '-e', 'P11LAB_SO_PIN_FILE=/run/secrets/so-pin']
    description = json.loads(docker('run', '--rm', image, 'describe').stdout)
    assert description['module_path'] == MODULE
    assert description['id'] == 'nss'
    assert docker(*base, *controls, image, 'init').returncode == 0
    # The adapter selects the SQL database through the real NSS params file.
    params = docker(*base, *controls, image, 'exec', '--', 'sh', '-c',
                    'printf "%s\\n" "$NSS_LIB_PARAMS_FILE"; cat "$NSS_LIB_PARAMS_FILE"').stdout
    lines = params.splitlines()
    assert lines[0] == '/run/p11lab/nss-lib-params'
    assert "configdir='sql:/var/lib/p11lab/nss'" in lines[1]
    assert "dbTokenDescription='P11Lab'" in lines[1]
    assert 'pin' not in params.lower() and '1234' not in params
    # The baked Linux default covers processes that never receive the variable
    # (notably the mTLS proxy daemon, whose shared entrypoint is SoftHSM-born).
    default = docker(*base, *controls, image, 'exec', '--', 'cat', '/etc/nss/params.config').stdout
    assert "configdir='sql:/var/lib/p11lab/nss'" in default
    assert "dbTokenDescription='P11Lab'" in default
    before = docker(*base, *controls, image, 'exec', '--', 'sh', '-c',
                    'find /var/lib/p11lab -type f -exec sha256sum {} + | sort').stdout
    assert '/var/lib/p11lab/nss/cert9.db' in before and '/var/lib/p11lab/nss/key4.db' in before
    assert '/var/lib/p11lab/nss/pkcs11.txt' in before
    (secrets / 'pin').write_text('5678')
    (secrets / 'so-pin').write_text('87654321')
    docker(*base, *controls, image, 'init')
    after = docker(*base, *controls, image, 'exec', '--', 'sh', '-c',
                   'find /var/lib/p11lab -type f -exec sha256sum {} + | sort').stdout
    assert before == after
    health = docker(*base, *controls, image, 'health')
    assert health.returncode == 0, health.stderr
    # Second provisioning round-trip keeps state byte-identical (reopen proof).
    docker(*base, *controls, image, 'health')
    conflict = docker(*base, *controls, '-e', 'P11LAB_PIN=other', image, 'init', check=False)
    assert conflict.returncode != 0 and 'conflicting' in conflict.stderr
    stripped = docker(*base, *controls, image, 'exec', '--', 'sh', '-c',
                      'for c in python python3 pkcs11-check pkcs11-tool certutil; do command -v "$c"; done; exit 0').stdout
    # certutil is the provider-native init/health tool; nothing else ships.
    assert stripped.splitlines() == ['/usr/local/bin/certutil'], stripped
    result = docker(*base, *controls, image, 'exec', '--', 'sh', '-c',
                    'printf "%s\\n" "$NSS_LIB_PARAMS_FILE" "$P11LAB_MODULE" "$1"; exit 37',
                    'caller', 'literal $argument with spaces', check=False)
    assert result.returncode == 37
    assert result.stdout.splitlines() == ['/run/p11lab/nss-lib-params', MODULE, 'literal $argument with spaces']
    (partial / 'unknown').write_text('foreign')
    result = docker('run', '--rm', '--network', 'none',
                    '--user', f'{os.getuid()}:{os.getgid()}', '--read-only', '--cap-drop', 'ALL',
                    '--security-opt', 'no-new-privileges',
                    '--tmpfs', f'/run/p11lab:rw,nosuid,nodev,uid={os.getuid()},gid={os.getgid()},mode=0700',
                    '--tmpfs', '/tmp:rw,nosuid,nodev',
                    '--mount', f'type=bind,src={partial},dst=/var/lib/p11lab',
                    '--mount', f'type=bind,src={secrets},dst=/run/secrets,readonly',
                    *controls, image, 'init', check=False)
    assert result.returncode != 0 and 'partial' in result.stderr
    marker = docker(*base, *controls, image, 'exec', '--', 'cat', '/var/lib/p11lab/nss/complete').stdout
    assert {line.split('=', 1)[0] for line in marker.splitlines()} == {'schema', 'provider', 'artifact', 'token', 'backend'}
    assert 'token=P11Lab' in marker
    assert 'pin' not in marker.lower()


@pytest.mark.parametrize('channel', CHANNELS)
@pytest.mark.parametrize('controls, message', [
    ([], 'absent'),
    (['-e', 'P11LAB_PIN=', '-e', 'P11LAB_SO_PIN=12345678'], 'empty'),
    (['-e', 'P11LAB_PIN=1234'], 'absent'),
    (['-e', 'P11LAB_PIN=1234', '-e', 'P11LAB_PIN_FILE=/missing', '-e', 'P11LAB_SO_PIN=12345678'], 'conflicting'),
    (['-e', 'P11LAB_PIN_FILE=/missing', '-e', 'P11LAB_SO_PIN=12345678'], 'readable'),
])
def test_initial_credentials_fail_explicitly(channel, controls, message):
    if channel not in IMAGES:
        pytest.skip('P11LAB_TEST_NSS_IMAGES lacks ' + channel)
    result = docker('run', '--rm', '--network', 'none', *controls, IMAGES[channel], 'init', check=False)
    assert result.returncode != 0 and message in result.stderr


@pytest.mark.parametrize('channel', CHANNELS)
def test_token_index_separate_from_native_slot(channel, tmp_path):
    if channel not in CONSUMERS:
        pytest.skip('P11LAB_TEST_NSS_CONSUMER_IMAGES lacks ' + channel)
    image = CONSUMERS[channel]
    state, secrets = tmp_path / 'state', tmp_path / 'secrets'
    state.mkdir()
    secrets.mkdir()
    (secrets / 'pin').write_bytes(b'1234')
    (secrets / 'so-pin').write_bytes(b'12345678')
    base = ['run', '--rm', '--network', 'none',
            '--user', f'{os.getuid()}:{os.getgid()}', '--read-only', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges',
            '--tmpfs', f'/run/p11lab:rw,nosuid,nodev,uid={os.getuid()},gid={os.getgid()},mode=0700',
            '--tmpfs', '/tmp:rw,nosuid,nodev',
            '--mount', f'type=bind,src={state},dst=/var/lib/p11lab',
            '--mount', f'type=bind,src={secrets},dst=/run/secrets,readonly',
            '-e', 'P11LAB_PIN_FILE=/run/secrets/pin', '-e', 'P11LAB_SO_PIN_FILE=/run/secrets/so-pin']
    docker(*base, image, 'init')
    listed = docker(*base, image, 'exec', '--', 'pkcs11-tool', '--module', MODULE, '--list-token-slots').stdout
    assert TOKEN_LABEL in listed
    # Token-present order: internal crypto services first, our DB token second.
    # pkcs11-tool prints the enumeration index with the native ID in hex:
    # index 1 is native 0x2, and the two values stay distinct.
    import re
    slots = [line for line in listed.splitlines() if line.startswith('Slot ')]
    assert len(slots) == 2, listed
    parsed = [re.fullmatch(r'Slot (\d+) \(0x([0-9a-fA-F]+)\): (.*)', line) for line in slots]
    assert all(parsed), listed
    assert [(int(m[1]), int(m[2], 16)) for m in parsed] == [(0, 1), (1, 2)], listed
    assert parsed[1][3] == 'NSS User Private Key and Certificate Services', listed
    token_section = listed.split(slots[1], 1)[1]
    assert 'token label        : ' + TOKEN_LABEL in token_section, listed
    # pkcs11-tool defaults to the first token-present slot (the internal
    # services slot, which takes no user login); select our database token.
    docker(*base, image, 'exec', '--', 'pkcs11-tool', '--module', MODULE,
           '--token-label', TOKEN_LABEL, '--login', '--pin', '1234', '--list-objects')


def run_direct(channel, image, argv, inputs, output, caller, timeout=300):
    spec = RunSpec('nss', channel, 'direct', as_ref(image), 'provider', None, None,
                   tuple(argv), dict(inputs), output, caller, timeout)
    result = run_application(spec)
    assert result.exit_code == 0, (result.lifecycle_errors, result.cleanup_errors)
    assert result.app_returncode == 0
    assert not result.lifecycle_errors and not result.cleanup_errors
    receipt = json.loads(Path(result.receipt_path).read_text())
    assert [stage['phase'] for stage in receipt['stages']] == ['init', 'ready', 'application', 'post-health']
    return result


SMOKE_ARGV = ('p11lab-smoke', '--module', MODULE, '--token-label', TOKEN_LABEL,
              '--pin-file', '/run/p11lab-input/P11LAB_PIN_FILE',
              '--output', '/p11lab-output/crypto', '--key-mode')


@pytest.mark.parametrize('channel', CHANNELS)
def test_direct_crypto_generated_oracle(channel, tmp_path):
    if channel not in CONSUMERS:
        pytest.skip('P11LAB_TEST_NSS_CONSUMER_IMAGES lacks ' + channel)
    pin, so_pin = write_pins(tmp_path)
    caller = tmp_path / 'caller'
    caller.mkdir()
    output = tmp_path / 'output'
    run_direct(channel, CONSUMERS[channel], (*SMOKE_ARGV, 'generated'),
               {'P11LAB_PIN_FILE': str(pin), 'P11LAB_SO_PIN_FILE': str(so_pin)}, output, caller)
    metadata = json.loads((output / 'crypto/result.json').read_text())
    assert metadata['key_mode'] == 'generated'
    print('oracle:', oracle(output / 'crypto'), '|', openssl_version())


@pytest.mark.parametrize('channel', CHANNELS)
def test_persisted_key_reopens_in_fresh_processes(channel, tmp_path):
    if channel not in CONSUMERS:
        pytest.skip('P11LAB_TEST_NSS_CONSUMER_IMAGES lacks ' + channel)
    image = CONSUMERS[channel]
    pin, so_pin = write_pins(tmp_path)
    caller = tmp_path / 'caller'
    caller.mkdir()
    state = tmp_path / 'persistent state'
    state.mkdir()
    inputs = {'P11LAB_PIN_FILE': str(pin), 'P11LAB_SO_PIN_FILE': str(so_pin),
              'P11LAB_STATE_DIR': str(state)}
    provision = RunSpec('nss', channel, 'direct', as_ref(image), 'provider', None, None,
                        ('pkcs11-tool', '--module', MODULE, '--token-label', TOKEN_LABEL,
                         '--login', '--pin', '1234', '--keypairgen', '--key-type', 'EC:prime256v1',
                         '--id', '42', '--label', 'nss-persist'),
                        dict(inputs), tmp_path / 'provision', caller, 300)
    provisioned = run_application(provision)
    assert provisioned.exit_code == 0, provisioned
    pubs = []
    for index in range(2):
        output = tmp_path / ('reopen-' + str(index))
        run_direct(channel, image, (*SMOKE_ARGV, 'existing', '--key-id', '42'),
                   dict(inputs), output, caller)
        oracle(output / 'crypto')
        pubs.append((output / 'crypto/public-key.der').read_bytes())
    assert pubs[0] == pubs[1] and len(pubs[0]) == 91


@pytest.mark.parametrize('channel', CHANNELS)
def test_lost_token_contents_are_not_reinitialized(channel, tmp_path):
    if channel not in IMAGES:
        pytest.skip('P11LAB_TEST_NSS_IMAGES lacks ' + channel)
    image = IMAGES[channel]
    state, secrets = tmp_path / 'state', tmp_path / 'secrets'
    state.mkdir()
    secrets.mkdir()
    (secrets / 'pin').write_bytes(b'1234')
    (secrets / 'so-pin').write_bytes(b'12345678')
    base = ['run', '--rm', '--network', 'none',
            '--user', f'{os.getuid()}:{os.getgid()}', '--read-only', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges',
            '--tmpfs', f'/run/p11lab:rw,nosuid,nodev,uid={os.getuid()},gid={os.getgid()},mode=0700',
            '--tmpfs', '/tmp:rw,nosuid,nodev',
            '--mount', f'type=bind,src={state},dst=/var/lib/p11lab',
            '--mount', f'type=bind,src={secrets},dst=/run/secrets,readonly',
            '-e', 'P11LAB_PIN_FILE=/run/secrets/pin', '-e', 'P11LAB_SO_PIN_FILE=/run/secrets/so-pin']
    docker(*base, image, 'init')
    (state / 'nss' / 'key4.db').unlink()
    snapshot = ['--entrypoint', 'sh', image, '-c', 'find /var/lib/p11lab -type f -exec sha256sum {} + | sort']
    before = docker(*base, *snapshot).stdout
    for operation in ('init', 'health'):
        result = docker(*base, image, operation, check=False)
        assert result.returncode != 0 and 'partial' in result.stderr
    result = docker(*base, image, 'exec', '--', 'sh', '-c', 'echo APP-RAN', check=False)
    assert result.returncode != 0 and 'APP-RAN' not in result.stdout
    assert docker(*base, *snapshot).stdout == before


@pytest.mark.parametrize('channel', CHANNELS)
def test_direct_checker_smoke(channel, tmp_path):
    if channel not in CHECKERS:
        pytest.skip('P11LAB_TEST_NSS_CHECKER_IMAGES lacks ' + channel)
    from p11lab.checker import run_checker
    pin, so_pin = write_pins(tmp_path)
    caller = tmp_path / 'caller'
    caller.mkdir()
    output = tmp_path / 'output'
    spec = RunSpec('nss', channel, 'direct', as_ref(CHECKERS[channel]), 'provider', None, None,
                   (), {'P11LAB_PIN_FILE': str(pin), 'P11LAB_SO_PIN_FILE': str(so_pin)},
                   output, caller, 1500)
    result = run_checker(spec, 'smoke-v1')
    record = json.loads((output / 'checker/checker-receipt.json').read_text())
    assert record['evidence']['observations_complete'] is True, record['evidence']
    assert record['token']['label'] == TOKEN_LABEL
    assert record['token']['token_present_index'] != record['token']['native_slot_id']
    print(f"checker direct/{channel}: exit={result.exit_code} "
          f"summary={record['evidence']['summary']} statuses={record['evidence']['provider_statuses']}")


@pytest.mark.parametrize('channel', CHANNELS)
def test_proxy_crypto_container(channel, tmp_path):
    if channel not in DAEMONS or not CALLER or channel not in CLIENTS:
        pytest.skip('proxy daemon, caller image and client bundles required')
    pin, so_pin = write_pins(tmp_path)
    caller = tmp_path / 'caller'
    caller.mkdir()
    output = tmp_path / 'output'
    bundle = Path(CLIENTS[channel])
    spec = RunSpec('nss', channel, 'proxy', as_ref(DAEMONS[channel]), 'container', as_ref(CALLER),
                   ArtifactRef('bundle', str(bundle),
                               hashlib.sha256(bundle.read_bytes()).hexdigest(), 'linux/amd64'),
                   ('/usr/local/bin/p11lab-smoke', '--module',
                    '/run/p11lab-client/libpkcs11_proxy_ng_shim.so', '--token-label', TOKEN_LABEL,
                    '--pin-file', '/run/p11lab-input/P11LAB_PIN_FILE',
                    '--output', '/p11lab-output/crypto', '--key-mode', 'generated'),
                   {'P11LAB_PIN_FILE': str(pin), 'P11LAB_SO_PIN_FILE': str(so_pin)},
                   output, caller, 600)
    result = run_application(spec)
    assert result.exit_code == 0, (result.lifecycle_errors, result.cleanup_errors)
    assert result.app_returncode == 0
    assert (output / 'proxy-health.stdout.log').read_text().strip() == 'SERVING'
    oracle(output / 'crypto')


def test_proxy_crypto_host(tmp_path):
    channel = 'release'
    if channel not in DAEMONS or channel not in CLIENTS:
        pytest.skip('proxy daemon and client bundle required')
    if shutil.which('cc') is None:
        pytest.skip('host C compiler required')
    pin, so_pin = write_pins(tmp_path)
    caller = tmp_path / 'caller'
    caller.mkdir()
    output = tmp_path / 'output'
    sources = tmp_path / 'consumer-sources'
    sources.mkdir()
    for name in ('smoke.c', 'p256.c', 'p256.h'):
        (sources / name).write_bytes(package_data('consumer/' + name).read_bytes())
    vendor = sources / 'vendor'
    vendor.mkdir()
    (vendor / 'pkcs11.h').write_bytes(package_data('consumer/vendor/pkcs11.h').read_bytes())
    binary = tmp_path / 'hostbin' / 'p11lab-smoke'
    binary.parent.mkdir()
    build = subprocess.run(['cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-pedantic',
                            str(sources / 'smoke.c'), str(sources / 'p256.c'), '-ldl', '-o', str(binary)],
                           capture_output=True, text=True, timeout=120)
    assert build.returncode == 0, build.stderr
    bundle = Path(CLIENTS[channel])
    script = ('exec "$0" --module "$P11LAB_SHIM" --token-label ' + TOKEN_LABEL +
              ' --pin-file "$1" --output "$P11LAB_OUTPUT_DIR/crypto" --key-mode generated')
    spec = RunSpec('nss', channel, 'proxy', as_ref(DAEMONS[channel]), 'host', None,
                   ArtifactRef('bundle', str(bundle),
                               hashlib.sha256(bundle.read_bytes()).hexdigest(), 'linux/amd64'),
                   ('sh', '-c', script, str(binary), str(pin)),
                   {'P11LAB_PIN_FILE': str(pin), 'P11LAB_SO_PIN_FILE': str(so_pin)},
                   output, caller, 600)
    result = run_application(spec)
    assert result.exit_code == 0, (result.lifecycle_errors, result.cleanup_errors)
    oracle(output / 'crypto')


@pytest.mark.parametrize('channel', CHANNELS)
def test_reset_retains_credential_file_inside_owned_tree(channel, tmp_path):
    # A PIN file inside the owned tree passes reset validation and is then
    # deleted with the tree: reset must retain the validated bytes outside
    # the wiped tree so the re-init succeeds (no destroy-then-fail).
    if channel not in IMAGES:
        pytest.skip('P11LAB_TEST_NSS_IMAGES lacks ' + channel)
    image = IMAGES[channel]
    state, secrets, control = tmp_path / 'state', tmp_path / 'secrets', tmp_path / 'control'
    state.mkdir()
    secrets.mkdir()
    control.mkdir()
    (secrets / 'pin').write_text('1234')
    (secrets / 'so-pin').write_text('12345678')
    base = ['run', '--rm', '--network', 'none',
            '--user', f'{os.getuid()}:{os.getgid()}',
            '--mount', f'type=bind,src={state},dst=/var/lib/p11lab',
            '--mount', f'type=bind,src={control},dst=/run/p11lab',
            '--mount', f'type=bind,src={secrets},dst=/run/secrets,readonly']
    file_controls = ['-e', 'P11LAB_PIN_FILE=/run/secrets/pin', '-e', 'P11LAB_SO_PIN_FILE=/run/secrets/so-pin']
    assert docker(*base, *file_controls, image, 'init').returncode == 0
    (state / 'nss' / 'tree-pin').write_bytes(b'1234')
    tree_controls = ['-e', 'P11LAB_PIN_FILE=/var/lib/p11lab/nss/tree-pin',
                     '-e', 'P11LAB_SO_PIN_FILE=/run/secrets/so-pin']
    assert docker(*base, *tree_controls, image, 'reset').returncode == 0
    assert docker(*base, image, 'health').returncode == 0
    assert list(control.glob('reset-pin.*')) == []
    assert list(control.glob('reset-so-pin.*')) == []
