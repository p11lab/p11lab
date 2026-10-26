"""Haskoki anchor acceptance: real init/readiness/crypto/persistence/lanes.

Durable regression for the Haskoki provider (Task 8; release locked at
upstream tag v0.5.0.0, rolling tracks main). Image lanes are
env-gated; only caller-owned inputs and output artifacts are mounted, never
a reference workspace:

- P11LAB_TEST_HASKOKI_IMAGES: JSON channel -> exact runtime engine ID.
- P11LAB_TEST_HASKOKI_CONSUMER_IMAGES: JSON channel -> exact test-only consumer
  derivative (provider + independent C smoke + OpenSC pkcs11-tool).
- P11LAB_TEST_HASKOKI_CHECKER_IMAGES: JSON channel -> exact installed checker
  derivative engine ID.
- P11LAB_TEST_HASKOKI_PROXY: JSON channel -> exact daemon derivative engine ID.
- P11LAB_TEST_HASKOKI_CALLER: exact caller-owned application image.
- P11LAB_TEST_HASKOKI_CLIENTS: JSON channel -> native-client bundle archive path.

The crypto oracle is the packaged independent verifier plus host OpenSSL;
its version is recorded with every verification.

Haskoki specifics (upstream e442a38d, main): configuration provisioning via
HASKOKI_CONFIG (no InitToken/InitPIN/SetPIN path); slot 0 always serves
label haskoki-demo (any other requested label is refused); provisioned PINs
are the upstream-fixed 1234 (user) / 5678 (SO) and anything else fails
explicitly at init; real crypto runs on engine=openssl over the pinned
OpenSSL 4.0.2 (libcrypto statically linked, legacy provider module shipped
beside the module, never the synthetic engine); trace is disabled; the
SQLite store is single-writer, so health/readiness never opens the
module (stock haskoki-ctl config check + lock-safe store inspect only).
Token objects persist across processes; session objects stay process-local.
"""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading

import pytest

from p11lab.catalog import load_environment, package_data
from p11lab.models import ArtifactRef, RunSpec
from p11lab.run import run_application

MODULE = '/usr/local/lib/p11lab/libhaskoki.so'
CONFIG = '/var/lib/p11lab/haskoki/haskoki.toml'
STORE = '/var/lib/p11lab/haskoki/token.sqlite'
TOKEN_LABEL = 'haskoki-demo'
USER_PIN = '1234'
SO_PIN = '5678'
CHANNELS = ('release', 'rolling')


IMAGES = json.loads(os.environ.get('P11LAB_TEST_HASKOKI_IMAGES', '{}'))
CONSUMERS = json.loads(os.environ.get('P11LAB_TEST_HASKOKI_CONSUMER_IMAGES', '{}'))
CHECKERS = json.loads(os.environ.get('P11LAB_TEST_HASKOKI_CHECKER_IMAGES', '{}'))
DAEMONS = json.loads(os.environ.get('P11LAB_TEST_HASKOKI_PROXY', '{}'))
CALLER = os.environ.get('P11LAB_TEST_HASKOKI_CALLER', '')
CLIENTS = json.loads(os.environ.get('P11LAB_TEST_HASKOKI_CLIENTS', '{}'))


def docker(*args, check=True):
    return subprocess.run(['docker', *args], capture_output=True, text=True, check=check, timeout=300)


def openssl_version():
    completed = subprocess.run(['openssl', 'version'], capture_output=True, text=True, timeout=30)
    assert completed.returncode == 0
    return completed.stdout.strip()


def oracle(output_dir):
    verifier = output_dir.parent / 'verify-haskoki.py'
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
    pin.write_bytes(USER_PIN.encode())
    so_pin.write_bytes(SO_PIN.encode())
    pin.chmod(0o600)
    so_pin.chmod(0o600)
    return pin, so_pin


def as_ref(image):
    return ArtifactRef('docker-local', image, image.removeprefix('sha256:'), 'linux/amd64')


def lifecycle_base(state, secrets):
    uid, gid = os.getuid(), os.getgid()
    return ['run', '--rm', '--network', 'none',
            '--user', f'{uid}:{gid}', '--read-only', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges',
            '--tmpfs', f'/run/p11lab:rw,nosuid,nodev,uid={uid},gid={gid},mode=0700',
            '--tmpfs', '/tmp:rw,nosuid,nodev',
            '--mount', f'type=bind,src={state},dst=/var/lib/p11lab',
            '--mount', f'type=bind,src={secrets},dst=/run/secrets,readonly']


def lifecycle_controls():
    return ['-e', 'P11LAB_PIN_FILE=/run/secrets/pin', '-e', 'P11LAB_SO_PIN_FILE=/run/secrets/so-pin',
            '-e', 'P11LAB_LABEL=' + TOKEN_LABEL]


def test_rolling_locked():
    spec = load_environment('haskoki', 'rolling')
    assert spec['channel_spec']['status'] == 'locked'


def test_release_locked():
    spec = load_environment('haskoki', 'release')
    assert spec['channel_spec']['status'] == 'locked'
    release = spec['channels']['release']
    assert release['lock'] == 'release.lock.json'


@pytest.mark.parametrize('channel', CHANNELS)
def test_real_standalone_lifecycle(channel, tmp_path):
    if channel not in IMAGES:
        pytest.skip('P11LAB_TEST_HASKOKI_IMAGES lacks ' + channel)
    image = IMAGES[channel]
    state, partial, secrets = tmp_path / 'state', tmp_path / 'partial', tmp_path / 'secrets'
    state.mkdir()
    partial.mkdir()
    secrets.mkdir()
    (secrets / 'pin').write_text(USER_PIN)
    (secrets / 'so-pin').write_text(SO_PIN)
    base = lifecycle_base(state, secrets)
    controls = lifecycle_controls()
    description = json.loads(docker('run', '--rm', image, 'describe').stdout)
    assert description['module_path'] == MODULE
    assert description['id'] == 'haskoki'
    initialized = docker(*base, *controls, image, 'init')
    assert initialized.returncode == 0, initialized.stderr
    env = docker(*base, *controls, image, 'exec', '--', 'sh', '-c',
                 'printf "%s\\n" "$HASKOKI_CONFIG" "$P11LAB_MODULE"').stdout
    assert env.splitlines() == [CONFIG, MODULE], env
    assert USER_PIN not in env and SO_PIN not in env
    before = docker(*base, *controls, image, 'exec', '--', 'sh', '-c',
                    'find /var/lib/p11lab -type f | sort').stdout
    assert CONFIG in before
    assert STORE in before
    assert '/var/lib/p11lab/haskoki/complete' in before
    assert before.split() == sorted(['/var/lib/p11lab/haskoki/complete',
                                     '/var/lib/p11lab/haskoki/haskoki.toml',
                                     '/var/lib/p11lab/haskoki/token.sqlite']), before
    assert not list(state.rglob('*.jsonl')), 'trace must stay disabled'
    config_text = (state / 'haskoki' / 'haskoki.toml').read_text()
    assert 'kind = "sqlite"' in config_text
    assert 'kind = "openssl"' in config_text
    assert 'enabled = false' in config_text
    assert USER_PIN not in config_text and SO_PIN not in config_text
    inspect = docker(*base, *controls, image, 'exec', '--', 'haskoki-ctl',
                     'store', 'inspect', '--path', STORE).stdout
    assert 'tokens: 1' in inspect, inspect
    # Re-init with the same provisioned credentials is a non-destructive
    # reopen: config, marker and seated-token count are stable.
    marker_before = (state / 'haskoki' / 'complete').read_bytes()
    docker(*base, *controls, image, 'init')
    assert (state / 'haskoki' / 'complete').read_bytes() == marker_before
    assert (state / 'haskoki' / 'haskoki.toml').read_text() == config_text
    reopened = docker(*base, *controls, image, 'exec', '--', 'haskoki-ctl',
                      'store', 'inspect', '--path', STORE).stdout
    assert 'tokens: 1' in reopened, reopened
    # Re-init on complete state is validate-only (sibling semantics): even
    # different credentials cannot change the fixed provisioning, and the
    # state is untouched.
    (secrets / 'pin').write_text('9999')
    (secrets / 'so-pin').write_text('9999')
    docker(*base, *controls, image, 'init')
    assert (state / 'haskoki' / 'complete').read_bytes() == marker_before
    assert (state / 'haskoki' / 'haskoki.toml').read_text() == config_text
    (secrets / 'pin').write_text(USER_PIN)
    (secrets / 'so-pin').write_text(SO_PIN)
    health = docker(*base, *controls, image, 'health')
    assert health.returncode == 0, health.stderr
    assert 'tokens: 1' in health.stdout
    assert 'config-ok: profile=ProfileRealCrypto' in health.stdout
    conflict = docker(*base, *controls, '-e', 'P11LAB_PIN=other', image, 'init', check=False)
    assert conflict.returncode != 0 and 'conflicting' in conflict.stderr
    stripped = docker(*base, *controls, image, 'exec', '--', 'sh', '-c',
                      'for c in python python3 pkcs11-check pkcs11-tool; do command -v "$c"; done; exit 0').stdout
    assert stripped == '', stripped
    native = docker(*base, *controls, image, 'exec', '--', 'sh', '-c',
                    'command -v haskoki-ctl; command -v haskoki-provision').stdout
    assert native.splitlines() == ['/usr/local/bin/haskoki-ctl', '/usr/local/bin/haskoki-provision'], native
    result = docker(*base, *controls, image, 'exec', '--', 'sh', '-c',
                    'printf "%s\\n" "$HASKOKI_CONFIG" "$P11LAB_MODULE" "$1"; exit 37',
                    'caller', 'literal $argument with spaces', check=False)
    assert result.returncode == 37
    assert result.stdout.splitlines() == [CONFIG, MODULE, 'literal $argument with spaces']
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
    marker = (state / 'haskoki' / 'complete').read_text()
    assert {line.split('=', 1)[0] for line in marker.splitlines()} == \
        {'schema', 'provider', 'artifact', 'token', 'backend', 'engine', 'profile'}
    assert 'token=' + TOKEN_LABEL in marker
    assert 'pin' not in marker.lower()
    assert USER_PIN not in marker and SO_PIN not in marker


@pytest.mark.parametrize('channel', CHANNELS)
@pytest.mark.parametrize('controls, message', [
    ([], 'absent'),
    (['-e', 'P11LAB_PIN=', '-e', 'P11LAB_SO_PIN=' + SO_PIN], 'empty'),
    (['-e', 'P11LAB_PIN=' + USER_PIN], 'absent'),
    (['-e', 'P11LAB_PIN=' + USER_PIN, '-e', 'P11LAB_PIN_FILE=/missing',
      '-e', 'P11LAB_SO_PIN=' + SO_PIN], 'conflicting'),
    (['-e', 'P11LAB_PIN_FILE=/missing', '-e', 'P11LAB_SO_PIN=' + SO_PIN], 'readable'),
    (['-e', 'P11LAB_PIN=9999', '-e', 'P11LAB_SO_PIN=' + SO_PIN], 'provisioned'),
    (['-e', 'P11LAB_PIN=' + USER_PIN, '-e', 'P11LAB_SO_PIN=9999'], 'provisioned'),
    (['-e', 'P11LAB_PIN=' + USER_PIN, '-e', 'P11LAB_SO_PIN=' + SO_PIN,
      '-e', 'P11LAB_LABEL=other'], 'haskoki-demo'),
])
def test_initial_credentials_fail_explicitly(channel, controls, message):
    if channel not in IMAGES:
        pytest.skip('P11LAB_TEST_HASKOKI_IMAGES lacks ' + channel)
    result = docker('run', '--rm', '--network', 'none', *controls, IMAGES[channel], 'init', check=False)
    assert result.returncode != 0 and message in result.stderr, (result.returncode, result.stderr)
    assert USER_PIN not in result.stderr and SO_PIN not in result.stderr


@pytest.mark.parametrize('channel', CHANNELS)
def test_token_slot_identity_and_label(channel, tmp_path):
    if channel not in CONSUMERS:
        pytest.skip('P11LAB_TEST_HASKOKI_CONSUMER_IMAGES lacks ' + channel)
    image = CONSUMERS[channel]
    state, secrets = tmp_path / 'state', tmp_path / 'secrets'
    state.mkdir()
    secrets.mkdir()
    (secrets / 'pin').write_bytes(USER_PIN.encode())
    (secrets / 'so-pin').write_bytes(SO_PIN.encode())
    base = lifecycle_base(state, secrets)
    controls = lifecycle_controls()
    docker(*base, *controls, image, 'init')
    listed = docker(*base, image, 'exec', '--', 'pkcs11-tool', '--module', MODULE,
                    '--list-token-slots').stdout
    assert TOKEN_LABEL in listed
    import re
    slots = [line for line in listed.splitlines() if line.startswith('Slot ')]
    assert len(slots) == 1, listed
    parsed = re.fullmatch(r'Slot (\d+) \(0x([0-9a-fA-F]+)\): (.*)', slots[0])
    assert parsed, listed
    assert (int(parsed[1]), int(parsed[2], 16)) == (0, 0), listed
    assert 'token label        : ' + TOKEN_LABEL in listed, listed
    docker(*base, image, 'exec', '--', 'pkcs11-tool', '--module', MODULE,
           '--token-label', TOKEN_LABEL, '--login', '--pin', USER_PIN, '--list-objects')


@pytest.mark.parametrize('channel', CHANNELS)
def test_concurrent_health_never_opens_module(channel, tmp_path):
    if channel not in IMAGES:
        pytest.skip('P11LAB_TEST_HASKOKI_IMAGES lacks ' + channel)
    image = IMAGES[channel]
    state, secrets = tmp_path / 'state', tmp_path / 'secrets'
    state.mkdir()
    secrets.mkdir()
    (secrets / 'pin').write_text(USER_PIN)
    (secrets / 'so-pin').write_text(SO_PIN)
    base = lifecycle_base(state, secrets)
    controls = lifecycle_controls()
    docker(*base, *controls, image, 'init')
    # Health uses lock-safe store inspection only: N concurrent health
    # containers must all succeed, which a module-open health could not
    # survive on the single-writer store.
    outcomes = []
    lock = threading.Lock()

    def one_health(index):
        try:
            completed = docker(*base, image, 'health')
            with lock:
                outcomes.append((index, completed.returncode, completed.stdout))
        except Exception as error:  # noqa: BLE001 - reported below
            with lock:
                outcomes.append((index, -1, repr(error)))

    workers = [threading.Thread(target=one_health, args=(index,)) for index in range(4)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=300)
    assert len(outcomes) == 4, outcomes
    for index, returncode, output in sorted(outcomes):
        assert returncode == 0, (index, output)
        assert 'tokens: 1' in output, (index, output)


@pytest.mark.parametrize('channel', CHANNELS)
def test_live_lock_refuses_second_open(channel, tmp_path):
    if channel not in IMAGES:
        pytest.skip('P11LAB_TEST_HASKOKI_IMAGES lacks ' + channel)
    image = IMAGES[channel]
    state, secrets = tmp_path / 'state', tmp_path / 'secrets'
    state.mkdir()
    secrets.mkdir()
    (secrets / 'pin').write_text(USER_PIN)
    (secrets / 'so-pin').write_text(SO_PIN)
    base = lifecycle_base(state, secrets)
    controls = lifecycle_controls()
    docker(*base, *controls, image, 'init')
    # A live owner pid in the sidecar exercises the real single-writer
    # refusal path. Upstream maps every store-open failure to a NULL open
    # reported as CKR_GENERAL_ERROR (0x5); that native value is preserved,
    # never normalized, and the detail string stays internal by design.
    script = ('sleep 60 & holder=$!; printf "%s\\n" "$holder" > ' + STORE + '.lock; '
              'if /usr/local/bin/haskoki-provision ' + MODULE + ' > /tmp/held.log 2>&1; then '
              'echo SECOND-OPEN-ACCEPTED; else echo "refused rc=$?"; fi; '
              'kill "$holder"; rm -f ' + STORE + '.lock; cat /tmp/held.log')
    held = docker(*base, *controls, image, 'exec', '--', 'sh', '-c', script)
    assert held.returncode == 0, held.stderr
    assert 'SECOND-OPEN-ACCEPTED' not in held.stdout, held.stdout
    assert 'refused rc=1' in held.stdout, held.stdout
    assert 'C_Initialize failed (rv=0x5)' in held.stdout, held.stdout
    health = docker(*base, image, 'health')
    assert health.returncode == 0, health.stderr
    assert 'tokens: 1' in health.stdout


def run_direct(channel, image, argv, inputs, output, caller, timeout=300):
    spec = RunSpec('haskoki', channel, 'direct', as_ref(image), 'provider', None, None,
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
        pytest.skip('P11LAB_TEST_HASKOKI_CONSUMER_IMAGES lacks ' + channel)
    pin, so_pin = write_pins(tmp_path)
    caller = tmp_path / 'caller'
    caller.mkdir()
    output = tmp_path / 'output'
    run_direct(channel, CONSUMERS[channel], (*SMOKE_ARGV, 'generated'),
               {'P11LAB_PIN_FILE': str(pin), 'P11LAB_SO_PIN_FILE': str(so_pin),
                'P11LAB_LABEL': TOKEN_LABEL}, output, caller)
    metadata = json.loads((output / 'crypto/result.json').read_text())
    assert metadata['key_mode'] == 'generated'
    assert not list(caller.rglob('*.jsonl')) and not list(output.rglob('*.jsonl'))
    print('oracle:', oracle(output / 'crypto'), '|', openssl_version())


@pytest.mark.parametrize('channel', CHANNELS)
def test_token_row_persists_across_processes(channel, tmp_path):
    if channel not in CONSUMERS:
        pytest.skip('P11LAB_TEST_HASKOKI_CONSUMER_IMAGES lacks ' + channel)
    image = CONSUMERS[channel]
    state, secrets = tmp_path / 'state', tmp_path / 'secrets'
    state.mkdir()
    secrets.mkdir()
    (secrets / 'pin').write_bytes(USER_PIN.encode())
    (secrets / 'so-pin').write_bytes(SO_PIN.encode())
    base = lifecycle_base(state, secrets)
    controls = lifecycle_controls()
    docker(*base, *controls, image, 'init')
    first = docker(*base, image, 'exec', '--', 'pkcs11-tool', '--module', MODULE,
                   '--list-token-slots')
    assert TOKEN_LABEL in first.stdout, first.stdout
    assert 'tokens: 1' in docker(*base, image, 'exec', '--', 'haskoki-ctl', 'store', 'inspect',
                                 '--path', STORE).stdout
    reopen = docker(*base, image, 'exec', '--', 'pkcs11-tool', '--module', MODULE,
                    '--token-label', TOKEN_LABEL, '--login', '--pin', USER_PIN, '--list-slots')
    assert TOKEN_LABEL in reopen.stdout, reopen.stdout
    assert 'tokens: 1' in docker(*base, image, 'exec', '--', 'haskoki-ctl', 'store', 'inspect',
                                 '--path', STORE).stdout


@pytest.mark.parametrize('channel', CHANNELS)
def test_persisted_key_reopens_in_fresh_processes(channel, tmp_path):
    if channel not in CONSUMERS:
        pytest.skip('P11LAB_TEST_HASKOKI_CONSUMER_IMAGES lacks ' + channel)
    image = CONSUMERS[channel]
    pin, so_pin = write_pins(tmp_path)
    caller = tmp_path / 'caller'
    caller.mkdir()
    state = tmp_path / 'persistent state'
    state.mkdir()
    inputs = {'P11LAB_PIN_FILE': str(pin), 'P11LAB_SO_PIN_FILE': str(so_pin),
              'P11LAB_LABEL': TOKEN_LABEL, 'P11LAB_STATE_DIR': str(state)}
    provision = RunSpec('haskoki', channel, 'direct', as_ref(image), 'provider', None, None,
                        ('pkcs11-tool', '--module', MODULE, '--token-label', TOKEN_LABEL,
                         '--login', '--pin', USER_PIN, '--keypairgen', '--key-type', 'EC:prime256v1',
                         '--id', '42', '--label', 'haskoki-persist'),
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
        pytest.skip('P11LAB_TEST_HASKOKI_IMAGES lacks ' + channel)
    image = IMAGES[channel]
    state, secrets = tmp_path / 'state', tmp_path / 'secrets'
    state.mkdir()
    secrets.mkdir()
    (secrets / 'pin').write_bytes(USER_PIN.encode())
    (secrets / 'so-pin').write_bytes(SO_PIN.encode())
    base = lifecycle_base(state, secrets)
    controls = lifecycle_controls()
    docker(*base, *controls, image, 'init')
    (state / 'haskoki' / 'token.sqlite').unlink()
    config_before = (state / 'haskoki' / 'haskoki.toml').read_bytes()
    marker_before = (state / 'haskoki' / 'complete').read_bytes()
    for operation in ('init', 'health'):
        result = docker(*base, image, operation, check=False)
        assert result.returncode != 0 and 'partial' in result.stderr
    result = docker(*base, image, 'exec', '--', 'sh', '-c', 'echo APP-RAN', check=False)
    assert result.returncode != 0 and 'APP-RAN' not in result.stdout
    assert not (state / 'haskoki' / 'token.sqlite').exists()
    assert (state / 'haskoki' / 'haskoki.toml').read_bytes() == config_before
    assert (state / 'haskoki' / 'complete').read_bytes() == marker_before


@pytest.mark.parametrize('channel', CHANNELS)
def test_direct_checker_smoke(channel, tmp_path):
    if channel not in CHECKERS:
        pytest.skip('P11LAB_TEST_HASKOKI_CHECKER_IMAGES lacks ' + channel)
    from p11lab.checker import run_checker
    pin, so_pin = write_pins(tmp_path)
    caller = tmp_path / 'caller'
    caller.mkdir()
    output = tmp_path / 'output'
    spec = RunSpec('haskoki', channel, 'direct', as_ref(CHECKERS[channel]), 'provider', None, None,
                   (), {'P11LAB_PIN_FILE': str(pin), 'P11LAB_SO_PIN_FILE': str(so_pin),
                        'P11LAB_LABEL': TOKEN_LABEL},
                   output, caller, 1500)
    result = run_checker(spec, 'smoke-v1')
    record = json.loads((output / 'checker/checker-receipt.json').read_text())
    assert record['evidence']['observations_complete'] is True, record['evidence']
    assert record['token']['label'] == TOKEN_LABEL
    assert record['token']['token_present_index'] == record['token']['native_slot_id'] == 0
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
    spec = RunSpec('haskoki', channel, 'proxy', as_ref(DAEMONS[channel]), 'container', as_ref(CALLER),
                   ArtifactRef('bundle', str(bundle),
                               hashlib.sha256(bundle.read_bytes()).hexdigest(), 'linux/amd64'),
                   ('/usr/local/bin/p11lab-smoke', '--module',
                    '/run/p11lab-client/libpkcs11_proxy_ng_shim.so', '--token-label', TOKEN_LABEL,
                    '--pin-file', '/run/p11lab-input/P11LAB_PIN_FILE',
                    '--output', '/p11lab-output/crypto', '--key-mode', 'generated'),
                   {'P11LAB_PIN_FILE': str(pin), 'P11LAB_SO_PIN_FILE': str(so_pin),
                    'P11LAB_LABEL': TOKEN_LABEL},
                   output, caller, 600)
    result = run_application(spec)
    assert result.exit_code == 0, (result.lifecycle_errors, result.cleanup_errors)
    assert result.app_returncode == 0
    assert (output / 'proxy-health.stdout.log').read_text().strip() == 'SERVING'
    oracle(output / 'crypto')


def test_proxy_crypto_host(tmp_path):
    channel = 'rolling'
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
    spec = RunSpec('haskoki', channel, 'proxy', as_ref(DAEMONS[channel]), 'host', None,
                   ArtifactRef('bundle', str(bundle),
                               hashlib.sha256(bundle.read_bytes()).hexdigest(), 'linux/amd64'),
                   ('sh', '-c', script, str(binary), str(pin)),
                   {'P11LAB_PIN_FILE': str(pin), 'P11LAB_SO_PIN_FILE': str(so_pin),
                    'P11LAB_LABEL': TOKEN_LABEL},
                   output, caller, 600)
    result = run_application(spec)
    assert result.exit_code == 0, (result.lifecycle_errors, result.cleanup_errors)
    oracle(output / 'crypto')
