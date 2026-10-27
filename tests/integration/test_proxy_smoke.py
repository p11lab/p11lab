"""Pinned mTLS proxy consumer paths: unit contracts plus opt-in Docker lanes.

P11LAB_TEST_PROXY_IMAGES is a JSON channel -> exact daemon derivative engine-ID
map. P11LAB_TEST_PROXY_CALLER_IMAGE is the exact caller-owned application
image. P11LAB_TEST_PROXY_CHECKER_IMAGES maps channels to installed checker
consumer images. P11LAB_TEST_PROXY_CLIENTS maps channels to
{"path": archive, "sha256": digest} native-client bundles. No reference
workspace is mounted anywhere.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from p11lab import run as run_module
from p11lab import tls as tls_module
from p11lab.catalog import package_data
from p11lab.docker import CommandResult
from p11lab.models import ArtifactRef, RunSpec

IMAGES = json.loads(os.environ.get('P11LAB_TEST_PROXY_IMAGES', '{}'))
CALLER = os.environ.get('P11LAB_TEST_PROXY_CALLER_IMAGE', '')
CHECKERS = json.loads(os.environ.get('P11LAB_TEST_PROXY_CHECKER_IMAGES', '{}'))
CLIENTS = json.loads(os.environ.get('P11LAB_TEST_PROXY_CLIENTS', '{}'))
NEEDS_DOCKER = not IMAGES or not CALLER or not CHECKERS or not CLIENTS

DAEMON_IMAGE = ArtifactRef('docker-local', 'sha256:' + 'a' * 64, 'a' * 64, 'linux/amd64')
CALLER_IMAGE = ArtifactRef('docker-local', 'sha256:' + 'b' * 64, 'b' * 64, 'linux/amd64')
CLIENT_BUNDLE = ArtifactRef('bundle', '/tmp/client.tar.gz', 'c' * 64, 'linux/amd64')

DERIVATIVE_BUILD = {'schema_version': 1, 'source_revision': tls_module.PROXY_SOURCE_REVISION,
                    'cargo_lock_sha256': tls_module.PROXY_CARGO_LOCK_SHA256,
                    'binaries': {'pkcs11-proxy-ng': 'd' * 64, 'pkcs11-proxy-ng-cli': 'e' * 64,
                                 'proxy-entrypoint.sh': 'f' * 64}}
CLIENT_MANIFEST = {'source': {'proxy': {'source_revision': tls_module.PROXY_SOURCE_REVISION,
                                        'cargo_lock_sha256': tls_module.PROXY_CARGO_LOCK_SHA256,
                                        'shim_sha256': '9' * 64, 'cli_sha256': 'e' * 64}}}

# Test-driver-only checker lane script, executed inside the checker consumer.
# Mirrors p11lab.checker._main + execute_checker (same collection check, same
# test flags, same provenance file) with two documented proxy accommodations:
# the child environment is preserved rather than scrubbed so the shim keeps
# its PKCS11_PROXY_* transport config, and PYTHONPATH carries the exit-time
# C_Finalize hook below. Never shipped; frozen checker code is untouched.
CHECKER_PROXY_DRIVER = '''"""Proxy checker-lane driver (test driver only, never shipped)."""
import json
import os
import subprocess
import sys
from pathlib import Path

TIMEOUT = 850

nodes = json.loads(sys.argv[1])
out = Path('/p11lab-output/checker')
out.mkdir(parents=True, exist_ok=False)
out.chmod(0o700)

from p11lab.checker import SOURCE, WHEEL, LOCK, canonical_node, installed_identity

identity = installed_identity()
root = Path(identity['installed_root'])

base_env = dict(os.environ)
base_env['PYTHONPATH'] = '/workspace/p11lab-proxy-driver'
discover = subprocess.run(
    [sys.executable, '-c',
     'import os; from pathlib import Path; '
     'from pkcs11_check.core.loader import load_module; '
     'p11 = load_module(Path(os.environ["P11LAB_MODULE"]), interface="auto"); '
     'slots = p11.get_slots(token_present=True); '
     'label = os.environ.get("P11LAB_LABEL", "P11Lab"); '
     'sel = [(i, s.slot_id) for i, s in enumerate(slots) if s.get_token().label == label]; '
     'assert len(sel) == 1, "token identity must select exactly one token-present slot"; '
     'p11.raw.C_Finalize(None); '
     'print(str(sel[0][0]) + " " + str(sel[0][1]))'],
    capture_output=True, text=True, timeout=120, env=base_env)
if discover.returncode:
    sys.stderr.write(discover.stderr[-2000:])
    sys.exit(2)
slot, native_id = discover.stdout.strip().split()
(out / 'slot.json').write_text(json.dumps({'token_present_index': int(slot), 'native_slot_id': int(native_id),
                                           'label': os.environ.get('P11LAB_LABEL', 'P11Lab')}, indent=2))


def secret(name):
    if name + '_FILE' in os.environ:
        return Path(os.environ[name + '_FILE']).read_text().rstrip('\\n')
    return os.environ[name]


pin, so_pin = secret('P11LAB_PIN'), secret('P11LAB_SO_PIN')
(out / 'build-provenance.json').write_text(json.dumps(
    {'extra': {'checker': {'source_revision': SOURCE, 'wheel_sha256': WHEEL, 'runtime_lock_sha256': LOCK}}}, indent=2))
env = dict(base_env)
env.update(HOME=str(out), XDG_CONFIG_HOME=str(out), PYTEST_DISABLE_PLUGIN_AUTOLOAD='1', PYTEST_ADDOPTS='-v',
           P11TEST_PIN=pin, P11TEST_SO_PIN=so_pin, PKCS11_CHECK_FRAMEWORK_VERSION='0.2.3',
           PKCS11_CHECK_BUILD_PROVENANCE=str(out / 'build-provenance.json'))

targets = [str(root / node) for node in nodes]
collect = subprocess.run([sys.executable, '-m', 'pkcs11_check', 'list-tests', '--include-disabled', *targets],
                         cwd=out, env=env, capture_output=True, text=True, timeout=180)
(out / 'collection.stdout.log').write_text(collect.stdout)
(out / 'collection.stderr.log').write_text(collect.stderr)
collected = [canonical_node(n, root) for n in collect.stdout.splitlines()]
if collect.returncode or len(collected) != len(targets) or set(collected) != set(targets):
    sys.stderr.write('installed collection differs from frozen selection\\n')
    sys.exit(2)
(out / 'collection.json').write_text(json.dumps({'nodes': nodes, 'installed_nodes': collected,
                                                 'returncode': collect.returncode}, indent=2))

argv = [sys.executable, '-m', 'pkcs11_check', 'test', '--module', os.environ['P11LAB_MODULE'],
        '--slot', slot, '--interface', 'auto', '--isolation', 'file', '--timeout', '180',
        '--ignore-disabled-tests', '--no-collection-cache', '--key-inject', 'off', '--recover-mode', 'off',
        '--output', 'json', '--output-file', str(out / 'results.json'), '--state-file', str(out / 'state.json'),
        '--policy-file', str(out / 'policy.json'), *targets]
with open(out / 'checker.stdout.log', 'wb') as so, open(out / 'checker.stderr.log', 'wb') as se:
    try:
        process = subprocess.run(argv, cwd=out, env=env, stdout=so, stderr=se,
                                 timeout=TIMEOUT, start_new_session=True)
    except subprocess.TimeoutExpired:
        sys.exit(124)
for name in ('checker.stdout.log', 'checker.stderr.log'):
    data = (out / name).read_bytes()
    if len(data) > 1024 * 1024:
        data = data[:1024 * 1024] + b'\\n[TRUNCATED]\\n'
    text = data.decode('utf-8', 'replace')
    for value in sorted({pin, so_pin} - {''}, key=len, reverse=True):
        text = text.replace(value, '[REDACTED]')
    (out / name).write_text(text)
sys.exit(process.returncode)
'''

# Exit-time C_Finalize for checker grandchildren (test driver only, never
# shipped). The checker's preflight helper initializes the module and exits
# without C_Finalize; against max_contexts=1 its orphaned context would block
# the first unit until lease expiry. No verdict or error is altered.
PROXY_SITECUSTOMIZE = '''"""Proxy-acceptance exit-time C_Finalize (test driver only, never shipped)."""
import atexit


def _p11lab_proxy_finalize_at_exit():
    try:
        import ctypes
        import os
        module = os.environ.get('P11LAB_MODULE')
        if not module:
            return

        class _Prefix(ctypes.Structure):
            _fields_ = [('major', ctypes.c_ubyte), ('minor', ctypes.c_ubyte),
                        ('C_Initialize', ctypes.c_void_p), ('C_Finalize', ctypes.c_void_p)]

        lib = ctypes.CDLL(module)
        functions = ctypes.c_void_p()
        if lib.C_GetFunctionList(ctypes.byref(functions)) != 0 or not functions.value:
            return
        finalize = ctypes.CFUNCTYPE(ctypes.c_ulong, ctypes.c_void_p)(
            _Prefix.from_address(functions.value).C_Finalize)
        finalize(None)
    except Exception:
        pass


atexit.register(_p11lab_proxy_finalize_at_exit)
'''


def test_rendered_daemon_toml_matches_contract():
    assert run_module.render_proxy_toml(module_path='/usr/local/lib/p11lab/libsofthsm2.so') == (
        '[backend]\nmodule = "/usr/local/lib/p11lab/libsofthsm2.so"\n'
        '\n[proxy]\nmax_contexts = 1\nmechanism_discovery = "transparent"\nlease_seconds = 1\n'
        'request_timeout_secs = 60\nstartup_timeout_secs = 30\n'
        '\n[listener.remote]\nbind = "0.0.0.0:7512"\nauth = "mtls"\nallow_insecure_tcp = false\n'
        'ca_cert = "/run/p11lab-tls/ca.crt"\nserver_cert = "/run/p11lab-tls/server.crt"\n'
        'server_key = "/run/p11lab-tls/server.key"\n\n[auth]\nallow_all_authenticated = true\n')
    with pytest.raises(ValueError):
        run_module.render_proxy_toml(module_path='relative/path.so')


def proxy_spec(tmp_path, **overrides):
    values = dict(environment='softhsm2', channel='release', mode='proxy', artifact=DAEMON_IMAGE,
                  execution_location='container', consumer_artifact=CALLER_IMAGE, client_artifact=CLIENT_BUNDLE,
                  argv=('app', '--flag'), inputs={'P11LAB_LABEL': 'P11Lab'}, output_dir=tmp_path / 'out',
                  cwd=tmp_path, timeout_seconds=60, installed_prefix=None)
    return RunSpec(**(values | overrides))


def test_prepare_proxy_accepts_both_lanes(tmp_path):
    assert run_module.prepare_proxy(proxy_spec(tmp_path))['host'] is False
    host = proxy_spec(tmp_path, execution_location='host', consumer_artifact=None)
    assert run_module.prepare_proxy(host)['host'] is True


@pytest.mark.parametrize('overrides', [
    {'mode': 'direct'},
    {'execution_location': 'provider'},
    {'artifact': ArtifactRef('docker-local', 'sha256:' + 'a' * 64, 'b' * 64, 'linux/amd64')},
    {'consumer_artifact': None},
    {'consumer_artifact': ArtifactRef('bundle', '/tmp/x.tar.gz', 'b' * 64, 'linux/amd64')},
    {'client_artifact': None},
    {'client_artifact': DAEMON_IMAGE},
    {'installed_prefix': Path('/tmp/prefix')},
    {'argv': ()},
    {'inputs': {'UNKNOWN': 'x'}},
    {'timeout_seconds': 0},
])
def test_prepare_proxy_container_rejects(tmp_path, overrides):
    with pytest.raises(ValueError):
        run_module.prepare_proxy(proxy_spec(tmp_path, **overrides))


def test_prepare_proxy_host_rejects_consumer_image(tmp_path):
    spec = proxy_spec(tmp_path, execution_location='host', consumer_artifact=CALLER_IMAGE)
    with pytest.raises(ValueError):
        run_module.prepare_proxy(spec)


def test_check_proxy_identities_matches_exact_build():
    assert run_module.check_proxy_identities(DERIVATIVE_BUILD, CLIENT_MANIFEST) == DERIVATIVE_BUILD


@pytest.mark.parametrize('derivative', [
    {'schema_version': 1, 'source_revision': '0' * 40, 'cargo_lock_sha256': tls_module.PROXY_CARGO_LOCK_SHA256,
     'binaries': DERIVATIVE_BUILD['binaries']},
    {'schema_version': 1, 'source_revision': tls_module.PROXY_SOURCE_REVISION, 'cargo_lock_sha256': '0' * 64,
     'binaries': DERIVATIVE_BUILD['binaries']},
    {'schema_version': 1, 'source_revision': tls_module.PROXY_SOURCE_REVISION,
     'cargo_lock_sha256': tls_module.PROXY_CARGO_LOCK_SHA256,
     'binaries': {'pkcs11-proxy-ng-cli': '0' * 64}},
])
def test_check_proxy_identities_rejects_component_change(derivative):
    with pytest.raises(ValueError):
        run_module.check_proxy_identities(derivative, CLIENT_MANIFEST)


def test_client_build_rejects_foreign_proxy(tmp_path):
    from p11lab.native import build_native_client_bundle
    shim, cli = tmp_path / 'shim.so', tmp_path / 'cli'
    shim.write_bytes(b'shim-bytes')
    cli.write_bytes(b'cli-bytes')
    import hashlib
    proxy = {'source_revision': '0' * 40, 'cargo_lock_sha256': tls_module.PROXY_CARGO_LOCK_SHA256,
             'source_archive_sha256': '0' * 64,
             'shim_sha256': hashlib.sha256(b'shim-bytes').hexdigest(),
             'cli_sha256': hashlib.sha256(b'cli-bytes').hexdigest(), 'toolchain': {'note': 'test'}}
    with pytest.raises(ValueError, match='proxy component identity'):
        build_native_client_bundle(proxy=proxy, shim=shim, cli=cli, licenses={}, output_dir=tmp_path / 'bundle',
                                   environment='softhsm2', channel='release')


class FakeEngine:
    """Scripted Docker double: records every creation for mount/contract assertions."""

    def __init__(self, build_stdout):
        self.build_stdout = build_stdout
        self.created = []
        self.removed = []
        self.commands = []
        self.networks = set()

    def image(self, artifact):
        return {'Id': artifact.reference, 'Os': 'linux', 'Architecture': 'amd64',
                'Descriptor': {'digest': artifact.reference}}

    def volume(self, name, labels, state_dir=None):
        return name

    def create(self, image, argv, options, labels, name):
        identity = f'container-{len(self.created)}'
        self.created.append({'image': image, 'argv': tuple(argv), 'options': list(options),
                             'labels': dict(labels), 'name': name, 'id': identity})
        return identity

    def execute(self, identity, timeout, interrupted):
        argv = self.created[int(identity.split('-')[1])]['argv']
        if argv[:1] == ('proxy-build',):
            return CommandResult(0, self.build_stdout, '', False)
        if argv[0] == 'cli':
            return CommandResult(0, 'SERVING\n', '', False)
        return CommandResult(0, 'caller output', '', False)

    def command(self, args, timeout=15, *, check=True, **kwargs):
        self.commands.append(list(args))
        if args[:2] == ['network', 'create']:
            self.networks.add(args[-1])
            return CommandResult(0, args[-1] + '-id\n', '', False)
        if args[:2] == ['network', 'inspect']:
            name = args[-1]
            assert name in self.networks
            return CommandResult(0, json.dumps([{'Name': name, 'Labels': {}}]), '', False)
        if args[0] in {'start', 'port', 'logs'}:
            return CommandResult(0, '127.0.0.1:32768\n' if args[0] == 'port' else '', '', False)
        raise AssertionError('unexpected command: ' + ' '.join(args))

    def remove(self, kind, identity, labels):
        self.removed.append((kind, identity))


class FakeInstalled:
    def __init__(self, prefix):
        from p11lab.native import CLIENT_MODULE
        self.artifact = CLIENT_BUNDLE
        self.prefix = prefix
        self.manifest = CLIENT_MANIFEST | {'environment': 'softhsm2', 'channel': 'release'}
        self.manifest_sha256 = '1' * 64
        self.receipt_path = prefix / '.p11lab-install.json'
        self.receipt_sha256 = '2' * 64
        shim = prefix / 'payload' / CLIENT_MODULE
        shim.parent.mkdir(parents=True)
        shim.write_bytes(b'fake-shim')


def fake_client(monkeypatch, tmp_path):
    import p11lab.native as native

    def install(artifact, prefix, *, environment, channel):
        assert artifact == CLIENT_BUNDLE
        return FakeInstalled(Path(prefix))

    monkeypatch.setattr(native, 'install_native_client_bundle', install)
    monkeypatch.setattr(native, 'preflight_native_client',
                        lambda prefix, manifest: {'loader': '/lib64/ld-linux-x86-64.so.2', 'architecture': 'x86_64',
                                                  'closure': {'shim': {'resolved': []}}, 'cli_version': 'test'})


def mounts_of(entry):
    options = entry['options']
    return [options[i + 1] for i, flag in enumerate(options) if flag == '--mount']


def test_orchestration_mounts_endpoints_and_cleanup(monkeypatch, tmp_path):
    engine = FakeEngine(json.dumps(DERIVATIVE_BUILD))
    monkeypatch.setattr(run_module, 'Docker', lambda: engine)
    fake_client(monkeypatch, tmp_path)
    spec = proxy_spec(tmp_path)
    result = run_module.run_application(spec)
    assert result.exit_code == 0, result
    assert result.lifecycle_errors == () and result.cleanup_errors == ()
    by_argv = {entry['argv'][0]: entry for entry in engine.created}
    assert [entry['argv'][0] for entry in engine.created] == [
        'proxy-build', 'init', 'daemon', 'cli', '--flag', 'health']
    # No CA private key in any mount or option of any stage.
    for entry in engine.created:
        assert not any('ca.key' in option for option in entry['options']), entry['argv']
    daemon = by_argv['daemon']
    assert daemon['image'] == DAEMON_IMAGE.reference
    assert daemon['argv'] == ('daemon', '/etc/p11lab/proxy.toml')
    assert '--network-alias' in daemon['options']
    daemon_mounts = mounts_of(daemon)
    assert any('dst=/run/p11lab-tls/server.key,readonly' in mount for mount in daemon_mounts)
    assert any('dst=/etc/p11lab/proxy.toml,readonly' in mount for mount in daemon_mounts)
    assert any('dst=/var/lib/p11lab' in mount for mount in daemon_mounts)
    health = by_argv['cli']
    assert health['argv'][-1] == 'health'
    assert 'https://provider-daemon:7512' in health['argv']
    assert not any('dst=/var/lib/p11lab' in mount for mount in mounts_of(health))
    app = by_argv['--flag']
    assert app['image'] == CALLER_IMAGE.reference
    assert app['argv'] == ('--flag',)
    assert app['options'][app['options'].index('--entrypoint') + 1] == 'app'
    app_mounts = mounts_of(app)
    assert any('dst=/run/p11lab-client/libpkcs11_proxy_ng_shim.so,readonly' in mount for mount in app_mounts)
    assert any('dst=/run/p11lab-client-tls/client.key,readonly' in mount for mount in app_mounts)
    assert any('dst=/workspace' in mount and 'src=' + str(tmp_path.resolve()) in mount for mount in app_mounts)
    assert not any('dst=/var/lib/p11lab' in mount for mount in app_mounts)
    env = [app['options'][i + 1] for i, flag in enumerate(app['options']) if flag == '--env']
    assert 'P11LAB_MODULE=/run/p11lab-client/libpkcs11_proxy_ng_shim.so' in env
    assert 'PKCS11_PROXY_ENDPOINT=https://provider-daemon:7512' in env
    assert 'PKCS11_PROXY_TLS_CA_CERT=/run/p11lab-client-tls/ca.crt' in env
    # Every owned resource is removed exactly once, network included.
    assert sorted(engine.removed) == sorted(
        [('container', entry['id']) for entry in engine.created] +
        [('volume', 'p11lab-' + json.loads(result.receipt_path.read_text())['run_id']),
         ('network', 'p11lab-proxy-' + json.loads(result.receipt_path.read_text())['run_id'])])
    record = json.loads(result.receipt_path.read_text())
    assert record['artifacts']['consumer']['reference'] == CALLER_IMAGE.reference
    assert record['artifacts']['client']['sha256'] == CLIENT_BUNDLE.sha256
    assert record['proxy']['tls']['server']['sans'] == ['127.0.0.1', 'localhost', 'provider-daemon']
    assert [stage['phase'] for stage in record['stages']] == [
        'proxy-build', 'init', 'daemon-start', 'proxy-health', 'application',
        'daemon-stop', 'post-health']
    assert record['stages'][-2] == {
        'phase': 'daemon-stop', 'container_id': daemon['id'], 'stopped': True}


def test_orchestration_refuses_foreign_derivative(monkeypatch, tmp_path):
    foreign = dict(DERIVATIVE_BUILD, source_revision='0' * 40)
    engine = FakeEngine(json.dumps(foreign))
    monkeypatch.setattr(run_module, 'Docker', lambda: engine)
    fake_client(monkeypatch, tmp_path)
    result = run_module.run_application(proxy_spec(tmp_path))
    assert result.exit_code == 1
    assert result.lifecycle_errors == ('proxy identity failed',)
    assert result.cleanup_errors == ()
    assert result.app_returncode is None
    assert [entry['argv'][0] for entry in engine.created] == ['proxy-build']
    record = json.loads(result.receipt_path.read_text())
    assert engine.removed == [('volume', 'p11lab-' + record['run_id']),
                              ('container', engine.created[0]['id'])]
    assert [stage['phase'] for stage in record['stages']] == ['proxy-build']


needs_docker = pytest.mark.skipif(NEEDS_DOCKER, reason='explicit proxy derivatives, caller image and client bundles required')


def docker(*args, check=True):
    return subprocess.run(['docker', *args], capture_output=True, text=True, check=check, timeout=180)


def evidence_root(tmp_path, name):
    root = Path(os.environ['P11LAB_TEST_PROXY_EVIDENCE']) / name if os.environ.get('P11LAB_TEST_PROXY_EVIDENCE') else tmp_path
    root.mkdir(parents=True, exist_ok=True)
    return root


def caller_dir(root):
    caller = root / 'caller with spaces'
    caller.mkdir(exist_ok=True)
    pin, so = caller / 'pin', caller / 'so-pin'
    pin.write_bytes(b'1234')
    so.write_bytes(b'12345678')
    pin.chmod(0o600)
    so.chmod(0o600)
    return caller


def daemon_ref(channel):
    return ArtifactRef('docker-local', IMAGES[channel], IMAGES[channel][7:], 'linux/amd64')


def caller_ref():
    return ArtifactRef('docker-local', CALLER, CALLER[7:], 'linux/amd64')


def checker_ref(channel):
    return ArtifactRef('docker-local', CHECKERS[channel], CHECKERS[channel][7:], 'linux/amd64')


def client_ref(channel):
    return ArtifactRef('bundle', CLIENTS[channel]['path'], CLIENTS[channel]['sha256'], 'linux/amd64')


def assert_clean(receipt):
    record = json.loads(receipt.read_text())
    assert not record['cleanup_errors']
    for item in record['owned_resources']:
        assert docker(item['kind'], 'inspect', item['identity'], check=False).returncode != 0
    return record


def verify_crypto(output):
    verifier = output.parent / 'verify.py'
    verifier.write_bytes(package_data('consumer/verify.py').read_bytes())
    try:
        result = subprocess.run([sys.executable, str(verifier), str(output)],
                                capture_output=True, text=True, timeout=120, check=False)
    finally:
        verifier.unlink(missing_ok=True)
    assert 'altered message rejected' in result.stdout, result.stderr
    assert result.returncode == 0
    return result.stdout


APP_ARGV = ('p11lab-smoke', '--module', '/run/p11lab-client/libpkcs11_proxy_ng_shim.so', '--token-label', 'P11Lab',
            '--pin-file', '/run/p11lab-input/P11LAB_PIN_FILE', '--output', '/p11lab-output/crypto',
            '--key-mode', 'generated')


@needs_docker
@pytest.mark.parametrize('channel,image', list(IMAGES.items()))
def test_container_app_crypto_oracle(channel, image, tmp_path):
    from p11lab.run import run_application
    root = evidence_root(tmp_path, 'app-' + channel)
    caller = caller_dir(root)
    try:
        spec = RunSpec('softhsm2', channel, 'proxy', daemon_ref(channel), 'container', caller_ref(),
                       client_ref(channel), APP_ARGV,
                       {'P11LAB_PIN_FILE': str(caller / 'pin'), 'P11LAB_SO_PIN_FILE': str(caller / 'so-pin'),
                        'P11LAB_LABEL': 'P11Lab'},
                       root / 'generated', caller, 300)
        result = run_application(spec)
        assert result.exit_code == 0, result
        metadata = json.loads((spec.output_dir / 'crypto/result.json').read_text())
        assert metadata['key_mode'] == 'generated'
        oracle = verify_crypto(spec.output_dir / 'crypto')
        (root / 'oracle.txt').write_text(oracle)
        record = assert_clean(result.receipt_path)
        assert record['artifacts']['consumer']['reference'] == CALLER
        assert record['artifacts']['provider']['reference'] == image
        assert record['artifacts']['consumer']['reference'] != record['artifacts']['provider']['reference']
        assert record['proxy']['endpoint'] == 'https://provider-daemon:7512'
        assert (spec.output_dir / 'proxy-health.stdout.log').read_text().strip() == 'SERVING'
    finally:
        (caller / 'pin').unlink(missing_ok=True)
        (caller / 'so-pin').unlink(missing_ok=True)


@needs_docker
@pytest.mark.parametrize('channel,image', list(IMAGES.items()))
def test_container_checker_evidence(channel, image, tmp_path):
    from p11lab.checker import SOURCE, WHEEL, LOCK, load_profile
    from p11lab.run import run_application
    root = evidence_root(tmp_path, 'checker-' + channel)
    caller = caller_dir(root)
    driver = caller / 'p11lab-proxy-driver'
    driver.mkdir(exist_ok=True)
    (driver / 'checker_proxy_driver.py').write_text(CHECKER_PROXY_DRIVER)
    (driver / 'sitecustomize.py').write_text(PROXY_SITECUSTOMIZE)
    try:
        nodes = json.dumps(load_profile()['nodes'], separators=(',', ':'))
        spec = RunSpec('softhsm2', channel, 'proxy', daemon_ref(channel), 'container', checker_ref(channel),
                       client_ref(channel),
                       ('/opt/p11lab-checker/bin/python', '/workspace/p11lab-proxy-driver/checker_proxy_driver.py', nodes),
                       {'P11LAB_PIN': '1234', 'P11LAB_SO_PIN': '12345678', 'P11LAB_LABEL': 'P11Lab'},
                       root / 'run', caller, 900)
        result = run_application(spec)
        assert result.exit_code == 0, result
        record = assert_clean(result.receipt_path)
        assert record['artifacts']['consumer']['reference'] == CHECKERS[channel]
        slot = json.loads((spec.output_dir / 'checker/slot.json').read_text())
        assert slot['token_present_index'] == 0 and slot['label'] == 'P11Lab'
        payload = json.loads((spec.output_dir / 'checker/results.json').read_text())
        assert payload['provenance']['extra']['checker'] == {
            'source_revision': SOURCE, 'wheel_sha256': WHEEL, 'runtime_lock_sha256': LOCK}
        script = ('import json; from pathlib import Path; '
                  'from p11lab.checker import installed_identity, load_profile, validate_results; '
                  'nodes = load_profile()["nodes"]; root = Path(installed_identity()["installed_root"]); '
                  'verdict = validate_results(Path("/evidence"), nodes, root); '
                  'Path("/validation.json").write_text(json.dumps(verdict, indent=2)); '
                  'assert verdict["complete"], verdict["errors"]')
        outcome = docker('run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
                         '--security-opt', 'no-new-privileges', '--user', f'{os.getuid()}:{os.getgid()}',
                         '--tmpfs', '/tmp:rw,nosuid,nodev',
                         '--mount', f'type=bind,src={spec.output_dir / "checker"},dst=/evidence,readonly',
                         '--mount', f'type=bind,src={root},dst=/validation-dir',
                         '--entrypoint', '/opt/p11lab-checker/bin/python', CHECKERS[channel],
                         '-c', script.replace('/validation.json', '/validation-dir/validation.json'))
        assert outcome.returncode == 0, outcome.stderr
        verdict = json.loads((root / 'validation.json').read_text())
        assert verdict['summary']['total'] == 23 and verdict['summary']['incomplete'] is False
    finally:
        (caller / 'pin').unlink(missing_ok=True)
        (caller / 'so-pin').unlink(missing_ok=True)


def host_smoke_binary(root):
    binary = root / 'hostbin' / 'p11lab-smoke'
    if binary.exists():
        return binary
    if shutil.which('cc') is None:
        pytest.skip('host C compiler required')
    sources = root / 'consumer-sources'
    sources.mkdir(exist_ok=True)
    for name in ('smoke.c', 'p256.c', 'p256.h'):
        (sources / name).write_bytes(package_data('consumer/' + name).read_bytes())
    vendor = sources / 'vendor'
    vendor.mkdir(exist_ok=True)
    (vendor / 'pkcs11.h').write_bytes(package_data('consumer/vendor/pkcs11.h').read_bytes())
    binary.parent.mkdir(exist_ok=True)
    build = subprocess.run(['cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-pedantic',
                            str(sources / 'smoke.c'), str(sources / 'p256.c'), '-ldl', '-o', str(binary)],
                           capture_output=True, text=True, timeout=120)
    assert build.returncode == 0, build.stderr
    return binary


@needs_docker
@pytest.mark.parametrize('channel,image', list(IMAGES.items()))
def test_host_shim_smoke_installed_client(channel, image, tmp_path):
    from p11lab.native import install_native_client_bundle
    from p11lab.run import run_application
    root = evidence_root(tmp_path, 'host-' + channel)
    caller = caller_dir(root)
    binary = host_smoke_binary(root)
    prefix = root / 'client prefix'
    installed = install_native_client_bundle(client_ref(channel), prefix, environment='softhsm2', channel=channel)
    try:
        spec = RunSpec('softhsm2', channel, 'proxy', daemon_ref(channel), 'host', None,
                       client_ref(channel),
                       (str(binary), '--module', str(prefix / 'payload/lib/libpkcs11_proxy_ng_shim.so'),
                        '--token-label', 'P11Lab', '--pin-file', str(caller / 'pin'),
                        '--output', str(root / 'run/crypto'), '--key-mode', 'generated'),
                       {'P11LAB_PIN_FILE': str(caller / 'pin'), 'P11LAB_SO_PIN_FILE': str(caller / 'so-pin'),
                        'P11LAB_LABEL': 'P11Lab'},
                       root / 'run', caller, 300, prefix)
        result = run_application(spec)
        assert result.exit_code == 0, result
        verify_crypto(spec.output_dir / 'crypto')
        record = assert_clean(result.receipt_path)
        assert record['proxy']['endpoint'].startswith('https://127.0.0.1:')
        assert record['proxy']['installation']['temporary'] is False
        assert record['proxy']['installation']['receipt_sha256'] == installed.receipt_sha256
    finally:
        (caller / 'pin').unlink(missing_ok=True)
        (caller / 'so-pin').unlink(missing_ok=True)


@needs_docker
@pytest.mark.parametrize('channel,image', list(IMAGES.items())[:1])
def test_host_shim_smoke_temporary_client(channel, image, tmp_path):
    from p11lab.run import run_application
    root = evidence_root(tmp_path, 'host-temp-' + channel)
    caller = caller_dir(root)
    binary = host_smoke_binary(root)
    script = ('exec "$0" --module "$P11LAB_SHIM" --token-label P11Lab --pin-file "$1" '
              '--output "$P11LAB_OUTPUT_DIR/crypto" --key-mode generated')
    try:
        spec = RunSpec('softhsm2', channel, 'proxy', daemon_ref(channel), 'host', None,
                       client_ref(channel), ('sh', '-c', script, str(binary), str(caller / 'pin')),
                       {'P11LAB_PIN_FILE': str(caller / 'pin'), 'P11LAB_SO_PIN_FILE': str(caller / 'so-pin'),
                        'P11LAB_LABEL': 'P11Lab'},
                       root / 'run', caller, 300)
        result = run_application(spec)
        assert result.exit_code == 0, result
        verify_crypto(spec.output_dir / 'crypto')
        record = assert_clean(result.receipt_path)
        assert record['proxy']['installation']['temporary'] is True
    finally:
        (caller / 'pin').unlink(missing_ok=True)
        (caller / 'so-pin').unlink(missing_ok=True)


class ManualDaemon:
    """Direct Docker orchestration for negative lanes; proves artifact behavior.

    Each case gets a fresh network, token state, TLS set and daemon. Readiness
    setup has its own counter; attempts counts calls after authorized setup,
    so exactly one negative/consumer attempt proves the no-replay property.
    """

    def __init__(self, root, channel, tag):
        from uuid import uuid4
        self.root = root
        self.image = IMAGES[channel]
        self.tag = tag
        self.nonce = uuid4().hex[:12]
        self.owned = []
        self.attempts = 0
        self.setup_attempts = 0


    def __enter__(self):
        return self

    def __exit__(self, *exc):
        if exc[0] is not None and getattr(self, 'daemon', None) is not None:
            logs = docker('logs', self.daemon, check=False)
            (self.root / ('manual-' + self.tag) / 'daemon.failure.log').write_text(
                logs.stdout[-65536:] + '\n--- stderr ---\n' + logs.stderr[-65536:])
        for kind, identity in reversed(self.owned):
            if kind == 'container':
                docker('container', 'rm', '--force', identity, check=False)
            elif kind == 'volume':
                docker('volume', 'rm', identity, check=False)
            elif kind == 'network':
                docker('network', 'rm', identity, check=False)
        for kind, identity in self.owned:
            assert docker(kind, 'inspect', identity, check=False).returncode != 0, (kind, identity)

    def start(self, tls_dir):
        from p11lab import tls as tls_module
        from p11lab.run import render_proxy_toml
        work = self.root / ('manual-' + self.tag)
        work.mkdir(parents=True, exist_ok=True)
        material = tls_module.create_test_tls(work / tls_dir, ('provider-daemon',))
        (work / 'proxy.toml').write_text(render_proxy_toml(module_path='/usr/local/lib/p11lab/libsofthsm2.so'))
        (work / 'proxy.toml').chmod(0o644)  # daemon refuses group/world-writable config
        (work / 'env').write_text('P11LAB_PIN=1234\nP11LAB_SO_PIN=12345678\nP11LAB_LABEL=P11Lab\nRUST_LOG=info,rustls=debug,tonic=debug\n')
        (work / 'state').mkdir(mode=0o700, exist_ok=True)
        network, volume = 't6neg-' + self.nonce, 't6neg-' + self.nonce
        docker('network', 'create', '--driver', 'bridge', '--label', 'org.p11lab.negative=' + self.nonce, network)
        self.owned.append(('network', network))
        docker('volume', 'create', '--name', volume, '--driver', 'local', '--opt', 'type=none',
               '--opt', 'o=bind', '--opt', 'device=' + str(work / 'state'),
               '--label', 'org.p11lab.negative=' + self.nonce)
        self.owned.append(('volume', volume))
        base = ['--user', f'{os.getuid()}:{os.getgid()}', '--read-only', '--cap-drop', 'ALL',
                '--security-opt', 'no-new-privileges',
                '--tmpfs', f'/run/p11lab:rw,nosuid,nodev,uid={os.getuid()},gid={os.getgid()},mode=0700',
                '--tmpfs', '/tmp:rw,nosuid,nodev',
                '--mount', f'type=volume,src={volume},dst=/var/lib/p11lab,volume-nocopy',
                '--env-file', str(work / 'env')]
        init = docker('create', '--name', network + '-init', '--label', 'org.p11lab.negative=' + self.nonce,
                      *base, '--network', 'none', self.image, 'init').stdout.strip()
        self.owned.append(('container', init))
        assert docker('start', '--attach', init, check=False).returncode == 0
        daemon = docker('create', '--name', network + '-daemon', '--label', 'org.p11lab.negative=' + self.nonce,
                        *base, '--network', network, '--network-alias', 'provider-daemon',
                        '--mount', f'type=bind,src={material["ca_cert"]},dst=/run/p11lab-tls/ca.crt,readonly',
                        '--mount', f'type=bind,src={material["server_cert"]},dst=/run/p11lab-tls/server.crt,readonly',
                        '--mount', f'type=bind,src={material["server_key"]},dst=/run/p11lab-tls/server.key,readonly',
                        '--mount', f'type=bind,src={work / "proxy.toml"},dst=/etc/p11lab/proxy.toml,readonly',
                        self.image, 'daemon', '/etc/p11lab/proxy.toml').stdout.strip()
        self.owned.append(('container', daemon))
        docker('start', daemon)
        self.network, self.material, self.daemon = network, material, daemon
        import time
        deadline = time.monotonic() + 30
        authorized = None
        while time.monotonic() < deadline:
            authorized = self.health_once(material, setup=True)
            if authorized.returncode == 0 and 'SERVING' in authorized.stdout:
                break
            time.sleep(.25)
        assert authorized is not None and authorized.returncode == 0 and 'SERVING' in authorized.stdout, (
            'authorized readiness failed', authorized.stderr if authorized else '')
        self.authorized_health = {'setup_attempts': self.setup_attempts, 'returncode': authorized.returncode,
                                  'stdout': authorized.stdout.strip()}
        (work / 'authorized-health.json').write_text(json.dumps(self.authorized_health, indent=2))
        return self

    def _client_mounts(self, material):
        return ['--mount', f'type=bind,src={material["ca_cert"]},dst=/run/p11lab-client-tls/ca.crt,readonly',
                '--mount', f'type=bind,src={material["client_cert"]},dst=/run/p11lab-client-tls/client.crt,readonly',
                '--mount', f'type=bind,src={material["client_key"]},dst=/run/p11lab-client-tls/client.key,readonly']

    def health_once(self, material, *, setup=False):
        before = docker('logs', self.daemon, check=False)
        name = self.network + f'-health-setup-{self.setup_attempts}' if setup else self.network + f'-health-{self.attempts}'
        cid = docker('create', '--name', name, '--label', 'org.p11lab.negative=' + self.nonce,
                     '--user', f'{os.getuid()}:{os.getgid()}', '--network', self.network, '--read-only',
                     '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                     '--tmpfs', '/tmp:rw,nosuid,nodev', *self._client_mounts(material),
                     self.image, 'cli', '--verbose', '--endpoint', 'https://provider-daemon:7512',
                     '--tls-ca-cert', '/run/p11lab-client-tls/ca.crt',
                     '--tls-client-cert', '/run/p11lab-client-tls/client.crt',
                     '--tls-client-key', '/run/p11lab-client-tls/client.key', 'health').stdout.strip()
        self.owned.append(('container', cid))
        if setup:
            self.setup_attempts += 1
        else:
            self.attempts += 1
        result = docker('start', '--attach', cid, check=False)
        after = docker('logs', self.daemon, check=False)
        assert after.stdout.startswith(before.stdout) and after.stderr.startswith(before.stderr)
        self.last_tls_diagnosis = after.stdout[len(before.stdout):] + after.stderr[len(before.stderr):]
        return result

    def smoke_once(self, host_shim, outdir, pinfile):
        outdir.mkdir(parents=True, exist_ok=True)
        cid = docker('create', '--name', self.network + f'-app-{self.attempts}',
                     '--label', 'org.p11lab.negative=' + self.nonce, '--entrypoint', 'p11lab-smoke',
                     '--user', f'{os.getuid()}:{os.getgid()}', '--network', self.network, '--read-only',
                     '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                     '--tmpfs', '/tmp:rw,nosuid,nodev',
                     '--mount', f'type=bind,src={outdir},dst=/p11lab-output',
                     '--mount', f'type=bind,src={pinfile},dst=/pin,readonly',
                     '--mount', f'type=bind,src={host_shim},dst=/run/p11lab-client/libpkcs11_proxy_ng_shim.so,readonly',
                     *self._client_mounts(self.material),
                     '--env', 'PKCS11_PROXY_ENDPOINT=https://provider-daemon:7512',
                     '--env', 'PKCS11_PROXY_TLS_CA_CERT=/run/p11lab-client-tls/ca.crt',
                     '--env', 'PKCS11_PROXY_TLS_CLIENT_CERT=/run/p11lab-client-tls/client.crt',
                     '--env', 'PKCS11_PROXY_TLS_CLIENT_KEY=/run/p11lab-client-tls/client.key',
                     CALLER, '--module', '/run/p11lab-client/libpkcs11_proxy_ng_shim.so',
                     '--token-label', 'P11Lab', '--pin-file', '/pin',
                     '--output', '/p11lab-output/crypto', '--key-mode', 'generated').stdout.strip()
        self.owned.append(('container', cid))
        self.attempts += 1
        return docker('start', '--attach', cid, check=False)


@needs_docker
@pytest.mark.parametrize('channel,image', list(IMAGES.items()))
def test_unauthorized_client_and_wrong_ca_refused(channel, image, tmp_path):
    from p11lab import tls as tls_module
    root = evidence_root(tmp_path, 'negatives-' + channel)
    outcomes = {}
    with ManualDaemon(root, channel, 'unauthorized') as lane:
        lane.start('tls-a')
        foreign = tls_module.create_test_tls(root / 'manual-unauthorized' / 'tls-b', ('provider-daemon',))
        assert tls_module.cert_sha256(Path(foreign['ca_cert'])) != tls_module.cert_sha256(Path(lane.material['ca_cert']))
        # Unauthorized client: foreign leaf against the daemon's own CA trust.
        attempt = lane.health_once({'ca_cert': lane.material['ca_cert'], 'client_cert': foreign['client_cert'],
                                    'client_key': foreign['client_key']})
        assert lane.attempts == 1
        assert attempt.returncode == 2 and 'SERVING' not in attempt.stdout, (attempt.returncode, attempt.stderr)
        assert_authentication_rejection(attempt, lane.last_tls_diagnosis)
        outcomes['unauthorized_client'] = {'attempts': lane.attempts, 'returncode': attempt.returncode,
                                           'stderr': attempt.stderr.strip(), 'daemon_tls_diagnosis': lane.last_tls_diagnosis,
                                           'authorized_health': lane.authorized_health}
    with ManualDaemon(root, channel, 'wrong-ca') as lane:
        lane.start('tls-a')
        foreign = tls_module.create_test_tls(root / 'manual-wrong-ca' / 'tls-b', ('provider-daemon',))
        # Wrong CA: consumer trusts a CA that did not sign the server leaf.
        attempt = lane.health_once({'ca_cert': foreign['ca_cert'], 'client_cert': lane.material['client_cert'],
                                    'client_key': lane.material['client_key']})
        assert lane.attempts == 1
        assert attempt.returncode == 2 and 'SERVING' not in attempt.stdout, (attempt.returncode, attempt.stderr)
        assert_authentication_rejection(attempt, lane.last_tls_diagnosis)
        outcomes['wrong_ca'] = {'attempts': lane.attempts, 'returncode': attempt.returncode,
                                'stderr': attempt.stderr.strip(), 'daemon_tls_diagnosis': lane.last_tls_diagnosis,
                                'authorized_health': lane.authorized_health}
    (root / 'outcomes.json').write_text(json.dumps(outcomes, indent=2))


def assert_authentication_rejection(attempt, daemon_diagnosis):
    text = (attempt.stdout + '\n' + attempt.stderr + '\n' + daemon_diagnosis).lower()
    assert not any(error in text for error in ('connection refused', 'connection reset', 'timed out', 'dns error')), text
    assert any(error in text for error in ('fatal alert', 'invalid peer certificate', 'unknownissuer',
                                          'unknown ca', 'certificate verify failed')), text


@needs_docker
@pytest.mark.parametrize('channel,image', list(IMAGES.items())[:1])
def test_daemon_loss_fails_without_replay(channel, image, tmp_path):
    import time
    root = evidence_root(tmp_path, 'daemon-loss-' + channel)
    caller = caller_dir(root)
    from p11lab.native import install_native_client_bundle
    prefix = root / 'client prefix'
    install_native_client_bundle(client_ref(channel), prefix, environment='softhsm2', channel=channel)
    shim = str(prefix / 'payload/lib/libpkcs11_proxy_ng_shim.so')
    try:
        with ManualDaemon(root, channel, 'loss') as lane:
            lane.start('tls')
            up = lane.health_once(lane.material)
            deadline = time.monotonic() + 30
            while up.returncode != 0 and time.monotonic() < deadline:
                time.sleep(1)
                up = lane.health_once(lane.material)
            assert up.returncode == 0, up.stderr
            served = lane.attempts
            docker('kill', lane.daemon)
            failed = lane.smoke_once(shim, root / 'output', caller / 'pin')
            assert lane.attempts == served + 1
            assert failed.returncode != 0, failed.stdout
            assert 'C_Initialize' in failed.stdout + failed.stderr
            (root / 'outcome.json').write_text(json.dumps(
                {'health_attempts_until_serving': served, 'operation_attempts_after_loss': 1,
                 'operation_returncode': failed.returncode,
                 'operation_output': (failed.stdout + failed.stderr).strip()[:500]}, indent=2))
    finally:
        (caller / 'pin').unlink(missing_ok=True)
        (caller / 'so-pin').unlink(missing_ok=True)


@needs_docker
@pytest.mark.parametrize('channel,image', list(IMAGES.items())[:1])
def test_neighbor_resources_survive_proxy(channel, image, tmp_path):
    from uuid import uuid4
    from p11lab.run import run_application
    root = evidence_root(tmp_path, 'neighbor-' + channel)
    caller = caller_dir(root)
    name = 'p11lab-neighbor-' + uuid4().hex
    volume = docker('volume', 'create', '--label', 'org.p11lab.run=another-owner', name).stdout.strip()
    neighbor = docker('create', '--name', name, '--label', 'org.p11lab.run=another-owner',
                      '--entrypoint', 'sleep', IMAGES[channel], '30').stdout.strip()
    try:
        spec = RunSpec('softhsm2', channel, 'proxy', daemon_ref(channel), 'container', caller_ref(),
                       client_ref(channel), ('true',),
                       {'P11LAB_PIN_FILE': str(caller / 'pin'), 'P11LAB_SO_PIN_FILE': str(caller / 'so-pin'),
                        'P11LAB_LABEL': 'P11Lab'},
                       root / 'run', caller, 300)
        result = run_application(spec)
        assert result.exit_code == 0, result
        assert_clean(result.receipt_path)
        assert json.loads(docker('container', 'inspect', neighbor).stdout)[0]['Id'] == neighbor
        assert json.loads(docker('volume', 'inspect', volume).stdout)[0]['Name'] == volume
    finally:
        docker('container', 'rm', '--force', neighbor, check=False)
        docker('volume', 'rm', volume, check=False)
        (caller / 'pin').unlink(missing_ok=True)
        (caller / 'so-pin').unlink(missing_ok=True)


@needs_docker
@pytest.mark.parametrize('channel,image', list(IMAGES.items())[:1])
def test_proxy_state_isolation(channel, image, tmp_path):
    from p11lab.run import run_application
    root = evidence_root(tmp_path, 'isolation-' + channel)
    caller = caller_dir(root)
    try:
        volumes = []
        for index in range(2):
            spec = RunSpec('softhsm2', channel, 'proxy', daemon_ref(channel), 'container', caller_ref(),
                           client_ref(channel), ('true',),
                           {'P11LAB_PIN_FILE': str(caller / 'pin'), 'P11LAB_SO_PIN_FILE': str(caller / 'so-pin'),
                            'P11LAB_LABEL': 'P11Lab'},
                           root / ('run-' + str(index)), caller, 300)
            result = run_application(spec)
            assert result.exit_code == 0, result
            record = assert_clean(result.receipt_path)
            volumes.extend(item['identity'] for item in record['owned_resources'] if item['kind'] == 'volume')
        assert len(volumes) == len(set(volumes)) == 2
        (root / 'volumes.json').write_text(json.dumps(volumes, indent=2))
    finally:
        (caller / 'pin').unlink(missing_ok=True)
        (caller / 'so-pin').unlink(missing_ok=True)


@needs_docker
@pytest.mark.parametrize('channel,image', list(IMAGES.items())[:1])
def test_mtls_negative_cannot_accept_dead_daemon(channel, image, tmp_path, monkeypatch):
    original = ManualDaemon.start
    def start_then_die(lane, tls_dir):
        result = original(lane, tls_dir)
        docker('kill', lane.daemon)
        return result
    monkeypatch.setattr(ManualDaemon, 'start', start_then_die)
    with pytest.raises(AssertionError):
        test_unauthorized_client_and_wrong_ca_refused(channel, image, tmp_path)
