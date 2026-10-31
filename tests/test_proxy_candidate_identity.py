"""Selected proxy-build identity: record, threading, and rejection matrix.

Covers plan checkboxes M07.2-3 (ProxyBuildIdentityV1 + threading): the
immutable candidate identity record, validator sameness checks, native-client
build/install/manifest/preflight threading, daemon-side checks with
launch-byte rehashes, and the CLI manifest surface. Hermetic only: no Docker,
no network, no live builds. A/B/C fixture bytes are authored in this file;
hash oracles use hashlib directly, never the code under test.
"""
import copy
import hashlib
import json
import struct
from pathlib import Path

import pytest

from p11lab import native as native_module
from p11lab import proxy_inputs as proxy_inputs_module
from p11lab import run as run_module
from p11lab import tls as tls_module
from p11lab.docker import CommandResult
from p11lab.models import ArtifactRef, ProxyBuildIdentityV1, RunSpec

DAEMON_PATH = 'bin/pkcs11-proxy-ng'
CLI_PATH = 'bin/pkcs11-proxy-ng-cli'
SHIM_PATH = 'lib/libpkcs11_proxy_ng_shim.so'
CLIENT_PATHS = (CLI_PATH, SHIM_PATH)
DAEMON_IMAGE = ArtifactRef('docker-local', 'sha256:' + 'a' * 64, 'a' * 64, 'linux/amd64')
CALLER_IMAGE = ArtifactRef('docker-local', 'sha256:' + 'b' * 64, 'b' * 64, 'linux/amd64')
CLIENT_BUNDLE = ArtifactRef('bundle', '/tmp/client.tar.gz', 'c' * 64, 'linux/amd64')


def stub_elf(*, elf_type, tag):
    """Minimal parseable ELF64: headers plus one PT_LOAD; no dynamic section.

    Independent byte builder (struct only): the producer ELF parser must read
    empty ABI maps from these stubs. Payload bytes after the program headers
    only differentiate fixture hashes.
    """
    payload = tag + b'\0' * (64 - len(tag))
    assert len(payload) == 64
    header = (b'\x7fELF' + bytes([2, 1, 1, 0]) + b'\0' * 8
              + struct.pack('<HHIQQQIHHHHHH', elf_type, 62, 1, 0, 64, 0, 0, 64, 56, 1, 0, 0, 0))
    total = 64 + 56 + len(payload)
    program = struct.pack('<IIQQQQQQ', 1, 5, 0, 0x400000, 0x400000, total, total, 0x1000)
    return header + program + payload


def empty_client_abi():
    """Literal ABI observation shape for stubs without dynamic sections."""
    return {'decision': 'conforming-recorded', 'runtime_qualification': 'not-performed',
            'floors': {CLI_PATH: {}, SHIM_PATH: {}},
            'needed': {CLI_PATH: [], SHIM_PATH: []},
            'interpreters': {CLI_PATH: None, SHIM_PATH: None}, 'shim_exports': [],
            'version_requirements': {CLI_PATH: [], SHIM_PATH: []},
            'symbol_versions': {CLI_PATH: [], SHIM_PATH: []}}


def full_empty_abi():
    """Literal full-record ABI with empty maps on all three product paths."""
    abi = empty_client_abi()
    abi['floors'][DAEMON_PATH] = {}
    abi['needed'][DAEMON_PATH] = []
    abi['interpreters'][DAEMON_PATH] = None
    abi['version_requirements'][DAEMON_PATH] = []
    abi['symbol_versions'][DAEMON_PATH] = []
    return abi


def default_record():
    """Fresh pinned-default record dict (absolute default, never wildcard)."""
    return tls_module.DEFAULT_PROXY_BUILD_IDENTITY().to_dict()


def fixture_record(shim_bytes, cli_bytes, *, tag, origin='installed-default',
                   caller_run='fixture-run', caller_job='fixture-job'):
    """Authored B/C-style record: same toolchain/config, distinct source/products."""
    base = default_record()
    base.update({
        'origin': origin,
        'source_commit': (tag[0] * 40) if origin == 'installed-default' else None,
        'source_tree': tag[1] * 40,
        'source_archive': ({'sha256': tag[2] * 64, 'size': 4321,
                            'prefix': 'pkcs11-proxy-ng-fixture-' + tag[0]}
                           if origin == 'installed-default' else None),
        'source_members': {'count': 7, 'canonical_roster_sha256': tag[3] * 64},
        'content_seal': None,
        'cargo_lock_sha256': tag[4] * 64,
        'vendor_packages': [{'identity': 'fixture-a-1.0.0', 'sha256': tag[5] * 64},
                            {'identity': 'fixture-b-2.3.4', 'sha256': tag[6] * 64}],
        'daemon': {'path': DAEMON_PATH, 'size': 4242, 'mode': 0o755, 'sha256': tag[7] * 64},
        'cli': {'path': CLI_PATH, 'size': len(cli_bytes), 'mode': 0o755,
                'sha256': hashlib.sha256(cli_bytes).hexdigest()},
        'shim': {'path': SHIM_PATH, 'size': len(shim_bytes), 'mode': 0o755,
                 'sha256': hashlib.sha256(shim_bytes).hexdigest()},
        'abi': full_empty_abi(),
        'build_context_digest': tag[8] * 64,
        'caller': {'origin': 'local-controller', 'run_id': caller_run + '-' + tag[0],
                   'job_id': caller_job + '-' + tag[0]},
        'provider_parent': {'family': 'fixture-provider-' + tag[0], 'platform': 'linux/amd64',
                            'manifest_digest': tag[9] * 64, 'config_digest': tag[10] * 64},
    })
    return ProxyBuildIdentityV1.from_dict(base).to_dict()


def fixture_bytes(tag):
    """Distinct stub product bytes per fixture tag (daemon bytes never exist)."""
    return (stub_elf(elf_type=3, tag=b'shim-' + tag),
            stub_elf(elf_type=2, tag=b'cli-' + tag))


def daemon_claim(record):
    """Authored proxy-build stdout claim matching a record (byte-stable shape)."""
    return {'schema_version': 1, 'source_revision': record['source_commit'],
            'cargo_lock_sha256': record['cargo_lock_sha256'],
            'binaries': {'pkcs11-proxy-ng': record['daemon']['sha256'],
                         'pkcs11-proxy-ng-cli': record['cli']['sha256'],
                         'proxy-entrypoint.sh': record['entrypoint_sha256']}}


def client_abi_observed(record):
    """Client-path restriction of a record ABI (what a build observes)."""
    abi = record['abi']
    return {'decision': abi['decision'], 'runtime_qualification': abi['runtime_qualification'],
            'floors': {path: copy.deepcopy(abi['floors'][path]) for path in CLIENT_PATHS},
            'needed': {path: copy.deepcopy(abi['needed'][path]) for path in CLIENT_PATHS},
            'interpreters': {path: abi['interpreters'][path] for path in CLIENT_PATHS},
            'shim_exports': list(abi['shim_exports']),
            'version_requirements': {path: copy.deepcopy(abi['version_requirements'][path])
                                     for path in CLIENT_PATHS},
            'symbol_versions': {path: copy.deepcopy(abi['symbol_versions'][path])
                                for path in CLIENT_PATHS}}


def client_manifest(record, abi_observed=None):
    """Authored native-client manifest identity section matching a record."""
    archive = record['source_archive']
    return {'source': {'proxy': {
        'repository': 'https://github.com/mingulov/pkcs11-proxy-ng',
        'source_revision': record['source_commit'],
        'source_archive_sha256': archive['sha256'] if archive else None,
        'cargo_lock_sha256': record['cargo_lock_sha256'],
        'shim_sha256': record['shim']['sha256'], 'cli_sha256': record['cli']['sha256'],
        'identity': copy.deepcopy(record),
        'abi_observed': (copy.deepcopy(abi_observed) if abi_observed is not None
                         else client_abi_observed(record))}}}


def launch_rehashes(record):
    return {'shim_sha256': record['shim']['sha256'], 'cli_sha256': record['cli']['sha256']}


def merged_actual(record, *, daemon=None, manifest=None, rehashes=None, abi=None):
    return {'daemon_build_json': copy.deepcopy(daemon) if daemon is not None else daemon_claim(record),
            'client_manifest': copy.deepcopy(manifest) if manifest is not None else client_manifest(record),
            'launch_rehashes': dict(rehashes) if rehashes is not None else launch_rehashes(record),
            'abi_observed': copy.deepcopy(abi) if abi is not None else client_abi_observed(record)}


def test_default_record_pins_live_proof_values():
    record = default_record()
    assert record['schema'] == 'p11lab.proxy-build-identity.v1'
    assert record['schema_version'] == 1
    assert record['origin'] == 'installed-default'
    assert record['source_commit'] == 'a348a5f59b535b1ca309ea9f0a722e3bec692f72'
    assert record['source_tree'] == '436915ad13986c6770de4d190684276bb71de0c8'
    assert record['source_archive'] == {
        'sha256': '4446dfd31ada97c7249cf0044e43ae2b77fb69960c9bee265f9acb6ea77194cc',
        'size': 2124074, 'prefix': 'pkcs11-proxy-ng-a348a5f59b535b1ca309ea9f0a722e3bec692f72'}
    assert record['source_members'] == {
        'count': 689,
        'canonical_roster_sha256': 'f2965bf8a12881f8ca6433b5c42b7339aafd19fb27851e7a625904c615f8c6d2'}
    assert record['content_seal'] is None
    assert record['cargo_lock_sha256'] == '39ae3c64cff6fddd4f2d621f8e26139005936b22e6d7652b2ed14e4921fa5979'
    assert len(record['vendor_packages']) == 282
    assert record['toolchain_manifest_sha256'] == '5aba2e7de287d689e9cb9476d7f2c234268319591f53eb0adcb76af80f51e3d5'
    assert record['toolchain_image'] == {
        'engine_id': 'sha256:7d00db51b3b184c06482221b76545142d970b726a70e19fc089b923043fc2025',
        'layers': ['sha256:8d9d35d1e1ec16aea046daa8655183d1da834773d867f119abf4859d72c00d4d']}
    assert record['rust_protoc'] == {
        'rustc_version': 'rustc 1.98.1 (48a229cea 2026-09-01)',
        'cargo_version': 'cargo 1.98.1 (797e8a9bc 2026-08-05)',
        'protoc_version': 'libprotoc 36.1',
        'rust_record_sha256': 'cd0da947db9fe2044b0bf8d0817d727d3bf3678d109f42697c43ec32f03ea2e5',
        'protoc_record_sha256': '2b99d40ed3960abcdbfefafa515325e61faf63be909e3fa25657edad69ea3bce',
        'crates_record_sha256': '7e2369937225fbbffcc75355247b6a5191c03f28d4378b1d9fe4ad8bca91f1a3'}
    assert record['target'] == 'x86_64-unknown-linux-gnu'
    assert record['packages'] == ['pkcs11-proxy-ng', 'pkcs11-proxy-ng-cli', 'pkcs11-proxy-ng-shim']
    assert record['features'] == 'default'
    assert record['profile'] == {'name': 'release', 'lto': 'thin', 'codegen-units': 1,
                                 'strip': 'symbols'}
    assert record['rustflags'] == []
    assert record['cargo_args'] == ['build', '--locked', '--offline', '--release', '--target',
                                    'x86_64-unknown-linux-gnu', '-p', 'pkcs11-proxy-ng', '-p',
                                    'pkcs11-proxy-ng-cli', '-p', 'pkcs11-proxy-ng-shim']
    assert record['controller_cargo_config_sha256'] == '42be131d92724bcd8416e544381b06b3bc4b6f929d53614eaeb429e3364f40f4'
    assert record['build_script_sha256'] == '48895b01bdf1d9d4eac6f809ed20b6c489beeb58eebc9dcb16850b55613b5428'
    assert record['daemon'] == {'path': DAEMON_PATH, 'size': 13071320, 'mode': 0o755,
                                'sha256': '4a1505c910e285015704ed0f510338c73a7e371bdbb42486a73e90bb5ea78c28'}
    assert record['cli'] == {'path': CLI_PATH, 'size': 6851136, 'mode': 0o755,
                             'sha256': '07d258d1b8cfe1237f8c09f245df0940f67c741dad96025034b6955bde2e3f0c'}
    assert record['shim'] == {'path': SHIM_PATH, 'size': 6287192, 'mode': 0o755,
                              'sha256': 'cd68a5cd5bd4a83961a6958f845f01bbf417b4c47954aabf45a17fe13adfe768'}
    assert record['daemon_config_sha256'] == 'a958111d2948445495502c5d25152246511bb43004e5dd75b7e1ef1870c2adf2'
    assert record['entrypoint_sha256'] == 'c51aae8cf914d27c288e5634343601ddc74bd1a56e3a7ed14843f7706333861b'
    assert record['hook_hashes'] == []
    assert record['build_context_digest'] == '990222a42e16041423a50fcc10b7ad6a3a84afaff25d1139aac94252c74cb51f'
    assert record['caller'] == {'origin': 'local-controller', 'run_id': None, 'job_id': None}
    assert record['provider_parent'] == {'family': None, 'platform': None,
                                         'manifest_digest': None, 'config_digest': None}


def test_default_record_abi_pins_live_proof_and_parsed_rows():
    abi = default_record()['abi']
    assert abi['decision'] == 'conforming-recorded'
    assert abi['runtime_qualification'] == 'not-performed'
    needed = ['libgcc_s.so.1', 'libm.so.6', 'libc.so.6', 'ld-linux-x86-64.so.2']
    floors = {'ld-linux-x86-64.so.2': {'GLIBC': '2.3'}, 'libc.so.6': {'GLIBC': '2.34'},
              'libgcc_s.so.1': {'GCC': '4.2.0'}, 'libm.so.6': {'GLIBC': '2.29'}}
    assert abi['needed'] == {DAEMON_PATH: needed, CLI_PATH: needed, SHIM_PATH: needed}
    assert abi['floors'] == {DAEMON_PATH: floors, CLI_PATH: floors, SHIM_PATH: floors}
    assert abi['interpreters'] == {DAEMON_PATH: '/lib64/ld-linux-x86-64.so.2',
                                   CLI_PATH: '/lib64/ld-linux-x86-64.so.2', SHIM_PATH: None}
    assert abi['shim_exports'] == ['C_GetFunctionList', 'C_GetInterface', 'C_GetInterfaceList']
    assert [len(abi['version_requirements'][path]) for path in (DAEMON_PATH, CLI_PATH, SHIM_PATH)] == [22, 21, 21]
    assert [len(abi['symbol_versions'][path]) for path in (DAEMON_PATH, CLI_PATH, SHIM_PATH)] == [115, 106, 97]
    assert all(set(row) == {'file', 'name'} for rows in abi['version_requirements'].values() for row in rows)
    assert all(set(row) == {'symbol', 'file', 'version'} for rows in abi['symbol_versions'].values()
               for row in rows)


def test_none_path_resolves_to_absolute_default():
    record = default_record()
    validated = proxy_inputs_module.validate_proxy_identity(merged_actual(record), None)
    assert validated['expected'] == record
    validated = proxy_inputs_module.validate_proxy_identity(merged_actual(record), record)
    assert validated['expected'] == record


def test_default_record_constructor_returns_fresh_instances():
    # Fix-1 Y-2 rewrite (reason: the identity record is now recursively
    # immutable, so the old in-place mutation no longer type-checks as a
    # freshness probe; freshness is now structural — mutation is refused and
    # every constructor call yields an independent pristine record).
    first = tls_module.DEFAULT_PROXY_BUILD_IDENTITY()
    with pytest.raises((TypeError, AttributeError)):
        first.abi['decision'] = 'mutated'
    assert tls_module.DEFAULT_PROXY_BUILD_IDENTITY().to_dict() == first.to_dict()
    assert first.to_dict() == default_record()


def test_identity_record_fields_reject_in_place_mutation():
    # Fix-1 Y-2: recursive immutability — every nested container refuses
    # item assignment, and attribute reassignment stays frozen.
    from types import MappingProxyType
    record = tls_module.DEFAULT_PROXY_BUILD_IDENTITY()
    before = record.to_dict()
    with pytest.raises(AttributeError):
        record.source_commit = '0' * 40

    def assert_frozen(value):
        if isinstance(value, MappingProxyType):
            with pytest.raises(TypeError):
                value['__probe__'] = 1
            for sub in value.values():
                assert_frozen(sub)
        elif isinstance(value, tuple):
            with pytest.raises(TypeError):
                value[0:0] = ()
            with pytest.raises(AttributeError):
                value.append(None)
            for sub in value:
                assert_frozen(sub)
        elif isinstance(value, (str, int, type(None))):
            pass
        else:
            raise AssertionError('mutable record storage: %r' % type(value))

    for name in before:
        assert_frozen(getattr(record, name))
    # Named probes for the exact Y-2 mutation sites.
    with pytest.raises(TypeError):
        record.shim['sha256'] = '0' * 64
    with pytest.raises(TypeError):
        record.provider_parent['family'] = 'evil'
    with pytest.raises(AttributeError):
        record.hook_hashes.append('evil')
    assert record.to_dict() == before


def test_identity_record_exports_and_inputs_stay_isolated():
    # Fix-1 Y-2: to_dict yields independent plain containers; from_dict
    # callers cannot alias the record through the input mapping.
    record = tls_module.DEFAULT_PROXY_BUILD_IDENTITY()
    before = record.to_dict()
    exported = record.to_dict()
    assert type(exported['shim']) is dict and type(exported['hook_hashes']) is list
    exported['shim']['sha256'] = '0' * 64
    exported['hook_hashes'].append('evil')
    exported['abi']['needed'][CLI_PATH].append('libevil.so.1')
    assert record.to_dict() == before
    raw = default_record()
    built = ProxyBuildIdentityV1.from_dict(raw)
    raw['shim']['sha256'] = '0' * 64
    raw['abi']['decision'] = 'mutated'
    assert built.to_dict() == before


def test_shared_record_is_safe_across_runspec_and_gates(tmp_path):
    # Fix-1 Y-2: one instance shared through RunSpec, the native resolver,
    # and the validator/check gates cannot be corrupted after validation.
    from p11lab.models import ProxyBuildIdentityV1
    record_b, _, _, _, _, _ = selected_pair()
    shared = ProxyBuildIdentityV1.from_dict(record_b)
    spec = RunSpec('softhsm2', 'release', 'proxy', DAEMON_IMAGE, 'container',
                   CALLER_IMAGE, CLIENT_BUNDLE, ('app',), {}, tmp_path / 'out',
                   tmp_path, 60, expected_proxy_identity=shared)
    with pytest.raises(TypeError):
        spec.expected_proxy_identity.shim['sha256'] = '0' * 64
    with pytest.raises(TypeError):
        shared.provider_parent['family'] = 'evil'
    with pytest.raises(AttributeError):
        shared.hook_hashes.append('evil')
    assert spec.expected_proxy_identity.to_dict() == record_b
    assert native_module._selected_proxy_identity(shared).to_dict() == record_b
    assert proxy_inputs_module.validate_proxy_identity(
        merged_actual(record_b), record_b)['expected'] == record_b
    assert run_module.check_proxy_identities(
        daemon_claim(record_b), client_manifest(record_b), expected=shared,
        launch_rehashes=launch_rehashes(record_b),
        daemon_image=image_naming()) == daemon_claim(record_b)


B_TAG = 'b0123456789'
C_TAG = 'c9876543210'


def selected_pair():
    """Authored B/C fixture records with distinct bytes, hashes, and parents."""
    shim_b, cli_b = fixture_bytes(b'B')
    shim_c, cli_c = fixture_bytes(b'C')
    assert (shim_b, cli_b) != (shim_c, cli_c)
    record_b = fixture_record(shim_b, cli_b, tag=B_TAG)
    record_c = fixture_record(shim_c, cli_c, tag=C_TAG)
    assert record_b != record_c
    return record_b, record_c, shim_b, cli_b, shim_c, cli_c


def test_explicit_a_passes_with_recorded_receipt_shape():
    record = default_record()
    actual = merged_actual(record)
    validated = proxy_inputs_module.validate_proxy_identity(actual, record)
    assert validated['expected'] == record
    assert validated['daemon'] == daemon_claim(record)
    assert validated['client_identity'] == record
    assert validated['launch_rehashes'] == launch_rehashes(record)
    assert validated['abi_decision'] == 'conforming-recorded'
    assert run_module.check_proxy_identities(
        daemon_claim(record), client_manifest(record), expected=record,
        launch_rehashes=launch_rehashes(record), daemon_image=image_naming()) == daemon_claim(record)


def test_validator_daemon_evidence_is_isolated_from_actual():
    record = default_record()
    actual = merged_actual(record)
    validated = proxy_inputs_module.validate_proxy_identity(actual, record)
    assert validated['daemon'] == daemon_claim(record)
    actual['daemon_build_json']['binaries']['pkcs11-proxy-ng'] = '0' * 64
    assert validated['daemon'] == daemon_claim(record)
    validated['daemon']['binaries']['pkcs11-proxy-ng-cli'] = '1' * 64
    assert actual['daemon_build_json']['binaries']['pkcs11-proxy-ng-cli'] == \
        record['cli']['sha256']


def test_explicit_b_passes_validator_and_check():
    record_b, _, _, _, _, _ = selected_pair()
    assert proxy_inputs_module.validate_proxy_identity(
        merged_actual(record_b), record_b)['expected'] == record_b
    assert run_module.check_proxy_identities(
        daemon_claim(record_b), client_manifest(record_b), expected=record_b,
        launch_rehashes=launch_rehashes(record_b),
        daemon_image=image_naming()) == daemon_claim(record_b)


def test_build_manifest_preflight_thread_expected_b(tmp_path):
    from p11lab.models import ProxyBuildIdentityV1
    record_b, _, shim_b, cli_b, _, _ = selected_pair()
    expected = ProxyBuildIdentityV1.from_dict(record_b)
    (tmp_path / 'shim.so').write_bytes(shim_b)
    (tmp_path / 'cli').write_bytes(cli_b)
    (tmp_path / 'license').write_bytes(b'fixture-license')
    proxy = {'source_revision': record_b['source_commit'],
             'cargo_lock_sha256': record_b['cargo_lock_sha256'],
             'source_archive_sha256': record_b['source_archive']['sha256'],
             'shim_sha256': record_b['shim']['sha256'], 'cli_sha256': record_b['cli']['sha256']}
    native_module.build_native_client_bundle(
        proxy=proxy, shim=tmp_path / 'shim.so', cli=tmp_path / 'cli',
        licenses={f'share/licenses/proxy-ng/{name}': tmp_path / 'license'
                  for name in ('LICENSE-APACHE', 'LICENSE-MIT')},
        output_dir=tmp_path / 'build', environment='softhsm2', channel='release',
        expected_proxy_identity=expected)
    manifest = json.loads((tmp_path / 'build' / 'manifest.json').read_bytes())
    assert manifest['source']['proxy']['identity'] == record_b
    assert manifest['source']['proxy']['abi_observed'] == empty_client_abi()
    native_module._validate_client_manifest(manifest, 'softhsm2', 'release',
                                                expected_proxy_identity=expected)


def test_preflight_rehashes_launch_bytes_and_catches_tamper(tmp_path, monkeypatch):
    from p11lab.models import ProxyBuildIdentityV1
    record_b, _, shim_b, cli_b, _, _ = selected_pair()
    expected = ProxyBuildIdentityV1.from_dict(record_b)
    prefix = tmp_path / 'prefix'
    (prefix / 'payload' / 'lib').mkdir(parents=True)
    (prefix / 'payload' / 'bin').mkdir(parents=True)
    (prefix / 'payload' / SHIM_PATH).write_bytes(shim_b)
    (prefix / 'payload' / CLI_PATH).write_bytes(cli_b)
    manifest = client_manifest(record_b) | {
        'environment': 'softhsm2', 'channel': 'release', 'role': 'native-client',
        'target': native_module.CLIENT_TARGET, 'module': native_module.CLIENT_MODULE,
        'host_requirements': native_module.CLIENT_HOST_REQUIREMENTS,
        'files': [{'path': SHIM_PATH, 'sha256': record_b['shim']['sha256']},
                  {'path': CLI_PATH, 'sha256': record_b['cli']['sha256']}]}

    class Completed:
        def __init__(self, stdout=''):
            self.returncode = 0
            self.stdout = stdout
            self.stderr = ''

    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv[0])
        return Completed('fixture 0.0' if argv[-1] == '--version' else '')

    monkeypatch.setattr(native_module.subprocess, 'run', fake_run)
    monkeypatch.setattr(native_module.platform, 'system', lambda: 'Linux')
    monkeypatch.setattr(native_module.platform, 'machine', lambda: 'x86_64')
    observed = native_module.preflight_native_client(prefix, manifest, expected_proxy_identity=expected)
    assert observed['rehashes']['before'] == observed['rehashes']['after'] == launch_rehashes(record_b)

    def tampering_run(argv, **kwargs):
        if argv[-1] == '--version':
            (prefix / 'payload' / SHIM_PATH).write_bytes(shim_b + b'x')
        return fake_run(argv, **kwargs)

    monkeypatch.setattr(native_module.subprocess, 'run', tampering_run)
    with pytest.raises(ValueError, match='changed during preflight'):
        native_module.preflight_native_client(prefix, manifest, expected_proxy_identity=expected)


@pytest.mark.parametrize('which', ['shim', 'cli'])
def test_preflight_rejects_tampered_bytes_before_any_execution(tmp_path, monkeypatch, which):
    # Fix-1 Y-1: bytes tampered before the first hash are compared against
    # the selected identity before the loader/CLI execute — no subprocess
    # may start on unselected bytes.
    from p11lab.models import ProxyBuildIdentityV1
    record_b, _, shim_b, cli_b, _, _ = selected_pair()
    expected = ProxyBuildIdentityV1.from_dict(record_b)
    prefix = tmp_path / 'prefix'
    (prefix / 'payload' / 'lib').mkdir(parents=True)
    (prefix / 'payload' / 'bin').mkdir(parents=True)
    tampered = b'tampered-executable-bytes'
    assert hashlib.sha256(tampered).hexdigest() not in (
        record_b['shim']['sha256'], record_b['cli']['sha256'])
    (prefix / 'payload' / SHIM_PATH).write_bytes(tampered if which == 'shim' else shim_b)
    (prefix / 'payload' / CLI_PATH).write_bytes(tampered if which == 'cli' else cli_b)
    manifest = client_manifest(record_b) | {
        'environment': 'softhsm2', 'channel': 'release', 'role': 'native-client',
        'target': native_module.CLIENT_TARGET, 'module': native_module.CLIENT_MODULE,
        'host_requirements': native_module.CLIENT_HOST_REQUIREMENTS,
        'files': [{'path': SHIM_PATH, 'sha256': record_b['shim']['sha256']},
                  {'path': CLI_PATH, 'sha256': record_b['cli']['sha256']}]}

    class Completed:
        def __init__(self, stdout=''):
            self.returncode = 0
            self.stdout = stdout
            self.stderr = ''

    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv[0])
        return Completed('fixture 0.0' if argv[-1] == '--version' else '')

    monkeypatch.setattr(native_module.subprocess, 'run', fake_run)
    monkeypatch.setattr(native_module.platform, 'system', lambda: 'Linux')
    monkeypatch.setattr(native_module.platform, 'machine', lambda: 'x86_64')
    with pytest.raises(ValueError, match='proxy identity mismatch'):
        native_module.preflight_native_client(prefix, manifest, expected_proxy_identity=expected)
    assert calls == []


@pytest.mark.parametrize('swap', ['daemon', 'client'])
def test_mixed_daemon_shim_rejects_both_directions(swap):
    record_a = default_record()
    record_b, _, _, _, _, _ = selected_pair()
    if swap == 'daemon':
        actual = merged_actual(record_b, daemon=daemon_claim(record_a))
    else:
        actual = merged_actual(record_b, manifest=client_manifest(record_a),
                               abi=client_abi_observed(record_a))
    with pytest.raises(ValueError, match='proxy identity mismatch'):
        proxy_inputs_module.validate_proxy_identity(actual, record_b)
    with pytest.raises(ValueError, match='proxy identity mismatch'):
        run_module.check_proxy_identities(actual['daemon_build_json'], actual['client_manifest'],
                                          expected=record_b, launch_rehashes=actual['launch_rehashes'],
                                          daemon_image=image_naming())


class FlowEngine:
    """Minimal scripted Docker double for identity-flow tests (no Docker)."""

    def __init__(self, build_stdout, *, image_id=None, tamper=None):
        self.build_stdout = build_stdout
        self.image_id = image_id
        self.tamper = tamper
        self.created = []
        self.removed = []
        self.stopped = set()

    def image(self, artifact):
        return {'Id': self.image_id or artifact.reference, 'Os': 'linux',
                'Architecture': 'amd64', 'Descriptor': {'digest': artifact.reference}}

    def volume(self, name, *args):
        return name

    def create(self, image, argv, options, labels, name):
        identity = 'container-%d' % len(self.created)
        self.created.append({'image': image, 'argv': tuple(argv), 'options': list(options),
                             'labels': dict(labels), 'name': name, 'id': identity})
        if self.tamper is not None and tuple(argv)[:1] == ('daemon',):
            self.tamper()
        return identity

    def execute(self, identity, timeout, interrupted):
        argv = self.created[int(identity.split('-')[1])]['argv']
        if argv[:1] == ('proxy-build',):
            return CommandResult(0, self.build_stdout, '', False)
        if argv[0] == 'cli':
            return CommandResult(0, 'SERVING\n', '', False)
        return CommandResult(0, 'caller output', '', False)

    def command(self, args, timeout=15, *, check=True, **kwargs):
        if args[:2] == ['network', 'create']:
            return CommandResult(0, args[-1] + '-id\n', '', False)
        if args[0] in {'start', 'port', 'logs'}:
            return CommandResult(0, '127.0.0.1:32768\n' if args[0] == 'port' else '', '', False)
        if args[0] == 'inspect':
            return CommandResult(0, json.dumps({'Running': args[-1] not in self.stopped,
                                               'ExitCode': 0}), '')
        raise AssertionError('unexpected command: ' + ' '.join(args))

    def stop(self, identity, labels):
        self.stopped.add(identity)

    def remove(self, kind, identity, labels):
        self.removed.append((kind, identity))


class FlowInstalled:
    def __init__(self, prefix, manifest, shim_bytes, cli_bytes):
        from p11lab.native import CLIENT_MODULE
        self.artifact = CLIENT_BUNDLE
        self.prefix = prefix
        self.manifest = manifest
        self.manifest_sha256 = '1' * 64
        self.receipt_path = prefix / '.p11lab-install.json'
        self.receipt_sha256 = '2' * 64
        shim = prefix / 'payload' / CLIENT_MODULE
        shim.parent.mkdir(parents=True)
        shim.write_bytes(shim_bytes)
        cli = prefix / 'payload' / CLI_PATH
        cli.parent.mkdir(parents=True, exist_ok=True)
        cli.write_bytes(cli_bytes)


def flow_client(monkeypatch, record, shim_bytes, cli_bytes):
    manifest = client_manifest(record) | {
        'environment': 'softhsm2', 'channel': 'release', 'role': 'native-client',
        'target': native_module.CLIENT_TARGET, 'module': native_module.CLIENT_MODULE,
        'host_requirements': native_module.CLIENT_HOST_REQUIREMENTS,
        'files': [{'path': SHIM_PATH, 'sha256': record['shim']['sha256']},
                  {'path': CLI_PATH, 'sha256': record['cli']['sha256']}]}

    def install(artifact, prefix, *, environment, channel, expected_proxy_identity=None):
        assert artifact == CLIENT_BUNDLE
        native_module._validate_client_manifest(manifest, environment, channel,
                                                expected_proxy_identity=expected_proxy_identity)
        return FlowInstalled(Path(prefix), manifest, shim_bytes, cli_bytes)

    monkeypatch.setattr(native_module, 'install_native_client_bundle', install)
    monkeypatch.setattr(native_module, 'preflight_native_client',
                        lambda prefix, manifest, expected_proxy_identity=None: {
                            'loader': '/lib64/ld-linux-x86-64.so.2', 'architecture': 'x86_64',
                            'closure': {'shim': {'resolved': []}}, 'cli_version': 'test',
                            'rehashes': {'before': launch_rehashes(record),
                                         'after': launch_rehashes(record)}})


def flow_spec(tmp_path, record, *, host=False):
    from p11lab.models import ProxyBuildIdentityV1
    return RunSpec('softhsm2', 'release', 'proxy', DAEMON_IMAGE,
                   'host' if host else 'container',
                   None if host else CALLER_IMAGE, CLIENT_BUNDLE, ('app', '--flag'),
                   {'P11LAB_LABEL': 'P11Lab'}, tmp_path / 'out', tmp_path, 60, None,
                   expected_proxy_identity=ProxyBuildIdentityV1.from_dict(record))


def argv_heads(engine):
    return [entry['argv'][0] for entry in engine.created]


def image_naming(*, observed=None):
    """Daemon image naming gate input: selected reference vs observed engine Id."""
    reference = DAEMON_IMAGE.reference
    return {'selected': reference, 'observed': reference if observed is None else observed}


def test_run_flow_accepts_selected_b_and_records_receipt(monkeypatch, tmp_path):
    record_b, _, shim_b, cli_b, _, _ = selected_pair()
    engine = FlowEngine(json.dumps(daemon_claim(record_b)))
    monkeypatch.setattr(run_module, 'Docker', lambda: engine)
    monkeypatch.setattr(run_module, '_create_proxy_network', lambda *args: 'fixture-network')
    flow_client(monkeypatch, record_b, shim_b, cli_b)
    result = run_module.run_application(flow_spec(tmp_path, record_b))
    assert result.exit_code == 0, result
    assert result.lifecycle_errors == () and result.cleanup_errors == ()
    assert argv_heads(engine) == ['proxy-build', 'init', 'daemon', 'cli', '--flag', 'health']
    record = json.loads(result.receipt_path.read_text())
    assert record['proxy']['expected_proxy_identity'] == record_b
    assert record['proxy']['launch_rehashes']['post_install'] == launch_rehashes(record_b)
    assert record['proxy']['launch_rehashes']['pre_launch'] == launch_rehashes(record_b)


@pytest.mark.parametrize('host', [False, True])
def test_run_flow_rejects_mixed_claims_before_init(monkeypatch, tmp_path, host):
    record_a = default_record()
    record_b, _, shim_b, cli_b, _, _ = selected_pair()
    engine = FlowEngine(json.dumps(daemon_claim(record_a)))
    monkeypatch.setattr(run_module, 'Docker', lambda: engine)
    monkeypatch.setattr(run_module, '_create_proxy_network', lambda *args: 'fixture-network')
    flow_client(monkeypatch, record_b, shim_b, cli_b)
    result = run_module.run_application(flow_spec(tmp_path, record_b, host=host))
    assert result.exit_code == 1
    assert result.lifecycle_errors == ('proxy identity failed',)
    assert result.app_returncode is None
    assert argv_heads(engine) == ['proxy-build']


@pytest.mark.parametrize('host', [False, True])
def test_run_flow_rejects_mixed_claims_direction2(monkeypatch, tmp_path, host):
    """Direction-2 run-level refusal is an install refusal, not a check refusal.

    Configuration mirrors direction-1 with the claims swapped: daemon-B
    claim + B bytes + A-recorded client manifest, selected B, both `host`
    lanes. Unlike direction-1, this never reaches the run-level check gate
    (`run.check_proxy_identities` at run.py:945-950): the real install path
    validates recorded-vs-selected first (`native._validate_client_manifest`
    at native.py:663-682, reached via install at run.py:917-919, before
    proxy-build creation at run.py:931-934), so the A-recorded manifest
    under expected-B raises inside install and lands in the outer handler
    (run.py:1174-1183) with zero containers created. Hence exit 1 with the
    install-refusal shape instead of the direction-1 check shape.
    """
    record_a = default_record()
    record_b, _, shim_b, cli_b, _, _ = selected_pair()
    engine = FlowEngine(json.dumps(daemon_claim(record_b)))
    monkeypatch.setattr(run_module, 'Docker', lambda: engine)
    monkeypatch.setattr(run_module, '_create_proxy_network', lambda *args: 'fixture-network')
    flow_client(monkeypatch, record_a, shim_b, cli_b)
    result = run_module.run_application(flow_spec(tmp_path, record_b, host=host))
    assert result.exit_code == 1
    assert result.lifecycle_errors == ('runner operation failed (ValueError)',)
    assert result.app_returncode is None
    assert argv_heads(engine) == []


@pytest.mark.parametrize('which', ['shim', 'cli'])
def test_altered_launch_bytes_reject_at_rehash(which):
    record_b, _, _, _, _, _ = selected_pair()
    rehashes = launch_rehashes(record_b)
    rehashes[which + '_sha256'] = '0' * 64
    with pytest.raises(ValueError, match='proxy identity mismatch'):
        proxy_inputs_module.validate_proxy_identity(merged_actual(record_b, rehashes=rehashes),
                                                    record_b)


@pytest.mark.parametrize('host', [False, True])
def test_run_flow_rejects_launch_drift_before_app(monkeypatch, tmp_path, host):
    record_b, _, shim_b, cli_b, _, _ = selected_pair()
    holder = {}

    def tamper():
        (holder['prefix'] / 'payload' / SHIM_PATH).write_bytes(shim_b + b'tampered')

    engine = FlowEngine(json.dumps(daemon_claim(record_b)), tamper=tamper)
    monkeypatch.setattr(run_module, 'Docker', lambda: engine)
    monkeypatch.setattr(run_module, '_create_proxy_network', lambda *args: 'fixture-network')
    manifest = client_manifest(record_b) | {
        'environment': 'softhsm2', 'channel': 'release', 'role': 'native-client',
        'target': native_module.CLIENT_TARGET, 'module': native_module.CLIENT_MODULE,
        'host_requirements': native_module.CLIENT_HOST_REQUIREMENTS,
        'files': [{'path': SHIM_PATH, 'sha256': record_b['shim']['sha256']},
                  {'path': CLI_PATH, 'sha256': record_b['cli']['sha256']}]}

    def install(artifact, prefix, *, environment, channel, expected_proxy_identity=None):
        assert artifact == CLIENT_BUNDLE
        installed = FlowInstalled(Path(prefix), manifest, shim_b, cli_b)
        holder['prefix'] = installed.prefix
        return installed

    monkeypatch.setattr(native_module, 'install_native_client_bundle', install)
    monkeypatch.setattr(native_module, 'preflight_native_client',
                        lambda prefix, manifest, expected_proxy_identity=None: {
                            'loader': 'fixture', 'architecture': 'x86_64',
                            'closure': {'shim': {'resolved': []}}, 'cli_version': 'test',
                            'rehashes': {'before': launch_rehashes(record_b),
                                         'after': launch_rehashes(record_b)}})
    result = run_module.run_application(flow_spec(tmp_path, record_b, host=host))
    assert result.exit_code == 1
    assert 'launch bytes changed before application launch' in result.lifecycle_errors
    assert result.app_returncode is None
    assert '--flag' not in argv_heads(engine) and 'true' not in argv_heads(engine)


def _tampered_client_abi(record, mutate):
    abi = client_abi_observed(record)
    mutate(abi)
    return abi


def test_altered_needed_rejects_at_abi_gate():
    record = default_record()
    abi = _tampered_client_abi(record, lambda a: a['needed'][SHIM_PATH].append('libevil.so.1'))
    with pytest.raises(ValueError, match='proxy identity mismatch'):
        proxy_inputs_module.validate_proxy_identity(merged_actual(record, abi=abi), record)


def test_raised_floor_rejects_at_abi_gate():
    record = default_record()

    def raise_floor(abi):
        abi['floors'][CLI_PATH]['libc.so.6']['GLIBC'] = '9.99'

    abi = _tampered_client_abi(record, raise_floor)
    with pytest.raises(ValueError, match='proxy identity mismatch'):
        proxy_inputs_module.validate_proxy_identity(merged_actual(record, abi=abi), record)


def test_missing_shim_export_rejects_at_abi_gate():
    record = default_record()
    abi = _tampered_client_abi(record, lambda a: a['shim_exports'].remove('C_GetFunctionList'))
    with pytest.raises(ValueError, match='proxy identity mismatch'):
        proxy_inputs_module.validate_proxy_identity(merged_actual(record, abi=abi), record)


def test_build_rejects_bytes_mismatching_selected_abi(tmp_path):
    from p11lab.models import ProxyBuildIdentityV1
    record_b, _, shim_b, cli_b, _, _ = selected_pair()
    bad = copy.deepcopy(record_b)
    bad['abi']['needed'][SHIM_PATH] = ['libevil.so.1']
    expected = ProxyBuildIdentityV1.from_dict(bad)
    (tmp_path / 'shim.so').write_bytes(shim_b)
    (tmp_path / 'cli').write_bytes(cli_b)
    (tmp_path / 'license').write_bytes(b'fixture-license')
    proxy = {'source_revision': bad['source_commit'], 'cargo_lock_sha256': bad['cargo_lock_sha256'],
             'source_archive_sha256': bad['source_archive']['sha256'],
             'shim_sha256': bad['shim']['sha256'], 'cli_sha256': bad['cli']['sha256']}
    with pytest.raises(ValueError, match='proxy identity mismatch'):
        native_module.build_native_client_bundle(
            proxy=proxy, shim=tmp_path / 'shim.so', cli=tmp_path / 'cli',
            licenses={f'share/licenses/proxy-ng/{name}': tmp_path / 'license'
                      for name in ('LICENSE-APACHE', 'LICENSE-MIT')},
            output_dir=tmp_path / 'build', environment='softhsm2', channel='release',
            expected_proxy_identity=expected)


def test_wrong_parent_rejects_at_naming_level():
    record_b, record_c, _, _, _, _ = selected_pair()
    bad = copy.deepcopy(record_b)
    bad['provider_parent'] = copy.deepcopy(record_c['provider_parent'])
    assert bad['provider_parent'] != record_b['provider_parent']
    actual = merged_actual(record_b, manifest=client_manifest(bad),
                           abi=client_abi_observed(record_b))
    with pytest.raises(ValueError, match='provider_parent'):
        proxy_inputs_module.validate_proxy_identity(actual, record_b)
    with pytest.raises(ValueError, match='provider_parent'):
        run_module.check_proxy_identities(actual['daemon_build_json'], actual['client_manifest'],
                                          expected=record_b,
                                          launch_rehashes=launch_rehashes(record_b),
                                          daemon_image=image_naming())


def test_daemon_image_naming_mismatch_rejects_at_check():
    record_b, _, _, _, _, _ = selected_pair()
    with pytest.raises(ValueError, match='proxy identity mismatch'):
        run_module.check_proxy_identities(
            daemon_claim(record_b), client_manifest(record_b), expected=record_b,
            launch_rehashes=launch_rehashes(record_b),
            daemon_image=image_naming(observed='sha256:' + '0' * 64))


def test_run_flow_rejects_daemon_image_naming_mismatch(monkeypatch, tmp_path):
    record_b, _, shim_b, cli_b, _, _ = selected_pair()
    engine = FlowEngine(json.dumps(daemon_claim(record_b)), image_id='sha256:' + '0' * 64)
    monkeypatch.setattr(run_module, 'Docker', lambda: engine)
    monkeypatch.setattr(run_module, '_create_proxy_network', lambda *args: 'fixture-network')
    flow_client(monkeypatch, record_b, shim_b, cli_b)
    result = run_module.run_application(flow_spec(tmp_path, record_b))
    assert result.exit_code == 1
    assert result.lifecycle_errors == ('proxy identity failed',)
    assert result.app_returncode is None
    assert argv_heads(engine) == ['proxy-build']


def test_matched_unselected_rejects_on_none_and_explicit_paths():
    _, record_c, _, _, _, _ = selected_pair()
    record_b, _, _, _, _, _ = selected_pair()
    with pytest.raises(ValueError, match='proxy identity mismatch'):
        proxy_inputs_module.validate_proxy_identity(merged_actual(record_c), None)
    with pytest.raises(ValueError, match='proxy identity mismatch'):
        proxy_inputs_module.validate_proxy_identity(merged_actual(record_c), record_b)
    with pytest.raises(ValueError, match='proxy identity mismatch'):
        run_module.check_proxy_identities(daemon_claim(record_c), client_manifest(record_c),
                                          expected=None,
                                          launch_rehashes=launch_rehashes(record_c),
                                          daemon_image=image_naming())


def write_manifest(tmp_path, record):
    path = tmp_path / 'proxy-build-manifest.json'
    path.write_text(json.dumps(record, indent=2, sort_keys=True))
    return path


def cli_run_argv(tmp_path, manifest=None, *, mode='proxy'):
    argv = ['run', 'softhsm2', '--channel', 'release', '--mode', mode, '--artifact',
           DAEMON_IMAGE.reference, '--consumer-image', CALLER_IMAGE.reference,
           '--client-artifact', '/tmp/client.tar.gz', '--client-sha256', 'c' * 64,
           '--output-dir', str(tmp_path / 'out'), '--cwd', str(tmp_path), '--', 'app']
    if manifest is not None:
        argv[1:1] = ['--proxy-build-manifest', str(manifest)]
    return argv


def test_cli_manifest_threads_expected_record(monkeypatch, tmp_path):
    from p11lab import cli as cli_module
    from p11lab.models import RunResult
    record_b, _, _, _, _, _ = selected_pair()
    captured = {}

    def fake_run(spec):
        captured['spec'] = spec
        return RunResult(0, (), (), 0, tmp_path / 'receipt.json')

    monkeypatch.setattr(run_module, 'run_application', fake_run)
    assert cli_module.main(cli_run_argv(tmp_path, write_manifest(tmp_path, record_b))) == 0
    assert captured['spec'].expected_proxy_identity.to_dict() == record_b


def test_cli_manifest_absent_selects_default(monkeypatch, tmp_path):
    from p11lab import cli as cli_module
    from p11lab.models import RunResult
    captured = {}

    def fake_run(spec):
        captured['spec'] = spec
        return RunResult(0, (), (), 0, tmp_path / 'receipt.json')

    monkeypatch.setattr(run_module, 'run_application', fake_run)
    assert cli_module.main(cli_run_argv(tmp_path)) == 0
    assert captured['spec'].expected_proxy_identity is None


@pytest.mark.parametrize('kind', ['missing', 'bad-json', 'partial', 'unknown-field'])
def test_cli_manifest_failures_are_usage_errors(tmp_path, kind):
    from p11lab import cli as cli_module
    record_b, _, _, _, _, _ = selected_pair()
    if kind == 'missing':
        manifest = tmp_path / 'absent.json'
    elif kind == 'bad-json':
        manifest = tmp_path / 'bad.json'
        manifest.write_text('{not json')
    elif kind == 'partial':
        manifest = tmp_path / 'partial.json'
        manifest.write_text(json.dumps({'schema': 'p11lab.proxy-build-identity.v1'}))
    else:
        manifest = tmp_path / 'unknown.json'
        manifest.write_text(json.dumps(record_b | {'unknown_field': 1}))
    assert cli_module.main(cli_run_argv(tmp_path, manifest)) == 2


def test_cli_manifest_duplicate_member_is_a_usage_error(monkeypatch, tmp_path):
    from p11lab import cli as cli_module
    from p11lab.models import RunResult
    record_b, _, _, _, _, _ = selected_pair()
    lines = json.dumps(record_b, indent=2, sort_keys=True).splitlines(keepends=True)
    index = next(i for i, line in enumerate(lines) if '"source_commit"' in line)
    assert lines[index].rstrip().endswith(',')
    lines.insert(index + 1, '  "source_commit": "%s",\n' % ('c' * 40))
    manifest = tmp_path / 'duplicate.json'
    manifest.write_text(''.join(lines))

    def fake_run(spec):
        return RunResult(0, (), (), 0, tmp_path / 'receipt.json')

    monkeypatch.setattr(run_module, 'run_application', fake_run)
    assert cli_module.main(cli_run_argv(tmp_path, manifest)) == 2


def test_cli_manifest_requires_proxy_mode(tmp_path):
    from p11lab import cli as cli_module
    record_b, _, _, _, _, _ = selected_pair()
    argv = ['run', 'softhsm2', '--channel', 'release', '--mode', 'direct', '--artifact',
           DAEMON_IMAGE.reference, '--proxy-build-manifest', str(write_manifest(tmp_path, record_b)),
           '--output-dir', str(tmp_path / 'out'), '--cwd', str(tmp_path), '--', 'app']
    assert cli_module.main(argv) == 2


def test_non_proxy_mode_with_expected_rejects_at_prepare(tmp_path):
    from p11lab.models import ProxyBuildIdentityV1
    record_b, _, _, _, _, _ = selected_pair()
    expected = ProxyBuildIdentityV1.from_dict(record_b)
    direct = RunSpec('softhsm2', 'release', 'direct', DAEMON_IMAGE, 'provider', None, None,
                     ('app',), {}, tmp_path / 'out', tmp_path, 60, expected_proxy_identity=expected)
    with pytest.raises(ValueError, match='requires proxy mode'):
        run_module.run_application(direct)
    native = RunSpec('softhsm2', 'release', 'native', CLIENT_BUNDLE, 'host', None, None,
                     ('app',), {}, tmp_path / 'out', tmp_path, 60,
                     expected_proxy_identity=expected)
    with pytest.raises(ValueError, match='requires proxy mode'):
        run_module.run_application(native)


def test_prepare_proxy_rejects_malformed_expected_shape(tmp_path):
    from dataclasses import replace
    record_b, _, _, _, _, _ = selected_pair()
    malformed = replace(flow_spec(tmp_path, record_b),
                        expected_proxy_identity={'not': 'a record'})
    with pytest.raises(ValueError, match='expected_proxy_identity'):
        run_module.prepare_proxy(malformed)


def test_record_schema_is_strict():
    record = default_record()
    with pytest.raises(ValueError, match='unknown field'):
        ProxyBuildIdentityV1.from_dict(record | {'unknown_field': 1})
    partial = dict(record)
    del partial['cargo_lock_sha256']
    with pytest.raises(ValueError, match='missing field'):
        ProxyBuildIdentityV1.from_dict(partial)
    bad = dict(record, cargo_lock_sha256='not-a-digest')
    with pytest.raises(ValueError, match='cargo_lock_sha256'):
        ProxyBuildIdentityV1.from_dict(bad)
    hooked = dict(record, hook_hashes=['deadbeef'])
    with pytest.raises(ValueError, match='hook_hashes'):
        ProxyBuildIdentityV1.from_dict(hooked)
    assert ProxyBuildIdentityV1.from_dict(record).to_dict() == record


def test_record_seal_rules_follow_origin():
    record_b, _, _, _, _, _ = selected_pair()
    dirty = dict(record_b, origin='local-dirty-snapshot', source_commit=None,
                 source_archive=None, content_seal='fixture-seal-1')
    assert ProxyBuildIdentityV1.from_dict(dirty).content_seal == 'fixture-seal-1'
    with pytest.raises(ValueError, match='content_seal'):
        ProxyBuildIdentityV1.from_dict(dict(dirty, content_seal=None))
    with pytest.raises(ValueError, match='content_seal'):
        ProxyBuildIdentityV1.from_dict(dict(record_b, content_seal='unexpected-seal'))
    with pytest.raises(ValueError, match='source_commit'):
        ProxyBuildIdentityV1.from_dict(dict(dirty, source_commit='f' * 40))


def test_sealed_dirty_origin_validates_present_seal_and_roster_digest():
    record_b, _, _, _, _, _ = selected_pair()
    dirty = dict(record_b, origin='local-dirty-snapshot', source_commit=None,
                 source_archive=None, content_seal='fixture-seal-1')
    dirty = ProxyBuildIdentityV1.from_dict(dirty).to_dict()
    assert proxy_inputs_module.validate_proxy_identity(
        merged_actual(dirty, daemon={'schema_version': 1, 'source_revision': None,
                                     'cargo_lock_sha256': dirty['cargo_lock_sha256'],
                                     'binaries': {'pkcs11-proxy-ng': dirty['daemon']['sha256'],
                                                  'pkcs11-proxy-ng-cli': dirty['cli']['sha256'],
                                                  'proxy-entrypoint.sh': dirty['entrypoint_sha256']}}),
        dirty)['expected'] == dirty
    resealed = dict(dirty)
    resealed['source_members'] = {'count': 7, 'canonical_roster_sha256': '0' * 64}
    with pytest.raises(ValueError, match='proxy identity mismatch'):
        proxy_inputs_module.validate_proxy_identity(merged_actual(dirty), resealed)


def test_stub_elf_parses_to_literal_empty_shape():
    from p11lab.round_core.proxy_worker import inspect_producer_elf
    for elf_type in (2, 3):
        info = inspect_producer_elf(stub_elf(elf_type=elf_type, tag=b'probe'))
        assert info['needed'] == [] and info['floors'] == {} and info['interpreter'] is None
        assert info['exports'] == [] and info['version_requirements'] == []
        assert info['symbol_versions'] == []
    assert empty_client_abi()['needed'] == {CLI_PATH: [], SHIM_PATH: []}


def test_native_expected_accepts_dict_records(tmp_path):
    record_b, _, shim_b, cli_b, _, _ = selected_pair()
    (tmp_path / 'shim.so').write_bytes(shim_b)
    (tmp_path / 'cli').write_bytes(cli_b)
    (tmp_path / 'license').write_bytes(b'fixture-license')
    proxy = {'source_revision': record_b['source_commit'],
             'cargo_lock_sha256': record_b['cargo_lock_sha256'],
             'source_archive_sha256': record_b['source_archive']['sha256'],
             'shim_sha256': record_b['shim']['sha256'], 'cli_sha256': record_b['cli']['sha256']}
    native_module.build_native_client_bundle(
        proxy=proxy, shim=tmp_path / 'shim.so', cli=tmp_path / 'cli',
        licenses={f'share/licenses/proxy-ng/{name}': tmp_path / 'license'
                  for name in ('LICENSE-APACHE', 'LICENSE-MIT')},
        output_dir=tmp_path / 'build', environment='softhsm2', channel='release',
        expected_proxy_identity=record_b)
    manifest = json.loads((tmp_path / 'build' / 'manifest.json').read_bytes())
    native_module._validate_client_manifest(manifest, 'softhsm2', 'release',
                                            expected_proxy_identity=record_b)


def test_install_and_load_thread_expected_to_gates(tmp_path, monkeypatch):
    from p11lab.models import ProxyBuildIdentityV1
    record_b, _, shim_b, cli_b, _, _ = selected_pair()
    expected = ProxyBuildIdentityV1.from_dict(record_b)
    (tmp_path / 'shim.so').write_bytes(shim_b)
    (tmp_path / 'cli').write_bytes(cli_b)
    (tmp_path / 'license').write_bytes(b'fixture-license')
    proxy = {'source_revision': record_b['source_commit'],
             'cargo_lock_sha256': record_b['cargo_lock_sha256'],
             'source_archive_sha256': record_b['source_archive']['sha256'],
             'shim_sha256': record_b['shim']['sha256'], 'cli_sha256': record_b['cli']['sha256']}
    artifact = native_module.build_native_client_bundle(
        proxy=proxy, shim=tmp_path / 'shim.so', cli=tmp_path / 'cli',
        licenses={f'share/licenses/proxy-ng/{name}': tmp_path / 'license'
                  for name in ('LICENSE-APACHE', 'LICENSE-MIT')},
        output_dir=tmp_path / 'build', environment='softhsm2', channel='release',
        expected_proxy_identity=expected)
    seen = []
    monkeypatch.setattr(native_module, 'preflight_native_client',
                        lambda prefix, manifest, expected_proxy_identity=None: seen.append(
                            expected_proxy_identity) or {'loader': 'x'})
    installed = native_module.install_native_client_bundle(
        artifact, tmp_path / 'prefix', environment='softhsm2', channel='release',
        expected_proxy_identity=expected)
    assert seen == [expected]
    reloaded = native_module.load_client_installation(
        installed.prefix, environment='softhsm2', channel='release', expected_proxy_identity=expected)
    assert seen == [expected, expected]
    assert reloaded.manifest['source']['proxy']['identity'] == record_b


def test_build_rejects_unparseable_bytes_fail_closed(tmp_path):
    from p11lab.models import ProxyBuildIdentityV1
    record_b, _, _, _, _, _ = selected_pair()
    garbage_shim, garbage_cli = b'not-an-elf-shim', b'not-an-elf-cli'
    bad = copy.deepcopy(record_b)
    bad['shim']['sha256'] = hashlib.sha256(garbage_shim).hexdigest()
    bad['shim']['size'] = len(garbage_shim)
    bad['cli']['sha256'] = hashlib.sha256(garbage_cli).hexdigest()
    bad['cli']['size'] = len(garbage_cli)
    expected = ProxyBuildIdentityV1.from_dict(bad)
    (tmp_path / 'shim.so').write_bytes(garbage_shim)
    (tmp_path / 'cli').write_bytes(garbage_cli)
    (tmp_path / 'license').write_bytes(b'fixture-license')
    proxy = {'source_revision': bad['source_commit'], 'cargo_lock_sha256': bad['cargo_lock_sha256'],
             'source_archive_sha256': bad['source_archive']['sha256'],
             'shim_sha256': bad['shim']['sha256'], 'cli_sha256': bad['cli']['sha256']}
    with pytest.raises(ValueError, match='ELF'):
        native_module.build_native_client_bundle(
            proxy=proxy, shim=tmp_path / 'shim.so', cli=tmp_path / 'cli',
            licenses={f'share/licenses/proxy-ng/{name}': tmp_path / 'license'
                      for name in ('LICENSE-APACHE', 'LICENSE-MIT')},
            output_dir=tmp_path / 'build', environment='softhsm2', channel='release',
            expected_proxy_identity=expected)


def test_validator_rejects_malformed_actual_and_expected_shapes():
    record_b, _, _, _, _, _ = selected_pair()
    actual = merged_actual(record_b)
    del actual['abi_observed']
    with pytest.raises(ValueError, match='actual invalid'):
        proxy_inputs_module.validate_proxy_identity(actual, record_b)
    with pytest.raises(ValueError, match='must be a dict or None'):
        proxy_inputs_module.validate_proxy_identity(merged_actual(record_b), ['not-a-dict'])
    bad_daemon = merged_actual(record_b)
    bad_daemon['daemon_build_json'] = dict(bad_daemon['daemon_build_json'], binaries={})
    with pytest.raises(ValueError, match='actual invalid'):
        proxy_inputs_module.validate_proxy_identity(bad_daemon, record_b)
    with pytest.raises(TypeError, match='requires a record'):
        ProxyBuildIdentityV1.from_dict(record_b).require_same_record('not-a-record', where='x')
    with pytest.raises(ValueError, match='must be a dict'):
        ProxyBuildIdentityV1.from_dict('not-a-dict')


def test_cli_manifest_size_bound_is_a_usage_error(tmp_path):
    from p11lab import cli as cli_module
    manifest = tmp_path / 'huge.json'
    manifest.write_bytes(b'{' + b' ' * (1024 * 1024) + b'}')
    assert cli_module.main(cli_run_argv(tmp_path, manifest)) == 2


def test_cli_manifest_read_is_bounded(tmp_path, monkeypatch):
    from p11lab import cli as cli_module
    manifest = tmp_path / 'big.json'
    manifest.write_bytes(b'{' + b' ' * (1024 * 1024 + 512) + b'}')
    pulled = []
    real_open = Path.open

    def counting_read_bytes(self):
        with real_open(self, mode='rb') as stream:
            data = stream.read()
        if self == manifest:
            pulled.append(len(data))
        return data

    class CountingBinaryStream:
        def __init__(self, stream):
            self._stream = stream

        def read(self, size=-1):
            data = self._stream.read(size)
            pulled.append(len(data))
            return data

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return self._stream.__exit__(*exc)

    def counting_open(self, *args, **kwargs):
        stream = real_open(self, *args, **kwargs)
        if self == manifest:
            return CountingBinaryStream(stream)
        return stream

    monkeypatch.setattr(Path, 'read_bytes', counting_read_bytes)
    monkeypatch.setattr(Path, 'open', counting_open)
    assert cli_module.main(cli_run_argv(tmp_path, manifest)) == 2
    assert pulled, 'loader never read the manifest'
    assert sum(pulled) <= 1024 * 1024 + 1


def test_cli_deeply_nested_json_manifest_is_a_usage_error(tmp_path):
    # Fix-1 Y-3: excessive JSON nesting raises RecursionError in the decoder
    # (below the size cap); Q12 requires every manifest failure to exit 2.
    from p11lab import cli as cli_module
    manifest = tmp_path / 'nested.json'
    payload = '[' * 10000 + '0' + ']' * 10000
    assert len(payload) < 1024 * 1024
    manifest.write_text(payload)
    assert cli_module.main(cli_run_argv(tmp_path, manifest)) == 2


def test_cli_deeply_nested_record_manifest_is_a_usage_error(tmp_path):
    # Fix-1 Y-3: hostile nesting inside a decodable record still exits 2 via
    # iterative schema validation (no validator recursion on hostile input).
    from p11lab import cli as cli_module
    record_b, _, _, _, _, _ = selected_pair()
    nested = record_b | {'hook_hashes': ['__NEST__']}
    text = json.dumps(nested, sort_keys=True)
    deep = '[' * 500 + '0' + ']' * 500
    manifest = tmp_path / 'nested-record.json'
    manifest.write_text(text.replace('["__NEST__"]', deep))
    json.loads(manifest.read_bytes().decode('utf-8'))
    assert cli_module.main(cli_run_argv(tmp_path, manifest)) == 2


def test_config_entrypoint_roster_vendor_oracles_recompute_pins():
    from p11lab.catalog import package_data
    from p11lab.models import canonical_json_bytes
    record = default_record()
    assert hashlib.sha256(
        run_module.render_proxy_toml(module_path='<provider-module>').encode()).hexdigest() == \
        record['daemon_config_sha256']
    assert hashlib.sha256(
        package_data('runtime/proxy-entrypoint.sh').read_bytes()).hexdigest() == \
        record['entrypoint_sha256']
    source = json.loads(package_data('tool-inputs/proxy/source-v1.json').read_text())
    assert len(source['members']) == record['source_members']['count']
    assert hashlib.sha256(canonical_json_bytes(source['members'])).hexdigest() == \
        record['source_members']['canonical_roster_sha256']
    crates = json.loads(package_data('tool-inputs/proxy/crates-v1.json').read_text())
    roster = sorted(({'identity': row['path'].removeprefix('crates/')[:-len('.crate')],
                      'sha256': row['sha256']} for row in crates['records']
                     if row['kind'] == 'proxy-crate'), key=lambda row: row['identity'])
    assert roster == record['vendor_packages']


def test_identity_record_freezes_accepted_dict_subclasses():
    # Fix-2 Y-2r: _check_product-shape validation accepts dict subclasses
    # via isinstance, so the verbatim codex OrderedDict trigger must fully
    # isolate (frozen storage plus independent export), never alias or
    # stay mutable.
    from collections import OrderedDict
    from types import MappingProxyType
    pristine = default_record()
    raw = tls_module.DEFAULT_PROXY_BUILD_IDENTITY().to_dict()
    raw['shim'] = OrderedDict(raw['shim'])
    selected = ProxyBuildIdentityV1.from_dict(raw)
    selected.to_dict()['shim']['sha256'] = '0' * 64
    assert selected.to_dict() == pristine
    assert raw == pristine
    assert type(selected.shim) is MappingProxyType
    assert selected.shim is not raw['shim']
    exported = selected.to_dict()
    assert type(exported['shim']) is dict
    with pytest.raises(TypeError):
        selected.shim['sha256'] = 'f' * 64
    raw['shim']['sha256'] = '1' * 64
    assert selected.to_dict() == pristine


def test_identity_record_freezes_subclasses_at_nested_sites():
    # Fix-2 Y-2r: every nested isinstance-accepted site freezes subclass
    # inputs — list subclasses in ABI maps, dict subclasses in rows and
    # nested maps, and the []-equal hook_hashes edge. Stored values refuse
    # mutation and stay isolated from both the input and the export.
    from collections import OrderedDict
    from types import MappingProxyType

    class SubList(list):
        pass

    pristine = default_record()
    assert pristine['abi']['version_requirements'][DAEMON_PATH]
    assert pristine['abi']['symbol_versions'][DAEMON_PATH]
    assert pristine['abi']['floors'][DAEMON_PATH]
    raw = copy.deepcopy(pristine)
    raw['vendor_packages'][0] = OrderedDict(raw['vendor_packages'][0])
    raw['abi']['needed'][CLI_PATH] = SubList(raw['abi']['needed'][CLI_PATH])
    raw['abi']['shim_exports'] = SubList(raw['abi']['shim_exports'])
    raw['abi']['version_requirements'][DAEMON_PATH] = SubList(
        OrderedDict(row) for row in raw['abi']['version_requirements'][DAEMON_PATH])
    raw['abi']['symbol_versions'][SHIM_PATH] = SubList(
        OrderedDict(row) for row in raw['abi']['symbol_versions'][SHIM_PATH])
    first_floor = next(iter(raw['abi']['floors'][DAEMON_PATH]))
    raw['abi']['floors'][DAEMON_PATH] = OrderedDict(raw['abi']['floors'][DAEMON_PATH])
    raw['abi']['floors'][DAEMON_PATH][first_floor] = OrderedDict(
        raw['abi']['floors'][DAEMON_PATH][first_floor])
    raw['hook_hashes'] = SubList(raw['hook_hashes'])
    assert raw == pristine
    built = ProxyBuildIdentityV1.from_dict(raw)
    assert built.to_dict() == pristine

    def assert_frozen(value):
        if isinstance(value, (dict, list)):
            raise AssertionError('unfrozen record storage: %r' % type(value))
        if isinstance(value, MappingProxyType):
            for sub in value.values():
                assert_frozen(sub)
        elif isinstance(value, tuple):
            for sub in value:
                assert_frozen(sub)
        elif isinstance(value, (str, int, type(None))):
            pass
        else:
            raise AssertionError('unexpected record storage: %r' % type(value))

    for name in pristine:
        assert_frozen(getattr(built, name))
    with pytest.raises(TypeError):
        built.vendor_packages[0]['identity'] = 'evil'
    with pytest.raises(AttributeError):
        built.abi['needed'][CLI_PATH].append('libevil.so.1')
    with pytest.raises(AttributeError):
        built.hook_hashes.append('evil')
    exported = built.to_dict()
    assert type(exported['vendor_packages'][0]) is dict
    assert type(exported['abi']['needed'][CLI_PATH]) is list
    assert type(exported['hook_hashes']) is list
    exported['vendor_packages'][0]['identity'] = 'evil'
    exported['abi']['needed'][CLI_PATH].append('libevil.so.1')
    exported['hook_hashes'].append('evil')
    exported['abi']['floors'][DAEMON_PATH][first_floor]['libevil.so'] = '9.9'
    assert built.to_dict() == pristine
    assert raw == pristine
    raw['vendor_packages'][0]['identity'] = 'evil'
    raw['abi']['needed'][CLI_PATH].append('libevil.so.1')
    raw['hook_hashes'].append('evil')
    assert built.to_dict() == pristine


def test_identity_freeze_thaw_helpers_roundtrip_frozen_inputs():
    # Fix-2 Y-2r: the helpers are total and idempotent — MappingProxyType
    # and tuple inputs re-freeze into fresh deep-frozen containers, and
    # thaw always yields independent exact plain containers (even for
    # plain/subclass inputs that never passed through freeze).
    from collections import OrderedDict
    from types import MappingProxyType
    from p11lab.models import _freeze_record_value, _thaw_record_value
    nested = {'a': [1, {'b': [2]}], 'c': OrderedDict(x=1)}
    frozen = _freeze_record_value(nested)
    assert type(frozen) is MappingProxyType
    assert type(frozen['a']) is tuple
    assert type(frozen['a'][1]) is MappingProxyType
    assert type(frozen['c']) is MappingProxyType
    assert _thaw_record_value(frozen) == {'a': [1, {'b': [2]}], 'c': {'x': 1}}
    nested['a'].append(3)
    nested['a'][1]['b'].append(4)
    nested['c']['y'] = 2
    assert _thaw_record_value(frozen) == {'a': [1, {'b': [2]}], 'c': {'x': 1}}
    refrozen = _freeze_record_value(frozen)
    assert type(refrozen) is MappingProxyType
    assert refrozen is not frozen
    assert _thaw_record_value(refrozen) == _thaw_record_value(frozen)
    live = {'k': [1]}
    frozen_live = _freeze_record_value(MappingProxyType(live))
    live['k'].append(2)
    live['z'] = 0
    assert _thaw_record_value(frozen_live) == {'k': [1]}
    frozen_tuple = _freeze_record_value(({'k': [1]},))
    assert type(frozen_tuple) is tuple
    assert type(frozen_tuple[0]) is MappingProxyType
    assert _thaw_record_value(frozen_tuple) == [{'k': [1]}]
    original = OrderedDict(a=[1])
    thawed_sub = _thaw_record_value(original)
    assert type(thawed_sub) is dict
    thawed_sub['a'].append(2)
    thawed_sub['b'] = 3
    assert original == OrderedDict(a=[1])
    plain = {'a': [1]}
    thawed_plain = _thaw_record_value(plain)
    assert thawed_plain == plain and thawed_plain is not plain
    assert thawed_plain['a'] is not plain['a']
    assert type(_freeze_record_value({})) is MappingProxyType
    assert type(_freeze_record_value([])) is tuple
    assert type(_thaw_record_value(MappingProxyType({}))) is dict
    assert _thaw_record_value(MappingProxyType({})) == {}
    assert type(_thaw_record_value(())) is list
    assert _thaw_record_value(()) == []
