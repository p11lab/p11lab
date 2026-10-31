"""Thin local derivative over the selected unchanged provider image.

Covers the M07 derivative slice: parent-selection loading (images.json entry
plus the protected DiffID roster), hermetic parent verification (exact
ordered DiffID prefix plus manifest/config binding), sealed offline build
context rendering, and receipt-chain parent proof through the daemon-image
naming gate. Hermetic only: no Docker, no network, no live builds. Fixture
hashes are invented in this file; oracles use hashlib directly, never the
code under test. Real pins are asserted only where the code under test reads
protected in-checkout data (roster loader, roster-anchored naming checks).
"""
import copy
import hashlib
import json
import os
import struct
from pathlib import Path

import pytest

from p11lab import native as native_module
from p11lab import proxy_derivative as derivative_module
from p11lab import proxy_inputs as proxy_inputs_module
from p11lab import run as run_module
from p11lab import tls as tls_module
from p11lab.docker import CommandResult, DockerError
from p11lab.models import ArtifactRef, ProxyBuildIdentityV1, RunSpec

DAEMON_PATH = 'bin/pkcs11-proxy-ng'
CLI_PATH = 'bin/pkcs11-proxy-ng-cli'
SHIM_PATH = 'lib/libpkcs11_proxy_ng_shim.so'
DAEMON_IMAGE = ArtifactRef('docker-local', 'sha256:' + 'd' * 64, 'd' * 64, 'linux/amd64')
CALLER_IMAGE = ArtifactRef('docker-local', 'sha256:' + 'e' * 64, 'e' * 64, 'linux/amd64')
CLIENT_BUNDLE = ArtifactRef('bundle', '/tmp/client.tar.gz', 'f' * 64, 'linux/amd64')

# Real roster pins, asserted only against protected in-checkout data.
# Authority: src/p11lab/data/ci/images.json (softhsm2/release/linux/amd64)
# plus src/p11lab/data/ci/softhsm2-release-amd64.diffids.json.
ROSTER_MANIFEST = '69cdeb9a74d13a3382547e184645ee18a7e9e2315246fd40ca814ef97b970d16'
ROSTER_CONFIG = 'e59ab297033cedfd8049f76bcf6d9e9c86f8df262be1c80ccbd7c1731437d24f'


@pytest.fixture(autouse=True)
def _no_host_openssl(monkeypatch, tmp_path):
    """Hard checkout-read boundary: no test here may reach host OpenSSL.

    Shadows `openssl` on PATH with a failing stand-in and points
    OPENSSL_CONF at a nonexistent path, so any unstubbed TLS generation
    fails loudly instead of inheriting host configuration.
    """
    poison = tmp_path / 'no-openssl-bin'
    poison.mkdir()
    shim = poison / 'openssl'
    shim.write_text('#!/bin/sh\necho hermetic-violation: openssl invoked >&2\nexit 127\n')
    shim.chmod(0o755)
    monkeypatch.setenv('OPENSSL_CONF', str(tmp_path / 'nonexistent-openssl.cnf'))
    monkeypatch.setenv('PATH', str(poison) + os.pathsep + os.environ.get('PATH', ''))


def _invented_layer(tag):
    """Independent oracle: invented DiffID from literal bytes via hashlib."""
    return 'sha256:' + hashlib.sha256(b'derivative-fixture:' + tag).hexdigest()


PARENT_LAYERS = [_invented_layer(b'parent-layer-%d' % index) for index in range(6)]
EXTRA_LAYERS = [_invented_layer(b'child-extra-%d' % index) for index in range(4)]
WRONG_LAYERS = [_invented_layer(b'wrong-parent-layer-%d' % index) for index in range(6)]


def invented_selection():
    """Authored parent selection with invented digests (Id equals manifest).

    Mirrors the real Id-equals-manifest split (brief pins): the engine Id
    carries the manifest value while the config digest differs, so every
    identifier must be checked in its own field.
    """
    return {'family': 'fixture-derivative', 'channel': 'release', 'platform': 'linux/amd64',
            'repository': 'example.invalid/fixture-derivative',
            'manifest_digest': 'sha256:' + 'a0' * 32, 'config_digest': 'sha256:' + 'a1' * 32,
            'local_engine_id': 'sha256:' + 'a0' * 32, 'layers': list(PARENT_LAYERS)}


def child_inspection(layers, **extra):
    """Authored engine-inspection shape carrying the given DiffID list."""
    inspection = {'Id': 'sha256:' + 'c0' * 32, 'Os': 'linux', 'Architecture': 'amd64',
                  'RootFS': {'Type': 'layers', 'Layers': list(layers)}}
    inspection.update(extra)
    return inspection


def parent_inspection(selection, *, engine_id=None, repo_digests=None):
    """Authored parent inspection matching a selection exactly."""
    digest = selection['manifest_digest']
    return {'Id': selection['local_engine_id'] if engine_id is None else engine_id,
            'Os': 'linux', 'Architecture': 'amd64',
            'RootFS': {'Type': 'layers', 'Layers': list(selection['layers'])},
            'RepoDigests': ([selection['repository'] + '@' + digest]
                            if repo_digests is None else list(repo_digests))}


def parent_evidence(selection, child_layers):
    """Observed daemon_parent evidence anchored to a selection."""
    return {'family': selection['family'], 'platform': selection['platform'],
            'manifest_digest': selection['manifest_digest'],
            'config_digest': selection['config_digest'],
            'parent_layers': list(selection['layers']), 'child_layers': list(child_layers)}


def stub_elf(*, elf_type, tag):
    """Minimal parseable ELF64 (struct-built); payload differentiates hashes."""
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


D_TAG = 'd0123456789'
E_TAG = 'e9876543210'


def fixture_record(shim_bytes, cli_bytes, *, tag, provider_parent='invented'):
    """Authored D/E-style record: distinct source/products, chosen F28."""
    base = default_record()
    if provider_parent == 'invented':
        parent = {'family': 'fixture-provider-' + tag[0], 'platform': 'linux/amd64',
                  'manifest_digest': tag[9] * 64, 'config_digest': tag[10] * 64}
    elif provider_parent == 'roster':
        parent = {'family': 'softhsm2', 'platform': 'linux/amd64',
                  'manifest_digest': ROSTER_MANIFEST, 'config_digest': ROSTER_CONFIG}
    else:
        raise AssertionError('unknown F28 fixture kind')
    base.update({
        'origin': 'installed-default',
        'source_commit': tag[0] * 40,
        'source_tree': tag[1] * 40,
        'source_archive': {'sha256': tag[2] * 64, 'size': 4321,
                           'prefix': 'pkcs11-proxy-ng-fixture-' + tag[0]},
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
        'caller': {'origin': 'local-controller', 'run_id': 'fixture-run-' + tag[0],
                   'job_id': 'fixture-job-' + tag[0]},
        'provider_parent': parent,
    })
    return ProxyBuildIdentityV1.from_dict(base).to_dict()


def fixture_bytes(tag):
    """Distinct stub product bytes per fixture tag."""
    return (stub_elf(elf_type=3, tag=b'shim-' + tag),
            stub_elf(elf_type=2, tag=b'cli-' + tag))


def daemon_claim(record):
    """Authored proxy-build stdout claim matching a record."""
    return {'schema_version': 1, 'source_revision': record['source_commit'],
            'cargo_lock_sha256': record['cargo_lock_sha256'],
            'binaries': {'pkcs11-proxy-ng': record['daemon']['sha256'],
                         'pkcs11-proxy-ng-cli': record['cli']['sha256'],
                         'proxy-entrypoint.sh': record['entrypoint_sha256']}}


def client_abi_observed(record):
    """Authored client ABI observation matching a record."""
    return {'decision': record['abi']['decision'],
            'runtime_qualification': record['abi']['runtime_qualification'],
            'floors': {path: record['abi']['floors'][path] for path in (CLI_PATH, SHIM_PATH)},
            'needed': {path: record['abi']['needed'][path] for path in (CLI_PATH, SHIM_PATH)},
            'interpreters': {path: record['abi']['interpreters'][path]
                             for path in (CLI_PATH, SHIM_PATH)},
            'shim_exports': list(record['abi']['shim_exports']),
            'version_requirements': {path: record['abi']['version_requirements'][path]
                                     for path in (CLI_PATH, SHIM_PATH)},
            'symbol_versions': {path: record['abi']['symbol_versions'][path]
                                for path in (CLI_PATH, SHIM_PATH)}}


def client_manifest(record):
    """Authored native-client manifest identity section matching a record."""
    archive = record['source_archive']
    return {'source': {'proxy': {
        'repository': 'https://github.com/mingulov/pkcs11-proxy-ng',
        'source_revision': record['source_commit'],
        'source_archive_sha256': archive['sha256'] if archive else None,
        'cargo_lock_sha256': record['cargo_lock_sha256'],
        'shim_sha256': record['shim']['sha256'], 'cli_sha256': record['cli']['sha256'],
        'identity': copy.deepcopy(record), 'abi_observed': client_abi_observed(record)}}}


def launch_rehashes(record):
    """Authored post-install shim/CLI digests matching a record."""
    return {'shim_sha256': record['shim']['sha256'], 'cli_sha256': record['cli']['sha256']}


def merged_actual(record, *, daemon_parent=None):
    """Merged validator actual, optionally carrying observed parent evidence."""
    actual = {'daemon_build_json': daemon_claim(record), 'client_manifest': client_manifest(record),
              'launch_rehashes': launch_rehashes(record),
              'abi_observed': client_abi_observed(record)}
    if daemon_parent is not None:
        actual['daemon_parent'] = copy.deepcopy(daemon_parent)
    return actual


def image_naming(*, parent=None):
    """Daemon image naming gate input, optionally with parent evidence."""
    reference = DAEMON_IMAGE.reference
    naming = {'selected': reference, 'observed': reference}
    if parent is not None:
        naming['parent'] = copy.deepcopy(parent)
    return naming


def selected_pair():
    """Authored D/E fixture records with distinct bytes, hashes, and parents."""
    shim_d, cli_d = fixture_bytes(b'D')
    shim_e, cli_e = fixture_bytes(b'E')
    assert (shim_d, cli_d) != (shim_e, cli_e)
    record_d = fixture_record(shim_d, cli_d, tag=D_TAG)
    record_e = fixture_record(shim_e, cli_e, tag=E_TAG)
    assert record_d != record_e
    return record_d, record_e, shim_d, cli_d, shim_e, cli_e


def test_loader_returns_verbatim_roster_pins():
    selection = derivative_module.load_parent_selection()
    assert selection['family'] == 'softhsm2'
    assert selection['channel'] == 'release'
    assert selection['platform'] == 'linux/amd64'
    assert selection['repository'] == 'ghcr.io/p11lab/softhsm2'
    assert selection['manifest_digest'] == 'sha256:' + ROSTER_MANIFEST
    assert selection['config_digest'] == 'sha256:' + ROSTER_CONFIG
    assert selection['local_engine_id'] == 'sha256:' + ROSTER_MANIFEST
    assert len(selection['layers']) == 6
    assert selection['layers'][0] == (
        'sha256:a6dc765193a52cbaede3c93a9ff48b9540948dd0774bbe7031fcb5847606f9ac')
    assert selection['layers'][-1] == (
        'sha256:9617d7149dc9fcd5798167d8b1097f2db8a29b4405d59b0b6964e1b50fcb94c3')


def test_loader_rejects_unbound_family():
    with pytest.raises(ValueError, match='selection unavailable'):
        derivative_module.load_parent_selection(family='kryoptic')
    with pytest.raises(ValueError, match='selection unavailable'):
        derivative_module.load_parent_selection(platform='linux/arm64')


def test_loader_refuses_cross_pin_mismatch(monkeypatch):
    real = derivative_module.load_parent_selection()

    def tampered():
        tampered_selection = dict(real)
        tampered_selection['manifest_digest'] = 'sha256:' + 'f' * 64
        return tampered_selection

    monkeypatch.setattr(derivative_module, '_read_roster_selection', tampered)
    with pytest.raises(ValueError, match='roster pin mismatch'):
        derivative_module.load_parent_selection()


def test_h1_parent_prefix_pass_returns_binding():
    selection = invented_selection()
    child = child_inspection(PARENT_LAYERS + EXTRA_LAYERS)
    binding = derivative_module.verify_derivative_parent(child, selection)
    assert binding['child_layers_prefix_ok'] is True
    assert binding['parent_layers'] == PARENT_LAYERS
    assert binding['child_layers'] == PARENT_LAYERS + EXTRA_LAYERS
    # The binding populates F28 naming fields from the verified selection.
    assert binding['family'] == selection['family']
    assert binding['platform'] == selection['platform']
    assert binding['manifest_digest'] == selection['manifest_digest']
    assert binding['config_digest'] == selection['config_digest']


def test_h1_exact_parent_layers_pass_without_extras():
    selection = invented_selection()
    binding = derivative_module.verify_derivative_parent(
        child_inspection(PARENT_LAYERS), selection)
    assert binding['child_layers_prefix_ok'] is True
    assert binding['child_layers'] == PARENT_LAYERS


def test_h1_full_parent_corroboration_passes():
    selection = invented_selection()
    binding = derivative_module.verify_derivative_parent(
        child_inspection(PARENT_LAYERS + EXTRA_LAYERS), selection,
        parent_inspection=parent_inspection(selection))
    assert binding['child_layers_prefix_ok'] is True


def test_h2_wrong_parent_rejects_direct_prefix():
    selection = invented_selection()
    with pytest.raises(ValueError, match=r'child\.RootFS\.Layers'):
        derivative_module.verify_derivative_parent(
            child_inspection(WRONG_LAYERS + EXTRA_LAYERS), selection)


def test_h2_reordered_parent_layers_reject():
    selection = invented_selection()
    reordered = list(PARENT_LAYERS)
    reordered[0], reordered[1] = reordered[1], reordered[0]
    with pytest.raises(ValueError, match=r'child\.RootFS\.Layers'):
        derivative_module.verify_derivative_parent(
            child_inspection(reordered + EXTRA_LAYERS), selection)


def test_h2_wrong_parent_rejects_naming_path():
    selection = derivative_module.load_parent_selection()
    evidence = parent_evidence(selection, WRONG_LAYERS + EXTRA_LAYERS)
    record = default_record()
    with pytest.raises(ValueError, match=r'child\.RootFS\.Layers'):
        proxy_inputs_module.validate_proxy_identity(merged_actual(record, daemon_parent=evidence),
                                                    None)


def test_h3_swapped_digests_reject_naming_path():
    record_d, _, shim_d, cli_d, _, _ = selected_pair()
    record = fixture_record(shim_d, cli_d, tag=D_TAG, provider_parent='roster')
    evidence = parent_evidence(derivative_module.load_parent_selection(),
                               derivative_module.load_parent_selection()['layers'] + EXTRA_LAYERS)
    evidence['manifest_digest'], evidence['config_digest'] = (
        evidence['config_digest'], evidence['manifest_digest'])
    with pytest.raises(ValueError, match='daemon_parent'):
        proxy_inputs_module.validate_proxy_identity(merged_actual(record, daemon_parent=evidence),
                                                    record)


def test_h3_swapped_selection_digests_reject_repo_corroboration():
    selection = invented_selection()
    selection['manifest_digest'], selection['config_digest'] = (
        selection['config_digest'], selection['manifest_digest'])
    with pytest.raises(ValueError, match=r'parent\.RepoDigests'):
        derivative_module.verify_derivative_parent(
            child_inspection(PARENT_LAYERS + EXTRA_LAYERS), selection,
            parent_inspection=parent_inspection(invented_selection()))


def test_h4_label_spoof_with_wrong_diffids_rejects():
    selection = invented_selection()
    digest = selection['manifest_digest']
    spoofed = child_inspection(
        WRONG_LAYERS + EXTRA_LAYERS,
        RepoDigests=[selection['repository'] + '@' + digest],
        RepoTags=[selection['repository'] + ':release'],
        Config={'Labels': {'org.p11lab.build-key': 'correct-label',
                           'org.p11lab.source-revision': 'correct-label'}})
    with pytest.raises(ValueError, match=r'child\.RootFS\.Layers'):
        derivative_module.verify_derivative_parent(
            spoofed, selection, parent_inspection=parent_inspection(selection))


def test_h4_correct_diffids_pass_despite_wrong_labels():
    selection = invented_selection()
    unlabeled = child_inspection(
        PARENT_LAYERS + EXTRA_LAYERS,
        RepoDigests=['example.invalid/wrong@sha256:' + 'b' * 64],
        RepoTags=['example.invalid/wrong:tag'],
        Config={'Labels': {'org.p11lab.build-key': 'wrong-label'}})
    # Labels, tags, and child RepoDigests are never evidence: the DiffID
    # prefix alone decides the child side.
    binding = derivative_module.verify_derivative_parent(unlabeled, selection)
    assert binding['child_layers_prefix_ok'] is True


def test_h5_engine_id_equals_manifest_passes_when_each_field_matches():
    selection = invented_selection()
    assert selection['local_engine_id'] == selection['manifest_digest']
    assert selection['config_digest'] != selection['manifest_digest']
    binding = derivative_module.verify_derivative_parent(
        child_inspection(PARENT_LAYERS + EXTRA_LAYERS), selection,
        parent_inspection=parent_inspection(selection))
    assert binding['child_layers_prefix_ok'] is True


def test_h5_parent_id_holding_config_value_rejects():
    selection = invented_selection()
    confused = parent_inspection(selection, engine_id=selection['config_digest'])
    with pytest.raises(ValueError, match=r'parent\.Id'):
        derivative_module.verify_derivative_parent(
            child_inspection(PARENT_LAYERS + EXTRA_LAYERS), selection,
            parent_inspection=confused)


def test_h5_repo_corroboration_binds_manifest_not_config():
    selection = invented_selection()
    config_repo = [selection['repository'] + '@' + selection['config_digest']]
    confused = parent_inspection(selection, repo_digests=config_repo)
    with pytest.raises(ValueError, match=r'parent\.RepoDigests'):
        derivative_module.verify_derivative_parent(
            child_inspection(PARENT_LAYERS + EXTRA_LAYERS), selection,
            parent_inspection=confused)


def invented_products(directory):
    """Authored product entries with invented bytes (hashlib oracle)."""
    Path(directory).mkdir(parents=True, exist_ok=True)
    entries = []
    for name in derivative_module.DERIVATIVE_PRODUCTS:
        data = b'derivative-fixture-product:' + name.encode()
        path = Path(directory) / name
        path.write_bytes(data)
        entries.append({'name': name, 'sha256': hashlib.sha256(data).hexdigest(),
                        'size': len(data), 'path': str(path)})
    return entries


def invented_notices():
    """Invented notice bytes (sealing only; pins fail closed separately)."""
    return {'LICENSE-APACHE': b'derivative-fixture-apache-notice',
            'LICENSE-MIT': b'derivative-fixture-mit-notice'}


def test_h6_context_round_trip_seals_staged_bytes(tmp_path):
    rendered = derivative_module.render_derivative_build_context(
        products=invented_products(tmp_path / 'products'), notices=invented_notices(),
        dest=tmp_path / 'ctx')
    manifest = (tmp_path / 'ctx' / 'proxy-bins.sha256').read_bytes()
    assert hashlib.sha256(manifest).hexdigest() == rendered['proxy_bins_sha256']
    assert rendered['staged_files'] == sorted(rendered['staged_files'])
    verified = derivative_module.verify_derivative_build_context(
        tmp_path / 'ctx', proxy_bins_sha256=rendered['proxy_bins_sha256'],
        staged_files=rendered['staged_files'])
    assert verified['verified'] is True


def test_h6_altered_product_byte_refuses_manifest(tmp_path):
    entries = invented_products(tmp_path / 'products')
    (tmp_path / 'products' / entries[0]['name']).write_bytes(b'tampered-product-bytes')
    with pytest.raises(ValueError, match='products'):
        derivative_module.render_derivative_build_context(
            products=entries, notices=invented_notices(), dest=tmp_path / 'ctx')


def test_h6_added_staged_file_refuses_roster(tmp_path):
    rendered = derivative_module.render_derivative_build_context(
        products=invented_products(tmp_path / 'products'), notices=invented_notices(),
        dest=tmp_path / 'ctx')
    (tmp_path / 'ctx' / 'proxy-bins' / 'extra-binary').write_bytes(b'intruder')
    with pytest.raises(ValueError, match='staged_files'):
        derivative_module.verify_derivative_build_context(
            tmp_path / 'ctx', proxy_bins_sha256=rendered['proxy_bins_sha256'],
            staged_files=rendered['staged_files'])


def test_h6_removed_staged_file_refuses_roster(tmp_path):
    rendered = derivative_module.render_derivative_build_context(
        products=invented_products(tmp_path / 'products'), notices=invented_notices(),
        dest=tmp_path / 'ctx')
    staged = sorted((tmp_path / 'ctx').rglob('*'))
    victim = [path for path in staged if path.is_file()][0]
    victim.unlink()
    with pytest.raises(ValueError, match='staged_files'):
        derivative_module.verify_derivative_build_context(
            tmp_path / 'ctx', proxy_bins_sha256=rendered['proxy_bins_sha256'],
            staged_files=rendered['staged_files'])


def test_h6_tampered_build_claim_rejects_expected():
    record_d, _, _, _, _, _ = selected_pair()
    claim = daemon_claim(record_d)
    claim['binaries']['pkcs11-proxy-ng'] = 'f' * 64
    actual = merged_actual(record_d)
    actual['daemon_build_json'] = claim
    with pytest.raises(ValueError, match='daemon.binaries.pkcs11-proxy-ng'):
        proxy_inputs_module.validate_proxy_identity(actual, record_d)


def test_h6_invented_notices_fail_pin_check_closed():
    with pytest.raises(ValueError, match='notices mismatch'):
        derivative_module.verify_derivative_notices(invented_notices())


def test_h6_notices_roster_shape_is_exact():
    with pytest.raises(ValueError, match='notices'):
        derivative_module.verify_derivative_notices({'LICENSE-APACHE': b'only-one'})


class RefusingEngine:
    """Docker double that fails any engine touch (fail-closed ordering)."""

    def __getattr__(self, name):
        raise AssertionError('engine must not be touched: ' + name)


def test_h6_build_refuses_wrong_parent_without_docker(tmp_path):
    with pytest.raises(ValueError, match='parent_ref'):
        derivative_module.build_proxy_derivative(
            parent_ref='sha256:' + 'f' * 64,
            products=invented_products(tmp_path / 'products'), notices=invented_notices(),
            build_args={'PROXY_BINS_MANIFEST_SHA256': '0' * 64,
                        'PROXY_SOURCE_REVISION': '0' * 40,
                        'PROXY_CARGO_LOCK_SHA256': '0' * 64},
            output=tmp_path / 'out', engine=RefusingEngine())


def test_h6_build_refuses_unpinned_notices_without_docker(tmp_path):
    selection = derivative_module.load_parent_selection()
    with pytest.raises(ValueError, match='notices mismatch'):
        derivative_module.build_proxy_derivative(
            parent_ref=selection['local_engine_id'],
            products=invented_products(tmp_path / 'products'), notices=invented_notices(),
            build_args={'PROXY_BINS_MANIFEST_SHA256': '0' * 64,
                        'PROXY_SOURCE_REVISION': '0' * 40,
                        'PROXY_CARGO_LOCK_SHA256': '0' * 64},
            output=tmp_path / 'out', engine=RefusingEngine())


def test_h6_build_refuses_manifest_arg_mismatch_without_docker(tmp_path, monkeypatch):
    selection = derivative_module.load_parent_selection()
    pinned = {'LICENSE-APACHE': b'pinned-apache-bytes', 'LICENSE-MIT': b'pinned-mit-bytes'}
    monkeypatch.setitem(derivative_module.DERIVATIVE_NOTICES, 'LICENSE-APACHE',
                        hashlib.sha256(pinned['LICENSE-APACHE']).hexdigest())
    monkeypatch.setitem(derivative_module.DERIVATIVE_NOTICES, 'LICENSE-MIT',
                        hashlib.sha256(pinned['LICENSE-MIT']).hexdigest())
    with pytest.raises(ValueError, match='PROXY_BINS_MANIFEST_SHA256'):
        derivative_module.build_proxy_derivative(
            parent_ref=selection['local_engine_id'],
            products=invented_products(tmp_path / 'products'), notices=pinned,
            build_args={'PROXY_BINS_MANIFEST_SHA256': '0' * 64,
                        'PROXY_SOURCE_REVISION': '0' * 40,
                        'PROXY_CARGO_LOCK_SHA256': '0' * 64},
            output=tmp_path / 'out', engine=RefusingEngine())


class ShapeEngine:
    """Minimal Docker double proving build observation assembly (no daemon)."""

    def __init__(self, selection, child_layers, claim):
        self.selection = selection
        self.child_layers = list(child_layers)
        self.claim = claim
        self.build_argv = None
        self.removed_images = []
        self.inspect_probes = []
        self.removed = []
        self.inspections = 0

    def image(self, artifact):
        self.inspections += 1
        if artifact.reference == self.selection['local_engine_id']:
            return parent_inspection(self.selection)
        return child_inspection(self.child_layers)

    def command(self, args, timeout=15, *, check=True, **kwargs):
        if args[0] == 'build':
            self.build_argv = list(args)
            iidfile = Path(args[args.index('--iidfile') + 1])
            iidfile.write_text('sha256:' + 'c9' * 32 + '\n')
            return CommandResult(0, 'fixture build ok', '', False)
        if args[:2] == ['image', 'rm']:
            self.removed_images.append(args[2])
            return CommandResult(0, '', '', False)
        if args[:2] == ['image', 'inspect']:
            self.inspect_probes.append(args[2])
            # Ref-bound daemon response: the bare marker alone is the unbound
            # diagnostic X-3r forbids, so the default fixture names the probed ref.
            return CommandResult(1, '', 'Error response from daemon: No such image: ' + args[2],
                                 False)
        raise AssertionError('unexpected command: ' + ' '.join(args))

    def create(self, image, argv, options, labels, name):
        assert tuple(argv) == ('proxy-build',)
        return 'c' * 64

    def execute(self, identity, timeout, interrupted):
        assert identity == 'c' * 64
        return CommandResult(0, json.dumps(self.claim), '', False)

    def remove(self, kind, identity, labels):
        assert (kind, identity) == ('container', 'c' * 64)
        self.removed.append((kind, identity))


def test_h6_build_observation_shape_with_fake_engine(tmp_path, monkeypatch):
    selection = derivative_module.load_parent_selection()
    pinned = {'LICENSE-APACHE': b'pinned-apache-bytes', 'LICENSE-MIT': b'pinned-mit-bytes'}
    monkeypatch.setitem(derivative_module.DERIVATIVE_NOTICES, 'LICENSE-APACHE',
                        hashlib.sha256(pinned['LICENSE-APACHE']).hexdigest())
    monkeypatch.setitem(derivative_module.DERIVATIVE_NOTICES, 'LICENSE-MIT',
                        hashlib.sha256(pinned['LICENSE-MIT']).hexdigest())
    record_d, _, _, _, _, _ = selected_pair()
    claim = daemon_claim(record_d)
    child_layers = selection['layers'] + EXTRA_LAYERS
    engine = ShapeEngine(selection, child_layers, claim)
    # Pre-render the seal the Dockerfile gate requires (independent copy).
    rendered = derivative_module.render_derivative_build_context(
        products=invented_products(tmp_path / 'products'), notices=pinned,
        dest=tmp_path / 'seal')
    observation = derivative_module.build_proxy_derivative(
        parent_ref=selection['local_engine_id'],
        products=invented_products(tmp_path / 'products'), notices=pinned,
        build_args={'PROXY_BINS_MANIFEST_SHA256': rendered['proxy_bins_sha256'],
                    'PROXY_SOURCE_REVISION': record_d['source_commit'],
                    'PROXY_CARGO_LOCK_SHA256': record_d['cargo_lock_sha256']},
        output=tmp_path / 'out', engine=engine)
    assert set(observation) == {'parent_inspection', 'child_inspection', 'base_ref',
                                'config_digest', 'manifest_digest_or_absence', 'diff_ids',
                                'build_json_bytes', 'cleanup'}
    assert observation['base_ref'] == selection['local_engine_id']
    assert observation['config_digest'] == selection['config_digest']
    assert observation['manifest_digest_or_absence']['corroborated'] is True
    assert observation['diff_ids'] == child_layers
    assert json.loads(bytes(observation['build_json_bytes']).decode()) == claim
    assert observation['cleanup']['child_absence_verified'] is True
    assert '--network=none' in engine.build_argv and '--pull=false' in engine.build_argv
    assert not any(entry == '-t' or entry.startswith('--tag') for entry in engine.build_argv)
    dockerfile_arg = engine.build_argv[engine.build_argv.index('--file') + 1]
    assert dockerfile_arg == str(tmp_path / 'out' / 'context' / 'Dockerfile')
    provider_args = [entry for entry in engine.build_argv
                     if entry.startswith('PROVIDER_IMAGE=')]
    assert provider_args == ['PROVIDER_IMAGE=' + selection['repository'] + '@'
                             + selection['manifest_digest']]


class FailingBuildEngine(ShapeEngine):
    """Docker double whose single build fails (failure evidence path)."""

    def command(self, args, timeout=15, *, check=True, **kwargs):
        if args[0] == 'build':
            self.build_argv = list(args)
            return CommandResult(1, 'fixture build failed', 'no dockerfile', False)
        return super().command(args, timeout, check=check, **kwargs)


def test_h6_failed_build_raises_with_failure_log(tmp_path, monkeypatch):
    selection = derivative_module.load_parent_selection()
    pinned = {'LICENSE-APACHE': b'pinned-apache-bytes', 'LICENSE-MIT': b'pinned-mit-bytes'}
    monkeypatch.setitem(derivative_module.DERIVATIVE_NOTICES, 'LICENSE-APACHE',
                        hashlib.sha256(pinned['LICENSE-APACHE']).hexdigest())
    monkeypatch.setitem(derivative_module.DERIVATIVE_NOTICES, 'LICENSE-MIT',
                        hashlib.sha256(pinned['LICENSE-MIT']).hexdigest())
    record_d, _, _, _, _, _ = selected_pair()
    rendered = derivative_module.render_derivative_build_context(
        products=invented_products(tmp_path / 'products'), notices=pinned,
        dest=tmp_path / 'seal')
    engine = FailingBuildEngine(selection, selection['layers'] + EXTRA_LAYERS,
                                daemon_claim(record_d))
    with pytest.raises(ValueError, match='derivative build failed'):
        derivative_module.build_proxy_derivative(
            parent_ref=selection['local_engine_id'],
            products=invented_products(tmp_path / 'products'), notices=pinned,
            build_args={'PROXY_BINS_MANIFEST_SHA256': rendered['proxy_bins_sha256'],
                        'PROXY_SOURCE_REVISION': record_d['source_commit'],
                        'PROXY_CARGO_LOCK_SHA256': record_d['cargo_lock_sha256']},
            output=tmp_path / 'out', engine=engine)
    assert 'fixture build failed' in (tmp_path / 'out' / 'build.log').read_text()
    assert engine.removed_images == []


# Fake-engine child identity minted by ShapeEngine builds (iidfile text).
CHILD_REF = 'sha256:' + 'c9' * 32


def funded_build(tmp_path, monkeypatch):
    """Sealed build inputs plus the roster selection for fake-engine builds."""
    selection = derivative_module.load_parent_selection()
    pinned = {'LICENSE-APACHE': b'pinned-apache-bytes', 'LICENSE-MIT': b'pinned-mit-bytes'}
    monkeypatch.setitem(derivative_module.DERIVATIVE_NOTICES, 'LICENSE-APACHE',
                        hashlib.sha256(pinned['LICENSE-APACHE']).hexdigest())
    monkeypatch.setitem(derivative_module.DERIVATIVE_NOTICES, 'LICENSE-MIT',
                        hashlib.sha256(pinned['LICENSE-MIT']).hexdigest())
    record_d, _, _, _, _, _ = selected_pair()
    rendered = derivative_module.render_derivative_build_context(
        products=invented_products(tmp_path / 'products'), notices=pinned,
        dest=tmp_path / 'seal')
    return {'selection': selection, 'record': record_d, 'notices': pinned,
            'build_args': {'PROXY_BINS_MANIFEST_SHA256': rendered['proxy_bins_sha256'],
                           'PROXY_SOURCE_REVISION': record_d['source_commit'],
                           'PROXY_CARGO_LOCK_SHA256': record_d['cargo_lock_sha256']}}


def run_funded_build(funded, tmp_path, engine):
    """Run build_proxy_derivative over sealed inputs with a fake engine."""
    selection = funded['selection']
    return derivative_module.build_proxy_derivative(
        parent_ref=selection['local_engine_id'],
        products=invented_products(tmp_path / 'products'), notices=funded['notices'],
        build_args=funded['build_args'], output=tmp_path / 'out', engine=engine)


class RawClaimEngine(ShapeEngine):
    """Docker double returning raw proxy-build stdout (claim-shape paths)."""

    def __init__(self, selection, child_layers, stdout):
        super().__init__(selection, child_layers, None)
        self.stdout = stdout

    def execute(self, identity, timeout, interrupted):
        assert identity == 'c' * 64
        return CommandResult(0, self.stdout, '', False)


class ExplodingExecuteEngine(ShapeEngine):
    """Docker double whose proxy-build execute raises (X-2 leak path)."""

    def execute(self, identity, timeout, interrupted):
        raise ValueError('fixture execute transport failure')


class ExplodingChildImageEngine(ShapeEngine):
    """Docker double whose child inspection raises (X-2 leak path)."""

    def image(self, artifact):
        if artifact.reference != self.selection['local_engine_id']:
            raise ValueError('fixture child inspection unavailable')
        return super().image(artifact)


class ProbeEngine(ShapeEngine):
    """Docker double answering absence probes with a fixed result (X-3 gate)."""

    def __init__(self, selection, child_layers, claim, probe):
        super().__init__(selection, child_layers, claim)
        self.probe = probe

    def command(self, args, timeout=15, *, check=True, **kwargs):
        if args[:2] == ['image', 'inspect']:
            self.inspect_probes.append(args[2])
            return self.probe
        return super().command(args, timeout, check=check, **kwargs)


def test_h6_execute_exception_removes_child_image(tmp_path, monkeypatch):
    funded = funded_build(tmp_path, monkeypatch)
    selection = funded['selection']
    engine = ExplodingExecuteEngine(selection, selection['layers'] + EXTRA_LAYERS,
                                    daemon_claim(funded['record']))
    with pytest.raises(ValueError, match='fixture execute transport failure'):
        run_funded_build(funded, tmp_path, engine)
    # The encompassing failure path removes exactly the owned child and
    # re-verifies absence; the container cleanup still ran first, and the
    # root error (not a cleanup error) is what the caller sees.
    assert engine.removed == [('container', 'c' * 64)]
    assert engine.removed_images == [CHILD_REF]
    assert engine.inspect_probes == [CHILD_REF]


def test_h6_malformed_claim_json_removes_child_image(tmp_path, monkeypatch):
    funded = funded_build(tmp_path, monkeypatch)
    selection = funded['selection']
    engine = RawClaimEngine(selection, selection['layers'] + EXTRA_LAYERS, 'not-json{{{')
    with pytest.raises(ValueError, match='derivative proxy-build claim invalid'):
        run_funded_build(funded, tmp_path, engine)
    assert engine.removed == [('container', 'c' * 64)]
    assert engine.removed_images == [CHILD_REF]
    assert engine.inspect_probes == [CHILD_REF]


def test_h6_non_dict_claim_removes_child_image(tmp_path, monkeypatch):
    funded = funded_build(tmp_path, monkeypatch)
    selection = funded['selection']
    engine = RawClaimEngine(selection, selection['layers'] + EXTRA_LAYERS, '[1, 2]')
    with pytest.raises(ValueError, match='derivative proxy-build claim invalid'):
        run_funded_build(funded, tmp_path, engine)
    assert engine.removed == [('container', 'c' * 64)]
    assert engine.removed_images == [CHILD_REF]
    assert engine.inspect_probes == [CHILD_REF]


def test_h6_child_inspection_failure_removes_child_image(tmp_path, monkeypatch):
    funded = funded_build(tmp_path, monkeypatch)
    selection = funded['selection']
    engine = ExplodingChildImageEngine(selection, selection['layers'] + EXTRA_LAYERS,
                                       daemon_claim(funded['record']))
    with pytest.raises(ValueError, match='fixture child inspection unavailable'):
        run_funded_build(funded, tmp_path, engine)
    assert engine.removed == []
    assert engine.removed_images == [CHILD_REF]
    assert engine.inspect_probes == [CHILD_REF]


def test_h6_child_verify_failure_removes_child_image(tmp_path, monkeypatch):
    funded = funded_build(tmp_path, monkeypatch)
    selection = funded['selection']
    engine = ShapeEngine(selection, WRONG_LAYERS + EXTRA_LAYERS,
                         daemon_claim(funded['record']))
    with pytest.raises(ValueError, match=r'child\.RootFS\.Layers'):
        run_funded_build(funded, tmp_path, engine)
    assert engine.removed == []
    assert engine.removed_images == [CHILD_REF]
    assert engine.inspect_probes == [CHILD_REF]


def test_h6_daemon_error_probe_leaves_cleanup_incomplete(tmp_path, monkeypatch):
    funded = funded_build(tmp_path, monkeypatch)
    selection = funded['selection']
    probe = CommandResult(1, '', 'Cannot connect to the Docker daemon: fixture', False)
    engine = ProbeEngine(selection, selection['layers'] + EXTRA_LAYERS,
                         daemon_claim(funded['record']), probe)
    with pytest.raises(ValueError, match='derivative child image cleanup incomplete'):
        run_funded_build(funded, tmp_path, engine)
    # Removal was still attempted (no leak by skip); only the absence gate
    # stays incomplete because a daemon error is not absence confirmation.
    assert engine.removed_images == [CHILD_REF]
    assert engine.inspect_probes == [CHILD_REF]


def test_h6_present_image_probe_leaves_cleanup_incomplete(tmp_path, monkeypatch):
    funded = funded_build(tmp_path, monkeypatch)
    selection = funded['selection']
    probe = CommandResult(0, '{}', '', False)
    engine = ProbeEngine(selection, selection['layers'] + EXTRA_LAYERS,
                         daemon_claim(funded['record']), probe)
    with pytest.raises(ValueError, match='derivative child image cleanup incomplete'):
        run_funded_build(funded, tmp_path, engine)
    assert engine.removed_images == [CHILD_REF]
    assert engine.inspect_probes == [CHILD_REF]


def test_h6_timed_out_probe_leaves_cleanup_incomplete(tmp_path, monkeypatch):
    funded = funded_build(tmp_path, monkeypatch)
    selection = funded['selection']
    probe = CommandResult(1, '', 'fixture context deadline exceeded', True)
    engine = ProbeEngine(selection, selection['layers'] + EXTRA_LAYERS,
                         daemon_claim(funded['record']), probe)
    with pytest.raises(ValueError, match='derivative child image cleanup incomplete'):
        run_funded_build(funded, tmp_path, engine)
    assert engine.removed_images == [CHILD_REF]
    assert engine.inspect_probes == [CHILD_REF]


def test_h6_daemon_style_absence_probe_verifies_cleanup(tmp_path, monkeypatch):
    funded = funded_build(tmp_path, monkeypatch)
    selection = funded['selection']
    probe = CommandResult(1, '', 'Error response from daemon: No such image: ' + CHILD_REF,
                           False)
    engine = ProbeEngine(selection, selection['layers'] + EXTRA_LAYERS,
                         daemon_claim(funded['record']), probe)
    observation = run_funded_build(funded, tmp_path, engine)
    assert observation['cleanup']['child_image_removed'] is True
    assert observation['cleanup']['child_absence_verified'] is True
    assert observation['cleanup']['child_absence_error'] is None


# Fix-3 (codex round-2 residuals X-2r/X-3r): hermetic fake-engine ONLY.
# Every test below was RED on fix-3-base bytes except the two fail-closed
# locks, which are GREEN on base by construction (base consumes no
# recovered resources at all, so "untouched" already holds there).

RECOVERED_CONTAINER = 'd' * 64


class RecoveredContainerEngine(ShapeEngine):
    """Docker double whose create fails after recovering an owned container.

    Raises the typed DockerError contract (resource=('container', id)),
    mirroring Docker._creation_failure, instead of a bare ValueError.
    """

    def __init__(self, selection, child_layers, claim):
        super().__init__(selection, child_layers, claim)
        self.calls = []

    def command(self, args, timeout=15, *, check=True, **kwargs):
        self.calls.append(('command', args[0], args[1] if len(args) > 1 else ''))
        return super().command(args, timeout=timeout, check=check, **kwargs)

    def create(self, image, argv, options, labels, name):
        raise DockerError('Docker resource creation failed',
                          resource=('container', RECOVERED_CONTAINER))

    def remove(self, kind, identity, labels):
        self.calls.append(('remove', kind, identity))
        assert (kind, identity) == ('container', RECOVERED_CONTAINER)
        self.removed.append((kind, identity))


def test_h6_create_resource_removes_recovered_container_first(tmp_path, monkeypatch):
    funded = funded_build(tmp_path, monkeypatch)
    selection = funded['selection']
    engine = RecoveredContainerEngine(selection, selection['layers'] + EXTRA_LAYERS,
                                      daemon_claim(funded['record']))
    with pytest.raises(DockerError, match='Docker resource creation failed'):
        run_funded_build(funded, tmp_path, engine)
    # The recovered owned container goes first (it can pin the child image),
    # then exactly the owned child image plus the absence probe; the outcome
    # is retained for the caller.
    assert engine.removed == [('container', RECOVERED_CONTAINER)]
    assert engine.removed_images == [CHILD_REF]
    assert engine.inspect_probes == [CHILD_REF]
    assert engine.calls.index(('remove', 'container', RECOVERED_CONTAINER)) < engine.calls.index(
        ('command', 'image', 'rm')) < engine.calls.index(('command', 'image', 'inspect'))
    record = json.loads((tmp_path / 'out' / 'build-cleanup.json').read_text())
    assert record['cleanup']['build_container_removed'] is True
    assert record['cleanup']['child_image_removed'] is True


class FailingRecoveredRemoveEngine(RecoveredContainerEngine):
    """Docker double whose recovered-container removal itself fails."""

    def remove(self, kind, identity, labels):
        self.calls.append(('remove', kind, identity))
        raise ValueError('fixture recovered rm failed')


def test_h6_create_resource_removal_failure_retained_without_masking(tmp_path, monkeypatch):
    funded = funded_build(tmp_path, monkeypatch)
    selection = funded['selection']
    engine = FailingRecoveredRemoveEngine(selection, selection['layers'] + EXTRA_LAYERS,
                                          daemon_claim(funded['record']))
    with pytest.raises(DockerError, match='Docker resource creation failed'):
        run_funded_build(funded, tmp_path, engine)
    # The removal failure is retained but never masks the root error, and
    # image cleanup still runs.
    assert engine.removed_images == [CHILD_REF]
    assert engine.inspect_probes == [CHILD_REF]
    record = json.loads((tmp_path / 'out' / 'build-cleanup.json').read_text())
    assert record['cleanup']['build_container_removed'] is False
    assert 'fixture recovered rm failed' in record['cleanup']['build_container_error']


class ParsingErrorRecoveredRemoveEngine(RecoveredContainerEngine):
    """Docker double whose recovered-container removal misparses a response."""

    def remove(self, kind, identity, labels):
        self.calls.append(('remove', kind, identity))
        raise KeyError('Config')


def test_h6_create_resource_removal_parsing_error_retained_without_masking(tmp_path, monkeypatch):
    funded = funded_build(tmp_path, monkeypatch)
    selection = funded['selection']
    engine = ParsingErrorRecoveredRemoveEngine(selection, selection['layers'] + EXTRA_LAYERS,
                                               daemon_claim(funded['record']))
    with pytest.raises(DockerError, match='Docker resource creation failed'):
        run_funded_build(funded, tmp_path, engine)
    # A parsing-shaped removal failure is retained like any removal failure:
    # the root error still propagates and image cleanup still runs.
    assert engine.removed_images == [CHILD_REF]
    assert engine.inspect_probes == [CHILD_REF]
    record = json.loads((tmp_path / 'out' / 'build-cleanup.json').read_text())
    assert record['cleanup']['build_container_removed'] is False
    assert 'recovered container rm raised KeyError' in record['cleanup']['build_container_error']


class UncertainResourceEngine(RecoveredContainerEngine):
    """Docker double whose create failure carries only an uncertain name."""

    def create(self, image, argv, options, labels, name):
        raise DockerError('Docker resource creation failed',
                          uncertain_resource=('container', name))

    def remove(self, kind, identity, labels):
        raise AssertionError('must not remove by unverified name')


def test_h6_create_uncertain_resource_left_untouched(tmp_path, monkeypatch):
    # LOCK (GREEN on base): base consumes nothing, so this already holds.
    # The fix must not overreach into unverified-name deletion.
    funded = funded_build(tmp_path, monkeypatch)
    selection = funded['selection']
    engine = UncertainResourceEngine(selection, selection['layers'] + EXTRA_LAYERS,
                                     daemon_claim(funded['record']))
    with pytest.raises(DockerError, match='Docker resource creation failed'):
        run_funded_build(funded, tmp_path, engine)
    assert engine.removed == []
    assert engine.removed_images == [CHILD_REF]
    assert engine.inspect_probes == [CHILD_REF]


class WrongKindResourceEngine(RecoveredContainerEngine):
    """Docker double whose create failure carries a non-container resource."""

    def create(self, image, argv, options, labels, name):
        raise DockerError('Docker resource creation failed',
                          resource=('volume', 'fixture-volume'))

    def remove(self, kind, identity, labels):
        raise AssertionError('must not consume non-container resources')


def test_h6_create_non_container_resource_left_untouched(tmp_path, monkeypatch):
    # LOCK (GREEN on base): only exact ('container', id) resources are consumed.
    funded = funded_build(tmp_path, monkeypatch)
    selection = funded['selection']
    engine = WrongKindResourceEngine(selection, selection['layers'] + EXTRA_LAYERS,
                                     daemon_claim(funded['record']))
    with pytest.raises(DockerError, match='Docker resource creation failed'):
        run_funded_build(funded, tmp_path, engine)
    assert engine.removed == []
    assert engine.removed_images == [CHILD_REF]
    assert engine.inspect_probes == [CHILD_REF]


def test_h6_build_log_write_failure_removes_child_image(tmp_path, monkeypatch):
    funded = funded_build(tmp_path, monkeypatch)
    selection = funded['selection']
    engine = ShapeEngine(selection, selection['layers'] + EXTRA_LAYERS,
                         daemon_claim(funded['record']))
    original_write_text = Path.write_text

    def guarded_write_text(self, *args, **kwargs):
        if self.name == 'build.log':
            raise OSError('fixture build.log unwritable')
        return original_write_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, 'write_text', guarded_write_text)
    with pytest.raises(OSError, match='fixture build.log unwritable'):
        run_funded_build(funded, tmp_path, engine)
    # A valid iidfile already exists, so the child image must still be
    # removed with absence re-verified, and the outcome recorded.
    assert engine.removed_images == [CHILD_REF]
    assert engine.inspect_probes == [CHILD_REF]
    record = json.loads((tmp_path / 'out' / 'build-cleanup.json').read_text())
    assert record['cleanup']['child_image_removed'] is True
    assert record['cleanup']['child_absence_verified'] is True


class MalformedInspectionEngine(ShapeEngine):
    """Docker double whose child inspection raises a parsing-shaped error."""

    def __init__(self, selection, child_layers, claim, failure):
        super().__init__(selection, child_layers, claim)
        self.failure = failure

    def image(self, artifact):
        if artifact.reference != self.selection['local_engine_id']:
            raise self.failure
        return super().image(artifact)


def _run_malformed_inspection(tmp_path, monkeypatch, failure):
    funded = funded_build(tmp_path, monkeypatch)
    selection = funded['selection']
    engine = MalformedInspectionEngine(selection, selection['layers'] + EXTRA_LAYERS,
                                       daemon_claim(funded['record']), failure)
    with pytest.raises(type(failure)):
        run_funded_build(funded, tmp_path, engine)
    assert engine.removed == []
    assert engine.removed_images == [CHILD_REF]
    assert engine.inspect_probes == [CHILD_REF]
    record = json.loads((tmp_path / 'out' / 'build-cleanup.json').read_text())
    assert record['cleanup']['child_image_removed'] is True
    return record


def test_h6_malformed_child_inspection_key_error_removes_child_image(tmp_path, monkeypatch):
    record = _run_malformed_inspection(tmp_path, monkeypatch, KeyError('RootFS'))
    assert record['error'] == "KeyError: 'RootFS'"


def test_h6_malformed_child_inspection_type_error_removes_child_image(tmp_path, monkeypatch):
    record = _run_malformed_inspection(tmp_path, monkeypatch,
                                       TypeError('fixture inspection not a dict'))
    assert record['error'] == 'TypeError: fixture inspection not a dict'


def test_h6_malformed_child_inspection_index_error_removes_child_image(tmp_path, monkeypatch):
    record = _run_malformed_inspection(tmp_path, monkeypatch,
                                       IndexError('fixture inspection list empty'))
    assert record['error'] == 'IndexError: fixture inspection list empty'


class ExecuteExplodingProbeEngine(ProbeEngine):
    """Docker double combining an execute failure with a fixed absence probe."""

    def execute(self, identity, timeout, interrupted):
        raise ValueError('fixture execute transport failure')


def test_h6_execute_failure_records_cleanup_outcome(tmp_path, monkeypatch):
    funded = funded_build(tmp_path, monkeypatch)
    selection = funded['selection']
    probe = CommandResult(1, '', 'Cannot connect to the Docker daemon: fixture', False)
    engine = ExecuteExplodingProbeEngine(selection, selection['layers'] + EXTRA_LAYERS,
                                         daemon_claim(funded['record']), probe)
    with pytest.raises(ValueError, match='fixture execute transport failure'):
        run_funded_build(funded, tmp_path, engine)
    # A caller catching the failure reads the exact populated outcome:
    # verified flags plus retained errors.
    record = json.loads((tmp_path / 'out' / 'build-cleanup.json').read_text())
    assert record['error'] == 'ValueError: fixture execute transport failure'
    assert record['cleanup']['build_container_removed'] is True
    assert record['cleanup']['child_image_removed'] is True
    assert record['cleanup']['child_absence_verified'] is False
    assert 'Cannot connect to the Docker daemon: fixture' in record['cleanup']['child_absence_error']


def test_h6_cleanup_incomplete_records_cleanup_outcome(tmp_path, monkeypatch):
    funded = funded_build(tmp_path, monkeypatch)
    selection = funded['selection']
    probe = CommandResult(1, '', 'Cannot connect to the Docker daemon: fixture', False)
    engine = ProbeEngine(selection, selection['layers'] + EXTRA_LAYERS,
                         daemon_claim(funded['record']), probe)
    with pytest.raises(ValueError, match='derivative child image cleanup incomplete'):
        run_funded_build(funded, tmp_path, engine)
    record = json.loads((tmp_path / 'out' / 'build-cleanup.json').read_text())
    assert record['error'] == 'ValueError: derivative child image cleanup incomplete'
    assert record['cleanup']['build_container_removed'] is True
    assert record['cleanup']['child_image_removed'] is True
    assert record['cleanup']['child_absence_verified'] is False
    assert 'Cannot connect to the Docker daemon: fixture' in record['cleanup']['child_absence_error']


def test_h6_failed_build_records_cleanup_outcome(tmp_path, monkeypatch):
    funded = funded_build(tmp_path, monkeypatch)
    selection = funded['selection']
    engine = FailingBuildEngine(selection, selection['layers'] + EXTRA_LAYERS,
                                daemon_claim(funded['record']))
    with pytest.raises(ValueError, match='derivative build failed'):
        run_funded_build(funded, tmp_path, engine)
    # No iidfile exists, so nothing is removed — but the (empty) outcome is
    # still available to the caller.
    assert engine.removed_images == []
    record = json.loads((tmp_path / 'out' / 'build-cleanup.json').read_text())
    assert record['error'] == 'ValueError: derivative build failed (see build.log)'
    assert record['cleanup'] == {'build_container_removed': False, 'build_container_error': None,
                                 'child_image_removed': False, 'child_absence_verified': False,
                                 'child_absence_error': None}


class NoIidfileEngine(ShapeEngine):
    """Docker double whose successful build writes no iidfile."""

    def command(self, args, timeout=15, *, check=True, **kwargs):
        if args[0] == 'build':
            self.build_argv = list(args)
            return CommandResult(0, 'fixture build ok', '', False)
        return super().command(args, timeout=timeout, check=check, **kwargs)


def test_h6_missing_iidfile_records_cleanup_outcome(tmp_path, monkeypatch):
    funded = funded_build(tmp_path, monkeypatch)
    selection = funded['selection']
    engine = NoIidfileEngine(selection, selection['layers'] + EXTRA_LAYERS,
                             daemon_claim(funded['record']))
    with pytest.raises(FileNotFoundError):
        run_funded_build(funded, tmp_path, engine)
    assert engine.removed_images == []
    record = json.loads((tmp_path / 'out' / 'build-cleanup.json').read_text())
    assert record['cleanup'] == {'build_container_removed': False, 'build_container_error': None,
                                 'child_image_removed': False, 'child_absence_verified': False,
                                 'child_absence_error': None}


def test_h6_observation_write_failure_records_cleanup_outcome(tmp_path, monkeypatch):
    funded = funded_build(tmp_path, monkeypatch)
    selection = funded['selection']
    engine = ShapeEngine(selection, selection['layers'] + EXTRA_LAYERS,
                         daemon_claim(funded['record']))
    original_write_text = Path.write_text

    def guarded_write_text(self, *args, **kwargs):
        if self.name == 'build-observation.json':
            raise OSError('fixture observation unwritable')
        return original_write_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, 'write_text', guarded_write_text)
    with pytest.raises(OSError, match='fixture observation unwritable'):
        run_funded_build(funded, tmp_path, engine)
    # Cleanup already verified before the observation write failed; the
    # recorded outcome preserves exactly that verified state.
    record = json.loads((tmp_path / 'out' / 'build-cleanup.json').read_text())
    assert record['cleanup']['build_container_removed'] is True
    assert record['cleanup']['child_image_removed'] is True
    assert record['cleanup']['child_absence_verified'] is True
    assert record['cleanup']['child_absence_error'] is None


def test_h6_misleading_connection_probe_leaves_cleanup_incomplete(tmp_path, monkeypatch):
    funded = funded_build(tmp_path, monkeypatch)
    selection = funded['selection']
    # Codex round-2 verbatim counterexample: a connection failure whose
    # socket path happens to contain the marker text.
    probe = CommandResult(1, '',
                           'Cannot connect to the Docker daemon at '
                           'unix:///tmp/no such image.sock', False)
    engine = ProbeEngine(selection, selection['layers'] + EXTRA_LAYERS,
                         daemon_claim(funded['record']), probe)
    with pytest.raises(ValueError, match='derivative child image cleanup incomplete'):
        run_funded_build(funded, tmp_path, engine)
    assert engine.removed_images == [CHILD_REF]
    assert engine.inspect_probes == [CHILD_REF]


def test_h6_truncated_stderr_absence_probe_leaves_cleanup_incomplete(tmp_path, monkeypatch):
    funded = funded_build(tmp_path, monkeypatch)
    selection = funded['selection']
    probe = CommandResult(1, '', 'Error response from daemon: No such image: ' + CHILD_REF,
                           False, False, True)
    engine = ProbeEngine(selection, selection['layers'] + EXTRA_LAYERS,
                         daemon_claim(funded['record']), probe)
    with pytest.raises(ValueError, match='derivative child image cleanup incomplete'):
        run_funded_build(funded, tmp_path, engine)


def test_h6_truncated_stdout_absence_probe_leaves_cleanup_incomplete(tmp_path, monkeypatch):
    funded = funded_build(tmp_path, monkeypatch)
    selection = funded['selection']
    probe = CommandResult(1, 'Error response from daemon: No such image: ' + CHILD_REF, '',
                           False, True, False)
    engine = ProbeEngine(selection, selection['layers'] + EXTRA_LAYERS,
                         daemon_claim(funded['record']), probe)
    with pytest.raises(ValueError, match='derivative child image cleanup incomplete'):
        run_funded_build(funded, tmp_path, engine)


def test_h6_wrong_ref_absence_probe_leaves_cleanup_incomplete(tmp_path, monkeypatch):
    funded = funded_build(tmp_path, monkeypatch)
    selection = funded['selection']
    probe = CommandResult(1, '', 'Error response from daemon: No such image: sha256:' + 'ab' * 32,
                           False)
    engine = ProbeEngine(selection, selection['layers'] + EXTRA_LAYERS,
                         daemon_claim(funded['record']), probe)
    with pytest.raises(ValueError, match='derivative child image cleanup incomplete'):
        run_funded_build(funded, tmp_path, engine)


def test_h6_unbound_absence_marker_leaves_cleanup_incomplete(tmp_path, monkeypatch):
    funded = funded_build(tmp_path, monkeypatch)
    selection = funded['selection']
    # The bare marker without the requested child ref must not confirm.
    probe = CommandResult(1, '', 'no such image', False)
    engine = ProbeEngine(selection, selection['layers'] + EXTRA_LAYERS,
                         daemon_claim(funded['record']), probe)
    with pytest.raises(ValueError, match='derivative child image cleanup incomplete'):
        run_funded_build(funded, tmp_path, engine)


class FailingRmProbeEngine(ProbeEngine):
    """Docker double whose image removal fails before a genuine absence probe."""

    def command(self, args, timeout=15, *, check=True, **kwargs):
        if args[:2] == ['image', 'rm']:
            self.removed_images.append(args[2])
            return CommandResult(1, '', 'Error: fixture rm failed', False)
        return super().command(args, timeout=timeout, check=check, **kwargs)


def test_h6_removal_failure_with_genuine_absence_retains_diagnostic(tmp_path, monkeypatch):
    funded = funded_build(tmp_path, monkeypatch)
    selection = funded['selection']
    probe = CommandResult(1, '', 'Error response from daemon: No such image: ' + CHILD_REF,
                           False)
    engine = FailingRmProbeEngine(selection, selection['layers'] + EXTRA_LAYERS,
                                  daemon_claim(funded['record']), probe)
    observation = run_funded_build(funded, tmp_path, engine)
    # Absence-verified and removal-error-retained are compatible facts.
    assert observation['cleanup']['child_absence_verified'] is True
    assert observation['cleanup']['child_absence_error'] is not None
    assert 'image rm' in observation['cleanup']['child_absence_error']
    assert 'fixture rm failed' in observation['cleanup']['child_absence_error']


# Fix-4 (codex round-3 residuals Y-1/Y-2/Y-3): hermetic fake-engine ONLY.
# Every test below was RED on fix-4-base bytes except the trailing-newline
# lock, which is GREEN on base by construction (base substring matching
# already accepts the genuine response with its CLI newline).


def test_h6_both_record_writes_fail_outcome_readable_from_exception(tmp_path, monkeypatch):
    funded = funded_build(tmp_path, monkeypatch)
    selection = funded['selection']
    engine = ShapeEngine(selection, selection['layers'] + EXTRA_LAYERS,
                         daemon_claim(funded['record']))
    original_write_text = Path.write_text

    def guarded_write_text(self, *args, **kwargs):
        if self.name in ('build.log', 'build-cleanup.json'):
            raise OSError('fixture record unwritable: ' + self.name)
        return original_write_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, 'write_text', guarded_write_text)
    with pytest.raises(OSError, match='fixture record unwritable: build.log') as excinfo:
        run_funded_build(funded, tmp_path, engine)
    # Both record writes failed, yet cleanup ran: the child image is gone
    # with absence re-verified, and the populated outcome stays readable
    # from the propagated exception itself.
    assert engine.removed_images == [CHILD_REF]
    assert engine.inspect_probes == [CHILD_REF]
    assert not (tmp_path / 'out' / 'build-cleanup.json').exists()
    outcome = excinfo.value.proxy_derivative_cleanup
    assert outcome['error'] == 'OSError: fixture record unwritable: build.log'
    assert outcome['cleanup']['child_image_removed'] is True
    assert outcome['cleanup']['child_absence_verified'] is True
    assert outcome['cleanup']['child_absence_error'] is None


class RaisingBuildEngine(ShapeEngine):
    """Docker double whose build writes a valid iidfile then raises (Y-1)."""

    def command(self, args, timeout=15, *, check=True, **kwargs):
        if args[0] == 'build':
            self.build_argv = list(args)
            iidfile = Path(args[args.index('--iidfile') + 1])
            iidfile.write_text(CHILD_REF + '\n')
            raise ValueError('fixture build transport failure')
        return super().command(args, timeout=timeout, check=check, **kwargs)


def test_h6_build_command_raise_with_valid_iidfile_removes_child_image(tmp_path, monkeypatch):
    funded = funded_build(tmp_path, monkeypatch)
    selection = funded['selection']
    engine = RaisingBuildEngine(selection, selection['layers'] + EXTRA_LAYERS,
                                daemon_claim(funded['record']))
    with pytest.raises(ValueError, match='fixture build transport failure') as excinfo:
        run_funded_build(funded, tmp_path, engine)
    # The effectful build already created the child, so the guarded failure
    # path removes it, re-verifies absence, and records the outcome both on
    # disk and on the propagated exception.
    assert engine.removed_images == [CHILD_REF]
    assert engine.inspect_probes == [CHILD_REF]
    record = json.loads((tmp_path / 'out' / 'build-cleanup.json').read_text())
    assert record['cleanup']['child_image_removed'] is True
    assert record['cleanup']['child_absence_verified'] is True
    assert excinfo.value.proxy_derivative_cleanup['cleanup']['child_absence_verified'] is True


def test_h6_dash_other_ref_probe_leaves_cleanup_incomplete(tmp_path, monkeypatch):
    funded = funded_build(tmp_path, monkeypatch)
    selection = funded['selection']
    # Codex round-3 verbatim counterexample: the probe names a different
    # reference (the requested ref plus a suffix), not the complete child.
    probe = CommandResult(1, '', 'Error response from daemon: No such image: '
                           + CHILD_REF + '-other', False)
    engine = ProbeEngine(selection, selection['layers'] + EXTRA_LAYERS,
                         daemon_claim(funded['record']), probe)
    with pytest.raises(ValueError, match='derivative child image cleanup incomplete'):
        run_funded_build(funded, tmp_path, engine)
    assert engine.removed_images == [CHILD_REF]
    assert engine.inspect_probes == [CHILD_REF]


def test_h6_embedded_absence_phrase_leaves_cleanup_incomplete(tmp_path, monkeypatch):
    funded = funded_build(tmp_path, monkeypatch)
    selection = funded['selection']
    # The recognized phrase embedded in a longer connection diagnostic is
    # not a complete absence response for the requested child.
    probe = CommandResult(1, '', 'Cannot connect to the Docker daemon at '
                           'unix:///var/run/docker.sock: last reply: Error response '
                           'from daemon: No such image: ' + CHILD_REF + ' (retrying)',
                           False)
    engine = ProbeEngine(selection, selection['layers'] + EXTRA_LAYERS,
                         daemon_claim(funded['record']), probe)
    with pytest.raises(ValueError, match='derivative child image cleanup incomplete'):
        run_funded_build(funded, tmp_path, engine)
    assert engine.removed_images == [CHILD_REF]
    assert engine.inspect_probes == [CHILD_REF]


def test_h6_lowercase_absence_probe_leaves_cleanup_incomplete(tmp_path, monkeypatch):
    funded = funded_build(tmp_path, monkeypatch)
    selection = funded['selection']
    # Only the exact enumerated daemon response shape confirms absence;
    # altered casing is an unrecognized (incomplete) response.
    probe = CommandResult(1, '', 'error response from daemon: no such image: ' + CHILD_REF,
                           False)
    engine = ProbeEngine(selection, selection['layers'] + EXTRA_LAYERS,
                         daemon_claim(funded['record']), probe)
    with pytest.raises(ValueError, match='derivative child image cleanup incomplete'):
        run_funded_build(funded, tmp_path, engine)


def test_h6_trailing_newline_absence_probe_verifies_cleanup(tmp_path, monkeypatch):
    # LOCK (GREEN on base): the daemon-facing CLI terminates the response
    # line, so surrounding whitespace cannot break verification.
    funded = funded_build(tmp_path, monkeypatch)
    selection = funded['selection']
    probe = CommandResult(1, '', 'Error response from daemon: No such image: '
                           + CHILD_REF + '\n', False)
    engine = ProbeEngine(selection, selection['layers'] + EXTRA_LAYERS,
                         daemon_claim(funded['record']), probe)
    observation = run_funded_build(funded, tmp_path, engine)
    assert observation['cleanup']['child_image_removed'] is True
    assert observation['cleanup']['child_absence_verified'] is True
    assert observation['cleanup']['child_absence_error'] is None


class AttemptDaemonEngine(ShapeEngine):
    """Docker double modelling a daemon namespace shared across attempts (Y-3).

    Mirrors Docker.create plus Docker._creation_failure plus Docker.remove
    ownership semantics over a plain dict: create fails closed with a typed
    recovery resource only when the exact name exists with every label
    matching; remove deletes only after re-verifying identity plus labels.
    """

    def __init__(self, selection, child_layers, claim, daemon, *, fail_create_cli=False,
                 fail_execute=False, fail_remove_first=False):
        super().__init__(selection, child_layers, claim)
        self.daemon = daemon
        self.fail_create_cli = fail_create_cli
        self.fail_execute = fail_execute
        self.fail_remove_first = fail_remove_first
        self.names = []
        self.container_identity = None

    def create(self, image, argv, options, labels, name):
        assert tuple(argv) == ('proxy-build',)
        self.names.append((name, dict(labels)))
        entry = self.daemon.get(name)
        if self.fail_create_cli or entry is not None:
            if (entry is not None and all(
                    entry['labels'].get(key) == value for key, value in labels.items())):
                raise DockerError('Docker resource creation failed',
                                  resource=('container', entry['identity']))
            raise DockerError('Docker resource creation failed',
                              uncertain_resource=('container', name))
        identity = hashlib.sha256(b'attempt-container:' + name.encode()).hexdigest()
        self.daemon[name] = {'identity': identity, 'labels': dict(labels)}
        self.container_identity = identity
        return identity

    def execute(self, identity, timeout, interrupted):
        assert identity == self.container_identity
        if self.fail_execute:
            raise ValueError('fixture execute transport failure')
        return CommandResult(0, json.dumps(self.claim), '', False)

    def remove(self, kind, identity, labels):
        if self.fail_remove_first:
            self.fail_remove_first = False
            raise DockerError('fixture attempt remove failed')
        for entry_name, entry in list(self.daemon.items()):
            if entry['identity'] == identity:
                if kind != 'container' or any(
                        entry['labels'].get(key) != value for key, value in labels.items()):
                    raise DockerError('refusing deletion: ownership identity/labels mismatch')
                del self.daemon[entry_name]
                self.removed.append((kind, identity))
                return
        raise DockerError('refusing deletion: ownership identity/labels mismatch')


def test_h6_cross_attempt_collision_leaves_other_attempt_untouched(tmp_path, monkeypatch):
    funded = funded_build(tmp_path, monkeypatch)
    selection = funded['selection']
    products = invented_products(tmp_path / 'products')
    daemon = {}

    def run_attempt(engine, *parts):
        return derivative_module.build_proxy_derivative(
            parent_ref=selection['local_engine_id'], products=products,
            notices=funded['notices'], build_args=funded['build_args'],
            output=tmp_path.joinpath(*parts), engine=engine)

    child_layers = selection['layers'] + EXTRA_LAYERS
    claim = daemon_claim(funded['record'])
    engine_a = AttemptDaemonEngine(selection, child_layers, claim, daemon,
                                   fail_execute=True, fail_remove_first=True)
    with pytest.raises(DockerError, match='fixture attempt remove failed'):
        run_attempt(engine_a, 'A', 'out')
    # Attempt A created its container and then crashed out of removal, so
    # the container still exists under attempt A's name and labels.
    assert len(daemon) == 1
    a_name, a_labels = engine_a.names[0]
    a_identity = engine_a.container_identity
    assert daemon[a_name]['identity'] == a_identity
    # Attempt B shares the output basename but must never collide: its
    # create fails, recovery reads back only B's own name, and A's
    # container is left untouched while B still cleans its own child image.
    engine_b = AttemptDaemonEngine(selection, child_layers, claim, daemon,
                                   fail_create_cli=True)
    with pytest.raises(DockerError, match='Docker resource creation failed'):
        run_attempt(engine_b, 'B', 'out')
    assert daemon.get(a_name, {}).get('identity') == a_identity
    b_name, b_labels = engine_b.names[0]
    assert (b_name, b_labels) != (a_name, a_labels)
    assert engine_b.removed_images == [CHILD_REF]
    assert engine_b.inspect_probes == [CHILD_REF]


# Fix-5 (codex round-4 residual Z-1): hermetic fake-engine ONLY. The two
# genuine-CLI-envelope tests were RED on fix-5-base bytes; the near-miss
# locks are GREEN on base by construction (base combined-stream matching
# already rejects any non-sentence text) and stay incomplete after the fix.


def test_h6_cli_empty_array_absence_probe_verifies_cleanup(tmp_path, monkeypatch):
    funded = funded_build(tmp_path, monkeypatch)
    selection = funded['selection']
    # Verbatim genuine Docker CLI absence envelope (ground truth, Docker
    # 29.9.1 — quoted, never re-probed): rc=1, stdout exactly `[]\n`,
    # stderr exactly the daemon sentence naming the complete ref.
    probe = CommandResult(1, '[]\n', 'Error response from daemon: No such image: '
                           + CHILD_REF + '\n', False, False, False)
    engine = ProbeEngine(selection, selection['layers'] + EXTRA_LAYERS,
                         daemon_claim(funded['record']), probe)
    observation = run_funded_build(funded, tmp_path, engine)
    assert observation['cleanup']['child_image_removed'] is True
    assert observation['cleanup']['child_absence_verified'] is True
    assert observation['cleanup']['child_absence_error'] is None
    assert engine.removed_images == [CHILD_REF]
    assert engine.inspect_probes == [CHILD_REF]


def test_h6_cli_empty_array_absence_with_rm_failure_retains_diagnostic(tmp_path, monkeypatch):
    funded = funded_build(tmp_path, monkeypatch)
    selection = funded['selection']
    probe = CommandResult(1, '[]\n', 'Error response from daemon: No such image: '
                           + CHILD_REF + '\n', False, False, False)
    engine = FailingRmProbeEngine(selection, selection['layers'] + EXTRA_LAYERS,
                                  daemon_claim(funded['record']), probe)
    observation = run_funded_build(funded, tmp_path, engine)
    # Absence-verified and removal-error-retained are compatible facts.
    assert observation['cleanup']['child_absence_verified'] is True
    assert observation['cleanup']['child_absence_error'] is not None
    assert 'image rm' in observation['cleanup']['child_absence_error']
    assert 'fixture rm failed' in observation['cleanup']['child_absence_error']


def test_h6_nonempty_stdout_absence_probe_leaves_cleanup_incomplete(tmp_path, monkeypatch):
    # LOCK (GREEN on base): a non-empty-array stdout object is not the
    # CLI's empty-result envelope, so the gate stays incomplete.
    funded = funded_build(tmp_path, monkeypatch)
    selection = funded['selection']
    probe = CommandResult(1, '[{}]', 'Error response from daemon: No such image: '
                           + CHILD_REF, False)
    engine = ProbeEngine(selection, selection['layers'] + EXTRA_LAYERS,
                         daemon_claim(funded['record']), probe)
    with pytest.raises(ValueError, match='derivative child image cleanup incomplete'):
        run_funded_build(funded, tmp_path, engine)
    assert engine.removed_images == [CHILD_REF]
    assert engine.inspect_probes == [CHILD_REF]


def test_h6_stderr_extra_line_absence_probe_leaves_cleanup_incomplete(tmp_path, monkeypatch):
    # LOCK (GREEN on base): stderr must be exactly the daemon sentence;
    # a trailing extra line leaves the gate incomplete.
    funded = funded_build(tmp_path, monkeypatch)
    selection = funded['selection']
    probe = CommandResult(1, '[]\n', 'Error response from daemon: No such image: '
                           + CHILD_REF + '\nExtra line\n', False, False, False)
    engine = ProbeEngine(selection, selection['layers'] + EXTRA_LAYERS,
                         daemon_claim(funded['record']), probe)
    with pytest.raises(ValueError, match='derivative child image cleanup incomplete'):
        run_funded_build(funded, tmp_path, engine)
    assert engine.removed_images == [CHILD_REF]
    assert engine.inspect_probes == [CHILD_REF]


def test_h7_default_path_without_evidence_is_unchanged():
    record = default_record()
    validated = proxy_inputs_module.validate_proxy_identity(merged_actual(record), None)
    assert validated['expected'] == record
    assert validated['daemon'] == daemon_claim(record)
    assert validated['client_identity'] == record
    assert validated['launch_rehashes'] == launch_rehashes(record)
    assert validated['abi_decision'] == 'conforming-recorded'
    assert validated['observed_parent'] is None
    assert run_module.check_proxy_identities(
        daemon_claim(record), client_manifest(record), expected=None,
        launch_rehashes=launch_rehashes(record),
        daemon_image=image_naming()) == daemon_claim(record)


def test_h7_default_path_records_observed_parent_without_failing():
    record = default_record()
    selection = derivative_module.load_parent_selection()
    evidence = parent_evidence(selection, selection['layers'] + EXTRA_LAYERS)
    validated = proxy_inputs_module.validate_proxy_identity(
        merged_actual(record, daemon_parent=evidence), None)
    assert validated['expected'] == record
    observed = validated['observed_parent']
    assert observed['child_layers_prefix_ok'] is True
    assert observed['manifest_digest'] == selection['manifest_digest']
    assert observed['config_digest'] == selection['config_digest']
    # Observed vs expected stay distinct: the default F28 stays all-None.
    assert validated['expected']['provider_parent'] == {
        'family': None, 'platform': None, 'manifest_digest': None, 'config_digest': None}
    assert run_module.check_proxy_identities(
        daemon_claim(record), client_manifest(record), expected=None,
        launch_rehashes=launch_rehashes(record),
        daemon_image=image_naming(parent=evidence)) == daemon_claim(record)


def test_h7_explicit_default_copy_behaves_as_default():
    record = default_record()
    selection = derivative_module.load_parent_selection()
    evidence = parent_evidence(selection, selection['layers'] + EXTRA_LAYERS)
    validated = proxy_inputs_module.validate_proxy_identity(
        merged_actual(record, daemon_parent=evidence), copy.deepcopy(record))
    assert validated['expected'] == record
    observed = validated['observed_parent']
    assert observed['child_layers_prefix_ok'] is True
    assert observed['manifest_digest'] == selection['manifest_digest']
    assert observed['config_digest'] == selection['config_digest']
    # Observed vs expected stay distinct: the explicit default copy F28 stays all-None.
    assert validated['expected']['provider_parent'] == {
        'family': None, 'platform': None, 'manifest_digest': None, 'config_digest': None}
    assert run_module.check_proxy_identities(
        daemon_claim(record), client_manifest(record), expected=copy.deepcopy(record),
        launch_rehashes=launch_rehashes(record),
        daemon_image=image_naming(parent=evidence)) == daemon_claim(record)


def roster_bound_record():
    """Authored explicit record with F28 bound to the protected roster."""
    shim, cli = fixture_bytes(b'R')
    return fixture_record(shim, cli, tag=D_TAG, provider_parent='roster'), shim, cli


def test_h8_explicit_roster_bound_record_passes_naming_check():
    record, _, _ = roster_bound_record()
    selection = derivative_module.load_parent_selection()
    evidence = parent_evidence(selection, selection['layers'] + EXTRA_LAYERS)
    validated = proxy_inputs_module.validate_proxy_identity(
        merged_actual(record, daemon_parent=evidence), record)
    assert validated['expected'] == record
    assert validated['observed_parent']['child_layers_prefix_ok'] is True
    assert run_module.check_proxy_identities(
        daemon_claim(record), client_manifest(record), expected=record,
        launch_rehashes=launch_rehashes(record),
        daemon_image=image_naming(parent=evidence)) == daemon_claim(record)


def test_h8_matched_but_unselected_parent_rejects():
    record_other, _, _, _, _, _ = selected_pair()
    selection = derivative_module.load_parent_selection()
    evidence = parent_evidence(selection, selection['layers'] + EXTRA_LAYERS)
    # Claim, manifest, rehashes, and ABI all match the expected record, but
    # the parent evidence binds the roster while the record binds elsewhere.
    with pytest.raises(ValueError, match='daemon_parent'):
        proxy_inputs_module.validate_proxy_identity(
            merged_actual(record_other, daemon_parent=evidence), record_other)
    with pytest.raises(ValueError, match='daemon_parent'):
        run_module.check_proxy_identities(
            daemon_claim(record_other), client_manifest(record_other), expected=record_other,
            launch_rehashes=launch_rehashes(record_other),
            daemon_image=image_naming(parent=evidence))


def test_h8_unselected_claim_still_rejects_with_parent_evidence():
    record_d, record_e, _, _, _, _ = selected_pair()
    selection = derivative_module.load_parent_selection()
    evidence = parent_evidence(selection, selection['layers'] + EXTRA_LAYERS)
    actual = merged_actual(record_e, daemon_parent=evidence)
    actual['daemon_build_json'] = daemon_claim(record_d)
    with pytest.raises(ValueError, match='proxy identity mismatch'):
        proxy_inputs_module.validate_proxy_identity(actual, None)


def test_h8_non_roster_family_rejects_at_selection():
    record_d, _, _, _, _, _ = selected_pair()
    evidence = parent_evidence(invented_selection(), PARENT_LAYERS + EXTRA_LAYERS)
    with pytest.raises(ValueError, match='selection unavailable'):
        proxy_inputs_module.validate_proxy_identity(
            merged_actual(record_d, daemon_parent=evidence), record_d)


def test_daemon_image_malformed_shape_names_optional_parent():
    record = default_record()
    with pytest.raises(ValueError, match='plus optional parent'):
        run_module.check_proxy_identities(
            daemon_claim(record), client_manifest(record), expected=None,
            launch_rehashes=launch_rehashes(record), daemon_image={})


class DerivativeFlowEngine:
    """Fake engine proving receipt parent fields through a full proxy flow."""

    def __init__(self, build_stdout, *, layers=None):
        self.build_stdout = build_stdout
        self.layers = None if layers is None else list(layers)
        self.created = []
        self.stopped = set()

    def image(self, artifact):
        observed = {'Id': artifact.reference, 'Os': 'linux', 'Architecture': 'amd64',
                    'Descriptor': {'digest': artifact.reference}}
        if self.layers is not None:
            observed['RootFS'] = {'Type': 'layers', 'Layers': list(self.layers)}
        return observed

    def volume(self, name, *args):
        return name

    def create(self, image, argv, options, labels, name):
        identity = 'container-%d' % len(self.created)
        self.created.append({'image': image, 'argv': tuple(argv), 'name': name})
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
        pass


class FlowInstalled:
    def __init__(self, prefix, manifest, shim_bytes, cli_bytes):
        self.artifact = CLIENT_BUNDLE
        self.prefix = prefix
        self.manifest = manifest
        self.manifest_sha256 = '1' * 64
        self.receipt_sha256 = '2' * 64
        shim = prefix / 'payload' / native_module.CLIENT_MODULE
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


def flow_spec(tmp_path, record):
    return RunSpec('softhsm2', 'release', 'proxy', DAEMON_IMAGE, 'container', CALLER_IMAGE,
                   CLIENT_BUNDLE, ('app', '--flag'), {'P11LAB_LABEL': 'P11Lab'},
                   tmp_path / 'out', tmp_path, 60, None,
                   expected_proxy_identity=ProxyBuildIdentityV1.from_dict(record))


def stub_tls_material(monkeypatch, tmp_path):
    """Hermetic TLS stand-in for full-flow tests (never touches OpenSSL).

    Mirrors the lifecycle-suite stub: fixed material paths plus a stubbed
    digest reader. TLS bytes are incidental to what the flows prove (the
    derivative-parent receipt fields), so receipt assertions stay unchanged.
    """
    material = {'server_names': [], 'openssl_version': 'fixture-no-openssl',
                'evidence': {'server': {}, 'client': {}}}
    for name in ('ca_cert', 'server_cert', 'server_key', 'client_cert', 'client_key'):
        material[name] = str(tmp_path / ('tls-stub-' + name))
    monkeypatch.setattr(tls_module, 'create_test_tls', lambda *args: material)
    monkeypatch.setattr(tls_module, 'cert_sha256', lambda *args: 'b' * 64)


def test_h8_flow_receipt_records_verified_derivative_parent(monkeypatch, tmp_path):
    record, shim, cli = roster_bound_record()
    selection = derivative_module.load_parent_selection()
    child_layers = selection['layers'] + EXTRA_LAYERS
    engine = DerivativeFlowEngine(json.dumps(daemon_claim(record)), layers=child_layers)
    monkeypatch.setattr(run_module, 'Docker', lambda: engine)
    monkeypatch.setattr(run_module, '_create_proxy_network', lambda *args: 'fixture-network')
    flow_client(monkeypatch, record, shim, cli)
    stub_tls_material(monkeypatch, tmp_path)
    result = run_module.run_application(flow_spec(tmp_path, record))
    assert result.exit_code == 0, result
    assert result.lifecycle_errors == () and result.cleanup_errors == ()
    receipt = json.loads(result.receipt_path.read_text())
    assert receipt['proxy']['derivative_parent'] == {
        'family': 'softhsm2', 'platform': 'linux/amd64',
        'manifest_digest': 'sha256:' + ROSTER_MANIFEST,
        'config_digest': 'sha256:' + ROSTER_CONFIG,
        'parent_layers': selection['layers'], 'child_layers_prefix_ok': True}


def test_h8_flow_receipt_without_layers_stays_explicit(monkeypatch, tmp_path):
    record, shim, cli = roster_bound_record()
    engine = DerivativeFlowEngine(json.dumps(daemon_claim(record)), layers=None)
    monkeypatch.setattr(run_module, 'Docker', lambda: engine)
    monkeypatch.setattr(run_module, '_create_proxy_network', lambda *args: 'fixture-network')
    flow_client(monkeypatch, record, shim, cli)
    stub_tls_material(monkeypatch, tmp_path)
    result = run_module.run_application(flow_spec(tmp_path, record))
    assert result.exit_code == 0, result
    receipt = json.loads(result.receipt_path.read_text())
    assert receipt['proxy']['derivative_parent'] == {
        'family': None, 'platform': None, 'manifest_digest': None, 'config_digest': None,
        'parent_layers': [], 'child_layers_prefix_ok': False}


def test_h8_flow_receipt_unverified_parent_stays_explicit(monkeypatch, tmp_path):
    record, shim, cli = roster_bound_record()
    engine = DerivativeFlowEngine(json.dumps(daemon_claim(record)),
                                  layers=WRONG_LAYERS + EXTRA_LAYERS)
    monkeypatch.setattr(run_module, 'Docker', lambda: engine)
    monkeypatch.setattr(run_module, '_create_proxy_network', lambda *args: 'fixture-network')
    flow_client(monkeypatch, record, shim, cli)
    stub_tls_material(monkeypatch, tmp_path)
    result = run_module.run_application(flow_spec(tmp_path, record))
    assert result.exit_code == 1
    assert result.lifecycle_errors == ('proxy identity failed',)
    receipt = json.loads(result.receipt_path.read_text())
    assert receipt['proxy']['derivative_parent'] == {
        'family': None, 'platform': None, 'manifest_digest': None, 'config_digest': None,
        'parent_layers': [], 'child_layers_prefix_ok': False}
