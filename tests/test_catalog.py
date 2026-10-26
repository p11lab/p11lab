import copy
import hashlib
import json

import pytest

from p11lab.catalog import (
    CatalogError, list_environments, load_environment, packaged_asset,
    package_data, validate_build_inputs, validate_descriptor, validate_tools,
)


EXPECTED_IDS = {
    'softhsm2', 'kryoptic', 'freehsm', 'haskoki', 'nss', 'wolfpkcs11',
    'pkcs11rs', 'opencryptoki', 'ykcs11', 'bouncyhsm', 'craton', 'cryptech',
    'corepkcs11', 'tpm2', 'opensc-pico', 'sc-hsm', 'opensc-isoapplet',
    'opensc-pivapplet', 'nethsm', 'siguldry', 'kmsp11-fakekms',
    'pkcs11-to-cmd', 'rustssm', 'softkms',
}


def _planned_spec():
    # No planned channels remain in the locked 24-provider cohort, so
    # planned-status gates graft a synthetic planned channel (the exact
    # retired stub shape) onto a locked environment instead of loading
    # a live stub.
    spec = load_environment('softhsm2', 'release')
    planned = {
        'status': 'planned',
        'source': {
            'kind': 'git',
            'url': 'https://example.org/token.git',
            'selector': {'kind': 'tag', 'value': '0.27.1'},
            'license_status': 'unreviewed',
            'revision': 'c' * 40,
            'license_observation': 'synthetic planned-channel fixture',
        },
        'pending': 'synthetic planned channel for gate tests',
    }
    spec['channels']['release'] = copy.deepcopy(planned)
    spec['channel_spec'] = copy.deepcopy(planned)
    spec.pop('lock', None)
    return spec


def test_full_cohort_has_distinct_module_and_backend_dispositions():
    entries = list_environments()
    assert {s['id'] for s in entries} == EXPECTED_IDS
    assert len(entries) == 24
    for spec in entries:
        validate_descriptor(spec)
        assert spec['module_implementation']['name']
        assert spec['backend']['name']
        expected_admission = 'blocked' if spec['id'] in ('cryptech', 'nethsm', 'siguldry', 'kmsp11-fakekms', 'softkms', 'tpm2', 'ykcs11', 'opensc-pico', 'sc-hsm', 'opensc-isoapplet', 'opensc-pivapplet') else 'unreviewed'
        assert spec['distribution']['status'] == expected_admission
        assert set(spec['channels']) == {'release', 'rolling'}
    by_id = {s['id']: s for s in entries}
    assert by_id['opensc-pico']['module_implementation'] == by_id['opensc-isoapplet']['module_implementation']
    assert by_id['sc-hsm']['module_implementation'] != by_id['opensc-pico']['module_implementation']
    assert by_id['kmsp11-fakekms']['backend']['simulated'] is True
    assert by_id['corepkcs11']['state_mode'] == 'process-local'
    assert 'windows/amd64' in by_id['bouncyhsm']['runtime_platforms']


def test_planned_entries_can_be_described_but_not_built():
    spec = _planned_spec()
    validate_descriptor(spec)
    assert spec['channel_spec']['status'] == 'planned'
    assert 'lock' not in spec
    assert 'lock' not in spec['channel_spec']
    assert 'recipe' not in spec['channel_spec']
    with pytest.raises(CatalogError, match='locked'):
        validate_build_inputs(spec)


@pytest.mark.parametrize('environment', ['pkcs11rs'])
def test_absent_release_tags_report_unavailable_reason(environment):
    spec = load_environment(environment, 'release')
    assert spec['channel_spec']['status'] == 'unavailable'
    assert 'tag' in spec['channel_spec']['reason']
    with pytest.raises(CatalogError, match='locked'):
        validate_build_inputs(spec)


def test_unknown_channel_and_environment_are_errors():
    with pytest.raises(CatalogError, match='channel'):
        load_environment('softhsm2', 'typo')
    with pytest.raises(CatalogError, match='environment'):
        load_environment('../softhsm2', 'release')


def test_invalid_full_source_revision_is_rejected():
    spec = _planned_spec()
    spec['channels']['release']['source']['revision'] = '13e6e86'
    with pytest.raises(CatalogError, match='revision'):
        validate_descriptor(spec)


def test_license_status_is_required_even_for_unreviewed_source():
    spec = _planned_spec()
    del spec['channels']['release']['source']['license_status']
    with pytest.raises(CatalogError, match='license_status'):
        validate_descriptor(spec)


def test_descriptor_cannot_grant_distribution_permission():
    spec = load_environment('tpm2', 'release')
    spec['distribution'] = {'status': 'eligible'}
    with pytest.raises(CatalogError, match='digest-bound'):
        validate_descriptor(spec)


@pytest.mark.parametrize('path', ['../tools.json', '/tmp/provider.json', 'a/../../tools.json', r'..\tools.json'])
def test_packaged_asset_rejects_escape(path):
    with pytest.raises(CatalogError, match='relative'):
        packaged_asset('softhsm2', path)


@pytest.fixture
def locked_environment(tmp_path):
    # pivapplet is locked with no native targets, so the tmp asset root
    # only shadows the grafted release lock (a native-target base would
    # fail its own native lock assets under the override).
    spec = load_environment('opensc-pivapplet', 'release')
    assets = []
    for role, path, content in [('recipe', 'Dockerfile', b'FROM scratch\n'), ('adapter', 'adapter.sh', b'#!/bin/sh\n')]:
        (tmp_path / path).write_bytes(content)
        assets.append({'role': role, 'path': path, 'sha256': hashlib.sha256(content).hexdigest()})
    lock = {
        'schema_version': 1,
        'sources': [{'kind': 'git', 'url': 'https://example.org/token.git', 'revision': 'a' * 40, 'license_status': 'unreviewed'}],
        'dependencies': [], 'patches': [],
        'base_images': ['example.org/base@sha256:' + 'b' * 64],
        'packages': [], 'toolchain': [], 'features': {}, 'assets': assets,
    }
    (tmp_path / 'release.lock.json').write_text(json.dumps(lock))
    spec['channels']['release'] = {'status': 'locked', 'lock': 'release.lock.json'}
    # Only the release lock is under test; the tmp asset root cannot serve
    # the real rolling lock, so park rolling as unavailable scaffolding.
    spec['channels']['rolling'] = {'status': 'unavailable', 'reason': 'synthetic fixture: only the release lock is under test'}
    spec['channel_spec'] = copy.deepcopy(spec['channels']['release'])
    spec['lock'] = lock
    return spec, tmp_path


def test_locked_build_requires_real_verified_assets(locked_environment):
    spec, root = locked_environment
    validate_descriptor(spec, asset_root=root)
    validate_build_inputs(spec, asset_root=root)
    (root / 'adapter.sh').unlink()
    with pytest.raises(CatalogError, match='asset'):
        validate_build_inputs(spec, asset_root=root)


def test_locked_asset_content_mismatch_fails(locked_environment):
    spec, root = locked_environment
    (root / 'Dockerfile').write_text('changed')
    with pytest.raises(CatalogError, match='sha256'):
        validate_build_inputs(spec, asset_root=root)


def test_locked_paths_cannot_escape_provider_root(locked_environment):
    spec, root = locked_environment
    spec['channels']['release']['lock'] = '../release.lock.json'
    with pytest.raises(CatalogError, match='relative'):
        validate_descriptor(spec, asset_root=root)


def test_symlink_asset_cannot_escape_provider_root(locked_environment):
    spec, root = locked_environment
    outside = root.parent / 'outside-adapter.sh'
    outside.write_text('#!/bin/sh\n')
    (root / 'adapter.sh').unlink()
    (root / 'adapter.sh').symlink_to(outside)
    with pytest.raises(CatalogError, match='escape'):
        validate_build_inputs(spec, asset_root=root)


def test_opensc_pivapplet_rolling_tracks_master_branch():
    spec = load_environment('opensc-pivapplet', 'rolling')
    assert spec['channel_spec']['status'] == 'locked'
    source = spec['lock']['sources'][0]
    assert source['id'] == 'opensc'
    assert source['selector'] == {'kind': 'branch', 'value': 'master'}
    assert len(source['revision']) == 40


def test_tools_reject_truncated_commit_pins():
    tools = json.loads(package_data('tools.json').read_text())
    tools['tools']['checker']['source']['revision'] = 'de4db3d'
    with pytest.raises(CatalogError, match='revision'):
        validate_tools(tools)


def test_tools_require_explicit_artifact_disposition():
    tools = json.loads(package_data('tools.json').read_text())
    del tools['tools']['proxy']['status']
    with pytest.raises(CatalogError, match='status'):
        validate_tools(tools)


@pytest.mark.parametrize('field', [
    ('channels', 'release', 'source', 'license_status'),
    ('channels', 'release', 'source', 'kind'),
    ('channels', 'release', 'source', 'selector', 'kind'),
    ('state_mode',),
    ('distribution', 'status'),
])
@pytest.mark.parametrize('malformed', [[], {}])
def test_malformed_descriptor_enums_raise_catalog_error(field, malformed):
    spec = _planned_spec()
    parent = spec
    for key in field[:-1]:
        parent = parent[key]
    parent[field[-1]] = malformed
    with pytest.raises(CatalogError):
        validate_descriptor(spec)


def test_malformed_consumer_license_status_raises_catalog_error():
    tools = json.loads(package_data('tools.json').read_text())
    tools['tools']['consumer']['license_status'] = []
    with pytest.raises(CatalogError, match='license_status'):
        validate_tools(tools)


def test_malformed_patch_license_status_raises_catalog_error(locked_environment):
    spec, root = locked_environment
    spec['lock']['patches'] = [{'license_status': []}]
    (root / 'release.lock.json').write_text(json.dumps(spec['lock']))
    with pytest.raises(CatalogError, match='license_status'):
        validate_descriptor(spec, asset_root=root)


def _spec_with_runtime_env(entries, token_stores=None):
    spec = load_environment('tpm2', 'release')
    spec['runtime_env'] = entries
    if token_stores is not None:
        spec['runtime_env_token_stores'] = token_stores
    return spec


def test_runtime_env_is_optional():
    spec = load_environment('sc-hsm', 'release')
    assert 'runtime_env' not in spec
    validate_descriptor(spec)


def test_runtime_env_accepts_fixed_nonsecret_entries():
    spec = _spec_with_runtime_env([
        {'name': 'FHSM_TOKENS_DIR', 'value': '/var/lib/p11lab/freehsm'},
        {'name': 'FHSM_INTEGRITY_ALLOW_UNSIGNED', 'value': '1'},
        {'name': 'FHSM_KAT_ALLOW_FAIL', 'value': '1'},
    ])
    validate_descriptor(spec)


def test_freehsm_declares_its_documented_nonsecret_env():
    spec = load_environment('freehsm', 'release')
    assert spec['runtime_env'] == [
        {'name': 'FHSM_TOKENS_DIR', 'value': '/var/lib/p11lab/freehsm'},
        {'name': 'FHSM_INTEGRITY_ALLOW_UNSIGNED', 'value': '1'},
        {'name': 'FHSM_KAT_ALLOW_FAIL', 'value': '1'},
    ]
    validate_descriptor(spec)


@pytest.mark.parametrize('name', [
    'FHSM_PIN', 'MY_SECRET', 'USER_PASSWORD', 'PRIVATE_DIR', 'API_KEY',
    'P11LAB_PIN', 'P11TEST_PIN', 'PYTEST_ADDOPTS', 'PKCS11_CHECK_FOO',
    'PKCS11_PROXY_ENDPOINT', 'LD_PRELOAD', 'PATH', 'LD_LIBRARY_PATH',
    'HOME', 'XDG_CONFIG_HOME', 'SYSTEMROOT', 'WINDIR',
    'PYTHONPATH', 'PYTHONHOME', 'PYTHONSTARTUP',
    'API_TOKEN', 'ACCESS_TOKEN', 'MY_TOKEN', 'TOKEN', 'USER_PASSWORD_FILE',
    'AUTHORIZATION', 'AUTH_MODE', 'CREDENTIALS', 'MY_CRED', 'PASSWD', 'USER_PASSWD',
    'BASH_ENV', 'ENV', 'SHELLOPTS', 'GCONV_PATH', 'PERL5OPT', 'PERL5LIB',
    'NODE_OPTIONS', 'NODE_PATH', 'RUBYOPT', 'TMPDIR', 'TMP', 'TEMP',
    'USERPROFILE', 'SHELL', 'COMSPEC', 'HOMEDRIVE', 'HOMEPATH', 'APPDATA',
    'LOCALAPPDATA', 'XDG_DATA_HOME', 'XDG_CACHE_HOME',
    'lower', 'X-PIN', 'HAS SPACE', '9LIVES', '', 'A' * 65,
])
def test_runtime_env_rejects_credential_reserved_and_malformed_names(name):
    spec = _spec_with_runtime_env([{'name': name, 'value': '1'}])
    with pytest.raises(CatalogError):
        validate_descriptor(spec)


def test_runtime_env_token_word_boundary_preserves_pkcs11_token_names():
    # TOKEN matches only as a whole underscore-bounded word: the reviewed
    # PKCS#11-token directory name stays valid while auth-token aliases fail.
    spec = _spec_with_runtime_env([{'name': 'FHSM_TOKENS_DIR', 'value': '/var/lib/p11lab/freehsm'}])
    validate_descriptor(spec)
    with pytest.raises(CatalogError):
        validate_descriptor(_spec_with_runtime_env([{'name': 'API_TOKEN', 'value': '1'}]))


def test_runtime_env_accepts_reviewed_native_token_store():
    # Repro: TOKEN's credential-word check rejected this required non-secret
    # file-store directory, preventing checker env restoration after scrubbing.
    # The exception is declared per-descriptor, not hardcoded in the catalogue.
    validate_descriptor(_spec_with_runtime_env([
        {'name': 'WOLFPKCS11_TOKEN_PATH', 'value': '/var/lib/p11lab/wolfpkcs11'},
    ], {'WOLFPKCS11_TOKEN_PATH': '/var/lib/p11lab/wolfpkcs11'}))


@pytest.mark.parametrize('name,value', [
    ('WOLFPKCS11_TOKEN_PATH', 'credential-value'),
    ('WOLFPKCS11_TOKEN_PATH', '/var/lib/p11lab/wolfpkcs11/../secrets'),
    ('API_TOKEN', '/var/lib/p11lab/wolfpkcs11'),
    ('ACCESS_TOKEN_PATH', '/var/lib/p11lab/wolfpkcs11'),
    ('UNREVIEWED_TOKEN_PATH', '/var/lib/p11lab/wolfpkcs11'),
])
def test_runtime_env_token_store_exception_preserves_credential_rejection(name, value):
    with pytest.raises(CatalogError):
        validate_descriptor(_spec_with_runtime_env([{'name': name, 'value': value}]))


def test_runtime_env_accepts_reviewed_pkcs11rs_token_store():
    # Native probe: this is the named software-token directory, not a secret.
    # Repro at e8b978a: validate_runtime_env rejected its TOKEN word.
    validate_descriptor(_spec_with_runtime_env([
        {'name': 'PKCS11RS_TOKEN_STORAGE', 'value': '/var/lib/p11lab/pkcs11rs'},
    ], {'PKCS11RS_TOKEN_STORAGE': '/var/lib/p11lab/pkcs11rs'}))


@pytest.mark.parametrize('name,value', [
    ('PKCS11RS_TOKEN_STORAGE', 'credential-value'),
    ('PKCS11RS_TOKEN_STORAGE', '/var/lib/p11lab/pkcs11rs/../secrets'),
    ('API_TOKEN', '/var/lib/p11lab/pkcs11rs'),
    ('ACCESS_TOKEN_STORAGE', '/var/lib/p11lab/pkcs11rs'),
    ('UNREVIEWED_TOKEN_STORAGE', '/var/lib/p11lab/pkcs11rs'),
])
def test_pkcs11rs_token_store_exception_preserves_credential_rejection(name, value):
    with pytest.raises(CatalogError):
        validate_descriptor(_spec_with_runtime_env([{'name': name, 'value': value}]))


@pytest.mark.parametrize('value', ['', 'has\nnewline', 'has\rcr', 'has\0nul', 'x' * 4097, 1, None, ['1']])
def test_runtime_env_rejects_bad_values(value):
    spec = _spec_with_runtime_env([{'name': 'FHSM_EXAMPLE', 'value': value}])
    with pytest.raises(CatalogError):
        validate_descriptor(spec)


@pytest.mark.parametrize('entries', [
    [], {}, None, 'FHSM_EXAMPLE=1',
    ['FHSM_EXAMPLE=1'], [{'name': 'FHSM_EXAMPLE'}],
    [{'value': '1'}], [{'name': 'FHSM_EXAMPLE', 'value': '1', 'inherit': True}],
    [{'name': 'FHSM_EXAMPLE', 'inherit': True}],
    [{'name': 'FHSM_A', 'value': '1'}, {'name': 'FHSM_A', 'value': '2'}],
])
def test_runtime_env_rejects_malformed_channels(entries):
    spec = _spec_with_runtime_env(entries)
    with pytest.raises(CatalogError):
        validate_descriptor(spec)


def _spec_with_inputs(entries):
    spec = load_environment('tpm2', 'release')
    spec['inputs'] = entries
    return spec


@pytest.mark.parametrize('entries', [
    {'FOO': {}},
    {'FOO': 'secret'},
    {'FOO': {'secret': 'yes', 'required': False}},
    {'FOO': {'secret': True}},
    {'FOO': {'secret': True, 'required': 1}},
    {'FOO': {'secret': True, 'required': False, 'default': 7}},
    {'FOO': {'secret': True, 'required': False, 'extra': 1}},
    {'': {'secret': True, 'required': False}},
    ['P11LAB_PIN'],
])
def test_inputs_entries_require_secret_required_shapes(entries):
    with pytest.raises(CatalogError):
        validate_descriptor(_spec_with_inputs(entries))


def test_inputs_entries_accept_documented_shapes():
    validate_descriptor(_spec_with_inputs({
        'P11LAB_PIN_FILE': {'secret': True, 'required': False},
        'P11LAB_LABEL': {'secret': False, 'required': False, 'default': 'P11Lab'},
    }))


@pytest.mark.parametrize('table', [
    [],
    {},
    {'bad-name': '/var/lib/p11lab/x'},
    {'STORE': 'credential-value'},
    {'STORE': '/var/lib/p11lab/../secrets'},
    {'STORE': '/var/lib/p11lab/'},
    {'STORE': '/etc/p11lab/store'},
    {'STORE': 'has\nnewline'},
])
def test_token_store_table_rejects_malformed_declarations(table):
    with pytest.raises(CatalogError):
        validate_descriptor(_spec_with_runtime_env(
            [{'name': 'FHSM_EXAMPLE', 'value': '1'}], table))


def test_token_store_exception_requires_exact_declared_value():
    with pytest.raises(CatalogError):
        validate_descriptor(_spec_with_runtime_env(
            [{'name': 'WOLFPKCS11_TOKEN_PATH', 'value': '/var/lib/p11lab/other'}],
            {'WOLFPKCS11_TOKEN_PATH': '/var/lib/p11lab/wolfpkcs11'}))


def test_token_store_exception_requires_matching_entry():
    with pytest.raises(CatalogError, match='lacks a runtime_env entry'):
        validate_descriptor(_spec_with_runtime_env(
            [{'name': 'FHSM_EXAMPLE', 'value': '1'}],
            {'WOLFPKCS11_TOKEN_PATH': '/var/lib/p11lab/wolfpkcs11'}))


def test_packaged_token_store_declarations_validate():
    for environment in ('wolfpkcs11', 'pkcs11rs'):
        spec = load_environment(environment, 'release')
        assert spec['runtime_env_token_stores']
        validate_descriptor(spec)


def test_tools_state_truth():
    tools = json.loads(package_data('tools.json').read_text())
    validate_tools(tools)
    states = {name: tool['status'] for name, tool in tools['tools'].items()}
    assert states == {'checker': 'planned', 'proxy': 'planned', 'p11scope': 'planned',
                      'oras': 'pinned-binary', 'consumer': 'owned'}
    assert tools['tools']['p11scope']['source']['revision'] == '7f8ca02bf926a5cbd4345180bbe7367c4f1abdf4'


def test_tools_oras_matches_oras_pin():
    from p11lab.publish import ORAS_PIN

    tools = json.loads(package_data('tools.json').read_text())
    oras = tools['tools']['oras']
    assert oras['source']['revision'] == ORAS_PIN['source']['revision']
    for entry in oras['artifacts']:
        pinned = ORAS_PIN['artifacts'][entry['platform']]
        assert entry['url'] == pinned['url']
        assert entry['sha256'] == pinned['sha256']
        assert entry['size'] == pinned['size']


@pytest.mark.parametrize('mutate', [
    lambda tools: tools['tools']['consumer'].__setitem__('status', 'planned'),
    lambda tools: tools['tools']['oras']['artifacts'].__setitem__(0, {}),
    lambda tools: tools['tools']['oras'].__setitem__('pending', 'unfinished'),
    lambda tools: tools['tools']['consumer'].__setitem__('pending', 'unfinished'),
    lambda tools: tools['tools']['consumer']['artifacts'].append('consumer/absent.c'),
    lambda tools: tools['tools']['proxy'].__setitem__('status', 'shipped'),
])
def test_tools_reject_false_or_broken_dispositions(mutate):
    tools = json.loads(package_data('tools.json').read_text())
    mutate(tools)
    with pytest.raises(CatalogError):
        validate_tools(tools)
