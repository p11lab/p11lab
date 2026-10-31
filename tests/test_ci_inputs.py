"""Pin behavior: immutable identity and eligibility remain independent."""
import copy
import hashlib
import importlib
import json

import pytest

from p11lab.catalog import package_data


def api():
    try:
        return importlib.import_module('p11lab.ci_inputs')
    except ModuleNotFoundError:
        pytest.fail('M01 packaged pin resolver is not implemented')


def pins():
    return api().load_image_pins()


def test_lookup_is_packaged_cwd_independent_and_detached(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    pin = api().load_image_pin('softhsm2', 'release', 'linux/amd64')
    assert pin['repository'] == 'ghcr.io/p11lab/softhsm2'
    assert pin['root']['digest'] == 'sha256:69cdeb9a74d13a3382547e184645ee18a7e9e2315246fd40ca814ef97b970d16'
    assert pin['root']['kind'] == 'manifest'
    assert pin['root']['index_digest'] is None
    assert pin['root']['index_absence_reason']
    assert pin['observations']['metadata'] is not None
    assert pin['observations']['pull'] is not None
    assert pin['observations']['runtime'] is not None
    assert pin['observations']['qualification'] is None
    assert pin['eligibility']['distribution_eligible'] is False
    assert pin['provenance']['recipe_sha256'] is None
    pin['repository'] = 'changed'
    assert api().load_image_pin('softhsm2', 'release', 'linux/amd64')['repository'] == 'ghcr.io/p11lab/softhsm2'


def test_other_six_pins_do_not_inherit_softhsm_runtime_observations():
    for pin in pins()['images']:
        if pin['environment'] != 'softhsm2':
            assert pin['observations']['pull'] is None
            assert pin['observations']['runtime'] is None
            assert pin['local_engine_id'] is None


def test_policy_bytes_are_freezable_separately_from_revision():
    raw = package_data('ci/images.json').read_bytes()
    policy = api().load_image_pins()
    assert policy['policy_revision']
    assert 'sha256' not in policy
    assert api().image_pins_sha256() == hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize('lookup', [
    ('softhsm2', 'rolling', 'linux/amd64'), ('softhsm2', 'release', 'linux/arm64'),
    ('../softhsm2', 'release', 'linux/amd64'),
])
def test_unavailable_lookup_is_explicit(lookup):
    with pytest.raises(ValueError, match='no image pin'):
        api().load_image_pin(*lookup)


@pytest.mark.parametrize('field', ['platform_manifest_digest', 'config_digest'])
def test_required_manifest_and_config_digests_cannot_be_missing(field):
    policy = pins()
    del policy['images'][0][field]
    with pytest.raises(ValueError, match=field):
        api().validate_image_pins(policy)


@pytest.mark.parametrize('field', ['digest', 'index_digest'])
def test_index_requires_real_index_identity(field):
    policy = pins()
    root = policy['images'][0]['root']
    root.update(kind='index', media_type='application/vnd.oci.image.index.v1+json',
                digest='sha256:' + 'a' * 64, index_digest='sha256:' + 'a' * 64,
                index_absence_reason=None)
    del root[field]
    with pytest.raises(ValueError, match=field):
        api().validate_image_pins(policy)


@pytest.mark.parametrize('change', [
    {'index_digest': 'sha256:' + 'a' * 64}, {'index_absence_reason': None},
    {'media_type': 'application/vnd.oci.image.index.v1+json'},
])
def test_manifest_cannot_invent_an_index(change):
    policy = pins()
    policy['images'][0]['root'].update(change)
    with pytest.raises(ValueError, match='root|index'):
        api().validate_image_pins(policy)


@pytest.mark.parametrize('field,value', [
    ('platform_manifest_digest', 'ghcr.io/p11lab/softhsm2:latest'),
    ('config_digest', 'sha256:abc'), ('config_digest', 'A' * 64),
    ('repository', 'ghcr.io/p11lab/softhsm2:latest'),
    ('local_engine_id', 'local-image:latest'),
])
def test_mutable_or_partial_identity_is_rejected(field, value):
    policy = pins()
    policy['images'][0][field] = value
    with pytest.raises(ValueError, match=field):
        api().validate_image_pins(policy)


def test_duplicate_lookup_rejected_before_resolving():
    policy = pins()
    policy['images'].append(copy.deepcopy(policy['images'][0]))
    with pytest.raises(ValueError, match='duplicate environment/channel/platform'):
        api().validate_image_pins(policy)


@pytest.mark.parametrize('axis', ['distribution_eligible', 'acquisition_eligible'])
def test_metadata_does_not_grant_distribution_or_acquisition(axis):
    policy = pins()
    policy['images'][0]['eligibility'][axis] = True
    with pytest.raises(ValueError, match='eligib|provenance'):
        api().validate_image_pins(policy)


def test_engine_id_is_not_assumed_equal_to_config():
    policy = pins()
    policy['images'][0]['local_engine_id'] = 'sha256:' + 'a' * 64
    assert api().validate_image_pins(policy)['images'][0]['local_engine_id'] == 'sha256:' + 'a' * 64


@pytest.mark.parametrize('mutation,diagnostic', [
    (lambda p: p.update(unexpected=True), 'unknown'),
    (lambda p: p.update(schema_version=True), 'schema_version'),
    (lambda p: p['images'][0]['eligibility'].update(distribution_eligible=1), 'distribution_eligible'),
    (lambda p: p['images'][0]['observations']['metadata'].update(observed_at='yesterday'), 'observed_at'),
    (lambda p: p['images'][0]['provenance'].update(recipe_sha256=float('nan')), 'JSON'),
])
def test_closed_finite_exact_typed_contract(mutation, diagnostic):
    policy = pins()
    mutation(policy)
    with pytest.raises(ValueError, match=diagnostic):
        api().validate_image_pins(policy)


def eligible_policy():
    policy = pins()
    pin = policy['images'][0]
    source = {'reference': pin['repository'] + '@sha256:' + 'b' * 64,
              'manifest_sha256': 'b' * 64, 'file_sha256': 'c' * 64, 'readback_proof_sha256': 'd' * 64}
    pin['provenance'].update(source_seal=source,
                              content_companion={**source, 'receipt_sha256': 'e' * 64, 'spdx_sha256': 'f' * 64},
                              recipe_sha256='1' * 64, provider_build_key='2' * 64, patches=[])
    pin['semantics'].update(modified=False, simulated=False)
    pin['eligibility'].update(distribution_eligible=True, blockers=[])
    return policy


def test_exact_index_and_resolved_distribution_declarations_are_supported():
    policy = eligible_policy()
    pin = policy['images'][0]
    pin['root'].update(kind='index', media_type='application/vnd.oci.image.index.v1+json',
                       digest='sha256:' + 'a' * 64, index_digest='sha256:' + 'a' * 64,
                       index_absence_reason=None)
    assert api().validate_image_pins(policy)['images'][0]['eligibility']['distribution_eligible'] is True


@pytest.mark.parametrize('mutation,diagnostic', [
    (lambda pin: pin['root'].update(digest='sha256:' + 'f' * 64), 'root'),
    (lambda pin: pin['provenance']['source_seal'].update(manifest_sha256='f' * 64), 'manifest_sha256'),
    (lambda pin: pin['provenance'].update(patches=[{'sha256': 'f' * 64, 'origin': 'upstream', 'license': 'BSD-2-Clause', 'license_status': 'unreviewed'}]), 'patch'),
    (lambda pin: pin['provenance'].update(patches=[{'sha256': 'f' * 64, 'origin': 'upstream', 'license': 'BSD-2-Clause', 'license_status': 'reviewed'}]), 'modified'),
    (lambda pin: pin.update(config_digest='sha256:' + 'f' * 64 + '\n'), 'config_digest'),
])
def test_resolved_policy_still_requires_consistent_exact_provenance(mutation, diagnostic):
    policy = eligible_policy()
    mutation(policy['images'][0])
    with pytest.raises(ValueError, match=diagnostic):
        api().validate_image_pins(policy)


def test_new_acquisition_requires_v2_handoff_and_qualified_observations():
    policy = eligible_policy()
    pin = policy['images'][0]
    pin['provenance']['handoff'] = {'reference': pin['repository'] + '@sha256:' + 'a' * 64,
                                   'manifest_sha256': 'a' * 64, 'file_sha256': 'b' * 64, 'schema_version': 2}
    pin['observations']['qualification'] = copy.deepcopy(pin['observations']['runtime'])
    pin['eligibility']['acquisition_eligible'] = True
    assert api().validate_image_pins(policy)['images'][0]['eligibility']['acquisition_eligible'] is True
    pin['provenance']['handoff']['schema_version'] = 1
    with pytest.raises(ValueError, match='schema_version'):
        api().validate_image_pins(policy)
