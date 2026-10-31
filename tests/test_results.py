"""Result validation preserves observations without granting acceptance."""
import copy
import hashlib
import importlib
import json

import pytest


D = 'a' * 64


def api():
    try:
        return importlib.import_module('p11lab.results')
    except ModuleNotFoundError:
        pytest.fail('M01 result validator is not implemented')


def identity(status='recorded'):
    return {'status': status, 'sha256': D if status == 'recorded' else None,
            'source_revision': None, 'artifact': None,
            'reason': None if status == 'recorded' else 'Not exercised in this diagnostic.'}


def artifact(path='run/receipt.json'):
    return {'path': path, 'bytes': 123, 'sha256': D, 'url': None, 'expires_at': None}


def result():
    expected = [{'outer_attempt_id': 'outer-1', 'shard_id': 's1', 'attempt_id': '00000000-0000-4000-8000-000000000001', 'case_ids': ['case-1', 'case-2']}]
    return {
        'schema_version': 1, 'kind': 'experiment-result', 'experiment_kind': 'image',
        'stage': 'runtime-diagnostic',
        'caller': {'kind': 'local', 'repository': None, 'run_id': None, 'run_attempt': None,
                   'job': 'diagnostic', 'local_run_id': 'local-1'},
        'identities': {name: identity('not-applicable' if name in ('derivative', 'client') else 'recorded')
                       for name in ('control', 'candidate', 'evaluator', 'policy', 'inputs', 'derivative', 'client', 'source')},
        'policy_revision': 'test-policy-1',
        'provider': {'environment': 'softhsm2', 'channel': 'release', 'platform': 'linux/amd64',
                     'artifact': {'kind': 'docker-local', 'reference': 'sha256:' + D, 'sha256': D, 'platform': 'linux/amd64'},
                     'registry_status': 'unperformed', 'registry_reason': 'Local candidate, not published.',
                     'root': None, 'platform_manifest_digest': None, 'config_digest': None,
                     'local_engine_id': 'sha256:' + D, 'build_receipt': artifact('build/receipt.json'),
                     'provider_build_key': D, 'experiment_key': 'b' * 64},
        'execution': {'profile': {'id': 'test', 'sha256': D},
                      'roster_sha256': hashlib.sha256(json.dumps(expected, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
                      'expected_shards': expected,
                      'observed_shards': [{'outer_attempt_id': 'outer-1', 'shard_id': 's1', 'attempt_id': '00000000-0000-4000-8000-000000000001', 'status': 'completed',
                                           'process_returncode': 1, 'findings': 2, 'skips': 1,
                                           'artifacts': [artifact('run/raw.json')], 'run_receipt': artifact()}],
                      'raw_status': {'process_returncode': 1, 'findings': 2, 'skips': 1}},
        'axes': {'image_usable': True, 'lifecycle_complete': True, 'evidence_complete': True,
                 'evidence_admitted': True, 'comparison_positive': None, 'within_budget': None,
                 'distribution_eligible': False},
        'policy': {'qualification_only': True, 'promotable': False,
                   'comparison_required': False, 'comparison_performed': False, 'coverage_positive': None,
                   'budget_required': False, 'budget_performed': False, 'distribution_required': False,
                   'image_semantics_reviewed': False, 'proxy': None},
        'reproduction': ['p11lab', 'run', 'softhsm2'], 'evidence': [artifact()],
        'limitations': ['Local synthetic contract fixture; no runtime qualification.'],
    }


def accepted(kind='image'):
    record = result()
    record.update(stage='accepted', experiment_kind=kind)
    record['axes'].update(comparison_positive=True, within_budget=True, distribution_eligible=True)
    record['policy'].update(qualification_only=False, comparison_required=True,
                            comparison_performed=True, coverage_positive=True,
                            budget_required=True, budget_performed=True, distribution_required=True,
                            image_semantics_reviewed=True if kind == 'image' else None)
    if kind == 'proxy':
        record['policy']['proxy'] = {'cells_admitted_complete': True, 'transport_controls_positive': True,
                                     'direct_attribution_complete': True}
        record['identities']['derivative'] = identity()
        record['identities']['client'] = identity()
    return record


def test_completed_findings_and_negative_comparison_are_valid_records():
    record = result()
    record['policy'].update(comparison_required=True, comparison_performed=True, coverage_positive=False)
    record['axes']['comparison_positive'] = False
    detached = api().validate_result(record)
    assert detached['execution']['raw_status'] == {'process_returncode': 1, 'findings': 2, 'skips': 1}
    assert detached['axes']['comparison_positive'] is False
    detached['limitations'].append('changed')
    assert len(record['limitations']) == 1


def test_local_build_does_not_fabricate_registry_digests():
    record = result()
    record['stage'] = 'local-built'
    record['axes'].update(image_usable=False, lifecycle_complete=False, evidence_complete=False, evidence_admitted=False)
    record['execution'].update(expected_shards=[], observed_shards=[], roster_sha256=None, profile=None)
    validated = api().validate_result(record)
    assert validated['provider']['root'] is None
    assert validated['provider']['artifact']['kind'] == 'docker-local'


def test_exit_zero_never_defaults_comparison_or_distribution():
    record = result()
    record['execution']['raw_status']['process_returncode'] = 0
    record['axes'].pop('distribution_eligible')
    with pytest.raises(ValueError, match='distribution_eligible'):
        api().validate_result(record)
    record = result()
    record['axes'].pop('comparison_positive')
    with pytest.raises(ValueError, match='comparison_positive'):
        api().validate_result(record)


@pytest.mark.parametrize('field,value,diagnostic', [
    ('stage', 'all-good', 'stage'), ('schema_version', True, 'schema_version'),
    ('unknown', True, 'unknown'), ('kind', 'run-receipt', 'kind'),
])
def test_unknown_contract_or_stage_rejected(field, value, diagnostic):
    record = result()
    record[field] = value
    with pytest.raises(ValueError, match=diagnostic):
        api().validate_result(record)


@pytest.mark.parametrize('performed,value', [(True, None), (False, True), (False, False)])
def test_null_comparison_only_when_declared_unperformed(performed, value):
    record = result()
    record['policy']['comparison_performed'] = performed
    record['axes']['comparison_positive'] = value
    with pytest.raises(ValueError, match='comparison'):
        api().validate_result(record)


@pytest.mark.parametrize('axis', ['image_usable', 'lifecycle_complete', 'evidence_complete',
                                  'evidence_admitted', 'comparison_positive', 'within_budget',
                                  'distribution_eligible'])
def test_claimed_image_acceptance_requires_each_independent_axis(axis):
    record = accepted()
    record['axes'][axis] = False
    if axis == 'evidence_complete':
        record['axes']['evidence_admitted'] = False
    with pytest.raises(ValueError, match=axis):
        api().validate_result(record)


def test_positive_comparison_cannot_substitute_for_coverage_or_review():
    for field in ('coverage_positive', 'image_semantics_reviewed'):
        record = accepted()
        record['policy'][field] = False
        with pytest.raises(ValueError, match=field):
            api().validate_result(record)


def test_promotion_claim_cannot_bypass_stage_or_qualification():
    for stage in ('runtime-diagnostic', 'qualification'):
        record = accepted()
        record['stage'] = stage
        record['policy'].update(promotable=True, qualification_only=True)
        with pytest.raises(ValueError, match='promotable|qualification'):
            api().validate_result(record)


def test_positive_image_result_can_retain_known_findings():
    assert api().validate_result(accepted())['execution']['raw_status']['process_returncode'] == 1


@pytest.mark.parametrize('axis', ['cells_admitted_complete', 'transport_controls_positive', 'direct_attribution_complete'])
def test_proxy_acceptance_requires_three_cell_transport_and_direct_controls(axis):
    record = accepted('proxy')
    record['policy']['proxy'][axis] = False
    with pytest.raises(ValueError, match=axis):
        api().validate_result(record)


@pytest.mark.parametrize('status', ['cancelled', 'missing', 'upload-lost'])
def test_missing_cancelled_or_upload_lost_evidence_is_not_complete(status):
    record = result()
    record['execution']['observed_shards'][0]['status'] = status
    with pytest.raises(ValueError, match='evidence_complete'):
        api().validate_result(record)
    record['axes'].update(evidence_complete=False, evidence_admitted=False)
    assert api().validate_result(record)['axes']['evidence_complete'] is False


@pytest.mark.parametrize('mutation,diagnostic', [
    (lambda r: r['execution'].update(observed_shards=[]), 'evidence_complete'),
    (lambda r: r['execution']['observed_shards'].append(copy.deepcopy(r['execution']['observed_shards'][0])), 'duplicate'),
    (lambda r: r['execution']['expected_shards'].append({'outer_attempt_id': 'outer-1', 'shard_id': 's2', 'attempt_id': '00000000-0000-4000-8000-000000000002', 'case_ids': ['case-1']}), 'overlap'),
    (lambda r: r['execution']['observed_shards'][0].update(run_receipt=None), 'evidence_complete'),
    (lambda r: r['execution'].update(roster_sha256='b' * 64), 'roster_sha256'),
    (lambda r: r['axes'].update(image_usable=1), 'image_usable'),
    (lambda r: r['evidence'][0].update(bytes=True), 'bytes'),
    (lambda r: r['evidence'][0].update(sha256='short'), 'sha256'),
    (lambda r: r['evidence'][0].update(path='../token'), 'path'),
    (lambda r: r['evidence'][0].update(bytes=float('inf')), 'JSON'),
    (lambda r: r['caller'].update(run_id=12), 'caller'),
    (lambda r: r['identities']['evaluator'].update(sha256=None), 'sha256'),
])
def test_misleading_or_malformed_result_is_diagnostic(mutation, diagnostic):
    record = result()
    mutation(record)
    with pytest.raises(ValueError, match=diagnostic):
        api().validate_result(record)


def test_published_stage_requires_observed_registry_identity():
    record = accepted()
    record['stage'] = 'published'
    with pytest.raises(ValueError, match='registry'):
        api().validate_result(record)


@pytest.mark.parametrize('stage', ['planned', 'local-built', 'metadata-readback'])
def test_early_stage_cannot_claim_completed_runtime_evidence(stage):
    record = result()
    record['stage'] = stage
    if stage == 'metadata-readback':
        record['provider'].update(registry_status='recorded', registry_reason=None,
                                  root={'kind': 'manifest', 'media_type': 'application/vnd.oci.image.manifest.v1+json',
                                        'digest': 'sha256:' + D, 'index_digest': None, 'index_absence_reason': 'Single manifest.'},
                                  platform_manifest_digest='sha256:' + D, config_digest='sha256:' + 'b' * 64)
    with pytest.raises(ValueError, match='stage|runtime'):
        api().validate_result(record)


def test_same_artifact_path_cannot_claim_conflicting_bytes():
    record = result()
    record['evidence'][0]['sha256'] = 'b' * 64
    with pytest.raises(ValueError, match='conflicting.*artifact|artifact.*conflict'):
        api().validate_result(record)


def test_explicit_unperformed_identity_does_not_satisfy_active_comparison():
    record = accepted()
    record['identities']['evaluator'] = identity('unperformed')
    with pytest.raises(ValueError, match='evaluator'):
        api().validate_result(record)


def test_published_result_with_exact_registry_ref_is_supported():
    record = accepted()
    record['stage'] = 'published'
    record['policy']['promotable'] = True
    provider = record['provider']
    provider.update(registry_status='recorded', registry_reason=None,
                    root={'kind': 'manifest', 'media_type': 'application/vnd.oci.image.manifest.v1+json',
                          'digest': 'sha256:' + D, 'index_digest': None, 'index_absence_reason': 'Single manifest.'},
                    platform_manifest_digest='sha256:' + D, config_digest='sha256:' + 'b' * 64,
                    artifact={'kind': 'oci', 'reference': 'ghcr.io/p11lab/softhsm2@sha256:' + D,
                              'sha256': D, 'platform': 'linux/amd64'})
    assert api().validate_result(record)['stage'] == 'published'
    provider['artifact']['reference'] = 'ghcr.io/p11lab/softhsm2:latest@sha256:' + D
    with pytest.raises(ValueError, match='reference'):
        api().validate_result(record)


def test_evidence_admission_cannot_survive_incomplete_evidence():
    record = result()
    record['axes']['evidence_complete'] = False
    with pytest.raises(ValueError, match='evidence_complete'):
        api().validate_result(record)


@pytest.mark.parametrize('mutation', [
    lambda r: r['axes'].update(within_budget=False),
    lambda r: r['axes'].update(distribution_eligible=False),
    lambda r: r['policy'].update(image_semantics_reviewed=False),
    lambda r: r['policy'].update(coverage_positive=False),
    lambda r: r['policy'].update(promotable=True, qualification_only=True),
    lambda r: r['identities']['evaluator'].update(status='unperformed', sha256=None, reason='Not evaluated.'),
])
def test_packaged_schema_also_rejects_misleading_positive_shape(mutation):
    from p11lab.ci_inputs import _validate_document
    record = accepted()
    mutation(record)
    with pytest.raises(ValueError):
        _validate_document(record, 'result.schema.json')


def test_non_json_container_and_cycle_raise_explicit_diagnostics():
    record = result()
    record['limitations'] = ('tuple is not a JSON array',)
    with pytest.raises(ValueError, match='JSON'):
        api().validate_result(record)
    record = result()
    record['limitations'].append(record)
    with pytest.raises(ValueError, match='JSON'):
        api().validate_result(record)


def local_built():
    record = result()
    record['stage'] = 'local-built'
    record['axes'].update(image_usable=False, lifecycle_complete=False, evidence_complete=False, evidence_admitted=False)
    record['execution'].update(expected_shards=[], observed_shards=[], roster_sha256=None, profile=None)
    return record


def freeze_roster(record):
    record['execution']['roster_sha256'] = hashlib.sha256(json.dumps(
        record['execution']['expected_shards'], sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def scheduled_n2():
    record = result()
    execution = record['execution']
    execution['expected_shards'] = []
    execution['observed_shards'] = []
    for outer, shard, physical, cases in [
        ('outer-1', 's1', '00000000-0000-4000-8000-000000000001', ['case-1', 'case-2']),
        ('outer-1', 's2', '00000000-0000-4000-8000-000000000002', ['case-3']),
        ('outer-2', 's1', '00000000-0000-4000-8000-000000000003', ['case-1', 'case-2']),
        ('outer-2', 's2', '00000000-0000-4000-8000-000000000004', ['case-3']),
    ]:
        member = {'outer_attempt_id': outer, 'shard_id': shard, 'attempt_id': physical}
        execution['expected_shards'].append({**member, 'case_ids': cases})
        execution['observed_shards'].append({**member, 'status': 'completed',
            'process_returncode': 1, 'findings': 2, 'skips': 1,
            'artifacts': [artifact(f'{outer}/{shard}/raw.json')],
            'run_receipt': artifact(f'{outer}/{shard}/receipt.json')})
    freeze_roster(record)
    return record


def test_complete_scheduled_n2_preserves_cases_and_independent_outer_attempts():
    validated = api().validate_result(scheduled_n2())
    expected = validated['execution']['expected_shards']
    assert [(s['outer_attempt_id'], s['shard_id'], s['case_ids']) for s in expected] == [
        ('outer-1', 's1', ['case-1', 'case-2']), ('outer-1', 's2', ['case-3']),
        ('outer-2', 's1', ['case-1', 'case-2']), ('outer-2', 's2', ['case-3'])]
    assert validated['axes']['evidence_complete'] is True
    assert validated['policy']['qualification_only'] is True
    assert validated['policy']['promotable'] is False


@pytest.mark.parametrize('mutation,diagnostic', [
    (lambda e: e['expected_shards'][1].update(case_ids=['case-1']), 'overlap'),
    (lambda e: e['expected_shards'][1].update(shard_id='s1'), 'duplicate.*shard'),
    (lambda e: e['expected_shards'][2].update(attempt_id=e['expected_shards'][0]['attempt_id']), 'duplicate.*attempt'),
    (lambda e: e['observed_shards'].append(copy.deepcopy(e['observed_shards'][0])), 'duplicate'),
    (lambda e: e.update(observed_shards=e['observed_shards'][:2]), 'evidence_complete'),
    (lambda e: e['observed_shards'][2].update(outer_attempt_id='outer-3'), 'roster'),
    (lambda e: e['observed_shards'][2].update(attempt_id='00000000-0000-4000-8000-000000000099'), 'roster'),
])
def test_n2_roster_rejects_within_outer_overlap_and_missing_duplicate_extra_attempts(mutation, diagnostic):
    record = scheduled_n2()
    mutation(record['execution'])
    freeze_roster(record)
    with pytest.raises(ValueError, match=diagnostic):
        api().validate_result(record)


def test_n2_roster_cannot_change_without_refreshing_exact_frozen_hash():
    record = scheduled_n2()
    record['execution']['expected_shards'][2]['outer_attempt_id'] = 'outer-3'
    with pytest.raises(ValueError, match='roster_sha256'):
        api().validate_result(record)


@pytest.mark.parametrize('validator', ['schema', 'public'])
def test_local_built_null_artifact_is_rejected_by_schema_and_public_validator(validator):
    from p11lab.ci_inputs import _validate_document
    record = local_built()
    record['provider']['artifact'] = None
    with pytest.raises(ValueError, match='artifact'):
        if validator == 'schema':
            _validate_document(record, 'result.schema.json')
        else:
            api().validate_result(record)
