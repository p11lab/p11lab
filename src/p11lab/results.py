"""ExperimentResultV1 declarations and stage-specific acceptance predicates.

Validation cannot authenticate referenced artifacts, evaluate a comparison or
perform distribution admission. Producers/consumers must bind those exact bytes
using the authoritative run receipts, admission and trusted evaluator contracts.
"""

import hashlib
import json

from .ci_inputs import (CIInputError, _require, _validate_document,
                        _validate_evidence, _validate_root)
from .identity import IdentityError, _ref


class ResultError(ValueError):
    """A result is incomplete in shape or makes an unsupported positive claim."""


_POSITIVE_STAGES = {'accepted', 'promoted', 'published'}
_EXECUTED_STAGES = {'runtime-diagnostic', 'qualification'} | _POSITIVE_STAGES


def _artifact_reference(value, platform, path):
    if value is None:
        return
    try:
        _ref(value)
    except IdentityError as error:
        raise ResultError(f'{path}: {error}') from error
    _require(value['platform'] == platform, f'{path}.platform must match provider platform')


def _execution(record):
    execution, axes = record['execution'], record['axes']
    expected, observed = execution['expected_shards'], execution['observed_shards']
    expected_members, physical_attempts, case_ids = set(), set(), {}
    for shard in expected:
        member = shard['outer_attempt_id'], shard['shard_id']
        _require(member not in expected_members, 'duplicate expected shard within outer attempt')
        expected_members.add(member)
        _require(shard['attempt_id'] not in physical_attempts, 'duplicate physical attempt_id in expected roster')
        physical_attempts.add(shard['attempt_id'])
        outer_cases = case_ids.setdefault(shard['outer_attempt_id'], set())
        _require(not outer_cases.intersection(shard['case_ids']), 'overlap in expected shard case_ids within outer attempt')
        outer_cases.update(shard['case_ids'])
    if expected:
        canonical = json.dumps(expected, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
        _require(execution['roster_sha256'] == hashlib.sha256(canonical.encode('utf-8')).hexdigest(),
                 'execution.roster_sha256 must bind the frozen canonical expected_shards')
    else:
        _require(execution['roster_sha256'] is None, 'execution.roster_sha256 must be null for an unperformed roster')
    roster = {(shard['outer_attempt_id'], shard['shard_id'], shard['attempt_id']) for shard in expected}
    actual = set()
    all_complete = bool(roster)
    artifacts = list(record['evidence'])
    if record['provider']['build_receipt'] is not None:
        artifacts.append(record['provider']['build_receipt'])
    for shard in observed:
        pair = shard['outer_attempt_id'], shard['shard_id'], shard['attempt_id']
        _require(pair not in actual, 'duplicate observed outer/shard/attempt')
        actual.add(pair)
        _require(pair in roster, 'observed shard/attempt is outside the frozen expected roster')
        complete = (shard['status'] == 'completed' and shard['process_returncode'] is not None
                    and shard['run_receipt'] is not None and bool(shard['artifacts']))
        all_complete = all_complete and complete
        for artifact in shard['artifacts'] + ([shard['run_receipt']] if shard['run_receipt'] else []):
            _validate_evidence(artifact)
            artifacts.append(artifact)
    if axes['evidence_complete']:
        _require(all_complete and actual == roster and execution['profile'] is not None
                 and record['evidence'], 'evidence_complete requires every expected shard/attempt, receipt and raw artifact')
    for artifact in record['evidence']:
        _validate_evidence(artifact)
    by_path = {}
    for artifact in artifacts:
        identity = artifact['bytes'], artifact['sha256']
        _require(artifact['path'] not in by_path or by_path[artifact['path']] == identity,
                 'conflicting artifact bytes/sha256 for path: ' + artifact['path'])
        by_path[artifact['path']] = identity


def _validate(record):
    result = _validate_document(record, 'result.schema.json')
    stage, provider, axes, policy = (result[key] for key in ('stage', 'provider', 'axes', 'policy'))
    _artifact_reference(provider['artifact'], provider['platform'], 'provider.artifact')
    for name, identity in result['identities'].items():
        _artifact_reference(identity['artifact'], provider['platform'], f'identities.{name}.artifact')
    if provider['registry_status'] == 'recorded':
        _validate_root(provider['root'], provider['platform_manifest_digest'], 'provider.root')
        if provider['artifact'] is not None and provider['artifact']['kind'] == 'oci':
            _require(provider['artifact']['sha256'] == provider['root']['digest'].removeprefix('sha256:'),
                     'provider.artifact must bind the observed root digest')
    if provider['artifact'] is not None and provider['artifact']['kind'] == 'docker-local':
        _require(provider['local_engine_id'] == provider['artifact']['reference'],
                 'provider.local_engine_id must match exact local ArtifactRef')
    if provider['build_receipt'] is not None:
        _validate_evidence(provider['build_receipt'], 'provider.build_receipt')
    if stage != 'planned':
        for name in ('candidate', 'policy', 'inputs'):
            _require(result['identities'][name]['status'] == 'recorded', f'identities.{name} required at {stage} stage')
        _require(provider['experiment_key'] is not None, f'provider.experiment_key required at {stage} stage')
    if stage in {'planned', 'local-built', 'metadata-readback'}:
        _require(not any(axes[name] for name in ('image_usable', 'lifecycle_complete', 'evidence_complete', 'evidence_admitted'))
                 and not policy['comparison_performed'] and not result['execution']['observed_shards'],
                 f'{stage} stage cannot claim completed runtime evidence or comparison')
    if stage == 'local-built':
        _require(provider['artifact'] is not None and provider['artifact']['kind'] == 'docker-local'
                 and provider['local_engine_id'] is not None and provider['build_receipt'] is not None
                 and provider['provider_build_key'] is not None,
                 'local-built stage requires exact local artifact, engine identity, build key and build receipt')
    if stage in ('metadata-readback', 'published'):
        _require(provider['registry_status'] == 'recorded', f'{stage} stage requires recorded registry identities')
    if stage in _EXECUTED_STAGES:
        _require(provider['artifact'] is not None and (provider['artifact']['kind'] != 'oci' or provider['registry_status'] == 'recorded'),
                 f'{stage} stage requires exact provider artifact and applicable registry identities')
        _require(result['execution']['profile'] is not None and result['execution']['expected_shards'],
                 f'{stage} stage requires profile and frozen expected shard roster')
    if policy['comparison_performed']:
        for name in ('control', 'evaluator'):
            _require(result['identities'][name]['status'] == 'recorded', f'comparison requires recorded identities.{name}')
    if result['experiment_kind'] != 'image':
        _require(policy['image_semantics_reviewed'] is None, 'image_semantics_reviewed must be null outside image experiments')
    if result['experiment_kind'] != 'proxy':
        _require(policy['proxy'] is None, 'proxy controls apply only to proxy experiments')
    elif stage in _EXECUTED_STAGES:
        _require(policy['proxy'] is not None, 'proxy experiments require explicit proxy control observations')
        for name in ('derivative', 'client'):
            _require(result['identities'][name]['status'] == 'recorded', f'proxy experiments require identities.{name}')
    _execution(result)
    positive = stage in _POSITIVE_STAGES or policy['promotable']
    if policy['promotable']:
        _require(stage in _POSITIVE_STAGES and not policy['qualification_only'],
                 'promotable requires an accepted stage, never qualification_only')
    if stage in ('promoted', 'published'):
        _require(policy['promotable'], f'{stage} stage requires promotable=true')
    if positive:
        for axis in ('image_usable', 'lifecycle_complete', 'evidence_complete', 'evidence_admitted', 'comparison_positive'):
            _require(axes[axis] is True, f'acceptance requires {axis}=true')
        _require(policy['comparison_required'] and policy['comparison_performed'] and policy['coverage_positive'] is True,
                 'acceptance requires active comparison and coverage_positive=true')
        _require(not policy['qualification_only'], 'acceptance cannot be qualification_only')
        if policy['budget_required'] or result['experiment_kind'] in ('image', 'proxy'):
            _require(axes['within_budget'] is True and policy['budget_performed'], 'acceptance requires within_budget=true')
        if policy['distribution_required'] or result['experiment_kind'] == 'image':
            _require(axes['distribution_eligible'], 'acceptance requires distribution_eligible=true')
        if result['experiment_kind'] == 'image':
            _require(policy['image_semantics_reviewed'] is True, 'image acceptance requires image_semantics_reviewed=true')
        if result['experiment_kind'] == 'proxy':
            for axis, value in policy['proxy'].items():
                _require(value, f'proxy acceptance requires {axis}=true')
    return result


def validate_result(record: dict) -> dict:
    """Validate and detach a result; completed negative observations stay valid.

    An accepted/promoted/published claim must satisfy its applicable independent
    predicates. Raw application exit codes never supply missing comparison,
    distribution, admission, lifecycle or coverage facts.
    """
    try:
        return _validate(record)
    except CIInputError as error:
        raise ResultError(str(error)) from error
