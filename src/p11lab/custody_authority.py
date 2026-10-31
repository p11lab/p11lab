"""Completed-producer custody checks, distinct from active source admission.

These checks do not by themselves construct a verified producer authority.
"""
import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
import time

from .delivery_authority import _check_verified, _profile_digest, _run_verifier
from .round_core.inputs import CUSTODY_MEMBER_LIMIT, SHA, canonical, digest, load_json

PREDICATE_TYPE = 'https://p11lab.org/attestations/image-custody/v1'
_AUTHORITY_KEY = object()


@dataclass(frozen=True, slots=True, init=False)
class VerifiedCompletedFinalization:
    """Authenticated completed producer; payload and fresh D remain unchecked."""

    _statement: bytes
    _observed: bytes
    _profile: bytes

    def __init__(self, key, statement, observed, profile):
        if key is not _AUTHORITY_KEY:
            raise TypeError('completed authority requires verified factory')
        object.__setattr__(self, '_statement', canonical(statement))
        object.__setattr__(self, '_observed', canonical(observed))
        object.__setattr__(self, '_profile', canonical(profile))

    def statement(self):
        return load_json(self._statement)

    def observed(self):
        return load_json(self._observed)

    def profile(self):
        return load_json(self._profile)


def _require_custody_graph(profile):
    graph_paths = {entry['path'] for entry in profile['graph']}
    required = {profile['workflow_path'], 'src/p11lab/custody_authority.py', 'src/p11lab/image_custody.py',
                'src/p11lab/round_core/artifacts.py', 'src/p11lab/round_core/inputs.py',
                'src/p11lab/round_core/evaluator_replay.py', 'src/p11lab/data/ci/delivery/evaluator-replay-driver.py',
                'src/p11lab/data/ci/delivery/custody-policy.json',
                'src/p11lab/data/ci/image-custody.schema.json',
                'src/p11lab/data/ci/delivery/image-evidence.py'}
    if not required <= graph_paths:
        raise ValueError('protected custody graph is incomplete')
    from .image_custody import _read_custody_policy
    _, shards = _read_custody_policy()
    prefix = 'src/p11lab/data/ci/delivery/custody-components/'
    declared = [entry for entry in profile['graph'] if entry['path'].startswith(prefix)]
    expected = [{'path': row['path'], 'sha256': row['sha256']} for row in shards]
    if sorted(declared, key=lambda item: item['path']) != sorted(expected, key=lambda item: item['path']):
        raise ValueError('protected custody policy shard graph mismatch')


def verify_completed_finalization(*, environment, channel, run_id, attempt, job_id,
                                  control_id, token, executable, trusted_root, output_dir):
    """Authenticate one completed producer and separately signed finalization.

    This does not verify payload bytes, re-run D, qualify, expose or hand off.
    """
    from . import delivery_authority as source
    from .image_custody import check_segment_roster
    from .round_core.artifacts import CustodyArtifactBytes, decode_custody_control

    profile = source.load_profile(environment, channel)
    source._check_local_controller(profile)
    if (any(type(value) is not int or value <= 0 for value in (run_id, attempt, job_id, control_id))
            or attempt != 1 or type(token) is not str or not token):
        raise ValueError('invalid completed custody selector')
    _require_custody_graph(profile)
    transport = source._github_transport(profile['repository'], token)
    base = {'run_id': run_id, 'attempt': attempt, 'workflow_id': profile['workflow_id'],
            'repository_id': profile['repository_id'], 'owner_id': profile['owner_id'],
            'head_sha': profile['source_sha'], 'job_name': profile['job'], 'job_id': job_id}
    control_selector = base | {'artifact_id': control_id, 'name': f'p11lab-image-custody-control-{run_id}-{attempt}'}
    now = source._clock()
    control = transport.resolve_custody(control_selector, now=now)
    if control['job_count'] != 1:
        raise ValueError('custody control producer mismatch')
    deadline = time.monotonic() + 60
    protection = source._load_protection(transport, profile, run_id, control['run'], deadline)
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=False)
    source._check_controller_graph(profile['graph'], lambda path: transport.source_file(profile['source_sha'], path),
                                   transport=transport, revision=profile['source_sha'], shard_journal=output / 'shard-graph-before.json')
    control_artifact = control['artifact']
    control_bytes = transport.download_custody_control(CustodyArtifactBytes(
        control_artifact['id'], control_artifact['size_in_bytes'], control_artifact['digest']))
    statement_raw, bundle_raw = decode_custody_control(control_bytes)
    statement_path, bundle_path = output / 'custody-finalization.json', output / 'bundle.json'
    with statement_path.open('xb') as stream:
        stream.write(statement_raw)
    with bundle_path.open('xb') as stream:
        stream.write(bundle_raw)
    result, verified_raw = run_custody_verifier(executable, statement_path, bundle_path, trusted_root,
        profile['root_sha256'], profile, output / 'attestation')
    identity = {'run_id': run_id, 'attempt': attempt, 'job': profile['job']}
    check_completed_signature(result, profile, identity, verified_raw, control['job'], source._clock())
    statement = load_json(verified_raw)
    try:
        rows = statement['artifacts']
        check_segment_roster(rows, run_id=run_id, attempt=attempt)
        if any(row['id'] == control_id for row in rows):
            raise ValueError('custody control artifact reused as data')
        payload_selectors = [base | {'artifact_id': row['id'], 'name': row['name']} for row in rows]
        expected_roster = [{'id': row['id'], 'name': row['name']} for row in rows]
        expected_roster.append({'id': control_id, 'name': control_selector['name']})
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError('malformed signed custody segment roster') from error
    roster = transport.resolve_custody_roster(run_id, expected_roster)
    payloads = [transport.resolve_custody(selector, now=source._clock()) for selector in payload_selectors]
    if any(payload['run'] != control['run'] or payload['job'] != control['job']
           or payload['job_count'] != 1 for payload in payloads):
        raise ValueError('custody control and payload producer mismatch')
    observed = {'run': control['run'], 'job': control['job'], 'control': control['artifact'],
                'segments': [payload['artifact'] for payload in payloads]}
    _check_finalization_identity(statement, profile, observed)
    second_payloads = [transport.resolve_custody(selector, now=source._clock()) for selector in payload_selectors]
    second_control = transport.resolve_custody(control_selector, now=source._clock())
    second_roster = transport.resolve_custody_roster(run_id, expected_roster)
    if payloads != second_payloads or control != second_control or roster != second_roster:
        raise ValueError('custody producer metadata changed during verification')
    if source._load_protection(transport, profile, run_id, second_control['run'], time.monotonic() + 60) != protection:
        raise ValueError('custody protection changed during verification')
    source._check_controller_graph(profile['graph'], lambda path: transport.source_file(profile['source_sha'], path),
                                   transport=transport, revision=profile['source_sha'], shard_journal=output / 'shard-graph-after.json')
    source._check_local_controller(profile)
    return VerifiedCompletedFinalization(_AUTHORITY_KEY, statement, observed, profile)


def run_custody_verifier(executable, statement, bundle, root, root_sha256, profile, output):
    """Run the existing pinned verifier on the distinct custody predicate."""
    return _run_verifier(executable, statement, bundle, root, root_sha256, profile, output, custody=True)


def _producer_identity(profile):
    return {key: profile[key] for key in ('repository', 'repository_id', 'owner_id', 'workflow_id',
            'workflow_path', 'source_sha', 'source_ref', 'signer_sha')} | {'graph_sha256': digest(profile['graph'])}


def _check_finalization_identity(statement, profile, observed):
    try:
        fields = {'schema_version', 'kind', 'role', 'environment', 'channel', 'profile_sha256',
                  'controller_sha256', 'producer', 'run', 'manifest_sha256', 'artifacts', 'image_archive', 'retention_days', 'evaluator', 'components'}
        if (type(statement) is not dict or set(statement) != fields
                or type(statement['schema_version']) is not int or statement['schema_version'] != 1
                or statement['kind'] != 'image-custody-finalization' or statement['role'] != 'image-custody-producer'
                or type(statement['retention_days']) is not int or statement['retention_days'] != 14
                or statement['environment'] != profile['environment'] or statement['channel'] != profile['channel']
                or statement['profile_sha256'] != _profile_digest(profile)
                or statement['controller_sha256'] != profile['controller_sha256']
                or statement['producer'] != _producer_identity(profile)
                or any(type(statement['producer'][key]) is not int for key in ('repository_id', 'owner_id', 'workflow_id'))
                or type(statement['manifest_sha256']) is not str or not SHA.fullmatch(statement['manifest_sha256'])):
            raise ValueError('custody finalization profile or manifest mismatch')
        image = statement['image_archive']
        if (type(image) is not dict or set(image) != {'sha256', 'size'}
                or type(image['size']) is not int or not 0 < image['size'] <= CUSTODY_MEMBER_LIMIT
                or type(image['sha256']) is not str or not SHA.fullmatch(image['sha256'])):
            raise ValueError('custody finalization image archive mismatch')
        from .round_core.evaluator_replay import check_evaluator_observation
        check_evaluator_observation(statement['evaluator'])
        from .image_custody import check_component_facts, check_segment_roster
        check_component_facts(statement['components'])
        evaluator_component = next(row for row in statement['components'] if row['name'] == 'evaluator-original')
        if evaluator_component['artifact']['sha256'] != statement['evaluator']['receipt_sha256']:
            raise ValueError('custody evaluator metadata identity mismatch')
        run, job, segments = observed['run'], observed['job'], observed['segments']
        identity = {'run_id': run['id'], 'attempt': run['run_attempt'], 'job': profile['job'], 'job_id': job['id']}
        check_segment_roster(statement['artifacts'], run_id=identity['run_id'], attempt=identity['attempt'])
        if type(segments) is not list or len(segments) != len(statement['artifacts']):
            raise ValueError('incomplete custody segment metadata')
        expected_artifacts = [{'role': row['role'], 'part': row['part'], 'id': artifact['id'], 'name': artifact['name'],
                               'size': artifact['size_in_bytes'], 'digest': artifact['digest']}
                              for row, artifact in zip(statement['artifacts'], segments)]
        if (statement['run'] != identity or statement['artifacts'] != expected_artifacts
                or any(type(statement['run'][key]) is not int for key in ('run_id', 'attempt', 'job_id'))
                or type(identity['run_id']) is not int or type(identity['attempt']) is not int
                or type(identity['job_id']) is not int
                or run['workflow_id'] != profile['workflow_id']
                or run['repository']['id'] != profile['repository_id']
                or run['repository']['owner']['id'] != profile['owner_id']
                or run['head_sha'] != profile['source_sha'] or job['head_sha'] != profile['source_sha']
                or job['name'] != profile['job'] or job['run_id'] != run['id']):
            raise ValueError('custody finalization producer or artifact mismatch')
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError('malformed custody finalization') from error


def check_finalization(statement, manifest, profile, observed):
    """Compare a signed finalization to independent metadata and exact bytes.

    This consistency check does not authenticate its inputs or admit custody.
    """
    _check_finalization_identity(statement, profile, observed)
    if (type(manifest) is not bytes or len(manifest) > 2 * 1024 * 1024
            or statement['manifest_sha256'] != hashlib.sha256(manifest).hexdigest()):
        raise ValueError('custody finalization manifest mismatch')
    from .image_custody import SEGMENT_ROLES, check_custody_manifest
    value = load_json(manifest)
    check_custody_manifest(value)
    expected_parts = [(role, part['part']) for role in SEGMENT_ROLES for part in value['files'][role]]
    if [(row['role'], row['part']) for row in statement['artifacts']] != expected_parts:
        raise ValueError('custody finalization part roster mismatch')
    if (value['image_archive'] != statement['image_archive'] or value['producer'] != statement['producer']
            or value['run'] != statement['run'] or value['profile_sha256'] != statement['profile_sha256']
            or value['controller_sha256'] != statement['controller_sha256']
            or value['components'] != statement['components']
            or value['evaluator_receipt_sha256'] != statement['evaluator']['receipt_sha256']
            or value['evaluator_identity_sha256'] != statement['evaluator']['identity_sha256']):
        raise ValueError('custody manifest differs from signed finalization')


def check_completed_signature(result, profile, identity, raw, job, now):
    """Check pinned verifier output against an independently authenticated job.

    Callers must authenticate the job and verifier output separately. This is
    not a constructor of completed producer authority.
    """
    try:
        if now.tzinfo is None:
            raise ValueError('verification clock requires timezone')
        def stamp(value):
            parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
            if parsed.tzinfo is None:
                raise ValueError('job timestamp requires timezone')
            return parsed.astimezone(timezone.utc)
        start, end = stamp(job['started_at']), stamp(job['completed_at'])
        if start > end:
            raise ValueError('invalid authenticated job timing')
        skew = timedelta(minutes=5)
        lower = max(start - skew, now - timedelta(days=14))
        upper = min(end + skew, now + skew)
        if lower > upper:
            raise ValueError('completed custody signature expired or premature')
        _check_verified(result, profile, identity, raw, now, predicate_type=PREDICATE_TYPE,
                        subject_name='custody-finalization.json', timestamp_window=(lower, upper))
    except (KeyError, TypeError, AttributeError, OverflowError) as error:
        raise ValueError('malformed completed job timing') from error
