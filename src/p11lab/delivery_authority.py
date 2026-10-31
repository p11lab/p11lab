"""Protected source-producer attestation verification.

A verified certificate binds a context to a workflow; the context remains a
claim until source, content and rights validators independently check it.
"""
import hashlib
from datetime import datetime, timedelta, timezone

PREDICATE_TYPE = 'https://p11lab.org/attestations/source-admission/v1'
ROUND_PREDICATE_TYPE = 'https://p11lab.org/attestations/round-artifact/v1'
PROMOTION_PREDICATE_TYPE = 'https://p11lab.org/attestations/image-promotion/v1'


def _check_verified(result, profile, identity, context, now, *, predicate_type=PREDICATE_TYPE,
                    subject_name='source-context.json', timestamp_window=None,
                    predicate=None):
    """Apply policy only to JSON returned by the pinned verifier, never a file claim."""
    if predicate is None:
        predicate = {'schema_version': 1}
    if type(result) is not list or len(result) != 1 or type(result[0]) is not dict:
        raise ValueError('ambiguous verified attestations')
    try:
        verified = result[0]['verificationResult']
        cert = verified['signature']['certificate']
        statement = verified['statement']
        timestamps = verified['verifiedTimestamps']
        repo = profile['repository']
        owner = repo.split('/')[0]
        workflow = 'https://github.com/' + repo + '/' + profile['workflow_path'] + '@' + profile['source_ref']
        invocation = (f'https://github.com/{repo}/actions/runs/{identity["run_id"]}'
                      f'/attempts/{identity["attempt"]}')
        expected = {'issuer': 'https://token.actions.githubusercontent.com',
            'subjectAlternativeName': workflow, 'buildSignerURI': workflow,
            'buildSignerDigest': profile['signer_sha'],
            'sourceRepositoryURI': 'https://github.com/' + repo,
            'sourceRepositoryIdentifier': str(profile['repository_id']),
            'sourceRepositoryOwnerURI': 'https://github.com/' + owner,
            'sourceRepositoryOwnerIdentifier': str(profile['owner_id']),
            'sourceRepositoryDigest': profile['source_sha'],
            'sourceRepositoryRef': profile['source_ref'], 'runnerEnvironment': 'github-hosted',
            'runInvocationURI': invocation}
        if type(cert) is not dict or any(cert.get(k) != v for k, v in expected.items()):
            raise ValueError('verified certificate identity mismatch')
        subject = {'name': subject_name, 'digest': {'sha256': hashlib.sha256(context).hexdigest()}}
        if (type(statement) is not dict or statement.get('_type') != 'https://in-toto.io/Statement/v1'
                or statement.get('predicateType') != predicate_type
                or statement.get('subject') != [subject]
                or statement.get('predicate') != predicate):
            raise ValueError('verified source context subject or predicate mismatch')
        if type(timestamps) is not list or not 1 <= len(timestamps) <= 8:
            raise ValueError('missing verified timestamps')
        if now.tzinfo is None:
            raise ValueError('verification clock requires timezone')
        lower, upper = (now - timedelta(seconds=profile['max_age_seconds']), now + timedelta(minutes=5))
        if timestamp_window is not None:
            lower, upper = timestamp_window
        for item in timestamps:
            if type(item) is not dict or item.get('type') not in ('Tlog', 'TimestampAuthority'):
                raise ValueError('invalid verified timestamp type')
            stamp = datetime.fromisoformat(item['timestamp'].replace('Z', '+00:00'))
            if stamp.tzinfo is None or not lower <= stamp <= upper:
                raise ValueError('verified timestamp outside accepted window')
    except (KeyError, TypeError, AttributeError, OverflowError) as error:
        raise ValueError('malformed verified attestation') from error


# Official gh v2.103.2 linux/amd64 release archive SHA256
# 62ccf747115ddc61237efffdde66a3c8f70ba249433dc64f70801089b59c59c8;
# extracted executable hash independently measured from that exact archive.
GH_EXECUTABLE_SHA256 = 'cbfdc94f3a5c0713c0d6df3e0a1d88a59a76b0c52332aad7d21d112f9da2cc0e'


def _read_bounded_file(path, limit):
    from pathlib import Path
    import stat
    p = Path(path)
    status = p.lstat()
    if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1 or status.st_size > limit:
        raise ValueError('unsafe or oversized verifier input')
    with p.open('rb') as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit or len(raw) != status.st_size:
        raise ValueError('verifier input changed or exceeded limit')
    return raw


def _run_verifier(executable, context_path, bundle_path, root_path, root_sha256, profile, output_dir,
                  *, custody=False, round_artifact=False, promotion=False):
    """Run the sealed verifier on snapshots; return only its actual native JSON."""
    import json
    from pathlib import Path
    from .inspection_bounded import bounded_stream
    from .jsonutil import loads

    executable = Path(executable)
    verifier = _read_bounded_file(executable, 64 * 1024 * 1024)
    if hashlib.sha256(verifier).hexdigest() != GH_EXECUTABLE_SHA256:
        raise ValueError('verifier executable digest mismatch')
    if type(custody) is not bool:
        raise ValueError('invalid verifier profile')
    if type(round_artifact) is not bool or (custody and round_artifact):
        raise ValueError('invalid verifier profile')
    if type(promotion) is not bool or ((custody or round_artifact) and promotion):
        raise ValueError('invalid verifier profile')
    context = _read_bounded_file(context_path, (2 if (custody or round_artifact) else 1) * 1024 * 1024)
    bundle = _read_bounded_file(bundle_path, (2 if (custody or round_artifact) else 16) * 1024 * 1024)
    root = _read_bounded_file(root_path, 4 * 1024 * 1024)
    if hashlib.sha256(root).hexdigest() != root_sha256:
        raise ValueError('protected trusted root digest mismatch')
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=False)
    verified_executable = output / 'gh'
    verified_executable.write_bytes(verifier)
    verified_executable.chmod(0o700)
    subject_path = output / ('promotion-context.json' if promotion else
                             ('round-artifact.json' if round_artifact else
                              ('custody-finalization.json' if custody else 'source-context.json')))
    subject_path.write_bytes(context)
    (output / 'bundle.json').write_bytes(bundle)
    (output / 'trusted-root.jsonl').write_bytes(root)
    (output / 'home').mkdir()
    repo = profile['repository']
    signer_workflow = 'github.com/' + repo + '/' + profile['workflow_path']
    cert_identity = 'https://' + signer_workflow + '@' + profile['source_ref']
    argv = [str(verified_executable.absolute()), 'attestation', 'verify', str(subject_path.absolute()),
            '--repo', repo, '--bundle', str((output / 'bundle.json').absolute()),
            '--custom-trusted-root', str((output / 'trusted-root.jsonl').absolute()),
            '--predicate-type', (PROMOTION_PREDICATE_TYPE if promotion else
                                (ROUND_PREDICATE_TYPE if round_artifact else
                                 ('https://p11lab.org/attestations/image-custody/v1' if custody else PREDICATE_TYPE))),
            '--format', 'json',
            '--signer-digest', profile['signer_sha'],
            '--source-digest', profile['source_sha'], '--source-ref', profile['source_ref'],
            '--cert-identity', cert_identity, '--deny-self-hosted-runners']
    env = {'PATH': '/usr/bin:/bin', 'HOME': str((output / 'home').absolute()),
           'GH_CONFIG_DIR': str((output / 'home/config').absolute()),
           'XDG_CACHE_HOME': str((output / 'home/cache').absolute())}
    journal = {}
    try:
        bounded_stream(argv, output / 'verified.json', 16 * 1024 * 1024, 120, env, journal)
        return loads(_read_bounded_file(output / 'verified.json', 16 * 1024 * 1024)), context
    finally:
        (output / 'verifier-journal.json').write_text(json.dumps(journal, sort_keys=True) + '\n')


def load_profile(environment, channel):
    """Select a controller-installed profile; never accept caller profile files."""
    from importlib.resources import files
    from .jsonutil import loads
    record = loads(files('p11lab').joinpath('data/ci/delivery/source-authority-profiles.json').read_bytes())
    if (type(record) is not dict or set(record) != {'schema_version', 'profiles'}
            or type(record['schema_version']) is not int or record['schema_version'] != 1
            or type(record['profiles']) is not list or len(record['profiles']) > 24):
        raise ValueError('invalid protected source profile catalog')
    matches = [p for p in record['profiles'] if type(p) is dict and p.get('environment') == environment
               and p.get('channel') == channel and p.get('enabled') is True]
    if len(matches) != 1:
        raise ValueError('protected source producer profile unavailable or ambiguous')
    return _validate_profile(matches[0])


def _validate_promotion_signer(signer):
    """Check the optional promotion_signer entry shape (values enroll later)."""
    import re
    keys = {'repository', 'repository_id', 'owner_id', 'workflow_path',
            'signer_sha', 'source_sha', 'source_ref'}
    if type(signer) is not dict or set(signer) != keys:
        raise ValueError('invalid protected source profile')
    if (type(signer['repository']) is not str
            or not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', signer['repository'])
            or type(signer['workflow_path']) is not str
            or not re.fullmatch(r'\.github/workflows/[A-Za-z0-9_.-]+\.yml', signer['workflow_path'])
            or type(signer['source_ref']) is not str
            or not re.fullmatch(r'refs/heads/[A-Za-z0-9._/-]+', signer['source_ref'])):
        raise ValueError('invalid protected source profile')
    if (any(type(signer[key]) is not int or signer[key] <= 0 for key in ('repository_id', 'owner_id'))
            or any(type(signer[key]) is not str or not re.fullmatch(r'[0-9a-f]{40}', signer[key])
                   for key in ('signer_sha', 'source_sha'))):
        raise ValueError('invalid protected source profile')
    return signer


def _validate_profile(profile):
    import re
    fields = {'enabled', 'environment', 'channel', 'repository', 'repository_id', 'owner_id',
              'workflow_path', 'workflow_id', 'signer_sha', 'source_sha', 'source_ref',
              'job', 'policy_sha256', 'review_sha256', 'controller_sha256', 'role', 'root_sha256',
              'max_age_seconds', 'environment_id', 'reviewer_ids', 'graph'}
    if (type(profile) is not dict
            or (set(profile) != fields and set(profile) != fields | {'promotion_signer'})
            or profile['enabled'] is not True):
        raise ValueError('invalid protected source profile')
    if any(type(profile[k]) is not str for k in ('environment', 'channel', 'repository', 'workflow_path',
                                                 'source_ref', 'job', 'role')):
        raise ValueError('invalid protected source profile identity')
    if (not re.fullmatch(r'[a-z0-9]+(?:-[a-z0-9]+)*', profile['environment'])
            or profile['channel'] != 'release'
            or not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', profile['repository'])
            or profile['workflow_path'] != '.github/workflows/provider-delivery.yml'
            or not re.fullmatch(r'refs/heads/[A-Za-z0-9._/-]+', profile['source_ref'])
            or not re.fullmatch(r'[A-Za-z0-9 _.-]{1,100}', profile['job'])
            or profile['role'] != 'source-producer'):
        raise ValueError('invalid protected source profile identity')
    if (any(type(profile[k]) is not int or profile[k] <= 0 for k in ('repository_id', 'owner_id', 'workflow_id', 'environment_id'))
            or type(profile['reviewer_ids']) is not list or not profile['reviewer_ids']
            or len(profile['reviewer_ids']) > 6
            or any(type(x) is not int or x <= 0 for x in profile['reviewer_ids'])
            or profile['reviewer_ids'] != sorted(set(profile['reviewer_ids']))
            or any(type(profile[k]) is not str or not re.fullmatch(r'[0-9a-f]{40}', profile[k])
                   for k in ('signer_sha', 'source_sha'))
            or any(type(profile[k]) is not str or not re.fullmatch(r'[0-9a-f]{64}', profile[k])
                   for k in ('policy_sha256', 'review_sha256', 'controller_sha256', 'root_sha256'))
            or type(profile['max_age_seconds']) is not int or not 60 <= profile['max_age_seconds'] <= 86400):
        raise ValueError('unresolved protected source profile pins')
    graph = profile['graph']
    if (type(graph) is not list or not 1 <= len(graph) <= 100
            or any(type(row) is not dict or set(row) != {'path', 'sha256'}
                   or type(row['path']) is not str or type(row['sha256']) is not str
                   or not re.fullmatch(r'[0-9a-f]{64}', row['sha256']) for row in graph)
            or not ({profile['workflow_path']} | {'src/p11lab/' + name for name in (
                'publish.py', 'cli.py', 'sources.py', 'licenses.py', 'source_transport.py',
                'delivery_authority.py', 'inspection_bounded.py', 'bounded_run.py',
                'image_validation.py', 'round_core/artifacts.py', 'round_core/inputs.py',
                'data/ci/delivery/validation-policy.json')}) <= {row['path'] for row in graph}):
        raise ValueError('protected workflow/controller graph is missing')
    if 'promotion_signer' in profile:
        _validate_promotion_signer(profile['promotion_signer'])
    return profile


def _check_active_metadata(profile, identity, attempt, jobs):
    """Check current attempt and active job without requiring job completion."""
    try:
        if (type(identity['run_id']) is not int or identity['run_id'] <= 0
                or type(identity['attempt']) is not int or identity['attempt'] <= 0
                or identity['job'] != profile['job']
                or attempt['id'] != identity['run_id'] or attempt['run_attempt'] != identity['attempt']
                or attempt['workflow_id'] != profile['workflow_id']
                or attempt['head_sha'] != profile['source_sha']
                or attempt['repository']['id'] != profile['repository_id']
                or attempt['repository']['owner']['id'] != profile['owner_id']
                or attempt['status'] != 'in_progress'):
            raise ValueError('active workflow identity mismatch')
        rows = jobs['jobs']
        if type(rows) is not list or jobs['total_count'] != len(rows) or len(rows) > 100:
            raise ValueError('incomplete active workflow jobs')
        selected = [row for row in rows if row.get('name') == profile['job']]
        if len(selected) != 1:
            raise ValueError('ambiguous active producer job')
        job = selected[0]
        if (job.get('run_id') != identity['run_id'] or job.get('head_sha') != profile['source_sha']
                or job.get('status') != 'in_progress'):
            raise ValueError('active producer job mismatch')
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError('malformed active workflow metadata') from error


def _clock():
    return datetime.now(timezone.utc)


def _github_transport(repository, token):
    from .round_core.artifacts import GitHubTransport
    return GitHubTransport(repository, token)


def verify_active_context(*, environment, channel, context_path, bundle_path, executable,
                          trusted_root, run_id, attempt, token, output_dir):
    """Verify an attestation and the selected currently running protected job.

    Return the authenticated context claim only. The caller must independently
    recompute and compare every content/rights/validation binding before D.
    """
    from pathlib import Path
    from .jsonutil import loads
    profile = load_profile(environment, channel)
    _check_local_controller(profile)
    identity = {'run_id': run_id, 'attempt': attempt, 'job': profile['job']}
    if (type(run_id) is not int or run_id <= 0 or type(attempt) is not int or attempt <= 0
            or type(token) is not str or not token):
        raise ValueError('missing protected run identity or Actions read token')
    result, raw = _run_verifier(executable, context_path, bundle_path, trusted_root,
                                profile['root_sha256'], profile, output_dir)
    _check_verified(result, profile, identity, raw, _clock())
    context = loads(raw)
    if (type(context) is not dict or set(context) != {'schema_version', 'environment', 'channel',
            'role', 'run', 'policy_sha256', 'review_sha256', 'profile_sha256', 'controller_sha256', 'payload'}
            or type(context['schema_version']) is not int or context['schema_version'] != 1
            or context['environment'] != environment or context['channel'] != channel
            or context['role'] != profile['role'] or context['run'] != identity
            or context['policy_sha256'] != profile['policy_sha256']
            or context['review_sha256'] != profile['review_sha256']
            or context['profile_sha256'] != _profile_digest(profile)
            or context['controller_sha256'] != profile['controller_sha256']
            or type(context['payload']) is not dict):
        raise ValueError('attested context does not match protected profile')
    _authenticate_live_run(profile, run_id, attempt, token, shard_journal=Path(output_dir) / 'shard-graph.json')
    return context


def _authenticate_live_run(profile, run_id, attempt, token, *, shard_journal=None):
    import time
    if (type(run_id) is not int or run_id <= 0 or type(attempt) is not int or attempt != 1
            or type(token) is not str or not token):
        raise ValueError('missing protected run identity or Actions read token')
    _check_local_controller(profile)
    identity = {'run_id': run_id, 'attempt': attempt, 'job': profile['job']}
    transport = _github_transport(profile['repository'], token)
    deadline = time.monotonic() + 60
    def check_metadata():
        run = transport._metadata(f'/actions/runs/{run_id}/attempts/{attempt}', deadline)
        jobs = transport._metadata(f'/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100', deadline)
        _check_active_metadata(profile, identity, run, jobs)
        return run
    run = check_metadata()
    protection = _load_protection(transport, profile, run_id, run, deadline)
    _check_controller_graph(profile['graph'], lambda path: transport.source_file(profile['source_sha'], path),
                            transport=transport, revision=profile['source_sha'], shard_journal=shard_journal)
    second_run = check_metadata()
    if _load_protection(transport, profile, run_id, second_run, deadline) != protection:
        raise ValueError('protected environment or approval changed during readback')
    return protection


def _installed_control_file(name):
    from importlib.resources import files
    prefix = 'src/p11lab/'
    if not name.startswith(prefix):
        raise ValueError('invalid installed controller path')
    return files('p11lab').joinpath(name.removeprefix(prefix)).read_bytes()


def _check_local_controller(profile):
    from pathlib import Path
    if _controller_digest(Path(__file__).parent) != profile['controller_sha256']:
        raise ValueError('installed controller package identity mismatch')
    policy = _installed_control_file('src/p11lab/data/ci/delivery/validation-policy.json')
    if hashlib.sha256(policy).hexdigest() != profile['policy_sha256']:
        raise ValueError('installed validation policy identity mismatch')


def _check_controller_graph(graph, fetch, *, transport=None, revision=None, shard_journal=None):
    from .image_custody import _read_custody_policy
    from .round_core.artifacts import VerifiedCustodySourceShards, verify_profile_graph
    _, selectors = _read_custody_policy()
    prefix = 'src/p11lab/data/ci/delivery/custody-components/'
    declared = [row for row in graph if row.get('path', '').startswith(prefix)]
    expected = [{'path': row['path'], 'sha256': row['sha256']} for row in selectors]
    if sorted(declared, key=lambda item: item['path']) != expected:
        raise ValueError('protected custody policy shard graph mismatch')
    shards = None
    if selectors:
        if transport is None or revision is None or shard_journal is None:
            raise ValueError('custody source shards require typed bounded transport and journal')
        shards = transport.source_custody_shards(revision, selectors, journal_path=shard_journal)
        if (type(shards) is not VerifiedCustodySourceShards
                or shards.facts() != {'repository': transport.repository, 'revision': revision, 'selectors': selectors}):
            raise ValueError('custody source shard transport identity mismatch')
    paths = {row['path'] for row in selectors}
    def verified_fetch(path):
        return shards.bytes_for(path) if path in paths and shards is not None else fetch(path)
    verify_profile_graph(graph, verified_fetch)
    for row in graph:
        if row['path'].startswith('src/p11lab/'):
            if hashlib.sha256(_installed_control_file(row['path'])).hexdigest() != row['sha256']:
                raise ValueError('installed controller source mismatch')


def _review_digest(inventory):
    """Bind protected review declarations, with cache paths and candidate facts removed."""
    import copy
    import json
    from .sources import _portable_inventory
    material = copy.deepcopy(inventory)
    if material.get('artifact') is None:
        material['artifact'] = {'kind': 'docker-local'}
    if material.get('observation') is None:
        material['observation'] = {'artifact': {'kind': 'docker-local'}}
    portable = _portable_inventory(material)
    review = {key: value for key, value in portable.items() if key not in ('artifact', 'observation', 'build_key')}
    raw = json.dumps(review, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
    return hashlib.sha256(raw).hexdigest()


def _controller_digest(root):
    import json
    from pathlib import Path
    root = Path(root)
    entries = []
    for path in sorted(root.rglob('*')):
        if path.is_symlink():
            raise ValueError('controller package contains symlink')
        if not path.is_file() or '__pycache__' in path.parts or path.suffix == '.pyc':
            continue
        name = path.relative_to(root).as_posix()
        if name == 'data/ci/delivery/source-authority-profiles.json':
            continue
        raw = _read_bounded_file(path, 16 * 1024 * 1024)
        entries.append({'path': name, 'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})
        if len(entries) > 10000:
            raise ValueError('controller package file bound exceeded')
    if not entries:
        raise ValueError('controller package empty')
    return hashlib.sha256(json.dumps(entries, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def _verify_validation_package(root, artifact, observation, policy_sha256, build_key, control_revision, validation_policy=None, journal_dir=None, *, replay_binding=None):
    """Rehash the bounded local validation package and match the exact candidate."""
    import re
    import tarfile
    from dataclasses import asdict
    from pathlib import Path, PurePosixPath
    from .jsonutil import loads
    from .image_validation import _source_digest, check_evidence_roster
    from .checker import load_profile
    from .publish import _regular_file
    if replay_binding is not None:
        from .round_core.evaluator_replay import EvaluatorReplayBinding
        if type(replay_binding) is not EvaluatorReplayBinding:
            raise TypeError('typed evaluator replay binding required')
    root = Path(root)
    validation_path = _regular_file(root / 'validation.json', 'local validation')
    raw = _read_bounded_file(validation_path, 16 * 1024 * 1024)
    try:
        value = loads(raw)
        distribution = observation['distribution']
        package = value['package']
        body = value['body']
        archive = _regular_file(root / 'package.tar.gz', 'local validation package')
        if (package['path'] != 'package.tar.gz' or type(package['size']) is not int
                or package['size'] != archive.stat().st_size or package['size'] > 512 * 1024 * 1024
                or type(package['sha256']) is not str or not re.fullmatch(r'[0-9a-f]{64}', package['sha256'])):
            raise ValueError('invalid validation package identity')
        if (body['path'] != 'validation-body.json' or type(body['size']) is not int
                or body['size'] > 16 * 1024 * 1024
                or type(body['sha256']) is not str or not re.fullmatch(r'[0-9a-f]{64}', body['sha256'])):
            raise ValueError('invalid validation body identity')
        with archive.open('rb') as stream:
            if hashlib.file_digest(stream, 'sha256').hexdigest() != package['sha256']:
                raise ValueError('validation package digest mismatch')
        observed = {}
        manifest_raw = None
        body_raw = None
        total = 0
        with tarfile.open(archive, 'r|gz') as tar:
            for member in tar:
                name = member.name
                path = PurePosixPath(name)
                if (not member.isfile() or path.is_absolute() or not name or '\\' in name
                        or any(part in ('', '.', '..') for part in name.split('/'))
                        or name in observed or member.size > 256 * 1024 * 1024 or len(observed) >= 10000):
                    raise ValueError('unsafe validation package member')
                total += member.size
                if total > 512 * 1024 * 1024:
                    raise ValueError('validation package byte bound exceeded')
                stream = tar.extractfile(member)
                digest, size = hashlib.sha256(), 0
                capture = bytearray()
                body_capture = bytearray()
                while block := stream.read(1024 * 1024):
                    size += len(block)
                    digest.update(block)
                    if name == 'evidence-manifest.json':
                        if size > 2 * 1024 * 1024:
                            raise ValueError('validation manifest byte bound exceeded')
                        capture.extend(block)
                    elif name == 'validation-body.json' and size <= 16 * 1024 * 1024:
                        body_capture.extend(block)
                if size != member.size:
                    raise ValueError('truncated validation package member')
                observed[name] = {'path': name, 'size': size, 'sha256': digest.hexdigest()}
                if name == 'evidence-manifest.json':
                    manifest_raw = bytes(capture)
                elif name == 'validation-body.json':
                    body_raw = bytes(body_capture)
        if manifest_raw is None:
            raise ValueError('validation package manifest missing')
        manifest = loads(manifest_raw)
        entries = manifest['files']
        if (type(manifest) is not dict or set(manifest) != {'files'} or type(entries) is not list
                or entries != [observed[name] for name in sorted(observed) if name != 'evidence-manifest.json']):
            raise ValueError('validation package roster mismatch')
        check_evidence_roster(observed, len(load_profile()['nodes']))
        enclosed = observed['validation-body.json']
        if enclosed['size'] != body['size'] or enclosed['sha256'] != body['sha256']:
            raise ValueError('validation body digest mismatch')
        gates = loads(body_raw)
        if gates != {key: item for key, item in value.items() if key not in ('package', 'body')}:
            raise ValueError('validation body differs from envelope')
        binding = gates['image_binding']
        if (gates['schema_version'] != 1 or gates['kind'] != 'local-image-validation'
                or gates['artifact'] != asdict(artifact) or gates['status'] != 'observations-complete'
                or gates['sharing'] != 'local-evidence-package' or gates['infrastructure_errors'] != []
                or gates['fixed_policy_sha256'] != policy_sha256 or gates['control_source_sha256'] != _source_digest()
                or gates['control_base_revision_declared'] != control_revision
                or binding['engine_id'] != artifact.reference or binding['build_key_label'] != build_key
                or binding['config_sha256'] != distribution['config_sha256']
                or binding['layers'] != distribution['layers'] or not binding['layers']
                or gates['checker']['summary']['incomplete'] is not False
                or gates['consumer']['app_returncode'] != 0
                or gates['admission']['admission']['admitted'] is not True
                or gates['oracle']['cleanup_errors'] != []):
            raise ValueError('local validation candidate, policy or completeness mismatch')
        controls = gates['oracle']['controls']
        if set(controls) != {'positive', 'altered_message', 'altered_signature'}:
            raise ValueError('oracle control roster mismatch')
        for name, code in (('positive', 0), ('altered_message', 1), ('altered_signature', 1)):
            row = controls[name]
            if row['returncode'] != code or row['timed_out'] is not False or row['cleanup'] != 'removed-exact-owned-container':
                raise ValueError('oracle control or cleanup incomplete')
        if validation_policy is None:
            raise ValueError('sealed validation policy required to recompute evidence')
        from .image_validation import verify_evidence_package
        if replay_binding is None:
            verify_evidence_package(archive, observed, gates, artifact, validation_policy, journal_dir)
        else:
            verify_evidence_package(archive, observed, gates, artifact, validation_policy, journal_dir,
                                    replay_binding=replay_binding)
        return {'validation_sha256': hashlib.sha256(raw).hexdigest(), 'package_sha256': package['sha256'],
                'body_sha256': body['sha256'], 'config_sha256': binding['config_sha256'], 'layers': binding['layers']}
    except (KeyError, TypeError, AttributeError, tarfile.TarError) as error:
        raise ValueError('malformed local validation evidence') from error


def prepare_source(*, environment, channel, artifact, inventory_path, validation_dir,
                   build_receipt, sealed_dir, output_dir, run_id, attempt, token, validation_policy=None):
    """Pre-publication rights and exact-candidate checks in the active trusted job.

    This returns a local source-publishing precondition, not D or promotion.
    """
    from pathlib import Path
    from .catalog import load_environment
    from .inspection_bounded import InspectionPolicy
    from .jsonutil import loads
    from .licenses import assess_distribution
    from .models import ArtifactRef
    from .publish import _claimed_artifact_blocker, check_input_match, verify_readback
    from .sources import collect_source_bundle
    if environment != 'softhsm2' or channel != 'release':
        raise ValueError('source admission currently supports softhsm2 release only')
    if (type(artifact) is not ArtifactRef or artifact.kind != 'docker-local'
            or artifact.reference != 'sha256:' + artifact.sha256 or artifact.platform != 'linux/amd64'):
        raise ValueError('source preparation requires exact local linux image')
    profile = load_profile(environment, channel)
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=False)
    _authenticate_live_run(profile, run_id, attempt, token, shard_journal=output / 'shard-graph.json')
    inventory = loads(_read_bounded_file(inventory_path, 16 * 1024 * 1024))
    if type(inventory) is not dict or _review_digest(inventory) != profile['review_sha256']:
        raise ValueError('protected source review inventory mismatch')
    binding = _claimed_artifact_blocker(artifact_kind=artifact.kind, artifact_reference=artifact.reference,
        artifact_digest=artifact.sha256, build_receipt_path=build_receipt, platform=artifact.platform)
    if binding:
        raise ValueError(binding)
    transcript = output / 'local-check.txt'
    transcript.write_text('Local source inspection only; no network authentication.\n')
    sealed_dir = Path(sealed_dir)
    verify_readback(sealed_dir / 'sealed-source.json', sealed_dir,
                    transcript_path=transcript, extract_dir=output / 'sealed')
    sealed = loads(_read_bounded_file(output / 'sealed/sealed.json', 4 * 1024 * 1024))
    spec = load_environment(environment, channel)
    _require_covered_build_assets(spec)
    matched = check_input_match(sealed, build_receipt, spec)
    if inventory.get('build_key') != matched['build_key']:
        raise ValueError('review inventory build key mismatch')
    validation = _verify_validation_package(validation_dir, artifact, inventory['observation'],
                                            profile['policy_sha256'], matched['build_key'], profile['source_sha'], validation_policy,
                                            output / 'validation-replay')
    collect_source_bundle(artifact, inventory, output / 'evidence', inspection_policy=InspectionPolicy(),
                          journal_path=output / 'collection-inspection.json')
    content = assess_distribution(artifact, output / 'evidence', inspection_policy=InspectionPolicy(),
                                  journal_path=output / 'assessment-inspection.json')
    if content['status'] != 'eligible':
        raise ValueError('actual source rights/content assessment blocked: ' + '; '.join(content['blockers']))
    return {'status': 'source-publication-preconditions-met', 'distribution_authority': 'not-yet-attested',
            'build_key': matched['build_key'], 'review_sha256': profile['review_sha256'],
            'validation': validation, 'source_evidence_dir': str(output / 'evidence')}


def _profile_digest(profile):
    import json
    return hashlib.sha256(json.dumps(profile, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def _make_context(environment, channel, profile, identity, facts):
    return {'schema_version': 1, 'environment': environment, 'channel': channel,
            'role': profile['role'], 'run': identity, 'policy_sha256': profile['policy_sha256'],
            'review_sha256': profile['review_sha256'], 'profile_sha256': _profile_digest(profile),
            'controller_sha256': profile['controller_sha256'], 'payload': facts}


def _source_facts(*, environment, channel, artifact, evidence_dir, validation_dir, build_receipt,
                  sealed_dir, registry, seal_digest, content_digest, output_dir, profile, validation_policy=None,
                  replay_binding=None):
    """Reacquire both exact source artifacts and recompute local delivery facts."""
    from dataclasses import asdict
    from pathlib import Path
    from . import publish, source_transport
    from .catalog import load_environment
    from .inspection_bounded import InspectionPolicy
    from .jsonutil import loads
    from .licenses import assess_distribution
    from .models import ArtifactRef
    from .sources import checksum
    if replay_binding is not None:
        from .round_core.evaluator_replay import EvaluatorReplayBinding
        if type(replay_binding) is not EvaluatorReplayBinding:
            raise TypeError('typed evaluator replay binding required')
    if (type(artifact) is not ArtifactRef or artifact.kind != 'docker-local'
            or artifact.reference != 'sha256:' + artifact.sha256 or artifact.platform != 'linux/amd64'
            or environment != 'softhsm2' or registry != 'ghcr.io/p11lab/' + environment or channel != 'release'):
        raise ValueError('source readback candidate or selected repository mismatch')
    binding = publish._claimed_artifact_blocker(artifact_kind=artifact.kind, artifact_reference=artifact.reference,
        artifact_digest=artifact.sha256, build_receipt_path=build_receipt, platform=artifact.platform)
    if binding:
        raise ValueError(binding)
    sealed_dir, evidence = Path(sealed_dir), Path(evidence_dir)
    seal_receipt_path = sealed_dir / 'sealed-source.json'
    seal_receipt = loads(_read_bounded_file(seal_receipt_path, 1024 * 1024))
    expected_seal = publish._seal_roster(seal_receipt_path, seal_receipt)
    content_receipt_path = evidence / 'source-companion.json'
    content_receipt = loads(_read_bounded_file(content_receipt_path, 1024 * 1024))
    if (type(content_receipt) is not dict or type(content_receipt.get('artifact')) is not dict
            or not {'sha256'} <= set(content_receipt['artifact'])
            or not {'size_bytes', 'sbom_sha256'} <= set(content_receipt)):
        raise ValueError('malformed local content source receipt')
    spdx = publish._regular_file(evidence / 'sbom.spdx.json', 'local SPDX')
    expected_content = {
        'source-companion.tar.gz': {'sha256': content_receipt['artifact']['sha256'],
                                    'size_bytes': content_receipt['size_bytes'],
                                    'media_type': publish.CONTENT_FILES['source-companion.tar.gz']},
        'source-companion.json': {'sha256': checksum(content_receipt_path),
                                  'size_bytes': content_receipt_path.stat().st_size,
                                  'media_type': publish.CONTENT_FILES['source-companion.json']},
        'sbom.spdx.json': {'sha256': content_receipt['sbom_sha256'],
                           'size_bytes': spdx.stat().st_size, 'media_type': publish.CONTENT_FILES['sbom.spdx.json']}}
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=False)
    source_transport.acquire(registry, seal_digest, expected_seal,
        artifact_type='application/vnd.p11lab.sealed-source.v1', output_dir=output / 'seal-oci')
    source_transport.acquire(registry, content_digest, expected_content,
        artifact_type='application/vnd.p11lab.source-companion.v1', output_dir=output / 'content-oci')
    seal_proof = publish.verify_readback(seal_receipt_path, output/'seal-oci/files',
        transcript_path=output/'seal-oci/transport-journal.json', extract_dir=output/'seal-extract',
        source_manifest_path=output/'seal-oci/manifest.json', source_manifest_digest=seal_digest, registry=registry)
    content_proof = publish.verify_content_readback(content_receipt_path, output/'content-oci/files',
        source_manifest_path=output/'content-oci/manifest.json', source_manifest_digest=content_digest,
        registry=registry, artifact=artifact, transcript_path=output/'content-oci/transport-journal.json',
        extract_dir=output/'content-extract')
    for name, record in expected_content.items():
        local = publish._regular_file(evidence / name, 'local content ' + name)
        if local.stat().st_size != record['size_bytes'] or checksum(local) != record['sha256']:
            raise ValueError('published content differs from locally assessed source: ' + name)
    inventory = loads(_read_bounded_file(output/'content-extract/inventory.json', 16 * 1024 * 1024))
    if _review_digest(inventory) != profile['review_sha256']:
        raise ValueError('protected source review identity mismatch')
    sealed = loads(_read_bounded_file(output/'seal-extract/sealed.json', 4 * 1024 * 1024))
    spec = load_environment(environment, channel)
    _require_covered_build_assets(spec)
    match = publish.check_input_match(sealed, build_receipt, spec)
    if inventory.get('build_key') != match['build_key']:
        raise ValueError('source inventory build key mismatch')
    content = assess_distribution(artifact, evidence, inspection_policy=InspectionPolicy(),
                                  journal_path=output/'assessment-inspection.json')
    if content['status'] != 'eligible':
        raise ValueError('actual source rights/content assessment blocked: ' + '; '.join(content['blockers']))
    validation_args = (validation_dir, artifact, inventory['observation'], profile['policy_sha256'],
                       match['build_key'], profile['source_sha'], validation_policy, output / 'validation-replay')
    if replay_binding is None:
        validation = _verify_validation_package(*validation_args)
    else:
        validation = _verify_validation_package(*validation_args, replay_binding=replay_binding)
    return {'artifact': asdict(artifact), 'build_key': match['build_key'],
            'build_receipt_sha256': checksum(publish._regular_file(build_receipt, 'build receipt')),
            'source': {'sealed': {'reference': seal_proof['reference'], 'manifest_sha256': seal_digest,
                                  'archive_sha256': seal_receipt['archive_sha256'],
                                  'receipt_sha256': checksum(seal_receipt_path)},
                       'content': {key: content_proof[key] for key in ('reference', 'manifest_sha256',
                                   'file_sha256', 'receipt_sha256', 'spdx_sha256', 'inventory_sha256')}},
            'validation': validation}


def prepare_context(*, environment, channel, artifact, evidence_dir, validation_dir, build_receipt,
                    sealed_dir, registry, seal_digest, content_digest, output_dir, run_id, attempt, token, validation_policy=None):
    """Freeze actual source and local validation facts for the attestation subject."""
    from pathlib import Path
    from .receipts import write_receipt
    profile = load_profile(environment, channel)
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=False)
    _authenticate_live_run(profile, run_id, attempt, token, shard_journal=output / 'shard-graph-before.json')
    facts = _source_facts(environment=environment, channel=channel, artifact=artifact,
        evidence_dir=evidence_dir, validation_dir=validation_dir, build_receipt=build_receipt,
        sealed_dir=sealed_dir, registry=registry, seal_digest=seal_digest, content_digest=content_digest,
        output_dir=output/'facts', profile=profile, validation_policy=validation_policy)
    _authenticate_live_run(profile, run_id, attempt, token, shard_journal=output / 'shard-graph-after.json')
    identity = {'run_id': run_id, 'attempt': attempt, 'job': profile['job']}
    context = _make_context(environment, channel, profile, identity, facts)
    write_receipt(output/'source-context.json', context)
    return context


def admit_source(*, environment, channel, artifact, evidence_dir, validation_dir, build_receipt,
                 sealed_dir, registry, seal_digest, content_digest, context_path, bundle_path,
                 executable, trusted_root, output_dir, run_id, attempt, token, validation_policy=None):
    """Authenticate the active producer and recompute D; never authorize exposure."""
    from pathlib import Path
    from .receipts import write_receipt
    profile = load_profile(environment, channel)
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=False)
    actual = verify_active_context(environment=environment, channel=channel, context_path=context_path,
        bundle_path=bundle_path, executable=executable, trusted_root=trusted_root,
        run_id=run_id, attempt=attempt, token=token, output_dir=output/'attestation')
    facts = _source_facts(environment=environment, channel=channel, artifact=artifact,
        evidence_dir=evidence_dir, validation_dir=validation_dir, build_receipt=build_receipt,
        sealed_dir=sealed_dir, registry=registry, seal_digest=seal_digest, content_digest=content_digest,
        output_dir=output/'facts', profile=profile, validation_policy=validation_policy)
    identity = {'run_id': run_id, 'attempt': attempt, 'job': profile['job']}
    expected = _make_context(environment, channel, profile, identity, facts)
    if actual != expected:
        raise ValueError('attested context differs from independently recomputed source facts')
    protection = _authenticate_live_run(profile, run_id, attempt, token, shard_journal=output / 'shard-graph-final.json')
    result = {'schema_version': 1, 'role': 'active-source-admission', 'source_status': 'eligible',
              'scope': 'active producer only; not durable completed-run qualification',
              'image_promotion_status': 'blocked', 'handoff_eligible': False,
              'protection': protection,
              'profile_sha256': _profile_digest(profile), 'context_sha256': hashlib.sha256(
                  _read_bounded_file(output/'attestation/source-context.json', 1024 * 1024)).hexdigest(), 'facts': facts}
    write_receipt(output/'source-admission.json', result)
    return result


def prepare_validation_tools(output_dir):
    """Acquire and build the fixed local checker, C consumer, oracle and evaluator."""
    import json
    from pathlib import Path
    from .docker import Docker
    from .jsonutil import loads
    from .round_core import bootstrap
    from .tool_builds import ToolBuildRequest, build_tool, verify_tool_build
    from .tool_inputs import load_tool_input_lock, resolve_tool_inputs
    profile = load_profile('softhsm2', 'release')
    _check_local_controller(profile)
    output = Path(output_dir).absolute()
    output.mkdir(parents=True, exist_ok=False)
    engine = Docker()
    tools = {}
    for name in ('checker', 'consumer', 'oracle'):
        selected = output / (name + '-inputs')
        resolve_tool_inputs(name, target='debian13-amd64', output_dir=selected)
        lock = load_tool_input_lock(name, target='debian13-amd64')
        engine.command(['pull', '--platform', 'linux/amd64', lock['base_image']], timeout=300)
        root = output / (name + '-build')
        receipt = selected / 'resolved-inputs.json'
        result = build_tool(ToolBuildRequest(name, receipt, root))
        if result['status'] != 'installed-local-only':
            raise ValueError('fixed local validation tool build incomplete: ' + name)
        manifest = root / 'manifest.json'
        digest = hashlib.sha256(_read_bounded_file(manifest, 16 * 1024 * 1024)).hexdigest()
        verify_tool_build(root, receipt_path=receipt, manifest_sha256=digest)
        tools[name] = {'root': str(root), 'input_receipt': str(receipt), 'manifest_sha256': digest}
    lock_root = Path(bootstrap.__file__).parent.parent / 'data/rounds/evaluator'
    source = loads(_read_bounded_file(lock_root/'source.json', 4 * 1024 * 1024))
    evaluator_root = output/'evaluator'
    receipt = bootstrap.acquire_evaluator(source, lock_root, evaluator_root)
    bootstrap.verify_receipt(receipt, evaluator_root, lock_root)
    evaluator_sha = hashlib.sha256(_read_bounded_file(evaluator_root/'evaluator-build-receipt.json', 16 * 1024 * 1024)).hexdigest()
    policy = {'tools': tools, 'evaluator': {'root': str(evaluator_root), 'receipt_sha256': evaluator_sha},
              'control_base_revision': profile['source_sha']}
    (output/'validation-policy.json').write_text(json.dumps(policy, sort_keys=True, indent=2) + '\n')
    return policy


def materialize_inventory(*, artifact, build_receipt, output_dir):
    """Bind the installed owner-reviewed template to one exact local image."""
    import json
    from dataclasses import asdict
    from importlib.resources import files
    from pathlib import Path
    from .inspection_bounded import InspectionPolicy
    from .jsonutil import loads
    from .licenses import inspect_artifact, validate_inventory
    from .models import ArtifactRef
    from .publish import _claimed_artifact_blocker
    profile = load_profile('softhsm2', 'release')
    _check_local_controller(profile)
    if (type(artifact) is not ArtifactRef or artifact.kind != 'docker-local'
            or artifact.reference != 'sha256:' + artifact.sha256 or artifact.platform != 'linux/amd64'):
        raise ValueError('inventory requires exact local linux candidate')
    error = _claimed_artifact_blocker(artifact_kind=artifact.kind, artifact_reference=artifact.reference,
        artifact_digest=artifact.sha256, build_receipt_path=build_receipt, platform=artifact.platform)
    if error:
        raise ValueError(error)
    build = loads(_read_bounded_file(build_receipt, 4 * 1024 * 1024))
    template = loads(files('p11lab').joinpath('data/ci/delivery/softhsm2-release.inventory.json').read_bytes())
    if (type(template) is not dict or template.get('artifact') is not None
            or template.get('observation') is not None or template.get('build_key') is not None):
        raise ValueError('invalid installed reviewed inventory template')
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=False)
    template['artifact'] = asdict(artifact)
    template['build_key'] = build['build_key']
    template['observation'] = inspect_artifact(artifact, inspection_policy=InspectionPolicy(),
                                               journal_path=output/'inspection.json')
    if _review_digest(template) != profile['review_sha256']:
        raise ValueError('installed source review template differs from protected profile')
    reasons = validate_inventory(artifact, template)
    if reasons:
        raise ValueError('installed source review template is incomplete: ' + '; '.join(reasons))
    (output/'inventory.json').write_text(json.dumps(template, sort_keys=True, indent=2) + '\n')
    return {'status': 'local-reviewed-inventory', 'review_sha256': profile['review_sha256']}


def _check_protection(profile, environment, branches, approvals, run):
    """Check owner-pinned environment rules and real first-attempt approval history."""
    try:
        if (environment['id'] != profile['environment_id'] or environment['name'] != 'source-delivery'
                or environment['deployment_branch_policy'] != {'protected_branches': False, 'custom_branch_policies': True}):
            raise ValueError('protected source delivery environment mismatch')
        rules = [r for r in environment['protection_rules'] if r.get('type') == 'required_reviewers']
        if len(rules) != 1 or rules[0]['prevent_self_review'] is not True:
            raise ValueError('independent required reviewer protection missing')
        rows = rules[0]['reviewers']
        if (type(rows) is not list or any(r.get('type') != 'User' or type(r.get('reviewer', {}).get('id')) is not int for r in rows)
                or sorted(r['reviewer']['id'] for r in rows) != profile['reviewer_ids']):
            raise ValueError('protected reviewer roster mismatch')
        branch_rows = branches['branch_policies']
        if (type(branch_rows) is not list or branches['total_count'] != 1 or len(branch_rows) != 1
                or branch_rows[0]['name'] != profile['source_ref'].removeprefix('refs/heads/')
                or branch_rows[0].get('type', 'branch') != 'branch'):
            raise ValueError('protected deployment branch policy mismatch')
        if type(approvals) is not list or len(approvals) > 100:
            raise ValueError('invalid workflow approval history')
        matches = [a for a in approvals if any(e.get('id') == profile['environment_id']
                                                for e in a.get('environments', []))]
        if len(matches) != 1:
            raise ValueError('missing or ambiguous environment approval')
        approved = matches[0]
        reviewer = approved['user']['id']
        actor = run['triggering_actor']['id']
        if (approved['state'] != 'approved' or type(reviewer) is not int or type(actor) is not int
                or reviewer not in profile['reviewer_ids'] or reviewer == actor
                or not any(e.get('id') == profile['environment_id'] and e.get('name') == 'source-delivery'
                           for e in approved['environments'])):
            raise ValueError('independent environment approval mismatch')
        return {'environment_id': profile['environment_id'], 'reviewer_id': reviewer, 'actor_id': actor}
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError('malformed environment protection or approval metadata') from error


def _load_protection(transport, profile, run_id, run, deadline):
    from .jsonutil import loads
    environment = transport._metadata('/environments/source-delivery', deadline)
    branches = transport._metadata('/environments/source-delivery/deployment-branch-policies?per_page=100', deadline)
    status, _, raw = transport._request(transport._base + f'/actions/runs/{run_id}/approvals',
                                        transport._token, 2 * 1024 * 1024, deadline)
    if status != 200:
        raise ValueError('unexpected approval history redirect')
    return _check_protection(profile, environment, branches, loads(raw), run)


def controller_identity():
    """Report local enrollment input hashes without asserting owner authorization."""
    from pathlib import Path
    from .jsonutil import loads
    root = Path(__file__).parent
    catalog_raw = _read_bounded_file(root/'data/ci/delivery/source-authority-profiles.json', 4 * 1024 * 1024)
    catalog = loads(catalog_raw)
    template = loads(_read_bounded_file(root/'data/ci/delivery/softhsm2-release.inventory.json', 16 * 1024 * 1024))
    policy = _read_bounded_file(root/'data/ci/delivery/validation-policy.json', 1024 * 1024)
    return {'authority': 'unverified-local-identities', 'controller_sha256': _controller_digest(root),
            'profile_catalog_sha256': hashlib.sha256(catalog_raw).hexdigest(),
            'review_sha256': _review_digest(template), 'policy_sha256': hashlib.sha256(policy).hexdigest(),
            'configured_profiles': len(catalog['profiles'])}


def _require_covered_build_assets(spec):
    """Block copied asset roles absent from the current runtime input projection."""
    covered = {'recipe', 'build-helper', 'adapter', 'adapter-common', 'notice'}
    assets = spec['lock']['assets']
    if type(assets) is not list or any(type(a) is not dict or a.get('role') not in covered for a in assets):
        raise ValueError('build input projection omits a copied asset role')
