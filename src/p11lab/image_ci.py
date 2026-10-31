"""Deterministic source-level image work selection; no evidence admission."""

import copy
import hashlib
import json
import re
from pathlib import PurePosixPath

from .build import runtime_inputs
from .catalog import load_environment, validate_build_inputs
from .identity import IdentityError, _ref, artifact_key


class ImageCIError(ValueError):
    """Invalid or ambiguous scheduling input."""


_SHA = re.compile(r'^[0-9a-f]{64}$')
_NAME = re.compile(r'^[a-z0-9][a-z0-9._-]{0,63}$')
_SECRET = re.compile(r'(?:^|[._/-])(?:pin|password|secret|credential|private[_-]key|api[_-]key|access[_-]token)(?:$|[._/-])', re.I)
_CONTENT = {'data', 'profile', 'config', 'initialization', 'selection', 'obligations', 'limits'}


def _require(condition, message):
    if not condition:
        raise ImageCIError(message)


def _digest(value):
    _require(isinstance(value, str) and _SHA.fullmatch(value) is not None, 'expected full sha256')


def _object(value, keys):
    _require(isinstance(value, dict) and set(value) == keys, 'unexpected or missing fields')


def _path(value):
    _require(isinstance(value, str) and value and '\\' not in value, 'invalid path')
    path = PurePosixPath(value)
    _require(bool(path.parts) and not path.is_absolute() and str(path) == value and all(p not in ('.', '..') for p in path.parts) and all(ord(c) >= 32 for c in value) and not _SECRET.search(value), 'noncanonical or credential path')
    return value


def _canonical(value):
    try:
        raw = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as error:
        raise ImageCIError('finite JSON required') from error
    _require(len(raw.encode()) <= 1048576, 'input too large')
    return raw


def experiment_key(inputs):
    """Hash a closed logical experiment projection, excluding physical attempts."""
    inputs = copy.deepcopy(inputs)
    _object(inputs, {'provider', 'policy_sha256', 'tools', 'content', 'roster', 'input_paths'})
    provider = inputs['provider']
    _object(provider, {'artifact', 'build_key', 'provenance_sha256'})
    try:
        _ref(provider['artifact'])
        _require(provider['artifact']['kind'] in {'oci', 'docker-local'}, 'image artifact required')
        if provider['artifact']['kind'] == 'oci':
            _require(re.fullmatch(r'[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}', provider['artifact']['reference']) is not None, 'invalid OCI reference')
    except (IdentityError, TypeError, KeyError) as error:
        raise ImageCIError('invalid immutable artifact') from error
    _digest(provider['build_key'])
    _digest(provider['provenance_sha256'])
    _digest(inputs['policy_sha256'])
    tools = inputs['tools']
    _require(isinstance(tools, dict) and 0 < len(tools) <= 32, 'fixed tools required')
    for name, tool in tools.items():
        _require(isinstance(name, str) and _NAME.fullmatch(name) is not None and not _SECRET.search(name), 'invalid tool name')
        _object(tool, {'source', 'build', 'dependencies', 'installed'})
        for digest in tool.values():
            _digest(digest)
    _object(inputs['content'], _CONTENT)
    for digest in inputs['content'].values():
        _digest(digest)
    input_paths = inputs['input_paths']
    _require(isinstance(input_paths, dict) and len(input_paths) <= 10000, 'invalid input paths')
    for path, digest in input_paths.items():
        _path(path)
        _digest(digest)
    roster = inputs['roster']
    _require(isinstance(roster, list) and 0 < len(roster) <= 4096, 'logical roster required')
    seen = set()
    for cell in roster:
        _object(cell, {'leg', 'shard', 'repetition'})
        _require(all(isinstance(cell[k], str) and _NAME.fullmatch(cell[k]) is not None for k in ('leg', 'shard')), 'invalid logical cell')
        _require(type(cell['repetition']) is int and 0 <= cell['repetition'] < 1000000, 'invalid repetition')
        key = (cell['leg'], cell['shard'], cell['repetition'])
        _require(key not in seen, 'duplicate logical cell')
        seen.add(key)
    canonical = _canonical({'schema_version': 1, 'kind': 'image-experiment', 'inputs': inputs})
    return hashlib.sha256(canonical.encode()).hexdigest()


def _freeze_experiment(experiment, build_key, platform, pending):
    projection = {'schema_version': 1, 'expected_build_key': build_key,
                  'expected_platform': platform, 'experiment': copy.deepcopy(experiment)}
    if pending:
        projection['experiment']['provider'] = None
    digest = hashlib.sha256(_canonical(projection).encode()).hexdigest()
    return projection | {'sha256': digest}


def bind_rebuilt_experiment(frozen, provider):
    """Bind a declared new provider to a frozen rebuild projection, not evidence."""
    frozen, provider = copy.deepcopy(frozen), copy.deepcopy(provider)
    _object(frozen, {'schema_version', 'expected_build_key', 'expected_platform', 'experiment', 'sha256'})
    _require(type(frozen['schema_version']) is int and frozen['schema_version'] == 1, 'invalid frozen projection version')
    _digest(frozen['sha256'])
    body = {k: v for k, v in frozen.items() if k != 'sha256'}
    _require(hashlib.sha256(_canonical(body).encode()).hexdigest() == frozen['sha256'], 'frozen projection digest mismatch')
    _digest(frozen['expected_build_key'])
    _require(isinstance(frozen['expected_platform'], str) and re.fullmatch(r'[a-z0-9]+/[a-z0-9]+', frozen['expected_platform']) is not None, 'invalid expected platform')
    experiment = frozen['experiment']
    _object(experiment, {'provider', 'policy_sha256', 'tools', 'content', 'roster', 'input_paths'})
    _require(experiment['provider'] is None, 'provider is not pending')
    _object(provider, {'artifact', 'build_key', 'provenance_sha256'})
    _require(provider['build_key'] == frozen['expected_build_key'], 'provider build key mismatch')
    experiment['provider'] = provider
    key = experiment_key(experiment)
    _require(provider['artifact']['platform'] == frozen['expected_platform'], 'provider platform mismatch')
    return {'inputs': experiment, 'experiment_key': key}


def select_image_work(policy, changed_paths, previous, *, retry=()):
    """Project fixed selected environments once; previous is a source snapshot, not evidence."""
    policy, changed_paths, previous, retry = copy.deepcopy((policy, changed_paths, previous, retry))
    _require(isinstance(policy, dict) and 0 < len(policy) <= 128 and all(isinstance(name, str) and _NAME.fullmatch(name) is not None for name in policy), 'finite selection required')
    _canonical(policy)
    _require(isinstance(changed_paths, list) and len(changed_paths) <= 10000, 'invalid changed paths')
    paths = [_path(path) for path in changed_paths]
    _require(len(paths) == len(set(paths)), 'duplicate changed path')
    if previous is not None:
        _object(previous, {'schema_version', 'environments'})
        _require(type(previous['schema_version']) is int and previous['schema_version'] == 1 and isinstance(previous['environments'], dict), 'invalid snapshot')
        _canonical(previous)
    _require(isinstance(retry, (list, tuple)) and all(isinstance(x, str) and x in policy for x in retry) and len(retry) == len(set(retry)), 'invalid retry selection')
    old = {} if previous is None else previous['environments']
    snapshot = {}
    runtime_paths = set()
    for environment, selected in sorted(policy.items()):
        _require(isinstance(environment, str) and _NAME.fullmatch(environment) is not None, 'invalid environment')
        _object(selected, {'channel', 'experiment'})
        _require(isinstance(selected['channel'], str) and _NAME.fullmatch(selected['channel']) is not None, 'invalid channel')
        spec = load_environment(environment, selected['channel'])
        validate_build_inputs(spec)
        prefix = 'src/p11lab/data/providers/' + environment + '/'
        runtime_paths.update((prefix + 'provider.json', prefix + spec['channel_spec']['lock']))
        runtime_paths.update(prefix + p['path'] for p in spec['lock']['patches'])
        for asset in spec['lock']['assets']:
            root = 'src/p11lab/data/runtime/' if asset.get('scope') == 'runtime' else prefix
            runtime_paths.add(root + asset['path'])
        build_key = artifact_key('runtime', runtime_inputs(spec))
        exp = experiment_key(selected['experiment'])
        _require(selected['experiment']['provider']['artifact']['platform'] == spec['runtime_platforms'][0], 'provider platform mismatch')
        runtime_paths.update(selected['experiment']['input_paths'])
        snapshot[environment] = {'build_key': build_key, 'experiment_key': exp,
                                 'provider': selected['experiment']['provider']}
    for path in paths:
        if path in runtime_paths or path.startswith('docs/') or path == 'README.md' or (path.startswith('src/p11lab/data/providers/') and path.endswith('/README.md')):
            continue
        raise ImageCIError('unknown changed path requires bounded validation: ' + path)
    _require(set(old) <= set(policy), 'previous snapshot contains unselected environment')
    work = []
    for environment, current in snapshot.items():
        prior = old.get(environment)
        if prior is not None:
            _object(prior, {'build_key', 'experiment_key', 'provider'})
            _digest(prior['build_key'])
            _digest(prior['experiment_key'])
            _object(prior['provider'], {'artifact', 'build_key', 'provenance_sha256'})
            _digest(prior['provider']['build_key'])
            _digest(prior['provider']['provenance_sha256'])
            try:
                _ref(prior['provider']['artifact'])
            except (IdentityError, TypeError, KeyError) as error:
                raise ImageCIError('invalid previous artifact') from error
            _require(prior['provider']['artifact']['kind'] in {'oci', 'docker-local'}, 'invalid previous image')
        action = None
        if current['build_key'] != current['provider']['build_key'] or (prior is not None and current['build_key'] != prior['build_key']):
            action = 'rebuild'
        elif environment in retry or prior is None or prior['experiment_key'] != current['experiment_key']:
            action = 'retest'
        if action:
            experiment = policy[environment]['experiment']
            work.append({'environment': environment, 'action': action,
                         'legs': sorted({cell['leg'] for cell in experiment['roster']}),
                         'provider_build_key': current['build_key'],
                         'provider': current['provider'] if action == 'retest' else None,
                         'experiment_key': current['experiment_key'] if action == 'retest' else None,
                         'policy_sha256': experiment['policy_sha256'],
                         'frozen': _freeze_experiment(experiment, current['build_key'],
                                                      experiment['provider']['artifact']['platform'],
                                                      action == 'rebuild')})
    return json.loads(_canonical({'schema_version': 1, 'work': work,
                                  'snapshot': {'schema_version': 1, 'environments': snapshot}}))
