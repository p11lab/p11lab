import copy

import pytest

from p11lab.build import runtime_inputs
from p11lab.catalog import load_environment
from p11lab.identity import artifact_key
from p11lab.image_ci import ImageCIError, experiment_key, select_image_work


def inputs():
    return {
        'provider': {'artifact': {'kind': 'oci', 'reference': 'registry.example/p@sha256:' + 'a' * 64,
                                  'sha256': 'a' * 64, 'platform': 'linux/amd64'},
                     'build_key': 'b' * 64, 'provenance_sha256': 'c' * 64},
        'policy_sha256': 'd' * 64,
        'tools': {'checker': {'source': '1' * 64, 'build': '2' * 64,
                              'dependencies': '3' * 64, 'installed': '4' * 64}},
        'content': {name: str(i) * 64 for i, name in enumerate(
            ['data', 'profile', 'config', 'initialization', 'selection', 'obligations', 'limits'], 1)},
        'input_paths': {'src/p11lab/data/profiles/example.json': '8' * 64},
        'roster': [{'leg': 'direct', 'shard': '0', 'repetition': 0}],
    }


def test_experiment_changes_with_fixed_content_and_exact_provider():
    base = inputs()
    for path in [('tools', 'checker', 'installed'), ('tools', 'checker', 'dependencies'),
                 ('content', 'data'), ('content', 'profile'), ('provider', 'artifact', 'sha256')]:
        changed = copy.deepcopy(base)
        target = changed
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = 'e' * 64
        if path[-1] == 'sha256':
            changed['provider']['artifact']['reference'] = 'registry.example/p@sha256:' + 'e' * 64
        assert experiment_key(changed) != experiment_key(base)


def test_experiment_rejects_alias_secrets_duplicates_and_unknown_fields():
    for mutate in ('alias', 'secret', 'duplicate', 'unknown'):
        value = inputs()
        if mutate == 'alias':
            value['provider']['artifact']['reference'] = 'registry.example/p:latest'
        elif mutate == 'secret':
            value['content']['password'] = 'x'
        elif mutate == 'duplicate':
            value['roster'].append(value['roster'][0].copy())
        else:
            value['attempt_id'] = 'abc'
        with pytest.raises(ImageCIError):
            experiment_key(value)


def test_docs_without_content_changes_schedule_nothing():
    policy = {'softhsm2': {'channel': 'release', 'experiment': inputs()}}
    policy['softhsm2']['experiment']['provider']['build_key'] = artifact_key('runtime', runtime_inputs(load_environment('softhsm2', 'release')))
    first = select_image_work(policy, [], None)
    unchanged = select_image_work(policy, ['docs/testing.md'], first['snapshot'])
    assert unchanged['work'] == []


def test_tool_change_retests_exact_provider_and_retry_is_not_suppressed():
    data = inputs()
    data['provider']['build_key'] = artifact_key('runtime', runtime_inputs(load_environment('softhsm2', 'release')))
    policy = {'softhsm2': {'channel': 'release', 'experiment': data}}
    first = select_image_work(policy, [], None)
    changed = copy.deepcopy(policy)
    changed['softhsm2']['experiment']['tools']['checker']['installed'] = 'f' * 64
    changed['softhsm2']['experiment']['input_paths']['src/p11lab/data/profiles/example.json'] = '9' * 64
    plan = select_image_work(changed, ['src/p11lab/data/profiles/example.json'], first['snapshot'])
    assert [(w['environment'], w['action']) for w in plan['work']] == [('softhsm2', 'retest')]
    assert plan['snapshot']['environments']['softhsm2']['provider'] == first['snapshot']['environments']['softhsm2']['provider']
    assert select_image_work(changed, ['src/p11lab/data/profiles/example.json'], first['snapshot'])['work'] == plan['work']


def test_unknown_paths_and_duplicate_paths_are_rejected():
    data = inputs()
    policy = {'softhsm2': {'channel': 'release', 'experiment': data}}
    for paths in (['src/unknown.py'], ['docs/a.md', 'docs/a.md'], ['docs/../README.md']):
        with pytest.raises(ImageCIError):
            select_image_work(policy, paths, None)


def test_stale_locked_asset_is_rejected(tmp_path, monkeypatch):
    import shutil
    from pathlib import Path
    import p11lab.catalog as catalog

    data = tmp_path / 'data'
    source = Path(catalog.__file__).parent / 'data'
    shutil.copytree(source / 'providers' / 'softhsm2', data / 'providers' / 'softhsm2')
    shutil.copytree(source / 'runtime', data / 'runtime')
    monkeypatch.setattr(catalog, 'files', lambda package: tmp_path)
    (data / 'providers' / 'softhsm2' / 'Dockerfile').write_text('tampered')
    with pytest.raises(catalog.CatalogError, match='sha256 mismatch'):
        select_image_work({'softhsm2': {'channel': 'release', 'experiment': inputs()}}, [], None)


@pytest.mark.parametrize(('environment', 'channel', 'role'), [
    ('kryoptic', 'release', 'dependency-lock'),
    ('corepkcs11', 'release', 'audit-source'),
    ('softhsm2', 'release', 'adapter-common'),
    ('softhsm2', 'release', 'notice'),
    ('softhsm2', 'release', 'recipe'),
])
def test_copied_locked_asset_mutation_changes_runtime_key(tmp_path, monkeypatch, environment, channel, role):
    import hashlib
    import json
    import shutil
    from pathlib import Path
    import p11lab.catalog as catalog

    data = tmp_path / 'data'
    source = Path(catalog.__file__).parent / 'data'
    shutil.copytree(source / 'providers' / environment, data / 'providers' / environment)
    shutil.copytree(source / 'runtime', data / 'runtime')
    monkeypatch.setattr(catalog, 'files', lambda package: tmp_path)
    old = catalog.load_environment(environment, channel)
    catalog.validate_build_inputs(old)
    old_key = artifact_key('runtime', runtime_inputs(old))
    lock_path = data / 'providers' / environment / old['channel_spec']['lock']
    lock = json.loads(lock_path.read_text())
    asset = next(a for a in lock['assets'] if a['role'] == role)
    root = data / 'runtime' if asset.get('scope') == 'runtime' else lock_path.parent
    path = root / asset['path']
    path.write_bytes(path.read_bytes() + b'\n# identity mutation\n')
    asset['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
    for descriptor in old['channels'].values():
        if descriptor.get('status') != 'locked':
            continue
        other_path = lock_path.parent / descriptor['lock']
        other = json.loads(other_path.read_text())
        for item in other['assets']:
            if item.get('scope', 'provider') == asset.get('scope', 'provider') and item['path'] == asset['path']:
                item['sha256'] = asset['sha256']
        other_path.write_text(json.dumps(other))
    new = catalog.load_environment(environment, channel)
    catalog.validate_build_inputs(new)
    assert artifact_key('runtime', runtime_inputs(new)) != old_key


def test_work_carries_closed_logical_legs():
    data = inputs()
    data['provider']['build_key'] = artifact_key('runtime', runtime_inputs(load_environment('softhsm2', 'release')))
    data['roster'].append({'leg': 'proxy', 'shard': '0', 'repetition': 0})
    plan = select_image_work({'softhsm2': {'channel': 'release', 'experiment': data}}, [], None)
    assert plan['work'][0]['legs'] == ['direct', 'proxy']
    assert plan['work'][0]['provider'] == data['provider']
    assert plan['work'][0]['policy_sha256'] == data['policy_sha256']


def test_canonical_experiment_digest_and_physical_attempt_separation():
    data = inputs()
    assert experiment_key(data) == '841f4b44533762188d0f73c592ef0157e299767d6f90689bc49f5887ead8da45'
    run = {'artifacts': [data['provider']['artifact']], 'profile': {'id': 'smoke', 'sha256': 'b' * 64},
           'configuration': {}, 'initialization': {}, 'selection': [], 'datasets': [], 'limits': {},
           'attempt_id': '4eb1e1fa-38b4-4c58-8862-184c2421ed11'}
    other = copy.deepcopy(run)
    other['attempt_id'] = '982a5ac4-26ed-4aa1-a1da-607ba5cfbe48'
    assert artifact_key('run', run) != artifact_key('run', other)
    assert experiment_key(data) == experiment_key(copy.deepcopy(data))


def test_logical_roster_order_and_membership_are_identity_inputs():
    data = inputs()
    data['roster'].append({'leg': 'direct', 'shard': '1', 'repetition': 0})
    reordered = copy.deepcopy(data)
    reordered['roster'].reverse()
    assert experiment_key(data) != experiment_key(reordered)
    reordered['roster'].pop()
    assert experiment_key(data) != experiment_key(reordered)


@pytest.mark.parametrize('field', ['sources', 'base_images', 'packages', 'toolchain'])
def test_real_lock_mutation_rebuilds_only_affected_provider(tmp_path, monkeypatch, field):
    import json
    import shutil
    from pathlib import Path
    import p11lab.catalog as catalog

    data = tmp_path / 'data'
    source = Path(catalog.__file__).parent / 'data'
    for name in ('softhsm2', 'kryoptic'):
        shutil.copytree(source / 'providers' / name, data / 'providers' / name)
    shutil.copytree(source / 'runtime', data / 'runtime')
    monkeypatch.setattr(catalog, 'files', lambda package: tmp_path)
    policy = {}
    for name in ('softhsm2', 'kryoptic'):
        experiment = inputs()
        experiment['provider']['build_key'] = artifact_key('runtime', runtime_inputs(catalog.load_environment(name, 'release')))
        policy[name] = {'channel': 'release', 'experiment': experiment}
    baseline = select_image_work(policy, [], None)['snapshot']
    lock_path = data / 'providers' / 'softhsm2' / 'release.lock.json'
    lock = json.loads(lock_path.read_text())
    if field == 'sources':
        lock[field][0]['revision'] = 'a' * 40
    elif field == 'base_images':
        lock[field][0] = 'docker.io/library/debian@sha256:' + 'a' * 64
    elif field == 'packages':
        lock[field][0]['version'] = 'changed'
    else:
        lock[field][0]['sha256'] = 'a' * 64
    lock_path.write_text(json.dumps(lock))
    plan = select_image_work(policy, ['src/p11lab/data/providers/softhsm2/release.lock.json'], baseline)
    assert [(w['environment'], w['action']) for w in plan['work']] == [('softhsm2', 'rebuild')]
    assert plan['work'][0]['provider'] is None
    assert plan['work'][0]['experiment_key'] is None


def test_explicit_retry_schedules_fresh_work_even_without_input_changes():
    data = inputs()
    data['provider']['build_key'] = artifact_key('runtime', runtime_inputs(load_environment('softhsm2', 'release')))
    policy = {'softhsm2': {'channel': 'release', 'experiment': data}}
    prior = select_image_work(policy, [], None)['snapshot']
    retry = select_image_work(policy, [], prior, retry=['softhsm2'])
    assert [(w['environment'], w['action']) for w in retry['work']] == [('softhsm2', 'retest')]
    with pytest.raises(ImageCIError):
        select_image_work(policy, [], prior, retry=['unknown'])


def test_shared_runtime_asset_rebuilds_actual_dependents(tmp_path, monkeypatch):
    import hashlib
    import json
    import shutil
    from pathlib import Path
    import p11lab.catalog as catalog

    data = tmp_path / 'data'
    source = Path(catalog.__file__).parent / 'data'
    for name in ('softhsm2', 'kryoptic'):
        shutil.copytree(source / 'providers' / name, data / 'providers' / name)
    shutil.copytree(source / 'runtime', data / 'runtime')
    monkeypatch.setattr(catalog, 'files', lambda package: tmp_path)
    policy = {}
    for name in ('softhsm2', 'kryoptic'):
        experiment = inputs()
        experiment['provider']['build_key'] = artifact_key('runtime', runtime_inputs(catalog.load_environment(name, 'release')))
        policy[name] = {'channel': 'release', 'experiment': experiment}
    baseline = select_image_work(policy, [], None)['snapshot']
    specs = [catalog.load_environment(name, 'release') for name in policy]
    paths = [{a['path'] for a in spec['lock']['assets'] if a.get('scope') == 'runtime'} for spec in specs]
    common = sorted(paths[0] & paths[1])[0]
    asset = data / 'runtime' / common
    asset.write_bytes(asset.read_bytes() + b'\n# common mutation\n')
    digest = hashlib.sha256(asset.read_bytes()).hexdigest()
    for spec in specs:
        for channel in spec['channels'].values():
            if channel.get('status') != 'locked':
                continue
            lock_path = data / 'providers' / spec['id'] / channel['lock']
            lock = json.loads(lock_path.read_text())
            for entry in lock['assets']:
                if entry.get('scope') == 'runtime' and entry['path'] == common:
                    entry['sha256'] = digest
            lock_path.write_text(json.dumps(lock))
    plan = select_image_work(policy, ['src/p11lab/data/runtime/' + common], baseline)
    assert [(w['environment'], w['action']) for w in plan['work']] == [('kryoptic', 'rebuild'), ('softhsm2', 'rebuild')]


def test_patch_bytes_rebuild_the_provider(tmp_path, monkeypatch):
    import hashlib
    import json
    import shutil
    from pathlib import Path
    import p11lab.catalog as catalog

    data = tmp_path / 'data'
    source = Path(catalog.__file__).parent / 'data'
    shutil.copytree(source / 'providers' / 'corepkcs11', data / 'providers' / 'corepkcs11')
    shutil.copytree(source / 'runtime', data / 'runtime')
    monkeypatch.setattr(catalog, 'files', lambda package: tmp_path)
    spec = catalog.load_environment('corepkcs11', 'release')
    experiment = inputs()
    experiment['provider']['build_key'] = artifact_key('runtime', runtime_inputs(spec))
    policy = {'corepkcs11': {'channel': 'release', 'experiment': experiment}}
    previous = select_image_work(policy, [], None)['snapshot']
    path = spec['lock']['patches'][0]['path']
    patch = data / 'providers' / 'corepkcs11' / path
    patch.write_bytes(patch.read_bytes() + b'\n# changed\n')
    digest = hashlib.sha256(patch.read_bytes()).hexdigest()
    for channel in spec['channels'].values():
        if channel.get('status') != 'locked':
            continue
        lock_path = patch.parents[1] / channel['lock']
        lock = json.loads(lock_path.read_text())
        for entry in lock['patches'] + lock['assets']:
            if entry['path'] == path:
                entry['sha256'] = digest
        lock_path.write_text(json.dumps(lock))
    plan = select_image_work(policy, ['src/p11lab/data/providers/corepkcs11/' + path], previous)
    assert [(w['environment'], w['action']) for w in plan['work']] == [('corepkcs11', 'rebuild')]


def test_provider_readme_alone_is_not_runtime_work():
    data = inputs()
    data['provider']['build_key'] = artifact_key('runtime', runtime_inputs(load_environment('softhsm2', 'release')))
    policy = {'softhsm2': {'channel': 'release', 'experiment': data}}
    snapshot = select_image_work(policy, [], None)['snapshot']
    assert select_image_work(policy, ['src/p11lab/data/providers/softhsm2/README.md'], snapshot)['work'] == []


def test_selected_lock_byte_change_changes_provider_key(tmp_path, monkeypatch):
    import shutil
    from pathlib import Path
    import p11lab.catalog as catalog

    data = tmp_path / 'data'
    source = Path(catalog.__file__).parent / 'data'
    shutil.copytree(source / 'providers' / 'softhsm2', data / 'providers' / 'softhsm2')
    shutil.copytree(source / 'runtime', data / 'runtime')
    monkeypatch.setattr(catalog, 'files', lambda package: tmp_path)
    before = catalog.load_environment('softhsm2', 'release')
    old = artifact_key('runtime', runtime_inputs(before))
    lock = data / 'providers' / 'softhsm2' / before['channel_spec']['lock']
    lock.write_bytes(lock.read_bytes() + b'\n')
    after = catalog.load_environment('softhsm2', 'release')
    catalog.validate_build_inputs(after)
    assert artifact_key('runtime', runtime_inputs(after)) != old


def test_retest_plan_retains_detached_full_experiment_and_logical_cells():
    import hashlib
    import json

    data = inputs()
    data['provider']['build_key'] = artifact_key('runtime', runtime_inputs(load_environment('softhsm2', 'release')))
    data['roster'].extend([{'leg': 'direct', 'shard': '1', 'repetition': 2},
                           {'leg': 'proxy', 'shard': '3', 'repetition': 1}])
    policy = {'softhsm2': {'channel': 'release', 'experiment': data}}
    expected = copy.deepcopy(data)
    work = json.loads(json.dumps(select_image_work(policy, [], None)))['work'][0]
    frozen = work['frozen']
    assert frozen['schema_version'] == 1
    body = {name: value for name, value in frozen.items() if name != 'sha256'}
    independent_digest = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
    assert frozen['sha256'] == independent_digest
    assert frozen['experiment'] == expected
    assert frozen['expected_build_key'] == expected['provider']['build_key']
    assert experiment_key(frozen['experiment']) == work['experiment_key']
    policy['softhsm2']['experiment']['roster'][1]['shard'] = 'changed'
    policy['softhsm2']['experiment']['tools']['checker']['installed'] = 'f' * 64
    policy['softhsm2']['experiment']['input_paths'].clear()
    assert frozen['experiment'] == expected
    assert experiment_key(frozen['experiment']) == work['experiment_key']


def test_rebuild_plan_freezes_pending_experiment_and_binds_new_provider():
    import json
    from p11lab import image_ci

    data = inputs()
    data['roster'].append({'leg': 'direct', 'shard': '1', 'repetition': 3})
    plan = select_image_work({'softhsm2': {'channel': 'release', 'experiment': data}}, [], None)
    work = json.loads(json.dumps(plan))['work'][0]
    frozen = work['frozen']
    assert work['action'] == 'rebuild'
    assert frozen['experiment']['provider'] is None
    assert frozen['experiment']['roster'] == data['roster']
    assert frozen['experiment']['input_paths'] == data['input_paths']
    assert frozen['experiment']['tools'] == data['tools']
    data['roster'].clear()
    provider = {'artifact': {'kind': 'oci', 'reference': 'registry.example/new@sha256:' + 'e' * 64,
                             'sha256': 'e' * 64, 'platform': 'linux/amd64'},
                'build_key': work['provider_build_key'], 'provenance_sha256': 'f' * 64}
    bound = image_ci.bind_rebuilt_experiment(frozen, provider)
    assert bound['inputs']['provider'] == provider
    assert bound['inputs']['roster'] == frozen['experiment']['roster']
    assert bound['experiment_key'] == experiment_key(bound['inputs'])
    provider['provenance_sha256'] = 'a' * 64
    assert bound['inputs']['provider']['provenance_sha256'] == 'f' * 64


def test_rebuild_binding_rejects_wrong_build_digest_provenance_or_frozen_bytes():
    from p11lab import image_ci

    frozen = select_image_work({'softhsm2': {'channel': 'release', 'experiment': inputs()}}, [], None)['work'][0]['frozen']
    provider = {'artifact': {'kind': 'oci', 'reference': 'registry.example/new@sha256:' + 'e' * 64,
                             'sha256': 'e' * 64, 'platform': 'linux/amd64'},
                'build_key': frozen['expected_build_key'], 'provenance_sha256': 'f' * 64}
    for mutation in ('build', 'digest', 'provenance', 'platform', 'frozen'):
        candidate, projection = copy.deepcopy(provider), copy.deepcopy(frozen)
        if mutation == 'build':
            candidate['build_key'] = '0' * 64
        elif mutation == 'digest':
            candidate['artifact']['sha256'] = '0' * 64
        elif mutation == 'provenance':
            candidate['provenance_sha256'] = 'latest'
        elif mutation == 'platform':
            candidate['artifact']['platform'] = 'linux/arm64'
        else:
            projection['experiment']['roster'][0]['shard'] = 'changed'
        with pytest.raises(ImageCIError):
            image_ci.bind_rebuilt_experiment(projection, candidate)
