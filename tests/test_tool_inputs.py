"""A resolved file is evidence, never an authority for its own digest."""
import copy
import hashlib
import importlib
import json

import pytest


def module():
    return importlib.import_module('p11lab.tool_inputs')


def test_packaged_consumer_lock_has_exact_curated_inventory():
    lock = module().load_tool_input_lock('consumer', target='debian13-amd64')
    assert lock['apt_snapshot'] == '20260918T000000Z'
    assert lock['base_image'].endswith('@sha256:7792b1f7702a86946cd518db72b6a407302c3e9bc1635634368b878189e8221c')
    assert len(lock['parent_packages']) == 78
    assert len(lock['packages']) == 43
    assert len(lock['sources']) == 16
    assert sum(len(s['files']) for s in lock['sources']) == 48
    assert len(lock['metadata']) == 9
    assert len(lock['resources']) == 8
    assert len(lock['stages']['compiler']['packages']) == 114
    assert len(lock['stages']['consumer']['packages']) == 86
    assert sum(p['size'] for p in lock['packages']) == 60235540
    assert lock['license_status'] == 'unreviewed'


def test_curated_parent_matches_supported_softhsm_release_runtime():
    from p11lab.catalog import package_data
    lock = module().load_tool_input_lock('consumer', target='debian13-amd64')
    parent = json.loads(package_data('providers/softhsm2/release.lock.json').read_bytes())
    fields = ('name', 'version', 'architecture', 'source_package', 'source_version')
    runtime = [{k: p[k] for k in fields} for p in parent['packages'] if p['phase'] == 'runtime']
    assert lock['parent_packages'] == runtime
    assert lock['apt_snapshot'] == parent['apt_snapshot']
    assert lock['base_image'] == parent['base_images'][0]


@pytest.mark.parametrize('toolset,target', [('checker', 'windows-amd64'), ('proxy', 'debian13-amd64'),
                                           ('../consumer', 'debian13-amd64'), ('consumer', 'windows-amd64')])
def test_tool_lock_rejects_unsupported_selection_before_output(toolset, target):
    with pytest.raises(ValueError, match='unsupported'):
        module().load_tool_input_lock(toolset, target=target)


def changed_asset(monkeypatch, transform):
    m = module()
    original = m.package_data
    class Asset:
        def __init__(self, data): self.data = data
        def read_bytes(self): return self.data
    def read(name):
        asset = original(name)
        if name.endswith('.lock.json'):
            data = json.loads(asset.read_bytes())
            transform(data)
            return Asset(json.dumps(data).encode())
        return asset
    monkeypatch.setattr(m, 'package_data', read)
    return m


@pytest.mark.parametrize('change', [
    lambda x: x.update(extra=True),
    lambda x: x['packages'][0].update(size=True),
    lambda x: x['packages'][0].update(size=-1),
    lambda x: x['packages'][0].update(size=0),
    lambda x: x['packages'][0].update(size=2**40),
    lambda x: x['packages'][0].update(sha256='A'*64),
    lambda x: x['packages'][0].update(architecture='arm64'),
    lambda x: x['packages'][0].update(source_version='wrong'),
    lambda x: x['packages'][0].update(index='trixie-updates.Packages'),
    lambda x: x['packages'].append(copy.deepcopy(x['packages'][0])),
    lambda x: x['packages'][0].update(path='../escape'),
    lambda x: x['packages'][0].update(path='/absolute'),
    lambda x: x['packages'][0].update(path='C:\\drive'),
    lambda x: x['packages'][1].update(path=x['packages'][0]['path']+'/child'),
    lambda x: x['sources'][0]['files'].pop(),
    lambda x: x['sources'][0]['files'][0].update(sha256='0'*64),
    lambda x: x['resources'][0].update(sha256='0'*64),
    lambda x: x['parent_packages'][0].update(version='wrong'),
    lambda x: x['stages']['compiler']['packages'].pop(),
    lambda x: x['provenance'].update(sha256='0'*64),
])
def test_tool_lock_rejects_ambiguous_records(monkeypatch, change):
    m = changed_asset(monkeypatch, change)
    with pytest.raises(ValueError):
        m.load_tool_input_lock('consumer', target='debian13-amd64')


def test_duplicate_json_keys_are_rejected(monkeypatch):
    m = module()
    original = m.package_data
    class Asset:
        def read_bytes(self): return b'{"schema_version":1,"schema_version":1}'
    monkeypatch.setattr(m, 'package_data', lambda name: Asset() if name.endswith('.lock.json') else original(name))
    with pytest.raises(ValueError, match='duplicate'):
        m.load_tool_input_lock('consumer', target='debian13-amd64')


@pytest.mark.parametrize('resource', ['consumer/smoke.c', 'tool-inputs/consumer.debian13-amd64.provenance.json'])
def test_tool_lock_verifies_provenance_and_owned_resources(monkeypatch, resource):
    m = module()
    original = m.package_data
    class Asset:
        def read_bytes(self): return b'altered packaged bytes'
    monkeypatch.setattr(m, 'package_data', lambda name: Asset() if name == resource else original(name))
    with pytest.raises(ValueError, match='checksum|provenance|resource'):
        m.load_tool_input_lock('consumer', target='debian13-amd64')


def alter_provenance(monkeypatch, transform):
    m = module()
    original = m.package_data
    lock = json.loads(original('tool-inputs/consumer.debian13-amd64.lock.json').read_bytes())
    proof = json.loads(original(lock['provenance']['path']).read_bytes())
    transform(proof)
    raw = json.dumps(proof).encode()
    lock['provenance']['sha256'] = hashlib.sha256(raw).hexdigest()
    class Asset:
        def __init__(self, data): self.data = data
        def read_bytes(self): return self.data
    def read(name):
        if name.endswith('.lock.json'): return Asset(json.dumps(lock).encode())
        if name == lock['provenance']['path']: return Asset(raw)
        return original(name)
    monkeypatch.setattr(m, 'package_data', read)
    return m


@pytest.mark.parametrize('change', [
    lambda p: p['relations']['compiler'].pop(),
    lambda p: p['relations']['consumer'].append(copy.deepcopy(p['relations']['consumer'][0])),
    lambda p: p['relations']['consumer'][0].update(selected_version='wrong'),
    lambda p: p['relations']['consumer'][0].update(selected_alternative='absent'),
    lambda p: p['relations']['consumer'][0].update(group='invented-dependency'),
    lambda p: p['source_bindings'][0]['files'].pop(),
    lambda p: p['parent_package_evidence'][0].update(version='wrong'),
    lambda p: p['conflicts']['compiler'].append('unexpected conflict'),
])
def test_fixed_proof_rejects_incomplete_or_substituted_witnesses(monkeypatch, change):
    m = alter_provenance(monkeypatch, change)
    with pytest.raises(ValueError):
        m.load_tool_input_lock('consumer', target='debian13-amd64')


def alter_authority(monkeypatch, change):
    """Reseal after mutation so structure, not only digest mismatch, is tested."""
    m = module()
    original = m.package_data
    lock = json.loads(original('tool-inputs/consumer.debian13-amd64.lock.json').read_bytes())
    proof = json.loads(original(lock['provenance']['path']).read_bytes())
    change(lock, proof)
    proof['lock_binding_sha256'] = m._digest(m._canonical({k: v for k, v in lock.items() if k != 'provenance'}))
    raw = json.dumps(proof).encode()
    lock['provenance']['sha256'] = hashlib.sha256(raw).hexdigest()
    class Asset:
        def __init__(self, data): self.data = data
        def read_bytes(self): return self.data
    def read(name):
        if name.endswith('.lock.json'): return Asset(json.dumps(lock).encode())
        if name == lock['provenance']['path']: return Asset(raw)
        return original(name)
    monkeypatch.setattr(m, 'package_data', read)
    return m


@pytest.mark.parametrize('change', [
    lambda l,p: p.update(schema_version=True),
    lambda l,p: p.update(metadata={}),
    lambda l,p: p['metadata']['trixie'].update(extra=True),
    lambda l,p: p['metadata']['trixie']['indexes'][0]['uncompressed'].update(size=True),
    lambda l,p: p['metadata']['trixie'].update(signatures=[]),
    lambda l,p: p['metadata']['verifier'].update(keyring_sha256='wrong'),
    lambda l,p: p['parent_package_evidence'][0]['relations'].update(Unknown='x'),
    lambda l,p: p['parent_package_evidence'][0].update(index='other.Packages'),
    lambda l,p: p.update(parent_incorporated_source_ids=['forged=1']),
    lambda l,p: p.update(limitations=None),
    lambda l,p: l['packages'][0].update(index='unknown.Packages'),
    lambda l,p: l['packages'][0].update(url=l['packages'][0]['url'].replace('20260918','20260919')),
    lambda l,p: l['metadata'][0].update(sha256='0'*64),
    lambda l,p: l['sources'][0].update(index='unknown.Sources'),
    lambda l,p: l['sources'][0]['files'][0].update(url='https://snapshot.debian.org/archive/wrong/file.dsc'),
    lambda l,p: l['packages'][0].update(name='../bad'),
])
def test_nested_provenance_structure_is_checked_even_when_resealed(monkeypatch, change):
    m = alter_authority(monkeypatch, change)
    with pytest.raises(ValueError):
        m.load_tool_input_lock('consumer', target='debian13-amd64')

@pytest.mark.parametrize('toolset,stage,roots', [
    ('checker', 'checker', {'python3.13', 'python3.13-venv'}),
    ('oracle', 'oracle', {'python3.13', 'openssl'}),
])
def test_fixed_executor_and_independent_oracle_have_protected_input_selection(toolset, stage, roots):
    lock = module().load_tool_input_lock(toolset, target='debian13-amd64')
    assert lock['schema_version'] == 2
    assert lock['toolset'] == toolset
    assert roots <= {r.split('=')[0] for r in lock['stages'][stage]['roots']}
    assert lock['license_status'] == 'unreviewed'
    assert lock['readiness']['installation'] == 'not-executed'
    assert lock['readiness']['qualification'] == 'blocked'
    if toolset == 'checker':
        assert lock['execution']['source_revision'] == '9df03bd8b811966fa7856394b19e3f57ffcd8a40'
        assert lock['execution']['expected_outputs'][0]['sha256'] == '58ac3451ae0dba207a48affa460309e4024c2ec7aefb04ef73062f420fdcffec'
        assert len(lock['execution']['runtime_wheels']) == 33
        assert len(lock['execution']['build_wheels']) == 7
        assert lock['execution']['reproduction'] == 'blocked-unreproduced-output'
    else:
        assert lock['execution']['provider_state'] == 'absent'
        assert lock['execution']['environment']['OPENSSL_CONF'] == '/opt/p11lab-oracle/openssl.cnf'


def test_authenticated_index_member_mismatch_fails_even_with_declared_archive_hash():
    m = module()
    fields = b'Package: example\nVersion: 1\nArchitecture: amd64\nFilename: pool/main/e/example/example.deb\nSize: 3\nSHA256: ' + b'a'*64 + b'\n'
    record = dict(name='example', version='1', architecture='amd64', filename='pool/main/e/example/example.deb',
                  size=3, sha256='a'*64, index='trixie.Packages', stanza_sha256=hashlib.sha256(fields).hexdigest(),
                  source_package='example', source_version='1', relations={})
    lock = {'packages': [record], 'sources': []}
    proof = {'parent_package_evidence': []}
    m._verify_index_records(lock, proof, {'trixie.Packages': fields + b'\n'})
    for altered in [fields.replace(b'Size: 3', b'Size: 4'), fields.replace(b'Architecture: amd64', b'Architecture: arm64'), fields + b'Depends: injected\n']:
        with pytest.raises(ValueError, match='index|member|stanza'):
            m._verify_index_records(lock, proof, {'trixie.Packages': altered + b'\n'})


def alter_fixed_authority(monkeypatch, toolset, change):
    m = module()
    original = m.package_data
    name = f'tool-inputs/{toolset}.debian13-amd64.lock.json'
    lock = json.loads(original(name).read_bytes())
    proof_name = lock['provenance']['path']
    proof = json.loads(original(proof_name).read_bytes())
    assets = {}
    change(lock, proof, assets)
    for record in lock['resources']:
        if record['asset'] in assets:
            record.update(sha256=m._digest(assets[record['asset']]), size=len(assets[record['asset']]))
    proof['lock_binding_sha256'] = m._digest(m._canonical({k: v for k, v in lock.items() if k != 'provenance'}))
    assets[proof_name] = json.dumps(proof).encode()
    lock['provenance']['sha256'] = m._digest(assets[proof_name])
    assets[name] = json.dumps(lock).encode()
    class Asset:
        def __init__(self, raw): self.raw = raw
        def read_bytes(self): return self.raw
    monkeypatch.setattr(m, 'package_data', lambda name: Asset(assets[name]) if name in assets else original(name))
    return m


@pytest.mark.parametrize('change', [
    lambda l,p,a: l.update(extra=True),
    lambda l,p,a: l['readiness'].update(installation='installed'),
    lambda l,p,a: l['execution'].update(source_revision='09a'+'0'*37),
    lambda l,p,a: l['execution']['expected_outputs'][0].update(sha256='0'*64),
    lambda l,p,a: l['execution']['runtime_wheels'].pop(),
    lambda l,p,a: l['execution']['runtime_wheels'].append(l['execution']['runtime_wheels'][0]),
    lambda l,p,a: l['execution']['build_wheels'].pop(),
    lambda l,p,a: l['execution'].update(reproduction='accepted'),
    lambda l,p,a: l['python_inputs'][0].update(size=True),
    lambda l,p,a: l['python_inputs'][0].update(kind='binary'),
    lambda l,p,a: l['python_inputs'][0].update(url='https://snapshot.debian.org/archive/debian/20260918T000000Z/pool/file.whl'),
    lambda l,p,a: l['python_inputs'][0].update(version='999'),
    lambda l,p,a: l['python_inputs'][0].update(sha256='0'*64),
    lambda l,p,a: l['packages'][0].update(kind='python-wheel'),
    lambda l,p,a: l['checker_source'].update(url='https://codeload.github.com/mingulov/pkcs11-check/tar.gz/main'),
    lambda l,p,a: l['checker_source'].update(manifest_asset='consumer/verify.py'),
    lambda l,p,a: p['relations']['checker'].pop(),
    lambda l,p,a: l['stages']['checker']['roots'].pop(),
])
def test_fixed_executor_mutants_fail_when_curated_binding_is_resealed(monkeypatch, change):
    m = alter_fixed_authority(monkeypatch, 'checker', change)
    with pytest.raises(ValueError): m.load_tool_input_lock('checker', target='debian13-amd64')


@pytest.mark.parametrize('field', ['mode', 'git_blob', 'missing', 'extra', 'revision', 'tree', 'commit'])
def test_complete_git_provenance_rejects_source_and_build_metadata_mutants(monkeypatch, field):
    def change(lock, proof, assets):
        asset = lock['execution']['source_manifest']
        manifest = json.loads(module().package_data(asset).read_bytes())
        if field in {'revision', 'tree', 'commit'}: manifest[field] += '0'
        elif field == 'missing': manifest['files'].pop()
        elif field == 'extra': manifest['files'].append(dict(manifest['files'][0], path='injected.py'))
        else:
            record = next(p for p in manifest['files'] if p['path'] == 'pyproject.toml')
            record[field] = '100755' if field == 'mode' else '0'*40
        assets[asset] = json.dumps(manifest).encode()
    m = alter_fixed_authority(monkeypatch, 'checker', change)
    with pytest.raises(ValueError): m.load_tool_input_lock('checker', target='debian13-amd64')


@pytest.mark.parametrize('change', [
    lambda l,p,a: l['execution'].update(provider_state='mounted'),
    lambda l,p,a: l['execution']['environment'].update(OPENSSL_CONF='/etc/ssl/openssl.cnf'),
    lambda l,p,a: l['execution']['environment'].update(LD_PRELOAD='/provider/module.so'),
    lambda l,p,a: l['execution']['argv'].append('--provider-module'),
    lambda l,p,a: l['resources'].pop(),
    lambda l,p,a: l['stages']['oracle']['roots'].pop(),
    lambda l,p,a: l.update(checker_source={}),
])
def test_oracle_rejects_provider_host_configuration_and_incomplete_runtime(monkeypatch, change):
    m = alter_fixed_authority(monkeypatch, 'oracle', change)
    with pytest.raises(ValueError): m.load_tool_input_lock('oracle', target='debian13-amd64')


@pytest.mark.parametrize('change', ['missing-source', 'orphan-resource'])
def test_checker_requires_complete_published_source_roster_and_no_orphan_resources(monkeypatch, change):
    def mutate(lock, proof, assets):
        if change == 'missing-source':
            index = next(i for i,p in enumerate(lock['python_inputs']) if p['kind']=='python-source')
            lock['python_inputs'].pop(index)
        else:
            from p11lab.catalog import package_data
            raw = package_data('consumer/verify.py').read_bytes()
            lock['resources'].append(dict(asset='consumer/verify.py',path='resources/orphan.py',sha256=hashlib.sha256(raw).hexdigest(),size=len(raw)))
    m = alter_fixed_authority(monkeypatch, 'checker', mutate)
    with pytest.raises(ValueError): m.load_tool_input_lock('checker', target='debian13-amd64')


def test_resolution_receipt_separates_missing_build_output_from_acquired_inputs():
    m = module()
    lock = m.load_tool_input_lock('checker', target='debian13-amd64')
    records = m._records(lock)
    receipt = m._receipt(lock, 'a'*64, records, [], 0)
    assert receipt['expected_outputs'] == lock['execution']['expected_outputs']
    assert receipt['readiness'] == lock['readiness']
    assert receipt['reproduction'] == 'blocked-unreproduced-output'
    assert not {p['path'] for p in receipt['expected_outputs']} & {p['path'] for p in receipt['records']}
    assert receipt['installation'] == 'not-executed'
