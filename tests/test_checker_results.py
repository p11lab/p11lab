"""Artifact-level completion checks using the optional pinned checker rules."""
import hashlib
import json
from pathlib import Path

import pytest

from p11lab.checker import canonical_node, load_profile, source_inventory, validate_results


def installed_root():
    tests = pytest.importorskip('pkcs11_check.testcases')
    return Path(tests.__file__).resolve().parent


def write_evidence(directory, nodes, disposition='passed'):
    """Durable per-node state/raw/cache/grouped execution fixture, not 23 units."""
    root = installed_root()
    directory.mkdir()
    caches = directory / '.state.json.report-records'
    caches.mkdir()
    targets = [str(root / node) for node in nodes]
    state = {'units': targets, 'results': [], 'process_observations': [], 'process_observations_complete': True}
    raw, groups = [], {}
    for target in targets:
        status = 'failed' if disposition == 'finalize' else 'passed' if disposition == 'interrupted' else disposition
        rc = {'passed': 0, 'failed': 1, 'crashed': -11, 'timeout': 124}[status]
        kind = {'crashed': 'signal', 'timeout': 'timeout'}.get(status, 'exit')
        observation = {'target': target, 'role': 'unit', 'attempt': 0,
                       'termination': {'raw_code': rc, 'kind': kind}}
        state['process_observations'].append(observation)
        state['results'].append({'target': target, 'status': status, 'returncode': rc,
                                 'completion_verified': True})
        records = [{'$report_type': 'SessionStart'},
                   {'$report_type': 'IsolatedUnitReport', 'target': target, 'attempt': 0}]
        if disposition not in {'crashed', 'timeout'}:
            records.append({'$report_type': 'TestReport', 'nodeid': target, 'when': 'call', 'outcome': 'passed'})
            if disposition != 'interrupted':
                records.append({'$report_type': 'SessionFinish', 'exitstatus': 0})
        if disposition == 'finalize':
            records.append({'$report_type': 'TeardownFinalize', 'outcome': 'error', 'rv': 5})
        (caches / (hashlib.sha256(target.encode()).hexdigest() + '.jsonl')).write_text(''.join(json.dumps(r) + '\n' for r in records))
        raw.append({'$report_type': 'ProcessReport', 'target': target, 'observation': observation})
        raw.extend(records)
        file = target.split('::', 1)[0]
        unit = groups.setdefault(file, {'target': file, 'status': status, 'executions': [], 'tests': [],
                                       'returncode': abs(rc),
                                       'counts': {'passed': 0, 'error': 0, 'crashed': 0, 'timeout': 0}})
        unit['executions'].append(observation)
        unit['counts'][status if status in {'crashed', 'timeout'} else 'passed'] += 1
        if disposition == 'finalize':
            unit['counts']['error'] += 1
        if disposition in {'crashed', 'timeout'}:
            unit['tests'].append({'nodeid': target, 'outcome': disposition})
        if disposition == 'finalize':
            unit['tests'].append({'nodeid': 'C_Finalize::teardown', 'lifecycle': 'session-teardown', 'outcome': 'error'})
    summary = {key: sum(u['counts'][key] for u in groups.values()) for key in ('passed', 'error', 'crashed', 'timeout')}
    payload = {'summary': summary | {'incomplete': disposition == 'timeout', 'total': sum(summary.values())}, 'units': list(groups.values())}
    (directory / 'state.json').write_text(json.dumps(state))
    (directory / 'results.json').write_text(json.dumps(payload))
    (directory / 'report.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in raw))
    return root


@pytest.mark.parametrize('disposition', ['passed', 'crashed', 'timeout', 'finalize'])
def test_supported_complete_observations(tmp_path, disposition):
    nodes = load_profile()['nodes'][:3]
    root = write_evidence(tmp_path / 'run', nodes, disposition)
    result = validate_results(tmp_path / 'run', nodes, root)
    assert result['observations_complete'], result
    assert result['complete'] is (disposition != 'timeout')
    assert len(json.loads((tmp_path / 'run/results.json').read_text())['units']) == 1
    assert result['provider_statuses'] == ['failed' if disposition == 'finalize' else disposition]


@pytest.mark.parametrize('mutation', ['interrupted', 'absent-cache', 'absent-report', 'missing-raw-case',
                                      'duplicate-bookend', 'contradictory-bookend', 'incomplete',
                                      'unknown-case', 'missing-supervisor', 'forged-crash', 'bare-finalize'])
def test_reject_unsupported_completion(tmp_path, mutation):
    nodes = load_profile()['nodes'][:1]
    disposition = {'interrupted': 'interrupted', 'forged-crash': 'crashed', 'bare-finalize': 'finalize'}.get(mutation, 'passed')
    directory = tmp_path / 'run'
    root = write_evidence(directory, nodes, disposition)
    cache = next((directory / '.state.json.report-records').glob('*.jsonl'))
    if mutation == 'absent-cache':
        cache.unlink()
    elif mutation == 'absent-report':
        (directory / 'report.jsonl').unlink()
    elif mutation == 'missing-raw-case':
        records = [r for r in (directory / 'report.jsonl').read_text().splitlines() if json.loads(r).get('$report_type') != 'TestReport']
        (directory / 'report.jsonl').write_text('\n'.join(records))
    elif mutation in {'duplicate-bookend', 'contradictory-bookend', 'unknown-case', 'bare-finalize'}:
        records = [json.loads(r) for r in cache.read_text().splitlines()]
        if mutation == 'duplicate-bookend':
            records.append({'$report_type': 'SessionFinish', 'exitstatus': 0})
        elif mutation == 'contradictory-bookend':
            records[-1]['exitstatus'] = 1
        elif mutation == 'unknown-case':
            records[2]['nodeid'] += '_unknown'
        else:
            records = [r for r in records if r.get('$report_type') != 'TeardownFinalize']
        cache.write_text(''.join(json.dumps(r) + '\n' for r in records))
    elif mutation == 'incomplete':
        payload = json.loads((directory / 'results.json').read_text())
        payload['summary']['incomplete'] = True
        (directory / 'results.json').write_text(json.dumps(payload))
    else:
        state = json.loads((directory / 'state.json').read_text())
        if mutation == 'missing-supervisor':
            state['process_observations'] = []
        else:
            state['process_observations'][0]['termination']['kind'] = 'exit'
        (directory / 'state.json').write_text(json.dumps(state))
    assert not validate_results(directory, nodes, root)['complete']


def test_exact_profile_and_source_identity(tmp_path):
    profile = load_profile()
    assert len(profile['nodes']) == len(set(profile['nodes'])) == 23
    assert len(profile['sources']) == 5
    root = installed_root()
    assert source_inventory(root, profile['nodes'])
    fake = tmp_path / 'source'
    fake.mkdir()
    for name in profile['sources']:
        (fake / name).write_bytes((root / name).read_bytes())
    (fake / 'test_digest.py').write_text('substituted source')
    with pytest.raises(ValueError, match='hash mismatch'):
        source_inventory(fake, profile['nodes'])
    fake_node = str(tmp_path / 'test_interface.py') + profile['nodes'][0][len('test_interface.py'):]
    with pytest.raises(ValueError, match='source path'):
        canonical_node(fake_node, root)
    assert canonical_node(profile['nodes'][0], root) == str(root / profile['nodes'][0])


def test_host_boundary_bounds_redacts_and_controls_environment(tmp_path, monkeypatch):
    import subprocess
    import sys
    from p11lab.checker import LOCK, SOURCE, WHEEL, execute_checker
    root = installed_root()
    nodes = load_profile()['nodes'][:1]
    pin, so = 'secret-1234', 'so-secret-5678'
    monkeypatch.setenv('P11TEST_MATCH', 'inherited-filter')
    monkeypatch.setenv('PYTEST_ADDOPTS', '-k never')
    real_popen = subprocess.Popen
    def collect(argv, **kwargs):
        assert kwargs['env']['PYTEST_ADDOPTS'] == '-v'
        assert 'P11TEST_MATCH' not in kwargs['env']
        return subprocess.CompletedProcess(argv, 0, str(root / nodes[0]) + '\n', '')
    def noisy(argv, **kwargs):
        assert kwargs['env']['P11TEST_PIN'] == pin
        assert pin not in argv and so not in argv
        code = 'import sys;sys.stdout.write("x"*(1024*1024-4)+"secret-1234"+"y"*65536);sys.stderr.write("so-secret-5678")'
        return real_popen([sys.executable, '-c', code], **kwargs)
    monkeypatch.setattr('p11lab.checker.subprocess.run', collect)
    monkeypatch.setattr('p11lab.checker.subprocess.Popen', noisy)
    monkeypatch.setattr('p11lab.checker.validate_results', lambda *a: {'complete': True, 'observations_complete': True})
    record = execute_checker(installed_root=root, module=Path('/module.so'), slot=0,
        nodes=nodes, output_dir=tmp_path / 'run', pin=pin, so_pin=so,
        identity={'source_revision': SOURCE, 'wheel_sha256': WHEEL, 'runtime_lock_sha256': LOCK})
    stdout = (tmp_path / 'run/checker.stdout.log').read_text()
    stderr = (tmp_path / 'run/checker.stderr.log').read_text()
    assert len(stdout) <= 1024 * 1024 and stdout.endswith('[TRUNCATED]\n')
    assert stdout.rstrip().removesuffix('[TRUNCATED]').rstrip().endswith('x')
    assert stderr == '[REDACTED]'
    assert record['logs_truncated']['checker.stdout.log']
    assert pin not in (tmp_path / 'run/checker-receipt.json').read_text()


@pytest.mark.parametrize('status', ['crashed', 'timeout'])
def test_immediate_supervisor_failure_without_pytest_cache(tmp_path, status):
    nodes = load_profile()['nodes'][:1]
    directory = tmp_path / 'run'
    root = write_evidence(directory, nodes, status)
    next((directory / '.state.json.report-records').glob('*.jsonl')).unlink()
    assert validate_results(directory, nodes, root)['observations_complete']
    (directory / 'report.jsonl').unlink()
    assert not validate_results(directory, nodes, root)['complete']


def test_timeout_preserves_raw_kill_signal_and_checker_timeout_code(tmp_path):
    nodes = load_profile()['nodes'][:1]
    directory = tmp_path / 'run'
    root = write_evidence(directory, nodes, 'timeout')
    state = json.loads((directory / 'state.json').read_text())
    payload = json.loads((directory / 'results.json').read_text())
    raw = [json.loads(line) for line in (directory / 'report.jsonl').read_text().splitlines()]
    state['process_observations'][0]['termination']['raw_code'] = -9
    payload['units'][0]['executions'][0]['termination']['raw_code'] = -9
    raw[0]['observation']['termination']['raw_code'] = -9
    (directory / 'state.json').write_text(json.dumps(state))
    (directory / 'results.json').write_text(json.dumps(payload))
    (directory / 'report.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in raw))
    assert state['results'][0]['returncode'] == 124
    assert validate_results(directory, nodes, root)['observations_complete']
    assert not validate_results(directory, nodes, root)['complete']


def test_empty_collection_is_not_a_successful_checker_run(tmp_path, monkeypatch):
    import subprocess
    from p11lab.checker import LOCK, SOURCE, WHEEL, execute_checker
    root = installed_root()
    monkeypatch.setattr('p11lab.checker.subprocess.run',
                        lambda argv, **kwargs: subprocess.CompletedProcess(argv, 0, '', '0 node-ids matched'))
    def forbidden(*args, **kwargs):
        pytest.fail('empty collection reached provider execution')
    monkeypatch.setattr('p11lab.checker.subprocess.Popen', forbidden)
    with pytest.raises(ValueError, match='collection differs'):
        execute_checker(installed_root=root, module=Path('/module.so'), slot=0,
            nodes=load_profile()['nodes'], output_dir=tmp_path / 'run', pin='1234', so_pin='12345678',
            identity={'source_revision': SOURCE, 'wheel_sha256': WHEEL, 'runtime_lock_sha256': LOCK})
    assert (tmp_path / 'run/collection.stdout.log').read_text() == ''


@pytest.mark.parametrize('location', ['state', 'raw', 'grouped'])
@pytest.mark.parametrize('extra_target', ['unknown', 'duplicate'])
def test_exact_unit_observation_rosters(tmp_path, location, extra_target):
    import copy
    nodes = load_profile()['nodes'][:1]
    directory = tmp_path / 'run'
    root = write_evidence(directory, nodes)
    state = json.loads((directory / 'state.json').read_text())
    extra = copy.deepcopy(state['process_observations'][0])
    if extra_target == 'unknown':
        extra['target'] += '_unknown'
    if location == 'state':
        state['process_observations'].append(extra)
        (directory / 'state.json').write_text(json.dumps(state))
    elif location == 'raw':
        with (directory / 'report.jsonl').open('a') as stream:
            stream.write(json.dumps({'$report_type': 'ProcessReport', 'target': extra['target'],
                                     'observation': extra}) + '\n')
    else:
        payload = json.loads((directory / 'results.json').read_text())
        payload['units'][0]['executions'].append(extra)
        (directory / 'results.json').write_text(json.dumps(payload))
    assert not validate_results(directory, nodes, root)['observations_complete']


@pytest.mark.parametrize('outcome', ['passed', 'failed'])
def test_duplicate_attempt_phase_in_cache_and_aggregate(tmp_path, outcome):
    nodes = load_profile()['nodes'][:1]
    directory = tmp_path / 'run'
    root = write_evidence(directory, nodes)
    duplicate = {'$report_type': 'TestReport', 'nodeid': str(root / nodes[0]),
                 'when': 'call', 'outcome': outcome}
    cache = next((directory / '.state.json.report-records').glob('*.jsonl'))
    for path in (cache, directory / 'report.jsonl'):
        records = [json.loads(line) for line in path.read_text().splitlines()]
        index = next(i for i, r in enumerate(records) if r.get('$report_type') == 'SessionFinish')
        records.insert(index, duplicate)
        path.write_text(''.join(json.dumps(r) + '\n' for r in records))
    assert not validate_results(directory, nodes, root)['observations_complete']


@pytest.mark.parametrize('mutation', ['cleared-timeout', 'hidden-finalize', 'missing-raw-finalize',
                                      'forged-finalize', 'finalize-outcome', 'grouped-status', 'grouped-returncode'])
def test_reconcile_aggregate_and_failure_classifications(tmp_path, mutation):
    nodes = load_profile()['nodes'][:1]
    directory = tmp_path / 'run'
    disposition = 'timeout' if mutation == 'cleared-timeout' else 'passed' if mutation == 'forged-finalize' else 'finalize'
    root = write_evidence(directory, nodes, disposition)
    payload = json.loads((directory / 'results.json').read_text())
    if mutation == 'cleared-timeout':
        payload['summary']['incomplete'] = False
    elif mutation == 'hidden-finalize':
        payload['units'][0]['tests'] = []
        payload['units'][0]['status'] = 'passed'
        payload['units'][0]['returncode'] = 0
        payload['units'][0]['counts']['error'] = 0
    elif mutation == 'missing-raw-finalize':
        records = [json.loads(line) for line in (directory / 'report.jsonl').read_text().splitlines()]
        records = [r for r in records if r.get('$report_type') != 'TeardownFinalize']
        (directory / 'report.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in records))
    elif mutation == 'forged-finalize':
        payload['units'][0]['tests'].append({'nodeid': 'C_Finalize::teardown',
                                            'lifecycle': 'session-teardown', 'outcome': 'error'})
    elif mutation == 'finalize-outcome':
        payload['units'][0]['tests'][0]['outcome'] = 'crashed'
    elif mutation == 'grouped-status':
        payload['units'][0]['status'] = 'passed'
    else:
        payload['units'][0]['returncode'] = 0
    (directory / 'results.json').write_text(json.dumps(payload))
    result = validate_results(directory, nodes, root)
    assert not result['complete'], result
    assert result['observations_complete'] is (mutation == 'cleared-timeout'), result


def test_build_provenance_file_reaches_native_assembler(tmp_path):
    from p11lab.checker import LOCK, SOURCE, WHEEL, checker_environment
    provenance = pytest.importorskip('pkcs11_check.provenance')
    env = checker_environment(tmp_path, 'secret-pin', 'secret-so-pin')
    path = Path(env['PKCS11_CHECK_BUILD_PROVENANCE'])
    assert path.is_file() and path.parent == tmp_path
    assert path.stat().st_mode & 0o777 == 0o600
    native = provenance.assemble(env=env, repo_root=None, build_file=path,
                                 data_manifest={}, data_dir=tmp_path, environment=None)
    assert native['extra']['checker'] == {'source_revision': SOURCE, 'wheel_sha256': WHEEL,
                                          'runtime_lock_sha256': LOCK}
    assert 'secret' not in path.read_text()


DECLARED_DESCRIPTOR = {'runtime_env': [
    {'name': 'FHSM_TOKENS_DIR', 'value': '/var/lib/p11lab/freehsm'},
    {'name': 'FHSM_INTEGRITY_ALLOW_UNSIGNED', 'value': '1'},
    {'name': 'FHSM_KAT_ALLOW_FAIL', 'value': '1'},
]}


def test_checker_environment_applies_declared_fixed_env(tmp_path, monkeypatch):
    from p11lab.checker import checker_environment
    monkeypatch.setenv('FHSM_TOKENS_DIR', '/wrong/dir')
    env = checker_environment(tmp_path, 'secret-pin', 'secret-so-pin',
                              provider_descriptor=DECLARED_DESCRIPTOR)
    assert env['FHSM_TOKENS_DIR'] == '/var/lib/p11lab/freehsm'
    assert env['FHSM_INTEGRITY_ALLOW_UNSIGNED'] == '1'
    assert env['FHSM_KAT_ALLOW_FAIL'] == '1'


def test_checker_environment_still_scrubs_undeclared_vars(tmp_path, monkeypatch):
    from p11lab.checker import checker_environment
    monkeypatch.setenv('FHSM_UNDECLARED', '1')
    monkeypatch.setenv('P11TEST_PIN', 'ambient-selection')
    monkeypatch.setenv('PYTEST_ADDOPTS', '-x')
    env = checker_environment(tmp_path, 'secret-pin', 'secret-so-pin',
                              provider_descriptor=DECLARED_DESCRIPTOR)
    assert 'FHSM_UNDECLARED' not in env
    assert env['P11TEST_PIN'] == 'secret-pin'
    assert env['PYTEST_ADDOPTS'] == '-v'


def test_checker_environment_keeps_declared_values_out_of_evidence(tmp_path):
    from p11lab.checker import checker_environment
    env = checker_environment(tmp_path, 'secret-pin', 'secret-so-pin',
                              provider_descriptor=DECLARED_DESCRIPTOR)
    provenance = Path(env['PKCS11_CHECK_BUILD_PROVENANCE']).read_text()
    assert '/var/lib/p11lab/freehsm' not in provenance


def test_checker_environment_rejects_invalid_declaration(tmp_path):
    from p11lab.checker import checker_environment
    with pytest.raises(ValueError):
        checker_environment(tmp_path, 'p', 's',
                            provider_descriptor={'runtime_env': [{'name': 'X_PIN', 'value': '1'}]})


def test_checker_environment_without_declaration_keeps_base_allowlist(tmp_path, monkeypatch):
    from p11lab.checker import checker_environment
    monkeypatch.setenv('FHSM_TOKENS_DIR', '1')
    monkeypatch.setenv('SOFTHSM2_CONF', '/run/p11lab/softhsm2.conf')
    env = checker_environment(tmp_path, 'p', 's', provider_descriptor={})
    assert 'FHSM_TOKENS_DIR' not in env
    assert env['SOFTHSM2_CONF'] == '/run/p11lab/softhsm2.conf'


def test_checker_environment_reads_in_image_declaration(tmp_path, monkeypatch):
    import p11lab.checker as checker_module
    from p11lab.checker import checker_environment
    output = tmp_path / 'out'
    output.mkdir()
    declared = tmp_path / 'provider.json'
    declared.write_text(json.dumps(DECLARED_DESCRIPTOR))
    monkeypatch.setattr(checker_module, 'PROVIDER_DESCRIPTOR_PATH', declared)
    env = checker_environment(output, 'p', 's')
    assert env['FHSM_TOKENS_DIR'] == '/var/lib/p11lab/freehsm'


def test_checker_environment_missing_declaration_file_is_no_extension(tmp_path, monkeypatch):
    import p11lab.checker as checker_module
    from p11lab.checker import checker_environment
    monkeypatch.setattr(checker_module, 'PROVIDER_DESCRIPTOR_PATH', tmp_path / 'absent.json')
    env = checker_environment(tmp_path, 'p', 's')
    assert 'FHSM_TOKENS_DIR' not in env


def test_checker_environment_corrupt_declaration_file_fails_closed(tmp_path, monkeypatch):
    import p11lab.checker as checker_module
    from p11lab.checker import checker_environment
    output = tmp_path / 'out'
    output.mkdir()
    corrupt = tmp_path / 'provider.json'
    corrupt.write_text('{not json')
    monkeypatch.setattr(checker_module, 'PROVIDER_DESCRIPTOR_PATH', corrupt)
    with pytest.raises(ValueError):
        checker_environment(output, 'p', 's')


def test_checker_environment_redirects_windows_home(tmp_path, monkeypatch):
    import os

    from p11lab.checker import checker_environment

    monkeypatch.setattr(os, 'name', 'nt')
    monkeypatch.delenv('USERPROFILE', raising=False)
    env = checker_environment(tmp_path, 'secret-pin', 'secret-so-pin')
    assert env['USERPROFILE'] == str(tmp_path)
    assert env['HOME'] == str(tmp_path)


def test_checker_environment_scrubs_home_on_posix(tmp_path, monkeypatch):
    import os

    from p11lab.checker import checker_environment

    monkeypatch.setattr(os, 'name', 'posix')
    monkeypatch.setenv('USERPROFILE', 'C:\\Users\\someone')
    env = checker_environment(tmp_path, 'secret-pin', 'secret-so-pin')
    assert 'USERPROFILE' not in env
    assert env['HOME'] == str(tmp_path)


def test_checker_private_api_resolves_pinned_version():
    import importlib.metadata

    pytest.importorskip("pkcs11_check.testcases")
    if importlib.metadata.version("pkcs11-check") != "0.2.2":
        pytest.skip("checker validation adapter pins pkcs11-check 0.2.2")
    from p11lab.checker import _checker_private_api

    api = _checker_private_api()
    assert callable(api["completion_verified_for_attempt"])
    assert callable(api["build_detail_from_report_records"])
    assert callable(api["build_isolated_json_payload"])
    assert api["FileRunResult"].__name__ == "FileRunResult"
    assert api["FileRunState"].__name__ == "FileRunState"


def test_checker_private_api_rejects_other_versions(monkeypatch):
    import importlib.metadata

    from p11lab import checker

    monkeypatch.setattr(importlib.metadata, "version", lambda name: "9.9.9")
    with pytest.raises(ValueError, match="requires pkcs11-check 0.2.2"):
        checker._checker_private_api()


def test_checker_private_imports_live_only_in_adapter():
    import inspect

    from p11lab import checker

    adapter = inspect.getsource(checker._checker_private_api)
    outside = inspect.getsource(checker).replace(adapter, "")
    for name in ("_completion_verified_for_attempt", "_build_detail_from_report_records",
                 "_build_isolated_json_payload", "FileRunState"):
        assert name in adapter
    for line in outside.splitlines():
        if line.strip().startswith("from pkcs11_check"):
            assert "._" not in line and " import _" not in line


class _FakeToken:
    def __init__(self, label):
        self.label = label


class _FakeSlot:
    def __init__(self, slot_id, label):
        self.slot_id = slot_id
        self._token = _FakeToken(label)

    def get_token(self):
        return self._token


def test_select_token_slot_matches_single_label():
    from p11lab.checker import select_token_slot
    slots = [_FakeSlot(7, 'haskoki-demo'), _FakeSlot(9, 'P11Lab')]
    assert select_token_slot(slots, 'haskoki-demo') == (0, 7)
    assert select_token_slot(slots, 'P11Lab') == (1, 9)


def test_select_token_slot_reports_tried_and_observed_labels():
    from p11lab.checker import select_token_slot
    with pytest.raises(ValueError) as mismatch:
        select_token_slot([_FakeSlot(7, 'haskoki-demo')], 'P11Lab')
    assert "label='P11Lab'" in str(mismatch.value)
    assert 'haskoki-demo' in str(mismatch.value)
    with pytest.raises(ValueError) as ambiguous:
        select_token_slot([_FakeSlot(7, 'P11Lab'), _FakeSlot(9, 'P11Lab')], 'P11Lab')
    assert "label='P11Lab'" in str(ambiguous.value)


PROXY_TRANSPORT = {
    'PKCS11_PROXY_ENDPOINT': 'https://provider-daemon:8443',
    'PKCS11_PROXY_TLS_CA_CERT': '/run/p11lab/tls/ca.crt',
    'PKCS11_PROXY_TLS_CLIENT_CERT': '/run/p11lab/tls/client.crt',
    'PKCS11_PROXY_TLS_CLIENT_KEY': '/run/p11lab/tls/client.key',
    'PKCS11_PROXY_CONNECT_TIMEOUT': '10',
}


def test_checker_environment_preserves_complete_proxy_transport(tmp_path, monkeypatch):
    from p11lab.checker import checker_environment
    monkeypatch.setenv('PKCS11_PROXY_ENDPOINT', 'https://ambient.example:1')
    env = checker_environment(tmp_path, 'p', 's', provider_descriptor={},
                              proxy_env=dict(PROXY_TRANSPORT),
                              module_path='/run/p11lab-client/libpkcs11_proxy_ng_shim.so')
    for name, value in PROXY_TRANSPORT.items():
        assert env[name] == value


def test_checker_environment_scrubs_ambient_proxy_without_explicit_transport(tmp_path, monkeypatch):
    from p11lab.checker import checker_environment
    for name, value in PROXY_TRANSPORT.items():
        monkeypatch.setenv(name, value)
    env = checker_environment(tmp_path, 'p', 's', provider_descriptor={})
    for name in PROXY_TRANSPORT:
        assert name not in env


def test_checker_environment_rejects_partial_or_foreign_proxy_transport(tmp_path):
    from p11lab.checker import checker_environment
    partial = dict(PROXY_TRANSPORT)
    del partial['PKCS11_PROXY_CONNECT_TIMEOUT']
    with pytest.raises(ValueError):
        checker_environment(tmp_path, 'p', 's', provider_descriptor={}, proxy_env=partial)
    foreign = dict(PROXY_TRANSPORT, PKCS11_PROXY_EXTRA='1')
    with pytest.raises(ValueError):
        checker_environment(tmp_path, 'p', 's', provider_descriptor={}, proxy_env=foreign)


def test_checker_environment_rejects_unclean_proxy_values(tmp_path):
    from p11lab.checker import checker_environment
    bad_endpoint = dict(PROXY_TRANSPORT, PKCS11_PROXY_ENDPOINT='http://provider-daemon:8443')
    with pytest.raises(ValueError):
        checker_environment(tmp_path, 'p', 's', provider_descriptor={}, proxy_env=bad_endpoint)
    bad_timeout = dict(PROXY_TRANSPORT, PKCS11_PROXY_CONNECT_TIMEOUT='10\n20')
    with pytest.raises(ValueError):
        checker_environment(tmp_path, 'p', 's', provider_descriptor={}, proxy_env=bad_timeout)


def test_proxy_transport_from_environ_requires_all_or_none(monkeypatch):
    from p11lab.checker import proxy_transport_from_environ
    assert proxy_transport_from_environ({}) is None
    assert proxy_transport_from_environ(dict(PROXY_TRANSPORT)) == PROXY_TRANSPORT
    with pytest.raises(ValueError):
        proxy_transport_from_environ({'PKCS11_PROXY_ENDPOINT': 'https://provider-daemon:8443'})
    for name in PROXY_TRANSPORT:
        monkeypatch.delenv(name, raising=False)
    assert proxy_transport_from_environ() is None
    for name, value in PROXY_TRANSPORT.items():
        monkeypatch.setenv(name, value)
    assert proxy_transport_from_environ() == PROXY_TRANSPORT


def test_validated_proxy_transport_accepts_only_the_clean_five():
    from p11lab.checker import _validated_proxy_transport
    assert _validated_proxy_transport(dict(PROXY_TRANSPORT)) == PROXY_TRANSPORT
    partial = dict(PROXY_TRANSPORT)
    del partial['PKCS11_PROXY_ENDPOINT']
    with pytest.raises(ValueError):
        _validated_proxy_transport(partial)
    with pytest.raises(ValueError):
        _validated_proxy_transport(dict(PROXY_TRANSPORT, PKCS11_PROXY_EXTRA='1'))
    bad = dict(PROXY_TRANSPORT, PKCS11_PROXY_ENDPOINT='http://provider-daemon:8443')
    with pytest.raises(ValueError):
        _validated_proxy_transport(bad)


def test_install_proxy_transport_leaves_direct_ambient_untouched(monkeypatch):
    import os
    from p11lab.checker import _install_proxy_transport
    monkeypatch.setenv('PKCS11_PROXY_ENDPOINT', 'https://stale.example:1')
    assert _install_proxy_transport('execute') is None
    assert os.environ['PKCS11_PROXY_ENDPOINT'] == 'https://stale.example:1'
    for name, value in PROXY_TRANSPORT.items():
        monkeypatch.setenv(name, value)
    assert _install_proxy_transport('execute') is None
    assert os.environ['PKCS11_PROXY_ENDPOINT'] == PROXY_TRANSPORT['PKCS11_PROXY_ENDPOINT']


def test_install_proxy_transport_scrubs_and_installs_for_proxy_action(monkeypatch):
    import os
    from p11lab.checker import _install_proxy_transport
    for name in PROXY_TRANSPORT:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv('PKCS11_PROXY_TLS_DOMAIN', raising=False)
    with pytest.raises(ValueError):
        _install_proxy_transport('execute-proxy')
    monkeypatch.setenv('PKCS11_PROXY_ENDPOINT', 'https://provider-daemon:8443')
    with pytest.raises(ValueError):
        _install_proxy_transport('execute-proxy')
    for name, value in PROXY_TRANSPORT.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv('PKCS11_PROXY_TLS_DOMAIN', 'stale.example')
    assert _install_proxy_transport('execute-proxy') == PROXY_TRANSPORT
    assert 'PKCS11_PROXY_TLS_DOMAIN' not in os.environ
    for name, value in PROXY_TRANSPORT.items():
        assert os.environ[name] == value


def test_run_checker_selects_execute_action_by_mode(tmp_path, monkeypatch):
    import json
    from p11lab.checker import run_checker
    from p11lab.models import ArtifactRef, RunResult, RunSpec
    import p11lab.run
    captured = {}
    receipt_path = tmp_path / 'outer-receipt.json'
    receipt_path.write_text(json.dumps({'lifecycle_errors': [], 'exit_code': 0}))
    def fake(spec):
        captured[spec.mode] = spec.argv
        return RunResult(app_returncode=0, lifecycle_errors=(), cleanup_errors=(),
                         exit_code=0, receipt_path=receipt_path)
    monkeypatch.setattr(p11lab.run, 'run_application', fake)
    for mode in ('direct', 'proxy'):
        spec = RunSpec(environment='softhsm2', channel='release', mode=mode,
                       artifact=ArtifactRef('docker-local', 'sha256:' + '0' * 64,
                                            '0' * 64, 'linux/amd64'),
                       execution_location='provider', consumer_artifact=None,
                       client_artifact=None, argv=(), inputs={},
                       output_dir=tmp_path / ('out-' + mode), cwd=tmp_path,
                       timeout_seconds=10)
        run_checker(spec, 'smoke-v1')
    assert captured['direct'][3] == 'execute'
    assert captured['proxy'][3] == 'execute-proxy'
    assert json.loads(captured['direct'][4])
    assert json.loads(captured['proxy'][4])
