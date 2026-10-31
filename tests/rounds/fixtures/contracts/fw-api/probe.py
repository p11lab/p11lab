"""Isolated test-only probe of the reviewed, installed public evaluator.

Dynamic access is confined to this explicit fixture inventory. The sole private
schema introspection is here; production coverage consumers use the literal list.
"""
from __future__ import annotations
import copy
import dataclasses
import hashlib
import importlib.util
import inspect
import io
import itertools
import json
import platform
import re
import subprocess
import sys
from pathlib import Path

import pkcs11_check
from pkcs11_check.core import evidence as e
from pkcs11_check.core.report_log import SessionCompletionTracker, iter_report_log_records

MODE, ROOT, FIXTURES = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3])

assert Path(pkcs11_check.__file__).is_relative_to(ROOT / 'evaluator-install'), pkcs11_check.__file__
assert platform.python_version() == '3.12.14'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def load(path):
    return json.loads(path.read_text())


def companion():
    spec = importlib.util.spec_from_file_location('trusted_e4', ROOT / 'source-companion/scripts/verify_round_receipt.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def api_probe(expected, coverage_expected=None, production_contract=None):
    verifier = companion()
    actual = {}
    for name in expected:
        if name.startswith('scripts/'):
            obj = getattr(verifier, name.split(':')[1])
        elif name.startswith('core.report_log.'):
            obj = {'SessionCompletionTracker': SessionCompletionTracker,
                   'iter_report_log_records': iter_report_log_records}[name.rsplit('.', 1)[1]]
        elif '.' in name:
            cls, method = name.split('.')
            owner = SessionCompletionTracker if cls == 'SessionCompletionTracker' else getattr(e, cls)
            obj = getattr(owner, method)
        else:
            obj = getattr(e, name)
        row = {}
        if isinstance(obj, (str, int)):
            row.update(module=None, value=obj)
        elif '.' in name and not name.startswith(('core.', 'scripts/')):
            is_prop = isinstance(obj, property)
            row.update(property=is_prop, signature=str(inspect.signature(obj.fget if is_prop else obj)))
        else:
            row.update(signature=str(inspect.signature(obj)))
            if 'module' in expected[name]:
                row['module'] = obj.__module__
            if dataclasses.is_dataclass(obj):
                row['fields'] = [{'name': f.name, 'type': str(f.type),
                                  'default': repr(f.default) if f.default is not dataclasses.MISSING else '<required>'}
                                 for f in dataclasses.fields(obj)]
            if name == 'Outcome':
                row['values'] = [v.value for v in obj]
        actual[name] = row
    assert actual == expected, json.dumps({k: {'actual': actual.get(k), 'expected': expected[k]} for k in expected if actual.get(k) != expected[k]}, indent=2)
    from pkcs11_check.core.quality_audit import _MECHANISM_COMPARISON_STATES
    fields = list(_MECHANISM_COMPARISON_STATES)
    fixed = load(FIXTURES / 'coverage-schema/09aabfec.json')
    production_path = production_contract or Path(__file__).resolve().parents[5] / 'src/p11lab/data/rounds/contract.json'
    production = load(production_path)['coverage_fields']
    assert production == fixed == fields, 'production coverage schema drift'
    assert fields == (coverage_expected if coverage_expected is not None else fixed), fields
    return {'api_count': len(actual), 'python': platform.python_version(), 'coverage_fields': fields}


def canonical(text):
    return ' '.join(re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', text).split())


def cli_command(args):
    # Stable public program name, isolated interpreter, no caller import paths.
    return [sys.executable, '-I', '-B', '-c',
            'from pkcs11_check.cli.app import app;app(prog_name="pkcs11-check")', *args]


def call(argv, **kwargs):
    return subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, timeout=60, **kwargs)


def cli_capture():
    from typer.main import get_command
    from pkcs11_check.cli.app import app
    root = get_command(app)
    names = ['root', 'list-tests', 'shard-units', 'test', 'fetch-data', 'compare-coverage',
             'evidence-export', 'evidence-admit', 'evidence-compare', 'merge-shards']
    signatures = {}
    snapshots = []
    for name in names:
        command = root if name == 'root' else root.commands[name]
        params = []
        for p in command.params:
            default = p.default
            if hasattr(default, 'value'):
                default = default.value
            if not isinstance(default, (str, int, float, bool, list, tuple, type(None))):
                default = repr(default)
            info = {'name': p.name, 'kind': p.param_type_name, 'opts': p.opts,
                    'secondary_opts': p.secondary_opts, 'required': p.required,
                    'default': default, 'nargs': p.nargs, 'type': p.type.name}
            if hasattr(p.type, 'choices'):
                info['choices'] = list(p.type.choices)
            params.append(info)
        signatures[name] = {'parameters': params}
        if name == 'root':
            signatures[name]['commands'] = list(root.commands)
        args = ['--help'] if name == 'root' else [name, '--help']
        proc = call(cli_command(args))
        assert proc.returncode == 0, proc.stderr
        snapshots.append({'command': ['pkcs11-check', *args], 'returncode': proc.returncode,
                          'stdout': proc.stdout, 'stderr': proc.stderr,
                          'stdout_sha256': sha(proc.stdout.encode()), 'stderr_sha256': sha(proc.stderr.encode()),
                          'canonical_stdout': canonical(proc.stdout), 'canonical_stderr': canonical(proc.stderr)})
    # Capture argparse's constructed parameter contract before reading any receipt.
    import argparse
    class CapturedParser(Exception):
        pass
    captured = []
    original_parse = argparse.ArgumentParser.parse_args
    def capture_parser(parser, *args, **kwargs):
        captured.append(parser)
        raise CapturedParser()
    argparse.ArgumentParser.parse_args = capture_parser
    try:
        companion().main([])
    except CapturedParser:
        pass
    finally:
        argparse.ArgumentParser.parse_args = original_parse
    assert len(captured) == 1
    signatures['verify-round-receipt'] = {'parameters': [
        {'name': action.dest, 'kind': 'option' if action.option_strings else 'argument',
         'opts': action.option_strings, 'secondary_opts': [], 'required': action.required,
         'default': action.default, 'nargs': action.nargs,
         'type': action.type.__name__ if action.type is not None else 'str'}
        for action in captured[0]._actions]}
    proc = call([sys.executable, '-I', '-B', str(ROOT / 'source-companion/scripts/verify_round_receipt.py'), '--help'])
    assert proc.returncode == 0, proc.stderr
    snapshots.append({'command': ['python3', 'scripts/verify_round_receipt.py', '--help'],
                      'returncode': proc.returncode, 'stdout': proc.stdout, 'stderr': proc.stderr,
                      'stdout_sha256': sha(proc.stdout.encode()), 'stderr_sha256': sha(proc.stderr.encode()),
                      'canonical_stdout': canonical(proc.stdout), 'canonical_stderr': canonical(proc.stderr)})
    return {'framework_sha': '09aabfec9fea7e424aabb991f6347349bfa84075', 'python': '3.12.14',
            'signatures': signatures, 'snapshots': snapshots}


def cli_probe():
    observed = cli_capture()
    expected = load(FIXTURES / 'fw-cli/09aabfec-python312.json')
    assert observed['signatures'] == expected['signatures'], 'parsed CLI signatures/defaults drifted'
    for current, fixed in zip(observed['snapshots'], expected['snapshots'], strict=True):
        assert current['command'] == fixed['command']
        assert current['returncode'] == fixed['returncode'] == 0
        assert current['canonical_stdout'] == fixed['canonical_stdout'], current['command']
        assert current['canonical_stderr'] == fixed['canonical_stderr'], current['command']
        assert sha(fixed['stdout'].encode()) == fixed['stdout_sha256']
        assert sha(fixed['stderr'].encode()) == fixed['stderr_sha256']
    (ROOT / 'contract-help-observed.json').write_text(json.dumps(observed, indent=2) + '\n')
    return {'help_count': len(observed['snapshots']), 'signature_count': len(observed['signatures'])}


def semantic_probe():
    fixed = FIXTURES / 'fw-api'
    streams = [fixed / f'outer{i}.jsonl' for i in (1, 2)]
    originals = [p.read_bytes() for p in streams]
    identity = {'lane': 'linux-amd64/softhsm/direct', 'lane_os': 'linux', 'lane_arch': 'amd64',
                'framework_sha': '09aabfec9fea7e424aabb991f6347349bfa84075', 'p11lab_sha': '0' * 40,
                'image_digest': 'sha256:' + '1' * 64, 'corpus_hash': '2' * 64,
                'disabled_hash': '3' * 64, 'planned_collection_hash': '4' * 64, 'planned_count': '1'}
    invalid = [0]
    def on_invalid():
        invalid[0] += 1
    sink = io.StringIO()
    header = e.export_ledger(iter_report_log_records(streams[0], on_invalid=on_invalid), identity, sink,
                             reader_invalid_lines=lambda: invalid[0])
    ledger_path = ROOT / 'N1-contract.ledger.jsonl'
    ledger_path.write_text(sink.getvalue())
    loaded_header, rows = e.load_ledger(ledger_path)
    assert loaded_header == header
    assert len(rows) == 1 and (rows[0].node_id, rows[0].phase) == ('test_a.py::test_one', 'call')
    assert rows[0].shard_id == 'outer1/shard0' and rows[0].attempt == 1
    assert list(iter_report_log_records(streams[1]))[0]['shard_id'] == 'outer2/shard0'
    roster = e.PredeclaredRoster(lane=header.lane,
        shards={'outer1/shard0': e.ShardExpectation(records=1, sha256=e.shard_digest(rows))})
    obligations = e.compile_obligations({'test_a.py::test_one': {}}, {'cases': ['test_a.py::test_one']})
    assert isinstance(obligations, e.ObligationInventory)
    assert obligations.members == frozenset({'test_a.py::test_one'}) and obligations.unselected == frozenset()
    admitted = e.admit_lane(header, rows, roster, obligations)
    assert admitted.admitted and admitted.failures == [] and admitted.warnings == []
    # Native row/header serialization, canonical seal and lifecycle return contracts.
    assert e.LedgerHeader.from_record(header.to_record(), line_number=1) == header
    assert e.LedgerRow.from_record(rows[0].to_record(), line_number=2) == rows[0]
    assert rows[0].sort_key == ('test_a.py::test_one', 'call', 1)
    assert isinstance(e.row_blob(rows[0]), bytes)
    assert e.shard_digest([]) == e.EMPTY_SHARD_SHA256
    tracker = SessionCompletionTracker()
    for record in iter_report_log_records(streams[0]):
        assert tracker.observe(record) is None
    assert tracker.complete is True and tracker.single_exitstatus == 0
    assert tracker.invalidate() is None and tracker.complete is False
    empty_deltas = e.RotationDeltas(version='ComparisonAdmissionV1', entries=())
    assert e.validate_deltas(empty_deltas) == []
    policy = e.QuorumPolicy(min_repeats=1, quorum_frac=1.0, disagree_is_unstable=True)
    verdict = e.compare_lanes((header, rows), (header, rows), empty_deltas, policy)
    assert isinstance(verdict, e.ComparisonVerdict)
    assert verdict.counts['compared'] == 1 and verdict.regressions == verdict.improvements == verdict.unstable == []
    combined = e.combine_attempts(rows, policy)
    assert combined == (e.fingerprint(rows[0]), []) and len(combined[0]) == 7
    collision = io.StringIO()
    try:
        e.export_ledger(itertools.chain.from_iterable(iter_report_log_records(p) for p in streams), identity, collision)
    except ValueError as exc:
        n2 = {'type': type(exc).__name__, 'error': str(exc), 'output_bytes': len(collision.getvalue().encode()),
              'original_bytes_preserved': originals == [p.read_bytes() for p in streams]}
    else:
        raise AssertionError('reviewed N=2 collision disappeared; new API/pin review required')
    assert 'duplicate occurrence key' in n2['error'] and n2['output_bytes'] == 0
    result = {'N1': {'admitted': admitted.admitted, 'compared': verdict.counts['compared']}, 'N2': n2,
              'coverage_veto_owner': 'W10'}
    failed = dataclasses.replace(rows[0], outcome=e.Outcome.FAILED, reason='failure-one')
    skipped = dataclasses.replace(rows[0], outcome=e.Outcome.SKIPPED, reason='capability')
    fixtures = {'identical_failed': ([failed], [failed]),
                'changed_reason': ([failed], [dataclasses.replace(failed, reason='failure-two')]),
                'added_skip': (rows, [*rows, dataclasses.replace(skipped, node_id='test_a.py::test_added')]), 'failed_to_skip': ([failed], [skipped]),
                'effect_only': ([failed], [dataclasses.replace(failed, effect='changed-side-effect')])}
    for name, (old, new) in fixtures.items():
        compared = e.compare_lanes((header, old), (header, new), empty_deltas, policy)
        result[name] = {'regressions': len(compared.regressions), 'improvements': len(compared.improvements),
                        'unstable': len(compared.unstable)}
    result['effect_only']['effect_retained'] = fixtures['effect_only'][1][0].to_record()['effect'] == 'changed-side-effect'
    result['quorum'] = {}
    for tier, count in [('smoke', 1), ('release', 2)]:
        p = e.QuorumPolicy(min_repeats=count, quorum_frac=1.0, disagree_is_unstable=True)
        result['quorum'][tier] = [p.min_repeats, p.quorum_frac, p.disagree_is_unstable]
    # Expose the unanimous shortcut as a limit: scheduling is independently closed later.
    assert e.combine_attempts(rows, e.QuorumPolicy(min_repeats=2, quorum_frac=1.0, disagree_is_unstable=True))[1] == []
    verifier = companion()
    assert isinstance(verifier.validate_lock({}), list) and verifier.validate_lock({})
    assert isinstance(verifier.validate_receipt(None, {}, 'bad'), list)
    assert isinstance(verifier.compute_bundle_identity({'a': '1' * 64}), str)
    assert len(verifier.compute_bundle_identity({'a': '1' * 64})) == 64
    from contextlib import redirect_stderr
    malformed = ROOT / 'contract-e4-empty.json'
    malformed.write_text('{}')
    with redirect_stderr(io.StringIO()):
        exit_status = verifier.main([str(malformed), '--lock', str(malformed), '--expect-fw', identity['framework_sha']])
    assert type(exit_status) is int and exit_status == 2
    (ROOT / 'contract-semantics.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def drift_probe(mutation):
    expected = load(FIXTURES / 'coverage-schema/09aabfec.json')
    observed = expected.copy()
    if mutation == 'add':
        observed.append('new_state')
    elif mutation == 'remove':
        observed.pop()
    elif mutation == 'reorder':
        observed[0], observed[1] = observed[1], observed[0]
    elif mutation == 'unknown-api':
        expected_api = load(FIXTURES / 'fw-api/09aabfec.json')
        expected_api['unreviewed_api'] = {}
        try:
            api_probe(expected_api)
        except (AssertionError, AttributeError):
            return {'rejected': True}
        raise AssertionError('unknown API was accepted')
    elif mutation == 'unknown-flag':
        proc = call(cli_command(['evidence-compare', '--unreviewed-flag']))
        assert proc.returncode == 2 and 'No such option' in proc.stderr
        return {'rejected': True}
    else:
        raise AssertionError(mutation)
    try:
        api_probe(load(FIXTURES / 'fw-api/09aabfec.json'), coverage_expected=observed)
    except AssertionError:
        return {'rejected': True}
    raise AssertionError('coverage mutation was accepted')


def batch_probe():
    # Only argument/manifest/collection validation: never loads a provider.
    import os
    target = 'test_blake2.py'
    nodeids = [target + '::test_fixture']
    payload = {'source': target, 'source_collection_count': 1,
               'source_collection_sha256': sha(json.dumps(nodeids, separators=(',', ':')).encode()), 'nodeids': nodeids}
    def manifest(data):
        data = copy.deepcopy(data)
        data['batch_id'] = sha(json.dumps({k: data[k] for k in payload}, sort_keys=True, separators=(',', ':')).encode())
        data.update(schema=1, plan_id='5' * 64)
        return data
    folder = ROOT / 'contract-batch'
    folder.mkdir(exist_ok=True)
    path = folder / 'selection.json'
    path.write_text(json.dumps(manifest(payload)))
    common = ['test', target, '--module', str(folder / 'missing-provider.so'), '--selection-manifest', str(path),
              '--format', 'json', '--isolation', 'file']
    rejected = {}
    transcripts = {}
    for label in ['format', 'isolation', 'target', 'count', 'digest', 'extra-field', 'unknown-flag']:
        args = common.copy()
        data = manifest(payload)
        expected_message = ''
        if label == 'format':
            args[args.index('json')] = 'summary'
            expected_message = 'requires --format json'
        elif label == 'isolation':
            args[-1] = 'test'
            expected_message = 'requires --isolation file'
        elif label == 'target':
            args[1] += '::test_fixture'
            expected_message = 'exactly one bare file target'
        elif label == 'count':
            data['source_collection_count'] = 0
            expected_message = 'source_collection_count'
        elif label == 'digest':
            data['source_collection_sha256'] = 'bad'
            expected_message = 'source_collection_sha256'
        elif label == 'extra-field':
            data['extra'] = True
            expected_message = 'unknown keys'
        else:
            args.append('--unreviewed-flag')
            expected_message = 'No such option'
        path.write_text(json.dumps(data))
        proc = call(cli_command(args))
        assert proc.returncode == 2, (label, proc.returncode, proc.stdout, proc.stderr)
        assert expected_message in proc.stdout + proc.stderr, (label, proc.stdout, proc.stderr)
        assert 'Module not found' not in proc.stdout + proc.stderr
        rejected[label] = proc.returncode
        transcripts[label] = {'argv': args, 'returncode': proc.returncode, 'stdout': proc.stdout, 'stderr': proc.stderr}
    # Well-formed but false count/digest must also fail the real installed plugin,
    # not merely a manifest-format check. Collection-only runs no provider fixtures.
    import pkcs11_check.testcases
    source = Path(pkcs11_check.testcases.__file__).parent / target
    for key, value, message in [('source_collection_count', 999999, 'source_collection_count mismatch'),
                                 ('source_collection_sha256', '0' * 64, 'source_collection_sha256 mismatch')]:
        if key.endswith('sha256'):
            base = call([sys.executable, '-I', '-B', '-m', 'pytest', '--collect-only', '-q', str(source), '-p', 'no:cacheprovider'])
            assert base.returncode == 0, base.stderr + base.stdout
            count = len(re.findall(r'^.*::.+$', base.stdout, re.MULTILINE))
            assert count > 0, base.stdout
        else:
            count = 999999
        data = dict(payload, source_collection_count=count)
        data[key] = value
        path.write_text(json.dumps(manifest(data)))
        env = dict(os.environ, PKCS11_CHECK_SELECTION_MANIFEST=str(path))
        proc = call([sys.executable, '-I', '-B', '-m', 'pytest', '--collect-only', '-q', str(source), '-p', 'no:cacheprovider'], env=env)
        assert proc.returncode != 0 and message in proc.stdout + proc.stderr, proc.stdout + proc.stderr
        transcripts[key] = {'returncode': proc.returncode, 'stdout': proc.stdout, 'stderr': proc.stderr}
    (ROOT / 'contract-batch.json').write_text(json.dumps(transcripts, indent=2) + '\n')
    return {'rejected': rejected}


if MODE == 'api':
    answer = api_probe(load(FIXTURES / 'fw-api/09aabfec.json'), production_contract=Path(sys.argv[4]) if len(sys.argv) > 4 else None)
elif MODE == 'cli':
    answer = cli_probe()
elif MODE == 'capture-cli':
    answer = cli_capture()
elif MODE == 'drift':
    answer = drift_probe(sys.argv[4])
elif MODE == 'semantics':
    answer = semantic_probe()
elif MODE == 'batch':
    answer = batch_probe()
else:
    raise AssertionError(MODE)
print(json.dumps(answer))
