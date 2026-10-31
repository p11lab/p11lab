"""Contract expectations are fixed to the reviewed 09aabfec public API."""
import json
from pathlib import Path
import subprocess
import pytest
from test_evaluator_build import evaluator  # noqa: F401 -- shared installed build fixture

# ruff: noqa: F811 -- pytest resolves this imported fixture by parameter name


def test_reviewed_contract_is_packaged():
    path = Path(__file__).resolve().parents[2] / 'src/p11lab/data/rounds/contract.json'
    assert path.is_file(), 'reviewed executable evaluator contract missing'
    data = json.loads(path.read_text())
    assert data['framework_sha'] == '09aabfec9fea7e424aabb991f6347349bfa84075'
    assert data['release_dependencies']['EVID-STREAM-1']['status'] == 'blocked'
    assert data['coverage_fields'] == json.loads((Path(__file__).parent / 'fixtures/contracts/coverage-schema/09aabfec.json').read_text())

FIXTURES = Path(__file__).parent / 'fixtures/contracts'


def run_probe(evaluator, mode, *args):
    receipt, root = evaluator
    script = FIXTURES / 'fw-api/probe.py'
    assert script.is_file(), 'installed evaluator probe missing'
    result = subprocess.run([str(root / 'evaluator-install/bin/python3'), '-I', '-B',
                             str(script), mode, str(root), str(FIXTURES), *map(str, args)],
                            env=receipt['environment'], cwd=root, capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stderr + result.stdout
    return json.loads(result.stdout)


def test_installed_public_signatures_fields_methods_constants(evaluator):
    data = run_probe(evaluator, 'api')
    assert data['api_count'] == 39
    assert data['python'] == '3.12.14'
    fixed = json.loads((FIXTURES / 'coverage-schema/09aabfec.json').read_text())
    production = json.loads((Path(__file__).resolve().parents[2] / 'src/p11lab/data/rounds/contract.json').read_text())['coverage_fields']
    assert data['coverage_fields'] == fixed == production


@pytest.mark.parametrize('mutation', ['add', 'remove', 'reorder', 'unknown-api', 'unknown-flag'])
def test_contract_drift_fails(evaluator, mutation):
    assert run_probe(evaluator, 'drift', mutation)['rejected'] is True


def test_complete_help_and_parsed_cli_contract(evaluator):
    data = run_probe(evaluator, 'cli')
    assert data['help_count'] == 11
    assert data['signature_count'] == 11


def test_actual_public_n1_and_fresh_n2_collision(evaluator):
    data = run_probe(evaluator, 'semantics')
    assert data['N1']['admitted'] is True
    assert data['N1']['compared'] == 1
    assert data['N2']['type'] == 'ValueError'
    assert 'duplicate occurrence key' in data['N2']['error']
    assert data['N2']['output_bytes'] == 0
    assert data['N2']['original_bytes_preserved'] is True


def test_pinned_comparison_semantics_and_return_shapes(evaluator):
    data = run_probe(evaluator, 'semantics')
    assert data['identical_failed']['regressions'] == 0
    assert data['changed_reason']['regressions'] == 1
    assert data['added_skip']['improvements'] == 1
    assert data['failed_to_skip']['improvements'] == 1
    assert data['effect_only']['regressions'] == 0
    assert data['effect_only']['effect_retained'] is True
    assert data['coverage_veto_owner'] == 'W10'
    assert data['quorum']['smoke'] == [1, 1.0, True]
    assert data['quorum']['release'] == [2, 1.0, True]


def test_exact_case_batch_negatives_and_candidate_boundary(evaluator):
    data = run_probe(evaluator, 'batch')
    assert set(data['rejected']) == {'format', 'isolation', 'target', 'count', 'digest', 'extra-field', 'unknown-flag'}
    assert all(value != 0 for value in data['rejected'].values())


def test_round_adapter_inventory_rejects_unregistered_consumption(tmp_path):
    from p11lab.round_core.bootstrap import audit_consumption
    contract = json.loads((Path(__file__).resolve().parents[2] / 'src/p11lab/data/rounds/contract.json').read_text())
    source = tmp_path / 'adapter.py'
    source.write_text('from pkcs11_check.core.evidence import compare_lanes\n')
    assert audit_consumption([source], contract) == []
    for code in [
        'from pkcs11_check.core.evidence import new_comparator\n',
        'import pkcs11_check.core.evidence as e\ne.new_comparator()\n',
        'import pkcs11_check.core.evidence as e\ngetattr(e, "compare_lanes")\n',
        'import importlib\nimportlib.import_module("pkcs11_check.core.evidence")\n',
        'from pkcs11_check.core.evidence import LedgerRow\nr = LedgerRow()\nr.unknown_facet\n',
        'import pkcs11_check.core.evidence as e\nvars(e)["compare_lanes"]\n',
        'argv = ["pkcs11-check", "evidence-compare"]\nargv.append(flag)\n',
        'import subprocess\nsubprocess.run(["python", "-m", "pkcs11_check", "evidence-compare", "--invented"])\n',
        'import subprocess\nsubprocess.run(["pkcs11-check", "evidence-compare", "--invented"])\n',
        'import subprocess\nsubprocess.run(["python3", "scripts/verify_round_receipt.py", "--invented"])\n',
    ]:
        source.write_text(code)
        assert audit_consumption([source], contract), code
    root = Path(__file__).resolve().parents[2] / 'src/p11lab/round_core'
    assert audit_consumption(sorted(root.glob('*.py')), contract) == []


@pytest.mark.parametrize('code', [
    'from pkcs11_check.core.evidence import LedgerRow\ndef consume(row: LedgerRow):\n    return row.unknown_facet\n',
    'from pkcs11_check.core.evidence import compare_lanes\nvalue = compare_lanes(a,b,c,d).unknown_facet\n',
    'from pkcs11_check.core.evidence import LedgerRow\ndef consume(row: LedgerRow, field: str):\n    return getattr(row, field)\n',
    'import subprocess\nflag = "--invented"\nsubprocess.run(["pkcs11-check", "evidence-compare", flag])\n',
    'import subprocess\ndef consume(flag):\n    subprocess.run(["pkcs11-check", "evidence-compare", flag])\n',
])
def test_reviewer_consumption_counterexamples_rejected(tmp_path, code):
    from p11lab.round_core.bootstrap import audit_consumption
    contract = json.loads((Path(__file__).resolve().parents[2] / 'src/p11lab/data/rounds/contract.json').read_text())
    source = tmp_path / 'reviewer.py'
    source.write_text(code)
    assert audit_consumption([source], contract), code


@pytest.mark.parametrize('mutation', ['add', 'remove', 'reorder'])
def test_production_coverage_schema_drift_rejected(evaluator, tmp_path, mutation):
    path = Path(__file__).resolve().parents[2] / 'src/p11lab/data/rounds/contract.json'
    contract = json.loads(path.read_text())
    if mutation == 'add':
        contract['coverage_fields'].append('unreviewed_state')
    elif mutation == 'remove':
        contract['coverage_fields'].pop()
    else:
        contract['coverage_fields'][0], contract['coverage_fields'][1] = contract['coverage_fields'][1], contract['coverage_fields'][0]
    changed = tmp_path / 'production-contract.json'
    changed.write_text(json.dumps(contract))
    with pytest.raises(AssertionError, match='production coverage schema drift'):
        run_probe(evaluator, 'api', changed)


@pytest.mark.parametrize('code', [
    'from pkcs11_check.core.evidence import LedgerRow\ndef consume(row: LedgerRow):\n    return row.reason\n',
    'from pkcs11_check.core.evidence import LedgerRow\ndef consume(row: "LedgerRow"):\n    return row.to_record()\n',
    'from pkcs11_check.core.evidence import compare_lanes\nvalue = compare_lanes(a,b,c,d).regressions\n',
    'import subprocess\nsubprocess.run(["pkcs11-check", "evidence-compare", "--output", "json"])\n',
])
def test_registered_typed_and_call_result_consumption_allowed(tmp_path, code):
    from p11lab.round_core.bootstrap import audit_consumption
    contract = json.loads((Path(__file__).resolve().parents[2] / 'src/p11lab/data/rounds/contract.json').read_text())
    source = tmp_path / 'supported.py'
    source.write_text(code)
    assert audit_consumption([source], contract) == []


def test_evaluator_program_alias_cannot_hide_dynamic_argv(tmp_path):
    from p11lab.round_core.bootstrap import audit_consumption
    contract = json.loads((Path(__file__).resolve().parents[2] / 'src/p11lab/data/rounds/contract.json').read_text())
    source = tmp_path / 'indirect-program.py'
    source.write_text('import subprocess\nprogram="pkcs11-check"\nflag="--invented"\nsubprocess.run([program,"evidence-compare",flag])\n')
    assert audit_consumption([source], contract)


@pytest.mark.parametrize('code', [
    'import subprocess\nargv=["python3","scripts/verify_round_receipt.py"]\nargv.append(flag)\nsubprocess.run(argv)\n',
    'import subprocess\nsubprocess.run("pkcs11-check evidence-compare --invented",shell=True)\n',
])
def test_unsupported_companion_extension_and_shell_argv_rejected(tmp_path, code):
    from p11lab.round_core.bootstrap import audit_consumption
    contract = json.loads((Path(__file__).resolve().parents[2] / 'src/p11lab/data/rounds/contract.json').read_text())
    source = tmp_path / 'unsupported-argv.py'
    source.write_text(code)
    assert audit_consumption([source], contract)


@pytest.mark.parametrize('reverse', [False, True])
@pytest.mark.parametrize('invalid', [False, True])
def test_function_parameters_keep_lexical_types(tmp_path, reverse, invalid):
    from p11lab.round_core.bootstrap import audit_consumption
    contract = json.loads((Path(__file__).resolve().parents[2] / 'src/p11lab/data/rounds/contract.json').read_text())
    row = 'def consume_row(value: LedgerRow):\n    return value.' + ('admitted' if invalid else 'reason') + '\n'
    verdict = 'def consume_verdict(value: AdmissionVerdict):\n    return value.admitted\n'
    functions = [row, verdict]
    if reverse:
        functions.reverse()
    source = tmp_path / 'lexical.py'
    source.write_text('from pkcs11_check.core.evidence import LedgerRow, AdmissionVerdict\n' + '\n'.join(functions))
    errors = audit_consumption([source], contract)
    if invalid:
        assert any('LedgerRow.admitted' in error for error in errors), errors
    else:
        assert errors == []


@pytest.mark.parametrize('reverse', [False, True])
def test_local_constructor_bindings_keep_lexical_types(tmp_path, reverse):
    from p11lab.round_core.bootstrap import audit_consumption
    contract = json.loads((Path(__file__).resolve().parents[2] / 'src/p11lab/data/rounds/contract.json').read_text())
    functions = ['def row():\n    value=LedgerRow()\n    return value.reason\n',
                 'def verdict():\n    value=AdmissionVerdict()\n    return value.admitted\n']
    if reverse:
        functions.reverse()
    source = tmp_path / 'local-values.py'
    source.write_text('from pkcs11_check.core.evidence import LedgerRow, AdmissionVerdict\n' + '\n'.join(functions))
    assert audit_consumption([source], contract) == []


@pytest.mark.parametrize('reverse', [False, True])
def test_program_and_argv_names_do_not_leak_between_functions(tmp_path, reverse):
    from p11lab.round_core.bootstrap import audit_consumption
    contract = json.loads((Path(__file__).resolve().parents[2] / 'src/p11lab/data/rounds/contract.json').read_text())
    functions = ['def evaluator():\n    program="pkcs11-check"\n    argv=["pkcs11-check","evidence-compare","--output","json"]\n    subprocess.run(argv)\n',
                 'def unrelated():\n    program="another-tool"\n    argv=[program,"--invented"]\n    argv.append("ordinary-argument")\n    subprocess.run(argv)\n']
    if reverse:
        functions.reverse()
    source = tmp_path / 'local-programs.py'
    source.write_text('import subprocess\n' + '\n'.join(functions))
    assert audit_consumption([source], contract) == []
    # An actual evaluator flag remains rejected regardless of a sibling's reuse.
    source.write_text(source.read_text().replace('"--output","json"', '"--invented"'))
    errors = audit_consumption([source], contract)
    assert any('unregistered CLI flag --invented' in error for error in errors), errors


def test_nested_function_scope_preserves_outer_and_shadowed_bindings(tmp_path):
    from p11lab.round_core.bootstrap import audit_consumption
    contract = json.loads((Path(__file__).resolve().parents[2] / 'src/p11lab/data/rounds/contract.json').read_text())
    source = tmp_path / 'nested.py'
    source.write_text('from pkcs11_check.core.evidence import LedgerRow, AdmissionVerdict\n'
                      'def outer(value: LedgerRow):\n'
                      '    def shadow(value: AdmissionVerdict):\n        return value.admitted\n'
                      '    def closure():\n        return value.reason\n'
                      '    return value.reason\n')
    assert audit_consumption([source], contract) == []
    source.write_text(source.read_text().replace('return value.reason', 'return value.admitted'))
    assert any('LedgerRow.admitted' in error for error in audit_consumption([source], contract))


def test_conflicting_types_within_one_function_fail_closed(tmp_path):
    from p11lab.round_core.bootstrap import audit_consumption
    contract = json.loads((Path(__file__).resolve().parents[2] / 'src/p11lab/data/rounds/contract.json').read_text())
    source = tmp_path / 'ambiguous.py'
    source.write_text('from pkcs11_check.core.evidence import LedgerRow, AdmissionVerdict\n'
                      'def consume():\n    value=LedgerRow()\n    value=AdmissionVerdict()\n    return value.admitted\n')
    assert any('ambiguous evaluator binding value' in error for error in audit_consumption([source], contract))


def test_parameter_shadowing_type_name_uses_enclosing_annotation_import(tmp_path):
    from p11lab.round_core.bootstrap import audit_consumption
    contract = json.loads((Path(__file__).resolve().parents[2] / 'src/p11lab/data/rounds/contract.json').read_text())
    source = tmp_path / 'annotation-scope.py'
    source.write_text('from pkcs11_check.core.evidence import LedgerRow\ndef consume(LedgerRow: LedgerRow):\n    return LedgerRow.admitted\n')
    assert any('LedgerRow.admitted' in error for error in audit_consumption([source], contract))
    source.write_text(source.read_text().replace('.admitted', '.reason'))
    assert audit_consumption([source], contract) == []


@pytest.mark.parametrize('code', [
    'import subprocess\nprogram="pkcs11-check"\nclass Adapter:\n    program="another-tool"\n    def consume(self):\n        subprocess.run([program,"evidence-compare","--invented"])\n',
    'import subprocess\nclass Adapter:\n    program="pkcs11-check"\n    argv=["pkcs11-check","evidence-compare","--invented"]\n',
])
def test_unmodeled_class_namespace_cannot_hide_program_bindings(tmp_path, code):
    from p11lab.round_core.bootstrap import audit_consumption
    contract = json.loads((Path(__file__).resolve().parents[2] / 'src/p11lab/data/rounds/contract.json').read_text())
    source = tmp_path / 'class-scope.py'
    source.write_text(code)
    assert any('class-local evaluator bindings' in error for error in audit_consumption([source], contract))


@pytest.mark.parametrize(('code', 'finding'), [
    ('import subprocess\ndef outer():\n    argv = ["pkcs11-check", "evidence-compare"]\n    def inner():\n        argv[0] = "pkcs11-check"\n        argv.append("--invented")\n        subprocess.run(argv)\n    inner()\n',
     'dynamic evaluator argv requires registration'),
    ('from pkcs11_check.core.evidence import LedgerRow\ndef outer(row: LedgerRow):\n    def inner():\n        row.effect = "changed"\n        return row.unknown_facet\n    return inner\n',
     'unregistered attribute LedgerRow.unknown_facet'),
])
def test_closure_item_and_attribute_mutation_preserve_tracking(tmp_path, code, finding):
    from p11lab.round_core.bootstrap import audit_consumption
    contract = json.loads((Path(__file__).resolve().parents[2] / 'src/p11lab/data/rounds/contract.json').read_text())
    source = tmp_path / 'closure-mutation.py'
    source.write_text(code)
    assert any(finding in error for error in audit_consumption([source], contract))


@pytest.mark.parametrize('binding', [
    'row = "ordinary"',
    'row, other = "ordinary", "other"',
    '[row, other] = ["ordinary", "other"]',
    'first, *row = ["first", "ordinary"]',
    '(first, [other, *row]) = ("first", ["other", "ordinary"])',
])
def test_real_local_binding_targets_shadow_inherited_types(tmp_path, binding):
    from p11lab.round_core.bootstrap import audit_consumption
    contract = json.loads((Path(__file__).resolve().parents[2] / 'src/p11lab/data/rounds/contract.json').read_text())
    source = tmp_path / 'actual-bindings.py'
    source.write_text('from pkcs11_check.core.evidence import LedgerRow\ndef outer(row: LedgerRow):\n'
                      '    def inner():\n        ' + binding + '\n        return row.count("ordinary")\n    return inner\n')
    assert audit_consumption([source], contract) == []
