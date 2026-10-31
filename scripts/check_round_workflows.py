#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check the deliberately narrow diagnostic workflow and its caller template."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import sys

import yaml


class WorkflowLoader(yaml.SafeLoader):
    pass


# GitHub's `on` is a key, not YAML 1.1's boolean synonym. Only true/false
# resolve to booleans, while duplicate keys and aliases are rejected.
WorkflowLoader.yaml_implicit_resolvers = copy.deepcopy(yaml.SafeLoader.yaml_implicit_resolvers)
for key, rules in WorkflowLoader.yaml_implicit_resolvers.items():
    WorkflowLoader.yaml_implicit_resolvers[key] = [r for r in rules if r[0] != 'tag:yaml.org,2002:bool']
WorkflowLoader.add_implicit_resolver('tag:yaml.org,2002:bool', re.compile(r'^(?:true|false)$', re.I), list('tTfF'))


def mapping(loader, node, deep=False):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str) or key in result:
            raise ValueError('non-string or duplicate mapping key')
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


WorkflowLoader.add_constructor('tag:yaml.org,2002:map', mapping)


def read(path, template=False):
    data = path.read_bytes()
    require(len(data) <= 65536, 'workflow exceeds size limit')
    text = data.decode('utf-8')
    if template:
        require('UNPUBLISHED TEMPLATE' in text, 'caller must be unpublished template')
        text = text.replace('<P11LAB_COMMIT_SHA>', 'a' * 40).replace('<FRAMEWORK_COMMIT_SHA>', 'b' * 40)
    tokens = list(yaml.scan(text, Loader=WorkflowLoader))
    require(len(tokens) <= 10000, 'workflow exceeds token limit')
    require(not any(isinstance(t, (yaml.AliasToken, yaml.AnchorToken)) for t in tokens), 'aliases forbidden')
    doc = yaml.load(text, Loader=WorkflowLoader)
    require(isinstance(doc, dict), 'workflow must be a mapping')
    return doc


def require(condition, message):
    if not condition:
        raise ValueError(message)


def check_actions(doc):
    for job in doc['jobs'].values():
        require('secrets' not in job, 'inherited secrets forbidden')
        for step in job.get('steps', []):
            if 'uses' in step:
                require(re.fullmatch(r'[\w.-]+/[\w.-]+@[0-9a-f]{40}', step['uses']) is not None, 'action pin must be full SHA')
                if step['uses'].startswith('actions/checkout@'):
                    require(step.get('with', {}).get('persist-credentials') is False, 'checkout credentials persist')


def check_execution(root):
    w = read(root / '.github/workflows/checker-round-execution.yml')
    c = read(root / 'examples/round-consumer/execution.yml', template=True)
    require(w.get('permissions') == {}, 'execution workflow permissions')
    check_actions(w)
    check_actions(c)
    require(set(w) == {'name', 'on', 'permissions', 'jobs'} and set(w['on']) == {'workflow_call'}, 'unexpected execution configuration')
    call = w['on']['workflow_call']
    require(set(call) == {'inputs', 'outputs'}, 'unexpected execution-call interface')
    require(set(call['inputs']) == {'framework_sha', 'tier', 'p11lab_ref'}, 'exact three execution inputs required')
    require(all(v == {'required': True, 'type': 'string'} for v in call['inputs'].values()), 'execution input types')
    names = {'round_positive', 'execution_artifact', 'capsule_sha256'}
    require(set(call['outputs']) == names, 'execution outputs')
    require(set(w['jobs']) == {'execute'}, 'unexpected execution job')
    job = w['jobs']['execute']
    require(set(job) == {'runs-on', 'timeout-minutes', 'permissions', 'outputs', 'steps'} and job['runs-on'] == 'ubuntu-24.04' and job['timeout-minutes'] == 20, 'execution job controls')
    require(job['permissions'] == {'contents': 'read', 'actions': 'read'}, 'execution job permissions')
    require(set(job['outputs']) == names, 'execution job outputs')
    for name in names:
        require(call['outputs'][name]['value'] == '${{ jobs.execute.outputs.' + name + ' }}', 'execution output mapping')
        require(job['outputs'][name] == '${{ steps.result.outputs.' + name + ' }}', 'execution job output mapping')
    steps = job['steps']
    require(len(steps) == 11 and [s.get('name') for s in steps] == ['Validate input identities', 'Checkout control source', 'Verify control identity', 'Set up Python', 'Stage round execution material', 'Resolve producer run and stage context', 'Upload resolution evidence', 'Stage sealed evaluator', 'Execute round lane and write execution manifest', 'Upload execution evidence', 'Report refusal'], 'unexpected execution steps')
    guard, checkout, head, setup, stage, context, resolution, evaluator, result, upload, report = steps
    allowed = [ {'name', 'id', 'shell', 'env', 'run'}, {'name', 'uses', 'with'}, {'name', 'shell', 'env', 'run'}, {'name', 'uses', 'with'}, {'name', 'id', 'shell', 'env', 'run'}, {'name', 'id', 'shell', 'env', 'run'}, {'name', 'if', 'uses', 'with'}, {'name', 'id', 'shell', 'run'}, {'name', 'id', 'shell', 'env', 'run'}, {'name', 'uses', 'with'}, {'name', 'shell', 'env', 'run'} ]
    require(all(set(step) == keys for step, keys in zip(steps, allowed)), 'unexpected execution step controls')
    require(all(step['shell'] == 'bash' for step in (guard, head, stage, context, evaluator, result, report)), 'unexpected execution shell')
    require('download-artifact' not in (root / '.github/workflows/checker-round-execution.yml').read_text(), 'cross-job evaluator download forbidden')
    require(guard.get('id') == 'inputs' and guard.get('env') == {'FRAMEWORK_SHA': '${{ inputs.framework_sha }}', 'P11LAB_REF': '${{ inputs.p11lab_ref }}', 'TIER': '${{ inputs.tier }}'}, 'execution input guard environment')
    require(guard.get('run') == '[[ "$FRAMEWORK_SHA" =~ ^[0-9a-f]{40}$ ]]\n[[ "$P11LAB_REF" =~ ^[0-9a-f]{40}$ ]]\ncase "$TIER" in pr-smoke|nightly|release) ;; *) exit 1 ;; esac\n', 'execution input validation')
    require(checkout['uses'] == 'actions/checkout@11d5960a326750d5838078e36cf38b85af677262' and checkout['with'] == {'repository': 'p11lab/p11lab', 'ref': '${{ inputs.p11lab_ref }}', 'path': 'p11lab-control', 'persist-credentials': False}, 'execution control checkout')
    require(head.get('env') == {'P11LAB_REF': '${{ inputs.p11lab_ref }}'} and head.get('run') == 'test "$(git -C p11lab-control rev-parse HEAD)" = "$P11LAB_REF"\n', 'execution control HEAD')
    require(setup['uses'] == 'actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065' and setup['with'] == {'python-version': '3.12.14'}, 'execution Python setup')
    require(stage.get('id') == 'stage' and stage.get('env') == {'FRAMEWORK_SHA': '${{ inputs.framework_sha }}', 'P11LAB_REF': '${{ inputs.p11lab_ref }}', 'TIER': '${{ inputs.tier }}', 'RUN_ID': '${{ github.run_id }}', 'RUN_ATTEMPT': '${{ github.run_attempt }}'}, 'execution stage environment')
    script = stage['run']
    # A reviewed stage script is a narrow executable allowlist. Any edit
    # requires updating this independently reviewed digest and the tests.
    require(hashlib.sha256(script.encode()).hexdigest() == '0cebc628f63371831bd298b507ec09b21b3222a09ea9f0db5388029300bd3b23', 'execution stage script changed')
    for fragment in ["'transport': 'github'", "'run_id': int(os.environ['RUN_ID'])", "'run_attempt': int(os.environ['RUN_ATTEMPT'])", 'round-context.json', 'round-evaluator', 'src/p11lab/data/rounds/policy.json', 'refused: staged policy root missing']:
        require(fragment in script, 'missing execution stage safeguard: ' + fragment)
    require(context.get('id') == 'context' and context.get('env') == {'FRAMEWORK_SHA': '${{ inputs.framework_sha }}', 'TIER': '${{ inputs.tier }}', 'RUN_ID': '${{ github.run_id }}', 'RUN_ATTEMPT': '${{ github.run_attempt }}', 'GITHUB_TOKEN': '${{ github.token }}'}, 'execution context environment')
    script = context['run']
    # A reviewed resolve-and-stage script is a narrow executable allowlist.
    # Any edit requires updating this independently reviewed digest and the
    # tests. One resolve-then-stage CLI call; nothing is minted here.
    require(hashlib.sha256(script.encode()).hexdigest() == 'd5ef1723df633f6ca135db7831107255a6fb521bf30464022ff198112e16247f', 'execution context script changed')
    for fragment in ['round resolve-producer', '--event-path', 'GITHUB_EVENT_PATH', '--profile', 'producer-profiles.json', '--framework-sha', '--tier', '--run-id', '--attempt', '--output-dir', 'round-staged', 'p11lab-control/src']:
        require(fragment in script, 'missing staged context safeguard: ' + fragment)
    require('minted' not in script, 'minted staging is forbidden')
    require(resolution.get('if') == "failure() && steps.context.conclusion == 'failure'", 'execution resolution upload gate')
    require(resolution['uses'] == 'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02' and resolution['with'] == {'name': 'p11lab-round-resolution-${{ github.run_id }}-${{ github.run_attempt }}', 'path': '${{ runner.temp }}/round-staged', 'if-no-files-found': 'error', 'retention-days': 14}, 'execution resolution upload')
    require(evaluator.get('id') == 'evaluator', 'execution evaluator identity')
    script = evaluator['run']
    # A reviewed evaluator-staging script is a narrow executable allowlist.
    # Any edit requires updating this independently reviewed digest and the
    # tests. Anonymous fetches only: no tokens, secrets, or downloads.
    require(hashlib.sha256(script.encode()).hexdigest() == 'c982573c468c20d388246fa2da8f16c28cf0836e22f46c1c3e3c0a8fa02e24b8', 'execution evaluator script changed')
    for fragment in ['acquire_evaluator', 'from_evaluator', 'evaluator-install/bin/pkcs11-check', 'evaluator-build-receipt.json', 'round-evaluator', 'refused: staged evaluator locks missing', 'refused: sealed launcher missing after staging']:
        require(fragment in script, 'missing evaluator staging safeguard: ' + fragment)
    for forbidden in ('GITHUB_TOKEN', 'GH_TOKEN', 'secrets', 'download-artifact', 'actions/download'):
        require(forbidden not in script, 'evaluator staging must stay anonymous and in-job: ' + forbidden)
    require(result.get('id') == 'result' and result.get('env') == stage['env'], 'execution result environment')
    script = result['run']
    # A reviewed execution script is a narrow executable allowlist. Any edit
    # requires updating this independently reviewed digest and the tests.
    require(hashlib.sha256(script.encode()).hexdigest() == 'bd24546ee7b0f7b6fdf676a669882579af57a2dc4dacf4d9d40ac0745abd0186', 'execution result script changed')
    for fragment in ['python -m p11lab round execute --context', "'round_positive': 'false'", "'refusal': 'true'", "'refusal_cause': 'missing-row'", 'refused: staged attempt identity mismatch', '|| code=$?', 'round-evidence', 'verdict-row.json', "'schema': 'p11lab-round-execution-v1'", "if capsule['round_positive'] is not False:", 'policy must remain diagnostic']:
        require(fragment in script, 'missing execution safeguard: ' + fragment)
    for fragment in ['--authority', '--baseline', '--candidate', 'round-staged', 'round-github-context.json', "'bridge'", "'context_shape'", "'live_qualified': False", "'honest_control': 'H-C-NOT-DEMONSTRATED'", "'diagnostic_only': True", "'limitations': limitations"]:
        require(fragment in script, 'missing staged bridge safeguard: ' + fragment)
    require(upload['uses'] == 'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02' and upload['with'] == {'name': 'p11lab-round-execution-${{ github.run_id }}-${{ github.run_attempt }}', 'path': '${{ runner.temp }}/round-evidence', 'if-no-files-found': 'error', 'retention-days': 14}, 'execution upload')
    require(report.get('env') == {'REFUSAL': '${{ steps.result.outputs.refusal }}', 'REFUSAL_CAUSE': '${{ steps.result.outputs.refusal_cause }}'} and report.get('run') == 'if [[ "$REFUSAL" == "false" ]]; then exit 0; fi\necho "refused: $REFUSAL_CAUSE" >&2\nexit 3\n', 'execution refusal report')
    require(c.get('permissions') == {'contents': 'read', 'actions': 'read'}, 'execution caller permissions')
    caller = c['jobs']['execution']
    require(set(caller) == {'permissions', 'uses', 'with'}, 'execution caller keys or inherited secrets')
    require(caller['permissions'] == {'contents': 'read', 'actions': 'read'}, 'execution caller job permissions')
    match = re.fullmatch(r'p11lab/p11lab/\.github/workflows/checker-round-execution\.yml@([0-9a-f]{40})', caller['uses'])
    require(match is not None, 'execution caller uses pin')
    inputs = caller['with']
    require(set(inputs) == {'framework_sha', 'tier', 'p11lab_ref'}, 'execution caller inputs')
    require(inputs['p11lab_ref'] == match.group(1), 'execution caller pin mismatch')
    require(re.fullmatch('[0-9a-f]{40}', inputs['framework_sha']) is not None and inputs['tier'] in ('pr-smoke', 'nightly', 'release'), 'execution caller inputs invalid')


def check_root(root):
    w = read(root / '.github/workflows/checker-round.yml')
    u = read(root / '.github/workflows/round-unit-validation.yml')
    c = read(root / 'examples/round-consumer/diagnostic.yml', template=True)
    for d in (w, u, c):
        require(d.get('permissions') == {'contents': 'read'}, 'workflow permissions')
        check_actions(d)
    require(set(w) == {'name', 'on', 'permissions', 'jobs'} and set(w['on']) == {'workflow_call'}, 'unexpected workflow configuration')
    call = w['on']['workflow_call']
    require(set(call) == {'inputs', 'outputs'}, 'unexpected workflow-call interface')
    require(set(call['inputs']) == {'framework_sha', 'tier', 'p11lab_ref'}, 'exact three inputs required')
    require(all(v == {'required': True, 'type': 'string'} for v in call['inputs'].values()), 'input types')
    names = {'round_positive', 'receipt_artifact', 'capsule_artifact', 'capsule_sha256', 'raw_artifacts_manifest'}
    require(set(call['outputs']) == names, 'IF-E5-2 outputs')
    require(set(w['jobs']) == {'diagnostic'}, 'unexpected job')
    job = w['jobs']['diagnostic']
    require(set(job['outputs']) == names, 'job outputs')
    for name in names:
        require(call['outputs'][name]['value'] == '${{ jobs.diagnostic.outputs.' + name + ' }}', 'output mapping')
        require(job['outputs'][name] == '${{ steps.result.outputs.' + name + ' }}', 'job output mapping')
    require(set(job) == {'runs-on', 'timeout-minutes', 'outputs', 'steps'} and job['runs-on'] == 'ubuntu-24.04' and job['timeout-minutes'] == 10, 'diagnostic job controls')
    steps = job['steps']
    require(len(steps) == 6 and [s.get('name') for s in steps] == ['Validate input identities', 'Checkout control source', 'Verify control identity', 'Set up Python', 'Validate policy and write diagnostic manifest', 'Upload diagnostic manifest'], 'unexpected diagnostic steps')
    guard, checkout, head, setup, result, upload = steps
    allowed = [ {'name', 'id', 'shell', 'env', 'run'}, {'name', 'uses', 'with'}, {'name', 'shell', 'env', 'run'}, {'name', 'uses', 'with'}, {'name', 'id', 'shell', 'env', 'run'}, {'name', 'uses', 'with'} ]
    require(all(set(step) == keys for step, keys in zip(steps, allowed)), 'unexpected step controls')
    require(all(step['shell'] == 'bash' for step in (guard, head, result)), 'unexpected shell')
    require(guard.get('id') == 'inputs' and guard.get('env') == {'FRAMEWORK_SHA': '${{ inputs.framework_sha }}', 'P11LAB_REF': '${{ inputs.p11lab_ref }}', 'TIER': '${{ inputs.tier }}'}, 'input guard environment')
    require(guard.get('run') == '[[ "$FRAMEWORK_SHA" =~ ^[0-9a-f]{40}$ ]]\n[[ "$P11LAB_REF" =~ ^[0-9a-f]{40}$ ]]\ncase "$TIER" in pr-smoke|nightly|release) ;; *) exit 1 ;; esac\n', 'input validation')
    require(checkout['uses'] == 'actions/checkout@11d5960a326750d5838078e36cf38b85af677262' and checkout['with'] == {'repository': 'p11lab/p11lab', 'ref': '${{ inputs.p11lab_ref }}', 'path': 'p11lab-control', 'persist-credentials': False}, 'control checkout')
    require(head.get('env') == {'P11LAB_REF': '${{ inputs.p11lab_ref }}'} and head.get('run') == 'test "$(git -C p11lab-control rev-parse HEAD)" = "$P11LAB_REF"\n', 'control HEAD')
    require(setup['uses'] == 'actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065' and setup['with'] == {'python-version': '3.12.14'}, 'Python setup')
    require(result.get('id') == 'result' and result.get('env') == guard['env'], 'result environment')
    script = result['run']
    # A reviewed diagnostic script is a narrow executable allowlist. Any edit
    # requires updating this independently reviewed digest and the tests.
    require(hashlib.sha256(script.encode()).hexdigest() == '8b014253692e3bc7755a8d62366fa7c0ee555ecb3370d6d0f80946c574e9abc5', 'diagnostic script changed')
    for fragment in ['PYTHONPATH="$GITHUB_WORKSPACE/p11lab-control/src" python -m p11lab round validate-policy --policy-root "$GITHUB_WORKSPACE/p11lab-control/src/p11lab/data/rounds"', "if policy['round_positive'] is not False:", "'diagnostic_only': True", "'round_positive': False", "echo 'round_positive=false'", "echo 'receipt_artifact='", "echo 'capsule_artifact='", "echo 'capsule_sha256='", "echo 'raw_artifacts_manifest='", "'schema': 'p11lab-round-diagnostic-v1'"]:
        require(fragment in script, 'missing diagnostic safeguard: ' + fragment)
    require(upload['uses'] == 'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02' and upload['with']['path'] == '${{ runner.temp }}/round-diagnostic.json' and upload['with']['if-no-files-found'] == 'error', 'diagnostic upload')
    # This workflow is a deliberately narrow, reviewed execution contract.
    # Changes to triggers, job controls, action pins, or commands must update
    # this allowlist and receive independent review; no generic YAML evaluator
    # can establish that arbitrary shell or conditions execute the checks.
    expected_unit = {
        'name': 'round-unit-validation',
        'on': {'pull_request': None, 'workflow_dispatch': None},
        'permissions': {'contents': 'read'},
        'jobs': {'validate': {
            'runs-on': 'ubuntu-24.04', 'timeout-minutes': 10,
            'steps': [
                {'uses': 'actions/checkout@11d5960a326750d5838078e36cf38b85af677262',
                 'with': {'persist-credentials': False}},
                {'uses': 'actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065',
                 'with': {'python-version': '3.12.14'}},
                {'name': 'Install pinned verification dependencies',
                 'run': 'python -m pip install --require-hashes --only-binary :all: -r .github/requirements/round-unit.txt -r .github/requirements/round-workflow.txt\n'},
                {'name': 'Verify round workflow contracts',
                 'run': 'python -m pytest tests/rounds/test_workflow_skeleton.py tests/rounds/test_policy.py -q\n'
                        'python -m pytest tests/rounds/test_execute_staged.py -q\n'
                        'python scripts/check_round_workflows.py --contract-fixtures tests/rounds/fixtures/contracts\n'
                        'python scripts/check_round_workflows.py --root .\n'},
            ],
        }},
    }
    require(u == expected_unit, 'unit workflow differs from reviewed execution contract')
    caller = c['jobs']['diagnostic']
    require(set(caller) == {'permissions', 'uses', 'with'}, 'caller keys or inherited secrets')
    require(caller['permissions'] == {'contents': 'read'}, 'caller permissions')
    match = re.fullmatch(r'p11lab/p11lab/\.github/workflows/checker-round\.yml@([0-9a-f]{40})', caller['uses'])
    require(match is not None, 'caller uses pin')
    inputs = caller['with']
    require(set(inputs) == {'framework_sha', 'tier', 'p11lab_ref'}, 'caller inputs')
    require(inputs['p11lab_ref'] == match.group(1), 'caller pin mismatch')
    require(re.fullmatch('[0-9a-f]{40}', inputs['framework_sha']) is not None and inputs['tier'] in ('pr-smoke', 'nightly', 'release'), 'caller inputs invalid')
    check_execution(root)


def fixtures(path):
    # Reuse the reviewed W01 coverage contract; fixture presence alone is not a
    # claim that an installed evaluator or provider was exercised.
    coverage = json.loads((path / 'coverage-schema/09aabfec.json').read_text())
    require(coverage == ['advertised', 'accepted', 'attempted', 'rejected_cleanly', 'skipped_by_capability', 'crashed', 'timeout', 'selected', 'selection_rejected', 'invoked'], 'W01 coverage contract drift')
    for name in ('fw-api/09aabfec.json', 'fw-cli/09aabfec-python312.json'):
        require(bool(json.loads((path / name).read_text())), 'empty W01 fixture')
    check_root(Path(__file__).resolve().parents[1])


def main():
    p = argparse.ArgumentParser()
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument('--root', type=Path)
    group.add_argument('--contract-fixtures', type=Path)
    args = p.parse_args()
    try:
        check_root(args.root) if args.root else fixtures(args.contract_fixtures)
    except (ValueError, KeyError, TypeError, OSError, RecursionError, yaml.YAMLError) as exc:
        print(f'workflow contract failed: {exc}', file=sys.stderr)
        return 1
    print('round workflow contracts OK')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
