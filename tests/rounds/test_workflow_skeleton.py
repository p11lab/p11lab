"""Contract tests for the diagnostic-only and execution reusable workflows."""
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
CHECK = ROOT / 'scripts/check_round_workflows.py'
SHA = 'a' * 40
EXECUTION = '.github/workflows/checker-round-execution.yml'
EXECUTION_CALLER = 'examples/round-consumer/execution.yml'


def check(root):
    return subprocess.run([sys.executable, str(CHECK), '--root', str(root)], capture_output=True, text=True)


def copy_contract(tmp_path):
    for name in ('.github/workflows/checker-round.yml', '.github/workflows/checker-round-execution.yml', '.github/workflows/round-unit-validation.yml', 'examples/round-consumer/diagnostic.yml', 'examples/round-consumer/execution.yml'):
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
    return tmp_path


def test_contract_accepts_current_tree():
    result = check(ROOT)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(('path', 'old', 'new'), [
    ('.github/workflows/checker-round.yml', 'framework_sha:', 'extra_input:'),
    ('.github/workflows/checker-round.yml', 'repository: p11lab/p11lab', 'repository: attacker/control'),
    ('.github/workflows/checker-round.yml', 'ref: ${{ inputs.p11lab_ref }}', 'ref: main'),
    ('.github/workflows/checker-round.yml', 'persist-credentials: false', 'persist-credentials: true'),
    ('.github/workflows/checker-round.yml', 'contents: read', 'contents: write'),
    ('.github/workflows/checker-round.yml', 'round_positive=false', 'round_positive=true'),
    ('.github/workflows/checker-round.yml', 'actions/checkout@11d5960a326750d5838078e36cf38b85af677262', 'actions/checkout@v4'),
    ('examples/round-consumer/diagnostic.yml', 'p11lab_ref: <P11LAB_COMMIT_SHA>', 'p11lab_ref: ' + 'b' * 40),
    ('examples/round-consumer/diagnostic.yml', 'permissions:', 'secrets: inherit\n    permissions:'),
])
def test_contract_rejects_mutations(tmp_path, path, old, new):
    root = copy_contract(tmp_path)
    file = root / path
    content = file.read_text()
    assert old in content
    file.write_text(content.replace(old, new, 1))
    assert check(root).returncode != 0


def test_duplicate_key_is_rejected(tmp_path):
    root = copy_contract(tmp_path)
    file = root / '.github/workflows/checker-round.yml'
    file.write_text(file.read_text() + '\npermissions: {}\n')
    assert check(root).returncode != 0


@pytest.mark.parametrize(('framework', 'tier', 'control', 'ok'), [
    (SHA, 'pr-smoke', SHA, True), (SHA, 'nightly', SHA, True),
    (SHA, 'release', SHA, True), ('a' * 39, 'pr-smoke', SHA, False),
    ('A' * 40, 'pr-smoke', SHA, False), (SHA, 'main', SHA, False),
    (SHA, 'pr-smoke', 'main', False),
])
def test_runtime_input_guard(framework, tier, control, ok):
    doc = yaml.safe_load((ROOT / '.github/workflows/checker-round.yml').read_text())
    step = next(x for x in doc['jobs']['diagnostic']['steps'] if x.get('id') == 'inputs')
    env = dict(os.environ, FRAMEWORK_SHA=framework, TIER=tier, P11LAB_REF=control)
    result = subprocess.run(['bash', '-e', '-c', step['run']], env=env, capture_output=True, text=True)
    assert (result.returncode == 0) == ok


def test_diagnostic_step_consumes_control_policy_and_emits_false(tmp_path):
    import json
    workspace = tmp_path / 'workspace'
    workspace.mkdir()
    (workspace / 'p11lab-control').symlink_to(ROOT, target_is_directory=True)
    output = tmp_path / 'output'
    output.touch()
    doc = yaml.safe_load((ROOT / '.github/workflows/checker-round.yml').read_text())
    step = next(x for x in doc['jobs']['diagnostic']['steps'] if x.get('id') == 'result')
    env = dict(os.environ, PATH=str(Path(sys.executable).parent) + os.pathsep + os.environ['PATH'],
               GITHUB_WORKSPACE=str(workspace), RUNNER_TEMP=str(tmp_path), GITHUB_OUTPUT=str(output),
               FRAMEWORK_SHA=SHA, P11LAB_REF='b' * 40, TIER='pr-smoke')
    proc = subprocess.run(['bash', '-e', '-c', step['run']], env=env, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    manifest = json.loads((tmp_path / 'round-diagnostic.json').read_text())
    assert manifest['schema'] == 'p11lab-round-diagnostic-v1'
    assert manifest['diagnostic_only'] is True and manifest['round_positive'] is False
    assert manifest['framework_sha'] == SHA and manifest['p11lab_ref'] == 'b' * 40
    assert manifest['policy']['round_positive'] is False
    assert all(manifest[key] is None for key in ('receipt_artifact', 'capsule_artifact', 'capsule_sha256', 'raw_artifacts_manifest'))
    assert output.read_text().splitlines() == ['round_positive=false', 'receipt_artifact=', 'capsule_artifact=', 'capsule_sha256=', 'raw_artifacts_manifest=']


def test_control_head_guard_rejects_wrong_revision(tmp_path):
    subprocess.run(['git', 'init', '-q', str(tmp_path / 'p11lab-control')], check=True)
    subprocess.run(['git', '-C', str(tmp_path / 'p11lab-control'), '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '--allow-empty', '-qm', 'fixture'], check=True)
    head = subprocess.check_output(['git', '-C', str(tmp_path / 'p11lab-control'), 'rev-parse', 'HEAD'], text=True).strip()
    doc = yaml.safe_load((ROOT / '.github/workflows/checker-round.yml').read_text())
    step = next(x for x in doc['jobs']['diagnostic']['steps'] if x.get('name') == 'Verify control identity')
    for ref, expected in [(head, 0), ('a' * 40, 1)]:
        result = subprocess.run(['bash', '-e', '-c', step['run']], cwd=tmp_path, env=dict(os.environ, P11LAB_REF=ref))
        assert result.returncode == expected


@pytest.mark.parametrize(('old', 'new'), [
    ('id: inputs\n', 'id: inputs\n        if: false\n'),
    ('id: result\n', 'id: result\n        continue-on-error: true\n'),
    ("echo 'round_positive=false'", "echo 'round_positive=false'\n            echo 'round_positive=true'"),
])
def test_contract_rejects_bypasses(tmp_path, old, new):
    root = copy_contract(tmp_path)
    file = root / '.github/workflows/checker-round.yml'
    content = file.read_text()
    assert old in content
    file.write_text(content.replace(old, new, 1))
    assert check(root).returncode != 0


@pytest.mark.parametrize(('old', 'new'), [
    ('  validate:\n', '  validate:\n    if: false\n'),
    ('  validate:\n', '  validate:\n    continue-on-error: true\n'),
    ('      - name: Verify round workflow contracts\n', '      - name: Verify round workflow contracts\n        if: false\n'),
    ('      - name: Verify round workflow contracts\n', '      - name: Verify round workflow contracts\n        continue-on-error: true\n'),
    ('      - name: Install pinned verification dependencies\n', '      - name: Install pinned verification dependencies\n        if: false\n'),
    ('          python -m pytest tests/rounds/test_workflow_skeleton.py tests/rounds/test_policy.py -q\n', ''),
    ('          python scripts/check_round_workflows.py --contract-fixtures tests/rounds/fixtures/contracts\n', '          true\n'),
    ('          python scripts/check_round_workflows.py --root .\n', ''),
    ('jobs:\n', 'defaults:\n  run:\n    shell: bash {0}\njobs:\n'),
    ('jobs:\n', 'env:\n  PYTHONPATH: /tmp/untrusted\njobs:\n'),
    ('  pull_request:\n', '  pull_request:\n    paths: ["never/**"]\n'),
])
def test_unit_workflow_rejects_skips_soft_failures_and_replaced_checks(tmp_path, old, new):
    root = copy_contract(tmp_path)
    file = root / '.github/workflows/round-unit-validation.yml'
    content = file.read_text()
    assert old in content
    file.write_text(content.replace(old, new, 1))
    assert check(root).returncode != 0


def test_contract_accepts_the_reviewed_python_version():
    result = check(ROOT)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize('path', ['.github/workflows/checker-round.yml', '.github/workflows/checker-round-execution.yml', '.github/workflows/round-unit-validation.yml'])
@pytest.mark.parametrize('version', ['3.12', '3.12.15'])
def test_contract_rejects_floating_or_mismatched_python_version(tmp_path, path, version):
    root = copy_contract(tmp_path)
    file = root / path
    content = file.read_text()
    old = "python-version: '3.12.14'"
    assert old in content
    file.write_text(content.replace(old, f"python-version: '{version}'", 1))
    assert check(root).returncode != 0


def test_execution_contract_accepts_current_tree():
    result = check(ROOT)
    assert result.returncode == 0, result.stderr


def test_execution_timeout_is_twenty():
    doc = yaml.safe_load((ROOT / EXECUTION).read_text())
    assert doc['jobs']['execute']['timeout-minutes'] == 20


@pytest.mark.parametrize(('path', 'old', 'new'), [
    (EXECUTION, 'framework_sha:', 'extra_input:'),
    (EXECUTION, 'repository: p11lab/p11lab', 'repository: attacker/control'),
    (EXECUTION, 'ref: ${{ inputs.p11lab_ref }}', 'ref: main'),
    (EXECUTION, 'persist-credentials: false', 'persist-credentials: true'),
    (EXECUTION, 'permissions: {}', 'permissions:\n  contents: write'),
    (EXECUTION, "'round_positive': 'false'", "'round_positive': 'true'"),
    (EXECUTION, 'actions/checkout@11d5960a326750d5838078e36cf38b85af677262', 'actions/checkout@v4'),
    (EXECUTION, 'p11lab-round-execution-', 'p11lab-round-evil-'),
    (EXECUTION, 'retention-days: 14', 'retention-days: 90'),
    (EXECUTION, 'timeout-minutes: 20', 'timeout-minutes: 10'),
    (EXECUTION, 'timeout-minutes: 20', 'timeout-minutes: 30'),
    (EXECUTION_CALLER, 'p11lab_ref: <P11LAB_COMMIT_SHA>', 'p11lab_ref: ' + 'b' * 40),
    (EXECUTION_CALLER, 'permissions:', 'secrets: inherit\n    permissions:'),
])
def test_execution_contract_rejects_mutations(tmp_path, path, old, new):
    root = copy_contract(tmp_path)
    file = root / path
    content = file.read_text()
    assert old in content
    file.write_text(content.replace(old, new, 1))
    assert check(root).returncode != 0


@pytest.mark.parametrize(('old', 'new'), [
    ('id: inputs\n', 'id: inputs\n        if: false\n'),
    ('id: result\n', 'id: result\n        continue-on-error: true\n'),
    ('id: stage\n', 'id: stage\n        if: false\n'),
    ('      - name: Report refusal\n', '      - name: Report refusal\n        if: false\n'),
    ("echo 'refused: staged policy root missing' >&2; exit 3", 'true'),
    ('refused: staged attempt identity mismatch', 'ok'),
])
def test_execution_contract_rejects_bypasses(tmp_path, old, new):
    root = copy_contract(tmp_path)
    file = root / EXECUTION
    content = file.read_text()
    assert old in content
    file.write_text(content.replace(old, new, 1))
    assert check(root).returncode != 0


@pytest.mark.parametrize(('framework', 'tier', 'control', 'ok'), [
    (SHA, 'pr-smoke', SHA, True), (SHA, 'nightly', SHA, True),
    (SHA, 'release', SHA, True), ('a' * 39, 'pr-smoke', SHA, False),
    ('A' * 40, 'pr-smoke', SHA, False), (SHA, 'main', SHA, False),
    (SHA, 'pr-smoke', 'main', False),
])
def test_execution_runtime_input_guard(framework, tier, control, ok):
    doc = yaml.safe_load((ROOT / EXECUTION).read_text())
    step = next(x for x in doc['jobs']['execute']['steps'] if x.get('id') == 'inputs')
    env = dict(os.environ, FRAMEWORK_SHA=framework, TIER=tier, P11LAB_REF=control)
    result = subprocess.run(['bash', '-e', '-c', step['run']], env=env, capture_output=True, text=True)
    assert (result.returncode == 0) == ok


def _execution_workspace(tmp_path, control):
    workspace = tmp_path / 'workspace'
    workspace.mkdir()
    (workspace / 'p11lab-control').symlink_to(control, target_is_directory=True)
    return workspace


def _execution_env(tmp_path, workspace):
    return dict(os.environ, PATH=str(Path(sys.executable).parent) + os.pathsep + os.environ['PATH'],
                GITHUB_WORKSPACE=str(workspace), RUNNER_TEMP=str(tmp_path),
                FRAMEWORK_SHA=SHA, P11LAB_REF='b' * 40, TIER='pr-smoke',
                RUN_ID='456', RUN_ATTEMPT='2')


def _execution_step(name):
    doc = yaml.safe_load((ROOT / EXECUTION).read_text())
    return next(x for x in doc['jobs']['execute']['steps'] if x.get('id') == name)


def test_execution_stage_writes_attempt_bound_context(tmp_path):
    import json
    workspace = _execution_workspace(tmp_path, ROOT)
    step = _execution_step('stage')
    proc = subprocess.run(['bash', '-e', '-c', step['run']], env=_execution_env(tmp_path, workspace),
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    archive = json.loads((tmp_path / 'round-context.json').read_text())
    assert archive == {'transport': 'github', 'tier': 'pr-smoke', 'framework_sha': SHA,
                       'p11lab_ref': 'b' * 40, 'run_id': 456, 'run_attempt': 2}
    assert (tmp_path / 'round-evaluator').is_dir()


def test_execution_stage_refuses_missing_policy_root(tmp_path):
    control = tmp_path / 'empty-control'
    control.mkdir()
    workspace = _execution_workspace(tmp_path, control)
    step = _execution_step('stage')
    proc = subprocess.run(['bash', '-e', '-c', step['run']], env=_execution_env(tmp_path, workspace),
                          capture_output=True, text=True)
    assert proc.returncode == 3
    assert 'refused: staged policy root missing' in proc.stderr


def test_execution_step_refuses_missing_comparison_material(tmp_path):
    import json
    workspace = _execution_workspace(tmp_path, ROOT)
    env = _execution_env(tmp_path, workspace)
    output = tmp_path / 'output'
    output.touch()
    env['GITHUB_OUTPUT'] = str(output)
    stage = subprocess.run(['bash', '-e', '-c', _execution_step('stage')['run']], env=env,
                           capture_output=True, text=True)
    assert stage.returncode == 0, stage.stderr
    proc = subprocess.run(['bash', '-e', '-c', _execution_step('result')['run']], env=env,
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    outputs = dict(line.split('=', 1) for line in output.read_text().splitlines())
    assert outputs['round_positive'] == 'false'
    assert outputs['refusal'] == 'true'
    assert outputs['refusal_cause'] == 'EXECUTE_TRANSPORT_REFUSED'
    assert outputs['execution_artifact'] == 'p11lab-round-execution-456-2'
    evidence = tmp_path / 'round-evidence'
    assert sorted(p.name for p in evidence.iterdir()) == ['round-capsule.json', 'round-execution.json', 'round-receipt.json', 'verdict-row.json']
    row = json.loads((evidence / 'verdict-row.json').read_text())
    assert row['cause'] == 'EXECUTE_TRANSPORT_REFUSED'
    assert row['exit_code'] == 3
    capsule = json.loads((evidence / 'round-capsule.json').read_text())
    assert capsule['round_positive'] is False
    assert outputs['capsule_sha256'] == capsule['capsule_sha256']
    manifest = json.loads((evidence / 'round-execution.json').read_text())
    assert manifest['schema'] == 'p11lab-round-execution-v1'
    assert manifest['round_positive'] is False and manifest['run_attempt'] == 2


def test_execution_step_rejects_attempt_mismatch(tmp_path):
    import json
    workspace = _execution_workspace(tmp_path, ROOT)
    env = _execution_env(tmp_path, workspace)
    output = tmp_path / 'output'
    output.touch()
    env['GITHUB_OUTPUT'] = str(output)
    stage = subprocess.run(['bash', '-e', '-c', _execution_step('stage')['run']], env=env,
                           capture_output=True, text=True)
    assert stage.returncode == 0, stage.stderr
    archive_path = tmp_path / 'round-context.json'
    archive = json.loads(archive_path.read_text())
    archive['run_attempt'] = 3
    archive_path.write_text(json.dumps(archive))
    proc = subprocess.run(['bash', '-e', '-c', _execution_step('result')['run']], env=env,
                          capture_output=True, text=True)
    assert proc.returncode == 3
    assert 'refused: staged attempt identity mismatch' in proc.stderr
    assert not (tmp_path / 'round-execution').exists()


def test_execution_report_step_propagates_refusal(tmp_path):
    doc = yaml.safe_load((ROOT / EXECUTION).read_text())
    step = next(x for x in doc['jobs']['execute']['steps'] if x.get('name') == 'Report refusal')
    cases = [('false', '', 0, ''), ('true', 'EXECUTE_TRANSPORT_REFUSED', 3, 'refused: EXECUTE_TRANSPORT_REFUSED')]
    for refusal, cause, expected, text in cases:
        env = dict(os.environ, REFUSAL=refusal, REFUSAL_CAUSE=cause)
        result = subprocess.run(['bash', '-e', '-c', step['run']], env=env, capture_output=True, text=True)
        assert result.returncode == expected
        assert text in result.stderr


@pytest.mark.skipif(os.environ.get('P11LAB_EXECUTION_DISPATCH_LIVE') != '1',
                    reason='live dispatch needs a published execution workflow and GitHub API access')
def test_live_execution_dispatch_designed_not_run(tmp_path):
    """Env-gated live proof: dispatch the execution workflow, await the single
    execution artifact, and assert diagnostic values. Requires
    P11LAB_EXECUTION_DISPATCH_REPO (owner/repo),
    P11LAB_EXECUTION_DISPATCH_REF (published SHA), and
    P11LAB_EXECUTION_DISPATCH_INPUTS (JSON file with framework_sha, tier,
    p11lab_ref); authenticates with GITHUB_TOKEN. No published revision
    exists yet (ASK-9 deferred), so this stays designed-not-run."""
    import json
    import time
    import urllib.request
    import zipfile

    repo = os.environ['P11LAB_EXECUTION_DISPATCH_REPO']
    ref = os.environ['P11LAB_EXECUTION_DISPATCH_REF']
    with open(os.environ['P11LAB_EXECUTION_DISPATCH_INPUTS']) as handle:
        inputs = json.load(handle)
    token = os.environ['GITHUB_TOKEN']
    base = f'https://api.github.com/repos/{repo}'

    def call(method, path, payload=None):
        data = None if payload is None else json.dumps(payload).encode()
        request = urllib.request.Request(base + path, data=data, method=method,
                                         headers={'Authorization': f'Bearer {token}',
                                                  'Accept': 'application/vnd.github+json'})
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode() or 'null')

    workflow = 'checker-round-execution.yml'
    call('POST', f'/actions/workflows/{workflow}/dispatches', {'ref': ref, 'inputs': inputs})
    run_id = None
    deadline = time.time() + 600
    while time.time() < deadline and run_id is None:
        runs = call('GET', f'/actions/workflows/{workflow}/runs?per_page=5')
        for row in runs['workflow_runs']:
            if row['head_sha'] == ref:
                run_id, attempt = row['id'], row['run_attempt']
                break
        else:
            time.sleep(10)
    assert run_id is not None, 'dispatched run not found'
    while True:
        run = call('GET', f'/actions/runs/{run_id}')
        if run['status'] == 'completed':
            break
        assert time.time() < deadline, 'live run timed out'
        time.sleep(15)
    name = f'p11lab-round-execution-{run_id}-{attempt}'
    artifacts = call('GET', f'/actions/runs/{run_id}/artifacts?per_page=10')
    match = [entry for entry in artifacts['artifacts'] if entry['name'] == name]
    assert len(match) == 1, 'single execution artifact'
    request = urllib.request.Request(f"{base}/actions/artifacts/{match[0]['id']}/zip",
                                     headers={'Authorization': f'Bearer {token}'})
    with urllib.request.urlopen(request, timeout=60) as response:
        blob = response.read()
    bundle_path = tmp_path / 'live-execution.zip'
    bundle_path.write_bytes(blob)
    with zipfile.ZipFile(bundle_path) as bundle:
        assert sorted(bundle.namelist()) == ['round-capsule.json', 'round-execution.json', 'round-receipt.json', 'verdict-row.json']
        row = json.loads(bundle.read('verdict-row.json').decode())
    assert row['round_positive'] is False


# --- B-C2x staged-mechanics extensions (append-only; rows above untouched) ---
#
# MECHANICS-COMPLETE / H-C-NOT-DEMONSTRATED: staged contexts below carry
# minted placeholders (minted repo, zero SHAs) that satisfy shape checks
# and refuse honestly at the enrolled-pin gates. The workflow never mints
# authority or endpoints; tests stage minted bridge files explicitly.

C2X_CONTEXT_STEP = 'Resolve producer run and stage context'
C2X_RESOLUTION_STEP = 'Upload resolution evidence'
C2X_EVALUATOR_STEP = 'Stage sealed evaluator'
C2X_GATE_LINE = '          python -m pytest tests/rounds/test_execute_staged.py -q\n'


def _c2x_stage_resolved_context(tmp_path, monkeypatch):
    """Stage a REAL-shaped context via the resolver with stubbed transport.

    Replaces the removed minted workflow builder; the workflow itself now
    resolves the producer run and stages this same shape in CI (hermetic
    negative controls for the step live below).
    """
    import json

    from test_producer_resolution import (
        CONSUMER_ATTEMPT,
        CONSUMER_RUN_ID,
        FRAMEWORK_SHA,
        TIER,
        StubTransport,
        make_event,
        make_profile,
    )
    from p11lab.round_core.producer_resolution import run_resolve_producer

    monkeypatch.setenv('GITHUB_RUN_ATTEMPT', '1')
    event_path = tmp_path / 'c2x-event.json'
    event_path.write_text(json.dumps(make_event()))
    profiles_path = tmp_path / 'c2x-profiles.json'
    profiles_path.write_text(json.dumps(
        {'schema_version': 1, 'profiles': [make_profile()]}))
    workspace = _execution_workspace(tmp_path, ROOT)
    env = _execution_env(tmp_path, workspace)
    stage = subprocess.run(['bash', '-e', '-c', _execution_step('stage')['run']],
                           env=env, capture_output=True, text=True)
    assert stage.returncode == 0, stage.stderr
    staged_dir = tmp_path / 'round-staged'
    run_resolve_producer(
        event_path=event_path, profile_path=profiles_path,
        framework_sha=FRAMEWORK_SHA, tier=TIER,
        consumer_run_id=CONSUMER_RUN_ID, consumer_attempt=CONSUMER_ATTEMPT,
        output_dir=staged_dir, transport=StubTransport())
    staged = staged_dir / 'round-github-context.json'
    return json.loads(staged.read_text()), env, workspace


def _c2x_stage_minted_bridge(tmp_path):
    """Stage MINTED (non-H-C) bridge files as the test stand-in for future
    enrollment staging; the workflow itself never mints evidence."""
    import json
    import shutil

    staged = tmp_path / 'round-staged'
    comparison = ROOT / 'tests/fixtures/comparison/checker-direct'
    shutil.copytree(comparison / 'baseline', staged / 'baseline')
    shutil.copytree(comparison / 'candidate', staged / 'candidate')
    envelope = json.loads((comparison / 'envelope.json').read_text())
    witness = json.loads((comparison / 'witness.json').read_text())
    (staged / 'authority.json').write_text(json.dumps(
        {'expectation': envelope, 'observations': witness}))
    return staged


def _c2x_run_result(tmp_path, env):
    output = tmp_path / 'output'
    output.touch()
    env = dict(env, GITHUB_OUTPUT=str(output))
    proc = subprocess.run(['bash', '-e', '-c', _execution_step('result')['run']],
                          env=env, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    return dict(line.split('=', 1) for line in output.read_text().splitlines())


@pytest.mark.parametrize(('path', 'old', 'new'), [
    (EXECUTION, C2X_CONTEXT_STEP, 'Build staged evil context'),
    (EXECUTION, C2X_RESOLUTION_STEP, 'Upload evil evidence'),
    (EXECUTION, C2X_EVALUATOR_STEP, 'Stage sealed evil'),
    (EXECUTION, 'round-github-context.json', 'round-evil.json'),
    (EXECUTION, 'round resolve-producer', 'round evil'),
    (EXECUTION, '--event-path', '--evil-path'),
    (EXECUTION, 'GITHUB_TOKEN: ${{ github.token }}',
     'GITHUB_TOKEN: ${{ secrets.EVIL }}'),
    (EXECUTION, "failure() && steps.context.conclusion == 'failure'",
     'always()'),
    (EXECUTION, 'p11lab-round-resolution-', 'p11lab-round-evil-'),
    (EXECUTION, 'acquire_evaluator', 'download_evaluator'),
    (EXECUTION, 'from_evaluator', 'from_cache'),
    (EXECUTION, '--authority', '--owner'),
    (EXECUTION, '--baseline', '--floor'),
    (EXECUTION, '--candidate', '--rival'),
    (EXECUTION, "'live_qualified': False", "'live_qualified': True"),
    (EXECUTION, "'honest_control': 'H-C-NOT-DEMONSTRATED'",
     "'honest_control': 'demonstrated'"),
    (EXECUTION, 'id: context\n', 'id: context\n        if: false\n'),
    (EXECUTION, 'id: evaluator\n', 'id: evaluator\n        continue-on-error: true\n'),
    (EXECUTION, 'acquire_evaluator',
     "os.environ['GITHUB_TOKEN']  # acquire_evaluator"),
    (EXECUTION, '      - name: Upload execution evidence\n',
     '      - name: Fetch foreign evaluator\n        uses: actions/download-artifact@v4\n      - name: Upload execution evidence\n'),
    ('.github/workflows/round-unit-validation.yml', C2X_GATE_LINE, '          true\n'),
])
def test_c2x_contract_rejects_new_step_mutations(tmp_path, path, old, new):
    root = copy_contract(tmp_path)
    file = root / path
    content = file.read_text()
    assert old in content
    file.write_text(content.replace(old, new, 1))
    assert check(root).returncode != 0


def test_c2x_resolver_stages_real_shape_hermetic(tmp_path, monkeypatch):
    import json

    from test_producer_resolution import (
        ATTEMPT_NR,
        DATA_SHA,
        FRAMEWORK_SHA,
        PRODUCER_HEAD_SHA,
        PRODUCER_JOB,
        REPO,
        REPO_ID,
        RUN_ID,
        WORKFLOW_ID,
    )

    context, env, workspace = _c2x_stage_resolved_context(tmp_path, monkeypatch)
    assert set(context) == {'transport', 'tier', 'identity', 'repository',
                            'run_head_sha', 'workflow_id', 'producer_job',
                            'dependency_lock_sha256', 'data_root',
                            'data_files', 'disabled_path', 'target',
                            'control_sha'}
    identity = context['identity']
    assert set(identity) == {'repository_id', 'run_id', 'attempt',
                             'candidate_sha', 'target_sha', 'merge_base_sha'}
    assert (context['transport'], context['tier']) == ('github', 'pr-smoke')
    assert (identity['repository_id'], identity['run_id'], identity['attempt']) == (REPO_ID, RUN_ID, ATTEMPT_NR)
    assert identity['candidate_sha'] == FRAMEWORK_SHA
    assert identity['target_sha'] == FRAMEWORK_SHA
    assert identity['merge_base_sha'] == FRAMEWORK_SHA
    assert context['repository'] == REPO
    assert context['run_head_sha'] == PRODUCER_HEAD_SHA
    assert context['workflow_id'] == WORKFLOW_ID
    assert context['producer_job'] == PRODUCER_JOB
    assert context['dependency_lock_sha256'] != '0' * 64
    assert context['control_sha'] == '10017b195e46ffd152a398970ed5412ae8c37f0a'
    assert context['data_files'] == [{'path': 'disabled.json', 'size': 16,
                                      'sha256': DATA_SHA}]
    assert context['disabled_path'] == 'disabled.json'
    pilot = json.loads((ROOT / 'src/p11lab/data/rounds/pilot-target.json').read_bytes())
    assert context['target'] == pilot
    assert 'minted' not in json.dumps(context)
    assert not Path(context['data_root']).exists()
    assert 'owner_proof_executable' not in context
    assert 'owner_proof_trusted_root' not in context


def _c2x_run_resolve_step(tmp_path, event_payload, run_attempt):
    import json

    workspace = _execution_workspace(tmp_path, ROOT)
    event_path = tmp_path / 'step-event.json'
    event_path.write_text(json.dumps(event_payload))
    env = dict(os.environ,
               PATH=str(Path(sys.executable).parent) + os.pathsep + os.environ['PATH'],
               GITHUB_WORKSPACE=str(workspace), RUNNER_TEMP=str(tmp_path),
               GITHUB_EVENT_PATH=str(event_path),
               FRAMEWORK_SHA=SHA, TIER='pr-smoke',
               RUN_ID='456', RUN_ATTEMPT=run_attempt, GITHUB_TOKEN='')
    proc = subprocess.run(['bash', '-e', '-c', _execution_step('context')['run']],
                          env=env, capture_output=True, text=True)
    return proc


def test_c2x_resolve_step_refuses_without_lineage(tmp_path):
    """The resolve step refuses a lineage-less event with typed exit 3 and
    refusal evidence, before any network use (no token is even set)."""
    proc = _c2x_run_resolve_step(tmp_path, {'action': 'completed'}, '1')
    assert proc.returncode == 3, proc.stderr
    assert proc.stderr.strip() == (
        'refused: producer run resolution: producer association unavailable')
    assert (tmp_path / 'round-staged/producer-resolution-456-1.json').is_file()
    assert not (tmp_path / 'round-staged/round-github-context.json').exists()


def test_c2x_resolve_step_refuses_consumer_rerun(tmp_path):
    """The resolve step refuses a consumer-only rerun with typed exit 3
    and refusal evidence, before any network use."""
    proc = _c2x_run_resolve_step(tmp_path, {'action': 'completed'}, '2')
    assert proc.returncode == 3, proc.stderr
    assert proc.stderr.strip() == 'refused: rerun requires producer'
    assert (tmp_path / 'round-staged/producer-resolution-456-2.json').is_file()
    assert not (tmp_path / 'round-staged/round-github-context.json').exists()


def test_c2x_staged_context_schema_accept_reaches_pins_gate(tmp_path, monkeypatch):
    """Full staged shape passes validation and refuses honestly at the
    enrolled-pin gate (pre-network); sockets blocked to prove hermeticity."""
    import http.client
    import socket
    import ssl
    import urllib.request

    assert http.client is not None and ssl is not None and urllib is not None
    import p11lab.tool_downloads
    from p11lab.round_core.inputs import prepare as prepare_inputs

    assert p11lab.tool_downloads is not None
    context, env, workspace = _c2x_stage_resolved_context(tmp_path, monkeypatch)

    def blocked(*args, **kwargs):
        raise AssertionError('network used during hermetic staged-context check')

    monkeypatch.setattr(socket, 'socket', blocked)

    with pytest.raises(ValueError, match='protected dependency lock pins unresolved'):
        prepare_inputs(context, ROOT / 'src/p11lab/data/rounds',
                       tmp_path / 'prepare-out')
    assert not (tmp_path / 'prepare-out').exists()


def test_c2x_staged_context_schema_accept_via_cli(tmp_path, monkeypatch):
    import json

    context, env, workspace = _c2x_stage_resolved_context(tmp_path, monkeypatch)
    context_path = tmp_path / 'staged-context.json'
    context_path.write_text(json.dumps(context))
    proc = subprocess.run(
        [sys.executable, '-m', 'p11lab', 'round', 'prepare',
         '--context', str(context_path),
         '--policy-root', str(ROOT / 'src/p11lab/data/rounds'),
         '--output-dir', str(tmp_path / 'cli-prepare'),
         '--output-json', str(tmp_path / 'cli-row.json')],
        capture_output=True, text=True, cwd=tmp_path,
        env=dict(os.environ, PYTHONPATH=str(ROOT / 'src')))
    assert proc.returncode == 2, proc.stderr
    assert 'protected dependency lock pins unresolved' in proc.stderr
    assert not (tmp_path / 'cli-row.json').exists()


@pytest.mark.parametrize(('mutate', 'match'), [
    (lambda c: c.pop('transport'), 'unknown transport'),
    (lambda c: c.pop('control_sha'), 'invalid preparation context'),
    (lambda c: c.update(evil=1), 'invalid preparation context'),
    (lambda c: c.__setitem__('target', 'not-a-dict'), 'invalid preparation context fields'),
    (lambda c: c.__setitem__('tier', ''), 'invalid preparation context fields'),
    (lambda c: c['identity'].pop('attempt'), 'invalid frozen invocation identity'),
    (lambda c: c['identity'].__setitem__('run_id', '456'), 'invalid preparation context identity or data roster'),
    (lambda c: c.__setitem__('workflow_id', 0), 'invalid preparation context identity or data roster'),
    (lambda c: c.__setitem__('data_files', []), 'invalid data file roster'),
    (lambda c: c.__setitem__('data_files', c['data_files'] * 2), 'duplicate or unsorted data file roster'),
])
def test_c2x_staged_context_schema_reject_rows(tmp_path, monkeypatch, mutate, match):
    import json

    context, env, workspace = _c2x_stage_resolved_context(tmp_path, monkeypatch)
    mutate(context)
    context_path = tmp_path / 'mutant-context.json'
    context_path.write_text(json.dumps(context))
    proc = subprocess.run(
        [sys.executable, '-m', 'p11lab', 'round', 'prepare',
         '--context', str(context_path),
         '--policy-root', str(ROOT / 'src/p11lab/data/rounds'),
         '--output-dir', str(tmp_path / 'cli-prepare'),
         '--output-json', str(tmp_path / 'cli-row.json')],
        capture_output=True, text=True, cwd=tmp_path,
        env=dict(os.environ, PYTHONPATH=str(ROOT / 'src')))
    assert proc.returncode == 2, proc.stderr
    assert match in proc.stderr
    assert not (tmp_path / 'cli-row.json').exists()


def test_c2x_result_bridged_partial_refuses_all_or_none(tmp_path, monkeypatch):
    """Authority without endpoints reaches the CLI bridge, which refuses
    all-or-none loudly (usage, no row); the manifest records the partial
    branch with non-H-C provenance instead of evidence rows."""
    import json

    context, env, workspace = _c2x_stage_resolved_context(tmp_path, monkeypatch)
    staged = tmp_path / 'round-staged'
    comparison = ROOT / 'tests/fixtures/comparison/checker-direct'
    envelope = json.loads((comparison / 'envelope.json').read_text())
    witness = json.loads((comparison / 'witness.json').read_text())
    (staged / 'authority.json').write_text(json.dumps(
        {'expectation': envelope, 'observations': witness}))
    outputs = _c2x_run_result(tmp_path, env)
    assert outputs['round_positive'] == 'false'
    assert outputs['refusal'] == 'true'
    assert outputs['refusal_cause'] == 'missing-row'
    evidence = tmp_path / 'round-evidence'
    assert sorted(p.name for p in evidence.iterdir()) == ['round-execution.json']
    manifest = json.loads((evidence / 'round-execution.json').read_text())
    assert manifest['schema'] == 'p11lab-round-execution-v1'
    assert manifest['round_positive'] is False
    assert manifest['cause'] == 'missing-row'
    assert manifest['exit_code'] == 2
    assert manifest['bridge'] == 'partial'
    assert manifest['context_shape'] == 'full'
    assert manifest['live_qualified'] is False
    assert manifest['honest_control'] == 'H-C-NOT-DEMONSTRATED'
    assert manifest['diagnostic_only'] is True
    assert manifest['limitations'] != []


def test_c2x_result_bridged_full_reaches_pins_gate_manifest(tmp_path, monkeypatch):
    """Resolved full bridge staging dispatches past the transport gate and
    refuses honestly at the enrolled-pin gate (usage, no row); the
    manifest records the staged branch with non-H-C provenance."""
    import json

    context, env, workspace = _c2x_stage_resolved_context(tmp_path, monkeypatch)
    _c2x_stage_minted_bridge(tmp_path)
    outputs = _c2x_run_result(tmp_path, env)
    assert outputs['round_positive'] == 'false'
    assert outputs['refusal'] == 'true'
    assert outputs['refusal_cause'] == 'missing-row'
    evidence = tmp_path / 'round-evidence'
    assert sorted(p.name for p in evidence.iterdir()) == ['round-execution.json']
    manifest = json.loads((evidence / 'round-execution.json').read_text())
    assert manifest['schema'] == 'p11lab-round-execution-v1'
    assert manifest['round_positive'] is False
    assert manifest['cause'] == 'missing-row'
    assert manifest['exit_code'] == 2
    assert manifest['bridge'] == 'staged'
    assert manifest['context_shape'] == 'full'
    assert manifest['live_qualified'] is False
    assert manifest['honest_control'] == 'H-C-NOT-DEMONSTRATED'
    assert manifest['diagnostic_only'] is True
    assert manifest['limitations'] != []
    assert manifest['execution_artifact'] == 'p11lab-round-execution-456-2'


def test_c2x_result_context_only_transport_refused(tmp_path, monkeypatch):
    """Full context without bridge entries still refuses pre-prepare with
    its typed cause and row; the manifest records the absent branch."""
    import json

    context, env, workspace = _c2x_stage_resolved_context(tmp_path, monkeypatch)
    outputs = _c2x_run_result(tmp_path, env)
    assert outputs['round_positive'] == 'false'
    assert outputs['refusal'] == 'true'
    assert outputs['refusal_cause'] == 'EXECUTE_TRANSPORT_REFUSED'
    assert outputs['execution_artifact'] == 'p11lab-round-execution-456-2'
    evidence = tmp_path / 'round-evidence'
    assert sorted(p.name for p in evidence.iterdir()) == ['round-capsule.json', 'round-execution.json', 'round-receipt.json', 'verdict-row.json']
    row = json.loads((evidence / 'verdict-row.json').read_text())
    assert row['cause'] == 'EXECUTE_TRANSPORT_REFUSED'
    manifest = json.loads((evidence / 'round-execution.json').read_text())
    assert manifest['schema'] == 'p11lab-round-execution-v1'
    assert manifest['round_positive'] is False
    assert manifest['bridge'] == 'absent'
    assert manifest['context_shape'] == 'full'
    assert manifest['live_qualified'] is False
    assert manifest['honest_control'] == 'H-C-NOT-DEMONSTRATED'
    assert manifest['diagnostic_only'] is True


def test_c2x_evaluator_step_contract():
    """In-job evaluator staging calls acquire_evaluator anonymously and
    asserts the launcher; no tokens, secrets, or cross-job downloads."""
    doc = yaml.safe_load((ROOT / EXECUTION).read_text())
    step = next(x for x in doc['jobs']['execute']['steps']
                if x.get('id') == 'evaluator')
    assert step['name'] == C2X_EVALUATOR_STEP
    assert set(step) == {'name', 'id', 'shell', 'run'}
    assert step['shell'] == 'bash'
    script = step['run']
    for fragment in ('acquire_evaluator', 'from_evaluator',
                     'evaluator-install/bin/pkcs11-check',
                     'evaluator-build-receipt.json', 'round-evaluator'):
        assert fragment in script, fragment
    for forbidden in ('GITHUB_TOKEN', 'GH_TOKEN', 'secrets',
                      'download-artifact', 'actions/download'):
        assert forbidden not in script, forbidden


def test_c2x_manifest_provenance_legacy_path(tmp_path):
    """The legacy (unstaged) path keeps its exact behavior and gains
    explicit non-H-C provenance in the manifest."""
    import json

    workspace = _execution_workspace(tmp_path, ROOT)
    env = _execution_env(tmp_path, workspace)
    stage = subprocess.run(['bash', '-e', '-c', _execution_step('stage')['run']],
                           env=env, capture_output=True, text=True)
    assert stage.returncode == 0, stage.stderr
    outputs = _c2x_run_result(tmp_path, env)
    assert outputs['round_positive'] == 'false'
    assert outputs['refusal'] == 'true'
    assert outputs['refusal_cause'] == 'EXECUTE_TRANSPORT_REFUSED'
    manifest = json.loads((tmp_path / 'round-evidence' / 'round-execution.json').read_text())
    assert manifest['bridge'] == 'absent'
    assert manifest['context_shape'] == 'legacy'
    assert manifest['live_qualified'] is False
    assert manifest['honest_control'] == 'H-C-NOT-DEMONSTRATED'
    assert manifest['diagnostic_only'] is True
    assert manifest['limitations'] != []
    assert manifest['round_positive'] is False


def test_c2x_unit_gate_runs_staged_suite(tmp_path):
    gate = (ROOT / '.github/workflows/round-unit-validation.yml').read_text()
    assert C2X_GATE_LINE in gate
    root = copy_contract(tmp_path)
    file = root / '.github/workflows/round-unit-validation.yml'
    file.write_text(file.read_text().replace(C2X_GATE_LINE, '', 1))
    assert check(root).returncode != 0
