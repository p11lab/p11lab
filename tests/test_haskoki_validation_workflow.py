"""Cost, secret-publication and evidence contracts for manual Haskoki CI."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / '.github/scripts/haskoki_validation.py'
WORKFLOW = ROOT / '.github/workflows/haskoki-release-validation.yml'


def module():
    assert SCRIPT.is_file(), 'safe Haskoki validation runner is missing'
    spec = importlib.util.spec_from_file_location('haskoki_validation', SCRIPT)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def test_workflow_is_bounded_manual_runtime_and_cheap_pr_registration():
    assert WORKFLOW.is_file(), 'bounded Haskoki validation workflow is missing'
    text = WORKFLOW.read_text()
    assert 'pull_request:' in text and 'workflow_dispatch:' in text
    assert "if: github.event_name == 'pull_request'" in text
    assert "if: github.event_name == 'workflow_dispatch'" in text
    assert text.count('runs-on: ubuntu-24.04') == 2
    assert text.count('timeout-minutes: 240') == 1
    assert text.count('timeout-minutes: 10') == 1
    assert 'contents: read' in text and 'packages: none' in text
    for forbidden in ('matrix:', 'continue-on-error:', 'schedule:', 'workflow_run:',
                      'pull_request_target:', 'packages: write', 'docker login',
                      'docker push', 'cache-to', 'upload-artifact', 'provider-delivery',
                      'windows-', 'secrets.', '${{ runner.temp }}'):
        assert forbidden not in text
    static = text.split('  static:\n', 1)[1].split('  runtime:\n', 1)[0]
    runtime = text.split('  runtime:\n', 1)[1]
    assert static.startswith("    if: github.event_name == 'pull_request'\n")
    assert runtime.startswith("    if: github.event_name == 'workflow_dispatch'\n")
    assert 'haskoki_validation.py build' not in static
    assert 'docker build' not in static
    assert runtime.count('haskoki_validation.py build') == 1
    assert 'timeout-minutes: 220' in runtime and 'timeout-minutes: 16' in runtime
    assert 'persist-credentials: false' in text
    assert 'if: always()' in text
    assert 'actionlint_1.7.12_linux_amd64.tar.gz' in text
    assert '8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8' in text


def test_report_only_emits_safe_fields_and_preserves_failures(tmp_path):
    runner = module()
    plugin = runner.SafeResults(tmp_path / 'safe.json')
    node = 'test_haskoki_release.py::test_pin_persists[PRIVATE-PIN]'
    plugin.pytest_collection_finish(SimpleNamespace(items=[SimpleNamespace(nodeid=node)]))
    for when, outcome in [('setup', 'passed'), ('call', 'failed'), ('teardown', 'passed')]:
        plugin.pytest_runtest_logreport(SimpleNamespace(
            nodeid=node, when=when, outcome=outcome,
            longrepr='PRIVATE-PIN PRIVATE-KEY', capstdout='PRIVATE-KEY', capstderr='PRIVATE-PIN'))
    plugin.pytest_sessionfinish(SimpleNamespace(), 1)
    text = (tmp_path / 'safe.json').read_text()
    assert 'PRIVATE-PIN' not in text and 'PRIVATE-KEY' not in text
    report = json.loads(text)
    assert report['counts'] == {'passed': 0, 'failed': 1, 'error': 0, 'skipped': 0, 'incomplete': 0}
    assert report['tests'][0]['test'] == 'test_pin_persists'
    assert len(report['tests'][0]['case_sha256']) == 64
    assert report['complete'] is True
    assert runner.result_exit_code(report) == 1


@pytest.mark.parametrize('bad', ['skipped', 'incomplete', 'xfail'])
def test_missing_or_disguised_evidence_cannot_pass(tmp_path, bad):
    runner = module()
    plugin = runner.SafeResults(tmp_path / 'safe.json')
    node = 'test_haskoki.py::test_direct_checker_smoke[release]'
    plugin.pytest_collection_finish(SimpleNamespace(items=[SimpleNamespace(nodeid=node)]))
    if bad != 'incomplete':
        report = SimpleNamespace(nodeid=node, when='setup', outcome='skipped')
        if bad == 'xfail':
            report.wasxfail = 'known gap must not be hidden'
        plugin.pytest_runtest_logreport(report)
    plugin.pytest_sessionfinish(SimpleNamespace(), 0)
    report = json.loads((tmp_path / 'safe.json').read_text())
    assert runner.result_exit_code(report) != 0
    assert report['complete'] is False


def test_no_collection_is_not_a_pass(tmp_path):
    runner = module()
    plugin = runner.SafeResults(tmp_path / 'safe.json')
    plugin.pytest_sessionfinish(SimpleNamespace(), 0)
    report = json.loads((tmp_path / 'safe.json').read_text())
    assert runner.result_exit_code(report) != 0
    assert report['complete'] is False


def test_summary_does_not_copy_raw_text_or_unallowlisted_fields(tmp_path):
    runner = module()
    root = tmp_path / 'run'
    root.mkdir()
    (root / 'state.json').write_text(json.dumps({
        'stages': {'build': 'passed', 'tests': 'PRIVATE-PIN'},
        'provider': {'reference': 'sha256:' + 'a' * 64, 'private_key': 'PRIVATE-KEY'},
        'exception': 'PRIVATE-PIN', 'log': '/private/token.sqlite',
    }))
    summary = runner.summary(root)
    assert 'PRIVATE-' not in summary and 'token.sqlite' not in summary
    assert 'No complete test report' in summary
    assert 'missing' in summary.lower()
    assert 'not full qualification' in summary.lower()


def test_unexpected_stage_rejected_before_work(tmp_path):
    assert SCRIPT.is_file(), 'safe runner is missing'
    result = subprocess.run([sys.executable, str(SCRIPT), 'publish', '--root', str(tmp_path)],
                            capture_output=True, text=True)
    assert result.returncode != 0
    assert not list(tmp_path.iterdir())


def test_dispatch_retries_fail_before_any_provider_build(tmp_path, monkeypatch):
    runner = module()
    monkeypatch.setenv('GITHUB_RUN_ATTEMPT', '2')
    with pytest.raises(ValueError, match='first attempt'):
        runner.initialize(tmp_path / 'run')
    assert not (tmp_path / 'run').exists()


def test_runtime_selection_uses_installed_package_and_all_acceptance_files():
    runner = module()
    argv = runner.pytest_arguments(Path('/private/tests'))
    assert '--maxfail=0' in argv
    assert '-p' in argv and 'no:terminal' in argv
    assert '-k' not in argv and '-x' not in argv
    assert '-c' in argv and '/dev/null' in argv
    assert str(Path('/private/tests/test_haskoki.py')) in argv
    assert str(Path('/private/tests/test_haskoki_release.py')) in argv
    assert 'pythonpath=' in argv


def test_gate_parser_records_only_measured_numeric_records(tmp_path):
    runner = module()
    log = tmp_path / 'build.log'
    log.write_text('''#17 [builder 1/1] RUN echo p11lab-gate: bundled_libhs_count=24
#17 0.42 p11lab-gate: bundled_libhs_count=25
#17 0.45 p11lab-gate: glibc_floor=GLIBC_2.38
p11lab-gate: hackage_archive_count=2
p11lab-gate: glibc_floor=PRIVATE-KEY
SECRET p11lab-gate: bundled_libhs_count=99
''')
    assert runner.gate_facts(log) == {'bundled_libhs_count': 25, 'glibc_floor': 'GLIBC_2.38', 'hackage_archive_count': 2}


def test_exact_runtime_identity_required_and_inherited_inputs_scrubbed(monkeypatch):
    runner = module()
    monkeypatch.setenv('P11LAB_PIN', 'PRIVATE-PIN')
    monkeypatch.setenv('P11LAB_TEST_HASKOKI_CHECKER_IMAGES', '{"release":"unreviewed"}')
    monkeypatch.setenv('PYTEST_ADDOPTS', '-x')
    monkeypatch.setenv('PYTHONPATH', '/development/workspace')
    with pytest.raises(ValueError, match='exact local image'):
        runner.integration_environment('provider:latest')
    env = runner.integration_environment('sha256:' + 'a' * 64)
    assert 'P11LAB_PIN' not in env and 'PYTEST_ADDOPTS' not in env and 'PYTHONPATH' not in env
    assert 'P11LAB_TEST_HASKOKI_CHECKER_IMAGES' not in env
    assert env['P11LAB_TEST_HASKOKI_CHANNELS'] == 'release'
    assert env['PYTEST_DISABLE_PLUGIN_AUTOLOAD'] == '1'


def test_runtime_expected_roster_includes_every_lane_without_green_skips():
    runner = module()
    assert sum(runner.EXPECTED_ROSTER.values()) == 49
    assert len(runner.DERIVATIVE_TESTS) == 8
    assert all(runner.EXPECTED_ROSTER[name] == 1 for name in runner.DERIVATIVE_TESTS)
    assert runner.EXPECTED_ROSTER['test_release_incompatible_schema_refuses_before_application_without_mutation'] == 18


def test_complete_failure_then_later_pass_are_both_retained(tmp_path):
    runner = module()
    plugin = runner.SafeResults(tmp_path / 'safe.json')
    nodes = ['test_haskoki_release.py::test_schema', 'test_haskoki_release.py::test_lock']
    plugin.pytest_collection_finish(SimpleNamespace(items=[SimpleNamespace(nodeid=node) for node in nodes]))
    for i, node in enumerate(nodes):
        for when in ('setup', 'call', 'teardown'):
            plugin.pytest_runtest_logreport(SimpleNamespace(nodeid=node, when=when,
                outcome='failed' if i == 0 and when == 'call' else 'passed'))
    plugin.pytest_sessionfinish(SimpleNamespace(), 1)
    report = json.loads((tmp_path / 'safe.json').read_text())
    assert report['counts']['failed'] == report['counts']['passed'] == 1
    assert report['complete'] is True
    assert runner.result_exit_code(report) == 1


def test_real_pytest_subprocess_keeps_secret_failure_text_private(tmp_path):
    runner = module()
    root = tmp_path / 'run'
    tests = root / 'private/tests'
    tests.mkdir(parents=True)
    (tests / 'test_haskoki.py').write_text('''def test_failure():
    print("PRIVATE-PIN")
    assert False, "PRIVATE-KEY"

def test_later_case():
    assert True
''')
    (tests / 'test_haskoki_release.py').write_text('''import pytest

def test_missing_derivative():
    pytest.skip("PRIVATE-KEY")
''')
    result = subprocess.run([sys.executable, '-I', str(SCRIPT), 'tests-internal', '--root', str(root)],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 1
    assert 'PRIVATE-' not in result.stdout + result.stderr
    serialized = (root / 'results.json').read_text()
    assert 'PRIVATE-' not in serialized
    report = json.loads(serialized)
    assert report['counts']['failed'] == report['counts']['passed'] == report['counts']['skipped'] == 1
    assert runner.result_exit_code(report) != 0


def test_safe_build_step_and_exact_input_hashes_are_retained(tmp_path):
    runner = module()
    log = tmp_path / 'build.log'
    log.write_text('#18 0.2 p11lab-gate: bundled_libhs_count=25\n#18 ERROR: PRIVATE-KEY\n')
    assert runner.gate_facts(log)['failed_buildkit_step'] == 18
    root = tmp_path / 'run'
    root.mkdir()
    (root / 'state.json').write_text(json.dumps({'stages': {}, 'gates': runner.gate_facts(log),
        'preflight': {'wheel_sha256': 'a' * 64, 'lock_sha256': 'b' * 64, 'source_archive_sha256': 'c' * 64}}))
    summary = runner.summary(root)
    assert 'PRIVATE-KEY' not in summary
    assert 'failed_buildkit_step: 18' in summary
    for key, digest in [('wheel_sha256', 'a' * 64), ('lock_sha256', 'b' * 64), ('source_archive_sha256', 'c' * 64)]:
        assert key + ': ' + digest in summary


def test_docker_prerequisites_require_supported_engine_and_metadata_flag():
    runner = module()
    version = {'Server': {'Os': 'linux', 'Arch': 'amd64', 'Version': '28.5.1'}}
    valid = runner.validate_docker_probe(version, 'github.com/docker/buildx v0.29.1 abc', '  --metadata-file string', {'DockerRootDir': '/var/lib/docker'})
    assert valid['docker_version'] == '28.5.1' and valid['buildx_version'] == 'v0.29.1'
    with pytest.raises(ValueError, match='metadata-file'):
        runner.validate_docker_probe(version, 'github.com/docker/buildx v0.29.1 abc', '', {'DockerRootDir': '/var/lib/docker'})
    with pytest.raises(ValueError, match='linux/amd64'):
        runner.validate_docker_probe({'Server': {'Os': 'linux', 'Arch': 'arm64', 'Version': '28.5.1'}},
                                     'github.com/docker/buildx v0.29.1 abc', '--metadata-file', {'DockerRootDir': '/var/lib/docker'})


def test_resource_floor_fails_without_mutating_runner():
    runner = module()
    valid = {'cpu_count': 2, 'memory_available_bytes': 6 * 1024 ** 3,
             'temp_free_bytes': 20 * 1024 ** 3, 'docker_free_bytes': 20 * 1024 ** 3}
    runner.validate_resources(valid)
    for key in valid:
        with pytest.raises(ValueError, match='resource'):
            runner.validate_resources(valid | {key: 0})


def test_summary_classifies_gate_refusal_separately_from_missing_coverage(tmp_path):
    runner = module()
    root = tmp_path / 'run'
    root.mkdir()
    (root / 'state.json').write_text(json.dumps({'stages': {'build': 'failed'},
        'gates': {'bundled_libhs_count': 25}}))
    report = runner.summary(root)
    assert 'build-gate refusal' in report
    assert 'missing derivative coverage' in report.lower()


@pytest.mark.parametrize('error, category, numeric', [
    (subprocess.CalledProcessError(128, ['git', 'fetch', 'PRIVATE-PIN'],
                                  output='PRIVATE-KEY', stderr='could not resolve host PRIVATE-PIN'),
     'subprocess_failure', {'returncode': 128}),
    (ValueError('git source archive checksum mismatch'), 'source_archive_hash_mismatch', {}),
    (ValueError('source checkout/revision or patch operation failed: PRIVATE-KEY'), 'source_command_failure', {}),
    (subprocess.TimeoutExpired(['PRIVATE-KEY'], 12.5, output='PRIVATE-PIN'),
     'subprocess_timeout', {'timeout_seconds': 12.5}),
    (ValueError('PRIVATE-PIN PRIVATE-KEY'), 'validation_failure', {}),
])
def test_driver_retains_only_allowlisted_failure_diagnostics(tmp_path, monkeypatch, capsys, error, category, numeric):
    runner = module()
    root = tmp_path / 'run'
    runner.initialize(root)
    def fail_build(selected):
        runner.checkpoint(selected, 'source-acquisition')
        raise error
    monkeypatch.setattr(runner, 'build', fail_build)
    monkeypatch.setattr(sys, 'argv', [str(SCRIPT), 'build', '--root', str(root)])
    assert runner.main() == 1
    state = json.loads((root / 'state.json').read_text())
    assert state['stages']['build'] == 'failed'
    assert state['failure'] == {'category': category, 'operation': 'build',
                                 'target': 'haskoki-release-runtime',
                                 'checkpoint': 'source-acquisition', **numeric}
    assert runner.result_exit_code({}) != 0
    retained = ((root / 'state.json').read_text() +
                (root / 'private/build-driver.log').read_text() + runner.summary(root))
    terminal = capsys.readouterr()
    assert 'PRIVATE-' not in retained + terminal.out + terminal.err
    assert category in runner.summary(root)
    assert (root / 'private/build-driver.log').stat().st_size > 0


def test_nested_subprocess_cause_retains_only_numeric_exit_status():
    runner = module()
    try:
        try:
            raise subprocess.CalledProcessError(19, ['PRIVATE-KEY'], stderr='PRIVATE-PIN')
        except subprocess.CalledProcessError as cause:
            raise ValueError('post-build command failed (19): PRIVATE-KEY PRIVATE-PIN') from cause
    except ValueError as error:
        record = runner.failure_record(error, 'build', 'post-build-identity-and-inventory')
    assert record['category'] == 'post_build_command_failure'
    assert record['returncode'] == 19
    assert 'PRIVATE-' not in json.dumps(record)


def test_summary_does_not_trust_unallowlisted_failure_fields(tmp_path):
    runner = module()
    root = tmp_path / 'run'
    root.mkdir()
    (root / 'state.json').write_text(json.dumps({'stages': {}, 'failure': {
        'category': 'PRIVATE-PIN', 'operation': 'PRIVATE-KEY', 'target': '/private/token.sqlite',
        'checkpoint': 'PRIVATE-PIN', 'returncode': 'PRIVATE-PIN', 'timeout_seconds': 'PRIVATE-KEY',
        'stderr': 'PRIVATE-KEY'}}))
    text = runner.summary(root)
    assert 'PRIVATE-' not in text and 'token.sqlite' not in text


@pytest.mark.parametrize('kind, category', [
    (FileNotFoundError, 'missing_prerequisite'), (PermissionError, 'permission_failure'),
    (OSError, 'filesystem_or_os_failure'), (AssertionError, 'assertion_failure'),
    (RuntimeError, 'unexpected_failure'),
])
def test_failure_categories_never_expose_exception_type_names_or_text(kind, category):
    runner = module()
    record = runner.failure_record(kind('PRIVATE-PIN /private/PRIVATE-KEY'), 'preflight', 'docker-capabilities')
    assert record['category'] == category
    assert 'PRIVATE-' not in json.dumps(record)
    assert kind.__name__ not in json.dumps(record)


def test_network_failure_retains_only_safe_http_status():
    from urllib.error import HTTPError, URLError
    runner = module()
    http = runner.failure_record(HTTPError('https://PRIVATE-KEY', 503, 'PRIVATE-PIN', {}, None),
                                 'build', 'source-acquisition')
    assert http['category'] == 'http_failure' and http['http_status'] == 503
    network = runner.failure_record(URLError('PRIVATE-KEY'), 'build', 'source-acquisition')
    assert network['category'] == 'network_failure'
    assert 'PRIVATE-' not in json.dumps([http, network])


@pytest.mark.parametrize('value', [True, 'PRIVATE-PIN', float('inf'), float('nan'), 10**1000, -1])
def test_failure_timeout_rejects_invalid_numeric_values(value):
    runner = module()
    record = runner.failure_record(subprocess.TimeoutExpired(['PRIVATE-KEY'], value), 'tests', 'all-release-acceptance')
    assert 'timeout_seconds' not in record
    poisoned = record | {'timeout_seconds': value}
    assert not any('timeout_seconds' in line for line in runner.failure_summary(poisoned))


@pytest.mark.parametrize('value', [True, 'PRIVATE-PIN', 256, -256, 10**1000])
def test_failure_returncode_rejects_invalid_numeric_values(value):
    runner = module()
    record = runner.failure_record(subprocess.CalledProcessError(value, ['PRIVATE-KEY']), 'build', 'source-acquisition')
    assert 'returncode' not in record
    assert not any('returncode' in line for line in runner.failure_summary(record | {'returncode': value}))


def test_failure_causal_traversal_is_bounded_and_cycle_safe():
    runner = module()
    cyclic = ValueError('PRIVATE-PIN')
    cyclic.__cause__ = cyclic
    assert runner.failure_record(cyclic, 'build', 'source-acquisition')['category'] == 'validation_failure'
    cause = subprocess.CalledProcessError(7, ['PRIVATE-KEY'])
    for _ in range(4):
        wrapped = ValueError('PRIVATE-PIN')
        wrapped.__cause__ = cause
        cause = wrapped
    assert 'returncode' not in runner.failure_record(cause, 'build', 'source-acquisition')


def test_minimal_ci_requirements_include_complete_pinned_build_and_test_closure():
    # Runtime Requires-Dist for Hatchling 1.32.4 and pytest 9.1.1 on Linux
    # Python 3.12; tomli's <3.11 and colorama's Windows markers do not apply.
    pins = dict(line.split('==', 1) for line in
                (ROOT / '.github/requirements/haskoki-validation.txt').read_text().splitlines()
                if line and not line.startswith('#'))
    expected = {'hatchling': '1.32.4', 'packaging': '26.3', 'pathspec': '1.1.1',
                'pluggy': '1.7.0', 'tomlkit': '0.15.2', 'trove-classifiers': '2026.9.21.13',
                'pytest': '9.1.1', 'iniconfig': '2.3.1', 'Pygments': '2.21.0',
                'editables': '0.6'}
    assert pins == expected
    workflow = WORKFLOW.read_text()
    assert '--no-deps --only-binary :all:' in workflow
    assert ' -m pip check' in workflow


def test_cheap_static_job_checks_dependencies_in_its_own_fresh_venv():
    static = WORKFLOW.read_text().split('  static:\n', 1)[1].split('  runtime:\n', 1)[0]
    assert 'python -m venv "$RUNNER_TEMP/haskoki-static-venv"' in static
    assert '"$RUNNER_TEMP/haskoki-static-venv/bin/python" -m pip install' in static
    assert '"$RUNNER_TEMP/haskoki-static-venv/bin/python" -m pip check' in static
    assert 'echo "$RUNNER_TEMP/haskoki-static-venv/bin" >> "$GITHUB_PATH"' in static
    assert 'haskoki_validation.py build' not in static
