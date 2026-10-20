#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""One-attempt Haskoki evidence runner. Never publish raw logs or artifacts.

This deliberately does not claim complete qualification: derivative builders
are not yet supported installed operations, so their lanes remain missing.
"""
import argparse
from collections import Counter
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from urllib.error import HTTPError, URLError

STAGES = ('preflight', 'build', 'tests')
STATES = {'pending', 'running', 'passed', 'failed', 'incomplete'}
CHECKPOINTS = {'installed-wheel-identity', 'locked-release-inputs', 'docker-capabilities',
               'runner-resources', 'compile-lifecycle-helper', 'collect-expected-roster',
               'locked-source-build', 'source-acquisition', 'closed-context-preparation',
               'docker-recipe-build', 'post-build-identity-and-inventory', 'all-release-acceptance'}
DERIVATIVE_TESTS = {
    'test_token_slot_identity_and_label', 'test_direct_crypto_generated_oracle',
    'test_token_row_persists_across_processes', 'test_persisted_key_reopens_in_fresh_processes',
    'test_direct_checker_smoke', 'test_release_checker_two_independent_frozen_shards', 'test_proxy_crypto_container', 'test_proxy_crypto_host',
}
EXPECTED_ROSTER = {
    'test_rolling_locked': 1, 'test_release_candidate_is_locked_but_not_qualified': 1,
    'test_real_standalone_lifecycle': 1, 'test_initial_credentials_fail_explicitly': 8,
    'test_concurrent_health_never_opens_module': 1,
    'test_lost_token_contents_are_not_reinitialized': 1,
    'test_release_fresh_store_is_schema3': 1,
    'test_release_native_open_does_not_migrate_incompatible_schema': 3,
    'test_release_incompatible_schema_refuses_before_application_without_mutation': 18,
    'test_release_real_module_holder_refuses_second_open_and_allows_parallel_health': 2,
    'test_release_stale_sidecar_with_unrelated_live_pid_is_taken_over': 1,
    'test_release_changed_pin_persists_and_reinit_never_restores_demo_pin': 2,
    'test_release_init_token_and_init_pin_commit_across_processes': 1,
    **{name: 1 for name in DERIVATIVE_TESTS},
}
HEX = re.compile(r'[0-9a-f]{64}')
IMAGE = re.compile(r'sha256:[0-9a-f]{64}')

FAILURE_CATEGORIES = {
    'subprocess_failure', 'subprocess_timeout', 'source_command_failure',
    'source_archive_hash_mismatch', 'source_revision_mismatch', 'source_archive_invalid',
    'post_build_command_failure', 'runtime_build_failure', 'validation_failure',
    'missing_prerequisite', 'permission_failure', 'filesystem_or_os_failure',
    'http_failure', 'network_failure', 'assertion_failure', 'unexpected_failure',
}
FAILURE_TARGETS = {'preflight': 'haskoki-release-preflight',
                   'build': 'haskoki-release-runtime', 'tests': 'haskoki-release-acceptance'}
KNOWN_FAILURE_MESSAGES = {
    'git source archive checksum mismatch': 'source_archive_hash_mismatch',
    'source archive checksum mismatch': 'source_archive_hash_mismatch',
    'source checkout revision mismatch': 'source_revision_mismatch',
    'unsafe or invalid source archive': 'source_archive_invalid',
}


def failure_category(error):
    # Never stringify an exception: args, command, URLs and assertion text may
    # contain credentials. Compare only fixed, known library message shapes.
    message = error.args[0] if error.args and isinstance(error.args[0], str) else ''
    if isinstance(error, ValueError):
        if message in KNOWN_FAILURE_MESSAGES:
            return KNOWN_FAILURE_MESSAGES[message]
        for prefix, category in (
            ('source checkout/revision or patch operation failed:', 'source_command_failure'),
            ('post-build command failed (', 'post_build_command_failure'),
            ('runtime build failed;', 'runtime_build_failure'),
        ):
            if message.startswith(prefix):
                return category
    for kind, category in (
        (subprocess.TimeoutExpired, 'subprocess_timeout'),
        (subprocess.CalledProcessError, 'subprocess_failure'),
        (HTTPError, 'http_failure'), (URLError, 'network_failure'),
        (FileNotFoundError, 'missing_prerequisite'), (PermissionError, 'permission_failure'),
        (OSError, 'filesystem_or_os_failure'), (ValueError, 'validation_failure'),
        (AssertionError, 'assertion_failure'),
    ):
        if isinstance(error, kind):
            return category
    return 'unexpected_failure'


def failure_record(error, operation, observed_checkpoint):
    operation = operation if operation in FAILURE_TARGETS else 'unknown'
    record = {'category': failure_category(error), 'operation': operation,
              'target': FAILURE_TARGETS.get(operation, 'haskoki-release-validation'),
              'checkpoint': observed_checkpoint if observed_checkpoint in CHECKPOINTS else 'unspecified'}
    # Wrappers can expose a genuine subprocess cause. Stop at four objects and
    # reject cycles; retain only validated numeric diagnostics, never type names.
    seen = set()
    for _ in range(4):
        if error is None or id(error) in seen:
            break
        seen.add(id(error))
        if isinstance(error, subprocess.CalledProcessError):
            value = error.returncode
            if type(value) is int and -255 <= value <= 255:
                record.setdefault('returncode', value)
        if isinstance(error, subprocess.TimeoutExpired):
            value = error.timeout
            if type(value) in (int, float) and 0 <= value <= 86400 and math.isfinite(value):
                record.setdefault('timeout_seconds', value)
        if isinstance(error, HTTPError):
            value = error.code
            if type(value) is int and 100 <= value <= 599:
                record.setdefault('http_status', value)
        error = error.__cause__ or (None if error.__suppress_context__ else error.__context__)
    return record


def failure_summary(record):
    if not isinstance(record, dict) or record.get('category') not in FAILURE_CATEGORIES:
        return []
    lines = ['- Failure category: ' + record['category']]
    operation = record.get('operation')
    if operation in FAILURE_TARGETS and record.get('target') == FAILURE_TARGETS[operation]:
        lines.append('- Failure operation: ' + operation + '; target: ' + FAILURE_TARGETS[operation])
    if record.get('checkpoint') in CHECKPOINTS:
        lines.append('- Failure checkpoint: ' + record['checkpoint'])
    for key, low, high in (('returncode', -255, 255), ('timeout_seconds', 0, 86400), ('http_status', 100, 599)):
        value = record.get(key)
        types = (int, float) if key == 'timeout_seconds' else (int,)
        if type(value) in types and low <= value <= high and math.isfinite(value):
            lines.append(f'- Failure {key}: {value}')
    return lines


def write_json(path, data):
    path = Path(path)
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(data, indent=2, sort_keys=True) + '\n')
    temporary.chmod(0o600)
    temporary.replace(path)


def read_json(path, default):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return default


def test_name(node):
    name = node.rsplit('::', 1)[-1].split('[', 1)[0]
    return name if re.fullmatch(r'test_[a-z0-9_]+', name) else 'invalid_test_identity'


class SafeResults:
    """Retain names, hashed identities and outcomes, never report payload text."""
    def __init__(self, output):
        self.output = Path(output)
        self.nodes = {}
        self.invalid = False
        self.collected = False

    def pytest_collection_finish(self, session):
        self.collected = True
        for item in session.items:
            digest = hashlib.sha256(item.nodeid.encode()).hexdigest()
            if digest in self.nodes:
                self.invalid = True
            self.nodes[digest] = {'test': test_name(item.nodeid), 'case_sha256': digest, 'phases': {}}
        self.save(None)

    def pytest_runtest_logreport(self, report):
        digest = hashlib.sha256(report.nodeid.encode()).hexdigest()
        if digest not in self.nodes or report.when not in ('setup', 'call', 'teardown'):
            self.invalid = True
            return
        if report.outcome not in ('passed', 'failed', 'skipped') or hasattr(report, 'wasxfail'):
            self.invalid = True
        phases = self.nodes[digest]['phases']
        if report.when in phases:
            self.invalid = True
        phases[report.when] = report.outcome if report.outcome in ('passed', 'failed', 'skipped') else 'invalid'
        self.save(None)

    def pytest_sessionfinish(self, session, exitstatus):
        self.save(int(exitstatus))

    def save(self, exitstatus):
        tests = []
        counts = dict.fromkeys(('passed', 'failed', 'error', 'skipped', 'incomplete'), 0)
        for node in self.nodes.values():
            phases = node['phases']
            if phases.get('setup') == 'failed' or phases.get('teardown') == 'failed':
                outcome = 'error'
            elif phases.get('call') == 'failed':
                outcome = 'failed'
            elif 'skipped' in phases.values():
                outcome = 'skipped'
            elif phases == {'setup': 'passed', 'call': 'passed', 'teardown': 'passed'}:
                outcome = 'passed'
            else:
                outcome = 'incomplete'
            counts[outcome] += 1
            tests.append({**node, 'outcome': outcome})
        complete = (self.collected and bool(tests) and not self.invalid and
                    not counts['incomplete'] and not counts['skipped'] and exitstatus in (0, 1))
        write_json(self.output, {'schema_version': 1, 'complete': complete,
                                'pytest_exit_code': exitstatus, 'counts': counts, 'tests': tests})


def result_exit_code(report):
    if not report.get('complete'):
        return 3
    if report.get('pytest_exit_code') != 0 or any(report['counts'][k] for k in ('failed', 'error')):
        return 1
    return 0


def initialize(root):
    if os.environ.get('GITHUB_RUN_ATTEMPT', '1') != '1':
        raise ValueError('only the first attempt is authorized; no automatic reruns')
    if os.environ.get('GITHUB_EVENT_NAME', 'workflow_dispatch') != 'workflow_dispatch':
        raise ValueError('runtime requires manual dispatch')
    root.mkdir(parents=True, exist_ok=False)
    root.chmod(0o700)
    (root / 'private').mkdir(mode=0o700)
    write_json(root / 'state.json', {'stages': dict.fromkeys(STAGES, 'pending')})


def update(root, **fields):
    state = read_json(root / 'state.json', {'stages': {}})
    state.update(fields)
    write_json(root / 'state.json', state)


def stage(root, name, status):
    state = read_json(root / 'state.json', {'stages': {}})
    state.setdefault('stages', {})[name] = status
    write_json(root / 'state.json', state)


def checkpoint(root, name):
    if name not in CHECKPOINTS:
        raise ValueError('unrecognized safe checkpoint')
    update(root, checkpoint=name)


def pytest_arguments(tests):
    return ['-c', '/dev/null', '-o', 'pythonpath=', '-o', 'addopts=',
            '--confcutdir', str(tests), '--maxfail=0', '-p', 'no:terminal',
            str(tests / 'test_haskoki.py'), str(tests / 'test_haskoki_release.py')]


def integration_environment(image):
    if not IMAGE.fullmatch(image):
        raise ValueError('runtime requires an exact local image ID')
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(('P11LAB_', 'PYTEST_', 'PYTHONPATH'))}
    env.update(PYTEST_DISABLE_PLUGIN_AUTOLOAD='1', P11LAB_TEST_HASKOKI_CHANNELS='release',
               P11LAB_TEST_HASKOKI_IMAGES=json.dumps({'release': image}))
    return env


def pytest_child(root, mode, image):
    log = root / 'private' / (mode + '.log')
    with log.open('w') as output:
        result = subprocess.run([sys.executable, '-I', str(Path(__file__).resolve()), mode,
                                 '--root', str(root)], env=integration_environment(image),
                                cwd=root / 'private/tests', stdout=output, stderr=subprocess.STDOUT,
                                timeout=900)
    return result.returncode


def validate_docker_probe(version, buildx, help_text, info):
    server = version.get('Server', {})
    if server.get('Os') != 'linux' or server.get('Arch') != 'amd64':
        raise ValueError('Docker server must be linux/amd64')
    if '--metadata-file' not in help_text:
        raise ValueError('docker build does not support --metadata-file')
    if not re.fullmatch(r'[0-9]+(?:\.[0-9]+){1,3}', server.get('Version', '')):
        raise ValueError('unsupported Docker version record')
    matched = re.search(r'\bv[0-9]+(?:\.[0-9]+){1,3}\b', buildx)
    if not matched or not isinstance(info.get('DockerRootDir'), str):
        raise ValueError('Docker buildx/storage prerequisite missing')
    return {'docker_version': server['Version'], 'buildx_version': matched[0],
            'platform': 'linux/amd64'}


def validate_resources(resources):
    floors = {'cpu_count': 2, 'memory_available_bytes': 6 * 1024 ** 3,
              'temp_free_bytes': 20 * 1024 ** 3, 'docker_free_bytes': 20 * 1024 ** 3}
    if any(type(resources.get(key)) is not int or resources[key] < minimum
           for key, minimum in floors.items()):
        raise ValueError('runner resource prerequisite not met')


def host_prerequisites(root):
    import platform
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        raise ValueError('host must be Linux amd64')
    def command(*args):
        return subprocess.run(args, capture_output=True, text=True, check=True, timeout=30).stdout
    checkpoint(root, 'docker-capabilities')
    version = json.loads(command('docker', 'version', '--format', '{{json .}}'))
    info = json.loads(command('docker', 'info', '--format', '{{json .}}'))
    probe = validate_docker_probe(version, command('docker', 'buildx', 'version'),
                                  command('docker', 'build', '--help'), info)
    checkpoint(root, 'runner-resources')
    available = re.search(r'^MemAvailable:\s+(\d+) kB$', Path('/proc/meminfo').read_text(), re.M)
    resources = {'cpu_count': os.cpu_count() or 0,
                 'memory_available_bytes': int(available[1]) * 1024 if available else 0,
                 'temp_free_bytes': shutil.disk_usage(root).free,
                 'docker_free_bytes': shutil.disk_usage(info['DockerRootDir']).free}
    update(root, host=probe | resources)
    validate_resources(resources)


def preflight(root, repository, wheel_dir):
    import p11lab
    from p11lab.catalog import package_data, load_environment, validate_build_inputs
    from importlib.metadata import distribution
    checkpoint(root, 'installed-wheel-identity')
    # Isolation is checked explicitly; pytest's repository pythonpath is disabled.
    if root.is_relative_to(repository.resolve()):
        raise ValueError('evidence and tests must live outside the checkout')
    if Path(p11lab.__file__).resolve().is_relative_to(repository.resolve()):
        raise ValueError('P11Lab must be wheel-installed outside the checkout')
    wheels = list(wheel_dir.glob('p11lab-*.whl'))
    if len(wheels) != 1:
        raise ValueError('exactly one producer wheel is required')
    wheel_hash = hashlib.sha256(wheels[0].read_bytes()).hexdigest()
    direct = json.loads(distribution('p11lab').read_text('direct_url.json'))
    if direct.get('archive_info', {}).get('hashes', {}).get('sha256') != wheel_hash:
        raise ValueError('installed package differs from the producer wheel')
    checkpoint(root, 'locked-release-inputs')
    spec = load_environment('haskoki', 'release')
    validate_build_inputs(spec)
    if spec['lock']['sources'][0].get('revision') != '091a2223e6dc559af72913c7f5a061ca22af34dc':
        raise ValueError('not the reviewed Haskoki v0.5 source')
    identities = {'source_revision': spec['lock']['sources'][0]['revision'],
                  'source_archive_sha256': spec['lock']['sources'][0]['archive_sha256'],
                  'wheel_sha256': wheel_hash,
                  'lock_sha256': hashlib.sha256(package_data('providers/haskoki/release.lock.json').read_bytes()).hexdigest()}
    update(root, preflight=identities)
    host_prerequisites(root)
    tests = root / 'private/tests'
    tests.mkdir()
    for name in ('test_haskoki.py', 'test_haskoki_release.py', 'test_checker_smoke.py', 'haskoki/lifecycle.c'):
        source = repository / 'tests/integration' / name
        dest = tests / name
        dest.parent.mkdir(exist_ok=True)
        shutil.copyfile(source, dest)
    checkpoint(root, 'compile-lifecycle-helper')
    helper = root / 'private/helper'
    helper.mkdir()
    (helper / 'pkcs11.h').write_bytes(package_data('consumer/vendor/pkcs11.h').read_bytes())
    with (root / 'private/helper-compile.log').open('w') as log:
        subprocess.run(['cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                        '-I' + str(helper), str(tests / 'haskoki/lifecycle.c'), '-ldl',
                        '-o', str(helper / 'lifecycle')], stdout=log, stderr=subprocess.STDOUT,
                       check=True, timeout=60)
    checkpoint(root, 'collect-expected-roster')
    if pytest_child(root, 'collect-internal', 'sha256:' + '0' * 64):
        raise ValueError('acceptance collection failed')
    collected = read_json(root / 'collection.json', {})
    roster = Counter(item['test'] for item in collected.get('tests', []))
    if roster != EXPECTED_ROSTER:
        raise ValueError('acceptance roster differs from reviewed 49-case selection')
    update(root, preflight=identities | {'collected': sum(roster.values()), 'runtime_and_catalogue': 41,
                            'missing_derivatives': 8,
                            'helper_sha256': hashlib.sha256((helper / 'lifecycle').read_bytes()).hexdigest()})


def gate_facts(log):
    """Only measured provider-gate records, never copied arbitrary log lines."""
    facts = {}
    if not log.is_file():
        return facts
    # Bounded stream; BuildKit prefixes may precede the fixed record marker.
    pattern = re.compile(r'^(?:#\d+\s+[0-9.]+\s+)?p11lab-gate: (bundled_libhs_count|hackage_archive_count|glibc_floor)=(\d{1,5}|GLIBC_\d{1,2}\.\d{1,2})$')
    with log.open(errors='replace') as stream:
        for line in stream:
            failed_step = re.match(r'^#(\d{1,5}) ERROR:', line)
            if failed_step:
                facts['failed_buildkit_step'] = int(failed_step[1])
            match = pattern.fullmatch(line.strip())
            if match and len(line) < 160:
                key, value = match.groups()
                if key == 'glibc_floor' and value.startswith('GLIBC_'):
                    facts[key] = value
                elif key != 'glibc_floor' and value.isdecimal():
                    facts[key] = int(value)
    return facts


def build(root):
    from dataclasses import asdict
    from p11lab.build import build_artifact
    from p11lab.catalog import load_environment
    output = root / 'private/provider'
    checkpoint(root, 'locked-source-build')
    try:
        artifact = build_artifact(load_environment('haskoki', 'release'), 'runtime', output)
        if artifact.kind != 'docker-local' or not IMAGE.fullmatch(artifact.reference) or artifact.platform != 'linux/amd64':
            raise ValueError('unexpected provider identity')
        update(root, provider=asdict(artifact))
    finally:
        update(root, gates=gate_facts(output / 'build.log'))
        observed = ('post-build-identity-and-inventory' if (output / 'image-id').is_file() else
                    'docker-recipe-build' if (output / 'build.log').is_file() else
                    'closed-context-preparation' if (output / 'sources/resolved-sources.json').is_file() else
                    'source-acquisition')
        checkpoint(root, observed)


def run_tests(root):
    checkpoint(root, 'all-release-acceptance')
    image = read_json(root / 'state.json', {})['provider']['reference']
    status = pytest_child(root, 'tests-internal', image)
    report = read_json(root / 'results.json', {})
    # A missing/failed pytest process cannot be reclassified as pass.
    code = result_exit_code(report)
    return code if code else status


def internal_pytest(root, collect=False):
    import pytest
    plugin = SafeResults(root / ('collection.json' if collect else 'results.json'))
    args = pytest_arguments(root / 'private/tests')
    if collect:
        args += ['--collect-only']
    return int(pytest.main(args, plugins=[plugin]))


def summary(root):
    state = read_json(root / 'state.json', {})
    report = read_json(root / 'results.json', {})
    lines = ['## Haskoki v0.5 standalone evidence',
             'Unpatched upstream; not full qualification. No source/image/release publication.',
             'Missing derivative lanes: direct C consumer/OpenSC, installed checker, proxy container and proxy host.',
             'Their existing tests remain selected; missing inputs are missing coverage, never a pass.',
             'Strict build gates remain enforced. Known schema-readiness gaps are ordinary failing tests.']
    lines.extend(failure_summary(state.get('failure')))
    if state.get('checkpoint') in CHECKPOINTS:
        lines.append('- Last observed stage: ' + state['checkpoint'])
    for name in STAGES:
        status = state.get('stages', {}).get(name, 'incomplete')
        lines.append(f'- {name}: {status if status in STATES else "incomplete"}')
    host = state.get('host', {})
    for name in ('cpu_count', 'memory_available_bytes', 'temp_free_bytes', 'docker_free_bytes'):
        value = host.get(name)
        if type(value) is int and value >= 0:
            lines.append(f'- runner {name}: {value}')
    for name in ('docker_version', 'buildx_version'):
        value = host.get(name, '')
        if isinstance(value, str) and re.fullmatch(r'v?[0-9]+(?:\.[0-9]+){1,3}', value):
            lines.append(f'- runner {name}: {value}')
    provider = state.get('provider', {})
    if IMAGE.fullmatch(str(provider.get('reference', ''))):
        lines.append('- Runtime image: ' + provider['reference'])
    preflight_data = state.get('preflight', {})
    for name in ('collected', 'runtime_and_catalogue', 'missing_derivatives'):
        value = preflight_data.get(name)
        if type(value) is int and 0 <= value <= 10000:
            lines.append(f'- {name}: {value}')
    for name, size in (('helper_sha256', 64), ('source_revision', 40), ('wheel_sha256', 64),
                       ('lock_sha256', 64), ('source_archive_sha256', 64)):
        value = preflight_data.get(name, '')
        if isinstance(value, str) and re.fullmatch('[0-9a-f]{' + str(size) + '}', value):
            lines.append(f'- {name}: {value}')
    gates = state.get('gates', {}) or gate_facts(root / 'private/provider/build.log')
    for name in ('bundled_libhs_count', 'hackage_archive_count', 'failed_buildkit_step'):
        value = gates.get(name)
        if type(value) is int and 0 <= value <= 100000:
            lines.append(f'- measured {name}: {value}')
    if re.fullmatch(r'GLIBC_\d{1,2}\.\d{1,2}', str(gates.get('glibc_floor', ''))):
        lines.append('- measured glibc_floor: ' + gates['glibc_floor'])
    if any(name in gates and gates[name] != expected for name, expected in
           {'bundled_libhs_count': 24, 'hackage_archive_count': 2, 'glibc_floor': 'GLIBC_2.38'}.items()):
        lines.append('Classification: build-gate refusal; strict observed input/closure/ABI mismatch.')
    elif state.get('stages', {}).get('build') in ('failed', 'running'):
        lines.append('Classification: build/acquisition/infrastructure failure or interruption; no runtime acceptance result.')
    if state.get('stages', {}).get('preflight') in ('failed', 'running'):
        lines.append('Classification: infrastructure/prerequisite failure before provider build.')
    lines.append('Classification: missing derivative coverage remains explicit and prevents complete validation.')
    if not gates:
        lines.append('No measured closure/ABI/Hackage gate record is available; no inference of pass.')
    if not report.get('complete'):
        lines.append('No complete test report: absent, skipped or incomplete evidence remains a failure.')
    counts = report.get('counts', {})
    if counts.get('failed', 0):
        lines.append('Classification: ordinary acceptance failure(s); unpatched provider observations are not suppressed.')
    if counts.get('error', 0):
        lines.append('Classification: test setup/teardown errors; not classified as provider findings.')
    for key in ('passed', 'failed', 'error', 'skipped', 'incomplete'):
        value = counts.get(key)
        if type(value) is int and 0 <= value <= 10000:
            lines.append(f'- {key}: {value}')
    for item in report.get('tests', []):
        if (item.get('test') in EXPECTED_ROSTER and
                item.get('outcome') in ('passed', 'failed', 'error', 'skipped', 'incomplete') and
                HEX.fullmatch(str(item.get('case_sha256', '')))):
            lines.append(f'- {item["test"]}: {item["outcome"]} (case {item["case_sha256"]})')
    lines.append('Raw logs, assertions, source archives, token stores and TLS/private keys are not retained publicly.')
    return '\n'.join(lines) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('init', 'preflight', 'build', 'tests', 'summary', 'collect-internal', 'tests-internal'))
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--repository', type=Path)
    parser.add_argument('--wheel-dir', type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    if args.operation == 'summary':
        text = summary(root)
        destination = os.environ.get('GITHUB_STEP_SUMMARY')
        if destination:
            with Path(destination).open('a') as output:
                output.write(text)
        else:
            print(text, end='')
        return 0
    if args.operation == 'init':
        initialize(root)
        return 0
    if args.operation.endswith('-internal'):
        return internal_pytest(root, args.operation == 'collect-internal')
    stage(root, args.operation, 'running')
    code = 1
    # Do not let exception repr, compiler output or pytest assertions enter CI logs.
    with (root / 'private' / (args.operation + '-driver.log')).open('w') as log:
        with redirect_stdout(log), redirect_stderr(log):
            try:
                if args.operation == 'preflight':
                    if args.repository is None or args.wheel_dir is None:
                        raise ValueError('preflight requires repository and wheel directory')
                    preflight(root, args.repository, args.wheel_dir)
                    code = 0
                elif args.operation == 'build':
                    build(root)
                    code = 0
                else:
                    code = run_tests(root)
            except Exception as error:
                observed = read_json(root / 'state.json', {}).get('checkpoint')
                failure = failure_record(error, args.operation, observed)
                update(root, failure=failure)
                print('failure: ' + json.dumps(failure, sort_keys=True))
                code = 1
    stage(root, args.operation, 'passed' if code == 0 else 'incomplete' if code == 3 else 'failed')
    print(args.operation + ': ' + ('passed' if code == 0 else 'failed or incomplete; see safe summary'))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
