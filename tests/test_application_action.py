"""Own-command Action regressions; acquisition fixtures never grant eligibility."""
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

import pytest

ROOT = Path(__file__).resolve().parents[1]
WRAPPER = ROOT / 'src/p11lab/data/delivery/action-run.py'


def wrapper():
    spec = importlib.util.spec_from_file_location('application_action', WRAPPER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def arguments(workspace, run_dir, requested='.'):
    return ['--environment', 'softhsm2', '--channel', 'release', '--mode', 'direct',
            '--registry', '127.0.0.1:5050/p11lab', '--handoff-digest', 'sha256:' + 'ab' * 32,
            '--command', '["./app", "literal $(touch bad); quote \\\" space"]', '--timeout', '10',
            '--workspace', str(workspace), '--working-directory', requested,
            '--oras', 'oras', '--run-dir', str(run_dir)]


@pytest.mark.parametrize('kind', ['symlink', 'ancestor-symlink', 'missing', 'absolute'])
def test_cwd_escape_rejected_before_acquisition(tmp_path, monkeypatch, kind):
    module = wrapper()
    caller = tmp_path / 'unrelated caller'
    caller.mkdir()
    outside = tmp_path / 'control'
    outside.mkdir()
    (outside / 'nested').mkdir()
    (caller / 'link').symlink_to(outside, target_is_directory=True)
    requested = {'symlink': 'link', 'ancestor-symlink': 'link/nested',
                 'missing': 'absent', 'absolute': str(outside)}[kind]
    monkeypatch.setattr(module, '_run', lambda *a, **k: pytest.fail('acquisition began for unsafe cwd'))
    run_dir = tmp_path / 'attempt'
    assert module.main(arguments(caller, run_dir, requested)) == 2
    outputs = dict(line.split('=', 1) for line in (run_dir / 'action-outputs.env').read_text().splitlines())
    assert outputs == {'exit-code': '2', 'app-returncode': '', 'receipt-path': '', 'handoff-sha256': ''}


@pytest.mark.parametrize('requested', ['.', 'nested space \'";$()', 'same-tree'])
def test_cwd_resolves_nested_and_same_tree_paths(tmp_path, monkeypatch, requested):
    module = wrapper()
    caller = tmp_path / 'unrelated caller'
    caller.mkdir()
    nested = caller / 'nested space \'";$()'
    nested.mkdir()
    (caller / 'same-tree').symlink_to(nested, target_is_directory=True)
    seen = []
    def acquisition(argv, *, env, cwd):
        seen.append(cwd)
        return 1
    monkeypatch.setattr(module, '_run', acquisition)
    attempt = tmp_path / 'attempt'
    assert module.main(arguments(caller, attempt, requested)) == 1
    assert seen == [str(caller if requested == '.' else nested)]
    assert (attempt / 'action-outputs.env').read_text().startswith('exit-code=1\n')


def test_owned_preflight_invalid_input_finalizes(tmp_path):
    module = wrapper()
    argv = arguments(tmp_path, tmp_path / 'attempt')
    argv[argv.index('--command') + 1] = 'invalid JSON'
    assert module.main(argv) == 2
    assert 'exit-code=2\n' in (tmp_path / 'attempt/action-outputs.env').read_text()


@pytest.mark.parametrize('number', [signal.SIGINT, signal.SIGTERM, signal.SIGHUP])
def test_wrapper_signal_reaches_owned_child_and_allows_cleanup(tmp_path, number):
    """Signal only wrapper PID; child must finish cleanup before wrapper exits."""
    child = tmp_path / 'child.py'
    ready, cleaned = tmp_path / 'ready', tmp_path / 'cleaned'
    child.write_text('import signal, time\nfrom pathlib import Path\n'
                     f'def stop(n, frame):\n time.sleep(.1)\n Path({str(cleaned)!r}).write_text(str(n))\n raise SystemExit(128+n)\n'
                     'for n in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP): signal.signal(n, stop)\n'
                     f'Path({str(ready)!r}).write_text("ready")\nwhile True: time.sleep(.02)\n')
    driver = tmp_path / 'driver.py'
    driver.write_text(f'import importlib.util, os, sys\ns=importlib.util.spec_from_file_location("action", {str(WRAPPER)!r})\n'
                      'm=importlib.util.module_from_spec(s)\ns.loader.exec_module(m)\n'
                      f'sys.exit(m._run([sys.executable, {str(child)!r}], env=dict(os.environ), cwd={str(tmp_path)!r}))\n')
    process = subprocess.Popen([sys.executable, str(driver)], env=dict(os.environ), start_new_session=True)
    try:
        deadline = time.monotonic() + 5
        while not ready.exists() and time.monotonic() < deadline:
            time.sleep(.02)
        assert ready.exists()
        os.kill(process.pid, number)
        assert process.wait(timeout=8) == 128 + number
        assert cleaned.read_text() == str(number)
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=3)


@pytest.mark.parametrize('kind', ['absent', 'symlink-record', 'malformed-record', 'symlink-receipt', 'changed-receipt'])
def test_collection_reports_incomplete_without_reusing_unsafe_evidence(tmp_path, monkeypatch, capsys, kind):
    module = wrapper()
    attempt = tmp_path / 'attempt'
    attempt.mkdir()
    target = tmp_path / 'secret'
    target.write_text('private sentinel')
    record = attempt / 'action-outputs.env'
    if kind == 'symlink-record':
        record.symlink_to(target)
    elif kind == 'malformed-record':
        record.write_text('exit-code=0\nreceipt-path=' + str(target) + '\n')
    elif kind != 'absent':
        from test_publish import _action_receipt_record
        output = attempt / 'run-output'
        output.mkdir()
        receipt = output / 'receipt.json'
        if kind == 'symlink-receipt':
            receipt.symlink_to(target)
        else:
            receipt.write_text(json.dumps(_action_receipt_record(exit_code=37))[:-1])
        record.write_text(f'exit-code=37\napp-returncode=0\nreceipt-path={receipt}\nhandoff-sha256=\n')
        context = {'values': {'environment': 'softhsm2', 'channel': 'release', 'mode': 'direct', 'command_argv': ['']},
                   'provider': _action_receipt_record()['artifacts']['provider']}
        (attempt / 'action-context.json').write_text(json.dumps(context))
    exported = tmp_path / 'github-output'
    monkeypatch.setenv('GITHUB_OUTPUT', str(exported))
    assert module.collect(str(attempt)) == 1
    outputs = dict(line.split('=', 1) for line in exported.read_text().splitlines())
    assert outputs['receipt-path'] == outputs['app-returncode'] == ''
    assert outputs['exit-code'] == '1'
    assert 'evidence incomplete' in capsys.readouterr().err
    assert 'private sentinel' not in exported.read_text()


def test_collection_changed_receipt_with_recorded_zero_fails_closed(tmp_path, monkeypatch, capsys):
    module = wrapper()
    from test_publish import _action_receipt_record
    attempt = tmp_path / 'attempt'
    output = attempt / 'run-output'
    output.mkdir(parents=True)
    receipt = output / 'receipt.json'
    receipt.write_text(json.dumps(_action_receipt_record(exit_code=0))[:-1])
    (attempt / 'action-outputs.env').write_text(
        f'exit-code=0\napp-returncode=0\nreceipt-path={receipt}\nhandoff-sha256=\n')
    context = {'values': {'environment': 'softhsm2', 'channel': 'release', 'mode': 'direct', 'command_argv': ['']},
               'provider': _action_receipt_record()['artifacts']['provider']}
    (attempt / 'action-context.json').write_text(json.dumps(context))
    exported = tmp_path / 'github-output'
    monkeypatch.setenv('GITHUB_OUTPUT', str(exported))
    assert module.collect(str(attempt)) == 1
    outputs = dict(line.split('=', 1) for line in exported.read_text().splitlines())
    assert outputs == {'exit-code': '1', 'app-returncode': '', 'receipt-path': '', 'handoff-sha256': ''}


def test_acquisition_timeout_is_bounded_and_owned_child_is_reaped(tmp_path, monkeypatch):
    module = wrapper()
    monkeypatch.setattr(module, 'CLEANUP_GRACE', .05)
    start = time.monotonic()
    result = module._capture([sys.executable, '-c', 'import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)'],
                             env=dict(os.environ), cwd=tmp_path, timeout=.1)
    assert result.returncode == 124
    assert time.monotonic() - start < 6


def test_missing_acquisition_executable_finalizes_without_traceback(tmp_path, capsys):
    module = wrapper()
    argv = arguments(tmp_path, tmp_path / 'attempt')
    argv[argv.index('--oras') + 1] = str(tmp_path / 'missing-oras')
    assert module.main(argv) == 1
    assert 'exit-code=1\n' in (tmp_path / 'attempt/action-outputs.env').read_text()
    assert 'Traceback' not in capsys.readouterr().err


@pytest.mark.parametrize('requested', [' app ', 'space app '])
def test_declared_cwd_preserves_literal_edge_spaces(tmp_path, monkeypatch, requested):
    module = wrapper()
    (tmp_path / requested).mkdir()
    seen = []
    def acquisition(argv, *, env, cwd):
        seen.append(cwd)
        return 1
    monkeypatch.setattr(module, '_run', acquisition)
    assert module.main(arguments(tmp_path, tmp_path / 'attempt', requested)) == 1
    assert seen == [str(tmp_path / requested)]


@pytest.mark.parametrize("manifest_failure, expected", [("cancellation", 143), ("array", 1), ("null", 1)])
def test_manifest_failure_finalizes_and_retains_cancellation(tmp_path, monkeypatch, manifest_failure, expected):
    """A cancelled manifest fetch is not downgraded to a generic failure."""
    from p11lab import publish
    module = wrapper()
    # The fixture seam stops before any provider is admitted or launched.
    handoff = {'catalogue': {'environment': 'softhsm2', 'channel': 'release', 'runtime_role': 'runtime'},
               'registry': '127.0.0.1:5050/p11lab',
               'binary': {'reference': '127.0.0.1:5050/p11lab@sha256:' + 'cc' * 32}}
    monkeypatch.setattr(publish, 'show_handoff', lambda path: handoff)
    monkeypatch.setattr(publish, 'require_eligible_handoff', lambda value: None)  # fixture only, never runtime proof
    def acquire(argv, *, env, cwd):
        if '-o' in argv:
            (Path(argv[argv.index('-o') + 1]) / 'handoff.json').write_text('{}')
        return 0
    def capture(argv, **kwargs):
        if argv[0] == 'oras':
            if manifest_failure == 'cancellation':
                module._active_signals['number'] = signal.SIGTERM
                return subprocess.CompletedProcess(argv, 143, b'', b'native manifest diagnostic\n')
            return subprocess.CompletedProcess(argv, 0, b'[]' if manifest_failure == 'array' else b'null', b'')
        return subprocess.CompletedProcess(argv, 0, b'[]', b'')
    monkeypatch.setattr(module, '_run', acquire)
    monkeypatch.setattr(module, '_capture', capture)
    attempt = tmp_path / 'attempt'
    assert module.main(arguments(tmp_path, attempt)) == expected
    assert (attempt / 'action-outputs.env').read_text().startswith(f'exit-code={expected}\n')


@pytest.mark.parametrize('scenario, expected, app_code, timed_out', [
    ('success', 0, 0, False), ('nonzero', 37, 37, False),
    ('native124', 124, 124, False), ('timeout', 124, 124, True),
    ('startup', 1, None, False),
])
def test_unrelated_caller_through_public_cli_and_shared_runner(tmp_path, monkeypatch, scenario, expected, app_code, timed_out):
    """Real wrapper/CLI/runner, fake engine: contract proof, not mount visibility."""
    from test_run_failures import Engine
    from p11lab import run
    from p11lab.cli import main as cli_main
    from p11lab.docker import CommandResult, DockerError
    module = wrapper()
    monkeypatch.delenv('CI', raising=False)
    monkeypatch.delenv('GITHUB_ACTIONS', raising=False)
    monkeypatch.setenv('UNFORWARDED_CONTROL_SECRET', 'outside-environment-sentinel')
    caller = tmp_path / 'caller unrelated to action'
    caller.mkdir()
    nested = caller / 'app space \'";$()'
    nested.mkdir()
    (nested / 'fixture').write_text('declared read write marker')
    outside = tmp_path / 'outside-control'
    outside.write_text('outside-filesystem-sentinel')
    engine_id = 'sha256:' + 'aa' * 32
    manifest = json.dumps({'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.manifest.v1+json',
                           'config': {'digest': 'sha256:' + 'bb' * 32}, 'layers': []}).encode()
    import hashlib
    digest = hashlib.sha256(manifest).hexdigest()
    registry = '127.0.0.1:5050/p11lab'
    handoff = {'schema_version': 1, 'registry': registry,
               'catalogue': {'environment': 'softhsm2', 'channel': 'release', 'runtime_role': 'runtime'},
               'source': {'reference': registry + '@sha256:' + 'dd' * 32, 'manifest_sha256': 'dd' * 32,
                          'file_sha256': 'ee' * 32, 'tag': 'source'},
               'binary': {'kind': 'docker-local', 'reference': registry + '@sha256:' + digest,
                          'manifest_sha256': digest, 'config_sha256': 'bb' * 32, 'engine_id': engine_id,
                          'tag': 'binary', 'platform': 'linux/amd64'},
               'admission': {'status': 'blocked', 'blockers': ['fixture only']},
               'producer': {}, 'readback': {}, 'exposure': {}}
    literal_argv = ['./app', 'space quote \'"', '$(touch SHOULD-NOT-EXIST); `literal`', str(outside)]
    class ApplicationEngine(Engine):
        def execute(self, identity, timeout, interrupted):
            argv = self.created[int(identity.split('-')[1])][1]
            if argv[0] == 'exec':
                if scenario == 'startup':
                    raise DockerError('fixture startup refusal')
                return CommandResult(app_code, '', '', timed_out)
            return super().execute(identity, timeout, interrupted)
    engine = ApplicationEngine()
    monkeypatch.setattr(run, 'Docker', lambda: engine)
    lifecycle_env = []
    def acquire_or_cli(argv, *, env, cwd):
        if argv[1:4] == ['-m', 'p11lab', 'run']:
            lifecycle_env.append(env)
            return cli_main(argv[3:])
        if argv[:2] != ['docker', 'pull']:
            (Path(argv[argv.index('-o') + 1]) / 'handoff.json').write_text(json.dumps(handoff))
        return 0
    def capture(argv, **kwargs):
        if argv[0] == 'oras':
            return subprocess.CompletedProcess(argv, 0, manifest, b'')
        observation = [{'Id': engine_id, 'Os': 'linux', 'Architecture': 'amd64',
                        'RepoDigests': [handoff['binary']['reference']]}]
        return subprocess.CompletedProcess(argv, 0, json.dumps(observation).encode(), b'')
    monkeypatch.setattr(module, '_run', acquire_or_cli)
    monkeypatch.setattr(module, '_capture', capture)
    attempt = tmp_path / 'attempt'
    argv = arguments(caller, attempt, nested.name)
    argv[argv.index('--command') + 1] = json.dumps(literal_argv)
    assert module.main([*argv, '--local-proof']) == expected
    record = json.loads((attempt / 'run-output/receipt.json').read_text())
    assert record['exit_code'] == expected and record['app_returncode'] == app_code
    assert record['timeout'] is timed_out
    assert not record['cleanup_errors']
    application = engine.created[2]
    assert list(application[1]) == ['exec', '--', *literal_argv]
    import csv
    import io
    mounts = [next(csv.reader(io.StringIO(application[2][i + 1]), strict=True))
              for i, option in enumerate(application[2]) if option == '--mount']
    assert ['type=bind', f'src={nested}', 'dst=/workspace'] in mounts
    assert ['type=bind', f'src={attempt / "run-output"}', 'dst=/p11lab-output'] in mounts
    assert all(str(outside) not in option for option in application[2])
    assert all('UNFORWARDED_CONTROL_SECRET' not in env for env in lifecycle_env)
    assert all('outside-environment-sentinel' not in contents for contents in engine.envfiles)
    assert len(engine.removed) == len(engine.created) + 1
    assert not (nested / 'SHOULD-NOT-EXIST').exists()
    # Context retained for collection carries counts, never actual caller argv.
    assert '$(touch' not in (attempt / 'action-context.json').read_text()


def test_successful_parent_with_stragglers_is_not_reported_as_clean_success(tmp_path):
    module = wrapper()
    result = module._capture([sys.executable, '-c',
        'import subprocess,sys; subprocess.Popen([sys.executable,"-c","import time; time.sleep(60)"])'],
        env=dict(os.environ), cwd=tmp_path, timeout=2)
    assert result.returncode == 1


def test_platform_without_sighup_still_finalizes_owned_preflight(tmp_path, monkeypatch):
    module = wrapper()
    monkeypatch.delattr(signal, 'SIGHUP')
    argv = arguments(tmp_path, tmp_path / 'attempt')
    argv[argv.index('--command') + 1] = 'invalid JSON'
    assert module.main(argv) == 2
    assert (tmp_path / 'attempt/action-outputs.env').read_text().startswith('exit-code=2\n')


@pytest.mark.parametrize('lifecycle, expected', [(True, 37), (False, 124)])
def test_watchdog_cleanup_preserves_only_lifecycle_native_status(tmp_path, monkeypatch, lifecycle, expected):
    """Real owned child exits37 after watchdog SIGTERM; acquisition stays timeout."""
    from p11lab import process
    module = wrapper()
    monkeypatch.setattr(module, 'CLEANUP_GRACE', .5)
    child = '''
import signal, time
from p11lab.run import compute_exit_code
def cleanup(number, frame):
    time.sleep(.05)
    code = compute_exit_code(app_returncode=37, app_completed=True,
        interrupted_signal=number, timed_out=False, lifecycle=[], cleanup=[])
    print('completed-native-status=' + str(code), flush=True)
    raise SystemExit(code)
signal.signal(signal.SIGTERM, cleanup)
while True: time.sleep(.01)
'''
    real_owner = process.SupervisedProcess
    def owned_child(argv, *, env, cwd, **kwargs):
        return real_owner([sys.executable, '-c', child],
            env=env | {'PYTHONPATH': str(ROOT / 'src')}, cwd=cwd, **kwargs)
    monkeypatch.setattr(process, 'SupervisedProcess', owned_child)
    if lifecycle:
        code = module._run([sys.executable, '-m', 'p11lab', 'run', '--timeout', '1'],
                           env=dict(os.environ), cwd=tmp_path)
    else:
        result = module._capture(['fixture-acquisition'], env=dict(os.environ), cwd=tmp_path, timeout=.5)
        assert b'completed-native-status=37' in result.stdout
        code = result.returncode
    assert code == expected


def watchdog_lifecycle_receipt(tmp_path, monkeypatch, app_code=37):
    """Real wrapper-owned CLI/runner/writer; engine metadata fixture, no Docker.

    The app result is complete before cleanup blocks. The watchdog signal reaches
    the unchanged shared lifecycle, whose native formula and receipt own status.
    """
    from p11lab import process
    module = wrapper()
    monkeypatch.setattr(module, 'CLEANUP_GRACE', 1)
    attempt = tmp_path / 'watchdog-attempt'
    attempt.mkdir()
    output = attempt / 'run-output'
    caller = tmp_path / 'unrelated caller'
    caller.mkdir()
    driver = f'''
import signal, sys, time
from p11lab import run
from p11lab.cli import main
from p11lab.docker import CommandResult
class Engine:
    def __init__(self): self.argv = []; self.delayed = False
    def image(self, artifact):
        return {{'Id': artifact.reference, 'Os': 'linux', 'Architecture': 'amd64'}}
    def volume(self, name, labels, state): return name
    def create(self, image, argv, options, labels, name):
        self.argv.append(argv)
        return str(len(self.argv)-1)
    def execute(self, identity, timeout, interrupted):
        code = {app_code} if self.argv[int(identity)][0] == 'exec' else 0
        return CommandResult(code, 'native application output', '', False)
    def remove(self, *args):
        if not self.delayed:
            self.delayed = True
            print('completed-app-cleanup-pending', flush=True)
            time.sleep(2.2)
run.Docker = Engine
raise SystemExit(main())
'''
    real_owner = process.SupervisedProcess
    def owned_cli(argv, *, env, cwd, **kwargs):
        assert argv[1:4] == ['-m', 'p11lab', 'run']
        return real_owner([sys.executable, '-c', driver, *argv[3:]],
            env=env | {'PYTHONPATH': str(ROOT / 'src')}, cwd=cwd, **kwargs)
    monkeypatch.setattr(process, 'SupervisedProcess', owned_cli)
    engine = 'sha256:' + 'aa' * 32
    code = module._run([sys.executable, '-m', 'p11lab', 'run', 'softhsm2', '--channel', 'release',
        '--mode', 'direct', '--artifact', engine, '--output-dir', str(output), '--cwd', str(caller),
        '--timeout', '1', '--', 'app'], env=dict(os.environ), cwd=caller)
    values = {'environment': 'softhsm2', 'channel': 'release', 'mode': 'direct', 'command_argv': ['app']}
    provider = {'kind': 'docker-local', 'reference': engine, 'sha256': 'aa' * 32, 'platform': 'linux/amd64'}
    return module, code, attempt, values, provider


@pytest.mark.parametrize('native_code', [37, 124])
def test_watchdog_completed_native_status_matches_real_lifecycle_receipt(tmp_path, monkeypatch, native_code):
    module, code, attempt, values, provider = watchdog_lifecycle_receipt(tmp_path, monkeypatch, native_code)
    record = json.loads((attempt / 'run-output/receipt.json').read_text())
    assert record['app_returncode'] == record['exit_code'] == native_code
    assert record['app_completed'] and record['interrupted_signal'] == signal.SIGTERM
    assert not record['timeout'] and not record['cleanup_errors']
    assert code == native_code
    receipt, app = module._receipt_outputs(attempt / 'run-output/receipt.json', values=values, provider=provider, code=code)
    assert receipt == str(attempt / 'run-output/receipt.json') and app == str(native_code)


def test_lifecycle_watchdog_forced_child_without_native_result_stays_timeout(tmp_path, monkeypatch):
    from p11lab import process
    module = wrapper()
    monkeypatch.setattr(module, 'CLEANUP_GRACE', .05)
    pid_file = tmp_path / 'owned-child-pid'
    child = ('import os, signal, time\nfrom pathlib import Path\n'
             'signal.signal(signal.SIGTERM, signal.SIG_IGN)\n'
             f'Path({str(pid_file)!r}).write_text(str(os.getpid()))\n'
             'while True: time.sleep(.01)\n')
    real_owner = process.SupervisedProcess
    def owned_child(argv, *, env, cwd, **kwargs):
        return real_owner([sys.executable, '-c', child], env=env, cwd=cwd, **kwargs)
    monkeypatch.setattr(process, 'SupervisedProcess', owned_child)
    code = module._run([sys.executable, '-m', 'p11lab', 'run', '--timeout', '1'],
                       env=dict(os.environ), cwd=tmp_path)
    assert code == 124
    assert pid_file.is_file()
    with pytest.raises(ProcessLookupError):
        os.kill(int(pid_file.read_text()), 0)
    assert not (tmp_path / 'receipt.json').exists()


def test_watchdog_final_soft_stop_keeps_available_normal_native_result(tmp_path, monkeypatch, capsys):
    """Shared finish may receive a native result before its eventual hard kill."""
    from p11lab import process
    module = wrapper()
    monkeypatch.setattr(module, 'CLEANUP_GRACE', .1)
    child = '''
import signal,time
from p11lab.run import compute_exit_code
received = 0
def cleanup(number, frame):
    global received
    received += 1
    if received == 2:
        code = compute_exit_code(app_returncode=37, app_completed=True,
            interrupted_signal=number, timed_out=False, lifecycle=[], cleanup=[])
        print('normal-native-result-after-soft-stop=' + str(code), flush=True)
        raise SystemExit(code)
signal.signal(signal.SIGTERM, cleanup)
while True: time.sleep(.01)
'''
    real_owner = process.SupervisedProcess
    def owned_child(argv, *, env, cwd, **kwargs):
        return real_owner([sys.executable, '-c', child],
            env=env | {'PYTHONPATH': str(ROOT / 'src')}, cwd=cwd, **kwargs)
    monkeypatch.setattr(process, 'SupervisedProcess', owned_child)
    code = module._run([sys.executable, '-m', 'p11lab', 'run', '--timeout', '1'],
                       env=dict(os.environ), cwd=tmp_path)
    output = capsys.readouterr()
    assert 'exceeded cleanup grace' in output.err
    assert 'normal-native-result-after-soft-stop=37' in output.out
    assert code == 37


# --- B-G2c gated acquisition wiring (appended; earlier rows untouched) ---

G2C_TRANSPORT_DIGEST = 'sha256:' + '11' * 32
G2C_PROMOTION_DIGEST = 'sha256:' + '22' * 32
G2C_EVIDENCE_REGISTRY = '127.0.0.1:5050/p11lab-evidence'


def _gated_material(tmp_path, *, registry='127.0.0.1:5050/softhsm2', mutate_pre=None,
                    mutate_post=None, booleans=False, transport_bundle=None, transport_root=None,
                    transport_manifest_extra=None, config='bb' * 32):
    """Valid v2 handoff plus bound evidence dirs, fixture exe bytes, canned OCI bytes."""
    import hashlib
    from test_acquisition import fixture_context, make_evidence
    from test_promotion import (ACQ, fixture_promotion_context,
                                fixture_promotion_profile, make_promotion_evidence)
    manifest_bytes = json.dumps({'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.manifest.v1+json',
                                 'config': {'digest': 'sha256:' + config}, 'layers': []}).encode()
    manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()
    proof_sha = '0' * 64
    engine_id = 'sha256:' + 'aa' * 32
    handoff = {'schema_version': 2, 'registry': registry,
               'catalogue': {'environment': 'softhsm2', 'channel': 'release', 'runtime_role': 'runtime'},
               'source': {'reference': registry + '@sha256:' + 'c3' * 32, 'manifest_sha256': 'c3' * 32,
                          'file_sha256': 'c4' * 32, 'tag': 'src',
                          'content_companion': {
                              'reference': registry + '@sha256:' + 'e' * 64, 'manifest_sha256': 'e' * 64,
                              'file_sha256': '1' * 64, 'receipt_sha256': '2' * 64,
                              'spdx_sha256': '3' * 64, 'readback_proof_sha256': proof_sha}},
               'binary': {'kind': 'docker-local', 'reference': registry + '@sha256:' + manifest_digest,
                          'manifest_sha256': manifest_digest, 'config_sha256': 'bb' * 32,
                          'engine_id': engine_id, 'platform': 'linux/amd64', 'tag': 'binary'},
               'admission': {'status': 'eligible', 'blockers': [], 'content_status': 'eligible',
                             'source_readback_status': 'verified'},
               'readback': {}, 'producer': {}, 'exposure': {}}
    if booleans:
        handoff['approved'] = True
        handoff['anonymous_source_available'] = True
        handoff['image_promotable'] = True
    if mutate_pre is not None:
        mutate_pre(handoff)
    companion = handoff['source']['content_companion']
    proof = {'schema_version': 1, 'role': 'content-readback-proof', 'registry': handoff['registry']}
    for name in ('reference', 'manifest_sha256', 'file_sha256', 'receipt_sha256', 'spdx_sha256'):
        proof[name] = companion[name]
    proof_bytes = (json.dumps(proof, sort_keys=True) + '\n').encode()
    handoff['source']['content_companion']['readback_proof_sha256'] = hashlib.sha256(proof_bytes).hexdigest()
    profile = fixture_promotion_profile()
    transport = make_evidence(tmp_path, context=fixture_context(profile, handoff), bundle=transport_bundle,
                              root=transport_root, manifest_extra=transport_manifest_extra,
                              name='g2c-transport-src')
    promotion = make_promotion_evidence(tmp_path, context=fixture_promotion_context(
        profile, handoff, proof_bytes=proof_bytes), proof=proof_bytes, name='g2c-promotion-src')
    if mutate_post is not None:
        mutate_post(handoff)
    observation = [{'Id': engine_id, 'Os': 'linux', 'Architecture': 'amd64',
                    'RepoDigests': [handoff['binary']['reference']]}]
    return {'handoff': handoff, 'profile': profile, 'transport': transport, 'promotion': promotion,
            'manifest': manifest_bytes, 'observation': observation,
            'exe': (ACQ / 'verifier' / 'verify-fixture.sh').read_bytes()}


def _gated_arguments(workspace, run_dir, *, transport=G2C_TRANSPORT_DIGEST, promotion=G2C_PROMOTION_DIGEST,
                     evidence_registry='', registry='127.0.0.1:5050/softhsm2', handoff_digest=None,
                     command='["./app"]', timeout='10', extra=()):
    handoff_digest = handoff_digest or 'sha256:' + 'ab' * 32
    return ['--environment', 'softhsm2', '--channel', 'release', '--mode', 'direct',
            '--registry', registry, '--handoff-digest', handoff_digest,
            '--command', command, '--timeout', timeout,
            '--workspace', str(workspace), '--working-directory', '.',
            '--oras', 'oras', '--run-dir', str(run_dir),
            '--transport-evidence-digest', transport, '--promotion-evidence-digest', promotion,
            '--evidence-registry', evidence_registry, *extra]


def _gated_run_stub(*, calls, handoff_ref, handoff, transport_ref=None, transport=None,
                    promotion_ref=None, promotion=None, cli=None):
    import shutil
    def fetch(argv, *, env, cwd):
        calls.append(argv)
        if argv[1:4] == ['-m', 'p11lab', 'run']:
            assert cli is not None, 'lifecycle must not run on this path'
            return cli(argv, env=env, cwd=cwd)
        if argv[:2] == ['docker', 'pull']:
            return 0
        target = Path(argv[argv.index('-o') + 1])
        ref = argv[-1]
        if ref == handoff_ref:
            (target / 'handoff.json').write_text(json.dumps(handoff))
        elif transport is not None and ref == transport_ref:
            for member in sorted(transport.iterdir()):
                shutil.copy(member, target / member.name)
        elif promotion is not None and ref == promotion_ref:
            for member in sorted(promotion.iterdir()):
                shutil.copy(member, target / member.name)
        else:
            pytest.fail('unexpected pull: ' + ref)
        return 0
    return fetch


def _gated_capture_stub(*, manifest_bytes, observation, exe_bytes, installer_envs, installer_argv=None):
    def capture(argv, **kwargs):
        if len(argv) > 2 and argv[0] == 'sh' and argv[1].endswith('install-gh.sh'):
            dest = Path(argv[argv.index('--output-dir') + 1])
            dest.mkdir(parents=True)
            exe = dest / 'gh'
            exe.write_bytes(exe_bytes)
            exe.chmod(0o755)
            installer_envs.append(dict(kwargs['env']))
            if installer_argv is not None:
                installer_argv.append(list(argv))
            return subprocess.CompletedProcess(argv, 0, (str(exe) + '\n').encode(), b'')
        if argv[0] == 'oras':
            return subprocess.CompletedProcess(argv, 0, manifest_bytes, b'')
        return subprocess.CompletedProcess(argv, 0, json.dumps(observation).encode(), b'')
    return capture


def _gated_engine(*, app_code=0):
    from test_run_failures import Engine
    from p11lab.docker import CommandResult
    class ApplicationEngine(Engine):
        def execute(self, identity, timeout, interrupted):
            argv = self.created[int(identity.split('-')[1])][1]
            if argv[0] == 'exec':
                return CommandResult(app_code, '', '', False)
            return super().execute(identity, timeout, interrupted)
    return ApplicationEngine()


def test_ci_local_proof_refusal_text_locked(tmp_path, monkeypatch, capsys):
    """Locked characterization: the :449-452 CI refusal bytes never change."""
    module = wrapper()
    monkeypatch.setenv('CI', 'true')
    registry = '127.0.0.1:5050/p11lab'
    handoff = {'schema_version': 1, 'registry': registry,
               'catalogue': {'environment': 'softhsm2', 'channel': 'release', 'runtime_role': 'runtime'},
               'source': {'reference': registry + '@sha256:' + 'dd' * 32, 'manifest_sha256': 'dd' * 32,
                          'file_sha256': 'ee' * 32, 'tag': 'source'},
               'binary': {'kind': 'docker-local', 'reference': registry + '@sha256:' + 'cc' * 32,
                          'manifest_sha256': 'cc' * 32, 'config_sha256': 'bb' * 32,
                          'engine_id': 'sha256:' + 'aa' * 32, 'tag': 'binary', 'platform': 'linux/amd64'},
               'admission': {'status': 'blocked', 'blockers': ['fixture only']},
               'producer': {}, 'readback': {}, 'exposure': {}}
    def fetch(argv, *, env, cwd):
        (Path(argv[argv.index('-o') + 1]) / 'handoff.json').write_text(json.dumps(handoff))
        return 0
    monkeypatch.setattr(module, '_run', fetch)
    assert module.main([*arguments(tmp_path, tmp_path / 'attempt'), '--local-proof']) == 1
    assert 'action-run: --local-proof refused: CI is set; local mechanics proof only\n' in capsys.readouterr().err


def test_gated_absent_evidence_still_r4_before_binary_pull(tmp_path, monkeypatch, capsys):
    """Locked characterization: None evidence reaches the gate R4 (R10 text at wrapper level)."""
    from test_acquisition import R4
    module = wrapper()
    monkeypatch.delenv('CI', raising=False)
    monkeypatch.delenv('GITHUB_ACTIONS', raising=False)
    material = _gated_material(tmp_path)
    calls = []
    handoff_ref = '127.0.0.1:5050/softhsm2@sha256:' + 'ab' * 32
    monkeypatch.setattr(module, '_run', _gated_run_stub(calls=calls, handoff_ref=handoff_ref,
                                                        handoff=material['handoff']))
    argv = arguments(tmp_path, tmp_path / 'attempt')
    argv[argv.index('--registry') + 1] = '127.0.0.1:5050/softhsm2'
    assert module.main(argv) == 1
    assert capsys.readouterr().err.splitlines() == ['action-run: ' + R4, 'action-run: evidence incomplete: no validated lifecycle receipt']
    assert len(calls) == 1 and calls[0][1] == 'pull' and calls[0][-1] == handoff_ref


def test_gated_valid_pair_proceeds_to_engine_stub(tmp_path, monkeypatch):
    """Gated honest success: real wrapper/CLI/runner, fake engine, honest argv."""
    from test_promotion import stub_gate_verifiers
    from p11lab import run
    from p11lab.cli import main as cli_main
    module = wrapper()
    monkeypatch.delenv('CI', raising=False)
    monkeypatch.delenv('GITHUB_ACTIONS', raising=False)
    monkeypatch.setenv('UNFORWARDED_CONTROL_SECRET', 'outside-environment-sentinel')
    monkeypatch.setenv('https_proxy', 'proxy-sentinel-must-pass-to-installer')
    caller = tmp_path / 'caller unrelated to action'
    caller.mkdir()
    nested = caller / 'app space \'";$()'
    nested.mkdir()
    outside = tmp_path / 'outside-control'
    outside.write_text('outside-filesystem-sentinel')
    material = _gated_material(tmp_path)
    stub_gate_verifiers(monkeypatch, material['profile'])
    engine = _gated_engine()
    monkeypatch.setattr(run, 'Docker', lambda: engine)
    lifecycle_env = []
    def cli(argv, *, env, cwd):
        lifecycle_env.append(env)
        return cli_main(argv[3:])
    calls, installer_envs, installer_argv = [], [], []
    registry = '127.0.0.1:5050/softhsm2'
    handoff_ref = registry + '@sha256:' + 'ab' * 32
    transport_ref = registry + '@' + G2C_TRANSPORT_DIGEST
    promotion_ref = registry + '@' + G2C_PROMOTION_DIGEST
    monkeypatch.setattr(module, '_run', _gated_run_stub(
        calls=calls, handoff_ref=handoff_ref, handoff=material['handoff'],
        transport_ref=transport_ref, transport=material['transport'],
        promotion_ref=promotion_ref, promotion=material['promotion'], cli=cli))
    monkeypatch.setattr(module, '_capture', _gated_capture_stub(
        manifest_bytes=material['manifest'], observation=material['observation'],
        exe_bytes=material['exe'], installer_envs=installer_envs, installer_argv=installer_argv))
    literal_argv = ['./app', 'space quote \'"', '$(touch SHOULD-NOT-EXIST); `literal`', str(outside)]
    attempt = tmp_path / 'attempt'
    argv = _gated_arguments(caller, attempt, command=json.dumps(literal_argv))
    argv[argv.index('--working-directory') + 1] = nested.name
    assert module.main(argv) == 0
    record = json.loads((attempt / 'run-output/receipt.json').read_text())
    assert record['exit_code'] == 0 and record['app_returncode'] == 0 and not record['timeout']
    application = engine.created[2]
    assert list(application[1]) == ['exec', '--', *literal_argv]
    assert all(str(outside) not in option for option in application[2])
    assert all('UNFORWARDED_CONTROL_SECRET' not in env for env in lifecycle_env)
    assert all('outside-environment-sentinel' not in contents for contents in engine.envfiles)
    assert not (nested / 'SHOULD-NOT-EXIST').exists()
    pulls = [argv for argv in calls if argv[0] == 'oras']
    assert [argv[-1] for argv in pulls] == [handoff_ref, transport_ref, promotion_ref]
    assert len(installer_envs) == 1
    assert installer_envs[0]['https_proxy'] == 'proxy-sentinel-must-pass-to-installer'
    assert installer_argv[0][:2] != ['sh', '--noproxy'] and '--noproxy' not in installer_argv[0]
    assert installer_argv[0][installer_argv[0].index('--output-dir') + 1].startswith(str(attempt))
    assert (attempt / 'transport-staging/verifier-journal.json').is_file()
    assert (attempt / 'promotion-staging/verifier-journal.json').is_file()


def test_gated_nonzero_app_code_propagates(tmp_path, monkeypatch):
    """Gated nonzero control: the application code propagates unchanged."""
    from test_promotion import stub_gate_verifiers
    from p11lab import run
    from p11lab.cli import main as cli_main
    module = wrapper()
    monkeypatch.delenv('CI', raising=False)
    monkeypatch.delenv('GITHUB_ACTIONS', raising=False)
    caller = tmp_path / 'caller'
    caller.mkdir()
    material = _gated_material(tmp_path)
    stub_gate_verifiers(monkeypatch, material['profile'])
    engine = _gated_engine(app_code=37)
    monkeypatch.setattr(run, 'Docker', lambda: engine)
    def cli(argv, *, env, cwd):
        return cli_main(argv[3:])
    calls, installer_envs = [], []
    registry = '127.0.0.1:5050/softhsm2'
    monkeypatch.setattr(module, '_run', _gated_run_stub(
        calls=calls, handoff_ref=registry + '@sha256:' + 'ab' * 32, handoff=material['handoff'],
        transport_ref=registry + '@' + G2C_TRANSPORT_DIGEST, transport=material['transport'],
        promotion_ref=registry + '@' + G2C_PROMOTION_DIGEST, promotion=material['promotion'], cli=cli))
    monkeypatch.setattr(module, '_capture', _gated_capture_stub(
        manifest_bytes=material['manifest'], observation=material['observation'],
        exe_bytes=material['exe'], installer_envs=installer_envs))
    attempt = tmp_path / 'attempt'
    assert module.main(_gated_arguments(caller, attempt)) == 37
    record = json.loads((attempt / 'run-output/receipt.json').read_text())
    assert record['exit_code'] == 37 and record['app_returncode'] == 37


def _gated_success_run(tmp_path, monkeypatch, module, *, tag, engine, cli, material):
    """One gated honest run; returns (code, app_code, lifecycle_envs)."""
    calls, installer_envs = [], []
    registry = '127.0.0.1:5050/softhsm2'
    lifecycle_envs = []
    def recording_cli(argv, *, env, cwd):
        lifecycle_envs.append(env)
        return cli(argv, env=env, cwd=cwd)
    monkeypatch.setattr(module, '_run', _gated_run_stub(
        calls=calls, handoff_ref=registry + '@sha256:' + 'ab' * 32, handoff=material['handoff'],
        transport_ref=registry + '@' + G2C_TRANSPORT_DIGEST, transport=material['transport'],
        promotion_ref=registry + '@' + G2C_PROMOTION_DIGEST, promotion=material['promotion'],
        cli=recording_cli))
    monkeypatch.setattr(module, '_capture', _gated_capture_stub(
        manifest_bytes=material['manifest'], observation=material['observation'],
        exe_bytes=material['exe'], installer_envs=installer_envs))
    caller = tmp_path / ('caller-' + tag)
    caller.mkdir()
    attempt = tmp_path / ('attempt-' + tag)
    code = module.main(_gated_arguments(caller, attempt))
    record = json.loads((attempt / 'run-output/receipt.json').read_text())
    return code, record['app_returncode'], lifecycle_envs


def test_gated_child_env_carries_no_tokens(tmp_path, monkeypatch):
    """ADV #7: subprocess-level token/offline evidence at the scrub layer."""
    import socket
    from test_promotion import stub_gate_verifiers
    from p11lab import inspection_bounded, run
    from p11lab.cli import main as cli_main
    module = wrapper()
    monkeypatch.delenv('CI', raising=False)
    monkeypatch.delenv('GITHUB_ACTIONS', raising=False)
    material = _gated_material(tmp_path)
    stub_gate_verifiers(monkeypatch, material['profile'])
    inner = inspection_bounded.bounded_stream
    verifier_envs = []
    def recording(argv, destination, max_bytes, timeout, env, record):
        verifier_envs.append(dict(env))
        return inner(argv, destination, max_bytes, timeout, env, record)
    monkeypatch.setattr(inspection_bounded, 'bounded_stream', recording)
    engine = _gated_engine()
    monkeypatch.setattr(run, 'Docker', lambda: engine)
    def cli(argv, *, env, cwd):
        return cli_main(argv[3:])
    clean = _gated_success_run(tmp_path, monkeypatch, module, tag='clean', engine=engine,
                               cli=cli, material=material)
    assert clean[0] == 0 and clean[1] == 0
    assert len(verifier_envs) == 2

    def forbidden(*items, **kwargs):
        raise AssertionError('gated acquisition path used a socket')
    monkeypatch.setenv('GH_TOKEN', 'garbage-token-must-be-ignored')
    monkeypatch.setenv('UNFORWARDED_CONTROL_SECRET', 'outside-environment-sentinel')
    monkeypatch.setattr(socket, 'socket', forbidden)
    monkeypatch.setattr(socket, 'create_connection', forbidden)
    monkeypatch.setattr(socket, 'getaddrinfo', forbidden)
    engine2 = _gated_engine()
    monkeypatch.setattr(run, 'Docker', lambda: engine2)
    dirty = _gated_success_run(tmp_path, monkeypatch, module, tag='dirty', engine=engine2,
                               cli=cli, material=material)
    assert dirty[0] == clean[0] and dirty[1] == clean[1]
    assert len(verifier_envs) == 4
    for env in verifier_envs:
        assert set(env) == {'PATH', 'HOME', 'GH_CONFIG_DIR', 'XDG_CACHE_HOME'}
        assert 'GH_TOKEN' not in env
        assert all('garbage-token-must-be-ignored' not in value for value in env.values())
    for env in dirty[2]:
        assert 'GH_TOKEN' not in env and 'UNFORWARDED_CONTROL_SECRET' not in env
        assert all('garbage-token-must-be-ignored' not in value for value in env.values())
        assert all('outside-environment-sentinel' not in value for value in env.values())


def test_gated_tampered_transport_evidence_refused(tmp_path, monkeypatch, capsys):
    """A forged transport root refuses with the R7 text before any binary pull."""
    from test_acquisition import FIXTURES, ROOT_MISMATCH
    from test_promotion import stub_gate_verifiers
    module = wrapper()
    monkeypatch.delenv('CI', raising=False)
    monkeypatch.delenv('GITHUB_ACTIONS', raising=False)
    honest = (FIXTURES / 'trusted-root.jsonl').read_bytes()
    tampered = honest[:-1] + (b'\x00' if honest[-1:] != b'\x00' else b'\xff')
    material = _gated_material(tmp_path, transport_root=tampered)
    stub_gate_verifiers(monkeypatch, material['profile'])
    calls, installer_envs = [], []
    registry = '127.0.0.1:5050/softhsm2'
    monkeypatch.setattr(module, '_run', _gated_run_stub(
        calls=calls, handoff_ref=registry + '@sha256:' + 'ab' * 32, handoff=material['handoff'],
        transport_ref=registry + '@' + G2C_TRANSPORT_DIGEST, transport=material['transport'],
        promotion_ref=registry + '@' + G2C_PROMOTION_DIGEST, promotion=material['promotion']))
    monkeypatch.setattr(module, '_capture', _gated_capture_stub(
        manifest_bytes=material['manifest'], observation=material['observation'],
        exe_bytes=material['exe'], installer_envs=installer_envs))
    assert module.main(_gated_arguments(tmp_path, tmp_path / 'attempt')) == 1
    assert 'action-run: ' + ROOT_MISMATCH in capsys.readouterr().err
    assert [argv for argv in calls if argv[:2] == ['docker', 'pull']] == []
    assert [argv for argv in calls if argv[1:4] == ['-m', 'p11lab', 'run']] == []
    assert len(installer_envs) == 1


def test_gated_evidence_handoff_mismatch_refused(tmp_path, monkeypatch, capsys):
    """Evidence bound to other digests refuses with the R8 text."""
    from test_acquisition import R8
    from test_promotion import stub_gate_verifiers
    module = wrapper()
    monkeypatch.delenv('CI', raising=False)
    monkeypatch.delenv('GITHUB_ACTIONS', raising=False)
    def swap(handoff):
        handoff['source']['manifest_sha256'] = 'ff' * 32
        handoff['source']['reference'] = handoff['registry'] + '@sha256:' + 'ff' * 32
    material = _gated_material(tmp_path, mutate_post=swap)
    stub_gate_verifiers(monkeypatch, material['profile'])
    calls, installer_envs = [], []
    registry = '127.0.0.1:5050/softhsm2'
    monkeypatch.setattr(module, '_run', _gated_run_stub(
        calls=calls, handoff_ref=registry + '@sha256:' + 'ab' * 32, handoff=material['handoff'],
        transport_ref=registry + '@' + G2C_TRANSPORT_DIGEST, transport=material['transport'],
        promotion_ref=registry + '@' + G2C_PROMOTION_DIGEST, promotion=material['promotion']))
    monkeypatch.setattr(module, '_capture', _gated_capture_stub(
        manifest_bytes=material['manifest'], observation=material['observation'],
        exe_bytes=material['exe'], installer_envs=installer_envs))
    assert module.main(_gated_arguments(tmp_path, tmp_path / 'attempt')) == 1
    assert 'action-run: ' + R8 in capsys.readouterr().err


def test_gated_partial_evidence_reaches_promotion_refusal(tmp_path, monkeypatch, capsys):
    """Transport verified but promotion absent refuses with the promotion text."""
    from test_promotion import P_UNAVAILABLE, stub_gate_verifiers
    module = wrapper()
    monkeypatch.delenv('CI', raising=False)
    monkeypatch.delenv('GITHUB_ACTIONS', raising=False)
    material = _gated_material(tmp_path)
    stub_gate_verifiers(monkeypatch, material['profile'])
    calls, installer_envs = [], []
    registry = '127.0.0.1:5050/softhsm2'
    monkeypatch.setattr(module, '_run', _gated_run_stub(
        calls=calls, handoff_ref=registry + '@sha256:' + 'ab' * 32, handoff=material['handoff'],
        transport_ref=registry + '@' + G2C_TRANSPORT_DIGEST, transport=material['transport']))
    monkeypatch.setattr(module, '_capture', _gated_capture_stub(
        manifest_bytes=material['manifest'], observation=material['observation'],
        exe_bytes=material['exe'], installer_envs=installer_envs))
    argv = _gated_arguments(tmp_path, tmp_path / 'attempt', promotion='')
    assert module.main(argv) == 1
    assert 'action-run: ' + P_UNAVAILABLE in capsys.readouterr().err
    pulls = [argv[-1] for argv in calls if argv[0] == 'oras']
    assert pulls == [registry + '@sha256:' + 'ab' * 32, registry + '@' + G2C_TRANSPORT_DIGEST]
    assert len(installer_envs) == 1


@pytest.mark.parametrize('field, bad', [('transport', 'latest'), ('promotion', 'sha256:xyz')])
def test_gated_malformed_evidence_digest_is_input_error(tmp_path, monkeypatch, capsys, field, bad):
    """Tag-form or truncated digests fail closed as input errors before acquisition."""
    module = wrapper()
    monkeypatch.delenv('CI', raising=False)
    monkeypatch.delenv('GITHUB_ACTIONS', raising=False)
    calls = []
    def fetch(argv, *, env, cwd):
        calls.append(argv)
        return 0
    monkeypatch.setattr(module, '_run', fetch)
    kwargs = {'transport': bad} if field == 'transport' else {'promotion': bad}
    argv = _gated_arguments(tmp_path, tmp_path / 'attempt', **kwargs)
    assert module.main(argv) == 2
    assert f'action {field}-evidence-digest must be sha256:<hex>' in capsys.readouterr().err
    assert calls == []


def test_gated_malformed_evidence_registry_is_input_error(tmp_path, monkeypatch, capsys):
    """A non-repository evidence registry fails closed before acquisition."""
    module = wrapper()
    monkeypatch.delenv('CI', raising=False)
    monkeypatch.delenv('GITHUB_ACTIONS', raising=False)
    calls = []
    def fetch(argv, *, env, cwd):
        calls.append(argv)
        return 0
    monkeypatch.setattr(module, '_run', fetch)
    argv = _gated_arguments(tmp_path, tmp_path / 'attempt', evidence_registry='not a repo!!')
    assert module.main(argv) == 2
    assert 'action evidence-registry must be a repository path' in capsys.readouterr().err
    assert calls == []


def test_gated_explicit_evidence_registry_routes_pulls(tmp_path, monkeypatch, capsys):
    """An explicit evidence registry routes evidence pulls but not the handoff."""
    from test_promotion import P_UNAVAILABLE, stub_gate_verifiers
    module = wrapper()
    monkeypatch.delenv('CI', raising=False)
    monkeypatch.delenv('GITHUB_ACTIONS', raising=False)
    material = _gated_material(tmp_path)
    stub_gate_verifiers(monkeypatch, material['profile'])
    calls, installer_envs = [], []
    registry = '127.0.0.1:5050/softhsm2'
    monkeypatch.setattr(module, '_run', _gated_run_stub(
        calls=calls, handoff_ref=registry + '@sha256:' + 'ab' * 32, handoff=material['handoff'],
        transport_ref=G2C_EVIDENCE_REGISTRY + '@' + G2C_TRANSPORT_DIGEST, transport=material['transport']))
    monkeypatch.setattr(module, '_capture', _gated_capture_stub(
        manifest_bytes=material['manifest'], observation=material['observation'],
        exe_bytes=material['exe'], installer_envs=installer_envs))
    argv = _gated_arguments(tmp_path, tmp_path / 'attempt', promotion='',
                            evidence_registry=G2C_EVIDENCE_REGISTRY)
    assert module.main(argv) == 1
    assert 'action-run: ' + P_UNAVAILABLE in capsys.readouterr().err
    pulls = [argv[-1] for argv in calls if argv[0] == 'oras']
    assert pulls == [registry + '@sha256:' + 'ab' * 32,
                     G2C_EVIDENCE_REGISTRY + '@' + G2C_TRANSPORT_DIGEST]


@pytest.mark.parametrize('kind', ['registry', 'role'])
def test_gated_bind_mismatch_refused_before_evidence(tmp_path, monkeypatch, capsys, kind):
    """Handoff/bind mismatches refuse before any evidence check or pull."""
    module = wrapper()
    monkeypatch.delenv('CI', raising=False)
    monkeypatch.delenv('GITHUB_ACTIONS', raising=False)
    if kind == 'role':
        def mutate(handoff):
            handoff['catalogue']['runtime_role'] = 'native'
        material = _gated_material(tmp_path, mutate_pre=mutate)
        argv = _gated_arguments(tmp_path, tmp_path / 'attempt')
        expected = 'action-run: handoff runtime role native does not serve mode direct'
    else:
        material = _gated_material(tmp_path)
        argv = _gated_arguments(tmp_path, tmp_path / 'attempt', registry='127.0.0.1:5050/other')
        expected = 'action-run: handoff binds a different registry/environment/channel'
    calls, installer_envs = [], []
    def fetch(argv, *, env, cwd):
        calls.append(argv)
        (Path(argv[argv.index('-o') + 1]) / 'handoff.json').write_text(json.dumps(material['handoff']))
        return 0
    def capture(argv, **kwargs):
        if len(argv) > 2 and argv[0] == 'sh' and argv[1].endswith('install-gh.sh'):
            installer_envs.append(dict(kwargs['env']))
            pytest.fail('verifier provisioning must not run before bind checks')
        return subprocess.CompletedProcess(argv, 0, b'[]', b'')
    monkeypatch.setattr(module, '_run', fetch)
    monkeypatch.setattr(module, '_capture', capture)
    assert module.main(argv) == 1
    assert expected in capsys.readouterr().err
    assert len(calls) == 1 and calls[0][1] == 'pull'
    assert installer_envs == []


@pytest.mark.parametrize('evidence', ['absent', 'malformed'])
def test_gated_caller_booleans_stay_inert(tmp_path, monkeypatch, capsys, evidence):
    """Approved/source/promotion caller flags neither open nor rescue the gate."""
    from test_acquisition import R4
    from test_promotion import stub_gate_verifiers
    module = wrapper()
    monkeypatch.delenv('CI', raising=False)
    monkeypatch.delenv('GITHUB_ACTIONS', raising=False)
    extra = {'schema_version': 99} if evidence == 'malformed' else None
    material = _gated_material(tmp_path, booleans=True, transport_manifest_extra=extra)
    stub_gate_verifiers(monkeypatch, material['profile'])
    calls, installer_envs = [], []
    registry = '127.0.0.1:5050/softhsm2'
    handoff_ref = registry + '@sha256:' + 'ab' * 32
    if evidence == 'absent':
        monkeypatch.setattr(module, '_run', _gated_run_stub(calls=calls, handoff_ref=handoff_ref,
                                                            handoff=material['handoff']))
        argv = arguments(tmp_path, tmp_path / 'attempt')
        argv[argv.index('--registry') + 1] = '127.0.0.1:5050/softhsm2'
        expected = R4
    else:
        monkeypatch.setattr(module, '_run', _gated_run_stub(
            calls=calls, handoff_ref=handoff_ref, handoff=material['handoff'],
            transport_ref=registry + '@' + G2C_TRANSPORT_DIGEST, transport=material['transport'],
            promotion_ref=registry + '@' + G2C_PROMOTION_DIGEST, promotion=material['promotion']))
        argv = _gated_arguments(tmp_path, tmp_path / 'attempt')
        expected = R4
    monkeypatch.setattr(module, '_capture', _gated_capture_stub(
        manifest_bytes=material['manifest'], observation=material['observation'],
        exe_bytes=material['exe'], installer_envs=installer_envs))
    assert module.main(argv) == 1
    assert 'action-run: ' + expected in capsys.readouterr().err


def test_gated_damaged_image_refused_after_gate(tmp_path, monkeypatch, capsys):
    """A config-damaged acquired image refuses with the integrity text past the gate."""
    from test_promotion import stub_gate_verifiers
    module = wrapper()
    monkeypatch.delenv('CI', raising=False)
    monkeypatch.delenv('GITHUB_ACTIONS', raising=False)
    material = _gated_material(tmp_path, config='cc' * 32)
    stub_gate_verifiers(monkeypatch, material['profile'])
    calls, installer_envs = [], []
    registry = '127.0.0.1:5050/softhsm2'
    monkeypatch.setattr(module, '_run', _gated_run_stub(
        calls=calls, handoff_ref=registry + '@sha256:' + 'ab' * 32, handoff=material['handoff'],
        transport_ref=registry + '@' + G2C_TRANSPORT_DIGEST, transport=material['transport'],
        promotion_ref=registry + '@' + G2C_PROMOTION_DIGEST, promotion=material['promotion']))
    monkeypatch.setattr(module, '_capture', _gated_capture_stub(
        manifest_bytes=material['manifest'], observation=material['observation'],
        exe_bytes=material['exe'], installer_envs=installer_envs))
    assert module.main(_gated_arguments(tmp_path, tmp_path / 'attempt')) == 1
    assert 'action-run: acquired image config differs from handoff' in capsys.readouterr().err
    assert [argv for argv in calls if argv[:2] == ['docker', 'pull']]
    assert [argv for argv in calls if argv[1:4] == ['-m', 'p11lab', 'run']] == []


def test_gated_verifier_provisioning_failure_blocks(tmp_path, monkeypatch, capsys):
    """A failed sealed-verifier install blocks acquisition without staging."""
    from test_promotion import stub_gate_verifiers
    module = wrapper()
    monkeypatch.delenv('CI', raising=False)
    monkeypatch.delenv('GITHUB_ACTIONS', raising=False)
    material = _gated_material(tmp_path)
    stub_gate_verifiers(monkeypatch, material['profile'])
    calls = []
    registry = '127.0.0.1:5050/softhsm2'
    monkeypatch.setattr(module, '_run', _gated_run_stub(
        calls=calls, handoff_ref=registry + '@sha256:' + 'ab' * 32, handoff=material['handoff'],
        transport_ref=registry + '@' + G2C_TRANSPORT_DIGEST, transport=material['transport'],
        promotion_ref=registry + '@' + G2C_PROMOTION_DIGEST, promotion=material['promotion']))
    def capture(argv, **kwargs):
        if len(argv) > 2 and argv[0] == 'sh' and argv[1].endswith('install-gh.sh'):
            return subprocess.CompletedProcess(argv, 1, b'', b'installer diagnostic\n')
        return subprocess.CompletedProcess(argv, 0, b'[]', b'')
    monkeypatch.setattr(module, '_capture', capture)
    attempt = tmp_path / 'attempt'
    assert module.main(_gated_arguments(tmp_path, attempt)) == 1
    assert 'action-run: sealed verifier provisioning failed' in capsys.readouterr().err
    assert not (attempt / 'transport-staging').exists()
    assert [argv[-1] for argv in calls if argv[0] == 'oras'] == [
        registry + '@sha256:' + 'ab' * 32, registry + '@' + G2C_TRANSPORT_DIGEST,
        registry + '@' + G2C_PROMOTION_DIGEST]


def test_gated_local_proof_skips_evidence_fetch(tmp_path, monkeypatch, capsys):
    """The local-proof diagnostic skips evidence pulls and verifier provisioning."""
    module = wrapper()
    monkeypatch.delenv('CI', raising=False)
    monkeypatch.delenv('GITHUB_ACTIONS', raising=False)
    material = _gated_material(tmp_path, config='cc' * 32)
    calls = []
    registry = '127.0.0.1:5050/softhsm2'
    def fetch(argv, *, env, cwd):
        calls.append(argv)
        if argv[1:4] == ['-m', 'p11lab', 'run']:
            pytest.fail('lifecycle must not run for a damaged image')
        if argv[:2] == ['docker', 'pull']:
            return 0
        (Path(argv[argv.index('-o') + 1]) / 'handoff.json').write_text(json.dumps(material['handoff']))
        return 0
    def capture(argv, **kwargs):
        if len(argv) > 2 and argv[0] == 'sh' and argv[1].endswith('install-gh.sh'):
            pytest.fail('verifier provisioning must not run for local proof')
        if argv[0] == 'oras':
            return subprocess.CompletedProcess(argv, 0, material['manifest'], b'')
        return subprocess.CompletedProcess(argv, 0, json.dumps(material['observation']).encode(), b'')
    monkeypatch.setattr(module, '_run', fetch)
    monkeypatch.setattr(module, '_capture', capture)
    argv = _gated_arguments(tmp_path, tmp_path / 'attempt', extra=['--local-proof'])
    assert module.main(argv) == 1
    assert 'action-run: acquired image config differs from handoff' in capsys.readouterr().err
    assert [argv for argv in calls if argv[0] == 'oras'] != []
    assert all(argv[-1] == registry + '@sha256:' + 'ab' * 32 for argv in calls if argv[0] == 'oras')
