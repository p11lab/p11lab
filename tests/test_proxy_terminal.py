"""Daemon evidence survives every exit without changing the application result."""
from dataclasses import replace
from types import SimpleNamespace
import json
import os
import signal
import traceback

import pytest

from p11lab import run
from p11lab.docker import CommandResult, Docker, DockerError
from test_proxy_lifecycle import IMAGE, client, spec, _LeasedEngine


class TerminalEngine(_LeasedEngine):
    def __init__(self, manifest, *, dead=False, inspect_error=False, logs_error=False,
                 stop_error=False, remove_error=False, startup_error=False, start_error=False,
                 inspect_result=None, log_result=None, consumer_timeout=False, consumer_signal=None):
        super().__init__(manifest)
        self.consumer_timeout = consumer_timeout
        self.consumer_signal = consumer_signal
        self.consumer_saw_interrupted = False
        self.dead = dead
        self.inspect_error = inspect_error
        self.logs_error = logs_error
        self.stop_error = stop_error
        self.remove_error = remove_error
        self.startup_error = startup_error
        self.start_error = start_error
        self.inspect_result = inspect_result
        self.log_result = log_result
        self.stopped = False
        self.events = []

    def execute(self, identity, *args):
        if not self.argv[identity]:
            if self.consumer_timeout or self.consumer_signal is not None:
                # Consumer lane only: the runner creates it with spec.argv[1:],
                # empty for this fixture. Map the flags exactly like
                # Docker.execute (124 on timeout, else 128+signal, no signal).
                args[1]()
                self.consumer_saw_interrupted = True
                if self.consumer_timeout:
                    return CommandResult(124, 'secret-test-pin consumer output',
                                         'secret-test-so consumer error', True)
                return CommandResult(128 + self.consumer_signal, 'secret-test-pin consumer output',
                                     'secret-test-so consumer error', False)
            return CommandResult(0, 'application output', '')
        if self.startup_error and self.argv[identity][0] == 'cli':
            return CommandResult(2, '', 'probe failed')
        return super().execute(identity, *args)

    def command(self, args, **kwargs):
        if args[0] == 'start' and self.start_error:
            raise DockerError('start secret-test-pin')
        if args[0] == 'inspect':
            self.events.append('inspect')
            if self.inspect_error:
                raise DockerError('inspect secret-test-pin')
            if self.inspect_result is not None:
                return self.inspect_result
            running = not (self.dead or self.stopped)
            return CommandResult(0, json.dumps({
                'Status': 'running' if running else 'exited', 'Running': running,
                'Paused': False, 'Restarting': False, 'OOMKilled': self.dead, 'Dead': False,
                'Pid': 123 if running else 0, 'ExitCode': 137 if self.dead else 0,
                'Error': 'secret-test-pin' if self.dead else '',
                'StartedAt': '2026-10-28T10:00:00Z',
                'FinishedAt': '0001-01-01T00:00:00Z' if running else '2026-10-28T10:00:01Z'}), '')
        if args[0] == 'logs':
            self.events.append('logs')
            if self.logs_error:
                return CommandResult(1, '', 'secret-test-so unavailable')
            if self.log_result is not None:
                return self.log_result
            return CommandResult(0, 'secret-test-pin daemon output', 'secret-test-so daemon error')
        return super().command(args, **kwargs)

    def stop(self, identity, labels):
        self.events.append('stop')
        if self.stop_error:
            raise DockerError('stop secret-test-pin')
        self.stopped = True

    def remove(self, kind, identity, labels):
        if self.argv.get(identity, ())[:1] == ('daemon',):
            self.events.append('remove')
            if self.remove_error:
                raise DockerError('remove secret-test-pin')
        return super().remove(kind, identity, labels)


def attempt(tmp_path, client, monkeypatch, engine, *, app_status=0, timeout=False, cancel=False, app_error=False):
    monkeypatch.setattr(run, 'Docker', lambda: engine)
    monkeypatch.setattr(run, '_create_proxy_network', lambda *args: 'fixture-network')
    def application(*args, **kwargs):
        if app_error:
            raise OSError('application secret-test-pin')
        if cancel:
            os.kill(os.getpid(), signal.SIGTERM)
        return app_status, timeout, {'drain_complete': True, 'stragglers_remaining': [],
                                    'supervision_errors': []}
    monkeypatch.setattr(run, '_run_proxy_host_app', application)
    selected = replace(spec(tmp_path, client), timeout_seconds=30)
    result = run.run_application(selected)
    receipt = json.loads(result.receipt_path.read_text())
    return result, receipt, receipt['proxy'].get('daemon_terminal')


def test_post_ready_death_is_failure_even_when_application_returns_zero(tmp_path, client, monkeypatch):
    result, receipt, evidence = attempt(tmp_path, client, monkeypatch, TerminalEngine(client.manifest, dead=True))
    assert result.exit_code == 1, 'a fresh successful post-health must not hide daemon death'
    assert receipt['app_returncode'] == 0 and receipt['app_completed'] is True
    assert 'daemon exited after readiness' in result.lifecycle_errors
    assert evidence['unexpected_death'] is True
    assert evidence['before_stop']['state']['ExitCode'] == 137
    assert evidence['before_stop']['state']['OOMKilled'] is True
    assert evidence['before_stop']['signal']['observed'] is None
    assert evidence['before_stop']['signal']['encoded_exit_candidate'] == 9
    assert evidence['stop_requested'] is False


def test_requested_stop_captures_terminal_state_and_logs_before_removal(tmp_path, client, monkeypatch):
    engine = TerminalEngine(client.manifest)
    result, receipt, evidence = attempt(tmp_path, client, monkeypatch, engine)
    assert evidence is not None, 'normal successful runs need daemon terminal evidence'
    assert result.exit_code == 0 and not result.lifecycle_errors and not result.cleanup_errors
    assert evidence['stop_requested'] is True and evidence['stop_succeeded'] is True
    assert evidence['unexpected_death'] is False
    assert evidence['before_stop']['state']['Running'] is True
    assert evidence['after_stop']['state']['Running'] is False
    assert engine.events == ['inspect', 'stop', 'inspect', 'logs', 'remove']
    assert not engine.post_ran_while_live
    for name in ('daemon.stdout.log', 'daemon.stderr.log'):
        text = (result.receipt_path.parent / name).read_text()
        assert '[REDACTED]' in text and 'secret-test-' not in text
    assert 'secret-test-' not in json.dumps(evidence)


@pytest.mark.parametrize('timeout,cancel,status,want', [(True, False, 124, 124), (False, True, 143, 143)])
def test_timeout_and_cancellation_retain_daemon_facts(tmp_path, client, monkeypatch, timeout, cancel, status, want):
    engine = TerminalEngine(client.manifest)
    result, receipt, evidence = attempt(tmp_path, client, monkeypatch, engine,
                                        app_status=status, timeout=timeout, cancel=cancel)
    assert evidence is not None, 'timeout and cancellation must capture before cleanup'
    assert result.exit_code == want
    assert receipt['app_returncode'] == status and receipt['app_completed'] is False
    assert receipt['timeout'] is timeout
    assert receipt['interrupted_signal'] == (15 if cancel else None)
    assert evidence['after_stop']['state']['Running'] is False
    assert engine.events[-2:] == ['logs', 'remove']


@pytest.mark.parametrize('inspect_error,logs_error', [(True, False), (False, True)])
def test_diagnostic_failure_is_explicit_without_replacing_app_failure(tmp_path, client, monkeypatch, inspect_error, logs_error):
    engine = TerminalEngine(client.manifest, inspect_error=inspect_error, logs_error=logs_error)
    result, receipt, evidence = attempt(tmp_path, client, monkeypatch, engine, app_status=23)
    assert evidence is not None, 'diagnostic failure must have explicit unavailable evidence'
    assert result.exit_code == 23 and receipt['app_returncode'] == 23
    assert evidence['errors']
    assert evidence['before_stop']['available'] is (not inspect_error)
    assert evidence['logs']['available'] is (not logs_error)
    assert not result.cleanup_errors
    assert 'secret-test-' not in json.dumps(receipt)
    assert engine.events[-1] == 'remove'


@pytest.mark.parametrize('failure', ['stop', 'remove'])
def test_cleanup_failure_does_not_erase_application_or_terminal_evidence(tmp_path, client, monkeypatch, failure):
    engine = TerminalEngine(client.manifest, stop_error=failure == 'stop', remove_error=failure == 'remove')
    result, receipt, evidence = attempt(tmp_path, client, monkeypatch, engine, app_status=31)
    assert evidence is not None, 'cleanup failure must not erase captured facts'
    assert result.exit_code == 31 and receipt['app_returncode'] == 31
    assert result.cleanup_errors
    assert evidence['logs']['available'] is True
    assert evidence['stop_succeeded'] is (failure != 'stop')
    assert not any(stage['phase'] == 'post-health' for stage in receipt['stages'])


def test_docker_stop_refuses_unowned_identity_and_labels():
    engine = Docker()
    commands = []
    def command(args, *a, **kw):
        commands.append(args)
        return CommandResult(0, json.dumps([{'Id': 'owned', 'Config': {'Labels': {'run': 'other'}}}]), '')
    engine.command = command
    with pytest.raises(DockerError, match='ownership'):
        engine.stop('owned', {'run': 'mine'})
    assert all('stop' not in args for args in commands)


# Pure gate for the readiness self-SIGTERM: frames is any stack sequence of
# entries exposing .filename/.name (the mock passes traceback.extract_stack()).
# True only when the sleep originates from run_proxy's readiness-poll loop with
# no subprocess frame on the stack, so slow openssl waits during TLS setup
# delegate to the real sleep instead of killing the test process early.
def _should_interrupt_from(frames):
    from_run_proxy = False
    for frame in frames:
        filename = getattr(frame, 'filename', '') or ''
        name = getattr(frame, 'name', '') or ''
        if os.path.basename(filename) == 'subprocess.py':
            return False
        if name == 'run_proxy' and os.path.basename(filename) == 'run.py':
            from_run_proxy = True
    return from_run_proxy


def _frame(filename, name):
    return SimpleNamespace(filename=filename, name=name)


def test_sleep_gate_interrupts_from_readiness_loop():
    frames = [
        _frame('tests/test_proxy_terminal.py', 'test_startup_and_application_exception_keep_terminal_evidence'),
        _frame('src/p11lab/run.py', 'run_proxy'),
        _frame('tests/test_proxy_terminal.py', 'gated_sleep'),
    ]
    assert _should_interrupt_from(frames) is True


def test_sleep_gate_ignores_openssl_subprocess_wait():
    # Observed FAIL stack: run_proxy is live (TLS setup) but the sleep comes
    # from openssl's subprocess wait, so the self-SIGTERM must not fire.
    frames = [
        _frame('src/p11lab/run.py', 'run_proxy'),
        _frame('src/p11lab/tls.py', 'create_test_tls'),
        _frame('src/p11lab/tls.py', '_openssl'),
        _frame('/usr/lib/python3.14/subprocess.py', 'run'),
        _frame('/usr/lib/python3.14/subprocess.py', 'wait'),
        _frame('/usr/lib/python3.14/subprocess.py', '_wait'),
        _frame('tests/test_proxy_terminal.py', 'gated_sleep'),
    ]
    assert _should_interrupt_from(frames) is False


def test_sleep_gate_ignores_unrelated_sleep():
    frames = [
        _frame('/usr/lib/python3.14/threading.py', '_wait_for_tstate_lock'),
        _frame('/usr/lib/python3.14/threading.py', 'join'),
    ]
    assert _should_interrupt_from(frames) is False


@pytest.mark.parametrize('failure', ['start', 'readiness', 'application'])
def test_startup_and_application_exception_keep_terminal_evidence(tmp_path, client, monkeypatch, failure):
    engine = TerminalEngine(client.manifest, start_error=failure == 'start', startup_error=failure == 'readiness')
    if failure == 'readiness':
        # A single failed health attempt consumes the readiness deadline.
        # Stack-gated: interrupt only between readiness attempts, never from
        # subprocess waits (e.g. slow openssl during TLS setup).
        real_sleep = run.time.sleep
        def gated_sleep(seconds):
            if _should_interrupt_from(traceback.extract_stack()):
                os.kill(os.getpid(), signal.SIGTERM)
            else:
                real_sleep(seconds)
        monkeypatch.setattr(run.time, 'sleep', gated_sleep)
    result, receipt, evidence = attempt(tmp_path, client, monkeypatch, engine, app_error=failure == 'application')
    assert evidence is not None
    assert result.exit_code != 0
    assert receipt['app_returncode'] is None and receipt['app_completed'] is False
    assert evidence['logs']['available'] is True
    assert engine.events[-1] == 'remove'
    assert evidence['ready_observed'] is (failure == 'application')
    assert 'secret-test-' not in json.dumps(receipt)


@pytest.mark.parametrize('result', [CommandResult(0, '{', ''), CommandResult(0, '{}', ''),
                                   CommandResult(0, '{"Running":true,"ExitCode":0}', '', False, True),
                                   CommandResult(0, '{"Running":true,"ExitCode":0,"Error":{"key":"secret-test-pin"}}', '')])
def test_invalid_state_remains_unknown_and_cannot_pass(tmp_path, client, monkeypatch, result):
    engine = TerminalEngine(client.manifest, inspect_result=result)
    outcome, receipt, evidence = attempt(tmp_path, client, monkeypatch, engine)
    assert evidence is not None
    assert outcome.exit_code == 1
    assert evidence['before_stop']['available'] is False
    assert evidence['before_stop']['state'] is None
    assert evidence['unexpected_death'] is None
    assert 'daemon terminal evidence unavailable' in outcome.lifecycle_errors
    assert 'secret-test-' not in json.dumps(receipt)


def test_terminal_log_truncation_redacts_partial_credential(tmp_path, client, monkeypatch):
    engine = TerminalEngine(client.manifest, log_result=CommandResult(0, 'bounded secret-test-p', 'secret-test-so failure',
                                                                    False, True, False))
    outcome, receipt, evidence = attempt(tmp_path, client, monkeypatch, engine)
    assert evidence is not None and outcome.exit_code == 0
    assert evidence['logs']['stdout_truncated'] is True
    assert 'secret-test' not in (outcome.receipt_path.parent / 'daemon.stdout.log').read_text()
    assert '[REDACTED]' in (outcome.receipt_path.parent / 'daemon.stderr.log').read_text()


@pytest.mark.parametrize('inspected', [[], [{}], [{'Id': 'other', 'Config': {'Labels': {'run': 'mine'}}}]])
def test_docker_stop_rejects_missing_or_wrong_owned_identity(inspected):
    engine = Docker()
    engine.command = lambda *args, **kwargs: CommandResult(0, json.dumps(inspected), '')
    with pytest.raises(DockerError):
        engine.stop('owned', {'run': 'mine'})


def test_failed_inspect_retains_raw_diagnostic_status_and_unknown_state(tmp_path, client, monkeypatch):
    engine = TerminalEngine(client.manifest, inspect_result=CommandResult(42, '', 'private error', True, False, True))
    outcome, receipt, evidence = attempt(tmp_path, client, monkeypatch, engine)
    assert outcome.exit_code == 1
    assert evidence['before_stop']['returncode'] == 42
    assert evidence['before_stop']['timed_out'] is True
    assert evidence['before_stop']['stderr_truncated'] is True
    assert evidence['before_stop']['state'] is None
    assert evidence['before_stop']['signal']['observed'] is None


def test_log_exception_preserves_unknown_status_and_cleanup(tmp_path, client, monkeypatch):
    engine = TerminalEngine(client.manifest)
    original = engine.command
    def command(args, **kwargs):
        if args[0] == 'logs':
            raise OSError('secret-test-pin logs failed')
        return original(args, **kwargs)
    engine.command = command
    outcome, receipt, evidence = attempt(tmp_path, client, monkeypatch, engine, app_status=17)
    assert outcome.exit_code == 17
    assert evidence['logs']['available'] is False
    assert evidence['logs']['returncode'] is None
    assert evidence['logs']['timed_out'] is None
    assert evidence['logs']['error'] == 'daemon logs unavailable (OSError)'
    assert not outcome.cleanup_errors
    assert engine.events[-1] == 'remove'
    assert 'secret-test-' not in json.dumps(receipt)


def container_attempt(tmp_path, client, monkeypatch, engine, *, timeout_seconds=30):
    monkeypatch.setattr(run, 'Docker', lambda: engine)
    monkeypatch.setattr(run, '_create_proxy_network', lambda *args: 'fixture-network')
    selected = replace(spec(tmp_path, client), execution_location='container', consumer_artifact=IMAGE,
                       installed_prefix=None, timeout_seconds=timeout_seconds)
    outcome = run.run_application(selected)
    receipt = json.loads(outcome.receipt_path.read_text())
    return outcome, receipt, receipt['proxy'].get('daemon_terminal')


def test_container_application_timeout_captures_terminal_state_before_removal(tmp_path, client, monkeypatch):
    engine = TerminalEngine(client.manifest, consumer_timeout=True)
    outcome, receipt, evidence = container_attempt(tmp_path, client, monkeypatch, engine)
    assert evidence is not None, 'container timeout must capture before cleanup'
    assert outcome.exit_code == 124
    assert receipt['app_returncode'] == 124 and receipt['app_completed'] is False
    assert receipt['timeout'] is True
    assert receipt['interrupted_signal'] is None
    assert outcome.lifecycle_errors == ()
    assert evidence['after_stop']['state']['Running'] is False
    assert engine.events[-2:] == ['logs', 'remove']
    assert not engine.post_ran_while_live
    assert engine.consumer_saw_interrupted is True
    application = next(stage for stage in receipt['stages'] if stage['phase'] == 'application')
    assert application['timed_out'] is True
    for name in ('application.stdout.log', 'application.stderr.log'):
        text = (outcome.receipt_path.parent / name).read_text()
        assert '[REDACTED]' in text and 'secret-test-' not in text
    assert 'secret-test-' not in json.dumps(receipt)


def test_container_consumer_signal_maps_to_143_without_real_signal(tmp_path, client, monkeypatch):
    engine = TerminalEngine(client.manifest, consumer_signal=15)
    outcome, receipt, evidence = container_attempt(tmp_path, client, monkeypatch, engine)
    assert evidence is not None, 'signal-shaped consumer result must capture before cleanup'
    assert outcome.exit_code == 143
    assert receipt['app_returncode'] == 143 and receipt['app_completed'] is True
    assert receipt['timeout'] is False
    assert receipt['interrupted_signal'] is None
    assert outcome.lifecycle_errors == ()
    assert evidence['stop_requested'] is True and evidence['stop_succeeded'] is True
    assert evidence['unexpected_death'] is False
    assert evidence['after_stop']['state']['Running'] is False
    assert engine.events == ['inspect', 'stop', 'inspect', 'logs', 'remove']
    assert not engine.post_ran_while_live
    assert engine.consumer_saw_interrupted is True
    assert any(stage['phase'] == 'post-health' and stage['returncode'] == 0 for stage in receipt['stages'])
    for name in ('application.stdout.log', 'application.stderr.log'):
        text = (outcome.receipt_path.parent / name).read_text()
        assert '[REDACTED]' in text and 'secret-test-' not in text
    assert 'secret-test-' not in json.dumps(receipt)


def test_container_timeout_with_dead_daemon_keeps_124_and_death_fact(tmp_path, client, monkeypatch):
    engine = TerminalEngine(client.manifest, dead=True, consumer_timeout=True)
    outcome, receipt, evidence = container_attempt(tmp_path, client, monkeypatch, engine)
    assert outcome.exit_code == 124, 'app timeout code wins while daemon death coexists'
    assert receipt['app_returncode'] == 124 and receipt['app_completed'] is False
    assert receipt['timeout'] is True
    assert evidence['unexpected_death'] is True
    assert evidence['stop_requested'] is False
    assert evidence['logs']['available'] is True
    assert outcome.lifecycle_errors == ('daemon exited after readiness',)
    for name in ('application.stdout.log', 'application.stderr.log'):
        text = (outcome.receipt_path.parent / name).read_text()
        assert '[REDACTED]' in text and 'secret-test-' not in text
    assert 'secret-test-' not in json.dumps(receipt)


def test_container_application_zero_does_not_hide_dead_daemon(tmp_path, client, monkeypatch):
    engine = TerminalEngine(client.manifest, dead=True)
    monkeypatch.setattr(run, 'Docker', lambda: engine)
    monkeypatch.setattr(run, '_create_proxy_network', lambda *args: 'fixture-network')
    selected = replace(spec(tmp_path, client), execution_location='container', consumer_artifact=IMAGE,
                       installed_prefix=None, timeout_seconds=30)
    outcome = run.run_application(selected)
    receipt = json.loads(outcome.receipt_path.read_text())
    assert outcome.exit_code == 1 and receipt['app_returncode'] == 0
    assert receipt['proxy']['daemon_terminal']['unexpected_death'] is True
    assert any(stage['phase'] == 'post-health' and stage['returncode'] == 0 for stage in receipt['stages'])


def test_docker_stop_keeps_exact_owned_container_for_inspection():
    engine = Docker()
    calls = []
    def command(args, *a, **kwargs):
        calls.append((args, kwargs))
        if args[0] == 'container':
            return CommandResult(0, json.dumps([{'Id': 'owned', 'Config': {'Labels': {'run': 'mine'}}}]), '')
        return CommandResult(0, '', '')
    engine.command = command
    engine.stop('owned', {'run': 'mine'})
    assert calls == [(['container', 'inspect', 'owned'], {}), (['stop', '--time', '5', 'owned'], {'timeout': 10})]
