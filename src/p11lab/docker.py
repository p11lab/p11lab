"""Bounded Docker commands and deletion by inspected owned identity only."""
from dataclasses import dataclass
import json
import os
import signal
import subprocess
import threading
import time


class DockerError(ValueError):
    def __init__(self, message, *, resource=None, uncertain_resource=None):
        super().__init__(message)
        self.resource = resource
        self.uncertain_resource = uncertain_resource


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    stdout_truncated: bool = False
    stderr_truncated: bool = False


def capture(argv, timeout, *, limit=65536, interrupted=None, on_stop=None, env=None):
    """Continuously drain both pipes, retaining only a bounded prefix of each.

    Blocking-thread capture (deliberate): docker CLI invocations are short
    control calls whose pipes close on process exit, so two blocking reader
    threads and a 64 KiB prefix each suffice. Supervised application/checker
    processes use process.py's nonblocking capture instead: their pipes can
    outlive any deadline, so draining must be abortable, and app logs get a
    larger 1 MiB budget.
    """
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True, env=env)
    buffers = [bytearray(), bytearray()]
    totals = [0, 0]

    def drain(stream, index):
        while block := stream.read(8192):
            totals[index] += len(block)
            buffers[index].extend(block[:max(0, limit - len(buffers[index]))])
        stream.close()

    readers = [threading.Thread(target=drain, args=(stream, i), daemon=True)
               for i, stream in enumerate((process.stdout, process.stderr))]
    for reader in readers:
        reader.start()
    deadline = time.monotonic() + timeout
    timed_out = False
    try:
        while process.poll() is None:
            requested = interrupted() if interrupted else None
            if requested or time.monotonic() >= deadline:
                timed_out = not bool(requested)
                if on_stop:
                    on_stop(requested or signal.SIGTERM)
                try:
                    os.killpg(process.pid, requested or signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                break
            time.sleep(.02)
        process.wait(timeout=3)
    finally:
        # Reap descendants that hold a pipe open after the CLI exits.
        for reader in readers:
            reader.join(timeout=.2)
        if any(reader.is_alive() for reader in readers):
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            for reader in readers:
                reader.join(timeout=1)
        if process.poll() is None:
            process.kill()
            process.wait(timeout=3)
    return CommandResult(process.returncode, *(bytes(b).decode('utf-8', 'replace') for b in buffers),
                         timed_out, *(total > limit for total in totals))


class Docker:
    def __init__(self):
        # Docker control-plane configuration is explicit; application env never
        # inherits the host environment. No credential values go in argv/errors.
        self.env = {key: value for key, value in os.environ.items()
                    if key in {'PATH', 'HOME', 'DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_CONFIG',
                               'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH', 'XDG_RUNTIME_DIR'}}

    def command(self, args, timeout=15, *, check=True, **kwargs):
        result = capture(['docker', *args], timeout, env=self.env, **kwargs)
        if check and (result.returncode or result.timed_out or result.stdout_truncated):
            raise DockerError('Docker operation failed: ' + args[0])
        return result

    def image(self, artifact):
        context = self.env.get('DOCKER_CONTEXT')
        endpoint = self.env.get('DOCKER_HOST') if not context else None
        if not endpoint:
            args = ['context', 'inspect', *([context] if context else []),
                    '--format', '{{json .Endpoints.docker.Host}}']
            endpoint = json.loads(self.command(args).stdout)
        if not isinstance(endpoint, str) or not endpoint.startswith('unix://'):
            raise DockerError('direct/provider requires a same-host local Unix Docker daemon')
        observed = json.loads(self.command(['image', 'inspect', artifact.reference]).stdout)[0]
        if observed['Id'] != artifact.reference or observed['Os'] + '/' + observed['Architecture'] != artifact.platform:
            raise DockerError('local engine image identity/platform mismatch')
        return observed

    def _creation_failure(self, kind, name, labels):
        # A timed-out CLI can have created a resource. Read back the nonce name
        # once, then let the runner clean up only its verified exact identity.
        resource = None
        try:
            result = self.command([kind, 'inspect', name], timeout=5)
            inspected = json.loads(result.stdout)[0]
            actual = inspected.get('Config', {}).get('Labels', {}) if kind == 'container' else inspected.get('Labels', {})
            identity = inspected.get('Id') if kind == 'container' else inspected.get('Name')
            observed_name = inspected.get('Name', '').removeprefix('/')
            if observed_name == name and identity and all(actual.get(k) == v for k, v in labels.items()):
                resource = (kind, identity)
        except (DockerError, OSError, ValueError, IndexError, TypeError):
            pass
        return DockerError('Docker resource creation failed', resource=resource,
                           uncertain_resource=(kind, name) if resource is None else None)

    def volume(self, name, labels, state_dir):
        args = ['volume', 'create', '--name', name, '--driver', 'local',
                '--opt', 'type=none', '--opt', 'o=bind', '--opt', 'device=' + str(state_dir)]
        for key, value in labels.items():
            args.extend(['--label', key + '=' + value])
        try:
            result = self.command(args)
            if result.stdout.strip() != name:
                raise DockerError('unexpected created volume identity')
        except (DockerError, OSError) as error:
            raise self._creation_failure('volume', name, labels) from error
        return name

    def create(self, image, argv, options, labels, name):
        args = ['create', '--name', name]
        for key, value in labels.items():
            args.extend(['--label', key + '=' + value])
        try:
            result = self.command([*args, *options, image, *argv])
            identity = result.stdout.strip()
            if len(identity) != 64 or any(c not in '0123456789abcdef' for c in identity):
                raise DockerError('unexpected created container identity')
        except (DockerError, OSError) as error:
            raise self._creation_failure('container', name, labels) from error
        return identity

    def execute(self, identity, timeout, interrupted):
        def stop(signum):
            self.command(['kill', '--signal', signal.Signals(signum).name, identity], 5, check=False)
        attached = self.command(['start', '--attach', identity], timeout, check=False,
                                interrupted=interrupted, on_stop=stop)
        requested_signal = interrupted()
        if attached.timed_out or requested_signal:
            return CommandResult(124 if attached.timed_out else 128 + requested_signal, attached.stdout,
                                 attached.stderr, attached.timed_out,
                                 attached.stdout_truncated, attached.stderr_truncated)
        state = json.loads(self.command(['inspect', '--format', '{{json .State}}', identity]).stdout)
        if state['Running'] or state.get('Error') or attached.returncode and state['ExitCode'] == 0:
            raise DockerError('container status unavailable or still running')
        return CommandResult(state['ExitCode'], attached.stdout, attached.stderr, False,
                             attached.stdout_truncated, attached.stderr_truncated)

    def remove(self, kind, identity, labels):
        inspected = json.loads(self.command([kind, 'inspect', identity]).stdout)[0]
        actual = inspected.get('Config', {}).get('Labels', {}) if kind == 'container' else inspected.get('Labels', {})
        observed_id = inspected.get('Id') if kind == 'container' else inspected.get('Name')
        if observed_id != identity or any(actual.get(k) != v for k, v in labels.items()):
            raise DockerError('refusing deletion: ownership identity/labels mismatch')
        self.command([kind, 'rm', *(['--force'] if kind == 'container' else []), identity], 10)

    def stop(self, identity, labels):
        """Stop an exactly owned container, retaining it for terminal diagnostics."""
        try:
            inspected = json.loads(self.command(['container', 'inspect', identity]).stdout)[0]
            actual = inspected.get('Config', {}).get('Labels') or {}
            if not isinstance(actual, dict):
                raise ValueError('invalid container labels')
        except (ValueError, IndexError, TypeError, AttributeError) as error:
            raise DockerError('refusing stop: ownership inspection unavailable') from error
        if inspected.get('Id') != identity or any(actual.get(k) != v for k, v in labels.items()):
            raise DockerError('refusing stop: ownership identity/labels mismatch')
        self.command(['stop', '--time', '5', identity], timeout=10)
