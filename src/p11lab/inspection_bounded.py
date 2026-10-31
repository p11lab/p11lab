"""Supervised, size-limited inert Docker image inspection transfers."""
from dataclasses import asdict, dataclass
import os
import json
from pathlib import Path
import re
import selectors
import signal
import subprocess
import time
from uuid import uuid4

from .docker import Docker, DockerError
from .models import ArtifactRef
from .receipts import write_receipt


class InspectionError(ValueError):
    """Bounded inspection cannot establish complete inert observations."""


@dataclass(frozen=True)
class InspectionPolicy:
    max_bytes: int = 512 * 1024**2
    timeout_seconds: int = 120

    def validate(self):
        if (type(self.max_bytes) is not int or not 1 <= self.max_bytes <= 512 * 1024**2
                or type(self.timeout_seconds) is not int or not 1 <= self.timeout_seconds <= 120):
            raise InspectionError('invalid bounded inspection policy')


def bounded_stream(argv, destination, max_bytes, timeout, env, record):
    """Stream to an exclusive file, never writing more than max_bytes."""
    if max_bytes < 1 or timeout <= 0:
        raise InspectionError('invalid inspection stream limit')
    record.update({'bytes_written': 0, 'overflow': False, 'timed_out': False,
                   'returncode': None, 'stderr': '', 'stderr_truncated': False})
    process = None
    stderr = bytearray()
    total_stderr = 0
    failure = None
    with Path(destination).open('xb') as output:
        try:
            process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, env=env, start_new_session=True)
            with selectors.DefaultSelector() as selector:
                for stream, role in ((process.stdout, 'stdout'), (process.stderr, 'stderr')):
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, role)
                deadline = time.monotonic() + timeout
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        record['timed_out'] = True
                        failure = 'inspection stream deadline exceeded'
                        break
                    for key, _ in selector.select(min(remaining, .1)):
                        try:
                            block = os.read(key.fd, 65536)
                        except BlockingIOError:
                            continue
                        if not block:
                            selector.unregister(key.fileobj)
                            continue
                        if key.data == 'stdout':
                            available = max_bytes - record['bytes_written']
                            if len(block) > available:
                                if available:
                                    output.write(block[:available])
                                    record['bytes_written'] += available
                                record['overflow'] = True
                                failure = 'inspection stream byte limit exceeded'
                                break
                            output.write(block)
                            record['bytes_written'] += len(block)
                        else:
                            total_stderr += len(block)
                            stderr.extend(block[:max(0, 65536 - len(stderr))])
                            if total_stderr > 65536:
                                record['stderr_truncated'] = True
                                failure = 'inspection diagnostic limit exceeded'
                                break
                    if failure:
                        break
            if failure:
                raise InspectionError(failure)
            process.wait(timeout=max(.01, deadline - time.monotonic()))
            if process.returncode:
                raise InspectionError('inspection stream process failed')
        except subprocess.TimeoutExpired as error:
            record['timed_out'] = True
            raise InspectionError('inspection stream deadline exceeded') from error
        finally:
            if process is not None:
                if process.poll() is None or failure:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    record['reap_failed'] = True
                for stream in (process.stdout, process.stderr):
                    if stream:
                        stream.close()
                record['returncode'] = process.returncode
            record['stderr'] = stderr.decode('utf-8', 'replace')


class BoundedInspection:
    """Inert exact-image export/save with recoverable, nonce-owned cleanup."""
    def __init__(self, artifact: ArtifactRef, policy: InspectionPolicy, journal: Path, *, engine=None):
        from .bounded_run import require_nonroot
        require_nonroot()
        if type(policy) is not InspectionPolicy:
            raise InspectionError('typed bounded inspection policy required')
        policy.validate()
        if (artifact.kind != 'docker-local' or not re.fullmatch(r'sha256:[0-9a-f]{64}', artifact.reference)
                or artifact.sha256 != artifact.reference[7:] or artifact.platform != 'linux/amd64'):
            raise InspectionError('bounded inspection requires an exact local image')
        self.artifact, self.policy, self.journal = artifact, policy, Path(journal)
        if self.journal.exists() or self.journal.is_symlink() or not self.journal.parent.is_dir():
            raise InspectionError('bounded inspection journal must be fresh')
        self.engine = engine or Docker()
        nonce = uuid4().hex
        self.labels = {'org.p11lab.inspection': nonce}
        self.name = 'p11lab-inspect-' + nonce
        self.record = {'schema_version': 1, 'artifact': asdict(artifact), 'policy': asdict(policy),
                       'labels': self.labels, 'name': self.name, 'status': 'preflight',
                       'cleanup': {'status': 'not-created'}, 'transfers': {}}
        self._write()
        try:
            self.image = self.engine.image(artifact)
            if self.image.get('Id') != artifact.reference:
                raise InspectionError('bounded inspection image identity mismatch')
            if self.image.get('Config', {}).get('Volumes'):
                raise InspectionError('implicit image volumes are unsupported')
            self.record['image'] = self.image
            self.record['status'] = 'preflight-complete'
        except Exception:
            self.record['status'] = 'preflight-failed'
            self._write()
            raise
        self._write()

    def _write(self):
        write_receipt(self.journal, self.record)

    def _inspect_container(self, identity):
        try:
            observed = json.loads(self.engine.command(['container', 'inspect', identity]).stdout)[0]
        except (KeyError, IndexError, TypeError, ValueError) as error:
            raise InspectionError('inspection container identity unavailable') from error
        state = observed.get('State') or {}
        labels = observed.get('Config', {}).get('Labels') or {}
        if (observed.get('Id') != identity or observed.get('Image') != self.artifact.reference
                or state.get('Running') is not False or state.get('Pid') != 0
                or any(labels.get(k) != v for k, v in self.labels.items())):
            raise InspectionError('inspection container identity mismatch')
        return observed

    def export(self, destination: Path):
        identity = None
        error = None
        try:
            try:
                identity = self.engine.create(self.artifact.reference, ['/p11lab-inspection-not-executed'],
                                              ['--pull=never', '--network', 'none', '--read-only',
                                               '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges=true'],
                                              self.labels, self.name)
            except DockerError as failure:
                if failure.resource and failure.resource[0] == 'container':
                    identity = failure.resource[1]
                if failure.uncertain_resource:
                    self.record['cleanup'] = {'status': 'creation-uncertain',
                                              'uncertain_name': failure.uncertain_resource[1]}
                raise InspectionError('inspection container creation failed') from failure
            self.record['container_id'] = identity
            self.record['cleanup'] = {'status': 'pending', 'container_id': identity}
            self.record['inspection_before'] = self._inspect_container(identity)
            self._write()
            transfer = {}
            self.record['transfers']['export'] = transfer
            bounded_stream(['docker', 'export', identity], destination, self.policy.max_bytes,
                           self.policy.timeout_seconds, self.engine.env, transfer)
            self.record['inspection_after'] = self._inspect_container(identity)
        except BaseException as failure:
            error = failure
            self.record['status'] = 'export-failed'
        finally:
            if identity is not None:
                try:
                    self.engine.remove('container', identity, self.labels)
                    self.record['cleanup'] = {'status': 'removed-exact-owned-container', 'container_id': identity}
                except Exception as failure:
                    self.record['cleanup'] = {'status': 'failed', 'container_id': identity,
                                              'error_type': type(failure).__name__}
            self._write()
        if self.record['cleanup']['status'] == 'failed':
            raise InspectionError('inspection container cleanup failed') from error
        if error is not None:
            raise error
        self.record['status'] = 'export-complete'
        self._write()

    def save(self, destination: Path):
        try:
            if (self.record['status'] != 'export-complete'
                    or self.record['cleanup']['status'] != 'removed-exact-owned-container'):
                raise InspectionError('bounded inspection export or cleanup incomplete')
            observed = self.engine.image(self.artifact)
            if observed.get('Id') != self.image.get('Id') or observed.get('RootFS') != self.image.get('RootFS'):
                raise InspectionError('source image identity changed before save')
            transfer = {}
            self.record['transfers']['save'] = transfer
            bounded_stream(['docker', 'image', 'save', self.artifact.reference], destination,
                           self.policy.max_bytes, self.policy.timeout_seconds, self.engine.env, transfer)
            self.record['status'] = 'save-complete'
        except BaseException:
            self.record['status'] = 'save-failed'
            raise
        finally:
            self._write()

    def complete(self):
        if self.record['status'] != 'save-complete' or self.record['cleanup']['status'] != 'removed-exact-owned-container':
            raise InspectionError('bounded inspection evidence incomplete')
        self.record['status'] = 'complete'
        self._write()

    def fail(self, error):
        self.record['status'] = 'failed'
        self.record['error_type'] = type(error).__name__
        self._write()
