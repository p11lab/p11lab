"""Bounded direct-run storage and output readback primitives."""
import io
import hashlib
import json
import os
import tarfile
import tempfile
from pathlib import Path, PurePosixPath


TRUSTED_HOLDER = 'sha256:7792b1f7702a86946cd518db72b6a407302c3e9bc1635634368b878189e8221c'


class CredentialTaintError(ValueError):
    """A raw original contains a staged credential and is private only."""


class CaptureUnavailableError(RuntimeError):
    """A stage stream is unknown, so evidence cannot be exported."""


def fixed_validation_command(role, phase):
    """Return only the two fixed, public-argument local validation invocations."""
    if role not in ('checker', 'consumer') or phase not in ('init', 'ready', 'application', 'post-health'):
        raise ValueError('unsupported fixed validation role or stage')
    if phase == 'init':
        return ['init']
    if phase in ('ready', 'post-health'):
        return ['health']
    if role == 'checker':
        from .checker import load_profile
        return ['exec', '--', '/opt/p11lab-checker/bin/python', '-m', 'p11lab.checker', 'execute',
                json.dumps(load_profile()['nodes'], separators=(',', ':'))]
    return ['exec', '--', 'p11lab-smoke', '--module', '/usr/local/lib/p11lab/libsofthsm2.so',
            '--token-label', 'P11Lab', '--pin-file', '/run/p11lab-input/P11LAB_PIN_FILE',
            '--output', '/p11lab-output/crypto', '--key-mode', 'generated']


def fixed_validation_observation(config, role, phase, user, secrets):
    """Digest the inspected fixed command only after excluding staged credentials."""
    if (not isinstance(config, dict) or config.get('Cmd') != fixed_validation_command(role, phase)
            or not isinstance(user, str) or not user or config.get('User') != user
            or not isinstance(config.get('Entrypoint'), list) or not config['Entrypoint']
            or any(not isinstance(value, str) or not value for value in config['Entrypoint'])):
        raise ValueError('fixed validation command or user mismatch')
    values = [*config['Cmd'], *config['Entrypoint'], user]
    if any(secret and any(secret in value for value in values) for secret in secrets):
        raise CredentialTaintError('fixed validation command contains staged credential')
    raw = json.dumps({'command': config['Cmd'], 'entrypoint': config['Entrypoint'], 'user': user},
                     ensure_ascii=False, sort_keys=True, separators=(',', ':'))
    if any(secret and secret in raw for secret in secrets):
        raise CredentialTaintError('fixed validation command contains staged credential')
    encoded = raw.encode('utf-8')
    if len(encoded) > 16384:
        raise ValueError('fixed validation command exceeds byte bound')
    return {'role': role, 'phase': phase, 'user': user, 'command_sha256': hashlib.sha256(encoded).hexdigest()}


def require_nonroot():
    if os.getuid() == 0 or os.geteuid() == 0:
        raise ValueError('bounded execution requires a nonroot caller')


def check_tmpfs_stat(text, size):
    stat = text.split()
    try:
        if (len(stat) != 4 or stat[0] != 'tmpfs' or int(stat[1]) * int(stat[2]) > size
                or int(stat[1]) * int(stat[2]) < size - 65536 or int(stat[3]) != 10000):
            raise ValueError('actual tmpfs byte/inode quota mismatch')
        return {'type': stat[0], 'block_size': int(stat[1]), 'blocks': int(stat[2]), 'inodes': int(stat[3])}
    except (ValueError, IndexError) as error:
        raise ValueError('actual tmpfs byte/inode quota mismatch') from error


def validate_policy(policy, timeout):
    from .models import BoundedRunPolicy
    if type(policy) is not BoundedRunPolicy or policy.inodes != 10000:
        raise ValueError('invalid bounded policy')
    for value, maximum in ((policy.state_bytes, 256 * 1024**2),
                           (policy.output_bytes, 256 * 1024**2),
                           (policy.tmp_bytes, 256 * 1024**2),
                           (policy.run_bytes, 32 * 1024**2),
                           (policy.memory_bytes, 2 * 1024**3),
                           (policy.pids, 256)):
        if type(value) is not int or not 1 <= value <= maximum:
            raise ValueError('invalid bounded policy limit')
    if type(timeout) is not int or not 1 <= timeout <= 540:
        raise ValueError('invalid bounded execution deadline')


def open_storage(engine, labels, name, size, record):
    """Open the shared physically limited output primitive with an original holder."""
    from .models import ArtifactRef
    from .round_core.worker import _OutputVolume, _inspection
    require_nonroot()
    engine.image(ArtifactRef('docker-local', TRUSTED_HOLDER, TRUSTED_HOLDER[7:], 'linux/amd64'))
    storage = _OutputVolume(engine, TRUSTED_HOLDER, labels, name, size, record)
    try:
        storage.open()
        observed = _inspection(engine, storage.holder, labels)
        config, host = observed.get('Config') or {}, observed.get('HostConfig') or {}
        mounts = observed.get('Mounts') or []
        if (observed.get('Image') != TRUSTED_HOLDER or config.get('User') != '65532:65532'
                or config.get('Entrypoint') != ['/bin/sleep'] or host.get('ReadonlyRootfs') is not True
                or host.get('NetworkMode') != 'none' or host.get('Memory') != 16 * 1024**2
                or host.get('MemorySwap') != 16 * 1024**2 or host.get('PidsLimit') != 4
                or 'ALL' not in (host.get('CapDrop') or []) or host.get('CapAdd')
                or host.get('Privileged') or 'no-new-privileges=true' not in (host.get('SecurityOpt') or [])
                or len(mounts) != 1 or mounts[0].get('Name') != storage.volume
                or mounts[0].get('Destination') != '/out' or mounts[0].get('RW') is not False):
            raise ValueError('trusted holder boundary mismatch')
        options = ['--pull=never', '--user', '65532:65532', '--read-only', '--network', 'none',
                   '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges=true', '--pids-limit', '16',
                   '--memory', '64m', '--memory-swap', '64m', '--cpus', '1', '--log-driver', 'none',
                   '--mount', f'type=volume,src={storage.volume},dst=/out,readonly', '--entrypoint', '/usr/bin/stat']
        probe = None
        try:
            try:
                probe = engine.create(TRUSTED_HOLDER, ['-f', '-c', '%T %S %b %c', '/out'], options, labels, name + '-stat')
            except Exception as error:
                resource = getattr(error, 'resource', None)
                if resource and resource[0] == 'container':
                    probe = resource[1]
                if getattr(error, 'uncertain_resource', None):
                    record.setdefault('cleanup_errors', []).append('tmpfs probe creation status unknown')
                raise
            actual = _inspection(engine, probe, labels)
            record['kernel_probe'] = {'container_id': probe, 'inspection_before': actual}
            ph = actual.get('HostConfig') or {}
            pm = actual.get('Mounts') or []
            if (actual.get('Image') != TRUSTED_HOLDER or (actual.get('Config') or {}).get('User') != '65532:65532'
                    or ph.get('ReadonlyRootfs') is not True or ph.get('NetworkMode') != 'none'
                    or ph.get('Memory') != 64 * 1024**2 or ph.get('MemorySwap') != 64 * 1024**2
                    or ph.get('PidsLimit') != 16 or ph.get('NanoCpus') != 1_000_000_000
                    or ph.get('CapAdd') or 'ALL' not in (ph.get('CapDrop') or [])
                    or 'no-new-privileges=true' not in (ph.get('SecurityOpt') or [])
                    or ph.get('Privileged') or len(pm) != 1 or pm[0].get('Name') != storage.volume
                    or pm[0].get('Destination') != '/out' or pm[0].get('RW') is not False):
                raise ValueError('tmpfs probe boundary mismatch')
            result = engine.execute(probe, 20, lambda: None)
            record['kernel_probe'].update({'returncode': result.returncode, 'stdout': result.stdout,
                                           'stderr': result.stderr, 'timed_out': result.timed_out,
                                           'stdout_truncated': result.stdout_truncated,
                                           'stderr_truncated': result.stderr_truncated,
                                           'inspection_after': _inspection(engine, probe, labels)})
            if result.returncode or result.timed_out or result.stdout_truncated or result.stderr_truncated:
                raise ValueError('tmpfs probe failed')
            record['kernel_tmpfs'] = check_tmpfs_stat(result.stdout, size)
        finally:
            if probe:
                try:
                    engine.remove('container', probe, labels)
                    record.setdefault('kernel_probe', {'container_id': probe})['cleanup'] = 'removed-exact-owned-container'
                except Exception as error:
                    record.setdefault('cleanup_errors', []).append('tmpfs probe cleanup: ' + type(error).__name__)
                    raise
        return storage
    except BaseException:
        errors = storage.close()
        if record.get('uncertain_resource'):
            errors.append('bounded storage creation status unknown')
        if errors:
            record.setdefault('cleanup_errors', []).extend(errors)
        raise


def retain_scanned_output(raw, destination, max_bytes, max_inodes, secrets, record):
    """Keep untouched originals private if any staged credential appears."""
    variants = set()
    for value in secrets:
        if value:
            variants.add(value)
            if value.endswith(b'\n'):
                variants.add(value[:-1])
    if any(value and value in raw for value in variants):
        record['tainted'] = True
        # Ignore caller-controlled TMPDIR: it may name the shareable output tree.
        private = Path(tempfile.mkdtemp(prefix='p11lab-private-tainted-', dir='/tmp'))
        if private.resolve().is_relative_to(Path(destination).resolve()):
            private.rmdir()
            raise CredentialTaintError('private retention overlaps output; export blocked')
        private.chmod(0o700)
        original = private / 'original.tar'
        fd = os.open(original, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
        record['private_original'] = str(original)
        raise CredentialTaintError('candidate output contains staged credential; private original retained')
    record['tainted'] = False
    archive = Path(destination) / 'bounded-output.tar'
    with archive.open('xb') as output:
        output.write(raw)
    retain_output(raw, destination, max_bytes, max_inodes)


def read_output(storage, destination, interrupted, credentials):
    from .process import supervised_exec
    from .round_core.worker import _inspection
    holder = _inspection(storage.engine, storage.holder, storage.labels)
    if holder.get('State', {}).get('Running') is not True:
        raise ValueError('bounded output holder unavailable')
    status, timeout, owner, facts = supervised_exec(
        ['docker', 'cp', storage.holder + ':/out/.', '-'], cwd=destination,
        env=storage.engine.env, timeout=30, interrupted=interrupted,
        limit=storage.max_bytes + 16 * 1024**2)
    raw = bytes(owner.capture.buffers[0])
    storage.record['readback'] = {'returncode': status, 'timed_out': timeout,
                                  'sha256': hashlib.sha256(raw).hexdigest(),
                                  'size': len(raw), **facts}
    if (status or timeout or facts['stdout_truncated'] or facts['stderr_truncated']
            or facts['supervision_errors'] or facts['stragglers_remaining'] or not facts['drain_complete']):
        raise ValueError('bounded output readback failed')
    retain_scanned_output(raw, destination, storage.max_bytes, 10000,
                          list(credentials.values()), storage.record['readback'])


def verify_container(observed, identity, image, labels, policy, user, expected_mounts, argv, entrypoint):
    """Reject any actual Docker boundary drift before starting a payload."""
    config = observed.get('Config') or {}
    host = observed.get('HostConfig') or {}
    state = observed.get('State') or {}
    actual_mounts = []
    for mount in observed.get('Mounts') or []:
        actual_mounts.append((mount.get('Type'), mount.get('Destination'),
                              mount.get('Name') if mount.get('Type') == 'volume' else mount.get('Source'),
                              mount.get('RW')))
    if (observed.get('Id') != identity or observed.get('Image') != image
            or state.get('Running') is not False or state.get('Pid') != 0
            or config.get('Cmd') != argv or config.get('Entrypoint') != entrypoint
            or config.get('User') != user
            or any((config.get('Labels') or {}).get(k) != v for k, v in labels.items())
            or host.get('Memory') != policy.memory_bytes or host.get('MemorySwap') != policy.memory_bytes
            or host.get('PidsLimit') != policy.pids or host.get('NanoCpus') != 1_000_000_000
            or host.get('ReadonlyRootfs') is not True or host.get('NetworkMode') != 'none'
            or 'ALL' not in (host.get('CapDrop') or []) or host.get('CapAdd')
            or not any(s in ('no-new-privileges', 'no-new-privileges=true') for s in (host.get('SecurityOpt') or []))
            or host.get('Privileged') or host.get('PidMode') not in ('', 'private')
            or host.get('IpcMode') != 'private' or host.get('Devices') or host.get('VolumesFrom')
            or sorted(actual_mounts) != sorted(expected_mounts)):
        raise ValueError('actual container boundary mismatch')
    expected_tmpfs = {
        '/tmp': f'rw,nosuid,nodev,size={policy.tmp_bytes},nr_inodes={policy.inodes}',
        '/dev/shm': f'rw,nosuid,nodev,size={policy.run_bytes},nr_inodes={policy.inodes},mode=1777',
        '/run/p11lab': f'rw,nosuid,nodev,uid={user.split(":")[0]},gid={user.split(":")[1]},mode=0700,size={policy.run_bytes},nr_inodes={policy.inodes}',
    }
    if host.get('Tmpfs') != expected_tmpfs:
        raise ValueError('actual container boundary tmpfs mismatch')


def retain_output(raw: bytes, destination: Path, max_bytes: int, max_inodes: int) -> None:
    """Validate the whole stopped producer tar before retaining exclusive files."""
    if len(raw) > max_bytes + 16 * 1024 * 1024:
        raise ValueError('bounded output archive exceeds limit')
    entries = []
    seen = set()
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
            for member in archive:
                if member.name in ('.', './') and member.isdir():
                    continue
                name = member.name.removeprefix('./').removesuffix('/')
                path = PurePosixPath(name)
                if (not name or name.startswith('/') or '\\' in name or '\0' in name
                        or any(p in ('', '.', '..') for p in name.split('/'))
                        or len(path.parts) > 32 or len(name) > 4096
                        or name in seen or len(seen) >= max_inodes):
                    raise ValueError('unsafe or duplicate bounded output path')
                seen.add(name)
                if not (member.isdir() or member.isfile()) or member.mode & 0o7000:
                    raise ValueError('unsafe bounded output type or mode')
                total += member.size
                if total > max_bytes or member.size < 0:
                    raise ValueError('bounded output exceeds byte limit')
                contents = b''
                if member.isfile():
                    stream = archive.extractfile(member)
                    if stream is None:
                        raise ValueError('missing bounded output content')
                    contents = stream.read(max_bytes + 1)
                    if len(contents) != member.size:
                        raise ValueError('bounded output content size mismatch')
                entries.append((path, member.isdir(), contents))
    except (tarfile.TarError, OSError) as error:
        raise ValueError('invalid bounded output archive') from error
    destination = Path(destination)
    if destination.is_symlink() or not destination.is_dir():
        raise ValueError('unsafe bounded output destination')
    for path, directory, _ in entries:
        target = destination.joinpath(*path.parts)
        for parent in (target, *target.parents):
            if parent == destination:
                break
            if parent.is_symlink() or (parent.exists() and (parent == target or not parent.is_dir())):
                raise ValueError('bounded output collision')
    for path, directory, data in sorted(entries, key=lambda x: len(x[0].parts)):
        target = destination.joinpath(*path.parts)
        if directory:
            target.mkdir(mode=0o700, parents=True, exist_ok=True)
        else:
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with target.open('xb') as stream:
                stream.write(data)
