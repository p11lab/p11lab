"""Quota-enforced fixed-tool installation in a bounded rootfs, never an overlay.

The only added capability is SYS_CHROOT in the trusted launcher. Effective,
permitted and inheritable capabilities are dropped and checked across exec before
package or wheel code runs. The outer root is always read-only.
"""
from __future__ import annotations

import io
import json
import os
import select
from pathlib import Path
import subprocess
import tarfile
import time
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from .docker import DockerError

if TYPE_CHECKING:
    from .tool_builds import _Attempt

JsonObject = dict[str, Any]
ROOTFS_BYTES = 768 * 1024**2
ROOTFS_INODES = 32768
SCRATCH_INODES = 16384


def bounded_install_policy() -> JsonObject:
    return {'schema_version': 2, 'kind': 'bounded-tmpfs-chroot-v1',
            'rootfs_bytes': ROOTFS_BYTES, 'rootfs_inodes': ROOTFS_INODES,
            'outer_root': 'read-only', 'setup_capabilities': ['SYS_CHROOT'],
            'payload_capabilities': 'zero-effective-permitted-inheritable',
            'no_new_privileges': True, 'scratch_bytes': 512 * 1024**2,
            'scratch_inodes': SCRATCH_INODES,
            'producer_output_bytes': 16 * 1024**2, 'producer_output_inodes': 10000}


def _transfer(attempt: _Attempt, argv: list[str], name: str, *, source: Path | None = None,
              destination: Path | None = None) -> None:
    """Bound trusted daemon tar transfer in bytes/time; never extract on the host."""
    from .tool_builds import MAX_EXPORT, ToolBuildError, _expect
    log = attempt.output / (name + '-transfer.stderr')
    record: JsonObject = {'argv': argv, 'source': str(source) if source else None,
                          'destination': str(destination) if destination else None}
    attempt.result.setdefault('rootfs_transfers', []).append(record)
    with log.open('xb') as errors:
        incoming = source.open('rb') if source else subprocess.DEVNULL
        outgoing = destination.open('xb') if destination else subprocess.DEVNULL
        try:
            process = subprocess.Popen(argv, stdin=incoming, stdout=outgoing, stderr=subprocess.PIPE,
                                       env=attempt.engine.env, start_new_session=True)
            started = time.monotonic()
            assert process.stderr is not None
            os.set_blocking(process.stderr.fileno(), False)
            total, retained, eof = 0, 0, False
            failed = None
            try:
                while process.poll() is None or not eof:
                    if (time.monotonic() - started > 120 or
                            destination is not None and destination.stat().st_size > MAX_EXPORT):
                        failed = 'rootfs transfer time/byte bound'
                        break
                    if not eof and select.select([process.stderr], [], [], .05)[0]:
                        block = os.read(process.stderr.fileno(), 8192)
                        if not block:
                            eof = True
                        else:
                            total += len(block)
                            prefix = block[:max(0, 65536 - retained)]
                            errors.write(prefix)
                            retained += len(prefix)
                            if total > 65536:
                                failed = 'rootfs transfer native log bound'
                                break
                    elif eof:
                        time.sleep(.02)
                if failed:
                    raise ToolBuildError(failed)
                _expect(process.returncode == 0, 'rootfs transfer failed; see native stderr')
            finally:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=5)
                process.stderr.close()
                record['returncode'] = process.returncode
                record['stderr_bytes_seen'] = total
                record['stderr_bytes_retained'] = retained
                record['stderr_truncated'] = total > retained
        finally:
            if source:
                incoming.close()  # type: ignore[union-attr]
            if destination:
                outgoing.close()  # type: ignore[union-attr]
    _expect(log.stat().st_size <= 65536, 'rootfs transfer log bound')
    if destination:
        _expect(destination.stat().st_size <= MAX_EXPORT, 'rootfs transfer output bound')


def _devices(path: Path) -> None:
    """Standard container null/zero/random devices, never host device mounts."""
    with tarfile.open(path, 'w') as archive:
        for name, minor in [('null', 3), ('zero', 5), ('random', 8), ('urandom', 9)]:
            member = tarfile.TarInfo('dev/' + name)
            member.type = tarfile.CHRTYPE
            member.mode = 0o666
            member.devmajor, member.devminor = 1, minor
            archive.addfile(member, io.BytesIO())


def install_bounded_rootfs(attempt: _Attempt, image: str, argv: list[str], *,
                           staged: Path, environment: dict[str, str], name: str,
                           rootfs_bytes: int = ROOTFS_BYTES,
                           rootfs_inodes: int = ROOTFS_INODES) -> tuple[JsonObject, JsonObject, str]:
    """Run one fixed install, stop it, independently read back, then import bytes.

    Smaller quotas are exposed only for explicit safe exhaustion controls. There
    is no storage-driver quota option and no writable-overlay fallback.
    """
    from .tool_builds import (_archive_inventory, _expect, _file, _options, _write, _write_launcher,
                             verify_execution_boundary)
    _expect(0 < rootfs_bytes <= ROOTFS_BYTES and 0 < rootfs_inodes <= ROOTFS_INODES,
            'unsupported bounded rootfs quota')
    trusted_image = attempt.result['base']['engine_id']
    record: JsonObject = {'policy': bounded_install_policy(), 'source_image': image, 'setup_image': trusted_image,
                          'bytes': rootfs_bytes, 'inodes': rootfs_inodes}
    attempt.result.setdefault('bounded_installations', []).append(record)
    initial = set(attempt.containers)
    volume = 'p11lab-rootfs-' + uuid4().hex
    owned_volume = False
    try:
        # Snapshot is from a stopped readonly container; no untrusted output can
        # grow the daemon overlay during this operation.
        snapshot = attempt.run(image, ['/bin/true'])
        parent_inventory = attempt.export(snapshot, name + '-parent')
        parent = attempt.output / (name + '-parent.tar')
        record['parent_archive'] = _file(parent)
        record['parent_regular_bytes'] = parent_inventory['regular_bytes']
        options = {'type': 'tmpfs', 'device': 'tmpfs',
                   'o': f'size={rootfs_bytes},nr_inodes={rootfs_inodes},mode=0755,uid=0,gid=0'}
        args = ['volume', 'create', '--name', volume, '--driver', 'local']
        for key, value in attempt.labels.items():
            args += ['--label', key + '=' + value]
        for key, value in options.items():
            args += ['--opt', key + '=' + value]
        try:
            _expect(attempt.engine.command(args).stdout.strip() == volume, 'unexpected rootfs volume identity')
            owned_volume = True
        except DockerError as error:
            if error.resource and error.resource == ('volume', volume):
                owned_volume = True
            # Creation can have succeeded despite a failed CLI; inspect only our nonce.
            observed = attempt.engine.command(['volume', 'inspect', volume], check=False)
            if observed.returncode == 0:
                found = json.loads(observed.stdout)[0]
                owned_volume = found.get('Name') == volume and found.get('Labels') == attempt.labels
            raise
        inspection = json.loads(attempt.engine.command(['volume', 'inspect', volume]).stdout)[0]
        record['volume_inspection'] = inspection
        _expect(inspection.get('Name') == volume and inspection.get('Driver') == 'local' and
                inspection.get('Options') == options and inspection.get('Labels') == attempt.labels,
                'actual rootfs volume quota/ownership mismatch')
        # Trusted sleeper owns no setup capability. Daemon copying preserves the
        # base tree's ownership/modes directly inside the quota-limited volume.
        holder_name = volume + '-holder'
        mounts = [f'type=volume,src={volume},dst=/rootfs']
        holder_options = _options(readonly=True)
        holder_options += ['--mount', mounts[0]]
        command = ['-i', 'PATH=/usr/bin:/bin', 'LC_ALL=C', '/bin/sleep', '900']
        try:
            holder = attempt.engine.create(trusted_image, command, holder_options, attempt.labels, holder_name)
        except DockerError as error:
            if error.resource and error.resource[0] == 'container':
                attempt.containers.append(error.resource[1])
            raise
        attempt.containers.append(holder)
        observed = json.loads(attempt.engine.command(['container', 'inspect', holder]).stdout)[0]
        verify_execution_boundary(observed, trusted_image, command, mounts, readonly=True, user='0:0')
        record['holder_inspection'] = observed
        attempt.engine.command(['start', holder])
        _transfer(attempt, ['docker', 'cp', '-a', '-', holder + ':/rootfs'], name + '-seed', source=parent)
        devices = attempt.output / (name + '-devices.tar')
        _devices(devices)
        _transfer(attempt, ['docker', 'cp', '-a', '-', holder + ':/rootfs'], name + '-devices', source=devices)
        launcher = attempt.output / (name + '-launch.pl')
        _write_launcher(launcher)
        payload = ['/usr/bin/env', '-i'] + [k + '=' + v for k, v in environment.items()] + argv
        container = attempt.run(trusted_image, ['/usr/bin/perl', '/launcher.pl', '/rootfs',
                                        str(rootfs_bytes), str(rootfs_inodes), *payload],
                                mounts=[f'type=volume,src={volume},dst=/rootfs',
                                        f'type=bind,src={staged},dst=/rootfs/inputs,readonly',
                                        f'type=bind,src={launcher},dst=/launcher.pl,readonly'],
                                rootfs_setup=True)
        record['payload_container'] = container
        native = attempt.result['stages'][-1]['native']['stdout']
        _expect('P11LAB_BOUNDED_ROOTFS_CAPS_ZERO_NNP_ONE\n' in native,
                'missing actual capability-drop/NNP gate')
        record['payload_capabilities_observed'] = 'zero-effective-permitted-inheritable'
        record['payload_no_new_privileges'] = 1
        stopped = json.loads(attempt.engine.command(['container', 'inspect', container]).stdout)[0]
        _expect(not stopped['State']['Running'], 'bounded rootfs payload not stopped')
        readback = attempt.output / (name + '-filesystem.tar')
        _transfer(attempt, ['docker', 'cp', holder + ':/rootfs/.', '-'], name + '-readback', destination=readback)
        inventory = _archive_inventory(readback)
        _write(attempt.output / (name + '-filesystem.json'), inventory)
        record['readback_archive'] = _file(readback)
        # Import is a stopped bounded byte transformation; no project executes in
        # the daemon image store. The flattened relationship is explicit.
        changes = ['--change', 'ENTRYPOINT []', '--change', 'CMD []', '--change',
                   'LABEL org.p11lab.admission=unreviewed-local-tool-only']
        for key, value in attempt.labels.items():
            changes += ['--change', 'LABEL ' + key + '=' + value]
        identity = attempt.engine.command(['image', 'import', '--platform', 'linux/amd64',
                                           *changes, str(readback)], timeout=120).stdout.strip()
        _expect(identity.startswith('sha256:') and len(identity) == 71, 'invalid imported rootfs identity')
        attempt.images.append(identity)
        info = json.loads(attempt.engine.command(['image', 'inspect', identity]).stdout)[0]
        _expect(info['Id'] == identity and info['Os'] == 'linux' and info['Architecture'] == 'amd64',
                'imported bounded rootfs image identity/platform mismatch')
        product = {'engine_id': identity, 'config_sha256': identity.removeprefix('sha256:'),
                   'layers': info['RootFS']['Layers'], 'size': info['Size'], 'inspection': info,
                   'composition': 'flattened-bounded-rootfs-import', 'parent_engine_id': image,
                   'rootfs_archive': record['readback_archive'], 'bounded_policy': bounded_install_policy()}
        return product, inventory, native
    finally:
        for identity in list(attempt.containers):
            if identity not in initial:
                try:
                    attempt.engine.remove('container', identity, attempt.labels)
                    attempt.containers.remove(identity)
                except Exception as error:
                    attempt.result['cleanup_errors'].append('bounded rootfs container: ' + str(error))
        if owned_volume:
            try:
                attempt.engine.remove('volume', volume, attempt.labels)
                record['cleanup'] = 'exact-owned-containers-and-volume-removed'
            except Exception as error:
                attempt.result['cleanup_errors'].append('bounded rootfs volume: ' + str(error))
