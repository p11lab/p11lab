"""Offline fixed-tool production. These local observations grant no distribution rights.

Only installed input authority selects packages/source. Project backends run in a
separate non-root, networkless, read-only container with a hard limited output.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import shutil
import struct
import subprocess
import tarfile
import time
from typing import Any, Callable, Protocol, cast
from uuid import uuid4
import zipfile

from .catalog import package_data
from .docker import CommandResult, Docker, DockerError
from .models import ArtifactRef
from .tool_downloads import safe_directory
from .tool_inputs import load_tool_input_lock, verify_resolved_tool_inputs, _read_regular as _untyped_read_regular
from .round_core.worker import _OutputVolume
from .tool_rootfs import bounded_install_policy, install_bounded_rootfs


JsonObject = dict[str, Any]


class _ReadRegular(Protocol):
    def __call__(self, path: Path, *, maximum: int) -> bytes: ...


class _Engine(Protocol):
    env: dict[str, str]

    def command(self, args: list[str], timeout: int = 15, *, check: bool = True,
                **kwargs: Any) -> CommandResult: ...
    def create(self, image: str, argv: list[str], options: list[str],
               labels: dict[str, str], name: str) -> str: ...
    def execute(self, identity: str, timeout: int,
                interrupted: Callable[[], int | None]) -> CommandResult: ...
    def remove(self, kind: str, identity: str, labels: dict[str, str]) -> None: ...
    def image(self, artifact: ArtifactRef) -> JsonObject: ...


# Typed views of existing shared primitives, without changing their behavior.
_read_regular = cast(_ReadRegular, _untyped_read_regular)
_new_docker = cast(Callable[[], Docker], Docker)

TARGET = 'debian13-amd64'
MAX_EXPORT = 1024 * 1024**2
PACKAGE_QUERY = "${Package}\\t${Version}\\t${Architecture}\\t${source:Package}\\t${source:Version}\\n"


class ToolBuildError(ValueError):
    """The actual tool closure could not be established; partial evidence is retained."""


@dataclass(frozen=True)
class ToolBuildRequest:
    toolset: str
    receipt_path: Path
    output_dir: Path


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def _file(path: Path) -> JsonObject:
    raw = _read_regular(path, maximum=MAX_EXPORT)
    return {'sha256': _sha(raw), 'size': len(raw)}


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise ToolBuildError(message)


def select_packages(lock: JsonObject, stage: str) -> list[JsonObject]:
    """Select only new archives for one frozen stage, preserving the base inventory."""
    wanted = set(lock['stages'][stage]['packages'])
    return [p for p in lock['packages'] if p['name'] in wanted]


def verify_package_inventory(lock: JsonObject, stage: str, actual: str) -> list[JsonObject]:
    """Compare all five observed identity fields to installed authority, including parent."""
    keys = ('name', 'version', 'architecture', 'source_package', 'source_version')
    authoritative = {p['name']: {k: p[k] for k in keys}
                     for p in lock['parent_packages'] + lock['packages']}
    expected = [authoritative[n] for n in sorted(lock['stages'][stage]['packages'])]
    observed = []
    for line in actual.splitlines():
        fields = line.split('\t')
        _expect(len(fields) == 5, 'malformed actual package inventory')
        observed.append(dict(zip(keys, fields)))
    _expect(sorted(observed, key=lambda p: p['name']) == expected,
            'actual package inventory differs from selected stage')
    return expected


def check_checker_output(wheel: Path) -> JsonObject:
    """Observe real output, retaining a mismatch without installing/relabeling it."""
    expected = load_tool_input_lock('checker', target=TARGET)['execution']['expected_outputs'][0]
    actual = _file(wheel)
    matched = all(actual[k] == expected[k] for k in ('sha256', 'size'))
    return {'expected': expected, 'observed': actual,
            'status': 'reproduced' if matched else 'blocked-output-mismatch'}


def inspect_elf(raw: bytes) -> JsonObject:
    """Read ELF64 little-endian amd64 interpreter/DT_NEEDED without executing it."""
    try:
        _expect(len(raw) >= 64 and raw[:7] == b'\x7fELF\x02\x01\x01', 'unsupported/truncated ELF')
        header = struct.unpack_from('<HHIQQQIHHHHHH', raw, 16)
        _expect(header[1] == 62 and (header[8] == 56 or header[9] == header[8] == 0) and header[9] <= 256, 'unsupported ELF headers')
        offset, count = header[4], header[9]
        _expect(offset + count * 56 <= len(raw), 'truncated ELF program headers')
        programs = [struct.unpack_from('<IIQQQQQQ', raw, offset + i * 56) for i in range(count)]
        for p in programs:
            _expect(p[2] + p[5] <= len(raw), 'truncated ELF segment')
        interpreter = None
        for p in programs:
            if p[0] == 3:
                value = raw[p[2]:p[2] + p[5]]
                _expect(value.endswith(b'\0') and len(value) <= 256, 'invalid ELF interpreter')
                interpreter = value[:-1].decode('ascii')
        dynamic = []
        for p in programs:
            if p[0] == 2:
                _expect(p[5] % 16 == 0, 'invalid ELF dynamic table')
                for pos in range(p[2], p[2] + p[5], 16):
                    tag, value = struct.unpack_from('<QQ', raw, pos)
                    if tag == 0:
                        break
                    dynamic.append((tag, value))
        strtab = next((v for t, v in dynamic if t == 5), None)
        needed, soname, search = [], None, []
        if strtab is not None:
            segment = next((p for p in programs if p[0] == 1 and p[3] <= strtab < p[3] + p[5]), None)
            if segment is None:
                raise ToolBuildError('ELF string table outside file')
            start = segment[2] + strtab - segment[3]
            for tag, value in dynamic:
                if tag in (1, 14, 15, 29):
                    end = raw.find(b'\0', start + value, min(len(raw), start + value + 4096))
                    _expect(end >= start + value, 'invalid ELF dynamic string')
                    text = raw[start + value:end].decode('ascii')
                    if tag == 1:
                        needed.append(text)
                    elif tag == 14:
                        soname = text
                    else:
                        search.append(text)
        return {'elf_type': header[0], 'interpreter': interpreter, 'needed': needed, 'soname': soname, 'search_paths': search}
    except (struct.error, UnicodeError, StopIteration) as exc:
        raise ToolBuildError('malformed ELF') from exc


def _safe_member(name: str) -> str:
    path = PurePosixPath(name.removeprefix('./'))
    _expect(not path.is_absolute() and '..' not in path.parts and str(path) not in ('', '.'),
            'unsafe archive member')
    return str(path)


def _archive_inventory(path: Path) -> JsonObject:
    """Independent stopped-filesystem readback; never extract image-controlled paths."""
    files: JsonObject = {}
    aliases: JsonObject = {}
    elfs: JsonObject = {}
    total = 0
    with tarfile.open(path, 'r|') as archive:
        for member in archive:
            if member.isdir() and member.name in ('.', './'):
                continue
            name = _safe_member(member.name)
            _expect(name not in files and name not in aliases, 'duplicate filesystem member')
            _expect(len(files) + len(aliases) < 100000, 'filesystem roster exceeds bound')
            if member.isfile():
                total += member.size
                _expect(total <= MAX_EXPORT and member.size <= 128 * 1024**2, 'filesystem byte bound')
                stream = archive.extractfile(member)
                if stream is None:
                    raise ToolBuildError('missing filesystem member')
                raw = stream.read(member.size + 1)
                _expect(len(raw) == member.size, 'filesystem member size mismatch')
                files[name] = {'size': len(raw), 'sha256': _sha(raw), 'mode': member.mode}
                if raw.startswith(b'\x7fELF'):
                    elfs[name] = inspect_elf(raw)
            elif member.issym() or member.islnk():
                aliases[name] = {'target': member.linkname, 'kind': 'symlink' if member.issym() else 'hardlink'}
            elif not member.isdir():
                # Docker exports standard /dev placeholders on some engines.
                _expect(name.startswith('dev/'), 'unexpected special filesystem member')
    return {'files': files, 'aliases': aliases, 'elfs': elfs, 'regular_bytes': total}


def _resolve(name: str, inventory: JsonObject) -> str:
    parts = list(PurePosixPath(name.lstrip('/')).parts)
    for _ in range(40):
        for i in range(1, len(parts) + 1):
            prefix = '/'.join(parts[:i])
            if prefix in inventory['aliases']:
                record = inventory['aliases'][prefix]
                target = record['target']
                base = [] if target.startswith('/') or record['kind'] == 'hardlink' else parts[:i - 1]
                pieces = base + list(PurePosixPath(target).parts) + parts[i:]
                result: list[str] = []
                for piece in pieces:
                    if piece in ('/', '.', ''):
                        continue
                    if piece == '..':
                        _expect(bool(result), 'escaping filesystem alias')
                        result.pop()
                    else:
                        result.append(piece)
                parts = result
                break
        else:
            return '/'.join(parts)
    raise ToolBuildError('filesystem alias cycle')


def _elf_closure(inventory: JsonObject, roots: list[str]) -> JsonObject:
    closure, pending = {}, [_resolve(p, inventory) for p in roots]
    while pending:
        name = pending.pop()
        if name in closure:
            continue
        _expect(name in inventory['elfs'], 'missing actual ELF: ' + name)
        meta = inventory['elfs'][name]
        dependencies = []
        if meta['interpreter']:
            dependencies.append(_resolve(meta['interpreter'], inventory))
        _expect(not meta['search_paths'], 'ELF RPATH/RUNPATH requires explicit loader review')
        for needed in meta['needed']:
            _expect('/' not in needed, 'unsafe ELF needed name')
            found = None
            for directory in ('lib/x86_64-linux-gnu', 'usr/lib/x86_64-linux-gnu', 'lib64', 'usr/lib64'):
                candidate = _resolve(directory + '/' + needed, inventory)
                if candidate in inventory['elfs']:
                    found = candidate
                    break
            if found is None:
                raise ToolBuildError('unresolved ELF dependency: ' + needed)
            dependencies.append(found)
        closure[name] = {**inventory['files'][name], **meta, 'resolved_dependencies': dependencies}
        pending += dependencies
    return closure


def _prepare_public_stage(root: Path) -> None:
    # Only call for fresh, owned input trees; never for the source/cache tree.
    import stat
    _expect(root.is_dir() and not root.is_symlink(), 'unsafe public stage root')
    paths = [root, *sorted(root.rglob('*'))]
    modes = []
    for path in paths:
        mode = path.lstat().st_mode
        _expect(stat.S_ISDIR(mode) or stat.S_ISREG(mode), 'unsafe public stage entry')
        modes.append((path, 0o755 if stat.S_ISDIR(mode) or mode & 0o111 else 0o644))
    for path, mode in modes:
        path.chmod(mode)


def _write_launcher(path: Path) -> None:
    path.write_bytes(package_data('tool-builds/rootfs-launch.pl').read_bytes())
    path.chmod(0o644)


def _copy_checked(source: Path, destination: Path, spec: JsonObject) -> None:
    raw = _read_regular(source, maximum=spec['size'])
    _expect(len(raw) == spec['size'] and _sha(raw) == spec['sha256'], 'input changed during staging')
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(raw)
    destination.chmod(0o644)


def _source(lock: JsonObject, inputs: Path, staged: Path) -> None:
    spec = lock['checker_source']
    manifest = json.loads(package_data(spec['manifest_asset']).read_bytes())
    expected = {p['path']: p for p in manifest['files']}
    seen = set()
    with tarfile.open(inputs / spec['path'], 'r:gz') as archive:
        for member in archive:
            if member.isdir():
                continue
            parts = PurePosixPath(member.name).parts
            name = _safe_member('/'.join(parts[1:]))
            _expect(member.isfile() and name in expected and name not in seen, 'source roster/type changed')
            p = expected[name]
            stream = archive.extractfile(member)
            if stream is None:
                raise ToolBuildError('missing source member')
            raw = stream.read(p['size'] + 1)
            _expect(len(raw) == p['size'] and _sha(raw) == p['sha256'], 'source member changed')
            path = staged / 'source' / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            path.chmod(0o755 if p['mode'] == '100755' else 0o644)
            seen.add(name)
    _expect(seen == set(expected), 'incomplete source roster')


def _options(*, readonly: bool, user: str = '0:0', rootfs_setup: bool = False) -> list[str]:
    _expect(readonly, 'writable overlay is unsupported; use bounded rootfs installation')
    _expect(not rootfs_setup or user == '0:0', 'bounded rootfs setup requires its fixed trusted user')
    result = ['--pull=never', '--network', 'none', '--ipc', 'private', '--cap-drop', 'ALL',
              '--security-opt', 'no-new-privileges=true', '--pids-limit', '128', '--memory', '1g',
              '--memory-swap', '1g', '--cpus', '1', '--log-driver', 'none', '--user', user,
              '--ulimit', 'nofile=256:256', '--ulimit', 'fsize=268435456:268435456',
              '--tmpfs', '/tmp:rw,nosuid,nodev,size=536870912,nr_inodes=16384,mode=1777', '--entrypoint', '/usr/bin/env']
    if rootfs_setup:
        result += ['--cap-add', 'SYS_CHROOT']
    if readonly:
        result.append('--read-only')
    return result


def context_identity(root: Path) -> JsonObject:
    """Seal actual staged read-only bytes before native execution, excluding no files."""
    _expect(not root.is_symlink(), 'unsafe context root')
    files: list[JsonObject] = []
    directories: list[JsonObject] = []
    total = 0
    paths = sorted(root.rglob('*')) if root.is_dir() else [root]
    for path in paths:
        _expect(not path.is_symlink(), 'unsafe context link')
        if path.is_dir():
            directories.append({'path': str(path.relative_to(root)), 'mode': path.stat().st_mode & 0o777})
            continue
        _expect(path.is_file(), 'unsafe context file type')
        spec = _file(path)
        total += spec['size']
        _expect(total <= 512 * 1024**2 and len(files) < 5000, 'context size/roster bound')
        files.append({'path': str(path.relative_to(root)) if root.is_dir() else root.name,
                      'mode': path.stat().st_mode & 0o777, **spec})
    root_mode = root.stat().st_mode & 0o777
    raw = json.dumps({'files': files, 'directories': directories, 'root_mode': root_mode},
                     sort_keys=True, separators=(',', ':')).encode()
    return {'sha256': _sha(raw), 'files': files, 'directories': directories, 'root_mode': root_mode, 'bytes': total}


def verify_execution_boundary(observed: JsonObject, image: str, command: list[str], mounts: list[str],
                              *, readonly: bool, user: str, rootfs_setup: bool = False) -> None:
    """Check the observed native boundary, including exact mount and scrubbed argv rosters."""
    config, host = observed['Config'], observed['HostConfig']
    required = {'NetworkMode': 'none', 'CapDrop': ['ALL'], 'ReadonlyRootfs': readonly,
                'Privileged': False, 'PidsLimit': 128, 'Memory': 1024**3, 'MemorySwap': 1024**3,
                'NanoCpus': 1000000000, 'SecurityOpt': ['no-new-privileges=true'], 'IpcMode': 'private',
                'Tmpfs': {'/tmp': 'rw,nosuid,nodev,size=536870912,nr_inodes=16384,mode=1777'}}
    _expect(observed['Image'] == image and config['User'] == user and
            config['Entrypoint'] == ['/usr/bin/env'] and config['Cmd'] == command and
            all(host.get(k) == v for k, v in required.items()) and
            host.get('PidMode') in ('', 'private') and
            host.get('CapAdd') == (['CAP_SYS_CHROOT'] if rootfs_setup else None) and
            all(not host.get(k) for k in ('Binds', 'Devices', 'VolumesFrom')),
            'actual execution boundary differs from requested isolation')
    expected = []
    for mount in mounts:
        fields = dict(part.split('=', 1) for part in mount.split(',') if '=' in part)
        expected.append((fields['type'], fields['src'], fields['dst'], 'readonly' not in mount.split(',')))
    actual = [(m['Type'], m.get('Name') if m['Type'] == 'volume' else m['Source'], m['Destination'], m['RW'])
              for m in observed['Mounts']]
    _expect(sorted(actual) == sorted(expected), 'actual mount boundary differs from selected input/output roster')


class _Attempt:
    def __init__(self, engine: Docker, output: Path, result: JsonObject):
        self.engine = cast(_Engine, engine)
        self.output, self.result = output, result
        self.labels = {'org.p11lab.tool-build': uuid4().hex}
        self.containers: list[str] = []
        self.images: list[str] = []
        self.serial = 0

    def run(self, image: str, argv: list[str], *, readonly: bool = True, user: str = '0:0',
            mounts: tuple[str, ...] | list[str] = (), environment: dict[str, str] | None = None,
            rootfs_setup: bool = False) -> str:
        if rootfs_setup:
            _expect(image == self.result.get('base', {}).get('engine_id'),
                    'trusted setup image differs from selected base')
        self.serial += 1
        name = 'p11lab-tool-' + self.labels['org.p11lab.tool-build'] + '-' + str(self.serial)
        options = _options(readonly=readonly, user=user, rootfs_setup=rootfs_setup)
        for mount in mounts:
            options += ['--mount', mount]
        command = ['-i']
        for key, value in (environment or {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'HOME': '/tmp'}).items():
            command.append(key + '=' + value)
        command += argv
        contexts = {}
        for mount in mounts:
            fields = dict(part.split('=', 1) for part in mount.split(',') if '=' in part)
            if fields['type'] == 'bind':
                _expect('readonly' in mount.split(','), 'input context must be read-only')
                contexts[fields['dst']] = context_identity(Path(fields['src']))
        record = {'image': image, 'argv': command, 'options': options, 'labels': self.labels,
                  'name': name, 'input_contexts': contexts, 'trusted_rootfs_setup': rootfs_setup}
        self.result['stages'].append(record)
        try:
            container = self.engine.create(image, command, options, self.labels, name)
        except DockerError as error:
            if error.resource and error.resource[0] == 'container':
                self.containers.append(error.resource[1])
            raise
        self.containers.append(container)
        record['container'] = container
        before = json.loads(self.engine.command(['container', 'inspect', container]).stdout)[0]
        record['inspection_before'] = before
        verify_execution_boundary(before, image, command, list(mounts), readonly=readonly, user=user, rootfs_setup=rootfs_setup)
        native = self.engine.execute(container, 900, lambda: None)
        record['native'] = asdict(native)
        stopped = json.loads(self.engine.command(['container', 'inspect', container]).stdout)[0]
        record['inspection_after'] = stopped
        _expect(not stopped['State']['Running'], 'producer not stopped')
        _expect(not (native.returncode or native.timed_out or native.stdout_truncated or native.stderr_truncated),
                'native tool stage failed; see retained native output')
        return container

    def commit(self, container: str) -> JsonObject:
        _expect(container in self.containers, 'unowned commit source')
        changes = ['--change', 'ENTRYPOINT []', '--change', 'CMD []', '--change',
                   'LABEL org.p11lab.admission=unreviewed-local-tool-only']
        identity = self.engine.command(['commit', *changes, container], timeout=120).stdout.strip()
        _expect(identity.startswith('sha256:') and len(identity) == 71, 'invalid committed tool image')
        self.images.append(identity)
        info = json.loads(self.engine.command(['image', 'inspect', identity]).stdout)[0]
        _expect(info['Id'] == identity and info['Os'] == 'linux' and info['Architecture'] == 'amd64',
                'committed image identity/platform mismatch')
        return {'engine_id': identity, 'config_sha256': identity.removeprefix('sha256:'),
                'layers': info['RootFS']['Layers'], 'size': info['Size'], 'inspection': info}

    def export(self, container: str, name: str) -> JsonObject:
        _expect(container in self.containers, 'unowned readback source')
        info = json.loads(self.engine.command(['container', 'inspect', container]).stdout)[0]
        _expect(not info['State']['Running'], 'readback requires a stopped producer')
        path = self.output / (name + '.tar')
        process = subprocess.Popen(['docker', 'export', '--output', str(path), container],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=self.engine.env)
        started = time.monotonic()
        try:
            while process.poll() is None:
                if time.monotonic() - started > 120 or (path.exists() and path.stat().st_size > MAX_EXPORT):
                    process.kill()
                    raise ToolBuildError('filesystem export time/byte bound')
                time.sleep(.05)
            _, stderr = process.communicate(timeout=5)
            _expect(process.returncode == 0, 'filesystem export failed: ' + stderr[:1024].decode('utf-8', 'replace'))
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
        _expect(path.stat().st_size <= MAX_EXPORT, 'filesystem export exceeds bound')
        inventory = _archive_inventory(path)
        _write(self.output / (name + '.json'), inventory)
        return inventory

    def cleanup(self, *, keep: str | None) -> None:
        for identity in reversed(self.containers):
            try:
                self.engine.remove('container', identity, self.labels)
            except Exception as error:
                self.result['cleanup_errors'].append(str(error))
        for identity in reversed(self.images):
            if identity == keep:
                continue
            try:
                info = json.loads(self.engine.command(['image', 'inspect', identity]).stdout)[0]
                _expect(info.get('Config', {}).get('Labels', {}).get('org.p11lab.tool-build') ==
                        self.labels['org.p11lab.tool-build'], 'unowned intermediate image')
                self.engine.command(['image', 'rm', identity])
            except Exception as error:
                self.result['cleanup_errors'].append(str(error))
        # Independent absence: matching nonce must find no containers/volumes.
        for resource in ('container', 'volume'):
            try:
                flags = '-aq' if resource == 'container' else '-q'
                remaining = self.engine.command([resource, 'ls', flags, '--filter',
                                                'label=org.p11lab.tool-build=' + self.labels['org.p11lab.tool-build']]).stdout.strip()
                if remaining:
                    self.result['cleanup_errors'].append('owned ' + resource + ' remains: ' + remaining)
            except Exception as error:
                self.result['cleanup_errors'].append('cleanup absence probe: ' + str(error))


def _install(attempt: _Attempt, lock: JsonObject, stage: str, staged: Path, base: str, *, extra: str = '') -> tuple[JsonObject, JsonObject]:
    _prepare_public_stage(staged)
    packages = select_packages(lock, stage)
    install = 'dpkg --unpack /inputs/debs/*.deb; dpkg --configure -a;' if packages else ''
    argv = ['/bin/sh', '-ec', install + extra + " dpkg-query -W -f='" + PACKAGE_QUERY + "' | sort"]
    image, inventory, native = install_bounded_rootfs(attempt, base, argv, staged=staged, name=stage,
        environment={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C',
                     'HOME': '/tmp', 'DEBIAN_FRONTEND': 'noninteractive'})
    # Maintainer output precedes the exact query. Delimit the roster explicitly.
    marker = 'P11LAB_PACKAGE_INVENTORY\n'
    _expect(marker in native, 'missing actual package inventory marker')
    observed = verify_package_inventory(lock, stage, native.split(marker)[-1])
    _write(attempt.output / (stage + '-packages.json'), observed)
    return image, inventory


def _stage_packages(lock: JsonObject, stage: str, inputs: Path, staged: Path) -> None:
    (staged / 'debs').mkdir(parents=True)
    for package in select_packages(lock, stage):
        _copy_checked(inputs / package['path'], staged / 'debs' / Path(package['path']).name, package)


def _producer(attempt: _Attempt, image: str, staged: Path, argv: list[str], output_name: str) -> Path:
    _prepare_public_stage(staged)
    record: JsonObject = {}
    volume = _OutputVolume(cast(Docker, attempt.engine), image, attempt.labels,
                           'p11lab-tool-output-' + uuid4().hex, 16 * 1024**2, record)
    attempt.result['producer_output'] = record
    destination = attempt.output / 'product'
    destination.mkdir()
    initial_containers = set(attempt.containers)
    try:
        volume.open()
        attempt.run(image, argv, user='65532:65532', mounts=[
            f'type=bind,src={staged},dst=/inputs,readonly',
            f'type=volume,src={volume.name},dst=/out'], environment={
                'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'HOME': '/tmp',
                'PYTHONHASHSEED': '0', 'SOURCE_DATE_EPOCH': '1580601600',
                'PYTHONNOUSERSITE': '1', 'PYTHONSAFEPATH': '1'})
        volume.readback(destination, (output_name,), lambda: None)
        return destination / output_name
    finally:
        # A stopped container still holds its mount reference. Release it before
        # deleting the bounded output volume, retaining terminal inspections.
        for identity in list(attempt.containers):
            if identity not in initial_containers:
                try:
                    attempt.engine.remove('container', identity, attempt.labels)
                    attempt.containers.remove(identity)
                except Exception as error:
                    attempt.result['cleanup_errors'].append('producer release: ' + str(error))
        attempt.result['cleanup_errors'] += volume.close()


def _stage_checker(lock: JsonObject, inputs: Path, staged: Path) -> None:
    _source(lock, inputs, staged)
    for spec in lock['python_inputs']:
        if spec['path'].endswith('.whl'):
            _copy_checked(inputs / spec['path'], staged / 'wheels' / Path(spec['path']).name, spec)
    for name in ('bootstrap', 'build', 'runtime'):
        asset = 'tool-inputs/checker/' + name + '-requirements.txt'
        (staged / (name + '-requirements.txt')).write_bytes(package_data(asset).read_bytes())


def verify_install_parent(before: JsonObject, after: JsonObject) -> JsonObject:
    """Fixed-wheel installation/startup may only add its own installation prefix."""
    for kind in ('files', 'aliases'):
        _expect(all(after[kind].get(name) == value for name, value in before[kind].items()),
                'checker installation changed an observed parent file or alias')
        _expect(all(name.startswith('opt/p11lab-checker/') for name in after[kind] if name not in before[kind]),
                'checker installation added content outside its installation prefix')
    return {'unchanged_files': len(before['files']), 'unchanged_aliases': len(before['aliases']),
            'additions': 'opt/p11lab-checker-only'}


def _checker_install_proof(inventory: JsonObject, staged: Path) -> JsonObject:
    """Verify every frozen wheel member against independently exported installed bytes."""
    root = 'opt/p11lab-checker/lib/python3.13/site-packages/'
    count = 0
    distributions = []
    for wheel in sorted((staged / 'wheels').glob('*.whl')):
        with zipfile.ZipFile(wheel) as archive:
            for member in archive.infolist():
                if member.is_dir() or member.filename.endswith('.dist-info/RECORD'):
                    continue
                name = root + _safe_member(member.filename)
                _expect(name in inventory['files'] and inventory['files'][name]['sha256'] == _sha(archive.read(member)),
                        'installed wheel member mismatch: ' + name)
                count += 1
                if member.filename.endswith('.dist-info/METADATA'):
                    distributions.append(member.filename.split('/')[0])
    _expect(len(distributions) == 33, 'actual installed 33-wheel roster incomplete')
    actual = sorted(name[len(root):].split('/')[0] for name in inventory['files']
                    if name.startswith(root) and name.endswith('.dist-info/METADATA'))
    _expect(actual == sorted(distributions + [n for n in actual if n.startswith('pip-')]),
            'unexpected installed distribution')
    return {'wheels': 33, 'verified_wheel_members': count, 'distributions': distributions}


def build_tool(request: ToolBuildRequest, *, engine: Docker | None = None) -> JsonObject:
    """Build/install one selected tool offline in a fresh local attempt.

    A mismatch is returned as blocked with its actual wheel retained. Native
    failures raise ToolBuildError after retaining manifest/logs and owned cleanup.
    Successful local product images remain installed; intermediates are removed.
    """
    _expect(type(request) is ToolBuildRequest, 'typed ToolBuildRequest required')
    _expect(request.toolset in {'checker', 'consumer', 'oracle'}, 'unsupported toolset')
    output = Path(request.output_dir).absolute()
    _expect(not output.exists() and not output.is_symlink(), 'output must be a fresh directory')
    safe_directory(output.parent)
    receipt = Path(request.receipt_path).absolute()
    resolved = verify_resolved_tool_inputs(request.toolset, target=TARGET, receipt_path=receipt)
    lock = load_tool_input_lock(request.toolset, target=TARGET)
    output.mkdir()
    result: JsonObject = {'schema_version': 2, 'kind': 'local-tool-build', 'toolset': request.toolset, 'target': TARGET,
              'status': 'incomplete', 'rights': 'unreviewed', 'qualification': 'not-performed',
              'input_lock_sha256': resolved['lock_sha256'], 'input_receipt': _file(receipt),
              'stages': [], 'cleanup_errors': [], 'installed': None, 'products': [],
              'producer_resources': _recipe_identity(), 'bounded_policy': bounded_install_policy()}
    attempt = _Attempt(engine or _new_docker(), output, result)
    keep = None
    try:
        _expect(',' not in str(output), 'unsupported comma in Docker mount path')
        base_id = lock['base_image'].split('@')[-1]
        base = attempt.engine.image(ArtifactRef('docker', base_id, base_id.removeprefix('sha256:'), 'linux/amd64'))
        _expect(base['Id'] == lock['base_image'].split('@')[-1] and base['Os'] == 'linux' and
                base['Architecture'] == 'amd64', 'selected immutable base is absent/mismatched')
        result['base'] = {'reference': lock['base_image'], 'engine_id': base['Id'],
                          'layers': base['RootFS']['Layers'], 'inspection': base}
        inputs, staged = receipt.parent, output / 'staged'
        staged.mkdir()
        stage = 'compiler' if request.toolset == 'consumer' else request.toolset
        _stage_packages(lock, stage, inputs, staged)
        marker = " printf 'P11LAB_PACKAGE_INVENTORY\\n';"
        extra = marker
        if request.toolset == 'oracle':
            for p in lock['resources']:
                _copy_checked(inputs / p['path'], staged / Path(p['path']).name, p)
            extra = ' mkdir -p /opt/p11lab-oracle; cp /inputs/verify.py /inputs/openssl.cnf /opt/p11lab-oracle/;' + marker
        image, inventory = _install(attempt, lock, stage, staged, base['Id'], extra=extra)
        result['builder'] = image
        result['package_archive_members'] = bind_package_members(lock, stage, inputs, inventory)
        if request.toolset == 'checker':
            _stage_checker(lock, inputs, staged)
            script = package_data('tool-builds/checker-build.sh').read_text()
            wheel = _producer(attempt, image['engine_id'], staged, ['/bin/sh', '-ec', script],
                              'pkcs11_check-0.2.3-py3-none-any.whl')
            result['products'].append({'path': str(wheel.relative_to(output)), **_file(wheel)})
            result['reproduction'] = check_checker_output(wheel)
            if result['reproduction']['status'] != 'reproduced':
                result['status'] = 'blocked-output-mismatch'
                return result
            # Restrict install wheelhouse to exactly the protected runtime roster.
            runtime = output / 'runtime'
            runtime.mkdir()
            (runtime / 'wheels').mkdir()
            for path in lock['execution']['runtime_wheels']:
                source = wheel if path.startswith('runtime-wheelhouse/') else staged / path
                shutil.copyfile(source, runtime / 'wheels' / Path(path).name)
            shutil.copyfile(staged / 'runtime-requirements.txt', runtime / 'runtime-requirements.txt')
            _prepare_public_stage(runtime)
            script = package_data('tool-builds/checker-install.sh').read_text()
            builder_inventory = inventory
            image, inventory, _ = install_bounded_rootfs(attempt, image['engine_id'],
                ['/bin/sh', '-ec', script], staged=runtime, name='installed',
                environment={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'HOME': '/tmp'})
            result['parent_preservation'] = verify_install_parent(builder_inventory, inventory)
            result['runtime_package_archive_members'] = bind_package_members(lock, stage, inputs, inventory)
            result['python_installation'] = _checker_install_proof(inventory, runtime)
            roots = ['usr/bin/python3.13'] + [n for n in inventory['elfs'] if n.startswith('opt/p11lab-checker/')]
        elif request.toolset == 'consumer':
            compiler_roots = ['usr/bin/cc', 'usr/bin/as', 'usr/bin/ld'] + [
                name for name in inventory['elfs'] if name.endswith(('/cc1', '/collect2'))]
            result['compiler_elf_closure'] = _elf_closure(inventory, compiler_roots)
            for p in lock['resources']:
                _copy_checked(inputs / p['path'], staged / 'consumer' / p['path'].removeprefix('resources/consumer/'), p)
            argv = ['/bin/sh', '-ec', 'cd /inputs/consumer; cc -std=c11 -O2 -Wall -Wextra -Werror -pedantic smoke.c p256.c -ldl -o /out/p11lab-smoke; chmod 755 /out/p11lab-smoke']
            binary = _producer(attempt, image['engine_id'], staged, argv, 'p11lab-smoke')
            result['products'].append({'path': str(binary.relative_to(output)), **_file(binary),
                                       'elf': inspect_elf(binary.read_bytes())})
            runtime = output / 'runtime'
            runtime.mkdir()
            _stage_packages(lock, 'consumer', inputs, runtime)
            shutil.copyfile(binary, runtime / 'p11lab-smoke')
            image, inventory = _install(attempt, lock, 'consumer', runtime, base['Id'], extra=
                ' cp /inputs/p11lab-smoke /usr/local/bin/p11lab-smoke; chmod 755 /usr/local/bin/p11lab-smoke;' + marker)
            result['runtime_package_archive_members'] = bind_package_members(lock, 'consumer', inputs, inventory)
            roots = ['usr/local/bin/p11lab-smoke']
            attempt.run(image['engine_id'], ['/usr/local/bin/p11lab-smoke', '--help'], user='65532:65532')
        else:
            roots = ['usr/bin/python3.13', 'usr/bin/openssl', 'usr/lib/x86_64-linux-gnu/ossl-modules/legacy.so']
            _oracle_controls(attempt, image['engine_id'], output, lock)
        result['elf_closure'] = _elf_closure(inventory, roots)
        result['installed'] = image
        result['status'] = 'installed-local-only'
        keep = image['engine_id']
        return result
    except BaseException as error:
        result['status'] = 'failed'
        result['error'] = {'type': type(error).__name__, 'message': str(error)}
        raise
    finally:
        attempt.cleanup(keep=keep)
        if result['cleanup_errors']:
            result['status'] = 'failed-cleanup'
        result['retained_product_image'] = keep
        result['evidence'] = {str(p.relative_to(output)): _file(p)
                              for p in output.iterdir() if p.is_file() and p.name != 'manifest.json'}
        _write(output / 'manifest.json', result)


def _recipe_identity() -> JsonObject:
    root = Path(__file__).parent
    shared = ('tool_rootfs.py', 'docker.py', 'process.py', 'tool_inputs.py', 'tool_downloads.py',
              'round_core/worker.py', 'round_core/inputs.py', 'round_core/evidence.py',
              'round_core/bootstrap.py')
    return {'driver': _file(Path(__file__)),
            'shared_primitives': {name: _file(root / name) for name in shared}, 'resources': {
        name: {'sha256': _sha(package_data('tool-builds/' + name).read_bytes()),
               'size': len(package_data('tool-builds/' + name).read_bytes())}
        for name in ('checker-build.sh', 'checker-install.sh', 'oracle-controls.py', 'rootfs-launch.pl')}}


def bind_package_members(lock: JsonObject, stage: str, inputs: Path, inventory: JsonObject) -> JsonObject:
    """Bind each acquired Debian data member to actual installed bytes or explicit change.

    Maintainer-generated/configuration changes remain visible. Executable, shared
    library and Python runtime members must match their selected archive exactly.
    Parent files are bound by immutable base/layer and actual readback inventories.
    """
    bindings = []
    for package in select_packages(lock, stage):
        raw = _read_regular(inputs / package['path'], maximum=package['size'])
        _expect(_sha(raw) == package['sha256'], 'package archive changed before member binding')
        _expect(raw[:8] == b'!<arch>\n', 'invalid Debian archive')
        pos, data = 8, None
        while pos + 60 <= len(raw):
            header = raw[pos:pos + 60]
            length = int(header[48:58].strip())
            name = header[:16].decode('ascii').strip().removesuffix('/')
            if name.startswith('data.tar'):
                data = raw[pos + 60:pos + 60 + length]
            pos += 60 + length + (length % 2)
        if data is None:
            raise ToolBuildError('missing Debian data member')
        members = []
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:*') as archive:
            for member in archive:
                if not member.isfile():
                    continue
                name = _safe_member(member.name)
                stream = archive.extractfile(member)
                if stream is None:
                    raise ToolBuildError('missing Debian file member')
                expected = _sha(stream.read(member.size + 1))
                actual_path = _resolve(name, inventory)
                actual = inventory['files'].get(actual_path)
                equal = actual is not None and actual['sha256'] == expected and actual['size'] == member.size
                critical = name.startswith(('usr/bin/', 'usr/sbin/', 'bin/', 'sbin/', 'usr/lib/', 'lib/')) and (member.mode & 0o111 or name.endswith(('.so', '.py')) or '.so.' in name)
                _expect(equal or not critical, 'installed executable/runtime differs from package archive: ' + name)
                members.append({'path': name, 'archive_sha256': expected, 'size': member.size,
                                'installed_path': actual_path, 'installed_sha256': actual['sha256'] if actual else None,
                                'status': 'equal' if equal else 'maintainer-modified-or-absent'})
        bindings.append({'name': package['name'], 'version': package['version'],
                         'archive_sha256': package['sha256'], 'members': members})
    return {'stage': stage, 'packages': bindings, 'rights': 'unreviewed'}


def _oracle_controls(attempt: _Attempt, image: str, output: Path, lock: JsonObject) -> None:
    script = output / 'oracle-controls.py'
    script.write_bytes(package_data('tool-builds/oracle-controls.py').read_bytes())
    script.chmod(0o644)
    environment = lock['execution']['environment']
    attempt.run(image, ['/usr/bin/python3.13', '-I', '-B', '/controls.py'], user='65532:65532',
                mounts=[f'type=bind,src={script},dst=/controls.py,readonly'], environment=environment)
    result = json.loads(attempt.result['stages'][-1]['native']['stdout'])
    _expect(result['positive']['returncode'] == 0 and result['altered_message']['returncode'] != 0 and
            result['altered_signature']['returncode'] != 0, 'oracle controls incomplete')
    attempt.result['oracle_controls'] = result


def verify_tool_build(output_dir: Path, *, receipt_path: Path | None = None,
                      manifest_sha256: str | None = None, engine: Docker | None = None) -> JsonObject:
    """Warm reuse reselects/re-hashes input authority and actual installed image files.

    A local receipt is an observation, never an external producer attestation.
    Reuse requires the original protected input receipt and matching installed code.
    """
    output = Path(output_dir).absolute()
    safe_directory(output)
    if receipt_path is None:
        raise ToolBuildError('warm reuse requires the protected input receipt')
    raw_manifest = _read_regular(output / 'manifest.json', maximum=16 * 1024**2)
    _expect(isinstance(manifest_sha256, str) and len(manifest_sha256) == 64 and
            _sha(raw_manifest) == manifest_sha256, 'missing or changed protected manifest SHA256')
    manifest: JsonObject = json.loads(raw_manifest)
    _expect(manifest.get('schema_version') == 2 and manifest.get('bounded_policy') == bounded_install_policy(), 'missing or changed bounded install policy')
    installs = manifest.get('bounded_installations', [])
    count = {'checker': 2, 'consumer': 2, 'oracle': 1}.get(manifest.get('toolset', ''), 0)
    _expect(count > 0 and len(installs) == count and all(
        p.get('policy') == bounded_install_policy() and p.get('bytes') == bounded_install_policy()['rootfs_bytes'] and
        p.get('inodes') == bounded_install_policy()['rootfs_inodes'] and
        p.get('payload_capabilities_observed') == 'zero-effective-permitted-inheritable' and
        p.get('payload_no_new_privileges') == 1 and
        p.get('setup_image') == manifest.get('base', {}).get('engine_id') and
        p.get('cleanup') == 'exact-owned-containers-and-volume-removed' for p in installs),
        'incomplete or changed bounded installation roster')
    _expect(manifest.get('kind') == 'local-tool-build' and manifest.get('status') == 'installed-local-only' and
            manifest.get('rights') == 'unreviewed' and manifest.get('qualification') == 'not-performed' and
            not manifest.get('cleanup_errors') and manifest.get('producer_resources') == _recipe_identity(),
            'incomplete or changed tool build')
    resolved = verify_resolved_tool_inputs(manifest['toolset'], target=TARGET, receipt_path=receipt_path)
    _expect(resolved['lock_sha256'] == manifest['input_lock_sha256'] and
            _file(Path(receipt_path)) == manifest['input_receipt'], 'tool input authority changed')
    for name, spec in manifest['evidence'].items():
        _expect(_safe_member(name) == name and _file(output / name) == spec, 'changed build evidence')
    for spec in manifest['products']:
        path = output / _safe_member(spec['path'])
        _expect(all(_file(path)[k] == spec[k] for k in ('size', 'sha256')), 'changed tool product')
    if manifest['toolset'] == 'checker':
        _expect(check_checker_output(output / manifest['products'][0]['path'])['status'] == 'reproduced',
                'checker expected output is not reproduced')
    docker = cast(_Engine, engine or _new_docker())
    installed = manifest['installed']
    actual = docker.image(ArtifactRef('docker', installed['engine_id'], installed['config_sha256'], 'linux/amd64'))
    _expect(actual['Id'] == installed['engine_id'] and actual['RootFS']['Layers'] == installed['layers'] and
            actual['Id'].removeprefix('sha256:') == installed['config_sha256'], 'installed engine/config/layers changed')
    # Immutable config/layers bind the stopped full filesystem readback retained
    # above. Rehash every tar member independently rather than trusting its JSON.
    prefix = {'consumer': 'consumer', 'oracle': 'oracle', 'checker': 'installed'}[manifest['toolset']]
    inventory = _archive_inventory(output / (prefix + '-filesystem.tar'))
    _expect(inventory == json.loads((output / (prefix + '-filesystem.json')).read_text()),
            'installed filesystem inventory differs from actual bytes')
    return manifest
