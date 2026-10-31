"""Bounded, local-only proxy toolchain assembly."""
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
import hashlib
import io
import lzma
import tarfile
import posixpath
import stat
import struct
import zipfile
from typing import Any, Iterable, Literal, cast

from .tool_builds import ToolBuildError, _resolve, _safe_member, inspect_elf
from .proxy_inputs import ProxyInputCache, ProxyInputError, _preflight_tar
from .round_core.worker import _pax_fields


class ToolchainError(ValueError):
    """The selected toolchain cannot be established."""


JsonObject = dict[str, Any]


_DESCRIPTOR = bytes.fromhex(
    '0a3c0a0c63616e6172792e70726f746f12067031316c6162'
    '221c0a0450696e6712140a0576616c7565180120012809520576616c7565'
    '620670726f746f33'
)


def check_protoc_descriptor(data: bytes) -> None:
    """Check the complete independently encoded canary descriptor."""
    if data != _DESCRIPTOR:
        raise ToolchainError('protoc descriptor does not match the independent golden')


def resolve_toolchain_closure(inventory: JsonObject, roots: list[str]) -> JsonObject:
    """Resolve the constrained Rust origin path and the fixed Debian directories."""
    closure: JsonObject = {}
    pending = [_resolve(root, inventory) for root in roots]
    while pending:
        name = pending.pop()
        if name in closure:
            continue
        if name not in inventory['elfs'] or name not in inventory['files']:
            raise ToolchainError('missing actual ELF: ' + name)
        meta = inventory['elfs'][name]
        paths = meta['search_paths']
        if (paths and (paths != ['$ORIGIN/../lib'] or meta.get('search_kind') != 'runpath'
                       or not name.startswith('opt/rust/')) or
                not paths and meta.get('search_kind') != 'none'):
            raise ToolchainError('unsupported ELF search path or tag: ' + name)
        dirs = []
        if paths:
            origin = str(PurePosixPath(name).parent)
            expanded = posixpath.normpath(origin + '/../lib')
            if expanded != 'opt/rust/lib':
                raise ToolchainError('unsupported ELF origin: ' + name)
            dirs.append(expanded)
        dirs.extend(('lib/x86_64-linux-gnu', 'usr/lib/x86_64-linux-gnu', 'lib64', 'usr/lib64'))
        dependencies = []
        if meta['interpreter']:
            dependencies.append(_resolve(meta['interpreter'], inventory))
        for needed in meta['needed']:
            if '/' in needed or not needed:
                raise ToolchainError('unsafe ELF dependency: ' + needed)
            found = next((_resolve(d + '/' + needed, inventory) for d in dirs
                          if _resolve(d + '/' + needed, inventory) in inventory['elfs']), None)
            if found is None:
                raise ToolchainError('unresolved ELF dependency: ' + name + ': ' + needed)
            dependencies.append(found)
        closure[name] = {**inventory['files'][name], **meta, 'resolved_dependencies': dependencies}
        pending.extend(dependencies)
    return closure


def _check_image_tar_frames(path: Path) -> None:
    """Reject hidden records, nonzero padding and unsafe extension metadata."""
    size = path.stat().st_size
    if size % 512:
        raise ToolchainError('unaligned image archive')
    records = metadata = extensions = 0
    with path.open('rb') as source:
        while source.tell() < size:
            header = source.read(512)
            if not any(header):
                if size - source.tell() < 512:
                    raise ToolchainError('short image archive terminator')
                while chunk := source.read(1024 * 1024):
                    if any(chunk):
                        raise ToolchainError('image archive has hidden trailer')
                return
            try:
                info = tarfile.TarInfo.frombuf(header, 'utf-8', 'strict')
            except (tarfile.HeaderError, ValueError, UnicodeError) as error:
                raise ToolchainError('invalid image tar header') from error
            records += 1
            if records > 65536 or info.size < 0 or info.size > 256 * 1024**2:
                raise ToolchainError('image tar frame limit')
            padded = (info.size + 511) // 512 * 512
            if source.tell() + padded > size:
                raise ToolchainError('truncated image tar frame')
            if info.type in (b'x', b'g', b'L', b'K'):
                extensions += 1
                metadata += info.size
                if extensions > 8 or metadata > 1024**2 or info.size > 65536:
                    raise ToolchainError('image tar metadata bound')
                payload = source.read(info.size)
                if info.type in (b'x', b'g'):
                    try:
                        _pax_fields(payload)
                    except (ValueError, UnicodeError) as error:
                        raise ToolchainError('unsafe image PAX metadata') from error
                elif info.size > 4096:
                    raise ToolchainError('image long name bound')
            else:
                extensions = 0
                if info.type not in (b'0', b'\0', b'1', b'2', b'3', b'5'):
                    raise ToolchainError('unsupported image tar frame')
                if info.type not in (b'0', b'\0') and info.size:
                    raise ToolchainError('nonregular image member payload')
                source.seek(info.size, 1)
            if any(source.read(padded - info.size)):
                raise ToolchainError('nonzero image tar padding')
    raise ToolchainError('missing image tar terminator')


def _inspect_toolchain_elf(raw: bytes) -> JsonObject:
    """Retain search-tag semantics that the shared ELF inspector combines."""
    info = inspect_elf(raw)
    header = struct.unpack_from('<HHIQQQIHHHHHH', raw, 16)
    tags: list[int] = []
    for index in range(header[9]):
        ph = struct.unpack_from('<IIQQQQQQ', raw, header[4] + index * 56)
        if ph[0] == 2:
            for offset in range(ph[2], ph[2] + ph[5], 16):
                tag, _ = struct.unpack_from('<QQ', raw, offset)
                if tag == 0:
                    break
                if tag in (15, 29):
                    tags.append(tag)
    if len(tags) > 1:
        raise ToolchainError('ambiguous ELF search tags')
    info['search_kind'] = {15: 'rpath', 29: 'runpath'}.get(tags[0], 'none') if tags else 'none'
    return info


def inventory_toolchain_archive(path: Path) -> JsonObject:
    """Read a bounded stopped image; no filesystem paths are extracted."""
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024**3:
        raise ToolchainError('unsafe or oversized image archive')
    _check_image_tar_frames(path)
    files: JsonObject = {}
    aliases: JsonObject = {}
    elfs: JsonObject = {}
    directories: JsonObject = {}
    devices: JsonObject = {}
    names: set[str] = set()
    total = 0
    try:
        with tarfile.open(path, 'r:') as archive:
            for member in archive:
                if member.isdir() and member.name in ('.', './'):
                    continue
                name = _safe_member(member.name)
                if name in names or len(names) >= 32768:
                    raise ToolchainError('duplicate or oversized image roster')
                names.add(name)
                if member.isfile():
                    total += member.size
                    if member.size > 256 * 1024**2 or total > 1024**3:
                        raise ToolchainError('image regular byte limit')
                    stream = archive.extractfile(member)
                    if stream is None:
                        raise ToolchainError('missing image member')
                    raw = stream.read(member.size + 1)
                    if len(raw) != member.size:
                        raise ToolchainError('truncated image member')
                    files[name] = {'size': member.size, 'sha256': hashlib.sha256(raw).hexdigest(),
                                   'mode': member.mode, 'uid': member.uid, 'gid': member.gid}
                    if raw.startswith(b'\x7fELF'):
                        elfs[name] = _inspect_toolchain_elf(raw)
                elif member.issym() or member.islnk():
                    aliases[name] = {'target': member.linkname,
                                     'kind': 'symlink' if member.issym() else 'hardlink',
                                     'mode': member.mode, 'uid': member.uid, 'gid': member.gid}
                elif member.isdir():
                    directories[name] = {'mode': member.mode, 'uid': member.uid, 'gid': member.gid}
                elif member.ischr():
                    expected = {'dev/null': (1, 3), 'dev/zero': (1, 5),
                                'dev/random': (1, 8), 'dev/urandom': (1, 9)}
                    if expected.get(name) != (member.devmajor, member.devminor):
                        raise ToolchainError('unsupported image device')
                    devices[name] = {'major': member.devmajor, 'minor': member.devminor,
                                     'mode': member.mode, 'uid': member.uid, 'gid': member.gid}
                else:
                    raise ToolchainError('unsupported image member')
            offset = archive.offset
        with path.open('rb') as raw_tar:
            raw_tar.seek(offset)
            trailer = raw_tar.read(1024)
            if len(trailer) != 1024 or any(trailer):
                raise ToolchainError('missing image archive terminator')
            while chunk := raw_tar.read(1024 * 1024):
                if any(chunk):
                    raise ToolchainError('image archive has trailing data')
        inventory = {'files': files, 'aliases': aliases, 'elfs': elfs, 'directories': directories,
                     'devices': devices, 'regular_bytes': total}
        for name in aliases:
            _resolve(name, inventory)
        return inventory
    except (ToolBuildError, tarfile.TarError, OSError) as error:
        raise ToolchainError('invalid image archive') from error


def read_rust_component(raw: bytes, prefix: str, component: str) -> JsonObject:
    """Validate one exact Rust install manifest and bind component member bytes."""
    if len(raw) > 1024**3:
        raise ToolchainError('Rust archive expansion exceeds bound')
    try:
        _preflight_tar(raw, allow_symlinks=False)
        component_prefix = prefix + '/' + component + '/'
        files: JsonObject = {}
        seen: set[str] = set()
        manifest = None
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
            for member in archive:
                name = _safe_member(member.name)
                if name in seen:
                    raise ToolchainError('duplicate Rust archive member')
                seen.add(name)
                if not member.isfile() or not name.startswith(component_prefix):
                    continue
                rel = name.removeprefix(component_prefix)
                stream = archive.extractfile(member)
                if stream is None:
                    raise ToolchainError('missing Rust component member')
                data = stream.read(member.size + 1)
                if len(data) != member.size:
                    raise ToolchainError('truncated Rust component member')
                if rel == 'manifest.in':
                    manifest = data
                else:
                    files[rel] = {'size': member.size, 'sha256': hashlib.sha256(data).hexdigest(),
                                  'mode': member.mode, 'offset': member.offset_data}
        if manifest is None or len(manifest) > 65536:
            raise ToolchainError('missing Rust component manifest')
        entries = manifest.decode('utf-8').splitlines()
        if any(not line.startswith('file:') for line in entries):
            raise ToolchainError('unsupported Rust component manifest entry')
        expected = [line.removeprefix('file:') for line in entries]
        if len(expected) != len(set(expected)) or set(expected) != set(files):
            raise ToolchainError('Rust component manifest differs from archive')
        return files
    except (ProxyInputError, ToolBuildError, tarfile.TarError, UnicodeError) as error:
        raise ToolchainError('invalid Rust component archive') from error


def decode_rust_archive(raw: bytes, *, limit: int = 1024**3) -> bytes:
    """Decode one XZ stream with a finite expansion cap and no trailer."""
    if not 0 < limit <= 1024**3 or len(raw) > 256 * 1024**2:
        raise ToolchainError('Rust compressed archive bound')
    try:
        decoder = lzma.LZMADecompressor(memlimit=134283928)
        decoded = decoder.decompress(raw, max_length=limit + 1)
        if len(decoded) > limit or not decoder.eof or decoder.unused_data:
            raise ToolchainError('Rust archive exceeds bound or has a trailer')
        return decoded
    except lzma.LZMAError as error:
        raise ToolchainError('invalid Rust XZ archive') from error


def read_protoc_archive(raw: bytes) -> JsonObject:
    """Validate the selected protoc zip as inert regular files and directories."""
    if len(raw) > 256 * 1024**2 or len(raw) < 22 or raw[-22:-18] != b'PK\x05\x06' or raw[-2:] != b'\0\0':
        raise ToolchainError('invalid protoc archive trailer or bound')
    files: JsonObject = {}
    seen: set[str] = set()
    total = 0
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            for member in archive.infolist():
                name = _safe_member(member.filename.rstrip('/'))
                if name in seen or len(seen) >= 32768:
                    raise ToolchainError('duplicate or oversized protoc roster')
                seen.add(name)
                mode = member.external_attr >> 16
                if member.create_system != 3 or member.flag_bits & 1:
                    raise ToolchainError('unsupported protoc archive member')
                if member.is_dir():
                    if not stat.S_ISDIR(mode):
                        raise ToolchainError('invalid protoc directory')
                    continue
                if not stat.S_ISREG(mode) or member.file_size > 256 * 1024**2:
                    raise ToolchainError('invalid protoc member type or size')
                total += member.file_size
                if total > 1024**3:
                    raise ToolchainError('protoc byte limit')
                data = archive.read(member)
                if len(data) != member.file_size:
                    raise ToolchainError('truncated protoc member')
                files[name] = {'size': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
                               'mode': mode & 0o7777}
        return files
    except (ToolBuildError, zipfile.BadZipFile, OSError) as error:
        raise ToolchainError('invalid protoc archive') from error


class _BoundedWriter:
    def __init__(self, stream: Any) -> None:
        self.stream = stream
        self.written = 0

    def write(self, data: bytes) -> int:
        if self.written + len(data) > 1024**3:
            raise ToolchainError('assembled image archive exceeds bound')
        count: int = self.stream.write(data)
        if count != len(data):
            raise ToolchainError('short image archive write')
        self.written += count
        return count

    def tell(self) -> int:
        return self.written


def assemble_image_archive(base: Path, components: Iterable[tuple[bytes, str, str]],
                           protoc: bytes, output: Path) -> JsonObject:
    """Assemble a fresh, inert flattened archive using only selected component files."""
    inventory = inventory_toolchain_archive(base)
    if output.exists() or output.is_symlink():
        raise ToolchainError('image archive output must be fresh')
    if any(n == p or n.startswith(p + '/') for n in (*inventory['files'], *inventory['aliases'])
           for p in ('opt/rust', 'opt/protoc')):
        raise ToolchainError('toolchain prefix already exists')
    for prefix in ('opt/rust', 'opt/protoc'):
        if _resolve(prefix, inventory) != prefix:
            raise ToolchainError('toolchain prefix traverses an alias')
    count = len(inventory['files']) + len(inventory['aliases'])
    total = inventory['regular_bytes']
    bound: JsonObject = {}
    added_dirs: set[str] = set()
    with output.open('xb') as stream:
        writer = _BoundedWriter(stream)
        with tarfile.open(fileobj=cast(Any, writer), mode='w|') as destination:
            with tarfile.open(base, 'r:') as source:
                for member in source:
                    data = source.extractfile(member) if member.isfile() else None
                    destination.addfile(member, data)

            def add(name: str, data: bytes, spec: JsonObject) -> None:
                nonlocal count, total
                if name in bound or len(data) != spec['size'] or hashlib.sha256(data).hexdigest() != spec['sha256']:
                    raise ToolchainError('changed or duplicate toolchain member: ' + name)
                total += len(data)
                count += 1
                if total > 1024**3 or count > 32768 or len(data) > 256 * 1024**2:
                    raise ToolchainError('assembled image member limit')
                parent = PurePosixPath(name).parent
                for directory in reversed(parent.parents):
                    text = str(directory)
                    if text in ('.', 'opt') or text in added_dirs:
                        continue
                    entry = tarfile.TarInfo(text)
                    entry.type = tarfile.DIRTYPE
                    entry.mode = 0o755
                    destination.addfile(entry)
                    added_dirs.add(text)
                text = str(parent)
                if text not in ('.', 'opt') and text not in added_dirs:
                    entry = tarfile.TarInfo(text)
                    entry.type = tarfile.DIRTYPE
                    entry.mode = 0o755
                    destination.addfile(entry)
                    added_dirs.add(text)
                entry = tarfile.TarInfo(name)
                entry.size = len(data)
                entry.mode = spec['mode']
                destination.addfile(entry, io.BytesIO(data))
                bound[name] = {k: spec[k] for k in ('size', 'sha256', 'mode')}

            for raw, prefix, component in components:
                for name, spec in read_rust_component(raw, prefix, component).items():
                    start = spec['offset']
                    add('opt/rust/' + name, raw[start:start + spec['size']], spec)
            proto = read_protoc_archive(protoc)
            with zipfile.ZipFile(io.BytesIO(protoc)) as archive:
                for name, spec in proto.items():
                    add('opt/protoc/' + name, archive.read(name), spec)
    return {'files': bound, 'regular_bytes': total, 'archive_bytes': writer.written}



@dataclass(frozen=True)
class ToolchainRequest:
    cache: ProxyInputCache
    output_dir: Path


def build_proxy_toolchain(request: ToolchainRequest) -> JsonObject:
    """Build the selected local toolchain, with no source execution or rights grant."""
    if type(request) is not ToolchainRequest:
        raise ToolchainError('typed ToolchainRequest required')
    return _build_selected_toolchain(request)


def check_canary_output(stdout: str) -> None:
    """Check versions, selected target and independent hello/descriptor outputs."""
    labels = ('P11LAB_RUSTC', 'P11LAB_CARGO', 'P11LAB_PROTOC', 'P11LAB_HELLO',
              'P11LAB_DESCRIPTOR', 'P11LAB_END')
    lines = stdout.splitlines()
    if any(lines.count(label) != 1 for label in labels):
        raise ToolchainError('missing or duplicate toolchain canary sections')
    indexes = [lines.index(label) for label in labels]
    if indexes != sorted(indexes) or indexes[0] != 0 or indexes[-1] != len(lines) - 1:
        raise ToolchainError('unexpected toolchain canary output')
    rustc = lines[indexes[0] + 1:indexes[1]]
    cargo = lines[indexes[1] + 1:indexes[2]]
    protoc = lines[indexes[2] + 1:indexes[3]]
    hello = lines[indexes[3] + 1:indexes[4]]
    descriptor = lines[indexes[4] + 1:indexes[5]]
    if (not rustc or not rustc[0].startswith('rustc 1.98.1 ') or
            rustc.count('host: x86_64-unknown-linux-gnu') != 1 or
            len(cargo) != 1 or not cargo[0].startswith('cargo 1.98.1 ') or
            protoc != ['libprotoc 36.1'] or hello != ['p11lab-toolchain-hello'] or
            len(descriptor) != 1):
        raise ToolchainError('toolchain canary output mismatch')
    try:
        check_protoc_descriptor(bytes.fromhex(descriptor[0]))
    except ValueError as error:
        raise ToolchainError('invalid descriptor hex') from error


def _canary_fixture(root: Path) -> None:
    root.mkdir(mode=0o755)
    (root / 'src').mkdir(mode=0o755)
    (root / 'Cargo.toml').write_text('[package]\nname = "p11lab-canary"\nversion = "0.1.0"\nedition = "2024"\n')
    (root / 'Cargo.lock').write_text('version = 4\n\n[[package]]\nname = "p11lab-canary"\nversion = "0.1.0"\n')
    (root / 'src/main.rs').write_text('fn main() { println!("p11lab-toolchain-hello"); }\n')
    (root / 'canary.proto').write_text('syntax = "proto3";\npackage p11lab;\nmessage Ping { string value = 1; }\n')
    from .tool_builds import _prepare_public_stage

    _prepare_public_stage(root)


def _canary_script() -> str:
    return '''set -eu
cd /canary
mkdir -p /tmp/home /tmp/cargo
printf 'P11LAB_RUSTC\\n'
/opt/rust/bin/rustc -vV
printf 'P11LAB_CARGO\\n'
/opt/rust/bin/cargo --version
printf 'P11LAB_PROTOC\\n'
/opt/protoc/bin/protoc --version
/opt/rust/bin/cargo build --locked --offline --target x86_64-unknown-linux-gnu --target-dir /out/target
printf 'P11LAB_HELLO\\n'
/out/target/x86_64-unknown-linux-gnu/debug/p11lab-canary
/opt/protoc/bin/protoc --proto_path=/canary --descriptor_set_out=/out/descriptor.pb /canary/canary.proto
printf 'P11LAB_DESCRIPTOR\\n'
/usr/bin/od -An -v -tx1 /out/descriptor.pb | /usr/bin/tr -d ' \\n'
printf '\\nP11LAB_END\\n'
'''


def _run_role(attempt: Any, image: str, argv: list[str], *, fixture: Path | None = None,
              timeout_seconds: int = 120) -> JsonObject:
    """Use the shared Docker boundary with the toolchain's stricter tmpfs quotas."""
    import json
    from dataclasses import asdict

    from .docker import DockerError
    from .tool_builds import _options, context_identity

    timeout_seconds = _canary_timeout(timeout_seconds)
    attempt.serial += 1
    name = 'p11lab-tool-' + attempt.labels['org.p11lab.tool-build'] + '-' + str(attempt.serial)
    options = _options(readonly=True, user='65532:65532')
    tmp = '/tmp:rw,nosuid,nodev,size=536870912,nr_inodes=16384,mode=1777'
    options[options.index(tmp)] = '/tmp:rw,nosuid,nodev,size=134217728,nr_inodes=16384,mode=1777'
    options += ['--tmpfs', '/out:rw,nosuid,nodev,exec,size=268435456,nr_inodes=10000,mode=1777']
    mounts = []
    context = None
    if fixture is not None:
        if ',' in str(fixture):
            raise ToolchainError('unsupported fixture mount path')
        mount = f'type=bind,src={fixture},dst=/canary,readonly'
        options += ['--mount', mount]
        mounts.append(mount)
        context = context_identity(fixture)
    command = ['-i', 'PATH=/usr/bin:/bin', 'LC_ALL=C', 'HOME=/tmp/home', 'CARGO_HOME=/tmp/cargo',
               'CARGO_NET_OFFLINE=true', 'RUSTC=/opt/rust/bin/rustc', 'TMPDIR=/tmp', *argv]
    record: JsonObject = {'name': name, 'image': image, 'argv': command, 'options': options,
                          'labels': attempt.labels, 'fixture': context, 'timeout_seconds': timeout_seconds}
    attempt.result['stages'].append(record)
    try:
        container = attempt.engine.create(image, command, options, attempt.labels, name)
    except DockerError as error:
        if error.resource and error.resource[0] == 'container':
            attempt.containers.append(error.resource[1])
        raise
    attempt.containers.append(container)
    record['container'] = container
    before = json.loads(attempt.engine.command(['container', 'inspect', container]).stdout)[0]
    record['inspection_before'] = before
    verify_role_boundary(before, image, command, mounts)
    native = attempt.engine.execute(container, timeout_seconds, lambda: None)
    record['native'] = asdict(native)
    after = json.loads(attempt.engine.command(['container', 'inspect', container]).stdout)[0]
    record['inspection_after'] = after
    require_native_success(record['native'], after['State'])
    if fixture is not None and context_identity(fixture) != context:
        raise ToolchainError('canary source changed during execution')
    return record


def _verify_launched_hashes(attempt: Any, image: str, inventory: JsonObject, closure: JsonObject) -> JsonObject:
    paths = sorted(closure)
    record = _run_role(attempt, image, ['/usr/bin/sha256sum', *('/' + p for p in paths)])
    expected = ''.join(inventory['files'][p]['sha256'] + '  /' + p + '\n' for p in paths)
    if record['native']['stdout'] != expected:
        raise ToolchainError('actual executable or library hashes differ')
    return {'paths': paths, 'stage': record['container']}


def _dynamic_loader_roots(inventory: JsonObject) -> list[tuple[str, str, str]]:
    """Derive the exact unique dynamic executable roots from the selected roster."""
    result = []
    seen: set[str] = set()
    for path in _toolchain_roots(inventory):
        real = _resolve(path, inventory)
        if real in seen:
            continue
        seen.add(real)
        meta = inventory['elfs'].get(real)
        if meta is None:
            raise ToolchainError('missing executable ELF root: ' + real)
        if meta['interpreter']:
            result.append((path, real, meta['interpreter']))
    return result


def _check_native_loader_output(inventory: JsonObject, closure: JsonObject, real: str, stdout: str) -> list[str]:
    """Compare one native loader's complete transitive set with closed file paths."""
    import re

    resolved: list[str] = []
    for line in stdout.splitlines():
        if 'not found' in line:
            raise ToolchainError('native loader dependency unavailable: ' + line)
        match = re.search(r'(?:=>\s+)?(/\S+)\s+\(0x[0-9a-fA-F]+\)', line)
        if match:
            resolved.append(resolve_native_loader_path(match.group(1), inventory))
        elif 'linux-vdso.so.1' not in line:
            raise ToolchainError('unsupported native loader observation: ' + line)
    expected: set[str] = set()
    pending = list(closure[real]['resolved_dependencies'])
    while pending:
        dependency = pending.pop()
        if dependency not in expected and dependency != real:
            expected.add(dependency)
            pending.extend(closure[dependency]['resolved_dependencies'])
    if set(resolved) != expected:
        raise ToolchainError('native loader resolution differs from closed inventory: ' + real)
    return sorted(resolved)


def _verify_native_loaders(attempt: Any, image: str, inventory: JsonObject, closure: JsonObject) -> list[JsonObject]:
    observed = []
    roots = _dynamic_loader_roots(inventory)
    if not roots:
        raise ToolchainError('native loader controls incomplete')
    for path, real, loader in roots:
        record = _run_role(attempt, image, [loader, '--list', '/' + path])
        resolved = _check_native_loader_output(inventory, closure, real, record['native']['stdout'])
        observed.append({'executable': real, 'path': path, 'loader': loader,
                         'resolved': resolved, 'stage': record['container']})
    return observed

def _build_selected_toolchain(request: ToolchainRequest) -> JsonObject:
    with _Deadline() as budget:
        return _build_selected_toolchain_inner(request, budget)


def _build_selected_toolchain_inner(request: ToolchainRequest, budget: '_Deadline') -> JsonObject:
    from .catalog import package_data
    from .models import ArtifactRef
    from .proxy_inputs import _regular_bytes, load_proxy_tool_records, verify_selected_proxy_inputs
    from .tool_builds import (_Attempt, _file, _install, _new_docker, _recipe_identity, _stage_packages, _write,
                              bind_package_members, context_identity)
    from .tool_downloads import safe_directory
    from .tool_inputs import load_tool_input_lock
    from .tool_rootfs import _transfer, bounded_install_policy

    if type(request.cache) is not ProxyInputCache:
        raise ToolchainError('typed ProxyInputCache required')
    output = Path(request.output_dir).absolute()
    safe_directory(output.parent)
    if output.exists() or output.is_symlink() or ',' in str(output):
        raise ToolchainError('output must be a fresh safe directory')
    output.mkdir(mode=0o755)
    result: JsonObject = {'schema_version': 2, 'kind': 'local-proxy-toolchain', 'status': 'incomplete',
                          'rights': 'unreviewed', 'authority': 'not-established',
                          'candidate_build': 'not-run', 'qualification': 'not-performed',
                          'stages': [], 'cleanup_errors': [], 'whole_attempt_seconds': 600}
    attempt = _Attempt(_new_docker(), output, result)
    kept = None
    complete = False
    error: BaseException | None = None
    try:
        budget.check('preflight')
        result['inputs'] = verify_selected_proxy_inputs(request.cache)
        budget.check('preflight')
        lock = load_tool_input_lock('consumer', target='debian13-amd64')
        base_id = lock['base_image'].split('@')[-1]
        base = attempt.engine.image(ArtifactRef('docker', base_id, base_id.removeprefix('sha256:'), 'linux/amd64'))
        result['base'] = {'reference': lock['base_image'], 'engine_id': base_id,
                          'layers': base['RootFS']['Layers'], 'inspection': base}
        result['bounded_policy'] = bounded_install_policy()
        result['producer_resources'] = _recipe_identity()
        recipe = package_data('tool-builds/proxy-toolchain-v1.json').read_bytes()
        result['role_policy'] = validate_role_policy(recipe)
        result['recipe'] = {'sha256': hashlib.sha256(recipe).hexdigest(), 'size': len(recipe)}
        result['driver'] = _file(Path(__file__))
        result['role_resources'] = _role_resources()
        result['input_receipt'] = _file(request.cache.debian_receipt)
        budget.check('work')
        staged = output / 'staged'
        staged.mkdir()
        _stage_packages(lock, 'compiler', request.cache.debian_receipt.parent, staged)
        compiler, compiler_inventory = _install(attempt, lock, 'compiler', staged, base_id,
                                                 extra=" printf 'P11LAB_PACKAGE_INVENTORY\\n';")
        result['compiler'] = compiler
        result['package_members'] = bind_package_members(lock, 'compiler', request.cache.debian_receipt.parent,
                                                         compiler_inventory)
        records = load_proxy_tool_records()
        rust = [r for r in records if r.kind == 'proxy-rust-dist']
        proto = [r for r in records if r.kind == 'proxy-protobuf']
        if len(rust) != 3 or len(proto) != 1:
            raise ToolchainError('selected tool component roster differs')

        def raw_record(record: Any) -> bytes:
            path: Path = request.cache.payload_root / record.path
            data: bytes = _regular_bytes(path, record.size)
            if len(data) != record.size or hashlib.sha256(data).hexdigest() != record.sha256:
                raise ToolchainError('selected tool payload changed before assembly')
            return data

        def components() -> Iterable[tuple[bytes, str, str]]:
            for record in rust:
                filename = PurePosixPath(record.path).name
                prefix = filename.removesuffix('.tar.xz')
                component = prefix.split('-1.98.1')[0]
                if component == 'rust-std':
                    component = 'rust-std-x86_64-unknown-linux-gnu'
                yield decode_rust_archive(raw_record(record)), prefix, component

        assembled = output / 'assembled-filesystem.tar'
        result['assembly'] = assemble_image_archive(output / 'compiler-filesystem.tar', components(),
                                                    raw_record(proto[0]), assembled)
        assembled_inventory = inventory_toolchain_archive(assembled)
        for path, expected in compiler_inventory['files'].items():
            observed_file = assembled_inventory['files'].get(path, {})
            if any(observed_file.get(k) != value for k, value in expected.items()):
                raise ToolchainError('compiler filesystem changed during assembly: ' + path)
        if any(any(assembled_inventory['aliases'].get(path, {}).get(k) != v for k, v in value.items())
               for path, value in compiler_inventory['aliases'].items()):
            raise ToolchainError('compiler aliases changed during assembly')
        for path, spec in result['assembly']['files'].items():
            observed_file = assembled_inventory['files'].get(path, {})
            if any(observed_file.get(k) != value for k, value in spec.items()):
                raise ToolchainError('assembled component differs from archive: ' + path)
        result['elf_closure'] = resolve_toolchain_closure(assembled_inventory, _toolchain_roots(assembled_inventory))
        _write(output / 'assembled-filesystem.json', assembled_inventory)
        changes = ['--change', 'ENTRYPOINT []', '--change', 'CMD []', '--change',
                   'LABEL org.p11lab.admission=unreviewed-local-tool-only']
        for key, value in attempt.labels.items():
            changes += ['--change', 'LABEL ' + key + '=' + value]
        image_id = attempt.engine.command(['image', 'import', '--platform', 'linux/amd64', *changes,
                                           str(assembled)], timeout=120).stdout.strip()
        if not image_id.startswith('sha256:') or len(image_id) != 71:
            raise ToolchainError('invalid imported toolchain image identity')
        attempt.images.append(image_id)
        info = attempt.engine.image(ArtifactRef('docker', image_id, image_id.removeprefix('sha256:'), 'linux/amd64'))
        result['image'] = {'engine_id': image_id, 'config_sha256': image_id.removeprefix('sha256:'),
                           'layers': info['RootFS']['Layers'], 'inspection': info,
                           'composition': 'flattened-import-of-assembled-filesystem',
                           'compiler_source_image': compiler['engine_id'], 'archive': _file(assembled)}
        snapshot = attempt.run(image_id, ['/bin/true'])
        readback = output / 'actual-image-filesystem.tar'
        _transfer(attempt, ['docker', 'export', snapshot], 'actual-image-export', destination=readback)
        actual = inventory_toolchain_archive(readback)
        compare_image_inventories(assembled_inventory, actual)
        _write(output / 'actual-image-filesystem.json', actual)
        result['launched_hashes'] = _verify_launched_hashes(attempt, image_id, actual, result['elf_closure'])
        result['loader_observations'] = _verify_native_loaders(attempt, image_id, actual, result['elf_closure'])
        fixture = output / 'canary'
        _canary_fixture(fixture)
        result['canary_context'] = context_identity(fixture)
        stage = _run_role(attempt, image_id, ['/bin/sh', '-ec', _canary_script()], fixture=fixture)
        check_canary_output(stage['native']['stdout'])
        result['canary'] = {'stage': stage['container'], 'status': 'matched-independent-output'}
        budget.check('work')
        complete = True
        kept = image_id
    except BaseException as failure:
        error = failure
    return _finalize_attempt(attempt, output, result, 'manifest.json', 'local-toolchain-observed',
                             complete, kept, error, budget)

def compare_image_inventories(expected: JsonObject, actual: JsonObject) -> None:
    """Compare complete bytes, metadata and alias meaning across image import."""
    if any(expected.get(k, {}) != actual.get(k, {}) for k in ('regular_bytes', 'files', 'elfs', 'directories', 'devices')):
        raise ToolchainError('image regular files or ELF inventory differ')
    left, right = expected['aliases'], actual['aliases']
    if left.keys() != right.keys():
        raise ToolchainError('image alias roster differs')
    for name in left:
        if (any(left[name].get(k) != right[name].get(k) for k in ('kind', 'mode', 'uid', 'gid')) or
                _resolve(name, expected) != _resolve(name, actual)):
            raise ToolchainError('image alias resolution differs: ' + name)


def verify_proxy_toolchain(output: Path, *, manifest_sha256: str, cache: ProxyInputCache | None,
                           verification_dir: Path | None = None) -> JsonObject:
    """Reverify protected bytes, source policy, contexts and actual installed image."""
    with _Deadline() as budget:
        return _verify_proxy_toolchain_inner(output, manifest_sha256, cache, verification_dir, budget)


def _verify_proxy_toolchain_inner(output: Path, manifest_sha256: str, cache: ProxyInputCache | None,
                                  verification_dir: Path | None, budget: '_Deadline') -> JsonObject:
    import json
    from .catalog import package_data
    from .models import ArtifactRef
    from .proxy_inputs import verify_selected_proxy_inputs
    from .tool_builds import (_Attempt, _file, _new_docker, _read_regular, _recipe_identity, context_identity)
    from .tool_downloads import safe_directory
    from .tool_rootfs import _transfer, bounded_install_policy

    budget.check('preflight')
    output = Path(output).absolute()
    if type(cache) is not ProxyInputCache or verification_dir is None:
        safe_directory(output)
        raw = _read_regular(output / 'manifest.json', maximum=16 * 1024**2)
        budget.check('preflight')
        if not isinstance(manifest_sha256, str) or len(manifest_sha256) != 64 or hashlib.sha256(raw).hexdigest() != manifest_sha256:
            raise ToolchainError('changed or unsealed toolchain manifest')
        raise ToolchainError('typed cache and fresh verification directory required')
    destination = Path(verification_dir).absolute()
    safe_directory(destination.parent)
    if destination.exists() or destination.is_symlink() or ',' in str(destination):
        raise ToolchainError('verification directory must be fresh')
    destination.mkdir(mode=0o755)
    result: JsonObject = {'schema_version': 2, 'kind': 'local-proxy-toolchain-warm-verification', 'status': 'incomplete',
                          'manifest_sha256': manifest_sha256, 'stages': [], 'cleanup_errors': [],
                          'source_attempt_completion': 'unconfirmed',
                          'verification_scope': 'selected-bytes-and-local-image'}
    attempt = _Attempt(_new_docker(), destination, result)
    success = False
    error: BaseException | None = None
    try:
        budget.check('preflight')
        safe_directory(output)
        raw = _read_regular(output / 'manifest.json', maximum=16 * 1024**2)
        budget.check('preflight')
        if not isinstance(manifest_sha256, str) or len(manifest_sha256) != 64 or hashlib.sha256(raw).hexdigest() != manifest_sha256:
            raise ToolchainError('changed or unsealed toolchain manifest')
        manifest = _parse_toolchain_observation(raw, manifest_sha256)
        recipe = package_data('tool-builds/proxy-toolchain-v1.json').read_bytes()
        policy = validate_role_policy(recipe)
        if (manifest.get('schema_version') != 2 or manifest.get('kind') != 'local-proxy-toolchain' or
                manifest.get('status') != 'observation-prepared' or manifest.get('attempt_completion') != 'unconfirmed' or manifest.get('rights') != 'unreviewed' or
                manifest.get('authority') != 'not-established' or manifest.get('candidate_build') != 'not-run' or
                manifest.get('qualification') != 'not-performed' or manifest.get('cleanup_errors') or
                manifest.get('bounded_policy') != bounded_install_policy() or manifest.get('role_policy') != policy or
                manifest.get('recipe') != {'sha256': hashlib.sha256(recipe).hexdigest(), 'size': len(recipe)} or
                manifest.get('producer_resources') != _recipe_identity() or manifest.get('driver') != _file(Path(__file__)) or
                manifest.get('role_resources') != _role_resources()):
            raise ToolchainError('toolchain receipt, code or policy changed')
        if (manifest.get('inputs') != verify_selected_proxy_inputs(cache) or
                manifest.get('input_receipt') != _file(cache.debian_receipt)):
            raise ToolchainError('selected input bytes or provenance observations changed')
        budget.check('preflight')
        evidence = manifest.get('evidence')
        required = {'compiler-filesystem.tar', 'compiler-filesystem.json', 'compiler-packages.json',
                    'assembled-filesystem.tar', 'assembled-filesystem.json',
                    'actual-image-filesystem.tar', 'actual-image-filesystem.json'}
        if not isinstance(evidence, dict) or not required <= evidence.keys():
            raise ToolchainError('incomplete toolchain evidence roster')
        for name, spec in evidence.items():
            if _safe_member(name) != name or '/' in name or _file(output / name) != spec:
                raise ToolchainError('toolchain evidence changed: ' + name)
            budget.check('preflight')
        if context_identity(output / 'canary') != manifest.get('canary_context'):
            raise ToolchainError('canary context changed')
        staged = [s['input_contexts']['/rootfs/inputs'] for s in manifest['stages']
                  if '/rootfs/inputs' in s.get('input_contexts', {})]
        if len(staged) != 1 or context_identity(output / 'staged') != staged[0]:
            raise ToolchainError('compiler input context changed')
        assembled = inventory_toolchain_archive(output / 'assembled-filesystem.tar')
        retained = inventory_toolchain_archive(output / 'actual-image-filesystem.tar')
        if (assembled != json.loads((output / 'assembled-filesystem.json').read_bytes()) or
                retained != json.loads((output / 'actual-image-filesystem.json').read_bytes())):
            raise ToolchainError('retained inventory differs from archive bytes')
        compare_image_inventories(assembled, retained)
        if resolve_toolchain_closure(retained, _toolchain_roots(retained)) != manifest.get('elf_closure'):
            raise ToolchainError('retained ELF closure differs from receipt')
        _verify_receipt_controls(manifest, output, retained)
        budget.check('preflight')
        image = manifest['image']
        if (image['composition'] != 'flattened-import-of-assembled-filesystem' or
                image['archive'] != _file(output / 'assembled-filesystem.tar') or
                image['engine_id'] != manifest.get('retained_product_image') or
                image['config_sha256'] != image['engine_id'].removeprefix('sha256:') or
                manifest.get('canary', {}).get('status') != 'matched-independent-output'):
            raise ToolchainError('invalid retained image or canary identity')

        budget.check('work')
        observed = attempt.engine.image(ArtifactRef('docker', image['engine_id'], image['config_sha256'], 'linux/amd64'))
        if observed['Id'] != image['engine_id'] or observed['RootFS']['Layers'] != image['layers']:
            raise ToolchainError('installed image config or layers changed')
        snapshot = attempt.run(image['engine_id'], ['/bin/true'])
        archive = destination / 'warm-filesystem.tar'
        _transfer(attempt, ['docker', 'export', snapshot], 'warm-image-export', destination=archive)
        current = inventory_toolchain_archive(archive)
        compare_image_inventories(retained, current)
        result['image'] = {'engine_id': observed['Id'], 'layers': observed['RootFS']['Layers'],
                           'filesystem_archive': _file(archive)}
        budget.check('work')
        success = True
    except BaseException as failure:
        error = failure
    return _finalize_attempt(attempt, destination, result, 'warm-verification.json', 'local-byte-verification-observed',
                             success, None, error, budget, collect_evidence=False)

def _role_resources() -> JsonObject:
    from .catalog import package_data
    from .tool_builds import _file

    root = Path(__file__).parent
    code = {name: _file(root / name) for name in ('proxy_inputs.py', 'proxy_supervisor.py')}
    names = ('source-v1.json', 'rust-v1.json', 'protoc-v1.json', 'crates-v1.json',
             'build-selection-v1.json', 'rust/cargo.tar.xz.asc', 'rust/rust-key.gpg.ascii',
             'rust/rust-manifest.toml', 'rust/rust-manifest.toml.asc', 'rust/rust-std.tar.xz.asc',
             'rust/rustc.tar.xz.asc')
    data = {}
    for name in names:
        raw = package_data('tool-inputs/proxy/' + name).read_bytes()
        data[name] = {'sha256': hashlib.sha256(raw).hexdigest(), 'size': len(raw)}
    return {'code': code, 'selection': data}


def resolve_native_loader_path(path: str, inventory: JsonObject) -> str:
    """Resolve observed loader paths, narrowly allowing the Rust origin spelling."""
    if not path.startswith('/') or '\x00' in path:
        raise ToolchainError('invalid native loader path')
    parts = list(PurePosixPath(path).parts[1:])
    if '..' not in parts:
        return _resolve(path, inventory)
    if not path.startswith('/opt/rust/bin/../lib/'):
        raise ToolchainError('unsupported native loader origin')
    stack: list[str] = []
    for part in parts:
        if part == '..':
            if not stack:
                raise ToolchainError('escaping native loader path')
            stack.pop()
        elif part not in ('', '.'):
            stack.append(part)
            if '/'.join(stack) in inventory['aliases']:
                raise ToolchainError('native loader path traverses an alias')
    normalized = '/'.join(stack)
    if not normalized.startswith('opt/rust/lib/'):
        raise ToolchainError('native loader path leaves Rust library prefix')
    return _resolve(normalized, inventory)


def validate_role_policy(raw: bytes) -> JsonObject:
    """Require the package-selected fixed role policy, never a receipt-selected policy."""
    import json

    if hashlib.sha256(raw).hexdigest() != 'c4bb2453dee9c41e136620b39262a948b3b6b1a74946fdcf1d515b213ba9f743':
        raise ToolchainError('installed toolchain role policy changed')
    value: JsonObject = json.loads(raw)
    return value


def require_native_success(native: JsonObject, state: JsonObject) -> None:
    """Incomplete native status, timeout, truncation or an active PID is failure."""
    if (type(native.get('returncode')) is not int or native['returncode'] != 0 or
            any(native.get(k) is not False for k in ('timed_out', 'stdout_truncated', 'stderr_truncated')) or
            state.get('Running') is not False or type(state.get('Pid')) is not int or state['Pid'] != 0):
        raise ToolchainError('native stage failed or is incomplete')


def _verify_receipt_controls(manifest: JsonObject, output: Path, inventory: JsonObject) -> None:
    from .tool_rootfs import bounded_install_policy

    installs = manifest.get('bounded_installations', [])
    if len(installs) != 1:
        raise ToolchainError('bounded compiler installation is incomplete')
    install = installs[0]
    policy = bounded_install_policy()
    if (install.get('policy') != policy or install.get('bytes') != policy['rootfs_bytes'] or
            install.get('inodes') != policy['rootfs_inodes'] or
            install.get('setup_image') != manifest.get('base', {}).get('engine_id') or
            install.get('payload_capabilities_observed') != 'zero-effective-permitted-inheritable' or
            install.get('payload_no_new_privileges') != 1 or
            install.get('cleanup') != 'exact-owned-containers-and-volume-removed'):
        raise ToolchainError('bounded compiler installation evidence differs')
    stages = manifest.get('stages', [])
    roots = _dynamic_loader_roots(inventory)
    if not roots or len(stages) != 5 + len(roots):
        raise ToolchainError('native stage roster is incomplete')
    for stage in stages:
        require_native_success(stage.get('native', {}), stage.get('inspection_after', {}).get('State', {}))
    canary_stage = stages[-1]
    if (manifest.get('canary', {}).get('stage') != canary_stage.get('container') or
            canary_stage.get('argv', [])[-3:] != ['/bin/sh', '-ec', _canary_script()]):
        raise ToolchainError('canary stage identity differs')
    check_canary_output(canary_stage['native']['stdout'])
    paths = sorted(manifest['elf_closure'])
    hashes = manifest.get('launched_hashes', {})
    if hashes.get('stage') != stages[3].get('container') or hashes.get('paths') != paths:
        raise ToolchainError('launched hash stage differs')
    expected_hashes = ''.join(manifest['elf_closure'][p]['sha256'] + '  /' + p + '\n' for p in paths)
    if stages[3]['native']['stdout'] != expected_hashes:
        raise ToolchainError('launched file hash observations differ')
    prefix = ['-i', 'PATH=/usr/bin:/bin', 'LC_ALL=C', 'HOME=/tmp/home', 'CARGO_HOME=/tmp/cargo',
              'CARGO_NET_OFFLINE=true', 'RUSTC=/opt/rust/bin/rustc', 'TMPDIR=/tmp']
    commands = [['/usr/bin/sha256sum', *('/' + p for p in paths)]]
    commands += [[loader, '--list', '/' + path] for path, _, loader in roots]
    commands.append(['/bin/sh', '-ec', _canary_script()])
    image = manifest['image']['engine_id']
    for offset, command in enumerate(commands):
        stage = stages[3 + offset]
        if stage.get('argv') != prefix + command or stage.get('timeout_seconds') != 120:
            raise ToolchainError('native stage command or deadline differs')
        mounts = [f'type=bind,src={output / "canary"},dst=/canary,readonly'] if stage is canary_stage else []
        verify_role_boundary(stage['inspection_before'], image, prefix + command, mounts)
    loaders = manifest.get('loader_observations', [])
    if len(loaders) != len(roots):
        raise ToolchainError('native loader stage roster differs')
    for observation, (path, real, loader), stage in zip(loaders, roots, stages[4:-1]):
        resolved = _check_native_loader_output(inventory, manifest['elf_closure'], real, stage['native']['stdout'])
        if observation != {'executable': real, 'path': path, 'loader': loader,
                           'resolved': resolved, 'stage': stage['container']}:
            raise ToolchainError('native loader observation differs')


def _canary_timeout(value: int) -> int:
    if type(value) is not int or not 0 < value <= 120:
        raise ToolchainError('unsupported canary time limit')
    return value


def verify_role_boundary(observed: JsonObject, image: str, command: list[str], mounts: list[str]) -> None:
    """Verify stricter role quotas, then apply the shared execution boundary."""
    import copy
    from .tool_builds import verify_execution_boundary

    expected_tmpfs = {'/tmp': 'rw,nosuid,nodev,size=134217728,nr_inodes=16384,mode=1777',
                      '/out': 'rw,nosuid,nodev,exec,size=268435456,nr_inodes=10000,mode=1777'}
    expected_ulimits = [{'Name': 'fsize', 'Soft': 268435456, 'Hard': 268435456},
                        {'Name': 'nofile', 'Soft': 256, 'Hard': 256}]
    host = observed['HostConfig']
    if host.get('Tmpfs') != expected_tmpfs or host.get('Ulimits') != expected_ulimits:
        raise ToolchainError('actual canary quota or ulimit differs')
    shared_view = copy.deepcopy(observed)
    shared_view['HostConfig']['Tmpfs'] = {'/tmp': 'rw,nosuid,nodev,size=536870912,nr_inodes=16384,mode=1777'}
    verify_execution_boundary(shared_view, image, command, mounts, readonly=True, user='65532:65532')


def _toolchain_roots(inventory: JsonObject) -> list[str]:
    roots = ['opt/rust/bin/rustc', 'opt/rust/bin/cargo', 'opt/protoc/bin/protoc',
             'usr/bin/cc', 'usr/bin/as', 'usr/bin/ld', 'usr/bin/env', 'usr/bin/sha256sum',
             'usr/bin/od', 'usr/bin/tr', 'usr/bin/mkdir', 'usr/bin/sh']
    compiler = [p for p in inventory['elfs'] if p.endswith(('/cc1', '/collect2'))]
    if any(sum(path.endswith('/' + name) for path in compiler) != 1 for name in ('cc1', 'collect2')):
        raise ToolchainError('missing or ambiguous GCC subprocess root')
    return roots + compiler


def _failure_evidence(output: Path) -> JsonObject:
    """Record bounded partial-file metadata without hashing after a failure."""
    from .tool_builds import MAX_EXPORT

    evidence: JsonObject = {}
    try:
        for index, path in enumerate(output.iterdir()):
            if index >= 512:
                evidence['__roster__'] = {'availability': 'truncated', 'limit': 512}
                break
            if path.name == 'manifest.json':
                continue
            try:
                info = path.lstat()
                if stat.S_ISDIR(info.st_mode):
                    continue
                row: JsonObject = {'size': info.st_size, 'mode': info.st_mode & 0o7777}
                if not stat.S_ISREG(info.st_mode):
                    row['availability'] = 'nonregular'
                elif info.st_size > MAX_EXPORT:
                    row['availability'] = 'over-limit'
                else:
                    row['availability'] = 'unhashed-after-failure'
                evidence[path.name] = row
            except OSError as error:
                evidence[path.name] = {'availability': 'unreadable', 'errno': error.errno}
    except OSError as error:
        evidence['__roster__'] = {'availability': 'unreadable', 'errno': error.errno}
    return evidence


def _clock() -> float:
    import time
    return time.monotonic()


class _DeadlineSignal(BaseException):
    pass


class _ReserveSignal(BaseException):
    pass


class _Deadline:
    """Whole observation deadline plus finite emergency cleanup/receipt allowances."""
    def __init__(self) -> None:
        self.start = 0.0
        self.end = 0.0
        self.phase = 'preflight'
        self.expired_phase: str | None = None
        self.old_handler: Any = None
        self.published: tuple[Path, JsonObject, str] | None = None

    def __enter__(self) -> '_Deadline':
        import signal
        import threading

        if threading.current_thread() is not threading.main_thread() or signal.getitimer(signal.ITIMER_REAL)[0]:
            raise ToolchainError('exclusive main-thread deadline required')
        self.start = _clock()
        self.end = self.start + 600.0
        self.old_handler = signal.getsignal(signal.SIGALRM)
        def expired(signum: int, frame: Any) -> None:
            self.expired_phase = self.phase
            raise _DeadlineSignal()
        signal.signal(signal.SIGALRM, expired)
        signal.setitimer(signal.ITIMER_REAL, 600.0)
        return self

    def check(self, phase: str) -> None:
        self.phase = phase
        if _clock() >= self.end:
            self.expired_phase = phase
            raise TimeoutError('whole toolchain observation deadline exceeded during ' + phase)

    def reserve(self, seconds: int) -> None:
        import signal

        def expired(signum: int, frame: Any) -> None:
            raise _ReserveSignal()
        signal.signal(signal.SIGALRM, expired)
        signal.setitimer(signal.ITIMER_REAL, float(seconds))

    def details(self) -> JsonObject:
        return {'limit_seconds': 600, 'elapsed_seconds': max(0.0, _clock() - self.start),
                'phase': self.phase, 'expired_phase': self.expired_phase,
                'cleanup_reserve_seconds': 30, 'failure_receipt_reserve_seconds': 10}

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> Literal[False]:
        import signal

        if self.published is not None:
            try:
                if exc is None:
                    self.check('return')
                elif isinstance(exc, _DeadlineSignal):
                    self.expired_phase = self.phase
                    raise TimeoutError('whole toolchain observation deadline exceeded during ' + self.phase)
            except (TimeoutError, _DeadlineSignal) as error:
                output, result, name = self.published
                timeout = _as_timeout(error, self)
                result['status'] = 'failed'
                result['error'] = {'type': type(timeout).__name__, 'message': str(timeout)}
                result['deadline'] = self.details()
                try:
                    self.reserve(10)
                    _atomic_receipt(output / name, result)
                except BaseException as failure:
                    timeout.add_note('failure receipt unavailable: ' + type(failure).__name__)
                finally:
                    signal.setitimer(signal.ITIMER_REAL, 0)
                    signal.signal(signal.SIGALRM, self.old_handler)
                raise timeout
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, self.old_handler)
        if isinstance(exc, _DeadlineSignal):
            raise TimeoutError('whole toolchain observation deadline exceeded during ' + self.phase)
        return False


def _as_timeout(error: BaseException, budget: _Deadline) -> BaseException:
    if isinstance(error, _DeadlineSignal):
        budget.expired_phase = budget.phase
        return TimeoutError('whole toolchain observation deadline exceeded during ' + budget.phase)
    return error


def _atomic_receipt(path: Path, result: JsonObject) -> None:
    import os
    from uuid import uuid4

    raw = _receipt_bytes(result)
    if len(raw) > 16 * 1024**2:
        raise ToolchainError('attempt receipt exceeds bound')
    temporary = path.with_name('.' + path.name + '.' + uuid4().hex + '.tmp')
    with temporary.open('xb') as stream:
        stream.write(raw)
    os.replace(temporary, path)


def _finalize_attempt(attempt: Any, output: Path, result: JsonObject, receipt: str,
                      success_status: str, complete: bool, keep: str | None,
                      error: BaseException | None, budget: _Deadline,
                      *, collect_evidence: bool = True) -> JsonObject:
    """Finish under the whole deadline; on failure use only finite cleanup reserves."""
    from .tool_builds import _file

    cleanup_done = False
    if error is None and complete:
        try:
            budget.check('finalization')
            if collect_evidence:
                evidence: JsonObject = {}
                for path in output.iterdir():
                    if path.is_file() and path.name != receipt:
                        try:
                            evidence[path.name] = _file(path)
                        except Exception as failure:
                            result['evidence_failure'] = {'path': path.name, 'type': type(failure).__name__,
                                                          'message': str(failure),
                                                          'errno': failure.errno if isinstance(failure, OSError) else None}
                            raise
                        budget.check('finalization')
                result['evidence'] = evidence
            budget.check('cleanup')
            attempt.cleanup(keep=keep)
            cleanup_done = True
            budget.check('cleanup')
            if result['cleanup_errors']:
                raise ToolchainError('owned cleanup unconfirmed')
            result['retained_product_image'] = keep
            result['status'] = 'observation-prepared'
            result['attempt_completion'] = 'unconfirmed'
            budget.check('receipt')
            result['deadline'] = budget.details()
            envelope = {'schema': 'p11lab.toolchain-observation.v2', 'state': 'provisional', 'manifest': result}
            _atomic_receipt(output / receipt, envelope)
            budget.published = (output, result, receipt)
            budget.check('receipt')
            witness = {'kind': 'bounded-api-return',
                       'operation': 'build-observation' if result['kind'] == 'local-proxy-toolchain' else 'byte-verification',
                       'receipt_sha256': hashlib.sha256(_receipt_bytes(envelope)).hexdigest(),
                       'caller_observation': 'return-must-be-observed-by-caller', 'authority': 'not-established',
                       'prior_build_attempt_completion': 'unconfirmed'}
            return {**result, 'status': success_status, 'completion_witness': witness}
        except BaseException as failure:
            error = failure
    if error is None:
        error = ToolchainError('toolchain observation incomplete')
    if not isinstance(error, (_DeadlineSignal, TimeoutError)) and _clock() >= budget.end:
        result['operation_error'] = {'type': type(error).__name__, 'message': str(error)}
        budget.expired_phase = budget.phase
        error = TimeoutError('whole toolchain observation deadline exceeded during ' + budget.phase)
    error = _as_timeout(error, budget)
    result['error'] = {'type': type(error).__name__, 'message': str(error)}
    result['status'] = 'failed'
    if not cleanup_done:
        try:
            budget.reserve(30)
            attempt.cleanup(keep=None)
        except BaseException as cleanup_error:
            result['cleanup_errors'].append('cleanup unconfirmed: ' + type(cleanup_error).__name__)
    if result['cleanup_errors']:
        result['status'] = 'failed-cleanup'
    result['retained_product_image'] = keep if cleanup_done else None
    if result['cleanup_errors']:
        result['product_image_cleanup'] = 'unconfirmed'
        result['product_image_candidate'] = result.get('image', {}).get('engine_id')
    result['deadline'] = budget.details()
    try:
        budget.reserve(10)
        result['evidence'] = _failure_evidence(output)
        evidence_failure = result.get('evidence_failure')
        if evidence_failure and evidence_failure['path'] in result['evidence']:
            row = result['evidence'][evidence_failure['path']]
            if row.get('availability') != 'over-limit':
                row['availability'] = 'unreadable'
            row['error'] = {key: evidence_failure[key] for key in ('type', 'message', 'errno')}
        _atomic_receipt(output / receipt, result)
    except BaseException as failure:
        error.add_note('failure receipt unavailable: ' + type(failure).__name__)
    raise error


def _receipt_bytes(value: JsonObject) -> bytes:
    import json
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def _parse_toolchain_observation(raw: bytes, manifest_sha256: str) -> JsonObject:
    from .tool_inputs import _json

    if not isinstance(manifest_sha256, str) or len(manifest_sha256) != 64 or hashlib.sha256(raw).hexdigest() != manifest_sha256:
        raise ToolchainError('changed or unsealed toolchain manifest')
    parser = cast(Any, _json)
    data = parser(raw)
    if (not isinstance(data, dict) or data.keys() != {'schema', 'state', 'manifest'} or
            data['schema'] != 'p11lab.toolchain-observation.v2' or data['state'] != 'provisional' or
            not isinstance(data['manifest'], dict)):
        raise ToolchainError('invalid provisional toolchain observation')
    manifest = data['manifest']
    allowed = {'schema_version', 'kind', 'status', 'attempt_completion', 'rights', 'authority',
               'candidate_build', 'qualification', 'stages', 'cleanup_errors', 'whole_attempt_seconds',
               'inputs', 'base', 'bounded_policy', 'producer_resources', 'role_policy', 'recipe', 'driver',
               'role_resources', 'input_receipt', 'bounded_installations', 'rootfs_transfers', 'compiler',
               'package_members', 'assembly', 'elf_closure', 'image', 'launched_hashes', 'loader_observations',
               'canary_context', 'canary', 'retained_product_image', 'deadline', 'evidence'}
    if (not set(manifest) <= allowed or manifest.get('schema_version') != 2 or
            manifest.get('kind') != 'local-proxy-toolchain' or manifest.get('status') != 'observation-prepared' or
            manifest.get('attempt_completion') != 'unconfirmed'):
        raise ToolchainError('invalid provisional toolchain manifest')
    return cast(JsonObject, manifest)


def read_toolchain_observation(output: Path, *, manifest_sha256: str,
                               require_completed: bool = False) -> JsonObject:
    """Read a protected selection as unverified provisional data, never completion."""
    from .tool_builds import _read_regular
    from .tool_downloads import safe_directory

    if type(require_completed) is not bool:
        raise ToolchainError('invalid completion requirement')
    output = Path(output).absolute()
    safe_directory(output)
    raw = _read_regular(output / 'manifest.json', maximum=16 * 1024**2)
    manifest = _parse_toolchain_observation(raw, manifest_sha256)
    if require_completed:
        raise ToolchainError('provisional toolchain observation does not establish completion')
    return {'status': 'provisional-observation-read', 'manifest': manifest,
            'attempt_completion': 'unconfirmed', 'byte_verification': 'not-performed',
            'authority': 'not-established'}
