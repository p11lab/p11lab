"""Independent controls for the bounded Rust candidate producer slice.

These tests never touch the network, the live Docker daemon, or retained
caller evidence. Fixture sources are authored below with an independent
hash/tree oracle; the producer must recompute every identity from bytes.
Live container proof (A/B builds, malicious build.rs/proc-macro canaries,
timeout/cancel/tool failure, the one selected a348 build) runs separately
with the installed wheel and is retained as run evidence, not committed here.
"""
import dataclasses
import gzip
import hashlib
import io
import json
import os
import struct
import tarfile

import pytest

from p11lab.docker import CommandResult
from p11lab.round_core import proxy_worker
from p11lab.round_core.proxy_worker import ProxyProducerError


TAG_A = 'fixture-a'
TAG_B = 'fixture-b'

SELECTED_COMMIT = 'a348a5f59b535b1ca309ea9f0a722e3bec692f72'
SELECTED_TREE = '436915ad13986c6770de4d190684276bb71de0c8'
SELECTED_ARCHIVE = '4446dfd31ada97c7249cf0044e43ae2b77fb69960c9bee265f9acb6ea77194cc'
SELECTED_LOCK = '39ae3c64cff6fddd4f2d621f8e26139005936b22e6d7652b2ed14e4921fa5979'
CURRENT_MANIFEST = '5aba2e7de287d689e9cb9476d7f2c234268319591f53eb0adcb76af80f51e3d5'


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def git_blob(data):
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()


def git_tree(members):
    """Independent Git tree hash over {path: (mode, blob)} plus link targets."""
    tree = {}
    for path, (mode, payload) in sorted(members.items()):
        node = tree
        parts = path.split('/')
        for part in parts[:-1]:
            child = node.setdefault(part, {})
            assert isinstance(child, dict), 'test fixture collision'
            node = child
        assert parts[-1] not in node, 'test fixture collision'
        node[parts[-1]] = (mode, payload)

    def encode(node):
        rows = []
        for name, value in node.items():
            if isinstance(value, dict):
                rows.append((name.encode() + b'/', b'40000 ' + name.encode() + b'\0' + encode(value)))
            else:
                mode, payload = value
                blob = payload if mode == '120000' else git_blob(payload)
                rows.append((name.encode(), mode.encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(blob)))
        content = b''.join(row for _, row in sorted(rows))
        return hashlib.sha1(b'tree ' + str(len(content)).encode() + b'\0' + content).digest()

    return encode(tree).hex()


def make_crate(identity, files):
    """Author a minimal registry .crate tarball; the caller binds its sha."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w', format=tarfile.PAX_FORMAT) as archive:
        top = tarfile.TarInfo(identity)
        top.type = tarfile.DIRTYPE
        top.mode = 0o755
        top.mtime = 0
        archive.addfile(top)
        for name, data in sorted(files.items()):
            assert '\0' not in name and name not in ('', '.', '..')
            info = tarfile.TarInfo(identity + '/' + name)
            info.size = len(data)
            info.mode = 0o644
            info.mtime = 0
            archive.addfile(info, io.BytesIO(data))
    return gzip.compress(buffer.getvalue(), mtime=0)


def make_source_archive(prefix, members):
    """Author a gzip source tarball; members map path -> (kind, payload, mode).

    kind 'file' carries bytes, kind 'link' carries the target text.
    """
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w', format=tarfile.PAX_FORMAT) as archive:
        top = tarfile.TarInfo(prefix)
        top.type = tarfile.DIRTYPE
        top.mode = 0o755
        top.mtime = 0
        archive.addfile(top)
        for path, (kind, payload, mode) in sorted(members.items()):
            info = tarfile.TarInfo(prefix + '/' + path)
            info.mtime = 0
            if kind == 'link':
                info.type = tarfile.SYMTYPE
                info.linkname = payload
                info.mode = 0o777
                archive.addfile(info)
            else:
                info.size = len(payload)
                info.mode = mode
                archive.addfile(info, io.BytesIO(payload))
    return gzip.compress(buffer.getvalue(), mtime=0)


def fixture_files(tag, dep):
    """Author one harmless two-crate workspace plus one registry dependency."""
    version = '0.0.0-' + tag
    root_manifest = (
        '[workspace]\nresolver = "2"\nmembers = ["crates/proxy", "crates/cli", "crates/shim"]\n'
        '\n[workspace.package]\nversion = "' + version + '"\nedition = "2021"\n'
        '\n[profile.release]\nlto = "thin"\nstrip = "symbols"\ncodegen-units = 1\n'
    ).encode()
    proxy_manifest = (
        '[package]\nname = "pkcs11-proxy-ng"\nversion.workspace = true\nedition.workspace = true\n'
        '\n[dependencies]\n' + dep + ' = "0.1.0"\n'
    ).encode()
    cli_manifest = (
        '[package]\nname = "pkcs11-proxy-ng-cli"\nversion.workspace = true\nedition.workspace = true\n'
    ).encode()
    shim_manifest = (
        '[package]\nname = "pkcs11-proxy-ng-shim"\nversion.workspace = true\nedition.workspace = true\n'
        '\n[lib]\ncrate-type = ["cdylib"]\n'
    ).encode()
    marker = tag.upper().replace('-', '_')
    files = {
        'Cargo.toml': ('file', root_manifest, 0o644),
        'Cargo.lock': ('file', b'placeholder', 0o644),
        'crates/proxy/Cargo.toml': ('file', proxy_manifest, 0o644),
        'crates/proxy/build.rs': ('file', b'fn main() { println!("cargo:rerun-if-changed=build.rs"); }\n', 0o644),
        'crates/proxy/src/main.rs': ('file', ('fn main() { println!("P11LAB-' + marker + '-DAEMON"); }\n').encode(), 0o644),
        'crates/cli/Cargo.toml': ('file', cli_manifest, 0o644),
        'crates/cli/src/main.rs': ('file', ('fn main() { println!("P11LAB-' + marker + '-CLI"); }\n').encode(), 0o644),
        'crates/shim/Cargo.toml': ('file', shim_manifest, 0o644),
        'crates/shim/src/lib.rs': ('file', (
            '#[no_mangle] pub extern "C" fn C_GetFunctionList() -> u32 { 0 }\n'
            '#[no_mangle] pub static FIXTURE_MARKER: &[u8] = b"P11LAB-' + marker + '-SHIM";\n'
        ).encode(), 0o644),
    }
    return files


def fixture_lock(tag, dep, checksum):
    version = '0.0.0-' + tag
    text = (
        '# This file is automatically @generated by Cargo.\n'
        '# It is not intended for manual editing.\n'
        'version = 4\n'
        '\n[[package]]\nname = "' + dep + '"\nversion = "0.1.0"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
        'checksum = "' + checksum + '"\n'
        '\n[[package]]\nname = "pkcs11-proxy-ng"\nversion = "' + version + '"\n'
        'dependencies = [\n "' + dep + '",\n]\n'
        '\n[[package]]\nname = "pkcs11-proxy-ng-cli"\nversion = "' + version + '"\n'
        '\n[[package]]\nname = "pkcs11-proxy-ng-shim"\nversion = "' + version + '"\n'
    )
    return text.encode()


def dep_crate_files(dep):
    return {
        'Cargo.toml': ('[package]\nname = "' + dep + '"\nversion = "0.1.0"\nedition = "2021"\n').encode(),
        'src/lib.rs': ('pub fn marker() -> &' + "'static str { \"" + dep.upper().replace('-', '_') + '" }\n').encode(),
    }


def oracle_members(files):
    members = []
    for path, (kind, payload, mode) in sorted(files.items()):
        if kind == 'link':
            members.append({'path': path, 'mode': '120000', 'size': len(payload.encode()),
                            'sha256': sha256(payload.encode()), 'git_blob': git_blob(payload.encode())})
        else:
            members.append({'path': path, 'mode': '100755' if mode & 0o111 else '100644',
                            'size': len(payload), 'sha256': sha256(payload), 'git_blob': git_blob(payload)})
    return members


def oracle_tree(files):
    table = {}
    for path, (kind, payload, mode) in files.items():
        if kind == 'link':
            table[path] = ('120000', payload)
        else:
            table[path] = ('100755' if mode & 0o111 else '100644', payload)
    return git_tree(table)


def build_fixture(tag, dep):
    """Author archive bytes, registry bytes, lock bytes and oracle identities."""
    crate_files = dep_crate_files(dep)
    crate = make_crate(dep + '-0.1.0', crate_files)
    lock = fixture_lock(tag, dep, sha256(crate))
    files = fixture_files(tag, dep)
    files['Cargo.lock'] = ('file', lock, 0o644)
    prefix = 'pkcs11-proxy-ng-' + tag
    archive = make_source_archive(prefix, files)
    members = oracle_members(files)
    return {
        'tag': tag, 'dep': dep, 'files': files, 'crate': crate, 'lock': lock,
        'archive': archive, 'prefix': prefix, 'members': members, 'tree': oracle_tree(files),
        'lock_sha256': sha256(lock), 'archive_sha256': sha256(archive),
        'vendor': [{'identity': dep + '-0.1.0', 'sha256': sha256(crate)}],
        'workspace': {
            'pkcs11-proxy-ng 0.0.0-' + tag: 'crates/proxy',
            'pkcs11-proxy-ng-cli 0.0.0-' + tag: 'crates/cli',
            'pkcs11-proxy-ng-shim 0.0.0-' + tag: 'crates/shim',
        },
    }


def fixture_selection(bundle, origin='local-test-fixture'):
    from p11lab.round_core.proxy_worker import ProxyProducerSelection
    return ProxyProducerSelection(
        origin=origin,
        source_commit=None,
        source_archive_sha256=bundle['archive_sha256'],
        source_archive_size=len(bundle['archive']),
        source_prefix=bundle['prefix'],
        source_tree=bundle['tree'],
        source_members=tuple(bundle['members']),
        cargo_lock_sha256=bundle['lock_sha256'],
        vendor_packages=tuple(bundle['vendor']),
        toolchain_manifest_sha256=CURRENT_MANIFEST,
        provider_parent={'status': 'unselected', 'detail': 'later-integration-slice'},
        caller_origin='local-controller',
        caller_run_id=None,
        caller_job_id=None,
    )


# ---------------------------------------------------------------------------
# Hand-encoded ELF64 test vectors (not tool-generated, not host binaries).
# ---------------------------------------------------------------------------

_ELF_BASE = 0x400000


def build_elf(*, elf_type=2, machine=62, elf_class=2, data=1, interpreter=None,
              needed=(), soname=None, symbols=(), verneed=(), gnu_hash=False,
              gnu_hash_buckets=1, extra_dynamic=(), runpath=None, raw_overrides=None,
              return_layout=False):
    """Encode a minimal ELF64 with program headers and dynamic metadata.

    symbols: list of (name, bind, type, defined[, visibility]) with bind in
    {1 global, 2 weak}, type in {1 object, 2 func}, visibility as an st_other
    value (default 0). Undefined symbols take versions from verneed in
    order. verneed: list of (filename, (version names...)). extra_dynamic:
    list of (tag, text) dynamic entries referencing the string table.
    gnu_hash_buckets replicates the single-bucket GNU hash chain across
    buckets (shared on purpose for revisit coverage).
    """
    # Reserve string offsets deterministically.
    layout_strings = []
    if interpreter is not None:
        layout_strings.append(interpreter.encode() + b'\0')
    for name in needed:
        layout_strings.append(name.encode() + b'\0')
    if soname is not None:
        layout_strings.append(soname.encode() + b'\0')
    if runpath is not None:
        layout_strings.append(runpath.encode() + b'\0')
    for _, text in extra_dynamic:
        layout_strings.append(text.encode() + b'\0')
    for name, _, _, _, *_ in symbols:
        layout_strings.append(name.encode() + b'\0')
    for filename, versions in verneed:
        layout_strings.append(filename.encode() + b'\0')
        for version in versions:
            layout_strings.append(version.encode() + b'\0')
    dynstr = b'\0'
    offsets = {}
    for raw in layout_strings:
        if raw[:-1] not in offsets:
            offsets[raw[:-1]] = len(dynstr)
        dynstr += raw

    n_symbols = 1 + len(symbols)
    dynsym = b'\0' * 24
    for name, bind, typ, defined, *rest in symbols:
        visibility = rest[0] if rest else 0
        dynsym += struct.pack('<IBBHQQ', offsets[name.encode()], bind << 4 | typ, visibility,
                              1 if defined else 0, 0, 0)
    if gnu_hash:
        # GNU hash with `gnu_hash_buckets` buckets sharing one bloom word and
        # one chain run; several buckets revisit the same chain on purpose.
        hash_tab = struct.pack('<IIII', gnu_hash_buckets, 1, 1, 5) + struct.pack(
            '<Q', ~0 & 0xFFFFFFFFFFFFFFFF)
        for _ in range(gnu_hash_buckets):
            hash_tab += struct.pack('<I', 1 if n_symbols > 1 else 0)
        for index in range(1, n_symbols):
            hash_tab += struct.pack('<I', 0x1234 | (1 if index == n_symbols - 1 else 0))
        hash_tag = 0x6ffffef5
    else:
        # SYSV hash with a single bucket.
        hash_tab = struct.pack('<II', 1, n_symbols) + struct.pack('<I', 1 if n_symbols > 1 else 0)
        for index in range(n_symbols):
            nxt = index + 1 if 0 < index + 1 < n_symbols else 0
            hash_tab += struct.pack('<I', nxt if index else 0)
        hash_tag = 4
    # Version symbols and requirements. Without VERNEED, undefined symbols
    # carry index 1 (global, no version), matching real toolchains; with
    # VERNEED, they take sequential indices from 2. Surplus versions (more
    # requirements than undefined references) are allowed for aggregate
    # interruptibility shapes; the parser must still bound and interrupt them.
    versym = struct.pack('<H', 0)
    next_index = 2
    for _, _, _, defined, *_ in symbols:
        if defined or not verneed:
            versym += struct.pack('<H', 1)
        else:
            versym += struct.pack('<H', next_index)
            next_index += 1
    undef_count = sum(1 for _, _, _, defined, *_ in symbols if not defined)
    flat_versions = [version for _, versions in verneed for version in versions]
    assert not verneed or undef_count <= len(flat_versions), 'test vector mismatch'
    verneed_raw = b''
    vn_index = 2
    verneed_blobs = []
    for filename, versions in verneed:
        aux = b''
        for position, version in enumerate(versions):
            last = position == len(versions) - 1
            aux += struct.pack('<IHHIi', 0, 0, vn_index, offsets[version.encode()],
                               0 if last else 16)
            vn_index += 1
        verneed_blobs.append((filename, aux))
    for position, (filename, aux) in enumerate(verneed_blobs):
        last = position == len(verneed_blobs) - 1
        entry = struct.pack('<HHIII', 1, len(verneed[position][1]), offsets[filename.encode()],
                            16, 0 if last else 16 + len(aux))
        verneed_raw += entry + aux

    has_dynamic = bool(needed) or soname is not None or bool(symbols) \
        or runpath is not None or bool(extra_dynamic)

    # Lay out file bytes; addresses resolve through one PT_LOAD identity map.
    blobs = {}
    offset = 64
    n_phdrs = 1 + (1 if interpreter is not None else 0) + (1 if has_dynamic else 0)
    offset += 56 * n_phdrs
    if interpreter is not None:
        blobs['interp'] = offset
        offset += len(interpreter.encode()) + 1
    if has_dynamic:
        blobs['dynamic'] = offset
        n_dyn = len(needed) + (1 if soname is not None else 0) + 5
        n_dyn += (2 if verneed else 0) + (1 if runpath is not None else 0) + 1
        n_dyn += len(extra_dynamic)
        offset += 16 * n_dyn
    blobs['dynstr'] = offset
    offset += len(dynstr)
    blobs['dynsym'] = offset
    offset += len(dynsym)
    blobs['hash'] = offset
    offset += len(hash_tab)
    if has_dynamic:
        blobs['versym'] = offset
        offset += len(versym)
    if verneed:
        blobs['verneed'] = offset
        offset += len(verneed_raw)
    total = offset

    def addr(key):
        return _ELF_BASE + blobs[key]

    out = bytearray()
    out += b'\x7fELF' + bytes([elf_class, data, 1, 0]) + b'\0' * 8
    out += struct.pack('<HHIQQQIHHHHHH', elf_type, machine, 1, 0, 64, 0, 0, 64, 56,
                       n_phdrs, 0, 0, 0)
    out += struct.pack('<IIQQQQQQ', 1, 5, 0, _ELF_BASE, _ELF_BASE, total, total, 0x1000)
    if interpreter is not None:
        raw = interpreter.encode() + b'\0'
        out += struct.pack('<IIQQQQQQ', 3, 4, blobs['interp'], addr('interp'), addr('interp'),
                           len(raw), len(raw), 1)
    if has_dynamic:
        dyn_size = 16 * n_dyn
        out += struct.pack('<IIQQQQQQ', 2, 4, blobs['dynamic'], addr('dynamic'),
                           addr('dynamic'), dyn_size, dyn_size, 8)
    assert len(out) == 64 + 56 * n_phdrs
    if interpreter is not None:
        out += interpreter.encode() + b'\0'
    if has_dynamic:
        entries = [(1, offsets[name.encode()]) for name in needed]
        if soname is not None:
            entries.append((14, offsets[soname.encode()]))
        if runpath is not None:
            entries.append((29, offsets[runpath.encode()]))
        entries += [(tag, offsets[text.encode()]) for tag, text in extra_dynamic]
        entries += [(5, addr('dynstr')), (10, len(dynstr)), (6, addr('dynsym')),
                    (hash_tag, addr('hash')), (0x6ffffff0, addr('versym'))]
        if verneed:
            entries += [(0x6ffffffe, addr('verneed')), (0x6fffffff, len(verneed))]
        entries.append((0, 0))
        assert len(entries) == n_dyn
        for tag, value in entries:
            out += struct.pack('<QQ', tag, value)
    out += dynstr + dynsym + hash_tab
    if has_dynamic:
        out += versym
    if verneed:
        out += verneed_raw
    assert len(out) == total, (len(out), total)
    raw = bytes(out)
    if raw_overrides:
        mutable = bytearray(raw)
        for at, chunk in raw_overrides:
            mutable[at:at + len(chunk)] = chunk
        raw = bytes(mutable)
    if return_layout:
        return raw, dict(blobs)
    return raw


RICH_SHIM = build_elf(
    elf_type=3, needed=('libc.so.6', 'libgcc_s.so.1'), soname='libpkcs11_proxy_ng_shim.so',
    symbols=(('C_GetFunctionList', 1, 2, True), ('shim_marker', 1, 1, True),
             ('printf', 1, 2, False), ('memcpy', 1, 2, False), ('__gcc_personality_v0', 1, 2, False)),
    verneed=(('libc.so.6', ('GLIBC_2.2.5', 'GLIBC_2.34')), ('libgcc_s.so.1', ('GCC_3.0',))),
)

RICH_PIE = build_elf(
    elf_type=3, interpreter='/lib64/ld-linux-x86-64.so.2', needed=('libc.so.6',),
    symbols=(('main', 1, 2, True), ('puts', 1, 2, False),),
    verneed=(('libc.so.6', ('GLIBC_2.34',)),),
)

STATIC_EXEC = build_elf(elf_type=2)


# ---------------------------------------------------------------------------
# Fake Docker engine and canned toolchain observation for hermetic flow tests.
# ---------------------------------------------------------------------------

FAKE_IMAGE = 'sha256:' + 'ab' * 32
FAKE_LAYERS = ['sha256:' + 'cd' * 32, 'sha256:' + 'ef' * 32]
FAKE_CANDIDATE_ID = '11' * 32
FAKE_HOLDER_ID = '22' * 32


class FakeCompleted:
    def __init__(self, stdout='', returncode=0):
        self.stdout = stdout
        self.returncode = returncode
        self.stderr = ''
        self.timed_out = False
        self.stdout_truncated = False
        self.stderr_truncated = False


class FakeEngine:
    """Scripted stand-in that emulates Docker control-plane behavior."""

    def __init__(self, *, inspection_before, inspection_stopped, execute_result,
                 list_leftover='', expected_inputs_src=None):
        self.ops = []
        self.env = {'PATH': '/usr/bin:/bin'}
        self.inspection_before = inspection_before
        self.inspection_stopped = inspection_stopped
        self.execute_result = execute_result
        self.list_leftover = list_leftover
        self.expected_inputs_src = expected_inputs_src
        self.volume_options = None
        self.volume_name = None
        self.create_options = None
        self.create_argv = None
        self.inspect_calls = 0

    def image(self, artifact):
        self.ops.append(('image', artifact.reference))
        return {'Id': artifact.reference, 'Os': 'linux', 'Architecture': 'amd64',
                'RootFS': {'Layers': list(FAKE_LAYERS)}, 'Config': {'Env': ['PATH=/usr/bin:/bin']}}

    def _mounts(self):
        mounts = []
        options = self.create_options or []
        index = 0
        while index < len(options):
            if options[index] == '--mount':
                spec = options[index + 1]
                fields = dict(part.split('=', 1) for part in spec.split(',') if '=' in part)
                entry = {
                    'Type': fields['type'],
                    'Name' if fields['type'] == 'volume' else 'Source':
                        fields.get('src') or fields.get('Name', ''),
                    'Destination': fields['dst'], 'RW': 'readonly' not in spec.split(',')}
                if fields['type'] == 'volume':
                    entry['Driver'] = 'local'
                    entry['Mode'] = 'z'
                else:
                    entry['Mode'] = ''
                    entry['Propagation'] = 'rprivate'
                mounts.append(entry)
                index += 2
            else:
                index += 1
        return mounts

    def command(self, args, timeout=15, *, check=True, **kwargs):
        self.ops.append(('command', tuple(args), timeout))
        if args[0] == 'volume' and args[1] == 'create':
            name = args[args.index('--name') + 1]
            self.volume_name = name
            self.volume_options = {}
            self.volume_labels = {}
            for position, token in enumerate(args):
                if token == '--opt':
                    key, _, value = args[position + 1].partition('=')
                    self.volume_options[key] = value
                if token == '--label':
                    key, _, value = args[position + 1].partition('=')
                    self.volume_labels[key] = value
            return FakeCompleted(name + '\n')
        if args[0] == 'volume' and args[1] == 'inspect':
            assert args[2] == self.volume_name
            return FakeCompleted(json.dumps([{
                'Name': self.volume_name, 'Driver': 'local', 'Options': self.volume_options,
                'Labels': dict(self.volume_labels)}]))
        if args[0] in ('container', 'volume') and args[1] == 'list':
            return FakeCompleted(self.list_leftover)
        if args[:2] == ['container', 'inspect']:
            identity = args[2]
            if identity == FAKE_HOLDER_ID:
                return FakeCompleted(json.dumps([{
                    'Id': FAKE_HOLDER_ID, 'Image': FAKE_IMAGE,
                    'Config': {'Labels': dict(FakeEngine.labels_of(self)),
                               'User': '65532:65532', 'Entrypoint': ['/bin/sleep']},
                    'HostConfig': {'PidMode': ''}, 'State': {'Running': True, 'Pid': 123}}]))
            self.inspect_calls += 1
            body = json.loads(json.dumps(
                self.inspection_before if self.inspect_calls == 1 else self.inspection_stopped))
            body['Mounts'] = self._mounts()
            body['Config']['Labels'] = dict(FakeEngine.labels_of(self))
            return FakeCompleted(json.dumps([body]))
        if args[0] == 'start':
            return FakeCompleted(args[1] + '\n')
        if args[0] in ('stop', 'rm', 'kill'):
            return FakeCompleted('')
        if args[:2] == ['container', 'rm'] or args[:2] == ['volume', 'rm']:
            return FakeCompleted('')
        if args[0] == 'inspect':
            return FakeCompleted(json.dumps({'Running': False, 'Pid': 0, 'ExitCode': 0}))
        raise AssertionError('unexpected fake command: %r' % (args,))

    @staticmethod
    def labels_of(engine):
        return getattr(engine, 'labels', {})

    def create(self, image, argv, options, labels, name):
        self.labels = dict(labels)
        if name.endswith('-holder'):
            self.ops.append(('create-holder', image, tuple(argv), tuple(options), name))
            return FAKE_HOLDER_ID
        self.ops.append(('create', image, tuple(argv), tuple(options), name))
        self.create_options = list(options)
        self.create_argv = list(argv)
        return FAKE_CANDIDATE_ID

    def execute(self, identity, timeout, interrupted):
        self.ops.append(('execute', identity, timeout))
        return self.execute_result

    def stop(self, identity, labels):
        self.ops.append(('stop', identity))

    def remove(self, kind, identity, labels):
        self.ops.append(('remove', kind, identity))


def canned_inspection(*, running, pid, image=FAKE_IMAGE, user='65532:65532',
                      entrypoint=None, cmd=None, readback_id=FAKE_CANDIDATE_ID):
    return {
        'Id': readback_id, 'Image': image,
        'Config': {'Labels': {'p11lab.proxy-producer': 'nonce', 'p11lab.proxy-context': 'ctx'},
                   'User': user, 'Entrypoint': entrypoint or ['/usr/bin/env'], 'Cmd': cmd or []},
        'HostConfig': {
            'NetworkMode': 'none', 'CapDrop': ['ALL'], 'CapAdd': None, 'ReadonlyRootfs': True,
            'Privileged': False, 'PidsLimit': 128, 'Memory': 4294967296,
            'MemorySwap': 4294967296, 'NanoCpus': 2000000000,
            'SecurityOpt': ['no-new-privileges=true'], 'IpcMode': 'private', 'PidMode': '',
            'Tmpfs': {'/scratch': 'rw,nosuid,nodev,exec,size=2147483648,nr_inodes=40000,mode=1777',
                      '/tmp': 'rw,nosuid,nodev,noexec,size=134217728,nr_inodes=16384,mode=1777'},
            'Ulimits': [{'Name': 'nofile', 'Soft': 1024, 'Hard': 1024}],
            'LogConfig': {'Type': 'none'},
            'Binds': None, 'Devices': [], 'VolumesFrom': None},
        'Mounts': [],
        'State': {'Running': running, 'Pid': pid},
    }


def canned_warm(**overrides):
    result = {
        'status': 'local-byte-verification-observed', 'cleanup_errors': [],
        'manifest_sha256': CURRENT_MANIFEST,
        'image': {'engine_id': FAKE_IMAGE, 'layers': list(FAKE_LAYERS),
                  'filesystem_archive': {'sha256': 'bb' * 32, 'size': 8}},
        'source_attempt_completion': 'unconfirmed',
        'completion_witness': {'kind': 'bounded-api-return', 'authority': 'not-established'},
    }
    result.update(overrides)
    return result


class FakeCp:
    """Stand-in for the bounded `docker cp` readback transport."""

    def __init__(self, tar_bytes, *, status=0, timed_out=False, truncated=False):
        self.tar_bytes = tar_bytes
        self.status = status
        self.timed_out = timed_out
        self.truncated = truncated
        self.calls = []

    def __call__(self, argv, *, cwd, env, timeout, interrupted, limit):
        from types import SimpleNamespace
        self.calls.append({'argv': list(argv), 'cwd': str(cwd), 'timeout': timeout})
        owner = SimpleNamespace(capture=SimpleNamespace(
            buffers=[bytearray(self.tar_bytes), bytearray()]))
        facts = {'stdout_truncated': self.truncated, 'stderr_truncated': False,
                 'supervision_errors': [], 'stragglers_remaining': False,
                 'drain_complete': True}
        return self.status, self.timed_out, owner, facts


def readback_tar_bytes(files):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w', format=tarfile.PAX_FORMAT) as archive:
        for directory in ('bin', 'lib'):
            info = tarfile.TarInfo(directory)
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            info.mtime = 0
            archive.addfile(info)
        for path, data in sorted(files.items()):
            info = tarfile.TarInfo(path)
            info.size = len(data)
            info.mode = 0o755
            info.mtime = 0
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


# ---------------------------------------------------------------------------
# Role policy: the frozen slice values, pinned and cross-checked.
# ---------------------------------------------------------------------------

def installed_policy_bytes():
    from p11lab.catalog import package_data
    return package_data('rounds/proxy-producer-v1.json').read_bytes()


def test_role_policy_pins_exact_slice_values():
    from p11lab.round_core.proxy_worker import load_producer_role_policy
    policy = load_producer_role_policy()
    assert policy['schema'] == 'p11lab.proxy-producer-role.v1'
    assert policy['whole_attempt_seconds'] == 600
    assert policy['build_seconds'] == 480
    assert policy['cleanup_reserve_seconds'] == 30
    assert policy['failure_receipt_reserve_seconds'] == 10
    assert policy['user'] == '65532:65532'
    assert policy['readonly_root'] is True
    assert policy['network_mode'] == 'none'
    assert policy['ipc_mode'] == 'private'
    assert policy['pid_mode'] == 'private'
    assert policy['cap_drop'] == ['ALL']
    assert policy['cap_add'] is None
    assert policy['security_opt'] == ['no-new-privileges=true']
    assert policy['privileged'] is False
    assert policy['pull'] == 'never'
    assert policy['log_driver'] == 'none'
    assert policy['cpus'] == 2
    assert policy['nano_cpus'] == 2000000000
    assert policy['pids_limit'] == 128
    assert policy['memory_bytes'] == 4294967296
    assert policy['memory_swap_bytes'] == 4294967296
    assert policy['nofile_soft'] == 1024
    assert policy['nofile_hard'] == 1024
    assert policy['tmpfs'] == {
        '/scratch': 'rw,nosuid,nodev,exec,size=2147483648,nr_inodes=40000,mode=1777',
        '/tmp': 'rw,nosuid,nodev,noexec,size=134217728,nr_inodes=16384,mode=1777'}
    assert policy['output_volume_bytes'] == 134217728
    assert policy['output_volume_inodes'] == 10000
    assert policy['entrypoint'] == ['/usr/bin/env']
    assert policy['environment'] == {
        'PATH': '/opt/rust/bin:/opt/protoc/bin:/usr/bin:/bin',
        'HOME': '/scratch/home',
        'CARGO_HOME': '/scratch/cargo-home',
        'CARGO_TARGET_DIR': '/scratch/target',
        'CARGO_NET_OFFLINE': 'true',
        'RUSTC': '/opt/rust/bin/rustc',
        'PROTOC': '/opt/protoc/bin/protoc',
        'LC_ALL': 'C',
        'TMPDIR': '/tmp'}
    for forbidden in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_WRAPPER',
                      'RUSTC_WORKSPACE_WRAPPER', 'RUSTUP_HOME'):
        assert forbidden in policy['environment_must_be_absent']
        assert forbidden not in policy['environment']
    assert policy['outputs'] == ['bin/pkcs11-proxy-ng', 'bin/pkcs11-proxy-ng-cli',
                                 'lib/libpkcs11_proxy_ng_shim.so']
    assert policy['interpreter'] == '/lib64/ld-linux-x86-64.so.2'
    assert policy['needed_allowlist'] == ['libc.so.6', 'libgcc_s.so.1', 'libm.so.6',
                                          'libdl.so.2', 'libpthread.so.0', 'linux-vdso.so.1',
                                          'ld-linux-x86-64.so.2']
    assert policy['executables'] == ['bin/pkcs11-proxy-ng', 'bin/pkcs11-proxy-ng-cli']
    assert policy['shared_objects'] == ['lib/libpkcs11_proxy_ng_shim.so']
    assert policy['shim_required_exports'] == ['C_GetFunctionList']
    assert policy['version_ceilings'] is None
    assert policy['build_script_sha256'] == sha256(proxy_worker._BUILD_SCRIPT.encode())
    assert policy['controller_cargo_config_sha256'] == sha256(proxy_worker._CONTROLLER_CARGO_CONFIG.encode())


def test_role_policy_digest_pin_is_current_and_tamper_is_refused():
    from p11lab.round_core.proxy_worker import validate_role_policy_bytes
    raw = installed_policy_bytes()
    assert sha256(raw) == proxy_worker._PRODUCER_ROLE_POLICY_SHA256
    assert validate_role_policy_bytes(raw)['schema'] == 'p11lab.proxy-producer-role.v1'
    for mutate in (b'600', b'65532', b'no-new-privileges'):
        assert mutate in raw
        with pytest.raises(ProxyProducerError):
            validate_role_policy_bytes(raw.replace(mutate, b'0' * len(mutate), 1))
    with pytest.raises(ProxyProducerError):
        validate_role_policy_bytes(raw + b' ')
    with pytest.raises(ProxyProducerError):
        validate_role_policy_bytes(b'not json')


def test_controller_cargo_config_is_offline_vendored_without_hooks():
    import tomllib
    config = tomllib.loads(proxy_worker._CONTROLLER_CARGO_CONFIG)
    assert config['net']['offline'] is True
    assert config['source']['crates-io']['replace-with'] == 'vendored-sources'
    assert config['source']['vendored-sources']['directory'] == 'vendor'
    assert 'credential-provider' not in proxy_worker._CONTROLLER_CARGO_CONFIG
    assert 'registry' not in config['source']['vendored-sources']
    assert set(config) <= {'net', 'source', 'build'}


def test_build_script_runs_one_fixed_offline_cargo_invocation():
    from p11lab.proxy_inputs import load_proxy_build_selection
    script = proxy_worker._BUILD_SCRIPT
    assert script.startswith('set -eu\n')
    assert script.count('/opt/rust/bin/cargo build') == 1
    assert script.count('/opt/rust/bin/cargo ') == 1
    expected = ' '.join(load_proxy_build_selection()['cargo_args'])
    assert expected in script
    assert '--locked' in script and '--offline' in script and '--release' in script
    assert 'RUSTFLAGS' not in script and 'credential' not in script
    assert '/bin/cp ' in script and '/bin/chmod 755' in script and '/bin/mkdir -p' in script
    assert 'curl' not in script and 'wget' not in script and 'ssh' not in script


# ---------------------------------------------------------------------------
# Selections: default binding, dirty snapshots, fixture oracle.
# ---------------------------------------------------------------------------

def test_default_selection_binds_exact_selected_values():
    from p11lab.round_core.proxy_worker import default_proxy_selection
    selection = default_proxy_selection(toolchain_manifest_sha256=CURRENT_MANIFEST)
    assert selection.origin == 'installed-default'
    assert selection.source_commit == SELECTED_COMMIT
    assert selection.source_tree == SELECTED_TREE
    assert selection.source_archive_sha256 == SELECTED_ARCHIVE
    assert selection.source_archive_size == 2124074
    assert selection.source_prefix == 'pkcs11-proxy-ng-' + SELECTED_COMMIT
    assert selection.cargo_lock_sha256 == SELECTED_LOCK
    assert len(selection.source_members) == 689
    assert len(selection.vendor_packages) == 282
    assert selection.vendor_packages == tuple(sorted(
        selection.vendor_packages, key=lambda row: row['identity']))
    assert selection.toolchain_manifest_sha256 == CURRENT_MANIFEST
    assert selection.provider_parent['status'] == 'unselected'
    assert selection.caller_origin == 'local-controller'


def test_default_selection_rejects_bad_toolchain_and_caller_fields():
    from p11lab.round_core.proxy_worker import default_proxy_selection
    with pytest.raises(ProxyProducerError):
        default_proxy_selection(toolchain_manifest_sha256='0' * 63)
    with pytest.raises(ProxyProducerError):
        default_proxy_selection(toolchain_manifest_sha256='zz' + '0' * 62)
    with pytest.raises(ProxyProducerError):
        default_proxy_selection(toolchain_manifest_sha256=CURRENT_MANIFEST,
                                caller_run_id='has space')
    with pytest.raises(ProxyProducerError):
        default_proxy_selection(toolchain_manifest_sha256=CURRENT_MANIFEST,
                                caller_job_id='has/slash')


def test_selection_shape_is_validated_at_construction():
    from p11lab.round_core.proxy_worker import ProxyProducerSelection
    bundle = build_fixture(TAG_A, 'atest-dep')
    valid = dict(origin='local-test-fixture', source_commit=None,
                 source_archive_sha256=bundle['archive_sha256'],
                 source_archive_size=len(bundle['archive']), source_prefix=bundle['prefix'],
                 source_tree=bundle['tree'], source_members=tuple(bundle['members']),
                 cargo_lock_sha256=bundle['lock_sha256'], vendor_packages=tuple(bundle['vendor']),
                 toolchain_manifest_sha256=CURRENT_MANIFEST,
                 provider_parent={'status': 'unselected'}, caller_origin='local-controller',
                 caller_run_id=None, caller_job_id=None)
    ProxyProducerSelection(**valid)
    for key, value in [('origin', 'candidate-claimed'), ('source_commit', 'x' * 39),
                       ('source_archive_sha256', '0' * 63), ('source_archive_size', -1),
                       ('source_prefix', '../escape'), ('source_tree', '0' * 39),
                       ('cargo_lock_sha256', 'Q' * 64),
                       ('toolchain_manifest_sha256', '0' * 64 + 'extra'),
                       ('caller_origin', 'protected-ci'), ('caller_run_id', ''),
                       ('vendor_packages', ({'identity': 'x'},))]:
        with pytest.raises(ProxyProducerError):
            ProxyProducerSelection(**{**valid, key: value})


def test_fixture_oracle_accepts_matching_pairs(tmp_path):
    from p11lab.round_core.proxy_worker import verify_producer_source
    for tag, dep in ((TAG_A, 'atest-dep'), (TAG_B, 'btest-dep')):
        bundle = build_fixture(tag, dep)
        archive = tmp_path / (tag + '.tar.gz')
        archive.write_bytes(bundle['archive'])
        verified = verify_producer_source(fixture_selection(bundle), archive)
        assert verified.lock_bytes == bundle['lock']
        assert verified.workspace == bundle['workspace']
        assert verified.links == {}


def test_fixture_selection_cross_and_tamper_are_refused(tmp_path):
    from p11lab.round_core.proxy_worker import verify_producer_source
    bundle_a = build_fixture(TAG_A, 'atest-dep')
    bundle_b = build_fixture(TAG_B, 'btest-dep')
    archive_a = tmp_path / 'a.tar.gz'
    archive_a.write_bytes(bundle_a['archive'])
    with pytest.raises(ProxyProducerError):
        verify_producer_source(fixture_selection(bundle_b), archive_a)
    mutated = bytearray(bundle_a['archive'])
    mutated[100] ^= 1
    archive_mut = tmp_path / 'mut.tar.gz'
    archive_mut.write_bytes(bytes(mutated))
    with pytest.raises(ProxyProducerError):
        verify_producer_source(fixture_selection(bundle_a), archive_mut)
    resealed = dict(bundle_a)
    resealed['archive'] = make_source_archive('wrong-prefix', bundle_a['files'])
    archive_prefix = tmp_path / 'prefix.tar.gz'
    archive_prefix.write_bytes(resealed['archive'])
    with pytest.raises(ProxyProducerError):
        verify_producer_source(fixture_selection(bundle_a), archive_prefix)


def test_fixture_member_roster_changes_are_refused(tmp_path):
    from p11lab.round_core.proxy_worker import verify_producer_source
    bundle = build_fixture(TAG_A, 'atest-dep')
    selection = fixture_selection(bundle)

    def check(files):
        archive = tmp_path / ('case-%d.tar.gz' % check.count)
        check.count += 1
        archive.write_bytes(make_source_archive(bundle['prefix'], files))
        with pytest.raises(ProxyProducerError):
            verify_producer_source(selection, archive)
    check.count = 0

    changed = dict(bundle['files'])
    changed['crates/proxy/src/main.rs'] = ('file', b'fn main() {}\n', 0o644)
    check(changed)
    added = dict(bundle['files'])
    added['extra.txt'] = ('file', b'extra', 0o644)
    check(added)
    missing = dict(bundle['files'])
    del missing['crates/cli/src/main.rs']
    check(missing)
    relinked = dict(bundle['files'])
    relinked['crates/cli/src/main.rs'] = ('link', '/etc/passwd', 0o777)
    check(relinked)
    cyclic = dict(bundle['files'])
    cyclic['loop-a'] = ('link', 'loop-b', 0o777)
    cyclic['loop-b'] = ('link', 'loop-a', 0o777)
    check(cyclic)


def test_fixture_lock_and_vendor_skew_are_refused(tmp_path):
    from p11lab.round_core.proxy_worker import verify_producer_source
    bundle = build_fixture(TAG_A, 'atest-dep')
    archive = tmp_path / 'a.tar.gz'
    archive.write_bytes(bundle['archive'])
    other = build_fixture(TAG_B, 'btest-dep')
    skewed = fixture_selection(bundle)
    with pytest.raises(ProxyProducerError):
        verify_producer_source(dataclasses.replace(skewed, cargo_lock_sha256=other['lock_sha256']),
                               archive)
    with pytest.raises(ProxyProducerError):
        verify_producer_source(dataclasses.replace(skewed, vendor_packages=tuple(other['vendor'])),
                               archive)
    with pytest.raises(ProxyProducerError):
        verify_producer_source(dataclasses.replace(skewed, vendor_packages=()), archive)


def test_empty_registry_roster_is_refused(tmp_path):
    from p11lab.round_core.proxy_worker import verify_producer_source
    bundle = build_fixture(TAG_A, 'atest-dep')
    lock = (b'version = 4\n\n[[package]]\nname = "pkcs11-proxy-ng"\nversion = "0.0.0-fixture-a"\n'
            b'\n[[package]]\nname = "pkcs11-proxy-ng-cli"\nversion = "0.0.0-fixture-a"\n'
            b'\n[[package]]\nname = "pkcs11-proxy-ng-shim"\nversion = "0.0.0-fixture-a"\n')
    files = dict(bundle['files'])
    files['Cargo.lock'] = ('file', lock, 0o644)
    archive = tmp_path / 'nodeps.tar.gz'
    archive.write_bytes(make_source_archive(bundle['prefix'], files))
    selection = dataclasses.replace(
        fixture_selection(bundle), source_archive_sha256=sha256(archive.read_bytes()),
        source_archive_size=archive.stat().st_size, source_members=tuple(oracle_members(files)),
        source_tree=oracle_tree(files), cargo_lock_sha256=sha256(lock), vendor_packages=())
    with pytest.raises(ProxyProducerError):
        verify_producer_source(selection, archive)


def test_verify_archive_degenerate_selection_without_root_manifest_is_typed_refusal(tmp_path):
    from p11lab.round_core.proxy_worker import verify_producer_source
    bundle = build_fixture(TAG_A, 'atest-dep')
    files = dict(bundle['files'])
    del files['Cargo.toml']
    archive = tmp_path / 'degenerate.tar.gz'
    archive.write_bytes(make_source_archive(bundle['prefix'], files))
    selection = dataclasses.replace(
        fixture_selection(bundle), source_archive_sha256=sha256(archive.read_bytes()),
        source_archive_size=archive.stat().st_size, source_members=tuple(oracle_members(files)),
        source_tree=oracle_tree(files))
    with pytest.raises(ProxyProducerError) as raised:
        verify_producer_source(selection, archive)
    assert type(raised.value) is ProxyProducerError
    assert 'Cargo.toml' in str(raised.value)


# ---------------------------------------------------------------------------
# Code snapshots: same lock/vendor closure, no fabricated commit.
# ---------------------------------------------------------------------------

def fixture_base(bundle):
    from p11lab.round_core.proxy_worker import SnapshotBase
    return SnapshotBase(
        members=tuple(bundle['members']),
        cargo_lock_sha256=bundle['lock_sha256'],
        vendor_roster=tuple(bundle['vendor']),
    )


def write_snapshot(root, files):
    for path, (kind, payload, mode) in files.items():
        target = root / path
        if kind == 'link':
            target.parent.mkdir(parents=True, exist_ok=True)
            target.symlink_to(payload)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
            target.chmod(mode)


def test_code_snapshot_accepts_manifest_stable_code_changes(tmp_path):
    from p11lab.round_core.proxy_worker import seal_code_snapshot, verify_snapshot_source
    bundle = build_fixture(TAG_A, 'atest-dep')
    files = dict(bundle['files'])
    files['crates/proxy/src/main.rs'] = (
        'file', b'fn main() { println!("dirty-iteration"); }\n', 0o644)
    files['notes.txt'] = ('file', b'scratch notes', 0o644)
    root = tmp_path / 'snap'
    root.mkdir()
    write_snapshot(root, files)
    selection = seal_code_snapshot(root, base=fixture_base(bundle),
                                   origin='local-test-fixture',
                                   toolchain_manifest_sha256=CURRENT_MANIFEST,
                                   caller_run_id='run-1', caller_job_id='job-2')
    assert selection.origin == 'local-test-fixture'
    assert selection.source_commit is None
    assert selection.source_archive_sha256 is None
    assert selection.source_archive_size is None
    assert selection.source_prefix is None
    assert selection.cargo_lock_sha256 == bundle['lock_sha256']
    assert selection.vendor_packages == tuple(bundle['vendor'])
    assert selection.caller_run_id == 'run-1'
    assert selection.caller_job_id == 'job-2'
    expected_tree = oracle_tree(files)
    assert selection.source_tree == expected_tree
    verified = verify_snapshot_source(selection, root)
    assert verified.lock_bytes == bundle['lock']
    assert verified.workspace == bundle['workspace']


def test_code_snapshot_preserves_links_and_modes(tmp_path):
    from p11lab.round_core.proxy_worker import seal_code_snapshot, verify_snapshot_source
    bundle = build_fixture(TAG_A, 'atest-dep')
    files = dict(bundle['files'])
    files['docs-link'] = ('link', 'crates/proxy/src/main.rs', 0o777)
    files['run.sh'] = ('file', b'#!/bin/sh\n', 0o755)
    root = tmp_path / 'snap'
    root.mkdir()
    write_snapshot(root, files)
    selection = seal_code_snapshot(root, base=fixture_base(bundle), origin='local-test-fixture',
                                   toolchain_manifest_sha256=CURRENT_MANIFEST)
    by_path = {row['path']: row for row in selection.source_members}
    assert by_path['docs-link']['mode'] == '120000'
    assert by_path['run.sh']['mode'] == '100755'
    assert by_path['crates/proxy/src/main.rs']['mode'] == '100644'
    verified = verify_snapshot_source(selection, root)
    assert verified.links == {'docs-link': {'target': 'crates/proxy/src/main.rs',
                                            'resolved': 'crates/proxy/src/main.rs'}}


def test_code_snapshot_refusals(tmp_path):
    from p11lab.round_core.proxy_worker import seal_code_snapshot
    bundle = build_fixture(TAG_A, 'atest-dep')
    base = fixture_base(bundle)

    def seal(files, **kwargs):
        root = tmp_path / ('snap-%d' % seal.count)
        seal.count += 1
        root.mkdir()
        write_snapshot(root, files)
        kwargs.setdefault('origin', 'local-test-fixture')
        return seal_code_snapshot(root, base=base,
                                  toolchain_manifest_sha256=CURRENT_MANIFEST, **kwargs)
    seal.count = 0

    changed_lock = dict(bundle['files'])
    changed_lock['Cargo.lock'] = ('file', bundle['lock'] + b'# dirty\n', 0o644)
    with pytest.raises(ProxyProducerError):
        seal(changed_lock)
    changed_manifest = dict(bundle['files'])
    changed_manifest['crates/proxy/Cargo.toml'] = (
        'file', bundle['files']['crates/proxy/Cargo.toml'][1] + b'# dirty\n', 0o644)
    with pytest.raises(ProxyProducerError):
        seal(changed_manifest)
    missing_manifest = dict(bundle['files'])
    del missing_manifest['crates/cli/Cargo.toml']
    with pytest.raises(ProxyProducerError):
        seal(missing_manifest)
    vendor = dict(bundle['files'])
    vendor['vendor/evil'] = ('file', b'x', 0o644)
    with pytest.raises(ProxyProducerError):
        seal(vendor)
    gitdir = dict(bundle['files'])
    gitdir['.git/config'] = ('file', b'x', 0o644)
    with pytest.raises(ProxyProducerError):
        seal(gitdir)
    escape = dict(bundle['files'])
    escape['evil'] = ('link', '/etc/passwd', 0o777)
    with pytest.raises(ProxyProducerError):
        seal(escape)
    outside = dict(bundle['files'])
    outside['sub/evil'] = ('link', '../../nowhere', 0o777)
    with pytest.raises(ProxyProducerError):
        seal(outside)
    cyclic = dict(bundle['files'])
    cyclic['loop-a'] = ('link', 'loop-b', 0o777)
    cyclic['loop-b'] = ('link', 'loop-a', 0o777)
    with pytest.raises(ProxyProducerError):
        seal(cyclic)
    with pytest.raises(ProxyProducerError):
        seal(dict(bundle['files']), origin='installed-default')


def test_seal_degenerate_base_without_root_manifest_is_typed_refusal(tmp_path):
    from p11lab.round_core.proxy_worker import seal_code_snapshot
    bundle = build_fixture(TAG_A, 'atest-dep')
    files = dict(bundle['files'])
    del files['Cargo.toml']
    base = dataclasses.replace(
        fixture_base(bundle),
        members=tuple(row for row in bundle['members'] if row['path'] != 'Cargo.toml'))
    root = tmp_path / 'snap'
    root.mkdir()
    write_snapshot(root, files)
    with pytest.raises(ProxyProducerError) as raised:
        seal_code_snapshot(root, base=base, origin='local-test-fixture',
                           toolchain_manifest_sha256=CURRENT_MANIFEST)
    assert type(raised.value) is ProxyProducerError
    assert 'Cargo.toml' in str(raised.value)


def test_snapshot_verify_detects_post_seal_changes(tmp_path):
    from p11lab.round_core.proxy_worker import seal_code_snapshot, verify_snapshot_source
    bundle = build_fixture(TAG_A, 'atest-dep')
    root = tmp_path / 'snap'
    root.mkdir()
    write_snapshot(root, bundle['files'])
    selection = seal_code_snapshot(root, base=fixture_base(bundle), origin='local-test-fixture',
                                   toolchain_manifest_sha256=CURRENT_MANIFEST)
    verify_snapshot_source(selection, root)
    (root / 'crates/proxy/src/main.rs').write_bytes(b'tampered\n')
    with pytest.raises(ProxyProducerError):
        verify_snapshot_source(selection, root)


def test_verify_snapshot_degenerate_selection_without_root_manifest_is_typed_refusal(tmp_path):
    from p11lab.round_core.proxy_worker import ProxyProducerSelection, verify_snapshot_source
    bundle = build_fixture(TAG_A, 'atest-dep')
    files = dict(bundle['files'])
    del files['Cargo.toml']
    selection = ProxyProducerSelection(
        origin='local-test-fixture', source_commit=None, source_archive_sha256=None,
        source_archive_size=None, source_prefix=None, source_tree=oracle_tree(files),
        source_members=tuple(oracle_members(files)), cargo_lock_sha256=bundle['lock_sha256'],
        vendor_packages=tuple(bundle['vendor']), toolchain_manifest_sha256=CURRENT_MANIFEST,
        provider_parent={'status': 'unselected', 'detail': 'later-integration-slice'},
        caller_origin='local-controller', caller_run_id=None, caller_job_id=None)
    root = tmp_path / 'snap'
    root.mkdir()
    write_snapshot(root, files)
    with pytest.raises(ProxyProducerError) as raised:
        verify_snapshot_source(selection, root)
    assert type(raised.value) is ProxyProducerError
    assert 'Cargo.toml' in str(raised.value)


def test_default_snapshot_base_binds_installed_selection():
    from p11lab.round_core.proxy_worker import default_snapshot_base
    base = default_snapshot_base()
    assert base.cargo_lock_sha256 == SELECTED_LOCK
    assert len(base.members) == 689
    assert len(base.vendor_roster) == 282
    assert {row['path'] for row in base.members if row['path'].endswith('Cargo.toml')} >= {
        'Cargo.toml', 'crates/cli/Cargo.toml', 'crates/shim/Cargo.toml'}


def test_release_profile_check_requires_exact_selected_settings():
    from p11lab.round_core.proxy_worker import check_release_profile
    good = b'[package]\nname = "x"\n[profile.release]\nlto = "thin"\nstrip = "symbols"\ncodegen-units = 1\n'
    assert check_release_profile(good) == {'lto': 'thin', 'strip': 'symbols', 'codegen-units': 1}
    for bad in (b'[package]\nname = "x"\n',
                b'[profile.release]\nlto = "fat"\nstrip = "symbols"\ncodegen-units = 1\n',
                b'[profile.release]\nlto = "thin"\nstrip = "none"\ncodegen-units = 1\n',
                b'[profile.release]\nlto = "thin"\nstrip = "symbols"\ncodegen-units = 16\n',
                b'[profile.release]\nlto = true\nstrip = "symbols"\ncodegen-units = 1\n',
                b'[profile.release]\nlto = "thin"\nstrip = "symbols"\ncodegen-units = 1\nopt-level = 0\n',
                b'[profile.release]\nlto = "thin"\nstrip = "symbols"\ncodegen-units = 1\npanic = "abort"\n',
                b'[profile.release]\nlto = "thin"\nstrip = "symbols"\ncodegen-units = 1\ndebug = true\n',
                b'not [valid toml'):
        with pytest.raises(ProxyProducerError):
            check_release_profile(bad)
    with pytest.raises(ProxyProducerError) as raised:
        check_release_profile(
            b'[profile.release]\nlto = "thin"\nstrip = "symbols"\ncodegen-units = 1\n'
            b'panic = "abort"\nopt-level = 0\n')
    assert str(raised.value) == ('workspace release profile carries unselected keys: '
                                 "['opt-level', 'panic']")


# ---------------------------------------------------------------------------
# Inert ELF inspection: kinds, exports, versioned requirements, floors.
# ---------------------------------------------------------------------------

def test_elf_rich_shim_reports_exports_and_floors():
    from p11lab.round_core.proxy_worker import inspect_producer_elf
    info = inspect_producer_elf(RICH_SHIM)
    assert info['elf_type'] == 3
    assert info['kind'] == 'shared-object'
    assert info['machine'] == 62
    assert info['class'] == 64
    assert info['data'] == 'lsb'
    assert info['interpreter'] is None
    assert info['needed'] == ['libc.so.6', 'libgcc_s.so.1']
    assert info['soname'] == 'libpkcs11_proxy_ng_shim.so'
    assert info['search_paths'] == []
    assert info['exports'] == [
        {'name': 'C_GetFunctionList', 'bind': 'global', 'type': 'func', 'visibility': 'default'},
        {'name': 'shim_marker', 'bind': 'global', 'type': 'object', 'visibility': 'default'}]
    assert info['exports_truncated'] is False
    assert info['undefined'] == ['__gcc_personality_v0', 'memcpy', 'printf']
    assert info['version_requirements'] == [
        {'file': 'libc.so.6', 'name': 'GLIBC_2.2.5'},
        {'file': 'libc.so.6', 'name': 'GLIBC_2.34'},
        {'file': 'libgcc_s.so.1', 'name': 'GCC_3.0'}]
    assert info['floors'] == {'libc.so.6': {'GLIBC': '2.34'}, 'libgcc_s.so.1': {'GCC': '3.0'}}


def test_elf_pie_and_static_kinds():
    from p11lab.round_core.proxy_worker import inspect_producer_elf
    pie = inspect_producer_elf(RICH_PIE)
    assert pie['kind'] == 'pie-executable'
    assert pie['interpreter'] == '/lib64/ld-linux-x86-64.so.2'
    assert pie['floors'] == {'libc.so.6': {'GLIBC': '2.34'}}
    static = inspect_producer_elf(STATIC_EXEC)
    assert static['kind'] == 'executable'
    assert static['interpreter'] is None
    assert static['needed'] == []
    assert static['exports'] == []
    assert static['version_requirements'] == []
    assert static['floors'] == {}


def test_elf_gnu_hash_symbols_are_read():
    from p11lab.round_core.proxy_worker import inspect_producer_elf
    raw = build_elf(
        elf_type=3, needed=('libc.so.6',), gnu_hash=True,
        symbols=(('C_GetFunctionList', 1, 2, True), ('puts', 1, 2, False),),
        verneed=(('libc.so.6', ('GLIBC_2.17',)),))
    info = inspect_producer_elf(raw)
    assert info['exports'] == [
        {'name': 'C_GetFunctionList', 'bind': 'global', 'type': 'func', 'visibility': 'default'}]
    assert info['undefined'] == ['puts']
    assert info['floors'] == {'libc.so.6': {'GLIBC': '2.17'}}


def test_elf_truncations_and_bad_headers_are_rejected():
    from p11lab.round_core.proxy_worker import inspect_producer_elf
    for end in (0, 10, 63, 64, 100, len(RICH_SHIM) - 10):
        with pytest.raises(ProxyProducerError):
            inspect_producer_elf(RICH_SHIM[:end])
    with pytest.raises(ProxyProducerError):
        inspect_producer_elf(b'not an elf at all' + b'\0' * 64)
    with pytest.raises(ProxyProducerError):
        inspect_producer_elf(build_elf(elf_class=1, needed=('libc.so.6',)))
    with pytest.raises(ProxyProducerError):
        inspect_producer_elf(build_elf(machine=3, needed=('libc.so.6',)))
    with pytest.raises(ProxyProducerError):
        inspect_producer_elf(build_elf(data=2, needed=('libc.so.6',)))


def test_elf_corrupt_tables_are_rejected():
    from p11lab.round_core.proxy_worker import inspect_producer_elf
    raw, layout = build_elf(
        elf_type=3, needed=('libc.so.6',),
        symbols=(('C_GetFunctionList', 1, 2, True), ('puts', 1, 2, False),),
        verneed=(('libc.so.6', ('GLIBC_2.34',)),), return_layout=True)

    def corrupt(at, chunk):
        mutated = bytearray(raw)
        mutated[at:at + len(chunk)] = chunk
        with pytest.raises(ProxyProducerError):
            inspect_producer_elf(bytes(mutated))

    corrupt(layout['dynamic'] + 1 * 16 + 8, struct.pack('<Q', 0x0BADF00D))  # STRTAB unmapped
    corrupt(layout['dynamic'] + 3 * 16 + 8, struct.pack('<Q', 0x0BADF00D))  # SYMTAB unmapped
    corrupt(layout['hash'], struct.pack('<II', 1, 0xFFFFFFFF))  # nchain bomb
    corrupt(layout['verneed'] + 4, struct.pack('<I', 0xFFFFFF))  # vn_file overrun
    corrupt(layout['dynsym'] + 24, struct.pack('<I', 0xFFFFFF))  # st_name overrun
    corrupt(18, struct.pack('<H', 0xFFFF))  # bad machine
    with pytest.raises(ProxyProducerError):
        inspect_producer_elf(build_elf(needed=('has/slash',)))
    with pytest.raises(ProxyProducerError):
        inspect_producer_elf(build_elf(needed=('',)))


def test_elf_export_recording_is_bounded(monkeypatch):
    from p11lab.round_core.proxy_worker import inspect_producer_elf
    monkeypatch.setattr(proxy_worker, '_MAX_RECORDED_SYMBOLS', 1)
    info = inspect_producer_elf(RICH_SHIM)
    assert info['exports_truncated'] is True
    assert len(info['exports']) == 1
    assert info['export_count'] == 2
    assert info['undefined_truncated'] is True
    assert len(info['undefined']) == 1
    assert info['undefined_count'] == 3
    assert info['requirements_truncated'] is True
    assert len(info['version_requirements']) == 1
    assert info['requirement_count'] == 3


# ---------------------------------------------------------------------------
# ABI policy: explicit expectations, recorded actuals, no silent relaxation.
# ---------------------------------------------------------------------------

def elf_infos():
    from p11lab.round_core.proxy_worker import inspect_producer_elf
    return {
        'bin/pkcs11-proxy-ng': inspect_producer_elf(RICH_PIE),
        'bin/pkcs11-proxy-ng-cli': inspect_producer_elf(RICH_PIE),
        'lib/libpkcs11_proxy_ng_shim.so': inspect_producer_elf(RICH_SHIM),
    }


def test_abi_policy_accepts_conforming_products():
    from p11lab.round_core.proxy_worker import check_producer_abi, load_producer_role_policy
    record = check_producer_abi(elf_infos(), load_producer_role_policy())
    assert record['decision'] == 'conforming-recorded'
    assert record['runtime_qualification'] == 'not-performed'
    assert record['floors']['lib/libpkcs11_proxy_ng_shim.so'] == {
        'libc.so.6': {'GLIBC': '2.34'}, 'libgcc_s.so.1': {'GCC': '3.0'}}
    assert record['shim_exports_truncated'] is False
    assert record['version_requirements_truncated'] == {
        'bin/pkcs11-proxy-ng': False, 'bin/pkcs11-proxy-ng-cli': False,
        'lib/libpkcs11_proxy_ng_shim.so': False}
    assert record['symbol_versions_truncated'] == {
        'bin/pkcs11-proxy-ng': False, 'bin/pkcs11-proxy-ng-cli': False,
        'lib/libpkcs11_proxy_ng_shim.so': False}


def test_abi_record_carries_truncation_flags(monkeypatch):
    from p11lab.round_core.proxy_worker import check_producer_abi, inspect_producer_elf
    from p11lab.round_core.proxy_worker import load_producer_role_policy
    elfs = elf_infos()
    monkeypatch.setattr(proxy_worker, '_MAX_RECORDED_SYMBOLS', 1)
    info = inspect_producer_elf(build_elf(
        elf_type=3, needed=('libc.so.6',),
        symbols=(('C_GetFunctionList', 1, 2, True), ('zzz_extra', 1, 2, True),
                 ('puts', 1, 2, False), ('gets', 1, 2, False)),
        verneed=(('libc.so.6', ('GLIBC_2.2.5', 'GLIBC_2.34')),)))
    assert info['exports_truncated'] is True
    assert info['requirements_truncated'] is True
    assert info['symbol_versions_truncated'] is True
    shim = 'lib/libpkcs11_proxy_ng_shim.so'
    elfs[shim] = info
    record = check_producer_abi(elfs, load_producer_role_policy())
    assert record['decision'] == 'conforming-recorded'
    assert record['shim_exports_truncated'] is True
    assert record['version_requirements_truncated'][shim] is True
    assert record['symbol_versions_truncated'][shim] is True
    assert record['version_requirements_truncated']['bin/pkcs11-proxy-ng'] is False
    assert record['symbol_versions_truncated']['bin/pkcs11-proxy-ng'] is False


def test_abi_policy_rejects_wrong_kinds_and_loaders():
    from p11lab.round_core.proxy_worker import check_producer_abi, load_producer_role_policy
    from p11lab.round_core.proxy_worker import inspect_producer_elf
    policy = load_producer_role_policy()

    def check(replace):
        infos = elf_infos()
        infos.update(replace)
        with pytest.raises(ProxyProducerError):
            check_producer_abi(infos, policy)

    check({'bin/pkcs11-proxy-ng': inspect_producer_elf(STATIC_EXEC)})  # not dynamic
    check({'lib/libpkcs11_proxy_ng_shim.so': inspect_producer_elf(RICH_PIE)})  # shim with loader
    check({'bin/pkcs11-proxy-ng-cli': inspect_producer_elf(RICH_SHIM)})  # bin as shared object
    other_interp = build_elf(elf_type=3, interpreter='/lib/ld-musl-x86_64.so.1',
                             needed=('libc.so.6',))
    check({'bin/pkcs11-proxy-ng': inspect_producer_elf(other_interp)})
    with_runpath = build_elf(elf_type=3, interpreter='/lib64/ld-linux-x86-64.so.2',
                             needed=('libc.so.6',), runpath='$ORIGIN/../lib')
    assert inspect_producer_elf(with_runpath)['search_paths'] == ['$ORIGIN/../lib']
    check({'bin/pkcs11-proxy-ng': inspect_producer_elf(with_runpath)})


def test_abi_policy_rejects_unsupported_dependencies_and_exports():
    from p11lab.round_core.proxy_worker import check_producer_abi, load_producer_role_policy
    from p11lab.round_core.proxy_worker import inspect_producer_elf
    policy = load_producer_role_policy()
    infos = elf_infos()
    infos['bin/pkcs11-proxy-ng'] = inspect_producer_elf(build_elf(
        elf_type=3, interpreter='/lib64/ld-linux-x86-64.so.2', needed=('libssl.so.3',)))
    with pytest.raises(ProxyProducerError):
        check_producer_abi(infos, policy)
    infos = elf_infos()
    infos['lib/libpkcs11_proxy_ng_shim.so'] = inspect_producer_elf(build_elf(
        elf_type=3, needed=('libc.so.6',),
        symbols=(('other_symbol', 1, 2, True),)))
    with pytest.raises(ProxyProducerError):
        check_producer_abi(infos, policy)


def test_abi_policy_enforces_ceilings_only_when_selected():
    from p11lab.round_core.proxy_worker import check_producer_abi, load_producer_role_policy
    policy = load_producer_role_policy()
    assert policy['version_ceilings'] is None
    check_producer_abi(elf_infos(), policy)
    strict = dict(policy, version_ceilings={'libc.so.6': {'GLIBC': '2.17'}})
    with pytest.raises(ProxyProducerError):
        check_producer_abi(elf_infos(), strict)
    loose = dict(policy, version_ceilings={'libc.so.6': {'GLIBC': '2.34'},
                                           'libgcc_s.so.1': {'GCC': '3.4'}})
    record = check_producer_abi(elf_infos(), loose)
    assert record['decision'] == 'conforming-recorded'


# ---------------------------------------------------------------------------
# Container run spec and boundary inspection.
# ---------------------------------------------------------------------------

def expected_command():
    from p11lab.round_core.proxy_worker import load_producer_role_policy
    policy = load_producer_role_policy()
    command = ['-i']
    for key, value in policy['environment'].items():
        command.append(key + '=' + value)
    return command + ['/bin/sh', '-ec', proxy_worker._BUILD_SCRIPT]


def expected_options(staging_src, volume):
    return [
        '--pull=never', '--user', '65532:65532', '--read-only',
        '--network', 'none', '--ipc', 'private', '--cap-drop', 'ALL',
        '--security-opt', 'no-new-privileges=true', '--pids-limit', '128',
        '--memory', '4g', '--memory-swap', '4g', '--cpus', '2',
        '--ulimit', 'nofile=1024:1024', '--log-driver', 'none',
        '--tmpfs', '/scratch:rw,nosuid,nodev,exec,size=2147483648,nr_inodes=40000,mode=1777',
        '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=134217728,nr_inodes=16384,mode=1777',
        '--mount', 'type=bind,src=' + staging_src + ',dst=/inputs,readonly',
        '--mount', 'type=volume,src=' + volume + ',dst=/out',
        '--entrypoint', '/usr/bin/env',
    ]


# Daemon-reported mount options, pinned 2026-10-30 on the local daemon with
# equivalent --mount flags (hello-world create+inspect+rm; volume removed
# after): bind Mode "" / Propagation "rprivate"; volume Driver "local" /
# Mode "z". Mirrors the verifier constants in proxy_worker; live
# reconfirmation required at the next live producer run.
def expected_mounts(staging_src, volume):
    return [
        {'Type': 'bind', 'Source': staging_src, 'Destination': '/inputs', 'RW': False,
         'Mode': '', 'Propagation': 'rprivate'},
        {'Type': 'volume', 'Name': volume, 'Destination': '/out', 'RW': True,
         'Driver': 'local', 'Mode': 'z'},
    ]


def test_run_spec_pins_exact_boundary_argv_and_mounts(tmp_path):
    from p11lab.round_core.proxy_worker import producer_run_spec
    spec = producer_run_spec(staging_source=tmp_path / 'staging' / 'source',
                             output_volume='p11lab-proxy-deadbeef-build-output')
    assert spec['image_role'] == 'warm-verified-toolchain'
    assert spec['command'] == expected_command()
    assert spec['options'] == expected_options(str(tmp_path / 'staging' / 'source'),
                                               'p11lab-proxy-deadbeef-build-output')
    assert spec['mounts'] == ['type=bind,src=' + str(tmp_path / 'staging' / 'source') + ',dst=/inputs,readonly',
                              'type=volume,src=p11lab-proxy-deadbeef-build-output,dst=/out']
    assert spec['build_timeout_seconds'] == 480
    joined = ' '.join(spec['options'] + spec['command'])
    for forbidden in ('--privileged', '/var/run/docker.sock', 'RUSTFLAGS', 'RUSTC_WRAPPER',
                      'credential', '--network host', '--network=host', '-v ', '--volume',
                      'latest', 'SYS_CHROOT', '--cap-add'):
        assert forbidden not in joined
    assert '--pull=never' in spec['options']


def test_run_spec_rejects_unsafe_staging_and_volume_names(tmp_path):
    from p11lab.round_core.proxy_worker import producer_run_spec
    with pytest.raises(ProxyProducerError):
        producer_run_spec(staging_source=tmp_path / 'a,b', output_volume='p11lab-proxy-x-output')
    with pytest.raises(ProxyProducerError):
        producer_run_spec(staging_source=tmp_path / 'staging', output_volume='has space')
    with pytest.raises(ProxyProducerError):
        producer_run_spec(staging_source=tmp_path / 'staging', output_volume='has,comma')


def test_boundary_verifier_accepts_exact_observation():
    from p11lab.round_core.proxy_worker import verify_producer_boundary
    observed = canned_inspection(running=True, pid=456)
    observed['Mounts'] = expected_mounts('/staging/source', 'vol-1')
    observed['Config']['Cmd'] = expected_command()
    verify_producer_boundary(observed, FAKE_IMAGE, expected_command(),
                             ['type=bind,src=/staging/source,dst=/inputs,readonly',
                              'type=volume,src=vol-1,dst=/out'])


def test_boundary_verifier_rejects_every_mutation():
    from p11lab.round_core.proxy_worker import verify_producer_boundary
    command = expected_command()
    mounts = ['type=bind,src=/staging/source,dst=/inputs,readonly',
              'type=volume,src=vol-1,dst=/out']

    def mutate(apply):
        observed = canned_inspection(running=True, pid=456)
        observed['Mounts'] = expected_mounts('/staging/source', 'vol-1')
        observed['Config']['Cmd'] = list(command)
        apply(observed)
        with pytest.raises(ProxyProducerError):
            verify_producer_boundary(observed, FAKE_IMAGE, command, mounts)

    mutate(lambda o: o.__setitem__('Image', 'sha256:' + '00' * 32))
    mutate(lambda o: o['Config'].__setitem__('User', '0:0'))
    mutate(lambda o: o['Config'].__setitem__('Entrypoint', ['/bin/sh']))
    mutate(lambda o: o['Config'].__setitem__('Cmd', command + ['extra']))
    mutate(lambda o: o['HostConfig'].__setitem__('NetworkMode', 'bridge'))
    mutate(lambda o: o['HostConfig'].__setitem__('CapDrop', []))
    mutate(lambda o: o['HostConfig'].__setitem__('CapAdd', ['SYS_CHROOT']))
    mutate(lambda o: o['HostConfig'].__setitem__('ReadonlyRootfs', False))
    mutate(lambda o: o['HostConfig'].__setitem__('Privileged', True))
    mutate(lambda o: o['HostConfig'].__setitem__('PidsLimit', 64))
    mutate(lambda o: o['HostConfig'].__setitem__('Memory', 1024 ** 3))
    mutate(lambda o: o['HostConfig'].__setitem__('MemorySwap', 1024 ** 3))
    mutate(lambda o: o['HostConfig'].__setitem__('NanoCpus', 1000000000))
    mutate(lambda o: o['HostConfig'].__setitem__('SecurityOpt', []))
    mutate(lambda o: o['HostConfig'].__setitem__('IpcMode', 'host'))
    mutate(lambda o: o['HostConfig'].__setitem__('PidMode', 'host'))
    mutate(lambda o: o['HostConfig'].__setitem__('Tmpfs', {'/tmp': 'rw'}))
    wrong_tmpfs = dict(canned_inspection(running=True, pid=1)['HostConfig']['Tmpfs'])
    wrong_tmpfs['/scratch'] = wrong_tmpfs['/scratch'].replace('exec', 'noexec')
    mutate(lambda o: o['HostConfig'].__setitem__('Tmpfs', wrong_tmpfs))
    mutate(lambda o: o['HostConfig'].__setitem__('Ulimits', []))
    mutate(lambda o: o['HostConfig'].__setitem__('LogConfig', {'Type': 'json-file'}))
    mutate(lambda o: o['HostConfig'].__setitem__('Binds', ['/host:/host']))
    mutate(lambda o: o['Mounts'].append(
        {'Type': 'bind', 'Source': '/etc', 'Destination': '/etc', 'RW': False}))
    mutate(lambda o: o['Mounts'].pop())
    mutate(lambda o: o['Mounts'][0].__setitem__('RW', True))
    mutate(lambda o: o['Mounts'][1].__setitem__('Destination', '/elsewhere'))
    mutate(lambda o: o['Mounts'][0].__setitem__('Propagation', 'shared'))
    mutate(lambda o: o['Mounts'][1].__setitem__('Driver', 'evil'))
    mutate(lambda o: o['Mounts'][0].__setitem__('Mode', 'z'))
    mutate(lambda o: o['Mounts'][1].__setitem__('Mode', 'rw'))


# ---------------------------------------------------------------------------
# Attempt flow against a scripted engine (no daemon, no retained inputs).
# ---------------------------------------------------------------------------

def write_fixture_inputs(root, bundle):
    from p11lab.proxy_inputs import ProxyInputCache
    archive = root / 'source.tar.gz'
    archive.write_bytes(bundle['archive'])
    crates = root / 'crates'
    crates.mkdir()
    (crates / (bundle['vendor'][0]['identity'] + '.crate')).write_bytes(bundle['crate'])
    cache = ProxyInputCache(source_archive=archive, payload_root=root,
                            vendor_root=root / 'vendor',
                            debian_receipt=root / 'resolved-inputs.json')
    return archive, crates, cache


def green_cp():
    return FakeCp(readback_tar_bytes({
        'bin/pkcs11-proxy-ng': RICH_PIE,
        'bin/pkcs11-proxy-ng-cli': RICH_PIE,
        'lib/libpkcs11_proxy_ng_shim.so': RICH_SHIM}))


def flow_engine(execute_result=None, **kwargs):
    before = canned_inspection(running=True, pid=789)
    before['Config']['Cmd'] = expected_command()
    stopped = canned_inspection(running=False, pid=0)
    stopped['Config']['Cmd'] = expected_command()
    return FakeEngine(inspection_before=before, inspection_stopped=stopped,
                      execute_result=execute_result or CommandResult(0, 'Finished\n', '', False, False, False),
                      **kwargs)


def test_produce_fake_green_binds_selection_and_observation(tmp_path, monkeypatch):
    import p11lab.round_core.worker as worker_module
    from p11lab.proxy_inputs import ProxyInputCache
    from p11lab.round_core.proxy_worker import produce_proxy_candidate
    bundle = build_fixture(TAG_A, 'atest-dep')
    archive, crates, cache = write_fixture_inputs(tmp_path, bundle)
    assert type(cache) is ProxyInputCache
    toolchain_output = tmp_path / 'toolchain'
    toolchain_output.mkdir()
    output = tmp_path / 'attempt'
    engine = flow_engine()
    calls = []
    monkeypatch.setattr(proxy_worker, 'verify_proxy_toolchain',
                        lambda out, **kwargs: calls.append((out, kwargs)) or canned_warm())
    cp = green_cp()
    monkeypatch.setattr(worker_module, 'supervised_exec', cp)
    result = produce_proxy_candidate(
        fixture_selection(bundle), source_archive=archive, vendor_archives=crates,
        cache=cache, toolchain_output=toolchain_output, output_dir=output, engine=engine)
    assert result['status'] == 'local-production-observed'
    assert result['qualification'] is False
    assert result['rights'] == 'unreviewed'
    assert result['authority'] == 'not-established'
    receipt_path = output / 'proxy-producer-observation.json'
    raw = receipt_path.read_bytes()
    assert result['completion_witness']['receipt_sha256'] == sha256(raw)
    assert result['completion_witness']['authority'] == 'not-established'
    assert result['completion_witness']['prior_attempt_completion'] == 'unconfirmed'
    data = json.loads(raw)
    assert data['status'] == 'observation-prepared'
    assert data['attempt_completion'] == 'unconfirmed'
    assert 'completion_witness' not in data
    assert b'authenticated' not in raw
    assert data['selection']['source_archive_sha256'] == bundle['archive_sha256']
    assert data['selection']['cargo_lock_sha256'] == bundle['lock_sha256']
    assert data['selection']['origin'] == 'local-test-fixture'
    assert data['toolchain']['image']['engine_id'] == FAKE_IMAGE
    assert data['toolchain']['warm_status'] == 'local-byte-verification-observed'
    assert data['toolchain']['manifest_sha256'] == CURRENT_MANIFEST
    assert data['build_view']['removed_candidate_cargo'] == []
    assert data['build_view']['workspace'] == bundle['workspace']
    assert data['staging']['before'] == data['staging']['after']
    assert data['originals']['before'] == data['originals']['after']
    assert [row['path'] for row in data['products']] == [
        'bin/pkcs11-proxy-ng', 'bin/pkcs11-proxy-ng-cli', 'lib/libpkcs11_proxy_ng_shim.so']
    assert data['products'][0]['sha256'] == sha256(RICH_PIE)
    assert data['products'][2]['sha256'] == sha256(RICH_SHIM)
    assert data['abi']['decision'] == 'conforming-recorded'
    assert data['cleanup_errors'] == []
    assert data['absence']['containers'] == '' and data['absence']['volumes'] == ''
    assert data['interrupted_signal'] is None
    assert data['deadline']['limit_seconds'] == 600
    assert data['deadline']['verdict'] == 'within-budget'
    assert data['deadline']['elapsed_seconds'] == data['phases']['elapsed_seconds']
    # The stubbed warm call carried the retained coordinates and a fresh dir.
    assert len(calls) == 1 and calls[0][0] == toolchain_output
    assert calls[0][1]['manifest_sha256'] == CURRENT_MANIFEST
    assert calls[0][1]['cache'] is cache
    assert str(calls[0][1]['verification_dir']).startswith(str(output))
    # Exact requested boundary: options, command, volume quotas.
    assert engine.create_argv == expected_command()
    staging_src = str(output / 'staging' / 'source')
    assert engine.create_options == expected_options(staging_src, engine.volume_name)
    assert engine.volume_name.startswith('p11lab-proxy-')
    assert engine.volume_name.endswith('-build-output')
    assert engine.volume_options == {'type': 'tmpfs', 'device': 'tmpfs',
                                     'o': 'size=134217728,nr_inodes=10000,mode=1777,uid=65532,gid=65532'}
    assert engine.ops[engine.ops.index(('execute', FAKE_CANDIDATE_ID, 480))][2] == 480
    # Stop and terminal inspection strictly precede the first readback byte.
    kinds = [op[0] for op in engine.ops]
    assert kinds.index('create') < kinds.index('execute') < kinds.index('stop')
    assert cp.calls, 'readback transport was never used'
    assert engine.inspect_calls >= 2
    assert all(call['cwd'] == str(output / 'products') for call in cp.calls)
    assert data['stop']['running'] is False and data['stop']['pid'] == 0
    # Staged build view: controller cargo config plus materialized vendor.
    staged = output / 'staging' / 'source'
    assert (staged / '.cargo' / 'config.toml').read_bytes() == proxy_worker._CONTROLLER_CARGO_CONFIG.encode()
    vendor_dir = staged / 'vendor' / bundle['vendor'][0]['identity']
    assert (vendor_dir / '.cargo-checksum.json').is_file()
    assert json.loads((vendor_dir / '.cargo-checksum.json').read_bytes())['package'] == sha256(bundle['crate'])
    assert (staged / 'crates' / 'proxy' / 'src' / 'main.rs').is_file()
    assert not (staged / 'vendor').is_symlink()


def test_produce_fake_config_candidate_is_neutralized(tmp_path, monkeypatch):
    import p11lab.round_core.worker as worker_module
    from p11lab.round_core.proxy_worker import produce_proxy_candidate
    bundle = build_fixture(TAG_A, 'atest-dep')
    files = dict(bundle['files'])
    files['.cargo/config.toml'] = ('file', b'[registries.staging]\ncredential-provider = "cargo:token"\n', 0o644)
    files['evil-helper.sh'] = ('file', b'#!/bin/sh\necho PWNED\n', 0o755)
    archive = make_source_archive(bundle['prefix'], files)
    selection = dataclasses.replace(
        fixture_selection(bundle), source_archive_sha256=sha256(archive),
        source_archive_size=len(archive), source_members=tuple(oracle_members(files)),
        source_tree=oracle_tree(files))
    root = tmp_path / 'inputs'
    root.mkdir()
    archive_path = root / 'source.tar.gz'
    archive_path.write_bytes(archive)
    crates = root / 'crates'
    crates.mkdir()
    (crates / (bundle['vendor'][0]['identity'] + '.crate')).write_bytes(bundle['crate'])
    from p11lab.proxy_inputs import ProxyInputCache
    cache = ProxyInputCache(source_archive=archive_path, payload_root=root,
                            vendor_root=root / 'vendor', debian_receipt=root / 'resolved-inputs.json')
    toolchain_output = tmp_path / 'toolchain'
    toolchain_output.mkdir()
    output = tmp_path / 'attempt'
    engine = flow_engine()
    monkeypatch.setattr(proxy_worker, 'verify_proxy_toolchain', lambda out, **kwargs: canned_warm())
    monkeypatch.setattr(worker_module, 'supervised_exec', green_cp())
    result = produce_proxy_candidate(selection, source_archive=archive_path, vendor_archives=crates,
                                     cache=cache, toolchain_output=toolchain_output,
                                     output_dir=output, engine=engine)
    assert result['status'] == 'local-production-observed'
    data = json.loads((output / 'proxy-producer-observation.json').read_bytes())
    assert data['build_view']['removed_candidate_cargo'] == ['.cargo/config.toml']
    staged = output / 'staging' / 'source'
    assert (staged / '.cargo' / 'config.toml').read_bytes() == proxy_worker._CONTROLLER_CARGO_CONFIG.encode()
    assert (staged / 'evil-helper.sh').is_file()  # inert: no config references it
    assert 'evil-helper' not in (staged / '.cargo' / 'config.toml').read_text()


def test_produce_fake_snapshot_flow_is_green(tmp_path, monkeypatch):
    import p11lab.round_core.worker as worker_module
    from p11lab.proxy_inputs import ProxyInputCache
    from p11lab.round_core.proxy_worker import produce_proxy_candidate, seal_code_snapshot
    bundle = build_fixture(TAG_B, 'btest-dep')
    files = dict(bundle['files'])
    files['docs-link'] = ('link', 'crates/cli/src/main.rs', 0o777)
    snap = tmp_path / 'snap'
    snap.mkdir()
    write_snapshot(snap, files)
    selection = seal_code_snapshot(snap, base=fixture_base(bundle), origin='local-test-fixture',
                                   toolchain_manifest_sha256=CURRENT_MANIFEST)
    crates = tmp_path / 'crates'
    crates.mkdir()
    (crates / (bundle['vendor'][0]['identity'] + '.crate')).write_bytes(bundle['crate'])
    cache = ProxyInputCache(source_archive=tmp_path / 'unused.tar.gz', payload_root=tmp_path,
                            vendor_root=tmp_path / 'vendor',
                            debian_receipt=tmp_path / 'resolved-inputs.json')
    toolchain_output = tmp_path / 'toolchain'
    toolchain_output.mkdir()
    output = tmp_path / 'attempt'
    engine = flow_engine()
    monkeypatch.setattr(proxy_worker, 'verify_proxy_toolchain', lambda out, **kwargs: canned_warm())
    monkeypatch.setattr(worker_module, 'supervised_exec', green_cp())
    result = produce_proxy_candidate(selection, snapshot_dir=snap, vendor_archives=crates,
                                     cache=cache, toolchain_output=toolchain_output,
                                     output_dir=output, engine=engine)
    assert result['status'] == 'local-production-observed'
    staged_link = output / 'staging' / 'source' / 'docs-link'
    assert staged_link.is_symlink()
    assert os.readlink(staged_link) == 'crates/cli/src/main.rs'


def run_flow(tmp_path, monkeypatch, bundle, *, execute_result=None, before=None,
             warm=None, cp=None, list_leftover='', interrupted=None, remove_raises=False,
             tag='flow'):
    import p11lab.round_core.worker as worker_module
    from p11lab.round_core.proxy_worker import produce_proxy_candidate
    root = tmp_path / tag
    root.mkdir(parents=True)
    archive, crates, cache = write_fixture_inputs(root, bundle)
    toolchain_output = root / 'toolchain'
    toolchain_output.mkdir()
    output = root / 'attempt'
    inspection_before = before or canned_inspection(running=True, pid=789)
    inspection_before['Config']['Cmd'] = expected_command()
    stopped = canned_inspection(running=False, pid=0)
    stopped['Config']['Cmd'] = expected_command()
    engine = FakeEngine(inspection_before=inspection_before, inspection_stopped=stopped,
                        execute_result=execute_result or CommandResult(0, 'ok\n', '', False, False, False),
                        list_leftover=list_leftover)
    if remove_raises:
        from p11lab.docker import DockerError

        def failing_remove(kind, identity, labels):
            engine.ops.append(('remove', kind, identity))
            raise DockerError('simulated removal failure')
        engine.remove = failing_remove
    monkeypatch.setattr(proxy_worker, 'verify_proxy_toolchain',
                        lambda out, **kwargs: canned_warm(**(warm or {})))
    fake_cp = cp or green_cp()
    monkeypatch.setattr(worker_module, 'supervised_exec', fake_cp)
    try:
        result = produce_proxy_candidate(
            fixture_selection(bundle), source_archive=archive, vendor_archives=crates,
            cache=cache, toolchain_output=toolchain_output, output_dir=output,
            engine=engine, interrupted=interrupted)
    except BaseException as error:
        return error, output, engine, fake_cp
    return result, output, engine, fake_cp


def read_receipt(output):
    raw = (output / 'proxy-producer-observation.json').read_bytes()
    assert b'authenticated' not in raw
    data = json.loads(raw)
    assert data['qualification'] is False
    assert data['rights'] == 'unreviewed'
    assert data['authority'] == 'not-established'
    assert 'completion_witness' not in data
    assert data['integrity_errors'] == []
    return data


def test_produce_refuses_changed_boundary_before_readback(tmp_path, monkeypatch):
    bundle = build_fixture(TAG_A, 'atest-dep')
    before = canned_inspection(running=True, pid=789)
    before['HostConfig']['Memory'] = 1024 ** 3
    error, output, engine, fake_cp = run_flow(tmp_path, monkeypatch, bundle, before=before)
    assert isinstance(error, ProxyProducerError)
    assert 'boundary' in str(error)
    assert fake_cp.calls == []
    data = read_receipt(output)
    assert data['status'] == 'failed'
    assert 'boundary' in data['error']['message']
    assert ('remove', 'container', FAKE_CANDIDATE_ID) in engine.ops
    assert ('remove', 'volume', engine.volume_name) in engine.ops


def test_produce_preserves_native_build_failure(tmp_path, monkeypatch):
    bundle = build_fixture(TAG_A, 'atest-dep')
    failed = CommandResult(101, 'Compiling x\n', 'error: build script failed\n',
                           False, False, False)
    error, output, engine, fake_cp = run_flow(tmp_path, monkeypatch, bundle, execute_result=failed)
    assert isinstance(error, ProxyProducerError)
    assert '101' in str(error)
    assert fake_cp.calls == []
    data = read_receipt(output)
    assert data['status'] == 'failed'
    assert data['native']['returncode'] == 101
    assert data['native']['stderr'] == 'error: build script failed\n'
    assert data['stop']['running'] is False and data['stop']['pid'] == 0
    assert data['absence'] == {'containers': '', 'volumes': ''}


def test_produce_preserves_timeout_and_cancel(tmp_path, monkeypatch):
    import signal
    bundle = build_fixture(TAG_A, 'atest-dep')
    timed_out = CommandResult(124, '', '', True, False, False)
    error, output, engine, fake_cp = run_flow(tmp_path, monkeypatch, bundle, execute_result=timed_out)
    assert isinstance(error, TimeoutError)
    assert fake_cp.calls == []
    data = read_receipt(output)
    assert data['status'] == 'failed'
    assert data['native']['timed_out'] is True
    assert data['stop']['pid'] == 0
    error, output, engine, fake_cp = run_flow(
        tmp_path, monkeypatch, bundle, interrupted=lambda: signal.SIGTERM, tag='cancel')
    assert isinstance(error, InterruptedError)
    data = read_receipt(output)
    assert data['interrupted_signal'] == signal.SIGTERM


def test_produce_refuses_truncated_logs(tmp_path, monkeypatch):
    bundle = build_fixture(TAG_A, 'atest-dep')
    truncated = CommandResult(0, 'ok\n', '', False, True, False)
    error, output, engine, fake_cp = run_flow(tmp_path, monkeypatch, bundle, execute_result=truncated)
    assert isinstance(error, ProxyProducerError)
    assert 'log limit' in str(error)
    assert fake_cp.calls == []


def test_produce_refuses_roster_and_abi_violations(tmp_path, monkeypatch):
    bundle = build_fixture(TAG_A, 'atest-dep')
    extra_cp = FakeCp(readback_tar_bytes({
        'bin/pkcs11-proxy-ng': RICH_PIE, 'bin/pkcs11-proxy-ng-cli': RICH_PIE,
        'lib/libpkcs11_proxy_ng_shim.so': RICH_SHIM, 'bin/evil': b'x'}))
    error, output, engine, fake_cp = run_flow(tmp_path, monkeypatch, bundle, cp=extra_cp)
    assert isinstance(error, (ValueError, ProxyProducerError))
    data = read_receipt(output)
    assert data['status'] == 'failed'
    assert data['staging']['before'] == data['staging']['after']
    assert data['absence'] == {'containers': '', 'volumes': ''}
    bad_abi_cp = FakeCp(readback_tar_bytes({
        'bin/pkcs11-proxy-ng': RICH_PIE, 'bin/pkcs11-proxy-ng-cli': RICH_PIE,
        'lib/libpkcs11_proxy_ng_shim.so': RICH_PIE}))
    error, output2, engine2, _ = run_flow(tmp_path, monkeypatch, bundle, cp=bad_abi_cp, tag='abi')
    assert isinstance(error, ProxyProducerError)
    assert 'shim' in str(error) or 'kind' in str(error) or 'loader' in str(error)


def test_produce_fails_before_docker_when_warm_is_unusable(tmp_path, monkeypatch):
    import p11lab.round_core.worker as worker_module
    from p11lab.proxy_toolchain import ToolchainError
    from p11lab.round_core.proxy_worker import produce_proxy_candidate
    bundle = build_fixture(TAG_A, 'atest-dep')
    archive, crates, cache = write_fixture_inputs(tmp_path, bundle)
    toolchain_output = tmp_path / 'toolchain'
    toolchain_output.mkdir()

    def attempt(name, warm_behavior):
        output = tmp_path / name
        engine = flow_engine()
        monkeypatch.setattr(proxy_worker, 'verify_proxy_toolchain', warm_behavior)
        monkeypatch.setattr(worker_module, 'supervised_exec', green_cp())
        with pytest.raises((ToolchainError, ProxyProducerError)):
            produce_proxy_candidate(
                fixture_selection(bundle), source_archive=archive, vendor_archives=crates,
                cache=cache, toolchain_output=toolchain_output, output_dir=output, engine=engine)
        assert not [op for op in engine.ops if op[0] in ('create', 'execute')]
        return read_receipt(output)

    def raising(out, **kwargs):
        raise ToolchainError('changed or unsealed toolchain manifest')
    data = attempt('warm-raise', raising)
    assert 'unsealed' in data['error']['message']
    data = attempt('warm-dirty', lambda out, **kwargs: canned_warm(cleanup_errors=['x']))
    assert 'cleanup' in data['error']['message']
    data = attempt('warm-status', lambda out, **kwargs: canned_warm(status='failed'))
    assert data['status'] == 'failed'


def test_produce_rejects_bad_inputs_without_touching_docker(tmp_path):
    from p11lab.proxy_inputs import ProxyInputCache
    from p11lab.round_core.proxy_worker import produce_proxy_candidate
    bundle = build_fixture(TAG_A, 'atest-dep')
    archive, crates, cache = write_fixture_inputs(tmp_path, bundle)
    toolchain_output = tmp_path / 'toolchain'
    toolchain_output.mkdir()

    class NeverEngine:
        def __getattr__(self, name):
            raise AssertionError('docker must not be used: ' + name)

    selection = fixture_selection(bundle)
    output = tmp_path / 'o1'
    with pytest.raises(TypeError):
        produce_proxy_candidate({'not': 'a selection'}, source_archive=archive,
                                vendor_archives=crates, cache=cache,
                                toolchain_output=toolchain_output, output_dir=output,
                                engine=NeverEngine())
    with pytest.raises(TypeError):
        produce_proxy_candidate(selection, source_archive=archive, vendor_archives=crates,
                                cache={'not': 'a cache'}, toolchain_output=toolchain_output,
                                output_dir=tmp_path / 'o2', engine=NeverEngine())
    with pytest.raises(ProxyProducerError):
        produce_proxy_candidate(selection, vendor_archives=crates, cache=cache,
                                toolchain_output=toolchain_output,
                                output_dir=tmp_path / 'o3', engine=NeverEngine())
    with pytest.raises(ProxyProducerError):
        produce_proxy_candidate(selection, source_archive=archive, vendor_archives=crates,
                                cache=cache, toolchain_output=tmp_path / 'missing',
                                output_dir=tmp_path / 'o4', engine=NeverEngine())
    (tmp_path / 'o5').mkdir()
    with pytest.raises(ProxyProducerError):
        produce_proxy_candidate(selection, source_archive=archive, vendor_archives=crates,
                                cache=cache, toolchain_output=toolchain_output,
                                output_dir=tmp_path / 'o5', engine=NeverEngine())
    tampered = tmp_path / 'tampered.tar.gz'
    tampered.write_bytes(bundle['archive'] + b'trailing')
    with pytest.raises(ProxyProducerError):
        produce_proxy_candidate(selection, source_archive=tampered, vendor_archives=crates,
                                cache=cache, toolchain_output=toolchain_output,
                                output_dir=tmp_path / 'o6', engine=NeverEngine())
    bad_cache = ProxyInputCache(source_archive=tmp_path / 'elsewhere.tar.gz',
                                payload_root=tmp_path, vendor_root=tmp_path / 'vendor',
                                debian_receipt=tmp_path / 'resolved-inputs.json')
    from p11lab.round_core.proxy_worker import default_proxy_selection
    default = default_proxy_selection(toolchain_manifest_sha256=CURRENT_MANIFEST)
    with pytest.raises(ProxyProducerError):
        produce_proxy_candidate(default, source_archive=archive, cache=bad_cache,
                                toolchain_output=toolchain_output,
                                output_dir=tmp_path / 'o7', engine=NeverEngine())


def test_produce_budget_refuses_late_build_start(tmp_path, monkeypatch):
    import p11lab.round_core.worker as worker_module
    from p11lab.round_core.proxy_worker import produce_proxy_candidate
    bundle = build_fixture(TAG_A, 'atest-dep')
    archive, crates, cache = write_fixture_inputs(tmp_path, bundle)
    toolchain_output = tmp_path / 'toolchain'
    toolchain_output.mkdir()
    output = tmp_path / 'attempt'
    engine = flow_engine()
    clock = {'now': 1000.0}
    monkeypatch.setattr(proxy_worker, '_clock', lambda: clock['now'])

    def slow_warm(out, **kwargs):
        clock['now'] += 590.0
        return canned_warm()
    monkeypatch.setattr(proxy_worker, 'verify_proxy_toolchain', slow_warm)
    monkeypatch.setattr(worker_module, 'supervised_exec', green_cp())
    with pytest.raises(ProxyProducerError) as raised:
        produce_proxy_candidate(
            fixture_selection(bundle), source_archive=archive, vendor_archives=crates,
            cache=cache, toolchain_output=toolchain_output, output_dir=output, engine=engine)
    assert 'remaining budget' in str(raised.value)
    assert not [op for op in engine.ops if op[0] in ('create', 'execute')]
    data = read_receipt(output)
    assert data['status'] == 'failed'


def test_produce_cleanup_failure_is_never_success(tmp_path, monkeypatch):
    bundle = build_fixture(TAG_A, 'atest-dep')
    error, output, engine, _ = run_flow(tmp_path, monkeypatch, bundle, remove_raises=True)
    assert isinstance(error, ProxyProducerError)
    assert 'cleanup' in str(error)
    data = read_receipt(output)
    assert data['status'] == 'failed-cleanup'
    assert data['cleanup_errors'] != []


def test_produce_after_check_errors_land_in_integrity_bucket(tmp_path, monkeypatch):
    bundle = build_fixture(TAG_A, 'atest-dep')
    real_inventory = proxy_worker._inventory_tree
    calls = {'count': 0}

    def flaky(root, limits):
        calls['count'] += 1
        if calls['count'] == 1:
            return real_inventory(root, limits)
        raise RuntimeError('simulated inventory blackout')

    monkeypatch.setattr(proxy_worker, '_inventory_tree', flaky)
    error, output, engine, _ = run_flow(tmp_path, monkeypatch, bundle)
    assert isinstance(error, RuntimeError)
    raw = (output / 'proxy-producer-observation.json').read_bytes()
    data = json.loads(raw)
    assert data['status'] == 'failed'
    assert data['cleanup_errors'] == []
    assert data['integrity_errors'] == ['staging-after: simulated inventory blackout']
    assert data['error']['type'] == 'RuntimeError'


def test_produce_leftover_resources_are_never_success(tmp_path, monkeypatch):
    bundle = build_fixture(TAG_A, 'atest-dep')
    error, output, engine, _ = run_flow(tmp_path, monkeypatch, bundle, list_leftover='deadbeef\n')
    assert isinstance(error, ProxyProducerError)
    assert 'cleanup' in str(error)
    data = read_receipt(output)
    assert data['status'] == 'failed-cleanup'


def _counting_cancel(flips_at):
    import signal
    calls = {'n': 0}

    def interrupted():
        calls['n'] += 1
        return None if calls['n'] < flips_at else signal.SIGTERM

    return interrupted, calls


def test_produce_cancel_after_stop_gate_is_never_success(tmp_path, monkeypatch):
    import signal
    bundle = build_fixture(TAG_A, 'atest-dep')
    interrupted, calls = _counting_cancel(3)
    error, output, engine, fake_cp = run_flow(
        tmp_path, monkeypatch, bundle, interrupted=interrupted, tag='cancel-after-stop')
    assert isinstance(error, InterruptedError)
    assert 'cancelled' in str(error)
    assert fake_cp.calls, 'cancel arrived after readback started'
    data = read_receipt(output)
    assert data['status'] == 'failed'
    assert data['interrupted_signal'] == signal.SIGTERM
    assert data['stop']['running'] is False and data['stop']['pid'] == 0
    assert calls['n'] >= 3


def test_produce_cancel_before_observation_is_never_success(tmp_path, monkeypatch):
    import signal
    bundle = build_fixture(TAG_A, 'atest-dep')
    interrupted, calls = _counting_cancel(4)
    error, output, engine, fake_cp = run_flow(
        tmp_path, monkeypatch, bundle, interrupted=interrupted, tag='cancel-before-observation')
    assert isinstance(error, InterruptedError)
    assert 'cancelled' in str(error)
    data = read_receipt(output)
    assert data['status'] == 'failed'
    assert data['interrupted_signal'] == signal.SIGTERM
    assert data['staging']['before'] == data['staging']['after']
    assert data['absence'] == {'containers': '', 'volumes': ''}
    assert calls['n'] >= 4


def test_produce_overrun_is_never_success(tmp_path, monkeypatch):
    import p11lab.round_core.worker as worker_module
    from p11lab.round_core.proxy_worker import produce_proxy_candidate
    bundle = build_fixture(TAG_A, 'atest-dep')
    archive, crates, cache = write_fixture_inputs(tmp_path, bundle)
    toolchain_output = tmp_path / 'toolchain'
    toolchain_output.mkdir()
    output = tmp_path / 'attempt'
    engine = flow_engine()
    clock = {'now': 1000.0}
    monkeypatch.setattr(proxy_worker, '_clock', lambda: clock['now'])

    def slow_warm(out, **kwargs):
        clock['now'] += 100.0
        return canned_warm()
    monkeypatch.setattr(proxy_worker, 'verify_proxy_toolchain', slow_warm)
    real_execute = engine.execute

    def slow_execute(identity, timeout, interrupted):
        clock['now'] += 510.0
        return real_execute(identity, timeout, interrupted)
    engine.execute = slow_execute
    monkeypatch.setattr(worker_module, 'supervised_exec', green_cp())
    with pytest.raises(ProxyProducerError) as raised:
        produce_proxy_candidate(
            fixture_selection(bundle), source_archive=archive, vendor_archives=crates,
            cache=cache, toolchain_output=toolchain_output, output_dir=output, engine=engine)
    assert 'budget' in str(raised.value)
    data = read_receipt(output)
    assert data['status'] == 'failed'
    assert data['build_timeout_seconds'] == 480
    assert data['deadline']['limit_seconds'] == 600
    assert data['deadline']['elapsed_seconds'] == 610.0
    assert data['deadline']['verdict'] == 'over-budget'
    assert data['deadline']['cleanup_reserve_seconds'] == 30
    assert data['deadline']['failure_receipt_reserve_seconds'] == 10
    assert data['interrupted_signal'] is None


# ---------------------------------------------------------------------------
# Fix round 2: external round-1 findings X-1..X-6. Each test below fails on
# the fix-2-base bytes and passes with the fix (RED-first, hermetic).
# ---------------------------------------------------------------------------

def test_produce_cancel_flips_at_five_is_never_success(tmp_path, monkeypatch):
    import signal
    bundle = build_fixture(TAG_A, 'atest-dep')
    interrupted, calls = _counting_cancel(5)
    error, output, engine, fake_cp = run_flow(
        tmp_path, monkeypatch, bundle, interrupted=interrupted, tag='cancel-flip-5')
    assert isinstance(error, InterruptedError)
    assert 'cancelled' in str(error)
    data = read_receipt(output)
    assert data['status'] == 'failed'
    assert data['interrupted_signal'] == signal.SIGTERM
    assert calls['n'] >= 5


def test_produce_cancel_at_publication_is_never_success(tmp_path, monkeypatch):
    import signal
    bundle = build_fixture(TAG_A, 'atest-dep')
    interrupted, calls = _counting_cancel(6)
    error, output, engine, fake_cp = run_flow(
        tmp_path, monkeypatch, bundle, interrupted=interrupted, tag='cancel-publication')
    assert isinstance(error, InterruptedError)
    assert 'cancelled' in str(error)
    data = read_receipt(output)
    assert data['status'] == 'failed'
    assert data['interrupted_signal'] == signal.SIGTERM
    assert calls['n'] >= 6


def test_produce_delayed_publication_overrun_is_never_success(tmp_path, monkeypatch):
    import p11lab.round_core.worker as worker_module
    from pathlib import Path
    from p11lab.round_core.proxy_worker import produce_proxy_candidate
    bundle = build_fixture(TAG_A, 'atest-dep')
    archive, crates, cache = write_fixture_inputs(tmp_path, bundle)
    toolchain_output = tmp_path / 'toolchain'
    toolchain_output.mkdir()
    output = tmp_path / 'attempt'
    engine = flow_engine()
    clock = {'now': 1000.0}
    monkeypatch.setattr(proxy_worker, '_clock', lambda: clock['now'])

    def slow_warm(out, **kwargs):
        clock['now'] += 500.0
        return canned_warm()
    monkeypatch.setattr(proxy_worker, 'verify_proxy_toolchain', slow_warm)
    monkeypatch.setattr(worker_module, 'supervised_exec', green_cp())
    real_write_bytes = Path.write_bytes
    advanced = {'done': False}

    def advancing_write_bytes(self, data):
        if self.name == 'proxy-producer-observation.json' and not advanced['done']:
            advanced['done'] = True
            clock['now'] += 150.0
        return real_write_bytes(self, data)
    monkeypatch.setattr(Path, 'write_bytes', advancing_write_bytes)
    with pytest.raises(ProxyProducerError) as raised:
        produce_proxy_candidate(
            fixture_selection(bundle), source_archive=archive, vendor_archives=crates,
            cache=cache, toolchain_output=toolchain_output, output_dir=output, engine=engine)
    assert 'budget' in str(raised.value)
    data = read_receipt(output)
    assert data['status'] == 'failed'
    assert data['build_timeout_seconds'] == 100
    assert data['deadline']['limit_seconds'] == 600
    assert data['deadline']['elapsed_seconds'] == 650.0
    assert data['deadline']['verdict'] == 'over-budget'
    assert data['interrupted_signal'] is None


def test_produce_cleanup_reserve_exhaustion_skips_with_uncertainty(tmp_path, monkeypatch):
    import p11lab.round_core.worker as worker_module
    from p11lab.docker import CommandResult
    from p11lab.round_core.proxy_worker import produce_proxy_candidate
    bundle = build_fixture(TAG_A, 'atest-dep')
    archive, crates, cache = write_fixture_inputs(tmp_path, bundle)
    toolchain_output = tmp_path / 'toolchain'
    toolchain_output.mkdir()
    output = tmp_path / 'attempt'
    failed = CommandResult(101, 'Compiling x\n', 'error: build script failed\n',
                           False, False, False)
    engine = flow_engine(execute_result=failed)
    clock = {'now': 1000.0}
    monkeypatch.setattr(proxy_worker, '_clock', lambda: clock['now'])
    monkeypatch.setattr(proxy_worker, 'verify_proxy_toolchain',
                        lambda out, **kwargs: canned_warm())
    monkeypatch.setattr(worker_module, 'supervised_exec', green_cp())
    real_stop = engine.stop

    def slow_stop(identity, labels):
        clock['now'] += 31.0
        return real_stop(identity, labels)
    engine.stop = slow_stop
    with pytest.raises(ProxyProducerError) as raised:
        produce_proxy_candidate(
            fixture_selection(bundle), source_archive=archive, vendor_archives=crates,
            cache=cache, toolchain_output=toolchain_output, output_dir=output, engine=engine)
    assert '101' in str(raised.value)
    data = read_receipt(output)
    assert data['status'] == 'failed-cleanup'
    assert len(data['cleanup_errors']) == 1
    assert 'cleanup reserve exhausted' in data['cleanup_errors'][0]
    assert 'absence' not in data
    assert data['cleanup_budget']['limit_seconds'] == 30
    assert data['cleanup_budget']['elapsed_seconds'] == 31.0
    assert data['cleanup_budget']['verdict'] == 'reserve-exceeded'


def test_produce_failure_receipt_reserve_exceeded_is_recorded(tmp_path, monkeypatch):
    import p11lab.round_core.worker as worker_module
    from pathlib import Path
    from p11lab.docker import CommandResult
    from p11lab.round_core.proxy_worker import produce_proxy_candidate
    bundle = build_fixture(TAG_A, 'atest-dep')
    archive, crates, cache = write_fixture_inputs(tmp_path, bundle)
    toolchain_output = tmp_path / 'toolchain'
    toolchain_output.mkdir()
    output = tmp_path / 'attempt'
    failed = CommandResult(101, 'Compiling x\n', 'error: build script failed\n',
                           False, False, False)
    engine = flow_engine(execute_result=failed)
    clock = {'now': 1000.0}
    monkeypatch.setattr(proxy_worker, '_clock', lambda: clock['now'])
    monkeypatch.setattr(proxy_worker, 'verify_proxy_toolchain',
                        lambda out, **kwargs: canned_warm())
    monkeypatch.setattr(worker_module, 'supervised_exec', green_cp())
    real_write_bytes = Path.write_bytes

    def slow_write_bytes(self, data):
        if self.name == 'proxy-producer-observation.json':
            clock['now'] += 11.0
        return real_write_bytes(self, data)
    monkeypatch.setattr(Path, 'write_bytes', slow_write_bytes)
    with pytest.raises(ProxyProducerError) as raised:
        produce_proxy_candidate(
            fixture_selection(bundle), source_archive=archive, vendor_archives=crates,
            cache=cache, toolchain_output=toolchain_output, output_dir=output, engine=engine)
    assert '101' in str(raised.value)
    notes = getattr(raised.value, '__notes__', [])
    assert any('failure receipt exceeded reserve' in note for note in notes)
    data = read_receipt(output)
    assert data['status'] == 'failed'


def test_elf_gnu_hash_chain_revisit_is_rejected():
    from p11lab.round_core.proxy_worker import inspect_producer_elf
    raw = build_elf(
        elf_type=3, needed=('libc.so.6',), gnu_hash=True, gnu_hash_buckets=2,
        symbols=(('C_GetFunctionList', 1, 2, True), ('puts', 1, 2, False),))
    with pytest.raises(ProxyProducerError) as raised:
        inspect_producer_elf(raw)
    assert 'revisit' in str(raised.value)


def test_elf_decoded_string_bytes_are_bounded(monkeypatch):
    from p11lab.round_core.proxy_worker import inspect_producer_elf
    symbols = tuple(('sym-%d-%s' % (i, 'x' * 600), 1, 2, True) for i in range(3))
    raw = build_elf(elf_type=3, needed=('libc.so.6',), symbols=symbols)
    assert inspect_producer_elf(raw)['export_count'] == 3
    monkeypatch.setattr(proxy_worker, '_MAX_ELF_STRING_BYTES', 1024)
    with pytest.raises(ProxyProducerError) as raised:
        inspect_producer_elf(raw)
    assert 'string bytes' in str(raised.value)


def test_elf_parsing_is_interruptible():
    import signal
    from p11lab.round_core.proxy_worker import inspect_producer_elf
    symbols = tuple(('sym-%05d' % index, 1, 2, False) for index in range(5000))
    raw = build_elf(elf_type=3, needed=('libc.so.6',), symbols=symbols)
    calls = {'n': 0}

    def flipping():
        calls['n'] += 1
        return signal.SIGTERM
    with pytest.raises(InterruptedError):
        inspect_producer_elf(raw, cancelled=flipping)
    assert calls['n'] >= 1
    info = inspect_producer_elf(raw, cancelled=lambda: None)
    assert info['undefined_count'] == 5000


def test_abi_policy_rejects_object_typed_shim_export():
    from p11lab.round_core.proxy_worker import check_producer_abi, inspect_producer_elf
    from p11lab.round_core.proxy_worker import load_producer_role_policy
    info = inspect_producer_elf(build_elf(
        elf_type=3, needed=('libc.so.6',),
        symbols=(('C_GetFunctionList', 1, 1, True),)))
    assert info['exports'] == [
        {'name': 'C_GetFunctionList', 'bind': 'global', 'type': 'object',
         'visibility': 'default'}]
    elfs = elf_infos()
    elfs['lib/libpkcs11_proxy_ng_shim.so'] = info
    with pytest.raises(ProxyProducerError) as raised:
        check_producer_abi(elfs, load_producer_role_policy())
    assert 'not externally callable' in str(raised.value)


def test_abi_policy_rejects_hidden_shim_export():
    from p11lab.round_core.proxy_worker import check_producer_abi, inspect_producer_elf
    from p11lab.round_core.proxy_worker import load_producer_role_policy
    info = inspect_producer_elf(build_elf(
        elf_type=3, needed=('libc.so.6',),
        symbols=(('C_GetFunctionList', 1, 2, True, 2),)))
    assert info['exports'] == [
        {'name': 'C_GetFunctionList', 'bind': 'global', 'type': 'func',
         'visibility': 'hidden'}]
    elfs = elf_infos()
    elfs['lib/libpkcs11_proxy_ng_shim.so'] = info
    with pytest.raises(ProxyProducerError) as raised:
        check_producer_abi(elfs, load_producer_role_policy())
    assert 'not externally callable' in str(raised.value)


def test_elf_filter_and_auxiliary_directives_are_rejected():
    from p11lab.round_core.proxy_worker import inspect_producer_elf
    for tag in (0x7fffffff, 0x7ffffffd):
        raw = build_elf(
            elf_type=3, needed=('libc.so.6',),
            symbols=(('C_GetFunctionList', 1, 2, True),),
            extra_dynamic=((tag, 'libevil.so.1'),))
        with pytest.raises(ProxyProducerError) as raised:
            inspect_producer_elf(raw)
        assert 'loading directive' in str(raised.value)


def test_elf_audit_directives_are_rejected():
    from p11lab.round_core.proxy_worker import inspect_producer_elf
    for tag in (0x6ffffefc, 0x6ffffefb):
        raw = build_elf(
            elf_type=3, interpreter='/lib64/ld-linux-x86-64.so.2', needed=('libc.so.6',),
            symbols=(('main', 1, 2, True),),
            extra_dynamic=((tag, 'libaudit.so.1'),))
        with pytest.raises(ProxyProducerError) as raised:
            inspect_producer_elf(raw)
        assert 'loading directive' in str(raised.value)


def test_abi_record_retains_version_requirements_and_symbol_associations():
    from p11lab.round_core.proxy_worker import check_producer_abi, inspect_producer_elf
    from p11lab.round_core.proxy_worker import load_producer_role_policy
    record = check_producer_abi(elf_infos(), load_producer_role_policy())
    shim = 'lib/libpkcs11_proxy_ng_shim.so'
    assert record['version_requirements'][shim] == [
        {'file': 'libc.so.6', 'name': 'GLIBC_2.2.5'},
        {'file': 'libc.so.6', 'name': 'GLIBC_2.34'},
        {'file': 'libgcc_s.so.1', 'name': 'GCC_3.0'}]
    assert record['symbol_versions'][shim] == [
        {'symbol': '__gcc_personality_v0', 'file': 'libgcc_s.so.1', 'version': 'GCC_3.0'},
        {'symbol': 'memcpy', 'file': 'libc.so.6', 'version': 'GLIBC_2.34'},
        {'symbol': 'printf', 'file': 'libc.so.6', 'version': 'GLIBC_2.2.5'}]
    assert record['version_requirements']['bin/pkcs11-proxy-ng'] == [
        {'file': 'libc.so.6', 'name': 'GLIBC_2.34'}]
    private = inspect_producer_elf(build_elf(
        elf_type=3, needed=('libc.so.6',),
        symbols=(('C_GetFunctionList', 1, 2, True), ('puts', 1, 2, False),),
        verneed=(('libc.so.6', ('GLIBC_PRIVATE',)),)))
    assert private['version_requirements'] == [{'file': 'libc.so.6', 'name': 'GLIBC_PRIVATE'}]
    assert private['floors'] == {}
    assert private['symbol_versions'] == [
        {'symbol': 'puts', 'file': 'libc.so.6', 'version': 'GLIBC_PRIVATE'}]


# ---------------------------------------------------------------------------
# Fix round 3: codex re-review residuals X-2r/X-3r + new breakage NB-1/NB-2.
# Each test below fails on the fix-3-base bytes and passes with the fix.
# ---------------------------------------------------------------------------


def test_elf_verneed_traversal_is_interruptible_via_aggregate_counter():
    import signal
    from p11lab.round_core.proxy_worker import inspect_producer_elf
    versions_a = tuple('VER_A_%04d' % i for i in range(2500))
    versions_b = tuple('VER_B_%04d' % i for i in range(2500))
    raw = build_elf(
        elf_type=3, needed=('libc.so.6',),
        symbols=(('C_GetFunctionList', 1, 2, True),
                 ('puts', 1, 2, False), ('gets', 1, 2, False)),
        verneed=(('libc.so.6', versions_a), ('libgcc_s.so.1', versions_b)))
    calls = {'n': 0}

    def flipping():
        calls['n'] += 1
        return signal.SIGTERM

    with pytest.raises(InterruptedError):
        inspect_producer_elf(raw, cancelled=flipping)
    assert calls['n'] >= 1
    info = inspect_producer_elf(raw, cancelled=lambda: None)
    assert info['requirement_count'] == 5000
    assert info['undefined_count'] == 2


def test_abi_policy_accepts_required_export_beyond_first_truncation_window():
    from p11lab.round_core.proxy_worker import check_producer_abi, inspect_producer_elf
    from p11lab.round_core.proxy_worker import load_producer_role_policy
    z_names = ['Z%05d' % i for i in range(16384)]
    symbols = tuple([(name, 1, 2, True) for name in z_names]
                    + [('C_GetFunctionList', 1, 2, True)])
    raw = build_elf(elf_type=3, needed=('libc.so.6',), symbols=symbols)
    info = inspect_producer_elf(raw)
    assert info['export_count'] == 16385
    assert info['exports_truncated'] is True
    retained = {row['name'] for row in info['exports']}
    assert 'C_GetFunctionList' in retained
    elfs = elf_infos()
    elfs['lib/libpkcs11_proxy_ng_shim.so'] = info
    record = check_producer_abi(elfs, load_producer_role_policy())
    assert record['decision'] == 'conforming-recorded'


def test_elf_unresolved_versym_reference_is_rejected():
    from p11lab.round_core.proxy_worker import inspect_producer_elf
    raw, layout = build_elf(
        elf_type=3, needed=('libc.so.6', 'libgcc_s.so.1'),
        soname='libpkcs11_proxy_ng_shim.so',
        symbols=(('C_GetFunctionList', 1, 2, True), ('shim_marker', 1, 1, True),
                 ('printf', 1, 2, False), ('memcpy', 1, 2, False),
                 ('__gcc_personality_v0', 1, 2, False)),
        verneed=(('libc.so.6', ('GLIBC_2.2.5', 'GLIBC_2.34')),
                 ('libgcc_s.so.1', ('GCC_3.0',))),
        return_layout=True)
    mutated = bytearray(raw)
    struct.pack_into('<H', mutated, layout['versym'] + 3 * 2, 7)
    with pytest.raises(ProxyProducerError) as raised:
        inspect_producer_elf(bytes(mutated))
    assert 'unresolved' in str(raised.value)


def test_elf_conflicting_version_index_is_rejected():
    from p11lab.round_core.proxy_worker import inspect_producer_elf
    raw, layout = build_elf(
        elf_type=3, needed=('libc.so.6',),
        symbols=(('C_GetFunctionList', 1, 2, True),
                 ('puts', 1, 2, False), ('gets', 1, 2, False)),
        verneed=(('libc.so.6', ('GLIBC_2.2.5', 'GLIBC_2.34')),),
        return_layout=True)
    mutated = bytearray(raw)
    struct.pack_into('<H', mutated, layout['verneed'] + 32 + 6, 2)
    with pytest.raises(ProxyProducerError) as raised:
        inspect_producer_elf(bytes(mutated))
    assert 'conflicting' in str(raised.value)


def test_produce_stalled_publication_write_is_abandoned_without_success(tmp_path, monkeypatch):
    import time as real_time
    import p11lab.round_core.worker as worker_module
    from pathlib import Path
    from p11lab.round_core.proxy_worker import produce_proxy_candidate
    bundle = build_fixture(TAG_A, 'atest-dep')
    archive, crates, cache = write_fixture_inputs(tmp_path, bundle)
    toolchain_output = tmp_path / 'toolchain'
    toolchain_output.mkdir()
    output = tmp_path / 'attempt'
    engine = flow_engine()
    clock = {'now': 1000.0}
    monkeypatch.setattr(proxy_worker, '_clock', lambda: clock['now'])

    def slow_warm(out, **kwargs):
        clock['now'] += 500.0
        return canned_warm()

    monkeypatch.setattr(proxy_worker, 'verify_proxy_toolchain', slow_warm)
    real_execute = engine.execute

    def slow_execute(identity, timeout, interrupted):
        clock['now'] += 99.5
        return real_execute(identity, timeout, interrupted)

    engine.execute = slow_execute
    monkeypatch.setattr(worker_module, 'supervised_exec', green_cp())
    real_write_bytes = Path.write_bytes
    blocked = {'done': False}

    def blocking_write(self, data):
        if self.name == 'proxy-producer-observation.json' and not blocked['done']:
            blocked['done'] = True
            real_time.sleep(2.0)
        return real_write_bytes(self, data)

    monkeypatch.setattr(Path, 'write_bytes', blocking_write)
    started = real_time.monotonic()
    with pytest.raises(ProxyProducerError) as raised:
        produce_proxy_candidate(
            fixture_selection(bundle), source_archive=archive, vendor_archives=crates,
            cache=cache, toolchain_output=toolchain_output, output_dir=output, engine=engine)
    elapsed_real = real_time.monotonic() - started
    assert 'abandoned' in str(raised.value).lower()
    assert 'unconfirmed' in str(raised.value).lower()
    assert elapsed_real < 1.5


def test_produce_cleanup_commands_are_clamped_to_remaining_reserve(tmp_path, monkeypatch):
    import p11lab.round_core.worker as worker_module
    from p11lab.docker import CommandResult
    from p11lab.round_core.proxy_worker import produce_proxy_candidate
    bundle = build_fixture(TAG_A, 'atest-dep')
    archive, crates, cache = write_fixture_inputs(tmp_path, bundle)
    toolchain_output = tmp_path / 'toolchain'
    toolchain_output.mkdir()
    output = tmp_path / 'attempt'
    failed = CommandResult(101, 'Compiling x\n', 'error: build script failed\n',
                           False, False, False)
    engine = flow_engine(execute_result=failed)
    clock = {'now': 1000.0}
    monkeypatch.setattr(proxy_worker, '_clock', lambda: clock['now'])
    monkeypatch.setattr(proxy_worker, 'verify_proxy_toolchain',
                        lambda out, **kwargs: canned_warm())
    monkeypatch.setattr(worker_module, 'supervised_exec', green_cp())
    real_stop = engine.stop

    def slow_stop(identity, labels):
        if identity == FAKE_CANDIDATE_ID:
            clock['now'] += 25.0
        return real_stop(identity, labels)

    engine.stop = slow_stop
    with pytest.raises(ProxyProducerError):
        produce_proxy_candidate(
            fixture_selection(bundle), source_archive=archive, vendor_archives=crates,
            cache=cache, toolchain_output=toolchain_output, output_dir=output, engine=engine)
    stop_indices = [i for i, op in enumerate(engine.ops) if op[0] == 'stop']
    assert len(stop_indices) >= 2
    cleanup_start = stop_indices[1]
    cleanup_commands = [op for op in engine.ops[cleanup_start + 1:] if op[0] == 'command']
    assert cleanup_commands, 'no cleanup commands observed'
    for op in cleanup_commands:
        assert op[2] <= 5.1, 'command not clamped to remaining reserve: %r' % (op,)
    data = read_receipt(output)
    assert data['status'] == 'failed'


def test_produce_failure_receipt_write_is_bounded(tmp_path, monkeypatch):
    import time as real_time
    import p11lab.round_core.worker as worker_module
    from pathlib import Path
    from p11lab.docker import CommandResult
    from p11lab.round_core.proxy_worker import produce_proxy_candidate
    bundle = build_fixture(TAG_A, 'atest-dep')
    archive, crates, cache = write_fixture_inputs(tmp_path, bundle)
    toolchain_output = tmp_path / 'toolchain'
    toolchain_output.mkdir()
    output = tmp_path / 'attempt'
    failed = CommandResult(101, 'Compiling x\n', 'error: build script failed\n',
                           False, False, False)
    engine = flow_engine(execute_result=failed)
    clock = {'now': 1000.0}
    monkeypatch.setattr(proxy_worker, '_clock', lambda: clock['now'])
    monkeypatch.setattr(proxy_worker, 'verify_proxy_toolchain',
                        lambda out, **kwargs: canned_warm())
    monkeypatch.setattr(worker_module, 'supervised_exec', green_cp())
    real_policy = proxy_worker.load_producer_role_policy()
    monkeypatch.setattr(proxy_worker, 'load_producer_role_policy',
                        lambda: {**real_policy, 'failure_receipt_reserve_seconds': 0.5})
    real_write_bytes = Path.write_bytes

    def blocking_write(self, data):
        if self.name == 'proxy-producer-observation.json':
            real_time.sleep(2.0)
        return real_write_bytes(self, data)

    monkeypatch.setattr(Path, 'write_bytes', blocking_write)
    started = real_time.monotonic()
    with pytest.raises(ProxyProducerError) as raised:
        produce_proxy_candidate(
            fixture_selection(bundle), source_archive=archive, vendor_archives=crates,
            cache=cache, toolchain_output=toolchain_output, output_dir=output, engine=engine)
    elapsed_real = real_time.monotonic() - started
    assert '101' in str(raised.value)
    notes = getattr(raised.value, '__notes__', [])
    assert any('abandoned' in note.lower() and 'unconfirmed' in note.lower()
               for note in notes), notes
    assert elapsed_real < 1.5


# ---------------------------------------------------------------------------
# Fix round 4: codex re-review-3 residuals X-2rr + new breakage NB-3.
# Each test below fails on the fix-4-base bytes and passes with the fix.
# ---------------------------------------------------------------------------


def test_produce_failure_receipt_phase_enforces_single_absolute_deadline(tmp_path, monkeypatch):
    import p11lab.round_core.worker as worker_module
    from pathlib import Path
    from p11lab.docker import CommandResult
    from p11lab.round_core.inputs import canonical as real_canonical
    from p11lab.round_core.proxy_worker import produce_proxy_candidate
    bundle = build_fixture(TAG_A, 'atest-dep')
    archive, crates, cache = write_fixture_inputs(tmp_path, bundle)
    toolchain_output = tmp_path / 'toolchain'
    toolchain_output.mkdir()
    output = tmp_path / 'attempt'
    failed = CommandResult(101, 'Compiling x\n', 'error: build script failed\n',
                           False, False, False)
    engine = flow_engine(execute_result=failed)
    clock = {'now': 1000.0}
    monkeypatch.setattr(proxy_worker, '_clock', lambda: clock['now'])
    monkeypatch.setattr(proxy_worker, 'verify_proxy_toolchain',
                        lambda out, **kwargs: canned_warm())
    monkeypatch.setattr(worker_module, 'supervised_exec', green_cp())

    def slow_canonical(value):
        data = real_canonical(value)
        if isinstance(value, dict) and 'error' in value:
            clock['now'] += 8.0
        return data

    monkeypatch.setattr(proxy_worker, 'canonical', slow_canonical)
    timeouts = []
    real_write_bytes = Path.write_bytes

    def fake_bounded_write(path, data, timeout):
        timeouts.append(timeout)
        if timeout < 9.0:
            clock['now'] += timeout
            return False
        clock['now'] += 9.0
        real_write_bytes(path, data)
        return True

    monkeypatch.setattr(proxy_worker, '_bounded_write_bytes', fake_bounded_write)
    with pytest.raises(ProxyProducerError) as raised:
        produce_proxy_candidate(
            fixture_selection(bundle), source_archive=archive, vendor_archives=crates,
            cache=cache, toolchain_output=toolchain_output, output_dir=output, engine=engine)
    assert '101' in str(raised.value)
    assert len(timeouts) == 1
    assert timeouts[0] == pytest.approx(2.0)
    notes = getattr(raised.value, '__notes__', [])
    assert any('abandoned' in note.lower() and 'unconfirmed' in note.lower()
               for note in notes), notes
    assert clock['now'] - 1000.0 <= 10.0 + 1e-9


def test_produce_interrupted_cleanup_restores_caller_engine_command(tmp_path, monkeypatch):
    import p11lab.round_core.worker as worker_module
    from p11lab.docker import CommandResult
    from p11lab.round_core.proxy_worker import produce_proxy_candidate
    bundle = build_fixture(TAG_A, 'atest-dep')
    archive, crates, cache = write_fixture_inputs(tmp_path, bundle)
    toolchain_output = tmp_path / 'toolchain'
    toolchain_output.mkdir()
    output = tmp_path / 'attempt'
    failed = CommandResult(101, 'Compiling x\n', 'error: build script failed\n',
                           False, False, False)
    engine = flow_engine(execute_result=failed)
    clock = {'now': 1000.0}
    monkeypatch.setattr(proxy_worker, '_clock', lambda: clock['now'])
    monkeypatch.setattr(proxy_worker, 'verify_proxy_toolchain',
                        lambda out, **kwargs: canned_warm())
    monkeypatch.setattr(worker_module, 'supervised_exec', green_cp())
    original_command = engine.command
    real_stop = engine.stop
    stops = {'n': 0}

    def interrupting_stop(identity, labels):
        stops['n'] += 1
        if stops['n'] == 2:
            raise KeyboardInterrupt('injected stop interrupt')
        return real_stop(identity, labels)

    engine.stop = interrupting_stop
    with pytest.raises(KeyboardInterrupt):
        produce_proxy_candidate(
            fixture_selection(bundle), source_archive=archive, vendor_archives=crates,
            cache=cache, toolchain_output=toolchain_output, output_dir=output, engine=engine)
    assert stops['n'] == 2
    assert engine.command == original_command
    assert getattr(engine.command, '__func__', None) is FakeEngine.command
    clock['now'] += 31.0
    completed = engine.command(['volume', 'list', '--filter', 'label=p11lab.test=x',
                                '--format', '{{.Name}}'])
    assert completed.stdout == ''


# ---------------------------------------------------------------------------
# M07-producer-minors M3: receipt durability (fsync + readback, headroom).
# Each test below fails on the pre-M3 bytes and passes with the fix
# (RED-first, hermetic: deterministic short-write/disk_usage injection only).
# ---------------------------------------------------------------------------

def test_bounded_write_detects_short_write_via_readback(tmp_path, monkeypatch):
    from pathlib import Path
    real_write_bytes = Path.write_bytes

    def truncating_write(self, data):
        return real_write_bytes(self, data[:len(data) // 2])

    monkeypatch.setattr(Path, 'write_bytes', truncating_write)
    with pytest.raises(ProxyProducerError) as raised:
        proxy_worker._bounded_write_bytes(tmp_path / 'receipt.json', b'x' * 64, 30.0)
    assert 'readback mismatch' in str(raised.value)


def test_produce_success_receipt_short_write_is_refused(tmp_path, monkeypatch):
    import p11lab.round_core.worker as worker_module
    from pathlib import Path
    from p11lab.round_core.proxy_worker import produce_proxy_candidate
    bundle = build_fixture(TAG_A, 'atest-dep')
    archive, crates, cache = write_fixture_inputs(tmp_path, bundle)
    toolchain_output = tmp_path / 'toolchain'
    toolchain_output.mkdir()
    output = tmp_path / 'attempt'
    engine = flow_engine()
    monkeypatch.setattr(proxy_worker, 'verify_proxy_toolchain',
                        lambda out, **kwargs: canned_warm())
    monkeypatch.setattr(worker_module, 'supervised_exec', green_cp())
    real_write_bytes = Path.write_bytes

    def truncating_write(self, data):
        if self.name == 'proxy-producer-observation.json':
            return real_write_bytes(self, data[:len(data) // 2])
        return real_write_bytes(self, data)

    monkeypatch.setattr(Path, 'write_bytes', truncating_write)
    with pytest.raises(ProxyProducerError) as raised:
        produce_proxy_candidate(
            fixture_selection(bundle), source_archive=archive, vendor_archives=crates,
            cache=cache, toolchain_output=toolchain_output, output_dir=output, engine=engine)
    assert 'readback mismatch' in str(raised.value)


def test_produce_failure_receipt_short_write_is_noted_without_masking_root(tmp_path, monkeypatch):
    import p11lab.round_core.worker as worker_module
    from pathlib import Path
    from p11lab.docker import CommandResult
    from p11lab.round_core.proxy_worker import produce_proxy_candidate
    bundle = build_fixture(TAG_A, 'atest-dep')
    archive, crates, cache = write_fixture_inputs(tmp_path, bundle)
    toolchain_output = tmp_path / 'toolchain'
    toolchain_output.mkdir()
    output = tmp_path / 'attempt'
    failed = CommandResult(101, 'Compiling x\n', 'error: build script failed\n',
                           False, False, False)
    engine = flow_engine(execute_result=failed)
    monkeypatch.setattr(proxy_worker, 'verify_proxy_toolchain',
                        lambda out, **kwargs: canned_warm())
    monkeypatch.setattr(worker_module, 'supervised_exec', green_cp())
    real_write_bytes = Path.write_bytes

    def truncating_write(self, data):
        if self.name == 'proxy-producer-observation.json':
            return real_write_bytes(self, data[:len(data) // 2])
        return real_write_bytes(self, data)

    monkeypatch.setattr(Path, 'write_bytes', truncating_write)
    with pytest.raises(ProxyProducerError) as raised:
        produce_proxy_candidate(
            fixture_selection(bundle), source_archive=archive, vendor_archives=crates,
            cache=cache, toolchain_output=toolchain_output, output_dir=output, engine=engine)
    assert '101' in str(raised.value)
    notes = getattr(raised.value, '__notes__', [])
    assert any('failure receipt unavailable' in note for note in notes), notes


def test_produce_success_receipt_headroom_refusal_raises(tmp_path, monkeypatch):
    import shutil
    from types import SimpleNamespace
    import p11lab.round_core.worker as worker_module
    from p11lab.round_core.proxy_worker import produce_proxy_candidate
    bundle = build_fixture(TAG_A, 'atest-dep')
    archive, crates, cache = write_fixture_inputs(tmp_path, bundle)
    toolchain_output = tmp_path / 'toolchain'
    toolchain_output.mkdir()
    output = tmp_path / 'attempt'
    engine = flow_engine()
    monkeypatch.setattr(proxy_worker, 'verify_proxy_toolchain',
                        lambda out, **kwargs: canned_warm())
    monkeypatch.setattr(worker_module, 'supervised_exec', green_cp())
    monkeypatch.setattr(shutil, 'disk_usage',
                        lambda path: SimpleNamespace(total=2 ** 40, used=2 ** 40, free=0))
    with pytest.raises(ProxyProducerError) as raised:
        produce_proxy_candidate(
            fixture_selection(bundle), source_archive=archive, vendor_archives=crates,
            cache=cache, toolchain_output=toolchain_output, output_dir=output, engine=engine)
    assert 'headroom' in str(raised.value)
    assert 'failure receipt unavailable: insufficient headroom' in getattr(
        raised.value, '__notes__', [])
    assert not (output / 'proxy-producer-observation.json').exists()


def test_produce_failure_receipt_headroom_shortage_is_noted_without_masking_root(
        tmp_path, monkeypatch):
    import shutil
    from types import SimpleNamespace
    import p11lab.round_core.worker as worker_module
    from p11lab.docker import CommandResult
    from p11lab.round_core.proxy_worker import produce_proxy_candidate
    bundle = build_fixture(TAG_A, 'atest-dep')
    archive, crates, cache = write_fixture_inputs(tmp_path, bundle)
    toolchain_output = tmp_path / 'toolchain'
    toolchain_output.mkdir()
    output = tmp_path / 'attempt'
    failed = CommandResult(101, 'Compiling x\n', 'error: build script failed\n',
                           False, False, False)
    engine = flow_engine(execute_result=failed)
    monkeypatch.setattr(proxy_worker, 'verify_proxy_toolchain',
                        lambda out, **kwargs: canned_warm())
    monkeypatch.setattr(worker_module, 'supervised_exec', green_cp())
    monkeypatch.setattr(shutil, 'disk_usage',
                        lambda path: SimpleNamespace(total=2 ** 40, used=2 ** 40, free=0))
    with pytest.raises(ProxyProducerError) as raised:
        produce_proxy_candidate(
            fixture_selection(bundle), source_archive=archive, vendor_archives=crates,
            cache=cache, toolchain_output=toolchain_output, output_dir=output, engine=engine)
    assert '101' in str(raised.value)
    assert 'failure receipt unavailable: insufficient headroom' in getattr(
        raised.value, '__notes__', [])
    assert not (output / 'proxy-producer-observation.json').exists()


