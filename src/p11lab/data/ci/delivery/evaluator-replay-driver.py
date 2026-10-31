# SPDX-License-Identifier: Apache-2.0
"""Run a fixed public evaluator operation and record its resident ELF mappings.

The journal is a same-process end-of-operation snapshot, not lifetime tracing.
It is written separately from the public operation's stdout and ledger.
"""
import hashlib
import importlib.util
import json
import os
import platform
from pathlib import Path
import runpy
import stat
import sys


def _check_map_binding(before, after, records, stat_before, stat_after, *, expected_device, expected_inode):
    if before != after or stat_before != stat_after:
        raise ValueError('mapped file or mount identity changed')
    rows = [row for row in records if row.split()[0] == str(before['mount_id'])]
    if len(rows) != 1 or rows[0] != before['mount_record']:
        raise ValueError('mapped file mount identity missing or ambiguous')
    fields = rows[0].split()
    major, minor = (int(part, 10) for part in fields[2].split(':'))
    if ((major, minor) != expected_device or before['fd_inode'] != expected_inode
            or stat_before[1] != expected_inode):
        raise ValueError('mapped file backing device or inode mismatch')
    return {'mount_id': before['mount_id'], 'mount_device': [major, minor],
            'stat_device': [os.major(stat_before[0]), os.minor(stat_before[0])],
            'inode': expected_inode}


def _fd_facts(descriptor):
    with open('/proc/self/fdinfo/' + str(descriptor), encoding='utf-8') as stream:
        info = stream.read(65537)
    if len(info) > 65536:
        raise ValueError('mapped file fdinfo bound')
    fields = {}
    for line in info.splitlines():
        key, _, value = line.partition(':')
        if key in ('mnt_id', 'ino'):
            if key in fields or not value.strip().isdigit():
                raise ValueError('invalid or duplicate mapped fdinfo identity')
            fields[key] = int(value.strip())
    if set(fields) != {'mnt_id', 'ino'}:
        raise ValueError('mapped fdinfo identity unavailable')
    with open('/proc/self/mountinfo', encoding='utf-8') as stream:
        raw = stream.read(2 * 1024 * 1024 + 1)
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError('mountinfo bound')
    records = raw.splitlines()
    rows = [row for row in records if row.split()[0] == str(fields['mnt_id'])]
    if len(rows) != 1:
        raise ValueError('mapped mount identity missing or ambiguous')
    return {'mount_id': fields['mnt_id'], 'fd_inode': fields['ino'], 'mount_record': rows[0]}, records


def _file(path, expected_device=None, expected_inode=None):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or info.st_size > 512 * 1024 * 1024:
            raise ValueError('unsafe, changed or oversized mapped file: ' + str(path))
        before, _ = _fd_facts(stream.fileno())
        is_elf = stream.read(4) == b'\x7fELF'
        stream.seek(0)
        value = hashlib.file_digest(stream, 'sha256').hexdigest() if is_elf else None
        after = os.fstat(stream.fileno())
        after_facts, records = _fd_facts(stream.fileno())
        current = path.stat(follow_symlinks=False)
        def identity(value):
            return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns,
                    value.st_ctime_ns, value.st_mode, value.st_nlink)
        before_stat = identity(info)
        after_stat = identity(after)
        if identity(current) != after_stat:
            raise ValueError('mapped file path changed: ' + str(path))
        if expected_device is None:
            parts = before['mount_record'].split()[2].split(':')
            expected_device = tuple(int(part, 10) for part in parts)
            expected_inode = info.st_ino
        binding = _check_map_binding(before, after_facts, records, before_stat, after_stat,
                                     expected_device=expected_device, expected_inode=expected_inode)
        if not is_elf:
            return None
        return {'path': str(path), 'size': info.st_size, 'sha256': value, **binding}


def _maps_snapshot():
    with open('/proc/self/maps', encoding='utf-8') as stream:
        raw = stream.read(2 * 1024 * 1024 + 1)
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError('runtime maps byte bound')
    return raw.splitlines()


def _file_maps(lines):
    return [line for line in lines if len(line.split(None, 5)) == 6
            and not line.split(None, 5)[5].startswith('[')]


def _check_maps_stable(before, after):
    if before != after:
        raise ValueError('resident mappings changed during observation')


def _code_identity(name, path):
    path = Path(path)
    if not path.is_absolute() or path.is_symlink():
        raise ValueError('unsafe executed code path: ' + name)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > 2 * 1024 * 1024:
            raise ValueError('unsafe executed code file: ' + name)
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        after = os.fstat(stream.fileno())
        current = path.stat(follow_symlinks=False)
        def identity(value):
            return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns,
                    value.st_ctime_ns, value.st_mode, value.st_nlink)
        if identity(before) != identity(after) or identity(after) != identity(current):
            raise ValueError('executed code changed during observation: ' + name)
        return {'name': name, 'path': str(path), 'size': before.st_size, 'sha256': digest}


def _checker_imports():
    prefix = Path(sys.prefix).resolve(strict=True)
    records = []
    for name, module in sorted(sys.modules.items()):
        if name != 'pkcs11_check' and not name.startswith('pkcs11_check.'):
            continue
        filename = getattr(module, '__file__', None)
        spec = getattr(module, '__spec__', None)
        if type(filename) is not str or spec is None or getattr(spec, 'origin', None) != filename:
            raise ValueError('checker import origin unavailable: ' + name)
        path = Path(filename)
        if not path.is_absolute() or not path.resolve(strict=True).is_relative_to(prefix) or path.is_symlink():
            raise ValueError('checker import outside selected interpreter: ' + name)
        cached = getattr(module, '__cached__', None)
        if cached is not None and Path(cached).exists():
            raise ValueError('checker bytecode cache is not an observed source identity: ' + name)
        records.append(_code_identity(name, path))
        if len(records) > 10000:
            raise ValueError('checker import roster bound')
    if not records or records[0]['name'] != 'pkcs11_check':
        raise ValueError('checker package import unavailable')
    return records


def _observation(operation, entrypoint):
    machine, system_platform, libc = platform.machine(), platform.platform(), list(platform.libc_ver())
    imports = _checker_imports()
    executable = Path(os.readlink('/proc/self/exe'))
    if not executable.is_absolute() or str(executable).endswith(' (deleted)'):
        raise ValueError('actual executable unavailable')
    exe = _file(executable)
    if exe is None:
        raise ValueError('actual executable is not ELF')
    entries, identities = {}, {}
    before = _maps_snapshot()
    for line in _file_maps(before):
        fields = line.split(None, 5)
        name = fields[5]
        if not name.startswith('/') or '\\' in name or name.endswith(' (deleted)'):
            raise ValueError('unsafe or deleted mapped file')
        major, minor = (int(part, 16) for part in fields[3].split(':'))
        inode = int(fields[4])
        if not inode:
            raise ValueError('mapped file inode unavailable')
        if name in identities and identities[name] != ((major, minor), inode):
            raise ValueError('mapped path has multiple file identities')
        if name not in identities:
            identities[name] = ((major, minor), inode)
            record = _file(Path(name), (major, minor), inode)
            if record is not None:
                entries[name] = record
            elif 'x' in fields[1]:
                raise ValueError('unknown executable mapping')
        if len(identities) > 10000:
            raise ValueError('mapped file count exceeded')
    after = _maps_snapshot()
    _check_maps_stable(_file_maps(before), _file_maps(after))
    if str(executable) not in entries:
        raise ValueError('executable missing from resident ELF mappings')
    return {'schema_version': 1, 'operation': operation, 'executable': exe,
            'loaded_elf': [entries[name] for name in sorted(entries)], 'checker_imports': imports,
            'entrypoint': entrypoint, 'controller_root': str(Path(__file__).resolve().parents[3]),
            'machine': machine, 'platform': system_platform, 'libc': libc,
            'observation_scope': 'resident ELF mappings immediately before process exit'}


def main():
    if len(sys.argv) < 4 or sys.argv[1] not in ('planner', 'admission'):
        raise ValueError('invalid fixed evaluator replay operation')
    operation, journal, args = sys.argv[1], Path(sys.argv[2]), sys.argv[3:]
    if not journal.is_absolute():
        raise ValueError('runtime journal requires absolute path')
    if operation == 'planner':
        if (len(args) != 7 or args[:4] != ['shard-units', '--shards', '1', '--testcases']
                or args[5:] != ['--format', 'json'] or not Path(args[4]).is_absolute()):
            raise ValueError('invalid fixed planner command')
    elif len(args) != 3 or any(not Path(arg).is_absolute() for arg in args):
        raise ValueError('invalid fixed admission command')
    descriptor = os.open(journal, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w', encoding='utf-8') as out:
        if operation == 'planner':
            spec = importlib.util.find_spec('pkcs11_check.__main__')
            if spec is None or type(spec.origin) is not str or not Path(spec.origin).resolve(strict=True).is_relative_to(Path(sys.prefix).resolve(strict=True)):
                raise ValueError('selected public planner entrypoint unavailable')
            entrypoint = _code_identity('pkcs11_check.__main__', Path(spec.origin))
        else:
            script = Path(__file__).with_name('image-evidence.py').resolve(strict=True)
            entrypoint = _code_identity('image-evidence.py', script)
        try:
            if operation == 'planner':
                sys.argv = ['pkcs11_check', *args]
                runpy.run_module('pkcs11_check', run_name='__main__', alter_sys=True)
            else:
                sys.argv = [str(script), *args]
                runpy.run_path(str(script), run_name='__main__')
        finally:
            if _code_identity(entrypoint['name'], entrypoint['path']) != entrypoint:
                raise ValueError('public evaluator entrypoint changed during execution')
            raw = json.dumps(_observation(operation, entrypoint), sort_keys=True, separators=(',', ':'))
            if len(raw.encode()) > 2 * 1024 * 1024:
                raise ValueError('runtime observation byte bound')
            out.write(raw + '\n')


if __name__ == '__main__':
    main()
