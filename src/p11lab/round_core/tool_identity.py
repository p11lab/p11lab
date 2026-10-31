"""Relocation-stable identity for a fully verified W01 evaluator receipt.

Only verified generated venv launchers, activation files, venv configuration,
Python links and their RECORD references receive location normalization. All
other installed file hashes and command arguments remain bound exactly.
"""
from __future__ import annotations

import base64
import csv
import hashlib
import io
import posixpath
import re
from pathlib import Path

from . import JsonObject
from .inputs import digest, load_json, read_source_archive


def _hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _script(raw: bytes, root: Path, environment: str) -> bytes | None:
    python = str(root / environment / 'bin/python3').encode()
    direct = b'#!' + python + b'\n'
    shell = b'#!/bin/sh\n\'\'\'exec\' ' + python + b' "$0" "$@"\n\' \'\'\'\n'
    if raw.startswith(direct):
        return b'#!<SEALED_VENV_PYTHON>\n' + raw[len(direct):]
    if raw.startswith(shell):
        return b'#!<SEALED_VENV_PYTHON>\n' + raw[len(shell):]
    return None


def _inventory(root: Path, rows: list[JsonObject], environment: str) -> list[JsonObject]:
    """Preserve every inventory entry, canonicalizing only known venv outputs."""
    normalized: dict[str, bytes] = {}
    records: dict[str, JsonObject] = {}
    for original in rows:
        row = dict(original)
        path = row['path']
        records[path] = row
        if path == environment + '/bin/python3' and 'link' in row:
            if row['link'] != str(root / 'python/bin/python3'):
                raise ValueError('unexpected venv Python link')
            row['link'] = '<SEALED_PYTHON>/bin/python3'
        elif 'sha256' in row:
            target = root / path
            parent = environment + '/bin/'
            base = path.removeprefix(parent)
            is_bin = path.startswith(parent) and '/' not in base
            if is_bin or path == environment + '/pyvenv.cfg':
                raw = target.read_bytes()
                if len(raw) != row['size'] or _hash(raw) != row['sha256']:
                    raise ValueError('verified venv file drift')
                if is_bin and b'#!<SEALED_VENV_PYTHON>\n' in raw:
                    raise ValueError('reserved normalization marker in venv launcher')
                transformed = _script(raw, root, environment) if is_bin else None
                if base in ('activate', 'activate.csh', 'activate.fish') or path == environment + '/pyvenv.cfg':
                    if b'<W01_OUTPUT>' in raw:
                        raise ValueError('reserved normalization marker in venv file')
                    transformed = raw.replace(str(root).encode(), b'<W01_OUTPUT>')
                if transformed is not None:
                    normalized[path] = transformed
                    row['size'] = len(transformed)
                    row['sha256'] = _hash(transformed)
    for path, row in records.items():
        if not path.endswith('.dist-info/RECORD'):
            continue
        raw = (root / path).read_bytes()
        if len(raw) > 8 * 1024 * 1024 or len(raw) != row['size'] or _hash(raw) != row['sha256']:
            raise ValueError('verified RECORD drift')
        site = posixpath.dirname(posixpath.dirname(path))
        rewritten: list[bytes] = []
        for line in raw.splitlines(keepends=True):
            try:
                decoded = line.decode('utf-8')
                parsed = list(csv.reader(io.StringIO(decoded, newline='')))
            except (UnicodeError, csv.Error) as error:
                raise ValueError('invalid installed RECORD') from error
            if len(parsed) != 1:
                raise ValueError('unsupported multiline installed RECORD row')
            entry = parsed[0]
            if len(entry) != 3:
                raise ValueError('invalid installed RECORD row')
            member = posixpath.normpath(posixpath.join(site, entry[0]))
            if member.startswith('../') or member.startswith('/'):
                raise ValueError('installed RECORD escapes output')
            if member in normalized:
                original_bytes = (root / member).read_bytes()
                expected = 'sha256=' + base64.urlsafe_b64encode(hashlib.sha256(original_bytes).digest()).rstrip(b'=').decode()
                if entry[1] != expected or entry[2] != str(len(original_bytes)):
                    raise ValueError('generated launcher RECORD mismatch')
                newline = '\r\n' if decoded.endswith('\r\n') else '\n' if decoded.endswith('\n') else ''
                encoded_original = io.StringIO(newline='')
                csv.writer(encoded_original, lineterminator=newline).writerow(entry)
                if encoded_original.getvalue() != decoded:
                    raise ValueError('unsupported generated launcher RECORD encoding')
                replacement = normalized[member]
                entry[1] = 'sha256=' + base64.urlsafe_b64encode(hashlib.sha256(replacement).digest()).rstrip(b'=').decode()
                entry[2] = str(len(replacement))
                encoded_row = io.StringIO(newline='')
                csv.writer(encoded_row, lineterminator=newline).writerow(entry)
                line = encoded_row.getvalue().encode()
            rewritten.append(line)
        encoded = b''.join(rewritten)
        row['sha256'] = _hash(encoded)
        row['size'] = len(encoded)
    return [records[row['path']] for row in rows]


def _command_arg(value: str, root: Path) -> str:
    if '<W01_OUTPUT>' in value or '<P11LAB_DATA>' in value:
        raise ValueError('reserved normalization marker in command')
    value = value.replace(str(root), '<W01_OUTPUT>')
    known = ('evaluator/build-linux-amd64.lock', 'contract.json')
    for suffix in known:
        if value.endswith('/p11lab/data/rounds/' + suffix):
            return '<P11LAB_DATA>/' + suffix
    return value


def _output_root_allowed(root: Path) -> bool:
    return re.fullmatch(r'/[^\x00-\x20\x7f\\]+', str(root)) is not None


def verified_evaluator_identity(root: Path) -> JsonObject:
    """Fully validate the W01 receipt, then derive code/tool identity and evidence."""
    from .bootstrap import verify_receipt

    root = root.resolve()
    if not _output_root_allowed(root):
        raise ValueError('unsafe W01 output path for stable launcher identity')
    locks = Path(__file__).resolve().parents[1] / 'data/rounds/evaluator'
    receipt_path = root / 'evaluator-build-receipt.json'
    receipt_raw = read_source_archive(receipt_path)
    actual_receipt_sha = _hash(receipt_raw)
    receipt = load_json(receipt_raw, max_bytes=16 * 1024 * 1024)
    verify_receipt(receipt, root, locks)
    if _hash(read_source_archive(receipt_path)) != actual_receipt_sha:
        raise ValueError('evaluator receipt changed during identity construction')
    inventories = {}
    for group, env in (('build_files', 'build-env'), ('installed_files', 'evaluator-install'), ('tool_files', 'tool-env')):
        inventories[group] = digest(_inventory(root, receipt[group], env))
    for group in ('source_files', 'python_files', 'companion_files', 'download_files', 'dist_files'):
        inventories[group] = digest(receipt[group])
    commands = [{'argv': [_command_arg(v, root) for v in row['argv']],
                 'cwd': _command_arg(row['cwd'], root), 'returncode': row['returncode']}
                for row in receipt['commands']]
    controller = [row for row in receipt['controller_files']
                  if row['path'] not in ('native-ldd.json', 'bootstrap-commands.json')]
    identity = {
        'schema_version': 1, 'source': receipt['source'], 'source_date_epoch': receipt['source_date_epoch'],
        'wheel': receipt['wheel'], 'locks': receipt['locks'], 'tooling_sha256': receipt['tooling_sha256'],
        'bootstrap_driver_sha256': receipt['bootstrap_driver_sha256'], 'contract_sha256': receipt['contract_sha256'],
        'python': {k: receipt['python'][k] for k in ('version', 'executable', 'sha256', 'archive_sha256')},
        'inventories': inventories, 'runtime_distributions': receipt['runtime_distributions'],
        'installed_origin': receipt['installed_origin'],
        'installed_sys_path': [_command_arg(v, root) for v in receipt['installed_sys_path']],
        'runtime_origins': {k: _command_arg(v, root) for k, v in receipt['runtime_origins'].items()},
        'public_api_probe': {'registered_entries': receipt['public_api_probe']['registered_entries'],
                             'origins': {k: _command_arg(v, root) for k, v in receipt['public_api_probe']['origins'].items()}},
        'help_commands': [r['command'] for r in receipt['help_probe']['snapshots']],
        'commands': commands, 'tools': receipt['tools'],
        'environment': {k: _command_arg(v, root) for k, v in receipt['environment'].items()},
        'controller_files': controller, 'source_companion': receipt['source_companion'],
        'release_dependencies': receipt['release_dependencies'],
    }
    # Detect mutation while constructing the identity; neither verification is a
    # substitute for the other and the original full receipt remains evidence.
    verify_receipt(receipt, root, locks)
    if _hash(read_source_archive(receipt_path)) != actual_receipt_sha:
        raise ValueError('evaluator receipt changed during identity construction')
    return {'identity_sha256': digest(identity), 'identity': identity,
            'receipt_sha256': actual_receipt_sha, 'receipt_path': str(receipt_path)}
