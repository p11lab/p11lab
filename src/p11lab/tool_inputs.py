"""Installed fixed-roster tool input authority; acquisition is not admission."""
import hashlib
import json
from pathlib import PurePosixPath
import re
from urllib.parse import urlsplit

from .catalog import package_data


class ToolInputError(ValueError):
    """Tool input selection, provenance or retained bytes failed verification."""


_LIMITS = {'file_bytes': 256 * 1024**2, 'total_bytes': 512 * 1024**2,
           'io_seconds': 60, 'payload_seconds': 900, 'attempt_seconds': 3600, 'redirects': 5}
_SHA = re.compile(r'[0-9a-f]{64}\Z')
_IDENTITY = {'name', 'version', 'architecture', 'source_package', 'source_version'}
_PACKAGE = _IDENTITY | {'filename', 'sha256', 'size', 'url', 'index', 'stanza_sha256',
                        'relations', 'license_status', 'copyright_path', 'path'}
_RELATIONS = {'Pre-Depends', 'Depends', 'Provides', 'Breaks', 'Conflicts', 'Replaces',
              'Multi-Arch', 'Built-Using', 'Static-Built-Using', 'Recommends', 'Suggests', 'Essential', 'Protected'}


def _require(ok, message):
    if not ok:
        raise ToolInputError(message)


def _keys(value, keys):
    _require(isinstance(value, dict) and value.keys() == keys, 'unexpected or missing tool-input fields')


def _json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            _require(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda value: (_ for _ in ()).throw(ToolInputError('nonfinite JSON')))
    except (ValueError, UnicodeError) as error:
        raise ToolInputError('invalid tool-input JSON: ' + str(error)) from error


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def _path(value):
    _require(isinstance(value, str) and bool(value) and '\\' not in value and ':' not in value
             and not PurePosixPath(value).is_absolute()
             and all(p not in {'', '.', '..'} for p in value.split('/'))
             and all(32 < ord(c) < 127 for c in value), 'unsafe tool input path')
    return value


def _sha(value):
    _require(isinstance(value, str) and _SHA.fullmatch(value), 'invalid tool input checksum')


def _url(value):
    _require(isinstance(value, str), 'invalid tool input URL')
    parsed = urlsplit(value)
    _require(parsed.scheme == 'https' and parsed.netloc == 'snapshot.debian.org'
             and parsed.path.startswith('/archive/') and not parsed.query and not parsed.fragment
             and not any(c.isspace() or ord(c) < 32 for c in value), 'unapproved tool input URL')


def _file(record):
    _path(record['path'])
    _sha(record['sha256'])
    _require(type(record['size']) is int and 0 < record['size'] <= _LIMITS['file_bytes'], 'invalid tool input size')
    if 'url' in record:
        if record.get('kind') in {'git-source', 'python-wheel', 'python-source', 'proxy-rust-dist', 'proxy-crate', 'proxy-source', 'proxy-protobuf'}:
            _opaque_url(record['url'], record['kind'])
        else:
            _url(record['url'])


def _unique(records, key):
    _require(isinstance(records, list) and bool(records), 'missing tool input roster')
    values = [p[key] for p in records]
    _require(all(isinstance(x, str) and x for x in values) and len(values) == len(set(values)),
             'duplicate or invalid tool input ' + key)


def _records(lock):
    """Portable handles are derived from the installed authority, never a receipt."""
    result = []
    for p in lock['packages']:
        result.append({k: p[k] for k in ('path', 'url', 'sha256', 'size')} |
                      {'kind': 'binary', 'id': p['name'] + '=' + p['version'],
                       'source': p['source_package'] + '=' + p['source_version'], 'license_status': 'unreviewed'})
    for source in lock['sources']:
        for p in source['files']:
            result.append({k: p[k] for k in ('path', 'url', 'sha256', 'size')} |
                          {'kind': 'source', 'id': p['filename'],
                           'source': source['name'] + '=' + source['version'], 'license_status': 'unreviewed'})
    for p in lock['metadata']:
        result.append({k: p[k] for k in ('path', 'url', 'sha256', 'size')} |
                      {'kind': 'metadata', 'id': p['filename']})
    for p in lock['resources']:
        result.append(dict(p) | {'kind': 'resource', 'id': p['asset']})
    if lock['schema_version'] == 2:
        result.extend(dict(p) for p in lock['python_inputs'])
        if lock['checker_source'] is not None:
            result.append(dict(lock['checker_source']) | {'kind': 'git-source', 'id': 'checker-source'})
    return result



def _text(value, *, limit=16384):
    _require(isinstance(value, str) and 0 < len(value) <= limit, 'invalid provenance text')


def _metadata_chain(lock, provenance):
    metadata = provenance['metadata']
    _keys(metadata, {'trixie', 'trixie-updates', 'trixie-security', 'verifier'})
    verifier = metadata['verifier']
    _keys(verifier, {'command', 'version', 'keyring_sha256', 'keyring_size', 'trust_basis', 'verification_utc'})
    _sha(verifier['keyring_sha256'])
    _require(type(verifier['keyring_size']) is int and 0 < verifier['keyring_size'] < 1024**2, 'invalid keyring size')
    for field in ('command', 'version', 'trust_basis', 'verification_utc'):
        _text(verifier[field])
    expected = []
    for suite in ('trixie', 'trixie-updates', 'trixie-security'):
        entry = metadata[suite]
        _keys(entry, {'url', 'filename', 'sha256', 'size', 'signatures', 'indexes'})
        archive = 'debian-security' if suite == 'trixie-security' else 'debian'
        prefix = f'https://snapshot.debian.org/archive/{archive}/{lock["apt_snapshot"]}/dists/{suite}/'
        _require(entry['url'] == prefix + 'InRelease' and entry['filename'] == suite + '.InRelease', 'invalid signed metadata origin')
        _require(isinstance(entry['signatures'], list) and 1 <= len(entry['signatures']) <= 8, 'missing signature provenance')
        for signature in entry['signatures']:
            _require(isinstance(signature, list) and len(signature) == 10
                     and all(isinstance(x, str) for x in signature)
                     and all(re.fullmatch(r'[A-F0-9]{40}', signature[i]) for i in (0, 9))
                     and re.fullmatch(r'\d{4}-\d{2}-\d{2}', signature[1])
                     and all(re.fullmatch(r'\d{1,12}', signature[i]) for i in range(2, 9)), 'invalid signature provenance')
        _require(isinstance(entry['indexes'], list) and len(entry['indexes']) == 2, 'incomplete published index roster')
        seen = set()
        for index in entry['indexes']:
            _keys(index, {'url', 'filename', 'sha256', 'size', 'uncompressed'})
            name = index['filename']
            _require(name in {suite + '.Packages.xz', suite + '.Sources.xz'} and name not in seen, 'duplicate/unknown index selector')
            seen.add(name)
            suffix = 'main/binary-amd64/Packages.xz' if name.endswith('.Packages.xz') else 'main/source/Sources.xz'
            _require(index['url'] == prefix + suffix, 'invalid published index origin')
            _keys(index['uncompressed'], {'sha256', 'size'})
            _sha(index['uncompressed']['sha256'])
            _require(type(index['uncompressed']['size']) is int and 0 < index['uncompressed']['size'] <= _LIMITS['file_bytes'], 'invalid expanded index size')
        for record in [entry] + entry['indexes']:
            selected = {k: record[k] for k in ('url', 'filename', 'sha256', 'size')}
            selected['path'] = 'metadata/' + record['filename']
            _file(selected)
            expected.append(selected)
    _require(lock['metadata'] == expected, 'metadata acquisition/selector chain mismatch')


def _selector(record, snapshot, suffix):
    _require(isinstance(record['index'], str) and record['index'] in
             {suite + '.' + suffix for suite in ('trixie', 'trixie-updates', 'trixie-security')}, 'unknown signed index selector')
    archive = 'debian-security' if record['index'].startswith('trixie-security.') else 'debian'
    prefix = f'https://snapshot.debian.org/archive/{archive}/{snapshot}/'
    return prefix


def _package_record(record, snapshot):
    for key in _IDENTITY:
        _text(record[key], limit=256)
    for key in ('name', 'source_package'):
        _require(re.fullmatch(r'[a-z0-9][a-z0-9+.-]*', record[key]), 'invalid package name')
    for key in ('version', 'source_version'):
        _require(re.fullmatch(r'[0-9][A-Za-z0-9.+:~\-]*', record[key]), 'invalid package version')
    _require(record['architecture'] in {'amd64', 'all'}, 'unsupported package architecture')
    _sha(record['stanza_sha256'])
    prefix = _selector(record, snapshot, 'Packages')
    _path(record['filename'])
    _require(record['filename'].endswith('.deb') and record['url'] == prefix + record['filename'], 'package origin/index mismatch')
    _file(record | {'path': record.get('path', record['filename'])})
    _require(isinstance(record['relations'], dict) and record['relations'].keys() <= _RELATIONS, 'invalid relation fields')
    for value in record['relations'].values():
        _text(value)
    _require(record['license_status'] == 'unreviewed'
             and record['copyright_path'] == '/usr/share/doc/' + record['name'] + '/copyright', 'invalid copyright binding')

def _validate(lock, provenance):
    _keys(lock, {'schema_version', 'toolset', 'target', 'platform', 'apt_snapshot', 'base_image',
                 'parent_packages', 'stages', 'packages', 'sources', 'metadata', 'resources',
                 'provenance', 'limits', 'license_status'} |
          ({'execution', 'readiness', 'python_inputs', 'checker_source'} if lock.get('schema_version') == 2 else set()))
    _require(type(lock['schema_version']) is int and lock['schema_version'] in {1, 2}, 'unsupported tool input schema')
    _require(lock['target'] == 'debian13-amd64' and lock['platform'] == 'linux/amd64'
             and ((lock['schema_version'] == 1 and lock['toolset'] == 'consumer')
                  or (lock['schema_version'] == 2 and lock['toolset'] in {'checker', 'oracle'})),
             'unsupported tool input selection')
    _require(lock['apt_snapshot'] == '20260918T000000Z' and lock['license_status'] == 'unreviewed', 'invalid snapshot/admission')
    _require(isinstance(lock['base_image'], str) and re.fullmatch(r'docker.io/library/debian@sha256:[0-9a-f]{64}', lock['base_image']), 'invalid base pin')
    _require(lock['limits'] == _LIMITS and all(type(v) is int for v in lock['limits'].values()), 'invalid acquisition limits')
    _keys(provenance, {'schema_version', 'lock_binding_sha256', 'metadata', 'parent_package_evidence',
                       'relations', 'conflicts', 'source_bindings', 'parent_incorporated_source_ids', 'status', 'limitations'})
    _require(type(provenance['schema_version']) is int and provenance['schema_version'] == 1 and provenance['status'] == 'authenticated-metadata-only', 'invalid provenance status')
    _require(_digest(_canonical({k: v for k, v in lock.items() if k != 'provenance'})) == provenance['lock_binding_sha256'],
             'curated provenance binding mismatch')
    _metadata_chain(lock, provenance)
    _text(provenance['limitations'], limit=4096)
    for key in ('parent_packages', 'packages'):
        _unique(lock[key], 'name')
        for p in lock[key]:
            _keys(p, _IDENTITY if key == 'parent_packages' else _PACKAGE)
            _require(all(isinstance(p[k], str) and p[k] for k in _IDENTITY)
                     and p['architecture'] in {'amd64', 'all'}, 'invalid package identity/architecture')
            if key == 'packages':
                _package_record(p, lock['apt_snapshot'])
                _file(p)
                _sha(p['stanza_sha256'])
                _require(isinstance(p['relations'], dict) and p['relations'].keys() <= _RELATIONS
                         and all(isinstance(v, str) and v for v in p['relations'].values()), 'invalid package relations')
                _require(p['license_status'] == 'unreviewed' and p['copyright_path'] == '/usr/share/doc/' + p['name'] + '/copyright', 'invalid copyright binding')
    parent = {p['name']: p for p in lock['parent_packages']}
    added = {p['name']: p for p in lock['packages']}
    _require(not parent.keys() & added.keys(), 'parent replacement is not supported')
    all_packages = parent | added
    _unique(provenance['parent_package_evidence'], 'name')
    parent_evidence = {}
    for record in provenance['parent_package_evidence']:
        _keys(record, _PACKAGE - {'path'})
        _package_record(record, lock['apt_snapshot'])
        parent_evidence[record['name']] = record
    _require([{k: p[k] for k in _IDENTITY} for p in provenance['parent_package_evidence']] == lock['parent_packages'],
             'parent provenance inventory mismatch')
    relation_records = parent_evidence | added
    incorporated = set()
    for record in relation_records.values():
        for field in ('Built-Using', 'Static-Built-Using'):
            for term in filter(None, record['relations'].get(field, '').split(',')):
                match = re.fullmatch(r'([a-z0-9][a-z0-9+.-]*) \(= ([^ ()]+)\)', term.strip())
                _require(match is not None, 'unsupported incorporated-source identity')
                incorporated.add(match[1] + '=' + match[2])
    _require(isinstance(provenance['parent_incorporated_source_ids'], list)
             and all(isinstance(x, str) for x in provenance['parent_incorporated_source_ids'])
             and len(incorporated) == len(provenance['parent_incorporated_source_ids'])
             and incorporated == set(provenance['parent_incorporated_source_ids']), 'incorporated source roster mismatch')

    stages = {'compiler', 'consumer'} if lock['schema_version'] == 1 else {lock['toolset']}
    _keys(lock['stages'], stages)
    _keys(provenance['relations'], stages)
    _keys(provenance['conflicts'], stages)
    for name, stage in lock['stages'].items():
        _keys(stage, {'roots', 'packages'})
        _require(isinstance(stage['packages'], list) and all(isinstance(x, str) for x in stage['packages'])
                 and len(stage['packages']) == len(set(stage['packages']))
                 and parent.keys() <= set(stage['packages']) <= all_packages.keys(), 'invalid complete stage roster')
        _require(isinstance(stage['roots'], list) and stage['roots'] and all(
            isinstance(x, str) and any(x == p['name'] + '=' + p['version'] for p in all_packages.values()) for x in stage['roots']), 'invalid stage root')
        _require(provenance['conflicts'][name] == [], 'curated closure has conflicts')
        expected = {(n, field, group.strip()) for n in stage['packages']
                    for field in ('Depends', 'Pre-Depends')
                    for group in relation_records[n]['relations'].get(field, '').split(',') if group.strip()}
        seen = set()
        _require(isinstance(provenance['relations'][name], list), 'invalid dependency witnesses')
        for witness in provenance['relations'][name]:
            _keys(witness, {'package', 'field', 'group', 'selected_package', 'selected_version', 'selected_alternative', 'from_parent'})
            key = (witness['package'], witness['field'], witness['group'])
            _require(key in expected and key not in seen, 'missing/duplicate/unknown dependency witness')
            seen.add(key)
            alternatives = [part.strip() for part in witness['group'].split('|')]
            _require(witness['selected_alternative'] in alternatives, 'invalid selected alternative')
            selected = witness['selected_package']
            _require(witness['package'] in stage['packages'] and selected in stage['packages']
                     and witness['selected_version'] == all_packages[selected]['version']
                     and type(witness['from_parent']) is bool and witness['from_parent'] == (selected in parent), 'invalid fixed dependency witness')
            term = re.fullmatch(r'([a-z0-9][a-z0-9+.-]*)(?::(?:any|native|amd64))?(?: \((<<|<=|=|>=|>>) ([^ ()]+)\))?', witness['selected_alternative'])
            _require(term is not None, 'unsupported dependency syntax')
            if selected != term[1]:
                provides = relation_records[selected]['relations'].get('Provides', '').split(',')
                _require(any(re.fullmatch(re.escape(term[1]) + (r' \(= [^ ()]+\)' if term[2] else r'(?: \(= [^ ()]+\))?'), x.strip()) for x in provides),
                         'selected package does not provide required identity/version')
        _require(seen == expected, 'missing dependency witness')
    _require(provenance['source_bindings'] == [{k: s[k] for k in ('name', 'version', 'files', 'index', 'stanza_sha256')} for s in lock['sources']],
             'source provenance binding mismatch')
    _unique(lock['sources'], 'name')
    sources = set()
    for source in lock['sources']:
        _keys(source, {'name', 'version', 'index', 'stanza_sha256', 'license_status', 'files'})
        _text(source['name'], limit=256)
        _text(source['version'], limit=256)
        _sha(source['stanza_sha256'])
        prefix = _selector(source, lock['apt_snapshot'], 'Sources')

        _require(source['license_status'] == 'unreviewed', 'invalid source license status')
        sources.add(source['name'] + '=' + source['version'])
        _unique(source['files'], 'filename')
        _require(sum(p['filename'].endswith('.dsc') for p in source['files']) == 1, 'missing exact source descriptor')
        for p in source['files']:
            _keys(p, {'filename', 'url', 'sha256', 'size', 'path'})
            _path(p['filename'])
            _require('/' not in p['filename'] and p['url'].startswith(prefix + 'pool/')
                     and p['url'].endswith('/' + p['filename']), 'source origin/index mismatch')
            _file(p)
    _require(all(p['source_package'] + '=' + p['source_version'] in sources for p in added.values()), 'missing corresponding source')
    for key, keys in [('metadata', {'filename', 'url', 'sha256', 'size', 'path'}),
                      ('resources', {'asset', 'sha256', 'size', 'path'})]:
        _unique(lock[key], 'path')
        for p in lock[key]:
            _keys(p, keys)
            _file(p)
            if key == 'resources':
                _path(p['asset'])
                prefixes = ('consumer/',) if lock['schema_version'] == 1 else ('consumer/', 'tool-inputs/checker/', 'oracle/')
                _require(p['asset'].startswith(prefixes), 'invalid owned resource')
    if lock['schema_version'] == 2:
        _validate_execution(lock)
    records = _records(lock)
    _unique(records, 'path')
    _unique(records, 'id')
    paths = {p['path'] for p in records}
    _require(not any('/'.join(path.split('/')[:i]) in paths for path in paths for i in range(1, len(path.split('/')))), 'input file/directory collision')
    _require(sum(p['size'] for p in records) <= _LIMITS['total_bytes'], 'tool inputs exceed aggregate size bound')


def _load(toolset, target):
    _require(toolset in {'consumer', 'checker', 'oracle'} and target == 'debian13-amd64',
             'unsupported toolset/target')
    raw = package_data(f'tool-inputs/{toolset}.{target}.lock.json').read_bytes()
    lock = _json(raw)
    _require(isinstance(lock, dict) and isinstance(lock.get('provenance'), dict), 'missing tool provenance')
    _keys(lock['provenance'], {'path', 'sha256'})
    _require(lock['toolset'] == toolset and lock['target'] == target, 'tool selection mismatch')
    _require(lock['provenance']['path'] == f'tool-inputs/{toolset}.{target}.provenance.json', 'unsupported provenance asset')
    provenance = package_data(lock['provenance']['path']).read_bytes()
    _require(_digest(provenance) == lock['provenance']['sha256'], 'provenance checksum mismatch')
    _validate(lock, _json(provenance))
    for record in lock['resources']:
        data = package_data(record['asset']).read_bytes()
        _require(len(data) == record['size'] and _digest(data) == record['sha256'], 'owned resource checksum/size mismatch')
    return lock, _digest(raw)


def _checked_load(toolset, target):
    try:
        return _load(toolset, target)
    except (KeyError, TypeError, AttributeError) as error:
        raise ToolInputError('malformed tool input lock') from error


def load_tool_input_lock(toolset: str, *, target: str) -> dict:
    """Load authoritative installed selection; no caller lock or URL override."""
    return _checked_load(toolset, target)[0]


def _read_regular(path, *, maximum):
    """Bounded read from a single no-follow descriptor, including FIFO races."""
    import os
    import stat
    mode = path.lstat().st_mode
    _require(stat.S_ISREG(mode), 'tool input must be a regular non-symlink file')
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        _require(stat.S_ISREG(info.st_mode) and info.st_size <= maximum, 'tool input type/size mismatch')
        data = stream.read(maximum + 1)
        _require(len(data) <= maximum, 'tool input exceeds size bound')
        return data


def _verify_tree(root, records, *, receipt):
    import os
    import stat
    from .tool_downloads import safe_directory
    safe_directory(root)
    expected = {p['path']: p for p in records}
    files = set(expected) | ({'resolved-inputs.json'} if receipt else set())
    directories = {str(PurePosixPath(name).parents[i]) for name in files
                   for i in range(len(PurePosixPath(name).parents) - 1)}
    seen = set()
    pending = [root]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                name = str((directory / entry.name).relative_to(root)).replace(os.sep, '/')
                mode = entry.stat(follow_symlinks=False).st_mode
                if stat.S_ISDIR(mode):
                    _require(name in directories, 'undeclared input directory')
                    pending.append(directory / entry.name)
                else:
                    _require(stat.S_ISREG(mode) and name in files, 'undeclared or special input file')
                    seen.add(name)
    _require(seen == files, 'missing or extra resolved input files')
    for name, record in expected.items():
        data = _read_regular(root / name, maximum=record['size'])
        _require(len(data) == record['size'] and _digest(data) == record['sha256'], 'resolved input checksum/size mismatch')


def _receipt(lock, lock_sha256, records, observations, elapsed):
    result = {'schema_version': 1, 'status': 'resolved', 'toolset': lock['toolset'], 'target': lock['target'],
            'lock_sha256': lock_sha256, 'records': records, 'observations': observations,
            'network_bytes': sum(p['size'] for p in records if p['kind'] != 'resource'),
            'resource_bytes': sum(p['size'] for p in records if p['kind'] == 'resource'),
            'elapsed_seconds': elapsed, 'admission': 'unreviewed', 'installation': 'not-executed'}
    if lock['schema_version'] == 2:
        result.update(expected_outputs=lock['execution']['expected_outputs'], readiness=lock['readiness'],
                      reproduction=lock['execution'].get('reproduction', 'not-applicable'))
    return result


def resolve_tool_inputs(toolset: str, *, target: str, output_dir) -> dict:
    """Acquire the authoritative opaque roster into a new owned attempt only."""
    from pathlib import Path
    import time
    from . import receipts
    from .tool_downloads import download_locked_file, safe_directory, _remaining
    lock, lock_sha256 = _checked_load(toolset, target)
    records = _records(lock)
    root = Path(output_dir).absolute()
    safe_directory(root.parent)
    root.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    deadline = started + _LIMITS['attempt_seconds']
    receipt_path = root / 'resolved-inputs.json'
    try:
        observations = []
        for record in records:
            _remaining(deadline)
            destination = root / record['path']
            if record['kind'] == 'resource':
                data = package_data(record['asset']).read_bytes()
                _require(len(data) == record['size'] and _digest(data) == record['sha256'], 'owned resource changed before copy')
                safe_directory(destination.parent)
                destination.parent.mkdir(parents=True, exist_ok=True)
                with destination.open('xb') as output:
                    output.write(data)
                observation = {'sha256': record['sha256'], 'size': len(data)}
            else:
                observation = download_locked_file(record, destination, deadline=deadline)
            observations.append({'path': record['path']} | observation)
        _verify_tree(root, records, receipt=False)
        if lock['schema_version'] == 2:
            _verify_execution_inputs(lock, root)
        _remaining(deadline)
        result = _receipt(lock, lock_sha256, records, observations, time.monotonic() - started)
        receipts.write_receipt(receipt_path, result)
        _remaining(deadline)
        return result
    except BaseException as error:
        # write_receipt can raise after replacing the file (directory fsync).
        # Best-effort invalidation must not obscure the original failure.
        try:
            receipt_path.unlink(missing_ok=True)
        except OSError as cleanup:
            error.add_note('Could not invalidate resolution receipt after failure: ' + str(cleanup))
        raise


def verify_resolved_tool_inputs(toolset: str, *, target: str, receipt_path) -> dict:
    """Re-select installed authority and rehash files; receipt hashes are not pins."""
    import math
    from pathlib import Path
    from .tool_downloads import safe_directory, _target
    lock, lock_sha256 = _checked_load(toolset, target)
    records = _records(lock)
    path = Path(receipt_path).absolute()
    _require(path.name == 'resolved-inputs.json', 'unexpected resolution receipt filename')
    safe_directory(path.parent)
    result = _json(_read_regular(path, maximum=4 * 1024**2))
    expected = _receipt(lock, lock_sha256, records, [], 0)
    _keys(result, expected.keys())
    _require(type(result['schema_version']) is int, 'invalid receipt schema')
    _require(type(result['elapsed_seconds']) in {int, float} and math.isfinite(result['elapsed_seconds'])
             and 0 <= result['elapsed_seconds'] <= _LIMITS['attempt_seconds'], 'invalid acquisition duration')
    _require(all(_canonical(result[key]) == _canonical(value) for key, value in expected.items()
                 if key not in {'elapsed_seconds', 'observations'}),
             'resolved receipt differs from authoritative installed inputs')
    observations = result['observations']
    _require(isinstance(observations, list) and len(observations) == len(records), 'incomplete acquisition observations')
    for record, observation in zip(records, observations):
        fields = {'path', 'sha256', 'size'} | ({'final_url'} if record['kind'] != 'resource' else set())
        _keys(observation, fields)
        _require(type(observation['size']) is int and all(observation[k] == record[k] for k in ('path', 'sha256', 'size')),
                 'acquisition observation mismatch')
        if 'final_url' in observation:
            _require(isinstance(observation['final_url'], str), 'invalid observed origin')
            _target(observation['final_url'])
            _require(urlsplit(observation['final_url']).netloc == urlsplit(record['url']).netloc,
                     'observed origin differs from selected input origin')
    _verify_tree(path.parent, records, receipt=True)
    if lock['schema_version'] == 2:
        _verify_execution_inputs(lock, path.parent)
    return result


def _opaque_url(value, kind):
    """Separate immutable upstream artifact families from signed Debian records."""
    _require(isinstance(value, str), 'invalid upstream input URL')
    parsed = urlsplit(value)
    _require(parsed.scheme == 'https' and not parsed.query and not parsed.fragment
             and not any(c.isspace() or ord(c) < 32 for c in value), 'unapproved upstream input URL')
    if kind == 'git-source':
        _require(parsed.netloc == 'codeload.github.com' and re.fullmatch(
            r'/mingulov/pkcs11-check/tar.gz/[0-9a-f]{40}', parsed.path), 'unapproved source origin/revision')
    elif kind == 'proxy-source':
        _require(parsed.netloc == 'codeload.github.com' and parsed.path ==
                 '/mingulov/pkcs11-proxy-ng/tar.gz/a348a5f59b535b1ca309ea9f0a722e3bec692f72', 'unapproved proxy source')
    elif kind == 'proxy-rust-dist':
        _require(parsed.netloc == 'static.rust-lang.org' and re.fullmatch(
            r'/dist/2026-09-03/(?:rustc|cargo|rust-std)-1\.98\.1-x86_64-unknown-linux-gnu\.tar\.xz', parsed.path),
            'unapproved proxy Rust distribution')
    elif kind == 'proxy-crate':
        _require(parsed.netloc == 'static.crates.io' and re.fullmatch(
            r'/crates/([A-Za-z0-9_-]+)/\1-[A-Za-z0-9_.+\-]+\.crate', parsed.path), 'unapproved crates archive')
    elif kind == 'proxy-protobuf':
        _require(parsed.netloc == 'github.com' and parsed.path ==
                 '/protocolbuffers/protobuf/releases/download/v36.1/protoc-36.1-linux-x86_64.zip',
                 'unapproved protobuf release asset')
    else:
        suffix = r'[^/]+\.whl' if kind == 'python-wheel' else r'[^/]+\.(?:tar\.gz|zip)'
        _require(parsed.netloc == 'files.pythonhosted.org' and re.fullmatch(
            r'/packages/[0-9a-f]{2}/[0-9a-f]{2}/[0-9a-f]{60}/' + suffix, parsed.path), 'unapproved Python artifact origin/type')


def _git_digest(kind, raw):
    return hashlib.sha1(kind.encode() + b' ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def _source_manifest(asset):
    manifest = _json(package_data(asset).read_bytes())
    _keys(manifest, {'repository', 'revision', 'tree', 'commit', 'files', 'authentication'})
    _require(manifest['repository'] == 'https://github.com/mingulov/pkcs11-check.git'
             and manifest['revision'] == '9df03bd8b811966fa7856394b19e3f57ffcd8a40', 'wrong checker source origin/revision')
    _text(manifest['commit'])
    _text(manifest['authentication'])
    _require(_git_digest('commit', manifest['commit'].encode()) == manifest['revision']
             and manifest['commit'].startswith('tree ' + manifest['tree'] + '\n'), 'Git commit/tree identity mismatch')
    _unique(manifest['files'], 'path')
    tree = {}
    for record in manifest['files']:
        _keys(record, {'path', 'mode', 'git_blob', 'sha256', 'size'})
        _path(record['path'])
        _sha(record['sha256'])
        _require(type(record['size']) is int and 0 <= record['size'] <= _LIMITS['file_bytes'], 'invalid Git source size')
        _require(record['mode'] in {'100644', '100755'} and re.fullmatch(r'[0-9a-f]{40}', record['git_blob']), 'invalid Git file identity/mode')
        directory = tree
        parts = record['path'].split('/')
        for part in parts[:-1]:
            _require(not isinstance(directory.get(part), tuple), 'Git file/directory collision')
            directory = directory.setdefault(part, {})
        _require(parts[-1] not in directory, 'duplicate Git path')
        directory[parts[-1]] = (record['mode'], record['git_blob'])
    def tree_oid(directory):
        raw = bytearray()
        for name, value in sorted(directory.items(), key=lambda x: (x[0] + ('/' if isinstance(x[1], dict) else '')).encode()):
            mode, oid = ('40000', tree_oid(value)) if isinstance(value, dict) else value
            raw.extend(mode.encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(oid))
        return _git_digest('tree', bytes(raw))
    _require(sum(p['size'] for p in manifest['files']) <= _LIMITS['total_bytes'], 'source expansion exceeds bound')
    _require(tree_oid(tree) == manifest['tree'], 'complete Git tree roster/modes mismatch')
    return manifest


def _validate_execution(lock):
    _keys(lock['readiness'], {'installation', 'qualification', 'rights', 'build_outputs'})
    _require(lock['readiness'] == {'installation': 'not-executed', 'qualification': 'blocked',
                                  'rights': 'unreviewed', 'build_outputs': 'not-produced'}, 'invalid input readiness claim')
    execution = lock['execution']
    if lock['toolset'] == 'oracle':
        _keys(execution, {'provider_state', 'environment', 'argv', 'runtime_roots', 'expected_outputs'})
        _require(lock['python_inputs'] == [] and lock['checker_source'] is None
                 and execution['provider_state'] == 'absent' and execution['expected_outputs'] == [], 'oracle is not independent')
        _require(execution['environment'] == {'OPENSSL_CONF': '/opt/p11lab-oracle/openssl.cnf',
                                             'OPENSSL_MODULES': '/usr/lib/x86_64-linux-gnu/ossl-modules',
                                             'PYTHONNOUSERSITE': '1', 'PYTHONSAFEPATH': '1', 'LC_ALL': 'C'}, 'invalid oracle environment')
        _require(execution['argv'] == ['/usr/bin/python3.13', '-I', '/opt/p11lab-oracle/verify.py',
                                        '/input', '--openssl', '/usr/bin/openssl'], 'invalid oracle invocation')
        _require(execution['runtime_roots'] == lock['stages']['oracle']['roots'], 'oracle runtime selector mismatch')
        assets = {p['asset'] for p in lock['resources']}
        _require(assets == {'consumer/verify.py', 'oracle/openssl.cnf'}, 'missing oracle script/configuration')
        _require({'python3.13', 'openssl'} <= {r.split('=')[0] for r in execution['runtime_roots']}, 'missing oracle runtime root')
        return
    _keys(execution, {'source_revision', 'source_manifest', 'runtime_lock', 'build_lock', 'bootstrap_lock',
                      'runtime_wheels', 'build_wheels', 'expected_outputs', 'retained_source',
                      'retained_wheel_metadata', 'reproduction', 'metadata_comparison', 'python_metadata'})
    _require(execution['source_revision'] == '9df03bd8b811966fa7856394b19e3f57ffcd8a40'
             and execution['source_manifest'] == 'tool-inputs/checker/source-manifest.json', 'wrong executor source')
    manifest = _source_manifest(execution['source_manifest'])
    _keys(lock['checker_source'], {'path', 'url', 'sha256', 'size', 'manifest_asset'})
    _file(lock['checker_source'] | {'kind': 'git-source'})
    _require(lock['checker_source']['url'].endswith('/' + manifest['revision'])
             and lock['checker_source']['manifest_asset'] == execution['source_manifest'], 'source acquisition binding mismatch')
    _require(execution['reproduction'] == 'blocked-unreproduced-output'
             and execution['metadata_comparison'] == 'complete-source-and-build-metadata-equal-official-git', 'unproved checker build claim')
    resources = {p['asset']: p for p in lock['resources']}
    fixed = [('runtime_lock', 'runtime-requirements.txt', '98a0341351b410b8ba6d732ae82ffef14442cded33caf8ab55e3958a0c407cab'),
             ('build_lock', 'build-requirements.txt', '594e522cfeeb6d3315db53587e932eb4d0c06fcf174d87fc2bd89355920d016e'),
             ('bootstrap_lock', 'bootstrap-requirements.txt', 'ca993306863bc89df9e3280001060b8bf59d751974eb47d16482279321f16f83')]
    requirements = {}
    for key, filename, digest in fixed:
        asset = 'tool-inputs/checker/' + filename
        _require(execution[key] == asset and resources[asset]['sha256'] == digest, 'fixed checker dependency lock mismatch')
        raw = package_data(asset).read_bytes()
        _require(_digest(raw) == digest, 'checker requirements checksum mismatch')
        entries = []
        for line in raw.decode().splitlines():
            match = re.fullmatch(r'([A-Za-z0-9_.-]+)==([^ ]+) --hash=sha256:([0-9a-f]{64})', line)
            _require(match is not None, 'nonportable checker requirement')
            entries.append((re.sub(r'[-_.]+', '-', match[1]).lower(), match[2], match[3]))
        _require(len(entries) == len(set(entries)), 'duplicate requirement')
        requirements[key] = entries
    _unique(lock['python_inputs'], 'path')
    _unique(lock['python_inputs'], 'id')
    metadata = {}
    _unique(execution['python_metadata'], 'asset')
    for record in execution['python_metadata']:
        _keys(record, {'asset', 'url', 'sha256', 'size', 'name', 'version'})
        _require(record['asset'] in resources and resources[record['asset']]['sha256'] == record['sha256']
                 and resources[record['asset']]['size'] == record['size'], 'Python metadata resource binding mismatch')
        _require(record['url'] == f'https://pypi.org/pypi/{record["name"]}/{record["version"]}/json', 'wrong Python metadata origin')
        data = _json(package_data(record['asset']).read_bytes())
        _require(data['info']['name'].lower().replace('_', '-') == record['name']
                 and data['info']['version'] == record['version'], 'Python metadata identity mismatch')
        metadata[record['asset']] = data
    selected = {}
    for record in lock['python_inputs']:
        _keys(record, {'path', 'url', 'sha256', 'size', 'filename', 'name', 'version', 'kind', 'metadata_asset', 'license_status', 'id'})
        _require(record['kind'] in {'python-wheel', 'python-source'} and record['license_status'] == 'unreviewed', 'invalid Python input type/admission')
        _file(record)
        _require(record['path'] == ('wheels/' if record['kind'] == 'python-wheel' else 'python-sources/') + record['filename']
                 and record['id'] == record['filename'], 'Python input path/identity mismatch')
        data = metadata[record['metadata_asset']]
        published = [p for p in data['urls'] if p['filename'] == record['filename']]
        _require(len(published) == 1, 'missing/duplicate published Python artifact')
        published = published[0]
        _require(published['url'] == record['url'] and published['digests']['sha256'] == record['sha256']
                 and type(published['size']) is int and published['size'] == record['size']
                 and published['yanked'] is False
                 and published['packagetype'] == ('bdist_wheel' if record['kind'] == 'python-wheel' else 'sdist')
                 and re.sub(r'[-_.]+', '-', data['info']['name']).lower() == record['name']
                 and data['info']['version'] == record['version'], 'published Python member identity/hash/type mismatch')
        if record['kind'] == 'python-wheel':
            selected[record['path']] = (record['name'], record['version'], record['sha256'])
    expected_resources = {execution[k] for k in ('source_manifest', 'runtime_lock', 'build_lock', 'bootstrap_lock', 'retained_wheel_metadata')} | set(metadata)
    _require(resources.keys() == expected_resources, 'orphan or missing checker resource')
    for asset, data in metadata.items():
        members = [p for p in lock['python_inputs'] if p['metadata_asset'] == asset]
        expected_sources = {p['filename'] for p in data['urls'] if p['packagetype'] == 'sdist'}
        _require(sum(p['kind'] == 'python-wheel' for p in members) == 1
                 and {p['filename'] for p in members if p['kind'] == 'python-source'} == expected_sources
                 and bool(expected_sources), 'incomplete published Python source/wheel roster')
    outputs = execution['expected_outputs']
    _require(outputs == [{'path': 'runtime-wheelhouse/pkcs11_check-0.2.3-py3-none-any.whl',
                         'sha256': '58ac3451ae0dba207a48affa460309e4024c2ec7aefb04ef73062f420fdcffec',
                         'size': 2084028, 'name': 'pkcs11-check', 'version': '0.2.3',
                         'status': 'expected-unbuilt-local-artifact-no-public-url'}], 'fixed checker output changed or relabeled')
    _keys(execution['retained_source'], {'sha256', 'size', 'official_git_comparison'})
    _require(execution['retained_source'] == {'sha256': '895f74063dda5ba97776906e0dae86cd3a2c68bc9254ae2cc84be07abc64f502',
                  'size': 18196480, 'official_git_comparison': 'all-1301-files-equal-executable-modes-preserved-git-archive-adds-group-write'}, 'retained source identity changed')
    _require(execution['retained_wheel_metadata'] == 'tool-inputs/checker/retained-wheel-metadata.json'
             and execution['retained_wheel_metadata'] in resources, 'missing retained wheel metadata')
    _require(execution['source_manifest'] in resources, 'missing source manifest resource')
    all_selected = set()
    for field, reqs in [('runtime_wheels', requirements['runtime_lock']),
                        ('build_wheels', requirements['build_lock'] + requirements['bootstrap_lock'])]:
        roster = execution[field]
        _require(isinstance(roster, list) and all(isinstance(x, str) for x in roster)
                 and len(roster) == len(set(roster)), 'duplicate/invalid wheel roster')
        actual = [selected[p] for p in roster if p in selected]
        if field == 'runtime_wheels':
            _require(outputs[0]['path'] in roster, 'missing fixed expected checker output')
            actual.append(('pkcs11-check', '0.2.3', outputs[0]['sha256']))
        _require(len(actual) == len(roster) == len(reqs) and set(actual) == set(reqs), 'wheel/requirement roster mismatch')
        all_selected.update(p for p in roster if p in selected)
    _require(all_selected == selected.keys(), 'unselected Python wheel input')
    _require({'python3.13', 'python3.13-venv'} <= {r.split('=')[0] for r in lock['stages']['checker']['roots']}, 'missing checker Python/venv root')


def _verify_execution_inputs(lock, root):
    """Read opaque source/metadata members only; never import or extract them."""
    _verify_debian_inputs(lock, root)
    if lock['toolset'] != 'checker':
        return
    import tarfile
    manifest = _source_manifest(lock['execution']['source_manifest'])
    expected = {p['path']: p for p in manifest['files']}
    prefix = 'pkcs11-check-' + manifest['revision']
    directories = {prefix} | {prefix + '/' + str(parent) for name in expected
                             for parent in PurePosixPath(name).parents if str(parent) != '.'}
    seen, seen_members = set(), set()
    with tarfile.open(root / lock['checker_source']['path'], mode='r:gz') as archive:
        for member in archive:
            name = member.name.rstrip('/')
            _path(name)
            _require(name not in seen_members, 'duplicate source archive member')
            seen_members.add(name)
            if member.isdir():
                _require(name in directories, 'undeclared source directory')
                continue
            _require(member.isfile() and name.startswith(prefix + '/'), 'unsafe source archive member type/path')
            relative = name[len(prefix) + 1:]
            _require(relative in expected, 'undeclared source member')
            record = expected[relative]
            _require(member.size == record['size'] and member.mode in {int(record['mode'], 8) & 0o777, (int(record['mode'], 8) & 0o777) | 0o020},
                     'source file size/mode mismatch')
            with archive.extractfile(member) as stream:
                raw = stream.read(record['size'] + 1)
            _require(len(raw) == record['size'] and _digest(raw) == record['sha256']
                     and _git_digest('blob', raw) == record['git_blob'], 'source file/Git object mismatch')
            seen.add(relative)
    _require(seen == expected.keys(), 'incomplete source archive roster')


def _index_fields(raw):
    result, last = {}, None
    for line in raw.decode().splitlines():
        if not line:
            continue
        if line.startswith(' '):
            _require(last is not None, 'invalid index continuation')
            result[last] += '\n' + line[1:]
        else:
            key, separator, value = line.partition(':')
            _require(separator and key not in result, 'duplicate/invalid index field')
            result[key] = value.strip()
            last = key
    return result


def _verify_index_records(lock, provenance, indexes):
    """Bind each curated package/source selector to the authenticated full stanza."""
    records = provenance['parent_package_evidence'] + lock['packages'] + lock['sources']
    for selector in {p['index'] for p in records}:
        wanted = [p for p in records if p['index'] == selector]
        expected = {(p['name'], p['version']): p for p in wanted}
        _require(len(expected) == len(wanted), 'duplicate index member selector')
        seen = set()
        for raw in indexes[selector].split(b'\n\n'):
            if not raw.strip():
                continue
            fields = _index_fields(raw)
            key = (fields.get('Package'), fields.get('Version'))
            if key not in expected:
                continue
            record = expected[key]
            _require(key not in seen and _digest(raw + b'\n') == record['stanza_sha256'], 'index member/stanza identity mismatch')
            seen.add(key)
            if selector.endswith('.Packages'):
                source = fields.get('Source', fields['Package'])
                match = re.fullmatch(r'([^ ()]+)(?: \(([^ ()]+)\))?', source)
                _require(match is not None, 'invalid index source identity')
                _require(fields['Filename'] == record['filename'] and fields['SHA256'] == record['sha256']
                         and fields['Size'] == str(record['size']) and fields['Architecture'] == record['architecture']
                         and match[1] == record['source_package'] and (match[2] or fields['Version']) == record['source_version']
                         and {k: v for k, v in fields.items() if k in _RELATIONS} == record['relations'], 'package index member binding mismatch')
            else:
                files = {line.split()[2]: (line.split()[0], int(line.split()[1]))
                         for line in fields['Checksums-Sha256'].splitlines() if line.strip()}
                _require(files == {p['filename']: (p['sha256'], p['size']) for p in record['files']}
                         and all('/' + fields['Directory'] + '/' + p['filename'] in p['url'] for p in record['files']),
                         'source index member binding mismatch')
        _require(seen == expected.keys(), 'missing authenticated index member')


def _verify_debian_inputs(lock, root):
    import lzma
    provenance_raw = package_data(lock['provenance']['path']).read_bytes()
    _require(_digest(provenance_raw) == lock['provenance']['sha256'], 'changed provenance checksum')
    provenance = _json(provenance_raw)
    _require(_digest(_canonical({k: v for k, v in lock.items() if k != 'provenance'})) == provenance['lock_binding_sha256'],
             'changed Debian provenance authority')
    indexes = {}
    for suite in ('trixie', 'trixie-updates', 'trixie-security'):
        entry = provenance['metadata'][suite]
        signed = _read_regular(root / ('metadata/' + entry['filename']), maximum=entry['size'])
        # Exact signed bytes are pinned by the previously authenticated installed
        # metadata chain. This operation does not trust new signature declarations.
        release = signed.split(b'\n\n', 1)[1].split(b'-----BEGIN PGP SIGNATURE-----', 1)[0]
        fields = _index_fields(release)
        published = {line.split()[2]: (line.split()[0], int(line.split()[1]))
                     for line in fields['SHA256'].splitlines() if line.strip()}
        for index in entry['indexes']:
            suffix = 'main/binary-amd64/Packages.xz' if index['filename'].endswith('.Packages.xz') else 'main/source/Sources.xz'
            _require(published[suffix] == (index['sha256'], index['size']), 'signed index checksum/member mismatch')
            compressed = _read_regular(root / ('metadata/' + index['filename']), maximum=index['size'])
            decoder = lzma.LZMADecompressor()
            expanded = decoder.decompress(compressed, max_length=index['uncompressed']['size'] + 1)
            _require(decoder.eof and not decoder.unused_data and len(expanded) == index['uncompressed']['size']
                     and _digest(expanded) == index['uncompressed']['sha256'], 'expanded index checksum/size mismatch')
            indexes[index['filename'][:-3]] = expanded
    _verify_index_records(lock, provenance, indexes)
