"""Native fact comparisons for protected completed-custody replay.

A comparison alone does not authenticate its inputs or create replay authority.
"""
import re
import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from pathlib import PurePosixPath

from .inputs import canonical, load_json

_SCOPE = 'resident ELF mappings immediately before process exit'
_OBSERVATION_KEY = object()
_BINDING_KEY = object()


@dataclass(frozen=True, slots=True, init=False)
class LocalEvaluatorObservation:
    """Actual local operations and sealed identity, not producer authority."""
    _data: bytes

    def __init__(self, key, value):
        if key is not _OBSERVATION_KEY:
            raise TypeError('local evaluator observation requires execution')
        object.__setattr__(self, '_data', canonical(value))

    def as_dict(self):
        return load_json(self._data)


@dataclass(frozen=True, slots=True, init=False)
class EvaluatorReplayBinding:
    """Authenticated old observation and strictly verified current execution."""
    _data: bytes

    def __init__(self, key, value):
        if key is not _BINDING_KEY:
            raise TypeError('evaluator replay binding requires verified factory')
        object.__setattr__(self, '_data', canonical(value))

    def as_dict(self):
        return load_json(self._data)


def _input_identity(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > 256 * 1024 * 1024:
            raise ValueError('unsafe or oversized evaluator input')
        digest_value = hashlib.file_digest(stream, 'sha256').hexdigest()
        after = os.fstat(stream.fileno())
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('evaluator input changed while hashing')
        return {'size': before.st_size, 'sha256': digest_value}


def observe_local_evaluator(root, seal, source_names, checker_output, plan, output):
    """Strictly verify and execute the existing planner and admission adapters.

    This local observation is not a completed producer, source D, or a replay
    authorization; later code must bind it to independently verified custody.
    """
    from .tool_identity import verified_evaluator_identity
    from ..delivery_authority import _read_bounded_file
    from ..image_validation import admit_checker, plan_checker_shard

    root, checker_output, plan = Path(root).resolve(strict=True), Path(checker_output).resolve(strict=True), Path(plan)
    output = Path(output).absolute()
    if (output.is_relative_to(root) or root.is_relative_to(output)
            or output.is_relative_to(checker_output) or checker_output.is_relative_to(output)
            or plan.resolve().is_relative_to(output)):
        raise ValueError('evaluator observation overlaps protected input')
    identity = verified_evaluator_identity(root)
    if identity['receipt_sha256'] != seal:
        raise ValueError('evaluator observation receipt mismatch')
    receipt_path = root / 'evaluator-build-receipt.json'
    receipt = load_json(_read_bounded_file(receipt_path, 16 * 1024 * 1024), max_bytes=16 * 1024 * 1024)
    driver = Path(__file__).resolve().parents[1] / 'data/ci/delivery/evaluator-replay-driver.py'
    driver_identity = _input_identity(driver)
    raw = checker_output / 'checker/report.jsonl'
    original_raw, original_plan = _input_identity(raw), _input_identity(plan)
    output.mkdir(parents=True, exist_ok=False)
    planner = plan_checker_shard(root, seal, source_names, output / 'planner', runtime_journal=output / 'planner-runtime.json')
    admission = admit_checker(root, seal, checker_output, plan, output / 'admission', runtime_journal=output / 'admission-runtime.json')
    runtime = {name: load_json(_read_bounded_file(output / (name + '-runtime.json'), 2 * 1024 * 1024))
               for name in ('planner', 'admission')}
    if (_input_identity(raw) != original_raw or _input_identity(plan) != original_plan or _input_identity(driver) != driver_identity
            or verified_evaluator_identity(root) != identity):
        raise ValueError('evaluator observation inputs changed during execution')
    value = {'schema_version': 1, 'kind': 'local-evaluator-observation', 'root': str(root),
             'receipt_sha256': seal, 'identity_sha256': identity['identity_sha256'], 'python': receipt['python'],
             'native_dependencies': receipt['native_dependencies'], 'raw': original_raw, 'plan': original_plan, 'driver': driver_identity,
             'planner': planner, 'admission': admission, 'runtime': runtime,
             'ledger': _input_identity(output / 'admission/ledger.jsonl')}
    check_evaluator_observation(value)
    return LocalEvaluatorObservation(_OBSERVATION_KEY, value)


def _runtime_projection(value, operation, root):
    if (type(value) is not dict or set(value) != {'schema_version', 'operation', 'executable', 'loaded_elf', 'checker_imports', 'entrypoint', 'controller_root',
                                                  'machine', 'platform', 'libc', 'observation_scope'}
            or type(value['schema_version']) is not int or value['schema_version'] != 1
            or value['operation'] != operation or value['observation_scope'] != _SCOPE
            or type(value['machine']) is not str or not value['machine']
            or type(value['platform']) is not str or not value['platform']
            or type(value['libc']) is not list or len(value['libc']) != 2
            or any(type(item) is not str or not item for item in value['libc'])
            or type(value['loaded_elf']) is not list or not 1 <= len(value['loaded_elf']) <= 10000):
        raise ValueError('invalid runtime observation for ' + operation)
    root = PurePosixPath(root)
    if not root.is_absolute() or '..' in root.parts:
        raise ValueError('invalid evaluator root')
    imports = value['checker_imports']
    if type(imports) is not list or not 1 <= len(imports) <= 10000:
        raise ValueError('invalid checker import roster')
    import_projection = []
    package = root / 'evaluator-install/lib/python3.12/site-packages/pkcs11_check'
    controller = value['controller_root']
    if (type(controller) is not str or controller == '/' or '\\' in controller or '\x00' in controller
            or not PurePosixPath(controller).is_absolute() or str(PurePosixPath(controller)) != controller
            or '..' in PurePosixPath(controller).parts):
        raise ValueError('invalid observed controller root')
    entrypoint = value['entrypoint']
    if (type(entrypoint) is not dict or set(entrypoint) != {'name', 'path', 'size', 'sha256'}
            or type(entrypoint['path']) is not str or '\\' in entrypoint['path'] or '\x00' in entrypoint['path']
            or str(PurePosixPath(entrypoint['path'])) != entrypoint['path'] or '..' in PurePosixPath(entrypoint['path']).parts
            or type(entrypoint['size']) is not int or not 0 <= entrypoint['size'] <= 2 * 1024 * 1024
            or type(entrypoint['sha256']) is not str or not re.fullmatch(r'[0-9a-f]{64}', entrypoint['sha256'])):
        raise ValueError('invalid observed evaluator entrypoint')
    if operation == 'planner':
        if entrypoint['name'] != 'pkcs11_check.__main__' or not PurePosixPath(entrypoint['path']).is_relative_to(package):
            raise ValueError('planner entrypoint outside selected evaluator root')
        entry_identity = (entrypoint['name'], PurePosixPath(entrypoint['path']).relative_to(root).as_posix(), entrypoint['size'], entrypoint['sha256'])
    else:
        expected = PurePosixPath(controller) / 'data/ci/delivery/image-evidence.py'
        if entrypoint['name'] != 'image-evidence.py' or PurePosixPath(entrypoint['path']) != expected:
            raise ValueError('admission entrypoint outside selected controller')
        entry_identity = (entrypoint['name'], 'data/ci/delivery/image-evidence.py', entrypoint['size'], entrypoint['sha256'])
    for item in imports:
        if (type(item) is not dict or set(item) != {'name', 'path', 'size', 'sha256'}
                or type(item['name']) is not str or not re.fullmatch(r'pkcs11_check(?:\.[A-Za-z_][A-Za-z0-9_]*)*', item['name'])
                or type(item['path']) is not str or '\\' in item['path'] or '\x00' in item['path']
                or str(PurePosixPath(item['path'])) != item['path'] or '..' in PurePosixPath(item['path']).parts
                or type(item['size']) is not int or not 0 <= item['size'] <= 2 * 1024 * 1024
                or type(item['sha256']) is not str or not re.fullmatch(r'[0-9a-f]{64}', item['sha256'])):
            raise ValueError('invalid checker import identity')
        path = PurePosixPath(item['path'])
        if not path.is_relative_to(package):
            raise ValueError('checker import outside selected evaluator root: ' + item['name'])
        import_projection.append((item['name'], path.relative_to(root).as_posix(), item['size'], item['sha256']))
    names = [row[0] for row in import_projection]
    if names != sorted(set(names)) or names[0] != 'pkcs11_check':
        raise ValueError('duplicate or missing checker imports')
    def project(row):
        if (type(row) is not dict or set(row) != {'path', 'size', 'sha256', 'mount_id', 'mount_device', 'stat_device', 'inode'}
                or type(row['path']) is not str or not row['path'].startswith('/')
                or '\\' in row['path'] or '\x00' in row['path']
                or str(PurePosixPath(row['path'])) != row['path']
                or '..' in PurePosixPath(row['path']).parts
                or type(row['size']) is not int or not 0 < row['size'] <= 512 * 1024 * 1024
                or type(row['sha256']) is not str or not re.fullmatch(r'[0-9a-f]{64}', row['sha256'])
                or any(type(row[key]) is not int or row[key] <= 0 for key in ('mount_id', 'inode'))
                or any(type(row[key]) is not list or len(row[key]) != 2
                       or any(type(part) is not int or part < 0 for part in row[key])
                       for key in ('mount_device', 'stat_device'))):
            raise ValueError('invalid runtime ELF identity')
        path = PurePosixPath(row['path'])
        logical = 'evaluator/' + path.relative_to(root).as_posix() if path.is_relative_to(root) else str(path)
        return logical, (row['size'], row['sha256'])
    projected = {}
    raw_projected = {}
    for item in value['loaded_elf']:
        name, identity = project(item)
        if name in projected:
            raise ValueError('duplicate runtime ELF identity')
        projected[name] = identity
        raw_projected[name] = item
    executable, identity = project(value['executable'])
    if not PurePosixPath(value['executable']['path']).is_relative_to(root):
        raise ValueError('actual evaluator executable outside selected root')
    if projected.get(executable) != identity or raw_projected.get(executable) != value['executable']:
        raise ValueError('actual executable absent from runtime mappings')
    return {'executable': (executable, identity), 'loaded_elf': projected,
            'checker_imports': import_projection, 'entrypoint': entry_identity,
            'machine': value['machine'], 'platform': value['platform'], 'libc': value['libc']}


def check_evaluator_observation(value):
    """Check a claimed observation's structure; this does not authenticate it."""
    try:
        keys = {'schema_version', 'kind', 'root', 'receipt_sha256', 'identity_sha256', 'python',
                'native_dependencies', 'raw', 'plan', 'planner', 'admission', 'runtime', 'ledger', 'driver'}
        if (type(value) is not dict or set(value) != keys or type(value['schema_version']) is not int
                or value['schema_version'] != 1 or value['kind'] != 'local-evaluator-observation'
                or type(value['root']) is not str or value['root'] == '/' or '\\' in value['root'] or '\x00' in value['root']
                or not PurePosixPath(value['root']).is_absolute()
                or str(PurePosixPath(value['root'])) != value['root'] or '..' in PurePosixPath(value['root']).parts
                or any(type(value[k]) is not str or not re.fullmatch(r'[0-9a-f]{64}', value[k])
                       for k in ('receipt_sha256', 'identity_sha256'))):
            raise ValueError('invalid evaluator observation identity')
        python = value['python']
        if (type(python) is not dict or set(python) != {'version', 'executable', 'sha256', 'archive_sha256', 'platform', 'libc'}
                or python['executable'] != 'python/bin/python3' or type(python['version']) is not str or not python['version']
                or type(python['platform']) is not str or not python['platform']
                or type(python['libc']) is not list or len(python['libc']) != 2
                or any(type(x) is not str or not x for x in python['libc'])
                or any(type(python[k]) is not str or not re.fullmatch(r'[0-9a-f]{64}', python[k])
                       for k in ('sha256', 'archive_sha256'))):
            raise ValueError('invalid evaluator Python identity')
        native = value['native_dependencies']
        if (type(native) is not list or not 1 <= len(native) <= 10000
                or any(type(row) is not dict or set(row) != {'path', 'sha256'}
                       or type(row['path']) is not str or not row['path'].startswith('/') or '\\' in row['path'] or '\x00' in row['path']
                       or str(PurePosixPath(row['path'])) != row['path'] or '..' in PurePosixPath(row['path']).parts
                       or type(row['sha256']) is not str or not re.fullmatch(r'[0-9a-f]{64}', row['sha256'])
                       for row in native)
                or [row['path'] for row in native] != sorted(set(row['path'] for row in native))):
            raise ValueError('invalid evaluator native dependency roster')
        for key in ('raw', 'plan', 'ledger', 'driver'):
            item = value[key]
            if (type(item) is not dict or set(item) != {'size', 'sha256'} or type(item['size']) is not int
                    or not 0 < item['size'] <= 256 * 1024 * 1024
                    or type(item['sha256']) is not str or not re.fullmatch(r'[0-9a-f]{64}', item['sha256'])):
                raise ValueError('invalid evaluator input or ledger identity')
        planner = value['planner']
        if (type(planner) is not dict or set(planner) != {'files', 'evaluator_source_sha256', 'stdout_sha256', 'evaluator_receipt_sha256'}
                or type(planner['files']) is not list or not planner['files']
                or any(type(name) is not str or PurePosixPath(name).name != name for name in planner['files'])
                or planner['files'] != sorted(set(planner['files']))
                or type(planner['evaluator_source_sha256']) is not dict
                or set(planner['evaluator_source_sha256']) != set(planner['files'])
                or any(type(v) is not str or not re.fullmatch(r'[0-9a-f]{64}', v) for v in planner['evaluator_source_sha256'].values())
                or type(planner['stdout_sha256']) is not str or not re.fullmatch(r'[0-9a-f]{64}', planner['stdout_sha256'])
                or planner['evaluator_receipt_sha256'] != value['receipt_sha256']):
            raise ValueError('invalid observed public planner')
        if (type(value['admission']) is not dict or type(value['admission'].get('admission')) is not dict
                or value['admission']['admission'].get('admitted') is not True
                or value['admission'].get('ledger_sha256') != value['ledger']['sha256']
                or type(value['runtime']) is not dict or set(value['runtime']) != {'planner', 'admission'}):
            raise ValueError('invalid observed public admission')
        expected_native = {row['path']: row['sha256'] for row in native}
        for operation in ('planner', 'admission'):
            runtime = value['runtime'][operation]
            _runtime_projection(runtime, operation, value['root'])
            if (runtime['machine'] != 'x86_64' or runtime['platform'] != python['platform']
                    or runtime['libc'] != python['libc'] or runtime['executable']['sha256'] != python['sha256']):
                raise ValueError('observed evaluator runtime/Python mismatch: ' + operation)
            for row in runtime['loaded_elf']:
                if not PurePosixPath(row['path']).is_relative_to(value['root']) and expected_native.get(row['path']) != row['sha256']:
                    raise ValueError('unknown observed native dependency: ' + row['path'])
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError('malformed evaluator observation') from error


def check_runtime_equivalence(producer, receiver, *, old_root, new_root):
    """Compare actual snapshot identities; no authentication is implied."""
    if (type(producer) is not dict or type(receiver) is not dict
            or set(producer) != {'planner', 'admission'} or set(receiver) != {'planner', 'admission'}):
        raise ValueError('runtime operation roster mismatch')
    for operation in ('planner', 'admission'):
        old = _runtime_projection(producer[operation], operation, old_root)
        new = _runtime_projection(receiver[operation], operation, new_root)
        if old != new:
            old_files, new_files = old['loaded_elf'], new['loaded_elf']
            changed = sorted(name for name in set(old_files) | set(new_files) if old_files.get(name) != new_files.get(name))
            edge = changed[0] if changed else operation + ' executable/platform/ABI'
            raise ValueError('evaluator runtime identity mismatch: ' + edge)


def check_replay_equivalence(producer, receiver):
    """Check observations without equating their full path-bound receipts."""
    check_evaluator_observation(producer)
    check_evaluator_observation(receiver)
    old_native = {item['path']: item['sha256'] for item in producer['native_dependencies']}
    new_native = {item['path']: item['sha256'] for item in receiver['native_dependencies']}
    changed_native = sorted(path for path in set(old_native) | set(new_native) if old_native.get(path) != new_native.get(path))
    if changed_native:
        raise ValueError('sealed evaluator native dependency mismatch: ' + changed_native[0])
    if (producer['receipt_sha256'] == receiver['receipt_sha256']
            or any(producer[key] != receiver[key] for key in ('identity_sha256', 'python',
                                                               'raw', 'plan', 'ledger', 'admission', 'driver'))
            or any(producer['planner'][key] != receiver['planner'][key]
                   for key in ('files', 'evaluator_source_sha256'))):
        raise ValueError('evaluator replay code, inputs or semantic result mismatch')
    check_runtime_equivalence(producer['runtime'], receiver['runtime'],
                              old_root=producer['root'], new_root=receiver['root'])


def bind_evaluator_replay(authority, original_receipt_path, current_observation):
    """Bind a signed producer observation to a strictly checked fresh replay.

    This establishes only the evaluator relation; it neither admits source D
    nor replaces the original validation package's recorded receipt identity.
    """
    from ..custody_authority import VerifiedCompletedFinalization
    from ..delivery_authority import _read_bounded_file
    from .tool_identity import verified_evaluator_identity

    if type(authority) is not VerifiedCompletedFinalization:
        raise TypeError('verified completed finalization required')
    if type(current_observation) is not LocalEvaluatorObservation:
        raise TypeError('actual local evaluator observation required')
    old = authority.statement()['evaluator']
    new = current_observation.as_dict()
    check_replay_equivalence(old, new)
    receipt_bytes = _read_bounded_file(original_receipt_path, 16 * 1024 * 1024)
    if hashlib.sha256(receipt_bytes).hexdigest() != old['receipt_sha256']:
        raise ValueError('original evaluator receipt identity mismatch')
    original_receipt = load_json(receipt_bytes, max_bytes=16 * 1024 * 1024)
    new_root = Path(new['root']).resolve(strict=True)
    current = verified_evaluator_identity(new_root)
    if current['receipt_sha256'] != new['receipt_sha256'] or current['identity_sha256'] != new['identity_sha256']:
        raise ValueError('fresh evaluator identity changed')
    current_receipt = load_json(_read_bounded_file(new_root / 'evaluator-build-receipt.json', 16 * 1024 * 1024),
                                max_bytes=16 * 1024 * 1024)
    fields = ('source', 'locks', 'wheel', 'tooling_sha256', 'bootstrap_driver_sha256', 'contract_sha256',
              'python', 'native_dependencies')
    try:
        if (any(original_receipt[field] != current_receipt[field] for field in fields)
                or original_receipt['python'] != old['python']
                or original_receipt['native_dependencies'] != old['native_dependencies']):
            raise ValueError('original and current evaluator receipt facts differ')
    except KeyError as error:
        raise ValueError('incomplete evaluator receipt facts') from error
    driver = Path(__file__).resolve().parents[1] / 'data/ci/delivery/evaluator-replay-driver.py'
    if (_input_identity(driver) != new['driver']
            or _read_bounded_file(original_receipt_path, 16 * 1024 * 1024) != receipt_bytes
            or verified_evaluator_identity(new_root) != current):
        raise ValueError('evaluator binding inputs changed during verification')
    return EvaluatorReplayBinding(_BINDING_KEY, {'schema_version': 1, 'kind': 'evaluator-replay-binding',
        'original_receipt_sha256': old['receipt_sha256'], 'current_receipt_sha256': new['receipt_sha256'],
        'identity_sha256': new['identity_sha256'], 'original_root': old['root'], 'current_root': new['root'],
        'raw': old['raw'], 'plan': old['plan'], 'ledger': old['ledger'], 'driver': old['driver'],
        'current_runtime': new['runtime']})
