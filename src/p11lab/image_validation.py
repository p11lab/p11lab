"""Local exact-image validation primitives; no publication authority is implied."""
from dataclasses import asdict
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import tarfile
import tempfile
from types import SimpleNamespace
from uuid import uuid4

from .docker import Docker, DockerError
from .licenses import inspect_artifact
from .models import ArtifactRef, BoundedRunPolicy, RunSpec
from .tool_builds import _elf_closure, _options, verify_execution_boundary, verify_tool_build
from .tool_inputs import load_tool_input_lock
from .checker import load_profile, run_checker
from .run import redact_text, run_application
from .bounded_run import CaptureUnavailableError, CredentialTaintError, require_nonroot, validate_policy
from .inspection_bounded import InspectionPolicy, bounded_stream
from .tool_rootfs import _transfer
from .process import supervised_exec
from .round_core.bootstrap import verify_receipt


def select_checker_additions(installed: dict, base: dict, provider: dict) -> dict:
    """Select the verified Python/checker closure without overwriting provider bytes."""
    parent = {entry['path'].lstrip('/'): entry for entry in provider['files']}
    additions = {}
    for kind in ('files', 'aliases'):
        for path, value in installed[kind].items():
            selected = (path == 'usr/bin/python3.13'
                        or path == 'etc/python3.13/sitecustomize.py'
                        or path.startswith(('usr/lib/python3.13/', 'opt/p11lab-checker/'))
                        or (path.startswith('usr/lib/x86_64-linux-gnu/')
                            and base[kind].get(path) != value))
            if not selected:
                continue
            existing = parent.get(path)
            if existing is not None:
                same = (all(existing.get(k) == value.get(k) for k in ('sha256', 'size', 'mode'))
                        if kind == 'files' else existing.get('link') == value.get('target'))
                if not same:
                    raise ValueError('checker copy would change parent bytes or alias: ' + path)
                continue
            additions[path] = {'kind': 'file' if kind == 'files' else 'alias', **value}
    return additions


def verify_composition(parent: dict, child: dict, additions: dict) -> None:
    """Verify every original object and every selected addition after composition."""
    before = {row['path'].lstrip('/'): row for row in parent['files']}
    after = {row['path'].lstrip('/'): row for row in child['files']}
    keys = ('sha256', 'size', 'mode', 'link')
    for path, value in before.items():
        if path not in after or any(after[path].get(key) != value.get(key) for key in keys):
            raise ValueError('provider parent changed: ' + path)
    for path, value in additions.items():
        actual = after.get(path, {})
        if value['kind'] == 'file':
            matches = all(actual.get(key) == value.get(key) for key in ('sha256', 'size', 'mode'))
        else:
            matches = actual.get('link') == value['target']
        if not matches:
            raise ValueError('verified copy mismatch: ' + path)
    if set(after) != set(before) | set(additions):
        raise ValueError('unexpected composition filesystem roster')


def verify_parent_metadata(parent: dict, child: dict) -> None:
    for path, metadata in parent.items():
        if child.get(path) != metadata:
            raise ValueError('provider parent metadata changed: ' + path)


def reject_unsafe_composition_paths(parent: dict, additions: dict) -> None:
    non_directories = {row['path'].lstrip('/') for row in parent['files']} | set(additions)
    for name in additions:
        pieces = name.split('/')
        if (not name or name.startswith('/') or any(piece in ('', '.', '..') for piece in pieces)
                or '\\' in name or '\0' in name):
            raise ValueError('unsafe composition path')
        if any('/'.join(pieces[:index]) in non_directories for index in range(1, len(pieces))):
            raise ValueError('composition path has a non-directory ancestor')


def _tree_metadata(archive: Path):
    result = {}
    with tarfile.open(archive, 'r|') as source:
        for member in source:
            name = member.name.removeprefix('./').removesuffix('/')
            if name in ('', '.') and member.isdir():
                continue
            if (not name or name.startswith('/') or '..' in name.split('/') or name in result
                    or len(result) >= 100000):
                raise ValueError('unsafe or duplicate provider export member')
            result[name] = {'type': member.type.hex(), 'mode': member.mode, 'uid': member.uid,
                            'gid': member.gid, 'link': member.linkname}
    return result


def _add_file(bundle, name, raw, mode, additions):
    info = tarfile.TarInfo(name)
    info.mode, info.uid, info.gid, info.size = mode, 0, 0, len(raw)
    bundle.addfile(info, io.BytesIO(raw))
    additions[name] = {'kind': 'file', 'sha256': hashlib.sha256(raw).hexdigest(),
                       'size': len(raw), 'mode': mode}


def _stage_checker(tool_dir: Path, parent: dict, output: Path):
    installed = json.loads((tool_dir / 'installed-filesystem.json').read_bytes())
    base = json.loads((tool_dir / 'checker-parent.json').read_bytes())
    selected = select_checker_additions(installed, base, parent)
    roots = ['usr/bin/python3.13'] + [path for path in installed['elfs']
             if path.startswith(('usr/lib/python3.13/', 'opt/p11lab-checker/'))]
    closure = _elf_closure(installed, roots)
    original = {entry['path'].lstrip('/'): entry for entry in parent['files']}
    for name, info in closure.items():
        if name not in selected and original.get(name, {}).get('sha256') != info['sha256']:
            raise ValueError('checker ELF dependency absent from verified composition: ' + name)
    copied = {}
    with tarfile.open(output, 'x') as destination, tarfile.open(tool_dir / 'installed-filesystem.tar', 'r|') as source:
        for member in source:
            name = member.name.removeprefix('./').removesuffix('/')
            if name not in selected:
                continue
            if name in copied:
                raise ValueError('duplicate selected tool member')
            expected = selected[name]
            if expected['kind'] == 'file':
                if not member.isfile() or member.mode != expected['mode'] or member.size != expected['size']:
                    raise ValueError('selected tool member changed')
                raw = source.extractfile(member).read(member.size + 1)
                if hashlib.sha256(raw).hexdigest() != expected['sha256'] or len(raw) != expected['size']:
                    raise ValueError('selected tool member bytes changed')
                _add_file(destination, name, raw, member.mode, copied)
            else:
                if not member.issym() or member.linkname != expected['target']:
                    raise ValueError('selected tool alias changed')
                info = tarfile.TarInfo(name)
                info.type, info.linkname, info.mode = tarfile.SYMTYPE, member.linkname, member.mode
                destination.addfile(info)
                copied[name] = expected
        if set(copied) != set(selected):
            raise ValueError('missing selected tool members')
        control = Path(__file__).parent
        for path in sorted(control.rglob('*')):
            if path.is_symlink():
                raise ValueError('controller package symlink is unsupported')
            if not path.is_file() or '__pycache__' in path.parts or path.suffix == '.pyc':
                continue
            raw = path.read_bytes()
            if len(raw) > 16 * 1024**2:
                raise ValueError('controller package file exceeds bound')
            name = 'opt/p11lab-code/p11lab/' + path.relative_to(control).as_posix()
            _add_file(destination, name, raw, 0o644, copied)
        seal = {'source_revision': '9df03bd8b811966fa7856394b19e3f57ffcd8a40',
                'wheel_sha256': '58ac3451ae0dba207a48affa460309e4024c2ec7aefb04ef73062f420fdcffec',
                'runtime_lock_sha256': '98a0341351b410b8ba6d732ae82ffef14442cded33caf8ab55e3958a0c407cab'}
        _add_file(destination, 'usr/share/p11lab/checker-install.json', json.dumps(seal).encode(), 0o644, copied)
        _add_file(destination, 'opt/p11lab-checker/lib/python3.13/site-packages/p11lab.pth',
                  b'/opt/p11lab-code\n', 0o644, copied)
    if output.stat().st_size > 256 * 1024**2:
        raise ValueError('composition input exceeds bound')
    return copied, closure


def compose_local_image(artifact: ArtifactRef, tool: str, tool_dir: Path, receipt: Path,
                        manifest_sha256: str, output: Path) -> dict:
    """Copy a verified fixed tool into an inert child and recheck parent and output bytes.

    The externally supplied seal is verified again before any composition. The
    resulting image is local-only and supplies no provenance/rights approval.
    """
    require_nonroot()
    tool_manifest = verify_tool_build(tool_dir, receipt_path=receipt, manifest_sha256=manifest_sha256)
    if tool not in ('checker', 'consumer') or tool_manifest.get('toolset') != tool:
        raise ValueError('incorrect verified tool role')
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    engine = Docker()
    image = engine.image(artifact)
    parent = inspect_artifact(artifact, inspection_policy=InspectionPolicy(), journal_path=output / 'parent-inspection.json')
    (output / 'parent.json').write_text(json.dumps(parent, sort_keys=True) + '\n')
    archive = output / 'composition.tar'
    closure = None
    if tool == 'checker':
        additions, closure = _stage_checker(Path(tool_dir), parent, archive)
    else:
        spec = tool_manifest['products'][0]
        raw = (Path(tool_dir) / spec['path']).read_bytes()
        if len(raw) != spec['size'] or hashlib.sha256(raw).hexdigest() != spec['sha256']:
            raise ValueError('consumer binary changed')
        additions = {}
        with tarfile.open(archive, 'x') as bundle:
            _add_file(bundle, 'usr/local/bin/p11lab-smoke', raw, 0o755, additions)
    existing = {v['path'].lstrip('/') for v in parent['files']}
    if existing & set(additions):
        raise ValueError('composition additions collide with parent')
    reject_unsafe_composition_paths(parent, additions)
    labels = {'org.p11lab.composition': uuid4().hex}
    container = None
    result = {'schema_version': 1, 'kind': 'local-copy-only-composition',
              'parent': asdict(artifact), 'parent_observation': image,
              'tool': tool, 'copy_files': additions, 'elf_closure': closure,
              'cleanup_errors': [], 'rootfs_transfers': []}
    attempt = SimpleNamespace(output=output, engine=engine, result=result)
    try:
        try:
            container = engine.create(artifact.reference, ['/p11lab-not-executed'], ['--network', 'none'],
                                      labels, 'p11lab-compose-' + labels['org.p11lab.composition'])
        except DockerError as error:
            if error.resource and error.resource[0] == 'container':
                container = error.resource[1]
            if error.uncertain_resource:
                result['cleanup_errors'].append('container creation status unknown')
            raise
        actual = json.loads(engine.command(['container', 'inspect', container]).stdout)[0]
        if actual.get('Image') != artifact.reference or actual.get('State', {}).get('Running') is not False:
            raise ValueError('composition child is not stopped on exact parent')
        result['source_container_id'] = container
        result['source_inspection'] = actual
        with tempfile.TemporaryDirectory(prefix='.composition-readback-', dir=output) as temporary:
            before_tar = Path(temporary) / 'before.tar'
            after_tar = Path(temporary) / 'after.tar'
            parent_transfer = {}
            result['rootfs_transfers'].append({'role': 'parent-export', 'record': parent_transfer})
            bounded_stream(['docker', 'export', container], before_tar, 512 * 1024**2, 120,
                           engine.env, parent_transfer)
            before_metadata = _tree_metadata(before_tar)
            _transfer(attempt, ['docker', 'cp', '-a', '-', container + ':/'], 'composition', source=archive)
            child_transfer = {}
            result['rootfs_transfers'].append({'role': 'child-export', 'record': child_transfer})
            bounded_stream(['docker', 'export', container], after_tar, 512 * 1024**2, 120,
                           engine.env, child_transfer)
            after_metadata = _tree_metadata(after_tar)
            verify_parent_metadata(before_metadata, after_metadata)
            for name in additions:
                info = after_metadata.get(name)
                if info is None or info['uid'] != 0 or info['gid'] != 0:
                    raise ValueError('composed file ownership mismatch: ' + name)
            (output / 'parent-metadata.json').write_text(json.dumps(before_metadata, sort_keys=True) + '\n')
            (output / 'child-metadata.json').write_text(json.dumps(after_metadata, sort_keys=True) + '\n')
            result['parent_metadata_preserved'] = True
        commit = engine.command(['commit', container]).stdout.strip()
        if not commit.startswith('sha256:') or len(commit) != 71:
            raise ValueError('unexpected composed image identity')
        derived = ArtifactRef('docker-local', commit, commit[7:], artifact.platform)
        child_image = engine.image(derived)
        parent_layers = image['RootFS']['Layers']
        if child_image['RootFS']['Layers'][:len(parent_layers)] != parent_layers:
            raise ValueError('composition lost parent layer prefix')
        child = inspect_artifact(derived, inspection_policy=InspectionPolicy(), journal_path=output / 'child-inspection.json')
        verify_composition(parent, child, additions)
        (output / 'child.json').write_text(json.dumps(child, sort_keys=True) + '\n')
        result['derived'] = asdict(derived)
        result['derived_observation'] = child_image
    finally:
        if container:
            try:
                engine.remove('container', container, labels)
                result['source_cleanup'] = 'removed-exact-owned-container'
            except (DockerError, OSError, ValueError):
                result['cleanup_errors'].append('composition child cleanup failed')
        (output / 'composition.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    if result['cleanup_errors']:
        raise ValueError('composition cleanup incomplete')
    return result


def check_oracle_results(results):
    for name, expected in (('positive', 0), ('altered_message', 1), ('altered_signature', 1)):
        item = results.get(name, {})
        identity = item.get('container_id')
        after = item.get('inspection_after') or {}
        if (not isinstance(identity, str) or not re.fullmatch('[0-9a-f]{64}', identity)
                or item.get('inspection_before', {}).get('Id') != identity or after.get('Id') != identity
                or after.get('State', {}).get('Running') is not False or after.get('State', {}).get('Pid') != 0
                or item.get('cleanup') != 'removed-exact-owned-container'
                or item.get('returncode') != expected or item.get('timed_out') is not False
                or item.get('stdout_truncated') is not False or item.get('stderr_truncated') is not False):
            raise ValueError('independent oracle control incomplete: ' + name)
    if ('OpenSSL verified original signature; altered message rejected.' not in results['positive'].get('stdout', '')
            or 'Verification failure' not in results['altered_message'].get('stdout', '')
            or 'OpenSSL rejected the original message signature' not in results['altered_signature'].get('stderr', '')):
        raise ValueError('independent oracle control did not exercise expected verification')


def check_catalog(nodes, selected, expected_counts):
    if (len(nodes) != len(set(nodes)) or len(selected) != len(set(selected))
            or not set(selected) <= set(nodes)):
        raise ValueError('checker catalog overlap or missing selection')
    counts = {name: 0 for name in expected_counts}
    for node in nodes:
        source, separator, _ = node.partition('::')
        if not separator or source not in counts:
            raise ValueError('checker catalog unexpected source or node')
        counts[source] += 1
    if counts != expected_counts:
        raise ValueError('checker catalog source counts differ from frozen selection')


def collect_checker_catalog(tool_dir: Path, receipt: Path, seal: str, output: Path) -> dict:
    require_nonroot()
    manifest = verify_tool_build(tool_dir, receipt_path=receipt, manifest_sha256=seal)
    if manifest.get('toolset') != 'checker':
        raise ValueError('incorrect checker role')
    profile = load_profile()
    counts = {'test_interface.py': 11, 'test_session_info.py': 4, 'test_object.py': 16,
              'test_digest.py': 21, 'test_sign.py': 18}
    root = '/opt/p11lab-checker/lib/python3.13/site-packages/pkcs11_check/testcases'
    inventory = json.loads((Path(tool_dir) / 'installed-filesystem.json').read_bytes())
    for name, sha in profile['sources'].items():
        if inventory['files'].get(root.lstrip('/') + '/' + name, {}).get('sha256') != sha:
            raise ValueError('checker catalog installed source differs from profile')
    image = manifest['installed']['engine_id']
    labels = {'org.p11lab.catalog': uuid4().hex}
    user = '65532:65532'
    command = ['-i', 'PATH=/usr/bin:/bin', 'HOME=/tmp', 'LC_ALL=C.UTF-8',
               'PYTHONDONTWRITEBYTECODE=1', 'PYTEST_DISABLE_PLUGIN_AUTOLOAD=1', 'PYTEST_ADDOPTS=-v',
               '/opt/p11lab-checker/bin/python', '-m', 'pkcs11_check', 'list-tests', '--include-disabled']
    command += [root + '/' + name for name in sorted(counts)]
    engine = Docker()
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    result = {'image': image, 'external_manifest_sha256': seal, 'command': command, 'cleanup_errors': []}
    identity = None
    try:
        try:
            identity = engine.create(image, command, _options(readonly=True, user=user), labels,
                                     'p11lab-catalog-' + labels['org.p11lab.catalog'])
        except DockerError as error:
            if error.resource and error.resource[0] == 'container':
                identity = error.resource[1]
            if error.uncertain_resource:
                result['cleanup_errors'].append('catalog creation status unknown')
            raise
        observed = json.loads(engine.command(['container', 'inspect', identity]).stdout)[0]
        verify_execution_boundary(observed, image, command, [], readonly=True, user=user)
        result['container_id'] = identity
        result['inspection_before'] = observed
        native = engine.execute(identity, 180, lambda: None)
        result['inspection_after'] = json.loads(engine.command(['container', 'inspect', identity]).stdout)[0]
        if (result['inspection_after'].get('State', {}).get('Running') is not False
                or result['inspection_after'].get('State', {}).get('Pid') != 0):
            raise ValueError('checker catalog process remained active')
        result['native'] = asdict(native)
        if native.returncode or native.timed_out or native.stdout_truncated or native.stderr_truncated:
            raise ValueError('checker catalog collection failed')
        nodes = native.stdout.splitlines()
        check_catalog(nodes, profile['nodes'], counts)
        result['nodes'] = nodes
    finally:
        if identity:
            try:
                engine.remove('container', identity, labels)
                result['cleanup'] = 'removed-exact-owned-container'
            except (DockerError, OSError, ValueError):
                result['cleanup_errors'].append('catalog cleanup failed')
        (output / 'catalog.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    if result['cleanup_errors']:
        raise ValueError('checker catalog cleanup incomplete')
    return result


def check_attempt_stage_identities(receipt, image, fixed_validation=None, entrypoint=None, user=None):
    phases = ('init', 'ready', 'application', 'post-health')
    stages = receipt['stages']
    boundaries = receipt['bounded_execution']['stages']
    if [row['phase'] for row in stages] != list(phases) or set(boundaries) != set(phases):
        raise ValueError('checker or consumer stage roster mismatch')
    ids = []
    for stage in stages:
        identity = stage['container_id']
        boundary = boundaries[stage['phase']]
        if (not isinstance(identity, str) or not re.fullmatch('[0-9a-f]{64}', identity)
                or boundary['id'] != identity or boundary['image'] != image):
            raise ValueError('checker or consumer stage identity mismatch')
        if fixed_validation is not None:
            from .bounded_run import fixed_validation_command, fixed_validation_observation
            if receipt['execution']['uid_gid'] != user:
                raise ValueError('fixed validation execution user mismatch')
            config = {'Cmd': fixed_validation_command(fixed_validation, stage['phase']),
                      'Entrypoint': entrypoint, 'User': user}
            expected = fixed_validation_observation(config, fixed_validation, stage['phase'], user, [])
            if boundary.get('fixed_validation_observation') != expected:
                raise ValueError('fixed validation observed command, entrypoint or user mismatch')
        ids.append(identity)
    if (len(set(ids)) != len(ids)
            or receipt['owned_resources'] != [{'kind': 'container', 'identity': identity} for identity in ids]):
        raise ValueError('checker or consumer stage ownership mismatch')


def check_checker_originals(output: Path, selected: list[str], image: str, fixed_validation=None,
                            entrypoint=None, user=None) -> dict:
    """Close the fixed outer attempt and original roster without interpreting findings."""
    output = Path(output)
    required = ('receipt.json', 'checker/checker-receipt.json', 'checker/collection.json',
                'checker/collection.stdout.log', 'checker/collection.stderr.log', 'checker/report.jsonl',
                'checker/results.json', 'checker/state.json', 'checker/coverage.json',
                'checker/checker.stdout.log', 'checker/checker.stderr.log', 'bounded-output.tar')
    for name in required:
        path = output / name
        if path.is_symlink() or not path.is_file():
            raise ValueError('checker original missing or unsafe: ' + name)
    outer = json.loads((output / 'receipt.json').read_bytes())
    inner = json.loads((output / 'checker/checker-receipt.json').read_bytes())
    collection = json.loads((output / 'checker/collection.json').read_bytes())
    state = json.loads((output / 'checker/state.json').read_bytes())
    phases = outer.get('stages', [])
    check_bounded_receipt(outer)
    check_attempt_stage_identities(outer, image, fixed_validation, entrypoint, user)
    expected = ['/opt/p11lab-checker/lib/python3.13/site-packages/pkcs11_check/testcases/' + node for node in selected]
    if (outer.get('artifacts', {}).get('provider', {}).get('reference') != image
            or outer.get('state', {}).get('persistent_caller_directory') is not False
            or outer.get('app_completed') is not True or type(outer.get('app_returncode')) is not int
            or outer.get('app_returncode') not in (0, 1) or 'interrupted_signal' not in outer
            or outer.get('timeout') is not False or outer.get('interrupted_signal') is not None
            or outer.get('lifecycle_errors') != [] or outer.get('cleanup_errors') != []
            or [p.get('phase') for p in phases] != ['init', 'ready', 'application', 'post-health']
            or any(type(p.get('returncode')) is not int or p.get('timed_out') is not False or p.get('stdout_truncated') is not False
                   or p.get('stderr_truncated') is not False for p in phases)
            or any(p.get('returncode') != 0 for p in (phases[0], phases[1], phases[3]))
            or inner.get('nodes') != selected or type(inner.get('returncode')) is not int
            or inner.get('returncode') != outer.get('app_returncode')
            or inner.get('timeout') is not False or inner.get('evidence', {}).get('observations_complete') is not True
            or inner.get('evidence', {}).get('complete') is not True
            or collection.get('returncode') != 0 or collection.get('nodes') != selected
            or set(collection.get('installed_nodes', [])) != set(expected)
            or len(collection.get('installed_nodes', [])) != len(expected)
            or state.get('units') != expected or state.get('process_observations_complete') is not True):
        raise ValueError('checker lifecycle, selection, supervision or original evidence incomplete')
    attempts = state.get('results', [])
    if (len(attempts) != len(expected) or {row.get('target') for row in attempts} != set(expected)
            or any(row.get('completion_verified') is not True for row in attempts)):
        raise ValueError('checker attempt roster incomplete')
    cache = output / 'checker/.state.json.report-records'
    if cache.is_symlink() or not cache.is_dir():
        raise ValueError('checker original report cache missing')
    members = list(cache.iterdir())
    if (len(members) != len(expected) or any(p.is_symlink() or not p.is_file() or p.stat().st_size == 0
                                              or p.suffix != '.jsonl' for p in members)):
        raise ValueError('checker original report cache incomplete')
    return {'outer_attempt_id': outer['attempt_id'], 'checker_attempt_id': inner['attempt_id'],
            'app_returncode': outer['app_returncode'], 'summary': inner['evidence']['summary'],
            'cache_count': len(members)}


SHARING_UNKNOWN_RECEIPT = 'blocked:unknown-receipt'
SHARING_FOREIGN_RECEIPT = 'blocked:foreign-receipt'
SHARING_CARRIER_MISMATCH = 'blocked:carrier-mismatch'
SHARING_INCOMPLETE_EVIDENCE = 'blocked-incomplete-evidence'

GATE_LANES = ('checker', 'consumer')
GATE_PHASES = ('init', 'ready', 'application', 'post-health')

EXPORT_GATE_SCHEMA = 'p11lab.evidence-gate.v1'
EXPORT_GATE_CHECKS = ('archive-scan', 'stream-scan', 'fixed-command', 'metadata-scan',
                      'capture-complete', 'lane-admission', 'oracle-scan', 'result-binding')

ORACLE_BIND_NAMES = ('public-key.pem', 'public-key.der', 'message.bin', 'digest.bin',
                     'signature.raw', 'signature.der', 'result.json')
ORACLE_BIND_DIRS = ('original', 'message', 'signature')


class GateCarrierError(ValueError):
    """A gate carrier is missing, foreign, or inconsistent; export is blocked as unknown."""

    def __init__(self, sharing, message):
        super().__init__(message)
        self.sharing = sharing


class IncompleteEvidenceError(ValueError):
    """Incomplete evidence outside the shareable roster; export is blocked."""

    def __init__(self, sharing, message):
        super().__init__(message)
        self.sharing = sharing


SHAREABLE_INCOMPLETE_ROSTER: frozenset[str] = frozenset()


def _shareable_incomplete(value):
    """Whether an incomplete value belongs to the shareable roster (v1: none do)."""
    errors = value.get('infrastructure_errors') if isinstance(value, dict) else None
    if not isinstance(errors, list):
        return False
    classes = {str(item).split(':')[0].strip() for item in errors}
    return bool(classes) and classes <= SHAREABLE_INCOMPLETE_ROSTER


def check_gate_admission(record, *, lane, image=None, basis=None, fixed=None, tar_bytes=None):
    """Single positive gate-1 lane-admission predicate (Q7).

    One shared helper with three call sites (reject_tainted_run, the
    packaging gate, the post-hoc verifier); no divergent copies. Taint and
    capture-unavailable keep their local-verdict errors; carrier problems
    raise GateCarrierError with an exact sharing label. Expected image,
    export-gate basis, and fixed-validation context bind tighter when the
    caller supplies them.
    """
    if not isinstance(record, dict):
        raise GateCarrierError(SHARING_UNKNOWN_RECEIPT, 'gate-1 lane receipt unreadable; export blocked')
    bounded = record.get('bounded_execution')
    readback = None
    if isinstance(bounded, dict):
        output = bounded.get('output')
        if isinstance(output, dict):
            candidate = output.get('readback')
            readback = candidate if isinstance(candidate, dict) else None
        if bounded.get('stream_tainted') is True or (readback or {}).get('tainted') is True:
            raise CredentialTaintError('candidate output contains staged credential; export blocked')
        if bounded.get('stream_capture_unavailable') is True:
            phase = bounded.get('stream_capture_phase', 'unknown')
            cause = bounded.get('stream_capture_error', 'unknown')
            raise CaptureUnavailableError(f'candidate stream unavailable ({phase}; {cause}); export blocked')
    stages = record.get('stages')
    if isinstance(stages, list):
        for row in stages:
            if isinstance(row, dict) and (row.get('stdout_truncated') is True or row.get('stderr_truncated') is True):
                raise CaptureUnavailableError('truncated capture; export blocked')
    if lane not in GATE_LANES:
        raise GateCarrierError(SHARING_FOREIGN_RECEIPT, 'gate-1 receipt lane not admitted; export blocked')
    if not isinstance(bounded, dict):
        raise GateCarrierError(SHARING_FOREIGN_RECEIPT, 'gate-1 receipt is not a bounded lane carrier; export blocked')
    if not isinstance(record.get('bounded_policy'), dict):
        raise GateCarrierError(SHARING_CARRIER_MISMATCH, 'gate-1 bounded policy missing; export blocked')
    if (record.get('environment') != 'softhsm2' or record.get('channel') != 'release'
            or record.get('mode') != 'direct' or record.get('execution_location') != 'provider'):
        raise GateCarrierError(SHARING_FOREIGN_RECEIPT, 'gate-1 receipt routing not admitted; export blocked')
    if (not isinstance(record.get('state'), dict)
            or record['state'].get('persistent_caller_directory') is not False):
        raise GateCarrierError(SHARING_FOREIGN_RECEIPT, 'gate-1 receipt state not disposable; export blocked')
    if not isinstance(record.get('attempt_id'), str) or not re.fullmatch('[0-9a-f]{32}', record['attempt_id']):
        raise GateCarrierError(SHARING_CARRIER_MISMATCH, 'gate-1 attempt identity mismatch; export blocked')
    if (not isinstance(stages, list) or any(not isinstance(row, dict) for row in stages)
            or [row.get('phase') for row in stages] != list(GATE_PHASES)):
        raise GateCarrierError(SHARING_CARRIER_MISMATCH, 'gate-1 stage roster mismatch; export blocked')
    for row in stages:
        if (not isinstance(row.get('container_id'), str)
                or not re.fullmatch('[0-9a-f]{64}', row['container_id'])
                or type(row.get('returncode')) is not int or row.get('timed_out') is not False
                or row.get('stdout_truncated') is not False or row.get('stderr_truncated') is not False):
            raise GateCarrierError(SHARING_CARRIER_MISMATCH, 'gate-1 stage identity or supervision mismatch; export blocked')
        if row['phase'] in ('init', 'ready', 'post-health') and row['returncode'] != 0:
            raise GateCarrierError(SHARING_CARRIER_MISMATCH, 'gate-1 stage lifecycle mismatch; export blocked')
    identities = [row['container_id'] for row in stages]
    if (len(set(identities)) != len(identities)
            or record.get('owned_resources') != [{'kind': 'container', 'identity': identity} for identity in identities]):
        raise GateCarrierError(SHARING_CARRIER_MISMATCH, 'gate-1 stage ownership mismatch; export blocked')
    if record.get('uncertain_resources') != [] or record.get('cleanup_errors') != []:
        raise GateCarrierError(SHARING_CARRIER_MISMATCH, 'gate-1 resource ownership mismatch; export blocked')
    if (not isinstance(readback, dict) or readback.get('returncode') != 0 or readback.get('timed_out') is not False
            or readback.get('tainted') is not False or readback.get('stdout_truncated') is not False
            or readback.get('stderr_truncated') is not False or readback.get('supervision_errors') != []
            or readback.get('stragglers_remaining') != [] or readback.get('drain_complete') is not True):
        raise GateCarrierError(SHARING_CARRIER_MISMATCH, 'gate-1 bounded readback incomplete; export blocked')
    if tar_bytes is None:
        raise GateCarrierError(SHARING_CARRIER_MISMATCH, 'gate-1 bounded readback tar unavailable; export blocked')
    if (readback.get('sha256') != hashlib.sha256(tar_bytes).hexdigest() or readback.get('size') != len(tar_bytes)):
        raise GateCarrierError(SHARING_CARRIER_MISMATCH, 'gate-1 bounded readback tar mismatch; export blocked')
    boundaries = bounded.get('stages')
    if (not isinstance(boundaries, dict) or set(boundaries) != set(GATE_PHASES)
            or any(not isinstance(row, dict) or 'fixed_validation_observation' not in row
                   or not row.get('id') or not row.get('image') for row in boundaries.values())):
        raise GateCarrierError(SHARING_CARRIER_MISMATCH, 'gate-1 fixed validation proof missing; export blocked')
    try:
        check_bounded_receipt(record)
    except (CredentialTaintError, CaptureUnavailableError):
        raise
    except ValueError as error:
        raise GateCarrierError(SHARING_CARRIER_MISMATCH, 'gate-1 lane admission failed: ' + str(error)) from error
    artifacts = record.get('artifacts')
    provider = artifacts.get('provider') if isinstance(artifacts, dict) else None
    if not isinstance(provider, dict) or not provider.get('reference'):
        raise GateCarrierError(SHARING_CARRIER_MISMATCH, 'gate-1 admission identity mismatch; export blocked')
    if image is not None and provider['reference'] != image:
        raise GateCarrierError(SHARING_CARRIER_MISMATCH, 'gate-1 admission identity mismatch; export blocked')
    if basis is not None and (basis.get(lane + '_attempt_id') != record['attempt_id']
                              or basis.get(lane + '_stages') != [row['container_id'] for row in stages]):
        raise GateCarrierError(SHARING_CARRIER_MISMATCH, 'gate-1 export gate identity mismatch; export blocked')
    try:
        if fixed is None:
            check_attempt_stage_identities(record, provider['reference'])
        else:
            check_attempt_stage_identities(record, image if image is not None else provider['reference'],
                                           fixed[0], fixed[1], fixed[2])
    except (CredentialTaintError, CaptureUnavailableError):
        raise
    except ValueError as error:
        raise GateCarrierError(SHARING_CARRIER_MISMATCH, 'gate-1 lane admission failed: ' + str(error)) from error


def reject_tainted_run(receipt_path: Path, *, lane=None):
    """Fail closed on tainted, unknown, foreign, or mismatched lane carriers."""
    path = Path(receipt_path)
    if lane is None:
        parent = path.parent.name
        lane = parent[:-len('-run')] if parent in ('checker-run', 'consumer-run') else None
    if path.is_symlink() or not path.is_file():
        raise GateCarrierError(SHARING_UNKNOWN_RECEIPT, 'gate-1 lane receipt unavailable; export blocked')
    try:
        record = json.loads(path.read_bytes())
    except (OSError, ValueError):
        raise GateCarrierError(SHARING_UNKNOWN_RECEIPT, 'gate-1 lane receipt unreadable; export blocked') from None
    tar_path = path.parent / 'bounded-output.tar'
    tar_bytes = None
    if not tar_path.is_symlink() and tar_path.is_file():
        try:
            tar_bytes = tar_path.read_bytes()
        except OSError:
            tar_bytes = None
    check_gate_admission(record, lane=lane, tar_bytes=tar_bytes)


def check_bounded_receipt(receipt):
    """Require retained physical quota and exact owned storage cleanup observations."""
    try:
        bounded = receipt['bounded_execution']
        policy = BoundedRunPolicy(**receipt['bounded_policy'])
        validate_policy(policy, 1)
        uid, gid = receipt['execution']['uid_gid'].split(':')
        expected_tmpfs = {
            '/tmp': f'rw,nosuid,nodev,size={policy.tmp_bytes},nr_inodes={policy.inodes}',
            '/dev/shm': f'rw,nosuid,nodev,size={policy.run_bytes},nr_inodes={policy.inodes},mode=1777',
            '/run/p11lab': f'rw,nosuid,nodev,uid={uid},gid={gid},mode=0700,size={policy.run_bytes},nr_inodes={policy.inodes}'}
        state_name = bounded['state']['volume_inspection']['Name']
        output_name = bounded['output']['volume_inspection']['Name']
        credentials = {('bind', '/run/p11lab-input/' + name, None, False)
                       for name, value in receipt['inputs'].items() if value['secret'] and name.endswith('_FILE')}
        if set(bounded['stages']) != {'init', 'ready', 'application', 'post-health'}:
            raise ValueError('incomplete bounded stage roster')
        for name in ('state', 'output'):
            item = bounded[name]
            quota = item['kernel_tmpfs']
            probe = item['kernel_probe']
            probe_id = probe['container_id']
            probe_after = probe['inspection_after']
            size = policy.state_bytes if name == 'state' else policy.output_bytes
            if (quota['type'] != 'tmpfs' or quota['inodes'] != policy.inodes
                    or quota['block_size'] * quota['blocks'] > size
                    or quota['block_size'] * quota['blocks'] < size - 65536
                    or item['holder_cleanup'] != 'removed-exact-owned-container'
                    or item['volume_cleanup'] != 'removed-exact-owned-volume'
                    or not re.fullmatch('[0-9a-f]{64}', probe_id)
                    or probe['inspection_before']['Id'] != probe_id or probe_after['Id'] != probe_id
                    or probe_after['State']['Running'] is not False or probe_after['State']['Pid'] != 0
                    or probe['returncode'] != 0 or probe['timed_out'] is not False
                    or probe['stdout_truncated'] is not False or probe['stderr_truncated'] is not False
                    or probe['cleanup'] != 'removed-exact-owned-container'):
                raise ValueError('incomplete bounded storage proof')
        for phase, stage in bounded['stages'].items():
            host = stage['host_config']
            mounts = {(item['Type'], item['Destination'], item.get('Name') if item['Type'] == 'volume' else None,
                       item['RW']) for item in stage['mounts']}
            expected_mounts = {('volume', '/var/lib/p11lab', state_name, True)} | credentials
            if phase == 'application':
                expected_mounts |= {('volume', '/p11lab-output', output_name, True), ('bind', '/workspace', None, False)}
            if (host['Memory'] != policy.memory_bytes or host['MemorySwap'] != policy.memory_bytes
                    or host['PidsLimit'] != policy.pids or host['NanoCpus'] != 1_000_000_000
                    or host['ReadonlyRootfs'] is not True or host['NetworkMode'] != 'none'
                    or 'ALL' not in host['CapDrop'] or host.get('CapAdd')
                    or host['IpcMode'] != 'private' or host['Privileged']
                    or 'no-new-privileges=true' not in host['SecurityOpt'] or host['Tmpfs'] != expected_tmpfs
                    or mounts != expected_mounts or len(mounts) != len(stage['mounts'])):
                raise ValueError('incomplete bounded stage proof')
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError('checker bounded execution evidence incomplete') from error


def verify_evaluator(root: Path, seal: str) -> dict:
    root = Path(root).resolve(strict=True)
    path = root / 'evaluator-build-receipt.json'
    if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != seal:
        raise ValueError('evaluator external receipt seal mismatch')
    receipt = json.loads(path.read_bytes())
    verify_receipt(receipt, root, Path(__file__).parent / 'data/rounds/evaluator')
    return receipt


def check_public_shard_plan(plan, source_view: Path, expected: set[str]) -> list[str]:
    if not isinstance(plan, dict) or set(plan) != {'shards'} or not isinstance(plan['shards'], list) or len(plan['shards']) != 1:
        raise ValueError('public shard plan must contain exactly one shard')
    rows = plan['shards'][0]
    if not isinstance(rows, list) or any(not isinstance(row, str) for row in rows):
        raise ValueError('public shard plan roster malformed')
    names = []
    for row in rows:
        try:
            path = Path(row)
            relative = path.relative_to(source_view)
        except ValueError as error:
            raise ValueError('public shard plan escaped selected source view') from error
        if len(relative.parts) != 1 or relative.name not in expected:
            raise ValueError('public shard plan contains unexpected source')
        names.append(relative.name)
    if len(names) != len(set(names)) or set(names) != expected:
        raise ValueError('public shard plan has missing or overlapping sources')
    return names


def _runtime_journal_path(path, evaluator, output):
    from .tool_downloads import safe_directory
    path = Path(path)
    if not path.is_absolute():
        raise ValueError('runtime journal requires absolute path')
    safe_directory(path.parent)
    if not path.parent.is_dir() or path.exists() or path.is_symlink():
        raise ValueError('runtime journal requires fresh destination')
    resolved = path.resolve()
    if resolved.is_relative_to(Path(evaluator).resolve()) or resolved.is_relative_to(Path(output).resolve()):
        raise ValueError('runtime journal overlaps protected evidence')
    return resolved


def _verify_runtime_journal(path, operation, evaluator):
    from .delivery_authority import _read_bounded_file
    from .round_core.inputs import load_json
    from .round_core.evaluator_replay import _runtime_projection
    value = load_json(_read_bounded_file(path, 2 * 1024 * 1024))
    _runtime_projection(value, operation, evaluator)


def plan_checker_shard(evaluator: Path, seal: str, source_names: set[str], output: Path, *, runtime_journal: Path | None = None) -> dict:
    """Use the verified evaluator's public file planner on an exact source view."""
    require_nonroot()
    evaluator = Path(evaluator).resolve(strict=True)
    verify_evaluator(evaluator, seal)
    if not source_names or any(Path(name).name != name or not name.startswith('test_') or not name.endswith('.py')
                               for name in source_names):
        raise ValueError('invalid selected planner source roster')
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    view = output / 'source-view'
    view.mkdir()
    original = evaluator / 'evaluator-install/lib/python3.12/site-packages/pkcs11_check/testcases'
    sources = {}
    for name in sorted(source_names):
        path = original / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 2 * 1024**2:
            raise ValueError('unsafe evaluator planner source')
        raw = path.read_bytes()
        (view / name).write_bytes(raw)
        sources[name] = hashlib.sha256(raw).hexdigest()
    command = [str(evaluator / 'evaluator-install/bin/python'), '-I', '-B', '-m', 'pkcs11_check',
               'shard-units', '--shards', '1', '--testcases', str(view), '--format', 'json']
    if runtime_journal is not None:
        journal = _runtime_journal_path(runtime_journal, evaluator, output)
        driver = Path(__file__).parent / 'data/ci/delivery/evaluator-replay-driver.py'
        command = [str(evaluator / 'evaluator-install/bin/python'), '-I', '-B', str(driver),
                   'planner', str(journal), *command[5:]]
    environment = {'PATH': '/usr/bin:/bin', 'HOME': str(output), 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
                   'PYTHONDONTWRITEBYTECODE': '1', 'LD_LIBRARY_PATH': str(evaluator / 'python/lib')}
    status, timeout, owner, facts = supervised_exec(command, cwd=output, env=environment, timeout=120, limit=1024 * 1024)
    stdout, stderr = bytes(owner.capture.buffers[0]), bytes(owner.capture.buffers[1])
    (output / 'planner.stdout.json').write_bytes(stdout)
    (output / 'planner.stderr.log').write_bytes(stderr)
    (output / 'process.json').write_text(json.dumps({'argv': command, 'returncode': status, 'timed_out': timeout, **facts}, indent=2) + '\n')
    if (status or timeout or facts['stdout_truncated'] or facts['stderr_truncated'] or facts['supervision_errors']
            or facts['stragglers_remaining'] or not facts['drain_complete']):
        raise ValueError('public shard planning incomplete')
    if runtime_journal is not None:
        _verify_runtime_journal(journal, 'planner', evaluator)
    names = check_public_shard_plan(json.loads(stdout), view, source_names)
    if any(hashlib.sha256((view / name).read_bytes()).hexdigest() != digest for name, digest in sources.items()):
        raise ValueError('selected planner source view changed')
    verify_evaluator(evaluator, seal)
    result = {'files': names, 'evaluator_source_sha256': sources,
              'stdout_sha256': hashlib.sha256(stdout).hexdigest(), 'evaluator_receipt_sha256': seal}
    (output / 'planner.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    return result


def admit_checker(evaluator: Path, seal: str, checker_output: Path, plan: Path, output: Path, *, runtime_journal: Path | None = None) -> dict:
    """Invoke the sealed evaluator's public APIs on original raw bytes in isolation."""
    require_nonroot()
    evaluator = Path(evaluator).resolve(strict=True)
    verify_evaluator(evaluator, seal)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    frozen = plan.read_bytes()
    raw = Path(checker_output) / 'checker/report.jsonl'
    driver = Path(__file__).parent / 'data/ci/delivery/image-evidence.py'
    environment = {'PATH': '/usr/bin:/bin', 'HOME': str(output), 'LANG': 'C.UTF-8',
                   'LC_ALL': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1',
                   'LD_LIBRARY_PATH': str(evaluator / 'python/lib')}
    command = [str(evaluator / 'evaluator-install/bin/python'), '-I', '-B', str(driver),
               str(raw.resolve()), str(plan.resolve()), str((output / 'ledger.jsonl').resolve())]
    if runtime_journal is not None:
        journal = _runtime_journal_path(runtime_journal, evaluator, output.resolve())
        replay_driver = Path(__file__).parent / 'data/ci/delivery/evaluator-replay-driver.py'
        command = [str(evaluator / 'evaluator-install/bin/python'), '-I', '-B', str(replay_driver),
                   'admission', str(journal), *command[4:]]
    status, timeout, owner, facts = supervised_exec(command, cwd=output, env=environment,
                                                     timeout=120, limit=2 * 1024**2)
    stdout = bytes(owner.capture.buffers[0])
    stderr = bytes(owner.capture.buffers[1])
    (output / 'evaluator.stdout.log').write_bytes(stdout)
    (output / 'evaluator.stderr.log').write_bytes(stderr)
    (output / 'process.json').write_text(json.dumps({'argv': command, 'returncode': status, 'timed_out': timeout, **facts}, indent=2) + '\n')
    if (status or timeout or facts['stdout_truncated'] or facts['stderr_truncated']
            or facts['supervision_errors'] or facts['stragglers_remaining'] or not facts['drain_complete']):
        raise ValueError('public evaluator execution incomplete')
    if runtime_journal is not None:
        _verify_runtime_journal(journal, 'admission', evaluator)
    if plan.read_bytes() != frozen:
        raise ValueError('protected selection changed during admission')
    verify_evaluator(evaluator, seal)
    result = json.loads(stdout)
    if result.get('admission', {}).get('admitted') is not True:
        raise ValueError('public evaluator rejected checker stream')
    (output / 'admission.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    return result


def _local_policy(policy):
    if not isinstance(policy, dict) or set(policy) != {'tools', 'evaluator', 'control_base_revision'}:
        raise ValueError('local validation policy must supply only fixed tool inputs and base revision')
    if not isinstance(policy['control_base_revision'], str) or not re.fullmatch('[0-9a-f]{40}', policy['control_base_revision']):
        raise ValueError('local validation policy base revision malformed')
    tools = policy['tools']
    if not isinstance(tools, dict) or set(tools) != {'checker', 'consumer', 'oracle'}:
        raise ValueError('local validation policy tool roster mismatch')
    for item in tools.values():
        if (not isinstance(item, dict) or set(item) != {'root', 'input_receipt', 'manifest_sha256'}
                or not all(isinstance(item[k], str) and item[k] for k in item)
                or not re.fullmatch('[0-9a-f]{64}', item['manifest_sha256'])
                or not Path(item['root']).is_absolute() or not Path(item['input_receipt']).is_absolute()):
            raise ValueError('local validation policy tool input malformed')
    evaluator = policy['evaluator']
    if (not isinstance(evaluator, dict) or set(evaluator) != {'root', 'receipt_sha256'}
            or not isinstance(evaluator['root'], str) or not Path(evaluator['root']).is_absolute()
            or not isinstance(evaluator['receipt_sha256'], str)
            or not re.fullmatch('[0-9a-f]{64}', evaluator['receipt_sha256'])):
        raise ValueError('local validation policy evaluator input malformed')


def _source_digest():
    package = Path(__file__).parent
    items = []
    for path in sorted(package.rglob('*')):
        if path.is_symlink():
            raise ValueError('controller package symlink unsupported')
        if not path.is_file() or '__pycache__' in path.parts or path.suffix == '.pyc':
            continue
        raw = path.read_bytes()
        if len(raw) > 16 * 1024**2:
            raise ValueError('controller package member exceeds bound')
        items.append({'path': path.relative_to(package).as_posix(), 'size': len(raw),
                      'sha256': hashlib.sha256(raw).hexdigest()})
    encoded = json.dumps(items, sort_keys=True, separators=(',', ':')).encode()
    return hashlib.sha256(encoded).hexdigest()


def _seal_evidence(root: Path):
    entries, total = [], 0
    for path in sorted(root.rglob('*')):
        if path.is_symlink():
            raise ValueError('evidence contains unsafe symlink')
        if path.is_dir():
            continue
        if not path.is_file() or path.name in ('receipt.json.tmp', 'package.tar.gz'):
            raise ValueError('unsafe evidence file')
        size = path.stat().st_size
        total += size
        if size > 256 * 1024**2 or total > 512 * 1024**2 or len(entries) >= 10000:
            raise ValueError('evidence roster or byte limit exceeded')
        digest = hashlib.sha256()
        with path.open('rb') as stream:
            while block := stream.read(1024 * 1024):
                digest.update(block)
        entries.append({'path': path.relative_to(root).as_posix(), 'size': size, 'sha256': digest.hexdigest()})
    return entries


def _write_private_bytes(path, data):
    """Create an evidence file exclusively with exact 0600, independent of umask."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.fchmod(fd, 0o600)
        stream = os.fdopen(fd, 'wb')
    except BaseException:
        os.close(fd)
        raise
    with stream:
        stream.write(data)


def _package_evidence(root: Path, entries: list[dict]):
    archive = root / 'package.tar.gz'
    fd = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.fchmod(fd, 0o600)
        stream = os.fdopen(fd, 'wb')
    except BaseException:
        os.close(fd)
        raise
    with stream:
        with tarfile.open(fileobj=stream, mode='w:gz', compresslevel=1) as bundle:
            for entry in entries:
                path = root / entry['path']
                raw = path.read_bytes()
                if len(raw) != entry['size'] or hashlib.sha256(raw).hexdigest() != entry['sha256']:
                    raise ValueError('evidence changed before packaging')
                info = tarfile.TarInfo(entry['path'])
                info.size, info.mode, info.uid, info.gid, info.mtime = len(raw), 0o600, 0, 0, 0
                bundle.addfile(info, io.BytesIO(raw))
    return {'path': archive.name, 'size': archive.stat().st_size,
            'sha256': hashlib.sha256(archive.read_bytes()).hexdigest()}


def _oracle_bind_roster():
    roster = [directory + '/' + name for directory in ORACLE_BIND_DIRS for name in ORACLE_BIND_NAMES]
    roster.append('message/altered.bin')
    return sorted(roster)


def _digest_oracle_inputs(oracle_root):
    bindings = []
    for relpath in _oracle_bind_roster():
        path = Path(oracle_root) / relpath
        if path.is_symlink() or not path.is_file():
            raise GateCarrierError(SHARING_CARRIER_MISMATCH, 'gate-1 oracle bind input unavailable; export blocked')
        raw = path.read_bytes()
        bindings.append({'path': relpath, 'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})
    return bindings


def scan_oracle_inputs(root, secrets):
    """Direct exact-byte scan of the oracle bind inputs while secrets live (Q8).

    Mirrors the G1-S1 archive vocabulary (exact bytes plus the LF-framing
    variant); both the transitively scanned chain and this scan must pass.
    """
    root = Path(root)
    vocabulary = []
    for secret in secrets:
        if not secret:
            continue
        encoded = secret if isinstance(secret, bytes) else secret.encode('utf-8')
        vocabulary.append(encoded)
        if encoded.endswith(b'\n'):
            vocabulary.append(encoded[:-1])
    bindings = _digest_oracle_inputs(root)
    for row in bindings:
        raw = (root / row['path']).read_bytes()
        for token in vocabulary:
            if token and token in raw:
                raise CredentialTaintError('oracle bind input contains staged credential; '
                                           f'export blocked ({row["path"]})')
    return {'inputs': bindings, 'clean': True}


def check_oracle_scan_binding(oracle_root, scan, basis_inputs):
    """Bind the sealed oracle scan proof to the packaged bind inputs (Q8)."""
    if not isinstance(scan, dict) or scan.get('clean') is not True or not isinstance(scan.get('inputs'), list):
        raise ValueError('gate-1 oracle scan proof incomplete')
    if scan['inputs'] != basis_inputs:
        raise ValueError('gate-1 oracle scan proof differs from export basis')
    if sorted(row.get('path') for row in scan['inputs'] if isinstance(row, dict)) != _oracle_bind_roster():
        raise ValueError('gate-1 oracle scan roster incomplete')
    for row in scan['inputs']:
        path = Path(oracle_root) / row['path']
        if path.is_symlink() or not path.is_file():
            raise ValueError('gate-1 oracle scan input unavailable')
        raw = path.read_bytes()
        if len(raw) != row.get('size') or hashlib.sha256(raw).hexdigest() != row.get('sha256'):
            raise ValueError('gate-1 oracle scan proof mismatch')


def _scan_completion(records):
    rows = []
    for lane in GATE_LANES:
        for row in records[lane]['stages']:
            for stream in ('stdout', 'stderr'):
                rows.append({'lane': lane, 'phase': row['phase'], 'stream': stream,
                             'scanned': True, 'clean': True})
    return rows


def require_export_gate(value):
    """Refuse any evidence without the exact gate-1 proof shape (Q10)."""
    gate = value.get('export_gate') if isinstance(value, dict) else None
    expected = [{'name': name, 'result': 'pass'} for name in EXPORT_GATE_CHECKS]
    if (not isinstance(gate, dict) or gate.get('schema') != EXPORT_GATE_SCHEMA
            or gate.get('checks') != expected or gate.get('verdict') != 'eligible'
            or not isinstance(gate.get('basis'), dict)):
        raise ValueError('unsupported facade export gate (legacy-not-gate1-verified); export blocked')
    return gate


def _read_lane_carrier(output, lane):
    output = Path(output)
    try:
        raw = (output / (lane + '-run/receipt.json')).read_bytes()
    except OSError as error:
        raise GateCarrierError(SHARING_UNKNOWN_RECEIPT, f'gate-1 {lane} receipt unavailable at packaging; export blocked') from error
    try:
        record = json.loads(raw)
    except ValueError as error:
        raise GateCarrierError(SHARING_UNKNOWN_RECEIPT, f'gate-1 {lane} receipt unreadable at packaging; export blocked') from error
    try:
        tar_bytes = (output / (lane + '-run/bounded-output.tar')).read_bytes()
    except OSError as error:
        raise GateCarrierError(SHARING_CARRIER_MISMATCH, f'gate-1 {lane} readback tar unavailable at packaging; export blocked') from error
    return record, raw, tar_bytes


def build_export_gate(output, *, images, entrypoint, user):
    """Build the sealed export-gate proof from admitted lane carriers (Q1/Q7)."""
    output = Path(output)
    records = {}
    raws = {}
    for lane in GATE_LANES:
        record, raw, tar_bytes = _read_lane_carrier(output, lane)
        check_gate_admission(record, lane=lane, image=images[lane],
                             fixed=(lane, entrypoint, user), tar_bytes=tar_bytes)
        records[lane], raws[lane] = record, raw
    if records['checker']['attempt_id'] == records['consumer']['attempt_id']:
        raise GateCarrierError(SHARING_CARRIER_MISMATCH, 'gate-1 lane attempts must be independent; export blocked')
    try:
        oracle_record = json.loads((output / 'oracle/oracle.json').read_bytes())
    except (OSError, ValueError) as error:
        raise GateCarrierError(SHARING_CARRIER_MISMATCH, 'gate-1 oracle proof unavailable; export blocked') from error
    scan = oracle_record.get('scan') if isinstance(oracle_record, dict) else None
    if not isinstance(scan, dict) or scan.get('clean') is not True or not isinstance(scan.get('inputs'), list):
        raise GateCarrierError(SHARING_CARRIER_MISMATCH, 'gate-1 oracle scan proof incomplete; export blocked')
    basis = {'checker_attempt_id': records['checker']['attempt_id'],
             'consumer_attempt_id': records['consumer']['attempt_id'],
             'checker_receipt_sha256': hashlib.sha256(raws['checker']).hexdigest(),
             'checker_receipt_size': len(raws['checker']),
             'consumer_receipt_sha256': hashlib.sha256(raws['consumer']).hexdigest(),
             'consumer_receipt_size': len(raws['consumer']),
             'checker_stages': [row['container_id'] for row in records['checker']['stages']],
             'consumer_stages': [row['container_id'] for row in records['consumer']['stages']],
             'oracle_inputs': scan['inputs'],
             'controller_sha256': _source_digest(),
             'scan_completion': _scan_completion(records)}
    gate = {'schema': EXPORT_GATE_SCHEMA,
            'checks': [{'name': name, 'result': 'pass'} for name in EXPORT_GATE_CHECKS],
            'verdict': 'eligible', 'basis': basis}
    for lane in GATE_LANES:
        record, _, tar_bytes = _read_lane_carrier(output, lane)
        check_gate_admission(record, lane=lane, image=images[lane], basis=basis,
                             fixed=(lane, entrypoint, user), tar_bytes=tar_bytes)
    return gate


def _seal_gated_evidence(root, export_gate):
    """Seal only proof-carrying evidence: gate shape plus basis-vs-bytes binding (Q1)."""
    root = Path(root)
    if not isinstance(export_gate, dict) or export_gate.get('schema') != EXPORT_GATE_SCHEMA:
        raise ValueError('gate-1 export gate schema missing or unsupported')
    expected = [{'name': name, 'result': 'pass'} for name in EXPORT_GATE_CHECKS]
    if export_gate.get('checks') != expected or export_gate.get('verdict') != 'eligible':
        raise ValueError('gate-1 export gate checks incomplete')
    basis = export_gate.get('basis')
    if not isinstance(basis, dict):
        raise ValueError('gate-1 export gate basis missing')
    for lane in GATE_LANES:
        try:
            raw = (root / (lane + '-run/receipt.json')).read_bytes()
        except OSError as error:
            raise GateCarrierError(SHARING_CARRIER_MISMATCH, 'gate-1 export gate basis receipt unavailable') from error
        if (hashlib.sha256(raw).hexdigest() != basis.get(lane + '_receipt_sha256')
                or len(raw) != basis.get(lane + '_receipt_size')):
            raise GateCarrierError(SHARING_CARRIER_MISMATCH, 'gate-1 export gate basis receipt mismatch')
        record = json.loads(raw)
        if not isinstance(record, dict) or record.get('attempt_id') != basis.get(lane + '_attempt_id'):
            raise GateCarrierError(SHARING_CARRIER_MISMATCH, 'gate-1 export gate basis attempt mismatch')
    if _digest_oracle_inputs(root / 'oracle') != basis.get('oracle_inputs'):
        raise GateCarrierError(SHARING_CARRIER_MISMATCH, 'gate-1 export gate oracle basis mismatch')
    try:
        oracle_record = json.loads((root / 'oracle/oracle.json').read_bytes())
    except (OSError, ValueError) as error:
        raise GateCarrierError(SHARING_CARRIER_MISMATCH, 'gate-1 export gate oracle scan unavailable') from error
    sealed_scan = oracle_record.get('scan') if isinstance(oracle_record, dict) else None
    if (not isinstance(sealed_scan, dict) or sealed_scan.get('clean') is not True
            or sealed_scan.get('inputs') != basis.get('oracle_inputs')):
        raise GateCarrierError(SHARING_CARRIER_MISMATCH, 'gate-1 export gate oracle scan mismatch')
    if basis.get('controller_sha256') != _source_digest():
        raise GateCarrierError(SHARING_CARRIER_MISMATCH, 'gate-1 export gate controller mismatch')
    return _seal_evidence(root)


def check_body_binding(value, body_raw):
    """Cross-check the supplied enclosed body against the packaged sidecar bytes (Q9)."""
    from .jsonutil import loads
    if loads(body_raw) != value:
        raise ValueError('validation body differs from envelope')


def _gate_packaging(output, result, carrier_errors, *, images):
    if carrier_errors:
        raise carrier_errors[0]
    if (result.get('status') != 'observations-complete' or result.get('infrastructure_errors')
            or any(result.get(name) is None for name in ('checker', 'consumer', 'admission', 'oracle'))):
        if not _shareable_incomplete(result):
            raise IncompleteEvidenceError(SHARING_INCOMPLETE_EVIDENCE,
                                          'gate-1 incomplete evidence is not shareable; export blocked')
    entrypoint = result['image_observation']['Config']['Entrypoint']
    user = f'{os.getuid()}:{os.getgid()}'
    return build_export_gate(Path(output), images=images, entrypoint=entrypoint, user=user)


def local_checker_plan(profile, catalog_nodes, image, fixed):
    prefix = 'opt/p11lab-checker/lib/python3.13/site-packages/pkcs11_check/testcases/'
    selected = [prefix + node for node in profile['nodes']]
    catalog = [prefix + node for node in catalog_nodes]
    selected_hash = hashlib.sha256(json.dumps(sorted(selected), separators=(',', ':')).encode()).hexdigest()
    return {'catalog': catalog, 'selected': selected,
            'exclusions': {node: 'outside-fixed-smoke-profile' for node in sorted(set(catalog) - set(selected))},
            'dataset': 'not-supplied-to-this-smoke', 'disabled_policy': 'ignore-disabled-tests',
            'expected_shards': ['attempt-1/shard-0'], 'expected_outer_attempts': 1,
            'identity': {'lane': fixed['lane'], 'lane_os': 'linux', 'lane_arch': 'amd64',
                         'framework_sha': fixed['checker_revision'], 'p11lab_sha': '',
                         'image_digest': image, 'corpus_hash': '', 'disabled_hash': '',
                         'planned_count': len(selected), 'planned_collection_hash': selected_hash,
                         'shard_id': 'attempt-1/shard-0', 'created_by': 'p11lab-local-validation'}}


def describe_provider_binding(artifact, observed, parent_observation):
    distribution = parent_observation.get('distribution') or {}
    labels = observed.get('Config', {}).get('Labels') or {}
    return {'engine_id': artifact.reference, 'registry_index': None,
            'descriptor': parent_observation.get('descriptor'),
            'config_sha256': distribution.get('config_sha256'), 'layers': distribution.get('layers'),
            'build_key_label': labels.get('org.p11lab.build-key'),
            'source_revision_label': labels.get('org.p11lab.source-revision'),
            'label_authority': 'observation-only', 'build_receipt': None,
            'recipe_identity': None, 'recipe_provenance': 'unavailable',
            'ordered_patches': None, 'patch_provenance': 'unavailable'}


def validate_image(artifact: ArtifactRef, policy: dict, output: Path) -> dict:
    """Run one local SoftHSM N1 checker and independent C/oracle validation.

    Caller-provided seals identify local inputs; this API grants no CI, source,
    reviewer, distribution or promotion authority.
    """
    require_nonroot()
    _local_policy(policy)
    policy = json.loads(json.dumps(policy, sort_keys=True, separators=(',', ':')))
    _local_policy(policy)
    if (type(artifact) is not ArtifactRef or artifact.kind != 'docker-local'
            or not re.fullmatch('sha256:[0-9a-f]{64}', artifact.reference)
            or artifact.sha256 != artifact.reference[7:] or artifact.platform != 'linux/amd64'):
        raise ValueError('local validation requires an exact linux/amd64 engine image')
    output = Path(output).absolute()
    if output.exists() or output.is_symlink():
        raise ValueError('local validation output must be fresh')
    roots = [Path(row['root']).resolve(strict=True) for row in policy['tools'].values()]
    roots += [Path(policy['evaluator']['root']).resolve(strict=True)]
    resolved_output = output.resolve()
    if any(resolved_output.is_relative_to(root) or root.is_relative_to(resolved_output) for root in roots):
        raise ValueError('local validation output overlaps a protected tool input')
    fixed_path = Path(__file__).parent / 'data/ci/delivery/validation-policy.json'
    fixed_bytes = fixed_path.read_bytes()
    fixed = json.loads(fixed_bytes)
    profile = load_profile()
    source_sha = _source_digest()
    engine = Docker()
    observed = engine.image(artifact)
    for name, row in policy['tools'].items():
        product = verify_tool_build(Path(row['root']), receipt_path=Path(row['input_receipt']),
                                    manifest_sha256=row['manifest_sha256'])
        if product.get('toolset') != name:
            raise ValueError('local validation policy tool role mismatch')
    verify_evaluator(Path(policy['evaluator']['root']), policy['evaluator']['receipt_sha256'])
    output.mkdir(parents=True, exist_ok=False)
    os.chmod(output, 0o700)
    result = {'schema_version': 1, 'kind': 'local-image-validation', 'scope': 'local-only',
              'artifact': asdict(artifact), 'image_observation': observed,
              'control_base_revision_declared': policy['control_base_revision'], 'control_source_sha256': source_sha,
              'control_commit': None, 'authenticated_producer': None,
              'fixed_policy_sha256': hashlib.sha256(fixed_bytes).hexdigest(),
              'profile_sha256': hashlib.sha256((Path(__file__).parent / 'data/profiles/smoke-v1.json').read_bytes()).hexdigest(),
              'checker_source_files': profile['sources'],
              'comparison': None, 'promotable': False, 'source_admission': 'unverified',
              'build_receipt': None, 'authority': 'local-unauthenticated',
              'qualification_eligible': False,
              'qualification_gaps': ['authenticated-control-commit', 'authenticated-producer',
                                     'provider-build-receipt', 'source-and-rights-admission',
                                     'accepted-baseline-and-comparison'],
              'sharing': 'not-yet-evaluated',
              'tool_manifest_sha256': {name: row['manifest_sha256'] for name, row in policy['tools'].items()},
              'evaluator_receipt_sha256': policy['evaluator']['receipt_sha256'],
              'status': 'incomplete', 'infrastructure_errors': [], 'checker': None,
              'consumer': None, 'admission': None, 'oracle': None}
    tools = policy['tools']
    sensitive_values = []
    carrier_errors: list[GateCarrierError] = []
    try:
        catalog = collect_checker_catalog(Path(tools['checker']['root']), Path(tools['checker']['input_receipt']),
                                          tools['checker']['manifest_sha256'], output / 'catalog')
        planner = plan_checker_shard(Path(policy['evaluator']['root']), policy['evaluator']['receipt_sha256'],
                                     set(profile['sources']), output / 'planning')
        checker = compose_local_image(artifact, 'checker', Path(tools['checker']['root']),
                                      Path(tools['checker']['input_receipt']), tools['checker']['manifest_sha256'],
                                      output / 'checker-composition')
        consumer = compose_local_image(artifact, 'consumer', Path(tools['consumer']['root']),
                                       Path(tools['consumer']['input_receipt']), tools['consumer']['manifest_sha256'],
                                       output / 'consumer-composition')
        parent_observation = json.loads((output / 'checker-composition/parent.json').read_text())
        result['image_binding'] = describe_provider_binding(artifact, observed, parent_observation)
        if _source_digest() != source_sha:
            raise ValueError('controller source changed during composition')
        plan = local_checker_plan(profile, catalog['nodes'], checker['derived']['reference'], fixed)
        plan['public_file_planner'] = planner
        plan_path = output / 'frozen-plan.json'
        plan_path.write_text(json.dumps(plan, sort_keys=True, indent=2) + '\n')
        workspace = output / 'workspace'
        workspace.mkdir()
        with tempfile.TemporaryDirectory(prefix='p11lab-validation-credentials-') as private:
            secret_root = Path(private)
            for lane in ('checker', 'consumer'):
                for name in ('pin', 'so-pin'):
                    path = secret_root / (lane + '-' + name)
                    credential = secrets.token_hex(8)
                    sensitive_values.append(credential)
                    path.write_text(credential)
                    path.chmod(0o600)
            def inputs(lane):
                return {'P11LAB_PIN_FILE': str(secret_root / (lane + '-pin')),
                        'P11LAB_SO_PIN_FILE': str(secret_root / (lane + '-so-pin')), 'P11LAB_LABEL': 'P11Lab'}
            try:
                spec = RunSpec('softhsm2', 'release', 'direct', ArtifactRef(**checker['derived']),
                               'provider', None, None, (), inputs('checker'), output / 'checker-run',
                               workspace, 540, bounded=BoundedRunPolicy(), fixed_validation='checker')
                run_checker(spec, 'smoke-v1')
                reject_tainted_run(spec.output_dir / 'receipt.json')
                result['checker'] = check_checker_originals(spec.output_dir, profile['nodes'], checker['derived']['reference'],
                                                            'checker', observed['Config']['Entrypoint'], f'{os.getuid()}:{os.getgid()}')
                result['admission'] = admit_checker(Path(policy['evaluator']['root']), policy['evaluator']['receipt_sha256'],
                                                    spec.output_dir, plan_path, output / 'admission')
            except Exception as error:
                result['infrastructure_errors'].append('checker/admission: ' + type(error).__name__ + ': '
                                                       + redact_text(str(error), False, sensitive_values, safe_marker=True))
                if isinstance(error, (CredentialTaintError, CaptureUnavailableError)):
                    raise
                receipt_path = output / 'checker-run/receipt.json'
                try:
                    reject_tainted_run(receipt_path)
                except (CredentialTaintError, CaptureUnavailableError):
                    raise
                except GateCarrierError as carrier:
                    carrier_errors.append(carrier)
                    result['infrastructure_errors'].append('checker/admission: ' + type(carrier).__name__ + ': '
                                                           + redact_text(str(carrier), False, sensitive_values, safe_marker=True))
                try:
                    interrupted = receipt_path.is_file() and json.loads(receipt_path.read_bytes()).get('interrupted_signal')
                except (OSError, ValueError):
                    interrupted = False
                if interrupted:
                    raise InterruptedError('local validation interrupted') from error
            try:
                argv = ('p11lab-smoke', '--module', '/usr/local/lib/p11lab/libsofthsm2.so', '--token-label', 'P11Lab',
                        '--pin-file', '/run/p11lab-input/P11LAB_PIN_FILE', '--output', '/p11lab-output/crypto', '--key-mode', 'generated')
                spec = RunSpec('softhsm2', 'release', 'direct', ArtifactRef(**consumer['derived']),
                               'provider', None, None, argv, inputs('consumer'), output / 'consumer-run',
                               workspace, 120, bounded=BoundedRunPolicy(), fixed_validation='consumer')
                run = run_application(spec)
                reject_tainted_run(run.receipt_path)
                if run.exit_code or run.app_returncode != 0 or run.lifecycle_errors or run.cleanup_errors:
                    raise ValueError('consumer lifecycle or application incomplete')
                check_bounded_receipt(json.loads(run.receipt_path.read_bytes()))
                result['consumer'] = {'app_returncode': run.app_returncode, 'receipt': 'consumer-run/receipt.json'}
                result['oracle'] = verify_consumer_output(Path(tools['oracle']['root']), Path(tools['oracle']['input_receipt']),
                                                         tools['oracle']['manifest_sha256'], spec.output_dir / 'crypto', output / 'oracle',
                                                         scan_secrets=tuple(sensitive_values))
            except Exception as error:
                result['infrastructure_errors'].append('consumer/oracle: ' + type(error).__name__ + ': '
                                                       + redact_text(str(error), False, sensitive_values, safe_marker=True))
                if isinstance(error, (CredentialTaintError, CaptureUnavailableError)):
                    raise
                try:
                    reject_tainted_run(output / 'consumer-run/receipt.json')
                except (CredentialTaintError, CaptureUnavailableError):
                    raise
                except GateCarrierError as carrier:
                    carrier_errors.append(carrier)
                    result['infrastructure_errors'].append('consumer/oracle: ' + type(carrier).__name__ + ': '
                                                           + redact_text(str(carrier), False, sensitive_values, safe_marker=True))
        if _source_digest() != source_sha:
            raise ValueError('controller source changed during validation')
        if (not result['infrastructure_errors'] and result['checker'] is not None and result['consumer'] is not None
                and result['admission'] is not None and result['oracle'] is not None):
            result['status'] = 'observations-complete'
        export_gate = _gate_packaging(output, result, carrier_errors,
                                      images={'checker': checker['derived']['reference'],
                                              'consumer': consumer['derived']['reference']})
        result['sharing'] = 'local-evidence-package'
        result['export_gate'] = export_gate
        body = {key: value for key, value in result.items() if key != 'package'}
        _write_private_bytes(output / 'validation-body.json',
                             (json.dumps(body, sort_keys=True, indent=2) + '\n').encode())
        entries = _seal_gated_evidence(output, export_gate)
        _write_private_bytes(output / 'evidence-manifest.json',
                             (json.dumps({'files': entries}, sort_keys=True, indent=2) + '\n').encode())
        entries.append({'path': 'evidence-manifest.json', 'size': (output / 'evidence-manifest.json').stat().st_size,
                        'sha256': hashlib.sha256((output / 'evidence-manifest.json').read_bytes()).hexdigest()})
        result['package'] = _package_evidence(output, entries)
        result['body'] = {'path': 'validation-body.json', 'size': (output / 'validation-body.json').stat().st_size,
                          'sha256': hashlib.sha256((output / 'validation-body.json').read_bytes()).hexdigest()}
    except Exception as error:
        result['status'] = 'tainted' if isinstance(error, CredentialTaintError) else 'incomplete'
        if isinstance(error, CredentialTaintError):
            result['sharing'] = 'blocked-credential-taint'
        elif isinstance(error, CaptureUnavailableError):
            result['sharing'] = 'blocked-stream-capture-unavailable'
        elif isinstance(error, GateCarrierError):
            result['sharing'] = error.sharing
        elif isinstance(error, IncompleteEvidenceError):
            result['sharing'] = error.sharing
        result['infrastructure_errors'].append(type(error).__name__ + ': '
                                               + redact_text(str(error), False, sensitive_values, safe_marker=True))
    _write_private_bytes(output / 'validation.json',
                         (json.dumps(result, sort_keys=True, indent=2) + '\n').encode())
    return result


def _oracle_commands():
    environment = load_tool_input_lock('oracle', target='debian13-amd64')['execution']['environment']
    prefix = ['-i'] + [key + '=' + value for key, value in environment.items()]
    return {
        'positive': ('original', prefix + ['/usr/bin/python3.13', '-I', '/opt/p11lab-oracle/verify.py', '/crypto', '--openssl', '/usr/bin/openssl']),
        'altered_message': ('message', prefix + ['/usr/bin/openssl', 'dgst', '-sha256', '-verify', '/crypto/public-key.pem', '-signature', '/crypto/signature.der', '/crypto/altered.bin']),
        'altered_signature': ('signature', prefix + ['/usr/bin/python3.13', '-I', '/opt/p11lab-oracle/verify.py', '/crypto', '--openssl', '/usr/bin/openssl']),
    }


def verify_consumer_output(tool_dir: Path, receipt: Path, seal: str, crypto: Path, output: Path, *, scan_secrets=()) -> dict:
    """Verify only public C outputs in the separately sealed, isolated oracle.

    When the facade's live credentials are supplied, the oracle bind inputs
    are additionally scanned before the first container creation; the scan
    proof is sealed with the result. Replays without live secrets omit it.
    """
    require_nonroot()
    manifest = verify_tool_build(tool_dir, receipt_path=receipt, manifest_sha256=seal)
    if manifest.get('toolset') != 'oracle':
        raise ValueError('incorrect independent oracle role')
    names = ORACLE_BIND_NAMES
    crypto = Path(crypto)
    if crypto.is_symlink() or not crypto.is_dir() or {p.name for p in crypto.iterdir()} != set(names):
        raise ValueError('consumer public output roster incomplete')
    data = {}
    for name in names:
        path = crypto / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
            raise ValueError('unsafe consumer public output')
        data[name] = path.read_bytes()
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    for sub in ('original', 'message', 'signature'):
        directory = output / sub
        directory.mkdir(mode=0o755)
        for name, raw in data.items():
            (directory / name).write_bytes(raw)
    (output / 'message/altered.bin').write_bytes(data['message.bin'] + b'altered\n')
    signature = bytearray(data['signature.der'])
    if not signature:
        raise ValueError('empty consumer signature')
    signature[-1] ^= 1
    (output / 'signature/signature.der').write_bytes(signature)
    scan = scan_oracle_inputs(output, scan_secrets) if scan_secrets else None
    image = manifest['installed']['engine_id']
    engine = Docker()
    labels = {'org.p11lab.oracle': uuid4().hex}
    user = f'{os.getuid()}:{os.getgid()}'
    commands = _oracle_commands()
    result = {'image': image, 'external_manifest_sha256': seal, 'controls': {}, 'cleanup_errors': [],
              'public_outputs': {name: {'sha256': hashlib.sha256(raw).hexdigest(), 'size': len(raw)}
                                 for name, raw in data.items()}}
    if scan is not None:
        result['scan'] = scan
    try:
        for name, (directory, command) in commands.items():
            mount = f'type=bind,src={(output / directory).resolve()},dst=/crypto,readonly'
            options = _options(readonly=True, user=user) + ['--mount', mount]
            control = {'argv': command, 'mount': mount}
            result['controls'][name] = control
            identity = None
            try:
                try:
                    identity = engine.create(image, command, options, labels, 'p11lab-oracle-' + labels['org.p11lab.oracle'] + '-' + name)
                except DockerError as error:
                    if error.resource and error.resource[0] == 'container':
                        identity = error.resource[1]
                    if error.uncertain_resource:
                        result['cleanup_errors'].append('oracle creation status unknown')
                    raise
                observed = json.loads(engine.command(['container', 'inspect', identity]).stdout)[0]
                verify_execution_boundary(observed, image, command, [mount], readonly=True, user=user)
                control.update(container_id=identity, inspection_before=observed)
                native = engine.execute(identity, 30, lambda: None)
                control.update(asdict(native))
                control['inspection_after'] = json.loads(engine.command(['container', 'inspect', identity]).stdout)[0]
            finally:
                if identity:
                    try:
                        engine.remove('container', identity, labels)
                        control['cleanup'] = 'removed-exact-owned-container'
                    except (DockerError, OSError, ValueError):
                        result['cleanup_errors'].append(name + ' cleanup failed')
    finally:
        (output / 'oracle.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    check_oracle_results(result['controls'])
    if result['cleanup_errors']:
        raise ValueError('oracle cleanup incomplete')
    return result


def check_evidence_roster(entries, selected_count):
    """Require the complete fixed local evidence roster, including the sealed validation body and per-node records."""
    common = {'child-inspection.json', 'child-metadata.json', 'child.json',
              'composition-transfer.stderr', 'composition.json', 'composition.tar',
              'parent-inspection.json', 'parent-metadata.json', 'parent.json'}
    phases = {phase + suffix for phase in ('init', 'ready', 'application', 'post-health')
              for suffix in ('.stdout.log', '.stderr.log')}
    names = {'frozen-plan.json', 'catalog/catalog.json', 'evidence-manifest.json', 'validation-body.json'}
    names |= {'admission/' + x for x in ('admission.json', 'evaluator.stderr.log',
             'evaluator.stdout.log', 'ledger.jsonl', 'process.json')}
    for lane in ('checker', 'consumer'):
        names |= {lane + '-composition/' + x for x in common}
        names |= {lane + '-run/' + x for x in phases | {'receipt.json', 'bounded-output.tar'}}
    originals = {'build-provenance.json', 'checker-receipt.json', 'checker.stderr.log',
                 'checker.stdout.log', 'collection.json', 'collection.stderr.log',
                 'collection.stdout.log'}
    for stem in ('coverage.json', 'provisioning.json', 'quality.json', 'report.jsonl',
                 'results.json', 'state.json'):
        originals |= {stem, stem + '.lock'}
    names |= {'checker-run/checker/' + x for x in originals}
    crypto = {'public-key.pem', 'public-key.der', 'message.bin', 'digest.bin',
              'signature.raw', 'signature.der', 'result.json'}
    names |= {'consumer-run/crypto/' + x for x in crypto}
    names |= {'oracle/oracle.json', 'oracle/message/altered.bin'}
    names |= {'oracle/' + directory + '/' + x
              for directory in ('original', 'message', 'signature') for x in crypto}
    names |= {'planning/' + x for x in ('planner.json', 'planner.stderr.log',
             'planner.stdout.json', 'process.json')}
    profile = load_profile()
    names |= {'planning/source-view/' + x for x in profile['sources']}
    actual = set(entries)
    records = actual - names
    pattern = r'checker-run/checker/\.state\.json\.report-records/[0-9a-f]{64}\.jsonl'
    if (not names <= actual or len(records) != selected_count
            or any(not re.fullmatch(pattern, name) for name in records)):
        raise ValueError('fixed validation evidence roster incomplete or unexpected')


def check_frozen_plan(plan, profile, catalog, image, fixed, planner):
    expected = local_checker_plan(profile, catalog, image, fixed)
    expected['public_file_planner'] = planner
    if plan != expected:
        raise ValueError('frozen checker plan mismatch')


def check_checker_reconciliation(actual, retained, checker):
    if (actual != retained or actual.get('complete') is not True
            or actual.get('observations_complete') is not True or actual.get('errors') != []
            or actual.get('summary') != checker.get('summary')):
        raise ValueError('checker raw evidence reconciliation disagrees with retained summary')


def replay_checker_reconciliation(image, checker_output, nodes, journal):
    """Run the existing checker adapter in the verified checker tool image.

    This adapter uses version-gated private upstream APIs; the separate sealed
    evaluator admission remains the public checker evidence interface.
    """
    require_nonroot()
    controller = Path(__file__).parent.resolve(strict=True)
    checker_output = Path(checker_output).resolve(strict=True)
    mounts = [f'type=bind,src={controller},dst=/p11lab,readonly',
              f'type=bind,src={checker_output},dst=/evidence,readonly']
    script = ('import json,sys; from pathlib import Path; sys.path.insert(0,"/"); '
              'from p11lab.checker import validate_results; '
              'print(json.dumps(validate_results(Path("/evidence"),json.loads(sys.argv[1]),'
              'Path("/opt/p11lab-checker/lib/python3.13/site-packages/pkcs11_check/testcases")),sort_keys=True))')
    command = ['-i', 'PATH=/usr/bin:/bin', 'HOME=/tmp', 'LC_ALL=C.UTF-8', 'PYTHONDONTWRITEBYTECODE=1',
               '/opt/p11lab-checker/bin/python', '-I', '-B', '-c', script, json.dumps(nodes, separators=(',', ':'))]
    user = f'{os.getuid()}:{os.getgid()}'
    options = _options(readonly=True, user=user)
    for mount in mounts:
        options += ['--mount', mount]
    engine = Docker()
    labels = {'org.p11lab.evidence-replay': uuid4().hex}
    record = {'image': image, 'container_id': None, 'cleanup': 'not-created'}
    identity = None
    try:
        try:
            identity = engine.create(image, command, options, labels,
                                     'p11lab-evidence-replay-' + labels['org.p11lab.evidence-replay'])
        except DockerError as error:
            if error.resource and error.resource[0] == 'container':
                identity = error.resource[1]
            if error.uncertain_resource:
                record['cleanup'] = 'creation-uncertain'
            record['container_id'] = identity
            raise
        record['container_id'] = identity
        before = json.loads(engine.command(['container', 'inspect', identity]).stdout)[0]
        record['inspection_before'] = before
        verify_execution_boundary(before, image, command, mounts, readonly=True, user=user)
        result = engine.execute(identity, 120, lambda: None)
        after = json.loads(engine.command(['container', 'inspect', identity]).stdout)[0]
        record['inspection_after'] = after
        record.update(returncode=result.returncode, timed_out=result.timed_out,
                      stdout_truncated=result.stdout_truncated, stderr_truncated=result.stderr_truncated,
                      stdout_sha256=hashlib.sha256(result.stdout.encode()).hexdigest(),
                      stderr_sha256=hashlib.sha256(result.stderr.encode()).hexdigest(),
                      stopped=after.get('Id') == identity and after.get('State', {}).get('Running') is False
                      and after.get('State', {}).get('Pid') == 0)
        if (result.returncode != 0 or result.timed_out is not False or result.stdout_truncated is not False
                or result.stderr_truncated is not False or record['stopped'] is not True):
            raise ValueError('checker raw evidence replay incomplete')
        from .jsonutil import loads
        return loads(result.stdout)
    finally:
        try:
            if identity:
                try:
                    engine.remove('container', identity, labels)
                    record['cleanup'] = 'removed-exact-owned-container'
                except (DockerError, OSError, ValueError):
                    record['cleanup'] = 'failed'
                    raise
        finally:
            Path(journal).write_text(json.dumps(record, sort_keys=True, indent=2) + '\n')


def check_evidence_policy(value, policy, *, replay_binding=None):
    _local_policy(policy)
    tools = policy['tools']
    expected_seal = policy['evaluator']['receipt_sha256']
    if replay_binding is not None:
        from .round_core.evaluator_replay import EvaluatorReplayBinding
        if type(replay_binding) is not EvaluatorReplayBinding:
            raise TypeError('typed evaluator replay binding required')
        binding = replay_binding.as_dict()
        if (binding['current_receipt_sha256'] != expected_seal
                or Path(binding['current_root']) != Path(policy['evaluator']['root']).resolve()):
            raise ValueError('evaluator replay binding policy mismatch')
        expected_seal = binding['original_receipt_sha256']
    if (value['tool_manifest_sha256'] != {name: row['manifest_sha256'] for name, row in tools.items()}
            or value['evaluator_receipt_sha256'] != expected_seal
            or value['control_base_revision_declared'] != policy['control_base_revision']
            or value['scope'] != 'local-only' or value['authority'] != 'local-unauthenticated'
            or value['comparison'] is not None or value['promotable'] is not False
            or value['qualification_eligible'] is not False):
        raise ValueError('local validation tool policy mismatch')


def check_captured_output(captured, packaged, subtree):
    """Bind every captured output file and directory to the packaged subtree."""
    import stat

    if subtree not in ('checker', 'crypto'):
        raise ValueError('unsupported captured output subtree')
    captured, packaged = Path(captured), Path(packaged)
    expected_root = packaged / subtree

    def tree(root, prefix):
        status = root.lstat()
        if not stat.S_ISDIR(status.st_mode):
            raise ValueError('unsafe captured output directory')
        files, directories = {}, set()
        if prefix:
            directories.add(prefix)
        for path in root.rglob('*'):
            status = path.lstat()
            name = '/'.join(filter(None, (prefix, path.relative_to(root).as_posix())))
            if stat.S_ISDIR(status.st_mode):
                directories.add(name)
            elif stat.S_ISREG(status.st_mode) and status.st_nlink == 1:
                files[name] = (path, status.st_size)
            else:
                raise ValueError('unsafe captured output member')
        return files, directories

    try:
        expected, expected_dirs = tree(expected_root, subtree)
        actual, actual_dirs = tree(captured, '')
    except OSError as error:
        raise ValueError('captured output subtree missing or unreadable') from error
    if not expected or set(actual) != set(expected) or actual_dirs != expected_dirs:
        raise ValueError('captured output roster differs from packaged originals')
    for name, (path, size) in actual.items():
        other, other_size = expected[name]
        if size != other_size:
            raise ValueError('captured output differs from bounded readback')
        with path.open('rb') as left, other.open('rb') as right:
            if hashlib.file_digest(left, 'sha256').digest() != hashlib.file_digest(right, 'sha256').digest():
                raise ValueError('captured output differs from bounded readback')


def _require_normalized_member(member):
    if member.mode != 0o600 or member.uid != 0 or member.gid != 0 or member.mtime != 0:
        raise ValueError('validation snapshot member not normalized (mode/owner/mtime)')


def _extract_snapshot_member(*, snapshot, secured, member, source, expected):
    snapshot = Path(snapshot)
    parent = (snapshot / member.name).parent
    parent.mkdir(parents=True, exist_ok=True)
    node = parent
    while node != snapshot and node not in secured:
        os.chmod(node, 0o700)
        secured.add(node)
        node = node.parent
    if source is None:
        raise ValueError('validation snapshot member unreadable')
    digest, size = hashlib.sha256(), 0
    fd = os.open(snapshot / member.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.fchmod(fd, 0o600)
        stream = os.fdopen(fd, 'wb')
    except BaseException:
        os.close(fd)
        raise
    with stream:
        while block := source.read(1024 * 1024):
            size += len(block)
            if size > expected['size']:
                raise ValueError('validation snapshot grew')
            digest.update(block)
            stream.write(block)
    if size != expected['size'] or digest.hexdigest() != expected['sha256']:
        raise ValueError('validation snapshot member changed')


def _assert_snapshot_modes(snapshot):
    import stat
    snapshot = Path(snapshot)
    for path in sorted(snapshot.rglob('*')):
        status = path.lstat()
        if stat.S_ISLNK(status.st_mode):
            raise ValueError('validation snapshot contains symlink')
        if stat.S_ISDIR(status.st_mode):
            expected = 0o700
        elif stat.S_ISREG(status.st_mode):
            expected = 0o600
        else:
            raise ValueError('validation snapshot contains non-regular file')
        if stat.S_IMODE(status.st_mode) != expected:
            raise ValueError('validation snapshot mode mismatch')


def verify_evidence_package(archive, observed, value, artifact, policy, journal_dir=None, *, replay_binding=None):
    """Recompute the fixed N1 result from a contained immutable package snapshot.

    The value is the enclosed validation body supplied by the light verifier,
    never the envelope: it must not carry package or body seal records.
    """
    from .jsonutil import loads

    if replay_binding is not None:
        from .round_core.evaluator_replay import EvaluatorReplayBinding
        if type(replay_binding) is not EvaluatorReplayBinding:
            raise TypeError('typed evaluator replay binding required')
    if 'package' in value or 'body' in value:
        raise ValueError('enclosed validation body required')
    require_export_gate(value)
    if (value.get('status') != 'observations-complete' or value.get('infrastructure_errors')
            or value.get('sharing') != 'local-evidence-package'):
        if not _shareable_incomplete(value):
            raise ValueError('gate-1 shareable roster refuses incomplete evidence')
    policy = json.loads(json.dumps(policy))
    check_evidence_policy(value, policy, replay_binding=replay_binding)
    binding = replay_binding.as_dict() if replay_binding is not None else None
    tools = policy['tools']
    products = {}
    for name, item in tools.items():
        products[name] = verify_tool_build(Path(item['root']), receipt_path=Path(item['input_receipt']),
                                           manifest_sha256=item['manifest_sha256'])
        if products[name]['toolset'] != name:
            raise ValueError('local validation tool role mismatch')
    evaluator = Path(policy['evaluator']['root'])
    seal = policy['evaluator']['receipt_sha256']
    original_seal = binding['original_receipt_sha256'] if binding is not None else seal
    verify_evaluator(evaluator, seal)
    profile = load_profile()
    fixed_path = Path(__file__).parent / 'data/ci/delivery/validation-policy.json'
    fixed = json.loads(fixed_path.read_bytes())
    if (value['fixed_policy_sha256'] != hashlib.sha256(fixed_path.read_bytes()).hexdigest()
            or value['profile_sha256'] != hashlib.sha256((Path(__file__).parent / 'data/profiles/smoke-v1.json').read_bytes()).hexdigest()
            or value['checker_source_files'] != profile['sources']):
        raise ValueError('fixed validation policy or profile mismatch')
    with tempfile.TemporaryDirectory(prefix='p11lab-validation-verification-') as temporary:
        base = Path(temporary)
        journal_root = Path(journal_dir) if journal_dir is not None else base / 'journals'
        protected = [Path(item['root']).resolve(strict=True) for item in tools.values()]
        protected += [evaluator.resolve(strict=True), Path(__file__).parent.resolve(strict=True),
                      Path(archive).parent.resolve(strict=True)]
        target = journal_root.resolve()
        if any(target.is_relative_to(root) or root.is_relative_to(target) for root in protected):
            raise ValueError('validation replay journal overlaps a protected input')
        journal_root.mkdir(parents=True, exist_ok=False)
        snapshot = base / 'snapshot'
        snapshot.mkdir(mode=0o700)
        os.chmod(snapshot, 0o700)
        secured = {snapshot}
        remaining = set(observed)
        with tarfile.open(archive, 'r|gz') as bundle:
            for member in bundle:
                if member.name not in remaining or not member.isfile():
                    raise ValueError('validation snapshot roster changed')
                remaining.remove(member.name)
                _require_normalized_member(member)
                _extract_snapshot_member(snapshot=snapshot, secured=secured, member=member,
                                         source=bundle.extractfile(member),
                                         expected=observed[member.name])
        if remaining:
            raise ValueError('validation snapshot incomplete')
        _assert_snapshot_modes(snapshot)
        try:
            packaged_body = (snapshot / 'validation-body.json').read_bytes()
        except OSError as error:
            raise ValueError('validation snapshot body missing') from error
        check_body_binding(value, packaged_body)
        if binding is not None:
            from .round_core.evaluator_replay import _input_identity
            if (_input_identity(snapshot / 'checker-run/checker/report.jsonl') != binding['raw']
                    or _input_identity(snapshot / 'frozen-plan.json') != binding['plan']
                    or _input_identity(snapshot / 'admission/ledger.jsonl') != binding['ledger']):
                raise ValueError('evaluator replay binding differs from original evidence')
        def read(name):
            return loads((snapshot / name).read_bytes())
        compositions = {}
        for name in ('checker', 'consumer'):
            prefix = name + '-composition/'
            comp = read(prefix + 'composition.json')
            parent, child = read(prefix + 'parent.json'), read(prefix + 'child.json')
            before, after = read(prefix + 'parent-metadata.json'), read(prefix + 'child-metadata.json')
            derived = ArtifactRef(**comp['derived'])
            if (comp['tool'] != name or comp['parent'] != asdict(artifact)
                    or parent['artifact'] != asdict(artifact) or child['artifact'] != asdict(derived)
                    or comp['parent_observation']['Id'] != artifact.reference
                    or comp['derived_observation']['Id'] != derived.reference
                    or not re.fullmatch('[0-9a-f]{64}', comp['source_container_id'])
                    or comp['source_inspection']['Id'] != comp['source_container_id']
                    or comp['source_inspection']['Image'] != artifact.reference
                    or comp['source_inspection']['State']['Running'] is not False
                    or derived.kind != 'docker-local' or derived.reference != 'sha256:' + derived.sha256
                    or derived.platform != artifact.platform or comp['cleanup_errors'] != []
                    or comp['source_cleanup'] != 'removed-exact-owned-container'
                    or comp['parent_metadata_preserved'] is not True
                    or comp['derived_observation']['RootFS']['Layers'][:len(comp['parent_observation']['RootFS']['Layers'])]
                    != comp['parent_observation']['RootFS']['Layers']):
                raise ValueError('validation composition identity or cleanup mismatch')
            transfers = comp['rootfs_transfers']
            if (len(transfers) != 3 or transfers[0]['role'] != 'parent-export'
                    or transfers[2]['role'] != 'child-export'
                    or any(item['record']['returncode'] != 0 or item['record']['timed_out'] is not False
                           or item['record']['overflow'] is not False or item['record']['stderr_truncated'] is not False
                           for item in (transfers[0], transfers[2]))
                    or transfers[1]['returncode'] != 0 or transfers[1]['stderr_truncated'] is not False):
                raise ValueError('validation composition transfer incomplete')
            verify_parent_metadata(before, after)
            verify_composition(parent, child, comp['copy_files'])
            current_child = inspect_artifact(derived, inspection_policy=InspectionPolicy(),
                                             journal_path=journal_root / (name + '-child-inspection.json'))
            if current_child != child:
                raise ValueError('validation child inspection differs from retained composition')
            if name == 'checker':
                expected, closure = _stage_checker(Path(tools[name]['root']), parent, base / 'checker-composition.tar')
                if expected != comp['copy_files'] or closure != comp['elf_closure']:
                    raise ValueError('checker composition does not match sealed tool and controller')
            else:
                spec = products[name]['products'][0]
                expected = {'usr/local/bin/p11lab-smoke': {'kind': 'file', 'sha256': spec['sha256'],
                            'size': spec['size'], 'mode': 0o755}}
                if comp['copy_files'] != expected:
                    raise ValueError('consumer composition does not match sealed tool')
            if (value['image_observation'] != comp['parent_observation']
                    or value['image_binding'] != describe_provider_binding(artifact, value['image_observation'], parent)):
                raise ValueError('validation composition parent differs from candidate observation')
            compositions[name] = comp
        checker_image = compositions['checker']['derived']['reference']
        catalog = read('catalog/catalog.json')
        native = catalog['native']
        testcase_root = '/opt/p11lab-checker/lib/python3.13/site-packages/pkcs11_check/testcases'
        catalog_command = ['-i', 'PATH=/usr/bin:/bin', 'HOME=/tmp', 'LC_ALL=C.UTF-8',
                           'PYTHONDONTWRITEBYTECODE=1', 'PYTEST_DISABLE_PLUGIN_AUTOLOAD=1', 'PYTEST_ADDOPTS=-v',
                           '/opt/p11lab-checker/bin/python', '-m', 'pkcs11_check', 'list-tests', '--include-disabled']
        catalog_command += [testcase_root + '/' + name for name in sorted(fixed['catalog_counts'])]
        if (catalog['external_manifest_sha256'] != tools['checker']['manifest_sha256']
                or catalog['image'] != products['checker']['installed']['engine_id']
                or catalog['command'] != catalog_command
                or catalog['inspection_before']['Id'] != catalog['container_id']
                or catalog['inspection_after']['Id'] != catalog['container_id']
                or catalog['cleanup'] != 'removed-exact-owned-container' or catalog['cleanup_errors'] != []
                or native['returncode'] != 0 or native['timed_out'] is not False or native['stdout_truncated'] is not False
                or native['stderr_truncated'] is not False or native['stdout'].splitlines() != catalog['nodes']
                or catalog['inspection_after']['State']['Running'] is not False
                or catalog['inspection_after']['State']['Pid'] != 0):
            raise ValueError('checker catalog execution incomplete')
        verify_execution_boundary(catalog['inspection_before'], catalog['image'], catalog['command'], [],
                                  readonly=True, user='65532:65532')
        check_catalog(catalog['nodes'], profile['nodes'], fixed['catalog_counts'])
        catalog_replay = collect_checker_catalog(Path(tools['checker']['root']), Path(tools['checker']['input_receipt']),
                                                 tools['checker']['manifest_sha256'], journal_root / 'catalog-replay')
        if catalog_replay['nodes'] != catalog['nodes']:
            raise ValueError('checker catalog replay disagrees with retained catalog')
        planner = read('planning/planner.json')
        process = read('planning/process.json')
        stdout = (snapshot / 'planning/planner.stdout.json').read_bytes()
        view = Path(process['argv'][-3])
        names = check_public_shard_plan(loads(stdout), view, set(profile['sources']))
        original = evaluator / 'evaluator-install/lib/python3.12/site-packages/pkcs11_check/testcases'
        source_sha = {name: hashlib.sha256((original / name).read_bytes()).hexdigest() for name in names}
        if (process['returncode'] != 0 or process['timed_out'] is not False or process['stdout_truncated'] is not False
                or process['stderr_truncated'] is not False or process['supervision_errors'] != [] or process['stragglers_remaining'] != []
                or process['drain_complete'] is not True or planner['files'] != names
                or planner['evaluator_receipt_sha256'] != original_seal or planner['evaluator_source_sha256'] != source_sha
                or planner['stdout_sha256'] != hashlib.sha256(stdout).hexdigest()
                or any(hashlib.sha256((snapshot / 'planning/source-view' / name).read_bytes()).hexdigest() != digest
                       for name, digest in source_sha.items())):
            raise ValueError('public planner evidence mismatch')
        if binding is None:
            replanned = plan_checker_shard(evaluator, seal, set(profile['sources']), journal_root / 'planner-replay')
        else:
            replanned = plan_checker_shard(evaluator, seal, set(profile['sources']), journal_root / 'planner-replay',
                                           runtime_journal=journal_root / 'planner-runtime.json')
            from .round_core.evaluator_replay import _runtime_projection
            from .delivery_authority import _read_bounded_file
            runtime = loads(_read_bounded_file(journal_root / 'planner-runtime.json', 2 * 1024 * 1024))
            if _runtime_projection(runtime, 'planner', evaluator) != _runtime_projection(binding['current_runtime']['planner'], 'planner', evaluator):
                raise ValueError('current planner runtime differs from replay binding')
        if (replanned['files'] != planner['files']
                or replanned['evaluator_source_sha256'] != planner['evaluator_source_sha256']
                or replanned['evaluator_receipt_sha256'] != seal):
            raise ValueError('public planner replay disagrees with retained plan')
        plan = read('frozen-plan.json')
        check_frozen_plan(plan, profile, catalog['nodes'], checker_image, fixed, planner)
        from .bounded_run import retain_output
        for lane in ('checker', 'consumer'):
            receipt = read(lane + '-run/receipt.json')
            if (receipt['environment'] != 'softhsm2' or receipt['channel'] != 'release'
                    or receipt['mode'] != 'direct' or receipt['uncertain_resources'] != []
                    or not re.fullmatch('[0-9a-f]{32}', receipt['attempt_id'])):
                raise ValueError('validation attempt identity or resource ownership mismatch')
            reject_tainted_run(snapshot / (lane + '-run/receipt.json'))
            data = (snapshot / (lane + '-run/bounded-output.tar')).read_bytes()
            record = receipt['bounded_execution']['output']['readback']
            if (record['sha256'] != hashlib.sha256(data).hexdigest() or record['size'] != len(data)
                    or record['returncode'] != 0 or record['timed_out'] is not False or record['tainted'] is not False
                    or record['stdout_truncated'] is not False or record['stderr_truncated'] is not False
                    or record['supervision_errors'] != [] or record['stragglers_remaining'] != []
                    or record['drain_complete'] is not True):
                raise ValueError('bounded output readback incomplete')
            lane_image = checker_image if lane == 'checker' else compositions['consumer']['derived']['reference']
            check_gate_admission(receipt, lane=lane, image=lane_image, basis=value['export_gate']['basis'],
                                 fixed=(lane, value['image_observation']['Config']['Entrypoint'],
                                        f'{os.getuid()}:{os.getgid()}'),
                                 tar_bytes=data)
            retained = base / (lane + '-readback')
            retained.mkdir()
            retain_output(data, retained, receipt['bounded_policy']['output_bytes'], 10000)
            check_captured_output(retained, snapshot / (lane + '-run'),
                                  'checker' if lane == 'checker' else 'crypto')
        if read('checker-run/receipt.json')['attempt_id'] == read('consumer-run/receipt.json')['attempt_id']:
            raise ValueError('checker and consumer attempts must be independent')
        completed = _scan_completion({'checker': read('checker-run/receipt.json'),
                                      'consumer': read('consumer-run/receipt.json')})
        if (value['export_gate']['basis'].get('scan_completion') != completed
                or any(not row['clean'] for row in completed)):
            raise ValueError('gate-1 scan completion proof mismatch')
        inner = read('checker-run/checker/checker-receipt.json')
        read('checker-run/checker/collection.json')
        read('checker-run/checker/state.json')
        if (not re.fullmatch('[0-9a-f]{32}', inner['attempt_id'])
                or inner['attempt_id'] in {read('checker-run/receipt.json')['attempt_id'],
                                           read('consumer-run/receipt.json')['attempt_id']}
                or inner['checker']['source_revision'] != fixed['checker_revision']
                or inner['checker']['wheel_sha256'] != fixed['checker_wheel_sha256']
                or inner['checker']['runtime_lock_sha256'] != fixed['checker_runtime_lock_sha256']
                or {name: row['sha256'] for name, row in inner['sources'].items()} != profile['sources']
                or inner['logs_truncated'] != {'checker.stdout.log': False, 'checker.stderr.log': False}
                or inner['supervision']['stdout_truncated'] is not False
                or inner['supervision']['stderr_truncated'] is not False
                or inner['supervision']['drain_complete'] is not True
                or inner['supervision']['supervision_errors'] != []
                or inner['supervision']['stragglers_remaining'] != []):
            raise ValueError('checker installed source identity mismatch')
        entrypoint = value['image_observation']['Config']['Entrypoint']
        user = f'{os.getuid()}:{os.getgid()}'
        checker = check_checker_originals(snapshot / 'checker-run', profile['nodes'], checker_image,
                                          'checker', entrypoint, user)
        if checker != value['checker'] or read('checker-run/checker/results.json')['summary'] != checker['summary']:
            raise ValueError('checker summary does not match originals')
        reconciled = replay_checker_reconciliation(products['checker']['installed']['engine_id'],
                                                    snapshot / 'checker-run/checker', profile['nodes'],
                                                    journal_root / 'checker-replay.json')
        check_checker_reconciliation(reconciled, inner['evidence'], checker)
        replay_dir = journal_root / 'admission-replay'
        if binding is None:
            replay = admit_checker(evaluator, seal, snapshot / 'checker-run', snapshot / 'frozen-plan.json', replay_dir)
        else:
            replay = admit_checker(evaluator, seal, snapshot / 'checker-run', snapshot / 'frozen-plan.json', replay_dir,
                                   runtime_journal=journal_root / 'admission-runtime.json')
            runtime = loads(_read_bounded_file(journal_root / 'admission-runtime.json', 2 * 1024 * 1024))
            if _runtime_projection(runtime, 'admission', evaluator) != _runtime_projection(binding['current_runtime']['admission'], 'admission', evaluator):
                raise ValueError('current admission runtime differs from replay binding')
        if (replay != value['admission'] or replay != read('admission/admission.json')
                or (replay_dir / 'ledger.jsonl').read_bytes() != (snapshot / 'admission/ledger.jsonl').read_bytes()
                or loads((snapshot / 'admission/evaluator.stdout.log').read_bytes()) != replay):
            raise ValueError('public evaluator replay disagrees with retained admission')
        process = read('admission/process.json')
        if (process['returncode'] != 0 or process['timed_out'] is not False or process['stdout_truncated'] is not False
                or process['stderr_truncated'] is not False or process['supervision_errors'] != [] or process['stragglers_remaining'] != []
                or process['drain_complete'] is not True):
            raise ValueError('retained evaluator supervision incomplete')
        receipt = read('consumer-run/receipt.json')
        check_bounded_receipt(receipt)
        check_attempt_stage_identities(receipt, compositions['consumer']['derived']['reference'],
                                       'consumer', entrypoint, user)
        stages = receipt['stages']
        if (receipt['artifacts']['provider'] != compositions['consumer']['derived']
                or receipt['app_completed'] is not True or receipt['app_returncode'] != 0 or receipt['exit_code'] != 0
                or receipt['timeout'] is not False or receipt['interrupted_signal'] is not None
                or receipt['lifecycle_errors'] != [] or receipt['cleanup_errors'] != []
                or receipt['uncertain_resources'] != []
                or [row['phase'] for row in stages] != ['init', 'ready', 'application', 'post-health']
                or any(row['returncode'] != 0 or row['timed_out'] is not False or row['stdout_truncated'] is not False
                       or row['stderr_truncated'] is not False for row in stages)
                or value['consumer'] != {'app_returncode': 0, 'receipt': 'consumer-run/receipt.json'}):
            raise ValueError('consumer lifecycle or summary mismatch')
        saved = read('oracle/oracle.json')
        if saved != value['oracle'] or saved['image'] != products['oracle']['installed']['engine_id'] or saved['external_manifest_sha256'] != tools['oracle']['manifest_sha256'] or saved['cleanup_errors'] != []:
            raise ValueError('oracle identity or summary mismatch')
        check_oracle_results(saved['controls'])
        check_oracle_scan_binding(snapshot / 'oracle', saved.get('scan'),
                                  value['export_gate']['basis'].get('oracle_inputs'))
        commands = _oracle_commands()
        for name, row in saved['controls'].items():
            directory, command = commands[name]
            mount = row['mount']
            if (row['argv'] != command or row['inspection_before']['Config']['User'] != f'{os.getuid()}:{os.getgid()}'
                    or not mount.startswith('type=bind,src=/') or not mount.endswith('/' + directory + ',dst=/crypto,readonly')):
                raise ValueError('retained oracle command or read-only input mismatch')
            verify_execution_boundary(row['inspection_before'], saved['image'], row['argv'], [row['mount']],
                                      readonly=True, user=f'{os.getuid()}:{os.getgid()}')
        for directory in ('original', 'message', 'signature'):
            for filename in saved['public_outputs']:
                original = (snapshot / 'consumer-run/crypto' / filename).read_bytes()
                actual = (snapshot / 'oracle' / directory / filename).read_bytes()
                if directory == 'signature' and filename == 'signature.der':
                    altered = bytearray(original)
                    if not altered:
                        raise ValueError('empty oracle signature')
                    altered[-1] ^= 1
                    original = bytes(altered)
                if original != actual:
                    raise ValueError('retained oracle input differs from consumer output')
        if (snapshot / 'oracle/message/altered.bin').read_bytes() != (snapshot / 'consumer-run/crypto/message.bin').read_bytes() + b'altered\n':
            raise ValueError('retained oracle altered message mismatch')
        oracle_output = base / 'oracle-replay'
        try:
            fresh = verify_consumer_output(Path(tools['oracle']['root']), Path(tools['oracle']['input_receipt']),
                                           tools['oracle']['manifest_sha256'], snapshot / 'consumer-run/crypto', oracle_output)
        finally:
            oracle_journal = oracle_output / 'oracle.json'
            if oracle_journal.is_file() and not oracle_journal.is_symlink():
                (journal_root / 'oracle-replay.json').write_bytes(oracle_journal.read_bytes())
        if (fresh['public_outputs'] != saved['public_outputs']
                or any(fresh['controls'][name]['returncode'] != row['returncode']
                       for name, row in saved['controls'].items())):
            raise ValueError('oracle replay disagrees with retained public output')
        for name, item in tools.items():
            if verify_tool_build(Path(item['root']), receipt_path=Path(item['input_receipt']),
                                 manifest_sha256=item['manifest_sha256']) != products[name]:
                raise ValueError('sealed validation tool changed during verification')
        verify_evaluator(evaluator, seal)
        if _source_digest() != value['control_source_sha256']:
            raise ValueError('controller changed during evidence verification')
        before = {entry['path']: entry for entry in _seal_gated_evidence(snapshot, value['export_gate'])}
        if before != observed:
            raise ValueError('validation evidence changed during verification')
