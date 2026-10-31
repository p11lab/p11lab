"""Closed inert transport roster for image qualification custody.

This module does not grant source rights, producer authority or qualification.
"""
import re
import hashlib
import os
import stat
import tarfile
import time
from dataclasses import dataclass
from pathlib import Path

from .round_core.inputs import CUSTODY_MEMBER_LIMIT, CUSTODY_TOTAL_LIMIT, CUSTODY_ZIP_LIMIT, canonical, extract_custody_archive, load_json

SEGMENT_ROLES = ('image', 'validation', 'source-records', 'evaluator-original',
                 'checker-tool', 'consumer-tool', 'oracle-tool', 'tool-inputs')
SEGMENT_FILES = {
    'image': ('image.tar',),
    'validation': ('validation.json', 'package.tar.gz'),
    'source-records': ('build-receipt.json', 'sealed-source.json', 'source-companion.json', 'sbom.spdx.json',
                       'source-context.json', 'source-bundle.json', 'source-admission.json',
                       'seal-readback-proof.json', 'content-readback-proof.json',
                       'seal-oci-manifest.json', 'seal-transport-journal.json',
                       'content-oci-manifest.json', 'content-transport-journal.json', 'component-rights.tar.gz'),
    'evaluator-original': ('evaluator-build-receipt.json',),
    'checker-tool': ('tool-root.tar.gz', 'installed-image.tar.gz', 'derived-image.tar.gz'),
    'consumer-tool': ('tool-root.tar.gz', 'installed-image.tar.gz', 'derived-image.tar.gz'),
    'oracle-tool': ('tool-root.tar.gz', 'installed-image.tar.gz'),
    'tool-inputs': ('checker-inputs.tar.gz', 'consumer-inputs.tar.gz', 'oracle-inputs.tar.gz'),
}
COMPONENTS = {
    'evaluator-original': 'custody-evaluator-metadata', 'checker-root': 'custody-tree',
    'consumer-root': 'custody-tree', 'oracle-root': 'custody-tree',
    'checker-inputs': 'custody-tree', 'consumer-inputs': 'custody-tree',
    'oracle-inputs': 'custody-tree',
    'checker-image': 'docker-local', 'checker-derived': 'docker-local',
    'consumer-image': 'docker-local', 'consumer-derived': 'docker-local',
    'oracle-image': 'docker-local',
}
_BYTES_KEY = object()
_PRODUCER_KEY = object()
_IMAGE_KEY = object()
_LOADED_KEY = object()
_PAYLOAD_KEY = object()
_SOURCE_REPLAY_KEY = object()
_TAR_METADATA_RECORD_LIMIT = 8 * 1024 * 1024
_TAR_METADATA_TOTAL_LIMIT = 64 * 1024 * 1024
_TAR_STREAM_LIMIT = 1024**3
_TAR_HEADER_LIMIT = 200000


class _BoundedTarReader:
    def __init__(self, source):
        self.source, self.total = source, 0
        self.deadline = time.monotonic() + 120

    def read(self, size):
        if type(size) is not int or size < 0 or time.monotonic() > self.deadline:
            raise ValueError('custody tar stream deadline or read bound')
        block = self.source.read(min(size, _TAR_STREAM_LIMIT + 1 - self.total))
        self.total += len(block)
        if self.total > _TAR_STREAM_LIMIT or time.monotonic() > self.deadline:
            raise ValueError('custody tar stream byte or deadline bound')
        return block


class _TarPrefix:
    def __init__(self, source, prefix):
        self.source, self.prefix = source, prefix

    def read(self, size):
        head, self.prefix = self.prefix[:size], self.prefix[size:]
        return head + self.source.read(size - len(head)) if len(head) < size else head

    def tell(self):
        return self.source.tell() - len(self.prefix)

    def seek(self, position):
        if self.prefix:
            raise ValueError('ambiguous custody tar metadata seek')
        return self.source.seek(position)


class _CustodyTarInfo(tarfile.TarInfo):
    """Bound extended headers before stdlib allocates or interprets them."""
    _pax_keys = frozenset((b'path', b'linkpath'))
    @classmethod
    def _fromtarfile(cls, archive, *, dircheck=True):
        archive._custody_headers = getattr(archive, '_custody_headers', 0) + 1
        if archive._custody_headers > _TAR_HEADER_LIMIT:
            raise ValueError('custody tar header count bound')
        return super()._fromtarfile(archive, dircheck=dircheck)

    def _metadata(self, archive):
        if not 0 <= self.size <= _TAR_METADATA_RECORD_LIMIT:
            raise ValueError('custody tar metadata record byte bound')
        archive._custody_metadata = getattr(archive, '_custody_metadata', 0) + self.size
        if archive._custody_metadata > _TAR_METADATA_TOTAL_LIMIT:
            raise ValueError('custody tar aggregate metadata byte bound')
        padded = self._block(self.size)
        raw = archive.fileobj.read(padded)
        if len(raw) != padded or any(raw[self.size:]):
            raise ValueError('truncated or invalid custody tar metadata')
        return raw

    def _with_prefix(self, archive, raw, operation):
        original = archive.fileobj
        wrapped = _TarPrefix(original, raw)
        archive.fileobj = wrapped
        try:
            result = operation(archive)
            if wrapped.prefix:
                raise ValueError('incomplete custody tar metadata')
            return result
        finally:
            archive.fileobj = original

    def _proc_pax(self, archive):
        if self.type != tarfile.XHDTYPE:
            raise ValueError('unsupported global custody tar metadata')
        raw = self._metadata(archive)
        payload, offset, keys = raw[:self.size], 0, set()
        while offset < len(payload):
            space = payload.find(b' ', offset, min(len(payload), offset + 20))
            if space < 0 or not payload[offset:space].isdigit():
                raise ValueError('invalid custody tar metadata record')
            length = int(payload[offset:space])
            end = offset + length
            if length < 5 or end > len(payload) or payload[end - 1:end] != b'\n':
                raise ValueError('invalid custody tar metadata length')
            key, separator, _ = payload[space + 1:end - 1].partition(b'=')
            if not separator or key not in self._pax_keys or key in keys:
                raise ValueError('unsupported or duplicate custody tar metadata')
            keys.add(key)
            offset = end
        pending = getattr(archive, '_custody_pending_keys', set())
        if pending & keys:
            raise ValueError('ambiguous consecutive custody tar metadata')
        archive._custody_pending_keys = pending | keys
        return self._with_prefix(archive, raw, super()._proc_pax)

    def _proc_gnulong(self, archive):
        raw = self._metadata(archive)
        if b'\0' in raw[:self.size].rstrip(b'\0'):
            raise ValueError('ambiguous custody tar long name')
        key = b'path' if self.type == tarfile.GNUTYPE_LONGNAME else b'linkpath'
        pending = getattr(archive, '_custody_pending_keys', set())
        if key in pending:
            raise ValueError('ambiguous consecutive custody tar metadata')
        archive._custody_pending_keys = pending | {key}
        return self._with_prefix(archive, raw, super()._proc_gnulong)

    def _proc_sparse(self, archive):
        raise ValueError('unsupported sparse custody tar member')

    def _proc_gnusparse_00(self, *args):
        raise ValueError('unsupported sparse custody tar member')

    def _proc_gnusparse_01(self, *args):
        raise ValueError('unsupported sparse custody tar member')

    def _proc_gnusparse_10(self, *args):
        raise ValueError('unsupported sparse custody tar member')

    def _proc_builtin(self, archive):
        if self.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE, tarfile.SYMTYPE):
            raise ValueError('unsupported custody tar member type')
        archive._custody_pending_keys = set()
        return super()._proc_builtin(archive)


class _CustodyContainerTarInfo(_CustodyTarInfo):
    """Inventory device and hard-link entries without extracting them."""
    def _proc_builtin(self, archive):
        if self.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE, tarfile.SYMTYPE,
                             tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE):
            raise ValueError('unsupported custody tool archive member type')
        archive._custody_pending_keys = set()
        return tarfile.TarInfo._proc_builtin(self, archive)


_CONSUMER_IMAGE_BINDING_KEY = object()


@dataclass(frozen=True, slots=True, init=False)
class ConsumerImageBinding:
    """Verified external consumer-image closure; never a source-rights grant."""
    _data: bytes

    def __init__(self, key, data):
        if key is not _CONSUMER_IMAGE_BINDING_KEY:
            raise TypeError('consumer image binding requires its verified factory')
        object.__setattr__(self, '_data', canonical(data))

    def as_dict(self):
        return load_json(self._data)

    def check(self, artifact, inventory):
        data = self.as_dict()
        if (artifact.kind != 'custody-tree' or artifact.sha256 != data['tree_sha256']
                or artifact.platform != data['platform']
                or inventory.get('external_image_prerequisite') != data['contract']):
            raise ValueError('consumer image prerequisite does not bind this tree and protected contract')
        observation = inventory.get('observation', {})
        expected_source = {'image': data['image'], 'tool_manifest_sha256': data['tool_manifest_sha256'],
                           'source': {key: data['source'][key] for key in ('receipt_sha256', 'archive_sha256', 'spdx_sha256')}}
        if inventory.get('external_image_source') != expected_source:
            raise ValueError('consumer image source identity changed')
        if observation.get('linked_libraries') != data['tree_links']:
            raise ValueError('consumer image prerequisite tree dependencies changed')

    def source_identity(self):
        data = self.as_dict()
        return {'image': data['image'], 'tool_manifest_sha256': data['tool_manifest_sha256'],
                'source': {key: data['source'][key] for key in ('receipt_sha256', 'archive_sha256', 'spdx_sha256')}}

    def covers(self, link):
        return link in self.as_dict()['covered_tree_links']

    def require_phase(self, phase):
        if self.as_dict()['phase'] != phase:
            raise ValueError('consumer image source proof phase mismatch')


@dataclass(frozen=True, slots=True, init=False)
class VerifiedCustodyBytes:
    """Authenticated inert bytes; source replay and qualification remain open."""
    _data: bytes

    def __init__(self, key, value):
        if key is not _BYTES_KEY:
            raise TypeError('custody bytes require verified acquisition')
        object.__setattr__(self, '_data', canonical(value))

    def as_dict(self):
        return load_json(self._data)


@dataclass(frozen=True, slots=True, init=False)
class VerifiedCustodyProducer:
    """Local active preconditions only; no binary has been saved or uploaded."""
    _data: bytes

    def __init__(self, key, value):
        if key is not _PRODUCER_KEY:
            raise TypeError('custody producer requires actual source and component checks')
        object.__setattr__(self, '_data', canonical(value))

    def as_dict(self):
        return load_json(self._data)


@dataclass(frozen=True, slots=True, init=False)
class PreparedCustodyImage:
    """A locally saved image after actual checks, not an uploaded artifact."""
    _data: bytes

    def __init__(self, key, value):
        if key is not _IMAGE_KEY:
            raise TypeError('custody image requires actual producer checks and save')
        object.__setattr__(self, '_data', canonical(value))

    def as_dict(self):
        return load_json(self._data)


@dataclass(frozen=True, slots=True, init=False)
class InertLoadedCustodyImage:
    """An authenticated image loaded for source replay, not admitted or qualified."""
    _data: bytes

    def __init__(self, key, value):
        if key is not _LOADED_KEY:
            raise TypeError('loaded custody image requires authenticated inert loading')
        object.__setattr__(self, '_data', canonical(value))

    def as_dict(self):
        return load_json(self._data)


@dataclass(frozen=True, slots=True, init=False)
class PreparedCustodyPayload:
    """A closed local pre-upload payload, without completed-run authority."""
    _data: bytes

    def __init__(self, key, value):
        if key is not _PAYLOAD_KEY:
            raise TypeError('custody payload requires actual producer preparation')
        object.__setattr__(self, '_data', canonical(value))

    def as_dict(self):
        return load_json(self._data)


@dataclass(frozen=True, slots=True, init=False)
class VerifiedCustodySourceReplay:
    """Fresh source D only; independent qualification and exposure stay open."""
    _data: bytes

    def __init__(self, key, value):
        if key is not _SOURCE_REPLAY_KEY:
            raise TypeError('source replay requires actual completed-producer checks')
        object.__setattr__(self, '_data', canonical(value))

    def as_dict(self):
        return load_json(self._data)


def _custody_policy_root():
    from importlib.resources import files
    return files('p11lab').joinpath('data/ci/delivery')


def _policy_resource_bytes(resource, limit):
    if getattr(resource, 'is_symlink', lambda: False)() or not resource.is_file():
        raise ValueError('custody policy resource missing or unsafe')
    with resource.open('rb') as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError('custody policy resource byte bound')
    return raw


def _read_custody_policy():
    """Load bounded, fixed role shards without treating them as rights approval."""
    root = _custody_policy_root()
    index = load_json(_policy_resource_bytes(root.joinpath('custody-policy.json'), 2 * 1024 * 1024))
    if type(index) is not dict or set(index) != {'schema_version', 'components'}:
        raise ValueError('invalid custody policy index')
    if type(index['schema_version']) is not int or type(index['components']) is not list:
        raise ValueError('invalid custody policy index fields')
    if index['schema_version'] == 1:
        return index, []
    if index['schema_version'] != 2:
        raise ValueError('unsupported custody policy index version')
    entries = index['components']
    if (len(entries) != len(COMPONENTS) or any(type(row) is not dict or set(row) != {'name', 'sha256', 'size_bytes'}
            or type(row['name']) is not str or type(row['sha256']) is not str
            or re.fullmatch(r'[0-9a-f]{64}', row['sha256']) is None
            or type(row['size_bytes']) is not int or not 0 < row['size_bytes'] <= 16 * 1024 * 1024 for row in entries)
            or [row['name'] for row in entries] != sorted(COMPONENTS)
            or sum(row['size_bytes'] for row in entries) > 32 * 1024 * 1024):
        raise ValueError('invalid bounded custody policy shard roster')
    directory = root.joinpath('custody-components')
    if getattr(directory, 'is_symlink', lambda: False)() or not directory.is_dir():
        raise ValueError('custody policy shard directory missing or unsafe')
    from itertools import islice
    expected = {row['name'] + '.json' for row in entries}
    members = list(islice(directory.iterdir(), len(expected) + 1))
    if len(members) != len(expected) or {item.name for item in members} != expected:
        raise ValueError('custody policy shard directory roster mismatch')
    components, graph = [], []
    for row in entries:
        name = row['name']
        resource = directory.joinpath(name + '.json')
        raw = _policy_resource_bytes(resource, row['size_bytes'])
        if len(raw) != row['size_bytes'] or hashlib.sha256(raw).hexdigest() != row['sha256']:
            raise ValueError('custody policy shard size or hash mismatch')
        value = load_json(raw, max_bytes=16 * 1024 * 1024)
        if (type(value) is not dict or value.get('name') != name or value.get('kind') != COMPONENTS[name]):
            raise ValueError('custody policy shard role mismatch')
        components.append(value)
        graph.append({'path': 'src/p11lab/data/ci/delivery/custody-components/' + name + '.json',
                      'sha256': row['sha256'], 'size_bytes': row['size_bytes']})
    return {'schema_version': 1, 'components': components}, graph


def _installed_custody_policy():
    return _read_custody_policy()[0]


def _reviewed_content_projection(observation, kind, dynamic_files=None):
    """Select content facts independently of a future image/config identity."""
    if kind == 'custody-evaluator-metadata':
        entries = observation['files']
        if (type(entries) is not list or len(entries) != 1
                or entries[0].get('path') != '/evaluator-build-receipt.json'
                or set(entries[0]) != {'path', 'sha256', 'size', 'mode', 'package'}
                or entries[0]['package'] is not None or observation['packages'] != []
                or observation['binaries'] != [] or observation['linked_libraries'] != []):
            raise ValueError('invalid generated evaluator metadata observation')
        metadata = dict(observation['generated_metadata'])
        if metadata.pop('receipt_sha256', None) != entries[0]['sha256']:
            raise ValueError('generated evaluator metadata receipt identity mismatch')
        return {'file': {'path': entries[0]['path'], 'mode': entries[0]['mode']}, 'generated_metadata': metadata}
    if kind == 'custody-tree':
        import copy
        value = copy.deepcopy({key: item for key, item in observation.items() if key != 'artifact'})
        dynamic_files = dynamic_files or {}
        if type(dynamic_files) is not dict:
            raise ValueError('invalid dynamic custody file bindings')
        for path, digest in dynamic_files.items():
            files = [row for row in value['files'] if row['path'] == path]
            entries = [row for row in value['tree_entries'] if row['path'] == path]
            if (len(files) != 1 or len(entries) != 1 or entries[0]['type'] != 'file'
                    or files[0]['sha256'] != digest or entries[0]['sha256'] != digest
                    or any(row['path'] == path for row in value['binaries'])):
                raise ValueError('invalid dynamic custody file identity')
            for row in (files[0], entries[0]):
                row['sha256'], row['size'] = None, None
        return value
    if kind != 'docker-local':
        raise ValueError('unsupported custody component kind')
    distribution = observation['distribution']
    return {'files': observation['files'], 'packages': observation['packages'],
            'binaries': observation['binaries'], 'linked_libraries': observation['linked_libraries'],
            'link_method': observation['link_method'], 'distribution': {
                'platform': distribution['platform'], 'runtime_mount_files': distribution['runtime_mount_files'],
                'hidden_layer_files': distribution['hidden_layer_files'], 'whiteouts': distribution['whiteouts'],
                'layers': [{'index': layer['index'], 'regular_file_bytes': layer['regular_file_bytes']}
                           for layer in distribution['layers']]}}


def _metadata_review_record(inventory, expected_sha):
    records = inventory.get('content_reviews')
    if (type(records) is not list or len(records) != 1 or type(records[0]) is not dict
            or set(records[0]) != {'path', 'sha256', 'source', 'status'}
            or records[0]['path'] != '/evaluator-build-receipt.json' or records[0]['sha256'] != expected_sha):
        raise ValueError('invalid protected evaluator metadata review binding')
    return records[0]


def _dynamic_review_record(inventory, path, expected_sha):
    records = inventory.get('content_reviews')
    matches = [row for row in records if type(row) is dict and row.get('path') == path] if type(records) is list else []
    if (len(matches) != 1 or set(matches[0]) != {'path', 'sha256', 'source', 'status'}
            or matches[0]['sha256'] != expected_sha):
        raise ValueError('invalid protected generated tool content review')
    return matches[0]


def _component_review_digest(inventory, artifact, dynamic_files=None, consumer_binding=None):
    import copy
    from . import delivery_authority
    material = copy.deepcopy(inventory)
    if consumer_binding is not None:
        consumer_binding.check(artifact, material)
        material['external_image_source'] = None
    if artifact.kind == 'custody-evaluator-metadata':
        _metadata_review_record(material, artifact.sha256)['sha256'] = None
    for path, digest in (dynamic_files or {}).items():
        _dynamic_review_record(material, path, digest)['sha256'] = None
    return delivery_authority._review_digest(material)


def _protected_component(name, artifact):
    from . import delivery_authority
    from .models import ArtifactRef
    profile = delivery_authority.load_profile('softhsm2', 'release')
    delivery_authority._check_local_controller(profile)
    policy = _installed_custody_policy()
    if (type(policy) is not dict or set(policy) != {'schema_version', 'components'}
            or type(policy['schema_version']) is not int or policy['schema_version'] != 1
            or type(policy['components']) is not list or len(policy['components']) > len(COMPONENTS)):
        raise ValueError('invalid protected custody component policy')
    rows = policy['components']
    allowed_fields = ({'name', 'kind', 'inventory', 'expected'},
                      {'name', 'kind', 'inventory', 'expected', 'archives', 'generated_metadata'})
    if (any(type(row) is not dict or set(row) not in allowed_fields
            or row['name'] not in COMPONENTS or row['kind'] != COMPONENTS[row['name']] for row in rows)
            or len({row['name'] for row in rows}) != len(rows)):
        raise ValueError('invalid protected custody component roster')
    matches = [row for row in rows if row['name'] == name]
    if len(matches) != 1 or type(artifact) is not ArtifactRef or artifact.kind != matches[0]['kind']:
        raise ValueError('protected custody component unavailable or artifact mismatch')
    template = matches[0]
    inventory = template['inventory']
    if (type(inventory) is not dict or inventory.get('artifact', False) is not None
            or inventory.get('observation', False) is not None or inventory.get('build_key', False) is not None
            or type(template['expected']) is not dict):
        raise ValueError('invalid protected custody inventory template')
    return profile, template


def _check_generated_tool_metadata(actual, template):
    """Check a protected closed schema with narrow typed observation fields."""
    from datetime import datetime
    count = 0
    def check(value, expected, depth):
        nonlocal count
        count += 1
        if count > 200000 or depth > 100:
            raise ValueError('generated tool metadata schema bound')
        if type(expected) is dict and set(expected) == {'$p11lab_observed'}:
            kind = expected['$p11lab_observed']
            if kind in ('sha256', 'hex64'):
                valid = type(value) is str and re.fullmatch(r'[0-9a-f]{64}', value) is not None
            elif kind == 'sha256ref':
                valid = type(value) is str and re.fullmatch(r'sha256:[0-9a-f]{64}', value) is not None
            elif kind == 'hex32':
                valid = type(value) is str and re.fullmatch(r'[0-9a-f]{32}', value) is not None
            elif kind == 'nonnegative-int':
                valid = type(value) is int and value >= 0
            elif kind == 'positive-int':
                valid = type(value) is int and value > 0
            elif kind == 'absolute-path':
                valid = (type(value) is str and len(value) <= 4096 and value.startswith('/')
                         and '\x00' not in value and '\\' not in value and str(Path(value)) == value
                         and '..' not in Path(value).parts)
            elif kind == 'identifier':
                valid = type(value) is str and re.fullmatch(r'[A-Za-z0-9_.:/-]{1,512}', value) is not None
            elif kind == 'timestamp':
                try:
                    parsed = datetime.fromisoformat(value.replace('Z', '+00:00')) if type(value) is str else None
                    valid = parsed is not None and parsed.tzinfo is not None
                except ValueError:
                    valid = False
            else:
                valid = False
            if not valid:
                raise ValueError('generated tool metadata typed field mismatch')
        elif type(expected) is dict:
            if type(value) is not dict or set(value) != set(expected):
                raise ValueError('generated tool metadata object roster mismatch')
            for key in expected:
                check(value[key], expected[key], depth + 1)
        elif type(expected) is list:
            if type(value) is not list or len(value) != len(expected):
                raise ValueError('generated tool metadata array roster mismatch')
            for left, right in zip(value, expected):
                check(left, right, depth + 1)
        elif type(value) is not type(expected) or value != expected:
            raise ValueError('generated tool metadata fixed field mismatch')
    check(actual, template, 0)


def _review_tool_dynamic_files(name, artifact, template, inventory, tool_config):
    """Reverify a fixed tool build and every protected nested archive review."""
    from . import licenses
    from .tool_builds import verify_tool_build
    archives = template.get('archives', [])
    metadata = template.get('generated_metadata')
    if not archives and metadata is None:
        return {}
    if (name not in ('checker-root', 'consumer-root', 'oracle-root') or artifact.kind != 'custody-tree'
            or type(archives) is not list or len(archives) > 64
            or type(tool_config) is not dict or set(tool_config) != {'root', 'input_receipt', 'manifest_sha256'}
            or Path(tool_config['root']).absolute() != Path(artifact.reference)):
        raise ValueError('invalid protected dynamic tool review context')
    manifest = verify_tool_build(Path(artifact.reference), receipt_path=Path(tool_config['input_receipt']),
                                 manifest_sha256=tool_config['manifest_sha256'])
    if manifest['toolset'] != name.removesuffix('-root'):
        raise ValueError('dynamic tool review role mismatch')
    actual = licenses.inspect_artifact(artifact)
    file_rows = {row['path']: row for row in actual['files']}
    dynamic = {}
    for spec in archives:
        if (type(spec) is not dict or type(spec.get('path')) is not str or not spec['path'].endswith('.tar')
                or spec['path'] not in manifest['evidence'] or '/' + spec['path'] in dynamic):
            raise ValueError('invalid protected dynamic tool archive roster')
        observed = _check_tool_archive_review(artifact, spec, inventory)
        if manifest['evidence'][spec['path']] != observed:
            raise ValueError('tool archive differs from verified build manifest')
        path = '/' + spec['path']
        if file_rows.get(path, {}).get('sha256') != observed['sha256']:
            raise ValueError('tool archive outer content changed')
        dynamic[path] = observed['sha256']
    if metadata is not None:
        if (type(metadata) is not dict or set(metadata) != {'path', 'renderer_sha256', 'template'}
                or metadata['path'] != 'manifest.json' or type(metadata['renderer_sha256']) is not str
                or not re.fullmatch(r'[0-9a-f]{64}', metadata['renderer_sha256'])
                or manifest['producer_resources']['driver']['sha256'] != metadata['renderer_sha256']):
            raise ValueError('invalid protected generated tool metadata renderer')
        _check_generated_tool_metadata(manifest, metadata['template'])
        row = file_rows.get('/manifest.json')
        if not row or row['sha256'] != tool_config['manifest_sha256']:
            raise ValueError('generated tool manifest identity changed')
        dynamic['/manifest.json'] = row['sha256']
    return dynamic


def _read_component_inventory(path):
    """Read one source inventory with the existing strict 16 MiB source bound."""
    from .delivery_authority import _read_bounded_file
    return load_json(_read_bounded_file(path, 16 * 1024 * 1024), max_bytes=16 * 1024 * 1024)


def _consumer_binding_needed(name, artifact):
    """A self-contained tree needs no external prerequisite witness."""
    if name != 'consumer-root':
        return False
    from . import licenses
    _, template = _protected_component(name, artifact)
    actual = licenses.inspect_artifact(artifact)
    return (template['inventory'].get('external_image_prerequisite') is not None
            or any(not link.get('resolved') for link in actual['linked_libraries']))


def _consumer_image_binding(artifact, tool_config, evidence_dir, output_dir, *, registry=None, manifest_sha256=None):
    """Recompute a local or readback-qualified consumer execution environment.

    The tree's own unresolved links remain unchanged. All image files remain
    external to that tree and the image's own source review remains mandatory.
    """
    import json
    import posixpath
    from dataclasses import asdict
    from . import delivery_authority, licenses, sources
    from .inspection_bounded import InspectionPolicy
    from .models import ArtifactRef
    from .tool_builds import _archive_inventory, _elf_closure, verify_tool_build

    if (type(tool_config) is not dict or set(tool_config) != {'root', 'input_receipt', 'manifest_sha256'}
            or Path(tool_config['root']).absolute() != Path(artifact.reference)):
        raise ValueError('consumer prerequisite requires the selected verified tool root')
    profile, tree_template = _protected_component('consumer-root', artifact)
    contract = tree_template['inventory'].get('external_image_prerequisite')
    fields = {'schema_version', 'kind', 'image_path', 'tree_paths', 'product_sha256', 'product_size',
              'product_mode', 'tree_modes', 'elf_closure', 'image_source_review_sha256'}
    if (type(contract) is not dict or set(contract) != fields or contract['schema_version'] != 1
            or contract['kind'] != 'consumer-image-external-prerequisite'
            or contract['image_path'] != '/usr/local/bin/p11lab-smoke'
            or contract['tree_paths'] != ['/product/p11lab-smoke', '/runtime/p11lab-smoke']
            or contract['tree_modes'] != {'/product/p11lab-smoke': 0o755, '/runtime/p11lab-smoke': 0o644}
            or contract['product_mode'] != 0o755 or type(contract['elf_closure']) is not dict):
        raise ValueError('missing or malformed protected consumer image prerequisite')
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=False)
    manifest = verify_tool_build(Path(artifact.reference), receipt_path=Path(tool_config['input_receipt']),
                                 manifest_sha256=tool_config['manifest_sha256'])
    if manifest['toolset'] != 'consumer':
        raise ValueError('consumer prerequisite selected wrong tool')
    installed = manifest['installed']
    image = ArtifactRef('docker-local', installed['engine_id'], installed['config_sha256'], artifact.platform)
    if image.reference != 'sha256:' + image.sha256 or image.platform != 'linux/amd64':
        raise ValueError('consumer prerequisite image identity mismatch')
    _, image_template = _protected_component('consumer-image', image)
    if contract['image_source_review_sha256'] != delivery_authority._review_digest(image_template['inventory']):
        raise ValueError('consumer prerequisite image source review mismatch')
    observed_tree = licenses.inspect_artifact(artifact)
    actual = licenses.inspect_artifact(image, inspection_policy=InspectionPolicy(), journal_path=output / 'image-inspection.json')
    distribution = actual['distribution']
    if (actual['artifact'] != asdict(image) or distribution['platform'] != image.platform
            or ['sha256:' + x['diff_id'].removeprefix('sha256:') for x in distribution['layers']] != installed['layers']
            or _reviewed_content_projection(actual, image.kind) != image_template['expected']):
        raise ValueError('consumer prerequisite image contents or layers mismatch')
    products = manifest['products']
    if (len(products) != 1 or products[0]['path'] != 'product/p11lab-smoke'
            or products[0]['sha256'] != contract['product_sha256']
            or products[0]['size'] != contract['product_size']
            or manifest['elf_closure'] != contract['elf_closure']):
        raise ValueError('consumer prerequisite product or protected closure mismatch')
    archive_path = Path(artifact.reference) / 'consumer-filesystem.tar'
    expected_archive = manifest['evidence']['consumer-filesystem.tar']
    descriptor = os.open(archive_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as source:
        before = os.fstat(source.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_size != expected_archive['size']
                or hashlib.file_digest(source, 'sha256').hexdigest() != expected_archive['sha256']):
            raise ValueError('consumer prerequisite filesystem archive changed')
        filesystem = _archive_inventory(Path('/proc/self/fd') / str(source.fileno()))
        source.seek(0)
        after_hash = hashlib.file_digest(source, 'sha256').hexdigest()
        after, current = os.fstat(source.fileno()), os.stat(archive_path, follow_symlinks=False)
        def identity(value):
            return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
                    value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if (after_hash != expected_archive['sha256'] or identity(before) != identity(after)
                or identity(after) != identity(current)):
            raise ValueError('consumer prerequisite filesystem archive changed during inspection')
    if _elf_closure(filesystem, [contract['image_path'].lstrip('/')]) != contract['elf_closure']:
        raise ValueError('consumer prerequisite actual ELF closure mismatch')
    tree_files = {x['path']: x for x in observed_tree['files']}
    image_files = {x['path']: x for x in actual['files']}
    image_elf = {x['path']: x for x in actual['binaries']}
    expected_file = {'sha256': contract['product_sha256'], 'size': contract['product_size'], 'mode': contract['product_mode']}
    for path in contract['tree_paths']:
        tree_expected = expected_file | {'mode': contract['tree_modes'][path]}
        if any(tree_files.get(path, {}).get(key) != val for key, val in tree_expected.items()):
            raise ValueError('consumer tree executable differs from protected product')
    if any(image_files.get(contract['image_path'], {}).get(key) != val for key, val in expected_file.items()):
        raise ValueError('consumer image executable differs from protected product')
    if {x['path'] for x in observed_tree['binaries']} != set(contract['tree_paths']):
        raise ValueError('consumer tree ELF roster changed')
    aliases = {x['path']: x['link'] for x in actual['files'] if 'link' in x}
    def resolve(path):
        if not path.startswith('/'):
            raise ValueError('invalid consumer interpreter path')
        parts, seen = path.split('/')[1:], set()
        for _ in range(64):
            changed = False
            for index in range(1, len(parts) + 1):
                prefix = '/' + '/'.join(parts[:index])
                if prefix in aliases:
                    if prefix in seen:
                        raise ValueError('cyclic consumer image alias')
                    seen.add(prefix)
                    target = aliases[prefix]
                    replaced = target if target.startswith('/') else posixpath.join(posixpath.dirname(prefix), target)
                    joined = posixpath.normpath(replaced + '/' + '/'.join(parts[index:]))
                    if not joined.startswith('/'):
                        raise ValueError('consumer image alias escapes root')
                    parts = joined.split('/')[1:]
                    changed = True
                    break
            if not changed:
                return '/' + '/'.join(parts)
        raise ValueError('consumer image alias depth exceeded')
    closure = contract['elf_closure']
    remaining = {contract['image_path'].lstrip('/')}
    reached = set()
    while remaining:
        name = remaining.pop()
        if name in reached:
            continue
        reached.add(name)
        row = closure.get(name)
        path = '/' + name
        if type(row) is not dict or path not in image_elf:
            raise ValueError('consumer image closure missing ELF')
        if any(image_files.get(path, {}).get(key) != row[key] for key in ('sha256', 'size', 'mode')):
            raise ValueError('consumer image closure file identity changed')
        if image_elf[path]['needed'] != row['needed']:
            raise ValueError('consumer image closure ELF dependencies changed')
        targets = set()
        for needed in row['needed']:
            links = [x for x in actual['linked_libraries'] if x['binary'] == path and x['needed'] == needed]
            if len(links) != 1 or len(links[0]['resolved']) != 1:
                raise ValueError('consumer image dependency missing or ambiguous')
            targets.add(links[0]['resolved'][0].lstrip('/'))
        if row['interpreter'] is not None:
            targets.add(resolve(row['interpreter']).lstrip('/'))
        if targets != set(row['resolved_dependencies']):
            raise ValueError('consumer image interpreter or dependency closure mismatch')
        remaining.update(targets - reached)
    if reached != set(closure):
        raise ValueError('consumer image closure has extra or missing files')
    covered = []
    needed = closure[contract['image_path'].lstrip('/')]['needed']
    for link in observed_tree['linked_libraries']:
        if (link['binary'] not in contract['tree_paths'] or link['needed'] not in needed or link['resolved']):
            raise ValueError('consumer tree dependency differs from selected image')
        covered.append(link)
    if len(covered) != len(contract['tree_paths']) * len(needed):
        raise ValueError('consumer tree dependency roster incomplete')
    evidence = Path(evidence_dir)
    receipt_path = evidence / 'source-companion.json'
    receipt = load_json(delivery_authority._read_bounded_file(receipt_path, 1024 * 1024))
    sources.verify_source_bundle(evidence / 'source-companion.tar.gz', output / 'source-extract')
    inventory = _read_component_inventory(output / 'source-extract/inventory.json')
    if (delivery_authority._review_digest(inventory) != contract['image_source_review_sha256']
            or _reviewed_content_projection(inventory['observation'], image.kind) != image_template['expected']):
        raise ValueError('consumer image source differs from protected review')
    assessed = licenses.assess_distribution(image, evidence, inspection_policy=InspectionPolicy(),
                                            journal_path=output / 'image-assessment.json')
    if assessed['status'] != 'eligible':
        raise ValueError('consumer image local source assessment incomplete')
    source = {'receipt_sha256': sources.checksum(receipt_path),
              'archive_sha256': receipt['artifact']['sha256'], 'spdx_sha256': receipt['sbom_sha256']}
    phase = 'local-only'
    if registry is not None or manifest_sha256 is not None:
        if not registry or not manifest_sha256:
            raise ValueError('consumer image readback requires exact registry and manifest')
        proof = verify_custody_component_source('consumer-image', image, evidence_dir=evidence, registry=registry,
                  manifest_sha256=manifest_sha256, output_dir=output / 'source-readback')
        if (proof['receipt_sha256'] != source['receipt_sha256'] or proof['file_sha256'] != source['archive_sha256']
                or proof['spdx_sha256'] != source['spdx_sha256']):
            raise ValueError('consumer image readback source differs from local assessment')
        source['manifest_sha256'] = manifest_sha256
        phase = 'source-readback'
    delivery_authority._check_local_controller(profile)
    if licenses.inspect_artifact(artifact) != observed_tree:
        raise ValueError('consumer tree changed during prerequisite verification')
    result = {'phase': phase, 'tree_sha256': artifact.sha256, 'platform': artifact.platform,
              'image': {'reference': image.reference, 'config_sha256': distribution['config_sha256'], 'layers': installed['layers']},
              'tool_manifest_sha256': tool_config['manifest_sha256'], 'source': source, 'contract': contract, 'tree_links': observed_tree['linked_libraries'],
              'covered_tree_links': covered, 'external_files': closure,
              'provisioning': 'runtime data copy is mode 0644; protected image executable is mode 0755'}
    (output / 'consumer-image-prerequisite.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    return ConsumerImageBinding(_CONSUMER_IMAGE_BINDING_KEY, result)


def materialize_custody_component(name, artifact, *, output_dir, tool_config=None, consumer_binding=None):
    """Reinspect one protected-reviewed component and collect its sources.

    Local eligibility alone does not prove source-first readback or D.
    """
    import copy
    import json
    from dataclasses import asdict
    from . import delivery_authority, licenses, sources
    from .inspection_bounded import InspectionPolicy

    profile, template = _protected_component(name, artifact)
    if (name == 'consumer-root' and template['inventory'].get('external_image_prerequisite') is not None
            and consumer_binding is None):
        raise ValueError('protected consumer image prerequisite requires typed binding')
    if consumer_binding is not None:
        if name != 'consumer-root' or type(consumer_binding) is not ConsumerImageBinding:
            raise TypeError('typed consumer-root binding required')
        consumer_binding.require_phase('local-only')
    inventory = copy.deepcopy(template['inventory'])
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=False)
    if artifact.kind == 'docker-local':
        actual = licenses.inspect_artifact(artifact, inspection_policy=InspectionPolicy(),
                                           journal_path=output / 'initial-inspection.json')
    else:
        actual = licenses.inspect_artifact(artifact)
    dynamic = _review_tool_dynamic_files(name, artifact, template, inventory, tool_config)
    if _reviewed_content_projection(actual, artifact.kind, dynamic) != template['expected']:
        raise ValueError('actual custody component differs from protected expected content')
    inventory['artifact'] = asdict(artifact)
    inventory['observation'] = actual
    if consumer_binding is not None:
        if inventory.get('external_image_source', False) is not None:
            raise ValueError('invalid protected consumer image source template')
        inventory['external_image_source'] = consumer_binding.source_identity()
    if artifact.kind == 'custody-evaluator-metadata':
        _metadata_review_record(inventory, None)['sha256'] = artifact.sha256
    for path, digest in dynamic.items():
        _dynamic_review_record(inventory, path, None)['sha256'] = digest
    reasons = licenses.validate_inventory(artifact, inventory, consumer_binding=consumer_binding)
    if reasons:
        raise ValueError('protected custody review incomplete: ' + '; '.join(reasons))
    evidence = output / 'evidence'
    if artifact.kind == 'docker-local':
        sources.collect_source_bundle(artifact, inventory, evidence, inspection_policy=InspectionPolicy(),
                                      journal_path=output / 'collection-inspection.json')
        assessment = licenses.assess_distribution(artifact, evidence, inspection_policy=InspectionPolicy(),
                                                  journal_path=output / 'assessment-inspection.json')
    else:
        sources.collect_source_bundle(artifact, inventory, evidence, consumer_binding=consumer_binding)
        assessment = licenses.assess_distribution(artifact, evidence, consumer_binding=consumer_binding)
    if assessment['status'] != 'eligible':
        raise ValueError('custody component content assessment blocked: ' + '; '.join(assessment['blockers']))
    if _review_tool_dynamic_files(name, artifact, template, template['inventory'], tool_config) != dynamic:
        raise ValueError('protected dynamic tool content changed during source collection')
    delivery_authority._check_local_controller(profile)
    result = {'schema_version': 1, 'component': name, 'artifact': asdict(artifact),
              'status': 'eligible-local-content', 'source_first_status': 'not-yet-read-back',
              'image_promotion_status': 'blocked', 'review_sha256': _component_review_digest(inventory, artifact, dynamic, consumer_binding),
              'source_companion_sha256': sources.checksum(evidence / 'source-companion.tar.gz')}
    (output / 'local-component-review.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    return result


def verify_custody_component_source(name, artifact, *, evidence_dir, registry, manifest_sha256, output_dir,
                                    replay_binding=None, tool_config=None, consumer_binding=None):
    """Reassess one protected component and reacquire its exact source first."""
    import shutil
    from . import delivery_authority, licenses, publish, source_transport, sources
    from .inspection_bounded import InspectionPolicy

    if consumer_binding is not None:
        if name != 'consumer-root' or type(consumer_binding) is not ConsumerImageBinding:
            raise TypeError('typed consumer-root binding required')
        consumer_binding.require_phase('source-readback')
    if replay_binding is not None:
        from .round_core.evaluator_replay import EvaluatorReplayBinding
        if (type(replay_binding) is not EvaluatorReplayBinding or name != 'evaluator-original'
                or artifact.kind != 'custody-evaluator-metadata'):
            raise TypeError('typed evaluator replay binding required for evaluator metadata')
    profile, template = _protected_component(name, artifact)
    if (name == 'consumer-root' and template['inventory'].get('external_image_prerequisite') is not None
            and consumer_binding is None):
        raise ValueError('protected consumer image prerequisite requires typed binding')
    evidence = Path(evidence_dir)
    receipt_path = publish._regular_file(evidence / 'source-companion.json', 'component source receipt')
    receipt = load_json(delivery_authority._read_bounded_file(receipt_path, 1024 * 1024))
    spdx = publish._regular_file(evidence / 'sbom.spdx.json', 'component SPDX')
    archive = publish._regular_file(evidence / 'source-companion.tar.gz', 'component source archive')
    try:
        expected = {
            'source-companion.tar.gz': {'sha256': receipt['artifact']['sha256'], 'size_bytes': receipt['size_bytes'],
                                        'media_type': publish.CONTENT_FILES['source-companion.tar.gz']},
            'source-companion.json': {'sha256': sources.checksum(receipt_path), 'size_bytes': receipt_path.stat().st_size,
                                      'media_type': publish.CONTENT_FILES['source-companion.json']},
            'sbom.spdx.json': {'sha256': receipt['sbom_sha256'], 'size_bytes': spdx.stat().st_size,
                               'media_type': publish.CONTENT_FILES['sbom.spdx.json']},
        }
        if (sources.checksum(archive) != expected['source-companion.tar.gz']['sha256']
                or archive.stat().st_size != expected['source-companion.tar.gz']['size_bytes']
                or sources.checksum(spdx) != expected['sbom.spdx.json']['sha256']):
            raise ValueError('component local source bytes changed')
    except (KeyError, TypeError) as error:
        raise ValueError('malformed component source receipt') from error
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=False)
    oci = output / 'source-oci'
    source_transport.acquire(registry, manifest_sha256, expected,
                             artifact_type='application/vnd.p11lab.source-companion.v1', output_dir=oci)
    proof = publish.verify_content_readback(receipt_path, oci / 'files', source_manifest_path=oci / 'manifest.json',
        source_manifest_digest=manifest_sha256, registry=registry, artifact=artifact,
        transcript_path=oci / 'transport-journal.json', extract_dir=output / 'source-extract')
    inventory = _read_component_inventory(output / 'source-extract/inventory.json')
    dynamic = _review_tool_dynamic_files(name, artifact, template, template['inventory'], tool_config)
    if _component_review_digest(inventory, artifact, dynamic, consumer_binding) != delivery_authority._review_digest(template['inventory']):
        raise ValueError('source companion review differs from protected component template')
    if _reviewed_content_projection(inventory['observation'], artifact.kind, dynamic) != template['expected']:
        raise ValueError('source companion differs from protected expected component content')
    cache = evidence / 'package-cache'
    target = oci / 'files' / 'package-cache'
    if cache.exists():
        if cache.is_symlink() or not cache.is_dir():
            raise ValueError('unsafe component package cache')
        entries = list(cache.iterdir())
        if len(entries) > 10000:
            raise ValueError('component package cache entry bound')
        target.mkdir()
        total = 0
        for path in entries:
            if not re.fullmatch(r'[0-9a-f]{64}\.deb', path.name):
                raise ValueError('unexpected component package cache member')
            publish._regular_file(path, 'component package cache member')
            total += path.stat().st_size
            if path.stat().st_size > 1024**3 or total > 5 * 1024**3:
                raise ValueError('component package cache byte bound')
            shutil.copyfile(path, target / path.name)
            if sources.checksum(target / path.name) != path.name.removesuffix('.deb'):
                raise ValueError('component package cache bytes changed')
    if replay_binding is not None:
        actual = licenses.inspect_artifact(artifact, replay_binding=replay_binding)
        assessment = licenses.assess_distribution(artifact, oci / 'files', replay_binding=replay_binding)
    elif artifact.kind == 'docker-local':
        actual = licenses.inspect_artifact(artifact, inspection_policy=InspectionPolicy(),
                                           journal_path=output / 'component-inspection.json')
        assessment = licenses.assess_distribution(artifact, oci / 'files', inspection_policy=InspectionPolicy(),
                                                  journal_path=output / 'component-assessment.json')
    else:
        actual = licenses.inspect_artifact(artifact)
        assessment = licenses.assess_distribution(artifact, oci / 'files', consumer_binding=consumer_binding)
    actual_projection = _reviewed_content_projection(actual, artifact.kind, dynamic)
    expected_projection = template['expected']
    if replay_binding is not None:
        import copy
        actual_projection, expected_projection = copy.deepcopy(actual_projection), copy.deepcopy(expected_projection)
        actual_projection['file'].pop('mode')
        expected_projection['file'].pop('mode')
    if (actual_projection != expected_projection
            or not licenses._same_observation(actual, inventory['observation'], artifact, replay_binding=replay_binding)
            or assessment['status'] != 'eligible'):
        raise ValueError('component actual content or source assessment changed')
    if _review_tool_dynamic_files(name, artifact, template, template['inventory'], tool_config) != dynamic:
        raise ValueError('protected dynamic tool content changed during source readback')
    delivery_authority._check_local_controller(profile)
    result = {'schema_version': 1, 'component': name, 'source_first_status': 'verified-anonymous-source-readback',
            'reference': proof['reference'], 'manifest_sha256': proof['manifest_sha256'],
            'file_sha256': proof['file_sha256'], 'receipt_sha256': proof['receipt_sha256'],
            'spdx_sha256': proof['spdx_sha256'], 'inventory_sha256': proof['inventory_sha256'],
            'source_archive_size': expected['source-companion.tar.gz']['size_bytes'],
            'review_sha256': delivery_authority._review_digest(template['inventory']),
            'image_promotion_status': 'blocked'}
    if replay_binding is not None:
        result['metadata_modes'] = {'original': inventory['observation']['files'][0]['mode'],
                                    'current': actual['files'][0]['mode']}
    return result


def read_validation_compositions(archive, package_sha256, candidate, *, evaluator_inputs_dir=None):
    """Read exact derived-image references; this is not validation or D."""
    import tarfile
    from dataclasses import asdict
    from pathlib import PurePosixPath
    from .models import ArtifactRef

    if (type(candidate) is not ArtifactRef or candidate.kind != 'docker-local'
            or candidate.reference != 'sha256:' + candidate.sha256 or candidate.platform != 'linux/amd64'
            or type(package_sha256) is not str or not re.fullmatch(r'[0-9a-f]{64}', package_sha256)):
        raise ValueError('invalid validation composition selector')
    expected = {name + '-composition/composition.json': name for name in ('checker', 'consumer')}
    input_names = {'checker-run/checker/report.jsonl': 'checker-input/checker/report.jsonl',
                   'frozen-plan.json': 'frozen-plan.json', 'planning/planner.json': 'original/planner.json',
                   'admission/admission.json': 'original/admission.json', 'admission/ledger.jsonl': 'original/ledger.jsonl'}
    output = Path(evaluator_inputs_dir).absolute() if evaluator_inputs_dir is not None else None
    found, seen, total = {}, set(), 0
    descriptor = os.open(archive, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > 512 * 1024**2
                or hashlib.file_digest(stream, 'sha256').hexdigest() != package_sha256):
            raise ValueError('validation archive identity mismatch')
        if output is not None:
            if Path(archive).absolute().is_relative_to(output):
                raise ValueError('validation output overlaps archive')
            output.mkdir(parents=True, exist_ok=False)
        stream.seek(0)
        try:
            import gzip
            with gzip.GzipFile(fileobj=stream, mode='rb') as decompressed:
                bounded = _BoundedTarReader(decompressed)
                with tarfile.open(fileobj=bounded, mode='r|', tarinfo=_CustodyTarInfo) as bundle:
                    for member in bundle:
                        path = PurePosixPath(member.name)
                        if (not member.isfile() or path.is_absolute() or str(path) != member.name
                                or '\\' in member.name or any(p in ('', '.', '..') for p in member.name.split('/'))
                                or member.name in seen or len(seen) >= 10000 or member.size > 256 * 1024**2):
                            raise ValueError('unsafe validation archive member')
                        seen.add(member.name)
                        total += member.size
                        if total > 512 * 1024**2:
                            raise ValueError('validation archive expanded bound')
                        if member.name in expected:
                            if member.size > 2 * 1024**2:
                                raise ValueError('validation composition size bound')
                            item = bundle.extractfile(member)
                            if item is None:
                                raise ValueError('validation composition missing')
                            raw = item.read(member.size + 1)
                            if len(raw) != member.size:
                                raise ValueError('validation composition truncated')
                            found[expected[member.name]] = load_json(raw)
                        elif output is not None and member.name in input_names:
                            source = bundle.extractfile(member)
                            if source is None:
                                raise ValueError('validation evaluator input missing')
                            destination = output / input_names[member.name]
                            destination.parent.mkdir(parents=True, exist_ok=True)
                            count = 0
                            with destination.open('xb') as target:
                                while block := source.read(65536):
                                    count += len(block)
                                    if count > member.size:
                                        raise ValueError('validation evaluator input grew')
                                    target.write(block)
                            if count != member.size:
                                raise ValueError('validation evaluator input truncated')
                    if any(bundle.fileobj.buf):
                        raise ValueError('unexpected trailing validation tar data')
                while tail := bounded.read(65536):
                    if any(tail):
                        raise ValueError('unexpected trailing validation tar data')
        except (tarfile.TarError, OSError, EOFError) as error:
            raise ValueError('invalid validation archive') from error
        stream.seek(0)
        if hashlib.file_digest(stream, 'sha256').hexdigest() != package_sha256:
            raise ValueError('validation archive changed while reading')
        after, current = os.fstat(stream.fileno()), os.stat(archive, follow_symlinks=False)
        def identity(value):
            return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if identity(before) != identity(after) or identity(after) != identity(current):
            raise ValueError('validation archive changed while reading')
    if set(found) != {'checker', 'consumer'}:
        raise ValueError('incomplete validation composition roster')
    if output is not None and not set(input_names) <= seen:
        raise ValueError('incomplete validation evaluator inputs')
    result = {}
    for name, item in found.items():
        try:
            derived = ArtifactRef(**item['derived'])
            if (item['tool'] != name or item['parent'] != asdict(candidate) or derived.kind != 'docker-local'
                    or not re.fullmatch(r'[0-9a-f]{64}', derived.sha256)
                    or derived.reference != 'sha256:' + derived.sha256 or derived.platform != candidate.platform):
                raise ValueError('validation composition candidate or derived image mismatch')
        except (KeyError, TypeError, AttributeError) as error:
            raise ValueError('malformed validation composition') from error
        result[name] = derived
    return result


def _check_validation_body_digest(package, body_sha256):
    """Re-stream the enclosed validation body digest from the payload archive.

    This never trusts the envelope string: the digest is recomputed from the
    payload's own package bytes and compared to the custody facts claim.
    """
    import tarfile
    from pathlib import PurePosixPath
    found, seen, total = None, set(), 0
    try:
        with tarfile.open(package, 'r|gz') as bundle:
            for member in bundle:
                path = PurePosixPath(member.name)
                if (not member.isfile() or path.is_absolute() or str(path) != member.name
                        or '\\' in member.name or any(p in ('', '.', '..') for p in member.name.split('/'))
                        or member.name in seen or len(seen) >= 10000 or member.size > 256 * 1024**2):
                    raise ValueError('unsafe validation archive member')
                seen.add(member.name)
                total += member.size
                if total > 512 * 1024**2:
                    raise ValueError('validation archive expanded bound')
                source = bundle.extractfile(member)
                digest = hashlib.sha256()
                while block := source.read(1024 * 1024):
                    digest.update(block)
                if member.name == 'validation-body.json':
                    found = digest.hexdigest()
    except (tarfile.TarError, OSError, EOFError) as error:
        raise ValueError('invalid validation archive') from error
    if found is None:
        raise ValueError('frozen validation body missing')
    if found != body_sha256:
        raise ValueError('frozen validation body digest mismatch')


def _producer_component_artifacts(policy, candidate, derived):
    """Independently inspect the fixed local tool and input identities."""
    from . import image_validation, licenses
    from .models import ArtifactRef
    from .tool_builds import verify_tool_build

    image_validation._local_policy(policy)
    items = {}
    evaluator = Path(policy['evaluator']['root'])
    items['evaluator-original'] = licenses.observe_custody_evaluator_metadata(evaluator, platform=candidate.platform).artifact()
    for name in ('checker', 'consumer', 'oracle'):
        row = policy['tools'][name]
        root, receipt = Path(row['root']), Path(row['input_receipt'])
        manifest = verify_tool_build(root, receipt_path=receipt, manifest_sha256=row['manifest_sha256'])
        if manifest['toolset'] != name:
            raise ValueError('custody tool role mismatch: ' + name)
        items[name + '-root'] = licenses.observe_custody_tree(root, platform=candidate.platform).artifact()
        items[name + '-inputs'] = licenses.observe_custody_tree(receipt.parent, platform=candidate.platform).artifact()
        installed = manifest['installed']
        identity = installed['engine_id']
        if (not re.fullmatch(r'sha256:[0-9a-f]{64}', identity)
                or identity != 'sha256:' + installed['config_sha256']):
            raise ValueError('custody installed tool identity mismatch: ' + name)
        items[name + '-image'] = ArtifactRef('docker-local', identity, identity.removeprefix('sha256:'), candidate.platform)
        if name in ('checker', 'consumer'):
            items[name + '-derived'] = derived[name]
    if set(items) != set(COMPONENTS):
        raise ValueError('incomplete fixed custody producer component roster')
    return items


def materialize_custody_components(*, output_dir, **producer_args):
    """After actual D, assess all fixed components and collect source-only bundles."""
    import json
    from . import delivery_authority
    from .custody_authority import _require_custody_graph
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=False)
    journal = {'status': 'incomplete', 'source_first_status': 'not-yet-read-back'}
    try:
        first = delivery_authority.admit_source(**producer_args, output_dir=output / 'source-before')
        if first.get('role') != 'active-source-admission' or first.get('source_status') != 'eligible':
            raise ValueError('actual active source admission incomplete')
        profile = delivery_authority.load_profile(producer_args['environment'], producer_args['channel'])
        _require_custody_graph(profile)
        delivery_authority._authenticate_live_run(profile, producer_args['run_id'], producer_args['attempt'], producer_args['token'],
                                                  shard_journal=output / 'shard-graph-standalone.json')
        facts = first['facts']
        candidate = producer_args['artifact']
        policy = producer_args['validation_policy']
        derived = read_validation_compositions(Path(producer_args['validation_dir']) / 'package.tar.gz',
                                               facts['validation']['package_sha256'], candidate)
        components = _producer_component_artifacts(policy, candidate, derived)
        rows = []
        for name in sorted(components):
            tool_config = policy['tools'][name.removesuffix('-root')] if name.endswith('-root') else None
            binding = (_consumer_image_binding(components[name], tool_config, output / 'consumer-image/evidence',
                                               output / 'consumer-local-prerequisite')
                       if _consumer_binding_needed(name, components[name]) else None)
            result = materialize_custody_component(name, components[name], output_dir=output / name,
                                                    tool_config=tool_config, consumer_binding=binding)
            rows.append({'name': name, 'evidence_dir': str((output / name / 'evidence').absolute()),
                         'review_sha256': result['review_sha256'],
                         'source_companion_sha256': result['source_companion_sha256']})
        last = delivery_authority.admit_source(**producer_args, output_dir=output / 'source-after')
        if (last.get('role') != 'active-source-admission' or last.get('source_status') != 'eligible'
                or last['facts'] != facts or last['context_sha256'] != first['context_sha256']
                or last['protection'] != first['protection']
                or _producer_component_artifacts(policy, candidate, derived) != components):
            raise ValueError('source or component identity changed during collection')
        journal['status'] = 'complete-local-source-collection-only'
        return {'schema_version': 1, 'kind': 'custody-component-source-collection', 'components': rows,
                'source_first_status': 'not-yet-read-back', 'image_promotable': False}
    except BaseException as error:
        journal['error_type'] = type(error).__name__
        raise
    finally:
        (output / 'component-source-journal.json').write_text(json.dumps(journal, sort_keys=True, indent=2) + '\n')


def _active_custody_job(environment, channel, run_id, attempt, token, *, journal_dir=None):
    """Independently read one stable, unique active producer job ID."""
    import time
    from . import delivery_authority
    from .round_core.inputs import stable_metadata
    profile = delivery_authority.load_profile(environment, channel)
    if journal_dir is not None:
        journal_dir = Path(journal_dir)
        journal_dir.mkdir(parents=True, exist_ok=False)
    before_journal = journal_dir / 'before.json' if journal_dir is not None else None
    after_journal = journal_dir / 'after.json' if journal_dir is not None else None
    protection = delivery_authority._authenticate_live_run(profile, run_id, attempt, token, shard_journal=before_journal)
    transport = delivery_authority._github_transport(profile['repository'], token)
    deadline = time.monotonic() + 60
    identity = {'run_id': run_id, 'attempt': attempt, 'job': profile['job']}
    def fetch():
        run = transport._metadata(f'/actions/runs/{run_id}/attempts/{attempt}', deadline)
        jobs = transport._metadata(f'/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100', deadline)
        delivery_authority._check_active_metadata(profile, identity, run, jobs)
        rows = jobs['jobs']
        ids = [row.get('id') if type(row) is dict else None for row in rows]
        if len(ids) != 1 or any(type(value) is not int or value <= 0 for value in ids) or len(ids) != len(set(ids)):
            raise ValueError('ambiguous active custody job IDs')
        selected = [row for row in rows if row['name'] == profile['job']]
        return {'run': run, 'job': selected[0]}
    observed = stable_metadata(fetch)
    if delivery_authority._authenticate_live_run(profile, run_id, attempt, token, shard_journal=after_journal) != protection:
        raise ValueError('active custody producer protection changed')
    return identity | {'job_id': observed['job']['id']}


def _verify_active_uploads(transport, profile, run, manifest, raw_manifest, uploads, output_dir):
    """Re-read and extract the complete frozen upload roster; not authority."""
    from . import delivery_authority
    from .round_core.artifacts import CustodyArtifactBytes, verify_custody_zip
    if type(raw_manifest) is not bytes or load_json(raw_manifest) != manifest:
        raise ValueError('custody preupload manifest mismatch')
    check_custody_manifest(manifest)
    expected = [(role, part['part']) for role in SEGMENT_ROLES for part in manifest['files'][role]]
    names = [f'p11lab-image-custody-{role}-part{part}-{run["run_id"]}-{run["attempt"]}' for role, part in expected]
    if (type(uploads) is not list or len(uploads) != len(names)
            or any(type(row) is not dict or set(row) != {'name', 'id', 'digest'}
                   or type(row['name']) is not str or type(row['id']) is not int or row['id'] <= 0
                   or type(row['digest']) is not str or not re.fullmatch(r'sha256:[0-9a-f]{64}', row['digest'])
                   for row in uploads)
            or len({row['id'] for row in uploads}) != len(uploads)
            or [row['name'] for row in uploads] != names):
        raise ValueError('custody uploaded part roster mismatch')
    roster = [{'id': row['id'], 'name': row['name']} for row in uploads]
    first_roster = transport.resolve_custody_roster(run['run_id'], roster)
    base = {'run_id': run['run_id'], 'attempt': run['attempt'], 'workflow_id': profile['workflow_id'],
            'repository_id': profile['repository_id'], 'owner_id': profile['owner_id'],
            'head_sha': profile['source_sha'], 'job_name': run['job'], 'job_id': run['job_id']}
    selectors = [base | {'artifact_id': item['id'], 'name': item['name']} for item in uploads]
    metadata = [transport.resolve_active_custody(selector, now=delivery_authority._clock()) for selector in selectors]
    if any(row['job_count'] != 1 or row['job']['id'] != run['job_id'] for row in metadata):
        raise ValueError('custody active upload job mismatch')
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=False)
    rows, retained = [], []
    for index, ((role, number), upload, observed) in enumerate(zip(expected, uploads, metadata)):
        item = observed['artifact']
        if item['digest'] != upload['digest']:
            raise ValueError('custody upload digest differs from independent metadata')
        identity = CustodyArtifactBytes(item['id'], item['size_in_bytes'], item['digest'])
        archive = output / (role + '-part' + str(number) + '.zip')
        transport.download_custody(identity, archive)
        verify_custody_zip(archive, identity)
        expected_files = dict(manifest['files'][role][number - 1]['files'])
        if index == 0:
            expected_files['custody-manifest.json'] = {'size': len(raw_manifest), 'sha256': hashlib.sha256(raw_manifest).hexdigest()}
        extracted = output / (role + '-part' + str(number))
        extract_custody_archive(archive, expected_files, extracted)
        retained.append((archive, identity, extracted, expected_files))
        rows.append({'role': role, 'part': number, 'id': identity.id, 'name': upload['name'],
                     'size': identity.size, 'digest': identity.digest})
    check_segment_roster(rows, run_id=run['run_id'], attempt=run['attempt'])
    later = [transport.resolve_active_custody(selector, now=delivery_authority._clock()) for selector in selectors]
    if later != metadata or transport.resolve_custody_roster(run['run_id'], roster) != first_roster:
        raise ValueError('custody active upload metadata changed')
    for archive, identity, extracted, expected_files in retained:
        verify_custody_zip(archive, identity)
        _verify_extracted_part(extracted, expected_files)
    return rows


def _same_planner_selection(original, replay):
    """Compare the fixed selection, retaining each path-bound stdout identity."""
    keys = {'files', 'evaluator_source_sha256', 'stdout_sha256', 'evaluator_receipt_sha256'}
    if (type(original) is not dict or type(replay) is not dict
            or set(original) != keys or set(replay) != keys
            or any(type(value.get('stdout_sha256')) is not str
                   or not re.fullmatch(r'[0-9a-f]{64}', value['stdout_sha256']) for value in (original, replay))):
        return False
    return all(original[key] == replay[key] for key in ('files', 'evaluator_source_sha256', 'evaluator_receipt_sha256'))


def verify_custody_producer(*, environment, channel, artifact, evidence_dir, validation_dir,
                            build_receipt, sealed_dir, registry, seal_digest, content_digest,
                            context_path, bundle_path, executable, trusted_root, run_id, attempt,
                            token, validation_policy, component_sources, output_dir):
    """Recompute active D, inspect fixed components and verify each source first.

    This returns only local preconditions. A later save must revalidate mutable
    identities and active authority before use; no upload is authorized here.
    """
    from dataclasses import asdict
    from . import delivery_authority
    from .checker import load_profile
    from .round_core.evaluator_replay import _input_identity, observe_local_evaluator

    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=False)
    admission_args = dict(environment=environment, channel=channel, artifact=artifact, evidence_dir=evidence_dir,
        validation_dir=validation_dir, build_receipt=build_receipt, sealed_dir=sealed_dir, registry=registry,
        seal_digest=seal_digest, content_digest=content_digest, context_path=context_path, bundle_path=bundle_path,
        executable=executable, trusted_root=trusted_root, run_id=run_id, attempt=attempt, token=token,
        validation_policy=validation_policy)
    admitted = delivery_authority.admit_source(**admission_args, output_dir=output / 'source-before')
    if admitted.get('role') != 'active-source-admission' or admitted.get('source_status') != 'eligible':
        raise ValueError('actual active source admission incomplete')
    from .custody_authority import _require_custody_graph
    profile = delivery_authority.load_profile(environment, channel)
    _require_custody_graph(profile)
    delivery_authority._authenticate_live_run(profile, run_id, attempt, token, shard_journal=output / 'shard-graph-standalone.json')
    facts = admitted['facts']
    derived = read_validation_compositions(Path(validation_dir) / 'package.tar.gz',
        facts['validation']['package_sha256'], artifact, evaluator_inputs_dir=output / 'evaluator-originals')
    components = _producer_component_artifacts(validation_policy, artifact, derived)
    if (type(component_sources) is not dict or set(component_sources) != set(components)
            or any(type(row) is not dict or set(row) != {'evidence_dir', 'manifest_sha256'}
                   or type(row['manifest_sha256']) is not str or not re.fullmatch(r'[0-9a-f]{64}', row['manifest_sha256'])
                   for row in component_sources.values())):
        raise ValueError('incomplete fixed custody component source roster')
    sources = []
    for name in sorted(components):
        source = component_sources[name]
        tool_config = validation_policy['tools'][name.removesuffix('-root')] if name.endswith('-root') else None
        image_source = component_sources.get('consumer-image')
        consumer_binding = (_consumer_image_binding(components[name], tool_config, image_source['evidence_dir'],
            output / 'consumer-readback-prerequisite', registry=registry, manifest_sha256=image_source['manifest_sha256'])
            if _consumer_binding_needed(name, components[name]) else None)
        checked = verify_custody_component_source(name, components[name], evidence_dir=source['evidence_dir'],
            registry=registry, manifest_sha256=source['manifest_sha256'], output_dir=output / ('source-' + name),
            tool_config=tool_config, consumer_binding=consumer_binding)
        identity = asdict(components[name])
        if identity['kind'] in ('custody-tree', 'custody-evaluator-metadata'):
            identity['reference'] = 'sha256:' + identity['sha256']
        source_keys = ('reference', 'manifest_sha256', 'file_sha256', 'receipt_sha256', 'spdx_sha256',
                       'inventory_sha256', 'source_archive_size')
        sources.append({'name': name, 'artifact': identity, 'review_sha256': checked['review_sha256'],
                        'source': {key: checked[key] for key in source_keys}})
    check_component_facts(sources)
    original = output / 'evaluator-originals'
    evaluator = validation_policy['evaluator']
    observed = observe_local_evaluator(Path(evaluator['root']), evaluator['receipt_sha256'],
        set(load_profile()['sources']), original / 'checker-input', original / 'frozen-plan.json', output / 'evaluator-observation')
    observation = observed.as_dict()
    if (not _same_planner_selection(observation['planner'], load_json((original / 'original/planner.json').read_bytes()))
            or observation['admission'] != load_json((original / 'original/admission.json').read_bytes())
            or observation['ledger'] != _input_identity(original / 'original/ledger.jsonl')):
        raise ValueError('producer evaluator result differs from original validation evidence')
    after = delivery_authority.admit_source(**admission_args, output_dir=output / 'source-after')
    if (after.get('role') != 'active-source-admission' or after.get('source_status') != 'eligible'
            or after['facts'] != facts or after['context_sha256'] != admitted['context_sha256']
            or after['protection'] != admitted['protection']):
        raise ValueError('active source admission changed during component checks')
    if _producer_component_artifacts(validation_policy, artifact, derived) != components:
        raise ValueError('custody producer components changed during verification')
    return VerifiedCustodyProducer(_PRODUCER_KEY, {'schema_version': 1, 'kind': 'active-custody-preconditions',
        'facts': facts, 'components': sources, 'evaluator': observation,
        'qualification_only': True, 'image_promotable': False, 'output_dir': str(output.absolute())})


def _sealed_file_record(path, limit):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= limit:
            raise ValueError('unsafe or oversized custody file')
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        after, current = os.fstat(stream.fileno()), os.stat(path, follow_symlinks=False)
        def identity(value):
            return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
                    value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if identity(before) != identity(after) or identity(after) != identity(current):
            raise ValueError('custody file changed while hashing')
        return {'size': before.st_size, 'sha256': digest}


def _preflight_saved_image(stream):
    """Bound the enclosing TAR and every selected layer before inspection."""
    import bz2
    import gzip
    import lzma
    from .licenses import relative_path
    from .jsonutil import loads

    budget = {'metadata': 0, 'headers': 0, 'expanded': 0, 'deadline': time.monotonic() + 120}

    class ImageOuterTarInfo(_CustodyContainerTarInfo):
        _pax_keys = frozenset((b'path', b'linkpath', b'mtime', b'atime', b'ctime',
                               b'uid', b'gid', b'uname', b'gname', b'size'))

    class ImageTarInfo(ImageOuterTarInfo):
        @classmethod
        def _fromtarfile(cls, archive, *, dircheck=True):
            budget['headers'] += 1
            if budget['headers'] > _TAR_HEADER_LIMIT or time.monotonic() > budget['deadline']:
                raise ValueError('custody image tar header count or deadline bound')
            return super()._fromtarfile(archive, dircheck=dircheck)

        def _metadata(self, archive):
            if not 0 <= self.size <= _TAR_METADATA_RECORD_LIMIT:
                raise ValueError('custody tar metadata record byte bound')
            budget['metadata'] += self.size
            if budget['metadata'] > _TAR_METADATA_TOTAL_LIMIT:
                raise ValueError('custody image tar aggregate metadata byte bound')
            return super()._metadata(archive)

    class LayerReader(_BoundedTarReader):
        def read(self, size):
            if type(size) is not int or size < 0 or time.monotonic() > budget['deadline']:
                raise ValueError('custody image tar deadline or read bound')
            block = super().read(min(size, _TAR_STREAM_LIMIT + 1 - budget['expanded']))
            budget['expanded'] += len(block)
            if budget['expanded'] > _TAR_STREAM_LIMIT or time.monotonic() > budget['deadline']:
                raise ValueError('custody image layer aggregate stream byte or deadline bound')
            return block

    class XZReader:
        """Decode one XZ stream with an explicit dictionary memory ceiling."""
        def __init__(self, source):
            self.source = source
            self.decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=128 * 1024**2)
            self.finished = False

        def read(self, size):
            if type(size) is not int or size < 0:
                raise ValueError('invalid custody XZ read bound')
            result = bytearray()
            target = min(size, 65536)
            while len(result) < target and not self.finished:
                if time.monotonic() > budget['deadline']:
                    raise ValueError('custody XZ stream deadline')
                if self.decoder.eof:
                    trailing = self.decoder.unused_data
                    length = len(trailing)
                    if any(trailing):
                        raise ValueError('unexpected trailing or concatenated custody XZ data')
                    while chunk := self.source.read(65536):
                        length += len(chunk)
                        if any(chunk) or time.monotonic() > budget['deadline']:
                            raise ValueError('unexpected trailing or late custody XZ data')
                    if length % 4:
                        raise ValueError('invalid custody XZ stream padding')
                    self.finished = True
                    break
                chunk = self.source.read(65536) if self.decoder.needs_input else b''
                if not chunk and self.decoder.needs_input:
                    raise ValueError('truncated custody XZ stream')
                try:
                    decoded = self.decoder.decompress(chunk, max_length=target - len(result))
                except lzma.LZMAError as error:
                    raise ValueError('custody XZ decoder memory or format failure: ' + str(error)) from error
                result.extend(decoded)
                if not decoded and not self.decoder.needs_input and not self.decoder.eof:
                    raise ValueError('stalled custody XZ decoder')
            return bytes(result)

        def close(self):
            pass

    def finish(archive, bounded):
        if any(archive.fileobj.buf):
            raise ValueError('unexpected trailing custody image tar data')
        while tail := bounded.read(65536):
            if any(tail):
                raise ValueError('unexpected trailing custody image tar data')

    stream.seek(0)
    outer = _BoundedTarReader(stream)
    names, manifest_raw = set(), None
    with tarfile.open(fileobj=outer, mode='r|', tarinfo=ImageTarInfo) as archive:
        for member in archive:
            name = relative_path(member.name.rstrip('/'))
            if name in names or len(names) >= 10000:
                raise ValueError('duplicate or oversized custody image tar roster')
            names.add(name)
            if member.size > CUSTODY_TOTAL_LIMIT:
                raise ValueError('custody image tar member byte bound')
            if name == 'manifest.json':
                if not member.isfile() or member.size > 1024 * 1024:
                    raise ValueError('invalid custody image manifest')
                source = archive.extractfile(member)
                if source is None:
                    raise ValueError('missing custody image manifest')
                manifest_raw = source.read(member.size + 1)
                if len(manifest_raw) != member.size:
                    raise ValueError('truncated custody image manifest')
        finish(archive, outer)
    if manifest_raw is None:
        raise ValueError('missing custody image manifest')
    value = loads(manifest_raw)
    if (type(value) is not list or len(value) != 1 or type(value[0]) is not dict
            or type(value[0].get('Layers')) is not list or len(value[0]['Layers']) > 10000
            or value[0].get('RepoTags') not in (None, [])):
        raise ValueError('invalid custody image manifest or mutable tags')
    layers = set()
    for item in value[0]['Layers']:
        if type(item) is not str or relative_path(item) != item or item not in names:
            raise ValueError('invalid custody image layer roster')
        layers.add(item)

    stream.seek(0)
    outer = _BoundedTarReader(stream)
    seen = set()
    with tarfile.open(fileobj=outer, mode='r|', tarinfo=ImageOuterTarInfo) as archive:
        for member in archive:
            if member.name not in layers:
                continue
            if not member.isfile() or member.name in seen:
                raise ValueError('missing or ambiguous custody image layer')
            seen.add(member.name)
            source = archive.extractfile(member)
            if source is None:
                raise ValueError('missing custody image layer')
            prefix = source.read(6)
            wrapped = _TarPrefix(source, prefix)
            if prefix.startswith(b'\x1f\x8b'):
                decompressed = gzip.GzipFile(fileobj=wrapped, mode='rb')
            elif prefix.startswith(b'BZh'):
                decompressed = bz2.BZ2File(wrapped, mode='rb')
            elif prefix.startswith(b'\xfd7zXZ\x00'):
                decompressed = XZReader(wrapped)
            else:
                decompressed = wrapped
            bounded = LayerReader(decompressed)
            with tarfile.open(fileobj=bounded, mode='r|', tarinfo=ImageTarInfo) as layer:
                for _ in layer:
                    pass
                finish(layer, bounded)
            if decompressed is not wrapped:
                decompressed.close()
        finish(archive, outer)
    if seen != layers:
        raise ValueError('incomplete custody image layer roster')


def _inspect_saved_image(path, *, tool_image=False):
    """Inspect the same opened save bytes whose identity is returned."""
    import tarfile
    from .jsonutil import loads
    from .licenses import inspect_distribution_archive
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if type(tool_image) is not bool:
            raise ValueError('invalid custody image archive role')
        limit = CUSTODY_TOTAL_LIMIT if tool_image else CUSTODY_MEMBER_LIMIT
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= limit:
            raise ValueError('unsafe or oversized custody image archive')
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        try:
            _preflight_saved_image(stream)
            fd_path = Path('/proc/self/fd') / str(stream.fileno())
            observed = inspect_distribution_archive(fd_path, [])
            with tarfile.open(fd_path, 'r:') as archive:
                manifest = archive.getmember('manifest.json')
                if not manifest.isfile() or manifest.size > 1024 * 1024:
                    raise ValueError('invalid custody image manifest')
                source = archive.extractfile(manifest)
                if source is None:
                    raise ValueError('missing custody image manifest')
                raw_manifest = source.read(manifest.size + 1)
                if len(raw_manifest) != manifest.size:
                    raise ValueError('truncated custody image manifest')
                value = loads(raw_manifest)
                if (type(value) is not list or len(value) != 1 or type(value[0]) is not dict
                        or value[0].get('RepoTags') not in (None, [])):
                    raise ValueError('custody image archive carries mutable tags')
        except (tarfile.TarError, KeyError, TypeError) as error:
            raise ValueError('invalid custody image archive') from error
        stream.seek(0)
        repeated = hashlib.file_digest(stream, 'sha256').hexdigest()
        after, current = os.fstat(stream.fileno()), os.stat(path, follow_symlinks=False)
        def identity(value):
            return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
                    value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if digest != repeated or identity(before) != identity(after) or identity(after) != identity(current):
            raise ValueError('custody image archive changed during inspection')
        return observed, {'size': before.st_size, 'sha256': digest}


def _check_saved_image_binding(artifact, distribution):
    """Bind the engine identity through the inspected OCI descriptor graph."""
    try:
        if distribution['platform'] != artifact.platform:
            raise ValueError('saved image platform mismatch')
        config = 'sha256:' + distribution['config_sha256']
        if artifact.reference == config:
            return
        descriptors = distribution['raw_descriptors']
        if type(descriptors) is not list or len(descriptors) > 10000:
            raise ValueError('invalid image descriptor roster')
        records = {'sha256:' + row['sha256']: row['document'] for row in descriptors}
        if len(records) != len(descriptors):
            raise ValueError('duplicate image descriptor')
        expected_layers = ['sha256:' + layer['sha256'] for layer in distribution['layers']]
        pending, seen, reached = [artifact.reference], set(), False
        while pending:
            digest = pending.pop()
            if digest in seen:
                continue
            seen.add(digest)
            document = records.get(digest)
            if type(document) is not dict:
                raise ValueError('missing image descriptor in saved graph')
            if (document.get('config', {}).get('digest') == config
                    and [row['digest'] for row in document.get('layers', [])] == expected_layers):
                reached = True
            pending.extend(row['digest'] for row in document.get('manifests', []))
        if not reached:
            raise ValueError('image descriptor does not reach exact config and layers')
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError('malformed saved image descriptor graph') from error


class _CappedWriter:
    def __init__(self, stream):
        self.stream, self.count = stream, 0

    def write(self, data):
        if self.count + len(data) > CUSTODY_MEMBER_LIMIT:
            raise ValueError('custody archive member byte bound')
        count = self.stream.write(data)
        self.count += count
        return count

    def flush(self):
        self.stream.flush()

    def tell(self):
        return self.count


def _gzip_verified_file(source, destination):
    """Compress one bounded local save and verify its complete round trip."""
    import gzip
    source, destination = Path(source), Path(destination)
    if source.absolute() == destination.absolute():
        raise ValueError('custody archive input/output alias')
    original = _sealed_file_record(source, CUSTODY_TOTAL_LIMIT)
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as reader, destination.open('xb') as target:
        with gzip.GzipFile(fileobj=_CappedWriter(target), mode='wb', filename='', mtime=0) as compressed:
            while block := reader.read(65536):
                compressed.write(block)
    if _sealed_file_record(source, CUSTODY_TOTAL_LIMIT) != original:
        raise ValueError('custody archive changed while compressing')
    result = _sealed_file_record(destination, CUSTODY_MEMBER_LIMIT)
    digest, size = hashlib.sha256(), 0
    with gzip.open(destination, 'rb') as reader:
        while block := reader.read(65536):
            size += len(block)
            if size > original['size']:
                raise ValueError('custody compressed archive expanded unexpectedly')
            digest.update(block)
    if (size != original['size'] or digest.hexdigest() != original['sha256']
            or _sealed_file_record(destination, CUSTODY_MEMBER_LIMIT) != result):
        raise ValueError('custody compressed archive differs from original')
    return result


def _observe_tool_archive(path):
    """Inventory every inert member of one generated tool filesystem tar."""
    from . import licenses
    initial = _sealed_file_record(path, CUSTODY_MEMBER_LIMIT)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    rows, seen, total = [], set(), 0
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if (before.st_size != initial['size'] or hashlib.file_digest(stream, 'sha256').hexdigest() != initial['sha256']):
            raise ValueError('tool archive changed before inspection')
        stream.seek(0)
        bounded = _BoundedTarReader(stream)
        try:
            with tarfile.open(fileobj=bounded, mode='r|', tarinfo=_CustodyContainerTarInfo) as archive:
                for member in archive:
                    name = member.name.removeprefix('./')
                    if name == '.':
                        name = ''
                    if name:
                        licenses.relative_path(name)
                    elif not member.isdir():
                        raise ValueError('invalid tool archive root entry')
                    if name in seen or len(seen) >= 100000 or member.mode & ~0o7777:
                        raise ValueError('duplicate or invalid tool archive member')
                    seen.add(name)
                    row = {'path': '/' + name, 'mode': member.mode}
                    if member.isdir():
                        row['type'] = 'directory'
                    elif member.issym():
                        if not member.linkname or '\x00' in member.linkname or len(os.fsencode(member.linkname)) > 4096:
                            raise ValueError('invalid tool archive symbolic link')
                        row.update(type='symlink', target=member.linkname)
                    elif member.islnk():
                        target = member.linkname.removeprefix('./')
                        licenses.relative_path(target)
                        row.update(type='hardlink', target='/' + target)
                    elif member.ischr() or member.isblk():
                        if member.devmajor < 0 or member.devminor < 0:
                            raise ValueError('invalid tool archive device')
                        row.update(type='character' if member.ischr() else 'block', major=member.devmajor, minor=member.devminor)
                    elif member.isfile():
                        total += member.size
                        if member.size > CUSTODY_MEMBER_LIMIT or total > CUSTODY_TOTAL_LIMIT:
                            raise ValueError('tool archive expanded byte bound')
                        content = archive.extractfile(member)
                        if content is None:
                            raise ValueError('tool archive file missing')
                        row.update(type='file', size=member.size, sha256=hashlib.file_digest(content, 'sha256').hexdigest())
                    else:
                        raise ValueError('unsupported tool archive member')
                    rows.append(row)
                if any(archive.fileobj.buf):
                    raise ValueError('unexpected trailing tool archive data')
            while tail := bounded.read(65536):
                if any(tail):
                    raise ValueError('unexpected trailing tool archive data')
        except tarfile.TarError as error:
            raise ValueError('invalid tool archive') from error
        stream.seek(0)
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        after, current = os.fstat(stream.fileno()), os.stat(path, follow_symlinks=False)
        def identity(value):
            return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
                    value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if digest != initial['sha256'] or identity(before) != identity(after) or identity(after) != identity(current):
            raise ValueError('tool archive changed while inspecting')
    by_path = {row['path']: row for row in rows}
    for row in rows:
        if row['type'] != 'hardlink':
            continue
        target, chain = row['target'], set()
        while target in by_path and by_path[target]['type'] == 'hardlink':
            if target in chain:
                raise ValueError('cyclic tool archive hardlink')
            chain.add(target)
            target = by_path[target]['target']
        if target not in by_path or by_path[target]['type'] != 'file':
            raise ValueError('tool archive hardlink target missing')
    return {'archive': initial, 'members': sorted(rows, key=lambda item: item['path']),
            'scope': 'inert regular bytes, modes, links, directories and device topology'}


def _check_tool_archive_review(artifact, spec, inventory):
    """Apply existing source/grant validation to every reviewed tar member."""
    import copy
    from dataclasses import asdict
    from . import licenses
    if (artifact.kind != 'custody-tree' or type(spec) is not dict
            or set(spec) != {'path', 'members', 'content_reviews'} or type(spec['path']) is not str
            or type(spec['members']) is not list or type(spec['content_reviews']) is not list):
        raise ValueError('invalid protected tool archive review')
    relative = licenses.relative_path(spec['path'])
    original = licenses.inspect_artifact(artifact)
    observed = _observe_tool_archive(Path(artifact.reference) / relative)
    if observed['members'] != spec['members']:
        raise ValueError('tool archive differs from protected expected member closure')
    by_path = {row['path']: row for row in observed['members']}
    files = []
    for row in observed['members']:
        if row['type'] not in ('file', 'hardlink'):
            continue
        target = row
        while target['type'] == 'hardlink':
            target = by_path[target['target']]
        files.append({'path': row['path'], 'sha256': target['sha256'], 'size': target['size'],
                      'mode': row['mode'], 'package': None})
    expected_reviews = {(row['path'], row['sha256']) for row in files}
    try:
        claimed_reviews = {(row['path'], row['sha256']) for row in spec['content_reviews']}
    except (KeyError, TypeError) as error:
        raise ValueError('malformed protected tool archive member reviews') from error
    if len(spec['content_reviews']) != len(files) or claimed_reviews != expected_reviews:
        raise ValueError('unreviewed or extra tool archive member content')
    nested = copy.deepcopy(inventory)
    nested['artifact'] = asdict(artifact)
    nested['observation'] = {'artifact': asdict(artifact), 'files': files, 'packages': [],
                             'binaries': [], 'linked_libraries': []}
    nested['content_reviews'] = copy.deepcopy(spec['content_reviews'])
    nested.pop('package_archives', None)
    nested.pop('package_files', None)
    nested.pop('layer_reviews', None)
    reasons = licenses.validate_inventory(artifact, nested)
    if reasons:
        raise ValueError('tool archive source review incomplete: ' + '; '.join(reasons))
    if licenses.inspect_artifact(artifact) != original:
        raise ValueError('tool tree changed during archive review')
    return observed['archive']


def _save_verified_tool_image(artifact, output_dir):
    """Save and recheck an exact tool or derivative image into a fresh directory."""
    import json
    from .docker import Docker
    from .inspection_bounded import bounded_stream
    from .models import ArtifactRef

    if (type(artifact) is not ArtifactRef or artifact.kind != 'docker-local'
            or artifact.reference != 'sha256:' + artifact.sha256 or artifact.platform != 'linux/amd64'):
        raise ValueError('invalid exact custody tool image identity')
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=False)
    record = {'status': 'incomplete', 'transfer': {}}
    try:
        docker = Docker()
        first = docker.image(artifact)
        raw, compressed = output / 'image.tar', output / 'image.tar.gz'
        bounded_stream(['docker', 'image', 'save', artifact.reference], raw, CUSTODY_TOTAL_LIMIT,
                       120, docker.env, record['transfer'])
        distribution, raw_record = _inspect_saved_image(raw, tool_image=True)
        _check_saved_image_binding(artifact, distribution)
        if [row['diff_id'] for row in distribution['layers']] != first.get('RootFS', {}).get('Layers'):
            raise ValueError('custody tool image archive differs from local engine')
        compressed_record = _gzip_verified_file(raw, compressed)
        second = docker.image(artifact)
        if (first.get('Id') != second.get('Id') or first.get('RootFS') != second.get('RootFS')
                or first.get('Os') != second.get('Os') or first.get('Architecture') != second.get('Architecture')
                or _sealed_file_record(raw, CUSTODY_TOTAL_LIMIT) != raw_record):
            raise ValueError('custody tool image changed during save')
        record['status'] = 'complete-local-save'
        return compressed_record
    except BaseException as error:
        record['error_type'] = type(error).__name__
        raise
    finally:
        (output / 'save-journal.json').write_text(json.dumps(record, sort_keys=True, indent=2) + '\n')


def _inspect_compressed_tool_image(archive, archive_identity, artifact, raw):
    """Expand and inspect a bounded exact tool save, without loading it."""
    import gzip
    from .models import ArtifactRef
    if (type(artifact) is not ArtifactRef or artifact.kind != 'docker-local'
            or artifact.reference != 'sha256:' + artifact.sha256 or artifact.platform != 'linux/amd64'
            or _sealed_file_record(archive, CUSTODY_MEMBER_LIMIT) != archive_identity):
        raise ValueError('custody tool archive identity mismatch')
    descriptor = os.open(archive, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as source:
        before = os.fstat(source.fileno())
        if (before.st_size != archive_identity['size']
                or hashlib.file_digest(source, 'sha256').hexdigest() != archive_identity['sha256']):
            raise ValueError('custody tool archive changed before expansion')
        source.seek(0)
        deadline, total = time.monotonic() + 120, 0
        with gzip.GzipFile(fileobj=source, mode='rb') as compressed, Path(raw).open('xb') as target:
            while block := compressed.read(65536):
                total += len(block)
                if total > CUSTODY_TOTAL_LIMIT or time.monotonic() > deadline:
                    raise ValueError('custody tool image expanded byte or deadline bound')
                target.write(block)
        source.seek(0)
        repeated = hashlib.file_digest(source, 'sha256').hexdigest()
        after, current = os.fstat(source.fileno()), os.stat(archive, follow_symlinks=False)
        def identity(value):
            return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
                    value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if repeated != archive_identity['sha256'] or identity(before) != identity(after) or identity(after) != identity(current):
            raise ValueError('custody tool archive changed during expansion')
    distribution, raw_identity = _inspect_saved_image(raw, tool_image=True)
    _check_saved_image_binding(artifact, distribution)
    return distribution, raw_identity


def _restore_component_image(archive, archive_identity, artifact, output_dir):
    """Restore one exact authenticated fixed-tool image without executing it."""
    import json
    from .docker import Docker
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=False)
    journal = {'status': 'incomplete', 'load': None, 'cleanup': 'not-applicable-before-load'}
    try:
        raw = output / 'image.tar'
        distribution, raw_identity = _inspect_compressed_tool_image(archive, archive_identity, artifact, raw)
        def identity(value):
            return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
                    value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        docker = Docker()
        context = docker.env.get('DOCKER_CONTEXT')
        endpoint = docker.env.get('DOCKER_HOST') if not context else None
        if not endpoint:
            endpoint = json.loads(docker.command(['context', 'inspect', *([context] if context else []),
                '--format', '{{json .Endpoints.docker.Host}}']).stdout)
        if not isinstance(endpoint, str) or not endpoint.startswith('unix://'):
            raise ValueError('custody tool image load requires a same-host local Unix Docker daemon')
        descriptor = os.open(raw, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as stream:
            before = os.fstat(stream.fileno())
            if (before.st_size != raw_identity['size']
                    or hashlib.file_digest(stream, 'sha256').hexdigest() != raw_identity['sha256']):
                raise ValueError('custody tool image changed before loading')
            fd_path = '/proc/' + str(os.getpid()) + '/fd/' + str(stream.fileno())
            journal['cleanup'] = 'load-attempt-may-have-retained-image'
            native = docker.command(['image', 'load', '--input', fd_path], timeout=120, check=False)
            journal['load'] = {'returncode': native.returncode, 'timed_out': native.timed_out,
                'stdout': native.stdout, 'stderr': native.stderr, 'stdout_truncated': native.stdout_truncated,
                'stderr_truncated': native.stderr_truncated}
            if native.returncode or native.timed_out or native.stdout_truncated or native.stderr_truncated:
                raise ValueError('native custody tool image load incomplete')
            stream.seek(0)
            repeated = hashlib.file_digest(stream, 'sha256').hexdigest()
            after, current = os.fstat(stream.fileno()), os.stat(raw, follow_symlinks=False)
            if repeated != raw_identity['sha256'] or identity(before) != identity(after) or identity(after) != identity(current):
                raise ValueError('custody tool image changed during load')
        observed = docker.image(artifact)
        if observed.get('RootFS', {}).get('Layers') != [row['diff_id'] for row in distribution['layers']]:
            raise ValueError('loaded custody tool image layers mismatch')
        if _sealed_file_record(archive, CUSTODY_MEMBER_LIMIT) != archive_identity:
            raise ValueError('custody tool archive changed during load')
        journal['status'], journal['cleanup'] = 'complete-inert-load-only', 'image-retained-for-source-replay'
        return {'engine_id': artifact.reference, 'archive': dict(archive_identity), 'raw_archive': raw_identity}
    except BaseException as error:
        journal['error_type'] = type(error).__name__
        raise
    finally:
        (output / 'load-journal.json').write_text(json.dumps(journal, sort_keys=True, indent=2) + '\n')


def _pack_verified_tree(artifact, destination):
    """Pack one measured tool tree, then independently check every tar member."""
    import gzip
    import tarfile
    from . import licenses
    if artifact.kind != 'custody-tree':
        raise ValueError('a measured custody tree is required')
    if Path(destination).absolute().is_relative_to(Path(artifact.reference).resolve(strict=True)):
        raise ValueError('custody tree archive overlaps input')
    original = licenses.inspect_artifact(artifact)
    entries = original['tree_entries']
    if sum(row.get('size', 0) for row in entries) > CUSTODY_TOTAL_LIMIT:
        raise ValueError('custody tree expanded byte bound')

    root = Path(artifact.reference)
    with Path(destination).open('xb') as raw:
        capped = _CappedWriter(raw)
        with gzip.GzipFile(fileobj=capped, mode='wb', filename='', mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w|') as bundle:
                for row in entries:
                    name = row['path'].removeprefix('/')
                    licenses.relative_path(name)
                    info = tarfile.TarInfo(name)
                    info.mode, info.uid, info.gid, info.mtime = row['mode'], 0, 0, 0
                    info.uname = info.gname = ''
                    if row['type'] == 'directory':
                        info.type = tarfile.DIRTYPE
                        bundle.addfile(info)
                    elif row['type'] == 'symlink':
                        info.type, info.linkname = tarfile.SYMTYPE, row['target']
                        bundle.addfile(info)
                    elif row['type'] == 'file':
                        descriptor = os.open(root / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                        with os.fdopen(descriptor, 'rb') as stream:
                            before = os.fstat(stream.fileno())
                            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                                    or before.st_size != row['size'] or stat.S_IMODE(before.st_mode) != row['mode']):
                                raise ValueError('custody tree member changed while packing')
                            info.size = row['size']
                            bundle.addfile(info, stream)
                            after = os.fstat(stream.fileno())
                            current = os.stat(root / name, follow_symlinks=False)
                            def identity(value):
                                return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
                                        value.st_size, value.st_mtime_ns, value.st_ctime_ns)
                            if identity(before) != identity(after) or identity(after) != identity(current):
                                raise ValueError('custody tree member changed while packing')
                    else:
                        raise ValueError('unsupported custody tree member')
    record = _sealed_file_record(destination, CUSTODY_MEMBER_LIMIT)
    expected = {row['path'].removeprefix('/'): row for row in entries}
    seen = set()
    with gzip.open(destination, 'rb') as decompressed:
        bounded = _BoundedTarReader(decompressed)
        with tarfile.open(fileobj=bounded, mode='r|', tarinfo=_CustodyTarInfo) as bundle:
            for member in bundle:
                if member.name not in expected or member.name in seen:
                    raise ValueError('custody tree archive roster mismatch')
                seen.add(member.name)
                row = expected[member.name]
                if member.mode != row['mode']:
                    raise ValueError('custody tree archive mode mismatch')
                if row['type'] == 'directory':
                    if not member.isdir():
                        raise ValueError('custody tree archive directory mismatch')
                elif row['type'] == 'symlink':
                    if not member.issym() or member.linkname != row['target']:
                        raise ValueError('custody tree archive link mismatch')
                else:
                    if not member.isfile() or member.size != row['size']:
                        raise ValueError('custody tree archive file mismatch')
                    stream = bundle.extractfile(member)
                    if stream is None or hashlib.file_digest(stream, 'sha256').hexdigest() != row['sha256']:
                        raise ValueError('custody tree archive member digest mismatch')
            if any(bundle.fileobj.buf):
                raise ValueError('unexpected trailing custody tar data')
        while tail := bounded.read(65536):
            if any(tail):
                raise ValueError('unexpected trailing custody tar data')
    if seen != set(expected) or _sealed_file_record(destination, CUSTODY_MEMBER_LIMIT) != record:
        raise ValueError('custody tree archive changed during verification')
    if licenses.inspect_artifact(artifact) != original:
        raise ValueError('custody tree changed during packing')
    return record


def _unpack_verified_tree(archive, archive_identity, tree_sha256, output_dir):
    """Restore one closed tree without following links or using old root paths."""
    import tarfile
    from . import licenses
    if (type(archive_identity) is not dict or set(archive_identity) != {'size', 'sha256'}
            or type(tree_sha256) is not str or not re.fullmatch(r'[0-9a-f]{64}', tree_sha256)
            or _sealed_file_record(archive, CUSTODY_MEMBER_LIMIT) != archive_identity):
        raise ValueError('custody tree archive identity mismatch')
    output = Path(output_dir).absolute()
    if Path(archive).absolute().is_relative_to(output):
        raise ValueError('custody tree output overlaps archive')
    output.mkdir(parents=True, exist_ok=False)
    root_fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    directories, modes, seen, total = {''}, {}, set(), 0

    def parent_fd(parts):
        descriptor = os.dup(root_fd)
        try:
            for name in parts:
                next_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                  dir_fd=descriptor)
                os.close(descriptor)
                descriptor = next_fd
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    try:
        archive_fd = os.open(archive, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(archive_fd, 'rb') as archive_stream:
            before = os.fstat(archive_stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size != archive_identity['size']
                    or hashlib.file_digest(archive_stream, 'sha256').hexdigest() != archive_identity['sha256']):
                raise ValueError('custody tree opened archive identity mismatch')
            archive_stream.seek(0)
            import gzip
            with gzip.GzipFile(fileobj=archive_stream, mode='rb') as decompressed:
                bounded = _BoundedTarReader(decompressed)
                with tarfile.open(fileobj=bounded, mode='r|', tarinfo=_CustodyTarInfo) as bundle:
                    for member in bundle:
                        name = licenses.relative_path(member.name)
                        if name in seen or len(seen) >= 100000:
                            raise ValueError('duplicate or oversized custody tree roster')
                        seen.add(name)
                        parts = name.split('/')
                        parent = '/'.join(parts[:-1])
                        if parent not in directories:
                            raise ValueError('custody tree parent directory missing')
                        if member.mode & ~0o7777:
                            raise ValueError('invalid custody tree mode')
                        descriptor = parent_fd(parts[:-1])
                        try:
                            if member.isdir():
                                os.mkdir(parts[-1], 0o700, dir_fd=descriptor)
                                directories.add(name)
                                modes[name] = member.mode
                            elif member.issym():
                                target = member.linkname
                                if not target or target.startswith('/') or '\\' in target or '\x00' in target:
                                    raise ValueError('custody tree link is foreign or unsafe')
                                stack = list(parts[:-1])
                                for item in target.split('/'):
                                    if item == '..':
                                        if not stack:
                                            raise ValueError('custody tree link escapes root')
                                        stack.pop()
                                    elif item and item != '.':
                                        stack.append(item)
                                os.symlink(target, parts[-1], dir_fd=descriptor)
                            elif member.isfile():
                                total += member.size
                                if member.size > CUSTODY_MEMBER_LIMIT or total > CUSTODY_TOTAL_LIMIT:
                                    raise ValueError('custody tree expanded byte bound')
                                source = bundle.extractfile(member)
                                if source is None:
                                    raise ValueError('custody tree file missing')
                                fd = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                             0o600, dir_fd=descriptor)
                                with os.fdopen(fd, 'wb') as target:
                                    count = 0
                                    while block := source.read(65536):
                                        count += len(block)
                                        if count > member.size:
                                            raise ValueError('custody tree file grew')
                                        target.write(block)
                                    if count != member.size:
                                        raise ValueError('custody tree file truncated')
                                    os.fchmod(target.fileno(), member.mode)
                            else:
                                raise ValueError('unsupported custody tree archive member')
                        finally:
                            os.close(descriptor)
                    if any(bundle.fileobj.buf):
                        raise ValueError('unexpected trailing custody tar data')
                while tail := bounded.read(65536):
                    if any(tail):
                        raise ValueError('unexpected trailing custody tar data')
            archive_stream.seek(0)
            repeated = hashlib.file_digest(archive_stream, 'sha256').hexdigest()
            after, current = os.fstat(archive_stream.fileno()), os.stat(archive, follow_symlinks=False)
            def identity(value):
                return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
                        value.st_size, value.st_mtime_ns, value.st_ctime_ns)
            if repeated != archive_identity['sha256'] or identity(before) != identity(after) or identity(after) != identity(current):
                raise ValueError('custody tree archive changed while extracting')
        for name in sorted(modes, key=lambda item: item.count('/'), reverse=True):
            descriptor = parent_fd(name.split('/'))
            try:
                os.fchmod(descriptor, modes[name])
            finally:
                os.close(descriptor)
    except tarfile.TarError as error:
        raise ValueError('invalid custody tree archive') from error
    finally:
        os.close(root_fd)
    if _sealed_file_record(archive, CUSTODY_MEMBER_LIMIT) != archive_identity:
        raise ValueError('custody tree archive changed during extraction')
    actual = licenses.observe_custody_tree(output, platform='linux/amd64').artifact()
    if actual.sha256 != tree_sha256:
        raise ValueError('restored custody tree identity mismatch')
    return actual


def prepare_custody_image(*, output_dir, **producer_args):
    """Save one exact candidate only after actual D and all component checks.

    A completed segmented payload, external attestation and fresh D remain open.
    Failed attempts retain their exclusive file and bounded native journal.
    """
    import json
    from .docker import Docker
    from .inspection_bounded import bounded_stream
    from .round_core.evaluator_replay import check_runtime_equivalence

    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=False)
    record = {'status': 'incomplete', 'transfer': {}}
    try:
        before = verify_custody_producer(**producer_args, output_dir=output / 'producer-before').as_dict()
        artifact = producer_args['artifact']
        binding = before['facts']['validation']
        docker = Docker()
        first = docker.image(artifact)
        expected_layers = [row['diff_id'] for row in binding['layers']]
        if first.get('RootFS', {}).get('Layers') != expected_layers:
            raise ValueError('candidate image config or layers differ before custody save')
        archive = output / 'image.tar'
        bounded_stream(['docker', 'image', 'save', artifact.reference], archive, CUSTODY_MEMBER_LIMIT,
                       120, docker.env, record['transfer'])
        distribution, archive_record = _inspect_saved_image(archive)
        _check_saved_image_binding(artifact, distribution)
        if (distribution['config_sha256'] != binding['config_sha256']
                or distribution['layers'] != binding['layers'] or distribution['platform'] != artifact.platform):
            raise ValueError('custody image archive differs from admitted candidate')
        second = docker.image(artifact)
        if (first.get('Id') != second.get('Id') or first.get('RootFS') != second.get('RootFS')
                or first.get('Os') != second.get('Os') or first.get('Architecture') != second.get('Architecture')):
            raise ValueError('candidate image changed during custody save')
        after = verify_custody_producer(**producer_args, output_dir=output / 'producer-after').as_dict()
        if before['facts'] != after['facts'] or before['components'] != after['components']:
            raise ValueError('producer source or component facts changed during custody save')
        old, new = before['evaluator'], after['evaluator']
        if (any(old[key] != new[key] for key in ('root', 'receipt_sha256', 'identity_sha256', 'python',
                'native_dependencies', 'raw', 'plan', 'ledger', 'admission', 'driver'))
                or not _same_planner_selection(old['planner'], new['planner'])):
            raise ValueError('producer evaluator changed during custody save')
        check_runtime_equivalence(old['runtime'], new['runtime'], old_root=old['root'], new_root=new['root'])
        if _sealed_file_record(archive, CUSTODY_MEMBER_LIMIT) != archive_record:
            raise ValueError('custody image archive changed after save')
        record['status'] = 'complete-local-image-only'
        return PreparedCustodyImage(_IMAGE_KEY, {'schema_version': 1, 'kind': 'prepared-local-custody-image',
            'artifact': before['facts']['artifact'], 'archive': archive_record, 'facts': before['facts'],
            'components': before['components'], 'evaluator': before['evaluator'], 'output_dir': str(output.absolute()),
            'qualification_only': True, 'image_promotable': False})
    except BaseException as error:
        record['error_type'] = type(error).__name__
        raise
    finally:
        (output / 'image-save-journal.json').write_text(json.dumps(record, sort_keys=True, indent=2) + '\n')


def _copy_custody_file(source, destination, *, expected=None, source_archive=False):
    source, destination = Path(source), Path(destination)
    if type(source_archive) is not bool:
        raise ValueError('invalid source archive copy role')
    limit = 5 * 1024**3 if source_archive else CUSTODY_MEMBER_LIMIT
    original = _sealed_file_record(source, limit)
    if expected is not None and original != expected:
        raise ValueError('custody source file identity mismatch')
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as reader, destination.open('xb') as writer:
        count = 0
        while block := reader.read(65536):
            count += len(block)
            if count > original['size']:
                raise ValueError('custody source file grew during copy')
            writer.write(block)
    if (_sealed_file_record(source, limit) != original or _sealed_file_record(destination, limit) != original):
        raise ValueError('custody source file changed during copy')
    return original


def _pack_component_rights(components, source_root, staging, destination):
    from . import licenses
    staging = Path(staging)
    staging.mkdir(parents=True, exist_ok=False)
    for row in components:
        source = Path(source_root) / ('source-' + row['name'])
        base = staging / row['name']
        expected = row['source']
        selected = [
            (source / 'source-oci/files/source-companion.json', 'source-companion.json', expected['receipt_sha256']),
            (source / 'source-oci/files/sbom.spdx.json', 'sbom.spdx.json', expected['spdx_sha256']),
            (source / 'source-extract/inventory.json', 'inventory.json', expected['inventory_sha256']),
            (source / 'source-oci/manifest.json', 'source-oci-manifest.json', expected['manifest_sha256']),
            (source / 'source-oci/transport-journal.json', 'source-transport-journal.json', None),
            (source / 'content-readback-proof.json', 'content-readback-proof.json', None),
        ]
        for path, name, digest in selected:
            record = _copy_custody_file(path, base / name)
            if digest is not None and record['sha256'] != digest:
                raise ValueError('retained component source record mismatch: ' + row['name'])
    measured = licenses.observe_custody_tree(staging, platform='linux/amd64').artifact()
    return {'archive': _pack_verified_tree(measured, destination), 'tree_sha256': measured.sha256}


def _verify_frozen_payload(manifest, raw_manifest, parts_root, output_dir):
    """Inspect every closed payload role; this grants neither D nor authority."""
    from .delivery_authority import _read_bounded_file
    from .models import ArtifactRef
    check_custody_manifest(manifest)
    if type(raw_manifest) is not bytes or load_json(raw_manifest) != manifest:
        raise ValueError('frozen custody manifest bytes differ')
    parts_root, output = Path(parts_root), Path(output_dir)
    output.mkdir(parents=True, exist_ok=False)
    directories = {(role, part['part']): parts_root / (role + '-part' + str(part['part']))
                   for role in SEGMENT_ROLES for part in manifest['files'][role]}
    for (role, number), directory in directories.items():
        expected = dict(manifest['files'][role][number - 1]['files'])
        if role == 'image' and number == 1:
            expected['custody-manifest.json'] = {'size': len(raw_manifest), 'sha256': hashlib.sha256(raw_manifest).hexdigest()}
        _verify_extracted_part(directory, expected)
    def member(role, name):
        choices = [(part['part'], part['files'][name]) for part in manifest['files'][role] if name in part['files']]
        if len(choices) != 1:
            raise ValueError('frozen custody member missing or ambiguous')
        number, record = choices[0]
        return directories[(role, number)] / name, record
    candidate = ArtifactRef(**manifest['artifact'])
    def record(name):
        path, _ = member('source-records', name)
        return load_json(_read_bounded_file(path, 16 * 1024 * 1024), max_bytes=16 * 1024 * 1024)
    seal, content = manifest['facts']['source']['sealed'], manifest['facts']['source']['content']
    for prefix, source_fact in (('seal', seal), ('content', content)):
        _, identity = member('source-records', prefix + '-oci-manifest.json')
        if identity['sha256'] != source_fact['manifest_sha256']:
            raise ValueError('frozen source OCI manifest identity mismatch: ' + prefix)
        proof = record(prefix + '-readback-proof.json')
        _, transcript = member('source-records', prefix + '-transport-journal.json')
        if proof.get('transcript_sha256') != transcript['sha256'] or proof.get('transcript_bytes') != transcript['size']:
            raise ValueError('frozen source readback transcript mismatch: ' + prefix)
        if prefix == 'seal':
            if (proof.get('source_manifest_sha256') != seal['manifest_sha256']
                    or proof.get('sealed_archive_sha256') != seal['archive_sha256']
                    or proof.get('receipt_sha256') != seal['receipt_sha256']):
                raise ValueError('frozen sealed-source readback proof mismatch')
        elif any(proof.get(key) != content[key] for key in ('reference', 'manifest_sha256', 'file_sha256',
                                                           'receipt_sha256', 'spdx_sha256', 'inventory_sha256')):
            raise ValueError('frozen content readback proof mismatch')
    admission = record('source-admission.json')
    _, context_identity = member('source-records', 'source-context.json')
    if (admission.get('role') != 'active-source-admission' or admission.get('source_status') != 'eligible'
            or admission.get('facts') != manifest['facts'] or admission.get('context_sha256') != context_identity['sha256']
            or admission.get('profile_sha256') != manifest['profile_sha256']):
        raise ValueError('frozen original source admission differs from manifest')
    archive, image_identity = member('image', 'image.tar')
    distribution, actual_identity = _inspect_saved_image(archive)
    _check_saved_image_binding(candidate, distribution)
    if (actual_identity != image_identity or actual_identity != manifest['image_archive']
            or distribution['config_sha256'] != manifest['config_sha256']
            or distribution['layers'] != manifest['layers']):
        raise ValueError('frozen custody image differs from admitted identity')
    package, _ = member('validation', 'package.tar.gz')
    derived = read_validation_compositions(package, manifest['facts']['validation']['package_sha256'], candidate)
    _check_validation_body_digest(package, manifest['facts']['validation']['body_sha256'])
    components = {row['name']: row for row in manifest['components']}
    rights_archive, rights_record = member('source-records', 'component-rights.tar.gz')
    rights = output / 'component-rights'
    _unpack_verified_tree(rights_archive, rights_record, manifest['component_rights_tree_sha256'], rights)
    if {item.name for item in rights.iterdir()} != set(components):
        raise ValueError('frozen component rights roster mismatch')
    for name, row in components.items():
        root = rights / name
        expected_names = {'source-companion.json', 'sbom.spdx.json', 'inventory.json',
                          'source-oci-manifest.json', 'source-transport-journal.json', 'content-readback-proof.json'}
        if root.is_symlink() or not root.is_dir() or {item.name for item in root.iterdir()} != expected_names:
            raise ValueError('frozen component rights files mismatch: ' + name)
        for filename, key in (('source-companion.json', 'receipt_sha256'), ('sbom.spdx.json', 'spdx_sha256'),
                              ('inventory.json', 'inventory_sha256'), ('source-oci-manifest.json', 'manifest_sha256')):
            if _sealed_file_record(root / filename, CUSTODY_MEMBER_LIMIT)['sha256'] != row['source'][key]:
                raise ValueError('frozen component source record mismatch: ' + name)
        proof = load_json((root / 'content-readback-proof.json').read_bytes())
        transcript = _sealed_file_record(root / 'source-transport-journal.json', CUSTODY_MEMBER_LIMIT)
        if (proof.get('transcript_sha256') != transcript['sha256'] or proof.get('transcript_bytes') != transcript['size']
                or proof.get('manifest_sha256') != row['source']['manifest_sha256']
                or proof.get('receipt_sha256') != row['source']['receipt_sha256']):
            raise ValueError('frozen component original readback proof mismatch: ' + name)
    for name in ('checker', 'consumer', 'oracle'):
        for role, filename, component in ((name + '-tool', 'tool-root.tar.gz', name + '-root'),
                                          ('tool-inputs', name + '-inputs.tar.gz', name + '-inputs')):
            path, identity = member(role, filename)
            _unpack_verified_tree(path, identity, components[component]['artifact']['sha256'], output / component)
        for suffix, filename in (('-image', 'installed-image.tar.gz'), ('-derived', 'derived-image.tar.gz')):
            component = name + suffix
            if component not in components:
                continue
            artifact = ArtifactRef(**components[component]['artifact'])
            if suffix == '-derived' and artifact != derived[name]:
                raise ValueError('frozen derivative differs from original validation')
            path, identity = member(name + '-tool', filename)
            _inspect_compressed_tool_image(path, identity, artifact, output / (component + '.tar'))
    for (role, number), directory in directories.items():
        expected = dict(manifest['files'][role][number - 1]['files'])
        if role == 'image' and number == 1:
            expected['custody-manifest.json'] = {'size': len(raw_manifest), 'sha256': hashlib.sha256(raw_manifest).hexdigest()}
        _verify_extracted_part(directory, expected)


def prepare_custody_payload(*, output_dir, **producer_args):
    """Prepare the fixed segmented local payload after active D and rights.

    This does not upload, sign or create completed-producer authority.
    """
    import json
    from . import delivery_authority
    from .custody_authority import _producer_identity
    from .round_core.evaluator_replay import check_runtime_equivalence

    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=False)
    journal = {'status': 'incomplete', 'qualification_only': True, 'image_promotable': False}
    try:
        prepared = prepare_custody_image(**producer_args, output_dir=output / 'image-work').as_dict()
        environment, channel = producer_args['environment'], producer_args['channel']
        run_id, attempt, token = producer_args['run_id'], producer_args['attempt'], producer_args['token']
        run = _active_custody_job(environment, channel, run_id, attempt, token, journal_dir=output / 'active-before')
        profile = delivery_authority.load_profile(environment, channel)
        delivery_authority._check_local_controller(profile)
        facts, components = prepared['facts'], prepared['components']
        candidate = producer_args['artifact']
        validation = Path(producer_args['validation_dir'])
        policy = producer_args['validation_policy']
        derived = read_validation_compositions(validation / 'package.tar.gz', facts['validation']['package_sha256'], candidate)
        actual_components = _producer_component_artifacts(policy, candidate, derived)
        stage = output / 'staged'
        for role in SEGMENT_ROLES:
            (stage / role).mkdir(parents=True)
        _copy_custody_file(output / 'image-work/image.tar', stage / 'image/image.tar', expected=prepared['archive'])
        _copy_custody_file(validation / 'validation.json', stage / 'validation/validation.json')
        _copy_custody_file(validation / 'package.tar.gz', stage / 'validation/package.tar.gz')
        source = output / 'image-work/producer-after/source-after'
        evidence = Path(producer_args['evidence_dir'])
        sealed = Path(producer_args['sealed_dir'])
        original_records = {
            'build-receipt.json': Path(producer_args['build_receipt']),
            'sealed-source.json': sealed / 'sealed-source.json',
            'source-companion.json': evidence / 'source-companion.json', 'sbom.spdx.json': evidence / 'sbom.spdx.json',
            'source-context.json': source / 'attestation/source-context.json', 'source-bundle.json': source / 'attestation/bundle.json',
            'source-admission.json': source / 'source-admission.json', 'seal-readback-proof.json': source / 'facts/readback-proof.json',
            'content-readback-proof.json': source / 'facts/content-readback-proof.json',
            'seal-oci-manifest.json': source / 'facts/seal-oci/manifest.json',
            'seal-transport-journal.json': source / 'facts/seal-oci/transport-journal.json',
            'content-oci-manifest.json': source / 'facts/content-oci/manifest.json',
            'content-transport-journal.json': source / 'facts/content-oci/transport-journal.json',
        }
        for name, path in original_records.items():
            _copy_custody_file(path, stage / 'source-records' / name)
        component_source_root = output / 'image-work/producer-after'
        rights = _pack_component_rights(components, component_source_root, output / 'component-rights-tree',
                                        stage / 'source-records/component-rights.tar.gz')
        receipt = Path(policy['evaluator']['root']) / 'evaluator-build-receipt.json'
        _copy_custody_file(receipt, stage / 'evaluator-original/evaluator-build-receipt.json',
                           expected={'size': receipt.stat().st_size, 'sha256': prepared['evaluator']['receipt_sha256']})
        for name in ('checker', 'consumer', 'oracle'):
            _pack_verified_tree(actual_components[name + '-root'], stage / (name + '-tool/tool-root.tar.gz'))
            _pack_verified_tree(actual_components[name + '-inputs'], stage / ('tool-inputs/' + name + '-inputs.tar.gz'))
            installed = _save_verified_tool_image(actual_components[name + '-image'], output / ('save-' + name + '-image'))
            _copy_custody_file(output / ('save-' + name + '-image/image.tar.gz'),
                               stage / (name + '-tool/installed-image.tar.gz'), expected=installed)
            if name in ('checker', 'consumer'):
                derived_save = _save_verified_tool_image(actual_components[name + '-derived'], output / ('save-' + name + '-derived'))
                _copy_custody_file(output / ('save-' + name + '-derived/image.tar.gz'),
                                   stage / (name + '-tool/derived-image.tar.gz'), expected=derived_save)
        measured = {role: {name: _sealed_file_record(stage / role / name, CUSTODY_MEMBER_LIMIT)
                            for name in SEGMENT_FILES[role]} for role in SEGMENT_ROLES}
        plan = _plan_custody_parts(measured)
        seal_receipt = load_json(delivery_authority._read_bounded_file(sealed / 'sealed-source.json', 1024 * 1024))
        content_receipt = load_json(delivery_authority._read_bounded_file(evidence / 'source-companion.json', 1024 * 1024))
        manifest = {'schema_version': 1, 'kind': 'image-qualification-custody', 'qualification_only': True,
            'image_promotable': False, 'retention_days': 14, 'artifact': facts['artifact'],
            'engine_id': facts['artifact']['reference'], 'config_sha256': facts['validation']['config_sha256'],
            'layers': facts['validation']['layers'], 'build_key': facts['build_key'], 'facts': facts,
            'image_archive': measured['image']['image.tar'], 'files': plan,
            'source_archives': {'sealed': {'size': seal_receipt['size_bytes'],
                'sha256': facts['source']['sealed']['archive_sha256'], 'media_type': 'application/gzip'},
                'content': {'size': content_receipt['size_bytes'], 'sha256': facts['source']['content']['file_sha256'],
                            'media_type': 'application/gzip'}},
            'producer': _producer_identity(profile), 'run': run,
            'profile_sha256': delivery_authority._profile_digest(profile), 'controller_sha256': profile['controller_sha256'],
            'evaluator_receipt_sha256': prepared['evaluator']['receipt_sha256'],
            'evaluator_identity_sha256': prepared['evaluator']['identity_sha256'], 'components': components,
            'component_rights_tree_sha256': rights['tree_sha256']}
        check_custody_manifest(manifest)
        raw = canonical(manifest)
        if len(raw) > 2 * 1024 * 1024:
            raise ValueError('custody manifest byte bound')
        parts_root = output / 'parts'
        parts_root.mkdir()
        part_rows = []
        for role in SEGMENT_ROLES:
            for part in plan[role]:
                number = part['part']
                directory = parts_root / (role + '-part' + str(number))
                directory.mkdir()
                for name, expected in part['files'].items():
                    _copy_custody_file(stage / role / name, directory / name, expected=expected)
                expected_files = dict(part['files'])
                if role == 'image' and number == 1:
                    (directory / 'custody-manifest.json').write_bytes(raw)
                    expected_files['custody-manifest.json'] = {'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
                _verify_extracted_part(directory, expected_files)
                part_rows.append({'role': role, 'part': number,
                    'name': f'p11lab-image-custody-{role}-part{number}-{run_id}-{attempt}', 'directory': str(directory.absolute())})
        _verify_frozen_payload(manifest, raw, parts_root, output / 'preupload-inspection')
        final = verify_custody_producer(**producer_args, output_dir=output / 'producer-final').as_dict()
        if final['facts'] != facts or final['components'] != components:
            raise ValueError('custody source or component facts changed during payload preparation')
        old, new = prepared['evaluator'], final['evaluator']
        if (any(old[key] != new[key] for key in ('root', 'receipt_sha256', 'identity_sha256', 'python',
                'native_dependencies', 'raw', 'plan', 'ledger', 'admission', 'driver'))
                or not _same_planner_selection(old['planner'], new['planner'])):
            raise ValueError('custody evaluator changed during payload preparation')
        check_runtime_equivalence(old['runtime'], new['runtime'], old_root=old['root'], new_root=new['root'])
        if (_active_custody_job(environment, channel, run_id, attempt, token, journal_dir=output / 'active-after') != run
                or delivery_authority.load_profile(environment, channel) != profile):
            raise ValueError('custody active producer changed during payload preparation')
        for row in part_rows:
            expected_files = dict(plan[row['role']][row['part'] - 1]['files'])
            if row['role'] == 'image' and row['part'] == 1:
                expected_files['custody-manifest.json'] = {'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
            _verify_extracted_part(row['directory'], expected_files)
        journal['status'] = 'complete-local-preupload-only'
        return PreparedCustodyPayload(_PAYLOAD_KEY, {'schema_version': 1, 'kind': 'prepared-custody-payload',
            'manifest_sha256': hashlib.sha256(raw).hexdigest(), 'manifest': manifest, 'parts': part_rows,
            'evaluator': prepared['evaluator'], 'output_dir': str(output.absolute()),
            'qualification_only': True, 'image_promotable': False})
    except BaseException as error:
        journal['error_type'] = type(error).__name__
        raise
    finally:
        (output / 'payload-journal.json').write_text(json.dumps(journal, sort_keys=True, indent=2) + '\n')


def finalize_custody_payload(*, payload_dir, uploads, output_dir, **producer_args):
    """Recheck actual D and uploaded bytes before writing the attestation subject."""
    import json
    from . import delivery_authority
    from .custody_authority import _producer_identity, check_finalization
    from .round_core.artifacts import CustodyArtifactBytes, verify_custody_zip
    from .round_core.evaluator_replay import check_runtime_equivalence

    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=False)
    journal = {'status': 'incomplete', 'attestation': 'not-performed', 'image_promotable': False}
    try:
        first = verify_custody_producer(**producer_args, output_dir=output / 'producer-before').as_dict()
        environment, channel = producer_args['environment'], producer_args['channel']
        run_id, attempt, token = producer_args['run_id'], producer_args['attempt'], producer_args['token']
        profile = delivery_authority.load_profile(environment, channel)
        run = _active_custody_job(environment, channel, run_id, attempt, token, journal_dir=output / 'active-before')
        parts_root = Path(payload_dir) / 'parts'
        manifest_path = parts_root / 'image-part1/custody-manifest.json'
        raw = delivery_authority._read_bounded_file(manifest_path, 2 * 1024 * 1024)
        manifest = load_json(raw)
        check_custody_manifest(manifest)
        if (manifest['facts'] != first['facts'] or manifest['components'] != first['components']
                or manifest['producer'] != _producer_identity(profile) or manifest['run'] != run
                or manifest['profile_sha256'] != delivery_authority._profile_digest(profile)
                or manifest['controller_sha256'] != profile['controller_sha256']
                or manifest['evaluator_receipt_sha256'] != first['evaluator']['receipt_sha256']
                or manifest['evaluator_identity_sha256'] != first['evaluator']['identity_sha256']):
            raise ValueError('preupload custody manifest differs from actual producer facts')
        expected_directories = {role + '-part' + str(part['part'])
                                for role in SEGMENT_ROLES for part in manifest['files'][role]}
        if (parts_root.is_symlink() or not parts_root.is_dir()
                or {item.name for item in parts_root.iterdir()} != expected_directories):
            raise ValueError('local custody part directory roster changed')
        _verify_frozen_payload(manifest, raw, parts_root, output / 'local-payload-inspection')
        transport = delivery_authority._github_transport(profile['repository'], token)
        rows = _verify_active_uploads(transport, profile, run, manifest, raw, uploads, output / 'uploaded-parts')
        _verify_frozen_payload(manifest, raw, output / 'uploaded-parts', output / 'uploaded-payload-inspection')
        last = verify_custody_producer(**producer_args, output_dir=output / 'producer-after').as_dict()
        if last['facts'] != first['facts'] or last['components'] != first['components']:
            raise ValueError('producer source or component facts changed during finalization')
        old, new = first['evaluator'], last['evaluator']
        if (any(old[key] != new[key] for key in ('root', 'receipt_sha256', 'identity_sha256', 'python',
                'native_dependencies', 'raw', 'plan', 'ledger', 'admission', 'driver'))
                or not _same_planner_selection(old['planner'], new['planner'])):
            raise ValueError('producer evaluator changed during finalization')
        check_runtime_equivalence(old['runtime'], new['runtime'], old_root=old['root'], new_root=new['root'])
        if (_active_custody_job(environment, channel, run_id, attempt, token, journal_dir=output / 'active-after') != run
                or delivery_authority.load_profile(environment, channel) != profile):
            raise ValueError('active custody producer changed during finalization')
        base = {'run_id': run_id, 'attempt': attempt, 'workflow_id': profile['workflow_id'],
                'repository_id': profile['repository_id'], 'owner_id': profile['owner_id'],
                'head_sha': profile['source_sha'], 'job_name': run['job'], 'job_id': run['job_id']}
        metadata = [transport.resolve_active_custody(base | {'artifact_id': row['id'], 'name': row['name']},
                                                       now=delivery_authority._clock()) for row in rows]
        if any(item['job_count'] != 1 or item['job']['id'] != run['job_id'] for item in metadata):
            raise ValueError('active custody artifact job changed')
        observed = {'run': metadata[0]['run'], 'job': metadata[0]['job'],
                    'segments': [item['artifact'] for item in metadata]}
        statement = {'schema_version': 1, 'kind': 'image-custody-finalization', 'role': 'image-custody-producer',
            'environment': environment, 'channel': channel, 'profile_sha256': delivery_authority._profile_digest(profile),
            'controller_sha256': profile['controller_sha256'], 'producer': _producer_identity(profile), 'run': run,
            'manifest_sha256': hashlib.sha256(raw).hexdigest(), 'artifacts': rows, 'image_archive': manifest['image_archive'],
            'retention_days': 14, 'evaluator': first['evaluator'], 'components': first['components']}
        check_finalization(statement, raw, profile, observed)
        for row in rows:
            archive = output / 'uploaded-parts' / (row['role'] + '-part' + str(row['part']) + '.zip')
            verify_custody_zip(archive, CustodyArtifactBytes(row['id'], row['size'], row['digest']))
        expected_roster = [{'id': row['id'], 'name': row['name']} for row in rows]
        transport.resolve_custody_roster(run_id, expected_roster)
        subject = output / 'custody-finalization.json'
        with subject.open('xb') as stream:
            stream.write(canonical(statement))
        journal['status'] = 'ready-for-external-attestation'
        return {'schema_version': 1, 'kind': 'custody-attestation-subject',
                'subject_path': str(subject.absolute()), 'subject_sha256': hashlib.sha256(subject.read_bytes()).hexdigest(),
                'predicate_type': 'https://p11lab.org/attestations/image-custody/v1',
                'attestation': 'not-performed', 'image_promotable': False}
    except BaseException as error:
        journal['error_type'] = type(error).__name__
        raise
    finally:
        (output / 'finalization-journal.json').write_text(json.dumps(journal, sort_keys=True, indent=2) + '\n')


def _verify_extracted_part(root, expected):
    root = Path(root)
    if root.is_symlink() or not root.is_dir() or {item.name for item in root.iterdir()} != set(expected):
        raise ValueError('extracted custody part roster changed')
    for name, record in expected.items():
        path = root / name
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size != record['size']:
                raise ValueError('extracted custody member identity changed')
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
            after = os.fstat(stream.fileno())
            current = os.stat(path, follow_symlinks=False)
            def identity(value):
                return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns, value.st_mode, value.st_nlink)
            if identity(before) != identity(after) or identity(after) != identity(current) or digest != record['sha256']:
                raise ValueError('extracted custody member identity changed')


def acquire_custody_payload(authority, *, token, executable, trusted_root, output_dir):
    """Authenticate and extract all exact inert parts without admitting D."""
    from . import delivery_authority
    from .custody_authority import VerifiedCompletedFinalization, check_finalization, verify_completed_finalization
    from .round_core.artifacts import CustodyArtifactBytes, read_custody_manifest, verify_custody_zip

    if type(authority) is not VerifiedCompletedFinalization:
        raise TypeError('verified completed finalization required')
    statement, observed, profile = authority.statement(), authority.observed(), authority.profile()
    run = statement['run']
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=False)
    selector = {'environment': statement['environment'], 'channel': statement['channel'],
                'run_id': run['run_id'], 'attempt': run['attempt'], 'job_id': run['job_id'],
                'control_id': observed['control']['id'], 'token': token,
                'executable': executable, 'trusted_root': trusted_root}
    first = verify_completed_finalization(**selector, output_dir=output / 'authority-before')
    if first.statement() != statement or first.observed() != observed or first.profile() != profile:
        raise ValueError('custody authority changed before acquisition')
    zip_root, extracted_root = output / 'zips', output / 'payload'
    zip_root.mkdir()
    extracted_root.mkdir()
    transport = delivery_authority._github_transport(profile['repository'], token)
    manifest = None
    saved = []
    for index, row in enumerate(statement['artifacts']):
        metadata = observed['segments'][index]
        expected = CustodyArtifactBytes(metadata['id'], metadata['size_in_bytes'], metadata['digest'])
        archive = zip_root / (row['role'] + '-part' + str(row['part']) + '.zip')
        transport.download_custody(expected, archive)
        if index == 0:
            if row['role'] != 'image' or row['part'] != 1:
                raise ValueError('custody first part is not the image manifest')
            raw = read_custody_manifest(archive, expected)
            check_finalization(statement, raw, profile, observed)
            manifest = load_json(raw)
        if manifest is None:
            raise ValueError('custody manifest unavailable')
        part = manifest['files'][row['role']][row['part'] - 1]
        expected_files = dict(part['files'])
        if index == 0:
            expected_files['custody-manifest.json'] = {'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
        destination = extracted_root / (row['role'] + '-part' + str(row['part']))
        extract_custody_archive(archive, expected_files, destination)
        saved.append((archive, expected, destination, expected_files))
    final = verify_completed_finalization(**selector, output_dir=output / 'authority-after')
    if final.statement() != statement or final.observed() != observed or final.profile() != profile:
        raise ValueError('custody authority changed during acquisition')
    for archive, expected, destination, expected_files in saved:
        verify_custody_zip(archive, expected)
        _verify_extracted_part(destination, expected_files)
    return VerifiedCustodyBytes(_BYTES_KEY, {'schema_version': 1, 'kind': 'verified-inert-custody-bytes',
        'output_dir': str(output.absolute()), 'manifest': manifest, 'finalization': statement,
        'qualification_only': True, 'image_promotable': False})


def verify_acquired_custody(authority, payload):
    """Recheck retained bytes at a later use boundary; this does not replay D."""
    from .custody_authority import VerifiedCompletedFinalization, check_finalization
    from .round_core.artifacts import CustodyArtifactBytes, read_custody_manifest, verify_custody_zip

    if type(authority) is not VerifiedCompletedFinalization or type(payload) is not VerifiedCustodyBytes:
        raise TypeError('verified completed authority and acquired custody bytes required')
    value = payload.as_dict()
    statement, observed, profile = authority.statement(), authority.observed(), authority.profile()
    if value['finalization'] != statement:
        raise ValueError('acquired custody authority changed')
    output = Path(value['output_dir'])
    zip_root, extracted_root = output / 'zips', output / 'payload'
    rows = statement['artifacts']
    names = {row['role'] + '-part' + str(row['part']) for row in rows}
    if (any(path.is_symlink() or not path.is_dir() for path in (output, zip_root, extracted_root))
            or {path.name for path in zip_root.iterdir()} != {name + '.zip' for name in names}
            or {path.name for path in extracted_root.iterdir()} != names):
        raise ValueError('acquired custody part roster changed')
    manifest = None
    for index, row in enumerate(rows):
        name = row['role'] + '-part' + str(row['part'])
        metadata = observed['segments'][index]
        expected = CustodyArtifactBytes(metadata['id'], metadata['size_in_bytes'], metadata['digest'])
        archive = zip_root / (name + '.zip')
        verify_custody_zip(archive, expected)
        if index == 0:
            raw = read_custody_manifest(archive, expected)
            check_finalization(statement, raw, profile, observed)
            manifest = load_json(raw)
            if manifest != value['manifest']:
                raise ValueError('acquired custody manifest changed')
        if manifest is None:
            raise ValueError('custody manifest unavailable')
        expected_files = dict(manifest['files'][row['role']][row['part'] - 1]['files'])
        if index == 0:
            expected_files['custody-manifest.json'] = {'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
        _verify_extracted_part(extracted_root / name, expected_files)


def load_custody_image(authority, payload, *, token, executable, trusted_root, output_dir):
    """Load exact authenticated image bytes inertly, before a separate fresh D."""
    import json
    from .custody_authority import VerifiedCompletedFinalization, verify_completed_finalization
    from .docker import Docker
    from .models import ArtifactRef

    if type(authority) is not VerifiedCompletedFinalization or type(payload) is not VerifiedCustodyBytes:
        raise TypeError('verified completed authority and acquired custody bytes required')
    statement, observed, profile = authority.statement(), authority.observed(), authority.profile()
    run = statement['run']
    selector = {'environment': statement['environment'], 'channel': statement['channel'], 'run_id': run['run_id'],
                'attempt': run['attempt'], 'job_id': run['job_id'], 'control_id': observed['control']['id'],
                'token': token, 'executable': executable, 'trusted_root': trusted_root}
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=False)
    journal = {'status': 'incomplete', 'load': None, 'cleanup': 'not-applicable-before-load'}
    try:
        first = verify_completed_finalization(**selector, output_dir=output / 'authority-before')
        if first.statement() != statement or first.observed() != observed or first.profile() != profile:
            raise ValueError('custody authority changed before image load')
        verify_acquired_custody(first, payload)
        data = payload.as_dict()
        manifest = data['manifest']
        archive = Path(data['output_dir']) / 'payload/image-part1/image.tar'
        distribution, identity = _inspect_saved_image(archive)
        candidate = ArtifactRef(**manifest['artifact'])
        _check_saved_image_binding(candidate, distribution)
        if (identity != manifest['image_archive'] or distribution['config_sha256'] != manifest['config_sha256']
                or distribution['layers'] != manifest['layers'] or distribution['platform'] != candidate.platform):
            raise ValueError('authenticated custody archive differs from image binding')
        docker = Docker()
        context = docker.env.get('DOCKER_CONTEXT')
        endpoint = docker.env.get('DOCKER_HOST') if not context else None
        if not endpoint:
            endpoint = json.loads(docker.command(['context', 'inspect', *([context] if context else []),
                '--format', '{{json .Endpoints.docker.Host}}']).stdout)
        if not isinstance(endpoint, str) or not endpoint.startswith('unix://'):
            raise ValueError('custody image load requires a same-host local Unix Docker daemon')
        descriptor = os.open(archive, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as stream:
            before = os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size != identity['size']
                    or hashlib.file_digest(stream, 'sha256').hexdigest() != identity['sha256']):
                raise ValueError('custody image changed before loading')
            fd_path = '/proc/' + str(os.getpid()) + '/fd/' + str(stream.fileno())
            journal['cleanup'] = 'load-attempt-may-have-retained-image'
            native = docker.command(['image', 'load', '--input', fd_path], timeout=120, check=False)
            journal['load'] = {'returncode': native.returncode, 'timed_out': native.timed_out,
                'stdout': native.stdout, 'stderr': native.stderr, 'stdout_truncated': native.stdout_truncated,
                'stderr_truncated': native.stderr_truncated}
            if native.returncode or native.timed_out or native.stdout_truncated or native.stderr_truncated:
                raise ValueError('native custody image load incomplete')
            stream.seek(0)
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
            after, current = os.fstat(stream.fileno()), os.stat(archive, follow_symlinks=False)
            def file_identity(value):
                return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
                        value.st_size, value.st_mtime_ns, value.st_ctime_ns)
            if digest != identity['sha256'] or file_identity(before) != file_identity(after) or file_identity(after) != file_identity(current):
                raise ValueError('custody image changed while loading')
        actual = docker.image(candidate)
        if actual.get('RootFS', {}).get('Layers') != [row['diff_id'] for row in manifest['layers']]:
            raise ValueError('loaded custody image layers mismatch')
        verify_acquired_custody(first, payload)
        last = verify_completed_finalization(**selector, output_dir=output / 'authority-after')
        if last.statement() != statement or last.observed() != observed or last.profile() != profile:
            raise ValueError('custody authority changed during image load')
        journal['status'] = 'complete-inert-load-only'
        journal['cleanup'] = 'image-retained-for-source-replay'
        return InertLoadedCustodyImage(_LOADED_KEY, {'schema_version': 1, 'kind': 'inert-loaded-custody-image',
            'artifact': manifest['artifact'], 'image_archive': identity, 'finalization': statement,
            'payload_output': data['output_dir'], 'load_output': str(output.absolute()),
            'source_status': 'not-yet-replayed', 'qualification_only': True, 'image_promotable': False})
    except BaseException as error:
        journal['error_type'] = type(error).__name__
        raise
    finally:
        (output / 'load-journal.json').write_text(json.dumps(journal, sort_keys=True, indent=2) + '\n')


def _payload_member(data, role, name):
    parts = data['manifest']['files'][role]
    selected = [(part['part'], part['files'][name]) for part in parts if name in part['files']]
    if len(selected) != 1:
        raise ValueError('missing or ambiguous retained custody member')
    number, identity = selected[0]
    path = Path(data['output_dir']) / 'payload' / (role + '-part' + str(number)) / name
    if _sealed_file_record(path, CUSTODY_MEMBER_LIMIT) != identity:
        raise ValueError('retained custody member changed')
    return path, identity


def _verify_original_source_attestation(authority, data, *, executable, trusted_root, output_dir):
    """Verify the original source signature in its authenticated job window."""
    from datetime import datetime, timedelta, timezone
    from . import delivery_authority
    statement, observed, profile = authority.statement(), authority.observed(), authority.profile()
    context_path, _ = _payload_member(data, 'source-records', 'source-context.json')
    bundle_path, _ = _payload_member(data, 'source-records', 'source-bundle.json')
    result, raw = delivery_authority._run_verifier(executable, context_path, bundle_path, trusted_root,
                                                    profile['root_sha256'], profile, output_dir)
    try:
        job = observed['job']
        start = datetime.fromisoformat(job['started_at'].replace('Z', '+00:00'))
        end = datetime.fromisoformat(job['completed_at'].replace('Z', '+00:00'))
        now = delivery_authority._clock()
        if start.tzinfo is None or end.tzinfo is None or now.tzinfo is None or start > end:
            raise ValueError('invalid completed source job timing')
        start, end = start.astimezone(timezone.utc), end.astimezone(timezone.utc)
        skew = timedelta(minutes=5)
        lower, upper = max(start - skew, now - timedelta(days=14)), min(end + skew, now + skew)
        if lower > upper:
            raise ValueError('completed source signature expired or premature')
        run = statement['run']
        identity = {'run_id': run['run_id'], 'attempt': run['attempt'], 'job': run['job']}
        delivery_authority._check_verified(result, profile, identity, raw, now, timestamp_window=(lower, upper))
        expected = delivery_authority._make_context(statement['environment'], statement['channel'], profile,
                                                      identity, data['manifest']['facts'])
        if load_json(raw) != expected:
            raise ValueError('original source context differs from custody facts')
    except (KeyError, TypeError, AttributeError, OverflowError) as error:
        raise ValueError('malformed completed source attestation timing') from error


def replay_custody_source(authority, payload, loaded, *, evaluator_root, token, executable, trusted_root, output_dir):
    """Reconstruct fixed inputs and recompute source D for an inert loaded image."""
    import json
    from . import delivery_authority, publish, source_transport
    from .checker import load_profile
    from .custody_authority import VerifiedCompletedFinalization, verify_completed_finalization
    from .docker import Docker
    from .models import ArtifactRef
    from .round_core.evaluator_replay import bind_evaluator_replay, observe_local_evaluator
    from .round_core.tool_identity import verified_evaluator_identity

    if (type(authority) is not VerifiedCompletedFinalization or type(payload) is not VerifiedCustodyBytes
            or type(loaded) is not InertLoadedCustodyImage):
        raise TypeError('typed completed authority, custody payload and inert loaded image required')
    statement, observed, profile = authority.statement(), authority.observed(), authority.profile()
    data, loaded_data = payload.as_dict(), loaded.as_dict()
    manifest = data['manifest']
    if (loaded_data['finalization'] != statement or loaded_data['payload_output'] != data['output_dir']
            or loaded_data['artifact'] != manifest['artifact'] or loaded_data['image_archive'] != manifest['image_archive']
            or loaded_data['source_status'] != 'not-yet-replayed'):
        raise ValueError('loaded custody image differs from authenticated payload')
    run = statement['run']
    selector = {'environment': statement['environment'], 'channel': statement['channel'], 'run_id': run['run_id'],
                'attempt': run['attempt'], 'job_id': run['job_id'], 'control_id': observed['control']['id'],
                'token': token, 'executable': executable, 'trusted_root': trusted_root}
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=False)
    journal = {'status': 'incomplete', 'source_status': 'not-yet-replayed',
               'image_promotion_status': 'blocked', 'qualification_status': 'not-performed'}
    try:
        first = verify_completed_finalization(**selector, output_dir=output / 'authority-before')
        if first.statement() != statement or first.observed() != observed or first.profile() != profile:
            raise ValueError('custody authority changed before source replay')
        verify_acquired_custody(first, payload)
        _verify_original_source_attestation(first, data, executable=executable, trusted_root=trusted_root,
                                            output_dir=output / 'original-source-attestation')
        candidate = ArtifactRef(**manifest['artifact'])
        image = Docker().image(candidate)
        if image.get('RootFS', {}).get('Layers') != [row['diff_id'] for row in manifest['layers']]:
            raise ValueError('loaded custody candidate changed before source replay')
        validation = output / 'validation'
        for name in ('validation.json', 'package.tar.gz'):
            source, identity = _payload_member(data, 'validation', name)
            _copy_custody_file(source, validation / name, expected=identity)
        validation_record = load_json(delivery_authority._read_bounded_file(validation / 'validation.json', 16 * 1024 * 1024),
                                      max_bytes=16 * 1024 * 1024)
        derived = read_validation_compositions(validation / 'package.tar.gz', manifest['facts']['validation']['package_sha256'],
                                               candidate, evaluator_inputs_dir=output / 'evaluator-originals')
        rights_archive, rights_identity = _payload_member(data, 'source-records', 'component-rights.tar.gz')
        rights = output / 'component-rights'
        _unpack_verified_tree(rights_archive, rights_identity, manifest['component_rights_tree_sha256'], rights)
        components = {row['name']: row for row in manifest['components']}
        restored = {}
        for name in ('checker', 'consumer', 'oracle'):
            for role, member, component in ((name + '-tool', 'tool-root.tar.gz', name + '-root'),
                                             ('tool-inputs', name + '-inputs.tar.gz', name + '-inputs')):
                archive, identity = _payload_member(data, role, member)
                restored[component] = _unpack_verified_tree(archive, identity, components[component]['artifact']['sha256'],
                                                             output / ('restored-' + component))
            for suffix, member in (('-image', 'installed-image.tar.gz'), ('-derived', 'derived-image.tar.gz')):
                component = name + suffix
                if component not in components:
                    continue
                artifact = ArtifactRef(**components[component]['artifact'])
                if suffix == '-derived' and artifact != derived[name]:
                    raise ValueError('retained validation derivative identity mismatch')
                archive, identity = _payload_member(data, name + '-tool', member)
                _restore_component_image(archive, identity, artifact, output / ('load-' + component))
                restored[component] = artifact
        evaluator = Path(evaluator_root).resolve(strict=True)
        current = verified_evaluator_identity(evaluator)
        originals = output / 'evaluator-originals'
        current_observation = observe_local_evaluator(evaluator, current['receipt_sha256'], set(load_profile()['sources']),
            originals / 'checker-input', originals / 'frozen-plan.json', output / 'evaluator-observation')
        original_receipt, _ = _payload_member(data, 'evaluator-original', 'evaluator-build-receipt.json')
        binding = bind_evaluator_replay(first, original_receipt, current_observation)
        metadata = components['evaluator-original']['artifact']
        restored['evaluator-original'] = ArtifactRef(metadata['kind'], str(original_receipt), metadata['sha256'], metadata['platform'])
        policy = {'tools': {name: {'root': restored[name + '-root'].reference,
                    'input_receipt': str(Path(restored[name + '-inputs'].reference) / 'resolved-inputs.json'),
                    'manifest_sha256': validation_record['tool_manifest_sha256'][name]}
                    for name in ('checker', 'consumer', 'oracle')},
                  'evaluator': {'root': str(evaluator), 'receipt_sha256': current['receipt_sha256']},
                  'control_base_revision': validation_record['control_base_revision_declared']}
        for name, row in components.items():
            expected = row['source']
            source_dir = rights / name
            receipt = _sealed_file_record(source_dir / 'source-companion.json', CUSTODY_MEMBER_LIMIT)
            spdx = _sealed_file_record(source_dir / 'sbom.spdx.json', CUSTODY_MEMBER_LIMIT)
            inventory = _sealed_file_record(source_dir / 'inventory.json', CUSTODY_MEMBER_LIMIT)
            source_manifest = _sealed_file_record(source_dir / 'source-oci-manifest.json', CUSTODY_MEMBER_LIMIT)
            if (receipt['sha256'] != expected['receipt_sha256'] or spdx['sha256'] != expected['spdx_sha256']
                    or inventory['sha256'] != expected['inventory_sha256']
                    or source_manifest['sha256'] != expected['manifest_sha256']):
                raise ValueError('retained component source identities changed: ' + name)
            registry = expected['reference'].rsplit('@sha256:', 1)[0]
            roster = {'source-companion.tar.gz': {'sha256': expected['file_sha256'],
                        'size_bytes': expected['source_archive_size'], 'media_type': publish.CONTENT_FILES['source-companion.tar.gz']},
                      'source-companion.json': {'sha256': receipt['sha256'], 'size_bytes': receipt['size'],
                                                'media_type': publish.CONTENT_FILES['source-companion.json']},
                      'sbom.spdx.json': {'sha256': spdx['sha256'], 'size_bytes': spdx['size'],
                                         'media_type': publish.CONTENT_FILES['sbom.spdx.json']}}
            reacquired = output / ('reacquire-' + name)
            source_transport.acquire(registry, expected['manifest_sha256'], roster,
                artifact_type='application/vnd.p11lab.source-companion.v1', output_dir=reacquired)
            evidence = output / ('evidence-' + name)
            for filename in roster:
                _copy_custody_file(reacquired / 'files' / filename, evidence / filename,
                                   source_archive=filename == 'source-companion.tar.gz')
            tool_config = policy['tools'][name.removesuffix('-root')] if name.endswith('-root') else None
            image_source = components['consumer-image']['source']
            consumer_binding = (_consumer_image_binding(restored[name], tool_config, output / 'evidence-consumer-image',
                output / 'consumer-readback-prerequisite', registry=registry, manifest_sha256=image_source['manifest_sha256'])
                if _consumer_binding_needed(name, restored[name]) else None)
            checked = verify_custody_component_source(name, restored[name], evidence_dir=evidence,
                registry=registry, manifest_sha256=expected['manifest_sha256'], output_dir=output / ('verify-' + name),
                replay_binding=binding if name == 'evaluator-original' else None, tool_config=tool_config,
                consumer_binding=consumer_binding)
            source_keys = ('reference', 'manifest_sha256', 'file_sha256', 'receipt_sha256', 'spdx_sha256',
                           'inventory_sha256', 'source_archive_size')
            if ({key: checked[key] for key in source_keys} != expected or checked['review_sha256'] != row['review_sha256']):
                raise ValueError('fresh component source facts differ from signed producer: ' + name)
        sealed_receipt, sealed_identity = _payload_member(data, 'source-records', 'sealed-source.json')
        content_receipt, content_identity = _payload_member(data, 'source-records', 'source-companion.json')
        spdx_file, spdx_identity = _payload_member(data, 'source-records', 'sbom.spdx.json')
        build_receipt, _ = _payload_member(data, 'source-records', 'build-receipt.json')
        seal = manifest['facts']['source']['sealed']
        content = manifest['facts']['source']['content']
        registry = seal['reference'].rsplit('@sha256:', 1)[0]
        if content['reference'].rsplit('@sha256:', 1)[0] != registry:
            raise ValueError('provider source repositories differ')
        seal_roster = {'sealed-source.tar.gz': {'sha256': seal['archive_sha256'],
                        'size_bytes': manifest['source_archives']['sealed']['size'],
                        'media_type': publish.SEAL_FILES['sealed-source.tar.gz']},
                       'sealed-source.json': {'sha256': sealed_identity['sha256'], 'size_bytes': sealed_identity['size'],
                                              'media_type': publish.SEAL_FILES['sealed-source.json']}}
        content_roster = {'source-companion.tar.gz': {'sha256': content['file_sha256'],
                           'size_bytes': manifest['source_archives']['content']['size'],
                           'media_type': publish.CONTENT_FILES['source-companion.tar.gz']},
                          'source-companion.json': {'sha256': content_identity['sha256'], 'size_bytes': content_identity['size'],
                                                    'media_type': publish.CONTENT_FILES['source-companion.json']},
                          'sbom.spdx.json': {'sha256': spdx_identity['sha256'], 'size_bytes': spdx_identity['size'],
                                             'media_type': publish.CONTENT_FILES['sbom.spdx.json']}}
        source_transport.acquire(registry, seal['manifest_sha256'], seal_roster,
            artifact_type='application/vnd.p11lab.sealed-source.v1', output_dir=output / 'provider-seal')
        source_transport.acquire(registry, content['manifest_sha256'], content_roster,
            artifact_type='application/vnd.p11lab.source-companion.v1', output_dir=output / 'provider-content')
        sealed_dir, provider_evidence = output / 'sealed', output / 'provider-evidence'
        _copy_custody_file(sealed_receipt, sealed_dir / 'sealed-source.json', expected=sealed_identity)
        for filename in content_roster:
            _copy_custody_file(output / 'provider-content/files' / filename, provider_evidence / filename,
                               source_archive=filename == 'source-companion.tar.gz')
        if (_sealed_file_record(provider_evidence / 'source-companion.json', CUSTODY_MEMBER_LIMIT) != content_identity
                or _sealed_file_record(provider_evidence / 'sbom.spdx.json', CUSTODY_MEMBER_LIMIT) != spdx_identity):
            raise ValueError('provider source evidence differs from retained originals')
        fresh = delivery_authority._source_facts(environment=statement['environment'], channel=statement['channel'],
            artifact=candidate, evidence_dir=provider_evidence, validation_dir=validation, build_receipt=build_receipt,
            sealed_dir=sealed_dir, registry=registry, seal_digest=seal['manifest_sha256'],
            content_digest=content['manifest_sha256'], output_dir=output / 'fresh-source-facts', profile=profile,
            validation_policy=policy, replay_binding=binding)
        if fresh != manifest['facts']:
            raise ValueError('fresh source D differs from signed original source facts')
        if Docker().image(candidate).get('RootFS', {}).get('Layers') != [row['diff_id'] for row in manifest['layers']]:
            raise ValueError('loaded custody candidate changed during source replay')
        verify_acquired_custody(first, payload)
        last = verify_completed_finalization(**selector, output_dir=output / 'authority-after')
        if last.statement() != statement or last.observed() != observed or last.profile() != profile:
            raise ValueError('custody authority changed during source replay')
        journal['status'], journal['source_status'] = 'complete-fresh-source-replay', 'eligible'
        return VerifiedCustodySourceReplay(_SOURCE_REPLAY_KEY, {'schema_version': 1, 'kind': 'fresh-custody-source-replay',
            'facts': fresh, 'artifact': manifest['artifact'], 'finalization_sha256': hashlib.sha256(canonical(statement)).hexdigest(),
            'original_evaluator_receipt_sha256': binding.as_dict()['original_receipt_sha256'],
            'current_evaluator_receipt_sha256': binding.as_dict()['current_receipt_sha256'],
            'source_status': 'eligible', 'qualification_status': 'not-performed', 'image_promotable': False,
            'output_dir': str(output.absolute())})
    except BaseException as error:
        journal['error_type'] = type(error).__name__
        raise
    finally:
        (output / 'source-replay-journal.json').write_text(json.dumps(journal, sort_keys=True, indent=2) + '\n')


def check_component_facts(rows):
    """Check the fixed independent source-rights roster, without granting it."""
    def sha(value):
        return type(value) is str and re.fullmatch(r'[0-9a-f]{64}', value) is not None
    if type(rows) is not list:
        raise ValueError('invalid custody component facts')
    required = set(COMPONENTS)
    names = [row.get('name') if type(row) is dict else None for row in rows]
    if (len(names) != len(required) or any(type(name) is not str for name in names)
            or names != sorted(set(names)) or not required <= set(names) or not set(names) <= set(COMPONENTS)):
        raise ValueError('incomplete custody component rights roster')
    for row in rows:
        if set(row) != {'name', 'artifact', 'review_sha256', 'source'} or not sha(row['review_sha256']):
            raise ValueError('invalid custody component rights fact')
        artifact = row['artifact']
        if (type(artifact) is not dict or set(artifact) != {'kind', 'reference', 'sha256', 'platform'}
                or artifact['kind'] != COMPONENTS[row['name']] or not sha(artifact['sha256'])
                or artifact['reference'] != 'sha256:' + artifact['sha256'] or artifact['platform'] != 'linux/amd64'):
            raise ValueError('invalid custody component artifact identity')
        source = row['source']
        if (type(source) is not dict or set(source) != {'reference', 'manifest_sha256', 'file_sha256', 'receipt_sha256',
                'spdx_sha256', 'inventory_sha256', 'source_archive_size'}
                or any(not sha(source[key]) for key in ('manifest_sha256', 'file_sha256', 'receipt_sha256',
                                                         'spdx_sha256', 'inventory_sha256'))
                or type(source['source_archive_size']) is not int or not 0 < source['source_archive_size'] <= 5 * 1024**3
                or type(source['reference']) is not str
                or not re.fullmatch(r'ghcr\.io/p11lab/[a-z0-9]+(?:-[a-z0-9]+)*@sha256:' + source['manifest_sha256'], source['reference'])):
            raise ValueError('invalid custody component immutable source identity')


def _plan_custody_parts(files):
    """Freeze the fixed role/member roster into one or two bounded parts each."""
    if type(files) is not dict or set(files) != set(SEGMENT_ROLES):
        raise ValueError('invalid custody file role roster')
    result, aggregate = {}, 0
    for role in SEGMENT_ROLES:
        entries = files[role]
        names = SEGMENT_FILES[role]
        if type(entries) is not dict or set(entries) != set(names):
            raise ValueError('invalid custody file member roster: ' + role)
        for item in entries.values():
            if (type(item) is not dict or set(item) != {'size', 'sha256'} or type(item['size']) is not int
                    or not 0 < item['size'] <= CUSTODY_MEMBER_LIMIT or type(item['sha256']) is not str
                    or not re.fullmatch(r'[0-9a-f]{64}', item['sha256'])):
                raise ValueError('invalid custody file identity')
        total = sum(entries[name]['size'] for name in names)
        aggregate += total
        if total <= CUSTODY_TOTAL_LIMIT:
            groups = [names]
        else:
            candidates = []
            for mask in range(1, (1 << len(names)) - 1):
                left = tuple(name for index, name in enumerate(names) if mask & (1 << index))
                right = tuple(name for index, name in enumerate(names) if not mask & (1 << index))
                left_size = sum(entries[name]['size'] for name in left)
                if left_size <= CUSTODY_TOTAL_LIMIT and total - left_size <= CUSTODY_TOTAL_LIMIT:
                    candidates.append((abs(total - 2 * left_size), mask, left, right))
            if not candidates:
                raise ValueError('custody role cannot fit within two bounded parts: ' + role)
            _, _, left, right = min(candidates)
            groups = [left, right]
        result[role] = [{'part': index, 'files': {name: dict(entries[name]) for name in group}}
                        for index, group in enumerate(groups, 1)]
    if aggregate > 8 * CUSTODY_TOTAL_LIMIT:
        raise ValueError('aggregate custody payload byte bound')
    return result


def check_custody_manifest(value):
    """Validate closed claimed payload identities; this does not authenticate D."""
    try:
        fields = {'schema_version', 'kind', 'qualification_only', 'image_promotable', 'retention_days',
                  'artifact', 'engine_id', 'config_sha256', 'layers', 'build_key', 'facts', 'image_archive',
                  'files', 'source_archives', 'producer', 'run', 'profile_sha256', 'controller_sha256',
                  'evaluator_receipt_sha256', 'evaluator_identity_sha256', 'components', 'component_rights_tree_sha256'}
        def sha(item):
            return type(item) is str and re.fullmatch(r'[0-9a-f]{64}', item) is not None
        if (type(value) is not dict or set(value) != fields
                or type(value['schema_version']) is not int or value['schema_version'] != 1
                or value['kind'] != 'image-qualification-custody' or value['qualification_only'] is not True
                or value['image_promotable'] is not False
                or type(value['retention_days']) is not int or value['retention_days'] != 14
                or any(not sha(value[key]) for key in ('build_key', 'config_sha256', 'profile_sha256',
                                                        'controller_sha256', 'evaluator_receipt_sha256', 'evaluator_identity_sha256',
                                                        'component_rights_tree_sha256'))):
            raise ValueError('invalid image custody manifest identity')
        check_component_facts(value['components'])
        producer, run = value['producer'], value['run']
        if (type(producer) is not dict or set(producer) != {'repository', 'repository_id', 'owner_id', 'workflow_id',
                'workflow_path', 'source_sha', 'source_ref', 'signer_sha', 'graph_sha256'}
                or type(producer['repository']) is not str
                or not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', producer['repository'])
                or any(type(producer[k]) is not int or producer[k] <= 0 for k in ('repository_id', 'owner_id', 'workflow_id'))
                or producer['workflow_path'] != '.github/workflows/provider-delivery.yml'
                or any(type(producer[k]) is not str or not re.fullmatch(r'[0-9a-f]{40}', producer[k]) for k in ('source_sha', 'signer_sha'))
                or type(producer['source_ref']) is not str or not re.fullmatch(r'refs/heads/[A-Za-z0-9._/-]+', producer['source_ref'])
                or not sha(producer['graph_sha256']) or type(run) is not dict or set(run) != {'run_id', 'attempt', 'job', 'job_id'}
                or any(type(run[k]) is not int or run[k] <= 0 for k in ('run_id', 'attempt', 'job_id'))
                or run['attempt'] != 1 or type(run['job']) is not str or not re.fullmatch(r'[A-Za-z0-9 _.-]{1,100}', run['job'])):
            raise ValueError('invalid custody producer identity')
        artifact = value['artifact']
        if (type(artifact) is not dict or set(artifact) != {'kind', 'reference', 'sha256', 'platform'}
                or artifact['kind'] != 'docker-local' or not sha(artifact['sha256'])
                or artifact['reference'] != 'sha256:' + artifact['sha256']
                or artifact['platform'] != 'linux/amd64' or value['engine_id'] != artifact['reference']):
            raise ValueError('invalid custody candidate identity')
        layers = value['layers']
        if (type(layers) is not list or not layers or any(type(row) is not dict
                or type(row.get('diff_id')) is not str or not re.fullmatch(r'sha256:[0-9a-f]{64}', row['diff_id'])
                for row in layers)):
            raise ValueError('invalid custody layer identities')
        files = value['files']
        if type(files) is not dict or set(files) != set(SEGMENT_ROLES):
            raise ValueError('invalid custody payload role roster')
        flattened = {}
        aggregate = 0
        for role, names in SEGMENT_FILES.items():
            parts = files[role]
            if type(parts) is not list or not 1 <= len(parts) <= 2:
                raise ValueError('invalid custody payload part roster: ' + role)
            entries = {}
            for number, part in enumerate(parts, 1):
                if (type(part) is not dict or set(part) != {'part', 'files'} or type(part['part']) is not int
                        or part['part'] != number or type(part['files']) is not dict or not part['files']
                        or not set(part['files']) <= set(names) or set(entries) & set(part['files'])):
                    raise ValueError('invalid or overlapping custody payload part: ' + role)
                total = 0
                for name, item in part['files'].items():
                    if (type(item) is not dict or set(item) != {'size', 'sha256'} or type(item['size']) is not int
                            or not 0 < item['size'] <= CUSTODY_MEMBER_LIMIT or not sha(item['sha256'])):
                        raise ValueError('invalid custody payload member identity')
                    total += item['size']
                    entries[name] = item
                if total > CUSTODY_TOTAL_LIMIT:
                    raise ValueError('custody part expanded byte bound')
                aggregate += total
            if set(entries) != set(names):
                raise ValueError('invalid custody payload file roster: ' + role)
            flattened[role] = entries
        if aggregate > 8 * CUSTODY_TOTAL_LIMIT:
            raise ValueError('aggregate custody expanded byte bound')
        files = flattened
        if files['validation']['validation.json']['size'] > 16 * 1024 * 1024:
            raise ValueError('validation original byte bound')
        if files['source-records']['source-context.json']['size'] > 1024 * 1024:
            raise ValueError('source context byte bound')
        if files['source-records']['source-bundle.json']['size'] > 16 * 1024 * 1024:
            raise ValueError('source attestation bundle byte bound')
        if value['image_archive'] != files['image']['image.tar']:
            raise ValueError('custody image archive mismatch')
        if value['evaluator_receipt_sha256'] != files['evaluator-original']['evaluator-build-receipt.json']['sha256']:
            raise ValueError('custody original evaluator receipt mismatch')
        evaluator_component = next(row for row in value['components'] if row['name'] == 'evaluator-original')
        if evaluator_component['artifact']['sha256'] != value['evaluator_receipt_sha256']:
            raise ValueError('custody evaluator metadata component mismatch')
        facts = value['facts']
        if (type(facts) is not dict or set(facts) != {'artifact', 'build_key', 'build_receipt_sha256', 'source', 'validation'}
                or facts['artifact'] != artifact or facts['build_key'] != value['build_key']
                or facts['build_receipt_sha256'] != files['source-records']['build-receipt.json']['sha256']):
            raise ValueError('custody source facts mismatch')
        validation = facts['validation']
        if (type(validation) is not dict or set(validation) != {'validation_sha256', 'package_sha256', 'body_sha256', 'config_sha256', 'layers'}
                or validation['validation_sha256'] != files['validation']['validation.json']['sha256']
                or validation['package_sha256'] != files['validation']['package.tar.gz']['sha256']
                or not sha(validation['body_sha256'])
                or validation['config_sha256'] != value['config_sha256'] or validation['layers'] != layers):
            raise ValueError('custody validation identity mismatch')
        source = facts['source']
        if type(source) is not dict or set(source) != {'sealed', 'content'}:
            raise ValueError('invalid custody source facts')
        sealed, content = source['sealed'], source['content']
        if (type(sealed) is not dict or set(sealed) != {'reference', 'manifest_sha256', 'archive_sha256', 'receipt_sha256'}
                or type(content) is not dict or set(content) != {'reference', 'manifest_sha256', 'file_sha256', 'receipt_sha256', 'spdx_sha256', 'inventory_sha256'}
                or any(not sha(sealed[key]) for key in ('manifest_sha256', 'archive_sha256', 'receipt_sha256'))
                or any(not sha(content[key]) for key in ('manifest_sha256', 'file_sha256', 'receipt_sha256', 'spdx_sha256', 'inventory_sha256'))
                or sealed['reference'] != 'ghcr.io/p11lab/softhsm2@sha256:' + sealed['manifest_sha256']
                or content['reference'] != 'ghcr.io/p11lab/softhsm2@sha256:' + content['manifest_sha256']
                or sealed['receipt_sha256'] != files['source-records']['sealed-source.json']['sha256']
                or content['receipt_sha256'] != files['source-records']['source-companion.json']['sha256']
                or content['spdx_sha256'] != files['source-records']['sbom.spdx.json']['sha256']):
            raise ValueError('custody immutable source identity mismatch')
        archives = value['source_archives']
        if type(archives) is not dict or set(archives) != {'sealed', 'content'}:
            raise ValueError('invalid custody source archive roster')
        for role, expected in (('sealed', sealed['archive_sha256']), ('content', content['file_sha256'])):
            row = archives[role]
            if (type(row) is not dict or set(row) != {'size', 'sha256', 'media_type'}
                    or type(row['size']) is not int or not 0 < row['size'] <= 5 * 1024**3
                    or row['sha256'] != expected or row['media_type'] != 'application/gzip'):
                raise ValueError('custody source archive identity mismatch')
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError('malformed image custody manifest') from error


def check_segment_roster(rows, *, run_id, attempt):
    """Reject missing, extra, reordered, reused or differently named segments.

    A caller must still authenticate the roster and independently read each
    exact artifact's metadata and bytes. No row here grants distribution.
    """
    if (type(run_id) is not int or run_id <= 0 or type(attempt) is not int or attempt != 1
            or type(rows) is not list or not len(SEGMENT_ROLES) <= len(rows) <= 2 * len(SEGMENT_ROLES)):
        raise ValueError('invalid custody segment roster')
    ids, digests, total = set(), set(), 0
    index = 0
    for role in SEGMENT_ROLES:
        count = 0
        while index < len(rows) and type(rows[index]) is dict and rows[index].get('role') == role:
            row = rows[index]
            count += 1
            if (set(row) != {'role', 'part', 'id', 'name', 'size', 'digest'}
                    or count > 2 or type(row['part']) is not int or row['part'] != count
                    or type(row['id']) is not int or row['id'] <= 0 or row['id'] in ids
                    or type(row['size']) is not int or not 0 < row['size'] <= CUSTODY_ZIP_LIMIT
                    or row['name'] != f'p11lab-image-custody-{role}-part{count}-{run_id}-{attempt}'
                    or type(row['digest']) is not str or not re.fullmatch(r'sha256:[0-9a-f]{64}', row['digest'])
                    or row['digest'] in digests):
                raise ValueError('invalid or reused custody segment identity')
            ids.add(row['id'])
            digests.add(row['digest'])
            total += row['size']
            index += 1
        if count == 0:
            raise ValueError('missing custody segment role: ' + role)
    if index != len(rows):
        raise ValueError('unexpected custody segment role')
    if total > 8 * CUSTODY_ZIP_LIMIT:
        raise ValueError('aggregate custody segment byte bound')
