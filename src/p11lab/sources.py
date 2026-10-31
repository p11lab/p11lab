"""Hash-checked acquisition with retained original archives and ordered patches."""
from contextlib import ExitStack
import hashlib
from importlib.resources import as_file
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
from urllib.request import urlopen

from .catalog import locked_asset, validate_build_inputs
from .jsonutil import loads as strict_json_loads


class SourceError(ValueError):
    """Source resolution did not satisfy the declared immutable inputs."""


def checksum(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def _command(argv, *, cwd=None):
    result = subprocess.run(argv, cwd=cwd, capture_output=True, text=True)
    if result.returncode:
        raise SourceError(f'source checkout/revision or patch operation failed: {result.stderr.strip()}')
    return result.stdout.strip()


def acquire_source(source: dict, output_dir: Path) -> dict:
    """Acquire one source. Callers validate public URL/pin schemas beforehand.

    file URLs are supported by this low-level primitive for offline acquisitions;
    catalogue-driven resolve_sources requires the validated public HTTPS URL.
    Each attempt uses a fresh directory; no failed or stale checkout is reused.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=False)
    checkout = output_dir / 'checkout'
    archive = output_dir / 'source.tar'
    if source['kind'] == 'git':
        repo = output_dir / 'git'
        _command(['git', 'init', '-q', str(repo)])
        _command(['git', '-C', str(repo), 'fetch', '--depth=1', '--no-tags', source['url'], source['revision']])
        actual = _command(['git', '-C', str(repo), 'rev-parse', 'FETCH_HEAD^{commit}'])
        if actual != source['revision']:
            raise SourceError('source checkout revision mismatch')
        _command(['git', '-C', str(repo), 'archive', '--format=tar', '--output=' + str(archive.resolve()), actual])
    else:
        with urlopen(source['url'], timeout=60) as response, archive.open('wb') as stream:
            while chunk := response.read(1024 * 1024):
                stream.write(chunk)
        if checksum(archive) != source['sha256']:
            raise SourceError('source archive checksum mismatch')
    if source.get('archive_sha256') and checksum(archive) != source['archive_sha256']:
        raise SourceError('git source archive checksum mismatch')
    checkout.mkdir()
    try:
        with tarfile.open(archive) as contents:
            contents.extractall(checkout, filter='data')
    except (tarfile.TarError, OSError) as error:
        raise SourceError('unsafe or invalid source archive') from error
    return {'source': source, 'archive': str(archive), 'sha256': checksum(archive), 'checkout': str(checkout)}


def apply_patches(checkout: Path, patches: list[Path]) -> None:
    """A failed declared patch is fatal; never silently skip or reorder it."""
    for patch in patches:
        _command(['patch', '--batch', '--forward', '-p1', '-i', str(Path(patch).resolve())], cwd=checkout)


def resolve_sources(spec: dict, *, output_dir: Path | None = None) -> dict:
    """Resolve a packaged locked spec; retain inputs for source distribution.

    Returned paths are acquisition evidence, not portable runtime dependencies.
    No source is qualified after a checksum, revision or patch failure.
    """
    validate_build_inputs(spec)
    if output_dir is None:
        output_dir = Path(tempfile.mkdtemp(prefix='p11lab-sources-'))
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    lock = spec['lock']
    acquired = [acquire_source(source, output_dir / f'source-{index}')
                for index, source in enumerate(lock['sources'] + lock['dependencies'])]
    with ExitStack() as stack:
        targets = {record['source']['id']: record for record in acquired if 'id' in record['source']}
        for patch in lock['patches']:
            path = stack.enter_context(as_file(locked_asset(spec['id'], patch)))
            target = targets[patch['target_source']] if 'target_source' in patch else acquired[0]
            apply_patches(Path(target['checkout']), [path])
    result = {'schema_version': 1, 'sources': acquired[:len(lock['sources'])],
              'dependencies': acquired[len(lock['sources']):], 'patches': lock['patches']}
    (output_dir / 'resolved-sources.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def _portable_inventory(inventory: dict) -> dict:
    """Drop acquisition paths and local references from recipient metadata."""
    import copy
    result = copy.deepcopy(inventory)
    for payload in result['payloads']:
        payload.pop('local_path', None)
    for archive in result.get('package_archives', []):
        archive.pop('local_path', None)
    # A local reference is an acquisition handle, not a public identity.
    for ref in (result['artifact'], result['observation']['artifact']):
        if ref['kind'] in ('bundle', 'custody-tree', 'custody-evaluator-metadata'):
            ref['reference'] = 'sha256:' + ref['sha256']
    return result


def _payload_copy(payload: dict, destination: Path) -> None:
    import shutil
    size = payload['size']
    if size > 1024**3:
        raise SourceError('source payload exceeds 1 GiB acquisition bound')
    destination.parent.mkdir(parents=True, exist_ok=True)
    if 'local_path' in payload:
        path = Path(payload['local_path'])
        if not path.is_file() or path.is_symlink() or path.stat().st_size != size:
            raise SourceError('source payload size/type mismatch: ' + payload['path'])
        shutil.copyfile(path, destination)
    else:
        from urllib.parse import urlparse
        url = payload.get('url', '')
        if urlparse(url).scheme != 'https' or urlparse(url).username or urlparse(url).password:
            raise SourceError('source payload needs local verified file or public HTTPS URL')
        count = 0
        with urlopen(url, timeout=60) as response, destination.open('wb') as stream:
            redirected = urlparse(response.geturl())
            if redirected.scheme != 'https' or redirected.username or redirected.password:
                raise SourceError('source payload redirected outside public HTTPS')
            while chunk := response.read(min(1024 * 1024, size + 1 - count)):
                count += len(chunk)
                if count > size:
                    raise SourceError('source payload exceeds declared size')
                stream.write(chunk)
    if destination.stat().st_size != size or checksum(destination) != payload['sha256']:
        raise SourceError('source payload checksum/size mismatch: ' + payload['path'])


def _verify_debian_source_sets(files: Path, inventory: dict) -> None:
    import re
    from .licenses import relative_path
    discovered = {identity for package in inventory.get('observation', {}).get('packages', [])
        for identity in [package['source_package'] + '=' + package['source_version']] + package['incorporated_sources']}
    for source in inventory['sources']:
        if not source.get('name') or not source.get('version') or source['id'] != source['name'] + '=' + source['version']:
            raise SourceError('source identity mismatch: ' + source['id'])
        if source.get('format') != 'debian' and source['id'] not in discovered:
            continue
        dscs = [name for name in source['payloads'] if name.endswith('.dsc')]
        if len(dscs) != 1:
            raise SourceError('Debian source payload needs one exact dsc: ' + source['id'])
        dsc = files / relative_path(dscs[0])
        text = dsc.read_text()
        for field, wanted in [('Source', source['name']), ('Version', source['version'])]:
            if not re.search(r'^' + field + ': ' + re.escape(wanted) + r'$', text, re.M):
                raise SourceError('Debian source identity mismatch: ' + source['id'])
        match = re.search(r'^Checksums-Sha256:\n((?:[ \t].*\n)+)', text, re.M)
        if not match:
            raise SourceError('Debian source missing payload checksums: ' + source['id'])
        for line in match[1].splitlines():
            digest, size, name = line.split()
            relative_path(name)
            path = dsc.parent / name
            relative = path.relative_to(files).as_posix()
            if relative not in source['payloads'] or not path.is_file() or path.stat().st_size != int(size) or checksum(path) != digest:
                raise SourceError('Debian corresponding-source payload missing/mismatched: ' + relative)


def _deb_members(path: Path) -> dict[str, bytes]:
    """Read bounded Debian ar members without executing package tools/hooks."""
    members = {}
    with path.open('rb') as stream:
        if stream.read(8) != b'!<arch>\n':
            raise SourceError('invalid package archive header')
        while header := stream.read(60):
            if len(header) != 60 or header[58:] != b'`\n':
                raise SourceError('invalid package archive member header')
            name = header[:16].decode('ascii').strip().removesuffix('/')
            size = int(header[48:58])
            if not name or name in members or not 0 <= size <= 1024**3 or len(members) >= 16:
                raise SourceError('duplicate/oversized package archive member')
            data = stream.read(size)
            if len(data) != size or (size % 2 and stream.read(1) != b'\n'):
                raise SourceError('truncated package archive member')
            members[name] = data
    if members.get('debian-binary') != b'2.0\n':
        raise SourceError('unsupported package archive version')
    return members


def _package_tar_files(data: bytes) -> dict[str, tuple[str, bytes | None]]:
    import io
    from .licenses import relative_path
    result, seen, total = {}, set(), 0
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:*') as contents:
        for member in contents:
            name = member.name.removeprefix('./').rstrip('/')
            if member.isdir() and name in {'', '.'}:
                continue
            relative_path(name)
            total += member.size
            if name in seen or len(seen) >= 50000 or member.size > 512 * 1024**2 or total > 2 * 1024**3:
                raise SourceError('duplicate/oversized package tar member')
            seen.add(name)
            if member.isfile():
                with contents.extractfile(member) as stream:
                    if name == 'control':
                        if member.size > 1024**2:
                            raise SourceError('oversized package control')
                        control = stream.read()
                        result[name] = (hashlib.sha256(control).hexdigest(), control)
                    else:
                        result[name] = (hashlib.file_digest(stream, 'sha256').hexdigest(), None)
    return result


def _verify_package_files(inventory: dict, files: Path, cache: Path) -> None:
    """Recheck authenticated archive selectors and every declared member SHA256.

    Authentication is an explicit reviewed selector supplied with evidence, just
    as source/grant review is. Binary archives stay outside the source companion.
    A retained cache is always rehashed; absent bytes may be acquired over HTTPS.
    """
    from .licenses import relative_path, parse_dpkg_status
    import posixpath
    observation = inventory.get('observation', {})
    packages = {p['name']: p for p in observation.get('packages', [])}
    observed = {f['path']: f for f in observation.get('files', [])}
    def installed_path(member):
        path, seen = '/' + relative_path(member), set()
        for _ in range(40):
            parts = path.strip('/').split('/')
            for i in range(1, len(parts) + 1):
                prefix = '/' + '/'.join(parts[:i])
                link = observed.get(prefix, {}).get('link')
                if link is not None:
                    if path in seen:
                        raise SourceError('cyclic package file alias')
                    seen.add(path)
                    target = link if link.startswith('/') else posixpath.join(posixpath.dirname(prefix), link)
                    path = posixpath.normpath(posixpath.join(target, *parts[i:]))
                    break
            else:
                return path
        raise SourceError('package file alias depth exceeded')
    checked = set()
    for record in inventory.get('package_archives', []):
        digest = record['sha256']
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest) or digest in checked:
            raise SourceError('invalid/duplicate package archive digest')
        checked.add(digest)
        authentication = record.get('authentication', {})
        if authentication.get('status') != 'reviewed':
            raise SourceError('unreviewed package archive authentication')
        selector = json.loads((files / relative_path(authentication['evidence_path'])).read_text())
        fields = ('package', 'version', 'architecture', 'source', 'sha256', 'size', 'url')
        if any(selector.get(field) != record.get(field) for field in fields):
            raise SourceError('authenticated package selector mismatch')
        cached = cache / (digest + '.deb')
        if cached.exists() or cached.is_symlink():
            if cached.is_symlink() or not cached.is_file() or cached.stat().st_size != record['size'] or checksum(cached) != digest:
                raise SourceError('package archive cache checksum/size mismatch')
        else:
            _payload_copy(record | {'path': digest + '.deb'}, cached)
        members = _deb_members(cached)
        def tar_member(prefix):
            names = [n for n in members if n in {prefix + suffix for suffix in ('.tar', '.tar.gz', '.tar.xz', '.tar.bz2')}]
            if len(names) != 1:
                raise SourceError('missing/unsupported package ' + prefix + ' archive')
            return _package_tar_files(members[names[0]])
        controls = tar_member('control')
        control = controls.get('control', (None, None))[1]
        if control is None or parse_dpkg_status(control.decode().rstrip('\n') + '\nStatus: install ok installed\n') != [packages.get(record['package'])]:
            raise SourceError('package control/installed identity mismatch')
        payload = tar_member('data')
        for file in inventory.get('package_files', []):
            if file.get('archive_sha256') != digest:
                continue
            member = relative_path(file['member'])
            if (file.get('package') != record['package'] or installed_path(member) != file.get('path')
                    or payload.get(member, (None,))[0] != file.get('sha256')):
                raise SourceError('authenticated package file/member SHA256 mismatch: ' + file['path'])
    if any(f.get('archive_sha256') not in checked for f in inventory.get('package_files', [])):
        raise SourceError('package file lacks authenticated archive')


def collect_source_bundle(artifact, inventory: dict, output_dir: Path, *,
                          inspection_policy=None, journal_path=None, consumer_binding=None) -> Path:
    """Collect exact retained sources/notices/recipes from reviewed declarations.

    Local cache paths are optional acquisition inputs, removed from the archive.
    Hashes and source closure are mandatory; URLs alone never count as sources.
    A fresh output directory preserves prior attempts. No public write occurs.
    """
    from .licenses import inspect_artifact, validate_inventory, spdx_inventory, relative_path
    reasons = validate_inventory(artifact, inventory, consumer_binding=consumer_binding)
    if inspection_policy is None and journal_path is None:
        actual = inspect_artifact(artifact)
    else:
        actual = inspect_artifact(artifact, inspection_policy=inspection_policy, journal_path=journal_path)
    if actual != inventory.get('observation'):
        reasons.append('actual binary content inventory mismatch')
    if reasons:
        raise SourceError('; '.join(reasons))
    output_dir = Path(output_dir)
    if sum(p['size'] for p in inventory['payloads']) > 4 * 1024**3:
        raise SourceError('source collection exceeds 4 GiB bound')
    output_dir.mkdir(parents=True, exist_ok=False)
    files = output_dir / 'files'
    files.mkdir()
    reserved = {'inventory.json', 'SHA256SUMS', 'sbom.spdx.json'}
    for payload in inventory['payloads']:
        if payload['path'] in reserved:
            raise SourceError('payload conflicts with generated metadata')
        _payload_copy(payload, files / relative_path(payload['path']))
    _verify_debian_source_sets(files, inventory)
    _verify_package_files(inventory, files, output_dir / 'package-cache')
    public = _portable_inventory(inventory)
    (files / 'inventory.json').write_text(json.dumps(public, sort_keys=True, indent=2) + '\n')
    sbom = spdx_inventory(artifact, public)
    (files / 'sbom.spdx.json').write_text(json.dumps(sbom, sort_keys=True, indent=2) + '\n')
    manifest = {p.relative_to(files).as_posix(): checksum(p) for p in sorted(files.rglob('*')) if p.is_file()}
    (files / 'SHA256SUMS').write_text(''.join(digest + '  ' + path + '\n' for path, digest in manifest.items()))
    archive = output_dir / 'source-companion.tar.gz'
    with tarfile.open(archive, 'w:gz') as contents:
        for path in sorted(files.rglob('*')):
            if path.is_file():
                contents.add(path, arcname=path.relative_to(files).as_posix(), recursive=False)
    import shutil
    shutil.copyfile(files / 'sbom.spdx.json', output_dir / 'sbom.spdx.json')
    # Public identity uses the immutable archive digest, never a staging path.
    receipt = {'schema_version': 1, 'role': 'source-companion', 'archive': archive.name,
        'artifact': {'kind': 'bundle', 'reference': 'sha256:' + checksum(archive), 'sha256': checksum(archive), 'platform': artifact.platform},
        'matched_artifact': public['artifact'], 'size_bytes': archive.stat().st_size,
        'sbom_sha256': checksum(output_dir / 'sbom.spdx.json'), 'inventory_sha256': checksum(files / 'inventory.json'),
        'payload_count': len(inventory['payloads']), 'source_count': len(inventory['sources']),
        'publication_status': 'not-published', 'source_rights': 'explicit reviewed records; no automatic grant inference'}
    (output_dir / 'source-companion.json').write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')
    return archive


def verify_source_receipt(artifact, receipt: dict, archive: Path, extracted: Path,
                          outer_spdx: Path, inventory: dict) -> None:
    """Check complete companion metadata/bytes, without a new rights evaluator."""
    from .licenses import _same_artifact, spdx_inventory
    if inventory != _portable_inventory(inventory):
        raise SourceError('source companion inventory contains private acquisition paths')
    digest = checksum(archive)
    expected = {'schema_version': 1, 'role': 'source-companion', 'archive': archive.name,
        'artifact': {'kind': 'bundle', 'reference': 'sha256:' + digest, 'sha256': digest, 'platform': artifact.platform},
        'matched_artifact': inventory['artifact'], 'size_bytes': archive.stat().st_size,
        'sbom_sha256': checksum(extracted / 'sbom.spdx.json'), 'inventory_sha256': checksum(extracted / 'inventory.json'),
        'payload_count': len(inventory['payloads']), 'source_count': len(inventory['sources']),
        'publication_status': 'not-published', 'source_rights': 'explicit reviewed records; no automatic grant inference'}
    if json.dumps(receipt, sort_keys=True) != json.dumps(expected, sort_keys=True):
        raise SourceError('source companion receipt metadata mismatch')
    if not _same_artifact(inventory['artifact'], artifact) or not _same_artifact(inventory['observation']['artifact'], artifact):
        raise SourceError('source companion ArtifactRef/platform mismatch')
    if outer_spdx.read_bytes() != (extracted / 'sbom.spdx.json').read_bytes():
        raise SourceError('outer/embedded SPDX inventory mismatch')
    sbom = strict_json_loads(outer_spdx.read_text())
    generated = spdx_inventory(artifact, inventory)
    # Creation time is observational metadata, not semantic inventory content.
    if not isinstance(sbom, dict) or not isinstance(sbom.get('creationInfo'), dict):
        raise SourceError('SPDX creation metadata missing')
    generated['creationInfo']['created'] = sbom['creationInfo'].get('created')
    if json.dumps(sbom, sort_keys=True) != json.dumps(generated, sort_keys=True):
        raise SourceError('SPDX content/inventory mismatch')


def verify_source_bundle(archive: Path, output_dir: Path) -> dict:
    """Extract only regular files into a new owned directory and verify every byte.

    Bound-based posture (deliberate): third-party source companions carry no
    install manifest, so there is no roster to be strict against; safety comes
    from regular-file-only extraction plus per-member/total/count bounds, with
    identity proven by the outer archive digest. Manifest-rostered bundles use
    the stricter check in bundle.py instead.
    """
    from .licenses import relative_path
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=False)
    total = 0
    seen = set()
    try:
        with tarfile.open(archive) as contents:
            for member in contents:
                name = relative_path(member.name)
                if not member.isfile() or name in seen or member.size > 1024**3:
                    raise SourceError('unsafe/duplicate/oversized source companion member')
                total += member.size
                if total > 4 * 1024**3 or len(seen) >= 50000:
                    raise SourceError('source companion exceeds extraction bounds')
                seen.add(name)
                destination = output_dir / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                import shutil
                with contents.extractfile(member) as source, destination.open('xb') as target:
                    shutil.copyfileobj(source, target)
        expected = {}
        for line in (output_dir / 'SHA256SUMS').read_text().splitlines():
            digest, name = line.split('  ', 1)
            relative_path(name)
            if name in expected:
                raise SourceError('duplicate companion manifest entry')
            expected[name] = digest
        if set(expected) != seen - {'SHA256SUMS'}:
            raise SourceError('source companion manifest roster mismatch')
        for name, digest in expected.items():
            if checksum(output_dir / name) != digest:
                raise SourceError('source companion checksum mismatch: ' + name)
        inventory = strict_json_loads((output_dir / 'inventory.json').read_text())
        strict_json_loads((output_dir / 'sbom.spdx.json').read_text())
        for payload in inventory['payloads']:
            name = relative_path(payload['path'])
            if name not in expected or expected[name] != payload['sha256'] or (output_dir / name).stat().st_size != payload['size']:
                raise SourceError('source payload manifest mismatch: ' + name)
        payload_names = [relative_path(payload['path']) for payload in inventory['payloads']]
        if (len(payload_names) != len(set(payload_names))
                or set(payload_names) & {'inventory.json', 'sbom.spdx.json', 'SHA256SUMS'}
                or seen != set(payload_names) | {'inventory.json', 'sbom.spdx.json', 'SHA256SUMS'}):
            raise SourceError('source companion inventory file roster mismatch')
        _verify_debian_source_sets(output_dir, inventory)
        return inventory
    except (tarfile.TarError, OSError, KeyError, ValueError) as error:
        raise SourceError('invalid source companion: ' + str(error)) from error
