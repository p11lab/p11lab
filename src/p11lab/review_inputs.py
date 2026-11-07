"""Fetch lock-pinned Debian bytes and extract license evidence for human review.

Scope is Debian inputs only: lock-pinned binary/source/index bytes plus
statically incorporated sources resolved through InRelease-pinned Sources.xz
indices. Provider upstream sources, dependencies, and patches are listed in
the report as explicitly not gathered.

Mechanical only: downloads, hash verification, and text extraction. This module
never concludes licenses, grants, redistribution rights, or eligibility; the
reviewer writes those conclusions into the committed inventory template from
the gathered bundle. Absence of report.json in the output directory means the
gathering did not complete; no partial result is ever claimed complete.
"""
import hashlib
import io
import json
import lzma
import re
import tarfile
import time
import tomllib
from pathlib import Path
from urllib.request import HTTPRedirectHandler, build_opener

from .sources import SourceError, checksum

SCHEMA_VERSION = 1
FETCH_ATTEMPTS = 6
PAYLOAD_SIZE_BOUND = 1024**3
EVIDENCE_FILE_BOUND = 1024**2
EVIDENCE_TAR_BOUND = 16 * 1024**2
COMPRESSED_INDEX_BOUND = 128 * 1024**2
INDEX_DECODER_MEMLIMIT = 256 * 1024**2
LICENSE_BASENAME = re.compile(r'(?i)(license|licence|copying|copyright)(\.|$|-|_)')
CARGO_LICENSE_FALLBACK = re.compile(r'^\s*license\s*=\s*["\']([^"\']+)["\']', re.M)
CARGO_LICENSE_FILE_FALLBACK = re.compile(r'^\s*license-file\s*=\s*["\']([^"\']+)["\']', re.M)
SOURCE_IDENTITY = re.compile(r'[a-z0-9][a-z0-9+.-]*=[0-9A-Za-z][0-9A-Za-z.+~:-]*')
BUILT_USING_ENTRY = re.compile(r'\s*([^ ()]+)\s*\(=\s*([^()]+)\)\s*')
INDEX_FILENAME = re.compile(r'snapshot\.debian\.org_archive_(debian(?:-security)?)_'
                             r'(\d{8}T\d{6}Z)_dists_(trixie(?:-updates|-security)?)_'
                             r'(InRelease|main_source_Sources\.lz4|main_binary-amd64_Packages\.lz4)')
INDEX_URL_PATH = {'InRelease': 'InRelease', 'main_source_Sources.lz4': 'main/source/Sources.lz4',
                  'main_binary-amd64_Packages.lz4': 'main/binary-amd64/Packages.lz4'}
POOL_DIRECTORY = re.compile(r'pool/(updates/)?(main|contrib|non-free|non-free-firmware)/[A-Za-z0-9+./~-]*')
SUITE_PREFERENCE = ('trixie', 'trixie-updates', 'trixie-security')


def _pool_directory_ok(directory):
    return (POOL_DIRECTORY.fullmatch(directory) is not None
            and all(segment not in ('.', '..') for segment in directory.split('/')))
DECODED_INDEX_BOUND = 512 * 1024**2


class FetchError(Exception):
    """Transient acquisition failure; the caller may retry."""


class _HTTPSOnlyRedirect(HTTPRedirectHandler):
    """Reject any redirect hop leaving public HTTPS (checked per hop)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        from urllib.parse import urlparse
        parsed = urlparse(newurl)
        if parsed.scheme != 'https' or parsed.username or parsed.password:
            raise SourceError('source payload redirected outside public HTTPS')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_url(url, size, sha256):
    """Fetch one pinned file over public HTTPS with size and hash checks."""
    from urllib.parse import urlparse
    from urllib.request import Request
    if type(size) is not int or not 0 < size <= PAYLOAD_SIZE_BOUND:
        raise SourceError('source payload size outside acquisition bound')
    if not re.fullmatch(r'[0-9a-f]{64}', sha256 or ''):
        raise SourceError('source payload lacks pinned sha256')
    parsed = urlparse(url or '')
    if parsed.scheme != 'https' or parsed.username or parsed.password:
        raise SourceError('source payload needs a public HTTPS URL')
    try:
        opener = build_opener(_HTTPSOnlyRedirect)
        request = Request(url, headers={'User-Agent': 'p11lab-review-inputs/1'})
        with opener.open(request, timeout=120) as response:
            redirected = urlparse(response.geturl())
            if redirected.scheme != 'https' or redirected.username or redirected.password:
                raise SourceError('source payload redirected outside public HTTPS')
            raw = response.read(size + 1)
    except SourceError:
        raise
    except Exception as error:
        raise FetchError(str(error) or type(error).__name__) from error
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != sha256:
        raise SourceError('source payload checksum/size mismatch')
    return raw


def _read_ar_members(raw):
    """Parse a Debian .deb (ar) archive into ordered (name, bytes) members."""
    if raw[:8] != b'!<arch>\n':
        raise SourceError('not an ar archive')
    members = []
    offset = 8
    while offset < len(raw):
        if len(raw) - offset < 60:
            raise SourceError('truncated ar member header')
        header = raw[offset:offset + 60]
        name = header[:16].decode('ascii', 'replace').rstrip()
        if name.endswith('/'):
            name = name[:-1]
        if '/' in name or not name or name.startswith(('#', '/')):
            raise SourceError('unsupported ar long-name member')
        try:
            size = int(header[48:58].decode('ascii').strip())
        except ValueError:
            raise SourceError('invalid ar member size') from None
        if header[58:60] != b'\x60\x0a' or size < 0 or offset + 60 + size > len(raw):
            raise SourceError('corrupt ar member')
        members.append((name, raw[offset + 60:offset + 60 + size]))
        offset += 60 + size + (size % 2)
    return members


def _tar_members(raw, *, name_hint=''):
    """Open a tar payload (any compression tarfile supports) for member reads."""
    try:
        return tarfile.open(fileobj=io.BytesIO(raw), mode='r:*')
    except tarfile.TarError as error:
        if name_hint.endswith('.tar.zst'):
            raise SourceError('unreadable zstd tar payload (needs Python 3.14+): ' + name_hint) from error
        raise SourceError('unreadable tar payload ' + name_hint) from error


def _safe_evidence_name(member):
    base = member.rsplit('/', 1)[-1]
    if not base or base in ('.', '..') or '/' in base or '\\' in base:
        return None
    if any(char < ' ' or char == '\x7f' for char in base):
        return None
    if len(base) > 100:
        base = base[:60] + '..' + base[-38:]
    return base


def _displayable_name(member):
    return ''.join(char if ' ' <= char != '\x7f' else '?' for char in member)


def _portable_component(name):
    """Quote characters rejected by artifact upload / NTFS-style filesystems.

    Debian identities carry epoch colons (attr=1:2.5.2-3) and archive member
    names are arbitrary upstream bytes; either would abort the CI bundle
    upload. Percent-quoting (including '%' itself) keeps the mapping
    injective, so distinct names never collide on disk.
    """
    return ''.join('%%%02X' % ord(char) if char in '"*:<>?|/\\%\r\n' or char < ' ' or char == '\x7f'
                   else char for char in name)


def _extract_texts(tar, evidence_dir, *, budget):
    """Retain license-like member bytes; returns {member: (relpath, sha256)} and gaps."""
    kept, gaps = {}, []
    spent = 0
    for member in tar.getmembers():
        if not member.isfile():
            continue
        base = _safe_evidence_name(member.name)
        if base is None:
            gaps.append('unsupported-member-name:' + _displayable_name(member.name))
            continue
        if not LICENSE_BASENAME.search(base):
            continue
        if member.size > EVIDENCE_FILE_BOUND:
            gaps.append('oversize-license-file:' + member.name)
            continue
        if spent + member.size > budget:
            gaps.append('evidence-budget-exceeded')
            break
        reader = tar.extractfile(member)
        if reader is None:
            continue
        raw = reader.read()
        digest = hashlib.sha256(raw).hexdigest()
        target = evidence_dir / (digest[:16] + '-' + _portable_component(base))
        if not target.exists():
            target.write_bytes(raw)
        kept[member.name] = (target.name, digest)
        spent += len(raw)
    return kept, gaps


def _cargo_signals(tar):
    """Read [package] license fields from the shallowest Cargo.toml in the tree.

    Returns (license, license_file, gaps, manifest_member or None).
    """
    manifests = [m for m in tar.getmembers()
                 if m.isfile() and (m.name == 'Cargo.toml' or m.name.endswith('/Cargo.toml'))]
    if not manifests:
        return None, None, [], None
    member = min(manifests, key=lambda m: m.name.count('/'))
    if member.size > EVIDENCE_FILE_BOUND:
        return None, None, ['oversize-cargo-toml'], member.name
    reader = tar.extractfile(member)
    raw = reader.read() if reader else b''
    try:
        package = tomllib.loads(raw.decode('utf-8')).get('package', {})
        if type(package) is not dict:
            raise ValueError('non-table package')
        license_value = package.get('license')
        file_value = package.get('license-file')
        if license_value is not None and type(license_value) is not str:
            return None, None, ['cargo-license-not-string'], member.name
        if file_value is not None and type(file_value) is not str:
            return None, None, ['cargo-license-file-not-string'], member.name
        return license_value, file_value, [], member.name
    except (tomllib.TOMLDecodeError, ValueError, UnicodeDecodeError):
        text = raw.decode('utf-8', 'replace')
        license_match = CARGO_LICENSE_FALLBACK.search(text)
        file_match = CARGO_LICENSE_FILE_FALLBACK.search(text)
        return (license_match.group(1) if license_match else None,
                file_match.group(1) if file_match else None,
                ['cargo-toml-unparseable'], member.name)


def _has_rust_signals(tar):
    for member in tar.getmembers():
        if not member.isfile():
            continue
        plain = member.name[2:] if member.name.startswith('./') else member.name
        base = plain.rsplit('/', 1)[-1]
        if base in ('Cargo.toml', 'Cargo.lock') or base.endswith('.rs'):
            return True
    return False


def _tar_root(tar):
    """Single top-level directory shared by all members, or None if wrapperless."""
    tops = {m.name[2:].split('/', 1)[0] if m.name.startswith('./') else m.name.split('/', 1)[0]
            for m in tar.getmembers() if m.name not in ('', '.', './')}
    if len(tops) != 1:
        return None
    (only,) = tops
    return only if any('/' in (m.name[2:] if m.name.startswith('./') else m.name) for m in tar.getmembers()) else None


def _record_copyright(tar, evidence_dir, identity, evidence, gaps):
    root = _tar_root(tar)
    want = root + '/debian/copyright' if root else 'debian/copyright'
    for member in tar.getmembers():
        if not member.isfile():
            continue
        plain = member.name[2:] if member.name.startswith('./') else member.name
        if plain != 'debian/copyright' and not plain.endswith('/debian/copyright'):
            continue
        if member.size > EVIDENCE_FILE_BOUND:
            gaps.append('oversize-debian-copyright')
            continue
        reader = tar.extractfile(member)
        text = reader.read() if reader else b''
        digest = hashlib.sha256(text).hexdigest()
        target = evidence_dir / ('copyright-' + digest[:16])
        target.write_bytes(text)
        relpath = str(Path('evidence') / _portable_component(identity) / target.name)
        evidence[member.name] = relpath
        # Only the packaging-root copyright satisfies the requirement;
        # vendored copies are retained as evidence under their own paths.
        if plain == want:
            evidence['debian/copyright'] = relpath


def _resolve_license_file(tar, manifest, declared, evidence_dir, identity, evidence, gaps):
    """Resolve a Cargo license-file path safely inside the tar; records gaps."""
    if not declared or declared.startswith('/') or '\\' in declared:
        gaps.append('missing-cargo-license-file')
        return
    parts = [p for p in declared.split('/') if p not in ('', '.')]
    if not parts or '..' in parts:
        gaps.append('missing-cargo-license-file')
        return
    root = manifest[2:] if manifest.startswith('./') else manifest
    home = root.rsplit('/', 1)[0] if '/' in root else ''
    candidates = [home + '/' + '/'.join(parts) if home else '/'.join(parts), '/'.join(parts)]
    members = {m.name[2:] if m.name.startswith('./') else m.name: m
               for m in tar.getmembers() if m.isfile()}
    for candidate in dict.fromkeys(candidates):
        member = members.get(candidate)
        if member is None:
            continue
        if member.size > EVIDENCE_FILE_BOUND:
            gaps.append('oversize-cargo-license-file')
            return
        reader = tar.extractfile(member)
        text = reader.read() if reader else b''
        digest = hashlib.sha256(text).hexdigest()
        base = _safe_evidence_name(member.name) or 'license-file'
        target = evidence_dir / (digest[:16] + '-' + _portable_component(base))
        if not target.exists():
            target.write_bytes(text)
        evidence[member.name] = str(Path('evidence') / _portable_component(identity) / target.name)
        return
    gaps.append('missing-cargo-license-file')


def _dsc_roster(raw):
    """Parse a .dsc into {basename: (sha256 or None, size)} from checksum rosters."""
    fields = _parse_deb822(_strip_clearsign(raw[:262144].decode('utf-8', 'replace')))
    for section in ('checksums-sha256', 'checksums-sha1', 'files'):
        rows = _checksum_rows(fields.get(section, ''), kind='.dsc')
        if not rows:
            continue
        roster = {}
        for digest, size, name in rows:
            if not size.isdigit():
                raise SourceError('malformed .dsc file size')
            roster[name] = (digest if section == 'checksums-sha256' else None, int(size))
        return roster
    return {}


def _gather_source(entry, files_dir, evidence_dir, fetch, *, via):
    identity = entry['name'] + '=' + entry['version']
    fetched = {}
    for item in entry['files']:
        raw = fetch(item['filename'])
        target = files_dir / item['filename'].rsplit('/', 1)[-1]
        target.write_bytes(raw)
        fetched[item['filename']] = hashlib.sha256(raw).hexdigest()
    gaps = []
    evidence = {}
    cargo_license = cargo_license_file = cargo_manifest = None
    saw_orig = saw_debian = saw_rust = False
    native_format = False
    dsc_seen = False
    for item in entry['files']:
        name = item['filename']
        raw = (files_dir / name.rsplit('/', 1)[-1]).read_bytes()
        if hashlib.sha256(raw).hexdigest() != fetched[name]:
            raise SourceError('retained payload changed during gathering: ' + name)
        if name.endswith('.dsc'):
            dsc_seen = True
            if re.search(r'^Format: 3\.0 \(native\)\s*$', raw[:65536].decode('utf-8', 'replace'), re.M):
                native_format = True
            roster = _dsc_roster(raw)
            have = {path.rsplit('/', 1)[-1]: digest for path, digest in fetched.items()}
            sizes = {item['filename'].rsplit('/', 1)[-1]: item['size'] for item in entry['files']}
            for filename, (digest, size) in roster.items():
                if filename not in have:
                    raise SourceError('dsc lists unfetched file %s: %s' % (identity, filename))
                if sizes[filename] != size:
                    raise SourceError('dsc size mismatch %s: %s' % (identity, filename))
                if digest is not None and have[filename] != digest:
                    raise SourceError('dsc checksum mismatch %s: %s' % (identity, filename))
        if name.endswith(('.tar.gz', '.tar.xz', '.tar.bz2', '.tar.zst')) and '.debian.tar' not in name:
            saw_orig = True
            with _tar_members(raw, name_hint=name) as tar:
                found_license, found_file, cargo_gaps, manifest = _cargo_signals(tar)
                gaps.extend(cargo_gaps)
                if cargo_license is None and found_license is not None:
                    cargo_license, cargo_manifest = found_license, manifest
                if cargo_license_file is None and found_file is not None:
                    cargo_license_file = found_file
                    if cargo_manifest is None:
                        cargo_manifest = manifest
                    _resolve_license_file(tar, manifest, found_file, evidence_dir, identity, evidence, gaps)
                saw_rust = saw_rust or _has_rust_signals(tar)
                kept, kept_gaps = _extract_texts(tar, evidence_dir, budget=EVIDENCE_TAR_BOUND)
                evidence.update({member: str(Path('evidence') / _portable_component(identity) / filename) for member, (filename, _) in kept.items()})
                gaps.extend(kept_gaps)
                _record_copyright(tar, evidence_dir, identity, evidence, gaps)
        elif '.debian.tar' in name:
            saw_debian = True
            with _tar_members(raw, name_hint=name) as tar:
                _record_copyright(tar, evidence_dir, identity, evidence, gaps)
    if not saw_orig:
        gaps.append('no-orig-tarball')
    if not dsc_seen:
        gaps.append('no-dsc')
    if not saw_debian and not native_format:
        gaps.append('no-debian-tarball')
    if 'debian/copyright' not in evidence:
        gaps.append('no-debian-copyright')
    if saw_rust and cargo_license is None and cargo_license_file is None:
        gaps.append('no-cargo-license')
    return {'verified': True, 'via': via, 'files': fetched, 'cargo_license': cargo_license,
            'cargo_license_file': cargo_license_file, 'cargo_manifest': cargo_manifest,
            'evidence': evidence, 'gaps': sorted(set(gaps))}


def _gather_binary(package, files_dir, evidence_dir, fetch):
    identity = package['name'] + '=' + package['version']
    item = package['binary_acquisition']
    raw = fetch(item['filename'])
    target = files_dir / item['filename'].rsplit('/', 1)[-1]
    target.write_bytes(raw)
    gaps = []
    evidence = {}
    incorporated = []
    members = _read_ar_members(raw)
    # Control problems are fatal: without a readable control file the
    # incorporated closure is unknown and completeness cannot be claimed.
    controls = [body for name, body in members if name.startswith('control.tar')]
    datas = [body for name, body in members if name.startswith('data.tar')]
    if len(controls) != 1 or len(datas) > 1:
        raise SourceError('ambiguous or missing ar members in ' + item['filename'])
    try:
        with _tar_members(controls[0], name_hint=item['filename']) as tar:
            names = tar.getnames()
            present = [name for name in ('control', './control') if name in names]
            if not present:
                problem = 'control file missing in ' + item['filename']
                text = ''
            elif any(tar.getmember(name).size > EVIDENCE_FILE_BOUND for name in present):
                problem = 'oversize control file in ' + item['filename']
                text = ''
            else:
                bodies = set()
                for name in present:
                    reader = tar.extractfile(name)
                    bodies.add(reader.read() if reader else b'')
                if len(bodies) != 1:
                    problem = 'conflicting control files in ' + item['filename']
                    text = ''
                else:
                    text = bodies.pop().decode('utf-8', 'replace')
                    problem = None
    except SourceError as error:
        raise SourceError('unreadable control tarball in %s: %s' % (item['filename'], error)) from error
    if problem is not None:
        raise SourceError(problem)
    incorporated = _built_using_identities(text)
    data = datas[0] if datas else None
    if data is None:
        gaps.append('no-data-tarball')
        return {'verified': True, 'sha256': hashlib.sha256(raw).hexdigest(), 'size': len(raw),
                'incorporated_sources': incorporated, 'evidence': evidence, 'gaps': sorted(set(gaps))}
    found_copyright = False
    try:
        with _tar_members(data, name_hint=item['filename']) as tar:
            want = 'usr/share/doc/' + package['name'] + '/copyright'
            for member in tar.getmembers():
                base = _safe_evidence_name(member.name)
                if not member.isfile() or base is None:
                    continue
                plain = member.name[2:] if member.name.startswith('./') else member.name
                if plain != want and not (LICENSE_BASENAME.search(base) and '/usr/share/doc/' in plain):
                    continue
                if member.size > EVIDENCE_FILE_BOUND:
                    gaps.append('oversize-doc-license:' + member.name)
                    continue
                reader = tar.extractfile(member)
                text = reader.read() if reader else b''
                digest = hashlib.sha256(text).hexdigest()
                out = evidence_dir / (digest[:16] + '-' + _portable_component(base))
                if not out.exists():
                    out.write_bytes(text)
                evidence[member.name] = str(Path('evidence') / _portable_component(identity) / out.name)
                found_copyright = found_copyright or plain == want
    except SourceError as error:
        gaps.append('unreadable-data-tarball:' + str(error))
    if not found_copyright:
        gaps.append('no-installed-copyright')
    return {'verified': True, 'sha256': hashlib.sha256(raw).hexdigest(), 'size': len(raw),
            'incorporated_sources': incorporated, 'evidence': evidence, 'gaps': sorted(set(gaps))}


def _require_file_entry(item):
    name = item.get('filename') if type(item) is dict else None
    if (type(name) is not str or not name or name.startswith('/') or '\\' in name or '/./' in '/' + name
            or name in ('.', '..') or '/../' in '/' + name + '/' or not name.rsplit('/', 1)[-1]
            or any(char < ' ' or char == '\x7f' for char in name)):
        raise ValueError('malformed lock file entry')
    if (not re.fullmatch(r'[0-9a-f]{64}', item.get('sha256', ''))
            or type(item.get('size')) is not int or not 0 < item['size'] <= PAYLOAD_SIZE_BOUND):
        raise ValueError('lock file entry lacks pinned identity: ' + name)
    if type(item.get('url')) is not str or not item['url']:
        raise ValueError('lock file entry lacks URL: ' + name)
    return name.rsplit('/', 1)[-1]


def _control_field(text, field):
    match = re.search(r'^' + field + r':(.*(?:\n[ \t].*)*)', text, re.M | re.IGNORECASE)
    return ' '.join(match.group(1).split()) if match else ''


def _built_using_identities(control_text):
    """Parse Built-Using/Static-Built-Using the way dpkg status parsing does."""
    identities = set()
    for field in ('Built-Using', 'Static-Built-Using'):
        if len(re.findall(r'^' + field + r':', control_text, re.M | re.IGNORECASE)) > 1:
            raise SourceError('duplicate control field: ' + field)
        for entry in _control_field(control_text, field).split(','):
            if not entry.strip():
                continue
            identity = BUILT_USING_ENTRY.fullmatch(entry)
            if not identity:
                raise SourceError('invalid ' + field + ' entry')
            identities.add(identity[1] + '=' + identity[2].strip())
    return sorted(identities)


def _parse_deb822(paragraph):
    """Parse one deb822 paragraph; duplicate or malformed fields are fatal.

    Field names are case-insensitive per deb822; keys are stored lowered.
    """
    fields = {}
    key = None
    for line in paragraph.splitlines():
        if not line.strip():
            continue
        if line.startswith((' ', '\t')):
            if key is None:
                raise SourceError('malformed deb822 continuation')
            fields[key] += '\n' + line
        elif ':' in line:
            name, value = line.split(':', 1)
            name = name.strip().lower()
            if not name or name in fields:
                raise SourceError('duplicate or empty deb822 field: ' + name)
            key = name
            fields[key] = value.strip()
        else:
            raise SourceError('malformed deb822 line')
    return fields


def _strip_clearsign(text):
    """Return the payload of clearsigned text, or the text itself when unsigned."""
    if not text.startswith('-----BEGIN PGP SIGNED MESSAGE-----'):
        return text
    lines = text.splitlines()
    try:
        blank = lines.index('', 2)
    except ValueError:
        raise SourceError('malformed clearsign armor') from None
    end = next((i for i, line in enumerate(lines) if line.startswith('-----BEGIN PGP SIGNATURE-----')), len(lines))
    return '\n'.join(lines[blank + 1:end])


def _checksum_rows(value, *, kind, paths=False):
    rows = []
    seen = set()
    for row in value.splitlines():
        if not row.strip():
            continue
        parts = row.split()
        if len(parts) != 3:
            raise SourceError('malformed %s checksum row' % kind)
        digest, size, name = parts
        if paths:
            bad = (not name or name.startswith('/') or name in seen
                   or any(segment in ('.', '..') for segment in name.split('/')))
        else:
            bad = '/' in name or name in ('.', '..') or name in seen
        if bad:
            raise SourceError('malformed %s file identity' % kind)
        seen.add(name)
        rows.append((digest, size, name))
    return rows


def _parse_sources_index(text):
    """Parse a Sources index into {(name, version): (directory, [(sha256, size, filename)])}."""
    stanzas = {}
    for paragraph in text.split('\n\n'):
        if not paragraph.strip():
            continue
        fields = _parse_deb822(paragraph)
        if 'package' not in fields or 'version' not in fields:
            continue
        files = []
        for digest, size, name in _checksum_rows(fields.get('checksums-sha256', ''), kind='Sources'):
            if not re.fullmatch(r'[0-9a-f]{64}', digest) or not size.isdigit():
                raise SourceError('malformed Sources file identity')
            files.append((digest, int(size), name))
        if not files:
            raise SourceError('Sources stanza lacks sha256 file rows')
        legacy = [(name, size) for _, size, name in _checksum_rows(fields.get('files', ''), kind='Sources')]
        if legacy and [(name, str(size)) for _, size, name in files] != legacy:
            raise SourceError('Sources md5/sha256 file roster mismatch')
        key = (fields['package'], fields['version'])
        record = (fields.get('directory', ''), files)
        if key in stanzas and stanzas[key] != record:
            raise SourceError('conflicting duplicate Sources stanza: %s=%s' % key)
        stanzas.setdefault(key, record)
    return stanzas


def _parse_inrelease(text):
    """Parse an InRelease SHA256 section into {relpath: (sha256, size)}."""
    fields = _parse_deb822(_strip_clearsign(text))
    out = {}
    for digest, size, path in _checksum_rows(fields.get('sha256', ''), kind='InRelease', paths=True):
        if not re.fullmatch(r'[0-9a-f]{64}', digest) or not size.isdigit():
            raise SourceError('malformed InRelease file identity')
        out[path] = (digest, int(size))
    if not out:
        raise SourceError('InRelease lacks SHA256 file rows')
    return out


def _index_url(filename, snapshot):
    match = INDEX_FILENAME.fullmatch(filename)
    if not match or match[2] != snapshot:
        raise ValueError('index file outside pinned snapshot: ' + filename)
    if match[4] != 'InRelease':
        raise ValueError('index file is a builder-cache fingerprint, not a download: ' + filename)
    return _snapshot_base(match[1], match[2]) + '/dists/' + match[3] + '/InRelease'


def _snapshot_base(archive, snapshot):
    return 'https://snapshot.debian.org/archive/%s/%s' % (archive, snapshot)


def _gather_incorporated(lock, wanted, have, sources, files_dir, evidence_root, entries, basenames, verified_fetch):
    for identity in sorted(set(wanted) & have):
        sources[identity]['via'] = sorted(set(sources[identity]['via']) | set(wanted[identity]))
    missing = sorted(set(wanted) - have)
    # Trust root: the reviewed lock's pinned index hashes. Despite the field
    # name, no OpenPGP signature is verified here; authenticity comes from
    # the committed lock plus hash-verified bytes, never from the URL alone.
    signed = lock.get('signed_index_inputs')
    if type(signed) is not list or not signed:
        if missing:
            raise ValueError('lock lacks pinned Sources indices for %d identities' % len(missing))
        return {}
    snapshot = lock['apt_snapshot']
    metadata_dir = files_dir / 'metadata'
    metadata_dir.mkdir(exist_ok=True)
    indices, releases = {}, {}
    for record in signed:
        if type(record) is not dict or set(record) != {'filename', 'sha256', 'size'}:
            raise ValueError('malformed signed index record')
        match = INDEX_FILENAME.fullmatch(record['filename'])
        if not match or match[2] != snapshot:
            raise ValueError('index file outside pinned snapshot: ' + record['filename'])
        archive, suite, kind = match[1], match[3], match[4]
        if kind != 'InRelease':
            # .lz4 pins are builder-cache fingerprints (verified from the
            # built image by build.py), not published files; resolution uses
            # the InRelease-pinned Sources.xz representation instead.
            indices[record['filename']] = {'suite': suite, 'verified': False, 'downloadable': False,
                                           'note': 'builder-cache fingerprint; not fetched'}
            continue
        url = _index_url(record['filename'], snapshot)
        _require_file_entry({'filename': record['filename'], 'sha256': record['sha256'],
                             'size': record['size'], 'url': url})
        entries[record['filename']] = {'url': url, 'size': record['size'], 'sha256': record['sha256']}
        raw = verified_fetch(record['filename'])
        (metadata_dir / record['filename']).write_bytes(raw)
        releases[suite] = (archive, _parse_inrelease(raw.decode('utf-8', 'replace')))
        indices[record['filename']] = {'suite': suite, 'verified': True,
                                       'sha256': hashlib.sha256(raw).hexdigest()}
    suites = {}
    for suite, (archive, release) in sorted(releases.items()):
        if 'main/source/Sources.xz' not in release:
            raise SourceError('Sources.xz missing from %s InRelease' % suite)
        digest, size = release['main/source/Sources.xz']
        if not 0 < size <= COMPRESSED_INDEX_BOUND:
            raise SourceError('invalid Sources.xz size in %s InRelease' % suite)
        key = 'index/' + suite + '/main/source/Sources.xz'
        entries[key] = {'url': _snapshot_base(archive, snapshot) + '/dists/' + suite + '/main/source/Sources.xz',
                        'size': size, 'sha256': digest}
        raw = verified_fetch(key)
        stored = metadata_dir / (suite + '-Sources.xz')
        stored.write_bytes(raw)
        decoder = lzma.LZMADecompressor(memlimit=INDEX_DECODER_MEMLIMIT)
        try:
            text = decoder.decompress(raw, max_length=DECODED_INDEX_BOUND + 1)
        except lzma.LZMAError as error:
            raise SourceError('unreadable Sources.xz for ' + suite) from error
        if len(text) > DECODED_INDEX_BOUND or not decoder.eof or decoder.unused_data:
            raise SourceError('Sources.xz exceeds decode bound for ' + suite)
        suites[suite] = _parse_sources_index(text.decode('utf-8', 'replace'))
        indices[key] = {'suite': suite, 'verified': True, 'sha256': hashlib.sha256(raw).hexdigest(),
                        'stanzas': len(suites[suite])}
    for identity in missing:
        if SOURCE_IDENTITY.fullmatch(identity) is None:
            raise SourceError('malformed wanted source identity: ' + identity)
        name, version = identity.split('=', 1)
        matches = [(suite, stanzas[(name, version)]) for suite, stanzas in suites.items() if (name, version) in stanzas]
        if not matches:
            raise SourceError('unresolved source: ' + identity)
        matches.sort(key=lambda match: SUITE_PREFERENCE.index(match[0]))
        suite, (directory, files) = matches[0]
        preferred_gap = None
        if len({tuple(sorted(files)) for _, (_, files) in matches}) != 1:
            preferred_gap = 'ambiguous-source-preferred:' + suite
        if not _pool_directory_ok(directory):
            raise SourceError('invalid incorporated source directory: ' + identity)
        archive = 'debian-security' if suite == 'trixie-security' else 'debian'
        base = 'https://snapshot.debian.org/archive/%s/%s/%s' % (archive, snapshot, directory)
        entry_files = []
        for digest, size, filename in files:
            if not 0 < size <= PAYLOAD_SIZE_BOUND:
                raise SourceError('invalid incorporated file size: ' + identity)
            entry_files.append({'filename': directory + '/' + filename, 'sha256': digest,
                                'size': size, 'url': base + '/' + filename})
        for item in entry_files:
            if item['filename'].rsplit('/', 1)[-1] in basenames:
                raise ValueError('duplicate incorporated basename: ' + item['filename'])
        for item in entry_files:
            basenames.add(item['filename'].rsplit('/', 1)[-1])
            entries[item['filename']] = item
        evidence_dir = evidence_root / _portable_component(identity)
        evidence_dir.mkdir(parents=True, exist_ok=True)
        sources[identity] = _gather_source({'name': name, 'version': version, 'files': entry_files},
                                            files_dir, evidence_dir, verified_fetch,
                                            via=sorted(wanted[identity]))
        if preferred_gap is not None:
            sources[identity]['gaps'] = sorted(set(sources[identity]['gaps']) | {preferred_gap})
    return indices


def gather_review_inputs(lock, output_dir, *, fetcher=None, attempts=FETCH_ATTEMPTS, sleeper=time.sleep,
                         cache_dir=None):
    """Fetch every lock-pinned Debian source/binary/index file and extract evidence.

    fetcher(filename) -> bytes overrides network acquisition (tests); the
    default fetches each entry URL over HTTPS with retries. cache_dir names
    an optional caller-owned directory of previously fetched bytes keyed by
    quoted entry filename; cached bytes are size/hash-verified against the current lock
    before use (a mismatch refetches), and every verified network fetch is
    stored there, so a rerun after a mirror outage resumes instead of
    restarting. Every returned byte string is size/hash-verified against
    the lock before use. Each
    binary's declared source identity and any statically incorporated
    sources (Built-Using/Static-Built-Using) resolve through lock entries
    first and the InRelease-pinned Sources.xz indices second; anything
    unresolvable fails the run. Provider upstream sources, dependencies,
    and patches are listed in the report as explicitly not gathered.
    """
    if type(lock) is not dict or type(lock.get('source_packages')) is not list or type(lock.get('packages')) is not list:
        raise ValueError('gather requires a locked source/binary roster')
    if type(lock.get('schema_version')) is not int or lock['schema_version'] != 1:
        raise ValueError('gather requires lock schema version 1')
    if type(lock.get('apt_snapshot')) is not str or not lock['apt_snapshot']:
        raise ValueError('gather requires a pinned apt snapshot')
    if type(attempts) is not int or attempts < 1:
        raise ValueError('gather requires at least one fetch attempt')
    entries, basenames, source_ids, binary_ids = {}, set(), set(), set()
    for source in lock['source_packages']:
        if type(source) is not dict or not source.get('name') or not source.get('version') or type(source.get('files')) is not list:
            raise ValueError('malformed lock source entry')
        identity = source['name'] + '=' + source['version']
        if SOURCE_IDENTITY.fullmatch(identity) is None or identity in source_ids:
            raise ValueError('duplicate or malformed lock source identity: ' + identity)
        source_ids.add(identity)
        for item in source['files']:
            base = _require_file_entry(item)
            if base in basenames:
                raise ValueError('duplicate lock basename: ' + base)
            basenames.add(base)
            entries[item['filename']] = item
    for package in lock['packages']:
        if type(package) is not dict or not package.get('name') or not package.get('version'):
            raise ValueError('malformed lock package entry')
        identity = package['name'] + '=' + package['version']
        if SOURCE_IDENTITY.fullmatch(identity) is None or identity in binary_ids:
            raise ValueError('duplicate or malformed lock package identity: ' + identity)
        binary_ids.add(identity)
        item = package.get('binary_acquisition', {})
        base = _require_file_entry(item)
        if base in basenames:
            raise ValueError('duplicate lock basename: ' + base)
        basenames.add(base)
        entries[item['filename']] = item

    def default_fetch(filename):
        item = entries[filename]
        return fetch_url(item['url'], item['size'], item['sha256'])

    fetch = fetcher if fetcher is not None else default_fetch
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=False)
    files_dir = output / 'files'
    files_dir.mkdir()
    (output / 'evidence').mkdir()
    cache = Path(cache_dir) if cache_dir is not None else None
    if cache is not None:
        cache.mkdir(parents=True, exist_ok=True)
        if not cache.is_dir() or cache.is_symlink():
            raise ValueError('gather cache_dir must be a real directory')
        if cache.resolve() == output.resolve() or cache.resolve().is_relative_to(output.resolve()):
            raise ValueError('gather cache_dir must not live inside the output directory')
        for stale in cache.glob('.staging-*'):
            try:
                if stale.is_file() and not stale.is_symlink():
                    stale.unlink()
            except OSError:
                pass
    cache_hits = [0]

    def cache_name(filename):
        from urllib.parse import quote
        return quote(filename, safe='')

    def cache_lookup(filename, item):
        try:
            raw = (cache / cache_name(filename)).read_bytes()
        except OSError:
            return None
        if len(raw) != item['size'] or hashlib.sha256(raw).hexdigest() != item['sha256']:
            return None
        cache_hits[0] += 1
        return raw

    def cache_store(filename, raw):
        import os
        target = cache / cache_name(filename)
        staging = cache / ('.staging-%s-%d' % (cache_name(filename), os.getpid()))
        try:
            staging.write_bytes(raw)
            staging.replace(target)
        except OSError:
            try:
                staging.unlink()
            except OSError:
                pass

    def verified_fetch(filename):
        item = entries[filename]
        if cache is not None:
            hit = cache_lookup(filename, item)
            if hit is not None:
                return hit
        last = None
        for attempt in range(1, attempts + 1):
            try:
                raw = fetch(filename)
            except FetchError as error:
                last = error
            else:
                if type(raw) is not bytes:
                    raise SourceError('fetcher returned non-bytes for ' + filename)
                if len(raw) != item['size'] or hashlib.sha256(raw).hexdigest() != item['sha256']:
                    raise SourceError('source payload checksum/size mismatch: ' + filename)
                if cache is not None:
                    cache_store(filename, raw)
                return raw
            if attempt < attempts:
                sleeper(min(60, 5 * attempt))
        raise SourceError('fetch failed after %d attempts: %s (%s)' % (attempts, filename, last))

    sources, binaries = {}, {}
    for source in lock['source_packages']:
        identity = source['name'] + '=' + source['version']
        evidence_dir = output / 'evidence' / _portable_component(identity)
        evidence_dir.mkdir(parents=True)
        sources[identity] = _gather_source(source, files_dir, evidence_dir, verified_fetch, via=['lock'])
    for package in lock['packages']:
        identity = package['name'] + '=' + package['version']
        evidence_dir = output / 'evidence' / _portable_component(identity)
        evidence_dir.mkdir(parents=True, exist_ok=True)
        binaries[identity] = _gather_binary(package, files_dir, evidence_dir, verified_fetch)
    wanted = {}
    for identity, binary in binaries.items():
        for incorporated in binary['incorporated_sources']:
            wanted.setdefault(incorporated, []).append('built-using:' + identity)
    for package in lock['packages']:
        declared = str(package.get('source_package', '')) + '=' + str(package.get('source_version', ''))
        if SOURCE_IDENTITY.fullmatch(declared) is None:
            raise ValueError('malformed lock binary source identity: ' + declared)
        wanted.setdefault(declared, []).append(
            'binary-source:' + package['name'] + '=' + package['version'])
    indices = _gather_incorporated(lock, wanted, {identity for identity in sources}, sources,
                                   files_dir, output / 'evidence', entries, basenames, verified_fetch)
    lock_digest = hashlib.sha256(json.dumps(lock, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    provider_inputs = {'status': 'not-gathered: debian-only scope',
                       'sources': [source for source in lock.get('sources', []) if type(source) is dict],
                       'patches': [patch for patch in lock.get('patches', []) if type(patch) is dict],
                       'dependencies': [dep for dep in lock.get('dependencies', [])]}
    report = {'schema_version': SCHEMA_VERSION, 'status': 'complete', 'lock_sha256': lock_digest,
              'apt_snapshot': lock.get('apt_snapshot'), 'sources': sources, 'binaries': binaries,
              'indices': indices, 'provider_inputs': provider_inputs,
              'summary': {'sources': len(sources), 'binaries': len(binaries),
                          'incorporated': sum(1 for s in sources.values()
                                              if any(tag.startswith('built-using:')
                                                     for tag in s['via'])),
                          'index_resolved': sum(1 for s in sources.values() if 'lock' not in s['via']),
                          'source_gaps': sum(len(s['gaps']) for s in sources.values()),
                          'binary_gaps': sum(len(b['gaps']) for b in binaries.values()),
                          'cache_hits': cache_hits[0]}}
    staged = output / 'report.json.staged'
    staged.write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    manifest = {'report.json': checksum(staged)}
    for path in sorted(output.rglob('*')):
        if not path.is_file():
            continue
        relpath = path.relative_to(output).as_posix()
        if '/' not in relpath and path.name in ('SHA256SUMS', 'report.json.staged'):
            continue
        if any(char < ' ' or char == '\x7f' for char in relpath):
            raise SourceError('unmanifestable output path')
        manifest[relpath] = checksum(path)
    (output / 'SHA256SUMS').write_text(''.join(digest + '  ' + path + '\n' for path, digest in sorted(manifest.items())))
    staged.replace(output / 'report.json')
    return {'status': 'complete', 'sources': len(sources), 'binaries': len(binaries), 'report': str(output / 'report.json')}
