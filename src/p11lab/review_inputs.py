"""Fetch lock-pinned distribution bytes and extract license evidence for human review.

Mechanical only: downloads, hash verification, and text extraction. This module
never concludes licenses, grants, redistribution rights, or eligibility; the
reviewer writes those conclusions into the committed inventory template from
the gathered bundle. Absence of report.json in the output directory means the
gathering did not complete; no partial result is ever claimed complete.
"""
import hashlib
import io
import json
import re
import tarfile
import time
from pathlib import Path
from urllib.request import urlopen

from .sources import SourceError, checksum

SCHEMA_VERSION = 1
FETCH_ATTEMPTS = 6
PAYLOAD_SIZE_BOUND = 1024**3
EVIDENCE_FILE_BOUND = 1024**2
EVIDENCE_TAR_BOUND = 16 * 1024**2
LICENSE_BASENAME = re.compile(r'(?i)(license|licence|copying|copyright)(\.|$|-|_)')
CARGO_LICENSE = re.compile(r'^\s*license\s*=\s*["\']([^"\']+)["\']', re.M)
CARGO_LICENSE_FILE = re.compile(r'^\s*license-file\s*=\s*["\']([^"\']+)["\']', re.M)
SOURCE_IDENTITY = re.compile(r'[a-z0-9][a-z0-9+.-]*=[0-9A-Za-z][0-9A-Za-z.+~:-]*')
BUILT_USING_ENTRY = re.compile(r'\s*([^ ()]+)\s*\(=\s*([^()]+)\)\s*')
INDEX_FILENAME = re.compile(r'snapshot\.debian\.org_archive_(debian(?:-security)?)_'
                             r'(\d{8}T\d{6}Z)_dists_(trixie(?:-updates|-security)?)_'
                             r'(InRelease|main_source_Sources\.lz4|main_binary-amd64_Packages\.lz4)')
INDEX_URL_PATH = {'InRelease': 'InRelease', 'main_source_Sources.lz4': 'main/source/Sources.lz4',
                  'main_binary-amd64_Packages.lz4': 'main/binary-amd64/Packages.lz4'}
POOL_DIRECTORY = re.compile(r'pool/(main|contrib|non-free|non-free-firmware)/[A-Za-z0-9+./~-]*')


def _pool_directory_ok(directory):
    return (POOL_DIRECTORY.fullmatch(directory) is not None
            and all(segment not in ('.', '..') for segment in directory.split('/')))
DECODED_INDEX_BOUND = 512 * 1024**2


class FetchError(Exception):
    """Transient acquisition failure; the caller may retry."""


def fetch_url(url, size, sha256):
    """Fetch one pinned file over public HTTPS with size and hash checks."""
    from urllib.parse import urlparse
    if type(size) is not int or not 0 < size <= PAYLOAD_SIZE_BOUND:
        raise SourceError('source payload size outside acquisition bound')
    if not re.fullmatch(r'[0-9a-f]{64}', sha256 or ''):
        raise SourceError('source payload lacks pinned sha256')
    parsed = urlparse(url or '')
    if parsed.scheme != 'https' or parsed.username or parsed.password:
        raise SourceError('source payload needs a public HTTPS URL')
    try:
        with urlopen(url, timeout=120) as response:
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


def _xxh32(data):
    prime1, prime2, prime3, prime4, prime5 = 0x9E3779B1, 0x85EBCA77, 0xC2B2AE3D, 0x27D4EB2F, 0x165667B1
    mask = 0xFFFFFFFF

    def rol(value, count):
        return ((value << count) | (value >> (32 - count))) & mask

    def word(offset):
        return int.from_bytes(data[offset:offset + 4], 'little')

    count, offset = len(data), 0
    if count >= 16:
        v1 = (prime1 + prime2) & mask
        v2, v3, v4 = prime2, 0, (mask + 1 - prime1) & mask
        while offset + 16 <= count:
            v1 = rol((v1 + word(offset) * prime2) & mask, 13) * prime1 & mask
            v2 = rol((v2 + word(offset + 4) * prime2) & mask, 13) * prime1 & mask
            v3 = rol((v3 + word(offset + 8) * prime2) & mask, 13) * prime1 & mask
            v4 = rol((v4 + word(offset + 12) * prime2) & mask, 13) * prime1 & mask
            offset += 16
        digest = (rol(v1, 1) + rol(v2, 7) + rol(v3, 12) + rol(v4, 18)) & mask
    else:
        digest = prime5
    digest = (digest + count) & mask
    while offset + 4 <= count:
        digest = rol((digest + word(offset) * prime3) & mask, 17) * prime4 & mask
        offset += 4
    while offset < count:
        digest = rol((digest + data[offset] * prime5) & mask, 11) * prime1 & mask
        offset += 1
    digest ^= digest >> 15
    digest = digest * prime2 & mask
    digest ^= digest >> 13
    digest = digest * prime3 & mask
    return digest ^ (digest >> 16)


def _lz4_block(block, out, base):
    """Decode one LZ4 block into out; matches may only reference this frame."""
    pos, end = 0, len(block)
    while pos < end:
        token = block[pos]
        pos += 1
        length = token >> 4
        if length == 15:
            while True:
                if pos >= end:
                    raise SourceError('truncated lz4 literal length')
                extra = block[pos]
                pos += 1
                length += extra
                if extra != 255:
                    break
        if pos + length > end or len(out) + length > DECODED_INDEX_BOUND:
            raise SourceError('invalid lz4 literals')
        out += block[pos:pos + length]
        pos += length
        if pos >= end:
            break
        if pos + 2 > end:
            raise SourceError('truncated lz4 match')
        offset = block[pos] | (block[pos + 1] << 8)
        pos += 2
        if offset == 0 or len(out) - offset < base:
            raise SourceError('invalid lz4 match offset')
        length = (token & 0x0F) + 4
        if (token & 0x0F) == 15:
            while True:
                if pos >= end:
                    raise SourceError('truncated lz4 match length')
                extra = block[pos]
                pos += 1
                length += extra
                if extra != 255:
                    break
        if len(out) + length > DECODED_INDEX_BOUND:
            raise SourceError('lz4 output exceeds bound')
        start = len(out) - offset
        for index in range(length):
            out.append(out[start + index])


def lz4_frame_decode(raw):
    """Decode one LZ4 frame (stdlib has no lz4 codec); rejects dictionaries."""
    out = bytearray()
    pos, end = 0, len(raw)
    while True:
        if pos + 8 > end:
            raise SourceError('truncated lz4 frame header')
        magic = int.from_bytes(raw[pos:pos + 4], 'little')
        if 0x184D2A50 <= magic <= 0x184D2A5F:
            pos += 8 + int.from_bytes(raw[pos + 4:pos + 8], 'little')
            continue
        if magic != 0x184D2204:
            raise SourceError('not an lz4 frame')
        flags, descriptor = raw[pos + 4], raw[pos + 5]
        if flags >> 6 != 0b01 or flags & 0x01:
            raise SourceError('unsupported lz4 flags')
        head = pos + 6 + (8 if flags & 0x08 else 0)
        if head + 1 > end:
            raise SourceError('truncated lz4 frame header')
        if ((_xxh32(raw[pos + 4:head]) >> 8) & 0xFF) != raw[head]:
            raise SourceError('bad lz4 header checksum')
        if (descriptor & 0xF0) not in (0x40, 0x50, 0x60, 0x70) or descriptor & 0x0F:
            raise SourceError('unsupported lz4 block descriptor')
        pos, base = head + 1, len(out)
        while True:
            if pos + 4 > end:
                raise SourceError('truncated lz4 block header')
            size = int.from_bytes(raw[pos:pos + 4], 'little')
            pos += 4
            if size == 0:
                break
            width = size & 0x7FFFFFFF
            if width > 4 * 1024**2 or pos + width > end:
                raise SourceError('invalid lz4 block size')
            if size & 0x80000000:
                if len(out) + width > DECODED_INDEX_BOUND:
                    raise SourceError('lz4 output exceeds bound')
                out += raw[pos:pos + width]
            else:
                _lz4_block(raw[pos:pos + width], out, base)
            pos += width
            if flags & 0x10:
                pos += 4
        # Compressed bytes are already hash-pinned; the content checksum adds
        # nothing, so it is skipped rather than recomputed over ~100 MB.
        if flags & 0x04:
            pos += 4
        break
    if pos != end:
        raise SourceError('trailing bytes after lz4 frame')
    return bytes(out)


def _safe_evidence_name(member):
    base = member.rsplit('/', 1)[-1]
    if not base or base in ('.', '..') or '/' in base or '\\' in base:
        return None
    if len(base) > 100:
        base = base[:60] + '..' + base[-38:]
    return base


def _extract_texts(tar, evidence_dir, *, budget):
    """Retain license-like member bytes; returns {member: (relpath, sha256)} and gaps."""
    kept, gaps = {}, []
    spent = 0
    for member in tar.getmembers():
        if not member.isfile():
            continue
        base = _safe_evidence_name(member.name)
        if base is None or not LICENSE_BASENAME.search(base):
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
        target = evidence_dir / (digest[:16] + '-' + base)
        if not target.exists():
            target.write_bytes(raw)
        kept[member.name] = (target.name, digest)
        spent += len(raw)
    return kept, gaps


def _cargo_signals(tar):
    """Read [package] license fields from the shallowest Cargo.toml in the tree."""
    manifests = [m for m in tar.getmembers()
                 if m.isfile() and (m.name == 'Cargo.toml' or m.name.endswith('/Cargo.toml'))]
    if not manifests:
        return None, None, []
    member = min(manifests, key=lambda m: m.name.count('/'))
    if member.size > EVIDENCE_FILE_BOUND:
        return None, None, ['oversize-cargo-toml']
    reader = tar.extractfile(member)
    text = reader.read().decode('utf-8', 'replace') if reader else ''
    license_match = CARGO_LICENSE.search(text)
    file_match = CARGO_LICENSE_FILE.search(text)
    return (license_match.group(1) if license_match else None,
            file_match.group(1) if file_match else None, [])


def _has_rust_signals(tar):
    for member in tar.getmembers():
        if not member.isfile():
            continue
        plain = member.name[2:] if member.name.startswith('./') else member.name
        base = plain.rsplit('/', 1)[-1]
        if base in ('Cargo.toml', 'Cargo.lock') or base.endswith('.rs'):
            return True
    return False


def _record_copyright(tar, evidence_dir, identity, evidence, gaps):
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
        evidence['debian/copyright'] = str(Path('evidence') / identity / target.name)


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
    cargo_license = cargo_license_file = None
    saw_orig = saw_debian = saw_rust = False
    native_format = False
    for item in entry['files']:
        name = item['filename']
        raw = (files_dir / name.rsplit('/', 1)[-1]).read_bytes()
        if hashlib.sha256(raw).hexdigest() != fetched[name]:
            raise SourceError('retained payload changed during gathering: ' + name)
        if name.endswith('.dsc') and re.search(r'^Format: 3\.0 \(native\)\s*$', raw[:65536].decode('utf-8', 'replace'), re.M):
            native_format = True
        if '.orig.tar' in name or (name.endswith(('.tar.gz', '.tar.xz', '.tar.bz2', '.tar.zst')) and '.debian.tar' not in name):
            saw_orig = True
            with _tar_members(raw, name_hint=name) as tar:
                found_license, found_file, cargo_gaps = _cargo_signals(tar)
                gaps.extend(cargo_gaps)
                if cargo_license is None:
                    cargo_license = found_license
                if cargo_license_file is None:
                    cargo_license_file = found_file
                saw_rust = saw_rust or _has_rust_signals(tar)
                kept, kept_gaps = _extract_texts(tar, evidence_dir, budget=EVIDENCE_TAR_BOUND)
                evidence.update({member: str(Path('evidence') / identity / filename) for member, (filename, _) in kept.items()})
                gaps.extend(kept_gaps)
                _record_copyright(tar, evidence_dir, identity, evidence, gaps)
        elif '.debian.tar' in name:
            saw_debian = True
            with _tar_members(raw, name_hint=name) as tar:
                _record_copyright(tar, evidence_dir, identity, evidence, gaps)
    if not saw_orig:
        gaps.append('no-orig-tarball')
    if not saw_debian and not native_format:
        gaps.append('no-debian-tarball')
    if 'debian/copyright' not in evidence:
        gaps.append('no-debian-copyright')
    if saw_rust and cargo_license is None and cargo_license_file is None:
        gaps.append('no-cargo-license')
    return {'verified': True, 'via': via, 'files': fetched, 'cargo_license': cargo_license,
            'cargo_license_file': cargo_license_file, 'evidence': evidence, 'gaps': sorted(set(gaps))}


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
    control = next((body for name, body in members if name.startswith('control.tar')), None)
    if control is None:
        gaps.append('no-control-tarball')
    else:
        try:
            with _tar_members(control, name_hint=item['filename']) as tar:
                names = tar.getnames()
                pick = 'control' if 'control' in names else './control' if './control' in names else None
                if pick is None:
                    gaps.append('no-control-file')
                elif tar.getmember(pick).size > EVIDENCE_FILE_BOUND:
                    gaps.append('oversize-control-file')
                else:
                    reader = tar.extractfile(pick)
                    text = reader.read().decode('utf-8', 'replace') if reader else ''
                    try:
                        incorporated = _built_using_identities(text)
                    except SourceError as error:
                        gaps.append('invalid-built-using:' + str(error))
        except SourceError as error:
            gaps.append('unreadable-control-tarball:' + str(error))
    data = next((body for name, body in members if name.startswith('data.tar')), None)
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
                out = evidence_dir / (digest[:16] + '-' + base)
                if not out.exists():
                    out.write_bytes(text)
                evidence[member.name] = str(Path('evidence') / identity / out.name)
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
            or name in ('.', '..') or '/../' in '/' + name + '/' or not name.rsplit('/', 1)[-1]):
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
        for entry in _control_field(control_text, field).split(','):
            if not entry.strip():
                continue
            identity = BUILT_USING_ENTRY.fullmatch(entry)
            if not identity:
                raise SourceError('invalid ' + field + ' entry')
            identities.add(identity[1] + '=' + identity[2].strip())
    return sorted(identities)


def _parse_sources_index(text):
    """Parse a Sources index into {(name, version): (directory, [(sha256, size, filename)])}."""
    stanzas = {}
    for paragraph in text.split('\n\n'):
        fields = {}
        for line in paragraph.splitlines():
            if line.startswith((' ', '\t')) and fields:
                fields[key] += '\n' + line
            elif ':' in line:
                key, value = line.split(':', 1)
                fields[key.strip()] = value.strip()
        if not fields or 'Package' not in fields or 'Version' not in fields:
            continue
        files = []
        for row in fields.get('Checksums-Sha256', '').splitlines():
            if not row.strip():
                continue
            parts = row.split()
            if len(parts) != 3:
                raise SourceError('malformed Sources checksum row')
            digest, size, name = parts
            if (not re.fullmatch(r'[0-9a-f]{64}', digest) or not size.isdigit()
                    or '/' in name or name in ('.', '..')):
                raise SourceError('malformed Sources file identity')
            files.append((digest, int(size), name))
        if not files:
            raise SourceError('Sources stanza lacks sha256 file rows')
        legacy = [tuple(row.split()) for row in fields.get('Files', '').splitlines() if row.strip()]
        if legacy and [(name, str(size)) for _, size, name in files] != [(name, size) for _, size, name in legacy]:
            raise SourceError('Sources md5/sha256 file roster mismatch')
        key = (fields['Package'], fields['Version'])
        record = (fields.get('Directory', ''), files)
        if key in stanzas and stanzas[key] != record:
            raise SourceError('conflicting duplicate Sources stanza: %s=%s' % key)
        stanzas.setdefault(key, record)
    return stanzas


def _index_url(filename, snapshot):
    match = INDEX_FILENAME.fullmatch(filename)
    if not match or match[2] != snapshot:
        raise ValueError('index file outside pinned snapshot: ' + filename)
    return 'https://snapshot.debian.org/archive/%s/%s/dists/%s/%s' % (
        match[1], match[2], match[3], INDEX_URL_PATH[match[4]])


def _gather_incorporated(lock, wanted, have, sources, files_dir, evidence_root, entries, basenames, verified_fetch):
    for identity in sorted(set(wanted) & have):
        extra = ['built-using:' + binary for binary in sorted(wanted[identity])]
        sources[identity]['via'] = sorted(set(sources[identity]['via']) | set(extra))
    missing = sorted(set(wanted) - have)
    if not missing:
        return {}
    # Trust root: the reviewed lock's pinned index hashes. Despite the field
    # name, no OpenPGP signature is verified here; authenticity comes from
    # the committed lock plus hash-verified bytes, never from the URL alone.
    signed = lock.get('signed_index_inputs')
    if type(signed) is not list or not signed:
        raise ValueError('lock lacks pinned Sources indices for %d incorporated identities' % len(missing))
    snapshot = lock['apt_snapshot']
    metadata_dir = files_dir / 'metadata'
    metadata_dir.mkdir(exist_ok=True)
    decoded = {}
    for record in signed:
        if type(record) is not dict or set(record) != {'filename', 'sha256', 'size'}:
            raise ValueError('malformed signed index record')
        _require_file_entry({'filename': record['filename'], 'sha256': record['sha256'],
                             'size': record['size'], 'url': _index_url(record['filename'], snapshot)})
        entries[record['filename']] = {'url': _index_url(record['filename'], snapshot),
                                       'size': record['size'], 'sha256': record['sha256']}
        raw = verified_fetch(record['filename'])
        (metadata_dir / record['filename']).write_bytes(raw)
        decoded[record['filename']] = raw
    suites = {}
    indices = {}
    for filename, raw in decoded.items():
        suite = INDEX_FILENAME.fullmatch(filename)[3]
        record = {'suite': suite, 'verified': True, 'sha256': hashlib.sha256(raw).hexdigest()}
        if filename.endswith('_Sources.lz4'):
            text = lz4_frame_decode(raw).decode('utf-8', 'replace')
            suites[suite] = _parse_sources_index(text)
            record['stanzas'] = len(suites[suite])
        indices[filename] = record
    for identity in missing:
        if SOURCE_IDENTITY.fullmatch(identity) is None:
            raise SourceError('malformed incorporated source identity: ' + identity)
        name, version = identity.split('=', 1)
        matches = [(suite, stanzas[(name, version)]) for suite, stanzas in suites.items() if (name, version) in stanzas]
        if not matches:
            raise SourceError('unresolved incorporated source: ' + identity)
        if len({(directory, tuple(files)) for _, (directory, files) in matches}) != 1:
            raise SourceError('ambiguous incorporated source across suites: ' + identity)
        suite, (directory, files) = matches[0]
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
        evidence_dir = evidence_root / identity
        evidence_dir.mkdir(parents=True, exist_ok=True)
        via = ['built-using:' + binary for binary in sorted(wanted[identity])]
        sources[identity] = _gather_source({'name': name, 'version': version, 'files': entry_files},
                                            files_dir, evidence_dir, verified_fetch, via=via)
    return indices


def gather_review_inputs(lock, output_dir, *, fetcher=None, attempts=FETCH_ATTEMPTS, sleeper=time.sleep):
    """Fetch every lock-pinned source/binary file and extract license evidence.

    fetcher(filename) -> bytes overrides network acquisition (tests); the
    default fetches each entry URL over HTTPS with retries. Every returned
    byte string is size/hash-verified against the lock before use. Binaries
    that statically incorporate other sources (Built-Using/Static-Built-Using)
    trigger a second phase that resolves those identities through the
    lock-pinned Sources indices and gathers their evidence too.
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

    def verified_fetch(filename):
        item = entries[filename]
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
                return raw
            if attempt < attempts:
                sleeper(min(60, 5 * attempt))
        raise SourceError('fetch failed after %d attempts: %s (%s)' % (attempts, filename, last))

    sources, binaries = {}, {}
    for source in lock['source_packages']:
        identity = source['name'] + '=' + source['version']
        evidence_dir = output / 'evidence' / identity
        evidence_dir.mkdir(parents=True)
        sources[identity] = _gather_source(source, files_dir, evidence_dir, verified_fetch, via=['lock'])
    for package in lock['packages']:
        identity = package['name'] + '=' + package['version']
        evidence_dir = output / 'evidence' / identity
        evidence_dir.mkdir(parents=True, exist_ok=True)
        binaries[identity] = _gather_binary(package, files_dir, evidence_dir, verified_fetch)
    wanted = {}
    for identity, binary in binaries.items():
        for incorporated in binary['incorporated_sources']:
            wanted.setdefault(incorporated, []).append(identity)
    indices = _gather_incorporated(lock, wanted, {identity for identity in sources}, sources,
                                   files_dir, output / 'evidence', entries, basenames, verified_fetch)
    lock_digest = hashlib.sha256(json.dumps(lock, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    report = {'schema_version': SCHEMA_VERSION, 'status': 'complete', 'lock_sha256': lock_digest,
              'apt_snapshot': lock.get('apt_snapshot'), 'sources': sources, 'binaries': binaries,
              'indices': indices,
              'summary': {'sources': len(sources), 'binaries': len(binaries),
                          'incorporated': sum(1 for s in sources.values() if 'lock' not in s['via']),
                          'source_gaps': sum(len(s['gaps']) for s in sources.values()),
                          'binary_gaps': sum(len(b['gaps']) for b in binaries.values())}}
    staged = output / 'report.json.staged'
    staged.write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    manifest = {'report.json': checksum(staged)}
    for path in sorted(output.rglob('*')):
        if path.is_file() and path.name not in ('SHA256SUMS', 'report.json.staged'):
            manifest[path.relative_to(output).as_posix()] = checksum(path)
    (output / 'SHA256SUMS').write_text(''.join(digest + '  ' + path + '\n' for path, digest in sorted(manifest.items())))
    staged.replace(output / 'report.json')
    return {'status': 'complete', 'sources': len(sources), 'binaries': len(binaries), 'report': str(output / 'report.json')}
