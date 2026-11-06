"""Review-input gathering fetches lock-pinned bytes and extracts license evidence without concluding rights."""
import hashlib
import io
import json
import tarfile
from pathlib import Path

import pytest

from p11lab import review_inputs
from p11lab.sources import SourceError


def make_tar(members):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w') as out:
        for name, data in members.items():
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            out.addfile(entry, io.BytesIO(data))
    buffer.seek(0)
    return buffer.read()


def make_ar(members):
    out = [b'!<arch>\n']
    for name, data in members:
        header = ('%-16s%-12d%-6d%-6d%-8o%-10d\x60\x0a' % (name, 0, 0, 0, 0o644, len(data))).encode()
        out.append(header + data + (b'\n' if len(data) % 2 else b''))
    return b''.join(out)


COPYRIGHT = b'Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\nUpstream: example\n'
CARGO = b'[package]\nname = "demo"\nversion = "1.0.0"\nlicense = "MIT OR Apache-2.0"\n'
MIT_TEXT = b'Permission is hereby granted, free of charge, to any person obtaining a copy\n'


@pytest.fixture
def demo_lock():
    orig = make_tar({'demo-1.0/Cargo.toml': CARGO, 'demo-1.0/LICENSE-MIT': MIT_TEXT})
    debian = make_tar({'debian/copyright': COPYRIGHT})
    dsc = b'Format: 3.0 (quilt)\nSource: demo\nVersion: 1.0.0-1\n'
    data_tar = make_tar({'./usr/share/doc/demo/copyright': COPYRIGHT})
    deb = make_ar([('debian-binary', b'2.0\n'), ('control.tar.xz', make_tar({'control': b'Package: demo\n'})),
                   ('data.tar.xz', data_tar)])
    files = {'demo_1.0.0-1.dsc': dsc, 'demo_1.0.0.orig.tar.gz': orig, 'demo_1.0.0-1.debian.tar.xz': debian}
    payloads = [{'filename': name, 'sha256': hashlib.sha256(raw).hexdigest(), 'size': len(raw),
                 'url': 'https://example.invalid/' + name} for name, raw in files.items()]
    package = {'name': 'demo', 'version': '1.0.0-1', 'architecture': 'amd64',
               'source_package': 'demo', 'source_version': '1.0.0-1',
               'binary_acquisition': {'filename': 'demo_1.0.0-1_amd64.deb',
                                      'sha256': hashlib.sha256(deb).hexdigest(), 'size': len(deb),
                                      'url': 'https://example.invalid/demo_1.0.0-1_amd64.deb'}}
    lock = {'schema_version': 1, 'apt_snapshot': '20260918T000000Z',
            'source_packages': [{'name': 'demo', 'version': '1.0.0-1', 'files': payloads}],
            'packages': [package]}
    return lock, dict(files, **{'demo_1.0.0-1_amd64.deb': deb})


def test_gather_verifies_hashes_and_extracts_signals(tmp_path, demo_lock):
    lock, store = demo_lock
    result = review_inputs.gather_review_inputs(lock, tmp_path / 'out', fetcher=store.get)
    assert result['status'] == 'complete'
    report = json.loads((tmp_path / 'out' / 'report.json').read_text())
    assert report['schema_version'] == 1
    source = report['sources']['demo=1.0.0-1']
    assert source['verified'] is True
    assert source['cargo_license'] == 'MIT OR Apache-2.0'
    assert 'debian/copyright' in source['evidence']
    evidence = tmp_path / 'out' / source['evidence']['debian/copyright']
    assert evidence.read_bytes() == COPYRIGHT
    binary = report['binaries']['demo=1.0.0-1']
    assert binary['verified'] is True
    assert './usr/share/doc/demo/copyright' in binary['evidence']


def test_gather_rejects_hash_mismatch_without_partial_claim(tmp_path, demo_lock):
    lock, store = demo_lock
    tampered = dict(store, **{'demo_1.0.0.orig.tar.gz': b'forged'})
    with pytest.raises(SourceError, match='checksum'):
        review_inputs.gather_review_inputs(lock, tmp_path / 'out', fetcher=tampered.get)
    assert not (tmp_path / 'out' / 'report.json').exists()


def test_gather_retries_transient_failures(tmp_path, demo_lock):
    lock, store = demo_lock
    attempts = []

    def flaky(name):
        attempts.append(name)
        if len([a for a in attempts if a == name]) < 3:
            raise review_inputs.FetchError('503 flaky mirror')
        return store[name]

    result = review_inputs.gather_review_inputs(lock, tmp_path / 'out', fetcher=flaky, sleeper=lambda seconds: None)
    assert result['status'] == 'complete'
    assert len(attempts) >= 3 * 4


def lz4_frame(content):
    header = bytes([0x60, 0x40])
    checksum = (review_inputs._xxh32(header) >> 8) & 0xFF
    token = min(len(content), 15) << 4
    block = bytes([token])
    if len(content) >= 15:
        remaining = len(content) - 15
        while remaining >= 255:
            block += b'\xff'
            remaining -= 255
        block += bytes([remaining])
    block += content
    return (b'\x04\x22\x4d\x18' + header + bytes([checksum])
            + len(block).to_bytes(4, 'little') + block + b'\x00\x00\x00\x00')


def test_lz4_frame_decode_round_trips_literals_and_matches():
    assert review_inputs.lz4_frame_decode(lz4_frame(b'Sources stanza bytes ' * 9)) == b'Sources stanza bytes ' * 9
    header = bytes([0x60, 0x40])
    checksum = (review_inputs._xxh32(header) >> 8) & 0xFF
    block = b'\x10a\x01\x00'
    frame = (b'\x04\x22\x4d\x18' + header + bytes([checksum])
             + len(block).to_bytes(4, 'little') + block + b'\x00\x00\x00\x00')
    assert review_inputs.lz4_frame_decode(frame) == b'aaaaa'
    with pytest.raises(SourceError, match='header checksum'):
        review_inputs.lz4_frame_decode(frame[:6] + b'\x00' + frame[7:])


def test_gather_accepts_pool_path_filenames_stored_by_basename(tmp_path, demo_lock):
    lock, store = demo_lock
    prefixed, relocated = {}, {}
    for name, raw in store.items():
        key = 'pool/main/d/demo/' + name
        relocated[key] = raw
    for entry in lock['source_packages'][0]['files']:
        prefixed[entry['filename']] = 'pool/main/d/demo/' + entry['filename']
        entry['filename'] = prefixed[entry['filename']]
    binary = lock['packages'][0]['binary_acquisition']
    binary['filename'] = 'pool/main/d/demo/' + binary['filename']
    result = review_inputs.gather_review_inputs(lock, tmp_path / 'out', fetcher=relocated.get,
                                                sleeper=lambda seconds: None)
    assert result['status'] == 'complete'
    assert (tmp_path / 'out' / 'files' / 'demo_1.0.0-1.dsc').is_file()


def test_gather_skips_cargo_gap_for_non_rust_tree(tmp_path, demo_lock):
    lock, store = demo_lock
    bare_orig = make_tar({'demo-1.0/README': b'no license signals here\n'})
    file_list = lock['source_packages'][0]['files']
    for entry in file_list:
        if entry['filename'] == 'demo_1.0.0.orig.tar.gz':
            entry['sha256'] = hashlib.sha256(bare_orig).hexdigest()
            entry['size'] = len(bare_orig)
    store = dict(store, **{'demo_1.0.0.orig.tar.gz': bare_orig})
    result = review_inputs.gather_review_inputs(lock, tmp_path / 'out', fetcher=store.get)
    assert result['status'] == 'complete'
    report = json.loads((tmp_path / 'out' / 'report.json').read_text())
    source = report['sources']['demo=1.0.0-1']
    assert source['cargo_license'] is None
    assert 'no-cargo-license' not in source['gaps']


def test_gather_flags_rust_tree_without_license_field(tmp_path, demo_lock):
    lock, store = demo_lock
    rust_orig = make_tar({'demo-1.0/Cargo.toml': b'[package]\nname = "demo"\nversion = "1.0.0"\n',
                          'demo-1.0/src/lib.rs': b'// no license\n'})
    file_list = lock['source_packages'][0]['files']
    for entry in file_list:
        if entry['filename'] == 'demo_1.0.0.orig.tar.gz':
            entry['sha256'] = hashlib.sha256(rust_orig).hexdigest()
            entry['size'] = len(rust_orig)
    store = dict(store, **{'demo_1.0.0.orig.tar.gz': rust_orig})
    review_inputs.gather_review_inputs(lock, tmp_path / 'out', fetcher=store.get)
    report = json.loads((tmp_path / 'out' / 'report.json').read_text())
    assert 'no-cargo-license' in report['sources']['demo=1.0.0-1']['gaps']


INDEX_NAME = ('snapshot.debian.org_archive_debian_20260918T000000Z'
              '_dists_trixie_main_source_Sources.lz4')
RELEASE_NAME = ('snapshot.debian.org_archive_debian_20260918T000000Z'
                '_dists_trixie_InRelease')


def incorporated_lock(with_built_using=True):
    helper_orig = make_tar({'helper-2.0/LICENSE': MIT_TEXT})
    helper_dsc = b'Format: 3.0 (native)\nSource: helper\nVersion: 2.0-1\n'
    stanza = ('Package: helper\nVersion: 2.0-1\nDirectory: pool/main/h/helper\n'
              'Files:\n d41d8cd98f00b204e9800998ecf8427e %d helper_2.0-1.dsc\n'
              ' d41d8cd98f00b204e9800998ecf8427e %d helper_2.0.orig.tar.gz\n'
              'Checksums-Sha256:\n %s %d helper_2.0-1.dsc\n %s %d helper_2.0.orig.tar.gz\n' % (
                  len(helper_dsc), len(helper_orig),
                  hashlib.sha256(helper_dsc).hexdigest(), len(helper_dsc),
                  hashlib.sha256(helper_orig).hexdigest(), len(helper_orig)))
    index = lz4_frame(stanza.encode())
    control = b'Package: demo\nVersion: 1.0.0-1\n'
    release = b'Origin: Debian\nSuite: trixie\n'
    if with_built_using:
        control += b'Static-Built-Using: helper (= 2.0-1)\n'
    deb = make_ar([('debian-binary', b'2.0\n'), ('control.tar.xz', make_tar({'control': control})),
                   ('data.tar.xz', make_tar({'./usr/share/doc/demo/copyright': COPYRIGHT}))])
    lock = {'schema_version': 1, 'apt_snapshot': '20260918T000000Z', 'source_packages': [],
            'packages': [{'name': 'demo', 'version': '1.0.0-1', 'architecture': 'amd64',
                          'source_package': 'demo', 'source_version': '1.0.0-1',
                          'binary_acquisition': {'filename': 'demo_1.0.0-1_amd64.deb',
                                                 'sha256': hashlib.sha256(deb).hexdigest(),
                                                 'size': len(deb), 'url': 'https://example.invalid/demo.deb'}}],
            'signed_index_inputs': [{'filename': INDEX_NAME, 'sha256': hashlib.sha256(index).hexdigest(),
                                     'size': len(index)},
                                    {'filename': RELEASE_NAME, 'sha256': hashlib.sha256(release).hexdigest(),
                                     'size': len(release)}]}
    store = {'demo_1.0.0-1_amd64.deb': deb, INDEX_NAME: index, RELEASE_NAME: release,
             'pool/main/h/helper/helper_2.0-1.dsc': helper_dsc,
             'pool/main/h/helper/helper_2.0.orig.tar.gz': helper_orig}
    return lock, store


def test_gather_resolves_incorporated_sources_through_pinned_index(tmp_path):
    lock, store = incorporated_lock()
    result = review_inputs.gather_review_inputs(lock, tmp_path / 'out', fetcher=store.get,
                                                sleeper=lambda seconds: None)
    assert result['status'] == 'complete'
    report = json.loads((tmp_path / 'out' / 'report.json').read_text())
    assert report['binaries']['demo=1.0.0-1']['incorporated_sources'] == ['helper=2.0-1']
    helper = report['sources']['helper=2.0-1']
    assert helper['verified'] is True
    assert helper['via'] == ['built-using:demo=1.0.0-1']
    assert any(name.endswith('LICENSE') for name in helper['evidence'])
    assert report['summary']['incorporated'] == 1
    assert report['indices'][INDEX_NAME]['stanzas'] == 1
    assert report['indices'][RELEASE_NAME] == {'suite': 'trixie', 'verified': True,
                                               'sha256': hashlib.sha256(store[RELEASE_NAME]).hexdigest()}


def test_gather_skips_index_phase_without_built_using(tmp_path):
    lock, store = incorporated_lock(with_built_using=False)
    result = review_inputs.gather_review_inputs(lock, tmp_path / 'out', fetcher=store.get,
                                                sleeper=lambda seconds: None)
    assert result['status'] == 'complete'
    report = json.loads((tmp_path / 'out' / 'report.json').read_text())
    assert report['sources'] == {}
    assert report['indices'] == {}


def test_gather_rejects_unresolved_incorporated_source(tmp_path):
    lock, store = incorporated_lock()
    empty = lz4_frame(b'Package: other\nVersion: 1\nDirectory: pool/main/o/other\nFiles:\n'
                      b' d41d8cd98f00b204e9800998ecf8427e 8 other_1.dsc\nChecksums-Sha256:\n'
                      b' ' + b'0' * 64 + b' 8 other_1.dsc\n')
    lock['signed_index_inputs'][0]['sha256'] = hashlib.sha256(empty).hexdigest()
    lock['signed_index_inputs'][0]['size'] = len(empty)
    store[INDEX_NAME] = empty
    with pytest.raises(SourceError, match='unresolved incorporated source'):
        review_inputs.gather_review_inputs(lock, tmp_path / 'out', fetcher=store.get,
                                           sleeper=lambda seconds: None)


def test_xxh32_matches_known_vectors():
    assert review_inputs._xxh32(b'') == 0x02CC5D05
    assert review_inputs._xxh32(b'abc') == 0x32D153FF
    assert review_inputs._xxh32(b'The quick brown fox jumps over the lazy dog') == 0xE85EA4DE


def test_lz4_decodes_real_encoder_frame():
    raw = (Path(__file__).parent / 'fixtures' / 'review-inputs' / 'trixie-updates_Sources.lz4').read_bytes()
    stanzas = review_inputs._parse_sources_index(review_inputs.lz4_frame_decode(raw).decode())
    assert ('python3.13', '3.13.5-2+deb13u4') in stanzas
    directory, files = stanzas[('libdatetime-timezone-perl', '1:2.65-1+2026c')]
    assert directory == 'pool/main/libd/libdatetime-timezone-perl'
    assert len(files) == 3


@pytest.mark.parametrize('filename', ['/abs/path.deb', '../escape.deb', 'a/../../b.deb', '', '.', 'pool/'])
def test_file_entry_rejects_traversal_and_empty_names(filename):
    with pytest.raises(ValueError, match='malformed lock file entry'):
        review_inputs._require_file_entry({'filename': filename, 'sha256': '0' * 64, 'size': 8,
                                           'url': 'https://example.invalid/x'})


def test_gather_rejects_exhausted_retries_and_non_bytes(tmp_path, demo_lock):
    lock, _ = demo_lock

    def down(name):
        raise review_inputs.FetchError('503')

    with pytest.raises(SourceError, match='failed after 2 attempts'):
        review_inputs.gather_review_inputs(lock, tmp_path / 'a', fetcher=down, attempts=2,
                                           sleeper=lambda seconds: None)
    with pytest.raises(SourceError, match='non-bytes'):
        review_inputs.gather_review_inputs(lock, tmp_path / 'b', fetcher=lambda name: 'text')
    with pytest.raises(ValueError, match='at least one fetch attempt'):
        review_inputs.gather_review_inputs(lock, tmp_path / 'c', fetcher=down, attempts=0)


def test_gather_rejects_bad_lock_shape_and_duplicates(tmp_path, demo_lock):
    lock, store = demo_lock
    bad_version = dict(lock, schema_version=2)
    with pytest.raises(ValueError, match='schema version 1'):
        review_inputs.gather_review_inputs(bad_version, tmp_path / 'a', fetcher=store.get)
    doubled = dict(lock, source_packages=lock['source_packages'] * 2)
    with pytest.raises(ValueError, match='duplicate or malformed lock source identity'):
        review_inputs.gather_review_inputs(doubled, tmp_path / 'b', fetcher=store.get)
    evil = {'schema_version': 1, 'apt_snapshot': 's', 'source_packages': [],
            'packages': [{'name': '../x', 'version': '1', 'binary_acquisition': {
                'filename': 'x.deb', 'sha256': '0' * 64, 'size': 8, 'url': 'https://example.invalid/x'}}]}
    with pytest.raises(ValueError, match='malformed lock package identity'):
        review_inputs.gather_review_inputs(evil, tmp_path / 'c', fetcher=store.get)


def test_ar_rejects_truncated_and_long_name_members():
    with pytest.raises(SourceError, match='not an ar archive'):
        review_inputs._read_ar_members(b'not-ar')
    with pytest.raises(SourceError, match='truncated ar member header'):
        review_inputs._read_ar_members(b'!<arch>\nshort')
    long_member = b'%-16s%-12d%-6d%-6d%-8o%-10d\x60\x0a' % (b'/42', 0, 0, 0, 0o644, 2) + b'ab'
    with pytest.raises(SourceError, match='long-name'):
        review_inputs._read_ar_members(b'!<arch>\n' + long_member)


def test_gather_labels_invalid_built_using_and_reads_lowercase(tmp_path, demo_lock):
    lock, store = demo_lock
    build = dict(store)
    control = b'Package: demo\nstatic-built-using: broken entry here\n'
    deb = make_ar([('debian-binary', b'2.0\n'), ('control.tar.xz', make_tar({'control': control})),
                   ('data.tar.xz', make_tar({'./usr/share/doc/demo/copyright': COPYRIGHT}))])
    lock['packages'][0]['binary_acquisition']['sha256'] = hashlib.sha256(deb).hexdigest()
    lock['packages'][0]['binary_acquisition']['size'] = len(deb)
    build['demo_1.0.0-1_amd64.deb'] = deb
    review_inputs.gather_review_inputs(lock, tmp_path / 'out', fetcher=build.get)
    report = json.loads((tmp_path / 'out' / 'report.json').read_text())
    gaps = report['binaries']['demo=1.0.0-1']['gaps']
    assert any(gap.startswith('invalid-built-using:') for gap in gaps)


def test_gather_rejects_ambiguous_and_mismatched_index(tmp_path):
    lock, store = incorporated_lock()
    second = INDEX_NAME.replace('trixie_main', 'trixie-updates_main')
    other_dsc = b'Format: 3.0 (native)\nSource: helper\nVersion: 2.0-1\nremarks: other suite\n'
    stanza = ('Package: helper\nVersion: 2.0-1\nDirectory: pool/main/h/helper\nChecksums-Sha256:\n'
              ' %s %d helper_2.0-1.dsc\n' % (hashlib.sha256(other_dsc).hexdigest(), len(other_dsc)))
    index = lz4_frame(stanza.encode())
    lock['signed_index_inputs'].append({'filename': second, 'sha256': hashlib.sha256(index).hexdigest(),
                                        'size': len(index)})
    store[second] = index
    with pytest.raises(SourceError, match='ambiguous incorporated source'):
        review_inputs.gather_review_inputs(lock, tmp_path / 'out', fetcher=store.get,
                                           sleeper=lambda seconds: None)
    with pytest.raises(ValueError, match='outside pinned snapshot'):
        review_inputs._index_url(INDEX_NAME, '20000101T000000Z')


def test_gather_handles_native_package_layout(tmp_path, demo_lock):
    lock, store = demo_lock
    native_orig = make_tar({'demo-1.0/debian/copyright': COPYRIGHT})
    native_dsc = b'Format: 3.0 (native)\nSource: demo\nVersion: 1.0.0-1\n'
    file_list = lock['source_packages'][0]['files']
    renamed = [entry for entry in file_list if '.debian.tar' not in entry['filename']]
    assert len(renamed) == 2
    lock['source_packages'][0]['files'] = renamed
    for entry in renamed:
        if entry['filename'].endswith('.dsc'):
            entry['sha256'] = hashlib.sha256(native_dsc).hexdigest()
            entry['size'] = len(native_dsc)
        else:
            entry['sha256'] = hashlib.sha256(native_orig).hexdigest()
            entry['size'] = len(native_orig)
    store = dict(store, **{'demo_1.0.0-1.dsc': native_dsc, 'demo_1.0.0.orig.tar.gz': native_orig})
    review_inputs.gather_review_inputs(lock, tmp_path / 'out', fetcher=store.get)
    report = json.loads((tmp_path / 'out' / 'report.json').read_text())
    source = report['sources']['demo=1.0.0-1']
    assert 'debian/copyright' in source['evidence']
    assert 'no-debian-tarball' not in source['gaps']
    assert 'no-debian-copyright' not in source['gaps']


def test_gather_records_cargo_oversize_gap(tmp_path, demo_lock, monkeypatch):
    lock, store = demo_lock
    monkeypatch.setattr(review_inputs, 'EVIDENCE_FILE_BOUND', 8)
    review_inputs.gather_review_inputs(lock, tmp_path / 'out', fetcher=store.get)
    report = json.loads((tmp_path / 'out' / 'report.json').read_text())
    assert 'oversize-cargo-toml' in report['sources']['demo=1.0.0-1']['gaps']


def test_gather_manifest_covers_every_output_byte(tmp_path, demo_lock):
    lock, store = demo_lock
    review_inputs.gather_review_inputs(lock, tmp_path / 'out', fetcher=store.get)
    lines = (tmp_path / 'out' / 'SHA256SUMS').read_text().splitlines()
    manifest = dict(line.split('  ')[::-1] for line in lines)
    assert 'report.json' in manifest
    assert not (tmp_path / 'out' / 'report.json.staged').exists()
    for path, digest in manifest.items():
        assert hashlib.sha256((tmp_path / 'out' / path).read_bytes()).hexdigest() == digest
