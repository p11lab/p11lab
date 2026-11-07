"""Review-input gathering fetches lock-pinned bytes and extracts license evidence without concluding rights."""
import hashlib
import io
import json
import lzma
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
    asc = b'-----BEGIN PGP SIGNATURE-----\nAAAA\n-----END PGP SIGNATURE-----\n'
    dsc = ('Format: 3.0 (quilt)\nSource: demo\nVersion: 1.0.0-1\nChecksums-Sha256:\n'
           ' %s %d demo_1.0.0.orig.tar.gz\n %s %d demo_1.0.0-1.debian.tar.xz\n' % (
               hashlib.sha256(orig).hexdigest(), len(orig),
               hashlib.sha256(debian).hexdigest(), len(debian))).encode()
    data_tar = make_tar({'./usr/share/doc/demo/copyright': COPYRIGHT})
    deb = make_ar([('debian-binary', b'2.0\n'), ('control.tar.xz', make_tar({'control': b'Package: demo\n'})),
                   ('data.tar.xz', data_tar)])
    files = {'demo_1.0.0-1.dsc': dsc, 'demo_1.0.0.orig.tar.gz': orig,
             'demo_1.0.0.orig.tar.gz.asc': asc, 'demo_1.0.0-1.debian.tar.xz': debian}
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
    bare_dsc = b'Format: 3.0 (quilt)\nSource: demo\nVersion: 1.0.0-1\n'
    file_list = lock['source_packages'][0]['files']
    for entry in file_list:
        if entry['filename'] == 'demo_1.0.0.orig.tar.gz':
            entry['sha256'] = hashlib.sha256(bare_orig).hexdigest()
            entry['size'] = len(bare_orig)
        if entry['filename'] == 'demo_1.0.0-1.dsc':
            entry['sha256'] = hashlib.sha256(bare_dsc).hexdigest()
            entry['size'] = len(bare_dsc)
    store = dict(store, **{'demo_1.0.0.orig.tar.gz': bare_orig, 'demo_1.0.0-1.dsc': bare_dsc})
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
    bare_dsc = b'Format: 3.0 (quilt)\nSource: demo\nVersion: 1.0.0-1\n'
    file_list = lock['source_packages'][0]['files']
    for entry in file_list:
        if entry['filename'] == 'demo_1.0.0.orig.tar.gz':
            entry['sha256'] = hashlib.sha256(rust_orig).hexdigest()
            entry['size'] = len(rust_orig)
        if entry['filename'] == 'demo_1.0.0-1.dsc':
            entry['sha256'] = hashlib.sha256(bare_dsc).hexdigest()
            entry['size'] = len(bare_dsc)
    store = dict(store, **{'demo_1.0.0.orig.tar.gz': rust_orig, 'demo_1.0.0-1.dsc': bare_dsc})
    review_inputs.gather_review_inputs(lock, tmp_path / 'out', fetcher=store.get)
    report = json.loads((tmp_path / 'out' / 'report.json').read_text())
    assert 'no-cargo-license' in report['sources']['demo=1.0.0-1']['gaps']


LZ4_NAME = ('snapshot.debian.org_archive_debian_20260918T000000Z'
              '_dists_trixie_main_source_Sources.lz4')
RELEASE_NAME = ('snapshot.debian.org_archive_debian_20260918T000000Z'
                '_dists_trixie_InRelease')
XZ_KEY = 'index/trixie/main/source/Sources.xz'


def stanza_for(name, version, directory, files):
    rows = ''.join(' %s %d %s\n' % (hashlib.sha256(raw).hexdigest(), len(raw), filename)
                   for filename, raw in files)
    return 'Package: %s\nVersion: %s\nDirectory: %s\nChecksums-Sha256:\n%s' % (name, version, directory, rows)


def release_for(xz):
    return ('Origin: Debian\nSuite: trixie\nSHA256:\n %s %d main/source/Sources.xz\n' % (
        hashlib.sha256(xz).hexdigest(), len(xz))).encode()


def incorporated_lock(with_built_using=True):
    helper_orig = make_tar({'helper-2.0/LICENSE': MIT_TEXT})
    helper_dsc = b'Format: 3.0 (native)\nSource: helper\nVersion: 2.0-1\n'
    demo_orig = make_tar({'demo-1.0/LICENSE': MIT_TEXT})
    demo_dsc = b'Format: 3.0 (native)\nSource: demo\nVersion: 1.0.0-1\n'
    text = (stanza_for('helper', '2.0-1', 'pool/main/h/helper',
                       [('helper_2.0-1.dsc', helper_dsc), ('helper_2.0.orig.tar.gz', helper_orig)])
            + '\n'
            + stanza_for('demo', '1.0.0-1', 'pool/main/d/demo',
                         [('demo_1.0.0-1.dsc', demo_dsc), ('demo_1.0.0.orig.tar.gz', demo_orig)]))
    xz = lzma.compress(text.encode())
    release = release_for(xz)
    control = b'Package: demo\nVersion: 1.0.0-1\n'
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
            'signed_index_inputs': [{'filename': LZ4_NAME, 'sha256': '1' * 64, 'size': 8},
                                    {'filename': RELEASE_NAME, 'sha256': hashlib.sha256(release).hexdigest(),
                                     'size': len(release)}]}
    store = {'demo_1.0.0-1_amd64.deb': deb, RELEASE_NAME: release, XZ_KEY: xz,
             'pool/main/h/helper/helper_2.0-1.dsc': helper_dsc,
             'pool/main/h/helper/helper_2.0.orig.tar.gz': helper_orig,
             'pool/main/d/demo/demo_1.0.0-1.dsc': demo_dsc,
             'pool/main/d/demo/demo_1.0.0.orig.tar.gz': demo_orig}
    return lock, store


def test_gather_resolves_sources_through_pinned_index(tmp_path):
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
    assert report['sources']['demo=1.0.0-1']['via'] == ['binary-source:demo=1.0.0-1']
    assert report['summary']['incorporated'] == 1
    assert report['summary']['index_resolved'] == 2
    assert report['indices'][XZ_KEY]['stanzas'] == 2
    assert report['indices'][RELEASE_NAME] == {'suite': 'trixie', 'verified': True,
                                               'sha256': hashlib.sha256(store[RELEASE_NAME]).hexdigest()}
    assert report['indices'][LZ4_NAME]['downloadable'] is False


def test_gather_records_indices_even_without_wanted_sources(tmp_path):
    lock, store = incorporated_lock()
    lock['packages'] = []
    result = review_inputs.gather_review_inputs(lock, tmp_path / 'out', fetcher=store.get,
                                                sleeper=lambda seconds: None)
    assert result['status'] == 'complete'
    report = json.loads((tmp_path / 'out' / 'report.json').read_text())
    assert report['sources'] == {}
    assert report['indices'][RELEASE_NAME]['verified'] is True
    assert report['indices'][XZ_KEY]['stanzas'] == 2


def test_gather_rejects_unresolved_source(tmp_path):
    lock, store = incorporated_lock()
    xz = lzma.compress(stanza_for('other', '1', 'pool/main/o/other', [('other_1.dsc', b'x')]).encode())
    release = release_for(xz)
    lock['signed_index_inputs'][1]['sha256'] = hashlib.sha256(release).hexdigest()
    lock['signed_index_inputs'][1]['size'] = len(release)
    store[RELEASE_NAME] = release
    store[XZ_KEY] = xz
    with pytest.raises(SourceError, match='unresolved source'):
        review_inputs.gather_review_inputs(lock, tmp_path / 'out', fetcher=store.get,
                                           sleeper=lambda seconds: None)


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


def test_gather_parses_lowercase_built_using(tmp_path, demo_lock):
    lock, store = demo_lock
    build = dict(store)
    control = b'Package: demo\nstatic-built-using: demo (= 1.0.0-1)\n'
    deb = make_ar([('debian-binary', b'2.0\n'), ('control.tar.xz', make_tar({'control': control})),
                   ('data.tar.xz', make_tar({'./usr/share/doc/demo/copyright': COPYRIGHT}))])
    lock['packages'][0]['binary_acquisition']['sha256'] = hashlib.sha256(deb).hexdigest()
    lock['packages'][0]['binary_acquisition']['size'] = len(deb)
    build['demo_1.0.0-1_amd64.deb'] = deb
    review_inputs.gather_review_inputs(lock, tmp_path / 'out', fetcher=build.get)
    report = json.loads((tmp_path / 'out' / 'report.json').read_text())
    assert report['binaries']['demo=1.0.0-1']['incorporated_sources'] == ['demo=1.0.0-1']
    assert sorted(report['sources']['demo=1.0.0-1']['via']) == ['binary-source:demo=1.0.0-1',
                                                                 'built-using:demo=1.0.0-1', 'lock']


def test_gather_rejects_invalid_built_using_and_duplicates(tmp_path, demo_lock):
    lock, store = demo_lock
    for control in (b'Package: demo\nStatic-Built-Using: broken entry here\n',
                    b'Package: demo\nBuilt-Using: demo (= 1.0.0-1)\nBuilt-Using: demo (= 1.0.0-1)\n'):
        deb = make_ar([('debian-binary', b'2.0\n'), ('control.tar.xz', make_tar({'control': control})),
                       ('data.tar.xz', make_tar({'./usr/share/doc/demo/copyright': COPYRIGHT}))])
        lock['packages'][0]['binary_acquisition']['sha256'] = hashlib.sha256(deb).hexdigest()
        lock['packages'][0]['binary_acquisition']['size'] = len(deb)
        with pytest.raises(SourceError):
            review_inputs.gather_review_inputs(lock, tmp_path / ('o%d' % len(control)),
                                               fetcher=dict(store, **{'demo_1.0.0-1_amd64.deb': deb}).get)
    twin = make_ar([('debian-binary', b'2.0\n'), ('control.tar.xz', make_tar({'control': b'Package: demo\n'})),
                    ('control.tar.gz', make_tar({'control': b'Package: demo\n'})),
                    ('data.tar.xz', make_tar({'./usr/share/doc/demo/copyright': COPYRIGHT}))])
    lock['packages'][0]['binary_acquisition']['sha256'] = hashlib.sha256(twin).hexdigest()
    lock['packages'][0]['binary_acquisition']['size'] = len(twin)
    with pytest.raises(SourceError, match='ambiguous or missing ar members'):
        review_inputs.gather_review_inputs(lock, tmp_path / 'twin',
                                           fetcher=dict(store, **{'demo_1.0.0-1_amd64.deb': twin}).get)


def _add_updates_suite(lock, store, stanza_text):
    second_release = RELEASE_NAME.replace('trixie_InRelease', 'trixie-updates_InRelease')
    xz = lzma.compress(stanza_text.encode())
    release = release_for(xz)
    lock['signed_index_inputs'].append({'filename': second_release,
                                        'sha256': hashlib.sha256(release).hexdigest(), 'size': len(release)})
    store[second_release] = release
    store['index/trixie-updates/main/source/Sources.xz'] = xz


def test_gather_prefers_base_suite_on_identical_content(tmp_path):
    lock, store = incorporated_lock()
    mirror = stanza_for('helper', '2.0-1', 'pool/updates/main/h/helper',
                        [('helper_2.0-1.dsc', store['pool/main/h/helper/helper_2.0-1.dsc']),
                         ('helper_2.0.orig.tar.gz', store['pool/main/h/helper/helper_2.0.orig.tar.gz'])])
    _add_updates_suite(lock, store, mirror)
    review_inputs.gather_review_inputs(lock, tmp_path / 'out', fetcher=store.get,
                                       sleeper=lambda seconds: None)
    report = json.loads((tmp_path / 'out' / 'report.json').read_text())
    helper = report['sources']['helper=2.0-1']
    assert sorted(helper['files']) == ['pool/main/h/helper/helper_2.0-1.dsc',
                                       'pool/main/h/helper/helper_2.0.orig.tar.gz']
    assert not [gap for gap in helper['gaps'] if gap.startswith('ambiguous-source')]


def test_gather_flags_content_ambiguity_with_gap(tmp_path):
    lock, store = incorporated_lock()
    other_dsc = b'Format: 3.0 (native)\nSource: helper\nVersion: 2.0-1\nremarks: other suite\n'
    _add_updates_suite(lock, store, stanza_for('helper', '2.0-1', 'pool/main/h/helper',
                                               [('helper_2.0-1.dsc', other_dsc)]))
    review_inputs.gather_review_inputs(lock, tmp_path / 'out', fetcher=store.get,
                                       sleeper=lambda seconds: None)
    report = json.loads((tmp_path / 'out' / 'report.json').read_text())
    assert 'ambiguous-source-preferred:trixie' in report['sources']['helper=2.0-1']['gaps']


def test_index_url_validates_snapshot_and_kind():
    with pytest.raises(ValueError, match='outside pinned snapshot'):
        review_inputs._index_url(RELEASE_NAME, '20000101T000000Z')
    with pytest.raises(ValueError, match='builder-cache fingerprint'):
        review_inputs._index_url(LZ4_NAME, '20260918T000000Z')


def test_gather_handles_native_package_layout(tmp_path, demo_lock):
    lock, store = demo_lock
    native_orig = make_tar({'demo-1.0/debian/copyright': COPYRIGHT})
    native_dsc = b'Format: 3.0 (native)\nSource: demo\nVersion: 1.0.0-1\n'
    file_list = lock['source_packages'][0]['files']
    renamed = [entry for entry in file_list
               if '.debian.tar' not in entry['filename'] and not entry['filename'].endswith('.asc')]
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
    monkeypatch.setattr(review_inputs, 'EVIDENCE_FILE_BOUND', 32)
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
    expected = {path.relative_to(tmp_path / 'out').as_posix()
                for path in (tmp_path / 'out').rglob('*') if path.is_file()} - {'SHA256SUMS'}
    assert set(manifest) == expected


def _swap_orig(lock, store, orig):
    bare_dsc = b'Format: 3.0 (quilt)\nSource: demo\nVersion: 1.0.0-1\n'
    for entry in lock['source_packages'][0]['files']:
        if entry['filename'] == 'demo_1.0.0.orig.tar.gz':
            entry['sha256'] = hashlib.sha256(orig).hexdigest()
            entry['size'] = len(orig)
        if entry['filename'] == 'demo_1.0.0-1.dsc':
            entry['sha256'] = hashlib.sha256(bare_dsc).hexdigest()
            entry['size'] = len(bare_dsc)
    return dict(store, **{'demo_1.0.0.orig.tar.gz': orig, 'demo_1.0.0-1.dsc': bare_dsc})


def test_gather_attributes_cargo_license_to_manifest(tmp_path, demo_lock):
    lock, store = demo_lock
    review_inputs.gather_review_inputs(lock, tmp_path / 'out', fetcher=store.get)
    report = json.loads((tmp_path / 'out' / 'report.json').read_text())
    source = report['sources']['demo=1.0.0-1']
    assert source['cargo_license'] == 'MIT OR Apache-2.0'
    assert source['cargo_manifest'] == 'demo-1.0/Cargo.toml'


def test_gather_ignores_license_outside_package_table(tmp_path, demo_lock):
    lock, store = demo_lock
    orig = make_tar({'demo-1.0/Cargo.toml': b'[package]\nname = "demo"\nversion = "1.0.0"\n'
                                            b'[package.metadata.other]\nlicense = "Bogus-1.0"\n',
                     'demo-1.0/src/lib.rs': b'// rust\n'})
    review_inputs.gather_review_inputs(lock, tmp_path / 'out', fetcher=_swap_orig(lock, store, orig).get)
    report = json.loads((tmp_path / 'out' / 'report.json').read_text())
    source = report['sources']['demo=1.0.0-1']
    assert source['cargo_license'] is None
    assert 'no-cargo-license' in source['gaps']


def test_gather_falls_back_on_unparseable_manifest(tmp_path, demo_lock):
    lock, store = demo_lock
    orig = make_tar({'demo-1.0/Cargo.toml': b'[package\nlicense = "MIT"\n',
                     'demo-1.0/src/lib.rs': b'// rust\n'})
    review_inputs.gather_review_inputs(lock, tmp_path / 'out', fetcher=_swap_orig(lock, store, orig).get)
    report = json.loads((tmp_path / 'out' / 'report.json').read_text())
    source = report['sources']['demo=1.0.0-1']
    assert source['cargo_license'] == 'MIT'
    assert 'cargo-toml-unparseable' in source['gaps']


def test_gather_resolves_and_flags_cargo_license_file(tmp_path, demo_lock):
    lock, store = demo_lock
    good = make_tar({'demo-1.0/Cargo.toml': b'[package]\nname = "demo"\nversion = "1.0.0"\n'
                                            b'license-file = "LICENSE.txt"\n',
                     'demo-1.0/LICENSE.txt': MIT_TEXT, 'demo-1.0/src/lib.rs': b'// rust\n'})
    review_inputs.gather_review_inputs(lock, tmp_path / 'good', fetcher=_swap_orig(lock, store, good).get)
    report = json.loads((tmp_path / 'good' / 'report.json').read_text())
    source = report['sources']['demo=1.0.0-1']
    assert source['cargo_license_file'] == 'LICENSE.txt'
    assert 'demo-1.0/LICENSE.txt' in source['evidence']
    assert 'no-cargo-license' not in source['gaps']
    lock2, _ = demo_lock
    bad = make_tar({'demo-1.0/Cargo.toml': b'[package]\nname = "demo"\nversion = "1.0.0-1"\n'
                                           b'license-file = "MISSING.txt"\n',
                    'demo-1.0/src/lib.rs': b'// rust\n'})
    review_inputs.gather_review_inputs(lock2, tmp_path / 'bad', fetcher=_swap_orig(lock2, store, bad).get)
    report = json.loads((tmp_path / 'bad' / 'report.json').read_text())
    assert 'missing-cargo-license-file' in report['sources']['demo=1.0.0-1']['gaps']


def test_gather_keeps_vendored_copyright_as_evidence_only(tmp_path, demo_lock):
    lock, store = demo_lock
    lock['source_packages'][0]['files'] = [entry for entry in lock['source_packages'][0]['files']
                                           if '.debian.tar' not in entry['filename']]
    orig = make_tar({'demo-1.0/vendor/other/debian/copyright': COPYRIGHT})
    review_inputs.gather_review_inputs(lock, tmp_path / 'out', fetcher=_swap_orig(lock, store, orig).get)
    report = json.loads((tmp_path / 'out' / 'report.json').read_text())
    source = report['sources']['demo=1.0.0-1']
    assert 'demo-1.0/vendor/other/debian/copyright' in source['evidence']
    assert 'no-debian-copyright' in source['gaps']


def test_deb822_rejects_duplicate_fields_and_files():
    with pytest.raises(SourceError, match='duplicate or empty deb822 field'):
        review_inputs._parse_deb822('Package: a\nPackage: a\n')
    with pytest.raises(SourceError, match='malformed Sources file identity'):
        review_inputs._parse_sources_index(
            'Package: a\nVersion: 1\nDirectory: pool/main/a/a\nChecksums-Sha256:\n'
            ' %s 8 f.dsc\n %s 8 f.dsc\n' % ('0' * 64, '1' * 64))


def test_dsc_roster_mismatch_is_fatal(tmp_path, demo_lock):
    lock, store = demo_lock
    forged = ('Format: 3.0 (quilt)\nSource: demo\nVersion: 1.0.0-1\nChecksums-Sha256:\n'
              ' %s 4 ghost.tar.gz\n' % ('0' * 64)).encode()
    for entry in lock['source_packages'][0]['files']:
        if entry['filename'] == 'demo_1.0.0-1.dsc':
            entry['sha256'] = hashlib.sha256(forged).hexdigest()
            entry['size'] = len(forged)
    with pytest.raises(SourceError, match='dsc lists unfetched file'):
        review_inputs.gather_review_inputs(lock, tmp_path / 'out',
                                           fetcher=dict(store, **{'demo_1.0.0-1.dsc': forged}).get)


def test_dsc_size_mismatch_is_fatal(tmp_path, demo_lock):
    lock, store = demo_lock
    orig = store['demo_1.0.0.orig.tar.gz']
    forged = ('Format: 3.0 (quilt)\nSource: demo\nVersion: 1.0.0-1\nChecksums-Sha256:\n'
              ' %s %d demo_1.0.0.orig.tar.gz\n' % (hashlib.sha256(orig).hexdigest(), len(orig) + 1)).encode()
    for entry in lock['source_packages'][0]['files']:
        if entry['filename'] == 'demo_1.0.0-1.dsc':
            entry['sha256'] = hashlib.sha256(forged).hexdigest()
            entry['size'] = len(forged)
    with pytest.raises(SourceError, match='dsc size mismatch'):
        review_inputs.gather_review_inputs(lock, tmp_path / 'out',
                                           fetcher=dict(store, **{'demo_1.0.0-1.dsc': forged}).get)


def test_deb822_field_names_are_case_insensitive(tmp_path):
    with pytest.raises(SourceError, match='duplicate or empty deb822 field'):
        review_inputs._parse_deb822('Package: a\npackage: a\n')
    stanzas = review_inputs._parse_sources_index(
        'package: a\nversion: 1\ndirectory: pool/main/a/a\nchecksums-sha256:\n %s 8 f.dsc\n' % ('0' * 64))
    assert stanzas[('a', '1')][1] == [('0' * 64, 8, 'f.dsc')]


def test_wrapperless_vendor_copyright_is_not_canonical(tmp_path, demo_lock):
    lock, store = demo_lock
    lock['source_packages'][0]['files'] = [entry for entry in lock['source_packages'][0]['files']
                                           if '.debian.tar' not in entry['filename']]
    orig = make_tar({'Cargo.toml': b'[package]\nname = "demo"\n',
                     'vendor/debian/copyright': COPYRIGHT})
    review_inputs.gather_review_inputs(lock, tmp_path / 'out', fetcher=_swap_orig(lock, store, orig).get)
    report = json.loads((tmp_path / 'out' / 'report.json').read_text())
    source = report['sources']['demo=1.0.0-1']
    assert 'vendor/debian/copyright' in source['evidence']
    assert 'no-debian-copyright' in source['gaps']


def test_conflicting_control_files_are_fatal(tmp_path, demo_lock):
    lock, store = demo_lock
    twin = make_ar([('debian-binary', b'2.0\n'),
                    ('control.tar.xz', make_tar({'control': b'Package: demo\n',
                                                 './control': b'Package: demo\nBuilt-Using: x (= 1)\n'})),
                    ('data.tar.xz', make_tar({'./usr/share/doc/demo/copyright': COPYRIGHT}))])
    lock['packages'][0]['binary_acquisition']['sha256'] = hashlib.sha256(twin).hexdigest()
    lock['packages'][0]['binary_acquisition']['size'] = len(twin)
    with pytest.raises(SourceError, match='conflicting control files'):
        review_inputs.gather_review_inputs(lock, tmp_path / 'out',
                                           fetcher=dict(store, **{'demo_1.0.0-1_amd64.deb': twin}).get)


def test_xz_decoder_limit_and_trailing_streams(tmp_path, monkeypatch):
    lock, store = incorporated_lock()
    monkeypatch.setattr(review_inputs, 'INDEX_DECODER_MEMLIMIT', 1024)
    with pytest.raises(SourceError, match='unreadable Sources.xz'):
        review_inputs.gather_review_inputs(lock, tmp_path / 'mem', fetcher=store.get,
                                           sleeper=lambda seconds: None)
    monkeypatch.setattr(review_inputs, 'INDEX_DECODER_MEMLIMIT', 256 * 1024**2)
    doubled = store[XZ_KEY] + lzma.compress(b'Package: late\nVersion: 1\n')
    release = release_for(doubled)
    lock['signed_index_inputs'][1]['sha256'] = hashlib.sha256(release).hexdigest()
    lock['signed_index_inputs'][1]['size'] = len(release)
    with pytest.raises(SourceError, match='exceeds decode bound'):
        review_inputs.gather_review_inputs(
            lock, tmp_path / 'trail',
            fetcher=dict(store, **{RELEASE_NAME: release, XZ_KEY: doubled}).get,
            sleeper=lambda seconds: None)


def test_fetch_url_validates_and_verifies_mocked_bytes(monkeypatch):
    with pytest.raises(SourceError, match='public HTTPS'):
        review_inputs.fetch_url('http://example.invalid/f', 8, '0' * 64)
    with pytest.raises(SourceError, match='pinned sha256'):
        review_inputs.fetch_url('https://example.invalid/f', 8, 'zzz')
    with pytest.raises(SourceError, match='acquisition bound'):
        review_inputs.fetch_url('https://example.invalid/f', 0, '0' * 64)

    raw = b'pinned-bytes'

    class Response:
        def geturl(self):
            return 'https://example.invalid/f'

        def read(self, limit=None):
            return raw

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    class Opener:
        def open(self, request, timeout=None):
            assert request.full_url == 'https://example.invalid/f'
            return Response()

    monkeypatch.setattr(review_inputs, 'build_opener', lambda *args: Opener())
    digest = hashlib.sha256(raw).hexdigest()
    assert review_inputs.fetch_url('https://example.invalid/f', len(raw), digest) == raw
    with pytest.raises(SourceError, match='checksum'):
        review_inputs.fetch_url('https://example.invalid/f', len(raw), '0' * 64)
    with pytest.raises(SourceError, match='outside public HTTPS'):
        review_inputs._HTTPSOnlyRedirect().redirect_request(None, None, 302, '', {}, 'http://evil/x')


def test_gather_cache_serves_verified_bytes_without_refetch(tmp_path, demo_lock):
    lock, store = demo_lock
    cache = tmp_path / 'cache'
    calls = []

    def counting(name):
        calls.append(name)
        return store[name]

    first = review_inputs.gather_review_inputs(lock, tmp_path / 'out1', fetcher=counting,
                                               cache_dir=cache, sleeper=lambda seconds: None)
    assert first['status'] == 'complete'
    assert calls, 'expected network fetches on a cold cache'

    def offline(name):
        raise review_inputs.FetchError('mirror unreachable')

    second = review_inputs.gather_review_inputs(lock, tmp_path / 'out2', fetcher=offline,
                                                cache_dir=cache, sleeper=lambda seconds: None)
    assert second['status'] == 'complete'
    first_report = json.loads((tmp_path / 'out1' / 'report.json').read_text())
    second_report = json.loads((tmp_path / 'out2' / 'report.json').read_text())
    assert first_report['summary']['cache_hits'] == 0
    assert second_report['summary']['cache_hits'] == len(calls)


def test_gather_cache_rejects_symlink_and_nested_dirs(tmp_path, demo_lock):
    lock, store = demo_lock
    real = tmp_path / 'real'
    real.mkdir()
    link = tmp_path / 'link'
    link.symlink_to(real, target_is_directory=True)
    with pytest.raises(ValueError, match='real directory'):
        review_inputs.gather_review_inputs(lock, tmp_path / 'out', fetcher=store.get,
                                           cache_dir=link, sleeper=lambda seconds: None)
    nested = tmp_path / 'out2' / 'cache'
    with pytest.raises(ValueError, match='inside the output directory'):
        review_inputs.gather_review_inputs(lock, tmp_path / 'out2', fetcher=store.get,
                                           cache_dir=nested, sleeper=lambda seconds: None)


def test_gather_cache_ignores_corrupt_entry_and_refetches(tmp_path, demo_lock):
    lock, store = demo_lock
    cache = tmp_path / 'cache'
    cache.mkdir()
    (cache / 'demo_1.0.0.orig.tar.gz').write_bytes(b'corrupt cache entry')
    calls = []

    def counting(name):
        calls.append(name)
        return store[name]

    result = review_inputs.gather_review_inputs(lock, tmp_path / 'out', fetcher=counting,
                                                cache_dir=cache, sleeper=lambda seconds: None)
    assert result['status'] == 'complete'
    assert 'demo_1.0.0.orig.tar.gz' in calls
    assert (cache / 'demo_1.0.0.orig.tar.gz').read_bytes() == store['demo_1.0.0.orig.tar.gz']


def test_gather_cache_never_serves_bytes_for_other_lock(tmp_path, demo_lock):
    lock, store = demo_lock
    cache = tmp_path / 'cache'
    review_inputs.gather_review_inputs(lock, tmp_path / 'out1', fetcher=store.get,
                                       cache_dir=cache, sleeper=lambda seconds: None)
    other_raw = b'different bytes, same basename'
    other = dict(lock)
    other['source_packages'] = [{'name': 'demo', 'version': '9.9.9-9',
                                 'files': [{'filename': 'demo_1.0.0.orig.tar.gz',
                                            'sha256': hashlib.sha256(other_raw).hexdigest(),
                                            'size': len(other_raw),
                                            'url': 'https://example.invalid/demo_1.0.0.orig.tar.gz'}]}]
    other['packages'] = []

    def offline(name):
        raise review_inputs.FetchError('mirror unreachable')

    with pytest.raises(SourceError, match='fetch failed'):
        review_inputs.gather_review_inputs(other, tmp_path / 'out2', fetcher=offline,
                                           cache_dir=cache, sleeper=lambda seconds: None)


BANNED_UPLOAD_CHARS = set('"*:<>?|\r\n')


def assert_bundle_paths_portable(root):
    offenders = [p.relative_to(root).as_posix() for p in root.rglob('*')
                 if BANNED_UPLOAD_CHARS & set(p.relative_to(root).as_posix())]
    assert not offenders, offenders


def test_gather_evidence_paths_quote_epoch_colons(tmp_path, demo_lock):
    lock, store = demo_lock
    lock['source_packages'][0]['version'] = '1:1.0.0-1'
    lock['packages'][0]['version'] = '1:1.0.0-1'
    lock['packages'][0]['source_version'] = '1:1.0.0-1'
    review_inputs.gather_review_inputs(lock, tmp_path / 'out', fetcher=store.get)
    report = json.loads((tmp_path / 'out' / 'report.json').read_text())
    assert report['sources']['demo=1:1.0.0-1']['verified'] is True
    for section in ('sources', 'binaries'):
        for relpath in report[section]['demo=1:1.0.0-1']['evidence'].values():
            assert not BANNED_UPLOAD_CHARS & set(relpath), relpath
            assert (tmp_path / 'out' / relpath).is_file()
    assert_bundle_paths_portable(tmp_path / 'out')


def test_gather_evidence_paths_quote_banned_member_chars(tmp_path, demo_lock):
    lock, store = demo_lock
    orig = make_tar({'demo-1.0/Cargo.toml': CARGO, 'demo-1.0/LICENSE-MIT:x': MIT_TEXT})
    files = dict(store)
    files['demo_1.0.0.orig.tar.gz'] = orig
    for item in lock['source_packages'][0]['files']:
        if item['filename'] == 'demo_1.0.0.orig.tar.gz':
            item['sha256'] = hashlib.sha256(orig).hexdigest()
            item['size'] = len(orig)
    lock['source_packages'][0]['files'] = [
        item for item in lock['source_packages'][0]['files']
        if item['filename'] != 'demo_1.0.0.orig.tar.gz.asc']
    dsc = ('Format: 3.0 (quilt)\nSource: demo\nVersion: 1.0.0-1\nChecksums-Sha256:\n'
           ' %s %d demo_1.0.0.orig.tar.gz\n' % (hashlib.sha256(orig).hexdigest(), len(orig)))
    debian = make_tar({'debian/copyright': COPYRIGHT})
    dsc += ' %s %d demo_1.0.0-1.debian.tar.xz\n' % (hashlib.sha256(debian).hexdigest(), len(debian))
    files['demo_1.0.0-1.dsc'] = dsc.encode()
    for item in lock['source_packages'][0]['files']:
        if item['filename'] == 'demo_1.0.0-1.dsc':
            item['sha256'] = hashlib.sha256(files['demo_1.0.0-1.dsc']).hexdigest()
            item['size'] = len(files['demo_1.0.0-1.dsc'])
    result = review_inputs.gather_review_inputs(lock, tmp_path / 'out', fetcher=files.get)
    assert result['status'] == 'complete'
    report = json.loads((tmp_path / 'out' / 'report.json').read_text())
    relpath = report['sources']['demo=1.0.0-1']['evidence']['demo-1.0/LICENSE-MIT:x']
    assert not BANNED_UPLOAD_CHARS & set(relpath), relpath
    assert (tmp_path / 'out' / relpath).read_bytes() == MIT_TEXT
    assert_bundle_paths_portable(tmp_path / 'out')


def test_report_lists_provider_inputs_as_not_gathered(tmp_path, demo_lock):
    lock, store = demo_lock
    lock['sources'] = [{'kind': 'git', 'url': 'https://example.invalid/upstream.git'}]
    lock['patches'] = [{'path': 'a.patch'}]
    lock['dependencies'] = ['build-essential']
    review_inputs.gather_review_inputs(lock, tmp_path / 'out', fetcher=store.get)
    report = json.loads((tmp_path / 'out' / 'report.json').read_text())
    assert report['provider_inputs']['status'] == 'not-gathered: debian-only scope'
    assert report['provider_inputs']['sources'] == lock['sources']
    assert report['provider_inputs']['patches'] == lock['patches']
    assert report['provider_inputs']['dependencies'] == ['build-essential']
