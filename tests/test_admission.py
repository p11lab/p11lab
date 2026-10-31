"""Admission rejects incomplete closure and verifies the bytes recipients receive."""
import hashlib
import json
from pathlib import Path
import tarfile
from dataclasses import asdict

import pytest

from p11lab.models import ArtifactRef
from p11lab import sources


def fixture_inventory(tmp_path):
    binary = tmp_path / 'binary.tar'
    import io
    with tarfile.open(binary, 'w') as tar:
        item = tarfile.TarInfo('demo.txt')
        item.size = 4
        tar.addfile(item, io.BytesIO(b'demo'))
    artifact = ArtifactRef('bundle', str(binary), hashlib.sha256(binary.read_bytes()).hexdigest(), 'linux/amd64')
    payloads = []
    for path, role, text in [('sources/demo.tar', 'source', 'complete source'), ('notices/demo.txt', 'notice', 'original grant'), ('BUILD.md', 'build', 'portable build instructions')]:
        local = tmp_path / Path(path).name
        local.write_text(text)
        payloads.append({'path': path, 'role': role, 'local_path': str(local), 'sha256': hashlib.sha256(local.read_bytes()).hexdigest(), 'size': local.stat().st_size})
    inventory = {'schema_version': 1, 'artifact': asdict(artifact), 'role': 'runtime',
        'observation': {'artifact': asdict(artifact), 'packages': [], 'binaries': [], 'linked_libraries': [], 'files': [{'path': '/demo.txt', 'sha256': hashlib.sha256(b'demo').hexdigest(), 'size': 4, 'mode': 420, 'package': None}]},
        'content_reviews': [{'path': '/demo.txt', 'sha256': hashlib.sha256(b'demo').hexdigest(), 'source': 'demo=1', 'status': 'reviewed'}],
        'sources': [{'id': 'demo=1', 'name': 'demo', 'version': '1', 'payloads': ['sources/demo.tar']}],
        'components': [{'id': 'demo=1', 'source': 'demo=1', 'scope': 'runtime'}],
        'reviews': [{'source': 'demo=1', 'status': 'reviewed', 'grant_known': True, 'source_redistribution': True,
                     'license_declared': 'MIT', 'license_concluded': 'MIT', 'chosen_route': 'retain grant and complete source',
                     'notices': ['notices/demo.txt'], 'grant_evidence': ['notices/demo.txt'], 'obligations': ['source', 'notice'], 'modifications': 'unmodified'}],
        'patches': [], 'payloads': payloads, 'build_instructions': 'BUILD.md', 'limitations': []}
    return artifact, inventory


def assemble(tmp_path):
    artifact, inventory = fixture_inventory(tmp_path)
    output = tmp_path / 'evidence'
    archive = sources.collect_source_bundle(artifact, inventory, output)
    return artifact, inventory, output, archive


def test_source_companion_is_portable_and_source_only(tmp_path):
    artifact, inventory, output, archive = assemble(tmp_path)
    with tarfile.open(archive) as contents:
        public = contents.extractfile('inventory.json').read().decode()
        assert str(tmp_path) not in public
        assert contents.extractfile('sources/demo.tar').read() == b'complete source'
        assert 'binary.tar' not in contents.getnames()
    assert sources.verify_source_bundle(archive, tmp_path / 'clean')['artifact']['sha256'] == artifact.sha256


def test_complete_evidence_is_eligible_but_never_publicly_authorized(tmp_path):
    from p11lab.licenses import assess_distribution
    artifact, inventory, output, archive = assemble(tmp_path)
    result = assess_distribution(artifact, output)
    assert result['status'] == 'eligible'
    assert result['publication_status'] == 'blocked'
    assert result['publication_blockers'] == ['anonymous-source-first delivery not verified']
    sbom = json.loads((output / 'sbom.spdx.json').read_text())
    assert sbom['spdxVersion'] == 'SPDX-2.3'
    assert sbom['packages'][0]['licenseConcluded'] == 'MIT'


@pytest.mark.parametrize('damage', ['source', 'notice', 'build', 'grant', 'patch', 'dependency', 'binary', 'changed-image', 'agpl'])
def test_incomplete_or_changed_evidence_refuses_admission(tmp_path, damage):
    artifact, inventory = fixture_inventory(tmp_path)
    if damage in {'source', 'notice', 'build'}:
        inventory['payloads'] = [p for p in inventory['payloads'] if p['role'] != damage]
    elif damage == 'grant':
        inventory['reviews'][0]['grant_known'] = False
    elif damage == 'patch':
        inventory['patches'] = [{'sha256': 'a' * 64, 'status': 'unreviewed'}]
    elif damage == 'dependency':
        inventory['observation']['linked_libraries'] = [{'binary': 'demo', 'needed': 'libmissing.so', 'resolved': []}]
    elif damage == 'binary':
        Path(artifact.reference).write_bytes(b'changed binary')
    elif damage == 'changed-image':
        inventory['artifact']['sha256'] = 'f' * 64
    elif damage == 'agpl':
        inventory['reviews'][0]['obligations'].append('agpl-remote-source')
    with pytest.raises(ValueError):
        sources.collect_source_bundle(artifact, inventory, tmp_path / 'evidence')


def test_changed_companion_bytes_block_existing_admission(tmp_path):
    from p11lab.licenses import assess_distribution
    artifact, inventory, output, archive = assemble(tmp_path)
    with archive.open('ab') as stream:
        stream.write(b'corruption')
    result = assess_distribution(artifact, output)
    assert result['status'] == 'blocked'
    assert any('checksum' in reason for reason in result['blockers'])


def test_forged_inventory_cannot_authorize_an_unrelated_digest(tmp_path):
    from p11lab.licenses import assess_distribution
    artifact, inventory, output, archive = assemble(tmp_path)
    changed = ArtifactRef(artifact.kind, artifact.reference, 'b' * 64, artifact.platform)
    assert assess_distribution(changed, output)['status'] == 'blocked'


def test_source_checksum_mismatch_refuses_collection(tmp_path):
    artifact, inventory = fixture_inventory(tmp_path)
    Path(inventory['payloads'][0]['local_path']).write_text('wrong source')
    with pytest.raises(ValueError, match='checksum|size'):
        sources.collect_source_bundle(artifact, inventory, tmp_path / 'evidence')


def test_unsafe_archive_cannot_escape_clean_extraction(tmp_path):
    import io
    archive = tmp_path / 'evil.tar'
    with tarfile.open(archive, 'w') as contents:
        item = tarfile.TarInfo('../outside')
        item.size = 1
        contents.addfile(item, io.BytesIO(b'x'))
    with pytest.raises(ValueError):
        sources.verify_source_bundle(archive, tmp_path / 'extract')
    assert not (tmp_path / 'outside').exists()


def test_real_sqv_static_metadata_requires_complete_source_roster(tmp_path):
    from p11lab.licenses import validate_inventory, parse_dpkg_status
    text = 'Package: sqv\nStatus: install ok installed\nVersion: 1.3.0-3+b2\nArchitecture: amd64\nSource: rust-sequoia-sqv (1.3.0-3)\nBuilt-Using: rust-nettle (= 7.3.0-1), rustc (= 1.85.0+dfsg3-1)\nStatic-Built-Using: rust-nettle (= 7.3.0-1), rust-clap (= 4.5.23-1)\n'
    packages = parse_dpkg_status(text)
    assert packages[0]['source_version'] == '1.3.0-3'
    assert packages[0]['incorporated_sources'] == ['rust-clap=4.5.23-1', 'rust-nettle=7.3.0-1', 'rustc=1.85.0+dfsg3-1']
    artifact, inventory = fixture_inventory(tmp_path)
    inventory['observation']['packages'] = packages
    reasons = validate_inventory(artifact, inventory)
    assert any('rustc=1.85.0+dfsg3-1' in reason for reason in reasons)
    assert any('rust-sequoia-sqv=1.3.0-3' in reason for reason in reasons)


def test_spdx_includes_actual_binary_and_incorporated_relationships(tmp_path):
    from p11lab.licenses import spdx_inventory
    artifact, inventory = fixture_inventory(tmp_path)
    inventory['observation']['packages'] = [{'name': 'demo-bin', 'version': '1+b2', 'architecture': 'amd64',
        'source_package': 'demo', 'source_version': '1', 'incorporated_sources': ['helper=2']}]
    inventory['sources'].append({'id': 'helper=2', 'name': 'helper', 'version': '2', 'payloads': []})
    inventory['reviews'].append({'source': 'helper=2', 'license_declared': 'MIT', 'license_concluded': 'NOASSERTION'})
    sbom = spdx_inventory(artifact, inventory)
    assert any(p['name'] == 'demo-bin' and p['versionInfo'] == '1+b2' for p in sbom['packages'])
    assert any(r['relationshipType'] == 'STATIC_LINK' for r in sbom['relationships'])
    assert any(r['relationshipType'] == 'GENERATED_FROM' for r in sbom['relationships'])
    assert next(p for p in sbom['packages'] if p['name'] == 'helper')['licenseConcluded'] == 'NOASSERTION'


def test_missing_reviewed_grant_file_blocks_despite_known_license_label(tmp_path):
    from p11lab.licenses import validate_inventory
    artifact, inventory = fixture_inventory(tmp_path)
    inventory['reviews'][0]['grant_evidence'] = ['notices/absent.txt']
    assert any('grant evidence' in reason for reason in validate_inventory(artifact, inventory))


def test_deleted_lower_layer_bytes_require_their_own_review(tmp_path):
    import io
    from p11lab.licenses import inspect_distribution_archive, validate_inventory
    layers = []
    for name, data in [('layer-a.tar', b'hidden unreviewed program'), ('layer-b.tar', b'')]:
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w') as tar:
            item = tarfile.TarInfo('secret' if data else '.wh.secret')
            item.size = len(data)
            tar.addfile(item, io.BytesIO(data))
        layers.append((name, stream.getvalue()))
    archive = tmp_path / 'image-save.tar'
    config = json.dumps({'architecture': 'amd64', 'os': 'linux', 'rootfs': {'type': 'layers', 'diff_ids': ['sha256:' + hashlib.sha256(data).hexdigest() for name, data in layers]}}).encode()
    with tarfile.open(archive, 'w') as tar:
        entries = layers + [('config.json', config), ('manifest.json', json.dumps([{'Config':'config.json','Layers':[n for n,d in layers]}]).encode())]
        for name, data in entries:
            item = tarfile.TarInfo(name)
            item.size = len(data)
            tar.addfile(item, io.BytesIO(data))
    distribution = inspect_distribution_archive(archive, [])
    assert distribution['hidden_layer_files'][0]['path'] == '/secret'
    assert distribution['whiteouts'] == ['/secret']
    artifact, inventory = fixture_inventory(tmp_path)
    inventory['observation']['distribution'] = distribution
    assert any('lower-layer' in reason for reason in validate_inventory(artifact, inventory))


def test_debian_dsc_requires_all_corresponding_payloads(tmp_path):
    artifact, inventory = fixture_inventory(tmp_path)
    dsc = tmp_path / 'demo.dsc'
    dsc.write_text('Format: 3.0 (quilt)\nSource: demo\nVersion: 1\nChecksums-Sha256:\n ' + '1'*64 + ' 12 demo.orig.tar.xz\n')
    inventory['payloads'][0] = {'path': 'sources/demo.dsc', 'local_path': str(dsc), 'role': 'source', 'size': dsc.stat().st_size, 'sha256': hashlib.sha256(dsc.read_bytes()).hexdigest()}
    inventory['sources'][0]['payloads'] = ['sources/demo.dsc']
    inventory['sources'][0]['format'] = 'debian'
    with pytest.raises(ValueError, match='Debian.*payload'):
        sources.collect_source_bundle(artifact, inventory, tmp_path / 'evidence')


def test_debug_admission_requires_exact_parent_relationship(tmp_path):
    from p11lab.licenses import validate_inventory
    artifact, inventory = fixture_inventory(tmp_path)
    inventory['role'] = 'debug-companion'
    assert any('debug' in reason and 'parent' in reason for reason in validate_inventory(artifact, inventory))


def test_unreviewed_copied_script_blocks_known_package_inventory(tmp_path):
    from p11lab.licenses import validate_inventory
    artifact, inventory = fixture_inventory(tmp_path)
    inventory['observation']['files'].append({'path': '/new-script', 'sha256': 'f'*64, 'package': None})
    assert any('/new-script' in reason for reason in validate_inventory(artifact, inventory))


def test_empty_deb822_field_does_not_append_conffiles_to_source_version():
    from p11lab.licenses import parse_dpkg_status
    packages = parse_dpkg_status('Package: libaudit-common\nStatus: install ok installed\nArchitecture: all\nSource: audit\nVersion: 1:4.0.2-2+deb13u1\nConffiles:\n /etc/libaudit.conf cdc703f9d27f0d980271a9e95d0f18b2\nDescription: library metadata\n')
    assert packages[0]['source_version'] == '1:4.0.2-2+deb13u1'


def test_outer_admission_and_companion_receipts_do_not_publish_acquisition_paths(tmp_path):
    from p11lab.licenses import assess_distribution
    artifact, inventory, output, archive = assemble(tmp_path)
    result = assess_distribution(artifact, output)
    receipt = json.loads((output/'source-companion.json').read_text())
    assert str(tmp_path) not in json.dumps(receipt)
    assert str(tmp_path) not in json.dumps(result)
    assert result['artifact']['reference'] == 'sha256:' + artifact.sha256


def test_source_id_binds_name_and_version(tmp_path):
    from p11lab.licenses import validate_inventory
    artifact, inventory = fixture_inventory(tmp_path)
    inventory['sources'][0].update(name='another', version='2')
    assert any('source identity mismatch' in r for r in validate_inventory(artifact, inventory))
    with pytest.raises(ValueError, match='source identity mismatch'):
        sources._verify_debian_source_sets(tmp_path, inventory)


def test_discovered_debian_source_cannot_drop_format(tmp_path):
    artifact, inventory = fixture_inventory(tmp_path)
    inventory['observation']['packages'] = [{'name': 'demo', 'source_package': 'demo', 'source_version': '1', 'incorporated_sources': []}]
    with pytest.raises(ValueError, match='Debian.*dsc'):
        sources._verify_debian_source_sets(tmp_path, inventory)


def elf_fixture(dynamic=True, renamed=False):
    import struct
    binary = bytearray(0x500)
    binary[:16] = b'\x7fELF\x02\x01\x01' + b'\0' * 9
    struct.pack_into('<HHIQQQIHHHHHH', binary, 16, 3, 62, 1, 0, 64 if dynamic else 0,
                     0x300 if dynamic else 0, 0, 64, 56, 2 if dynamic else 0, 64, 4 if dynamic else 0, 1 if dynamic else 0)
    if dynamic:
        struct.pack_into('<IIQQQQQQ', binary, 64, 1, 4, 0, 0x400000, 0, len(binary), len(binary), 4096)
        struct.pack_into('<IIQQQQQQ', binary, 120, 2, 4, 0x200, 0x400200, 0, 64, 64, 8)
        for i, (tag, value) in enumerate([(1, 1), (5, 0x400240), (10, 11), (0, 0)]):
            struct.pack_into('<QQ', binary, 0x200 + i * 16, tag, value)
        binary[0x240:0x24b] = b'\0libc.so.6\0'
        names = b'\0.shstrtab\0' + (b'.xynamic\0' if renamed else b'.dynamic\0') + b'.dynstr\0'
        binary[0x280:0x280 + len(names)] = names
        for i, h in enumerate([(0, 0, 0, 0, 0, 0), (1, 3, 0, 0, 0x280, len(names)),
                               (11, 6, 2, 0x400200, 0x200, 64), (20, 3, 2, 0x400240, 0x240, 11)]):
            struct.pack_into('<IIQQQQIIQQ', binary, 0x300 + i * 64, *h, 0, 0, 1, 0)
    return bytes(binary)


def test_loader_dynamic_dependencies_and_static_binary():
    from p11lab.licenses import _needed
    assert _needed(elf_fixture()) == ['libc.so.6']
    assert _needed(elf_fixture(dynamic=False)) == []


def test_renamed_dynamic_section_cannot_hide_loader_dependencies():
    from p11lab.licenses import _needed
    with pytest.raises(ValueError, match='ELF.*inconsistent'):
        _needed(elf_fixture(renamed=True))


def redirected_dynamic_offset():
    import struct
    binary = bytearray(elf_fixture())
    offset = len(binary)
    binary.extend(b'\0' * 64)
    struct.pack_into('<Q', binary, 120 + 8, offset)
    struct.pack_into('<Q', binary, 0x300 + 2 * 64 + 24, offset)
    return bytes(binary)


def test_dynamic_file_offset_must_match_loader_address_mapping():
    from p11lab.licenses import _needed
    with pytest.raises(ValueError, match='dynamic.*mapping'):
        _needed(redirected_dynamic_offset())


def test_file_backed_dynamic_segment_cannot_use_split_debug_exemption():
    import struct
    from p11lab.licenses import _needed
    binary = bytearray(elf_fixture())
    struct.pack_into('<Q', binary, 120 + 32, 0)
    struct.pack_into('<I', binary, 0x300 + 2 * 64 + 4, 8)
    with pytest.raises(ValueError, match='dynamic'):
        _needed(bytes(binary))


def test_collection_rejects_redirected_dynamic_offset(tmp_path, monkeypatch):
    from p11lab.licenses import inspect_artifact
    artifact, _ = mock_docker(monkeypatch, {'usr/bin/demo': redirected_dynamic_offset()})
    _, inventory = fixture_inventory(tmp_path)
    # On the vulnerable parser inspection succeeds and collection admits this
    # executable despite the missing libc used by its unchanged loader mapping.
    with pytest.raises(ValueError, match='dynamic.*mapping'):
        inventory.update(artifact=asdict(artifact), observation=inspect_artifact(artifact))
        inventory['components'] = [{'id': '/usr/bin/demo', 'source': 'demo=1'}]
        inventory['content_reviews'] = [{'path': f['path'], 'sha256': f['sha256'],
            'source': 'demo=1', 'status': 'reviewed'} for f in inventory['observation']['files']]
        sources.collect_source_bundle(artifact, inventory, tmp_path / 'evidence')


def tar_bytes(entries):
    import io
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w') as contents:
        for name, data in entries.items():
            member = tarfile.TarInfo(name)
            if isinstance(data, tuple):
                member.type, member.linkname = data
                contents.addfile(member)
            else:
                member.size = len(data)
                contents.addfile(member, io.BytesIO(data))
    return stream.getvalue()


def mock_docker(monkeypatch, entries, platform='linux/amd64'):
    from p11lab import licenses
    artifact = ArtifactRef('docker-local', 'sha256:' + 'a'*64, 'a'*64, 'linux/amd64')
    calls = []
    rootfs = tar_bytes(entries)
    layer = tar_bytes(entries)
    config = json.dumps({'os': 'linux', 'architecture': 'amd64', 'rootfs': {'type': 'layers', 'diff_ids': ['sha256:' + hashlib.sha256(layer).hexdigest()]}}).encode()
    descriptor_data = json.dumps({'schemaVersion': 2, 'config': {'digest': 'sha256:' + hashlib.sha256(config).hexdigest(), 'size': len(config)},
                                  'layers': [{'digest': 'sha256:' + hashlib.sha256(layer).hexdigest(), 'size': len(layer)}]}).encode()
    artifact = ArtifactRef('docker-local', 'sha256:' + hashlib.sha256(descriptor_data).hexdigest(), hashlib.sha256(descriptor_data).hexdigest(), 'linux/amd64')
    saved = tar_bytes({'config.json': config, 'layer.tar': layer, 'blobs/sha256/' + hashlib.sha256(config).hexdigest(): config,
        'blobs/sha256/' + hashlib.sha256(layer).hexdigest(): layer, 'blobs/sha256/' + artifact.sha256: descriptor_data,
        'manifest.json': json.dumps([{'Config': 'config.json', 'Layers': ['layer.tar']}]).encode()})
    def output(command, **kwargs):
        calls.append(command)
        if command[1:3] == ['image', 'inspect']:
            os_name, arch = platform.split('/')
            return json.dumps([{'Id': artifact.reference, 'Os': os_name, 'Architecture': arch, 'Descriptor': {'digest': artifact.reference, 'size': len(descriptor_data)}}])
        assert command[1] == 'create', command
        return 'owned-container\n'
    def run(command, **kwargs):
        calls.append(command)
        if command[1] == 'export':
            Path(command[command.index('--output') + 1]).write_bytes(rootfs)
        elif command[1:3] == ['image', 'save']:
            Path(command[command.index('--output') + 1]).write_bytes(saved)
        else:
            assert command == ['docker', 'rm', 'owned-container']
    monkeypatch.setattr(licenses.subprocess, 'check_output', output)
    monkeypatch.setattr(licenses.subprocess, 'run', run)
    return artifact, calls


@pytest.mark.parametrize('state', ['verified', 'modified', 'unverifiable'])
def test_installed_file_checksums_require_review_for_changed_bytes(tmp_path, monkeypatch, state):
    from p11lab.licenses import inspect_artifact, validate_inventory
    original, actual = b'original', b'changed' if state == 'modified' else b'original'
    entries = {'usr/bin/demo': actual, 'var/lib/dpkg/status': b'Package: demo\nVersion: 1\nArchitecture: amd64\nStatus: install ok installed\n',
               'var/lib/dpkg/info/demo.list': b'/usr/bin/demo\n'}
    if state != 'unverifiable':
        entries['var/lib/dpkg/info/demo.md5sums'] = (hashlib.md5(original).hexdigest() + '  usr/bin/demo\n').encode()
    artifact, calls = mock_docker(monkeypatch, entries)
    observation = inspect_artifact(artifact)
    file = next(f for f in observation['files'] if f['path'] == '/usr/bin/demo')
    assert file['package_verification']['status'] == state
    _, inventory = fixture_inventory(tmp_path)
    inventory.update(artifact=asdict(artifact), observation=observation)
    inventory['content_reviews'] = [{'path': f['path'], 'sha256': f['sha256'], 'source': 'demo=1', 'status': 'reviewed'}
                                   for f in observation['files'] if f['path'] != '/usr/bin/demo']
    reasons = validate_inventory(artifact, inventory)
    assert any('/usr/bin/demo' in r for r in reasons)
    inventory['content_reviews'].append({'path': file['path'], 'sha256': hashlib.sha256(original).hexdigest(), 'source': 'demo=1', 'status': 'reviewed'})
    assert any('/usr/bin/demo' in r for r in validate_inventory(artifact, inventory)) == (state == 'modified')
    inventory['content_reviews'][-1]['sha256'] = file['sha256']
    assert validate_inventory(artifact, inventory) == []
    assert all(c[1] != 'run' for c in calls)


def collision_pair():
    original = bytes.fromhex(
        'd131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f8955'
        'ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5bd88'
        '23e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0e99'
        'f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70')
    changed = bytearray(original)
    for offset in [19, 45, 59, 83, 109, 123]:
        changed[offset] ^= 128
    assert hashlib.md5(original).digest() == hashlib.md5(changed).digest()
    assert hashlib.sha256(original).digest() != hashlib.sha256(changed).digest()
    return original, bytes(changed)


def deb_bytes(control, files):
    result = b'!<arch>\n'
    for name, data in [('debian-binary', b'2.0\n'), ('control.tar', tar_bytes({'./control': control})),
                       ('data.tar', tar_bytes(files))]:
        header = f'{name + "/":<16}{0:<12}{0:<6}{0:<6}{"100644":<8}{len(data):<10}`\n'.encode()
        result += header + data + (b'\n' if len(data) % 2 else b'')
    return result


def package_inventory(tmp_path, monkeypatch, *, substituted=False):
    from p11lab.licenses import inspect_artifact
    original, changed = collision_pair()
    control = b'Package: demo\nVersion: 1\nArchitecture: amd64\n'
    entries = {'usr/share/demo/file': changed if substituted else original,
        'var/lib/dpkg/status': control + b'Status: install ok installed\n',
        'var/lib/dpkg/info/demo.list': b'/usr/share/demo/file\n',
        'var/lib/dpkg/info/demo.md5sums': (hashlib.md5(original).hexdigest() + '  usr/share/demo/file\n').encode()}
    artifact, _ = mock_docker(monkeypatch, entries)
    _, inventory = fixture_inventory(tmp_path)
    inventory.update(artifact=asdict(artifact), observation=inspect_artifact(artifact))
    inventory['content_reviews'] = [{'path': f['path'], 'sha256': f['sha256'],
        'source': 'demo=1', 'status': 'reviewed'} for f in inventory['observation']['files'] if f['path'] != '/usr/share/demo/file']
    source = tmp_path / 'demo.tar'
    source.write_bytes(tar_bytes({'demo-1/file': original}))
    inventory['payloads'][0].update(sha256=sources.checksum(source), size=source.stat().st_size)
    dsc = tmp_path / 'demo.dsc'
    dsc.write_text('Source: demo\nVersion: 1\nChecksums-Sha256:\n ' + sources.checksum(source) + ' ' + str(source.stat().st_size) + ' demo.tar\n')
    inventory['sources'][0]['payloads'].append('sources/demo.dsc')
    inventory['payloads'].append({'path': 'sources/demo.dsc', 'role': 'source', 'local_path': str(dsc),
        'sha256': sources.checksum(dsc), 'size': dsc.stat().st_size})
    deb = tmp_path / 'demo.deb'
    deb.write_bytes(deb_bytes(control, {'./usr/share/demo/file': original, './usr/share/demo/decoy': changed}))
    record = {'package': 'demo', 'version': '1', 'architecture': 'amd64', 'source': 'demo=1',
        'sha256': sources.checksum(deb), 'size': deb.stat().st_size, 'url': 'https://example.org/demo.deb'}
    evidence = tmp_path / 'package-selector.json'
    evidence.write_text(json.dumps(record))
    inventory['payloads'].append({'path': 'metadata/package-selector.json', 'role': 'metadata',
        'local_path': str(evidence), 'sha256': sources.checksum(evidence), 'size': evidence.stat().st_size})
    inventory['package_archives'] = [record | {'local_path': str(deb),
        'authentication': {'status': 'reviewed', 'evidence_path': 'metadata/package-selector.json'}}]
    inventory['package_files'] = [{'path': '/usr/share/demo/file', 'sha256': hashlib.sha256(original).hexdigest(),
        'package': 'demo', 'archive_sha256': record['sha256'], 'member': 'usr/share/demo/file'}]
    return artifact, inventory


@pytest.mark.parametrize('evidence', ['manifest-only', 'original-sha256', 'forged-sha256', 'wrong-member'])
def test_md5_collision_requires_authenticated_file_sha256(tmp_path, monkeypatch, evidence):
    artifact, inventory = package_inventory(tmp_path, monkeypatch, substituted=True)
    if evidence == 'manifest-only':
        inventory.pop('package_files')
        inventory.pop('package_archives')
    elif evidence in {'forged-sha256', 'wrong-member'}:
        inventory['package_files'][0]['sha256'] = hashlib.sha256(collision_pair()[1]).hexdigest()
        if evidence == 'wrong-member':
            inventory['package_files'][0]['member'] = 'usr/share/demo/decoy'
    with pytest.raises(ValueError, match='content|package'):
        sources.collect_source_bundle(artifact, inventory, tmp_path / 'evidence')


@pytest.mark.parametrize('damage', ['none', 'cache-bytes', 'selector', 'control-identity'])
def test_package_archive_is_reverified_by_collection_and_assessment(tmp_path, monkeypatch, damage):
    from p11lab.licenses import assess_distribution
    artifact, inventory = package_inventory(tmp_path, monkeypatch)
    if damage == 'selector':
        inventory['package_archives'][0]['version'] = '2'
    elif damage == 'control-identity':
        deb = Path(inventory['package_archives'][0]['local_path'])
        deb.write_bytes(deb_bytes(b'Package: another\nVersion: 1\nArchitecture: amd64\n',
            {'usr/share/demo/file': collision_pair()[0]}))
        record = inventory['package_archives'][0]
        record.update(sha256=sources.checksum(deb), size=deb.stat().st_size)
        inventory['package_files'][0]['archive_sha256'] = record['sha256']
        evidence = Path(inventory['payloads'][-1]['local_path'])
        evidence.write_text(json.dumps({k: record[k] for k in ['package', 'version', 'architecture', 'source', 'sha256', 'size', 'url']}))
        inventory['payloads'][-1].update(sha256=sources.checksum(evidence), size=evidence.stat().st_size)
    output = tmp_path / 'evidence'
    if damage in {'selector', 'control-identity'}:
        with pytest.raises(ValueError, match='package'):
            sources.collect_source_bundle(artifact, inventory, output)
        return
    archive = sources.collect_source_bundle(artifact, inventory, output)
    with tarfile.open(archive) as contents:
        assert not any(name.endswith('.deb') for name in contents.getnames())
        assert str(tmp_path) not in contents.extractfile('inventory.json').read().decode()
    if damage == 'cache-bytes':
        cache = output / 'package-cache' / (inventory['package_archives'][0]['sha256'] + '.deb')
        assert cache.is_file()
        cache.write_bytes(b'changed authenticated archive')
    result = assess_distribution(artifact, output)
    assert result['status'] == ('blocked' if damage == 'cache-bytes' else 'eligible'), result


def test_assessment_rejects_resealed_collision_with_forged_file_binding(tmp_path, monkeypatch):
    from p11lab import licenses
    artifact, inventory = package_inventory(tmp_path, monkeypatch)
    output = tmp_path / 'evidence'
    archive = sources.collect_source_bundle(artifact, inventory, output)
    changed = collision_pair()[1]
    entries = {'usr/share/demo/file': changed,
        'var/lib/dpkg/status': b'Package: demo\nVersion: 1\nArchitecture: amd64\nStatus: install ok installed\n',
        'var/lib/dpkg/info/demo.list': b'/usr/share/demo/file\n',
        'var/lib/dpkg/info/demo.md5sums': (hashlib.md5(changed).hexdigest() + '  usr/share/demo/file\n').encode()}
    substituted, _ = mock_docker(monkeypatch, entries)
    with tarfile.open(archive) as contents:
        retained = {m.name: contents.extractfile(m).read() for m in contents}
    public = json.loads(retained['inventory.json'])
    public.update(artifact=asdict(substituted), observation=licenses.inspect_artifact(substituted))
    public['package_files'][0]['sha256'] = hashlib.sha256(changed).hexdigest()
    retained['inventory.json'] = json.dumps(public).encode()
    retained['sbom.spdx.json'] = json.dumps(licenses.spdx_inventory(substituted, public)).encode()
    retained['SHA256SUMS'] = ''.join(hashlib.sha256(data).hexdigest() + '  ' + name + '\n'
        for name, data in sorted(retained.items()) if name != 'SHA256SUMS').encode()
    archive.write_bytes(tar_bytes(retained))
    (output / 'sbom.spdx.json').write_bytes(retained['sbom.spdx.json'])
    receipt_path = output / 'source-companion.json'
    receipt = json.loads(receipt_path.read_text())
    receipt.update(matched_artifact=public['artifact'], size_bytes=archive.stat().st_size,
        inventory_sha256=hashlib.sha256(retained['inventory.json']).hexdigest(),
        sbom_sha256=hashlib.sha256(retained['sbom.spdx.json']).hexdigest())
    receipt['artifact'].update(sha256=sources.checksum(archive), reference='sha256:' + sources.checksum(archive))
    receipt_path.write_text(json.dumps(receipt))
    result = licenses.assess_distribution(substituted, output)
    assert result['status'] == 'blocked'
    assert any('package file/member SHA256 mismatch' in r for r in result['blockers']), result


def test_package_ownership_alone_does_not_authorize_changed_content(tmp_path):
    from p11lab.licenses import validate_inventory
    artifact, inventory = fixture_inventory(tmp_path)
    file = inventory['observation']['files'][0]
    file.update(package='demo', sha256='f'*64)
    assert any('/demo.txt' in r for r in validate_inventory(artifact, inventory))


@pytest.mark.parametrize('bad', ['Built-Using: rustc (= 1)\nBuilt-Using:', 'Built-Using: rustc (= 1)\nbuilt-using:',
                               'bad line', 'Bad field: invalid'])
def test_malformed_dpkg_paragraph_cannot_erase_static_sources(bad):
    from p11lab.licenses import parse_dpkg_status
    with pytest.raises(ValueError, match='dpkg'):
        parse_dpkg_status('Package: demo\nStatus: install ok installed\nVersion: 1\nArchitecture: amd64\n' + bad + '\n')


def test_dpkg_orphan_continuation_is_rejected():
    from p11lab.licenses import parse_dpkg_status
    with pytest.raises(ValueError, match='dpkg'):
        parse_dpkg_status(' orphan\nPackage: demo\nStatus: install ok installed\nVersion: 1\nArchitecture: amd64\n')


@pytest.mark.parametrize('field', ['reference', 'platform', 'kind', 'inventory_sha256', 'payload_count', 'source_count', 'size_bytes', 'schema_version', 'role', 'source_rights', 'publication_status', 'boolean-schema', 'outer-spdx'])
def test_receipt_fields_bind_extracted_inventory_and_spdx(tmp_path, field):
    from p11lab.licenses import assess_distribution
    artifact, inventory, output, archive = assemble(tmp_path)
    receipt_path = output / 'source-companion.json'
    receipt = json.loads(receipt_path.read_text())
    if field in {'reference', 'platform', 'kind'}:
        receipt['artifact'][field] = 'incorrect'
    elif field == 'boolean-schema':
        receipt['schema_version'] = True
    elif field == 'outer-spdx':
        sbom = json.loads((output / 'sbom.spdx.json').read_text())
        sbom['packages'] = []
        (output / 'sbom.spdx.json').write_text(json.dumps(sbom))
        receipt['sbom_sha256'] = sources.checksum(output / 'sbom.spdx.json')
    else:
        receipt[field] = 0 if isinstance(receipt[field], int) else 'incorrect'
    receipt_path.write_text(json.dumps(receipt))
    assert assess_distribution(artifact, output)['status'] == 'blocked'


@pytest.fixture
def debug_bundle(tmp_path):
    import subprocess
    from p11lab.catalog import packaged_asset
    from p11lab.debug import verify_debug_files
    original = tmp_path / 'original'
    original.mkdir()
    code = tmp_path / 'demo.c'
    code.write_text('int main(void) { return 0; }')
    names = ['libsofthsm2.so', 'softhsm2-util']
    for name in names:
        subprocess.run(['gcc', '-g', '-Wl,--build-id', str(code), '-o', str(original / name)], check=True)
    subprocess.run(['sh', str(packaged_asset('softhsm2', 'split-debug.sh')), str(original), str(tmp_path / 'shipped'), str(tmp_path / 'debug'), *names], check=True)
    runtime = {name: (tmp_path / 'shipped' / name).read_bytes() for name in names}
    records = verify_debug_files(tmp_path / 'debug', runtime)
    return runtime, records, {f.name: f.read_bytes() for f in (tmp_path / 'debug').iterdir()}


@pytest.mark.parametrize('changed', [False, True])
def test_debug_inspection_binds_inert_parent_bytes(tmp_path, monkeypatch, debug_bundle, changed):
    from p11lab import licenses
    runtime, records, retained = debug_bundle
    entries = {path: runtime[name] + (b'wrong' if changed else b'') for name, path in
               [('libsofthsm2.so', 'usr/local/lib/p11lab/libsofthsm2.so'), ('softhsm2-util', 'usr/local/bin/softhsm2-util')]}
    parent, calls = mock_docker(monkeypatch, entries)
    transport = licenses.subprocess.check_output
    def output(command, **kwargs):
        # Hostile image code offers the certifiable bytes instead of shipped bytes.
        if command[1] == 'run':
            calls.append(command)
            return runtime[Path(command[-1]).name]
        return transport(command, **kwargs)
    monkeypatch.setattr(licenses.subprocess, 'check_output', output)
    retained['provenance.json'] = json.dumps({'role': 'debug-companion', 'matched_runtime': asdict(parent), 'binaries': records}).encode()
    archive = tmp_path / 'debug.tar'
    archive.write_bytes(tar_bytes(retained))
    artifact = ArtifactRef('bundle', str(archive), sources.checksum(archive), parent.platform)
    if changed:
        with pytest.raises(ValueError, match='hash|parent'):
            licenses.inspect_artifact(artifact)
    else:
        assert licenses.inspect_artifact(artifact)['debug_relationship']['binaries'] == records
    assert all(c[1] != 'run' for c in calls)


def saved_image(tmp_path, damage=None, compressed=False):
    import gzip
    layer_raw = tar_bytes({'file': b'content'})
    layer = gzip.compress(layer_raw) if compressed else layer_raw
    config = {'os': 'linux', 'architecture': 'amd64', 'rootfs': {'type': 'layers', 'diff_ids': ['sha256:' + hashlib.sha256(layer_raw).hexdigest()]}}
    if damage == 'omitted-layer':
        config['rootfs']['diff_ids'].append('sha256:' + 'f'*64)
    if damage == 'diff-id':
        config['rootfs']['diff_ids'][0] = 'sha256:' + 'f'*64
    config_bytes = json.dumps(config).encode()
    config_sha, layer_sha = hashlib.sha256(config_bytes).hexdigest(), hashlib.sha256(layer).hexdigest()
    descriptor = {'schemaVersion': 2, 'config': {'digest': 'sha256:' + config_sha, 'size': len(config_bytes)},
                  'layers': [{'digest': 'sha256:' + layer_sha, 'size': len(layer)}]}
    if damage == 'descriptor-size':
        descriptor['layers'][0]['size'] += 1
    if damage == 'descriptor-config':
        descriptor['config']['digest'] = 'sha256:' + layer_sha
        descriptor['config']['size'] = len(layer)
    if damage == 'descriptor-layers':
        descriptor['layers'] = []
    descriptor_bytes = json.dumps(descriptor).encode()
    descriptor_sha = hashlib.sha256(descriptor_bytes).hexdigest()
    entries = {'blobs/sha256/' + config_sha: config_bytes, 'blobs/sha256/' + layer_sha: layer,
               'blobs/sha256/' + descriptor_sha: descriptor_bytes,
               'index.json': json.dumps({'schemaVersion': 2, 'manifests': [{'digest': 'sha256:' + descriptor_sha, 'size': len(descriptor_bytes)}]}).encode(),
               'manifest.json': json.dumps([{'Config': 'blobs/sha256/' + config_sha, 'Layers': ['blobs/sha256/' + layer_sha]}]).encode()}
    archive = tmp_path / 'save.tar'
    archive.write_bytes(tar_bytes(entries))
    return archive


@pytest.mark.parametrize('damage', ['omitted-layer', 'diff-id', 'descriptor-size', 'descriptor-config', 'descriptor-layers'])
def test_saved_image_rejects_inconsistent_config_layer_graph(tmp_path, damage):
    from p11lab.licenses import inspect_distribution_archive
    with pytest.raises(ValueError, match='layer|descriptor|graph'):
        inspect_distribution_archive(saved_image(tmp_path, damage), [])


def test_compressed_layer_diff_id_uses_uncompressed_bytes(tmp_path):
    from p11lab.licenses import inspect_distribution_archive
    archive = saved_image(tmp_path, compressed=True)
    assert len(inspect_distribution_archive(archive, [])['layers']) == 1


@pytest.mark.parametrize('damage', ['sha256', 'provenance', 'changed_behavior', 'bytes'])
def test_patch_review_binds_hash_provenance_and_behavior(tmp_path, damage):
    artifact, inventory = fixture_inventory(tmp_path)
    payload = inventory['payloads'][0]
    patch = {'path': payload['path'], 'sha256': payload['sha256'], 'license': 'MIT', 'status': 'reviewed',
             'provenance': 'Original patch against demo=1', 'changed_behavior': 'Provisioning change, no PKCS#11 semantic change'}
    inventory['patches'] = [patch]
    if damage == 'sha256':
        patch['sha256'] = 'f'*64
    elif damage == 'bytes':
        Path(payload['local_path']).write_bytes(b'changed patch')
    else:
        patch.pop(damage)
    with pytest.raises(ValueError, match='patch|payload'):
        sources.collect_source_bundle(artifact, inventory, tmp_path / 'evidence')


def test_complete_ordered_patch_review_is_retained(tmp_path):
    artifact, inventory = fixture_inventory(tmp_path)
    payload = inventory['payloads'][0]
    inventory['patches'] = [{'path': payload['path'], 'sha256': payload['sha256'], 'license': 'MIT', 'status': 'reviewed',
                             'provenance': 'Original demo=1 patch', 'changed_behavior': 'Provisioning only'}]
    archive = sources.collect_source_bundle(artifact, inventory, tmp_path / 'evidence')
    assert sources.verify_source_bundle(archive, tmp_path / 'clean')['patches'] == inventory['patches']


def test_distribution_archive_records_measured_archive_bytes(tmp_path):
    from p11lab.licenses import inspect_distribution_archive
    archive = saved_image(tmp_path, compressed=True)
    distribution = inspect_distribution_archive(archive, [])
    assert distribution['archive_size_bytes'] == archive.stat().st_size
    assert 'archive' in distribution['measurement']


@pytest.mark.parametrize('kind', ['duplicate', 'symlink', 'hardlink'])
@pytest.mark.parametrize('operation', ['source', 'binary'])
def test_source_and_binary_bundles_reject_duplicate_or_link_members(tmp_path, kind, operation):
    import io
    from p11lab.licenses import inspect_artifact
    archive = tmp_path / 'unsafe.tar'
    with tarfile.open(archive, 'w') as contents:
        item = tarfile.TarInfo('file')
        item.size = 1
        contents.addfile(item, io.BytesIO(b'x'))
        item = tarfile.TarInfo('file' if kind == 'duplicate' else 'alias')
        if kind == 'duplicate':
            item.size = 1
            contents.addfile(item, io.BytesIO(b'y'))
        else:
            item.type = tarfile.SYMTYPE if kind == 'symlink' else tarfile.LNKTYPE
            item.linkname = 'file'
            contents.addfile(item)
    with pytest.raises(ValueError, match='duplicate|unsafe|unsupported'):
        if operation == 'source':
            sources.verify_source_bundle(archive, tmp_path / 'clean')
        else:
            inspect_artifact(ArtifactRef('bundle', str(archive), sources.checksum(archive), 'linux/amd64'))


@pytest.mark.parametrize('damage', ['checksum', 'roster', 'duplicate-manifest', 'payload-size'])
def test_companion_manifest_integrity_boundaries(tmp_path, damage):
    artifact, inventory, output, archive = assemble(tmp_path)
    with tarfile.open(archive) as contents:
        entries = {m.name: contents.extractfile(m).read() for m in contents}
    if damage == 'checksum':
        entries['BUILD.md'] += b'changed'
    elif damage == 'roster':
        entries['undeclared'] = b'new'
    elif damage == 'duplicate-manifest':
        entries['SHA256SUMS'] += entries['SHA256SUMS'].splitlines(keepends=True)[0]
    else:
        inv = json.loads(entries['inventory.json'])
        inv['payloads'][0]['size'] += 1
        entries['inventory.json'] = json.dumps(inv).encode()
        entries['SHA256SUMS'] = ''.join(hashlib.sha256(data).hexdigest() + '  ' + name + '\n' for name, data in entries.items() if name != 'SHA256SUMS').encode()
    archive.write_bytes(tar_bytes(entries))
    with pytest.raises(ValueError, match='checksum|roster|duplicate|manifest'):
        sources.verify_source_bundle(archive, tmp_path / 'clean')


def test_docker_local_inspection_resolves_links_and_never_runs_image(monkeypatch):
    from p11lab.licenses import inspect_artifact
    artifact, calls = mock_docker(monkeypatch, {'usr/bin/app': elf_fixture(), 'usr/lib/real-libc': elf_fixture(dynamic=False),
        'usr/lib/libc.so.6': (tarfile.SYMTYPE, 'real-libc'), 'usr/lib/hard-libc': (tarfile.LNKTYPE, 'usr/lib/real-libc')})
    observation = inspect_artifact(artifact)
    assert observation['linked_libraries'] == [{'binary': '/usr/bin/app', 'needed': 'libc.so.6', 'resolved': ['/usr/lib/real-libc']}]
    assert ['docker', 'rm', 'owned-container'] in calls
    assert all(c[1] not in {'run', 'start', 'exec'} for c in calls)


def test_docker_local_inspection_rejects_wrong_platform(monkeypatch):
    from p11lab.licenses import inspect_artifact
    artifact, calls = mock_docker(monkeypatch, {'file': b'content'}, platform='linux/arm64')
    with pytest.raises(ValueError, match='platform'):
        inspect_artifact(artifact)
    assert len(calls) == 1


def test_docker_export_failure_removes_only_owned_container(monkeypatch):
    import subprocess
    from p11lab import licenses
    artifact, calls = mock_docker(monkeypatch, {'file': b'content'})
    transport = licenses.subprocess.run
    def run(command, **kwargs):
        if command[1] == 'export':
            raise subprocess.CalledProcessError(1, command)
        return transport(command, **kwargs)
    monkeypatch.setattr(licenses.subprocess, 'run', run)
    with pytest.raises(ValueError, match='inspection failed'):
        licenses.inspect_artifact(artifact)
    assert calls[-1] == ['docker', 'rm', 'owned-container']


def test_docker_mount_observation_uses_distributed_bytes(monkeypatch):
    from p11lab import licenses
    artifact, calls = mock_docker(monkeypatch, {'etc/hosts': b'distributed'})
    transport = licenses.subprocess.run
    def run(command, **kwargs):
        result = transport(command, **kwargs)
        if command[1] == 'export':
            Path(command[command.index('--output') + 1]).write_bytes(tar_bytes({'etc/hosts': b'engine-injected'}))
        return result
    monkeypatch.setattr(licenses.subprocess, 'run', run)
    observation = licenses.inspect_artifact(artifact)
    assert observation['files'][0]['sha256'] == hashlib.sha256(b'distributed').hexdigest()
    assert observation['distribution']['hidden_layer_files'] == []


def test_changed_package_manifest_cannot_reuse_old_content_review(tmp_path):
    from p11lab.licenses import validate_inventory
    artifact, inventory = fixture_inventory(tmp_path)
    inventory['observation']['files'][0].update(package='demo', package_verification={
        'status': 'verified', 'expected_md5': 'a'*32, 'actual_md5': 'a'*32,
        'manifest_path': '/var/lib/dpkg/info/demo.md5sums', 'manifest_sha256': 'f'*64})
    inventory['content_reviews'] = [{'path': '/var/lib/dpkg/info/demo.md5sums', 'sha256': 'e'*64, 'status': 'reviewed', 'source': 'demo=1'}]
    assert any('/demo.txt' in r for r in validate_inventory(artifact, inventory))


@pytest.mark.parametrize('case', ['credentials', 'http', 'redirect-http', 'redirect-credentials', 'overflow', 'short', 'checksum', 'bound', 'success'])
def test_source_acquisition_https_and_byte_boundaries(tmp_path, monkeypatch, case):
    import io
    data = b'payload'
    destination = tmp_path / 'payload'
    record = {'path': 'source', 'url': 'https://example.org/source', 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
    if case == 'credentials':
        record['url'] = 'https://user:secret@example.org/source'
    if case == 'http':
        record['url'] = 'http://example.org/source'
    if case == 'bound':
        record['size'] = 1024**3 + 1
    if case == 'checksum':
        record['sha256'] = 'f'*64
    response = io.BytesIO(data + b'extra' if case == 'overflow' else data[:-1] if case == 'short' else data)
    response.geturl = lambda: 'http://example.org/redirect' if case == 'redirect-http' else 'https://user:secret@example.org/redirect' if case == 'redirect-credentials' else record['url']
    monkeypatch.setattr(sources, 'urlopen', lambda *args, **kwargs: response)
    if case == 'success':
        sources._payload_copy(record, destination)
        assert destination.read_bytes() == data
    else:
        with pytest.raises(ValueError):
            sources._payload_copy(record, destination)


@pytest.fixture(scope='module')
def installed_admission(tmp_path_factory):
    import os
    import subprocess
    root = tmp_path_factory.mktemp('installed admission with spaces')
    wheel_dir, venv = root / 'wheels', root / 'venv'
    subprocess.run(['uv', 'build', '--wheel', '--out-dir', str(wheel_dir), str(Path(__file__).resolve().parents[1])], check=True, capture_output=True)
    subprocess.run(['uv', 'venv', str(venv)], check=True, capture_output=True)
    python = venv / 'bin/python'
    subprocess.run(['uv', 'pip', 'install', '--python', str(python), str(next(wheel_dir.glob('*.whl')))], check=True, capture_output=True)
    env = {k: v for k, v in os.environ.items() if k not in {'PYTHONPATH', 'PYTHONHOME'}}
    caller = root / 'outside checkout'
    caller.mkdir()
    return python, caller, env


def test_installed_admission_cli_all_operations_and_blocking_status(tmp_path, installed_admission):
    import subprocess
    python, caller, env = installed_admission
    artifact, inventory = fixture_inventory(tmp_path)
    artifact_json, inventory_json = tmp_path / 'artifact.json', tmp_path / 'inventory.json'
    artifact_json.write_text(json.dumps(asdict(artifact)))
    inventory_json.write_text(json.dumps(inventory))
    def cli(operation, *args):
        return subprocess.run([str(python), '-m', 'p11lab.licenses', operation, *map(str, args)], cwd=caller, env=env, capture_output=True, text=True)
    result = cli('inspect', '--artifact', artifact_json, '--output-dir', tmp_path / 'observed')
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == inventory['observation']
    evidence = tmp_path / 'evidence'
    result = cli('collect', '--artifact', artifact_json, '--inventory', inventory_json, '--output-dir', evidence)
    assert result.returncode == 0, result.stderr
    result = cli('verify', '--archive', evidence / 'source-companion.tar.gz', '--output-dir', tmp_path / 'clean')
    assert result.returncode == 0, result.stderr
    result = cli('assess', '--artifact', artifact_json, '--output-dir', evidence)
    assert result.returncode == 0 and json.loads(result.stdout)['status'] == 'eligible', result.stderr
    receipt = json.loads((evidence / 'source-companion.json').read_text())
    receipt['size_bytes'] = 0
    (evidence / 'source-companion.json').write_text(json.dumps(receipt))
    result = cli('assess', '--artifact', artifact_json, '--output-dir', evidence)
    assert result.returncode == 2 and json.loads(result.stdout)['status'] == 'blocked'
    Path(artifact.reference).write_bytes(b'changed')
    result = cli('inspect', '--artifact', artifact_json, '--output-dir', tmp_path / 'invalid')
    assert result.returncode == 2 and 'checksum' in result.stderr and 'Traceback' not in result.stderr


@pytest.mark.parametrize('damage', ['digest', 'size'])
def test_local_engine_descriptor_binds_saved_graph(monkeypatch, damage):
    from p11lab import licenses
    artifact, _ = mock_docker(monkeypatch, {'file': b'content'})
    transport = licenses.subprocess.check_output
    def output(command, **kwargs):
        result = transport(command, **kwargs)
        if command[1:3] == ['image', 'inspect']:
            inspected = json.loads(result)
            inspected[0]['Descriptor'][damage] = 'sha256:' + 'f'*64 if damage == 'digest' else 0
            return json.dumps(inspected)
        return result
    monkeypatch.setattr(licenses.subprocess, 'check_output', output)
    with pytest.raises(ValueError, match='descriptor'):
        licenses.inspect_artifact(artifact)


@pytest.mark.parametrize('connected', [False, True])
@pytest.mark.parametrize('depth', [0, 1])
def test_engine_root_must_reach_selected_image_graph(tmp_path, monkeypatch, connected, depth):
    from p11lab import licenses
    selected, _ = mock_docker(monkeypatch, {'file': b'content'})
    get, run = licenses.subprocess.check_output, licenses.subprocess.run
    descriptor = json.loads(get(['docker', 'image', 'inspect', selected.reference]))[0]['Descriptor']
    child = json.dumps({'schemaVersion': 2, 'manifests': [descriptor] if connected else []}).encode()
    child_ref = {'digest': 'sha256:' + hashlib.sha256(child).hexdigest(), 'size': len(child)}
    root = child if depth == 0 else json.dumps({'schemaVersion': 2, 'manifests': [child_ref]}).encode()
    digest = hashlib.sha256(root).hexdigest()
    artifact = ArtifactRef('docker-local', 'sha256:' + digest, digest, 'linux/amd64')
    def output(command, **kwargs):
        answer = get(command, **kwargs)
        if command[1:3] == ['image', 'inspect']:
            observed = json.loads(answer)
            observed[0].update(Id=artifact.reference, Descriptor={'digest': artifact.reference, 'size': len(root)})
            return json.dumps(observed)
        return answer
    def transport(command, **kwargs):
        answer = run(command, **kwargs)
        if command[1:3] == ['image', 'save']:
            destination = Path(command[command.index('--output') + 1])
            with tarfile.open(destination) as saved:
                entries = {m.name: saved.extractfile(m).read() for m in saved}
            entries.update({'blobs/sha256/' + digest: root,
                'blobs/sha256/' + child_ref['digest'].removeprefix('sha256:'): child,
                'index.json': json.dumps({'schemaVersion': 2, 'manifests': [{'digest': artifact.reference, 'size': len(root)}]}).encode()})
            destination.write_bytes(tar_bytes(entries))
        return answer
    monkeypatch.setattr(licenses.subprocess, 'check_output', output)
    monkeypatch.setattr(licenses.subprocess, 'run', transport)
    def collect_and_assess():
        observation = licenses.inspect_artifact(artifact)
        _, inventory = fixture_inventory(tmp_path)
        inventory.update(artifact=asdict(artifact), observation=observation)
        inventory['content_reviews'] = [{'path': f['path'], 'sha256': f['sha256'], 'source': 'demo=1', 'status': 'reviewed'} for f in observation['files']]
        sources.collect_source_bundle(artifact, inventory, tmp_path / 'evidence')
        return licenses.assess_distribution(artifact, tmp_path / 'evidence')
    if connected:
        assert collect_and_assess()['status'] == 'eligible'
    else:
        with pytest.raises(ValueError, match='root.*reach'):
            collect_and_assess()


def test_debug_parent_reexport_must_equal_inspected_hashes(tmp_path, monkeypatch, debug_bundle):
    from p11lab import licenses
    runtime, records, retained = debug_bundle
    paths = [('libsofthsm2.so', 'usr/local/lib/p11lab/libsofthsm2.so'), ('softhsm2-util', 'usr/local/bin/softhsm2-util')]
    parent, _ = mock_docker(monkeypatch, {path: runtime[name] for name, path in paths})
    transport, exports = licenses.subprocess.run, []
    def run(command, **kwargs):
        result = transport(command, **kwargs)
        if command[1] == 'export':
            exports.append(command)
            if len(exports) == 2:
                Path(command[command.index('--output') + 1]).write_bytes(tar_bytes({path: runtime[name] + b'changed' for name, path in paths}))
        return result
    monkeypatch.setattr(licenses.subprocess, 'run', run)
    retained['provenance.json'] = json.dumps({'role': 'debug-companion', 'matched_runtime': asdict(parent), 'binaries': records}).encode()
    archive = tmp_path / 'debug.tar'
    archive.write_bytes(tar_bytes(retained))
    with pytest.raises(ValueError, match='parent byte identity'):
        licenses.inspect_artifact(ArtifactRef('bundle', str(archive), sources.checksum(archive), parent.platform))


@pytest.mark.parametrize('damage', ['dynamic-bounds', 'string-bounds', 'string-section', 'unterminated'])
def test_loader_metadata_bounds_fail_closed(damage):
    import struct
    from p11lab.licenses import _needed
    binary = bytearray(elf_fixture())
    if damage == 'dynamic-bounds':
        struct.pack_into('<Q', binary, 120 + 32, len(binary))
    elif damage == 'string-bounds':
        struct.pack_into('<Q', binary, 0x200 + 24, 0x800000)
    elif damage == 'string-section':
        struct.pack_into('<Q', binary, 0x300 + 3*64 + 24, 0x241)
    else:
        struct.pack_into('<QQ', binary, 0x230, 1, 1)
    with pytest.raises(ValueError, match='ELF'):
        _needed(binary)


def test_rootfs_link_before_regular_file_uses_no_stale_content(monkeypatch):
    from p11lab.licenses import inspect_artifact
    artifact, _ = mock_docker(monkeypatch, {'alias': (tarfile.SYMTYPE, 'file'), 'file': b'content'})
    assert inspect_artifact(artifact)['files'][0]['link'] == 'file'


@pytest.mark.parametrize('member', ['inventory.json', 'sbom.spdx.json'])
@pytest.mark.parametrize('damage', ['duplicate', 'nested-duplicate', 'NaN', 'Infinity', '-Infinity', '1e999'])
def test_rehashed_inner_json_ambiguity_blocks_local_assessment(tmp_path, member, damage):
    import shutil
    from p11lab.licenses import assess_distribution
    from test_source_delivery import content_fixture, rewrite_content, malformed_inner_json
    args = content_fixture(tmp_path)
    rewrite_content(args, lambda files: malformed_inner_json(files, member, damage, args['artifact']))
    evidence = args['expected_receipt_path'].parent
    for name in ('source-companion.tar.gz', 'source-companion.json', 'sbom.spdx.json'):
        shutil.copyfile(args['pulled_dir'] / name, evidence / name)
    result = assess_distribution(args['artifact'], evidence)
    assert result['status'] == 'blocked'
    assert any('duplicate' in reason or 'nonfinite' in reason for reason in result['blockers'])
    assert result['publication_status'] == 'blocked'


def test_collection_and_assessment_forward_bounded_inspection_policy(tmp_path, monkeypatch):
    """Delivery callers can require the supervised inspector in both passes."""
    from p11lab import licenses
    from p11lab.inspection_bounded import InspectionPolicy

    artifact, inventory = fixture_inventory(tmp_path)
    policy = InspectionPolicy(max_bytes=1048576, timeout_seconds=3)
    journals = [tmp_path / 'collection-journal.json', tmp_path / 'assessment-journal.json']
    calls = []

    def inspected(candidate, *, inspection_policy, journal_path):
        assert candidate == artifact
        calls.append((inspection_policy, journal_path))
        return inventory['observation']

    monkeypatch.setattr(licenses, 'inspect_artifact', inspected)
    evidence = tmp_path / 'evidence'
    sources.collect_source_bundle(artifact, inventory, evidence,
                                  inspection_policy=policy, journal_path=journals[0])
    result = licenses.assess_distribution(artifact, evidence,
                                          inspection_policy=policy, journal_path=journals[1])
    assert result['status'] == 'eligible'
    assert calls == [(policy, journals[0]), (policy, journals[1])]


def test_assess_admission_record_matches_returned_bytes(tmp_path):
    """Forensic fidelity: admission.json bytes equal the serialized verdict."""
    from p11lab.licenses import assess_distribution
    artifact, inventory, output, archive = assemble(tmp_path)
    result = assess_distribution(artifact, output)
    assert result['status'] == 'eligible'
    expected = (json.dumps(result, sort_keys=True, indent=2) + '\n').encode()
    assert (output / 'admission.json').read_bytes() == expected


def test_assess_admission_overwrite_is_deterministic(tmp_path):
    """Second sequential call with same inputs writes identical bytes."""
    from p11lab.licenses import assess_distribution
    artifact, inventory, output, archive = assemble(tmp_path)
    first = assess_distribution(artifact, output)
    before = (output / 'admission.json').read_bytes()
    second = assess_distribution(artifact, output)
    assert second == first
    assert (output / 'admission.json').read_bytes() == before


def test_assess_missing_dir_returns_blocked_and_records_verdict(tmp_path):
    """Missing dir: blocked naming the missing companion, verdict recorded."""
    from p11lab.licenses import assess_distribution
    artifact, inventory = fixture_inventory(tmp_path)
    missing = tmp_path / 'absent' / 'evidence'
    assert not missing.exists()
    result = assess_distribution(artifact, missing)  # must not raise
    assert result['status'] == 'blocked'
    assert any('source-companion.json' in reason for reason in result['blockers'])
    expected = (json.dumps(result, sort_keys=True, indent=2) + '\n').encode()
    assert (missing / 'admission.json').read_bytes() == expected
