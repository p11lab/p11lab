"""Offline fixed-tool closure contracts; no provider or network required."""
import importlib
import io
import json
import os
import stat
import struct
import tarfile

import pytest


@pytest.mark.parametrize('mask', [0o022, 0o007, 0o077])
def test_owned_public_stage_is_readable_without_changing_private_inputs(tmp_path, mask):
    import hashlib
    private = tmp_path / 'private'
    private.mkdir(mode=0o700)
    source = private / 'source'
    source.write_bytes(b'private original')
    source.chmod(0o600)
    before = (stat.S_IMODE(private.stat().st_mode), stat.S_IMODE(source.stat().st_mode),
              hashlib.sha256(source.read_bytes()).hexdigest())
    old = os.umask(mask)
    try:
        staged = private / 'staged'
        (staged / 'nested').mkdir(parents=True)
        (staged / 'nested' / 'data').write_bytes(b'data')
        executable = staged / 'nested' / 'executable'
        executable.write_bytes(b'executable')
        executable.chmod(0o700)
        api()._prepare_public_stage(staged)
        launcher = private / 'launcher.pl'
        api()._write_launcher(launcher)
    finally:
        os.umask(old)
    assert [stat.S_IMODE(p.stat().st_mode) for p in (staged, staged / 'nested')] == [0o755, 0o755]
    assert stat.S_IMODE((staged / 'nested' / 'data').stat().st_mode) == 0o644
    assert stat.S_IMODE(executable.stat().st_mode) == 0o755
    assert stat.S_IMODE(launcher.stat().st_mode) == 0o644
    context = api().context_identity(staged)
    assert context['root_mode'] == 0o755
    assert context['directories'] == [{'path': 'nested', 'mode': 0o755}]
    assert {f['path']: f['mode'] for f in context['files']} == {
        'nested/data': 0o644, 'nested/executable': 0o755}
    assert api().context_identity(launcher)['files'][0]['mode'] == 0o644
    assert (stat.S_IMODE(private.stat().st_mode), stat.S_IMODE(source.stat().st_mode),
            hashlib.sha256(source.read_bytes()).hexdigest()) == before
    assert (staged / 'nested' / 'data').read_bytes() == b'data'


@pytest.mark.parametrize('kind', ['symlink', 'fifo'])
def test_public_stage_rejects_nonregular_entries_before_chmod(tmp_path, kind):
    staged = tmp_path / 'staged'
    staged.mkdir(mode=0o700)
    entry = staged / 'bad'
    if kind == 'symlink':
        entry.symlink_to(tmp_path)
    else:
        os.mkfifo(entry)
    with pytest.raises(ValueError, match='stage'):
        api()._prepare_public_stage(staged)
    assert stat.S_IMODE(staged.stat().st_mode) == 0o700


def api():
    return importlib.import_module('p11lab.tool_builds')


@pytest.mark.parametrize('mask', [0o007, 0o077])
def test_oracle_controls_direct_bind_readable_to_unprivileged_user(tmp_path, mask):
    from p11lab.catalog import package_data
    private = tmp_path / 'private'
    private.mkdir(mode=0o700)
    cached = private / 'cached'
    cached.write_bytes(b'private input')
    cached.chmod(0o600)
    source = package_data('tool-builds/oracle-controls.py')
    before = (private.stat().st_mode, cached.stat().st_mode, cached.read_bytes(), source.read_bytes())
    controls = {'positive': {'returncode': 0}, 'altered_message': {'returncode': 1},
                'altered_signature': {'returncode': 1}}

    class Attempt:
        result = {'stages': []}

        def run(self, image, argv, *, user, mounts, environment):
            script = private / 'oracle-controls.py'
            assert image == 'selected-image'
            assert argv == ['/usr/bin/python3.13', '-I', '-B', '/controls.py']
            assert user == '65532:65532'
            assert mounts == [f'type=bind,src={script},dst=/controls.py,readonly']
            assert environment == {'LC_ALL': 'C'}
            assert stat.S_IMODE(script.stat().st_mode) == 0o644
            assert script.read_bytes() == before[3]
            self.result['stages'].append({'native': {'stdout': json.dumps(controls)}})

    attempt = Attempt()
    old = os.umask(mask)
    try:
        api()._oracle_controls(attempt, 'selected-image', private, {'execution': {'environment': {'LC_ALL': 'C'}}})
    finally:
        os.umask(old)
    assert attempt.result['oracle_controls'] == controls
    assert (private.stat().st_mode, cached.stat().st_mode, cached.read_bytes(), source.read_bytes()) == before


@pytest.mark.parametrize('positive,message,signature', [(1, 1, 1), (0, 0, 1), (0, 1, 0)])
def test_oracle_controls_reject_invalid_native_control_results(tmp_path, positive, message, signature):
    class Attempt:
        result = {'stages': []}

        def run(self, *args, **kwargs):
            self.result['stages'].append({'native': {'stdout': json.dumps({
                'positive': {'returncode': positive}, 'altered_message': {'returncode': message},
                'altered_signature': {'returncode': signature}})}})

    with pytest.raises(ValueError, match='oracle controls incomplete'):
        api()._oracle_controls(Attempt(), 'image', tmp_path, {'execution': {'environment': {}}})


def test_invalid_selector_fails_before_output_or_engine(tmp_path):
    m = api()
    out = tmp_path / 'out'
    with pytest.raises(ValueError, match='toolset'):
        m.build_tool(m.ToolBuildRequest('proxy', tmp_path / 'resolved-inputs.json', out))
    assert not out.exists()


def test_missing_receipt_never_creates_output(tmp_path):
    m = api()
    with pytest.raises((ValueError, OSError)):
        m.build_tool(m.ToolBuildRequest('checker', tmp_path / 'resolved-inputs.json', tmp_path / 'out'))
    assert not (tmp_path / 'out').exists()


@pytest.mark.parametrize('mode', ['existing', 'symlink'])
def test_output_requires_fresh_safe_directory(tmp_path, mode):
    m = api()
    out = tmp_path / 'out'
    if mode == 'existing':
        out.mkdir()
    else:
        out.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError, match='output'):
        m.build_tool(m.ToolBuildRequest('oracle', tmp_path / 'resolved-inputs.json', out))


def test_checker_mismatch_retains_observed_identity_without_accepting(tmp_path):
    m = api()
    wheel = tmp_path / 'pkcs11_check-0.2.3-py3-none-any.whl'
    wheel.write_bytes(b'new real bytes')
    observation = m.check_checker_output(wheel)
    assert observation['status'] == 'blocked-output-mismatch'
    assert observation['observed']['size'] == 14
    assert observation['observed']['sha256'] != observation['expected']['sha256']
    assert wheel.read_bytes() == b'new real bytes'


def test_expected_output_does_not_accept_same_size_mutation(tmp_path):
    m = api()
    wheel = tmp_path / 'pkcs11_check-0.2.3-py3-none-any.whl'
    wheel.write_bytes(b'x' * 2084028)
    assert m.check_checker_output(wheel)['status'] == 'blocked-output-mismatch'


def elf_fixture():
    # Minimal ELF64 executable with one PT_INTERP; independent literal layout.
    data = bytearray(160)
    data[:16] = b'\x7fELF\x02\x01\x01' + bytes(9)
    struct.pack_into('<HHIQQQIHHHHHH', data, 16, 3, 62, 1, 0, 64, 0, 0, 64, 56, 1, 0, 0, 0)
    interpreter = b'/lib64/ld-linux-x86-64.so.2\0'
    struct.pack_into('<IIQQQQQQ', data, 64, 3, 4, 128, 0, 0, len(interpreter), len(interpreter), 1)
    data[128:128 + len(interpreter)] = interpreter
    return bytes(data)


def test_elf_interpreter_is_read_from_actual_bytes():
    result = api().inspect_elf(elf_fixture())
    assert result['interpreter'] == '/lib64/ld-linux-x86-64.so.2'
    assert result['needed'] == []


@pytest.mark.parametrize('data', [b'not ELF', b'\x7fELF', elf_fixture()[:80]])
def test_invalid_elf_blocks_closure(data):
    with pytest.raises(ValueError, match='ELF'):
        api().inspect_elf(data)


def test_stage_package_selection_excludes_other_stage_archives():
    m = api()
    from p11lab.tool_inputs import load_tool_input_lock
    lock = load_tool_input_lock('consumer', target='debian13-amd64')
    selected = m.select_packages(lock, 'compiler')
    assert 'gcc' in {p['name'] for p in selected}
    assert 'opensc' not in {p['name'] for p in selected}
    assert 'libc6' not in {p['name'] for p in selected}  # unchanged parent


def test_actual_package_inventory_rejects_added_or_upgraded_package():
    m = api()
    lock = {'parent_packages': [{'name': 'libc6', 'version': '1', 'architecture': 'amd64',
                                'source_package': 'glibc', 'source_version': '1'}],
            'packages': [], 'stages': {'x': {'packages': ['libc6']}}}
    expected = 'libc6\t1\tamd64\tglibc\t1\n'
    assert m.verify_package_inventory(lock, 'x', expected)[0]['name'] == 'libc6'
    for actual in [expected.replace('\t1\t', '\t2\t', 1), expected + 'extra\t1\tall\textra\t1\n', '']:
        with pytest.raises(ValueError, match='package'):
            m.verify_package_inventory(lock, 'x', actual)


def test_untrusted_receipt_cannot_authorize_warm_reuse(tmp_path):
    m = api()
    (tmp_path / 'manifest.json').write_text(json.dumps({'status': 'installed', 'toolset': 'oracle'}))
    with pytest.raises(ValueError):
        m.verify_tool_build(tmp_path)


def test_cleanup_probe_failure_is_retained_without_hiding_native_failure(tmp_path):
    m = api()
    class UnavailableEngine:
        def command(self, args, **kwargs):
            raise OSError('engine unavailable during independent readback')
    record = {'cleanup_errors': []}
    attempt = m._Attempt(UnavailableEngine(), tmp_path, record)
    attempt.cleanup(keep=None)
    assert len(record['cleanup_errors']) == 2
    assert all('unavailable' in message for message in record['cleanup_errors'])


def tar_fixture(path, members):
    with tarfile.open(path, 'w') as archive:
        for name, content in members:
            item = tarfile.TarInfo(name)
            item.mode = 0o644
            item.size = len(content)
            archive.addfile(item, io.BytesIO(content))


def test_independent_filesystem_readback_hashes_actual_bytes(tmp_path):
    path = tmp_path / 'root.tar'
    tar_fixture(path, [('usr/bin/python3.13', elf_fixture()), ('etc/openssl.cnf', b'fixed config')])
    result = api()._archive_inventory(path)
    assert result['files']['etc/openssl.cnf']['size'] == 12
    assert result['elfs']['usr/bin/python3.13']['interpreter'] == '/lib64/ld-linux-x86-64.so.2'
    assert result['regular_bytes'] == 172


@pytest.mark.parametrize('members', [
    [('../escape', b'x')], [('same', b'a'), ('same', b'b')],
    [('usr/bin/python3.13', b'\x7fELFbroken')],
])
def test_untrusted_filesystem_roster_or_elf_blocks_readback(tmp_path, members):
    path = tmp_path / 'root.tar'
    tar_fixture(path, members)
    with pytest.raises(ValueError):
        api()._archive_inventory(path)


def test_missing_loader_never_counts_as_complete_elf_closure():
    inventory = {'files': {'usr/bin/tool': {'sha256': 'a', 'size': 160}}, 'aliases': {},
                 'elfs': {'usr/bin/tool': {'interpreter': '/lib64/missing', 'needed': [],
                                         'soname': None, 'search_paths': []}}}
    with pytest.raises(ValueError, match='missing actual ELF'):
        api()._elf_closure(inventory, ['usr/bin/tool'])


def test_alias_cycle_never_counts_as_file_identity():
    inventory = {'aliases': {'a': {'kind': 'symlink', 'target': 'b'},
                             'b': {'kind': 'symlink', 'target': 'a'}}}
    with pytest.raises(ValueError, match='cycle'):
        api()._resolve('a', inventory)


def test_relocatable_compiler_object_is_inventory_data_without_a_loader():
    raw = bytearray(64)
    raw[:16] = b'\x7fELF\x02\x01\x01' + bytes(9)
    struct.pack_into('<HHIQQQIHHHHHH', raw, 16, 1, 62, 1, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0)
    result = api().inspect_elf(bytes(raw))
    assert result['elf_type'] == 1
    assert result['interpreter'] is None


def deb_fixture(path, name):
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode='w') as tar:
        item = tarfile.TarInfo(name)
        item.mode = 0o755
        item.size = 1
        tar.addfile(item, io.BytesIO(b'x'))
    data = archive.getvalue()
    header = ('data.tar/'.ljust(16) + '0'.ljust(12) + '0'.ljust(6) + '0'.ljust(6) +
              '100644'.ljust(8) + str(len(data)).ljust(10) + '`\n').encode()
    path.write_bytes(b'!<arch>\n' + header + data)
    import hashlib
    package = {'name': 'example', 'version': '1', 'path': path.name, 'size': path.stat().st_size,
               'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
    return {'packages': [package], 'stages': {'x': {'packages': ['example']}}}


def test_documentation_exclusion_is_visible_without_claiming_runtime_loss(tmp_path):
    lock = deb_fixture(tmp_path / 'example.deb', 'usr/share/doc/example/examples/rules')
    result = api().bind_package_members(lock, 'x', tmp_path, {'files': {}, 'aliases': {}})
    assert result['packages'][0]['members'][0]['status'] == 'maintainer-modified-or-absent'


def test_missing_actual_runtime_executable_blocks_package_member_binding(tmp_path):
    lock = deb_fixture(tmp_path / 'example.deb', 'usr/bin/executable')
    with pytest.raises(ValueError, match='differs from package'):
        api().bind_package_members(lock, 'x', tmp_path, {'files': {}, 'aliases': {}})


def test_stopped_producer_reference_is_released_before_output_volume(monkeypatch, tmp_path):
    m = api()
    references = set()
    class Engine:
        def remove(self, kind, identity, labels):
            references.remove(identity)
    class Volume:
        def __init__(self, *args):
            self.name = 'bounded-volume'
        def open(self):
            pass
        def readback(self, destination, expected, interrupted):
            (destination / expected[0]).write_bytes(b'product')
        def close(self):
            return ['volume still referenced by stopped producer'] if references else []
    class Attempt:
        engine = Engine()
        output = tmp_path
        labels = {'nonce': 'fixed'}
        result = {'cleanup_errors': []}
        containers = []
        def run(self, *args, **kwargs):
            references.add('producer')
            self.containers.append('producer')
            return 'producer'
    monkeypatch.setattr(m, '_OutputVolume', Volume)
    attempt = Attempt()
    product = m._producer(attempt, 'image', tmp_path, ['build'], 'tool')
    assert product.read_bytes() == b'product'
    assert attempt.result['cleanup_errors'] == []
    assert not references


def test_warm_receipt_requires_protected_external_seal_even_with_inputs(tmp_path):
    (tmp_path / 'manifest.json').write_text('{"status":"installed-local-only"}')
    with pytest.raises(ValueError, match='protected manifest'):
        api().verify_tool_build(tmp_path, receipt_path=tmp_path / 'resolved-inputs.json')


def test_changed_receipt_cannot_repin_its_own_manifest(tmp_path):
    path = tmp_path / 'manifest.json'
    path.write_text('{"status":"installed-local-only"}')
    with pytest.raises(ValueError, match='protected manifest'):
        api().verify_tool_build(tmp_path, receipt_path=tmp_path / 'resolved-inputs.json',
                                manifest_sha256='0' * 64)


def inspected_boundary():
    return {'Image': 'sha256:' + 'a' * 64,
            'Config': {'User': '65532:65532', 'Entrypoint': ['/usr/bin/env'],
                       'Cmd': ['-i', 'PATH=/usr/bin:/bin', '/bin/true']},
            'HostConfig': {'NetworkMode': 'none', 'CapDrop': ['ALL'], 'CapAdd': None,
                           'ReadonlyRootfs': True, 'Privileged': False, 'PidsLimit': 128,
                           'Memory': 1073741824, 'MemorySwap': 1073741824, 'NanoCpus': 1000000000,
                           'SecurityOpt': ['no-new-privileges=true'], 'PidMode': '', 'IpcMode': 'private',
                           'Binds': None, 'Devices': [], 'VolumesFrom': None,
                           'Tmpfs': {'/tmp': 'rw,nosuid,nodev,size=536870912,nr_inodes=16384,mode=1777'}},
            'Mounts': [{'Type': 'bind', 'Source': '/frozen', 'Destination': '/inputs', 'RW': False}]}


@pytest.mark.parametrize('mutation', [
    ('NetworkMode', 'host'), ('CapAdd', ['SYS_ADMIN']), ('SecurityOpt', []), ('MemorySwap', -1),
    ('NanoCpus', 0), ('PidMode', 'host'), ('IpcMode', 'host'), ('VolumesFrom', ['other']),
    ('Binds', ['/var/run/docker.sock:/socket']), ('Devices', ['/dev/kvm']),
])
def test_changed_native_boundary_is_rejected_before_execution(mutation):
    observed = inspected_boundary()
    observed['HostConfig'][mutation[0]] = mutation[1]
    with pytest.raises(ValueError, match='boundary'):
        api().verify_execution_boundary(observed, 'sha256:' + 'a' * 64,
                                         ['-i', 'PATH=/usr/bin:/bin', '/bin/true'],
                                         ['type=bind,src=/frozen,dst=/inputs,readonly'],
                                         readonly=True, user='65532:65532')


def test_extra_or_writable_input_mount_is_rejected():
    for mutation in ('extra', 'writable'):
        observed = inspected_boundary()
        if mutation == 'extra':
            observed['Mounts'].append({'Type': 'bind', 'Source': '/credential', 'Destination': '/secret', 'RW': False})
        else:
            observed['Mounts'][0]['RW'] = True
        with pytest.raises(ValueError, match='boundary'):
            api().verify_execution_boundary(observed, 'sha256:' + 'a' * 64,
                                             ['-i', 'PATH=/usr/bin:/bin', '/bin/true'],
                                             ['type=bind,src=/frozen,dst=/inputs,readonly'],
                                             readonly=True, user='65532:65532')


def test_checker_startup_cannot_mutate_or_add_files_outside_install_prefix():
    m = api()
    before = {'files': {'usr/bin/python3.13': {'sha256': 'pinned'}}, 'aliases': {}}
    after = {'files': {**before['files'], 'opt/p11lab-checker/site/pkg.py': {'sha256': 'wheel'}}, 'aliases': {}}
    assert m.verify_install_parent(before, after)['unchanged_files'] == 1
    after['files']['usr/bin/python3.13'] = {'sha256': 'replaced'}
    with pytest.raises(ValueError, match='parent'):
        m.verify_install_parent(before, after)
    after['files']['usr/bin/python3.13'] = before['files']['usr/bin/python3.13']
    after['files']['root/startup-canary'] = {'sha256': 'unexpected'}
    with pytest.raises(ValueError, match='prefix'):
        m.verify_install_parent(before, after)


def test_actual_build_context_identity_changes_with_bytes_and_rejects_links(tmp_path):
    source = tmp_path / 'source.c'
    source.write_bytes(b'original')
    first = api().context_identity(tmp_path)
    assert first['files'][0]['path'] == 'source.c'
    assert first['files'][0]['size'] == 8
    source.write_bytes(b'changed!')
    assert api().context_identity(tmp_path)['sha256'] != first['sha256']
    source.unlink()
    source.symlink_to('/etc/hosts')
    with pytest.raises(ValueError, match='context'):
        api().context_identity(tmp_path)


def test_installation_requires_total_tmpfs_byte_and_inode_quota():
    policy = api().bounded_install_policy()
    assert policy['rootfs_bytes'] == 805306368
    assert policy['rootfs_inodes'] == 32768
    assert policy['outer_root'] == 'read-only'
    assert policy['payload_capabilities'] == 'zero-effective-permitted-inheritable'
    assert policy['setup_capabilities'] == ['SYS_CHROOT']


def test_writable_overlay_installation_is_rejected_before_execution():
    with pytest.raises(ValueError, match='bounded'):
        api()._options(readonly=False)


def test_bound_policy_is_required_even_with_protected_old_manifest_seal(tmp_path):
    import hashlib
    manifest = {'kind': 'local-tool-build', 'status': 'installed-local-only',
                'rights': 'unreviewed', 'qualification': 'not-performed', 'cleanup_errors': [],
                'producer_resources': api()._recipe_identity()}
    raw = json.dumps(manifest).encode()
    (tmp_path / 'manifest.json').write_bytes(raw)
    with pytest.raises(ValueError, match='bounded'):
        api().verify_tool_build(tmp_path, receipt_path=tmp_path / 'resolved-inputs.json',
                                manifest_sha256=hashlib.sha256(raw).hexdigest())


def test_only_explicit_trusted_setup_may_hold_native_chroot_capability():
    observed = inspected_boundary()
    observed['Config']['User'] = '0:0'
    observed['HostConfig']['CapAdd'] = ['CAP_SYS_CHROOT']
    api().verify_execution_boundary(observed, 'sha256:' + 'a' * 64,
                                   ['-i', 'PATH=/usr/bin:/bin', '/bin/true'],
                                   ['type=bind,src=/frozen,dst=/inputs,readonly'],
                                   readonly=True, user='0:0', rootfs_setup=True)
    with pytest.raises(ValueError, match='boundary'):
        api().verify_execution_boundary(observed, 'sha256:' + 'a' * 64,
                                       ['-i', 'PATH=/usr/bin:/bin', '/bin/true'],
                                       ['type=bind,src=/frozen,dst=/inputs,readonly'],
                                       readonly=True, user='0:0')


def test_mismatched_or_incomplete_bounded_policy_cannot_be_a_warm_hit(tmp_path):
    import hashlib
    for policy in ({**api().bounded_install_policy(), 'rootfs_inodes': 0}, api().bounded_install_policy()):
        manifest = {'bounded_policy': policy, 'toolset': 'checker', 'bounded_installations': []}
        raw = json.dumps(manifest).encode()
        (tmp_path / 'manifest.json').write_bytes(raw)
        with pytest.raises(ValueError, match='bounded'):
            api().verify_tool_build(tmp_path, receipt_path=tmp_path / 'resolved-inputs.json',
                                    manifest_sha256=hashlib.sha256(raw).hexdigest())


def test_derived_image_never_receives_trusted_setup_capability(tmp_path):
    result = {'stages': [], 'cleanup_errors': [], 'base': {'engine_id': 'sha256:' + 'a' * 64}}
    attempt = api()._Attempt(object(), tmp_path, result)
    with pytest.raises(ValueError, match='selected base'):
        attempt.run('sha256:' + 'b' * 64, ['/bin/true'], rootfs_setup=True)


def test_rootfs_transfer_retains_only_bounded_native_error_prefix(tmp_path):
    import sys
    from types import SimpleNamespace
    from p11lab.tool_rootfs import _transfer
    attempt = SimpleNamespace(output=tmp_path, result={}, engine=SimpleNamespace(env={}))
    with pytest.raises(ValueError, match='transfer'):
        _transfer(attempt, [sys.executable, '-I', '-c', 'import sys; sys.stderr.write("x"*262144)'], 'error')
    assert (tmp_path / 'error-transfer.stderr').stat().st_size <= 65536
