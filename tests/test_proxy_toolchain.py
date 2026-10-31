"""Independent controls for the proxy compiler tool image."""
import pytest

from p11lab.proxy_toolchain import ToolchainError, check_protoc_descriptor


# Hand-encoded FileDescriptorSet: canary.proto, package p11lab, message Ping,
# optional string value = 1, syntax proto3. The oracle is not tool-generated.
DESCRIPTOR = bytes.fromhex(
    '0a3c' '0a0c63616e6172792e70726f746f' '12067031316c6162'
    '221c0a0450696e6712140a0576616c7565180120012809520576616c7565'
    '620670726f746f33'
)


def test_protoc_control_requires_exact_descriptor_not_just_exit_zero():
    check_protoc_descriptor(DESCRIPTOR)
    with pytest.raises(ToolchainError):
        check_protoc_descriptor(DESCRIPTOR.replace(b'value', b'other', 1))
    with pytest.raises(ToolchainError):
        check_protoc_descriptor(b'')


def test_rust_closure_resolves_only_selected_origin_and_system_libraries():
    from p11lab.proxy_toolchain import resolve_toolchain_closure

    def elf(needed=(), paths=(), interpreter=None):
        return {'elf_type': 3, 'interpreter': interpreter, 'needed': list(needed),
                'soname': None, 'search_paths': list(paths), 'search_kind': 'runpath' if paths else 'none'}

    inventory = {
        'files': {p: {'sha256': 'a' * 64, 'size': 1, 'mode': 0o755} for p in (
            'opt/rust/bin/rustc', 'opt/rust/lib/driver.so',
            'usr/lib/x86_64-linux-gnu/libc.so.6', 'usr/lib/x86_64-linux-gnu/ld.so')},
        'aliases': {'lib64/ld.so': {'target': '/usr/lib/x86_64-linux-gnu/ld.so', 'kind': 'symlink'}},
        'elfs': {
            'opt/rust/bin/rustc': elf(('driver.so', 'libc.so.6'), ('$ORIGIN/../lib',), '/lib64/ld.so'),
            'opt/rust/lib/driver.so': elf(('libc.so.6',), ('$ORIGIN/../lib',)),
            'usr/lib/x86_64-linux-gnu/libc.so.6': elf(),
            'usr/lib/x86_64-linux-gnu/ld.so': elf(),
        },
    }
    closure = resolve_toolchain_closure(inventory, ['opt/rust/bin/rustc'])
    assert set(closure) == set(inventory['files'])
    inventory['elfs']['opt/rust/bin/rustc']['search_kind'] = 'rpath'
    with pytest.raises(ToolchainError):
        resolve_toolchain_closure(inventory, ['opt/rust/bin/rustc'])
    inventory['elfs']['opt/rust/bin/rustc']['search_kind'] = 'runpath'
    inventory['elfs']['opt/rust/bin/rustc']['search_paths'] = ['$ORIGIN/../../untrusted']
    with pytest.raises(ToolchainError):
        resolve_toolchain_closure(inventory, ['opt/rust/bin/rustc'])


def test_toolchain_inventory_rejects_trailing_data_and_escaping_links(tmp_path):
    import io
    import tarfile

    from p11lab.proxy_toolchain import inventory_toolchain_archive

    archive = tmp_path / 'image.tar'
    with tarfile.open(archive, 'w') as tar:
        entry = tarfile.TarInfo('usr/bin/tool')
        entry.mode = 0o755
        entry.size = 3
        tar.addfile(entry, io.BytesIO(b'abc'))
    result = inventory_toolchain_archive(archive)
    assert result['files']['usr/bin/tool']['sha256'] == (
        'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
    archive.write_bytes(archive.read_bytes() + b'nonzero')
    with pytest.raises(ToolchainError):
        inventory_toolchain_archive(archive)
    with tarfile.open(archive, 'w') as tar:
        link = tarfile.TarInfo('usr/escape')
        link.type = tarfile.SYMTYPE
        link.linkname = '../../outside'
        tar.addfile(link)
    with pytest.raises(ToolchainError):
        inventory_toolchain_archive(archive)


def test_rust_component_rejects_unlisted_and_missing_install_files():
    import io
    import tarfile

    from p11lab.proxy_toolchain import read_rust_component

    def fixture(files):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w') as tar:
            for name, body in files.items():
                entry = tarfile.TarInfo('rust-test/rustc/' + name)
                entry.size = len(body)
                entry.mode = 0o755
                tar.addfile(entry, io.BytesIO(body))
        return buffer.getvalue()

    clean = {'manifest.in': b'file:bin/rustc\n', 'bin/rustc': b'compiler'}
    files = read_rust_component(fixture(clean), 'rust-test', 'rustc')
    assert files['bin/rustc']['sha256'] == 'e996bb0ea465fae70d3e3c66b3b6e02d33d2f1eb76d5958720578b6cf359cc2e'
    with pytest.raises(ToolchainError):
        read_rust_component(fixture(clean | {'bin/extra': b'extra'}), 'rust-test', 'rustc')
    with pytest.raises(ToolchainError):
        read_rust_component(fixture({'manifest.in': clean['manifest.in']}), 'rust-test', 'rustc')


def test_rust_archive_rejects_hidden_compressed_trailer_and_expansion_bomb():
    import lzma

    from p11lab.proxy_toolchain import decode_rust_archive

    compressed = lzma.compress(b'hello')
    assert decode_rust_archive(compressed, limit=5) == b'hello'
    with pytest.raises(ToolchainError):
        decode_rust_archive(compressed + b'extra', limit=5)
    with pytest.raises(ToolchainError):
        decode_rust_archive(compressed, limit=4)


def test_protoc_archive_rejects_traversal_links_and_trailing_bytes():
    import io
    import stat
    import zipfile

    from p11lab.proxy_toolchain import read_protoc_archive

    def fixture(name, data=b'bin', mode=stat.S_IFREG | 0o755):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w') as archive:
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.external_attr = mode << 16
            archive.writestr(info, data)
        return stream.getvalue()

    assert read_protoc_archive(fixture('bin/protoc'))['bin/protoc']['size'] == 3
    for bad in (fixture('../escape'), fixture('bin/protoc', mode=stat.S_IFLNK | 0o777),
                fixture('bin/protoc') + b'extra'):
        with pytest.raises(ToolchainError):
            read_protoc_archive(bad)


def test_toolchain_inventory_rejects_nonzero_file_padding(tmp_path):
    import io
    import tarfile

    from p11lab.proxy_toolchain import inventory_toolchain_archive

    path = tmp_path / 'bad-padding.tar'
    with tarfile.open(path, 'w') as tar:
        entry = tarfile.TarInfo('file')
        entry.size = 1
        tar.addfile(entry, io.BytesIO(b'x'))
    raw = bytearray(path.read_bytes())
    raw[513] = 1
    path.write_bytes(raw)
    with pytest.raises(ToolchainError):
        inventory_toolchain_archive(path)


def test_assembly_preserves_base_and_refuses_existing_rust_path(tmp_path):
    import io
    import tarfile
    import zipfile

    from p11lab.proxy_toolchain import assemble_image_archive, inventory_toolchain_archive

    def tar_bytes(items):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w') as tar:
            for name, data in items.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                info.mode = 0o755
                tar.addfile(info, io.BytesIO(data))
        return buf.getvalue()

    component = tar_bytes({'test/rustc/manifest.in': b'file:bin/rustc\n',
                           'test/rustc/bin/rustc': b'compiler'})
    zipbuf = io.BytesIO()
    with zipfile.ZipFile(zipbuf, 'w') as archive:
        import stat
        info = zipfile.ZipInfo('bin/protoc')
        info.create_system = 3
        info.external_attr = (stat.S_IFREG | 0o755) << 16
        archive.writestr(info, b'protoc')
    base = tmp_path / 'base.tar'
    base.write_bytes(tar_bytes({'usr/bin/cc': b'cc'}))
    out = tmp_path / 'assembled.tar'
    assemble_image_archive(base, [(component, 'test', 'rustc')], zipbuf.getvalue(), out)
    files = inventory_toolchain_archive(out)['files']
    assert files['usr/bin/cc']['size'] == 2
    assert files['opt/rust/bin/rustc']['sha256'] == 'e996bb0ea465fae70d3e3c66b3b6e02d33d2f1eb76d5958720578b6cf359cc2e'
    assert files['opt/protoc/bin/protoc']['mode'] == 0o755
    bad = tmp_path / 'collision.tar'
    bad.write_bytes(tar_bytes({'opt/rust/bin/rustc': b'wrong'}))
    with pytest.raises(ToolchainError):
        assemble_image_archive(bad, [(component, 'test', 'rustc')], zipbuf.getvalue(), tmp_path / 'bad.tar')


def test_build_rejects_untyped_request_before_creating_output(tmp_path):
    from p11lab.proxy_toolchain import build_proxy_toolchain

    with pytest.raises(ToolchainError):
        build_proxy_toolchain({'output_dir': tmp_path / 'out'})
    assert not (tmp_path / 'out').exists()


def test_canary_oracle_rejects_wrong_output_even_when_process_succeeds():
    from p11lab.proxy_toolchain import check_canary_output

    stdout = ('P11LAB_RUSTC\nrustc 1.98.1 (test)\nhost: x86_64-unknown-linux-gnu\n'
              'P11LAB_CARGO\ncargo 1.98.1 (test)\nP11LAB_PROTOC\nlibprotoc 36.1\n'
              'P11LAB_HELLO\np11lab-toolchain-hello\nP11LAB_DESCRIPTOR\n'
              + DESCRIPTOR.hex() + '\nP11LAB_END\n')
    check_canary_output(stdout)
    with pytest.raises(ToolchainError):
        check_canary_output(stdout.replace('p11lab-toolchain-hello', 'wrong'))
    with pytest.raises(ToolchainError):
        check_canary_output(stdout.replace(DESCRIPTOR.hex(), '00'))
    with pytest.raises(ToolchainError):
        check_canary_output(stdout.replace('x86_64-unknown-linux-gnu', 'wrong-target'))


def test_warm_reuse_rejects_changed_sealed_manifest_before_any_image_access(tmp_path):
    from p11lab.proxy_toolchain import verify_proxy_toolchain

    (tmp_path / 'manifest.json').write_text('{}')
    with pytest.raises(ToolchainError):
        verify_proxy_toolchain(tmp_path, manifest_sha256='0' * 64, cache=None)


def test_image_comparison_accepts_only_equivalent_hardlink_spelling():
    from p11lab.proxy_toolchain import compare_image_inventories

    base = {'regular_bytes': 1, 'files': {'usr/bin/perl': {'size': 1, 'mode': 0o755, 'sha256': 'a'}},
            'elfs': {}, 'aliases': {'usr/bin/perl5': {'kind': 'hardlink', 'target': './usr/bin/perl'}}}
    same = {'regular_bytes': 1, 'files': dict(base['files']), 'elfs': {},
            'aliases': {'usr/bin/perl5': {'kind': 'hardlink', 'target': 'usr/bin/perl'}}}
    compare_image_inventories(base, same)
    same['aliases']['usr/bin/perl5']['target'] = 'usr/bin/wrong'
    with pytest.raises(ToolchainError):
        compare_image_inventories(base, same)
    same['aliases']['usr/bin/perl5']['target'] = 'usr/bin/perl'
    same['files']['usr/bin/perl'] = {'size': 1, 'mode': 0o644, 'sha256': 'a'}
    with pytest.raises(ToolchainError):
        compare_image_inventories(base, same)


def test_native_loader_path_normalization_rejects_aliases_and_escapes():
    from p11lab.proxy_toolchain import resolve_native_loader_path

    inventory = {'aliases': {}, 'files': {}, 'elfs': {}}
    path = '/opt/rust/bin/../lib/../lib/driver.so'
    assert resolve_native_loader_path(path, inventory) == 'opt/rust/lib/driver.so'
    with pytest.raises(ToolchainError):
        resolve_native_loader_path('/opt/rust/bin/../../../../etc/passwd', inventory)
    inventory['aliases']['opt/rust/bin'] = {'kind': 'symlink', 'target': '/usr/bin'}
    with pytest.raises(ToolchainError):
        resolve_native_loader_path(path, inventory)


def test_changed_toolchain_role_policy_is_refused():
    from p11lab.catalog import package_data
    from p11lab.proxy_toolchain import validate_role_policy

    raw = package_data('tool-builds/proxy-toolchain-v1.json').read_bytes()
    assert validate_role_policy(raw)['target'] == 'x86_64-unknown-linux-gnu'
    with pytest.raises(ToolchainError):
        validate_role_policy(raw.replace(b'1073741824', b'2073741824', 1))


def test_authored_canary_fixture_is_readable_with_restrictive_umask(tmp_path):
    import os

    from p11lab.proxy_toolchain import _canary_fixture

    old = os.umask(0o077)
    try:
        root = tmp_path / 'fixture'
        _canary_fixture(root)
    finally:
        os.umask(old)
    assert root.stat().st_mode & 0o777 == 0o755
    assert (root / 'src').stat().st_mode & 0o777 == 0o755
    assert (root / 'src/main.rs').stat().st_mode & 0o777 == 0o644


def test_incomplete_native_outcome_cannot_be_reused_as_success():
    from p11lab.proxy_toolchain import require_native_success

    native = {'returncode': 0, 'timed_out': False, 'stdout_truncated': False, 'stderr_truncated': False}
    state = {'Running': False, 'Pid': 0}
    require_native_success(native, state)
    for changed in ({'returncode': 1}, {'timed_out': True}, {'stdout_truncated': True},
                    {'stderr_truncated': True}):
        with pytest.raises(ToolchainError):
            require_native_success(native | changed, state)
    for changed in ({'Running': True}, {'Pid': 1}, {'Pid': None}):
        with pytest.raises(ToolchainError):
            require_native_success(native, state | changed)


def test_canary_timeout_limit_rejects_values_outside_fixed_cap():
    from p11lab.proxy_toolchain import _canary_timeout

    assert _canary_timeout(1) == 1
    with pytest.raises(ToolchainError):
        _canary_timeout(0)
    with pytest.raises(ToolchainError):
        _canary_timeout(121)


def test_native_role_boundary_rejects_changed_quota_or_network():
    import copy
    from p11lab.proxy_toolchain import verify_role_boundary

    command = ['-i', 'PATH=/usr/bin:/bin', '/bin/true']
    observed = {
        'Image': 'sha256:chosen',
        'Config': {'User': '65532:65532', 'Entrypoint': ['/usr/bin/env'], 'Cmd': command},
        'HostConfig': {'NetworkMode': 'none', 'CapDrop': ['ALL'], 'CapAdd': None,
                       'ReadonlyRootfs': True, 'Privileged': False, 'PidsLimit': 128,
                       'Memory': 1024**3, 'MemorySwap': 1024**3, 'NanoCpus': 1000000000,
                       'SecurityOpt': ['no-new-privileges=true'], 'IpcMode': 'private',
                       'PidMode': '', 'Binds': None, 'Devices': None, 'VolumesFrom': None,
                       'Tmpfs': {'/tmp': 'rw,nosuid,nodev,size=134217728,nr_inodes=16384,mode=1777',
                                 '/out': 'rw,nosuid,nodev,exec,size=268435456,nr_inodes=10000,mode=1777'},
                       'Ulimits': [{'Name': 'fsize', 'Soft': 268435456, 'Hard': 268435456},
                                   {'Name': 'nofile', 'Soft': 256, 'Hard': 256}]},
        'Mounts': [],
    }
    verify_role_boundary(observed, 'sha256:chosen', command, [])
    for key, value in (('NetworkMode', 'bridge'), ('Ulimits', [])):
        changed = copy.deepcopy(observed)
        changed['HostConfig'][key] = value
        with pytest.raises(ValueError):
            verify_role_boundary(changed, 'sha256:chosen', command, [])


def test_image_comparison_rejects_directory_mode_changes():
    from p11lab.proxy_toolchain import compare_image_inventories

    left = {'regular_bytes': 0, 'files': {}, 'elfs': {}, 'aliases': {},
            'directories': {'opt': {'mode': 0o755, 'uid': 0, 'gid': 0}}}
    right = {'regular_bytes': 0, 'files': {}, 'elfs': {}, 'aliases': {},
             'directories': {'opt': {'mode': 0o700, 'uid': 0, 'gid': 0}}}
    with pytest.raises(ToolchainError):
        compare_image_inventories(left, right)


def test_native_loader_controls_include_and_detect_changed_gcc_subprocess(monkeypatch):
    import p11lab.proxy_toolchain as module

    roots = ['opt/rust/bin/rustc', 'opt/rust/bin/cargo', 'opt/protoc/bin/protoc',
             'usr/bin/cc', 'usr/bin/as', 'usr/bin/ld', 'usr/bin/env', 'usr/bin/sha256sum',
             'usr/bin/od', 'usr/bin/tr', 'usr/bin/mkdir', 'usr/bin/sh',
             'usr/libexec/gcc/x86_64-linux-gnu/14/cc1',
             'usr/libexec/gcc/x86_64-linux-gnu/14/collect2']
    loader = 'usr/lib/x86_64-linux-gnu/ld.so'
    lib = 'usr/lib/x86_64-linux-gnu/libgood.so'
    def elf(interpreter='/lib64/ld.so', needed=()):
        return {'elf_type': 3, 'interpreter': interpreter, 'needed': list(needed),
                'soname': None, 'search_paths': [], 'search_kind': 'none'}
    elfs = {p: elf() for p in roots}
    elfs['opt/protoc/bin/protoc'] = elf(None)
    cc1 = roots[-2]
    elfs[cc1] = elf(needed=['libgood.so'])
    elfs[loader] = elf(None)
    elfs[lib] = elf(None)
    inventory = {'files': {p: {'size': 1, 'sha256': 'a' * 64, 'mode': 0o755} for p in elfs},
                 'elfs': elfs, 'aliases': {'lib64/ld.so': {'kind': 'symlink', 'target': '/'+loader}}}
    closure = module.resolve_toolchain_closure(inventory, roots)
    def run(_attempt, _image, argv):
        selected = argv[-1].lstrip('/')
        stdout = '\t/lib64/ld.so (0x1234)\n'
        if selected == cc1:
            stdout += '\tlibgood.so => /usr/lib/x86_64-linux-gnu/libwrong.so (0x1234)\n'
        return {'container': selected, 'native': {'stdout': stdout}}
    monkeypatch.setattr(module, '_run_role', run)
    with pytest.raises(module.ToolchainError, match='loader resolution differs'):
        module._verify_native_loaders(None, 'image', inventory, closure)


def test_oversized_partial_does_not_mask_transfer_failure_or_cleanup(tmp_path, monkeypatch):
    import json
    import p11lab.proxy_inputs as inputs
    import p11lab.tool_builds as shared
    from p11lab.proxy_toolchain import ToolchainRequest, build_proxy_toolchain

    output = tmp_path / 'attempt'
    cache = inputs.ProxyInputCache(tmp_path/'source', tmp_path/'payload', tmp_path/'vendor', tmp_path/'receipt')
    def fail_after_partial(_cache):
        (output/'partial.tar').write_bytes(b'123456789')
        raise shared.ToolBuildError('forced bounded transfer failure')
    def cleanup(attempt, *, keep):
        attempt.result['test_cleanup_called'] = True
    monkeypatch.setattr(inputs, 'verify_selected_proxy_inputs', fail_after_partial)
    monkeypatch.setattr(shared, 'MAX_EXPORT', 8)
    monkeypatch.setattr(shared, '_new_docker', lambda: object())
    monkeypatch.setattr(shared._Attempt, 'cleanup', cleanup)
    with pytest.raises(shared.ToolBuildError, match='forced bounded transfer failure'):
        build_proxy_toolchain(ToolchainRequest(cache, output))
    receipt = json.loads((output/'manifest.json').read_text())
    assert receipt['status'] != 'local-toolchain-observed'
    assert receipt['error']['message'] == 'forced bounded transfer failure'
    assert receipt['test_cleanup_called'] is True
    partial = receipt['evidence']['partial.tar']
    assert partial['availability'] == 'over-limit' and partial['size'] == 9
    assert 'sha256' not in partial


def test_warm_preflight_counts_toward_whole_deadline_and_records_failure(tmp_path, monkeypatch):
    import hashlib
    import json
    import p11lab.proxy_inputs as inputs
    import p11lab.proxy_toolchain as module
    import p11lab.tool_builds as shared
    from p11lab.catalog import package_data
    from p11lab.tool_rootfs import bounded_install_policy

    output = tmp_path/'output'
    output.mkdir()
    verification = tmp_path/'verification'
    policy_raw = package_data('tool-builds/proxy-toolchain-v1.json').read_bytes()
    manifest = {'schema_version': 2, 'kind': 'local-proxy-toolchain',
                'status': 'observation-prepared', 'attempt_completion': 'unconfirmed', 'rights': 'unreviewed',
                'authority': 'not-established', 'candidate_build': 'not-run',
                'qualification': 'not-performed', 'cleanup_errors': [],
                'bounded_policy': bounded_install_policy(), 'role_policy': json.loads(policy_raw),
                'recipe': {'sha256': hashlib.sha256(policy_raw).hexdigest(), 'size': len(policy_raw)},
                'producer_resources': {}, 'driver': {}, 'role_resources': {},
                'inputs': {}, 'input_receipt': {}}
    raw = json.dumps({'schema':'p11lab.toolchain-observation.v2', 'state':'provisional',
                      'manifest':manifest}).encode()
    (output/'manifest.json').write_bytes(raw)
    clock = [0.0]
    monkeypatch.setattr(module, '_clock', lambda: clock[0], raising=False)
    monkeypatch.setattr(shared, '_file', lambda path: {})
    monkeypatch.setattr(shared, '_recipe_identity', lambda: {})
    monkeypatch.setattr(shared, '_new_docker', lambda: object())
    monkeypatch.setattr(module, '_role_resources', lambda: {})
    def slow_inputs(_cache):
        clock[0] = 601.0
        return {}
    monkeypatch.setattr(inputs, 'verify_selected_proxy_inputs', slow_inputs)
    def cleanup(attempt, *, keep):
        attempt.result['test_cleanup_called'] = True
    monkeypatch.setattr(shared._Attempt, 'cleanup', cleanup)
    cache = inputs.ProxyInputCache(tmp_path/'source', tmp_path/'payload', tmp_path/'vendor', tmp_path/'receipt')
    with pytest.raises(TimeoutError):
        module.verify_proxy_toolchain(output, manifest_sha256=hashlib.sha256(raw).hexdigest(),
                                      cache=cache, verification_dir=verification)
    receipt = json.loads((verification/'warm-verification.json').read_text())
    assert receipt['status'] != 'verified-local-only'
    assert receipt['test_cleanup_called'] is True
    assert receipt['deadline']['expired_phase'] == 'preflight'


@pytest.mark.parametrize('slow_phase', ['finalization', 'cleanup'])
def test_late_finalization_or_cleanup_cannot_publish_success(tmp_path, monkeypatch, slow_phase):
    import json
    import p11lab.proxy_toolchain as module
    import p11lab.tool_builds as shared

    output = tmp_path/'attempt'
    output.mkdir()
    (output/'small').write_bytes(b'x')
    clock = [0.0]
    monkeypatch.setattr(module, '_clock', lambda: clock[0], raising=False)
    def file_hash(_path):
        if slow_phase == 'finalization':
            clock[0] = 601.0
        return {'size': 1, 'sha256': 'a'*64}
    monkeypatch.setattr(shared, '_file', file_hash)
    result = {'status': 'incomplete', 'cleanup_errors': [], 'stages': []}
    class Attempt:
        def cleanup(self, *, keep):
            result['test_cleanup_called'] = True
            if slow_phase == 'cleanup':
                clock[0] = 601.0
    with pytest.raises(TimeoutError):
        with module._Deadline() as budget:
            module._finalize_attempt(Attempt(), output, result, 'manifest.json',
                                     'local-toolchain-observed', True, None, None, budget)
    receipt = json.loads((output/'manifest.json').read_text())
    assert receipt['status'] != 'local-toolchain-observed'
    assert receipt['test_cleanup_called'] is True
    assert receipt['deadline']['expired_phase'] == slow_phase


def test_build_preflight_deadline_records_cleanup_and_timeout(tmp_path, monkeypatch):
    import json
    import p11lab.proxy_inputs as inputs
    import p11lab.proxy_toolchain as module
    import p11lab.tool_builds as shared

    output = tmp_path/'attempt'
    clock = [0.0]
    monkeypatch.setattr(module, '_clock', lambda: clock[0])
    monkeypatch.setattr(shared, '_new_docker', lambda: object())
    def slow_inputs(_cache):
        clock[0] = 601.0
        return {}
    monkeypatch.setattr(inputs, 'verify_selected_proxy_inputs', slow_inputs)
    def cleanup(attempt, *, keep):
        attempt.result['test_cleanup_called'] = True
    monkeypatch.setattr(shared._Attempt, 'cleanup', cleanup)
    cache = inputs.ProxyInputCache(tmp_path/'source', tmp_path/'payload', tmp_path/'vendor', tmp_path/'receipt')
    with pytest.raises(TimeoutError):
        module.build_proxy_toolchain(module.ToolchainRequest(cache, output))
    receipt = json.loads((output/'manifest.json').read_text())
    assert receipt['status'] != 'local-toolchain-observed'
    assert receipt['test_cleanup_called'] is True
    assert receipt['deadline']['expired_phase'] == 'preflight'


def test_evidence_hash_error_keeps_failure_receipt_and_cleanup(tmp_path, monkeypatch):
    import json
    import p11lab.proxy_toolchain as module
    import p11lab.tool_builds as shared

    (tmp_path/'unreadable').write_bytes(b'x')
    def fail_hash(_path):
        raise OSError('forced read failure')
    monkeypatch.setattr(shared, '_file', fail_hash)
    result = {'status': 'incomplete', 'cleanup_errors': [], 'stages': []}
    class Attempt:
        def cleanup(self, *, keep):
            result['test_cleanup_called'] = True
    with pytest.raises(OSError, match='forced read failure'):
        with module._Deadline() as budget:
            module._finalize_attempt(Attempt(), tmp_path, result, 'manifest.json',
                                     'local-toolchain-observed', True, None, None, budget)
    receipt = json.loads((tmp_path/'manifest.json').read_text())
    assert receipt['status'] != 'local-toolchain-observed'
    assert receipt['test_cleanup_called'] is True
    assert receipt['error']['message'] == 'forced read failure'
    assert receipt['evidence']['unreadable']['availability'] == 'unreadable'
    assert receipt['evidence']['unreadable']['error']['message'] == 'forced read failure'


def test_warm_manifest_read_is_inside_deadline_and_leaves_receipt(tmp_path, monkeypatch):
    import hashlib
    import json
    import p11lab.proxy_inputs as inputs
    import p11lab.proxy_toolchain as module
    import p11lab.tool_builds as shared

    output=tmp_path/'output'
    output.mkdir()
    raw=b'{}'
    (output/'manifest.json').write_bytes(raw)
    dest=tmp_path/'verification'
    clock=[0.0]
    monkeypatch.setattr(module, '_clock', lambda: clock[0])
    read=shared._read_regular
    def slow_read(path, *, maximum):
        value=read(path,maximum=maximum)
        clock[0]=601.0
        return value
    monkeypatch.setattr(shared, '_read_regular', slow_read)
    monkeypatch.setattr(shared, '_new_docker', lambda: object())
    def cleanup(attempt, *, keep):
        attempt.result['test_cleanup_called']=True
    monkeypatch.setattr(shared._Attempt, 'cleanup', cleanup)
    cache=inputs.ProxyInputCache(tmp_path/'source',tmp_path/'payload',tmp_path/'vendor',tmp_path/'receipt')
    with pytest.raises(TimeoutError):
        module.verify_proxy_toolchain(output,manifest_sha256=hashlib.sha256(raw).hexdigest(),
                                       cache=cache,verification_dir=dest)
    receipt=json.loads((dest/'warm-verification.json').read_text())
    assert receipt['status'] != 'verified-local-only' and receipt['test_cleanup_called']
    assert receipt['deadline']['expired_phase']=='preflight'


def test_cleanup_deadline_unconfirmed_is_never_success(tmp_path):
    import json
    import p11lab.proxy_toolchain as module

    result = {'status':'incomplete','cleanup_errors':[],'stages':[]}
    class Attempt:
        def cleanup(self, *, keep):
            raise module._ReserveSignal()
    with pytest.raises(module.ToolchainError):
        with module._Deadline() as budget:
            module._finalize_attempt(Attempt(), tmp_path, result, 'manifest.json',
                                     'local-toolchain-observed', False, None,
                                     module.ToolchainError('original failure'), budget)
    receipt=json.loads((tmp_path/'manifest.json').read_text())
    assert receipt['status']=='failed-cleanup'
    assert receipt['error']['message']=='original failure'
    assert receipt['cleanup_errors']==['cleanup unconfirmed: _ReserveSignal']


def test_success_receipt_is_downgraded_if_its_write_finishes_late(tmp_path, monkeypatch):
    import json
    import p11lab.proxy_toolchain as module

    clock=[0.0]
    monkeypatch.setattr(module,'_clock',lambda:clock[0])
    write=module._atomic_receipt
    calls=[0]
    def slow_receipt(path,result):
        write(path,result)
        calls[0]+=1
        if calls[0]==1:
            clock[0]=601.0
    monkeypatch.setattr(module,'_atomic_receipt',slow_receipt)
    result={'status':'incomplete','cleanup_errors':[],'stages':[]}
    class Attempt:
        def cleanup(self, *, keep):
            result['test_cleanup_called']=True
    with pytest.raises(TimeoutError):
        with module._Deadline() as budget:
            module._finalize_attempt(Attempt(),tmp_path,result,'manifest.json',
                                     'local-toolchain-observed',True,None,None,budget)
    receipt=json.loads((tmp_path/'manifest.json').read_text())
    assert receipt['status']=='failed'
    assert receipt['deadline']['expired_phase']=='receipt'
    assert receipt['test_cleanup_called']


def test_over_deadline_native_failure_preserves_original_diagnostic(tmp_path, monkeypatch):
    import json
    import p11lab.proxy_toolchain as module

    clock=[0.0]
    monkeypatch.setattr(module,'_clock',lambda:clock[0])
    result={'status':'incomplete','cleanup_errors':[],'stages':[]}
    class Attempt:
        def cleanup(self, *, keep):
            result['test_cleanup_called']=True
    with pytest.raises(TimeoutError):
        with module._Deadline() as budget:
            budget.phase='work'
            clock[0]=601.0
            module._finalize_attempt(Attempt(),tmp_path,result,'manifest.json',
                                     'local-toolchain-observed',False,None,
                                     module.ToolchainError('native failure'),budget)
    receipt=json.loads((tmp_path/'manifest.json').read_text())
    assert receipt['operation_error']['message']=='native failure'
    assert receipt['deadline']['expired_phase']=='work'
    assert receipt['status']=='failed'


def test_missing_gcc_subprocess_cannot_shrink_native_root_roster():
    from p11lab.proxy_toolchain import _toolchain_roots

    with pytest.raises(ToolchainError):
        _toolchain_roots({'elfs': {'usr/libexec/gcc/x86_64-linux-gnu/14/cc1': {}}})


def test_real_bounded_transfer_retains_native_failure_and_partial_metadata(tmp_path, monkeypatch):
    import json
    import os
    import sys
    import p11lab.proxy_toolchain as module
    import p11lab.tool_builds as shared
    from p11lab.tool_rootfs import _transfer

    monkeypatch.setattr(shared, 'MAX_EXPORT', 8)
    result={'status':'incomplete','cleanup_errors':[],'stages':[]}
    class Engine:
        env=dict(os.environ)
    class Attempt:
        engine=Engine()
        output=tmp_path
        def __init__(self):
            self.result=result
        def cleanup(self, *, keep):
            self.result['test_cleanup_called']=True
    attempt=Attempt()
    with pytest.raises(shared.ToolBuildError, match='rootfs transfer time/byte bound'):
        with module._Deadline() as budget:
            try:
                _transfer(attempt, [sys.executable, '-c',
                          'import sys,time; sys.stdout.buffer.write(b"x"*1024); sys.stdout.flush(); time.sleep(5)'],
                          'forced', destination=tmp_path/'partial.tar')
            except shared.ToolBuildError as error:
                module._finalize_attempt(attempt,tmp_path,result,'manifest.json',
                                         'local-toolchain-observed',False,None,error,budget)
    receipt=json.loads((tmp_path/'manifest.json').read_text())
    assert receipt['status']=='failed' and receipt['test_cleanup_called']
    assert receipt['error']['message']=='rootfs transfer time/byte bound'
    assert receipt['rootfs_transfers'][0]['returncode'] != 0
    assert receipt['evidence']['partial.tar']['availability']=='over-limit'
    assert receipt['evidence']['partial.tar']['size']==1024
    assert 'sha256' not in receipt['evidence']['partial.tar']


def test_real_deadline_signal_preserves_failure_receipt_and_cleanup(tmp_path):
    import json
    import signal
    import time
    import p11lab.proxy_toolchain as module

    result={'status':'incomplete','cleanup_errors':[],'stages':[]}
    class Attempt:
        def cleanup(self, *, keep):
            result['test_cleanup_called']=True
    with pytest.raises(TimeoutError):
        with module._Deadline() as budget:
            budget.phase='work'
            signal.setitimer(signal.ITIMER_REAL,0.03)
            try:
                time.sleep(0.5)
            except BaseException as error:
                module._finalize_attempt(Attempt(),tmp_path,result,'manifest.json',
                                         'local-toolchain-observed',False,None,error,budget)
    receipt=json.loads((tmp_path/'manifest.json').read_text())
    assert receipt['error']['type']=='TimeoutError'
    assert receipt['deadline']['expired_phase']=='work'
    assert receipt['test_cleanup_called'] and receipt['status']=='failed'


@pytest.mark.parametrize('kind,success_status,receipt_name', [
    ('local-proxy-toolchain', 'local-toolchain-observed', 'manifest.json'),
    ('local-proxy-toolchain-warm-verification', 'verified-local-only', 'warm-verification.json'),
])
@pytest.mark.parametrize('failure', ['write-error', 'reserve-expired'])
def test_late_publication_never_leaves_consumable_success_when_failure_write_unavailable(
        tmp_path, monkeypatch, kind, success_status, receipt_name, failure):
    import json
    import p11lab.proxy_toolchain as module

    clock=[0.0]
    monkeypatch.setattr(module,'_clock',lambda:clock[0])
    write=module._atomic_receipt
    calls=[0]
    def first_late_then_unavailable(path,data):
        calls[0]+=1
        if calls[0]==1:
            write(path,data)
            clock[0]=601.0
            return
        if failure=='write-error':
            raise OSError('forced failure receipt write')
        raise module._ReserveSignal()
    monkeypatch.setattr(module,'_atomic_receipt',first_late_then_unavailable)
    result={'schema_version':2,'kind':kind,'status':'incomplete','cleanup_errors':[],'stages':[]}
    cleaned=[]
    class Attempt:
        def cleanup(self, *, keep):
            cleaned.append(True)
    with pytest.raises(TimeoutError) as raised:
        with module._Deadline() as budget:
            module._finalize_attempt(Attempt(),tmp_path,result,receipt_name,success_status,True,None,None,budget)
    assert 'failure receipt unavailable' in ' '.join(raised.value.__notes__)
    saved=json.loads((tmp_path/receipt_name).read_text())
    assert saved.get('state')=='provisional'
    assert saved['manifest']['status']=='observation-prepared'
    assert saved['manifest']['attempt_completion']=='unconfirmed'
    assert 'completion_witness' not in saved['manifest']
    assert cleaned==[True]
    if kind=='local-proxy-toolchain':
        import hashlib
        digest=hashlib.sha256((tmp_path/receipt_name).read_bytes()).hexdigest()
        assert module.read_toolchain_observation(tmp_path,manifest_sha256=digest)['attempt_completion']=='unconfirmed'
        with pytest.raises(module.ToolchainError):
            module.read_toolchain_observation(tmp_path,manifest_sha256=digest,require_completed=True)


@pytest.mark.parametrize('kind,success_status,receipt_name', [
    ('local-proxy-toolchain', 'local-toolchain-observed', 'manifest.json'),
    ('local-proxy-toolchain-warm-verification', 'verified-local-only', 'warm-verification.json'),
])
def test_return_phase_expiry_cannot_publish_success_when_failure_write_fails(
        tmp_path, monkeypatch, kind, success_status, receipt_name):
    import json
    import p11lab.proxy_toolchain as module

    clock=[0.0]
    monkeypatch.setattr(module,'_clock',lambda:clock[0])
    original_check=module._Deadline.check
    def check(budget,phase):
        if phase=='return':
            clock[0]=601.0
        return original_check(budget,phase)
    monkeypatch.setattr(module._Deadline,'check',check)
    write=module._atomic_receipt
    calls=[0]
    def unavailable_on_failure(path,data):
        calls[0]+=1
        if calls[0]>1:
            raise OSError('forced failure receipt write')
        write(path,data)
    monkeypatch.setattr(module,'_atomic_receipt',unavailable_on_failure)
    result={'schema_version':2,'kind':kind,'status':'incomplete','cleanup_errors':[],'stages':[]}
    cleaned=[]
    class Attempt:
        def cleanup(self, *, keep):
            cleaned.append(True)
    with pytest.raises(TimeoutError):
        with module._Deadline() as budget:
            module._finalize_attempt(Attempt(),tmp_path,result,receipt_name,success_status,True,None,None,budget)
    saved=json.loads((tmp_path/receipt_name).read_text())
    assert saved.get('state')=='provisional'
    assert saved['manifest']['status']=='observation-prepared'
    assert saved['manifest']['attempt_completion']=='unconfirmed'


def test_api_return_witness_is_distinct_from_provisional_file_and_does_not_mint_completion(tmp_path):
    import hashlib
    import json
    import p11lab.proxy_toolchain as module

    result={'schema_version':2,'kind':'local-proxy-toolchain','status':'incomplete','cleanup_errors':[],'stages':[]}
    cleaned=[]
    class Attempt:
        def cleanup(self, *, keep):
            cleaned.append(True)
    with module._Deadline() as budget:
        returned=module._finalize_attempt(Attempt(),tmp_path,result,'manifest.json',
                                          'local-toolchain-observed',True,None,None,budget)
    raw=(tmp_path/'manifest.json').read_bytes()
    digest=hashlib.sha256(raw).hexdigest()
    envelope=json.loads(raw)
    assert envelope['state']=='provisional'
    assert envelope['manifest']['attempt_completion']=='unconfirmed'
    assert 'completion_witness' not in envelope['manifest']
    assert returned['status']=='local-toolchain-observed'
    assert returned['completion_witness']['receipt_sha256']==digest
    assert returned['completion_witness']['authority']=='not-established'
    observation=module.read_toolchain_observation(tmp_path,manifest_sha256=digest)
    assert observation['attempt_completion']=='unconfirmed'
    assert observation['byte_verification']=='not-performed'
    with pytest.raises(module.ToolchainError):
        module.read_toolchain_observation(tmp_path,manifest_sha256=digest,require_completed=True)


def test_provisional_reader_rejects_self_claimed_completion_even_with_selected_hash(tmp_path):
    import hashlib
    import json
    import p11lab.proxy_toolchain as module

    manifest={'schema_version':2,'kind':'local-proxy-toolchain','status':'observation-prepared',
              'attempt_completion':'unconfirmed','completion_witness':{'caller_observation':'completed'}}
    raw=json.dumps({'schema':'p11lab.toolchain-observation.v2','state':'provisional','manifest':manifest}).encode()
    (tmp_path/'manifest.json').write_bytes(raw)
    with pytest.raises(module.ToolchainError):
        module.read_toolchain_observation(tmp_path,manifest_sha256=hashlib.sha256(raw).hexdigest())


def test_reader_refuses_legacy_or_self_asserted_completed_envelopes(tmp_path):
    import hashlib
    import json
    import p11lab.proxy_toolchain as module

    manifest={'schema_version':2,'kind':'local-proxy-toolchain','status':'observation-prepared',
              'attempt_completion':'unconfirmed'}
    records=[{'schema_version':1,'kind':'local-proxy-toolchain','status':'local-toolchain-observed'},
             {'schema':'p11lab.toolchain-observation.v2','state':'completed','manifest':manifest},
             {'schema':'p11lab.toolchain-observation.v2','state':'provisional',
              'manifest':manifest | {'attempt_completion':'completed'}}]
    for record in records:
        raw=json.dumps(record).encode()
        (tmp_path/'manifest.json').write_bytes(raw)
        with pytest.raises(module.ToolchainError):
            module.read_toolchain_observation(tmp_path,manifest_sha256=hashlib.sha256(raw).hexdigest())
