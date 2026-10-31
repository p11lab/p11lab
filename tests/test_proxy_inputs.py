import hashlib
import io
import json
import tarfile

import pytest

from p11lab import proxy_inputs


def digest(data):
    return hashlib.sha256(data).hexdigest()


def archive(name='demo-1.2.3', member='src/lib.rs', data=b'fixture', *, link=False):
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode='w:gz') as tar:
        info = tarfile.TarInfo(name + '/' + member)
        if link:
            info.type = tarfile.SYMTYPE
            info.linkname = '../../outside'
        else:
            info.size = len(data)
        tar.addfile(info, None if link else io.BytesIO(data))
    return result.getvalue()


def lock(raw, source='registry+https://github.com/rust-lang/crates.io-index'):
    return (f'version = 4\n[[package]]\nname = "demo"\nversion = "1.2.3"\n'
            f'source = "{source}"\nchecksum = "{digest(raw)}"\n').encode()


def test_locked_crate_materializes_cargo_checksum_without_execution(tmp_path):
    raw = archive()
    lock_bytes = lock(raw)
    inputs = tmp_path / 'archives'
    inputs.mkdir()
    (inputs / 'demo-1.2.3.crate').write_bytes(raw)
    output = tmp_path / 'vendor'
    receipt = proxy_inputs.materialize_locked_crates(lock_bytes, digest(lock_bytes), inputs, output)
    assert (output / 'demo-1.2.3/src/lib.rs').read_bytes() == b'fixture'
    metadata = json.loads((output / 'demo-1.2.3/.cargo-checksum.json').read_bytes())
    assert metadata == {'files': {'src/lib.rs': digest(b'fixture')}, 'package': digest(raw)}
    assert receipt['lock_sha256'] == digest(lock_bytes)
    assert receipt['status'] == 'materialized-inputs-only'


@pytest.mark.parametrize('case', ['wrong-lock', 'extra', 'corrupt', 'missing', 'link', 'traversal', 'git'])
def test_rejects_untrusted_or_unsupported_inputs_before_materialization(tmp_path, case):
    raw = archive(link=case == 'link', member='../escape' if case == 'traversal' else 'src/lib.rs')
    lock_bytes = lock(raw, 'git+https://example.org/repo#abc' if case == 'git' else 'registry+https://github.com/rust-lang/crates.io-index')
    inputs = tmp_path / 'archives'
    inputs.mkdir()
    if case != 'missing':
        (inputs / 'demo-1.2.3.crate').write_bytes(b'corrupt' if case == 'corrupt' else raw)
    if case == 'extra':
        (inputs / 'extra.crate').write_bytes(b'extra')
    output = tmp_path / 'vendor'
    with pytest.raises(proxy_inputs.ProxyInputError):
        proxy_inputs.materialize_locked_crates(lock_bytes, 'a' * 64 if case == 'wrong-lock' else digest(lock_bytes), inputs, output)
    assert not output.exists()


def test_file_directory_collision_rejected_before_output(tmp_path):
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode='w:gz') as tar:
        for name in ('demo-1.2.3/src', 'demo-1.2.3/src/lib.rs'):
            info = tarfile.TarInfo(name)
            info.size = 1
            tar.addfile(info, io.BytesIO(b'x'))
    raw = result.getvalue()
    lock_bytes = lock(raw)
    inputs = tmp_path / 'archives'
    inputs.mkdir()
    (inputs / 'demo-1.2.3.crate').write_bytes(raw)
    output = tmp_path / 'vendor'
    with pytest.raises(proxy_inputs.ProxyInputError):
        proxy_inputs.materialize_locked_crates(lock_bytes, digest(lock_bytes), inputs, output)
    assert not output.exists()


def test_workspace_packages_bind_to_member_manifests():
    files = {
        'Cargo.toml': b'[workspace]\nmembers=["crates/app"]\n[workspace.package]\nversion="1.0.0"\n',
        'crates/app/Cargo.toml': b'[package]\nname="app"\nversion.workspace=true\n',
    }
    lock_bytes = b'version=4\n[[package]]\nname="app"\nversion="1.0.0"\n'
    hashes = {name: digest(raw) for name, raw in files.items()}
    result = proxy_inputs.validate_workspace_mapping(lock_bytes, digest(lock_bytes), files, hashes)
    assert result == {'app 1.0.0': 'crates/app'}


@pytest.mark.parametrize('case', ['outside', 'unknown', 'git', 'wrong-manifest', 'extra-package'])
def test_workspace_rejects_unbound_or_unsupported_sources(case):
    dep = {'outside': '../outside', 'unknown': '../unknown'}.get(case)
    dependency = (f'\n[dependencies]\nother={{path="{dep}"}}\n' if dep else
                  '\n[dependencies]\nother={git="https://example.com/repo"}\n' if case == 'git' else '')
    files = {'Cargo.toml': b'[workspace]\nmembers=["crates/app"]\n[workspace.package]\nversion="1.0.0"\n',
             'crates/app/Cargo.toml': ('[package]\nname="app"\nversion.workspace=true\n' + dependency).encode()}
    lock_bytes = b'version=4\n[[package]]\nname="app"\nversion="1.0.0"\n'
    if case == 'extra-package':
        lock_bytes += b'[[package]]\nname="other"\nversion="1.0.0"\n'
    hashes = {name: digest(raw) for name, raw in files.items()}
    if case == 'wrong-manifest':
        hashes['Cargo.toml'] = 'a' * 64
    with pytest.raises(proxy_inputs.ProxyInputError):
        proxy_inputs.validate_workspace_mapping(lock_bytes, digest(lock_bytes), files, hashes)


def test_materialize_registry_with_explicit_validated_workspace_roster(tmp_path):
    raw = archive()
    lock_bytes = lock(raw) + b'[[package]]\nname="app"\nversion="1.0.0"\n'
    inputs = tmp_path / 'archives'
    inputs.mkdir()
    (inputs / 'demo-1.2.3.crate').write_bytes(raw)
    receipt = proxy_inputs.materialize_locked_crates(lock_bytes, digest(lock_bytes), inputs, tmp_path / 'vendor',
                                                      workspace={'app 1.0.0': 'crates/app'})
    assert receipt['packages'][0]['identity'] == 'demo-1.2.3'


def git_hash(kind, raw):
    return hashlib.sha1(kind.encode() + b' ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def source_fixture(target='file.txt'):
    data = b'source'
    entries = [('file.txt', '100644', data), ('link', '120000', target.encode())]
    tree_raw = b''.join(mode.encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(git_hash('blob', raw))
                        for name, mode, raw in entries)
    roster = [{'path': name, 'mode': mode, 'size': len(raw), 'sha256': digest(raw), 'git_blob': git_hash('blob', raw)}
              for name, mode, raw in entries]
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode='w:gz') as tar:
        for name, mode, raw in entries:
            info = tarfile.TarInfo('source/' + name)
            if mode == '120000':
                info.type, info.linkname = tarfile.SYMTYPE, raw.decode()
                tar.addfile(info)
            else:
                info.size = len(raw)
                tar.addfile(info, io.BytesIO(raw))
    return result.getvalue(), roster, git_hash('tree', tree_raw)


def test_source_reader_retains_link_identity_without_materializing(tmp_path):
    raw, roster, tree = source_fixture()
    result = proxy_inputs.inspect_source_members(raw, digest(raw), 'source', tree, roster)
    assert result['links'] == {'link': {'target': 'file.txt', 'resolved': 'file.txt'}}
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize('case', ['escape', 'missing', 'bad-tree', 'corrupt', 'extra'])
def test_source_reader_rejects_unbound_members_and_links(case):
    raw, roster, tree = source_fixture('../../outside' if case == 'escape' else 'missing' if case == 'missing' else 'file.txt')
    if case == 'extra':
        roster.pop()
    with pytest.raises(proxy_inputs.ProxyInputError):
        proxy_inputs.inspect_source_members(raw, 'a' * 64 if case == 'corrupt' else digest(raw), 'source',
                                            'a' * 40 if case == 'bad-tree' else tree, roster)


def test_installed_proxy_selection_has_fixed_immutable_identity():
    selected = proxy_inputs.load_proxy_source_selection()
    assert selected.commit == 'a348a5f59b535b1ca309ea9f0a722e3bec692f72'
    assert selected.tree == '436915ad13986c6770de4d190684276bb71de0c8'
    assert selected.cargo_lock_sha256 == '39ae3c64cff6fddd4f2d621f8e26139005936b22e6d7652b2ed14e4921fa5979'
    assert len(selected.members) == 689


def test_proxy_transport_approves_only_typed_selected_static_rust():
    from p11lab.tool_inputs import ToolInputError, _file
    from p11lab.tool_downloads import _target
    base = {'path': 'rust/rustc.tar.xz', 'sha256': 'a' * 64, 'size': 1, 'kind': 'proxy-rust-dist',
            'url': 'https://static.rust-lang.org/dist/2026-09-03/rustc-1.98.1-x86_64-unknown-linux-gnu.tar.xz'}
    _file(base)
    _target(base['url'])
    for url in (base['url'] + '?token=x', base['url'].replace('rustc-', 'rustfmt-'),
                base['url'].replace('1.98.1', 'stable')):
        with pytest.raises(ToolInputError):
            _file(base | {'url': url})


def test_protobuf_redirect_is_fixed_and_receipt_strips_signed_query():
    import time
    from p11lab.tool_downloads import _ProxyProtobufRedirects, _protobuf_final_origin
    from p11lab.tool_inputs import ToolInputError, _file
    from urllib.request import Request
    initial = 'https://github.com/protocolbuffers/protobuf/releases/download/v36.1/protoc-36.1-linux-x86_64.zip'
    final = 'https://release-assets.githubusercontent.com/github-production-release-asset/23357588/da3acdab-6782-435e-bd24-7bff8471a65e?sig=secret'
    _file({'kind': 'proxy-protobuf', 'path': 'protoc.zip', 'url': initial, 'size': 1, 'sha256': 'a' * 64})
    redirect = _ProxyProtobufRedirects(time.monotonic() + 10, origin=initial)
    request = Request(initial)
    request.timeout = 10
    assert redirect.redirect_request(request, None, 302, 'Found', {}, final).full_url == final
    assert _protobuf_final_origin(final) == 'https://release-assets.githubusercontent.com'
    with pytest.raises(ToolInputError):
        _protobuf_final_origin(final.replace('release-assets.githubusercontent.com', 'evil.example'))


def test_crate_preserves_common_punctuation_in_filenames(tmp_path):
    raw = archive(member='src/example.repr(C)@0.2.rs')
    lock_bytes = lock(raw)
    inputs = tmp_path / 'archives'
    inputs.mkdir()
    (inputs / 'demo-1.2.3.crate').write_bytes(raw)
    output = tmp_path / 'vendor'
    proxy_inputs.materialize_locked_crates(lock_bytes, digest(lock_bytes), inputs, output)
    assert (output / 'demo-1.2.3/src/example.repr(C)@0.2.rs').read_bytes() == b'fixture'


def test_offline_receipt_rejects_final_origin_from_another_tool_family(tmp_path, monkeypatch):
    from p11lab import tool_inputs
    record = {'path': 'package.deb', 'url': 'https://snapshot.debian.org/archive/debian/20260918T000000Z/package.deb',
              'sha256': 'a' * 64, 'size': 1, 'kind': 'binary'}
    lock = {'schema_version': 1}
    expected = {'schema_version': 1, 'elapsed_seconds': 0, 'observations': []}
    receipt = {'schema_version': 1, 'elapsed_seconds': 0,
               'observations': [{'path': record['path'], 'sha256': record['sha256'], 'size': 1,
                                 'final_url': 'https://static.rust-lang.org/dist/2026-09-03/rustc-1.98.1-x86_64-unknown-linux-gnu.tar.xz'}]}
    path = tmp_path / 'resolved-inputs.json'
    path.write_text(json.dumps(receipt))
    monkeypatch.setattr(tool_inputs, '_checked_load', lambda *_: (lock, 'b' * 64))
    monkeypatch.setattr(tool_inputs, '_records', lambda _: [record])
    monkeypatch.setattr(tool_inputs, '_receipt', lambda *_: expected)
    monkeypatch.setattr(tool_inputs, '_verify_tree', lambda *_, **__: None)
    with pytest.raises(tool_inputs.ToolInputError):
        tool_inputs.verify_resolved_tool_inputs('consumer', target='debian13-amd64', receipt_path=path)


def test_materialized_vendor_verification_detects_drift_and_extra_files(tmp_path):
    raw = archive()
    lock_bytes = lock(raw)
    inputs = tmp_path / 'archives'
    inputs.mkdir()
    (inputs / 'demo-1.2.3.crate').write_bytes(raw)
    output = tmp_path / 'vendor'
    proxy_inputs.materialize_locked_crates(lock_bytes, digest(lock_bytes), inputs, output)
    result = proxy_inputs.verify_materialized_crates(lock_bytes, digest(lock_bytes), inputs, output)
    assert result['status'] == 'verified-materialized-inputs-only'
    (output / 'demo-1.2.3/src/lib.rs').write_bytes(b'mutated')
    with pytest.raises(proxy_inputs.ProxyInputError):
        proxy_inputs.verify_materialized_crates(lock_bytes, digest(lock_bytes), inputs, output)
    (output / 'demo-1.2.3/src/lib.rs').write_bytes(b'fixture')
    (output / 'extra').write_bytes(b'x')
    with pytest.raises(proxy_inputs.ProxyInputError):
        proxy_inputs.verify_materialized_crates(lock_bytes, digest(lock_bytes), inputs, output)


def test_packaged_tool_roster_exposes_typed_immutable_inputs():
    from p11lab.tool_downloads import ProxyInputRecord
    records = proxy_inputs.load_proxy_tool_records()
    assert len(records) == 286
    assert all(type(record) is ProxyInputRecord for record in records)
    assert sum(record.kind == 'proxy-crate' for record in records) == 282
    assert sum(record.kind == 'proxy-rust-dist' for record in records) == 3
    assert sum(record.kind == 'proxy-protobuf' for record in records) == 1


def test_typed_proxy_payload_verifier_rehashes_bytes(tmp_path):
    from p11lab.tool_downloads import ProxyInputRecord
    data = b'opaque bytes'
    record = ProxyInputRecord('rust/rustc.tar.xz',
        'https://static.rust-lang.org/dist/2026-09-03/rustc-1.98.1-x86_64-unknown-linux-gnu.tar.xz',
        digest(data), len(data), 'proxy-rust-dist')
    (tmp_path / 'rust').mkdir()
    path = tmp_path / record.path
    path.write_bytes(data)
    assert proxy_inputs.verify_proxy_payload(record, tmp_path)['sha256'] == digest(data)
    path.write_bytes(b'other bytes!')
    with pytest.raises(proxy_inputs.ProxyInputError):
        proxy_inputs.verify_proxy_payload(record, tmp_path)


def test_resolution_rejects_source_mismatch_before_tool_download(tmp_path, monkeypatch):
    from p11lab import tool_downloads
    calls = tmp_path / 'calls'
    def fake_download(record, destination, **kwargs):
        calls.write_text(record.kind)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(b'bad source')
        return {'sha256': digest(b'bad source'), 'size': 10, 'final_url': record.url}
    monkeypatch.setattr(tool_downloads, 'download_proxy_file', fake_download)
    output = tmp_path / 'attempt'
    with pytest.raises(proxy_inputs.ProxyInputError):
        proxy_inputs.resolve_selected_proxy_inputs(output, debian_receipt=tmp_path / 'not-used')
    assert calls.read_text() == 'proxy-source'
    assert not (output / 'resolved-proxy-inputs.json').exists()


def test_selected_git_commit_object_binds_exact_tree():
    source = proxy_inputs.load_proxy_source_selection()
    assert git_hash('commit', source.commit_object) == source.commit
    assert source.commit_object.startswith(('tree ' + source.tree + '\n').encode())


def test_installed_rust_signature_evidence_is_rehashed(monkeypatch):
    original = proxy_inputs.package_data
    class Altered:
        def read_bytes(self):
            return b'altered key'
    monkeypatch.setattr(proxy_inputs, 'package_data', lambda path: Altered() if path.endswith('rust-key.gpg.ascii') else original(path))
    with pytest.raises(proxy_inputs.ProxyInputError):
        proxy_inputs.load_proxy_tool_records()


def test_source_rejects_hidden_nonzero_tar_after_terminator():
    import gzip
    raw, roster, tree = source_fixture()
    hostile = gzip.compress(gzip.decompress(raw) + b'X' * 512)
    with pytest.raises(proxy_inputs.ProxyInputError):
        proxy_inputs.inspect_source_members(hostile, digest(hostile), 'source', tree, roster)


def test_crate_rejects_hidden_nonzero_tar_after_terminator(tmp_path):
    import gzip
    raw = gzip.compress(gzip.decompress(archive()) + b'X' * 512)
    lock_bytes = lock(raw)
    inputs = tmp_path / 'archives'
    inputs.mkdir()
    (inputs / 'demo-1.2.3.crate').write_bytes(raw)
    with pytest.raises(proxy_inputs.ProxyInputError):
        proxy_inputs.materialize_locked_crates(lock_bytes, digest(lock_bytes), inputs, tmp_path / 'vendor')


def test_build_selection_is_explicit_and_not_build_evidence():
    plan = proxy_inputs.load_proxy_build_selection()
    assert plan['target'] == 'x86_64-unknown-linux-gnu'
    assert plan['profile'] == 'release'
    assert plan['features'] == 'default'
    assert plan['build_status'] == 'not-run'
    assert 'RUSTC_WRAPPER' in plan['environment_must_clear']


def test_crate_materialization_preserves_and_verifies_file_permissions(tmp_path):
    import stat
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode='w:gz') as tar:
        info = tarfile.TarInfo('demo-1.2.3/build.sh')
        info.mode, info.size = 0o755, 1
        tar.addfile(info, io.BytesIO(b'x'))
    raw = result.getvalue()
    lock_bytes = lock(raw)
    inputs = tmp_path / 'archives'
    inputs.mkdir()
    (inputs / 'demo-1.2.3.crate').write_bytes(raw)
    output = tmp_path / 'vendor'
    proxy_inputs.materialize_locked_crates(lock_bytes, digest(lock_bytes), inputs, output)
    path = output / 'demo-1.2.3/build.sh'
    assert stat.S_IMODE(path.stat().st_mode) == 0o755
    path.chmod(0o644)
    with pytest.raises(proxy_inputs.ProxyInputError):
        proxy_inputs.verify_materialized_crates(lock_bytes, digest(lock_bytes), inputs, output)


def test_offline_provenance_requires_complete_selected_origin_observations(tmp_path):
    from p11lab.proxy_inputs import load_proxy_source_selection, load_proxy_tool_records

    selection = load_proxy_source_selection()
    records = load_proxy_tool_records()
    receipt = {
        "source_observation": {
            "sha256": selection.archive_sha256,
            "size": selection.archive_size,
            "final_url": "https://codeload.github.com/mingulov/pkcs11-proxy-ng/tar.gz/"
            + selection.commit,
        },
        "observations": [
            {
                "path": r.path,
                "size": r.size,
                "sha256": r.sha256,
                "final_url": "https://release-assets.githubusercontent.com"
                if r.kind == "proxy-protobuf"
                else r.url,
            }
            for r in records
        ],
    }
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps(receipt))
    assert (
        proxy_inputs.verify_proxy_acquisition_receipt(path)["selected_origin"]
        == "receipt-consistent-unattested"
    )
    assert proxy_inputs.verify_proxy_acquisition_receipt(path)["attempt_completion"] == "unconfirmed"
    provisional = {"schema": "p11lab.proxy-input-observations.v1", "state": "provisional", "manifest": receipt}
    path.write_text(json.dumps(provisional))
    checked = proxy_inputs.verify_proxy_acquisition_receipt(path)
    assert checked["attempt_completion"] == "unconfirmed"
    assert checked["acquisition_provenance"] == "unattested-provisional-observation"
    for state in ("completed", "unknown"):
        altered_provisional = provisional | {"state": state}
        path.write_text(json.dumps(altered_provisional))
        with pytest.raises(proxy_inputs.ProxyInputError):
            proxy_inputs.verify_proxy_acquisition_receipt(path)
    path.write_text(json.dumps(provisional | {"schema": "p11lab.proxy-input-observations.v2"}))
    with pytest.raises(proxy_inputs.ProxyInputError):
        proxy_inputs.verify_proxy_acquisition_receipt(path)
    incomplete_manifest = receipt | {"observations": receipt["observations"][:-1]}
    path.write_text(json.dumps(provisional | {"manifest": incomplete_manifest}))
    with pytest.raises(proxy_inputs.ProxyInputError):
        proxy_inputs.verify_proxy_acquisition_receipt(path)
    for mutation in ("missing", "wrong-origin", "wrong-sha", "missing-url", "extra"):
        altered = json.loads(json.dumps(receipt))
        if mutation == "missing":
            altered["observations"].pop()
        if mutation == "wrong-origin":
            altered["observations"][0]["final_url"] = (
                "https://static.crates.io/crates/demo/demo-1.0.crate"
            )
        if mutation == "wrong-sha":
            altered["observations"][0]["sha256"] = "a" * 64
        if mutation == "missing-url":
            del altered["observations"][0]["final_url"]
        if mutation == "extra":
            altered["observations"].append(altered["observations"][0])
        path.write_text(json.dumps(altered))
        with pytest.raises((proxy_inputs.ProxyInputError, ValueError)):
            proxy_inputs.verify_proxy_acquisition_receipt(path)


def test_offline_cache_defaults_to_explicit_byte_only_state(monkeypatch, tmp_path):
    from types import SimpleNamespace
    from p11lab import tool_inputs

    selection = SimpleNamespace(
        commit="a", tree="b", archive_sha256="c", cargo_lock_sha256="d"
    )
    source = SimpleNamespace(
        selection=selection, lock_bytes=b"", workspace={}, links={}
    )
    monkeypatch.setattr(proxy_inputs, "verify_selected_proxy_source", lambda _: source)
    monkeypatch.setattr(proxy_inputs, "load_proxy_tool_records", lambda: ())
    monkeypatch.setattr(proxy_inputs, "_registry_roster", lambda *args: {})
    monkeypatch.setattr(
        proxy_inputs, "verify_materialized_crates", lambda *args, **kw: {}
    )
    monkeypatch.setattr(proxy_inputs, "load_proxy_build_selection", lambda: {})
    monkeypatch.setattr(
        tool_inputs,
        "verify_resolved_tool_inputs",
        lambda *args, **kw: {"lock_sha256": "e"},
    )
    monkeypatch.setattr(
        tool_inputs, "load_tool_input_lock", lambda *args, **kw: {"base_image": "base"}
    )
    monkeypatch.setattr(tool_inputs, "_verify_debian_inputs", lambda *args: None)
    cache = proxy_inputs.ProxyInputCache(
        tmp_path / "source",
        tmp_path / "payload",
        tmp_path / "vendor",
        tmp_path / "debian",
    )
    result = proxy_inputs.verify_selected_proxy_inputs(cache)
    assert result["byte_verification"] == "verified"
    assert result["selected_origin"] == "unverified-no-acquisition-receipt"
    assert result["protoc_signer"] == "unverified"
    assert result["authority"] == "not-established"


def _fake_resolver_setup(monkeypatch, tmp_path, fail_stage):
    from types import SimpleNamespace
    from p11lab import tool_downloads

    selection = SimpleNamespace(
        commit="a" * 40,
        archive_sha256="b" * 64,
        archive_size=1,
        cargo_lock_sha256="c" * 64,
    )
    records = [
        tool_downloads.ProxyInputRecord(
            f"crates/demo-{n}.crate",
            f"https://static.crates.io/crates/demo/demo-{n}.crate",
            str(n) * 64,
            1,
            "proxy-crate",
        )
        for n in (1, 2)
    ]
    source = SimpleNamespace(selection=selection, lock_bytes=b"lock", workspace={})
    monkeypatch.setattr(proxy_inputs, "load_proxy_source_selection", lambda: selection)
    monkeypatch.setattr(proxy_inputs, "load_proxy_tool_records", lambda: tuple(records))
    monkeypatch.setattr(
        proxy_inputs,
        "_registry_roster",
        lambda *args: {"demo-1": "1" * 64, "demo-2": "2" * 64},
    )

    def download(record, destination, **kwargs):
        destination.parent.mkdir(parents=True, exist_ok=True)
        if fail_stage == "download" and record.path.endswith("demo-2.crate"):
            destination.with_name(destination.name + ".part").write_bytes(b"x")
            raise OSError(13, "secret=NEVER-RETAIN /private/path")
        destination.write_bytes(b"x")
        return {"size": record.size, "sha256": record.sha256, "final_url": record.url}

    monkeypatch.setattr(tool_downloads, "download_proxy_file", download)

    def source_verify(path):
        if fail_stage == "cpu-timeout":
            import os
            import time

            (tmp_path / "worker-pid").write_text(str(os.getpid()))
            time.sleep(10)
        return source

    monkeypatch.setattr(proxy_inputs, "verify_selected_proxy_source", source_verify)
    monkeypatch.setattr(
        proxy_inputs, "materialize_locked_crates", lambda *args, **kw: None
    )
    if fail_stage == "verification":

        def fail(*args):
            raise RuntimeError("secret=NEVER-RETAIN /private/path")

        monkeypatch.setattr(proxy_inputs, "verify_selected_proxy_inputs", fail)


@pytest.mark.parametrize("stage", ["download", "verification"])
def test_failed_resolver_retains_sanitized_incremental_attempt(
    tmp_path, monkeypatch, stage
):
    _fake_resolver_setup(monkeypatch, tmp_path, stage)
    output = tmp_path / "attempt"
    with pytest.raises(proxy_inputs.ProxyInputError):
        proxy_inputs.resolve_selected_proxy_inputs(
            output, debian_receipt=tmp_path / "debian", timeout_seconds=3
        )
    journal = (output / "attempt.jsonl").read_text()
    events = [json.loads(line) for line in journal.splitlines()]
    assert any(
        event.get("event") == "download-complete"
        and event.get("path") == "crates/demo-1.crate"
        for event in events
    )
    assert events[-1]["event"] == "terminal" and events[-1]["status"] == "failed"
    assert events[-1]["stage"] == stage and events[-1]["error_kind"] in {
        "os-error",
        "internal-error",
    }
    if stage == "download":
        assert events[-1]["native_errno"] == 13
    assert all(event["attempt_id"] == events[0]["attempt_id"] for event in events)
    assert "NEVER-RETAIN" not in journal and "/private/path" not in journal
    assert len(journal.encode()) <= 1024 * 1024
    assert not (output / "resolved-proxy-inputs.json").exists()
    if stage == "download":
        assert (output / "payload/crates/demo-2.crate.part").exists()


def test_whole_resolver_timeout_kills_and_reaps_cpu_worker(tmp_path, monkeypatch):
    import os
    import time

    _fake_resolver_setup(monkeypatch, tmp_path, "cpu-timeout")
    output = tmp_path / "attempt"
    started = time.monotonic()
    with pytest.raises(TimeoutError):
        proxy_inputs.resolve_selected_proxy_inputs(
            output, debian_receipt=tmp_path / "debian", timeout_seconds=0.5
        )
    assert time.monotonic() - started < 3
    pid = int((tmp_path / "worker-pid").read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)
    with pytest.raises(ChildProcessError):
        os.waitpid(pid, os.WNOHANG)
    events = [
        json.loads(line) for line in (output / "attempt.jsonl").read_text().splitlines()
    ]
    assert events[-1]["event"] == "terminal" and events[-1]["status"] == "timeout"
    assert (
        events[-1]["worker_reaped"] is True
        and events[-1]["stage"] == "source-verification"
    )
    assert not (output / "resolved-proxy-inputs.json").exists()


def test_proxy_worker_bounds_ipc_and_reaps_its_descendant(tmp_path):
    import os
    import time
    from p11lab.proxy_supervisor import (
        ProxyDeadlineExceeded,
        ProxyWorkerError,
        run_proxy_worker,
    )

    with pytest.raises(ProxyWorkerError) as oversized:
        run_proxy_worker(
            lambda: {"payload": "x" * (3 * 1024 * 1024)}, deadline=time.monotonic() + 3
        )
    assert oversized.value.category == "ipc-limit" and oversized.value.worker_reaped
    marker = tmp_path / "descendant"

    def blocked():
        child = os.fork()
        if child == 0:
            time.sleep(10)
            os._exit(0)
        marker.write_text(str(child))
        time.sleep(10)
        return {}

    with pytest.raises(ProxyDeadlineExceeded) as timeout:
        run_proxy_worker(blocked, deadline=time.monotonic() + 0.5)
    assert timeout.value.worker_reaped
    child = int(marker.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(child, 0)
    with pytest.raises(ChildProcessError):
        os.waitpid(child, os.WNOHANG)


def test_successful_resolver_retains_provisional_manifest_and_reaps_workers(
    tmp_path, monkeypatch
):
    import os

    _fake_resolver_setup(monkeypatch, tmp_path, "success")
    monkeypatch.setattr(
        proxy_inputs,
        "verify_selected_proxy_inputs",
        lambda cache: {"status": "partial-input-bytes-verified"},
    )
    monkeypatch.setattr(
        proxy_inputs,
        "_validate_acquisition_observations",
        lambda receipt: {"selected_origin": "receipt-consistent-unattested"},
    )
    output = tmp_path / "attempt"
    result = proxy_inputs.resolve_selected_proxy_inputs(
        output, debian_receipt=tmp_path / "debian", timeout_seconds=3
    )
    saved = json.loads((output / "proxy-inputs-provisional.json").read_text())
    assert saved["schema"] == "p11lab.proxy-input-observations.v1" and saved["state"] == "provisional"
    assert saved["manifest"] == {key: value for key, value in result.items() if key != "finalization_supervision"}
    assert result["supervision"]["worker_reaped"] is True
    assert result["finalization_supervision"]["worker_reaped"] is True
    pid = result["supervision"]["worker_pid"]
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)
    with pytest.raises(ChildProcessError):
        os.waitpid(pid, os.WNOHANG)
    events = [
        json.loads(line) for line in (output / "attempt.jsonl").read_text().splitlines()
    ]
    assert events[-1]["status"] == "provisional" and events[-1]["worker_pid"] == pid
    assert events[-1]["reaper_cleanup"] == "unconfirmed"
    assert events[-1]["acquisition_reaper_cleanup"] == "confirmed"
    assert events[-1]["stage"] == "verification"


def test_journal_failure_does_not_report_success_or_hide_uncertainty(
    tmp_path, monkeypatch
):
    _fake_resolver_setup(monkeypatch, tmp_path, "success")
    original = proxy_inputs._journal

    def fail(root, attempt_id, event, started, **fields):
        if event == "download-complete":
            raise OSError("secret never retain")
        if event == "terminal":
            raise OSError("secret never retain")
        return original(root, attempt_id, event, started, **fields)

    monkeypatch.setattr(proxy_inputs, "_journal", fail)
    output = tmp_path / "attempt"
    with pytest.raises(proxy_inputs.ProxyInputError) as failure:
        proxy_inputs.resolve_selected_proxy_inputs(
            output, debian_receipt=tmp_path / "debian", timeout_seconds=3
        )
    assert "journal/cleanup status unavailable" in " ".join(
        getattr(failure.value, "__notes__", [])
    )
    assert "secret" not in str(failure.value)
    assert not (output / "resolved-proxy-inputs.json").exists()


def test_resolver_deadline_also_bounds_receipt_finalization(tmp_path, monkeypatch):
    import os
    import time

    _fake_resolver_setup(monkeypatch, tmp_path, "success")
    monkeypatch.setattr(
        proxy_inputs,
        "verify_selected_proxy_inputs",
        lambda cache: {"status": "partial-input-bytes-verified"},
    )
    monkeypatch.setattr(
        proxy_inputs,
        "_validate_acquisition_observations",
        lambda receipt: {"selected_origin": "receipt-consistent-unattested"},
    )

    def blocked(*args, **kwargs):
        (tmp_path / "finalizer-pid").write_text(str(os.getpid()))
        time.sleep(10)
        return {}

    monkeypatch.setattr(proxy_inputs, "_finish_attempt", blocked)
    output = tmp_path / "attempt"
    started = time.monotonic()
    with pytest.raises(TimeoutError):
        proxy_inputs.resolve_selected_proxy_inputs(
            output, debian_receipt=tmp_path / "debian", timeout_seconds=0.5
        )
    assert time.monotonic() - started < 3
    pid = int((tmp_path / "finalizer-pid").read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)
    with pytest.raises(ChildProcessError):
        os.waitpid(pid, os.WNOHANG)
    events = [
        json.loads(line) for line in (output / "attempt.jsonl").read_text().splitlines()
    ]
    assert events[-1]["event"] == "terminal" and events[-1]["status"] == "timeout"
    assert events[-1]["stage"] == "finalization"
    assert not (output / "resolved-proxy-inputs.json").exists()


def test_finalization_timeout_keeps_only_provisional_observations(tmp_path, monkeypatch):
    import time
    from p11lab import receipts

    _fake_resolver_setup(monkeypatch, tmp_path, "success")
    monkeypatch.setattr(
        proxy_inputs,
        "verify_selected_proxy_inputs",
        lambda cache: {"status": "partial-input-bytes-verified"},
    )
    monkeypatch.setattr(
        proxy_inputs,
        "_validate_acquisition_observations",
        lambda receipt: {"selected_origin": "receipt-consistent-unattested"},
    )

    def blocked_write(path, record):
        path.write_text(json.dumps(record))
        time.sleep(10)

    monkeypatch.setattr(receipts, "write_receipt", blocked_write)
    output = tmp_path / "attempt"
    with pytest.raises(TimeoutError):
        proxy_inputs.resolve_selected_proxy_inputs(
            output, debian_receipt=tmp_path / "debian", timeout_seconds=0.5
        )
    assert not (output / "resolved-proxy-inputs.json").exists()
    assert json.loads((output / "proxy-inputs-provisional.json").read_text())["state"] == "provisional"
    events = [
        json.loads(line) for line in (output / "attempt.jsonl").read_text().splitlines()
    ]
    assert events[-1]["status"] == "timeout" and events[-1]["stage"] == "finalization"


def test_finalizer_error_after_publication_keeps_only_provisional_observations(tmp_path, monkeypatch):
    from p11lab import receipts
    from p11lab.proxy_supervisor import ProxyWorkerError

    _fake_resolver_setup(monkeypatch, tmp_path, "success")
    monkeypatch.setattr(proxy_inputs, "verify_selected_proxy_inputs", lambda cache: {"status": "partial-input-bytes-verified"})
    monkeypatch.setattr(proxy_inputs, "_validate_acquisition_observations", lambda receipt: {"selected_origin": "receipt-consistent-unattested"})
    original = receipts.write_receipt

    def publish_then_fail(path, record):
        original(path, record)
        raise OSError(13, "private diagnostic")

    monkeypatch.setattr(receipts, "write_receipt", publish_then_fail)
    output = tmp_path / "attempt"
    with pytest.raises(ProxyWorkerError) as error:
        proxy_inputs.resolve_selected_proxy_inputs(output, debian_receipt=tmp_path / "debian", timeout_seconds=3)
    assert error.value.native_errno == 13 and error.value.worker_reaped is True
    assert not (output / "resolved-proxy-inputs.json").exists()
    assert json.loads((output / "proxy-inputs-provisional.json").read_text())["state"] == "provisional"
    events = [json.loads(line) for line in (output / "attempt.jsonl").read_text().splitlines()]
    assert events[-1]["status"] == "failed" and events[-1]["native_errno"] == 13
    assert all(event.get("status") != "completed" for event in events)


@pytest.mark.parametrize("operation", ["completed", "timeout"])
def test_finalizer_lock_contention_never_leaves_success_evidence(tmp_path, monkeypatch, operation):
    import os
    import threading
    import time
    from p11lab import process, receipts
    from p11lab.proxy_supervisor import ProxyCleanupUnconfirmed

    _fake_resolver_setup(monkeypatch, tmp_path, "success")
    monkeypatch.setattr(proxy_inputs, "verify_selected_proxy_inputs", lambda cache: {"status": "partial-input-bytes-verified"})
    monkeypatch.setattr(proxy_inputs, "_validate_acquisition_observations", lambda receipt: {"selected_origin": "receipt-consistent-unattested"})
    original_write = receipts.write_receipt
    marker, held = tmp_path / "written", tmp_path / "held"
    release = threading.Event()
    initial = process._reaper_users

    def holder():
        end = time.monotonic() + 3
        while not marker.exists() and time.monotonic() < end:
            time.sleep(0.005)
        if marker.exists():
            with process._reaper_lock:
                held.write_text("held")
                release.wait(10)

    def write_then_contend(path, record):
        original_write(path, record)
        marker.write_text(str(os.getpid()))
        end = time.monotonic() + 3
        while not held.exists() and time.monotonic() < end:
            time.sleep(0.005)
        if operation == "timeout":
            time.sleep(10)

    monkeypatch.setattr(receipts, "write_receipt", write_then_contend)
    thread = threading.Thread(target=holder)
    thread.start()
    output = tmp_path / "attempt"
    started = time.monotonic()
    try:
        with pytest.raises(ProxyCleanupUnconfirmed) as failure:
            proxy_inputs.resolve_selected_proxy_inputs(output, debian_receipt=tmp_path / "debian", timeout_seconds=0.7)
        assert time.monotonic() - started < 4
        assert failure.value.operation_category == operation
        assert failure.value.worker_pid == int(marker.read_text()) and failure.value.worker_reaped is True
        assert failure.value.wait_status is not None
        events = [json.loads(line) for line in (output / "attempt.jsonl").read_text().splitlines()]
        assert any(event.get("event") == "download-complete" for event in events)
        assert not (output / "resolved-proxy-inputs.json").exists()
        provisional = json.loads((output / "proxy-inputs-provisional.json").read_text())
        assert provisional["state"] == "provisional" and provisional["schema"] == "p11lab.proxy-input-observations.v1"
        assert not any(event.get("event") == "terminal" and event.get("status") == "completed" for event in events)
        assert events[-1].get("reaper_cleanup") != "confirmed"
    finally:
        release.set()
        thread.join(timeout=2)
        if process._reaper_users == initial + 1:
            process._subreaper(False)
    assert not thread.is_alive() and process._reaper_users == initial


def test_successful_worker_kills_and_reaps_same_group_descendant(tmp_path):
    import os
    import time
    from p11lab.proxy_supervisor import run_proxy_worker
    marker = tmp_path / 'child-pid'
    def action():
        child = os.fork()
        if child == 0:
            os.closerange(3, 1024)
            time.sleep(10)
            os._exit(0)
        marker.write_text(str(child))
        return {'state': 'finished'}
    witness = run_proxy_worker(action, deadline=time.monotonic() + 3, include_witness=True)
    assert witness['group_cleanup'] == 'confirmed' and witness['worker_reaped'] is True
    child = int(marker.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(child, 0)
    with pytest.raises(ChildProcessError):
        os.waitpid(child, os.WNOHANG)


def test_untrusted_signed_query_is_not_written_to_journal(tmp_path, monkeypatch):
    from p11lab import tool_downloads
    _fake_resolver_setup(monkeypatch, tmp_path, 'success')
    def download(record, destination, **kwargs):
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(b'x')
        return {'size': record.size, 'sha256': record.sha256, 'final_url': record.url + '?sig=NEVER-RETAIN'}
    monkeypatch.setattr(tool_downloads, 'download_proxy_file', download)
    output = tmp_path/'attempt'
    with pytest.raises(proxy_inputs.ProxyInputError):
        proxy_inputs.resolve_selected_proxy_inputs(output, debian_receipt=tmp_path/'debian', timeout_seconds=3)
    journal = (output/'attempt.jsonl').read_text()
    assert 'NEVER-RETAIN' not in journal and '?sig=' not in journal
    assert json.loads(journal.splitlines()[-1])['status'] == 'failed'


def test_proxy_worker_abnormal_signal_is_reaped_and_not_success():
    import os
    import signal
    import time
    from p11lab.proxy_supervisor import ProxyWorkerError, run_proxy_worker
    def crash():
        os.kill(os.getpid(), signal.SIGKILL)
        return {}
    with pytest.raises(ProxyWorkerError) as failure:
        run_proxy_worker(crash, deadline=time.monotonic() + 3)
    assert failure.value.category == 'worker-exit'
    assert failure.value.worker_reaped is True
    assert os.WIFSIGNALED(failure.value.wait_status)
    assert os.WTERMSIG(failure.value.wait_status) == signal.SIGKILL


def test_supervisor_setup_failure_reaps_spawned_worker(tmp_path, monkeypatch):
    import os
    import time
    from p11lab.proxy_supervisor import run_proxy_worker
    marker = tmp_path/'worker'
    def action():
        marker.write_text(str(os.getpid()))
        time.sleep(10)
        return {}
    def fail_setup(fd, blocking):
        time.sleep(0.2)
        raise OSError('injected setup failure')
    monkeypatch.setattr(os, 'set_blocking', fail_setup)
    try:
        with pytest.raises(OSError):
            run_proxy_worker(action, deadline=time.monotonic() + 1)
        pid = int(marker.read_text())
        with pytest.raises(ProcessLookupError):
            os.kill(pid, 0)
        with pytest.raises(ChildProcessError):
            os.waitpid(pid, os.WNOHANG)
    finally:
        if marker.exists():
            pid = int(marker.read_text())
            try:
                os.kill(pid, 9)
            except ProcessLookupError:
                pass
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass


def test_subreaper_setup_contention_respects_acquisition_deadline(tmp_path):
    import threading
    import time
    from p11lab import process
    from p11lab.proxy_supervisor import ProxyDeadlineExceeded, run_proxy_worker

    ready = threading.Event()
    release = threading.Event()

    def holder():
        with process._reaper_lock:
            ready.set()
            release.wait(0.8)

    thread = threading.Thread(target=holder)
    thread.start()
    assert ready.wait(2)
    marker = tmp_path / "worker-started"
    started = time.monotonic()
    try:
        with pytest.raises(ProxyDeadlineExceeded) as error:
            run_proxy_worker(
                lambda: {"value": marker.write_text("started")}, deadline=started + 0.1
            )
        assert time.monotonic() - started < 0.5
        assert error.value.worker_pid == 0 and not marker.exists()
    finally:
        release.set()
        thread.join(timeout=2)
    assert not thread.is_alive()


@pytest.mark.parametrize("operation", ["complete", "timeout"])
def test_subreaper_release_contention_is_bounded_and_preserves_worker_status(
    tmp_path, operation
):
    import os
    import threading
    import time
    from p11lab import process
    from p11lab.proxy_supervisor import ProxyWorkerError, run_proxy_worker

    initial_users = process._reaper_users
    ready = tmp_path / "worker-ready"
    locked = tmp_path / "lock-held"
    release = threading.Event()

    def holder():
        end = time.monotonic() + 2
        while not ready.exists() and time.monotonic() < end:
            time.sleep(0.005)
        with process._reaper_lock:
            locked.write_text("held")
            release.wait(0.8)

    thread = threading.Thread(target=holder)
    thread.start()

    def action():
        ready.write_text(str(os.getpid()))
        end = time.monotonic() + 2
        while not locked.exists() and time.monotonic() < end:
            time.sleep(0.005)
        if operation == "timeout":
            time.sleep(10)
        return {"completed": True}

    started = time.monotonic()
    try:
        with pytest.raises(ProxyWorkerError) as error:
            run_proxy_worker(
                action,
                deadline=started + (0.2 if operation == "timeout" else 2),
                include_witness=True,
            )
        assert time.monotonic() - started < 0.7
        assert error.value.category == "subreaper-release-unconfirmed"
        assert error.value.worker_reaped is True and error.value.worker_pid == int(
            ready.read_text()
        )
        assert error.value.operation_category == (
            "timeout" if operation == "timeout" else "completed"
        )
        with pytest.raises(ProcessLookupError):
            os.kill(error.value.worker_pid, 0)
        with pytest.raises(ChildProcessError):
            os.waitpid(error.value.worker_pid, os.WNOHANG)
    finally:
        release.set()
        thread.join(timeout=2)
        if process._reaper_users == initial_users + 1:
            process._subreaper(False)
    assert not thread.is_alive() and process._reaper_users == initial_users


def test_bounded_reaper_lease_preserves_ordinary_nested_ownership():
    import time
    from p11lab import process

    initial = process._reaper_users
    process._subreaper(True)
    try:
        process._subreaper(True, deadline=time.monotonic() + 1)
        assert process._reaper_users == initial + 2
        process._subreaper(False, deadline=time.monotonic() + 1)
        assert process._reaper_users == initial + 1
    finally:
        process._subreaper(False)
    assert process._reaper_users == initial


def test_bounded_restore_failure_retains_lease_until_explicit_retry(monkeypatch):
    import ctypes
    import time
    from p11lab import process

    assert process._reaper_users == 0

    class FakeLibc:
        fail_restore = True

        def prctl(self, command, arg, *rest):
            if command == 37:
                arg._obj.value = 0
            if command == 36 and arg == 0 and self.fail_restore:
                return 1
            return 0

    fake = FakeLibc()
    monkeypatch.setattr(ctypes, "CDLL", lambda *args, **kwargs: fake)
    process._subreaper(True, deadline=time.monotonic() + 1)
    try:
        with pytest.raises(OSError):
            process._subreaper(False, deadline=time.monotonic() + 1)
        assert process._reaper_users == 1
    finally:
        fake.fail_restore = False
        process._subreaper(False, deadline=time.monotonic() + 1)
    assert process._reaper_users == 0


@pytest.mark.parametrize("operation", ["completed", "timeout"])
def test_resolver_records_unconfirmed_reaper_release_and_no_receipt(
    tmp_path, monkeypatch, operation
):
    import threading
    import time
    from p11lab import process
    from p11lab.proxy_supervisor import ProxyCleanupUnconfirmed

    _fake_resolver_setup(monkeypatch, tmp_path, "success")
    marker = tmp_path / "verify-ready"
    held = tmp_path / "lock-held"
    release = threading.Event()
    initial = process._reaper_users

    def holder():
        end = time.monotonic() + 2
        while not marker.exists() and time.monotonic() < end:
            time.sleep(0.005)
        with process._reaper_lock:
            held.write_text("held")
            release.wait(0.8)

    thread = threading.Thread(target=holder)
    thread.start()

    def verify(cache):
        marker.write_text("ready")
        end = time.monotonic() + 2
        while not held.exists() and time.monotonic() < end:
            time.sleep(0.005)
        if operation == "timeout":
            time.sleep(10)
        return {"status": "partial-input-bytes-verified"}

    monkeypatch.setattr(proxy_inputs, "verify_selected_proxy_inputs", verify)
    monkeypatch.setattr(
        proxy_inputs,
        "_validate_acquisition_observations",
        lambda receipt: {"selected_origin": "receipt-consistent-unattested"},
    )
    output = tmp_path / "attempt"
    try:
        with pytest.raises(ProxyCleanupUnconfirmed) as failure:
            proxy_inputs.resolve_selected_proxy_inputs(
                output,
                debian_receipt=tmp_path / "debian",
                timeout_seconds=0.35 if operation == "timeout" else 2,
            )
        assert (
            failure.value.operation_category == operation
            and failure.value.worker_reaped is True
        )
        events = [
            json.loads(line)
            for line in (output / "attempt.jsonl").read_text().splitlines()
        ]
        assert events[-1]["status"] == (
            "timeout" if operation == "timeout" else "failed"
        )
        assert events[-1]["reaper_cleanup"] == "unconfirmed"
        assert (
            events[-1]["worker_pid"] == failure.value.worker_pid
            and events[-1]["worker_reaped"] is True
        )
        assert not (output / "resolved-proxy-inputs.json").exists()
    finally:
        release.set()
        thread.join(timeout=2)
        if process._reaper_users == initial + 1:
            process._subreaper(False)
    assert not thread.is_alive() and process._reaper_users == initial


def test_resolver_reports_journal_uncertainty_if_reaper_lock_stays_contended(tmp_path, monkeypatch):
    import threading
    import time
    from p11lab import process
    from p11lab.proxy_supervisor import ProxyCleanupUnconfirmed
    _fake_resolver_setup(monkeypatch, tmp_path, 'success')
    marker, held = tmp_path/'verify-ready', tmp_path/'lock-held'
    release = threading.Event()
    initial = process._reaper_users
    def holder():
        end = time.monotonic() + 2
        while not marker.exists() and time.monotonic() < end:
            time.sleep(0.005)
        with process._reaper_lock:
            held.write_text('held')
            release.wait(10)
    thread = threading.Thread(target=holder)
    thread.start()
    def verify(cache):
        marker.write_text('ready')
        end = time.monotonic() + 2
        while not held.exists() and time.monotonic() < end:
            time.sleep(0.005)
        return {'status': 'partial-input-bytes-verified'}
    monkeypatch.setattr(proxy_inputs, 'verify_selected_proxy_inputs', verify)
    monkeypatch.setattr(proxy_inputs, '_validate_acquisition_observations', lambda receipt: {'selected_origin': 'receipt-consistent-unattested'})
    output = tmp_path/'attempt'
    started = time.monotonic()
    try:
        with pytest.raises(ProxyCleanupUnconfirmed) as failure:
            proxy_inputs.resolve_selected_proxy_inputs(output, debian_receipt=tmp_path/'debian', timeout_seconds=2)
        assert time.monotonic() - started < 4
        assert failure.value.worker_reaped is True and failure.value.lease_cleanup == 'unconfirmed'
        assert 'journal/cleanup status unavailable' in ' '.join(getattr(failure.value, '__notes__', []))
        events = [json.loads(line) for line in (output/'attempt.jsonl').read_text().splitlines()]
        assert events[-1]['event'] == 'verification-complete'
        assert not (output/'resolved-proxy-inputs.json').exists()
    finally:
        release.set()
        thread.join(timeout=2)
        if process._reaper_users == initial + 1:
            process._subreaper(False)
    assert not thread.is_alive() and process._reaper_users == initial


def test_no_worker_started_if_lease_setup_finishes_after_deadline(tmp_path, monkeypatch):
    import time
    from p11lab import process, proxy_supervisor
    initial = process._reaper_users
    original = process._subreaper
    marker = tmp_path/'worker-started'
    def delayed(acquire, *, deadline=None):
        original(acquire, deadline=deadline)
        if acquire:
            time.sleep(0.15)
    def forbidden(*args, **kwargs):
        marker.write_text('started')
        return {'result': {}, 'worker_pid': 0, 'worker_reaped': True, 'wait_status': 0}
    monkeypatch.setattr(process, '_subreaper', delayed)
    monkeypatch.setattr(proxy_supervisor, '_run_proxy_worker', forbidden)
    with pytest.raises(proxy_supervisor.ProxyDeadlineExceeded):
        proxy_supervisor.run_proxy_worker(lambda: {}, deadline=time.monotonic()+0.1)
    assert not marker.exists() and process._reaper_users == initial


def test_release_uncertainty_keeps_worker_cleanup_evidence_after_setup_error(tmp_path, monkeypatch):
    import os
    import threading
    import time
    from p11lab import process, proxy_supervisor
    initial = process._reaper_users
    ready, held = tmp_path/'worker-ready', tmp_path/'lock-held'
    release = threading.Event()
    def holder():
        end = time.monotonic() + 2
        while not ready.exists() and time.monotonic() < end:
            time.sleep(0.005)
        with process._reaper_lock:
            held.write_text('held')
            release.wait(0.8)
    thread = threading.Thread(target=holder)
    thread.start()
    def action():
        ready.write_text(str(os.getpid()))
        time.sleep(10)
        return {}
    def fail_setup(fd, blocking):
        end = time.monotonic() + 2
        while not held.exists() and time.monotonic() < end:
            time.sleep(0.005)
        raise OSError(13, 'secret ignored')
    monkeypatch.setattr(os, 'set_blocking', fail_setup)
    try:
        with pytest.raises(proxy_supervisor.ProxyCleanupUnconfirmed) as failure:
            proxy_supervisor.run_proxy_worker(action, deadline=time.monotonic()+2)
        assert failure.value.worker_pid == int(ready.read_text())
        assert failure.value.worker_reaped is True
        assert failure.value.wait_status is not None
        assert failure.value.native_errno == 13
        assert 'secret ignored' not in str(failure.value)
    finally:
        release.set()
        thread.join(timeout=2)
        if process._reaper_users == initial+1:
            process._subreaper(False)
    assert not thread.is_alive() and process._reaper_users == initial
