"""Integrity failures must prevent qualified source/context results."""
import hashlib
import io
from pathlib import Path
import subprocess
import tarfile

import pytest

from p11lab.sources import SourceError, acquire_source, apply_patches
from p11lab.build import BuildError, validate_context


def archive(tmp_path, content=b'original\n'):
    path = tmp_path / 'input.tar'
    with tarfile.open(path, 'w') as out:
        entry = tarfile.TarInfo('tree/data.txt')
        entry.size = len(content)
        out.addfile(entry, io.BytesIO(content))
    return path


def test_archive_checksum_mismatch_is_fatal_before_extraction(tmp_path):
    path = archive(tmp_path)
    with pytest.raises(SourceError, match='checksum'):
        acquire_source({'kind': 'archive', 'url': path.as_uri(), 'sha256': '0' * 64}, tmp_path / 'out')
    assert not (tmp_path / 'out/tree').exists()


def test_verified_archive_retains_original_and_extracts(tmp_path):
    path = archive(tmp_path)
    result = acquire_source({'kind': 'archive', 'url': path.as_uri(), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}, tmp_path / 'out')
    assert Path(result['archive']).read_bytes() == path.read_bytes()
    assert (Path(result['checkout']) / 'tree/data.txt').read_bytes() == b'original\n'


def test_wrong_git_checkout_sha_is_fatal(tmp_path):
    repo = tmp_path / 'repo'
    repo.mkdir()
    subprocess.run(['git', 'init', '-q', str(repo)], check=True)
    (repo / 'data').write_text('real')
    subprocess.run(['git', '-C', str(repo), 'add', 'data'], check=True)
    subprocess.run(['git', '-C', str(repo), '-c', 'user.name=Test', '-c', 'user.email=test@example.org', 'commit', '-qm', 'fixture'], check=True)
    with pytest.raises(SourceError, match='checkout|revision'):
        acquire_source({'kind': 'git', 'url': repo.as_uri(), 'revision': 'a' * 40}, tmp_path / 'out')


def test_failed_ordered_patch_keeps_failure_and_no_qualified_result(tmp_path):
    tree = tmp_path / 'tree'
    tree.mkdir()
    (tree / 'data').write_text('old\n')
    good = tmp_path / 'good.patch'
    good.write_text('--- a/data\n+++ b/data\n@@ -1 +1 @@\n-old\n+new\n')
    bad = tmp_path / 'bad.patch'
    bad.write_text('--- a/data\n+++ b/data\n@@ -1 +1 @@\n-absent\n+oops\n')
    with pytest.raises(SourceError, match='patch'):
        apply_patches(tree, [good, bad])
    assert (tree / 'data').read_text() == 'new\n'


def test_unlisted_context_file_is_fatal(tmp_path):
    (tmp_path / 'Dockerfile').write_text('FROM scratch\n')
    (tmp_path / 'credentials').write_text('private')
    with pytest.raises(BuildError, match='undeclared'):
        validate_context(tmp_path, {'Dockerfile': hashlib.sha256((tmp_path / 'Dockerfile').read_bytes()).hexdigest()})


def test_changed_context_asset_is_fatal(tmp_path):
    (tmp_path / 'Dockerfile').write_text('FROM scratch\n')
    with pytest.raises(BuildError, match='checksum'):
        validate_context(tmp_path, {'Dockerfile': '0' * 64})


def test_archive_cannot_escape_destination(tmp_path):
    path = tmp_path / 'evil.tar'
    with tarfile.open(path, 'w') as out:
        entry = tarfile.TarInfo('../escaped')
        entry.size = 1
        out.addfile(entry, io.BytesIO(b'x'))
    with pytest.raises(SourceError, match='archive'):
        acquire_source({'kind': 'archive', 'url': path.as_uri(), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}, tmp_path / 'out')
    assert not (tmp_path / 'escaped').exists()


def test_shared_runtime_asset_rejects_unknown_scope(tmp_path):
    from p11lab.catalog import CatalogError, locked_asset
    with pytest.raises(CatalogError, match='scope'):
        locked_asset('softhsm2', {'scope': 'workspace', 'path': 'common.sh'}, asset_root=tmp_path)


def test_shared_runtime_asset_cannot_escape_root(tmp_path):
    from p11lab.catalog import CatalogError, locked_asset
    with pytest.raises(CatalogError, match='relative'):
        locked_asset('softhsm2', {'scope': 'runtime', 'path': '../providers/softhsm2/provider.json'}, asset_root=tmp_path)


def test_shared_runtime_asset_uses_packaged_root_not_staging_root(tmp_path):
    from p11lab.catalog import locked_asset
    (tmp_path / 'common.sh').write_text('untrusted local override')
    asset = locked_asset('softhsm2', {'scope': 'runtime', 'path': 'common.sh'}, asset_root=tmp_path)
    assert b'untrusted local override' not in asset.read_bytes()
    assert asset.is_file()


def test_planned_environment_cannot_emit_artifact(tmp_path):
    import copy
    from p11lab.catalog import CatalogError, load_environment
    from p11lab.build import build_artifact
    # No planned channels remain in the locked cohort; graft the retired
    # stub shape onto a locked environment to keep the gate covered.
    spec = load_environment('softhsm2', 'release')
    planned = {
        'status': 'planned',
        'source': {
            'kind': 'git',
            'url': 'https://example.org/token.git',
            'selector': {'kind': 'tag', 'value': '0.27.1'},
            'license_status': 'unreviewed',
            'revision': 'c' * 40,
            'license_observation': 'synthetic planned-channel fixture',
        },
        'pending': 'synthetic planned channel for gate tests',
    }
    spec['channels']['release'] = copy.deepcopy(planned)
    spec['channel_spec'] = copy.deepcopy(planned)
    spec.pop('lock', None)
    with pytest.raises(CatalogError, match='locked'):
        build_artifact(spec, 'runtime', tmp_path / 'output')
    assert not (tmp_path / 'output/artifact.json').exists()


def test_actual_inventory_rejects_unexpected_package():
    from p11lab.build import verify_inventory
    expected = [{'name': 'libc6', 'version': '2', 'architecture': 'amd64', 'source_package': 'glibc', 'source_version': '2'}]
    with pytest.raises(BuildError, match='inventory'):
        verify_inventory('libc6\t2\tamd64\tglibc\t2\npython3\t3\tamd64\tpython3\t3\n', expected)


def test_actual_inventory_requires_exact_source_identity():
    from p11lab.build import verify_inventory
    expected = [{'name': 'libc6', 'version': '2', 'architecture': 'amd64', 'source_package': 'glibc', 'source_version': '2'}]
    with pytest.raises(BuildError, match='inventory'):
        verify_inventory('libc6\t2\tamd64\tglibc\t1\n', expected)


@pytest.mark.parametrize('operation', ['resolve', 'build'])
def test_cli_locked_operation_rejects_unlocked_channel_without_output(operation, tmp_path, capsys):
    from p11lab.cli import main
    output = tmp_path / 'attempt'
    # pkcs11rs release has no tag (unavailable); the last planned stub is
    # locked, and both unlocked dispositions share the locked-inputs gate.
    assert main([operation, 'pkcs11rs', '--channel', 'release', '--output-dir', str(output)]) == 2
    assert 'locked' in capsys.readouterr().err
    assert not output.exists()


def test_cli_build_rejects_unsupported_role_before_output(tmp_path, capsys):
    from p11lab.cli import main
    output = tmp_path / 'attempt'
    with pytest.raises(SystemExit) as status:
        main(['build', 'softhsm2', '--channel', 'release', '--role', 'proxy', '--output-dir', str(output)])
    assert status.value.code == 2
    assert 'proxy' in capsys.readouterr().err
    assert not output.exists()


def make_git_fixture(tmp_path):
    repo = tmp_path / 'repo'
    repo.mkdir()
    subprocess.run(['git', 'init', '-q', str(repo)], check=True)
    (repo / 'data').write_text('real')
    subprocess.run(['git', '-C', str(repo), 'add', 'data'], check=True)
    subprocess.run(['git', '-C', str(repo), '-c', 'user.name=Test', '-c', 'user.email=test@example.org', 'commit', '-qm', 'fixture'], check=True)
    revision = subprocess.run(['git', '-C', str(repo), 'rev-parse', 'HEAD'], check=True, capture_output=True, text=True).stdout.strip()
    return repo, revision


def test_git_archive_must_match_declared_content_hash(tmp_path):
    repo, revision = make_git_fixture(tmp_path)
    with pytest.raises(SourceError, match='checksum'):
        acquire_source({'kind': 'git', 'url': repo.as_uri(), 'revision': revision, 'archive_sha256': '0' * 64}, tmp_path / 'out')
    assert not (tmp_path / 'out/checkout').exists()


def test_successful_fetch_of_wrong_checkout_sha_is_rejected(tmp_path, monkeypatch):
    # Simulate a transport returning a valid but different commit; extraction must
    # still depend on the independent rev-parse result, not fetch's exit status.
    import p11lab.sources as sources
    repo, revision = make_git_fixture(tmp_path)
    real_command = sources._command
    def redirected(argv, **kwargs):
        if 'fetch' in argv:
            argv = argv[:-1] + [revision]
        return real_command(argv, **kwargs)
    monkeypatch.setattr(sources, '_command', redirected)
    with pytest.raises(SourceError, match='revision mismatch'):
        acquire_source({'kind': 'git', 'url': repo.as_uri(), 'revision': 'a' * 40}, tmp_path / 'out')
    assert not (tmp_path / 'out/source.tar').exists()


def test_signed_index_receipt_must_match_expected_hashes():
    from p11lab.build import verify_index_inventory
    with pytest.raises(BuildError, match='index'):
        verify_index_inventory('a' * 64 + '  trixie_InRelease\n', [{'filename': 'trixie_InRelease', 'sha256': 'b' * 64}])


def test_shared_adapter_change_changes_runtime_build_key():
    import copy
    from p11lab.catalog import load_environment
    from p11lab.build import runtime_inputs
    from p11lab.identity import artifact_key
    spec = load_environment('softhsm2', 'release')
    altered = copy.deepcopy(spec)
    common = next(a for a in altered['lock']['assets'] if a['role'] == 'adapter-common')
    common['sha256'] = 'e' * 64
    assert artifact_key('runtime', runtime_inputs(spec)) != artifact_key('runtime', runtime_inputs(altered))


def test_build_metadata_cannot_substitute_other_engine_digest():
    from p11lab.build import verify_build_metadata
    with pytest.raises(BuildError, match='engine'):
        verify_build_metadata({'containerimage.config.digest': 'sha256:' + 'a' * 64, 'containerimage.digest': 'sha256:' + 'b' * 64}, 'sha256:' + 'c' * 64)


@pytest.mark.parametrize('engine_id', ['sha256:' + 'a' * 64, 'sha256:' + 'b' * 64])
def test_build_metadata_supports_classic_config_and_current_index_engine_ids(engine_id):
    from p11lab.build import verify_build_metadata
    verify_build_metadata({'containerimage.config.digest': 'sha256:' + 'a' * 64, 'containerimage.digest': 'sha256:' + 'b' * 64}, engine_id)


def test_build_metadata_without_optional_config_keeps_exact_output_binding():
    from p11lab.build import verify_build_metadata
    verify_build_metadata({'containerimage.digest': 'sha256:' + 'b' * 64}, 'sha256:' + 'b' * 64)


def test_metadata_descriptor_platform_must_match_runtime():
    from p11lab.build import verify_build_metadata
    metadata = {'containerimage.digest': 'sha256:' + 'b' * 64, 'containerimage.descriptor': {'digest': 'sha256:' + 'b' * 64, 'platform': {'os': 'linux', 'architecture': 'arm64'}}}
    with pytest.raises(BuildError, match='platform'):
        verify_build_metadata(metadata, 'sha256:' + 'b' * 64, 'linux/amd64')


def test_checked_readback_failure_is_a_build_error_with_attempt_and_stderr(tmp_path):
    import sys
    from p11lab.build import _checked
    with pytest.raises(BuildError) as raised:
        _checked([sys.executable, '-c', 'import sys; sys.stderr.write("readback unavailable"); sys.exit(29)'], tmp_path)
    text = str(raised.value)
    assert '29' in text and 'readback unavailable' in text and str(tmp_path) in text
