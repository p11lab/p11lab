"""Independent source transport fixtures; no registry/rights/runtime qualification."""
import copy
import hashlib
import io
import json
import shutil
import tarfile
from dataclasses import asdict
from pathlib import Path

import pytest

from p11lab import publish, sources
from p11lab.models import ArtifactRef


def sha(data):
    return hashlib.sha256(data).hexdigest()


def document(path, value):
    path.write_text(json.dumps(value, sort_keys=True) + '\n')
    return path


def content_fixture(tmp_path, *, build_key=None):
    # Independent, deliberately tiny binary and reviewed-source declarations.
    binary = tmp_path / 'binary.tar'
    with tarfile.open(binary, 'w') as tar:
        entry = tarfile.TarInfo('demo.txt')
        entry.size = 4
        tar.addfile(entry, io.BytesIO(b'demo'))
    artifact = ArtifactRef('bundle', str(binary), sha(binary.read_bytes()), 'linux/amd64')
    payloads = []
    for name, role, data in [('sources/demo.tar', 'source', b'complete source'),
                             ('notices/grant.txt', 'notice', b'original grant'),
                             ('BUILD.md', 'build', b'portable instructions')]:
        path = tmp_path / name.replace('/', '-')
        path.write_bytes(data)
        payloads.append(dict(path=name, role=role, local_path=str(path), sha256=sha(data), size=len(data)))
    inventory = dict(schema_version=1, artifact=asdict(artifact), role='runtime',
        observation=dict(artifact=asdict(artifact), packages=[], binaries=[], linked_libraries=[],
                         files=[dict(path='/demo.txt', sha256=sha(b'demo'), size=4, mode=420, package=None)]),
        content_reviews=[dict(path='/demo.txt', sha256=sha(b'demo'), source='demo=1', status='reviewed')],
        sources=[dict(id='demo=1', name='demo', version='1', payloads=['sources/demo.tar'])],
        components=[dict(id='demo=1', source='demo=1', scope='runtime')],
        reviews=[dict(source='demo=1', status='reviewed', grant_known=True, source_redistribution=True,
                      license_declared='MIT', license_concluded='MIT', chosen_route='retain grant',
                      notices=['notices/grant.txt'], grant_evidence=['notices/grant.txt'],
                      obligations=['source', 'notice'], modifications='unmodified')],
        patches=[], payloads=payloads, build_instructions='BUILD.md', limitations=[])
    if build_key is not None:
        inventory['build_key'] = build_key
    producer = tmp_path / 'producer'
    sources.collect_source_bundle(artifact, inventory, producer)
    pulled = tmp_path / 'pulled'
    pulled.mkdir()
    for name in publish.CONTENT_FILES:
        shutil.copyfile(producer / name, pulled / name)
    manifest = oci_manifest(tmp_path / 'manifest.json', pulled, publish.CONTENT_FILES)
    transcript = tmp_path / 'transcript.log'
    transcript.write_bytes(b'fixture transcript, no transport authentication\n')
    return dict(expected_receipt_path=producer / 'source-companion.json', pulled_dir=pulled,
                source_manifest_path=manifest, source_manifest_digest=sha(manifest.read_bytes()),
                registry='ghcr.io/p11lab/softhsm2', artifact=artifact, transcript_path=transcript,
                extract_dir=tmp_path / 'extracted')


def oci_manifest(path, root, roster):
    return document(path, {'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.manifest.v1+json',
        'layers': [{'mediaType': media, 'digest': 'sha256:' + sha((root / name).read_bytes()),
                    'size': (root / name).stat().st_size,
                    'annotations': {'org.opencontainers.image.title': name}} for name, media in roster.items()]})


def test_content_readback_binds_actual_archive_receipt_spdx_and_scope(tmp_path):
    args = content_fixture(tmp_path)
    proof = publish.verify_content_readback(**args)
    assert proof['role'] == 'content-readback-proof'
    assert proof['schema_version'] == 1
    assert proof['artifact']['sha256'] == args['artifact'].sha256
    assert proof['reference'] == args['registry'] + '@sha256:' + args['source_manifest_digest']
    assert proof['manifest_sha256'] == args['source_manifest_digest']
    assert proof['file_sha256'] == sha((args['pulled_dir'] / 'source-companion.tar.gz').read_bytes())
    assert proof['receipt_sha256'] == sha(args['expected_receipt_path'].read_bytes())
    assert proof['spdx_sha256'] == sha((args['pulled_dir'] / 'sbom.spdx.json').read_bytes())
    assert proof['inventory_sha256'] == sha((args['extract_dir'] / 'inventory.json').read_bytes())
    assert proof['transport_authentication'] == 'unverified'
    assert proof['publication_status'] == 'blocked'
    assert 'anonymous_source_available' not in proof
    assert json.loads((tmp_path / 'content-readback-proof.json').read_text()) == proof
    assert str(tmp_path) not in json.dumps(proof)


@pytest.mark.parametrize('damage', ['missing', 'extra', 'duplicate', 'title', 'media', 'size', 'digest',
                                   'manifest-digest', 'symlink', 'directory', 'extra-file', 'archive',
                                   'receipt', 'spdx', 'transcript', 'artifact', 'platform'])
def test_content_readback_refuses_changed_or_unsafe_transport(tmp_path, damage):
    args = content_fixture(tmp_path)
    manifest = json.loads(args['source_manifest_path'].read_text())
    if damage == 'missing':
        manifest['layers'].pop()
    elif damage == 'extra':
        manifest['layers'].append(dict(manifest['layers'][0], annotations={'org.opencontainers.image.title': 'extra'}))
    elif damage == 'duplicate':
        manifest['layers'].append(copy.deepcopy(manifest['layers'][0]))
    elif damage == 'title':
        manifest['layers'][0]['annotations']['org.opencontainers.image.title'] = '../source-companion.tar.gz'
    elif damage == 'media':
        manifest['layers'][0]['mediaType'] = 'application/octet-stream'
    elif damage == 'size':
        manifest['layers'][0]['size'] += 1
    elif damage == 'digest':
        manifest['layers'][0]['digest'] = 'sha256:' + 'f' * 64
    elif damage == 'manifest-digest':
        args['source_manifest_digest'] = 'f' * 64
    elif damage in {'symlink', 'directory'}:
        path = args['pulled_dir'] / 'sbom.spdx.json'
        path.unlink()
        if damage == 'symlink':
            path.symlink_to(args['expected_receipt_path'].parent / 'sbom.spdx.json')
        else:
            path.mkdir()
    elif damage == 'extra-file':
        (args['pulled_dir'] / 'runtime.tar').write_bytes(b'not source')
    elif damage in {'archive', 'receipt', 'spdx'}:
        name = {'archive': 'source-companion.tar.gz', 'receipt': 'source-companion.json', 'spdx': 'sbom.spdx.json'}[damage]
        with (args['pulled_dir'] / name).open('ab') as stream:
            stream.write(b'corrupt')
    elif damage == 'transcript':
        args['transcript_path'].write_bytes(b'')
    elif damage == 'artifact':
        args['artifact'] = ArtifactRef('bundle', args['artifact'].reference, 'f' * 64, 'linux/amd64')
    elif damage == 'platform':
        args['artifact'] = ArtifactRef('bundle', args['artifact'].reference, args['artifact'].sha256, 'linux/arm64')
    if damage in {'missing', 'extra', 'duplicate', 'title', 'media', 'size', 'digest'}:
        document(args['source_manifest_path'], manifest)
        args['source_manifest_digest'] = sha(args['source_manifest_path'].read_bytes())
    with pytest.raises(publish.PublishError):
        publish.verify_content_readback(**args)
    assert not (tmp_path / 'content-readback-proof.json').exists()


def historical_handoff():
    registry = 'ghcr.io/p11lab/softhsm2'
    return dict(schema_version=1, registry=registry,
        catalogue=dict(environment='softhsm2', channel='release', runtime_role='runtime'),
        source=dict(reference=registry + '@sha256:' + 'a'*64, manifest_sha256='a'*64, file_sha256='b'*64, tag='src'),
        binary=dict(kind='docker-local', reference=registry + '@sha256:' + 'c'*64,
                    manifest_sha256='c'*64, engine_id='sha256:' + 'd'*64, tag='rt'),
        admission=dict(status='eligible', blockers=[]), readback={}, producer={}, exposure={})


def test_historical_v1_display_is_separate_from_acquisition(tmp_path):
    value = historical_handoff()
    assert publish.show_handoff(document(tmp_path / 'historical.json', value)) == value
    with pytest.raises(publish.PublishError, match='schema.*2|schema.*v2'):
        publish.require_eligible_handoff(value)


def test_v2_cannot_self_authorize_source_transport_or_full_image_promotion(tmp_path):
    value = historical_handoff()
    value['schema_version'] = 2
    value['source']['content_companion'] = dict(reference=value['registry'] + '@sha256:' + 'e'*64,
        manifest_sha256='e'*64, file_sha256='1'*64, receipt_sha256='2'*64,
        spdx_sha256='3'*64, readback_proof_sha256='4'*64)
    value['admission'].update(content_status='eligible', source_readback_status='verified',
                              anonymous_source_available=True, image_promotable=True)
    assert publish.show_handoff(document(tmp_path / 'v2.json', value)) == value
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(value)
    assert str(info.value) == 'authenticated source transport evidence unavailable; acquisition blocked'
    del value['admission']['anonymous_source_available']
    del value['admission']['image_promotable']
    with pytest.raises(publish.PublishError) as stripped:
        publish.require_eligible_handoff(value)
    assert str(stripped.value) == str(info.value)


def _v2_eligible_handoff():
    value = historical_handoff()
    value['schema_version'] = 2
    value['source']['content_companion'] = dict(reference=value['registry'] + '@sha256:' + 'e'*64,
        manifest_sha256='e'*64, file_sha256='1'*64, receipt_sha256='2'*64,
        spdx_sha256='3'*64, readback_proof_sha256='4'*64)
    value['admission'].update(content_status='eligible', source_readback_status='verified')
    return value


def test_r2_evidence_cannot_rescue_ineligible_admission(tmp_path, monkeypatch):
    from pathlib import Path as _Path
    from test_acquisition import fixture_context, fixture_profile, make_evidence, stub_verifier
    profile = fixture_profile()
    value = _v2_eligible_handoff()
    value['admission'].update(status='blocked', blockers=['not eligible'])
    evidence = make_evidence(tmp_path, context=fixture_context(profile, _v2_eligible_handoff()))
    stub_verifier(monkeypatch, profile)
    fixtures = _Path(__file__).parent / 'fixtures' / 'acquisition'
    with pytest.raises(publish.PublishError, match='handoff admission is not eligible'):
        publish.require_eligible_handoff(value, evidence,
            executable=fixtures / 'verifier' / 'verify-fixture.sh',
            trusted_root=evidence / 'trusted-root.jsonl',
            output_dir=tmp_path / 'verify-out')


def test_r3_evidence_cannot_rescue_incomplete_readback(tmp_path, monkeypatch):
    from pathlib import Path as _Path
    from test_acquisition import fixture_context, fixture_profile, make_evidence, stub_verifier
    profile = fixture_profile()
    value = _v2_eligible_handoff()
    value['admission'].update(source_readback_status='missing')
    evidence = make_evidence(tmp_path, context=fixture_context(profile, _v2_eligible_handoff()))
    stub_verifier(monkeypatch, profile)
    fixtures = _Path(__file__).parent / 'fixtures' / 'acquisition'
    with pytest.raises(publish.PublishError,
                       match='handoff requires complete source/content readback admission'):
        publish.require_eligible_handoff(value, evidence,
            executable=fixtures / 'verifier' / 'verify-fixture.sh',
            trusted_root=evidence / 'trusted-root.jsonl',
            output_dir=tmp_path / 'verify-out')


def test_r9_valid_transport_evidence_still_refuses_promotion(tmp_path, monkeypatch):
    from pathlib import Path as _Path
    from test_acquisition import fixture_context, fixture_profile, make_evidence, stub_verifier
    profile = fixture_profile()
    value = _v2_eligible_handoff()
    evidence = make_evidence(tmp_path, context=fixture_context(profile, value))
    stub_verifier(monkeypatch, profile)
    fixtures = _Path(__file__).parent / 'fixtures' / 'acquisition'
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(value, evidence,
            executable=fixtures / 'verifier' / 'verify-fixture.sh',
            trusted_root=evidence / 'trusted-root.jsonl',
            output_dir=tmp_path / 'verify-out')
    assert str(info.value) == 'full image validation/promotion integration unavailable; acquisition blocked'
    assert 'authenticated source transport' not in str(info.value)


@pytest.mark.parametrize('damage', ['missing', 'extra-field', 'repository', 'digest', 'self-digest'])
def test_v2_content_summary_is_exact_and_same_repository(tmp_path, damage):
    value = historical_handoff()
    value['schema_version'] = 2
    content = dict(reference=value['registry'] + '@sha256:' + 'e'*64, manifest_sha256='e'*64,
                   file_sha256='1'*64, receipt_sha256='2'*64, spdx_sha256='3'*64, readback_proof_sha256='4'*64)
    value['source']['content_companion'] = content
    if damage == 'missing':
        del content['receipt_sha256']
    elif damage == 'extra-field':
        content['approved'] = True
    elif damage == 'repository':
        content['reference'] = 'ghcr.io/p11lab/other@sha256:' + 'e'*64
    elif damage == 'digest':
        content['manifest_sha256'] = 'f'*64
    else:
        content['self_digest'] = '5'*64
    with pytest.raises(publish.PublishError):
        publish.show_handoff(document(tmp_path / 'bad.json', value))


def admit_fixture(tmp_path):
    from test_publish import seal_fixture, build_receipt_for, readback_proof_for, pushed_manifest_for, admission_inventory
    spec, receipt, sealed = seal_fixture(tmp_path)
    artifact, inventory = admission_inventory(tmp_path)
    evidence = tmp_path / 'evidence'
    sources.collect_source_bundle(artifact, inventory, evidence)
    digest, manifest = pushed_manifest_for(tmp_path)
    return dict(artifact_kind=artifact.kind, artifact_reference=artifact.reference, artifact_digest=artifact.sha256,
        platform=artifact.platform, sealed_receipt_path=tmp_path / 'seal/sealed-source.json', sealed_manifest=sealed,
        readback_proof=readback_proof_for(tmp_path, spec, receipt, sealed),
        build_receipt_path=build_receipt_for(tmp_path, spec, receipt, sealed, artifact=asdict(artifact)),
        spec=spec, registry='ghcr.io/p11lab/softhsm2', evidence_dir=evidence,
        out_dir=tmp_path / 'admission', producer={'p11lab_wheel_sha256': 'ab'*32},
        source_manifest_digest=digest, source_manifest_path=manifest)


def test_local_content_eligibility_cannot_grant_delivery_without_complete_readback(tmp_path):
    args = admit_fixture(tmp_path)
    result = publish.admit(**args)
    assert result['status'] == 'blocked'
    assert any('complete-content' in reason for reason in result['blockers'])


def test_seal_admission_refuses_extra_oci_layer(tmp_path):
    args = admit_fixture(tmp_path)
    value = json.loads(args['source_manifest_path'].read_text())
    value['layers'].append({'digest': 'sha256:' + 'f'*64, 'size': 1})
    document(args['source_manifest_path'], value)
    args['source_manifest_digest'] = sha(args['source_manifest_path'].read_bytes())
    with pytest.raises(publish.PublishError, match='layer|roster'):
        publish.admit(**args)


def test_exposure_does_not_emit_new_handoff_without_full_promotion(tmp_path):
    args = admit_fixture(tmp_path)
    result = publish.admit(**args)
    admission = json.loads(Path(result['admission']).read_text())
    admission['catalogue'].update(runtime_role='native', target='debian13-amd64')
    document(Path(result['admission']), admission)
    with pytest.raises(publish.PublishError, match='validation|promotion'):
        publish.expose(admission_path=Path(result['admission']), pushed_digest='e'*64,
            pushed_tag=publish.artifact_tag('native', 'softhsm2', 'release', args['artifact_digest'], 'debian13-amd64'),
            pushed_size=100, local_inspect_path=None, pulled_inspect_path=None,
            pulled_bundle_path=Path(args['artifact_reference']), registry=args['registry'],
            out_dir=tmp_path / 'handoff')
    assert not (tmp_path / 'handoff').exists()


@pytest.mark.parametrize('damage', [None, 'engine', 'config', 'platform', 'manifest', 'repository', 'fake-index'])
def test_acquired_image_binds_manifest_config_engine_and_platform(tmp_path, damage):
    value = historical_handoff()
    config = 'e'*64
    path = document(tmp_path / 'image-manifest.json', {'schemaVersion': 2,
        'mediaType': 'application/vnd.oci.image.manifest.v1+json',
        'config': {'digest': 'sha256:' + config, 'mediaType': 'application/vnd.oci.image.config.v1+json', 'size': 100},
        'layers': []})
    digest = sha(path.read_bytes())
    value['binary'].update(manifest_sha256=digest, reference=value['registry'] + '@sha256:' + digest,
                           config_sha256=config, platform='linux/amd64')
    observed = {'Id': value['binary']['engine_id'], 'Os': 'linux', 'Architecture': 'amd64',
                'RepoDigests': [value['binary']['reference']]}
    if damage == 'engine':
        observed['Id'] = 'sha256:' + 'f'*64
    elif damage == 'config':
        value['binary']['config_sha256'] = 'f'*64
    elif damage == 'platform':
        observed['Architecture'] = 'arm64'
    elif damage == 'manifest':
        path.write_bytes(path.read_bytes() + b' ')
    elif damage == 'repository':
        observed['RepoDigests'] = ['ghcr.io/p11lab/other@sha256:' + digest]
    elif damage == 'fake-index':
        value['binary']['platform_manifest_sha256'] = digest
    if damage:
        with pytest.raises(publish.PublishError):
            publish.verify_acquired_image(value, observed, manifest_path=path)
    else:
        actual = publish.verify_acquired_image(value, observed, manifest_path=path)
        assert actual == dict(kind='docker-local', reference=value['binary']['engine_id'],
                              sha256='d'*64, platform='linux/amd64')


def full_admit_fixture(tmp_path):
    args = admit_fixture(tmp_path)
    root = tmp_path / 'complete'
    root.mkdir()
    content = content_fixture(root, build_key=args['sealed_manifest']['build_key'])
    proof = publish.verify_content_readback(**content)
    args.update(evidence_dir=content['expected_receipt_path'].parent,
        content_receipt_path=content['expected_receipt_path'], content_manifest_path=content['source_manifest_path'],
        content_manifest_digest=content['source_manifest_digest'], content_readback_proof_path=root / 'content-readback-proof.json',
        content_pulled_dir=content['pulled_dir'], content_transcript_path=content['transcript_path'])
    # Strict seal proof, reusing independently protected producer bytes.
    args['readback_proof'] = publish.verify_readback(args['sealed_receipt_path'], tmp_path / 'proof-pulled',
        transcript_path=tmp_path / 'proof-transcript.log', extract_dir=tmp_path / 'strict-seal',
        source_manifest_path=args['source_manifest_path'], source_manifest_digest=args['source_manifest_digest'],
        registry=args['registry'])
    return args, content, proof


def test_complete_content_byte_readback_is_retained_but_cannot_authenticate_transport(tmp_path):
    args, content, proof = full_admit_fixture(tmp_path)
    result = publish.admit(**args)
    value = json.loads(Path(result['admission']).read_text())
    assert value['verdict']['content_status'] == 'eligible'
    assert value['verdict']['source_readback_status'] == 'verified'
    assert value['source']['content_companion'] == {
        **{key: proof[key] for key in ('reference', 'manifest_sha256', 'file_sha256', 'receipt_sha256', 'spdx_sha256')},
        'readback_proof_sha256': sha(args['content_readback_proof_path'].read_bytes())}
    assert result['status'] == 'blocked'
    assert result['blockers'] == ['authenticated anonymous source transport integration unavailable']


@pytest.mark.parametrize('damage', ['proof', 'transcript', 'receipt', 'manifest', 'build-key', 'repository', 'local-spdx'])
def test_admission_rechecks_complete_bytes_and_proof_not_claimed_booleans(tmp_path, damage):
    args, content, proof = full_admit_fixture(tmp_path)
    if damage == 'proof':
        proof['file_sha256'] = 'f'*64
        document(args['content_readback_proof_path'], proof)
    elif damage == 'transcript':
        args['content_transcript_path'].write_bytes(b'other transcript')
    elif damage == 'receipt':
        args['content_receipt_path'].write_bytes(args['content_receipt_path'].read_bytes() + b' ')
    elif damage == 'manifest':
        args['content_manifest_digest'] = 'f'*64
    elif damage == 'build-key':
        # A complete, correctly collected/hashed companion for another build.
        root = tmp_path / 'other-build'
        root.mkdir()
        content = content_fixture(root, build_key='f'*64)
        publish.verify_content_readback(**content)
        args.update(evidence_dir=content['expected_receipt_path'].parent,
            content_receipt_path=content['expected_receipt_path'], content_manifest_path=content['source_manifest_path'],
            content_manifest_digest=content['source_manifest_digest'], content_readback_proof_path=root / 'content-readback-proof.json',
            content_pulled_dir=content['pulled_dir'], content_transcript_path=content['transcript_path'])
    elif damage == 'repository':
        args['registry'] = 'ghcr.io/p11lab/other'
    else:
        (args['evidence_dir'] / 'sbom.spdx.json').write_bytes(b'{}')
    with pytest.raises(publish.PublishError):
        publish.admit(**args)
    assert not args['out_dir'].exists()


def test_content_readback_public_cli_operation(tmp_path, capsys):
    from p11lab.cli import main
    args = content_fixture(tmp_path)
    artifact = document(tmp_path / 'artifact.json', asdict(args['artifact']))
    assert main(['publish', 'verify-content-readback', '--content-receipt', str(args['expected_receipt_path']),
        '--pulled-dir', str(args['pulled_dir']), '--source-manifest', str(args['source_manifest_path']),
        '--source-manifest-digest', args['source_manifest_digest'], '--registry', args['registry'],
        '--artifact', str(artifact), '--transcript', str(args['transcript_path']),
        '--extract-dir', str(args['extract_dir'])]) == 0
    assert json.loads(capsys.readouterr().out)['publication_status'] == 'blocked'


@pytest.mark.parametrize('ci,local_proof', [(False, False), (True, True)])
def test_action_refuses_v1_before_binary_acquisition_even_if_claimed_eligible(tmp_path, monkeypatch, ci, local_proof):
    from test_publish import _action_run_module
    module = _action_run_module()
    monkeypatch.setenv('CI', 'true' if ci else '')
    calls = []
    def fetch(argv, *, env, cwd):
        calls.append(argv)
        target = Path(argv[argv.index('-o') + 1])
        document(target / 'handoff.json', historical_handoff())
        return 0
    monkeypatch.setattr(module, '_run', fetch)
    code = module.main(['--environment', 'softhsm2', '--channel', 'release', '--mode', 'direct',
        '--registry', 'ghcr.io/p11lab/softhsm2', '--handoff-digest', 'sha256:' + 'f'*64,
        '--command', '["app"]', '--timeout', '60', '--workspace', str(tmp_path), '--working-directory', '.', '--oras', 'oras',
        '--run-dir', str(tmp_path / 'action'), *(['--local-proof'] if local_proof else [])])
    assert code == 1
    assert len(calls) == 1
    argv = calls[0]
    assert argv[0] == 'oras'
    assert argv[1] == 'pull'
    assert argv[argv.index('-o') + 1] == str(tmp_path / 'action' / 'handoff')
    assert argv[-1] == 'ghcr.io/p11lab/softhsm2@sha256:' + 'f' * 64


def test_action_refuses_v2_without_evidence_before_binary_acquisition(tmp_path, monkeypatch):
    from test_publish import _action_run_module
    module = _action_run_module()
    monkeypatch.setenv('CI', '')
    calls = []
    def fetch(argv, *, env, cwd):
        calls.append(argv)
        target = Path(argv[argv.index('-o') + 1])
        document(target / 'handoff.json', _v2_eligible_handoff())
        return 0
    monkeypatch.setattr(module, '_run', fetch)
    code = module.main(['--environment', 'softhsm2', '--channel', 'release', '--mode', 'direct',
        '--registry', 'ghcr.io/p11lab/softhsm2', '--handoff-digest', 'sha256:' + 'f'*64,
        '--command', '["app"]', '--timeout', '60', '--workspace', str(tmp_path), '--working-directory', '.', '--oras', 'oras',
        '--run-dir', str(tmp_path / 'action')])
    assert code == 1
    assert len(calls) == 1
    argv = calls[0]
    assert argv[0] == 'oras'
    assert argv[1] == 'pull'
    assert argv[argv.index('-o') + 1] == str(tmp_path / 'action' / 'handoff')
    assert argv[-1] == 'ghcr.io/p11lab/softhsm2@sha256:' + 'f' * 64


@pytest.mark.parametrize('damage', ['inner-manifest-hash', 'member-count', 'source-count', 'archive-size', 'hardlink'])
def test_seal_readback_checks_producer_metadata_and_safe_regular_files(tmp_path, damage):
    from test_publish import seal_fixture
    seal_fixture(tmp_path)
    source = tmp_path / 'seal'
    pulled = tmp_path / 'pulled'
    pulled.mkdir()
    for name in publish.SEAL_FILES:
        shutil.copyfile(source / name, pulled / name)
    receipt = json.loads((source / 'sealed-source.json').read_text())
    if damage == 'hardlink':
        path = pulled / 'sealed-source.json'
        path.unlink()
        path.hardlink_to(source / 'sealed-source.json')
    else:
        field = {'inner-manifest-hash': 'manifest_sha256', 'member-count': 'member_count',
                 'source-count': 'source_count', 'archive-size': 'size_bytes'}[damage]
        receipt[field] = 'f'*64 if field == 'manifest_sha256' else receipt[field] + 1
        document(source / 'sealed-source.json', receipt)
        shutil.copyfile(source / 'sealed-source.json', pulled / 'sealed-source.json')
    manifest = oci_manifest(tmp_path / 'oci.json', pulled, publish.SEAL_FILES)
    transcript = tmp_path / 'transcript'
    transcript.write_bytes(b'fixture')
    with pytest.raises(publish.PublishError):
        publish.verify_readback(source / 'sealed-source.json', pulled, transcript_path=transcript,
            extract_dir=tmp_path / 'extracted', source_manifest_path=manifest,
            source_manifest_digest=sha(manifest.read_bytes()), registry='ghcr.io/p11lab/softhsm2')


def rewrite_content(args, changes):
    """Produce internally rehashed malicious archives; outer checks alone suffice less."""
    archive = args['pulled_dir'] / 'source-companion.tar.gz'
    with tarfile.open(archive) as tar:
        files = {entry.name: tar.extractfile(entry).read() for entry in tar}
    changes(files)
    files['SHA256SUMS'] = ''.join(sha(data) + '  ' + name + '\n' for name, data in sorted(files.items())
                                   if name != 'SHA256SUMS').encode()
    with tarfile.open(archive, 'w:gz') as tar:
        for name, data in sorted(files.items()):
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            tar.addfile(entry, io.BytesIO(data))
    receipt = json.loads(args['expected_receipt_path'].read_text())
    receipt['artifact'].update(sha256=sha(archive.read_bytes()), reference='sha256:' + sha(archive.read_bytes()))
    receipt.update(size_bytes=archive.stat().st_size, inventory_sha256=sha(files['inventory.json']),
                   sbom_sha256=sha(files['sbom.spdx.json']))
    document(args['expected_receipt_path'], receipt)
    shutil.copyfile(args['expected_receipt_path'], args['pulled_dir'] / 'source-companion.json')
    (args['pulled_dir'] / 'sbom.spdx.json').write_bytes(files['sbom.spdx.json'])
    oci_manifest(args['source_manifest_path'], args['pulled_dir'], publish.CONTENT_FILES)
    args['source_manifest_digest'] = sha(args['source_manifest_path'].read_bytes())


@pytest.mark.parametrize('damage', ['extra-inner-file', 'spdx-inventory', 'private-path'])
def test_content_verifies_inner_inventory_roster_and_spdx_semantics(tmp_path, damage):
    args = content_fixture(tmp_path)
    def changes(files):
        if damage == 'extra-inner-file':
            files['runtime.tar'] = b'unlisted bytes'
        elif damage == 'spdx-inventory':
            value = json.loads(files['sbom.spdx.json'])
            value['packages'][0]['licenseConcluded'] = 'forged'
            files['sbom.spdx.json'] = json.dumps(value).encode()
        else:
            value = json.loads(files['inventory.json'])
            value['payloads'][0]['local_path'] = '/private/cache/source.tar'
            files['inventory.json'] = json.dumps(value).encode()
            from p11lab.licenses import spdx_inventory
            files['sbom.spdx.json'] = json.dumps(spdx_inventory(args['artifact'], value)).encode()
    rewrite_content(args, changes)
    with pytest.raises(publish.PublishError):
        publish.verify_content_readback(**args)


def test_ambiguous_json_manifest_is_rejected_even_with_matching_byte_digest(tmp_path):
    args = content_fixture(tmp_path)
    data = args['source_manifest_path'].read_text()
    # Different JSON consumers can select different occurrences of one key.
    data = data.replace('"schemaVersion": 2', '"schemaVersion": 1, "schemaVersion": 2')
    args['source_manifest_path'].write_text(data)
    args['source_manifest_digest'] = sha(args['source_manifest_path'].read_bytes())
    with pytest.raises(publish.PublishError, match='JSON|duplicate'):
        publish.verify_content_readback(**args)


@pytest.mark.parametrize('damage', [None, 'ambiguous-platform', 'child-digest', 'child-size', 'child-media', 'missing-child'])
def test_acquired_index_uses_independent_root_platform_and_config_identities(tmp_path, damage):
    value = historical_handoff()
    child = document(tmp_path / 'child.json', {'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.manifest.v1+json',
        'config': {'digest': 'sha256:' + 'e'*64}, 'layers': []})
    child_digest = sha(child.read_bytes())
    descriptor = dict(digest='sha256:' + child_digest, size=child.stat().st_size,
                      mediaType='application/vnd.oci.image.manifest.v1+json', platform=dict(os='linux', architecture='amd64'))
    index = dict(schemaVersion=2, mediaType='application/vnd.oci.image.index.v1+json', manifests=[descriptor])
    if damage == 'ambiguous-platform':
        index['manifests'].append(copy.deepcopy(descriptor))
    elif damage == 'child-digest':
        descriptor['digest'] = 'sha256:' + 'f'*64
    elif damage == 'child-size':
        descriptor['size'] += 1
    elif damage == 'child-media':
        descriptor['mediaType'] = 'application/octet-stream'
    root = document(tmp_path / 'root.json', index)
    value['binary'].update(manifest_sha256=sha(root.read_bytes()),
        reference=value['registry'] + '@sha256:' + sha(root.read_bytes()), platform='linux/amd64',
        config_sha256='e'*64, platform_manifest_sha256=child_digest)
    observed = dict(Id=value['binary']['engine_id'], Os='linux', Architecture='amd64', RepoDigests=[value['binary']['reference']])
    kwargs = dict(manifest_path=root, platform_manifest_path=None if damage == 'missing-child' else child)
    if damage:
        with pytest.raises(publish.PublishError):
            publish.verify_acquired_image(value, observed, **kwargs)
    else:
        assert publish.verify_acquired_image(value, observed, **kwargs)['reference'] == 'sha256:' + 'd'*64


@pytest.mark.parametrize('damage', [None, 'digest', 'symlink', 'hardlink', 'platform'])
def test_acquired_bundle_uses_shared_exact_byte_integrity_primitive(tmp_path, damage):
    value = historical_handoff()
    path = tmp_path / 'bundle.tar.gz'
    path.write_bytes(b'native fixture')
    value['binary'].update(kind='bundle', file_sha256=sha(path.read_bytes()), platform='linux/amd64')
    if damage == 'digest':
        path.write_bytes(b'other')
    elif damage in {'symlink', 'hardlink'}:
        source = tmp_path / 'source'
        path.rename(source)
        if damage == 'symlink':
            path.symlink_to(source)
        else:
            path.hardlink_to(source)
    elif damage == 'platform':
        value['binary']['platform'] = '../../linux'
    if damage:
        with pytest.raises(publish.PublishError):
            publish.verify_acquired_bundle(value, path)
    else:
        assert publish.verify_acquired_bundle(value, path) == dict(kind='bundle', reference=str(path.resolve()),
            sha256=sha(b'native fixture'), platform='linux/amd64')


@pytest.mark.parametrize('damage', ['engine', 'config', 'platform'])
def test_action_local_diagnostics_still_refuse_wrong_acquired_image_identity(tmp_path, monkeypatch, damage):
    from test_publish import _action_run_module
    from types import SimpleNamespace
    module = _action_run_module()
    monkeypatch.delenv('CI', raising=False)
    monkeypatch.delenv('GITHUB_ACTIONS', raising=False)
    handoff = historical_handoff()
    manifest = json.dumps(dict(schemaVersion=2, mediaType='application/vnd.oci.image.manifest.v1+json',
                               config={'digest': 'sha256:' + 'e'*64}, layers=[])).encode()
    digest = sha(manifest)
    handoff['binary'].update(manifest_sha256=digest, reference=handoff['registry'] + '@sha256:' + digest,
                            config_sha256='e'*64, platform='linux/amd64')
    observed = dict(Id=handoff['binary']['engine_id'], Os='linux', Architecture='amd64',
                    RepoDigests=[handoff['binary']['reference']])
    if damage == 'engine':
        observed['Id'] = 'sha256:' + 'f'*64
    elif damage == 'config':
        handoff['binary']['config_sha256'] = 'f'*64
    else:
        observed['Architecture'] = 'arm64'
    calls = []
    def fetch(argv, *, env, cwd):
        calls.append(argv)
        if argv[0] == 'oras':
            document(Path(argv[argv.index('-o') + 1]) / 'handoff.json', handoff)
        elif argv[:2] != ['docker', 'pull']:
            pytest.fail('application must not run after acquired identity mismatch')
        return 0
    def inspect(argv, **kwargs):
        return SimpleNamespace(returncode=0, stdout=manifest if argv[0] == 'oras' else json.dumps([observed]), stderr='')
    monkeypatch.setattr(module, '_run', fetch)
    monkeypatch.setattr(module, '_capture', inspect)
    assert module.main(['--environment', 'softhsm2', '--channel', 'release', '--mode', 'direct',
        '--registry', handoff['registry'], '--handoff-digest', 'sha256:' + 'f'*64, '--command', '["app"]',
        '--timeout', '60', '--workspace', str(tmp_path), '--working-directory', '.', '--oras', 'oras',
        '--run-dir', str(tmp_path / 'action'), '--local-proof']) == 1
    assert len(calls) == 2


@pytest.mark.parametrize('damage', ['environment', 'channel', 'reference', 'source-manifest', 'files', 'schema'])
def test_admission_refuses_changed_seal_proof_identity(tmp_path, damage):
    args, content, proof = full_admit_fixture(tmp_path)
    if damage == 'environment':
        args['readback_proof']['environment'] = 'other'
    elif damage == 'channel':
        args['readback_proof']['channel'] = 'rolling'
    elif damage == 'reference':
        args['readback_proof']['reference'] = 'ghcr.io/p11lab/other@sha256:' + args['source_manifest_digest']
    elif damage == 'source-manifest':
        args['readback_proof']['source_manifest_sha256'] = 'f'*64
    elif damage == 'files':
        args['readback_proof']['files']['sealed-source.json']['size_bytes'] += 1
    else:
        args['readback_proof']['schema_version'] = True
    result = publish.admit(**args)
    assert result['status'] == 'blocked'
    assert any('seal' in reason for reason in result['blockers'])


def test_admit_cli_threads_complete_readback_options_without_eligibility_bypass(tmp_path, capsys):
    from p11lab.cli import main
    args, content, proof = full_admit_fixture(tmp_path)
    sealed_path = document(tmp_path / 'sealed-manifest.json', args['sealed_manifest'])
    proof_path = document(tmp_path / 'seal-proof.json', args['readback_proof'])
    argv = ['publish', 'admit', 'softhsm2', '--channel', 'release', '--artifact-kind', 'bundle',
        '--artifact-reference', args['artifact_reference'], '--artifact-digest', args['artifact_digest'],
        '--platform', args['platform'], '--registry', args['registry'], '--sealed-receipt', str(args['sealed_receipt_path']),
        '--sealed-manifest', str(sealed_path), '--readback-proof', str(proof_path),
        '--build-receipt', str(args['build_receipt_path']), '--evidence-dir', str(args['evidence_dir']),
        '--output-dir', str(args['out_dir']), '--producer-wheel-sha256', 'ab'*32,
        '--source-manifest', str(args['source_manifest_path']), '--source-manifest-digest', args['source_manifest_digest'],
        '--content-receipt', str(args['content_receipt_path']), '--content-manifest', str(args['content_manifest_path']),
        '--content-manifest-digest', args['content_manifest_digest'], '--content-readback-proof', str(args['content_readback_proof_path']),
        '--content-pulled-dir', str(args['content_pulled_dir']), '--content-transcript', str(args['content_transcript_path'])]
    assert main(argv) == 3
    value = json.loads(Path(json.loads(capsys.readouterr().out)['admission']).read_text())
    assert value['verdict']['source_readback_status'] == 'verified'
    assert value['verdict']['source_transport_authentication'] == 'unverified'
    assert main(['publish', 'show-handoff', '--content-receipt', str(args['content_receipt_path'])]) == 2
    assert 'is not a publish show-handoff option' in capsys.readouterr().err


def malformed_inner_json(files, member, damage, artifact):
    """Retain malformed raw JSON while rehashing a semantically valid archive."""
    text = files[member].decode()
    if damage == 'duplicate':
        hidden = ('"payloads": [{"local_path": "/private/cache/source.tar"}],'
                  if member == 'inventory.json' else '"documentComment": "/private/cache/source.tar",')
        text = '{' + hidden + text[1:]
    elif damage == 'nested-duplicate':
        if member == 'inventory.json':
            value = '"path": "sources/demo.tar"'
            assert value in text
            text = text.replace(value, '"path": "/private/cache/source.tar", ' + value, 1)
        else:
            value = json.dumps(json.loads(text)['creationInfo']['created'])
            text = text.replace('"created": ' + value, '"created": "/private/cache/source.tar", "created": ' + value, 1)
    elif member == 'inventory.json':
        text = '{"diagnostic": ' + damage + ',' + text[1:]
    else:
        value = json.dumps(json.loads(text)['creationInfo']['created'])
        text = text.replace('"created": ' + value, '"created": ' + damage, 1)
    files[member] = text.encode()
    if member == 'inventory.json':
        # The permissive parse is intentional mutant construction: outer
        # identity and generated semantics must be valid independent controls.
        from p11lab.licenses import spdx_inventory
        files['sbom.spdx.json'] = json.dumps(spdx_inventory(artifact, json.loads(text))).encode()


@pytest.mark.parametrize('member', ['inventory.json', 'sbom.spdx.json'])
@pytest.mark.parametrize('damage', ['duplicate', 'nested-duplicate', 'NaN', 'Infinity', '-Infinity', '1e999'])
def test_rehashed_inner_json_ambiguity_refuses_content_readback(tmp_path, member, damage):
    args = content_fixture(tmp_path)
    rewrite_content(args, lambda files: malformed_inner_json(files, member, damage, args['artifact']))
    with pytest.raises(publish.PublishError, match='duplicate|nonfinite'):
        publish.verify_content_readback(**args)
    assert not (tmp_path / 'content-readback-proof.json').exists()


def test_g2b_valid_transport_and_promotion_pair_passes(tmp_path, monkeypatch):
    from test_promotion import valid_gate_args
    args = valid_gate_args(tmp_path, monkeypatch)
    assert publish.require_eligible_handoff(**args) == args['value']


def test_g2b_valid_bundle_pair_passes_delivery_matrix(tmp_path, monkeypatch):
    from test_promotion import bundle_handoff, valid_gate_args
    args = valid_gate_args(tmp_path, monkeypatch, bundle_handoff())
    assert publish.require_eligible_handoff(**args) == args['value']


def test_g2b_forged_promotion_is_refused_delivery_matrix(tmp_path, monkeypatch):
    from test_promotion import valid_gate_args
    args = valid_gate_args(tmp_path, monkeypatch, promotion_damage='cert')
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(**args)
    assert str(info.value) == 'verified certificate identity mismatch'


@pytest.mark.parametrize('damage', ['binary', 'proof'])
def test_g2b_unbound_promotion_is_refused_delivery_matrix(tmp_path, monkeypatch, damage):
    from test_promotion import (fixture_promotion_context, fixture_promotion_profile,
                                make_promotion_evidence, stub_gate_verifiers, v2p_handoff)
    from test_acquisition import fixture_context, make_evidence
    from pathlib import Path as _Path
    profile = fixture_promotion_profile()
    value = v2p_handoff()
    other = v2p_handoff()
    if damage == 'binary':
        value['binary']['manifest_sha256'] = 'f' * 64
        value['binary']['reference'] = value['registry'] + '@sha256:' + 'f' * 64
    else:
        value['source']['content_companion']['readback_proof_sha256'] = 'f' * 64
    transport = make_evidence(tmp_path, context=fixture_context(profile, value),
                              name='evidence')
    promo = make_promotion_evidence(tmp_path,
                                    context=fixture_promotion_context(profile, other))
    stub_gate_verifiers(monkeypatch, profile)
    fixtures = _Path(__file__).parent / 'fixtures' / 'acquisition'
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(
            value, transport, executable=fixtures / 'verifier' / 'verify-fixture.sh',
            trusted_root=transport / 'trusted-root.jsonl',
            output_dir=tmp_path / 'verify-out', promotion_dir=promo,
            promotion_executable=fixtures / 'verifier' / 'verify-fixture.sh',
            promotion_trusted_root=promo / 'promotion-trusted-root.jsonl',
            promotion_output_dir=tmp_path / 'promotion-out')
    assert str(info.value) == 'promotion evidence differs from the handoff digests; acquisition blocked'


def test_g2b_promotion_policy_is_refused_delivery_matrix(tmp_path, monkeypatch):
    import json as _json
    from test_promotion import (PROMO, fixture_promotion_context, fixture_promotion_profile,
                                make_promotion_evidence, stub_gate_verifiers, v2p_handoff)
    from test_acquisition import fixture_context, make_evidence
    from pathlib import Path as _Path
    profile = fixture_promotion_profile()
    value = v2p_handoff()
    transport = make_evidence(tmp_path, context=fixture_context(profile, value),
                              name='evidence')
    result = _json.loads((PROMO / 'validation-result.json').read_text())
    result['promotable'] = False
    validation = (_json.dumps(result, sort_keys=True) + '\n').encode()
    promo = make_promotion_evidence(
        tmp_path, context=fixture_promotion_context(profile, value,
                                                    validation_bytes=validation),
        validation=validation)
    stub_gate_verifiers(monkeypatch, profile)
    fixtures = _Path(__file__).parent / 'fixtures' / 'acquisition'
    with pytest.raises(publish.PublishError) as info:
        publish.require_eligible_handoff(
            value, transport, executable=fixtures / 'verifier' / 'verify-fixture.sh',
            trusted_root=transport / 'trusted-root.jsonl',
            output_dir=tmp_path / 'verify-out', promotion_dir=promo,
            promotion_executable=fixtures / 'verifier' / 'verify-fixture.sh',
            promotion_trusted_root=promo / 'promotion-trusted-root.jsonl',
            promotion_output_dir=tmp_path / 'promotion-out')
    assert str(info.value) == 'promotion validation policy mismatch; acquisition blocked'
