"""Two-envelope seal between validation.json and validation-body.json.

Hermetic light-path coverage (stdlib tarfile/hashlib plus the repo JSON
decoder): no Docker, no network. The heavy replay entry is monkeypatched
out; these tests pin the seal relationship, not replay semantics.

Mutant map: envelope-only tampers (M1/M6) must diverge from the sealed
body; body-byte swaps break the inner manifest compare (M2a) or the body
seal (M2b); a dropped body breaks the fixed roster (M3); the round trip
(M7) replays gates from the enclosed body; a missing body seal record
falls through to malformed evidence while a malformed record is rejected
(M8 split).
"""
import hashlib
import io
import json
import tarfile

import pytest

from p11lab import delivery_authority as authority
from p11lab.image_validation import _package_evidence, _seal_evidence, _source_digest
from p11lab.jsonutil import loads
from p11lab.models import ArtifactRef

# Fixed member golden duplicated from test_image_validation.py C1 plus the
# sealed body member; the round trip fails closed here if they drift.
_FIXED_NAMES = """
admission/admission.json
admission/evaluator.stderr.log
admission/evaluator.stdout.log
admission/ledger.jsonl
admission/process.json
catalog/catalog.json
checker-composition/child-inspection.json
checker-composition/child-metadata.json
checker-composition/child.json
checker-composition/composition-transfer.stderr
checker-composition/composition.json
checker-composition/composition.tar
checker-composition/parent-inspection.json
checker-composition/parent-metadata.json
checker-composition/parent.json
checker-run/application.stderr.log
checker-run/application.stdout.log
checker-run/bounded-output.tar
checker-run/checker/build-provenance.json
checker-run/checker/checker-receipt.json
checker-run/checker/checker.stderr.log
checker-run/checker/checker.stdout.log
checker-run/checker/collection.json
checker-run/checker/collection.stderr.log
checker-run/checker/collection.stdout.log
checker-run/checker/coverage.json
checker-run/checker/coverage.json.lock
checker-run/checker/provisioning.json
checker-run/checker/provisioning.json.lock
checker-run/checker/quality.json
checker-run/checker/quality.json.lock
checker-run/checker/report.jsonl
checker-run/checker/report.jsonl.lock
checker-run/checker/results.json
checker-run/checker/results.json.lock
checker-run/checker/state.json
checker-run/checker/state.json.lock
checker-run/init.stderr.log
checker-run/init.stdout.log
checker-run/post-health.stderr.log
checker-run/post-health.stdout.log
checker-run/ready.stderr.log
checker-run/ready.stdout.log
checker-run/receipt.json
consumer-composition/child-inspection.json
consumer-composition/child-metadata.json
consumer-composition/child.json
consumer-composition/composition-transfer.stderr
consumer-composition/composition.json
consumer-composition/composition.tar
consumer-composition/parent-inspection.json
consumer-composition/parent-metadata.json
consumer-composition/parent.json
consumer-run/application.stderr.log
consumer-run/application.stdout.log
consumer-run/bounded-output.tar
consumer-run/crypto/digest.bin
consumer-run/crypto/message.bin
consumer-run/crypto/public-key.der
consumer-run/crypto/public-key.pem
consumer-run/crypto/result.json
consumer-run/crypto/signature.der
consumer-run/crypto/signature.raw
consumer-run/init.stderr.log
consumer-run/init.stdout.log
consumer-run/post-health.stderr.log
consumer-run/post-health.stdout.log
consumer-run/ready.stderr.log
consumer-run/ready.stdout.log
consumer-run/receipt.json
frozen-plan.json
oracle/message/altered.bin
oracle/message/digest.bin
oracle/message/message.bin
oracle/message/public-key.der
oracle/message/public-key.pem
oracle/message/result.json
oracle/message/signature.der
oracle/message/signature.raw
oracle/oracle.json
oracle/original/digest.bin
oracle/original/message.bin
oracle/original/public-key.der
oracle/original/public-key.pem
oracle/original/result.json
oracle/original/signature.der
oracle/original/signature.raw
oracle/signature/digest.bin
oracle/signature/message.bin
oracle/signature/public-key.der
oracle/signature/public-key.pem
oracle/signature/result.json
oracle/signature/signature.der
oracle/signature/signature.raw
planning/planner.json
planning/planner.stderr.log
planning/planner.stdout.json
planning/process.json
planning/source-view/test_digest.py
planning/source-view/test_interface.py
planning/source-view/test_object.py
planning/source-view/test_session_info.py
planning/source-view/test_sign.py
evidence-manifest.json
validation-body.json
""".split()

_POLICY_SHA256 = 'd' * 64
_BUILD_KEY = 'e' * 64
_CONTROL_REVISION = 'c' * 40


def _artifact():
    return ArtifactRef('docker-local', 'sha256:' + 'a' * 64, 'a' * 64, 'linux/amd64')


def _observation():
    return {'distribution': {'config_sha256': 'b' * 64, 'layers': [{'sha256': 'c' * 64}]}}


def _controls():
    return {name: {'returncode': code, 'timed_out': False, 'cleanup': 'removed-exact-owned-container'}
            for name, code in (('positive', 0), ('altered_message', 1), ('altered_signature', 1))}


def _body_fixture(artifact):
    """Full 29-key produce-shape body; every light gate passes."""
    from p11lab.checker import load_profile
    return {
        'schema_version': 1, 'kind': 'local-image-validation', 'scope': 'local-only',
        'artifact': {'kind': artifact.kind, 'reference': artifact.reference,
                     'sha256': artifact.sha256, 'platform': artifact.platform},
        'image_observation': {'distribution': {'config_sha256': 'b' * 64}},
        'image_binding': {'engine_id': artifact.reference, 'config_sha256': 'b' * 64,
                          'layers': [{'sha256': 'c' * 64}], 'build_key_label': _BUILD_KEY},
        'control_base_revision_declared': _CONTROL_REVISION,
        'control_source_sha256': _source_digest(),
        'control_commit': None, 'authenticated_producer': None,
        'fixed_policy_sha256': _POLICY_SHA256, 'profile_sha256': '1' * 64,
        'checker_source_files': load_profile()['sources'],
        'comparison': None, 'promotable': False, 'source_admission': 'unverified',
        'build_receipt': None, 'authority': 'local-unauthenticated',
        'qualification_eligible': False,
        'qualification_gaps': ['authenticated-control-commit', 'authenticated-producer',
                               'provider-build-receipt', 'source-and-rights-admission',
                               'accepted-baseline-and-comparison'],
        'sharing': 'local-evidence-package',
        'tool_manifest_sha256': {'checker': '1' * 64, 'consumer': '2' * 64, 'oracle': '3' * 64},
        'evaluator_receipt_sha256': '4' * 64, 'status': 'observations-complete',
        'infrastructure_errors': [], 'checker': {'summary': {'incomplete': False}},
        'consumer': {'app_returncode': 0}, 'admission': {'admission': {'admitted': True}},
        'oracle': {'cleanup_errors': [], 'controls': _controls()},
    }


def _sealed_pair(root, body):
    """Seal a 128-member stub tree with the real produce helpers."""
    for name in _FIXED_NAMES:
        if name in ('evidence-manifest.json', 'validation-body.json'):
            continue
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'stub:' + name.encode())
    for n in range(23):
        path = root / f'checker-run/checker/.state.json.report-records/{n:064x}.jsonl'
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'record:%d' % n)
    body_raw = (json.dumps(body, sort_keys=True, indent=2) + '\n').encode()
    (root / 'validation-body.json').write_bytes(body_raw)
    entries = _seal_evidence(root)
    (root / 'evidence-manifest.json').write_text(json.dumps({'files': entries}, sort_keys=True, indent=2) + '\n')
    entries.append({'path': 'evidence-manifest.json', 'size': (root / 'evidence-manifest.json').stat().st_size,
                    'sha256': hashlib.sha256((root / 'evidence-manifest.json').read_bytes()).hexdigest()})
    package = _package_evidence(root, entries)
    envelope = dict(body)
    envelope['package'] = package
    envelope['body'] = {'path': 'validation-body.json', 'size': len(body_raw),
                        'sha256': hashlib.sha256(body_raw).hexdigest()}
    (root / 'validation.json').write_text(json.dumps(envelope, sort_keys=True, indent=2) + '\n')
    return envelope, body_raw


def _check(root, artifact, **kwargs):
    return authority._verify_validation_package(root, artifact, _observation(), _POLICY_SHA256,
                                                _BUILD_KEY, _CONTROL_REVISION, **kwargs)


def _tar_members(path):
    members = {}
    with tarfile.open(path, 'r:gz') as tar:
        for member in tar:
            members[member.name] = tar.extractfile(member).read()
    return members


def _rewrite_tar(path, members):
    path.unlink()
    with tarfile.open(path, 'w:gz') as tar:
        for name in sorted(members):
            item = tarfile.TarInfo(name)
            item.size = len(members[name])
            tar.addfile(item, io.BytesIO(members[name]))


def _refresh_package_seal(root, envelope):
    archive = root / 'package.tar.gz'
    envelope['package'] = {'path': 'package.tar.gz', 'size': archive.stat().st_size,
                           'sha256': hashlib.sha256(archive.read_bytes()).hexdigest()}
    (root / 'validation.json').write_text(json.dumps(envelope, sort_keys=True, indent=2) + '\n')


def _swap_body_byte(members):
    swapped = bytearray(members['validation-body.json'])
    swapped[10] ^= 1
    members['validation-body.json'] = bytes(swapped)
    return members


def test_envelope_status_flip_diverges_from_sealed_body(tmp_path):
    artifact = _artifact()
    envelope, _ = _sealed_pair(tmp_path, _body_fixture(artifact))
    envelope['status'] = 'incomplete'
    (tmp_path / 'validation.json').write_text(json.dumps(envelope, sort_keys=True, indent=2) + '\n')
    with pytest.raises(ValueError, match='validation body differs from envelope'):
        _check(tmp_path, artifact)


def test_envelope_gate_flip_never_reaches_gates(tmp_path):
    artifact = _artifact()
    envelope, _ = _sealed_pair(tmp_path, _body_fixture(artifact))
    envelope['oracle']['controls']['positive']['returncode'] = 1
    (tmp_path / 'validation.json').write_text(json.dumps(envelope, sort_keys=True, indent=2) + '\n')
    with pytest.raises(ValueError, match='validation body differs from envelope'):
        _check(tmp_path, artifact)


def test_body_byte_swap_with_stale_inner_manifest_breaks_package_compare(tmp_path):
    artifact = _artifact()
    envelope, _ = _sealed_pair(tmp_path, _body_fixture(artifact))
    members = _swap_body_byte(_tar_members(tmp_path / 'package.tar.gz'))
    _rewrite_tar(tmp_path / 'package.tar.gz', members)
    _refresh_package_seal(tmp_path, envelope)
    with pytest.raises(ValueError, match='validation package roster mismatch'):
        _check(tmp_path, artifact)


def test_body_byte_swap_with_fresh_manifest_breaks_body_seal(tmp_path):
    artifact = _artifact()
    envelope, _ = _sealed_pair(tmp_path, _body_fixture(artifact))
    members = _swap_body_byte(_tar_members(tmp_path / 'package.tar.gz'))
    manifest = loads(members['evidence-manifest.json'])
    for entry in manifest['files']:
        if entry['path'] == 'validation-body.json':
            entry['size'] = len(members['validation-body.json'])
            entry['sha256'] = hashlib.sha256(members['validation-body.json']).hexdigest()
    members['evidence-manifest.json'] = (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode()
    _rewrite_tar(tmp_path / 'package.tar.gz', members)
    _refresh_package_seal(tmp_path, envelope)
    with pytest.raises(ValueError, match='validation body digest mismatch'):
        _check(tmp_path, artifact)


def test_dropped_body_breaks_fixed_roster(tmp_path):
    artifact = _artifact()
    envelope, _ = _sealed_pair(tmp_path, _body_fixture(artifact))
    members = _tar_members(tmp_path / 'package.tar.gz')
    del members['validation-body.json']
    manifest = loads(members['evidence-manifest.json'])
    manifest['files'] = [entry for entry in manifest['files'] if entry['path'] != 'validation-body.json']
    members['evidence-manifest.json'] = (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode()
    _rewrite_tar(tmp_path / 'package.tar.gz', members)
    _refresh_package_seal(tmp_path, envelope)
    with pytest.raises(ValueError, match='fixed validation evidence roster incomplete or unexpected'):
        _check(tmp_path, artifact)


def test_light_round_trip_replays_gates_from_enclosed_body(tmp_path, monkeypatch):
    import p11lab.image_validation as validation_api
    artifact = _artifact()
    body = _body_fixture(artifact)
    assert len(body) == 29
    envelope, body_raw = _sealed_pair(tmp_path, body)
    assert set(envelope) == set(body) | {'package', 'body'} and len(envelope) == 31
    assert _tar_members(tmp_path / 'package.tar.gz')['validation-body.json'] == body_raw
    assert envelope['body'] == {'path': 'validation-body.json', 'size': len(body_raw),
                                'sha256': hashlib.sha256(body_raw).hexdigest()}
    seen = {}

    def fake_heavy(archive, observed, value, artifact_arg, policy, journal_dir=None, **kwargs):
        seen['value'] = value
        seen['archive'] = archive

    monkeypatch.setattr(validation_api, 'verify_evidence_package', fake_heavy)
    result = _check(tmp_path, artifact, validation_policy={})
    assert seen['value'] == loads(body_raw) == body
    assert 'package' not in seen['value'] and 'body' not in seen['value']
    assert result == {'validation_sha256': hashlib.sha256((tmp_path / 'validation.json').read_bytes()).hexdigest(),
                      'package_sha256': envelope['package']['sha256'],
                      'body_sha256': envelope['body']['sha256'],
                      'config_sha256': 'b' * 64, 'layers': [{'sha256': 'c' * 64}]}


def _small_envelope(artifact):
    return {
        'schema_version': 1, 'kind': 'local-image-validation', 'artifact': vars(artifact),
        'status': 'observations-complete', 'infrastructure_errors': [],
        'sharing': 'local-evidence-package', 'fixed_policy_sha256': _POLICY_SHA256,
        'control_source_sha256': _source_digest(),
        'control_base_revision_declared': _CONTROL_REVISION,
        'image_binding': {'engine_id': artifact.reference, 'config_sha256': 'b' * 64,
                          'layers': [{'sha256': 'c' * 64}], 'build_key_label': _BUILD_KEY},
        'checker': {'summary': {'incomplete': False}}, 'consumer': {'app_returncode': 0},
        'admission': {'admission': {'admitted': True}},
        'oracle': {'cleanup_errors': [], 'controls': _controls()},
    }


def _small_package(root):
    data = b'raw evaluator evidence'
    roster = {'files': [{'path': 'checker/raw.json', 'size': len(data),
                         'sha256': hashlib.sha256(data).hexdigest()}]}
    manifest = (json.dumps(roster, sort_keys=True) + '\n').encode()
    archive = root / 'package.tar.gz'
    with tarfile.open(archive, 'w:gz') as tar:
        for name, raw in (('checker/raw.json', data), ('evidence-manifest.json', manifest)):
            item = tarfile.TarInfo(name)
            item.size = len(raw)
            tar.addfile(item, io.BytesIO(raw))
    return {'path': 'package.tar.gz', 'size': archive.stat().st_size,
            'sha256': hashlib.sha256(archive.read_bytes()).hexdigest()}


def test_missing_body_seal_falls_through_to_malformed_evidence(tmp_path):
    artifact = _artifact()
    envelope = _small_envelope(artifact)
    envelope['package'] = _small_package(tmp_path)
    assert 'body' not in envelope
    (tmp_path / 'validation.json').write_text(json.dumps(envelope))
    with pytest.raises(ValueError, match='malformed local validation evidence'):
        _check(tmp_path, artifact)


@pytest.mark.parametrize('record', [
    {'path': 'validation-body.json', 'size': 'huge', 'sha256': '0' * 64},
    {'path': 'wrong-name.json', 'size': 10, 'sha256': '0' * 64},
    {'path': 'validation-body.json', 'size': 10, 'sha256': 'not-a-digest'},
])
def test_malformed_body_seal_record_is_rejected(tmp_path, record):
    artifact = _artifact()
    envelope = _small_envelope(artifact)
    envelope['package'] = _small_package(tmp_path)
    envelope['body'] = record
    (tmp_path / 'validation.json').write_text(json.dumps(envelope))
    with pytest.raises(ValueError, match='invalid validation body identity'):
        _check(tmp_path, artifact)


def test_heavy_replay_rejects_seal_bearing_value_before_io(tmp_path):
    from p11lab.image_validation import verify_evidence_package
    value = {'package': {'path': 'package.tar.gz', 'size': 1, 'sha256': '0' * 64},
             'body': {'path': 'validation-body.json', 'size': 1, 'sha256': '0' * 64}}
    with pytest.raises(ValueError, match='enclosed validation body required'):
        verify_evidence_package(tmp_path / 'missing', {}, value, None, {})
