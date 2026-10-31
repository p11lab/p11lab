"""Local image composition must preserve its parent and verified tool bytes."""
import json
from pathlib import Path
import pytest
from dataclasses import asdict
from p11lab.models import ArtifactRef, BoundedRunPolicy


def test_selection_refuses_parent_collision():
    from p11lab.image_validation import select_checker_additions
    tool = {'files': {'usr/bin/python3.13': {'sha256': 'b', 'size': 1, 'mode': 0o755}}, 'aliases': {}}
    base = {'files': {}, 'aliases': {}}
    parent = {'files': [{'path': '/usr/bin/python3.13', 'sha256': 'a', 'size': 1, 'mode': 0o755}]}
    with pytest.raises(ValueError, match='parent'):
        select_checker_additions(tool, base, parent)


def test_selection_does_not_copy_unrelated_or_identical_parent_files():
    from p11lab.image_validation import select_checker_additions
    file = {'sha256': 'a', 'size': 1, 'mode': 0o755}
    tool = {'files': {'usr/bin/python3.13': file, 'opt/p11lab-checker/lib/x': file,
                      'etc/unrelated': file}, 'aliases': {}}
    parent = {'files': [{'path': '/usr/bin/python3.13', **file}]}
    selected = select_checker_additions(tool, {'files': {}, 'aliases': {}}, parent)
    assert selected == {'opt/p11lab-checker/lib/x': {'kind': 'file', **file}}


def test_parent_mutation_is_not_accepted():
    from p11lab.image_validation import verify_composition
    parent = {'files': [{'path': '/provider.so', 'sha256': 'a', 'size': 1, 'mode': 0o755}]}
    child = {'files': [{'path': '/provider.so', 'sha256': 'b', 'size': 1, 'mode': 0o755}]}
    with pytest.raises(ValueError, match='parent'):
        verify_composition(parent, child, {})


def test_copied_file_must_match_verified_source():
    from p11lab.image_validation import verify_composition
    parent = {'files': []}
    child = {'files': [{'path': '/new', 'sha256': 'b', 'size': 1, 'mode': 0o755}]}
    with pytest.raises(ValueError, match='copy'):
        verify_composition(parent, child, {'new': {'kind': 'file', 'sha256': 'a', 'size': 1, 'mode': 0o755}})


def test_parent_directory_metadata_cannot_change():
    from p11lab.image_validation import verify_parent_metadata
    original = {'usr': {'mode': 0o755, 'uid': 0, 'gid': 0, 'type': 'dir'}}
    altered = {'usr': {'mode': 0o777, 'uid': 0, 'gid': 0, 'type': 'dir'}}
    with pytest.raises(ValueError, match='parent'):
        verify_parent_metadata(original, altered)


def test_composition_refuses_symlink_ancestor():
    from p11lab.image_validation import reject_unsafe_composition_paths
    parent = {'files': [{'path': '/opt', 'link': '/etc'}]}
    with pytest.raises(ValueError, match='ancestor'):
        reject_unsafe_composition_paths(parent, {'opt/p11lab-checker/new': {'kind': 'file'}})


def test_oracle_rejects_accepted_negative_or_infrastructure_failure():
    from p11lab.image_validation import check_oracle_results
    evidence = {'container_id': 'a' * 64, 'inspection_before': {'Id': 'a' * 64},
                'inspection_after': {'Id': 'a' * 64, 'State': {'Running': False, 'Pid': 0}},
                'cleanup': 'removed-exact-owned-container'}
    positive = {'returncode': 0, 'timed_out': False, 'stdout_truncated': False, 'stderr_truncated': False,
                'stdout': 'OpenSSL verified original signature; altered message rejected.', 'stderr': '', **evidence}
    negative = {'returncode': 1, 'timed_out': False, 'stdout_truncated': False, 'stderr_truncated': False,
                'stdout': 'Verification failure', 'stderr': '', **evidence}
    signature = negative | {'stdout': '', 'stderr': 'p11lab verification failed: OpenSSL rejected the original message signature'}
    check_oracle_results({'positive': positive, 'altered_message': negative, 'altered_signature': signature})
    with pytest.raises(ValueError, match='oracle'):
        check_oracle_results({'positive': positive, 'altered_message': positive, 'altered_signature': signature})
    with pytest.raises(ValueError, match='oracle'):
        check_oracle_results({'positive': positive, 'altered_message': negative | {'timed_out': True}, 'altered_signature': signature})
    with pytest.raises(ValueError, match='oracle'):
        check_oracle_results({'positive': positive, 'altered_message': negative | {'stdout': '', 'stderr': 'missing key'}, 'altered_signature': signature})
    with pytest.raises(ValueError, match='oracle'):
        check_oracle_results({'positive': positive | {'cleanup': 'unknown'}, 'altered_message': negative, 'altered_signature': signature})


def test_catalog_requires_exact_full_roster_and_unique_entries():
    from p11lab.image_validation import check_catalog
    with pytest.raises(ValueError, match='catalog'):
        check_catalog(['test_a.py::case', 'test_a.py::case'], ['test_a.py::case'], {'test_a.py': 2})
    with pytest.raises(ValueError, match='catalog'):
        check_catalog(['test_a.py::case'], ['test_a.py::missing'], {'test_a.py': 1})


def test_public_shard_plan_rejects_missing_and_duplicate_files(tmp_path):
    from p11lab.image_validation import check_public_shard_plan
    expected = {'test_a.py', 'test_b.py'}
    a, b = str(tmp_path / 'test_a.py'), str(tmp_path / 'test_b.py')
    assert check_public_shard_plan({'shards': [[a, b]]}, tmp_path, expected) == ['test_a.py', 'test_b.py']
    with pytest.raises(ValueError, match='shard'):
        check_public_shard_plan({'shards': [[a, a]]}, tmp_path, expected)
    with pytest.raises(ValueError, match='shard'):
        check_public_shard_plan({'shards': [[a]]}, tmp_path, expected)


def test_missing_checker_originals_cannot_be_complete(tmp_path):
    from p11lab.image_validation import check_checker_originals
    with pytest.raises(ValueError, match='checker'):
        check_checker_originals(tmp_path, ['test_a.py::case'], 'sha256:' + 'a' * 64)


def test_evaluator_receipt_seal_is_required(tmp_path):
    from p11lab.image_validation import verify_evaluator
    (tmp_path / 'evaluator-build-receipt.json').write_text('{}')
    with pytest.raises(ValueError, match='evaluator'):
        verify_evaluator(tmp_path, '0' * 64)


def test_tainted_lane_is_not_eligible_for_evidence_export(tmp_path):
    from p11lab.image_validation import reject_tainted_run
    from p11lab.bounded_run import CredentialTaintError
    receipt = tmp_path / 'receipt.json'
    receipt.write_text(json.dumps({'bounded_execution': {'output': {'readback': {'tainted': True}}}}))
    with pytest.raises(CredentialTaintError, match='credential'):
        reject_tainted_run(receipt)


@pytest.mark.parametrize('checker_error', [False, True])
@pytest.mark.parametrize('reason', ['archive', 'stream', 'unavailable'])
def test_tainted_checker_blocks_entire_package(tmp_path, monkeypatch, checker_error, reason):
    from dataclasses import asdict
    import p11lab.image_validation as api
    image = ArtifactRef('docker-local', 'sha256:' + 'a' * 64, 'a' * 64, 'linux/amd64')
    tools = {}
    for name in ('checker', 'consumer', 'oracle'):
        root = tmp_path / name
        root.mkdir()
        tools[name] = {'root': str(root), 'input_receipt': str(root / 'input.json'), 'manifest_sha256': 'a' * 64}
    evaluator = tmp_path / 'evaluator'
    evaluator.mkdir()
    policy = {'tools': tools, 'evaluator': {'root': str(evaluator), 'receipt_sha256': 'a' * 64},
              'control_base_revision': 'a' * 40}
    monkeypatch.setattr(api, 'Docker', lambda: type('D', (), {'image': lambda self, artifact: {'Config': {}}})())
    secret = 'p11lab-test-credential-78c8bde1'
    monkeypatch.setattr(api.secrets, 'token_hex', lambda _size: secret)
    monkeypatch.setattr(api, 'verify_tool_build', lambda root, **kwargs: {'toolset': Path(root).name})
    monkeypatch.setattr(api, 'verify_evaluator', lambda *args: {})
    monkeypatch.setattr(api, 'collect_checker_catalog', lambda *args: {'nodes': api.load_profile()['nodes']})
    monkeypatch.setattr(api, 'plan_checker_shard', lambda *args: {'files': []})
    def compose(artifact, tool, root, receipt, seal, output):
        output.mkdir()
        (output / 'parent.json').write_text(json.dumps({'distribution': {}}))
        return {'derived': asdict(artifact)}
    monkeypatch.setattr(api, 'compose_local_image', compose)
    def checker(spec, profile):
        spec.output_dir.mkdir()
        bounded = {'output': {'readback': {'tainted': reason == 'archive'}}}
        if reason == 'stream':
            bounded['stream_tainted'] = True
        if reason == 'unavailable':
            bounded['stream_capture_unavailable'] = True
            bounded['stream_capture_phase'] = 'post-health'
            bounded['stream_capture_error'] = 'RuntimeError'
        (spec.output_dir / 'receipt.json').write_text(json.dumps({'bounded_execution': bounded}))
        if checker_error:
            raise ValueError('later adapter failure ' + secret)
    monkeypatch.setattr(api, 'run_checker', checker)
    monkeypatch.setattr(api, 'run_application', lambda *args: pytest.fail('consumer must not run'))
    output = tmp_path / 'result'
    result = api.validate_image(image, policy, output)
    if reason == 'unavailable':
        assert result['status'] == 'incomplete' and result['sharing'] == 'blocked-stream-capture-unavailable'
        assert any('unavailable' in error and 'RuntimeError' in error and 'post-health' in error
                   for error in result['infrastructure_errors'])
    else:
        assert result['status'] == 'tainted' and result['sharing'] == 'blocked-credential-taint'
    assert 'package' not in result and 'body' not in result
    assert not (output / 'package.tar.gz').exists() and not (output / 'validation-body.json').exists()
    assert secret not in (output / 'validation.json').read_text()


@pytest.mark.parametrize('reason', ['archive', 'stream', 'unavailable'])
@pytest.mark.parametrize('consumer_error', [False, True])
def test_tainted_consumer_blocks_entire_package(tmp_path, monkeypatch, reason, consumer_error):
    from dataclasses import asdict
    from types import SimpleNamespace
    import p11lab.image_validation as api
    image = ArtifactRef('docker-local', 'sha256:' + 'a' * 64, 'a' * 64, 'linux/amd64')
    tools = {}
    for name in ('checker', 'consumer', 'oracle'):
        root = tmp_path / name
        root.mkdir()
        tools[name] = {'root': str(root), 'input_receipt': str(root / 'input.json'), 'manifest_sha256': 'a' * 64}
    evaluator = tmp_path / 'evaluator'
    evaluator.mkdir()
    policy = {'tools': tools, 'evaluator': {'root': str(evaluator), 'receipt_sha256': 'a' * 64},
              'control_base_revision': 'a' * 40}
    monkeypatch.setattr(api, 'Docker', lambda: type('D', (), {'image': lambda self, artifact: {'Config': {}}})())
    monkeypatch.setattr(api, 'verify_tool_build', lambda root, **kwargs: {'toolset': Path(root).name})
    monkeypatch.setattr(api, 'verify_evaluator', lambda *args: {})
    monkeypatch.setattr(api, 'collect_checker_catalog', lambda *args: {'nodes': api.load_profile()['nodes']})
    monkeypatch.setattr(api, 'plan_checker_shard', lambda *args: {'files': []})
    def compose(artifact, tool, root, receipt, seal, output):
        output.mkdir()
        (output / 'parent.json').write_text(json.dumps({'distribution': {}}))
        return {'derived': asdict(artifact)}
    monkeypatch.setattr(api, 'compose_local_image', compose)
    monkeypatch.setattr(api, 'run_checker', lambda *args: None)
    monkeypatch.setattr(api, 'check_checker_originals', lambda *args: {})
    monkeypatch.setattr(api, 'admit_checker', lambda *args: {})
    def consumer(spec):
        spec.output_dir.mkdir()
        receipt = spec.output_dir / 'receipt.json'
        bounded = {'output': {'readback': {'tainted': reason == 'archive'}}}
        if reason == 'stream':
            bounded['stream_tainted'] = True
        if reason == 'unavailable':
            bounded['stream_capture_unavailable'] = True
            bounded['stream_capture_phase'] = 'post-health'
            bounded['stream_capture_error'] = 'RuntimeError'
        receipt.write_text(json.dumps({'bounded_execution': bounded}))
        if consumer_error:
            raise RuntimeError('later consumer error')
        return SimpleNamespace(receipt_path=receipt, exit_code=1, app_returncode=0, lifecycle_errors=(), cleanup_errors=())
    monkeypatch.setattr(api, 'run_application', consumer)
    monkeypatch.setattr(api, 'verify_consumer_output', lambda *args: pytest.fail('oracle must not run'))
    output = tmp_path / 'result'
    result = api.validate_image(image, policy, output)
    if reason == 'unavailable':
        assert result['status'] == 'incomplete' and result['sharing'] == 'blocked-stream-capture-unavailable'
        assert any('unavailable' in error and 'RuntimeError' in error and 'post-health' in error
                   for error in result['infrastructure_errors'])
    else:
        assert result['status'] == 'tainted' and result['sharing'] == 'blocked-credential-taint'
    assert 'package' not in result and 'body' not in result
    assert not (output / 'package.tar.gz').exists() and not (output / 'validation-body.json').exists()


def test_local_policy_rejects_claimed_approval_before_output(tmp_path):
    from p11lab.image_validation import validate_image
    image = ArtifactRef('docker-local', 'sha256:' + 'a' * 64, 'a' * 64, 'linux/amd64')
    with pytest.raises(ValueError, match='policy'):
        validate_image(image, {'reviewed': True, 'promotable': True}, tmp_path / 'result')
    assert not (tmp_path / 'result').exists()


def test_oracle_refuses_root_before_tool_or_output(tmp_path, monkeypatch):
    from p11lab.image_validation import verify_consumer_output
    monkeypatch.setattr('os.getuid', lambda: 0)
    with pytest.raises(ValueError, match='nonroot'):
        verify_consumer_output(tmp_path / 'missing', tmp_path / 'missing.json', '0' * 64,
                               tmp_path / 'crypto', tmp_path / 'out')
    assert not (tmp_path / 'out').exists()


def test_dirty_local_source_does_not_claim_base_as_control_commit():
    from p11lab.image_validation import local_checker_plan
    plan = local_checker_plan({'nodes': ['test_a.py::case']}, ['test_a.py::case'],
                              'sha256:' + 'a' * 64, {'lane': 'lane', 'checker_revision': 'b' * 40})
    assert plan['identity']['p11lab_sha'] == ''


def test_historical_recipe_and_patch_roster_are_explicitly_unknown():
    from p11lab.image_validation import describe_provider_binding
    artifact = ArtifactRef('docker-local', 'sha256:' + 'a' * 64, 'a' * 64, 'linux/amd64')
    observed = {'Config': {'Labels': {'org.p11lab.source-revision': 'declared'}}}
    result = describe_provider_binding(artifact, observed, {'distribution': {}})
    assert result['recipe_identity'] is None and result['ordered_patches'] is None
    assert result['recipe_provenance'] == result['patch_provenance'] == 'unavailable'
    assert result['source_revision_label'] == 'declared' and result['label_authority'] == 'observation-only'


@pytest.fixture
def complete_checker(tmp_path):
    output = tmp_path / 'out'
    checker = output / 'checker'
    cache = checker / '.state.json.report-records'
    cache.mkdir(parents=True)
    selected = ['test_a.py::case']
    node = '/opt/p11lab-checker/lib/python3.13/site-packages/pkcs11_check/testcases/' + selected[0]
    image = 'sha256:' + 'a' * 64
    stages = [{'phase': phase, 'container_id': str(index) * 64,
               'returncode': int(phase == 'application'), 'timed_out': False,
               'stdout_truncated': False, 'stderr_truncated': False}
              for index, phase in enumerate(('init', 'ready', 'application', 'post-health'), 1)]
    policy = BoundedRunPolicy()
    probe = {'container_id': 'a' * 64, 'returncode': 0, 'timed_out': False, 'stdout_truncated': False, 'stderr_truncated': False,
             'inspection_before': {'Id': 'a' * 64},
             'inspection_after': {'Id': 'a' * 64, 'State': {'Running': False, 'Pid': 0}},
             'cleanup': 'removed-exact-owned-container'}
    host = {'Memory': policy.memory_bytes, 'MemorySwap': policy.memory_bytes, 'PidsLimit': policy.pids,
            'NanoCpus': 1_000_000_000, 'ReadonlyRootfs': True, 'NetworkMode': 'none', 'CapDrop': ['ALL'],
            'CapAdd': None, 'IpcMode': 'private', 'Privileged': False, 'SecurityOpt': ['no-new-privileges=true'],
            'Tmpfs': {'/tmp': f'rw,nosuid,nodev,size={policy.tmp_bytes},nr_inodes={policy.inodes}',
                      '/dev/shm': f'rw,nosuid,nodev,size={policy.run_bytes},nr_inodes={policy.inodes},mode=1777',
                      '/run/p11lab': f'rw,nosuid,nodev,uid=1,gid=1,mode=0700,size={policy.run_bytes},nr_inodes={policy.inodes}'}}
    state_mount = {'Type': 'volume', 'Destination': '/var/lib/p11lab', 'Name': 'state', 'RW': True}
    stage_records = {phase: {'host_config': host, 'mounts': [state_mount]} for phase in ('init', 'ready', 'application', 'post-health')}
    stage_records['application'] = {'host_config': host, 'mounts': [state_mount,
        {'Type': 'volume', 'Destination': '/p11lab-output', 'Name': 'output', 'RW': True},
        {'Type': 'bind', 'Destination': '/workspace', 'Source': '/workspace', 'RW': False}]}
    for stage in stages:
        stage_records[stage['phase']].update(id=stage['container_id'], image=image)
    outer = {'attempt_id': 'outer', 'artifacts': {'provider': {'reference': image}},
             'state': {'persistent_caller_directory': False}, 'app_completed': True, 'app_returncode': 1,
             'execution': {'uid_gid': '1:1'}, 'inputs': {},
             'timeout': False, 'interrupted_signal': None, 'lifecycle_errors': [], 'cleanup_errors': [], 'stages': stages,
             'owned_resources': [{'kind': 'container', 'identity': stage['container_id']} for stage in stages],
             'bounded_policy': asdict(policy),
             'bounded_execution': {'state': {'kernel_tmpfs': {'type': 'tmpfs', 'inodes': 10000, 'block_size': 4096, 'blocks': policy.state_bytes // 4096},
                                               'kernel_probe': probe,
                                               'volume_inspection': {'Name': 'state'},
                                               'holder_cleanup': 'removed-exact-owned-container', 'volume_cleanup': 'removed-exact-owned-volume'},
                                   'output': {'kernel_tmpfs': {'type': 'tmpfs', 'inodes': 10000, 'block_size': 4096, 'blocks': policy.output_bytes // 4096},
                                              'kernel_probe': probe,
                                              'volume_inspection': {'Name': 'output'},
                                              'holder_cleanup': 'removed-exact-owned-container', 'volume_cleanup': 'removed-exact-owned-volume'},
                                   'stages': stage_records}}
    inner = {'attempt_id': 'inner', 'nodes': selected, 'returncode': 1, 'timeout': False,
             'evidence': {'observations_complete': True, 'complete': True, 'summary': {'failed': 1}}}
    collection = {'returncode': 0, 'nodes': selected, 'installed_nodes': [node]}
    state = {'units': [node], 'process_observations_complete': True,
             'results': [{'target': node, 'completion_verified': True}]}
    for name, data in [('receipt.json', outer), ('checker/checker-receipt.json', inner),
                       ('checker/collection.json', collection), ('checker/state.json', state)]:
        (output / name).write_text(json.dumps(data))
    for name in ('collection.stdout.log', 'collection.stderr.log', 'report.jsonl', 'results.json',
                 'coverage.json', 'checker.stdout.log', 'checker.stderr.log'):
        (checker / name).write_text('x')
    (output / 'bounded-output.tar').write_bytes(b'tar')
    (cache / 'a.jsonl').write_text('x')
    return output, selected, image


def test_completed_provider_finding_is_not_an_infrastructure_failure(complete_checker):
    from p11lab.image_validation import check_checker_originals
    result = check_checker_originals(*complete_checker)
    assert result['app_returncode'] == 1 and result['summary']['failed'] == 1


@pytest.mark.parametrize('mutation', ['global_crash', 'cleanup', 'missing_raw', 'missing_cache', 'missing_boundary', 'boundary_memory', 'boundary_mount', 'probe_cleanup', 'unknown_timeout', 'unknown_stage_supervision', 'missing_interrupt', 'boolean_returncode', 'wrong_stage_id', 'wrong_stage_image'])
def test_incomplete_checker_is_refused(complete_checker, mutation):
    from p11lab.image_validation import check_checker_originals
    output, selected, image = complete_checker
    receipt = output / 'receipt.json'
    outer = json.loads(receipt.read_text())
    if mutation == 'global_crash':
        outer['app_completed'] = False
    elif mutation == 'cleanup':
        outer['cleanup_errors'] = ['volume cleanup failed']
    elif mutation == 'missing_raw':
        (output / 'checker/report.jsonl').unlink()
    elif mutation == 'missing_cache':
        (output / 'checker/.state.json.report-records/a.jsonl').unlink()
    elif mutation == 'missing_boundary':
        del outer['bounded_execution']
    elif mutation == 'boundary_memory':
        outer['bounded_execution']['stages']['application']['host_config']['Memory'] = 1
    elif mutation == 'boundary_mount':
        outer['bounded_execution']['stages']['application']['mounts'][0]['RW'] = False
    elif mutation == 'unknown_timeout':
        outer['timeout'] = None
    elif mutation == 'unknown_stage_supervision':
        outer['stages'][0]['timed_out'] = None
    elif mutation == 'missing_interrupt':
        del outer['interrupted_signal']
    elif mutation == 'boolean_returncode':
        outer['app_returncode'] = True
    elif mutation == 'wrong_stage_id':
        outer['bounded_execution']['stages']['application']['id'] = 'f' * 64
    elif mutation == 'wrong_stage_image':
        outer['bounded_execution']['stages']['application']['image'] = 'sha256:' + 'f' * 64
    else:
        outer['bounded_execution']['output']['kernel_probe']['cleanup'] = 'unknown'
    receipt.write_text(json.dumps(outer))
    with pytest.raises(ValueError, match='checker|bounded'):
        check_checker_originals(output, selected, image)


def test_closed_evidence_roster_rejects_missing_stages_and_unexpected_files():
    from p11lab.image_validation import check_evidence_roster

    # Names captured from a complete local validation; content is not an authority fixture.
    required = set("""
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
    """.split())
    records = {f"checker-run/checker/.state.json.report-records/{n:064x}.jsonl" for n in range(23)}
    full = required | records
    check_evidence_roster(full, 23)
    for missing in ("frozen-plan.json", "catalog/catalog.json", "planning/planner.json",
                    "checker-run/checker/report.jsonl", "admission/ledger.jsonl",
                    "consumer-run/receipt.json", "consumer-run/crypto/signature.der",
                    "oracle/oracle.json", "oracle/message/altered.bin"):
        with pytest.raises(ValueError, match="roster"):
            check_evidence_roster(full - {missing}, 23)
    with pytest.raises(ValueError, match="roster"):
        check_evidence_roster(full | {"unexpected.json"}, 23)
    with pytest.raises(ValueError, match="roster"):
        check_evidence_roster(full - {next(iter(records))}, 23)


def test_frozen_plan_rejects_changed_candidate_shard_selection_and_planner():
    from p11lab.checker import load_profile
    from p11lab.image_validation import check_frozen_plan, local_checker_plan

    profile = load_profile()
    fixed = {'lane': 'fixed-lane', 'checker_revision': '1' * 40}
    catalog = profile['nodes'] + ['test_object.py::Unselected::test_case']
    image = 'sha256:' + '2' * 64
    planner = {'files': sorted(profile['sources']), 'evaluator_receipt_sha256': '3' * 64}
    plan = local_checker_plan(profile, catalog, image, fixed)
    plan['public_file_planner'] = planner
    check_frozen_plan(plan, profile, catalog, image, fixed, planner)
    for field, changed in (
        ('candidate', {'image_digest': 'sha256:' + '4' * 64}),
        ('shard', {'shard_id': 'attempt-2/shard-0'}),
        ('count', {'planned_count': 999}),
    ):
        mutated = json.loads(json.dumps(plan))
        mutated['identity'].update(changed)
        with pytest.raises(ValueError, match='frozen'):
            check_frozen_plan(mutated, profile, catalog, image, fixed, planner)
    mutated = json.loads(json.dumps(plan))
    mutated['selected'].pop()
    with pytest.raises(ValueError, match='frozen'):
        check_frozen_plan(mutated, profile, catalog, image, fixed, planner)
    mutated = json.loads(json.dumps(plan))
    mutated['public_file_planner']['evaluator_receipt_sha256'] = '5' * 64
    with pytest.raises(ValueError, match='frozen'):
        check_frozen_plan(mutated, profile, catalog, image, fixed, planner)


def test_validation_policy_requires_exact_sealed_tool_and_evaluator_identities():
    from p11lab.image_validation import check_evidence_policy

    tools = {name: {'root': f'/tmp/{name}', 'input_receipt': f'/tmp/{name}.json',
                    'manifest_sha256': digit * 64}
             for name, digit in [('checker', '1'), ('consumer', '2'), ('oracle', '3')]}
    policy = {'tools': tools, 'evaluator': {'root': '/tmp/evaluator', 'receipt_sha256': '4' * 64},
              'control_base_revision': '5' * 40}
    observed = {'tool_manifest_sha256': {name: item['manifest_sha256'] for name, item in tools.items()},
                'evaluator_receipt_sha256': '4' * 64, 'control_base_revision_declared': '5' * 40,
                'scope': 'local-only', 'authority': 'local-unauthenticated', 'comparison': None,
                'promotable': False, 'qualification_eligible': False}
    check_evidence_policy(observed, policy)
    for name in tools:
        changed = json.loads(json.dumps(observed))
        changed['tool_manifest_sha256'][name] = 'f' * 64
        with pytest.raises(ValueError, match='policy'):
            check_evidence_policy(changed, policy)
    for key in ('evaluator_receipt_sha256', 'control_base_revision_declared'):
        changed = dict(observed, **{key: 'f' * len(observed[key])})
        with pytest.raises(ValueError, match='policy'):
            check_evidence_policy(changed, policy)
    with pytest.raises(ValueError, match='policy'):
        check_evidence_policy(observed, policy | {'approved': True})


def test_checker_reconciliation_rejects_changed_counts_or_incomplete_raw_evidence():
    from p11lab.image_validation import check_checker_reconciliation

    actual = {'complete': True, 'observations_complete': True, 'errors': [],
              'summary': {'passed': 2, 'failed': 1, 'incomplete': False},
              'provider_statuses': ['failed']}
    checker = {'summary': dict(actual['summary']), 'app_returncode': 1}
    check_checker_reconciliation(actual, actual, checker)
    with pytest.raises(ValueError, match='reconciliation'):
        check_checker_reconciliation(actual | {'summary': {'passed': 3, 'failed': 0, 'incomplete': False}},
                                     actual, checker)
    with pytest.raises(ValueError, match='reconciliation'):
        check_checker_reconciliation(actual | {'complete': False, 'errors': ['missing attempt']}, actual, checker)
    with pytest.raises(ValueError, match='reconciliation'):
        check_checker_reconciliation(actual, actual, checker | {'summary': {'passed': 3, 'failed': 0}})


def test_fixed_stage_observations_bind_inspected_command_entrypoint_and_user(complete_checker):
    from p11lab.bounded_run import fixed_validation_command, fixed_validation_observation
    from p11lab.image_validation import check_attempt_stage_identities

    output, _, image = complete_checker
    receipt = json.loads((output / 'receipt.json').read_text())
    entrypoint = ['/usr/local/bin/p11lab-provider']
    user = '1:1'
    for phase, boundary in receipt['bounded_execution']['stages'].items():
        config = {'Cmd': fixed_validation_command('checker', phase), 'Entrypoint': entrypoint, 'User': user}
        boundary['fixed_validation_observation'] = fixed_validation_observation(config, 'checker', phase, user, [])
    check_attempt_stage_identities(receipt, image, 'checker', entrypoint, user)
    for field in ('command_sha256', 'user', 'role', 'phase'):
        changed = json.loads(json.dumps(receipt))
        changed['bounded_execution']['stages']['application']['fixed_validation_observation'][field] = 'wrong'
        with pytest.raises(ValueError, match='fixed validation'):
            check_attempt_stage_identities(changed, image, 'checker', entrypoint, user)
    changed = json.loads(json.dumps(receipt))
    del changed['bounded_execution']['stages']['application']['fixed_validation_observation']
    with pytest.raises(ValueError, match='fixed validation'):
        check_attempt_stage_identities(changed, image, 'checker', entrypoint, user)
    with pytest.raises(ValueError, match='fixed validation'):
        check_attempt_stage_identities(receipt, image, 'checker', ['/different'], user)


@pytest.mark.parametrize('lane,subtree', [('checker', 'checker'), ('consumer', 'crypto')])
@pytest.mark.parametrize('mutation', ['none', 'empty', 'partial', 'altered', 'extra_file', 'extra_dir', 'symlink', 'hardlink'])
def test_captured_output_requires_exact_subtree_membership_and_bytes(tmp_path, lane, subtree, mutation):
    from p11lab.image_validation import check_captured_output

    captured = tmp_path / 'captured'
    packaged = tmp_path / 'packaged'
    captured.mkdir()
    packaged.mkdir()
    files = {'one.json': b'original-one', 'nested/two.bin': b'original-two'}
    for relative, contents in files.items():
        for root in (captured, packaged):
            path = root / subtree / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(contents)
    # These are controller-generated siblings, never required in the readback.
    (packaged / 'receipt.json').write_text('{}')
    (packaged / 'application.stdout.log').write_text('controller log')
    if mutation == 'empty':
        import shutil
        shutil.rmtree(captured / subtree)
    elif mutation == 'partial':
        (captured / subtree / 'nested/two.bin').unlink()
    elif mutation == 'altered':
        (captured / subtree / 'one.json').write_bytes(b'changed')
    elif mutation == 'extra_file':
        (captured / 'unexpected.txt').write_text('extra')
    elif mutation == 'extra_dir':
        (captured / subtree / 'empty-extra').mkdir()
    elif mutation == 'symlink':
        path = captured / subtree / 'one.json'
        path.unlink()
        path.symlink_to(packaged / subtree / 'one.json')
    elif mutation == 'hardlink':
        import os
        path = captured / subtree / 'one.json'
        path.unlink()
        os.link(packaged / subtree / 'one.json', path)
    if mutation == 'none':
        check_captured_output(captured, packaged, subtree)
    else:
        with pytest.raises(ValueError, match='captured|readback'):
            check_captured_output(captured, packaged, subtree)


# ---- P0-B1 facade gate-1 pins (Q1-Q10; gaps A-H order) ----

_P0B1_PHASES = ('init', 'ready', 'application', 'post-health')
_P0B1_CRYPTO_NAMES = ('public-key.pem', 'public-key.der', 'message.bin', 'digest.bin',
                      'signature.raw', 'signature.der', 'result.json')
_P0B1_ENTRYPOINT = ['/usr/local/bin/p11lab-provider']


def _p0b1_policy(tmp_path):
    tools = {}
    for name in ('checker', 'consumer', 'oracle'):
        root = tmp_path / name
        root.mkdir(exist_ok=True)
        tools[name] = {'root': str(root), 'input_receipt': str(root / 'input.json'),
                       'manifest_sha256': 'a' * 64}
    evaluator = tmp_path / 'evaluator'
    evaluator.mkdir(exist_ok=True)
    return {'tools': tools,
            'evaluator': {'root': str(evaluator), 'receipt_sha256': 'a' * 64},
            'control_base_revision': 'a' * 40}


def _p0b1_valid_receipt(*, image, lane, attempt, entrypoint, user, tar_bytes, app_returncode=0):
    """Admission-passing lane receipt: bounded proofs, identities, readback, fixed observations."""
    import hashlib
    from dataclasses import asdict
    from p11lab.bounded_run import fixed_validation_command, fixed_validation_observation
    from p11lab.models import BoundedRunPolicy
    policy = BoundedRunPolicy()
    uid, gid = user.split(':')
    stages = []
    for phase in _P0B1_PHASES:
        identity = hashlib.sha256(f'{lane}/{phase}'.encode()).hexdigest()
        stages.append({'phase': phase, 'container_id': identity,
                       'returncode': app_returncode if phase == 'application' else 0,
                       'timed_out': False, 'stdout_truncated': False, 'stderr_truncated': False})
    host = {'Memory': policy.memory_bytes, 'MemorySwap': policy.memory_bytes, 'PidsLimit': policy.pids,
            'NanoCpus': 1_000_000_000, 'ReadonlyRootfs': True, 'NetworkMode': 'none', 'CapDrop': ['ALL'],
            'CapAdd': None, 'IpcMode': 'private', 'Privileged': False, 'SecurityOpt': ['no-new-privileges=true'],
            'Tmpfs': {'/tmp': f'rw,nosuid,nodev,size={policy.tmp_bytes},nr_inodes={policy.inodes}',
                      '/dev/shm': f'rw,nosuid,nodev,size={policy.run_bytes},nr_inodes={policy.inodes},mode=1777',
                      '/run/p11lab': f'rw,nosuid,nodev,uid={uid},gid={gid},mode=0700,size={policy.run_bytes},nr_inodes={policy.inodes}'}}
    probe = {'container_id': 'b' * 64, 'returncode': 0, 'timed_out': False,
             'stdout_truncated': False, 'stderr_truncated': False,
             'inspection_before': {'Id': 'b' * 64},
             'inspection_after': {'Id': 'b' * 64, 'State': {'Running': False, 'Pid': 0}},
             'cleanup': 'removed-exact-owned-container'}
    boundaries = {}
    for row in stages:
        phase = row['phase']
        mounts = [{'Type': 'volume', 'Destination': '/var/lib/p11lab', 'Name': 'state', 'RW': True}]
        if phase == 'application':
            mounts += [{'Type': 'volume', 'Destination': '/p11lab-output', 'Name': 'output', 'RW': True},
                       {'Type': 'bind', 'Destination': '/workspace', 'Source': '/workspace', 'RW': False}]
        config = {'Cmd': fixed_validation_command(lane, phase),
                  'Entrypoint': list(entrypoint), 'User': user}
        boundaries[phase] = {'id': row['container_id'], 'image': image, 'host_config': host,
                             'mounts': mounts,
                             'fixed_validation_observation': fixed_validation_observation(
                                 config, lane, phase, user, [])}

    def _storage(size, name):
        return {'kernel_tmpfs': {'type': 'tmpfs', 'inodes': 10000, 'block_size': 4096,
                                 'blocks': size // 4096},
                'kernel_probe': dict(probe), 'volume_inspection': {'Name': name},
                'holder_cleanup': 'removed-exact-owned-container',
                'volume_cleanup': 'removed-exact-owned-volume'}

    output_storage = _storage(policy.output_bytes, 'output')
    output_storage['readback'] = {'returncode': 0, 'timed_out': False, 'tainted': False,
                                  'stdout_truncated': False, 'stderr_truncated': False,
                                  'supervision_errors': [], 'stragglers_remaining': [],
                                  'drain_complete': True,
                                  'sha256': hashlib.sha256(tar_bytes).hexdigest(),
                                  'size': len(tar_bytes)}
    return {'schema_version': 1, 'run_id': hashlib.sha256(f'{lane}/run'.encode()).hexdigest()[:32],
            'attempt_id': attempt, 'environment': 'softhsm2', 'channel': 'release',
            'mode': 'direct', 'execution_location': 'provider',
            'artifacts': {'provider': {'kind': 'docker-local', 'reference': image,
                                       'sha256': image.removeprefix('sha256:'),
                                       'platform': 'linux/amd64'},
                          'consumer': None, 'client': None},
            'image_observation': {'Id': image, 'platform': 'linux/amd64'},
            'execution': {'container_cwd': '/workspace', 'output_mount': '/p11lab-output',
                          'uid_gid': user, 'capabilities': [], 'network': 'none',
                          'root_readonly': True,
                          'writable': ['/var/lib/p11lab', '/run/p11lab', '/tmp', '/p11lab-output'],
                          'argv_count': 3},
            'inputs': {},
            'state': {'persistent_caller_directory': False, 'owned_directory': None,
                      'directory_ownership': None, 'control_uid_gid': user,
                      'control_mode': '0700', 'owned_directory_retained': False},
            'stages': stages,
            'owned_resources': [{'kind': 'container', 'identity': row['container_id']}
                                for row in stages],
            'uncertain_resources': [],
            'app_returncode': app_returncode, 'app_completed': True,
            'lifecycle_errors': [], 'cleanup_errors': [],
            'exit_code': app_returncode, 'timeout': False, 'interrupted_signal': None,
            'bounded_policy': asdict(policy),
            'bounded_execution': {'state': _storage(policy.state_bytes, 'state'),
                                  'output': output_storage, 'stages': boundaries}}


def _p0b1_write_lane(output_dir, receipt, tar_bytes):
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / 'receipt.json').write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')
    (output_dir / 'bounded-output.tar').write_bytes(tar_bytes)


def _p0b1_flow_base(tmp_path, monkeypatch, image, entrypoint):
    """Policy plus hermetic flow mocks (no lanes, no oracle); each test wires its own."""
    import p11lab.image_validation as api
    from dataclasses import asdict
    policy = _p0b1_policy(tmp_path)
    monkeypatch.setattr(api, 'Docker', lambda: type(
        'D', (), {'image': lambda self, artifact: {'Config': {'Entrypoint': list(entrypoint)}}})())
    monkeypatch.setattr(api.secrets, 'token_hex', lambda _size: 'p11lab-test-credential-78c8bde1')
    monkeypatch.setattr(api, 'verify_tool_build',
                        lambda root, **kwargs: {'toolset': Path(root).name,
                                                'installed': {'engine_id': 'sha256:' + 'e' * 64}})
    monkeypatch.setattr(api, 'verify_evaluator', lambda *args: {})
    monkeypatch.setattr(api, 'collect_checker_catalog',
                        lambda *args: {'nodes': api.load_profile()['nodes']})
    monkeypatch.setattr(api, 'plan_checker_shard', lambda *args: {'files': []})

    def _compose(artifact, tool, root, receipt, seal, output):
        output.mkdir()
        (output / 'parent.json').write_text(json.dumps({'distribution': {}}))
        return {'derived': asdict(artifact)}

    monkeypatch.setattr(api, 'compose_local_image', _compose)
    return api, policy, tmp_path / 'result'


class _P0B1OracleEngine:
    """Fake oracle engine: boundary-clean inspects plus canned control outcomes."""

    def __init__(self, image, user, entrypoint):
        self.engine_id, self.user, self.entrypoint = image, user, list(entrypoint)
        self.requests = {}
        self.removed = []

    def engine_image(self):
        return {'Config': {'Entrypoint': list(self.entrypoint)}}

    def image(self, artifact):
        return self.engine_image()

    def create(self, image, argv, options, labels, name):
        import hashlib
        control = name.rsplit('-', 1)[-1]
        identity = hashlib.sha256(('oracle/' + control).encode()).hexdigest()
        self.requests[identity] = (control, list(argv), list(options))
        return identity

    def command(self, args):
        from p11lab.docker import CommandResult
        identity = args[-1]
        _, argv, options = self.requests[identity]
        mounts = []
        for index, option in enumerate(options):
            if option == '--mount':
                fields = dict(part.split('=', 1) for part in options[index + 1].split(',') if '=' in part)
                mounts.append({'Type': fields['type'], 'Source': fields['src'],
                               'Destination': fields['dst'],
                               'RW': 'readonly' not in options[index + 1].split(',')})
        observed = {'Id': identity, 'Image': self.engine_id, 'State': {'Running': False, 'Pid': 0},
                    'Config': {'User': self.user, 'Entrypoint': ['/usr/bin/env'], 'Cmd': argv},
                    'HostConfig': {'NetworkMode': 'none', 'CapDrop': ['ALL'], 'ReadonlyRootfs': True,
                                   'Privileged': False, 'PidsLimit': 128, 'Memory': 1024**3,
                                   'MemorySwap': 1024**3, 'NanoCpus': 1000000000,
                                   'SecurityOpt': ['no-new-privileges=true'], 'IpcMode': 'private',
                                   'Tmpfs': {'/tmp': 'rw,nosuid,nodev,size=536870912,nr_inodes=16384,mode=1777'},
                                   'PidMode': '', 'CapAdd': None, 'Binds': [],
                                   'Devices': [], 'VolumesFrom': []},
                    'Mounts': mounts}
        return CommandResult(0, json.dumps([observed]), '')

    def execute(self, identity, timeout, interrupted):
        from p11lab.docker import CommandResult
        control = self.requests[identity][0]
        if control == 'positive':
            return CommandResult(0, 'OpenSSL verified original signature; altered message rejected.',
                                 '', False, False, False)
        if control == 'altered_message':
            return CommandResult(1, 'Verification failure', '', False, False, False)
        return CommandResult(1, '', 'oracle: OpenSSL rejected the original message signature',
                             False, False, False)

    def remove(self, kind, identity, labels):
        self.removed.append((kind, identity))


def _p0b1_crypto(directory, payload=None):
    directory.mkdir(parents=True, exist_ok=True)
    for name in _P0B1_CRYPTO_NAMES:
        raw = (payload or {}).get(name, b'clean-public-bytes/' + name.encode())
        (directory / name).write_bytes(raw)
    return directory


def _p0b1_minimal_gate():
    from p11lab.image_validation import EXPORT_GATE_CHECKS, EXPORT_GATE_SCHEMA
    return {'schema': EXPORT_GATE_SCHEMA,
            'checks': [{'name': name, 'result': 'pass'} for name in EXPORT_GATE_CHECKS],
            'verdict': 'eligible', 'basis': {}}


def test_p0b1_gapA_missing_receipt_blocks_unknown(tmp_path):
    from p11lab.image_validation import reject_tainted_run
    try:
        reject_tainted_run(tmp_path / 'checker-run' / 'receipt.json')
    except ValueError as error:
        assert getattr(error, 'sharing', None) == 'blocked:unknown-receipt'
    else:
        pytest.fail('missing lane receipt must block export as unknown')


def test_p0b1_gapA_unparseable_receipt_blocks_unknown(tmp_path):
    from p11lab.image_validation import reject_tainted_run
    receipt = tmp_path / 'checker-run' / 'receipt.json'
    receipt.parent.mkdir()
    receipt.write_bytes(b'{"bounded_execution": not-json')
    try:
        reject_tainted_run(receipt)
    except ValueError as error:
        assert getattr(error, 'sharing', None) == 'blocked:unknown-receipt'
    else:
        pytest.fail('unparseable lane receipt must block export as unknown')


def test_p0b1_gapA_foreign_receipt_blocked(tmp_path):
    from p11lab.image_validation import reject_tainted_run
    receipt = tmp_path / 'receipt.json'
    receipt.write_text(json.dumps({'note': 'not a lane receipt'}))
    try:
        reject_tainted_run(receipt)
    except ValueError as error:
        assert getattr(error, 'sharing', None) == 'blocked:foreign-receipt'
    else:
        pytest.fail('foreign receipt must block export')


def test_p0b1_gapA_carrier_mismatch_blocked(tmp_path):
    from p11lab.image_validation import reject_tainted_run
    receipt = tmp_path / 'checker-run' / 'receipt.json'
    receipt.parent.mkdir()
    receipt.write_text(json.dumps({'bounded_execution': {'output': {'readback': {'tainted': False}}}}))
    try:
        reject_tainted_run(receipt)
    except ValueError as error:
        assert getattr(error, 'sharing', None) == 'blocked:carrier-mismatch'
    else:
        pytest.fail('mismatched carrier must block export')


def test_p0b1_gapA_missing_lane_blocks_packaging(tmp_path, monkeypatch):
    from types import SimpleNamespace
    image = ArtifactRef('docker-local', 'sha256:' + 'a' * 64, 'a' * 64, 'linux/amd64')
    api, policy, output = _p0b1_flow_base(tmp_path, monkeypatch, image, _P0B1_ENTRYPOINT)
    monkeypatch.setattr(api, 'run_checker', lambda *args: None)
    monkeypatch.setattr(api, 'check_checker_originals', lambda *args: {})
    monkeypatch.setattr(api, 'admit_checker', lambda *args: {})

    def _consumer(spec):
        spec.output_dir.mkdir()
        receipt = spec.output_dir / 'receipt.json'
        receipt.write_text(json.dumps({'bounded_execution': {'output': {'readback': {'tainted': False}}}}))
        return SimpleNamespace(receipt_path=receipt, exit_code=0, app_returncode=0,
                               lifecycle_errors=(), cleanup_errors=())

    monkeypatch.setattr(api, 'run_application', _consumer)
    monkeypatch.setattr(api, 'verify_consumer_output', lambda *args: {})
    result = api.validate_image(image, policy, output)
    assert result['status'] == 'incomplete' and result['sharing'] == 'blocked:unknown-receipt'
    assert 'package' not in result and 'body' not in result
    assert not (output / 'package.tar.gz').exists() and not (output / 'validation-body.json').exists()


def test_p0b1_gapB_export_gate_schema_exact():
    from p11lab.image_validation import EXPORT_GATE_CHECKS, EXPORT_GATE_SCHEMA
    assert EXPORT_GATE_SCHEMA == 'p11lab.evidence-gate.v1'
    assert tuple(EXPORT_GATE_CHECKS) == ('archive-scan', 'stream-scan', 'fixed-command', 'metadata-scan',
                                         'capture-complete', 'lane-admission', 'oracle-scan',
                                         'result-binding')


def test_p0b1_gapB_seal_requires_checks_and_basis(tmp_path):
    from p11lab.image_validation import _seal_gated_evidence
    root = tmp_path / 'root'
    root.mkdir()
    (root / 'evidence.txt').write_bytes(b'sealed')
    with pytest.raises(ValueError, match='gate-1 export gate'):
        _seal_gated_evidence(root, None)
    gate = _p0b1_minimal_gate()
    gate['checks'] = []
    with pytest.raises(ValueError, match='gate-1 export gate'):
        _seal_gated_evidence(root, gate)
    gate = _p0b1_minimal_gate()
    del gate['basis']
    with pytest.raises(ValueError, match='gate-1 export gate'):
        _seal_gated_evidence(root, gate)


def _p0b1_successful_flow(tmp_path, monkeypatch):
    """Complete hermetic flow: valid lanes, real oracle on the fake engine, mocked evaluator."""
    import os
    from types import SimpleNamespace
    image = ArtifactRef('docker-local', 'sha256:' + 'a' * 64, 'a' * 64, 'linux/amd64')
    api, policy, output = _p0b1_flow_base(tmp_path, monkeypatch, image, _P0B1_ENTRYPOINT)
    user = f'{os.getuid()}:{os.getgid()}'
    engine = _P0B1OracleEngine('sha256:' + 'e' * 64, user, _P0B1_ENTRYPOINT)
    monkeypatch.setattr(api, 'Docker', lambda: engine)
    attempts = {'checker': 'c' * 32, 'consumer': 'd' * 32}
    tars = {lane: b'fake-bounded-tar-bytes/' + lane.encode() for lane in attempts}

    def _checker(spec, profile):
        receipt = _p0b1_valid_receipt(image=image.reference, lane='checker',
                                      attempt=attempts['checker'], entrypoint=_P0B1_ENTRYPOINT,
                                      user=user, tar_bytes=tars['checker'], app_returncode=1)
        _p0b1_write_lane(spec.output_dir, receipt, tars['checker'])

    def _consumer(spec):
        receipt = _p0b1_valid_receipt(image=image.reference, lane='consumer',
                                      attempt=attempts['consumer'], entrypoint=_P0B1_ENTRYPOINT,
                                      user=user, tar_bytes=tars['consumer'])
        _p0b1_write_lane(spec.output_dir, receipt, tars['consumer'])
        _p0b1_crypto(spec.output_dir / 'crypto')
        return SimpleNamespace(receipt_path=spec.output_dir / 'receipt.json', exit_code=0,
                               app_returncode=0, lifecycle_errors=(), cleanup_errors=())

    monkeypatch.setattr(api, 'run_checker', _checker)
    monkeypatch.setattr(api, 'check_checker_originals',
                        lambda *args: {'outer_attempt_id': attempts['checker'],
                                        'checker_attempt_id': 'e' * 32, 'app_returncode': 1,
                                        'summary': {'failed': 1}, 'cache_count': 23})
    monkeypatch.setattr(api, 'admit_checker', lambda *args: {})
    monkeypatch.setattr(api, 'run_application', _consumer)
    result = api.validate_image(image, policy, output)
    return output, result, attempts, tars


def test_p0b1_gapB_packaged_body_carries_export_gate(tmp_path, monkeypatch):
    import hashlib
    import p11lab.image_validation as api
    output, result, attempts, _ = _p0b1_successful_flow(tmp_path, monkeypatch)
    assert result['status'] == 'observations-complete' and result['sharing'] == 'local-evidence-package'
    assert (output / 'package.tar.gz').is_file() and (output / 'validation-body.json').is_file()
    body = json.loads((output / 'validation-body.json').read_bytes())
    gate = body['export_gate']
    assert gate['schema'] == 'p11lab.evidence-gate.v1' and gate['verdict'] == 'eligible'
    assert gate['checks'] == [{'name': name, 'result': 'pass'} for name in api.EXPORT_GATE_CHECKS]
    basis = gate['basis']
    assert basis['checker_attempt_id'] == attempts['checker']
    assert basis['consumer_attempt_id'] == attempts['consumer']
    assert basis['controller_sha256'] == api._source_digest()
    for lane in ('checker', 'consumer'):
        raw = (output / (lane + '-run/receipt.json')).read_bytes()
        assert basis[lane + '_receipt_sha256'] == hashlib.sha256(raw).hexdigest()
        assert basis[lane + '_receipt_size'] == len(raw)
        assert basis[lane + '_stages'] == [row['container_id']
                                           for row in json.loads(raw)['stages']]
    expected_oracle = sorted([f'{directory}/{name}' for directory in ('original', 'message', 'signature')
                              for name in _P0B1_CRYPTO_NAMES] + ['message/altered.bin'])
    assert [row['path'] for row in basis['oracle_inputs']] == expected_oracle
    for row in basis['oracle_inputs']:
        raw = (output / 'oracle' / row['path']).read_bytes()
        assert row['size'] == len(raw) and row['sha256'] == hashlib.sha256(raw).hexdigest()
    assert len(basis['scan_completion']) == 16
    assert all(row['scanned'] and row['clean'] for row in basis['scan_completion'])
    assert {(row['lane'], row['phase'], row['stream']) for row in basis['scan_completion']} == {
        (lane, phase, stream) for lane in ('checker', 'consumer')
        for phase in _P0B1_PHASES for stream in ('stdout', 'stderr')}


def test_p0b1_gapB_legacy_package_refused_without_gate(tmp_path):
    from p11lab.image_validation import verify_evidence_package
    with pytest.raises(ValueError, match='unsupported facade export gate'):
        verify_evidence_package(tmp_path / 'missing.tar.gz', {}, {}, None, {})


def test_p0b1_gapB_wrong_gate_schema_refused(tmp_path):
    from p11lab.image_validation import verify_evidence_package
    value = {'export_gate': {'schema': 'p11lab-facade-gate1-v1',
                             'checks': [], 'verdict': 'eligible', 'basis': {}}}
    with pytest.raises(ValueError, match='unsupported facade export gate'):
        verify_evidence_package(tmp_path / 'missing.tar.gz', {}, value, None, {})


def test_p0b1_gapC_package_file_created_0600(tmp_path):
    import os
    from p11lab.image_validation import _package_evidence, _seal_evidence
    root = tmp_path / 'root'
    root.mkdir()
    (root / 'evidence.txt').write_bytes(b'sealed')
    entries = _seal_evidence(root)
    old = os.umask(0)
    try:
        package = _package_evidence(root, entries)
    finally:
        os.umask(old)
    assert package['path'] == 'package.tar.gz'
    assert (root / 'package.tar.gz').stat().st_mode & 0o777 == 0o600


def test_p0b1_gapC_snapshot_member_modes_required():
    import tarfile
    from p11lab.image_validation import _require_normalized_member

    def _member(**overrides):
        info = tarfile.TarInfo('evidence.txt')
        info.size, info.mode, info.uid, info.gid, info.mtime = 1, 0o600, 0, 0, 0
        info.type = tarfile.REGTYPE
        for key, value in overrides.items():
            setattr(info, key, value)
        return info

    _require_normalized_member(_member())
    for bad in ({'mode': 0o644}, {'mode': 0o400}, {'uid': 1}, {'gid': 1}, {'mtime': 1}):
        with pytest.raises(ValueError, match='not normalized'):
            _require_normalized_member(_member(**bad))


def test_p0b1_gapC_snapshot_files_private(tmp_path):
    import os
    import tarfile
    from p11lab.image_validation import (_assert_snapshot_modes, _extract_snapshot_member,
                                          _package_evidence, _seal_evidence)
    root = tmp_path / 'root'
    (root / 'nested').mkdir(parents=True)
    (root / 'evidence.txt').write_bytes(b'sealed')
    (root / 'nested/inner.bin').write_bytes(b'inner')
    entries = _seal_evidence(root)
    observed = {entry['path']: entry for entry in entries}
    old = os.umask(0)
    try:
        _package_evidence(root, entries)
        snapshot = tmp_path / 'snapshot'
        snapshot.mkdir(mode=0o700)
        os.chmod(snapshot, 0o700)
        secured = {snapshot}
        with tarfile.open(root / 'package.tar.gz', 'r:gz') as bundle:
            for member in bundle:
                assert member.mode == 0o600 and member.uid == 0 and member.gid == 0
                _extract_snapshot_member(snapshot=snapshot, secured=secured, member=member,
                                         source=bundle.extractfile(member),
                                         expected=observed[member.name])
        assert (snapshot / 'evidence.txt').stat().st_mode & 0o777 == 0o600
        assert (snapshot / 'nested').stat().st_mode & 0o777 == 0o700
        assert (snapshot / 'nested/inner.bin').stat().st_mode & 0o777 == 0o600
        _assert_snapshot_modes(snapshot)
        (snapshot / 'evidence.txt').chmod(0o644)
        with pytest.raises(ValueError, match='mode'):
            _assert_snapshot_modes(snapshot)
    finally:
        os.umask(old)


def test_p0b1_gapC_no_umask_call_in_src():
    import re
    from pathlib import Path as _Path
    import p11lab
    hits = []
    for path in sorted((_Path(p11lab.__file__).parent).glob('*.py')):
        for number, line in enumerate(path.read_text().splitlines(), 1):
            if re.search(r'(?<!\w)umask\s*\(', line):
                hits.append(f'{path.name}:{number}')
    assert hits == []


def test_p0b1_gapC_packaged_output_modes_private(tmp_path, monkeypatch):
    output, result, _, _ = _p0b1_successful_flow(tmp_path, monkeypatch)
    assert result['status'] == 'observations-complete'
    assert output.stat().st_mode & 0o777 == 0o700
    assert (output / 'package.tar.gz').stat().st_mode & 0o777 == 0o600
    assert (output / 'validation-body.json').stat().st_mode & 0o777 == 0o600
    assert (output / 'evidence-manifest.json').stat().st_mode & 0o777 == 0o600
    assert (output / 'validation.json').stat().st_mode & 0o777 == 0o600


def _p0b1_outer_receipt(tmp_path):
    import os
    image = 'sha256:' + 'a' * 64
    receipt = _p0b1_valid_receipt(image=image, lane='checker', attempt='c' * 32,
                                  entrypoint=_P0B1_ENTRYPOINT,
                                  user=f'{os.getuid()}:{os.getgid()}',
                                  tar_bytes=b'outer-tar', app_returncode=0)
    path = tmp_path / 'receipt.json'
    path.write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')
    return path, receipt


def test_p0b1_gapD_summary_merge_preserves_gate_fields(tmp_path):
    from p11lab.checker import GATE_RECEIPT_FIELDS, merge_checker_summary
    path, before = _p0b1_outer_receipt(tmp_path)
    merged = merge_checker_summary(path, profile='smoke-v1', nodes=['n1'],
                                   evidence_complete=False, observations_complete=False,
                                   exit_code=0)
    assert merged['checker'] == {'profile': 'smoke-v1', 'nodes': ['n1'],
                                 'evidence_complete': False, 'observations_complete': False}
    assert merged['lifecycle_errors'] == ['checker observation evidence incomplete or unavailable']
    assert merged['exit_code'] == 1
    assert set(merged) - set(before) == {'checker'}
    for key in GATE_RECEIPT_FIELDS:
        assert key in before, key
        assert merged[key] == before[key], key
    for key in before:
        if key not in ('lifecycle_errors', 'exit_code'):
            assert merged[key] == before[key], key


def test_p0b1_gapD_lifecycle_append_only_and_no_summary_replace(tmp_path):
    from p11lab.checker import merge_checker_summary
    path, before = _p0b1_outer_receipt(tmp_path)
    before['lifecycle_errors'] = ['earlier']
    path.write_text(json.dumps(before, sort_keys=True, indent=2) + '\n')
    merged = merge_checker_summary(path, profile='smoke-v1', nodes=['n1'],
                                   evidence_complete=True, observations_complete=False,
                                   exit_code=0)
    assert merged['lifecycle_errors'] == ['earlier', 'checker observation evidence incomplete or unavailable']
    assert merged['exit_code'] == 0
    with pytest.raises(ValueError, match='checker'):
        merge_checker_summary(path, profile='other', nodes=['n2'],
                              evidence_complete=True, observations_complete=True,
                              exit_code=0)


def test_p0b1_gapD_nonzero_exit_never_cleared(tmp_path):
    from p11lab.checker import merge_checker_summary
    path, before = _p0b1_outer_receipt(tmp_path)
    before['exit_code'] = 1
    path.write_text(json.dumps(before, sort_keys=True, indent=2) + '\n')
    merged = merge_checker_summary(path, profile='smoke-v1', nodes=['n1'],
                                   evidence_complete=False, observations_complete=True,
                                   exit_code=1)
    assert merged['exit_code'] == 1
    before['exit_code'] = 2
    path.write_text(json.dumps(before, sort_keys=True, indent=2) + '\n')
    with pytest.raises(ValueError, match='exit'):
        merge_checker_summary(path, profile='smoke-v1', nodes=['n1'],
                              evidence_complete=False, observations_complete=True,
                              exit_code=0)
    (tmp_path / 'second').mkdir(exist_ok=True)
    path2, _ = _p0b1_outer_receipt(tmp_path / 'second')
    merged = merge_checker_summary(path2, profile='smoke-v1', nodes=['n1'],
                                   evidence_complete=True, observations_complete=True,
                                   exit_code=0)
    assert merged['exit_code'] == 0 and merged['lifecycle_errors'] == []


def test_p0b1_gapD_run_checker_uses_gated_merge(tmp_path, monkeypatch):
    import p11lab.checker as checker_api
    from p11lab.models import ArtifactRef, RunResult, RunSpec
    calls = []
    real = checker_api.merge_checker_summary

    def _spy(path, **kwargs):
        calls.append((str(path), kwargs))
        return real(path, **kwargs)

    monkeypatch.setattr(checker_api, 'merge_checker_summary', _spy)

    def _fake_run_app(spec):
        out = spec.output_dir
        (out / 'checker').mkdir(parents=True)
        (out / 'checker/checker-receipt.json').write_text(json.dumps(
            {'evidence': {'complete': True, 'observations_complete': True}}))
        _, receipt = _p0b1_outer_receipt(out)
        return RunResult(app_returncode=0, lifecycle_errors=(), cleanup_errors=(),
                         exit_code=0, receipt_path=out / 'receipt.json')

    monkeypatch.setattr('p11lab.run.run_application', _fake_run_app)
    image = ArtifactRef('docker-local', 'sha256:' + 'a' * 64, 'a' * 64, 'linux/amd64')
    spec = RunSpec('softhsm2', 'release', 'direct', image, 'provider', None, None, (),
                   {}, tmp_path / 'run', tmp_path, 10)
    result = checker_api.run_checker(spec, 'smoke-v1')
    assert len(calls) == 1 and calls[0][1]['profile'] == 'p11lab-smoke-v1'
    outer = json.loads((tmp_path / 'run' / 'receipt.json').read_text())
    assert outer['checker']['observations_complete'] is True
    assert result.exit_code == 0 and result.lifecycle_errors == ()


def test_p0b1_gapD_ledger_text_stays_comparable(tmp_path):
    from p11lab.checker import merge_checker_summary
    path, _ = _p0b1_outer_receipt(tmp_path)
    merged = merge_checker_summary(path, profile='smoke-v1', nodes=['n1'],
                                   evidence_complete=True, observations_complete=True,
                                   exit_code=0)
    assert path.read_bytes() == (json.dumps(merged, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()


def test_p0b1_gapE_shareable_roster_empty():
    from p11lab.image_validation import SHAREABLE_INCOMPLETE_ROSTER, _shareable_incomplete
    assert SHAREABLE_INCOMPLETE_ROSTER == frozenset()
    assert _shareable_incomplete({'infrastructure_errors': ['checker/admission: ValueError: boom']}) is False
    assert _shareable_incomplete({'infrastructure_errors': []}) is False
    assert _shareable_incomplete({}) is False


def test_p0b1_gapE_incomplete_never_packages(tmp_path, monkeypatch):
    import os
    from types import SimpleNamespace
    image = ArtifactRef('docker-local', 'sha256:' + 'a' * 64, 'a' * 64, 'linux/amd64')
    api, policy, output = _p0b1_flow_base(tmp_path, monkeypatch, image, _P0B1_ENTRYPOINT)
    user = f'{os.getuid()}:{os.getgid()}'
    attempts = {'checker': 'c' * 32, 'consumer': 'd' * 32}
    tars = {lane: b'fake-bounded-tar-bytes/' + lane.encode() for lane in attempts}

    def _checker(spec, profile):
        receipt = _p0b1_valid_receipt(image=image.reference, lane='checker',
                                      attempt=attempts['checker'], entrypoint=_P0B1_ENTRYPOINT,
                                      user=user, tar_bytes=tars['checker'], app_returncode=1)
        _p0b1_write_lane(spec.output_dir, receipt, tars['checker'])

    def _consumer(spec):
        receipt = _p0b1_valid_receipt(image=image.reference, lane='consumer',
                                      attempt=attempts['consumer'], entrypoint=_P0B1_ENTRYPOINT,
                                      user=user, tar_bytes=tars['consumer'])
        _p0b1_write_lane(spec.output_dir, receipt, tars['consumer'])
        return SimpleNamespace(receipt_path=spec.output_dir / 'receipt.json', exit_code=0,
                               app_returncode=0, lifecycle_errors=(), cleanup_errors=())

    def _boom(*args, **kwargs):
        raise ValueError('oracle boom')

    monkeypatch.setattr(api, 'run_checker', _checker)
    monkeypatch.setattr(api, 'check_checker_originals', lambda *args: {'summary': {}})
    monkeypatch.setattr(api, 'admit_checker', lambda *args: {})
    monkeypatch.setattr(api, 'run_application', _consumer)
    monkeypatch.setattr(api, 'verify_consumer_output', _boom)
    result = api.validate_image(image, policy, output)
    assert result['status'] == 'incomplete' and result['sharing'] == 'blocked-incomplete-evidence'
    assert 'package' not in result and 'body' not in result
    assert not (output / 'package.tar.gz').exists() and not (output / 'validation-body.json').exists()


def test_p0b1_gapE_body_binding_cross_check():
    from p11lab.image_validation import check_body_binding
    value = {'status': 'observations-complete', 'n': 1}
    body_raw = (json.dumps(value, sort_keys=True) + '\n').encode()
    assert check_body_binding(value, body_raw) is None
    with pytest.raises(ValueError, match='validation body differs from envelope'):
        check_body_binding(value, (json.dumps({'status': 'incomplete', 'n': 1}) + '\n').encode())
    with pytest.raises(ValueError, match='validation body differs from envelope'):
        check_body_binding({'status': 'tampered', 'n': 1}, body_raw)


def test_p0b1_gapE_verifier_cross_checks_enclosed_body(tmp_path, monkeypatch):
    import hashlib
    import p11lab.image_validation as api
    from p11lab.checker import load_profile
    from p11lab.image_validation import _package_evidence, _seal_evidence, verify_evidence_package
    tools = {}
    for name, digit in (('checker', '1'), ('consumer', '2'), ('oracle', '3')):
        root = tmp_path / name
        root.mkdir()
        tools[name] = {'root': str(root), 'input_receipt': str(root / 'input.json'),
                       'manifest_sha256': digit * 64}
    (tmp_path / 'evaluator').mkdir()
    policy = {'tools': tools, 'evaluator': {'root': str(tmp_path / 'evaluator'), 'receipt_sha256': '4' * 64},
              'control_base_revision': '5' * 40}
    package_dir = Path(api.__file__).parent
    fixed_raw = (package_dir / 'data/ci/delivery/validation-policy.json').read_bytes()
    profile_raw = (package_dir / 'data/profiles/smoke-v1.json').read_bytes()
    body = {'schema_version': 1, 'kind': 'local-image-validation', 'scope': 'local-only',
            'authority': 'local-unauthenticated', 'status': 'observations-complete',
            'sharing': 'local-evidence-package', 'infrastructure_errors': [],
            'tool_manifest_sha256': {name: row['manifest_sha256'] for name, row in tools.items()},
            'evaluator_receipt_sha256': '4' * 64, 'control_base_revision_declared': '5' * 40,
            'control_source_sha256': api._source_digest(), 'comparison': None, 'promotable': False,
            'qualification_eligible': False,
            'fixed_policy_sha256': hashlib.sha256(fixed_raw).hexdigest(),
            'profile_sha256': hashlib.sha256(profile_raw).hexdigest(),
            'checker_source_files': load_profile()['sources'],
            'control_commit': None, 'export_gate': _p0b1_minimal_gate()}
    root = tmp_path / 'evidence'
    root.mkdir()
    (root / 'validation-body.json').write_bytes((json.dumps(body, sort_keys=True, indent=2) + '\n').encode())
    entries = _seal_evidence(root)
    (root / 'evidence-manifest.json').write_text(json.dumps({'files': entries}, sort_keys=True, indent=2) + '\n')
    entries.append({'path': 'evidence-manifest.json', 'size': (root / 'evidence-manifest.json').stat().st_size,
                    'sha256': hashlib.sha256((root / 'evidence-manifest.json').read_bytes()).hexdigest()})
    _package_evidence(root, entries)
    observed = {entry['path']: entry for entry in entries}
    monkeypatch.setattr(api, 'verify_tool_build', lambda root, **kwargs: {'toolset': Path(root).name})
    monkeypatch.setattr(api, 'verify_evaluator', lambda *args: {})
    value = json.loads(json.dumps(body))
    value['control_commit'] = 'tampered-after-seal'
    with pytest.raises(ValueError, match='validation body differs from envelope'):
        verify_evidence_package(root / 'package.tar.gz', observed, value, None, policy)


def test_p0b1_gapE_verifier_enforces_roster(tmp_path):
    from p11lab.image_validation import verify_evidence_package
    value = {'export_gate': _p0b1_minimal_gate(), 'status': 'incomplete',
             'sharing': 'local-evidence-package', 'infrastructure_errors': ['boom']}
    with pytest.raises(ValueError, match='shareable roster'):
        verify_evidence_package(tmp_path / 'missing.tar.gz', {}, value, None, {})


def _p0b1_truncated_receipt(phase, stream):
    stages = []
    for name in _P0B1_PHASES:
        stages.append({'phase': name, 'stdout_truncated': name == phase and stream == 'stdout',
                       'stderr_truncated': name == phase and stream == 'stderr'})
    return {'bounded_execution': {}, 'stages': stages}


@pytest.mark.parametrize('phase', ['init', 'ready', 'application', 'post-health'])
@pytest.mark.parametrize('stream', ['stdout', 'stderr'])
def test_p0b1_gapF_truncation_blocks_export(phase, stream):
    from p11lab.bounded_run import CaptureUnavailableError
    from p11lab.image_validation import check_gate_admission
    with pytest.raises(CaptureUnavailableError, match='truncated capture'):
        check_gate_admission(_p0b1_truncated_receipt(phase, stream), lane='consumer')


def test_p0b1_gapF_clean_flags_pass_truncation_screen():
    from p11lab.image_validation import check_gate_admission, GateCarrierError
    receipt = _p0b1_truncated_receipt('application', 'stdout')
    for row in receipt['stages']:
        row['stdout_truncated'] = row['stderr_truncated'] = False
    with pytest.raises(GateCarrierError):
        check_gate_admission(receipt, lane='consumer')


def test_p0b1_gapF_truncated_clean_lane_blocks_packaging(tmp_path, monkeypatch):
    import os
    from types import SimpleNamespace
    image = ArtifactRef('docker-local', 'sha256:' + 'a' * 64, 'a' * 64, 'linux/amd64')
    api, policy, output = _p0b1_flow_base(tmp_path, monkeypatch, image, _P0B1_ENTRYPOINT)
    user = f'{os.getuid()}:{os.getgid()}'
    tar = b'fake-bounded-tar-bytes/checker'

    def _checker(spec, profile):
        receipt = _p0b1_valid_receipt(image=image.reference, lane='checker', attempt='c' * 32,
                                      entrypoint=_P0B1_ENTRYPOINT, user=user, tar_bytes=tar,
                                      app_returncode=1)
        _p0b1_write_lane(spec.output_dir, receipt, tar)

    def _consumer(spec):
        spec.output_dir.mkdir()
        receipt = _p0b1_truncated_receipt('application', 'stdout')
        (spec.output_dir / 'receipt.json').write_text(json.dumps(receipt))
        return SimpleNamespace(receipt_path=spec.output_dir / 'receipt.json', exit_code=0,
                               app_returncode=0, lifecycle_errors=(), cleanup_errors=())

    monkeypatch.setattr(api, 'run_checker', _checker)
    monkeypatch.setattr(api, 'check_checker_originals', lambda *args: {'summary': {}})
    monkeypatch.setattr(api, 'admit_checker', lambda *args: {})
    monkeypatch.setattr(api, 'run_application', _consumer)
    monkeypatch.setattr(api, 'verify_consumer_output', lambda *args: {})
    result = api.validate_image(image, policy, output)
    assert result['status'] == 'incomplete' and result['sharing'] == 'blocked-stream-capture-unavailable'
    assert any('truncated capture' in error for error in result['infrastructure_errors'])
    assert 'package' not in result and 'body' not in result
    assert not (output / 'package.tar.gz').exists() and not (output / 'validation-body.json').exists()


def _p0b1_admission_case(mutation):
    import os
    image = 'sha256:' + 'a' * 64
    user = f'{os.getuid()}:{os.getgid()}'
    tar = b'fake-bounded-tar-bytes/consumer'
    receipt = _p0b1_valid_receipt(image=image, lane='consumer', attempt='d' * 32,
                                  entrypoint=_P0B1_ENTRYPOINT, user=user, tar_bytes=tar)
    kwargs = {'lane': 'consumer', 'tar_bytes': tar}
    expected = None
    if mutation == 'native-routing':
        receipt['mode'] = 'native'
        del receipt['bounded_execution']
        del receipt['bounded_policy']
        expected = 'blocked:foreign-receipt'
    elif mutation == 'missing-policy':
        del receipt['bounded_policy']
        expected = 'blocked:carrier-mismatch'
    elif mutation == 'bad-attempt':
        receipt['attempt_id'] = 'ZZZ'
        expected = 'blocked:carrier-mismatch'
    elif mutation == 'bad-stage-id':
        receipt['stages'][0]['container_id'] = 'ZZZ'
        expected = 'blocked:carrier-mismatch'
    elif mutation == 'dup-stage-id':
        receipt['stages'][1]['container_id'] = receipt['stages'][0]['container_id']
        expected = 'blocked:carrier-mismatch'
    elif mutation == 'uncertain':
        receipt['uncertain_resources'] = [{'kind': 'container', 'name': 'x'}]
        expected = 'blocked:carrier-mismatch'
    elif mutation == 'cleanup':
        receipt['cleanup_errors'] = ['x']
        expected = 'blocked:carrier-mismatch'
    elif mutation == 'readback-code':
        receipt['bounded_execution']['output']['readback']['returncode'] = 1
        expected = 'blocked:carrier-mismatch'
    elif mutation == 'missing-observation':
        del receipt['bounded_execution']['stages']['application']['fixed_validation_observation']
        expected = 'blocked:carrier-mismatch'
    elif mutation == 'tar-mismatch':
        kwargs['tar_bytes'] = b'other-bytes'
        expected = 'blocked:carrier-mismatch'
    elif mutation == 'image-context':
        kwargs['image'] = 'sha256:' + 'f' * 64
        expected = 'blocked:carrier-mismatch'
    elif mutation == 'basis-context':
        kwargs['basis'] = {'consumer_attempt_id': '0' * 32,
                           'consumer_stages': [row['container_id'] for row in receipt['stages']]}
        expected = 'blocked:carrier-mismatch'
    return receipt, kwargs, expected


@pytest.mark.parametrize('mutation', ['pass', 'native-routing', 'missing-policy', 'bad-attempt',
                                      'bad-stage-id', 'dup-stage-id', 'uncertain', 'cleanup',
                                      'readback-code', 'missing-observation', 'tar-mismatch',
                                      'image-context', 'basis-context'])
def test_p0b1_gapG_admission_predicate_classes(mutation):
    from p11lab.image_validation import check_gate_admission
    receipt, kwargs, expected = _p0b1_admission_case(mutation)
    if expected is None:
        assert check_gate_admission(receipt, **kwargs) is None
    else:
        try:
            check_gate_admission(receipt, **kwargs)
        except ValueError as error:
            assert getattr(error, 'sharing', None) == expected
        else:
            pytest.fail(f'{mutation} must block export')


def test_p0b1_gapG_single_helper_three_call_sites():
    import inspect
    import p11lab.image_validation as api
    assert len(inspect.getsource(api).split('def check_gate_admission(')) == 2
    for name in ('reject_tainted_run', 'build_export_gate', 'verify_evidence_package'):
        assert 'check_gate_admission(' in inspect.getsource(getattr(api, name)), name


def test_p0b1_gapG_unbounded_lane_refused(tmp_path):
    from p11lab.image_validation import reject_tainted_run
    receipt = {'schema_version': 1, 'attempt_id': 'd' * 32, 'environment': 'softhsm2',
               'channel': 'release', 'mode': 'direct', 'execution_location': 'provider',
               'stages': [{'phase': phase} for phase in _P0B1_PHASES]}
    path = tmp_path / 'consumer-run' / 'receipt.json'
    path.parent.mkdir()
    path.write_text(json.dumps(receipt))
    try:
        reject_tainted_run(path)
    except ValueError as error:
        assert getattr(error, 'sharing', None) == 'blocked:foreign-receipt'
    else:
        pytest.fail('unbounded lane receipt must block export as foreign')


def test_p0b1_gapG_packaging_enforces_fixed_observation(tmp_path, monkeypatch):
    import os
    from types import SimpleNamespace
    image = ArtifactRef('docker-local', 'sha256:' + 'a' * 64, 'a' * 64, 'linux/amd64')
    api, policy, output = _p0b1_flow_base(tmp_path, monkeypatch, image, _P0B1_ENTRYPOINT)
    user = f'{os.getuid()}:{os.getgid()}'
    attempts = {'checker': 'c' * 32, 'consumer': 'd' * 32}
    tars = {lane: b'fake-bounded-tar-bytes/' + lane.encode() for lane in attempts}

    def _checker(spec, profile):
        receipt = _p0b1_valid_receipt(image=image.reference, lane='checker',
                                      attempt=attempts['checker'], entrypoint=_P0B1_ENTRYPOINT,
                                      user=user, tar_bytes=tars['checker'], app_returncode=1)
        _p0b1_write_lane(spec.output_dir, receipt, tars['checker'])

    def _consumer(spec):
        receipt = _p0b1_valid_receipt(image=image.reference, lane='consumer',
                                      attempt=attempts['consumer'], entrypoint=_P0B1_ENTRYPOINT,
                                      user=user, tar_bytes=tars['consumer'])
        receipt['bounded_execution']['stages']['application']['fixed_validation_observation']['command_sha256'] = 'tampered'
        _p0b1_write_lane(spec.output_dir, receipt, tars['consumer'])
        return SimpleNamespace(receipt_path=spec.output_dir / 'receipt.json', exit_code=0,
                               app_returncode=0, lifecycle_errors=(), cleanup_errors=())

    def _oracle_ok(tool_dir, receipt, seal, crypto, out, **kwargs):
        out.mkdir(parents=True, exist_ok=True)
        for directory in ('original', 'message', 'signature'):
            for name in _P0B1_CRYPTO_NAMES:
                target = out / directory / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(b'oracle-bytes/' + name.encode())
        (out / 'message/altered.bin').write_bytes(b'altered')
        (out / 'oracle.json').write_text(json.dumps({'controls': {}}))
        return {'controls': {}, 'cleanup_errors': []}

    monkeypatch.setattr(api, 'run_checker', _checker)
    monkeypatch.setattr(api, 'check_checker_originals', lambda *args: {'summary': {}})
    monkeypatch.setattr(api, 'admit_checker', lambda *args: {})
    monkeypatch.setattr(api, 'run_application', _consumer)
    monkeypatch.setattr(api, 'verify_consumer_output', _oracle_ok)
    result = api.validate_image(image, policy, output)
    assert result['status'] == 'incomplete' and result['sharing'] == 'blocked:carrier-mismatch'
    assert 'package' not in result and 'body' not in result
    assert not (output / 'package.tar.gz').exists() and not (output / 'validation-body.json').exists()


def _p0b1_oracle_tree(root):
    for directory in ('original', 'message', 'signature'):
        for name in _P0B1_CRYPTO_NAMES:
            target = root / directory / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b'bytes/' + directory.encode() + b'/' + name.encode())
    (root / 'message/altered.bin').write_bytes(b'altered')
    return root


def test_p0b1_gapH_oracle_scan_finds_planted_secret(tmp_path, monkeypatch):
    import p11lab.image_validation as api
    from p11lab.bounded_run import CredentialTaintError
    secret = 'p11lab-h1-planted-secret-41af'
    crypto = _p0b1_crypto(tmp_path / 'crypto',
                          {'message.bin': b'prefix-' + secret.encode() + b'-suffix'})
    monkeypatch.setattr(api, 'verify_tool_build',
                        lambda root, **kwargs: {'toolset': 'oracle',
                                                'installed': {'engine_id': 'sha256:' + 'e' * 64}})

    def _no_engine():
        raise RuntimeError('must not reach engine')

    monkeypatch.setattr(api, 'Docker', _no_engine)
    with pytest.raises(CredentialTaintError, match='credential'):
        api.verify_consumer_output(tmp_path / 'tool', tmp_path / 'receipt.json', '0' * 64,
                                   crypto, tmp_path / 'oracle', scan_secrets=(secret,))


def test_p0b1_gapH_scan_proof_bindings_sorted(tmp_path):
    import hashlib
    from p11lab.image_validation import scan_oracle_inputs
    root = _p0b1_oracle_tree(tmp_path / 'oracle')
    scan = scan_oracle_inputs(root, ('unrelated-secret',))
    assert scan['clean'] is True
    assert len(scan['inputs']) == 22
    assert [row['path'] for row in scan['inputs']] == sorted(row['path'] for row in scan['inputs'])
    for row in scan['inputs']:
        raw = (root / row['path']).read_bytes()
        assert row['size'] == len(raw) and row['sha256'] == hashlib.sha256(raw).hexdigest()


def test_p0b1_gapH_clean_oracle_records_scan_proof(tmp_path, monkeypatch):
    import os
    import p11lab.image_validation as api
    user = f'{os.getuid()}:{os.getgid()}'
    engine = _P0B1OracleEngine('sha256:' + 'e' * 64, user, _P0B1_ENTRYPOINT)
    monkeypatch.setattr(api, 'Docker', lambda: engine)
    monkeypatch.setattr(api, 'verify_tool_build',
                        lambda root, **kwargs: {'toolset': 'oracle',
                                                'installed': {'engine_id': engine.engine_id}})
    crypto = _p0b1_crypto(tmp_path / 'crypto')
    result = api.verify_consumer_output(tmp_path / 'tool', tmp_path / 'receipt.json', '0' * 64,
                                        crypto, tmp_path / 'oracle',
                                        scan_secrets=('p11lab-h3-secret-9f2c',))
    assert result['scan']['clean'] is True and len(result['scan']['inputs']) == 22
    assert result['controls']['positive']['returncode'] == 0
    assert result['controls']['altered_message']['returncode'] == 1
    assert result['controls']['altered_signature']['returncode'] == 1
    assert set(result['public_outputs']) == set(_P0B1_CRYPTO_NAMES)


def test_p0b1_gapH_verifier_binds_scan_proof(tmp_path):
    import hashlib
    from p11lab.image_validation import check_oracle_scan_binding
    root = _p0b1_oracle_tree(tmp_path / 'oracle')
    bindings = []
    for directory in ('original', 'message', 'signature'):
        for name in _P0B1_CRYPTO_NAMES:
            raw = (root / directory / name).read_bytes()
            bindings.append({'path': f'{directory}/{name}', 'size': len(raw),
                             'sha256': hashlib.sha256(raw).hexdigest()})
    raw = (root / 'message/altered.bin').read_bytes()
    bindings.append({'path': 'message/altered.bin', 'size': len(raw),
                     'sha256': hashlib.sha256(raw).hexdigest()})
    bindings.sort(key=lambda row: row['path'])
    scan = {'inputs': bindings, 'clean': True}
    assert check_oracle_scan_binding(root, scan, bindings) is None
    (root / 'message/altered.bin').write_bytes(b'tampered-bytes!')
    with pytest.raises(ValueError, match='oracle'):
        check_oracle_scan_binding(root, scan, bindings)
    with pytest.raises(ValueError, match='oracle'):
        check_oracle_scan_binding(root, scan, [])
