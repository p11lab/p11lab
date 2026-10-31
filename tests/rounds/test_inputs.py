"""Authority construction failures must precede candidate execution."""

import json
from pathlib import Path

import pytest

from p11lab.round_core import inputs

FIXTURES = Path(__file__).parent / "fixtures/authority"


@pytest.mark.parametrize("axis", ["checker", "image", "proxy"])
def test_protected_expectation_accepts_only_selected_axis(axis):
    value = json.loads((FIXTURES / f"{axis}-authorized.json").read_bytes())[
        "protected_expected"
    ]
    frozen = inputs.freeze_comparison_expectation(value)
    assert frozen.as_dict() == value
    value["protected"]["control_sha"] = "a" * 40
    assert frozen.as_dict()["protected"]["control_sha"] != "a" * 40


@pytest.mark.parametrize(
    "mutation",
    [
        "axis",
        "source",
        "control",
        "family",
        "platform",
        "parent",
        "unselected-proxy",
        "bool",
        "unknown",
        "duplicate",
        "omitted",
        "union",
    ],
)
def test_protected_expectation_rejects_inconsistent_selection(mutation):
    value = json.loads((FIXTURES / "checker-authorized.json").read_bytes())[
        "protected_expected"
    ]
    candidate = value["endpoints"]["candidate"]
    if mutation == "axis":
        value["allowed_axis"] = "proxy"
    if mutation == "source":
        value["protected"]["selected_candidate_source_sha"] = "a" * 40
    if mutation == "control":
        candidate["frozen_controls"]["profile"] = "a" * 64
    if mutation == "family":
        candidate["artifacts"]["provider"]["family"] = "nss"
    if mutation == "platform":
        candidate["artifacts"]["provider"]["platform"] = "linux/arm64"
    if mutation == "parent":
        candidate["artifacts"]["derivative"]["parent_manifest_digest"] = (
            "sha256:" + "a" * 64
        )
    if mutation == "unselected-proxy":
        candidate["artifacts"]["proxy"]["daemon_sha256"] = "a" * 64
    if mutation == "bool":
        value["schema_version"] = True
    if mutation == "unknown":
        candidate["unexpected"] = 1
    if mutation == "duplicate":
        candidate["catalog"].append(candidate["catalog"][0])
    if mutation == "omitted":
        candidate["observed_selected"] = []
    if mutation == "union":
        value["catalog_union"] = []
    with pytest.raises(ValueError):
        inputs.freeze_comparison_expectation(value)


def test_absent_proxy_is_explicit_and_cannot_authorize_proxy_axis():
    value = json.loads((FIXTURES / "checker-authorized.json").read_bytes())[
        "protected_expected"
    ]
    value = json.loads((FIXTURES / "checker-direct-authorized.json").read_bytes())[
        "protected_expected"
    ]
    assert (
        inputs.freeze_comparison_expectation(value).as_dict()["endpoints"]["baseline"][
            "artifacts"
        ]["proxy"]
        is None
    )
    value.update(operation="proxy", allowed_axis="proxy")
    with pytest.raises(ValueError):
        inputs.freeze_comparison_expectation(value)


@pytest.mark.parametrize("raw", [b'{"a":1,"a":2}', b'{"a":NaN}', b"[]", b"{}" * 100])
def test_closed_json_rejects_ambiguous_or_oversized_input(raw):
    with pytest.raises(ValueError):
        inputs.load_json(raw, max_bytes=64)


def test_candidate_json_cannot_assert_authenticated_authority():
    with pytest.raises(TypeError):
        inputs.freeze_candidate_context({}, {"authenticated": True}, {}, {})


def test_full_sealed_evaluator_receipt_reaches_verifier_with_bounded_large_inventory(
    tmp_path, monkeypatch
):
    # Real W01 receipts exceed 2 MiB. Parsing must not weaken full verification.
    from p11lab.round_core import bootstrap

    (tmp_path / "evaluator-build-receipt.json").write_text(
        json.dumps({"inventory": "x" * (2 * 1024 * 1024)})
    )

    def reject_unverified(receipt, root, locks):
        raise LookupError("full bootstrap verifier called")

    monkeypatch.setattr(bootstrap, "verify_receipt", reject_unverified)
    with pytest.raises(LookupError, match="full bootstrap verifier called"):
        inputs.SealedToolInputs.from_evaluator(tmp_path)


@pytest.mark.parametrize("kind", ["symlink", "fifo", "oversize"])
def test_source_snapshot_rejects_nonregular_or_oversized_inputs(tmp_path, kind):
    import os

    path = tmp_path / "source.tar.gz"
    if kind == "symlink":
        path.symlink_to("/etc/passwd")
    if kind == "fifo":
        os.mkfifo(path)
    if kind == "oversize":
        with path.open("wb") as stream:
            stream.truncate(inputs.SOURCE_ARCHIVE_LIMIT + 1)
    with pytest.raises(ValueError, match="source archive"):
        inputs.read_source_archive(path)


def test_candidate_archive_requires_exact_regular_roster(tmp_path):
    import hashlib
    import stat
    import zipfile

    archive = tmp_path / 'dist.zip'
    with zipfile.ZipFile(archive, 'w') as out:
        out.writestr('dist/candidate.whl', b'wheel')
    expected = {'dist/candidate.whl': {'size': 5, 'sha256': hashlib.sha256(b'wheel').hexdigest()}}
    assert inputs.verify_candidate_archive(archive, expected)['dist/candidate.whl'] == b'wheel'
    with zipfile.ZipFile(archive, 'a') as out:
        link = zipfile.ZipInfo('dist/link')
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        out.writestr(link, 'candidate.whl')
    with pytest.raises(ValueError):
        inputs.verify_candidate_archive(archive, expected)


@pytest.mark.parametrize('mutation', ['missing', 'altered', 'duplicate', 'traversal'])
def test_candidate_archive_rejects_wrong_members_and_same_size_mutation(tmp_path, mutation):
    import hashlib
    import zipfile

    archive = tmp_path / 'dist.zip'
    with zipfile.ZipFile(archive, 'w') as out:
        if mutation != 'missing':
            out.writestr('candidate.whl', b'WHEEL' if mutation == 'altered' else b'wheel')
        if mutation == 'duplicate':
            with pytest.warns(UserWarning):
                out.writestr('candidate.whl', b'wheel')
        if mutation == 'traversal':
            out.writestr('../escape', b'x')
    expected = {'candidate.whl': {'size': 5, 'sha256': hashlib.sha256(b'wheel').hexdigest()}}
    with pytest.raises(ValueError):
        inputs.verify_candidate_archive(archive, expected)


def test_candidate_archive_rejects_declared_symlink(tmp_path):
    import hashlib
    import stat
    import zipfile

    archive = tmp_path / 'dist.zip'
    link = zipfile.ZipInfo('candidate.whl')
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(archive, 'w') as out:
        out.writestr(link, 'wheel')
    expected = {'candidate.whl': {'size': 5, 'sha256': hashlib.sha256(b'wheel').hexdigest()}}
    with pytest.raises(ValueError):
        inputs.verify_candidate_archive(archive, expected)


def test_select_run_artifact_rejects_old_attempt_and_ambiguous_names():
    identity = {'repository_id': 123, 'run_id': 456, 'attempt': 2,
                'candidate_sha': 'a' * 40, 'run_head_sha': 'b' * 40,
                'workflow_id': 789, 'producer_job': 'build'}
    attempt = {'id': 456, 'run_attempt': 2, 'head_sha': 'b' * 40,
               'workflow_id': 789, 'repository': {'id': 123},
               'run_started_at': '2026-10-28T00:00:00Z'}
    jobs = {'total_count': 1, 'jobs': [{'id': 17, 'run_id': 456, 'name': 'build',
                                       'head_sha': 'b' * 40, 'conclusion': 'success',
                                       'started_at': '2026-10-28T00:00:00Z',
                                       'completed_at': '2026-10-28T00:00:02Z'}]}
    artifact = {'id': 20, 'name': 'p11lab-framework-dist-' + 'a' * 40 + '-2',
                'expired': False, 'size_in_bytes': 5, 'created_at': '2026-10-28T00:00:01Z',
                'workflow_run': {'id': 456, 'repository_id': 123, 'head_sha': 'b' * 40}}
    listing = {'total_count': 1, 'artifacts': [artifact]}
    assert inputs.select_run_artifact(identity, attempt, jobs, listing)['id'] == 20
    with pytest.raises(ValueError):
        inputs.select_run_artifact(identity, {**attempt, 'run_attempt': 1}, jobs, listing)
    with pytest.raises(ValueError):
        inputs.select_run_artifact(identity, attempt, jobs, {'total_count': 2, 'artifacts': [artifact, artifact]})


def test_metadata_stability_requires_three_spaced_identical_reads():
    now = [0.0]
    reads = []
    values = iter([{'id': 1}, {'id': 2}, {'id': 2}, {'id': 2}])

    def fetch():
        reads.append(now[0])
        return next(values)

    def sleep(seconds):
        now[0] += seconds

    assert inputs.stable_metadata(fetch, clock=lambda: now[0], sleep=sleep) == {'id': 2}
    assert reads == [0, 2, 4, 6]


def test_metadata_stability_never_returns_after_deadline():
    now = [0.0]

    def fetch():
        now[0] += 30
        return {'id': 1}

    with pytest.raises(ValueError, match='60 seconds'):
        inputs.stable_metadata(fetch, clock=lambda: now[0], sleep=lambda n: now.__setitem__(0, now[0] + n))


def test_artifact_metadata_requires_exact_integer_identifiers():
    identity = {'repository_id': 1, 'run_id': 1, 'attempt': 1,
                'candidate_sha': 'a' * 40, 'run_head_sha': 'b' * 40,
                'workflow_id': 1, 'producer_job': 'build'}
    attempt = {'id': True, 'run_attempt': 1, 'head_sha': 'b' * 40,
               'workflow_id': 1, 'repository': {'id': 1},
               'run_started_at': '2026-10-28T00:00:00Z'}
    jobs = {'total_count': 1, 'jobs': [{'id': 1, 'run_id': 1, 'name': 'build',
            'head_sha': 'b' * 40, 'conclusion': 'success',
            'started_at': '2026-10-28T00:00:00Z', 'completed_at': '2026-10-28T00:00:02Z'}]}
    artifact = {'id': 1, 'name': 'p11lab-framework-dist-' + 'a' * 40 + '-1',
                'expired': False, 'size_in_bytes': 5, 'created_at': '2026-10-28T00:00:01Z',
                'workflow_run': {'id': 1, 'repository_id': 1, 'head_sha': 'b' * 40}}
    with pytest.raises(ValueError):
        inputs.select_run_artifact(identity, attempt, jobs, {'total_count': 1, 'artifacts': [artifact]})


def test_github_download_strips_token_and_rejects_unapproved_redirect(monkeypatch):
    from p11lab.round_core.artifacts import GitHubTransport

    calls = []
    def request(url, token, limit, deadline):
        calls.append((url, token))
        if len(calls) == 1:
            return 302, {'location': 'https://x.blob.core.windows.net/a?secret=x'}, b''
        return 200, {}, b'zip'
    client = GitHubTransport('owner/repo', 'secret-token')
    monkeypatch.setattr(client, '_request', request)
    assert client.download(3) == b'zip'
    assert calls[0][1] == 'secret-token'
    assert calls[1][1] is None
    calls.clear()
    def bad_request(url, token, limit, deadline):
        return 302, {'location': 'https://evil.example/a?secret=x'}, b''
    monkeypatch.setattr(client, '_request', bad_request)
    with pytest.raises(ValueError):
        client.download(3)


def test_candidate_manifest_binds_frozen_target_and_base():
    identity = {'repository_id': 123, 'run_id': 456, 'attempt': 2,
                'candidate_sha': 'a' * 40, 'target_sha': 'b' * 40,
                'merge_base_sha': 'c' * 40}
    roles = {role: {'path': role + ('.tar.gz' if role == 'sdist' else '.whl'),
                    'size': 5, 'sha256': 'd' * 64}
             for role in ('primary_wheel', 'sdist', 'sdist_probe_wheel', 'replay_base_wheel')}
    manifest = {'schema_version': 1, 'identity': identity, 'roles': roles,
                'dependency_lock_sha256': 'e' * 64, 'source_receipt_sha256': 'f' * 64,
                'build_receipt_sha256': '1' * 64}
    assert inputs.validate_candidate_manifest(manifest, identity) == manifest
    changed = dict(identity, target_sha='9' * 40)
    with pytest.raises(ValueError, match='identity'):
        inputs.validate_candidate_manifest(manifest, changed)


def test_artifact_retry_is_only_for_transient_errors(monkeypatch):
    from p11lab.round_core import artifacts
    client = artifacts.GitHubTransport('owner/repo', 'token')
    calls = []
    def resolve(identity):
        calls.append('resolve')
        if len(calls) == 1:
            raise artifacts.TransientTransportError('transient')
        return {'id': 3, 'digest': 'sha256:4a70fe9aa6436e02c2dea340fbd1e352e4ef2d8ce6ca52ad25d4b95471fc8bf2'}
    monkeypatch.setattr(client, 'resolve', resolve)
    monkeypatch.setattr(client, 'download', lambda artifact_id: b'zip')
    sleeps = []
    assert client.acquire({}, sleep=sleeps.append)[1] == b'zip'
    assert sleeps == [10]
    monkeypatch.setattr(client, 'resolve', lambda identity: (_ for _ in ()).throw(ValueError('HTTP 404')))
    sleeps.clear()
    with pytest.raises(ValueError, match='404'):
        client.acquire({}, sleep=sleeps.append)
    assert sleeps == []


def test_dist_verification_rejects_missing_dependency_and_changed_lock(tmp_path):
    import hashlib
    import io
    import tarfile
    import zipfile
    def h(raw):
        return hashlib.sha256(raw).hexdigest()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        z.writestr('wheel/data', b'payload')
    wheel = buf.getvalue()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w:gz') as tar:
        row = tarfile.TarInfo('source/data')
        row.size = 7
        tar.addfile(row, io.BytesIO(b'payload'))
    sdist = buf.getvalue()
    identity = {'repository_id': 123, 'run_id': 456, 'attempt': 2,
                'candidate_sha': 'a' * 40, 'target_sha': 'b' * 40, 'merge_base_sha': 'c' * 40}
    roles = {role: {'path': role + ('.tar.gz' if role == 'sdist' else '.whl'),
                    'size': len(sdist if role == 'sdist' else wheel),
                    'sha256': h(sdist if role == 'sdist' else wheel)}
             for role in ('primary_wheel', 'sdist', 'sdist_probe_wheel', 'replay_base_wheel')}
    dep = {'path': 'deps/tool.whl', 'size': len(wheel), 'sha256': h(wheel)}
    lock = inputs.canonical({'schema_version': 1, 'build_roots': ['tool==1'],
                             'runtime_extras': [], 'build_wheels': [dep], 'runtime_wheels': [dep]})
    source = inputs.canonical({'revision': identity['candidate_sha']})
    build = inputs.canonical({'identity': identity, 'roles_sha256': inputs.digest(roles)})
    manifest = {'schema_version': 1, 'identity': identity, 'roles': roles,
                'dependency_lock_sha256': h(lock), 'source_receipt_sha256': h(source),
                'build_receipt_sha256': h(build)}
    def archive(include_wheel=True):
        result = io.BytesIO()
        with zipfile.ZipFile(result, 'w') as out:
            out.writestr('candidate-manifest.json', inputs.canonical(manifest))
            out.writestr('dependency-lock.json', lock)
            out.writestr('source-receipt.json', source)
            out.writestr('build-receipt.json', build)
            for role, record in roles.items():
                out.writestr(record['path'], sdist if role == 'sdist' else wheel)
            if include_wheel:
                out.writestr('deps/tool.whl', wheel)
        return result.getvalue()
    result = inputs.verify_dist_bytes(archive(), identity, h(lock), tmp_path / 'good.zip')
    assert result['roles']['primary_wheel']['sha256'] == h(wheel)
    with pytest.raises(ValueError):
        inputs.verify_dist_bytes(archive(False), identity, h(lock), tmp_path / 'missing.zip')
    with pytest.raises(ValueError, match='lock'):
        inputs.verify_dist_bytes(archive(), identity, '0' * 64, tmp_path / 'changed.zip')


def test_prepare_refuses_fixture_transport_in_ci(tmp_path, monkeypatch):
    monkeypatch.setenv('CI', 'true')
    with pytest.raises(ValueError, match='fixture.*CI'):
        inputs.prepare({'transport': 'fixture'}, None, tmp_path / 'out')


def test_public_prepare_fixture_from_cli(tmp_path):
    import os
    import subprocess
    import sys
    env = dict(os.environ)
    env['PYTHONPATH'] = str(Path(__file__).parents[2] / 'src')
    env.pop('CI', None)
    env.pop('GITHUB_ACTIONS', None)
    fixtures = Path(__file__).parent / 'fixtures'
    result = subprocess.run([sys.executable, '-m', 'p11lab', 'round', 'prepare',
        '--context', str(fixtures / 'valid-context.json'), '--policy-root', str(fixtures / 'policy'),
        '--output-dir', str(tmp_path / 'output'), '--output-json', str(tmp_path / 'result.json')],
        text=True, capture_output=True, env=env)
    assert result.returncode == 0, result.stderr
    output = json.loads((tmp_path / 'result.json').read_text())
    assert output['authority'] == 'local-fixture-non-authoritative'
    assert output['round_positive'] is False
    assert output['identity']['candidate_sha'] == 'a' * 40
    import zipfile
    assert zipfile.is_zipfile(tmp_path / 'output/dist/primary_wheel/fixture_app-0.0.1-py3-none-any.whl')
    assert zipfile.is_zipfile(tmp_path / 'output/dist/deps/fixture_pkg-0.0.1-py3-none-any.whl')


def test_prepare_fixture_rejects_wrong_attempt_metadata(tmp_path, monkeypatch):
    monkeypatch.delenv('CI', raising=False)
    monkeypatch.delenv('GITHUB_ACTIONS', raising=False)
    fixtures = Path(__file__).parent / 'fixtures'
    context = json.loads((fixtures / 'valid-context.json').read_bytes())
    context['artifact_path'] = str(fixtures / context['artifact_path'])
    context['data_root'] = str(fixtures / context['data_root'])
    metadata = json.loads((fixtures / context['fixture_metadata_path']).read_bytes())
    metadata['attempt']['run_attempt'] = 1
    path = tmp_path / 'metadata.json'
    path.write_text(json.dumps(metadata))
    context['fixture_metadata_path'] = str(path)
    with pytest.raises(ValueError, match='run identity'):
        inputs.prepare(context, fixtures / 'policy', tmp_path / 'out')


@pytest.mark.parametrize('mutation', ['target', 'base', 'same-size-corpus', 'stale-cache'])
def test_fixture_prepare_rejects_changed_frozen_inputs(tmp_path, monkeypatch, mutation):
    import shutil
    monkeypatch.delenv('CI', raising=False)
    monkeypatch.delenv('GITHUB_ACTIONS', raising=False)
    fixtures = Path(__file__).parent / 'fixtures'
    context = json.loads((fixtures / 'valid-context.json').read_bytes())
    context['artifact_path'] = str(fixtures / context['artifact_path'])
    context['fixture_metadata_path'] = str(fixtures / context['fixture_metadata_path'])
    data = tmp_path / 'data'
    shutil.copytree(fixtures / 'input-data', data)
    context['data_root'] = str(data)
    if mutation in ('target', 'base'):
        context['identity']['target_sha' if mutation == 'target' else 'merge_base_sha'] = '9' * 40
    elif mutation == 'same-size-corpus':
        corpus = data / 'corpus.bin'
        corpus.write_bytes(b'X' * len(corpus.read_bytes()))
    else:
        (data / 'stale').write_bytes(b'old')
    with pytest.raises(ValueError):
        inputs.prepare(context, fixtures / 'policy', tmp_path / 'out')


def test_protected_profile_requires_bound_graph_bytes():
    from p11lab.round_core.artifacts import verify_profile_graph
    import hashlib
    graph = [{'path': '.github/workflows/build.yml', 'sha256': hashlib.sha256(b'protected').hexdigest()}]
    assert verify_profile_graph(graph, lambda path: b'protected') == graph
    with pytest.raises(ValueError, match='graph'):
        verify_profile_graph(graph, lambda path: b'attacker')


def test_producer_profile_requires_exact_protected_context_and_graph():
    import hashlib
    from p11lab.round_core.artifacts import verify_producer_profile
    graph = [{'path': '.github/workflows/build.yml', 'sha256': hashlib.sha256(b'protected').hexdigest()},
             {'path': 'boundary-proof.json', 'sha256': hashlib.sha256(b'protected').hexdigest()}]
    profile = {'repository': 'owner/repo', 'repository_id': 123, 'owner_id': 1794540, 'workflow_id': 789,
               'producer_job': 'build', 'control_sha': 'e' * 40, 'policy_sha256': '8' * 64,
               'workflow_path': '.github/workflows/build.yml', 'boundary_path': 'boundary-proof.json',
               'target_sha256': '1' * 64, 'data_sources_sha256': '2' * 64, 'data_sources': [], 'context_artifact_name': 'control-{run_id}-{attempt}', 'context_job': 'context', 'runtime': {'image': 'sha256:' + '3' * 64, 'layers': ['sha256:' + '4' * 64], 'config_sha256': '5' * 64, 'tool_identity_sha256': '6' * 64, 'python_version': '3.12.14', 'max_output_bytes': 16777216, 'source_date_epoch': 1}, 'graph': graph}
    context = dict(profile, run_head_sha='d' * 40)
    verify_producer_profile(profile, context, lambda path: b'protected')
    context['control_sha'] = 'f' * 40
    with pytest.raises(ValueError):
        verify_producer_profile(profile, context, lambda path: b'protected')


def test_prepare_rejects_malformed_context_before_creating_output(tmp_path, monkeypatch):
    monkeypatch.delenv('CI', raising=False)
    monkeypatch.delenv('GITHUB_ACTIONS', raising=False)
    with pytest.raises(ValueError, match='context'):
        inputs.prepare({'transport': 'fixture'}, None, tmp_path / 'out')
    assert not (tmp_path / 'out').exists()


def test_artifact_digest_binds_actual_downloaded_bytes():
    import hashlib
    from p11lab.round_core.artifacts import verify_artifact_digest
    digest = 'sha256:' + hashlib.sha256(b'good').hexdigest()
    verify_artifact_digest(b'good', {'digest': digest})
    with pytest.raises(ValueError, match='digest'):
        verify_artifact_digest(b'evil', {'digest': digest})


def test_artifact_cache_hit_rechecks_authenticated_digest(tmp_path, monkeypatch):
    import hashlib
    from p11lab.round_core.artifacts import GitHubTransport
    client = GitHubTransport('owner/repo', 'token')
    metadata = {'id': 4, 'digest': 'sha256:' + hashlib.sha256(b'good').hexdigest()}
    monkeypatch.setattr(client, 'resolve', lambda identity: metadata)
    monkeypatch.setattr(client, 'download', lambda artifact_id: pytest.fail('cache should be used'))
    cache = tmp_path / 'cache.zip'
    cache.write_bytes(b'good')
    assert client.acquire({}, cache_file=cache)[1] == b'good'
    cache.write_bytes(b'evil')
    with pytest.raises(ValueError, match='digest'):
        client.acquire({}, cache_file=cache)


def test_offline_closure_probe_rejects_missing_runtime_dependency(tmp_path):
    import os
    import subprocess
    import zipfile
    evaluator = os.environ.get('P11LAB_W01_OUTPUT')
    if not evaluator:
        pytest.skip('sealed W01 evaluator not selected')
    python = Path(evaluator) / 'evaluator-install/bin/python3'
    def wheel(path, name, requires=''):
        with zipfile.ZipFile(path, 'w') as z:
            z.writestr(name + '-1.0.dist-info/METADATA', 'Metadata-Version: 2.1\nName: ' + name + '\nVersion: 1.0\n' + requires)
    candidate = tmp_path / 'application-1.0-py3-none-any.whl'
    dependency = tmp_path / 'dependency-1.0-py3-none-any.whl'
    wheel(candidate, 'application', 'Requires-Dist: dependency>=1\n')
    wheel(dependency, 'dependency')
    request = {'candidate': str(candidate), 'dependencies': [str(dependency)],
               'target': {'python_version': '3.12', 'platforms': ['linux_x86_64'], 'abis': ['cp312'],
                          'marker_environment': {'implementation_name': 'cpython', 'implementation_version': '3.12.14',
                          'os_name': 'posix', 'platform_machine': 'x86_64', 'platform_release': '',
                          'platform_system': 'Linux', 'platform_version': '', 'python_full_version': '3.12.14',
                          'platform_python_implementation': 'CPython', 'python_version': '3.12', 'sys_platform': 'linux'}}}
    probe = Path(__file__).parents[2] / 'src/p11lab/round_core/closure_probe.py'
    def run():
        return subprocess.run([str(python), '-I', '-B', str(probe)], input=json.dumps(request),
                              text=True, capture_output=True)
    assert run().returncode == 0
    request['dependencies'] = []
    failed = run()
    assert failed.returncode != 0
    assert 'missing dependency' in failed.stderr


def test_offline_closure_probe_build_roots_and_extras(tmp_path):
    import os
    import subprocess
    import zipfile
    evaluator = os.environ.get('P11LAB_W01_OUTPUT')
    if not evaluator:
        pytest.skip('sealed W01 evaluator not selected')
    def wheel(name, metadata):
        path = tmp_path / (name + '-1.0-py3-none-any.whl')
        with zipfile.ZipFile(path, 'w') as z:
            z.writestr(name + '-1.0.dist-info/METADATA', 'Metadata-Version: 2.1\nName: ' + name + '\nVersion: 1.0\n' + metadata)
        return str(path)
    tool = wheel('tool', 'Provides-Extra: feature\nRequires-Dist: dependency>=1; extra == "feature"\n')
    dep = wheel('dependency', '')
    target = {'python_version': '3.12', 'platforms': ['linux_x86_64'], 'abis': ['cp312'],
              'marker_environment': {'implementation_name': 'cpython', 'implementation_version': '3.12.14',
              'os_name': 'posix', 'platform_machine': 'x86_64', 'platform_release': '', 'platform_system': 'Linux',
              'platform_version': '', 'python_full_version': '3.12.14', 'platform_python_implementation': 'CPython',
              'python_version': '3.12', 'sys_platform': 'linux'}}
    request = {'candidate': None, 'dependencies': [tool, dep], 'target': target,
               'roots': ['tool[feature]==1.0']}
    probe = Path(__file__).parents[2] / 'src/p11lab/round_core/closure_probe.py'
    result = subprocess.run([str(Path(evaluator) / 'evaluator-install/bin/python3'), '-I', '-B', str(probe)],
                            input=json.dumps(request), text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)['dependencies'] == ['dependency', 'tool']


def test_offline_probe_enforces_orphan_policy_across_sides(tmp_path):
    import os
    import subprocess
    import zipfile
    evaluator = os.environ.get('P11LAB_W01_OUTPUT')
    if not evaluator:
        pytest.skip('sealed W01 evaluator not selected')
    paths = []
    for name in ('application', 'unused'):
        path = tmp_path / (name + '-1.0-py3-none-any.whl')
        with zipfile.ZipFile(path, 'w') as z:
            z.writestr(name + '-1.0.dist-info/METADATA', 'Metadata-Version: 2.1\nName: ' + name + '\nVersion: 1.0\n')
        paths.append(str(path))
    request = json.loads((Path(__file__).parent / 'fixtures/valid-context.json').read_bytes())
    request = {'candidate': paths[0], 'dependencies': [paths[1]], 'target': request['target'], 'allow_orphans': True}
    probe = Path(__file__).parents[2] / 'src/p11lab/round_core/closure_probe.py'
    result = subprocess.run([str(Path(evaluator) / 'evaluator-install/bin/python3'), '-I', '-B', str(probe)],
                            input=json.dumps(request), text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)['dependencies'] == []


def test_static_closures_use_sealed_probe_and_require_complete_rosters(tmp_path):
    import os
    import zipfile
    evaluator = os.environ.get('P11LAB_W01_OUTPUT')
    if not evaluator:
        pytest.skip('sealed W01 evaluator not selected')
    def wheel(path, name, requires=''):
        path.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(path, 'w') as z:
            z.writestr(name + '-1.0.dist-info/METADATA', 'Metadata-Version: 2.1\nName: ' + name + '\nVersion: 1.0\n' + requires)
    candidate = 'candidate/application-1.0-py3-none-any.whl'
    dep = 'deps/dependency-1.0-py3-none-any.whl'
    wheel(tmp_path / candidate, 'application', 'Requires-Dist: dependency>=1\n')
    wheel(tmp_path / dep, 'dependency')
    lock = {'build_roots': ['dependency==1.0'], 'runtime_extras': [], 'build_wheels': [{'path': dep}], 'runtime_wheels': [{'path': dep}]}
    roles = {key: {'path': candidate} for key in ('primary_wheel', 'sdist_probe_wheel', 'replay_base_wheel')}
    target = json.loads((Path(__file__).parent / 'fixtures/valid-context.json').read_bytes())['target']
    result = inputs.validate_offline_closures(tmp_path, lock, roles, target,
                    Path(evaluator) / 'evaluator-install/bin/python3')
    assert result['status'] == 'static-closure-verified'
    lock['runtime_wheels'] = []
    with pytest.raises(ValueError, match='closure'):
        inputs.validate_offline_closures(tmp_path, lock, roles, target,
                    Path(evaluator) / 'evaluator-install/bin/python3')


def test_offline_probe_applies_selected_candidate_extras(tmp_path):
    import os
    import subprocess
    import zipfile
    evaluator = os.environ.get('P11LAB_W01_OUTPUT')
    if not evaluator:
        pytest.skip('sealed W01 evaluator not selected')
    for name, metadata in [('application', 'Provides-Extra: test\nRequires-Dist: dependency>=1; extra == "test"\n'), ('dependency', '')]:
        with zipfile.ZipFile(tmp_path / (name + '-1.0-py3-none-any.whl'), 'w') as z:
            z.writestr(name + '-1.0.dist-info/METADATA', 'Metadata-Version: 2.1\nName: ' + name + '\nVersion: 1.0\n' + metadata)
    target = json.loads((Path(__file__).parent / 'fixtures/valid-context.json').read_bytes())['target']
    request = {'candidate': str(tmp_path / 'application-1.0-py3-none-any.whl'),
               'dependencies': [str(tmp_path / 'dependency-1.0-py3-none-any.whl')],
               'target': target, 'candidate_extras': ['test']}
    probe = Path(__file__).parents[2] / 'src/p11lab/round_core/closure_probe.py'
    result = subprocess.run([str(Path(evaluator) / 'evaluator-install/bin/python3'), '-I', '-B', str(probe)],
                            input=json.dumps(request), text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)['dependencies'] == ['dependency']


def test_offline_probe_rejects_undeclared_extra(tmp_path):
    import os
    import subprocess
    import zipfile
    evaluator = os.environ.get('P11LAB_W01_OUTPUT')
    if not evaluator:
        pytest.skip('sealed W01 evaluator not selected')
    candidate = tmp_path / 'application-1.0-py3-none-any.whl'
    with zipfile.ZipFile(candidate, 'w') as z:
        z.writestr('application-1.0.dist-info/METADATA', 'Metadata-Version: 2.1\nName: application\nVersion: 1.0\n')
    target = json.loads((Path(__file__).parent / 'fixtures/valid-context.json').read_bytes())['target']
    request = {'candidate': str(candidate), 'dependencies': [], 'target': target, 'candidate_extras': ['unknown']}
    probe = Path(__file__).parents[2] / 'src/p11lab/round_core/closure_probe.py'
    result = subprocess.run([str(Path(evaluator) / 'evaluator-install/bin/python3'), '-I', '-B', str(probe)],
                            input=json.dumps(request), text=True, capture_output=True)
    assert result.returncode != 0


def test_offline_probe_rejects_ambiguous_metadata_identity(tmp_path):
    import os
    import subprocess
    import zipfile
    evaluator = os.environ.get('P11LAB_W01_OUTPUT')
    if not evaluator:
        pytest.skip('sealed W01 evaluator not selected')
    candidate = tmp_path / 'application-1.0-py3-none-any.whl'
    with zipfile.ZipFile(candidate, 'w') as z:
        z.writestr('application-1.0.dist-info/METADATA', 'Metadata-Version: 2.1\nName: application\nName: attacker\nVersion: 1.0\n')
    target = json.loads((Path(__file__).parent / 'fixtures/valid-context.json').read_bytes())['target']
    request = {'candidate': str(candidate), 'dependencies': [], 'target': target}
    probe = Path(__file__).parents[2] / 'src/p11lab/round_core/closure_probe.py'
    result = subprocess.run([str(Path(evaluator) / 'evaluator-install/bin/python3'), '-I', '-B', str(probe)],
                            input=json.dumps(request), text=True, capture_output=True)
    assert result.returncode != 0


@pytest.mark.parametrize('mutation', ['python', 'tag', 'direct-url', 'version', 'marker'])
def test_offline_probe_rejects_incompatible_or_unlocked_metadata(tmp_path, mutation):
    import os
    import subprocess
    import zipfile
    evaluator = os.environ.get('P11LAB_W01_OUTPUT')
    if not evaluator:
        pytest.skip('sealed W01 evaluator not selected')
    suffix = 'cp311-cp311-win_amd64' if mutation == 'tag' else 'py3-none-any'
    candidate = tmp_path / ('application-1.0-' + suffix + '.whl')
    dep = tmp_path / 'dependency-1.0-py3-none-any.whl'
    requirement = {'direct-url': 'dependency @ https://example.test/pkg.whl',
                   'version': 'dependency>=2',
                   'marker': 'dependency>=1; sys_platform == "win32"'}.get(mutation, 'dependency>=1')
    with zipfile.ZipFile(candidate, 'w') as z:
        extra = 'Requires-Python: >=3.13\n' if mutation == 'python' else ''
        z.writestr('application-1.0.dist-info/METADATA',
                   'Metadata-Version: 2.1\nName: application\nVersion: 1.0\n' + extra + 'Requires-Dist: ' + requirement + '\n')
    with zipfile.ZipFile(dep, 'w') as z:
        z.writestr('dependency-1.0.dist-info/METADATA', 'Metadata-Version: 2.1\nName: dependency\nVersion: 1.0\n')
    target = json.loads((Path(__file__).parent / 'fixtures/valid-context.json').read_bytes())['target']
    request = {'candidate': str(candidate), 'dependencies': [str(dep)], 'target': target}
    probe = Path(__file__).parents[2] / 'src/p11lab/round_core/closure_probe.py'
    result = subprocess.run([str(Path(evaluator) / 'evaluator-install/bin/python3'), '-I', '-B', str(probe)],
                            input=json.dumps(request), text=True, capture_output=True)
    assert result.returncode != 0


def test_public_data_download_is_anonymous_and_revision_pinned(monkeypatch):
    import hashlib
    import io
    from p11lab import tool_downloads
    calls = []
    class Response(io.BytesIO):
        headers = {'Content-Encoding': 'identity', 'Content-Length': '4'}
        def geturl(self):
            return 'https://raw.githubusercontent.com/owner/repo/' + 'a' * 40 + '/data/item'
    class Opener:
        def open(self, request, timeout):
            calls.append(request)
            return Response(b'data')
    monkeypatch.setattr(tool_downloads, 'build_opener', lambda *args: Opener())
    source = tool_downloads.RoundDataSource('https://raw.githubusercontent.com/owner/repo/' + 'a' * 40 + '/data/item', 4,
        hashlib.sha256(b'data').hexdigest())
    assert tool_downloads.download_round_data(source) == b'data'
    assert not calls[0].has_header('Authorization')
    bad = tool_downloads.RoundDataSource(source.url.replace('a' * 40, 'main'), 4, source.sha256)
    with pytest.raises(ValueError):
        tool_downloads.download_round_data(bad)


def test_wheel_archive_rejects_links_and_traversal():
    import io
    import stat
    import zipfile
    def archive(name, link=False):
        buf = io.BytesIO()
        entry = zipfile.ZipInfo(name)
        if link:
            entry.create_system = 3
            entry.external_attr = (stat.S_IFLNK | 0o777) << 16
        with zipfile.ZipFile(buf, 'w') as z:
            z.writestr(entry, b'x')
        return buf.getvalue()
    inputs.inspect_opaque_wheel(archive('safe/file'))
    with pytest.raises(ValueError):
        inputs.inspect_opaque_wheel(archive('../escape'))
    with pytest.raises(ValueError):
        inputs.inspect_opaque_wheel(archive('safe/link', link=True))


def test_prebuilt_install_rejects_untyped_context_before_output(tmp_path):
    from p11lab.round_core.prebuilt import install_prebuilt_candidate
    with pytest.raises(TypeError, match='typed'):
        install_prebuilt_candidate({}, tmp_path / 'output')
    assert not (tmp_path / 'output').exists()


def test_authenticated_profile_is_checked_before_artifact_download(monkeypatch):
    import hashlib
    from p11lab.round_core.artifacts import GitHubTransport
    client = GitHubTransport('owner/repo', 'token')
    metadata = {'id': 1, 'digest': 'sha256:' + hashlib.sha256(b'zip').hexdigest()}
    calls = []
    monkeypatch.setattr(client, 'resolve', lambda identity: metadata)
    monkeypatch.setattr(client, 'download', lambda artifact_id: calls.append('download') or b'zip')
    client.acquire({}, before_download=lambda value: calls.append('profile'))
    assert calls == ['profile', 'download']
    calls.clear()
    def reject(value):
        raise ValueError('untrusted producer')
    with pytest.raises(ValueError):
        client.acquire({}, before_download=reject)
    assert calls == []


def test_control_artifact_rejects_extra_members_and_duplicate_json():
    import io
    import zipfile
    from p11lab.round_core.artifacts import decode_control_artifact
    def archive(payload, extra=False):
        out = io.BytesIO()
        with zipfile.ZipFile(out, 'w') as z:
            z.writestr('context.json', payload)
            if extra:
                z.writestr('surprise', b'x')
        return out.getvalue()
    assert decode_control_artifact(archive(b'{"run_id":1}')) == {'run_id': 1}
    with pytest.raises(ValueError):
        decode_control_artifact(archive(b'{"run_id":1}', True))
    with pytest.raises(ValueError):
        decode_control_artifact(archive(b'{"run_id":1,"run_id":2}'))


@pytest.mark.parametrize('case', ['identity', 'policy', 'clean'])
def test_configured_live_path_binds_protected_context(tmp_path, monkeypatch, case):
    import hashlib
    import io
    import shutil
    import zipfile
    from p11lab.round_core import artifacts
    import importlib.resources
    fixtures = Path(__file__).parent / 'fixtures'
    for name in ('policy', 'profiles', 'ci'):
        shutil.copytree(fixtures / name, tmp_path / name)
    context = json.loads((fixtures / 'valid-context.json').read_bytes())
    context.pop('artifact_path')
    context.pop('fixture_metadata_path')
    context.update(transport='github', control_sha='e' * 40, data_root=str(fixtures / 'input-data'), owner_id=1794540)
    with zipfile.ZipFile(fixtures / 'fixture-dist.zip') as z:
        lock = json.loads(z.read('dependency-lock.json'))
    sources_path = tmp_path / 'policy/sources.json'
    sources = json.loads(sources_path.read_bytes())
    sources['pins']['corpus']['sha256'] = inputs.digest(context['data_files'])
    sources['pins']['checker-build-lock']['sha256'] = inputs.digest({'roots': lock['build_roots'], 'wheels': lock['build_wheels']})
    sources['pins']['checker-runtime-lock']['sha256'] = inputs.digest({'extras': lock['runtime_extras'], 'wheels': lock['runtime_wheels']})
    sources_path.write_text(json.dumps(sources))
    profile_path = tmp_path / 'profiles/round-pr-smoke-v1.json'
    tier_profile = json.loads(profile_path.read_bytes())
    tier_profile['disabled_inventory']['sha256'] = next(x['sha256'] for x in context['data_files'] if x['path'] == 'disabled.json')
    profile_path.write_text(json.dumps(tier_profile))
    from p11lab.round_core.policy import load_policy
    protected_policy_sha = load_policy(tmp_path / 'policy', 'pr-smoke').policy_digest
    source_bytes = b'protected-graph'
    graph = [{'path': '.github/workflows/build.yml', 'sha256': hashlib.sha256(source_bytes).hexdigest()},
             {'path': 'proof.json', 'sha256': hashlib.sha256(source_bytes).hexdigest()}]
    profile = {'repository': context['repository'], 'repository_id': context['identity']['repository_id'],
               'owner_id': context['owner_id'],
               'workflow_id': context['workflow_id'], 'producer_job': context['producer_job'], 'control_sha': context['control_sha'],
               'policy_sha256': protected_policy_sha,
               'target_sha256': inputs.digest(context['target']), 'data_sources_sha256': inputs.digest([]),
               'data_sources': [], 'context_artifact_name': 'control-{run_id}-{attempt}', 'context_job': 'context',
               'runtime': {'image': 'sha256:' + '3' * 64, 'layers': ['sha256:' + '4' * 64], 'config_sha256': '5' * 64,
                           'tool_identity_sha256': inputs.digest({'fixture': True}), 'python_version': '3.12.14', 'max_output_bytes': 16777216, 'source_date_epoch': 1},
               'workflow_path': graph[0]['path'], 'boundary_path': graph[1]['path'], 'graph': graph}
    if case == 'policy':
        changed_data = tmp_path / 'changed-data'
        shutil.copytree(fixtures / 'input-data', changed_data)
        (changed_data / 'corpus.bin').write_bytes(b'Z' * (changed_data / 'corpus.bin').stat().st_size)
        (changed_data / 'disabled.json').write_bytes(b'[ ]')
        context['data_root'] = str(changed_data)
        for row in context['data_files']:
            data = (changed_data / row['path']).read_bytes()
            row['size'] = len(data)
            row['sha256'] = hashlib.sha256(data).hexdigest()
        changed = json.loads(sources_path.read_bytes())
        changed['pins']['corpus']['sha256'] = inputs.digest(context['data_files'])
        changed['pins']['checker-build-lock']['sha256'] = '8' * 64
        changed['pins']['checker-runtime-lock']['sha256'] = '9' * 64
        sources_path.write_text(json.dumps(changed))
        changed_profile = json.loads(profile_path.read_bytes())
        changed_profile['disabled_inventory']['sha256'] = next(row['sha256'] for row in context['data_files'] if row['path'] == 'disabled.json')
        profile_path.write_text(json.dumps(changed_profile))
    class Resource:
        def joinpath(self, path): return self
        def read_bytes(self): return inputs.canonical({'schema_version': 1, 'profiles': [profile]})
    monkeypatch.setattr(importlib.resources, 'files', lambda name: Resource())
    calls = []
    class FixtureGitHub:
        def __init__(self, repository, token): pass
        def source_file(self, revision, path): return source_bytes
        def acquire(self, identity, **kwargs):
            calls.append(kwargs.get('artifact_name'))
            if kwargs.get('before_download'):
                kwargs['before_download']({'id': 1})
            changed = {key: context[key] for key in ('identity', 'repository', 'run_head_sha', 'workflow_id', 'producer_job',
                       'control_sha', 'target', 'dependency_lock_sha256', 'data_files', 'disabled_path')}
            changed['policy_sha256'] = protected_policy_sha
            if case == 'identity':
                changed = dict(changed, identity=dict(changed['identity'], target_sha='9' * 40))
            if kwargs.get('artifact_name') is None:
                metadata = json.loads((fixtures / 'fixture-metadata.json').read_bytes())['listing']['artifacts'][0]
                return metadata, (fixtures / 'fixture-dist.zip').read_bytes()
            out = io.BytesIO()
            with zipfile.ZipFile(out, 'w') as z:
                z.writestr('context.json', inputs.canonical(changed))
            metadata = json.loads((fixtures / 'fixture-metadata.json').read_bytes())['listing']['artifacts'][0]
            return metadata, out.getvalue()
    monkeypatch.setattr(artifacts, 'GitHubTransport', FixtureGitHub)
    monkeypatch.setenv('GITHUB_TOKEN', 'test-token')
    if case == 'policy':
        with pytest.raises(ValueError, match='policy.*profile'):
            inputs.prepare(context, tmp_path / 'policy', tmp_path / 'output')
        assert calls == []
        assert not (tmp_path / 'output').exists()
        return
    if case == 'identity':
        with pytest.raises(ValueError, match='protected caller context mismatch'):
            inputs.prepare(context, tmp_path / 'policy', tmp_path / 'output')
        assert calls == ['control-456-2']
        assert not (tmp_path / 'output').exists()
        return
    from p11lab.round_core import bootstrap, prebuilt
    def acquire(source_pin, lock_root, output):
        output.mkdir()
        (output / 'evaluator-build-receipt.json').write_bytes(b'receipt')
        return {'python': {'platform': 'fixture', 'libc': ['fixture', '1']}, 'native_dependencies': []}
    monkeypatch.setattr(bootstrap, 'acquire_evaluator', acquire)
    monkeypatch.setattr(inputs, 'verify_dependency_origins', lambda root, lock, output: {'status': 'mock-origin'})
    monkeypatch.setattr(inputs, 'validate_offline_closures', lambda *args: {'status': 'mock-closure'})
    fake_tools = inputs.SealedToolInputs(tmp_path, '6' * 64, (), (), b'', ())
    monkeypatch.setattr(inputs.SealedToolInputs, 'from_evaluator', lambda root: fake_tools)
    monkeypatch.setattr(inputs, 'verified_evaluator_identity', lambda root: {'identity_sha256': inputs.digest({'fixture': True}),
                        'receipt_sha256': '6' * 64, 'identity': {'fixture': True}})
    monkeypatch.setattr(prebuilt, 'install_prebuilt_candidate', lambda selection, output: {
        'status': 'installed', 'installed_manifest_sha256': '7' * 64})
    result = inputs.prepare(context, tmp_path / 'policy', tmp_path / 'output')
    assert calls == ['control-456-2', None]
    assert result['authority'] == 'protected-profile-source-verified'
    assert set(result['candidate_install']['roles']) == {'primary_wheel', 'sdist_probe_wheel', 'replay_base_wheel'}
    assert result['round_positive'] is False


def test_round_data_transport_classifies_404_as_fatal_and_503_as_transient(monkeypatch):
    import hashlib
    from urllib.error import HTTPError
    from p11lab import tool_downloads
    source = tool_downloads.RoundDataSource('https://raw.githubusercontent.com/owner/repo/' + 'a' * 40 + '/data/item',
                                           4, hashlib.sha256(b'data').hexdigest())
    class Opener:
        status = 404
        def open(self, request, timeout):
            raise HTTPError(request.full_url, self.status, 'failure', {}, None)
    opener = Opener()
    monkeypatch.setattr(tool_downloads, 'build_opener', lambda *args: opener)
    with pytest.raises(ValueError) as missing:
        tool_downloads.download_round_data(source)
    assert not isinstance(missing.value, tool_downloads.TransientRoundDataError)
    opener.status = 503
    with pytest.raises(tool_downloads.TransientRoundDataError):
        tool_downloads.download_round_data(source)


def test_prebuilt_install_rejects_changed_wheel_before_output(tmp_path):
    from p11lab.round_core.prebuilt import ProtectedRuntimeSelection, WheelSnapshot, install_prebuilt_candidate
    wheel = tmp_path / 'candidate-1.0-py3-none-any.whl'
    wheel.write_bytes(b'changed')
    selection = ProtectedRuntimeSelection(image='sha256:' + 'a' * 64, layers=('sha256:' + 'b' * 64,),
        config_sha256='c' * 64, control_revision='d' * 40, python_version='3.12.14',
        tools=inputs.SealedToolInputs(tmp_path, 'e' * 64, (), (), b'', ()),
        candidate=WheelSnapshot(wheel, 'f' * 64), dependencies=())
    with pytest.raises(ValueError, match='wheel snapshot mismatch'):
        install_prebuilt_candidate(selection, tmp_path / 'output')
    assert not (tmp_path / 'output').exists()


def test_offline_probe_rejects_inconsistent_target_abi(tmp_path):
    import os
    import subprocess
    import zipfile
    evaluator = os.environ.get('P11LAB_W01_OUTPUT')
    if not evaluator:
        pytest.skip('sealed W01 evaluator not selected')
    wheel = tmp_path / 'application-1.0-py3-none-any.whl'
    with zipfile.ZipFile(wheel, 'w') as z:
        z.writestr('application-1.0.dist-info/METADATA', 'Metadata-Version: 2.1\nName: application\nVersion: 1.0\n')
    target = json.loads((Path(__file__).parent / 'fixtures/valid-context.json').read_bytes())['target']
    target['abis'] = ['cp311']
    request = {'candidate': str(wheel), 'dependencies': [], 'target': target}
    probe = Path(__file__).parents[2] / 'src/p11lab/round_core/closure_probe.py'
    result = subprocess.run([str(Path(evaluator) / 'evaluator-install/bin/python3'), '-I', '-B', str(probe)],
                            input=json.dumps(request), text=True, capture_output=True)
    assert result.returncode != 0


def test_public_data_download_supports_empty_pinned_file(monkeypatch):
    import hashlib
    import io
    from p11lab import tool_downloads
    class Response(io.BytesIO):
        headers = {'Content-Length': '0'}
        def geturl(self):
            return 'https://raw.githubusercontent.com/owner/repo/' + 'a' * 40 + '/empty'
    class Opener:
        def open(self, request, timeout):
            return Response(b'')
    monkeypatch.setattr(tool_downloads, 'build_opener', lambda *args: Opener())
    source = tool_downloads.RoundDataSource('https://raw.githubusercontent.com/owner/repo/' + 'a' * 40 + '/empty',
                                           0, hashlib.sha256(b'').hexdigest())
    assert tool_downloads.download_round_data(source) == b''


def test_fixture_context_cannot_inject_live_data_sources(tmp_path, monkeypatch):
    monkeypatch.delenv('CI', raising=False)
    monkeypatch.delenv('GITHUB_ACTIONS', raising=False)
    context = json.loads((Path(__file__).parent / 'fixtures/valid-context.json').read_bytes())
    context['data_sources'] = [{'url': 'https://example.test/data'}]
    with pytest.raises(ValueError, match='context'):
        inputs.prepare(context, None, tmp_path / 'output')
    assert not (tmp_path / 'output').exists()


def test_dependency_origin_readback_rejects_altered_download(tmp_path, monkeypatch):
    import hashlib
    from p11lab import tool_downloads
    root = tmp_path / 'dist'
    (root / 'deps').mkdir(parents=True)
    (root / 'deps/tool.whl').write_bytes(b'good')
    entry = {'path': 'deps/tool.whl', 'size': 4, 'sha256': hashlib.sha256(b'good').hexdigest(),
             'url': 'https://files.pythonhosted.org/packages/' + 'a' * 2 + '/' + 'b' * 2 + '/' + 'c' * 60 + '/tool.whl'}
    lock = {'build_wheels': [entry], 'runtime_wheels': [entry]}
    def download(record, path, *, deadline):
        path.write_bytes(b'evil')
        return {'size': 4, 'sha256': entry['sha256'], 'final_url': record['url']}
    monkeypatch.setattr(tool_downloads, 'download_locked_file', download)
    with pytest.raises(ValueError, match='dependency.*origin'):
        inputs.verify_dependency_origins(root, lock, tmp_path / 'readback')


def test_verified_evaluator_identity_is_stable_across_real_output_directories():
    import os
    first = os.environ.get('P11LAB_W01_OUTPUT')
    second = os.environ.get('P11LAB_W03_SECOND_EVALUATOR')
    if not first or not second:
        pytest.skip('two real W01 receipts not selected')
    first_tools = inputs.SealedToolInputs.from_evaluator(Path(first))
    second_tools = inputs.SealedToolInputs.from_evaluator(Path(second))
    a = inputs.verified_evaluator_identity(Path(first))
    b = inputs.verified_evaluator_identity(Path(second))
    assert first_tools.receipt_sha256 == a['receipt_sha256']
    assert second_tools.receipt_sha256 == b['receipt_sha256']
    assert a['identity_sha256'] == b['identity_sha256']
    assert a['receipt_sha256'] != b['receipt_sha256']


def test_tool_identity_rejects_literal_normalization_marker(tmp_path):
    import hashlib
    from p11lab.round_core.tool_identity import _inventory
    path = tmp_path / 'build-env/bin/activate'
    path.parent.mkdir(parents=True)
    path.write_bytes(b'unsafe literal <W01_OUTPUT>')
    row = {'path': 'build-env/bin/activate', 'size': path.stat().st_size,
           'mode': 0o644, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
    with pytest.raises(ValueError, match='normalization marker'):
        _inventory(tmp_path, [row], 'build-env')


def test_tool_identity_normalizes_only_verified_launcher_location(tmp_path):
    import hashlib
    from p11lab.round_core.tool_identity import _inventory
    def row(root, shell, body):
        path = root / 'build-env/bin/tool'
        path.parent.mkdir(parents=True, exist_ok=True)
        executable = str(root / 'build-env/bin/python3').encode()
        prefix = (b'#!/bin/sh\n\'\'\'exec\' ' + executable + b' "$0" "$@"\n\' \'\'\'\n'
                  if shell else b'#!' + executable + b'\n')
        raw = prefix + body
        path.write_bytes(raw)
        return {'path': 'build-env/bin/tool', 'size': len(raw), 'mode': 0o644,
                'sha256': hashlib.sha256(raw).hexdigest()}
    first = tmp_path / 'one'
    second = tmp_path / 'two'
    a = _inventory(first, [row(first, False, b'print(1)\n')], 'build-env')
    b = _inventory(second, [row(second, True, b'print(1)\n')], 'build-env')
    assert a == b
    c = _inventory(second, [row(second, True, b'print(2)\n')], 'build-env')
    assert a != c


def test_verified_tool_identity_binds_full_code_and_inventories():
    import hashlib
    import os
    root = os.environ.get('P11LAB_W01_OUTPUT')
    if not root:
        pytest.skip('sealed W01 evaluator not selected')
    result = inputs.verified_evaluator_identity(Path(root))
    receipt = inputs.load_json((Path(root) / 'evaluator-build-receipt.json').read_bytes(), max_bytes=16 * 1024 * 1024)
    identity = result['identity']
    for name in ('source', 'wheel', 'locks', 'tooling_sha256', 'bootstrap_driver_sha256',
                 'contract_sha256', 'runtime_distributions', 'source_companion'):
        assert identity[name] == receipt[name]
    assert set(identity['inventories']) == {'build_files', 'installed_files', 'tool_files', 'source_files',
                                             'python_files', 'companion_files', 'download_files', 'dist_files'}
    assert len(identity['commands']) == len(receipt['commands'])
    assert result['receipt_sha256'] == hashlib.sha256((Path(root) / 'evaluator-build-receipt.json').read_bytes()).hexdigest()


def test_tool_identity_rejects_forged_launcher_record(tmp_path):
    import hashlib
    from p11lab.round_core.tool_identity import _inventory
    binary = tmp_path / 'build-env/bin/tool'
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b'#!' + str(tmp_path / 'build-env/bin/python3').encode() + b'\nprint(1)\n')
    record = tmp_path / 'build-env/lib/python3.12/site-packages/tool-1.0.dist-info/RECORD'
    record.parent.mkdir(parents=True)
    record.write_text('../../../bin/tool,sha256=forged,1\n')
    rows = [{'path': str(p.relative_to(tmp_path)), 'size': p.stat().st_size, 'mode': 0o644,
             'sha256': hashlib.sha256(p.read_bytes()).hexdigest()} for p in (binary, record)]
    with pytest.raises(ValueError, match='RECORD mismatch'):
        _inventory(tmp_path, rows, 'build-env')


def test_tool_identity_preserves_nonlauncher_record_bytes(tmp_path):
    import hashlib
    from p11lab.round_core.tool_identity import _inventory
    def inspect(root, raw):
        path = root / 'build-env/lib/python3.12/site-packages/tool-1.0.dist-info/RECORD'
        path.parent.mkdir(parents=True)
        path.write_bytes(raw)
        row = {'path': str(path.relative_to(root)), 'size': len(raw), 'mode': 0o644,
               'sha256': hashlib.sha256(raw).hexdigest()}
        return _inventory(root, [row], 'build-env')
    assert inspect(tmp_path / 'a', b'file,sha256=abc,3\r\n') != inspect(tmp_path / 'b', b'"file",sha256=abc,3\r\n')


def test_tool_identity_never_projects_unverified_receipt(monkeypatch):
    import os
    from p11lab.round_core import bootstrap, tool_identity
    root = os.environ.get('P11LAB_W01_OUTPUT')
    if not root:
        pytest.skip('sealed W01 evaluator not selected')
    def reject(*args):
        raise ValueError('receipt validation failed')
    monkeypatch.setattr(bootstrap, 'verify_receipt', reject)
    monkeypatch.setattr(tool_identity, '_inventory', lambda *args: pytest.fail('projection ran before receipt validation'))
    with pytest.raises(ValueError, match='receipt validation failed'):
        inputs.verified_evaluator_identity(Path(root))


def test_tool_identity_rejects_receipt_replacement_during_validation(tmp_path, monkeypatch):
    from p11lab.round_core import bootstrap, tool_identity
    receipt = tmp_path / 'evaluator-build-receipt.json'
    receipt.write_text('{"version":1}')
    def replace(*args):
        receipt.write_text('{"version":2}')
    monkeypatch.setattr(bootstrap, 'verify_receipt', replace)
    monkeypatch.setattr(tool_identity, '_inventory', lambda *args: pytest.fail('used stale receipt'))
    with pytest.raises(ValueError, match='receipt changed'):
        inputs.verified_evaluator_identity(tmp_path)


def test_sealed_tools_reject_receipt_replacement_during_validation(tmp_path, monkeypatch):
    from p11lab.round_core import bootstrap
    path = tmp_path / 'evaluator-build-receipt.json'
    path.write_text(json.dumps({'source': {'build_wheels': [{'name': 'pip', 'version': '1'}]}, 'python_files': [1]}))
    def replace(*args):
        path.write_text('{"different":true}')
    monkeypatch.setattr(bootstrap, 'verify_receipt', replace)
    with pytest.raises(ValueError, match='receipt changed'):
        inputs.SealedToolInputs.from_evaluator(tmp_path)
