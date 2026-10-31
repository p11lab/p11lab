"""Policy admission controls; no provider, checker or network execution."""
import importlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

DATA = Path(__file__).resolve().parents[2] / 'src/p11lab/data'


def loader():
    # A missing implementation is reported as a behavior failure in the first RED.
    try:
        return importlib.import_module('p11lab.round_core.policy').load_policy
    except ModuleNotFoundError:
        pytest.fail('the public protected policy loader is absent')


@pytest.fixture
def root(tmp_path):
    for directory in ('rounds', 'profiles', 'ci'):
        shutil.copytree(DATA / directory, tmp_path / directory)
    return tmp_path / 'rounds'


def edit(root, relative, change):
    path = root / relative
    value = json.loads(path.read_text())
    change(value)
    path.write_text(json.dumps(value))


@pytest.mark.parametrize(('tier', 'expected', 'attempts'), [
    ('pr-smoke', ('softhsm2',), 1),
    ('nightly', ('softhsm2', 'kryoptic', 'nss'), 1),
    ('release', ('softhsm2', 'kryoptic', 'nss', 'tpm2', 'opencryptoki'), 2),
])
def test_frozen_active_roster_and_diagnostic_limits(tier, expected, attempts):
    policy = loader()(DATA / 'rounds', tier)
    result = policy.to_record()
    assert tuple(lane['id'] for lane in result['active_lanes']) == expected
    assert result['outer_attempts'] == attempts
    assert result['activation_state'] == 'diagnostic'
    assert result['round_positive'] is False
    assert result['quorum'] == {'min_repeats': attempts, 'required_fraction': 1.0, 'require_unanimous': True}
    assert result['scope']['visibility'] == 'baseline-candidate-catalog-union'
    assert result['scope']['enforcement'] == 'frozen-tier-selection'
    assert result['gates']
    assert all(lane['reason'] for lane in result['inactive_lanes'])
    assert all(lane['platform'] == 'linux/amd64' for lane in result['active_lanes'])
    assert len(result['policy_digest']) == 64
    assert len(result['roster_digest']) == 64
    if tier == 'release':
        assert any('EVID-STREAM-1' in gate for gate in result['gates'])
        assert any('E5' in gate for gate in result['gates'])
        assert result['active_lanes'][-1]['transport'] == 'pkcs11-proxy-ng'


def test_policy_is_immutable_and_bound_to_all_profile_bytes(root):
    policy = loader()(root, 'nightly')
    with pytest.raises(TypeError):
        policy.active_lanes[0]['id'] = 'other'
    with pytest.raises((AttributeError, TypeError)):
        policy.policy_digest = 'other'
    path = root / '../profiles/round-windows-v1.json'
    path.write_text(path.read_text() + '\n')
    assert loader()(root, 'nightly').policy_digest != policy.policy_digest


@pytest.mark.parametrize('tier', ['PR', '', 'linux', 'pr-smok', 'all'])
def test_unknown_tier_never_defaults(tier):
    with pytest.raises(ValueError, match='tier'):
        loader()(DATA / 'rounds', tier)


@pytest.mark.parametrize('field', ['os', 'image', 'selector', 'timeout', 'baseline', 'receipts', 'p11lab_ref'])
def test_caller_override_fields_are_rejected(root, field):
    edit(root, 'policy.json', lambda value: value.update({field: 'caller'}))
    with pytest.raises(ValueError, match='fields'):
        loader()(root, 'pr-smoke')


@pytest.mark.parametrize('activation', ['qualified', 'required'])
def test_json_cannot_authorize_promotion(root, activation):
    edit(root, 'policy.json', lambda value: value.update(activation_state=activation))
    with pytest.raises(ValueError, match='activation.*unverified'):
        loader()(root, 'pr-smoke')


@pytest.mark.parametrize('mutation', [
    lambda p: p['tiers']['nightly'].update(mandatory_lanes=[]),
    lambda p: p['tiers']['nightly'].update(mandatory_lanes=['softhsm2', 'softhsm2', 'nss']),
    lambda p: p['tiers']['nightly'].update(mandatory_lanes=['softhsm2', 'nss']),
    lambda p: p['tiers']['pr-smoke'].update(mandatory_lanes=['softhsm2', 'kryoptic']),
    lambda p: p['lanes'][0].update(transport='tcp'),
    lambda p: p['lanes'][0].update(emulated=True),
    lambda p: p['lanes'][0].update(runner='ubuntu-latest'),
    lambda p: p['lanes'][0].update(platform='linux/arm64'),
    lambda p: p['lanes'][0].pop('channel'),
    lambda p: p['lanes'][0].update(id='other'),
    lambda p: p['lanes'].append(p['lanes'][0]),
    lambda p: p['tiers']['release'].update(outer_attempts=1),
    lambda p: p['tiers']['nightly'].update(outer_attempts=True),
    lambda p: p['tiers']['nightly'].update(profile='round-pr-smoke-v1'),
])
def test_lane_identity_membership_and_scheduling_are_protected(root, mutation):
    edit(root, 'policy.json', mutation)
    with pytest.raises(ValueError):
        loader()(root, 'nightly')


@pytest.mark.parametrize('mutation', [
    lambda s: s.update(evaluator_revision='main'),
    lambda s: s.update(evaluator_contract_sha256='0' * 63),
    lambda s: s['pins'].pop('softhsm2-runtime'),
    lambda s: s['pins']['softhsm2-runtime'].update(sha256='sha256:abc'),
    lambda s: s['pins']['softhsm2-runtime'].update(sha256='', reason=''),
    lambda s: s['pins']['softhsm2-runtime'].update(reason=''),
    lambda s: s['pins']['softhsm2-runtime'].update(verified=True),
    lambda s: s['baseline'].update(index='../baselines/evil.json'),
])
def test_sources_reject_malformed_or_missing_identity(root, mutation):
    edit(root, 'sources.json', mutation)
    with pytest.raises(ValueError):
        loader()(root, 'pr-smoke')


@pytest.mark.parametrize(('profile', 'mutation'), [
    ('round-pr-smoke-v1', lambda p: p['nodes'].pop()),
    ('round-pr-smoke-v1', lambda p: p['nodes'].append(p['nodes'][0])),
    ('round-pr-smoke-v1', lambda p: p['nodes'].__setitem__(0, 'test_other.py::test_other')),
    ('round-pr-smoke-v1', lambda p: p.update(source_revision='a' * 40)),
    ('round-linux-v1', lambda p: p.update(marker_expression='not security')),
    ('round-linux-v1', lambda p: p.update(destructive=True)),
    ('round-windows-v1', lambda p: p.update(key_injection=True)),
    ('round-macos-full-v1', lambda p: p.update(marker_expression='not slow')),
    ('round-linux-v1', lambda p: p['disabled_inventory'].update(reason='')),
    ('round-linux-v1', lambda p: p['disabled_inventory'].update(sha256='broken')),
])
def test_profile_shrinking_or_ambiguous_disabled_lists_fail(root, profile, mutation):
    edit(root, f'../profiles/{profile}.json', mutation)
    with pytest.raises(ValueError):
        loader()(root, 'nightly')


def test_duplicate_json_and_missing_files_fail_closed(root):
    path = root / 'policy.json'
    path.write_text('{"schema_version":1,"schema_version":1}')
    with pytest.raises(ValueError, match='duplicate'):
        loader()(root, 'pr-smoke')
    path.unlink()
    with pytest.raises((ValueError, OSError)):
        loader()(root, 'pr-smoke')


def test_public_cli_writes_diagnostic_and_rejects_extra_options(tmp_path):
    output = tmp_path / 'proof.json'
    command = [sys.executable, '-m', 'p11lab', 'round', 'validate-policy',
               '--policy-root', str(DATA / 'rounds'), '--tier', 'pr-smoke', '--output-json', str(output)]
    env = dict(os.environ, PYTHONPATH=str(DATA.parents[1]))
    completed = subprocess.run(command, capture_output=True, text=True, env=env)
    assert completed.returncode == 0, completed.stderr
    assert json.loads(output.read_text())['round_positive'] is False
    for extra in (['--os', 'ubuntu-latest'], ['--selector', 'one'], ['--tier', 'unknown']):
        rejected = subprocess.run(command + extra, capture_output=True, text=True, env=env)
        assert rejected.returncode == 2


def test_referenced_image_catalog_contract_cannot_drift(root):
    # Discovery data are not eligibility evidence, but the policy still binds their bytes.
    path = root.parent / 'ci/images.json'
    path.parent.mkdir(exist_ok=True)
    path.write_bytes((DATA / 'ci/images.json').read_bytes() + b'\n')
    with pytest.raises(ValueError, match='image.*bytes'):
        loader()(root, 'pr-smoke')


def test_resolved_syntax_never_becomes_qualification(root):
    def resolve(sources):
        for pin in sources['pins'].values():
            pin.update(sha256='a' * 64, reason='Claimed identity; authenticity unverified.')
        sources['baseline']['epoch'] = 'claimed-epoch'
    edit(root, 'sources.json', resolve)
    edit(root, '../profiles/round-pr-smoke-v1.json', lambda p: p['disabled_inventory'].update(sha256='b' * 64))
    diagnostic = loader()(root, 'pr-smoke').to_record()
    assert diagnostic['round_positive'] is False
    assert any('qualifying receipts' in gate for gate in diagnostic['gates'])
    edit(root, 'policy.json', lambda p: p.update(activation_state='qualified'))
    with pytest.raises(ValueError, match='activation.*unverified'):
        loader()(root, 'pr-smoke')


def test_untrusted_receipt_claims_are_not_accepted(root):
    edit(root, 'policy.json', lambda p: p['qualification'].update(authenticated_receipts=[{
        'reviewer': 'claimed-owner', 'runs': ['1', '2', '3'], 'verified': True}]))
    with pytest.raises(ValueError, match='qualification'):
        loader()(root, 'pr-smoke')


@pytest.mark.parametrize('toolset', ['checker', 'oracle'])
def test_round_dispatch_preserves_reviewed_tool_selectors(toolset, monkeypatch, tmp_path, capsys):
    from p11lab.cli import main
    from p11lab import tool_inputs
    monkeypatch.setattr(tool_inputs, 'resolve_tool_inputs',
        lambda selected, **kwargs: {'selected': selected, 'target': kwargs['target']})
    assert main(['tools', 'resolve', toolset, '--target', 'debian13-amd64',
                 '--output-dir', str(tmp_path)]) == 0
    assert json.loads(capsys.readouterr().out) == {'selected': toolset, 'target': 'debian13-amd64'}


@pytest.mark.parametrize('substitution', ['paired', 'bytes-only', 'declaration-only'])
def test_evaluator_revision_cannot_accompany_substituted_contract(root, substitution):
    import hashlib
    substituted = b'{}\n'
    if substitution != 'declaration-only':
        (root / 'contract.json').write_bytes(substituted)
    if substitution != 'bytes-only':
        edit(root, 'sources.json', lambda s: s.update(
            evaluator_contract_sha256=hashlib.sha256(substituted).hexdigest()))
    with pytest.raises(ValueError, match='evaluator contract'):
        loader()(root, 'pr-smoke')


@pytest.mark.parametrize(('tier', 'providers', 'proxy'), [
    ('pr-smoke', ('softhsm2',), False),
    ('nightly', ('softhsm2', 'kryoptic', 'nss'), False),
    ('release', ('softhsm2', 'kryoptic', 'nss', 'tpm2', 'opencryptoki'), True),
])
@pytest.mark.parametrize('claimed', [False, True])
def test_every_selected_source_pin_retains_its_own_verification_gate(root, tier, providers, proxy, claimed):
    if claimed:
        edit(root, 'sources.json', lambda s: [pin.update(sha256='a' * 64) for pin in s['pins'].values()])
    result = loader()(root, tier).to_record()
    expected = {'checker-build-lock', 'checker-runtime-lock', 'corpus',
                'runner-image', 'runner-resources', 'baseline-index'}
    expected.update(f'{provider}-{kind}' for provider in providers
                    for kind in ('runtime', 'handoff', 'provider-source', 'recipe'))
    if proxy:
        expected.update(('proxy-client', 'proxy-daemon'))
    prefix = 'Unverified digest' if claimed else 'Unresolved digest'
    for name in expected:
        assert any(gate.startswith(f'{prefix}: {name}:') for gate in result['gates']), name
    if not proxy:
        assert not any(gate.startswith(f'{prefix}: proxy-client:') for gate in result['gates'])
    assert result['round_positive'] is False


@pytest.mark.parametrize(('tier', 'profile'), [
    ('pr-smoke', 'round-pr-smoke-v1'), ('nightly', 'round-linux-v1'), ('release', 'round-linux-v1'),
])
@pytest.mark.parametrize('claimed', [False, True])
def test_selected_disabled_inventory_has_named_missing_or_unverified_gate(root, tier, profile, claimed):
    if claimed:
        edit(root, f'../profiles/{profile}.json', lambda p: p['disabled_inventory'].update(sha256='b' * 64))
    gates = loader()(root, tier).to_record()['gates']
    prefix = 'Unverified disabled inventory' if claimed else 'Unresolved disabled inventory'
    assert any(gate.startswith(f'{prefix}: {profile}:') for gate in gates)


@pytest.mark.parametrize('claimed', [False, True])
def test_baseline_epoch_claim_does_not_hide_its_verification_gate(root, claimed):
    if claimed:
        edit(root, 'sources.json', lambda s: s['baseline'].update(epoch='claimed-epoch'))
    prefix = 'Unverified baseline epoch:' if claimed else 'Unresolved baseline epoch;'
    assert any(gate.startswith(prefix) for gate in loader()(root, 'pr-smoke').gates)
