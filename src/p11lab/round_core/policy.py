"""Strict, immutable round policy loading without checker or runtime execution.

JSON describes proposed control inputs. It is never proof of protected review,
receipt authenticity, provider qualification, or required-check activation.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from importlib.resources import files
import json
from pathlib import Path
import re
from types import MappingProxyType
from typing import Any, Callable, Mapping, cast

from ..jsonutil import loads

_decode = cast(Callable[[bytes], Any], loads)
_SHA256 = re.compile(r'[0-9a-f]{64}\Z')
_SHA1 = re.compile(r'[0-9a-f]{40}\Z')
_EVALUATOR = '09aabfec9fea7e424aabb991f6347349bfa84075'
_EVALUATOR_CONTRACT = 'aa2cf9f1ef72ad021fa42d47f9e8ae660f54d47be85c184532e0d2e6fe3f0eed'
_SMOKE_NODES = '294136b34eb9a65777e11f270cf9fc967482b369fb7c261476d98063cf87cbe3'
_LINUX = ('softhsm2', 'kryoptic', 'nss', 'tpm2', 'opencryptoki')
_TIERS = {
    'pr-smoke': (('softhsm2',), 1, 'round-pr-smoke-v1', 20, 14, 1),
    'nightly': (('softhsm2', 'kryoptic', 'nss'), 1, 'round-linux-v1', 90, 30, 3),
    'release': (_LINUX, 2, 'round-linux-v1', 90, 90, 3),
}
_PROFILES = {
    'round-pr-smoke-v1': ('exact-nodes', '', ''),
    'round-linux-v1': ('filtered', 'not (wycheproof or acvp or cctv or stress or fuzz or slow)', ''),
    'round-windows-v1': ('filtered', 'not security', 'test_encrypt or test_sign or test_digest'),
    'round-macos-full-v1': ('full', '', ''),
}
_DEFERRED = {
    'linux-bouncyhsm': ('bouncyhsm', 'linux/amd64', 'ubuntu-24.04', 'deferred-linux', 'optional'),
    'windows-softhsm2': ('softhsm2', 'windows/amd64', 'windows-2025-vs2026', 'future-native', 'future-mandatory'),
    'windows-bouncyhsm': ('bouncyhsm', 'windows/amd64', 'windows-2025-vs2026', 'future-native', 'future-mandatory'),
    'windows-nss': ('nss', 'windows/amd64', 'windows-2025-vs2026', 'future-native', 'optional'),
    'macos-softhsm2': ('softhsm2', 'macos/arm64', 'macos-26', 'future-native', 'future-mandatory'),
    'macos-bouncyhsm': ('bouncyhsm', 'macos/arm64', 'macos-26', 'future-native', 'optional'),
}
_SHARED_PINS = ('checker-build-lock', 'checker-runtime-lock', 'corpus',
                'runner-image', 'runner-resources', 'baseline-index')
_PROVIDER_PIN_KINDS = ('runtime', 'handoff', 'provider-source', 'recipe')
_PINS = {f'{lane}-{kind}' for lane in _LINUX for kind in _PROVIDER_PIN_KINDS}
_PINS.update((*_SHARED_PINS, 'proxy-daemon', 'proxy-client'))


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _object(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    _require(type(value) is dict, f'{label}: expected an object')
    _require(set(value) == keys, f'{label}: missing or extra fields (expected {sorted(keys)})')
    return dict(value)


def _same(value: Any, expected: Any, label: str) -> None:
    # JSON equality distinguishes booleans from integers unlike Python ==.
    _require(_canonical(value) == _canonical(expected), f'{label}: unsupported protected contract')


def _text(value: Any, label: str) -> None:
    _require(isinstance(value, str) and bool(value.strip()), f'{label}: nonempty identity/reason required')


def _sha(value: Any, label: str) -> None:
    _require(isinstance(value, str) and _SHA256.fullmatch(value) is not None,
             f'{label}: expected lowercase SHA256')


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def _hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


@dataclass(frozen=True)
class LoadedPolicy:
    """Frozen policy proposal plus diagnostics; never an acceptance receipt."""
    tier: str
    activation_state: str
    policy_digest: str
    roster_digest: str
    file_hashes: Mapping[str, str]
    active_lanes: tuple[Mapping[str, Any], ...]
    inactive_lanes: tuple[Mapping[str, Any], ...]
    outer_attempts: int
    profile: Mapping[str, Any]
    scope: Mapping[str, Any]
    gates: tuple[str, ...]
    controls: Mapping[str, Any]

    def to_record(self) -> dict[str, Any]:
        return {
            'schema_version': 1, 'kind': 'round-policy-diagnostic', 'tier': self.tier,
            'activation_state': self.activation_state, 'policy_digest': self.policy_digest,
            'roster_digest': self.roster_digest, 'file_hashes': dict(self.file_hashes),
            'active_lanes': _thaw(self.active_lanes), 'inactive_lanes': _thaw(self.inactive_lanes),
            'outer_attempts': self.outer_attempts,
            'quorum': {'min_repeats': self.outer_attempts, 'required_fraction': 1.0, 'require_unanimous': True},
            'profile': _thaw(self.profile), 'scope': _thaw(self.scope),
            'controls': _thaw(self.controls), 'gates': list(self.gates),
            'round_positive': False,
        }


def _profile(value: Any, name: str) -> dict[str, Any]:
    profile = _object(value, {'schema_version', 'id', 'collection', 'nodes', 'marker_expression',
        'keyword_expression', 'destructive', 'key_injection', 'recovery', 'disabled_inventory'}, name)
    collection, markers, keywords = _PROFILES[name]
    for key, expected in {'schema_version': 1, 'id': name, 'collection': collection,
            'marker_expression': markers, 'keyword_expression': keywords,
            'destructive': False, 'key_injection': False, 'recovery': False}.items():
        _same(profile[key], expected, f'{name}.{key}')
    nodes = profile['nodes']
    _require(type(nodes) is list and all(isinstance(node, str) for node in nodes), f'{name}: invalid nodes')
    _require(len(nodes) == len(set(nodes)), f'{name}: duplicate nodes')
    if name == 'round-pr-smoke-v1':
        _require(len(nodes) == 23 and _hash(_canonical(nodes)) == _SMOKE_NODES,
                 'smoke: expected the reviewed 23-node seed; W05 must revalidate candidate collection')
    else:
        _same(nodes, [], f'{name}.nodes')
    disabled = _object(profile['disabled_inventory'], {'sha256', 'reason'}, f'{name}.disabled_inventory')
    _text(disabled['reason'], f'{name}.disabled_inventory.reason')
    if disabled['sha256'] is not None:
        _sha(disabled['sha256'], f'{name}.disabled_inventory.sha256')
    return profile


def _sources(value: Any, contract: bytes, image_contract: bytes) -> dict[str, Any]:
    sources = _object(value, {'schema_version', 'evaluator_revision', 'evaluator_contract_sha256',
        'checker_candidate', 'image_pins', 'baseline', 'pins'}, 'sources')
    _same(sources['schema_version'], 1, 'sources.schema_version')
    _require(isinstance(sources['evaluator_revision'], str) and
             _SHA1.fullmatch(sources['evaluator_revision']) is not None, 'malformed evaluator revision')
    _same(sources['evaluator_revision'], _EVALUATOR, 'evaluator_revision')
    _sha(sources['evaluator_contract_sha256'], 'evaluator_contract_sha256')
    _same(sources['evaluator_contract_sha256'], _EVALUATOR_CONTRACT, 'reviewed evaluator contract identity')
    _same(_hash(contract), _EVALUATOR_CONTRACT, 'reviewed evaluator contract bytes')
    _same(sources['checker_candidate'], 'caller-selected-immutable-revision', 'checker_candidate')
    images = _object(sources['image_pins'], {'path', 'sha256', 'authority'}, 'image_pins')
    _same(images['path'], 'ci/images.json', 'image_pins.path')
    _sha(images['sha256'], 'image_pins.sha256')
    _same(images['sha256'], _hash(image_contract), 'image catalog contract bytes')
    _same(images['authority'], 'discovery-only; acquisition and admission remain separately gated', 'image_pins.authority')
    baseline = _object(sources['baseline'], {'index', 'compatibility', 'epoch'}, 'baseline')
    _same(baseline['index'], 'baselines/index.json', 'baseline.index')
    _same(baseline['compatibility'], 'round-baseline-v1', 'baseline.compatibility')
    if baseline['epoch'] is not None:
        _text(baseline['epoch'], 'baseline.epoch')
    pins = _object(sources['pins'], _PINS, 'source pins')
    for key, value in pins.items():
        pin = _object(value, {'sha256', 'reason'}, key)
        _text(pin['reason'], key + '.reason')
        if pin['sha256'] is not None:
            _sha(pin['sha256'], key + '.sha256')
    return sources


def _policy(value: Any) -> dict[str, Any]:
    policy = _object(value, {'schema_version', 'id', 'activation_state', 'commission', 'tiers',
        'lanes', 'scope', 'qualification', 'retries', 'budgets'}, 'policy')
    for key, expected in {'schema_version': 1, 'id': 'linux-amd64-round-v1', 'commission': 'linux-amd64'}.items():
        _same(policy[key], expected, 'policy.' + key)
    _require(policy['activation_state'] in ('diagnostic', 'qualified', 'required'), 'unknown activation_state')
    tiers = _object(policy['tiers'], set(_TIERS), 'tiers')
    for name, (roster, attempts, profile, budget, retention, raw) in _TIERS.items():
        _same(tiers[name], dict(mandatory_lanes=list(roster), outer_attempts=attempts, profile=profile,
            leg_target_minutes=budget, durable_retention_days=retention, raw_transfer_days=raw), name)
    _require(type(policy['lanes']) is list and bool(policy['lanes']), 'lanes: empty or invalid roster')
    seen = set()
    for value in policy['lanes']:
        lane = _object(value, {'id', 'provider', 'channel', 'platform', 'runner', 'transport',
            'emulated', 'cohort', 'requirement', 'reason'}, 'lane')
        name = lane['id']
        _text(name, 'lane.id')
        _require(name not in seen, f'duplicate lane: {name}')
        seen.add(name)
        _text(lane['reason'], name + '.reason')
        _same(lane['channel'], 'release', name + '.channel')
        _same(lane['emulated'], False, name + '.emulated')
        _same(lane['transport'], 'pkcs11-proxy-ng' if name == 'opencryptoki' else 'direct', name + '.transport')
        if name in _LINUX:
            identity = (name, 'linux/amd64', 'ubuntu-24.04', 'linux-amd64', 'mandatory')
        else:
            _require(name in _DEFERRED, f'unknown lane: {name}')
            identity = _DEFERRED[name]
        _same([lane[key] for key in ('provider', 'platform', 'runner', 'cohort', 'requirement')],
              list(identity), name + '.identity')
    _require(seen == set(_LINUX) | set(_DEFERRED), 'missing mandatory or inactive lane identity')
    scope = _object(policy['scope'], {'visibility', 'enforcement', 'unselected_obligations'}, 'scope')
    _same(scope['visibility'], 'baseline-candidate-catalog-union', 'scope.visibility')
    _same(scope['enforcement'], 'frozen-tier-selection', 'scope.enforcement')
    _text(scope['unselected_obligations'], 'scope.unselected_obligations')
    _same(policy['qualification'], dict(fresh_rounds=3, identical_semantic_projections=True,
        authenticated_receipts=[], policy_self_authorizes=False), 'qualification')
    _same(policy['retries'], dict(pre_provider_infra_retries=1, backoff_seconds=10,
        after_provider_start=False, verdict_negative=False), 'retries')
    _same(policy['budgets'], dict(status='targets-unmeasured', nightly_failed_raw_days=30,
        quota_stop_fraction=0.8), 'budgets')
    return policy


def load_policy(root: Path | None, tier: str) -> LoadedPolicy:
    """Validate exact policy/profile contracts and return an immutable proposal.

    ``None`` loads installed package resources. A root identifies a reviewed
    policy directory, not caller override authority. External authentication and
    qualification are deliberately unavailable here: activation always fails
    closed until a separately reviewed receipt-verification operation exists.
    """
    _require(isinstance(tier, str) and tier in _TIERS, f'unknown tier: {tier!r}')
    data = files('p11lab').joinpath('data') if root is None else Path(root).parent
    policy_root = data.joinpath('rounds') if root is None else Path(root)
    raw = {
        'rounds/policy.json': policy_root.joinpath('policy.json').read_bytes(),
        'rounds/sources.json': policy_root.joinpath('sources.json').read_bytes(),
        'rounds/contract.json': policy_root.joinpath('contract.json').read_bytes(),
        'ci/images.json': data.joinpath('ci', 'images.json').read_bytes(),
    }
    for name in _PROFILES:
        raw[f'profiles/{name}.json'] = data.joinpath('profiles', name + '.json').read_bytes()
    policy = _policy(_decode(raw['rounds/policy.json']))
    sources = _sources(_decode(raw['rounds/sources.json']), raw['rounds/contract.json'], raw['ci/images.json'])
    profiles = {name: _profile(_decode(raw[f'profiles/{name}.json']), name) for name in _PROFILES}
    lane_map = {lane['id']: lane for lane in policy['lanes']}
    selected, attempts, profile_name, _, _, _ = _TIERS[tier]
    active = [dict(lane_map[name], profile=profile_name) for name in selected]
    inactive = []
    for name, lane in lane_map.items():
        if name in selected:
            continue
        record = dict(lane)
        if name in _LINUX:
            record['reason'] = f'Not selected for frozen {tier} tier; retained in later Linux tiers.'
        record['profile'] = ('round-windows-v1' if name.startswith('windows-') else
                             'round-macos-full-v1' if name.startswith('macos-') else 'round-linux-v1')
        inactive.append(record)
    needed = set(_SHARED_PINS)
    needed.update(f'{name}-{kind}' for name in selected for kind in _PROVIDER_PIN_KINDS)
    if 'opencryptoki' in selected:
        needed.update(('proxy-client', 'proxy-daemon'))
    gates = [f'Unresolved digest: {name}: {sources["pins"][name]["reason"]}'
             if sources['pins'][name]['sha256'] is None else
             f'Unverified digest: {name}: declared SHA256 {sources["pins"][name]["sha256"]}; resource bytes and authority remain unverified.'
             for name in sorted(needed)]
    if sources['baseline']['epoch'] is None:
        gates.append('Unresolved baseline epoch; prepare must freeze the accepted index bytes and hash.')
    else:
        gates.append(f'Unverified baseline epoch: declared {sources["baseline"]["epoch"]}; accepted index bytes and generation authority remain unverified.')
    disabled = profiles[profile_name]['disabled_inventory']
    if disabled['sha256'] is None:
        gates.append(f'Unresolved disabled inventory: {profile_name}: {disabled["reason"]}')
    else:
        gates.append(f'Unverified disabled inventory: {profile_name}: declared SHA256 {disabled["sha256"]}; candidate/lane inventory bytes and authority remain unverified.')
    gates.extend(('HR1: protected reviewer/owner identities and activation authority are unverified.',
        'No independently verified qualifying receipts: three complete fresh-provider rounds with identical semantic projections are required.',
        'Provider/handoff anonymous readback and actual resolved runner image/resources require qualification.',
        'Time/storage/resource budgets are unmeasured targets; HR2 effective quota facts are absent.',
        'No runtime execution, evidence completeness, regression, coverage, or CI acceptance has been verified.'))
    if tier == 'release':
        gates.extend(('EVID-STREAM-1: N=2 public stream-context export/admission/comparison remains blocked.',
                      'E5: release dry-run and same-run artifact/capsule handoff remain unverified.'))
    if policy['activation_state'] != 'diagnostic':
        raise ValueError('activation refused: unverified protected authority/qualifying receipts; ' + '; '.join(gates))
    hashes = {name: _hash(value) for name, value in sorted(raw.items())}
    controls = {key: policy[key] for key in ('qualification', 'retries', 'budgets')}
    controls['tier'] = policy['tiers'][tier]
    controls['baseline'] = sources['baseline']
    controls['evaluator_revision'] = sources['evaluator_revision']
    controls['image_pins'] = sources['image_pins']
    controls['sources'] = sources
    return LoadedPolicy(tier, 'diagnostic', _hash(_canonical(hashes)),
        _hash(_canonical({'tier': tier, 'lanes': active, 'attempts': attempts, 'profile': profiles[profile_name]})),
        MappingProxyType(hashes), _freeze(active), _freeze(inactive), attempts,
        _freeze(profiles[profile_name]), _freeze(policy['scope']), tuple(gates), _freeze(controls))
