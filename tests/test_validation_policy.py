"""Static contract pins for the M08 provider-image-validation policy.

The gate's fixed tool+gate policy lives in protected data
(`src/p11lab/data/ci/validation-policy.json`): authoring pins its closed
schema, the Q2-ruled concrete values (each cited to its accepted record),
and the Q3-required `unqualified:<reason>` markers with their exact
reasons, plus the whole-policy gate-unsatisfiable assertion. Families
P1-P5 follow M08-validation-preparation/report.md section 3 as adapted
by D/M08-validation-brief.md (deltas ruled there, not verbatim).

Hermetic: every path below resolves inside this checkout (ROOT); the
tests read the M08 policy, the frozen M03 delivery record, tools.json,
the smoke-v1 profile bytes, and the new workflow. No network, no
registry, no invented concrete values: the only concrete pins are the
Q2-ruled ones, each cited; every invented digest is an obvious
constructed constant (`"0" * 64`) used only as a mutation negative.

Q3 evaluator follow-up routing (candidate receipts live ONLY in this
comment, never as policy values): no evaluator designation record
exists. Two undesignated candidates are known: `47047d93...`
(W01-replacement, full
`47047d933068800cfa8a9596a5579877d4c83c1408ef006b6cea7d8030c313f4`)
and `0790dca2...` (W03-second, full
`0790dca26abbdb5f37b18fe7a9f80431a9d05c24aa027116342dd1712c76081e`).
Designating either is a separately authorized step.
"""

import copy
import hashlib
import inspect
import json
import re
from pathlib import Path

import pytest

from p11lab import image_ci

ROOT = Path(__file__).resolve().parent.parent
POLICY = ROOT / "src/p11lab/data/ci/validation-policy.json"
M03_POLICY = ROOT / "src/p11lab/data/ci/delivery/validation-policy.json"
TOOLS = ROOT / "src/p11lab/data/tools.json"
PROFILE = ROOT / "src/p11lab/data/profiles/smoke-v1.json"
WORKFLOW = ROOT / ".github/workflows/provider-image-validation.yml"

HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")

# Q3 exact reason markers (D/M08-validation-brief.md Q2/Q3). Each fails
# any 40/64-hex regex by construction (the `unqualified:` prefix).
UNQ_SOURCE_MANIFEST = "unqualified:no-accepted-source-manifest"
UNQ_BUILD_MANIFEST = "unqualified:no-accepted-build-manifest"
UNQ_DEPENDENCIES_MANIFEST = "unqualified:no-accepted-dependencies-manifest"
UNQ_INSTALLED_MANIFEST = "unqualified:no-accepted-installed-manifest"
UNQ_EVALUATOR = "unqualified:no-designated-evaluator-receipt"
UNQ_CONTROL_COMMIT = "unqualified:no-sealed-control-commit"
UNQ_CHECKER_TIER = "unqualified:no-accepted-checker-tier"

SLOT_REASONS = {
    "source": UNQ_SOURCE_MANIFEST,
    "build": UNQ_BUILD_MANIFEST,
    "dependencies": UNQ_DEPENDENCIES_MANIFEST,
    "installed": UNQ_INSTALLED_MANIFEST,
}

# Q2 concrete pins, each cited to its accepted record (verified
# 2026-10-30; cross-checked against the live records below, never
# trusted blindly).
CHECKER_REVISION = "9df03bd8b811966fa7856394b19e3f57ffcd8a40"  # tools.json checker + M03 record + profile
PROXY_REVISION = "a348a5f59b535b1ca309ea9f0a722e3bec692f72"  # tools.json proxy
CHECKER_WHEEL_SHA256 = "58ac3451ae0dba207a48affa460309e4024c2ec7aefb04ef73062f420fdcffec"  # M03 record + profile
CHECKER_RUNTIME_LOCK_SHA256 = "98a0341351b410b8ba6d732ae82ffef14442cded33caf8ab55e3958a0c407cab"  # M03 record + profile
PROFILE_SHA256 = "57ffa60750dbf76f21e72ad20fb9d3c43a6270c821dd7628115fd63dcb86cc56"  # sha256 of the R profile bytes
CATALOG_COUNTS = {  # M03 record catalog_counts, same mapping
    "test_interface.py": 11,
    "test_session_info.py": 4,
    "test_object.py": 16,
    "test_digest.py": 21,
    "test_sign.py": 18,
}
PROXY_TIER = "proxy-diagnostic-v1"  # only tier proxy-round.yml accepts

TOP_KEYS = {"schema_version", "kind", "source_revisions", "fixed_tools",
            "evaluator", "control", "providers", "rounds"}
TOOL_ROSTER = {"checker", "proxy", "consumer", "oracle"}
QUAD_KEYS = {"source", "build", "dependencies", "installed"}


def _load_policy():
    return json.loads(POLICY.read_bytes())


def _load_record(path):
    return json.loads(path.read_bytes())


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _match(message):
    # Prefix-anchored: pytest appends its own introspection after a custom
    # assert message, so the full intended message must match from the start
    # while trailing rewrite output is tolerated.
    return "^" + re.escape(message)


# P1 focused assertions (one per row so each mutation reddens exactly
# its assertion).
def _assert_p1_top_keys(policy):
    assert set(policy) == TOP_KEYS, "top-level keys must be the closed M08 set"


def _assert_p1_version_kind(policy):
    assert policy["schema_version"] == 1
    assert policy["kind"] == "provider-image-validation"


def _assert_p1_tool_roster(policy):
    assert set(policy["fixed_tools"]) == TOOL_ROSTER, "fixed-tools roster must be the closed tool set"
    for name, quad in policy["fixed_tools"].items():
        assert set(quad) == QUAD_KEYS, "tool quad keys must be the closed slot set: %s" % name


def _assert_p1_subkeys(policy):
    assert set(policy["source_revisions"]) == {"checker", "proxy"}
    assert set(policy["evaluator"]) == {"receipt_sha256"}
    assert set(policy["control"]) == {"profile", "profile_sha256", "control_commit", "catalog"}
    assert set(policy["providers"]) == {"allowlist", "mode"}
    assert set(policy["rounds"]) == {"framework_sha", "proxy_sha", "proxy_tier", "checker_tier"}
    assert set(policy["control"]["catalog"]) == set(CATALOG_COUNTS)


def test_p1_top_level_keys_closed():
    _assert_p1_top_keys(_load_policy())


def test_p1_schema_version_and_kind():
    _assert_p1_version_kind(_load_policy())


def test_p1_fixed_tools_roster_and_quad_keys():
    _assert_p1_tool_roster(_load_policy())


def test_p1_sub_object_keys_closed():
    _assert_p1_subkeys(_load_policy())


def test_p1_mutation_unknown_top_level_key_rejected():
    bad = _load_policy()
    bad["policy_revision"] = "2026-10-30.1"
    with pytest.raises(AssertionError, match=_match("top-level keys must be the closed M08 set")):
        _assert_p1_top_keys(bad)


def test_p1_mutation_missing_top_level_key_rejected():
    bad = _load_policy()
    del bad["rounds"]
    with pytest.raises(AssertionError, match=_match("top-level keys must be the closed M08 set")):
        _assert_p1_top_keys(bad)


def test_p1_mutation_unknown_tool_rejected():
    bad = _load_policy()
    bad["fixed_tools"]["p11scope"] = dict(bad["fixed_tools"]["checker"])
    with pytest.raises(AssertionError, match=_match("fixed-tools roster must be the closed tool set")):
        _assert_p1_tool_roster(bad)


def test_p1_mutation_quad_key_rejected():
    bad = _load_policy()
    bad["fixed_tools"]["checker"]["provenance"] = "0" * 64
    with pytest.raises(AssertionError, match=_match("tool quad keys must be the closed slot set: checker")):
        _assert_p1_tool_roster(bad)
    bad = _load_policy()
    del bad["fixed_tools"]["oracle"]["installed"]
    with pytest.raises(AssertionError, match=_match("tool quad keys must be the closed slot set: oracle")):
        _assert_p1_tool_roster(bad)


# P2 focused assertions: Q3 exact markers + Q2 concrete formats.
def _assert_p2_tool_markers(policy):
    for name, quad in policy["fixed_tools"].items():
        for slot, reason in SLOT_REASONS.items():
            assert quad[slot] == reason, "tool slot must carry its exact unqualified marker: %s/%s" % (name, slot)
            assert HEX64.match(quad[slot]) is None, "tool slot marker must not be hex: %s/%s" % (name, slot)


def _assert_p2_single_markers(policy):
    assert policy["evaluator"]["receipt_sha256"] == UNQ_EVALUATOR, "evaluator receipt must be the exact unqualified marker"
    assert policy["control"]["control_commit"] == UNQ_CONTROL_COMMIT, "control commit must be the exact unqualified marker"
    assert policy["rounds"]["checker_tier"] == UNQ_CHECKER_TIER, "checker tier must be the exact unqualified marker"
    for value in (policy["evaluator"]["receipt_sha256"], policy["control"]["control_commit"]):
        assert HEX40.match(value) is None and HEX64.match(value) is None, "single markers must not be hex"


def _assert_p2_concrete_hex(policy):
    assert HEX40.match(policy["source_revisions"]["checker"]) is not None, "checker source revision must be 40-hex"
    assert HEX40.match(policy["source_revisions"]["proxy"]) is not None, "proxy source revision must be 40-hex"
    assert HEX64.match(policy["control"]["profile_sha256"]) is not None, "profile sha256 must be 64-hex"
    assert HEX40.match(policy["rounds"]["framework_sha"]) is not None, "framework sha must be 40-hex"
    assert HEX40.match(policy["rounds"]["proxy_sha"]) is not None, "rounds proxy sha must be 40-hex"


def _assert_p2_concrete_names(policy):
    assert policy["control"]["profile"] == "smoke-v1"
    assert policy["rounds"]["proxy_tier"] == PROXY_TIER


def test_p2_fixed_tools_slots_exact_markers():
    _assert_p2_tool_markers(_load_policy())


def test_p2_evaluator_control_commit_checker_tier_exact_markers():
    _assert_p2_single_markers(_load_policy())


def test_p2_concrete_hex_fields():
    _assert_p2_concrete_hex(_load_policy())


def test_p2_profile_and_proxy_tier_exact():
    _assert_p2_concrete_names(_load_policy())


def test_p2_mutation_qualified_tool_slot_rejected():
    bad = _load_policy()
    bad["fixed_tools"]["checker"]["source"] = "0" * 64
    with pytest.raises(AssertionError, match=_match("tool slot must carry its exact unqualified marker: checker/source")):
        _assert_p2_tool_markers(bad)


def test_p2_mutation_qualified_evaluator_rejected():
    bad = _load_policy()
    bad["evaluator"]["receipt_sha256"] = "0" * 64
    with pytest.raises(AssertionError, match=_match("evaluator receipt must be the exact unqualified marker")):
        _assert_p2_single_markers(bad)


def test_p2_mutation_concrete_hex_malformed_rejected():
    bad = _load_policy()
    bad["rounds"]["framework_sha"] = CHECKER_REVISION[:39]
    with pytest.raises(AssertionError, match=_match("framework sha must be 40-hex")):
        _assert_p2_concrete_hex(bad)
    bad = _load_policy()
    bad["control"]["profile_sha256"] = "g" + "0" * 63
    with pytest.raises(AssertionError, match=_match("profile sha256 must be 64-hex")):
        _assert_p2_concrete_hex(bad)


def test_p2_mutation_reason_typo_rejected():
    bad = _load_policy()
    bad["fixed_tools"]["proxy"]["installed"] = "unqualified:no-accepted-installed-manifests"
    with pytest.raises(AssertionError, match=_match("tool slot must carry its exact unqualified marker: proxy/installed")):
        _assert_p2_tool_markers(bad)
    bad = _load_policy()
    bad["rounds"]["checker_tier"] = "UNQUALIFIED:no-accepted-checker-tier"
    with pytest.raises(AssertionError, match=_match("checker tier must be the exact unqualified marker")):
        _assert_p2_single_markers(bad)


# P3 focused assertions: Q9 allowlist posture.
def _allowed(policy, environment):
    providers = policy["providers"]
    return providers["mode"] == "explicit-allowlist" and environment in providers["allowlist"]


def _assert_p3_exact(policy):
    assert policy["providers"] == {"allowlist": ["softhsm2"], "mode": "explicit-allowlist"}, "providers must be the explicit softhsm2 allowlist"


def test_p3_providers_exact():
    _assert_p3_exact(_load_policy())


def test_p3_allowlist_gate():
    policy = _load_policy()
    assert _allowed(policy, "softhsm2") is True
    for other in ("nss", "kryoptic", "opencryptoki", "*", "", "softhsm2 "):
        assert _allowed(policy, other) is False, other


def test_p3_mutation_wildcard_rejected():
    bad = _load_policy()
    bad["providers"]["allowlist"] = ["*"]
    with pytest.raises(AssertionError, match=_match("providers must be the explicit softhsm2 allowlist")):
        _assert_p3_exact(bad)
    # A wildcard admits nobody under explicit matching: the pin keeps the
    # gate narrow on purpose instead of failing open or closed by accident.
    assert _allowed(bad, "softhsm2") is False


def test_p3_mutation_empty_or_mode_flip_rejected():
    bad = _load_policy()
    bad["providers"]["allowlist"] = []
    with pytest.raises(AssertionError, match=_match("providers must be the explicit softhsm2 allowlist")):
        _assert_p3_exact(bad)
    bad = _load_policy()
    bad["providers"]["mode"] = "pattern-allowlist"
    with pytest.raises(AssertionError, match=_match("providers must be the explicit softhsm2 allowlist")):
        _assert_p3_exact(bad)


# P4 focused assertions: M03 cross-consistency (the M08 file must agree
# with the frozen M03 record, never silently promote past it).
def _assert_p4_source_revisions(policy):
    tools = _load_record(TOOLS)
    m03 = _load_record(M03_POLICY)
    assert policy["source_revisions"]["checker"] == CHECKER_REVISION, "policy checker revision must be the pinned revision"
    assert policy["source_revisions"]["proxy"] == PROXY_REVISION, "policy proxy revision must be the pinned revision"
    assert tools["tools"]["checker"]["source"]["revision"] == CHECKER_REVISION, "tools.json checker revision must be the pinned revision"
    assert tools["tools"]["proxy"]["source"]["revision"] == PROXY_REVISION, "tools.json proxy revision must be the pinned revision"
    assert m03["checker_revision"] == CHECKER_REVISION, "M03 checker revision must be the pinned revision"
    assert policy["rounds"]["framework_sha"] == CHECKER_REVISION, "rounds framework sha must be the checker revision"
    assert policy["rounds"]["proxy_sha"] == PROXY_REVISION, "rounds proxy sha must be the proxy revision"


def _assert_p4_catalog(policy):
    m03 = _load_record(M03_POLICY)
    assert policy["control"]["catalog"] == CATALOG_COUNTS, "control catalog must match the pinned M03 counts"
    assert m03["catalog_counts"] == CATALOG_COUNTS, "M03 catalog counts must match the pinned counts"


def _assert_p4_m03_unpromoted():
    m03 = _load_record(M03_POLICY)
    assert m03["comparison"] is None
    assert m03["promotable"] is False


def _assert_p4_wheel_lock():
    m03 = _load_record(M03_POLICY)
    profile = _load_record(PROFILE)
    assert m03["checker_wheel_sha256"] == CHECKER_WHEEL_SHA256
    assert m03["checker_runtime_lock_sha256"] == CHECKER_RUNTIME_LOCK_SHA256
    assert profile["wheel_sha256"] == CHECKER_WHEEL_SHA256
    assert profile["runtime_lock_sha256"] == CHECKER_RUNTIME_LOCK_SHA256
    assert profile["source_revision"] == CHECKER_REVISION


def _assert_p4_profile_sha(policy):
    assert policy["control"]["profile_sha256"] == PROFILE_SHA256
    assert hashlib.sha256(PROFILE.read_bytes()).hexdigest() == PROFILE_SHA256


def test_p4_source_revisions_match_tools_and_m03():
    _assert_p4_source_revisions(_load_policy())


def test_p4_catalog_matches_m03():
    _assert_p4_catalog(_load_policy())


def test_p4_m03_still_unpromoted():
    _assert_p4_m03_unpromoted()


def test_p4_wheel_lock_match_profile():
    _assert_p4_wheel_lock()


def test_p4_profile_sha256_matches_bytes():
    _assert_p4_profile_sha(_load_policy())


def test_p4_mutation_catalog_drift_rejected():
    bad = _load_policy()
    bad["control"]["catalog"]["test_sign.py"] = 19
    with pytest.raises(AssertionError, match=_match("control catalog must match the pinned M03 counts")):
        _assert_p4_catalog(bad)


def test_p4_mutation_source_revision_drift_rejected():
    bad = _load_policy()
    bad["source_revisions"]["proxy"] = "0" * 40
    with pytest.raises(AssertionError, match=_match("policy proxy revision must be the pinned revision")):
        _assert_p4_source_revisions(bad)


# P5 focused assertions: policy-hash binding.
def _policy_canonical_sha256(policy):
    return hashlib.sha256(_canonical(policy)).hexdigest()


def test_p5_canonical_hash_stable():
    first = _policy_canonical_sha256(_load_policy())
    second = _policy_canonical_sha256(json.loads(POLICY.read_bytes()))
    assert first == second
    assert HEX64.match(first) is not None


def test_p5_single_byte_mutation_changes_hash():
    before = _policy_canonical_sha256(_load_policy())
    bad = _load_policy()
    bad["control"]["catalog"]["test_sign.py"] = 19
    assert _policy_canonical_sha256(bad) != before
    bad = _load_policy()
    bad["rounds"]["proxy_tier"] = "proxy-diagnostic-v2"
    assert _policy_canonical_sha256(bad) != before


def test_p5_workflow_records_policy_sha256():
    text = WORKFLOW.read_text()
    assert "policy_sha256" in text
    assert "validation-policy.json" in text
    assert "hashlib.sha256" in text


# Q3 whole-policy gate-unsatisfiable assertion: the exact set of
# unqualified slots, no more and no fewer. Any silent qualification
# (concrete value where a marker belongs) or any new unqualified slot
# fails here even if every per-field test above were weakened.
def _unqualified_paths(policy):
    found = set()

    def visit(node, path):
        if isinstance(node, dict):
            for key, value in node.items():
                visit(value, path + (key,))
        elif isinstance(node, list):
            for index, value in enumerate(node):
                visit(value, path + (index,))
        elif isinstance(node, str) and node.startswith("unqualified:"):
            found.add(path)

    visit(policy, ())
    return found


EXPECTED_UNQUALIFIED_PATHS = (
    {("fixed_tools", tool, slot) for tool in sorted(TOOL_ROSTER) for slot in sorted(QUAD_KEYS)}
    | {("evaluator", "receipt_sha256"), ("control", "control_commit"), ("rounds", "checker_tier")}
)


def _assert_q3_gate_unsatisfiable(policy):
    assert _unqualified_paths(policy) == EXPECTED_UNQUALIFIED_PATHS, "unqualified paths must be exactly the 19 gate-unsatisfiable slots"
    assert len(EXPECTED_UNQUALIFIED_PATHS) == 19, "expected unqualified path count must be 19"


def test_q3_policy_as_a_whole_is_gate_unsatisfiable():
    _assert_q3_gate_unsatisfiable(_load_policy())


def test_q3_mutation_silent_qualification_rejected():
    bad = _load_policy()
    bad["control"]["control_commit"] = "0" * 40
    with pytest.raises(AssertionError, match=_match("unqualified paths must be exactly the 19 gate-unsatisfiable slots")):
        _assert_q3_gate_unsatisfiable(bad)
    bad = _load_policy()
    bad["rounds"]["checker_tier"] = "release"
    with pytest.raises(AssertionError, match=_match("unqualified paths must be exactly the 19 gate-unsatisfiable slots")):
        _assert_q3_gate_unsatisfiable(bad)


def test_q3_mutation_new_unqualified_slot_rejected():
    bad = _load_policy()
    bad["rounds"]["proxy_tier"] = "unqualified:no-accepted-proxy-tier"
    with pytest.raises(AssertionError, match=_match("unqualified paths must be exactly the 19 gate-unsatisfiable slots")):
        _assert_q3_gate_unsatisfiable(bad)


# H-2 pin: the reshaped workflow freezes its plan via the module-private
# image_ci._freeze_experiment (fix-1 G-2: the only plan-freezing
# projection in image_ci.py; no public plan API exists). Pin existence +
# call shape here so a future removal/rename fails closed in the suite
# instead of at workflow runtime. Read-only import; no behavior change.
def test_h2_freeze_experiment_shape_pinned():
    assert hasattr(image_ci, "_freeze_experiment"), "workflow plan call must exist: image_ci._freeze_experiment"
    target = image_ci._freeze_experiment
    assert callable(target), "workflow plan call must be callable: image_ci._freeze_experiment"
    params = list(inspect.signature(target).parameters.values())
    assert [param.name for param in params] == ["experiment", "build_key", "platform", "pending"], \
        "freeze arity must match the workflow call: (experiment, build_key, platform, pending)"
    assert all(param.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
              for param in params), "freeze params must accept the workflow positional call"
