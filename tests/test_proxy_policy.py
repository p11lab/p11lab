"""Hermetic proxy-policy roster and truth-table verdict (H1-H15).

Design: L351-360 (proxy policy acceptance), L362-369 (budgets), L371-387
(control roster), L389-397 (source binding), L399-403 (accepted-first +
mutants), L405-419 (A/S/T/R/B predicate + truth table). Every test cites
its row.
All fixtures are authored here with invented hashes; nothing reads outside
the checkout.
"""

import copy
import json
from types import MappingProxyType

import pytest

from p11lab import proxy_policy


MANIFEST = "sha256:69cdeb9a74d13a3382547e184645ee18a7e9e2315246fd40ca814ef97b970d16"
CONFIG = "sha256:e59ab297033cedfd8049f76bcf6d9e9c86f8df262be1c80ccbd7c1731437d24f"
ROSTER = (
    "PX-AUTH",
    "PX-STATE",
    "PX-REPLAY",
    "PX-CLIENT-CRASH",
    "PX-DAEMON-DEATH",
    "PX-DAEMON-STOP",
    "PX-LIMIT",
)


def shipped_policy():
    from importlib.resources import files

    return json.loads(
        files("p11lab").joinpath("data/ci/proxy-policy.json").read_bytes()
    )


def mutated_policy(tmp_path, mutate):
    record = shipped_policy()
    mutate(record)
    path = tmp_path / "proxy-policy.json"
    path.write_text(json.dumps(record))
    return path


def clean_cells(**overrides):
    cells = {
        "direct": {
            "admitted": True,
            "complete": True,
            "attribution_usable": True,
            "findings": [],
        },
        "accepted-proxy": {
            "admitted": True,
            "complete": True,
            "terminal_evidence_complete": True,
        },
        "candidate-proxy": {
            "admitted": True,
            "complete": True,
            "terminal_evidence_complete": True,
        },
        "comparison": {"performed": True, "positive": True, "coverage_positive": True},
        "cancelled": False,
        "uploads_complete": True,
        "infrastructure_error": None,
    }
    aliases = {"accepted_proxy": "accepted-proxy", "candidate_proxy": "candidate-proxy"}
    for key, value in overrides.items():
        key = aliases.get(key, key)
        if isinstance(value, dict):
            cells[key].update(value)
        else:
            cells[key] = value
    return cells


def clean_controls(fail=(), fail_accepted=()):
    controls = {}
    for control in ROSTER:
        controls[control] = {
            "accepted-proxy": "fail" if control in fail_accepted else "pass",
            "candidate-proxy": "fail" if control in fail else "pass",
        }
    return controls


def clean_budgets(within=True):
    return {"within_budget": within}


def test_h1_policy_exact_shape_accepts_and_freezes():
    # Design L351-360 (tier acceptance) + L362-369 (budgets).
    loaded = proxy_policy.load_proxy_policy()
    assert loaded.tier == "proxy-diagnostic-v1"
    assert loaded.activation_state == "diagnostic"
    assert [control["id"] for control in loaded.controls] == list(ROSTER)
    assert loaded.budgets["per_cell_seconds"] == 300
    assert loaded.budgets["transport_controls_seconds"] == 300
    assert loaded.budgets["acquisition_preflight_seconds"] == 600
    assert loaded.budgets["workflow_active_minutes"] == 30
    assert loaded.budgets["raw_bytes"] == 2147483648
    assert loaded.budgets["diagnostics_bytes"] == 16777216
    assert loaded.budgets["retention_days"] == 14
    assert loaded.provider["manifest_digest"] == MANIFEST
    assert loaded.provider["config_digest"] == CONFIG
    assert loaded.fixed_inputs["profile"] == "round-pr-smoke-v1"
    assert loaded.fixed_inputs["nodes"] == 23
    assert loaded.fixed_inputs["destructive"] is False
    assert type(loaded.provider) is MappingProxyType
    assert type(loaded.budgets) is MappingProxyType
    assert type(loaded.controls) is tuple
    with pytest.raises(TypeError):
        loaded.provider["family"] = "kryoptic"
    with pytest.raises(TypeError):
        loaded.budgets["retention_days"] = 15
    with pytest.raises(AttributeError):
        loaded.controls.append({})


@pytest.mark.parametrize("tier", ["pr-smoke", "nightly", "release", "made-up", ""])
def test_h2_unknown_and_checker_tier_names_reject(tier):
    # Design L353 (only proxy-diagnostic-v1; reject checker tier names).
    with pytest.raises(ValueError, match="tier"):
        proxy_policy.load_proxy_policy(tier=tier)


def test_h2_unknown_control_rejects(tmp_path):
    # Design L359 (freeze the roster before execution).
    extra = copy.deepcopy(shipped_policy()["controls"][0])
    extra["id"] = "PX-MADE-UP"
    path = mutated_policy(tmp_path, lambda r: r["controls"].append(extra))
    with pytest.raises(ValueError, match="PX-MADE-UP"):
        proxy_policy.load_proxy_policy(path=path)


def test_h2_unknown_field_rejects(tmp_path):
    path = mutated_policy(tmp_path, lambda r: r.update(extra_field=1))
    with pytest.raises(ValueError, match="extra_field|missing or extra"):
        proxy_policy.load_proxy_policy(path=path)
    path = mutated_policy(tmp_path, lambda r: r["controls"][0].update(extra=1))
    with pytest.raises(ValueError, match="extra|missing or extra"):
        proxy_policy.load_proxy_policy(path=path)


def _control_by_id(record, control_id):
    return next(c for c in record["controls"] if c["id"] == control_id)


def test_h2_g1_unknown_stimulus_field_refuses(tmp_path):
    # G-1: stimulus is a per-control pinned contract; unknown keys refuse.
    def add(record):
        _control_by_id(record, "PX-AUTH")["stimulus"]["unreviewed_probe"] = "probe"

    path = mutated_policy(tmp_path, add)
    with pytest.raises(ValueError, match="stimulus"):
        proxy_policy.load_proxy_policy(path=path)


def test_h2_g1_altered_stimulus_value_refuses(tmp_path):
    # G-1: reviewed stimulus values are pinned; alterations refuse.
    def alter(record):
        _control_by_id(record, "PX-AUTH")["stimulus"]["valid_client"] = (
            "two mTLS handshakes + enumerate"
        )

    path = mutated_policy(tmp_path, alter)
    with pytest.raises(ValueError, match="stimulus"):
        proxy_policy.load_proxy_policy(path=path)


def test_h2_g1_removed_stimulus_binding_refuses(tmp_path):
    # G-1: removing a reviewed stimulus binding refuses.
    def strip(record):
        del _control_by_id(record, "PX-AUTH")["stimulus"]["invalid_client"]

    path = mutated_policy(tmp_path, strip)
    with pytest.raises(ValueError, match="stimulus"):
        proxy_policy.load_proxy_policy(path=path)


def test_h2_g1_unknown_ck_rv_field_refuses(tmp_path):
    # G-1: ck_rv is a per-control pinned contract; unknown keys refuse.
    def add(record):
        _control_by_id(record, "PX-AUTH")["expected"]["ck_rv"]["unreviewed_probe"] = (
            "CKR_OK"
        )

    path = mutated_policy(tmp_path, add)
    with pytest.raises(ValueError, match="ck_rv"):
        proxy_policy.load_proxy_policy(path=path)


def test_h2_g1_altered_ck_rv_value_refuses(tmp_path):
    # G-1: reviewed ck_rv values are pinned; alterations refuse.
    def alter(record):
        _control_by_id(record, "PX-AUTH")["expected"]["ck_rv"]["valid_enumerate"] = (
            "CKR_GENERAL_ERROR"
        )

    path = mutated_policy(tmp_path, alter)
    with pytest.raises(ValueError, match="ck_rv"):
        proxy_policy.load_proxy_policy(path=path)


def test_h2_g1_removed_ck_rv_binding_refuses(tmp_path):
    # G-1: removing a reviewed ck_rv binding refuses.
    def strip(record):
        del _control_by_id(record, "PX-AUTH")["expected"]["ck_rv"][
            "invalid_reject_point"
        ]

    path = mutated_policy(tmp_path, strip)
    with pytest.raises(ValueError, match="ck_rv"):
        proxy_policy.load_proxy_policy(path=path)


def test_h2_g1_unknown_backend_effect_field_refuses(tmp_path):
    # G-1: backend_effect is a per-control pinned contract; unknown keys refuse.
    def add(record):
        _control_by_id(record, "PX-STATE")["expected"]["backend_effect"][
            "unreviewed_probe"
        ] = 7

    path = mutated_policy(tmp_path, add)
    with pytest.raises(ValueError, match="backend_effect"):
        proxy_policy.load_proxy_policy(path=path)


def test_h2_g1_verbatim_unreviewed_backend_swap_refuses(tmp_path):
    # G-1 verbatim trigger: replacing PX-AUTH's backend observation with
    # {"unreviewed": true} removes the call-counter binding: refuse.
    def swap(record):
        _control_by_id(record, "PX-AUTH")["expected"]["backend_effect"] = {
            "unreviewed": True
        }

    path = mutated_policy(tmp_path, swap)
    with pytest.raises(ValueError, match="backend_effect"):
        proxy_policy.load_proxy_policy(path=path)


def test_h2_g1_verbatim_counter_delta_0_to_1_refuses(tmp_path):
    # G-1 verbatim trigger: changing PX-AUTH's expected counter delta
    # from 0 to 1 refuses.
    def alter(record):
        _control_by_id(record, "PX-AUTH")["expected"]["backend_effect"][
            "call_counter_delta_by_invalid"
        ] = 1

    path = mutated_policy(tmp_path, alter)
    with pytest.raises(ValueError, match="backend_effect"):
        proxy_policy.load_proxy_policy(path=path)


def test_h2_g1_removed_backend_binding_refuses(tmp_path):
    # G-1: removing a reviewed backend-effect binding refuses.
    def strip(record):
        del _control_by_id(record, "PX-STATE")["expected"]["backend_effect"][
            "objects_found_by_b"
        ]

    path = mutated_policy(tmp_path, strip)
    with pytest.raises(ValueError, match="backend_effect"):
        proxy_policy.load_proxy_policy(path=path)


def test_h2_g1_unknown_termination_field_refuses(tmp_path):
    # G-1: termination is a per-control pinned contract; unknown keys refuse.
    def add(record):
        _control_by_id(record, "PX-CLIENT-CRASH")["expected"]["termination"][
            "unreviewed_probe"
        ] = "probe"

    path = mutated_policy(tmp_path, add)
    with pytest.raises(ValueError, match="termination"):
        proxy_policy.load_proxy_policy(path=path)


def test_h2_g1_altered_termination_value_refuses(tmp_path):
    # G-1: reviewed termination values are pinned; alterations refuse.
    def alter(record):
        _control_by_id(record, "PX-DAEMON-STOP")["expected"]["termination"][
            "unexpected_death"
        ] = True

    path = mutated_policy(tmp_path, alter)
    with pytest.raises(ValueError, match="termination"):
        proxy_policy.load_proxy_policy(path=path)


def test_h2_g1_removed_termination_binding_refuses(tmp_path):
    # G-1: removing a reviewed termination binding refuses.
    def strip(record):
        del _control_by_id(record, "PX-DAEMON-STOP")["expected"]["termination"][
            "stop_succeeded"
        ]

    path = mutated_policy(tmp_path, strip)
    with pytest.raises(ValueError, match="termination"):
        proxy_policy.load_proxy_policy(path=path)


def test_h3_unpinned_px_limit_leaves_tier_unqualified_never_guessed(tmp_path):
    # Design L389-391 (missing observer/harness leaves the tier
    # unqualified, never guessed); Q2: no in-checkout binding exists.
    loaded = proxy_policy.load_proxy_policy()
    assert loaded.tier_qualified is False
    assert any("PX-LIMIT" in gate for gate in loaded.gates)
    limit = next(c for c in loaded.controls if c["id"] == "PX-LIMIT")
    assert limit["expected"]["ck_rv"] is None


def test_h3_guessed_px_limit_value_refuses(tmp_path):
    # A pinned-looking value without a bound source is a guess: refuse.
    def pin(record):
        for control in record["controls"]:
            if control["id"] == "PX-LIMIT":
                control["expected"]["ck_rv"] = {"second_client": "CKR_HOST_MEMORY"}

    path = mutated_policy(tmp_path, pin)
    with pytest.raises(ValueError, match="PX-LIMIT"):
        proxy_policy.load_proxy_policy(path=path)


@pytest.mark.parametrize("binding", [None, "", "   "])
def test_h4_control_without_source_binding_refuses(tmp_path, binding):
    # Design L389-391 (expected fields must be source-bound).
    def strip(record):
        if binding is None:
            del record["controls"][0]["source_binding"]
        else:
            record["controls"][0]["source_binding"] = binding

    path = mutated_policy(tmp_path, strip)
    with pytest.raises(ValueError, match="source_binding"):
        proxy_policy.load_proxy_policy(path=path)


def test_h4_control_without_backend_observer_binding_refuses(tmp_path):
    # Design L389-397 (independent backend-effect oracle binding).
    path = mutated_policy(
        tmp_path, lambda r: r["controls"][1]["expected"].update(backend_effect=None)
    )
    with pytest.raises(ValueError, match="backend_effect"):
        proxy_policy.load_proxy_policy(path=path)


def test_h5_t1_clean_control_is_positive_and_maps_to_proxy_acceptance():
    # Design L405-411 (A/S/T/R/B predicate) + L415 (T1 row).
    verdict = proxy_policy.evaluate_proxy_verdict(
        clean_cells(), clean_controls(), clean_budgets()
    )
    assert verdict == {
        "experiment_positive": True,
        "exit_code": 0,
        "evidence_complete": True,
        "typed_cause": None,
    }
    axes = proxy_policy.proxy_axes_for(clean_cells(), clean_controls(), clean_budgets())
    assert axes == {
        "cells_admitted_complete": True,
        "transport_controls_positive": True,
        "direct_attribution_complete": True,
    }
    from test_results import accepted
    from p11lab.results import validate_result

    record = accepted("proxy")
    record["policy"]["proxy"] = axes
    assert validate_result(record)["policy"]["proxy"] == axes


def test_h5_verdict_input_contract_rejects_malformed_facts():
    cells = clean_cells()
    cells["extra-cell"] = {"admitted": True}
    with pytest.raises(ValueError, match="missing or extra"):
        proxy_policy.evaluate_proxy_verdict(cells, clean_controls(), clean_budgets())
    controls = clean_controls()
    controls["PX-AUTH"]["candidate-proxy"] = "maybe"
    with pytest.raises(ValueError, match="maybe"):
        proxy_policy.evaluate_proxy_verdict(clean_cells(), controls, clean_budgets())


@pytest.mark.parametrize("flaw", ["comparison", "coverage", "candidate-control"])
def test_h6_t2_completed_negative_keeps_complete_evidence(flaw):
    # Design L416 (completed negative; evidence_complete=true).
    cells, controls = clean_cells(), clean_controls()
    if flaw == "comparison":
        cells["comparison"]["positive"] = False
    elif flaw == "coverage":
        cells["comparison"]["coverage_positive"] = False
    else:
        controls["PX-STATE"]["candidate-proxy"] = "fail"
    verdict = proxy_policy.evaluate_proxy_verdict(cells, controls, clean_budgets())
    assert verdict == {
        "experiment_positive": False,
        "exit_code": 1,
        "evidence_complete": True,
        "typed_cause": "completed-negative",
    }


def test_h6_t2_candidate_transport_flaw_flips_proxy_axis_against_acceptance():
    # Q5: the flipped transport axis must fail validate_result's proxy
    # acceptance (results.py proxy axes), hermetically.
    from test_results import accepted
    from p11lab.results import validate_result

    axes = proxy_policy.proxy_axes_for(
        clean_cells(), clean_controls(fail=("PX-REPLAY",)), clean_budgets()
    )
    assert axes["transport_controls_positive"] is False
    record = accepted("proxy")
    record["policy"]["proxy"] = axes
    with pytest.raises(ValueError, match="transport_controls_positive"):
        validate_result(record)


@pytest.mark.parametrize("flaw", ["absent", "incomplete", "unusable"])
def test_h7_t3_direct_gap_is_attribution_unknown(flaw):
    # Design L417 (attribution unknown) + L467 (missing direct evidence
    # means unknown attribution).
    if flaw == "absent":
        cells = clean_cells(
            direct={"admitted": False, "complete": False, "attribution_usable": False}
        )
    elif flaw == "incomplete":
        cells = clean_cells(direct={"complete": False})
    else:
        cells = clean_cells(direct={"attribution_usable": False})
    verdict = proxy_policy.evaluate_proxy_verdict(
        cells, clean_controls(), clean_budgets()
    )
    assert verdict == {
        "experiment_positive": False,
        "exit_code": 1,
        "evidence_complete": False,
        "typed_cause": "attribution-unknown",
    }


def test_h7_t3_beats_completed_negative():
    # Q7 boundary: T3 > T2.
    cells = clean_cells(direct={"attribution_usable": False})
    cells["comparison"]["positive"] = False
    verdict = proxy_policy.evaluate_proxy_verdict(
        cells, clean_controls(fail=("PX-AUTH",)), clean_budgets()
    )
    assert (verdict["exit_code"], verdict["typed_cause"]) == (1, "attribution-unknown")


def test_h7_t3_beats_accepted_control_failure():
    # Q7 boundary: T3 > T4 (direct absence wins over accepted-control failure).
    cells = clean_cells(direct={"attribution_usable": False})
    verdict = proxy_policy.evaluate_proxy_verdict(
        cells, clean_controls(fail_accepted=("PX-STATE",)), clean_budgets()
    )
    assert (verdict["exit_code"], verdict["typed_cause"]) == (1, "attribution-unknown")


@pytest.mark.parametrize("control", ["PX-AUTH", "PX-DAEMON-STOP"])
@pytest.mark.parametrize("candidate", ["pass", "fail"])
def test_h8_t4_accepted_control_failure_is_control_unqualified(control, candidate):
    # Design L399-400 (accepted must meet each contract first;
    # unqualified baseline blocks positive) + L417.
    controls = clean_controls(fail_accepted=(control,))
    if candidate == "fail":
        controls["PX-STATE"]["candidate-proxy"] = "fail"
    verdict = proxy_policy.evaluate_proxy_verdict(
        clean_cells(), controls, clean_budgets()
    )
    assert verdict == {
        "experiment_positive": False,
        "exit_code": 1,
        "evidence_complete": False,
        "typed_cause": "control-unqualified",
    }


@pytest.mark.parametrize(
    "other", ["candidate-differs", "terminal-evidence-lost", "budget-exceeded"]
)
def test_h8_t4_beats_transport_terminal_and_budget_rows(other):
    # Q7 boundaries: T4 > T5/T7/T2 (accepted-unqualified wins over
    # candidate transport failure, lost terminal evidence, budget-negative).
    controls = clean_controls(fail=("PX-AUTH",), fail_accepted=("PX-STATE",))
    cells = clean_cells()
    if other == "terminal-evidence-lost":
        cells["candidate-proxy"]["terminal_evidence_complete"] = False
    budgets = clean_budgets(within=other != "budget-exceeded")
    verdict = proxy_policy.evaluate_proxy_verdict(cells, controls, budgets)
    assert (verdict["exit_code"], verdict["typed_cause"]) == (1, "control-unqualified")


@pytest.mark.parametrize("cell", ["accepted-proxy", "candidate-proxy"])
def test_h9_t5_lost_terminal_evidence_is_incomplete(cell):
    # Design L472-473 (bounded logs + exit/signal retained before removal).
    cells = clean_cells()
    cells[cell]["terminal_evidence_complete"] = False
    verdict = proxy_policy.evaluate_proxy_verdict(
        cells, clean_controls(), clean_budgets()
    )
    assert verdict == {
        "experiment_positive": False,
        "exit_code": 1,
        "evidence_complete": False,
        "typed_cause": "terminal-evidence-unavailable",
    }


@pytest.mark.parametrize("other", ["budget-exceeded", "candidate-differs"])
def test_h9_t5_beats_budget_and_completed_negative(other):
    # Q7 boundaries: T5 > T7/T2.
    cells = clean_cells(candidate_proxy={"terminal_evidence_complete": False})
    controls = clean_controls(fail=("PX-AUTH",) if other == "candidate-differs" else ())
    budgets = clean_budgets(within=other != "budget-exceeded")
    verdict = proxy_policy.evaluate_proxy_verdict(cells, controls, budgets)
    assert (verdict["exit_code"], verdict["typed_cause"]) == (
        1,
        "terminal-evidence-unavailable",
    )


def test_h10_t6_missing_or_cancelled_evidence_is_incomplete():
    # Design L359-360 (absence is incomplete, never a smaller success) +
    # L417 + L421-423 (cancellation without final output is incomplete).
    cases = [
        clean_cells(accepted_proxy={"admitted": False, "complete": False}),
        clean_cells(candidate_proxy={"complete": False}),
        clean_cells(cancelled=True),
        clean_cells(uploads_complete=False),
        clean_cells(
            comparison={
                "performed": False,
                "positive": False,
                "coverage_positive": False,
            }
        ),
    ]
    for cells in cases:
        verdict = proxy_policy.evaluate_proxy_verdict(
            cells, clean_controls(), clean_budgets()
        )
        assert verdict == {
            "experiment_positive": False,
            "exit_code": 1,
            "evidence_complete": False,
            "typed_cause": "missing-evidence",
        }


def test_h10_t6_absent_or_renamed_control_is_incomplete_never_smaller_success():
    # Design L359-360: absence/rename is incomplete, never a smaller
    # successful selection.
    absent = clean_controls()
    del absent["PX-REPLAY"]
    renamed = clean_controls()
    renamed["PX-REPLAY-V2"] = renamed.pop("PX-REPLAY")
    for controls in (absent, renamed):
        verdict = proxy_policy.evaluate_proxy_verdict(
            clean_cells(), controls, clean_budgets()
        )
        assert verdict == {
            "experiment_positive": False,
            "exit_code": 1,
            "evidence_complete": False,
            "typed_cause": "missing-evidence",
        }


def test_h10_t6_beats_attribution_unknown():
    # Q7 boundary: T6 > T3 (a missing proxy cell wins over direct absence).
    cells = clean_cells(
        direct={"admitted": False, "complete": False, "attribution_usable": False},
        candidate_proxy={"admitted": False, "complete": False},
    )
    verdict = proxy_policy.evaluate_proxy_verdict(
        cells, clean_controls(), clean_budgets()
    )
    assert (verdict["exit_code"], verdict["typed_cause"]) == (1, "missing-evidence")


def test_h11_t7_budget_exceeded_is_incomplete_negative():
    # Design L369 (exceeding caps makes within_budget=false) + L418
    # (budget-negative); Q7: evidence outside the qualified envelope.
    verdict = proxy_policy.evaluate_proxy_verdict(
        clean_cells(), clean_controls(), clean_budgets(within=False)
    )
    assert verdict == {
        "experiment_positive": False,
        "exit_code": 1,
        "evidence_complete": False,
        "typed_cause": "budget-exceeded",
    }


def test_h11_t7_beats_completed_negative_and_fails_budget_acceptance():
    # Q7 boundary: T7 > T2. Proxy axes stay true (cells/transport/direct
    # hold) but validate_result must still refuse via within_budget=false.
    from test_results import accepted
    from p11lab.results import validate_result

    verdict = proxy_policy.evaluate_proxy_verdict(
        clean_cells(), clean_controls(fail=("PX-AUTH",)), clean_budgets(within=False)
    )
    assert (verdict["exit_code"], verdict["typed_cause"]) == (1, "budget-exceeded")
    axes = proxy_policy.proxy_axes_for(clean_cells(), clean_controls(), clean_budgets())
    record = accepted("proxy")
    record["policy"]["proxy"] = axes
    record["axes"]["within_budget"] = False
    with pytest.raises(ValueError, match="within_budget"):
        validate_result(record)


def test_h12_t8_usage_or_infrastructure_is_exit_2():
    # Design L419 (usage/infrastructure exit 2 with available diagnostics).
    cells = clean_cells(infrastructure_error="runner unreachable: invented-fixture")
    verdict = proxy_policy.evaluate_proxy_verdict(
        cells, clean_controls(), clean_budgets()
    )
    assert verdict == {
        "experiment_positive": False,
        "exit_code": 2,
        "evidence_complete": False,
        "typed_cause": "usage-or-infrastructure",
    }


@pytest.mark.parametrize("other", ["missing-cell", "completed-negative"])
def test_h12_t8_beats_every_exit_1_row(other):
    # Q7 boundary: T8 > T6 > ... (infrastructure failure wins over all).
    if other == "missing-cell":
        cells = clean_cells(candidate_proxy={"admitted": False, "complete": False})
    else:
        cells = clean_cells()
    cells["infrastructure_error"] = "unreadable inputs: invented-fixture"
    controls = clean_controls(
        fail=("PX-AUTH",) if other == "completed-negative" else ()
    )
    verdict = proxy_policy.evaluate_proxy_verdict(cells, controls, clean_budgets())
    assert (verdict["exit_code"], verdict["typed_cause"]) == (
        2,
        "usage-or-infrastructure",
    )


def test_h13_t9_injected_ck_rv_mismatch_is_detected_via_transport():
    # Design L402-403 (injected mismatch controls are harness mutants and
    # must be detected) + L426-427 (fault mutants demonstrate the
    # predicate). Scripted fake oracle (Q3): the fixture supplies the
    # flipped CK_RV; the verdict sees a candidate transport-contract flaw.
    observation = {
        "control": "PX-STATE",
        "proxy": "candidate-proxy",
        "ck_rv": "0x00000006",
        "expected_ck_rv": "CKR_OK",
        "match": False,
        "backend_objects_found_by_b": 0,
    }
    assert observation["match"] is False
    controls = clean_controls(fail=(observation["control"],))
    verdict = proxy_policy.evaluate_proxy_verdict(
        clean_cells(), controls, clean_budgets()
    )
    assert verdict == {
        "experiment_positive": False,
        "exit_code": 1,
        "evidence_complete": True,
        "typed_cause": "completed-negative",
    }
    axes = proxy_policy.proxy_axes_for(clean_cells(), controls, clean_budgets())
    assert axes == {
        "cells_admitted_complete": True,
        "transport_controls_positive": False,
        "direct_attribution_complete": True,
    }


def test_h14_t10_injected_post_start_crash_is_detected_via_lifecycle_fact():
    # Design L402-403 + L472-474 (distinguish requested shutdown from
    # death after readiness). Scripted observation carries the landed
    # death signal (run.py:876-878); the verdict sees a candidate
    # transport-contract flaw with complete evidence.
    observation = {
        "proxy": "candidate-proxy",
        "unexpected_death": True,
        "lifecycle": "daemon exited after readiness",
        "logs_available": True,
    }
    assert observation["unexpected_death"] is True
    controls = clean_controls(fail=("PX-STATE",))
    verdict = proxy_policy.evaluate_proxy_verdict(
        clean_cells(), controls, clean_budgets()
    )
    assert verdict == {
        "experiment_positive": False,
        "exit_code": 1,
        "evidence_complete": True,
        "typed_cause": "completed-negative",
    }


def test_h15_t11_direct_findings_do_not_veto_a_clean_proxy():
    # Design L410 (direct checker outcomes need not equal proxy outcomes).
    cells = clean_cells(direct={"findings": ["provider-finding:invented-only"]})
    verdict = proxy_policy.evaluate_proxy_verdict(
        cells, clean_controls(), clean_budgets()
    )
    assert verdict == {
        "experiment_positive": True,
        "exit_code": 0,
        "evidence_complete": True,
        "typed_cause": None,
    }


# G-F2 pin: emitted (typed_cause, exit_code) closed set + doc consistency.
# Binding D/G-F2-brief.md: T1 emits None (not "positive") with
# experiment_positive True (proxy_policy.py:537-543); T11 is design-only
# (code comments :486, :539 referencing design L410), not an emitted cause.
# T2-T8 verified exact, unchanged.


def _gf2_inputs(label):
    # Table-driven inputs reaching each of the 8 emitted rows; precedence
    # T8 > T6 > T3 > T4 > T5 > T7 > T2 > T1 (proxy_policy.py:485-486).
    if label == "T1":
        return clean_cells(), clean_controls(), clean_budgets()
    if label == "T2":
        cells = clean_cells(comparison={"positive": False})
        return cells, clean_controls(), clean_budgets()
    if label == "T3":
        cells = clean_cells(direct={"attribution_usable": False})
        return cells, clean_controls(), clean_budgets()
    if label == "T4":
        return clean_cells(), clean_controls(fail_accepted=("PX-AUTH",)), clean_budgets()
    if label == "T5":
        cells = clean_cells(candidate_proxy={"terminal_evidence_complete": False})
        return cells, clean_controls(), clean_budgets()
    if label == "T6":
        cells = clean_cells(cancelled=True)
        return cells, clean_controls(), clean_budgets()
    if label == "T7":
        return clean_cells(), clean_controls(), clean_budgets(within=False)
    if label == "T8":
        cells = clean_cells(infrastructure_error="invented-fixture: unreachable")
        return cells, clean_controls(), clean_budgets()
    raise AssertionError(f"unknown G-F2 label: {label!r}")


_GF2_ROWS = (
    ("T1", None, 0, True),
    ("T2", "completed-negative", 1, False),
    ("T3", "attribution-unknown", 1, False),
    ("T4", "control-unqualified", 1, False),
    ("T5", "terminal-evidence-unavailable", 1, False),
    ("T6", "missing-evidence", 1, False),
    ("T7", "budget-exceeded", 1, False),
    ("T8", "usage-or-infrastructure", 2, False),
)


@pytest.mark.parametrize(("label", "cause", "code", "positive"), _GF2_ROWS)
def test_gf2_emitted_cause_pin(label, cause, code, positive):
    # Each reachable row emits its pinned (typed_cause, exit_code); T1 also
    # pins experiment_positive True (code already emits None pre-change).
    cells, controls, budgets = _gf2_inputs(label)
    verdict = proxy_policy.evaluate_proxy_verdict(cells, controls, budgets)
    assert (verdict["typed_cause"], verdict["exit_code"]) == (cause, code)
    assert verdict["experiment_positive"] is positive


def test_gf2_emitted_cause_set_closed():
    # Closed set by construction: equality with the literal set, not subset.
    # Any new emitted string on these 8 rows fails here.
    emitted = set()
    for label, _cause, _code, _positive in _GF2_ROWS:
        cells, controls, budgets = _gf2_inputs(label)
        verdict = proxy_policy.evaluate_proxy_verdict(cells, controls, budgets)
        emitted.add((verdict["typed_cause"], verdict["exit_code"]))
    assert emitted == {
        (None, 0),
        ("completed-negative", 1),
        ("attribution-unknown", 1),
        ("control-unqualified", 1),
        ("terminal-evidence-unavailable", 1),
        ("missing-evidence", 1),
        ("budget-exceeded", 1),
        ("usage-or-infrastructure", 2),
    }


def _gf2_doc_cells():
    from pathlib import Path

    text = (
        Path(__file__).resolve().parent.parent / "docs" / "round-gating.md"
    ).read_text(encoding="utf-8")
    rows = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("| T"):
            continue
        parts = [part.strip() for part in stripped.split("|")]
        # ["", "T1", "<cause>", "<exit>", ""]
        if len(parts) < 5:
            continue
        rows[parts[1]] = (parts[2], parts[3])
    return text, rows


def test_gf2_doc_table_matches_emitted_set():
    # Doc-consistency: T1 null + experiment_positive, T11 design-only (not
    # emitted), T2-T8 exact, pin sentence enforces the set. RED pre-change
    # (table says "positive"); GREEN after the doc correction.
    import re

    text, rows = _gf2_doc_cells()
    # T1: corrected cause is null with experiment_positive true.
    t1_cause, t1_exit = rows["T1"]
    assert "null" in t1_cause.lower().replace("`", "")
    assert "experiment_positive" in t1_cause
    assert t1_exit.strip() == "0"
    # T11: design-only bounded-diagnostic limit, NOT an emitted cause.
    t11_cause, t11_exit = rows["T11"]
    assert "design-only" in t11_cause.lower()
    assert "not an emitted cause" in t11_cause.lower()
    assert "bounded diagnostic positive" in t11_cause.lower()
    assert "not emitted" in t11_exit.lower()
    # T2-T8: verified exact, unchanged.
    assert rows["T2"][0] == "completed-negative"
    assert rows["T3"][0] == "attribution-unknown"
    assert rows["T4"][0] == "control-unqualified"
    assert rows["T5"][0] == "terminal-evidence-unavailable"
    assert rows["T6"][0] == "missing-evidence"
    assert rows["T7"][0] == "budget-exceeded"
    assert rows["T8"][0] == "usage-or-infrastructure"
    # Pin sentence enforces the set; old "exactly the labels" gone.
    assert "exactly the labels" not in text
    assert "pinned in" in text
    assert "tests/test_proxy_policy.py" in text
    # Parsed T1-T8 doc set equals the emitted literal set.
    doc_emitted = set()
    for label in ("T1", "T2", "T3", "T4", "T5", "T6", "T7", "T8"):
        cause_raw, exit_raw = rows[label]
        if label == "T1":
            cause = None if "null" in cause_raw.lower() else cause_raw.strip()
        else:
            cause = cause_raw
        match = re.search(r"\d+", exit_raw)
        assert match is not None
        doc_emitted.add((cause, int(match.group(0))))
    assert doc_emitted == {
        (None, 0),
        ("completed-negative", 1),
        ("attribution-unknown", 1),
        ("control-unqualified", 1),
        ("terminal-evidence-unavailable", 1),
        ("missing-evidence", 1),
        ("budget-exceeded", 1),
        ("usage-or-infrastructure", 2),
    }
