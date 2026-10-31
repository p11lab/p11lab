"""Strict proxy transport-control policy loading and truth-table verdict.

Design: L351-360 (policy acceptance), L362-369 (budgets), L371-387 (control
roster), L389-397 (source binding), L399-403 (accepted-first + mutants),
L405-419 (A/S/T/R/B predicate + truth table). Every roster branch and verdict
row cites its design lines. results.py is untouched: proxy_axes_for() maps
verdict inputs onto its proxy axes (cells_admitted_complete,
transport_controls_positive, direct_attribution_complete).
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

from .jsonutil import loads

_decode = cast(Callable[[bytes], Any], loads)

# Strict-helper idiom parallels round_core/policy.py (_object exact keys,
# _same pinned values, _sha/_digest digests, _freeze immutability) without
# importing that module's private helpers: depending on another module's
# underscore API would couple this loader to its internals. jsonutil.loads
# (public) is reused for duplicate-key/nonfinite rejection.
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_TIER = "proxy-diagnostic-v1"
_SCHEMA = "p11lab.proxy-policy.v1"
_CONTROL_IDS = (
    "PX-AUTH",
    "PX-STATE",
    "PX-REPLAY",
    "PX-CLIENT-CRASH",
    "PX-DAEMON-DEATH",
    "PX-DAEMON-STOP",
    "PX-LIMIT",
)
_RUN_ON = ["accepted-proxy", "candidate-proxy"]
# Prep S3: termination is non-null only for these three controls.
_TERMINATION_CONTROLS = frozenset(
    {"PX-CLIENT-CRASH", "PX-DAEMON-DEATH", "PX-DAEMON-STOP"}
)
_PROVIDER = {
    "family": "softhsm2",
    "channel": "release",
    "platform": "linux/amd64",
    "manifest_digest": "sha256:69cdeb9a74d13a3382547e184645ee18a7e9e2315246fd40ca814ef97b970d16",
    "config_digest": "sha256:e59ab297033cedfd8049f76bcf6d9e9c86f8df262be1c80ccbd7c1731437d24f",
}
_BUDGETS = {
    "per_cell_seconds": 300,
    "transport_controls_seconds": 300,
    "acquisition_preflight_seconds": 600,
    "workflow_active_minutes": 30,
    "raw_bytes": 2147483648,
    "diagnostics_bytes": 16777216,
    "retention_days": 14,
}
_FIXED_NULLABLE = ("checker", "consumer", "dataset", "config")
# G-1: per-control pinned nested contracts, transcribed from the reviewed
# shipped policy bytes. _control demands these exactly via _same
# (exact keys AND exact values); unknown keys, altered values, and
# removed bindings all refuse. PX-LIMIT ck_rv stays unbound (null).
_STIMULUS = {
    "PX-AUTH": {
        "valid_client": "one mTLS handshake + enumerate",
        "invalid_client": (
            "untrusted-cert handshake from"
            " tests/fixtures/proxy-tls/untrusted-client.pem,"
            " rejected pre-provider-op"
        ),
    },
    "PX-STATE": {
        "instance_a": "create uniquely identified token object in instance A",
        "instance_b": (
            "explicit cross-instance lookup: search instance B LIVE while A runs (Q1)"
        ),
    },
    "PX-REPLAY": {
        "request": "one non-idempotent create with unique CKA_ID",
        "fault": (
            "transport fault loses the response after backend effect ack"
            " (test connection only)"
        ),
    },
    "PX-CLIENT-CRASH": {
        "crash": "terminate one active client process",
        "finalizer": "without checker exit finalizer (hooks omitted)",
    },
    "PX-DAEMON-DEATH": {
        "death": "terminate dedicated ready daemon",
        "client": "while its control client remains",
    },
    "PX-DAEMON-STOP": {"stop": "normal requested shutdown of dedicated ready daemon"},
    "PX-LIMIT": {
        "second_client": (
            "attempt second simultaneous client/context against the selected"
            " single-client version (a348a5f)"
        )
    },
}
_CK_RV = {
    "PX-AUTH": {
        "valid_enumerate": "CKR_OK",
        "invalid_reject_point": "before-provider-operation",
    },
    "PX-STATE": {
        "creation_ck_rv": "preserved-verbatim",
        "search_ck_rv": "preserved-verbatim",
    },
    "PX-REPLAY": {"client_records": "transport-failure", "silent_success": False},
    "PX-CLIENT-CRASH": {"client_crash": "recorded", "reconnect_claim": "none"},
    "PX-DAEMON-DEATH": {"client_observes": "transport-failure"},
    "PX-DAEMON-STOP": {"stop": "recorded-clean"},
}
_BACKEND_EFFECT = {
    "PX-AUTH": {"call_counter_delta_by_invalid": 0},
    "PX-STATE": {"objects_found_by_a": 1, "objects_found_by_b": 0},
    "PX-REPLAY": {
        "backend_operation_count": 1,
        "post_shutdown_enumerated_objects": 1,
    },
    "PX-CLIENT-CRASH": {
        "owned_process_closed": True,
        "provider_cleanup_observed": True,
    },
    "PX-DAEMON-DEATH": {"client_transport_failure_observed": True},
    "PX-DAEMON-STOP": {"stop_requested": True},
    "PX-LIMIT": {"first_context_unaffected": True},
}
_TERMINATION = {
    "PX-CLIENT-CRASH": {
        "client": "terminated-no-finalizer",
        "daemon": "terminal-facts-required",
    },
    "PX-DAEMON-DEATH": {"unexpected_death": True, "logs_available": True},
    "PX-DAEMON-STOP": {"unexpected_death": False, "stop_succeeded": True},
}


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _object(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    _require(type(value) is dict, f"{label}: expected an object")
    _require(
        set(value) == keys,
        f"{label}: missing or extra fields (expected {sorted(keys)})",
    )
    return dict(value)


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def _same(value: Any, expected: Any, label: str) -> None:
    # JSON equality distinguishes booleans from integers unlike Python ==.
    _require(
        _canonical(value) == _canonical(expected),
        f"{label}: unsupported protected contract",
    )


def _text(value: Any, label: str) -> None:
    _require(
        isinstance(value, str) and bool(value.strip()),
        f"{label}: nonempty identity/reason required",
    )


def _digest(value: Any, label: str) -> None:
    _require(
        isinstance(value, str)
        and value.startswith("sha256:")
        and _HEX64.fullmatch(value.removeprefix("sha256:")) is not None,
        f"{label}: expected sha256:<64 hex>",
    )


def _hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


@dataclass(frozen=True)
class LoadedProxyPolicy:
    """Frozen proxy diagnostic policy; never a qualification receipt.

    tier_qualified is False while any gate holds (this slice: the PX-LIMIT
    rejection value is unbound, and budgets are unqualified targets).
    Null fixed_inputs (checker/consumer/dataset/config with a named
    follow-up) do NOT unqualify the hermetic verdict, which consumes
    cells/controls/budgets only.
    """

    tier: str
    activation_state: str
    tier_qualified: bool
    gates: tuple[str, ...]
    policy_digest: str
    provider: Mapping[str, Any]
    fixed_inputs: Mapping[str, Any]
    fixed_input_follow_ups: Mapping[str, Any]
    cells: tuple[str, ...]
    attempts_per_cell: int
    comparison: Mapping[str, Any]
    controls: tuple[Mapping[str, Any], ...]
    budgets: Mapping[str, Any]


def _control(value: Any) -> dict[str, Any]:
    control = _object(
        value,
        {
            "id",
            "design_ref",
            "run_on",
            "stimulus",
            "expected",
            "source_binding",
            "budget_seconds",
        },
        "control",
    )
    _require(control["id"] in _CONTROL_IDS, f"unknown control: {control['id']!r}")
    _text(control["design_ref"], control["id"] + ".design_ref")
    _same(control["run_on"], _RUN_ON, control["id"] + ".run_on")
    # G-1: each control's nested contract is pinned exactly (keys AND
    # reviewed values); the shipped policy bytes define the contract.
    _same(control["stimulus"], _STIMULUS[control["id"]], control["id"] + ".stimulus")
    expected = _object(
        control["expected"],
        {"ck_rv", "backend_effect", "termination"},
        control["id"] + ".expected",
    )
    _same(
        expected["backend_effect"],
        _BACKEND_EFFECT[control["id"]],
        control["id"] + ".expected.backend_effect",
    )
    termination = expected["termination"]
    if control["id"] in _TERMINATION_CONTROLS:
        _same(
            termination,
            _TERMINATION[control["id"]],
            control["id"] + ".expected.termination",
        )
    else:
        _require(
            termination is None, control["id"] + ".expected.termination: must be null"
        )
    ck_rv = expected["ck_rv"]
    if control["id"] == "PX-LIMIT":
        # Design L389-391 + Q2: no in-checkout binding exists for the
        # second-client rejection value; any pinned-looking value here is
        # a guess and refuses. The tier stays unqualified (H3).
        _require(
            ck_rv is None,
            "PX-LIMIT ck_rv: refusing guessed rejection value; no in-checkout binding exists",
        )
    else:
        _same(ck_rv, _CK_RV[control["id"]], control["id"] + ".expected.ck_rv")
    _text(control["source_binding"], control["id"] + ".source_binding")
    _same(control["budget_seconds"], 300, control["id"] + ".budget_seconds")
    return control


def load_proxy_policy(tier: str = _TIER, path: Path | None = None) -> LoadedProxyPolicy:
    """Validate the exact proxy-policy contract and return it frozen.

    ``None`` loads the installed package resource. ``path`` loads an
    authored copy (tests). Unknown tiers and checker tier names reject
    (design L353); unknown controls or fields reject (design L359-360).
    The tier stays unqualified while PX-LIMIT is unbound (design
    L389-391) and budgets are unqualified targets (design L362-369).
    """
    _require(tier == _TIER, f"unknown tier: {tier!r} (only {_TIER} is accepted)")
    raw = (
        Path(path).read_bytes()
        if path is not None
        else files("p11lab").joinpath("data/ci/proxy-policy.json").read_bytes()
    )
    top = _object(
        _decode(raw),
        {
            "schema",
            "schema_version",
            "id",
            "activation_state",
            "commission",
            "budgets_qualified",
            "provider",
            "fixed_inputs",
            "fixed_input_follow_ups",
            "cells",
            "attempts_per_cell",
            "no_retry_after_start",
            "comparison",
            "controls",
            "budgets",
        },
        "proxy-policy",
    )
    _same(top["schema"], _SCHEMA, "proxy-policy.schema")
    _same(top["schema_version"], 1, "proxy-policy.schema_version")
    _same(top["id"], _TIER, "proxy-policy.id")
    _same(top["activation_state"], "diagnostic", "proxy-policy.activation_state")
    _same(top["commission"], "linux-amd64", "proxy-policy.commission")
    _same(top["budgets_qualified"], False, "proxy-policy.budgets_qualified")
    provider = _object(top["provider"], set(_PROVIDER), "proxy-policy.provider")
    for key, expected in _PROVIDER.items():
        if key.endswith("_digest"):
            _digest(provider[key], "proxy-policy.provider." + key)
        _same(provider[key], expected, "proxy-policy.provider." + key)
    fixed = _object(
        top["fixed_inputs"],
        {"checker", "profile", "nodes", "destructive", "consumer", "dataset", "config"},
        "proxy-policy.fixed_inputs",
    )
    _same(fixed["profile"], "round-pr-smoke-v1", "proxy-policy.fixed_inputs.profile")
    _same(fixed["nodes"], 23, "proxy-policy.fixed_inputs.nodes")
    _same(fixed["destructive"], False, "proxy-policy.fixed_inputs.destructive")
    for key in _FIXED_NULLABLE:
        if fixed[key] is not None:
            _text(fixed[key], "proxy-policy.fixed_inputs." + key)
    follow_ups = top["fixed_input_follow_ups"]
    _require(
        type(follow_ups) is dict,
        "proxy-policy.fixed_input_follow_ups: expected an object",
    )
    nulled = {key for key in _FIXED_NULLABLE if fixed[key] is None}
    _require(
        set(follow_ups) == nulled,
        "proxy-policy.fixed_input_follow_ups: must name exactly the null fixed_inputs",
    )
    for key, item in follow_ups.items():
        _text(item, "proxy-policy.fixed_input_follow_ups." + key)
    _same(
        top["cells"],
        ["direct", "accepted-proxy", "candidate-proxy"],
        "proxy-policy.cells",
    )
    _same(top["attempts_per_cell"], 1, "proxy-policy.attempts_per_cell")
    _same(top["no_retry_after_start"], True, "proxy-policy.no_retry_after_start")
    comparison = _object(
        top["comparison"],
        {"baseline", "candidate", "direct_role"},
        "proxy-policy.comparison",
    )
    _same(comparison["baseline"], "accepted-proxy", "proxy-policy.comparison.baseline")
    _same(
        comparison["candidate"], "candidate-proxy", "proxy-policy.comparison.candidate"
    )
    _same(
        comparison["direct_role"],
        "attribution-only",
        "proxy-policy.comparison.direct_role",
    )
    _require(type(top["controls"]) is list, "proxy-policy.controls: expected an array")
    controls = [_control(value) for value in top["controls"]]
    seen = [control["id"] for control in controls]
    _require(len(seen) == len(set(seen)), "proxy-policy.controls: duplicate control id")
    _require(
        set(seen) == set(_CONTROL_IDS),
        f"proxy-policy.controls: roster must be exactly {list(_CONTROL_IDS)}",
    )
    budgets = _object(top["budgets"], set(_BUDGETS), "proxy-policy.budgets")
    for key, expected_budget in _BUDGETS.items():
        _same(budgets[key], expected_budget, "proxy-policy.budgets." + key)
    gates = (
        "PX-LIMIT pinned rejection unbound: tier unqualified; live-slice follow-up required.",
        "Budgets are unqualified targets (budgets_qualified=false); no consumer may treat them as envelopes.",
    )
    return LoadedProxyPolicy(
        _TIER,
        "diagnostic",
        False,
        gates,
        _hash(raw),
        _freeze(provider),
        _freeze(fixed),
        _freeze(dict(follow_ups)),
        ("direct", "accepted-proxy", "candidate-proxy"),
        1,
        _freeze(comparison),
        _freeze(controls),
        _freeze(budgets),
    )


def _flag(value: Any, label: str) -> bool:
    _require(type(value) is bool, f"{label}: expected a boolean")
    return value


def _checked_inputs(cells: Any, controls: Any, budgets: Any) -> tuple[dict, dict, dict]:
    """Strict-check verdict inputs; roster mismatch is NOT an error here.

    Cells/budgets are this function's own contract (violations raise).
    The control roster is external reality: a missing or renamed control
    is incomplete evidence (design L359-360), decided by the caller of
    this helper, never an exception.
    """
    checked = _object(
        cells,
        {
            "direct",
            "accepted-proxy",
            "candidate-proxy",
            "comparison",
            "cancelled",
            "uploads_complete",
            "infrastructure_error",
        },
        "cells",
    )
    direct = _object(
        checked["direct"],
        {"admitted", "complete", "attribution_usable", "findings"},
        "cells.direct",
    )
    for key in ("admitted", "complete", "attribution_usable"):
        _flag(direct[key], "cells.direct." + key)
    _require(
        type(direct["findings"]) is list, "cells.direct.findings: expected an array"
    )
    for name in ("accepted-proxy", "candidate-proxy"):
        cell = _object(
            checked[name],
            {"admitted", "complete", "terminal_evidence_complete"},
            "cells." + name,
        )
        for key in ("admitted", "complete", "terminal_evidence_complete"):
            _flag(cell[key], f"cells.{name}.{key}")
    comparison = _object(
        checked["comparison"],
        {"performed", "positive", "coverage_positive"},
        "cells.comparison",
    )
    for key in ("performed", "positive", "coverage_positive"):
        _flag(comparison[key], "cells.comparison." + key)
    _flag(checked["cancelled"], "cells.cancelled")
    _flag(checked["uploads_complete"], "cells.uploads_complete")
    infra = checked["infrastructure_error"]
    _require(
        infra is None or (isinstance(infra, str) and bool(infra.strip())),
        "cells.infrastructure_error: expected null or a nonempty detail",
    )
    _require(type(controls) is dict, "controls: expected an object")
    for control_id, outcomes in controls.items():
        pair = _object(
            outcomes, {"accepted-proxy", "candidate-proxy"}, f"controls.{control_id}"
        )
        for proxy, outcome in pair.items():
            _require(
                outcome in ("pass", "fail"),
                f"controls.{control_id}.{proxy}: expected pass or fail, got {outcome!r}",
            )
    checked_budgets = _object(budgets, {"within_budget"}, "budgets")
    _flag(checked_budgets["within_budget"], "budgets.within_budget")
    return checked, dict(controls), checked_budgets


def evaluate_proxy_verdict(cells: Any, controls: Any, budgets: Any) -> dict[str, Any]:
    """Pure truth-table verdict over observed facts (design L405-419).

    Typed-cause precedence (Q7): T8(exit 2) > T6 > T3 > T4 > T5 > T7
    (exit 1, evidence_complete=false) > T2 (exit 1, evidence_complete=true)
    > T1/T11 (exit 0). Direct-cell absence is T3 (attribution-unknown);
    missing accepted/candidate evidence is T6 (missing-evidence).
    """
    checked, observed, checked_budgets = _checked_inputs(cells, controls, budgets)
    failed = {"experiment_positive": False, "exit_code": 1, "evidence_complete": False}
    if checked["infrastructure_error"] is not None:  # T8: design L419.
        return {**failed, "exit_code": 2, "typed_cause": "usage-or-infrastructure"}
    roster_complete = set(observed) == set(_CONTROL_IDS)  # Design L359-360.
    proxy_complete = all(
        checked[name]["admitted"] and checked[name]["complete"]
        for name in ("accepted-proxy", "candidate-proxy")
    )
    if (
        not roster_complete
        or not proxy_complete
        or checked["cancelled"]
        or not checked["uploads_complete"]
        or not checked["comparison"]["performed"]
    ):  # T6: design L417, L421-423.
        return {**failed, "typed_cause": "missing-evidence"}
    direct = checked["direct"]
    if not (
        direct["admitted"] and direct["complete"] and direct["attribution_usable"]
    ):  # T3: design L417, L467.
        return {**failed, "typed_cause": "attribution-unknown"}
    if any(
        observed[control]["accepted-proxy"] == "fail" for control in _CONTROL_IDS
    ):  # T4: design L399-400, L417.
        return {**failed, "typed_cause": "control-unqualified"}
    if any(
        not checked[name]["terminal_evidence_complete"]
        for name in ("accepted-proxy", "candidate-proxy")
    ):  # T5: design L472-473.
        return {**failed, "typed_cause": "terminal-evidence-unavailable"}
    if not checked_budgets["within_budget"]:  # T7: design L369, L418.
        return {**failed, "typed_cause": "budget-exceeded"}
    comparison = checked["comparison"]
    if (
        not comparison["positive"]
        or not comparison["coverage_positive"]
        or any(
            observed[control]["candidate-proxy"] == "fail" for control in _CONTROL_IDS
        )
    ):  # T2: design L416.
        return {
            "experiment_positive": False,
            "exit_code": 1,
            "evidence_complete": True,
            "typed_cause": "completed-negative",
        }
    return {
        "experiment_positive": True,
        "exit_code": 0,  # T1: L415; T11: L410.
        "evidence_complete": True,
        "typed_cause": None,
    }


def proxy_axes_for(cells: Any, controls: Any, budgets: Any) -> dict[str, bool]:
    """Map verdict inputs onto results.py proxy acceptance axes (Q5).

    cells_admitted_complete = A (all three cells admitted/complete);
    transport_controls_positive = T (roster exact, every control meets its
    contract on both proxies, terminal evidence retained);
    direct_attribution_complete = R (direct usable/complete). Budget (B)
    maps onto results.py within_budget, not onto these axes.
    """
    checked, observed, _ = _checked_inputs(cells, controls, budgets)
    admitted = all(
        checked[name]["admitted"] and checked[name]["complete"]
        for name in ("direct", "accepted-proxy", "candidate-proxy")
    )
    transport = (
        set(observed) == set(_CONTROL_IDS)
        and all(
            outcome == "pass"
            for control in _CONTROL_IDS
            for outcome in (
                observed[control]["accepted-proxy"],
                observed[control]["candidate-proxy"],
            )
        )
        and all(
            checked[name]["terminal_evidence_complete"]
            for name in ("accepted-proxy", "candidate-proxy")
        )
    )
    direct = checked["direct"]
    return {
        "cells_admitted_complete": admitted,
        "transport_controls_positive": transport,
        "direct_attribution_complete": bool(
            direct["admitted"] and direct["complete"] and direct["attribution_usable"]
        ),
    }
