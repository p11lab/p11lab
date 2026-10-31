"""Typed `round execute` causes, shared without engine dependencies.

`execute.py` imports Docker-capable worker code; workflow contracts and tests
import this module instead to read the closed cause/status/exit mapping.
"""
from __future__ import annotations

from enum import Enum


class ExecuteCause(str, Enum):
    """Closed `EXECUTE_*` cause set for one round lane execution."""

    EXECUTE_OK = "EXECUTE_OK"
    EXECUTE_TRANSPORT_REFUSED = "EXECUTE_TRANSPORT_REFUSED"
    EXECUTE_PRODUCE_INPUTS_MISSING = "EXECUTE_PRODUCE_INPUTS_MISSING"
    EXECUTE_PRODUCER_FAILED = "EXECUTE_PRODUCER_FAILED"
    EXECUTE_EVALUATOR_REFUSED = "EXECUTE_EVALUATOR_REFUSED"
    EXECUTE_EVALUATOR_FAILED = "EXECUTE_EVALUATOR_FAILED"
    EXECUTE_BIND_INPUTS_MISSING = "EXECUTE_BIND_INPUTS_MISSING"
    EXECUTE_BIND_REFUSED = "EXECUTE_BIND_REFUSED"
    EXECUTE_BIND_FAILED = "EXECUTE_BIND_FAILED"
    EXECUTE_ENDPOINT_DRIFT = "EXECUTE_ENDPOINT_DRIFT"
    EXECUTE_COMPARE_FAILED = "EXECUTE_COMPARE_FAILED"
    EXECUTE_MISSING_SELECTED = "EXECUTE_MISSING_SELECTED"
    EXECUTE_COVERAGE_FAILED = "EXECUTE_COVERAGE_FAILED"
    EXECUTE_PROVIDER_FAILED = "EXECUTE_PROVIDER_FAILED"


CAUSE_STATUS: dict[ExecuteCause, str] = {
    ExecuteCause.EXECUTE_OK: "executed",
    ExecuteCause.EXECUTE_TRANSPORT_REFUSED: "refused",
    ExecuteCause.EXECUTE_PRODUCE_INPUTS_MISSING: "refused",
    ExecuteCause.EXECUTE_PRODUCER_FAILED: "infrastructure-error",
    ExecuteCause.EXECUTE_EVALUATOR_REFUSED: "refused",
    ExecuteCause.EXECUTE_EVALUATOR_FAILED: "infrastructure-error",
    ExecuteCause.EXECUTE_BIND_INPUTS_MISSING: "refused",
    ExecuteCause.EXECUTE_BIND_REFUSED: "refused",
    ExecuteCause.EXECUTE_BIND_FAILED: "infrastructure-error",
    ExecuteCause.EXECUTE_ENDPOINT_DRIFT: "infrastructure-error",
    ExecuteCause.EXECUTE_COMPARE_FAILED: "infrastructure-error",
    ExecuteCause.EXECUTE_MISSING_SELECTED: "refused",
    ExecuteCause.EXECUTE_COVERAGE_FAILED: "infrastructure-error",
    ExecuteCause.EXECUTE_PROVIDER_FAILED: "provider-failure",
}

CAUSE_EXIT: dict[ExecuteCause, int] = {
    ExecuteCause.EXECUTE_OK: 0,
    ExecuteCause.EXECUTE_TRANSPORT_REFUSED: 3,
    ExecuteCause.EXECUTE_PRODUCE_INPUTS_MISSING: 3,
    ExecuteCause.EXECUTE_PRODUCER_FAILED: 3,
    ExecuteCause.EXECUTE_EVALUATOR_REFUSED: 3,
    ExecuteCause.EXECUTE_EVALUATOR_FAILED: 3,
    ExecuteCause.EXECUTE_BIND_INPUTS_MISSING: 3,
    ExecuteCause.EXECUTE_BIND_REFUSED: 3,
    ExecuteCause.EXECUTE_BIND_FAILED: 3,
    ExecuteCause.EXECUTE_ENDPOINT_DRIFT: 3,
    ExecuteCause.EXECUTE_COMPARE_FAILED: 3,
    ExecuteCause.EXECUTE_MISSING_SELECTED: 3,
    ExecuteCause.EXECUTE_COVERAGE_FAILED: 3,
    ExecuteCause.EXECUTE_PROVIDER_FAILED: 0,
}
