"""B-C2y argv regression: sealed compare takes ledger files, coverage keeps dirs.

Hermetic by default: a fake sealed launcher (a tmp_path script recording
argv plus canned JSON verdicts) rooted in a fake SealedToolInputs
exercises the production `_run_sealed_compare` / `_run_sealed_coverage`
adapters directly. RED on pre-fix code (compare passes endpoint
directories); GREEN post-fix. No machine paths: tmp_path plus the
P11LAB_C2X_G7_EVALUATOR_ROOT env gate only.
"""
import json
import os
import stat
import subprocess
from pathlib import Path

import pytest

from test_execute_staged import _stage_bridge

COMPARE_VERDICT: dict[str, object] = {
    "regressions": [], "improvements": [], "unstable": [], "counts": {}}
COVERAGE_VERDICT: dict[str, object] = {
    "has_loss": False, "states_compared": [], "lost_by_state": {}}

_LAUNCHER_SCRIPT = """#!/bin/sh
out="$HOME/argv-$1.txt"
printf '%s\\n' "$@" > "$out"
if [ "$1" = "evidence-compare" ]; then
  printf '%s' 'COMPARE_JSON'
else
  printf '%s' 'COVERAGE_JSON'
fi
"""


def _make_fake_tools(toolroot):
    from p11lab.round_core.inputs import SealedToolInputs

    launcher = toolroot / "evaluator-install/bin/pkcs11-check"
    launcher.parent.mkdir(parents=True)
    script = (_LAUNCHER_SCRIPT
              .replace("COMPARE_JSON", json.dumps(COMPARE_VERDICT))
              .replace("COVERAGE_JSON", json.dumps(COVERAGE_VERDICT)))
    launcher.write_text(script)
    launcher.chmod(launcher.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP
                   | stat.S_IXOTH)
    return SealedToolInputs(toolroot, "a" * 64, (), (), b"", ())


def _make_endpoints(directory):
    baseline = directory / "baseline"
    candidate = directory / "candidate"
    for root in (baseline, candidate):
        root.mkdir(parents=True)
        (root / "ledger.jsonl").write_text("{}\n")
    return baseline, candidate


def _recorded_operands(workdir, command):
    lines = (workdir / ("argv-" + command + ".txt")).read_text().splitlines()
    assert lines[0] == command
    assert lines[3:] == ["--output", "json"]
    return lines[1], lines[2]


def test_run_sealed_compare_passes_ledger_files(tmp_path):
    """Compare argv pins: `<endpoint>/ledger.jsonl` files, not directories."""
    from p11lab.round_core.execute import CompareOutcome, _run_sealed_compare

    tools = _make_fake_tools(tmp_path / "tools")
    baseline, candidate = _make_endpoints(tmp_path)
    workdir = tmp_path / "work"
    workdir.mkdir()
    outcome = _run_sealed_compare(tools, baseline, candidate, {}, workdir)
    assert isinstance(outcome, CompareOutcome)
    assert outcome.positive is True
    first, second = _recorded_operands(workdir, "evidence-compare")
    assert first == str(baseline / "ledger.jsonl")
    assert second == str(candidate / "ledger.jsonl")


def test_run_sealed_coverage_keeps_directories(tmp_path):
    """Coverage argv pins: endpoint directories (proven tool contract)."""
    from p11lab.round_core.execute import CoverageOutcome, _run_sealed_coverage

    tools = _make_fake_tools(tmp_path / "tools")
    baseline, candidate = _make_endpoints(tmp_path)
    workdir = tmp_path / "work"
    workdir.mkdir()
    outcome = _run_sealed_coverage(tools, baseline, candidate, {}, workdir)
    assert isinstance(outcome, CoverageOutcome)
    assert outcome.positive is True
    first, second = _recorded_operands(workdir, "compare-coverage")
    assert first == str(baseline)
    assert second == str(candidate)


@pytest.mark.skipif(os.environ.get("P11LAB_C2X_G7_EVALUATOR_ROOT") is None,
                    reason="C2y live adapter proof needs a retained sealed "
                    "evaluator root")
def test_c2y_live_sealed_compare_adapter_ledger_argv(tmp_path):
    """Env-gated live proof: the real `_run_sealed_compare` reaches the
    rc 0/1 path and parses against staged fixtures. The sealed CLI only
    consumes `tools.root`, so the retained root is bound directly
    (receipt verification stays with the bootstrap suites). Skipped
    without P11LAB_C2X_G7_EVALUATOR_ROOT; the gate stays hermetic."""
    from p11lab.round_core.execute import CompareOutcome, _run_sealed_compare
    from p11lab.round_core.inputs import SealedToolInputs

    root = Path(os.environ["P11LAB_C2X_G7_EVALUATOR_ROOT"]).resolve()
    launcher = root / "evaluator-install/bin/pkcs11-check"
    assert launcher.is_file(), "sealed launcher missing (owning-repo fix)"
    assert not launcher.is_symlink(), "launcher must be a regular file"
    tools = SealedToolInputs(root, "c2y-live-adapter-proof", (), (), b"", ())
    authority, baseline, candidate = _stage_bridge(tmp_path)
    assert authority.is_file()
    workdir = tmp_path / "work"
    workdir.mkdir()
    outcome = _run_sealed_compare(tools, baseline, candidate, {}, workdir)
    assert isinstance(outcome, CompareOutcome)
    assert (workdir / "verdict-compare.json").is_file()
    env = {"PATH": "/usr/bin:/bin", "HOME": str(workdir),
           "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
           "LD_LIBRARY_PATH": str(root / "python/lib"),
           "PYTHONDONTWRITEBYTECODE": "1"}
    observed = subprocess.run(
        [str(launcher), "evidence-compare", str(baseline / "ledger.jsonl"),
         str(candidate / "ledger.jsonl"), "--output", "json"],
        cwd=workdir, env=env, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300,
        check=False)
    print(f"C2y live sealed compare: rc={observed.returncode} "
          f"positive={outcome.positive} counts={outcome.counts}")
    assert observed.returncode in (0, 1), observed.returncode
