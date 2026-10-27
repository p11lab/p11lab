"""Structural pins for the checker validation workflows.

The shard/merge contract lives partly in workflow YAML (merger.py is inline):
a silent edit there can drop fail-closed behavior that no Python unit test
executes. These tests pin the load-bearing lines in both lanes.
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"

LANES = ("checker-direct-validation.yml", "checker-proxy-validation.yml")


def _text(name):
    return (WORKFLOWS / name).read_text()


def test_attempt_projection_carries_evidence_complete():
    for name in LANES:
        text = _text(name)
        assert "'evidence_complete': " in text, name


def test_merge_requires_evidence_complete():
    for name in LANES:
        text = _text(name)
        assert "if record.get('evidence_complete') is not True:" in text, name


def test_dispatch_inputs_never_interpolate_into_shell():
    # Dispatch inputs reach shell only through step env mappings; direct
    # ${{ inputs.* }} interpolation inside run blocks is an injection sink.
    # Expression contexts (names, artifact names, concurrency, env mappings)
    # are safe and keep their interpolations.
    for name in LANES:
        for line in _text(name).splitlines():
            stripped = line.strip()
            if "${{ inputs.suite }}" in stripped or "${{ inputs.channel }}" in stripped:
                assert stripped.startswith(("P11LAB_INPUT_", "INPUT_")) or \
                    stripped.startswith("name:") or "concurrency" in stripped, (name, stripped)
