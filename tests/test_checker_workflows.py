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


def test_lane_selection_is_dynamic_per_run():
    # No static env roster: the select job resolves explicit single env,
    # PR-changed provider dirs, or the full lane; matrices consume it.
    for name in LANES:
        text = _text(name)
        assert "outputs:\n      envs: ${{ steps.resolve.outputs.envs }}" in text, name
        assert "matrix:\n        environment: ${{ fromJSON(needs.select.outputs.envs) }}" in text, name


def test_digest_override_replaces_pin_everywhere():
    # An override must replace the pin in pull verification AND image
    # construction, never just one side.
    direct = _text("checker-direct-validation.yml")
    assert direct.count("P11LAB_DIGEST_OVERRIDE") >= 4
    proxy = _text("checker-proxy-validation.yml")
    assert proxy.count("P11LAB_DIGEST_OVERRIDE") >= 4


def test_advisory_softens_findings_only():
    for name in LANES:
        text = _text(name)
        assert "advisory and not problems" in text, name


def test_select_fails_unknown_explicit_env():
    # A typo'd environment must fail selection, never silently validate
    # nothing (or an empty matrix that poisons the run conclusion).
    import re
    for name in LANES:
        text = _text(name)
        assert re.search(r"is not covered by the (direct|proxy) lane", text), name
        assert "needs.select.outputs.envs != '[]'" not in text, name


def test_delivery_coverage_gates_match_lane_rosters():
    # provider-delivery gates each reusable call on explicit coverage; the
    # lists must equal the lane select rosters exactly.
    import json
    import re
    delivery = (WORKFLOWS / "provider-delivery.yml").read_text()
    lanes = {"validate-direct": "checker-direct-validation.yml",
             "validate-proxy": "checker-proxy-validation.yml"}
    for job, lane in lanes.items():
        gate = re.search(job + r":\n    needs: expose-binary\n    if: contains\(fromJSON\('(\[.*?\])'\), inputs\.environment\)", delivery)
        assert gate, job
        lane_envs = re.search(r'LANE_ENVS="([^"]+)"', _text(lane))
        assert lane_envs, lane
        assert sorted(json.loads(gate.group(1))) == sorted(lane_envs.group(1).split()), (job, lane)


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
