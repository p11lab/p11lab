"""Structural pins for the M08 provider-image-validation workflow.

The rebuild/retest orchestration contract lives in workflow YAML with
inline `python - <<'PY'` loaders (Q1): a silent edit there can drop
fail-closed behavior that no Python unit test executes. These tests pin
the load-bearing lines, following the `test_checker_workflows.py`
structural-pin idiom. Families W1-W7 follow
M08-validation-preparation/report.md section 3 as adapted by
D/M08-validation-brief.md (deltas ruled there, not verbatim).

Fix-1 shape (D/M08-validation-fix-1-findings.md): no fabricated
digest/receipt/claim (G-1: guard dominates every emission, pending
identities refused downstream); real `image_ci`/runtime-identity key
derivation (G-2); lane-call read permissions (G-3); executable
mutations (G-4); exact `match=` on every `raises` with substitute-first
order (G-5); exact-line scanners rejecting unrecognized syntax (G-6);
exact 64-hex first digest guard (G-7).

Hermetic: the only file read is the workflow itself, resolved inside
this checkout (ROOT). No network, no registry, no invented concrete
values: mutation negatives use obvious constructed constants.
"""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github/workflows/provider-image-validation.yml"

INPUT_ROSTER = {"environment", "channel", "digest", "suite", "p11lab_ref"}
JOB_ROSTER = ["select", "build", "validate-local", "validate-direct", "validate-proxy", "aggregate"]
SELECT_OUTPUTS = {"mode", "provider_build_key", "experiment_key", "plan_digest",
                  "artifact_digest", "artifact_reference", "policy_sha256"}
STANZA_KEYS = {"description", "required", "type", "default"}


def _match(message):
    # Prefix-anchored: pytest appends its own introspection after a custom
    # assert message, so the full intended message must match from the start
    # while trailing rewrite output is tolerated.
    return "^" + re.escape(message)


def _text():
    return WORKFLOW.read_text()


def _mutate(text, match, replacement):
    assert match in text, "mutation anchor absent: %r" % match[:80]
    return text.replace(match, replacement, 1)


def _on_section(text):
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if line == "on:")
    end = next((i for i in range(start + 1, len(lines)) if re.match(r"^[A-Za-z]+:", lines[i])), len(lines))
    section = lines[start:end]
    for line in section[1:]:
        if not line.strip() or line.strip().startswith("#"):
            continue
        if re.match(r"^  ([A-Za-z_]+):\s*$", line):
            continue
        if line.startswith("    "):
            continue
        raise AssertionError("unrecognized trigger syntax: %r" % line.strip())
    return section


def _trigger_inputs(text, trigger):
    section = _on_section(text)
    names = []
    stanzas = {}
    current = None
    in_trigger = False
    in_inputs = False
    for line in section:
        if not line.strip() or line.strip().startswith("#"):
            continue
        top = re.match(r"^  (\w+):\s*$", line)
        if top:
            in_trigger = (top.group(1) == trigger)
            in_inputs = False
            current = None
            continue
        if not in_trigger:
            continue
        if re.match(r"^    \S", line) and not line.startswith("      "):
            if line != "    inputs:":
                raise AssertionError("unrecognized %s stanza: %r" % (trigger, line.strip()))
            in_inputs = True
            current = None
            continue
        if not in_inputs:
            continue
        named = re.match(r"^      (\w+):\s*$", line)
        if named:
            current = named.group(1)
            names.append(current)
            stanzas[current] = []
            continue
        if line.startswith("      ") and not line.startswith("        "):
            raise AssertionError("unrecognized input syntax: %r" % line.strip())
        if current is not None and line.startswith("        "):
            key = line.strip().split(":", 1)[0]
            if key not in STANZA_KEYS:
                raise AssertionError("unrecognized input key: %r" % line.strip())
            stanzas[current].append(line)
            continue
        raise AssertionError("unrecognized input syntax: %r" % line.strip())
    return names, stanzas


def _jobs(text):
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if line == "jobs:")
    return [re.match(r"^  ([\w-]+):\s*$", line).group(1)
            for line in lines[start:] if re.match(r"^  ([\w-]+):\s*$", line)]


def _job_slice(text, job):
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if re.match(r"^  %s:\s*$" % job, line))
    end = next((i for i in range(start + 1, len(lines)) if re.match(r"^  [\w-]+:\s*$", lines[i])), len(lines))
    return lines[start:end]


def _needs(text, job):
    found = []
    in_needs = False
    for line in _job_slice(text, job):
        if re.match(r"^    needs:\s*$", line):
            in_needs = True
        elif in_needs:
            match = re.match(r"^      - ([\w-]+)\s*$", line)
            if match:
                found.append(match.group(1))
            else:
                break
    return found


def _run_spans(text):
    lines = text.splitlines()
    spans = []
    for index, line in enumerate(lines):
        match = re.match(r"^(\s*)run: \|\s*$", line)
        if not match:
            continue
        base = len(match.group(1))
        end = index + 1
        while end < len(lines) and (not lines[end].strip() or len(lines[end]) - len(lines[end].lstrip()) > base):
            end += 1
        spans.append((index, end))
    return spans


def _run_lines(text):
    lines = text.splitlines()
    out = []
    for start, end in _run_spans(text):
        out.extend(lines[start + 1:end])
    return out


# W1 focused assertions: reusable + dispatch only, never direct-push.
def _assert_w1_triggers(text):
    triggers = [re.match(r"^  ([A-Za-z_]+):", line).group(1)
                for line in _on_section(text) if re.match(r"^  ([A-Za-z_]+):", line)]
    assert triggers == ["workflow_call", "workflow_dispatch"], \
        "triggers must be reusable-call plus manual-dispatch only"


def test_w1_triggers_reusable_and_dispatch_only():
    _assert_w1_triggers(_text())


def test_w1_mutation_pr_trigger_rejected():
    bad = _mutate(_text(), "  workflow_dispatch:\n", "  workflow_dispatch:\n  pull_request:\n")
    with pytest.raises(AssertionError, match=_match("triggers must be reusable-call plus manual-dispatch only")):
        _assert_w1_triggers(bad)


def test_w1_mutation_dispatch_removed_rejected():
    bad = _mutate(_text(), "  workflow_dispatch:\n", "  schedule:\n")
    with pytest.raises(AssertionError, match=_match("triggers must be reusable-call plus manual-dispatch only")):
        _assert_w1_triggers(bad)


def test_w1_mutation_quoted_trigger_rejected():
    bad = _mutate(_text(), "  workflow_dispatch:\n", "  workflow_dispatch:\n  \"push\":\n")
    with pytest.raises(AssertionError, match=_match("unrecognized trigger syntax: '\"push\":'")):
        _assert_w1_triggers(bad)


# W2 focused assertions: the 5-input roster, closed, with required
# control ref and no tool-override interpolation.
def _assert_w2_call_roster(text):
    names, _ = _trigger_inputs(text, "workflow_call")
    assert set(names) == INPUT_ROSTER, "workflow_call inputs must be the closed 5-input roster"


def _assert_w2_dispatch_roster(text):
    names, _ = _trigger_inputs(text, "workflow_dispatch")
    assert set(names) == INPUT_ROSTER, "workflow_dispatch inputs must be the closed 5-input roster"


def _assert_w2_ref_required(text):
    for trigger in ("workflow_call", "workflow_dispatch"):
        _, stanzas = _trigger_inputs(text, trigger)
        assert "p11lab_ref" in stanzas, "p11lab_ref input missing: " + trigger
        assert any(line.strip() == "required: true" for line in stanzas["p11lab_ref"]), \
            "p11lab_ref must be required: " + trigger


def _assert_w2_dispatch_defaults(text):
    _, stanzas = _trigger_inputs(text, "workflow_dispatch")
    assert any("default: 'softhsm2'" in line for line in stanzas["environment"]), \
        "dispatch environment default must be softhsm2"
    assert any("default: 'release'" in line for line in stanzas["channel"]), \
        "dispatch channel default must be release"
    assert any("default: ''" in line for line in stanzas["digest"]), \
        "dispatch digest default must be empty"
    assert any("default: 'smoke'" in line for line in stanzas["suite"]), \
        "dispatch suite default must be smoke"


def _assert_w2_no_tool_override(text):
    assert re.search(r"inputs\.(framework_sha|proxy_sha|tool\w*|checker\w*|tier\w*)\b", text) is None, \
        "tool-override interpolation is forbidden"


def test_w2_call_inputs_closed_roster():
    _assert_w2_call_roster(_text())


def test_w2_dispatch_inputs_closed_roster():
    _assert_w2_dispatch_roster(_text())


def test_w2_p11lab_ref_required_both():
    _assert_w2_ref_required(_text())


def test_w2_dispatch_defaults():
    _assert_w2_dispatch_defaults(_text())


def test_w2_no_tool_override_interpolation():
    _assert_w2_no_tool_override(_text())


def test_w2_mutation_added_tier_input_rejected():
    anchor = "    inputs:\n      environment:"
    bad = _mutate(_text(), anchor, "    inputs:\n      tier:\n        description: 'Candidate tier override.'\n        required: false\n        type: string\n      environment:")
    with pytest.raises(AssertionError, match=_match("workflow_call inputs must be the closed 5-input roster")):
        _assert_w2_call_roster(bad)


def test_w2_mutation_ref_required_dropped_rejected():
    anchor = ("      p11lab_ref:\n"
              "        description: 'Pinned 40-hex control commit for reusable calls.'\n"
              "        required: true")
    bad = _mutate(_text(), anchor, anchor.replace("required: true", "required: false"))
    with pytest.raises(AssertionError, match=_match("p11lab_ref must be required: workflow_call")):
        _assert_w2_ref_required(bad)


def test_w2_mutation_tool_interpolation_rejected():
    bad = _mutate(_text(), "P11LAB_INPUT_REF: ${{ inputs.p11lab_ref }}",
                  "P11LAB_INPUT_REF: ${{ inputs.p11lab_ref }}-${{ inputs.tool }}")
    with pytest.raises(AssertionError, match=_match("tool-override interpolation is forbidden")):
        _assert_w2_no_tool_override(bad)


def test_w2_mutation_unknown_stanza_key_rejected():
    anchor = "      suite:\n        description: 'smoke or full.'\n        required: false\n        type: string\n"
    bad = _mutate(_text(), anchor, anchor + "        options: ['smoke']\n")
    with pytest.raises(AssertionError, match=_match("unrecognized input key: \"options: ['smoke']\"")):
        _assert_w2_call_roster(bad)


def test_w2_mutation_trigger_secrets_rejected():
    anchor = "  workflow_call:\n    inputs:\n"
    bad = _mutate(_text(), anchor, anchor + "    secrets:\n")
    with pytest.raises(AssertionError, match=_match("unrecognized workflow_call stanza: 'secrets:'")):
        _assert_w2_call_roster(bad)


# W3 focused assertions: inputs reach shell only through env mappings.
def _assert_w3_no_expression_in_run(text):
    spans = _run_spans(text)
    assert spans, "no run blocks found"
    for line in _run_lines(text):
        assert "${{" not in line, "run block interpolates inputs: " + line.strip()


def _assert_w3_env_anchors(text):
    assert "P11LAB_INPUT_ENVIRONMENT" in text, "P11LAB_INPUT_ENVIRONMENT must be mapped"
    assert "P11LAB_INPUT_REF" in text, "P11LAB_INPUT_REF must be mapped"
    assert "ref: ${{ inputs.p11lab_ref }}" in text, "control checkout must pin p11lab_ref"


def test_w3_no_expression_in_run_blocks():
    _assert_w3_no_expression_in_run(_text())


def test_w3_env_mapping_anchors():
    _assert_w3_env_anchors(_text())


def test_w3_mutation_input_in_run_rejected():
    anchor = 'test "$P11LAB_INPUT_ENVIRONMENT" = softhsm2'
    bad = _mutate(_text(), anchor, 'test "${{ inputs.digest }}" = softhsm2')
    with pytest.raises(AssertionError, match=_match('run block interpolates inputs: test "${{ inputs.digest }}" = softhsm2')):
        _assert_w3_no_expression_in_run(bad)


# W4 focused assertions: the select -> build -> validate-local ->
# {validate-direct, validate-proxy} -> aggregate DAG.
def _assert_w4_job_roster(text):
    assert _jobs(text) == JOB_ROSTER, "job roster must be the closed M08 DAG"


def _assert_w4_needs_edges(text):
    assert _needs(text, "select") == [], "select must need nothing"
    assert _needs(text, "build") == ["select"], "build must need select"
    assert _needs(text, "validate-local") == ["select", "build"], "validate-local must need select and build"
    assert _needs(text, "validate-direct") == ["validate-local"], "validate-direct must need validate-local"
    assert _needs(text, "validate-proxy") == ["validate-local"], "validate-proxy must need validate-local"


def _assert_w4_aggregate(text):
    assert _needs(text, "aggregate") == ["select", "build", "validate-local", "validate-direct", "validate-proxy"], \
        "aggregate must need every leg"
    if_lines = [line for line in _job_slice(text, "aggregate") if re.match(r"^    if:\s*", line)]
    assert len(if_lines) == 1, "aggregate must declare exactly one condition"
    assert "always()" in if_lines[0], "aggregate must always run"


def _assert_w4_gate_conditions(text):
    build_if = [line for line in _job_slice(text, "build") if re.match(r"^    if:\s*", line)]
    assert len(build_if) == 1, "build must declare exactly one condition"
    assert "needs.select.outputs.mode" in build_if[0] and "'rebuild'" in build_if[0], \
        "build must run on rebuild selection"
    local_if = [line for line in _job_slice(text, "validate-local") if re.match(r"^    if:\s*", line)]
    assert len(local_if) == 1, "validate-local must declare exactly one condition"
    assert "always()" in local_if[0] and "'retest'" in local_if[0] and "needs.build.result" in local_if[0], \
        "validate-local must gate on retest or build success"


def test_w4_job_roster_closed():
    _assert_w4_job_roster(_text())


def test_w4_needs_edges():
    _assert_w4_needs_edges(_text())


def test_w4_aggregate_always_and_all_legs():
    _assert_w4_aggregate(_text())


def test_w4_gate_conditions():
    _assert_w4_gate_conditions(_text())


def test_w4_mutation_extra_job_rejected():
    bad = _mutate(_text(), "  aggregate:\n", "  publish:\n    needs: aggregate\n  aggregate:\n")
    with pytest.raises(AssertionError, match=_match("job roster must be the closed M08 DAG")):
        _assert_w4_job_roster(bad)


def test_w4_mutation_dropped_needs_rejected():
    bad = _mutate(_text(), "  build:\n    needs:\n      - select\n", "  build:\n")
    with pytest.raises(AssertionError, match=_match("build must need select")):
        _assert_w4_needs_edges(bad)


def test_w4_mutation_aggregate_always_removed_rejected():
    bad = _mutate(_text(), "    if: always()\n", "    if: success()\n")
    with pytest.raises(AssertionError, match=_match("aggregate must always run")):
        _assert_w4_aggregate(bad)


# W5 focused assertions: policy fixed at the pinned control checkout,
# loaded inline (Q1), POSIX shell throughout.
PYTHON_JOBS = {"select", "build", "validate-local", "aggregate"}


def _assert_w5_python_jobs_pin_control(text):
    holders = {job for job in _jobs(text) if "python - <<'PY'" in "\n".join(_job_slice(text, job))}
    assert holders == PYTHON_JOBS, "python jobs must be the pinned control quartet"
    assert text.count("python - <<'PY'") == 4, "python loaders must be exactly four"
    for job in sorted(holders):
        blob = "\n".join(_job_slice(text, job))
        assert "persist-credentials: false" in blob, "control checkout must drop credentials: " + job
        assert "rev-parse" in blob, "control checkout must verify identity: " + job
        assert "p11lab-control" in blob, "control path must be used: " + job


def _assert_w5_policy_load(text):
    blob = "\n".join(_job_slice(text, "select"))
    assert "data/ci/validation-policy.json" in blob, "select must load the protected policy"
    assert "[0-9a-f]{40}" in blob, "select must pin 40-hex revisions"
    assert "[0-9a-f]{64}" in blob, "select must pin 64-hex profile"
    assert "policy_sha256" in blob, "select must record the policy digest"
    assert "hashlib.sha256" in blob, "select must use hashlib"


def _assert_w5_shell_pairing(text):
    shells = re.findall(r"^\s*shell:\s*(\S+)\s*$", text, re.M)
    assert shells, "shell declarations must exist"
    assert set(shells) == {"sh"}, "every run step must use POSIX sh"
    assert len(shells) == len(re.findall(r"^\s*run: \|\s*$", text, re.M)), "every shell must pair a run block"


def test_w5_python_jobs_pin_control():
    _assert_w5_python_jobs_pin_control(_text())


def test_w5_policy_load_in_select():
    _assert_w5_policy_load(_text())


def test_w5_shell_pairing():
    _assert_w5_shell_pairing(_text())


def test_w5_mutation_rev_parse_removed_rejected():
    bad = _mutate(_text(), "rev-parse HEAD", "show-ref HEAD")
    with pytest.raises(AssertionError, match=_match("control checkout must verify identity: select")):
        _assert_w5_python_jobs_pin_control(bad)


def test_w5_mutation_credentials_flipped_rejected():
    bad = _mutate(_text(), "persist-credentials: false", "persist-credentials: true")
    with pytest.raises(AssertionError, match=_match("control checkout must drop credentials: select")):
        _assert_w5_python_jobs_pin_control(bad)


def test_w5_mutation_policy_path_removed_rejected():
    bad = _mutate(_text(), "src/p11lab/data/ci/validation-policy.json",
                  "src/p11lab/data/ci/delivery/validation-policy.json")
    with pytest.raises(AssertionError, match=_match("select must load the protected policy")):
        _assert_w5_policy_load(bad)


def test_w4_mutation_build_condition_flipped_rejected():
    bad = _mutate(_text(), "needs.select.outputs.mode == 'rebuild'", "needs.select.outputs.mode == 'retest'")
    with pytest.raises(AssertionError, match=_match("build must run on rebuild selection")):
        _assert_w4_gate_conditions(bad)


BUILD_GUARD_EXIT = "raise SystemExit('gate unsatisfiable: %d unqualified marker(s) in protected policy' % len(markers))"
BUILD_KEY_MATCH = "assert rederived == os.environ['P11LAB_SELECT_BUILD_KEY'], 'declared provider build key does not match locked recipe'"
BUILD_RECEIPT_OUTCOME = "'inputs_reverified': rederived == os.environ['P11LAB_SELECT_BUILD_KEY']"


def _assert_w4_build_records(text):
    blob = "\n".join(_job_slice(text, "build"))
    guard = blob.find(BUILD_GUARD_EXIT)
    assert guard != -1, "build guard must exit before claims"
    assert "'inputs_reverified': True" not in blob, "build must not claim verification literally"
    assert "assert re.fullmatch(r'[0-9a-f]{64}', os.environ['P11LAB_SELECT_BUILD_KEY']) is not None" in blob, \
        "build must require the 64-hex select key"
    assert "rederived = artifact_key('runtime', runtime_inputs(spec))" in blob, \
        "build must rederive the provider key from recipe inputs"
    assert BUILD_KEY_MATCH in blob, "build must match the declared key to the locked recipe"
    assert "'reverified_build_key': rederived," in blob, "build receipt must record the reverified key"
    assert "'artifact_reference': os.environ['P11LAB_ARTIFACT_REF']," in blob, \
        "build receipt must record the artifact reference"
    assert BUILD_RECEIPT_OUTCOME in blob, "build receipt must record the reverification outcome"
    rederived_at = blob.find("rederived = artifact_key('runtime', runtime_inputs(spec))")
    assert rederived_at > guard, "build guard must precede reverification"
    assert blob.find(BUILD_KEY_MATCH) > rederived_at, "build reverification must precede the key match"
    assert blob.find(BUILD_RECEIPT_OUTCOME) > blob.find(BUILD_KEY_MATCH), \
        "build key match must precede the receipt"


def test_w4_build_records_receipt():
    _assert_w4_build_records(_text())


def test_w4_mutation_build_receipt_removed_rejected():
    bad = _mutate(_text(), BUILD_RECEIPT_OUTCOME,
                  "'inputs_reverified': rederived != os.environ['P11LAB_SELECT_BUILD_KEY']")
    with pytest.raises(AssertionError, match=_match("build receipt must record the reverification outcome")):
        _assert_w4_build_records(bad)


def test_w4_mutation_build_verified_literal_rejected():
    bad = _mutate(_text(), BUILD_RECEIPT_OUTCOME, "'inputs_reverified': True")
    with pytest.raises(AssertionError, match=_match("build must not claim verification literally")):
        _assert_w4_build_records(bad)


def test_w4_mutation_build_reverification_flipped_rejected():
    bad = _mutate(_text(), BUILD_KEY_MATCH, BUILD_KEY_MATCH.replace("rederived ==", "rederived !="))
    with pytest.raises(AssertionError, match=_match("build must match the declared key to the locked recipe")):
        _assert_w4_build_records(bad)


def test_w4_build_pin_ignores_comment_only_change():
    bad = _mutate(_text(), "# Re-verify the declared provider build key against the locked",
                  "# Re-verify the key.")
    _assert_w4_build_records(bad)


def test_w4_mutation_build_guard_removed_rejected():
    anchor = ("          markers = [value for value in json.dumps(policy).split('\"') if value.startswith('unqualified:')]\n"
              "          if markers:\n"
              "              " + BUILD_GUARD_EXIT + "\n"
              "          sys.path.insert(0, os.path.join(control, 'src'))\n"
              "          from p11lab.build import runtime_inputs\n"
              "          from p11lab.catalog import load_environment, validate_build_inputs\n"
              "          from p11lab.identity import artifact_key\n"
              "          assert re.fullmatch(r'[0-9a-f]{64}', os.environ['P11LAB_SELECT_BUILD_KEY']) is not None")
    bad = _mutate(_text(), anchor,
                  "          sys.path.insert(0, os.path.join(control, 'src'))\n"
                  "          from p11lab.build import runtime_inputs\n"
                  "          from p11lab.catalog import load_environment, validate_build_inputs\n"
                  "          from p11lab.identity import artifact_key\n"
                  "          assert re.fullmatch(r'[0-9a-f]{64}', os.environ['P11LAB_SELECT_BUILD_KEY']) is not None")
    with pytest.raises(AssertionError, match=_match("build guard must exit before claims")):
        _assert_w4_build_records(bad)


SELECT_GUARD_EXIT = BUILD_GUARD_EXIT
OCI_EXEC = ("              assert re.fullmatch(r'(?:[a-z0-9][a-z0-9._:/-]*@)?sha256:[0-9a-f]{64}', "
            "digest) is not None")
PROVIDER_LINE = "provider_build_key = artifact_key('runtime', runtime_inputs(spec))"


# W6 focused assertions: keys recorded once, aliases refused.
def _assert_w6_select_outputs(text):
    found = []
    in_outputs = False
    for line in _job_slice(text, "select"):
        if re.match(r"^    outputs:\s*$", line):
            in_outputs = True
        elif in_outputs:
            match = re.match(r"^      (\w+):", line)
            if match:
                found.append(match.group(1))
            else:
                break
    assert set(found) == SELECT_OUTPUTS, "select must emit the closed output set"


def _assert_w6_digest_discipline(text):
    blob = "\n".join(_job_slice(text, "select"))
    guard = blob.find(SELECT_GUARD_EXIT)
    assert guard != -1, "select guard must exit before claims"
    assert OCI_EXEC in blob, "select must validate the exact OCI digest"
    assert blob.find(OCI_EXEC) > guard, "select guard must precede digest validation"
    assert "Empty digest means rebuild from the locked recipe; never tag resolution." in blob, \
        "select must refuse tag resolution"
    assert "Only an exact sha256 digest selects retest work; a mutable alias never does." in blob, \
        "select must refuse mutable aliases"


def _assert_w6_key_discipline(text):
    blob = "\n".join(_job_slice(text, "select"))
    guard = blob.find(SELECT_GUARD_EXIT)
    assert guard != -1, "select guard must exit before claims"
    assert "hashlib.sha256(('" not in blob, "select must not hand-roll key derivation"
    plines = [line for line in blob.splitlines() if line.strip().startswith("provider_build_key = ")]
    assert len(plines) == 1, "select must derive the provider key once"
    assert "policy_sha256" not in plines[0], "provider key must not depend on tool policy"
    assert plines[0].strip() == PROVIDER_LINE, "provider key must come from recipe inputs"
    assert "bindings = policy.get('experiment_bindings')" in blob, \
        "select must gate on accepted experiment bindings"
    assert "if not isinstance(bindings, dict):" in blob, "select must require a bindings mapping"
    assert "raise SystemExit('no accepted experiment_bindings for %s; refusing to substitute' % mode)" in blob, \
        "select must refuse substituted bindings"
    assert "'build_key': bindings['provider']['build_key']," in blob, \
        "experiment must bind provider build provenance"
    assert "'provenance_sha256': bindings['provider']['provenance_sha256']}" in blob, \
        "experiment must bind provider provenance digest"
    assert "'content': bindings['content']," in blob, "experiment must bind content"
    assert "'roster': bindings['roster']," in blob, "experiment must bind roster"
    assert "'input_paths': bindings['input_paths']}" in blob, "experiment must bind input paths"
    assert "'tools': policy['fixed_tools']," in blob, "experiment must bind fixed tools"
    assert "experiment_key = image_ci.experiment_key(experiment)" in blob, \
        "select must derive the experiment key via image_ci"
    assert "image_ci._freeze_experiment(" in blob, "select must freeze the plan via image_ci"
    assert "plan_digest = frozen['sha256']" in blob, "plan digest must bind the frozen artifact plan"
    assert "Rebuild on provider inputs; retest keeps the exact provider ref with a new experiment key." in blob, \
        "select must rebuild on provider inputs"
    assert "A docs-only change schedules no provider build." in blob, "select must schedule nothing docs-only"
    assert "A missing/failed prior result never satisfies completed-key lookup." in blob, \
        "select must refuse missing priors"
    assert "Resolve once before fanout: keys, mode, and the frozen plan digest." in blob, \
        "select must resolve once before fanout"
    provider_at = blob.find(PROVIDER_LINE)
    assert provider_at > guard, "select guard must precede provider derivation"
    assert blob.find("experiment_key = image_ci.experiment_key(experiment)") > blob.find("bindings = policy.get"), \
        "bindings gate must precede the experiment key"
    assert blob.find("GITHUB_OUTPUT") > blob.find("plan_digest = frozen['sha256']"), \
        "plan must precede emission"


def _assert_w6_pending_rebuild(text):
    blob = "\n".join(_job_slice(text, "select"))
    assert "artifact_digest = 'pending:rebuild'" in blob, "rebuild artifact digest must stay pending"
    assert "artifact_reference = 'pending:rebuild:' + provider_build_key" in blob, \
        "rebuild artifact reference must stay pending"
    assert "experiment_key = 'pending:rebuild'" in blob, "rebuild experiment key must stay pending"


def _assert_w6_first_guard(text):
    blob = "\n".join(_job_slice(text, "select"))
    assert "sha256:*|*@sha256:*)" not in blob, "first guard must not accept bare sha256 suffixes"
    assert blob.count('test "${#suffix}" -eq 64') == 2, "first guard must enforce 64-hex suffixes"
    assert blob.count("case \"$suffix\" in ''|*[!0-9a-f]*) echo 'digest must be empty or an exact sha256 digest'") == 2, \
        "first guard must enforce lowercase hex twice"
    assert "suffix=${P11LAB_INPUT_DIGEST#sha256:}" in blob, "first guard must strip bare digests"
    assert "suffix=${P11LAB_INPUT_DIGEST##*@sha256:}" in blob, "first guard must strip references"


def test_w6_select_outputs_exact():
    _assert_w6_select_outputs(_text())


def test_w6_digest_discipline():
    _assert_w6_digest_discipline(_text())


def test_w6_key_discipline():
    _assert_w6_key_discipline(_text())


def test_w6_rebuild_artifact_pending():
    _assert_w6_pending_rebuild(_text())


def test_w6_first_guard_exact():
    _assert_w6_first_guard(_text())


def test_w6_mutation_output_dropped_rejected():
    bad = _mutate(_text(), "      plan_digest: ${{ steps.resolve.outputs.plan_digest }}\n", "")
    with pytest.raises(AssertionError, match=_match("select must emit the closed output set")):
        _assert_w6_select_outputs(bad)


def test_w6_mutation_alias_refusal_removed_rejected():
    bad = _mutate(_text(), "Only an exact sha256 digest selects retest work; a mutable alias never does.",
                  "Any digest selects retest work.")
    with pytest.raises(AssertionError, match=_match("select must refuse mutable aliases")):
        _assert_w6_digest_discipline(bad)


def test_w6_mutation_oci_regex_removed_rejected():
    bad = _mutate(_text(), "r'(?:[a-z0-9][a-z0-9._:/-]*@)?sha256:[0-9a-f]{64}'", "r'sha256:[0-9a-f]{64}'")
    with pytest.raises(AssertionError, match=_match("select must validate the exact OCI digest")):
        _assert_w6_digest_discipline(bad)


def test_w6_oci_pin_ignores_diagnostic_echo():
    bad = _mutate(_text(), "'digest must match @sha256:[0-9a-f]{64}'", "'digest must match'")
    _assert_w6_digest_discipline(bad)


def test_w6_mutation_rebuild_rule_removed_rejected():
    bad = _mutate(_text(), "Rebuild on provider inputs; retest keeps the exact provider ref with a new experiment key.",
                  "Rebuild always.")
    with pytest.raises(AssertionError, match=_match("select must rebuild on provider inputs")):
        _assert_w6_key_discipline(bad)


def test_w6_mutation_provider_policy_dependence_rejected():
    bad = _mutate(_text(), PROVIDER_LINE, "provider_build_key = artifact_key('runtime', policy_sha256)")
    with pytest.raises(AssertionError, match=_match("provider key must not depend on tool policy")):
        _assert_w6_key_discipline(bad)


def test_w6_mutation_hand_rolled_key_rejected():
    bad = _mutate(_text(), PROVIDER_LINE,
                  "provider_build_key = hashlib.sha256(('provider:' + artifact_reference + ':' + policy_sha256).encode()).hexdigest()")
    with pytest.raises(AssertionError, match=_match("select must not hand-roll key derivation")):
        _assert_w6_key_discipline(bad)


def test_w6_mutation_experiment_content_dropped_rejected():
    bad = _mutate(_text(), "                            'content': bindings['content'],\n", "")
    with pytest.raises(AssertionError, match=_match("experiment must bind content")):
        _assert_w6_key_discipline(bad)


def test_w6_mutation_plan_unbound_rejected():
    bad = _mutate(_text(), "plan_digest = frozen['sha256']", "plan_digest = provider_build_key")
    with pytest.raises(AssertionError, match=_match("plan digest must bind the frozen artifact plan")):
        _assert_w6_key_discipline(bad)


def test_w6_mutation_select_guard_removed_rejected():
    anchor = ("          markers = [value for value in json.dumps(policy).split('\"') if value.startswith('unqualified:')]\n"
              "          if markers:\n"
              "              " + SELECT_GUARD_EXIT + "\n"
              "          sys.path.insert(0, os.path.join(control, 'src'))\n"
              "          from p11lab.build import runtime_inputs\n"
              "          from p11lab.catalog import load_environment, validate_build_inputs\n"
              "          from p11lab.identity import artifact_key\n"
              "          from p11lab import image_ci")
    bad = _mutate(_text(), anchor,
                  "          sys.path.insert(0, os.path.join(control, 'src'))\n"
                  "          from p11lab.build import runtime_inputs\n"
                  "          from p11lab.catalog import load_environment, validate_build_inputs\n"
                  "          from p11lab.identity import artifact_key\n"
                  "          from p11lab import image_ci")
    with pytest.raises(AssertionError, match=_match("select guard must exit before claims")):
        _assert_w6_key_discipline(bad)


def test_w6_mutation_pending_fabricated_rejected():
    anchor = ("              mode = 'rebuild'\n"
              "              artifact_digest = 'pending:rebuild'\n"
              "              artifact_reference = 'pending:rebuild:' + provider_build_key")
    bad = _mutate(_text(), anchor,
                  "              mode = 'rebuild'\n"
                  "              artifact_digest = 'sha256:' + hashlib.sha256(('rebuild:' + policy_sha256).encode()).hexdigest()\n"
                  "              artifact_reference = 'local/provider-build@' + artifact_digest")
    with pytest.raises(AssertionError, match=_match("rebuild artifact digest must stay pending")):
        _assert_w6_pending_rebuild(bad)


def test_w6_mutation_first_guard_length_dropped_rejected():
    bad = _mutate(_text(), 'test "${#suffix}" -eq 64', 'test "${#suffix}" -ge 1')
    with pytest.raises(AssertionError, match=_match("first guard must enforce 64-hex suffixes")):
        _assert_w6_first_guard(bad)


ROUND_REFUSAL = "          assert 'round_positive' not in verdict_inputs and 'experiment-positive' not in verdict_inputs, 'round outputs refused'"
VERDICT_INPUTS = "          verdict_inputs = set(capsule['legs'])"
PENDING_REFUSAL = "          assert not digest.startswith('pending:'), 'pending artifact refused before fanout'"


# W7 focused assertions: lanes now, rounds later (Q6); the proxy leg is
# included but pinned non-qualifying (Q4); local gate pre-fanout (1c).
def _assert_w7_lane_calls(text):
    uses = re.findall(r"^\s*uses:\s*(\S+)\s*$", text, re.M)
    local = {entry for entry in uses if entry.startswith("./")}
    assert local == {"./.github/workflows/checker-direct-validation.yml",
                     "./.github/workflows/checker-proxy-validation.yml"}, \
        "lanes must be the two reusable validations"
    assert [entry for entry in uses if "checker-round.yml" in entry or "proxy-round.yml" in entry] == [], \
        "round calls must be absent"


def _assert_w7_round_outputs_refused(text):
    lines = _job_slice(text, "aggregate")
    assert ROUND_REFUSAL in lines, "aggregate must refuse round outputs"
    assert VERDICT_INPUTS in lines, "verdict inputs must be legs only"
    mentions = [line for line in lines if "round_positive" in line or "experiment-positive" in line]
    assert mentions == [ROUND_REFUSAL], "round-output mentions must be the refusal only"


def _assert_w7_proxy_guard(text):
    blob = "\n".join(_job_slice(text, "aggregate"))
    assert "validate-proxy" in blob, "proxy leg must be recorded"
    assert "non-qualifying" in blob, "proxy leg must be non-qualifying"
    assert "'qualifying': False" in blob, "proxy leg must not qualify"
    assert "M07 operational legs" in blob, "proxy cause must name M07 legs"
    assert "evidence_complete" in blob, "proxy leg must record evidence"


def _assert_w7_local_gate(text):
    blob = "\n".join(_job_slice(text, "validate-local"))
    assert PENDING_REFUSAL in blob, "local gate must refuse pending artifacts"
    assert "validate_image" in blob, "local gate must call image validation"
    assert "observations-complete" in blob, "local gate must require complete observations"
    assert "infrastructure_errors" in blob, "local gate must require zero infrastructure errors"
    assert "before any fanout" in blob, "local gate must run before any fanout"
    assert blob.find(PENDING_REFUSAL) < blob.find("GITHUB_OUTPUT"), "pending refusal must precede emission"


def _assert_w7_lane_digest(text):
    for job in ("validate-direct", "validate-proxy"):
        blob = "\n".join(_job_slice(text, job))
        assert "digest: ${{ needs.validate-local.outputs.artifact_digest }}" in blob, \
            "lane digest must flow through the gate: " + job
    gate = "\n".join(_job_slice(text, "validate-local"))
    assert "artifact_digest: ${{ steps.gate.outputs.artifact_digest }}" in gate, \
        "gate must emit the validated digest"


def _call_permissions(text, job):
    perms = []
    in_perms = False
    for line in _job_slice(text, job):
        if re.match(r"^    permissions:\s*$", line):
            in_perms = True
        elif in_perms:
            if re.match(r"^      \S", line):
                perms.append(line)
            else:
                break
    return perms


def _assert_w7_lane_permissions(text):
    for job in ("validate-direct", "validate-proxy"):
        assert _call_permissions(text, job) == ["      contents: read", "      actions: read"], \
            "lane call must grant contents+actions read: " + job


DISCIPLINE_PHRASES = (
    "source-seal",
    "build-content admission",
    "completed observations",
    "fingerprint",
    "disposition",
    "no diagnostic green",
    "no automatic rebaseline",
    "unusable image",
    "missing evidence",
    "cleanup",
    "finalization cannot outrun required legs",
)


def _assert_w4_discipline(text):
    blob = "\n".join(_job_slice(text, "aggregate"))
    for phrase in DISCIPLINE_PHRASES:
        assert phrase in blob, "aggregate must record promotion discipline: " + phrase


def _verdict_block(text):
    lines = _job_slice(text, "aggregate")
    start = next(i for i, line in enumerate(lines) if "usable = (" in line)
    end = next(i for i in range(start, len(lines)) if "capsule['verdict']" in lines[i])
    return "\n".join(lines[start:end + 1])


def _assert_w7_verdict_independent(text):
    block = _verdict_block(text)
    assert "experiment_key" not in block and "EXP_KEY" not in block, "verdict must ignore experiment keys"


def test_w7_lane_calls_present_round_calls_absent():
    _assert_w7_lane_calls(_text())


def test_w7_round_outputs_never_feed_verdict():
    _assert_w7_round_outputs_refused(_text())


def test_w7_proxy_leg_non_qualifying_guard():
    _assert_w7_proxy_guard(_text())


def test_w7_local_gate_pre_fanout():
    _assert_w7_local_gate(_text())


def test_w4_aggregate_promotion_discipline():
    _assert_w4_discipline(_text())


def test_w7_lane_digest_flows_through_gate():
    _assert_w7_lane_digest(_text())


def test_w7_lane_calls_grant_read():
    _assert_w7_lane_permissions(_text())


def test_w7_verdict_ignores_experiment_keys():
    _assert_w7_verdict_independent(_text())


def test_w7_mutation_round_call_added_rejected():
    bad = _mutate(_text(), "    uses: ./.github/workflows/checker-proxy-validation.yml",
                  "    uses: ./.github/workflows/proxy-round.yml")
    with pytest.raises(AssertionError, match=_match("lanes must be the two reusable validations")):
        _assert_w7_lane_calls(bad)


def test_w7_mutation_round_output_wired_rejected():
    bad = _mutate(_text(), "verdict_inputs = set(capsule['legs'])",
                  "verdict_inputs = set(capsule['legs']) | {'round_positive'}")
    with pytest.raises(AssertionError, match=_match("verdict inputs must be legs only")):
        _assert_w7_round_outputs_refused(bad)


def test_w7_mutation_round_refusal_removed_rejected():
    bad = _mutate(_text(), ROUND_REFUSAL + "\n", "")
    with pytest.raises(AssertionError, match=_match("aggregate must refuse round outputs")):
        _assert_w7_round_outputs_refused(bad)


def test_w7_mutation_proxy_guard_flipped_rejected():
    bad = _mutate(_text(), "'qualifying': False", "'qualifying': True")
    with pytest.raises(AssertionError, match=_match("proxy leg must not qualify")):
        _assert_w7_proxy_guard(bad)


def test_w7_mutation_local_gate_removed_rejected():
    bad = _mutate(_text(), "observations-complete", "observations")
    with pytest.raises(AssertionError, match=_match("local gate must require complete observations")):
        _assert_w7_local_gate(bad)


def test_w7_mutation_pending_refusal_removed_rejected():
    bad = _mutate(_text(), PENDING_REFUSAL + "\n", "")
    with pytest.raises(AssertionError, match=_match("local gate must refuse pending artifacts")):
        _assert_w7_local_gate(bad)


def test_w7_mutation_lane_digest_bypass_rejected():
    bad = _mutate(_text(), "digest: ${{ needs.validate-local.outputs.artifact_digest }}",
                  "digest: ${{ needs.select.outputs.artifact_digest }}")
    with pytest.raises(AssertionError, match=_match("lane digest must flow through the gate: validate-direct")):
        _assert_w7_lane_digest(bad)


def test_w7_mutation_lane_permissions_dropped_rejected():
    bad = _mutate(_text(), "      actions: read\n", "")
    with pytest.raises(AssertionError, match=_match("lane call must grant contents+actions read: validate-direct")):
        _assert_w7_lane_permissions(bad)


def test_w7_mutation_verdict_uses_experiment_key_rejected():
    anchor = "          usable = (os.environ['P11LAB_LOCAL_STATUS'] == 'observations-complete'"
    bad = _mutate(_text(), anchor, anchor + " and os.environ['P11LAB_EXP_KEY'] != ''")
    with pytest.raises(AssertionError, match=_match("verdict must ignore experiment keys")):
        _assert_w7_verdict_independent(bad)


def test_w4_mutation_discipline_phrase_removed_rejected():
    bad = _mutate(_text(), "finalization cannot outrun required legs", "finalization")
    with pytest.raises(AssertionError, match=_match("aggregate must record promotion discipline: finalization cannot outrun required legs")):
        _assert_w4_discipline(bad)


# G-F3 focused assertions: third-party action pins + per-job timeouts
# (M08 workflow pin hardening, closes L-rounds A1). Proxy idiom
# (`tests/test_proxy_workflows.py:20-35`): the three SHAs are module
# constants and every `uses:` of those actions must equal its frozen
# ref exactly. Parse idiom stays line-scanner based (no YAML library):
# first-token `uses:` capture tolerates the trailing `# v4`-style
# comments while the pin itself must match byte-for-byte.
GF3_CHECKOUT = "actions/checkout@11d5960a326750d5838078e36cf38b85af677262"
GF3_SETUP_PYTHON = "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065"
GF3_UPLOAD_ARTIFACT = "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
GF3_FROZEN_PINS = frozenset({GF3_CHECKOUT, GF3_SETUP_PYTHON, GF3_UPLOAD_ARTIFACT})
GF3_TIMEOUTS = {"select": 10, "build": 60, "validate-local": 60, "aggregate": 10}
GF3_REUSABLE_USES = {
    "validate-direct": "./.github/workflows/checker-direct-validation.yml",
    "validate-proxy": "./.github/workflows/checker-proxy-validation.yml",
}


def _gf3_uses_tokens(text):
    return re.findall(r"^\s*uses:\s*(\S+)", text, re.M)


def _gf3_job_timeout_lines(text, job):
    return [line for line in _job_slice(text, job) if line.startswith("    timeout-minutes:")]


def _assert_gf3_action_pins(text):
    third_party = [entry for entry in _gf3_uses_tokens(text) if not entry.startswith("./")]
    assert third_party, "third-party action pins must exist"
    for entry in third_party:
        assert entry in GF3_FROZEN_PINS, "third-party action must equal its frozen pin: " + entry
    for pin in sorted(GF3_FROZEN_PINS):
        assert pin in third_party, "frozen pin must be used: " + pin


def _assert_gf3_timeouts(text):
    for job in sorted(GF3_TIMEOUTS):
        found = _gf3_job_timeout_lines(text, job)
        assert len(found) == 1, "executable job must declare exactly one timeout: " + job
        assert found[0].strip() == "timeout-minutes: %d" % GF3_TIMEOUTS[job], \
            "timeout must be pinned: " + job


def _assert_gf3_reusable_calls(text):
    for job in sorted(GF3_REUSABLE_USES):
        blob = _job_slice(text, job)
        uses = [line.strip() for line in blob if re.match(r"^    uses:\s*\S+", line)]
        assert uses == ["uses: " + GF3_REUSABLE_USES[job]], \
            "reusable call must use its local path: " + job
        # No timeout-minutes by GitHub semantics: `timeout-minutes` is not
        # allowed on reusable-workflow call jobs, so assert its absence
        # explicitly -- a future timeout addition here must be a
        # conscious diff.
        assert _gf3_job_timeout_lines(text, job) == [], \
            "reusable call must not declare a timeout: " + job


def test_gf3_action_pins_frozen():
    _assert_gf3_action_pins(_text())


def test_gf3_timeouts_pinned():
    _assert_gf3_timeouts(_text())


def test_gf3_reusable_calls_local():
    _assert_gf3_reusable_calls(_text())


def test_gf3_mutation_checkout_sha_drift_rejected():
    bad = _mutate(_text(), GF3_CHECKOUT, "actions/checkout@" + "0" * 40)
    with pytest.raises(AssertionError, match=_match("third-party action must equal its frozen pin: actions/checkout@" + "0" * 40)):
        _assert_gf3_action_pins(bad)


def test_gf3_mutation_setup_python_tag_float_rejected():
    bad = _mutate(_text(), GF3_SETUP_PYTHON, "actions/setup-python@v5")
    with pytest.raises(AssertionError, match=_match("third-party action must equal its frozen pin: actions/setup-python@v5")):
        _assert_gf3_action_pins(bad)


def test_gf3_mutation_upload_pin_unused_rejected():
    text = _text()
    assert GF3_UPLOAD_ARTIFACT in text, "mutation anchor absent: upload pin"
    bad = "\n".join(line for line in text.splitlines() if GF3_UPLOAD_ARTIFACT not in line)
    with pytest.raises(AssertionError, match=_match("frozen pin must be used: " + GF3_UPLOAD_ARTIFACT)):
        _assert_gf3_action_pins(bad)


def test_gf3_mutation_build_timeout_changed_rejected():
    anchor = ("    if: ${{ needs.select.outputs.mode == 'rebuild' }}\n"
              "    runs-on: ubuntu-24.04\n"
              "    timeout-minutes: 60\n")
    bad = _mutate(_text(), anchor, anchor.replace("timeout-minutes: 60", "timeout-minutes: 30"))
    with pytest.raises(AssertionError, match=_match("timeout must be pinned: build")):
        _assert_gf3_timeouts(bad)


def test_gf3_mutation_select_timeout_missing_rejected():
    anchor = "  select:\n    runs-on: ubuntu-24.04\n    timeout-minutes: 10\n"
    bad = _mutate(_text(), anchor, "  select:\n    runs-on: ubuntu-24.04\n")
    with pytest.raises(AssertionError, match=_match("executable job must declare exactly one timeout: select")):
        _assert_gf3_timeouts(bad)


def test_gf3_mutation_direct_lane_path_changed_rejected():
    anchor = "    uses: ./.github/workflows/checker-direct-validation.yml"
    bad = _mutate(_text(), anchor, "    uses: ./.github/workflows/checker-round.yml")
    with pytest.raises(AssertionError, match=_match("reusable call must use its local path: validate-direct")):
        _assert_gf3_reusable_calls(bad)


def test_gf3_mutation_direct_lane_timeout_added_rejected():
    anchor = "    uses: ./.github/workflows/checker-direct-validation.yml\n"
    bad = _mutate(_text(), anchor, anchor + "    timeout-minutes: 10\n")
    with pytest.raises(AssertionError, match=_match("reusable call must not declare a timeout: validate-direct")):
        _assert_gf3_reusable_calls(bad)


# Q1-Q7 focused assertions: structural pins for the P0-D protected
# image-qualification workflow (custody acquire -> N=1 fixed smoke ->
# qualification record). Same idiom as families W1-W7/GF3 above: exact
# trigger/input/job rosters, env-mapped inputs, frozen action pins,
# pinned timeouts, least permissions, exact-digest discipline, and
# no-publication pins. Helpers _jobs/_job_slice/_needs/_run_spans/
# _on_section/_trigger_inputs/_mutate/_match are text-generic and reused.
QWORKFLOW = ROOT / ".github/workflows/image-qualification.yml"

Q_INPUT_ROSTER = {"environment", "channel", "custody_run_id",
                  "custody_attempt", "custody_job_id",
                  "custody_control_id", "p11lab_ref"}
Q_JOB_ROSTER = ["acquire", "smoke", "record"]
Q_CHECKOUT = "actions/checkout@11d5960a326750d5838078e36cf38b85af677262"
Q_SETUP_PYTHON = "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065"
Q_UPLOAD = "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
Q_DOWNLOAD = "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093"
Q_FROZEN_PINS = frozenset({Q_CHECKOUT, Q_SETUP_PYTHON, Q_UPLOAD, Q_DOWNLOAD})
Q_TIMEOUTS = {"acquire": 180, "record": 10}
Q_RECORD_IF = ("    if: ${{ always() && needs.acquire.result == 'success' "
               "&& (needs.smoke.result == 'success' "
               "|| needs.smoke.result == 'failure') }}")
Q_SMOKE_USES = "    uses: ./.github/workflows/checker-direct-validation.yml"
Q_SMOKE_DIGEST = "      digest: ${{ needs.acquire.outputs.image_digest }}"
Q_SMOKE_SUITE = "      suite: smoke"
Q_ARTIFACT = ("p11lab-image-qualification-${{ github.run_id }}-"
              "${{ github.run_attempt }}")
Q_INPUTS_ARTIFACT = ("p11lab-image-qualification-inputs-"
                     "${{ github.run_id }}-${{ github.run_attempt }}")
Q_MERGED = "checker-direct-merged-${{ github.run_id }}"
Q_DIGEST_ASSERT = ("assert re.fullmatch(r'sha256:[0-9a-f]{64}', "
                   "reference) is not None")
Q_QUALIFY_LINE = ("p11lab custody qualify --payload-dir payload-root "
                  "--smoke-result smoke-result.json "
                  "--openssl-result payload-root/openssl-result.json "
                  "--output-dir qualification-out")
Q_GH_SEAL = ("cbfdc94f3a5c0713c0d6df3e0a1d88a59a76b0c52332aad7d21d112f9da2cc0e")


def _qtext():
    return QWORKFLOW.read_text()


def _assert_q2_roster(text, trigger):
    names, _ = _trigger_inputs(text, trigger)
    assert set(names) == Q_INPUT_ROSTER, \
        "%s inputs must be the closed 7-input roster" % trigger


def _assert_q2_call_types(text):
    _, stanzas = _trigger_inputs(text, "workflow_call")
    for name in ("custody_run_id", "custody_attempt", "custody_job_id",
                 "custody_control_id"):
        assert any(line.strip() == "type: number"
                   for line in stanzas[name]), \
            "custody id must be typed number: " + name
        assert any(line.strip() == "required: true"
                   for line in stanzas[name]), \
            "custody id must be required: " + name


def _assert_q2_ref_required(text):
    for trigger in ("workflow_call", "workflow_dispatch"):
        _, stanzas = _trigger_inputs(text, trigger)
        assert "p11lab_ref" in stanzas, "p11lab_ref input missing: " + trigger
        assert any(line.strip() == "required: true"
                   for line in stanzas["p11lab_ref"]), \
            "p11lab_ref must be required: " + trigger


def _assert_q2_channel_default(text):
    _, stanzas = _trigger_inputs(text, "workflow_call")
    assert any("default: 'release'" in line
               for line in stanzas["channel"]), \
        "call channel default must be release"


def _assert_q2_dispatch_defaults(text):
    _, stanzas = _trigger_inputs(text, "workflow_dispatch")
    assert any("default: 'softhsm2'" in line
               for line in stanzas["environment"]), \
        "dispatch environment default must be softhsm2"
    assert any("default: 'release'" in line
               for line in stanzas["channel"]), \
        "dispatch channel default must be release"


def test_q1_triggers_reusable_and_dispatch_only():
    _assert_w1_triggers(_qtext())


def test_q1_mutation_pr_trigger_rejected():
    bad = _mutate(_qtext(), "  workflow_dispatch:\n",
                  "  workflow_dispatch:\n  pull_request:\n")
    with pytest.raises(AssertionError, match=_match(
            "triggers must be reusable-call plus manual-dispatch only")):
        _assert_w1_triggers(bad)


def test_q1_mutation_dispatch_removed_rejected():
    bad = _mutate(_qtext(), "  workflow_dispatch:\n", "  schedule:\n")
    with pytest.raises(AssertionError, match=_match(
            "triggers must be reusable-call plus manual-dispatch only")):
        _assert_w1_triggers(bad)


def test_q2_call_inputs_closed_roster():
    _assert_q2_roster(_qtext(), "workflow_call")


def test_q2_dispatch_inputs_closed_roster():
    _assert_q2_roster(_qtext(), "workflow_dispatch")


def test_q2_custody_ids_typed_number_and_required():
    _assert_q2_call_types(_qtext())


def test_q2_p11lab_ref_required_both():
    _assert_q2_ref_required(_qtext())


def test_q2_channel_default_release():
    _assert_q2_channel_default(_qtext())


def test_q2_dispatch_defaults():
    _assert_q2_dispatch_defaults(_qtext())


def test_q2_no_tool_override_interpolation():
    _assert_w2_no_tool_override(_qtext())


def test_q2_mutation_added_input_rejected():
    anchor = "    inputs:\n      environment:"
    bad = _mutate(_qtext(), anchor,
                  "    inputs:\n      tier:\n"
                  "        description: 'Candidate tier override.'\n"
                  "        required: false\n"
                  "        type: string\n      environment:")
    with pytest.raises(AssertionError, match=_match(
            "workflow_call inputs must be the closed 7-input roster")):
        _assert_q2_roster(bad, "workflow_call")


def test_q2_mutation_ref_required_dropped_rejected():
    anchor = ("      p11lab_ref:\n"
              "        description: 'Pinned 40-hex control commit for reusable calls.'\n"
              "        required: true")
    bad = _mutate(_qtext(), anchor,
                  anchor.replace("required: true", "required: false"))
    with pytest.raises(AssertionError, match=_match(
            "p11lab_ref must be required: workflow_call")):
        _assert_q2_ref_required(bad)


def test_q3_no_expression_in_run_blocks():
    _assert_w3_no_expression_in_run(_qtext())


def test_q3_env_mapping_anchors():
    _assert_w3_env_anchors(_qtext())


def test_q3_mutation_input_in_run_rejected():
    anchor = 'test "$P11LAB_INPUT_ENVIRONMENT" = softhsm2'
    bad = _mutate(_qtext(), anchor,
                  'test "${{ inputs.environment }}" = softhsm2')
    with pytest.raises(AssertionError, match=_match(
            'run block interpolates inputs: '
            'test "${{ inputs.environment }}" = softhsm2')):
        _assert_w3_no_expression_in_run(bad)


def _assert_q4_job_roster(text):
    assert _jobs(text) == Q_JOB_ROSTER, \
        "job roster must be the closed qualification DAG"


def _assert_q4_needs_edges(text):
    assert _needs(text, "acquire") == [], "acquire must need nothing"
    assert _needs(text, "smoke") == ["acquire"], "smoke must need acquire"
    assert _needs(text, "record") == ["acquire", "smoke"], \
        "record must need acquire and smoke"


def _assert_q4_record_condition(text):
    conditions = [line for line in _job_slice(text, "record")
                  if re.match(r"^    if:\s*", line)]
    assert conditions == [Q_RECORD_IF], \
        "record must run on completed acquire plus completed smoke"


def _assert_q4_smoke_call(text):
    blob = _job_slice(text, "smoke")
    uses = [line.strip() for line in blob
            if re.match(r"^    uses:\s*\S+", line)]
    assert uses == [Q_SMOKE_USES.strip()], \
        "smoke must call the direct validation lane"
    assert _gf3_job_timeout_lines(text, "smoke") == [], \
        "smoke call must not declare a timeout"


def test_q4_job_roster_closed():
    _assert_q4_job_roster(_qtext())


def test_q4_needs_edges():
    _assert_q4_needs_edges(_qtext())


def test_q4_record_condition():
    _assert_q4_record_condition(_qtext())


def test_q4_smoke_call_local_no_timeout():
    _assert_q4_smoke_call(_qtext())


def test_q4_mutation_extra_job_rejected():
    bad = _mutate(_qtext(), "  record:\n",
                  "  publish:\n    needs: record\n  record:\n")
    with pytest.raises(AssertionError, match=_match(
            "job roster must be the closed qualification DAG")):
        _assert_q4_job_roster(bad)


def test_q4_mutation_record_condition_weakened_rejected():
    bad = _mutate(_qtext(), "|| needs.smoke.result == 'failure'",
                  "|| needs.smoke.result == 'cancelled'")
    with pytest.raises(AssertionError, match=_match(
            "record must run on completed acquire plus completed smoke")):
        _assert_q4_record_condition(bad)


def _assert_q5_control_pins(text):
    holders = {job for job in _jobs(text)
               if "python - <<'PY'" in "\n".join(_job_slice(text, job))}
    assert holders == {"acquire", "record"}, \
        "python jobs must be acquire and record"
    assert text.count("python - <<'PY'") == 4, \
        "python loaders must be exactly four"
    for job in ("acquire", "record"):
        blob = "\n".join(_job_slice(text, job))
        assert "persist-credentials: false" in blob, \
            "control checkout must drop credentials: " + job
        assert "rev-parse" in blob, \
            "control checkout must verify identity: " + job
        assert "p11lab-control" in blob, "control path must be used: " + job
        assert "ref: ${{ inputs.p11lab_ref }}" in blob, \
            "control checkout must pin p11lab_ref: " + job


def _assert_q5_shell_pairing(text):
    shells = re.findall(r"^\s*shell:\s*(\S+)\s*$", text, re.M)
    assert shells, "shell declarations must exist"
    assert set(shells) == {"sh"}, "every run step must use POSIX sh"
    assert len(shells) == len(re.findall(r"^\s*run: \|\s*$", text, re.M)), \
        "every shell must pair a run block"


def _assert_q5_runner(text):
    assert text.count("runs-on: ubuntu-24.04") == 2, \
        "executable jobs must run on ubuntu-24.04"


def test_q5_control_pins():
    _assert_q5_control_pins(_qtext())


def test_q5_shell_pairing():
    _assert_q5_shell_pairing(_qtext())


def test_q5_runner():
    _assert_q5_runner(_qtext())


def test_q5_mutation_credentials_flipped_rejected():
    bad = _mutate(_qtext(), "persist-credentials: false",
                  "persist-credentials: true")
    with pytest.raises(AssertionError, match=_match(
            "control checkout must drop credentials: acquire")):
        _assert_q5_control_pins(bad)


def test_q5_mutation_rev_parse_removed_rejected():
    bad = _mutate(_qtext(), "rev-parse HEAD", "show-ref HEAD")
    with pytest.raises(AssertionError, match=_match(
            "control checkout must verify identity: acquire")):
        _assert_q5_control_pins(bad)


def test_q5_mutation_shell_bash_rejected():
    bad = _mutate(_qtext(), "        shell: sh\n", "        shell: bash\n")
    with pytest.raises(AssertionError, match=_match(
            "every run step must use POSIX sh")):
        _assert_q5_shell_pairing(bad)


def _assert_q6_action_pins(text):
    third_party = [entry for entry in _gf3_uses_tokens(text)
                   if not entry.startswith("./")]
    assert third_party, "third-party action pins must exist"
    for entry in third_party:
        assert entry in Q_FROZEN_PINS, \
            "third-party action must equal its frozen pin: " + entry
    for pin in sorted(Q_FROZEN_PINS):
        assert pin in third_party, "frozen pin must be used: " + pin


def _assert_q6_timeouts(text):
    for job in sorted(Q_TIMEOUTS):
        found = _gf3_job_timeout_lines(text, job)
        assert len(found) == 1, \
            "executable job must declare exactly one timeout: " + job
        assert found[0].strip() == "timeout-minutes: %d" % Q_TIMEOUTS[job], \
            "timeout must be pinned: " + job


def _assert_q6_top_permissions(text):
    assert text.count("permissions: {}") == 1, \
        "workflow must deny permissions by default"


def _assert_q6_job_permissions(text):
    for job in ("acquire", "smoke", "record"):
        assert _call_permissions(text, job) == ["      contents: read",
                                                "      actions: read"], \
            "qualification job must grant contents+actions read: " + job


def test_q6_action_pins_frozen():
    _assert_q6_action_pins(_qtext())


def test_q6_timeouts_pinned():
    _assert_q6_timeouts(_qtext())


def test_q6_top_permissions_deny_by_default():
    _assert_q6_top_permissions(_qtext())


def test_q6_job_permissions_least():
    _assert_q6_job_permissions(_qtext())


def test_q6_mutation_checkout_sha_drift_rejected():
    bad = _mutate(_qtext(), Q_CHECKOUT, "actions/checkout@" + "0" * 40)
    with pytest.raises(AssertionError, match=_match(
            "third-party action must equal its frozen pin: "
            "actions/checkout@" + "0" * 40)):
        _assert_q6_action_pins(bad)


def test_q6_mutation_download_pin_unused_rejected():
    text = _qtext()
    assert Q_DOWNLOAD in text, "mutation anchor absent: download pin"
    bad = "\n".join(line for line in text.splitlines()
                    if Q_DOWNLOAD not in line)
    with pytest.raises(AssertionError, match=_match(
            "frozen pin must be used: " + Q_DOWNLOAD)):
        _assert_q6_action_pins(bad)


def test_q6_mutation_acquire_timeout_changed_rejected():
    anchor = "    runs-on: ubuntu-24.04\n    timeout-minutes: 180\n"
    bad = _mutate(_qtext(), anchor,
                  anchor.replace("timeout-minutes: 180",
                                 "timeout-minutes: 60"))
    with pytest.raises(AssertionError, match=_match(
            "timeout must be pinned: acquire")):
        _assert_q6_timeouts(bad)


def test_q6_mutation_record_timeout_missing_rejected():
    anchor = ("  record:\n    needs:\n      - acquire\n      - smoke\n"
              + Q_RECORD_IF + "\n    runs-on: ubuntu-24.04\n"
              "    timeout-minutes: 10\n")
    bad = _mutate(_qtext(), anchor, anchor.replace(
        "    timeout-minutes: 10\n", ""))
    with pytest.raises(AssertionError, match=_match(
            "executable job must declare exactly one timeout: record")):
        _assert_q6_timeouts(bad)


def test_q6_mutation_job_permission_dropped_rejected():
    bad = _mutate(_qtext(), "      actions: read\n", "")
    with pytest.raises(AssertionError, match=_match(
            "qualification job must grant contents+actions read: acquire")):
        _assert_q6_job_permissions(bad)


def _assert_q7_acquire_invocation(text):
    blob = "\n".join(_job_slice(text, "acquire"))
    assert "p11lab custody prepare-evaluator --output-dir evaluator" in blob, \
        "acquire must prepare a fresh evaluator"
    for flag in ("--environment", "--channel", "--run-id", "--attempt",
                 "--job-id", "--control-id", "--gh", "--trusted-root",
                 "--evaluator-root", "--output-dir"):
        assert "p11lab custody acquire" in blob and flag in blob, \
            "acquire must pass custody selector " + flag
    assert "$RUNNER_TEMP/p11lab-gh/gh_2.103.2_linux_amd64/bin/gh" in blob, \
        "acquire must use the sealed verifier"
    assert Q_GH_SEAL in blob, "acquire must pin the sealed verifier digest"
    assert "open('custody-replay/custody-selector.json', 'x'" in blob, \
        "acquire must record the verified selector echo"


def _assert_q7_exact_digest(text):
    blob = "\n".join(_job_slice(text, "acquire"))
    assert Q_DIGEST_ASSERT in blob, \
        "acquire must assert the exact image digest"
    assert "json.dumps({'artifact': artifact}" in blob, \
        "acquire must project the exact artifact identity"
    assert "image_digest=%s" in blob, "acquire must emit the image digest"


def _assert_q7_openssl_leg(text):
    blob = "\n".join(_job_slice(text, "acquire"))
    assert "p11lab image validate-local" in blob, \
        "openssl leg must reuse local image validation"
    assert "result['consumer']['app_returncode'] == 0" in blob, \
        "openssl leg must require the consumer control"
    assert "controls['altered_signature']['returncode'] == 1" in blob, \
        "openssl leg must require the oracle controls"
    assert "result['status'] == 'observations-complete'" in blob, \
        "openssl leg must require complete observations"


def _assert_q7_no_round_outputs(text):
    assert "round" not in text, "round outputs must be absent"


def _assert_q7_smoke_leg(text):
    blob = "\n".join(_job_slice(text, "smoke"))
    assert Q_SMOKE_DIGEST in blob, \
        "smoke digest must flow from the acquire gate"
    assert Q_SMOKE_SUITE in blob, "smoke suite must be smoke"
    assert "advisory" not in blob, "smoke must not be advisory"


def _assert_q7_record_emission(text):
    blob = "\n".join(_job_slice(text, "record"))
    assert Q_QUALIFY_LINE in blob, "record must emit one qualification record"
    assert "missing smoke evidence; refusing to record" in blob, \
        "record must refuse missing smoke evidence"
    assert ("assert len(raw) <= 8 * 1024 * 1024, "
            "'smoke evidence byte bound'") in blob, \
        "record must bound smoke evidence reads"
    assert "os.environ['P11LAB_SMOKE_RESULT'] == 'success'" in blob, \
        "record must bind the smoke job result"
    assert "Three runs never concatenate into one record" in blob, \
        "record must refuse concatenated observations"
    assert Q_ARTIFACT in blob, "record must upload the qualification record"
    assert Q_MERGED in blob, "record must read smoke merge evidence"


def _assert_q7_inputs_transfer(text):
    blob = "\n".join(_job_slice(text, "acquire"))
    assert Q_INPUTS_ARTIFACT in blob, \
        "acquire must upload the qualification inputs"
    assert "path: qualification-inputs/" in blob, \
        "inputs upload must carry the staged layout"
    record = "\n".join(_job_slice(text, "record"))
    assert Q_INPUTS_ARTIFACT in record, \
        "record must download the qualification inputs"


def _assert_q7_no_publication(text):
    assert "oras" not in text, "registry publication tooling must be absent"
    assert "actions/attest@" not in text, \
        "attestation publication must be absent"
    assert "packages: write" not in text, \
        "package publication permission must be absent"


def test_q7_acquire_invocation():
    _assert_q7_acquire_invocation(_qtext())


def test_q7_exact_digest_assertion():
    _assert_q7_exact_digest(_qtext())


def test_q7_openssl_leg_reuses_local_validation():
    _assert_q7_openssl_leg(_qtext())


def test_q7_no_round_outputs():
    _assert_q7_no_round_outputs(_qtext())


def test_q7_smoke_leg_exact_digest_suite():
    _assert_q7_smoke_leg(_qtext())


def test_q7_record_emission():
    _assert_q7_record_emission(_qtext())


def test_q7_inputs_transfer():
    _assert_q7_inputs_transfer(_qtext())


def test_q7_no_publication():
    _assert_q7_no_publication(_qtext())


def test_q7_mutation_acquire_control_flag_dropped_rejected():
    anchor = ' --control-id "$P11LAB_CUSTODY_CONTROL_ID"'
    bad = _mutate(_qtext(), anchor, "")
    with pytest.raises(AssertionError, match=_match(
            "acquire must pass custody selector --control-id")):
        _assert_q7_acquire_invocation(bad)


def test_q7_mutation_digest_assertion_relaxed_rejected():
    bad = _mutate(_qtext(), "r'sha256:[0-9a-f]{64}'", "r'sha256:[0-9a-f]+'")
    with pytest.raises(AssertionError, match=_match(
            "acquire must assert the exact image digest")):
        _assert_q7_exact_digest(bad)


def test_q7_mutation_smoke_digest_bypass_rejected():
    bad = _mutate(_qtext(), Q_SMOKE_DIGEST,
                  "      digest: ${{ inputs.digest }}")
    with pytest.raises(AssertionError, match=_match(
            "smoke digest must flow from the acquire gate")):
        _assert_q7_smoke_leg(bad)


def test_q7_mutation_smoke_advisory_added_rejected():
    bad = _mutate(_qtext(), Q_SMOKE_SUITE,
                  Q_SMOKE_SUITE + "\n      advisory: 'true'")
    with pytest.raises(AssertionError, match=_match(
            "smoke must not be advisory")):
        _assert_q7_smoke_leg(bad)


def test_q7_mutation_missing_evidence_guard_removed_rejected():
    bad = _mutate(_qtext(), "missing smoke evidence; refusing to record",
                  "missing smoke evidence")
    with pytest.raises(AssertionError, match=_match(
            "record must refuse missing smoke evidence")):
        _assert_q7_record_emission(bad)


def test_q7_mutation_publication_tooling_added_rejected():
    anchor = "      - name: Emit image qualification record\n"
    bad = _mutate(_qtext(), anchor,
                  anchor + "        oras pull placeholder\n")
    with pytest.raises(AssertionError, match=_match(
            "registry publication tooling must be absent")):
        _assert_q7_no_publication(bad)
