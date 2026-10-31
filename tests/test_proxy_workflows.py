"""Static contract tests for the proxy-round reusable workflow.

Covers the workflow YAML, the public caller example, and the caller doc
(prep S1.1, S1.2, S1.5-aggregator, S1.6). YAML parsing is self-contained
(PyYAML with the checker idiom: `on` stays a string key, duplicate keys
and aliases reject); `scripts/check_round_workflows.py` is untouched (Q5).
"""

import copy
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from p11lab import native as native_module
from p11lab import proxy_derivative as derivative_module
from p11lab import tls as tls_module
from p11lab.models import ProxyBuildIdentityV1
from p11lab.round_core import proxy_execute as proxy_execute_module

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "proxy-round.yml"
EXAMPLE = ROOT / "examples" / "proxy-consumer" / "workflow.yml"
DOC = ROOT / "docs" / "proxy-ci.md"

TIER = "proxy-diagnostic-v1"
PYTHON_VERSION = "3.12.14"
CHECKOUT = "actions/checkout@11d5960a326750d5838078e36cf38b85af677262"
SETUP_PYTHON = "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065"
UPLOAD_ARTIFACT = "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
SHA_A = "a" * 40
SHA_B = "b" * 40
SHA_C = "c" * 40

JOBS = ("validate", "direct", "accepted-proxy", "candidate-proxy", "aggregate")
CELLS = ("direct", "accepted-proxy", "candidate-proxy")
OUTPUTS = ("result-artifact", "result-sha256", "experiment-positive")
GUARD_RUN = (
    "case \"$PROXY_SHA\" in ''|*[!0-9a-f]*) exit 1 ;; esac\n"
    "test \"${#PROXY_SHA}\" -eq 40\n"
    "case \"$P11LAB_REF\" in ''|*[!0-9a-f]*) exit 1 ;; esac\n"
    "test \"${#P11LAB_REF}\" -eq 40\n"
    "case \"$TIER\" in proxy-diagnostic-v1) ;; *) exit 1 ;; esac\n"
)
HEAD_RUN = 'test "$(git -C p11lab-control rev-parse HEAD)" = "$P11LAB_REF"\n'


class WorkflowLoader(yaml.SafeLoader):
    pass


WorkflowLoader.yaml_implicit_resolvers = copy.deepcopy(
    yaml.SafeLoader.yaml_implicit_resolvers
)
for _key, _rules in WorkflowLoader.yaml_implicit_resolvers.items():
    WorkflowLoader.yaml_implicit_resolvers[_key] = [
        r for r in _rules if r[0] != "tag:yaml.org,2002:bool"
    ]
WorkflowLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool", re.compile(r"^(?:true|false)$", re.I), list("tTfF")
)


def _mapping(loader, node, deep=False):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str) or key in result:
            raise ValueError("non-string or duplicate mapping key")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


WorkflowLoader.add_constructor("tag:yaml.org,2002:map", _mapping)


def _loads(text):
    raw = text.encode("utf-8")
    assert len(raw) <= 65536, "workflow exceeds size limit"
    tokens = list(yaml.scan(text, Loader=WorkflowLoader))
    assert len(tokens) <= 10000, "workflow exceeds token limit"
    assert not any(
        isinstance(t, (yaml.AliasToken, yaml.AnchorToken)) for t in tokens
    ), "aliases forbidden"
    doc = yaml.load(text, Loader=WorkflowLoader)
    assert isinstance(doc, dict), "workflow must be a mapping"
    return doc


def _workflow_text():
    return WORKFLOW.read_text()


def _workflow_doc(text=None):
    return _loads(_workflow_text() if text is None else text)


def _check_workflow(doc, text):
    assert set(doc) == {"name", "on", "permissions", "jobs"}, "top-level keys"
    assert doc["name"] == "proxy-round"
    assert doc["permissions"] == {}, "top-level permissions minimal"
    assert set(doc["on"]) == {"workflow_call"}, "reusable-only trigger"
    call = doc["on"]["workflow_call"]
    assert set(call) == {"inputs", "outputs"}, "call interface keys"
    assert set(call["inputs"]) == {
        "proxy_sha",
        "tier",
        "p11lab_ref",
    }, "exactly three inputs"
    assert all(
        v == {"required": True, "type": "string"}
        for v in call["inputs"].values()
    ), "input shape"
    assert set(call["outputs"]) == set(OUTPUTS), "exactly three outputs"
    for name in OUTPUTS:
        assert call["outputs"][name] == {
            "value": "${{ jobs.aggregate.outputs['" + name + "'] }}"
        }, "output mapping " + name
    jobs = doc["jobs"]
    assert set(jobs) == set(JOBS), "frozen five-job roster"

    validate = jobs["validate"]
    assert set(validate) == {"runs-on", "timeout-minutes", "permissions", "steps"}
    assert validate["runs-on"] == "ubuntu-24.04"
    assert validate["timeout-minutes"] == 10
    assert validate["permissions"] == {"contents": "read", "actions": "read"}
    steps = validate["steps"]
    assert [s.get("name") for s in steps] == [
        "Validate input identities",
        "Checkout control source",
        "Verify control identity",
        "Set up Python",
        "Validate policy and write diagnostic manifest",
        "Upload diagnostic manifest",
    ], "validate steps"
    guard, checkout, head, setup, result, upload = steps
    assert guard["id"] == "inputs"
    assert guard["shell"] == "sh"
    assert guard["env"] == {
        "PROXY_SHA": "${{ inputs.proxy_sha }}",
        "TIER": "${{ inputs.tier }}",
        "P11LAB_REF": "${{ inputs.p11lab_ref }}",
    }, "guard env"
    assert guard["run"] == GUARD_RUN, "POSIX input guard"
    assert checkout["uses"] == CHECKOUT
    assert checkout["with"] == {
        "repository": "p11lab/p11lab",
        "ref": "${{ inputs.p11lab_ref }}",
        "path": "p11lab-control",
        "persist-credentials": False,
    }, "control checkout"
    assert head["shell"] == "sh"
    assert head["env"] == {"P11LAB_REF": "${{ inputs.p11lab_ref }}"}
    assert head["run"] == HEAD_RUN, "control HEAD guard"
    assert setup["uses"] == SETUP_PYTHON
    assert setup["with"] == {"python-version": PYTHON_VERSION}, "pinned Python"
    assert result["id"] == "result"
    assert result["shell"] == "sh"
    assert result["env"] == guard["env"], "result env"
    script = result["run"]
    for fragment in (
        'PYTHONPATH="$GITHUB_WORKSPACE/p11lab-control/src" python -',
        "from p11lab import proxy_policy",
        "proxy_policy.load_proxy_policy(os.environ['TIER'])",
        "loaded.tier_qualified is False",
        "'schema': 'p11lab-proxy-diagnostic-v1'",
        "'diagnostic_only': True",
        "'unqualified_cause': 'tier-unqualified'",
        "PX-LIMIT pinned rejection unbound; budgets are unqualified targets",
        "dict(loaded.provider)",
        "'p11lab-proxy-dist-'",
        "'result_artifact': None",
        "'experiment_positive': False",
        "proxy-diagnostic.json",
    ):
        assert fragment in script, "validate script keeps " + fragment
    assert upload["uses"] == UPLOAD_ARTIFACT
    assert upload["with"] == {
        "name": "p11lab-proxy-diagnostic-${{ github.run_id }}-${{ github.run_attempt }}",
        "path": "${{ runner.temp }}/proxy-diagnostic.json",
        "if-no-files-found": "error",
        "retention-days": 14,
    }, "diagnostic upload"

    for cell in CELLS:
        job = jobs[cell]
        assert set(job) == {
            "runs-on",
            "timeout-minutes",
            "permissions",
            "steps",
        }, "cell keys " + cell
        assert job["runs-on"] == "ubuntu-24.04", cell
        assert job["timeout-minutes"] == 10, cell
        assert job["permissions"] == {}, "secretless cell " + cell
        assert [s.get("name") for s in job["steps"]] == [
            "Emit not-executed cell diagnostic",
            "Upload cell manifest",
        ], "cell steps " + cell
        emit, cell_upload = job["steps"]
        assert emit["shell"] == "sh", cell
        assert emit["env"] == {
            "PROXY_SHA": "${{ inputs.proxy_sha }}",
            "TIER": "${{ inputs.tier }}",
        }, "cell env " + cell
        for fragment in (
            "'schema': 'p11lab-proxy-cell-diagnostic-v1'",
            "'cell': '%s'" % cell,
            "'status': 'not-executed'",
            "proxy-cell-%s.json" % cell,
        ):
            assert fragment in emit["run"], "cell script keeps %s in %s" % (
                fragment,
                cell,
            )
        assert cell_upload["uses"] == UPLOAD_ARTIFACT, cell
        assert cell_upload["with"] == {
            "name": "p11lab-proxy-cell-%s-${{ github.run_id }}-${{ github.run_attempt }}"
            % cell,
            "path": "${{ runner.temp }}/proxy-cell-%s.json" % cell,
            "if-no-files-found": "error",
            "retention-days": 14,
        }, "cell upload " + cell

    agg = jobs["aggregate"]
    assert set(agg) == {
        "runs-on",
        "timeout-minutes",
        "if",
        "needs",
        "permissions",
        "outputs",
        "steps",
    }, "aggregate keys"
    assert agg["runs-on"] == "ubuntu-24.04"
    assert agg["timeout-minutes"] == 30, "aggregate timeout"
    assert agg["if"] == "always()", "aggregate always runs"
    assert agg["needs"] == [
        "validate",
        "direct",
        "accepted-proxy",
        "candidate-proxy",
    ], "aggregate needs all four"
    assert agg["permissions"] == {"contents": "read", "actions": "read"}
    assert set(agg["outputs"]) == set(OUTPUTS)
    for name in OUTPUTS:
        assert agg["outputs"][name] == (
            "${{ steps.result.outputs['" + name + "'] }}"
        ), "aggregate output " + name
    assert [s.get("name") for s in agg["steps"]] == [
        "Write diagnostic capsule",
        "Upload diagnostic capsule",
    ], "aggregate steps"
    write, capsule_upload = agg["steps"]
    assert write["id"] == "result"
    assert write["shell"] == "sh"
    assert write["env"] == guard["env"], "capsule env"
    for fragment in (
        "'schema': 'p11lab-proxy-experiment-result-v1'",
        "'diagnostic_only': True",
        "'unqualified_cause': 'tier-unqualified'",
        "proxy-capsule.json",
        "echo 'result-artifact='",
        "echo 'result-sha256='",
        "echo 'experiment-positive=false'",
        '"$GITHUB_OUTPUT"',
    ):
        assert fragment in write["run"], "capsule script keeps " + fragment
    assert capsule_upload["uses"] == UPLOAD_ARTIFACT
    assert capsule_upload["with"] == {
        "name": "p11lab-proxy-capsule-${{ github.run_id }}-${{ github.run_attempt }}",
        "path": "${{ runner.temp }}/proxy-capsule.json",
        "if-no-files-found": "error",
        "retention-days": 14,
    }, "capsule upload"

    assert "secrets" not in text, "no secrets anywhere"
    assert "pull_request_target" not in text, "never executes a PR target"
    assert "download-artifact" not in text, "fewer moving parts"
    assert "pip install" not in text, "policy loads from control only"
    assert "CKR_" not in text, "no guessed rejection values"
    for job_name, job in jobs.items():
        for step in job.get("steps", []):
            assert "if" not in step, "no step-level bypass in %s" % job_name
            assert "continue-on-error" not in step, "no soft failure in %s" % (
                job_name
            )
            if "uses" in step:
                assert re.fullmatch(
                    r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", step["uses"]
                ), "full-SHA pin " + step["uses"]
                assert step["uses"] in (
                    CHECKOUT,
                    SETUP_PYTHON,
                    UPLOAD_ARTIFACT,
                ), "frozen pin " + step["uses"]
            if "run" in step:
                assert "${{ inputs." not in step["run"], (
                    "dispatch inputs reach shell only via env in %s" % job_name
                )
            if step.get("shell") is not None:
                assert step["shell"] == "sh", "POSIX shell in %s" % job_name


def test_contract_accepts_workflow():
    text = _workflow_text()
    _check_workflow(_workflow_doc(text), text)


def test_on_stays_a_string_key():
    assert "on" in _workflow_doc()


BARE_PYTHON = re.compile(r"(?<![\w/.-])python(?![\w.])")


def test_bare_python_requires_setup_python():
    doc = _workflow_doc()
    violations = []
    for job_name, job in doc["jobs"].items():
        steps = job.get("steps", [])
        has_setup = any(
            s.get("uses", "").startswith("actions/setup-python@")
            for s in steps
        )
        for step in steps:
            if BARE_PYTHON.search(step.get("run", "")) and not has_setup:
                violations.append(
                    "%s: %s" % (job_name, step.get("name", step.get("id")))
                )
    assert violations == [], (
        "bare-PATH python without setup-python: %s" % ", ".join(violations)
    )


def test_duplicate_key_is_rejected():
    with pytest.raises(Exception):
        _loads(_workflow_text() + "\npermissions: {}\n")


def _mutated_rejects(old, new, count=1):
    text = _workflow_text()
    assert old in text, "mutation anchor missing: %r" % old
    mutated = text.replace(old, new, count)
    with pytest.raises(Exception):
        _check_workflow(_loads(mutated), mutated)


@pytest.mark.parametrize(
    ("old", "new"),
    [
        (
            "      p11lab_ref:\n",
            "      advisory:\n        required: false\n        type: string\n"
            "      p11lab_ref:\n",
        ),
        (CHECKOUT, "actions/checkout@v4"),
        (SETUP_PYTHON, "actions/setup-python@v5"),
        (UPLOAD_ARTIFACT, "actions/upload-artifact@v4"),
        ("repository: p11lab/p11lab", "repository: attacker/control"),
        ("ref: ${{ inputs.p11lab_ref }}", "ref: main"),
        ("path: p11lab-control", "path: control"),
        ("persist-credentials: false", "persist-credentials: true"),
        (
            'test "${#PROXY_SHA}" -eq 40',
            'test "${{ inputs.proxy_sha }}" != ""',
        ),
        ("  validate:\n", "  validate_disabled:\n"),
        ("  direct:\n", "  direct_disabled:\n"),
        ("  accepted-proxy:\n", "  accepted-proxy_disabled:\n"),
        ("  candidate-proxy:\n", "  candidate-proxy_disabled:\n"),
        ("  aggregate:\n", "  aggregate_disabled:\n"),
        ("echo 'experiment-positive=false'", "echo 'experiment-positive=true'"),
        ("echo 'result-artifact='", "echo 'result-artifact=x'"),
        ("echo 'result-sha256='", "echo 'result-sha256=x'"),
        ("permissions: {}", "permissions: {}\nsecrets: inherit"),
        ("contents: read", "contents: write"),
        (
            "    permissions: {}\n",
            "    permissions:\n      contents: read\n",
        ),
        ("if: always()", "if: success()"),
        ("        id: inputs\n", "        id: inputs\n        if: false\n"),
        (
            "        id: result\n",
            "        id: result\n        continue-on-error: true\n",
        ),
        ("timeout-minutes: 30", "timeout-minutes: 60"),
        ("retention-days: 14", "retention-days: 1"),
        ("python-version: '3.12.14'", "python-version: '3.12'"),
        ("in proxy-diagnostic-v1)", "in proxy-diagnostic-v1|*)"),
        ("*[!0-9a-f]*", "*"),
        ("'status': 'not-executed'", "'status': 'executed'"),
        (
            "'unqualified_cause': 'tier-unqualified'",
            "'unqualified_cause': None",
        ),
        ("      - candidate-proxy\n", ""),
        ("shell: sh", "shell: bash"),
        (
            'PYTHONPATH="$GITHUB_WORKSPACE/p11lab-control/src" python -',
            "pip install p11lab\n          python -",
        ),
    ],
)
def test_contract_rejects_mutations(old, new):
    _mutated_rejects(old, new)


@pytest.mark.parametrize(
    ("proxy", "tier", "control", "ok"),
    [
        (SHA_A, TIER, SHA_B, True),
        ("a" * 39, TIER, SHA_B, False),
        ("A" * 40, TIER, SHA_B, False),
        ("g" * 40, TIER, SHA_B, False),
        ("", TIER, SHA_B, False),
        (SHA_A, "pr-smoke", SHA_B, False),
        (SHA_A, "nightly", SHA_B, False),
        (SHA_A, "release", SHA_B, False),
        (SHA_A, "main", SHA_B, False),
        (SHA_A, "", SHA_B, False),
        (SHA_A, TIER, "main", False),
        (SHA_A, TIER, "b" * 39, False),
    ],
)
def test_runtime_input_guard(proxy, tier, control, ok):
    doc = _workflow_doc()
    step = next(
        x
        for x in doc["jobs"]["validate"]["steps"]
        if x.get("id") == "inputs"
    )
    env = dict(os.environ, PROXY_SHA=proxy, TIER=tier, P11LAB_REF=control)
    result = subprocess.run(
        ["sh", "-e", "-c", step["run"]], env=env, capture_output=True, text=True
    )
    assert (result.returncode == 0) == ok


def test_control_head_guard_rejects_wrong_revision(tmp_path):
    subprocess.run(
        ["git", "init", "-q", str(tmp_path / "p11lab-control")], check=True
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(tmp_path / "p11lab-control"),
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "--allow-empty",
            "-qm",
            "fixture",
        ],
        check=True,
    )
    head = subprocess.check_output(
        ["git", "-C", str(tmp_path / "p11lab-control"), "rev-parse", "HEAD"],
        text=True,
    ).strip()
    doc = _workflow_doc()
    step = next(
        x
        for x in doc["jobs"]["validate"]["steps"]
        if x.get("name") == "Verify control identity"
    )
    for ref, expected in [(head, 0), (SHA_A, 1)]:
        result = subprocess.run(
            ["sh", "-e", "-c", step["run"]],
            cwd=tmp_path,
            env=dict(os.environ, P11LAB_REF=ref),
        )
        assert result.returncode == expected


def _hermetic_env(tmp_path, **extra):
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    link = bindir / "python"
    if not link.exists():
        link.symlink_to(sys.executable)
    env["PATH"] = str(bindir) + os.pathsep + env["PATH"]
    env["GITHUB_WORKSPACE"] = str(tmp_path / "workspace")
    env["RUNNER_TEMP"] = str(tmp_path)
    env.update(extra)
    return env


def test_validate_step_loads_control_policy_and_writes_manifest(tmp_path):
    import json

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "p11lab-control").symlink_to(ROOT, target_is_directory=True)
    doc = _workflow_doc()
    step = next(
        x
        for x in doc["jobs"]["validate"]["steps"]
        if x.get("id") == "result"
    )
    env = _hermetic_env(
        tmp_path,
        PROXY_SHA=SHA_A,
        P11LAB_REF=SHA_B,
        TIER=TIER,
        GITHUB_RUN_ATTEMPT="1",
    )
    proc = subprocess.run(
        ["sh", "-e", "-c", step["run"]],
        env=env,
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    manifest = json.loads((tmp_path / "proxy-diagnostic.json").read_text())
    assert manifest["schema"] == "p11lab-proxy-diagnostic-v1"
    assert manifest["diagnostic_only"] is True
    assert manifest["proxy_sha"] == SHA_A
    assert manifest["p11lab_ref"] == SHA_B
    assert manifest["tier"] == TIER
    assert manifest["tier_qualified"] is False
    assert manifest["unqualified_cause"] == "tier-unqualified"
    assert manifest["provider"]["family"] == "softhsm2"
    assert manifest["provider"]["channel"] == "release"
    assert manifest["provider"]["platform"] == "linux/amd64"
    assert manifest["expected_same_run_artifact"] == (
        "p11lab-proxy-dist-" + SHA_A + "-1"
    )
    assert manifest["result_artifact"] is None
    assert manifest["result_sha256"] is None
    assert manifest["experiment_positive"] is False


@pytest.mark.parametrize("cell", CELLS)
def test_cell_step_emits_not_executed_diagnostic(tmp_path, cell):
    import json

    doc = _workflow_doc()
    step = next(
        x
        for x in doc["jobs"][cell]["steps"]
        if x.get("name") == "Emit not-executed cell diagnostic"
    )
    env = _hermetic_env(tmp_path, PROXY_SHA=SHA_A, TIER=TIER)
    proc = subprocess.run(
        ["sh", "-e", "-c", step["run"]],
        env=env,
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    manifest = json.loads((tmp_path / ("proxy-cell-%s.json" % cell)).read_text())
    assert manifest["schema"] == "p11lab-proxy-cell-diagnostic-v1"
    assert manifest["diagnostic_only"] is True
    assert manifest["cell"] == cell
    assert manifest["status"] == "not-executed"
    assert manifest["proxy_sha"] == SHA_A
    assert manifest["tier"] == TIER


def test_aggregate_step_writes_capsule_and_empty_outputs(tmp_path):
    import json

    output = tmp_path / "output"
    output.touch()
    doc = _workflow_doc()
    step = next(
        x
        for x in doc["jobs"]["aggregate"]["steps"]
        if x.get("id") == "result"
    )
    env = _hermetic_env(
        tmp_path,
        PROXY_SHA=SHA_A,
        P11LAB_REF=SHA_B,
        TIER=TIER,
        GITHUB_OUTPUT=str(output),
    )
    proc = subprocess.run(
        ["sh", "-e", "-c", step["run"]],
        env=env,
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    capsule = json.loads((tmp_path / "proxy-capsule.json").read_text())
    assert capsule["schema"] == "p11lab-proxy-experiment-result-v1"
    assert capsule["diagnostic_only"] is True
    assert capsule["experiment_positive"] is False
    assert capsule["evidence_complete"] is False
    assert capsule["comparison_positive"] is None
    assert capsule["unqualified_cause"] == "tier-unqualified"
    assert output.read_text().splitlines() == [
        "result-artifact=",
        "result-sha256=",
        "experiment-positive=false",
    ]


def _example_text():
    return EXAMPLE.read_text()


def _example_doc(text=None):
    raw = _example_text() if text is None else text
    assert "UNPUBLISHED TEMPLATE" in raw, "caller stays an unpublished template"
    substituted = raw.replace("<P11LAB_COMMIT_SHA>", SHA_C).replace(
        "<PROXY_COMMIT_SHA>", SHA_B
    )
    return _loads(substituted), substituted


def _check_example(doc, text):
    assert set(doc) == {"name", "on", "permissions", "jobs"}, "caller keys"
    assert doc["on"] == {"pull_request": None}, "caller trigger"
    assert "workflow_dispatch" not in text, "no dispatch path in caller"
    assert doc["permissions"] == {
        "contents": "read",
        "actions": "read",
    }, "caller permissions"
    assert set(doc["jobs"]) == {"diagnostic"}, "caller job"
    caller = doc["jobs"]["diagnostic"]
    assert set(caller) == {"permissions", "uses", "with"}, "caller job keys"
    assert caller["permissions"] == {"contents": "read", "actions": "read"}
    match = re.fullmatch(
        r"p11lab/p11lab/\.github/workflows/proxy-round\.yml@([0-9a-f]{40})",
        caller["uses"],
    )
    assert match is not None, "caller uses pin"
    inputs = caller["with"]
    assert set(inputs) == {"proxy_sha", "tier", "p11lab_ref"}, "caller inputs"
    assert inputs["p11lab_ref"] == match.group(1), "caller pin equality"
    assert re.fullmatch(r"[0-9a-f]{40}", inputs["proxy_sha"]) is not None
    assert inputs["tier"] == TIER, "caller tier literal"
    assert "secrets" not in text, "no secrets in caller"
    assert "pull_request_target" not in text, "caller never runs a PR target"
    assert "token" not in text, "no dispatch tokens in caller"


def test_contract_accepts_example():
    doc, substituted = _example_doc()
    _check_example(doc, substituted)


@pytest.mark.parametrize(
    ("old", "new"),
    [
        (
            "p11lab_ref: <P11LAB_COMMIT_SHA>",
            "p11lab_ref: <PROXY_COMMIT_SHA>",
        ),
        ("tier: proxy-diagnostic-v1", "tier: pr-smoke"),
        ("@<P11LAB_COMMIT_SHA>", "@v4"),
        (
            "      tier: proxy-diagnostic-v1\n",
            "      tier: proxy-diagnostic-v1\n      advisory: x\n",
        ),
        ("  contents: read", "  contents: write"),
        (
            "permissions:\n  contents: read",
            "permissions:\n  contents: read\nsecrets: inherit",
        ),
        ("  pull_request:", "  workflow_dispatch:"),
        ("  pull_request:", "  pull_request_target:"),
        ("  actions: read\n", ""),
    ],
)
def test_example_rejects_mutations(old, new):
    text = _example_text()
    assert old in text, "mutation anchor missing: %r" % old
    mutated = text.replace(old, new, 1)
    with pytest.raises(Exception):
        doc, substituted = _example_doc(mutated)
        _check_example(doc, substituted)


def _doc_text():
    return DOC.read_text()


def _check_doc(text):
    lowered = text.lower()
    for phrase in (
        "diagnostic-only",
        "cannot satisfy a release gate",
        "n=1",
        "flaky-green",
        "positive controls",
        "fault mutants",
        "complete-negative",
        "proxy-diagnostic-v1",
        "proxy_sha",
        "p11lab_ref",
        "result-artifact",
        "result-sha256",
        "experiment-positive",
        "p11lab-proxy-dist-",
        "tier-unqualified",
        "actions: read",
        "rerun_requires_producer",
        "self-assertion is insufficient",
        "proxy-round-execution",
        "execute-cell",
        "proxy aggregate",
        "one cell per job",
        "uploads-incomplete",
        "never the checker exit 3",
        "upload-before-report",
        "scaffold-scoped",
        "cell-payload-",
        "comparison.json",
        "budgets.json",
        "p11lab-proxy-verdict-",
        "missing-row",
        "t3 and t6",
        "incomplete-evidence",
        "full-rerun",
    ):
        assert phrase in lowered, "doc states " + phrase


def test_contract_accepts_doc():
    _check_doc(_doc_text())


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("cannot satisfy a release gate", "satisfies release gates"),
        ("N=1", "N=9"),
        ("Diagnostic-only", "Fully-qualified"),
        ("Positive controls", "Good feelings"),
        ("fault mutants", "fault friends"),
        ("rerun_requires_producer", "rerun_anything"),
        ("actions: read", "actions: write"),
        ("upload-before-report", "report-before-upload"),
        ("scaffold-scoped", "fully-qualified"),
        ("never the checker exit 3", "sometimes the checker exit 3"),
        ("T3 and T6", "T3 only"),
        ("missing-row", "absent-row"),
        ("one cell per job", "one cell per run"),
    ],
)
def test_doc_rejects_mutations(old, new):
    text = _doc_text()
    assert old in text, "mutation anchor missing: %r" % old
    with pytest.raises(Exception):
        _check_doc(text.replace(old, new, 1))


# ---------------------------------------------------------------------------
# B-P2: proxy-round-execution.yml operational-path contract.
#
# Parallel contract for the NEW execution workflow (diagnostic assertions
# above stay byte-identical): per-cell `proxy execute-cell` invocation with
# real observation uploads, an `always()` aggregate running `proxy
# aggregate` over tolerant same-run downloads, and exact 1/2 verdict
# propagation after upload. Pilot (d) mirrors (MS-A/MS-B/WP/T-PX/F-CRASH/
# F-NOTERM/F-ACCEPT) drive the REAL workflow step scripts hermetically.
# Independence rule: staging builders below are re-authored from the
# production contract; this module never imports from other test modules.
# Committed P1a fixture bytes (daemon/cl/shim.bin, manifest.json) are read
# read-only, following the established P1c precedent. Fixture IDs are
# invented here and differ from every other suite on purpose.
# ---------------------------------------------------------------------------

EXECUTION_WORKFLOW = ROOT / ".github" / "workflows" / "proxy-round-execution.yml"
EXECUTION_EXAMPLE = ROOT / "examples" / "proxy-consumer" / "execution.yml"
DOWNLOAD_ARTIFACT = (
    "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093"
)
EXECUTION_USES = (CHECKOUT, SETUP_PYTHON, UPLOAD_ARTIFACT, DOWNLOAD_ARTIFACT)

W2_RUN_ID = 999991
W2_RUN_ATTEMPT = 5
W2_AUTHORITY = {
    "repository_id": 9999,
    "repository_full_name": "example/proxy-workflow-cells",
    "producer_job_id": "999992",
    "artifact_id": 999993,
}
W2_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "proxy_execute"

CELL_RESULTS_ENV = (
    "${{ needs.direct.result }}/${{ needs.accepted-proxy.result }}/"
    "${{ needs.candidate-proxy.result }}"
)


def _execution_workflow_text():
    return EXECUTION_WORKFLOW.read_text()


def _execution_workflow_doc(text=None):
    raw = _execution_workflow_text() if text is None else text
    return _loads(raw)


def _check_execution_guard(job, job_name):
    guard = next(s for s in job["steps"] if s.get("id") == "inputs")
    assert guard["shell"] == "sh", "POSIX guard in " + job_name
    assert guard["env"] == {
        "PROXY_SHA": "${{ inputs.proxy_sha }}",
        "TIER": "${{ inputs.tier }}",
        "P11LAB_REF": "${{ inputs.p11lab_ref }}",
    }, "guard env in " + job_name
    assert guard["run"] == GUARD_RUN, "POSIX input guard in " + job_name


def _check_execution_checkout(job, job_name):
    steps = {s.get("name"): s for s in job["steps"]}
    checkout = steps["Checkout control source"]
    assert checkout["uses"] == CHECKOUT, job_name
    assert checkout["with"] == {
        "repository": "p11lab/p11lab",
        "ref": "${{ inputs.p11lab_ref }}",
        "path": "p11lab-control",
        "persist-credentials": False,
    }, "control checkout in " + job_name
    head = steps["Verify control identity"]
    assert head["shell"] == "sh", job_name
    assert head["env"] == {"P11LAB_REF": "${{ inputs.p11lab_ref }}"}, job_name
    assert head["run"] == HEAD_RUN, "control HEAD guard in " + job_name
    setup = steps["Set up Python"]
    assert setup["uses"] == SETUP_PYTHON, job_name
    assert setup["with"] == {"python-version": PYTHON_VERSION}, job_name


def _check_execution_producer_download(job, job_name):
    download = next(
        s for s in job["steps"] if s.get("name") == "Download producer artifact"
    )
    assert download["uses"] == DOWNLOAD_ARTIFACT, job_name
    assert download["with"] == {
        "name": "p11lab-proxy-dist-${{ inputs.proxy_sha }}-${{ github.run_attempt }}",
        "path": "${{ runner.temp }}/proxy-producer",
    }, "same-run producer download in " + job_name


def _check_execution_workflow(doc, text):
    assert set(doc) == {"name", "on", "permissions", "jobs"}, "top-level keys"
    assert doc["name"] == "proxy-round-execution"
    assert doc["permissions"] == {}, "top-level permissions minimal"
    assert set(doc["on"]) == {"workflow_call"}, "reusable-only trigger"
    call = doc["on"]["workflow_call"]
    assert set(call) == {"inputs", "outputs"}, "call interface keys"
    assert set(call["inputs"]) == {
        "proxy_sha",
        "tier",
        "p11lab_ref",
    }, "exactly three inputs"
    assert all(
        v == {"required": True, "type": "string"}
        for v in call["inputs"].values()
    ), "input shape"
    assert set(call["outputs"]) == set(OUTPUTS), "exactly three outputs"
    for name in OUTPUTS:
        assert call["outputs"][name] == {
            "value": "${{ jobs.aggregate.outputs['" + name + "'] }}"
        }, "output mapping " + name
    jobs = doc["jobs"]
    assert set(jobs) == set(JOBS), "frozen five-job roster"

    validate = jobs["validate"]
    assert set(validate) == {"runs-on", "timeout-minutes", "permissions", "steps"}
    assert validate["runs-on"] == "ubuntu-24.04"
    assert validate["timeout-minutes"] == 10
    assert validate["permissions"] == {"contents": "read", "actions": "read"}
    assert [s.get("name") for s in validate["steps"]] == [
        "Validate input identities",
        "Checkout control source",
        "Verify control identity",
        "Set up Python",
        "Validate execution policy",
    ], "validate steps"
    _check_execution_guard(validate, "validate")
    _check_execution_checkout(validate, "validate")
    policy = validate["steps"][-1]
    assert policy["shell"] == "sh"
    assert policy["env"] == {
        "PROXY_SHA": "${{ inputs.proxy_sha }}",
        "TIER": "${{ inputs.tier }}",
        "P11LAB_REF": "${{ inputs.p11lab_ref }}",
    }, "policy env"
    for fragment in (
        'PYTHONPATH="$GITHUB_WORKSPACE/p11lab-control/src" python -',
        "from p11lab import proxy_policy",
        "proxy_policy.load_proxy_policy(os.environ['TIER'])",
        "loaded.tier_qualified is False",
        "policy_digest=",
        "expected_same_run_artifact=",
        "'p11lab-proxy-dist-'",
    ):
        assert fragment in policy["run"], "policy script keeps " + fragment

    for cell in CELLS:
        job = jobs[cell]
        assert set(job) == {
            "runs-on",
            "timeout-minutes",
            "permissions",
            "steps",
        }, "cell keys " + cell
        assert job["runs-on"] == "ubuntu-24.04", cell
        assert job["timeout-minutes"] == 10, cell
        assert job["permissions"] == {"contents": "read", "actions": "read"}, cell
        assert [s.get("name") for s in job["steps"]] == [
            "Validate input identities",
            "Checkout control source",
            "Verify control identity",
            "Set up Python",
            "Download producer artifact",
            "Execute one proxy cell",
            "Upload cell observation",
            "Report cell verdict",
        ], "cell steps " + cell
        _check_execution_guard(job, cell)
        _check_execution_checkout(job, cell)
        _check_execution_producer_download(job, cell)
        result = next(s for s in job["steps"] if s.get("id") == "result")
        assert result["shell"] == "sh", cell
        assert result["env"] == {
            "PROXY_SHA": "${{ inputs.proxy_sha }}",
            "RUN_ID": "${{ github.run_id }}",
            "RUN_ATTEMPT": "${{ github.run_attempt }}",
            "CELL": cell,
        }, "cell env routes exactly one cell: " + cell
        script = result["run"]
        assert script.count("proxy execute-cell") == 1, "one invocation " + cell
        for fragment in (
            'PYTHONPATH="$GITHUB_WORKSPACE/p11lab-control/src"',
            "python -m p11lab proxy execute-cell",
            '--cell "$CELL"',
            '"$ARTIFACT_DIR/cell-payload-$CELL.json"',
            "p11lab-proxy-dist-$PROXY_SHA-$RUN_ATTEMPT",
            "proxy-cell-$CELL",
            "row.json",
            "cell-$CELL.log",
            "cell_exit=",
            "cell_cause=",
            "missing-row",
            "typed_cause",
        ):
            assert fragment in script, "cell script keeps %s in %s" % (
                fragment,
                cell,
            )
        upload = next(
            s for s in job["steps"] if s.get("name") == "Upload cell observation"
        )
        assert upload["uses"] == UPLOAD_ARTIFACT, cell
        assert upload["with"] == {
            "name": "p11lab-proxy-cell-%s-${{ github.run_id }}-${{ github.run_attempt }}"
            % cell,
            "path": "${{ runner.temp }}/proxy-cell-%s" % cell,
            "if-no-files-found": "error",
            "retention-days": 14,
        }, "cell upload " + cell
        report = next(
            s for s in job["steps"] if s.get("name") == "Report cell verdict"
        )
        assert report["shell"] == "sh", cell
        assert report["env"] == {
            "CELL_EXIT": "${{ steps.result.outputs.cell_exit }}",
            "CELL_CAUSE": "${{ steps.result.outputs.cell_cause }}",
        }, "cell report env " + cell
        for fragment in (
            'case "$CELL_EXIT" in',
            "exit 0",
            "exit 1",
            "exit 2",
            "unexpected cell exit",
        ):
            assert fragment in report["run"], "cell report keeps %s in %s" % (
                fragment,
                cell,
            )

    agg = jobs["aggregate"]
    assert set(agg) == {
        "runs-on",
        "timeout-minutes",
        "if",
        "needs",
        "permissions",
        "outputs",
        "steps",
    }, "aggregate keys"
    assert agg["runs-on"] == "ubuntu-24.04"
    assert agg["timeout-minutes"] == 30, "aggregate timeout"
    assert agg["if"] == "always()", "aggregate always runs"
    assert agg["needs"] == [
        "validate",
        "direct",
        "accepted-proxy",
        "candidate-proxy",
    ], "aggregate needs all four"
    assert agg["permissions"] == {"contents": "read", "actions": "read"}
    assert set(agg["outputs"]) == set(OUTPUTS)
    for name in OUTPUTS:
        assert agg["outputs"][name] == (
            "${{ steps.result.outputs['" + name + "'] }}"
        ), "aggregate output " + name
    assert [s.get("name") for s in agg["steps"]] == [
        "Validate input identities",
        "Checkout control source",
        "Verify control identity",
        "Set up Python",
        "Download producer artifact",
        "Download cell observations",
        "Aggregate proxy observations",
        "Upload verdict row",
        "Upload proxy capsule",
        "Report proxy verdict",
    ], "aggregate steps"
    _check_execution_guard(agg, "aggregate")
    _check_execution_checkout(agg, "aggregate")
    _check_execution_producer_download(agg, "aggregate")
    downloads = next(
        s for s in agg["steps"] if s.get("name") == "Download cell observations"
    )
    assert downloads["id"] == "cells"
    assert downloads["shell"] == "sh"
    assert downloads["env"] == {
        "GH_TOKEN": "${{ github.token }}",
        "GH_REPO": "${{ github.repository }}",
        "RUN_ID": "${{ github.run_id }}",
        "RUN_ATTEMPT": "${{ github.run_attempt }}",
    }, "download env stays same-run"
    for fragment in (
        "command -v gh",
        'gh run download "$RUN_ID"',
        "p11lab-proxy-cell-",
        "--name",
        "--dir",
        '-name "$cell.json"',
        "missing=",
        "warning: cell",
        "ambiguous evidence",
    ):
        assert fragment in downloads["run"], "download script keeps " + fragment
    result = next(s for s in agg["steps"] if s.get("id") == "result")
    assert result["shell"] == "sh"
    assert result["env"] == {
        "PROXY_SHA": "${{ inputs.proxy_sha }}",
        "RUN_ID": "${{ github.run_id }}",
        "RUN_ATTEMPT": "${{ github.run_attempt }}",
        "CELL_RESULTS": CELL_RESULTS_ENV,
        "MISSING": "${{ steps.cells.outputs.missing }}",
    }, "aggregate env"
    script = result["run"]
    assert script.count("proxy aggregate") == 1, "one aggregation"
    for fragment in (
        "python -m p11lab proxy aggregate",
        "--cells-dir",
        "--comparison",
        "--budgets",
        "--cancelled",
        "--uploads-incomplete",
        "*cancelled*",
        "verdict-row.json",
        "proxy-capsule.json",
        "aggregate.log",
        "must stay unclaimed",
        "p11lab-proxy-capsule-",
        "'p11lab-proxy-capsule-' + os.environ['RUN_ID']",
        "'experiment_positive': 'false'",
        "result_sha256",
        "experiment_positive",
        "missing-row",
    ):
        assert fragment in script, "aggregate script keeps " + fragment
    row_upload = next(
        s for s in agg["steps"] if s.get("name") == "Upload verdict row"
    )
    assert row_upload["uses"] == UPLOAD_ARTIFACT
    assert row_upload["with"] == {
        "name": "p11lab-proxy-verdict-${{ github.run_id }}-${{ github.run_attempt }}",
        "path": "${{ runner.temp }}/proxy-aggregate/verdict-row.json",
        "if-no-files-found": "error",
        "retention-days": 14,
    }, "verdict row upload"
    capsule_upload = next(
        s for s in agg["steps"] if s.get("name") == "Upload proxy capsule"
    )
    assert capsule_upload["uses"] == UPLOAD_ARTIFACT
    assert capsule_upload["with"] == {
        "name": "p11lab-proxy-capsule-${{ github.run_id }}-${{ github.run_attempt }}",
        "path": "${{ runner.temp }}/proxy-aggregate/proxy-capsule.json",
        "if-no-files-found": "error",
        "retention-days": 14,
    }, "capsule upload"
    report = next(s for s in agg["steps"] if s.get("name") == "Report proxy verdict")
    assert report["shell"] == "sh"
    assert report["env"] == {
        "VERDICT_EXIT": "${{ steps.result.outputs.verdict_exit }}",
        "VERDICT_CAUSE": "${{ steps.result.outputs.typed_cause }}",
        "EVIDENCE_COMPLETE": "${{ steps.result.outputs.evidence_complete }}",
    }, "aggregate report env"
    for fragment in (
        'case "$VERDICT_EXIT" in',
        "evidence_complete=",
        "exit 0",
        "exit 1",
        "exit 2",
        "unexpected verdict exit",
    ):
        assert fragment in report["run"], "aggregate report keeps " + fragment

    assert "secrets" not in text, "no secrets anywhere"
    assert "pull_request_target" not in text, "never executes a PR target"
    assert "pip install" not in text, "loads from control only"
    assert "CKR_" not in text, "no guessed rejection values"
    assert "not-executed" not in text, "operational path executes"
    assert "experiment-positive=true" not in text, "never claims positive"
    assert "exit 3" not in text, "proxy exits are 1/2, never checker 3"
    assert "execute_proxy_experiment" not in text, "no whole-experiment loop"
    assert "executor" not in text, "aggregate takes no executor"
    for job_name, job in jobs.items():
        for step in job.get("steps", []):
            assert "if" not in step, "no step-level bypass in %s" % job_name
            assert "continue-on-error" not in step, "no soft failure in %s" % (
                job_name
            )
            if "uses" in step:
                assert re.fullmatch(
                    r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", step["uses"]
                ), "full-SHA pin " + step["uses"]
                assert step["uses"] in EXECUTION_USES, "frozen pin " + step["uses"]
            if "run" in step:
                assert "${{ inputs." not in step["run"], (
                    "dispatch inputs reach shell only via env in %s" % job_name
                )
            if step.get("shell") is not None:
                assert step["shell"] == "sh", "POSIX shell in %s" % job_name


def test_execution_contract_accepts_workflow():
    text = _execution_workflow_text()
    _check_execution_workflow(_execution_workflow_doc(text), text)


def test_execution_on_stays_a_string_key():
    assert "on" in _execution_workflow_doc()


def test_execution_bare_python_requires_setup_python():
    doc = _execution_workflow_doc()
    violations = []
    for job_name, job in doc["jobs"].items():
        steps = job.get("steps", [])
        has_setup = any(
            s.get("uses", "").startswith("actions/setup-python@")
            for s in steps
        )
        for step in steps:
            if BARE_PYTHON.search(step.get("run", "")) and not has_setup:
                violations.append(
                    "%s: %s" % (job_name, step.get("name", step.get("id")))
                )
    assert violations == [], (
        "bare-PATH python without setup-python: %s" % ", ".join(violations)
    )


def test_execution_duplicate_key_is_rejected():
    with pytest.raises(Exception):
        _loads(_execution_workflow_text() + "\npermissions: {}\n")


def _mutated_execution_rejects(old, new, count=1):
    text = _execution_workflow_text()
    assert old in text, "mutation anchor missing: %r" % old
    mutated = text.replace(old, new, count)
    with pytest.raises(Exception):
        _check_execution_workflow(_loads(mutated), mutated)


@pytest.mark.parametrize(
    ("old", "new"),
    [
        (
            "      p11lab_ref:\n",
            "      advisory:\n        required: false\n        type: string\n"
            "      p11lab_ref:\n",
        ),
        (CHECKOUT, "actions/checkout@v4"),
        (SETUP_PYTHON, "actions/setup-python@v5"),
        (UPLOAD_ARTIFACT, "actions/upload-artifact@v4"),
        (DOWNLOAD_ARTIFACT, "actions/download-artifact@v4"),
        ("repository: p11lab/p11lab", "repository: attacker/control"),
        ("ref: ${{ inputs.p11lab_ref }}", "ref: main"),
        ("path: p11lab-control", "path: control"),
        ("persist-credentials: false", "persist-credentials: true"),
        (
            'test "${#PROXY_SHA}" -eq 40',
            'test "${{ inputs.proxy_sha }}" != ""',
        ),
        ("  validate:\n", "  validate_disabled:\n"),
        ("  direct:\n", "  direct_disabled:\n"),
        ("  accepted-proxy:\n", "  accepted-proxy_disabled:\n"),
        ("  candidate-proxy:\n", "  candidate-proxy_disabled:\n"),
        ("  aggregate:\n", "  aggregate_disabled:\n"),
        (
            "'experiment_positive': 'false'",
            "'experiment_positive': 'true'",
        ),
        (
            "'p11lab-proxy-capsule-' + os.environ['RUN_ID']",
            "'p11lab-proxy-capsule-x-' + os.environ['RUN_ID']",
        ),
        ("permissions: {}", "permissions: {}\nsecrets: inherit"),
        ("GH_TOKEN: ${{ github.token }}", "GH_TOKEN: ${{ secrets.GH_TOKEN }}"),
        ("contents: read", "contents: write"),
        ("if: always()", "if: success()"),
        ("        id: inputs\n", "        id: inputs\n        if: false\n"),
        (
            "        id: result\n",
            "        id: result\n        continue-on-error: true\n",
        ),
        (
            "        id: cells\n",
            "        id: cells\n        continue-on-error: true\n",
        ),
        ("timeout-minutes: 30", "timeout-minutes: 60"),
        ("retention-days: 14", "retention-days: 1"),
        ("python-version: '3.12.14'", "python-version: '3.12'"),
        ("in proxy-diagnostic-v1)", "in proxy-diagnostic-v1|*)"),
        ("*[!0-9a-f]*", "*"),
        ("          CELL: direct\n", "          CELL: accepted-proxy\n"),
        ('--cell "$CELL"', "--cell candidate-proxy"),
        (
            '--output-json "$CELL_DIR/row.json"',
            '--output-json "$CELL_DIR/row.json"\n'
            '          python -m p11lab proxy execute-cell --cell "$CELL"',
        ),
        (
            "name: proxy-round-execution",
            "name: proxy-round-execution\n# not-executed",
        ),
        (
            "name: proxy-round-execution",
            "name: proxy-round-execution\n# experiment-positive=true",
        ),
        (
            'echo "refused: $CELL_CAUSE" >&2; exit 2',
            'echo "refused: $CELL_CAUSE" >&2; exit 3',
        ),
        ("needs.direct.result", "needs.direct.outputs"),
        ("*cancelled*", "*success*"),
        (" --uploads-incomplete", ""),
        (" --cancelled", ""),
        ('gh run download "$RUN_ID"', 'gh run download "123"'),
        (
            "python -m p11lab proxy aggregate",
            "python -m p11lab proxy aggregate --executor x",
        ),
        ("      - candidate-proxy\n", ""),
        ("shell: sh", "shell: bash"),
        (
            'PYTHONPATH="$GITHUB_WORKSPACE/p11lab-control/src" python -',
            "pip install p11lab\n          python -",
        ),
        (
            "p11lab-proxy-dist-${{ inputs.proxy_sha }}",
            "p11lab-proxy-dist-${{ github.run_id }}",
        ),
        ("          MISSING: ${{ steps.cells.outputs.missing }}\n", ""),
    ],
)
def test_execution_contract_rejects_mutations(old, new):
    _mutated_execution_rejects(old, new)


@pytest.mark.parametrize(
    ("proxy", "tier", "control", "ok"),
    [
        (SHA_A, TIER, SHA_B, True),
        ("a" * 39, TIER, SHA_B, False),
        ("A" * 40, TIER, SHA_B, False),
        ("g" * 40, TIER, SHA_B, False),
        ("", TIER, SHA_B, False),
        (SHA_A, "pr-smoke", SHA_B, False),
        (SHA_A, "nightly", SHA_B, False),
        (SHA_A, "release", SHA_B, False),
        (SHA_A, "main", SHA_B, False),
        (SHA_A, "", SHA_B, False),
        (SHA_A, TIER, "main", False),
        (SHA_A, TIER, "b" * 39, False),
    ],
)
def test_execution_runtime_input_guard(proxy, tier, control, ok):
    doc = _execution_workflow_doc()
    step = next(
        x
        for x in doc["jobs"]["validate"]["steps"]
        if x.get("id") == "inputs"
    )
    env = dict(os.environ, PROXY_SHA=proxy, TIER=tier, P11LAB_REF=control)
    result = subprocess.run(
        ["sh", "-e", "-c", step["run"]], env=env, capture_output=True, text=True
    )
    assert (result.returncode == 0) == ok


@pytest.mark.parametrize("job", ("direct", "accepted-proxy", "candidate-proxy", "aggregate"))
@pytest.mark.parametrize(
    ("proxy", "tier", "control", "ok"),
    [(SHA_A, TIER, SHA_B, True), ("g" * 40, TIER, SHA_B, False),
     (SHA_A, "release", SHA_B, False)],
)
def test_execution_job_guards_match_validate(job, proxy, tier, control, ok):
    doc = _execution_workflow_doc()
    step = next(
        x for x in doc["jobs"][job]["steps"] if x.get("id") == "inputs"
    )
    assert step["run"] == GUARD_RUN, "identical guard in " + job
    env = dict(os.environ, PROXY_SHA=proxy, TIER=tier, P11LAB_REF=control)
    result = subprocess.run(
        ["sh", "-e", "-c", step["run"]], env=env, capture_output=True, text=True
    )
    assert (result.returncode == 0) == ok


def test_execution_control_head_guard_rejects_wrong_revision(tmp_path):
    subprocess.run(
        ["git", "init", "-q", str(tmp_path / "p11lab-control")], check=True
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(tmp_path / "p11lab-control"),
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "--allow-empty",
            "-qm",
            "fixture",
        ],
        check=True,
    )
    head = subprocess.check_output(
        ["git", "-C", str(tmp_path / "p11lab-control"), "rev-parse", "HEAD"],
        text=True,
    ).strip()
    doc = _execution_workflow_doc()
    step = next(
        x
        for x in doc["jobs"]["aggregate"]["steps"]
        if x.get("name") == "Verify control identity"
    )
    for ref, expected in [(head, 0), (SHA_A, 1)]:
        result = subprocess.run(
            ["sh", "-e", "-c", step["run"]],
            cwd=tmp_path,
            env=dict(os.environ, P11LAB_REF=ref),
        )
        assert result.returncode == expected


def test_execution_validate_policy_step_echoes_digest(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "p11lab-control").symlink_to(ROOT, target_is_directory=True)
    doc = _execution_workflow_doc()
    step = next(
        x
        for x in doc["jobs"]["validate"]["steps"]
        if x.get("name") == "Validate execution policy"
    )
    env = _hermetic_env(
        tmp_path,
        PROXY_SHA=SHA_A,
        P11LAB_REF=SHA_B,
        TIER=TIER,
        GITHUB_RUN_ATTEMPT="1",
    )
    proc = subprocess.run(
        ["sh", "-e", "-c", step["run"]],
        env=env,
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert "policy_digest=" in proc.stdout
    assert "provider=softhsm2/release/linux/amd64" in proc.stdout
    assert (
        "expected_same_run_artifact=p11lab-proxy-dist-" + SHA_A + "-1"
    ) in proc.stdout


def _w2_read_json(path):
    import json

    return json.loads(Path(path).read_text(encoding="utf-8"))


def _w2_write_json(path, value):
    import json

    Path(path).write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _w2_record(sha, run_id, attempt, **overrides):
    row = {
        "sha": sha,
        "run_id": run_id,
        "run_attempt": attempt,
        "name": "p11lab-proxy-dist-%s-%d" % (sha, attempt),
        **W2_AUTHORITY,
    }
    row.update(overrides)
    return row


def _w2_default_record():
    return tls_module.DEFAULT_PROXY_BUILD_IDENTITY().to_dict()


def _w2_payload_digests():
    import hashlib

    return {
        role: (len(data), hashlib.sha256(data).hexdigest())
        for role, data in (
            ("daemon", (W2_FIXTURES / "daemon.bin").read_bytes()),
            ("cli", (W2_FIXTURES / "cli.bin").read_bytes()),
            ("shim", (W2_FIXTURES / "shim.bin").read_bytes()),
        )
    }


def _w2_synthetic(record):
    digests = _w2_payload_digests()
    record = copy.deepcopy(record)
    for role in ("daemon", "cli", "shim"):
        size, sha256 = digests[role]
        record[role] = dict(record[role])
        record[role]["size"] = size
        record[role]["sha256"] = sha256
    return ProxyBuildIdentityV1.from_dict(record).to_dict()


def _w2_daemon_claim(record):
    return {
        "schema_version": 1,
        "source_revision": record["source_commit"],
        "cargo_lock_sha256": record["cargo_lock_sha256"],
        "binaries": {
            "pkcs11-proxy-ng": record["daemon"]["sha256"],
            "pkcs11-proxy-ng-cli": record["cli"]["sha256"],
            "proxy-entrypoint.sh": record["entrypoint_sha256"],
        },
    }


def _w2_client_abi(record):
    abi = record["abi"]
    paths = (native_module.CLIENT_CLI, native_module.CLIENT_MODULE)
    return {
        "decision": abi["decision"],
        "runtime_qualification": abi["runtime_qualification"],
        "floors": {
            path: copy.deepcopy(abi["floors"][path]) for path in paths
        },
        "needed": {
            path: copy.deepcopy(abi["needed"][path]) for path in paths
        },
        "interpreters": {path: abi["interpreters"][path] for path in paths},
        "shim_exports": list(abi["shim_exports"]),
        "version_requirements": {
            path: copy.deepcopy(abi["version_requirements"][path])
            for path in paths
        },
        "symbol_versions": {
            path: copy.deepcopy(abi["symbol_versions"][path]) for path in paths
        },
    }


def _w2_client_manifest(record, abi=None):
    archive = record["source_archive"]
    proxy = {
        "source_revision": record["source_commit"],
        "source_archive_sha256": archive["sha256"] if archive else None,
        "cargo_lock_sha256": record["cargo_lock_sha256"],
        "shim_sha256": record["shim"]["sha256"],
        "cli_sha256": record["cli"]["sha256"],
        "identity": copy.deepcopy(record),
        "abi_observed": (
            copy.deepcopy(abi) if abi is not None else _w2_client_abi(record)
        ),
    }
    return {
        "role": "native-client",
        "target": native_module.CLIENT_TARGET,
        "module": native_module.CLIENT_MODULE,
        "host_requirements": copy.deepcopy(
            native_module.CLIENT_HOST_REQUIREMENTS
        ),
        "source": {"proxy": proxy},
        "files": [
            {
                "path": native_module.CLIENT_MODULE,
                "sha256": record["shim"]["sha256"],
            },
            {
                "path": native_module.CLIENT_CLI,
                "sha256": record["cli"]["sha256"],
            },
        ],
        "environment": "softhsm2",
        "channel": "release",
    }


def _w2_launch_rehashes(record):
    return {
        "shim_sha256": record["shim"]["sha256"],
        "cli_sha256": record["cli"]["sha256"],
    }


def _w2_daemon_image(*, observed=None):
    reference = "sha256:" + "a" * 64
    return {
        "selected": reference,
        "observed": reference if observed is None else observed,
    }


def _w2_child_inspection(*, layers=None):
    if layers is None:
        layers = list(derivative_module.load_parent_selection()["layers"]) + [
            "sha256:" + "8" * 64
        ]
    return {"RootFS": {"Layers": layers}}


def _w2_stage_artifact(root, name, **overrides):
    record = _w2_synthetic(_w2_default_record())
    staged = Path(root) / name
    staged.mkdir(parents=True)
    _w2_write_json(
        staged / "records.json",
        overrides.get(
            "records",
            [_w2_record(record["source_commit"], W2_RUN_ID, W2_RUN_ATTEMPT)],
        ),
    )
    _w2_write_json(
        staged / "authority.json",
        overrides.get("authority", dict(W2_AUTHORITY)),
    )
    manifest = overrides.get("manifest")
    if manifest is None:
        manifest = _w2_read_json(W2_FIXTURES / "manifest.json")
        manifest["source_commit"] = record["source_commit"]
        manifest["run_id"] = W2_RUN_ID
        manifest["run_attempt"] = W2_RUN_ATTEMPT
        manifest["caller_repository_id"] = W2_AUTHORITY["repository_id"]
        manifest["caller_repository_full_name"] = W2_AUTHORITY[
            "repository_full_name"
        ]
        manifest["build_job_id"] = W2_AUTHORITY["producer_job_id"]
    _w2_write_json(staged / "manifest.json", manifest)
    for role in ("daemon", "cli", "shim"):
        path = manifest[role + "_path"]
        assert ".." not in path.split("/") and not path.startswith("/")
        (staged / path).write_bytes((W2_FIXTURES / path).read_bytes())
    _w2_write_json(
        staged / "daemon_build.json",
        overrides.get("daemon_build", _w2_daemon_claim(record)),
    )
    _w2_write_json(
        staged / "client_manifest.json",
        overrides.get("client_manifest", _w2_client_manifest(record)),
    )
    _w2_write_json(
        staged / "launch_rehashes.json",
        overrides.get("rehashes", _w2_launch_rehashes(record)),
    )
    _w2_write_json(
        staged / "abi_observed.json",
        overrides.get("abi", _w2_client_abi(record)),
    )
    _w2_write_json(
        staged / "daemon_image.json",
        overrides.get("daemon_image", _w2_daemon_image()),
    )
    _w2_write_json(
        staged / "child_inspection.json",
        overrides.get("child_inspection", _w2_child_inspection()),
    )
    (staged / "parent_ref.txt").write_text(
        overrides.get(
            "parent_ref",
            derivative_module.load_parent_selection()["local_engine_id"],
        ),
        encoding="utf-8",
    )
    _w2_write_json(
        staged / "expected_identity.json",
        overrides.get("expected_identity", record),
    )
    return staged


def _w2_honest_name():
    sha = _w2_default_record()["source_commit"]
    return "p11lab-proxy-dist-%s-%d" % (sha, W2_RUN_ATTEMPT)


def _w2_spec_doc(**overrides):
    doc = {
        "environment": "softhsm2",
        "channel": "release",
        "mode": "proxy",
        "artifact": {
            "kind": "image",
            "reference": "sha256:" + "0" * 64,
            "sha256": "0" * 64,
            "platform": "linux/amd64",
        },
        "execution_location": "container",
        "consumer_artifact": None,
        "client_artifact": None,
        "argv": ["round-harness", "--cell", "candidate-proxy"],
        "inputs": {"P11LAB_HARNESS_SEED": "w2-synthetic"},
        "timeout_seconds": 300,
    }
    doc.update(overrides)
    return doc


def _w2_proxy_payload_doc(**overrides):
    doc = {
        "spec": _w2_spec_doc(**overrides.pop("spec", {})),
        "plan": {"descriptor": {"inputs": {}}, "host": True},
        "log_refs": ["cell-logs/candidate-proxy/client.log"],
    }
    doc.update(overrides)
    return doc


def _w2_run_cell_step(tmp_path, cell, *, stage_overrides=None, payload=None):
    doc = _execution_workflow_doc()
    step = next(
        x for x in doc["jobs"][cell]["steps"] if x.get("id") == "result"
    )
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    control = workspace / "p11lab-control"
    if not control.exists():
        control.symlink_to(ROOT, target_is_directory=True)
    producer = tmp_path / "proxy-producer"
    staged = _w2_stage_artifact(
        producer, _w2_honest_name(), **(stage_overrides or {})
    )
    if payload is None:
        payload = _w2_proxy_payload_doc()
    _w2_write_json(staged / ("cell-payload-%s.json" % cell), payload)
    output = tmp_path / "output"
    output.touch()
    env = _hermetic_env(
        tmp_path,
        PROXY_SHA=_w2_default_record()["source_commit"],
        RUN_ID=str(W2_RUN_ID),
        RUN_ATTEMPT=str(W2_RUN_ATTEMPT),
        CELL=cell,
        GITHUB_OUTPUT=str(output),
    )
    proc = subprocess.run(
        ["sh", "-e", "-c", step["run"]],
        env=env,
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    outputs = dict(
        line.split("=", 1) for line in output.read_text().splitlines() if "=" in line
    )
    return proc, tmp_path / ("proxy-cell-" + cell), outputs


@pytest.mark.parametrize("cell", ("accepted-proxy", "candidate-proxy"))
def test_execution_cell_step_refuses_ms_a(tmp_path, cell):
    import json

    record = _w2_synthetic(_w2_default_record())
    claim = _w2_daemon_claim(record)
    claim["source_revision"] = "a" * 40
    proc, outdir, outputs = _w2_run_cell_step(
        tmp_path, cell, stage_overrides={"daemon_build": claim}
    )
    assert proc.returncode == 0, proc.stderr
    assert outputs["cell_exit"] == "1"
    assert outputs["cell_cause"] == "PROXY_GATE_IDENTITY_REFUSED"
    row = json.loads((outdir / "row.json").read_text())
    assert row["exit_code"] == 1
    assert row["cause"] == "PROXY_GATE_IDENTITY_REFUSED"
    assert (
        row["cause_detail"]
        == "proxy identity mismatch: daemon.source_revision"
    )
    assert not (outdir / (cell + ".json")).exists(), "no observation on refusal"
    assert (outdir / "proxy-gated.json").exists()
    assert (outdir / ("cell-%s.log" % cell)).exists()


def test_execution_cell_step_refuses_ms_b(tmp_path):
    import json

    record = _w2_synthetic(_w2_default_record())
    manifest = _w2_client_manifest(record)
    manifest["source"]["proxy"]["identity"]["source_commit"] = "b" * 40
    proc, outdir, outputs = _w2_run_cell_step(
        tmp_path,
        "candidate-proxy",
        stage_overrides={"client_manifest": manifest},
    )
    assert proc.returncode == 0, proc.stderr
    assert outputs["cell_exit"] == "1"
    assert outputs["cell_cause"] == "PROXY_GATE_INSTALL_REFUSED"
    row = json.loads((outdir / "row.json").read_text())
    assert row["exit_code"] == 1
    assert row["cause"] == "PROXY_GATE_INSTALL_REFUSED"
    assert (
        row["cause_detail"]
        == "proxy identity mismatch: client_manifest.identity.source_commit"
    )
    assert not (outdir / "candidate-proxy.json").exists()


def test_execution_cell_step_refuses_wp_parent(tmp_path):
    import json

    proc, outdir, outputs = _w2_run_cell_step(
        tmp_path,
        "candidate-proxy",
        stage_overrides={"parent_ref": "sha256:" + "9" * 64},
    )
    assert proc.returncode == 0, proc.stderr
    assert outputs["cell_exit"] == "1"
    assert outputs["cell_cause"] == "PROXY_GATE_DERIVATIVE_REFUSED"
    row = json.loads((outdir / "row.json").read_text())
    assert row["cause_detail"] == "proxy derivative build mismatch: parent_ref"
    assert not (outdir / "candidate-proxy.json").exists()


def test_execution_cell_step_refuses_wp_layers(tmp_path):
    import json

    proc, outdir, outputs = _w2_run_cell_step(
        tmp_path,
        "candidate-proxy",
        stage_overrides={
            "child_inspection": {
                "RootFS": {"Layers": ["sha256:" + "9" * 64]}
            }
        },
    )
    assert proc.returncode == 0, proc.stderr
    assert outputs["cell_exit"] == "1"
    assert outputs["cell_cause"] == "PROXY_GATE_DERIVATIVE_REFUSED"
    row = json.loads((outdir / "row.json").read_text())
    assert (
        row["cause_detail"]
        == "proxy derivative parent mismatch: child.RootFS.Layers"
    )
    assert not (outdir / "candidate-proxy.json").exists()


def test_execution_cell_step_usage_bad_payload(tmp_path):
    proc, outdir, outputs = _w2_run_cell_step(
        tmp_path, "candidate-proxy", payload={"bogus": True}
    )
    assert proc.returncode == 0, proc.stderr
    assert outputs["cell_exit"] == "2"
    assert outputs["cell_cause"] == "missing-row"
    assert not outdir.exists(), "usage writes no output dir"
    log = (tmp_path / "cell-candidate-proxy.log").read_text()
    assert "staged cell payload keys must be exactly" in log


def test_execution_direct_cell_routes_through_cli(tmp_path):
    payload = {
        "spec": _w2_spec_doc(mode="proxy"),
        "installed_prefix": "/nonexistent-w2-prefix",
        "log_refs": ["cell-logs/direct/client.log"],
    }
    proc, outdir, outputs = _w2_run_cell_step(
        tmp_path, "direct", payload=payload
    )
    assert proc.returncode == 0, proc.stderr
    assert outputs["cell_exit"] == "2"
    assert outputs["cell_cause"] == "missing-row"
    assert not outdir.exists(), "usage writes no output dir"
    log = (tmp_path / "cell-direct.log").read_text()
    assert "mismatches cell direct" in log


@pytest.mark.parametrize(
    ("exit_code", "cause", "expected", "stderr"),
    [
        ("0", "PROXY_CELL_OK", 0, ""),
        (
            "1",
            "PROXY_GATE_IDENTITY_REFUSED",
            1,
            "refused: PROXY_GATE_IDENTITY_REFUSED",
        ),
        ("2", "usage-or-infrastructure", 2, "refused: usage-or-infrastructure"),
        ("139", "missing-row", 2, "unexpected cell exit: 139"),
    ],
)
def test_execution_cell_report_propagates_exits(
    tmp_path, exit_code, cause, expected, stderr
):
    doc = _execution_workflow_doc()
    step = next(
        x
        for x in doc["jobs"]["candidate-proxy"]["steps"]
        if x.get("name") == "Report cell verdict"
    )
    env = dict(os.environ, CELL_EXIT=exit_code, CELL_CAUSE=cause)
    proc = subprocess.run(
        ["sh", "-e", "-c", step["run"]],
        env=env,
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == expected
    if stderr:
        assert stderr in proc.stderr
    else:
        assert proc.stderr == ""


_W2_STUB_GH = """#!/bin/sh
# Stub gh: serves planted artifact trees, fails stub-missing names.
name=""
dir=""
while [ $# -gt 0 ]; do
  case "$1" in
    --name) name="$2"; shift 2 ;;
    --dir) dir="$2"; shift 2 ;;
    *) shift ;;
  esac
done
case " $GH_STUB_MISSING " in
  *" $name "*) echo "stub: no artifact $name" >&2; exit 1 ;;
esac
cp -r "$GH_STUB_SRC/$name/." "$dir/"
"""


def _w2_cell_artifact_name(cell):
    return "p11lab-proxy-cell-%s-%d-%d" % (cell, W2_RUN_ID, W2_RUN_ATTEMPT)


def _w2_run_download_step(tmp_path, *, plant, missing_env="", scrub_gh=False):
    import json
    import stat

    doc = _execution_workflow_doc()
    step = next(
        x for x in doc["jobs"]["aggregate"]["steps"] if x.get("id") == "cells"
    )
    src = tmp_path / "planted"
    for cell, layout in plant.items():
        for relpath in layout:
            target = src / _w2_cell_artifact_name(cell) / relpath
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps({"probe": cell}) + "\n")
    output = tmp_path / "output"
    output.touch()
    env = _hermetic_env(
        tmp_path,
        GH_TOKEN="w2-token",
        GH_REPO="example/proxy-workflow-cells",
        RUN_ID=str(W2_RUN_ID),
        RUN_ATTEMPT=str(W2_RUN_ATTEMPT),
        GITHUB_OUTPUT=str(output),
        GH_STUB_SRC=str(src),
        GH_STUB_MISSING=missing_env,
    )
    bindir = tmp_path / "bin"
    shell = ["sh", "-e", "-c", step["run"]]
    if scrub_gh:
        import shutil

        sh_binary = shutil.which("sh")
        assert sh_binary is not None, "host lacks sh"
        shell = [sh_binary, "-e", "-c", step["run"]]
        for tool in ("find", "sort", "grep", "cp", "mkdir"):
            resolved = shutil.which(tool)
            assert resolved is not None, "host lacks " + tool
            (bindir / tool).symlink_to(resolved)
        env["PATH"] = str(bindir)
    else:
        stub = bindir / "gh"
        stub.write_text(_W2_STUB_GH)
        stub.chmod(stub.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    proc = subprocess.run(
        shell,
        env=env,
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    outputs = dict(
        line.split("=", 1) for line in output.read_text().splitlines() if "=" in line
    )
    return proc, tmp_path / "proxy-cells", outputs


def test_execution_download_assembles_present_cells(tmp_path):
    proc, cells, outputs = _w2_run_download_step(
        tmp_path,
        plant={
            "direct": ["nested/deep/direct.json"],
            "accepted-proxy": ["accepted-proxy.json"],
            "candidate-proxy": ["candidate-proxy.json"],
        },
    )
    assert proc.returncode == 0, proc.stderr
    assert outputs["missing"] == ""
    for cell in CELLS:
        assert (cells / (cell + ".json")).exists(), cell


def test_execution_download_tolerates_missing_cell(tmp_path):
    proc, cells, outputs = _w2_run_download_step(
        tmp_path,
        plant={
            "direct": ["direct.json"],
            "accepted-proxy": ["accepted-proxy.json"],
        },
        missing_env=_w2_cell_artifact_name("candidate-proxy"),
    )
    assert proc.returncode == 0, proc.stderr
    assert outputs["missing"] == "candidate-proxy"
    assert "warning: cell candidate-proxy" in proc.stderr
    assert (cells / "direct.json").exists()
    assert (cells / "accepted-proxy.json").exists()
    assert not (cells / "candidate-proxy.json").exists()


def test_execution_download_rejects_ambiguous_evidence(tmp_path):
    proc, _cells, _outputs = _w2_run_download_step(
        tmp_path,
        plant={
            "direct": ["direct.json", "sub/direct.json"],
            "accepted-proxy": ["accepted-proxy.json"],
            "candidate-proxy": ["candidate-proxy.json"],
        },
    )
    assert proc.returncode == 2
    assert "ambiguous evidence for cell direct" in proc.stderr


def test_execution_download_requires_gh(tmp_path):
    proc, _cells, _outputs = _w2_run_download_step(
        tmp_path,
        plant={cell: [cell + ".json"] for cell in CELLS},
        scrub_gh=True,
    )
    assert proc.returncode == 2
    assert "require gh" in proc.stderr


def _w2_observation(cell, shape):
    base = {
        "admitted": True,
        "attribution_usable": True,
        "cell": cell,
        "complete": True,
        "findings": [],
        "log_refs": ["cell-logs/%s/client.log" % cell],
        "logs_available": True,
        "terminal_evidence_complete": True,
        "unexpected_death": False,
    }
    if shape == "crash":
        base.update(
            findings=["client-exit:137"],
            log_refs=[
                "cell-logs/%s/client.log" % cell,
                "cell-logs/%s/daemon.log" % cell,
            ],
            unexpected_death=True,
        )
    elif shape == "no-logs":
        base.update(
            findings=["client-exit:137"],
            log_refs=[],
            logs_available=False,
            terminal_evidence_complete=False,
            unexpected_death=True,
        )
    elif shape != "clean":
        raise AssertionError("unknown shape " + shape)
    obs = proxy_execute_module.CellObservation.from_dict(
        dict(base), run_id=W2_RUN_ID, run_attempt=W2_RUN_ATTEMPT
    )
    return dict(obs.to_dict(), run_id=W2_RUN_ID, run_attempt=W2_RUN_ATTEMPT)


def _w2_gates():
    return [
        {"gate": gate, "cause": "PROXY_GATE_OK", "cause_detail": None}
        for gate in ("selection", "bytes", "install", "identity", "derivative")
    ]


def _w2_selection():
    return {
        "artifact_id": W2_AUTHORITY["artifact_id"],
        "name": _w2_honest_name(),
        "producer_job_id": W2_AUTHORITY["producer_job_id"],
        "repository_full_name": W2_AUTHORITY["repository_full_name"],
        "repository_id": W2_AUTHORITY["repository_id"],
        "run_attempt": W2_RUN_ATTEMPT,
        "run_id": W2_RUN_ID,
        "sha": _w2_default_record()["source_commit"],
    }


def _w2_cell_record(cell, shape):
    obs = _w2_observation(cell, shape)
    return {
        "schema": proxy_execute_module.CELL_OBSERVATION_SCHEMA,
        "artifact": _w2_honest_name(),
        "proxy_sha": _w2_default_record()["source_commit"],
        "run_id": W2_RUN_ID,
        "run_attempt": W2_RUN_ATTEMPT,
        "cell": cell,
        "status": "executed",
        "observation": obs,
        "log_refs": list(obs["log_refs"]),
        "infrastructure_error": None,
        "gates": _w2_gates(),
        "selection": _w2_selection(),
    }


def _w2_executor_failed_record(cell):
    return {
        "schema": proxy_execute_module.CELL_OBSERVATION_SCHEMA,
        "artifact": _w2_honest_name(),
        "proxy_sha": _w2_default_record()["source_commit"],
        "run_id": W2_RUN_ID,
        "run_attempt": W2_RUN_ATTEMPT,
        "cell": cell,
        "status": "executor-failed",
        "observation": None,
        "log_refs": [],
        "infrastructure_error": "cell %s executor failed: fake boom w2" % cell,
        "gates": _w2_gates(),
        "selection": _w2_selection(),
    }


def _w2_run_aggregate_step(
    tmp_path,
    mapping,
    *,
    comparison=None,
    budgets=None,
    cell_results="success/success/success",
    missing="",
):
    doc = _execution_workflow_doc()
    step = next(
        x for x in doc["jobs"]["aggregate"]["steps"] if x.get("id") == "result"
    )
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    control = workspace / "p11lab-control"
    if not control.exists():
        control.symlink_to(ROOT, target_is_directory=True)
    producer = tmp_path / "proxy-producer" / _w2_honest_name()
    producer.mkdir(parents=True)
    _w2_write_json(
        producer / "comparison.json",
        (
            comparison
            if comparison is not None
            else {
                "performed": True,
                "positive": True,
                "coverage_positive": True,
            }
        ),
    )
    _w2_write_json(
        producer / "budgets.json",
        budgets if budgets is not None else {"within_budget": True},
    )
    cells = tmp_path / "proxy-cells"
    cells.mkdir()
    for cell, shape in mapping.items():
        if shape == "executor-failed":
            record = _w2_executor_failed_record(cell)
        else:
            record = _w2_cell_record(cell, shape)
        _w2_write_json(cells / (cell + ".json"), record)
    output = tmp_path / "output"
    output.touch()
    env = _hermetic_env(
        tmp_path,
        PROXY_SHA=_w2_default_record()["source_commit"],
        RUN_ID=str(W2_RUN_ID),
        RUN_ATTEMPT=str(W2_RUN_ATTEMPT),
        CELL_RESULTS=cell_results,
        MISSING=missing,
        GITHUB_OUTPUT=str(output),
    )
    proc = subprocess.run(
        ["sh", "-e", "-c", step["run"]],
        env=env,
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    outputs = dict(
        line.split("=", 1) for line in output.read_text().splitlines() if "=" in line
    )
    return proc, tmp_path / "proxy-aggregate", outputs


def _w2_assert_uploaded(aggdir, outputs, *, cause, complete):
    import hashlib
    import json

    assert outputs["typed_cause"] == cause
    assert outputs["evidence_complete"] == ("true" if complete else "false")
    assert outputs["experiment_positive"] == "false"
    expected_artifact = "p11lab-proxy-capsule-%d-%d" % (
        W2_RUN_ID,
        W2_RUN_ATTEMPT,
    )
    assert outputs["result_artifact"] == expected_artifact
    capsule_bytes = (aggdir / "proxy-capsule.json").read_bytes()
    assert outputs["result_sha256"] == hashlib.sha256(capsule_bytes).hexdigest()
    row = json.loads((aggdir / "verdict-row.json").read_text())
    assert row["verdict"]["typed_cause"] == (None if cause == "null" else cause)
    assert row["evidence_complete"] is complete
    assert row["experiment_positive"] is False
    capsule = json.loads(capsule_bytes.decode("utf-8"))
    assert capsule["experiment_positive"] is False
    return row


def test_execution_aggregate_f_crash_completed_negative(tmp_path):
    proc, aggdir, outputs = _w2_run_aggregate_step(
        tmp_path,
        {
            "direct": "clean",
            "accepted-proxy": "clean",
            "candidate-proxy": "crash",
        },
    )
    assert proc.returncode == 0, proc.stderr
    assert outputs["verdict_exit"] == "1"
    _w2_assert_uploaded(aggdir, outputs, cause="completed-negative", complete=True)


def test_execution_aggregate_f_noterm_incomplete(tmp_path):
    proc, aggdir, outputs = _w2_run_aggregate_step(
        tmp_path,
        {
            "direct": "clean",
            "accepted-proxy": "clean",
            "candidate-proxy": "no-logs",
        },
    )
    assert proc.returncode == 0, proc.stderr
    assert outputs["verdict_exit"] == "1"
    _w2_assert_uploaded(
        aggdir, outputs, cause="terminal-evidence-unavailable", complete=False
    )


def test_execution_aggregate_f_accept_control_unqualified(tmp_path):
    proc, aggdir, outputs = _w2_run_aggregate_step(
        tmp_path,
        {
            "direct": "clean",
            "accepted-proxy": "crash",
            "candidate-proxy": "crash",
        },
    )
    assert proc.returncode == 0, proc.stderr
    assert outputs["verdict_exit"] == "1"
    _w2_assert_uploaded(
        aggdir, outputs, cause="control-unqualified", complete=False
    )


def test_execution_aggregate_tpx_control_required_first(tmp_path):
    proc, aggdir, outputs = _w2_run_aggregate_step(
        tmp_path,
        {"direct": "clean", "candidate-proxy": "crash"},
    )
    assert proc.returncode == 0, proc.stderr
    assert outputs["verdict_exit"] == "1"
    _w2_assert_uploaded(aggdir, outputs, cause="missing-evidence", complete=False)


def test_execution_aggregate_missing_cell_is_t6(tmp_path):
    proc, aggdir, outputs = _w2_run_aggregate_step(
        tmp_path,
        {"direct": "clean", "accepted-proxy": "clean"},
    )
    assert proc.returncode == 0, proc.stderr
    assert outputs["verdict_exit"] == "1"
    _w2_assert_uploaded(aggdir, outputs, cause="missing-evidence", complete=False)


def test_execution_aggregate_missing_direct_is_t3(tmp_path):
    proc, aggdir, outputs = _w2_run_aggregate_step(
        tmp_path,
        {"accepted-proxy": "clean", "candidate-proxy": "clean"},
    )
    assert proc.returncode == 0, proc.stderr
    assert outputs["verdict_exit"] == "1"
    _w2_assert_uploaded(
        aggdir, outputs, cause="attribution-unknown", complete=False
    )


def test_execution_aggregate_executor_failed_is_t8(tmp_path):
    proc, aggdir, outputs = _w2_run_aggregate_step(
        tmp_path,
        {
            "direct": "clean",
            "accepted-proxy": "clean",
            "candidate-proxy": "executor-failed",
        },
    )
    assert proc.returncode == 0, proc.stderr
    assert outputs["verdict_exit"] == "2"
    row = _w2_assert_uploaded(
        aggdir, outputs, cause="usage-or-infrastructure", complete=False
    )
    assert row["exit_code"] == 2
    assert "fake boom w2" in row["infrastructure_error"]


def test_execution_aggregate_clean_trio_reports_unclaimed(tmp_path):
    proc, aggdir, outputs = _w2_run_aggregate_step(
        tmp_path,
        {cell: "clean" for cell in CELLS},
    )
    assert proc.returncode == 0, proc.stderr
    assert outputs["verdict_exit"] == "0"
    _w2_assert_uploaded(aggdir, outputs, cause="null", complete=True)


def test_execution_aggregate_cancelled_cells_flag(tmp_path):
    import json

    proc, aggdir, outputs = _w2_run_aggregate_step(
        tmp_path,
        {cell: "clean" for cell in CELLS},
        cell_results="success/cancelled/success",
    )
    assert proc.returncode == 0, proc.stderr
    assert outputs["verdict_exit"] == "1"
    row = json.loads((aggdir / "verdict-row.json").read_text())
    assert row["cancelled"] is True
    assert row["verdict"]["typed_cause"] == "missing-evidence"


def test_execution_aggregate_missing_cells_flag(tmp_path):
    import json

    proc, aggdir, outputs = _w2_run_aggregate_step(
        tmp_path,
        {cell: "clean" for cell in CELLS},
        missing="candidate-proxy",
    )
    assert proc.returncode == 0, proc.stderr
    assert outputs["verdict_exit"] == "1"
    row = json.loads((aggdir / "verdict-row.json").read_text())
    assert row["uploads_complete"] is False
    assert row["verdict"]["typed_cause"] == "missing-evidence"


def test_execution_aggregate_usage_bad_comparison(tmp_path):
    proc, aggdir, outputs = _w2_run_aggregate_step(
        tmp_path,
        {cell: "clean" for cell in CELLS},
        comparison={"performed": True},
    )
    assert proc.returncode == 0, proc.stderr
    assert outputs["verdict_exit"] == "2"
    assert outputs["typed_cause"] == "missing-row"
    assert outputs["evidence_complete"] == "false"
    assert outputs["result_artifact"] == ""
    assert outputs["result_sha256"] == ""
    assert outputs["experiment_positive"] == "false"
    assert not aggdir.exists(), "usage writes no output dir"
    log = (tmp_path / "aggregate.log").read_text()
    assert "comparison must bind" in log


@pytest.mark.parametrize(
    ("exit_code", "cause", "complete", "expected", "stderr"),
    [
        ("0", "null", "true", 0, ""),
        (
            "1",
            "completed-negative",
            "true",
            1,
            "refused: completed-negative (evidence_complete=true)",
        ),
        (
            "1",
            "missing-evidence",
            "false",
            1,
            "refused: missing-evidence (evidence_complete=false)",
        ),
        (
            "1",
            "attribution-unknown",
            "false",
            1,
            "refused: attribution-unknown (evidence_complete=false)",
        ),
        (
            "2",
            "usage-or-infrastructure",
            "false",
            2,
            "refused: usage-or-infrastructure (evidence_complete=false)",
        ),
        ("99", "missing-row", "false", 2, "unexpected verdict exit: 99"),
    ],
)
def test_execution_aggregate_report_propagates_verdict(
    tmp_path, exit_code, cause, complete, expected, stderr
):
    doc = _execution_workflow_doc()
    step = next(
        x
        for x in doc["jobs"]["aggregate"]["steps"]
        if x.get("name") == "Report proxy verdict"
    )
    env = dict(
        os.environ,
        VERDICT_EXIT=exit_code,
        VERDICT_CAUSE=cause,
        EVIDENCE_COMPLETE=complete,
    )
    proc = subprocess.run(
        ["sh", "-e", "-c", step["run"]],
        env=env,
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == expected
    if stderr:
        assert stderr in proc.stderr
    else:
        assert proc.stderr == ""


def _execution_example_text():
    return EXECUTION_EXAMPLE.read_text()


def _execution_example_doc(text=None):
    raw = _execution_example_text() if text is None else text
    assert "UNPUBLISHED TEMPLATE" in raw, "caller stays an unpublished template"
    substituted = raw.replace("<P11LAB_COMMIT_SHA>", SHA_C).replace(
        "<PROXY_COMMIT_SHA>", SHA_B
    )
    return _loads(substituted), substituted


def _check_execution_example(doc, text):
    assert set(doc) == {"name", "on", "permissions", "jobs"}, "caller keys"
    assert doc["on"] == {"pull_request": None}, "caller trigger"
    assert "workflow_dispatch" not in text, "no dispatch path in caller"
    assert doc["permissions"] == {
        "contents": "read",
        "actions": "read",
    }, "caller permissions"
    assert set(doc["jobs"]) == {"execution"}, "caller job"
    caller = doc["jobs"]["execution"]
    assert set(caller) == {"permissions", "uses", "with"}, "caller job keys"
    assert caller["permissions"] == {"contents": "read", "actions": "read"}
    match = re.fullmatch(
        r"p11lab/p11lab/\.github/workflows/proxy-round-execution\.yml@([0-9a-f]{40})",
        caller["uses"],
    )
    assert match is not None, "caller uses pin"
    inputs = caller["with"]
    assert set(inputs) == {"proxy_sha", "tier", "p11lab_ref"}, "caller inputs"
    assert inputs["p11lab_ref"] == match.group(1), "caller pin equality"
    assert re.fullmatch(r"[0-9a-f]{40}", inputs["proxy_sha"]) is not None
    assert inputs["tier"] == TIER, "caller tier literal"
    assert "secrets" not in text, "no secrets in caller"
    assert "pull_request_target" not in text, "caller never runs a PR target"
    assert "token" not in text, "no dispatch tokens in caller"
    lowered = text.lower()
    for phrase in (
        "caller-owned producer",
        "not an operational honest control",
        "same-run current-attempt",
        "cell-payload-",
        "comparison.json",
        "budgets.json",
        "full-rerun",
        "rerun_requires_producer",
    ):
        assert phrase in lowered, "caller documents " + phrase


def test_execution_contract_accepts_example():
    doc, substituted = _execution_example_doc()
    _check_execution_example(doc, substituted)


@pytest.mark.parametrize(
    ("old", "new"),
    [
        (
            "p11lab_ref: <P11LAB_COMMIT_SHA>",
            "p11lab_ref: <PROXY_COMMIT_SHA>",
        ),
        ("tier: proxy-diagnostic-v1", "tier: pr-smoke"),
        ("@<P11LAB_COMMIT_SHA>", "@v4"),
        (
            "      tier: proxy-diagnostic-v1\n",
            "      tier: proxy-diagnostic-v1\n      advisory: x\n",
        ),
        ("  contents: read", "  contents: write"),
        (
            "permissions:\n  contents: read",
            "permissions:\n  contents: read\nsecrets: inherit",
        ),
        ("  pull_request:", "  workflow_dispatch:"),
        ("  pull_request:", "  pull_request_target:"),
        ("  actions: read\n", ""),
        ("caller-owned producer", "built-in producer"),
        (
            "NOT an operational honest control",
            "an operational honest control",
        ),
    ],
)
def test_execution_example_rejects_mutations(old, new):
    text = _execution_example_text()
    assert old in text, "mutation anchor missing: %r" % old
    mutated = text.replace(old, new, 1)
    with pytest.raises(Exception):
        doc, substituted = _execution_example_doc(mutated)
        _check_execution_example(doc, substituted)


@pytest.mark.skipif(
    os.environ.get("P11LAB_PROXY_EXECUTION_LIVE") != "1",
    reason="live proxy execution needs a test caller repo PR run and API access",
)
def test_live_proxy_execution_designed_not_run(tmp_path):
    """Env-gated live proof: fetch a completed test-repo PR run, assert the
    frozen five-artifact roster, and assert the capsule stays unclaimed.
    Requires P11LAB_PROXY_EXECUTION_REPO (owner/repo) and
    P11LAB_PROXY_EXECUTION_RUN (run id); authenticates with GITHUB_TOKEN.
    No published revision exists yet (ASK-9 deferred), so this stays
    designed-not-run."""
    import json
    import urllib.request
    import zipfile

    repo = os.environ["P11LAB_PROXY_EXECUTION_REPO"]
    run_id = os.environ["P11LAB_PROXY_EXECUTION_RUN"]
    token = os.environ["GITHUB_TOKEN"]
    base = "https://api.github.com/repos/%s/actions/runs/%s" % (repo, run_id)

    def call(path):
        request = urllib.request.Request(
            base + path,
            headers={
                "Authorization": "Bearer %s" % token,
                "Accept": "application/vnd.github+json",
            },
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode() or "null")

    run = call("")
    attempt = run["run_attempt"]
    names = {entry["name"] for entry in call("/artifacts")["artifacts"]}
    expected = {
        "p11lab-proxy-cell-%s-%s-%d" % (cell, run_id, attempt)
        for cell in ("direct", "accepted-proxy", "candidate-proxy")
    } | {
        "p11lab-proxy-verdict-%s-%d" % (run_id, attempt),
        "p11lab-proxy-capsule-%s-%d" % (run_id, attempt),
    }
    assert expected <= names, "frozen five-artifact roster"
    capsule_id = next(
        entry["id"]
        for entry in call("/artifacts")["artifacts"]
        if entry["name"] == "p11lab-proxy-capsule-%s-%d" % (run_id, attempt)
    )
    archive = tmp_path / "capsule.zip"
    request = urllib.request.Request(
        "https://api.github.com/repos/%s/actions/artifacts/%d/zip"
        % (repo, capsule_id),
        headers={"Authorization": "Bearer %s" % token},
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        archive.write_bytes(response.read())
    with zipfile.ZipFile(archive) as bundle:
        capsule = json.loads(bundle.read("proxy-capsule.json").decode())
    assert capsule["schema"] == "p11lab-proxy-experiment-result-v1"
    assert capsule["experiment_positive"] is False
    assert run["conclusion"] in ("success", "failure"), "run reached a verdict"
