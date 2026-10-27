"""Cheap Linux CI wiring: full test collection, pinned inputs, no publication."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import textwrap

import pytest

from p11lab.publish import ACTION_PINS

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/linux-unit-validation.yml"
REQUIREMENTS = ROOT / ".github/requirements/linux-unit.txt"


def workflow():
    assert WORKFLOW.is_file(), "the bounded Linux validation workflow is missing"
    return WORKFLOW.read_text()


def step(name):
    match = re.search(
        rf"^      - name: {re.escape(name)}\n(.*?)(?=^      - name: |\Z)",
        workflow(), re.MULTILINE | re.DOTALL,
    )
    assert match, name
    return match.group(1)


def python_script(name):
    match = re.search(
        r"^          python - <<'PY'\n(.*?)^          PY$",
        step(name), re.MULTILINE | re.DOTALL,
    )
    assert match, name
    return textwrap.dedent(match.group(1))


def test_linux_validation_is_one_bounded_read_only_job():
    text = workflow()
    events = re.search(r"^on:\n(.*?)(?=^\S)", text, re.M | re.S).group(1)
    assert re.findall(r"^  ([a-z_]+):", events, re.M) == ["pull_request", "workflow_dispatch"]
    assert "paths:" not in events
    assert "permissions:\n  contents: read\n" in text
    assert "persist-credentials: false" in step("Checkout P11Lab")
    assert re.findall(r"^  ([a-z-]+):\n    runs-on:", text, re.M) == ["validate"]
    assert "runs-on: ubuntu-24.04\n    timeout-minutes: 10\n" in text
    for forbidden in ("matrix:", "services:", "container:", "continue-on-error:",
                      "secrets.", "packages:", "contents: write", "docker", "build-provider",
                      "upload-artifact", "cache-to", "registry", "login"):
        assert forbidden not in text.lower(), forbidden
    assert "cancel-in-progress: true" in text


def test_linux_validation_actions_and_toolchain_are_exactly_pinned():
    text = workflow()
    uses = re.findall(r"^\s*uses:\s*(\S+)", text, re.M)
    assert len(uses) == 2
    for entry in uses:
        repository, sha = entry.split("@")
        assert sha == ACTION_PINS[repository]["sha"]
    assert "python-version: '3.12.14'" in step("Set up Python")
    assert "uv==0.12.23" in step("Install pinned test environment")
    assert "UV_PYTHON: '3.12.14'" in text
    assert "UV_PYTHON_DOWNLOADS: never" in text
    assert "UV_BUILD_CONSTRAINT: ${{ github.workspace }}/.github/requirements/linux-unit.txt" in text


def test_linux_validation_job_environment_uses_only_available_contexts():
    # GitHub resolves job env before runner contexts become available.
    # https://docs.github.com/en/actions/reference/workflows-and-actions/contexts#context-availability
    job_env = re.search(r"^    env:\n(.*?)^    steps:\n", workflow(), re.M | re.S).group(1)
    available = {"github", "needs", "strategy", "matrix", "vars", "secrets", "inputs"}
    for expression in re.findall(r"\$\{\{(.*?)\}\}", job_env):
        roots = re.findall(r"(?<![\w.])([A-Za-z_]\w*)\s*[.\[]", expression)
        assert set(roots) <= available, f"unavailable job-env context in {expression!r}"


def test_linux_validation_cache_is_set_for_current_and_later_steps(tmp_path):
    # Exercise the real bootstrap before environment creation/install, without
    # downloading anything. Spaces in runner paths must remain intact.
    bootstrap = step("Install pinned test environment").split("python -m venv", 1)[0]
    bootstrap = textwrap.dedent(bootstrap.split("run: |\n", 1)[1])
    environment_file = tmp_path / "github-env"
    runner_temp = tmp_path / "runner temp"
    result = subprocess.run(
        ["bash", "-eo", "pipefail", "-c", bootstrap + '\nprintf "%s" "$UV_CACHE_DIR"\n'],
        env=os.environ | {"RUNNER_TEMP": str(runner_temp), "GITHUB_ENV": str(environment_file),
                          "UV_CACHE_DIR": "wrong inherited cache"},
        text=True, capture_output=True,
    )
    assert result.returncode == 0, result.stderr
    expected = str(runner_temp / "uv-cache")
    assert result.stdout == expected
    assert environment_file.read_text() == f"UV_CACHE_DIR={expected}\n"


def test_linux_validation_dependencies_and_build_backend_are_closed():
    assert REQUIREMENTS.is_file(), "CI dependencies must be pinned separately"
    entries = [line for line in REQUIREMENTS.read_text().splitlines()
               if line and not line.startswith("#")]
    assert all(re.fullmatch(r"[A-Za-z0-9_.-]+==[0-9][A-Za-z0-9_.]*", line) for line in entries)
    pins = dict(line.split("==") for line in entries)
    assert len(pins) == len(entries), "duplicate package pins"
    for dependency in ("hatchling", "editables", "packaging", "pathspec",
                       "pluggy", "trove-classifiers"):
        assert dependency in pins, dependency
    assert pins["pytest"] == "9.1.1"
    install = step("Install pinned test environment")
    assert "--no-deps --only-binary :all:" in install
    assert "--no-deps --no-build-isolation" in install
    assert "uv pip check --python .venv/bin/python" in install


def test_linux_validation_checker_requirement_uses_catalogue_pin(tmp_path):
    result = subprocess.run(
        [sys.executable, "-c", python_script("Install pinned test environment")],
        cwd=ROOT, env=os.environ | {"RUNNER_TEMP": str(tmp_path)},
        text=True, capture_output=True,
    )
    assert result.returncode == 0, result.stderr
    source = json.loads((ROOT / "src/p11lab/data/tools.json").read_text())["tools"]["checker"]["source"]
    requirement = (tmp_path / "checker-requirement.txt").read_text()
    assert requirement == f"pkcs11-check @ git+{source['url']}@{source['revision']}\n"
    assert 'metadata.version("pkcs11-check") == "0.2.3"' in step("Verify checker provenance")
    assert 'direct["vcs_info"]["commit_id"] == source["revision"]' in step("Verify checker provenance")
    assert 'direct["url"] == source["url"]' in step("Verify checker provenance")
    assert "import pkcs11_check.testcases" in step("Verify checker provenance")
    assert "import pkcs11_check.provenance" in step("Verify checker provenance")


def test_linux_validation_runs_full_suite_and_preserves_status():
    text = workflow()
    assert "PYTEST_DISABLE_PLUGIN_AUTOLOAD: '1'" in text
    run = step("Run full pytest suite")
    assert "python -m pytest -ra --junitxml=\"$RUNNER_TEMP/p11lab-tests.xml\"" in run
    assert re.findall(r"^          python -m pytest (.*)$", run, re.M) == [
        '-ra --junitxml="$RUNNER_TEMP/p11lab-tests.xml"',
    ]
    for suppressed in ("--ignore", "--deselect", "-k ", "--maxfail", "||", "exit 0",
                       "continue-on-error"):
        assert suppressed not in run, suppressed
    assert "if: always()" in step("Summarize results and limitations")


def test_linux_validation_requires_each_system_test_tool():
    # `command -v bash gcc cc openssl` succeeds when only its last tool exists.
    # Check each tool individually so missing native-test coverage fails early.
    preflight = step("Verify checker provenance")
    assert 'for tool in bash gcc cc openssl; do' in preflight
    assert 'command -v "$tool"' in preflight


@pytest.mark.parametrize("report", [
    None,
    '<testsuites><testsuite tests="4" failures="1" errors="0" skipped="2">'
    '<testcase name="ok"/><testcase name="bad"><failure>failed</failure></testcase>'
    '<testcase name="runtime"><skipped message="explicit runtime IDs required"/></testcase>'
    '<testcase name="checker"><skipped message="missing checker"/></testcase>'
    '</testsuite></testsuites>',
])
def test_linux_validation_summary_never_hides_missing_or_skipped_evidence(tmp_path, report):
    if report is not None:
        (tmp_path / "p11lab-tests.xml").write_text(report)
    summary = tmp_path / "summary"
    result = subprocess.run(
        [sys.executable, "-c", python_script("Summarize results and limitations")],
        env=os.environ | {"RUNNER_TEMP": str(tmp_path), "GITHUB_STEP_SUMMARY": str(summary)},
        text=True, capture_output=True,
    )
    assert result.returncode == 0, result.stderr
    text = summary.read_text()
    assert "not provider runtime qualification" in text
    if report is None:
        assert "No pytest report" in text
        assert "not a pass" in text
    else:
        assert "4 tests, 1 failures, 0 errors, 2 skipped" in text
        assert "explicit runtime IDs required" in text
        assert "missing checker" in text
