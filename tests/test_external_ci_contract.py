"""M09 source-acceptance contract for the shipped external-CI examples.

Asserts plan M09 checkbox 1 over the shipped caller templates: explicit
control repository/ref, separate caller checkout, full action pins, no
private paths or dispatch tokens, unchanged checker input shape, declared
caller permissions, and complete aggregates. Static source acceptance ONLY:
no pilots, publication, activation, Docker, network, or execution.

Method: substitute-then-validate (template placeholders become fixed
invented 40-hex constants before parsing/pin checks; templates stay
templates), strict YAML loader, exact key-set asserts, and anchored
old/new mutation tables routed through one ``_check_*`` function per
family, each reddening exactly its assertion (``match=`` proves which).

Binding rulings implemented (coordinator Q1-Q13): Q1 substitution idiom;
Q2 literal app checkout vs absence-plus-candidate-by-input for the pure
``uses:`` callers; Q3 literal app aggregates vs delegation shape for
round/proxy; Q4 all 8 points on the 3 caller YAMLs plus the A4/A5 surface
scan on all 28 example files; Q5 portable ``../`` allowed, README
``.local`` denial lines allowlisted, scripts get zero-occurrence asserts;
Q6 windows checkout requirement grandfathered (native lane postponed per
its README; not machine-specific) -- no assertion for or against;
Q7 docs out of scope (checkbox says "examples"); Q8 W25/W26 files
unidentified by name, so no assertions can target them (follow-up for the
activation slice); Q9 self-contained file reusing the proxy idioms, the
round checker script untouched; Q10 caller-surface only, deep semantics
deferred to owner suites with citing comments; Q11 ``retention-days: 1``
pinned as-is; Q12 shape-only tiers (exact ``with:`` key sets vs the
reusable ``inputs:``; tier literals stay owned by round/proxy suites).

Deferred to owner suites (asserted here only at the caller surface):
reusable-side control checkout (``tests/rounds/test_workflow_skeleton.py``,
``tests/test_proxy_workflows.py``), reusable aggregators (proxy suite
aggregator pins, round skeleton suite), the M04 Action ``with:`` shape
(``tests/test_application_action.py``), tier literals (round/proxy
suites), and shell deep semantics (``tests/test_examples_p11kit.py``,
``tests/test_examples_p11scope.py``).
"""

import re
from pathlib import Path

import pytest
import yaml

import copy

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"
APP = "examples/application-ci/action.yml"
ROUND = "examples/round-consumer/diagnostic.yml"
PROXY = "examples/proxy-consumer/workflow.yml"
CALLERS = {"app": APP, "round": ROUND, "proxy": PROXY}
CHECKER_REUSABLE = ".github/workflows/checker-round.yml"
PROXY_REUSABLE = ".github/workflows/proxy-round.yml"
REUSABLE = {"round": CHECKER_REUSABLE, "proxy": PROXY_REUSABLE}

# Fixed invented 40-hex constants for substitute-then-validate (Q1).
SHA_A = "a" * 40  # framework candidate
SHA_B = "b" * 40  # proxy candidate
SHA_C = "c" * 40  # p11lab control ref
SHA_D = "d" * 40  # published Action commit
SUBS = {
    "<P11LAB_COMMIT_SHA>": SHA_C,
    "<FRAMEWORK_COMMIT_SHA>": SHA_A,
    "<PROXY_COMMIT_SHA>": SHA_B,
    "REQUIRED_PUBLISHED_ACTION_COMMIT": SHA_D,
    # No REQUIRED_ELIGIBLE_HANDOFF_MANIFEST_SHA256 entry: the digest
    # slot stays owned by the M04 suite (Q10) and passes through
    # preserved. Exactly the brief's four substitutions live here.
}

# Full-SHA `uses:` pin: action form plus reusable-workflow-path form. The
# path alternative is required: the round/proxy callers address
# `org/repo/.github/workflows/<name>.yml@<sha>`, which the bare action
# regex cannot match. Moving tags still fail the trailing 40-hex.
USES_RE = re.compile(r"[\w.-]+/[\w.-]+(?:/[\w./-]+)?@[0-9a-f]{40}")
# Home-directory tilde at a path position (Q5). A Debian version tilde
# such as `3.5.7-1~deb13u3` is not a path and must not match.
TILDE_RE = re.compile(r"(?:^|[\s=:\"'`(\[{])~(?:/|$|[A-Za-z_])", re.M)
# Dispatch-token secret reference (A5 surface): a GitHub `${{ secrets. }}`
# expression or a `secrets.NAME` access. Prose ("must not print secrets.")
# and local lowercase uses (`secrets.mkdir`) must still pass.
SECRETS_REF_RE = re.compile(r"\$\{\{[^}\n]*secrets\.|secrets\.[A-Za-z_]*[A-Z]")
# README `.local` denial lines, pinned exactly per owning file (Q5):
# the only two `.local` mentions in the shipped examples, both
# denials (the DENIAL_LINES list below). Any other `.local` line --
# including a positive use sharing its line with an unrelated
# negation -- fails closed.
DENIAL_LINES = frozenset(
    {
        (
            "examples/p11-kit/README.md",
            "  `src/` directory into the vessel (only `src/`; no `.local/` content,",
        ),
        (
            "examples/p11scope/README.md",
            "cannot run it. No checkout mounts, no `.local/` content, and no",
        ),
    }
)

# Per-run private scratch in the p11scope demo vessel (M09
# tmp-hygiene): a mktemp dir under `${TMPDIR:-/tmp}` -- note `/tmp}` is
# not the substring `/tmp/`, so the owning file holds ZERO `/tmp/`
# lines -- child-chowned 700, removed by an EXIT trap. TOKENDIR/CONF
# relocate under `$SCRATCH` (chmod 700/600 kept); the observer writes
# `-o` to `$PROFILE` and the run copies it to `$WORK`. Bound to the
# owning file with exact occurrence counts (each pin exactly once, in
# that file only); any `/tmp/` line -- even one -- fails closed.
SCRATCH_MANAGED_OWNER = "examples/p11scope/demo-inner.sh"
SCRATCH_MANAGED = frozenset(
    {
        'SCRATCH=$(mktemp -d "${TMPDIR:-/tmp}/obs-XXXXXX")',
        'TOKENDIR="$SCRATCH/tokens"',
        'CONF="$SCRATCH/softhsm.conf"',
        'PROFILE="$SCRATCH/observed-profile.json"',
        '-o "$PROFILE" -- \\',
        'cp "$PROFILE" "$WORK/observed-profile.json"',
        "trap 'rm -rf \"$SCRATCH\"' EXIT",
        'chown "$CHILD_UID:$CHILD_UID" "$SCRATCH"',
    }
)

EXPECTED_WITH = {
    "round": {"framework_sha", "tier", "p11lab_ref"},
    "proxy": {"proxy_sha", "tier", "p11lab_ref"},
}
CANDIDATE = {"round": "framework_sha", "proxy": "proxy_sha"}
EXPECTED_ON = {
    "app": {"workflow_dispatch": None},
    "round": {"workflow_dispatch": None},
    "proxy": {"pull_request": None},
}

# Frozen 28-file example roster (Q4): every file below gets the A4/A5
# surface scan, and any roster drift fails closed so new files cannot
# silently escape the scan.
EXPECTED_ROSTER = frozenset(
    {
        "examples/application-ci/action.yml",
        "examples/application-ci/action-gated.yml",
        "examples/external-consumer/README.md",
        "examples/external-consumer/checker-driver.py",
        "examples/external-consumer/consumer-app.py",
        "examples/external-consumer/run-container.sh",
        "examples/external-consumer/run-native.sh",
        "examples/linux/README.md",
        "examples/linux/prepare-consumer.py",
        "examples/native-softhsm/README.md",
        "examples/native-softhsm/run.sh",
        "examples/p11-kit/Dockerfile.demo",
        "examples/p11-kit/README.md",
        "examples/p11-kit/demo-inner.sh",
        "examples/p11-kit/lib.sh",
        "examples/p11-kit/run.sh",
        "examples/p11scope/Dockerfile.demo",
        "examples/p11scope/README.md",
        "examples/p11scope/demo-inner.sh",
        "examples/p11scope/lib.sh",
        "examples/p11scope/pins.env",
        "examples/p11scope/run.sh",
        "examples/proxy-consumer/execution.yml",
        "examples/proxy-consumer/workflow.yml",
        "examples/round-consumer/diagnostic.yml",
        "examples/round-consumer/execution.yml",
        "examples/windows/README.md",
        "examples/windows/run.py",
    }
)


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


def _substitute(text):
    for old, new in SUBS.items():
        text = text.replace(old, new)
    return text


def _caller_doc(path):
    return _loads(_substitute((ROOT / path).read_text()))


def _reusable_inputs(path):
    doc = _loads((ROOT / path).read_text())
    return set(doc["on"]["workflow_call"]["inputs"])


def _mutated_text(path, old, new, count=1):
    text = (ROOT / path).read_text()
    assert old in text, "mutation anchor missing: %r in %s" % (old, path)
    if count == 0:
        return text.replace(old, new)
    return text.replace(old, new, count)


def _mutated_doc(path, old, new, count=1):
    return _loads(_substitute(_mutated_text(path, old, new, count)))


def _with_extra_line(path, line):
    return (ROOT / path).read_text() + "\n" + line + "\n"


def _check_control_repo_ref(doc, caller):
    """A1: the caller names org p11lab with a pinned control ref."""
    if caller == "app":
        steps = doc["jobs"]["application"]["steps"]
        provider = next(
            (s for s in steps if s.get("id") == "provider"), None
        )
        assert provider is not None, "app provider step present"
        uses = provider["uses"]
        assert uses.split("/")[0] == "p11lab", "control uses org"
        assert "@" in uses and uses.rsplit("@", 1)[1] != "", (
            "control uses pin present"
        )
        return
    job = doc["jobs"]["diagnostic"]
    uses = job["uses"]
    assert uses.split("/")[0] == "p11lab", "control uses org"
    pin = uses.rsplit("@", 1)[1] if "@" in uses else ""
    assert pin == job["with"].get("p11lab_ref"), (
        "control uses pin equals p11lab_ref"
    )


def _check_app_checkout(doc):
    """A2 (app): literal separate caller checkout (Q2)."""
    steps = doc["jobs"]["application"]["steps"]
    checkout = next(
        (s for s in steps if s.get("uses", "").startswith("actions/checkout@")),
        None,
    )
    assert checkout is not None, "app checkout step present"
    with_map = checkout.get("with", {})
    assert with_map.get("persist-credentials") is False, (
        "app checkout persist-credentials false"
    )
    assert with_map.get("path") == "caller", "app checkout path caller"
    assert with_map.get("sparse-checkout") == "ci-application", (
        "app checkout sparse-checkout ci-application"
    )


def _check_pure_caller_separation(doc, text, caller):
    """A2 (round/proxy): separation by absence plus candidate-by-input.

    The pure `uses:` callers declare no steps of their own, so nothing can
    shadow the control checkout that happens inside the reusable workflow;
    the candidate arrives only as input SHAs (Q2).
    """
    assert "actions/checkout" not in text, "pure caller declares no checkout"
    assert "run:" not in text, "pure caller declares no run steps"
    for name, job in doc["jobs"].items():
        assert "steps" not in job, "pure caller declares no steps"
    with_map = doc["jobs"]["diagnostic"]["with"]
    candidate = with_map.get(CANDIDATE[caller], "")
    assert re.fullmatch(r"[0-9a-f]{40}", candidate or "") is not None, (
        "pure caller candidate arrives by input"
    )
    control = with_map.get("p11lab_ref", "")
    assert re.fullmatch(r"[0-9a-f]{40}", control or "") is not None, (
        "pure caller control ref arrives by input"
    )


def _check_pins(doc):
    """A3: every `uses:` is pinned to a full 40-hex commit SHA."""
    uses_values = []
    for job in doc["jobs"].values():
        if "uses" in job:
            uses_values.append(job["uses"])
        for step in job.get("steps", []):
            if "uses" in step:
                uses_values.append(step["uses"])
    assert uses_values, "caller declares at least one uses pin"
    for value in uses_values:
        assert USES_RE.fullmatch(value) is not None, (
            "full-SHA uses pin: %s" % value
        )


def _check_no_private_paths(text, rel):
    """A4: no machine-specific absolute paths or baked secrets (Q4/Q5).

    Relative `../` mounts are portable and allowed; README `.local`
    mentions are allowed only on the pinned per-file denial lines; the
    owning file must carry the scratch-mechanism pins (each exactly
    once) and zero `/tmp/` lines -- every other file allows no `/tmp/`.
    """
    if rel.name == "README.md":
        for line in text.splitlines():
            if ".local" in line:
                assert (rel.as_posix(), line) in DENIAL_LINES, (
                    "README .local only on denial lines: %r" % line
                )
    else:
        assert ".local" not in text, "no .local in non-README examples"
    assert "/home/" not in text, "no /home/ paths in examples"
    assert "/root/" not in text, "no /root/ paths in examples"
    assert "$HOME" not in text, "no $HOME paths in examples"
    assert TILDE_RE.search(text) is None, "no home ~ paths in examples"
    assert "C:\\" not in text, "no windows drive path in examples"
    if rel.as_posix() == SCRATCH_MANAGED_OWNER:
        # Pins first: a regression that both drops a pin and adds a
        # `/tmp/` line (N5/N6) must redden the pin assertion.
        for pin in sorted(SCRATCH_MANAGED):
            count = sum(
                1 for line in text.splitlines() if line.strip() == pin
            )
            assert count == 1, (
                "scratch mechanism pinned exactly once: %r (found %d)"
                % (pin, count)
            )
        found = sorted(
            line.strip() for line in text.splitlines() if "/tmp/" in line
        )
        assert found == [], (
            "no baked /tmp/ paths in examples: %r" % (found,)
        )
    else:
        for line in text.splitlines():
            assert "/tmp/" not in line, (
                "no baked /tmp/ paths in examples: %r" % line
            )


def _check_no_dispatch_tokens_yaml(text):
    """A5 (caller YAMLs): strict absence of dispatch-token markers."""
    assert "secrets." not in text, "no secrets. in caller"
    assert "secrets:" not in text, "no secrets: in caller"
    assert "inherit" not in text, "no inherit in caller"
    assert "github.token" not in text, "no github.token in caller"
    assert "GITHUB_TOKEN" not in text, "no GITHUB_TOKEN in caller"


def _check_surface_tokens(text):
    """A5 (all 28): dispatch-token surface scan.

    Deliberately not a bare `"token" not in text` check: PKCS#11 token
    vocabulary (`--token-label`, `token_present`), local `secrets`
    variables, and "must not print secrets" denial prose must still pass.
    """
    assert SECRETS_REF_RE.search(text) is None, (
        "no secret reference in examples"
    )
    assert "secrets:" not in text, "no secrets: in examples"
    assert "inherit" not in text, "no inherit in examples"
    assert "github.token" not in text, "no github.token in examples"
    assert "GITHUB_TOKEN" not in text, "no GITHUB_TOKEN in examples"


def _check_trigger(doc, caller):
    """A5 trigger: each caller keeps exactly its documented trigger.

    `workflow_dispatch` is legitimate on round/app and `pull_request` is
    the documented proxy design (caller authority); neither is asserted
    absent anywhere.
    """
    assert doc.get("on") == EXPECTED_ON[caller], (
        "caller trigger is exactly its documented one"
    )


def _check_input_shape(with_map, reusable_keys, caller):
    """A6: caller `with:` shape matches the reusable `inputs:` (Q12).

    Shape only: exact key sets cross-checked against the reusable
    workflow. Tier literal values stay owned by the round/proxy suites.
    """
    keys = set(with_map)
    assert keys == EXPECTED_WITH[caller], "caller with shape"
    assert keys == set(reusable_keys), "caller with matches reusable inputs"


def _check_permissions(doc):
    """A7: declared minimal caller permissions, top level and every job.

    Jobs without their own block inherit the top level; the effective set
    on every job must be declared and free of `write`.
    """
    top = doc.get("permissions")
    assert isinstance(top, dict) and len(top) > 0, (
        "top-level permissions declared"
    )
    assert "write" not in "|".join(map(str, top.values())), (
        "top-level permissions minimal"
    )
    for name, job in doc["jobs"].items():
        effective = dict(top)
        effective.update(job.get("permissions") or {})
        assert "write" not in "|".join(map(str, effective.values())), (
            "job permissions minimal: %s" % name
        )


def _check_app_aggregate(doc):
    """A8 (app): literal always() evidence collection (Q3, Q11)."""
    steps = doc["jobs"]["application"]["steps"]
    label = next(
        s for s in steps if s.get("name") == "Label unavailable evidence"
    )
    assert "always()" in label.get("if", ""), (
        "unavailable-evidence label runs always()"
    )
    upload = next(
        s
        for s in steps
        if s.get("uses", "").startswith("actions/upload-artifact@")
    )
    assert "always()" in upload.get("if", ""), "receipt upload runs always()"
    with_map = upload.get("with", {})
    assert with_map.get("if-no-files-found") == "error", (
        "receipt upload errors when empty"
    )
    assert with_map.get("retention-days") == 1, "retention-days pinned 1"


def _check_delegation_shape(doc):
    """A8 (round/proxy): single-job delegation to the reusable workflow.

    The no-`steps:` half of the delegation shape is owned by the A2
    absence check above; aggregation internals stay covered
    reusable-side (`tests/test_proxy_workflows.py` aggregator pins, round
    skeleton suite) and are not duplicated here (Q3/Q10).
    """
    assert set(doc["jobs"]) == {"diagnostic"}, (
        "pure caller delegates from one job"
    )
    assert "uses" in doc["jobs"]["diagnostic"], (
        "pure caller job calls its reusable workflow"
    )


def _check_roster(found):
    assert set(found) == set(EXPECTED_ROSTER), "example roster"


def _found_roster():
    return sorted(
        p.relative_to(ROOT).as_posix()
        for p in EXAMPLES.rglob("*")
        if p.is_file()
    )


@pytest.mark.parametrize("caller", ["app", "round", "proxy"])
def test_callers_accept_contract(caller):
    path = CALLERS[caller]
    raw = (ROOT / path).read_text()
    substituted = _substitute(raw)
    doc = _loads(substituted)
    _check_control_repo_ref(doc, caller)
    if caller == "app":
        _check_app_checkout(doc)
    else:
        _check_pure_caller_separation(doc, substituted, caller)
    _check_pins(doc)
    _check_no_dispatch_tokens_yaml(raw)
    _check_trigger(doc, caller)
    if caller != "app":
        # App `with:` keys are the M04 Action shape, owned by
        # tests/test_application_action.py; M09 must not re-pin (Q10).
        _check_input_shape(
            doc["jobs"]["diagnostic"]["with"],
            _reusable_inputs(REUSABLE[caller]),
            caller,
        )
    _check_permissions(doc)
    if caller == "app":
        _check_app_aggregate(doc)
    else:
        _check_delegation_shape(doc)


def test_examples_accept_surface():
    found = _found_roster()
    _check_roster(found)
    for rel in found:
        text = (ROOT / rel).read_text()
        _check_no_private_paths(text, Path(rel))
        _check_surface_tokens(text)


def test_caller_rejects_duplicate_keys():
    with pytest.raises(Exception):
        _loads(_substitute((ROOT / ROUND).read_text()) + "\npermissions: {}\n")


def test_surface_accepts_pkcs11_vocab_and_local_secrets():
    benign = (
        "slots = p11.get_slots(token_present=True)\n"
        'cmd = ["x", "--token-label", label]\n'
        'secrets = Path("secrets")\n'
        "secrets.mkdir(exist_ok=True)\n"
        "# must not print secrets.\n"
    )
    _check_surface_tokens(benign)


def test_paths_accepts_denials_relatives_version_tilde_and_managed_scratch():
    _check_no_private_paths(
        "  `src/` directory into the vessel (only `src/`; no `.local/` content,\n",
        Path("examples/p11-kit/README.md"),
    )
    _check_no_private_paths(
        "cannot run it. No checkout mounts, no `.local/` content, and no\n",
        Path("examples/p11scope/README.md"),
    )
    _check_no_private_paths(
        'src=$DIR/../../src\n', Path("examples/p11-kit/run.sh")
    )
    _check_no_private_paths(
        "3.5.7-1~deb13u3\n", Path("examples/p11-kit/README.md")
    )
    _check_no_private_paths(
        "\n".join(sorted(SCRATCH_MANAGED)) + "\n",
        Path("examples/p11scope/demo-inner.sh"),
    )


def test_workflow_dispatch_stays_legitimate_on_round_and_app():
    for caller in ("app", "round"):
        _check_trigger(_caller_doc(CALLERS[caller]), caller)


def test_tier_values_are_shape_only_not_pinned():
    _check_input_shape(
        {"framework_sha": SHA_A, "tier": "some-future-tier", "p11lab_ref": SHA_C},
        {"framework_sha", "tier", "p11lab_ref"},
        "round",
    )


@pytest.mark.parametrize(
    ("caller", "old", "new", "match"),
    [
        (
            "round",
            "uses: p11lab/p11lab/.github/workflows/checker-round.yml",
            "uses: attacker/p11lab/.github/workflows/checker-round.yml",
            "control uses org",
        ),
        (
            "round",
            "p11lab_ref: <P11LAB_COMMIT_SHA>",
            "p11lab_ref: " + SHA_B,
            "control uses pin equals p11lab_ref",
        ),
        (
            "proxy",
            "uses: p11lab/p11lab/.github/workflows/proxy-round.yml",
            "uses: attacker/p11lab/.github/workflows/proxy-round.yml",
            "control uses org",
        ),
        (
            "proxy",
            "p11lab_ref: <P11LAB_COMMIT_SHA>",
            "p11lab_ref: " + SHA_A,
            "control uses pin equals p11lab_ref",
        ),
        (
            "app",
            "        id: provider\n",
            "        id: renamed\n",
            "app provider step present",
        ),
        (
            "app",
            "uses: p11lab/p11lab@REQUIRED_PUBLISHED_ACTION_COMMIT",
            "uses: attacker/p11lab@REQUIRED_PUBLISHED_ACTION_COMMIT",
            "control uses org",
        ),
        (
            "app",
            "uses: p11lab/p11lab@REQUIRED_PUBLISHED_ACTION_COMMIT",
            "uses: p11lab/p11lab",
            "control uses pin present",
        ),
    ],
)
def test_a1_rejects_control_mutations(caller, old, new, match):
    with pytest.raises(AssertionError, match=match):
        _check_control_repo_ref(
            _mutated_doc(CALLERS[caller], old, new), caller
        )


@pytest.mark.parametrize(
    ("old", "new", "match"),
    [
        (
            "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4\n"
            "        with:\n"
            "          persist-credentials: false\n"
            "          path: caller\n"
            "          sparse-checkout: ci-application\n",
            "",
            "app checkout step present",
        ),
        (
            "          persist-credentials: false\n",
            "",
            "app checkout persist-credentials false",
        ),
        (
            "          path: caller\n",
            "",
            "app checkout path caller",
        ),
        (
            "          sparse-checkout: ci-application\n",
            "",
            "app checkout sparse-checkout ci-application",
        ),
    ],
)
def test_a2_app_rejects_checkout_mutations(old, new, match):
    with pytest.raises(AssertionError, match=match):
        _check_app_checkout(_mutated_doc(APP, old, new))


@pytest.mark.parametrize(
    ("caller", "old", "new", "match"),
    [
        (
            "proxy",
            "    uses: p11lab/p11lab/.github/workflows/proxy-round.yml@<P11LAB_COMMIT_SHA>\n",
            "    uses: p11lab/p11lab/.github/workflows/proxy-round.yml@<P11LAB_COMMIT_SHA>\n"
            "    steps:\n"
            "      - uses: actions/checkout@" + SHA_A + "\n",
            "pure caller declares no checkout",
        ),
        (
            "round",
            "    uses: p11lab/p11lab/.github/workflows/checker-round.yml@<P11LAB_COMMIT_SHA>\n",
            "    uses: p11lab/p11lab/.github/workflows/checker-round.yml@<P11LAB_COMMIT_SHA>\n"
            "    steps:\n"
            "      - run: echo shadow\n",
            "pure caller declares no run steps",
        ),
        (
            "proxy",
            "    uses: p11lab/p11lab/.github/workflows/proxy-round.yml@<P11LAB_COMMIT_SHA>\n",
            "    uses: p11lab/p11lab/.github/workflows/proxy-round.yml@<P11LAB_COMMIT_SHA>\n"
            "    steps:\n"
            "      - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02\n",
            "pure caller declares no steps",
        ),
        (
            "round",
            "      framework_sha: <FRAMEWORK_COMMIT_SHA>\n",
            "",
            "pure caller candidate arrives by input",
        ),
        (
            "proxy",
            "      p11lab_ref: <P11LAB_COMMIT_SHA>\n",
            "",
            "pure caller control ref arrives by input",
        ),
    ],
)
def test_a2_pure_rejects_separation_mutations(caller, old, new, match):
    text = _mutated_text(CALLERS[caller], old, new)
    with pytest.raises(AssertionError, match=match):
        _check_pure_caller_separation(
            _loads(_substitute(text)), _substitute(text), caller
        )


@pytest.mark.parametrize(
    ("caller", "old", "new", "count", "match"),
    [
        # Both control placeholders move together so pin equality still
        # holds and only the full-SHA pin assertion reddens.
        ("round", "<P11LAB_COMMIT_SHA>", "v4", 0, "full-SHA uses pin"),
        ("proxy", "<P11LAB_COMMIT_SHA>", "v4", 0, "full-SHA uses pin"),
        (
            "app",
            "actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
            "actions/checkout@v4",
            1,
            "full-SHA uses pin",
        ),
        (
            "app",
            "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
            "actions/upload-artifact@v4",
            1,
            "full-SHA uses pin",
        ),
        (
            "round",
            "    uses: p11lab/p11lab/.github/workflows/checker-round.yml@<P11LAB_COMMIT_SHA>\n",
            "",
            1,
            "caller declares at least one uses pin",
        ),
    ],
)
def test_a3_rejects_moving_tags(caller, old, new, count, match):
    with pytest.raises(AssertionError, match=match):
        _check_pins(_mutated_doc(CALLERS[caller], old, new, count))


@pytest.mark.parametrize(
    ("rel", "line", "match"),
    [
        (
            "examples/external-consumer/run-native.sh",
            "LEAK=.local/x",
            "no .local in non-README examples",
        ),
        (
            "examples/p11-kit/README.md",
            "see .local/cache for details",
            "README .local only on denial lines",
        ),
        (
            "examples/linux/prepare-consumer.py",
            "x = '/home/alice/x'",
            "no /home/ paths in examples",
        ),
        (
            "examples/p11scope/run.sh",
            "D=/root/x",
            "no /root/ paths in examples",
        ),
        (
            "examples/native-softhsm/run.sh",
            "D=$HOME/x",
            r"no \$HOME paths in examples",
        ),
        (
            "examples/windows/run.py",
            "p = Path('~/x')",
            "no home ~ paths in examples",
        ),
        (
            "examples/external-consumer/run-container.sh",
            "P='C:\\evil'",
            "no windows drive path in examples",
        ),
        (
            "examples/p11scope/demo-inner.sh",
            "CACHE=/tmp/evil-cache",
            "no baked /tmp/ paths in examples",
        ),
        # N1-N4: each retired fixed path, appended even ONCE to the
        # fixed owner file, reddens the empty-`/tmp/` assert. N1
        # supersedes the old duplicate-only row (a single occurrence
        # now fails, not just duplicates).
        (
            "examples/p11scope/demo-inner.sh",
            "TOKENDIR=/tmp/obs-tokens",
            "no baked /tmp/ paths in examples",
        ),
        (
            "examples/p11scope/demo-inner.sh",
            "CONF=/tmp/obs-softhsm.conf",
            "no baked /tmp/ paths in examples",
        ),
        (
            "examples/p11scope/demo-inner.sh",
            "-o /tmp/observed-profile.json -- \\",
            "no baked /tmp/ paths in examples",
        ),
        (
            "examples/p11scope/demo-inner.sh",
            'cp /tmp/observed-profile.json "$WORK/observed-profile.json"',
            "no baked /tmp/ paths in examples",
        ),
        (
            "examples/p11-kit/run.sh",
            "TOKENDIR=/tmp/obs-tokens",
            "no baked /tmp/ paths in examples",
        ),
    ],
)
def test_a4_rejects_private_paths(rel, line, match):
    with pytest.raises(AssertionError, match=match):
        _check_no_private_paths(_with_extra_line(rel, line), Path(rel))


@pytest.mark.parametrize(
    ("old", "new", "match"),
    [
        # N5: fixed-path regression replacing the relocated pin.
        (
            'TOKENDIR="$SCRATCH/tokens"',
            "TOKENDIR=/tmp/obs-tokens",
            "scratch mechanism pinned exactly once",
        ),
        # N6: literal-`/tmp/` mktemp in place of the TMPDIR form.
        (
            'SCRATCH=$(mktemp -d "${TMPDIR:-/tmp}/obs-XXXXXX")',
            "SCRATCH=$(mktemp -d /tmp/obs-XXXXXX)",
            "scratch mechanism pinned exactly once",
        ),
        # N7: scratch mechanism deleted.
        (
            'SCRATCH=$(mktemp -d "${TMPDIR:-/tmp}/obs-XXXXXX")',
            "",
            "scratch mechanism pinned exactly once",
        ),
        # N8: scratch mechanism duplicated.
        (
            'SCRATCH=$(mktemp -d "${TMPDIR:-/tmp}/obs-XXXXXX")',
            'SCRATCH=$(mktemp -d "${TMPDIR:-/tmp}/obs-XXXXXX")\n'
            'SCRATCH=$(mktemp -d "${TMPDIR:-/tmp}/obs-XXXXXX")',
            "scratch mechanism pinned exactly once",
        ),
    ],
)
def test_a4_rejects_scratch_mechanism_mutations(old, new, match):
    with pytest.raises(AssertionError, match=match):
        _check_no_private_paths(
            _mutated_text(SCRATCH_MANAGED_OWNER, old, new),
            Path(SCRATCH_MANAGED_OWNER),
        )


@pytest.mark.parametrize(
    ("rel", "line"),
    [
        (
            "examples/p11-kit/README.md",
            "Load .local/cache; no network access is required.",
        ),
        (
            "examples/p11-kit/README.md",
            "Mount .local/cache; do not enable debug logging.",
        ),
        (
            "examples/p11scope/README.md",
            "Sync .local/state nightly; never skip the audit log.",
        ),
        (
            "examples/p11scope/README.md",
            "Ship .local/overrides without extra review.",
        ),
        # Right denial line, wrong file: exceptions are file-specific.
        (
            "examples/p11-kit/README.md",
            "cannot run it. No checkout mounts, no `.local/` content, and no",
        ),
    ],
)
def test_a4_rejects_denial_counterexamples(rel, line):
    with pytest.raises(
        AssertionError, match="README .local only on denial lines"
    ):
        _check_no_private_paths(_with_extra_line(rel, line), Path(rel))


@pytest.mark.parametrize(
    ("caller", "old", "new", "match"),
    [
        (
            "app",
            "permissions:\n  contents: read\njobs:",
            "permissions:\n  contents: read\nsecrets: inherit\njobs:",
            "no secrets: in caller",
        ),
        (
            "app",
            "          timeout: '300'\n",
            "          timeout: '300'\n          extra: ${{ secrets.GITHUB_TOKEN }}\n",
            "no secrets. in caller",
        ),
        (
            "app",
            "          timeout: '300'\n",
            "          timeout: '300'\n          extra: GITHUB_TOKEN\n",
            "no GITHUB_TOKEN in caller",
        ),
        (
            "round",
            "      tier: pr-smoke\n",
            "      tier: pr-smoke\n      token_env: ${{ github.token }}\n",
            "no github.token in caller",
        ),
        (
            "round",
            "      tier: pr-smoke\n",
            "      tier: pr-smoke\n      mode: inherit\n",
            "no inherit in caller",
        ),
    ],
)
def test_a5_yaml_rejects_dispatch_tokens(caller, old, new, match):
    with pytest.raises(AssertionError, match=match):
        _check_no_dispatch_tokens_yaml(_mutated_text(CALLERS[caller], old, new))


@pytest.mark.parametrize(
    ("rel", "line", "match"),
    [
        (
            "examples/p11-kit/lib.sh",
            "GITHUB_TOKEN=x",
            "no GITHUB_TOKEN in examples",
        ),
        (
            "examples/external-consumer/consumer-app.py",
            "u = '${{ secrets.foo }}'",
            "no secret reference in examples",
        ),
        (
            "examples/p11scope/pins.env",
            "K=secrets.GITHUB_TOKEN",
            "no secret reference in examples",
        ),
        (
            "examples/p11scope/run.sh",
            "secrets: inherit",
            "no secrets: in examples",
        ),
        (
            "examples/p11scope/run.sh",
            "MODE=inherit",
            "no inherit in examples",
        ),
        (
            "examples/external-consumer/consumer-app.py",
            "t = github.token",
            "no github.token in examples",
        ),
    ],
)
def test_a5_surface_rejects_dispatch_tokens(rel, line, match):
    with pytest.raises(AssertionError, match=match):
        _check_surface_tokens(_with_extra_line(rel, line))


@pytest.mark.parametrize(
    ("caller", "old", "new"),
    [
        ("proxy", "  pull_request:\n", "  workflow_dispatch:\n"),
        ("proxy", "  pull_request:\n", "  pull_request_target:\n"),
        ("round", "  workflow_dispatch:\n", "  push:\n"),
        ("app", "  workflow_dispatch:\n", "  push:\n"),
    ],
)
def test_trigger_rejects_undocumented_trigger(caller, old, new):
    with pytest.raises(
        AssertionError, match="caller trigger is exactly its documented one"
    ):
        _check_trigger(_mutated_doc(CALLERS[caller], old, new), caller)


@pytest.mark.parametrize(
    ("caller", "old", "new"),
    [
        (
            "round",
            "      tier: pr-smoke\n",
            "      tier: pr-smoke\n      advisory: x\n",
        ),
        (
            "round",
            "      p11lab_ref: <P11LAB_COMMIT_SHA>\n",
            "",
        ),
        (
            "round",
            "      framework_sha: <FRAMEWORK_COMMIT_SHA>\n",
            "      proxy_sha: <FRAMEWORK_COMMIT_SHA>\n",
        ),
        (
            "proxy",
            "      tier: proxy-diagnostic-v1\n",
            "      tier: proxy-diagnostic-v1\n      advisory: x\n",
        ),
        (
            "proxy",
            "      p11lab_ref: <P11LAB_COMMIT_SHA>\n",
            "",
        ),
        (
            "proxy",
            "      proxy_sha: <PROXY_COMMIT_SHA>\n",
            "      framework_sha: <PROXY_COMMIT_SHA>\n",
        ),
    ],
)
def test_a6_rejects_input_shape_mutations(caller, old, new):
    doc = _mutated_doc(CALLERS[caller], old, new)
    with pytest.raises(AssertionError, match="caller with shape"):
        _check_input_shape(
            doc["jobs"]["diagnostic"]["with"],
            _reusable_inputs(REUSABLE[caller]),
            caller,
        )


@pytest.mark.parametrize("caller", ["round", "proxy"])
def test_a6_rejects_reusable_input_drift(caller):
    doc = _caller_doc(CALLERS[caller])
    drifted = set(EXPECTED_WITH[caller]) - {"p11lab_ref"}
    with pytest.raises(
        AssertionError, match="caller with matches reusable inputs"
    ):
        _check_input_shape(
            doc["jobs"]["diagnostic"]["with"], drifted, caller
        )


@pytest.mark.parametrize(
    ("caller", "old", "new", "match"),
    [
        (
            "app",
            "  contents: read",
            "  contents: write",
            "top-level permissions minimal",
        ),
        (
            "round",
            "      contents: read",
            "      contents: write",
            "job permissions minimal",
        ),
        (
            "proxy",
            "permissions:\n  contents: read\n  actions: read\njobs:",
            "jobs:",
            "top-level permissions declared",
        ),
        (
            "round",
            "permissions:\n  contents: read\njobs:",
            "jobs:",
            "top-level permissions declared",
        ),
        (
            "app",
            "permissions:\n  contents: read\njobs:",
            "jobs:",
            "top-level permissions declared",
        ),
    ],
)
def test_a7_rejects_permission_mutations(caller, old, new, match):
    with pytest.raises(AssertionError, match=match):
        _check_permissions(_mutated_doc(CALLERS[caller], old, new))


@pytest.mark.parametrize(
    ("old", "new", "match"),
    [
        (
            "        if: ${{ always() && steps.provider.outputs['receipt-path'] == '' }}\n",
            "        if: ${{ steps.provider.outputs['receipt-path'] == '' }}\n",
            "unavailable-evidence label runs always",
        ),
        (
            "        if: ${{ always() && steps.provider.outputs['receipt-path'] != '' }}\n",
            "        if: ${{ steps.provider.outputs['receipt-path'] != '' }}\n",
            "receipt upload runs always",
        ),
        (
            "          if-no-files-found: error\n",
            "",
            "receipt upload errors when empty",
        ),
        (
            "          retention-days: 1\n",
            "          retention-days: 14\n",
            "retention-days pinned 1",
        ),
    ],
)
def test_a8_app_rejects_aggregate_mutations(old, new, match):
    with pytest.raises(AssertionError, match=match):
        _check_app_aggregate(_mutated_doc(APP, old, new))


@pytest.mark.parametrize(
    ("caller", "old", "new", "match"),
    [
        (
            "round",
            "jobs:\n  diagnostic:\n",
            "jobs:\n  extra:\n    runs-on: ubuntu-24.04\n  diagnostic:\n",
            "pure caller delegates from one job",
        ),
        (
            "proxy",
            "jobs:\n  diagnostic:\n",
            "jobs:\n  extra:\n    runs-on: ubuntu-24.04\n  diagnostic:\n",
            "pure caller delegates from one job",
        ),
        (
            "round",
            "    uses: p11lab/p11lab/.github/workflows/checker-round.yml@<P11LAB_COMMIT_SHA>\n",
            "    runs-on: ubuntu-24.04\n",
            "pure caller job calls its reusable workflow",
        ),
    ],
)
def test_a8_delegation_rejects_shape_mutations(caller, old, new, match):
    with pytest.raises(AssertionError, match=match):
        _check_delegation_shape(_mutated_doc(CALLERS[caller], old, new))


def test_roster_rejects_extra_and_missing_files():
    found = _found_roster()
    with pytest.raises(AssertionError, match="example roster"):
        _check_roster(found + ["examples/evil/new.sh"])
    with pytest.raises(AssertionError, match="example roster"):
        _check_roster([p for p in found if p != "examples/windows/run.py"])
