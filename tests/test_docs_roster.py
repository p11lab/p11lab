"""M09 doc-roster/content contract for the M09 Files doc set.

Pins that the seven M09 docs plus the root README exist and still carry
their load-bearing anchors (exact literals, cross-doc anchors, dates,
tiers, input/output names, limits). Static Markdown checks ONLY: no
pilots, activation, publication, Docker, network, or execution.

Method: per-doc ``path.exists()`` plus one ``_check_<doc>`` function
holding a lowercased must-pin phrase list (proxy idiom), one accept
test per doc as positive control (plus one line-exact accept for the
Q6 heading), and parametrized in-memory
string-replace mutation tables routed through one ``_check_*`` per
family, each reddening exactly its assertion (fully anchored
``match=`` proves which). Checks use explicit ``raise`` so the
message is exact (a bare ``assert`` would gain rewritten
introspection). ``_mutated`` replaces ALL occurrences
because pinned phrases legitimately recur; every row still reddens
exactly its assertion.

Binding rulings implemented (coordinator Q1-Q10): Q1 this M09-scoped
name beside ``test_external_ci_contract.py``; ``tests/rounds/
test_docs_policy.py`` stays RESERVED for the W25 slice (needs
unavailable W25 evidence) and is the follow-up, not this file. Q2
full must-pin lists (load-bearing facts, not style). Q3 proxy-ci
existence + title ONLY with a citing comment to the owner suite
(Q10 overlap rule). Q4 this slice is the sole v1 author of
``docs/round-gating.md``; W25 only amends. Q5 README byte-identical
(no round-doc link asserts either way). Q6 the four anchor-side
targets pinned (heading exact, files exist); link-text spelling
stays prose. Q7 NO absence asserts for ``docs/results/``,
CODEOWNERS, or activation files (the activation slice adds them).
Q8 typed-cause labels exactly as implemented in
``proxy_policy.py`` (no labels beyond those verdict rows). Q9 image gate stays a
brief pointer (M08 owns image semantics). Q10 full 64-hex SoftHSM
digest pin (full-SHA style).

The roster test pins that the M09 set EXISTS; it must NOT assert
``docs/`` contains ONLY the M09 set (further docs live there).
"""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

# M09 Files doc set (M09-brief Files line): 7 docs + root README.
ROSTER = (
    "docs/published-images.md",
    "docs/application-ci.md",
    "docs/round-contract.md",
    "docs/round-gating.md",
    "docs/proxy-ci.md",
    "docs/integration-validation-status.md",
    "docs/testing.md",
    "README.md",
)

# Q6 anchor-side file targets (existence only; link text stays prose).
ANCHOR_TARGETS = (
    "examples/application-ci/action.yml",
    "src/p11lab/data/ci/result.schema.json",
    "src/p11lab/data/ci/images.json",
)


def _text(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def _mutated(rel, old, new):
    text = _text(rel)
    assert old in text, "mutation anchor missing: %r" % old
    return text.replace(old, new)


def _match(phrase):
    return "^" + re.escape("doc states " + phrase) + "$"


def _check_roster(existing):
    for rel in ROSTER:
        if rel not in existing:
            raise AssertionError("missing roster doc: " + rel)


def test_roster_exists():
    _check_roster([rel for rel in ROSTER if (ROOT / rel).exists()])


@pytest.mark.parametrize("rel", ROSTER)
def test_roster_rejects_missing_doc(rel):
    remaining = [other for other in ROSTER if other != rel]
    with pytest.raises(
        AssertionError, match="^" + re.escape("missing roster doc: " + rel) + "$"
    ):
        _check_roster(remaining)


def test_anchor_targets_exist():
    for rel in ANCHOR_TARGETS:
        assert (ROOT / rel).exists(), "missing anchor target: " + rel


PUBLISHED_IMAGES_PHRASES = (
    "try a published provider with docker",
    "no checkout",
    "python, compiler, checker",
    "src/p11lab/data/ci/images.json",
    "sha256:69cdeb9a74d13a3382547e184645ee18a7e9e2315246fd40ca814ef97b970d16",
    "ineligible for distribution/acquisition",
    "## mount your own prebuilt application",
    '"$p11lab_module"',
    "must not expand",
    "2026-10-28",
    "narrow usability observations",
)


def _check_published_images(text):
    lowered = text.lower()
    for phrase in PUBLISHED_IMAGES_PHRASES:
        if phrase not in lowered:
            raise AssertionError("doc states " + phrase)


def test_published_images_accept():
    _check_published_images(_text("docs/published-images.md"))


@pytest.mark.parametrize(
    ("old", "new", "phrase"),
    [
        (
            "# Try a published provider with Docker",
            "# Try a published provider with Podman",
            "try a published provider with docker",
        ),
        ("No checkout", "Full checkout", "no checkout"),
        (
            "Python, compiler, checker",
            "Python, compiler, auditor",
            "python, compiler, checker",
        ),
        (
            "src/p11lab/data/ci/images.json",
            "src/p11lab/data/ci/pictures.json",
            "src/p11lab/data/ci/images.json",
        ),
        (
            "sha256:69cdeb9a74d13a3382547e184645ee18a7e9e2315246fd40ca814ef97b970d16",
            "sha256:" + "0" * 64,
            "sha256:69cdeb9a74d13a3382547e184645ee18a7e9e2315246fd40ca814ef97b970d16",
        ),
        (
            "ineligible for distribution/acquisition",
            "eligible for distribution",
            "ineligible for distribution/acquisition",
        ),
        (
            "## Mount your own prebuilt application",
            "## Mount apps",
            "## mount your own prebuilt application",
        ),
        ('"$P11LAB_MODULE"', '"$P11LAB_ADAPTER"', '"$p11lab_module"'),
        ("must not expand", "may expand freely", "must not expand"),
        ("2026-10-28", "2020-10-28", "2026-10-28"),
        (
            "narrow usability observations",
            "broad usability observations",
            "narrow usability observations",
        ),
    ],
)
def test_published_images_rejects_mutations(old, new, phrase):
    with pytest.raises(AssertionError, match=_match(phrase)):
        _check_published_images(_mutated("docs/published-images.md", old, new))


# Q6 (FIX-2.2): the complete anchor-side heading line, exact full line.
# The substring phrase above cannot see a " v2" suffix, so the suffix
# negative routes through this splitlines-exact checker instead.
PUBLISHED_IMAGES_HEADING_LINE = "## mount your own prebuilt application"


def _check_published_images_heading_line(text):
    if PUBLISHED_IMAGES_HEADING_LINE not in text.lower().splitlines():
        raise AssertionError(
            "doc states heading line " + PUBLISHED_IMAGES_HEADING_LINE
        )


def test_published_images_heading_line_accept():
    _check_published_images_heading_line(_text("docs/published-images.md"))


@pytest.mark.parametrize(
    ("old", "new", "phrase"),
    [
        (
            "## Mount your own prebuilt application",
            "## Mount your own prebuilt application v2",
            "heading line ## mount your own prebuilt application",
        ),
    ],
)
def test_published_images_heading_line_rejects_mutations(old, new, phrase):
    with pytest.raises(AssertionError, match=_match(phrase)):
        _check_published_images_heading_line(
            _mutated("docs/published-images.md", old, new)
        )


APPLICATION_CI_PHRASES = (
    "run your application in ci",
    "not executable as supplied",
    "read/write",
    "/workspace",
    "exit-code",
    "app-returncode",
    "receipt-path",
    "handoff-sha256",
    "always()",
    "evidence incomplete",
    "authorized clean unrelated",
    "persist-credentials: false",
    "no retries",
    "native compatibility is inactive",
)


def _check_application_ci(text):
    lowered = text.lower()
    for phrase in APPLICATION_CI_PHRASES:
        if phrase not in lowered:
            raise AssertionError("doc states " + phrase)


def test_application_ci_accept():
    _check_application_ci(_text("docs/application-ci.md"))


@pytest.mark.parametrize(
    ("old", "new", "phrase"),
    [
        (
            "# Run your application in CI",
            "# Run your application in production",
            "run your application in ci",
        ),
        (
            "not executable as supplied",
            "ready to run",
            "not executable as supplied",
        ),
        ("read/write", "read-only", "read/write"),
        ("/workspace", "/nowhere", "/workspace"),
        ("exit-code", "exit-status", "exit-code"),
        ("app-returncode", "app-exitcode", "app-returncode"),
        ("receipt-path", "receipt-url", "receipt-path"),
        ("handoff-sha256", "handoff-md5", "handoff-sha256"),
        ("always()", "never()", "always()"),
        ("evidence incomplete", "evidence complete", "evidence incomplete"),
        (
            "authorized clean unrelated",
            "authorized dirty unrelated",
            "authorized clean unrelated",
        ),
        (
            "persist-credentials: false",
            "persist-credentials: true",
            "persist-credentials: false",
        ),
        ("no retries", "three retries", "no retries"),
        (
            "Native compatibility is inactive",
            "Native compatibility is active",
            "native compatibility is inactive",
        ),
    ],
)
def test_application_ci_rejects_mutations(old, new, phrase):
    with pytest.raises(AssertionError, match=_match(phrase)):
        _check_application_ci(_mutated("docs/application-ci.md", old, new))


ROUND_CONTRACT_PHRASES = (
    "evaluator bootstrap and round evidence contract",
    "09aabfec9fea7e424aabb991f6347349bfa84075",
    "evid-stream-1 blocks release",
    "n=1 contract tests",
    "are diagnostics, not provider qualification or release acceptance",
    "round_positive=false",
    "pr-smoke",
    "nightly",
    "`release`",
    "no external authenticated receipt-verification seam",
    "budgets are unmeasured targets",
)


def _check_round_contract(text):
    lowered = text.lower()
    for phrase in ROUND_CONTRACT_PHRASES:
        if phrase not in lowered:
            raise AssertionError("doc states " + phrase)


def test_round_contract_accept():
    _check_round_contract(_text("docs/round-contract.md"))


@pytest.mark.parametrize(
    ("old", "new", "phrase"),
    [
        (
            "# Evaluator bootstrap and round evidence contract",
            "# Evaluator bootstrap and round evidence wishes",
            "evaluator bootstrap and round evidence contract",
        ),
        (
            "09aabfec9fea7e424aabb991f6347349bfa84075",
            "f" * 40,
            "09aabfec9fea7e424aabb991f6347349bfa84075",
        ),
        (
            "EVID-STREAM-1 blocks release",
            "EVID-STREAM-1 closed",
            "evid-stream-1 blocks release",
        ),
        ("N=1 contract tests", "N=9 contract tests", "n=1 contract tests"),
        (
            "are diagnostics, not provider qualification or release acceptance",
            "are qualifications and release acceptance",
            "are diagnostics, not provider qualification or release acceptance",
        ),
        ("round_positive=false", "round_positive=true", "round_positive=false"),
        ("pr-smoke", "pr-fog", "pr-smoke"),
        ("nightly", "daily", "nightly"),
        ("`release`", "`launch`", "`release`"),
        (
            "no external authenticated receipt-verification seam",
            "no external authenticated receipt-verification portal",
            "no external authenticated receipt-verification seam",
        ),
        (
            "budgets are unmeasured targets",
            "budgets are measured facts",
            "budgets are unmeasured targets",
        ),
    ],
)
def test_round_contract_rejects_mutations(old, new, phrase):
    with pytest.raises(AssertionError, match=_match(phrase)):
        _check_round_contract(_mutated("docs/round-contract.md", old, new))


ROUND_GATING_PHRASES = (
    "round tiers and gating",
    "diagnostic-only",
    "cannot satisfy a release gate",
    "no release gate satisfied",
    "`pr-smoke`",
    "`nightly`",
    "`release`",
    "proxy-diagnostic-v1",
    "framework_sha",
    "proxy_sha",
    "p11lab_ref",
    "round_positive",
    "result-artifact",
    "result-sha256",
    "experiment-positive",
    "a and s and t and r and b",
    "tier-unqualified",
    "n=1",
    "flaky-green",
    "evid-stream-1",
    "rerun_requires_producer",
    "promotion: blocked",
    "never feed this verdict",
    "p11lab-proxy-dist-",
    "px-auth",
    "px-state",
    "px-replay",
    "px-client-crash",
    "px-daemon-death",
    "px-daemon-stop",
    "px-limit",
    "completed-negative",
    "attribution-unknown",
    "control-unqualified",
    "terminal-evidence-unavailable",
    "budget-exceeded",
    "missing-evidence",
    "usage-or-infrastructure",
    "bounded diagnostic positive",
    "t8 > t6 > t3 > t4 > t5 > t7 > t2 > t1/t11",
    "outer attempt",
    "durable retention",
    "preserves failed attempts",
    "exactly three inputs, all required strings: `framework_sha`, `tier`,\n`p11lab_ref`.",
)


def _check_round_gating(text):
    lowered = text.lower()
    for phrase in ROUND_GATING_PHRASES:
        if phrase not in lowered:
            raise AssertionError("doc states " + phrase)


def test_round_gating_accept():
    _check_round_gating(_text("docs/round-gating.md"))


@pytest.mark.parametrize(
    ("old", "new", "phrase"),
    [
        (
            "# Round tiers and gating",
            "# Round tiers and wishes",
            "round tiers and gating",
        ),
        ("diagnostic-only", "fully-qualified", "diagnostic-only"),
        (
            "cannot satisfy a release gate",
            "satisfies release gates",
            "cannot satisfy a release gate",
        ),
        (
            "no release gate satisfied",
            "every release gate satisfied",
            "no release gate satisfied",
        ),
        ("`pr-smoke`", "`pr-fog`", "`pr-smoke`"),
        ("`nightly`", "`daily`", "`nightly`"),
        ("`release`", "`launch`", "`release`"),
        (
            "proxy-diagnostic-v1",
            "proxy-qualifying-v9",
            "proxy-diagnostic-v1",
        ),
        ("framework_sha", "framework_commit", "framework_sha"),
        ("proxy_sha", "proxy_commit", "proxy_sha"),
        ("p11lab_ref", "p11lab_main", "p11lab_ref"),
        ("round_positive", "round_negative", "round_positive"),
        ("result-artifact", "result-package", "result-artifact"),
        ("result-sha256", "result-sha1", "result-sha256"),
        ("experiment-positive", "experiment-negative", "experiment-positive"),
        (
            "A AND S AND T AND R AND B",
            "A AND S AND T AND R",
            "a and s and t and r and b",
        ),
        ("tier-unqualified", "tier-qualified", "tier-unqualified"),
        ("N=1", "N=9", "n=1"),
        ("flaky-green", "flaky-red", "flaky-green"),
        ("EVID-STREAM-1", "EVID-STREAM-9", "evid-stream-1"),
        ("rerun_requires_producer", "rerun_anything", "rerun_requires_producer"),
        ("promotion: blocked", "promotion: allowed", "promotion: blocked"),
        (
            "never feed this verdict",
            "may feed this verdict",
            "never feed this verdict",
        ),
        ("p11lab-proxy-dist-", "p11lab-proxy-pkg-", "p11lab-proxy-dist-"),
        ("PX-AUTH", "PX-AAAA", "px-auth"),
        ("PX-STATE", "PX-BBBB", "px-state"),
        ("PX-REPLAY", "PX-CCCC", "px-replay"),
        ("PX-CLIENT-CRASH", "PX-DDDD", "px-client-crash"),
        ("PX-DAEMON-DEATH", "PX-EEEE", "px-daemon-death"),
        ("PX-DAEMON-STOP", "PX-FFFF", "px-daemon-stop"),
        ("PX-LIMIT", "PX-GGGG", "px-limit"),
        (
            "completed-negative",
            "completed-positive",
            "completed-negative",
        ),
        (
            "attribution-unknown",
            "attribution-known",
            "attribution-unknown",
        ),
        (
            "control-unqualified",
            "control-qualified",
            "control-unqualified",
        ),
        (
            "terminal-evidence-unavailable",
            "terminal-evidence-ready",
            "terminal-evidence-unavailable",
        ),
        ("budget-exceeded", "budget-met", "budget-exceeded"),
        ("missing-evidence", "missing-proof", "missing-evidence"),
        (
            "usage-or-infrastructure",
            "usage-and-infrastructure",
            "usage-or-infrastructure",
        ),
        (
            "bounded diagnostic positive",
            "limited diagnostic positive",
            "bounded diagnostic positive",
        ),
        (
            "T8 > T6 > T3 > T4 > T5 > T7 > T2 > T1/T11",
            "T8 > T6 > T3 > T4 > T5 > T7 > T2 > T0/T00",
            "t8 > t6 > t3 > t4 > t5 > t7 > t2 > t1/t11",
        ),
        ("outer attempt", "outer try", "outer attempt"),
        ("durable retention", "fleeting retention", "durable retention"),
        (
            "preserves failed attempts",
            "deletes failed attempts",
            "preserves failed attempts",
        ),
        (
            "`framework_sha`, `tier`,\n`p11lab_ref`",
            "`framework_sha`, `extra_input`, `tier`,\n`p11lab_ref`",
            "exactly three inputs, all required strings: `framework_sha`, `tier`,\n`p11lab_ref`.",
        ),
    ],
)
def test_round_gating_rejects_mutations(old, new, phrase):
    with pytest.raises(AssertionError, match=_match(phrase)):
        _check_round_gating(_mutated("docs/round-gating.md", old, new))


# Q3: existence + title ONLY for proxy-ci. Deep content pins live in the
# owner suite (tests/test_proxy_workflows.py _check_doc phrase list +
# accept + mutation rejections); duplicating them here would churn on
# every owner rewording.
def _check_proxy_ci(text):
    if "# proxy ci caller contract" not in text.lower():
        raise AssertionError("doc states # proxy ci caller contract")


def test_proxy_ci_accept():
    _check_proxy_ci(_text("docs/proxy-ci.md"))


@pytest.mark.parametrize(
    ("old", "new", "phrase"),
    [
        (
            "# Proxy CI caller contract",
            "# Proxy CI caller wishes",
            "# proxy ci caller contract",
        ),
    ],
)
def test_proxy_ci_rejects_mutations(old, new, phrase):
    with pytest.raises(AssertionError, match=_match(phrase)):
        _check_proxy_ci(_mutated("docs/proxy-ci.md", old, new))


INTEGRATION_STATUS_PHRASES = (
    "# integration validation status",
    "availability update: **2026-10-28**",
    "seven `linux/amd64` alpha pins",
    "metadata availability only",
    "historical 2026-10-20 integration snapshot",
    "distribution/acquisition ineligible",
    "not provider certification",
    "narrow runtime evidence",
    "## merged changes and original review evidence",
    "## open proposals",
    "## remaining work",
)


def _check_integration_status(text):
    lowered = text.lower()
    for phrase in INTEGRATION_STATUS_PHRASES:
        if phrase not in lowered:
            raise AssertionError("doc states " + phrase)


def test_integration_status_accept():
    _check_integration_status(_text("docs/integration-validation-status.md"))


@pytest.mark.parametrize(
    ("old", "new", "phrase"),
    [
        (
            "# Integration validation status",
            "# Integration validation wishes",
            "# integration validation status",
        ),
        (
            "Availability update: **2026-10-28**",
            "Availability update: **2020-01-01**",
            "availability update: **2026-10-28**",
        ),
        (
            "seven `linux/amd64` alpha pins",
            "seven `linux/amd64` beta pins",
            "seven `linux/amd64` alpha pins",
        ),
        (
            "metadata availability only",
            "full qualification",
            "metadata availability only",
        ),
        (
            "historical 2026-10-20 integration snapshot",
            "historical 2020-01-01 integration snapshot",
            "historical 2026-10-20 integration snapshot",
        ),
        (
            "distribution/acquisition ineligible",
            "distribution/acquisition eligible",
            "distribution/acquisition ineligible",
        ),
        (
            "not provider certification",
            "full provider certification",
            "not provider certification",
        ),
        (
            "narrow runtime evidence",
            "broad runtime evidence",
            "narrow runtime evidence",
        ),
        (
            "## Merged changes and original review evidence",
            "## Merged changes",
            "## merged changes and original review evidence",
        ),
        ("## Open proposals", "## Open questions", "## open proposals"),
        ("## Remaining work", "## Remaining wishes", "## remaining work"),
    ],
)
def test_integration_status_rejects_mutations(old, new, phrase):
    with pytest.raises(AssertionError, match=_match(phrase)):
        _check_integration_status(
            _mutated("docs/integration-validation-status.md", old, new)
        )


TESTING_PHRASES = (
    "testing levels",
    "linux-unit-validation.yml",
    "full pytest collection",
    "a green bounded check is **not provider runtime",
    "qualification**, windows compatibility",
    "## experimentresultv1",
    "validate_result",
    "pytest_disable_plugin_autoload=1",
    "python 3.12.14, uv 0.12.23, pytest 9.1.1",
)


def _check_testing(text):
    lowered = text.lower()
    for phrase in TESTING_PHRASES:
        if phrase not in lowered:
            raise AssertionError("doc states " + phrase)


def test_testing_accept():
    _check_testing(_text("docs/testing.md"))


@pytest.mark.parametrize(
    ("old", "new", "phrase"),
    [
        ("# Testing levels", "# Testing wishes", "testing levels"),
        (
            "linux-unit-validation.yml",
            "linux-unit-validation.yaml",
            "linux-unit-validation.yml",
        ),
        (
            "full pytest collection",
            "partial pytest collection",
            "full pytest collection",
        ),
        (
            "A green bounded check is **not provider runtime",
            "A green bounded check proves provider runtime",
            "a green bounded check is **not provider runtime",
        ),
        (
            "qualification**, Windows compatibility",
            "certification**, Windows compatibility",
            "qualification**, windows compatibility",
        ),
        (
            "## ExperimentResultV1",
            "## ExperimentResultV2",
            "## experimentresultv1",
        ),
        ("validate_result", "validate_outcome", "validate_result"),
        (
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD=1",
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD=0",
            "pytest_disable_plugin_autoload=1",
        ),
        (
            "Python 3.12.14, uv 0.12.23, pytest 9.1.1",
            "Python 3.12.14, uv 0.12.23, pytest 9.9.9",
            "python 3.12.14, uv 0.12.23, pytest 9.1.1",
        ),
    ],
)
def test_testing_rejects_mutations(old, new, phrase):
    with pytest.raises(AssertionError, match=_match(phrase)):
        _check_testing(_mutated("docs/testing.md", old, new))


README_PHRASES = (
    "# p11lab",
    "24 locked provider candidates",
    "2026-10-28",
    "confirmed seven alpha image pins",
    "docs/published-images.md",
    "docs/integration-validation-status.md",
    "## license",
)


def _check_readme(text):
    lowered = text.lower()
    for phrase in README_PHRASES:
        if phrase not in lowered:
            raise AssertionError("doc states " + phrase)


def test_readme_accept():
    _check_readme(_text("README.md"))


@pytest.mark.parametrize(
    ("old", "new", "phrase"),
    [
        ("# P11Lab", "# P11 Lab", "# p11lab"),
        (
            "24 locked provider candidates",
            "24 qualified providers",
            "24 locked provider candidates",
        ),
        ("2026-10-28", "2020-10-28", "2026-10-28"),
        (
            "confirmed seven alpha image pins",
            "confirmed seven beta image pins",
            "confirmed seven alpha image pins",
        ),
        (
            "docs/published-images.md",
            "docs/published-pictures.md",
            "docs/published-images.md",
        ),
        (
            "docs/integration-validation-status.md",
            "docs/integration-validation-hopes.md",
            "docs/integration-validation-status.md",
        ),
        ("## License", "## Legal", "## license"),
    ],
)
def test_readme_rejects_mutations(old, new, phrase):
    with pytest.raises(AssertionError, match=_match(phrase)):
        _check_readme(_mutated("README.md", old, new))
