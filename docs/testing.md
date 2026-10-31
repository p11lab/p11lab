# Testing levels

## Bounded Linux validation

`linux-unit-validation.yml` runs on pull requests and manual dispatch. It has
one `ubuntu-24.04` job with a ten-minute ceiling, read-only repository
permissions, and no persisted checkout credentials. It does not build provider
images, start live providers, publish artifacts, export caches, or change the
delivery and Windows workflows.

The job runs the **full pytest collection** without selection filters or
failure suppression. This includes source contracts, lifecycle behavior,
installed-wheel checks, and real checker planning/merge/adaptation tests.
Python 3.12.14, uv 0.12.23, pytest 9.1.1, and the Linux Python dependency closure
are version-pinned. The checker is installed from the immutable source revision
in `src/p11lab/data/tools.json` and must identify as version 0.2.3. Its installed
source URL and commit are verified before testing; absence is an error rather
than a reason to omit checker tests.

`.github/requirements/linux-unit.txt` pins both runtime test dependencies and
build-backend dependencies. The direct installations use no dependency
resolution and no build isolation. Installed-wheel fixtures still exercise
their normal isolated builds, with `UV_BUILD_CONSTRAINT` applying the same pins
to those builds. `uv pip check` validates the installed dependency requirements.
Package versions are pinned, not package archive hashes; the hosted runner's
OS and system-tool updates are not frozen by `ubuntu-24.04`.

Third-party pytest plugin autoload is disabled so unrelated installed plugins
cannot change collection. The checker and its dependencies remain installed,
and the checker tests run normally. The job prints the installed versions and
checker provenance, pytest prints all skip reasons, and the job summary records
test/failure/error/skip totals plus every distinct skip reason. Test failures
fail the job. A missing or unreadable test report is not evidence of a pass.

The workflow changes no provider, checker, dataset, image, or publication
eligibility. Installing the pinned checker for private CI execution is not an
assertion of distribution-license clearance.

## Live-provider and platform evidence

The live-provider integration tests keep their existing explicit image,
client, checker, and caller input gates. The bounded workflow does not supply
these inputs, so those tests are collected but skipped, visibly. These skips
mean runtime evidence is absent. A green bounded check is **not provider runtime
qualification**, Windows compatibility, a successful provider rebuild, or
publication approval.

Full runtime evidence requires separate, explicitly provisioned runs with the
locked provider/tool inputs and retained receipts described in
[runtime-contract.md](runtime-contract.md), [proxy.md](proxy.md),
[native.md](native.md), and [delivery.md](delivery.md). The existing Windows
native workflow may also be triggered by its own path rules on other changes;
this bounded workflow does not replace or relax those rules. Resource-intensive
provider matrices, publication, releases, and cache exports remain separate
operations.

## Local reproduction

When editing this workflow, run `actionlint` 1.7.12 against
`.github/workflows/linux-unit-validation.yml` as well as the pytest contract
tests. YAML parsing alone does not validate GitHub's expression-context rules.

Use Python 3.12.14 and an isolated virtual environment. The workflow's install
steps are the authoritative commands: install uv 0.12.23, install the pinned
requirements without dependency resolution, then install P11Lab and the checker
at the revision in `tools.json` without dependency resolution or build
isolation. Verify the checker provenance and run:

```sh
export PYTEST_DISABLE_PLUGIN_AUTOLOAD=1
export UV_PYTHON=3.12.14
export UV_PYTHON_DOWNLOADS=never
export UV_BUILD_CONSTRAINT="$PWD/.github/requirements/linux-unit.txt"
python -m pytest -ra
```

Keep uv on `PATH` and use a writable uv cache. Sandboxed hosts may forbid local
Unix sockets or process operations that an ordinary Linux runner permits.
Report these failures explicitly; do not skip or reinterpret them as passes.

## ExperimentResultV1

[result.schema.json](../src/p11lab/data/ci/result.schema.json) defines the closed
JSON shape for `schema_version=1`, `kind="experiment-result"`.
`p11lab.results.validate_result(record)` checks its structure and cross-field
invariants and returns a detached JSON value. It uses only the Python standard
library. Unknown fields/stages, bool-as-int values, partial/tag identities,
non-JSON/nonfinite values and conflicting artifact identities fail with explicit
field diagnostics. Validation checks declarations; trusted consumers must still
authenticate authority and read/hash/admit the referenced bytes independently.
It performs no comparison, registry readback or rights assessment itself.

| Fields | Serialized meaning |
| --- | --- |
| `experiment_kind`, `stage` | Kind is image/checker/proxy/consumer; stage follows the applicability table below |
| `caller` | `kind`, `repository`, `run_id`, `run_attempt`, `job`, `local_run_id`; GitHub requires real positive integer IDs and repository, while local requires null GitHub fields and an explicit local ID |
| `identities` | Separate control/candidate/evaluator/policy/inputs/derivative/client/source records; each has `status`, `sha256`, `source_revision`, `artifact`, `reason` |
| Identity applicability | `recorded` requires SHA256 and null reason; `unperformed`/`not-applicable` require null identities and an explicit reason. Source revisions and ArtifactRefs are additionally recorded where applicable; one identity never substitutes for another |
| `policy_revision` | Human policy revision, distinct from the frozen policy/input byte hashes |
| `provider` | environment/channel/platform, exact `artifact`, `registry_status`/`registry_reason`, `root`, platform/config/local-engine IDs, `build_receipt`, `provider_build_key`, `experiment_key` |
| Provider applicability | Registry identity is either recorded with complete root/platform/config digests or unperformed with explicit reason and null registry fields. Exact local `docker-local` ArtifactRef/engine/build receipts need no invented registry digest |
| `execution.profile` | Profile ID and exact SHA256, nullable before execution |
| `execution.expected_shards`, `roster_sha256` | Frozen ordered roster of outer_attempt_id/shard_id/attempt_id/case_ids; SHA256 of UTF-8 JSON with sorted keys, compact separators and ensure_ascii=False. Empty unperformed roster has null hash |
| `execution.observed_shards` | outer_attempt_id/shard_id/attempt_id, completed/cancelled/missing/upload-lost status, raw process_returncode/findings/skips, raw artifacts and immutable `run_receipt` pointer |
| `execution.raw_status` | Raw process_returncode, findings and skips; none implies a pass or rewrites provider errors |
| `axes` | Explicit independent image_usable/lifecycle_complete/evidence_complete/evidence_admitted/comparison_positive/within_budget/distribution_eligible |
| `policy` | qualification_only/promotable, comparison_required/comparison_performed/coverage_positive, budget_required/budget_performed, distribution_required, image_semantics_reviewed, proxy controls |
| `policy.proxy` | Null outside proxy experiments; otherwise separate cells_admitted_complete/transport_controls_positive/direct_attribution_complete observations |
| `reproduction` | Command argv array, not a shell string with ambiguous quoting |
| `evidence`, artifact pointers | Canonical relative path, exact bytes/SHA256, public HTTPS URL or explicit null, expiry timestamp or null; unavailable public locators remain null |
| `limitations` | Explicit scope, missing proofs, retention and observation limits |

Artifacts use full lowercase SHA256, sizes use exact nonnegative integers, and
UTC timestamps identify observations/expiry. ArtifactRefs retain the existing
kind/reference/sha256/platform contract. Root index identity is conditional on
actual root kind, as in the [pin contract](delivery.md#packaged-image-pin-contract).
An image's engine ID is an independent observation, never assumed equal to config.
Provider build identity and experiment identity remain separate: changing tools,
profile, data or evaluator can require retesting the same provider image.

| Stage | Required achieved evidence/applicability |
| --- | --- |
| `planned` | Explicit unperformed identities permitted; cannot claim completed runtime evidence/comparison |
| `local-built` | Exact local ArtifactRef, engine ID, build key and build receipt; runtime evidence/comparison unperformed |
| `metadata-readback` | Recorded registry root/platform/config identities; cannot claim runtime completion |
| `runtime-diagnostic` | Exact provider artifact, profile and frozen expected roster; incomplete or negative observations retained |
| `qualification` | Same execution identity requirements; comparison can remain explicitly unperformed; cannot claim promotability |
| `accepted` | Complete/admitted evidence and applicable positive policy predicates below |
| `promoted` | Accepted predicates plus explicit promotable=true; image semantics review applies |
| `published` | Promoted predicates plus recorded registry root/platform/config identity |

Every stage after planned requires recorded candidate/policy/input hashes and
experiment key. Performed comparison requires independently recorded control and
evaluator hashes. Comparison is null **only** with comparison_performed=false,
and coverage is then null too. Measured budget is a boolean; an unperformed budget
is explicitly null. Runtime proxy results additionally require derivative/client
identities and explicit proxy controls. Required-but-unperformed comparison may be
retained diagnostically; it cannot satisfy accepted/promoted/published stages.

An accepted claim requires image_usable, lifecycle_complete, evidence_complete,
evidence_admitted, comparison_positive and coverage_positive all true, active
required/performed comparison, and qualification_only=false. Required budget and
distribution gates must also pass. Image acceptance/promotion always additionally
requires within_budget, distribution_eligible and image_semantics_reviewed true.
Proxy acceptance always requires within_budget and all three independent proxy
controls true (A/S/T/R/B); direct outcomes need not equal proxy outcomes. Checker
comparison remains delegated to the trusted evaluator: an added skip without
exercise loss can remain positive; image observation review is an additional
image predicate. This validator does not implement a replacement comparator.

A completed negative comparison is a valid result. So are nonzero native findings
exits and explicit budget/distribution negatives in diagnostic/qualification
records. Process exit zero supplies none of the missing axes. Changing only
promotable or stage cannot override failed policy facts. Known unchanged findings
may coexist with accepted evidence when the trusted comparison and coverage pass.

`outer_attempt_id` explicitly groups one scheduled outer repetition of the
experiment. Within each outer group, shard IDs are unique and authored case IDs
are disjoint. The same shard IDs and case IDs may repeat across scheduled outer
groups, preserving the original case names. `attempt_id` identifies each physical
per-shard invocation, distinct across the entire frozen roster; producers using
RunSpec bind its original fresh invocation UUID, rather than reusing it as an
outer-group ID. Each observed outer/shard/invocation triple must match the exact
frozen expected triple. The expected roster is independently authored policy
input; recomputing a hash alone does not authenticate a changed schedule.

Completeness requires every scheduled outer/shard/invocation triple, completed
status, raw process status, raw artifact and immutable run-receipt pointer.
Missing scheduled second observations, cancelled, upload-lost, duplicate,
unexpected and within-outer overlapping members cannot satisfy it. Scheduled
N=2 observations belong in the same frozen roster, rather than being treated as
optional retries. Retries use fresh invocation IDs/results; failed attempts remain
retained without silently replacing the frozen expected attempt. This record
expressiveness does not activate release N=2: EVID-STREAM-1 and the other release
gates remain blocked until independently satisfied. Contradictory hashes/sizes for
the same artifact path fail. Existing run receipt v1 remains authoritative for
lifecycle facts; this result references its exact bytes without changing its
schema. Evidence admission requires evidence_complete=true but is still an
independent trusted-consumer operation. Null/expired URLs are explicit retention
limits; a structurally valid historic result does not authenticate currently
available evidence. Required source/license artifacts remain durable separately
from bounded raw traces.
