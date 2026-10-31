# Round tiers and gating

Status: diagnostic-only. This doc records which round tiers exist, what
their gates are, and what diagnostic runs do and do not establish. Every
shipped round policy is `diagnostic`: runs validate policy and emit
diagnostic manifests only, and cannot satisfy a release gate. No tier
currently qualifies a provider.

Sources: `.github/workflows/checker-round.yml` L1-2;
`.github/workflows/proxy-round.yml` L1-2; `docs/round-contract.md`
L313-321; `src/p11lab/data/rounds/policy.json` L4;
`src/p11lab/data/ci/proxy-policy.json` L4-7.

## Checker tiers and lanes

| Tier | Mandatory lanes | Attempts | Leg target | Retention |
| --- | --- | --- | --- | --- |
| `pr-smoke` | SoftHSM2 only | 1 outer attempt | 20-min leg target | 14-day durable retention |
| `nightly` | SoftHSM2, Kryoptic, NSS | 1 outer attempt | 90-min leg target | 30-day durable retention |
| `release` | above plus TPM2, OpenCryptoki | 2 outer attempts | 90-min leg target | 90-day durable retention |

All active lanes run Linux amd64 on runner `ubuntu-24.04`. OpenCryptoki
uses `pkcs11-proxy-ng` transport; every other active lane uses direct
transport. Leg targets and retentions are policy values; budgets are
unmeasured targets, and budget values require measurement before any
qualification use.

Sources: `src/p11lab/data/rounds/policy.json` L5-41 (tiers), L44-104
(lanes); `docs/round-contract.md` L291-311;
`.github/workflows/checker-round.yml` L50.

## Checker caller contract

Exactly three inputs, all required strings: `framework_sha`, `tier`,
`p11lab_ref`. The caller's literal `uses` SHA must equal the literal
`p11lab_ref` value. The control checkout is explicitly `repository:
p11lab/p11lab`, `ref: p11lab_ref`, `path: p11lab-control`, with
credentials not persisted; control identity is verified with
`rev-parse`. Outputs are `round_positive`, `receipt_artifact`,
`capsule_artifact`, `capsule_sha256`, `raw_artifacts_manifest`
(IF-E5-1–4 shape). Current diagnostic values are `false` with empty
artifacts.
See `docs/checker-ci.md` for the full caller contract; this section summarizes it.
An execution path (`.github/workflows/checker-round-execution.yml`)
takes the same three inputs and returns `round_positive` (always
false), `execution_artifact`, and `capsule_sha256`: one artifact per
run attempt, refusals exit 3 after upload.

Sources: `.github/workflows/checker-round.yml` L6-26, L51-63, L91-97;
`.github/workflows/checker-round-execution.yml` L8-25, L30-32, L142-148,
L149-157.

## Proxy tier and caller contract

The only accepted tier is `proxy-diagnostic-v1`. Exactly three inputs:
`proxy_sha`, `tier`, `p11lab_ref`. Same control-checkout and rev-parse
verification shape as the checker tier. Each of the three cells (direct,
accepted-proxy, candidate-proxy) runs one fresh-state attempt (N=1).
Outputs are `result-artifact`, `result-sha256`, `experiment-positive`.
Same-run artifact name:
`p11lab-proxy-dist-<proxy_sha>-<run_attempt>`; accept only current-run
current-attempt artifacts, no cross-run lookup. Full reruns only: a
partial rerun lacking a current producer fails
`rerun_requires_producer`. Caller permissions are `contents: read` plus
`actions: read`. See `docs/proxy-ci.md` for the full caller contract;
this section summarizes it.

Sources: `.github/workflows/proxy-round.yml` L6-22, L44-57, L89,
L199-207, L286-290; `docs/proxy-ci.md`.

## Proxy positive predicate and typed causes

`experiment-positive = A AND S AND T AND R AND B`, where A means all
three cells admitted and complete; S means accepted-vs-candidate
comparison plus coverage positive; T means every transport control
meets its contract on both proxies; R means direct attribution usable
and complete (raw findings may remain); B means within budgets. Direct
outcomes need not equal proxy outcomes. A passing predicate is a
bounded diagnostic positive, never provider qualification or release
eligibility.

Typed causes (`evaluate_proxy_verdict` in
`src/p11lab/proxy_policy.py`):

| Label | Typed cause | CLI exit |
| --- | --- | --- |
| T1 | `null` (with `experiment_positive: true`) | 0 |
| T2 | completed-negative | 1, evidence complete |
| T3 | attribution-unknown | 1 |
| T4 | control-unqualified | 1 |
| T5 | terminal-evidence-unavailable | 1 |
| T6 | missing-evidence | 1 |
| T7 | budget-exceeded | 1 |
| T8 | usage-or-infrastructure | 2 |
| T11 | design-only bounded-diagnostic limit (bounded diagnostic positive; not an emitted cause) | - (design-only; not emitted) |

Precedence: T8 > T6 > T3 > T4 > T5 > T7 > T2 > T1/T11. The emitted
`(typed_cause, exit_code)` set is pinned in `tests/test_proxy_policy.py`.

Sources: `src/p11lab/proxy_policy.py` L482-542.

## Transport control roster

Each control below runs on both the accepted and the candidate proxy:

| Control | Stimulus | Expected observation |
| --- | --- | --- |
| PX-AUTH | one valid mTLS client, then an invalid/untrusted client | valid enumerate succeeds; invalid handshake rejected before any provider operation, backend call counter unchanged |
| PX-STATE | create a uniquely identified object in instance A, then a live cross-instance lookup in B | A finds exactly its object, B finds none |
| PX-REPLAY | one non-idempotent create, then a transport fault losing the response | no replay; client records transport failure; post-shutdown direct enumeration sees exactly one object; backend operation count is one |
| PX-CLIENT-CRASH | terminate one active client without checker exit finalizer | crash recorded, owned process closed, provider cleanup observed |
| PX-DAEMON-DEATH | terminate a dedicated ready daemon while its client remains | bounded logs retained; client observes transport failure |
| PX-DAEMON-STOP | requested shutdown of a dedicated ready daemon | clean stop recorded; requested stop distinguished from death |
| PX-LIMIT | second simultaneous client against the single-client version | exact pinned rejection; first context unaffected |

The fixed accepted proxy must meet each contract first: an unsupported
or failing accepted control is control-unqualified, never a skip.
A missing PX-LIMIT observer or PX-REPLAY harness leaves the tier
unqualified, never guessed, and blocks a tier positive.

Sources: `src/p11lab/data/ci/proxy-policy.json` controls array;
`src/p11lab/proxy_policy.py` control roster.

## Budgets and retention

Proxy caps: 300 seconds per cell lifecycle/checker, 300 seconds for
transport controls together, 600 seconds acquisition/preflight, whole
active workflow within 30 minutes, raw evidence within 2 GiB,
diagnostics within 16 MiB, 14-day retention; queue time is measured
and reported separately. Checker legs: 20-minute `pr-smoke` target
and 90-minute other targets with 14/30/90-day durable retention per
tier. Exceeding a cap makes `within_budget=false`; selected IDs are
never reduced to fit. All values are proposed, unmeasured targets
(`budgets_qualified: false`); none is a measured budget.

Sources: `src/p11lab/data/ci/proxy-policy.json` L7, L149-157;
`.github/workflows/proxy-round.yml` L272-274;
`src/p11lab/data/rounds/policy.json` L11-40.

## Diagnostic limits

The checker workflow validates policy and writes a diagnostic manifest
only: policy must remain diagnostic, `round_positive=false`, and null
receipt/capsule/sha/manifest. The proxy workflow emits not-executed
cell diagnostics plus a capsule with `experiment_positive=false`,
`evidence_complete`/`evidence_admitted=false`, and typed unqualified
cause `tier-unqualified` (PX-LIMIT pinned rejection unbound; budgets
are unqualified targets). No cell executes. The capsule limitations
record "diagnostic-only: no cell executed; no release gate satisfied".
A diagnostic capsule records its cause; it is never a positive receipt.

Sources: `.github/workflows/checker-round.yml` L76-97;
`.github/workflows/proxy-round.yml` L70-95, L103-198, L224-284;
`docs/round-contract.md` L313-321.

## Release-gate requirements

Release execution additionally requires EVID-STREAM-1 (reviewed
public stream-context API plus a new evaluator pin, then passing
export, admit, and compare controls for pass/pass, pass/fail,
fail/pass, missing, duplicate, overlap, and incomplete streams) and
the IF-E5-2 dry-run path. Release N=2 schedules both attempts always;
disagreement is red. Baseline promotion requires three separate
complete qualification rounds. W23-W26 trust, evidence, and budget
closure applies, with HR1 named approvers, HR2 quota facts, HR3
dispatch authority, and scoped authorization. Linux diagnostic
completion never silently activates release.

Sources: `docs/round-contract.md` L99-108, L295-296.

## N=1 residuals

Single-attempt PR/`nightly` runs cannot detect a within-invocation
flaky-green observation: one favorable observation can pass despite a
flaky provider or test. Three qualification rounds reduce initial
uncertainty but do not remove the per-PR/per-nightly residual. Even
release N=2's two matching observations cannot prove absence of
flakiness. Positive controls and fault mutants must demonstrate the
predicate, including complete-negative evidence.

Sources: `docs/proxy-ci.md` L45-47.

## Activation boundaries

No automatic external notifications or issues. No external action
before scoped authorization: prepare concrete pins and manifests
first, then perform only the approved publication, default-branch
landing, dispatch, required-check, or release activation change.
Rollback disables the new required gate or pin under owner review and
preserves failed attempts; it never silently falls back to
membership-only green or changes provider identity. Windows and macOS
lanes stay explicitly inactive; native tasks stay `postponed`, never
green.

Explicitly open W25/W26 gates (claimed by no slice yet): protected
ownership (CODEOWNERS plus verified protections, needs HR1
identities); E5 handoff acknowledgment including the IF-E5-2 dry-run
mode; measured budgets and quotas; sanitized `docs/results/` pilot
evidence; W26 independent review verdicts and the activation record.

## Image-gate relation

Provider image validation is a separate gate owned by M08
(`.github/workflows/provider-image-validation.yml`): resolve-once
selection, build receipt, M03 local gate before fanout, direct plus
proxy legs, and an always() aggregate. Its promotion predicate is
U/L/E/B/D/C plus `image_semantics_reviewed`. Round outputs (`round_positive`, `experiment-positive`) must
never feed this verdict; the proxy leg is recorded but non-qualifying.
The current verdict is `promotion: blocked`. Full semantics live in
`docs/image-validation.md` and `docs/image-ci.md`.

Sources: `.github/workflows/provider-image-validation.yml` L1-18,
L372-386, L460-485.
