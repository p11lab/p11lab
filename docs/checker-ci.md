# Checker CI caller contract

Diagnostic-only reusable workflow: `.github/workflows/checker-round.yml`.
It validates policy and writes a diagnostic manifest only: it does not
execute or qualify a round and cannot satisfy a release gate.

## Inputs

| Input | Required | Shape |
| --- | --- | --- |
| `framework_sha` | yes | full 40-hex candidate commit SHA |
| `tier` | yes | exactly one of `pr-smoke`, `nightly`, `release` |
| `p11lab_ref` | yes | full 40-hex P11Lab control checkout SHA |

The caller's literal `uses` SHA must equal the literal `p11lab_ref` value.
No eligible published revision exists yet (ASK-9 deferred), so the SHA is
a forward pin, not a usable reference today.
The control checkout is explicitly `repository: p11lab/p11lab`,
`ref: p11lab_ref`, `path: p11lab-control`, with credentials not
persisted; control identity is verified with `rev-parse`.

## Outputs

`round_positive`, `receipt_artifact`, `capsule_artifact`,
`capsule_sha256`, `raw_artifacts_manifest`. In this diagnostic slice
`round_positive` stays `false` and the artifact outputs stay empty:
policy must remain diagnostic, and the manifest records
`diagnostic_only` with null receipt/capsule/sha/manifest.

Copy the [caller template](../examples/round-consumer/diagnostic.yml)
into the caller's `.github/workflows/`, replace both exact
`<P11LAB_COMMIT_SHA>` placeholders with the same reviewed full commit
SHA after a compatible workflow is published, and set
`<FRAMEWORK_COMMIT_SHA>` to the candidate identity. The template is
unpublished and diagnostic-only: it is not executable as supplied.

Sources: `.github/workflows/checker-round.yml` L2, L5-26, L48-63,
L76, L84-97; `docs/round-gating.md` L5-7, L32-45;
`examples/round-consumer/diagnostic.yml` L1-4, L14-18.

## Execution path

The operational reusable workflow
`.github/workflows/checker-round-execution.yml` stages a full github
context plus a sealed evaluator, invokes `p11lab round execute`
through the staged-entry bridge (B-C2x mechanics,
H-C-NOT-DEMONSTRATED), and uploads one evidence artifact. It takes the
same three inputs (`framework_sha`, `tier`, `p11lab_ref`; the caller
`uses` SHA must equal `p11lab_ref`) and returns three outputs:
`round_positive` (always `false`; the capsule is asserted diagnostic),
`execution_artifact` (the single uploaded artifact name), and
`capsule_sha256`. Top-level permissions are empty; the `execute` job
carries `contents: read` + `actions: read` (same-run artifact metadata
only: current run and attempt, no cross-run lookup).

Staging runs in four steps after the input guard, control checkout,
control-identity verification, and Python setup. `Stage round
execution material` keeps the attempt-bound 6-field archive plus an
evaluator-root placeholder. `Resolve producer run and stage context`
runs one `round resolve-producer` call that stages the authority,
baseline, and candidate entries plus the full-shape github context;
nothing is minted here — minted staging is forbidden and the contract
check enforces it — so unresolved leaves refuse honestly instead.
`Upload resolution evidence` uploads the staged directory only when
resolution fails. `Stage sealed evaluator` builds the exact reviewed
evaluator in-job via `acquire_evaluator` (anonymous fetches only; no
tokens, secrets, or cross-job downloads, which the host-bound receipt
roster would refuse) and asserts the sealed launcher. Preparation
builds its own evaluator copy internally, so the double-build cost is
documented, not optimized, here.

The execute step passes each bridge entry it finds staged
(`--authority`, `--baseline`, `--candidate`) with the full context
when present, else the legacy 6-field context without flags; the CLI
enforces all-or-none, so partial staging refuses loudly as usage
(exit 2, no row) rather than proceeding silently. The step refuses
with exit 3 when the staged attempt identity mismatches the current
attempt, otherwise runs `round execute`, asserts the capsule stayed
diagnostic, writes an execution manifest
(`p11lab-round-execution-v1`) even when no row exists (manifest-only
evidence records the refusal instead of leaving the job without
artifacts), and echoes fail-closed outputs. Every manifest carries
explicit non-H-C provenance: `bridge` (`absent`/`partial`/`staged`),
`context_shape` (`legacy`/`full`), `live_qualified: false`,
`honest_control: H-C-NOT-DEMONSTRATED`, `mechanics: B-C2x`,
`diagnostic_only: true`, and a limitations list naming the pending
enrollments. The single artifact
`p11lab-round-execution-<run_id>-<run_attempt>` holds the verdict row,
receipt, capsule, and manifest (manifest only when no row exists)
with 14-day retention. A final report step exits 3 on refusal, after
the upload, so missing staged material refuses loudly with its typed
cause and uploaded evidence, never silently. No retries,
normalization, or silent skips; no `secrets: inherit` or
`continue-on-error`. The single `if:` (`failure() &&
steps.context.conclusion == 'failure'` at
checker-round-execution.yml:113) gates the resolution-evidence upload
and is mandated by the contract check
(scripts/check_round_workflows.py:119).

Copy the [execution caller
template](../examples/round-consumer/execution.yml) into the caller's
`.github/workflows/`, replace both exact `<P11LAB_COMMIT_SHA>`
placeholders with the same reviewed full commit SHA after a compatible
workflow is published, and set `<FRAMEWORK_COMMIT_SHA>` to the
candidate identity. The template is unpublished: it is not executable
as supplied. Caller permissions are `contents: read` plus `actions:
read` (top-level and job-level).

Execution sources:
`.github/workflows/checker-round-execution.yml` L1-6, L10-27, L30-34,
L40-67, L68-91, L92-111, L112-119, L120-143, L154-162, L163-171,
L178-187, L195-209, L210-224, L225-231, L232-240;
`examples/round-consumer/execution.yml` L2-6, L10-12, L14-22.
