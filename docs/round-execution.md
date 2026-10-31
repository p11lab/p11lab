# Round execution (`p11lab round execute`)

`round execute` runs one policy lane over the fixture or github transport and
returns a verdict row with a typed cause. Fixture callers stage the builder
identity explicitly; github binds builder and sandbox from the enrolled
producer profile and requires owner-proven staging. This document covers the
execution chain only; evidence binding stays in `round-contract.md`, which
this slice does not touch.

```console
p11lab round execute --context context.json --policy-root policy \
    --evaluator-root evaluator --output-dir round-proof --output-json row.json \
    [--tier pr-smoke] [--authority authority.json --baseline baseline/ \
    --candidate candidate/]
```

Exit codes: `0` executed with a verdict row (even on provider failure, which
the row carries), `2` usage, `3` infrastructure or negative gate (the
`admit`/`expose` precedent). Every chain halt still writes the row, receipt,
and capsule, so negatives stay observable. Usage errors (unreadable context,
tier mismatch, unknown lane, stale output directory) raise before any row
exists, mirroring `round prepare`.

## Chain order

`prepare` → `bootstrap` → `produce` → `bind` → `compare` → `coverage` →
`done`. Bootstrap precedes produce because freezing the candidate context
needs the sealed tool inputs; the receipt records the actual phase history.
Each phase writes evidence under the output directory (`prepare/`,
`produce/`, `bind/binding.json`, `compare/`, `coverage/`) plus
`round-receipt.json` and `round-capsule.json`.

- `prepare` reuses round input preparation into `prepare/`.
- `bootstrap` binds the caller-prebuilt sealed evaluator with verify-only
  `SealedToolInputs.from_evaluator`; drift or a wrong pin refuses with the
  exact library text. No evaluator is built here.
- `produce` freezes the candidate context from the prepared fixture sdist,
  the staged builder identity and witness expectation, then runs the real
  `produce_candidate` (the caller may inject an engine, as its own contract
  allows). A non-`produced` observation halts the chain.
- `bind` runs `validate_comparison_envelope` over caller-staged endpoint
  directories and the typed witness. Missing selected obligations are fatal.
- `compare`/`coverage` run the sealed `evidence-compare` and
  `compare-coverage` CLIs (`--output json`) and assemble the verdict here:
  `comparison_positive` needs zero regressions and nothing quorum-unstable;
  `coverage_positive` needs zero mechanism-state loss. Verdict inputs are
  re-hashed against the binding before and after each CLI so compared bytes
  stay identical to the bound snapshots. Provider failure does not stop the
  coverage phase.
- `done` queries the `results.py` acceptance predicates (`validate_result`
  on a positive copy of an honest diagnostic mapping) and records the
  blocker in the receipt and capsule limitations. `round_positive` is always
  false; no positive is emitted.

## Callers and seams

The CLI stages the comparison witness and endpoint directories through
the staged-entry bridge (see below) and refuses without them at produce
inputs for fixture (or earlier at bootstrap without a sealed evaluator,
or pre-prepare for github). Library callers stage material explicitly:
`builder` (sealed image, layers, config digest, source epoch),
`authority` (typed witness carrying the expectation), `sandbox` (wheel
name, reports, bounds), and `baseline` / `candidate` endpoint
directories. For fixture these are fully caller-staged; for github the
builder and sandbox bind from profile material instead (see below),
while the witness and endpoint directories stay caller-staged.
Seams (`run_prepare`, `bind_produce_inputs`, `engine`, `bind_evaluator`,
`bind_envelope`, `run_compare`, `run_coverage`) default to the real
primitives; hermetic tests inject fakes. Only public library operations are
used; worker/bootstrap/comparison/results internals are untouched.

## GitHub transport (C1b)

Github runs the same chain, verdict row, capsule, receipt, and 14-cause
vocabulary as fixture. The CLI stages nothing, so it refuses github before
prepare (`EXECUTE_TRANSPORT_REFUSED`) without touching the network. Library
callers stage owner-proven material to proceed: the typed `authority`
witness and `baseline` / `candidate` endpoint directories from owner-proven
github downloads (verified by the existing bind before any verdict). The
builder source epoch binds from the enrolled profile `runtime` block (see
the epoch note below). Caller `builder` / `sandbox` / `source_date_epoch`
values are rejected for github; fixture rejects the github-only staging
parameters; all rejections are typed, never silent.

`prepare` performs the owner proof, policy-bundle, cache/dist, and identity
checks over the network boundary; its precise errors propagate unchanged
(exit 2), exactly as for fixture. A prepared run without a verified owner
proof (unenrolled trust root) refuses after prepare with
`EXECUTE_TRANSPORT_REFUSED`. At produce, the binder cross-checks the shipped
enrolled profile against the prepared profile pin, then binds
`BuilderIdentity.image/layers/config_sha256/source_date_epoch` from the
profile `runtime` block and `SandboxPolicy.max_output_bytes` from the same
block, the wheel name from the prepared candidate dist primary wheel, and
reports/timeout from explicit staging or the fixture-tested defaults (no
silent widening). A profile mismatch, a missing profile epoch, or an
unbound wheel refuses with `EXECUTE_PRODUCE_INPUTS_MISSING`.

Epoch note (B-C1c enrolled): the profile `runtime` block carries a
`source_date_epoch` leaf pinned from the producer commit's committer
timestamp at enrollment, mirroring the evaluator source pin. The binder
reads it after the digest cross-check; explicitly staged epochs are
rejected, and a missing leaf refuses fail-closed.

## Staged-entry bridge (B-C2x mechanics, H-C-NOT-DEMONSTRATED)

The CLI bridge (`--authority`, `--baseline`, `--candidate`) stages the
typed witness plus the two endpoint directories; the flags are
all-or-none and omitting all three preserves the legacy unstaged call.
The authority file is staged controller JSON with exactly two keys:
`expectation` (a comparison envelope, frozen with the existing
`freeze_comparison_expectation` contract) and `observations` (a
`local-controller` observation mapping, canonicalized to witness
bytes). `rounds.load_staged_comparison` validates every entry before
dispatch: non-`Path` types raise `TypeError`, while partial flags,
missing/non-directory/noncanonical endpoint roots, a missing or
oversized authority file, malformed JSON, a failing expectation
freeze (exact contract text propagates), non-object observations, and
unsupported provenance (anything but `local-controller`) raise
`ValueError`, so the CLI reports exit 2 with the executor untouched
(no output directory, no row).

The witness is an interface boundary type, never authority: parsing
JSON never confers producer authority. The authority file must be
independently staged controller material, so a file staged under
either endpoint root is refused as candidate-controlled before
dispatch; after dispatch the existing binder re-verifies the envelope
against the independent expectation and the sealed evaluator against
the protected pin, so misbound or changed staging refuses with its
typed `EXECUTE_BIND_*` cause, never silently. Endpoint roots must be
canonical absolute directories (mirroring the binder's own rule).

Mechanics closure is `MECHANICS-COMPLETE / H-C-NOT-DEMONSTRATED`:
minted staged files reach exit 0 through the typed staged-entry path
with injected verdict seams (run IDs minted, capsules diagnostic,
`round_positive` always false), while the real CLI dispatches staged
entries to the honest gates (fixture refuses at bootstrap without a
sealed evaluator; github passes the transport gate into preparation).
Live honest-control proof waits on auth-gated enrollment plus an
authorized live dispatch. The G7 launcher probe
(`P11LAB_C2X_G7_EVALUATOR_ROOT`, env-gated) asserts the sealed
launcher is present as a regular file and that both sealed verdict
commands accept the documented argv shape; the unit gate stays
hermetic (the probe skips without the variable).

## Verdict row, capsule, receipt

The row carries lane/provider, transport, tier, attempt, phase, status,
cause, cause detail, exit code, comparison/coverage positives, regression
and improvement rows, selected/observed counts, missing selected names,
usability/evidence flags, producer status, receipt/expectation/policy
digests, attempt/shard rosters, and the candidate coverage map (ten states,
ten names each). Statuses are `executed`, `provider-failure`,
`infrastructure-error`, and `refused`; causes are the closed `EXECUTE_*`
enum in `round_core/causes.py` with a fixed status/exit table.

The capsule (`p11lab-round-execution-v1`) is round-native with proxy-shared
leaves: schema, tier, framework SHA, policy record, expectation/observation
and evaluator-receipt digests, bound endpoints, the verdict row, promotion
flags (always false), receipt/capsule artifact names, a self hash (SHA-256
over canonical bytes with `capsule_sha256` nulled), the raw artifact
manifest, usability/evidence leaves, and limitations. The receipt records
inputs, phase history, artifacts present at write time, the acceptance
query, and the verdict digest. Receipt command logs are data only; nothing
executes them.

## Hermeticity and residuals

Unit and CLI tests are hermetic: fixture contexts, a minted stage-compatible
dist, a fake engine with a canned `docker cp` queue, injected binders and
verdict runners, and byte-backed endpoint fixtures. Github tests mock the
network boundary at the `run_prepare` seam (the dist still goes through the
real `verify_dist_bytes`) and block sockets process-wide. One fixture test
is env-gated (`P11LAB_EXECUTE_LIVE=1`) for a real Docker plus sealed-evaluator
run and is designed, not run, here; one github test is likewise gated
(`P11LAB_EXECUTE_GITHUB_LIVE=1`, with `P11LAB_EXECUTE_GITHUB_CONTEXT`,
`P11LAB_EXECUTE_GITHUB_EXPECTATION`,
`P11LAB_EXECUTE_GITHUB_OBSERVATIONS`, `P11LAB_EXECUTE_GITHUB_BASELINE`,
`P11LAB_EXECUTE_GITHUB_CANDIDATE`, and `P11LAB_W01_OUTPUT` plus owner-proof
context inputs) for a real owner-proof plus Docker run. Bridge
mechanics tests are hermetic too: staged-context schema accept/reject
rows run the real producer resolver (stubbed transport) into the real
preparation gates (sockets blocked for the accept case), and minted
staged entries run the real CLI into the honest refusal gates. Residuals:
provider-failure classification in the real compare parser awaits the owning
repo's output contract (it stays false; injected runners prove the status
path); `evidence-compare` takes per-endpoint `ledger.jsonl` file operands
while `compare-coverage` keeps endpoint directory operands; multi-lane
orchestration belongs to a later slice.
Auth-gated residuals stay open: pin/trust-root/baseline enrollment,
caller-repo producer staging (dist/control artifacts, endpoint
evidence), builder-repo naming/qualification, owner-proof enrollment,
the live evaluator-build timing versus the 10-minute job budget, and
one authorized live dispatch proving the full run.
