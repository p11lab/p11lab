# Proxy CI caller contract

Diagnostic-only reusable workflow: `.github/workflows/proxy-round.yml`.
It does not execute or qualify a proxy round and cannot satisfy a release gate.

## Inputs

| Input | Required | Shape |
| --- | --- | --- |
| `proxy_sha` | yes | full 40-hex candidate commit SHA |
| `tier` | yes | exactly `proxy-diagnostic-v1` |
| `p11lab_ref` | yes | full 40-hex P11Lab control checkout SHA |

The caller's literal `uses` SHA must equal the literal `p11lab_ref` value.
No eligible published revision exists yet (ASK-9 deferred), so the SHA is
a forward pin, not a usable reference today.
No input selects checker, consumer, dataset, config, or provider: the
accepted proxy, checker, independent consumer, and initial provider
(SoftHSM2 release, Linux amd64) come from protected policy at `p11lab_ref`.

## Outputs

`result-artifact`, `result-sha256`, `experiment-positive`. In this
diagnostic slice the artifact outputs stay empty and `experiment-positive`
stays `false`: results name only a validated existing capsule, and no cell
executes. The candidate lane cells exist in the workflow as STAGED
(not-executed) structure and no staged cell satisfies a control.
The diagnostic capsule records the typed unqualified cause
`tier-unqualified` (PX-LIMIT pinned rejection unbound; budgets are
unqualified targets).

## Caller duties

Build the candidate once before invocation under the M05 producer
boundary; workers consume those bytes with exact byte verification.
Same-run artifact name: `p11lab-proxy-dist-<proxy_sha>-<run_attempt>`.
Accept only current-run current-attempt artifacts; no cross-run lookup.
Bind repository/run/attempt/producer-job/artifact IDs from read-only API
metadata; a manifest's self-assertion is insufficient. Full reruns only:
a partial rerun lacking a current producer fails `rerun_requires_producer`.
Official callers derive the candidate from `pull_request.head.sha` on
`pull_request`, never executing it under `pull_request_target`;
third-party callers resolve the actual upstream revision and never relabel
the application event SHA. Declare caller `permissions: contents: read` +
`actions: read` (top-level and job-level, as the callee requires),
use full-SHA action pins, and keep private paths and dispatch tokens out
of the caller file.

Owner-proof caller steps (producer job only): the producing job writes
`round-artifact.json` (`schema_version`, `dist_digest`, `run_id`, `attempt`),
attests it under predicate type `https://p11lab.org/attestations/round-artifact/v1`
with predicate `{'schema_version': 1, 'producer_job': profile['producer_job']}`,
and uploads the single envelope file
`round-attestation.json` (`subject_b64`, `bundle_b64`) as the artifact named by
the profile template. Set `dist_digest` as `'sha256:' + hashlib.sha256(dist_raw).hexdigest()`
over the exact dist bytes; encode `subject_b64`/`bundle_b64` with the standard alphabet
accepted by `base64.b64decode(envelope['subject_b64'], validate=True)` and
`base64.b64decode(envelope['bundle_b64'], validate=True)`.
Grant `id-token: write` exclusively to the producer job;
no other job may hold it. Caller repositories and their workflow revisions stay
owned by the caller owner: this contract specifies the steps, and this slice
ships the consumer-side verifier only, with no caller-repo edits.

## Proxy execute gates (P1a)

`p11lab proxy execute --artifact PATH --run-id R --attempt N --output-dir O
--output-json V` gates one caller-built artifact without executing any
cell. PATH is a directory whose basename is the claimed same-run artifact
name `p11lab-proxy-dist-<proxy_sha>-<run_attempt>`; it stages `records.json`
(API listing snapshot), `authority.json` (staged repository/producer bind),
`manifest.json` (caller build manifest), the daemon/CLI/shim payload bytes,
the daemon build claim, the native-client manifest, launch rehashes, the ABI
observation, daemon image naming, the child inspection, the parent ref, and
optionally the explicit expected proxy identity (caller-staged, test-only
authority like `run --proxy-build-manifest`; absent means the absolute
pinned default).

Gate order is selection (same-run current-attempt + authority bind;
full-rerun rule) → bytes (manifest roster, payload rehash, digest agreement
with claim/roster) → install (recorded-vs-selected client validation before
any container) → identity (daemon/client/record sameness at the check gate)
→ derivative (parent ref + layer prefix, no Docker). Refusals carry typed
causes `PROXY_GATE_SELECTION_REFUSED`, `PROXY_GATE_BYTES_REFUSED`,
`PROXY_GATE_INSTALL_REFUSED`, `PROXY_GATE_IDENTITY_REFUSED`,
`PROXY_GATE_DERIVATIVE_REFUSED` with the exact gate text; every refusal
exits 1 with `evidence_complete` false and a `missing-evidence` verdict
mirror (the T6 verdict P1b would emit for unrun cells). Gated material exits
0 with verdict pending; experiment_positive stays false on every path —
gates never emit a positive. Usage errors (bad IDs, missing artifact, stale
output directory, unreadable staged inputs) raise and exit 2. Cells, verdict,
and capsule belong to P1b: rows record cells+verdict+capsule as
not-run/pending/absent.

## Proxy execute cells (P1b)

`execute_proxy_experiment` continues past the P1a gates: admission
reuses `execute_proxy` unchanged (refusals run no cells and write no
capsule), then the three cells — direct, accepted-proxy,
candidate-proxy — run in order through the injected `CellExecutor`
seam. The production executor is a thin adapter over the real runners
(`run_proxy` for proxy cells, `run_native_softhsm` for direct);
hermetic runs inject scripted fakes. Cell order is
accepted-before-candidate: a candidate crash claim surfaces as
completed-negative only when the accepted control passes, because an
accepted death fails the accepted control and the real verdict's
precedence then yields control-unqualified ahead of any candidate
claim. Deaths without retained logs yield
terminal-evidence-unavailable instead. Every crash observation binds
run/cell/retained-logs; misbound executors fail loud as
usage-or-infrastructure with their exact text.

The verdict is the real `evaluate_proxy_verdict` output verbatim
(T-series texts, exits, and flags exact); rows and the
`proxy-capsule.json` capsule (schema
`p11lab-proxy-experiment-result-v1`, proxy-native `cells{}`/
`experiment_*`/control rows plus the shared `image_usable`,
`evidence_complete`, `evidence_admitted`, `comparison_positive`,
`limitations[]` leaves) always carry `experiment_positive` false with
`live_qualified` false: controls from scripted cells are unqualified
by construction, and the slice's own positive claim waits for live qualification.
Comparison stays caller-performed and budgets stay
unqualified targets. Real-Docker local proofs run where a daemon
exists and never gate hermetic green; full live dispatch is env-gated
by design and not part of this slice.

## Proxy distributed execution (P1c)

`p11lab proxy execute-cell --cell CELL --artifact PATH --run-id R
--attempt N --cell-payload FILE --output-dir O --output-json V` gates
one caller-built artifact (reusing `execute_proxy`: refusals run no
cell, write no observation file, and exit 1), then runs EXACTLY one
named cell (`direct`, `accepted-proxy`, `candidate-proxy`) through
the production adapter and writes the frozen cell-observation
artifact `O/<CELL>.json` (schema
`p11lab-proxy-cell-observation-v1`: run, attempt, cell, observation,
log refs, plus cited gates/selection). The staged cell payload is
bounded JSON — production runner inputs (`spec` run descriptor,
`plan` or `installed_prefix`, `log_refs`) with exact keys and strict
types; bad payloads raise before admission and exit 2. Executor
failures and misbound returns exit 2 as
`usage-or-infrastructure` with the exact `cell <CELL> executor ...`
text, still writing the observation file so the aggregate can cite
the failure. The cell row keeps `verdict` pending and writes no
capsule: a single cell never completes experiment evidence.

`p11lab proxy aggregate --cells-dir D --run-id R --attempt N
--comparison FILE --budgets FILE --output-dir O --output-json V
[--cancelled] [--uploads-incomplete]` merges uploaded cell
observations without executing anything: each cell ran once in its
own job and the aggregate re-executes nothing (it takes no
executor). It reads `D/<CELL>.json`, binds run/attempt/cell from
the invocation, checks cross-cell selection agreement, runs the
REAL `evaluate_proxy_verdict` oracle, and writes the experiment row
plus `proxy-capsule.json` (same shape as the P1b loop, with
`experiment_positive` false and live qualification pending).
Missing or skipped cells yield `missing-evidence` (T6); corrupt or
misbound staged cells yield `usage-or-infrastructure` (T8) while
every well-formed sibling still aggregates (unlike the single-loop
entry, which stops after an infrastructure error). Exits stay
exact: 0 executed, 1 gate/verdict refusal with typed cause, 2
usage or infrastructure — never checker exit 3.

## Proxy execution workflow (B-P2)

The operational reusable workflow is
`.github/workflows/proxy-round-execution.yml`. It takes the same three
inputs (`proxy_sha`, `tier`, `p11lab_ref`) and returns the same three
outputs (`result-artifact`, `result-sha256`, `experiment-positive`) as
the diagnostic workflow. Validate, direct, accepted-proxy,
candidate-proxy, and aggregate keep the 10/10/10/10/30-minute limits
with an `always()` aggregate over the four predecessors.

Each cell job runs EXACTLY one cell per job via `p11lab proxy
execute-cell --cell/--artifact/--run-id/--attempt/--cell-payload/
--output-dir/--output-json`: the job downloads the same-run
current-attempt producer artifact, invokes one named cell, uploads the
cell observation artifact `p11lab-proxy-cell-<cell>-<run>-<attempt>`
(row, observation, gated record, and the cell log alongside), then
reports the captured exit. No job re-executes the whole experiment:
`execute-cell` runs one named cell and the aggregate re-executes
nothing. The aggregate downloads the three uploaded observations with
tolerant same-run reads (missing uploads stay missing evidence, never
silent skips), then runs `p11lab proxy aggregate`
over them with `--cells-dir/--run-id/--attempt/--comparison/
--budgets/--cancelled/--uploads-incomplete --output-dir/--output-json`,
uploading the verdict row artifact
`p11lab-proxy-verdict-<run>-<attempt>` and the capsule artifact
`p11lab-proxy-capsule-<run>-<attempt>` before reporting the verdict.

The producer stages the per-cell `cell-payload-<cell>.json` inputs plus
caller-performed `comparison.json` and `budgets.json` inside the dist
artifact with the artifact-dir basename preserved; the full-rerun rule,
same-run current-attempt selection, and metadata over manifest binding
from the caller contract apply unchanged, and upload-before-report
holds on every evidence path: refusals and verdicts upload first, then
the report steps propagate the proxy exits 1 and 2 exactly, never the checker exit 3.
Steps that capture no row (usage failures before any evidence exists)
record the `missing-row` cause and fail loudly at the upload. The
aggregate treats T3 and T6 as incomplete-evidence refusals (exit 1,
evidence incomplete); only T2 completes evidence. Every result binds
run, attempt, candidate, and cell. Claims stay scaffold-scoped until
live qualification: `experiment-positive` stays `false` on every path,
including T1-shaped verdicts, which are reported exact but never
claimed. Live dispatch stays env-gated by design and is not part of
this slice.

## Residuals

N=1 cannot detect within-invocation flaky-green observations. Positive controls and fault mutants must demonstrate the predicate, including complete-negative evidence. Queue time is measured and reported separately; job timeouts never bound queue.
