# Evaluator bootstrap and round evidence contract

P11Lab's round evaluator is a separate trusted installation built from public
`pkcs11-check` source commit
[`09aabfec9fea7e424aabb991f6347349bfa84075`](https://github.com/mingulov/pkcs11-check/tree/09aabfec9fea7e424aabb991f6347349bfa84075),
tree `59e8db7572575ec82f9ef56e27fa6a2f4bc574da`. Its package version is `0.2.3`;
that version alone does not identify the evaluator. This contract does not
activate release pins or qualify any provider.

The packaged `data/rounds/evaluator/source.json` binds the source archive and
critical files, Python 3.12.14 archive, reproducible build timestamp, and exact
build/runtime wheels. The two adjacent hash-required locks constrain the build
frontend, backend, pip and the full declared evaluator runtime dependency
closure. `data/rounds/tooling.json` and `.github/requirements/round-unit.txt` seal
independent round verification tools, including actionlint 1.7.12, ruff 0.15.18
and mypy 2.1.0. Ordinary provider images do not acquire these dependencies.

`p11lab.round_core.bootstrap.acquire_evaluator(source_pin, lock_root, output)`
accepts only the packaged reviewed source pin. It fetches HTTPS objects, verifies
size and SHA-256 before extraction, rejects unsafe or duplicate archive entries,
and installs into fresh environments. Build and installation use only sealed
wheels, `--no-index`, `--require-hashes`, and no editable installs. The evaluator
wheel is built with `build --wheel --no-isolation`; a published evaluator wheel
is unnecessary. Source/dependency acquisition failure stops the bootstrap.

The supported bootstrap target is Linux x86_64 with glibc at least 2.39. The
portable Python's `lib` directory is the explicit native library search path;
its bundled Tcl/Tk libraries are part of the recorded Python closure. Commands
use a fresh HOME, fixed locale, `-I -B`, and a scrubbed environment. Caller Python
paths, pip configuration and workspace checker installations supply no evaluator
code. This trusted-source bootstrap is not a sandbox for candidate build hooks.

`evaluator-build-receipt.json` records the actual wheel hash, source identity,
Python archive/executable/stdlib inventory, build/runtime/tool wheel hashes,
installed file inventories and origins, native library hashes, source epoch,
commands and results. Reuse verifies complete file rosters and hashes as well as
the current source and dependency locks. Replay also reconstructs the exact permitted
process environment, release dependency state, installed import paths, tool/API/help
observations and driver identity; altered operational metadata is rejected. Receipt
command logs are historical observations and are never executed by the verifier.
Preserve incomplete output for diagnosis
and use a fresh output directory for another attempt.

The E4 receipt verifier is a source companion, not a wheel entry point. Bootstrap
copies `scripts/verify_round_receipt.py` with the source licenses and notices. Its
SHA-256 is `ab72ff5d8ae6081574c16a7ea19543a0c64d3da29ca7c18e213093bc48810891`.
Invoke the trusted copy as:

```console
python3 scripts/verify_round_receipt.py RECEIPT --lock LOCK --expect-fw SHA
```

It returns 0 for a valid receipt, 1 for invalid evidence and 2 for usage or
infrastructure failure. P11Lab retains the full acquired source and upstream
license files; any future distribution still needs its own actual-content and
source-obligation review.

`data/rounds/contract.json` registers consumed APIs, dataclass fields and defaults,
methods, constants and CLI parameter signatures. The fixed fixtures under
`tests/rounds/fixtures/contracts` assert all 39 registered entries and all eleven
complete help outputs against a source-built Python 3.12.14 installation. Help
canonicalization removes ANSI and normalizes whitespace only. Raw stdout,
stderr, exit statuses and hashes remain in the snapshots. Contract advancement
requires reviewed fixture changes; collecting observations does not update the
expected contract. Adapter imports, attributes, dynamic evaluator access and
literal CLI arguments are checked against this inventory. The supported adapter
syntax uses static imports, direct typed parameters (including quoted names),
constructors and registered call results. Evaluator argv lists/tuples must contain
literal strings; indirect/dynamic values and dynamic evaluator attribute access
are rejected and need a separately reviewed contract seam. Unmodeled evaluator
return access and compound evaluator parameter annotations fail closed. This
static guard is not a general Python analyzer or a candidate sandbox. Parameter,
local object, executable and argv bindings belong to their lexical function scope;
sibling functions may reuse names without changing one another's inferred types.
Annotations resolve through the enclosing imports, and nested closures retain
their enclosing bindings. Conflicting evaluator types within one scope,
global/nonlocal mutation and class-local evaluator bindings require a reviewed
seam and are rejected conservatively.

The ordered required coverage fields are:

```text
advertised, accepted, attempted, rejected_cleanly, skipped_by_capability,
crashed, timeout, selected, selection_rejected, invoked
```

Only the isolated contract test probes the evaluator's private comparison-state
constant. Product coverage validation uses this literal list and the public CLI.
An added, removed or reordered state, unregistered API or unknown flag fails.

Public E3 comparison intentionally treats identical failed fingerprints as equal,
a changed failure reason as a regression, and an added skip as a visible
improvement. Failed to skipped is also an E3 improvement; W10 must independently
veto loss of required coverage. Effect changes remain in the ledger and its row
seal but are outside the seven-field E3 fingerprint. The unanimous-attempt
shortcut does not prove the scheduled repeat count; the orchestrator must close
the independently frozen roster.

At this pin, one complete producer-shaped raw stream passes the actual public
reader, export, load, admission and comparison path. Two fresh streams for the
same case, even with different shard tags, collide on `(node_id, phase, attempt)`
and export raises before emitting ledger bytes. **EVID-STREAM-1 blocks release
N=2 support.** A reviewed public stream-context API and accepted new evaluator
pin must preserve original inner attempts and reversible stream context, then
pass raw export/admit/compare controls for pass/pass, pass/fail, fail/pass,
missing/duplicate attempts, overlap and incomplete-first streams. Renumbered raw
attempts and hand-built ledger rows cannot close this gate. N=1 contract tests
are diagnostics, not provider qualification or release acceptance.

Run the bounded source/bootstrap contract tests with:

```console
python3 -m pytest tests/rounds/test_contract.py tests/rounds/test_evaluator_build.py -q
```

The real integration fixture acquires and builds sealed public inputs. Set
`P11LAB_W01_OUTPUT` to preserve/revalidate an existing bootstrap directory between
runs. These checks start no provider and run no provider matrix.

The early candidate producer seam is separate from trusted evaluator bootstrap.
`p11lab.round_core.inputs.freeze_candidate_context` takes typed
`ProtectedSelection`, `LocalProducerEvent`, `VerifiedSource` and
`SealedToolInputs` values. It freezes canonical JSON with the selected source
revision, independently inspected Git tree and archive membership, archive hash,
control/evaluator/policy and per-side membership identities, provider parent,
builder image/config/layers, dependency/Python closure and attempt. The tools
factory reuses full bootstrap receipt verification. Local authority is labeled
`local-controller`; neither a candidate JSON flag nor local repository metadata
supplies authenticated GitHub run, attempt, job or artifact authority. Future CI
acquisition must supply its independently authenticated control-plane metadata.

`freeze_comparison_expectation` and the single `COMPARISON_ENVELOPE_V1` schema
freeze a protected controller selection and check its own closed consistency for
checker, image and proxy axes. Fixed controls, family/platform, exact provider
parent and selected source remain explicit, along with each source catalog,
selected/observed membership, exclusion reasons and their unions. A direct checker
or image cell may explicitly carry `artifacts.proxy: null`; the proxy axis requires
its selected proxy. JSON decoding bounds bytes and rejects duplicate keys and
nonfinite values; the schema rejects unknown fields, incorrect scalar types,
malformed identities and duplicate/noncanonical membership. Synthetic fixtures
exercise these contracts without claiming comparator execution. Actual original
header, sidecar, ledger and endpoint authentication belongs to the single M03
`validate_comparison_envelope` integration; this expectation constructor does not
perform that integration or evaluator comparison.

`p11lab.round_core.worker.produce_candidate(context, policy, output_dir)` is the
shared in-process Python wheel operation. Every attempt needs a fresh directory.
It rechecks inert archive bytes, Git tree, membership, Python closure, offline
wheels and exact lock roster before backend execution. Build requirements must
be explicitly present in the protected sealed requirement roster. New or dynamic
requirements never trigger an online resolver. Metadata inspection is inert;
build, pip installation and installed `.pth` startup remain in separate owned
Docker sandboxes. The installed closure is independently rehashed before startup
and mounted read-only. Wheel data relocation currently fails closed pending a
reviewed contract; a sealed Rust/compiler/vendor closure and proxy build driver
remain separate integration gates. This operation introduces no additional public
CLI command and does not alter ordinary application Action semantics.

The builder uses an exact local Linux amd64 image, UID/GID 65532, read-only root
and inputs, Docker's default private PID namespace (independently inspected),
private IPC, no network, no capabilities and no-new-privileges. CPU, memory, PIDs,
time and retained logs are bounded. Scratch uses limited tmpfs mounts; output
uses a separately owned tmpfs volume with hard byte and inode limits. A trusted
non-candidate sleeper keeps that volume mounted after candidate execution stops.
Only after independently observing the candidate stopped with PID zero does the
controller collect a bounded binary Docker-copy tar through owned process-tree
supervision. It validates the complete roster, sizes, paths, modes and regular
file types before extraction; links, devices, aliases and unexpected directories
fail. It hashes actual controller-read bytes, never a candidate-supplied RECORD
or hash claim. Only the exact labeled candidate, holder and volume are removed.
Timeout, cancellation, uncertain creation, failed cleanup and rejected output
remain explicit infrastructure evidence with bounded logs and raw copy data.

`p11lab.round_core.evidence.verify_candidate_product` requires a typed protected
context and controller stop witness. It binds observed product bytes to that
local context; it does not prove that a hostile backend compiled honestly or
qualify a provider. The bounded source tests run without Docker. The explicit
live authority fixture requires a verified sealed-tool directory and exact pinned
builder image; it does not silently skip and report qualification. The early
Python proof does not activate CI authentication, Rust/build.rs support,
EVID-STREAM-1, N=2 comparison or release/publication eligibility.

Source preprocessing accepts regular-file plain/gzip tar snapshots with explicit
limits before generic tar interpretation: 40 MiB compressed and total expanded
stream, 32 MiB file payload, 64 KiB per extended metadata record, 1 MiB aggregate
metadata, and bounded header count/extension depth. Ordinary Git PAX comments,
paths and timestamps remain supported. Sparse/unknown metadata and all PAX `size`
fields fail closed; fixed headers alone determine payload boundaries. One controller-owned immutable archive snapshot feeds
hash, membership and tree checks and source materialization; the final staged
file/directory roster, bytes and file modes are verified before TOML/backend work.

Installed site processing also checks the sealed CPython native `.pth` error
diagnostics: a caught startup exception fails the producer even when Python
returns zero and no optional startup report was requested. Truncated startup
capture is incomplete evidence and fails. Native return codes and bounded
stdout/stderr, including truncation flags, remain unchanged in the observation.

`p11lab.comparison.validate_comparison_envelope(envelope, endpoints)` is the shared
local comparison binding operation. It reuses the canonical expectation constructor
and schema above; packaged `data/ci/comparison.schema.json` is a generated exact
mirror with its source name, checked for equality on every call. It is a canonical
shape description, not a separate JSON Schema implementation.

The `endpoints` Python mapping has exactly four entries: `authority` is a
`LocalComparisonWitness`, `evaluator` is `SealedToolInputs`, and `baseline` and
`candidate` are canonical absolute `Path` values for stopped, controller-owned
endpoint directories. The witness contains a `FrozenComparisonExpectation` and
immutable observation bytes. Those bytes have `schema_version: 1`,
`scope: "local-controller"`, and `endpoints: {baseline, candidate}`. Each side has
`files`, a sorted list of exact `{path, size, sha256}` records, and `streams`,
exactly one `{path, attempt, shard_id, selected}` record. This bounded interface
supports N=1 only. Freeze the lane, source, controls, catalogs, selections,
exclusions, attempt and shard names independently before execution; seal measured
file bytes afterwards from the producer's stopped, independently observed output.
Observed survivors must never define the scheduled roster.

Each directory contains `artifacts.json`, `header.json`, `sidecar.json`,
`ledger.jsonl`, `coverage.json`, `catalog.json`, `selected.json`,
`obligations.json`, `raw-manifest.json`, `build-manifest.json`,
`installed-manifest.json`, `source.tar`, `checker.whl`, the declared raw JSONL
original, and `controls/<control-name>.json` for all five frozen controls.
`catalog.json` and `selected.json` wrap their respective exact lists under those
names. `raw-manifest.json` contains `streams` equal to the independently frozen
stream assignment. Obligations use the public `{catalog, profile: {cases}}`
format. Coverage uses the public `mechanism_coverage` object with all ten ordered
contract fields represented as `<state>_names` lists. The sidecar hashes bind
actual build manifest, installation manifest and opaque source archive bytes;
the checker artifact hashes additionally bind the actual wheel and installation
manifest. No archive is imported or executed. The control hashes bind actual
control files, and the ledger header binds the executor, tested derivative,
control revision, dataset, exact selected membership and measured raw original.

The producer must independently verify source revisions, actual provider and
derivative inspection identities, dependency closures, fresh-state lifecycle and
exact execution ownership before supplying this witness. `artifacts.json` is a
protected observation binding, not a candidate assertion that an image was run.
These typed objects express a trusted Python calling boundary; their constructors
do not authenticate their origin. Never deserialize candidate output into the
witness or use candidate booleans as authority. Local observations do not supply
GitHub repository/workflow/run/job authenticity, source rights, custody, baseline
review or publication authorization.

The guard snapshots bounded regular single-link files through directory
handles, rejects aliases, special files, changing reads, extra or missing files,
ambiguous JSON and invalid identity types before public evidence operations. It
revalidates the explicit evaluator's full sealed installation and separately
checks its source revision against the protected evaluator identity. The tested
executor revision remains the endpoint's checker revision; evaluator09a never
replaces executor9df or its support catalog.

On those snapshots, an isolated evaluator process uses only the registered public
reader, session tracker, exporter, loader, obligation compiler, shard seal and
admission APIs. It reproduces the supplied ledger from the complete raw original,
preserves all node and inner/outer attempt IDs, and checks public observed
membership and shards against the independent plan. A failed provider observation
may admit. The guard returns checked byte manifests and admission metadata with
`comparison: null` and `image_promotable: false`; it computes no semantic or
coverage verdict and supplies no handoff eligibility. Actual guard-to-admission
routing is covered by provider-free tests. The future image/round facade must
invoke this same operation before public semantic and coverage comparison, and
must keep compared bytes identical to these snapshots throughout the operation.
That facade, authenticated CI provenance, real artifact/lifecycle observations,
independent baseline review and fresh evaluation remain separate integration
gates. This helper does not implement an `image evaluate` command or image
promotion, and equal or self-compared fixtures cannot authorize either.

## Protected policy diagnostics

The installed `p11lab` command validates the same policy loader intended for
future round workflows. It requires no checker installation or provider process:

```console
p11lab round validate-policy --tier pr-smoke --output-json policy-proof.json
```

To inspect a policy resource tree from a reviewed P11Lab checkout, use the literal
public operation:

```console
p11lab round validate-policy --policy-root src/p11lab/data/rounds --tier pr-smoke --output-json policy-proof.json
```

The resource tree includes sibling `profiles/` and `ci/images.json`, and the
rounds directory includes the evaluator contract. Validation seals their exact
bytes into `policy_digest`, returns a separate selected-roster digest, and reports
all active and inactive lanes with reasons. Editing policy, profile, or image
catalog bytes changes the identity or fails validation. The enclosing immutable
P11Lab revision must be verified by the caller; JSON does not authenticate itself.
Image-catalog hashes bind discovery data, without granting image admission.

The initial active commission is Linux amd64 on `ubuntu-24.04`: `pr-smoke` selects
SoftHSM2 with the reviewed 23-node seed, `nightly` selects SoftHSM2/Kryoptic/NSS,
and `release` additionally selects TPM2 and OpenCryptoki. OpenCryptoki uses
`pkcs11-proxy-ng`; the other active providers use direct transport. PR/nightly
schedule one fresh outer provider attempt; release schedules two unanimous
attempts. Release execution remains blocked on EVID-STREAM-1 and the E5 handoff.
Validation never executes these attempts.

The Linux nightly/release selector excludes wycheproof, acvp, cctv, stress, fuzz,
and slow markers and retains security tests with destructive execution disabled.
The PR nodes are a seed requiring W05 candidate/lane collection revalidation,
with no inherited fixed source, wheel, or test-file hash binding. Missing or
renamed nodes must fail collection. Windows/macOS profiles retain their reviewed
selectors and non-destructive settings, but those lanes are explicitly inactive
and are not prerequisites for Linux activation. Linux BouncyHSM remains deferred.

Catalog visibility covers the full baseline/candidate testcase union; regression
enforcement covers the frozen selected tier. Every unselected/disabled obligation
needs a reason during collection, and missing selected obligations are fatal.
A PR smoke diagnostic does not imply full-suite or full-provider coverage.
Twenty-minute PR and ninety-minute other leg budgets are unmeasured targets.

All shipped policies remain `diagnostic`, and every diagnostic contains
`round_positive=false`. Unresolved identities and disabled inventories, absent
protected authority and qualifying receipts, unmeasured quotas/resources, and
later runtime/evidence checks are explicit gates. Even syntactically resolved
pins or claimed receipt JSON cannot activate `qualified` or `required`; this
operation has no external authenticated receipt-verification seam. Unknown tiers,
extra fields/options, selector/OS/image overrides, emulation, and roster shrinking
fail closed. A valid diagnostic is policy-source evidence only, not runtime,
provider, CI, publication, or release qualification.

## Preparing opaque round inputs

`p11lab round prepare --context context.json --policy-root policy --output-dir
input-proof --output-json input-proof.json` records a diagnostic input manifest.
A context identifies a tier, caller run and attempt, candidate, frozen target and
merge base, target interpreter/ABI/platform, artifact transport, dependency lock,
and data inventory. Relative fixture paths resolve beside the context file. The
included test fixture transport is local-only and is refused in CI; it does not
verify a GitHub caller or producer. A cache entry is checked against the selected
artifact digest before use. An existing output directory is not reused.

The GitHub transport reads the current run and attempt, validates the artifact
name and digest, and strips its Actions token before the approved storage redirect.
Metadata alone does not identify the uploading job or prove that source builds ran
inside the protected boundary. The separately protected caller profile and owner
proof supply that authority: the shipped set provides the profile premise (entry
#1, below), and enrolled profiles additionally verify a producer-job attestation
bundle uploaded by the producing job itself. Verification checks the certificate
identity, the round subject and job-naming predicate, and a signature timestamp
inside the authenticated producer-job window; the closed two-job roster admits
exactly the producer and context jobs. Token exclusivity — `id-token: write`
granted only to the producer job — is established by human review of the exact
workflow bytes pinned in the profile graph; the standard library has no YAML
parser, so this review-rooted premise is stated, not code-derived. A profile
whose trust root is still the unenrolled zeros sentinel skips owner proof and
establishes no uploading-job authority; the sentinel must be replaced by
enrollment before live use. Consumers pin the expected `owner_id` from their own
configuration, never by copying the profile, or the ownership loop is vacuous.
Configured live preparation reuses the sealed evaluator and checks selected wheel
requirements and target compatibility as inert metadata. That source-level check
is distinct from a guarded offline installation receipt. Provider delivery, actual
candidate installation, independent caller authority, and later execution remain
open gates; this command does not establish a positive round or release eligibility.

The context is a JSON object with `transport` (`github` or `fixture`), `tier`,
`repository`, `workflow_id`, `run_head_sha`, `producer_job`, and an `identity`
object containing `repository_id`, `run_id`, `attempt`, `candidate_sha`,
`target_sha`, and `merge_base_sha`. Revisions are lowercase 40-character commit
IDs; run, attempt, repository and workflow IDs are positive integers. The context
also supplies `dependency_lock_sha256`, `data_root`, `data_files`, `disabled_path`,
and `target`. Each data file entry has `path`, `size`, and `sha256`; entries are
sorted by relative path and describe the complete directory. The target object
contains `python_version`, `abis`, `platforms`, and the explicit PEP 508
`marker_environment`; it is selected by protected control, not inferred from the
evaluator interpreter. An optional `cache_file` names an artifact archive whose
digest must match the independently selected current-run artifact.
An optional `owner_id` names the expected caller-owner account id and must equal the profile value.

Fixture contexts also name `artifact_path` and `fixture_metadata_path`. GitHub
contexts instead name `control_sha` and require a read-only `GITHUB_TOKEN` for
caller-run Actions artifact metadata and downloads. Public source graph, PyPI
wheel readback and data reads are anonymous. Live dependency lock entries include
the exact PyPI wheel URL as well as path, size and digest; each selected wheel is
independently downloaded and compared with the dist bytes. A protected producer
profile fixes the context-artifact name and job, workflow graph and boundary
evidence, full policy-bundle digest, target and data sources, and verified runtime
tool identity. Live preparation rejects a policy bundle that differs from the
protected digest. The tool identity binds validated W01 inputs, code and installed
inventories independently of output-directory paths; the complete actual receipt,
including its location and host observations, is retained separately.

Shipped entry #1 (proposed at control `10017b1`; review re-pins to the exact
commit holding the final bytes) profiles the `mingulov/p11lab-round-caller` test
caller (repository id `1439580215`, workflow id `401625989` — the live-proven
pre-push diagnostic template id, producer.yml still 404, re-enrollment at G3a
staging) with producer job
`produce-framework-dist`, context job `upload-round-context`, and context artifact
`p11lab-round-context-{run_id}-{attempt}`. The graph pins the reviewed caller
workflow plus `README.md` as boundary evidence with explicit weak semantics
(caller-repo presence evidence only; upgraded when a producer recipe lands). The
runtime pins `debian:13-slim` (amd64 manifest `sha256:1e1a2217…`), Python
`3.12.14`, the sealed-evaluator tool identity, and a 96MiB output bound
(`max_output_bytes 100663296`, review-blessed: it quotas `/out` plus `/scratch`
plus per-file `RLIMIT_FSIZE` plus manifest readback per
`prebuilt.py:181,187,195,200`, and both production defaults are 96MiB per
`prebuilt.py:46` and `worker.py:297`). The pinned
target is the minimal valid-context shape (joint review with B-C1, which authors
contexts). Capture premise: the image identity was captured on a
containerd-image-store engine where
it equals the manifest digest; B-C1 live proof must re-verify on the actual
prepare host and re-pin on mismatch. Caller-side follow-ups owned outside this
slice: the operational caller must use exactly these job names and upload the
context artifact and the attestation envelope artifact
(`p11lab-round-attestation-{run_id}-{attempt}`); real data-source rows are still
TBD (`data_sources` ships empty, so live use additionally requires local
`data_root`), as are lock/corpus pins.

The live W01 output path permits absolute normalized paths excluding ASCII
whitespace,
control characters, DEL and backslash; non-ASCII printable characters and
punctuation are allowed, while spaces remain refused because generated
launcher scripts cannot execute through them. The
independently downloaded context must match the proposed identity and
input selection before downloading the dist. The shipped profile set holds entry
#1, so selection can now pass this boundary for the profiled caller; live runs
remain blocked on owner-proof enrollment (entry #1 ships the unenrolled zeros
trust root), data sources, and lock/corpus pins. Profiles and
source pins are reviewed P11Lab control, not fields accepted from a candidate's artifact.
