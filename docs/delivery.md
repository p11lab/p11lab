# Delivery: registry contract, pipeline, and consumers

## Current eligibility boundary

The source-first producer keeps the candidate on one runner through local
validation, reviewed source assembly, source publication, anonymous digest
readback, context attestation and source admission. After successful source admission,
the custody path separately reviews every required tool component, publishes
and verifies its source companion, and retains the exact inert bytes needed
for later source replay. The protected producer profile, provider inventory and
custody component policy are currently unconfigured; activation requires owner
review of the actual identities, source rights and environment protections.
The `trusted-producer` job's `timeout-minutes: 360`
(`.github/workflows/provider-delivery.yml:36`) covers this consolidated
single-producer pipeline (up from 240 on the pre-consolidation multi-job
pipeline).

The `source-delivery` GitHub environment must independently protect the
controller wheel URL and SHA256 and require an authorized reviewer distinct from
the triggering actor. The workflow checks the environment ID, exact reviewer
roster, review history and exact deployment branch policy against its installed
protected profile. It currently accepts only the first attempt of a run: GitHub's
review history does not identify an attempt, so a retry needs a new run. The
profile also pins the producer workflow/source, numeric repository and owner,
controller bytes, validation policy, reviewed inventory and attestation trust
root. A profile supplied beside a candidate is not authority. These are owner
activation requirements, not claims that the current environment is protected.
The current source-admission implementation selects only SoftHSM release and
refuses copied build-context asset roles outside its covered runtime-input
projection. Extending the selection requires reviewing those input bindings.

The source operations receive the prepared local validation tool policy through
`--validation-policy`. They recheck the sealed tools and evaluator, the fixed
plan and original evidence, and the independent public-crypto controls before
source publication and again during source admission. This local validation
evidence does not itself establish producer authority or source rights.
The checker evidence replay uses P11Lab's existing version-gated compatibility
adapter in the fixed checker image; that adapter uses private checker interfaces.
The separate sealed evaluator independently admits the original public ledger.
For the two fixed validation invocations, the bounded runner retains a digest of
the command and entrypoint it actually inspected, after checking for staged
credentials. Ordinary runs do not retain application arguments through this
option.

`admit-source` can establish source eligibility for that active producer only.
The separate legacy `admit` remains blocked; `expose` cannot create a new handoff
until binary custody, qualification, baseline and comparison are complete.
Current alpha pins are not upgraded by these operations. Caller transcripts are
still unverified evidence; `show-handoff` can display historical schema-v1
records without making them eligible.

## Qualification-only image custody

After source admission, the producer independently assesses the fixed evaluator
metadata, tool inputs, tool images and validation-derived images against the
protected component policy. It publishes and anonymously reads back the required
source companions before it saves or uploads any custody binary. The empty
installed component policy blocks this operation until an owner reviews the
complete content, notices, grants and corresponding source obligations. A
candidate's source admission does not approve its tools for distribution.

For a configured policy, the version 2 index lists the exact twelve component
names in sorted order, with each shard's SHA256 and byte length. Shard paths are
derived as `data/ci/delivery/custody-components/<name>.json`; each strict JSON
shard is limited to 16 MiB and their total to 32 MiB. The index is limited to
2 MiB. The protected source graph binds the index and every derived shard, and
the controller identity includes their installed bytes. The small version 1
policy remains supported; the installed empty policy does not grant eligibility.

The fixed consumer root can rely on its selected consumer image for executable
dependencies only under the protected exact product, image and library closure
contract. Local source collection uses a provisional assessment of that image;
custody eligibility and receiver replay independently require its verified
source publication and readback. The original tree inventory remains unchanged,
and external image dependencies do not become files distributed by the tree.

Protected graph verification fetches version 2 shards by the fixed repository,
full source revision and derived paths through the GitHub Contents API. Its
supervised batch has a 120-second deadline including name resolution and reads;
the supplied Actions read token is sent only to the exact API origin, with no
redirect or authentication fallback. Bounded diagnostic journals record
selectors, observed hashes and sizes, status, timing and worker cleanup without
recording tokens or payload bytes. These diagnostics are not authority.

The producer freezes eight logical roles and one or two numbered parts per role,
then uploads the parts for 14 days. Each artifact is limited to 1 GiB, each
member to 512 MiB, and all parts together to 8 GiB. The finalization operation
independently rechecks the active producer, the exact artifact IDs, digests and
bytes, and the source and evaluator evidence. The workflow attests that
finalization and uploads a separate two-file control artifact. A completed
producer and its protected environment are checked again when retrieving it.

For an enrolled producer, a receiver can prepare a fresh evaluator and replay
the retained custody, using the exact completed run, attempt, job and control
artifact IDs and the pinned attestation verifier and trusted root selected by
the protected profile:

```sh
p11lab custody prepare-evaluator --output-dir evaluator
p11lab custody acquire --environment softhsm2 --channel release \
  --run-id RUN_ID --attempt ATTEMPT --job-id JOB_ID --control-id CONTROL_ID \
  --gh /path/to/pinned/gh --trusted-root /path/to/trusted-root.jsonl \
  --evaluator-root evaluator --output-dir custody-replay
```

Set `GH_TOKEN` to a token with the required repository read access. The receiver
checks the attestation, exact closed artifact rosters and bytes, loads the exact
image without running it, reacquires required source companions and repeats the
source checks. The evaluator binding checks the original receipt and a strictly
verified fresh evaluator, including actual planner and admission operations and
file-backed executable, loader and library observations. Those native
observations are resident snapshots, not a complete history of mappings during
the process lifetime. Missing, changed or unavailable evidence blocks replay.
The retained image is for qualification only: custody and fresh source replay
are not provider qualification, promotion, runtime exposure or release.

### Image qualification records

Qualification proper starts where custody ends. The
`.github/workflows/image-qualification.yml` workflow retrieves one
completed custody (exact run, attempt, job and control IDs at a pinned
control commit), loads the exact image bytes, runs the N=1 fixed smoke
through the reusable direct lane plus the M03 consumer/OpenSSL control
(`p11lab.image_validation.validate_image`, reused, never forked), and
emits one `ImageQualificationV1` record per run:

```sh
p11lab custody qualify --payload-dir custody-replay \
  --smoke-result smoke-result.json --openssl-result openssl-result.json \
  --output-dir qualification-out
p11lab custody baseline-index --record run1.json --record run2.json \
  --record run3.json --output-dir baseline-out
```

Each record binds the custody selector and artifact digest, the image
engine/config/layer/build-key identities, the frozen smoke-v1 roster,
and the two leg outcomes. `comparison` is always null and `promotable`
is always false: a record observes, it never promotes. Exactly three
records with equal semantic projections form one
`ImageBaselineIndexV1`, represented by the earliest run with all three
originals retained; altered custody, a missing leg, roster change,
projection drift, or any other count is refused, and three observations
never concatenate into one record. The full three-run baseline ceremony
executes live in a later phase; this path only retrieves and observes,
with no registry publication or auto-promotion. The `acquire` job's
`timeout-minutes: 180` (`.github/workflows/image-qualification.yml:80`)
covers custody replay and the M03 staging bound.

## Enrolling a source producer

Enrollment is an owner-controlled operation and is not included in the current
unreviewed profile catalog. First review the immutable producer workflow and
controller source, the complete inventory template, source rights, package
selectors, notices and patches. The installed
`data/ci/delivery/softhsm2-release.inventory.json` has null candidate identities
and no approved reviews. Once an owner has supplied the real reviewed records,
`p11lab publish controller-identity` reports the controller, inventory-review
and fixed-validation-policy hashes. This command reports local identities only;
it does not approve them.

An enabled entry in the controller wheel's
`data/ci/delivery/source-authority-profiles.json` binds the fixed `softhsm2`
release, repository and owner numeric IDs, workflow ID/path, exact signer and
source revisions and source ref, job name, source-delivery environment ID,
sorted numeric user reviewer IDs, validation-policy, reviewed-inventory,
controller-package and trusted-root SHA256 values, and the protected source
graph. The graph includes the workflow and the controller files used by this
path. The controller-package digest excludes the profile catalog itself to avoid
a self-referential hash; the wheel is independently pinned after the profile is
reviewed. A producer source commit can therefore be frozen first, followed by a
separate controller wheel containing the owner-selected profile.

Configure the `source-delivery` environment with a single exact branch policy,
required user reviewers, and self-review prevention. Set its protected
`P11LAB_CONTROL_WHEEL_URL` and `P11LAB_CONTROL_WHEEL_SHA256` to the reviewed
release wheel. Before installing it, the workflow reads those two values from
the environment-specific GitHub API and compares them with the values received
by the job; this prevents repository or organization variable fallback from
substituting a paired wheel and profile. Supply the environment secret
`P11LAB_ENVIRONMENT_READER_TOKEN` as a narrowly scoped read-only GitHub App
installation token with Environments read access. GitHub documents that
permission for the environment-variable endpoint; the workflow's ordinary
`GITHUB_TOKEN` permission keys do not include an Environments permission.
See GitHub's [environment-variable API permissions](https://docs.github.com/en/rest/actions/variables#get-an-environment-variable)
and [workflow permission keys](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#permissions).
Missing token, inaccessible environment variables, missing review, ambiguous
identity or mismatched pins block activation. These environment and token
settings have not been created or verified by this repository change.

The producer uses the separately pinned GitHub CLI verifier and an
owner-selected trusted root to verify a GitHub artifact attestation over the
complete source context. It checks the verified certificate, numeric repository
and owner, signer workflow and revision, source revision and ref, runner,
run/attempt, subject digest and trusted timestamps. The context's source,
inventory, artifact, build and validation facts are independently recomputed;
the attestation predicate cannot grant rights. The source gate remains separate
from binary quarantine and image promotion.

## Complete source byte verification

Publish two separately identified source artifacts: the build-input seal contains
exactly `sealed-source.tar.gz` (`application/gzip`) and `sealed-source.json`
(`application/json`); the complete-content artifact contains exactly
`source-companion.tar.gz` (`application/gzip`), `source-companion.json`
(`application/json`) and `sbom.spdx.json` (`application/spdx+json`). Explicitly set
these layer media types when transporting them. Both use OCI image manifest
media type `application/vnd.oci.image.manifest.v1+json`; each layer title is its
exact filename. Extra, missing, duplicate, wrongly titled or incorrectly sized
layers and unsafe/non-regular pulled files are refused. No package cache, runtime
archive, wheel cache, private acquisition paths or workspace history belongs in
these source transports.

The protected producer supplies the expected receipt, current ArtifactRef,
manifest digest and repository; never derive the expected identity solely from
the pulled candidate. These supported operations work from the installed wheel:

```sh
p11lab publish verify-readback --sealed-receipt producer/sealed-source.json \
  --pulled-dir pulled-seal --source-manifest seal-manifest.json \
  --source-manifest-digest <seal-manifest-sha256> --registry ghcr.io/p11lab/<environment> \
  --transcript seal-pull.log --extract-dir verified-seal
p11lab publish verify-content-readback --content-receipt producer/source-companion.json \
  --artifact artifact.json --pulled-dir pulled-content --source-manifest content-manifest.json \
  --source-manifest-digest <content-manifest-sha256> --registry ghcr.io/p11lab/<environment> \
  --transcript content-pull.log --extract-dir verified-content
```

Use new extraction directories. Content verification rechecks the source archive,
exact inner file roster, receipt fields, ArtifactRef/platform, inventory hash and
identical outer/embedded SPDX, including the SPDX content relationships. It writes
`content-readback-proof.json` beside the extraction directory. A successful byte
check reports `transport_authentication: unverified` and
`publication_status: blocked`; it authenticates neither a GitHub job nor an
anonymous network run and supplies no rights conclusion. Omitting the seal
manifest options preserves archive-only local diagnostics, which cannot satisfy
source admission.

`admit` accepts the existing seal/build/evidence arguments plus
`--content-receipt`, `--content-manifest`, `--content-manifest-digest`,
`--content-readback-proof`, `--content-pulled-dir` and `--content-transcript`.
It reruns complete byte verification, compares the proof with those bytes and
requires byte equality with local `--evidence-dir` content assessed by
`assess_distribution`. The portable inventory must carry the exact producer
`build_key`; its receipt/inventory hashes bind that key. The repository must name
the selected environment. Missing content inputs block admission. Complete local
byte evidence can report `source_readback_status: verified` while admission
remains blocked pending authenticated source transport. Full image promotion is
separate and remains blocked.

All receipt families remain schema 1. Handoffs have a distinct schema 2; their
required `source.content_companion` has exactly these fields:

```yaml
reference: ghcr.io/p11lab/<environment>@sha256:<content-manifest>
manifest_sha256: <content-manifest-bytes>
file_sha256: <source-companion.tar.gz-bytes>
receipt_sha256: <source-companion.json-bytes>
spdx_sha256: <sbom.spdx.json-bytes>
readback_proof_sha256: <content-readback-proof.json-bytes>
```

The reference stays in the same environment repository. No handoff embeds its
own digest. `require_eligible_handoff` is the shared public acquisition gate and
the Action calls it before acquiring a binary. It requires schema 2, positive
admission and complete source/content readback; caller
`approved`/`anonymous_source_available`/`image_promotable` booleans cannot open it.

Authenticated source transport verifies through a handoff-pinned evidence
directory (`evidence-manifest.json` with `schema_version: 1`,
`attestation-context.json`, `bundle.json`, `trusted-root.jsonl`, plus an
optional supplementary `transport-journal.json`). Expected source/content
digests always derive from the handoff, never from the manifest inside the
dir; a transcript alone is refused. The sealed `gh` verifier (pinned by
`GH_PIN`, installed by `install-gh.sh` on Linux/amd64, executable digest
enforced before execution) checks the attestation offline against the
controller-installed profile; the trusted root is profile-pinned
digest-checked bytes. No `GH_TOKEN` is read and no live GitHub API reads
run on the acquisition path.

The supplied runtime root must byte-match the packaged
`trusted-root.jsonl` member; the supplied path (not the member) then runs
through the verifier, whose profile pin still checks those bytes. The
manifest is read only after regular-file validation through a 1MiB bound,
and its `schema_version` must be the integer 1 (boolean/float aliases are
refused). The roster is closed including hidden entries: any dotfile,
dot-directory, or dot-symlink is refused.

The attested payload follows the existing producer shape
(`payload.source.sealed` / `payload.source.content`) and binds the handoff
as follows (this mapping replaces Q-G2a-5's flat field list):

| Producer fact | Handoff field |
|---|---|
| `source.sealed.reference` | `source.reference` |
| `source.sealed.manifest_sha256` | `source.manifest_sha256` |
| `source.sealed.archive_sha256` | `source.file_sha256` |
| `source.content.reference` | `source.content_companion.reference` |
| `source.content.manifest_sha256` | `source.content_companion.manifest_sha256` |
| `source.content.file_sha256` | `source.content_companion.file_sha256` |
| `source.content.receipt_sha256` | `source.content_companion.receipt_sha256` |
| `source.content.spdx_sha256` | `source.content_companion.spdx_sha256` |

Every nested level must be an object; any missing, malformed, or unequal
mapped field refuses. `readback_proof_sha256` stays required by handoff
schema2 but is not authenticated here — an explicit coverage boundary,
never filled by `inventory_sha256` or any manifest declaration. The
promotion evidence below obtains and independently verifies the proof
bytes, binds their hash to the handoff field, and validates their
relationship to the authenticated source/content identities; caller
admission booleans cannot satisfy that obligation. Valid transport
evidence without promotion evidence reaches promotion refusal.

Refusals are typed: `authenticated source transport evidence unavailable;
acquisition blocked` (missing or malformed evidence), the reused verifier
texts (`verifier executable digest mismatch`, `protected trusted root
digest mismatch`, `verified certificate identity mismatch`, `verified
source context subject or predicate mismatch`, `verified timestamp outside
accepted window`, `ambiguous verified attestations`) else `authenticated
source transport verification failed: bundle digest mismatch` (tampered
transport), `attested source facts differ from the handoff digests;
acquisition blocked` (binding mismatch), and `full image
validation/promotion integration unavailable; acquisition blocked`
(transport passed; promotion still refused). The frozen v2-test pattern
(`unavailable|unverified|authentication|promotion`) holds in its narrowed
advisory form: the v2-test's reached refusal matches (verbatim refusal
texts take precedence over matching every text). B-G2a's gate signature and
evidence semantics are append-only. B-G2b adds evidence inputs and
promotion checks; it MUST NOT change the meaning, requiredness, or
refusal texts of any B-G2a parameter, and MUST NOT weaken any B-G2a RED
hook (§5). Windows verifier packaging is a recorded B-G2c follow-up.

### Verifier-text refusal mapping

Per the narrowed rule above — the v2-test's reached refusal matches —
each deterministic verifier text below surfaces verbatim; anything
else collapses to the fallback row.

| Verifier text | Surfaced refusal | Cause hint |
|---|---|---|
| `verifier executable digest mismatch` | verbatim | sealed verifier bytes differ from the pin |
| `protected trusted root digest mismatch` | verbatim | trusted-root bytes differ from the profile pin |
| `verified certificate identity mismatch` | verbatim | attestation certificate differs from the profile pins |
| `verified source context subject or predicate mismatch` | verbatim | verified statement binds other bytes or predicate |
| `verified timestamp outside accepted window` | verbatim | attestation time outside the profile age window |
| `ambiguous verified attestations` | verbatim | verifier returned zero or several attestations |
| `missing verified timestamps` | verbatim | verifier returned an empty timestamp list |
| `verification clock requires timezone` | verbatim | local verification clock lacks timezone |
| `invalid verified timestamp type` | verbatim | timestamp entry is not Tlog or TimestampAuthority |
| `malformed verified attestation` | verbatim | verified JSON lacks the attestation shape |
| `unsafe or oversized verifier input` | verbatim | verifier input not a single-link file or over its bound |
| `verifier input changed or exceeded limit` | verbatim | verifier input grew between size check and read |
| `Expecting value: line 1 column 1 (char 0)` | verbatim | truncated verifier output at offset 0; other offsets collapse |
| any other verifier error | `authenticated source transport verification failed: bundle digest mismatch` | unknown cause; still refused fail-closed |

### Promotion evidence

Trusted image promotion verifies through a second handoff-pinned
evidence directory (`promotion-manifest.json` with `schema_version: 1`,
`promotion-context.json`, `promotion-bundle.json`,
`promotion-trusted-root.jsonl`, `validation-result.json`,
`readback-proof.json`). Expected binary/source digests always derive
from the handoff, never from the manifest inside the dir. The sealed
`gh` verifier (same pin and trusted-root infrastructure as transport,
no new root) checks the producer-CI promotion attestation offline
against the controller-installed profile extended with a
`promotion_signer` entry; the promotion predicate and subject differ
from the transport leg so source evidence can never double as
promotion evidence. No `GH_TOKEN` is read and no live GitHub API reads
run on the promotion path. The roster is closed including hidden
entries: any dotfile or unknown member is refused.

The attested promotion record binds the handoff as follows:

| Promotion fact | Handoff field |
|---|---|
| `promotion.binary.reference` | `binary.reference` |
| `promotion.binary.manifest_sha256` | `binary.manifest_sha256` |
| `promotion.binary.engine_id` | `binary.engine_id` (image kinds) |
| `promotion.binary.file_sha256` | `binary.file_sha256` (bundle kind) |
| `promotion.source.manifest_sha256` | `source.manifest_sha256` |
| `promotion.source.file_sha256` | `source.file_sha256` |
| `promotion.validation_result_sha256` | `validation-result.json` member bytes |
| `promotion.readback_proof_sha256` | `source.content_companion.readback_proof_sha256` and `readback-proof.json` member bytes |

Every nested level must be an object; any missing, malformed, or
unequal mapped field refuses. The `validation-result.json` member must
be a producer-CI result (`role: image-validation-result`,
`scope: producer-ci`, `authority: producer-attested`,
`promotable: true`); local-only results never authorize promotion. The
`readback-proof.json` member closes the transport coverage boundary:
its bytes are obtained, independently verified against the handoff
registry and content-companion identities, and hash-bound to
`readback_proof_sha256`. Eligible handoffs with both valid evidence
kinds pass; all else is refused.

Refusals are typed: `full image validation/promotion integration
unavailable; acquisition blocked` (missing or malformed promotion
evidence, including a missing `promotion_signer` entry), the reused
verifier texts (same mapping table as transport) else `authenticated
promotion verification failed: bundle digest mismatch` (forged
promotion), `promotion evidence differs from the handoff digests;
acquisition blocked` (binding mismatch), and `promotion validation
policy mismatch; acquisition blocked` (producer-CI result policy). The
frozen v2-test pattern (`unavailable|unverified|authentication|promotion`)
holds in its narrowed advisory form: the v2-test's reached refusal
matches (verbatim refusal texts take precedence over matching every
text). Live residuals for the owning-repo follow-up (all fail-closed):
the shared verifier argv still carries only the source predicate filter,
the installed catalog still ships no profiles, and profile validation
still rejects a `promotion_signer` entry.

The shared integrity primitives `verify_acquired_image` and
`verify_acquired_bundle` grant no authority. The Action uses them to check the
actual acquired bytes/identities against a handoff. Images require an immutable
root manifest, an independent expected engine ID and config SHA256, and platform;
an index additionally requires its selected platform-manifest digest and bytes.
A single-platform manifest has no invented index digest. Docker engine identity
may differ from config identity. Native archives must be safe regular files with
the declared SHA256 and platform. Historical local mechanics remain available
only through the wrapper's explicit `--local-proof` diagnostic, which is refused
whenever CI markers are set and is never exposed by `action.yml`.


P11Lab publishes provider environments source-first through one
repository per catalogue environment, `ghcr.io/p11lab/<environment>`
(for example `ghcr.io/p11lab/softhsm2`). Digests are identities; tags
are discovery aliases only. Runtime images additionally carry
human-friendly aliases (upstream version plus `latest` on release;
`rolling` plus `rolling-<rev12>` on rolling); those aliases are mutable
conveniences and are never accepted as acquisition identity.
(2026-10-26: adopted per-provider repositories with version/`latest`
aliases, replacing the single-package layout that excluded them.)

## Registry contract

Each environment repository holds that environment's delivery artifacts.
Each artifact is acquired by immutable digest reference
(`ghcr.io/p11lab/<environment>@sha256:<hex>`); the
tag recorded beside it is an alias that must never be trusted as identity.
Acquisition entry points (`p11lab.publish.require_digest_reference`, the
reusable action, the consumer examples) refuse tag-form references.

References always bind the registry manifest digest (`repo@sha256:<manifest>`);
file digests are recorded alongside for byte verification after the pull.
Tag aliases embed the digest the consumer verifies next: the manifest
digest for images, the file digest for ORAS artifacts. Tag roles
(alias `<role>-<env>-<channel>[-<target>]-<digest12>`):

| Role | Content | Pushed by |
| --- | --- | --- |
| `src` | Sealed source: exact upstream archives, patches, lock, recipe inputs | `provider-*.yml`, `native-delivery.yml` after the seal step |
| `rt` | Runtime image (observed root manifest or index digest) | expose job, only when admission is `eligible` |
| `native` | Native bundle bytes (file digest) | expose job, only when admission is `eligible` |
| `sbom` | SPDX inventory (when reviewed evidence exists) | planned/future: no push path exists yet |
| `handoff` | Handoff manifest binding the digests above plus the verdict | finalize job, after binary readback |

Runtime images are additionally pushed under human-friendly aliases
from `p11lab.publish.runtime_aliases`, recorded in the handoff
`binary.aliases` beside the canonical digest alias: the verbatim
upstream release tag plus `latest` on the release channel (for example
`ghcr.io/p11lab/softhsm2:2.7.0`), `rolling-<lock-rev12>` plus `rolling`
on the rolling channel. The versioned alias is conditional: it appears
only when the channel lock pins exactly one git source with a usable tag
selector (release) or revision (rolling), and never when it would spell a
floating (`latest`/`rolling`) or canonical alias name; otherwise the
channel floats alone. The canonical alias keeps the `<env>` segment
so tags stay self-describing across repositories. Native bundles and
ORAS artifacts (`src`, `sbom`, `handoff`) keep canonical digest aliases
only: OCI tags share one namespace per repository, so version tags
there would collide with the image tags. `latest` tracks the
release-channel head only; no `stable` tag exists.

Source companions are intended for durable registry retention. The current
source-first workflow does not upload a binary transport or cache.

A newly created GHCR package may need an owner visibility setting before
anonymous pulls work; that setting is an explicit coordinator step before
the first publication to each of the 24 environment packages.

## Legacy pipeline sequence

This historical sequence does not describe the current provider workflow. It does not establish that
an alpha image satisfies the newer complete-content, schema-v2 handoff and
semantic qualification gates. The packaged policy below deliberately leaves
those images inactive while the required evidence is unresolved.

`p11lab publish` implements the gates; it decides only and never pushes or
publishes. `seal-sources` is network-free; `seal-native` acquires upstream
bytes and verifies them against the lock before sealing. The workflows run
this sequence:

1. **Seal** (`seal-sources` / `seal-native`): freeze the exact build-input
   bytes (retained upstream archives, patches, locks, recipe inputs) with
   a manifest. Reruns refuse to overwrite an existing seal directory.
2. **Build/test the exact binary** (`p11lab build`, consumer smoke plus
   the OpenSSL oracle, or native install/run in a pinned container).
3. **Publish the sealed source** to the registry (`src` alias).
4. **Anonymous source readback**: pull by digest with fresh empty
   credential state (empty ORAS auth file and home, no `packages`
   permission on the readback job) and verify every byte against the seal
   (`verify-readback`). The transcript is bound to the readback proof.
   Anonymity of that pull holds by platform plus human review: the job
   cannot present credentials it has no permission to hold, and reviewers
   inspect the bound transcript itself — no code assertion proves the
   absence of credentials.
5. **Admit** (`check-inputs`, then `admit`): require the readback to match
   the seal, the built inputs to match the seal, and actual-content
   evidence to assess. Any failure blocks with its reason.
6. **Expose the binary** (verdict-gated): only an `eligible` verdict runs
   the upload. The pushed binary is pulled back anonymously and compared
   byte for byte (engine Id plus layer DiffIDs for images, exact file
   bytes for bundles) before `expose` writes the handoff.
7. **Finalize**: publish the handoff manifest (`handoff` alias).

These conditions stop binary upload and cache export, fail closed with
the reason: a missing, private, expired, or altered source companion; an
input mismatch between the seal and the build; a newly discovered,
missing, or renamed build input. The `admit` and `expose` CLIs exit 3 on a
blocked verdict (distinct from usage error 2); the expose jobs additionally
carry an `if: eligible` gate so a blocked run can never upload.

## Reusable action

`action.yml` runs a caller application against a handoff:

- Inputs: `environment`, `channel`, `mode` (`direct`/`native`),
  `registry`, `handoff-digest`, `transport-evidence-digest`,
  `promotion-evidence-digest`, `evidence-registry`, `command`
  (application argv as a JSON array), `inputs` (newline-separated
  `NAME=VALUE` provider inputs), `state-dir`, `timeout`,
  `working-directory`. The canonical spec lives in
  `p11lab.publish.ACTION_INPUTS`; tests enforce parity with `action.yml`.
- The action installs p11lab from its own revision (self-pinning
  `uses: p11lab/p11lab@<sha>`), bootstraps the pinned ORAS release,
  fetches the handoff anonymously by digest, acquires the binary by
  digest, and runs `p11lab run` only. Pass credentials by file path
  (`*_FILE` inputs), never inline; only input names are logged.
- The child receives OS essentials plus only the declared provider
  inputs. The host environment and publisher credentials are never
  forwarded into providers.
- Historical schema-v1 and non-eligible schema-v2 handoffs are refused. The application exit code propagates
  unchanged, and receipts are collected even on failure (`exit-code`,
  `app-returncode`, `receipt-path`, `handoff-sha256` outputs).
- Each invocation gets a separate temporary directory, so multiple action
  steps in one job do not overwrite or reuse earlier receipts. Explicitly
  configured persistent state (such as `state-dir`) is still shared as requested.

Example (Linux, direct mode):

```yaml
- uses: p11lab/p11lab@<pinned-sha>
  id: provider
  with:
    environment: softhsm2
    channel: release
    handoff-digest: sha256:<handoff-digest>
    command: '["my-app", "--token-label", "P11Lab"]'
    inputs: |
      P11LAB_PIN_FILE=${{ github.workspace }}/pin
      P11LAB_SO_PIN_FILE=${{ github.workspace }}/so-pin

- uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4
  if: ${{ always() && steps.provider.outputs['receipt-path'] != '' }}
  with:
    name: provider-receipt
    path: ${{ steps.provider.outputs['receipt-path'] }}
    if-no-files-found: error
    retention-days: 1
```

Upload the exact `receipt-path`, not its parent directory, a temporary-root
glob, or `RUNNER_TEMP`: these broader paths may include token state,
credentials, provider configuration, and downloaded bundles. Give each
invocation's receipt artifact a distinct name. Failures before application
execution may have no receipt; collection never falls back to a prior run.
Missing, non-regular, malformed, or invocation-mismatched receipts leave
`receipt-path` and `app-returncode` empty without changing `exit-code`.
Receipt shape and invocation checks are not provider qualification or
proof of authenticity against caller-controlled host processes.

The `registry` input defaults to `ghcr.io/p11lab/<environment>`;
pass it explicitly only to use a mirror or local registry.

Direct mode needs Linux runners with Docker; native mode needs the
bundle's host floor instead (Debian 13 amd64, or the Windows floor for
Windows bundles).

### Gated acquisition evidence

The wrapper pulls each evidence package anonymously by digest-only
reference (`<evidence-registry>@sha256:<hex>`, never a tag) into a fresh
run-attempt subdirectory, provisions the sealed `gh` verifier per
attempt from the packaged `install-gh.sh` (the gate still enforces the
executable pin before running it), and passes fixed staging
subdirectories the verifier creates itself. Staging is never
caller-controlled. An empty `evidence-registry` resolves to `registry`.
Verifier provisioning uses the Linux/amd64 installer; other floors
block at provisioning.

Gated acquisition needs both evidence digests: empty digests map to
`None` so the gate refuses with its typed texts (absent transport
evidence refuses before any binary pull, with only the handoff fetch
performed); malformed digests or registries are input errors. Partial
evidence (transport only) reaches the promotion refusal. Handoff
registry/environment/channel and runtime-role bindings are checked
before any evidence pull. `--local-proof` still bypasses the gate and
fetches no evidence; it stays refused in CI and out of `action.yml`.

Callers use `examples/application-ci/action-gated.yml`, the gated
successor of `examples/application-ci/action.yml`: same copy-out idiom,
plus the two evidence digests. Both templates stay intentionally
incomplete until the ASK-9 eligible-handoff and evidence identities
exist; the legacy template is unchanged.

## Native acquisition without Docker

Native bundles are OCI artifacts fetched with the pinned ORAS CLI:

- ORAS 1.3.4, source revision
  `db9e29505c3059f2b8fde34ae8cae266c5c765e9` (observed Apache-2.0 in release tarball; distribution admission unreviewed).
  Linux amd64 tarball sha256
  `f27adb935022d94df8dc77719c322dda592c78a0d57a6f7dcdd8d900b248c454`;
  Windows amd64 zip sha256
  `ffdb6aa40267686b5d507da1f21a57fc502a9a7c86b90c54557d335644c99dbd`.
- Installers `src/p11lab/data/delivery/install-oras.sh` (Linux amd64)
  and `install-oras.ps1` (Windows amd64) verify size, digest, archive
  roster, and the `oras version` self-report. Pins must match
  `p11lab.publish.ORAS_PIN`; tests enforce parity.

Manual native acquisition, initialization, and use (Debian 13 amd64;
`ca-certificates` installed for registry TLS). p11lab's own source
readback requires the Debian controller CA bundle at exactly
`/etc/ssl/certs/ca-certificates.crt`; no fallback exists by design
(ambient-trust refusal), so off-Debian readback is fail-closed
unavailable:

```sh
# 1. Install ORAS (pins verified inside the script).
sh install-oras.sh --output-dir "$HOME/p11lab-oras"
export PATH="$HOME/p11lab-oras:$PATH"

# 2. Fetch the handoff by digest, anonymously.
printf '{"auths":{}}\n' > anon-auth.json
oras pull --registry-config anon-auth.json -o handoff \
  ghcr.io/p11lab/softhsm2@sha256:<handoff-digest>
python3 -m p11lab publish show-handoff --handoff handoff/handoff.json

# 3. Fetch the bundle by its manifest reference, anonymously, then verify
# the file bytes against the handoff file digest.
oras pull --registry-config anon-auth.json -o bundle \
  ghcr.io/p11lab/softhsm2@sha256:<bundle-manifest-digest>
sha256sum bundle/*.tar.gz  # must equal the handoff binary file digest

# 4. Install and run. No Docker is used or needed.
p11lab install softhsm2 --channel release --platform linux/amd64 \
  --artifact bundle/softhsm2-native.tar.gz --sha256 <bundle-file-digest> \
  --prefix "$HOME/p11lab-prefix"
p11lab run softhsm2 --channel release --mode native \
  --installed-prefix "$HOME/p11lab-prefix" \
  --input "P11LAB_PIN_FILE=$HOME/pin" --input "P11LAB_SO_PIN_FILE=$HOME/so-pin" \
  --output-dir ./first-run -- ./my-app
```

The same digest-first shape applies to container consumers with
`docker pull` under an empty `DOCKER_CONFIG`. `examples/external-consumer/`
automates both lanes end to end from a handoff bundle; the Windows consumer
job (`.github/workflows/clean-consumer-windows.yml`) is authored and
review-verified but pending CI on a Windows host.

## Catalogue binding

Public catalogue entries bind to manifests through the admission record:
environment, channel, runtime role, build key, `provider.json` digest,
and lock digests are recorded from the live installed catalogue at admit
time, and `expose` rechecks the tag alias against the pushed digest. The
handoff never embeds its own digest; its bytes are recorded externally
(`sha256sum.txt` beside it, the registry digest after its push).

Residual: handoffs are integrity-by-digest, not signed — authenticity
rests on registry TLS plus digest pinning, with no provenance
attestation. SLSA/cosign attestation is a follow-up; no key
infrastructure is in scope for this work.

After publication, the coordinator verifies anonymous readback with the
manifest digests from the handoff (`source.reference`, `binary.reference`):

```sh
printf '{"auths":{}}\n' > anon-auth.json
oras pull --registry-config anon-auth.json -o verify \
  ghcr.io/p11lab/softhsm2@sha256:<source-manifest-digest>
sha256sum verify/sealed-source.tar.gz  # must equal the sealed file digest
DOCKER_CONFIG="$PWD/empty-docker" docker pull ghcr.io/p11lab/softhsm2@sha256:<binary-manifest-digest>
```

## Pins

GitHub Actions (full commit SHAs; tests require the exact `uses: repo@sha`
form in every T13-owned workflow):

| Action | Tag | SHA |
| --- | --- | --- |
| actions/attest | v4.2.2 | `1e69f48acb82d1966a394da916b4c1698aa569d6` |
| actions/checkout | v4 | `11d5960a326750d5838078e36cf38b85af677262` |
| actions/setup-python | v5 | `a26af69be951a213d495a4c3e4e4022e16d87065` |
| actions/upload-artifact | v4 | `ea165f8d65b6e75b540449e92b4886f43607fa02` |
| actions/download-artifact | v4 | `d3f86a106a0bac45b974a628896c90dbdf5c8093` |
| actions/setup-dotnet | v4 | `67a3573c9a986a3f9c594539f4ab511d57bb3ce9` |
| ilammy/msvc-dev-cmd | v1 | `0b201ec74fa43914dc39ae48a89fd1d8cb592756` |

Tool images used by the pipeline and its proof (digests recorded at use;
stand-ins must be pinned at use):

| Image | Digest |
| --- | --- |
| debian:trixie-slim (native test floor) | `sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a` |

## Local proof versus publication

The sequence is proven against a local registry with explicit
local-proof acknowledgments wherever a blocked verdict is overridden for
mechanics proof. Nothing in `main` is published by this work: no pushes,
tags, releases, or cache exports. Publication additionally requires
reviewed source/license evidence per artifact (admission `eligible`),
the GHCR package visibility step, coordinator authorization for each
push, and a recorded wheel-to-source-revision mapping for the producer
wheel so consumers can fetch matching helper scripts.

## Packaged image-pin contract

[images.json](../src/p11lab/data/ci/images.json) is the shared packaged pin source;
[images.schema.json](../src/p11lab/data/ci/images.schema.json) defines its closed
ImagePinsV1 shape. New consumers use the installed package independently of the
working directory:

```python
from p11lab.ci_inputs import load_image_pin, load_image_pins, image_pins_sha256

pin = load_image_pin("softhsm2", "release", "linux/amd64")
reference = pin["repository"] + "@" + pin["root"]["digest"]
policy = load_image_pins()
revision = policy["policy_revision"]
exact_policy_sha256 = image_pins_sha256()
```

The resolver does no network access or OCI observation validation. It returns
inactive records too; callers must apply their required eligibility gates.
Round policy must freeze these same file bytes and externally calculated SHA256,
and record the human policy revision separately. There is no self-referential
policy hash. Existing workflow constants remain until their integration migration;
they must not become a second authority for new consumers.

Each unique `environment`/`channel`/`platform` record contains:

| Fields | Meaning and applicability |
| --- | --- |
| `repository`, `root.kind`, `root.media_type`, `root.digest` | Exact registry repository and observed immutable root; never a tag |
| `root.index_digest`, `root.index_absence_reason` | Index digest equals root digest for an index root; null with an explicit reason only for a positively identified manifest root |
| `platform_manifest_digest`, `config_digest`, `local_engine_id` | Required platform/config digests; separately observed engine ID may be null and is never inferred from config |
| `provenance.source_seal`, `content_companion`, `handoff` | Nullable immutable registry references and externally calculated manifest/file/readback hashes; content companion additionally binds receipt/SPDX; handoff records its schema version |
| `provenance.recipe_sha256`, `provider_build_key`, `patches` | Nullable publication-bound identities; patches are ordered SHA256/origin/license/review records, with null meaning unresolved and an empty list meaning known none |
| `semantics.modified`, `simulated`, `transport_limitations` | Explicit nullable behavior disclosures and limits; a declared patch list requires modified=true |
| `observations.metadata`, `pull`, `runtime`, `qualification` | Independent nullable dated, source-bound evidence pointers with limitations |
| `eligibility.distribution_eligible`, `acquisition_eligible`, `blockers` | Explicit independent policy declarations; missing required proofs cannot become eligible through metadata edits |

On 2026-10-28 all seven alpha roots were anonymously metadata-readable:
softhsm2, kryoptic, bouncyhsm, haskoki, freehsm, nss and opencryptoki. Earlier
documentation listed five; the additional nss/opencryptoki pins were already
present in validation workflow inputs. All seven are single-platform manifests,
not indexes. Only SoftHSM2 has a narrow dated local pull/runtime pointer; its
engine ID was separately observed and differs from config. The runtime report
is retained locally (`url=null`), not represented as a public qualification
receipt. Other six pull/runtime observations and all qualification pointers are
null. Old smoke reports do not upgrade these facts.

Published recipe/source/ordered-patch bindings and complete-content companions
have not been established by this metadata readback. Those fields remain null,
and all seven records are distribution/acquisition ineligible. The current lock
cannot supply fabricated provenance for older image bytes. Eligibility requires
reviewed actual contents, both required source readbacks and their exact binding;
new acquisition additionally requires a schema-v2 handoff and qualified
observations. A valid record is a declaration, never a substitute for validating
the actual OCI/config/build/run/admission bytes.

Native PKCS#11 libraries require a compatible architecture/libc and dependency
closure. Network sharing alone cannot make them remotely loadable; proxy use
requires a compatible client module and transport. Patch/simulation status for
these published bytes remains unresolved rather than inferred from current
catalogue recipes. Observability remains optional.
