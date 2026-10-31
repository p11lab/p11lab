# Image scheduling source API

`p11lab.image_ci` provides a deterministic source-level planning API. It does
not run builds or tests, authenticate declared inputs, admit evidence, determine
whether a prior result satisfies validation, or authorize distribution. Workflow
integration must resolve protected policy and verified content before calling it,
and separately perform all required validation and evidence checks.

`experiment_key(inputs)` returns a SHA-256 over a versioned canonical JSON
projection. The closed input object has these fields:

- `provider`: an immutable OCI digest or exact local engine image ID expressed as
  an ArtifactRef (`kind`, `reference`, `sha256`, `platform`), plus `build_key`
  and `provenance_sha256` identifying its known build provenance. A mutable tag
  or an unknown historical build key is not accepted. Do not derive a historical
  image's build key from today's recipe.
- `policy_sha256`: the exact protected input-policy content digest.
- `tools`: a nonempty map of fixed selected tool names to objects containing
  `source`, `build`, `dependencies` and `installed` SHA-256 content identities.
  Each required checker, proxy, consumer or evaluator must be represented by the
  protected policy; this function cannot establish that the selection is trusted.
- `content`: SHA-256 identities under exactly `data`, `profile`, `config`,
  `initialization`, `selection`, `obligations` and `limits`.
- `input_paths`: canonical repository-relative input paths mapped to their
  content SHA-256 snapshots. Their supplied hashes are declarations, not proof of
  the bytes. Include test-only inputs whose changes should trigger this plan.
- `roster`: a nonempty ordered array of `{leg, shard, repetition}` logical cells.
  Duplicate cells are rejected; roster order is part of the identity.

All digests are lowercase 64-character hexadecimal SHA-256 values. Physical
attempt IDs, timestamps, credentials, mutable aliases and unknown fields are not
part of this projection and must not be supplied. A physical execution still needs
its own fresh attempt identity; the existing `artifact_key('run', ...)` retains
that behavior.

`select_image_work(policy, changed_paths, previous, *, retry=())` takes a
protected selected map from environment IDs to `{channel, experiment}` objects,
where `experiment` has the shape above. It loads and validates each actual locked
catalogue entry and computes the provider key using
`artifact_key('runtime', runtime_inputs(spec))`. The return value is detached,
versioned JSON containing a source `snapshot` and finite `work` array. Each work
entry has an action (`rebuild` or `retest`), its selected legs, current provider
build key and policy digest. Its `frozen` object contains the complete ordered
logical experiment, fixed tool and content identities, input-path snapshots,
expected provider build key and platform. `frozen.sha256` is the SHA-256 of the
UTF-8 canonical JSON object formed by removing `sha256` from `frozen`, with sorted
keys, compact separators and unescaped Unicode. Retests retain the exact provider
and reproducible experiment key. For rebuilds, the frozen experiment's provider
is null: the new artifact and its experiment key do not yet exist. Resolve this
plan once and pass its exact frozen projection to all workers.

After a rebuild, `bind_rebuilt_experiment(frozen, provider)` accepts the retained
pending projection and the newly declared provider object. It checks the projection
digest, expected build key and platform, and the provider's immutable ArtifactRef
and provenance digest syntax; it returns detached `inputs` and `experiment_key`.
It does not authenticate the artifact or provenance, prove that the receipt is
correct, or admit any result. The operational layer must independently establish
those facts. The projection digest detects inconsistent bytes against the retained
digest; it does not authenticate a replacement projection and replacement digest.

Pass a previous source snapshot to compare projections; pass `None` for a first
selection. A changed runtime projection schedules rebuild and validation for its
selected legs. Changes to fixed test inputs schedule a retest of the exact frozen
provider. Unreferenced documentation, including provider README files, schedules no
image work when projections are unchanged. A locked notice is a build input. A
changed path outside selected locked resources, declared `input_paths`, and the
bounded documentation exceptions is rejected. Path filters are hints: the
validated resource and declared content projections determine identity. Ensure the
supplied snapshots represent the actual resolved bytes, including removed paths,
before calling the API.

The previous snapshot is a content comparison baseline, **not** a completed-result
record. It has no authority to establish validation success or suppress a required
retry. Supply selected environment names in `retry` to schedule another physical
attempt even if content is unchanged. The later operational integration must
independently decide required retries and admit fresh exact evidence for every
required leg; failed, missing, incomplete, ambiguous or unverified results do not
satisfy that gate. No cache restore bypasses existing input digest and roster
verification.

The runtime recipe projection now includes the selected lock bytes and complete
ordered closed asset roster under projection version 2, including dependency locks and future accepted
asset roles. Consequently old runtime keys and receipts remain historical; they
must not be silently relabeled as version 2 or used as fresh evidence for it.
Image usability, provider observations, completeness and distribution eligibility
remain separate decisions. Source tests of this API do not qualify any provider,
image, tool, platform, workflow or release.
