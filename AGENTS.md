# P11Lab agent guide

## Purpose and current stage

P11Lab helps developers exercise PKCS#11 applications against reproducible,
reusable provider environments. It ships a catalogue of 24 locked provider
candidates (container runtimes plus native bundles) with pinned sources,
lifecycle adapters, and direct/proxy/checker/consumer lanes driven by the
`p11lab` command. The installed checker is one consumer, alongside arbitrary
applications.

Public reuse includes another developer's GitHub repository running its own
application tests and optionally checker profiles against these environments.
Keep the provider catalogue extensible through recipes and metadata with shared
validation and orchestration. Public CI integrations must use the same supported
operations as local users and work without development-workspace mounts.

The catalogue, lanes, demos, and delivery pipeline are implemented and under
frozen-cohort audit; five provider runtimes are published as alpha images
under per-provider `ghcr.io/p11lab/<environment>` repositories (digests are
identities, tags are aliases). No releases or cache exports exist yet.
`prd.md` remains an initial draft, not an
approved implementation specification. Current user decisions and verified
component behavior take precedence over assumptions in that draft.

Use `pkcs11-proxy-ng` as the preferred remote integration. `p11-kit` is an optional
demonstration where feasible. The requested observability project is
<https://github.com/mingulov/p11scope>, not the unrelated OpenCryptoki command
with the same name. Keep observability optional for ordinary image consumers.

## Repository boundaries

- This repository owns P11Lab provider packaging, integration examples, public
  image contracts, and eventual lab orchestration.
- `pkcs11-check-ws` and `pkcs11-proxy-ng-ws` are development references.
  Locate their current checkouts and read applicable agent guides before working
  there. Do not make them
  required paths, build contexts, or runtime mounts for a public P11Lab artifact.
- Their nested `pkcs11-check` and `pkcs11-proxy-ng` repositories own the checker
  and proxy implementations. Propose component changes in the owning repository;
  do not fork their behavior into P11Lab without a stated reason.
- Migrate selected recipes, initialization helpers, and patches with provenance
  and licensing review. Do not copy whole workspace histories, private plans,
  reports, credentials, or unrelated files.
- Inspect Git status and preserve unrelated edits, untracked files, and stashes.
  Do not stage an existing user draft merely because it is untracked.

## Local documents and public documentation

Store development plans, Superpowers artifacts, design drafts, reviews, research,
handoffs, scratch work, and generated investigation output under `.local/`.
Suggested locations are `.local/docs/specs/`, `.local/docs/plans/`,
`.local/docs/reviews/`, and `.local/artifacts/`.

`.local/` is intentionally gitignored. Do not force-add or upload its contents.
This location overrides skill defaults such as `docs/superpowers/`. A skill's
instruction to commit a plan does not authorize committing these local documents.

Public usage, integration, and contributor documentation belongs in `docs/` or
the relevant component directory when it is ready for publication. Do not make
public documentation, builds, or CI depend on `.local/` or link to its files.
Keep public documentation generic and free of machine-specific private paths.

## Licensing and publication

P11Lab's original material is Apache-2.0 unless explicitly stated otherwise.
Providers, dependencies, datasets, copied code, and upstream-derived patches
retain their applicable licenses; the root license does not relicense them.

- Record the source, revision, license evidence, required notices, and any source
  distribution obligations for every published component and provider variant.
- Review patch licensing against the upstream project. Do not blanket-relicense
  existing patches or assume a P11Lab patch supplies missing upstream rights.
- An image needs review of its actual contents, including base/runtime packages,
  linked libraries, utilities, and optional integrations. Provider licensing alone
  is insufficient. Keep checker and dataset eligibility separate from runtime
  image eligibility.
- Preserve existing local-only/no-publication restrictions when migrating
  recipes. Missing or ambiguous grants and unreviewed variants are not eligible
  for public distribution by default.
- Preserve exact sources, patches, build instructions, licenses, and notices as
  required for each distributed artifact. An SBOM supplements those obligations.
- Public image pushes, cache exports, releases, tags, repository pushes, and
  external messages require authorization in the current task or session.

## Provider image and integration contracts

- Keep build tools, checker dependencies, test datasets, and tracing requirements
  out of the basic provider runtime unless the provider itself requires them.
  Measure image size; do not assume a frozen Python executable is smaller.
- Document the module path, architecture/libc, runtime dependencies,
  configuration, slot/token selection, initialization, readiness, writable state,
  permissions, shutdown, and reset behavior.
- Support execution by arbitrary applications. A shared Docker network does not
  make a native PKCS#11 library remotely loadable. Remote consumers require a
  compatible client module and transport; direct consumers require a compatible
  local module and its dependency closure.
- Initialize disposable test state at runtime. Do not silently reset persistent
  tokens. Keep credentials out of published logs and metadata.
- Use independent provider/token state for independent test shards and clients.
  Respect the selected proxy version's documented isolation limits.
- P11Lab patches are supported deliverables. Record the upstream revision,
  ordered patch hashes, patch provenance/license, and changed behavior. Distinguish
  provisioning extensions from changes to PKCS#11 semantics or simulation.
  A declared patch that fails to apply must fail the build.
- Preserve provider behavior and native errors. Do not hide failures, normalize
  return values, or add silent retries to make test reports look better.

## Testing, evidence, and reproducibility

- Use `pkcs11-check` for test selection, execution, and supported shard/merge
  semantics. Keep P11Lab focused on environment orchestration and presentation.
- `fetch-data` downloads test datasets. Provider capability discovery is a
  separate operation. Verify actual public commands before documenting them.
- Pin provider, patch, recipe, base-image, package, checker, proxy, and dataset
  inputs. Record artifact digests and actual resolved inputs. Mutable tags and
  branch names are discovery aliases, not sufficient run identities.
- Separate image rebuild decisions from test scheduling. Checker, proxy,
  dataset, profile, and configuration changes can require retesting an unchanged
  provider image. Failed attempts remain retryable.
- Freeze selected test/shard manifests. Validate the complete expected shard
  roster, reject overlap, and retain explicit attempt identities when retrying.
- Report image usability, provider findings, infrastructure errors, and evidence
  completeness separately. Missing evidence is not a pass; provider failures can
  be valid completed observations. A passing smoke run is not provider-wide
  qualification or certification.
- Keep raw logs and traces bounded and separate from durable manifests and any
  required source/license artifacts. Public results must identify patched or
  simulated variants and observation limitations.
- Run checks appropriate to the change and report what was actually verified.
  Documentation-only changes normally need diff, link, and ignore checks, not
  expensive provider builds. Do not run full matrices without a task reason.

## Working practice

Progress within the authorized scope, ask focused questions only where an answer
changes the design or required permissions, and make concrete proposals before
requesting approval. Do not treat every routine implementation choice as a new
permission boundary. Keep commits scoped when commits are authorized; never
merge, rewrite history, delete unrelated worktrees, or publish as an incidental
part of a review.
