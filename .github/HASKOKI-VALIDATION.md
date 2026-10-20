# Manual Haskoki v0.5.0.0 evidence

This workflow is **not complete provider qualification**. It gathers evidence
from an unpatched, source-built release candidate without publishing source,
images, releases, caches, logs or private runtime state. Existing strict source,
package, Hackage, GHC closure and ABI gates remain unchanged. A build refusal is
not a runtime acceptance result. Known schema-readiness gaps remain ordinary
failing tests, never xfails or accepted exceptions.

## Triggers and cost

- A matching pull request runs only a bounded 10-minute static validation job.
  It installs the exact pinned no-deps requirements into a fresh venv and
  requires `pip check` before static tests. It does not build a provider or
  start Windows workflows.
- A deliberate `workflow_dispatch` runs one Ubuntu 24.04 job with a hard
  240-minute ceiling, a 220-minute build step and a 16-minute test step.
  Test execution itself has a 15-minute ceiling. Setup consumes the same job
  budget. There is no matrix, automatic retry or follow-on run.
- GitHub run attempts after the first are rejected before provider work. A new
  dispatch is a new capacity-consuming action requiring its own authorization.
- Permissions are `contents: read`, `packages: none`; checkout credentials are
  not persisted. No registry login, release operation or artifact upload exists.

GitHub's [workflow dispatch reference](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflow_dispatch)
says that after a workflow has run once it can be dispatched against a branch
or tag through the API or CLI. The PR-only static run provides initial
registration. Verify actual registration before dispatching; do not merge a
workflow to the default branch merely to enable execution.

## Preparation and evidence

P11Lab is built as a wheel and installed into an isolated environment outside
the checkout. Preflight verifies wheel provenance, the exact release source
commit and lock, Linux amd64 Docker/buildx and `docker build --metadata-file`
support, then conservatively requires two CPUs, 6 GiB available memory and
20 GiB free on both runner-temp and Docker storage. No installed toolchains are
removed to fit resources. Those minima are prerequisites, not proof the build
will fit. The test-only C helper must compile before a provider build starts.

The copied acceptance files are collected outside repository imports with
installed package resources. Their exact reviewed roster is 49 cases:
41 runtime/catalogue cases and 8 derivative-dependent cases. Full release
selection runs without fail-fast. The missing derivative inputs produce
explicit missing coverage and a nonzero result, even if all available cases
pass. The unpatched schema assertions may also fail independently.

Safe step summaries retain only validated stage classifications, exact hashes,
measured numeric gate/resource observations, test function names, hashed case
identities and numeric outcomes. Driver failures retain only fixed failure
categories and operation/checkpoint targets, plus bounded numeric subprocess
exit/timeout or HTTP status when actually available. Exception text, command
arguments, URLs and arbitrary exception type names are never retained in those
diagnostics. Raw assertions/output, source archives, token
stores, PINs, generated keys and TLS private keys remain private runner-local
state and are not uploaded or printed. Interrupted or missing reports cannot
be represented as passing evidence.

## Remaining derivative prerequisites

Complete direct consumer/OpenSC, installed checker and proxy host/container
lanes need reviewed installed acquisition/build operations that do not exist
in the current package. The packaged derivative Dockerfiles are context
contracts, not acquisition APIs. Missing inputs include the OpenSC package
closure, exact checker wheel/runtime-lock and Python Debian closure, pinned
proxy Rust/protoc/crate acquisition and verified daemon/CLI/shim identities.
Native client packaging supports already-verified components, not their build.
Do not substitute local development outputs, unsealed wheels or relaxed hashes.
A separate design and review must close these gaps before claiming all-lane
qualification or authorizing additional builds.
