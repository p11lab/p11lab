# Integration validation status

Availability update: **2026-10-28**. Anonymous fresh manifest and config readback
confirmed seven `linux/amd64` alpha pins: softhsm2, kryoptic, bouncyhsm, haskoki,
freehsm, nss and opencryptoki. Their roots are single-platform Docker schema-2
manifests, with separately recorded config digests; they have no image-index
digest. Exact pins, dated evidence pointers and unresolved provenance are in the
packaged [image policy](../src/p11lab/data/ci/images.json). The readback downloaded
no layers and executed no providers. It establishes metadata availability only.

A separate local Docker 29 observation on 2026-10-28 exercised the SoftHSM2 pin:
anonymous pull with cached layers, default metadata, explicit disposable
initialization, health, bundled tool execution, compatible persistent state and
independent state volumes. It used Linux amd64, glibc 2.41 and default root;
other platforms/users, cold-cache pulls and public CI remain unverified. The
observed engine ID is the root manifest digest, distinct from the config digest.
Only this pin has that narrow runtime evidence. No source/handoff readback or
actual-content rights admission was established; all seven policy records remain
distribution/acquisition ineligible. This adds no provider-wide qualification,
certification, release, or cache-export claim.

The sections below are the **historical 2026-10-20 integration snapshot**.
Its baseline, PR states, counts and runtime gaps are facts as of that date,
not refreshed current status. Historical baseline:
[`main` at 4507bc85](https://github.com/mingulov/p11lab/commit/4507bc855919dcbbace4ddd719da907376d1b30b).
The catalogue contains 24 locked provider candidates. At that date integration work
focuses on SoftHSM2 and Haskoki, not catalogue expansion.

This is a contributor evidence snapshot and roadmap, not provider certification.
Seven scoped changes are now merged into `main`. Only #5 and #7 remain open;
neither is approved for merge. Source/package tests do not qualify provider
runtime behavior or establish eligibility for distribution.

## What the evidence establishes

- **Source/package checks:** orchestration, installed-package and packaged-adapter
  contracts. Adapter fixtures substitute native tools where stated; they do not
  prove the provider's cryptographic or database behavior.
- **Runtime observations:** require the exact built provider, real tools and
  transports, expected lane inputs and complete run receipts. A missing input or
  skipped test is missing evidence, not a pass.
- **Distribution admission:** separately requires reviewed redistribution rights,
  complete source obligations, evidence of actual artifact contents and immutable
  public source readback bound to the binary. Tests cannot grant those rights.

## Merged changes and original review evidence

The seven PRs in this section are merged. Their linked revisions below identify
the original patch-level independent reviews, before rebasing onto cumulative
`main`; they are not the rebased commit IDs. Those reviews retain their commands,
red/green regressions and limitations. Later cumulative evidence is reported
separately below. Scoped independent review is not a formal GitHub `APPROVE`
review: none is recorded for #1–#9, all authored by `mingulov`.

- [#1: Haskoki lifecycle failures](https://github.com/mingulov/p11lab/pull/1)
  ([1cd5e3a4](https://github.com/mingulov/p11lab/commit/1cd5e3a4e0d49b4d7ca7818787204ee810752e0f)):
  preserve native failures and harden signal, identity, state-inventory and owned
  cleanup boundaries. Actual adapter tests run under dash and bash.
- [#2: Proxy shutdown receipt expectation](https://github.com/mingulov/p11lab/pull/2)
  ([9011658f](https://github.com/mingulov/p11lab/commit/9011658fa2ace20dee70be6d0ef1896edbe9eaa9)):
  correct a stale assertion while retaining strict daemon-stop-before-post-health
  ordering. Production lifecycle behavior is unchanged.
- [#3: Action isolation and receipt safety](https://github.com/mingulov/p11lab/pull/3)
  ([bdbc43ae](https://github.com/mingulov/p11lab/commit/bdbc43ae810b7f97764dd693dc726b2120e22180)):
  isolate repeated invocations and advertise only safe, complete receipts matching
  the invocation, artifact and CLI status. This is not authenticity proof against
  caller-controlled host processes; Windows behavior remains simulated.
- [#4: Bounded Linux source/package CI](https://github.com/mingulov/p11lab/pull/4)
  ([569f05d3](https://github.com/mingulov/p11lab/commit/569f05d38b053771d20f19166f551b71e8e30344)),
  originally stacked on #2: one read-only, 10-minute job with pinned Python
  dependencies and checker source. The
  [hosted run](https://github.com/mingulov/p11lab/actions/runs/39454787936)
  recorded **1001 passed, 1000 skipped in 58.06 seconds**. It built no provider.
- [#6: SoftHSM2 initialization outcomes](https://github.com/mingulov/p11lab/pull/6)
  ([c1fbe90d](https://github.com/mingulov/p11lab/commit/c1fbe90df29d4a68f582b7c84e2f854a4bac47d4)):
  preserve native/signal failures and cleanup ownership in container and native
  adapters. Identity/marker bytes are addressed separately by #8.
- [#8: SoftHSM2 identity and marker bytes](https://github.com/mingulov/p11lab/pull/8)
  ([e3b6dcc2](https://github.com/mingulov/p11lab/commit/e3b6dcc252468a9d6f533038b03a763b5a37fb2f)),
  originally stacked on #6: enforce existing byte-exact identity and completion
  marker contracts in both adapters. Its full local run recorded **2016 passed,
  1000 skipped, 3 known failures**; independent review repeated all **1028 adapter
  cases** plus 64 boundary probes. These tests substitute native tools; runtime
  remains unqualified.
- [#9: SoftHSM2 native traversal status](https://github.com/mingulov/p11lab/pull/9)
  ([1d8318fe](https://github.com/mingulov/p11lab/commit/1d8318fec5730b02c79316fe52dd3d5fb600d585)),
  originally stacked on #8: check failures at five native `find` guards using the
  existing helper, preserving query predicates and adapter status 1 with
  `cannot enumerate`. Its full local run recorded **2188 passed, 1000 skipped,
  3 known failures**; all **1200 adapter cases** passed, including an independent
  archive rerun. This is adapter evidence, not a real-provider runtime result.

The changes landed by rebase in order #2, #4, #1, #3, #6, #8, #9, preserving
#2 before #4 and #6 before #8 before #9. #1 and #3 were independent proposals
against the original baseline. The original local suites for #1, #3, #6, #8 and
#9 had three failures: the stale proxy expectation later fixed by #2 and two
sandbox AF_UNIX restrictions. These historical results are not the final
combined-tree result.

## Cumulative source/package verification

Fresh hosted cumulative checks passed before each landing from #4 onward.
The [final pre-merge hosted run](https://github.com/mingulov/p11lab/actions/runs/39484924716)
recorded **2507 passed, 1000 skipped, 0 failed**. The tested rebased #9 tree is
byte-identical to `main` at that snapshot and the locally tested cumulative tree:
`a47bab8406393a4117fc744a02daed3f5fe43748`. This is verified pre-merge evidence
for that exact final tree, not a claim of a separate post-merge workflow run.

The local unfiltered cumulative suite recorded **2505 passed, 1000 skipped,
2 failed in 190.47 seconds**. Both failures were the known sandbox AF_UNIX
restrictions in `test_assert_owned_socket_happy_path` and
`test_assert_owned_socket_refuses_foreign_uid`; both passed in the final hosted
run. No failures were suppressed. Existing opt-in integration skips remain
intact and are missing runtime evidence, not passes. No provider build, real
Haskoki/SoftHSM runtime qualification, image, release or cache publication is
established by these checks.

## Open proposals

- [#5: Manual Haskoki release validation](https://github.com/mingulov/p11lab/pull/5)
  ([fca1b148](https://github.com/mingulov/p11lab/commit/fca1b148f074bc0f3fd527bc02fe7920f33fa4cd)),
  stacked on the [release candidate at 4f753f3f](https://github.com/mingulov/p11lab/commit/4f753f3f0a54ca8ae1131b3d0657494022b2c086):
  a no-publication pipeline with a separate manual runtime job. The
  [corrected hosted static run](https://github.com/mingulov/p11lab/actions/runs/39463132399)
  recorded **203 passed in 3.42 seconds** on its PR merge; runtime was skipped.
- [#7: Integration validation status](https://github.com/mingulov/p11lab/pull/7):
  this documentation-only evidence snapshot, independent of the code proposals.

#5 still targets its release-candidate branch, which has no separate PR; that
candidate and its static result are not part of the cumulative tree above.
#7 targets `main` and changes documentation only. Neither open PR has been merged.

## Haskoki runtime evidence still pending

The v0.5.0.0 candidate uses unpatched upstream
`091a2223e6dc559af72913c7f5a061ca22af34dc`. Its exact 24-Haskell-library,
GLIBC_2.38 and two-Hackage recipe gates remain unchanged and unmeasured for the
candidate build. Source inspection and pipeline preparation do not verify that
runtime closure.

No manual Haskoki runtime attempt has started as of this snapshot. Both recorded
Haskoki runs were `pull_request` static checks, with runtime skipped, including
the [initial failed static run](https://github.com/mingulov/p11lab/actions/runs/39461303417)
and the corrected run above. Workflow `390791808` is registered, but its file
is absent from default `main` at the baseline above.
[GitHub's dispatch documentation](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflow_dispatch)
states that `workflow_dispatch` requires the file on the default branch, while
also describing branch/tag dispatch after a workflow has run. The previously
suggested `gh workflow run` command has not been verified successful;
registration and static runs do not establish a working runtime launch path.
A label-triggered alternative is only a proposal awaiting explicit approval,
not implemented.

The approved one-run budget remains unused: the frozen payload is
[`fca1b148`](https://github.com/mingulov/p11lab/commit/fca1b148f074bc0f3fd527bc02fe7920f33fa4cd),
with a hard 240-minute ceiling, no matrix, no publication and no automatic
rerun. Resolve the launch path without changing those limits. Its 49 selected
acceptance cases comprise 39 runtime cases, two static cases and eight
derivative-dependent cases whose inputs are missing. Missing derivative evidence
must produce an incomplete, nonzero outcome. The schema-readiness gap is covered
by ordinary acceptance assertions; any observed failure must not be xfailed or
waived, and preparation is not qualification.

## Remaining work

The next focus is reusable tool-input builders and real end-to-end workflow
evidence, rather than additional shell-only hardening.

1. Establish scoped runtime evidence for pinned Haskoki and SoftHSM2 builds:
   fresh/repeated initialization, health, native errors, direct consumers,
   checker, proxy and failure isolation. Keep provider findings, infrastructure
   failures and evidence completeness separate.
2. Implement the accepted consumer/OpenSC/C-smoke resolve/build architecture.
   The acquisition-only implementation was reconciled unchanged onto current
   `main` and independently re-reviewed: **193 focused tests passed**. The
   acquisition implementation is not merged.
   One real installed-wheel acquisition completed: **100 pinned network files
   (398,198,218 bytes)** plus **8 installed resources (190,630 bytes)**, exit
   status 0 in 950.7246 seconds, with no partial files. Separate installed-API
   reverification passed. This is acquisition evidence only: no extraction,
   acquired-package installation, payload execution, Docker build or publication
   occurred. ABI, compiler and cryptographic behavior, and license admission,
   remain unverified. No builder exists yet; builder execution, checker/Python
   and proxy/native-client derivatives remain later work. The legacy consumer
   recipe still installs packages online; it is not the new public builder API.
3. Track exhaustive traversal, descendant-type, state-root and foreground-child
   cancellation concerns separately. #9 checks existing query failures; it does
   not settle those policies or establish a fixed layout for opaque provider
   state.
4. Review source redistribution eligibility **before upload**, complete companion
   identity and actual-content admission. Role-separated repository naming is an
   accepted design direction; detailed migration is not implemented. Source
   rights, publication, schema/handoff details and private-information disclosure
   remain separate decisions, not permissions granted by that direction.
5. Maintain the provider/version and platform gap survey as research. Discovery
   alone does not add providers, change locks or expand the supported matrix.

The existing [delivery workflows](delivery.md) contain source and binary
publication steps and are not test-only entry points. At this baseline, their
admission calls omit actual-content evidence, so binary admission stays blocked.
Archive sealing alone does not establish source redistribution eligibility.
Preserve fail-closed gates while reviewing that design; do not use delivery as a
runtime-validation shortcut. See [source and licensing evidence](licensing.md)
for the separate obligations.
