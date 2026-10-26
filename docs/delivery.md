# Delivery: registry contract, pipeline, and consumers

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
| `rt` | Runtime image (registry index digest) | expose job, only when admission is `eligible` |
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

Source companions are retained durably in the registry, never as
short-lived CI artifacts. CI artifacts carry job transport only
(`retention-days: 1`) and must never be mistaken for publication.

A newly created GHCR package may need an owner visibility setting before
anonymous pulls work; that setting is an explicit coordinator step before
the first publication to each of the 24 environment packages.

## Pipeline sequence

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
  `registry`, `handoff-digest`, `command` (application argv as a JSON
  array), `inputs` (newline-separated `NAME=VALUE` provider inputs),
  `state-dir`, `timeout`, `working-directory`. The canonical spec lives in
  `p11lab.publish.ACTION_INPUTS`; tests enforce parity with `action.yml`.
- The action installs p11lab from its own revision (self-pinning
  `uses: p11lab/p11lab@<sha>`), bootstraps the pinned ORAS release,
  fetches the handoff anonymously by digest, acquires the binary by
  digest, and runs `p11lab run` only. Pass credentials by file path
  (`*_FILE` inputs), never inline; only input names are logged.
- The child receives OS essentials plus only the declared provider
  inputs. The host environment and publisher credentials are never
  forwarded into providers.
- Non-eligible handoffs are refused. The application exit code propagates
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

## Native acquisition without Docker

Native bundles are OCI artifacts fetched with the pinned ORAS CLI:

- ORAS 1.3.4, source revision
  `db9e29505c3059f2b8fde34ae8cae266c5c765e9` (Apache-2.0).
  Linux amd64 tarball sha256
  `f27adb935022d94df8dc77719c322dda592c78a0d57a6f7dcdd8d900b248c454`;
  Windows amd64 zip sha256
  `ffdb6aa40267686b5d507da1f21a57fc502a9a7c86b90c54557d335644c99dbd`.
- Installers `src/p11lab/data/delivery/install-oras.sh` (Linux amd64)
  and `install-oras.ps1` (Windows amd64) verify size, digest, archive
  roster, and the `oras version` self-report. Pins must match
  `p11lab.publish.ORAS_PIN`; tests enforce parity.

Manual native acquisition, initialization, and use (Debian 13 amd64;
`ca-certificates` installed for registry TLS):

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
