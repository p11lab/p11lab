# Remote SoftHSM over pinned mTLS proxy

P11Lab runs external applications and the installed checker against SoftHSM
through `pkcs11-proxy-ng` over mutually authenticated TLS. The daemon loads
the provider locally in its own container; the consumer loads only a
compatible client shim. A shared Docker network never makes the provider
module remotely loadable. This path needs Linux amd64 throughout; native
Windows proxy and cross-OS topologies are unqualified follow-ups.

## Pinned components

The daemon, administration CLI and shim are built from public source
`a348a5f59b535b1ca309ea9f0a722e3bec692f72` (0.2.0) with the frozen
`Cargo.lock`, `--locked --offline`, Rust 1.98.1 and protoc 36.1. All three
are dynamically linked against glibc with a measured GLIBC 2.34 floor plus
`libgcc_s`, and need no OpenSSL at runtime. They load on Debian 13
(glibc 2.41) and newer glibc hosts; musl is a separate unbuilt target.

The provider-plus-daemon image derives from the exact accepted runtime and
adds only the daemon, CLI, lifecycle entrypoint and pinned-source notices.
It reports its component identities through `proxy-build`. The native-client
bundle carries the shim and CLI with the same recorded proxy identities.
A proxy component change invalidates both identities: a run refuses a daemon
derivative or client bundle that does not match the pinned source, lock and
CLI bytes. Distribution admission is separate for every artifact.

Runs select one expected proxy-build identity before anything else: the
pinned default record (the live-observed producer build: source, lock,
vendored closure, toolchain, target, daemon/CLI/shim bytes, ABI, daemon
config, entrypoint, hooks, build context, caller, and provider parent
naming) or an explicit `--proxy-build-manifest` record. The daemon claim,
recorded client identity, launch-byte rehashes, and observed client ABI must
all equal the selection exactly; any mismatch refuses the run before the
init container, and launch bytes are re-verified immediately before the
application starts. The receipt records the selection (`expected_proxy_identity`,
or the `{"selected": "fixed-default"}` marker on the default path) plus the
post-install and pre-launch rehash digests.

The daemon image must also descend from the selected unchanged provider
image: the run verifies that the daemon's observed DiffIDs start with the
protected six-layer roster for softhsm2/release on linux/amd64 and binds
the distribution manifest digest (`sha256:69cdeb9a…`) and config digest
(`sha256:e59ab297…`) into the provider-parent naming. Explicit records
verify the observed parent against their bound F28 exactly; default runs
record the observed binding without failing on it. The receipt carries the
outcome as `proxy.derivative_parent` (family, platform, manifest and config
digests, parent layers, prefix flag), explicit when absent or unverified.
Offline limitation: "retained RepoDigest equality (manifest corroboration)
+ config digest + DiffID prefix is SUFFICIENT for this slice.
Manifest-fetch (network) deferred."

## Selecting a proxy run

Proxy runs use the library API or the CLI: `prepare_proxy(spec)` validates
selection without creating resources, and `run_application` routes
`mode='proxy'`. `p11lab run --mode proxy` takes the daemon image as
`--artifact`, the caller image as `--consumer-image` for `proxy/container`,
and the native-client bundle as `--client-artifact` plus its
`--client-sha256`; `prepare_proxy` still requires the `bundle` kind with a
full SHA-256 on `linux/amd64`, and a reused client installation
(`installed_prefix` for `proxy/host`) stays library-only.
`--proxy-build-manifest PATH` selects an explicit expected identity record
instead of the pinned default; the manifest is strict JSON (unknown or
missing fields reject), and a missing, unreadable, or invalid manifest, or
the flag on a non-proxy mode, is a usage error (exit 2). Manifests larger
than 1 MiB are usage errors: the loader reads at most 1 MiB + 1 byte. The
manifest stays caller-authored until the workflow slice mints sealed
selections.

`proxy/container` needs an exact daemon image, an explicit exact caller image
and an exact native-client bundle. The consumer container runs precisely the
caller argv with `argv[0]` as entrypoint, so provider-derived consumers cannot
reinterpret the command. The shim is mounted read-only with client TLS files,
and the consumer receives `P11LAB_MODULE` pointing at the shim plus the exact
`PKCS11_PROXY_ENDPOINT`/`PKCS11_PROXY_TLS_*` transport variables. The
consumer mounts no token state: the token is reachable only through the shim.

`proxy/host` needs an exact daemon image and an exact client bundle. The
application runs on the host with the shim from a verified installation
(`installed_prefix`) or a verified temporary prefix, whose path is exported
as `P11LAB_SHIM` and `P11LAB_MODULE`. It inherits the caller environment
minus `P11LAB_*`, `SOFTHSM*`, `LD_*` and `PKCS11_PROXY_*` names, plus the
declared inputs and the shim/transport variables. The daemon publishes its
port on the loopback interface only; anything else fails the run before
the application.

## TLS and daemon contract

Every run generates a fresh evaluation CA with server and client leaves
(OpenSSL Ed25519) and verifies chain, SAN and EKU before use. The server leaf
covers `provider-daemon`, `localhost` and `127.0.0.1` with serverAuth; the
client leaf carries a nonempty subject with clientAuth. Only server
leaf/key+CA reach the daemon and only client leaf/key+CA reach the consumer;
the CA private key never enters a mount. Partial TLS triples, wrong owners,
group/other-readable keys and world-writable certificates fail before any
container starts. The daemon additionally refuses a group/world-writable
config file.

The daemon takes a positional TOML file with the provider module path,
`max_contexts = 1`, transparent mechanism discovery, an IP:port mTLS
listener and `allow_all_authenticated` for the dedicated evaluation
instance. `lease_seconds = 1` reclaims contexts orphaned by short-lived
helpers that exit without `C_Finalize` (observed in checker preflight);
reaping still needs an expired lease plus a new admission, so a second live
context is refused exactly as with the default lease. The context-free CLI
health probe must report SERVING before the application runs; it checks
transport and backend gating, never application behavior. In the pinned
CLI, exit 0 holds exactly when SERVING is reported (exit 1 is
NOT_SERVING, 2 is probe failure), so the runner's exit-code check is
equivalent to asserting the SERVING line. The daemon configuration fixes
`request_timeout_secs = 60` and `startup_timeout_secs = 30`; the runner's
health gate gets a 30-second window with at most 10 seconds per probe and
one second between attempts.

## Isolation and failures

One logical client uses one dedicated daemon, token state and TLS set.
Restart the daemon between independent clients and use separate tokens for
shards. After a restart all handles are invalid; reopen sessions instead of
replaying operations. Unauthorized clients, wrong-CA consumers and daemon
loss fail closed without retries: the CLI reports transport failure and the
application observes native errors such as `CKR_GENERAL_ERROR` on connect
or `CKR_HOST_MEMORY` at the context limit. Direct/provider and transport
outcomes are recorded separately and never merged.

Every created, identified daemon gets a terminal diagnostic attempt before
removal, including successful runs, startup or application failure, timeouts,
and cancellation. `receipt.json` records `proxy.daemon_terminal`: Docker
state before a requested stop, state after that stop when attempted, readiness
and stop facts, and diagnostic availability. The state fields retain Docker's
exit code, running status, OOM flag, error, and timestamps; unavailable facts
are null. An encoded signal candidate (for example exit 137 suggesting signal
9) is an inference from the exit-code convention, never an observed signal or
proof of termination cause. A stop request is recorded separately from a
daemon found already exited. Death observed after readiness is a lifecycle
failure even when the application returned zero or fresh post-health succeeds.

`daemon.stdout.log` and `daemon.stderr.log` retain bounded prefixes through the
same credential-snapshot redactor as other engine logs, with truncation flags
in the receipt. Only allowlisted Docker state fields are retained; container
configuration, environment, mounts, and TLS key material are excluded. Failed
inspect/log attempts record unavailable evidence and available raw diagnostic
status separately from application return codes and cleanup errors. Such a
diagnostic failure cannot produce a successful run. Application nonzero return
codes retain their existing precedence. A requested stop and owned removal
complete before the fresh post-health container takes the token-state lease;
stop or removal failure skips post-health. These observations establish run
evidence, not provider or proxy qualification.

Residual bridge exposure (STRIDE S2/D4): the daemon and a
`proxy/container` consumer share one owned bridge network, so daemon-side
listeners that cannot bind loopback stay reachable from the consumer. The
frozen vpcd handler in the isoapplet/pivapplet providers listens wildcard
on 35963/35964, so a malicious or buggy consumer can dial the card channel
directly, bypassing mTLS proxy auth, or disrupt card state. The tpm2 swtpm
listeners bind `127.0.0.1` explicitly. Direct mode is unaffected
(`--network none`). Bridge segmentation (a daemon-only network plus a
published loopback proxy port) stays a future option, not implemented.

The installed checker runs in its declared consumer through the same
contract. Its driver preserves the controlled container environment for the
shim and finalizes helper contexts deterministically at process exit; result
evidence is validated with the frozen checker validator, and interface
observations (for example v2-only negotiation skips) are transport facts,
not provider findings.

## Native-client bundle

The `native-client` role packages the shim (`lib/...` module) and CLI with
proxy license notices. Installation verifies the archive, manifest and every
payload file, checks the Linux x86_64 host, resolves the shim closure with
the system loader and launches the CLI before publishing the prefix. It
installs no prerequisites and changes no loader settings. Archive hash and
installed placement stay separate identities with their own receipts.

Proxy container bind mounts preserve literal double quotes, spaces, and shell
metacharacters in caller paths through Docker's CSV mount format. Existing
comma-path restrictions and single-line input validation still apply. The
consumer's workspace and output remain writable; the shim, TLS material, and
configuration remain read-only, and token state stays on the daemon side.

After the application can write output, controller log creation refuses an
existing path, including symlinks, hardlinks, and ordinary files, instead of
following or truncating it. A refused application, daemon, or post-health log
makes evidence incomplete and prevents success. Completed application status
keeps its normal precedence, and daemon status capture and owned cleanup still
run. Host application captures also record stream-specific `log_errors` without
losing process status, timeout, truncation, or supervision facts. This protects
controller writes; a host application already runs with the caller's privileges.

## Pinned transport-control roster

The diagnostic tier's required transport controls are pinned in
`src/p11lab/data/ci/proxy-policy.json` (tier `proxy-diagnostic-v1`): seven
stimuli with expected CK_RV, backend-effect and termination contracts that
run on both accepted and candidate proxies, with strict loading and a pure
truth-table verdict in `src/p11lab/proxy_policy.py`. The roster is
diagnostic-only — budgets are unqualified targets and the PX-LIMIT rejection
value stays unbound until the live slice qualifies it — so any missing
control, failed accepted control or lost terminal evidence yields an
incomplete verdict, never a smaller success.
