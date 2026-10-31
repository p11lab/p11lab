# Provider application execution

The [published-image quickstart](published-images.md) runs the SoftHSM runtime
with plain Docker, without installing P11Lab or building a provider. It documents
the published digest, default-root permissions and compatible prebuilt application
mounts. The controls and receipts below describe installed `p11lab run`; plain
Docker does not automatically apply them.

Direct/provider requires a same-host Docker daemon on a local Unix socket; SSH
and TCP endpoints are rejected before resources are created. Host bind mounts and
bind-backed owned volumes depend on that host filesystem.

Install P11Lab and use `p11lab describe softhsm2 --channel release` to inspect the
installed provider contract. Build receipts identify local artifacts by their
exact Docker engine image ID. A local engine ID is distinct from an OCI registry
manifest digest, a config digest, and a native bundle archive hash; it may change
when transferred to another engine. Run requires the inspected local ID and
platform, never a mutable tag. Registry execution pulls no images by
itself: runs always bind an exact local engine ID (or a verified
native installation); tag-form references are refused.

`p11lab run ID --channel release|rolling --mode direct --where provider
--artifact sha256:IMAGE_ID --output-dir NEW_DIR -- ARGV...` executes the selected
image's `/usr/local/bin/p11lab-provider` adapter: `init`, `health`,
`exec -- ARGV...`, then `health`. The selected image may be a compatible caller
owned derivative with application tools. Its artifact occupies the provider role;
separate consumer and client identities remain null. `--consumer-image` and
`--client-artifact` reject in direct/provider mode. Native and host
execution are selected explicitly with `--mode`/`--where` (see
[native.md](native.md)); proxy execution is CLI- or library-driven (see
[proxy.md](proxy.md)). Mismatched combinations reject before resources
are created.

The four stages run as four sequential containers sharing token state
but no processes: nothing persists between stages except the token store
and the output directory, and daemon/emulator providers self-provision
per stage over `--network none` loopback. Startup cost is paid once per
stage container.
Shutdown is container termination per stage
(graceful exit or forced removal during bounded
cleanup); there is no separate daemon-shutdown step
beyond owned container and volume removal.

The application receives literal arguments, its explicit `--cwd` mounted read/write
at `/workspace`, and the new output directory at `/p11lab-output`.
`P11LAB_OUTPUT_DIR` points to that directory. The application working directory is
`/workspace`; lifecycle stages keep the image's working directory. Host variables
are not forwarded to the application. Only declared `--input NAME=VALUE` entries
reach the adapter; absent and empty inputs remain distinct. For SoftHSM prefer
`P11LAB_PIN_FILE` and `P11LAB_SO_PIN_FILE`, pointing to private host files with
one nonempty UTF-8 line with one optional trailing LF. Extra lines, CR, NUL
and invalid UTF-8 are refused; the optional LF frames the file and is not
part of the PIN. Credentials are bounded to 4096 bytes, copied into a
private temporary directory, and individually mounted read-only at
`/run/p11lab-input/NAME`. The temporary directory is removed after the run.
The original credential files and permissions are preserved. PIN values, file
paths and credential hashes are omitted from the receipt. Scalar PIN inputs are
explicit disposable-test alternatives and remain secret inputs. They stay
visible to the host caller through `docker inspect`, so prefer credential
files outside disposable tests.

Each invocation has independent opaque run and attempt IDs, exact container IDs,
and ownership labels. The default token store is a new owned Docker volume
backed by a private caller-owned temporary directory, removed at cleanup.
Volume copy-up is disabled to preserve its caller ownership. `--state-dir EXISTING_DIR` binds a caller-owned persistent
store, which is retained even on failure. Passing `P11LAB_STATE_DIR` as an
input is equivalent to `--state-dir` (same caller, same effect; combining
both is rejected as a duplicate). Init never resets existing tokens;
incompatible, partial or unknown state fails. Use a separate store for independent
clients and shards. Remove a persistent store only as an explicit user operation.
A persisted key must be provisioned as a token object; the smoke application's
generated keys are session objects and do not persist.

SoftHSM exposes `/usr/local/lib/p11lab/libsofthsm2.so` for Linux amd64 with
Debian 13 glibc 2.41 and its recorded OpenSSL dependency closure. The adapter
creates `/run/p11lab/softhsm2.conf` on each invocation, selects the exact token
label (`P11Lab` by default), and verifies initialization before reaching the
application. Native slot IDs and consumer slot indices are different values.
No module becomes remotely loadable by placing containers on a shared network.

SoftHSM's packaged `runtime-id` must be a readable, non-symlink regular file
containing exactly 64 lowercase hexadecimal bytes followed by one LF. This is
the build-input key, not a Docker image ID or registry digest. Completion markers
bind that key and the exact label bytes with fixed fields, order and a single
final LF. Invalid identity files, changed marker bytes and metadata read failures
reject before provider or application execution. A changed build key does not
migrate or rewrite existing state; use a separate explicitly initialized store.

Before SoftHSM initialization cleanup, handled HUP, INT and TERM stop the adapter
with status 129, 130 and 143 respectively, without resuming marker publication.
The shell may defer its trap until a foreground utility returns; signaling
only the adapter does not promise prompt cancellation of a blocked native child.
The adapter does not forward these signals to that child. Owned exit cleanup
attempts both lock and control-temporary removal even if a stop arrives, preserving
an existing failure status. Otherwise, the first observed cleanup failure or
stop supplies the exit status. A cleanup failure makes otherwise-successful
initialization nonzero; provider state and any already-published completion marker
are not rolled back.
Diagnostic write failures do not replace native failure statuses. Partial token
state, including an unpromoted completion temporary, is retained for explicit
inspection, not automatically reset or retried.

Containers explicitly use the invoking caller's UID/GID, no Linux capabilities,
no network, a read-only root filesystem and
`no-new-privileges`. Writes are limited to token state, `/run/p11lab`, `/tmp`, the
caller working directory and output directory. A non-root caller UID/GID is
exercised on a local rootful Linux engine. Rootless Docker and unrestricted
arbitrary UID compatibility are not promised. Docker bind paths
containing commas are rejected; paths with spaces and shell metacharacters work.
Public image distribution requires separate source and license admission.

`--timeout SECONDS` bounds the lifecycle attempt to 1..86400 seconds (24h
ceiling, enforced by the CLI). Docker control operations and
cleanup have separate bounded waits; cleanup can extend elapsed time beyond the
application deadline. SIGINT, SIGTERM and SIGHUP are forwarded to the running
container and owned attached processes are reaped. Host-executed applications
run supervised: signals forward to the owned process tree only, pipes drain
bounded while the process lives, and incomplete supervision (undrained logs,
surviving stragglers, supervision errors) is recorded as a lifecycle error
that fails runs which would otherwise report success. Cleanup targets only recorded
IDs whose ownership labels still match, never broad name prefixes. Containers
that do not terminate gracefully are forcibly removed during bounded cleanup.
A failed creation command gets one label-checked readback of its nonce name;
verified exact IDs enter cleanup. Unverified creation outcomes are retained as
explicit uncertainty and cleanup failure, with their private state directory
retained for recovery. Unrelated resources are preserved. Unexpected host
destruction can leave owned
resources behind without a completed receipt.

A completed application nonzero exit is primary even if post-health or cleanup
fails, times out, or is interrupted. Secondary timeout/signal facts remain in the
receipt. Otherwise application zero plus lifecycle/cleanup failure returns 1;
timeout returns 124; interruption returns 128 plus the signal number. Known attach
timeout/interruption outcomes do not require another successful status inspection;
ownership inspection remains required for cleanup. Failure before application
execution records null `app_returncode`. Atomic `receipt.json` records stages,
artifact roles, inspected descriptor, ownership IDs, execution controls, timeout,
interruption, application completion and cleanup errors. Each engine stage's
stdout/stderr retains a bounded 64 KiB raw-byte prefix while draining all
output; supervised host processes (proxy/host and native applications)
retain a bounded 1 MiB prefix per stream instead. The receipt declares
truncation either way.
Known explicit credential values are redacted. Commands and arbitrary argument
contents are omitted, so callers must separately retain a safe reproduction
command. Applications are responsible for keeping their own exported output safe.
This is an application execution record, not provider qualification.

SoftHSM builds split only debug sections before constructing the runtime image.
The ordinary static symbols, dynamic symbols and linking metadata are retained.
The runtime has GNU build IDs and debuglinks, without the separate debug files.
To retain a matching optional **binary** debug companion separately, use:

```sh
p11lab build softhsm2 --channel release --output-dir build-release \
  --debug-output-dir debug-release
```

The debug directory contains a compressed archive and its separate
`artifact.json` receipt. The receipt binds exact runtime bytes to original,
shipped and debug hashes, GNU build IDs and debuglink CRCs. A failed export never
emits a matched companion receipt. The binary archive includes the upstream
license and provenance referencing the exact source inputs; it requires the
runtime's source/license companion and is not a source-only companion.
All artifacts remain unreviewed until distribution admission. Runtime receipts
call Docker's `.Size` value `docker_reported_size_bytes`; it is an engine storage
observation, not a measured registry download or unpacked filesystem size.

Checker sharding freezes the plan before execution: `plan_shards` records the
roster, per-file source hashes, checker identity and the planner argv under a
`plan_id` seal. Attempts carry explicit `{shard_id, attempt_id, directory,
nodes, sources, checker, selected}` identities; validation requires exactly
one selected attempt per shard, the frozen node roster with no overlap or
reassignment, and matching checker/source identities. There is no balancer;
shard assignment is the frozen plan's.
