# Run your application in CI

P11Lab's optional composite Action runs one caller command through the supported
`p11lab run` lifecycle: initialize disposable provider state, check readiness,
execute the command, check health and remove owned resources. The command runs
inside the provider image. The attempt ends with that command; later host steps
have no provider module or service. Files your command writes to the declared
caller directory remain on the host.

This source is prepared for Linux amd64 and a same-host local Unix Docker daemon.
Public acquisition currently fails closed: authenticated source transport and
full image promotion are still unavailable. Current published alpha images are
not eligible handoffs. There is no published immutable Action revision containing
this change or completed unrelated-repository GitHub pilot. The
[caller workflow template](../examples/application-ci/action.yml) therefore has
explicit required identity placeholders and is **not executable as supplied**.
Replace them only after publication and acquisition eligibility are established.
Ordinary [raw Docker consumers](published-images.md) remain supported independently
of this optional integration. Native compatibility is inactive for this workflow;
Windows, macOS, host-module setup and persistent service setup are outside it.

## Package the caller command

Supply your prebuilt application and its compatible dependency closure in a
credential-free caller subdirectory such as `ci-application/`. The image does not
provide your app, a compiler, Python, the checker or an application dependency
installer. Executables need Linux x86-64 compatibility, the correct libc, an
available ELF interpreter, shared libraries and supported library symbol versions.
Scripts need an interpreter already in the selected image or supplied compatibly
by the caller. See the [published image ABI example](published-images.md#mount-your-own-prebuilt-application)
and [runtime contract](runtime-contract.md).

`command` is a nonempty JSON array of literal argument strings. For example,
`["./run-tests", "a path with spaces", "literal $(text); quote \""]` does not invoke
a shell. Relative executables and file paths resolve inside `/workspace`; absolute
host executable paths are not translated to container paths. To use shell syntax,
explicitly choose a compatible shell as your command and understand its parsing.
The provider adapter supplies `P11LAB_MODULE` and its provider configuration to
your process; your application chooses how to use that module.

`working-directory` is relative to the caller workspace, not the Action's source
checkout. It defaults to `.`. The wrapper resolves the workspace and requested
path before acquisition and refuses nonexistent directories, absolute paths,
parent traversal and paths that escape through symlinks. Nested directories,
spaces, quotes and symlinks resolving within the workspace are supported. Docker's
bind syntax cannot represent commas in these host paths.

## Files, environment and lifetime

The resolved caller directory is mounted **read/write** at `/workspace`, and the
attempt output directory at `/p11lab-output`. The process sees
`P11LAB_OUTPUT_DIR=/p11lab-output`. All files within those mounts are visible,
including secrets, `.git` credentials or configuration that the caller places
there. Environment filtering cannot hide mounted files. Use a disposable app/test
subdirectory with no secrets, checkout with `persist-credentials: false`, and keep
credential/control files outside the declared mounts. Audit the app directory
before running third-party code.

Only declared provider inputs reach the provider environment; ordinary host and
publisher environment variables are not forwarded. Declare credentials through
supported `*_FILE` inputs outside the application directory. Each declared
credential file is intentionally snapshotted and mounted read-only; the parent
credential directory is not mounted. Such declared credentials are available to
the provider/application as required. Keep secret values out of command arguments
and public artifacts.

The shared direct runner uses the caller UID/GID, no network, a read-only image
root, no capabilities and owned disposable state. State persists only when
explicitly requested with the existing state input; persistent tokens are never
silently reset. Give independent clients/shards independent provider state.
Arbitrary applications can still chmod or create troublesome files in writable
mounts. Keep exact owned paths until cleanup succeeds, inspect failures, and do
not recursively delete a caller checkout to repair a failed run.

`timeout` retains its existing shared lifecycle meaning, including readiness and
application stages. Each wrapper acquisition call (handoff/binary pull, inspect,
manifest fetch or native installation) has a separate 300-second deadline.
Wrapper-owned children receive SIGINT, SIGTERM and SIGHUP at their own PID and get
up to 180 seconds to finish cleanup. The lifecycle has an additional 180-second
watchdog allowance beyond its requested timeout before cancellation is forwarded;
this is not additional application runtime. After the cleanup grace, shared
process supervision forcibly reaps the owned tree with its bounded drain/reap
steps (normally up to five more seconds). There are no retries. A job-wide CI
cancellation deadline, SIGKILL or runner loss can prevent cleanup and receipt
production; wrapper forwarding does not establish GitHub cancellation qualification.

## Status and evidence

The existing outputs are `exit-code`, `app-returncode`, `receipt-path` and
`handoff-sha256`. Safely allocated attempts finalize these even when validation,
acquisition or startup fails. A preflight failure has no invented lifecycle
receipt. Application output must avoid reserved stage log filenames such as
`application.stdout.log` and `post-health.stderr.log`. A pre-existing log entry
(including a symlink or hardlink) is refused with an explicit evidence-incomplete
lifecycle error; the controller never follows it to overwrite another host file.
The shared runner still preserves a completed nonzero app status.
`handoff-sha256` is populated only after fetched handoff bytes pass the
shared shape validation; it is not an admission verdict. A lifecycle's completed
application status keeps the shared runner's precedence over later failures.
A native app exit 124 and an actual timeout remain distinct in the receipt.

The `always()` collector rechecks the attempt's regular output record and the
receipt's shape, artifact, invocation and exit status. Missing, symlinked,
malformed or mismatched evidence leaves receipt/app fields empty and visibly
labels **evidence incomplete** in logs and the step summary. Failures before safe
attempt allocation use exit-code 1 in collection because no wrapper outcome
record exists. These are host-side evidence checks, not authenticity against a
malicious process controlling the caller host, provider certification or a full
public CI qualification.

Copy the template into the caller's `.github/workflows/`, replace both required
pins, and adapt its own command to your application's interface. Upload exactly
`receipt-path` on `always()` when present, with `if-no-files-found: error`. Keep
upload failures visible. When it is empty, retain the explicit incompleteness
label. Never upload the receipt's parent, `RUNNER_TEMP`, token state or broad
globs: those can include credentials and acquired private state. Additional app
outputs require the caller's own deliberate artifact selection.

Before claiming public reuse, an authorized clean unrelated GitHub repository
must run compatible own-app success, intentional nonzero, blocked-handoff and
cancellation controls, including read/write marker and outside-mount/environment
sentinels. Bind each result to the published Action commit, caller commit,
genuinely eligible handoff, acquired image manifest/config/engine/platform and
validated receipt or explicit incompleteness. Local fixtures and Docker diagnostics
do not close that acceptance gate.
