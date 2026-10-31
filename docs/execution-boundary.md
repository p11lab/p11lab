# Execution boundary

## Host rules

- H-ALLOW-1: The controller may run in-process and in fork-without-exec
  workers (`proxy_supervisor`) that run only controller callables with data
  inputs.
- H-ALLOW-2: Sealed or pinned interpreters may run with literal, fixed argv
  and verified scripts (evaluator planner/admission, closure probe,
  installed `pkcs11-check` planning/execution/merge); where the input is
  protected, seal before AND after (evaluator pattern).
- H-ALLOW-3: System toolchain binaries (`docker`, `git`, `patch`,
  `openssl`, `ldd`) may run with controller-constructed argv only;
  `shell=True` is prohibited everywhere and candidate-controlled strings
  never enter argv.
- H-ALLOW-4: The local operator's own application argv may run in the proxy
  host lane only, supervised with redacted bounded logs and a scrubbed
  environment; the operator is trusted and hostile argv is outside the
  threat model.
- H-DENY-1: Never import, `runpy`, `eval`, `exec`, or otherwise execute
  bytes from the network, candidate outputs, wheels, or archives on the
  host; such bytes may only be hashed, compared, roster-checked, and
  parsed with bounded inert parsers.
- H-DENY-2: Never fork while holding (or while a sibling thread may hold)
  a lock the child path needs, except in the deliberate contention tests;
  prefer single-threaded fork points and keep the child's import surface
  warm (module-level imports) so post-fork imports cannot deadlock on a
  held import lock.

## Container rules

- C-ALLOW-1: Provider, candidate-install/startup, and build-backend code
  may execute only inside containers launched from sealed/pinned images
  with the recorded boundary (nonroot user, read-only root, no network,
  inspected before start, stopped before readback, exact-owned cleanup).
- C-DENY-1: No candidate code on the host, no host mounts writable by the
  candidate beyond the owned output volume, no network for candidate
  stages.

## Extraction rule

- E-1: Extract only after authentication (digest or closed roster), with
  traversal/link/device/duplicate/size guards; extracted bytes are data
  until a rule above admits them for execution.

## Test rule

- T-1: Deliberate fork-under-contention tests are the only sanctioned
  threaded-fork probes; they prove fail-closed timeouts, not progress, and
  their `DeprecationWarning`s are retained signals — never add warning
  filters, never claim a warning-free pass, never suppress the warning
  instead of narrowing the fork surface.

## Documented limitation

Local evidence acquisition and validation execute only trusted code on the
host: the p11lab controller, sealed or pinned tool interpreters with fixed
arguments, and system utilities with controller-constructed arguments.
Downloaded bytes, candidate outputs, wheels, and archives are hashed,
compared, and parsed on the host but never imported or executed there;
provider and candidate code runs only inside the documented container
boundaries, plus your own application command in the proxy lane, which runs
on the host under supervision — do not pass untrusted third-party commands
there. Process isolation uses fork without exec under a hard deadline: if a
worker is started while other threads hold locks it needs, the child may
stall and the operation fails closed with a timeout rather than a result.
The test suite deliberately exercises this case, so contention tests emit
Python fork-while-threaded warnings by design; the warnings are retained as
evidence of the test and are never suppressed. Invoke acquisition from
single-threaded code when dependable progress matters. These limits do not
affect the correctness of completed results: timeouts and unconfirmed
cleanups are reported as failures, never as passes.

## Native lane exclusion

The native lane (`native.py`) is unreviewed for execution boundaries: it
executes provider libraries and applications on the host by design, and
nothing here qualifies native host execution.

## Loader inspection

`/usr/bin/ldd` loader-based inspection of built artifacts is the least
inert host-exec site; it runs only on locally built trees in producer
bootstrap and should stay out of any future untrusted-input path.

## Static-pin scope

The pins in `tests/test_execution_boundary.py`
are literal-only: the `shell=True` pin matches
direct `shell=` keywords with a constant-`True`
value, and the dynamic-exec pin matches bare
`eval`/`exec`/`__import__` call names.
Keyword-splat (`**{"shell": True}`), variable
(`shell=flag`), attribute (`builtins.eval`), and
computed-name forms bypass the static check;
their absence rests on review, not on the pin.
