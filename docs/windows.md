# Native BouncyHSM on Windows x64

BouncyHSM runs natively on Windows x64 as a P11Lab native bundle: the
upstream PKCS#11 client DLL, the managed server tree, and a small P11Lab
readiness probe. The host supplies .NET 10 and the x64 VC runtime; P11Lab
supervises one owned server per run, provisions one labeled token per state
directory, and runs one caller application against the native module.

Status: acceptance input only. Distribution remains `unreviewed`: bundle
bytes are verified and exercised here, but whole-artifact licensing, source
companion delivery, and digest-bound admission are separate requirements.
No bundle, image, cache export, or release is published by these steps.

Windows acquisition is not hermetic. The workflow pins its actions by
commit SHA but uses a hosted runner image, the `10.0.x` runtime patch
band, a pip upgrade, and unlocked Python test/checker dependencies.
The workflows record the resolved set in the job log (`pip freeze`
output); hash-constrained installs are a follow-up.
Exact resolved versions and bundle hashes identify an executed attempt;
they do not pin all downloaded bytes or prove reproducible Windows
builds. This remains a qualification limitation.
The rolling build SDK stays fenced to 10.0.401; runtime preflight still requires
both .NET runtimes at 10.0.12 or later within the 10.0 band, with `LatestPatch`
roll-forward. Fully immutable acquisition and dependency locks are required
before claiming hermetic Windows qualification.

## Prerequisites

Host prerequisites (never bundled, always verified before use):

| Input | Release | Rolling |
|---|---|---|
| Windows | x64 with the VC-runtime/UCRT closure the DLL imports (tested on the `windows-2025-vs2026` hosted image, Server 2025 build 26100, image 20260925.250.1) | same |
| .NET 10 | SDK or runtime with `Microsoft.NETCore.App` and `Microsoft.AspNetCore.App` 10.0.12 or later in the 10.0 band (`LatestPatch` roll-forward; the resolved runtimes land in the receipt) | same |
| Python | 3.12+ for the operator side (P11Lab itself); ordinary consumers do not need Python | same |
| Provider bytes | Upstream `BouncyHsm.zip` for tag v2.3.4, SHA-256 `af483a48b3d89a1284308ad88a30a08a37cae891319a74fbc2fbb4ebf1ea0a8a` (26,851,123 bytes), verified plus its full 381-file inner roster including the x64 DLL `native/Win-x64/BouncyHsm.Pkcs11Lib.dll` (`7c965ff44201a43cd146cfa842ee1b8af15e484ae3d09e46a8cd81a186f833af`, 270,336 bytes) | Source checkout of `https://github.com/harrison314/BouncyHsm.git` at `f09ab9a342741c56bb56621a707c1b94dfdeac4b`, .NET SDK exactly 10.0.401 (fenced by `global.json`), locked NuGet restore from the shipped `dotnet-locks-rolling/`, MSVC `v145` toolset targeting x64 |
| Test tooling | `cl` for the probe build, OpenSSL CLI for the independent signature oracle, git for source checkouts | same plus `msbuild` for the DLL build |

CAUTION: an earlier review draft quoted `7ccb1840...` (archive) and
`2f4ecd62...` (DLL). Those hashes do not match the staged bytes, the
acquisition record, or a fresh upstream download; the corrected values
above are verified three ways and pinned in
`windows.release.files.json`.

## Bundle layout and identity

Both channels produce the same N1 bundle shape (tarball, installed with
the reviewed `bundle.py` machinery; there is no second installer):

- `bin/BouncyHsm.Pkcs11Lib.dll` — the native client module (manifest `module`).
- `bin/bouncyhsm-probe.exe` — the P11Lab PKCS#11 probe, compiled from the
  locked `probe.c` with MSVC `v145`. Every native operation in lifecycle
  and acceptance goes through this binary.
- `server/` — the managed server tree (`BouncyHsm.exe` plus its composition).
  Release keeps the upstream composition minus the other-platform clients
  under `native/`; rolling is a Release `dotnet publish` of `BouncyHsm`.
- `share/licenses/bouncyhsm/{LICENSE,FILE-NOTICES.txt}` — upstream BSD-3
  text plus P11Lab file notices (embedded MIT helper, cryptoki note,
  managed-closure observations).
- `share/p11lab/{native-id,provider.json,THIRD-PARTY-NOTICES.txt}` and
  `share/licenses/p11lab/LICENSE` — bundle identity and P11Lab terms.

The target lock pins, per channel, the source revision, the acquisition
(archive hash plus full inner roster, or the source-build toolchain
claims), the module/lifecycle/host contract, and the asset hashes. The
builder re-verifies the acquisition and records the payload bytes in the
manifest; install re-verifies the archive, the manifest, and the payload
before host preflight.

## Install

Native operations are library calls (there is no `p11lab` CLI spelling
for bundle clients, the same precedent the proxy lanes use):

```python
from pathlib import Path
from p11lab.models import ArtifactRef
from p11lab.native import build_bouncyhsm_bundle, install_bouncyhsm_bundle

# Release: verified archive plus the CI-built probe.
artifact = build_bouncyhsm_bundle(
    environment="bouncyhsm", channel="release", target="windows-amd64",
    output_dir=Path("build/release-bundle"),
    archive=Path("BouncyHsm.zip"), probe_exe=Path("bouncyhsm-probe.exe"),
)
installed = install_bouncyhsm_bundle(
    artifact, Path(r"C:\p11\prefix"), environment="bouncyhsm", channel="release",
)
```

```python
# Rolling: staged payload plus pinned build claims.
artifact = build_bouncyhsm_bundle(
    environment="bouncyhsm", channel="rolling", target="windows-amd64",
    output_dir=Path("build/rolling-bundle"), payload_dir=Path("payload"),
    build_meta={"source_revision": "f09ab9a342741c56bb56621a707c1b94dfdeac4b",
                "sdk_version": "10.0.401", "toolset": "v145",
                "compiler": "...", "publish": "..."},
)
```

The rolling payload directory holds `server/` (with `BouncyHsm.exe`),
`BouncyHsm.Pkcs11Lib.dll`, `bouncyhsm-probe.exe`, and `LICENSE`.

Install runs archive verification, manifest readback, target-contract
validation, and host/ABI preflight (x64 identity, a real DLL load through
the shipped probe proving the VC-runtime/UCRT closure, and the .NET
runtime floor) inside a staging directory first; the requested prefix is
created only after preflight passes. State, control, and output always
live outside the prefix.

## Run

`run_native_bouncyhsm(spec, installed)` supervises exactly one owned
server and runs one application:

- The caller artifact must equal the installed receipt artifact, and the
  payload is reverified before anything is provisioned.
- HTTP and native TCP endpoints are per-instance loopback ports
  (`P11LAB_HTTP_PORT`/`P11LAB_TCP_PORT`, or ephemeral selection). An
  occupied requested port fails the run instead of attaching.
- One token per state directory. A fresh state directory provisions
  exactly one labeled slot (LiteDB persistence); compatible state is
  reused without credentials; foreign, ambiguous, or partial state fails
  without reset and without touching other data.
  An existing empty `bouncyhsm/` directory without a valid completion marker
  is an incomplete attempt and is refused. Recovery requires explicit
  replacement or removal of disposable state by its owner.
- Readiness is HTTP health plus a native probe plus the provisioned slot
  at every stage. HTTP alone never qualifies.
- The application inherits `P11LAB_MODULE`, `BOUNCY_HSM_CFG_STRING`, and
  `P11LAB_OUTPUT_DIR`; nothing else provider-specific leaks in.
- Shutdown stops owned server/application trees, finishes bounded log capture,
  records straggler cleanup, and verifies the endpoints are released. Foreign
  processes are never signaled and foreign directories are never removed.
- Exit status keeps a completed application status even if a later check
  fails; timeouts report 124. Secrets are redacted from logs and the
  receipt records ports, slot, stages, and the resolved host runtimes.

```python
from p11lab.models import RunSpec
from p11lab.native import load_bouncyhsm_installation, run_native_bouncyhsm

installed = load_bouncyhsm_installation(
    Path(r"C:\p11\prefix"), environment="bouncyhsm",
    channel="release", platform="windows/amd64",
)
spec = RunSpec(
    "bouncyhsm", "release", "native", installed.artifact, "host",
    None, None,
    ("p11lab-smoke.exe", "--module", str(module), "--token-label", "P11Lab",
     "--pin-file", "pin", "--output", "out/smoke", "--key-mode", "generated"),
    {"P11LAB_PIN_FILE": "pin", "P11LAB_SO_PIN_FILE": "so-pin"},
    Path("out"), Path("."), 300, installed.prefix,
)
result = run_native_bouncyhsm(spec, installed)
```

`examples/windows/` shows the same flow end to end, including the C
consumer build (`cl`) and the independent OpenSSL verification.

## Manual operation

Without P11Lab, run the server directly from an install prefix:

```powershell
$env:ASPNETCORE_URLS = "http://127.0.0.1:8080"
$env:BouncyHsm_PersistenceStorageType = "LiteDb"
$env:BouncyHsm_LiteDbPersistentRepositorySetup__DbFilePath = "C:\p11\state\BouncyHsm.db"
$env:BouncyHsm_BouncyHsmSetup__TcpEndpoint__Endpoint = "127.0.0.1:8765"
C:\p11\prefix\payload\server\BouncyHsm.exe
```

Provision one slot (`GET /Slot` must be `[]` first; `POST /Slot` takes the
`CreateSlotDto` with PascalCase keys), point the client at it
(`$env:BOUNCY_HSM_CFG_STRING = "Server=127.0.0.1;Port=8765;"`), and run the
application with the DLL path. The probe checks readiness without P11Lab:

```powershell
C:\p11\prefix\payload\bin\bouncyhsm-probe.exe --module C:\p11\prefix\payload\bin\BouncyHsm.Pkcs11Lib.dll --load-only
C:\p11\prefix\payload\bin\bouncyhsm-probe.exe --module ... --server 127.0.0.1 --port 8765
```

## State, persistence, reset, and limits

- Writable state is the LiteDB file plus the completion marker under
  `<state>/bouncyhsm/`; the server log and credential snapshots stay in
  the control directory. Both default under the run output directory.
- Restarting against the same state directory reuses the token; the slot,
  label, and persistent objects (including `CKA_TOKEN` keys) survive.
- Reset is an explicit removal or replacement of the disposable state
  directory. Nothing resets persistent tokens implicitly.
- Shutdown on Windows is process termination (no graceful server
  endpoint); LiteDB recovers on the next open and the runner verifies the
  ports are released.
- Loopback only: the server binds `127.0.0.1`, and the client transport
  is never remoted. Cross-OS loading (a Windows DLL from Linux or vice
  versa) is rejected by platform preflight.
- No proxy, container, or checker-container lanes exist on Windows. The
  installed checker runs on the host through the documented direct driver
  (frozen flags and validator); see the acceptance workflow.
- Paths with spaces are supported; PIN material stays in files or
  explicit scalar inputs and never lands in logs, receipts, or artifacts.
  PIN files contain one nonempty UTF-8 line with one optional trailing LF;
  extra lines, CR, NUL and invalid UTF-8 are refused before provisioning.
