# Native BouncyHSM on Windows: worked example

This example installs a Windows x64 bundle and runs the independent C
consumer through one supervised native run. It uses the same library
operations as the acceptance workflow.

## Prerequisites

- Windows x64 with the VC runtime, .NET 10 (SDK or runtime with ASP.NET
  Core 10.0.12+), Python 3.12+, MSVC `v145` (`cl`, and `msbuild` for
  rolling), OpenSSL CLI, git. See `docs/windows.md`.
- A P11Lab checkout with P11Lab importable (`pip install <checkout>` or
  `PYTHONPATH=<checkout>/src`).
- The C consumer sources from the installed package data
  (`src/p11lab/data/consumer/`: `smoke.c`, `p256.c`, `verify.py`).

## Release: verified archive

```powershell
# Fetch and record the pinned archive (hash enforced by the builder too).
curl.exe -sSL -o BouncyHsm.zip https://github.com/harrison314/BouncyHsm/releases/download/v2.3.4/BouncyHsm.zip
(Get-FileHash BouncyHsm.zip -Algorithm SHA256).Hash  # AF483A48...

# Build the probe from the locked sources.
cl /std:clatest /O2 /W4 /WX <p11lab>\src\p11lab\data\providers\bouncyhsm\probe.c /link /OUT:bouncyhsm-probe.exe

# Assemble and install the bundle.
python -c "from pathlib import Path; from p11lab.native import build_bouncyhsm_bundle; ..."
```

The exact calls are in `run.py`; the snippet below shows the shape:

```python
from pathlib import Path
from p11lab.native import build_bouncyhsm_bundle, install_bouncyhsm_bundle

artifact = build_bouncyhsm_bundle(
    environment="bouncyhsm", channel="release", target="windows-amd64",
    output_dir=Path("build/release-bundle"),
    archive=Path("BouncyHsm.zip"), probe_exe=Path("bouncyhsm-probe.exe"),
)
installed = install_bouncyhsm_bundle(
    artifact, Path("prefix"), environment="bouncyhsm", channel="release"
)
```

## Rolling: source build

```powershell
git clone https://github.com/harrison314/BouncyHsm.git upstream
git -C upstream checkout f09ab9a342741c56bb56621a707c1b94dfdeac4b
'{"sdk":{"version":"10.0.401","rollForward":"disable"}}' | Set-Content upstream/global.json
Push-Location upstream; dotnet --version; Pop-Location  # must print 10.0.401
foreach ($p in "BouncyHsm", "BouncyHsm.Client", "BouncyHsm.Core", "BouncyHsm.Infrastructure", "BouncyHsm.Spa") {
  Copy-Item "<p11lab>\src\p11lab\data\providers\bouncyhsm\dotnet-locks-rolling\$p.packages.lock.json" "upstream\src\Src\$p\packages.lock.json"
}
dotnet publish upstream/src/Src/BouncyHsm/BouncyHsm.csproj -c Release -o payload/server /p:RestoreLockedMode=true /p:Deterministic=true /p:DebugSymbols=false /p:DebugType=None
msbuild upstream/src/Src/BouncyHsm.Pkcs11Lib/BouncyHsm.Pkcs11Lib.vcxproj /p:Configuration=Release /p:Platform=x64 /p:PlatformToolset=v145 /p:OutDir=%CD%\dll\
copy dll\BouncyHsm.Pkcs11Lib.dll payload\
copy upstream\LICENSE payload\
cl /std:clatest /O2 /W4 /WX <p11lab>\src\p11lab\data\providers\bouncyhsm\probe.c /link /OUT:payload\bouncyhsm-probe.exe
```

(`PlatformToolset=v145` fails loudly when the toolset is absent; record
`cl` and `dotnet --info` output with the run.)

## Run the consumer

```powershell
# Build the independent consumer (pinned cryptoki headers travel with it).
cl /std:clatest /O2 /W4 /WX <consumer>\smoke.c <consumer>\p256.c /link /OUT:p11lab-smoke.exe

# PIN files hold one line with at most one trailing newline (framing, not part of the PIN).
python run.py --prefix prefix --channel release --tools .
python <consumer>\verify.py out/smoke
```

`run.py` provisions one token under `state/`, runs the consumer, and
prints the receipt summary. Re-running against the same state directory
reuses the token without credentials; point at an occupied port to see
the refusal instead of an attach.

## What is verified

- Bundle install re-verifies every byte and runs host/ABI preflight
  (real DLL load, VC-runtime closure, .NET floor) before touching the
  prefix.
- The run supervises exactly one owned server on per-instance loopback
  ports, requires native readiness plus the provisioned slot, and stops
  only its own server.
- The OpenSSL oracle independently verifies the consumer signature.
