# Fixed tool input acquisition

P11Lab acquires protected input sets for Debian 13 Linux amd64 without a provider
checkout, project backend execution or private artifact cache:

```sh
p11lab tools resolve consumer --target debian13-amd64 --output-dir ./consumer-inputs
p11lab tools resolve checker --target debian13-amd64 --output-dir ./checker-inputs
p11lab tools resolve oracle --target debian13-amd64 --output-dir ./oracle-inputs
```

Each output directory must be fresh. A successful operation writes
`resolved-inputs.json` only after checking the complete file roster against the
installed lock. It retains opaque archives and copies protected resources. The
checker source archive is read to verify its complete Git tree and modes, without
extracting or importing it. No metadata hook, backend, installation, `.pth` file,
checker, provider or oracle is executed. `proxy` fails as unsupported; there is no
`tools build` operation.

## Selection and trust

All three selectors use snapshot `20260918T000000Z` and base
`docker.io/library/debian@sha256:7792b1f7702a86946cd518db72b6a407302c3e9bc1635634368b878189e8221c`.
The protected 78-package parent inventory is shared with the existing consumer
selection. It is provider neutral. A later builder must authenticate the actual
parent image and installed package files, including loader and libraries.

The installed provenance binds authenticated InRelease bytes, compressed and
expanded Packages/Sources hashes, recorded Debian signature verification and
exact binary/source stanzas. Resolution uses these installed pins rather than
accepting a caller lock, URL, receipt or signature declaration. The new checker
and oracle sets additionally check acquired index members against the complete
protected package/source stanzas. They use fixed dependency witnesses, with no
live package solver or automatic retries. Debian metadata authentication was
performed during curation; resolving does not launch a fresh PGP verifier.

Python artifacts have a separate type and origin policy. Packaged original PyPI
version metadata binds each selected filename, version, size, SHA256 and wheel or
source type to its official `files.pythonhosted.org` URL. This is recorded
HTTPS/package-index provenance, not Debian signature authentication. The checker
source uses only the official immutable GitHub codeload URL. The packaged commit,
complete path/mode/blob roster and Git tree are checked against revision
`9df03bd8b811966fa7856394b19e3f57ffcd8a40`. Each acquired source member must match
both its SHA256 and Git blob identity. No signed-commit claim is made.

## Checker executor and independent oracle

The checker selector fixes Debian CPython `3.13.5-2+deb13u5`, its stdlib, venv,
Debian pip/setuptools bootstrap wheels, loader/library dependency closure and
16 additional binary packages (94 packages including the declared parent).
Its portable Python inputs select 32 runtime dependency wheels, seven build/
bootstrap wheels (two shared with runtime), and their published source archives.
The runtime lock remains SHA256
`98a0341351b410b8ba6d732ae82ffef14442cded33caf8ab55e3958a0c407cab`.
The complete runtime roster has 33 wheels only **after** producing the fixed
checker output.

That output is the retained local `pkcs11_check-0.2.3-py3-none-any.whl`, SHA256
`58ac3451ae0dba207a48affa460309e4024c2ec7aefb04ef73062f420fdcffec`.
It has no observed public URL and is explicitly absent from the acquisition
roster. The source archive and sealed build inputs provide a portable route to a
later build. Reproducing the exact output, or deciding a different output variant,
remains blocked pending actual build evidence and review. The old local source
tar SHA256 `895f74063dda5ba97776906e0dae86cd3a2c68bc9254ae2cc84be07abc64f502`
is preserved separately: all 1,301 files, including project/version/build metadata,
match official Git objects; Git archive adds group-write permission while retaining
executable status. Complete retained wheel distribution metadata is recorded.
None of this substitutes the distinct sealed evaluator or a Python 3.12 install.

The oracle selector is independent of provider modules and token state. It adds
12 binary packages (90 including parent), fixing CPython and stdlib plus OpenSSL
`3.5.7-1~deb13u2`. Parent `libssl3t64`, loader, libc and transitive packages remain
bound by the parent inventory and signed-index evidence. The protected invocation
uses `/usr/bin/python3.13 -I`, packaged `consumer/verify.py`, `/usr/bin/openssl`,
`PYTHONNOUSERSITE=1`, `PYTHONSAFEPATH=1` and `LC_ALL=C`. `OPENSSL_CONF` points to the
packaged default-provider-only configuration; `OPENSSL_MODULES` fixes the Debian
module directory. The later runner must replace the environment with that exact
map, without inheriting host OpenSSL, loader or Python overrides. The legacy module is present in the parent package inventory
but is not activated by that configuration. A later independent image must prove
the actual executable/stdlib/libcrypto/loader/module/config bytes and environment;
resolution does not invent an installed or executed manifest.

## Preserved consumer inputs and subsequent builds

The consumer v1 lock and provenance bytes are unchanged: 43 unique binary archives,
16 source sets/48 files, nine metadata files and eight resources, 108 files total.
Its planned compiler roots are `gcc=4:14.2.0-1` and
`libc6-dev=2.41-12+deb13u4`; consumer utility root is `opensc=0.26.1-2`.
The compiler and consumer stage rosters contain 114 and 86 packages respectively.
The acquired consumer closure is not the oracle closure.

The next builder must consume verified input rosters, install offline, retain
actual package/ELF/loader manifests, record the compiler and complete command,
hash the resulting C executable and bind each derivative to its unchanged exact
parent. The C command is `cc -std=c11 -O2 -Wall -Wextra -Werror -pedantic smoke.c
p256.c -ldl`. Its binary and source/build relationship require new evidence;
historical images cannot qualify newly built artifacts. Checker wheel production,
its actual 33-wheel installation, and independent oracle positive/altered-message
negative controls are also subsequent work.

## Rechecking retained inputs

```python
from pathlib import Path
from p11lab.tool_inputs import verify_resolved_tool_inputs

result = verify_resolved_tool_inputs(
    "checker", target="debian13-amd64",
    receipt_path=Path("checker-inputs/resolved-inputs.json"),
)
```

This offline Python API reselects installed authority and rehashes every file.
Missing or extra files/directories, special members, symlinks, edited receipts,
changed bytes and wrong source/type selectors fail. Keep inputs and receipt
together. The exact installed lock bytes are required; a toolset name alone is
insufficient. Receipts record relative paths and explicit `installation=not-executed`
and `admission=unreviewed`, never an installed tool or image identity.

Fixed-tool builds copy public inputs into owned staging trees. Before read-only
mounts, staged directories are made traversable and regular files readable by
the sandbox; executable inputs retain their executable distinction. The generated
launcher is also readable by the sandbox. These modes are recorded in the input
context evidence and do not change cached inputs, source files or private
attempt directories.

## Bounds and remaining gates

The per-file limit is 256 MiB and aggregate limit 512 MiB. Requests have a
60-second I/O timeout, 900-second monotonic payload deadline, 3600-second attempt
deadline and at most five redirects. Redirects stay within the selected approved
HTTPS origin. Checks cover address attempts, TLS/request transitions, headers and
chunk framing. These budgets cannot preempt arbitrary stuck OS DNS or filesystem
calls. Allow extra space for receipts and retained partial failed attempts.

Failures retain diagnostics without a success receipt; retry in a fresh directory.
Receipt-write failure invalidates a replaced receipt where filesystem cleanup
succeeds and preserves the original error if cleanup also fails. These guarantees
assume a functioning filesystem and no concurrent adversarial writer or change to
the installed authority.

All source/license/artifact distribution status remains unreviewed. Metadata,
source archives and expected notice paths do not supply rights approval. Inherited
parent sources and `sqv` incorporated sources remain actual-content obligations.
Acquisition does not qualify installation, build reproducibility, usability,
provider behavior, CI custody or publication. No existing gate is enabled.
