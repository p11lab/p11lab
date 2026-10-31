# Offline fixed tools

P11Lab's supported Python operations build the standalone fixed checker, C
consumer and independent OpenSSL oracle from protected, verified input rosters.
They use Linux amd64 Docker and the exact cached Debian base selected by the
installed input lock. They never pull a mutable fallback, build a provider image,
or grant distribution or provider qualification.

Resolve each selection first using `p11lab tools resolve` as described in
[tool inputs](tool-inputs.md). Then use a fresh output directory:

```python
from hashlib import sha256
from pathlib import Path
from p11lab.tool_builds import ToolBuildRequest, build_tool, verify_tool_build

output = Path("tool-attempt")
receipt = Path("checker-inputs/resolved-inputs.json")
result = build_tool(ToolBuildRequest("checker", receipt, output))
if result["status"] != "installed-local-only":
    raise RuntimeError(result["status"])

# Retain this seal in protected controller state before a later reuse operation.
# A hash supplied by an untrusted cache is not an authenticated seal.
manifest_sha256 = sha256((output / "manifest.json").read_bytes()).hexdigest()
verified = verify_tool_build(
    output, receipt_path=receipt, manifest_sha256=manifest_sha256
)
```

Replace `checker` with `consumer` or `oracle` and select that tool's matching
receipt. Input selection always comes from installed protected package resources;
the resolution receipt cannot select different source, packages, wheels or URLs.
There is no build CLI in this operation. P11Lab has no host installation side
effects: only its caller-owned Python environment and task-owned Docker resources
are used. Project metadata/backend code never runs on the host.

Each native stage uses a scrubbed environment, no network, no Docker socket or
credentials, one CPU, 1 GiB RAM with no additional swap, 128 PIDs, bounded file
sizes/logs and a 900-second deadline. Every outer container root is read-only.
Debian and checker installation write only into a named tmpfs rootfs with a hard
768 MiB / 32,768-inode quota. A trusted Perl launcher from the selected original
Debian base verifies actual tmpfs type/byte/inode limits and uses only
`SYS_CHROOT` to enter it. The launcher drops effective, permitted and inheritable
capabilities and verifies zero capabilities, no-new-privileges, and denied chroot
across exec before package or wheel code runs. Derived images never receive the
setup capability. No host device is mounted; only the standard null/zero/random
character nodes are reproduced inside the bounded rootfs.

Source/backend compilation continues separately as UID/GID 65532 with all
capabilities dropped, read-only root/inputs, a 512 MiB / 16,384-inode scratch tmpfs,
and the existing separate 16 MiB / 10,000-inode producer output tmpfs. The shared
candidate producer defaults are unchanged. Rootfs population and stopped readback
use bounded trusted Docker tar transfers; observed bytes are then flattened into
a new local image with the parent and archive identities recorded explicitly.
This is not Docker layer inheritance. Unsupported quota setup fails; there is no
writable-overlay fallback. Filesystem readback remains bounded to 1 GiB / 120
seconds, in addition to the limits enforced during execution. Native errors and
cleanup failures prevent a successful receipt.

The checker uses authenticated complete official source, locked build/bootstrap
wheels, Debian Python 3.13 and its 32 dependency wheels. The newly built wheel
must reproduce the protected expected SHA256 and size before installation can
start. A mismatch remains `blocked-output-mismatch`, preserving actual bytes and
provenance for a reviewed variant decision. Installation verifies every selected
wheel member against independently exported installed files and records the full
33-distribution roster. After installation/startup, every observed Debian parent
file and alias must remain unchanged; additions are restricted to the checker
installation prefix. The distinct evaluator is unaffected.

The consumer compiles the selected C source with
`cc -std=c11 -O2 -Wall -Wextra -Werror -pedantic smoke.c p256.c -ldl`, installs it
with the selected runtime package stage, and records actual compiler and runtime
ELF closures. The oracle installs the protected Python script/OpenSSL config and
runs provider-free public P-256 fixture controls: the packaged verifier must
accept the original signature, reject a changed signature, and observe OpenSSL
rejecting an altered message. No provider module, private key or token state is
mounted; the fixture's scalar-one key is public mathematical test data.

`manifest.json` distinguishes input/package/source, source-driver/build invocation,
product, actual installed-file, engine/config/layer and ELF identities. Debian
archive members are compared with actual filesystem bytes; excluded or changed
non-runtime files remain explicit. Unchanged parent files are bound to the exact
base image/layers plus full filesystem readback. Original exports, manifests and
native failures remain in the attempt directory. Staging files are diagnostic
copies, not reuse authority. Protocol-v2 warm reuse rejects old/unbounded or changed policy/installation
rosters even when their manifest seal is valid. It requires the externally retained manifest
seal and rehashes the protected input receipt, all durable evidence/products and
full filesystem archive; the local image's immutable config/layers must still
match. It executes no backend and grants no external producer authenticity.

Successful standalone product images remain in the local engine and are named by
engine/config SHA256 in the receipt. Intermediate images, all stopped containers
and output volumes are removed by exact inspected task ownership; independent
nonce-filtered absence is checked. A failed cleanup keeps the attempt failed.
These retained local images have unreviewed rights and are not public artifacts.
A later provider derivative must separately bind its unchanged provider parent,
actual composition and applicable source/content admission; this standalone
receipt supplies none of those decisions.
