# Local proxy compiler toolchain

P11Lab provides a local, Linux amd64 proxy toolchain observation through the
Python API. It uses the fixed proxy input selection and the selected Debian
compiler package closure. The observation does not establish source authority,
license or redistribution eligibility, caller identity, proxy build readiness,
ABI compatibility, provider behavior, or release qualification.

The selected Rust compiler, Cargo, standard library, and protoc archives are
verified as inert inputs. The source archive and vendor tree are reverified but
are not executed. Debian packages are installed using the shared bounded rootfs
installer. Rust and protoc files are then assembled as inert data into a flattened
local image; the original archives remain separate. The image is not represented
as retaining the Debian image's OCI parent layers. The result records the actual
image ID, config and layers, full stopped-filesystem inventories, package and
archive member identities, executable dependency closure, native loader output,
and cleanup observations. The selected closure accepts only the observed Rust
`$ORIGIN/../lib` RUNPATH; RPATH and other search paths are refused. Native loader
observations cover every dynamic executable in the selected root roster,
including compiler subprocesses, and are checked against the closed in-image
library paths. Warm verification rechecks the same complete roster.

```python
from pathlib import Path
from p11lab.proxy_inputs import ProxyInputCache
from p11lab.proxy_toolchain import (
    ToolchainRequest, build_proxy_toolchain, read_toolchain_observation,
    verify_proxy_toolchain,
)

cache = ProxyInputCache(
    source_archive=Path("inputs/source/proxy.tar.gz"),
    payload_root=Path("inputs/payload"),
    vendor_root=Path("inputs/vendor"),
    debian_receipt=Path("debian-inputs/resolved-inputs.json"),
    acquisition_receipt=Path("inputs/resolved-proxy-inputs.json"),
)
result = build_proxy_toolchain(ToolchainRequest(cache, Path("toolchain-attempt")))
# A caller that receives this return can retain its own witness and selection.
selected_sha256 = result["completion_witness"]["receipt_sha256"]
observation = read_toolchain_observation(
    Path("toolchain-attempt"), manifest_sha256=selected_sha256,
)
verification = verify_proxy_toolchain(
    Path("toolchain-attempt"), manifest_sha256=selected_sha256,
    cache=cache, verification_dir=Path("toolchain-verification"),
)
```

Both output directories must be fresh. The durable build and warm files use the
versioned `p11lab.toolchain-observation.v2` envelope and remain provisional:
they preserve the observed bytes and facts but say publisher/API completion is
unconfirmed. A correct selected hash and the file's own fields cannot establish
completion. `read_toolchain_observation` reads only this provisional selection;
it does not verify the underlying image or inputs, and `require_completed=True`
refuses it even with the correct hash. Legacy self-declared success receipts are
not accepted by this reader.

A successful bounded API return carries a separate completion witness for the
caller that actually receives that return. The witness is not a signature or
independent producer/caller authority. A later caller or workflow must protect
its own native completion evidence if durable completion is needed. Warm
verification reselects installed policy and inputs, checks evidence and contexts,
and independently exports and checks the actual local image. Its returned
`local-byte-verification-observed` result and witness describe that verification;
they do not establish completion of the earlier build attempt. A digest taken
from an untrusted manifest does not authenticate it. The acquisition receipt
supports only unattested origin consistency; it grants no producer authority.

Native controls run without network as a nonroot user with a read-only image,
all capabilities dropped and no-new-privileges. The fixed dependency-free Cargo
project is compiled offline and locked using an empty owned Cargo home and a
controlled environment. Its output and a protoc descriptor are checked against
independent fixed expectations. The writable output is a 256 MiB, 10,000-inode
`nosuid,nodev` tmpfs, with execution enabled for the authored hello program;
`/tmp` is a separate 128 MiB tmpfs. These controls do not run the proxy source,
its build scripts or proc macros, or any provider.

The toolchain-specific archive, regular-byte and file-count limits are 1 GiB,
1 GiB and 32,768 entries, with a 256 MiB per-file limit. The XZ decoder memory
limit is 134,283,928 bytes, matching the measured selected Rust streams. The
compiler install retains the shared 768 MiB bounded rootfs policy; no shared
limit is raised. Canaries have a 120-second limit. Build and warm verification each have a
600-second whole-observation deadline, including preflight, cleanup and receipt
finalization. After a failure or timeout, up to 30 seconds is reserved for
cleanup and 10 seconds for recording the failure; these reserves never permit a
late success. Oversized or unreadable partial evidence is recorded as metadata
without inventing a hash. Failed or incomplete attempts and unconfirmed cleanup
do not become successful observations.
