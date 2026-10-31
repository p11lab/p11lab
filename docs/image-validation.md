# Local image validation API

`p11lab.image_validation.validate_image(artifact, policy, output)` runs a local
SoftHSM2 release image through one fixed direct checker shard and an independent
C/OpenSSL consumer check. The output directory must not exist. The candidate is
an exact `ArtifactRef` of kind `docker-local` for `linux/amd64`; the reference
and SHA must identify the same local engine image.

The caller supplies local tool build directories, their input receipts, and
independently retained manifest SHA-256 values for `checker`, `consumer`, and
`oracle`. The evaluator root and its independently retained receipt SHA-256 are
also required. `control_base_revision` identifies a declared Git base; it does
not assert that the running package is committed or authenticated.
The bounded local API requires a nonroot caller.

```python
from pathlib import Path
from p11lab.image_validation import validate_image
from p11lab.models import ArtifactRef

image_id = "sha256:" + "<64 lowercase hex digits>"
artifact = ArtifactRef("docker-local", image_id, image_id[7:], "linux/amd64")
policy = {
    "control_base_revision": "<40 lowercase hex digits>",
    "tools": {
        "checker": {"root": "/path/to/checker-build", "input_receipt": "/path/to/checker-inputs.json", "manifest_sha256": "<64 lowercase hex digits>"},
        "consumer": {"root": "/path/to/consumer-build", "input_receipt": "/path/to/consumer-inputs.json", "manifest_sha256": "<64 lowercase hex digits>"},
        "oracle": {"root": "/path/to/oracle-build", "input_receipt": "/path/to/oracle-inputs.json", "manifest_sha256": "<64 lowercase hex digits>"},
    },
    "evaluator": {"root": "/path/to/evaluator", "receipt_sha256": "<64 lowercase hex digits>"},
}
result = validate_image(artifact, policy, Path("/path/to/new-output"))
```

Tool receipts are revalidated against installed input authority and their
external seals. The checker and consumer are copied into separate stopped
children of the exact provider image; each child is checked against its parent
and the verified copied files. Each run uses disposable token state. The
independent oracle receives only the consumer's public output files. Original
reports, lifecycle and cleanup observations, the public admission result, and a
bounded evidence package are retained under the output directory.

Candidate output and captured stage-stream prefixes are checked for exact
staged credentials before retaining or redacting them. A matching original
archive or captured stream prefix is kept separately in a private directory,
the result is marked tainted, and evidence packaging is blocked. Public stage
logs are redacted derivatives; the stream capture is bounded and decoded, so a
private captured prefix is not a complete byte-for-byte stream. If a stage's
stream capture is unavailable, packaging is also blocked without claiming that
a credential was observed. These checks do not prove that a malicious provider
cannot encode information about a credential in other output.

`status: observations-complete` means the required local observations and
admission completed. It does not authorize image distribution or promotion.
The initial result has `comparison: null` and `promotable: false`; authenticated
producer identity, source and rights admission, a reviewed baseline, and a fresh
comparison remain separate work. A completed checker finding can have a nonzero
native status; a missing original, incomplete lifecycle, or failed cleanup makes
the local result incomplete.
