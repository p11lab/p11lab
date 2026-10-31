# Direct Linux application smoke

For a first run with Docker alone, use the
[published SoftHSM quickstart](../../docs/published-images.md). It exercises shipped
provider tools and shows how to mount your own compatible prebuilt application;
no provider build or P11Lab installation is required.

The following is an optional application packaging example using the installed
P11Lab tools and a separate consumer derivative. Building this application is not
a prerequisite for using the published provider. There is no public prebuilt
`p11lab-smoke` download implied by this example.

Install the P11Lab wheel in a Python 3.12+ environment. The basic provider runtime
has no compiler, checker, Python or tracing dependency. Use the artifact from
`p11lab build softhsm2 --channel release --output-dir runtime-build`, or another
verified compatible local image. The build output's `artifact.json` contains the
exact local engine image ID.

The independent C consumer is a separate derivative. Prepare its context from the
installed package; this works outside a source checkout:

```sh
python3 prepare-consumer.py --channel release --output-dir consumer-context
```

Read the provider ID from the build receipt, tag it for Docker's `FROM` syntax,
and verify the tag still resolves to that exact ID. Keep this alias if it is the
last tag of an originally untagged image, since removing that alias can remove the
local parent artifact. The alias routes a build; it is not the artifact identity.

```sh
PROVIDER_ID=$(python3 -c 'import json; print(json.load(open("runtime-build/artifact.json"))["artifact"]["reference"])')
docker tag "$PROVIDER_ID" p11lab-local-provider:consumer-parent
test "$(docker image inspect --format '{{.Id}}' p11lab-local-provider:consumer-parent)" = "$PROVIDER_ID"
docker build --platform linux/amd64 --provenance=false \
  --build-arg PROVIDER_IMAGE=p11lab-local-provider:consumer-parent \
  --iidfile consumer-id consumer-context
```

The compiler runs against the pinned Debian ABI; its dependency inventory and
consumer/header licenses are retained. The final derivative contains the C
application, its sources and notices; build tools remain in the builder stage.
The provider is not recompiled. Caller supplied derivatives and upstream package
contents need their own distribution review before publication.

Create private PIN and SO PIN files with no trailing newline for compatibility
with applications that read raw file bytes. The adapter also accepts one optional
final LF, but individual applications may differ. Run from your own
application working directory, with a new output directory:

```sh
p11lab run softhsm2 --channel release --artifact "$(cat consumer-id)" \
  --input "P11LAB_PIN_FILE=$PWD/pin" --input "P11LAB_SO_PIN_FILE=$PWD/so-pin" \
  --output-dir smoke-run -- \
  p11lab-smoke --module /usr/local/lib/p11lab/libsofthsm2.so \
  --token-label P11Lab --pin-file /run/p11lab-input/P11LAB_PIN_FILE \
  --output /p11lab-output/crypto --key-mode generated
```

Copy the installed public verifier beside the exported artifacts:

```sh
python3 -c 'from p11lab.catalog import package_data; from pathlib import Path; Path("verify.py").write_bytes(package_data("consumer/verify.py").read_bytes())'
```

Use a separately pinned application image containing Python and OpenSSL as the
oracle, recording its exact inspected image identity and OpenSSL version. It needs
only the public crypto directory and verifier, never provider token state or PINs:

```sh
# ORACLE_ID is your verified immutable local engine image ID, not a mutable tag.
docker run --rm --network none --read-only --cap-drop ALL --tmpfs /tmp \
  --user "$(id -u):$(id -g)" \
  --mount "type=bind,src=$PWD/smoke-run/crypto,dst=/crypto,readonly" \
  --mount "type=bind,src=$PWD/verify.py,dst=/verify.py,readonly" \
  "$ORACLE_ID" python3 /verify.py /crypto
```

Require both the run's zero exit and the separate verifier's zero exit. The C
application performs P256 key generation and `CKM_ECDSA` signing of a SHA256 digest
in one process. The verifier independently accepts the exported signature with
OpenSSL and rejects an altered message. Generated session keys are destroyed;
for a separately provisioned persistent token key, use `--state-dir`,
`--key-mode existing --key-id HEX`. Retain an application profile containing the
exact `key_id_hex`, `key_mode`, `public_key_source` from `result.json`, provider
derivative identity, mechanism and independent oracle identity alongside the
receipt. Key IDs are explicit public provisioning metadata, never PIN hashes. See the
[consumer contract](../../src/p11lab/data/consumer/README.md) and
[runtime contract](../../docs/runtime-contract.md) for supported behavior and
limits. A passing application smoke is not provider-wide qualification.
