# Try a published provider with Docker

These commands use the existing SoftHSM alpha runtime on a native Linux amd64
host with a local Docker daemon and ordinary shell/coreutils. No checkout,
Python, compiler, checker, GitHub account or provider build is needed. Internet
access is needed for the pull; subsequent commands use `--network none`.

The exact digest below matches the packaged [image policy](../src/p11lab/data/ci/images.json).
On 2026-10-28 an anonymous pull and this lifecycle sequence succeeded on Docker
29, Linux amd64, with default-root containers. Layers were cached, so a cold
layer download was not tested. These are narrow usability observations, not
provider certification or public-CI qualification. All seven alpha pins remain
ineligible for distribution/acquisition under that policy pending bound source,
actual-content licensing and handoff admission; registry availability alone does
not satisfy those gates. See [delivery](delivery.md).

## SoftHSM: pull, initialize and inspect

Run the blocks in the same shell. The temporary directory and uniquely named
volume belong to this demonstration. The PINs are public disposable examples;
do not reuse them for real tokens or enable shell tracing around credentials.
Files intentionally contain no newline, so applications that read raw PIN bytes
can use them too.

```sh
IMAGE=ghcr.io/p11lab/softhsm2@sha256:69cdeb9a74d13a3382547e184645ee18a7e9e2315246fd40ca814ef97b970d16
P11LAB_DEMO_DIR=$(mktemp -d "${TMPDIR:-/tmp}/p11lab-demo.XXXXXXXX")
VOLUME="p11lab-softhsm-$(basename "$P11LAB_DEMO_DIR")"
mkdir "$P11LAB_DEMO_DIR/docker-config" "$P11LAB_DEMO_DIR/secrets"
chmod 700 "$P11LAB_DEMO_DIR/secrets"
printf '1234' > "$P11LAB_DEMO_DIR/secrets/pin"
printf '12345678' > "$P11LAB_DEMO_DIR/secrets/so-pin"
chmod 600 "$P11LAB_DEMO_DIR/secrets/pin" "$P11LAB_DEMO_DIR/secrets/so-pin"
DOCKER_CONFIG="$P11LAB_DEMO_DIR/docker-config" docker pull --platform linux/amd64 "$IMAGE"
docker volume create "$VOLUME"

# No command defaults to describe: metadata, not token initialization.
docker run --rm --network none --platform linux/amd64 "$IMAGE"
docker run --rm --network none --platform linux/amd64 \
  --mount "type=volume,src=$VOLUME,dst=/var/lib/p11lab" \
  --mount "type=bind,src=$P11LAB_DEMO_DIR/secrets,dst=/run/demo-secrets,readonly" \
  -e P11LAB_PIN_FILE=/run/demo-secrets/pin \
  -e P11LAB_SO_PIN_FILE=/run/demo-secrets/so-pin "$IMAGE" init
docker run --rm --network none --platform linux/amd64 \
  --mount "type=volume,src=$VOLUME,dst=/var/lib/p11lab" "$IMAGE" health
docker run --rm --network none --platform linux/amd64 \
  --mount "type=volume,src=$VOLUME,dst=/var/lib/p11lab" "$IMAGE" exec -- \
  sh -c 'softhsm2-util --module "$P11LAB_MODULE" --show-slots'
```

Require each command to exit zero before continuing. The slot listing should
include an initialized token labeled `P11Lab`. Keep the single quotes around the
inner shell: the adapter exports `P11LAB_MODULE` inside the container; the host
shell must not expand it. `health` and `exec` require initialized state.

A compatible second initialization preserves the existing token and objects:

```sh
docker run --rm --network none --platform linux/amd64 \
  --mount "type=volume,src=$VOLUME,dst=/var/lib/p11lab" \
  --mount "type=bind,src=$P11LAB_DEMO_DIR/secrets,dst=/run/demo-secrets,readonly" \
  -e P11LAB_PIN_FILE=/run/demo-secrets/pin \
  -e P11LAB_SO_PIN_FILE=/run/demo-secrets/so-pin "$IMAGE" init
```

This checks the recorded non-secret configuration, not whether newly supplied
PINs authenticate to the existing token. It does not change its PINs or reset it.
Changed build identity or token label, unknown state, and partial nonempty state
are rejected. Inspect failures before proceeding; do not delete a persistent
store to make initialization succeed. Use an independently initialized volume
for each independent client or shard.

## Mount your own prebuilt application

The runtime is Debian 13 amd64, glibc 2.41. Its module is
`/usr/local/lib/p11lab/libsofthsm2.so`; the observed library closure includes
OpenSSL libcrypto3, libstdc++6, libgcc_s1, libz1, libzstd1, libm and glibc with its
ELF loader. Your executable must match Linux x86-64/glibc, have an available ELF
interpreter and all required shared libraries, and support loading this module.
An executable built for another libc, newer unavailable symbols or missing
libraries will not become compatible merely by mounting it. The image does not
include a compiler, Python or the checker.

Place your already-built executable and any compatible application dependency
closure in your own application directory. Set `APP_DIR` to its absolute host
path. The following is a template: replace `your-app` and its options with your
application's actual interface. It assumes that interface accepts module, token
label and PIN-file arguments; those option names are not a P11Lab API.

```sh
APP_DIR=/absolute/path/to/your/prebuilt-application
mkdir "$P11LAB_DEMO_DIR/output"
docker run --rm --network none --platform linux/amd64 \
  --mount "type=volume,src=$VOLUME,dst=/var/lib/p11lab" \
  --mount "type=bind,src=$APP_DIR,dst=/app,readonly" \
  --mount "type=bind,src=$P11LAB_DEMO_DIR/secrets,dst=/run/demo-secrets,readonly" \
  --mount "type=bind,src=$P11LAB_DEMO_DIR/output,dst=/output" "$IMAGE" exec -- \
  sh -c 'exec /app/your-app --module "$P11LAB_MODULE" --token-label P11Lab --pin-file /run/demo-secrets/pin --output /output'
```

Use your application's documented loader/library configuration for dependencies
in `/app`; mounting libraries alone does not configure the loader. The adapter
preserves a completed application's native exit status. Docker itself can fail
before the application starts. In the observed mounted-app experiment a
compatible existing ELF executable exited 0, generated an ECDSA signature that
independent OpenSSL verification accepted, and an altered-message check failed.
Removing its ELF interpreter produced Docker exit 255 and `no such file or
directory`, even though the executable existed. That is a loader failure, not a
provider finding. The experiment does not supply a public downloadable application
binary or promise compatibility for arbitrary binaries.

An optional thin application derivative can package your executable and its
libraries on top of this pinned runtime. That is application packaging; it does
not require rebuilding the provider. The [Linux smoke example](../examples/linux/README.md)
shows a separate application build, and the [runtime contract](runtime-contract.md)
describes installed CLI orchestration and receipts.

## State, permissions and cleanup

Plain Docker here uses the published default UID/GID `0:0`, a writable root
filesystem and Docker's default capabilities. It does not apply the installed
CLI's caller-UID, read-only-root or capability restrictions. Bind-mounted output
may be root-owned. Alternate UIDs, rootless Docker, SELinux bind labeling,
Windows/macOS hosts and other architectures/libcs were not tested by this probe.
Keep bind paths absolute and free of commas for Docker's `--mount` syntax.

Persistent token state is `/var/lib/p11lab/softhsm2/tokens` within the volume.
The adapter regenerates `/run/p11lab/softhsm2.conf` on each invocation and exports
its provider configuration to the application; `/run/p11lab` need not persist.
Containers are sequential and `--rm` removes them after exit. A shared Docker
network does not expose the native module remotely; remote applications need a
compatible proxy client and transport.

After all consumers exit, retain any wanted public application output, then
remove only this demonstration's volume and directory. These operations destroy
its disposable token and PIN files. Do not substitute an existing persistent
volume's name or use broad prune commands.

```sh
if docker volume rm "$VOLUME"; then
  unset VOLUME
else
  printf '%s\n' 'Volume cleanup failed; retain VOLUME and inspect before continuing.' >&2
  false
fi
```

Continue only after volume removal succeeds. Remove the owned directory
separately so a partial failure retains its exact path for inspection and retry:

```sh
if rm -r -- "$P11LAB_DEMO_DIR"; then
  unset IMAGE P11LAB_DEMO_DIR APP_DIR
else
  printf '%s\n' 'Directory cleanup failed; retain P11LAB_DEMO_DIR and inspect before retrying.' >&2
  false
fi
```

If the optional root-running application left directories the host cannot
remove, keep all consumers stopped and permit no concurrent output changes.
After saving wanted output, the following repair uses the same pinned runtime
and mounts only this demonstration's output. It changes directory ownership and
owner permissions so the caller can remove their contents; it does not traverse
symbolic links or change application files (including hard-linked files).
Use only the original owned path; refuse a symbolic-link output directory.

```sh
if [ -d "$P11LAB_DEMO_DIR/output" ] && [ ! -L "$P11LAB_DEMO_DIR/output" ]; then
  docker run --rm --pull never --network none --platform linux/amd64 \
    --user 0:0 --entrypoint sh \
    --mount "type=bind,src=$P11LAB_DEMO_DIR/output,dst=/output" "$IMAGE" \
    -c 'find -P /output -xdev -type d -exec chown -- "$1:$2" {} + -exec chmod u+rwx -- {} +' \
    sh "$(id -u)" "$(id -g)"
else
  printf '%s\n' 'Owned output is absent or a symbolic link; inspect without broad cleanup.' >&2
  false
fi
```

Require repair to exit zero, then retry only the directory-removal block. Keep
`P11LAB_DEMO_DIR` and `IMAGE` until that removal succeeds. If volume removal
failed instead, inspect that failure and retry only its block first. Never
replace these paths with the caller's working directory or an unowned path.

## Other alpha images

The policy records seven immutable pins with fresh anonymous manifest/config
readback on 2026-10-28. Only SoftHSM has the runtime observation above; the other
six have metadata evidence only, so no generic passing quickstart is claimed.
The table carries the published pins; separate evidence and eligibility fields with the machine-readable source stay in the
[shared policy](../src/p11lab/data/ci/images.json).

| Environment | Published pin | observation | caveat |
| --- | --- | --- | --- |
| softhsm2 | `ghcr.io/p11lab/softhsm2@sha256:69cdeb9a74d13a3382547e184645ee18a7e9e2315246fd40ca814ef97b970d16` | Narrow Docker lifecycle and mounted-app observation | Default-root Linux amd64/glibc only |
| kryoptic | `ghcr.io/p11lab/kryoptic@sha256:f7398f42e70141f2b321cfbd97f71ef5d7cf401c80ff26e2de9056a45bcb96c9` | Metadata only | Runtime quickstart unqualified |
| bouncyhsm | `ghcr.io/p11lab/bouncyhsm@sha256:809ab1985931c7356f53e3675d26632870c06aedaf961987e7e92b1c5496c08e` | Metadata only | Runtime quickstart unqualified |
| haskoki | `ghcr.io/p11lab/haskoki@sha256:dc7086e2b831f47223460d9ac3afd8cd8106deb9c135d4084d963cd0b7f84daa` | Metadata only | Runtime quickstart unqualified |
| freehsm | `ghcr.io/p11lab/freehsm@sha256:559127e1c3f73ded28f708518dd90d376951781863e4112a6185e1b646047197` | Metadata only | Current recipe uses upstream dev-mode TESTMODE; no FIPS claim |
| nss | `ghcr.io/p11lab/nss@sha256:42e6095ac865cf6c183c20fda489e3bbe5ac2c6522685f4db8a95adb56017e01` | Metadata only | Runtime quickstart unqualified |
| opencryptoki | `ghcr.io/p11lab/opencryptoki@sha256:b4bc9b9a3afc617bf6c956cac3c34fbcbaa391fdd6d386b1e53ec3bfbe65f924` | Metadata only | Needs provider-specific UID/GID, writable state and IPC setup |

Current FreeHSM recipe settings are `FHSM_INTEGRITY_ALLOW_UNSIGNED=1` and
`FHSM_KAT_ALLOW_FAIL=1` with `PROFILE=interop`, identifying the token model as
`FreeHSM-TESTMODE`. Current OpenCryptoki recipes select software SWToken only.
These are recipe disclosures, not proof that those recipes or their ordered
patch sets bind the historical published image bytes. Published patch,
modification and simulation provenance remains unresolved in the policy; do not
interpret unknown fields as an unmodified-provider guarantee. Licensing and
source-companion review must cover actual image contents, not only the provider.
