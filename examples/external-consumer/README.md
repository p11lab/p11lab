# External consumer (handoff only)

Run a P11Lab provider from a published handoff without a source checkout,
development mounts, or reference workspaces. Everything the consumer touches
is hash-pinned: the handoff digest, the wheel digest recorded in the handoff,
and the ORAS pin compiled into the installed package.

Two lanes:

- `run-container.sh` — pull the runtime image by digest (anonymous), build
  the C consumer derivative from the installed package, run the smoke
  application with real crypto plus the OpenSSL oracle, then a deliberate
  wrong-PIN failure proving failure preservation. Needs Docker, python3
  with venv, openssl.
- `run-native.sh` — pull the native bundle by digest with ORAS
  (anonymous), install it, build the caller smoke tool from the installed
  package, run the application plus the oracle, optionally run the checker
  at its pinned revision (`--checker`), then the wrong-PIN failure. Refuses
  to run when Docker is present: native acquisition and installation need
  none. Debian 13 amd64 with python3 (venv), gcc with libc headers, openssl,
  tar, and ca-certificates is required; `--checker` additionally needs git
  and network access to the pinned checker revision.

`consumer-app.py` is the caller-owned application wrapper (reads the
runner-provided module/output locations from the environment);
`checker-driver.py` is the optional checker lane (public checker CLI with
the frozen smoke profile and the controlled checker environment).

Checkout-less consumers fetch these example scripts from the P11Lab
source revision matching the handoff's producer wheel (each release
records the wheel-to-revision mapping), the same revision that
supplies `prepare-consumer.py` below.

## Handoff bundle layout

The proof bundle is a directory with:

- `handoff.json` — digest bindings plus the admission verdict.
- `sha256sum.txt` — digests of every other bundle file (the handoff never
  embeds its own digest; this file is the external record).
- `p11lab-*.whl` — the producer wheel; its digest must equal the
  `producer.p11lab_wheel_sha256` recorded in the handoff.
- `oras_1.3.4_linux_amd64.tar.gz` — the pinned upstream ORAS release
  tarball, byte-identical to the release artifact; verified against the
  pin in the installed package, roster-checked, and unpacked before use.
- `prepare-consumer.py` (container lane) — hash-pinned copy of the
  derivative preparation script (see the production note below).

## Quickstart (local proof)

```sh
run-container.sh --bundle-dir /path/to/bundle --work-dir /path/to/fresh-work --local-proof
run-native.sh --bundle-dir /path/to/native-bundle --work-dir /path/to/fresh-work --local-proof --checker
```

Both scripts refuse a non-eligible handoff unless `--local-proof`
explicitly acknowledges the blocked verdict and prints its blockers. A
blocked verdict means the binary must not be treated as a release; the
local proof exercises the mechanics only. Prefer PIN files over scalar
`--input P11LAB_PIN=...` values: scalar secrets stay visible to the host
caller through `docker inspect`.

## Production bootstrap

Once handoffs are published, replace the bundle files with their published
equivalents and drop `--local-proof`:

- Install the released p11lab wheel by pinned hash (`pip install` from the
  published index), instead of the bundled wheel file.
- Fetch ORAS with `install-oras.sh` from the installed package
  (`python -c 'from p11lab.catalog import package_data; ...'` for
  `data/delivery/install-oras.sh`), instead of the bundled binary.
- Fetch `handoff.json` by digest with ORAS from `ghcr.io/p11lab/<environment>`,
  instead of the bundled copy.
- Fetch `prepare-consumer.py` from the P11Lab source revision matching the
  handoff's producer wheel (each release records the wheel-to-revision
  mapping), instead of the bundled copy.

Windows consumers use the same handoff contract through the reusable action;
see `docs/delivery.md` and `.github/workflows/clean-consumer-windows.yml`.
