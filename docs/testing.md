# Testing levels

## Bounded Linux validation

`linux-unit-validation.yml` runs on pull requests and manual dispatch. It has
one `ubuntu-24.04` job with a ten-minute ceiling, read-only repository
permissions, and no persisted checkout credentials. It does not build provider
images, start live providers, publish artifacts, export caches, or change the
delivery and Windows workflows.

The job runs the **full pytest collection** without selection filters or
failure suppression. This includes source contracts, lifecycle behavior,
installed-wheel checks, and real checker planning/merge/adaptation tests.
Python 3.12.14, uv 0.12.23, pytest 9.1.1, and the Linux Python dependency closure
are version-pinned. The checker is installed from the immutable source revision
in `src/p11lab/data/tools.json` and must identify as version 0.2.3. Its installed
source URL and commit are verified before testing; absence is an error rather
than a reason to omit checker tests.

`.github/requirements/linux-unit.txt` pins both runtime test dependencies and
build-backend dependencies. The direct installations use no dependency
resolution and no build isolation. Installed-wheel fixtures still exercise
their normal isolated builds, with `UV_BUILD_CONSTRAINT` applying the same pins
to those builds. `uv pip check` validates the installed dependency requirements.
Package versions are pinned, not package archive hashes; the hosted runner's
OS and system-tool updates are not frozen by `ubuntu-24.04`.

Third-party pytest plugin autoload is disabled so unrelated installed plugins
cannot change collection. The checker and its dependencies remain installed,
and the checker tests run normally. The job prints the installed versions and
checker provenance, pytest prints all skip reasons, and the job summary records
test/failure/error/skip totals plus every distinct skip reason. Test failures
fail the job. A missing or unreadable test report is not evidence of a pass.

The workflow changes no provider, checker, dataset, image, or publication
eligibility. Installing the pinned checker for private CI execution is not an
assertion of distribution-license clearance.

## Live-provider and platform evidence

The live-provider integration tests keep their existing explicit image,
client, checker, and caller input gates. The bounded workflow does not supply
these inputs, so those tests are collected but skipped, visibly. These skips
mean runtime evidence is absent. A green bounded check is **not provider runtime
qualification**, Windows compatibility, a successful provider rebuild, or
publication approval.

Full runtime evidence requires separate, explicitly provisioned runs with the
locked provider/tool inputs and retained receipts described in
[runtime-contract.md](runtime-contract.md), [proxy.md](proxy.md),
[native.md](native.md), and [delivery.md](delivery.md). The existing Windows
native workflow may also be triggered by its own path rules on other changes;
this bounded workflow does not replace or relax those rules. Resource-intensive
provider matrices, publication, releases, and cache exports remain separate
operations.

## Local reproduction

When editing this workflow, run `actionlint` 1.7.12 against
`.github/workflows/linux-unit-validation.yml` as well as the pytest contract
tests. YAML parsing alone does not validate GitHub's expression-context rules.

Use Python 3.12.14 and an isolated virtual environment. The workflow's install
steps are the authoritative commands: install uv 0.12.23, install the pinned
requirements without dependency resolution, then install P11Lab and the checker
at the revision in `tools.json` without dependency resolution or build
isolation. Verify the checker provenance and run:

```sh
export PYTEST_DISABLE_PLUGIN_AUTOLOAD=1
export UV_PYTHON=3.12.14
export UV_PYTHON_DOWNLOADS=never
export UV_BUILD_CONSTRAINT="$PWD/.github/requirements/linux-unit.txt"
python -m pytest -ra
```

Keep uv on `PATH` and use a writable uv cache. Sandboxed hosts may forbid local
Unix sockets or process operations that an ordinary Linux runner permits.
Report these failures explicitly; do not skip or reinterpret them as passes.
