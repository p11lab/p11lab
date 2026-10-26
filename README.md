# P11Lab

Reusable PKCS#11 provider environments for application development and testing.

P11Lab ships a catalogue of 24 locked provider candidates with pinned
sources, build recipes, and lifecycle adapters, plus the `p11lab` command
for local use: `list`, `describe`, `validate`, `resolve`, `build`,
`install`, `run` (`direct`, `proxy`, and `native` modes), and source-first
delivery gates (`publish`). Providers run containerized runtimes, native
bundles (Debian 13 amd64, Windows x64 for BouncyHSM), and pinned-mTLS
proxy lanes; the installed checker and independent consumers exercise the
same artifacts. Fifteen providers carry full cohort documentation in
[docs/developer-release-cohort.md](docs/developer-release-cohort.md); the
rest are described by their catalogue entries. Five release runtimes
(haskoki, kryoptic, freehsm, bouncyhsm, softhsm2) are published as alpha
images under per-provider repositories `ghcr.io/p11lab/<environment>`
(see [delivery](docs/delivery.md)); digests are the identities and tags are
mutable aliases. Every other candidate's distribution stays blocked or
unreviewed pending admission.

Start with the [provider application execution](docs/runtime-contract.md)
contract, then the [native](docs/native.md), [proxy](docs/proxy.md),
[Windows](docs/windows.md), [delivery](docs/delivery.md),
[licensing](docs/licensing.md), and
[adding providers](docs/adding-providers.md) guides. `examples/` holds
runnable consumers, including the optional p11-kit and p11scope
demonstrations.

See the [integration validation status](docs/integration-validation-status.md)
for current evidence, open review proposals, runtime limits, and remaining work.

## License

Unless stated otherwise, P11Lab-authored code, build recipes, configuration, and
documentation are licensed under [Apache-2.0](LICENSE).

Target PKCS#11 providers, dependencies, datasets, copied material, and
upstream-derived patches retain their applicable licenses. The P11Lab license
does not replace their terms or by itself authorize distribution of an image.
