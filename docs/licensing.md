# Source companions and distribution evidence

Every distributed artifact has its own inventory and admission record. The
P11Lab Apache-2.0 license covers original P11Lab material; it does not relicense
providers, Debian packages, copied headers, datasets or optional integrations.
Runtime, native, debug, checker, proxy, source and cache outputs have separate
boundaries. A provider's top-level license is insufficient for an entire image.

The supported operations are also callable from an installed wheel, with no
repository mounts:

```sh
python -m p11lab.licenses inspect --artifact artifact.json --output-dir observation
python -m p11lab.licenses collect --artifact artifact.json --inventory inventory.json --output-dir sources
python -m p11lab.licenses verify --archive sources/source-companion.tar.gz --output-dir extracted
python -m p11lab.licenses assess --artifact artifact.json --output-dir sources
```

`artifact.json` is an `ArtifactRef` or a build receipt containing one. Collection
uses `collect_source_bundle(artifact, inventory, output_dir) -> Path`; assessment
uses `assess_distribution(artifact, evidence_dir) -> dict`. Output directories
for inspection, collection and verification must be new. Failed attempts remain
available for diagnosis. These operations neither publish nor change visibility.
`assess` exits 2 on a blocked assessment, the same code usage errors use.
The optional packaged `data/runtime/source-companion.Dockerfile` wraps the
collected `files/` directory in a scratch, source-only OCI image. Its immutable
identity must be verified separately; the source archive receipt does not admit a
subsequently generated OCI object automatically.

Image inspection creates a stopped container, exports its inert filesystem and
removes that exact container. It inventories installed dpkg Source, Built-Using
and Static-Built-Using fields, per-file dpkg md5sums verification, every
regular-file hash and ELF DT_NEEDED relationship from PT_DYNAMIC program headers
for the supported Linux amd64 ELF ABI. The dynamic segment's file offset must
agree with its virtual address mapping through PT_LOAD. It also inspects distributed
OCI layers: config diff_ids must match the complete ordered layer roster and
uncompressed hashes, and OCI descriptor digests/sizes must match the exported
graph, and the claimed engine root must reach the selected config and layers.
Measured distribution archive bytes accompany blob and file/layer metrics.
Deleted/overwritten lower-layer content needs explicit source review.
Engine-injected hosts/hostname/resolver files are replaced with their actual
underlying distributed bytes. Library candidates are recorded from the rootfs;
this is not an assertion of runtime loader search order or plugin configuration.
Images with unsupported ELF formats, missing libraries or unmapped copied binaries
fail closed. Build-only packages are provenance unless a shipped artifact contains
them; exporting a builder or cache creates a new distribution boundary.

An inventory has schema version 1 and these required fields:

| Field | Contract |
| --- | --- |
| `artifact`, `role`, `observation` | Exact ArtifactRef, delivery role and complete result of `inspect_artifact`. |
| `sources` | Explicit `id: name=version`, `name`, `version`, ordered `payloads` paths. Debian records use `format: debian`; discovered installed/static Debian identities require complete Debian verification even if this field is omitted. |
| `payloads` | Portable relative `path`, SHA256, size, role (`source`, `notice`, `license`, `build`, `metadata`), plus optional acquisition `local_path` or public HTTPS `url`. |
| `components` | Component ID, owning source identity and scope. Copied ELF IDs are their absolute artifact paths. |
| `reviews` | One explicit reviewer assertion per source: status, known grant, source redistribution rights, original license expression, chosen route, concluded expression, retained grant/notice paths, obligations and modifications. |
| `patches` | Ordered `path`/`sha256`/`license`/`provenance`/`changed_behavior` and reviewed `status`; an empty list means no P11Lab patches. |
| `build_instructions` | Retained payload path with role `build`. |
| `content_reviews` | Exact path/SHA256/source/reviewed mapping for copied/generated files and explicit modified/unverifiable package-file reviews. `package_verification` records the installed MD5 comparison only; neither matching MD5 nor a reviewed checksum manifest authorizes an installed file. |
| `package_archives` | Authenticated Debian binary selectors: `package`, `version`, `architecture`, `source: name=version`, `sha256`, `size`, public HTTPS `url`, optional acquisition `local_path`, and `authentication: {status: reviewed, evidence_path: ...}`. The evidence path names a retained metadata JSON payload with the same selector fields. |
| `package_files` | Per-file `path`, `sha256`, `package`, `archive_sha256`, and canonical relative `member`. Collection and assessment rehash the binary archive, check its control identity, and verify the SHA256 of the named regular payload member. Member paths must resolve to the installed path through observed aliases. An unmatched file requires an explicit SHA256 content/source review. |
| `parent_artifact` | Required exact parent for debug companions; inspection reads inert parent exports and verifies exact runtime hashes, build IDs and GNU debuglink CRCs, without running parent code. |
| `layer_reviews` | Explicit path/hash/source/reviewed records for any distributed lower-layer bytes absent from the final rootfs. |
| `limitations` | Unresolved attribution precision and other evidence limits. |

`status: reviewed`, `grant_known: true`, and `source_redistribution: true` are
review conclusions supplied by a responsible reviewer, not inferred by the
collector. `grant_evidence` and `notices` contain payload paths to original grants.
Missing evidence, unknown rights, unresolved source dependencies, unreviewed
patches and mismatched bytes block collection or admission. Neither a regex match
nor an Apache root license supplies a grant. Debian `.dsc` identities and every
named SHA256/size payload are checked, including additional orig archives and
Debian patches. Source URLs without actual retained payloads never satisfy this
operation. Source archives are retained inertly; collection does not execute their
build hooks. Companion extraction permits regular files only, validates canonical
contained paths, rejects duplicates and verifies the complete SHA256SUMS roster.

Package selector authentication is an explicit review conclusion grounded in
retained authenticated repository metadata. The gate checks the selector, archive
bytes, control identity and individual member hashes; it does not infer repository
authentication from a URL or from an image's dpkg checksum files. MD5 collisions
cannot substitute for the SHA256 evidence. Debian archive inspection reads inert
ar/tar members and executes no package scripts. Supported tar compression is gzip,
xz or bzip2, plus uncompressed tar; unsupported formats fail closed.

The `package-cache/` directory beside a collected source archive contains only
binary verification inputs and is excluded from the source archive and `files/`
OCI wrapper context. Assessment rehashes cached archives every time; an absent
archive can be acquired using its public HTTPS selector. A corrupt retained cache
blocks assessment. Local acquisition paths are removed from the portable
inventory. Keep verification caches separate from source-only publication.

The archive drops private acquisition paths. It includes inventory.json,
SHA256SUMS, SPDX 2.3 JSON, notices, complete source families and usable build/install
instructions. The separate receipt binds binary, companion and SPDX hashes
without circular embedded hashes. Assessment re-inspects actual binary bytes and
verifies the companion in a new temporary directory, binds every receipt field to
measured/extracted metadata and requires identical outer/embedded SPDX bytes; an unrelated admitted digest
never authorizes a changed artifact. SPDX contains binary/source/static-link
relationships and actual file hashes. Mixed source-package and uncertain final
Rust vendor attribution may use `NOASSERTION` while retained exact source grants
remain reviewed. This differs from an unknown redistribution grant, which blocks.

The first SoftHSM inventory includes all inherited packages and sqv's declared
static source closure, not only the provider's ldd output. sqv/reader/OpenPGP/policy
select LGPLv3 where their grants permit; Nettle Rust wrappers select LGPL-3.0-only.
The exercised LGPLv3 4(d)(0) route retains complete application/library source and
Debian packaged-cargo rebuild/recombine directions, accommodating fat LTO.
Original grants and alternatives remain in the sources. Compatible native LGPL
shared libraries remain replaceable. GCC runtime exceptions and file-specific
SoftHSM, p11-kit header, Unicode, compiler_builtins LLVM and Rust attribution
notices are retained separately. Other-target/tool source licenses are preserved
without asserting they all govern the Linux sqv executable.

`eligible` means local evidence permits preparing this exact artifact for
redistribution. Its `publication_status` remains blocked until the release
workflow verifies anonymous, immutable source retrieval from the shared
`ghcr.io/p11lab/<environment>` repositories **before** exposing matching binaries through a
registry, public cache or CI artifact. Private uploads and authenticated readback
are insufficient. Publish source directions beside binary access and retain source
while the corresponding binary is available and for additional applicable duties.
Task 13 owns that delivery gate. GitHub prerelease fallback is not adopted.

Modified AGPL services additionally need `agpl-remote-source` in their reviewed
obligations and `agpl_remote_source_offer: {status: reviewed, evidence_path: ...}`
with retained operational offer evidence. Container boundaries do not supply an
exception to remote users' source rights. Binary source delivery and the service's
remote offer are separate obligations.
