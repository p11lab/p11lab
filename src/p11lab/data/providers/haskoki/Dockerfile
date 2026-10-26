# SPDX-License-Identifier: Apache-2.0
# Haskoki Linux runtime: source-built libhaskoki.so (GHC 9.10.3, real-crypto
# OpenSSL4 engine over pinned OpenSSL 4.0.2: static libcrypto plus the shipped
# legacy provider module) with its bundled GHC closure, the provider-native
# haskoki-ctl init/health tool, and a minimal
# P11Lab provisioning opener. System libgmp comes from the base image;
# libffi.so.8 is vendored from a pinned snapshot .deb with an ld.so.conf
# entry. No checker, consumer tooling, compiler, Haskell toolchain, or SDK
# ships.
ARG BASE_IMAGE=docker.io/library/debian@sha256:7792b1f7702a86946cd518db72b6a407302c3e9bc1635634368b878189e8221c
FROM ${BASE_IMAGE} AS builder
COPY snapshot.sources /etc/apt/sources.list.d/p11lab.sources
COPY builder-requested.txt /tmp/builder-requested.txt
COPY base-packages.tsv builder-packages.tsv /tmp/
RUN rm -f /etc/apt/sources.list /etc/apt/sources.list.d/debian.sources \
 && dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n' | sort > /tmp/actual-base.tsv \
 && diff -u /tmp/base-packages.tsv /tmp/actual-base.tsv \
 && apt-get -o APT::Update::Error-Mode=any update \
 && xargs apt-get install -y --no-install-recommends < /tmp/builder-requested.txt \
 && dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n' | sort > /tmp/actual-builder.tsv \
 && diff -u /tmp/builder-packages.tsv /tmp/actual-builder.tsv
# Pinned GHC 9.10.3 + cabal-install 3.12.1.0 bindists, verified before use
# (build-only; the trixie snapshot ships only GHC 9.6, which cannot compile
# this source).
COPY toolchain-manifest.txt /tmp/toolchain-manifest.txt
RUN grep -v '^#' /tmp/toolchain-manifest.txt | grep -Eq '^(HASKOKI_(GHC|CABAL)_(URL|SHA256|SIZE))=[^ ]+$' \
 && [ "$(grep -v '^#' /tmp/toolchain-manifest.txt | grep -c .)" = 6 ] \
 && . /tmp/toolchain-manifest.txt \
 && curl -fsSL --retry 3 --retry-all-errors -o /tmp/ghc.tar.xz "$HASKOKI_GHC_URL" \
 && echo "$HASKOKI_GHC_SHA256  /tmp/ghc.tar.xz" | sha256sum -c - \
 && [ "$(stat -c %s /tmp/ghc.tar.xz)" = "$HASKOKI_GHC_SIZE" ] \
 && curl -fsSL --retry 3 --retry-all-errors -o /tmp/cabal.tar.xz "$HASKOKI_CABAL_URL" \
 && echo "$HASKOKI_CABAL_SHA256  /tmp/cabal.tar.xz" | sha256sum -c - \
 && [ "$(stat -c %s /tmp/cabal.tar.xz)" = "$HASKOKI_CABAL_SIZE" ] \
 && mkdir -p /tmp/ghc /tmp/cabalx \
 && tar -xJf /tmp/ghc.tar.xz -C /tmp/ghc \
 && (cd /tmp/ghc/ghc-9.10.3-x86_64-unknown-linux && ./configure --prefix=/opt/ghc-9.10.3 && make install) \
 && tar -xJf /tmp/cabal.tar.xz -C /tmp/cabalx \
 && cp /tmp/cabalx/cabal /usr/local/bin/cabal && chmod 755 /usr/local/bin/cabal \
 && rm -rf /tmp/ghc /tmp/cabalx /tmp/ghc.tar.xz /tmp/cabal.tar.xz
ENV PATH=/opt/ghc-9.10.3/bin:/usr/local/bin:/usr/bin:/bin
RUN ghc --numeric-version | grep -qx '9\.10\.3' && cabal --numeric-version | grep -qx '3\.12\.1\.0'
# Pinned OpenSSL 4.0.2 (upstream configure flags): static libcrypto linked into
# the module plus the legacy provider module shipped beside it (upstream loads
# "legacy" at open and fails closed when it is absent; the module-local
# ossl-modules anchor dir keeps the baked /opt MODULESDIR out of the runtime).
COPY openssl-manifest.txt /tmp/openssl-manifest.txt
RUN grep -v '^#' /tmp/openssl-manifest.txt | grep -Eq '^(OPENSSL_(VERSION|URL|SHA256|SIZE))=[^ ]+$' \
 && [ "$(grep -v '^#' /tmp/openssl-manifest.txt | grep -c .)" = 4 ] \
 && . /tmp/openssl-manifest.txt \
 && [ "$OPENSSL_VERSION" = 4.0.2 ] \
 && curl -fsSL --retry 3 --retry-all-errors -o /tmp/openssl.tar.gz "$OPENSSL_URL" \
 && echo "$OPENSSL_SHA256  /tmp/openssl.tar.gz" | sha256sum -c - \
 && [ "$(stat -c %s /tmp/openssl.tar.gz)" = "$OPENSSL_SIZE" ] \
 && mkdir -p /tmp/ossl && tar -xzf /tmp/openssl.tar.gz -C /tmp/ossl \
 && (cd /tmp/ossl/openssl-4.0.2 \
     && perl ./Configure --prefix=/opt/openssl-4.0.2 --openssldir=/opt/openssl-4.0.2/ssl \
        --libdir=lib no-docs no-tests threads no-shared no-pinshared linux-x86_64 \
     && make -j2 && make install_sw) \
 && rm -rf /tmp/ossl /tmp/openssl.tar.gz \
 && /opt/openssl-4.0.2/bin/openssl version | grep -qx 'OpenSSL 4\.0\.2 .*'
COPY source.tar /tmp/source.tar
COPY source.sha256 /tmp/source.sha256
RUN cd /tmp && sha256sum -c source.sha256 && mkdir -p /build/haskoki && tar -xf source.tar -C /build/haskoki
# Pinned libffi8 runtime library, verified and extracted (vendored into the
# provider directory with an ld.so.conf entry; see the runtime stage).
COPY libffi-manifest.txt /tmp/libffi-manifest.txt
RUN grep -v '^#' /tmp/libffi-manifest.txt | grep -Eq '^(LIBFFI_(URL|SHA256|SIZE))=[^ ]+$' \
 && [ "$(grep -v '^#' /tmp/libffi-manifest.txt | grep -c .)" = 3 ] \
 && . /tmp/libffi-manifest.txt \
 && curl -fsSL --retry 3 --retry-all-errors -o /tmp/libffi8.deb "$LIBFFI_URL" \
 && echo "$LIBFFI_SHA256  /tmp/libffi8.deb" | sha256sum -c - \
 && [ "$(stat -c %s /tmp/libffi8.deb)" = "$LIBFFI_SIZE" ] \
 && mkdir -p /tmp/libffi && dpkg-deb -x /tmp/libffi8.deb /tmp/libffi \
 && ls /tmp/libffi/usr/lib/x86_64-linux-gnu/libffi.so.8* \
 && test -f /tmp/libffi/usr/share/doc/libffi8/copyright \
 && rm /tmp/libffi8.deb
# Haskell build: only the shipped components. Resolution is pinned by the
# frozen index-state inside cabal.project.freeze (asserted below); every
# dependency besides the two Hackage sdists below resolves to GHC boot
# libraries from the pinned bindist.
COPY hackage-manifest.txt /tmp/hackage-manifest.txt
RUN grep -v '^#' /tmp/hackage-manifest.txt | grep -Eq '^((HACKAGE_INDEX_STATE)|(DIRECT_SQLITE|HSC2HS)_(URL|SHA256|SIZE))=[^ ]+$' \
 && [ "$(grep -v '^#' /tmp/hackage-manifest.txt | grep -c .)" = 7 ] \
 && . /tmp/hackage-manifest.txt \
 && grep -qx "index-state: hackage.haskell.org $HACKAGE_INDEX_STATE" /build/haskoki/cabal.project.freeze \
 && cd /build/haskoki && cabal update \
 && cabal build flib:haskoki exe:haskoki-ctl -j2 --ghc-options=-j2 \
 && SO_LIST=$(find /build/haskoki/dist-newstyle -name 'libhaskoki*.so' | sort) \
 && [ "$(printf '%s\n' "$SO_LIST" | grep -c .)" = 1 ] \
 && CTL=$(find /build/haskoki/dist-newstyle -path '*haskoki-ctl/haskoki-ctl' -type f | sort | head -1) \
 && [ -n "$CTL" ] && [ -x "$CTL" ] \
 && printf '%s\n' "$SO_LIST" > /tmp/so-path && printf '%s\n' "$CTL" > /tmp/ctl-path \
 && echo "module under test: $SO_LIST" && echo "ctl binary: $CTL"
# Seal the Hackage fetch set: exactly the two manifested sdists, byte-exact.
RUN . /tmp/hackage-manifest.txt \
 && actual=$(find /root/.cache/cabal/packages -name '*.tar.gz' ! -name '01-index*' | sort) \
 && [ "$(printf '%s\n' "$actual" | grep -c .)" = 2 ] \
 && ds_path=$(find /root/.cache/cabal/packages -name 'direct-sqlite-2.3.29.tar.gz') \
 && hs_path=$(find /root/.cache/cabal/packages -name 'hsc2hs-0.68.10.tar.gz') \
 && printf '%s  %s\n%s  %s\n' "$DIRECT_SQLITE_SHA256" "$ds_path" "$HSC2HS_SHA256" "$hs_path" | sha256sum -c - \
 && [ "$(stat -c %s "$ds_path")" = "$DIRECT_SQLITE_SIZE" ] \
 && [ "$(stat -c %s "$hs_path")" = "$HSC2HS_SIZE" ] \
 && printf '%s\n' "$ds_path" > /tmp/ds-path && printf '%s\n' "$hs_path" > /tmp/hs-path \
 && sha256sum "$ds_path" "$hs_path" | tee /tmp/hackage-observed.sha256
COPY provision.c /tmp/provision.c
RUN cc -std=c11 -O2 -Wall -Wextra -Werror -I/build/haskoki/spec/vendor -o /tmp/haskoki-provision /tmp/provision.c -ldl \
 && test -x /tmp/haskoki-provision
COPY FILE-NOTICES.txt /tmp/FILE-NOTICES.txt
COPY signed-index-inputs.sha256 /tmp/signed-index-inputs.sha256
RUN cd /var/lib/apt/lists && sha256sum -c /tmp/signed-index-inputs.sha256
RUN set -eu; SO=$(cat /tmp/so-path); CTL=$(cat /tmp/ctl-path); \
 mkdir -p /runtime/usr/local/lib/p11lab /runtime/usr/local/bin /runtime/etc/ld.so.conf.d /runtime/usr/share/p11lab/build /runtime/usr/share/licenses/haskoki; \
 cp "$SO" /runtime/usr/local/lib/p11lab/libhaskoki.so; \
 cp "$CTL" /runtime/usr/local/bin/haskoki-ctl; \
 cp /tmp/haskoki-provision /runtime/usr/local/bin/haskoki-provision; \
 mkdir -p /runtime/usr/local/lib/p11lab/ossl-modules; \
 test -f /opt/openssl-4.0.2/lib/ossl-modules/legacy.so; \
 cp /opt/openssl-4.0.2/lib/ossl-modules/legacy.so /runtime/usr/local/lib/p11lab/ossl-modules/legacy.so; \
 sha256sum /runtime/usr/local/lib/p11lab/ossl-modules/legacy.so > /runtime/usr/share/p11lab/build/openssl-modules.sha256; \
 cp -P /tmp/libffi/usr/lib/x86_64-linux-gnu/libffi.so.8* /runtime/usr/local/lib/p11lab/; \
 printf '%s\n' /usr/local/lib/p11lab > /runtime/etc/ld.so.conf.d/p11lab-haskoki.conf; \
 cp /tmp/libffi/usr/share/doc/libffi8/copyright /runtime/usr/share/licenses/haskoki/libffi8-copyright; \
 . /tmp/libffi-manifest.txt; printf '%s\n' "libffi8_version=3.4.8-2" "libffi8_deb_sha256=$LIBFFI_SHA256" > /runtime/usr/share/p11lab/build/libffi.txt; \
 ldd "$SO" > /runtime/usr/share/p11lab/build/linked-dependencies.txt 2>&1; \
 if grep -q 'not found' /runtime/usr/share/p11lab/build/linked-dependencies.txt; then echo 'unresolved module closure'; exit 1; fi; \
 if grep -i -E 'libcrypto|libssl' /runtime/usr/share/p11lab/build/linked-dependencies.txt; then echo 'dynamic libcrypto in module closure (must be static pinned)'; exit 1; fi; \
 ldd "$SO" | awk '/libHS.*=>/ {print $3}' | sort -u | while read -r lib; do cp "$lib" /runtime/usr/local/lib/p11lab/; done; \
 bundled=$(ls /runtime/usr/local/lib/p11lab/libHS*.so | wc -l); \
 [ "$bundled" = 24 ] || { echo "bundled GHC closure count drift: $bundled"; exit 1; }; \
 ldd "$SO" | awk '{print $1}' | grep '\.so' | grep -v '^libHS' | sort -u > /runtime/usr/share/p11lab/build/host-deps.txt; \
 if grep -v -E '^(/lib64/ld-linux-x86-64\.so\.2|libc\.so|libffi\.so|libgmp\.so|libm\.so|linux-vdso)' /runtime/usr/share/p11lab/build/host-deps.txt | grep -q .; then echo 'unexpected host dep outside {ld-linux,libc,libffi,libgmp,libm,vdso}'; exit 1; fi; \
 for f in /runtime/usr/local/lib/p11lab/*.so /runtime/usr/local/lib/p11lab/ossl-modules/*.so /runtime/usr/local/bin/haskoki-ctl; do objdump -T "$f" 2>/dev/null | grep -o 'GLIBC_[0-9.]*'; done | sort -uV > /runtime/usr/share/p11lab/build/glibc-refs.txt; \
 floor=$(tail -1 /runtime/usr/share/p11lab/build/glibc-refs.txt); \
 [ "$floor" = GLIBC_2.38 ] || { echo "glibc floor drift: $floor"; exit 1; }; \
 printf '%s\n' "$floor" > /runtime/usr/share/p11lab/build/glibc-floor.txt; \
 cp /build/haskoki/LICENSE /runtime/usr/share/licenses/haskoki/haskoki-LICENSE; \
 ds_path=$(cat /tmp/ds-path); hs_path=$(cat /tmp/hs-path); \
 tar -xzOf "$ds_path" direct-sqlite-2.3.29/LICENSE > /runtime/usr/share/licenses/haskoki/direct-sqlite-LICENSE; \
 tar -xzOf "$hs_path" hsc2hs-0.68.10/LICENSE > /runtime/usr/share/licenses/haskoki/hsc2hs-LICENSE; \
 cp /tmp/FILE-NOTICES.txt /runtime/usr/share/licenses/haskoki/FILE-NOTICES.txt; \
 cp /tmp/actual-base.tsv /tmp/actual-builder.tsv /runtime/usr/share/p11lab/build/; \
 cp /tmp/hackage-observed.sha256 /runtime/usr/share/p11lab/build/; \
 cp /tmp/toolchain-manifest.txt /tmp/openssl-manifest.txt /tmp/hackage-manifest.txt /tmp/libffi-manifest.txt /runtime/usr/share/p11lab/build/; \
 (cd /build/haskoki && sha256sum cabal.project cabal.project.freeze haskoki.cabal toolchain.lock) > /runtime/usr/share/p11lab/build/cabal-inputs.sha256; \
 CABAL_VER=$(sed -n -E 's/^version:[[:space:]]+([^[:space:]]+)[[:space:]]*$/\1/p' /build/haskoki/haskoki.cabal); \
 [ -n "$CABAL_VER" ] || { echo 'haskoki.cabal: version field missing'; exit 1; }; \
 [ "$(printf '%s\n' "$CABAL_VER" | grep -c .)" = 1 ] || { echo 'haskoki.cabal: ambiguous version field'; exit 1; }; \
 printf '%s\n' "$CABAL_VER" | grep -qx '[0-9][0-9.]*' || { echo "haskoki.cabal: unexpected version format: $CABAL_VER"; exit 1; }; \
 printf '%s\n' "$CABAL_VER" > /runtime/usr/share/p11lab/build/haskoki-version.txt; \
 cp /build/haskoki/dist-newstyle/cache/plan.json /runtime/usr/share/p11lab/build/cabal-plan.json; \
 { echo "ghc $(ghc --numeric-version)"; echo "cabal $(cabal --numeric-version)"; gcc --version | head -1; perl -v | sed -n '2p'; /opt/openssl-4.0.2/bin/openssl version; } > /runtime/usr/share/p11lab/build/toolchain.txt; \
 printf '%s\n' 'openssl_prefix=/opt/openssl-4.0.2' 'openssl_configure=--prefix=/opt/openssl-4.0.2 --openssldir=/opt/openssl-4.0.2/ssl --libdir=lib no-docs no-tests threads no-shared no-pinshared linux-x86_64' 'cabal_targets=flib:haskoki exe:haskoki-ctl' 'cabal_jobs=2' 'bundled_libhs_count=24' > /runtime/usr/share/p11lab/build/haskoki.txt; \
 readelf -d /runtime/usr/local/lib/p11lab/libhaskoki.so > /runtime/usr/share/p11lab/build/module-dynamic.txt; \
 ldd /runtime/usr/local/bin/haskoki-ctl /runtime/usr/local/bin/haskoki-provision > /runtime/usr/share/p11lab/build/tools-linked-dependencies.txt; \
 (cd /var/lib/apt/lists && sha256sum *InRelease *Packages.lz4 *Sources.lz4) > /runtime/usr/share/p11lab/build/actual-signed-indexes.sha256
FROM ${BASE_IMAGE} AS runtime
COPY --from=builder /runtime/ /
COPY entrypoint.sh /usr/local/bin/p11lab-provider
COPY THIRD-PARTY-NOTICES.txt SOURCE-ACCESS.md /usr/share/p11lab/
COPY common.sh LICENSE provider.json runtime-id build-inputs.json /usr/share/p11lab/
RUN chmod 755 /usr/local/bin/p11lab-provider /usr/local/bin/haskoki-ctl /usr/local/bin/haskoki-provision \
 && find /usr/share/p11lab /usr/share/licenses -type f -exec chmod 644 {} + \
 && chmod 644 /etc/ld.so.conf.d/p11lab-haskoki.conf \
 && chmod 755 /usr/local/lib/p11lab/*.so /usr/local/lib/p11lab/ossl-modules /usr/local/lib/p11lab/ossl-modules/*.so /etc/ld.so.conf.d \
 && mkdir -p /var/lib/p11lab /run/p11lab \
 && dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n' | sort > /usr/share/p11lab/build/actual-runtime.tsv \
 && diff -u /usr/share/p11lab/build/actual-base.tsv /usr/share/p11lab/build/actual-runtime.tsv \
 && ldconfig \
 && ldd /usr/local/lib/p11lab/libhaskoki.so > /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && ! grep -q 'not found' /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && ! grep -i -E 'libcrypto|libssl' /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && if ldd /usr/local/lib/p11lab/libhaskoki.so | grep 'libHS.*=>' | grep -v '/usr/local/lib/p11lab/' | grep -q .; then echo 'bundled lib resolved outside the provider directory'; exit 1; fi \
 && ldconfig -p | grep -q 'libffi.so.8.*=> /usr/local/lib/p11lab/' \
 && EXPECTED_VER=$(cat /usr/share/p11lab/build/haskoki-version.txt) \
 && printf '%s\n' "$EXPECTED_VER" | grep -qx '[0-9][0-9.]*' \
 && ACTUAL_VER=$(haskoki-ctl --version) \
 && [ "$ACTUAL_VER" = "haskoki-ctl $EXPECTED_VER" ] \
 && test -f /usr/local/lib/p11lab/ossl-modules/legacy.so \
 && mkdir -p /tmp/smoke/haskoki \
 && printf '%s\n' 'schema_version = 1' 'profile = "real-crypto"' '' '[storage]' 'kind = "sqlite"' 'path = "/tmp/smoke/haskoki/token.sqlite"' '' '[engine]' 'kind = "openssl"' '' '[trace]' 'enabled = false' > /tmp/smoke/haskoki/haskoki.toml \
 && export HASKOKI_CONFIG=/tmp/smoke/haskoki/haskoki.toml \
 && haskoki-ctl config check --config "$HASKOKI_CONFIG" | grep -q '^config-ok: profile=ProfileRealCrypto' \
 && /usr/local/bin/haskoki-provision /usr/local/lib/p11lab/libhaskoki.so | grep -q '^provision: OK' \
 && haskoki-ctl store inspect --path /tmp/smoke/haskoki/token.sqlite | grep -q '^tokens: 1$' \
 && /usr/local/bin/haskoki-provision /usr/local/lib/p11lab/libhaskoki.so | grep -q '^provision: OK' \
 && rm -rf /tmp/smoke
ENTRYPOINT ["/usr/local/bin/p11lab-provider"]
CMD ["describe"]
