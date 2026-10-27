# SPDX-License-Identifier: Apache-2.0
# FreeHSM Linux runtime: source-built libfreehsm.so (PROFILE=interop) plus
# the provider-native fhsm-token init/health tool, running against the base
# image's system OpenSSL. No checker, consumer tooling, compiler, or SDK ships.
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
COPY source.tar /tmp/source.tar
COPY source.sha256 /tmp/source.sha256
RUN cd /tmp && sha256sum -c source.sha256 && mkdir -p /build/freehsm && tar -xf source.tar -C /build/freehsm
RUN cd /build/freehsm && make generate PROFILE=interop \
 && make -j2 OPENSSL_PREFIX=/usr PROFILE=interop libfreehsm.so tools/fhsm-token \
 && test -f libfreehsm.so && test -x tools/fhsm-token
COPY FILE-NOTICES.txt /tmp/FILE-NOTICES.txt
COPY signed-index-inputs.sha256 /tmp/signed-index-inputs.sha256
RUN cd /var/lib/apt/lists && sha256sum -c /tmp/signed-index-inputs.sha256
RUN mkdir -p /runtime/usr/local/lib/p11lab /runtime/usr/local/bin /runtime/usr/share/p11lab/build /runtime/usr/share/licenses/freehsm \
 && cp /build/freehsm/libfreehsm.so /runtime/usr/local/lib/p11lab/ \
 && cp /build/freehsm/tools/fhsm-token /runtime/usr/local/bin/fhsm-token \
 && strip --strip-unneeded /runtime/usr/local/lib/p11lab/libfreehsm.so /runtime/usr/local/bin/fhsm-token \
 && cp /build/freehsm/LICENSE /build/freehsm/NOTICE /runtime/usr/share/licenses/freehsm/ \
 && cp /tmp/FILE-NOTICES.txt /runtime/usr/share/licenses/freehsm/FILE-NOTICES.txt \
 && cp /tmp/actual-base.tsv /tmp/actual-builder.tsv /runtime/usr/share/p11lab/build/ \
 && printf '%s\n' 'profile=interop' 'openssl_prefix=/usr' 'compile_jobs=2' \
      "build_command=make generate PROFILE=interop && make -j2 OPENSSL_PREFIX=/usr PROFILE=interop libfreehsm.so tools/fhsm-token" \
      > /runtime/usr/share/p11lab/build/freehsm.txt \
 && grep -c '^const .*C_GetFunctionList\|CKM_' /build/freehsm/src/gen/fhsm_dispatch.c > /runtime/usr/share/p11lab/build/dispatch-markers.txt \
 && (cd /var/lib/apt/lists && sha256sum *InRelease *Packages.lz4 *Sources.lz4) > /runtime/usr/share/p11lab/build/actual-signed-indexes.sha256 \
 && ldd /runtime/usr/local/lib/p11lab/libfreehsm.so /runtime/usr/local/bin/fhsm-token > /runtime/usr/share/p11lab/build/linked-dependencies.txt \
 && gcc --version > /runtime/usr/share/p11lab/build/compiler.txt \
 && dpkg-query -W -f='${Package} ${Version} ${source:Package} ${source:Version}\n' libssl3t64 libssl-dev > /runtime/usr/share/p11lab/build/system-crypto.txt
FROM ${BASE_IMAGE} AS runtime
COPY --from=builder /runtime/ /
COPY entrypoint.sh /usr/local/bin/p11lab-provider
COPY THIRD-PARTY-NOTICES.txt SOURCE-ACCESS.md /usr/share/p11lab/
COPY common.sh LICENSE provider.json runtime-id build-inputs.json /usr/share/p11lab/
RUN chmod 755 /usr/local/bin/p11lab-provider /usr/local/bin/fhsm-token \
 && find /usr/share/p11lab /usr/share/licenses -type f -exec chmod 644 {} + \
 && chmod 755 /usr/local/lib/p11lab/libfreehsm.so \
 && mkdir -p /var/lib/p11lab /run/p11lab \
 && dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n' | sort > /usr/share/p11lab/build/actual-runtime.tsv \
 && diff -u /usr/share/p11lab/build/actual-base.tsv /usr/share/p11lab/build/actual-runtime.tsv \
 && ldd /usr/local/lib/p11lab/libfreehsm.so /usr/local/bin/fhsm-token > /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && ! grep -q 'not found' /usr/share/p11lab/build/runtime-linked-dependencies.txt
ENTRYPOINT ["/usr/local/bin/p11lab-provider"]
CMD ["describe"]
