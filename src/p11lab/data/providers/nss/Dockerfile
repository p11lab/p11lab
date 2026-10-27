# SPDX-License-Identifier: Apache-2.0
# NSS softoken Linux runtime: source-built NSS + pinned NSPR (system
# SQLite/zlib), softoken module with its NSS/NSPR closure, provider-native
# certutil for init/health, and a baked default params file selecting the
# SQL database. No checker, consumer tooling, compiler, or SDK ships.
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
RUN cd /tmp && sha256sum -c source.sha256 && mkdir -p /build/nss && tar -xf source.tar -C /build/nss
COPY nspr-manifest.txt /tmp/nspr-manifest.txt
COPY nspr-manifest.sh /tmp/nspr-manifest.sh
# NSPR_TAG in the manifest is evidence-only (which branch the revision came
# from), never a fetch pin: the tarball below is revision-bound through
# NSPR_URL and verified by NSPR_SHA256 plus NSPR_SIZE. The manifest file
# itself stays a strict six-line machine format and cannot carry this note.
RUN . /tmp/nspr-manifest.sh && p11lab_nspr_manifest /tmp/nspr-manifest.txt \
 && curl -fsSL --retry 3 --retry-all-errors -o /tmp/nspr.tar.gz "$NSPR_URL" \
 && echo "$NSPR_SHA256  /tmp/nspr.tar.gz" | sha256sum -c - \
 && [ "$(stat -c %s /tmp/nspr.tar.gz)" = "$NSPR_SIZE" ] \
 && mkdir -p /build/nspr && tar -xzf /tmp/nspr.tar.gz --strip-components=1 -C /build/nspr \
 && rm /tmp/nspr.tar.gz
# Pinned gyp-next 0.22.3 wheel, verified before extraction (build-only).
RUN curl -fsSL --retry 3 --retry-all-errors -o /tmp/gyp.whl https://files.pythonhosted.org/packages/64/c3/57a5d2beb587746ad0ec04b33c8a19990f3e758527031369c6beab8447b6/gyp_next-0.22.3-py3-none-any.whl \
 && echo "cda65d585e378250685bf2f63afa365ac6738501bef992337914e219caf71c69  /tmp/gyp.whl" | sha256sum -c - \
 && mkdir -p /opt/gyp && python3 -c "import zipfile; zipfile.ZipFile('/tmp/gyp.whl').extractall('/opt/gyp')" \
 && printf '#!/bin/sh\nexec python3 -c "from gyp import script_main; script_main()" "$@"\n' > /usr/local/bin/gyp \
 && chmod 755 /usr/local/bin/gyp \
 && rm /tmp/gyp.whl
ENV PYTHONPATH=/opt/gyp MAKEFLAGS=-j2
RUN cd /build/nss && ./build.sh -j 2 -o --disable-tests --system-sqlite \
 && test -f /build/dist/Release/lib/libsoftokn3.so \
 && test -f /build/dist/Release/lib/libfreeblpriv3.so \
 && test -f /build/dist/Release/bin/certutil
COPY params.config /tmp/params.config
COPY FILE-NOTICES.txt /tmp/FILE-NOTICES.txt
COPY signed-index-inputs.sha256 /tmp/signed-index-inputs.sha256
RUN cd /var/lib/apt/lists && sha256sum -c /tmp/signed-index-inputs.sha256
RUN mkdir -p /runtime/usr/local/lib/p11lab /runtime/usr/local/bin /runtime/etc/nss /runtime/etc/ld.so.conf.d /runtime/usr/share/p11lab/build /runtime/usr/share/licenses/nss \
 && cp /build/dist/Release/lib/libsoftokn3.so /build/dist/Release/lib/libsoftokn3.chk \
      /build/dist/Release/lib/libfreeblpriv3.so /build/dist/Release/lib/libfreeblpriv3.chk \
      /build/dist/Release/lib/libnss3.so /build/dist/Release/lib/libnssutil3.so \
      /build/dist/Release/lib/libsmime3.so /build/dist/Release/lib/libssl3.so \
      /build/dist/Release/lib/libnspr4.so /build/dist/Release/lib/libplc4.so \
      /build/dist/Release/lib/libplds4.so /runtime/usr/local/lib/p11lab/ \
 && cp /build/dist/Release/bin/certutil /runtime/usr/local/bin/ \
 && printf '%s\n' /usr/local/lib/p11lab > /runtime/etc/ld.so.conf.d/p11lab-nss.conf \
 && cp /tmp/params.config /runtime/etc/nss/params.config \
 && cp /build/nss/COPYING /runtime/usr/share/licenses/nss/COPYING.nss \
 && cp /build/nspr/LICENSE /runtime/usr/share/licenses/nss/LICENSE.nspr \
 && cp /build/nss/lib/freebl/libcrux/README.md /runtime/usr/share/licenses/nss/libcrux-README.md \
 && sed -n '1,/^ \*\/$/p' /build/nss/lib/freebl/verified/Hacl_Chacha20.c > /runtime/usr/share/licenses/nss/HACL-MIT.txt \
 && grep -q 'Permission is hereby granted' /runtime/usr/share/licenses/nss/HACL-MIT.txt \
 && grep -q 'SOFTWARE\.' /runtime/usr/share/licenses/nss/HACL-MIT.txt \
 && cp /tmp/FILE-NOTICES.txt /runtime/usr/share/licenses/nss/FILE-NOTICES.txt \
 && cp /tmp/actual-base.tsv /tmp/actual-builder.tsv /runtime/usr/share/p11lab/build/ \
 && . /tmp/nspr-manifest.sh && p11lab_nspr_manifest /tmp/nspr-manifest.txt && printf '%s\n' "nspr_tag=$NSPR_TAG" "nspr_revision=$NSPR_REVISION" "nspr_version=$NSPR_VERSION" "nspr_tarball_sha256=$NSPR_SHA256" > /runtime/usr/share/p11lab/build/nspr.txt \
 && printf '%s\n' 'gyp_next_version=0.22.3' 'gyp_next_wheel_sha256=cda65d585e378250685bf2f63afa365ac6738501bef992337914e219caf71c69' "gyp_version=$(gyp --version)" > /runtime/usr/share/p11lab/build/gyp.txt \
 && printf '%s\n' "nss_version=$(sed -n 's/^#define NSS_VMAJOR //p; s/^#define NSS_VMINOR //p; s/^#define NSS_VPATCH //p' /build/nss/lib/nss/nss.h | paste -sd .)" > /runtime/usr/share/p11lab/build/nss-version.txt \
 && (cd /var/lib/apt/lists && sha256sum *InRelease *Packages.lz4 *Sources.lz4) > /runtime/usr/share/p11lab/build/actual-signed-indexes.sha256 \
 && ldd /runtime/usr/local/lib/p11lab/*.so /runtime/usr/local/bin/certutil > /runtime/usr/share/p11lab/build/linked-dependencies.txt \
 && gcc --version > /runtime/usr/share/p11lab/build/compiler.txt \
 && dpkg-query -W -f='${Package} ${Version} ${source:Package} ${source:Version}\n' libsqlite3-0 zlib1g > /runtime/usr/share/p11lab/build/system-crypto.txt
FROM ${BASE_IMAGE} AS runtime
COPY --from=builder /runtime/ /
COPY THIRD-PARTY-NOTICES.txt SOURCE-ACCESS.md /usr/share/p11lab/
COPY common.sh LICENSE provider.json runtime-id build-inputs.json /usr/share/p11lab/
COPY entrypoint.sh /usr/local/bin/p11lab-provider
RUN chmod 755 /usr/local/bin/p11lab-provider /usr/local/bin/certutil \
 && find /usr/share/p11lab /usr/share/licenses -type f -exec chmod 644 {} + \
 && chmod 644 /etc/nss/params.config /etc/ld.so.conf.d/p11lab-nss.conf \
 && chmod 755 /usr/local/lib/p11lab/*.so /etc/nss /etc/ld.so.conf.d \
 && mkdir -p /var/lib/p11lab /run/p11lab \
 && dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n' | sort > /usr/share/p11lab/build/actual-runtime.tsv \
 && diff -u /usr/share/p11lab/build/actual-base.tsv /usr/share/p11lab/build/actual-runtime.tsv \
 && ldconfig \
 && ldd /usr/local/lib/p11lab/libsoftokn3.so /usr/local/lib/p11lab/libfreeblpriv3.so /usr/local/lib/p11lab/libnss3.so /usr/local/lib/p11lab/libnssutil3.so /usr/local/lib/p11lab/libsmime3.so /usr/local/lib/p11lab/libssl3.so /usr/local/lib/p11lab/libnspr4.so /usr/local/lib/p11lab/libplc4.so /usr/local/lib/p11lab/libplds4.so /usr/local/bin/certutil > /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && ! grep -q 'not found' /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && test -f /etc/nss/params.config \
 && ldconfig -p | grep -q /usr/local/lib/p11lab/libsoftokn3.so
ENTRYPOINT ["/usr/local/bin/p11lab-provider"]
CMD ["describe"]
