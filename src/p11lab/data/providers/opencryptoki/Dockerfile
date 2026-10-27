# SPDX-License-Identifier: Apache-2.0
# SWToken only. Native source is unpatched; daemon forking is supervised by
# the original P11Lab adapter. Debian's libcrypto and legacy provider suffice.
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
COPY source.tar source.sha256 /tmp/
RUN cd /tmp && sha256sum -c source.sha256 && mkdir -p /build/opencryptoki \
 && tar -xf source.tar -C /build/opencryptoki
WORKDIR /build/opencryptoki
RUN --network=none sh bootstrap.sh \
 && CPPFLAGS='-DLOG_FILE=\"/run/p11lab/opencryptoki/logs/pkcsslotd.log\"' \
      ./configure --prefix=/usr/local --libdir=/usr/local/lib/p11lab \
      --sysconfdir=/var/lib/p11lab --localstatedir=/var/lib/p11lab/opencryptoki \
      --with-pkcsslotd-user=p11lab --with-pkcs-group=p11lab --without-systemd \
      --enable-swtok --disable-icatok --disable-ccatok --disable-ep11tok \
      --disable-tpmtok --disable-icsftok --disable-p11sak --disable-p11kmip \
      --disable-pkcstok_migrate --disable-pkcsstats --disable-pkcscca \
      --disable-pkcshsm_mk_change --disable-pkcstok_admin \
 && make -j2 RUN_PATH=/run/p11lab lockdir=/run/p11lab/opencryptoki/locks logdir=/run/p11lab/opencryptoki/logs
COPY provision.c /tmp/provision.c
RUN --network=none cc -std=c11 -O2 -Wall -Wextra -Werror -pedantic \
      -I/usr/include/p11-kit-1 /tmp/provision.c -ldl -o /tmp/p11lab-opencryptoki
COPY FILE-NOTICES.txt /tmp/FILE-NOTICES.txt
COPY signed-index-inputs.sha256 /tmp/signed-index-inputs.sha256
RUN cd /var/lib/apt/lists && sha256sum -c /tmp/signed-index-inputs.sha256
RUN mkdir -p /runtime/usr/local/lib/p11lab /runtime/usr/local/bin /runtime/usr/local/sbin \
      /runtime/usr/share/p11lab/build /runtime/usr/share/p11lab/opencryptoki \
      /runtime/usr/share/licenses/opencryptoki /runtime/usr/share/licenses/runtime-closure \
 && cp opencryptoki/.libs/libopencryptoki.so.0.0.0 /runtime/usr/local/lib/p11lab/libopencryptoki.so \
 && cp opencryptoki/stdll/.libs/libpkcs11_sw.so.0.0.0 /runtime/usr/local/lib/p11lab/libpkcs11_sw.so \
 && cp usr/sbin/pkcsslotd/pkcsslotd /runtime/usr/local/sbin/ \
 && cp /tmp/p11lab-opencryptoki /runtime/usr/local/bin/ \
 && strip --strip-unneeded /runtime/usr/local/lib/p11lab/libopencryptoki.so /runtime/usr/local/lib/p11lab/libpkcs11_sw.so /runtime/usr/local/sbin/pkcsslotd \
 && cp /usr/lib/x86_64-linux-gnu/liblber.so.2.0.200 /runtime/usr/local/lib/p11lab/liblber.so.2 \
 && cp /usr/lib/x86_64-linux-gnu/libnss_wrapper.so /runtime/usr/local/lib/p11lab/ \
 && printf '%s\n' 'ca319704dd4f58b5b3fc8510738850f03f18940544ba04bebf2fa8a23a798346  /runtime/usr/local/lib/p11lab/liblber.so.2' \
      'f78a1f924b674de69b65975f3bc61bbc9ebe0918125b5a322217f031fc928413  /runtime/usr/local/lib/p11lab/libnss_wrapper.so' | sha256sum -c - \
 && cp doc/strength-example.conf /runtime/usr/share/p11lab/opencryptoki/strength.conf \
 && cp LICENSE /tmp/FILE-NOTICES.txt /runtime/usr/share/licenses/opencryptoki/ \
 && cp usr/lib/common/constant_time.h /runtime/usr/share/licenses/opencryptoki/ \
 && cp /usr/share/doc/libldap2/copyright /runtime/usr/share/licenses/runtime-closure/libldap2-copyright \
 && cp /usr/share/doc/libnss-wrapper/copyright /runtime/usr/share/licenses/runtime-closure/libnss-wrapper-copyright \
 && cp /usr/share/doc/libp11-kit-dev/copyright /runtime/usr/share/licenses/runtime-closure/build-header-copyright \
 && cp /usr/include/p11-kit-1/p11-kit/pkcs11.h /runtime/usr/share/licenses/runtime-closure/build-pkcs11-header.h \
 && cp /tmp/actual-base.tsv /tmp/actual-builder.tsv /runtime/usr/share/p11lab/build/ \
 && cp config.log /runtime/usr/share/p11lab/build/opencryptoki-config.log \
 && (cd /var/lib/apt/lists && sha256sum *InRelease *Packages.lz4 *Sources.lz4) > /runtime/usr/share/p11lab/build/actual-signed-indexes.sha256 \
 && cc --version > /runtime/usr/share/p11lab/build/compiler.txt \
 && openssl version -a > /runtime/usr/share/p11lab/build/openssl.txt \
 && openssl list -providers -provider default -provider legacy >> /runtime/usr/share/p11lab/build/openssl.txt \
 && printf '%s\n' 'SWToken only; native source unpatched; make -j2' \
      'system libcrypto.so.3 + Debian openssl-provider-legacy' \
      'RUN_PATH=/run/p11lab; lockdir=/run/p11lab/opencryptoki/locks; logdir=/run/p11lab/opencryptoki/logs' \
      'native forking daemon; Linux subreaper; primary GID 1001; caller UID via NSS wrapper' \
      > /runtime/usr/share/p11lab/build/options.txt
FROM ${BASE_IMAGE} AS runtime
COPY --from=builder /runtime/ /
COPY THIRD-PARTY-NOTICES.txt SOURCE-ACCESS.md common.sh LICENSE provider.json runtime-id build-inputs.json /usr/share/p11lab/
COPY entrypoint.sh /usr/local/bin/p11lab-provider
RUN printf '%s\n' '/usr/local/lib/p11lab' > /etc/ld.so.conf.d/p11lab-opencryptoki.conf \
 && ldconfig \
 && chmod 755 /usr/local/bin/p11lab-provider /usr/local/bin/p11lab-opencryptoki /usr/local/sbin/pkcsslotd \
 && find /usr/share/p11lab /usr/share/licenses -type f -exec chmod 644 {} + \
 && chown 0:1001 /usr/share/p11lab/opencryptoki/strength.conf \
 && chmod 640 /usr/share/p11lab/opencryptoki/strength.conf \
 && mkdir -p /var/lib/p11lab /run/p11lab \
 && chgrp 1001 /var/lib/p11lab /run/p11lab \
 && chmod 2770 /var/lib/p11lab /run/p11lab \
 && dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n' | sort > /usr/share/p11lab/build/actual-runtime.tsv \
 && diff -u /usr/share/p11lab/build/actual-base.tsv /usr/share/p11lab/build/actual-runtime.tsv \
 && ldd /usr/local/lib/p11lab/libopencryptoki.so /usr/local/lib/p11lab/libpkcs11_sw.so /usr/local/sbin/pkcsslotd /usr/local/bin/p11lab-opencryptoki /usr/local/lib/p11lab/libnss_wrapper.so > /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && ! grep -q 'not found' /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && grep -q 'libcrypto.so.3' /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && printf '%s\n' '533bb6758a00a87a2d7835bcd3ebca58e0def2c1096ec582dea180adceeb7404  /usr/lib/x86_64-linux-gnu/ossl-modules/legacy.so' | sha256sum -c -
ENTRYPOINT ["/usr/local/bin/p11lab-provider"]
CMD ["describe"]
