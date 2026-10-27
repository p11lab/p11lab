# SPDX-License-Identifier: Apache-2.0
# BouncyHSM Linux runtime: source-built managed server (locked NuGet
# restore, pinned SDK 10.0.401), source-built Linux x64 client module,
# P11Lab probe, pinned ASP.NET Core runtime 10.0.12, and snapshot-pinned
# libicu. The Blazor management UI ships intact; only the dev-only debug
# proxy is removed (used solely by browser debug sessions, never at
# runtime). No checker, consumer tooling, SDK, or NuGet cache ships.
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
RUN cd /tmp && sha256sum -c source.sha256 && mkdir /build && tar -xf source.tar -C /build
COPY dotnet-locks/ /tmp/dotnet-locks/
RUN for project in BouncyHsm BouncyHsm.Core BouncyHsm.Client BouncyHsm.Infrastructure BouncyHsm.Spa; do \
      cp /tmp/dotnet-locks/$project.packages.lock.json /build/src/Src/$project/packages.lock.json; \
    done
# Pinned .NET SDK 10.0.401, verified by embedded SHA512 before extraction.
RUN curl -fsSL --retry 3 --retry-all-errors -o /tmp/dotnet-sdk.tar.gz https://builds.dotnet.microsoft.com/dotnet/Sdk/10.0.401/dotnet-sdk-10.0.401-linux-x64.tar.gz \
 && echo "51c8b999af9e8dd9998c9edc5944e19a90788862068acd38694e098889054ce8c23d4f0c5cccfa16bf187d044562359e5ee69a9f8ad0bbe913ba90311fbce25b  /tmp/dotnet-sdk.tar.gz" | sha512sum -c - \
 && mkdir -p /usr/share/dotnet-sdk && tar -xzf /tmp/dotnet-sdk.tar.gz -C /usr/share/dotnet-sdk \
 && rm /tmp/dotnet-sdk.tar.gz
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1 DOTNET_NUGET_SIGNATURE_VERIFICATION=true NUGET_PACKAGES=/tmp/nuget-packages PATH=/usr/share/dotnet-sdk:${PATH}
RUN cd /build && dotnet --version > /tmp/sdk-version.txt \
 && dotnet publish src/Src/BouncyHsm/BouncyHsm.csproj -c Release -m:2 -o /app/server /p:RestoreLockedMode=true /p:Deterministic=true /p:DebugSymbols=false /p:DebugType=None \
 && make -C /build/build_linux CC=gcc
# Drop the dev-only Blazor debug proxy before staging; the management UI
# (wwwroot) ships intact.
RUN test -d /app/server/BlazorDebugProxy \
 && rm -rf /app/server/BlazorDebugProxy \
 && test ! -e /app/server/BlazorDebugProxy \
 && test -d /app/server/wwwroot && test -f /app/server/BouncyHsm.dll \
 && test -f /app/server/BouncyHsm.Spa.dll && test -x /app/server/BouncyHsm
COPY probe.c /tmp/probe.c
RUN cc -std=c11 -O2 -Wall -Wextra -Werror -pedantic /tmp/probe.c -ldl -o /app/bouncyhsm-probe
# Pinned ASP.NET Core runtime 10.0.12, verified by embedded SHA512.
RUN curl -fsSL --retry 3 --retry-all-errors -o /tmp/aspnet-runtime.tar.gz https://builds.dotnet.microsoft.com/dotnet/aspnetcore/Runtime/10.0.12/aspnetcore-runtime-10.0.12-linux-x64.tar.gz \
 && echo "c489fc3a9dcc85f24f2d52e9a81b46fdf51affc8a360d008dbd5e3b7ce524969adc4a54f555ad13e29b822f59ed1cae9785608cbac2282f2c9c4fda45c21c7d1  /tmp/aspnet-runtime.tar.gz" | sha512sum -c - \
 && mkdir -p /runtime-dotnet/usr/share/dotnet && tar -xzf /tmp/aspnet-runtime.tar.gz -C /runtime-dotnet/usr/share/dotnet \
 && cp /usr/share/dotnet-sdk/dotnet /runtime-dotnet/usr/share/dotnet/dotnet \
 && rm /tmp/aspnet-runtime.tar.gz
COPY FILE-NOTICES.txt /tmp/FILE-NOTICES.txt
COPY signed-index-inputs.sha256 /tmp/signed-index-inputs.sha256
RUN cd /var/lib/apt/lists && sha256sum -c /tmp/signed-index-inputs.sha256
# Three staging roots become three runtime layers (stable first): the dotnet
# runtime, the provider/evidence base, and the volatile published server, so a
# server-only rebuild re-pushes one small layer instead of the whole closure.
# ICU ships only the data/i18n/uc libraries CoreCLR loads (no io/test/tool).
RUN mkdir -p /runtime-base/usr/local/lib/p11lab /runtime-base/usr/local/bin /runtime-server/opt/bouncyhsm /runtime-server/usr/share/p11lab/build /runtime-base/usr/lib/x86_64-linux-gnu /runtime-base/usr/share/p11lab/build/restore /runtime-base/usr/share/licenses/bouncyhsm \
 && cp /build/build_linux/BouncyHsm.Pkcs11Lib-x64.so /runtime-base/usr/local/lib/p11lab/libBouncyHsm.Pkcs11.so \
 && cp /app/bouncyhsm-probe /runtime-base/usr/local/bin/ \
 && cp -r /app/server /runtime-server/opt/bouncyhsm/server \
 && cp /build/LICENSE /runtime-base/usr/share/licenses/bouncyhsm/LICENSE \
 && cp /tmp/FILE-NOTICES.txt /runtime-base/usr/share/licenses/bouncyhsm/FILE-NOTICES.txt \
 && cp /runtime-dotnet/usr/share/dotnet/ThirdPartyNotices.txt /runtime-base/usr/share/licenses/bouncyhsm/dotnet-ThirdPartyNotices.txt \
 && cp /runtime-dotnet/usr/share/dotnet/LICENSE.txt /runtime-base/usr/share/licenses/bouncyhsm/dotnet-LICENSE.txt \
 && cp /usr/share/doc/libicu76/copyright /runtime-base/usr/share/licenses/bouncyhsm/libicu76.copyright \
 && for f in libicudata libicui18n libicuuc; do cp -P /usr/lib/x86_64-linux-gnu/$f.so.76* /runtime-base/usr/lib/x86_64-linux-gnu/; done \
 && [ "$(ls /runtime-base/usr/lib/x86_64-linux-gnu/ | wc -l)" = 6 ] \
 && for s in libicudata.so.76 libicui18n.so.76 libicuuc.so.76; do test -L /runtime-base/usr/lib/x86_64-linux-gnu/$s && test -f /runtime-base/usr/lib/x86_64-linux-gnu/$s || exit 1; done \
 && cp /tmp/actual-base.tsv /tmp/actual-builder.tsv /runtime-base/usr/share/p11lab/build/ \
 && cp /tmp/sdk-version.txt /runtime-base/usr/share/p11lab/build/sdk-version.txt \
 && cp /tmp/dotnet-locks/*.packages.lock.json /runtime-base/usr/share/p11lab/build/restore/ \
 && cp /build/src/Src/BouncyHsm/obj/project.assets.json /runtime-base/usr/share/p11lab/build/restore/BouncyHsm.project.assets.json \
 && (cd /var/lib/apt/lists && sha256sum *InRelease *Packages.lz4 *Sources.lz4) > /runtime-base/usr/share/p11lab/build/actual-signed-indexes.sha256 \
 && (cd /app/server && find . -type f -print0 | sort -z | xargs -0 sha256sum) > /runtime-server/usr/share/p11lab/build/server-files.sha256 \
 && ldd /runtime-base/usr/local/lib/p11lab/libBouncyHsm.Pkcs11.so /runtime-base/usr/local/bin/bouncyhsm-probe /runtime-dotnet/usr/share/dotnet/dotnet > /runtime-base/usr/share/p11lab/build/linked-dependencies.txt \
 && gcc --version > /runtime-base/usr/share/p11lab/build/compiler.txt \
 && DOTNET_ROOT=/runtime-dotnet/usr/share/dotnet /runtime-dotnet/usr/share/dotnet/dotnet --list-runtimes > /runtime-base/usr/share/p11lab/build/runtime-list.txt
FROM ${BASE_IMAGE} AS runtime
COPY --from=builder /runtime-dotnet/ /
COPY --from=builder /runtime-base/ /
COPY --from=builder /runtime-server/ /
COPY entrypoint.sh /usr/local/bin/p11lab-provider
COPY THIRD-PARTY-NOTICES.txt SOURCE-ACCESS.md /usr/share/p11lab/
COPY common.sh LICENSE provider.json runtime-id build-inputs.json /usr/share/p11lab/
RUN chmod 755 /usr/local/bin/p11lab-provider /usr/local/bin/bouncyhsm-probe /opt/bouncyhsm/server/BouncyHsm \
 && find /usr/share/p11lab /usr/share/licenses -type f -exec chmod 644 {} + \
 && mkdir -p /var/lib/p11lab /run/p11lab \
 && dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n' | sort > /usr/share/p11lab/build/actual-runtime.tsv \
 && diff -u /usr/share/p11lab/build/actual-base.tsv /usr/share/p11lab/build/actual-runtime.tsv \
 && ldd /usr/local/lib/p11lab/libBouncyHsm.Pkcs11.so /usr/local/bin/bouncyhsm-probe /usr/share/dotnet/dotnet > /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && ! grep -q 'not found' /usr/share/p11lab/build/runtime-linked-dependencies.txt \
 && /usr/share/dotnet/dotnet --list-runtimes | tee /usr/share/p11lab/build/runtime-list-actual.txt | grep -q 'Microsoft.NETCore.App 10.0.12' \
 && grep -q 'Microsoft.AspNetCore.App 10.0.12' /usr/share/p11lab/build/runtime-list-actual.txt
ENTRYPOINT ["/usr/local/bin/p11lab-provider"]
CMD ["describe"]
