# SPDX-License-Identifier: Apache-2.0
# Optional Debian/CPython 3.13 derivative. The basic provider is unchanged.
# Portable offline context contract:
# - python-debs/: complete .deb closure acquired from signed Debian snapshot
#   indexes for the selected runtime, with source/version/license inventory;
# - python-debs.sha256: exact archive hashes, sealed by the required build arg;
# - runtime-wheelhouse/ and runtime-requirements.txt: the frozen 33-wheel set;
# - p11lab/: packaged adapter sources (including data/profiles/smoke-v1.json).
# Acquire these bytes by their recorded public URLs and verify their seals before
# building; no development workspace path, network resolver or cache export.
# Distribution still requires separate actual-content source/notice admission.
ARG PROVIDER_IMAGE
FROM ${PROVIDER_IMAGE}
ARG PYTHON_DEBS_MANIFEST_SHA256
COPY python-debs/ /tmp/python-debs/
COPY python-debs.sha256 /tmp/python-debs.sha256
RUN test -n "$PYTHON_DEBS_MANIFEST_SHA256" \
 && echo "$PYTHON_DEBS_MANIFEST_SHA256  /tmp/python-debs.sha256" | sha256sum -c - \
 && cd /tmp && sha256sum -c python-debs.sha256 \
 && dpkg -i /tmp/python-debs/*.deb \
 && rm -rf /tmp/python-debs \
 && python3.13 -m venv /opt/p11lab-checker
COPY runtime-wheelhouse/ /tmp/runtime-wheelhouse/
COPY runtime-requirements.txt /tmp/runtime-requirements.txt
RUN echo '98a0341351b410b8ba6d732ae82ffef14442cded33caf8ab55e3958a0c407cab  /tmp/runtime-requirements.txt' | sha256sum -c - \
 && /opt/p11lab-checker/bin/python -m pip install --no-index --no-cache-dir --only-binary=:all: \
      --find-links /tmp/runtime-wheelhouse --require-hashes -r /tmp/runtime-requirements.txt \
 && /opt/p11lab-checker/bin/python -m pip check \
 && mkdir -p /usr/share/p11lab/checker \
 && cp /tmp/runtime-requirements.txt /tmp/python-debs.sha256 /usr/share/p11lab/checker/ \
 && (cd /tmp/runtime-wheelhouse && sha256sum *.whl) > /usr/share/p11lab/checker/wheels.sha256 \
 && dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n' \
      | sort > /usr/share/p11lab/checker/debian-packages.tsv \
 && rm -rf /tmp/runtime-wheelhouse /tmp/runtime-requirements.txt \
 && printf '%s\n' '{"source_revision":"9df03bd8b811966fa7856394b19e3f57ffcd8a40","wheel_sha256":"58ac3451ae0dba207a48affa460309e4024c2ec7aefb04ef73062f420fdcffec","runtime_lock_sha256":"98a0341351b410b8ba6d732ae82ffef14442cded33caf8ab55e3958a0c407cab"}' > /usr/share/p11lab/checker-install.json
COPY p11lab/ /opt/p11lab-code/p11lab/
RUN chmod -R a+rX /opt/p11lab-code /usr/share/p11lab/checker /usr/share/p11lab/checker-install.json \
 && printf '%s\n' /opt/p11lab-code > /opt/p11lab-checker/lib/python3.13/site-packages/p11lab.pth \
 && /opt/p11lab-checker/bin/python -c 'from p11lab.checker import installed_identity,source_inventory,load_profile; from pathlib import Path; i=installed_identity(); source_inventory(Path(i["installed_root"]),load_profile()["nodes"])'
ENV PATH="/opt/p11lab-checker/bin:${PATH}"
# Inherit the accepted provider lifecycle entrypoint; caller still uses exec --.
