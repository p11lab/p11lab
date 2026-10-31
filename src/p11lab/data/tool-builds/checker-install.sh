# SPDX-License-Identifier: Apache-2.0
set -eu
/usr/bin/python3.13 -I -B -m venv /opt/p11lab-checker
/opt/p11lab-checker/bin/python -I -B -m pip install --no-index --no-cache-dir --only-binary=:all: --find-links /inputs/wheels --require-hashes -r /inputs/runtime-requirements.txt
/opt/p11lab-checker/bin/python -I -B -m pip check
/opt/p11lab-checker/bin/python -I -B -c 'import importlib.metadata as m; import pkcs11_check; print(m.version("pkcs11-check"))'
