# SPDX-License-Identifier: Apache-2.0
set -eu
/usr/bin/python3.13 -I -B -m venv /tmp/build
/tmp/build/bin/python -I -B -m pip install --no-index --no-cache-dir --only-binary=:all: --find-links /inputs/wheels --require-hashes -r /inputs/bootstrap-requirements.txt
/tmp/build/bin/python -I -B -m pip install --no-index --no-cache-dir --only-binary=:all: --find-links /inputs/wheels --require-hashes -r /inputs/build-requirements.txt
/tmp/build/bin/python -I -B -m pip wheel --no-index --no-cache-dir --no-deps --no-build-isolation --wheel-dir /out /inputs/source
chmod 644 /out/*.whl
