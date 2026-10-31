"""Harmless PEP 517 import/hook fixture, producing an installed startup sentinel."""

import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("canary", "/inputs/source/canary.py")
canary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(canary)
canary.probe("backend-import")


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    import base64
    import csv
    import hashlib
    import io
    import zipfile

    canary.probe("backend-hook")
    name = "authority_canary-0.0.0-py3-none-any.whl"
    files = {
        "authority_canary.pth": "import runpy; runpy.run_path('/inputs/source/canary.py')['probe']('pth-startup')\n",
        "authority_canary-0.0.0.dist-info/METADATA": "Metadata-Version: 2.1\nName: authority-canary\nVersion: 0.0.0\n",
        "authority_canary-0.0.0.dist-info/WHEEL": "Wheel-Version: 1.0\nGenerator: harmless-M05-fixture\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
    }
    rows = []
    for path, value in files.items():
        content = value.encode()
        rows.append(
            (
                path,
                "sha256="
                + base64.urlsafe_b64encode(hashlib.sha256(content).digest())
                .rstrip(b"=")
                .decode(),
                str(len(content)),
            )
        )
    rows.append(("authority_canary-0.0.0.dist-info/RECORD", "", ""))
    output = io.StringIO()
    csv.writer(output, lineterminator="\n").writerows(rows)
    files[rows[-1][0]] = output.getvalue()
    with zipfile.ZipFile(Path(wheel_directory) / name, "w") as archive:
        for path, value in files.items():
            archive.writestr(path, value)
    return name
