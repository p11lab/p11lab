"""Seal coherence for the pinned pkcs11-check 0.2.3 release.

Every pin site (adapter constants, frozen smoke profile, consumer
Dockerfile, tool registry) must name the same release. The private-API
adapter surface is frozen by contract: a checker refactor breaks here.
"""
import importlib.metadata
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from p11lab import checker

SOURCE = '9df03bd8b811966fa7856394b19e3f57ffcd8a40'
WHEEL = '58ac3451ae0dba207a48affa460309e4024c2ec7aefb04ef73062f420fdcffec'
LOCK = '98a0341351b410b8ba6d732ae82ffef14442cded33caf8ab55e3958a0c407cab'
VERSION = '0.2.3'

REPO = Path(__file__).resolve().parent.parent


def test_module_seal_is_023_release():
    assert (checker.SOURCE, checker.WHEEL, checker.LOCK) == (SOURCE, WHEEL, LOCK)


def test_execute_checker_accepts_023_identity(tmp_path):
    pytest.importorskip('pkcs11_check')
    identity = {'source_revision': SOURCE, 'wheel_sha256': WHEEL,
                'runtime_lock_sha256': LOCK}
    with pytest.raises(ValueError, match='execution requires this interpreter installed test root'):
        checker.execute_checker(installed_root=tmp_path / 'missing', module=tmp_path / 'm.so',
                                slot=0, nodes=[], output_dir=tmp_path / 'out',
                                pin='x', so_pin='y', identity=identity)


def test_execute_checker_rejects_022_identity(tmp_path):
    stale = {'source_revision': 'de4db3d2ee738a9f99d0654e4baf568cdbd4774a',
             'wheel_sha256': '812c57e94fb967bc5ba939f0519bba67c58d5e755705b84c8442bbc2774d96f9',
             'runtime_lock_sha256': 'fe8bce22bb409a005977449cadb64f70ea19dd0a0ce9d685d78ac11447926372'}
    with pytest.raises(ValueError, match='checker installation identity mismatch'):
        checker.execute_checker(installed_root=tmp_path / 'missing', module=tmp_path / 'm.so',
                                slot=0, nodes=[], output_dir=tmp_path / 'out',
                                pin='x', so_pin='y', identity=stale)


def test_smoke_profile_seal_matches_module():
    profile = checker.load_profile()
    assert profile['checker_version'] == VERSION
    assert profile['source_revision'] == checker.SOURCE
    assert profile['wheel_sha256'] == checker.WHEEL
    assert profile['runtime_lock_sha256'] == checker.LOCK


def test_consumer_dockerfile_seal_matches_module():
    text = (REPO / 'src/p11lab/data/runtime/checker.Dockerfile').read_text()
    assert f"'{checker.LOCK}  /tmp/runtime-requirements.txt'" in text
    assert f'"source_revision":"{checker.SOURCE}"' in text
    assert f'"wheel_sha256":"{checker.WHEEL}"' in text
    assert f'"runtime_lock_sha256":"{checker.LOCK}"' in text


def test_tools_registry_checker_revision_matches_module():
    tools = json.loads((REPO / 'src/p11lab/data/tools.json').read_text())
    assert tools['tools']['checker']['source']['revision'] == checker.SOURCE


def test_checker_environment_advertises_023_framework(tmp_path):
    pytest.importorskip('pkcs11_check')
    out = tmp_path / 'out'
    out.mkdir()
    env = checker.checker_environment(out, 'pin', 'sopin')
    assert env['PKCS11_CHECK_FRAMEWORK_VERSION'] == VERSION


def _installed_checker_version():
    try:
        return importlib.metadata.version('pkcs11-check')
    except importlib.metadata.PackageNotFoundError:
        return None


def test_frozen_smoke_nodes_collect_under_installed_checker():
    """Guard against checker node-id churn breaking the frozen profile.

    Runs only where the pinned checker is installed (CI installs it
    from the tool registry); collection errors fail loud.
    """
    installed = _installed_checker_version()
    if installed != VERSION:
        pytest.skip(f'pinned checker {VERSION} not installed (found {installed})')
    import pkcs11_check.testcases as tests
    root = Path(tests.__file__).resolve().parent
    targets = [str(root / node) for node in checker.load_profile()['nodes']]
    proc = subprocess.run([sys.executable, '-m', 'pytest', '--collect-only', '-q',
                           '-p', 'no:cacheprovider', *targets],
                          capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr[-2000:]
    match = re.search(r'(\d+) tests? collected', proc.stdout)
    assert match is not None, proc.stdout[-2000:]
    assert int(match.group(1)) == len(targets)


def test_validation_adapter_private_api_intact():
    """The adapter's pinned private imports must resolve under 0.2.3."""
    installed = _installed_checker_version()
    if installed != VERSION:
        pytest.skip(f'pinned checker {VERSION} not installed (found {installed})')
    api = checker._checker_private_api()
    assert set(api) == {'completion_verified_for_attempt',
                        'build_detail_from_report_records',
                        'build_isolated_json_payload', 'FileRunResult', 'FileRunState'}
