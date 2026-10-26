import json
import os
from pathlib import Path
import subprocess

import pytest


@pytest.fixture(scope='module')
def installed(tmp_path_factory):
    root = tmp_path_factory.mktemp('installed p11lab with spaces')
    checkout = Path(__file__).resolve().parents[1]
    wheel_dir = root / 'wheels'
    subprocess.run(['uv', 'build', '--wheel', '--out-dir', str(wheel_dir), str(checkout)], check=True, capture_output=True, text=True)
    venv = root / 'venv'
    subprocess.run(['uv', 'venv', str(venv)], check=True, capture_output=True, text=True)
    python = venv / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
    subprocess.run(['uv', 'pip', 'install', '--python', str(python), str(next(wheel_dir.glob('*.whl')))], check=True, capture_output=True, text=True)
    caller = root / 'caller directory with spaces'
    caller.mkdir()
    # Remove editable/source-tree import routes from the subprocess environment.
    env = {k: v for k, v in os.environ.items() if k not in {'PYTHONPATH', 'PYTHONHOME'}}
    command = venv / ('Scripts/p11lab.exe' if os.name == 'nt' else 'bin/p11lab')
    return command, python, caller, env


def test_installed_catalogue_uses_packaged_assets_without_checkout(installed):
    command, python, caller, env = installed
    result = subprocess.run([str(command), 'list', '--json'], cwd=caller, env=env, capture_output=True, text=True, check=True)
    entries = json.loads(result.stdout)
    assert len(entries) == 24
    subprocess.run([str(command), 'validate'], cwd=caller, env=env, capture_output=True, text=True, check=True)
    script = '''
from pathlib import Path
from p11lab.catalog import list_environments, packaged_asset, package_data
assert len(list_environments()) == 24
for spec in list_environments():
    assert packaged_asset(spec['id'], 'provider.json').is_file()
assert package_data('tools.json').is_file()
print(Path.cwd())
'''
    result = subprocess.run([str(python), '-c', script], cwd=caller, env=env, capture_output=True, text=True, check=True)
    assert result.stdout.strip() == str(caller)


def test_installed_describe_explains_unavailable_and_rejects_unknown_channel(installed):
    command, _, caller, env = installed
    result = subprocess.run([str(command), 'describe', 'pkcs11rs', '--channel', 'release'], cwd=caller, env=env, capture_output=True, text=True, check=True)
    assert json.loads(result.stdout)['channel_spec']['status'] == 'unavailable'
    result = subprocess.run([str(command), 'describe', 'haskoki', '--channel', 'made-up'], cwd=caller, env=env, capture_output=True, text=True)
    assert result.returncode == 2
    assert 'channel' in result.stderr
