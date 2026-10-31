"""Real public-source, sealed evaluator bootstrap; no workspace checker imports."""
import copy
import json
from pathlib import Path

import pytest

DATA = Path(__file__).resolve().parents[2] / 'src/p11lab/data/rounds'


def test_bootstrap_contract_exists():
    from p11lab.round_core.bootstrap import acquire_evaluator
    assert callable(acquire_evaluator)


def test_rejects_wrong_pin_before_acquisition(tmp_path):
    from p11lab.round_core.bootstrap import acquire_evaluator
    pin = json.loads((DATA / 'evaluator/source.json').read_text())
    pin['commit'] = 'f' * 40
    with pytest.raises(ValueError, match='reviewed source pin'):
        acquire_evaluator(pin, DATA / 'evaluator', tmp_path / 'wrong')


def test_real_source_build_and_offline_install(evaluator):
    receipt, root = evaluator
    assert receipt['schema'] == 1
    assert receipt['source']['commit'] == '09aabfec9fea7e424aabb991f6347349bfa84075'
    assert receipt['python']['version'] == '3.12.14'
    assert receipt['wheel']['sha256']
    assert len(receipt['runtime_distributions']) == 34  # 32 dependencies, evaluator, sealed pip
    assert receipt['source_companion']['sha256'] == 'ab72ff5d8ae6081574c16a7ea19543a0c64d3da29ca7c18e213093bc48810891'
    assert receipt['native_dependencies']
    assert len(receipt['runtime_origins']) == 34
    assert all(Path(origin).is_relative_to(root / 'evaluator-install') for origin in receipt['runtime_origins'].values())
    assert receipt['python_files'] and receipt['installed_files'] and receipt['source_files']
    assert all(c['returncode'] == 0 for c in receipt['commands'])
    assert all('--no-index' in c['argv'] and '--require-hashes' in c['argv']
               for c in receipt['commands'] if 'install' in c['argv'])
    from p11lab.round_core.bootstrap import verify_receipt
    verify_receipt(receipt, root, DATA / 'evaluator')


def test_replay_lock_mismatch_rejected(evaluator, tmp_path):
    from p11lab.round_core.bootstrap import verify_receipt
    receipt, root = evaluator
    locks = tmp_path / 'locks'
    locks.mkdir()
    for p in (DATA / 'evaluator').iterdir():
        if p.is_file():
            (locks / p.name).write_bytes(p.read_bytes())
    with (locks / 'runtime-linux-amd64.lock').open('a') as stream:
        stream.write('# drift\n')
    with pytest.raises(ValueError, match='lock'):
        verify_receipt(receipt, root, locks)


def test_receipt_inventory_tamper_rejected(evaluator):
    from p11lab.round_core.bootstrap import verify_receipt
    receipt, root = evaluator
    broken = copy.deepcopy(receipt)
    broken['installed_files'][0]['sha256'] = '0' * 64
    with pytest.raises(ValueError, match='inventory'):
        verify_receipt(broken, root, DATA / 'evaluator')

@pytest.fixture(scope='session')
def evaluator(tmp_path_factory):
    import os
    from p11lab.round_core.bootstrap import acquire_evaluator
    pin = json.loads((DATA / 'evaluator/source.json').read_text())
    root = Path(os.environ.get('P11LAB_W01_OUTPUT', str(tmp_path_factory.mktemp('evaluator'))))
    receipt = acquire_evaluator(pin, DATA / 'evaluator', root)
    return receipt, root


@pytest.mark.parametrize('mutation', ['lock-roster', 'wheel', 'runtime-roster', 'python', 'native-roster', 'controller-roster', 'commands', 'companion'])
def test_receipt_metadata_tamper_rejected(evaluator, mutation):
    from p11lab.round_core.bootstrap import verify_receipt
    receipt, root = evaluator
    broken = copy.deepcopy(receipt)
    if mutation == 'lock-roster':
        broken['locks'] = {}
    elif mutation == 'wheel':
        broken['wheel']['sha256'] = '0' * 64
    elif mutation == 'runtime-roster':
        broken['runtime_distributions'] = []
    elif mutation == 'python':
        broken['python']['sha256'] = '0' * 64
    elif mutation == 'native-roster':
        broken['native_dependencies'] = []
    elif mutation == 'controller-roster':
        broken['controller_files'] = []
    elif mutation == 'commands':
        broken['commands'] = []
    else:
        broken['source_companion']['sha256'] = '0' * 64
    with pytest.raises(ValueError):
        verify_receipt(broken, root, DATA / 'evaluator')


@pytest.mark.parametrize('kind', ['traversal', 'duplicate', 'escape-link', 'device'])
def test_acquisition_rejects_unsafe_archives(tmp_path, kind):
    import io
    import tarfile
    from p11lab.round_core.bootstrap import extract_verified
    archive = tmp_path / 'bad.tar'
    with tarfile.open(archive, 'w') as out:
        if kind == 'traversal':
            member = tarfile.TarInfo('../outside')
        elif kind == 'escape-link':
            member = tarfile.TarInfo('inside')
            member.type = tarfile.SYMTYPE
            member.linkname = '../../outside'
        elif kind == 'device':
            member = tarfile.TarInfo('device')
            member.type = tarfile.CHRTYPE
        else:
            member = tarfile.TarInfo('duplicate')
            out.addfile(member, io.BytesIO(b''))
        out.addfile(member, io.BytesIO(b''))
    with pytest.raises(ValueError):
        extract_verified(archive, tmp_path / 'extracted')
    assert not (tmp_path / 'outside').exists()


def test_download_cache_checksum_and_public_url_checks(tmp_path):
    from p11lab.round_core.bootstrap import fetch_verified
    destination = tmp_path / 'cached.whl'
    destination.write_bytes(b'bad bytes')
    spec = {'url': 'https://files.pythonhosted.org/example.whl', 'sha256': '0' * 64, 'size': 9}
    with pytest.raises(ValueError, match='checksum'):
        fetch_verified(spec, destination)
    spec['url'] = 'file:///etc/passwd'
    with pytest.raises(ValueError, match='HTTPS'):
        fetch_verified(spec, destination)


def test_sealed_environment_excludes_caller_imports_and_configuration(evaluator, tmp_path):
    import subprocess
    receipt, root = evaluator
    fake = tmp_path / 'pkcs11_check'
    fake.mkdir()
    (fake / '__init__.py').write_text('raise RuntimeError("candidate import leaked")\n')
    env = dict(receipt['environment'], PYTHONPATH=str(tmp_path), PYTHONHOME=str(tmp_path),
               VIRTUAL_ENV=str(tmp_path), PIP_INDEX_URL='https://invalid.example')
    result = subprocess.run([str(root / 'evaluator-install/bin/python3'), '-I', '-B', '-c',
                             'import pkcs11_check;print(pkcs11_check.__file__)'],
                            env=env, cwd=tmp_path, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == str(root / receipt['installed_origin'])
    assert 'PYTHONPATH' not in receipt['environment']
    assert 'VIRTUAL_ENV' not in receipt['environment']


def test_packaged_round_unit_lock_has_exact_complete_tool_closure():
    source = json.loads((DATA / 'evaluator/source.json').read_text())
    tools = json.loads((DATA / 'tooling.json').read_text())
    expected = {}
    for wheel in [*source['runtime_wheels'], *source['build_wheels'], *tools['wheels']]:
        line = f"{wheel['name']}=={wheel['version']} --hash=sha256:{wheel['sha256']}"
        if wheel['name'] in expected:
            assert expected[wheel['name']] == line
        expected[wheel['name']] = line
    path = DATA.parents[3] / '.github/requirements/round-unit.txt'
    observed = [line for line in path.read_text().splitlines() if line and not line.startswith('#')]
    assert sorted(observed) == sorted(expected.values())
    assert tools['actionlint']['version'] == '1.7.12'


def test_bootstrap_seals_installed_public_startup_contract(evaluator):
    from p11lab.round_core.bootstrap import sha256
    receipt, _ = evaluator
    assert receipt.get('contract_sha256') == sha256(DATA / 'contract.json')
    assert receipt.get('public_api_probe', {}).get('registered_entries') == 39
    assert receipt.get('help_probe', {}).get('complete_helps') == 11


@pytest.mark.parametrize('mutation', ['ld-preload', 'path', 'home', 'pip-config', 'release-status',
                                     'installed-origin', 'sys-path', 'runtime-origins', 'tools',
                                     'api-origins', 'help-snapshots', 'python-platform', 'driver', 'extra-key'])
def test_operational_receipt_metadata_is_verified(evaluator, mutation):
    """Exact reviewer environment/release probes plus other returned execution claims."""
    from p11lab.round_core.bootstrap import verify_receipt
    receipt, root = evaluator
    broken = copy.deepcopy(receipt)
    if mutation == 'ld-preload':
        broken['environment']['LD_PRELOAD'] = '/untrusted/reviewer-example.so'
    elif mutation == 'path':
        broken['environment']['PATH'] = '/untrusted/bin'
    elif mutation == 'home':
        broken['environment']['HOME'] = '/untrusted/home'
    elif mutation == 'pip-config':
        broken['environment']['PIP_CONFIG_FILE'] = '/untrusted/pip.conf'
    elif mutation == 'release-status':
        broken['release_dependencies']['EVID-STREAM-1']['status'] = 'active'
    elif mutation == 'installed-origin':
        broken['installed_origin'] = '/untrusted/checker.py'
    elif mutation == 'sys-path':
        broken['installed_sys_path'].append('/untrusted/imports')
    elif mutation == 'runtime-origins':
        broken['runtime_origins'][next(iter(broken['runtime_origins']))] = '/untrusted/imports'
    elif mutation == 'tools':
        broken['tools']['ruff'] = '/untrusted/ruff'
    elif mutation == 'api-origins':
        broken['public_api_probe']['origins']['package'] = '/untrusted/checker.py'
    elif mutation == 'help-snapshots':
        broken['help_probe']['snapshots'][0]['argv'][0] = '/untrusted/python'
    elif mutation == 'python-platform':
        broken['python']['platform'] = 'unverified-platform'
    elif mutation == 'driver':
        broken['bootstrap_driver_sha256'] = '0' * 64
    else:
        broken['unreviewed_executor'] = '/untrusted/executor'
    with pytest.raises(ValueError):
        verify_receipt(broken, root, DATA / 'evaluator')


def test_installed_p11lab_wheel_replays_packaged_contract_outside_checkout(evaluator, tmp_path):
    """Build/install P11Lab offline, then deny every checkout read during replay."""
    import os
    import shutil
    import subprocess
    from p11lab.round_core.bootstrap import inventory, sha256
    receipt, root = evaluator
    checkout = Path(__file__).resolve().parents[2]
    outside = tmp_path / 'installed-consumer'
    outside.mkdir()
    dist = outside / 'dist'
    commands = []

    def run(argv):
        result = subprocess.run(argv, env=receipt['environment'], cwd=outside,
                                capture_output=True, text=True, timeout=120)
        commands.append({'argv': argv, 'returncode': result.returncode,
                         'stdout': result.stdout, 'stderr': result.stderr})
        assert result.returncode == 0, result.stdout + result.stderr
        return result.stdout

    run([str(root / 'build-env/bin/python3'), '-I', '-B', '-m', 'build', '--wheel',
         '--no-isolation', '--outdir', str(dist), str(checkout)])
    wheel, = dist.glob('*.whl')
    pip_spec = next(item for item in receipt['source']['build_wheels'] if item['name'] == 'pip')
    pip_wheel = root / 'downloads/build-wheels' / pip_spec['filename']
    shutil.copyfile(pip_wheel, dist / pip_wheel.name)
    lock = outside / 'installed-consumer.lock'
    lock.write_text(f"p11lab==0.1.0.dev0 --hash=sha256:{sha256(wheel)}\n"
                    f"pip=={pip_spec['version']} --hash=sha256:{pip_spec['sha256']}\n")
    install = outside / 'install'
    run([str(root / 'python/bin/python3'), '-I', '-B', '-m', 'venv', '--without-pip', str(install)])
    python = install / 'bin/python3'
    code = f'import runpy,sys;sys.path.insert(0,{str(pip_wheel)!r});runpy.run_module("pip",run_name="__main__")'
    run([str(python), '-I', '-B', '-c', code, 'install', '--no-index', '--no-compile',
         '--find-links', str(dist), '--require-hashes', '-r', str(lock)])
    script = r'''import json,sys
from pathlib import Path
blocked=Path(sys.argv[1]).resolve()
install=Path(sys.argv[2]).resolve()
root=Path(sys.argv[3]).resolve()
def forbid_checkout(event,args):
    if event=='open' and isinstance(args[0],(str,bytes)):
        name=Path(args[0].decode() if isinstance(args[0],bytes) else args[0]).resolve()
        if name.is_relative_to(blocked):
            raise RuntimeError('checkout read forbidden: '+str(name))
sys.addaudithook(forbid_checkout)
import p11lab
from p11lab.round_core import bootstrap
origin=Path(bootstrap.__file__).resolve()
assert origin.is_relative_to(install), origin
assert not any(Path(item).resolve().is_relative_to(blocked) for item in sys.path)
data=origin.parents[1]/'data/rounds'
pin=json.loads((data/'evaluator/source.json').read_text())
contract=json.loads((data/'contract.json').read_text())
for name in ['build-linux-amd64.lock','runtime-linux-amd64.lock']:
    assert (data/'evaluator'/name).is_file()
assert json.loads((data/'tooling.json').read_text())['actionlint']['version']=='1.7.12'
receipt=bootstrap.acquire_evaluator(pin,data/'evaluator',root)
assert receipt['release_dependencies']==contract['release_dependencies']
assert receipt['release_dependencies']['EVID-STREAM-1']['status']=='blocked'
print(json.dumps({'installed_origin':str(origin),'data_root':str(data),'wheel_sha256':receipt['wheel']['sha256'],
                  'release_status':'blocked','checkout_reads':'denied','registered_entries':receipt['public_api_probe']['registered_entries']}))
'''
    observed = json.loads(run([str(python), '-I', '-B', '-c', script,
                               str(checkout), str(install), str(root)]))
    assert observed['registered_entries'] == 39
    assert observed['wheel_sha256'] == receipt['wheel']['sha256']
    evidence = {'p11lab_wheel': {'filename': wheel.name, 'sha256': sha256(wheel)},
                'commands': commands, 'observation': observed, 'installed_files': inventory(outside, install)}
    evidence_path = Path(os.environ.get('P11LAB_W01_PACKAGING_EVIDENCE', str(outside / 'packaging-proof.json')))
    evidence_path.write_text(json.dumps(evidence, indent=2) + '\n')
