"""Acquire the reviewed evaluator from public, hashed inputs.

This is a trusted-tool bootstrap, not a candidate build sandbox. It never loads
an evaluator from the caller's Python environment or resolves packages online.
"""
from __future__ import annotations

import hashlib
from datetime import datetime
import json
import os
import platform
import re
import shutil
import subprocess
import tarfile
import urllib.parse
import urllib.request
from pathlib import Path, PurePosixPath

from . import JsonObject

_DATA = Path(__file__).resolve().parents[1] / 'data' / 'rounds'
_SHA256 = re.compile(r'[0-9a-f]{64}')
_CONTROLLER_FILES = ('installed-runtime.lock', 'tooling.lock', 'public-commit.json',
                     'native-ldd.json', 'bootstrap-commands.json')

# Isolated, explicit public contract probe; no private evaluator schema access.
_API_PROBE = r"""import dataclasses,inspect,json,runpy,sys
from pathlib import Path
import pkcs11_check
from pkcs11_check.core import evidence as e
from pkcs11_check.core import report_log
expected=json.loads(Path(sys.argv[1]).read_text())["api_contract"]
companion_path=Path(sys.argv[2])
companion=runpy.run_path(str(companion_path))
actual={}
for name, wanted in expected.items():
    if name.startswith("scripts/"):
        obj=companion[name.split(":")[1]]
    elif name.startswith("core.report_log."):
        obj=getattr(report_log,name.rsplit(".",1)[1])
    elif "." in name:
        cls,method=name.split(".")
        owner=report_log.SessionCompletionTracker if cls=="SessionCompletionTracker" else getattr(e,cls)
        obj=getattr(owner,method)
    else:
        obj=getattr(e,name)
    row={}
    if isinstance(obj,(str,int)):
        row.update(module=None,value=obj)
    elif "." in name and not name.startswith(("core.","scripts/")):
        prop=isinstance(obj,property)
        row.update(property=prop,signature=str(inspect.signature(obj.fget if prop else obj)))
    else:
        row["signature"]=str(inspect.signature(obj))
        if "module" in wanted:
            row["module"]=obj.__module__
        if dataclasses.is_dataclass(obj):
            row["fields"]=[{"name":f.name,"type":str(f.type),"default":repr(f.default) if f.default is not dataclasses.MISSING else "<required>"} for f in dataclasses.fields(obj)]
        if name=="Outcome":
            row["values"]=[v.value for v in obj]
    actual[name]=row
if actual!=expected:
    raise ValueError("installed public API differs from reviewed contract")
root=companion_path.parents[2]
origins={"package":pkcs11_check.__file__,"evidence":e.__file__,"report_log":report_log.__file__,"e4":str(companion_path)}
if any(not Path(p).is_relative_to(root) for p in origins.values()):
    raise ValueError("public probe import outside trusted output")
print(json.dumps({"registered_entries":len(actual),"origins":origins}))
"""

_INSTALL_PROBE = '''import importlib.metadata as m,json,sys,pkcs11_check
print(json.dumps({"distributions": sorted([{"name": d.metadata["Name"].lower().replace("_","-"), "version":d.version} for d in m.distributions()],key=lambda d:d["name"]), "origin":pkcs11_check.__file__,"sys_path":sys.path,"origins":{d.metadata["Name"]:str(d.locate_file("")) for d in m.distributions()}}))'''
_PUBLIC_CLI = 'from pkcs11_check.cli.app import app;app(prog_name="pkcs11-check")'
_RECEIPT_KEYS = {
    'bootstrap_driver_sha256', 'build_files', 'commands', 'companion_files', 'contract_sha256',
    'controller_files', 'dist_files', 'download_files', 'environment', 'help_probe', 'installed_files',
    'installed_origin', 'installed_sys_path', 'locks', 'native_dependencies', 'public_api_probe',
    'python', 'python_files', 'release_dependencies', 'runtime_distributions', 'runtime_origins',
    'schema', 'source', 'source_companion', 'source_date_epoch', 'source_files', 'tool_files',
    'tooling_sha256', 'tools', 'wheel',
}


def sha256(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def _json(path: Path) -> JsonObject:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError(f'expected JSON object: {path.name}')
    return value


def _write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def _relative(root: Path, value: str) -> Path:
    name = PurePosixPath(value)
    if name.is_absolute() or '..' in name.parts or '\\' in value:
        raise ValueError('unsafe inventory path')
    path = root / value
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError('inventory escapes output')
    return path


def fetch_verified(spec: JsonObject, destination: Path) -> None:
    """Fetch one HTTPS object, bound its length, and check before atomic rename."""
    url = urllib.parse.urlsplit(spec['url'])
    if url.scheme != 'https' or url.username or url.password or not url.netloc:
        raise ValueError('acquisition requires a public HTTPS URL')
    if not _SHA256.fullmatch(spec['sha256']) or type(spec['size']) is not int:
        raise ValueError('invalid acquisition hash/size')
    if destination.exists():
        if destination.stat().st_size != spec['size'] or sha256(destination) != spec['sha256']:
            raise ValueError(f'acquisition checksum mismatch: {destination.name}')
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    part = destination.with_suffix(destination.suffix + '.partial')
    try:
        request = urllib.request.Request(spec['url'], headers={'User-Agent': 'P11Lab-sealed-bootstrap/1'})
        with urllib.request.urlopen(request, timeout=90) as response, part.open('xb') as out:
            if urllib.parse.urlsplit(response.url).scheme != 'https':
                raise ValueError('insecure acquisition redirect')
            total = 0
            while block := response.read(1024 * 1024):
                total += len(block)
                if total > spec['size']:
                    raise ValueError('acquisition exceeds declared size')
                out.write(block)
        if total != spec['size'] or sha256(part) != spec['sha256']:
            raise ValueError(f'acquisition checksum mismatch: {destination.name}')
        part.replace(destination)
    finally:
        part.unlink(missing_ok=True)


def extract_verified(archive: Path, destination: Path) -> None:
    """Reject traversal, duplicates, devices and escaping links before extraction."""
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive) as bundle:
        members = bundle.getmembers()
        names: set[str] = set()
        for member in members:
            name = PurePosixPath(member.name)
            if name.is_absolute() or '..' in name.parts or '\\' in member.name:
                raise ValueError('unsafe archive path')
            key = str(name)
            if key in names:
                raise ValueError('duplicate archive member')
            names.add(key)
            if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
                raise ValueError('unsupported archive member')
            if member.issym() or member.islnk():
                base = destination / name.parent if member.issym() else destination
                target = base / member.linkname
                if not target.resolve().is_relative_to(destination.resolve()):
                    raise ValueError('unsafe archive link')
        bundle.extractall(destination, filter='data')


def inventory(root: Path, subtree: Path) -> list[JsonObject]:
    result: list[JsonObject] = []
    for path in sorted(subtree.rglob('*')):
        if path.is_symlink():
            result.append({'path': path.relative_to(root).as_posix(), 'link': os.readlink(path)})
        elif path.is_file():
            result.append({'path': path.relative_to(root).as_posix(), 'sha256': sha256(path),
                           'size': path.stat().st_size, 'mode': path.stat().st_mode & 0o777})
    return result


def _verify_inventory(root: Path, entries: list[JsonObject], subtree: str) -> None:
    for entry in entries:
        path = _relative(root, entry['path'])
        if 'link' in entry:
            valid = path.is_symlink() and os.readlink(path) == entry['link']
        else:
            valid = (path.is_file() and not path.is_symlink()
                     and path.stat().st_size == entry['size']
                     and path.stat().st_mode & 0o777 == entry['mode']
                     and sha256(path) == entry['sha256'])
        if not valid:
            raise ValueError(f'inventory mismatch: {entry["path"]}')
    if inventory(root, root / subtree) != entries:
        raise ValueError(f'inventory roster mismatch: {subtree}')


def _lock_text(wheels: list[JsonObject]) -> str:
    return ''.join(f'{w["name"]}=={w["version"]} --hash=sha256:{w["sha256"]}\n' for w in wheels)


def _check_lock(path: Path, wheels: list[JsonObject]) -> None:
    actual = [line for line in path.read_text().splitlines() if line and not line.startswith('#')]
    if actual != _lock_text(wheels).splitlines():
        raise ValueError(f'lock roster/hash mismatch: {path.name}')


def _environment(output: Path, source_date_epoch: int) -> dict[str, str]:
    """Reconstruct the complete permitted process environment from trusted inputs."""
    return {'PATH': '/usr/bin:/bin', 'HOME': str(output / 'home'), 'LANG': 'C.UTF-8',
           'LC_ALL': 'C.UTF-8', 'SOURCE_DATE_EPOCH': str(source_date_epoch),
           'PYTHONDONTWRITEBYTECODE': '1', 'PIP_CONFIG_FILE': '/dev/null',
           'PIP_DISABLE_PIP_VERSION_CHECK': '1', 'PIP_NO_INPUT': '1',
           'NO_COLOR': '1', 'TERM': 'dumb', 'COLUMNS': '120',
           'LD_LIBRARY_PATH': str(output / 'python/lib')}


def _verify_operational_metadata(receipt: JsonObject, output: Path, pin: JsonObject) -> None:
    """Validate every returned execution/identity claim without executing receipt argv."""
    contract = _json(_DATA / 'contract.json')
    tooling = _json(_DATA / 'tooling.json')
    if set(receipt) != _RECEIPT_KEYS:
        raise ValueError('receipt field roster mismatch')
    if receipt['environment'] != _environment(output, pin['source_date_epoch']):
        raise ValueError('execution environment receipt mismatch')
    if receipt['release_dependencies'] != contract['release_dependencies']:
        raise ValueError('release dependency receipt mismatch')
    if receipt['bootstrap_driver_sha256'] != sha256(Path(__file__)):
        raise ValueError('bootstrap driver receipt mismatch; build a fresh receipt')
    expected_python = {'version': pin['python']['version'], 'executable': 'python/bin/python3',
                       'sha256': sha256(output / 'python/bin/python3'),
                       'archive_sha256': pin['python']['sha256'], 'platform': platform.platform(),
                       'libc': list(platform.libc_ver())}
    if receipt['python'] != expected_python:
        raise ValueError('Python operational receipt mismatch')
    commands = json.loads((output / 'bootstrap-commands.json').read_text())
    if not isinstance(commands, list) or not commands or any(c['returncode'] != 0 for c in commands):
        raise ValueError('invalid bootstrap command observations')
    def observation(argv: list[str]) -> JsonObject:
        matches = [c for c in commands if c['argv'] == argv]
        if len(matches) != 1:
            raise ValueError('missing/duplicate operational command observation')
        result: JsonObject = matches[0]
        return result
    installed = str(output / 'evaluator-install/bin/python3')
    details = json.loads(observation([installed, '-I', '-B', '-c', _INSTALL_PROBE])['stdout'])
    site = output / 'evaluator-install/lib/python3.12/site-packages'
    expected_origin = site / 'pkcs11_check/__init__.py'
    expected_sys_path = [str(output / 'python/lib/python312.zip'), str(output / 'python/lib/python3.12'),
                         str(output / 'python/lib/python3.12/lib-dynload'), str(site)]
    if (receipt['installed_origin'] != expected_origin.relative_to(output).as_posix()
            or details['origin'] != str(expected_origin)
            or receipt['installed_sys_path'] != expected_sys_path or details['sys_path'] != expected_sys_path
            or receipt['runtime_origins'] != details['origins']
            or any(value != str(site) for value in receipt['runtime_origins'].values())
            or sorted(name.lower().replace('_', '-') for name in receipt['runtime_origins'])
                != [entry['name'] for entry in receipt['runtime_distributions']]
            or details['distributions'] != receipt['runtime_distributions']):
        raise ValueError('installed operational origin/path receipt mismatch')
    expected_api = {'registered_entries': len(contract['api']), 'origins': {
        'package': str(expected_origin), 'evidence': str(site / 'pkcs11_check/core/evidence/__init__.py'),
        'report_log': str(site / 'pkcs11_check/core/report_log.py'),
        'e4': str(output / 'source-companion/scripts/verify_round_receipt.py')}}
    api_observations = [c for c in commands if c['argv'][:5] == [installed, '-I', '-B', '-c', _API_PROBE]]
    if (len(api_observations) != 1 or json.loads(api_observations[0]['stdout']) != expected_api
            or receipt['public_api_probe'] != expected_api):
        raise ValueError('public API operational receipt mismatch')
    snapshots = []
    for expected_help in contract['help_contract']:
        public_argv = expected_help['command']
        if public_argv[0] == 'pkcs11-check':
            argv = [installed, '-I', '-B', '-c', _PUBLIC_CLI, *public_argv[1:]]
        else:
            argv = [installed, '-I', '-B', str(output / 'source-companion/scripts/verify_round_receipt.py'), '--help']
        result = observation(argv)
        for stream in ('stdout', 'stderr'):
            text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', result[stream])
            digest = hashlib.sha256(' '.join(text.split()).encode()).hexdigest()
            if digest != expected_help[stream + '_canonical_sha256']:
                raise ValueError('public help observation contract mismatch')
        snapshots.append({'command': public_argv, **result})
    if receipt['help_probe'] != {'complete_helps': len(snapshots), 'snapshots': snapshots}:
        raise ValueError('public help operational receipt mismatch')
    tools = {name: observation([str(output / 'tool-env/bin' / name), '--version'])['stdout'].strip()
             for name in ('ruff', 'mypy')}
    tools['actionlint'] = observation([str(output / 'tool-env/actionlint/actionlint'), '-version'])['stdout'].strip()
    if receipt['tools'] != tools:
        raise ValueError('tool operational receipt mismatch')
    versions = {wheel['name']: wheel['version'] for wheel in tooling['wheels']}
    if (tools['ruff'] != 'ruff ' + versions['ruff']
            or not tools['mypy'].startswith('mypy ' + versions['mypy'] + ' ')
            or tools['actionlint'].splitlines()[0] != tooling['actionlint']['version']):
        raise ValueError('tool version observation mismatch')



def verify_receipt(receipt: JsonObject, output: Path, lock_root: Path) -> None:
    """Fail closed on replay drift, missing/extra installed bytes or native drift."""
    output = output.resolve()
    pin = _json(lock_root / 'source.json')
    if pin != _json(_DATA / 'evaluator/source.json') or receipt['source'] != pin:
        raise ValueError('source pin receipt mismatch')
    _verify_operational_metadata(receipt, output, pin)
    if set(receipt['locks']) != {'source.json', 'build-linux-amd64.lock', 'runtime-linux-amd64.lock'}:
        raise ValueError('lock receipt roster mismatch')
    for name, digest in receipt['locks'].items():
        if sha256(lock_root / name) != digest:
            raise ValueError(f'lock mismatch: {name}')
    for key, subtree in [('source_files', 'evaluator-source'), ('python_files', 'python'),
                         ('installed_files', 'evaluator-install'), ('build_files', 'build-env'),
                         ('tool_files', 'tool-env'), ('companion_files', 'source-companion'),
                         ('download_files', 'downloads'), ('dist_files', 'evaluator-dist')]:
        _verify_inventory(output, receipt[key], subtree)
    wheel = receipt['wheel']
    wheel_path = _relative(output, 'evaluator-dist/' + wheel['filename'])
    expected_wheel = {'name': 'pkcs11-check', 'version': '0.2.3', 'filename': wheel_path.name,
                      'sha256': sha256(wheel_path), 'size': wheel_path.stat().st_size}
    if wheel != expected_wheel:
        raise ValueError('wheel receipt mismatch')
    pip = next(w for w in pin['build_wheels'] if w['name'] == 'pip')
    expected = sorted([{'name': w['name'].lower().replace('_', '-'), 'version': w['version']}
                       for w in [*pin['runtime_wheels'], pip, {'name': 'pkcs11-check', 'version': '0.2.3'}]],
                      key=lambda w: w['name'])
    if receipt['runtime_distributions'] != expected:
        raise ValueError('runtime distribution receipt roster mismatch')
    if sha256(_DATA / 'tooling.json') != receipt['tooling_sha256']:
        raise ValueError('tool lock mismatch')
    if receipt.get('contract_sha256') != sha256(_DATA / 'contract.json'):
        raise ValueError('public contract lock mismatch')
    if receipt.get('public_api_probe', {}).get('registered_entries') != len(_json(_DATA / 'contract.json')['api']):
        raise ValueError('public API probe receipt mismatch')
    if receipt.get('help_probe', {}).get('complete_helps') != 11:
        raise ValueError('public help probe receipt mismatch')
    if type(receipt['schema']) is not int or receipt['schema'] != 1 or receipt['source_date_epoch'] != pin['source_date_epoch']:
        raise ValueError('receipt schema/source epoch mismatch')
    if receipt['controller_files'] != [{'path': name, 'sha256': sha256(output / name)} for name in _CONTROLLER_FILES]:
        raise ValueError('controller inventory roster mismatch')
    if receipt['commands'] != json.loads((output / 'bootstrap-commands.json').read_text()):
        raise ValueError('command receipt mismatch')
    if (receipt['python']['version'] != pin['python']['version']
            or receipt['python']['archive_sha256'] != pin['python']['sha256']
            or receipt['python']['executable'] != 'python/bin/python3'
            or receipt['python']['sha256'] != sha256(output / 'python/bin/python3')):
        raise ValueError('Python receipt mismatch')
    if receipt['source_companion'] != {'path': 'source-companion/scripts/verify_round_receipt.py',
                                       'sha256': pin['files']['scripts/verify_round_receipt.py']}:
        raise ValueError('source companion receipt mismatch')
    native_paths = set()
    for observation in json.loads((output / 'native-ldd.json').read_text()):
        for match in re.findall(r'(?:=>\s*)?(/[^\s()]+)', observation['stdout']):
            native_path = Path(match).resolve()
            if native_path.is_file() and not native_path.is_relative_to(output):
                native_paths.add(str(native_path))
    if (receipt['native_dependencies'] != [{'path': name, 'sha256': sha256(Path(name))} for name in sorted(native_paths)]
            or not native_paths):
        raise ValueError('native dependency receipt roster mismatch')
    for entry in receipt['controller_files']:
        if sha256(_relative(output, entry['path'])) != entry['sha256']:
            raise ValueError('controller input/output inventory mismatch')
    for native in receipt['native_dependencies']:
        path = Path(native['path'])
        if not path.is_file() or sha256(path) != native['sha256']:
            raise ValueError('native dependency mismatch')


def acquire_evaluator(source_pin: JsonObject, lock_root: Path, output: Path) -> JsonObject:
    """Build and install the exact reviewed evaluator, preserving a replay receipt.

    Only the packaged reviewed source pin is accepted. The caller chooses an
    output directory, not an implementation import or dependency search path.
    Existing completed output is reused only after complete inventory validation.
    """
    reviewed = _json(_DATA / 'evaluator/source.json')
    if source_pin != reviewed or _json(lock_root / 'source.json') != reviewed:
        raise ValueError('expected reviewed source pin and sealed dependency roster')
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        raise ValueError('bootstrap supports Linux x86_64 only')
    libc, version = platform.libc_ver()
    if libc != 'glibc' or tuple(map(int, version.split('.'))) < (2, 39):
        raise ValueError('bootstrap currently qualified for glibc >= 2.39')
    output = output.resolve()
    receipt_path = output / 'evaluator-build-receipt.json'
    if receipt_path.exists():
        existing_receipt = _json(receipt_path)
        verify_receipt(existing_receipt, output, lock_root)
        return existing_receipt
    if output.exists() and any(p.name != 'downloads' for p in output.iterdir()):
        raise ValueError('incomplete output; preserve it and choose a fresh directory')
    output.mkdir(parents=True, exist_ok=True)
    for group in ('build', 'runtime'):
        _check_lock(lock_root / f'{group}-linux-amd64.lock', source_pin[group + '_wheels'])
    commands: list[JsonObject] = []
    home = output / 'home'
    home.mkdir()
    env = _environment(output, source_pin['source_date_epoch'])

    def run(argv: list[str], *, cwd: Path = output) -> str:
        proc = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, text=True, timeout=300)
        record = {'argv': argv, 'cwd': cwd.relative_to(output).as_posix(),
                  'returncode': proc.returncode, 'stdout': proc.stdout, 'stderr': proc.stderr}
        commands.append(record)
        _write(output / 'bootstrap-commands.json', commands)
        if proc.returncode:
            raise RuntimeError(f'bootstrap command failed: {argv!r}\n{proc.stderr}')
        return proc.stdout

    downloads = output / 'downloads'
    fetch_verified(source_pin, downloads / 'source.tar.gz')
    fetch_verified(source_pin['python'], downloads / 'python.tar.gz')
    extract_verified(downloads / 'python.tar.gz', output)
    python = output / 'python/bin/python3'
    actual_version = run([str(python), '-I', '-B', '-c', 'import platform;print(platform.python_version())']).strip()
    if actual_version != source_pin['python']['version']:
        raise ValueError('interpreter version mismatch')
    source_extract = output / 'source-extract'
    extract_verified(downloads / 'source.tar.gz', source_extract)
    roots = list(source_extract.iterdir())
    if len(roots) != 1 or roots[0].name != 'pkcs11-check-' + source_pin['commit']:
        raise ValueError('source archive root mismatch')
    roots[0].rename(output / 'evaluator-source')
    source_extract.rmdir()
    source = output / 'evaluator-source'
    for name, digest in source_pin['files'].items():
        if sha256(_relative(source, name)) != digest:
            raise ValueError(f'source content mismatch: {name}')
    # The sealed archive hash binds all source bytes, and commit metadata binds tree/epoch.
    metadata_url = f'https://api.github.com/repos/mingulov/pkcs11-check/git/commits/{source_pin["commit"]}'
    with urllib.request.urlopen(urllib.request.Request(metadata_url, headers={'User-Agent': 'P11Lab'}), timeout=60) as response:
        metadata = json.load(response)
    if (metadata['sha'] != source_pin['commit'] or metadata['tree']['sha'] != source_pin['tree']
            or int(datetime.fromisoformat(metadata['committer']['date'].replace('Z', '+00:00')).timestamp()) != source_pin['source_date_epoch']):
        raise ValueError('public commit/tree mismatch')
    _write(output / 'public-commit.json', metadata)
    for group in ('build', 'runtime'):
        target = downloads / (group + '-wheels')
        for spec in source_pin[group + '_wheels']:
            if Path(spec['filename']).name != spec['filename']:
                raise ValueError('unsafe wheel filename')
            fetch_verified(spec, target / spec['filename'])
        if {p.name for p in target.iterdir()} != {w['filename'] for w in source_pin[group + '_wheels']}:
            raise ValueError('wheel directory roster mismatch')
    pip_spec = next(w for w in source_pin['build_wheels'] if w['name'] == 'pip')
    pip_wheel = downloads / 'build-wheels' / pip_spec['filename']

    def create_env(name: str) -> Path:
        target = output / name
        run([str(python), '-I', '-B', '-m', 'venv', '--without-pip', str(target)])
        return target / 'bin/python3'

    def pip_install(interpreter: Path, wheels: Path, lock: Path) -> None:
        # Import only the explicitly hashed pip wheel; neither ensurepip nor host pip.
        code = f'import runpy,sys;sys.path.insert(0,{str(pip_wheel)!r});runpy.run_module("pip",run_name="__main__")'
        run([str(interpreter), '-I', '-B', '-c', code, 'install', '--no-index', '--no-compile',
             '--find-links', str(wheels), '--require-hashes', '-r', str(lock)])

    builder = create_env('build-env')
    pip_install(builder, downloads / 'build-wheels', lock_root.resolve() / 'build-linux-amd64.lock')
    run([str(builder), '-I', '-B', '-m', 'pip', 'check'])
    dist = output / 'evaluator-dist'
    run([str(builder), '-I', '-B', '-m', 'build', '--wheel', '--no-isolation', '--outdir', str(dist), str(source)])
    wheels = list(dist.glob('*.whl'))
    if len(wheels) != 1 or len(list(dist.iterdir())) != 1:
        raise ValueError('expected one evaluator wheel')
    wheel = wheels[0]
    wheel_spec = {'name': 'pkcs11-check', 'version': '0.2.3', 'filename': wheel.name, 'sha256': sha256(wheel), 'size': wheel.stat().st_size}
    runtime_lock = output / 'installed-runtime.lock'
    runtime_lock.write_text(_lock_text([*source_pin['runtime_wheels'], pip_spec, wheel_spec]))
    runtime_wheels = output / 'install-wheels'
    runtime_wheels.mkdir()
    for path in [*(downloads / 'runtime-wheels').iterdir(), pip_wheel, wheel]:
        shutil.copyfile(path, runtime_wheels / path.name)
    installed = create_env('evaluator-install')
    pip_install(installed, runtime_wheels, runtime_lock)
    run([str(installed), '-I', '-B', '-m', 'pip', 'check'])
    shutil.rmtree(runtime_wheels)
    details_code = _INSTALL_PROBE
    details = json.loads(run([str(installed), '-I', '-B', '-c', details_code]))
    expected = sorted([{'name': w['name'].lower().replace('_', '-'), 'version': w['version']}
                       for w in [*source_pin['runtime_wheels'], pip_spec, wheel_spec]], key=lambda w: w['name'])
    if details['distributions'] != expected or not Path(details['origin']).is_relative_to(output / 'evaluator-install'):
        raise ValueError('installed distribution/origin roster mismatch')
    companion = output / 'source-companion'
    (companion / 'scripts').mkdir(parents=True)
    shutil.copyfile(source / 'scripts/verify_round_receipt.py', companion / 'scripts/verify_round_receipt.py')
    for name in source_pin['license_files']:
        shutil.copyfile(source / name, companion / name)
    public_api_probe = json.loads(run([str(installed), '-I', '-B', '-c', _API_PROBE,
                                        str(_DATA / 'contract.json'), str(companion / 'scripts/verify_round_receipt.py')]))
    help_snapshots = []
    for expected_help in _json(_DATA / 'contract.json')['help_contract']:
        public_argv = expected_help['command']
        if public_argv[0] == 'pkcs11-check':
            argv = [str(installed), '-I', '-B', '-c',
                    _PUBLIC_CLI, *public_argv[1:]]
        else:
            argv = [str(installed), '-I', '-B', str(companion / 'scripts/verify_round_receipt.py'), '--help']
        run(argv)
        command_result = commands[-1]
        def canonical_hash(value: str) -> str:
            value = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', value)
            return hashlib.sha256(' '.join(value.split()).encode()).hexdigest()
        if (canonical_hash(command_result['stdout']) != expected_help['stdout_canonical_sha256']
                or canonical_hash(command_result['stderr']) != expected_help['stderr_canonical_sha256']):
            raise ValueError(f'public CLI help contract drift: {public_argv}')
        help_snapshots.append({'command': public_argv, **command_result})
    help_probe = {'complete_helps': len(help_snapshots), 'snapshots': help_snapshots}
    tooling = _json(_DATA / 'tooling.json')
    tool_wheels = downloads / 'tool-wheels'
    for spec in tooling['wheels']:
        fetch_verified(spec, tool_wheels / spec['filename'])
    tool_lock = output / 'tooling.lock'
    tool_lock.write_text(_lock_text([*tooling['wheels'], pip_spec]))
    shutil.copyfile(pip_wheel, tool_wheels / pip_wheel.name)
    tool_python = create_env('tool-env')
    pip_install(tool_python, tool_wheels, tool_lock)
    run([str(tool_python), '-I', '-B', '-m', 'pip', 'check'])
    fetch_verified(tooling['actionlint'], downloads / 'actionlint.tar.gz')
    extract_verified(downloads / 'actionlint.tar.gz', output / 'tool-env/actionlint')
    tools = {}
    for name in ('ruff', 'mypy'):
        tools[name] = run([str(output / 'tool-env/bin' / name), '--version']).strip()
    tools['actionlint'] = run([str(output / 'tool-env/actionlint/actionlint'), '-version']).strip()
    native_paths: set[Path] = set()
    ldd_outputs = []
    for tree in ('python', 'evaluator-install', 'tool-env'):
        for path in sorted((output / tree).rglob('*')):
            if not path.is_file() or path.is_symlink() or not ('.so' in path.name or path == python.resolve()):
                continue
            proc = subprocess.run(['/usr/bin/ldd', str(path)], env=env, capture_output=True, text=True, timeout=30)
            ldd_outputs.append({'path': path.relative_to(output).as_posix(), 'returncode': proc.returncode,
                                'stdout': proc.stdout, 'stderr': proc.stderr})
            for match in re.findall(r'(?:=>\s*)?(/[^\s()]+)', proc.stdout):
                dep = Path(match).resolve()
                if dep.is_file() and not dep.is_relative_to(output):
                    native_paths.add(dep)
            if 'not found' in proc.stdout:
                raise ValueError(f'unresolved native dependency: {path.name}')
    _write(output / 'native-ldd.json', ldd_outputs)
    receipt: JsonObject = {'schema': 1, 'source': source_pin, 'source_date_epoch': source_pin['source_date_epoch'],
        'python': {'version': actual_version, 'executable': 'python/bin/python3', 'sha256': sha256(python),
                   'archive_sha256': source_pin['python']['sha256'], 'platform': platform.platform(), 'libc': [libc, version]},
        'wheel': wheel_spec, 'runtime_distributions': details['distributions'],
        'installed_origin': Path(details['origin']).relative_to(output).as_posix(),
        'installed_sys_path': details['sys_path'], 'runtime_origins': details['origins'],
        'commands': commands, 'tools': tools,
        'locks': {name: sha256(lock_root / name) for name in ('source.json', 'build-linux-amd64.lock', 'runtime-linux-amd64.lock')},
        'tooling_sha256': sha256(_DATA / 'tooling.json'), 'environment': env,
        'bootstrap_driver_sha256': sha256(Path(__file__)),
        'contract_sha256': sha256(_DATA / 'contract.json'),
        'public_api_probe': public_api_probe, 'help_probe': help_probe,
        'controller_files': [{'path': name, 'sha256': sha256(output / name)} for name in _CONTROLLER_FILES],
        'source_companion': {'path': 'source-companion/scripts/verify_round_receipt.py',
                             'sha256': sha256(companion / 'scripts/verify_round_receipt.py')},
        'native_dependencies': [{'path': str(path), 'sha256': sha256(path)} for path in sorted(native_paths)],
        'release_dependencies': _json(_DATA / 'contract.json')['release_dependencies']}
    for key, subtree in [('source_files', 'evaluator-source'), ('python_files', 'python'),
                         ('installed_files', 'evaluator-install'), ('build_files', 'build-env'),
                         ('tool_files', 'tool-env'), ('companion_files', 'source-companion'),
                         ('download_files', 'downloads'), ('dist_files', 'evaluator-dist')]:
        receipt[key] = inventory(output, output / subtree)
    verify_receipt(receipt, output, lock_root)
    _write(receipt_path, receipt)
    return receipt


def audit_consumption(paths: list[Path], contract: JsonObject) -> list[str]:
    """Reject unregistered evaluator imports, attributes and literal CLI argv.

    Supported syntax is static imports, direct typed parameters, constructors,
    registered call results and literal-string argv lists/tuples. Unmodeled
    evaluator return access, indirect argv and dynamic evaluator access fail
    closed. Dynamic evaluator imports/access require a separately reviewed probe;
    they cannot expand this allowlist by observing a candidate implementation.
    """
    import ast

    allowed = set(contract['api']) | set(contract['attributes'])
    errors: list[str] = []
    for path in paths:
        tree = ast.parse(path.read_text(), filename=str(path))
        def audit_scope(owner: ast.AST, inherited_aliases: dict[str, str],
                        inherited_programs: dict[str, str], inherited_arrays: set[str]) -> None:
            nodes: list[ast.AST] = []
            children: list[ast.AST] = []
            scopes = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
            def collect(node: ast.AST) -> None:
                if node is not owner and isinstance(node, scopes):
                    children.append(node)
                    return
                nodes.append(node)
                for child in ast.iter_child_nodes(node):
                    collect(child)
            collect(owner)
            aliases = dict(inherited_aliases)
            program_aliases = dict(inherited_programs)
            cli_arrays = set(inherited_arrays)
            # Every local binding shadows its enclosing name throughout a Python
            # function. Clear all three inference maps before resolving locals.
            def bound_names(target: ast.AST) -> set[str]:
                if isinstance(target, ast.Name):
                    return {target.id}
                if isinstance(target, (ast.Tuple, ast.List)):
                    return {name for element in target.elts for name in bound_names(element)}
                if isinstance(target, ast.Starred):
                    return bound_names(target.value)
                # Attribute/subscript targets read their base and mutate an
                # object; they do not bind that base in the current scope.
                return set()
            local_names: set[str] = set()
            for node in nodes:
                if isinstance(node, ast.arg):
                    local_names.add(node.arg)
                elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    for target in targets:
                        local_names.update(bound_names(target))
                elif isinstance(node, (ast.Import, ast.ImportFrom)):
                    local_names.update(item.asname or item.name.split('.')[0] for item in node.names)
                elif isinstance(node, (ast.Global, ast.Nonlocal)):
                    errors.append(f'{path.name}:{node.lineno}: global/nonlocal adapter mutation requires a reviewed seam')
            local_names.update(child.name for child in children if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)))
            for local_name in local_names:
                aliases.pop(local_name, None)
                program_aliases.pop(local_name, None)
                cli_arrays.discard(local_name)
            for node in nodes:
                if isinstance(node, ast.ImportFrom) and (node.module or '').startswith('pkcs11_check'):
                    module = node.module or ''
                    for item in node.names:
                        if module == 'pkcs11_check.core.evidence':
                            name = item.name
                        elif module == 'pkcs11_check.core.report_log':
                            name = 'core.report_log.' + item.name
                        else:
                            name = module + '.' + item.name
                        aliases[item.asname or item.name] = name
                        if name not in allowed:
                            errors.append(f'{path.name}:{node.lineno}: unregistered API {name}')
                elif isinstance(node, ast.Import):
                    for item in node.names:
                        if item.name.startswith('pkcs11_check'):
                            if not item.asname:
                                errors.append(f'{path.name}:{node.lineno}: evaluator module import requires explicit alias')
                            aliases[item.asname or item.name] = item.name
                            if item.name not in {'pkcs11_check.core.evidence', 'pkcs11_check.core.report_log'}:
                                errors.append(f'{path.name}:{node.lineno}: unregistered module {item.name}')
            classes = {name for name, spec in contract['api_contract'].items() if 'fields' in spec}

            def qualified(node: ast.AST, bindings: dict[str, str] | None = None) -> str | None:
                lookup = aliases if bindings is None else bindings
                if isinstance(node, ast.Name):
                    return lookup.get(node.id)
                if isinstance(node, ast.Call):
                    function_name = qualified(node.func, bindings)
                    if function_name in classes:
                        return function_name
                    if function_name in contract['api_contract']:
                        signature = contract['api_contract'][function_name].get('signature', '')
                        match = re.search(r" -> '([^']+)'$", signature)
                        if match and match[1] in classes:
                            return match[1]
                    if function_name:
                        # An unmodeled evaluator-derived return is never silently
                        # treated as an ordinary, untracked Python object.
                        return function_name + '<unresolved-result>'
                if isinstance(node, ast.Attribute):
                    parent = qualified(node.value, bindings)
                    if parent:
                        if parent == 'pkcs11_check.core.evidence':
                            return node.attr
                        if parent == 'pkcs11_check.core.report_log':
                            return 'core.report_log.' + node.attr
                        if parent == 'core.report_log.SessionCompletionTracker':
                            parent = 'SessionCompletionTracker'
                        return parent + '.' + node.attr
                return None
            # Propagate explicit constructors and registered return types to local
            # aliases so row/verdict field consumption is also inventoried.
            for parameter in nodes:
                if not isinstance(parameter, ast.arg) or parameter.annotation is None:
                    continue
                annotation = parameter.annotation
                if isinstance(annotation, ast.Constant) and isinstance(annotation.value, str):
                    annotation = ast.parse(annotation.value, mode='eval').body
                parameter_type = qualified(annotation, inherited_aliases)
                if parameter_type:
                    aliases[parameter.arg] = parameter_type
                elif any(qualified(part, inherited_aliases) for part in ast.walk(annotation)):
                    errors.append(f'{path.name}:{parameter.lineno}: unsupported evaluator annotation requires a direct registered type')
                    aliases[parameter.arg] = '<unresolved-evaluator-parameter>'
            for _ in range(3):
                for assignment in nodes:
                    if not isinstance(assignment, (ast.Assign, ast.AnnAssign)):
                        continue
                    targets = assignment.targets if isinstance(assignment, ast.Assign) else [assignment.target]
                    value = assignment.value
                    value_name = qualified(value) if value is not None else None
                    if isinstance(value, ast.Call):
                        function_name = qualified(value.func)
                        if function_name in classes:
                            value_name = function_name
                        elif function_name in contract['api_contract']:
                            signature = contract['api_contract'][function_name].get('signature', '')
                            match = re.search(r" -> '([^']+)'$", signature)
                            if match and match[1] in classes:
                                value_name = match[1]
                    if isinstance(assignment, ast.AnnAssign):
                        value_name = qualified(assignment.annotation) or value_name
                    if value_name:
                        for target in targets:
                            if isinstance(target, ast.Name):
                                previous = aliases.get(target.id)
                                if previous is not None and previous != value_name:
                                    aliases[target.id] = '<ambiguous-evaluator-binding>'
                                    errors.append(f'{path.name}:{assignment.lineno}: ambiguous evaluator binding {target.id}')
                                else:
                                    aliases[target.id] = value_name
            # Recognize a literal program alias too, so moving only the executable
            # token to a variable cannot hide an otherwise dynamic evaluator argv.
            for assignment in nodes:
                if isinstance(assignment, ast.Assign) and isinstance(assignment.value, ast.Constant):
                    program_value = assignment.value.value
                    if isinstance(program_value, str) and (program_value in {'pkcs11-check', 'pkcs11_check'}
                                                   or program_value.endswith('/verify_round_receipt.py')
                                                   or program_value == 'verify_round_receipt.py'):
                        for target in assignment.targets:
                            if isinstance(target, ast.Name):
                                program_aliases[target.id] = program_value
            def literal_program(node: ast.AST) -> str | None:
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    return node.value
                if isinstance(node, ast.Name):
                    return program_aliases.get(node.id)
                return None
            def is_evaluator_program(program: str | None) -> bool:
                return program is not None and (program in {'pkcs11-check', 'pkcs11_check'}
                                                 or program.endswith('/verify_round_receipt.py')
                                                 or program == 'verify_round_receipt.py')
            for assignment in nodes:
                if isinstance(assignment, ast.Assign) and isinstance(assignment.value, (ast.List, ast.Tuple)):
                    if any(is_evaluator_program(literal_program(part)) for part in assignment.value.elts):
                        cli_arrays.update(target.id for target in assignment.targets if isinstance(target, ast.Name))
            for node in nodes:
                if isinstance(node, ast.Attribute):
                    qualified_name = qualified(node)
                    if qualified_name and qualified_name not in allowed and not qualified_name.startswith('pkcs11_check.core.'):
                        errors.append(f'{path.name}:{node.lineno}: unregistered attribute {qualified_name}')
                if isinstance(node, ast.Call):
                    runner = node.func.attr if isinstance(node.func, ast.Attribute) else node.func.id if isinstance(node.func, ast.Name) else ''
                    if runner in {'run', 'Popen', 'check_call', 'check_output'} and node.args:
                        shell_argument = node.args[0]
                        if isinstance(shell_argument, ast.Constant) and isinstance(shell_argument.value, str):
                            words = shell_argument.value.split()
                            if any(is_evaluator_program(word) for word in words):
                                errors.append(f'{path.name}:{node.lineno}: shell/string evaluator argv is unsupported; use a literal list')
                    if isinstance(node.func, ast.Name) and node.func.id in {'getattr', 'setattr', 'vars', 'dir', 'eval', 'exec', '__import__'}:
                        if any(qualified(arg) or (isinstance(arg, ast.Constant) and isinstance(arg.value, str)
                                                  and 'pkcs11_check' in arg.value) for arg in node.args):
                            errors.append(f'{path.name}:{node.lineno}: dynamic evaluator access')
                    if (isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name)
                            and node.func.value.id in cli_arrays and node.func.attr in {'append', 'extend', 'insert'}):
                        errors.append(f'{path.name}:{node.lineno}: dynamic evaluator argv requires registration')
                    if isinstance(node.func, ast.Attribute) and node.func.attr == 'import_module':
                        if not node.args or not isinstance(node.args[0], ast.Constant) or 'pkcs11_check' in str(node.args[0].value):
                            errors.append(f'{path.name}:{node.lineno}: dynamic evaluator import')
                if isinstance(node, (ast.List, ast.Tuple)) and node.elts:
                    strings = [resolved_program for item in node.elts if (resolved_program := literal_program(item)) is not None]
                    e4_index = next((index for index, argument in enumerate(strings)
                                     if argument.endswith('/verify_round_receipt.py') or argument == 'verify_round_receipt.py'), None)
                    if not strings or (not {'pkcs11-check', 'pkcs11_check'}.intersection(strings) and e4_index is None):
                        continue
                    if any(not isinstance(argument, ast.Constant) or not isinstance(argument.value, str) for argument in node.elts):
                        errors.append(f'{path.name}:{node.lineno}: unresolved evaluator argv; literal strings are required')
                    if e4_index is not None:
                        start = e4_index
                    else:
                        start = strings.index('pkcs11-check') if 'pkcs11-check' in strings else strings.index('pkcs11_check')
                    tail = strings[start + 1:]
                    command = 'verify-round-receipt' if e4_index is not None else next((item for item in tail if not item.startswith('-')), 'root')
                    signature = contract['cli_signatures'].get(command)
                    if signature is None:
                        errors.append(f'{path.name}:{node.lineno}: unregistered CLI command {command}')
                        continue
                    flags = {'--help'}
                    for parameter in signature['parameters']:
                        flags.update(parameter['opts'])
                        flags.update(parameter['secondary_opts'])
                    for argument in tail:
                        if argument.startswith('-') and argument.split('=')[0] not in flags:
                            errors.append(f'{path.name}:{node.lineno}: unregistered CLI flag {argument}')
            if isinstance(owner, ast.ClassDef) and (inherited_aliases or inherited_programs or inherited_arrays
                                                    or aliases or program_aliases or cli_arrays):
                errors.append(f'{path.name}:{owner.lineno}: class-local evaluator bindings require a reviewed seam')
            for child in children:
                audit_scope(child, aliases, program_aliases, cli_arrays)

        audit_scope(tree, {}, {}, set())
    return errors
