"""Install a prebuilt wheel inside the existing protected M05 Docker boundary.

Typed selections are controller inputs, not authentication of caller JSON. This
seam produces local installation observations and never establishes CI authority.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import re
import signal
import shutil
import tempfile
import threading
from pathlib import Path
from typing import Callable
from uuid import uuid4

from ..docker import Docker, DockerError
from ..models import ArtifactRef
from . import JsonObject
from .bootstrap import inventory, sha256
from .evidence import read_products
from .inputs import DIGEST, SHA, REV, SealedToolInputs, canonical, digest, inspect_opaque_wheel, load_json, read_source_archive, safe_path
from .worker import _OutputVolume, _inspection, _installed_roster, _verify_installed, check_startup_diagnostics


@dataclass(frozen=True)
class WheelSnapshot:
    path: Path
    sha256: str


@dataclass(frozen=True)
class ProtectedRuntimeSelection:
    """Controller-selected runtime and exact wheels, independent of candidate JSON."""
    image: str
    layers: tuple[str, ...]
    config_sha256: str
    control_revision: str
    python_version: str
    tools: SealedToolInputs
    candidate: WheelSnapshot
    dependencies: tuple[WheelSnapshot, ...]
    timeout_seconds: int = 60
    max_output_bytes: int = 96 * 1024 * 1024


_DRIVER = r'''import os,resource,runpy,subprocess,sys
from pathlib import Path
phase=sys.argv[1]
limit=int(sys.argv[2]); expected=sys.argv[3]
resource.setrlimit(resource.RLIMIT_FSIZE,(limit,limit))
if '.'.join(str(x) for x in sys.version_info[:3]) != expected: raise SystemExit('runtime version mismatch')
env={'PATH':'/usr/bin:/bin','HOME':'/scratch/home','LANG':'C.UTF-8','LC_ALL':'C.UTF-8',
     'LD_LIBRARY_PATH':'/inputs/python/lib','PYTHONDONTWRITEBYTECODE':'1','PIP_CONFIG_FILE':'/dev/null',
     'PIP_DISABLE_PIP_VERSION_CHECK':'1','PIP_NO_INPUT':'1'}
python='/inputs/python/bin/python3'
if phase=='install':
    bootstrap="import runpy,sys;sys.path.insert(0,sys.argv.pop(1));runpy.run_module('pip',run_name='__main__')"
    args=[python,'-I','-B','-c',bootstrap,'/inputs/pip.whl','install','--no-index','--no-deps',
          '--no-compile','--require-hashes','--target','/out/site','-r','/inputs/requirements.lock']
else:
    args=[python,'-I','-B','-c',"import site;site.addsitedir('/installed/site');print('candidate site startup completed',flush=True)"]
result=subprocess.run(args,env=env,check=False)
raise SystemExit(result.returncode)
'''


def install_prebuilt_candidate(selection: ProtectedRuntimeSelection, output_dir: Path, *,
                               engine: Docker | None = None,
                               interrupted: Callable[[], int | None] | None = None) -> JsonObject:
    """Install exact prebuilt snapshots; no source build, retry, or authority claim."""
    if type(selection) is not ProtectedRuntimeSelection or type(selection.tools) is not SealedToolInputs:
        raise TypeError('typed protected runtime selection required')
    if (not DIGEST.fullmatch(selection.image) or not selection.layers
            or any(not DIGEST.fullmatch(v) for v in selection.layers)
            or not SHA.fullmatch(selection.config_sha256) or not REV.fullmatch(selection.control_revision)
            or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', selection.python_version)
            or type(selection.timeout_seconds) is not int or not 1 <= selection.timeout_seconds <= 300
            or type(selection.max_output_bytes) is not int or not 1024 <= selection.max_output_bytes <= 128 * 1024 * 1024):
        raise ValueError('invalid protected runtime selection')
    snapshots = (selection.candidate, *selection.dependencies)
    if any(type(item) is not WheelSnapshot or not SHA.fullmatch(item.sha256) for item in snapshots):
        raise ValueError('invalid wheel selection')
    names = [safe_path(item.path.name) for item in snapshots]
    if len(names) != len(set(names)) or any(not re.fullmatch(r'[A-Za-z0-9_.+-]+\.whl', name) for name in names):
        raise ValueError('duplicate or invalid wheel filenames')
    # Snapshot and hash all inputs before output creation or candidate execution.
    wheel_bytes = [read_source_archive(item.path) for item in snapshots]
    if any(hashlib.sha256(raw).hexdigest() != item.sha256 for item, raw in zip(snapshots, wheel_bytes)):
        raise ValueError('prebuilt wheel snapshot mismatch')
    for raw in wheel_bytes:
        inspect_opaque_wheel(raw)
    tools = selection.tools
    receipt = tools.root / 'evaluator-build-receipt.json'
    if not SHA.fullmatch(tools.receipt_sha256) or sha256(receipt) != tools.receipt_sha256:
        raise ValueError('runtime tool receipt mismatch')
    pip_records = [load_json(row) for row in tools.wheels if load_json(row).get('name') == 'pip']
    if len(pip_records) != 1:
        raise ValueError('sealed pip wheel missing or ambiguous')
    pip = pip_records[0]
    pip_name = safe_path(pip['filename'])
    if pip_name != Path(pip_name).name:
        raise ValueError('invalid sealed pip wheel')
    pip_raw = read_source_archive(tools.root / 'downloads/build-wheels' / pip_name)
    if len(pip_raw) != pip['size'] or hashlib.sha256(pip_raw).hexdigest() != pip['sha256']:
        raise ValueError('sealed pip bytes mismatch')
    output_dir = output_dir.absolute()
    output_dir.mkdir(parents=True, exist_ok=False)
    engine = engine or Docker()
    context = {'image': selection.image, 'layers': list(selection.layers), 'config_sha256': selection.config_sha256,
               'control_revision': selection.control_revision, 'python_version': selection.python_version,
               'tool_receipt_sha256': tools.receipt_sha256,
               'wheels': [{'filename': name, 'sha256': item.sha256} for name, item in zip(names, snapshots)],
               'max_output_bytes': selection.max_output_bytes}
    context_hash = digest(context)
    result: JsonObject = {'schema_version': 1, 'scope': 'local-controller', 'status': 'incomplete',
                          'context_sha256': context_hash, 'stages': [], 'cleanup_errors': [], 'qualification': False}
    (output_dir / 'protected-context.json').write_bytes(canonical(context))
    labels = {'p11lab.candidate': uuid4().hex, 'p11lab.context': context_hash}
    stage = Path(tempfile.mkdtemp(prefix='p11lab-prebuilt-'))
    owned = None
    volume = None
    stop_state: dict[str, int | None] = {'signal': None}
    old_handlers: dict = {}
    def receive(signum: int, frame: object) -> None:
        stop_state['signal'] = stop_state['signal'] or signum
    def cancelled() -> int | None:
        return stop_state['signal'] or (interrupted() if interrupted else None)
    if threading.current_thread() is threading.main_thread():
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            old_handlers[signum] = signal.signal(signum, receive)
    try:
        shutil.copytree(tools.root / 'python', stage / 'python', symlinks=True)
        for path in (stage / 'python').rglob('*'):
            if path.is_symlink() and not path.resolve().is_relative_to((stage / 'python').resolve()):
                raise ValueError('runtime Python link escapes closure')
        python_roster = [load_json(row) for row in tools.python_members]
        if inventory(stage, stage / 'python') != python_roster:
            raise ValueError('runtime Python inventory mismatch')
        result['protected_python_before_sha256'] = digest(python_roster)
        for path in (stage / 'python').rglob('*'):
            if path.is_dir() and not path.is_symlink():
                path.chmod(0o755)
        (stage / 'python').chmod(0o755)
        (stage / 'wheels').mkdir()
        for name, raw in zip(names, wheel_bytes):
            (stage / 'wheels' / name).write_bytes(raw)
        (stage / 'pip.whl').write_bytes(pip_raw)
        requirements = ''.join('file:///inputs/wheels/' + name + ' --hash=sha256:' + item.sha256 + '\n'
                               for name, item in zip(names, snapshots))
        (stage / 'requirements.lock').write_text(requirements)
        (stage / 'driver.py').write_text(_DRIVER)
        stage.chmod(0o755)
        original_names = ['driver.py', 'pip.whl', 'requirements.lock', *('wheels/' + name for name in names)]
        originals = {name: sha256(stage / name) for name in original_names}
        result['protected_originals_before'] = originals
        artifact = ArtifactRef('image', selection.image, selection.image[7:], 'linux/amd64')
        image = engine.image(artifact)
        if (digest(image.get('Config')) != selection.config_sha256
                or image.get('RootFS', {}).get('Layers') != list(selection.layers)
                or image.get('Config', {}).get('Volumes')
                or any(e.split('=', 1)[0] not in {'PATH', 'LANG', 'LC_ALL', 'TZ'}
                       for e in image.get('Config', {}).get('Env', []))):
            raise ValueError('protected runtime image mismatch')
        expected_files: set[str] = set()
        for name in names:
            roster = set(_installed_roster(stage / 'wheels' / name))
            if expected_files & roster:
                raise ValueError('installed wheel roster collision')
            expected_files.update(roster)
        installed_manifest: list[JsonObject] | None = None
        for phase in ('install', 'startup'):
            if cancelled():
                raise InterruptedError('prebuilt installation cancelled')
            product = output_dir / phase
            product.mkdir(mode=0o755)
            record: JsonObject = {'phase': phase, 'name': 'p11lab-prebuilt-' + labels['p11lab.candidate'] + '-' + phase}
            result['stages'].append(record)
            volume = _OutputVolume(engine, artifact.reference, labels, record['name'] + '-output', selection.max_output_bytes, record)
            volume.open()
            options = ['--pull=never', '--user', '65532:65532', '--read-only', '--network', 'none',
                       '--ipc', 'private', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges=true',
                       '--pids-limit', '64', '--memory', '384m', '--memory-swap', '384m', '--cpus', '1',
                       '--ulimit', 'nofile=256:256', '--log-driver', 'none', '--workdir', '/scratch',
                       '--tmpfs', f'/scratch:rw,nosuid,nodev,mode=1777,size={selection.max_output_bytes},nr_inodes=10000',
                       '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,mode=1777,size=16m,nr_inodes=4096',
                       '--env', 'HOME=/scratch/home', '--env', 'PATH=/usr/bin:/bin', '--env', 'LANG=C.UTF-8',
                       '--env', 'LD_LIBRARY_PATH=/inputs/python/lib', '--env', 'PYTHONDONTWRITEBYTECODE=1',
                       '--mount', f'type=bind,src={stage},dst=/inputs,readonly',
                       '--mount', f'type=volume,src={volume.name},dst=/out', '--entrypoint', '/inputs/python/bin/python3']
            if phase == 'startup':
                if read_products(output_dir / 'install', tuple(r['path'] for r in installed_manifest or []),
                                 max_bytes=selection.max_output_bytes) != installed_manifest:
                    raise ValueError('installed bytes changed before startup')
                options += ['--mount', f"type=bind,src={output_dir / 'install'},dst=/installed,readonly"]
            try:
                owned = engine.create(artifact.reference, ['-I', '-B', '/inputs/driver.py', phase,
                                      str(selection.max_output_bytes), selection.python_version], options, labels, record['name'])
            except DockerError as error:
                if error.resource and error.resource[0] == 'container':
                    owned = error.resource[1]
                record['uncertain_resource'] = error.uncertain_resource
                raise
            record['container_id'] = owned
            before = _inspection(engine, owned, labels)
            record['inspect_before'] = before
            host = before.get('HostConfig', {})
            mounts = {mount.get('Destination'): mount for mount in before.get('Mounts', [])}
            tmpfs = {'/scratch': f'rw,nosuid,nodev,mode=1777,size={selection.max_output_bytes},nr_inodes=10000',
                     '/tmp': 'rw,nosuid,nodev,noexec,mode=1777,size=16m,nr_inodes=4096'}
            if (host.get('PidMode') not in ('', 'private') or host.get('NetworkMode') != 'none'
                    or host.get('ReadonlyRootfs') is not True or 'ALL' not in (host.get('CapDrop') or [])
                    or 'no-new-privileges=true' not in (host.get('SecurityOpt') or [])
                    or host.get('Tmpfs') != tmpfs or host.get('PidsLimit') != 64
                    or host.get('Memory') != 384 * 1024 * 1024
                    or set(mounts) != ({'/inputs', '/out', '/installed'} if phase == 'startup' else {'/inputs', '/out'})
                    or before.get('Config', {}).get('User') != '65532:65532'
                    or mounts.get('/inputs', {}).get('RW') is not False
                    or mounts.get('/out', {}).get('Name') != volume.name
                    or (phase == 'startup' and mounts.get('/installed', {}).get('RW') is not False)):
                raise DockerError('candidate isolation inspection mismatch')
            execution = engine.execute(owned, selection.timeout_seconds, cancelled)
            record['execution'] = asdict(execution)
            engine.stop(owned, labels)
            stopped = _inspection(engine, owned, labels)
            record['inspect_stopped'] = stopped
            if stopped['State']['Running'] or stopped['State']['Pid'] != 0:
                raise DockerError('candidate not stopped before readback')
            if execution.returncode or execution.timed_out or cancelled() or execution.stdout_truncated or execution.stderr_truncated:
                raise ValueError('candidate execution failed or output truncated')
            if phase == 'startup':
                check_startup_diagnostics(execution.stderr, stderr_truncated=execution.stderr_truncated)
            expected = tuple(sorted(expected_files)) if phase == 'install' else ()
            volume.readback(product, expected, cancelled)
            if phase == 'install':
                for name in names:
                    _verify_installed(stage / 'wheels' / name, product)
                installed_manifest = read_products(product, expected, max_bytes=selection.max_output_bytes)
                result['installed_files'] = installed_manifest
                result['installed_manifest_sha256'] = digest(installed_manifest)
            engine.remove('container', owned, labels)
            owned = None
            result['cleanup_errors'].extend(volume.close())
            volume = None
            if result['cleanup_errors']:
                raise DockerError('prebuilt output cleanup incomplete')
        result['status'] = 'installed'
    except (Exception, KeyboardInterrupt) as error:
        result['status'] = 'infrastructure-error'
        result['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        if owned:
            try:
                engine.stop(owned, labels)
            except Exception as error:
                result['cleanup_errors'].append('container stop: ' + str(error))
            try:
                engine.remove('container', owned, labels)
            except Exception as error:
                result['cleanup_errors'].append('container remove: ' + str(error))
        if volume is not None:
            result['cleanup_errors'].extend(volume.close())
        if 'protected_originals_before' in result:
            try:
                result['protected_originals_after'] = {name: sha256(stage / name) for name in result['protected_originals_before']}
                if result['protected_originals_after'] != result['protected_originals_before']:
                    raise ValueError('protected originals changed')
                if any(hashlib.sha256(read_source_archive(item.path)).hexdigest() != item.sha256 for item in snapshots):
                    raise ValueError('caller wheel snapshots changed')
                python_after = inventory(stage, stage / 'python')
                result['protected_python_after_sha256'] = digest(python_after)
                if python_after != python_roster or sha256(receipt) != tools.receipt_sha256:
                    raise ValueError('protected runtime inputs changed')
            except (OSError, ValueError):
                result['status'] = 'infrastructure-error'
                result['error'] = 'protected input preservation check failed'
        if result['cleanup_errors']:
            result['status'] = 'infrastructure-error'
        try:
            shutil.rmtree(stage)
        except OSError as error:
            result['status'] = 'infrastructure-error'
            result['cleanup_errors'].append('staging cleanup: ' + str(error))
        for signum, handler in old_handlers.items():
            signal.signal(signum, handler)
        result['interrupted_signal'] = cancelled()
        (output_dir / 'installation-observation.json').write_bytes(canonical(result) + b'\n')
    return result
