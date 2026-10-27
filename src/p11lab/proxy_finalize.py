"""Proxy exit-finalize hook for checker children (F3 follow-up).

The checker's preflight helper initializes the module and exits without
C_Finalize; against a single-context proxy daemon its orphaned context blocks
the test session. This module ships a site customization that finalizes at
interpreter exit, installed per-run for proxy checker children only. The hook
is preflight-gated (exact argv match), Linux-scoped (Unix loader alignment),
and evidence-recording (silent inactivity is impossible to miss).
"""
import hashlib
import json
import os
from pathlib import Path

HOOK_VERSION = '1'
HOOK_DIRNAME = 'p11lab-proxy-hook'
HOOK_FILENAME = 'sitecustomize.py'
HOOK_META_FILENAME = 'finalize-hook.json'
EVIDENCE_PREFIX = 'finalize-evidence-'
PREFLIGHT_MODULE = 'pkcs11_check.core.preflight'
CKR_OK = 0
CKR_CRYPTOKI_NOT_INITIALIZED = 0x190

HOOK_SOURCE = '''"""P11Lab proxy exit-finalize (generated; do not edit by hand)."""
import atexit
import json
import os
import sys

_HOOK_VERSION = '1'
_PREFLIGHT_MODULE = 'pkcs11_check.core.preflight'


def _is_preflight(argv):
    # Restricted to the exact producer shape [exe, -m, preflight, ...]; the
    # checker spawns nothing else, and anything fancier (flag clusters,
    # wrappers, -c injections) fails loud downstream via missing evidence
    # instead of risking a divergent hand-rolled option parser.
    args = list(argv)
    return len(args) > 2 and args[1] == '-m' and args[2] == _PREFLIGHT_MODULE


def _module_arg(argv):
    # Last --module wins (argparse parity), searched only in the preflight
    # argument segment so interpreter values can never shadow it.
    value = None
    segment = list(argv)[3:]
    for position, token in enumerate(segment):
        if token == '--module' and position + 1 < len(segment):
            value = segment[position + 1]
    return value


def _write_evidence(path, payload):
    try:
        with open(path, 'w') as stream:
            json.dump(payload, stream, indent=2)
    except OSError:
        pass


def _finalize_at_exit(module_path, evidence_path, module_argv, pid):
    if os.getpid() != pid:
        return
    attempted, rv, failure = False, None, None
    try:
        noload = os.RTLD_NOLOAD
    except AttributeError:
        failure = 'noload-unavailable'
    else:
        import ctypes
        try:
            lib = ctypes.CDLL(module_path, mode=noload)
        except Exception:
            failure = 'not-loaded'
        else:
            try:
                getlist = lib.C_GetFunctionList
                getlist.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
                getlist.restype = ctypes.c_ulong

                class _Prefix(ctypes.Structure):
                    _fields_ = [('major', ctypes.c_ubyte),
                                ('minor', ctypes.c_ubyte),
                                ('C_Initialize', ctypes.c_void_p),
                                ('C_Finalize', ctypes.c_void_p)]

                functions = ctypes.c_void_p()
                if getlist(ctypes.byref(functions)) != 0 or not functions.value:
                    failure = 'no-funclist'
                else:
                    address = _Prefix.from_address(functions.value).C_Finalize
                    if not address:
                        failure = 'null-finalize'
                    else:
                        finalize = ctypes.CFUNCTYPE(ctypes.c_ulong, ctypes.c_void_p)(address)
                        attempted = True
                        rv = int(finalize(None))
            except Exception:
                failure = 'finalize-error'
    if evidence_path is not None:
        _write_evidence(evidence_path, {
            'hook_version': _HOOK_VERSION, 'pid': pid,
            'module_env': module_path, 'module_argv': module_argv,
            'attempted': attempted, 'rv': rv,
            'failure_class': failure or 'none',
        })


def _maybe_register():
    if sys.platform != 'linux':
        return
    argv = list(getattr(sys, 'orig_argv', []) or [])
    if not _is_preflight(argv):
        return
    module_path = os.environ.get('P11LAB_MODULE')
    evidence_dir = os.environ.get('P11LAB_PROXY_FINALIZE_DIR')
    pid = os.getpid()
    module_argv = _module_arg(argv)
    if not module_path or module_argv != module_path:
        if evidence_dir:
            if not module_path:
                failure = 'no-module-env'
            elif module_argv is None:
                failure = 'no-module-arg'
            else:
                failure = 'module-mismatch'
            _write_evidence(os.path.join(evidence_dir, 'finalize-evidence-%d.json' % pid), {
                'hook_version': _HOOK_VERSION, 'pid': pid,
                'module_env': module_path, 'module_argv': module_argv,
                'attempted': False, 'rv': None, 'failure_class': failure,
            })
        return
    evidence_path = None
    if evidence_dir:
        evidence_path = os.path.join(evidence_dir, 'finalize-evidence-%d.json' % pid)
    atexit.register(_finalize_at_exit, module_path, evidence_path, module_argv, pid)


_maybe_register()
'''


def _write_exclusive(path, payload):
    if path.is_symlink():
        raise FileExistsError('hook path is a symlink: %s' % path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(payload)
    except BaseException:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise
    os.chmod(path, 0o600)


def install_hook(directory):
    """Write the hook + metadata into a fresh run-owned directory.

    Returns {'dir', 'sha256', 'version'}. Fails closed on relative paths,
    path separators, existing files, symlinks, and unverified bytes.
    """
    target = Path(directory)
    if not target.is_absolute():
        raise ValueError('hook directory must be absolute')
    if os.pathsep in str(target):
        raise ValueError('hook directory must not contain a path separator')
    if target.is_symlink() or target.exists():
        raise FileExistsError('hook directory already exists: %s' % target)
    target.mkdir(mode=0o700, parents=False, exist_ok=False)
    os.chmod(target, 0o700)
    payload = HOOK_SOURCE.encode('utf-8')
    hook_file = target / HOOK_FILENAME
    _write_exclusive(hook_file, payload)
    if hook_file.read_bytes() != payload:
        raise ValueError('hook write verification failed')
    digest = hashlib.sha256(payload).hexdigest()
    meta = {'version': HOOK_VERSION, 'sha256': digest, 'scope': 'preflight'}
    meta_file = target / HOOK_META_FILENAME
    _write_exclusive(meta_file, (json.dumps(meta, indent=2) + '\n').encode('utf-8'))
    if json.loads(meta_file.read_text()) != meta:
        raise ValueError('hook metadata verification failed')
    return {'dir': str(target), 'sha256': digest, 'version': HOOK_VERSION}


def reconcile_evidence(hook_dir, *, module_path, hook_version, hook_sha256):
    """Classify per-preflight finalize evidence; [] means every preflight ran clean.

    The expected hook identity and module binding arrive from durable
    provenance (not current code), so revalidation never retro-fails history.
    At least one evidence file is required and every file must be fully
    consistent; anything else yields one error string per problem. RV 0
    (released) and CKR_CRYPTOKI_NOT_INITIALIZED (already finalized, e.g. a
    future well-behaved checker) both count as clean.
    """
    root = Path(hook_dir)
    if not root.is_dir():
        return ['proxy finalize evidence missing: %s' % root]
    try:
        meta = json.loads((root / HOOK_META_FILENAME).read_text())
    except (OSError, ValueError):
        return ['proxy finalize install metadata unreadable: %s' % root]
    if (
        not isinstance(meta, dict)
        or meta.get('version') != hook_version
        or meta.get('sha256') != hook_sha256
        or meta.get('scope') != 'preflight'
    ):
        return ['proxy finalize install identity mismatch: %s' % root]
    try:
        disk = (root / HOOK_FILENAME).read_bytes()
    except OSError:
        return ['proxy finalize hook unreadable: %s' % root]
    if hashlib.sha256(disk).hexdigest() != hook_sha256:
        return ['proxy finalize hook bytes differ from locked install: %s' % root]
    try:
        names = sorted(
            path.name
            for path in root.iterdir()
            if path.name.startswith(EVIDENCE_PREFIX) and path.name.endswith('.json')
        )
    except OSError:
        return ['proxy finalize evidence unreadable: %s' % root]
    if not names:
        return ['proxy finalize evidence missing: no preflight finalize observed']
    errors = []
    for name in names:
        errors.extend(
            _reconcile_record(root / name, name, module_path, hook_version)
        )
    return errors


def _reconcile_record(path, name, module_path, hook_version):
    try:
        record = json.loads(path.read_text())
    except (OSError, ValueError):
        return ['proxy finalize evidence unreadable: %s' % name]
    if not isinstance(record, dict):
        return ['proxy finalize evidence malformed: %s' % name]
    stem = name[len(EVIDENCE_PREFIX):-len('.json')]
    pid = record.get('pid')
    if not stem.isdigit() or type(pid) is not int or pid <= 0 or pid != int(stem):
        return ['proxy finalize evidence pid mismatch: %s' % name]
    if record.get('hook_version') != hook_version:
        return ['proxy finalize evidence version mismatch: %s' % name]
    if record.get('module_env') != module_path or record.get('module_argv') != module_path:
        return ['proxy finalize evidence module mismatch: %s' % name]
    if record.get('attempted') is not True:
        return [
            'proxy finalize not attempted: %s (failure_class=%r)'
            % (name, record.get('failure_class'))
        ]
    rv = record.get('rv')
    if record.get('failure_class') != 'none' or type(rv) is not int or rv not in (
        CKR_OK,
        CKR_CRYPTOKI_NOT_INITIALIZED,
    ):
        return [
            'proxy finalize failed: %s (rv=%r failure_class=%r)'
            % (name, rv, record.get('failure_class'))
        ]
    return []
