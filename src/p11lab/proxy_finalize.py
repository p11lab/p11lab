"""Proxy exit-finalize hook for checker children (F3 follow-up).

The checker's preflight helper initializes the module and exits without
C_Finalize; against a single-context proxy daemon its orphaned context blocks
the test session. Unit workers share the defect for p11_module-only tests
(the checker's sessionfinish finalizes only when _RAW_INSTANCE is stashed).
This module ships a site customization that finalizes at interpreter exit,
installed per-run for proxy checker children only. The hook is role-gated
(exact preflight argv match, unit workers by -m pytest plus the checker's
unit-child marker), Linux-scoped (Unix loader alignment), and
evidence-recording (silent inactivity is impossible to miss).
"""
import hashlib
import json
import os
from pathlib import Path

HOOK_VERSION = '2'
HOOK_DIRNAME = 'p11lab-proxy-hook'
HOOK_FILENAME = 'sitecustomize.py'
HOOK_META_FILENAME = 'finalize-hook.json'
EVIDENCE_PREFIX = 'finalize-evidence-'
PREFLIGHT_MODULE = 'pkcs11_check.core.preflight'
UNIT_CHILD_ENV = 'PKCS11_CHECK_UNIT_CHILD'
HOOK_SCOPE = 'preflight+unit'
# Installed scope by hook version, so revalidation never retro-fails
# history: v1 gated the preflight only, v2 adds unit workers.
VERSION_SCOPES = {'1': 'preflight', '2': HOOK_SCOPE}
CKR_OK = 0
CKR_CRYPTOKI_NOT_INITIALIZED = 0x190

HOOK_SOURCE = '''"""P11Lab proxy exit-finalize (generated; do not edit by hand)."""
import atexit
import json
import os
import sys

_HOOK_VERSION = '2'
_PREFLIGHT_MODULE = 'pkcs11_check.core.preflight'
_UNIT_CHILD_ENV = 'PKCS11_CHECK_UNIT_CHILD'


def _is_preflight(argv):
    # Restricted to the exact producer shape [exe, -m, preflight, ...]; the
    # checker spawns nothing else, and anything fancier (flag clusters,
    # wrappers, -c injections) fails loud downstream via missing evidence
    # instead of risking a divergent hand-rolled option parser.
    args = list(argv)
    return len(args) > 2 and args[1] == '-m' and args[2] == _PREFLIGHT_MODULE


def _is_unit(argv, environ):
    # Unit workers share the producer shape [exe, -m, pytest, unit, ...]
    # for initial runs and retries; the checker's per-child marker (set
    # only by its supervised spawn) distinguishes them from any other
    # pytest invocation, so no node-id grammar is matched here.
    args = list(argv)
    return (len(args) > 3 and args[1] == '-m' and args[2] == 'pytest'
            and environ.get(_UNIT_CHILD_ENV) == '1')


def _module_arg(argv, flag):
    # Last flag wins (argparse parity), searched only in the child
    # argument segment so interpreter values can never shadow it. Space
    # form only: the producer emits ["--p11-module", path] /
    # ["--module", path]; anything else fails loud via binding evidence.
    value = None
    segment = list(argv)[3:]
    for position, token in enumerate(segment):
        if token == flag and position + 1 < len(segment):
            value = segment[position + 1]
    return value


def _write_evidence(path, payload):
    try:
        with open(path, 'w') as stream:
            json.dump(payload, stream, indent=2)
    except OSError:
        pass


def _finalize_at_exit(module_path, evidence_path, module_argv, pid, role, target):
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
            'hook_version': _HOOK_VERSION, 'pid': pid, 'role': role,
            'target': target, 'module_env': module_path,
            'module_argv': module_argv, 'attempted': attempted, 'rv': rv,
            'failure_class': failure or 'none',
        })


def _maybe_register():
    if sys.platform != 'linux':
        return
    argv = list(getattr(sys, 'orig_argv', []) or [])
    if _is_preflight(argv):
        role, flag, target = 'preflight', '--module', None
    elif _is_unit(argv, os.environ):
        role, flag, target = 'unit', '--p11-module', argv[3]
    else:
        return
    module_path = os.environ.get('P11LAB_MODULE')
    evidence_dir = os.environ.get('P11LAB_PROXY_FINALIZE_DIR')
    pid = os.getpid()
    module_argv = _module_arg(argv, flag)
    if not module_path or module_argv != module_path:
        if evidence_dir:
            if not module_path:
                failure = 'no-module-env'
            elif module_argv is None:
                failure = 'no-module-arg'
            else:
                failure = 'module-mismatch'
            _write_evidence(os.path.join(evidence_dir, 'finalize-evidence-%d.json' % pid), {
                'hook_version': _HOOK_VERSION, 'pid': pid, 'role': role,
                'target': target, 'module_env': module_path,
                'module_argv': module_argv, 'attempted': False, 'rv': None,
                'failure_class': failure,
            })
        return
    evidence_path = None
    if evidence_dir:
        evidence_path = os.path.join(evidence_dir, 'finalize-evidence-%d.json' % pid)
    atexit.register(_finalize_at_exit, module_path, evidence_path, module_argv, pid,
                    role, target)


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
    meta = {'version': HOOK_VERSION, 'sha256': digest, 'scope': HOOK_SCOPE}
    meta_file = target / HOOK_META_FILENAME
    _write_exclusive(meta_file, (json.dumps(meta, indent=2) + '\n').encode('utf-8'))
    if json.loads(meta_file.read_text()) != meta:
        raise ValueError('hook metadata verification failed')
    return {'dir': str(target), 'sha256': digest, 'version': HOOK_VERSION}


def reconcile_evidence(hook_dir, *, module_path, hook_version, hook_sha256,
                       expect_units=True, executed_targets=None):
    """Classify per-process finalize evidence; [] means every child ran clean.

    The expected hook identity and module binding arrive from durable
    provenance (not current code), so revalidation never retro-fails history.
    At least one evidence file is required and every file must be fully
    consistent; anything else yields one error string per problem. RV 0
    (released) and CKR_CRYPTOKI_NOT_INITIALIZED (already finalized, e.g. a
    unit the checker's sessionfinish already released) both count as clean.
    A unit record that never loaded the module is clean only as the exact
    tuple (attempted False, present rv None, not-loaded): setup failures
    and skips may exit before touching it. The preflight always loads the
    module, so its not-loaded stays loud.
    Beyond per-record checks, v2+ requires at least one preflight record
    (the v1 guarantee) and, when expect_units is true, at least one unit
    record, so a disarmed gate cannot pass on the other role's evidence.
    Presence counts any record carrying a valid role, even one that fails
    other checks. When executed_targets names the supervisor's executed
    unit roster, every entry must have at least one unit record, so one
    worker's evidence cannot stand in for another's. v1 history is exempt
    from presence and coverage: the v1 hook never gated units.
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
        or not isinstance(hook_version, str)
        or hook_version not in VERSION_SCOPES
        or meta.get('version') != hook_version
        or meta.get('sha256') != hook_sha256
        or meta.get('scope') != VERSION_SCOPES[hook_version]
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
        return ['proxy finalize evidence missing: no finalize observed']
    errors = []
    for name in names:
        errors.extend(
            _reconcile_record(root / name, name, module_path, hook_version)
        )
    if hook_version != '1':
        roles = set()
        covered = set()
        for name in names:
            try:
                record = json.loads((root / name).read_text())
            except (OSError, ValueError):
                continue
            if not isinstance(record, dict):
                continue
            if record.get('role') in ('preflight', 'unit'):
                roles.add(record['role'])
            target = record.get('target')
            if record.get('role') == 'unit' and isinstance(target, str) and target:
                covered.add(target)
        if 'preflight' not in roles:
            errors.append('proxy finalize evidence missing preflight record: %s' % root)
        if expect_units and 'unit' not in roles:
            errors.append('proxy finalize evidence missing unit records: %s' % root)
        if expect_units and executed_targets is not None:
            missing = [target for target in executed_targets if target not in covered]
            if missing:
                shown = ', '.join(missing[:5])
                if len(missing) > 5:
                    shown += ', ... (%d more)' % (len(missing) - 5)
                errors.append('proxy finalize evidence missing unit targets: %s' % shown)
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
    if hook_version == '1':
        # v1 records predate roles; the v1 hook gated the preflight only.
        role = 'preflight'
    else:
        role = record.get('role')
        if role not in ('preflight', 'unit'):
            return ['proxy finalize evidence role mismatch: %s' % name]
    target = record.get('target')
    if role == 'unit':
        if not isinstance(target, str) or not target:
            return ['proxy finalize evidence unit target mismatch: %s' % name]
    elif target is not None:
        return ['proxy finalize evidence preflight target mismatch: %s' % name]
    if record.get('module_env') != module_path or record.get('module_argv') != module_path:
        return ['proxy finalize evidence module mismatch: %s' % name]
    attempted = record.get('attempted')
    if attempted is not True:
        if (role == 'unit' and attempted is False and 'rv' in record
                and record.get('rv') is None
                and record.get('failure_class') == 'not-loaded'):
            return []
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
