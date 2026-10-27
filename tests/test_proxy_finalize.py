"""Productized proxy exit-finalize hook: template, installer, and behavior."""
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from p11lab.proxy_finalize import (
    CKR_CRYPTOKI_NOT_INITIALIZED,
    CKR_OK,
    HOOK_DIRNAME,
    HOOK_SOURCE,
    HOOK_VERSION,
    install_hook,
)

needs_linux = pytest.mark.skipif(
    sys.platform != 'linux', reason='proxy finalize hook is linux-scoped'
)


def test_hook_template_compiles_and_carries_version():
    compile(HOOK_SOURCE, 'sitecustomize.py', 'exec')
    assert HOOK_VERSION == '1'
    assert HOOK_DIRNAME == 'p11lab-proxy-hook'
    assert CKR_OK == 0
    assert CKR_CRYPTOKI_NOT_INITIALIZED == 0x190


def run_child(arguments, hook_dir, extra_env=None):
    env = {
        'PATH': os.defpath,
        'PYTHONPATH': str(hook_dir),
        'PYTHONDONTWRITEBYTECODE': '1',
    }
    env.update(extra_env or {})
    return subprocess.run(
        [sys.executable, *arguments],
        capture_output=True, text=True, timeout=120, env=env,
    )


def test_hook_bare_child_is_inert(tmp_path):
    installed = install_hook(tmp_path / HOOK_DIRNAME)
    assert installed['version'] == HOOK_VERSION
    completed = run_child(['-c', 'pass'], installed['dir'])
    assert completed.returncode == 0, completed.stderr
    assert list(Path(installed['dir']).glob('finalize-evidence-*.json')) == []


def write_stub_preflight(stub_dir):
    package = stub_dir / 'pkcs11_check' / 'core'
    package.mkdir(parents=True)
    (stub_dir / 'pkcs11_check' / '__init__.py').write_text('')
    (stub_dir / 'pkcs11_check' / 'core' / '__init__.py').write_text('')
    (package / 'preflight.py').write_text(
        'import sys\n'
        'print("stub-preflight", "--module" in sys.argv)\n'
    )


@needs_linux
def test_hook_gate_matches_preflight_argv_only(tmp_path):
    installed = install_hook(tmp_path / HOOK_DIRNAME)
    write_stub_preflight(tmp_path / 'stub')
    hook_path = os.pathsep.join(
        [installed['dir'], str(tmp_path / 'stub')]
    )
    completed = run_child(
        ['-m', 'pkcs11_check.core.preflight', '--module', '/nonexistent/libx.so'],
        hook_path,
        {'P11LAB_MODULE': '/nonexistent/libx.so',
         'P11LAB_PROXY_FINALIZE_DIR': installed['dir']},
    )
    assert completed.returncode == 0, completed.stderr
    evidence = list(Path(installed['dir']).glob('finalize-evidence-*.json'))
    assert len(evidence) == 1
    record = json.loads(evidence[0].read_text())
    assert record['attempted'] is False
    assert record['failure_class'] == 'not-loaded'
    assert record['module_argv'] == '/nonexistent/libx.so'
    assert record['hook_version'] == HOOK_VERSION


def test_hook_gate_ignores_other_modules(tmp_path):
    installed = install_hook(tmp_path / HOOK_DIRNAME)
    completed = run_child(
        ['-m', 'pytest', '--version'], installed['dir'],
        {'P11LAB_MODULE': '/nonexistent/libx.so',
         'P11LAB_PROXY_FINALIZE_DIR': installed['dir']},
    )
    assert completed.returncode == 0
    assert list(Path(installed['dir']).glob('finalize-evidence-*.json')) == []


@needs_linux
def test_hook_missing_module_env_is_loud(tmp_path):
    installed = install_hook(tmp_path / HOOK_DIRNAME)
    write_stub_preflight(tmp_path / 'stub')
    hook_path = os.pathsep.join(
        [installed['dir'], str(tmp_path / 'stub')]
    )
    completed = run_child(
        ['-m', 'pkcs11_check.core.preflight', '--module', '/x/y.so'],
        hook_path,
        {'P11LAB_PROXY_FINALIZE_DIR': installed['dir']},
    )
    assert completed.returncode == 0, completed.stderr
    evidence = list(Path(installed['dir']).glob('finalize-evidence-*.json'))
    assert len(evidence) == 1
    record = json.loads(evidence[0].read_text())
    assert record['attempted'] is False
    assert record['failure_class'] == 'no-module-env'


def test_install_hook_writes_verified_files(tmp_path):
    installed = install_hook(tmp_path / HOOK_DIRNAME)
    root = Path(installed['dir'])
    assert installed['sha256'] == hashlib.sha256(HOOK_SOURCE.encode()).hexdigest()
    hook_file = root / 'sitecustomize.py'
    assert hook_file.read_text() == HOOK_SOURCE
    if os.name == 'posix':
        assert stat.S_IMODE(hook_file.stat().st_mode) == 0o600
        assert stat.S_IMODE(root.stat().st_mode) == 0o700
    meta = json.loads((root / 'finalize-hook.json').read_text())
    assert meta == {'version': HOOK_VERSION, 'sha256': installed['sha256'],
                    'scope': 'preflight'}
    assert sorted(p.name for p in root.iterdir()) == ['finalize-hook.json', 'sitecustomize.py']
    with pytest.raises(FileExistsError):
        install_hook(tmp_path / HOOK_DIRNAME)


def test_install_hook_rejects_hostile_paths(tmp_path):
    with pytest.raises(ValueError):
        install_hook(tmp_path / ('a%sb' % os.pathsep))
    if os.name == 'posix':
        link = tmp_path / 'link'
        link.symlink_to(tmp_path / 'nowhere')
        with pytest.raises(FileExistsError):
            install_hook(link)
    with pytest.raises(ValueError):
        install_hook(Path('relative-hook-dir'))


FAKE_MODULE_C = r'''
#include <stdio.h>
#include <stdlib.h>
typedef unsigned long CK_RV;
typedef struct { unsigned char major, minor; CK_RV (*C_Initialize)(void *); CK_RV (*C_Finalize)(void *); } FakeList;
static int initialized = 0;
static void log_line(const char *what) {
    const char *path = getenv("FAKE_P11_LOG");
    if (!path) return;
    FILE *f = fopen(path, "a");
    if (!f) return;
    fprintf(f, "%s\n", what);
    fclose(f);
}
static CK_RV fake_init(void *args) {
    (void)args;
    log_line("init-call");
    if (!initialized) { initialized = 1; log_line("init-effect"); }
    return 0;
}
static CK_RV fake_fin(void *args) {
    (void)args;
    log_line("fin-call");
    if (initialized) { initialized = 0; log_line("fin-effect"); return 0; }
    return 0x190;
}
static FakeList table = {2, 1, fake_init, fake_fin};
CK_RV C_GetFunctionList(void *out) {
    *(void **)out = (void *)&table;
    return 0;
}
'''

needs_cc = pytest.mark.skipif(
    shutil.which('cc') is None, reason='C compiler required for native fixture'
)


def build_fake_module(tmp_path):
    source = tmp_path / 'fake_p11.c'
    source.write_text(FAKE_MODULE_C)
    library = tmp_path / 'libfakep11.so'
    completed = subprocess.run(
        ['cc', '-shared', '-fPIC', '-O2', '-o', str(library), str(source)],
        capture_output=True, text=True, timeout=120,
    )
    assert completed.returncode == 0, completed.stderr
    return library


STUB_INIT_AND_EXIT = '''
import ctypes
import gc
import os
import sys
hold = '--hold' in sys.argv
lib = ctypes.CDLL(os.environ['P11LAB_MODULE'])
table = ctypes.c_void_p()
assert lib.C_GetFunctionList(ctypes.byref(table)) == 0
Init = ctypes.CFUNCTYPE(ctypes.c_ulong, ctypes.c_void_p)
init = Init(ctypes.cast(table, ctypes.POINTER(ctypes.c_void_p))[1])
assert init(None) == 0
if not hold:
    del lib, table, init
    gc.collect()
print('stub-initialized')
'''


def write_initializing_stub(stub_dir):
    package = stub_dir / 'pkcs11_check' / 'core'
    package.mkdir(parents=True)
    (stub_dir / 'pkcs11_check' / '__init__.py').write_text('')
    (stub_dir / 'pkcs11_check' / 'core' / '__init__.py').write_text('')
    (package / 'preflight.py').write_text(textwrap.dedent(STUB_INIT_AND_EXIT))


def run_stub_preflight(tmp_path, library, argv_extra=()):
    installed = install_hook(tmp_path / HOOK_DIRNAME)
    write_initializing_stub(tmp_path / 'stub')
    hook_path = os.pathsep.join([installed['dir'], str(tmp_path / 'stub')])
    log = tmp_path / 'native.log'
    completed = run_child(
        ['-m', 'pkcs11_check.core.preflight', '--module', str(library), *argv_extra],
        hook_path,
        {'P11LAB_MODULE': str(library),
         'P11LAB_PROXY_FINALIZE_DIR': installed['dir'],
         'FAKE_P11_LOG': str(log)},
    )
    evidence = list(Path(installed['dir']).glob('finalize-evidence-*.json'))
    lines = log.read_text().splitlines() if log.exists() else []
    records = [json.loads(path.read_text()) for path in evidence]
    return completed, records, lines


@needs_cc
def test_cc_fixture_held_ref_finalizes_shared_state(tmp_path):
    if sys.platform != 'linux':
        pytest.skip('native finalize hook is linux-scoped')
    library = build_fake_module(tmp_path)
    completed, records, lines = run_stub_preflight(tmp_path, library, ('--hold',))
    assert completed.returncode == 0, completed.stderr
    assert 'stub-initialized' in completed.stdout
    assert len(records) == 1
    record = records[0]
    assert record['attempted'] is True
    assert record['failure_class'] == 'none'
    assert record['rv'] == 0
    assert lines.count('init-call') == 1, lines
    assert lines == ['init-call', 'init-effect', 'fin-call', 'fin-effect']


PROXY_TRANSPORT = {
    'PKCS11_PROXY_ENDPOINT': 'https://provider-daemon:8443',
    'PKCS11_PROXY_TLS_CA_CERT': '/run/p11lab/tls/ca.crt',
    'PKCS11_PROXY_TLS_CLIENT_CERT': '/run/p11lab/tls/client.crt',
    'PKCS11_PROXY_TLS_CLIENT_KEY': '/run/p11lab/tls/client.key',
    'PKCS11_PROXY_CONNECT_TIMEOUT': '10',
}


@needs_linux
def test_checker_environment_proxy_installs_hook_channel(tmp_path, monkeypatch):
    from p11lab.checker import checker_environment
    monkeypatch.delenv('PYTHONPATH', raising=False)
    monkeypatch.delenv('P11LAB_MODULE', raising=False)
    module = tmp_path / 'libshim.so'
    module.write_bytes(b'fake')
    env = checker_environment(tmp_path, 'p', 's', proxy_env=dict(PROXY_TRANSPORT),
                              module_path=str(module))
    hook_dir = Path(env['P11LAB_PROXY_FINALIZE_DIR'])
    assert hook_dir == tmp_path.resolve() / HOOK_DIRNAME
    assert env['PYTHONPATH'] == str(hook_dir)
    assert env['PYTHONDONTWRITEBYTECODE'] == '1'
    assert env['P11LAB_MODULE'] == str(module)
    assert (hook_dir / 'sitecustomize.py').read_text() == HOOK_SOURCE
    assert set(PROXY_TRANSPORT) <= set(env)
    provenance = json.loads((tmp_path.resolve() / 'build-provenance.json').read_text())
    assert provenance['extra']['proxy_finalize'] == {
        'version': HOOK_VERSION,
        'sha256': hashlib.sha256(HOOK_SOURCE.encode()).hexdigest(),
        'scope': 'preflight', 'module': str(module),
    }
    assert 'checker' in provenance['extra']


def test_checker_environment_proxy_requires_module_path(tmp_path):
    from p11lab.checker import checker_environment
    with pytest.raises(ValueError):
        checker_environment(tmp_path, 'p', 's', proxy_env=dict(PROXY_TRANSPORT))


def test_checker_environment_direct_has_no_hook_channel(tmp_path, monkeypatch):
    from p11lab.checker import checker_environment
    monkeypatch.setenv('PYTHONPATH', '/ambient/hook')
    monkeypatch.setenv('P11LAB_MODULE', '/ambient/lib.so')
    env = checker_environment(tmp_path, 'p', 's')
    for name in ('PYTHONPATH', 'PYTHONDONTWRITEBYTECODE', 'P11LAB_MODULE',
                 'P11LAB_PROXY_FINALIZE_DIR'):
        assert name not in env
    assert not (tmp_path.resolve() / HOOK_DIRNAME).exists()
    provenance = json.loads((tmp_path.resolve() / 'build-provenance.json').read_text())
    assert set(provenance['extra']) == {'checker'}


def test_checker_environment_validates_transport_before_install(tmp_path):
    from p11lab.checker import checker_environment
    partial = dict(PROXY_TRANSPORT)
    del partial['PKCS11_PROXY_CONNECT_TIMEOUT']
    with pytest.raises(ValueError):
        checker_environment(tmp_path, 'p', 's', proxy_env=partial,
                            module_path=str(tmp_path / 'lib.so'))
    assert not (tmp_path.resolve() / HOOK_DIRNAME).exists()


def write_evidence(hook_dir, name, record):
    path = hook_dir / name
    path.write_text(json.dumps(record))
    return path


MODULE_PATH = '/run/p11lab-client/libpkcs11_proxy_ng_shim.so'


def clean_record(**overrides):
    record = {'hook_version': HOOK_VERSION, 'pid': 1234,
              'module_env': MODULE_PATH, 'module_argv': MODULE_PATH,
              'attempted': True, 'rv': 0, 'failure_class': 'none'}
    record.update(overrides)
    return record


def installed_hook(tmp_path):
    installed = install_hook(tmp_path / HOOK_DIRNAME)
    return Path(installed['dir']), installed


def reconcile(installed, hook_dir):
    from p11lab.proxy_finalize import reconcile_evidence
    return reconcile_evidence(
        hook_dir, module_path=MODULE_PATH,
        hook_version=installed['version'], hook_sha256=installed['sha256'],
    )


def test_reconcile_accepts_clean_evidence(tmp_path):
    hook_dir, installed = installed_hook(tmp_path)
    write_evidence(hook_dir, 'finalize-evidence-1234.json', clean_record())
    write_evidence(hook_dir, 'finalize-evidence-1235.json',
                   clean_record(pid=1235, rv=CKR_CRYPTOKI_NOT_INITIALIZED))
    assert reconcile(installed, hook_dir) == []


def test_reconcile_flags_missing_evidence(tmp_path):
    hook_dir, installed = installed_hook(tmp_path)
    errors = reconcile(installed, hook_dir)
    assert len(errors) == 1 and 'missing' in errors[0]


def test_reconcile_flags_bad_outcomes(tmp_path):
    hook_dir, installed = installed_hook(tmp_path)
    write_evidence(hook_dir, 'finalize-evidence-1234.json',
                   clean_record(attempted=False, rv=None, failure_class='not-loaded'))
    write_evidence(hook_dir, 'finalize-evidence-1235.json', clean_record(pid=1235, rv=5))
    (hook_dir / 'finalize-evidence-1236.json').write_text('not json')
    errors = reconcile(installed, hook_dir)
    assert len(errors) == 3


def test_reconcile_rejects_type_confusion(tmp_path):
    assert False in (0, CKR_CRYPTOKI_NOT_INITIALIZED)
    assert True == 1
    hook_dir, installed = installed_hook(tmp_path)
    write_evidence(hook_dir, 'finalize-evidence-1234.json', clean_record(rv=False))
    write_evidence(hook_dir, 'finalize-evidence-1.json', clean_record(pid=True))
    assert len(reconcile(installed, hook_dir)) == 2


def test_reconcile_rejects_identity_mismatch(tmp_path):
    hook_dir, installed = installed_hook(tmp_path)
    write_evidence(hook_dir, 'finalize-evidence-1234.json',
                   clean_record(hook_version='9'))
    write_evidence(hook_dir, 'finalize-evidence-1235.json',
                   clean_record(pid=1235, module_env='/other/lib.so'))
    write_evidence(hook_dir, 'finalize-evidence-1236.json',
                   clean_record(pid=9999))
    write_evidence(hook_dir, 'finalize-evidence-1237.json', {'attempted': True})
    assert len(reconcile(installed, hook_dir)) == 4


def test_reconcile_rejects_tampered_install(tmp_path):
    hook_dir, installed = installed_hook(tmp_path)
    write_evidence(hook_dir, 'finalize-evidence-1234.json', clean_record())
    with open(hook_dir / 'sitecustomize.py', 'ab') as stream:
        stream.write(b'# tampered\n')
    assert reconcile(installed, hook_dir) != []
    (hook_dir / 'finalize-hook.json').write_text(json.dumps({'version': '9'}))
    assert reconcile(installed, hook_dir) != []


@needs_cc
def test_cc_fixture_dropped_ref_documents_loader_reality(tmp_path):
    if sys.platform != 'linux':
        pytest.skip('native finalize hook is linux-scoped')
    library = build_fake_module(tmp_path)
    completed, records, lines = run_stub_preflight(tmp_path, library)
    assert completed.returncode == 0, completed.stderr
    assert 'stub-initialized' in completed.stdout
    assert len(records) == 1
    record = records[0]
    assert lines.count('init-call') == 1, lines
    assert record['attempted'] is True
    assert record['failure_class'] == 'none'
    assert record['rv'] == 0
    assert lines == ['init-call', 'init-effect', 'fin-call', 'fin-effect']


@needs_linux
def test_hook_gate_ignores_dash_c_injection(tmp_path):
    installed = install_hook(tmp_path / HOOK_DIRNAME)
    hook_env = {'P11LAB_MODULE': '/nonexistent/libx.so',
                'P11LAB_PROXY_FINALIZE_DIR': installed['dir']}
    for argv in (['-c', 'pass', '-m', 'pkcs11_check.core.preflight', '--module', '/x.so'],
                ['-cpass', '-m', 'pkcs11_check.core.preflight', '--module', '/x.so']):
        completed = run_child(argv, installed['dir'], hook_env)
        assert completed.returncode == 0, completed.stderr
    assert list(Path(installed['dir']).glob('finalize-evidence-*.json')) == []


@needs_linux
def test_hook_module_mismatch_is_loud(tmp_path):
    installed = install_hook(tmp_path / HOOK_DIRNAME)
    write_stub_preflight(tmp_path / 'stub')
    hook_path = os.pathsep.join([installed['dir'], str(tmp_path / 'stub')])
    completed = run_child(
        ['-m', 'pkcs11_check.core.preflight', '--module', '/other/lib.so'],
        hook_path,
        {'P11LAB_MODULE': '/expected/lib.so',
         'P11LAB_PROXY_FINALIZE_DIR': installed['dir']},
    )
    assert completed.returncode == 0, completed.stderr
    evidence = list(Path(installed['dir']).glob('finalize-evidence-*.json'))
    assert len(evidence) == 1
    record = json.loads(evidence[0].read_text())
    assert record['attempted'] is False
    assert record['failure_class'] == 'module-mismatch'


@needs_linux
@needs_cc
def test_hook_never_loaded_library_is_loud(tmp_path):
    if sys.platform != 'linux':
        pytest.skip('native finalize hook is linux-scoped')
    installed = install_hook(tmp_path / HOOK_DIRNAME)
    write_stub_preflight(tmp_path / 'stub')
    hook_path = os.pathsep.join([installed['dir'], str(tmp_path / 'stub')])
    library = build_fake_module(tmp_path)
    completed = run_child(
        ['-m', 'pkcs11_check.core.preflight', '--module', str(library)],
        hook_path,
        {'P11LAB_MODULE': str(library),
         'P11LAB_PROXY_FINALIZE_DIR': installed['dir']},
    )
    assert completed.returncode == 0, completed.stderr
    evidence = list(Path(installed['dir']).glob('finalize-evidence-*.json'))
    assert len(evidence) == 1
    record = json.loads(evidence[0].read_text())
    assert record['attempted'] is False
    assert record['failure_class'] == 'not-loaded'


def test_hook_gate_parser_matrix(monkeypatch, tmp_path):
    import p11lab.proxy_finalize as finalized
    import atexit as std_atexit

    exact = ['py', '-m', 'pkcs11_check.core.preflight', '--module', '/m.so']
    cases = [
        # (argv, registers, module_argv, evidence_class)
        (exact, True, '/m.so', None),
        (['py', '-m', 'pkcs11_check.core.preflight', '--module', '/a.so',
          '--module', '/m.so'], True, '/m.so', None),
        (['py', '-c', 'code', '-m', 'pkcs11_check.core.preflight'], False, None, None),
        (['py', '-ccode', '-m', 'pkcs11_check.core.preflight',
          '--module', '/m.so'], False, None, None),
        (['py', '-qcpass', '-m', 'pkcs11_check.core.preflight',
          '--module', '/m.so'], False, None, None),
        (['py', '-W', 'ignore', '-m', 'pkcs11_check.core.preflight',
          '--module', '/m.so'], False, None, None),
        (['py', 'script.py', '-m', 'pkcs11_check.core.preflight'], False, None, None),
        (['py', '-m', 'pytest', 'x', '-m', 'pkcs11_check.core.preflight'],
         False, None, None),
        (['py', '-m', 'pkcs11_check.core.preflight', '--module', '/a.so'],
         False, None, 'module-mismatch'),
        (['py', '-m', 'pkcs11_check.core.preflight'], False, None, 'no-module-arg'),
        (['py', '-m'], False, None, None),
        (['py'], False, None, None),
    ]
    for index, (argv, registers, module_argv, evidence_class) in enumerate(cases):
        case_dir = tmp_path / ('case%d' % index)
        case_dir.mkdir()
        recorded = []
        monkeypatch.setattr(std_atexit, 'register',
                            lambda fn, *a: recorded.append((fn, a)))
        monkeypatch.setattr('sys.orig_argv', argv)
        monkeypatch.setattr('sys.platform', 'linux')
        monkeypatch.setenv('P11LAB_MODULE', '/m.so')
        monkeypatch.setenv('P11LAB_PROXY_FINALIZE_DIR', str(case_dir))
        namespace = {'__name__': 'sitecustomize-probe'}
        exec(compile(finalized.HOOK_SOURCE, 'sitecustomize.py', 'exec'), namespace)
        assert (len(recorded) == 1) is registers, argv
        if registers:
            assert recorded[0][1][2] == module_argv, argv
        found = list(case_dir.glob('finalize-evidence-*.json'))
        if evidence_class is None:
            assert found == [], argv
        else:
            assert len(found) == 1, argv
            record = json.loads(found[0].read_text())
            assert record['attempted'] is False, argv
            assert record['failure_class'] == evidence_class, argv


def test_hook_template_matches_module_identity():
    from p11lab.proxy_finalize import HOOK_SOURCE, HOOK_VERSION, PREFLIGHT_MODULE
    assert "'%s'" % HOOK_VERSION in HOOK_SOURCE
    assert PREFLIGHT_MODULE in HOOK_SOURCE


def write_provenance(output, finalize=None):
    extra = {'checker': {'source_revision': 's', 'wheel_sha256': 'w',
                         'runtime_lock_sha256': 'r'}}
    if finalize is not None:
        extra['proxy_finalize'] = finalize
    (output / 'build-provenance.json').write_text(json.dumps({'extra': extra}))


def test_durable_finalize_errors_cover_proxy_runs(tmp_path):
    from p11lab.checker import durable_finalize_errors
    output = tmp_path / 'run'
    output.mkdir()
    installed = install_hook(output / HOOK_DIRNAME)
    finalize = {'version': installed['version'], 'sha256': installed['sha256'],
                'scope': 'preflight', 'module': MODULE_PATH}
    write_provenance(output, finalize)
    assert 'missing' in durable_finalize_errors(output)[0]
    hook_dir = Path(installed['dir'])
    write_evidence(hook_dir, 'finalize-evidence-1234.json', clean_record())
    assert durable_finalize_errors(output) == []


def test_durable_finalize_errors_reject_malformed_declarations(tmp_path):
    from p11lab.checker import durable_finalize_errors
    for index, malformed in enumerate(({}, None, False, 0, '', [])):
        output = tmp_path / ('run%d' % index)
        output.mkdir()
        extra = {'checker': {'source_revision': 's'}}
        extra['proxy_finalize'] = malformed
        (output / 'build-provenance.json').write_text(json.dumps({'extra': extra}))
        errors = durable_finalize_errors(output)
        assert len(errors) == 1 and 'malformed' in errors[0], malformed


def test_durable_finalize_errors_skip_direct_runs(tmp_path):
    from p11lab.checker import durable_finalize_errors
    output = tmp_path / 'run'
    output.mkdir()
    write_provenance(output)
    assert durable_finalize_errors(output) == []
    assert durable_finalize_errors(tmp_path / 'absent') == []
    foreign = tmp_path / 'foreign'
    foreign.mkdir()
    (foreign / 'build-provenance.json').write_text('[1, 2, 3]')
    assert durable_finalize_errors(foreign) == []
