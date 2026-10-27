"""Failure-path checks against the actual packaged lifecycle scripts."""
import os
import shlex
import shutil
import subprocess

import pytest

from p11lab.catalog import package_data


PROVIDERS = ('softhsm2', 'bouncyhsm', 'nss', 'freehsm', 'haskoki', 'opencryptoki')


def run_script(text, directory, **env):
    script = directory / 'entrypoint.sh'
    script.write_text(text)
    return subprocess.run(['bash', str(script)], capture_output=True, text=True,
                          timeout=30, env=os.environ | env)


def enumeration_guards():
    for provider in PROVIDERS:
        text = package_data(f'providers/{provider}/entrypoint.sh').read_text()
        for index, line in enumerate(text.splitlines()):
            if '$(find ' in line or 'p11lab_check_find ' in line:
                yield pytest.param(line.strip(), id=f'{provider}-line-{index + 1}')


@pytest.mark.parametrize('guard', list(enumeration_guards()))
def test_state_enumeration_failure_is_never_an_empty_roster(tmp_path, guard):
    common = package_data('runtime/common.sh').read_text()
    result = run_script(common + '\n' +
                        'find() { echo "injected find I/O failure" >&2; return 73; }\n'
                        'state=/state; owned=/state/provider\n' + guard + '\n'
                        'echo ENUMERATION-FAILURE-IGNORED\n', tmp_path)
    assert result.returncode != 0, result.stdout + result.stderr
    assert 'ENUMERATION-FAILURE-IGNORED' not in result.stdout
    assert 'cannot enumerate' in result.stderr, result.stderr
    assert 'injected find I/O failure' in result.stderr


def freehsm_script(directory):
    state, control = directory / 'state', directory / 'control'
    state.mkdir()
    control.mkdir()
    runtime_id = directory / 'runtime-id'
    runtime_id.write_text('test-artifact\n')
    tool = directory / 'fhsm-token'
    tool.write_text(
        '#!/bin/sh\nset -eu\n'
        'printf "%s\\n" "$1" >> "$CALLS"\n'
        'printf "%s\\n" "native stdout: $1"\n'
        'printf "%s\\n" "native diagnostic: $1 ${KAT_WARNING-}" >&2\n'
        'case "$1" in\n'
        'init) printf token > "$FHSM_TOKENS_DIR/slot0.tok"; '
        'printf key > "$FHSM_TOKENS_DIR/audit.key" ;;\n'
        'info) printf "  label P11Lab\\n" ;;\n'
        'esac\n')
    tool.chmod(0o755)
    text = package_data('providers/freehsm/entrypoint.sh').read_text()
    text = text.replace('. /usr/share/p11lab/common.sh',
                        package_data('runtime/common.sh').read_text())
    for original, redirect in [('/var/lib/p11lab', state), ('/run/p11lab', control),
                               ('/usr/share/p11lab/runtime-id', runtime_id),
                               ('/usr/local/bin/fhsm-token', tool)]:
        text = text.replace(original, str(redirect))
    script = directory / 'provider'
    script.write_text(text)
    return script, state, control


def run_freehsm(script, operation, **env):
    return subprocess.run(['sh', str(script), operation], capture_output=True,
                          text=True, timeout=30, env=os.environ | {
                              'P11LAB_PIN': 'user-test', 'P11LAB_SO_PIN': 'so-test',
                              'CALLS': str(script.parent / 'native-calls')} | env)


@pytest.mark.parametrize('operation', ['init', 'health'])
@pytest.mark.parametrize('warning', ['', 'KAT FAIL: successful tool warning'])
def test_successful_freehsm_tools_preserve_both_streams(tmp_path, operation, warning):
    script, _, control = freehsm_script(tmp_path)
    assert run_freehsm(script, 'init').returncode == 0
    result = run_freehsm(script, operation, KAT_WARNING=warning)
    native_operation = 'info'  # Both health and an idempotent init reopen the token.
    assert result.returncode == 0, result.stderr
    assert f'native diagnostic: {native_operation}' in result.stderr
    assert 'native diagnostic:' not in result.stdout
    if operation == 'health':
        assert 'native stdout: info' in result.stdout
    if warning:
        assert warning in result.stderr
    assert not list(control.glob('init.*'))


def test_fresh_freehsm_init_preserves_success_diagnostics(tmp_path):
    script, _, control = freehsm_script(tmp_path)
    result = run_freehsm(script, 'init', KAT_WARNING='KAT FAIL: successful tool warning')
    assert result.returncode == 0, result.stderr
    assert 'native stdout: init' in result.stdout
    assert 'native diagnostic: init KAT FAIL:' in result.stderr
    assert 'native diagnostic:' not in result.stdout
    assert not list(control.glob('init.*'))


def haskoki_script(directory):
    state, control = directory / 'state', directory / 'control'
    state.mkdir()
    control.mkdir()
    runtime_id = directory / 'runtime-id'
    runtime_id.write_text('a' * 64 + '\n')
    config, store = state / 'haskoki' / 'haskoki.toml', state / 'haskoki' / 'token.sqlite'
    expected = directory / 'expected-config'
    expected.write_text(
        'schema_version = 1\nprofile = "real-crypto"\n\n'
        f'[storage]\nkind = "sqlite"\npath = "{store}"\n\n'
        '[engine]\nkind = "openssl"\n\n[trace]\nenabled = false\n')
    ctl = directory / 'haskoki-ctl'
    ctl.write_text(
        '#!/bin/sh\nset -eu\n'
        'printf "%s\\n" "$1 $2" >> "$CALLS"\n'
        'case "$1 $2" in\n'
        '"config check") [ "$#" -eq 4 ] && [ "$3" = --config ] '
        f'&& [ "$4" = {shlex.quote(str(config))} ] || exit 98\n'
        f'cmp -s -- "$4" {shlex.quote(str(expected))} || exit 98\n'
        'printf "native config stdout\\n"; '
        'printf "native config diagnostic\\n" >&2; exit "$CONFIG_STATUS" ;;\n'
        '"store inspect") [ "$#" -eq 4 ] && [ "$3" = --path ] '
        f'&& [ "$4" = {shlex.quote(str(store))} ] || exit 98\n'
        'printf "%s\\n" "${STORE_REPORT-tokens: 1}"; '
        'printf "native store diagnostic\\n" >&2; exit "${STORE_STATUS-0}" ;;\n'
        '*) exit 99 ;;\n'
        'esac\n')
    ctl.chmod(0o755)
    provision = directory / 'haskoki-provision'
    provision.write_text(
        '#!/bin/sh\nset -eu\n'
        '[ "$#" -eq 1 ] && [ "$1" = /usr/local/lib/p11lab/libhaskoki.so ] || exit 98\n'
        'printf "provision\\n" >> "$CALLS"\n'
        'printf token > "$(dirname "$HASKOKI_CONFIG")/token.sqlite"\n')
    provision.chmod(0o755)
    text = package_data('providers/haskoki/entrypoint.sh').read_text()
    text = text.replace('. /usr/share/p11lab/common.sh',
                        package_data('runtime/common.sh').read_text())
    for original, redirect in [('/var/lib/p11lab', state), ('/run/p11lab', control),
                               ('/usr/share/p11lab/runtime-id', runtime_id),
                               ('/usr/local/bin/haskoki-ctl', ctl),
                               ('/usr/local/bin/haskoki-provision', provision)]:
        text = text.replace(original, str(redirect))
    script = directory / 'provider'
    script.write_text(text)
    return script, state, control


def run_haskoki(script, shell, operation, *argv, **env):
    environment = os.environ | {
        'P11LAB_PIN': '1234', 'P11LAB_SO_PIN': '5678',
        'CALLS': str(script.parent / 'native-calls'), 'CONFIG_STATUS': '0'} | env
    return subprocess.run([shell, str(script), operation, *argv], capture_output=True,
                          text=True, timeout=30,
                          env={key: value for key, value in environment.items() if value is not None})


@pytest.mark.parametrize('shell', ['sh', 'bash'])
@pytest.mark.parametrize('status', [1, 37, 127])
def test_haskoki_initial_config_failure_preserves_native_status(tmp_path, shell, status):
    script, state, control = haskoki_script(tmp_path)
    calls = tmp_path / 'native-calls'
    result = subprocess.run([shell, str(script), 'init'], capture_output=True,
                            text=True, timeout=30, env=os.environ | {
                                'P11LAB_PIN': '1234', 'P11LAB_SO_PIN': '5678',
                                'CALLS': str(calls), 'CONFIG_STATUS': str(status)})
    assert result.returncode == status, result.stdout + result.stderr
    assert 'native token initialization failed; partial state retained' in result.stderr
    assert 'native config stdout' in result.stderr
    assert 'native config diagnostic' in result.stderr
    assert calls.read_text().splitlines() == ['config check']
    assert (state / 'haskoki' / 'haskoki.toml').is_file()
    assert not (state / 'haskoki' / 'token.sqlite').exists()
    assert not (state / 'haskoki' / 'complete').exists()
    assert not (state / '.init-lock').exists()
    assert not list(control.glob('init.*'))
    assert not list(control.glob('marker.*'))


@pytest.mark.parametrize('shell', ['sh', 'bash'])
def test_haskoki_successful_initial_config_reaches_provisioning(tmp_path, shell):
    script, state, control = haskoki_script(tmp_path)
    calls = tmp_path / 'native-calls'
    result = subprocess.run([shell, str(script), 'init'], capture_output=True,
                            text=True, timeout=30, env=os.environ | {
                                'P11LAB_PIN': '1234', 'P11LAB_SO_PIN': '5678',
                                'CALLS': str(calls), 'CONFIG_STATUS': '0'})
    assert result.returncode == 0, result.stdout + result.stderr
    assert calls.read_text().splitlines() == ['config check', 'provision', 'store inspect']
    assert (state / 'haskoki' / 'token.sqlite').is_file()
    assert (state / 'haskoki' / 'complete').is_file()
    assert not (state / '.init-lock').exists()
    assert not list(control.glob('init.*'))
    assert not list(control.glob('marker.*'))


@pytest.mark.parametrize('shell', ['sh', 'bash'])
@pytest.mark.parametrize('status', [2, 37, 126, 127])
def test_haskoki_initial_inspection_preserves_native_failure(tmp_path, shell, status):
    script, state, control = haskoki_script(tmp_path)
    result = run_haskoki(script, shell, 'init', STORE_STATUS=str(status))
    assert result.returncode == status, result.stdout + result.stderr
    assert 'native store diagnostic' in result.stderr
    assert (tmp_path / 'native-calls').read_text().splitlines() == [
        'config check', 'provision', 'store inspect']
    assert (state / 'haskoki' / 'token.sqlite').is_file()
    assert not (state / 'haskoki' / 'complete').exists()
    assert not (state / '.init-lock').exists()
    assert not list(control.glob('init.*'))
    assert not list(control.glob('marker.*'))


@pytest.mark.parametrize('shell', ['sh', 'bash'])
@pytest.mark.parametrize('report', ['tokens: 0', 'tokens: 2', '', 'tokens: 1\ntokens: 2'])
def test_haskoki_initial_inspection_requires_one_token(tmp_path, shell, report):
    script, state, _ = haskoki_script(tmp_path)
    result = run_haskoki(script, shell, 'init', STORE_REPORT=report)
    assert result.returncode != 0, result.stdout + result.stderr
    assert not (state / 'haskoki' / 'complete').exists()


@pytest.mark.parametrize('shell', ['sh', 'bash'])
@pytest.mark.parametrize('native_stage', ['config', 'provision'])
@pytest.mark.parametrize('signal,number', [('HUP', 1), ('INT', 2), ('TERM', 15)])
def test_haskoki_interrupted_init_does_not_continue(tmp_path, shell, native_stage, signal, number):
    script, state, control = haskoki_script(tmp_path)
    native = tmp_path / ('haskoki-ctl' if native_stage == 'config' else 'haskoki-provision')
    text = native.read_text()
    anchor = 'exit "$CONFIG_STATUS"' if native_stage == 'config' else 'printf token >'
    text = text.replace(anchor, f'kill -{signal} "$PPID"; ' + anchor)
    native.write_text(text)
    result = run_haskoki(script, shell, 'init')
    assert result.returncode == 128 + number, result.stdout + result.stderr
    assert (tmp_path / 'native-calls').read_text().splitlines() == (
        ['config check'] if native_stage == 'config' else ['config check', 'provision'])
    assert not (state / 'haskoki' / 'complete').exists()
    assert not (state / '.init-lock').exists()
    assert not list(control.glob('init.*'))
    assert not list(control.glob('marker.*'))


def haskoki_state_snapshot(state):
    return {str(p.relative_to(state)): (p.lstat().st_mode,
            p.readlink().as_posix() if p.is_symlink() else p.read_bytes() if p.is_file() else None)
            for p in state.rglob('*')}


@pytest.mark.parametrize('shell', ['sh', 'bash'])
@pytest.mark.parametrize('operation', ['init', 'health', 'exec'])
@pytest.mark.parametrize('damage', [
    'hidden-file', 'double-dot-file', 'dangling-link', 'hidden-dangling-link',
    'lock-dangling-link', 'lock-directory', 'lock-fifo', 'extra-marker-lf',
    'missing-config', 'malformed-config',
])
def test_haskoki_rejects_unsafe_state_before_native_tools(tmp_path, shell, operation, damage):
    script, state, _ = haskoki_script(tmp_path)
    assert run_haskoki(script, shell, 'init').returncode == 0
    owned = state / 'haskoki'
    if damage in ('hidden-file', 'double-dot-file'):
        (owned / ('.foreign' if damage == 'hidden-file' else '..foreign')).write_text('foreign')
    elif damage.endswith('dangling-link') or damage == 'dangling-link':
        name = {'dangling-link': 'foreign', 'hidden-dangling-link': '.foreign',
                'lock-dangling-link': 'token.sqlite.lock'}[damage]
        (owned / name).symlink_to(tmp_path / 'missing')
    elif damage == 'lock-directory':
        (owned / 'token.sqlite.lock').mkdir()
    elif damage == 'lock-fifo':
        if not hasattr(os, 'mkfifo'):
            pytest.skip('FIFO creation is unavailable on this platform')
        os.mkfifo(owned / 'token.sqlite.lock')
    elif damage == 'missing-config':
        (owned / 'haskoki.toml').unlink()
    elif damage == 'malformed-config':
        (owned / 'haskoki.toml').write_text('not the pinned config\n')
    else:
        with (owned / 'complete').open('ab') as stream:
            stream.write(b'\n')
    calls = tmp_path / 'native-calls'
    calls.write_text('')
    before = haskoki_state_snapshot(state)
    argv = ('--', 'sh', '-c', 'echo app >> "$CALLS"') if operation == 'exec' else ()
    result = run_haskoki(script, shell, operation, *argv)
    assert result.returncode != 0, result.stdout + result.stderr
    assert calls.read_text() == ''
    assert haskoki_state_snapshot(state) == before


@pytest.mark.skipif(os.name != 'posix' or os.geteuid() == 0,
                    reason='requires a non-root POSIX directory enumeration')
@pytest.mark.parametrize('shell', ['sh', 'bash'])
@pytest.mark.parametrize('operation', ['init', 'health', 'exec'])
def test_haskoki_unreadable_owned_roster_is_not_empty(tmp_path, shell, operation):
    script, state, _ = haskoki_script(tmp_path)
    assert run_haskoki(script, shell, 'init').returncode == 0
    owned = state / 'haskoki'
    (owned / 'foreign').write_text('foreign')
    calls = tmp_path / 'native-calls'
    calls.write_text('')
    before = haskoki_state_snapshot(state)
    owned.chmod(0o300)
    try:
        argv = ('--', 'sh', '-c', 'echo app >> "$CALLS"') if operation == 'exec' else ()
        result = run_haskoki(script, shell, operation, *argv)
        assert result.returncode != 0, result.stdout + result.stderr
        assert 'cannot enumerate' in result.stderr
        assert calls.read_text() == ''
    finally:
        owned.chmod(0o700)
    assert haskoki_state_snapshot(state) == before


@pytest.mark.parametrize('shell', ['sh', 'bash'])
@pytest.mark.parametrize('operation', ['init', 'health', 'exec'])
def test_haskoki_symlinked_state_root_is_not_traversed(tmp_path, shell, operation):
    script, state, _ = haskoki_script(tmp_path)
    assert run_haskoki(script, shell, 'init').returncode == 0
    outside = tmp_path / 'outside-state'
    state.rename(outside)
    state.symlink_to(outside, target_is_directory=True)
    (outside / 'foreign').write_text('must not be modified')
    calls = tmp_path / 'native-calls'
    calls.write_text('')
    before = haskoki_state_snapshot(outside)
    argv = ('--', 'sh', '-c', 'echo app >> "$CALLS"') if operation == 'exec' else ()
    result = run_haskoki(script, shell, operation, *argv)
    assert result.returncode != 0, result.stdout + result.stderr
    assert calls.read_text() == ''
    assert state.is_symlink() and state.readlink() == outside
    assert haskoki_state_snapshot(outside) == before


@pytest.mark.parametrize('shell', ['sh', 'bash'])
@pytest.mark.parametrize('operation', ['init', 'health', 'exec'])
@pytest.mark.parametrize('identity', [None, b'', b'not-an-identity\n', b'a' * 64 + b'\n\n',
                                    b'a' * 64 + b'\0', b'A' * 64 + b'\n'])
def test_haskoki_rejects_invalid_runtime_identity(tmp_path, shell, operation, identity):
    script, state, _ = haskoki_script(tmp_path)
    if operation != 'init':
        assert run_haskoki(script, shell, 'init').returncode == 0
    runtime_id = tmp_path / 'runtime-id'
    if identity is None:
        runtime_id.unlink()
    else:
        runtime_id.write_bytes(identity)
    calls = tmp_path / 'native-calls'
    calls.write_text('')
    before = haskoki_state_snapshot(state)
    argv = ('--', 'sh', '-c', 'echo app >> "$CALLS"') if operation == 'exec' else ()
    result = run_haskoki(script, shell, operation, *argv)
    assert result.returncode != 0, result.stdout + result.stderr
    assert calls.read_text() == ''
    assert haskoki_state_snapshot(state) == before


@pytest.mark.parametrize('shell', ['sh', 'bash'])
@pytest.mark.parametrize('native_stage', ['config', 'provision'])
def test_haskoki_native_status_survives_missing_diagnostic_log(tmp_path, shell, native_stage):
    script, state, _ = haskoki_script(tmp_path)
    native = tmp_path / ('haskoki-ctl' if native_stage == 'config' else 'haskoki-provision')
    native.write_text('#!/bin/sh\nrm -f "$(dirname "$CALLS")/control/init.$PPID"\nexit 37\n')
    result = run_haskoki(script, shell, 'init')
    assert result.returncode == 37, result.stdout + result.stderr
    assert not (state / 'haskoki' / 'complete').exists()


@pytest.mark.skipif(not os.path.exists('/dev/full'), reason='/dev/full is required to simulate diagnostic write failure')
@pytest.mark.parametrize('shell', ['sh', 'bash'])
@pytest.mark.parametrize('native_stage', ['config', 'provision', 'inspect'])
def test_haskoki_native_status_survives_full_diagnostic_sink(tmp_path, shell, native_stage):
    script, state, _ = haskoki_script(tmp_path)
    if native_stage == 'provision':
        (tmp_path / 'haskoki-provision').write_text('#!/bin/sh\nexit 37\n')
    with open('/dev/full', 'wb') as sink:
        result = subprocess.run([shell, str(script), 'init'], stdout=subprocess.PIPE,
                                stderr=sink, text=True, timeout=30, env=os.environ | {
                                    'P11LAB_PIN': '1234', 'P11LAB_SO_PIN': '5678',
                                    'CALLS': str(tmp_path / 'native-calls'),
                                    'CONFIG_STATUS': '37' if native_stage == 'config' else '0',
                                    'STORE_STATUS': '37' if native_stage == 'inspect' else '0'})
    assert result.returncode == 37
    assert not (state / 'haskoki' / 'complete').exists()


@pytest.mark.parametrize('shell', ['sh', 'bash'])
@pytest.mark.parametrize('missing,status', [(True, 127), (False, 126)])
def test_haskoki_initial_missing_or_nonexecutable_validator(tmp_path, shell, missing, status):
    script, state, _ = haskoki_script(tmp_path)
    ctl = tmp_path / 'haskoki-ctl'
    if missing:
        ctl.unlink()
    else:
        ctl.chmod(0o644)
    result = run_haskoki(script, shell, 'init')
    assert result.returncode == status
    assert not (tmp_path / 'native-calls').exists()
    assert not (state / 'haskoki' / 'complete').exists()


@pytest.mark.parametrize('shell', ['sh', 'bash'])
@pytest.mark.parametrize('name', ['P11LAB_PIN', 'P11LAB_SO_PIN'])
@pytest.mark.parametrize('value', [None, '', 'wrong'])
def test_haskoki_invalid_credentials_leave_no_init_temporary_files(tmp_path, shell, name, value):
    script, state, control = haskoki_script(tmp_path)
    result = run_haskoki(script, shell, 'init', **{name: value})
    assert result.returncode != 0
    assert not (tmp_path / 'native-calls').exists()
    assert not list(state.iterdir())
    assert not list(control.glob('init.*'))
    assert not list(control.glob('marker.*'))


@pytest.mark.parametrize('shell', ['sh', 'bash'])
def test_haskoki_rejected_init_does_not_remove_another_initializers_lock(tmp_path, shell):
    script, state, _ = haskoki_script(tmp_path)
    lock = state / '.init-lock'
    lock.mkdir()
    result = run_haskoki(script, shell, 'init')
    assert result.returncode != 0
    assert not (tmp_path / 'native-calls').exists()
    assert lock.is_dir()


@pytest.mark.parametrize('shell', ['sh', 'bash'])
@pytest.mark.parametrize('cleanup_tool', ['rm', 'rmdir'])
@pytest.mark.parametrize('native_status', [0, 37])
def test_haskoki_cleanup_failure_is_reported_without_hiding_native_status(
        tmp_path, shell, cleanup_tool, native_status):
    script, state, control = haskoki_script(tmp_path)
    tools = tmp_path / 'tools'
    tools.mkdir()
    tool = tools / cleanup_tool
    tool.write_text('#!/bin/sh\nprintf "injected cleanup failure\\n" >&2\nexit 73\n')
    tool.chmod(0o755)
    result = run_haskoki(script, shell, 'init', CONFIG_STATUS=str(native_status),
                         PATH=str(tools) + os.pathsep + os.environ['PATH'])
    assert result.returncode == (native_status or 1), result.stdout + result.stderr
    assert 'cleanup failed' in result.stderr
    assert (state / 'haskoki' / 'complete').exists() is (native_status == 0)
    assert (state / '.init-lock').exists() is (cleanup_tool == 'rmdir')
    assert bool(list(control.glob('marker.*'))) is (cleanup_tool == 'rm')


@pytest.mark.parametrize('shell', ['sh', 'bash'])
@pytest.mark.parametrize('cleanup_tool', ['rm', 'rmdir'])
@pytest.mark.parametrize('primary', [0, 37, 'HUP', 'INT', 'TERM'])
@pytest.mark.parametrize('stop,status', [('HUP', 129), ('INT', 130), ('TERM', 143)])
def test_haskoki_cleanup_signals_finish_cleanup_and_preserve_primary_status(
        tmp_path, shell, cleanup_tool, primary, stop, status):
    script, state, control = haskoki_script(tmp_path)
    initial_status = primary
    if isinstance(primary, str):
        initial_status = {'HUP': 129, 'INT': 130, 'TERM': 143}[primary]
        ctl = tmp_path / 'haskoki-ctl'
        ctl.write_text(ctl.read_text().replace(
            'exit "$CONFIG_STATUS"', f'kill -{primary} "$PPID"; exit 0'))
    tools = tmp_path / 'tools'
    tools.mkdir()
    calls = tmp_path / 'cleanup-calls'
    for name in ('rmdir', 'rm'):
        executable = shutil.which(name)
        assert executable, name
        wrapper = tools / name
        wrapper.write_text(
            '#!/bin/sh\nset -eu\n'
            f'printf "%s\\n" {name} >> {shlex.quote(str(calls))}\n'
            f'{shlex.quote(executable)} "$@"\n'
            + (f'kill -{stop} "$PPID"\n' if name == cleanup_tool else ''))
        wrapper.chmod(0o755)
    result = run_haskoki(
        script, shell, 'init', CONFIG_STATUS=str(primary if isinstance(primary, int) else 0),
        PATH=str(tools) + os.pathsep + os.environ['PATH'])
    assert result.returncode == (initial_status or status), result.stdout + result.stderr
    assert calls.read_text().splitlines() == ['rmdir', 'rm']
    assert not (state / '.init-lock').exists()
    assert not list(control.glob('marker.*'))
    assert not list(control.glob('init.*'))
    assert (state / 'haskoki' / 'complete').exists() is (primary == 0)


@pytest.mark.parametrize('shell', ['sh', 'bash'])
@pytest.mark.parametrize('native_status', [0, 37])
@pytest.mark.parametrize('first_failure,expected', [('HUP', 129), ('INT', 130), ('cleanup', 1)])
def test_haskoki_cleanup_keeps_first_observed_failure(tmp_path, shell, native_status,
                                                     first_failure, expected):
    script, state, control = haskoki_script(tmp_path)
    tools = tmp_path / 'tools'
    tools.mkdir()
    rmdir = tools / 'rmdir'
    if first_failure == 'cleanup':
        rmdir.write_text('#!/bin/sh\nexit 73\n')
    else:
        rmdir.write_text(
            f'#!/bin/sh\n{shlex.quote(shutil.which("rmdir"))} "$@"\n'
            f'kill -{first_failure} "$PPID"\n')
    rmdir.chmod(0o755)
    rm = tools / 'rm'
    rm.write_text(
        f'#!/bin/sh\n{shlex.quote(shutil.which("rm"))} "$@"\nkill -TERM "$PPID"\n')
    rm.chmod(0o755)
    result = run_haskoki(script, shell, 'init', CONFIG_STATUS=str(native_status),
                         PATH=str(tools) + os.pathsep + os.environ['PATH'])
    assert result.returncode == (native_status or expected), result.stdout + result.stderr
    assert not list(control.glob('marker.*'))
    assert not list(control.glob('init.*'))
    assert (state / '.init-lock').exists() is (first_failure == 'cleanup')


@pytest.mark.parametrize('data,accepted', [
    (b'1234', True), (b'1234\n', True), (b'1234\n\n', False),
    (b'12\n34', False), (b'1234\r\n', False), (b'1234\0', False),
])
def test_secret_file_has_exactly_one_text_line(tmp_path, data, accepted):
    source = tmp_path / 'pin'
    source.write_bytes(data)
    result = run_script(package_data('runtime/common.sh').read_text() +
                        '\np11lab_secret P11LAB_PIN P11LAB_PIN_FILE\n'
                        'printf "%s" "$credential"\n', tmp_path,
                        P11LAB_PIN_FILE=str(source))
    assert (result.returncode == 0) is accepted, result.stderr
    if accepted:
        assert result.stdout == '1234'
    else:
        assert 'credential' in result.stderr


@pytest.mark.parametrize('operation', ['init', 'health', 'server', 'exec'])
@pytest.mark.parametrize('damage', ['missing-db', 'db-link', 'log-link', 'marker-bytes', 'empty-owned'])
def test_bouncy_container_rejects_state_before_open(tmp_path, operation, damage):
    state, control = tmp_path / 'state', tmp_path / 'control'
    owned = state / 'bouncyhsm'
    owned.mkdir(parents=True)
    control.mkdir()
    runtime_id = tmp_path / 'runtime-id'
    runtime_id.write_text('fixture\n')
    (owned / 'complete').write_text('schema=1\nprovider=bouncyhsm\nartifact=fixture\nlabel=P11Lab\nslot=1\nbackend=litedb\n')
    (owned / 'BouncyHsm.db').write_bytes(b'original-db')
    outside = tmp_path / 'outside'
    outside.write_bytes(b'original-outside')
    if damage == 'missing-db':
        (owned / 'BouncyHsm.db').unlink()
    elif damage in ('db-link', 'log-link'):
        path = owned / ('BouncyHsm.db' if damage == 'db-link' else 'BouncyHsm-log.db')
        path.unlink(missing_ok=True)
        path.symlink_to(outside)
    elif damage == 'marker-bytes':
        with (owned / 'complete').open('ab') as stream:
            stream.write(b'\n')
    else:
        for path in owned.iterdir():
            path.unlink()
    server = tmp_path / 'dotnet'
    server.write_text('#!/bin/sh\necho opened >> "$CALLS"\nprintf mutated > "$BouncyHsm_LiteDbPersistentRepositorySetup__DbFilePath"\nexit 7\n')
    server.chmod(0o755)
    text = package_data('providers/bouncyhsm/entrypoint.sh').read_text()
    text = text.replace('. /usr/share/p11lab/common.sh', package_data('runtime/common.sh').read_text())
    for original, redirect in [('/var/lib/p11lab', state), ('/run/p11lab', control),
                               ('/usr/share/p11lab/runtime-id', runtime_id),
                               ('/usr/share/dotnet/dotnet', server),
                               ('/opt/bouncyhsm/server', tmp_path)]:
        text = text.replace(original, str(redirect))
    script = tmp_path / 'provider'
    script.write_text(text)
    def snapshot():
        return {str(p.relative_to(state)): p.readlink().as_posix() if p.is_symlink()
                else p.read_bytes() if p.is_file() else 'directory' for p in state.rglob('*')}
    before = snapshot()
    result = subprocess.run(['bash', str(script), operation, *(['--', 'true'] if operation == 'exec' else [])],
                            env=os.environ | {'CALLS': str(tmp_path / 'calls')},
                            capture_output=True, text=True, timeout=15)
    assert result.returncode != 0
    assert not (tmp_path / 'calls').exists(), 'rejected state reached the server'
    assert snapshot() == before
    assert outside.read_bytes() == b'original-outside'


def test_bouncy_slot_dto_preserves_quotes_backslashes_and_unicode(tmp_path):
    import json
    text = package_data('providers/bouncyhsm/entrypoint.sh').read_text()
    functions = text.split('case "${1-}" in', 1)[0]
    functions = functions.replace('. /usr/share/p11lab/common.sh', package_data('runtime/common.sh').read_text())
    dto = next(line.strip() for line in text.splitlines() if line.strip().startswith('dto='))
    pin = 'quote"slash\\tab\t\u00e4'
    result = run_script(functions + '\nlabel=P11Lab\nuser_credential=$TEST_PIN\ncredential=$TEST_PIN\n'
                        + dto + '\nprintf "%s" "$dto"\n', tmp_path, TEST_PIN=pin)
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload['Token']['UserPin'] == payload['Token']['SoPin'] == pin
